package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

func rule(t testing.TB, id string, sev models.Severity, query string) *models.Rule {
	t.Helper()
	var q any
	if err := yaml.Unmarshal([]byte(query), &q); err != nil {
		t.Fatal(err)
	}
	return &models.Rule{
		ID: id, Title: id, Severity: sev, Category: models.CategorySecurity,
		Target: "compose", Resources: []string{"service"},
		Message: "{{ .Resource.Name }}: {{ .Value }}", Query: q,
	}
}

const composeFile = `services:
  api:
    image: acme/api:latest
    privileged: true
  # stackguard:ignore COMP_SEC_002
  db:
    image: postgres:16
    privileged: true
  cache:
    image: redis:7
`

func newEngine(t testing.TB, opts Options, rules ...*models.Rule) *Engine {
	t.Helper()
	e, err := New(rules, opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestScanProgress(t *testing.T) {
	privileged := rule(t, "COMP_SEC_001", models.SeverityError, `{path: privileged, equals: true}`)
	var stages []string
	var last ScanPhase
	e := newEngine(t, Options{Progress: func(p ScanPhase) {
		stages = append(stages, p.Stage)
		last = p
	}}, privileged)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(composeFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scan(context.Background(), []string{dir}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"discovering", "parsing", "evaluating"}; !reflect.DeepEqual(stages, want) {
		t.Fatalf("progress stages = %v, want %v", stages, want)
	}
	if last.Rules != 1 || last.Resources == 0 || last.Files == 0 {
		t.Fatalf("evaluating phase should carry counts, got %+v", last)
	}
}

func TestScanSources(t *testing.T) {
	privileged := rule(t, "COMP_SEC_001", models.SeverityError, `{path: privileged, equals: true}`)
	latest := rule(t, "COMP_MNT_001", models.SeverityWarning, `{path: _image.tag, equals: latest}`)
	e := newEngine(t, Options{}, privileged, latest)

	rep, err := e.ScanSources(context.Background(), []parser.Source{{Path: "docker-compose.yml", Content: []byte(composeFile)}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range rep.Findings {
		got = append(got, fmt.Sprintf("%s %s:%d %s", f.RuleID, f.File, f.Line, f.Message))
	}
	want := []string{
		"COMP_MNT_001 docker-compose.yml:3 api: latest",
		"COMP_SEC_001 docker-compose.yml:4 api: true",
		"COMP_SEC_001 docker-compose.yml:8 db: true",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("findings:\n got %v\nwant %v", got, want)
	}
	if rep.Score.Total != 100-10-10-3 {
		t.Errorf("score = %d", rep.Score.Total)
	}
	if rep.Stats.Resources != 4 || rep.Stats.FilesParsed != 1 {
		t.Errorf("stats = %+v", rep.Stats)
	}
	for _, rr := range rep.Results {
		if rr.Status != models.RuleFailed || rr.Evaluated != 3 {
			t.Errorf("result %s = %+v", rr.RuleID, rr)
		}
	}
	if rep.Findings[0].Fingerprint == "" || rep.Findings[1].Fingerprint == rep.Findings[2].Fingerprint {
		t.Error("fingerprints must be set and distinct per resource")
	}
}

func TestDisableOverrideAndTargets(t *testing.T) {
	privileged := rule(t, "COMP_SEC_001", models.SeverityError, `{path: privileged, equals: true}`)
	latest := rule(t, "COMP_MNT_001", models.SeverityWarning, `{path: _image.tag, equals: latest}`)
	src := []parser.Source{{Path: "docker-compose.yml", Content: []byte(composeFile)}}

	e := newEngine(t, Options{
		DisabledRules:     []string{"comp_mnt_001"},
		SeverityOverrides: map[string]models.Severity{"COMP_SEC_001": models.SeverityInfo},
	}, privileged, latest)
	rep, _ := e.ScanSources(context.Background(), src)
	if len(e.Rules()) != 1 || len(rep.Findings) != 2 || rep.Findings[0].Severity != models.SeverityInfo {
		t.Errorf("disable/override not applied: rules=%d findings=%+v", len(e.Rules()), rep.Findings)
	}
	if privileged.Severity != models.SeverityError {
		t.Error("severity override must not mutate the shared rule")
	}

	e = newEngine(t, Options{Targets: []string{"kubernetes"}}, privileged)
	rep, _ = e.ScanSources(context.Background(), src)
	if len(e.Rules()) != 0 || rep.Stats.FilesParsed != 0 {
		t.Errorf("target filter not applied: %+v", rep.Stats)
	}
}

func TestSuppression(t *testing.T) {
	src := []parser.Source{{Path: "docker-compose.yml", Content: []byte(`services:
  api:
    image: x:1
    # stackguard:ignore COMP_SEC_001 -- needed for eBPF tooling
    privileged: true
  db:
    privileged: true # stackguard:ignore
  cache:
    # stackguard:ignore COMP_SEC_009
    privileged: true
`)}}
	e := newEngine(t, Options{}, rule(t, "COMP_SEC_001", models.SeverityError, `{path: privileged, equals: true}`))
	rep, _ := e.ScanSources(context.Background(), src)
	if len(rep.Findings) != 1 || rep.Findings[0].Resource != "cache" {
		t.Errorf("findings = %+v", rep.Findings)
	}
	if rep.Stats.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2", rep.Stats.Suppressed)
	}
}

func TestSkippedAndPassed(t *testing.T) {
	r := rule(t, "COMP_SEC_001", models.SeverityError, `{path: privileged, equals: true}`)
	e := newEngine(t, Options{}, r)

	rep, _ := e.ScanSources(context.Background(), []parser.Source{{Path: "main.tf", Content: []byte(`resource "a" "b" {}`)}})
	if rep.Results[0].Status != models.RuleSkipped {
		t.Errorf("status = %s, want skipped", rep.Results[0].Status)
	}
	rep, _ = e.ScanSources(context.Background(), []parser.Source{{Path: "compose.yaml", Content: []byte("services:\n  a:\n    image: x:1\n")}})
	if rep.Results[0].Status != models.RulePassed {
		t.Errorf("status = %s, want passed", rep.Results[0].Status)
	}
}

func TestParseErrorsBecomeDiagnostics(t *testing.T) {
	e := newEngine(t, Options{}, rule(t, "COMP_SEC_001", models.SeverityError, `{path: privileged, equals: true}`))
	rep, err := e.ScanSources(context.Background(), []parser.Source{
		{Path: "docker-compose.yml", Content: []byte("services: [unclosed")},
		{Path: "compose.yaml", Content: []byte("services:\n  a:\n    privileged: true\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Diagnostics) != 1 || len(rep.Findings) != 1 {
		t.Errorf("diagnostics=%v findings=%v", rep.Diagnostics, rep.Findings)
	}
}

func TestCompileErrorsSurface(t *testing.T) {
	bad := rule(t, "COMP_SEC_001", models.SeverityError, `{path: privileged, nope: true}`)
	if _, err := New([]*models.Rule{bad}, Options{}); err == nil {
		t.Fatal("expected compile error")
	}
}

func ruleWithCategory(t testing.TB, id string, sev models.Severity, cat string, query string) *models.Rule {
	t.Helper()
	r := rule(t, id, sev, query)
	r.Category = cat
	return r
}

func TestProfileQuickFiltering(t *testing.T) {
	q := `{path: privileged, equals: true}`
	errorSec := ruleWithCategory(t, "SEC_001", models.SeverityError, models.CategorySecurity, q)
	warnSec := ruleWithCategory(t, "SEC_002", models.SeverityWarning, models.CategorySecurity, q)
	errorOps := ruleWithCategory(t, "OPS_001", models.SeverityError, models.CategoryOperational, q)
	warnOps := ruleWithCategory(t, "OPS_002", models.SeverityWarning, models.CategoryOperational, q)
	infoSec := ruleWithCategory(t, "SEC_003", models.SeverityInfo, models.CategorySecurity, q)
	errorRel := ruleWithCategory(t, "REL_001", models.SeverityError, models.CategoryReliability, q)

	all := []*models.Rule{errorSec, warnSec, errorOps, warnOps, infoSec, errorRel}

	e := newEngine(t, Options{Profile: models.ProfileQuick}, all...)
	ids := ruleIDs(e)
	want := map[string]bool{"SEC_001": true, "REL_001": true}
	if len(ids) != len(want) {
		t.Fatalf("quick profile rules = %v, want %v", ids, want)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected rule in quick profile: %s", id)
		}
	}
}

func TestProfileStandardFiltering(t *testing.T) {
	q := `{path: privileged, equals: true}`
	errorSec := ruleWithCategory(t, "SEC_001", models.SeverityError, models.CategorySecurity, q)
	warnPerf := ruleWithCategory(t, "PERF_001", models.SeverityWarning, models.CategoryPerformance, q)
	infoSec := ruleWithCategory(t, "SEC_002", models.SeverityInfo, models.CategorySecurity, q)

	e := newEngine(t, Options{Profile: models.ProfileStandard}, errorSec, warnPerf, infoSec)
	ids := ruleIDs(e)
	want := map[string]bool{"SEC_001": true, "PERF_001": true}
	if len(ids) != len(want) {
		t.Fatalf("standard profile rules = %v, want %v", ids, want)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected rule in standard profile: %s", id)
		}
	}
}

func TestProfileStrictFiltering(t *testing.T) {
	q := `{path: privileged, equals: true}`
	errorSec := ruleWithCategory(t, "SEC_001", models.SeverityError, models.CategorySecurity, q)
	infoPerf := ruleWithCategory(t, "PERF_001", models.SeverityInfo, models.CategoryPerformance, q)
	offByDefault := ruleWithCategory(t, "ORG_001", models.SeverityWarning, models.CategorySecurity, q)
	offByDefault.OffByDefault = true

	e := newEngine(t, Options{Profile: models.ProfileStrict}, errorSec, infoPerf, offByDefault)
	ids := ruleIDs(e)
	if len(ids) != 3 {
		t.Fatalf("strict profile rules = %v, want all 3", ids)
	}
}

func TestProfileQuickWithExplicitEnable(t *testing.T) {
	q := `{path: privileged, equals: true}`
	warnOps := ruleWithCategory(t, "OPS_001", models.SeverityWarning, models.CategoryOperational, q)

	e := newEngine(t, Options{
		Profile:     models.ProfileQuick,
		EnabledRules: []string{"OPS_001"},
	}, warnOps)
	ids := ruleIDs(e)
	if len(ids) != 1 || ids[0] != "OPS_001" {
		t.Errorf("explicit --enable should override quick filter, got %v", ids)
	}
}

func TestProfileStrictOffByDefaultDisabled(t *testing.T) {
	q := `{path: privileged, equals: true}`
	offByDefault := ruleWithCategory(t, "ORG_001", models.SeverityWarning, models.CategorySecurity, q)
	offByDefault.OffByDefault = true

	e := newEngine(t, Options{
		Profile:       models.ProfileStrict,
		DisabledRules: []string{"ORG_001"},
	}, offByDefault)
	if len(e.Rules()) != 0 {
		t.Error("--disable should still exclude off-by-default rules even in strict")
	}
}

func ruleIDs(e *Engine) []string {
	var ids []string
	for _, r := range e.Rules() {
		ids = append(ids, r.Rule.ID)
	}
	return ids
}

func BenchmarkEvaluate(b *testing.B) {
	rules := []*models.Rule{
		rule(b, "COMP_SEC_001", models.SeverityError, `{path: privileged, equals: true}`),
		rule(b, "COMP_SEC_002", models.SeverityError, `{path: ports.*, where: {all: [{path: target, regex: "^(5432|6379)$"}, {path: host_ip, not_exists: true}]}}`),
		rule(b, "COMP_OPS_001", models.SeverityWarning, `{all: [{path: deploy.resources.limits.memory, not_exists: true}, {path: mem_limit, not_exists: true}]}`),
	}
	e := newEngine(b, Options{}, rules...)
	resources := make([]models.Resource, 1000)
	for i := range resources {
		resources[i] = models.Resource{
			Target: "compose", Type: "service", Name: fmt.Sprintf("svc%d", i), File: "c.yml", Line: i + 1,
			Properties: map[string]any{
				"image": "x:1",
				"ports": []any{map[string]any{"target": "8080"}, map[string]any{"target": "5432"}},
			},
		}
	}
	b.ResetTimer()
	for b.Loop() {
		e.Evaluate(resources)
	}
}
