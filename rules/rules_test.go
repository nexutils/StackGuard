package rules_test

// These tests check every built-in rule. To add a rule, add only its fixtures:

// 	testdata/rules/<RULE_ID>/fail/...   must produce at least one finding
// 	testdata/rules/<RULE_ID>/pass/...   optional; must produce none
// 	testdata/rules/_clean/<target>/...  must produce no findings for ANY rule
// 	                                    of that target

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nexutils/StackGuard/internal/engine"
	"github.com/nexutils/StackGuard/internal/loader"
	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser/all"
	"github.com/nexutils/StackGuard/rules"
)

const fixtures = "../testdata/rules"

var idTargets = map[string]string{
	"COMP": "compose", "DOCK": "dockerfile", "K8S": "kubernetes", "HELM": "helm",
	"TF": "terraform", "GHA": "github", "JENK": "jenkins", "ANS": "ansible", "NGX": "nginx",
}

func loadEmbedded(t *testing.T) []*models.Rule {
	t.Helper()
	set, err := loader.Load(
		loader.Options{KnownTargets: all.Registry().Names()},
		loader.Layer{Name: "embedded", FS: rules.FS, Embedded: true},
	)
	if err != nil {
		t.Fatalf("embedded rules are invalid: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("no embedded rules found")
	}
	return set.All()
}

func TestEmbeddedRulesConventions(t *testing.T) {
	for _, r := range loadEmbedded(t) {
		parts := strings.Split(r.ID, "_")
		if len(parts) < 3 {
			t.Errorf("%s: ID must look like TARGET_SEGMENT_NNN", r.ID)
			continue
		}
		if want := idTargets[parts[0]]; want != r.Target {
			t.Errorf("%s: ID prefix %s implies target %q, rule has %q", r.ID, parts[0], want, r.Target)
		}
		if !slices.Contains(models.Categories, r.Category) {
			t.Errorf("%s: unknown category %q", r.ID, r.Category)
		}
		if want := "embedded:" + r.Target + "/"; !strings.HasPrefix(r.Source, want) {
			t.Errorf("%s: must live under %s, found in %s", r.ID, want, r.Source)
		}
		// description and remediation are required; pass_message is optional.
		if r.Description == "" {
			t.Errorf("%s: description is required for built-in rules", r.ID)
		}
		if r.Remediation == "" {
			t.Errorf("%s: remediation is required for built-in rules", r.ID)
		}
	}
}

func scan(t *testing.T, rs []*models.Rule, dir string, enabled ...string) *models.Report {
	t.Helper()
	e, err := engine.New(rs, engine.Options{EnabledRules: enabled})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Scan(context.Background(), []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range rep.Diagnostics {
		t.Errorf("%s: unexpected diagnostic: %s", d.File, d.Message)
	}
	return rep
}

func TestRuleFixtures(t *testing.T) {
	for _, r := range loadEmbedded(t) {
		t.Run(r.ID, func(t *testing.T) {
			failDir := filepath.Join(fixtures, r.ID, "fail")
			if _, err := os.Stat(failDir); err != nil {
				t.Fatalf("missing fixture directory %s", failDir)
			}
			rep := scan(t, []*models.Rule{r}, failDir, r.ID)
			if len(rep.Findings) == 0 {
				t.Errorf("fail fixture produced no findings")
			}
			for _, f := range rep.Findings {
				if f.Line <= 0 {
					t.Errorf("finding without a line number: %+v", f)
				}
				if strings.Contains(f.Message, "<no value>") || strings.Contains(f.Message, "{{") {
					t.Errorf("message template not rendered properly: %q", f.Message)
				}
			}

			passDir := filepath.Join(fixtures, r.ID, "pass")
			if _, err := os.Stat(passDir); err == nil {
				for _, f := range scan(t, []*models.Rule{r}, passDir, r.ID).Findings {
					t.Errorf("pass fixture produced finding: %s:%d %s", f.File, f.Line, f.Message)
				}
			}
		})
	}
}

func TestCleanFixtures(t *testing.T) {
	byTarget := map[string][]*models.Rule{}
	for _, r := range loadEmbedded(t) {
		byTarget[r.Target] = append(byTarget[r.Target], r)
	}
	for target, rs := range byTarget {
		t.Run(target, func(t *testing.T) {
			dir := filepath.Join(fixtures, "_clean", target)
			if _, err := os.Stat(dir); err != nil {
				t.Fatalf("missing clean fixture %s", dir)
			}
			rep := scan(t, rs, dir)
			if rep.Stats.Resources == 0 {
				t.Fatalf("clean fixture produced no %s resources", target)
			}
			for _, f := range rep.Findings {
				t.Errorf("clean fixture: %s %s:%d %s", f.RuleID, f.File, f.Line, f.Message)
			}
		})
	}
}

func TestEveryFixtureHasARule(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range loadEmbedded(t) {
		ids[r.ID] = true
	}
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") && !ids[e.Name()] {
			t.Errorf("fixture directory %s has no matching rule", e.Name())
		}
	}
}
