package loader

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nexutils/StackGuard/internal/models"
)

const validRule = `
id: COMP_SEC_001
title: Privileged container
severity: ERROR
category: security
target: compose
resource: service
message: "{{ .Resource.Name }} is privileged"
query:
  path: privileged
  equals: true
`

func layer(name string, files map[string]string) Layer {
	fsys := fstest.MapFS{}
	for p, c := range files {
		fsys[p] = &fstest.MapFile{Data: []byte(c)}
	}
	return Layer{Name: name, FS: fsys}
}

func TestLoadAndOverride(t *testing.T) {
	embedded := layer("embedded", map[string]string{
		"compose/COMP_SEC_001.yaml": validRule,
		"compose/COMP_REL_001.yaml": strings.NewReplacer("COMP_SEC_001", "COMP_REL_001", "security", "reliability").Replace(validRule),
		"README.md":                 "ignored",
	})
	embedded.Embedded = true
	local := layer("local", map[string]string{
		"override.yml": strings.Replace(validRule, "severity: ERROR", "severity: warning", 1),
	})

	set, err := Load(Options{KnownTargets: []string{"compose"}}, embedded, local)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2 {
		t.Fatalf("got %d rules, want 2", set.Len())
	}
	r, ok := set.Get("comp_sec_001")
	if !ok {
		t.Fatal("rule lookup should be case-insensitive")
	}
	if r.Severity != models.SeverityWarning || r.Source != "local:override.yml" {
		t.Errorf("local layer did not override embedded rule: severity=%s source=%s", r.Severity, r.Source)
	}
	if r.Resources[0] != "service" {
		t.Errorf("resource not decoded: %v", r.Resources)
	}
	other, _ := set.Get("COMP_REL_001")
	if other.Source != "embedded:compose/COMP_REL_001.yaml" {
		t.Errorf("embedded source = %q", other.Source)
	}
	if ids := []string{set.All()[0].ID, set.All()[1].ID}; ids[0] != "COMP_REL_001" || ids[1] != "COMP_SEC_001" {
		t.Errorf("All() not sorted: %v", ids)
	}
}

func TestMultiDocumentAndResourceList(t *testing.T) {
	two := validRule + "---\n" + strings.NewReplacer(
		"COMP_SEC_001", "COMP_SEC_002",
		"resource: service", "resource: [service, network]",
	).Replace(validRule)
	set, err := Load(Options{}, layer("l", map[string]string{"rules.yaml": two}))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := set.Get("COMP_SEC_002")
	if !ok || len(r.Resources) != 2 {
		t.Fatalf("second document not loaded correctly: %+v", r)
	}
}

func TestValidation(t *testing.T) {
	tests := map[string]struct {
		rule string
		want string
	}{
		"missing fields":   {"id: COMP_SEC_009\nquery: {path: a, exists: true}\n", "title is required"},
		"bad id":           {strings.Replace(validRule, "COMP_SEC_001", "comp-1", 1), "must look like"},
		"bad severity":     {strings.Replace(validRule, "ERROR", "FATAL", 1), "unknown severity"},
		"bad category":     {strings.Replace(validRule, "category: security", "category: vibes", 1), "unknown category"},
		"unknown target":   {strings.Replace(validRule, "target: compose", "target: cobol", 1), "unknown target"},
		"unknown field":    {validRule + "sevrity: ERROR\n", "sevrity"},
		"unknown operator": {strings.Replace(validRule, "equals: true", "equalz: true", 1), "unknown operator"},
		"no query":         {strings.Replace(validRule, "query:\n  path: privileged\n  equals: true\n", "", 1), "query is required"},
		"bad template":     {strings.Replace(validRule, `"{{ .Resource.Name }} is privileged"`, `"{{ .Resource.Name "`, 1), "message template"},
		"bad glob":         {strings.Replace(validRule, "resource: service", `resource: "["`, 1), "bad resource glob"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(Options{KnownTargets: []string{"compose"}}, layer("l", map[string]string{"r.yaml": tt.rule}))
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected ValidationError, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestDuplicateInLayer(t *testing.T) {
	_, err := Load(Options{}, layer("l", map[string]string{"a.yaml": validRule, "b.yaml": validRule}))
	if err == nil || !strings.Contains(err.Error(), "duplicate rule ID") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestProblemsAreAggregated(t *testing.T) {
	_, err := Load(Options{}, layer("l", map[string]string{
		"a.yaml": strings.Replace(validRule, "ERROR", "LOUD", 1),
		"b.yaml": strings.Replace(validRule, "category: security", "category: x", 1),
	}))
	var ve *ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 2 {
		t.Fatalf("expected 2 aggregated problems, got %v", err)
	}
}

func TestDirLayerMissing(t *testing.T) {
	if _, ok := DirLayer("x", "/definitely/not/here"); ok {
		t.Error("DirLayer should report a missing directory")
	}
}
