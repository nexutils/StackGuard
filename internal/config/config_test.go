package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nexutils/StackGuard/internal/models"
)

func TestResolve(t *testing.T) {
	c := Config{
		DisabledRules:     []string{"comp_sec_003 "},
		SeverityOverrides: map[string]string{"comp_rel_001": "error"},
		FailOn:            "warning",
		MinScore:          70,
	}
	r, err := c.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if r.DisabledRules[0] != "COMP_SEC_003" {
		t.Errorf("disabled rule not normalised: %q", r.DisabledRules[0])
	}
	if r.SeverityOverrides["COMP_REL_001"] != models.SeverityError {
		t.Errorf("override not applied: %v", r.SeverityOverrides)
	}
	if r.FailOn == nil || *r.FailOn != models.SeverityWarning {
		t.Errorf("fail_on = %v, want WARNING", r.FailOn)
	}

	for _, v := range []string{"none", "never", ""} {
		r, err := Config{FailOn: v}.Resolve()
		if err != nil || r.FailOn != nil {
			t.Errorf("fail_on %q: got %v, %v; want disabled", v, r.FailOn, err)
		}
	}

	// Profile parsing.
	for _, tc := range []struct {
		input string
		want  models.Profile
	}{
		{"", models.ProfileStandard},
		{"quick", models.ProfileQuick},
		{"strict", models.ProfileStrict},
	} {
		r, err := Config{Profile: tc.input}.Resolve()
		if err != nil {
			t.Errorf("profile %q: %v", tc.input, err)
		} else if r.Profile != tc.want {
			t.Errorf("profile %q = %v, want %v", tc.input, r.Profile, tc.want)
		}
	}
	if _, err := (Config{Profile: "turbo"}).Resolve(); err == nil {
		t.Error("expected error for unknown profile")
	}

	bad := []Config{
		{FailOn: "fatal"},
		{SeverityOverrides: map[string]string{"X_SEC_001": "loud"}},
		{MinScore: 101},
		{Profile: "turbo"},
	}
	for _, c := range bad {
		if _, err := c.Resolve(); err == nil {
			t.Errorf("Resolve(%+v): expected error", c)
		}
	}
}

func TestFind(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "repo", "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "repo", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A config above the repository root must not be picked up.
	if err := os.WriteFile(filepath.Join(root, ".stackguard.yaml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Find(nested); got != "" {
		t.Errorf("Find crossed the repository root: %q", got)
	}
	want := filepath.Join(root, "repo", "a", ".stackguard.yml")
	if err := os.WriteFile(want, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Find(nested); got != want {
		t.Errorf("Find = %q, want %q", got, want)
	}
}
