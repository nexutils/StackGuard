package github

import (
	"context"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

func parse(t *testing.T, wf string) map[string]any {
	t.Helper()
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte(wf)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	return res[0].Properties
}

func TestParseUses(t *testing.T) {
	tests := map[string]map[string]any{
		"actions/checkout@v4": {
			"kind": "repo", "owner": "actions", "repo": "checkout", "ref": "v4", "ref_is_sha": false,
		},
		"tj-actions/changed-files@0f7a1b2c3d4e5f60718293a4b5c6d7e8f9012345": {
			"kind": "repo", "owner": "tj-actions", "repo": "changed-files",
			"ref": "0f7a1b2c3d4e5f60718293a4b5c6d7e8f9012345", "ref_is_sha": true,
		},
		"owner/repo/sub/path@main": {
			"kind": "repo", "owner": "owner", "repo": "repo", "path": "sub/path",
			"ref": "main", "ref_is_sha": false,
		},
		"./.github/actions/local": {"kind": "local", "path": "./.github/actions/local"},
		"docker://alpine:3.19":    {"kind": "docker"},
	}
	for in, want := range tests {
		got := parseUses(in)
		for k, v := range want {
			if got[k] != v {
				t.Errorf("parseUses(%q)[%s] = %v, want %v", in, k, got[k], v)
			}
		}
	}
}

func TestBuildModel(t *testing.T) {
	wf := `
name: CI
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
env:
  GLOBAL: g
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env:
      JOB_ENV: j
    steps:
      - uses: actions/checkout@v4
      - name: Install
        run: npm ci
        env:
          STEP_ENV: s
      - uses: actions/setup-node@v4
        with:
          node-version: "20.11.0"
          cache: npm
  deploy-prod:
    runs-on: ubuntu-24.04
    environment: production
    needs: [build]
    steps:
      - name: Ship it
        run: kubectl apply -f k8s/
`
	props := parse(t, wf)

	w := props["workflows"].([]any)[0].(map[string]any)
	if w["name"] != "CI" {
		t.Errorf("workflow name = %v", w["name"])
	}
	triggers := w["triggers"].([]any)
	if len(triggers) != 2 || triggers[0] != "pull_request" || triggers[1] != "push" {
		t.Errorf("triggers = %#v", triggers)
	}

	jobs := props["jobs"].([]any)
	if len(jobs) != 2 {
		t.Fatalf("jobs = %d", len(jobs))
	}
	byID := map[string]map[string]any{}
	for _, j := range jobs {
		m := j.(map[string]any)
		byID[m["id"].(string)] = m
	}
	build := byID["build"]
	if build["runs_on"] != "ubuntu-latest" || build["timeout_minutes"] != 10 {
		t.Errorf("build job = %#v", build)
	}
	if build["is_deploy"] != false {
		t.Errorf("build is_deploy = %v, want false", build["is_deploy"])
	}

	dep := byID["deploy-prod"]
	if dep["is_deploy"] != true {
		t.Errorf("deploy-prod is_deploy = %v (name and kubectl apply)", dep["is_deploy"])
	}
	if env := dep["environment"].(map[string]any); env["name"] != "production" {
		t.Errorf("environment = %#v (string should normalize to {name})", env)
	}
	if needs := dep["needs"].([]any); len(needs) != 1 || needs[0] != "build" {
		t.Errorf("needs = %#v", needs)
	}

	// steps are flattened across jobs, with back-references and with_pairs
	steps := props["steps"].([]any)
	if len(steps) != 4 {
		t.Fatalf("steps = %d, want 4", len(steps))
	}
	setup := steps[2].(map[string]any)
	pairs := setup["with_pairs"].([]any)
	if len(pairs) != 2 || pairs[0] != "cache=npm" || pairs[1] != "node-version=20.11.0" {
		t.Errorf("with_pairs = %#v", pairs)
	}
	if a := setup["action"].(map[string]any); a["owner"] != "actions" || a["ref_is_sha"] != false {
		t.Errorf("action = %#v", a)
	}
	if jr := setup["job"].(map[string]any); jr["id"] != "build" {
		t.Errorf("step.job = %#v", jr)
	}

	// env entries at all three levels
	levels := map[string]bool{}
	for _, e := range props["env_entries"].([]any) {
		levels[e.(map[string]any)["level"].(string)] = true
	}
	for _, want := range []string{"workflow", "job", "step"} {
		if !levels[want] {
			t.Errorf("no env_entries at level %q", want)
		}
	}
}

func TestNonWorkflowYieldsNothing(t *testing.T) {
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte("- just: a list\n")})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Errorf("expected no resource, got %d", len(res))
	}
}
