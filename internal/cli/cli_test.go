package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../../testdata/rules"

// run runs the CLI without using the user's rules or STACKGUARD_* settings.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv(envHome, t.TempDir())
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "STACKGUARD_") && k != envHome {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != ExitOK || !strings.HasPrefix(out, "stackguard ") {
		t.Errorf("code=%d out=%q", code, out)
	}
	code, out, _ = run(t, "version", "-f", "json")
	var info map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &info) != nil || info["go_version"] == "" {
		t.Errorf("json version: code=%d out=%q", code, out)
	}
}

func TestScanExitCodes(t *testing.T) {
	clean := filepath.Join(fixtures, "_clean")
	failing := filepath.Join(fixtures, "COMP_SEC_001", "fail")

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"clean", []string{"scan", clean}, ExitOK},
		{"error finding fails", []string{"scan", failing}, ExitFindings},
		{"fail-on none", []string{"scan", failing, "--fail-on", "none"}, ExitOK},
		{"min-score", []string{"scan", failing, "--fail-on", "none", "--min-score", "99"}, ExitFindings},
		{"target filter", []string{"scan", failing, "--target", "kubernetes"}, ExitOK},
		{"missing path", []string{"scan", "does/not/exist"}, ExitUsage},
		{"bad format", []string{"scan", clean, "-f", "xml"}, ExitUsage},
		{"bad fail-on", []string{"scan", clean, "--fail-on", "sometimes"}, ExitUsage},
		{"unknown flag", []string{"scan", "--nope"}, ExitUsage},
		{"unknown command", []string{"frobnicate"}, ExitUsage},
		{"bad log level", []string{"--log-level", "chatty", "version"}, ExitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := run(t, tt.args...)
			if code != tt.want {
				t.Errorf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.want, out, errOut)
			}
		})
	}
}

func TestScanJSONAndOutputFile(t *testing.T) {
	dir := filepath.Join(fixtures, "COMP_SEC_009", "fail")
	code, out, _ := run(t, "scan", dir, "-f", "json", "--fail-on", "none")
	var doc struct {
		Score    int `json:"score"`
		Findings []struct {
			RuleID string `json:"rule_id"`
			Line   int    `json:"line"`
		} `json:"findings"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil {
		t.Fatalf("code=%d out=%s", code, out)
	}
	found := false
	for _, f := range doc.Findings {
		if f.RuleID == "COMP_SEC_009" && f.Line > 0 {
			found = true
		}
	}
	if !found || doc.Score >= 100 {
		t.Errorf("unexpected JSON report: score=%d findings=%+v", doc.Score, doc.Findings)
	}

	// Disabling a rule removes its findings.
	_, out, _ = run(t, "scan", dir, "-f", "json", "--fail-on", "none", "--disable", "comp_sec_009")
	if strings.Contains(out, `"rule_id": "COMP_SEC_009"`) {
		t.Error("--disable did not remove the rule's findings")
	}

	outFile := filepath.Join(t.TempDir(), "report.sarif")
	code, out, _ = run(t, "scan", dir, "-f", "sarif", "-o", outFile, "--fail-on", "none")
	data, err := os.ReadFile(outFile)
	if code != ExitOK || out != "" || err != nil || !bytes.Contains(data, []byte(`"version": "2.1.0"`)) {
		t.Errorf("sarif to file: code=%d stdout=%q err=%v", code, out, err)
	}
}

func TestConfigFileAndEnv(t *testing.T) {
	tmp := t.TempDir()
	failing, _ := filepath.Abs(filepath.Join(fixtures, "COMP_SEC_001", "fail"))
	cfg := writeFile(t, filepath.Join(tmp, ".stackguard.yaml"), `
disabled_rules: [COMP_REL_001, COMP_REL_002]
severity_overrides:
  COMP_SEC_001: warning
fail_on: error
`)
	code, out, _ := run(t, "scan", failing, "--config", cfg, "-f", "json")
	if code != ExitOK {
		t.Errorf("override to WARNING should not fail on ERROR: code=%d\n%s", code, out)
	}
	if strings.Contains(out, `"rule_id": "COMP_REL_001"`) {
		t.Error("disabled rule still reported")
	}
	if !strings.Contains(out, `"severity": "WARNING"`) {
		t.Error("severity override not reflected in findings")
	}

	// Flags beat the config file.
	if code, _, _ := run(t, "scan", failing, "--config", cfg, "--fail-on", "warning"); code != ExitFindings {
		t.Errorf("--fail-on flag should override config, got %d", code)
	}

	// Environment variables beat the config file.
	t.Setenv(envHome, t.TempDir())
	t.Setenv("STACKGUARD_FAIL_ON", "none")
	var o, e bytes.Buffer
	if code := Run(context.Background(), []string{"scan", failing}, &o, &e); code != ExitOK {
		t.Errorf("STACKGUARD_FAIL_ON=none should disable failing, got %d\n%s", code, e.String())
	}
	os.Unsetenv("STACKGUARD_FAIL_ON")

	bad := writeFile(t, filepath.Join(tmp, "bad.yaml"), "fail_onn: error\n")
	if code, _, errOut := run(t, "scan", failing, "--config", bad); code != ExitUsage || !strings.Contains(errOut, "fail_onn") {
		t.Errorf("unknown config key should be a usage error: code=%d stderr=%s", code, errOut)
	}
}

func TestLocalRuleOverrides(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "COMP_SEC_001.yaml"), `
id: COMP_SEC_001
title: Privileged container (company policy)
severity: INFO
category: security
target: compose
resource: service
message: "{{ .Resource.Name }} is privileged"
query:
  path: privileged
  equals: true
`)
	code, out, errOut := run(t, "explain", "COMP_SEC_001", "--rules-dir", dir)
	if code != ExitOK || !strings.Contains(out, "company policy") || !strings.Contains(out, "INFO") {
		t.Errorf("override not applied: code=%d\n%s%s", code, out, errOut)
	}

	// User-level rules in $STACKGUARD_HOME/rules are picked up too.
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "rules", "custom.yaml"), `
id: ACME_SEC_001
title: Custom rule
severity: ERROR
category: security
target: compose
message: custom
query: {path: privileged, exists: true}
`)
	t.Setenv(envHome, home)
	var o, e bytes.Buffer
	if c := Run(context.Background(), []string{"explain", "acme_sec_001"}, &o, &e); c != ExitOK || !strings.Contains(o.String(), "Custom rule") {
		t.Errorf("user rules not loaded: code=%d %s %s", c, o.String(), e.String())
	}

	invalid := t.TempDir()
	writeFile(t, filepath.Join(invalid, "bad.yaml"), "id: nope\n")
	if code, _, errOut := run(t, "rules", "--rules-dir", invalid); code != ExitUsage || !strings.Contains(errOut, "invalid rule") {
		t.Errorf("invalid local rule should be a usage error: code=%d stderr=%s", code, errOut)
	}
}

func TestEnableOffByDefaultRule(t *testing.T) {
	dir := filepath.Join(fixtures, "COMP_PROD_005", "fail")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("no off-by-default fixture")
	}
	// Off by default: no COMP_PROD_005 finding.
	if _, out, _ := run(t, "scan", dir, "-f", "json", "--fail-on", "none"); strings.Contains(out, `"rule_id": "COMP_PROD_005"`) {
		t.Error("off-by-default rule fired without --enable")
	}
	// Enabled explicitly: it fires.
	if _, out, _ := run(t, "scan", dir, "-f", "json", "--fail-on", "none", "--enable", "comp_prod_005"); !strings.Contains(out, `"rule_id": "COMP_PROD_005"`) {
		t.Error("--enable did not turn on the off-by-default rule")
	}
}

func TestRulesCommand(t *testing.T) {
	code, out, _ := run(t, "rules", "--target", "compose", "--category", "security")
	if code != ExitOK || !strings.Contains(out, "COMP_SEC_001") || strings.Contains(out, "COMP_REL_001") || strings.Contains(out, "K8S_") {
		t.Errorf("filtering failed: code=%d\n%s", code, out)
	}

	code, out, _ = run(t, "rules", "-f", "json", "--severity", "error")
	var rows []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil || len(rows) == 0 {
		t.Fatalf("json: code=%d out=%s", code, out)
	}
	for _, r := range rows {
		if r.Severity != "ERROR" {
			t.Errorf("%s has severity %s, want ERROR only", r.ID, r.Severity)
		}
	}

	if code, out, _ := run(t, "rules", "--validate"); code != ExitOK || !strings.Contains(out, "rules are valid") {
		t.Errorf("validate: code=%d out=%s", code, out)
	}
}

func TestExplain(t *testing.T) {
	code, out, _ := run(t, "explain", "comp_sec_001")
	for _, want := range []string{"COMP_SEC_001 · Container is running in privileged mode", "Remediation", "Query", "path: privileged"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
	if code != ExitOK {
		t.Errorf("code = %d", code)
	}
	if code, _, errOut := run(t, "explain", "NOPE_SEC_999"); code != ExitUsage || !strings.Contains(errOut, "unknown rule") {
		t.Errorf("unknown rule: code=%d stderr=%s", code, errOut)
	}
	if code, _, _ := run(t, "explain"); code != ExitUsage {
		t.Errorf("missing argument: code=%d", code)
	}
}

func TestScore(t *testing.T) {
	dir := filepath.Join(fixtures, "COMP_SEC_001", "fail")
	code, out, _ := run(t, "score", dir, "-f", "json")
	var s struct{ Total, Max, Errors int }
	if code != ExitOK || json.Unmarshal([]byte(out), &s) != nil || s.Max != 100 || s.Errors == 0 {
		t.Errorf("code=%d out=%s", code, out)
	}
	if code, _, _ := run(t, "score", dir, "--min-score", "100"); code != ExitFindings {
		t.Errorf("min-score gate: code=%d", code)
	}
}
