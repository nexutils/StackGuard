package all

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/reporters"
	"github.com/nexutils/StackGuard/internal/testutil"
)

const goldenDir = "../../../testdata/reporters"

func sampleReport() *models.Report {
	privileged := &models.Rule{
		ID: "COMP_SEC_001", Title: "Privileged container", Severity: models.SeverityError,
		Category: models.CategorySecurity, Target: "compose", Tags: []string{"cis-docker-5.4"},
		Description: "Privileged containers can take over the host.",
		Remediation: "Remove `privileged: true`.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#privileged"},
		PassMessage: "No services run in privileged mode",
	}
	memory := &models.Rule{
		ID: "COMP_OPS_001", Title: "Missing memory limit", Severity: models.SeverityWarning,
		Category: models.CategoryOperational, Target: "compose",
		PassMessage: "All services have a memory limit",
	}
	pinned := &models.Rule{
		ID: "COMP_MNT_001", Title: "Unpinned image version", Severity: models.SeverityWarning,
		Category: models.CategoryMaintainability, Target: "compose",
		PassMessage: "Containers use pinned image versions",
	}
	tf := &models.Rule{ID: "TF_SEC_001", Title: "Public S3 bucket ACL", Severity: models.SeverityError, Category: models.CategorySecurity, Target: "terraform"}
	return &models.Report{
		SchemaVersion: models.ReportSchemaVersion,
		Score:         models.Score{Total: 87, Max: 100, Errors: 1, Warnings: 1},
		Findings: []models.Finding{
			{RuleID: "COMP_SEC_001", Title: privileged.Title, Severity: models.SeverityError, Category: "security", Target: "compose",
				File: "docker-compose.yml", Resource: "api", Message: "Service 'api' runs in privileged mode <b>",
				Remediation: privileged.Remediation, Line: 4, Column: 5, Path: "privileged", Fingerprint: "aaaa"},
			{RuleID: "COMP_OPS_001", Title: memory.Title, Severity: models.SeverityWarning, Category: "operational", Target: "compose",
				File: "docker-compose.yml", Resource: "redis", Message: "Service 'redis' has no memory limit",
				Line: 9, Fingerprint: "bbbb"},
		},
		Results: []models.RuleResult{
			{Rule: memory, RuleID: memory.ID, Status: models.RuleFailed, Evaluated: 2, Findings: 1},
			{Rule: pinned, RuleID: pinned.ID, Status: models.RulePassed, Evaluated: 2},
			{Rule: privileged, RuleID: privileged.ID, Status: models.RuleFailed, Evaluated: 2, Findings: 1},
			{Rule: tf, RuleID: tf.ID, Status: models.RuleSkipped},
		},
		Diagnostics: []models.Diagnostic{{File: "broken.yml", Parser: "compose", Message: "yaml: line 2: did not find expected key"}},
		Stats:       models.ScanStats{FilesDiscovered: 3, FilesParsed: 1, Resources: 2, RulesEvaluated: 4, DurationMillis: 12},
	}
}

func render(t *testing.T, format string, opts reporters.Options, rep *models.Report) []byte {
	t.Helper()
	r, err := New(format, opts)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := r.Report(&buf, rep); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGolden(t *testing.T) {
	opts := reporters.Options{ToolVersion: "1.2.3", BaseDir: "/work"}
	for format, file := range map[string]string{
		"console": "console.golden.txt",
		"json":    "report.golden.json",
		"sarif":   "report.golden.sarif",
		"html":    "report.golden.html",
	} {
		t.Run(format, func(t *testing.T) {
			testutil.Golden(t, filepath.Join(goldenDir, file), render(t, format, opts, sampleReport()))
		})
	}
}

func TestConsoleVariants(t *testing.T) {
	quiet := render(t, "console", reporters.Options{Quiet: true}, sampleReport())
	if bytes.Contains(quiet, []byte("Passed")) || bytes.Contains(quiet, []byte("Could not parse")) {
		t.Errorf("quiet output should omit passed rules and diagnostics:\n%s", quiet)
	}
	colored := render(t, "console", reporters.Options{Color: true}, sampleReport())
	if !bytes.Contains(colored, []byte("\x1b[31m✗")) {
		t.Error("color output should contain ANSI codes")
	}
	clean := render(t, "console", reporters.Options{}, &models.Report{Score: models.Score{Total: 100, Max: 100}})
	if !strings.HasPrefix(string(clean), "✓ No issues found") {
		t.Errorf("clean report:\n%s", clean)
	}

	summary := render(t, "console", reporters.Options{}, sampleReport())
	if !bytes.Contains(summary, []byte("✓ 1 passed")) || !bytes.Contains(summary, []byte("compose 1")) {
		t.Errorf("default console should summarise passed rules:\n%s", summary)
	}
	if bytes.Contains(summary, []byte("Containers use pinned image versions")) {
		t.Errorf("default console should not list each passed rule:\n%s", summary)
	}
	if !bytes.Contains(summary, []byte("--show-passed")) {
		t.Errorf("summary should hint at --show-passed:\n%s", summary)
	}

	full := render(t, "console", reporters.Options{ShowPassed: true}, sampleReport())
	if !bytes.Contains(full, []byte("Containers use pinned image versions")) {
		t.Errorf("--show-passed should list each passed rule:\n%s", full)
	}
}

func TestJSONOmitSkipped(t *testing.T) {
	// The sample report's tf rule is skipped (no terraform resources scanned).
	var full struct {
		Rules []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(render(t, "json", reporters.Options{}, sampleReport()), &full); err != nil {
		t.Fatal(err)
	}
	var skippedSeen bool
	for _, r := range full.Rules {
		if r.Status == "skipped" {
			skippedSeen = true
		}
	}
	if !skippedSeen {
		t.Fatal("default JSON should include skipped rules (sample has TF_SEC_001 skipped)")
	}

	var trimmed struct {
		Rules []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(render(t, "json", reporters.Options{OmitSkipped: true}, sampleReport()), &trimmed); err != nil {
		t.Fatal(err)
	}
	if len(trimmed.Rules) >= len(full.Rules) {
		t.Errorf("OmitSkipped should drop rules: got %d, full had %d", len(trimmed.Rules), len(full.Rules))
	}
	for _, r := range trimmed.Rules {
		if r.Status == "skipped" {
			t.Errorf("OmitSkipped left a skipped rule: %s", r.ID)
		}
		if r.Status != "passed" && r.Status != "failed" {
			t.Errorf("unexpected status %q for %s", r.Status, r.ID)
		}
	}
}

func TestSARIFOmitSkipped(t *testing.T) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(render(t, "sarif", reporters.Options{OmitSkipped: true}, sampleReport()), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == "TF_SEC_001" { // the sample's skipped rule
			t.Error("OmitSkipped should drop skipped rule TF_SEC_001 from driver.rules")
		}
	}
	// ruleIndex references must still resolve to the correct rule after trimming.
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of range (%d rules)", res.RuleIndex, len(run.Tool.Driver.Rules))
		}
		if got := run.Tool.Driver.Rules[res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("ruleIndex %d points at %s, want %s", res.RuleIndex, got, res.RuleID)
		}
	}
}

// TestSARIFShape checks the properties GitHub code scanning relies on.
func TestSARIFShape(t *testing.T) {
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	base := t.TempDir()
	rep := sampleReport()
	rep.Findings[0].File = filepath.Join(base, "deploy", "docker-compose.yml")
	rep.Findings[1].Line = 0
	if err := json.Unmarshal(render(t, "sarif", reporters.Options{BaseDir: base}, rep), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", doc)
	}
	run := doc.Runs[0]
	for _, res := range run.Results {
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex %d does not point at %s", res.RuleIndex, res.RuleID)
		}
		loc := res.Locations[0].PhysicalLocation
		if loc.Region.StartLine < 1 {
			t.Errorf("startLine must be >= 1, got %d", loc.Region.StartLine)
		}
		if strings.HasPrefix(loc.ArtifactLocation.URI, "/") {
			t.Errorf("URI must be relative, got %q", loc.ArtifactLocation.URI)
		}
		if res.PartialFingerprints["stackguard/v1"] == "" {
			t.Error("missing partial fingerprint")
		}
	}
	if got := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "deploy/docker-compose.yml" {
		t.Errorf("URI = %q", got)
	}
}

func TestHTMLEscapes(t *testing.T) {
	out := render(t, "html", reporters.Options{}, sampleReport())
	if bytes.Contains(out, []byte("privileged mode <b>")) {
		t.Error("finding messages must be HTML-escaped")
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := New("xml", reporters.Options{}); err == nil {
		t.Error("expected error for unknown format")
	}
}
