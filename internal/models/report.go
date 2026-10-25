package models

// ReportSchemaVersion is bumped whenever the JSON report shape changes in a
// backwards-incompatible way.
const ReportSchemaVersion = "2"

// RepoMetadata identifies the repository that was scanned, when available.
type RepoMetadata struct {
	Name       string `json:"name,omitempty"`
	RemoteURL  string `json:"remote_url,omitempty"`
	Branch     string `json:"branch,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`
	CommitDate string `json:"commit_date,omitempty"`
}

// Score summarises findings as a single number plus per-severity counts.
type Score struct {
	Total    int `json:"total"`
	Max      int `json:"max"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
}

// RuleStatus describes the outcome of one rule over a whole scan.
type RuleStatus string

const (
	// RulePassed means the rule ran against at least one resource and found nothing.
	RulePassed RuleStatus = "passed"
	// RuleFailed means the rule produced at least one finding.
	RuleFailed RuleStatus = "failed"
	// RuleSkipped means no resource of the rule's target was scanned.
	RuleSkipped RuleStatus = "skipped"
)

// RuleResult is the per-rule outcome of a scan.
type RuleResult struct {
	Rule      *Rule      `json:"-"`
	RuleID    string     `json:"rule_id"`
	Status    RuleStatus `json:"status"`
	Evaluated int        `json:"evaluated"`
	Findings  int        `json:"findings"`
}

// Diagnostic is a non-fatal problem encountered while scanning, such as a
// file that failed to parse.
type Diagnostic struct {
	File    string `json:"file"`
	Parser  string `json:"parser,omitempty"`
	Message string `json:"message"`
}

// ScanStats carries counters about a scan.
type ScanStats struct {
	FilesDiscovered int   `json:"files_discovered"`
	FilesParsed     int   `json:"files_parsed"`
	Resources       int   `json:"resources"`
	RulesEvaluated  int   `json:"rules_evaluated"`
	Suppressed      int    `json:"suppressed"`
	DurationMillis  int64  `json:"duration_ms"`
	ScannedAt       string `json:"scanned_at,omitempty"`
}

// Report is the complete result of a scan and the input to every reporter.
type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Repository    *RepoMetadata `json:"repository,omitempty"`
	Score         Score         `json:"score"`
	Findings      []Finding     `json:"findings"`
	Results       []RuleResult  `json:"results"`
	Diagnostics   []Diagnostic  `json:"diagnostics"`
	Stats         ScanStats     `json:"stats"`
}
