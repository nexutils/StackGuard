package models

// Finding is a single rule violation on a single resource.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Target      string   `json:"target"`
	File        string   `json:"file"`
	Resource    string   `json:"resource"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	Line        int      `json:"line"`
	Column      int      `json:"column,omitempty"`
	// Path is the property path that triggered the finding, if known.
	Path string `json:"path,omitempty"`
	// Fingerprint identifies the finding independently of line numbers, so it
	// stays stable when unrelated lines move. Used for SARIF and baselines.
	Fingerprint string `json:"fingerprint"`
}
