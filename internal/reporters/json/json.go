// Package json renders reports as a stable, versioned JSON document.
package json

import (
	"encoding/json"
	"io"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/reporters"
)

// Document is the JSON report schema (schema_version "1").
type Document struct {
	SchemaVersion string              `json:"schema_version"`
	Tool          Tool                `json:"tool"`
	Score         int                 `json:"score"`
	Summary       models.Score        `json:"summary"`
	Findings      []models.Finding    `json:"findings"`
	Rules         []RuleResult        `json:"rules"`
	Diagnostics   []models.Diagnostic `json:"diagnostics"`
	Stats         models.ScanStats    `json:"stats"`
}

// Tool identifies the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RuleResult is a rule's outcome with enough metadata to be self-describing.
type RuleResult struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Severity  models.Severity   `json:"severity"`
	Category  string            `json:"category"`
	Target    string            `json:"target"`
	Status    models.RuleStatus `json:"status"`
	Evaluated int               `json:"evaluated"`
	Findings  int               `json:"findings"`
}

// Reporter is the JSON reporter.
type Reporter struct {
	opts reporters.Options
}

// New returns a JSON reporter.
func New(opts reporters.Options) reporters.Reporter { return &Reporter{opts: opts} }

func (j *Reporter) Report(w io.Writer, r *models.Report) error {
	doc := Document{
		SchemaVersion: r.SchemaVersion,
		Tool:          Tool{Name: "stackguard", Version: j.opts.ToolVersion},
		Score:         r.Score.Total,
		Summary:       r.Score,
		Findings:      r.Findings,
		Rules:         make([]RuleResult, 0, len(r.Results)),
		Diagnostics:   r.Diagnostics,
		Stats:         r.Stats,
	}
	if doc.Findings == nil {
		doc.Findings = []models.Finding{}
	}
	if doc.Diagnostics == nil {
		doc.Diagnostics = []models.Diagnostic{}
	}
	for _, rr := range r.Results {
		if j.opts.OmitSkipped && rr.Status == models.RuleSkipped {
			continue
		}
		out := RuleResult{ID: rr.RuleID, Status: rr.Status, Evaluated: rr.Evaluated, Findings: rr.Findings}
		if rr.Rule != nil {
			out.Title, out.Severity, out.Category, out.Target = rr.Rule.Title, rr.Rule.Severity, rr.Rule.Category, rr.Rule.Target
		}
		doc.Rules = append(doc.Rules, out)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
