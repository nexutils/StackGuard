// Package csv renders findings as RFC 4180 CSV — one header row followed by
// one row per finding.
package csv

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/reporters"
)

var header = []string{
	"rule_id", "severity", "category", "target",
	"file", "line", "resource", "title", "message",
}

// Reporter is the CSV reporter.
type Reporter struct{}

// New returns a CSV reporter.
func New(_ reporters.Options) reporters.Reporter { return &Reporter{} }

func (c *Reporter) Report(w io.Writer, r *models.Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, f := range r.Findings {
		row := []string{
			f.RuleID,
			f.Severity.String(),
			f.Category,
			f.Target,
			f.File,
			strconv.Itoa(f.Line),
			f.Resource,
			f.Title,
			f.Message,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
