// Package reporters defines how scan reports are rendered. Each format lives
// in its own sub-package; package all wires them together.
package reporters

import (
	"io"

	"github.com/nexutils/StackGuard/internal/models"
)

// Reporter renders a report to a writer.
type Reporter interface {
	Report(w io.Writer, r *models.Report) error
}

// Options are shared by every reporter; each uses what applies to it.
type Options struct {
	// Color enables ANSI colors (console only).
	Color bool
	// Quiet limits console output to findings and the score line.
	Quiet bool
	// ShowPassed lists every passed rule in the console reporter. When false
	// (the default) passed rules are collapsed to a summary line.
	ShowPassed bool
	// OmitSkipped drops rules with status "skipped" from the JSON report's
	// rules array. When false (the default) the array is the full ledger.
	OmitSkipped bool
	// ToolVersion is embedded in machine-readable formats.
	ToolVersion string
	// BaseDir is used to make file paths relative (SARIF requires relative
	// URIs for GitHub code scanning). Empty means the current directory.
	BaseDir string
}

// Factory builds a reporter.
type Factory func(Options) Reporter
