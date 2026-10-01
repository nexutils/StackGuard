// Package console renders reports for humans in a terminal.
package console

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/reporters"
)

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
)

// Reporter is the console reporter.
type Reporter struct {
	opts reporters.Options
}

// New returns a console reporter.
func New(opts reporters.Options) reporters.Reporter { return &Reporter{opts: opts} }

func (c *Reporter) paint(color, s string) string {
	if !c.opts.Color {
		return s
	}
	return color + s + reset
}

func (c *Reporter) symbol(s models.Severity) string {
	switch s {
	case models.SeverityError:
		return c.paint(red, "✗")
	case models.SeverityWarning:
		return c.paint(yellow, "⚠")
	default:
		return c.paint(cyan, "ℹ")
	}
}

func (c *Reporter) Report(out io.Writer, r *models.Report) error {
	w := bufio.NewWriter(out)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "%s No issues found\n", c.paint(green, "✓"))
	}
	file := "\x00"
	for _, f := range r.Findings {
		if f.File != file {
			if file != "\x00" {
				fmt.Fprintln(w)
			}
			file = f.File
			fmt.Fprintln(w, c.paint(bold, f.File))
		}
		fmt.Fprintf(w, "  %s %s  %s\n", c.symbol(f.Severity), f.Message,
			c.paint(dim, fmt.Sprintf("%s · line %d", f.RuleID, f.Line)))
	}

	if !c.opts.Quiet {
		var passed []models.RuleResult
		for _, rr := range r.Results {
			if rr.Status == models.RulePassed {
				passed = append(passed, rr)
			}
		}
		if len(passed) > 0 {
			fmt.Fprintf(w, "\n%s\n", c.paint(bold, "Passed"))
			for _, rr := range passed {
				text := rr.RuleID
				if rr.Rule != nil {
					text = rr.Rule.PassMessage
					if text == "" {
						text = rr.Rule.Title
					}
				}
				fmt.Fprintf(w, "  %s %s  %s\n", c.paint(green, "✓"), text, c.paint(dim, rr.RuleID))
			}
		}
		if len(r.Diagnostics) > 0 {
			fmt.Fprintf(w, "\n%s\n", c.paint(bold, "Could not parse"))
			for _, d := range r.Diagnostics {
				fmt.Fprintf(w, "  %s %s: %s\n", c.paint(yellow, "!"), d.File, d.Message)
			}
		}
	}

	fmt.Fprintf(w, "\n%s  %s\n", c.scoreLine(r.Score), c.paint(dim, strings.Join([]string{
		plural(r.Score.Errors, "error", "errors"),
		plural(r.Score.Warnings, "warning", "warnings"),
		plural(r.Score.Infos, "info", "info"),
		plural(r.Stats.FilesParsed, "file", "files"),
		plural(r.Stats.Resources, "resource", "resources"),
		plural(r.Stats.RulesEvaluated, "rule", "rules"),
	}, " · ")))
	if !c.opts.Quiet && len(r.Findings) > 0 {
		fmt.Fprintln(w, c.paint(dim, "Run 'stackguard explain <RULE_ID>' for details and remediation."))
	}
	return w.Flush()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (c *Reporter) scoreLine(s models.Score) string {
	color := green
	switch {
	case s.Total < 50:
		color = red
	case s.Total < 80:
		color = yellow
	}
	return c.paint(bold, "Score: ") + c.paint(bold+color, fmt.Sprintf("%d/%d", s.Total, s.Max))
}
