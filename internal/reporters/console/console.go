// Package console renders reports for humans in a terminal.
package console

import (
	"bufio"
	"fmt"
	"io"
	"sort"
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

	if repo := r.Repository; repo != nil {
		parts := []string{}
		if repo.Name != "" {
			parts = append(parts, repo.Name)
		}
		if repo.Branch != "" {
			parts = append(parts, repo.Branch)
		}
		if repo.CommitSHA != "" {
			sha := repo.CommitSHA
			if len(sha) > 8 {
				sha = sha[:8]
			}
			parts = append(parts, sha)
		}
		if len(parts) > 0 {
			fmt.Fprintln(w, c.paint(dim, strings.Join(parts, " · ")))
			fmt.Fprintln(w)
		}
	}

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
		var failed int
		for _, rr := range r.Results {
			switch rr.Status {
			case models.RulePassed:
				passed = append(passed, rr)
			case models.RuleFailed:
				failed++
			}
		}
		if len(passed) > 0 {
			if c.opts.ShowPassed {
				c.writePassedList(w, passed)
			} else {
				c.writePassedSummary(w, passed, failed)
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

// writePassedList prints one line per passed rule (shown with --show-passed).
func (c *Reporter) writePassedList(w io.Writer, passed []models.RuleResult) {
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

// writePassedSummary collapses passed rules to a count, a per-target breakdown
// and a pass-ratio bar. This is the default so findings stay on screen.
func (c *Reporter) writePassedSummary(w io.Writer, passed []models.RuleResult, failed int) {
	counts := map[string]int{}
	var order []string
	for _, rr := range passed {
		t := "other"
		if rr.Rule != nil && rr.Rule.Target != "" {
			t = rr.Rule.Target
		}
		if counts[t] == 0 {
			order = append(order, t)
		}
		counts[t]++
	}
	sort.Slice(order, func(i, j int) bool {
		if counts[order[i]] != counts[order[j]] {
			return counts[order[i]] > counts[order[j]]
		}
		return order[i] < order[j]
	})
	parts := make([]string, len(order))
	for i, t := range order {
		parts[i] = fmt.Sprintf("%s %d", t, counts[t])
	}

	fmt.Fprintf(w, "\n%s", c.paint(green, fmt.Sprintf("✓ %d passed", len(passed))))
	if len(parts) > 0 {
		fmt.Fprintf(w, "  %s", c.paint(dim, strings.Join(parts, " · ")))
	}
	fmt.Fprintln(w)

	total := len(passed) + failed
	fmt.Fprintf(w, "  %s  %s\n", c.passBar(len(passed), total),
		c.paint(dim, fmt.Sprintf("%d/%d · %d%%   run with --show-passed to list", len(passed), total, pct(len(passed), total))))
}

// passBar renders a fixed-width pass-ratio bar, degrading to ASCII when colors
// are disabled.
func (c *Reporter) passBar(passed, total int) string {
	const width = 24
	fill := width
	if total > 0 {
		fill = passed * width / total
		if fill == 0 && passed > 0 {
			fill = 1
		}
	}
	if fill > width {
		fill = width
	}
	if !c.opts.Color {
		return "[" + strings.Repeat("#", fill) + strings.Repeat("-", width-fill) + "]"
	}
	return c.paint(green, strings.Repeat("█", fill)) + c.paint(dim, strings.Repeat("░", width-fill))
}

// pct returns n/d as a rounded percentage, guarding against division by zero.
func pct(n, d int) int {
	if d <= 0 {
		return 0
	}
	return (n*100 + d/2) / d
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
