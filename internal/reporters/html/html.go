// Package html renders reports as a single self-contained HTML page with no
// external assets, suitable for CI artifacts.
package html

import (
	_ "embed"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/reporters"
)

//go:embed report.html.tmpl
var tmplSource string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sevClass": func(s models.Severity) string {
		switch s {
		case models.SeverityError:
			return "error"
		case models.SeverityWarning:
			return "warning"
		default:
			return "info"
		}
	},
	"scoreClass": func(total int) string {
		switch {
		case total < 50:
			return "bad"
		case total < 80:
			return "fair"
		default:
			return "good"
		}
	},
	"shortSHA": func(sha string) string {
		if len(sha) > 8 {
			return sha[:8]
		}
		return sha
	},
	"join": strings.Join,
}).Parse(tmplSource))

// Reporter is the HTML reporter.
type Reporter struct {
	opts reporters.Options
}

// New returns an HTML reporter.
func New(opts reporters.Options) reporters.Reporter { return &Reporter{opts: opts} }

type fileGroup struct {
	File     string
	Findings []models.Finding
}

type passedRule struct {
	ID      string
	Message string
}

type view struct {
	Report     *models.Report
	Version    string
	Files      []fileGroup
	Passed     []passedRule
	Repository *models.RepoMetadata
	Config     *models.ScanConfig
}

func (h *Reporter) Report(w io.Writer, r *models.Report) error {
	v := view{Report: r, Version: h.opts.ToolVersion, Repository: r.Repository, Config: r.Config}
	byFile := map[string][]models.Finding{}
	for _, f := range r.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}
	for file, fs := range byFile {
		v.Files = append(v.Files, fileGroup{File: file, Findings: fs})
	}
	sort.Slice(v.Files, func(i, j int) bool { return v.Files[i].File < v.Files[j].File })
	for _, rr := range r.Results {
		if rr.Status != models.RulePassed || rr.Rule == nil {
			continue
		}
		msg := rr.Rule.PassMessage
		if msg == "" {
			msg = rr.Rule.Title
		}
		v.Passed = append(v.Passed, passedRule{ID: rr.RuleID, Message: msg})
	}
	return tmpl.Execute(w, v)
}
