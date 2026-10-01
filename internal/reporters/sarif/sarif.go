// Package sarif renders reports as SARIF 2.1.0, compatible with GitHub code
// scanning (github/codeql-action/upload-sarif).
package sarif

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/reporters"
)

const (
	schemaURI      = "https://json.schemastore.org/sarif-2.1.0.json"
	version        = "2.1.0"
	informationURI = "https://github.com/nexutils/StackGuard"
	srcRoot        = "%SRCROOT%"
	fingerprintKey = "stackguard/v1"
)

// Reporter is the SARIF reporter.
type Reporter struct {
	opts reporters.Options
}

// New returns a SARIF reporter.
func New(opts reporters.Options) reporters.Reporter { return &Reporter{opts: opts} }

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool         `json:"tool"`
	Results     []result     `json:"results"`
	Invocations []invocation `json:"invocations"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     text           `json:"shortDescription"`
	FullDescription      text           `json:"fullDescription"`
	Help                 help           `json:"help"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration config         `json:"defaultConfiguration"`
	Properties           ruleProperties `json:"properties"`
}

type text struct {
	Text string `json:"text"`
}

type help struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type config struct {
	Level string `json:"level"`
}

type ruleProperties struct {
	Tags []string `json:"tags"`
	// SecuritySeverity drives the severity shown by GitHub code scanning for
	// security rules.
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type invocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

func level(s models.Severity) string {
	switch s {
	case models.SeverityError:
		return "error"
	case models.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(s models.Severity) string {
	switch s {
	case models.SeverityError:
		return "8.0"
	case models.SeverityWarning:
		return "5.5"
	default:
		return "2.0"
	}
}

func (s *Reporter) Report(w io.Writer, r *models.Report) error {
	base := s.opts.BaseDir
	if base == "" {
		base, _ = os.Getwd()
	}

	drv := driver{Name: "StackGuard", Version: s.opts.ToolVersion, InformationURI: informationURI, Rules: []rule{}}
	index := map[string]int{}
	for _, rr := range r.Results {
		if rr.Rule == nil {
			continue
		}
		index[rr.RuleID] = len(drv.Rules)
		drv.Rules = append(drv.Rules, toRule(rr.Rule))
	}

	results := make([]result, 0, len(r.Findings))
	for _, f := range r.Findings {
		idx, ok := index[f.RuleID]
		if !ok {
			// Finding for a rule not in Results; describe it minimally.
			idx = len(drv.Rules)
			index[f.RuleID] = idx
			drv.Rules = append(drv.Rules, toRule(&models.Rule{ID: f.RuleID, Title: f.Title, Severity: f.Severity, Category: f.Category, Target: f.Target, Remediation: f.Remediation}))
		}
		results = append(results, result{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     level(f.Severity),
			Message:   text{Text: f.Message},
			Locations: []location{{PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{URI: relURI(base, f.File), URIBaseID: srcRoot},
				Region:           region{StartLine: max(1, f.Line), StartColumn: f.Column},
			}}},
			PartialFingerprints: map[string]string{fingerprintKey: f.Fingerprint},
		})
	}

	doc := log{
		Schema:  schemaURI,
		Version: version,
		Runs: []run{{
			Tool:        tool{Driver: drv},
			Results:     results,
			Invocations: []invocation{{ExecutionSuccessful: true}},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func toRule(r *models.Rule) rule {
	desc := r.Description
	if desc == "" {
		desc = r.Title
	}
	md := "**" + r.Title + "**\n\n" + desc
	if r.Remediation != "" {
		md += "\n\n**Remediation**\n\n" + r.Remediation
	}
	plain := desc
	if r.Remediation != "" {
		plain += "\n\nRemediation: " + r.Remediation
	}
	props := ruleProperties{Tags: append([]string{r.Category, r.Target}, r.Tags...)}
	if r.Category == models.CategorySecurity {
		props.Tags = append(props.Tags, "security")
		props.SecuritySeverity = securitySeverity(r.Severity)
	}
	var helpURI string
	if len(r.References) > 0 {
		helpURI = r.References[0]
	}
	return rule{
		ID:                   r.ID,
		Name:                 pascal(r.Title),
		ShortDescription:     text{Text: r.Title},
		FullDescription:      text{Text: desc},
		Help:                 help{Text: plain, Markdown: md},
		HelpURI:              helpURI,
		DefaultConfiguration: config{Level: level(r.Severity)},
		Properties:           props,
	}
}

func relURI(base, file string) string {
	p := file
	if filepath.IsAbs(p) {
		if rel, err := filepath.Rel(base, p); err == nil {
			p = rel
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(p), "./")
}

// pascal turns a title into a SARIF-friendly rule name ("Privileged
// container" -> "PrivilegedContainer").
func pascal(s string) string {
	var b strings.Builder
	upper := true
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			if upper {
				c -= 'a' - 'A'
			}
			b.WriteRune(c)
			upper = false
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteRune(c)
			upper = false
		default:
			upper = true
		}
	}
	return b.String()
}
