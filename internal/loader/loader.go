// Package loader loads rule definitions from layered file systems.
//
// Layers are applied in order; a rule in a later layer replaces a rule with
// the same ID from an earlier layer. The CLI uses:
//
//  1. embedded rules
//  2. ~/.stackguard/rules
//  3. <project>/.stackguard/rules
//  4. directories from config `rules_dirs` and --rules-dir
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/template"

	"go.yaml.in/yaml/v3"

	"github.com/nexutils/StackGuard/internal/engine/query"
	"github.com/nexutils/StackGuard/internal/models"
)

var idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*_[A-Z]+_[0-9]{3,}$`)

// Layer is a named source of rule files.
type Layer struct {
	Name string
	FS   fs.FS
	// Embedded marks layers compiled into the binary; their rule Source is
	// prefixed with "embedded:".
	Embedded bool
	// Root is the directory the FS was opened from, used to build readable
	// Source paths for on-disk layers.
	Root string
}

// DirLayer returns a layer for an on-disk directory, or false if the
// directory does not exist.
func DirLayer(name, dir string) (Layer, bool) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return Layer{}, false
	}
	return Layer{Name: name, FS: os.DirFS(dir), Root: dir}, true
}

// Options customise validation.
type Options struct {
	// KnownTargets restricts rule targets. Empty disables the check.
	KnownTargets []string
}

// RuleSet is the merged result of loading all layers.
type RuleSet struct {
	byID map[string]*models.Rule
}

// All returns every rule sorted by ID.
func (s *RuleSet) All() []*models.Rule {
	out := make([]*models.Rule, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns the rule with the given ID (case-insensitive).
func (s *RuleSet) Get(id string) (*models.Rule, bool) {
	r, ok := s.byID[strings.ToUpper(strings.TrimSpace(id))]
	return r, ok
}

// Len returns the number of rules.
func (s *RuleSet) Len() int { return len(s.byID) }

// ValidationError aggregates every problem found while loading, so authors
// can fix them all in one pass.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "invalid rule: " + e.Problems[0]
	}
	return fmt.Sprintf("%d invalid rules:\n  - %s", len(e.Problems), strings.Join(e.Problems, "\n  - "))
}

// Load reads and validates all layers. On validation problems it returns the
// rules that did load together with a *ValidationError.
func Load(opts Options, layers ...Layer) (*RuleSet, error) {
	set := &RuleSet{byID: map[string]*models.Rule{}}
	var problems []string
	for _, layer := range layers {
		inLayer := map[string]string{}
		err := fs.WalkDir(layer.FS, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !isYAML(p) {
				return nil
			}
			data, err := fs.ReadFile(layer.FS, p)
			if err != nil {
				return err
			}
			source := sourceName(layer, p)
			rules, errs := parseFile(data, source, opts)
			problems = append(problems, errs...)
			for _, r := range rules {
				if prev, dup := inLayer[r.ID]; dup {
					problems = append(problems, fmt.Sprintf("%s: duplicate rule ID %s (also in %s)", source, r.ID, prev))
					continue
				}
				inLayer[r.ID] = source
				set.byID[r.ID] = r
			}
			return nil
		})
		if err != nil {
			return set, fmt.Errorf("loading rules from %s: %w", layer.Name, err)
		}
	}
	if len(problems) > 0 {
		return set, &ValidationError{Problems: problems}
	}
	return set, nil
}

func sourceName(l Layer, p string) string {
	if l.Embedded {
		return "embedded:" + p
	}
	if l.Root != "" {
		return path.Join(strings.ReplaceAll(l.Root, `\`, "/"), p)
	}
	return l.Name + ":" + p
}

func isYAML(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// ruleDoc is the on-disk rule schema. Unknown fields are rejected.
type ruleDoc struct {
	ID          string     `yaml:"id"`
	Title       string     `yaml:"title"`
	Severity    string     `yaml:"severity"`
	Category    string     `yaml:"category"`
	Target      string     `yaml:"target"`
	Resource    stringList `yaml:"resource"`
	Message     string     `yaml:"message"`
	PassMessage string     `yaml:"pass_message"`
	Description string     `yaml:"description"`
	Remediation string     `yaml:"remediation"`
	References  []string   `yaml:"references"`
	Tags        []string   `yaml:"tags"`
	Query       yaml.Node  `yaml:"query"`
	When        yaml.Node  `yaml:"when"`
	Enabled     *bool      `yaml:"enabled"`
	Fix         any        `yaml:"fix"`
}

// renderYAML re-encodes a node, preserving key order and comments.
func renderYAML(n *yaml.Node) string {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return ""
	}
	return buf.String()
}

func renderWhen(n *yaml.Node) string {
	if n.Kind == 0 {
		return ""
	}
	return renderYAML(n)
}

// stringList accepts either a single string or a list of strings.
type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*s = []string{n.Value}
		return nil
	case yaml.SequenceNode:
		var l []string
		if err := n.Decode(&l); err != nil {
			return err
		}
		*s = l
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list of strings", n.Line)
}

// parseFile decodes every YAML document in data as a rule.
func parseFile(data []byte, source string, opts Options) ([]*models.Rule, []string) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var (
		rules    []*models.Rule
		problems []string
	)
	for i := 0; ; i++ {
		var doc ruleDoc
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", source, err))
			break
		}
		r, errs := build(doc, source, opts)
		if len(errs) > 0 {
			label := source
			if doc.ID != "" {
				label += " (" + doc.ID + ")"
			}
			for _, e := range errs {
				problems = append(problems, label+": "+e)
			}
			continue
		}
		rules = append(rules, r)
	}
	return rules, problems
}

func build(d ruleDoc, source string, opts Options) (*models.Rule, []string) {
	var errs []string
	need := func(field, v string) {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, field+" is required")
		}
	}
	need("id", d.ID)
	need("title", d.Title)
	need("severity", d.Severity)
	need("category", d.Category)
	need("target", d.Target)
	need("message", d.Message)

	if d.ID != "" && !idPattern.MatchString(d.ID) {
		errs = append(errs, fmt.Sprintf("id %q must look like TARGET_CATEGORY_NNN (e.g. COMP_SEC_001)", d.ID))
	}
	sev, err := models.ParseSeverity(d.Severity)
	if d.Severity != "" && err != nil {
		errs = append(errs, err.Error())
	}
	if d.Category != "" && !slices.Contains(models.Categories, d.Category) {
		errs = append(errs, fmt.Sprintf("unknown category %q (want one of %s)", d.Category, strings.Join(models.Categories, ", ")))
	}
	if d.Target != "" && len(opts.KnownTargets) > 0 && !slices.Contains(opts.KnownTargets, d.Target) {
		errs = append(errs, fmt.Sprintf("unknown target %q (want one of %s)", d.Target, strings.Join(opts.KnownTargets, ", ")))
	}
	for _, g := range d.Resource {
		if _, err := path.Match(g, ""); err != nil {
			errs = append(errs, fmt.Sprintf("bad resource glob %q: %v", g, err))
		}
	}
	var q, when any
	if d.Query.Kind == 0 {
		errs = append(errs, "query is required")
	} else if err := d.Query.Decode(&q); err != nil {
		errs = append(errs, "query: "+err.Error())
	} else if _, err := query.Compile(q); err != nil {
		errs = append(errs, err.Error())
	}
	if d.When.Kind != 0 {
		if err := d.When.Decode(&when); err != nil {
			errs = append(errs, "when: "+err.Error())
		} else if _, err := query.Compile(when); err != nil {
			errs = append(errs, "when: "+err.Error())
		}
	}
	for field, text := range map[string]string{"message": d.Message, "pass_message": d.PassMessage} {
		if _, err := template.New(field).Parse(text); err != nil {
			errs = append(errs, fmt.Sprintf("%s template: %v", field, err))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errs
	}
	return &models.Rule{
		ID:           d.ID,
		Title:        d.Title,
		Severity:     sev,
		Category:     d.Category,
		Target:       d.Target,
		Resources:    d.Resource,
		Message:      strings.TrimSpace(d.Message),
		PassMessage:  strings.TrimSpace(d.PassMessage),
		Description:  strings.TrimSpace(d.Description),
		Remediation:  strings.TrimSpace(d.Remediation),
		References:   d.References,
		Tags:         d.Tags,
		Query:        q,
		QueryYAML:    renderYAML(&d.Query),
		When:         when,
		WhenYAML:     renderWhen(&d.When),
		OffByDefault: d.Enabled != nil && !*d.Enabled,
		Fix:          d.Fix,
		Source:       source,
	}, nil
}
