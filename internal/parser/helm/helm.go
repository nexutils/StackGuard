// Package helm parses a Helm chart into a single "helm" resource per chart,
// anchored on Chart.yaml.
//
// The chart is rendered in-process (render.go: text/template + sprig + Helm's
// own helpers, the way `helm template` does with default values) and the output
// is fed through the kubernetes model, so the resource exposes rendered.* in
// exactly the kubernetes shape (rendered.containers[*].sc, rendered.workloads[*]
// .has_pdb, ...). It also exposes values, values_entries[*], chart, templates[*]
// and context.files[*]. See model.go. values.yaml and template files are claimed
// by CanParse (so other parsers skip them) but fold into the chart's resource.
package helm

import (
	"context"
	"os"
	"path/filepath"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

const Target = "helm"

// Parser implements parser.Parser for Helm charts.
type Parser struct {
	// exists is swappable for tests.
	exists func(path string) bool
}

func New() *Parser {
	return &Parser{exists: func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	}}
}

func (*Parser) Name() string { return Target }

func (p *Parser) CanParse(f *parser.FileInfo) bool {
	base := f.Base()
	switch {
	case base == "Chart.yaml":
		return true
	case base == "values.yaml":
		return p.exists(filepath.Join(filepath.Dir(f.Path), "Chart.yaml"))
	default:
		return p.templateFile(f.Path)
	}
}

// templateFile reports whether path is inside a chart's templates/ directory.
func (p *Parser) templateFile(path string) bool {
	for dir := filepath.Dir(path); ; {
		if filepath.Base(dir) == "templates" {
			return p.exists(filepath.Join(filepath.Dir(dir), "Chart.yaml"))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

func (p *Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	// One "helm" resource per chart, anchored on Chart.yaml. values.yaml and
	// template files are claimed by CanParse (so other parsers skip them) but
	// fold into the chart's resource rather than producing their own.
	if filepath.Base(src.Path) != "Chart.yaml" || src.Path == "" {
		return nil, nil
	}
	return buildChart(src.Path)
}
