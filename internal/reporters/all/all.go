// Package all wires every built-in report format.
package all

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nexutils/StackGuard/internal/reporters"
	"github.com/nexutils/StackGuard/internal/reporters/console"
	"github.com/nexutils/StackGuard/internal/reporters/csv"
	"github.com/nexutils/StackGuard/internal/reporters/html"
	"github.com/nexutils/StackGuard/internal/reporters/json"
	"github.com/nexutils/StackGuard/internal/reporters/sarif"
)

var factories = map[string]reporters.Factory{
	"console": console.New,
	"csv":     csv.New,
	"json":    json.New,
	"sarif":   sarif.New,
	"html":    html.New,
}

// New returns the reporter for a format name.
func New(format string, opts reporters.Options) (reporters.Reporter, error) {
	f, ok := factories[strings.ToLower(format)]
	if !ok {
		return nil, fmt.Errorf("unknown format %q (want one of %s)", format, strings.Join(Formats(), ", "))
	}
	return f(opts), nil
}

// Formats lists the available format names.
func Formats() []string {
	names := make([]string, 0, len(factories))
	for n := range factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
