// Package all wires every built-in parser into a registry. It is the only
// place that needs to change when a new parser is added.
package all

import (
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/ansible"
	"github.com/nexutils/StackGuard/internal/parser/compose"
	"github.com/nexutils/StackGuard/internal/parser/dockerfile"
	"github.com/nexutils/StackGuard/internal/parser/github"
	"github.com/nexutils/StackGuard/internal/parser/helm"
	"github.com/nexutils/StackGuard/internal/parser/jenkins"
	"github.com/nexutils/StackGuard/internal/parser/kubernetes"
	"github.com/nexutils/StackGuard/internal/parser/nginx"
	"github.com/nexutils/StackGuard/internal/parser/terraform"
)

// Detection priorities. Parsers that identify files precisely by name or
// location come first; content-sniffing parsers for generic YAML come last.
const (
	priorityPath    = 100 // decided by path alone
	priorityChart   = 90  // Helm: Chart.yaml siblings and templates/
	priorityName    = 80  // decided by file name, falls back to sniffing
	prioritySniff   = 50  // generic YAML, decided by content
	priorityLastYML = 10  // weakest content heuristics
)

// Registry returns a new registry containing every built-in parser.
func Registry() *parser.Registry {
	r := parser.NewRegistry()
	r.Register(dockerfile.New(), priorityPath)
	r.Register(terraform.New(), priorityPath)
	r.Register(jenkins.New(), priorityPath)
	r.Register(github.New(), priorityPath)
	r.Register(helm.New(), priorityChart)
	r.Register(compose.New(), priorityName)
	r.Register(nginx.New(), priorityName)
	r.Register(kubernetes.New(), prioritySniff)
	r.Register(ansible.New(), priorityLastYML)
	return r
}
