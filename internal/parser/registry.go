package parser

import (
	"fmt"
	"sort"
)

// Registry holds parsers ordered by priority. Detection asks each parser in
// turn and the first one that accepts a file wins, so parsers with precise
// detection (by file name) should get a higher priority than parsers that
// sniff content.
type Registry struct {
	entries []entry
}

type entry struct {
	parser   Parser
	priority int
	seq      int
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a parser. Higher priority parsers are consulted first; ties
// keep registration order. It panics on duplicate names.
func (r *Registry) Register(p Parser, priority int) {
	for _, e := range r.entries {
		if e.parser.Name() == p.Name() {
			panic(fmt.Sprintf("parser: duplicate parser %q", p.Name()))
		}
	}
	r.entries = append(r.entries, entry{parser: p, priority: priority, seq: len(r.entries)})
	sort.SliceStable(r.entries, func(i, j int) bool {
		if r.entries[i].priority != r.entries[j].priority {
			return r.entries[i].priority > r.entries[j].priority
		}
		return r.entries[i].seq < r.entries[j].seq
	})
}

// Detect returns the parser responsible for the file, or nil.
func (r *Registry) Detect(f *FileInfo) Parser {
	if f.IsBinary() {
		return nil
	}
	for _, e := range r.entries {
		if e.parser.CanParse(f) {
			return e.parser
		}
	}
	return nil
}

// Get returns a parser by name.
func (r *Registry) Get(name string) (Parser, bool) {
	for _, e := range r.entries {
		if e.parser.Name() == name {
			return e.parser, true
		}
	}
	return nil, false
}

// Names returns parser names in detection order.
func (r *Registry) Names() []string {
	names := make([]string, len(r.entries))
	for i, e := range r.entries {
		names[i] = e.parser.Name()
	}
	return names
}
