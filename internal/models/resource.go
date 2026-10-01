package models

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Position is a location inside a source file. Lines and columns are 1-based;
// zero means unknown.
type Position struct {
	Line      int `json:"line"`
	Column    int `json:"column,omitempty"`
	EndLine   int `json:"end_line,omitempty"`
	EndColumn int `json:"end_column,omitempty"`
}

// Resource is the common representation every parser produces. Rules operate
// only on Resources, never on raw files.
type Resource struct {
	// Target is the technology the resource came from ("compose", "kubernetes", ...).
	// It equals the Name() of the parser that produced it.
	Target string `json:"target"`
	// Type is the kind of resource within the target ("service", "Deployment",
	// "resource.aws_s3_bucket", "job", ...).
	Type string `json:"type"`
	Name string `json:"name"`
	File string `json:"file"`
	Line int    `json:"line"`
	// Properties holds the resource's data as generic values: map[string]any,
	// []any, string, bool, int, float64 or nil.
	Properties map[string]any `json:"properties"`
	// Locations maps canonical property paths (see JoinPath) to their position
	// in the source file. It is best effort; missing entries fall back to the
	// nearest ancestor path and finally to Line.
	Locations map[string]Position `json:"locations,omitempty"`
}

// PositionFor returns the most specific known position for a property path.
func (r *Resource) PositionFor(path string) Position {
	for p := path; p != ""; p = parentPath(p) {
		if pos, ok := r.Locations[p]; ok && pos.Line > 0 {
			return pos
		}
	}
	return Position{Line: r.Line}
}

// JoinPath appends a map key to a canonical property path. Keys that would be
// ambiguous in path syntax are quoted.
func JoinPath(prefix, key string) string {
	if needsQuote(key) {
		key = strconv.Quote(key)
	}
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// JoinIndex appends a list index to a canonical property path.
func JoinIndex(prefix string, i int) string {
	if prefix == "" {
		return strconv.Itoa(i)
	}
	return prefix + "." + strconv.Itoa(i)
}

func needsQuote(key string) bool {
	return key == "" || key == "*" || strings.ContainsAny(key, ".[]\"")
}

// parentPath strips the last segment of a canonical path, honouring quoted
// segments.
func parentPath(p string) string {
	inQuote := false
	last := -1
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			if inQuote {
				i++
			}
		case '"':
			inQuote = !inQuote
		case '.':
			if !inQuote {
				last = i
			}
		}
	}
	if last < 0 {
		return ""
	}
	return p[:last]
}

// Lookup is a map that rules can traverse like any other property but that
// serializes as its sorted keys only. Parsers use it for cross-references
// (e.g. every Compose service's view of its sibling services) so shared data
// is not duplicated in JSON output.
type Lookup map[string]any

func (l Lookup) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return json.Marshal(keys)
}
