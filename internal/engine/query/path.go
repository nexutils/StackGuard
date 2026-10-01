package query

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nexutils/StackGuard/internal/engine/operators"
	"github.com/nexutils/StackGuard/internal/models"
)

// Path is a parsed property path. Syntax:
//
//	a.b.c              nested keys
//	ports.0 / ports[0] list index
//	ports.* / ports[*] every value of a map or element of a list
//	labels."a.b"       quoted key (also labels["a.b"])
//	**                 every scalar anywhere below (keys starting with "_",
//	                   StackGuard's derived properties, are skipped)
//	depends_on.{dep}   capture a map KEY into the variable "dep"
//	depends_on[{dep}]  capture a list ITEM into "dep"
//	@                  the root value itself
//
// A capture that is already bound (by an earlier condition in the same rule)
// is substituted instead: `_services.{dep}.healthcheck`.
type Path struct {
	raw  string
	segs []segment
}

type segKind int

const (
	segKey segKind = iota
	segWildcard
	segRecursive
	segCaptureKey
	segCaptureItem
)

type segment struct {
	kind segKind
	key  string // key for segKey, variable name for captures
}

// Env holds capture bindings. It is never mutated; binding returns a copy.
type Env map[string]string

func (e Env) bind(name, value string) Env {
	out := make(Env, len(e)+1)
	for k, v := range e {
		out[k] = v
	}
	out[name] = value
	return out
}

// Match is one value a path resolved to, with its concrete canonical path
// and the bindings in effect.
type Match struct {
	Path  string
	Value any
	Env   Env
}

var captureRe = regexp.MustCompile(`^\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// ParsePath parses path syntax.
func ParsePath(s string) (Path, error) {
	p := Path{raw: s}
	if strings.TrimSpace(s) == "" {
		return p, fmt.Errorf("empty path")
	}
	if s == "@" {
		return p, nil
	}
	i := 0
	expectSegment := true
	for i < len(s) {
		c := s[i]
		switch {
		case c == '.':
			if expectSegment {
				return p, fmt.Errorf("path %q: empty segment at offset %d", s, i)
			}
			expectSegment = true
			i++
		case c == '[':
			seg, n, err := parseBracket(s, i)
			if err != nil {
				return p, err
			}
			p.segs = append(p.segs, seg)
			expectSegment = false
			i += n
		case c == '"':
			if !expectSegment {
				return p, fmt.Errorf("path %q: missing '.' before quoted key at offset %d", s, i)
			}
			key, n, err := parseQuoted(s, i)
			if err != nil {
				return p, err
			}
			p.segs = append(p.segs, segment{kind: segKey, key: key})
			expectSegment = false
			i += n
		default:
			if !expectSegment {
				return p, fmt.Errorf("path %q: unexpected %q at offset %d", s, c, i)
			}
			j := i
			for j < len(s) && s[j] != '.' && s[j] != '[' && s[j] != '"' {
				j++
			}
			tok := s[i:j]
			switch {
			case tok == "*":
				p.segs = append(p.segs, segment{kind: segWildcard})
			case tok == "**":
				p.segs = append(p.segs, segment{kind: segRecursive})
			case captureRe.MatchString(tok):
				p.segs = append(p.segs, segment{kind: segCaptureKey, key: captureRe.FindStringSubmatch(tok)[1]})
			case strings.ContainsAny(tok, "{}"):
				return p, fmt.Errorf("path %q: invalid capture %q (want {name})", s, tok)
			default:
				p.segs = append(p.segs, segment{kind: segKey, key: tok})
			}
			expectSegment = false
			i = j
		}
	}
	if expectSegment {
		return p, fmt.Errorf("path %q: trailing '.'", s)
	}
	return p, nil
}

// parseBracket parses "[...]" at s[i] and returns the segment and its length.
func parseBracket(s string, i int) (segment, int, error) {
	if i+1 < len(s) && s[i+1] == '"' {
		key, n, err := parseQuoted(s, i+1)
		if err != nil {
			return segment{}, 0, err
		}
		end := i + 1 + n
		if end >= len(s) || s[end] != ']' {
			return segment{}, 0, fmt.Errorf("path %q: expected ']' after quoted key", s)
		}
		return segment{kind: segKey, key: key}, end - i + 1, nil
	}
	end := strings.IndexByte(s[i:], ']')
	if end < 0 {
		return segment{}, 0, fmt.Errorf("path %q: unterminated '['", s)
	}
	inner := s[i+1 : i+end]
	switch {
	case inner == "*":
		return segment{kind: segWildcard}, end + 1, nil
	case isIndex(inner):
		return segment{kind: segKey, key: inner}, end + 1, nil
	case captureRe.MatchString(inner):
		return segment{kind: segCaptureItem, key: captureRe.FindStringSubmatch(inner)[1]}, end + 1, nil
	}
	return segment{}, 0, fmt.Errorf("path %q: invalid index %q", s, inner)
}

// parseQuoted parses a Go-quoted string at s[i] and returns it and its length.
func parseQuoted(s string, i int) (string, int, error) {
	end := closingQuote(s, i)
	if end < 0 {
		return "", 0, fmt.Errorf("path %q: unterminated quoted key", s)
	}
	key, err := strconv.Unquote(s[i : end+1])
	if err != nil {
		return "", 0, fmt.Errorf("path %q: bad quoted key: %w", s, err)
	}
	return key, end - i + 1, nil
}

func (p Path) String() string { return p.raw }

// HasWildcard reports whether the path can resolve to more than one value.
func (p Path) HasWildcard() bool {
	for _, s := range p.segs {
		if s.kind != segKey {
			return true
		}
	}
	return false
}

// HasCaptures reports whether the path binds or uses capture variables.
func (p Path) HasCaptures() bool {
	for _, s := range p.segs {
		if s.kind == segCaptureKey || s.kind == segCaptureItem {
			return true
		}
	}
	return false
}

// Resolve returns every value the path reaches in root, in deterministic
// order, with no capture bindings. prefix is prepended to canonical paths.
func (p Path) Resolve(root any, prefix string) []Match {
	return p.ResolveEnv(root, prefix, nil)
}

// ResolveEnv resolves the path with capture bindings env. Unbound captures
// bind to each key or item they visit; the resulting bindings are returned in
// Match.Env.
func (p Path) ResolveEnv(root any, prefix string, env Env) []Match {
	var out []Match
	resolve(root, p.segs, prefix, env, &out)
	return out
}

// DeepestPrefix returns the canonical path of the longest leading part of the
// path that exists in root, stopping at the first non-literal segment. It
// points findings for missing values at the closest existing parent.
func (p Path) DeepestPrefix(root any, prefix string) string {
	cur := root
	best := prefix
	for _, s := range p.segs {
		if s.kind != segKey {
			return best
		}
		next, key, ok := step(cur, s.key)
		if !ok {
			return best
		}
		best = key(best)
		cur = next
	}
	return best
}

func resolve(v any, segs []segment, prefix string, env Env, out *[]Match) {
	if l, ok := v.(models.Lookup); ok {
		v = map[string]any(l)
	}
	if len(segs) == 0 {
		*out = append(*out, Match{Path: prefix, Value: v, Env: env})
		return
	}
	s, rest := segs[0], segs[1:]
	switch s.kind {
	case segKey:
		if next, key, ok := step(v, s.key); ok {
			resolve(next, rest, key(prefix), env, out)
		}
	case segWildcard:
		eachChild(v, prefix, false, func(child any, p, _ string) {
			resolve(child, rest, p, env, out)
		})
	case segRecursive:
		recurse(v, rest, prefix, env, out)
	case segCaptureKey:
		if bound, ok := env[s.key]; ok {
			if next, key, ok := step(v, bound); ok {
				resolve(next, rest, key(prefix), env, out)
			}
			return
		}
		if _, isMap := v.(map[string]any); !isMap {
			return
		}
		eachChild(v, prefix, false, func(child any, p, k string) {
			resolve(child, rest, p, env.bind(s.key, k), out)
		})
	case segCaptureItem:
		list, ok := v.([]any)
		if !ok {
			return
		}
		bound, isBound := env[s.key]
		for i, e := range list {
			if e == nil || !isScalar(e) {
				continue
			}
			val := operators.ToString(e)
			next := env
			if isBound {
				if val != bound {
					continue
				}
			} else {
				next = env.bind(s.key, val)
			}
			resolve(e, rest, models.JoinIndex(prefix, i), next, out)
		}
	}
}

// recurse implements `**`: with no remaining segments it yields every scalar
// below v; otherwise it applies the remaining segments at v and at every
// container below it.
func recurse(v any, rest []segment, prefix string, env Env, out *[]Match) {
	if l, ok := v.(models.Lookup); ok {
		v = map[string]any(l)
	}
	if len(rest) > 0 {
		resolve(v, rest, prefix, env, out)
	}
	switch v.(type) {
	case map[string]any, []any:
		eachChild(v, prefix, true, func(child any, p, _ string) {
			recurse(child, rest, p, env, out)
		})
	default:
		if len(rest) == 0 && prefix != "" {
			*out = append(*out, Match{Path: prefix, Value: v, Env: env})
		}
	}
}

// eachChild visits map values (sorted by key) or list elements. With
// skipDerived, map keys starting with "_" are skipped.
func eachChild(v any, prefix string, skipDerived bool, fn func(child any, path, key string)) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			if skipDerived && strings.HasPrefix(k, "_") {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fn(t[k], models.JoinPath(prefix, k), k)
		}
	case []any:
		for i, e := range t {
			fn(e, models.JoinIndex(prefix, i), strconv.Itoa(i))
		}
	case []string:
		for i, e := range t {
			fn(e, models.JoinIndex(prefix, i), strconv.Itoa(i))
		}
	case []map[string]any:
		for i, e := range t {
			fn(e, models.JoinIndex(prefix, i), strconv.Itoa(i))
		}
	}
}

// step applies one literal segment. The returned func extends a canonical
// prefix with the segment.
func step(v any, key string) (any, func(string) string, bool) {
	switch t := v.(type) {
	case models.Lookup:
		return step(map[string]any(t), key)
	case map[string]any:
		next, ok := t[key]
		return next, func(p string) string { return models.JoinPath(p, key) }, ok
	case map[string]string:
		next, ok := t[key]
		return next, func(p string) string { return models.JoinPath(p, key) }, ok
	case []any, []string, []map[string]any:
		idx, err := strconv.Atoi(key)
		if err != nil || idx < 0 {
			return nil, nil, false
		}
		var next any
		switch l := t.(type) {
		case []any:
			if idx >= len(l) {
				return nil, nil, false
			}
			next = l[idx]
		case []string:
			if idx >= len(l) {
				return nil, nil, false
			}
			next = l[idx]
		case []map[string]any:
			if idx >= len(l) {
				return nil, nil, false
			}
			next = l[idx]
		}
		return next, func(p string) string { return models.JoinIndex(p, idx) }, true
	}
	return nil, nil, false
}

func isScalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any, models.Lookup:
		return false
	}
	return true
}

func isIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func closingQuote(s string, start int) int {
	for i := start + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}
