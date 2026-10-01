package query

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nexutils/StackGuard/internal/engine/operators"
)

// Reserved query keys. Any other key in a leaf is looked up in the operator
// registry.
const (
	keyAll      = "all"
	keyAny      = "any"
	keyNot      = "not"
	keyPath     = "path"
	keyWhere    = "where"
	keyGtRef    = "gt_ref"
	keyLtRef    = "lt_ref"
	keyCountGte = "count_gte"
)

// operatorNames lists registered operators plus the structural leaf keys.
func operatorNames() []string {
	names := append(operators.Names(), keyGtRef, keyLtRef, keyWhere, keyCountGte)
	sort.Strings(names)
	return names
}

// hasCaptures reports whether any path in the condition uses captures.
func hasCaptures(c Condition) bool {
	switch t := c.(type) {
	case *Leaf:
		return t.Path.HasCaptures()
	case *Where:
		return t.captures
	case *RefCompare:
		return t.Path.HasCaptures() || t.Ref.HasCaptures()
	case *CountAtLeast:
		return t.Path.HasCaptures()
	case Not:
		return hasCaptures(t.Cond)
	case All:
		for _, ch := range t {
			if hasCaptures(ch) {
				return true
			}
		}
	case Any:
		for _, ch := range t {
			if hasCaptures(ch) {
				return true
			}
		}
	}
	return false
}

// Compile turns a decoded YAML query into a Condition. Accepted shapes:
//
//	{path: p, <operator>: arg}      leaf
//	{path: p, where: <query>}       some element at p satisfies the sub-query
//	{path: p, gt_ref: q}            number at p is greater than number at q
//	{all: [<query>, ...]}           every sub-query matches
//	{any: [<query>, ...]}           at least one sub-query matches
//	{not: <query>}                  sub-query does not match
func Compile(raw any) (Condition, error) {
	return compile(raw, "query")
}

func compile(raw any, where string) (Condition, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a mapping, got %s", where, describe(raw))
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("%s: empty condition", where)
	}

	for _, combinator := range []string{keyAll, keyAny, keyNot} {
		v, ok := m[combinator]
		if !ok {
			continue
		}
		if len(m) != 1 {
			return nil, fmt.Errorf("%s: %q must be the only key in its mapping (found %s)", where, combinator, keys(m))
		}
		if combinator == keyNot {
			c, err := compile(v, where+".not")
			if err != nil {
				return nil, err
			}
			return Not{Cond: c}, nil
		}
		list, ok := v.([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("%s.%s: expected a non-empty list of conditions", where, combinator)
		}
		children := make([]Condition, 0, len(list))
		for i, item := range list {
			c, err := compile(item, fmt.Sprintf("%s.%s[%d]", where, combinator, i))
			if err != nil {
				return nil, err
			}
			children = append(children, c)
		}
		if combinator == keyAll {
			return All(children), nil
		}
		return Any(children), nil
	}

	return compileLeaf(m, where)
}

func compileLeaf(m map[string]any, where string) (Condition, error) {
	rawPath, ok := m[keyPath]
	if !ok {
		return nil, fmt.Errorf("%s: missing %q (or one of all/any/not)", where, keyPath)
	}
	pathStr, ok := rawPath.(string)
	if !ok {
		return nil, fmt.Errorf("%s.path: expected a string, got %s", where, describe(rawPath))
	}
	p, err := ParsePath(pathStr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}

	var opKeys []string
	for k := range m {
		if k != keyPath {
			opKeys = append(opKeys, k)
		}
	}
	sort.Strings(opKeys)

	// count_gte is a modifier that pairs with one ordinary operator and turns
	// the leaf's default "any element matches" into "at least N elements match".
	if cntArg, ok := m[keyCountGte]; ok {
		n, ok := operators.ToFloat(cntArg)
		if !ok {
			return nil, fmt.Errorf("%s: %s: expects a number, got %s", where, keyCountGte, describe(cntArg))
		}
		var others []string
		for _, k := range opKeys {
			if k != keyCountGte {
				others = append(others, k)
			}
		}
		if len(others) != 1 {
			return nil, fmt.Errorf("%s: path %q with %s needs exactly one other operator (found %v)", where, pathStr, keyCountGte, others)
		}
		opName := others[0]
		op, ok := operators.Lookup(opName)
		if !ok {
			return nil, fmt.Errorf("%s: unknown operator %q (want one of %s)", where, opName, strings.Join(operatorNames(), ", "))
		}
		matcher, err := op.Compile(m[opName])
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", where, opName, err)
		}
		return &CountAtLeast{Path: p, Operator: opName, Match: matcher, N: int(n)}, nil
	}

	if len(opKeys) != 1 {
		if len(opKeys) == 0 {
			return nil, fmt.Errorf("%s: path %q has no operator (want one of %s)", where, pathStr, strings.Join(operatorNames(), ", "))
		}
		return nil, fmt.Errorf("%s: path %q has several operators %v; use all/any to combine them", where, pathStr, opKeys)
	}

	opName := opKeys[0]
	switch opName {
	case keyWhere:
		sub, err := compile(m[keyWhere], where+".where")
		if err != nil {
			return nil, err
		}
		return &Where{Path: p, Cond: sub, captures: p.HasCaptures() || hasCaptures(sub)}, nil
	case keyGtRef, keyLtRef:
		refStr, ok := m[opName].(string)
		if !ok {
			return nil, fmt.Errorf("%s: %s: expects a path, got %s", where, opName, describe(m[opName]))
		}
		ref, err := ParsePath(refStr)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", where, opName, err)
		}
		cmp := func(a, b float64) bool { return a > b }
		if opName == keyLtRef {
			cmp = func(a, b float64) bool { return a < b }
		}
		return &RefCompare{Path: p, Ref: ref, Operator: opName, cmp: cmp}, nil
	}
	op, ok := operators.Lookup(opName)
	if !ok {
		return nil, fmt.Errorf("%s: unknown operator %q (want one of %s)", where, opName, strings.Join(operatorNames(), ", "))
	}
	matcher, err := op.Compile(m[opName])
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", where, opName, err)
	}
	return &Leaf{Path: p, Operator: opName, Match: matcher}, nil
}

func keys(m map[string]any) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}

func describe(v any) string {
	switch v.(type) {
	case nil:
		return "nothing"
	case []any:
		return "a list"
	case map[string]any:
		return "a mapping"
	default:
		return fmt.Sprintf("%T", v)
	}
}
