// Package query compiles and evaluates rule queries: trees of conditions over
// a resource's properties.
//
// Conditions are evaluated as a search for solutions. Each solution is a set
// of capture bindings (see Path) that satisfies the condition. That lets a
// capture bound in one branch of an `all` constrain later branches, e.g.
// "service X depends on {dep} AND {dep} has no healthcheck".
package query

import (
	"github.com/nexutils/StackGuard/internal/engine/operators"
	"github.com/nexutils/StackGuard/internal/models"
)

// Evidence explains why a condition matched: the canonical property path and
// the value found there, plus the capture bindings. Path is empty when no
// specific property is to blame (for example a missing property).
type Evidence struct {
	Path     string
	Value    any
	Bindings Env
}

// Yield receives one solution. It returns false to stop the search.
type Yield func(env Env, ev Evidence) bool

// Condition is a node in a compiled query. Solve calls yield for each
// solution under env, and returns false if yield asked to stop. root is the
// value paths are resolved against; prefix is its canonical path.
type Condition interface {
	Solve(root any, prefix string, env Env, yield Yield) bool
}

// Eval reports whether c has at least one solution, and the evidence of the
// first one.
func Eval(c Condition, root any, prefix string) (bool, Evidence) {
	var (
		ok  bool
		got Evidence
	)
	c.Solve(root, prefix, nil, func(env Env, ev Evidence) bool {
		ok, got = true, ev
		got.Bindings = env
		return false
	})
	return ok, got
}

// EvalResource evaluates a condition against a resource's properties.
func EvalResource(c Condition, r *models.Resource) (bool, Evidence) {
	return Eval(c, r.Properties, "")
}

// Leaf applies one operator to the values a path resolves to. It matches if
// any resolved value matches; if nothing resolves, the matcher is called once
// with present=false.
type Leaf struct {
	Path     Path
	Operator string
	Match    operators.Matcher
}

func (l *Leaf) Solve(root any, prefix string, env Env, yield Yield) bool {
	matches := l.Path.ResolveEnv(root, prefix, env)
	if len(matches) == 0 {
		if l.Match(nil, false) {
			return yield(env, Evidence{Path: l.Path.DeepestPrefix(root, prefix)})
		}
		return true
	}
	captures := l.Path.HasCaptures()
	for _, m := range matches {
		if !l.Match(m.Value, true) {
			continue
		}
		if !yield(m.Env, Evidence{Path: m.Path, Value: m.Value}) {
			return false
		}
		if !captures {
			// Further matches only differ in evidence, not bindings.
			return true
		}
	}
	return true
}

// Where matches if at least one value the path resolves to satisfies Cond,
// evaluated with that value as root. It correlates several checks on the same
// list element, e.g. "some port targets 5432 AND is bound to all interfaces".
type Where struct {
	Path     Path
	Cond     Condition
	captures bool
}

func (w *Where) Solve(root any, prefix string, env Env, yield Yield) bool {
	for _, m := range w.Path.ResolveEnv(root, prefix, env) {
		found := false
		cont := w.Cond.Solve(m.Value, m.Path, m.Env, func(e Env, ev Evidence) bool {
			found = true
			if ev.Path == "" || ev.Path == m.Path {
				ev = Evidence{Path: m.Path, Value: m.Value}
			}
			return yield(e, ev)
		})
		if !cont {
			return false
		}
		if found && !w.captures {
			return true
		}
	}
	return true
}

// All matches when every child matches under shared bindings.
type All []Condition

func (a All) Solve(root any, prefix string, env Env, yield Yield) bool {
	return a.solve(0, root, prefix, env, Evidence{}, yield)
}

func (a All) solve(i int, root any, prefix string, env Env, best Evidence, yield Yield) bool {
	if i == len(a) {
		return yield(env, best)
	}
	return a[i].Solve(root, prefix, env, func(e Env, ev Evidence) bool {
		b := best
		if b.Path == "" && ev.Path != prefix {
			b = ev
		}
		return a.solve(i+1, root, prefix, e, b, yield)
	})
}

// Any matches when at least one child matches.
type Any []Condition

func (a Any) Solve(root any, prefix string, env Env, yield Yield) bool {
	for _, c := range a {
		if !c.Solve(root, prefix, env, yield) {
			return false
		}
	}
	return true
}

// Not matches when its child has no solution under the current bindings.
type Not struct{ Cond Condition }

func (n Not) Solve(root any, prefix string, env Env, yield Yield) bool {
	found := false
	n.Cond.Solve(root, prefix, env, func(Env, Evidence) bool {
		found = true
		return false
	})
	if found {
		return true
	}
	return yield(env, Evidence{})
}

// RefCompare compares the numeric value at Path with the numeric value at
// Ref, both resolved against the same root (gt_ref / lt_ref).
type RefCompare struct {
	Path     Path
	Ref      Path
	Operator string
	cmp      func(a, b float64) bool
}

func (r *RefCompare) Solve(root any, prefix string, env Env, yield Yield) bool {
	for _, m := range r.Path.ResolveEnv(root, prefix, env) {
		a, ok := operators.ToFloat(m.Value)
		if !ok {
			continue
		}
		for _, ref := range r.Ref.ResolveEnv(root, prefix, m.Env) {
			b, ok := operators.ToFloat(ref.Value)
			if ok && r.cmp(a, b) {
				if !yield(ref.Env, Evidence{Path: m.Path, Value: m.Value}) {
					return false
				}
			}
		}
	}
	return true
}

// RefEquals matches when the value at Path equals the value at Ref, both
// resolved against the same root (equals_ref). Unlike gt_ref / lt_ref it is not
// numeric: scalars compare by value and maps/lists structurally, so a rule can
// ask "is the liveness probe identical to the readiness probe?".
type RefEquals struct {
	Path Path
	Ref  Path
}

func (r *RefEquals) Solve(root any, prefix string, env Env, yield Yield) bool {
	for _, m := range r.Path.ResolveEnv(root, prefix, env) {
		for _, ref := range r.Ref.ResolveEnv(root, prefix, m.Env) {
			if !operators.Equal(m.Value, ref.Value) {
				continue
			}
			if !yield(ref.Env, Evidence{Path: m.Path, Value: m.Value}) {
				return false
			}
		}
	}
	return true
}

// CountAtLeast matches when at least N of the values its path resolves to
// satisfy Match. It backs the `count_gte` modifier: where a plain leaf matches
// if *any* element under a wildcard matches, count_gte requires a minimum
// number of them (e.g. "2 or more RUN instructions install packages").
type CountAtLeast struct {
	Path     Path
	Operator string
	Match    operators.Matcher
	N        int
}

func (c *CountAtLeast) Solve(root any, prefix string, env Env, yield Yield) bool {
	count := 0
	var last Match
	found := false
	for _, m := range c.Path.ResolveEnv(root, prefix, env) {
		if c.Match(m.Value, true) {
			count++
			last, found = m, true
		}
	}
	if count < c.N {
		return true
	}
	ev := Evidence{Path: c.Path.DeepestPrefix(root, prefix)}
	if found {
		ev = Evidence{Path: last.Path, Value: last.Value}
	}
	return yield(env, ev)
}
