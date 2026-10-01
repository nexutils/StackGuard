// Package operators implements the comparison operators available in rule
// queries. New operators are added by implementing Operator and calling
// Register from an init function; no changes to the rule schema or engine are
// needed.
package operators

import (
	"fmt"
	"sort"
	"sync"
)

// Matcher tests a single resolved value. present is false when the queried
// path resolved to nothing, in which case value is nil. A Matcher is called
// once per resolved value, or exactly once with present=false when nothing
// resolved.
type Matcher func(value any, present bool) bool

// Operator turns a rule argument into a Matcher. Compile runs once, when rules
// are loaded, so it should validate the argument and do any expensive
// preparation (such as compiling a regular expression) up front.
type Operator interface {
	Name() string
	Compile(arg any) (Matcher, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Operator{}
)

// Register adds an operator. It panics on duplicate names, since that is a
// programming error.
func Register(op Operator) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[op.Name()]; dup {
		panic(fmt.Sprintf("operators: duplicate operator %q", op.Name()))
	}
	registry[op.Name()] = op
}

// Lookup returns the operator with the given name.
func Lookup(name string) (Operator, bool) {
	mu.RLock()
	defer mu.RUnlock()
	op, ok := registry[name]
	return op, ok
}

// Names returns all registered operator names, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Func adapts a name and compile function into an Operator.
type Func struct {
	OpName    string
	CompileFn func(arg any) (Matcher, error)
}

func (f Func) Name() string                     { return f.OpName }
func (f Func) Compile(arg any) (Matcher, error) { return f.CompileFn(arg) }
