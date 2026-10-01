package operators

import "testing"

func TestBuiltins(t *testing.T) {
	type check struct {
		value   any
		present bool
		want    bool
	}
	tests := []struct {
		op     string
		arg    any
		checks []check
	}{
		{"equals", true, []check{
			{true, true, true},
			{"true", true, true},
			{false, true, false},
			{nil, false, false},
		}},
		{"equals", 8080, []check{
			{8080, true, true},
			{"8080", true, true},
			{8080.0, true, true},
			{"80", true, false},
		}},
		{"not_equals", "always", []check{
			{"no", true, true},
			{"always", true, false},
			{nil, false, false},
		}},
		{"exists", true, []check{
			{"x", true, true},
			{nil, true, true},
			{nil, false, false},
		}},
		{"exists", false, []check{
			{nil, false, true},
			{"x", true, false},
		}},
		{"not_exists", true, []check{
			{nil, false, true},
			{"x", true, false},
		}},
		{"contains", "sock", []check{
			{"/var/run/docker.sock:/var/run/docker.sock", true, true},
			{[]any{"a", "sock"}, true, true},
			{[]any{"a", "socks"}, true, false},
			{map[string]any{"sock": 1}, true, true},
			{42, true, false},
			{nil, false, false},
		}},
		{"regex", `^(latest)?$`, []check{
			{"latest", true, true},
			{"", true, true},
			{"1.2", true, false},
			{[]any{"1.2", "latest"}, true, true},
			{nil, true, false},
			{map[string]any{}, true, false},
		}},
		{"greater_than", 1, []check{
			{2, true, true},
			{"3", true, true},
			{1, true, false},
			{"abc", true, false},
			{nil, false, false},
		}},
		{"not_matches", `noexec`, []check{
			{"/tmp:size=64m", true, true},
			{"/tmp:noexec", true, false},
			{nil, false, false},
			{map[string]any{}, true, false},
		}},
		{"in", []any{"any", "on-failure"}, []check{
			{"any", true, true},
			{"always", true, false},
			{nil, false, false},
		}},
		{"not_in", []any{"fluentd", "journald"}, []check{
			{"json-file", true, true},
			{"journald", true, false},
			{nil, false, false},
		}},
		{"contains_any", []any{"SYS_ADMIN", "ALL"}, []check{
			{[]any{"NET_RAW", "ALL"}, true, true},
			{[]any{"NET_RAW"}, true, false},
			{nil, false, false},
		}},
		{"length_gte", 2, []check{
			{[]any{"a", "b"}, true, true},
			{[]any{"a"}, true, false},
			{map[string]any{"a": 1, "b": 2}, true, true},
		}},
		{"type", "list", []check{
			{[]any{}, true, true},
			{map[string]any{}, true, false},
			{nil, false, false},
		}},
		{"gte", 2, []check{
			{2, true, true},
			{1, true, false},
		}},
		{"lte", 2, []check{
			{2, true, true},
			{3, true, false},
		}},
		{"less_than", 2, []check{
			{1, true, true},
			{1.5, true, true},
			{2, true, false},
		}},
	}
	for _, tt := range tests {
		op, ok := Lookup(tt.op)
		if !ok {
			t.Fatalf("operator %q not registered", tt.op)
		}
		m, err := op.Compile(tt.arg)
		if err != nil {
			t.Fatalf("%s(%v): compile: %v", tt.op, tt.arg, err)
		}
		for _, c := range tt.checks {
			if got := m(c.value, c.present); got != c.want {
				t.Errorf("%s(%v) on (%#v, present=%v) = %v, want %v", tt.op, tt.arg, c.value, c.present, got, c.want)
			}
		}
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []struct {
		op  string
		arg any
	}{
		{"exists", "yes"},
		{"not_exists", 1},
		{"regex", "("},
		{"regex", 5},
		{"greater_than", "big"},
		{"contains", []any{1}},
		{"in", "x"},
		{"contains_any", []any{}},
		{"type", "tuple"},
		{"length_gte", "many"},
	}
	for _, b := range bad {
		op, _ := Lookup(b.op)
		if _, err := op.Compile(b.arg); err == nil {
			t.Errorf("%s(%v): expected compile error", b.op, b.arg)
		}
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	Register(Func{"equals", compileEquals(false)})
}
