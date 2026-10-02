package query

import (
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nexutils/StackGuard/internal/models"
)

var sample = map[string]any{
	"image":      "postgres:latest",
	"privileged": true,
	"ports": []any{
		map[string]any{"target": "8080", "host_ip": "127.0.0.1"},
		map[string]any{"target": "5432"},
	},
	"labels": map[string]any{"com.example.team": "db"},
	"deploy": map[string]any{"replicas": 1},
}

func TestParsePath(t *testing.T) {
	good := map[string][]segment{
		"a":                   {{key: "a"}},
		"a.b.c":               {{key: "a"}, {key: "b"}, {key: "c"}},
		"ports.*.target":      {{key: "ports"}, {kind: segWildcard}, {key: "target"}},
		"ports[0].target":     {{key: "ports"}, {key: "0"}, {key: "target"}},
		"ports[*]":            {{key: "ports"}, {kind: segWildcard}},
		`labels."a.b".c`:      {{key: "labels"}, {key: "a.b"}, {key: "c"}},
		`"x\"y"`:              {{key: `x"y`}},
		"_podSpec.containers": {{key: "_podSpec"}, {key: "containers"}},
		"@":                   nil,
		`labels["a.b/c"]`:     {{key: "labels"}, {key: "a.b/c"}},
		"services.*.**":       {{key: "services"}, {kind: segWildcard}, {kind: segRecursive}},
		"depends_on.{dep}":    {{key: "depends_on"}, {kind: segCaptureKey, key: "dep"}},
		"depends_on[{dep}]":   {{key: "depends_on"}, {kind: segCaptureItem, key: "dep"}},
	}
	for in, want := range good {
		p, err := ParsePath(in)
		if err != nil {
			t.Errorf("ParsePath(%q): %v", in, err)
			continue
		}
		if !reflect.DeepEqual(p.segs, want) {
			t.Errorf("ParsePath(%q) = %+v, want %+v", in, p.segs, want)
		}
	}
	for _, in := range []string{"", "a..b", "a.", ".a", "a[", "a[x]", `a."b`, `a"b"`, "a[0]b", "a.{bad-name}", `a["x"`, "a.{x"} {
		if _, err := ParsePath(in); err == nil {
			t.Errorf("ParsePath(%q): expected error", in)
		}
	}
}

type pv struct {
	Path  string
	Value any
}

func paths(ms []Match) []pv {
	var out []pv
	for _, m := range ms {
		out = append(out, pv{m.Path, m.Value})
	}
	return out
}

func TestResolve(t *testing.T) {
	tests := []struct {
		path string
		want []pv
	}{
		{"privileged", []pv{{"privileged", true}}},
		{"ports.*.target", []pv{{"ports.0.target", "8080"}, {"ports.1.target", "5432"}}},
		{"ports.1.target", []pv{{"ports.1.target", "5432"}}},
		{"ports.9.target", nil},
		{"ports.x", nil},
		{`labels."com.example.team"`, []pv{{`labels."com.example.team"`, "db"}}},
		{`labels["com.example.team"]`, []pv{{`labels."com.example.team"`, "db"}}},
		{"labels.*", []pv{{`labels."com.example.team"`, "db"}}},
		{"deploy.**", []pv{{"deploy.replicas", 1}}},
		{"image.tag", nil},
		{"missing.deep", nil},
	}
	for _, tt := range tests {
		p, err := ParsePath(tt.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := paths(p.Resolve(sample, "")); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Resolve(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestRecursiveSkipsDerived(t *testing.T) {
	root := map[string]any{
		"a":         map[string]any{"b": []any{"x", map[string]any{"c": "y"}}},
		"_services": map[string]any{"other": "secret"},
	}
	p, _ := ParsePath("**")
	got := paths(p.Resolve(root, ""))
	want := []pv{{"a.b.0", "x"}, {"a.b.1.c", "y"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// compose mimics a normalised Compose service with sibling lookups.
var compose = map[string]any{
	"depends_on": map[string]any{
		"db":    map[string]any{"condition": "service_healthy"},
		"cache": map[string]any{"condition": "service_healthy"},
	},
	"needs": []any{"db", "ghost"},
	"_services": models.Lookup{
		"db":    map[string]any{"healthcheck": map[string]any{"test": "pg_isready"}},
		"cache": map[string]any{},
	},
	"mem":  map[string]any{"reservation": 512, "limit": 256},
	"mem2": map[string]any{"reservation": 128, "limit": 256},
}

func TestCaptures(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
		dep   string
	}{
		{"key capture joins across paths", `{all: [
			{path: "depends_on.{dep}.condition", equals: service_healthy},
			{path: "_services.{dep}.healthcheck.test", not_exists: true}]}`, true, "cache"},
		{"backtracks past non-matching bindings", `{all: [
			{path: "depends_on.{dep}", exists: true},
			{path: "_services.{dep}.healthcheck.test", exists: true}]}`, true, "db"},
		{"item capture", `{all: [
			{path: "needs[{dep}]", exists: true},
			{path: "_services.{dep}", not_exists: true}]}`, true, "ghost"},
		{"no solution", `{all: [
			{path: "needs[{dep}]", exists: true},
			{path: "depends_on.{dep}.condition", equals: service_started}]}`, false, ""},
		{"not respects bindings", `{all: [
			{path: "depends_on.{dep}", exists: true},
			{not: {path: "_services.{dep}.healthcheck", exists: true}}]}`, true, "cache"},
		{"gt_ref", `{path: mem.reservation, gt_ref: mem.limit}`, true, ""},
		{"gt_ref false", `{path: mem2.reservation, gt_ref: mem2.limit}`, false, ""},
		{"lt_ref", `{path: mem2.reservation, lt_ref: mem2.limit}`, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw any
			if err := yaml.Unmarshal([]byte(tt.query), &raw); err != nil {
				t.Fatal(err)
			}
			c, err := Compile(raw)
			if err != nil {
				t.Fatal(err)
			}
			ok, ev := Eval(c, compose, "")
			if ok != tt.want {
				t.Fatalf("Eval = %v, want %v", ok, tt.want)
			}
			if tt.dep != "" && ev.Bindings["dep"] != tt.dep {
				t.Errorf("dep = %q, want %q", ev.Bindings["dep"], tt.dep)
			}
		})
	}
}

func TestDeepestPrefix(t *testing.T) {
	p, _ := ParsePath("deploy.resources.limits.memory")
	if got := p.DeepestPrefix(sample, ""); got != "deploy" {
		t.Errorf("DeepestPrefix = %q, want deploy", got)
	}
}

func TestCompileAndEval(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		want     bool
		wantPath string
	}{
		{"equals", `{path: privileged, equals: true}`, true, "privileged"},
		{"equals miss", `{path: privileged, equals: false}`, false, ""},
		{"not_exists", `{path: healthcheck, not_exists: true}`, true, ""},
		{"not_exists points at parent", `{path: deploy.resources.limits.memory, not_exists: true}`, true, "deploy"},
		{"wildcard any", `{path: ports.*.target, equals: 5432}`, true, "ports.1.target"},
		{"all", `{all: [{path: privileged, equals: true}, {path: image, regex: ":latest$"}]}`, true, "privileged"},
		{"all fails", `{all: [{path: privileged, equals: true}, {path: image, regex: ":1\\.2$"}]}`, false, ""},
		{"any", `{any: [{path: nope, exists: true}, {path: image, contains: postgres}]}`, true, "image"},
		{"not", `{not: {path: image, contains: redis}}`, true, ""},
		{"where correlates elements", `{path: ports.*, where: {all: [{path: target, equals: 5432}, {path: host_ip, not_exists: true}]}}`, true, "ports.1.target"},
		{"where no match", `{path: ports.*, where: {all: [{path: target, equals: 8080}, {path: host_ip, not_exists: true}]}}`, false, ""},
		{"where on missing path", `{path: volumes.*, where: {path: x, not_exists: true}}`, false, ""},
		{"greater_than", `{path: deploy.replicas, less_than: 2}`, true, "deploy.replicas"},
		{"where on scalars with @", `{path: ports.*.target, where: {all: [{path: "@", regex: "^5"}, {not: {path: "@", equals: 5433}}]}}`, true, "ports.1.target"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw any
			if err := yaml.Unmarshal([]byte(tt.query), &raw); err != nil {
				t.Fatal(err)
			}
			c, err := Compile(raw)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			got, ev := Eval(c, sample, "")
			if got != tt.want {
				t.Fatalf("Eval = %v, want %v", got, tt.want)
			}
			if ev.Path != tt.wantPath {
				t.Errorf("evidence path = %q, want %q", ev.Path, tt.wantPath)
			}
		})
	}
}

func TestCountGte(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		want     bool
		wantPath string
	}{
		{"two match", `{path: "ports.*.target", matches: "^[0-9]+$", count_gte: 2}`, true, "ports.1.target"},
		{"only one matches", `{path: "ports.*.target", matches: "^5", count_gte: 2}`, false, ""},
		{"one is enough", `{path: "ports.*.target", equals: "8080", count_gte: 1}`, true, "ports.0.target"},
		{"absent path", `{path: "nope.*", exists: true, count_gte: 1}`, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw any
			if err := yaml.Unmarshal([]byte(tt.query), &raw); err != nil {
				t.Fatal(err)
			}
			c, err := Compile(raw)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			got, ev := Eval(c, sample, "")
			if got != tt.want {
				t.Fatalf("Eval = %v, want %v", got, tt.want)
			}
			if got && ev.Path != tt.wantPath {
				t.Errorf("evidence path = %q, want %q", ev.Path, tt.wantPath)
			}
		})
	}
}

func TestEqualsRef(t *testing.T) {
	data := map[string]any{
		"probeA": map[string]any{"httpGet": map[string]any{"path": "/healthz", "port": 8080}},
		"probeB": map[string]any{"httpGet": map[string]any{"path": "/healthz", "port": 8080}},
		"probeC": map[string]any{"httpGet": map[string]any{"path": "/ready", "port": 8080}},
		"min":    2,
		"max":    2,
		"other":  5,
	}
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{"identical maps", `{path: probeA, equals_ref: probeB}`, true},
		{"different maps", `{path: probeA, equals_ref: probeC}`, false},
		{"equal numbers", `{path: min, equals_ref: max}`, true},
		{"different numbers", `{path: min, equals_ref: other}`, false},
		{"missing ref", `{path: min, equals_ref: nope}`, false},
		{"missing path", `{path: nope, equals_ref: min}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw any
			if err := yaml.Unmarshal([]byte(tt.query), &raw); err != nil {
				t.Fatal(err)
			}
			c, err := Compile(raw)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if got, _ := Eval(c, data, ""); got != tt.want {
				t.Fatalf("Eval = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []string{
		`[]`,
		`{}`,
		`{path: a}`,
		`{equals: 1}`,
		`{path: a, equals: 1, exists: true}`,
		`{path: a, bogus: 1}`,
		`{path: a, regex: "("}`,
		`{all: []}`,
		`{all: [{path: a, equals: 1}], path: b}`,
		`{any: {path: a, equals: 1}}`,
		`{not: [1]}`,
		`{path: "a..b", equals: 1}`,
		`{path: a, where: {}}`,
		`{path: a, gt_ref: 5}`,
		`{path: a, gt_ref: "b..c"}`,
		`{path: a, equals_ref: 5}`,
		`{path: a, equals_ref: "b..c"}`,
		`{path: a, count_gte: 2}`,
		`{path: a, count_gte: 2, equals: 1, exists: true}`,
		`{path: a, count_gte: "x", equals: 1}`,
	}
	for _, q := range bad {
		var raw any
		if err := yaml.Unmarshal([]byte(q), &raw); err != nil {
			t.Fatal(err)
		}
		if _, err := Compile(raw); err == nil {
			t.Errorf("Compile(%s): expected error", q)
		}
	}
}

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{"a.b", "a[0].b", `a."b.c"`, "a.*.b", "[*]"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePath(s)
		if err != nil {
			return
		}
		_ = p.Resolve(sample, "")
		_ = p.DeepestPrefix(sample, "")
	})
}
