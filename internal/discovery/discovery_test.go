package discovery

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscover(t *testing.T) {
	root := t.TempDir()
	files := []string{
		"docker-compose.yml",
		"deploy/k8s/app.yaml",
		"deploy/k8s/app.generated.yaml",
		"node_modules/pkg/compose.yml",
		".git/config",
		"examples/Dockerfile",
		"big/Dockerfile",
		".github/workflows/ci.yml",
	}
	for _, f := range files {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		content := []byte("x")
		if f == "big/Dockerfile" {
			content = make([]byte, 2048)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, IgnoreFile), []byte("# comment\nexamples/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(context.Background(), []string{root}, Options{
		Exclude:     []string{"*.generated.yaml"},
		MaxFileSize: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, f := range got {
		rel, _ := filepath.Rel(root, f.Path)
		rels = append(rels, filepath.ToSlash(rel))
	}
	want := []string{".github/workflows/ci.yml", ".stackguardignore", "deploy/k8s/app.yaml", "docker-compose.yml"}
	if !reflect.DeepEqual(rels, want) {
		t.Errorf("Discover = %v, want %v", rels, want)
	}
}

func TestDiscoverExplicitFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "Dockerfile")
	if err := os.WriteFile(p, []byte("FROM x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Discover(context.Background(), []string{p, p}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Explicit {
		t.Errorf("Discover = %+v, want one explicit file", got)
	}
	if _, err := Discover(context.Background(), []string{filepath.Join(root, "missing")}, Options{}); err == nil {
		t.Error("expected error for missing root")
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		glob, path string
		want       bool
	}{
		{"**/*.yaml", "a/b/c.yaml", true},
		{"**/*.yaml", "c.yaml", true},
		{"a/*.yaml", "a/b/c.yaml", false},
		{"a/**", "a/b/c.yaml", true},
		{"testdata", "testdata/x/y", true},
		{"src/*.tf", "src/main.tf", true},
		{"src/?.tf", "src/ab.tf", false},
	}
	for _, tt := range tests {
		m, err := newMatcher([]string{tt.glob})
		if err != nil {
			t.Fatal(err)
		}
		if got := m.match(tt.path, false); got != tt.want {
			t.Errorf("match(%q, %q) = %v, want %v", tt.glob, tt.path, got, tt.want)
		}
	}
}
