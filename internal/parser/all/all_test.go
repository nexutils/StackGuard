package all

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/testutil"
)

const parserFixtures = "../../../testdata/parsers"

// TestParsersGolden detects and parses every fixture under
// testdata/parsers/<target>/ and compares the resources with a golden file
// next to the input (<input>.golden.json). Files the target's parser claims
// but that yield no resources (e.g. Helm templates) produce no golden file.
func TestParsersGolden(t *testing.T) {
	reg := Registry()
	targets, err := os.ReadDir(parserFixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range targets {
		target := dir.Name()
		root := filepath.Join(parserFixtures, target)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasSuffix(path, ".golden.json") {
				return err
			}
			rel, _ := filepath.Rel(parserFixtures, path)
			rel = filepath.ToSlash(rel)
			t.Run(rel, func(t *testing.T) {
				p := reg.Detect(parser.NewFileInfo(path))
				if p == nil || p.Name() != target {
					got := "<none>"
					if p != nil {
						got = p.Name()
					}
					t.Fatalf("detected by %s, want %s", got, target)
				}
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				res, err := p.Parse(context.Background(), parser.Source{Path: rel, Content: content})
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if len(res) == 0 {
					return
				}
				for _, r := range res {
					if r.Target != target || r.Type == "" || r.Name == "" || r.Line <= 0 {
						t.Errorf("incomplete resource: target=%q type=%q name=%q line=%d", r.Target, r.Type, r.Name, r.Line)
					}
				}
				testutil.GoldenJSON(t, path+".golden.json", res)
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetection(t *testing.T) {
	reg := Registry()
	tests := []struct {
		path    string
		content string
		want    string
	}{
		{"docker-compose.yml", "", "compose"},
		{"compose.prod.yaml", "", "compose"},
		{"stack.yml", "services:\n  web:\n    image: x\n", "compose"},
		{"Dockerfile", "", "dockerfile"},
		{"build/api.Dockerfile", "", "dockerfile"},
		{"Dockerfile.dev", "", "dockerfile"},
		{"k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n", "kubernetes"},
		{"main.tf", "", "terraform"},
		{".github/workflows/release.yaml", "on: push\n", "github"},
		{"Jenkinsfile", "", "jenkins"},
		{"ci/deploy.jenkinsfile", "", "jenkins"},
		{"playbook.yml", "- hosts: all\n", "ansible"},
		{"roles/web/tasks/main.yml", "- name: x\n  debug: {}\n", "ansible"},
		{"nginx.conf", "", "nginx"},
		{"conf.d/site.conf", "server {\n listen 80;\n}\n", "nginx"},
		{"random.yaml", "foo: bar\n", ""},
		{"list.yaml", "- a\n- b\n", ""},
		{"app.conf", "key=value\n", ""},
		{"README.md", "# hi", ""},
		{"templated.yaml", "apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Name }}\n", ""},
		{"binary.yaml", "apiVersion: v1\x00kind: x\n", ""},
	}
	for _, tt := range tests {
		p := reg.Detect(parser.NewFileInfoFromBytes(tt.path, []byte(tt.content)))
		got := ""
		if p != nil {
			got = p.Name()
		}
		if got != tt.want {
			t.Errorf("Detect(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
