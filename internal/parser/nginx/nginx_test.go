package nginx

import (
	"strings"
	"testing"
)

func TestParseConfigErrors(t *testing.T) {
	bad := []string{
		"http {",
		"}",
		"server_tokens off",
		"http { listen 80 }",
		"{ }",
		`add_header "unterminated;`,
	}
	for _, in := range bad {
		if _, err := ParseConfig(in); err == nil {
			t.Errorf("ParseConfig(%q): expected error", in)
		}
	}
}

func TestParseConfig(t *testing.T) {
	dirs, err := ParseConfig("# c\nhttp {\n  include mime.types; ;\n  server { listen 80; }\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 1 || dirs[0].Name != "http" || len(dirs[0].Block) != 2 {
		t.Fatalf("unexpected tree: %+v", dirs)
	}
	srv := dirs[0].Block[1]
	if srv.Name != "server" || !srv.HasBlock || srv.Line != 4 || strings.Join(srv.Block[0].Args, " ") != "80" {
		t.Errorf("unexpected server directive: %+v", srv)
	}
}

func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{
		"http { server { listen 80; } }",
		`log_format main '$a "${b}"';`,
		"location ~ \\.php$ { deny all; }",
		"a { b { c { d; } } }",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseConfig(s)
	})
}
