package dockerfile

import (
	"context"
	"reflect"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

func TestLex(t *testing.T) {
	src := "# comment\n" +
		"FROM alpine:3.19\n" +
		"RUN apk add \\\n" +
		"    # inline comment\n" +
		"    curl \\\n" +
		"    git\n" +
		"run <<EOT\n" +
		"echo hi\n" +
		"EOT\n" +
		"USER app\n"
	want := []Instruction{
		{Cmd: "FROM", Args: "alpine:3.19", Line: 2},
		{Cmd: "RUN", Args: "apk add curl git", Line: 3},
		{Cmd: "RUN", Args: "<<EOT\necho hi", Line: 7},
		{Cmd: "USER", Args: "app", Line: 10},
	}
	if got := Lex(src); !reflect.DeepEqual(got, want) {
		t.Errorf("Lex:\n got %#v\nwant %#v", got, want)
	}
}

// parse is a test helper: parse source with no file path (so no .dockerignore).
func parse(t *testing.T, content string) map[string]any {
	t.Helper()
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte(content)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	return res[0].Properties
}

func TestParseModel(t *testing.T) {
	src := `# syntax=docker/dockerfile:1
FROM golang:1.22 AS build
ARG VERSION=1.0
RUN go build -o app .
FROM alpine:3.19
LABEL org.opencontainers.image.title="demo"
COPY --from=build /src/app /app
RUN apk add --no-cache curl=8.5.0 && apk add git
ENV PORT=8080 SECRET=shh
EXPOSE 8080
USER nobody
HEALTHCHECK --interval=30s CMD ["curl","-f","http://localhost:8080/health"]
ENTRYPOINT ["/app"]
`
	props := parse(t, src)

	stages, ok := props["stages"].([]any)
	if !ok || len(stages) != 2 {
		t.Fatalf("stages: got %T len %d, want 2", props["stages"], len(stages))
	}
	final := props["final"].(map[string]any)

	if final["base"] != "alpine:3.19" {
		t.Errorf("final.base = %v", final["base"])
	}
	if final["base_stage"] != false {
		t.Errorf("final.base_stage = %v", final["base_stage"])
	}
	if final["user"] != "nobody" {
		t.Errorf("final.user = %v", final["user"])
	}
	// COPY --from=build is structured.
	copies := final["copy"].([]any)
	c0 := copies[0].(map[string]any)
	if c0["from"] != "build" || c0["dest"] != "/app" {
		t.Errorf("copy = %#v", c0)
	}
	if src0 := c0["src"].([]any); len(src0) != 1 || src0[0] != "/src/app" {
		t.Errorf("copy.src = %#v", c0["src"])
	}
	// ENV is a KEY=VALUE list.
	if env := final["env"].([]any); !reflect.DeepEqual(env, []any{"PORT=8080", "SECRET=shh"}) {
		t.Errorf("final.env = %#v", env)
	}
	// EXPOSE normalizes the protocol.
	if exp := final["expose"].([]any); len(exp) != 1 || exp[0] != "8080/tcp" {
		t.Errorf("final.expose = %#v", exp)
	}
	// HEALTHCHECK flags and test command.
	hc := final["healthcheck"].(map[string]any)
	if hc["interval"] != "30s" || hc["value"] != "curl -f http://localhost:8080/health" {
		t.Errorf("healthcheck = %#v", hc)
	}
	// ENTRYPOINT exec form.
	ep := final["entrypoint"].(map[string]any)
	if ep["form"] != "exec" || ep["value"] != "/app" {
		t.Errorf("entrypoint = %#v", ep)
	}
	// packages parsed from both apk invocations; curl pinned, git not.
	pkgs := final["packages"].([]any)
	if len(pkgs) != 2 {
		t.Fatalf("packages = %#v", pkgs)
	}
	if p0 := pkgs[0].(map[string]any); p0["name"] != "curl" || p0["version"] != "8.5.0" {
		t.Errorf("packages[0] = %#v", p0)
	}
	if p1 := pkgs[1].(map[string]any); p1["name"] != "git" || p1["version"] != nil {
		t.Errorf("packages[1] = %#v (version should be absent)", p1)
	}
	// two separate apk add layers -> max_consecutive_run counts the RUN streak.
	if final["max_consecutive_run"].(int) != 1 {
		t.Errorf("max_consecutive_run = %v", final["max_consecutive_run"])
	}

	// `all` sees RUNs from every stage.
	all := props["all"].(map[string]any)
	if run := all["run"].([]any); len(run) != 2 {
		t.Errorf("all.run = %#v", run)
	}
	if arg := all["arg"].([]any); !reflect.DeepEqual(arg, []any{"VERSION=1.0"}) {
		t.Errorf("all.arg = %#v", arg)
	}
	// directives captured.
	if d := props["directives"].(map[string]any); d["syntax"] != "docker/dockerfile:1" {
		t.Errorf("directives = %#v", d)
	}
}

func TestParseNoFROM(t *testing.T) {
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte("# just a comment\n")})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Errorf("expected no resources for a Dockerfile with no FROM, got %d", len(res))
	}
}
