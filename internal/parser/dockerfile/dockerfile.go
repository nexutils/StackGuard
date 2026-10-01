// Package dockerfile parses a Dockerfile into a single "dockerfile" resource.
//
// Unlike a per-stage view, the whole file is one resource so rules can reason
// about the build as a unit: which stage ships, what every stage does, and the
// build context. The property model is:
//
//	directives.<name>        parser directives (# syntax=, # escape=, # check=)
//	context.dockerignore[*]  patterns from a sibling .dockerignore (if present)
//	stages[*]                one entry per FROM, in order
//	final                    the last stage (what ships)
//	all                      list fields unioned across stages, plus pre-FROM ARGs
//
// Each stage (and final) exposes:
//
//	name                 AS alias (absent if none)
//	base                 image reference after FROM (or an earlier stage alias)
//	base_stage           true when base refers to an earlier stage
//	platform             --platform value
//	index                stage position; layer_count / max_consecutive_run
//	instructions.<n>     {cmd, args, index} keyed by global instruction index
//	run[*]               RUN text (exec form space-joined)
//	copy[*]              COPY/ADD: {cmd, from, src[*], dest, chown, chmod,
//	                     checksum, remote}
//	env[*] / arg[*]      "KEY=VALUE" / "KEY" or "KEY=default"
//	labels               map of LABELs written in this file
//	expose[*]            "port/proto"        volume[*]  container paths
//	user                 last USER
//	entrypoint / cmd     {value, form: exec|shell}
//	healthcheck          {value, interval, timeout, start_period, retries}
//	stopsignal           string
//	packages[*]          {manager, name, version} from install commands
//	package_counts.<n>   times <n> is installed
package dockerfile

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

const Target = "dockerfile"

var (
	heredocStart = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)
	directiveRe  = regexp.MustCompile(`^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.+?)\s*$`)
)

// knownDirectives are the only comments treated as parser directives; any other
// leading comment ends directive parsing.
var knownDirectives = map[string]bool{"syntax": true, "escape": true, "check": true}

// Parser implements parser.Parser for Dockerfiles.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	base := strings.ToLower(f.Base())
	return base == "dockerfile" ||
		base == "containerfile" ||
		strings.HasPrefix(base, "dockerfile.") ||
		strings.HasSuffix(base, ".dockerfile")
}

// Instruction is one logical Dockerfile instruction.
type Instruction struct {
	Cmd  string
	Args string
	Line int
}

func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	content := string(src.Content)
	instrs := Lex(content)

	var (
		stages   []*stage
		cur      *stage
		aliases  = map[string]bool{}
		preArg   []any
		preLines []int
		gi       int
	)
	for _, in := range instrs {
		gi++
		if in.Cmd == "FROM" {
			st := newStage(in, len(stages), aliases)
			stages = append(stages, st)
			cur = st
			if st.name != "" {
				aliases[strings.ToLower(st.name)] = true
			}
			continue
		}
		if cur == nil {
			if in.Cmd == "ARG" { // ARG before the first FROM belongs to `all`
				for _, a := range argEntries(in.Args) {
					preArg = append(preArg, a)
					preLines = append(preLines, in.Line)
				}
			}
			continue
		}
		cur.apply(in, gi)
	}
	if len(stages) == 0 {
		return nil, nil
	}

	res := models.Resource{
		Target:     Target,
		Type:       Target,
		Name:       nameFor(src.Path),
		File:       src.Path,
		Line:       fromLine(stages[0]),
		Properties: map[string]any{},
		Locations:  map[string]models.Position{},
	}
	props := res.Properties

	if d := parseDirectives(content); len(d) > 0 {
		props["directives"] = d
	}
	if di := readDockerignore(src.Path); di != nil {
		props["context"] = map[string]any{"dockerignore": di}
	}

	stageMaps := make([]any, len(stages))
	for i, st := range stages {
		stageMaps[i] = st.toMap()
	}
	props["stages"] = stageMaps
	props["final"] = stageMaps[len(stages)-1]
	props["all"] = buildAll(&res, stages, preArg, preLines)

	registerLocations(&res, stages)
	return []models.Resource{res}, nil
}

// buildAll unions the list fields of every stage (plus pre-FROM ARGs) and, as a
// side effect, registers the source line of each unioned item under all.*.
func buildAll(res *models.Resource, stages []*stage, preArg []any, preLines []int) map[string]any {
	all := map[string]any{}
	var run, copies, env, arg, pkgs []any

	for i, a := range preArg {
		res.Locations["all.arg."+strconv.Itoa(len(arg))] = models.Position{Line: preLines[i]}
		arg = append(arg, a)
	}
	appendAll := func(field string, items []any, st *stage, dst *[]any) {
		for j, it := range items {
			if line, ok := st.locs[field+"."+strconv.Itoa(j)]; ok {
				res.Locations["all."+field+"."+strconv.Itoa(len(*dst))] = models.Position{Line: line}
			}
			*dst = append(*dst, it)
		}
	}
	for _, st := range stages {
		appendAll("run", st.run, st, &run)
		appendAll("copy", st.copies, st, &copies)
		appendAll("env", st.env, st, &env)
		appendAll("arg", st.arg, st, &arg)
		pkgs = append(pkgs, st.pkgList...)
	}
	putList(all, "run", run)
	putList(all, "copy", copies)
	putList(all, "env", env)
	putList(all, "arg", arg)
	putList(all, "packages", pkgs)
	return all
}

// registerLocations mirrors each stage's relative positions under the paths the
// stage is exposed at (stages.N and, for the last stage, final).
func registerLocations(res *models.Resource, stages []*stage) {
	mirror := func(prefix string, st *stage) {
		res.Locations[prefix] = models.Position{Line: fromLine(st)}
		for rel, line := range st.locs {
			res.Locations[prefix+"."+rel] = models.Position{Line: line}
		}
	}
	for i, st := range stages {
		mirror("stages."+strconv.Itoa(i), st)
	}
	mirror("final", stages[len(stages)-1])
}

func fromLine(st *stage) int {
	if l, ok := st.locs["base"]; ok {
		return l
	}
	return 1
}

func nameFor(path string) string {
	if path == "" {
		return "Dockerfile"
	}
	return filepath.Base(path)
}

// parseDirectives reads leading parser-directive comments, stopping at the first
// line that is not a known directive.
func parseDirectives(content string) map[string]any {
	out := map[string]any{}
	for _, ln := range strings.Split(content, "\n") {
		m := directiveRe.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			break
		}
		key := strings.ToLower(m[1])
		if !knownDirectives[key] {
			break
		}
		out[key] = m[2]
	}
	return out
}

// readDockerignore returns the sibling .dockerignore patterns, a non-nil empty
// slice when the file exists but is empty, or nil when there is no file (or the
// source is in-memory with no path).
func readDockerignore(dockerfilePath string) []any {
	if dockerfilePath == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(dockerfilePath), ".dockerignore"))
	if err != nil {
		return nil
	}
	out := []any{}
	for _, ln := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// Lex splits a Dockerfile into logical instructions, joining line
// continuations, dropping comments and consuming heredoc bodies.
func Lex(content string) []Instruction {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var out []Instruction
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		start := i + 1
		var b strings.Builder
		for {
			trimmed := strings.TrimRight(line, " \t")
			if strings.HasSuffix(trimmed, "\\") {
				b.WriteString(strings.TrimRight(strings.TrimSuffix(trimmed, "\\"), " \t"))
				b.WriteByte(' ')
				// Skip comment and blank lines inside a continuation.
				for i+1 < len(lines) {
					next := strings.TrimSpace(lines[i+1])
					if next == "" || strings.HasPrefix(next, "#") {
						i++
						continue
					}
					break
				}
				if i+1 >= len(lines) {
					break
				}
				i++
				line = strings.TrimSpace(lines[i])
				continue
			}
			b.WriteString(trimmed)
			break
		}
		logical := strings.TrimSpace(b.String())
		cmd, args, _ := strings.Cut(logical, " ")
		cmd = strings.ToUpper(cmd)
		args = strings.TrimSpace(args)

		if m := heredocStart.FindStringSubmatch(args); m != nil && (cmd == "RUN" || cmd == "COPY" || cmd == "ADD") {
			var body []string
			for i+1 < len(lines) {
				i++
				if strings.TrimSpace(lines[i]) == m[1] {
					break
				}
				body = append(body, lines[i])
			}
			args += "\n" + strings.Join(body, "\n")
		}
		out = append(out, Instruction{Cmd: cmd, Args: args, Line: start})
	}
	return out
}

// splitQuoted splits on whitespace outside of quotes.
func splitQuoted(s string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote rune
	)
	for _, c := range s {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			cur.WriteRune(c)
		case c == '"' || c == '\'':
			quote = c
			cur.WriteRune(c)
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
