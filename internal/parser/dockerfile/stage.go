package dockerfile

import (
	"encoding/json"
	"strconv"
	"strings"
)

// stage accumulates the instructions of one FROM section into the property
// shape rules query (see the package doc for the full model).
type stage struct {
	index     int
	name      string // AS alias; empty when unnamed
	base      string // image reference, or the alias of an earlier stage
	baseStage bool   // base refers to an earlier stage
	platform  string

	instrs map[string]any // keyed by the stringified global instruction index
	run    []any          // RUN command text (exec form space-joined)
	copies []any          // COPY/ADD, structured
	env    []any          // "KEY=VALUE"
	arg    []any          // "KEY" or "KEY=default"
	labels map[string]any
	expose []any // "port/proto"
	volume []any

	user       string
	hasUser    bool
	entrypoint map[string]any
	cmd        map[string]any
	health     map[string]any
	stopsignal string

	layerCount int
	maxRun     int
	runStreak  int

	pkgList []any // packages as property maps, reused when building `all`

	// locs maps a stage-relative property path ("base", "run.0", "user", …) to
	// its source line, so the orchestrator can register accurate positions at
	// every path the stage is exposed under (stages.N, final, all).
	locs map[string]int
}

// newStage parses a FROM instruction. aliases holds the lower-cased names of
// stages declared before this one, so a base that refers to one is detected.
func newStage(in Instruction, index int, aliases map[string]bool) *stage {
	s := &stage{index: index, instrs: map[string]any{}, labels: map[string]any{}, locs: map[string]int{}}
	fields := strings.Fields(in.Args)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasPrefix(f, "--platform="):
			s.platform = strings.TrimPrefix(f, "--platform=")
		case strings.HasPrefix(f, "--"):
		case strings.EqualFold(f, "AS") && i+1 < len(fields):
			s.name = fields[i+1]
			i++
		case s.base == "":
			s.base = f
		}
	}
	s.baseStage = aliases[strings.ToLower(s.base)]
	if s.base != "" {
		s.locs["base"] = in.Line
	}
	return s
}

// apply folds one non-FROM instruction into the stage. gi is the instruction's
// global index across the whole file, used to order instructions for gt_ref.
func (s *stage) apply(in Instruction, gi int) {
	key := strconv.Itoa(gi)
	s.instrs[key] = map[string]any{"cmd": in.Cmd, "args": in.Args, "index": gi}
	s.locs["instructions."+key] = in.Line

	if in.Cmd == "RUN" || in.Cmd == "COPY" || in.Cmd == "ADD" {
		s.layerCount++
	}
	if in.Cmd == "RUN" {
		s.runStreak++
		if s.runStreak > s.maxRun {
			s.maxRun = s.runStreak
		}
	} else {
		s.runStreak = 0
	}

	switch in.Cmd {
	case "RUN":
		s.locs["run."+strconv.Itoa(len(s.run))] = in.Line
		s.run = append(s.run, runText(in.Args))
	case "COPY", "ADD":
		s.locs["copy."+strconv.Itoa(len(s.copies))] = in.Line
		s.copies = append(s.copies, parseCopy(in.Cmd, in.Args))
	case "ENV":
		for _, e := range envEntries(in.Args) {
			s.locs["env."+strconv.Itoa(len(s.env))] = in.Line
			s.env = append(s.env, e)
		}
	case "ARG":
		for _, a := range argEntries(in.Args) {
			s.locs["arg."+strconv.Itoa(len(s.arg))] = in.Line
			s.arg = append(s.arg, a)
		}
	case "LABEL":
		for k, v := range labelPairs(in.Args) {
			s.labels[k] = v
			s.locs["labels."+k] = in.Line
		}
	case "EXPOSE":
		for _, p := range strings.Fields(in.Args) {
			if !strings.Contains(p, "/") {
				p += "/tcp"
			}
			s.locs["expose."+strconv.Itoa(len(s.expose))] = in.Line
			s.expose = append(s.expose, p)
		}
	case "VOLUME":
		for _, v := range volumeList(in.Args) {
			s.locs["volume."+strconv.Itoa(len(s.volume))] = in.Line
			s.volume = append(s.volume, v)
		}
	case "USER":
		s.user, s.hasUser = strings.TrimSpace(in.Args), true
		s.locs["user"] = in.Line
	case "ENTRYPOINT":
		s.entrypoint = parseExecForm(in.Args)
		s.locs["entrypoint"] = in.Line
		s.locs["entrypoint.value"] = in.Line
	case "CMD":
		s.cmd = parseExecForm(in.Args)
		s.locs["cmd"] = in.Line
		s.locs["cmd.value"] = in.Line
	case "HEALTHCHECK":
		s.health = parseHealthcheck(in.Args)
		s.locs["healthcheck"] = in.Line
		s.locs["healthcheck.value"] = in.Line
	case "STOPSIGNAL":
		s.stopsignal = strings.TrimSpace(in.Args)
		s.locs["stopsignal"] = in.Line
	}
}

// toMap renders the stage's queryable properties. Empty collections are
// omitted so `exists: false` rules behave, while numeric summaries are always
// present.
func (s *stage) toMap() map[string]any {
	m := map[string]any{
		"index":               s.index,
		"base":                s.base,
		"base_stage":          s.baseStage,
		"layer_count":         s.layerCount,
		"max_consecutive_run": s.maxRun,
	}
	if s.name != "" {
		m["name"] = s.name
	}
	if s.platform != "" {
		m["platform"] = s.platform
	}
	putList(m, "run", s.run)
	putList(m, "copy", s.copies)
	putList(m, "env", s.env)
	putList(m, "arg", s.arg)
	putList(m, "expose", s.expose)
	putList(m, "volume", s.volume)
	if len(s.instrs) > 0 {
		m["instructions"] = s.instrs
	}
	if len(s.labels) > 0 {
		m["labels"] = s.labels
	}
	if s.hasUser {
		m["user"] = s.user
	}
	if s.entrypoint != nil {
		m["entrypoint"] = s.entrypoint
	}
	if s.cmd != nil {
		m["cmd"] = s.cmd
	}
	if s.health != nil {
		m["healthcheck"] = s.health
	}
	if s.stopsignal != "" {
		m["stopsignal"] = s.stopsignal
	}

	pkgs := extractPackages(toStrings(s.run))
	if len(pkgs) > 0 {
		list := make([]any, 0, len(pkgs))
		counts := map[string]any{}
		for _, p := range pkgs {
			entry := map[string]any{"manager": p.Manager, "name": p.Name}
			if p.Version != "" {
				entry["version"] = p.Version
			}
			list = append(list, entry)
			counts[p.Name] = countOf(counts, p.Name) + 1
		}
		m["packages"] = list
		m["package_counts"] = counts
		s.pkgList = list
	}
	return m
}

func putList(m map[string]any, key string, v []any) {
	if len(v) > 0 {
		m[key] = v
	}
}

func countOf(m map[string]any, k string) int {
	if n, ok := m[k].(int); ok {
		return n
	}
	return 0
}

func toStrings(vs []any) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// parseCopy turns COPY/ADD arguments into the structured copy shape. Remote is
// true for ADD sources that are URLs or git repositories.
func parseCopy(cmd, args string) map[string]any {
	m := map[string]any{"cmd": cmd}
	var rest []string
	for _, t := range strings.Fields(args) {
		switch {
		case strings.HasPrefix(t, "--from="):
			m["from"] = strings.TrimPrefix(t, "--from=")
		case strings.HasPrefix(t, "--chown="):
			m["chown"] = strings.TrimPrefix(t, "--chown=")
		case strings.HasPrefix(t, "--chmod="):
			m["chmod"] = strings.TrimPrefix(t, "--chmod=")
		case strings.HasPrefix(t, "--checksum="):
			m["checksum"] = strings.TrimPrefix(t, "--checksum=")
		case strings.HasPrefix(t, "--"):
		default:
			rest = append(rest, t)
		}
	}
	// Exec form: COPY ["src", "dest"].
	if len(rest) > 0 && strings.HasPrefix(rest[0], "[") {
		if arr, ok := parseJSONArray(args[strings.IndexByte(args, '['):]); ok {
			rest = arr
		}
	}
	var src []any
	switch {
	case len(rest) >= 2:
		for _, s := range rest[:len(rest)-1] {
			src = append(src, s)
		}
		m["dest"] = rest[len(rest)-1]
	case len(rest) == 1:
		src = append(src, rest[0])
	}
	m["src"] = src
	remote := false
	if cmd == "ADD" {
		for _, s := range src {
			if isRemoteSource(s.(string)) {
				remote = true
			}
		}
	}
	m["remote"] = remote
	return m
}

func isRemoteSource(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "git@") || strings.HasSuffix(s, ".git")
}

// parseExecForm classifies ENTRYPOINT/CMD (and reused for the HEALTHCHECK test
// command) as exec or shell form and returns its joined value.
func parseExecForm(args string) map[string]any {
	a := strings.TrimSpace(args)
	if strings.HasPrefix(a, "[") {
		if arr, ok := parseJSONArray(a); ok {
			return map[string]any{"value": strings.Join(arr, " "), "form": "exec"}
		}
	}
	return map[string]any{"value": a, "form": "shell"}
}

func parseHealthcheck(args string) map[string]any {
	a := strings.TrimSpace(args)
	if strings.EqualFold(a, "NONE") {
		return map[string]any{"value": "NONE"}
	}
	m := map[string]any{"value": ""}
	toks := strings.Fields(a)
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case strings.HasPrefix(t, "--interval="):
			m["interval"] = strings.TrimPrefix(t, "--interval=")
		case strings.HasPrefix(t, "--timeout="):
			m["timeout"] = strings.TrimPrefix(t, "--timeout=")
		case strings.HasPrefix(t, "--start-period="):
			m["start_period"] = strings.TrimPrefix(t, "--start-period=")
		case strings.HasPrefix(t, "--retries="):
			m["retries"] = strings.TrimPrefix(t, "--retries=")
		case strings.HasPrefix(t, "--"):
		default:
			rest := strings.Join(toks[i:], " ")
			for _, kw := range []string{"CMD", "cmd"} {
				rest = strings.TrimSpace(strings.TrimPrefix(rest, kw))
			}
			m["value"] = parseExecForm(rest)["value"]
			return m
		}
	}
	return m
}

func envEntries(args string) []string {
	s := strings.TrimSpace(args)
	if s == "" {
		return nil
	}
	first := strings.Fields(s)[0]
	if !strings.Contains(first, "=") { // legacy: ENV KEY value...
		val := strings.TrimSpace(strings.TrimPrefix(s, first))
		return []string{first + "=" + strings.Trim(val, `"'`)}
	}
	var out []string
	for _, tok := range splitQuoted(s) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			out = append(out, k+"="+strings.Trim(v, `"'`))
		} else {
			out = append(out, tok)
		}
	}
	return out
}

func argEntries(args string) []string { return strings.Fields(strings.TrimSpace(args)) }

func labelPairs(args string) map[string]string {
	out := map[string]string{}
	for _, tok := range splitQuoted(strings.TrimSpace(args)) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			out[strings.Trim(k, `"'`)] = strings.Trim(v, `"'`)
		}
	}
	return out
}

func volumeList(args string) []string {
	a := strings.TrimSpace(args)
	if strings.HasPrefix(a, "[") {
		if arr, ok := parseJSONArray(a); ok {
			return arr
		}
	}
	return strings.Fields(a)
}

func runText(args string) string {
	a := strings.TrimSpace(args)
	if strings.HasPrefix(a, "[") {
		if arr, ok := parseJSONArray(a); ok {
			return strings.Join(arr, " ")
		}
	}
	return a
}

func parseJSONArray(s string) ([]string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil, false
	}
	end := strings.LastIndexByte(s, ']')
	if end < 0 {
		return nil, false
	}
	var arr []string
	if err := json.Unmarshal([]byte(s[:end+1]), &arr); err != nil {
		return nil, false
	}
	return arr, true
}
