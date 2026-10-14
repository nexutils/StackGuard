package github

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/yamlutil"
)

// This file builds the single "github" resource rules query (see the package
// doc). Project-wide signals (every `uses` / `run` / step name across the
// workflows directory, plus .github/dependabot.yml) are read from the sibling
// workflow files, the way the Dockerfile parser reads its sibling
// .dockerignore.

var (
	shaRef     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	deployName = regexp.MustCompile(`(?i)(deploy|release|publish|prod)`)
	deployCmd  = regexp.MustCompile(`(?i)(kubectl\s+apply|kubectl\s+rollout|helm\s+(upgrade|install)|terraform\s+apply|aws\s+(ecs|lambda|s3\s+sync|cloudformation\s+deploy)|gcloud\s+(run\s+deploy|app\s+deploy|builds\s+submit)|az\s+\S+\s+deploy|serverless\s+deploy|flyctl\s+deploy|wrangler\s+(publish|deploy)|netlify\s+deploy|vercel\s+(deploy|--prod))`)
)

// build assembles the resource for one workflow file.
func build(src parser.Source, doc map[string]any) []models.Resource {
	if doc == nil {
		return nil
	}
	file := src.Path
	props := map[string]any{}

	wf := map[string]any{}
	if file != "" {
		wf["file"] = filepath.ToSlash(file)
	}
	setIf(wf, "name", doc["name"])
	setIf(wf, "env", doc["env"])
	setIf(wf, "concurrency", doc["concurrency"])
	setIf(wf, "permissions", doc["permissions"])
	triggers := normalizeTriggers(doc["on"])
	putList(wf, "triggers", triggers)
	if on := normalizeOn(doc["on"]); len(on) > 0 {
		wf["on"] = on
	}

	wfRef := map[string]any{}
	if file != "" {
		wfRef["file"] = filepath.ToSlash(file)
	}
	putList(wfRef, "triggers", triggers)
	setIf(wfRef, "permissions", doc["permissions"])

	var jobs, steps, envEntries, strs []any
	collectStrings(doc, &strs)
	addEnv(&envEntries, doc["env"], "workflow", file)

	jobsMap, _ := doc["jobs"].(map[string]any)
	for _, id := range sortedKeys(jobsMap) {
		raw, ok := jobsMap[id].(map[string]any)
		if !ok {
			continue
		}
		job, jobSteps := buildJob(id, raw, wfRef, file, &envEntries)
		jobs = append(jobs, job)
		steps = append(steps, jobSteps...)
	}
	putList(wf, "jobs", jobs)

	props["workflows"] = []any{wf}
	putList(props, "jobs", jobs)
	putList(props, "steps", steps)
	putList(props, "env_entries", envEntries)
	putList(props, "strings", strs)
	if ctx := buildContext(file); len(ctx) > 0 {
		props["context"] = ctx
	}

	return []models.Resource{{
		Target: Target, Type: Target, Name: nameFor(file),
		File: file, Line: 1,
		Properties: props, Locations: map[string]models.Position{},
	}}
}

func buildJob(id string, raw map[string]any, wfRef map[string]any, file string, envEntries *[]any) (map[string]any, []any) {
	job := map[string]any{"id": id, "workflow": wfRef}
	setIf(job, "name", raw["name"])
	setIf(job, "permissions", raw["permissions"])
	setIf(job, "concurrency", raw["concurrency"])
	setIf(job, "if", raw["if"])
	setIf(job, "strategy", raw["strategy"])
	setIf(job, "container", raw["container"])
	setIf(job, "services", raw["services"])
	setIf(job, "env", raw["env"])
	setIf(job, "outputs", raw["outputs"])
	setIf(job, "uses", raw["uses"])
	if v, ok := raw["timeout-minutes"]; ok {
		job["timeout_minutes"] = v
	}
	if ro := joinScalars(raw["runs-on"]); ro != "" {
		job["runs_on"] = ro
	}
	putList(job, "needs", toAnyList(raw["needs"]))
	if env := normalizeEnvironment(raw["environment"]); env != nil {
		job["environment"] = env
	}
	if u, ok := raw["uses"].(string); ok {
		if a := parseUses(u); a != nil {
			job["action"] = a
		}
	}
	addEnv(envEntries, raw["env"], "job", file)

	jobRef := map[string]any{"id": id}
	if ro, ok := job["runs_on"]; ok {
		jobRef["runs_on"] = ro
	}
	if env, ok := job["environment"]; ok {
		jobRef["environment"] = env
	}

	var steps []any
	rawSteps, _ := raw["steps"].([]any)
	for _, s := range rawSteps {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		steps = append(steps, buildStep(sm, jobRef, wfRef, file, envEntries))
	}

	isDeploy := deployName.MatchString(id)
	if n, _ := raw["name"].(string); !isDeploy && deployName.MatchString(n) {
		isDeploy = true
	}
	if env, ok := job["environment"].(map[string]any); ok && !isDeploy {
		if n, _ := env["name"].(string); deployName.MatchString(n) {
			isDeploy = true
		}
	}
	if !isDeploy {
		for _, s := range steps {
			if run, _ := s.(map[string]any)["run"].(string); deployCmd.MatchString(run) {
				isDeploy = true
				break
			}
		}
	}
	job["is_deploy"] = isDeploy
	jobRef["is_deploy"] = isDeploy
	putList(job, "steps", steps)
	return job, steps
}

func buildStep(raw map[string]any, jobRef, wfRef map[string]any, file string, envEntries *[]any) map[string]any {
	st := map[string]any{"job": jobRef, "workflow": wfRef}
	for _, k := range []string{"id", "name", "uses", "run", "shell", "if", "env", "with"} {
		setIf(st, k, raw[k])
	}
	if v, ok := raw["continue-on-error"]; ok {
		st["continue_on_error"] = v
	}
	if v, ok := raw["timeout-minutes"]; ok {
		st["timeout_minutes"] = v
	}
	if with, ok := raw["with"].(map[string]any); ok {
		putList(st, "with_pairs", flattenPairs("", with))
	}
	if u, ok := raw["uses"].(string); ok {
		if a := parseUses(u); a != nil {
			st["action"] = a
		}
	}
	addEnv(envEntries, raw["env"], "step", file)
	return st
}

// parseUses splits a `uses:` reference into its parts.
func parseUses(u string) map[string]any {
	u = strings.TrimSpace(u)
	if u == "" {
		return nil
	}
	a := map[string]any{}
	switch {
	case strings.HasPrefix(u, "docker://"):
		a["kind"] = "docker"
		return a
	case strings.HasPrefix(u, "./") || strings.HasPrefix(u, "../"):
		a["kind"] = "local"
		a["path"] = u
		return a
	}
	a["kind"] = "repo"
	ref := ""
	if i := strings.LastIndex(u, "@"); i > 0 {
		ref = u[i+1:]
		u = u[:i]
	}
	parts := strings.Split(u, "/")
	if len(parts) >= 1 {
		a["owner"] = parts[0]
	}
	if len(parts) >= 2 {
		a["repo"] = parts[1]
	}
	if len(parts) > 2 {
		a["path"] = strings.Join(parts[2:], "/")
	}
	if ref != "" {
		a["ref"] = ref
	}
	a["ref_is_sha"] = shaRef.MatchString(ref)
	return a
}

// normalizeTriggers reduces `on` (string, list or map) to the event names.
func normalizeTriggers(on any) []any {
	switch t := on.(type) {
	case string:
		return []any{t}
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]any, 0, len(t))
		for _, k := range sortedKeys(t) {
			out = append(out, k)
		}
		return out
	}
	return nil
}

// normalizeOn renders `on` as a map of event -> config.
func normalizeOn(on any) map[string]any {
	switch t := on.(type) {
	case string:
		return map[string]any{t: nil}
	case []any:
		out := map[string]any{}
		for _, e := range t {
			if s, ok := e.(string); ok {
				out[s] = nil
			}
		}
		return out
	case map[string]any:
		return t
	}
	return nil
}

// normalizeEnvironment turns a string environment into {name}.
func normalizeEnvironment(v any) map[string]any {
	switch t := v.(type) {
	case string:
		return map[string]any{"name": t}
	case map[string]any:
		return t
	}
	return nil
}

func addEnv(out *[]any, v any, level, file string) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	for _, k := range sortedKeys(m) {
		e := map[string]any{"key": k, "value": scalarString(m[k]), "level": level}
		if file != "" {
			e["file"] = filepath.ToSlash(file)
		}
		*out = append(*out, e)
	}
}

// buildContext reads the sibling workflows (and .github/dependabot.yml) for the
// project-wide signals the repository-scoped rules need.
func buildContext(self string) map[string]any {
	if self == "" {
		return nil
	}
	dir := filepath.Dir(self)     // .github/workflows
	parent := filepath.Dir(dir)   // .github
	base := filepath.Base(parent) // ".github"
	ctx := map[string]any{}

	var files, uses, runs, names []any
	_ = filepath.WalkDir(parent, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(parent, p)
		if rerr != nil {
			return nil
		}
		files = append(files, base+"/"+filepath.ToSlash(rel))
		if len(files) >= 500 {
			return filepath.SkipAll
		}
		return nil
	})
	if len(files) > 0 {
		ctx["files"] = files
	}

	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !isYAMLFile(e.Name()) {
				continue
			}
			data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
			if rerr != nil {
				continue
			}
			doc := decodeMap(data)
			jobs, _ := doc["jobs"].(map[string]any)
			for _, jid := range sortedKeys(jobs) {
				j, ok := jobs[jid].(map[string]any)
				if !ok {
					continue
				}
				list, _ := j["steps"].([]any)
				for _, s := range list {
					sm, ok := s.(map[string]any)
					if !ok {
						continue
					}
					if v, ok := sm["uses"].(string); ok {
						uses = append(uses, v)
					}
					if v, ok := sm["run"].(string); ok {
						runs = append(runs, v)
					}
					if v, ok := sm["name"].(string); ok {
						names = append(names, v)
					}
				}
			}
		}
	}
	putList(ctx, "uses", uses)
	putList(ctx, "runs", runs)
	putList(ctx, "step_names", names)

	for _, n := range []string{"dependabot.yml", "dependabot.yaml"} {
		if data, rerr := os.ReadFile(filepath.Join(parent, n)); rerr == nil {
			if m := decodeMap(data); m != nil {
				ctx["dependabot"] = m
			}
			break
		}
	}
	return ctx
}

// ---- helpers ----

func flattenPairs(prefix string, m map[string]any) []any {
	var out []any
	for _, k := range sortedKeys(m) {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch v := m[k].(type) {
		case map[string]any:
			out = append(out, flattenPairs(key, v)...)
		default:
			out = append(out, key+"="+scalarString(v))
		}
	}
	return out
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(strings.Trim(yamlScalar(t), "\n"))
	}
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case int:
		return itoa(t)
	case int64:
		return itoa(int(t))
	case float64:
		if t == float64(int(t)) {
			return itoa(int(t))
		}
	}
	return ""
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func joinScalars(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, scalarString(e))
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func toAnyList(v any) []any {
	switch t := v.(type) {
	case string:
		return []any{t}
	case []any:
		return t
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func collectStrings(v any, out *[]any) {
	if len(*out) >= 5000 {
		return
	}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) != "" {
			*out = append(*out, t)
		}
	case []any:
		for _, e := range t {
			collectStrings(e, out)
		}
	case map[string]any:
		for _, k := range sortedKeys(t) {
			collectStrings(t[k], out)
		}
	}
}

func decodeMap(data []byte) map[string]any {
	docs, err := yamlutil.Documents(data)
	if err != nil {
		return nil
	}
	for _, doc := range docs {
		dec := yamlutil.NewDecoder()
		v, err := dec.Decode(doc, "")
		if err != nil {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return nil
}

func isYAMLFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yml" || ext == ".yaml"
}

func setIf(m map[string]any, key string, v any) {
	if v != nil {
		m[key] = v
	}
}

func putList(m map[string]any, key string, v []any) {
	if len(v) > 0 {
		m[key] = v
	}
}

func nameFor(path string) string {
	if path == "" {
		return "workflow.yml"
	}
	return filepath.Base(path)
}
