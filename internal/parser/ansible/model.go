package ansible

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/yamlutil"
)

// mb accumulates the project model while building the single ansible resource.
type mb struct {
	file, dir string
	tasks     []any
	plays     []any
	vars      []any
	roles     []any
	strs      []any
	taskLines []int
	playLines []int
	varCount  map[string]int // excludes role_defaults
	config    map[string]any
	context   map[string]any
	comments  map[int]string
}

// build assembles the resource for a playbook file. Returns ok=false when the
// file is not a playbook (no resource is emitted; its tasks come in via roles).
func build(src parser.Source) ([]models.Resource, error) {
	docs, err := yamlutil.Documents(src.Content)
	if err != nil {
		return nil, err
	}
	m := &mb{file: src.Path, dir: filepath.Dir(src.Path), varCount: map[string]int{}, comments: extractComments(src.Content)}

	line := 1
	isPlaybook := false
	for _, doc := range docs {
		if doc.Kind != yaml.SequenceNode {
			continue
		}
		dec := yamlutil.NewDecoder()
		val, err := dec.Decode(doc, "")
		if err != nil {
			return nil, err
		}
		items, _ := val.([]any)
		m.collectStrings(items)
		for i, it := range items {
			play, ok := it.(map[string]any)
			if !ok || (play["hosts"] == nil && play["import_playbook"] == nil) {
				continue
			}
			isPlaybook = true
			if line == 1 {
				line = dec.Locations[strconv.Itoa(i)].Line
			}
			m.addPlay(play, dec.Locations, i)
		}
	}
	if !isPlaybook {
		return nil, nil
	}
	if src.Path != "" {
		m.readSiblings()
	}

	props := map[string]any{}
	putList(props, "tasks", m.tasks)
	putList(props, "plays", m.plays)
	putList(props, "vars", m.vars)
	putList(props, "roles", m.roles)
	putList(props, "strings", m.strs)
	if len(m.varCount) > 0 {
		vc := map[string]any{}
		for k, n := range m.varCount {
			vc[k] = n
		}
		props["var_counts"] = vc
	}
	if len(m.config) > 0 {
		props["config"] = m.config
	}
	if len(m.context) > 0 {
		props["context"] = m.context
	}

	locs := map[string]models.Position{}
	for i, ln := range m.taskLines {
		if ln > 0 {
			locs["tasks."+strconv.Itoa(i)] = models.Position{Line: ln}
		}
	}
	for i, ln := range m.playLines {
		if ln > 0 {
			locs["plays."+strconv.Itoa(i)] = models.Position{Line: ln}
		}
	}
	return []models.Resource{{
		Target: Target, Type: Target, Name: nameFor(src.Path),
		File: src.Path, Line: line, Properties: props, Locations: locs,
	}}, nil
}

func (m *mb) addPlay(play map[string]any, locs map[string]models.Position, idx int) {
	pp := map[string]any{}
	setIf(pp, "name", play["name"])
	if h, ok := play["hosts"]; ok {
		pp["hosts"] = scalarString(h)
	}
	if b, ok := asBool(play["become"]); ok {
		pp["become"] = b
	}
	setIf(pp, "become_user", play["become_user"])
	setIf(pp, "serial", play["serial"])
	setIf(pp, "max_fail_percentage", play["max_fail_percentage"])
	if b, ok := asBool(play["any_errors_fatal"]); ok {
		pp["any_errors_fatal"] = b
	}
	setIf(pp, "gather_facts", play["gather_facts"])
	setIf(pp, "strategy", play["strategy"])
	if v, ok := play["tags"]; ok {
		pp["tags"] = stringList(v)
	}
	playBecome, _ := asBool(play["become"])

	var ptasks, phandlers, pblocks []any
	kindOf := map[string]string{"pre_tasks": "pre_task", "tasks": "task", "post_tasks": "post_task", "handlers": "handler"}
	base := strconv.Itoa(idx)
	for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
		list, _ := play[section].([]any)
		c := taskCtx{kind: kindOf[section], become: playBecome, comments: m.comments}
		dst := &ptasks
		if section == "handlers" {
			dst = &phandlers
		}
		m.addTasks(list, c, locs, models.JoinPath(base, section), dst, &pblocks, false)
	}
	for _, r := range roleRefs(play["roles"]) {
		m.expandRole(r, playBecome, &ptasks, &phandlers)
	}

	pp["task_count"] = len(ptasks)
	putList(pp, "tasks", ptasks)
	putList(pp, "handlers", phandlers)
	putList(pp, "blocks", pblocks)
	m.addVarsFromMap(mapOf(play["vars"]), "play", m.file, "", false)
	for _, vf := range stringSlice(play["vars_files"]) {
		m.readVarsFile(filepath.Join(m.dir, vf), "play_vars_file", "")
	}

	m.plays = append(m.plays, pp)
	m.playLines = append(m.playLines, locs[base].Line)
}

// addTasks flattens a task list, recursing into block/rescue/always, appending
// to the global tasks and to the play's task/handler/block lists.
func (m *mb) addTasks(list []any, c taskCtx, locs map[string]models.Position, path string, dst, blocks *[]any, ancestorLoop bool) {
	for i, it := range list {
		raw, ok := it.(map[string]any)
		if !ok {
			continue
		}
		p := models.JoinIndex(path, i)
		if _, isBlock := raw["block"]; isBlock {
			blk := map[string]any{}
			bl, _ := asBool(raw["become"])
			cc := c
			cc.become = c.become || bl
			_, hasLoop := raw["loop"]
			for _, section := range []string{"block", "rescue", "always"} {
				sub, _ := raw[section].([]any)
				sc := cc
				sc.inBlock = sc.inBlock || section == "block"
				sc.inRescue = sc.inRescue || section == "rescue"
				sc.inAlways = sc.inAlways || section == "always"
				sc.ancestorLoop = ancestorLoop || hasLoop
				var secTasks []any
				m.addTasks(sub, sc, locs, models.JoinPath(p, section), dst, blocks, sc.ancestorLoop)
				// record the section's tasks on the block (shallow, for plays[*].blocks)
				_ = secTasks
				if s, ok := raw[section].([]any); ok && len(s) > 0 {
					blk[section] = normalizeShallow(s)
				}
			}
			*blocks = append(*blocks, blk)
			continue
		}
		cc := c
		cc.ancestorLoop = ancestorLoop
		t := normalizeTask(raw, locs[p].Line, cc)
		m.tasks = append(m.tasks, t)
		m.taskLines = append(m.taskLines, locs[p].Line)
		*dst = append(*dst, t)
		m.addVarsFromMap(mapOf(raw["vars"]), "task", m.file, "", false)
	}
}

// normalizeShallow renders block section tasks just enough for plays[*].blocks
// rules (args.dest, args.cmd, args.daemon_reload, rescue presence).
func normalizeShallow(list []any) []any {
	out := make([]any, 0, len(list))
	for _, it := range list {
		if raw, ok := it.(map[string]any); ok {
			out = append(out, normalizeTask(raw, 0, taskCtx{kind: "task"}))
		}
	}
	return out
}

func (m *mb) expandRole(name string, playBecome bool, ptasks, phandlers *[]any) {
	roleDir := filepath.Join(m.dir, "roles", name)
	load := func(rel, kind string, dst *[]any) {
		data, err := os.ReadFile(filepath.Join(roleDir, rel))
		if err != nil {
			return
		}
		m.collectStringsBytes(data)
		list := decodeList(data)
		c := taskCtx{kind: kind, role: name, file: filepath.Join("roles", name, rel), become: playBecome, comments: map[int]string{}}
		m.addTasks(list, c, map[string]models.Position{}, "", dst, &[]any{}, false)
	}
	load(filepath.Join("tasks", "main.yml"), "task", ptasks)
	load(filepath.Join("handlers", "main.yml"), "handler", phandlers)
}

func (m *mb) readSiblings() {
	// ansible.cfg
	if data, err := os.ReadFile(filepath.Join(m.dir, "ansible.cfg")); err == nil {
		m.config = parseINI(data)
	}
	// group_vars / host_vars
	for src, sub := range map[string]string{"group_vars": "group_vars", "host_vars": "host_vars"} {
		dir := filepath.Join(m.dir, sub)
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !isYAMLFile(p) {
				return nil
			}
			m.readVarsFile(p, src, "")
			return nil
		})
	}
	// inventory files (best-effort: inventory/, hosts, *.ini)
	for _, name := range []string{"inventory", "hosts", "inventory.yml", "inventory.ini"} {
		p := filepath.Join(m.dir, name)
		if data, err := os.ReadFile(p); err == nil {
			m.readInventory(data)
		}
	}
	// roles: metadata + defaults/vars
	m.readRoles()
	// context
	m.readContext()
}

func (m *mb) readRoles() {
	entries, err := os.ReadDir(filepath.Join(m.dir, "roles"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		roleDir := filepath.Join(m.dir, "roles", name)
		defaults := readYAMLMap(filepath.Join(roleDir, "defaults", "main.yml"))
		rvars := readYAMLMap(filepath.Join(roleDir, "vars", "main.yml"))
		for k, v := range defaults {
			m.addVar(k, v, "role_defaults", filepath.Join("roles", name, "defaults", "main.yml"), name, false)
		}
		for k, v := range rvars {
			m.addVar(k, v, "role_vars", filepath.Join("roles", name, "vars", "main.yml"), name, false)
		}
		hasTests := dirExists(filepath.Join(roleDir, "molecule")) || dirExists(filepath.Join(roleDir, "tests"))
		taskCount := countRoleTasks(roleDir)
		defined := map[string]bool{}
		for k := range defaults {
			defined[k] = true
		}
		for k := range rvars {
			defined[k] = true
		}
		role := map[string]any{
			"name":         name,
			"has_defaults": len(defaults) > 0,
			"has_tests":    hasTests,
			"task_count":   taskCount,
		}
		if without := roleVarsWithoutDefault(roleDir, name, defined); len(without) > 0 {
			role["vars_without_default"] = without
		}
		m.roles = append(m.roles, role)
	}
}

func (m *mb) readContext() {
	ctx := map[string]any{}
	// files + vault files
	var files, vaultFiles []any
	_ = filepath.WalkDir(m.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != m.dir && strings.HasPrefix(d.Name(), ".") && d.Name() != ".ansible-lint" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(m.dir, p)
		rel = filepath.ToSlash(rel)
		files = append(files, rel)
		if isVaultFile(p) {
			vaultFiles = append(vaultFiles, rel)
		}
		if len(files) >= 1000 {
			return filepath.SkipAll
		}
		return nil
	})
	if len(files) > 0 {
		ctx["files"] = files
	}
	if len(vaultFiles) > 0 {
		ctx["vault_files"] = vaultFiles
	}
	// requirements.yml / galaxy.yml
	if reqs := readRequirements(m.dir); len(reqs) > 0 {
		ctx["requirements"] = reqs
	}
	// requirements.txt / pyproject
	if data, err := os.ReadFile(filepath.Join(m.dir, "requirements.txt")); err == nil {
		var py []any
		for _, ln := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(ln); t != "" && !strings.HasPrefix(t, "#") {
				py = append(py, t)
			}
		}
		if len(py) > 0 {
			ctx["python_requirements"] = py
		}
	}
	// .ansible-lint
	if lint := readYAMLMap(filepath.Join(m.dir, ".ansible-lint")); lint != nil {
		ctx["ansible_lint_config"] = lint
	}
	if len(ctx) > 0 {
		m.context = ctx
	}
}

// ---- vars ----

func (m *mb) addVarsFromMap(vars map[string]any, source, file, role string, vaulted bool) {
	for k, v := range vars {
		m.addVar(k, v, source, file, role, vaulted)
	}
}

func (m *mb) addVar(name string, value any, source, file, role string, fileVaulted bool) {
	val := scalarString(value)
	vaulted := fileVaulted || strings.Contains(val, "$ANSIBLE_VAULT")
	entry := map[string]any{
		"name": name, "value": val, "source": source, "vaulted": vaulted,
	}
	if file != "" {
		entry["file"] = file
	}
	if role != "" {
		entry["role"] = role
		entry["role_prefixed"] = strings.HasPrefix(name, role+"_")
	}
	m.vars = append(m.vars, entry)
	if source != "role_defaults" {
		m.varCount[name]++
	}
}

func (m *mb) readVarsFile(path, source, role string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	m.collectStringsBytes(data)
	vaulted := isVaultBytes(data)
	vars := decodeMap(data)
	for k, v := range vars {
		m.addVar(k, v, source, filepath.Base(path), role, vaulted)
	}
}

func (m *mb) readInventory(data []byte) {
	// YAML inventory: pull vars under any `vars:` mapping.
	if vars := decodeMap(data); vars != nil {
		var walk func(v any)
		walk = func(v any) {
			mp, ok := v.(map[string]any)
			if !ok {
				return
			}
			if vv, ok := mp["vars"].(map[string]any); ok {
				m.addVarsFromMap(vv, "inventory", "inventory", "", false)
			}
			for _, child := range mp {
				walk(child)
			}
		}
		walk(map[string]any(vars))
		m.collectStringsBytes(data)
		return
	}
	// INI inventory: key=value host vars.
	for _, ln := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "[") {
			continue
		}
		for _, tok := range strings.Fields(t) {
			if k, v, ok := strings.Cut(tok, "="); ok {
				m.addVar(k, v, "inventory", "inventory", "", false)
			}
		}
	}
}

// ---- strings ----

func (m *mb) collectStrings(v any) {
	if len(m.strs) >= 5000 {
		return
	}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) != "" {
			m.strs = append(m.strs, t)
		}
	case []any:
		for _, e := range t {
			m.collectStrings(e)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.collectStrings(t[k])
		}
	}
}

func (m *mb) collectStringsBytes(data []byte) {
	for _, n := range decodeAll(data) {
		m.collectStrings(n)
	}
}

// ---- helpers ----

func extractComments(content []byte) map[int]string {
	out := map[int]string{}
	var root yaml.Node
	if yaml.Unmarshal(content, &root) != nil {
		return out
	}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		for _, c := range []string{n.LineComment, n.HeadComment} {
			if t := cleanComment(c); t != "" && out[n.Line] == "" {
				out[n.Line] = t
			}
		}
		for _, ch := range n.Content {
			walk(ch)
		}
	}
	walk(&root)
	return out
}

func cleanComment(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "#")
	return strings.TrimSpace(s)
}

func roleRefs(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, r := range list {
		switch t := r.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			if n, ok := t["role"].(string); ok {
				out = append(out, n)
			} else if n, ok := t["name"].(string); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

func roleVarsWithoutDefault(roleDir, name string, defined map[string]bool) []any {
	used := map[string]bool{}
	ref := regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(\|[^}]*)?\}\}`)
	_ = filepath.WalkDir(filepath.Join(roleDir, "tasks"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isYAMLFile(p) {
			return nil
		}
		data, _ := os.ReadFile(p)
		for _, mt := range ref.FindAllStringSubmatch(string(data), -1) {
			v, filt := mt[1], mt[2]
			if strings.Contains(filt, "default") {
				continue
			}
			if defined[v] || isAnsibleFact(v) {
				continue
			}
			used[v] = true
		}
		return nil
	})
	var out []any
	for v := range used {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].(string) < out[j].(string) })
	return out
}

func isAnsibleFact(v string) bool {
	return strings.HasPrefix(v, "ansible_") || v == "item" || v == "inventory_hostname" ||
		v == "hostvars" || v == "groups" || v == "role_name" || v == "role_path" || v == "playbook_dir"
}

func readRequirements(dir string) []any {
	var out []any
	for _, name := range []string{"requirements.yml", "requirements.yaml", "galaxy.yml"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		top := decodeMap(data)
		for _, kind := range []string{"collections", "roles", "dependencies"} {
			list, _ := top[kind].([]any)
			k := "collection"
			if kind == "roles" {
				k = "role"
			}
			for _, item := range list {
				entry := map[string]any{"kind": k}
				switch t := item.(type) {
				case string:
					entry["name"] = t
				case map[string]any:
					if n, ok := t["name"]; ok {
						entry["name"] = n
					}
					if ver, ok := t["version"]; ok {
						entry["version"] = scalarString(ver)
					}
				}
				out = append(out, entry)
			}
		}
	}
	return out
}

func countRoleTasks(roleDir string) int {
	n := 0
	_ = filepath.WalkDir(filepath.Join(roleDir, "tasks"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isYAMLFile(p) {
			return nil
		}
		data, _ := os.ReadFile(p)
		n += len(decodeList(data))
		return nil
	})
	return n
}

func readYAMLMap(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return decodeMap(data)
}

func decodeMap(data []byte) map[string]any {
	for _, doc := range decodeAll(data) {
		if mp, ok := doc.(map[string]any); ok {
			return mp
		}
	}
	return nil
}

func decodeList(data []byte) []any {
	for _, doc := range decodeAll(data) {
		if l, ok := doc.([]any); ok {
			return l
		}
	}
	return nil
}

func decodeAll(data []byte) []any {
	docs, err := yamlutil.Documents(data)
	if err != nil {
		return nil
	}
	var out []any
	for _, doc := range docs {
		dec := yamlutil.NewDecoder()
		if v, err := dec.Decode(doc, ""); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func isVaultFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 20)
	n, _ := f.Read(buf)
	return strings.HasPrefix(string(buf[:n]), "$ANSIBLE_VAULT")
}

func isVaultBytes(data []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT")
}

func isYAMLFile(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func stringSlice(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
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
		return "playbook.yml"
	}
	return filepath.Base(path)
}
