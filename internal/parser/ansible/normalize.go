package ansible

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// This file normalizes raw decoded tasks/vars into the shape rules query (see
// the package doc). It reuses moduleOf/shortModule/taskKeywords from ansible.go.

var boolWord = regexp.MustCompile(`^(?i)(yes|no|true|false|on|off)$`)

// boolify converts Ansible's YAML-1.1 boolean spellings to real bools, leaving
// everything else untouched. Applied to task keywords and module args, not to
// free-form command text or variable values (where literal text matters).
func boolify(v any) any {
	if s, ok := v.(string); ok && boolWord.MatchString(s) {
		switch strings.ToLower(s) {
		case "yes", "true", "on":
			return true
		case "no", "false", "off":
			return false
		}
	}
	return v
}

func asBool(v any) (val, ok bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(t) {
		case "yes", "true", "on", "1":
			return true, true
		case "no", "false", "off", "0":
			return false, true
		}
	}
	return false, false
}

// stringList turns a scalar or list into a []any of strings (for when/notify/tags).
func stringList(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, scalarString(e))
		}
		return out
	default:
		return []any{scalarString(v)}
	}
}

// scalarString renders a scalar; maps/lists are JSON-encoded (var values).
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case bool, int, int64, float64:
		b, _ := json.Marshal(t)
		return string(b)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// taskCtx carries inherited facts while flattening a task list.
type taskCtx struct {
	kind         string // task | handler | pre_task | post_task
	role, file   string
	become       bool // play- or block-level become in effect
	inBlock      bool
	inRescue     bool
	inAlways     bool
	ancestorLoop bool
	comments     map[int]string
}

var withKey = regexp.MustCompile(`^with_`)

// normalizeTask builds the queryable property map for one task.
func normalizeTask(raw map[string]any, line int, c taskCtx) map[string]any {
	t := map[string]any{}
	fqcn := moduleOf(raw)
	module := shortModule(fqcn)
	if fqcn != "" {
		t["module"] = module
		t["module_raw"] = fqcn
	}
	if name, ok := raw["name"].(string); ok {
		t["name"] = name
	}

	// Arguments: module value (map / free-form string / argv) merged with `args`.
	args, cmd := moduleArgs(raw, fqcn, module)
	if cmd != "" {
		args["cmd"] = cmd
	}
	if len(args) > 0 {
		t["args"] = args
		t["arg_pairs"] = flattenArgs("", args)
	}

	// Scalar task keywords, boolified where they are booleans.
	copyKey := func(key string, boolean bool) {
		if v, ok := raw[key]; ok {
			if boolean {
				if b, ok := asBool(v); ok {
					t[key] = b
					return
				}
			}
			t[key] = v
		}
	}
	for _, k := range []string{"register", "changed_when", "failed_when", "retries", "until",
		"delay", "become_user", "async", "poll", "throttle", "delegate_to", "check_mode"} {
		copyKey(k, false)
	}
	for _, k := range []string{"ignore_errors", "no_log", "run_once", "become", "diff"} {
		copyKey(k, true)
	}
	if v, ok := raw["check_mode"]; ok {
		if b, ok := asBool(v); ok {
			t["check_mode"] = b
		}
	}
	for _, k := range []string{"when", "notify", "tags"} {
		if v, ok := raw[k]; ok {
			t[k] = stringList(v)
		}
	}

	// become_effective: task, block or play level.
	become, _ := asBool(raw["become"])
	t["become_effective"] = become || c.become

	// Loops.
	loopRaw, hasLoop := raw["loop"]
	if !hasLoop {
		for k, v := range raw {
			if withKey.MatchString(k) {
				loopRaw, hasLoop = v, true
				break
			}
		}
	}
	if hasLoop {
		t["loop"] = true
		t["loop_raw"] = scalarString(loopRaw)
		t["nested_loop"] = c.ancestorLoop
	}
	if lc, ok := raw["loop_control"].(map[string]any); ok {
		if lv, ok := lc["loop_var"]; ok {
			t["loop_control"] = map[string]any{"loop_var": lv}
		}
	}

	// keywords: task keys that are not the module and not plain args.
	var keywords []any
	for k := range raw {
		if taskKeywords[k] || withKey.MatchString(k) || k == fqcn {
			keywords = append(keywords, k)
		}
	}
	sort.Slice(keywords, func(i, j int) bool { return keywords[i].(string) < keywords[j].(string) })
	if len(keywords) > 0 {
		t["keywords"] = keywords
	}

	t["kind"] = c.kind
	if c.inBlock {
		t["in_block"] = true
	}
	if c.inRescue {
		t["in_rescue"] = true
	}
	if c.inAlways {
		t["in_always"] = true
	}
	if c.role != "" {
		t["role"] = c.role
	}
	if c.file != "" {
		t["file"] = c.file
	}
	if cm := c.comments[line]; cm != "" {
		t["comment"] = cm
	} else if cm := c.comments[line-1]; cm != "" {
		t["comment"] = cm
	}
	return t
}

// moduleArgs extracts a task's arguments as a map plus a free-form cmd string.
func moduleArgs(raw map[string]any, fqcn, module string) (map[string]any, string) {
	args := map[string]any{}
	cmd := ""

	freeForm := map[string]bool{"shell": true, "command": true, "raw": true, "script": true}
	if v, ok := raw[fqcn]; ok {
		switch val := v.(type) {
		case map[string]any:
			for k, e := range val {
				args[k] = boolify(e)
			}
		case string:
			if freeForm[module] {
				cmd = val
			} else {
				mergeKV(args, val)
			}
		}
	}
	if argv, ok := raw["argv"].([]any); ok {
		parts := make([]string, 0, len(argv))
		for _, a := range argv {
			parts = append(parts, scalarString(a))
		}
		cmd = strings.TrimSpace(cmd + " " + strings.Join(parts, " "))
	}
	if extra, ok := raw["args"].(map[string]any); ok {
		for k, e := range extra {
			if k == "cmd" {
				if s, ok := e.(string); ok {
					cmd = s
				}
				continue
			}
			args[k] = boolify(e)
		}
	}
	return args, cmd
}

// mergeKV parses "k=v k2=v2" free-form into args.
func mergeKV(args map[string]any, s string) {
	for _, tok := range strings.Fields(s) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			args[k] = boolify(v)
		}
	}
}

// flattenArgs renders args as "key=value" pairs, dotting nested keys.
func flattenArgs(prefix string, args map[string]any) []any {
	var out []any
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch v := args[k].(type) {
		case map[string]any:
			out = append(out, flattenArgs(key, v)...)
		default:
			out = append(out, key+"="+scalarString(v))
		}
	}
	return out
}
