package jenkins

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
)

// builder walks the block tree and assembles the jenkins resource model.
type builder struct {
	text, code string
	dir        string
	lineOf     func(int) int
	locs       map[string]models.Position

	steps     []any
	stages    []any
	agents    []any
	env       []any
	libraries []any

	declarative bool
	seenInput   bool
}

// --- block-name classification ---

var postConditions = map[string]bool{
	"always": true, "success": true, "failure": true, "unstable": true,
	"unsuccessful": true, "aborted": true, "changed": true, "fixed": true,
	"regression": true, "cleanup": true,
}

var structural = map[string]bool{
	"pipeline": true, "stages": true, "stage": true, "steps": true, "post": true,
	"options": true, "environment": true, "agent": true, "when": true, "tools": true,
	"triggers": true, "parameters": true, "parallel": true, "matrix": true,
	"axes": true, "axis": true, "exclude": true, "excludes": true,
	"docker": true, "dockerfile": true, "kubernetes": true, "input": true,
}

// wrapperSteps take a closure and are themselves steps.
var wrapperSteps = map[string]bool{
	"withCredentials": true, "sshagent": true, "withAWS": true, "withVault": true,
	"withDockerRegistry": true, "withKubeConfig": true, "withKubeCredentials": true,
	"withEnv": true, "timeout": true, "retry": true, "dir": true, "lock": true,
	"ws": true, "catchError": true, "warnError": true, "waitUntil": true,
	"container": true, "podTemplate": true, "ansiColor": true, "wrap": true,
	"timestamps": true, "configFileProvider": true, "withMaven": true,
}

var credsScopeSteps = map[string]bool{
	"withCredentials": true, "sshagent": true, "withAWS": true, "withVault": true,
	"withDockerRegistry": true, "withKubeConfig": true, "withKubeCredentials": true,
	"configFileProvider": true,
}

// walkCtx carries the lexical context down into steps.
type walkCtx struct {
	inPost        bool
	postCondition string
	credsInScope  bool
	enclosing     []string
	stage         *stageAcc
	agentType     string
	agentLabel    string
}

func (c walkCtx) with(name string) walkCtx {
	c.enclosing = append(append([]string{}, c.enclosing...), name)
	if credsScopeSteps[name] {
		c.credsInScope = true
	}
	return c
}

// stageAcc accumulates one stage as it is walked.
type stageAcc struct {
	name           string
	options        []any
	hasTimeout     bool
	hasInput       bool
	hasWhen        bool
	whenText       string
	parallel       bool
	failFast       bool
	inputSubmitter bool
	envName        string
	agentType      string
	agentLabel     string
	stepNames      map[string]bool
	scripts        []string
	postStepName   map[string]bool
	postConds      []any
	line           int
}

func newStageAcc() *stageAcc {
	return &stageAcc{stepNames: map[string]bool{}, postStepName: map[string]bool{}}
}

// --- top-level build ---

func (b *builder) build(root *block) (map[string]any, map[string]models.Position) {
	b.locs = map[string]models.Position{}

	pipe := findChild(root, "pipeline")
	b.declarative = pipe != nil
	scope := root
	if pipe != nil {
		scope = pipe
		b.locs["pipeline"] = models.Position{Line: b.lineOf(pipe.headerStart)}
	}

	// Pipeline-level directives.
	pipeOptions := b.optionNames(findChild(scope, "options"))
	pipePost := conditionNames(findChild(scope, "post"))
	pipeTools := b.toolEntries(findChild(scope, "tools"))
	pipeTriggers := b.triggerNames(findChild(scope, "triggers"))
	pipeEnvCreds := b.collectEnv(findChild(scope, "environment"))

	topType, topLabel := "", ""
	if pipe != nil {
		if ab := findChild(pipe, "agent"); ab != nil {
			topType, topLabel = b.parseAgent(ab)
			b.addAgent(topType, topLabel, ab, nil)
		} else if t, l := inlineAgent(b.childlessCode(pipe)); t != "" {
			topType, topLabel = t, l
			b.addAgent(t, l, nil, nil)
		}
	} else {
		topType, topLabel = b.scriptedAgent(root)
		if topType != "" {
			b.addAgent(topType, topLabel, findChild(root, "node"), nil)
		}
	}

	ctx := walkCtx{credsInScope: pipeEnvCreds, agentType: topType, agentLabel: topLabel}

	if b.declarative {
		if sb := findChild(scope, "stages"); sb != nil {
			for _, st := range sb.children {
				if st.name == "stage" {
					b.walkStage(st, ctx)
				}
			}
		}
		// pipeline-level post steps (notifications, cleanup).
		b.walkPost(findChild(scope, "post"), ctx, nil)
	} else {
		b.walkScripted(root, ctx)
	}

	kind := "scripted"
	if b.declarative {
		kind = "declarative"
	}
	pipeline := map[string]any{
		"kind":               kind,
		"has_global_timeout": contains(pipeOptions, "timeout") || (!b.declarative && hasDescendantBlock(root, "timeout")),
		"options_names":      pipeOptions,
		"post_conditions":    pipePost,
		"triggers":           pipeTriggers,
	}
	// `tools` is set only when a tools block exists, so `exists` checks work.
	if len(pipeTools) > 0 {
		pipeline["tools"] = pipeTools
	}

	props := map[string]any{
		"pipeline":    pipeline,
		"stages":      b.stages,
		"steps":       b.steps,
		"agents":      b.agents,
		"env_entries": b.env,
		"libraries":   b.collectLibraries(),
		"strings":     b.stringLiterals(),
		"text":        b.text,
		"context":     map[string]any{"files": scanDir(b.dir)},
	}
	return props, b.locs
}

// scanDir lists the file paths in the Jenkinsfile's directory subtree (relative
// to it), so rules can look for sibling automation (DR / backup pipelines). It is
// best-effort: an unreadable directory (in-memory sources, the golden harness)
// yields nothing.
func scanDir(dir string) []any {
	if dir == "" || dir == "." {
		dir = "."
	}
	var out []any
	const maxFiles = 20000
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if count >= maxFiles {
			return fs.SkipAll
		}
		count++
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return stringOf(out[i]) < stringOf(out[j]) })
	return out
}

// --- stage ---

func (b *builder) walkStage(stage *block, ctx walkCtx) {
	sa := newStageAcc()
	sa.name = headerArg(b.text, stage)
	sa.line = b.lineOf(stage.headerStart)
	sa.options = b.optionNames(findChild(stage, "options"))
	sa.hasTimeout = contains(sa.options, "timeout") || hasDescendantBlock(stage, "timeout")
	sa.parallel = findChild(stage, "parallel") != nil
	sa.failFast = regexp.MustCompile(`\bfailFast\s+true\b`).MatchString(b.childlessCode(stage))
	if w := findChild(stage, "when"); w != nil {
		sa.hasWhen = true
		sa.whenText = strings.TrimSpace(b.text[w.bodyStart:w.bodyEnd])
	}
	stEnvCreds := b.collectEnv(findChild(stage, "environment"))
	sa.envName = b.stageEnv(stage, sa.name)

	at, al := ctx.agentType, ctx.agentLabel
	if a := findChild(stage, "agent"); a != nil {
		at, al = b.parseAgent(a)
		b.addAgent(at, al, a, sa)
	} else if t, l := inlineAgent(b.childlessCode(stage)); t != "" {
		at, al = t, l
		b.addAgent(t, l, nil, sa)
	}
	sa.agentType, sa.agentLabel = at, al

	// input directive / step makes the stage gated.
	stageCode := b.childlessCode(stage)
	inputBlk := findChild(stage, "input")
	sa.hasInput = inputBlk != nil || hasLeafStep(stageCode, "input") ||
		regexp.MustCompile(`(?m)^\s*input\b`).MatchString(stageCode)
	if sa.hasInput {
		region := stageCode
		if inputBlk != nil {
			region = b.text[inputBlk.bodyStart:min(inputBlk.bodyEnd, len(b.text))]
		}
		sa.inputSubmitter = regexp.MustCompile(`\bsubmitter\b`).MatchString(region) ||
			regexp.MustCompile(`\bsubmitter\b`).MatchString(b.text[stage.bodyStart:min(stage.bodyEnd, len(b.text))])
	}

	stageIdx := len(b.stages)
	b.locs[idx("stages", stageIdx)] = models.Position{Line: sa.line}

	stepCtx := ctx
	stepCtx.stage = sa
	stepCtx.agentType, stepCtx.agentLabel = at, al
	if stEnvCreds {
		stepCtx.credsInScope = true
	}

	if sb := findChild(stage, "steps"); sb != nil {
		b.walkSteps(sb, stepCtx)
	} else if !sa.parallel {
		// scripted stage: steps live directly in the stage body.
		b.walkSteps(stage, stepCtx)
	}
	if p := findChild(stage, "parallel"); p != nil {
		for _, c := range p.children {
			if c.name == "stage" {
				b.walkStage(c, ctx)
			}
		}
	}
	b.walkPost(findChild(stage, "post"), stepCtx, sa)

	b.stages = append(b.stages, b.finalizeStage(sa))
}

func (b *builder) finalizeStage(sa *stageAcc) map[string]any {
	scripts := strings.Join(sa.scripts, "\n")
	m := map[string]any{
		"name":            sa.name,
		"options_names":   sa.options,
		"has_timeout":     sa.hasTimeout,
		"has_input":       sa.hasInput,
		"has_when":        sa.hasWhen,
		"parallel":        sa.parallel,
		"failFast":        sa.failFast,
		"step_names":      keys(sa.stepNames),
		"scripts":         scripts,
		"post_step_names": keys(sa.postStepName),
		"post_conditions": sa.postConds,
		"is_deploy":       isDeploy(sa.name, scripts),
		"targets_prod":    targetsProd(sa.name, sa.envName),
	}
	// `input` and `when` are set only when present, so `exists` checks work.
	if sa.hasInput {
		m["input"] = true
		if sa.inputSubmitter {
			m["input_submitter"] = true
		}
	}
	if sa.hasWhen {
		m["when"] = sa.whenText
	}
	if sa.envName != "" {
		m["environment_name"] = sa.envName
	}
	// gated: an input anywhere at/above this stage.
	m["gated"] = sa.hasInput || b.seenInput
	if sa.hasInput {
		b.seenInput = true
	}
	return m
}

// --- steps ---

func (b *builder) walkSteps(region *block, ctx walkCtx) {
	b.addLeafSteps(region, ctx)
	for _, c := range region.children {
		switch {
		case c.name == "stage":
			b.walkStage(c, ctx)
		case c.name == "parallel":
			for _, cc := range c.children {
				if cc.name == "stage" {
					b.walkStage(cc, ctx)
				}
			}
		case wrapperSteps[c.name]:
			b.addStep(c.name, headerArgsText(b.text, c), "", "", ctx, c.headerStart)
			b.walkSteps(c, ctx.with(c.name))
		case c.name == "node":
			nc := ctx
			nc.agentType, nc.agentLabel = "node", headerArg(b.text, c)
			b.walkSteps(c, nc)
		case c.name == "script":
			b.walkSteps(c, ctx)
		case structural[c.name] || postConditions[c.name]:
			// handled by the stage/pipeline; not a step
		default:
			b.walkSteps(c, ctx)
		}
	}
}

func (b *builder) walkScripted(root *block, ctx walkCtx) {
	// Scripted pipelines have no stages{} wrapper; stage('x'){} and steps appear
	// directly. Treat the whole file as a steps region.
	b.walkSteps(root, ctx)
}

func (b *builder) walkPost(post *block, ctx walkCtx, sa *stageAcc) {
	if post == nil {
		return
	}
	pc := ctx
	pc.inPost = true
	for _, cond := range post.children {
		if !postConditions[cond.name] {
			continue
		}
		if sa != nil {
			sa.postConds = appendUnique(sa.postConds, cond.name)
		}
		cc := pc
		cc.postCondition = cond.name
		before := len(b.steps)
		b.walkSteps(cond, cc)
		if sa != nil {
			for _, s := range b.steps[before:] {
				sa.postStepName[stringOf(s.(map[string]any)["name"])] = true
			}
		}
	}
}

var shRe = regexp.MustCompile(`\b(sh|bat|powershell|pwsh)\s*\(?\s*(?:script\s*:\s*)?('''|"""|'|")`)
var leafRe = regexp.MustCompile(`(?m)(?:^|[;{}])[ \t]*([a-zA-Z_]\w*)\b`)

// inlineAgent detects the brace-less agent directives `agent any` / `agent none`.
func inlineAgent(code string) (atype, label string) {
	if m := regexp.MustCompile(`\bagent\s+(any|none)\b`).FindStringSubmatch(code); m != nil {
		return m[1], ""
	}
	return "", ""
}

// addLeafSteps extracts the leaf steps that sit directly in a region's body.
func (b *builder) addLeafSteps(region *block, ctx walkCtx) {
	ownCode := b.childlessCode(region)
	base := region.bodyStart

	// sh / bat / powershell / pwsh with their script body and quote style.
	for _, m := range shRe.FindAllStringSubmatchIndex(ownCode, -1) {
		name := ownCode[m[2]:m[3]]
		quoteTok := ownCode[m[4]:m[5]]
		bodyStart := base + m[5]
		quote := quoteStyle(quoteTok)
		script := ""
		if end := strings.Index(b.text[bodyStart:], quoteTok); end >= 0 {
			script = b.text[bodyStart : bodyStart+end]
		}
		b.addStep(name, script, script, quote, ctx, base+m[0])
	}

	// Other leaf step calls (archiveArtifacts, junit, input, cleanWs, ...).
	for _, m := range leafRe.FindAllStringSubmatchIndex(ownCode, -1) {
		name := ownCode[m[2]:m[3]]
		if structural[name] || postConditions[name] || wrapperSteps[name] ||
			name == "sh" || name == "bat" || name == "powershell" || name == "pwsh" ||
			name == "node" || name == "script" || isKeyword(name) {
			continue
		}
		// skip assignments / property access (def x = ..., currentBuild.x)
		rest := ownCode[m[3]:]
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, ".") {
			continue
		}
		args := lineFrom(b.text, base+m[3])
		b.addStep(name, "", args, "", ctx, base+m[2])
	}
}

func (b *builder) addStep(name, script, args, quote string, ctx walkCtx, off int) {
	i := len(b.steps)
	b.locs[idx("steps", i)] = models.Position{Line: b.lineOf(off)}
	step := map[string]any{
		"name":                 name,
		"script":               script,
		"args":                 args,
		"quote":                quote,
		"post_condition":       ctx.postCondition,
		"credentials_in_scope": ctx.credsInScope,
		"in_post":              ctx.inPost,
		"enclosing":            toAnyList(ctx.enclosing),
		"stage_has_timeout":    ctx.stage != nil && ctx.stage.hasTimeout,
		"agent": map[string]any{
			"type":  ctx.agentType,
			"label": ctx.agentLabel,
		},
	}
	b.steps = append(b.steps, step)
	if ctx.stage != nil {
		ctx.stage.stepNames[name] = true
		if script != "" {
			ctx.stage.scripts = append(ctx.stage.scripts, script)
		}
	}
}

// --- directives ---

func (b *builder) optionNames(opt *block) []any {
	if opt == nil {
		return []any{}
	}
	return callNames(b.childlessCode(opt))
}

func conditionNames(post *block) []any {
	if post == nil {
		return []any{}
	}
	var out []any
	for _, c := range post.children {
		if postConditions[c.name] {
			out = appendUnique(out, c.name)
		}
	}
	return out
}

func (b *builder) toolEntries(tools *block) []any {
	if tools == nil {
		return []any{}
	}
	out := []any{}
	re := regexp.MustCompile(`(?m)^[ \t]*([a-zA-Z_]\w*)\s+['"]([^'"]+)['"]`)
	for _, m := range re.FindAllStringSubmatch(b.text[tools.bodyStart:tools.bodyEnd], -1) {
		out = append(out, map[string]any{"type": m[1], "name": m[2]})
	}
	return out
}

func (b *builder) triggerNames(trig *block) []any {
	if trig == nil {
		return []any{}
	}
	return callNames(b.childlessCode(trig))
}

// collectEnv records an environment block's entries and reports whether any entry
// binds a credentials() helper.
func (b *builder) collectEnv(envBlk *block) bool {
	if envBlk == nil {
		return false
	}
	hasCreds := false
	re := regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_]\w*)\s*=\s*(.+?)[ \t]*$`)
	for _, m := range re.FindAllStringSubmatch(b.text[envBlk.bodyStart:envBlk.bodyEnd], -1) {
		kind, value := classifyEnvValue(strings.TrimSpace(m[2]))
		if kind == "credentials" {
			hasCreds = true
		}
		i := len(b.env)
		b.locs[idx("env_entries", i)] = models.Position{Line: b.lineOf(envBlk.headerStart)}
		b.env = append(b.env, map[string]any{"key": m[1], "value": value, "value_kind": kind})
	}
	return hasCreds
}

func classifyEnvValue(raw string) (kind, value string) {
	if strings.HasPrefix(raw, "credentials(") {
		return "credentials", raw
	}
	if len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') {
		if i := strings.LastIndexByte(raw, raw[0]); i > 0 {
			inner := raw[1:i]
			if strings.Contains(inner, "${") {
				return "reference", inner
			}
			return "literal", inner
		}
	}
	if strings.Contains(raw, "${") || strings.Contains(raw, "env.") {
		return "reference", raw
	}
	return "expr", raw
}

// --- agents ---

func (b *builder) parseAgent(agent *block) (atype, label string) {
	if agent == nil {
		return "", ""
	}
	own := b.childlessCode(agent)
	switch {
	case findChild(agent, "kubernetes") != nil:
		return "kubernetes", ""
	case findChild(agent, "dockerfile") != nil:
		return "dockerfile", ""
	case findChild(agent, "docker") != nil:
		return "docker", ""
	case regexp.MustCompile(`\bany\b`).MatchString(own):
		return "any", ""
	case regexp.MustCompile(`\bnone\b`).MatchString(own):
		return "none", ""
	case regexp.MustCompile(`\blabel\b`).MatchString(own):
		return "label", firstString(b.text[agent.bodyStart:agent.bodyEnd])
	}
	return "custom", ""
}

func (b *builder) scriptedAgent(root *block) (atype, label string) {
	if n := findChild(root, "node"); n != nil {
		return "node", headerArg(b.text, n)
	}
	return "node", ""
}

func (b *builder) addAgent(atype, label string, agent *block, _ *stageAcc) {
	entry := map[string]any{"type": atype, "label": label, "args": "", "yaml": "", "images": []any{}}
	if agent != nil {
		if d := findChild(agent, "docker"); d != nil {
			entry["images"] = []any{firstString(b.text[d.bodyStart:d.bodyEnd])}
			if m := regexp.MustCompile(`args\s+['"]([^'"]*)['"]`).FindStringSubmatch(b.text[d.bodyStart:d.bodyEnd]); m != nil {
				entry["args"] = m[1]
			}
		}
		if k := findChild(agent, "kubernetes"); k != nil {
			entry["yaml"] = strings.TrimSpace(b.text[k.bodyStart:k.bodyEnd])
			entry["images"] = imagesIn(b.text[k.bodyStart:k.bodyEnd])
		}
		own := b.text[agent.bodyStart:agent.bodyEnd]
		if m := regexp.MustCompile(`args\s+['"]([^'"]*)['"]`).FindStringSubmatch(own); m != nil && entry["args"] == "" {
			entry["args"] = m[1]
		}
	}
	i := len(b.agents)
	if agent != nil {
		b.locs[idx("agents", i)] = models.Position{Line: b.lineOf(agent.headerStart)}
	}
	b.agents = append(b.agents, entry)
}

// --- libraries & strings ---

func (b *builder) collectLibraries() []any {
	out := []any{}
	seen := map[string]bool{}
	add := func(spec string) {
		spec = strings.Trim(spec, `'"`)
		if spec == "" || seen[spec] {
			return
		}
		seen[spec] = true
		name, version := spec, ""
		if at := strings.LastIndexByte(spec, '@'); at >= 0 {
			name, version = spec[:at], spec[at+1:]
		}
		e := map[string]any{"name": name}
		if version != "" {
			e["version"] = version
		}
		out = append(out, e)
	}
	for _, m := range regexp.MustCompile(`@Library\(\s*(\[[^\]]*\]|['"][^'"]+['"])`).FindAllStringSubmatch(b.text, -1) {
		for _, s := range regexp.MustCompile(`['"][^'"]+['"]`).FindAllString(m[1], -1) {
			add(s)
		}
	}
	for _, m := range regexp.MustCompile(`\blibrary\s*\(?\s*(?:identifier\s*:\s*)?['"]([^'"]+)['"]`).FindAllStringSubmatch(b.text, -1) {
		add(m[1])
	}
	return out
}

func (b *builder) stringLiterals() []any {
	out := []any{}
	seen := map[string]bool{}
	text := b.text
	n := len(text)
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for i := 0; i < n; {
		switch {
		case strings.HasPrefix(text[i:], "//"):
			if j := strings.IndexByte(text[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = n
			}
		case strings.HasPrefix(text[i:], "/*"):
			if j := strings.Index(text[i+2:], "*/"); j >= 0 {
				i += 2 + j + 2
			} else {
				i = n
			}
		case strings.HasPrefix(text[i:], "'''") || strings.HasPrefix(text[i:], `"""`):
			q := text[i : i+3]
			if j := strings.Index(text[i+3:], q); j >= 0 {
				add(text[i+3 : i+3+j])
				i += 3 + j + 3
			} else {
				i = n
			}
		case text[i] == '\'' || text[i] == '"':
			q := text[i]
			j := i + 1
			for j < n && text[j] != q && text[j] != '\n' {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			add(text[i+1 : min(j, n)])
			i = j + 1
		default:
			i++
		}
	}
	sort.Slice(out, func(i, j int) bool { return stringOf(out[i]) < stringOf(out[j]) })
	return out
}

// --- derivations ---

var deployRe = regexp.MustCompile(`(?i)\b(kubectl\s+(apply|set|rollout)|helm\s+(upgrade|install)|terraform\s+apply|aws\s+(deploy|ecs|s3\s+sync|cloudformation)|az\s+webapp|gcloud\s+(app|run)\s+deploy|argocd\s+app|ansible-playbook|serverless\s+deploy|cap\s+\w+\s+deploy|docker\s+stack\s+deploy|flyctl\s+deploy|netlify\s+deploy|vercel\b)`)
var deployNameRe = regexp.MustCompile(`(?i)(deploy|release|rollout|publish|ship|promote|canary|blue-?green)`)

func isDeploy(name, scripts string) bool {
	return deployNameRe.MatchString(name) || deployRe.MatchString(scripts)
}

func targetsProd(name, env string) bool {
	re := regexp.MustCompile(`(?i)\b(prod|production|prd|live)\b`)
	return re.MatchString(name) || re.MatchString(env)
}

// stageEnv derives a stage's target environment from its name, an explicit
// environment entry, or a --namespace / --context / workspace argument.
func (b *builder) stageEnv(stage *block, name string) string {
	re := regexp.MustCompile(`(?i)\b(prod|production|prd|live|stag|staging|qa|uat|pre-?prod|dev|development|test|int|sandbox)\b`)
	if m := re.FindString(name); m != "" {
		return strings.ToLower(m)
	}
	if e := findChild(stage, "environment"); e != nil {
		body := b.text[e.bodyStart:e.bodyEnd]
		if m := regexp.MustCompile(`(?mi)^\s*(DEPLOY_ENV|ENVIRONMENT|ENV|TARGET_ENV)\s*=\s*['"]?([a-z0-9_-]+)`).FindStringSubmatch(body); m != nil {
			return strings.ToLower(m[2])
		}
	}
	code := b.childlessCode(stage)
	if m := regexp.MustCompile(`(?i)(--namespace|--context|-n)[= ]([a-z0-9_-]+)`).FindStringSubmatch(b.text[stage.bodyStart:min(stage.bodyEnd, len(b.text))]); m != nil {
		_ = code
		return strings.ToLower(m[2])
	}
	return ""
}

// --- small helpers ---

func (b *builder) childlessCode(blk *block) string { return blankChildren(b.code, blk) }

func blankChildren(src string, blk *block) string {
	if blk.bodyStart > len(src) {
		return ""
	}
	end := blk.bodyEnd
	if end > len(src) {
		end = len(src)
	}
	buf := []byte(src[blk.bodyStart:end])
	for _, c := range blk.children {
		from := c.headerStart
		if from < blk.bodyStart {
			from = blk.bodyStart
		}
		to := c.bodyEnd + 1
		if to > end {
			to = end
		}
		for k := from - blk.bodyStart; k < to-blk.bodyStart && k >= 0 && k < len(buf); k++ {
			if buf[k] != '\n' {
				buf[k] = ' '
			}
		}
	}
	return string(buf)
}

func findChild(blk *block, name string) *block {
	if blk == nil {
		return nil
	}
	for _, c := range blk.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

func hasDescendantBlock(blk *block, name string) bool {
	for _, c := range blk.children {
		if c.name == name || hasDescendantBlock(c, name) {
			return true
		}
	}
	return false
}

func hasLeafStep(code, name string) bool {
	return regexp.MustCompile(`(?m)(?:^|[;&|{(])\s*` + regexp.QuoteMeta(name) + `\b`).MatchString(code)
}

func callNames(code string) []any {
	var out []any
	for _, m := range regexp.MustCompile(`(?m)(?:^|[;&|{(])\s*([a-zA-Z_]\w*)\s*\(`).FindAllStringSubmatch(code, -1) {
		out = appendUnique(out, m[1])
	}
	return out
}

func headerArg(text string, blk *block) string {
	if blk.headerStart < 0 || blk.start > len(text) {
		return ""
	}
	return firstString(text[blk.headerStart:blk.start])
}

func headerArgsText(text string, blk *block) string {
	if blk.headerStart < 0 || blk.start > len(text) {
		return ""
	}
	return strings.TrimSpace(text[blk.headerStart:blk.start])
}

func firstString(s string) string {
	if m := regexp.MustCompile(`['"]([^'"]*)['"]`).FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func imagesIn(yaml string) []any {
	out := []any{}
	for _, m := range regexp.MustCompile(`(?m)image:\s*['"]?([^\s'"]+)`).FindAllStringSubmatch(yaml, -1) {
		out = append(out, m[1])
	}
	return out
}

func lineFrom(text string, off int) string {
	if off >= len(text) {
		return ""
	}
	end := strings.IndexByte(text[off:], '\n')
	if end < 0 {
		return strings.TrimSpace(text[off:])
	}
	return strings.TrimSpace(text[off : off+end])
}

func quoteStyle(q string) string {
	switch q {
	case "'''":
		return "triple_single"
	case `"""`:
		return "triple_double"
	case "'":
		return "single"
	case `"`:
		return "double"
	}
	return ""
}

var keywords = map[string]bool{
	"def": true, "if": true, "else": true, "for": true, "while": true, "return": true,
	"try": true, "catch": true, "finally": true, "switch": true, "case": true,
	"new": true, "import": true, "class": true, "true": true, "false": true, "null": true,
	"public": true, "private": true, "static": true, "void": true, "int": true,
	"String": true, "println": true, "assert": true, "throw": true, "do": true,
	"break": true, "continue": true, "this": true, "it": true, "each": true,
}

func isKeyword(s string) bool { return keywords[s] }

func idx(prefix string, i int) string { return models.JoinIndex(prefix, i) }

func contains(list []any, s string) bool {
	for _, e := range list {
		if stringOf(e) == s {
			return true
		}
	}
	return false
}

func appendUnique(list []any, s string) []any {
	if contains(list, s) {
		return list
	}
	return append(list, s)
}

func keys(m map[string]bool) []any {
	out := make([]any, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return stringOf(out[i]) < stringOf(out[j]) })
	return out
}

func toAnyList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
