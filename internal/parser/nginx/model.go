package nginx

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
)

// This file builds the rich per-config model rules query (see the package doc).
// It works on the directive tree produced by ParseConfig, after includes are
// resolved.

// headerDirectives do not inherit from a parent once a context sets any of
// them (nginx's add_header rule); the same applies to proxy_set_header.
var nonInheritingList = map[string]bool{
	"add_header": true, "more_set_headers": true, "proxy_set_header": true,
}

// listDirectives keep every occurrence in `effective` (they are multi-valued);
// everything else keeps only the innermost value.
var listDirectives = map[string]bool{
	"add_header": true, "more_set_headers": true, "proxy_set_header": true,
	"access_log": true,
}

var proxyPassDirectives = []string{"proxy_pass", "grpc_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass"}

var metaComment = regexp.MustCompile(`(?m)^\s*#\s*@([A-Za-z0-9_.-]+)\s*:\s*(.+?)\s*$`)

// ctx is one context's simple (non-block) directives: name -> occurrences, each
// occurrence being its arguments joined by single spaces.
type ctx map[string][]string

// simpleDirs collects the non-block directives of a block into a ctx.
func simpleDirs(dirs []*Directive) ctx {
	c := ctx{}
	for _, d := range dirs {
		if d.HasBlock {
			continue
		}
		c[d.Name] = append(c[d.Name], strings.Join(d.Args, " "))
	}
	return c
}

// listMap renders a ctx as queryable properties: each directive is a list of
// its occurrences (so `x[*]` iterates them and `x` with exists/length_gte works).
func listMap(c ctx) map[string]any {
	m := make(map[string]any, len(c))
	for k, occ := range c {
		vs := make([]any, len(occ))
		for i, o := range occ {
			vs[i] = o
		}
		m[k] = vs
	}
	return m
}

// effectiveMap computes directive values after inheritance down the chain
// (outermost first). Scalars keep the innermost value; header/list directives
// follow nginx's non-inheritance rule.
func effectiveMap(chain []ctx) map[string]any {
	eff := map[string]any{}
	names := map[string]bool{}
	for _, c := range chain {
		for k := range c {
			names[k] = true
		}
	}
	for name := range names {
		if listDirectives[name] {
			// Innermost context that sets it wins entirely (non-inheritance).
			for i := len(chain) - 1; i >= 0; i-- {
				if occ, ok := chain[i][name]; ok && (!nonInheritingList[name] || len(occ) > 0) {
					vs := make([]any, len(occ))
					for j, o := range occ {
						vs[j] = o
					}
					eff[name] = vs
					break
				}
			}
			continue
		}
		// Scalar: innermost value (last occurrence of the innermost setter).
		for i := len(chain) - 1; i >= 0; i-- {
			if occ, ok := chain[i][name]; ok && len(occ) > 0 {
				eff[name] = occ[len(occ)-1]
				break
			}
		}
	}
	eff["headers"] = effectiveHeaders(chain)
	return eff
}

// effectiveHeaders applies add_header inheritance: the innermost context that
// declares any add_header/more_set_headers replaces its parents' headers.
func effectiveHeaders(chain []ctx) []any {
	for i := len(chain) - 1; i >= 0; i-- {
		c := chain[i]
		if len(c["add_header"]) == 0 && len(c["more_set_headers"]) == 0 {
			continue
		}
		var out []any
		for _, h := range c["add_header"] {
			out = append(out, h) // "Name value [always]"
		}
		for _, h := range c["more_set_headers"] {
			// more_set_headers "Name: value" -> "Name value"
			out = append(out, strings.Replace(strings.Trim(h, `"`), ":", "", 1))
		}
		return out
	}
	return nil
}

// serverInfo carries a server's derived facts for building leaves.
type serverInfo struct {
	props  map[string]any
	chain  []ctx // http, server
	tls    bool
	redir  bool
	intern bool
	names  []any
	line   int
	leaves []leafBuild
}

type leafBuild struct {
	props map[string]any
	line  int
}

func buildServer(d *Directive, httpCtx ctx) serverInfo {
	sc := simpleDirs(d.Block)
	chain := []ctx{httpCtx, sc}

	names := toAnyList(sc["server_name"])
	listen := toAnyList(sc["listen"])
	tls := serverHasTLS(sc)
	redir := serverRedirectOnly(d.Block)
	intern := serverInternalOnly(sc)

	sp := listMap(sc)
	sp["server_name"] = names
	sp["listen"] = listen
	sp["tls"] = tls
	sp["redirect_only"] = redir
	sp["internal_only"] = intern
	sp["effective"] = effectiveMap(chain)

	info := serverInfo{props: sp, chain: chain, tls: tls, redir: redir, intern: intern, names: names, line: d.Line}

	var locs []any
	collectLocations(d.Block, chain, names, tls, redir, intern, &locs, &info.leaves)
	sp["locations"] = locs

	// A server with no location is itself a leaf.
	if len(info.leaves) == 0 {
		lp := map[string]any{
			"server_name": names, "tls": tls, "redirect_only": redir, "internal_only": intern,
			"effective": sp["effective"],
		}
		addProxyFacts(lp, chain)
		info.leaves = append(info.leaves, leafBuild{props: lp, line: d.Line})
	}
	return info
}

// collectLocations walks a server's location tree. Every location (nested
// included) becomes a leaf and an entry in the server's locations list.
func collectLocations(dirs []*Directive, parentChain []ctx, names []any, tls, redir, intern bool, locsOut *[]any, leaves *[]leafBuild) {
	for _, d := range dirs {
		if d.Name != "location" || !d.HasBlock {
			continue
		}
		lc := simpleDirs(d.Block)
		chain := append(append([]ctx{}, parentChain...), lc)
		path, modifier := locationPath(d.Args)

		lm := listMap(lc)
		lm["path"] = path
		if modifier != "" {
			lm["modifier"] = modifier
		}
		*locsOut = append(*locsOut, lm)

		lp := map[string]any{
			"path": path, "server_name": names,
			"tls": tls, "redirect_only": redir, "internal_only": intern,
			"effective": effectiveMap(chain),
		}
		if modifier != "" {
			lp["modifier"] = modifier
		}
		addProxyFacts(lp, chain)
		*leaves = append(*leaves, leafBuild{props: lp, line: d.Line})

		// Nested locations.
		collectLocations(d.Block, chain, names, tls, redir, intern, locsOut, leaves)
	}
}

// addProxyFacts sets proxied and proxy_target_is_upstream on a leaf.
func addProxyFacts(lp map[string]any, chain []ctx) {
	eff, _ := lp["effective"].(map[string]any)
	proxied := false
	target := ""
	for _, name := range proxyPassDirectives {
		if v, ok := eff[name]; ok {
			proxied = true
			if name == "proxy_pass" {
				target, _ = v.(string)
			}
		}
	}
	lp["proxied"] = proxied
	lp["proxy_target_is_upstream"] = false
	_ = chain
	if target != "" {
		lp["_proxy_target"] = target // resolved against upstream names later
	}
}

func serverHasTLS(c ctx) bool {
	for _, l := range c["listen"] {
		if regexp.MustCompile(`(^|\s)(ssl|quic)(\s|$)`).MatchString(l) {
			return true
		}
	}
	for _, v := range c["ssl"] {
		if v == "on" {
			return true
		}
	}
	return false
}

func serverRedirectOnly(dirs []*Directive) bool {
	sawAnswer := false
	sawRedirect := false
	var walk func(ds []*Directive)
	walk = func(ds []*Directive) {
		for _, d := range ds {
			if d.HasBlock {
				walk(d.Block)
				continue
			}
			switch d.Name {
			case "return":
				if len(d.Args) > 0 && regexp.MustCompile(`^30[12378]$`).MatchString(d.Args[0]) {
					sawRedirect = true
				} else {
					sawAnswer = true
				}
			case "rewrite":
				if len(d.Args) >= 3 && (d.Args[2] == "permanent" || d.Args[2] == "redirect") {
					sawRedirect = true
				}
			case "proxy_pass", "fastcgi_pass", "root", "alias", "try_files", "index", "grpc_pass":
				sawAnswer = true
			}
		}
	}
	walk(dirs)
	return sawRedirect && !sawAnswer
}

func serverInternalOnly(c ctx) bool {
	if len(c["listen"]) == 0 {
		return false
	}
	for _, l := range c["listen"] {
		addr := strings.Fields(l)
		if len(addr) == 0 {
			return false
		}
		a := addr[0]
		if !strings.HasPrefix(a, "127.0.0.1") && !strings.HasPrefix(a, "[::1]") && !strings.HasPrefix(a, "unix:") {
			return false
		}
	}
	return true
}

func locationPath(args []string) (path, modifier string) {
	if len(args) == 0 {
		return "", ""
	}
	switch args[0] {
	case "=", "~", "~*", "^~":
		if len(args) >= 2 {
			return args[1], args[0]
		}
		return "", args[0]
	}
	return args[0], ""
}

func toAnyList(ss []string) []any {
	if len(ss) == 0 {
		return nil
	}
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// resolveIncludes expands `include <glob>;` directives by reading and parsing
// the referenced files, relative to dir. Missing or unreadable files are
// skipped; recursion is bounded.
func resolveIncludes(dirs []*Directive, dir string, depth int) []*Directive {
	if depth > 16 {
		return dirs
	}
	var out []*Directive
	for _, d := range dirs {
		if d.Name == "include" && !d.HasBlock && len(d.Args) > 0 {
			pattern := d.Args[0]
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(dir, pattern)
			}
			matches, _ := filepath.Glob(pattern)
			for _, m := range matches {
				data, err := os.ReadFile(m)
				if err != nil {
					continue
				}
				sub, err := ParseConfig(string(data))
				if err != nil {
					continue
				}
				out = append(out, resolveIncludes(sub, filepath.Dir(m), depth+1)...)
			}
			continue
		}
		if d.HasBlock {
			d.Block = resolveIncludes(d.Block, dir, depth)
		}
		out = append(out, d)
	}
	return out
}

// buildModel assembles the single per-config resource from the resolved
// directive tree. raw is the main config's text (for # @meta comments); file
// is its path ("" for in-memory sources, which skip disk-derived context).
func buildModel(root []*Directive, file string, raw []byte) models.Resource {
	props := map[string]any{}
	locs := map[string]models.Position{}

	mainCtx := simpleDirs(root)
	props["main"] = listMap(mainCtx)

	var httpBlock, eventsBlock, streamBlock *Directive
	for _, d := range root {
		if !d.HasBlock {
			continue
		}
		switch d.Name {
		case "events":
			eventsBlock = d
		case "http":
			httpBlock = d
		case "stream":
			streamBlock = d
		}
	}
	if eventsBlock != nil {
		props["events"] = listMap(simpleDirs(eventsBlock.Block))
	}
	httpCtx := ctx{}
	if httpBlock != nil {
		httpCtx = simpleDirs(httpBlock.Block)
		props["http"] = listMap(httpCtx)
	}

	logTargets := map[string]bool{}
	addLogs := func(c ctx) {
		for _, key := range []string{"access_log", "error_log"} {
			for _, occ := range c[key] {
				if f := strings.Fields(occ); len(f) > 0 {
					logTargets[f[0]] = true
				}
			}
		}
	}
	addLogs(mainCtx)
	addLogs(httpCtx)

	upstreamNames := map[string]bool{}
	var upstreams []any
	collectUp := func(parent *Directive) {
		if parent == nil {
			return
		}
		for _, d := range parent.Block {
			if d.Name != "upstream" || !d.HasBlock {
				continue
			}
			name := ""
			if len(d.Args) > 0 {
				name = d.Args[0]
			}
			upstreamNames[name] = true
			um := listMap(simpleDirs(d.Block))
			um["name"] = name
			um["health_check"] = false
			um["_line"] = d.Line
			upstreams = append(upstreams, um)
		}
	}
	collectUp(httpBlock)
	collectUp(streamBlock)

	var servers, leaves []any
	var serverLines, leafLines []int
	if httpBlock != nil {
		for _, d := range httpBlock.Block {
			if d.Name != "server" || !d.HasBlock {
				continue
			}
			si := buildServer(d, httpCtx)
			servers = append(servers, si.props)
			serverLines = append(serverLines, si.line)
			addLogs(simpleDirs(d.Block))
			for _, lf := range si.leaves {
				leaves = append(leaves, lf.props)
				leafLines = append(leafLines, lf.line)
			}
		}
	}

	// Resolve proxy_target_is_upstream and upstream health_check.
	upstreamHealth := map[string]bool{}
	for _, lf := range leaves {
		lp := lf.(map[string]any)
		target, ok := lp["_proxy_target"].(string)
		delete(lp, "_proxy_target")
		if !ok {
			continue
		}
		host := proxyHost(target)
		if upstreamNames[host] {
			lp["proxy_target_is_upstream"] = true
			if eff, ok := lp["effective"].(map[string]any); ok {
				if _, has := eff["health_check"]; has {
					upstreamHealth[host] = true
				}
			}
		}
	}
	for _, u := range upstreams {
		um := u.(map[string]any)
		if name, _ := um["name"].(string); upstreamHealth[name] {
			um["health_check"] = true
		}
	}

	if len(servers) > 0 {
		props["servers"] = servers
	}
	if len(leaves) > 0 {
		props["leaves"] = leaves
	}
	if len(upstreams) > 0 {
		props["upstreams"] = upstreams
	}
	if len(logTargets) > 0 {
		lt := make([]any, 0, len(logTargets))
		for t := range logTargets {
			lt = append(lt, t)
		}
		sort.Slice(lt, func(i, j int) bool { return lt[i].(string) < lt[j].(string) })
		props["log_targets"] = lt
	}

	meta := map[string]any{}
	for _, m := range metaComment.FindAllStringSubmatch(string(raw), -1) {
		meta[m[1]] = m[2]
	}
	if len(meta) > 0 {
		props["meta"] = meta
	}
	if file != "" {
		if c := buildContext(file); len(c) > 0 {
			props["context"] = c
		}
	}

	for i, ln := range serverLines {
		locs["servers."+strconv.Itoa(i)] = models.Position{Line: ln}
	}
	for i, ln := range leafLines {
		locs["leaves."+strconv.Itoa(i)] = models.Position{Line: ln}
	}
	for i, u := range upstreams {
		um := u.(map[string]any)
		if ln, ok := um["_line"].(int); ok {
			locs["upstreams."+strconv.Itoa(i)] = models.Position{Line: ln}
			delete(um, "_line")
		}
	}

	line := 1
	if httpBlock != nil {
		line = httpBlock.Line
	}
	return models.Resource{
		Target: Target, Type: Target, Name: nameFor(file),
		File: file, Line: line,
		Properties: props, Locations: locs,
	}
}

// proxyHost extracts the host (or upstream name) from a proxy_pass target.
func proxyHost(t string) string {
	s := strings.TrimSpace(t)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

// buildContext fills the best-effort host/repo context consumed by the
// off-by-default production rules. in_vcs uses a bounded ancestor search so it
// reflects a config kept near its repo root rather than any distant .git.
func buildContext(file string) map[string]any {
	c := map[string]any{}
	dir := filepath.Dir(file)

	inVCS := false
	d := dir
	for i := 0; i < 4; i++ {
		if fi, err := os.Stat(filepath.Join(d, ".git")); err == nil && fi.IsDir() {
			inVCS = true
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	c["in_vcs"] = inVCS

	var files []any
	_ = filepath.WalkDir(dir, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if de.IsDir() {
			if p != dir && strings.HasPrefix(de.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, filepath.ToSlash(p))
		if len(files) >= 200 {
			return filepath.SkipAll
		}
		return nil
	})
	if len(files) > 0 {
		c["files"] = files
	}

	if strings.HasPrefix(dir, "/etc/") || dir == "/etc" {
		for _, p := range []string{"/etc/logrotate.d/nginx", "/etc/logrotate.d/nginx-common"} {
			if _, err := os.Stat(p); err == nil {
				c["logrotate"] = p
				break
			}
		}
	}
	return c
}

func nameFor(file string) string {
	if file == "" {
		return "nginx.conf"
	}
	return filepath.Base(file)
}
