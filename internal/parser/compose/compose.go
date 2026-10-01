// Package compose parses Docker Compose files.
//
// Resources:
//
//	service   one per entry under services:
//	network   one per entry under networks:
//	volume    one per entry under volumes:
//	project   the whole file, for rules that look across services
//
// Service properties mirror the Compose file after normalisation, so short
// and long syntax look the same to rules. Variable interpolation is NOT
// resolved: "${VAR:-x}" stays literal text, so rules can see hardcoded
// defaults.
//
//	environment, build.args  list of "KEY=VALUE" (or "KEY" when unset)
//	sysctls                  list of "key=value"
//	labels                   mapping
//	ports      list of "HOST_IP:PUBLISHED:TARGET/PROTO" (HOST_IP and PUBLISHED
//	           empty when unset; IPv6 hosts in brackets):
//	             "5432:5432" -> ":5432:5432/tcp", "9000" -> "::9000/tcp"
//	volumes    list of "TYPE:SOURCE:TARGET:OPTIONS", OPTIONS starting with
//	           rw or ro, then propagation / SELinux flags:
//	             "./src:/app" -> "bind:./src:/app:rw"
//	             "/data"      -> "volume::/data:rw" (anonymous)
//	tmpfs      list of "TARGET:OPTIONS"; tmpfs-type volumes are moved here
//	security_opt              "key:value" (the first "=" becomes ":")
//	cap_add, cap_drop         upper case, without the "CAP_" prefix
//	command, entrypoint, healthcheck.test   one space-joined string
//	memory sizes              bytes (mem_limit, mem_reservation, memswap_limit,
//	                          shm_size, deploy.resources.*.memory)
//	cpus                      float (cpus, deploy.resources.*.cpus)
//	depends_on                left as written (list or mapping)
//
// Derived service properties:
//
//	_image      {name, tag, digest}
//	_services   every service in the file by name (for cross-service rules,
//	            e.g. `_services.{dep}.healthcheck`)
//
// The project resource has the whole file plus:
//
//	_index.volume_mounts.<volume>   services mounting the named volume
//	_index.volume_writers.<volume>  services mounting it read-write
package compose

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nexutils/StackGuard/internal/engine/operators"
	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/imageref"
	"github.com/nexutils/StackGuard/internal/parser/yamlutil"
)

const Target = "compose"

var (
	fileName        = regexp.MustCompile(`^(docker-)?compose([.-][\w.-]+)?\.ya?ml$`)
	topLevelService = regexp.MustCompile(`(?m)^services:\s*$`)
	apiVersionKind  = regexp.MustCompile(`(?m)^(apiVersion|kind):`)
	sizeRe          = regexp.MustCompile(`^(?i)\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?)(?:i?b)?\s*$`)
)

// Parser implements parser.Parser for Docker Compose.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	if !f.IsYAML() {
		return false
	}
	if fileName.MatchString(strings.ToLower(f.Base())) {
		return true
	}
	head := f.Head()
	return topLevelService.Match(head) && !apiVersionKind.Match(head)
}

func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	docs, err := yamlutil.Documents(src.Content)
	if err != nil {
		return nil, err
	}
	var out []models.Resource
	for _, doc := range docs {
		if doc.Kind != yaml.MappingNode {
			continue
		}
		res, err := parseDoc(doc, src.Path)
		if err != nil {
			return nil, err
		}
		out = append(out, res...)
	}
	return out, nil
}

func parseDoc(doc *yaml.Node, file string) ([]models.Resource, error) {
	dec := yamlutil.NewDecoder()
	root, err := dec.DecodeMap(doc, "")
	if err != nil {
		return nil, err
	}
	locs := dec.Locations
	var out []models.Resource

	services, _ := root["services"].(map[string]any)
	names := sortedByLine(services, "services", locs)
	serviceLocs := map[string]map[string]models.Position{}
	for _, name := range names {
		props, ok := services[name].(map[string]any)
		if !ok {
			props = map[string]any{}
			services[name] = props
		}
		prefix := models.JoinPath("services", name)
		sl := yamlutil.SubLocations(locs, prefix)
		normalizeService(props, sl)
		serviceLocs[name] = sl
	}

	// Sibling lookup, built after normalisation so it sees the same shapes.
	siblings := models.Lookup{}
	for _, name := range names {
		siblings[name] = services[name]
	}
	for _, name := range names {
		props := services[name].(map[string]any)
		out = append(out, models.Resource{
			Target:     Target,
			Type:       "service",
			Name:       name,
			File:       file,
			Line:       locs[models.JoinPath("services", name)].Line,
			Properties: withSiblings(props, siblings),
			Locations:  serviceLocs[name],
		})
	}

	for _, section := range []struct{ key, typ string }{{"networks", "network"}, {"volumes", "volume"}} {
		m, _ := root[section.key].(map[string]any)
		for _, name := range sortedByLine(m, section.key, locs) {
			props, _ := m[name].(map[string]any)
			if props == nil {
				props = map[string]any{}
			}
			prefix := models.JoinPath(section.key, name)
			out = append(out, models.Resource{
				Target:     Target,
				Type:       section.typ,
				Name:       name,
				File:       file,
				Line:       locs[prefix].Line,
				Properties: props,
				Locations:  yamlutil.SubLocations(locs, prefix),
			})
		}
	}

	root["_index"] = buildIndex(services, names)
	projectName, _ := root["name"].(string)
	if projectName == "" {
		projectName = filepath.Base(filepath.Dir(file))
		if projectName == "." || projectName == string(filepath.Separator) {
			projectName = "compose project"
		}
	}
	out = append(out, models.Resource{
		Target:     Target,
		Type:       "project",
		Name:       projectName,
		File:       file,
		Line:       1,
		Properties: root,
		Locations:  locs,
	})
	return out, nil
}

// withSiblings returns a shallow copy of props with _services added. A copy
// keeps the project resource's services free of the lookup.
func withSiblings(props map[string]any, siblings models.Lookup) map[string]any {
	out := make(map[string]any, len(props)+1)
	for k, v := range props {
		out[k] = v
	}
	out["_services"] = siblings
	return out
}

// buildIndex computes which services mount each named volume.
func buildIndex(services map[string]any, names []string) map[string]any {
	mounts := map[string]any{}
	writers := map[string]any{}
	for _, name := range names {
		props, _ := services[name].(map[string]any)
		vols, _ := props["volumes"].([]any)
		for _, v := range vols {
			s, _ := v.(string)
			parts := strings.SplitN(s, ":", 4)
			if len(parts) != 4 || parts[0] != "volume" || parts[1] == "" {
				continue
			}
			mounts[parts[1]] = appendUnique(mounts[parts[1]], name)
			if strings.HasPrefix(parts[3], "rw") {
				writers[parts[1]] = appendUnique(writers[parts[1]], name)
			}
		}
	}
	return map[string]any{"volume_mounts": mounts, "volume_writers": writers}
}

func appendUnique(list any, s string) any {
	l, _ := list.([]any)
	for _, e := range l {
		if e == s {
			return l
		}
	}
	return append(l, s)
}

// sortedByLine returns the keys of m in source order.
func sortedByLine(m map[string]any, prefix string, locs map[string]models.Position) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		li := locs[models.JoinPath(prefix, keys[i])].Line
		lj := locs[models.JoinPath(prefix, keys[j])].Line
		if li != lj {
			return li < lj
		}
		return keys[i] < keys[j]
	})
	return keys
}

func normalizeService(props map[string]any, locs map[string]models.Position) {
	if img, ok := props["image"].(string); ok {
		props["_image"] = imageref.Parse(img).Properties()
		if pos, ok := locs["image"]; ok {
			locs["_image"] = pos
		}
	}
	props["environment"] = keyValueList(props["environment"], "environment", locs)
	if props["environment"] == nil {
		delete(props, "environment")
	}
	if build, ok := props["build"].(map[string]any); ok {
		if args := keyValueList(build["args"], "build.args", locs); args != nil {
			build["args"] = args
		}
	}
	if s := keyValueList(props["sysctls"], "sysctls", locs); s != nil {
		props["sysctls"] = s
	}
	if l, ok := props["labels"].([]any); ok {
		m := map[string]any{}
		for i, e := range l {
			k, v, _ := strings.Cut(operators.ToString(e), "=")
			m[k] = v
			if pos, ok := locs[models.JoinIndex("labels", i)]; ok {
				locs[models.JoinPath("labels", k)] = pos
			}
		}
		props["labels"] = m
	}
	if ports, ok := props["ports"].([]any); ok {
		for i, p := range ports {
			ports[i] = normalizePort(p)
		}
	}
	normalizeMounts(props, locs)
	for _, key := range []string{"security_opt"} {
		if l, ok := props[key].([]any); ok {
			for i, e := range l {
				l[i] = strings.Replace(operators.ToString(e), "=", ":", 1)
			}
		}
	}
	for _, key := range []string{"cap_add", "cap_drop"} {
		if l, ok := props[key].([]any); ok {
			for i, e := range l {
				l[i] = strings.TrimPrefix(strings.ToUpper(operators.ToString(e)), "CAP_")
			}
		}
	}
	for _, key := range []string{"command", "entrypoint"} {
		if l, ok := props[key].([]any); ok {
			props[key] = joinList(l)
		}
	}
	if hc, ok := props["healthcheck"].(map[string]any); ok {
		if l, ok := hc["test"].([]any); ok {
			hc["test"] = joinList(l)
		}
	}
	for _, key := range []string{"mem_limit", "mem_reservation", "memswap_limit", "shm_size"} {
		normalizeSize(props, key)
	}
	if v, ok := props["cpus"]; ok {
		props["cpus"] = toFloat(v)
	}
	if res := nested(props, "deploy", "resources"); res != nil {
		for _, section := range []string{"limits", "reservations"} {
			if m, ok := res[section].(map[string]any); ok {
				normalizeSize(m, "memory")
				if v, ok := m["cpus"]; ok {
					m["cpus"] = toFloat(v)
				}
			}
		}
	}
}

// keyValueList converts a mapping or list of KEY=VALUE entries into a list of
// "KEY=VALUE" strings in source order. It returns nil if v is neither.
func keyValueList(v any, prefix string, locs map[string]models.Position) []any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = operators.ToString(e)
		}
		return out
	case map[string]any:
		keys := sortedByLine(t, prefix, locs)
		out := make([]any, 0, len(keys))
		for i, k := range keys {
			if pos, ok := locs[models.JoinPath(prefix, k)]; ok {
				locs[models.JoinIndex(prefix, i)] = pos
			}
			if t[k] == nil {
				out = append(out, k)
			} else {
				out = append(out, k+"="+operators.ToString(t[k]))
			}
		}
		return out
	}
	return nil
}

// normalizePort converts short or long port syntax into
// "HOST_IP:PUBLISHED:TARGET/PROTO".
func normalizePort(p any) any {
	if m, ok := p.(map[string]any); ok {
		host := operators.ToString(m["host_ip"])
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		proto := operators.ToString(m["protocol"])
		if proto == "" {
			proto = "tcp"
		}
		return fmt.Sprintf("%s:%s:%s/%s", host, operators.ToString(m["published"]), operators.ToString(m["target"]), proto)
	}
	s := operators.ToString(p)
	proto := "tcp"
	if before, after, ok := cutLast(s, "/"); ok {
		s, proto = before, after
	}
	rest, target, ok := cutLast(s, ":")
	if !ok {
		return "::" + s + "/" + proto
	}
	host, published := "", rest
	if h, pub, ok := cutLast(rest, ":"); ok {
		host, published = h, pub
	}
	return fmt.Sprintf("%s:%s:%s/%s", host, published, target, proto)
}

// normalizeMounts converts volumes to "TYPE:SOURCE:TARGET:OPTIONS" and tmpfs
// to "TARGET:OPTIONS", moving tmpfs-type volumes into tmpfs.
func normalizeMounts(props map[string]any, locs map[string]models.Position) {
	var tmpfs []any
	switch t := props["tmpfs"].(type) {
	case string:
		tmpfs = []any{t}
	case []any:
		for _, e := range t {
			tmpfs = append(tmpfs, operators.ToString(e))
		}
	}

	if vols, ok := props["volumes"].([]any); ok {
		var out []any
		for i, v := range vols {
			if m, ok := v.(map[string]any); ok && operators.ToString(m["type"]) == "tmpfs" {
				if pos, ok := locs[models.JoinIndex("volumes", i)]; ok {
					locs[models.JoinIndex("tmpfs", len(tmpfs))] = pos
				}
				tmpfs = append(tmpfs, longTmpfs(m))
				continue
			}
			if pos, ok := locs[models.JoinIndex("volumes", i)]; ok {
				locs[models.JoinIndex("volumes", len(out))] = pos
			}
			out = append(out, normalizeVolume(v))
		}
		if out == nil {
			delete(props, "volumes")
		} else {
			props["volumes"] = out
		}
	}
	if tmpfs != nil {
		props["tmpfs"] = tmpfs
	}
}

func normalizeVolume(v any) string {
	if m, ok := v.(map[string]any); ok {
		typ := operators.ToString(m["type"])
		if typ == "" {
			typ = "volume"
		}
		opts := []string{"rw"}
		if ro, _ := m["read_only"].(bool); ro {
			opts[0] = "ro"
		}
		if b, ok := m["bind"].(map[string]any); ok {
			if p := operators.ToString(b["propagation"]); p != "" {
				opts = append(opts, p)
			}
			if s := operators.ToString(b["selinux"]); s != "" {
				opts = append(opts, s)
			}
		}
		return fmt.Sprintf("%s:%s:%s:%s", typ, operators.ToString(m["source"]), operators.ToString(m["target"]), strings.Join(opts, ","))
	}
	parts := strings.Split(operators.ToString(v), ":")
	var src, dst, rawOpts string
	switch len(parts) {
	case 1:
		dst = parts[0]
	case 2:
		src, dst = parts[0], parts[1]
	default:
		src, dst, rawOpts = parts[0], parts[1], strings.Join(parts[2:], ":")
	}
	typ := "volume"
	if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") || strings.HasPrefix(src, "$") {
		typ = "bind"
	}
	mode := "rw"
	var rest []string
	for _, o := range strings.Split(rawOpts, ",") {
		switch o {
		case "":
		case "ro", "readonly":
			mode = "ro"
		case "rw":
		default:
			rest = append(rest, o)
		}
	}
	return fmt.Sprintf("%s:%s:%s:%s", typ, src, dst, strings.Join(append([]string{mode}, rest...), ","))
}

func longTmpfs(m map[string]any) string {
	var opts []string
	if t, ok := m["tmpfs"].(map[string]any); ok {
		if s, ok := t["size"]; ok {
			opts = append(opts, "size="+operators.ToString(s))
		}
		if md, ok := t["mode"]; ok {
			opts = append(opts, "mode="+operators.ToString(md))
		}
	}
	return operators.ToString(m["target"]) + ":" + strings.Join(opts, ",")
}

func joinList(l []any) string {
	parts := make([]string, len(l))
	for i, e := range l {
		parts[i] = operators.ToString(e)
	}
	return strings.Join(parts, " ")
}

func nested(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// normalizeSize converts a memory size ("512m", "1gb", 1073741824) to bytes.
// Values that cannot be parsed (e.g. "${MEM}") are left untouched.
func normalizeSize(m map[string]any, key string) {
	v, ok := m[key]
	if !ok {
		return
	}
	if b, ok := parseBytes(v); ok {
		m[key] = b
	}
}

func parseBytes(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return n, true
		}
		m := sizeRe.FindStringSubmatch(t)
		if m == nil {
			return 0, false
		}
		f, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		exp := strings.Index("kmgt", strings.ToLower(m[2])) + 1
		return int64(f * math.Pow(1024, float64(exp))), true
	}
	return 0, false
}

func toFloat(v any) any {
	if f, ok := operators.ToFloat(v); ok {
		return f
	}
	return v
}

func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
