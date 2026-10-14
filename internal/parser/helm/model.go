package helm

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser/kubernetes"
)

// buildChart assembles the single "helm" resource for a chart, given its
// Chart.yaml path. The chart is rendered in-process (render.go) and the output
// fed through the Kubernetes model so rendered.* matches the kubernetes target
// exactly. Rendering is best-effort: if it fails, rendered.* is omitted and the
// values/chart-based rules still run.
func buildChart(chartYAML string) ([]models.Resource, error) {
	c, err := loadChart(chartYAML)
	if err != nil {
		return nil, err
	}
	props := map[string]any{}
	if len(c.chart) > 0 {
		props["chart"] = c.chart
	}
	if len(c.values) > 0 {
		props["values"] = c.values
	}

	// values_entries from values.yaml and ci/*-values.yaml.
	var entries []any
	collectValueEntries(c.values, "", "values.yaml", &entries)
	for _, ci := range ciValueFiles(c.dir) {
		if data, err := os.ReadFile(ci); err == nil {
			m := fromYAML(string(data))
			collectValueEntries(m, "", filepath.Base(ci), &entries)
		}
	}
	putList(props, "values_entries", entries)

	// templates[*] {file, text}
	var templates []any
	for _, t := range c.templates {
		templates = append(templates, map[string]any{"file": t.name, "text": t.text})
	}
	putList(props, "templates", templates)

	// rendered.* via the kubernetes model.
	if out, rerr := c.render(); rerr == nil && strings.TrimSpace(out) != "" {
		if rendered, merr := kubernetes.Model([]byte(out)); merr == nil && rendered != nil {
			props["rendered"] = rendered
		}
	}

	if ctx := buildContext(c.dir); len(ctx) > 0 {
		props["context"] = ctx
	}

	name := filepath.Base(c.dir)
	if n, _ := c.chart["name"].(string); n != "" {
		name = n
	}
	return []models.Resource{{
		Target: Target, Type: Target, Name: name,
		File: chartYAML, Line: 1,
		Properties: props, Locations: map[string]models.Position{},
	}}, nil
}

// collectValueEntries flattens values into {path, key, value, file} entries for
// every scalar, path dotted (e.g. postgresql.auth.password).
func collectValueEntries(v any, prefix, file string, out *[]any) {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(t) {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			collectValueEntries(t[k], p, file, out)
		}
	case []any:
		for i, e := range t {
			collectValueEntries(e, prefix+"."+strconv.Itoa(i), file, out)
		}
	default:
		if prefix == "" {
			return
		}
		key := prefix
		if i := strings.LastIndex(prefix, "."); i >= 0 {
			key = prefix[i+1:]
		}
		*out = append(*out, map[string]any{
			"path": prefix, "key": key, "value": scalarString(v), "file": file,
		})
	}
}

func ciValueFiles(dir string) []string {
	ci := filepath.Join(dir, "ci")
	entries, err := os.ReadDir(ci)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, "-values.yaml") || strings.HasSuffix(n, "-values.yml") {
			out = append(out, filepath.Join(ci, n))
		}
	}
	sort.Strings(out)
	return out
}

func buildContext(dir string) map[string]any {
	var files []any
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return nil
		}
		files = append(files, filepath.ToSlash(rel))
		if len(files) >= 500 {
			return filepath.SkipAll
		}
		return nil
	})
	if len(files) == 0 {
		return nil
	}
	return map[string]any{"files": files}
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func putList(m map[string]any, key string, v []any) {
	if len(v) > 0 {
		m[key] = v
	}
}
