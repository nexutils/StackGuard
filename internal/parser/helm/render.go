package helm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"go.yaml.in/yaml/v3"
)

// This file renders a chart the way `helm template` does, in-process, with Go
// text/template + sprig and Helm's own template functions. It is best-effort:
// charts that use features we do not implement (heavy subcharts, .Files, odd
// named templates) fail to render and are skipped with a diagnostic rather than
// producing wrong findings.

// chartDir holds a loaded chart.
type chartDir struct {
	dir       string
	chart     map[string]any // Chart.yaml
	values    map[string]any // values.yaml
	templates []tmplFile     // templates/*.yaml|*.tpl
}

type tmplFile struct {
	name string // path relative to templates/, e.g. "deployment.yaml"
	text string
}

// loadChart reads Chart.yaml, values.yaml and the templates/ directory.
func loadChart(chartYAML string) (*chartDir, error) {
	dir := filepath.Dir(chartYAML)
	c := &chartDir{dir: dir}

	data, err := os.ReadFile(chartYAML)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &c.chart); err != nil {
		return nil, fmt.Errorf("Chart.yaml: %w", err)
	}
	if vdata, err := os.ReadFile(filepath.Join(dir, "values.yaml")); err == nil {
		_ = yaml.Unmarshal(vdata, &c.values)
	}
	if c.values == nil {
		c.values = map[string]any{}
	}

	tdir := filepath.Join(dir, "templates")
	_ = filepath.WalkDir(tdir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" && ext != ".tpl" {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(tdir, p)
		c.templates = append(c.templates, tmplFile{name: filepath.ToSlash(rel), text: string(b)})
		return nil
	})
	sort.Slice(c.templates, func(i, j int) bool { return c.templates[i].name < c.templates[j].name })
	return c, nil
}

// render renders every non-helper template and returns a single multi-document
// manifest stream, each document prefixed with a "# Source:" comment like helm.
func (c *chartDir) render() (string, error) {
	chartName, _ := c.chart["name"].(string)
	if chartName == "" {
		chartName = filepath.Base(c.dir)
	}
	root := map[string]any{
		"Values": c.values,
		"Chart":  chartContext(c.chart),
		"Release": map[string]any{
			"Name": chartName, "Namespace": "default", "Service": "Helm",
			"IsUpgrade": false, "IsInstall": true, "Revision": 1,
		},
		"Capabilities": map[string]any{
			"KubeVersion": map[string]any{"Version": "v1.30.0", "Major": "1", "Minor": "30"},
			"APIVersions": []any{},
			"HelmVersion": map[string]any{"Version": "v3.15.0"},
		},
		"Template": map[string]any{"Name": "", "BasePath": chartName + "/templates"},
	}

	// One template set so `define`/`include` across files resolve, like Helm.
	tmpl := template.New(chartName).Funcs(helmFuncs())
	for _, t := range c.templates {
		name := chartName + "/templates/" + t.name
		if _, err := tmpl.New(name).Parse(t.text); err != nil {
			return "", fmt.Errorf("%s: %w", t.name, err)
		}
	}
	// include needs to resolve against this set.
	tmpl.Funcs(template.FuncMap{
		"include": func(name string, data any) (string, error) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
				return "", err
			}
			return buf.String(), nil
		},
		"tpl": func(text string, data any) (string, error) {
			t, err := template.New("tpl").Funcs(helmFuncs()).Parse(text)
			if err != nil {
				return "", err
			}
			var buf bytes.Buffer
			if err := t.Execute(&buf, data); err != nil {
				return "", err
			}
			return buf.String(), nil
		},
	})

	var out strings.Builder
	for _, t := range c.templates {
		base := filepath.Base(t.name)
		// Helpers and partials (_*.tpl / _*.yaml) are included, not rendered.
		if strings.HasPrefix(base, "_") || strings.HasSuffix(base, ".tpl") {
			continue
		}
		name := chartName + "/templates/" + t.name
		rootCopy := map[string]any{}
		for k, v := range root {
			rootCopy[k] = v
		}
		rootCopy["Template"] = map[string]any{"Name": name, "BasePath": chartName + "/templates"}

		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, rootCopy); err != nil {
			return "", fmt.Errorf("%s: %w", t.name, err)
		}
		doc := strings.TrimSpace(buf.String())
		if doc == "" {
			continue
		}
		out.WriteString("---\n# Source: " + chartName + "/templates/" + t.name + "\n")
		out.WriteString(doc)
		out.WriteString("\n")
	}
	return out.String(), nil
}

// chartContext maps the raw Chart.yaml keys to the capitalized field names Helm
// exposes under .Chart (e.g. appVersion -> AppVersion, apiVersion -> APIVersion).
func chartContext(raw map[string]any) map[string]any {
	rename := map[string]string{
		"apiVersion": "APIVersion", "kubeVersion": "KubeVersion", "appVersion": "AppVersion",
		"name": "Name", "version": "Version", "description": "Description", "type": "Type",
		"home": "Home", "icon": "Icon", "condition": "Condition", "deprecated": "Deprecated",
		"sources": "Sources", "keywords": "Keywords", "maintainers": "Maintainers",
		"dependencies": "Dependencies", "annotations": "Annotations", "tags": "Tags",
	}
	out := map[string]any{"IsRoot": true}
	for k, v := range raw {
		if cap, ok := rename[k]; ok {
			out[cap] = v
		} else {
			out[k] = v
		}
	}
	return out
}

// helmFuncs is sprig plus the Helm-specific template functions charts rely on.
func helmFuncs() template.FuncMap {
	f := sprig.TxtFuncMap()
	f["toYaml"] = toYAML
	f["toJson"] = toJSON
	f["fromYaml"] = fromYAML
	f["required"] = func(msg string, v any) (any, error) {
		if v == nil {
			return nil, fmt.Errorf("%s", msg)
		}
		if s, ok := v.(string); ok && s == "" {
			return nil, fmt.Errorf("%s", msg)
		}
		return v, nil
	}
	// lookup against a live cluster returns empty under `helm template`.
	f["lookup"] = func(_ ...any) map[string]any { return map[string]any{} }
	// include / tpl are installed after parsing (they need the template set).
	f["include"] = func(string, any) (string, error) { return "", nil }
	f["tpl"] = func(s string, _ any) (string, error) { return s, nil }
	return f
}

func toYAML(v any) string {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimRight(buf.String(), "\n")
}

func fromYAML(s string) map[string]any {
	m := map[string]any{}
	_ = yaml.Unmarshal([]byte(s), &m)
	return m
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
