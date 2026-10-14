package helm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

// writeChart lays out a minimal chart in a temp dir and returns its Chart.yaml.
func writeChart(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "Chart.yaml")
}

func parse(t *testing.T, chartYAML string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(chartYAML)
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Path: chartYAML, Content: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	return res[0].Properties
}

func TestRenderAndModel(t *testing.T) {
	chartYAML := writeChart(t, map[string]string{
		"Chart.yaml": `apiVersion: v2
name: web
version: 1.0.0
appVersion: "2.3.4"
maintainers:
  - name: platform
`,
		"values.yaml": `replicaCount: 3
image:
  repository: ghcr.io/example-org/web
  tag: ""
resources:
  requests:
    cpu: 100m
postgresql:
  auth:
    password: hunter2secret
`,
		"templates/_helpers.tpl": `{{- define "web.fullname" -}}{{ .Release.Name }}-web{{- end -}}`,
		"templates/deployment.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "web.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
  template:
    spec:
      containers:
        - name: web
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          resources: {{- toYaml .Values.resources | nindent 12 }}
`,
	})
	props := parse(t, chartYAML)

	// chart + maintainers
	chart := props["chart"].(map[string]any)
	if chart["name"] != "web" {
		t.Errorf("chart.name = %v", chart["name"])
	}

	// values_entries carries dotted paths, including the nested password
	var foundPw bool
	for _, e := range props["values_entries"].([]any) {
		m := e.(map[string]any)
		if m["path"] == "postgresql.auth.password" {
			foundPw = true
			if m["key"] != "password" || m["value"] != "hunter2secret" {
				t.Errorf("password entry = %#v", m)
			}
		}
	}
	if !foundPw {
		t.Error("values_entries missing postgresql.auth.password")
	}

	// rendered.* must be populated via the kubernetes model, with the include +
	// toYaml + default helpers resolved.
	rendered, ok := props["rendered"].(map[string]any)
	if !ok {
		t.Fatal("rendered is missing (chart did not render)")
	}
	containers, ok := rendered["containers"].([]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("rendered.containers = %#v", rendered["containers"])
	}
	c := containers[0].(map[string]any)
	if c["image"] != "ghcr.io/example-org/web:2.3.4" {
		t.Errorf("image = %v (default .Chart.AppVersion should apply)", c["image"])
	}
	// toYaml rendered the resources map
	if res := c["resources"].(map[string]any); res["requests"] == nil {
		t.Errorf("resources not rendered: %#v", c["resources"])
	}
	// derived sc field exists (from the kubernetes model)
	if _, ok := c["sc"].(map[string]any); !ok {
		t.Errorf("rendered container has no effective sc: %#v", c)
	}
	w := rendered["workloads"].([]any)[0].(map[string]any)
	if w["kind"] != "Deployment" || w["has_pdb"] != false {
		t.Errorf("rendered workload = %#v", w)
	}
}
