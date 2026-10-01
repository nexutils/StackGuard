package compose

import (
	"context"
	"reflect"
	"testing"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

func TestNormalizePort(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{"9000", "::9000/tcp"},
		{80, "::80/tcp"},
		{"5432:5432", ":5432:5432/tcp"},
		{"127.0.0.1:8080:80", "127.0.0.1:8080:80/tcp"},
		{"127.0.0.1::5432", "127.0.0.1::5432/tcp"},
		{"[::1]:53:53/udp", "[::1]:53:53/udp"},
		{"8000-8100:8000-8100", ":8000-8100:8000-8100/tcp"},
		{map[string]any{"target": 80, "published": "8080"}, ":8080:80/tcp"},
		{map[string]any{"target": 53, "host_ip": "::1", "protocol": "udp"}, "[::1]::53/udp"},
	}
	for _, tt := range tests {
		if got := normalizePort(tt.in); got != tt.want {
			t.Errorf("normalizePort(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeVolume(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{"./src:/app", "bind:./src:/app:rw"},
		{"./src:/app:ro,rshared", "bind:./src:/app:ro,rshared"},
		{"./src:/app:z", "bind:./src:/app:rw,z"},
		{"pgdata:/var/lib/pg", "volume:pgdata:/var/lib/pg:rw"},
		{"/data", "volume::/data:rw"},
		{"~/.ssh:/root/.ssh:ro", "bind:~/.ssh:/root/.ssh:ro"},
		{map[string]any{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock", "read_only": true}, "bind:/var/run/docker.sock:/var/run/docker.sock:ro"},
		{map[string]any{"type": "bind", "source": "/mnt", "target": "/mnt", "bind": map[string]any{"propagation": "rshared"}}, "bind:/mnt:/mnt:rw,rshared"},
		{map[string]any{"source": "data", "target": "/data"}, "volume:data:/data:rw"},
	}
	for _, tt := range tests {
		if got := normalizeVolume(tt.in); got != tt.want {
			t.Errorf("normalizeVolume(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseBytes(t *testing.T) {
	tests := map[any]int64{
		"512m": 512 << 20, "1G": 1 << 30, "1gb": 1 << 30, "256MiB": 256 << 20,
		"100k": 100 << 10, "2048": 2048, 1024: 1024, "-1": -1, "1.5g": 3 << 29,
	}
	for in, want := range tests {
		if got, ok := parseBytes(in); !ok || got != want {
			t.Errorf("parseBytes(%v) = %d, %v; want %d", in, got, ok, want)
		}
	}
	if _, ok := parseBytes("${MEM_LIMIT}"); ok {
		t.Error("interpolated values must be left alone")
	}
}

const sample = `
name: shop
services:
  api:
    image: ghcr.io/acme/api:1.2
    environment:
      B: "2"
      A: 1
      EMPTY:
    cap_add: [cap_net_admin]
    security_opt: ["no-new-privileges=true"]
    command: ["serve", "--port", "8080"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
    mem_limit: 512m
    tmpfs: /run
    volumes:
      - data:/data
      - type: tmpfs
        target: /tmp
        tmpfs: {size: 1000}
    labels: ["team=payments"]
  worker:
    volumes: ["data:/data:ro"]
volumes:
  data: {}
`

func TestParse(t *testing.T) {
	res, err := New().Parse(context.Background(), parser.Source{Path: "shop/compose.yaml", Content: []byte(sample)})
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string][]models.Resource{}
	for _, r := range res {
		byType[r.Type] = append(byType[r.Type], r)
	}
	if len(byType["service"]) != 2 || len(byType["volume"]) != 1 || len(byType["project"]) != 1 {
		t.Fatalf("unexpected resources: %v", byType)
	}
	api := byType["service"][0].Properties
	checks := map[string]any{
		"environment":  []any{"B=2", "A=1", "EMPTY"},
		"cap_add":      []any{"NET_ADMIN"},
		"security_opt": []any{"no-new-privileges:true"},
		"command":      "serve --port 8080",
		"mem_limit":    int64(512 << 20),
		"tmpfs":        []any{"/run", "/tmp:size=1000"},
		"volumes":      []any{"volume:data:/data:rw"},
		"labels":       map[string]any{"team": "payments"},
	}
	for k, want := range checks {
		if !reflect.DeepEqual(api[k], want) {
			t.Errorf("%s = %#v, want %#v", k, api[k], want)
		}
	}
	if api["healthcheck"].(map[string]any)["test"] != "CMD curl -f http://localhost" {
		t.Errorf("healthcheck.test = %v", api["healthcheck"])
	}
	if sib, ok := api["_services"].(models.Lookup); !ok || sib["worker"] == nil {
		t.Errorf("_services missing sibling: %v", api["_services"])
	}
	// The environment list keeps the line of each key.
	if pos := byType["service"][0].PositionFor("environment.1"); pos.Line != 8 {
		t.Errorf("environment.1 line = %d, want 8", pos.Line)
	}

	project := byType["project"][0]
	if project.Name != "shop" {
		t.Errorf("project name = %q", project.Name)
	}
	idx := project.Properties["_index"].(map[string]any)
	if !reflect.DeepEqual(idx["volume_mounts"], map[string]any{"data": []any{"api", "worker"}}) ||
		!reflect.DeepEqual(idx["volume_writers"], map[string]any{"data": []any{"api"}}) {
		t.Errorf("index = %v", idx)
	}
	if _, leaked := project.Properties["services"].(map[string]any)["api"].(map[string]any)["_services"]; leaked {
		t.Error("project services must not carry the sibling lookup")
	}
}
