package nginx

import (
	"context"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

func parse(t *testing.T, conf string) map[string]any {
	t.Helper()
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte(conf)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	return res[0].Properties
}

func TestBuildModel(t *testing.T) {
	conf := `
worker_processes auto;
# @owner: team-edge
http {
    server_tokens off;
    add_header X-Content-Type-Options nosniff always;
    upstream backend {
        least_conn;
        server 10.0.0.1:8080 max_fails=2;
        server 10.0.0.2:8080;
    }
    server {
        listen 443 ssl;
        server_name example.com;
        ssl_protocols TLSv1.2 TLSv1.3;
        location /api {
            proxy_pass http://backend;
            proxy_read_timeout 90s;
        }
        location /static {
            add_header Cache-Control "max-age=3600";
        }
    }
    server {
        listen 80;
        return 301 https://example.com$request_uri;
    }
}
`
	props := parse(t, conf)

	// main + meta
	if main := props["main"].(map[string]any); main["worker_processes"] == nil {
		t.Error("main.worker_processes missing")
	}
	if meta := props["meta"].(map[string]any); meta["owner"] != "team-edge" {
		t.Errorf("meta.owner = %v", meta["owner"])
	}

	servers := props["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	s0 := servers[0].(map[string]any)
	if s0["tls"] != true {
		t.Error("server 0 should be tls")
	}
	if s0["redirect_only"] != false {
		t.Error("server 0 should not be redirect_only")
	}
	s1 := servers[1].(map[string]any)
	if s1["redirect_only"] != true {
		t.Error("server 1 (return 301) should be redirect_only")
	}

	// effective inheritance: server inherits server_tokens from http.
	eff0 := s0["effective"].(map[string]any)
	if eff0["server_tokens"] != "off" {
		t.Errorf("effective.server_tokens = %v (should inherit http)", eff0["server_tokens"])
	}
	if eff0["ssl_protocols"] != "TLSv1.2 TLSv1.3" {
		t.Errorf("effective.ssl_protocols = %v", eff0["ssl_protocols"])
	}

	// leaves: /api, /static (server 0) + server 1 (no location).
	leaves := props["leaves"].([]any)
	if len(leaves) != 3 {
		t.Fatalf("expected 3 leaves, got %d", len(leaves))
	}
	// Find the /api leaf.
	var api map[string]any
	for _, lf := range leaves {
		l := lf.(map[string]any)
		if l["path"] == "/api" {
			api = l
		}
	}
	if api == nil {
		t.Fatal("no /api leaf")
	}
	if api["proxied"] != true || api["proxy_target_is_upstream"] != true {
		t.Errorf("/api proxied=%v upstream=%v", api["proxied"], api["proxy_target_is_upstream"])
	}
	apiEff := api["effective"].(map[string]any)
	if apiEff["proxy_read_timeout"] != "90s" {
		t.Errorf("/api effective.proxy_read_timeout = %v", apiEff["proxy_read_timeout"])
	}
	// add_header non-inheritance: /api sets none, so it inherits http's header.
	if hdrs := apiEff["headers"].([]any); len(hdrs) != 1 || hdrs[0] != "X-Content-Type-Options nosniff always" {
		t.Errorf("/api headers = %v (should inherit http add_header)", apiEff["headers"])
	}
	// /static sets its own add_header, so it does NOT inherit the http one.
	for _, lf := range leaves {
		l := lf.(map[string]any)
		if l["path"] != "/static" {
			continue
		}
		hdrs := l["effective"].(map[string]any)["headers"].([]any)
		if len(hdrs) != 1 || hdrs[0] != "Cache-Control max-age=3600" {
			t.Errorf("/static headers = %v (should NOT inherit, only its own)", hdrs)
		}
	}

	// upstream with load-balancing + health_check false.
	ups := props["upstreams"].([]any)
	if len(ups) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(ups))
	}
	u := ups[0].(map[string]any)
	if u["name"] != "backend" || u["health_check"] != false {
		t.Errorf("upstream = %#v", u)
	}
	if srv := u["server"].([]any); len(srv) != 2 {
		t.Errorf("upstream.server = %v", u["server"])
	}
	if u["least_conn"] == nil {
		t.Error("upstream.least_conn missing")
	}
}
