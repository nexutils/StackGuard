package kubernetes

import (
	"context"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

func parse(t *testing.T, manifest string) map[string]any {
	t.Helper()
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte(manifest)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	return res[0].Properties
}

const sample = `
apiVersion: v1
kind: Namespace
metadata:
  name: app
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
  labels:
    app.kubernetes.io/name: web
spec:
  replicas: 2
  template:
    metadata:
      labels:
        app: web
      annotations:
        seccomp.security.alpha.kubernetes.io/pod: runtime/default
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      initContainers:
        - name: migrate
          image: migrate:1.0
        - name: proxy
          image: proxy:1.0
          restartPolicy: Always
      containers:
        - name: web
          image: web:1.2.3
          securityContext:
            runAsUser: 0
            privileged: true
          env:
            - name: DUP
              value: a
            - name: DUP
              value: b
            - name: OK
              value: c
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: app
spec:
  selector:
    app: web
  ports:
    - port: 80
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: app
spec:
  scaleTargetRef:
    kind: Deployment
    name: web
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web
  namespace: app
spec:
  selector:
    matchLabels:
      app: web
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: app
spec:
  podSelector: {}
  policyTypes:
    - Ingress
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: q
  namespace: app
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
  namespace: app
data:
  API_KEY: abc
  LOG_LEVEL: info
`

func TestBuildModel(t *testing.T) {
	props := parse(t, sample)

	// containers: 1 container + 2 init (one is a sidecar)
	containers := props["containers"].([]any)
	if len(containers) != 3 {
		t.Fatalf("containers = %d, want 3", len(containers))
	}
	byName := map[string]map[string]any{}
	for _, c := range containers {
		m := c.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if byName["web"]["type"] != "container" {
		t.Errorf("web type = %v", byName["web"]["type"])
	}
	if byName["migrate"]["type"] != "init" {
		t.Errorf("migrate type = %v", byName["migrate"]["type"])
	}
	if byName["proxy"]["type"] != "sidecar" {
		t.Errorf("proxy type = %v (restartPolicy Always init = sidecar)", byName["proxy"]["type"])
	}

	// effective securityContext: container overrides pod, annotation converted
	sc := byName["web"]["sc"].(map[string]any)
	if sc["runAsUser"] != 0 {
		t.Errorf("sc.runAsUser = %v, container should win over pod", sc["runAsUser"])
	}
	if sc["runAsNonRoot"] != true {
		t.Errorf("sc.runAsNonRoot = %v, should inherit from pod", sc["runAsNonRoot"])
	}
	if sc["privileged"] != true {
		t.Errorf("sc.privileged = %v", sc["privileged"])
	}
	if p := sc["seccompProfile"].(map[string]any); p["type"] != "RuntimeDefault" {
		t.Errorf("seccompProfile = %#v (legacy annotation should convert)", p)
	}
	// the init container has no annotation of its own but inherits pod-level sc
	if isc := byName["migrate"]["sc"].(map[string]any); isc["runAsUser"] != 1000 {
		t.Errorf("init sc.runAsUser = %v", isc["runAsUser"])
	}

	// duplicate env names
	if dup := byName["web"]["env_duplicate_names"].([]any); len(dup) != 1 || dup[0] != "DUP" {
		t.Errorf("env_duplicate_names = %#v", byName["web"]["env_duplicate_names"])
	}

	// workload cross-object facts
	w := props["workloads"].([]any)[0].(map[string]any)
	for key, want := range map[string]bool{
		"has_hpa": true, "has_pdb": true, "network_policy_selected": true, "automount_token": true,
	} {
		if w[key] != want {
			t.Errorf("workload.%s = %v, want %v", key, w[key], want)
		}
	}
	if w["monitor_selected"] != false {
		t.Errorf("monitor_selected = %v, want false (no ServiceMonitor)", w["monitor_selected"])
	}
	if w["pod"] == nil || w["pod_metadata"] == nil {
		t.Error("pod / pod_metadata missing")
	}

	// service targets the pods
	svc := props["services"].([]any)[0].(map[string]any)
	if svc["targets_pods"] != true {
		t.Errorf("targets_pods = %v", svc["targets_pods"])
	}

	// namespace facts
	ns := props["namespaces"].([]any)[0].(map[string]any)
	if ns["name"] != "app" || ns["declared"] != true || ns["has_resource_quota"] != true {
		t.Errorf("namespace = %#v", ns)
	}
	if ns["has_limit_range"] != false || ns["has_default_deny_ingress"] != true {
		t.Errorf("namespace policy flags = %#v", ns)
	}

	// configmap keys
	cm := props["configmaps"].([]any)[0].(map[string]any)
	keys := cm["data_keys"].([]any)
	if len(keys) != 2 || keys[0] != "API_KEY" {
		t.Errorf("data_keys = %#v", keys)
	}
}

func TestNoObjectsYieldsNothing(t *testing.T) {
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte("foo: bar\n")})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Errorf("expected no resource for a non-manifest file, got %d", len(res))
	}
}
