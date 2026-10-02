// Package kubernetes parses Kubernetes manifests into a single "kubernetes"
// resource per file.
//
// Like the Dockerfile parser emits one resource per Dockerfile and reads the
// sibling .dockerignore, this emits one resource per manifest file and reads
// the sibling manifests in the same directory, so cross-object checks (PDB,
// HPA, NetworkPolicy, ServiceMonitor, quotas) work across files while findings
// are still reported once, against the file that declares the object.
//
// The property model (see model.go) is:
//
//	resources[*]     every object in this file
//	strings[*]       every scalar value
//	workloads[*]     Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/
//	                 ReplicationController/Job/CronJob, with pod, pod_metadata,
//	                 job, has_pdb, has_hpa, network_policy_selected,
//	                 monitor_selected, automount_token
//	containers[*]    every container flattened, with type (container | init |
//	                 sidecar | ephemeral), workload, workload_pod,
//	                 env_duplicate_names and sc (the EFFECTIVE securityContext:
//	                 pod-level merged with the container's, legacy seccomp /
//	                 AppArmor annotations converted)
//	services[*] (+ targets_pods), ingresses[*], secrets[*],
//	configmaps[*] (+ data_keys[*]), hpas[*], pdbs[*],
//	rbac_roles[*], rbac_bindings[*]
//	namespaces[*]    name, labels, declared, has_resource_quota,
//	                 has_limit_range, has_default_deny_ingress
package kubernetes

import (
	"bytes"
	"context"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/yamlutil"
)

const Target = "kubernetes"

var (
	apiVersionLine = regexp.MustCompile(`(?m)^apiVersion:\s*\S`)
	kindLine       = regexp.MustCompile(`(?m)^kind:\s*\S`)
)

// podSpecPaths maps workload kinds to where their pod spec lives.
var podSpecPaths = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
}

// Parser implements parser.Parser for Kubernetes manifests.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	if !f.IsYAML() {
		return false
	}
	head := f.Head()
	// Unrendered Helm templates are not valid YAML; the helm parser owns them.
	if bytes.Contains(head, []byte("{{")) {
		return false
	}
	return apiVersionLine.Match(head) && kindLine.Match(head)
}

func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	own, err := decodeObjects(src.Content, src.Path)
	if err != nil {
		return nil, err
	}
	all := append(append([]object{}, own...), siblingObjects(src.Path)...)
	return build(src, own, all), nil
}

// objectsFrom decodes one YAML document into objects, flattening *List kinds.
func objectsFrom(doc *yaml.Node) ([]object, error) {
	if doc.Kind != yaml.MappingNode {
		return nil, nil
	}
	dec := yamlutil.NewDecoder()
	props, err := dec.DecodeMap(doc, "")
	if err != nil {
		return nil, err
	}
	kind, _ := props["kind"].(string)
	if kind == "" {
		return nil, nil
	}

	// v1.List and friends: recurse into items.
	if strings.HasSuffix(kind, "List") {
		_, items := yamlutil.MappingValue(doc, "items")
		if items == nil || items.Kind != yaml.SequenceNode {
			return nil, nil
		}
		var out []object
		for _, item := range items.Content {
			objs, err := objectsFrom(item)
			if err != nil {
				return nil, err
			}
			out = append(out, objs...)
		}
		return out, nil
	}

	o := object{kind: kind, props: props, line: doc.Line}
	o.apiVersion, _ = props["apiVersion"].(string)
	if meta, ok := props["metadata"].(map[string]any); ok {
		o.name, _ = meta["name"].(string)
		o.namespace, _ = meta["namespace"].(string)
	}
	return []object{o}, nil
}
