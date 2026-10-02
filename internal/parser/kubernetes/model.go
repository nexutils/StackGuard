package kubernetes

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/yamlutil"
)

// This file turns the objects of one manifest file into the single "kubernetes"
// resource rules query (see the package doc). Cross-object facts (has_pdb,
// has_hpa, network_policy_selected, targets_pods, namespace quotas) are
// computed against the objects of sibling manifests in the same directory, the
// way the Dockerfile parser reads its sibling .dockerignore.

// object is one decoded Kubernetes object.
type object struct {
	kind, apiVersion string
	name, namespace  string
	props            map[string]any
	line             int
}

func (o object) labels() map[string]any      { return mapAt(o.props, "metadata", "labels") }
func (o object) annotations() map[string]any { return mapAt(o.props, "metadata", "annotations") }

// podSpec returns the object's pod spec, if it is a workload kind.
func (o object) podSpec() map[string]any {
	path, ok := podSpecPaths[o.kind]
	if !ok {
		return nil
	}
	cur := o.props
	for _, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// podMetadata returns the pod template metadata (the Pod's own for kind Pod).
func (o object) podMetadata() map[string]any {
	switch o.kind {
	case "Pod":
		return mapAt(o.props, "metadata")
	case "CronJob":
		return mapAt(o.props, "spec", "jobTemplate", "spec", "template", "metadata")
	default:
		return mapAt(o.props, "spec", "template", "metadata")
	}
}

func (o object) podLabels() map[string]any {
	if md := o.podMetadata(); md != nil {
		if l, ok := md["labels"].(map[string]any); ok {
			return l
		}
	}
	return nil
}

// jobSpec returns the Job spec for Job / CronJob.
func (o object) jobSpec() map[string]any {
	switch o.kind {
	case "Job":
		return mapAt(o.props, "spec")
	case "CronJob":
		return mapAt(o.props, "spec", "jobTemplate", "spec")
	}
	return nil
}

var workloadKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"ReplicaSet": true, "ReplicationController": true, "Job": true, "CronJob": true,
}

// build assembles the resource for one manifest file. own are this file's
// objects; all adds the sibling manifests for cross-object lookups.
func build(src parser.Source, own, all []object) []models.Resource {
	if len(own) == 0 {
		return nil
	}
	props := map[string]any{}
	locs := map[string]models.Position{}
	idx := newIndex(all)

	var resources, strs []any
	for i, o := range own {
		resources = append(resources, o.props)
		locs["resources."+strconv.Itoa(i)] = models.Position{Line: o.line}
		collectStrings(o.props, &strs)
	}
	props["resources"] = resources
	putList(props, "strings", strs)

	var workloads, containers []any
	var byKind = map[string][]any{}
	for _, o := range own {
		switch {
		case workloadKinds[o.kind]:
			w := buildWorkload(o, idx)
			locs["workloads."+strconv.Itoa(len(workloads))] = models.Position{Line: o.line}
			workloads = append(workloads, w)
			for _, c := range buildContainers(o, idx) {
				locs["containers."+strconv.Itoa(len(containers))] = models.Position{Line: o.line}
				containers = append(containers, c)
			}
		case o.kind == "Service":
			s := cloneMap(o.props)
			s["targets_pods"] = idx.serviceTargetsPods(o)
			byKind["services"] = append(byKind["services"], s)
		case o.kind == "Ingress":
			byKind["ingresses"] = append(byKind["ingresses"], o.props)
		case o.kind == "Secret":
			byKind["secrets"] = append(byKind["secrets"], o.props)
		case o.kind == "ConfigMap":
			c := cloneMap(o.props)
			c["data_keys"] = configMapKeys(o.props)
			byKind["configmaps"] = append(byKind["configmaps"], c)
		case o.kind == "HorizontalPodAutoscaler":
			byKind["hpas"] = append(byKind["hpas"], o.props)
		case o.kind == "PodDisruptionBudget":
			byKind["pdbs"] = append(byKind["pdbs"], o.props)
		case o.kind == "Role" || o.kind == "ClusterRole":
			byKind["rbac_roles"] = append(byKind["rbac_roles"], o.props)
		case o.kind == "RoleBinding" || o.kind == "ClusterRoleBinding":
			byKind["rbac_bindings"] = append(byKind["rbac_bindings"], o.props)
		}
	}
	putList(props, "workloads", workloads)
	putList(props, "containers", containers)
	for k, v := range byKind {
		putList(props, k, v)
	}
	putList(props, "namespaces", buildNamespaces(own, idx))

	return []models.Resource{{
		Target: Target, Type: Target, Name: nameFor(src.Path),
		File: src.Path, Line: own[0].line,
		Properties: props, Locations: locs,
	}}
}

func buildWorkload(o object, idx *index) map[string]any {
	w := map[string]any{
		"kind":       o.kind,
		"apiVersion": o.apiVersion,
	}
	if md := mapAt(o.props, "metadata"); md != nil {
		w["metadata"] = md
	}
	if spec := mapAt(o.props, "spec"); spec != nil {
		w["spec"] = spec
	}
	if pod := o.podSpec(); pod != nil {
		w["pod"] = pod
	}
	if pm := o.podMetadata(); pm != nil {
		w["pod_metadata"] = pm
	}
	if js := o.jobSpec(); js != nil {
		w["job"] = js
	}
	w["has_pdb"] = idx.hasPDB(o)
	w["has_hpa"] = idx.hasHPA(o)
	w["network_policy_selected"] = idx.networkPolicySelects(o)
	w["monitor_selected"] = idx.monitorSelects(o)
	w["automount_token"] = idx.automountToken(o)
	return w
}

// buildContainers flattens every container of a workload with its effective
// securityContext.
func buildContainers(o object, idx *index) []any {
	pod := o.podSpec()
	if pod == nil {
		return nil
	}
	podSC := mapAt(pod, "securityContext")
	annotations := map[string]any{}
	if pm := o.podMetadata(); pm != nil {
		if a, ok := pm["annotations"].(map[string]any); ok {
			annotations = a
		}
	}
	wl := map[string]any{"kind": o.kind, "name": o.name}
	if o.namespace != "" {
		wl["namespace"] = o.namespace
	}

	var out []any
	add := func(list any, kind string) {
		items, _ := list.([]any)
		for _, it := range items {
			raw, ok := it.(map[string]any)
			if !ok {
				continue
			}
			c := cloneMap(raw)
			typ := kind
			if kind == "init" {
				if rp, _ := raw["restartPolicy"].(string); rp == "Always" {
					typ = "sidecar"
				}
			}
			c["type"] = typ
			c["workload"] = wl
			c["workload_pod"] = pod
			name, _ := raw["name"].(string)
			c["sc"] = effectiveSC(podSC, mapAt(raw, "securityContext"), annotations, name)
			if dups := duplicateEnvNames(raw); len(dups) > 0 {
				c["env_duplicate_names"] = dups
			}
			out = append(out, c)
		}
	}
	add(pod["containers"], "container")
	add(pod["initContainers"], "init")
	add(pod["ephemeralContainers"], "ephemeral")
	return out
}

// effectiveSC merges the pod securityContext (and the legacy seccomp/AppArmor
// annotations) with the container's; the container wins.
func effectiveSC(podSC, ctrSC, annotations map[string]any, ctrName string) map[string]any {
	sc := map[string]any{}
	// Legacy annotations first: an explicit field overrides them.
	if v, ok := annotations["seccomp.security.alpha.kubernetes.io/pod"].(string); ok {
		sc["seccompProfile"] = profileFromAnnotation(v)
	}
	if v, ok := annotations["container.apparmor.security.beta.kubernetes.io/"+ctrName].(string); ok {
		sc["appArmorProfile"] = profileFromAnnotation(v)
	}
	for _, k := range []string{"runAsUser", "runAsGroup", "runAsNonRoot", "seccompProfile",
		"appArmorProfile", "seLinuxOptions", "windowsOptions"} {
		if v, ok := podSC[k]; ok {
			sc[k] = v
		}
	}
	for k, v := range ctrSC {
		sc[k] = v
	}
	return sc
}

// profileFromAnnotation converts a legacy seccomp/AppArmor annotation value to
// the modern {type, localhostProfile} shape.
func profileFromAnnotation(v string) map[string]any {
	switch {
	case v == "runtime/default" || v == "docker/default":
		return map[string]any{"type": "RuntimeDefault"}
	case v == "unconfined":
		return map[string]any{"type": "Unconfined"}
	case strings.HasPrefix(v, "localhost/"):
		return map[string]any{"type": "Localhost", "localhostProfile": strings.TrimPrefix(v, "localhost/")}
	}
	return map[string]any{"type": v}
}

func duplicateEnvNames(container map[string]any) []any {
	env, _ := container["env"].([]any)
	seen := map[string]int{}
	for _, e := range env {
		if m, ok := e.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				seen[n]++
			}
		}
	}
	var out []any
	for n, c := range seen {
		if c > 1 {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].(string) < out[j].(string) })
	return out
}

func configMapKeys(props map[string]any) []any {
	var out []any
	for _, field := range []string{"data", "binaryData"} {
		for k := range mapAt(props, field) {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].(string) < out[j].(string) })
	return out
}

// buildNamespaces lists every namespace declared in this file or referenced by
// its objects, with the policy facts computed across all manifests.
func buildNamespaces(own []object, idx *index) []any {
	names := map[string]bool{}
	for _, o := range own {
		if o.kind == "Namespace" {
			names[o.name] = true
		}
		if o.namespace != "" {
			names[o.namespace] = true
		}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	var out []any
	for _, n := range sorted {
		ns := map[string]any{"name": n, "declared": idx.namespaceDeclared(n)}
		if l := idx.namespaceLabels(n); l != nil {
			ns["labels"] = l
		}
		ns["has_resource_quota"] = idx.nsHasKind(n, "ResourceQuota")
		ns["has_limit_range"] = idx.nsHasKind(n, "LimitRange")
		ns["has_default_deny_ingress"] = idx.hasDefaultDenyIngress(n)
		out = append(out, ns)
	}
	return out
}

// ---- cross-object index ----

type index struct{ all []object }

func newIndex(all []object) *index { return &index{all: all} }

func (ix *index) of(kinds ...string) []object {
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	var out []object
	for _, o := range ix.all {
		if want[o.kind] {
			out = append(out, o)
		}
	}
	return out
}

func (ix *index) hasPDB(w object) bool {
	labels := w.podLabels()
	for _, p := range ix.of("PodDisruptionBudget") {
		if p.namespace != w.namespace {
			continue
		}
		if labelSelectorMatches(mapAt(p.props, "spec", "selector"), labels, false) {
			return true
		}
	}
	return false
}

func (ix *index) hasHPA(w object) bool {
	for _, h := range ix.of("HorizontalPodAutoscaler", "ScaledObject") {
		ref := mapAt(h.props, "spec", "scaleTargetRef")
		if ref == nil {
			continue
		}
		name, _ := ref["name"].(string)
		kind, _ := ref["kind"].(string)
		if name != w.name || h.namespace != w.namespace {
			continue
		}
		if kind == "" || kind == w.kind {
			return true
		}
	}
	return false
}

func (ix *index) networkPolicySelects(w object) bool {
	labels := w.podLabels()
	for _, np := range ix.of("NetworkPolicy") {
		if np.namespace != w.namespace {
			continue
		}
		// An empty podSelector selects every pod in the namespace.
		if labelSelectorMatches(mapAt(np.props, "spec", "podSelector"), labels, true) {
			return true
		}
	}
	return false
}

func (ix *index) monitorSelects(w object) bool {
	labels := w.podLabels()
	for _, m := range ix.of("PodMonitor") {
		if labelSelectorMatches(mapAt(m.props, "spec", "selector"), labels, false) {
			return true
		}
	}
	// A ServiceMonitor selects Services; the Service must in turn select the pods.
	for _, m := range ix.of("ServiceMonitor") {
		sel := mapAt(m.props, "spec", "selector")
		for _, svc := range ix.of("Service") {
			if !labelSelectorMatches(sel, svc.labels(), false) {
				continue
			}
			if matchLabels(mapAt(svc.props, "spec", "selector"), labels) {
				return true
			}
		}
	}
	return false
}

// automountToken is the effective automountServiceAccountToken: the pod
// setting, else the ServiceAccount's, else true.
func (ix *index) automountToken(w object) bool {
	pod := w.podSpec()
	if v, ok := boolAt(pod, "automountServiceAccountToken"); ok {
		return v
	}
	saName, _ := pod["serviceAccountName"].(string)
	if saName == "" {
		saName = "default"
	}
	for _, sa := range ix.of("ServiceAccount") {
		if sa.name == saName && sa.namespace == w.namespace {
			if v, ok := boolAt(sa.props, "automountServiceAccountToken"); ok {
				return v
			}
		}
	}
	return true
}

func (ix *index) serviceTargetsPods(s object) bool {
	sel := mapAt(s.props, "spec", "selector")
	if len(sel) == 0 {
		return false
	}
	for _, o := range ix.all {
		if !workloadKinds[o.kind] {
			continue
		}
		if matchLabels(sel, o.podLabels()) {
			return true
		}
	}
	return false
}

func (ix *index) namespaceDeclared(name string) bool {
	for _, o := range ix.of("Namespace") {
		if o.name == name {
			return true
		}
	}
	return false
}

func (ix *index) namespaceLabels(name string) map[string]any {
	for _, o := range ix.of("Namespace") {
		if o.name == name {
			return o.labels()
		}
	}
	return nil
}

func (ix *index) nsHasKind(ns, kind string) bool {
	for _, o := range ix.of(kind) {
		if o.namespace == ns {
			return true
		}
	}
	return false
}

// hasDefaultDenyIngress is true when a NetworkPolicy in the namespace selects
// every pod and declares the Ingress policy type with no allow rules.
func (ix *index) hasDefaultDenyIngress(ns string) bool {
	for _, np := range ix.of("NetworkPolicy") {
		if np.namespace != ns {
			continue
		}
		if len(mapAt(np.props, "spec", "podSelector")) != 0 {
			continue // not a catch-all
		}
		spec := mapAt(np.props, "spec")
		types, _ := spec["policyTypes"].([]any)
		hasIngress := false
		for _, t := range types {
			if s, _ := t.(string); s == "Ingress" {
				hasIngress = true
			}
		}
		if !hasIngress {
			continue
		}
		if rules, ok := spec["ingress"].([]any); ok && len(rules) > 0 {
			continue // allows traffic, not a default deny
		}
		return true
	}
	return false
}

// ---- label selectors ----

// labelSelectorMatches evaluates a LabelSelector {matchLabels, matchExpressions}
// against labels. emptyMatchesAll controls what an empty selector means.
func labelSelectorMatches(sel, labels map[string]any, emptyMatchesAll bool) bool {
	if sel == nil {
		return false
	}
	ml := mapAt(sel, "matchLabels")
	exprs, _ := sel["matchExpressions"].([]any)
	if len(ml) == 0 && len(exprs) == 0 {
		return emptyMatchesAll
	}
	if !matchLabels(ml, labels) {
		return false
	}
	for _, e := range exprs {
		if !matchExpression(mapOf(e), labels) {
			return false
		}
	}
	return true
}

func matchLabels(sel, labels map[string]any) bool {
	if len(sel) == 0 {
		return false
	}
	for k, want := range sel {
		got, ok := labels[k]
		if !ok || scalar(got) != scalar(want) {
			return false
		}
	}
	return true
}

func matchExpression(e, labels map[string]any) bool {
	key, _ := e["key"].(string)
	op, _ := e["operator"].(string)
	values, _ := e["values"].([]any)
	got, present := labels[key]
	in := func() bool {
		for _, v := range values {
			if scalar(v) == scalar(got) {
				return true
			}
		}
		return false
	}
	switch op {
	case "In":
		return present && in()
	case "NotIn":
		return !present || !in()
	case "Exists":
		return present
	case "DoesNotExist":
		return !present
	}
	return false
}

// ---- small helpers ----

func mapAt(m map[string]any, path ...string) map[string]any {
	cur := m
	for _, k := range path {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func boolAt(m map[string]any, key string) (bool, bool) {
	if m == nil {
		return false, false
	}
	b, ok := m[key].(bool)
	return b, ok
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return strings.TrimSpace(strings.Trim(strconv.Quote(toStr(t)), `"`))
	}
}

func toStr(v any) string {
	switch t := v.(type) {
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func collectStrings(v any, out *[]any) {
	if len(*out) >= 5000 {
		return
	}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) != "" {
			*out = append(*out, t)
		}
	case []any:
		for _, e := range t {
			collectStrings(e, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectStrings(t[k], out)
		}
	}
}

func putList(m map[string]any, key string, v []any) {
	if len(v) > 0 {
		m[key] = v
	}
}

func nameFor(path string) string {
	if path == "" {
		return "manifest.yaml"
	}
	return filepath.Base(path)
}

// siblingObjects decodes the other manifest files in the same directory, so
// cross-object rules (PDB, HPA, NetworkPolicy, quotas) see the whole set.
func siblingObjects(self string) []object {
	if self == "" {
		return nil
	}
	dir := filepath.Dir(self)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []object
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if p == self || !isYAMLFile(p) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		objs, err := decodeObjects(data, p)
		if err != nil {
			continue
		}
		out = append(out, objs...)
		if len(out) >= 2000 {
			break
		}
	}
	return out
}

func isYAMLFile(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}

// decodeObjects decodes every object in a manifest file.
func decodeObjects(content []byte, file string) ([]object, error) {
	docs, err := yamlutil.Documents(content)
	if err != nil {
		return nil, err
	}
	var out []object
	for _, doc := range docs {
		objs, err := objectsFrom(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, objs...)
	}
	_ = file
	return out, nil
}
