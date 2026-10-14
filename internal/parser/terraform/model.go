package terraform

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/nexutils/StackGuard/internal/models"
)

// buildModule assembles one "terraform" resource from a module's .tf files.
func buildModule(dir, anchor string, files []tfFile) *models.Resource {
	if len(files) == 0 {
		return nil
	}
	b := &builder{
		locs:        map[string]models.Position{},
		defaultTags: map[string]map[string]any{},
		stringSet:   map[string]struct{}{},
		byAddress:   map[string]int{},
		azSet:       map[string]struct{}{},
	}

	// First pass: provider default_tags so resources can merge them.
	for _, f := range files {
		for _, blk := range f.body.Blocks {
			if blk.Type == "provider" && len(blk.Labels) == 1 {
				b.collectDefaultTags(blk, f.src)
			}
		}
	}

	// Second pass: every block, in a stable order (file name, then source order).
	for _, f := range files {
		for _, blk := range f.body.Blocks {
			b.add(blk, f.src)
		}
	}

	b.linkReferences()

	moduleName := filepath.Base(dir)
	if moduleName == "." || moduleName == "" || moduleName == "/" {
		moduleName = strings.TrimSuffix(anchor, filepath.Ext(anchor))
	}

	props := map[string]any{
		"resources":      b.resources,
		"data_sources":   b.data,
		"variables":      b.variables,
		"outputs":        b.outputs,
		"locals_entries": b.locals,
		"providers":      b.providers,
		"module_calls":   b.modules,
		"terraform":      b.terraform,
		"summary":        b.summary(),
		"strings":        b.strings(),
		"context":        b.context(dir, files),
	}

	return &models.Resource{
		Target:     Target,
		Type:       Target,
		Name:       moduleName,
		File:       filepath.ToSlash(filepath.Join(dir, anchor)),
		Line:       1,
		Properties: props,
		Locations:  b.locs,
	}
}

type builder struct {
	resources []any
	data      []any
	variables []any
	outputs   []any
	locals    []any
	providers []any
	modules   []any
	terraform map[string]any

	locs        map[string]models.Position
	defaultTags map[string]map[string]any // provider name -> merged default_tags
	stringSet   map[string]struct{}
	azSet       map[string]struct{} // distinct availability zones
	byAddress   map[string]int      // address -> index in combined
	combined    []map[string]any
	rawRefs     [][]string // per combined index: referenced addresses
}

// add dispatches one top-level block.
func (b *builder) add(blk *hclsyntax.Block, src []byte) {
	switch blk.Type {
	case "resource":
		b.addResource(blk, src, false)
	case "data":
		b.addResource(blk, src, true)
	case "variable":
		b.addVariable(blk, src)
	case "output":
		b.addOutput(blk, src)
	case "locals":
		b.addLocals(blk, src)
	case "provider":
		b.addProvider(blk, src)
	case "module":
		b.addModule(blk, src)
	case "terraform":
		b.addTerraform(blk, src)
	}
}

func (b *builder) addResource(blk *hclsyntax.Block, src []byte, isData bool) {
	if len(blk.Labels) != 2 {
		return
	}
	rtype, name := blk.Labels[0], blk.Labels[1]
	address := rtype + "." + name
	kind := "resource"
	listName := "resources"
	idx := len(b.resources)
	if isData {
		kind = "data"
		listName = "data_sources"
		idx = len(b.data)
		address = "data." + address
	}
	prefix := listName + "." + strconv.Itoa(idx)
	b.locs[prefix] = rangePos(blk.TypeRange)

	attrs := convertBody(blk.Body, prefix+".attrs", src, b.locs)
	b.collectStrings(attrs)
	b.collectAZ(attrs)

	provider := providerOf(rtype)
	entry := map[string]any{
		"type":              rtype,
		"name":              name,
		"address":           address,
		"provider":          provider,
		"module":            "",
		"kind":              kind,
		"file":              blk.TypeRange.Filename,
		"line":              blk.TypeRange.Start.Line,
		"attrs":             attrs,
		"attr_pairs":        flattenPairs(attrs),
		"has_count":         hasAttr(blk, "count"),
		"has_for_each":      hasAttr(blk, "for_each"),
		"lifecycle":         singleBlock(attrs, "lifecycle"),
		"references":        []any{},
		"referenced_by":     []any{},
		"policy_statements": b.policyStatements(rtype, attrs),
	}
	if !isData {
		entry["tags"] = b.resourceTags(provider, attrs)
		entry["taggable"] = taggable(kind, provider, rtype)
		entry["stateful"] = stateful(rtype)
	} else {
		entry["tags"] = map[string]any{}
		entry["taggable"] = false
		entry["stateful"] = false
	}

	b.byAddress[address] = len(b.combined)
	b.combined = append(b.combined, entry)
	b.rawRefs = append(b.rawRefs, referenceAddrs(attrs))
	if isData {
		b.data = append(b.data, entry)
	} else {
		b.resources = append(b.resources, entry)
	}
}

func (b *builder) addVariable(blk *hclsyntax.Block, src []byte) {
	if len(blk.Labels) != 1 {
		return
	}
	idx := len(b.variables)
	prefix := "variables." + strconv.Itoa(idx)
	b.locs[prefix] = rangePos(blk.TypeRange)
	body := convertBody(blk.Body, prefix, src, b.locs)
	def, hasDef := body["default"]
	entry := map[string]any{
		"name":           blk.Labels[0],
		"type":           stringOf(body["type"]),
		"default":        def,
		"has_default":    hasDef,
		"sensitive":      boolOf(body["sensitive"]),
		"description":    stringOf(body["description"]),
		"has_validation": hasNestedBlock(blk, "validation"),
	}
	b.collectStrings(body)
	b.variables = append(b.variables, entry)
}

func (b *builder) addOutput(blk *hclsyntax.Block, src []byte) {
	if len(blk.Labels) != 1 {
		return
	}
	idx := len(b.outputs)
	prefix := "outputs." + strconv.Itoa(idx)
	b.locs[prefix] = rangePos(blk.TypeRange)
	body := convertBody(blk.Body, prefix, src, b.locs)
	val, hasVal := body["value"]
	entry := map[string]any{
		"name":        blk.Labels[0],
		"value":       val,
		"has_value":   hasVal,
		"sensitive":   boolOf(body["sensitive"]),
		"description": stringOf(body["description"]),
	}
	b.collectStrings(body)
	b.outputs = append(b.outputs, entry)
}

func (b *builder) addLocals(blk *hclsyntax.Block, src []byte) {
	prefix := "locals." + strconv.Itoa(len(b.locals))
	body := convertBody(blk.Body, prefix, src, b.locs)
	b.collectStrings(body)
	names := make([]string, 0, len(body))
	for k := range body {
		if strings.HasPrefix(k, "_") {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		b.locals = append(b.locals, map[string]any{
			"name":  name,
			"value": body[name],
		})
	}
}

func (b *builder) addProvider(blk *hclsyntax.Block, src []byte) {
	if len(blk.Labels) != 1 {
		return
	}
	idx := len(b.providers)
	prefix := "providers." + strconv.Itoa(idx)
	b.locs[prefix] = rangePos(blk.TypeRange)
	attrs := convertBody(blk.Body, prefix, src, b.locs)
	b.collectStrings(attrs)
	entry := map[string]any{
		"name":         blk.Labels[0],
		"alias":        stringOf(attrs["alias"]),
		"region":       stringOf(attrs["region"]),
		"attrs":        attrs,
		"attr_pairs":   flattenPairs(attrs),
		"default_tags": defaultTagsOf(attrs),
	}
	b.providers = append(b.providers, entry)
}

func (b *builder) addModule(blk *hclsyntax.Block, src []byte) {
	if len(blk.Labels) != 1 {
		return
	}
	idx := len(b.modules)
	prefix := "module_calls." + strconv.Itoa(idx)
	b.locs[prefix] = rangePos(blk.TypeRange)
	attrs := convertBody(blk.Body, prefix, src, b.locs)
	b.collectStrings(attrs)
	source := stringOf(attrs["source"])
	entry := map[string]any{
		"name":       blk.Labels[0],
		"source":     source,
		"version":    stringOf(attrs["version"]),
		"local":      strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../"),
		"attrs":      attrs,
		"attr_pairs": flattenPairs(attrs),
	}
	b.modules = append(b.modules, entry)
}

func (b *builder) addTerraform(blk *hclsyntax.Block, src []byte) {
	tf := map[string]any{}
	if b.terraform != nil {
		tf = b.terraform
	}
	body := convertBody(blk.Body, "terraform", src, b.locs)
	if v, ok := body["required_version"]; ok {
		tf["required_version"] = v
	}
	if rp := singleBlock(body, "required_providers"); rp != nil {
		providers := map[string]any{}
		for k, v := range rp {
			if strings.HasPrefix(k, "_") {
				continue
			}
			providers[k] = v
		}
		tf["required_providers"] = providers
	}
	if backend := firstBlock(body, "backend"); backend != nil {
		bt := ""
		if lbls, ok := backend["_labels"].([]any); ok && len(lbls) > 0 {
			bt = stringOf(lbls[0])
		}
		clean := map[string]any{}
		for k, v := range backend {
			if strings.HasPrefix(k, "_") {
				continue
			}
			clean[k] = v
		}
		tf["backend"] = map[string]any{"type": bt, "attrs": clean}
	}
	if firstBlock(body, "cloud") != nil {
		tf["cloud"] = true
	}
	b.terraform = tf
	b.locs["terraform"] = rangePos(blk.TypeRange)
}

// collectDefaultTags records a provider's default_tags for later merge.
func (b *builder) collectDefaultTags(blk *hclsyntax.Block, src []byte) {
	attrs := convertBody(blk.Body, "", src, map[string]models.Position{})
	if dt := defaultTagsOf(attrs); len(dt) > 0 {
		name := blk.Labels[0]
		merged := b.defaultTags[name]
		if merged == nil {
			merged = map[string]any{}
			b.defaultTags[name] = merged
		}
		for k, v := range dt {
			merged[k] = v
		}
	}
}

// resourceTags merges a resource's own tags over the provider default_tags.
func (b *builder) resourceTags(provider string, attrs map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range b.defaultTags[provider] {
		out[k] = v
	}
	// AWS/Azure use `tags`, Google uses `labels`.
	for _, key := range []string{"tags", "labels"} {
		if tags, ok := attrs[key].(map[string]any); ok {
			for k, v := range tags {
				out[k] = v
			}
		}
	}
	return out
}

// linkReferences fills references / referenced_by with {type,address,attrs}.
func (b *builder) linkReferences() {
	for i, entry := range b.combined {
		addr := stringOf(entry["address"])
		seen := map[string]bool{}
		for _, target := range b.rawRefs[i] {
			if target == addr || seen[target] {
				continue
			}
			tj, ok := b.byAddress[target]
			if !ok {
				continue
			}
			seen[target] = true
			tEntry := b.combined[tj]
			entry["references"] = append(entry["references"].([]any), refObject(tEntry))
			tEntry["referenced_by"] = append(tEntry["referenced_by"].([]any), refObject(entry))
		}
	}
}

func refObject(entry map[string]any) map[string]any {
	return map[string]any{
		"type":    entry["type"],
		"address": entry["address"],
		"attrs":   entry["attrs"],
	}
}

func (b *builder) summary() map[string]any {
	types := map[string]any{}
	provSet := map[string]struct{}{}
	for _, e := range b.resources {
		m := e.(map[string]any)
		t := stringOf(m["type"])
		types[t] = asInt(types[t]) + 1
		provSet[stringOf(m["provider"])] = struct{}{}
	}
	for _, e := range b.providers {
		provSet[stringOf(e.(map[string]any)["name"])] = struct{}{}
	}
	provs := make([]any, 0, len(provSet))
	for p := range provSet {
		provs = append(provs, p)
	}
	sort.Slice(provs, func(i, j int) bool { return stringOf(provs[i]) < stringOf(provs[j]) })

	hasBackend, backendType := false, ""
	if b.terraform != nil {
		if be, ok := b.terraform["backend"].(map[string]any); ok {
			hasBackend = true
			backendType = stringOf(be["type"])
		}
	}
	return map[string]any{
		"resource_count": len(b.resources),
		"data_count":     len(b.data),
		"provider_count": len(b.providers),
		"module_count":   len(b.modules),
		"variable_count": len(b.variables),
		"output_count":   len(b.outputs),
		"types":          types,
		"providers":      provs,
		"has_backend":    hasBackend,
		"backend_type":   backendType,
		"az_count":       len(b.azSet),
	}
}

func (b *builder) strings() []any {
	out := make([]any, 0, len(b.stringSet))
	for s := range b.stringSet {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return stringOf(out[i]) < stringOf(out[j]) })
	return out
}

func (b *builder) context(dir string, files []tfFile) map[string]any {
	moduleFiles := make([]any, 0, len(files))
	for _, f := range files {
		moduleFiles = append(moduleFiles, f.name)
	}
	repoFiles, ciText := scanModuleTree(dir)
	if len(repoFiles) == 0 {
		repoFiles = moduleFiles
	}
	return map[string]any{
		"files":          repoFiles,
		"ci_text":        ciText,
		"is_root_module": b.terraform != nil || len(b.providers) > 0,
		"environment":    b.environment(dir),
		"state_store":    b.stateStore(),
	}
}

// environment derives the environment name from the directory, or from a local /
// variable named environment, env or stage with a literal value.
func (b *builder) environment(dir string) string {
	if e := environmentOf(dir); e != "" {
		return e
	}
	isName := func(n string) bool { return n == "environment" || n == "env" || n == "stage" }
	for _, l := range b.locals {
		m := l.(map[string]any)
		if isName(stringOf(m["name"])) {
			if s := stringOf(m["value"]); s != "" && !strings.Contains(s, "${") {
				return s
			}
		}
	}
	for _, v := range b.variables {
		m := v.(map[string]any)
		if isName(stringOf(m["name"])) {
			if s := stringOf(m["default"]); s != "" && !strings.Contains(s, "${") {
				return s
			}
		}
	}
	return ""
}

// stateStore reports on the bucket / storage account that holds state when it is
// managed in this configuration.
func (b *builder) stateStore() map[string]any {
	out := map[string]any{"found": false, "versioning": false, "soft_delete": false}
	if b.terraform == nil {
		return out
	}
	be, ok := b.terraform["backend"].(map[string]any)
	if !ok {
		return out
	}
	attrs, _ := be["attrs"].(map[string]any)
	switch stringOf(be["type"]) {
	case "s3":
		if r := b.findByAttr("aws_s3_bucket", "bucket", stringOf(attrs["bucket"])); r != nil {
			out["found"] = true
			out["versioning"] = s3Versioning(r)
		}
	case "gcs":
		if r := b.findByAttr("google_storage_bucket", "name", stringOf(attrs["bucket"])); r != nil {
			out["found"] = true
			if v := firstBlock(r["attrs"].(map[string]any), "versioning"); v != nil {
				out["versioning"] = boolOf(v["enabled"])
			}
		}
	case "azurerm":
		if r := b.findByAttr("azurerm_storage_account", "name", stringOf(attrs["storage_account_name"])); r != nil {
			out["found"] = true
			if bp := firstBlock(r["attrs"].(map[string]any), "blob_properties"); bp != nil {
				out["versioning"] = boolOf(bp["versioning_enabled"])
				if dr := firstBlock(bp, "delete_retention_policy"); dr != nil {
					out["soft_delete"] = true
				}
			}
		}
	}
	return out
}

// s3Versioning reports whether an aws_s3_bucket has versioning enabled, inline or
// through a referencing aws_s3_bucket_versioning resource.
func s3Versioning(bucket map[string]any) bool {
	if v := firstBlock(bucket["attrs"].(map[string]any), "versioning"); v != nil {
		if boolOf(v["enabled"]) {
			return true
		}
	}
	for _, rb := range bucket["referenced_by"].([]any) {
		m := rb.(map[string]any)
		if stringOf(m["type"]) != "aws_s3_bucket_versioning" {
			continue
		}
		if vc := firstBlock(m["attrs"].(map[string]any), "versioning_configuration"); vc != nil {
			if stringOf(vc["status"]) == "Enabled" {
				return true
			}
		}
	}
	return false
}

func (b *builder) findByAttr(rtype, key, val string) map[string]any {
	if val == "" {
		return nil
	}
	for _, e := range b.resources {
		m := e.(map[string]any)
		if stringOf(m["type"]) != rtype {
			continue
		}
		if stringOf(m["attrs"].(map[string]any)[key]) == val {
			return m
		}
	}
	return nil
}

// collectStrings records every string literal (not a ${...} reference) found in v.
func (b *builder) collectStrings(v any) {
	switch t := v.(type) {
	case string:
		if t != "" && !strings.Contains(t, "${") {
			b.stringSet[t] = struct{}{}
		}
	case map[string]any:
		for k, val := range t {
			if strings.HasPrefix(k, "_") {
				continue
			}
			b.collectStrings(val)
		}
	case []any:
		for _, e := range t {
			b.collectStrings(e)
		}
	}
}

// collectAZ records distinct availability zones so summary.az_count can report
// how many zones subnets span.
func (b *builder) collectAZ(attrs map[string]any) {
	if az, ok := attrs["availability_zone"].(string); ok && az != "" && !strings.Contains(az, "${") {
		b.azSet[az] = struct{}{}
	}
	if list, ok := attrs["availability_zones"].([]any); ok {
		for _, e := range list {
			if s := stringOf(e); s != "" && !strings.Contains(s, "${") {
				b.azSet[s] = struct{}{}
			}
		}
	}
}

// policyStatements extracts normalized IAM statements from a literal JSON policy
// attribute or from an aws_iam_policy_document data source's statement blocks.
func (b *builder) policyStatements(rtype string, attrs map[string]any) []any {
	var out []any
	if rtype == "aws_iam_policy_document" {
		for _, raw := range toList(attrs["statement"]) {
			stmt, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, map[string]any{
				"effect":         defaultStr(stringOf(stmt["effect"]), "Allow"),
				"actions":        toStringList(stmt["actions"]),
				"not_actions":    toStringList(stmt["not_actions"]),
				"resources":      toStringList(stmt["resources"]),
				"not_resources":  toStringList(stmt["not_resources"]),
				"principals":     principalsFromBlocks(stmt),
				"condition_keys": conditionKeysFromBlocks(stmt),
				"has_condition":  firstBlock(stmt, "condition") != nil,
				"sid":            stringOf(stmt["sid"]),
			})
		}
		return out
	}
	for key, val := range attrs {
		if !strings.HasSuffix(key, "policy") {
			continue
		}
		s, ok := val.(string)
		if !ok || strings.Contains(s, "${") {
			continue
		}
		out = append(out, parseJSONPolicy(s)...)
	}
	return out
}

// --- references ---

var refRE = regexp.MustCompile(`\b(data\.[a-z][a-z0-9_]*\.[A-Za-z0-9_-]+|module\.[A-Za-z0-9_-]+|var\.[A-Za-z0-9_-]+|local\.[A-Za-z0-9_-]+|[a-z][a-z0-9]*(?:_[a-z0-9]+)+\.[A-Za-z0-9_-]+)`)

// referenceAddrs returns the distinct addresses referenced by an attrs tree.
func referenceAddrs(v any) []string {
	set := map[string]struct{}{}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if !strings.Contains(t, "${") {
				return
			}
			for _, m := range refRE.FindAllString(t, -1) {
				set[m] = struct{}{}
			}
		case map[string]any:
			for k, val := range t {
				if strings.HasPrefix(k, "_") {
					continue
				}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// flattenPairs lists every scalar leaf as {key,value,path}.
func flattenPairs(attrs map[string]any) []any {
	var out []any
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				if strings.HasPrefix(k, "_") {
					continue
				}
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child := k
				if prefix != "" {
					child = prefix + "." + k
				}
				walk(child, t[k])
			}
		case []any:
			for i, e := range t {
				walk(prefix+"."+strconv.Itoa(i), e)
			}
		default:
			if v == nil {
				return
			}
			key := prefix
			if i := strings.LastIndex(prefix, "."); i >= 0 {
				key = prefix[i+1:]
			}
			out = append(out, map[string]any{
				"key":   key,
				"value": scalarString(v),
				"path":  prefix,
			})
		}
	}
	walk("", attrs)
	return out
}

// --- IAM policy parsing ---

func parseJSONPolicy(s string) []any {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil || len(doc.Statement) == 0 {
		return nil
	}
	var arr []map[string]any
	if err := json.Unmarshal(doc.Statement, &arr); err != nil {
		var one map[string]any
		if err := json.Unmarshal(doc.Statement, &one); err != nil {
			return nil
		}
		arr = []map[string]any{one}
	}
	var out []any
	for _, st := range arr {
		cond, hasCond := st["Condition"]
		out = append(out, map[string]any{
			"effect":         defaultStr(stringOf(st["Effect"]), "Allow"),
			"actions":        jsonStringList(st["Action"]),
			"not_actions":    jsonStringList(st["NotAction"]),
			"resources":      jsonStringList(st["Resource"]),
			"not_resources":  jsonStringList(st["NotResource"]),
			"principals":     jsonPrincipals(st["Principal"]),
			"condition_keys": jsonConditionKeys(cond),
			"has_condition":  hasCond,
			"sid":            stringOf(st["Sid"]),
		})
	}
	return out
}

func jsonStringList(v any) []any {
	switch t := v.(type) {
	case string:
		return []any{t}
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, stringOf(e))
		}
		return out
	}
	return []any{}
}

// jsonPrincipals normalizes a JSON Principal to ["*"] or ["AWS:arn", "Service:x"].
func jsonPrincipals(v any) []any {
	switch t := v.(type) {
	case string:
		return []any{t}
	case map[string]any:
		out := []any{}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, id := range jsonStringList(t[k]) {
				out = append(out, k+":"+stringOf(id))
			}
		}
		return out
	}
	return []any{}
}

// jsonConditionKeys returns the sorted condition keys of a JSON Condition block.
func jsonConditionKeys(v any) []any {
	m, ok := v.(map[string]any)
	if !ok {
		return []any{}
	}
	set := map[string]struct{}{}
	for _, inner := range m {
		if im, ok := inner.(map[string]any); ok {
			for k := range im {
				set[k] = struct{}{}
			}
		}
	}
	return sortedAny(set)
}

// principalsFromBlocks reads the principals {type, identifiers} blocks of an
// aws_iam_policy_document statement.
func principalsFromBlocks(stmt map[string]any) []any {
	out := []any{}
	for _, raw := range toList(stmt["principals"]) {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		ptype := stringOf(p["type"])
		for _, id := range toStringList(p["identifiers"]) {
			if ptype == "AWS" && stringOf(id) == "*" {
				out = append(out, "AWS:*")
			} else {
				out = append(out, ptype+":"+stringOf(id))
			}
		}
	}
	return out
}

func conditionKeysFromBlocks(stmt map[string]any) []any {
	set := map[string]struct{}{}
	for _, raw := range toList(stmt["condition"]) {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if v := stringOf(c["variable"]); v != "" {
			set[v] = struct{}{}
		}
	}
	return sortedAny(set)
}

// --- repository context ---

var ciNames = map[string]bool{
	".gitlab-ci.yml": true, ".gitlab-ci.yaml": true,
	"azure-pipelines.yml": true, "azure-pipelines.yaml": true,
	"atlantis.yaml": true, "atlantis.yml": true,
	".pre-commit-config.yaml": true, ".pre-commit-config.yml": true,
	".tflint.hcl": true,
}

// scanModuleTree walks the module directory subtree (not upward — no repo-walk or
// .git logic, to stay consistent with the other parsers and keep scans scoped to
// what is handed in) and returns its file paths (relative to the module dir) plus
// the text of any CI / automation config files found within it. Best-effort: when
// the directory cannot be read (in-memory sources, the content-based golden
// harness) it returns nothing and the caller falls back to the .tf file names.
func scanModuleTree(moduleDir string) (files []any, ciText []any) {
	if moduleDir == "" {
		return nil, nil
	}
	const maxFiles = 20000
	count := 0
	_ = filepath.WalkDir(moduleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if count >= maxFiles {
			return fs.SkipAll
		}
		count++
		rel, rerr := filepath.Rel(moduleDir, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		files = append(files, rel)
		if isCIFile(rel, d.Name()) {
			if text := readCapped(path); text != "" {
				ciText = append(ciText, map[string]any{"file": rel, "text": text})
			}
		}
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return stringOf(files[i]) < stringOf(files[j]) })
	sort.Slice(ciText, func(i, j int) bool {
		return stringOf(ciText[i].(map[string]any)["file"]) < stringOf(ciText[j].(map[string]any)["file"])
	})
	return files, ciText
}

func isCIFile(rel, base string) bool {
	if ciNames[base] {
		return true
	}
	if base == "Jenkinsfile" || strings.HasSuffix(strings.ToLower(base), ".jenkinsfile") {
		return true
	}
	if strings.Contains(rel, ".github/workflows/") {
		ext := strings.ToLower(filepath.Ext(base))
		return ext == ".yml" || ext == ".yaml"
	}
	return false
}

func readCapped(path string) string {
	const maxBytes = 256 * 1024
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	return string(b)
}

// --- small helpers ---

func providerOf(rtype string) string {
	if i := strings.Index(rtype, "_"); i > 0 {
		return rtype[:i]
	}
	return rtype
}

var taggableProviders = map[string]bool{"aws": true, "azurerm": true, "google": true, "alicloud": true, "oci": true}

var nonTaggable = map[string]bool{
	"aws_iam_role_policy_attachment": true, "aws_iam_policy_attachment": true,
	"aws_route": true, "aws_route_table_association": true,
	"aws_security_group_rule": true, "aws_s3_bucket_policy": true,
	"aws_lambda_permission": true, "aws_iam_role_policy": true,
	"aws_iam_user_policy": true, "aws_iam_group_policy": true,
	"aws_s3_bucket_public_access_block": true, "aws_s3_bucket_versioning": true,
	"aws_s3_bucket_acl": true, "aws_network_acl_rule": true,
}

func taggable(kind, provider, rtype string) bool {
	return kind == "resource" && taggableProviders[provider] && !nonTaggable[rtype]
}

var statefulTypes = map[string]bool{
	"aws_db_instance": true, "aws_rds_cluster": true, "aws_rds_cluster_instance": true,
	"aws_dynamodb_table": true, "aws_s3_bucket": true, "aws_ebs_volume": true,
	"aws_efs_file_system": true, "aws_elasticache_cluster": true,
	"aws_elasticache_replication_group": true, "aws_redshift_cluster": true,
	"aws_docdb_cluster": true, "aws_neptune_cluster": true, "aws_instance": true,
	"aws_fsx_lustre_file_system": true, "aws_sqs_queue": true, "aws_kinesis_stream": true,
	"google_sql_database_instance": true, "google_compute_disk": true,
	"google_storage_bucket": true, "google_spanner_instance": true,
	"google_bigtable_instance": true,
	"azurerm_managed_disk":     true, "azurerm_storage_account": true,
	"azurerm_mssql_database": true, "azurerm_mssql_server": true,
	"azurerm_postgresql_flexible_server": true, "azurerm_mysql_flexible_server": true,
	"azurerm_cosmosdb_account": true, "azurerm_key_vault": true,
}

func stateful(rtype string) bool { return statefulTypes[rtype] }

func defaultTagsOf(attrs map[string]any) map[string]any {
	dt := singleBlock(attrs, "default_tags")
	if dt == nil {
		return map[string]any{}
	}
	if tags, ok := dt["tags"].(map[string]any); ok {
		return tags
	}
	return map[string]any{}
}

func singleBlock(attrs map[string]any, key string) map[string]any { return firstBlock(attrs, key) }

func firstBlock(attrs map[string]any, key string) map[string]any {
	list, ok := attrs[key].([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	m, _ := list[0].(map[string]any)
	return m
}

func hasAttr(blk *hclsyntax.Block, name string) bool {
	_, ok := blk.Body.Attributes[name]
	return ok
}

func hasNestedBlock(blk *hclsyntax.Block, typ string) bool {
	for _, b := range blk.Body.Blocks {
		if b.Type == typ {
			return true
		}
	}
	return false
}

func environmentOf(dir string) string {
	lower := strings.ToLower(dir)
	for _, env := range []string{"production", "prod", "staging", "stage", "development", "dev", "test", "qa", "sandbox"} {
		if strings.Contains(lower, env) {
			return env
		}
	}
	return ""
}

func toList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func toStringList(v any) []any {
	switch t := v.(type) {
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, stringOf(e))
		}
		return out
	case string:
		return []any{t}
	}
	return []any{}
}

func sortedAny(set map[string]struct{}) []any {
	out := make([]any, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return stringOf(out[i]) < stringOf(out[j]) })
	return out
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}

func asInt(v any) int {
	i, _ := v.(int)
	return i
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
