// Package terraform parses Terraform (HCL) into one rich "terraform" resource
// per root module (directory of .tf files), the same one-resource-per-unit shape
// the dockerfile/helm/kubernetes parsers use.
//
// A scan hands the parser each .tf file; the parser anchors on the first .tf in
// the directory (sorted), reads every sibling .tf, and emits a single resource
// whose Properties model the whole module:
//
//	resources[*] / data_sources[*]  {type,name,address,provider,kind,attrs,
//	                                 attr_pairs[*],tags,taggable,stateful,
//	                                 lifecycle,references[*],referenced_by[*],
//	                                 policy_statements[*],...}
//	variables[*] / outputs[*] / locals_entries[*] / providers[*] / module_calls[*]
//	terraform    {required_version,required_providers,backend,...}
//	summary.*    counts, types, providers, has_backend
//	strings[*]   every string literal in the module
//	context.*    files, is_root_module, environment
//
// Attribute literals become plain Go values; references/functions/interpolation
// are kept as source text wrapped in ${...} (see exprValue). Nested blocks always
// become lists of maps, and the query engine reads a plain key through a list, so
// `settings.ip_configuration.ipv4_enabled` works whether the block repeats or not.
package terraform

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

const Target = "terraform"

// Parser implements parser.Parser for Terraform.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	return f.Ext() == ".tf"
}

// tfFile is one parsed .tf file in a module.
type tfFile struct {
	name string // base name
	src  []byte
	body *hclsyntax.Body
}

func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	base := filepath.Base(src.Path)
	dir := filepath.Dir(src.Path)

	// Collect the module's .tf files. When the directory can be listed (a real
	// scan), anchor on its first .tf so a module emits exactly one resource and
	// every sibling folds in. When it cannot (in-memory sources, the content-
	// based golden harness), fall back to just the file we were handed.
	names := []string{base}
	fromDisk := map[string]bool{}
	if entries, err := os.ReadDir(dir); err == nil {
		names = names[:0]
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".tf" {
				continue
			}
			names = append(names, e.Name())
			if e.Name() != base {
				fromDisk[e.Name()] = true
			}
		}
		sort.Strings(names)
		if len(names) == 0 || names[0] != base {
			return nil, nil // another .tf in this directory is the anchor
		}
	}

	var files []tfFile
	for _, name := range names {
		content := src.Content
		if fromDisk[name] {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			content = b
		}
		file, diags := hclsyntax.ParseConfig(content, name, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			if name == base {
				return nil, fmt.Errorf("%s", diags.Error())
			}
			continue // skip an unparseable sibling rather than fail the module
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		files = append(files, tfFile{name: name, src: content, body: body})
	}

	res := buildModule(dir, base, files)
	if res == nil {
		return nil, nil
	}
	return []models.Resource{*res}, nil
}

func classify(b *hclsyntax.Block) (typ, name string) {
	labels := b.Labels
	switch b.Type {
	case "resource", "data":
		if len(labels) != 2 {
			return "", ""
		}
		return b.Type + "." + labels[0], labels[0] + "." + labels[1]
	case "provider":
		if len(labels) != 1 {
			return "", ""
		}
		return "provider." + labels[0], labels[0]
	case "module", "variable", "output":
		if len(labels) != 1 {
			return "", ""
		}
		return b.Type, labels[0]
	case "terraform", "locals":
		return b.Type, b.Type
	}
	return "", ""
}

func convertBody(body *hclsyntax.Body, prefix string, src []byte, locs map[string]models.Position) map[string]any {
	props := map[string]any{}
	for name, attr := range body.Attributes {
		p := models.JoinPath(prefix, name)
		locs[p] = rangePos(attr.NameRange)
		props[name] = exprValue(attr.Expr, src)
	}
	for _, blk := range body.Blocks {
		key := blk.Type
		list, _ := props[key].([]any)
		p := models.JoinIndex(models.JoinPath(prefix, key), len(list))
		if len(list) == 0 {
			locs[models.JoinPath(prefix, key)] = rangePos(blk.TypeRange)
		}
		locs[p] = rangePos(blk.TypeRange)
		child := convertBody(blk.Body, p, src, locs)
		if len(blk.Labels) > 0 {
			child["_labels"] = toAnyList(blk.Labels)
		}
		props[key] = append(list, child)
	}
	return props
}

// exprValue evaluates literal expressions and falls back to source text.
//
// A reference, function call or interpolation cannot be evaluated without
// context, so it is kept as its source text wrapped in ${...} (e.g. var.region
// becomes "${var.region}"). This lets rules tell a hardcoded literal apart from
// a reference (a value starting with "${" is not a literal), and lets the model
// recover the referenced addresses for the dependency graph.
func exprValue(expr hclsyntax.Expression, src []byte) any {
	val, diags := expr.Value(nil)
	if !diags.HasErrors() && val.IsWhollyKnown() {
		if v, ok := ctyToGo(val); ok {
			return v
		}
	}
	s := strings.TrimSpace(string(expr.Range().SliceBytes(src)))
	// A quoted template string ("prefix-${var.x}") already carries its ${...};
	// drop the surrounding quotes so the value reads like an interpolation.
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if strings.HasPrefix(s, "${") {
		return s
	}
	return "${" + s + "}"
}

func ctyToGo(v cty.Value) (any, bool) {
	if v.IsNull() {
		return nil, true
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return v.AsString(), true
	case t == cty.Bool:
		return v.True(), true
	case t == cty.Number:
		bf := v.AsBigFloat()
		if bf.IsInt() {
			if i, acc := bf.Int64(); acc == big.Exact {
				return int(i), true
			}
		}
		f, _ := bf.Float64()
		return f, true
	case t.IsListType() || t.IsSetType() || t.IsTupleType():
		out := []any{}
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			g, ok := ctyToGo(ev)
			if !ok {
				return nil, false
			}
			out = append(out, g)
		}
		return out, true
	case t.IsMapType() || t.IsObjectType():
		out := map[string]any{}
		for it := v.ElementIterator(); it.Next(); {
			k, ev := it.Element()
			g, ok := ctyToGo(ev)
			if !ok {
				return nil, false
			}
			out[k.AsString()] = g
		}
		return out, true
	}
	return nil, false
}

func rangePos(r hcl.Range) models.Position {
	return models.Position{Line: r.Start.Line, Column: r.Start.Column, EndLine: r.End.Line, EndColumn: r.End.Column}
}

func toAnyList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
