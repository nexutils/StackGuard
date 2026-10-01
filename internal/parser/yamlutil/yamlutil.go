// Package yamlutil converts YAML node trees into the generic values used by
// Resource.Properties while recording source positions for every path.
package yamlutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"

	"github.com/nexutils/StackGuard/internal/models"
)

// maxNodes bounds alias expansion so hostile "billion laughs" documents cannot
// exhaust memory.
const maxNodes = 1_000_000

// ErrTooLarge is returned when a document expands beyond maxNodes.
var ErrTooLarge = errors.New("yaml document expands to too many nodes")

// Documents parses every document in a (possibly multi-document) YAML stream
// and returns their root content nodes. Empty documents are skipped.
func Documents(content []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
			docs = append(docs, doc.Content[0])
		}
	}
}

// Decoder converts nodes to generic values, recording positions keyed by
// canonical property path.
type Decoder struct {
	Locations map[string]models.Position
	budget    int
	err       error
}

// NewDecoder returns a Decoder with an empty location table.
func NewDecoder() *Decoder {
	return &Decoder{Locations: map[string]models.Position{}, budget: maxNodes}
}

// Decode converts n. prefix is the canonical path of n.
func (d *Decoder) Decode(n *yaml.Node, prefix string) (any, error) {
	v := d.decode(n, prefix)
	return v, d.err
}

// DecodeMap converts a mapping node; it errors if n is not a mapping.
func (d *Decoder) DecodeMap(n *yaml.Node, prefix string) (map[string]any, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: expected a mapping", n.Line)
	}
	v, err := d.Decode(n, prefix)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

func (d *Decoder) decode(n *yaml.Node, prefix string) any {
	if d.err != nil || n == nil {
		return nil
	}
	d.budget--
	if d.budget < 0 {
		d.err = ErrTooLarge
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil
		}
		return d.decode(n.Content[0], prefix)
	case yaml.AliasNode:
		return d.decode(n.Alias, prefix)
	case yaml.ScalarNode:
		var v any
		if err := n.Decode(&v); err != nil {
			return n.Value
		}
		return v
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for i, item := range n.Content {
			p := models.JoinIndex(prefix, i)
			d.Locations[p] = pos(item)
			out = append(out, d.decode(item, p))
		}
		return out
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		d.decodeMapping(n, prefix, out)
		return out
	}
	return nil
}

func (d *Decoder) decodeMapping(n *yaml.Node, prefix string, out map[string]any) {
	// Merge keys (<<) are applied first so explicit keys override them.
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Tag == "!!merge" || (k.Value == "<<" && k.Tag != "!!str") {
			d.merge(v, prefix, out)
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Tag == "!!merge" || (k.Value == "<<" && k.Tag != "!!str") {
			continue
		}
		key := k.Value
		p := models.JoinPath(prefix, key)
		d.Locations[p] = pos(k)
		out[key] = d.decode(v, p)
	}
}

func (d *Decoder) merge(v *yaml.Node, prefix string, out map[string]any) {
	for v.Kind == yaml.AliasNode {
		v = v.Alias
	}
	switch v.Kind {
	case yaml.MappingNode:
		d.decodeMapping(v, prefix, out)
	case yaml.SequenceNode:
		for _, item := range v.Content {
			d.merge(item, prefix, out)
		}
	}
}

func pos(n *yaml.Node) models.Position {
	return models.Position{Line: n.Line, Column: n.Column}
}

// MappingValue returns the value node for key in a mapping node, plus the key
// node, or nil if absent.
func MappingValue(n *yaml.Node, key string) (keyNode, valueNode *yaml.Node) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i], n.Content[i+1]
		}
	}
	return nil, nil
}

// SubLocations extracts the locations under prefix, re-rooted so that prefix
// itself becomes the empty path.
func SubLocations(locs map[string]models.Position, prefix string) map[string]models.Position {
	out := map[string]models.Position{}
	for k, v := range locs {
		if k == prefix {
			continue
		}
		if len(k) > len(prefix) && k[:len(prefix)] == prefix && k[len(prefix)] == '.' {
			out[k[len(prefix)+1:]] = v
		}
	}
	return out
}
