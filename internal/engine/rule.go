package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"path/filepath"
	"text/template"

	"github.com/nexutils/StackGuard/internal/engine/query"
	"github.com/nexutils/StackGuard/internal/models"
)

// CompiledRule is a rule ready for evaluation: its query is compiled and its
// message template parsed.
type CompiledRule struct {
	Rule *models.Rule
	Cond query.Condition
	// When is the optional precondition; nil means always.
	When query.Condition
	msg  *template.Template
}

// Compile prepares a rule for evaluation.
func Compile(r *models.Rule) (*CompiledRule, error) {
	cond, err := query.Compile(r.Query)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", r.ID, err)
	}
	var when query.Condition
	if r.When != nil {
		if when, err = query.Compile(r.When); err != nil {
			return nil, fmt.Errorf("rule %s: when: %w", r.ID, err)
		}
	}
	msg, err := template.New(r.ID).Option("missingkey=zero").Parse(r.Message)
	if err != nil {
		return nil, fmt.Errorf("rule %s: message template: %w", r.ID, err)
	}
	return &CompiledRule{Rule: r, Cond: cond, When: when, msg: msg}, nil
}

// Applies reports whether the rule targets the resource: target and resource
// type match, and the `when` precondition (if any) holds.
func (c *CompiledRule) Applies(res *models.Resource) bool {
	if res.Target != c.Rule.Target {
		return false
	}
	matched := len(c.Rule.Resources) == 0
	for _, g := range c.Rule.Resources {
		if ok, _ := path.Match(g, res.Type); ok {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	if c.When != nil {
		ok, _ := query.EvalResource(c.When, res)
		return ok
	}
	return true
}

// Evaluate checks one resource and returns a finding if the rule matches.
func (c *CompiledRule) Evaluate(res *models.Resource) (models.Finding, bool) {
	ok, ev := query.EvalResource(c.Cond, res)
	if !ok {
		return models.Finding{}, false
	}
	pos := res.PositionFor(ev.Path)
	r := c.Rule
	return models.Finding{
		RuleID:      r.ID,
		Title:       r.Title,
		Severity:    r.Severity,
		Category:    r.Category,
		Target:      r.Target,
		File:        res.File,
		Resource:    res.Name,
		Message:     c.message(res, ev),
		Remediation: r.Remediation,
		Line:        pos.Line,
		Column:      pos.Column,
		Path:        ev.Path,
		Fingerprint: fingerprint(r.ID, res, ev.Path),
	}, true
}

// messageData is what rule message templates can reference.
type messageData struct {
	Resource *models.Resource
	Rule     *models.Rule
	Value    any
	Path     string
	// Captures holds values bound by {name} path captures.
	Captures map[string]string
}

func (c *CompiledRule) message(res *models.Resource, ev query.Evidence) string {
	var buf bytes.Buffer
	if err := c.msg.Execute(&buf, messageData{Resource: res, Rule: c.Rule, Value: ev.Value, Path: ev.Path, Captures: ev.Bindings}); err != nil {
		return c.Rule.Message
	}
	return buf.String()
}

func fingerprint(ruleID string, res *models.Resource, evidencePath string) string {
	h := sha256.New()
	for _, part := range []string{ruleID, filepath.ToSlash(res.File), res.Type, res.Name, evidencePath} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}
