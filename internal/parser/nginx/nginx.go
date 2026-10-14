// Package nginx parses nginx configuration into a single "nginx" resource that
// models the whole config after include resolution and directive inheritance.
//
// Directive values are their arguments joined by single spaces. Raw contexts
// expose each directive as a list of occurrences (`x[*]`); computed `effective`
// values expose the value after inheritance. The property model is:
//
//	main.<d> / events.<d> / http.<d>   top-level, events and http directives
//	servers[*]                         every server block, with server_name[*],
//	                                   listen[*], tls, redirect_only,
//	                                   internal_only, locations[*], effective.<d>
//	leaves[*]                          every location plus serverless servers -
//	                                   the contexts that answer requests - with
//	                                   effective.<d>, effective.headers[*],
//	                                   proxied, proxy_target_is_upstream, path
//	upstreams[*]                       name, server[*], health_check
//	log_targets[*]                     access_log / error_log destinations
//	meta.<key>                         "# @key: value" comment annotations
//	context.in_vcs / files[*] / logrotate   best-effort host/repo signals
//
// The directive tree (ParseConfig) is built first; model.go turns it into the
// resource. effective.<d> is the innermost value down http -> server ->
// location; add_header/proxy_set_header follow nginx's non-inheritance rule.
package nginx

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

const Target = "nginx"

var blockHead = regexp.MustCompile(`(?m)^\s*(http|server|events|upstream|location)\b[^;{]*\{`)

// Parser implements parser.Parser for nginx configuration.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	base := strings.ToLower(f.Base())
	if base == "nginx.conf" {
		return true
	}
	if f.Ext() != ".conf" {
		return false
	}
	return strings.Contains(strings.ToLower(f.SlashPath()), "nginx") || blockHead.Match(f.Head())
}

// Directive is a parsed nginx directive, possibly with a block.
type Directive struct {
	Name     string
	Args     []string
	Line     int
	Block    []*Directive
	HasBlock bool
}

func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	dirs, err := ParseConfig(string(src.Content))
	if err != nil {
		return nil, err
	}
	if src.Path != "" {
		dirs = resolveIncludes(dirs, filepath.Dir(src.Path), 0)
	}
	return []models.Resource{buildModel(dirs, src.Path, src.Content)}, nil
}

// ParseConfig parses nginx configuration text into a directive tree.
func ParseConfig(text string) ([]*Directive, error) {
	toks, err := lex(text)
	if err != nil {
		return nil, err
	}
	p := &cfgParser{toks: toks}
	dirs, err := p.block(false)
	if err != nil {
		return nil, err
	}
	return dirs, nil
}

type tokKind int

const (
	tWord tokKind = iota
	tSemi
	tOpen
	tClose
)

type token struct {
	kind tokKind
	text string
	line int
}

// lex tokenises nginx configuration: words (bare or quoted), ';', '{', '}'.
// Comments run from '#' to end of line.
func lex(s string) ([]token, error) {
	var toks []token
	line := 1
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case '\n':
			line++
			i++
		case ' ', '\t', '\r':
			i++
		case '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case ';':
			toks = append(toks, token{tSemi, ";", line})
			i++
		case '{':
			toks = append(toks, token{tOpen, "{", line})
			i++
		case '}':
			toks = append(toks, token{tClose, "}", line})
			i++
		case '"', '\'':
			start := line
			var b strings.Builder
			j := i + 1
			for ; j < len(s) && s[j] != c; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				if s[j] == '\n' {
					line++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, fmt.Errorf("line %d: unterminated quoted string", start)
			}
			toks = append(toks, token{tWord, b.String(), start})
			i = j + 1
		default:
			j := i
			for j < len(s) {
				ch := s[j]
				if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '{' || ch == '}' {
					break
				}
				// A '{' directly after '$' is part of a variable like ${var}.
				if ch == '$' && j+1 < len(s) && s[j+1] == '{' {
					if end := strings.IndexByte(s[j:], '}'); end > 0 {
						j += end + 1
						continue
					}
				}
				j++
			}
			toks = append(toks, token{tWord, s[i:j], line})
			i = j
		}
	}
	return toks, nil
}

type cfgParser struct {
	toks []token
	pos  int
}

func (p *cfgParser) block(nested bool) ([]*Directive, error) {
	var dirs []*Directive
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		switch t.kind {
		case tClose:
			if !nested {
				return nil, fmt.Errorf("line %d: unexpected '}'", t.line)
			}
			p.pos++
			return dirs, nil
		case tSemi:
			p.pos++ // stray semicolon
			continue
		case tOpen:
			return nil, fmt.Errorf("line %d: unexpected '{'", t.line)
		}

		d := &Directive{Name: t.text, Line: t.line}
		p.pos++
	args:
		for {
			if p.pos >= len(p.toks) {
				return nil, fmt.Errorf("line %d: directive %q is not terminated", d.Line, d.Name)
			}
			a := p.toks[p.pos]
			switch a.kind {
			case tWord:
				d.Args = append(d.Args, a.text)
				p.pos++
			case tSemi:
				p.pos++
				break args
			case tOpen:
				p.pos++
				child, err := p.block(true)
				if err != nil {
					return nil, err
				}
				d.Block, d.HasBlock = child, true
				break args
			case tClose:
				return nil, fmt.Errorf("line %d: directive %q is missing ';'", d.Line, d.Name)
			}
		}
		dirs = append(dirs, d)
	}
	if nested {
		return nil, fmt.Errorf("unexpected end of file: missing '}'")
	}
	return dirs, nil
}
