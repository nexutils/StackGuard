// Package jenkins extracts a structural model from Jenkinsfiles.
//
// There is no Groovy parser for Go, so this is a deliberately heuristic scanner:
// it masks comments and string literals, matches braces to build a block tree,
// and walks that tree to produce one rich "jenkins" resource per file, the same
// one-resource-per-unit shape the other parsers use. See model.go for the shape
// (pipeline.*, stages[*], steps[*], agents[*], env_entries[*], libraries[*],
// strings[*], text).
package jenkins

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

const Target = "jenkins"

// Parser implements parser.Parser for Jenkinsfiles.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	base := strings.ToLower(f.Base())
	return base == "jenkinsfile" || strings.HasPrefix(base, "jenkinsfile.") || strings.HasSuffix(base, ".jenkinsfile")
}

func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	text := string(src.Content)
	code := maskNonCode(text)
	root := parseBlocks(code)

	b := &builder{text: text, code: code, lineOf: lineIndex(text), dir: filepath.Dir(src.Path)}
	props, locs := b.build(root)

	return []models.Resource{{
		Target:     Target,
		Type:       Target,
		Name:       "pipeline",
		File:       src.Path,
		Line:       1,
		Properties: props,
		Locations:  locs,
	}}, nil
}

// block is a node in the brace tree. name is the leading identifier before the
// "{" (e.g. "stage", "options", "withCredentials"); header is the whole fragment
// before it (e.g. "stage('Build')").
type block struct {
	name                                   string
	header                                 string
	headerStart, start, bodyStart, bodyEnd int
	children                               []*block
	parent                                 *block
}

// parseBlocks builds the brace tree of masked code. The root spans the file.
func parseBlocks(code string) *block {
	root := &block{bodyStart: 0, bodyEnd: len(code)}
	stack := []*block{root}
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '{':
			name, header, hs := headerFor(code, i)
			parent := stack[len(stack)-1]
			b := &block{name: name, header: header, headerStart: hs, start: i, bodyStart: i + 1, parent: parent}
			parent.children = append(parent.children, b)
			stack = append(stack, b)
		case '}':
			if len(stack) > 1 {
				b := stack[len(stack)-1]
				b.bodyEnd = i
				stack = stack[:len(stack)-1]
			}
		}
	}
	for len(stack) > 1 {
		b := stack[len(stack)-1]
		b.bodyEnd = len(code)
		stack = stack[:len(stack)-1]
	}
	return root
}

// headerFor scans backward from a "{" to recover the block's identifier and the
// full header fragment (identifier plus any (...) / [...] argument groups).
func headerFor(code string, brace int) (name, header string, headerStart int) {
	j := brace - 1
	for j >= 0 && isSpace(code[j]) {
		j--
	}
	// Skip balanced argument groups: stage('x'), withCredentials([...]), timeout(5).
	for j >= 0 && (code[j] == ')' || code[j] == ']') {
		j = matchOpenBackward(code, j) - 1
		for j >= 0 && isSpace(code[j]) {
			j--
		}
	}
	end := j
	for j >= 0 && (isIdentChar(code[j]) || code[j] == '.') {
		j--
	}
	name = strings.TrimSpace(code[j+1 : end+1])
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		name = name[dot+1:]
	}
	header = strings.TrimSpace(code[j+1 : brace])
	return name, header, j + 1
}

func matchOpenBackward(code string, close int) int {
	openCh := byte('(')
	if code[close] == ']' {
		openCh = '['
	}
	closeCh := code[close]
	depth := 0
	for i := close; i >= 0; i-- {
		switch code[i] {
		case closeCh:
			depth++
		case openCh:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return close
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// maskNonCode returns text with the contents of comments and string literals
// replaced by spaces (quotes are kept), preserving offsets. This lets simple
// regexes and brace matching ignore braces inside strings.
func maskNonCode(text string) string {
	b := []byte(text)
	n := len(b)
	blank := func(from, to int) {
		for k := from; k < to && k < n; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	for i := 0; i < n; {
		switch {
		case strings.HasPrefix(text[i:], "//"):
			j := strings.IndexByte(text[i:], '\n')
			if j < 0 {
				j = n - i
			}
			blank(i, i+j)
			i += j
		case strings.HasPrefix(text[i:], "/*"):
			j := strings.Index(text[i+2:], "*/")
			end := n
			if j >= 0 {
				end = i + 2 + j + 2
			}
			blank(i, end)
			i = end
		case strings.HasPrefix(text[i:], "'''") || strings.HasPrefix(text[i:], `"""`):
			q := text[i : i+3]
			j := strings.Index(text[i+3:], q)
			end := n
			if j >= 0 {
				end = i + 3 + j
			}
			blank(i+3, end)
			i = end + 3
		case text[i] == '\'' || text[i] == '"':
			q := text[i]
			j := i + 1
			for j < n && text[j] != q && text[j] != '\n' {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			blank(i+1, j)
			i = j + 1
		default:
			i++
		}
	}
	return string(b)
}

// matchBrace returns the index of the brace closing the one at open, or
// len(code) if unbalanced.
func matchBrace(code string, open int) int {
	depth := 0
	for i := open; i < len(code); i++ {
		switch code[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(code)
}

// lineIndex returns a function mapping byte offsets to 1-based line numbers.
func lineIndex(text string) func(int) int {
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return func(off int) int {
		lo, hi := 0, len(starts)-1
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if starts[mid] <= off {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		return lo + 1
	}
}
