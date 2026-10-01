// Package discovery finds candidate files to scan.
package discovery

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IgnoreFile is read from each scan root; each non-comment line is a glob
// pattern excluded from the scan.
const IgnoreFile = ".stackguardignore"

// DefaultMaxFileSize is the default size above which files are skipped.
const DefaultMaxFileSize = 5 << 20

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".stackguard": true,
	"node_modules": true, "vendor": true, ".terraform": true,
	".venv": true, "venv": true, "__pycache__": true, ".idea": true,
}

// Options configures discovery.
type Options struct {
	// Exclude holds glob patterns relative to each root. `**` matches across
	// directories; a pattern without '/' matches a file or directory name at
	// any depth; a trailing '/' matches directories only.
	Exclude     []string
	MaxFileSize int64
	Logger      *slog.Logger
}

// File is a discovered file. Explicit is true when the user named the file
// directly rather than it being found by walking a directory.
type File struct {
	Path     string
	Explicit bool
}

// Discover walks roots and returns candidate files in deterministic order.
func Discover(ctx context.Context, roots []string, opts Options) ([]File, error) {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	var out []File
	seen := map[string]bool{}
	add := func(f File) {
		if key := filepath.Clean(f.Path); !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(File{Path: root, Explicit: true})
			continue
		}

		patterns := append([]string{}, opts.Exclude...)
		patterns = append(patterns, readIgnoreFile(filepath.Join(root, IgnoreFile))...)
		m, err := newMatcher(patterns)
		if err != nil {
			return nil, err
		}

		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.Warn("cannot read path", "path", path, "error", err)
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if path != root && (skipDirs[d.Name()] || m.match(rel, true)) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || m.match(rel, false) {
				return nil
			}
			if fi, err := d.Info(); err == nil && fi.Size() > opts.MaxFileSize {
				log.Debug("skipping large file", "path", path, "size", fi.Size())
				return nil
			}
			add(File{Path: path})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readIgnoreFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var pats []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			pats = append(pats, line)
		}
	}
	return pats
}

type pattern struct {
	re      *regexp.Regexp
	dirOnly bool
}

type matcher []pattern

func newMatcher(globs []string) (matcher, error) {
	var m matcher
	for _, g := range globs {
		g = strings.TrimSpace(filepath.ToSlash(g))
		if g == "" {
			continue
		}
		p := pattern{}
		if strings.HasSuffix(g, "/") {
			p.dirOnly = true
			g = strings.TrimSuffix(g, "/")
		}
		g = strings.TrimPrefix(g, "./")
		if !strings.Contains(g, "/") {
			g = "**/" + g
		}
		re, err := globToRegexp(g)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude pattern %q: %w", g, err)
		}
		p.re = re
		m = append(m, p)
	}
	return m, nil
}

func (m matcher) match(rel string, isDir bool) bool {
	for _, p := range m {
		if p.dirOnly && !isDir {
			continue
		}
		if p.re.MatchString(rel) {
			return true
		}
	}
	return false
}

// globToRegexp converts a glob with `**` support into an anchored regexp.
// A match on a directory prefix also matches everything below it.
func globToRegexp(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		c := g[i]
		switch c {
		case '*':
			if i+1 < len(g) && g[i+1] == '*' {
				i++
				if i+1 < len(g) && g[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("(?:/.*)?$")
	return regexp.Compile(b.String())
}
