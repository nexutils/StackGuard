// Package parser defines how source files become Resources. Each supported
// technology lives in its own sub-package and implements Parser.
package parser

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nexutils/StackGuard/internal/models"
)

// HeadSize is how many leading bytes of a file are available for content
// sniffing in CanParse.
const HeadSize = 4096

// Parser converts one kind of source file into Resources.
type Parser interface {
	// Name identifies the target technology. It is used as Resource.Target
	// and as the `target` field of rules.
	Name() string
	// CanParse decides whether this parser handles the file. It should be
	// cheap: use the path first and only then f.Head().
	CanParse(f *FileInfo) bool
	// Parse converts the source into resources.
	Parse(ctx context.Context, src Source) ([]models.Resource, error)
}

// Source is the content to parse. Content may come from disk or from an
// editor buffer (LSP), so parsers must never re-read Path themselves.
type Source struct {
	Path    string
	Content []byte
}

// FileInfo describes a candidate file for detection. The head of the file is
// read lazily and at most once.
type FileInfo struct {
	Path string

	once sync.Once
	head []byte
	load func() []byte
}

// NewFileInfo returns a FileInfo backed by a file on disk.
func NewFileInfo(path string) *FileInfo {
	return &FileInfo{Path: path, load: func() []byte {
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		buf := make([]byte, HeadSize)
		n, _ := io.ReadFull(f, buf)
		return buf[:n]
	}}
}

// NewFileInfoFromBytes returns a FileInfo backed by in-memory content.
func NewFileInfoFromBytes(path string, content []byte) *FileInfo {
	return &FileInfo{Path: path, load: func() []byte {
		if len(content) > HeadSize {
			return content[:HeadSize]
		}
		return content
	}}
}

// Head returns up to HeadSize leading bytes of the file.
func (f *FileInfo) Head() []byte {
	f.once.Do(func() { f.head = f.load() })
	return f.head
}

// Base is the file name without directories.
func (f *FileInfo) Base() string { return filepath.Base(f.Path) }

// Ext is the lower-cased file extension including the dot.
func (f *FileInfo) Ext() string { return strings.ToLower(filepath.Ext(f.Path)) }

// SlashPath is the path with forward slashes, for portable matching.
func (f *FileInfo) SlashPath() string { return filepath.ToSlash(f.Path) }

// IsYAML reports whether the file has a YAML extension.
func (f *FileInfo) IsYAML() bool {
	ext := f.Ext()
	return ext == ".yml" || ext == ".yaml"
}

// IsBinary reports whether the head looks like binary data.
func (f *FileInfo) IsBinary() bool {
	return bytes.IndexByte(f.Head(), 0) >= 0
}
