// Package imageref splits container image references into their parts.
package imageref

import "strings"

// Ref is a parsed image reference such as
// "registry.example.com:5000/team/app:1.2@sha256:abc".
type Ref struct {
	Name   string
	Tag    string
	Digest string
}

// Parse splits an image reference. It does not validate the reference.
func Parse(s string) Ref {
	s = strings.TrimSpace(s)
	var r Ref
	if at := strings.IndexByte(s, '@'); at >= 0 {
		r.Digest = s[at+1:]
		s = s[:at]
	}
	lastSlash := strings.LastIndexByte(s, '/')
	if colon := strings.LastIndexByte(s, ':'); colon > lastSlash {
		r.Tag = s[colon+1:]
		s = s[:colon]
	}
	r.Name = s
	return r
}

// Properties renders the reference as a property map, omitting empty parts.
func (r Ref) Properties() map[string]any {
	m := map[string]any{"name": r.Name}
	if r.Tag != "" {
		m["tag"] = r.Tag
	}
	if r.Digest != "" {
		m["digest"] = r.Digest
	}
	return m
}
