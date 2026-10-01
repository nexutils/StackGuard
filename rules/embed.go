// Package rules contains built-in rules, grouped by target in YAML files.
package rules

import "embed"

// FS contains all built-in rule files.
//
//go:embed */*.yaml
var FS embed.FS
