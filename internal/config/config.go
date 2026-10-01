// Package config defines StackGuard's project configuration (.stackguard.yaml).
//
// This package only holds the schema and its validation. Reading the file,
// environment variables and flags is done by the CLI (via Viper), so the
// engine and other front-ends never depend on how configuration was sourced.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
)

// FileNames are the config file names searched for, in order.
var FileNames = []string{".stackguard.yaml", ".stackguard.yml"}

// FailNever disables failing on findings.
const FailNever = "none"

// Config is the user-facing configuration.
type Config struct {
	// DisabledRules lists rule IDs that are never evaluated.
	DisabledRules []string `mapstructure:"disabled_rules" yaml:"disabled_rules,omitempty"`
	// EnabledRules turns on rules that are off by default (organisation-specific
	// conventions). DisabledRules wins if a rule is in both.
	EnabledRules []string `mapstructure:"enabled_rules" yaml:"enabled_rules,omitempty"`
	// SeverityOverrides maps rule IDs to a replacement severity.
	SeverityOverrides map[string]string `mapstructure:"severity_overrides" yaml:"severity_overrides,omitempty"`
	// Exclude holds glob patterns of paths to skip, relative to each scan root.
	Exclude []string `mapstructure:"exclude" yaml:"exclude,omitempty"`
	// RulesDirs are extra directories of rule files, relative to the config file.
	RulesDirs []string `mapstructure:"rules_dirs" yaml:"rules_dirs,omitempty"`
	// Targets restricts scanning to these targets.
	Targets []string `mapstructure:"targets" yaml:"targets,omitempty"`
	// FailOn is the minimum severity that makes `scan` exit non-zero, or "none".
	FailOn string `mapstructure:"fail_on" yaml:"fail_on,omitempty"`
	// MinScore makes `scan` and `score` exit non-zero below this score.
	MinScore int `mapstructure:"min_score" yaml:"min_score,omitempty"`
	// Format is the default output format.
	Format string `mapstructure:"format" yaml:"format,omitempty"`
}

// Default returns the configuration used when nothing is configured.
func Default() Config {
	return Config{FailOn: models.SeverityError.String(), Format: "console"}
}

// Resolved is a validated Config with parsed values.
type Resolved struct {
	Config
	SeverityOverrides map[string]models.Severity
	// FailOn is nil when failing on findings is disabled.
	FailOn *models.Severity
}

// Resolve validates the configuration. Rule IDs are normalised to upper case
// (Viper lower-cases map keys).
func (c Config) Resolve() (Resolved, error) {
	r := Resolved{Config: c, SeverityOverrides: map[string]models.Severity{}}
	r.DisabledRules = upperAll(c.DisabledRules)
	r.EnabledRules = upperAll(c.EnabledRules)
	for id, s := range c.SeverityOverrides {
		sev, err := models.ParseSeverity(s)
		if err != nil {
			return r, fmt.Errorf("severity_overrides.%s: %w", strings.ToUpper(id), err)
		}
		r.SeverityOverrides[strings.ToUpper(id)] = sev
	}
	switch strings.ToLower(strings.TrimSpace(c.FailOn)) {
	case "", FailNever, "never":
	default:
		sev, err := models.ParseSeverity(c.FailOn)
		if err != nil {
			return r, fmt.Errorf("fail_on: %w (or %q)", err, FailNever)
		}
		r.FailOn = &sev
	}
	if c.MinScore < 0 || c.MinScore > 100 {
		return r, fmt.Errorf("min_score must be between 0 and 100, got %d", c.MinScore)
	}
	return r, nil
}

func upperAll(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strings.ToUpper(strings.TrimSpace(id))
	}
	return out
}

// Find searches dir and its parents for a config file, stopping at the
// repository root (a directory containing .git) or the filesystem root.
// It returns "" when none is found.
func Find(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		for _, name := range FileNames {
			p := filepath.Join(dir, name)
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
