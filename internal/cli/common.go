package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nexutils/StackGuard/internal/config"
	"github.com/nexutils/StackGuard/internal/loader"
	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser/all"
	"github.com/nexutils/StackGuard/rules"
)

// envHome overrides the StackGuard home directory (default ~/.stackguard).
const envHome = "STACKGUARD_HOME"

// flagBinding maps a config key to a command flag. Bound flags override the
// config file and environment when set explicitly.
type flagBinding struct {
	key  string
	flag string
}

// loadConfig reads defaults, the config file, STACKGUARD_* environment
// variables and bound flags, in increasing order of precedence.
func (a *app) loadConfig(cmd *cobra.Command, bindings ...flagBinding) (config.Resolved, string, error) {
	v := viper.New()
	def := config.Default()
	// Every key needs a default so AutomaticEnv can resolve it.
	v.SetDefault("disabled_rules", []string{})
	v.SetDefault("enabled_rules", []string{})
	v.SetDefault("severity_overrides", map[string]string{})
	v.SetDefault("exclude", []string{})
	v.SetDefault("rules_dirs", []string{})
	v.SetDefault("targets", []string{})
	v.SetDefault("fail_on", def.FailOn)
	v.SetDefault("min_score", def.MinScore)
	v.SetDefault("format", def.Format)
	v.SetDefault("profile", "")

	v.SetEnvPrefix("STACKGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	file := a.cfgFile
	if file == "" {
		if wd, err := os.Getwd(); err == nil {
			file = config.Find(wd)
		}
	}
	if file != "" {
		v.SetConfigFile(file)
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			return config.Resolved{}, "", usageError("reading config %s: %v", file, err)
		}
		a.log.Debug("loaded config", "file", file)
	}

	for _, b := range bindings {
		if f := cmd.Flags().Lookup(b.flag); f != nil {
			if err := v.BindPFlag(b.key, f); err != nil {
				return config.Resolved{}, "", internalError(err)
			}
		}
	}

	var cfg config.Config
	if err := v.UnmarshalExact(&cfg); err != nil {
		return config.Resolved{}, "", usageError("invalid configuration: %v", err)
	}
	res, err := cfg.Resolve()
	if err != nil {
		return config.Resolved{}, "", usageError("invalid configuration: %v", err)
	}

	baseDir := ""
	if file != "" {
		baseDir = filepath.Dir(file)
	}
	return res, baseDir, nil
}

// loadRules loads embedded rules plus local override layers.
func (a *app) loadRules(cfg config.Resolved, baseDir string, extraDirs []string) (*loader.RuleSet, error) {
	layers := []loader.Layer{{Name: "embedded", FS: rules.FS, Embedded: true}}

	home := os.Getenv(envHome)
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".stackguard")
		}
	}
	if home != "" {
		if l, ok := loader.DirLayer("user", filepath.Join(home, "rules")); ok {
			layers = append(layers, l)
		}
	}

	project := baseDir
	if project == "" {
		project, _ = os.Getwd()
	}
	if l, ok := loader.DirLayer("project", filepath.Join(project, ".stackguard", "rules")); ok {
		layers = append(layers, l)
	}

	for _, d := range cfg.RulesDirs {
		if !filepath.IsAbs(d) && baseDir != "" {
			d = filepath.Join(baseDir, d)
		}
		l, ok := loader.DirLayer("config", d)
		if !ok {
			return nil, usageError("rules directory %s does not exist", d)
		}
		layers = append(layers, l)
	}
	for _, d := range extraDirs {
		l, ok := loader.DirLayer("flag", d)
		if !ok {
			return nil, usageError("rules directory %s does not exist", d)
		}
		layers = append(layers, l)
	}

	for _, l := range layers[1:] {
		a.log.Debug("loading rules layer", "name", l.Name, "dir", l.Root)
	}
	set, err := loader.Load(loader.Options{KnownTargets: all.Registry().Names()}, layers...)
	if err != nil {
		var ve *loader.ValidationError
		if errors.As(err, &ve) {
			return nil, usageError("%v", err)
		}
		return nil, internalError(err)
	}
	a.warnUnknownRuleIDs(set, cfg)
	return set, nil
}

// warnUnknownRuleIDs flags config entries for rules that do not exist, which
// usually means a typo or a renamed rule. It warns instead of failing so a
// stale config does not break CI.
func (a *app) warnUnknownRuleIDs(set *loader.RuleSet, cfg config.Resolved) {
	for _, id := range cfg.DisabledRules {
		if _, ok := set.Get(id); !ok {
			a.log.Warn("disabled_rules references an unknown rule", "rule", id)
		}
	}
	for id := range cfg.SeverityOverrides {
		if _, ok := set.Get(id); !ok {
			a.log.Warn("severity_overrides references an unknown rule", "rule", id)
		}
	}
	for _, id := range cfg.EnabledRules {
		if _, ok := set.Get(id); !ok {
			a.log.Warn("enabled_rules references an unknown rule", "rule", id)
		}
	}
}

// colorEnabled decides whether to emit ANSI colors on w.
func (a *app) colorEnabled(w any) bool {
	if a.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}

// effectiveSeverity applies config overrides for display purposes.
func effectiveSeverity(r *models.Rule, cfg config.Resolved) models.Severity {
	if s, ok := cfg.SeverityOverrides[r.ID]; ok {
		return s
	}
	return r.Severity
}
