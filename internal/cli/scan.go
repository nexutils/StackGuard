package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nexutils/StackGuard/internal/config"
	"github.com/nexutils/StackGuard/internal/engine"
	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/reporters"
	reporterall "github.com/nexutils/StackGuard/internal/reporters/all"
	"github.com/nexutils/StackGuard/internal/version"
)

// scanFlags are shared by `scan` and `score`.
type scanFlags struct {
	targets  []string
	disable  []string
	enable   []string
	exclude  []string
	rulesDir []string
	jobs     int
	minScore int
}

func (f *scanFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringSliceVar(&f.targets, "target", nil, "only scan these targets (e.g. compose,kubernetes)")
	fl.StringSliceVar(&f.disable, "disable", nil, "rule IDs to disable (added to disabled_rules)")
	fl.StringSliceVar(&f.enable, "enable", nil, "off-by-default rule IDs to enable (added to enabled_rules)")
	fl.StringSliceVar(&f.exclude, "exclude", nil, "glob patterns to exclude (added to exclude)")
	fl.StringSliceVar(&f.rulesDir, "rules-dir", nil, "extra directory of rule files (repeatable)")
	fl.IntVarP(&f.jobs, "jobs", "j", 0, "parallel parsers (default: number of CPUs)")
	fl.IntVar(&f.minScore, "min-score", 0, "exit with code 1 if the score is below this value")
}

var scanBindings = []flagBinding{
	{key: "targets", flag: "target"},
	{key: "min_score", flag: "min-score"},
	{key: "fail_on", flag: "fail-on"},
	{key: "format", flag: "format"},
	{key: "profile", flag: "profile"},
}

func newScanCommand(a *app) *cobra.Command {
	var (
		sf          scanFlags
		output      string
		quiet       bool
		showPassed  bool
		omitSkipped bool
	)
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan files or directories for issues",
		Example: `  stackguard scan .
  stackguard scan docker-compose.yml k8s/
  stackguard scan . --format sarif --output stackguard.sarif
  stackguard scan . --fail-on warning --min-score 80`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, rep, err := a.runScan(cmd, &sf, args, !quiet)
			if err != nil {
				return err
			}
			if err := a.writeReport(cfg.Format, output, quiet, showPassed, omitSkipped, rep); err != nil {
				return err
			}
			return gate(cfg, rep)
		},
	}
	sf.register(cmd)
	cmd.Flags().StringP("profile", "p", "", "scan profile: quick, standard or strict (default \"standard\")")
	cmd.Flags().StringP("format", "f", "", "output format: "+strings.Join(reporterall.Formats(), ", ")+" (default \"console\")")
	cmd.Flags().String("fail-on", "", "minimum severity that fails the scan: error, warning, info or none (default \"error\")")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the report to a file instead of stdout")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "console: only print findings and the score")
	cmd.Flags().BoolVar(&showPassed, "show-passed", false, "console: list every passed rule instead of a summary")
	cmd.Flags().BoolVar(&omitSkipped, "omit-skipped", false, "json/sarif: drop rules with status skipped from the report (stats are unchanged)")
	return cmd
}

// runScan loads configuration and rules, then scans paths. When interactive is
// true and stderr is a color-capable terminal, a progress spinner is shown
// while the scan runs.
func (a *app) runScan(cmd *cobra.Command, sf *scanFlags, paths []string, interactive bool) (config.Resolved, *models.Report, error) {
	cfg, baseDir, err := a.loadConfig(cmd, scanBindings...)
	if err != nil {
		return cfg, nil, err
	}
	set, err := a.loadRules(cfg, baseDir, sf.rulesDir)
	if err != nil {
		return cfg, nil, err
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return cfg, nil, usageError("cannot scan %s: %v", p, err)
		}
	}

	var progress func(engine.ScanPhase)
	if interactive && a.colorEnabled(a.errOut) {
		sp := newSpinner(a.errOut)
		sp.start()
		defer sp.stop()
		progress = sp.update
	}

	disabled := append(append([]string{}, cfg.DisabledRules...), upper(sf.disable)...)
	enabled := append(append([]string{}, cfg.EnabledRules...), upper(sf.enable)...)
	e, err := engine.New(set.All(), engine.Options{
		Targets:           cfg.Targets,
		Profile:           cfg.Profile,
		DisabledRules:     disabled,
		EnabledRules:      enabled,
		SeverityOverrides: cfg.SeverityOverrides,
		Exclude:           append(append([]string{}, cfg.Exclude...), sf.exclude...),
		Jobs:              sf.jobs,
		Logger:            a.log,
		Progress:          progress,
	})
	if err != nil {
		return cfg, nil, usageError("%v", err)
	}
	rep, err := e.Scan(cmd.Context(), paths)
	if err != nil {
		return cfg, nil, internalError(err)
	}
	a.log.Debug("scan complete",
		"files", rep.Stats.FilesParsed, "resources", rep.Stats.Resources,
		"findings", len(rep.Findings), "duration_ms", rep.Stats.DurationMillis)
	return cfg, rep, nil
}

func (a *app) writeReport(format, output string, quiet, showPassed, omitSkipped bool, rep *models.Report) error {
	var (
		w     io.Writer = a.out
		color           = a.colorEnabled(a.out)
	)
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return internalError(err)
		}
		defer f.Close()
		w, color = f, false
	}
	r, err := reporterall.New(format, reporters.Options{
		Color:       color,
		Quiet:       quiet,
		ShowPassed:  showPassed,
		OmitSkipped: omitSkipped,
		ToolVersion: version.Get().Version,
	})
	if err != nil {
		return usageError("%v", err)
	}
	if err := r.Report(w, rep); err != nil {
		return internalError(fmt.Errorf("writing report: %w", err))
	}
	return nil
}

// gate turns findings and score thresholds into an exit code.
func gate(cfg config.Resolved, rep *models.Report) error {
	if cfg.FailOn != nil {
		for _, f := range rep.Findings {
			if f.Severity >= *cfg.FailOn {
				return &exitError{code: ExitFindings}
			}
		}
	}
	if cfg.MinScore > 0 && rep.Score.Total < cfg.MinScore {
		return &exitError{code: ExitFindings}
	}
	return nil
}

func upper(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToUpper(strings.TrimSpace(s))
	}
	return out
}
