package cli

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nexutils/StackGuard/internal/models"
)

func newRulesCommand(a *app) *cobra.Command {
	var (
		targets    []string
		categories []string
		severity   string
		format     string
		rulesDir   []string
		validate   bool
	)
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List available rules",
		Example: `  stackguard rules
  stackguard rules --target compose --category security
  stackguard rules --severity warning --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, baseDir, err := a.loadConfig(cmd)
			if err != nil {
				return err
			}
			set, err := a.loadRules(cfg, baseDir, rulesDir)
			if err != nil {
				return err
			}
			if validate {
				fmt.Fprintf(a.out, "✓ %d rules are valid\n", set.Len())
				return nil
			}

			var minSev *models.Severity
			if severity != "" {
				s, err := models.ParseSeverity(severity)
				if err != nil {
					return usageError("--severity: %v", err)
				}
				minSev = &s
			}

			type row struct {
				*models.Rule
				Disabled     bool `json:"disabled"`
				OffByDefault bool `json:"off_by_default"`
			}
			var rows []row
			for _, r := range set.All() {
				cp := *r
				cp.Severity = effectiveSeverity(r, cfg)
				switch {
				case len(targets) > 0 && !slices.Contains(targets, cp.Target):
					continue
				case len(categories) > 0 && !slices.Contains(categories, cp.Category):
					continue
				case minSev != nil && cp.Severity < *minSev:
					continue
				}
				rows = append(rows, row{Rule: &cp, Disabled: slices.Contains(cfg.DisabledRules, r.ID), OffByDefault: r.OffByDefault})
			}

			switch format {
			case "json":
				if rows == nil {
					rows = []row{}
				}
				enc := json.NewEncoder(a.out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rows); err != nil {
					return internalError(err)
				}
			case "", "table":
				tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tTARGET\tTITLE")
				for _, r := range rows {
					title := r.Title
					if r.Disabled {
						title += " (disabled)"
					} else if r.OffByDefault {
						title += " (off by default)"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Category, r.Target, title)
				}
				if err := tw.Flush(); err != nil {
					return internalError(err)
				}
				fmt.Fprintf(a.out, "\n%d rules\n", len(rows))
			default:
				return usageError("unknown format %q for rules (want table or json)", format)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringSliceVar(&targets, "target", nil, "only list rules for these targets")
	fl.StringSliceVar(&categories, "category", nil, "only list rules in these categories ("+strings.Join(models.Categories, ", ")+")")
	fl.StringVar(&severity, "severity", "", "only list rules at or above this severity")
	fl.StringVarP(&format, "format", "f", "table", "output format: table or json")
	fl.StringSliceVar(&rulesDir, "rules-dir", nil, "extra directory of rule files (repeatable)")
	fl.BoolVar(&validate, "validate", false, "validate all rules and exit (non-zero on errors)")
	return cmd
}
