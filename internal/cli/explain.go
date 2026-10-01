package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newExplainCommand(a *app) *cobra.Command {
	var (
		format   string
		rulesDir []string
	)
	cmd := &cobra.Command{
		Use:     "explain RULE_ID",
		Short:   "Show details and remediation for a rule",
		Example: `  stackguard explain COMP_SEC_001`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, baseDir, err := a.loadConfig(cmd)
			if err != nil {
				return err
			}
			set, err := a.loadRules(cfg, baseDir, rulesDir)
			if err != nil {
				return err
			}
			rule, ok := set.Get(args[0])
			if !ok {
				return usageError("unknown rule %q; run 'stackguard rules' to list rules", args[0])
			}
			r := *rule
			r.Severity = effectiveSeverity(rule, cfg)

			if format == "json" {
				enc := json.NewEncoder(a.out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(r); err != nil {
					return internalError(err)
				}
				return nil
			}
			if format != "" && format != "text" {
				return usageError("unknown format %q for explain (want text or json)", format)
			}

			w := bufio.NewWriter(a.out)
			fmt.Fprintf(w, "%s · %s\n\n", r.ID, r.Title)
			target := r.Target
			if len(r.Resources) > 0 {
				target += " (" + strings.Join(r.Resources, ", ") + ")"
			}
			fmt.Fprintf(w, "  Severity:  %s\n  Category:  %s\n  Target:    %s\n  Source:    %s\n", r.Severity, r.Category, target, r.Source)
			if len(r.Tags) > 0 {
				fmt.Fprintf(w, "  Tags:      %s\n", strings.Join(r.Tags, ", "))
			}
			section(w, "Description", r.Description)
			section(w, "Remediation", r.Remediation)
			if len(r.References) > 0 {
				fmt.Fprintf(w, "\nReferences\n")
				for _, ref := range r.References {
					fmt.Fprintf(w, "  - %s\n", ref)
				}
			}
			section(w, "Query", r.QueryYAML)
			return w.Flush()
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: text or json")
	cmd.Flags().StringSliceVar(&rulesDir, "rules-dir", nil, "extra directory of rule files (repeatable)")
	return cmd
}

func section(w *bufio.Writer, title, body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	fmt.Fprintf(w, "\n%s\n", title)
	for _, line := range strings.Split(body, "\n") {
		fmt.Fprintf(w, "  %s\n", line)
	}
}
