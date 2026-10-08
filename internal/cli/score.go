package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newScoreCommand(a *app) *cobra.Command {
	var (
		sf     scanFlags
		format string
	)
	cmd := &cobra.Command{
		Use:   "score [path...]",
		Short: "Print the production-readiness score",
		Long: `Scan like 'stackguard scan' but print only the score.

The score starts at 100 and loses 10 points per ERROR, 3 per WARNING and
1 per INFO finding, down to a minimum of 0. With --min-score the command
exits with code 1 when the score is lower.`,
		Example: `  stackguard score .
  stackguard score . --min-score 80 --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, rep, err := a.runScan(cmd, &sf, args, true)
			if err != nil {
				return err
			}
			s := rep.Score
			switch format {
			case "json":
				enc := json.NewEncoder(a.out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(s); err != nil {
					return internalError(err)
				}
			case "", "console":
				fmt.Fprintf(a.out, "Score: %d/%d\n", s.Total, s.Max)
				fmt.Fprintf(a.out, "  %d errors, %d warnings, %d info\n", s.Errors, s.Warnings, s.Infos)
			default:
				return usageError("unknown format %q for score (want console or json)", format)
			}
			if cfg.MinScore > 0 && s.Total < cfg.MinScore {
				return &exitError{code: ExitFindings}
			}
			return nil
		},
	}
	sf.register(cmd)
	cmd.Flags().StringP("profile", "p", "", "scan profile: quick, standard or strict (default \"standard\")")
	cmd.Flags().StringVarP(&format, "format", "f", "console", "output format: console or json")
	return cmd
}
