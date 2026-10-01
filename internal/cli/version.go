package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nexutils/StackGuard/internal/version"
)

func newVersionCommand(a *app) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := version.Get()
			switch format {
			case "json":
				enc := json.NewEncoder(a.out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(info); err != nil {
					return internalError(err)
				}
			case "", "text":
				fmt.Fprintf(a.out, "stackguard %s\n", info.Version)
				if info.Commit != "" {
					fmt.Fprintf(a.out, "  commit:  %s\n", info.Commit)
				}
				if info.Date != "" {
					fmt.Fprintf(a.out, "  built:   %s\n", info.Date)
				}
				fmt.Fprintf(a.out, "  go:      %s\n  platform: %s\n", info.GoVersion, info.Platform)
			default:
				return usageError("unknown format %q for version (want text or json)", format)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: text or json")
	return cmd
}
