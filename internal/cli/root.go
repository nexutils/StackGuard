// Package cli implements the stackguard command line. It is the only package
// that knows about Cobra, Viper, flags and process exit codes.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// app holds state shared by all commands.
type app struct {
	out, errOut io.Writer

	cfgFile   string
	logLevel  string
	logFormat string
	verbose   bool
	noColor   bool

	log *slog.Logger
}

// Execute runs the CLI with the process's arguments and returns the exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

// Run executes the CLI with explicit arguments and streams. It is the entry
// point used by tests.
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	root := NewRootCommand(out, errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintln(errOut, "Error:", ee.err)
		}
		return ee.code
	}
	// Errors from Cobra itself (unknown command, bad arguments).
	fmt.Fprintln(errOut, "Error:", err)
	return ExitUsage
}

// NewRootCommand builds the command tree.
func NewRootCommand(out, errOut io.Writer) *cobra.Command {
	a := &app{out: out, errOut: errOut}

	root := &cobra.Command{
		Use:   "stackguard",
		Short: "Scan infrastructure and deployment configuration for production-readiness issues",
		Long: `StackGuard scans Docker Compose, Dockerfiles, Kubernetes, Helm, Terraform,
GitHub Actions, Jenkins, Ansible and nginx configuration for security,
reliability, operational and maintainability issues.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.setupLogging()
		},
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return usageError("%v\nRun '%s --help' for usage.", err, c.CommandPath())
	})

	pf := root.PersistentFlags()
	pf.StringVar(&a.cfgFile, "config", "", "config file (default: .stackguard.yaml in the current directory or a parent)")
	pf.StringVar(&a.logLevel, "log-level", "warn", "log level: debug, info, warn, error")
	pf.StringVar(&a.logFormat, "log-format", "text", "log format: text or json")
	pf.BoolVarP(&a.verbose, "verbose", "v", false, "verbose logging (same as --log-level debug)")
	pf.BoolVar(&a.noColor, "no-color", false, "disable colored output")

	root.AddCommand(
		newScanCommand(a),
		newScoreCommand(a),
		newRulesCommand(a),
		newExplainCommand(a),
		newVersionCommand(a),
	)
	return root
}

func (a *app) setupLogging() error {
	level := slog.LevelWarn
	if a.verbose {
		level = slog.LevelDebug
	} else if err := level.UnmarshalText([]byte(a.logLevel)); err != nil {
		return usageError("invalid --log-level %q", a.logLevel)
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch strings.ToLower(a.logFormat) {
	case "text":
		h = slog.NewTextHandler(a.errOut, opts)
	case "json":
		h = slog.NewJSONHandler(a.errOut, opts)
	default:
		return usageError("invalid --log-format %q (want text or json)", a.logFormat)
	}
	a.log = slog.New(h)
	return nil
}
