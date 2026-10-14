// Package main is the entry point for the stackguard CLI.
package main

import (
	"os"

	"github.com/nexutils/StackGuard/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
