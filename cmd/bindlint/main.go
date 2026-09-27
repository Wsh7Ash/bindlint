// Command bindlint is an offline DNS zone-file parser and RFC-aware linter.
package main

import (
	"os"

	"github.com/Wsh7Ash/bindlint/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
