// vectorgen is the CLI for adding to and regenerating Wycheproof test vectors.
//
// Requires GOEXPERIMENT=jsonv2 to build.
//
// Subcommands:
//
//	fmt [--check] <glob>...   Format vector files (or check formatting).
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "fmt":
		os.Exit(runFmt(args))
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "vectorgen: unknown subcommand %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `vectorgen — Wycheproof test vector tooling

Usage:
  vectorgen fmt [--check] <glob>...

Subcommands:
  fmt    Normalize formatting of vector JSON files in place.
         With --check, exit non-zero if any file would be modified.

Glob patterns are expanded with Go's filepath.Glob (shell-style, no recursion).
`)
}
