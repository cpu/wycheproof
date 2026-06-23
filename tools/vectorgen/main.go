// vectorgen is the CLI for adding to and regenerating Wycheproof test vectors.
//
// Requires GOEXPERIMENT=jsonv2 to build.
//
// Subcommands:
//
//	fmt     [--check] <glob>...   Format vector files (or check formatting).
//	lint    [flags]               Validate vector files against their schemas.
//	add     [flags]               Append a group, or append into an existing group.
//	update  [flags]               Patch existing tests in place.
//	replace [flags]               Swap a whole group for a fresh one in place.
package main

import (
	"fmt"
	"io"
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
	case "lint":
		os.Exit(runLint(args))
	case "add":
		os.Exit(runAdd(args))
	case "update":
		os.Exit(runUpdate(args))
	case "replace":
		os.Exit(runReplace(args))
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
  vectorgen fmt     [--check] <glob>...
  vectorgen lint    [flags]
  vectorgen add     --vectors <file> --input <envelope>|- [flags]
  vectorgen update  --vectors <glob> --input <envelope>|- [flags]
  vectorgen replace --vectors <file> --source <name>[@<v>] --input <envelope>|- [flags]

Subcommands:
  fmt      Normalize formatting of vector JSON files in place.
           With --check, exit non-zero if any file would be modified.
  lint     Validate vector files against their declared schemas and
           structural invariants.
  add      Append a new test group, or new tests into an existing group,
           per an envelope JSON. Pass --create to allow creating new files.
  update   Patch existing tests in place across one or more files, matching
           tests by tcId within source-filtered groups.
  replace  Swap the single group matching --source for a fresh group from the
           envelope, preserving the original group's position in the file.

Glob patterns for fmt and update are expanded with Go's filepath.Glob
(shell-style, no recursion).
`)
}

// readEnvelope reads an envelope JSON from path, or from stdin if path is "-".
func readEnvelope(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}
