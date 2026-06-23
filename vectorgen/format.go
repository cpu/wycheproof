// Package vectorgen provides primitives for adding to and regenerating
// Wycheproof test vector files while preserving field order and producing
// minimal diffs.
//
// This package requires the GOEXPERIMENT=jsonv2 build experiment.
package vectorgen

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckFormatFile reports whether path is already in canonical formatted form.
// It does not modify the file, use FormatFile for that.
func CheckFormatFile(path string) (bool, error) {
	orig, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	out, err := FormatBytes(orig)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}

	return bytes.Equal(orig, out), nil
}

// FormatFile reads path and formats its contents.
//
// It writes the result back atomically only if the content changed.
// It returns true if the file was modified.
//
// Use CheckFormatFile to check for formatting consistency without making
// changes.
func FormatFile(path string) (bool, error) {
	orig, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	out, err := FormatBytes(orig)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	if bytes.Equal(orig, out) {
		return false, nil
	}
	if err := writeAtomic(path, out); err != nil {
		return false, err
	}

	return true, nil
}

// FormatBytes returns the canonical formatted form of a Wycheproof JSON vector
// file's contents. The output ends with a trailing newline.
//
// Formatting preserves existing object key order and the raw byte form of
// scalar values (numbers, strings) — only whitespace is normalized.
func FormatBytes(in []byte) ([]byte, error) {
	in = bytes.TrimRight(in, "\n")
	v := jsontext.Value(append([]byte(nil), in...))
	if err := v.Format([]jsontext.Options{
		jsontext.Multiline(true),
		jsontext.WithIndent("  "),
		jsontext.SpaceAfterColon(true),
		jsontext.PreserveRawStrings(true),
		jsontext.CanonicalizeRawInts(false),
		jsontext.CanonicalizeRawFloats(false),
	}...); err != nil {
		return nil, fmt.Errorf("formatting JSON: %w", err)
	}

	return append([]byte(v), '\n'), nil
}

// FormatSkipped reports whether path matches a file pattern that is exempt
// from canonical formatting.
//
// Currently only the aes_ff1_radix*_test.json files are exempt: they contain
// integer-list "msg" and "ct" inputs which the formatter would expand to one
// element per line, ballooning these files. No other vectors in the tree have
// this shape, so the carve-out is intentionally narrow.
func FormatSkipped(path string) bool {
	return strings.HasPrefix(filepath.Base(path), "aes_ff1_radix")
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".vectorgen-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }

	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}

	return nil
}
