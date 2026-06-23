package main_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/c2sp/wycheproof/vectorgen"
)

// TestGeneratorOutputIsValidAndStable runs the example generator end-to-end,
// asserts the produced vector file passes vectorgen.LintBytes (against the
// embedded schemas), and confirms it is byte-stable under vectorgen.FormatBytes
// (i.e. an operator running `vectorgen fmt --check` would see no diff).
func TestGeneratorOutputIsValidAndStable(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "example.json")

	cmd := exec.Command("go", "run", ".", "-o", out)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "GOEXPERIMENT=jsonv2")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generator failed: %v\n%s", err, output)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	if err := vectorgen.LintBytes(data, nil); err != nil && !errors.Is(err, vectorgen.ErrIgnoredSchema) {
		t.Errorf("output failed lint: %v", err)
	}

	formatted, err := vectorgen.FormatBytes(data)
	if err != nil {
		t.Fatalf("FormatBytes: %v", err)
	}
	if !bytes.Equal(data, formatted) {
		t.Error("output not byte-stable under FormatBytes (vectorgen fmt --check would fail)")
	}
}
