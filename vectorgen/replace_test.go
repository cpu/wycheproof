package vectorgen_test

import (
	"bytes"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"testing"

	"github.com/c2sp/wycheproof/vectorgen"
)

// TestReplacePreservesGroupPosition replaces the second group in a two-group
// file. The first group's bytes must remain untouched, and the replacement
// must land at the original group's position (not appended at the end).
func TestReplacePreservesGroupPosition(t *testing.T) {
	dir := "testdata/add_intogroup"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}

	groupTemplate := jsontext.Value(`{
		"type": "MLKEMDecapsValidationTest",
		"source": {"name": "github/lukaszobernig/reenc", "version": "2.0"},
		"parameterSet": "ML-KEM-512"
	}`)
	// One short test (incorrect length, will be rejected by the impl, so
	// schema validation passes without needing K).
	newTest := jsontext.Value(`{
		"comment": "synthetic replacement",
		"dk": "00",
		"ek": "00",
		"c": "00",
		"result": "invalid",
		"flags": ["IncorrectCiphertextLength"]
	}`)
	env := vectorgen.AddEnvelope{
		GroupTemplate: groupTemplate,
		Tests:         []jsontext.Value{newTest},
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	if err := vectorgen.Replace(target, env, "github/lukaszobernig/reenc", "", opts); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}

	// Position check: the reenc group should still be the second group, not
	// appended at the end. Find both source markers and confirm aws-lc comes
	// before reenc.
	awsLcIdx := bytes.Index(got, []byte(`"github/aws/aws-lc"`))
	reencIdx := bytes.Index(got, []byte(`"github/lukaszobernig/reenc"`))
	if awsLcIdx < 0 || reencIdx < 0 {
		t.Fatalf("missing source markers: awsLc=%d reenc=%d", awsLcIdx, reencIdx)
	}
	if awsLcIdx > reencIdx {
		t.Error("reenc group moved before aws-lc; replace should preserve position")
	}

	// Renumbering: with 7 aws-lc tests and 1 replacement, total = 8.
	if !bytes.Contains(got, []byte(`"numberOfTests": 8,`)) {
		t.Errorf("expected numberOfTests bumped to 8, file head:\n%s", head(got, 300))
	}
	if !bytes.Contains(got, []byte(`"tcId": 8,`)) {
		t.Error("expected new test to get tcId 8")
	}
	if bytes.Contains(got, []byte(`"tcId": 9,`)) {
		t.Error("did not expect tcId 9 — only 8 tests should remain")
	}

	// Version bump: the new group's source.version is "2.0".
	if !bytes.Contains(got, []byte(`"version": "2.0"`)) {
		t.Error("expected new group's source version 2.0 to be present")
	}
}

// TestReplaceRejectsAmbiguousSource ensures Replace refuses to silently pick
// one of multiple groups sharing the same source name.
func TestReplaceRejectsAmbiguousSource(t *testing.T) {
	file := []byte(`{
  "algorithm": "TEST",
  "schema": "rewrite_schema.json",
  "numberOfTests": 0,
  "notes": {},
  "testGroups": [
    {"type": "RewriteTest", "source": {"name": "dup", "version": "1"}, "tests": []},
    {"type": "RewriteTest", "source": {"name": "dup", "version": "2"}, "tests": []}
  ]
}
`)
	tmp := t.TempDir()
	target := filepath.Join(tmp, "ambig.json")
	if err := os.WriteFile(target, file, 0o644); err != nil {
		t.Fatal(err)
	}
	env := vectorgen.AddEnvelope{
		GroupTemplate: jsontext.Value(`{"type": "RewriteTest", "source": {"name": "dup", "version": "3"}}`),
		Tests:         []jsontext.Value{jsontext.Value(`{"tcId": 1, "value": "x"}`)},
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS("testdata/update_rewrite")}
	err := vectorgen.Replace(target, env, "dup", "", opts)
	if err == nil {
		t.Fatal("expected error for ambiguous source")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("matched 2")) {
		t.Errorf("expected ambiguity error, got: %v", err)
	}
}

// TestReplaceRejectsMetadataFields ensures Replace rejects envelopes that
// contain new-file-only metadata (catches operator confusion between add and
// replace).
func TestReplaceRejectsMetadataFields(t *testing.T) {
	dir := "testdata/add_intogroup"
	before, err := os.ReadFile(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, before, 0o644); err != nil {
		t.Fatal(err)
	}
	env := vectorgen.AddEnvelope{
		Algorithm:     "ML-KEM",
		GroupTemplate: jsontext.Value(`{"type": "X"}`),
		Tests:         []jsontext.Value{jsontext.Value(`{"comment": "x"}`)},
	}
	opts := vectorgen.Options{SchemasFS: os.DirFS(dir)}
	err = vectorgen.Replace(target, env, "github/lukaszobernig/reenc", "", opts)
	if err == nil {
		t.Fatal("expected error for metadata fields in Replace envelope")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("algorithm/schema/header")) {
		t.Errorf("expected error to mention metadata fields, got: %v", err)
	}
}

func head(b []byte, n int) string {
	if len(b) < n {
		return string(b)
	}
	return string(b[:n])
}
