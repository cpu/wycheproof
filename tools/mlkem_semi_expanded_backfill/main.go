// mlkem_semi_expanded_backfill adds the ek and (where derivable) K fields to
// each test case in mlkem_*_semi_expanded_decaps_test.json. We use
// cloudflare/circl instead of the Go stdlib ML-KEM to support ML-KEM-512
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func main() {
	root := flag.String("root", ".", "wycheproof repo root")
	dryRun := flag.Bool("dry-run", false, "print intended changes without writing files")
	flag.Parse()

	for _, ps := range paramSets {
		path := filepath.Join(*root, ps.file)
		log.Printf("Processing %s (%s)", ps.name, path)
		if err := process(path, ps, *dryRun); err != nil {
			log.Fatalf("  failed: %v", err)
		}
	}
}

func process(path string, ps paramSet, dryRun bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f testFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	for gi := range f.TestGroups {
		g := &f.TestGroups[gi]
		if g.ParameterSet != ps.name {
			return fmt.Errorf("group %d parameterSet=%q, want %q", gi, g.ParameterSet, ps.name)
		}
		for ti := range g.Tests {
			t := &g.Tests[ti]
			if err := backfillCase(t, ps); err != nil {
				return fmt.Errorf("tcId %d: %w", t.TcId, err)
			}
		}
	}

	out, err := marshalIndent(&f)
	if err != nil {
		return err
	}
	if dryRun {
		fmt.Println(string(out))
		return nil
	}

	return os.WriteFile(path, out, 0o644)
}

func backfillCase(t *testCase, ps paramSet) error {
	dk, err := hex.DecodeString(t.Dk)
	if err != nil {
		return fmt.Errorf("decode dk: %w", err)
	}
	c, err := hex.DecodeString(t.C)
	if err != nil {
		return fmt.Errorf("decode c: %w", err)
	}

	if len(dk) >= ps.dkPKESize+ps.ekSize {
		t.Ek = hex.EncodeToString(dk[ps.dkPKESize : ps.dkPKESize+ps.ekSize])
	} else {
		return fmt.Errorf("dk too short (%d bytes) to extract ek (need %d)", len(dk), ps.dkPKESize+ps.ekSize)
	}

	if len(c) != ps.ctSize {
		log.Printf("  tcId %d: ct len %d != %d, skipping K", t.TcId, len(c), ps.ctSize)
		return nil
	}

	sk := ps.newKey()
	if err := sk.Unpack(dk); err != nil {
		log.Printf("  tcId %d: dk Unpack rejected (%v), skipping K", t.TcId, err)
		return nil
	}
	ss := make([]byte, 32)
	sk.DecapsulateTo(ss, c)
	t.K = hex.EncodeToString(ss)

	log.Printf("  tcId %d: K=%s", t.TcId, t.K)
	return nil
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

var paramSets = []paramSet{
	{
		name: "ML-KEM-512", file: "testvectors_v1/mlkem_512_semi_expanded_decaps_test.json",
		dkPKESize: 768, ekSize: 800, dkTotalSize: 1632, ctSize: 768,
		newKey: func() circlKey { return &mlkem512.PrivateKey{} },
	},
	{
		name: "ML-KEM-768", file: "testvectors_v1/mlkem_768_semi_expanded_decaps_test.json",
		dkPKESize: 1152, ekSize: 1184, dkTotalSize: 2400, ctSize: 1088,
		newKey: func() circlKey { return &mlkem768.PrivateKey{} },
	},
	{
		name: "ML-KEM-1024", file: "testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json",
		dkPKESize: 1536, ekSize: 1568, dkTotalSize: 3168, ctSize: 1568,
		newKey: func() circlKey { return &mlkem1024.PrivateKey{} },
	},
}

type paramSet struct {
	name        string
	file        string
	dkPKESize   int
	ekSize      int
	dkTotalSize int
	ctSize      int
	newKey      func() circlKey
}

type circlKey interface {
	Unpack([]byte) error
	DecapsulateTo(ss, ct []byte)
}

type testFile struct {
	Algorithm     string          `json:"algorithm"`
	Schema        string          `json:"schema"`
	NumberOfTests int             `json:"numberOfTests"`
	Header        json.RawMessage `json:"header,omitempty"`
	Notes         json.RawMessage `json:"notes,omitempty"`
	TestGroups    []testGroup     `json:"testGroups"`
}

type testGroup struct {
	Type         string          `json:"type"`
	Source       json.RawMessage `json:"source"`
	ParameterSet string          `json:"parameterSet"`
	Tests        []testCase      `json:"tests"`
}

type testCase struct {
	TcId    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Dk      string   `json:"dk"`
	C       string   `json:"c"`
	Ek      string   `json:"ek"`
	K       string   `json:"K,omitempty"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}
