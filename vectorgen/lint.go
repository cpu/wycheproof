package vectorgen

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/c2sp/wycheproof"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// LintOptions configures Lint.
type LintOptions struct {
	// SchemasFS is the filesystem containing schema files. If nil, the embedded
	// wycheproof.Schemas is used.
	SchemasFS fs.FS

	// VectorDirs lists directories to scan for vector files. If empty, scans
	// "testvectors_v1" on disk.
	VectorDirs []string

	// Filter, if non-nil, restricts linting to vector filenames matching the
	// regexp.
	Filter *regexp.Regexp

	// Log, if non-nil, receives a one-line message per vector processed. The
	// summary is returned in LintResults; callers can decide whether to print it.
	Log func(format string, args ...any)
}

// LintResults summarizes a Lint run.
type LintResults struct {
	Total    int
	Valid    int
	Invalid  int
	NoSchema int
	Ignored  int
}

// Lint walks the configured vector directories and validates every *.json
// vector against its declared schema and against structural invariants
// (single test-group type per file, unique tcIds, accurate numberOfTests).
//
// Returns the per-category counts. Lint itself only returns an error for
// unrecoverable I/O problems; per-vector validation failures are recorded in
// the results.
func Lint(opts LintOptions) (LintResults, error) {
	if opts.Log == nil {
		opts.Log = func(string, ...any) {}
	}
	if len(opts.VectorDirs) == 0 {
		opts.VectorDirs = []string{"testvectors_v1"}
	}

	compiler, err := newSchemaCompiler(opts.SchemasFS)
	if err != nil {
		return LintResults{}, err
	}

	var results LintResults
	for _, dir := range opts.VectorDirs {
		if err := lintDir(compiler, dir, opts.Filter, opts.Log, &results); err != nil {
			return results, err
		}
	}
	return results, nil
}

func lintDir(compiler *jsonschema.Compiler, dir string, filter *regexp.Regexp, logf func(string, ...any), results *LintResults) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		if filter != nil && !filter.MatchString(d.Name()) {
			return nil
		}

		results.Total++

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		if err := lintTestGroups(data); err != nil {
			logf("❌ %q: %s", path, err)
			results.Invalid++
			return nil
		}

		lintAgainstSchema(compiler, data, path, logf, results)
		return nil
	})
}

func lintTestGroups(data []byte) error {
	var v struct {
		NumberOfTests int `json:"numberOfTests"`
		TestGroups    []struct {
			Type  string `json:"type"`
			Tests []struct {
				TcId int `json:"tcId"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("decoding test groups: %w", err)
	}

	types := make(map[string]bool)
	for _, tg := range v.TestGroups {
		if tg.Type != "" {
			types[tg.Type] = true
		}
	}
	if len(types) > 1 {
		var names []string
		for t := range types {
			names = append(names, t)
		}
		return fmt.Errorf("multiple test group types: %v (expected only one per file)", names)
	}

	ids := make(map[int]struct{})
	for _, tg := range v.TestGroups {
		for _, t := range tg.Tests {
			if _, ok := ids[t.TcId]; ok {
				return fmt.Errorf("duplicate tcId %d", t.TcId)
			}
			ids[t.TcId] = struct{}{}
		}
	}
	if len(ids) != v.NumberOfTests {
		return fmt.Errorf("declared %d tests, found %d", v.NumberOfTests, len(ids))
	}
	return nil
}

func lintAgainstSchema(compiler *jsonschema.Compiler, data []byte, path string, logf func(string, ...any), results *LintResults) {
	var v struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		logf("❌ %q: invalid vector JSON: %s", path, err)
		results.Invalid++
		return
	}
	if v.Schema == "" {
		logf("❌ %q: no schema specified", path)
		results.NoSchema++
		return
	}
	if missingSchemas[v.Schema] {
		logf("⚠️ %q: ignoring missing schema %q", path, v.Schema)
		results.Ignored++
		return
	}

	schema, err := compiler.Compile(v.Schema)
	if err != nil {
		logf("❌ %q: invalid schema %q: %s", path, v.Schema, err)
		results.Invalid++
		return
	}

	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		logf("❌ %q: invalid vector JSON: %s", path, err)
		results.Invalid++
		return
	}
	if err := schema.Validate(instance); err != nil {
		logf("❌ %q: doesn't validate with schema: %s", path, err)
		results.Invalid++
		return
	}

	logf("✅ %q: validates with %q", path, v.Schema)
	results.Valid++
}

func newSchemaCompiler(schemasFS fs.FS) (*jsonschema.Compiler, error) {
	if schemasFS == nil {
		schemasFS = wycheproof.Schemas
	}
	compiler := jsonschema.NewCompiler()
	for _, f := range customFormats {
		compiler.RegisterFormat(&f)
	}
	compiler.AssertFormat()

	if err := fs.WalkDir(schemasFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := fs.ReadFile(schemasFS, path)
		if err != nil {
			return fmt.Errorf("read schema %s: %w", path, err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse schema %s: %w", path, err)
		}
		return compiler.AddResource(path, doc)
	}); err != nil {
		return nil, err
	}
	return compiler, nil
}

// missingSchemas names schema files referenced by existing _v1 vectors that
// have not yet been ported to schemas/. Vectors referencing these are reported
// as "ignored" rather than "invalid" until the schemas are added.
var missingSchemas = map[string]bool{
	"fpe_str_test_schema.json":                      true, // aes_ff1_base*_test.json
	"fpe_list_test_schema.json":                     true, // aes_ff1_radix*_test.json
	"ecdsa_bitcoin_verify_schema.json":              true, // ecdsa_secp256k1_sha256_bitcoin_test.json
	"pbe_test_schema.json":                          true, // pbes2_hmacsha*_aes_*_test.json
	"rsassa_pss_with_parameters_verify_schema.json": true, // rsa_pss_*_test.json
}

var customFormats = []jsonschema.Format{
	{Name: "Asn", Validate: validateHex},
	{Name: "Der", Validate: validateHex},
	{Name: "EcCurve", Validate: validateCurve},
	{Name: "HexBytes", Validate: validateHex},
	{Name: "BigInt", Validate: validateHex},
	{Name: "Pem", Validate: validatePem},
}

func validateHex(value any) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("non-string HexBytes value")
	}
	if s != strings.ToLower(s) {
		return errors.New("non-lowercase HexBytes value")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("invalid HexBytes value: %w", err)
	}
	return nil
}

func validatePem(value any) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("non-string Pem value")
	}
	if _, rest := pem.Decode([]byte(s)); len(rest) != 0 {
		return fmt.Errorf("invalid Pem value: trailing bytes %x", rest)
	}
	return nil
}

func validateCurve(value any) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("non-string EcCurve value")
	}
	if !curveNames[s] {
		return fmt.Errorf("unknown EcCurve name: %q", s)
	}
	return nil
}

var curveNames = map[string]bool{
	"edwards25519":    true,
	"curve25519":      true,
	"edwards448":      true,
	"curve448":        true,
	"secp224r1":       true,
	"secp224k1":       true,
	"secp256r1":       true,
	"secp256k1":       true,
	"sect283k1":       true,
	"sect283r1":       true,
	"secp384r1":       true,
	"sect409k1":       true,
	"sect409r1":       true,
	"secp521r1":       true,
	"sect571k1":       true,
	"sect571r1":       true,
	"P-256K":          true,
	"P-256":           true,
	"P-384":           true,
	"P-521":           true,
	"FRP256v1":        true,
	"brainpoolP224r1": true,
	"brainpoolP224t1": true,
	"brainpoolP256r1": true,
	"brainpoolP256t1": true,
	"brainpoolP320r1": true,
	"brainpoolP320t1": true,
	"brainpoolP384r1": true,
	"brainpoolP384t1": true,
	"brainpoolP512r1": true,
	"brainpoolP512t1": true,
}
