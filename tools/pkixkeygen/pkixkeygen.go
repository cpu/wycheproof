// pkixkeygen generates PKIX key-decode test vectors (PKCS#8 PrivateKeyInfo
// and SubjectPublicKeyInfo) that exercise malformed and edge-case encodings.
//
// The schema types used below live in schema.go, generated from the JSON
// schemas by schemagen; regenerate with `go generate ./tools/pkixkeygen`.
package main

//go:generate go run ../schemagen -schemas-dir ../../schemas -output schema.go -package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var outDir = flag.String("out", "testvectors_v1", "output directory for vector files")

// goAllowList records cases where Go's x509 parser disagrees with our
// declared result for reasons we believe are a Go limitation/bug.
var goAllowList = map[goAllowKey]string{
	// Go's ParsePKCS8PrivateKey does not support the ML-DSA expanded-only or
	// "both" private-key forms; the encodings are well-formed per the draft
	// Use-of-ML-DSA-in-X.509 document.
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 2}: "expanded-only form unsupported",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 2}: "expanded-only form unsupported",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 2}: "expanded-only form unsupported",
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 3}: `"both" form unsupported`,
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 3}: `"both" form unsupported`,
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 3}: `"both" form unsupported`,

	// TODO(XXX): Consider fixing the instances below this mark.

	// Unknown version number accepted:
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 11}: "Go's ParsePKCS8PrivateKey does not validate the PKCS#8 version field",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 11}: "Go's ParsePKCS8PrivateKey does not validate the PKCS#8 version field",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 11}: "Go's ParsePKCS8PrivateKey does not validate the PKCS#8 version field",

	// Negative version number accepted:
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 33}: "Go's ParsePKCS8PrivateKey does not validate the PKCS#8 version field",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 33}: "Go's ParsePKCS8PrivateKey does not validate the PKCS#8 version field",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 33}: "Go's ParsePKCS8PrivateKey does not validate the PKCS#8 version field",

	// Go's ParsePKCS8PrivateKey does not validate the version/field combination.
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 43}: "Go's ParsePKCS8PrivateKey does not reject the v2 publicKey field when version=0",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 43}: "Go's ParsePKCS8PrivateKey does not reject the v2 publicKey field when version=0",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 43}: "Go's ParsePKCS8PrivateKey does not reject the v2 publicKey field when version=0",

	// v2-without-publicKey accepted: RFC 5958 §2 requires v2 if and only if
	// publicKey is present; Go does not enforce this.
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 44}: "Go's ParsePKCS8PrivateKey does not require the v2 publicKey field when version=1",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 44}: "Go's ParsePKCS8PrivateKey does not require the v2 publicKey field when version=1",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 44}: "Go's ParsePKCS8PrivateKey does not require the v2 publicKey field when version=1",

	// Malformed v2 publicKey accepted: Go's ParsePKCS8PrivateKey does not
	// validate the contents (or even size) of the optional publicKey field
	// for ML-DSA when the seed-form privateKey is present.
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 45}: "Go's ParsePKCS8PrivateKey does not validate the size of the v2 publicKey field",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 45}: "Go's ParsePKCS8PrivateKey does not validate the size of the v2 publicKey field",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 45}: "Go's ParsePKCS8PrivateKey does not validate the size of the v2 publicKey field",

	// Bare-SET attributes accepted: Go's ParsePKCS8PrivateKey does not
	// validate the tag of the optional attributes field.
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 47}: "Go's ParsePKCS8PrivateKey does not validate the tag of the optional attributes field",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 47}: "Go's ParsePKCS8PrivateKey does not validate the tag of the optional attributes field",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 47}: "Go's ParsePKCS8PrivateKey does not validate the tag of the optional attributes field",

	// Various trailing data not detected:
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 17}: "Go's ParsePKCS8PrivateKey does not check for trailing bytes after the outer SEQUENCE",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 17}: "Go's ParsePKCS8PrivateKey does not check for trailing bytes after the outer SEQUENCE",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 17}: "Go's ParsePKCS8PrivateKey does not check for trailing bytes after the outer SEQUENCE",
	{filename: "mldsa_44_pkcs8_decode_test.json", tcId: 31}: "Go's ParsePKCS8PrivateKey does not reject extra trailing fields inside the outer SEQUENCE",
	{filename: "mldsa_65_pkcs8_decode_test.json", tcId: 31}: "Go's ParsePKCS8PrivateKey does not reject extra trailing fields inside the outer SEQUENCE",
	{filename: "mldsa_87_pkcs8_decode_test.json", tcId: 31}: "Go's ParsePKCS8PrivateKey does not reject extra trailing fields inside the outer SEQUENCE",
	{filename: "mldsa_44_spki_decode_test.json", tcId: 19}:  "Go's ParsePKIXPublicKey does not reject extra trailing fields inside the outer SEQUENCE",
	{filename: "mldsa_65_spki_decode_test.json", tcId: 19}:  "Go's ParsePKIXPublicKey does not reject extra trailing fields inside the outer SEQUENCE",
	{filename: "mldsa_87_spki_decode_test.json", tcId: 19}:  "Go's ParsePKIXPublicKey does not reject extra trailing fields inside the outer SEQUENCE",
}

type goAllowKey struct {
	filename string
	tcId     int
}

// fileSpecs is the master catalog of test files + caseSpec generators.
var fileSpecs = []fileSpec{
	mldsaPkcs8FileSpec(mldsaParams44),
	mldsaPkcs8FileSpec(mldsaParams65),
	mldsaPkcs8FileSpec(mldsaParams87),
	mldsaSpkiFileSpec(mldsaParams44),
	mldsaSpkiFileSpec(mldsaParams65),
	mldsaSpkiFileSpec(mldsaParams87),
}

func main() {
	flag.Parse()

	for _, spec := range fileSpecs {
		if err := emitFile(spec); err != nil {
			log.Fatalf("emitting %s: %v", spec.filename, err)
		}
	}
}

func emitFile(spec fileSpec) error {
	tests := make([]PkixKeyDecodeTestVector, 0, len(spec.cases))
	for i, c := range spec.cases {
		tcId := i + 1
		der, err := c.build()
		if err != nil {
			return fmt.Errorf("case %d (%q): build: %w", tcId, c.comment, err)
		}

		// Sanity check every case against Go's x509 parser.
		if mismatch, parseErr := classifyMismatch(spec.keyType, c.result, der); mismatch != "" {
			key := goAllowKey{filename: spec.filename, tcId: tcId}
			if reason, ok := goAllowList[key]; ok {
				log.Printf("ALLOWED %s tcId=%d (%s): %s [reason: %s]", spec.filename, tcId, c.comment, mismatch, reason)
			} else {
				return fmt.Errorf("case %d (%q): %s (Go parser err=%v)", tcId, c.comment, mismatch, parseErr)
			}
		}

		tests = append(tests, PkixKeyDecodeTestVector{
			TcId:    tcId,
			Comment: c.comment,
			Encoded: hex.EncodeToString(der),
			Result:  c.result,
			Flags:   c.flags,
		})
	}

	file := PkixKeyDecodeSchemaJson{
		Algorithm:     spec.algorithm,
		Header:        spec.header,
		Notes:         spec.notes,
		NumberOfTests: len(tests),
		Schema:        PkixKeyDecodeSchemaJsonSchemaPkixKeyDecodeSchemaJson,
		TestGroups: []PkixKeyDecodeTestGroup{{
			Type:         PkixKeyDecodeTestGroupTypePkixKeyDecode,
			Source:       Source{Name: spec.sourceName, Version: spec.sourceVer},
			KeyType:      spec.keyType,
			Algorithm:    spec.algorithm,
			ParameterSet: spec.parameterSet,
			Tests:        tests,
		}},
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling vector file: %w", err)
	}
	data = append(data, '\n')

	out := filepath.Join(*outDir, spec.filename)
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", out, err)
	}

	log.Printf("wrote %s (%d test(s))", out, len(tests))
	return nil
}

func mldsaPkcs8FileSpec(p mldsaParamSet) fileSpec {
	seedInner := append([]byte{mldsaSeedFormTag, byte(p.seedLen)}, mldsaSeed...)

	// build a PKCS#8 PrivateKeyInfo. Zero-value fields default to a
	// well-formed v1 seed-form encoding for parameter set p. Per-case
	// malformations override individual fields. algParameters, attributes,
	// and publicKey are pre-built TLVs (so cases can mutate tags or
	// contents directly).
	type pkcs8Params struct {
		version       int64                 // default 0 (v1)
		oid           asn1.ObjectIdentifier // default p.oid
		algParameters []byte                // default nil (absent)
		inner         []byte                // default seedInner
		attributes    []byte                // default nil (absent)
		publicKey     []byte                // default nil (absent)
	}
	privateKeyInfo := func(params pkcs8Params) ([]byte, error) {
		oid := params.oid
		if oid == nil {
			oid = p.oid
		}
		inner := params.inner
		if inner == nil {
			inner = seedInner
		}
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(params.version)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oid)
				if params.algParameters != nil {
					b.AddBytes(params.algParameters)
				}
			})
			b.AddASN1OctetString(inner)
			if params.attributes != nil {
				b.AddBytes(params.attributes)
			}
			if params.publicKey != nil {
				b.AddBytes(params.publicKey)
			}
		})
		return b.Bytes()
	}
	expandedKey := p.expandedKey
	pub := p.publicKey()

	// Well-formed encodings of the three PKCS#8 PrivateKeyInfo fields,
	// used as building blocks for the structural-malformation cases.
	v0VersionTLV := []byte{0x02, 0x01, 0x00}
	v1VersionTLV := []byte{0x02, 0x01, 0x01}
	algIDTLV := func() []byte {
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(p.oid)
		})
		out, err := b.Bytes()
		if err != nil {
			log.Fatalf("building %s AlgorithmIdentifier: %v", p.name, err)
		}
		return out
	}()
	privateKeyTLV := rawTLV(cbasn1.OCTET_STRING, seedInner, lengthShortest, 0)

	// v2 publicKey [1] IMPLICIT BIT STRING: tag 0x81 (context-specific,
	// primitive, tag 1). BIT STRING content is unused-bits byte (0) || pub.
	publicKeyTLV := func(pubBytes []byte) []byte {
		return rawTLV(cbasn1.Tag(1).ContextSpecific(), append([]byte{0x00}, pubBytes...), lengthShortest, 0)
	}
	// attributes [0] IMPLICIT SET OF Attribute: tag 0xa0 (context-specific,
	// constructed, tag 0).
	emptyAttributesTLV := []byte{0xa0, 0x00}

	// Baseline well-formed bytes, used for the outer-DER mutation cases that
	// rewrap a known-good inner payload with a malformed outer length encoding.
	wellFormed, err := privateKeyInfo(pkcs8Params{})
	if err != nil {
		log.Fatalf("building %s well-formed PKCS#8: %v", p.name, err)
	}

	return fileSpec{
		filename:     mldsaFilename(p, "pkcs8"),
		algorithm:    "ML-DSA",
		parameterSet: p.name,
		keyType:      PkixKeyDecodeTestGroupKeyTypePkcs8,
		header: []string{
			"Test vectors for decoding " + p.name + " PKCS#8 PrivateKeyInfo encodings.",
			"Vectors exercise malformed and edge-case DER inputs; consumers should",
			"verify their PKCS#8 parser accepts/rejects each encoding per the",
			"per-test result field.",
		},
		notes:      pkixNotes(PkixKeyDecodeTestGroupKeyTypePkcs8),
		sourceName: "github.com/c2sp/wycheproof/tools/pkixkeygen",
		sourceVer:  "1",
		cases: []caseSpec{
			{
				comment: "well-formed " + p.name + " PKCS#8 with seed",
				result:  ResultValid,
				flags:   []string{flagNormal, flagSeedForm},
				build:   func() ([]byte, error) { return wellFormed, nil },
			},
			{
				comment: "well-formed " + p.name + " PKCS#8 with semi-expanded form",
				result:  ResultValid,
				flags:   []string{flagNormal, flagExpandedForm},
				build: func() ([]byte, error) {
					inner := append([]byte{0x04}, shortestLength(len(expandedKey))...)
					inner = append(inner, expandedKey...)
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: "well-formed " + p.name + " PKCS#8 with both seed & semi-expanded form",
				result:  ResultValid,
				flags:   []string{flagNormal, flagSeedForm, flagExpandedForm},
				build: func() ([]byte, error) {
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(mldsaSeed)
						b.AddASN1OctetString(expandedKey)
					})
					inner, err := b.Bytes()
					if err != nil {
						return nil, err
					}
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},

			{
				comment: "AlgorithmIdentifier.parameters is NULL; ML-DSA forbids any parameters",
				result:  ResultInvalid,
				flags:   []string{flagInvalidAlgID, flagSeedForm},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{algParameters: nullTLV})
				},
			},
			{
				comment: "AlgorithmIdentifier.parameters is an OID; ML-DSA forbids any parameters",
				result:  ResultInvalid,
				flags:   []string{flagInvalidAlgID, flagSeedForm},
				build: func() ([]byte, error) {
					// OID 1.2.840.113549.1.1.1 (rsaEncryption) chosen as a recognizable
					// foreign value.
					return privateKeyInfo(pkcs8Params{algParameters: []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}})
				},
			},
			{
				comment: "privateKey OCTET STRING is empty",
				result:  ResultInvalid,
				flags:   []string{flagInvalidInnerEncoding},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{inner: []byte{}})
				},
			},
			{
				comment: "privateKey inner tag is unknown (0x00)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidInnerEncoding},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{inner: append([]byte{0x00, byte(p.seedLen)}, mldsaSeed...)})
				},
			},
			{
				comment: "privateKey inner is seed form but declared length byte (0x21) != PrivateKeySize (0x20)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidInnerEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					inner := make([]byte, 0, 2+p.seedLen)
					inner = append(inner, mldsaSeedFormTag, byte(p.seedLen+1))
					inner = append(inner, mldsaSeed...)
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: "privateKey inner is seed form but truncated (31 seed bytes)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidKeySize, flagSeedForm},
				build: func() ([]byte, error) {
					inner := append([]byte{mldsaSeedFormTag, byte(p.seedLen)}, mldsaSeed[:31]...)
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: "privateKey inner is seed form but extended (33 seed bytes)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidKeySize, flagSeedForm},
				build: func() ([]byte, error) {
					extended := append(append([]byte{}, mldsaSeed...), 0x00)
					inner := append([]byte{mldsaSeedFormTag, byte(p.seedLen)}, extended...)
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: "version is 2; RFC 5958 only defines versions 0 (v1) and 1 (v2)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidVersion, flagSeedForm},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{version: 2})
				},
			},
			{
				comment: "outer SEQUENCE length encoded in non-minimal 1-octet long form (0x81 0x34 vs 0x34)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthLongForm1, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE length encoded in non-minimal 2-octet long form (0x82 0x00 0x34)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthLongForm2, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE uses BER indefinite length (0x80 ... 00 00); illegal DER",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthIndefinite, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE declared length is one byte too large; reads past end",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthShortest, +1), nil
				},
			},
			{
				comment: "outer SEQUENCE declared length is one byte too small; truncates last body byte",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthShortest, -1), nil
				},
			},
			{
				comment: "well-formed encoding followed by a trailing 0x00 byte",
				result:  ResultInvalid,
				flags:   []string{flagTrailingData, flagSeedForm},
				build: func() ([]byte, error) {
					return append(append([]byte(nil), wellFormed...), 0x00), nil
				},
			},
			{
				comment: "AlgorithmIdentifier.algorithm is the Ed25519 OID; ML-DSA seed-form inner bytes are not a valid Ed25519 PrivateKey",
				result:  ResultInvalid,
				flags:   []string{flagWrongAlgorithm, flagSeedForm},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{oid: oidEd25519})
				},
			},
			{
				comment: "privateKey inner is expanded-only form but body is truncated by one byte",
				result:  ResultInvalid,
				flags:   []string{flagInvalidKeySize, flagInvalidInnerEncoding, flagExpandedForm},
				build: func() ([]byte, error) {
					truncated := expandedKey[:len(expandedKey)-1]
					inner := append([]byte{0x04}, shortestLength(len(truncated))...)
					inner = append(inner, truncated...)
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: "privateKey inner is expanded-only form but declared length is one byte larger than the body",
				result:  ResultInvalid,
				flags:   []string{flagInvalidInnerEncoding, flagExpandedForm},
				build: func() ([]byte, error) {
					inner := append([]byte{0x04}, shortestLength(len(expandedKey)+1)...)
					inner = append(inner, expandedKey...)
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: `privateKey inner is "both" form with components in reversed order (expandedKey before seed)`,
				result:  ResultInvalid,
				flags:   []string{flagInvalidInnerEncoding, flagSeedForm, flagExpandedForm},
				build: func() ([]byte, error) {
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(expandedKey)
						b.AddASN1OctetString(mldsaSeed)
					})
					inner, err := b.Bytes()
					if err != nil {
						return nil, err
					}
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: `privateKey inner is "both" form missing the seed component (SEQUENCE contains only expandedKey)`,
				result:  ResultInvalid,
				flags:   []string{flagInvalidInnerEncoding, flagExpandedForm},
				build: func() ([]byte, error) {
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(expandedKey)
					})
					inner, err := b.Bytes()
					if err != nil {
						return nil, err
					}
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: `privateKey inner is "both" form but seed component is 31 bytes instead of 32`,
				result:  ResultInvalid,
				flags:   []string{flagInvalidKeySize, flagInvalidInnerEncoding, flagSeedForm, flagExpandedForm},
				build: func() ([]byte, error) {
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(mldsaSeed[:31])
						b.AddASN1OctetString(expandedKey)
					})
					inner, err := b.Bytes()
					if err != nil {
						return nil, err
					}
					return privateKeyInfo(pkcs8Params{inner: inner})
				},
			},
			{
				comment: "outer SEQUENCE is empty (zero fields)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, nil, lengthShortest, 0), nil
				},
			},
			{
				comment: "outer container is tagged as SET (0x31) instead of SEQUENCE (0x30)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					body := bytes.Join([][]byte{v0VersionTLV, algIDTLV, privateKeyTLV}, nil)
					return rawTLV(cbasn1.SET, body, lengthShortest, 0), nil
				},
			},
			{
				comment: "version field is missing",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{algIDTLV, privateKeyTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "AlgorithmIdentifier field is missing",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{v0VersionTLV, privateKeyTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "privateKey OCTET STRING field is missing",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{v0VersionTLV, algIDTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "fields are reordered: privateKey before AlgorithmIdentifier",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{v0VersionTLV, privateKeyTLV, algIDTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "AlgorithmIdentifier SEQUENCE is tagged as SET (0x31)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1ObjectIdentifier(p.oid)
					innerBody, err := b.Bytes()
					if err != nil {
						return nil, err
					}
					badAlgID := rawTLV(cbasn1.SET, innerBody, lengthShortest, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{v0VersionTLV, badAlgID, privateKeyTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "extra trailing field (NULL) inside the outer SEQUENCE after privateKey",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{v0VersionTLV, algIDTLV, privateKeyTLV, nullTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "version field encoded with redundant leading 0x00 byte",
				result:  ResultInvalid,
				flags:   []string{flagInvalidVersion, flagSeedForm},
				build: func() ([]byte, error) {
					badVersion := []byte{0x02, 0x02, 0x00, 0x00}
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{badVersion, algIDTLV, privateKeyTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "version field encoded as a negative integer (-1)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidVersion, flagSeedForm},
				build: func() ([]byte, error) {
					badVersion := []byte{0x02, 0x01, 0xff}
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{badVersion, algIDTLV, privateKeyTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE length encoded in non-minimal 3-octet long form (0x83 0x00 0x00 ll)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthLongForm3, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE length octet is the reserved 0xff value",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthReservedFF, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE declares a 4-octet length of 0xffffffff, far larger than the body",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding, flagSeedForm},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthOverflow, 0), nil
				},
			},
			{
				comment: "AlgorithmIdentifier.parameters uses context-specific tag class ([0] IMPLICIT NULL)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidAlgID, flagSeedForm},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{algParameters: []byte{0xa0, 0x00}})
				},
			},
			{
				comment: "AlgorithmIdentifier.algorithm OID has non-minimal base-128 sub-identifier encoding",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					badAlgID := rawTLV(cbasn1.SEQUENCE, overlongOIDTLV(p), lengthShortest, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{v0VersionTLV, badAlgID, privateKeyTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "v1 with empty attributes SET",
				result:  ResultValid,
				flags:   []string{flagNormal, flagSeedForm},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{attributes: emptyAttributesTLV})
				},
			},
			{
				comment: "v1 with non-empty attributes (one Attribute, OID 1.2.3 with NULL value)",
				result:  ResultValid,
				flags:   []string{flagNormal, flagSeedForm},
				build: func() ([]byte, error) {
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 3})
						b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
							b.AddASN1NULL()
						})
					})
					attrBody, err := b.Bytes()
					if err != nil {
						return nil, err
					}
					return privateKeyInfo(pkcs8Params{attributes: rawTLV(cbasn1.Tag(0).ContextSpecific().Constructed(), attrBody, lengthShortest, 0)})
				},
			},
			{
				comment: "v2 with publicKey matching the seed-derived public key",
				result:  ResultValid,
				flags:   []string{flagNormal, flagSeedForm, flagPkcs8V2},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{version: 1, publicKey: publicKeyTLV(pub)})
				},
			},
			{
				comment: "v2 with empty attributes AND publicKey matching the seed-derived public key",
				result:  ResultValid,
				flags:   []string{flagNormal, flagSeedForm, flagPkcs8V2},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{version: 1, attributes: emptyAttributesTLV, publicKey: publicKeyTLV(pub)})
				},
			},
			{
				comment: "v1 with publicKey field present; RFC 5958 §2 restricts publicKey to v2",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{publicKey: publicKeyTLV(pub)})
				},
			},
			{
				comment: "v2 without publicKey field; RFC 5958 §2 requires v2 if and only if publicKey is present",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm, flagPkcs8V2},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{version: 1})
				},
			},
			{
				comment: "v2 with publicKey BIT STRING truncated by one byte",
				result:  ResultInvalid,
				flags:   []string{flagInvalidKeySize, flagSeedForm, flagPkcs8V2},
				build: func() ([]byte, error) {
					return privateKeyInfo(pkcs8Params{version: 1, publicKey: publicKeyTLV(pub[:len(pub)-1])})
				},
			},
			{
				comment: "v2 with publicKey bytes that do not match the seed-derived public key; RFC 9881 does not require this cross-check",
				result:  ResultAcceptable,
				flags:   []string{flagInconsistentPublicKey, flagSeedForm, flagPkcs8V2},
				build: func() ([]byte, error) {
					mismatched := append([]byte{}, pub...)
					mismatched[0] ^= 0xff
					return privateKeyInfo(pkcs8Params{version: 1, publicKey: publicKeyTLV(mismatched)})
				},
			},
			{
				comment: "v2 with attributes encoded as bare SET (0x31) instead of [0] IMPLICIT (0xa0)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure, flagSeedForm, flagPkcs8V2},
				build: func() ([]byte, error) {
					badAttributes := []byte{0x31, 0x00}
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{v1VersionTLV, algIDTLV, privateKeyTLV, badAttributes, publicKeyTLV(pub)}, nil), lengthShortest, 0), nil
				},
			},
		},
	}
}

func mldsaSpkiFileSpec(p mldsaParamSet) fileSpec {
	// build a SubjectPublicKeyInfo with caller-supplied OID, algorithm
	// parameters, and public-key bytes. algParameters, if non-nil, is
	// appended verbatim inside the AlgorithmIdentifier SEQUENCE after the
	// OID.
	subjectPublicKeyInfo := func(oid asn1.ObjectIdentifier, algParameters, pub []byte) ([]byte, error) {
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oid)
				if algParameters != nil {
					b.AddBytes(algParameters)
				}
			})
			b.AddASN1BitString(pub)
		})
		return b.Bytes()
	}

	pub := p.publicKey()

	// Well-formed encodings of the two SPKI fields, used as building blocks
	// for the structural-malformation cases.
	algIDTLV := func() []byte {
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(p.oid)
		})
		out, err := b.Bytes()
		if err != nil {
			log.Fatalf("building %s AlgorithmIdentifier: %v", p.name, err)
		}
		return out
	}()
	pubTLV := func() []byte {
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1BitString(pub)
		out, err := b.Bytes()
		if err != nil {
			log.Fatalf("building %s public-key BIT STRING: %v", p.name, err)
		}
		return out
	}()

	// Baseline well-formed bytes for outer-DER mutation cases.
	wellFormed, err := subjectPublicKeyInfo(p.oid, nil, pub)
	if err != nil {
		log.Fatalf("building %s well-formed SPKI: %v", p.name, err)
	}

	return fileSpec{
		filename:     mldsaFilename(p, "spki"),
		algorithm:    "ML-DSA",
		parameterSet: p.name,
		keyType:      PkixKeyDecodeTestGroupKeyTypeSpki,
		header: []string{
			"Test vectors for decoding " + p.name + " SubjectPublicKeyInfo encodings.",
			"Vectors exercise malformed and edge-case DER inputs; consumers should",
			"verify their SPKI parser accepts/rejects each encoding per the",
			"per-test result field.",
		},
		notes:      pkixNotes(PkixKeyDecodeTestGroupKeyTypeSpki),
		sourceName: "github.com/c2sp/wycheproof/tools/pkixkeygen",
		sourceVer:  "1",
		cases: []caseSpec{
			{
				comment: "well-formed " + p.name + " SubjectPublicKeyInfo",
				result:  ResultValid,
				flags:   []string{flagNormal},
				build:   func() ([]byte, error) { return wellFormed, nil },
			},
			{
				comment: "AlgorithmIdentifier.parameters is NULL; ML-DSA forbids any parameters",
				result:  ResultInvalid,
				flags:   []string{flagInvalidAlgID},
				build: func() ([]byte, error) {
					return subjectPublicKeyInfo(p.oid, nullTLV, pub)
				},
			},
			{
				comment: "public-key BIT STRING is truncated by one byte",
				result:  ResultInvalid,
				flags:   []string{flagInvalidKeySize},
				build: func() ([]byte, error) {
					return subjectPublicKeyInfo(p.oid, nil, pub[:len(pub)-1])
				},
			},
			{
				comment: "public-key BIT STRING has one extra trailing byte",
				result:  ResultInvalid,
				flags:   []string{flagInvalidKeySize},
				build: func() ([]byte, error) {
					extended := append(append([]byte{}, pub...), 0x00)
					return subjectPublicKeyInfo(p.oid, nil, extended)
				},
			},
			{
				comment: "public-key BIT STRING has non-zero unused-bits header (0x04)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidBitString},
				build: func() ([]byte, error) {
					// Hand-roll the BIT STRING with a 0x04 unused-bits byte instead of 0x00.
					bs := append([]byte{0x04}, pub...)
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1ObjectIdentifier(p.oid)
						})
						b.AddBytes(rawTLV(cbasn1.BIT_STRING, bs, lengthShortest, 0))
					})
					return b.Bytes()
				},
			},
			{
				comment: "outer SEQUENCE length encoded in non-minimal 1-octet long form, truncating the high byte of the declared length",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthLongForm1, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE uses BER indefinite length (0x80 ... 00 00); illegal DER",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthIndefinite, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE declared length is one byte too large; reads past end",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthShortest, +1), nil
				},
			},
			{
				comment: "outer SEQUENCE declared length is one byte too small; truncates last body byte",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthShortest, -1), nil
				},
			},
			{
				comment: "well-formed encoding followed by a trailing 0x00 byte",
				result:  ResultInvalid,
				flags:   []string{flagTrailingData},
				build: func() ([]byte, error) {
					return append(append([]byte(nil), wellFormed...), 0x00), nil
				},
			},
			{
				comment: "AlgorithmIdentifier.algorithm is a sibling ML-DSA OID; public-key bytes are the wrong size for that parameter set",
				result:  ResultInvalid,
				flags:   []string{flagWrongAlgorithm},
				build: func() ([]byte, error) {
					return subjectPublicKeyInfo(p.siblingOID, nil, pub)
				},
			},
			{
				comment: "AlgorithmIdentifier.algorithm is the Ed25519 OID; ML-DSA public-key bytes are far too large for an Ed25519 key (32 bytes)",
				result:  ResultInvalid,
				flags:   []string{flagWrongAlgorithm},
				build: func() ([]byte, error) {
					return subjectPublicKeyInfo(oidEd25519, nil, pub)
				},
			},
			{
				comment: "outer SEQUENCE is empty (zero fields)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, nil, lengthShortest, 0), nil
				},
			},
			{
				comment: "outer container is tagged as SET (0x31) instead of SEQUENCE (0x30)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					body := bytes.Join([][]byte{algIDTLV, pubTLV}, nil)
					return rawTLV(cbasn1.SET, body, lengthShortest, 0), nil
				},
			},
			{
				comment: "AlgorithmIdentifier field is missing",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, pubTLV, lengthShortest, 0), nil
				},
			},
			{
				comment: "subjectPublicKey BIT STRING field is missing",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, algIDTLV, lengthShortest, 0), nil
				},
			},
			{
				comment: "fields are reordered: subjectPublicKey before AlgorithmIdentifier",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{pubTLV, algIDTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "AlgorithmIdentifier SEQUENCE is tagged as SET (0x31)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					b := cryptobyte.NewBuilder(nil)
					b.AddASN1ObjectIdentifier(p.oid)
					innerBody, err := b.Bytes()
					if err != nil {
						return nil, err
					}
					badAlgID := rawTLV(cbasn1.SET, innerBody, lengthShortest, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{badAlgID, pubTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "extra trailing field (NULL) inside the outer SEQUENCE after subjectPublicKey",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{algIDTLV, pubTLV, nullTLV}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "public-key BIT STRING unused-bits header is 0x08 (illegal; max is 7)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidBitString},
				build: func() ([]byte, error) {
					bs := append([]byte{0x08}, pub...)
					badPub := rawTLV(cbasn1.BIT_STRING, bs, lengthShortest, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{algIDTLV, badPub}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "public-key BIT STRING is empty (no unused-bits header byte at all)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidBitString},
				build: func() ([]byte, error) {
					badPub := rawTLV(cbasn1.BIT_STRING, nil, lengthShortest, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{algIDTLV, badPub}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "public-key field tag is OCTET STRING (0x04) instead of BIT STRING (0x03)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidBitString},
				build: func() ([]byte, error) {
					badPub := rawTLV(cbasn1.OCTET_STRING, pub, lengthShortest, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{algIDTLV, badPub}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "public-key BIT STRING uses BER indefinite length (illegal DER)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidBitString},
				build: func() ([]byte, error) {
					bs := append([]byte{0x00}, pub...)
					badPub := rawTLV(cbasn1.BIT_STRING, bs, lengthIndefinite, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{algIDTLV, badPub}, nil), lengthShortest, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE length encoded in non-minimal 3-octet long form (0x83 0x00 hh ll)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthLongForm3, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE length octet is the reserved 0xff value",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthReservedFF, 0), nil
				},
			},
			{
				comment: "outer SEQUENCE declares a 4-octet length of 0xffffffff, far larger than the body",
				result:  ResultInvalid,
				flags:   []string{flagInvalidLengthEncoding},
				build: func() ([]byte, error) {
					return rawTLV(cbasn1.SEQUENCE, rewrapOuter(wellFormed), lengthOverflow, 0), nil
				},
			},
			{
				comment: "AlgorithmIdentifier.parameters uses context-specific tag class ([0] IMPLICIT NULL)",
				result:  ResultInvalid,
				flags:   []string{flagInvalidAlgID},
				build: func() ([]byte, error) {
					return subjectPublicKeyInfo(p.oid, []byte{0xa0, 0x00}, pub)
				},
			},
			{
				comment: "AlgorithmIdentifier.algorithm OID has non-minimal base-128 sub-identifier encoding",
				result:  ResultInvalid,
				flags:   []string{flagInvalidStructure},
				build: func() ([]byte, error) {
					badAlgID := rawTLV(cbasn1.SEQUENCE, overlongOIDTLV(p), lengthShortest, 0)
					return rawTLV(cbasn1.SEQUENCE, bytes.Join([][]byte{badAlgID, pubTLV}, nil), lengthShortest, 0), nil
				},
			},
		},
	}
}

func pkixNotes(keyType PkixKeyDecodeTestGroupKeyType) Notes {
	note := func(bugType, description string) NoteEntry {
		desc := description
		return NoteEntry{BugType: bugType, Description: &desc}
	}

	n := Notes{
		flagNormal:                note("BASIC", "Well-formed encoding included as a sanity check that the corpus's positive path is accepted."),
		flagInvalidLengthEncoding: note("MODIFIED_PARAMETER", "The encoding uses a length octet form that is not the shortest valid DER form, or declares a length that does not match the body (non-minimal long form, BER indefinite length, over- or under-declared length). Strict DER parsers should reject; BER-tolerant parsers may accept."),
		flagTrailingData:          note("MODIFIED_PARAMETER", "The encoding consists of a well-formed structure followed by extra bytes after the outer SEQUENCE. Parsers should reject any input with trailing data."),
		flagInvalidAlgID:          note("MODIFIED_PARAMETER", "The AlgorithmIdentifier is malformed for the key type: typically its parameters field is present when the algorithm forbids any parameters."),
		flagWrongAlgorithm:        note("MODIFIED_PARAMETER", "The AlgorithmIdentifier.algorithm OID identifies a different algorithm than the key bytes. Parsers should validate that the OID matches the key material before deriving a key."),
		flagInvalidStructure:      note("MODIFIED_PARAMETER", "The outer or inner SEQUENCE shape is malformed: a required field is missing, the fields are reordered, an extra trailing field is present, the outer container has the wrong tag (e.g. SET instead of SEQUENCE), or an inner field is tagged incorrectly."),
	}

	switch keyType {
	case PkixKeyDecodeTestGroupKeyTypePkcs8:
		n[flagInvalidInnerEncoding] = note("MODIFIED_PARAMETER", "The PKCS#8 PrivateKey OCTET STRING body is malformed: empty, has an unrecognized inner tag, has an inner length that does not match the body, or (for the ML-DSA \"both\" form) has its components reordered or missing.")
		n[flagInvalidKeySize] = note("MODIFIED_PARAMETER", "The encoded private-key material has the wrong byte length for the declared algorithm or parameter set (seed truncated or extended, or a structural component of the wrong size).")
		n[flagInvalidVersion] = note("MODIFIED_PARAMETER", "The PKCS#8 version field is invalid: it has a value other than 0 (v1) or 1 (v2), or it is encoded non-canonically (negative, or with a redundant leading zero byte). RFC 5958 defines only versions 0 and 1; other integers and non-canonical encodings must be rejected.")
		n[flagInconsistentPublicKey] = note("LEGACY", "The v2 PKCS#8 publicKey field contains bytes that do not match the public key derivable from the private key seed. RFC 9881 does not require this cross-check (RFC 5958 §2 only says SHOULD match); parsers MAY accept or reject. Cases flagged with this are declared 'acceptable'.")
		n[flagSeedForm] = note("BASIC", "The PKCS#8 PrivateKey OCTET STRING content uses the ML-DSA seed form (0x80 || len || seed). Cases tagged with both SeedForm and ExpandedForm use the \"both\" CHOICE.")
		n[flagExpandedForm] = note("BASIC", "The PKCS#8 PrivateKey OCTET STRING content uses the ML-DSA semi-expanded form (0x04 OCTET STRING). Cases tagged with both SeedForm and ExpandedForm use the \"both\" CHOICE.")
		n[flagPkcs8V2] = note("BASIC", "The case uses a PKCS#8 v2 PrivateKeyInfo encoding (version=1). Implementations that only support v1 PKCS#8 (version=0) can use this flag to identify applicable cases.")
	case PkixKeyDecodeTestGroupKeyTypeSpki:
		n[flagInvalidKeySize] = note("MODIFIED_PARAMETER", "The encoded public-key material has the wrong byte length for the declared algorithm or parameter set (truncated or extended).")
		n[flagInvalidBitString] = note("MODIFIED_PARAMETER", "The SubjectPublicKey BIT STRING is malformed at the BIT STRING layer: the unused-bits header byte is non-zero or larger than 7, the BIT STRING contents are empty, the BIT STRING tag is substituted with another tag (e.g. OCTET STRING), or the BIT STRING uses indefinite length.")
	}
	return n
}

// Flags describing the property under test. Each flag is the key of a
// NoteEntry in the file's notes map (see pkixNotes). Multiple flags may be
// attached to a single case where it straddles categories.
const (
	flagNormal                = "Normal"
	flagInvalidLengthEncoding = "InvalidLengthEncoding"
	flagTrailingData          = "TrailingData"
	flagInvalidAlgID          = "InvalidAlgorithmIdentifier"
	flagWrongAlgorithm        = "WrongAlgorithm"
	flagInvalidInnerEncoding  = "InvalidInnerEncoding"
	flagInvalidKeySize        = "InvalidKeySize"
	flagInvalidVersion        = "InvalidVersion"
	flagInvalidBitString      = "InvalidBitString"
	flagInvalidStructure      = "InvalidStructure"
	flagInconsistentPublicKey = "InconsistentPublicKey"
	flagSeedForm              = "SeedForm"
	flagExpandedForm          = "ExpandedForm"
	flagPkcs8V2               = "Pkcs8V2"
)

// fileSpec describes one vector file: one schema group, one keyType, one
// algorithm + parameter set, and the list of test cases that belong in it.
type fileSpec struct {
	filename     string
	algorithm    string
	parameterSet string
	keyType      PkixKeyDecodeTestGroupKeyType
	header       []string
	notes        Notes
	sourceName   string
	sourceVer    string
	cases        []caseSpec
}

// caseSpec is the declarative form of one test vector. The build function
// produces the encoded DER bytes; result/flags/comment describe the expected
// parser outcome.
type caseSpec struct {
	comment string
	result  Result
	flags   []string
	build   func() ([]byte, error)
}

// classifyMismatch feeds der to the Go x509 parser that matches keyType and
// reports whether the parser's accept/reject decision disagrees with the
// case's expected result.
// When it disagrees a description string and the underlying error (if any)
// is returned.
func classifyMismatch(keyType PkixKeyDecodeTestGroupKeyType, expected Result, der []byte) (string, error) {
	var parseErr error
	switch keyType {
	case PkixKeyDecodeTestGroupKeyTypePkcs8:
		_, parseErr = x509.ParsePKCS8PrivateKey(der)
	case PkixKeyDecodeTestGroupKeyTypeSpki:
		_, parseErr = x509.ParsePKIXPublicKey(der)
	default:
		parseErr = fmt.Errorf("unknown keyType %q", keyType)
	}

	parserAccepted := parseErr == nil
	switch expected {
	case ResultValid:
		if !parserAccepted {
			return "declared valid but Go x509 parser rejected it", parseErr
		}
	case ResultInvalid:
		if parserAccepted {
			return "declared invalid but Go x509 parser accepted it", parseErr
		}
	}
	return "", parseErr
}

func mldsaFilename(p mldsaParamSet, keyForm string) string {
	return "mldsa_" + strings.TrimPrefix(p.name, "ML-DSA-") + "_" + keyForm + "_decode_test.json"
}

// overlongOIDTLV returns an OBJECT IDENTIFIER TLV for p.oid with the final
// sub-identifier encoded in non-minimal base-128 form (0x80 || sub-id) instead
// of the canonical single-byte encoding. Relies on all ML-DSA OIDs ending in
// a sub-identifier < 128.
func overlongOIDTLV(p mldsaParamSet) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1ObjectIdentifier(p.oid)
	canonical, err := b.Bytes()
	if err != nil {
		log.Fatalf("encoding %s OID: %v", p.name, err)
	}
	// canonical = [0x06, len, ... canonical sub-ids ..., lastByte]
	lastSubID := canonical[len(canonical)-1]
	if lastSubID >= 0x80 {
		log.Fatalf("%s OID final sub-identifier (0x%02x) is not single-byte; overlongOIDTLV needs to grow", p.name, lastSubID)
	}
	body := append([]byte{}, canonical[2:len(canonical)-1]...)
	body = append(body, 0x80, lastSubID)
	return rawTLV(cbasn1.OBJECT_IDENTIFIER, body, lengthShortest, 0)
}

// mldsaParamSet selects an ML-DSA parameter set. siblingOID is another
// ML-DSA OID (different parameter set) used by the wrong-algorithm SPKI case.
type mldsaParamSet struct {
	name        string
	oid         asn1.ObjectIdentifier
	siblingOID  asn1.ObjectIdentifier
	params      mldsa.Parameters
	seedLen     int
	expandedKey []byte
}

// publicKey returns the raw public-key bytes derivable from mldsaSeed under
// parameter set p.
func (p mldsaParamSet) publicKey() []byte {
	sk, err := mldsa.NewPrivateKey(p.params, mldsaSeed)
	if err != nil {
		log.Fatalf("deriving %s public key from seed: %v", p.name, err)
	}
	return sk.PublicKey().Bytes()
}

var (
	mldsaParams44 = mldsaParamSet{
		name:        "ML-DSA-44",
		oid:         oidMldsa44,
		siblingOID:  oidMldsa65,
		params:      mldsa.MLDSA44(),
		seedLen:     mldsa.PrivateKeySize,
		expandedKey: mldsaSemiExpanded44,
	}
	mldsaParams65 = mldsaParamSet{
		name:        "ML-DSA-65",
		oid:         oidMldsa65,
		siblingOID:  oidMldsa87,
		params:      mldsa.MLDSA65(),
		seedLen:     mldsa.PrivateKeySize,
		expandedKey: mldsaSemiExpanded65,
	}
	mldsaParams87 = mldsaParamSet{
		name:        "ML-DSA-87",
		oid:         oidMldsa87,
		siblingOID:  oidMldsa44,
		params:      mldsa.MLDSA87(),
		seedLen:     mldsa.PrivateKeySize,
		expandedKey: mldsaSemiExpanded87,
	}
)

var mldsaSeed = bytes.Repeat([]byte{0x2a}, mldsa.PrivateKeySize)

// nullTLV is the DER encoding of an ASN.1 NULL value.
var nullTLV = []byte{byte(cbasn1.NULL), 0x00}

// mldsaSeedFormTag is the leading byte of the ML-DSA seed-form privateKey
// inner encoding ([0] IMPLICIT OCTET STRING per RFC 9881 §6).
const mldsaSeedFormTag byte = 0x80

// Semi-expanded private-key bytes for each parameter set, derived from
// mldsaSeed.
var (
	//go:embed testdata/mldsa_44_semiexpanded.bin
	mldsaSemiExpanded44 []byte
	//go:embed testdata/mldsa_65_semiexpanded.bin
	mldsaSemiExpanded65 []byte
	//go:embed testdata/mldsa_87_semiexpanded.bin
	mldsaSemiExpanded87 []byte
)

var (
	// RFC 9755 / NIST CSOR allocations for ML-DSA OIDs:
	// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
	// csor(3) nistAlgorithm(4) sigAlgs(3) { 17, 18, 19 }
	oidMldsa44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMldsa65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMldsa87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)
