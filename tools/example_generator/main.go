// example_generator demonstrates the vectorgen library API by producing a
// tiny HMAC-SHA256 vector file from Go stdlib crypto.
//
// It is not a real generator — the existing Wycheproof HMAC vectors are far
// more comprehensive. The point is to show downstream generator authors how
// to wire up vectorgen.Add from Go.
//
// Note: the test and groupTemplate objects are built as RawObjects (ordered
// maps) rather than Go maps, because Go's map iteration order is randomized
// and json/v2 serializes map keys alphabetically. Either is valid input to
// vectorgen.Add, but operators usually want deterministic key order in their
// output, which means using an ordered structure here.
//
// Usage:
//
//	GOEXPERIMENT=jsonv2 go run ./tools/example_generator -o /tmp/example_hmac_test.json
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/c2sp/wycheproof/vectorgen"
)

type input struct {
	comment string
	key     []byte
	msg     []byte
}

var inputs = []input{
	{"empty message", []byte("0123456789abcdef0123456789abcdef"), []byte{}},
	{"single byte", []byte("0123456789abcdef0123456789abcdef"), []byte{0x00}},
	{"hello world", []byte("0123456789abcdef0123456789abcdef"), []byte("hello world")},
}

func main() {
	out := flag.String("o", "", "output file path (required)")
	flag.Parse()
	if *out == "" {
		log.Fatal("missing -o")
	}

	tests := make([]jsontext.Value, len(inputs))
	for i, in := range inputs {
		mac := hmac.New(sha256.New, in.key)
		mac.Write(in.msg)
		tests[i] = mustEncode(vectorgen.RawObject{
			{Name: "comment", Value: mustEncodeString(in.comment)},
			{Name: "key", Value: mustEncodeString(hex.EncodeToString(in.key))},
			{Name: "msg", Value: mustEncodeString(hex.EncodeToString(in.msg))},
			{Name: "tag", Value: mustEncodeString(hex.EncodeToString(mac.Sum(nil)))},
			{Name: "result", Value: mustEncodeString("valid")},
			{Name: "flags", Value: jsontext.Value("[]")},
		})
	}

	source := vectorgen.RawObject{
		{Name: "name", Value: mustEncodeString("github.com/c2sp/wycheproof/tools/example_generator")},
		{Name: "version", Value: mustEncodeString("1")},
	}
	groupTemplate := mustEncode(vectorgen.RawObject{
		{Name: "type", Value: mustEncodeString("MacTest")},
		{Name: "source", Value: mustEncode(source)},
		{Name: "keySize", Value: jsontext.Value("256")},
		{Name: "tagSize", Value: jsontext.Value("256")},
	})

	env := vectorgen.AddEnvelope{
		Algorithm: "HMACSHA256",
		Schema:    "mac_test_schema_v1.json",
		Header: []string{
			"Example HMAC-SHA256 vectors produced by tools/example_generator,",
			"demonstrating the vectorgen library API. Not exhaustive.",
		},
		GroupTemplate: groupTemplate,
		Tests:         tests,
	}

	if err := vectorgen.Add(*out, env, vectorgen.Options{}); err != nil {
		log.Fatalf("vectorgen.Add: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
}

func mustEncode(v any) jsontext.Value {
	b, err := json.Marshal(v)
	if err != nil {
		log.Fatalf("encoding: %v", err)
	}
	return b
}

func mustEncodeString(s string) jsontext.Value {
	return mustEncode(s)
}
