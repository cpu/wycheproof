# Updating Wycheproof vectors with `vectorgen`

Three common workflows are covered: **add**ing new vectors to an existing
file, **update**ing existing vectors to add or rewrite a field, and
**replace**ing a whole group of vectors with regenerated output.

All commands assume Go 1.26+. Set `GOEXPERIMENT=jsonv2` once per shell, or
prefix every invocation:

```
export GOEXPERIMENT=jsonv2
```

After any change, run `go run ./tools/vectorgen fmt --check
'testvectors_v1/*.json'` and `go run ./tools/vectorgen lint` to confirm the
result is canonical and schema-valid.

---

## A) Add new vectors to an existing file

Use case: you've generated a few new vectors that fit an existing test group
(same source name), and want to append them.

1. **Scaffold a starter envelope** for the right schema:

   ```
   go run ./tools/vectorgen scaffold add \
     --schema mlkem_semi_expanded_decaps_test_schema.json \
     --output envelope.json
   ```

   The output has placeholders like `"<HexBytes>"` and `"<one of: valid,
   invalid, acceptable>"` so it's obvious what each field expects.

2. **Edit `envelope.json`**: remove the `algorithm`, `schema`, `header`, and
   `groupTemplate` fields (those are only for creating new files). Keep just
   `tests` and optionally `notes`. Fill the test placeholders with real values.
   Do NOT include a `tcId` field — the tool assigns them.

3. **Apply with `--into-group`** (the source name identifies which existing
   group to append into):

   ```
   go run ./tools/vectorgen add \
     --vectors testvectors_v1/mlkem_512_semi_expanded_decaps_test.json \
     --input envelope.json \
     --into-group github/aws/aws-lc
   ```

   The tool finds the matching group, appends your tests with continuing
   tcIds, recomputes `numberOfTests`, and merges new note entries.

If you want a brand-new group instead of appending into an existing one, drop
`--into-group` and keep the `groupTemplate` field in the envelope.

To create a whole new vector file, keep all the scaffold fields and pass
`--create`:

```
go run ./tools/vectorgen add --create \
  --vectors testvectors_v1/my_new_test.json \
  --input envelope.json
```

---

## B) Add or rewrite a field across existing vectors

Use case: a generator was updated to produce a new field (e.g. `ek`), or a
bug was fixed and existing values need rewriting.

1. **Scaffold an update envelope by hand** — there's no `scaffold update`
   today. The shape is small:

   ```json
   {
     "source": "github/aws/aws-lc",
     "patches": [
       { "tcId": 1, "ek": "...", "K": "..." },
       { "tcId": 2, "ek": "..." }
     ]
   }
   ```

   `source` selects which groups to patch (use `"name@version"` to
   disambiguate). Each patch's `tcId` identifies the test; other fields are
   merged in.

2. **Apply** (use globs to patch parallel files in one shot):

   ```
   go run ./tools/vectorgen update \
     --vectors 'testvectors_v1/mlkem_*_semi_expanded_decaps_test.json' \
     --input envelope.json
   ```

   Defaults are strict:
   - **All matching tests must be covered.** Add `--partial` to permit a
     subset.
   - **Existing field values must not differ.** Add `--overwrite` to rewrite
     a field that already has a different value.

   New keys are inserted at the position implied by the test-vector schema's
   `properties` array. Existing key order is preserved.

---

## C) Replace a whole group of vectors

Use case: a generator bug forced you to regenerate every test in a group, or
a group's tests have changed in size and composition.

1. **Construct an envelope** with the new group's template and tests (same
   shape as the add envelope; no `algorithm`/`schema`/`header`):

   ```json
   {
     "groupTemplate": {
       "type": "MLKEMDecapsValidationTest",
       "source": { "name": "github/lukaszobernig/reenc", "version": "2.0" },
       "parameterSet": "ML-KEM-512"
     },
     "tests": [
       { "comment": "...", "dk": "...", "c": "...", "ek": "...", "result": "invalid", "flags": [...] }
     ]
   }
   ```

2. **Apply with `--source`** identifying the group to swap out:

   ```
   go run ./tools/vectorgen replace \
     --vectors testvectors_v1/mlkem_512_semi_expanded_decaps_test.json \
     --source github/lukaszobernig/reenc@1.0 \
     --input envelope.json
   ```

   The new group lands at the position of the old one (not appended at the
   end). Every test in the file is renumbered sequentially from 1, since the
   replacement may differ in size.

If `--source` matches more than one group, you'll get an error listing them
— disambiguate with `name@version`.

---

## Safety net

Every mutating operation (`add`, `update`, `replace`) validates the merged
result against the schema before writing. On failure, the candidate output
is written to `<vectorfile>.rej` and the original is left untouched, so
you can inspect what went wrong without losing the original file.

---

## Appendix: doing the same from Go

The CLI is a thin wrapper over `github.com/c2sp/wycheproof/vectorgen`. Go
generators that produce vectors directly can skip the JSON envelope and
call the library functions. The same three workflows look like this:

All examples elide error handling and assume `import "github.com/c2sp/wycheproof/vectorgen"`.
Generators must be built with `GOEXPERIMENT=jsonv2`. Each test or group
object is a `jsontext.Value` (raw JSON bytes); build them however you like
— `RawObject` (an ordered map) is convenient when you want deterministic
key order, since Go maps serialize alphabetically through `json/v2`.

### A) Add new vectors to an existing file

```go
env := vectorgen.AddEnvelope{
    Tests:     []jsontext.Value{ /* one or more test objects */ },
    IntoGroup: "github/aws/aws-lc", // or "name@version"
}
err := vectorgen.Add("testvectors_v1/mlkem_512_semi_expanded_decaps_test.json",
    env, vectorgen.Options{})
```

To append a new group instead, drop `IntoGroup` and set `env.GroupTemplate`
(a `jsontext.Value` whose `tests` field is absent — the library fills it
in). To create a brand-new file, also set `Algorithm`, `Schema`, and
optionally `Header`.

### B) Add or rewrite a field across existing vectors

```go
env := vectorgen.UpdateEnvelope{
    Source: "github/aws/aws-lc",
    Patches: []jsontext.Value{
        jsontext.Value(`{"tcId": 1, "ek": "..."}`),
        jsontext.Value(`{"tcId": 2, "ek": "..."}`),
    },
    Overwrite: true, // replace existing values
    Partial:   true, // patch a subset
}
err := vectorgen.Update("testvectors_v1/mlkem_512_semi_expanded_decaps_test.json",
    env, vectorgen.Options{})
```

For glob-style multi-file updates, call `Update` once per matching file —
there's no library-level glob helper.

### C) Replace a whole group

```go
env := vectorgen.AddEnvelope{
    GroupTemplate: jsontext.Value(`{
        "type": "MLKEMDecapsValidationTest",
        "source": {"name": "github/lukaszobernig/reenc", "version": "2.0"},
        "parameterSet": "ML-KEM-512"
    }`),
    Tests: []jsontext.Value{ /* new tests */ },
}
filter := vectorgen.ParseSourceFilter("github/lukaszobernig/reenc@1.0")
err := vectorgen.Replace("testvectors_v1/mlkem_512_semi_expanded_decaps_test.json",
    env, filter, vectorgen.Options{})
```

### Other useful entry points

- `vectorgen.ScaffoldAdd(schemaName, opts) ([]byte, error)` — same JSON
  skeleton the CLI produces.
- `vectorgen.LintBytes(data, schemasFS) error` — validate an in-memory
  buffer against a schema; returns sentinel `ErrNoSchema` /
  `ErrIgnoredSchema` for the special cases.
- `vectorgen.FormatBytes(in) ([]byte, error)` — canonical formatter for
  one-off bytes; `FormatFile` / `CheckFormatFile` operate on disk.
- `vectorgen.Options{SchemasFS: os.DirFS("schemas")}` — override the
  embedded `wycheproof.Schemas` (useful when developing schemas alongside
  vectors).

See `tools/example_generator/main.go` for a complete working example using
this library to produce HMAC-SHA256 vectors.
