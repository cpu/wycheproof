# add_pr255

Fixture for `TestAddRecreatesPR255`. Recreates the new vector file added by
[PR #255](https://github.com/C2SP/wycheproof/pull/255), demonstrating the
"create from scratch" path of `vectorgen.Add` (no `before.json` — the target
does not exist).

- `envelope.json` — the entire file metadata bundled with the test data:
  algorithm, schema, header, groupTemplate, tests (tcIds stripped), notes.
- `after.json` — the file at commit `1812c93` from PR #255. Asserted
  byte-equal to the output of `vectorgen.Add`.

This fixture uses the embedded `mldsa_verify_schema.json` from
`wycheproof.Schemas` (no local schema copy needed; the schema is unchanged
between the embedded snapshot and the PR).
