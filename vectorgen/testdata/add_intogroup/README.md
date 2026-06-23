# add_intogroup

Fixture for `TestAddIntoGroup`. Exercises `vectorgen.Add` with
`env.IntoGroup` set: a single test is appended to an existing group identified
by its `source.name`, without creating a new group.

- `before.json` — the file at commit `44dcf46` (i.e. the post-PR-#254 state,
  with the re-encryption group already present). The test appends one more
  vector into that group.
- `mlkem_semi_expanded_decaps_test_schema.json`, `common.json` — schemas
  matching the post-PR-#254 state (the `ek`/`K` field additions are not in
  the embedded schemas).
