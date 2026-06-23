# add_pr254c2

Fixture for `TestAddRecreatesPR254Commit2`. Recreates the second commit of
[PR #254](https://github.com/C2SP/wycheproof/pull/254) (re-encryption test
vectors appended to `mlkem_512_semi_expanded_decaps_test.json`).

- `before.json` — the file at commit `f0b4b70` (post-ek/K, 7 tests, no
  re-encryption group yet).
- `envelope.json` — distilled from commit `44dcf46`'s diff: the new group's
  template, its two tests (with tcIds stripped), and the new
  `MalleableCiphertext` notes entry.
- `after.json` — the file at commit `44dcf46`. Asserted byte-equal to the
  output of `vectorgen.Add(before, envelope)`.
- `mlkem_semi_expanded_decaps_test_schema.json`, `common.json` — schemas at
  commit `f0b4b70`, needed because the embedded schemas in `wycheproof`
  predate the `ek`/`K` additions.
