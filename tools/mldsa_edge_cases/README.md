# ML-DSA edge-case generator

This generator maintains the ML-DSA signing and verification vectors whose
comments describe edge cases and high-water marks in `ExpandA`, `ExpandS`,
`RejNTTPoly`, `RejBoundedPoly`, `SampleInBall`, and `Power2Round`. It updates
the matching seed, semi-expanded-key, and verify groups together.

The searches are implemented directly from FIPS 204. The implementation
includes key generation, polynomial arithmetic, deterministic signing through
challenge generation, `SampleInBall`, and `Power2Round`. In particular, it
uses the final key-generation domain separation:

```
SHAKE256(xi || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128)
```

Run a deterministic search without changing files:

```
GOEXPERIMENT=jsonv2 go run ./tools/mldsa_edge_cases
```

Regenerate the vectors in place:

```
GOEXPERIMENT=jsonv2 go run ./tools/mldsa_edge_cases -write
```

Writing requires OpenSSL 3.5 or newer with ML-DSA enabled. OpenSSL is used only
to materialize the public and semi-expanded private keys and deterministic
signatures after the independent search. The generator checks OpenSSL's public
key and signature challenge against its FIPS 204 implementation, and verifies
each signature. The resulting files are formatted and schema-validated with
the repository's `vectorgen` package before they are written.

The ML-DSA-65 third-block searches require the long `RejBoundedPoly` stream to
belong to s1. This makes the resulting public key and signature sensitive to
corruption after the second SHAKE256 rate block.

When only test fields change within an existing group, the generator preserves
the group's original source. It assigns its own source only when it replaces
the group's key material.
