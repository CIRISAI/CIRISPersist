//! v31.0.0 (CIRISPersist#645) — **the signature-covered envelope columns must
//! round-trip byte-exact, on every backend.**
//!
//! # What went wrong
//!
//! Eleven columns holding producer-signed envelopes were `JSONB` on Postgres
//! and `TEXT` on SQLite. `JSONB` is not a byte-preserving container: it parses
//! numbers into `numeric`, which discards exponent notation. Measured through
//! the real `put_public_key` → `lookup_public_key` path before V122 landed:
//!
//! ```text
//! submitted: {…,"exp":1e+2,…,"neg":1.5e-3,…}
//! reloaded:  {…,"exp":100,…,"neg":0.0015,…}
//! ```
//!
//! and with it, [`crate::federation::wire_index::content_hash_of`] moved from
//! `bf61b57c…` to `a6b819b3…`. That hash is deliberately
//! `sha256(serde_json::to_vec(record))` with **no** canonicalization step —
//! its whole design is that persist's hash equals CIRISEdge's by construction
//! because both sides hash the same bytes. A storage container that rewrites
//! those bytes breaks the identity: persist advertises `H`, a peer fetches by
//! `H`, and the record persist reloads no longer hashes to `H`.
//!
//! V105 had already written the rule down — "TEXT (not JSONB) for
//! signed_envelope: the envelope must round-trip BYTE-EXACT for re-publish,
//! and JSONB does not preserve the producer's serialization" — and V112
//! followed it. V122 retrofits the eleven planes that predate it.
//!
//! # v31.0.0 (CIRISPersist#647) — the claimed property moved
//!
//! The witnesses below no longer claim byte-identity with the PRODUCER. They
//! claim byte-identity with `ceg_produce_canonicalize(submitted)`, because
//! [`crate::federation::canonical_at_rest::canonicalize_in_place`] replaces
//! the envelope with its JCS form at every `put_*` chokepoint.
//!
//! Nothing here is weakened. V105's requirement was always byte-exactness
//! **through our storage**, not byte-identity **with the producer** — and it
//! is still V122's TEXT column that delivers it: `jsonb` would rewrite even
//! canonical bytes (`1e+21` renders as `1000000000000000000000` through
//! `numeric`). What the change adds is the operator-facing property #647
//! exists for, asserted here on all three backends:
//! `sha256sum(column) == original_content_hash`
//! (`test_support::assert_column_sha256_is_original_content_hash`).
//!
//! # Why the shared body exists
//!
//! The bug was **exactly** a backend divergence: the SQLite leg was correct all
//! along, so any witness that ran on one backend proved nothing about the
//! other. `test_support::exercise_envelope_byte_exactness` therefore takes a
//! `&dyn FederationDirectory` and is run identically by both SQL suites; the
//! parity assertion IS one body over two backends.
//!
//! # v62.0.0 (JSON cut, E5) — the witnesses are retired
//!
//! Every witness here measured the earlier form: a producer's JSON envelope,
//! signed over its JCS image, kept byte-exact in a TEXT column so that
//! `sha256sum(column) == original_content_hash` and the wire content hash
//! survived storage. An edition-2 row is its CBOR statement (kept as bytes in
//! `ceg_statements`); the envelope column is the door's mapping of it, and a
//! producer's number tokens (`1e+2`, `1.5e-3`) cannot be carried by a
//! statement at all. The fixture (`AWKWARD_ENVELOPE_JSON`), the shared body
//! (`test_support::exercise_envelope_byte_exactness`, run by the sqlite and
//! postgres suites) and the two JCS-measurement unit tests are deleted.
