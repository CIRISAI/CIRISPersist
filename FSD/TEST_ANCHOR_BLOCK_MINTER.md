# FSD — the test-anchor block minter lives in persist (CIRISPersist#805)

**Release:** v47.4.0 (MINOR: new `test-anchor`-gated public surface; one new env var read; one new log line at an existing rejection; no migration, no ABI move).
**Ask (CIRISServer, corrected 2026-09-04):** three consumers each rolled a minter for the six-value `CIRIS_TEST_TRUST_ROOT*` block; one signed a two-key literal that had **never** rooted, and nothing at boot could tell — the failure surfaced months later as `rooting_unsigned_provenance_link` with the detail (`link test-accord-holder-0: classical scrub-signature did not verify`) produced and dropped.

## 1. What is true today

- `genesis::test_anchor_registration_envelope(key_id, ed_pub, ml_pub)` builds the terminus envelope (`{"test_anchor": true}` + the #659 subject binding: `key_id`, `identity_type`, both pubkeys). `genesis::test_anchor_genesis_records()` reads `CIRIS_TEST_TRUST_ROOT` (comma-separated Ed25519 pubkeys, via verify-core's `test_trust_root_override`, which also requires `CIRIS_TESTING_MODE`), `_PQC`, `_SCRUB`, `_SCRUB_PQC` per slot and seeds one `accord_holder` record per slot with the env-supplied scrub — **verifying nothing**. A missing scrub becomes the literal `test-anchor-placeholder`.
- The **minter** — derive the keys from `CIRIS_TEST_TRUST_ROOT_SEED`, build persist's envelope, canonicalize, sign Ed25519 over the canonical bytes and ML-DSA-65 over `canonical ‖ ed_sig` — exists in CIRISEdge (`tests/anchor_block_generate.rs`, correct) and existed in CIRISServer (`examples/test_anchor_env.rs`, wrong, deleted). Only persist knows the right answer: the envelope shape and the canonicalization are persist's, the signature primitives are the pinned verify's.
- The ML-DSA seed is derived, by convention in both consumers, as `SHA-256("ciris-test-trust-root/mldsa/v1" ‖ ed_seed)`. Persist does not own that string today; it must, or the PQC half of a re-mint drifts.
- `rooting::root_binding_anchored` produces `RootingVerdict::Rejected { rejection }` at eight sites; the rejection carries the failing link and verify's text. Persist logs nothing there. The Python `provenance_chain` renders `format!("provenance_chain: {}", rej.kind())` — the detail is dropped at the FFI.

## 2. The rule

**There is one correct block per persist+verify pair, and persist mints it.** A consumer that carries a block carries persist's bytes; a block that does not verify under the running pair is said so at boot, in words that name the fix.

## 3. The structure

### 3.1 The minter (`federation::genesis`, `#[cfg(feature = "test-anchor")]`)
```rust
pub const TEST_ANCHOR_MLDSA_SEED_DOMAIN: &[u8] = b"ciris-test-trust-root/mldsa/v1";
pub fn test_anchor_mldsa_seed(ed_seed: &[u8; 32]) -> [u8; 32];          // SHA-256(domain ‖ ed_seed)
pub struct TestAnchorHolder { key_id, root, pqc, scrub, scrub_pqc, seed } // all base64 as the env carries them
pub struct TestAnchorBlock { holders: Vec<TestAnchorHolder>, minted_by: String }
pub fn mint_test_anchor_block(ed_seeds: &[[u8; 32]]) -> Result<TestAnchorBlock, Error>;
impl TestAnchorBlock {
    pub fn env_pairs(&self) -> Vec<(&'static str, String)>;  // the SEVEN vars, slots comma-joined
    pub fn compose_lines(&self) -> String;                   // `  KEY: "value"` per var, compose-ready
}
// (no `apply_to_env`: the #738 hygiene gate forbids src/ code that mutates the anchor
//  environment; a harness sets the seven `env_pairs()` itself, in its own process)
pub fn test_anchor_minted_by() -> &'static str;              // "persist vX.Y.Z / verify vA.B.C"
```
Holder `i` is `test-accord-holder-{i}` (the seeder's naming). `mint` is pure (no directory, no clock): Ed25519 from the seed, ML-DSA-65 from `test_anchor_mldsa_seed`, the envelope from `test_anchor_registration_envelope`, `ceg_produce_canonicalize`, `ed.sign(canonical)`, `mldsa.sign(canonical ‖ ed_sig)`. For one holder and the seed `AQID…HyA=` this reproduces CIRISEdge's minter and the block in CIRISServer's `harness/mesh-repro/docker-compose.yml` byte-for-byte on the Ed25519 side (I159 pins it); the ML-DSA signature is randomized and is pinned by verification, not equality.

`test_anchor_minted_by()` = `env!("CARGO_PKG_VERSION")` + the `ciris-verify-core` `tag` parsed at first use from persist's own `Cargo.toml` (`include_str!`), so the pair a block was minted against is the pair that compiled the minter — never a hand-typed string.

### 3.2 The seventh value, and what the seeder says at boot
`CIRIS_TEST_TRUST_ROOT_MINTED_BY: "persist vX / verify vY"`. `test_anchor_genesis_records()` now, per slot:
- **Structural** (the one that cannot lie): when a `_SCRUB` is supplied, hybrid-verify it (`verify::hybrid::verify_hybrid`) over the canonical envelope against the slot's pubkeys. If it does not verify: `tracing::warn!(target: TEST_ANCHOR_LOG_TARGET, key_id, detail, "…does not verify under this persist/verify pair — re-mint: cargo run --example mint_test_anchor --features test-anchor")`. The record is still seeded (the rooting walk is the gate; a harness that wants to *see* the rejection must still be able to boot).
- **Advisory:** when `_MINTED_BY` is present and differs from `test_anchor_minted_by()`: one `warn!` naming both. Absent: silent (every existing block predates the tag).

### 3.3 The rejection detail is logged where the verdict is produced
`root_binding_anchored` becomes a shell around `root_binding_anchored_inner`; on `Rejected` it emits one `tracing::warn!(target: ROOTING_LOG_TARGET, key_id, kind = rejection.kind(), detail = ?rejection, "root_binding rejected")`. Every caller — the announce-admit path, the FFI, the Server pin — gets the line without touching their code. The Python `provenance_chain` error keeps its prefix (`provenance_chain: <kind>`) and appends `: {rejection:?}`.

### 3.4 The example
`examples/mint_test_anchor.rs` (`required-features = ["test-anchor"]`): `cargo run --example mint_test_anchor --features test-anchor [seed_b64…]` prints `compose_lines()`; no argument uses the consumers' shared seed `AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=`, so the printed block is the one every harness already carries, plus the seventh line.

## 4. Invariants (RED first; sqlite through an Engine where a directory is needed; env tests `#[serial]` with the seven vars restored)

- **I159 — one block per pair, and it is the consumers' block.** `mint_test_anchor_block(&[seed_0102…20])`: `holders[0].key_id == "test-accord-holder-0"`, `root == "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ="`, `scrub == "ZOkeMQA9qWCJTjzCn9osJLwedBxvg0y+dusOp9bErJZKbZDouYSq3DWwGyXH3BpquFtBwRAeIb6502i+Ffi8Bg=="`, `pqc` = the compose value (pinned by SHA-256), `scrub_pqc` hybrid-verifies with the Ed25519 half; `seed` round-trips; `compose_lines()` has exactly the seven keys in order; two holders yield comma-joined slots that `test_anchor_genesis_records` splits back into two records.
- **I160 — a minted block roots.** Apply the block to env; `test_anchor_genesis_records()` yields one record whose scrub hybrid-verifies and emits **no** warn on `TEST_ANCHOR_LOG_TARGET`; an `Engine` on `sqlite::memory:` seeds `test-accord-holder-0`, and `root_binding(dir, …)` is `Confirmed`.
- **I161 — a stale block is named at boot, and the rejection carries its detail.** The Server shape that never rooted (the same seed signing the two-key literal `{"key_id","test_anchor"}`): the seeder warns on `TEST_ANCHOR_LOG_TARGET` with `key_id`, a `detail`, and the re-mint hint; `root_binding` is `Rejected { UnsignedProvenanceLink { key_id: "test-accord-holder-0", detail } }` with `detail` containing `did not verify`, and one warn on `ROOTING_LOG_TARGET` carries `kind = rooting_unsigned_provenance_link` and that detail.
- **I162 — the minted-by tag.** `test_anchor_minted_by()` = `persist v<CARGO_PKG_VERSION> / verify v16.1.0` (the tag in `Cargo.toml`); a block carries it as the seventh value; the seeder is silent when the env tag equals it or is absent, and warns naming both when it differs.

Mutants planned: the ML-DSA domain string changed (I159: PQC pubkey pin); ML-DSA signed over `canonical` alone (I159/I160: verify fails); the seeder's structural check dropped (I161 no warn); the check reading the placeholder as a verifying scrub (I160 warns); the rooting warn dropped (I161); `minted_by` from a literal (I162 after a version bump — recorded as the reason it is derived); `apply_to_env` skipping `CIRIS_TESTING_MODE` (I160 seeds nothing).

## 5. Verification

### 5.1 Mutation round (v47.4.0, wt-805 at 8d76c411; lane = I159/I162 in-crate + `test_anchor_block_805` (own process), features `test-anchor,sqlite`; each mutant reverted before the next)

| # | Mutant | Verdict | Killed by |
|---|--------|---------|-----------|
| M1 | ML-DSA seed domain changed | KILLED | i159_the_minter_reproduces_the_consumers_block |
| M2 | ML-DSA signed over canonical alone (not canonical ‖ ed_sig) | KILLED | i159_the_minter_reproduces_the_consumers_block i160_a_minted_block_roots i162_the_minted_by_tag_is_checked_at_boot |
| M3 | seeder structural check dropped | KILLED | i161_a_stale_block_is_named_at_boot_and_the_rejection_carries_detail |
| M4 | rooting warn loses the detail | KILLED | i161_a_stale_block_is_named_at_boot_and_the_rejection_carries_detail |
| M5 | rooting warn loses the kind | KILLED | i161_a_stale_block_is_named_at_boot_and_the_rejection_carries_detail |
| M6 | minted_by from a literal | KILLED | i162_minted_by_is_the_compiled_pair |
| M7 | minted-by check dropped | KILLED | i162_the_minted_by_tag_is_checked_at_boot |
| M8 | env_pairs arms CIRIS_TESTING_MODE=false | KILLED | i160_a_minted_block_roots i161_a_stale_block_is_named_at_boot_and_the_rejection_carries_detail i162_the_minted_by_tag_is_checked_at_boot |
| M9 | holder naming off by one | KILLED | i159_the_minter_reproduces_the_consumers_block i160_a_minted_block_roots i162_the_minted_by_tag_is_checked_at_boot |
| M10 | envelope minted without the PQC pubkey | KILLED | i159_the_minter_reproduces_the_consumers_block i160_a_minted_block_roots i162_the_minted_by_tag_is_checked_at_boot |

10 of 10 killed. Not mutated: the placeholder scrub (`test-anchor-placeholder`, written when no `_SCRUB` is supplied) is not verified and never was — a block without scrubs is the pre-#545 shape and is left to the walk; the structural check runs only for a SUPPLIED scrub.

## 6. Not in scope
- Removing the consumers' copies (CIRISEdge#…, CIRISServer#… — filed at ship).
- Refusing a non-verifying block at seed time: the rooting walk is the gate; the seeder reports.
- Any change to what `test_trust_root_override` accepts.
