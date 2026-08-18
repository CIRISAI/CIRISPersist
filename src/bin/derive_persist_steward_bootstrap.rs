//! Emit the canonical bytes CIRISCore signs to produce the
//! persist-steward bootstrap row for v0.2.0's V005 migration.
//!
//! # Workflow
//!
//! 1. CIRISCore generates a fresh Ed25519 keypair for `persist-steward`.
//! 2. CIRISCore hands the **public key** (base64 standard alphabet,
//!    32 raw bytes → 44 base64 chars) to persist's repo.
//! 3. Run this helper:
//!    ```text
//!    PERSIST_STEWARD_PUBKEY_B64="..." cargo run --release \
//!        --features postgres \
//!        --bin derive_persist_steward_bootstrap \
//!        > /tmp/persist-steward-bootstrap.json
//!    ```
//! 4. Hand `/tmp/persist-steward-bootstrap.json` back to CIRISCore.
//!    The `signing_input_base64` field is the EXACT canonical payload
//!    that needs to be signed with the persist-steward Ed25519
//!    **secret** key (the secret never enters this repo). Base64-decode
//!    it and sign the decoded bytes — do NOT sign the base64 text, and
//!    do NOT re-serialize `registration_envelope` on CIRISCore's side.
//!    (The signature it returns is 64 bytes; the payload being signed
//!    is the canonical envelope, which is longer. v37.0.0 corrected a
//!    doc line here that called the payload "the EXACT 64-byte
//!    canonical payload" — that was the signature's length, not the
//!    preimage's, and a ceremony instruction that misstates the
//!    preimage is the same defect class as the one fixed below.)
//! 5. CIRISCore returns the signature (64-byte Ed25519 sig, base64
//!    standard).
//! 6. Replace the `__SCRUB_SIGNATURE_BASE64__` placeholder in
//!    the persist-steward bootstrap record (constructed in code — there is no
//!    `V005__persist_steward_bootstrap.sql` in either migration tree; see
//!    CIRISPersist#680)
//!    (and the SQLite mirror) with the returned signature; commit.
//! 7. Publish the persist-steward fingerprint
//!    (hex SHA-256 of pubkey raw bytes) in `CHANGELOG.md` v0.2.0 entry
//!    and `docs/FEDERATION_DIRECTORY.md` §"Bootstrap" pinning section.
//!
//! # Output shape
//!
//! ```json
//! {
//!   "key_id": "persist-steward",
//!   "pubkey_base64": "<from PERSIST_STEWARD_PUBKEY_B64 env>",
//!   "fingerprint_hex": "<sha256 of raw pubkey bytes>",
//!   "registration_envelope": { ... },
//!   "canonical_envelope_base64": "<base64 of canonical bytes>",
//!   "original_content_hash_hex": "<sha256 of canonical bytes>",
//!   "signing_input_base64": "<EXACT bytes for CIRISCore to sign>",
//!   "valid_from": "...",
//!   "scrub_timestamp": "..."
//! }
//! ```
//!
//! `signing_input_base64` and `canonical_envelope_base64` are the
//! same content for this bootstrap row (the signature is over the
//! canonical envelope bytes; SHA-256 of those bytes is the
//! `original_content_hash` separately committed). CIRISCore signs
//! `signing_input_base64`.
//!
//! # v37.0.0 (CIRISPersist#739) — the ceremony preimage is the PRODUCE GATE, not a local choice
//!
//! **THE SIXTH INSTANCE of the #714 / #716 / #735 canonicalization-parity
//! class, and the only one that mints a TRUST ROOT out of band.**
//!
//! From the v4.15.0 JCS produce flip (`#871`) to v36.x this binary hand-built
//! [`PythonJsonDumpsCanonicalizer`](ciris_persist::verify::canonical::PythonJsonDumpsCanonicalizer)
//! for BOTH commitments it emits — `signing_input_base64`, the bytes an
//! operator signs with a key that never enters this repo, and
//! `original_content_hash_hex`, the value baked into the row's
//! `original_content_hash` column. Meanwhile every Rust verifier of a key
//! registration rebuilds both halves with
//! [`ceg_produce_canonicalize`](ciris_persist::verify::canonical::ceg_produce_canonicalize):
//! `federation::register::verify_key_registration` canonicalizes the
//! `registration_envelope` through the gate at `register.rs:775` and refuses
//! the row at `register.rs:778` if `sha256(gate_bytes) !=
//! original_content_hash`, then hybrid-verifies the scrub signatures over
//! those same gate bytes. `Engine::register_self_federation_key` (instance
//! four of this class, `engine.rs:2996`) mints through the gate. So did every
//! plane except this one.
//!
//! **Why the rule is not a local choice.** The canonicalization epoch is a
//! chain-wide release event routed through ONE `const fn`
//! (`produce_canon_version`) precisely so the flip is a one-line change that
//! cannot leave a plane behind. A site that spells its own canonicalizer has
//! opted out of that mechanism: it is correct only for as long as somebody
//! remembers it exists, and nothing tells them. All six instances of this
//! class were found while fixing the previous one, because each site is
//! *locally reasonable* — it hand-builds a rule that happens to be right for
//! the payload in front of it.
//!
//! **Why it was benign — and why "benign" was an accident, not a property.**
//! `PythonJsonDumpsCanonicalizer` (Python `json.dumps(sort_keys=True,
//! ensure_ascii=True)`) and `ceg_produce_canonicalize` (RFC 8785 JCS at the
//! current produce epoch) agree byte-for-byte on structured ASCII with no
//! ambiguous float tokens. [`steward_registration_envelope`] is a hard-coded
//! ASCII literal, so the two rules agreed and the artifact verified. That
//! accident — not a check, not a test — is what hid instances one through
//! five for versions. It is not a property of the code; it is a property of
//! today's fixture.
//!
//! **What breaks the day the fixture is edited.** A ceremony tool is exactly
//! where a fixture gets edited: a node label, an operator's name, an
//! organisation with an accent in it, a numeric field carrying `1e-05`. On
//! the first such edit the two rules diverge, and then:
//!
//!   * the operator signs V1 bytes; `verify_key_registration` rebuilds JCS
//!     bytes; the hybrid verify fails as a generic signature mismatch that
//!     names the KEY, not the canonicalizer — the misdirection #714's commit
//!     message describes;
//!   * `original_content_hash_hex` is over V1 bytes while the stored envelope
//!     canonicalizes to JCS, so the row is self-inconsistent AT REST and every
//!     peer refuses it with `registration original_content_hash mismatch`;
//!   * and unlike every other instance of this class, **it is not re-mintable
//!     by a running node.** The signing key is held out of band by CIRISCore,
//!     the artifact is a trust root rather than a row, and the ceremony is a
//!     one-shot human event. There is no re-mint path and no detection path
//!     short of the whole mesh refusing the root.
//!
//! Routed through the gate, the bytes the operator signs and the bytes every
//! verifier rebuilds are the same byte sequence by construction. Witnessed by
//! [`canonicalizer_parity_739`] — on a corpus pinned to DIVERGE under the two
//! rules, because a parity assertion over an ASCII corpus passes against the
//! unfixed code and proves nothing.
//!
//! # Verification (after CIRISCore signs)
//!
//! Once you have the signature, verify it locally:
//! ```text
//! python3 -c "
//! import base64; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
//! pk = Ed25519PublicKey.from_public_bytes(base64.b64decode('<pubkey_base64>'))
//! pk.verify(base64.b64decode('<signature_base64>'), base64.b64decode('<signing_input_base64>'))
//! print('OK')
//! "
//! ```
//! Successful verification → the signature is correct → bake into V005.

use std::env;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};

use ciris_persist::verify::canonical::ceg_produce_canonicalize;

/// Bootstrap timestamps: a fixed point at v0.2.0 release time.
/// Pin to a specific date so the row is deterministic across
/// multi-region deploys (every node's V005 inserts the same row).
const BOOTSTRAP_TIMESTAMP: &str = "2026-05-15T00:00:00Z";

/// The ceremony's registration envelope — the JSON object the operator's
/// out-of-band Ed25519 signature covers, and the object whose canonical
/// form is committed as `original_content_hash`.
///
/// Fields chosen to match what consumers already see for other identity
/// types — string-typed for forward compat.
///
/// **If you edit this, read the `#739` section of the module doc first.**
/// It is all-ASCII today, which is the ONLY reason the pre-v37.0.0
/// hand-built canonicalizer produced a verifiable artifact. The code no
/// longer depends on that (it routes through the produce gate), so a
/// non-ASCII edit is now safe — but it is safe *because of the fix*, and
/// the parity witness is what keeps it that way.
fn steward_registration_envelope() -> serde_json::Value {
    serde_json::json!({
        "role": "persist-steward",
        "primitive": "ciris-persist",
        "scope": "federation-directory-substrate",
        "version_introduced": "0.2.0",
        "policy_anchor": "out-of-band-fingerprint-pinning",
    })
}

/// **THE ceremony preimage.** The exact byte sequence the operator signs
/// out of band, and the byte sequence `original_content_hash` commits to.
///
/// v37.0.0 (CIRISPersist#739) — routed through
/// [`ceg_produce_canonicalize`], the single produce-side canonicalization
/// entry point, so this ceremony rides the same signed epoch as every
/// verifier that will ever rebuild these bytes
/// (`federation::register::verify_key_registration`, `register.rs:775`).
/// Before v37.0.0 it hand-built `PythonJsonDumpsCanonicalizer`; see the
/// module doc for what that costs on the first non-ASCII fixture edit.
///
/// Lifted out of `main` as a named function so the parity witness can
/// assert WHICH preimage it produces — a `[[bin]]` whose logic lives
/// entirely inside `main` has no test seam at all, and an untested fix to
/// a trust-root ceremony is not a fix.
fn ceremony_signing_input(
    registration_envelope: &serde_json::Value,
) -> Result<Vec<u8>, ciris_persist::verify::Error> {
    ceg_produce_canonicalize(registration_envelope)
}

/// The SECOND, separate commitment: `original_content_hash`, the hex
/// SHA-256 of the canonical envelope bytes.
///
/// It is a distinct cryptographic commitment from the signature — the
/// registration gate checks it BEFORE it resolves a signer
/// (`register.rs:778`), so a row can fail here with every signature
/// intact. Kept as its own function so the witness can red on a
/// hash-side defect that leaves the signing input correct, and so
/// "fixing the signing input" can never be mistaken for fixing both.
///
/// Note the argument: the SHA-256 is over the **raw canonical bytes**,
/// never over their base64 transport form.
fn ceremony_content_hash_hex(signing_input: &[u8]) -> String {
    hex::encode(Sha256::digest(signing_input))
}

/// Fingerprint: hex-encoded SHA-256 of the raw 32-byte pubkey.
/// This is what consumers pin for out-of-band anchoring (matches
/// the existing trust-contract §3.3 pattern for the registry's
/// own steward key).
///
/// Not a canonicalization site: the preimage is 32 raw key bytes, with no
/// JSON and therefore no epoch to get wrong.
fn steward_fingerprint_hex(pubkey_raw: &[u8]) -> String {
    hex::encode(Sha256::digest(pubkey_raw))
}

/// Assemble the full ceremony artifact. The envelope is a parameter (not
/// read from [`steward_registration_envelope`] directly) so the witness can
/// drive a DIVERGENT envelope through the real assembly path — the wiring
/// between the canonicalizer and the two emitted fields is itself a place
/// this can go wrong.
fn build_bootstrap_artifact(
    pubkey_b64: &str,
    pubkey_raw: &[u8],
    registration_envelope: serde_json::Value,
    timestamp: &str,
) -> Result<serde_json::Value, ciris_persist::verify::Error> {
    let signing_input = ceremony_signing_input(&registration_envelope)?;
    let canonical_b64 = BASE64.encode(&signing_input);
    let original_content_hash_hex = ceremony_content_hash_hex(&signing_input);

    Ok(serde_json::json!({
        "key_id": "persist-steward",
        "pubkey_base64": pubkey_b64,
        "fingerprint_hex": steward_fingerprint_hex(pubkey_raw),
        "algorithm": "ed25519",
        "identity_type": "steward",
        "identity_ref": "persist",
        "registration_envelope": registration_envelope,
        "canonical_envelope_base64": canonical_b64,
        "original_content_hash_hex": original_content_hash_hex,
        // The signing input: the canonical bytes of the registration
        // envelope, as produced by the CEG produce gate. CIRISCore signs
        // THESE bytes with the persist-steward Ed25519 secret. The output
        // is the `scrub_signature` field (base64) baked into V005.
        "signing_input_base64": canonical_b64,
        "valid_from": timestamp,
        "scrub_timestamp": timestamp,
        "scrub_key_id": "persist-steward",
        "_handoff": {
            "step_3_handed_to_ciriscore": [
                "signing_input_base64 (the bytes to sign)",
                "fingerprint_hex (for sanity check after signing)",
            ],
            "step_5_received_from_ciriscore": [
                "scrub_signature_base64 (Ed25519 signature over signing_input_base64)",
            ],
            // v31.3.0 (CIRISPersist#680) — these two paths named files that
            // exist in NEITHER migration tree, and never did: nothing under
            // `migrations/` mentions `persist_steward` at all. V005 is
            // `V005__readonly_role.sql` on postgres and has no sqlite twin.
            // The list described a plan that was not executed the way it was
            // written, and a citation to a phantom file is worse than no
            // citation — it is the thing a reader trusts instead of looking.
            "step_6_baked_into_persist_repo": [
                "NOTE (#680): no migration carries this row. The bootstrap \
                 record is constructed in code, not baked into DDL — see \
                 `federation::types` and the `persist-steward` fixtures.",
                "CHANGELOG.md v0.2.0 entry (publishing fingerprint_hex)",
                "docs/FEDERATION_DIRECTORY.md §\"Bootstrap\" pinning section",
            ],
            // v37.0.0 (CIRISPersist#739) — name the rule in the artifact
            // itself, so the operator holding this JSON can tell which
            // canonicalization their signature covers without reading source.
            "canonicalization": "ceg_produce_canonicalize (RFC 8785 JCS at the \
             current produce epoch) — the SAME rule federation::register::\
             verify_key_registration rebuilds. Sign the base64-DECODED \
             signing_input_base64 verbatim; do not re-serialize \
             registration_envelope.",
        },
    }))
}

fn main() {
    let pubkey_b64 = env::var("PERSIST_STEWARD_PUBKEY_B64").unwrap_or_else(|_| {
        eprintln!(
            "PERSIST_STEWARD_PUBKEY_B64 unset.\n\
             Set to the base64-encoded 32-byte Ed25519 public key for persist-steward,\n\
             generated by CIRISCore."
        );
        std::process::exit(1);
    });

    let pubkey_raw = match BASE64.decode(&pubkey_b64) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("PERSIST_STEWARD_PUBKEY_B64 base64 decode: {e}");
            std::process::exit(1);
        }
    };
    if pubkey_raw.len() != 32 {
        eprintln!(
            "PERSIST_STEWARD_PUBKEY_B64 wrong length: got {} bytes, expected 32 (Ed25519 raw)",
            pubkey_raw.len()
        );
        std::process::exit(1);
    }

    let out = match build_bootstrap_artifact(
        &pubkey_b64,
        &pubkey_raw,
        steward_registration_envelope(),
        BOOTSTRAP_TIMESTAMP,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("canonicalize: {e}");
            std::process::exit(1);
        }
    };

    // Output JSON to stdout. Compact representation — pipe through
    // `jq` if a human is reading.
    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
}

// ─── CIRISPersist#739 — the ceremony canonicalization parity witness ────────

/// v37.0.0 (CIRISPersist#739) — **the bytes this ceremony hands an operator
/// to sign must be the bytes every verifier rebuilds.**
///
/// The SIXTH instance of the #714 / #716 / #735 class, and the only one whose
/// artifact is a trust root minted out of band: there is no re-mint path. See
/// the module doc for the defect and its blast radius.
///
/// # Why an ASCII test proves nothing here
///
/// `PythonJsonDumpsCanonicalizer` and [`ceg_produce_canonicalize`] (RFC 8785
/// JCS at the current produce epoch) agree **byte-for-byte** on structured
/// ASCII with unambiguous float tokens — which is exactly what
/// [`steward_registration_envelope`] is. A witness written over the shipped
/// fixture therefore passes against the UNFIXED code and asserts nothing about
/// canonicalization at all. That silent rot is how instances one through five
/// survived a green suite for versions.
///
/// So every parity assertion below runs over [`divergent_corpus`], and is
/// paired with [`the_divergent_corpus_actually_diverges`] — the anti-vacuity
/// pin, which reds if anyone "simplifies" the fixtures back to ASCII. Modelled
/// on `canonicalizer_parity_735` at the end of `src/ffi/pyo3.rs`.
///
/// # Test seam
///
/// This is a `[[bin]]`. Cargo compiles and runs `#[cfg(test)]` code inside bin
/// targets (`test = true` is the default for a bin), so the seam exists — but
/// only for code reachable from something other than `main`. Pre-v37.0.0 every
/// line of this tool lived inside `main`, so it had NO seam and could not be
/// witnessed at all. The smallest refactor that creates one was applied: the
/// envelope-to-bytes step ([`ceremony_signing_input`]), the hash commitment
/// ([`ceremony_content_hash_hex`]) and the artifact assembly
/// ([`build_bootstrap_artifact`]) are lifted out of `main`, which now does
/// argument validation and printing only.
#[cfg(test)]
mod canonicalizer_parity_739 {
    // Deliberately NO `use super::*`: every reference to the functions under
    // test is spelled `super::` at the call site, so a reader can see which
    // module's rule is being pinned without resolving a glob.
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_persist::verify::canonical::{
        ceg_produce_canonicalize, Canonicalizer, PythonJsonDumpsCanonicalizer,
    };
    use sha2::{Digest, Sha256};

    /// A 32-byte Ed25519 public key in the shape the tool validates, so the
    /// artifact-level tests exercise the real argument path.
    fn fixture_pubkey() -> ([u8; 32], String) {
        let raw = [0x39u8; 32];
        let b64 = B64.encode(raw);
        (raw, b64)
    }

    /// Registration envelopes on which the two canonicalization rules
    /// DISAGREE, in the two ways they can: raw UTF-8 vs `\uXXXX` escapes, and
    /// wire float tokens vs ECMAScript number serialization.
    ///
    /// These are not synthetic for a *ceremony*: a steward bootstrap envelope
    /// names a role, a primitive and a scope, and the next mesh's operator is
    /// as likely to be `Ökologische Föderation` as `persist`. Nothing on this
    /// path enforces ASCII — the whole defect is that nothing had to.
    fn divergent_corpus() -> Vec<serde_json::Value> {
        vec![
            // Non-ASCII in exactly the fields this ceremony's envelope carries.
            serde_json::json!({
                "role": "persist-steward",
                "primitive": "ciris-persist",
                "scope": "föderations-verzeichnis",
                "operator": "Ökologische Föderation — 生態",
                "policy_anchor": "out-of-band-fingerprint-pinning",
            }),
            // Non-ASCII nested BELOW the top level: the divergence is not a
            // top-level-only property, and a ceremony envelope is exactly the
            // shape someone extends with a nested policy block.
            serde_json::json!({
                "role": "persist-steward",
                "policy_blob": {"note": "h\u{00e9}llo", "tier": "commons", "sigil": "⚠️"},
                "version_introduced": "0.2.0",
            }),
            // Non-ES float tokens — unicode is NOT the only divergence axis.
            // `1e-05` and the long decimal are preserved verbatim by
            // serde_json's arbitrary_precision parse and re-serialized per
            // ECMAScript rules by JCS (`1e-5` / `0.003199200000000001`).
            serde_json::from_str::<serde_json::Value>(
                r#"{"role":"persist-steward","quorum_epsilon":1e-05,"weight":0.0031992000000000006}"#,
            )
            .expect("wire float fixture parses"),
        ]
    }

    /// The one envelope the artifact-level witnesses drive end to end.
    fn divergent_envelope() -> serde_json::Value {
        divergent_corpus()
            .into_iter()
            .next()
            .expect("corpus is non-empty")
    }

    /// **The anti-vacuity pin.** Every other test in this module asserts
    /// PARITY between two rules; on an all-ASCII corpus those assertions pass
    /// against the *unfixed* code and prove nothing (a check that cannot fail
    /// is a report). This asserts the corpus actually exercises the V1/V2
    /// divergence — per element, so replacing ANY fixture with an agreeing one
    /// reds HERE rather than silently disarming the module.
    #[test]
    fn the_divergent_corpus_actually_diverges() {
        for env in divergent_corpus() {
            let v1 = PythonJsonDumpsCanonicalizer
                .canonicalize_value(&env)
                .expect("v1 canonicalize");
            let jcs = ceg_produce_canonicalize(&env).expect("jcs canonicalize");
            assert_ne!(
                v1, jcs,
                "fixture must exercise the V1/V2 divergence — an all-agreeing \
                 corpus makes every parity assertion in this module vacuous, \
                 which is how instances 1-5 of this class survived: {env}"
            );
        }
    }

    /// **The corpus covers BOTH divergence axes.** Unicode is the axis
    /// everyone reaches for; the ES-float axis (`1e-05`,
    /// `0.0031992000000000006`) is the one #714's commit message had to spell
    /// out. A corpus that diverges only on unicode would still pass
    /// [`the_divergent_corpus_actually_diverges`] while leaving half the class
    /// unwitnessed, so the two axes are pinned separately.
    #[test]
    fn the_corpus_covers_both_divergence_axes() {
        let non_ascii = divergent_corpus().iter().any(|env| {
            serde_json::to_string(env)
                .expect("fixture serializes")
                .bytes()
                .any(|b| !b.is_ascii())
        });
        assert!(
            non_ascii,
            "corpus must carry a NON-ASCII fixture (the ensure_ascii=True vs raw-UTF-8 axis)"
        );

        // The ES-float axis: an ASCII-only fixture that STILL diverges can
        // only be diverging on number serialization.
        let ascii_only_but_divergent = divergent_corpus().into_iter().any(|env| {
            let ascii = serde_json::to_string(&env)
                .expect("fixture serializes")
                .is_ascii();
            let v1 = PythonJsonDumpsCanonicalizer
                .canonicalize_value(&env)
                .expect("v1");
            let jcs = ceg_produce_canonicalize(&env).expect("jcs");
            ascii && v1 != jcs
        });
        assert!(
            ascii_only_but_divergent,
            "corpus must carry an ASCII-ONLY fixture that still diverges (the \
             non-ES-float-token axis: `1e-05`, `0.0031992000000000006`) — \
             unicode is not the only way these two rules disagree"
        );
    }

    /// **CIRISPersist#739 — the signing input IS the produce gate, not V1.**
    ///
    /// Asserts WHICH preimage [`super::ceremony_signing_input`] produces, by
    /// spelling both candidates out and pinning the match to one and the
    /// mismatch to the other. A right-outcome-through-the-wrong-mechanism pass
    /// is therefore not available to it: an implementation that returned V1
    /// bytes fails the `assert_eq!`, and an implementation that returned some
    /// third rule fails both.
    #[test]
    fn signing_input_is_the_produce_gate_not_v1() {
        for env in divergent_corpus() {
            let actual = super::ceremony_signing_input(&env).expect("ceremony signing input");
            let gate = ceg_produce_canonicalize(&env).expect("gate canonicalize");
            let v1 = PythonJsonDumpsCanonicalizer
                .canonicalize_value(&env)
                .expect("v1 canonicalize");
            assert_ne!(gate, v1, "fixture must diverge or this test cannot fail");

            assert_eq!(
                String::from_utf8_lossy(&actual),
                String::from_utf8_lossy(&gate),
                "the ceremony must hand the operator the bytes \
                 verify_key_registration rebuilds (ceg_produce_canonicalize) — \
                 CIRISPersist#739: {env}"
            );
            assert_ne!(
                actual, v1,
                "and must NOT be PythonJsonDumpsCanonicalizer — that is the \
                 #739 defect, and it mints a trust root nothing can verify: {env}"
            );
        }
    }

    /// **CIRISPersist#739 — the content hash is the SECOND commitment, and it
    /// is over the gate's bytes.**
    ///
    /// `original_content_hash` is checked at `register.rs:778` BEFORE any
    /// signer is resolved, so it can refuse a row whose signatures are all
    /// intact. Fixing the signing input is not automatically fixing this, so
    /// it is asserted separately: the emitted hex must equal
    /// `sha256(ceg_produce_canonicalize(envelope))` — over the RAW canonical
    /// bytes, not their base64 transport form — and must not equal the V1
    /// hash.
    #[test]
    fn content_hash_is_sha256_of_the_produce_gate_bytes_not_v1() {
        for env in divergent_corpus() {
            let signing_input =
                super::ceremony_signing_input(&env).expect("ceremony signing input");
            let actual = super::ceremony_content_hash_hex(&signing_input);

            let gate_hash = hex::encode(Sha256::digest(
                ceg_produce_canonicalize(&env).expect("gate canonicalize"),
            ));
            let v1_hash = hex::encode(Sha256::digest(
                PythonJsonDumpsCanonicalizer
                    .canonicalize_value(&env)
                    .expect("v1 canonicalize"),
            ));
            assert_ne!(
                gate_hash, v1_hash,
                "fixture must diverge or this test cannot fail"
            );

            assert_eq!(
                actual, gate_hash,
                "original_content_hash must be sha256 of the PRODUCE-GATE bytes \
                 — the exact value register.rs:778 recomputes — CIRISPersist#739: {env}"
            );
            assert_ne!(
                actual, v1_hash,
                "and must NOT be the V1 hash: a row whose stored envelope \
                 canonicalizes to JCS while its hash is over V1 is refused by \
                 every peer as `registration original_content_hash mismatch`: {env}"
            );

            // The hash is over the raw bytes, never the base64 transport form.
            let over_b64 = hex::encode(Sha256::digest(B64.encode(&signing_input)));
            assert_ne!(
                actual, over_b64,
                "original_content_hash must be sha256 of the canonical BYTES, \
                 not of their base64 encoding: {env}"
            );
        }
    }

    /// **CIRISPersist#739 — the assembled artifact's two commitments are the
    /// gate's, and they agree with each other.**
    ///
    /// The two tests above pin the helpers; this pins the WIRING, driving a
    /// divergent envelope through the same `build_bootstrap_artifact` call
    /// `main` makes. An artifact that emitted, say, `serde_json::to_string`
    /// of the envelope as `signing_input_base64` — the plainest way to get
    /// this wrong — would pass both helper tests and fail here.
    #[test]
    fn artifact_emits_the_gate_preimage_and_the_gate_hash() {
        let (raw, b64) = fixture_pubkey();
        let envelope = divergent_envelope();
        let gate = ceg_produce_canonicalize(&envelope).expect("gate canonicalize");
        let v1 = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&envelope)
            .expect("v1 canonicalize");
        assert_ne!(gate, v1, "fixture must diverge or this test cannot fail");

        let art = super::build_bootstrap_artifact(
            &b64,
            &raw,
            envelope.clone(),
            super::BOOTSTRAP_TIMESTAMP,
        )
        .expect("artifact builds");

        let signing_input_b64 = art["signing_input_base64"]
            .as_str()
            .expect("signing_input_base64 is a string");
        let signing_input = B64
            .decode(signing_input_b64)
            .expect("signing_input_base64 decodes");
        assert_eq!(
            String::from_utf8_lossy(&signing_input),
            String::from_utf8_lossy(&gate),
            "signing_input_base64 must decode to the produce-gate bytes — CIRISPersist#739"
        );
        assert_ne!(
            signing_input, v1,
            "signing_input_base64 must NOT decode to the V1 bytes"
        );

        assert_eq!(
            art["original_content_hash_hex"]
                .as_str()
                .expect("original_content_hash_hex is a string"),
            hex::encode(Sha256::digest(&gate)),
            "original_content_hash_hex must be sha256 of the produce-gate bytes"
        );

        // canonical_envelope_base64 and signing_input_base64 are documented as
        // the same content; a ceremony that drifted them apart would have the
        // operator sign one thing while the artifact publishes another.
        assert_eq!(
            art["canonical_envelope_base64"].as_str(),
            art["signing_input_base64"].as_str(),
            "canonical_envelope_base64 and signing_input_base64 must be the same bytes"
        );

        // The envelope is republished VERBATIM — it is what a verifier
        // re-canonicalizes, so any rewrite between hashing and publishing is
        // the self-inconsistent-at-rest failure in another costume.
        assert_eq!(
            art["registration_envelope"], envelope,
            "the artifact must publish the exact envelope it canonicalized"
        );

        assert_eq!(
            art["fingerprint_hex"].as_str().expect("fingerprint_hex"),
            hex::encode(Sha256::digest(raw)),
            "fingerprint is sha256 over the RAW 32 pubkey bytes"
        );
    }

    /// **CIRISPersist#739 — end to end: a signature over what this tool emits
    /// verifies against what a verifier rebuilds.**
    ///
    /// Plays the ceremony out with a deterministic key: base64-decode
    /// `signing_input_base64`, Ed25519-sign it exactly as CIRISCore does with
    /// the secret half, then verify the way `verify_key_registration` does —
    /// by re-canonicalizing the PUBLISHED `registration_envelope` through the
    /// gate and checking the signature over THOSE bytes, rather than over the
    /// bytes the tool handed out. That distinction is the whole defect: pre-fix
    /// the two are different byte sequences on this envelope, so the verify
    /// leg fails and the negative leg below shows exactly what fails with it.
    #[test]
    fn a_signature_over_the_emitted_input_verifies_against_the_rebuilt_bytes() {
        use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

        let (raw, b64) = fixture_pubkey();
        let envelope = divergent_envelope();
        let art = super::build_bootstrap_artifact(
            &b64,
            &raw,
            envelope.clone(),
            super::BOOTSTRAP_TIMESTAMP,
        )
        .expect("artifact builds");

        // CIRISCore's side: sign the decoded signing input, nothing else.
        let sk = SigningKey::from_bytes(&[0x73; 32]);
        let emitted = B64
            .decode(art["signing_input_base64"].as_str().expect("str"))
            .expect("decodes");
        let sig = sk.sign(&emitted);

        // The verifier's side: rebuild from the PUBLISHED envelope.
        let published = art["registration_envelope"].clone();
        let rebuilt = ceg_produce_canonicalize(&published).expect("verifier rebuild");
        sk.verifying_key().verify(&rebuilt, &sig).expect(
            "a signature over the ceremony's signing_input MUST verify against the \
             bytes a verifier rebuilds from the published envelope — CIRISPersist#739",
        );

        // And the negative leg, so this cannot pass by the two rules agreeing:
        // the V1 rebuild — what the pre-fix tool would have had the operator
        // sign — is refused against this same signature.
        let v1_rebuilt = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&published)
            .expect("v1 rebuild");
        assert_ne!(
            rebuilt, v1_rebuilt,
            "fixture must diverge or the negative leg below is vacuous"
        );
        assert!(
            sk.verifying_key().verify(&v1_rebuilt, &sig).is_err(),
            "the V1 rebuild must NOT verify — if it did, this fixture is not \
             exercising the divergence and the whole module is a report"
        );
    }

    /// **The shipped fixture is wired correctly** — a consistency check on the
    /// artifact `main` actually emits.
    ///
    /// Deliberately NOT a canonicalization witness: [`super::steward_registration_envelope`]
    /// is all-ASCII, so V1 and JCS agree on it and this test passes against the
    /// unfixed code. It is here to catch a WIRING regression on the real
    /// ceremony payload (hash over the wrong buffer, envelope rewritten after
    /// hashing), and it is documented as vacuous-on-canonicalization so nobody
    /// later mistakes it for the parity witness and deletes the divergent
    /// corpus.
    #[test]
    fn the_shipped_ceremony_fixture_is_internally_consistent() {
        let (raw, b64) = fixture_pubkey();
        let envelope = super::steward_registration_envelope();
        let art = super::build_bootstrap_artifact(
            &b64,
            &raw,
            envelope.clone(),
            super::BOOTSTRAP_TIMESTAMP,
        )
        .expect("artifact builds");

        let gate = ceg_produce_canonicalize(&envelope).expect("gate canonicalize");
        assert_eq!(
            B64.decode(art["signing_input_base64"].as_str().expect("str"))
                .expect("decodes"),
            gate,
        );
        assert_eq!(
            art["original_content_hash_hex"].as_str().expect("str"),
            hex::encode(Sha256::digest(&gate)),
        );
        assert_eq!(art["key_id"].as_str(), Some("persist-steward"));
        assert_eq!(art["scrub_key_id"].as_str(), Some("persist-steward"));
        assert_eq!(art["valid_from"].as_str(), Some(super::BOOTSTRAP_TIMESTAMP));
        assert_eq!(
            art["scrub_timestamp"].as_str(),
            Some(super::BOOTSTRAP_TIMESTAMP)
        );
    }
}
