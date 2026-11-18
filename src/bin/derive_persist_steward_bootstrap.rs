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
//! `canonicalizer_parity_739` (deleted in v62: the JSON ceremony's
//! canonicalization is earlier-form) — on a corpus pinned to DIVERGE under the two
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
