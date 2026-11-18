//! Genesis-seeded `federation_keys` rows — the HUMANITY_ACCORD holder
//! rooting anchor (CIRISPersist#347, v12.0.2).
//!
//! Since v12.0.0 ([[rooting]]) `root_binding` roots a peer only if its
//! provenance chain terminates at a self-signed row whose Ed25519 pubkey is
//! one of the pinned HUMANITY_ACCORD holder keys
//! ([`ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor`]).
//! But those anchor **rows** were never seeded — deferred through v12.0.0 /
//! v12.0.1 — so a fresh node rooted nothing.
//!
//! This module **bakes the already-signed holder records** produced by the
//! real 3-holder FIPS-YubiKey ceremony (CIRISPersist#268, v9.11.0; captured
//! to the CEG outbox) and first-boot-seeds them into `federation_keys`. It is
//! a *bake-what-exists* step — no new ceremony, no new signatures. Each record
//! is a self-signed `accord_holder` [`SignedKeyRecord`] (A1/B1/C1) whose
//! Ed25519 pubkey equals the anchor and whose scrub-signature verifies over
//! its canonical `registration_envelope` — satisfying all four
//! `root_binding` terminus requirements as-is.
//!
//! **Genesis-trusted admission.** The seed bypasses the per-registration
//! `accord_holder` 24 h fresh-nonce hardware-attestation gate: that gate is a
//! replay defense for *ongoing* registrations, and the pinned ceremony bake IS
//! the trust root — re-verifying its nonce freshness at every boot is a
//! category error (the records carry no per-registration `attestation_evidence`
//! anyway; the custody proof is the separate #268 CEG artifact). See
//! `SqliteBackend::seed_genesis_accord_holders` / the Postgres twin.

pub mod bundle;
// v62.0.0 (json-cut, slice C5): the bundle/1 ceremony assembler (`ceremony`),
// its outputs verifier (`ceremony_verify`), the amend (`amend`), the
// per-backend replay scratch (`scratch`) and the software ceremony minter
// (`test_ceremony`) are deleted. A genesis bundle is a `ceg-genesis-bundle/2`
// statement set read by Verify (`edition2::genesis`).
/// v47.4.0 (CIRISPersist#805) — the `CIRIS_TEST_TRUST_ROOT*` block minter.
#[cfg(feature = "test-anchor")]
pub mod test_anchor_block;
// TODO(json-cut C5): remove after E flip — the bundle/1 type and its reader
// stay only while the boot seed and the test call sites read the baked seed.
pub use bundle::{
    check_serve_transport_destinations, parse_genesis_bundle, verify_bundle_quorum,
    GenesisAuthorization, GenesisBundle, GenesisRosterRecord, GENESIS_BUNDLE_VERSION,
    SERVE_TRANSPORT_DESTINATIONS_VERSION, SERVE_TRANSPORT_DESTINATION_INVALID,
};
#[cfg(feature = "test-anchor")]
pub use test_anchor_block::*;

pub mod posture;
/// v53.1.0 — a bundle's roster records (the boot seed's accord-head rule; the
/// bundle/1 import door is deleted in v62.0.0).
pub mod roster_install;
pub use posture::{
    constitutional_seat, genesis_posture, require_constitutional_root, AbsentReason,
    BakeNotAdoptedReason, GenesisFault, GenesisLeg, GenesisPosture, ROOT_REQUIRING_GATES,
};
pub use roster_install::{
    bundle_accord_genesis, install_accord_genesis_head, RosterRecordOutcome, RosterSource,
};

use super::SignedKeyRecord;

/// The baked HUMANITY_ACCORD holder records (A1/B1/C1) — the #268 ceremony's
/// self-signed `accord_holder` `SignedKeyRecord`s, embedded verbatim. Source
/// of truth: `CIRISVerify/accord_ceremony_artifacts/holders/{A1,B1,C1}.json`
/// (`holder_record`), whose Ed25519 pubkeys equal
/// `accord_holder_bootstrap_anchor()`.
const ACCORD_HOLDER_SEED_JSON: &str = include_str!("accord_holder_seed.json");

/// Parse-once accessor for the baked HUMANITY_ACCORD holder genesis records.
///
/// # Panics
///
/// Panics if the embedded JSON is malformed — a build-time-checked constant, so
/// a panic here means the resource was corrupted in the tree (caught by
/// [`tests::accord_holder_seed_parses_and_matches_anchor`]).
pub fn accord_holder_genesis_records() -> &'static [SignedKeyRecord] {
    use std::sync::OnceLock;
    static PARSED: OnceLock<Vec<SignedKeyRecord>> = OnceLock::new();
    PARSED.get_or_init(|| {
        serde_json::from_str(ACCORD_HOLDER_SEED_JSON)
            .expect("embedded accord_holder_seed.json must be valid [SignedKeyRecord]")
    })
}

/// v31.0.0 (CIRISVerify 13.1.0) — **THE PINNED TEST-ANCHOR PREIMAGE, as a
/// function instead of a sentence.**
///
/// The `CIRIS_TEST_TRUST_ROOT_SCRUB[_PQC]` contract has always been a preimage
/// two repos must agree on byte-for-byte, and until this cut it was pinned only
/// in prose — with the literal `{"key_id": …, "test_anchor": true}` written out
/// THREE times (here, in the #451 e2e, and in CIRISServer's harness). 13.1.0
/// added `identity_type` and both pubkeys to the provenance-link subject
/// binding, so the literal moved, and every copy that did not move became a
/// terminus that cannot root. Exporting the envelope makes the next move one
/// edit and gives the harness something to CALL rather than transcribe.
///
/// Callers sign `JCS(...)` of the returned object: classical = Ed25519 over
/// those bytes, PQC = the bound hybrid form (`SelfSigner::sign_bound`) over the
/// same bytes.
#[cfg(feature = "test-anchor")]
#[must_use]
pub fn test_anchor_registration_envelope(
    key_id: &str,
    pubkey_ed25519_base64: &str,
    pubkey_ml_dsa_65_base64: Option<&str>,
) -> serde_json::Value {
    let mut envelope = serde_json::json!({ "test_anchor": true });
    crate::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        crate::federation::types::identity_type::ACCORD_HOLDER,
        pubkey_ed25519_base64,
        pubkey_ml_dsa_65_base64,
        // v38.7.0 (CIRISVerify v14.0.0) — the FIFTH member, and deliberately
        // `None` here. A test anchor carries no expiry FIELD because its
        // lifetime is not a date: it is bounded by the runtime AND-gate and
        // the anti-prod tripwire in verify's `test_trust_root_override`, which
        // a `valid_until` in the bytes could only weaken by suggesting the
        // anchor is good until then. `None` also keeps these bytes IDENTICAL
        // to the pre-v14 envelope, so the two transcribed copies this doc
        // names (the #451 e2e and CIRISServer's harness) still root against it
        // without re-transcription — but only because
        // `bind_subject_into_envelope` OMITS an absent optional. Verify's
        // `require_optional` MATERIALIZES `null`, which is right for a
        // checking projection and wrong inside a preimage; the pin in
        // `test_anchor_envelope_member_set_is_pinned_v14` is what holds that
        // distinction still.
        None,
    )
    .expect("the synthesized test-anchor envelope is a JSON object");
    envelope
}

/// The synthesized test-anchor holder row for one slot — the ONE spelling,
/// shared by [`test_anchor_genesis_records`] (slots read from the env) and
/// the dry-run ceremony minter (slots taken from a minted block,
/// CIRISPersist#973), so a bundle's carried holders are byte-for-byte the
/// rows the boot seed installs.
#[cfg(feature = "test-anchor")]
pub(crate) fn test_anchor_holder_record(
    key_id: &str,
    pubkey_ed25519_base64: String,
    pqc_pubkey: Option<String>,
    envelope: serde_json::Value,
    canonical: &[u8],
    scrub_ed: Option<String>,
    scrub_pqc: Option<String>,
) -> SignedKeyRecord {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let ts: chrono::DateTime<chrono::Utc> = ACCORD_FAMILY_FOUNDED_AT
        .parse()
        .expect("ACCORD_FAMILY_FOUNDED_AT is a valid RFC-3339 constant");
    SignedKeyRecord {
        record: crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64,
            pqc_completed_at: pqc_pubkey.as_ref().map(|_| ts),
            pubkey_ml_dsa_65_base64: pqc_pubkey,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::ACCORD_HOLDER.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: ts,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(canonical)),
            scrub_signature_classical: scrub_ed
                .unwrap_or_else(|| B64.encode(b"test-anchor-placeholder")),
            scrub_signature_pqc: scrub_pqc,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: ts,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            // The V-schema requires accord_holder rows to CARRY evidence;
            // this is the SoftwareOnly_TEST custody marker (the tier
            // verify's accord_custody_attestation admits under the same
            // gate, CIRISVerify#202) — honest about what it is, never a
            // fabricated hardware claim.
            attestation_evidence: Some(serde_json::json!({
                "tier": "SoftwareOnly_TEST",
                "test_anchor": true,
            })),
            consent_role: None,
            additional_scrubs: Vec::new(),
        },
    }
}

/// v17.1.0 (CIRISPersist#449, CIRISVerify#202) — the SYNTHESIZED test-anchor
/// holder rows: one deterministic self-signed `accord_holder` record per
/// `CIRIS_TEST_TRUST_ROOT` pubkey (`test-accord-holder-{i}`), so the genesis
/// seed is self-consistent with verify's SWAPPED live anchor under
/// [`test_anchor_active`](ciris_verify_core::test_anchor::test_anchor_active).
/// `None` whenever the mode is off (the shared runtime AND-gate + anti-prod
/// tripwire live in verify's `test_trust_root_override`; persist consults it
/// rather than re-parsing the env, so the two crates cannot diverge on what
/// "test mode" means).
///
/// NOT baked artifacts — synthesized per call from env-supplied material.
/// persist never sees the test root's PRIVATE key, so what the row can carry
/// is exactly what the harness supplies (v17.2.0, CIRISPersist#451; all
/// index-aligned with `CIRIS_TEST_TRUST_ROOT`, all optional):
///
/// - **`CIRIS_TEST_TRUST_ROOT_PQC`** — comma-separated base64 ML-DSA-65
///   PUBKEYS. When present the seeded row is PQC-complete
///   (`pubkey_ml_dsa_65_base64 = Some`, `pqc_completed_at` set), so a full
///   hybrid scrub signed by the SW root verifies under the always-on
///   `HybridPolicy::Strict` registration gate with ZERO relaxation of the
///   verification itself — the #451 node-bless unblock.
/// - **`CIRIS_TEST_TRUST_ROOT_SCRUB`** (+ optional
///   **`CIRIS_TEST_TRUST_ROOT_SCRUB_PQC`**) — comma-separated base64
///   self-scrub SIGNATURES over this row's canonical envelope, produced by
///   the harness (it holds the private halves). The signing contract is
///   pinned by [`test_anchor_registration_envelope`] — **call it, do not
///   transcribe it.** v31.0.0 (CIRISVerify 13.1.0) MOVED this preimage: the
///   envelope was `{"key_id":…,"test_anchor":true}` and now additionally binds
///   `identity_type` (`accord_holder`) and both of the row's pubkeys, because
///   verify's provenance-link check requires the full subject binding and
///   refuses a link whose signed bytes omit it. A harness still signing the
///   old literal produces a terminus persist's `root_binding` will not confirm.
///   Classical = Ed25519 over `JCS(...)` of that object; PQC = the bound
///   hybrid form (`SelfSigner::sign_bound` over the same canonical bytes). When present
///   the seeded terminus is a fully scrub-VERIFYING rooting root — persist's
///   own `root_binding` Confirms a chain terminating here (its
///   `RequireHybrid` link policy needs the FULL hybrid form — v37.0.0 doc
///   correction: this said `Ed25519Fallback` / "classical-only or
///   full-hybrid", stale since CIRISPersist#465 tightened the walk. A
///   classical-only terminus does NOT root).
///   When absent: a non-verifying placeholder — the seed + presence checks +
///   verify-side anchor-membership rooting still work, but persist-side
///   `root_binding` will NOT confirm through this terminus (the pinned
///   contract the #451 e2e documents).
///
/// # Which `CIRIS_TEST_TRUST_ROOT*` variable is which
///
/// v23.0.0 (CIRISPersist#551 item 7) — #551 reports an hour lost to this
/// prefix, because one name family spans three different kinds of thing and
/// two different owners. Persist reads ONLY public material, and every
/// variable it reads is listed above:
///
/// | variable | carries | owner |
/// |---|---|---|
/// | `CIRIS_TEST_TRUST_ROOT` | Ed25519 **pubkeys** (the 1-of-N anchor) | CIRISVerify (`test_trust_root_override`) |
/// | `CIRIS_TEST_TRUST_ROOT_PQC` | ML-DSA-65 **pubkeys** | persist (here) |
/// | `CIRIS_TEST_TRUST_ROOT_SCRUB[_PQC]` | scrub **signatures** | persist (here) |
/// | `CIRIS_TEST_TRUST_ROOT_SEED` | 32 bytes of **private key** material | **CIRISServer** (`src/test_bless.rs`) |
///
/// The last row is the one that burned the hour, and it is **not persist's**:
/// persist never reads `..._SEED`, never holds the test root's private half,
/// and cannot mint with it — the harness signs and hands us the signatures.
/// Renaming it (to `..._PRIVATE_KEY`, per #551) is CIRISServer's to make in
/// the crate that reads it; persist renaming its own public-material slots to
/// match would break the very harness that sets both families
/// (`CIRISServer/harness/mesh-repro/docker-compose.yml` sets all five) while
/// fixing nothing, so the boundary is documented here instead.
#[cfg(feature = "test-anchor")]
pub fn test_anchor_genesis_records() -> Option<Vec<SignedKeyRecord>> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    /// The i-th comma-separated slot of `var`, trimmed; `None` when the var
    /// is unset or the slot is missing/empty.
    fn env_slot(var: &str, i: usize) -> Option<String> {
        let raw = std::env::var(var).ok()?;
        let slot = raw.split(',').nth(i)?.trim().to_owned();
        (!slot.is_empty()).then_some(slot)
    }

    let keys = ciris_verify_core::test_anchor::test_trust_root_override()?;
    // v47.4.0 (CIRISPersist#805, FSD §3.2) — the ADVISORY tag: a block that
    // names the pair it was minted by is checked against the running pair;
    // an untagged block (every one that predates the tag) is not scolded.
    if let Ok(tag) = std::env::var("CIRIS_TEST_TRUST_ROOT_MINTED_BY") {
        let tag = tag.trim();
        if !tag.is_empty() && tag != test_anchor_minted_by() {
            tracing::warn!(
                target: TEST_ANCHOR_LOG_TARGET,
                block_minted_by = tag,
                running_pair = test_anchor_minted_by(),
                "CIRIS_TEST_TRUST_ROOT_MINTED_BY names a different persist/verify pair than \
                 the one running — the scrubs may not verify; re-mint: \
                 cargo run --example mint_test_anchor --features test-anchor"
            );
        }
    }
    let mut out = Vec::with_capacity(keys.len());
    for (i, ed) in keys.iter().enumerate() {
        let key_id = format!("test-accord-holder-{i}");
        // #451 — optional PQC pubkey + real self-scrub signatures (see the
        // doc contract above). The PQC scrub only rides alongside a
        // classical one (it is the BOUND half of a hybrid pair).
        //
        // v31.0.0 (CIRISVerify 13.1.0) — read BEFORE the envelope, because the
        // envelope now BINDS the PQC pubkey rather than merely accompanying it.
        let pqc_pubkey = env_slot("CIRIS_TEST_TRUST_ROOT_PQC", i);
        let scrub_ed = env_slot("CIRIS_TEST_TRUST_ROOT_SCRUB", i);
        let scrub_pqc = scrub_ed
            .as_ref()
            .and_then(|_| env_slot("CIRIS_TEST_TRUST_ROOT_SCRUB_PQC", i));
        let pubkey_ed25519_base64 = B64.encode(ed);
        let envelope = test_anchor_registration_envelope(
            &key_id,
            &pubkey_ed25519_base64,
            pqc_pubkey.as_deref(),
        );
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
            .expect("canonicalize test-anchor envelope");
        // v47.4.0 (CIRISPersist#805, FSD §3.2) — the STRUCTURAL check: a
        // supplied scrub either verifies over persist's canonical envelope
        // under the running persist/verify pair, or the boot log says so in
        // words that name the fix. The record is still seeded — the rooting
        // walk is the gate; the seeder reports.
        if let Some(sig) = scrub_ed.as_deref() {
            if let Err(e) = crate::verify::hybrid::verify_hybrid(
                &canonical,
                sig,
                scrub_pqc.as_deref(),
                &pubkey_ed25519_base64,
                pqc_pubkey.as_deref(),
                crate::verify::hybrid::HybridPolicy::Strict,
                None,
            ) {
                tracing::warn!(
                    target: TEST_ANCHOR_LOG_TARGET,
                    key_id = %key_id,
                    detail = %e,
                    running_pair = test_anchor_minted_by(),
                    "CIRIS_TEST_TRUST_ROOT block: the scrub for this slot does not verify \
                     under this persist/verify pair — the block was minted against another \
                     pair (or against a hand-rolled envelope) and will not root. Re-mint it: \
                     cargo run --example mint_test_anchor --features test-anchor"
                );
            }
        }
        out.push(test_anchor_holder_record(
            &key_id,
            pubkey_ed25519_base64,
            pqc_pubkey,
            envelope,
            &canonical,
            scrub_ed,
            scrub_pqc,
        ));
    }
    Some(out)
}

/// v17.1.0 (CIRISPersist#449) — is the test-anchor override LIVE (feature
/// compiled in AND runtime-armed AND a decodable `CIRIS_TEST_TRUST_ROOT`)?
/// Const-`false` on a prod build — every test-mode branch below is dead code
/// the optimizer removes, exactly like verify's inert twins.
///
/// `pub(crate)` since v21.3.0 (CIRISPersist#513): the canonical FIPS-custody
/// admission floor consults it — under the (feature-gated, runtime-armed)
/// test anchor the floor relaxes to the legacy quorum, because test-anchor
/// rosters are explicitly declared software keys.
pub(crate) fn test_anchor_override_active() -> bool {
    #[cfg(feature = "test-anchor")]
    {
        ciris_verify_core::test_anchor::test_trust_root_override().is_some()
    }
    #[cfg(not(feature = "test-anchor"))]
    {
        false
    }
}

/// v17.1.0 (CIRISPersist#449) — the EFFECTIVE accord-holder genesis roster:
/// the synthesized [`test_anchor_genesis_records`] under a live test-anchor
/// override, the baked A1/B1/C1 [`accord_holder_genesis_records`] otherwise
/// (and ALWAYS on a prod build — the test branch is compiled out). This is
/// the ONE selector every roster consumer rides — the backend genesis seeds,
/// [`verify_anchor_seeded`], the family bake, and the admission quorum roster
/// (`accord_holder_roster_key_ids`) — so the whole accord machinery follows
/// the same anchor verify roots against, by construction.
pub fn effective_accord_holder_records() -> std::borrow::Cow<'static, [SignedKeyRecord]> {
    #[cfg(feature = "test-anchor")]
    if let Some(test) = test_anchor_genesis_records() {
        return std::borrow::Cow::Owned(test);
    }
    std::borrow::Cow::Borrowed(accord_holder_genesis_records())
}

/// Fail-secure presence check (CIRISPersist#347 req 3): confirm every pinned
/// [`accord_holder_bootstrap_anchor`](ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor)
/// pubkey is live as a seeded self-signed `accord_holder` row, and that the
/// seeded set is *exactly* the anchor (no missing holder, no divergent pubkey
/// squatting a holder `key_id`). Run at boot right after the seed.
///
/// v31.0.0 (CIRISPersist#648) — the `Err` arm is now a typed [`GenesisFault`]
/// rather than a `String`, because the two things it fused have opposite
/// consequences: a holder row that was never seeded is a node before its
/// ceremony ([`GenesisFault::Absent`] — boot proceeds, the gates refuse), while
/// a holder `key_id` present with somebody else's pubkey is anchor SQUATTING
/// ([`GenesisFault::Divergent`] — boot still refuses). Fusing them is why the
/// seed had to be unconditional.
pub async fn verify_anchor_seeded<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use std::collections::HashSet;

    // #449 — `accord_holder_bootstrap_anchor()` is the LIVE anchor (verify
    // swaps it for the SW test root under `test_anchor_active()`), so the
    // record set checked against it must be the matching EFFECTIVE roster:
    // the same fail-secure present==anchor invariant, enforced against
    // whichever anchor is actually live. On a prod build both selectors are
    // the baked constants and this is byte-identical to pre-#449.
    let anchor: HashSet<[u8; 32]> =
        ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor()
            .into_iter()
            .collect();
    let mut present: HashSet<[u8; 32]> = HashSet::new();

    const LEG: GenesisLeg = GenesisLeg::Anchor;
    let records = effective_accord_holder_records();
    for sr in records.iter() {
        let r = &sr.record;
        let row = dir
            .lookup_public_key(&r.key_id)
            .await
            // The backend refused the question — honestly unknown, never
            // guessed, and never `Absent` (which would let a node whose
            // directory is unreadable boot as if it were merely young).
            .map_err(|e| GenesisFault::unreadable(LEG, format!("lookup {}: {e}", r.key_id)))?
            // NOT seeded — the pre-genesis arm. Boot proceeds; every gate in
            // `ROOT_REQUIRING_GATES` refuses (CIRISPersist#648).
            .ok_or_else(|| {
                GenesisFault::absent(LEG, format!("accord holder {} not seeded", r.key_id))
            })?;
        // A conflicting pre-existing row (same key_id, different pubkey) must
        // fail — `ON CONFLICT DO NOTHING` would have skipped our insert. This
        // is SQUATTING, not absence: somebody's key already answers to a
        // constitutional holder's name, and #648 does not make that survivable.
        if row.pubkey_ed25519_base64 != r.pubkey_ed25519_base64 {
            return Err(GenesisFault::divergent(
                LEG,
                format!(
                    "accord holder {} present with a divergent pubkey (anchor squatting)",
                    r.key_id
                ),
            ));
        }
        let ed: [u8; 32] = B64
            .decode(&row.pubkey_ed25519_base64)
            .map_err(|e| GenesisFault::divergent(LEG, format!("{} pubkey b64: {e}", r.key_id)))?
            .try_into()
            .map_err(|_| {
                GenesisFault::divergent(LEG, format!("{} pubkey not 32 bytes", r.key_id))
            })?;
        if !anchor.contains(&ed) {
            return Err(GenesisFault::divergent(
                LEG,
                format!("seeded holder {} is not a pinned anchor key", r.key_id),
            ));
        }
        present.insert(ed);
    }
    if present != anchor {
        return Err(GenesisFault::divergent(
            LEG,
            format!(
                "seeded anchor set (n={}) does not equal accord_holder_bootstrap_anchor() (n={})",
                present.len(),
                anchor.len()
            ),
        ));
    }
    Ok(())
}

/// The pinned genesis instant for the baked HUMANITY_ACCORD family row — a
/// FIXED timestamp (not wall-clock) so the entrenched row + its
/// `persist_row_hash` are deterministic across boots and backends
/// (CIRISPersist#386). Matches the accord-holder seed's `valid_from`.
const ACCORD_FAMILY_FOUNDED_AT: &str = "2026-05-01T00:00:00Z";

/// The baked **HUMANITY_ACCORD `federation_families` row** (CIRISPersist#386) —
/// the entrenched `quorum:2/3` family over the A1/B1/C1 founder seats. Fully
/// determined by the pinned verify constants `HUMANITY_ACCORD_FAMILY_KEY_ID`
/// and `ACCORD_CONSENSUS_PROTOCOL` plus the seeded accord-holder `key_id`s.
/// persist's [`Family`](crate::federation::types::Family) carries no
/// founder-signature field, so no signature is stored (bake-what-exists, same
/// trust model as the holder-row seed). The member seats reuse the holder
/// `key_id`s from [`accord_holder_genesis_records`], so the family stays
/// coherent with the seeded holders by construction.
pub fn accord_family_genesis_record() -> crate::federation::types::Family {
    // #449 — founder seats follow the EFFECTIVE roster so the family stays
    // coherent with the seeded holders (test or baked) by construction.
    // v53.0.0 (CC 3.2 T6) — the genesis version names the charter it was
    // minted with, or no charter is in force for the accord at all.
    accord_family_genesis_record_for(
        ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID,
        ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
        effective_accord_holder_records()
            .iter()
            .map(|sr| sr.record.key_id.as_str()),
        &genesis_family_charter_digest(),
    )
}

/// v53.0.0 (CC 3.2 T6) — the accord family's genesis record over a given
/// founder set: what [`accord_family_genesis_record`] builds from this build's
/// roster, and what the ceremony assembler signs as the family's genesis head.
/// One construction, so the signed head and the seeded row cannot differ.
/// `charter_digest` is the stored row hash of the charter the genesis version
/// names ([`bundle_family_charter_digest`]); a genesis version names no
/// predecessor.
pub fn accord_family_genesis_record_for<'a>(
    family_key_id: &str,
    consensus_protocol: &str,
    founders: impl IntoIterator<Item = &'a str>,
    charter_digest: &str,
) -> crate::federation::types::Family {
    use crate::federation::types::{Family, FamilyMember};
    let founded_at = ACCORD_FAMILY_FOUNDED_AT
        .parse()
        .expect("ACCORD_FAMILY_FOUNDED_AT is a valid RFC-3339 constant");
    let members = founders
        .into_iter()
        .map(|key_id| FamilyMember {
            key_id: key_id.to_owned(),
            joined_at: founded_at,
            role: Some("founder".to_owned()),
        })
        .collect();
    Family {
        prev_head_digest: String::new(),
        charter_digest: charter_digest.to_owned(),
        family_key_id: family_key_id.to_owned(),
        family_name: "HUMANITY_ACCORD".to_owned(),
        members,
        founded_at,
        consensus_protocol: consensus_protocol.to_owned(),
        consensus_protocol_entrenched: true,
        dissolved_at: None,
        persist_row_hash: String::new(),
    }
}

/// v53.0.0 (CC 3.2 T6, operator ruling B-1 on CIRISConstitution#136) — **the
/// charter the accord family's genesis version names**: the `persist_row_hash`
/// of the bundle's charter of the family (`delegates_to` toward
/// `humanity-accord` carrying the charter reading — `genesis-charter`). The
/// head names the charter in force, and a charter no version names is not in
/// force ([`charter_in_force`](crate::federation::canonical_community::charter_in_force)),
/// so the genesis version must name the bundle's. Empty when the bundle in
/// force carries none.
#[must_use]
pub fn genesis_family_charter_digest() -> String {
    bundle_family_charter_digest(canonical_genesis_bundle())
}

/// [`genesis_family_charter_digest`] over a given bundle: the stored row hash
/// of the bundle's charter of the accord family, empty when it carries none.
/// The ceremony verifier reads the bundle it verifies through this, never the
/// compiled one.
#[must_use]
pub fn bundle_family_charter_digest(bundle: &GenesisBundle) -> String {
    let family = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    bundle
        .attestations
        .iter()
        .map(|s| &s.attestation)
        .find(|a| {
            a.attestation_type == crate::federation::types::attestation_type::DELEGATES_TO
                && a.attested_key_id == family
                && crate::federation::trust_root::job_dimension_admits(
                    &a.attestation_envelope,
                    crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
                )
        })
        .and_then(|a| crate::federation::canonical_community::stored_row_hash(a).ok())
        .unwrap_or_default()
}

/// First-boot-seed the baked HUMANITY_ACCORD **family row** (CIRISPersist#386).
/// Generic over [`FederationDirectory`] so it stays **pg/sqlite-symmetric**.
/// The untied tail of #344/#347: genesis bakes the accord-holder KEY rows but
/// not the FAMILY row, so `lookup_family("humanity-accord")` returned `None` on
/// a fresh node and every family/quorum display + entrenched-roster surface fell
/// through. MUST run **after** [`accord_holder_genesis_records`] are seeded (the
/// family's member seats FK-reference the holder `federation_keys` rows).
///
/// Idempotent: skips when the row is already present (reboot), inserts on first
/// boot. Same bake-what-exists trust model as the holder seed.
pub async fn seed_accord_family<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Family;
    // v31.0.0 (CIRISPersist#648) — a second assemble never becomes a
    // replacement: a held head stands unless the genesis successor rule
    // ([`roster_install`]) says it is a stale genesis head of this same
    // accord — one that names no charter (a v52 row, I428) or names a charter
    // that is no longer a live row while the bundle's is. Anything else held is
    // left standing (#648, I428b). v53.1.0 — the same function the import door
    // and the post-delegation-plane boot step use.
    match roster_install::install_accord_genesis_head(dir, canonical_genesis_bundle()).await {
        Ok(RosterRecordOutcome::Refused { reason }) => {
            tracing::warn!(%reason, "genesis family seed: the held accord head is left standing");
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => Err(GenesisFault::absent(
            LEG,
            format!("seed accord family: {e} (are A1/B1/C1 seeded first?)"),
        )),
    }
}

/// Fail-secure presence check (CIRISPersist#386): the baked HUMANITY_ACCORD
/// family row is live with its entrenched `quorum:2/3` protocol and the full
/// A1/B1/C1 founder seat set. Run at boot right after [`seed_accord_family`];
/// `Err` is surfaced as
/// [`EngineError::GenesisSeed`](crate::engine::EngineError::GenesisSeed).
pub async fn verify_family_seeded<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Family;
    let expected = accord_family_genesis_record();
    let row = dir
        .lookup_family(&expected.family_key_id)
        .await
        .map_err(|e| GenesisFault::unreadable(LEG, format!("lookup_family: {e}")))?
        .ok_or_else(|| {
            GenesisFault::absent(
                LEG,
                format!("accord family {} not seeded", expected.family_key_id),
            )
        })?;
    // Present-and-WRONG on either axis is divergence, not youth: the threshold
    // and the seats are exactly what an accord m-of-n is measured by, and a
    // mutated one is an altered root wearing the constitutional name.
    if row.consensus_protocol != expected.consensus_protocol || !row.consensus_protocol_entrenched {
        return Err(GenesisFault::divergent(LEG, format!(
            "seeded accord family {} has non-entrenched / divergent protocol (got {:?}, entrenched={})",
            expected.family_key_id, row.consensus_protocol, row.consensus_protocol_entrenched
        )));
    }
    let seats: std::collections::BTreeSet<&str> =
        row.members.iter().map(|m| m.key_id.as_str()).collect();
    let want: std::collections::BTreeSet<&str> =
        expected.members.iter().map(|m| m.key_id.as_str()).collect();
    if seats != want {
        return Err(GenesisFault::divergent(
            LEG,
            format!(
                "seeded accord family {} seats {seats:?} != the founder set {want:?}",
                expected.family_key_id
            ),
        ));
    }
    Ok(())
}

/// The baked **canonical genesis seed** — the operator's
/// `ciris-canonical-1-d7bdeu223k` node, **2-of-3 accord-co-scrubbed** (A1
/// primary + B1 in `additional_scrubs`, over a byte-identical envelope)
/// (CIRISPersist#390, v13.4.0). This REPLACES the 1-of-N record #383 removed:
/// with canonical ADD requiring a 2-of-3 accord co-scrub, a single-anchor
/// founding record was a first-strike weakness. Bake-what-was-conferred (live
/// YubiKey scrub sigs), the same trust model as [`accord_holder_genesis_records`]
/// — NOT a constant-derived artifact.
///
/// v23.0.0 (CIRISPersist#551 item 1) — the asset is now a [`GenesisBundle`],
/// the same artifact shape a genesis ceremony emits, so "is this node seeded?"
/// is answered by a TYPE rather than a judgement call. The record inside
/// `serve_nodes` is byte-identical to the pre-v23 bare-list content (the row
/// this seeds, its envelope, and its scrub signatures are untouched — the
/// wire is sacred, only the container changed).
///
/// v23.1.0 (CIRISPersist#554) — **this is the mesh's first production trust
/// root.** The June 2026 hardware ceremony (A1/B1/C1 on FIPS YubiKeys, 2-of-3
/// co-scrub) chartering `ciris-canonical-1-d7bdeu223k` with `infra:serve`.
/// It replaces the bundle-shaped PLACEHOLDER v23.0.0 shipped — `holders 0,
/// attestations 0, authorizations 0` — which had the right type and no
/// content.
///
/// Read what it carries off the fields, all four planes now populated:
/// `holders` (A1/B1/C1, each with real YubiKey PIV custody evidence — the
/// shape #554 made representable), `serve_nodes` (the re-blessed canonical),
/// `attestations` (charter + serve grant + lifecycle — the delegation plane),
/// and `authorizations` (A1 + B1 hybrid, the 2-of-3 quorum).
///
/// The carried `holders` are cross-check input, NOT this node's roster: the
/// roster remains the separately-baked [`accord_holder_genesis_records`], and
/// bundle-carried holder records are never the verification authority (the
/// #377 lesson — a forged bundle carrying attacker "holders" proves nothing).
/// The two lists agree here because they are the same ceremony's output, and
/// [`verify_bundle_quorum`] re-derives authority from persist's own state
/// regardless.
///
/// Unlike the placeholder, this artifact carries the authorizations the quorum
/// gate requires (the bundle/1 bake door that installed such an artifact on a
/// live node, `bake_assembled_genesis`, is deleted in v62.0.0).
///
/// TODO(json-cut C5): remove after E flip, with the seed it backs.
const CANONICAL_SEED_JSON: &str = include_str!("canonical_seed.json");

/// Parse-once accessor for the baked canonical genesis **bundle**
/// (v23.0.0, CIRISPersist#551 item 1 — replaces `canonical_genesis_records`;
/// the bare `[{record}]` parse path is deleted, see [`parse_genesis_bundle`]).
/// Callers wanting the seeded records read [`GenesisBundle::serve_nodes`].
///
/// # Panics
///
/// Panics if the embedded JSON is not a valid bundle (build-time-checked
/// constant; caught by [`tests::canonical_seed_is_a_bundle_and_is_2of3_accord_conferred`]).
// TODO(json-cut C5): remove after E flip (C2's fixture_genesis replaces it).
pub fn canonical_genesis_bundle() -> &'static GenesisBundle {
    use std::sync::OnceLock;
    // v62.0.0 (json-cut C5): the #973 software-ceremony seam (a test-anchor
    // process booting against an installed bundle/1) is deleted.
    static PARSED: OnceLock<GenesisBundle> = OnceLock::new();
    PARSED.get_or_init(|| {
        parse_genesis_bundle(CANONICAL_SEED_JSON)
            .expect("embedded canonical_seed.json must be a valid GenesisBundle")
    })
}

/// CIRISPersist#973 (CC 3.2 T4a, "bundle only") — **is `row` a member of the
/// pinned GenesisBundle?** "An unlabelled row that is a member of the pinned
/// GenesisBundle (T5, `bundle_fingerprint`) keeps the reading its direction
/// gives it, because the three rows baked into the shipped bundle were minted
/// before the job labels existed and a fresh node could not otherwise seed."
///
/// Membership is the baked id AND the baked signed statement: the row's
/// canonical envelope equals the bundle row's, so a different statement stored
/// under a baked id is not a member. The bundle is the one this build pins
/// ([`canonical_genesis_bundle`]: the compiled artifact, or under a live test
/// anchor the installed software ceremony). A row that cannot be canonicalized
/// is not a member.
#[must_use]
pub fn is_pinned_bundle_row(row: &super::Attestation) -> bool {
    is_pinned_bundle_statement(&row.attestation_id, &row.attestation_envelope)
        && canonical_genesis_bundle().attestations.iter().any(|sa| {
            sa.attestation.attestation_id == row.attestation_id
                && sa.attestation.attesting_key_id == row.attesting_key_id
                && sa.attestation.attested_key_id == row.attested_key_id
                && sa.attestation.attestation_type == row.attestation_type
        })
}

/// [`is_pinned_bundle_row`] for a row not yet assembled: the id it will be
/// stored under and its signed envelope (the write gate's view).
#[must_use]
pub fn is_pinned_bundle_statement(attestation_id: &str, envelope: &serde_json::Value) -> bool {
    let Ok(got) = super::canonical_at_rest::canonical_bytes(envelope) else {
        return false;
    };
    canonical_genesis_bundle().attestations.iter().any(|sa| {
        sa.attestation.attestation_id == attestation_id
            && super::canonical_at_rest::canonical_bytes(&sa.attestation.attestation_envelope)
                .is_ok_and(|want| want == got)
    })
}

/// v31.0.0 (CIRISPersist#660) — **the baked delegation-plane ids, as a closed
/// set**, derived from the artifact rather than re-listed.
///
/// Today: `genesis-charter`, `genesis-grant:ciris-canonical-1-d7bdeu223k`,
/// `genesis-lifecycle`. Deriving it from [`canonical_genesis_bundle`] means a
/// re-bake that renames or adds a conferral row moves the reservation with it;
/// a hand-written list would reserve the OLD names and leave the new ones open,
/// which is the failure this whole class keeps taking.
#[must_use]
pub fn genesis_delegation_ids() -> Vec<&'static str> {
    canonical_genesis_bundle()
        .attestations
        .iter()
        .map(|a| a.attestation.attestation_id.as_str())
        .collect()
}

/// The baked row for `id`, if `id` is a genesis delegation id.
fn baked_delegation_row(id: &str) -> Option<&'static super::Attestation> {
    canonical_genesis_bundle()
        .attestations
        .iter()
        .map(|a| &a.attestation)
        .find(|a| a.attestation_id == id)
}

/// v31.1.0 (CIRISPersist#665) — **the re-bake replacement door's own gate.**
///
/// [`FederationDirectory::purge_genesis_delegation_row_v31`](super::FederationDirectory::purge_genesis_delegation_row_v31)
/// exists because the general purge door cannot serve the re-bake: two of the
/// three genesis delegation rows are `delegates_to`, which
/// [`check_purge_admission`](crate::federation::migration::check_purge_admission)
/// refuses as exclusion-bearing. That refusal is right and stays; this is a
/// different door with a different, much smaller authority, and this is the
/// sentence that draws it:
///
/// > the id must be one the COMPILED-IN bundle carries.
///
/// Everything that makes the bypass defensible follows from that one bound. The
/// door can only ever address a row this binary is holding a replacement for,
/// so the worst a wrong caller achieves is a delegation plane that reads
/// `Absent` — which BOOTS, and which the next start re-seeds. It can never
/// remove a conferral the node cannot re-create from its own artifact.
///
/// Asked INSIDE every backend implementation, not just at the call site: a
/// delete door whose safety lives entirely in its caller is the shape
/// CIRISPersist#652 had.
///
/// # Tier 1
///
/// Pure — a membership test against the 3-element baked set. No directory read.
///
/// # Errors
///
/// [`Error::InvalidArgument`](super::Error::InvalidArgument) if `attestation_id`
/// is not a baked genesis delegation id.
pub fn check_genesis_rebake_purge_admission(attestation_id: &str) -> Result<(), super::Error> {
    check_genesis_rebake_purge_admission_under(
        attestation_id,
        &bundle::GenesisPurgeAuthority::CompiledIn,
    )
}

/// v38.0.0 (CIRISPersist#671) — the purge door's predicate, under a NAMED
/// authority. `CompiledIn` keeps the exact #665 bound; `QuorumVerified`
/// widens it to ids a bundle carries whose holder quorum THIS NODE verified
/// ([`bundle::QuorumVerifiedBundle`] is constructible only by
/// [`bundle::verify_bundle_quorum`], so the widening is a proof, never a
/// caller-supplied string list). An id under NEITHER bound refuses — a
/// caller with no verified bundle cannot purge a candidate id, on any
/// backend, which is the negative half the witness pins.
pub fn check_genesis_rebake_purge_admission_under(
    attestation_id: &str,
    authority: &bundle::GenesisPurgeAuthority<'_>,
) -> Result<(), super::Error> {
    if baked_delegation_row(attestation_id).is_some() {
        return Ok(());
    }
    if let bundle::GenesisPurgeAuthority::QuorumVerified(verified) = authority {
        if verified.carries_attestation_id(attestation_id) {
            return Ok(());
        }
    }
    Err(super::Error::InvalidArgument(format!(
        "refusing to purge attestation {attestation_id} through the genesis re-bake door \
         (CIRISPersist#665/#671): it is not one of the baked genesis delegation ids {:?}, and \
         the presented authority carries no quorum-verified bundle naming it. This door exists \
         only to let a ceremony replace rows it is HOLDING replacements for — the general purge \
         path is `purge_attestation_v31`, and it refuses exclusion-bearing rows on purpose",
        genesis_delegation_ids(),
    )))
}

/// v31.0.0 (CIRISPersist#660) — **the genesis delegation ids are RESERVED** to
/// the accord holders, at every write door.
///
/// # The hole this closes
///
/// `genesis-charter` / `genesis-grant:…` / `genesis-lifecycle` were reserved
/// NOWHERE. One ordinary `scores` row from any registered key, written under one
/// of those ids, was admitted — and two things followed, both remote and both
/// unauthenticated:
///
/// 1. [`verify_delegation_plane_seeded`] found a row whose
///    `original_content_hash` is not the baked one, classified it
///    [`GenesisFault::divergent`], and
///    [`GenesisFault::refuses_boot`](GenesisFault::refuses_boot) is true for
///    exactly that arm — so **a peer could deny a node its boot** by writing one
///    attestation. #648 added the delegation leg to close a fail-OPEN banner;
///    without this reservation it opened a fail-CLOSED denial in its place.
/// 2. The primary key was then TAKEN, so the real ceremony row could never
///    install. The denial was permanent, not transient.
///
/// # Shape: mirrored from the #648 family reservation
///
/// [`Error::ConstitutionalFamilyReserved`](super::Error::ConstitutionalFamilyReserved)
/// reserved the `humanity-accord` FAMILY id after the same finding on the family
/// plane — nothing reserved it, and only an accident of ordering (the seed was
/// unconditional, so the key was always already taken) had defended it. This is
/// that finding on the ATTESTATION plane and it takes the same shape: a typed
/// refusal, at the door, naming the reservation.
///
/// It differs from #648 in one way, and the difference is forced by the plane.
/// The family reservation could be ABSOLUTE at the peer door because the
/// ceremony writes families through a different method
/// ([`put_family_local`](super::FederationDirectory::put_family_local)). The
/// delegation plane has no second door: the bundle/1 bake (deleted in v62.0.0), the host's
/// stage-1 boot write, and a peer's replication all arrive at
/// `put_attestation`. So the reservation names an AUTHOR instead:
///
/// > A row claiming a baked genesis delegation id must be **federation-tier**
/// > and **attested by a seated accord holder** on this node's effective roster.
///
/// That is `check_reserved_prefix_admission`'s own `accord:*` rule
/// (CC 3.4.1, the one constitutional asymmetry) applied to the id namespace
/// rather than the type namespace, and it draws exactly the trust boundary #648
/// drew for the family id.
///
/// # Why NOT "must be byte-identical to the baked row"
///
/// That was the first form of this gate and it was wrong — caught by
/// `bake_real_genesis_v2_artifact_490` and
/// `genesis_candidate_bundle_roots_to_the_family_under_quorum_557`, which install
/// a CANDIDATE re-mint bundle. A re-ceremony legitimately reissues
/// `genesis-charter` with new content and new instants; pinning the content
/// would have reserved the ids against the one operation they exist for, and
/// 31.1.0's re-bake would have been refused by its own substrate. The ids belong
/// to the accord holders, not to one artifact.
///
/// # What this does and does not close
///
/// It closes the finding as reported: *one ordinary `scores` row from any
/// registered key*. An ordinary peer cannot claim these ids at either door, so
/// it can neither take the primary key the ceremony needs nor drive
/// [`verify_delegation_plane_seeded`] to its `divergent` arm — which
/// [`GenesisFault::refuses_boot`], and was therefore a remote, unauthenticated,
/// permanent boot-denial.
///
/// It does NOT make `Divergent` unreachable outright, and the honest statement
/// of what remains is:
///
/// - a **seated accord holder** can still write a divergent conferral row. That
///   is the constitutional root itself, the same authority that could simply
///   re-charter the mesh, and `refuses_boot` is the correct response to a root
///   that has genuinely altered its own delegation plane;
/// - a write **beneath persist** — a restored backup, a direct `UPDATE`, a
///   pre-#660 corpus — is unreachable by any door and equally must classify as
///   divergent.
///
/// Both remaining routes are ones where refusing to serve is the right answer.
/// The one that was wrong was a stranger choosing it for you. Witnessed in
/// `exercise_genesis_id_squat_refused` (refused at both doors, posture
/// unmoved) and `assert_injected_squat_is_divergent` (still classified, still
/// refuses boot, still banners).
///
/// # Tier 1
///
/// Pure: a string compare against a 3-element set, then a membership test
/// against the baked roster. No directory read — the roster is re-derived from
/// this node's own baked state, never from anything the row carries (#377).
///
/// # Errors
///
/// [`Error::GenesisAttestationReserved`](super::Error::GenesisAttestationReserved)
/// naming the id, the claimant and which half of the rule it failed.
pub fn check_genesis_attestation_reserved(row: &super::Attestation) -> Result<(), super::Error> {
    if baked_delegation_row(&row.attestation_id).is_none() {
        // The overwhelmingly common path: not a genesis id, nothing to say.
        return Ok(());
    }
    let refuse = |field: &str, detail: String| super::Error::GenesisAttestationReserved {
        attestation_id: row.attestation_id.clone(),
        attesting_key_id: row.attesting_key_id.clone(),
        field: field.to_owned(),
        detail,
    };

    // (a) FEDERATION TIER. A ceremony row is federation-tier by construction;
    // the local door mints local-tier rows and is never a genesis door. This
    // half is what makes the local door safe without a second rule there — and
    // the local door DOES have to be gated, because `get_attestation` does not
    // filter by tier, so a local-tier row is already enough to take the key and
    // flip the posture.
    if row.tier != crate::federation::types::attestation_tier::FEDERATION {
        return Err(refuse(
            "tier",
            format!(
                "is {:?} — the genesis delegation plane is federation-tier, and a local-tier \
                 row under this id would take the primary key the ceremony needs",
                row.tier
            ),
        ));
    }

    // (b) A SEATED ACCORD HOLDER. Re-derived from THIS node's effective baked
    // roster — the same selector `verify_bundle_quorum` and the admission
    // quorum ride — never from anything the row carries.
    let seated = effective_accord_holder_records()
        .iter()
        .any(|h| h.record.key_id == row.attesting_key_id);
    if !seated {
        return Err(refuse(
            "attesting_key_id",
            "is not a seated accord holder on this node's roster — these ids are installed \
             by the genesis ceremony, and the ceremony is the accord holders"
                .to_owned(),
        ));
    }
    Ok(())
}

/// First-boot-seed the baked 2-of-3 canonical genesis server(s)
/// (CIRISPersist#390). Generic over [`FederationDirectory`] (pg/sqlite-symmetric).
///
/// Admitted **through the ordinary
/// [`check_canonical_role_admission`](crate::federation::admission::check_canonical_role_admission)
/// gate** inside [`FederationDirectory::put_public_key`] — so the record proves
/// its own accord-conferral (both scrubs re-verified as ≥2 distinct
/// HUMANITY_ACCORD holders via `verify_quorum_policy`), not a force-insert. MUST
/// run **after** the accord holders + family are seeded (the 2-of-3 verifies
/// against the seeded A1/B1 anchor). Idempotent: a byte-identical row already
/// present is a `put_public_key` no-op; a `key_id` collision with different
/// content surfaces as an `Err` (never a silent overwrite — the same
/// trust-root-takeover invariant as the family bake).
// TODO(json-cut C5): remove after E flip (the baked bundle/1 seed).
pub async fn seed_canonical_servers<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Canonical;
    for sr in &canonical_genesis_bundle().serve_nodes {
        let kid = &sr.record.key_id;
        // Branch on the EXISTING row's shape (CIRISPersist#394 + #410):
        //  - absent (a FRESH node) → `put_public_key`: insert through the m-of-n
        //    canonical gate (holders are seeded first, so the scrubs verify).
        //  - present + SELF-SIGNED (the canonical node holds its OWN minted
        //    `node` row, #394) → `apply_replicated_key_record`'s Upgrade arm.
        //    v62.0.0 (json-cut C5): the `adopt_scrub_upgrade` door that took
        //    this case without the `owner_of` gate is deleted; a refusal by
        //    that gate is a logged skip below, never a boot abort.
        //  - present + ALREADY ANCHOR-SCRUBBED but DIFFERENT (#410 — an upgraded
        //    fleet node holds a PRIOR baked canonical, e.g. the :4243 record
        //    before the :4242 re-bake) → route through `apply_replicated_key_record`
        //    so the #405 SUPERSEDE path takes it: the baked record wins iff it is
        //    strictly-newer (envelope valid_from) AND m-of-n re-verifies. Byte-
        //    identical ⇒ Unchanged; a baked record OLDER than a runtime-superseded
        //    one ⇒ Refused → SKIP (never downgrade, never brick). Historically
        //    `adopt_scrub_upgrade` returned a fatal Conflict here, bricking boot
        //    on every canonical-record change (same class as #394, one deeper).
        let existing = dir
            .lookup_public_key(kid)
            .await
            .map_err(|e| GenesisFault::unreadable(LEG, format!("lookup canonical {kid}: {e}")))?;
        let res: Result<(), crate::federation::Error> = match existing {
            None => dir.put_public_key(sr.clone()).await,
            Some(_) => {
                use crate::federation::register::ReplicatedKeyOutcome as O;
                match dir.apply_replicated_key_record(sr.clone()).await {
                    // v54.0.0 (#995 row 2) — `ScrubsRehydrated`: the baked record
                    // re-offered at boot restores a quorum a pre-v53.1.4 door dropped.
                    Ok(
                        O::Superseded
                        | O::Unchanged
                        | O::Upgraded
                        | O::Inserted
                        | O::Rebound
                        | O::ScrubsRehydrated
                        // v54.1.0 (#1044) — the held row failed verification and
                        // the baked record (same pubkeys, same claim) replaced it.
                        | O::InvalidReplaced,
                    ) => Ok(()),
                    // Existing is same-or-newer (or not admissible against the
                    // baked record): do NOT downgrade the node, do NOT brick.
                    // v24.2.0 (CIRISPersist#565) — the warning names the branch
                    // that fired. `already_anchored_identical` here is a boot
                    // NORMALITY on a baked-seed fleet (the node already holds
                    // exactly this anchoring), which is precisely what the old
                    // "existing is same-or-newer" prose could not tell an
                    // operator apart from a real re-scrub refusal.
                    Ok(O::Refused { reason }) => {
                        tracing::warn!(
                            key_id = %kid,
                            refusal_reason = reason.as_str(),
                            "genesis canonical seed: baked record REFUSED over the existing \
                             anchor-scrubbed row — skipping"
                        );
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        };
        // v31.0.0 (CIRISPersist#648) — a refused canonical bake is `Absent`,
        // never `Divergent`: the byte-exact-else-`Err` discipline above already
        // makes a genuine takeover attempt impossible to install, and the state
        // 31.0.0 actually ships in is precisely this one — a baked bundle whose
        // pre-#643 attestations no longer bind, so the canonical leg does not
        // land. That is a node awaiting its ceremony, and it boots.
        res.map_err(|e| {
            GenesisFault::absent(
                LEG,
                format!(
                "seed canonical server {kid}: {e} (are A1/B1 holders + accord family seeded first?)"
            ),
            )
        })?;
    }
    Ok(())
}

/// Fail-secure presence check (CIRISPersist#390): every baked canonical record
/// is live with matching pubkey and the `canonical` role still conferred. Run
/// at boot right after [`seed_canonical_servers`]; `Err` surfaces as
/// [`EngineError::GenesisSeed`](crate::engine::EngineError::GenesisSeed).
pub async fn verify_canonical_seeded<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Canonical;
    for sr in &canonical_genesis_bundle().serve_nodes {
        let r = &sr.record;
        let row = dir
            .lookup_public_key(&r.key_id)
            .await
            .map_err(|e| GenesisFault::unreadable(LEG, format!("lookup {}: {e}", r.key_id)))?
            .ok_or_else(|| {
                GenesisFault::absent(LEG, format!("canonical server {} not seeded", r.key_id))
            })?;
        if row.pubkey_ed25519_base64 != r.pubkey_ed25519_base64 {
            return Err(GenesisFault::divergent(
                LEG,
                format!(
                    "canonical server {} present with a divergent pubkey (squatting)",
                    r.key_id
                ),
            ));
        }
        // v62.0.0 (CC rc20 4.2.1 / 3.4.7.1, #1274) — the standing is the
        // accord's conferral, read from the stored scrub set, never the
        // `canonical` label in `identity_type` (inert on its own).
        let conferred = crate::federation::admission::holds_canonical_conferral(
            dir.as_dyn_directory(),
            &row,
            &crate::federation::admission::accord_holder_roster_key_ids(),
        )
        .await
        .map_err(|e| GenesisFault::unreadable(LEG, format!("conferral {}: {e}", r.key_id)))?;
        if !conferred {
            return Err(GenesisFault::divergent(
                LEG,
                format!(
                    "seeded canonical server {} lost its canonical conferral (the accord's \
                     co-scrub over its record does not verify; identity_type={:?})",
                    r.key_id, row.identity_type
                ),
            ));
        }
    }
    Ok(())
}

/// v31.0.0 (CIRISPersist#648) — **the DELEGATION-PLANE leg**: are the rows that
/// say what this root actually CONFERS installed, and still bound?
///
/// # Why this leg exists
///
/// The other three legs are all the KEY plane. [`verify_anchor_seeded`] checks
/// `federation_keys` rows, [`verify_family_seeded`] a `federation_families`
/// row, [`verify_canonical_seeded`] more `federation_keys` rows. The binding
/// gates this release added — `check_row_column_binding` (#643) and
/// `check_instant_binding` (#598) — are ATTESTATION gates, so not one of them
/// touches any of those three legs, and the stale baked seed's key plane
/// therefore installs perfectly on a 31.0.0 node.
///
/// The consequence, before this leg existed, was MEASURED, and is the reason it
/// does: a normally-constructed 31.0.0 `Engine` reported `Entrenched`, rendered
/// NO banner, and a server reading `entrenched()` would enable agent mode — on
/// a root whose `genesis-charter` / `genesis-grant:…` / `genesis-lifecycle`
/// rows are refused at every `put_attestation` and can never be installed. That
/// is a fail-open banner: the operator sees green while conferral is dead.
///
/// # Absent vs divergent
///
/// A row that is MISSING, or present in the pre-#643 shape, is
/// [`GenesisFault::absent`] — a node awaiting its ceremony, which BOOTS. That
/// follows [`seed_canonical_servers`]'s precedent deliberately: 31.0.0 is the
/// binary that RUNS the ceremony, and a posture that bricked the node on the
/// exact state the release ships in would put the ceremony out of reach.
///
/// A row present whose `original_content_hash` is not the baked one, and that
/// is NOT a verifiable statement by a seated accord holder, is
/// [`GenesisFault::divergent`] — a SUBSTITUTED conferral row, and the one case
/// here that must not serve. Same split, and the same reasoning, as the
/// canonical leg's squatting check.
///
/// # The (stored, baked) relations (CIRISPersist#973)
///
/// | stored vs the compiled-in row | this leg |
/// |---|---|
/// | identical | `Ok` |
/// | a verified holder statement STRICTLY NEWER | `Ok` (the mesh is ahead of this binary) |
/// | a verified holder statement OLDER | `absent` — the bake was not adopted |
/// | a verified holder statement of the SAME vintage, different content | `absent` — a tie, not adopted |
/// | same signed envelope, altered around it | `divergent` |
/// | not a verifiable holder statement | `divergent` |
/// | missing, or pre-v31 shaped | `absent` |
///
/// The OLDER arm is what an upgrading node holds when the boot seed could not
/// install the re-mint (refused at the door — a bake stamped ahead of this
/// node's clock — or the seed has not run). It is not `divergent`: that
/// refuses to boot, and an upgrade must never brick a node over a row its own
/// holders signed. It is not `Ok` either: before #973 it was, because the raw
/// bundle row was compared as a stored row and lost to every conformant one,
/// so the node reported `Entrenched` on the previous root with nothing to say
/// the new one had not landed. A rollback written beneath persist (an old
/// genuine row put back) is the same state and gets the same answer: not
/// entrenched, and the next boot's seed supersedes it.
pub async fn verify_delegation_plane_seeded<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Delegation;
    for sa in &canonical_genesis_bundle().attestations {
        let want = &sa.attestation;
        let id = &want.attestation_id;
        let row = dir
            .get_attestation(id)
            .await
            .map_err(|e| GenesisFault::unreadable(LEG, format!("lookup {id}: {e}")))?
            .ok_or_else(|| {
                GenesisFault::absent(LEG, format!("delegation row {id} is not installed"))
            })?;
        // Content FIRST: a substituted conferral row is the case that must not
        // serve, and the signed digest alone separates it from a merely stale one.
        //
        // v31.1.0 (CIRISPersist#665 review) — **THE COMPILED-IN BUNDLE IS THE
        // FLOOR, NOT THE IDENTITY.** This arm used to be a bare equality against
        // the baked content hash, and that made a legitimately NEWER root
        // indistinguishable from an attack: a node that had run a re-ceremony
        // — or replicated from a peer that had — fails a byte-equality against
        // its own binary's artifact BY CONSTRUCTION, so the only posture it
        // could reach was `Divergent`, which refuses to boot. The check that
        // exists to notice a root altered beneath persist was also refusing
        // every successor the root is designed to have.
        //
        // A portable trust root whose whole purpose is that it can be RE-CUT
        // must be able to recognise its own successor. So the question is no
        // longer *"is this byte-equal to what I shipped with"* but:
        //
        //   is this a REAL statement by my seated accord holders, and is it at
        //   least as new as the one I shipped with?
        //
        // **This is a narrowing of what counts as sound in every direction
        // except one.** Still `Divergent`, still refusing to serve: an injected
        // squat, a row renamed onto a genesis id, a fabricated row claiming a
        // holder's `key_id`, a corrupted signature. A holder-signed row OLDER
        // than the compiled-in one (a rollback, or an upgrade whose re-mint
        // did not land) and a same-vintage twin are NOT sound either, but they
        // are `Absent`, not `Divergent` (#973; see the table on this fn).
        // The single thing that is served on in place of the bake is a newer,
        // quorum-verified, holder-signed root.
        //
        // ── THE PROPERTY, ASKED FIRST: CAN THIS PLANE CONFER RIGHT NOW? ──
        //
        // v31.1.0 (CIRISPersist#665 review) — this leg reported `Entrenched` on
        // a plane that could not confer THREE times, and every fix was correct
        // for the case in front of it and wrong as a rule: no signature check at
        // all; then whole-row comparison but only on the seed path; then on the
        // read path too, but only where a baked comparand EXISTS. The floor rule
        // then deliberately created a path where the stored row is legitimately
        // NOT the baked row — and that path had no wholeness check at all,
        // because there was nothing to compare against.
        //
        // Byte-equality with a compiled-in artifact was never the property. It
        // was a PROXY that happened to imply it, and each new legitimate way for
        // a row to differ removed the implication while the code went on looking
        // careful. So the property is asked DIRECTLY, and asked FIRST — ahead of
        // every arm below, so that no arm can accept a row the plane cannot
        // actually confer with, and so a path added later inherits the check
        // instead of having to remember it.
        //
        // See `delegation_row_accord_quorum`. The cost is real crypto on the
        // common path, and it is worth it: three rows, once per boot, to answer
        // the only question this leg exists to answer.
        match delegation_row_accord_quorum(dir, &row).await {
            Ok(Some(quorum)) if !quorum.met() => {
                return Err(GenesisFault::divergent(
                    LEG,
                    format!(
                        "delegation row {id} no longer reaches the accord quorum that confers it \
                         — {}. The row is present and its base signature may still verify, but \
                         the distinct seated-holder co-signatures have fallen below the \
                         threshold, so this plane CANNOT CONFER. Serving on it would report a \
                         constitutional root no peer would accept",
                        quorum.describe(),
                    ),
                ))
            }
            Ok(Some(_)) => {}
            // No accord family on this node at all: PRE-GENESIS, and
            // `verify_family_seeded` is the leg that reports it. Fall through
            // rather than double-report — the arms below still classify this
            // row, and on the boot path the family leg has already run.
            Ok(None) => {}
            Err(e) => {
                return Err(GenesisFault::unreadable(
                    LEG,
                    format!("delegation row {id}: the accord quorum could not be counted: {e}"),
                ))
            }
        }

        // The arms below decide WHICH acceptable-row story this is — the baked
        // artifact, this ceremony's row damaged around its signed envelope, or a
        // successor. They no longer carry the burden of implying quorum.
        //
        // # v31.1.0 (CIRISPersist#665 review) — BYTE-WHOLENESS IS ASKED HERE TOO
        //
        // The previous cut taught the SEED to compare the whole row rather than
        // its content hash, and stopped there. That closed the fail-open on the
        // boot SEQUENCE and left it wide open on the read PATH: `genesis_posture`
        // never calls the seed, so `Engine::genesis_posture`, `NodeState::genesis`
        // → `StateBand::Green` and CIRISServer's agent-mode gate all answered
        // from this function alone — and this function compared only the content
        // hash. Damage landing AFTER boot was therefore invisible to every live
        // query, on a threat model whose whole premise is a writer with raw
        // corpus access, i.e. one who does not wait for a restart.
        //
        // The tell was in our own witness: `assert_damaged_current_row_is_repaired`
        // asserted that this leg PASSES on a row whose co-signature set had been
        // thinned below quorum, labelled "that blindness is the finding". It was
        // identified and then fixed in only one of the two places that had it.
        // The witness now asserts the opposite, which is what makes this a fix
        // rather than a comment.
        //
        // Narrowing `GenesisPosture::Entrenched`'s doc instead was the available
        // alternative and is the weaker one: CIRISServer#398 consumes that
        // sentence as a cross-repo contract, so the predicate is what has to be
        // true.
        let whole = baked_row_matches_stored(&row, want)
            .map_err(|e| GenesisFault::unreadable(LEG, format!("compare {id} to the bake: {e}")))?;
        if !whole {
            if row.original_content_hash == want.original_content_hash {
                // Same signed statement, altered around it. The holders' bytes
                // are intact but the material carrying them is not — a charter
                // whose `additional_scrubs` were thinned still hashes the same
                // and still fails `family_quorum_over`. Fail-secure: the seed
                // repairs this when it runs, and a node that reaches here
                // without the seed having repaired it must not report green.
                return Err(GenesisFault::divergent(
                    LEG,
                    format!(
                        "delegation row {id} carries the baked content hash but does not match \
                         the baked artifact — the unsigned material around the signed envelope \
                         (signature columns, or the co-signature quorum set) was altered beneath \
                         persist. The signed statement is intact; what carries it is not"
                    ),
                ));
            }
            let real = stored_row_is_verifiable_holder_statement(dir, &row).await;
            // v31.1.0 (CIRISPersist#665 review) — **STRICTLY NEWER, not merely
            // not-older.** This asked `!candidate_is_strictly_newer(want, &row)`
            // — "the baked row is not newer than the stored one" — which is
            // TRUE when the two are the same age. So a stored row bearing the
            // same envelope-bound `asserted_at` as the compiled-in artifact but
            // DIFFERENT content was accepted as a successor, and posture could
            // reach `Entrenched` on a plane where neither statement supersedes
            // the other.
            //
            // Equal time with different content is not a successor; it is an
            // AMBIGUITY, and `Entrenched` is the strongest claim this plane
            // makes. Conferring it on a state the node cannot adjudicate is the
            // same class as the other four rounds — a gate reporting something
            // it cannot back. The successor has to WIN, not tie.
            //
            // The envelope-identical case cannot reach here: `original_content_hash`
            // is the digest of the canonical envelope, so identical envelopes
            // give identical hashes and the damage arm above owns them. Every row
            // that arrives here is a genuinely different statement.
            let stored_supersedes = stored_is_acceptable_successor(&row, want);
            if !real {
                return Err(GenesisFault::divergent(
                    LEG,
                    format!(
                        "delegation row {id} is present with a content hash that is not the baked \
                         one (stored {}, baked {}) and is not a verifiable statement by a seated \
                         accord holder — a substituted conferral row",
                        row.original_content_hash, want.original_content_hash,
                    ),
                ));
            }
            if !stored_supersedes {
                // CIRISPersist#973 — a VERIFIED holder statement that does not
                // supersede the bake: the previous ceremony's row (the boot
                // seed could not install its successor — refused at the door,
                // or not yet run), or a twin of the same vintage. Neither is a
                // substitution, so neither is `Divergent` (which refuses to
                // boot, and would brick an upgrading node whose re-mint was
                // refused for its clock). Neither is `Entrenched` either: this
                // binary's root was NOT adopted, and the operator must see
                // that. `Absent` boots, raises the banner, and matches what
                // the boot seed itself reports for the same state. The next
                // boot's seed supersedes an older row as soon as the door
                // admits the bake.
                // CIRISPersist#973 — the cause, typed. The read path sees a
                // verified older (or same-vintage) row and a bake that is
                // not installed; WHY the seed did not install it is the
                // seed's fault to carry (`Refused`), not this leg's to guess.
                let stored_older = candidate_is_strictly_newer(want, &row);
                return Err(GenesisFault::bake_not_adopted(
                    LEG,
                    format!(
                        "delegation row {id}: the compiled-in root was not adopted — the stored \
                         row is a verified accord-holder statement (asserted {}, content {}) \
                         that is {} the baked one (asserted {}, content {})",
                        row.asserted_at,
                        row.original_content_hash,
                        if stored_older {
                            "OLDER than"
                        } else {
                            "of the SAME vintage as, and different from,"
                        },
                        want.asserted_at,
                        want.original_content_hash,
                    ),
                    if stored_older {
                        BakeNotAdoptedReason::StoredOlder
                    } else {
                        BakeNotAdoptedReason::EqualVintage
                    },
                    // `real` held above: the stored row is a verified
                    // accord-holder statement, so the previous root stands.
                    true,
                ));
            }
            // A verified holder statement at least as new as ours. The mesh's
            // root is ahead of this binary; that is allowed, and the remaining
            // shape check below still applies to it.
            //
            // Its co-signature set is NOT checked against a baked artifact, and
            // cannot be: this node does not hold the newer ceremony's bundle to
            // compare against. Leg 2/3 of the authenticity check cover the base
            // scrub and bind the content hash to the signed envelope; a thinned
            // `additional_scrubs` on a NEWER row is caught where it has always
            // been caught, by the quorum readers that count it.
            tracing::info!(
                attestation_id = %id,
                stored_asserted_at = %row.asserted_at,
                baked_asserted_at = %want.asserted_at,
                "genesis delegation posture: serving on an accord-holder statement newer than \
                 the compiled-in artifact (CIRISPersist#665)"
            );
        }
        // Then SHAPE: a row installed under the pre-v31 envelope is the state
        // 31.0.0 ships in, so it is `absent` — awaiting the re-ceremony.
        //
        // v31.0.0 (CIRISPersist#660) — asked through the MIGRATION classifier
        // rather than by re-listing its gates. This was a second implementation
        // of [`classify_shape`](crate::federation::migration::classify_shape) and
        // it disagreed with the first in three ways, one of them live:
        //
        // - it evaluated `check_instant_binding` at `Utc::now()` instead of the
        //   ROW'S OWN `asserted_at`. #650 fixed exactly that in the classifier
        //   because the skew arm is a FRESHNESS bound, not a shape fact — and
        //   here the consequence was that a node with a lagging clock (VM
        //   snapshot, container up before NTP) demoted a fully entrenched root
        //   to `pre_genesis`, raised the banner and told the host to refuse
        //   agent mode. A posture that changes because the clock moved is not
        //   reporting on a trust root.
        // - it ran the two gates in the opposite order, so a row failing both
        //   drew a different sentence here than in the migration report.
        // - it never asked `check_canonical_at_rest` (#647), so this leg called
        //   a row conformant that the migration classifier calls legacy.
        //
        // One spelling. Freshness is still enforced where it belongs — the put
        // doors, promotion, and `check_reseal_admission`, all against the true
        // clock.
        if let crate::federation::migration::RowShape::Legacy { why } =
            crate::federation::migration::classify_shape(&row, row.asserted_at)
        {
            return Err(GenesisFault::absent(
                LEG,
                format!("delegation row {id} is not v31-shaped: {why}"),
            ));
        }
    }
    Ok(())
}

/// v31.0.0 (CIRISPersist#648) — **is this bundle's delegation plane bound to
/// its typed columns (CIRISPersist#643), i.e. is it a v31-shaped bundle?**
///
/// `Ok(())` when every attestation the bundle carries passes
/// [`check_row_column_binding`](crate::federation::admission::check_row_column_binding);
/// `Err` naming the first that does not.
///
/// # Why a predicate and not a version flag
///
/// The baked `canonical_seed.json` was signed before the #643 row mirror
/// existed, so its `genesis-charter` / `genesis-grant:…` / `genesis-lifecycle`
/// rows are refused at every `put_attestation` — correctly, and that gate must
/// not be weakened to bake a stale artifact (it closes the verb-substitution
/// and authority-injection attacks; a genesis-shaped carve-out would be a
/// permanent hole in exactly the rows that grant everything).
///
/// The four genesis tests that fail on that refusal are made honest by asking
/// this question rather than by being skipped: they assert the REFUSAL while
/// the baked bundle is pre-v31, and assert INSTALLATION once it is re-signed.
/// The assertion inverts on the artifact, not on a hand-edited expectation, so
/// 31.1.0's re-bake turns the seed-install witnesses back on by itself and
/// nobody has to remember to.
#[must_use = "the caller branches on which regime the baked bundle is in"]
pub fn bundle_delegation_plane_v31_shaped(bundle: &GenesisBundle) -> Result<(), String> {
    for att in &bundle.attestations {
        let row = &att.attestation;
        // "v31-shaped" is a property of the envelope, not of one issue number.
        // Asking only about the #643 mirror was over-specific the moment #598's
        // instant gate widened past `consent:state:*`: the stale bundle now
        // trips the instant gate FIRST, and a predicate that answered
        // "row-bound: no" for the wrong reason would still be answering by
        // accident.
        //
        // v31.0.0 (CIRISPersist#660) — so ask the ONE routine that already owns
        // that question, [`classify_shape`](crate::federation::migration::classify_shape),
        // at the row's own instant. This was the second of two copies of it
        // living in this file; see `verify_delegation_plane_seeded` for the
        // three ways both copies had drifted. Evaluating at `asserted_at`
        // matters here for a reason of its own: a BAKED artifact's instants are
        // fixed at ceremony time and recede further into the past with every
        // release, so a wall-clock skew arm was asking a question about the
        // build clock, not about the bundle.
        //
        // **Measured, not assumed: `row.asserted_at` here is an EQUIVALENT
        // MUTANT today.** `classify_shape` DISCARDS its `now` argument
        // (`let _ = now;`, #650) and evaluates the binding at the row's own
        // instant regardless, so replacing this argument with `Utc::now()`
        // changes nothing — a mutation campaign confirmed it survives, as does
        // the converse mutation inside `classify_shape`. Only mutating BOTH
        // reaches the skew arm, and that pair reds
        // `delegation_plane_shape_is_clock_independent_660`.
        //
        // The redundancy is kept deliberately and stated rather than removed:
        // it is defence in depth for a property whose absence is silent, and
        // passing the wall clock here would be the wrong argument to pass even
        // while the callee ignores it. If `classify_shape` ever starts honouring
        // `now`, this call site is already correct.
        // v31.1.0 — ask the BINDING gates directly, NOT `classify_shape`.
        //
        // `classify_shape` also asks `check_canonical_at_rest`, which is a
        // STORAGE invariant: `sha256(stored column) == original_content_hash`.
        // An on-disk ceremony artifact is not "at rest in a database", and
        // `put_attestation` CANONICALIZES on ingest by design (#647) — so a
        // bundle whose envelope carries `weight: 1.0` where JCS emits `1` is
        // admitted, stored canonical, and entirely valid. Its signatures were
        // never at risk: `original_content_hash` is taken over
        // `ceg_produce_canonicalize(envelope)`, and canonicalize(1.0) == "1".
        //
        // Asking the storage question here produced a FALSE "pre-v31" verdict
        // for a genuinely v31 bundle, and the two halves disagreed out loud:
        // the predicate said legacy while the real door admitted the row. That
        // is #660's lesson one field over — a clock failure is not a shape
        // failure, and neither is a serialization difference. Shape is the
        // BINDING: does the row carry its mirror and its signed instants.
        crate::federation::admission::check_row_column_binding(row).map_err(|e| e.to_string())?;
        crate::federation::admission::check_instant_binding(
            row,
            row.asserted_at,
            crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
        )
        .map_err(|e| e.to_string())?;
        // v61 (CC 2.6.2) — and its signed instants are `.sssZ`.
        if let Some(v) = crate::federation::admission::signed_instant_form_violation(row) {
            return Err(format!(
                "attestation {}: `{}` = {:?} is not in the CC 2.6.2 form",
                row.attestation_id, v.member, v.value
            ));
        }
    }
    Ok(())
}

/// An ordinary, wholly unremarkable `scores` row under `id` from `attester` —
/// the "one row from any registered key" of the #660 finding. Caller seals it.
///
/// Shared by the squat witness and by the injected-squat legs, so the row the
/// door refuses and the row a backend smuggles past the door are the SAME row.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) fn ordinary_scores_row(id: &str, attester: &str) -> super::Attestation {
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
    let now = chrono::Utc::now();
    super::Attestation {
        attestation_id: id.to_owned(),
        attesting_key_id: attester.to_owned(),
        attested_key_id: attester.to_owned(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: Some(1.0),
        asserted_at: now,
        expires_at: None,
        attestation_envelope: serde_json::json!({
            "id": id,
            "dimension": "trust:demo:v1",
            "score": 1.0,
            "confidence": 0.9,
        }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: attester.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// v13.4.1 (CIRISPersist#392) — the **single shared genesis-seed routine** run
/// by BOTH engine constructors ([`Engine::with_signer`](crate::engine::Engine::with_signer)
/// AND the pyo3 `PyEngine::new`), so they are **seed-identical by construction**
/// and can never drift again. Called right after the backend-specific
/// `seed_genesis_accord_holders` (the only inherent-per-backend step); this
/// covers everything downstream of it, in order:
/// 1. [`verify_anchor_seeded`] — the A1/B1/C1 rooting anchors are live;
/// 2. [`seed_accord_family`] + [`verify_family_seeded`] — the entrenched
///    `quorum:2/3` HUMANITY_ACCORD family (#386);
/// 3. [`seed_canonical_servers`] + [`verify_canonical_seeded`] — the baked
///    2-of-3 canonical genesis server (#390).
///
/// Any future genesis bake MUST be added HERE (not inline in a ctor) so both
/// paths stay identical. Errors are `String`; each caller maps to its own error
/// type (`EngineError::GenesisSeed` / a `PyErr`). Generic over
/// [`FederationDirectory`] (pg/sqlite-symmetric); `seed_canonical_servers`
/// verifies the 2-of-3 against the just-seeded A1/B1 anchor, so ordering is
/// load-bearing and fail-secure.
pub async fn seed_family_and_canonical<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    verify_anchor_seeded(dir).await?;
    seed_accord_family(dir).await?;
    verify_family_seeded(dir).await?;
    // #449 — under a live test-anchor override the baked 2-of-3 canonical
    // record is NOT seedable by construction: its A1/B1 scrubs cannot verify
    // against the swapped SW roster (the m-of-n gate would fail-secure
    // refuse it, correctly). The local mesh harness mints its own software
    // canonical under the test anchor instead (CIRISVerify#202 /
    // CIRISServer#258), so skip the bake rather than brick the boot. Dead
    // code on a prod build (the fence compiles the branch out).
    // #973 — unless a software ceremony is installed: then every leg below
    // runs against ITS bundle and community, which the test roster signed.
    if test_anchor_override_active() {
        tracing::warn!(
            "CIRIS_TESTING_MODE: test trust root active — skipping the baked \
             2-of-3 canonical genesis seed (the harness mints its own canonical \
             under the SW test anchor). This MUST NOT appear in production."
        );
        return Ok(());
    }
    seed_canonical_servers(dir).await?;
    verify_canonical_seeded(dir).await?;
    // v59.0.0 (CIRISPersist#1106, CC 5.3.4) — the serve nodes' transit pairs,
    // once their keys are held.
    seed_serve_transport_destinations(dir).await?;
    seed_delegation_plane(dir).await?;
    verify_delegation_plane_seeded(dir).await?;
    // v53.1.0 — the accord head again, now that the delegation plane holds
    // this bundle's charter: a head left from an earlier ceremony, whose
    // charter the plane just superseded, is a stale genesis head and takes
    // the bundle's (I497). Before the plane is installed it cannot be told
    // apart from a working root, so the early call above leaves it.
    seed_accord_family(dir).await?;
    // #973 — the community birth, last: it is admitted THROUGH the key plane
    // and the delegation plane above. Inert until a ceremony bakes the asset.
    seed_canonical_community(dir).await?;
    verify_canonical_community_seeded(dir).await?;
    Ok(())
}

/// v59.0.0 (CIRISPersist#1106, CC 5.3.4 rc9 `6cde890`,
/// `CLM-bundle-seeds-transit-pairs`) — **seed the serve nodes' transit pairs
/// from the pinned bundle**, so a fresh node holds a Rooted pair for every
/// seated serve node with no network. Each row goes through the ORDINARY
/// signed transport-destination door
/// ([`put_signed_transport_destination`](super::FederationDirectory::put_signed_transport_destination):
/// the projection-equals-envelope check, the in-row separation rule, the
/// node's own hybrid signature, `signer_acts_for`), never a side door, so it
/// lands `Rooted` and `self_at_login::transit_kex_pair_for(node)` returns it.
/// A row this node already holds a newer binding for (a quorum re-bind) is
/// `Refused` by the monotonic apply and stays superseded. A v2 / v3 bundle
/// carries none: nothing is seeded.
///
/// # Errors
///
/// [`GenesisFault::Divergent`] when the pinned rows fail the bundle's
/// structural check or the door refuses one; `Unreadable` on a backend error.
pub async fn seed_serve_transport_destinations<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    let bundle = canonical_genesis_bundle();
    let divergent = |detail: String| GenesisFault::Divergent {
        leg: GenesisLeg::Canonical,
        detail,
    };
    check_serve_transport_destinations(bundle).map_err(|e| divergent(e.to_string()))?;
    for row in &bundle.serve_transport_destinations {
        match dir.put_signed_transport_destination(row).await {
            Ok(_) => {}
            Err(super::Error::Backend(e)) => {
                return Err(GenesisFault::Unreadable {
                    leg: GenesisLeg::Canonical,
                    detail: format!("serve transport destination seed: {e}"),
                })
            }
            Err(e) => {
                return Err(divergent(format!(
                    "{SERVE_TRANSPORT_DESTINATION_INVALID}: the pinned bundle's transport row for \
                     {} is refused by the transport door: {e}",
                    row.attesting_key_id
                )))
            }
        }
    }
    Ok(())
}

/// CIRISPersist#973 / v53.0.0 (CC rc7, T5) — the `ciris-canonical` birth
/// record **the pinned bundle carries**. The bundle is the only genesis
/// artifact: a community seeded from anything the bundle does not pin has no
/// anchor, so there is no separate community asset any more. `None` while the
/// bundle carries no birth (a version-2 bundle) — every caller treats `None` as
/// "this leg does not exist yet". Under a live test anchor with a software
/// ceremony installed this reads that ceremony's bundle, through
/// [`canonical_genesis_bundle`].
pub fn canonical_community_asset() -> Option<&'static super::SignedCommunity> {
    canonical_genesis_bundle()
        .community_record(super::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID)
}

/// CIRISPersist#973 — what the community boot leg did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityLegOutcome {
    /// No asset is compiled in: nothing read, nothing written.
    NotBaked,
    /// The birth was admitted through the signed door.
    Installed,
    /// This node already holds exactly the baked birth.
    AlreadyHeld,
    /// This node holds a DIFFERENT record under the id — a chain that has
    /// moved past the birth, or another ceremony's. Left untouched: the
    /// compiled asset is a floor, never the identity (the #665 rule).
    HeldDiffers,
    /// v53.1.1 — this node held a PRIOR genesis's birth (no predecessor,
    /// another charter) and the BAKE replaced it with the baked birth, keeping
    /// the held row as the superseded prior (operator ruling 2026-10-04).
    Replaced,
}

/// CIRISPersist#973 — **seed the baked community birth at boot.** See
/// [`seed_canonical_community_from`]; this passes the compiled asset.
///
/// # Errors
///
/// As [`seed_canonical_community_from`].
pub async fn seed_canonical_community<D>(dir: &D) -> Result<CommunityLegOutcome, GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    seed_canonical_community_from(dir, canonical_community_asset(), RosterSource::Bake).await
}

/// CIRISPersist#973 — the community boot leg over a given asset.
///
/// - no asset ⇒ [`CommunityLegOutcome::NotBaked`], without a read;
/// - the id is held ⇒ nothing is written ([`AlreadyHeld`](CommunityLegOutcome::AlreadyHeld)
///   or [`HeldDiffers`](CommunityLegOutcome::HeldDiffers));
/// - otherwise the birth goes through the ordinary SIGNED
///   [`put_community`](super::FederationDirectory::put_community) door —
///   signature, trust-root shape, founders, accord quorum, founding rule —
///   never a trusted-local write.
///
/// # Errors
///
/// Only [`GenesisFault::Absent`] (the door refused or errored: a node
/// awaiting its ceremony) and [`GenesisFault::Unreadable`] (the directory
/// could not be asked). NEVER `Divergent`: nothing this leg finds may stop a
/// boot.
pub async fn seed_canonical_community_from<D>(
    dir: &D,
    asset: Option<&super::SignedCommunity>,
    source: RosterSource,
) -> Result<CommunityLegOutcome, GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Community;
    let Some(birth) = asset else {
        return Ok(CommunityLegOutcome::NotBaked);
    };
    let id = &birth.community.community_key_id;
    let held = dir
        .lookup_community(id)
        .await
        .map_err(|e| GenesisFault::unreadable(LEG, format!("lookup community {id}: {e}")))?;
    if let Some(held) = held {
        let same = match (
            super::types::compute_persist_row_hash(&held),
            super::types::compute_persist_row_hash(&birth.community),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if same {
            return Ok(CommunityLegOutcome::AlreadyHeld);
        }
        // v53.1.1 — the operator's ruling on the final genesis (2026-10-04):
        // "It should replace right? This is a new seed even if it is the same
        // settings." The BAKE, and only the bake, replaces a held PRIOR-GENESIS
        // birth: a genesis row (no predecessor) that names another charter.
        // A version chain (a roster that moved past some birth) is never
        // rolled back, and an import never replaces a rooted row.
        // Codex on #983: only THE compiled asset's birth may replace (a
        // caller's row never does), and a held birth is replaceable only
        // when it names no charter, or names one that is no longer a live
        // charter row while the baked birth's is — the family rule
        // (`roster_install::genesis_head_replaceable`), so a NEWER birth a
        // node imported is never rolled back by an older bake.
        let is_compiled = canonical_community_asset().is_some_and(|c| {
            super::types::compute_persist_row_hash(&c.community).ok()
                == super::types::compute_persist_row_hash(&birth.community).ok()
        });
        let family = crate::federation::canonical_community::accord_family_key_id();
        let charter_superseded = if held.charter_digest.is_empty() {
            true
        } else {
            let held_live = roster_install::charter_row_live(dir, family, &held.charter_digest)
                .await
                .map_err(|e| GenesisFault::unreadable(LEG, format!("charter row: {e}")))?;
            let baked_live =
                roster_install::charter_row_live(dir, family, &birth.community.charter_digest)
                    .await
                    .map_err(|e| GenesisFault::unreadable(LEG, format!("charter row: {e}")))?;
            !held_live && baked_live
        };
        if source == RosterSource::Bake
            && is_compiled
            && held.prev_head_digest.is_empty()
            && charter_superseded
        {
            let snapshot = serde_json::to_value(birth)
                .map_err(|e| GenesisFault::unreadable(LEG, format!("birth snapshot: {e}")))?;
            dir.supersede_group_row(
                crate::federation::cohort::Cohort::Community,
                snapshot,
                Some(serde_json::json!({
                    crate::federation::canonical_community::BIRTH_REPLACES_UNROOTED:
                        held.persist_row_hash,
                })),
            )
            .await
            .map_err(|e| {
                GenesisFault::absent(
                    LEG,
                    format!("replace the held {id} row with the baked birth: {e}"),
                )
            })?;
            tracing::info!(
                community_key_id = %id,
                replaced = %held.persist_row_hash,
                "genesis community seed: the bake replaces the held prior-genesis birth with the \
                 baked birth (operator ruling 2026-10-04)"
            );
            return Ok(CommunityLegOutcome::Replaced);
        }
        tracing::info!(
            community_key_id = %id,
            "genesis community seed: this node holds a record under the baked id that is not              the baked birth — leaving it in place (CIRISPersist#973)"
        );
        return Ok(CommunityLegOutcome::HeldDiffers);
    }
    match dir.put_community(birth.clone()).await {
        Ok(()) => Ok(CommunityLegOutcome::Installed),
        Err(e) => Err(GenesisFault::absent(
            LEG,
            format!("seed community {id}: {e} (is the key and delegation plane seeded first?)"),
        )),
    }
}

/// CIRISPersist#973 — the community leg's presence check: with an asset
/// baked, the id it names is held. `Ok` without a read when no asset is baked.
///
/// # Errors
///
/// [`GenesisFault::Absent`] / [`GenesisFault::Unreadable`] only.
pub async fn verify_canonical_community_seeded<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    verify_canonical_community_seeded_for(dir, canonical_community_asset()).await
}

/// [`verify_canonical_community_seeded`] over a given asset.
///
/// # Errors
///
/// [`GenesisFault::Absent`] / [`GenesisFault::Unreadable`] only.
pub async fn verify_canonical_community_seeded_for<D>(
    dir: &D,
    asset: Option<&super::SignedCommunity>,
) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Community;
    let Some(birth) = asset else { return Ok(()) };
    let id = &birth.community.community_key_id;
    match dir.lookup_community(id).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(GenesisFault::absent(
            LEG,
            format!("community {id} not seeded"),
        )),
        Err(e) => Err(GenesisFault::unreadable(
            LEG,
            format!("lookup community {id}: {e}"),
        )),
    }
}

/// v31.1.0 — **install the baked bundle's DELEGATION PLANE at boot.**
///
/// Until 31.1.0 the boot seed installed only the KEY plane — the accord
/// holders, the `humanity-accord` family, the canonical serve nodes — and the
/// `genesis-charter` / `genesis-grant:…` / `genesis-lifecycle` rows were
/// installed by the explicit ceremony bake alone. That was survivable while
/// the baked bundle predated #643, because those rows were refused anyway.
///
/// With a v31-shaped seed it stops being survivable: the rows are installable,
/// nothing installs them, and [`verify_delegation_plane_seeded`] correctly
/// reports `PreGenesis { leg: Delegation }` forever. A node would ship a valid
/// trust root it never adopts — green artifact, dead conferral plane, which is
/// the exact fail-open the fourth posture leg exists to catch.
///
/// Discipline matches [`seed_canonical_servers`] deliberately:
/// - **already present and byte-current ⇒ no-op.** A row that matches the baked
///   artifact WHOLE — every column, via
///   [`baked_row_matches_stored`] — is this ceremony's row, already entrenched;
///   boot NORMALITY on a seeded fleet. Matching on `original_content_hash`
///   alone was not enough: that digest covers the envelope only, so corrupted
///   signature columns read as current. See
///   [`baked_row_matches_stored`] and `DelegationRowOutcome::Repaired`.
/// - **refused ⇒ `absent`, never `divergent`.** A refusal means this node is
///   awaiting its ceremony, and it must BOOT. `divergent` refuses to serve, and
///   an artifact that cannot install is not evidence of tampering — that
///   distinction is what keeps 31.0.0's seedless boot working.
///
/// # v31.1.0 (CIRISPersist#665) — the UPGRADE path: a re-bake SUPERSEDES
///
/// The first form of this routine skipped any id it found present, and that
/// bricked every upgrading node. The chain is short and entirely mechanical: a
/// v30 node already holds `genesis-charter` / `genesis-grant:…` /
/// `genesis-lifecycle` from the PREVIOUS ceremony — **same ids, different
/// content** — so the skip fired, [`verify_delegation_plane_seeded`] ran next,
/// found a stored `original_content_hash` that is not the baked one, and
/// returned `Divergent`. `Divergent` is the one posture arm that REFUSES TO
/// BOOT. A re-bake would therefore have taken down exactly the fleet that
/// v31.0.0 went out of its way to keep bootable, where a stale delegation plane
/// was `Absent` and `Absent` boots.
///
/// The divergent arm was written when a hash mismatch had exactly one cause: a
/// SUBSTITUTED conferral row. A re-bake produces a second, entirely legitimate
/// cause, and the arm cannot tell them apart from the hash alone — so the
/// separation has to happen HERE, before verification, and the baked bundle has
/// to win where it is entitled to.
///
/// ## Which mismatches are replaced, and which are still refused
///
/// **Chosen semantics: the baked artifact supersedes a PRIOR CEREMONY'S row,
/// and only a prior ceremony's row.** A mismatch is replaceable iff the STORED
/// row is a complete, self-consistent statement by the accord holders — which
/// is to say, all three of:
///
/// 1. it passes [`check_genesis_attestation_reserved`] — federation-tier, and
///    attested by a seated accord holder on THIS node's effective roster (the
///    #660 reservation, re-asked against a row that is already in the corpus
///    rather than one arriving at a door);
/// 2. its scrub signature verifies, under `Strict` hybrid policy, against that
///    attester's REGISTERED pubkeys, over its OWN envelope;
/// 3. the digest that verification returns — `SHA-256` of the canonical
///    envelope — is exactly the row's stored `original_content_hash`.
///
/// Leg 3 is not redundant with leg 2 and is the reason this is not merely a
/// signature check. `original_content_hash` is a COLUMN, and the ceremony's
/// signature is taken over the ENVELOPE, so the column is not covered by it —
/// a row can carry a perfectly valid holder signature and a content hash that
/// was scribbled on afterwards. Asking `verify_envelope_hybrid_signature` for
/// its return value rather than just its `Ok` binds the two back together: the
/// pairing (envelope, digest) is checked, not just the envelope.
///
/// Anything that fails any leg is LEFT EXACTLY WHERE IT IS and not written to.
/// [`verify_delegation_plane_seeded`] runs immediately after and classifies it
/// `Divergent`, boot refuses, and the operator gets the banner. **This is the
/// stated decision the finding asked for: a genuinely substituted row is still
/// detected, not silently overwritten.** The alternative — let the baked
/// artifact win over every mismatch — was rejected. It is safe in the narrow
/// sense (the only bytes this routine can ever write are the compiled-in ones,
/// so overwriting is never a privilege gain) but it would have retired the
/// delegation leg's `Divergent` arm entirely, and that arm is the only thing in
/// the substrate that notices a root altered beneath persist. Repairing damage
/// silently and reporting nothing is how a compromise stays invisible.
///
/// What an attacker cannot do, concretely: forge leg 2 without a seated
/// holder's key. A row renamed onto a genesis id beneath persist carries a
/// signature over its own former envelope and fails; a fabricated row claiming
/// `attesting_key_id: "A1"` fails; the baked row with a rewritten content hash
/// fails leg 3. All three stay `Divergent` — witnessed in
/// `assert_injected_squat_is_divergent` on all three backends.
///
/// ## The write
///
/// Replacement is a destructive boot-time write, so it goes through the one
/// door narrow enough to justify it —
/// [`purge_genesis_delegation_row_v31`](super::FederationDirectory::purge_genesis_delegation_row_v31),
/// which can only address ids the compiled-in bundle carries (see
/// [`check_genesis_rebake_purge_admission`]) — and is immediately followed by
/// an ordinary `put_attestation` of the baked row, so the replacement pays the
/// full admission stack exactly as a first-boot install does. The general purge
/// door is unusable here and deliberately so: `genesis-charter` and
/// `genesis-grant:…` are `delegates_to`, which `check_purge_admission` refuses
/// as exclusion-bearing, and weakening that gate to make a boot path convenient
/// is the trade CIRISPersist#650 exists to refuse.
///
/// A crash between the delete and the insert leaves the row missing, which is
/// `Absent` — it boots, and the next start re-installs it. There is no
/// interleaving that yields a worse state than "awaiting its ceremony".
///
/// # Idempotence
///
/// Boot runs every start. Second and later starts find the baked hash already
/// stored and take the no-op arm; the replacement arm is reachable only while a
/// prior ceremony's row is still present, and it removes its own precondition.
pub async fn seed_delegation_plane<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Delegation;
    for sa in &canonical_genesis_bundle().attestations {
        let id = &sa.attestation.attestation_id;
        // READ, then decide, then act. The read is separated from the decision
        // deliberately — see `install_or_supersede_delegation_row`, which takes
        // this value as an argument precisely so that the STALE read a lost
        // primary-key race produces is expressible as data.
        // v31.1.0 (CIRISPersist#665 review) — RE-READ AND RE-DECIDE on a lost
        // compare-and-delete. The decision is made from a read, and under a
        // rolling deployment another initializer can replace this row in
        // between; the destructive door then declines to fire and reports
        // `RaceLostReclassify`, having written nothing. Re-reading converges
        // immediately in practice — the competing writer has by then installed a
        // row this pass will classify as current or newer, both of which are
        // terminal — so the bound is small and exists only so a pathological
        // flapper cannot spin the boot.
        const RECLASSIFY_ATTEMPTS: usize = 4;
        for attempt in 1..=RECLASSIFY_ATTEMPTS {
            let stored = dir.get_attestation(id).await.map_err(|e| {
                GenesisFault::unreadable(LEG, format!("lookup delegation row {id}: {e}"))
            })?;
            match install_or_supersede_delegation_row(dir, sa, stored).await? {
                DelegationRowOutcome::RaceLostReclassify => {
                    tracing::info!(
                        attestation_id = %id,
                        attempt,
                        "genesis delegation seed: the row changed under our classification — \
                         re-reading and deciding again (CIRISPersist#665)"
                    );
                    continue;
                }
                _ => break,
            }
        }
        // Deliberately NOT a fault when the attempts are exhausted. Something
        // else is actively writing this id, so the plane is not this pass's to
        // settle; whatever that writer lands is subject to the same rules, and
        // `verify_delegation_plane_seeded` below judges the result on its
        // merits rather than on who got there last.
    }
    Ok(())
}

/// v31.1.0 (CIRISPersist#665) — **what [`seed_delegation_plane`] did about one
/// row**, so that a seed pass can be asserted on rather than inferred.
///
/// # THE REPLACEMENT MATRIX — who may replace what
///
/// Two doors write this plane: the BOOT SEED, which installs the compiled-in
/// baked bundle, and
/// `bake_assembled_genesis` (deleted in v62.0.0, json-cut C5), which installed
/// a quorum-verified ceremony bundle. Until the #665 review they
/// did not know the other existed, and every P1 raised against this file was
/// that gap seen from a different side. The closed set, so the next person to
/// touch either door has it at the definition site:
///
/// | stored | boot seed (installs the BAKED bundle) | authenticated bake (installs a CEREMONY bundle) |
/// |---|---|---|
/// | *nothing* | install → [`Installed`](Self::Installed) | install |
/// | a PRIOR ceremony's row (older) | replace → [`Superseded`](Self::Superseded) | replace if newer |
/// | the baked row, byte-whole | no-op → [`AlreadyCurrent`](Self::AlreadyCurrent) | no-op |
/// | this ceremony's row, unsigned material damaged | repair → [`Repaired`](Self::Repaired) | repair |
/// | a NEWER ceremony's row | **leave** → [`LeftAsNewerCeremony`](Self::LeftAsNewerCeremony) | replace if strictly newer |
/// | anything not a verifiable holder statement | **leave** → [`LeftAsSubstituted`](Self::LeftAsSubstituted), and refuse to serve | refuse |
///
/// One rule generates every row of it:
///
/// > **A reserved genesis delegation row may be replaced only by a STRICTLY
/// > NEWER row that is itself a verifiable statement by this node's seated
/// > accord holders — never by an older one, from either door.**
///
/// Authenticity is [`stored_row_is_verifiable_holder_statement`]; recency is
/// [`candidate_is_strictly_newer`]. Both must pass before anything is deleted.
/// The two questions are separate on purpose: fusing them is what let a
/// legitimate newer ceremony be read as a supersedable predecessor, because
/// "real" was being taken to mean "prior".
///
/// Note the asymmetry in the newer-ceremony row, and that it is deliberate: the
/// boot seed may never overwrite a newer statement, while the bake may — a
/// ceremony is the accord holders acting, and a binary's compiled-in bundle is
/// just the oldest thing in the room.
///
/// # And the rule is not enough on its own: the WRITE has to be atomic
///
/// Every decision above is made from a `get_attestation` taken before the write,
/// so the authority answer can be correct and the write still wrong. Under a
/// rolling deployment — two engine versions initializing one postgres database,
/// which is simply what a fleet upgrade is — another initializer can replace the
/// row between the classifying read and the write. A stale initializer then
/// deletes a NEWER constitutional statement and installs its own older baked
/// one: the exact rollback this table refuses, performed by the caller that had
/// already been told it was allowed to write.
///
/// So the destructive door is a COMPARE-AND-DELETE. It carries the
/// `persist_row_hash` of the row that was classified and fires only if that is
/// still the row that is there; otherwise it writes nothing and the caller
/// re-reads and decides again ([`RaceLostReclassify`](Self::RaceLostReclassify)).
/// **Reclassify, never remove.**
///
/// The non-destructive paths need no equivalent, and it is worth saying why
/// rather than leaving it to be rediscovered: an `INSERT` that races a newer row
/// fails on the primary key and is reported as [`Raced`](Self::Raced), so the
/// newer row stands untouched. Only a delete can destroy something, so only the
/// delete carries the compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationRowOutcome {
    /// The plane did not hold this id; the baked row was installed.
    Installed,
    /// The baked row was already stored, byte-current. Boot normality.
    AlreadyCurrent,
    /// A PREVIOUS ceremony's row was removed and the baked row installed over
    /// it. The upgrade path — see [`seed_delegation_plane`].
    Superseded,
    /// THIS ceremony's row was present with its signed envelope intact but the
    /// unsigned material around it altered beneath persist — a corrupted
    /// signature column, a thinned `additional_scrubs` quorum set, a scribbled
    /// content hash — and the baked artifact was restored over it.
    ///
    /// Distinct from [`Superseded`](Self::Superseded) on purpose: nothing
    /// constitutional changed (the holders' statement is byte-identical), but
    /// something that is NOT a write door wrote to the corpus, and an operator
    /// should be told which of those two happened.
    Repaired,
    /// The install lost a primary-key race: somebody else wrote this id between
    /// the read and the write. The row is present, so the plane is seeded;
    /// nothing more to do, and emphatically not a reason to stop seeding.
    Raced,
    /// The compare-and-delete found a different row than the one classified —
    /// somebody wrote this id between the caller's read and its write. **Nothing
    /// was written**, and the caller should re-read and decide again.
    ///
    /// Reached in a rolling deployment, where two engine versions initialize one
    /// database. Forcing the install instead would let a stale initializer roll
    /// a newer ceremony back to its own compiled-in bytes — the exact rollback
    /// [`candidate_is_strictly_newer`] refuses, performed by the one caller that
    /// had already decided it was entitled to write.
    RaceLostReclassify,
    /// A verified accord-holder statement is present that is **not older** than
    /// the compiled-in one. It was LEFT UNTOUCHED and the node serves on it.
    ///
    /// This node's root is ahead of its binary — a re-ceremony ran here, or on
    /// a peer this node replicated from — which is the entire point of a trust
    /// root that can be re-cut. The boot seed has no authority to roll it back:
    /// the compiled-in bundle is the oldest statement in the room, not the
    /// definitive one.
    LeftAsNewerCeremony,
    /// A row is present that is neither the baked one nor a verifiable
    /// statement by a seated accord holder. It was LEFT UNTOUCHED;
    /// [`verify_delegation_plane_seeded`] will classify it `Divergent` and boot
    /// will refuse.
    LeftAsSubstituted,
}

/// v31.1.0 (CIRISPersist#665) — the per-row body of [`seed_delegation_plane`],
/// which owns the whole install/supersede/refuse decision for ONE baked row.
///
/// `stored` is what the caller's [`get_attestation`](super::FederationDirectory::get_attestation)
/// returned. It is a PARAMETER rather than a read taken here, and that is the
/// load-bearing part of this signature: between a boot's read and its write,
/// another engine initializing the same database can install the row, and the
/// only faithful expression of the loser's position is *"acted on `None` while
/// the row exists"*. Passing the read in makes that state reachable by a
/// witness without a timing-dependent harness, and it costs the production path
/// nothing — the caller reads once and hands the value over.
///
/// The decision rules, and the reasoning for every arm, live in
/// [`seed_delegation_plane`]'s documentation.
///
/// # Errors
///
/// [`GenesisFault::absent`] if the row could not be installed or a previous
/// ceremony's row could not be removed. Never [`GenesisFault::divergent`]: an
/// artifact that will not install is a node awaiting its ceremony, and it must
/// BOOT. Divergence is [`verify_delegation_plane_seeded`]'s verdict to reach,
/// over the corpus, after seeding has done what it can.
pub async fn install_or_supersede_delegation_row<D>(
    dir: &D,
    sa: &super::SignedAttestation,
    stored: Option<super::Attestation>,
) -> Result<DelegationRowOutcome, GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Delegation;
    let baked = &sa.attestation;
    let id = &baked.attestation_id;

    if let Some(stored) = stored {
        // Already this ceremony's row, WHOLE. The overwhelmingly common path on
        // every start after the first.
        //
        // v31.1.0 (CIRISPersist#665 review) — this compares the ROW, not its
        // content hash. `original_content_hash` is the digest of the ENVELOPE
        // alone, so a row whose envelope and hash are untouched while its
        // `scrub_signature_classical`, its PQC half or its `additional_scrubs`
        // were rewritten beneath persist passed this check — and passed
        // `verify_delegation_plane_seeded` behind it, which asks only for the
        // content hash and the v31 shape and never verifies a signature. The
        // node then reported `entrenched` while holding a constitutional row
        // that can no longer pass federation ingest.
        //
        // That is not theoretical on `genesis-charter`. It is the FAMILY
        // CHARTER, and [`family_quorum_over`](crate::federation::trust_root)
        // counts DISTINCT VERIFIED co-signatures over its envelope: drop B1's
        // entry from `additional_scrubs` and the charter falls from 2-of-3 to 1,
        // the constitutional trust root stops validating, and the posture still
        // says `entrenched`. A fail-OPEN banner — precisely the class the
        // delegation leg was added (#648) to catch, reintroduced one column
        // over. Same unsigned-column-beside-signed-bytes shape as the
        // `original_content_hash` gap closed in `stored_row_is_verifiable_holder_statement`.
        match baked_row_matches_stored(&stored, baked) {
            Ok(true) => return Ok(DelegationRowOutcome::AlreadyCurrent),
            Ok(false) => {}
            // Unanswerable ⇒ NOT current. Fail-secure: never report a root
            // entrenched on the strength of a question that could not be asked.
            Err(e) => {
                return Err(GenesisFault::unreadable(
                    LEG,
                    format!("delegation row {id} could not be compared to the baked artifact: {e}"),
                ))
            }
        }

        // Not the baked row. Before asking whether it is somebody ELSE'S
        // statement, ask whether it is THIS one, damaged.
        //
        // The signed envelope is the ceremony's entire statement — the
        // signature covers `attestation_envelope` and nothing else. So a stored
        // row whose canonical envelope is byte-identical to the baked one IS
        // this ceremony's row, with the unsigned material around it altered:
        // a corrupted signature column, a thinned co-signature set, a scribbled
        // content hash. Restoring the compiled-in bytes destroys no
        // constitutional statement, because the statement is the same one — the
        // node is putting back exactly what the holders signed.
        //
        // Deliberately NOT silent, and deliberately not a boot refusal. The
        // damage is only reachable by a writer who already has raw access to
        // the corpus (the write doors cannot produce it — #660 reserves these
        // ids), so refusing to serve would hand that writer a one-byte outage
        // on a node whose own binary is holding the correct row. It is logged
        // at ERROR and reported as a distinct outcome so the repair is
        // observable rather than invisible.
        match envelope_matches_baked(&stored, baked) {
            Ok(true) => {
                tracing::error!(
                    attestation_id = %id,
                    "genesis delegation seed: this ceremony's row is present with its SIGNED \
                     ENVELOPE intact but the material around it altered beneath persist \
                     (signature columns, co-signature set, or content hash). Restoring the baked \
                     artifact. The corpus was modified by something that is not a write door — \
                     investigate the host (CIRISPersist#665)"
                );
                return replace_with_baked(
                    dir,
                    sa,
                    &stored.persist_row_hash,
                    DelegationRowOutcome::Repaired,
                )
                .await;
            }
            Ok(false) => {}
            Err(e) => {
                return Err(GenesisFault::unreadable(
                    LEG,
                    format!("delegation row {id} envelope could not be canonicalized: {e}"),
                ))
            }
        }

        // A different statement entirely. Two questions, in this order, and both
        // must pass before anything is deleted: is it REAL, and are we NEWER?
        if !stored_row_is_verifiable_holder_statement(dir, &stored).await {
            tracing::error!(
                attestation_id = %id,
                stored_content_hash = %stored.original_content_hash,
                baked_content_hash = %baked.original_content_hash,
                "genesis delegation seed: a row under this baked id is present, does NOT match \
                 the baked artifact, and is NOT a verifiable statement by a seated accord \
                 holder — leaving it untouched. This is a SUBSTITUTED conferral row; the posture \
                 check that runs next will refuse to serve"
            );
            return Ok(DelegationRowOutcome::LeftAsSubstituted);
        }
        // It is real. **A real statement newer than ours is our SUCCESSOR, not
        // our problem** — this node is running a ceremony that postdates the
        // binary, which is the entire point of a trust root that can be re-cut.
        // Rolling it back to the compiled-in bytes would destroy a newer
        // constitutional statement and pin the mesh to whatever its oldest
        // binary happens to carry.
        if !candidate_is_strictly_newer(baked, &stored) {
            tracing::info!(
                attestation_id = %id,
                stored_asserted_at = %stored.asserted_at,
                baked_asserted_at = %baked.asserted_at,
                "genesis delegation seed: this node holds a verified accord-holder statement \
                 that is not older than the compiled-in one — leaving it in place. The mesh's \
                 root is ahead of this binary, which is allowed (CIRISPersist#665)"
            );
            return Ok(DelegationRowOutcome::LeftAsNewerCeremony);
        }
        tracing::warn!(
            attestation_id = %id,
            superseded_content_hash = %stored.original_content_hash,
            baked_content_hash = %baked.original_content_hash,
            "genesis delegation seed: replacing a PREVIOUS ceremony's row with the baked \
             artifact (CIRISPersist#665)"
        );
        return replace_with_baked(
            dir,
            sa,
            &stored.persist_row_hash,
            DelegationRowOutcome::Superseded,
        )
        .await;
    }

    match dir.put_attestation(sa.clone()).await {
        // v38.5.0 (CIRISPersist#771) — the TYPED duplicate signal the #665
        // comment below said would have to exist. `AlreadyHeld` IS the lost
        // race: the row is present and this call did not put it there.
        Ok(crate::federation::AttestationOutcome::Inserted) => Ok(DelegationRowOutcome::Installed),
        Ok(_) => Ok(DelegationRowOutcome::Raced),
        // v31.1.0 (CIRISPersist#665) — A LOST PRIMARY-KEY RACE IS SUCCESS.
        //
        // Two engines initializing one database both read `None` above and both
        // write; one loses. The loser previously fell to the arm below and
        // returned `absent`, which ABANDONS THE REST OF THE PLANE — so if the
        // winner exited after its first insert, the node stayed permanently
        // half-seeded until somebody restarted it.
        //
        // The reason the old `Conflict`-only match never fired is that NO
        // backend reports a duplicate `attestation_id` as `Conflict`: all three
        // render it as `Error::Backend`. That predicate now lives in exactly one
        // place — see `Error::is_duplicate_key`, which also records why it is a
        // string test and what would have to change to make it a typed one.
        Err(e) if e.is_duplicate_key() => Ok(DelegationRowOutcome::Raced),
        // CIRISPersist#973 — the bake was offered and refused, and no row is
        // held under this id: nothing is in force on this row.
        Err(e) => Err(GenesisFault::bake_not_adopted(
            LEG,
            format!("delegation row {id} could not be installed: {e}"),
            BakeNotAdoptedReason::Refused {
                refusal: e.kind().to_owned(),
            },
            false,
        )),
    }
}

/// v31.1.0 (CIRISPersist#665) — the row `put_attestation` WOULD have stored for
/// this baked artifact: envelope canonical at rest (#647), `persist_row_hash`
/// stamped. Comparing a stored row against the raw bundle row instead would
/// report a false mismatch on both counts.
fn baked_row_as_stored(baked: &super::Attestation) -> Result<super::Attestation, super::Error> {
    let mut expected = baked.clone();
    super::canonical_at_rest::canonicalize_in_place(&mut expected.attestation_envelope)?;
    expected.persist_row_hash = super::types::compute_persist_row_hash(&expected)?;
    Ok(expected)
}

/// v31.1.0 (CIRISPersist#665 review) — **is the stored row the baked row, whole?**
///
/// The `AlreadyCurrent` test. Compares the two rows' `persist_row_hash`
/// DIGESTS — recomputed from content on both sides, never trusting either
/// stored column — because that digest is taken over the entire row minus
/// itself. Every column the ceremony fixes is therefore covered in one
/// comparison: the scrub signature, its PQC half, the `additional_scrubs`
/// quorum set, the envelope, the content hash, the endpoints, the tier. **A
/// column added to `Attestation` in future is covered automatically**, which a
/// hand-listed field-by-field comparison would not be — and this check exists
/// because a hand-picked single field (`original_content_hash`) was what let
/// corrupted signatures read as current.
///
/// Digests rather than `==` on the struct, deliberately:
/// [`compute_persist_row_hash`](crate::federation::types::compute_persist_row_hash)
/// truncates every instant to microseconds before hashing (#646) precisely so
/// the answer is reproducible across backends. Postgres stores microseconds
/// where sqlite and memory store nanoseconds, so a struct comparison would
/// report a false mismatch on postgres alone — the "memory tolerates what
/// postgres rejects" trap, inverted.
///
/// What it does NOT cover: the stored `persist_row_hash` COLUMN itself, which
/// the digest drops by construction. That column is persist-computed
/// bookkeeping rather than ceremony content and is not authority-bearing on
/// this plane; the row's substance is fully covered.
///
/// # Errors
///
/// If either row cannot be canonicalized or hashed. The caller treats that as
/// NOT current — never report a root entrenched on a question that could not be
/// asked.
fn baked_row_matches_stored(
    stored: &super::Attestation,
    baked: &super::Attestation,
) -> Result<bool, super::Error> {
    let expected = baked_row_as_stored(baked)?;
    let want = super::types::compute_persist_row_hash(&expected)?;
    let got = super::types::compute_persist_row_hash(stored)?;
    Ok(want == got)
}

/// v31.1.0 (CIRISPersist#665 review) — **is the stored row's SIGNED STATEMENT
/// the baked one, whatever state the unsigned material around it is in?**
///
/// The signature covers `attestation_envelope` and nothing else, so a canonical
/// envelope equal to the baked canonical envelope means the holders said exactly
/// this. Used to separate *this ceremony's row, damaged* from *somebody else's
/// statement* — the first is repairable from the compiled-in artifact without
/// destroying anything, the second is not.
///
/// Compared canonically on both sides so a difference in key order or number
/// rendering — which the producer's signature is indifferent to — is not read as
/// a different statement.
fn envelope_matches_baked(
    stored: &super::Attestation,
    baked: &super::Attestation,
) -> Result<bool, super::Error> {
    let want = super::canonical_at_rest::canonical_bytes(&baked.attestation_envelope)?;
    let got = super::canonical_at_rest::canonical_bytes(&stored.attestation_envelope)?;
    Ok(want == got)
}

/// v31.1.0 (CIRISPersist#665) — remove the row under this baked id and install
/// the baked artifact over it, reporting `outcome` on success.
///
/// The one place the destructive half happens, shared by the SUPERSEDE arm (a
/// previous ceremony's row) and the REPAIR arm (this ceremony's row with the
/// unsigned material around it altered). Both write the same bytes through the
/// same doors; only the reason differs, and the reason is the caller's to log.
///
/// A crash between the delete and the insert leaves the row missing, which is
/// `Absent` — it boots, and the next start re-installs it. There is no
/// interleaving that yields a worse state than "awaiting its ceremony".
async fn replace_with_baked<D>(
    dir: &D,
    sa: &super::SignedAttestation,
    expected_persist_row_hash: &str,
    outcome: DelegationRowOutcome,
) -> Result<DelegationRowOutcome, GenesisFault>
where
    D: super::FederationDirectory + ?Sized,
{
    const LEG: GenesisLeg = GenesisLeg::Delegation;
    let id = &sa.attestation.attestation_id;

    // v31.1.0 (CIRISPersist#665 review) — **PRE-FLIGHT THE DETERMINISTIC DOORS
    // BEFORE DELETING ANYTHING.**
    //
    // The recovery story for this routine was "a crash between the delete and
    // the insert leaves the row missing, which is `Absent`, which boots and
    // re-installs next start". That covers a CRASH. It does not cover a
    // REFUSAL: if `put_attestation` returns a non-duplicate `Err`, the old row
    // is already gone and the next start re-reads `None`, takes the insert
    // branch, and hits the very same refusal. Stable, not transient — the node
    // is permanently out of `Entrenched` with no row at all.
    //
    // `put_attestation` is a full admission door (envelope size, reserved
    // prefix, the #643/#598 bindings, quota), and #653 is exactly the class
    // where one artifact is admitted at one door and refused at another. The
    // severity is worst on the REPAIR arm, where the row being deleted still
    // carries a byte-identical SIGNED ENVELOPE — the holders' actual statement
    // — and a failed insert trades a partially-damaged constitutional row for
    // no constitutional row.
    //
    // So the checks that are PURE and DETERMINISTIC — the ones whose refusal
    // would simply recur — run here, while the old row is still present. A
    // refusal now costs nothing: nothing has been deleted. Rate limiting is
    // deliberately not pre-flighted; it is neither pure nor deterministic, and
    // a door that could refuse for a transient reason is exactly the one whose
    // retry the next boot fixes.
    // CIRISPersist#973 — on the SUPERSEDE arm the row being replaced is a
    // verified holder statement of an earlier ceremony: while it is still
    // present, the previous root is in force. (The repair arm replaces this
    // ceremony's own damaged row; nothing older stands behind it.)
    let predecessor_stands = outcome == DelegationRowOutcome::Superseded;
    if let Err(e) = preflight_replacement_admission(&sa.attestation) {
        return Err(GenesisFault::bake_not_adopted(
            LEG,
            format!(
                "refusing to remove the installed delegation row {id}: the replacement would be \
                 refused at the write door anyway ({e}) — nothing deleted"
            ),
            BakeNotAdoptedReason::Refused {
                refusal: e.kind().to_owned(),
            },
            predecessor_stands,
        ));
    }

    match dir
        .purge_genesis_delegation_row_v31(
            id,
            expected_persist_row_hash,
            &bundle::GenesisPurgeAuthority::CompiledIn,
        )
        .await
    {
        // v31.1.0 (CIRISPersist#665 review) — the compare-and-delete found a
        // DIFFERENT row than the one that was classified. Somebody else wrote
        // this id between our read and this call — a rolling deployment, most
        // likely — so the decision that authorized this write was made against a
        // corpus that no longer exists. Write NOTHING and tell the caller to
        // re-decide; forcing the install here is precisely how a stale
        // initializer would roll a newer ceremony back.
        Ok(false) => return Ok(DelegationRowOutcome::RaceLostReclassify),
        Ok(true) => {}
        // A directory with no replacement door cannot be repaired or upgraded
        // in place. `absent` BOOTS — and it short-circuits ahead of
        // `verify_delegation_plane_seeded`, so such a node comes up awaiting its
        // ceremony rather than bricked by a fault it cannot clear.
        Err(e @ super::Error::Unsupported { .. }) => {
            return Err(GenesisFault::bake_not_adopted(
                LEG,
                format!(
                    "delegation row {id} needs replacing and this directory has no re-bake \
                     replacement door: {e}"
                ),
                BakeNotAdoptedReason::Refused {
                    refusal: e.kind().to_owned(),
                },
                predecessor_stands,
            ))
        }
        Err(e) => {
            return Err(GenesisFault::bake_not_adopted(
                LEG,
                format!("delegation row {id} could not be removed for replacement: {e}"),
                BakeNotAdoptedReason::Refused {
                    refusal: e.kind().to_owned(),
                },
                predecessor_stands,
            ))
        }
    }
    match dir.put_attestation(sa.clone()).await {
        // v38.5.0 (#771) — same typed split as above; a duplicate is the race
        // arm, never a fresh install.
        Ok(crate::federation::AttestationOutcome::Inserted) => Ok(outcome),
        Ok(_) => Ok(DelegationRowOutcome::Raced),
        // Somebody else completed the same replacement first. The plane holds
        // the baked row either way, which is what this was for.
        Err(e) if e.is_duplicate_key() => Ok(DelegationRowOutcome::Raced),
        // The predecessor was removed above and the bake was then refused:
        // nothing stands under this id.
        Err(e) => Err(GenesisFault::bake_not_adopted(
            LEG,
            format!("baked delegation row {id} could not be installed over its predecessor: {e}"),
            BakeNotAdoptedReason::Refused {
                refusal: e.kind().to_owned(),
            },
            false,
        )),
    }
}

/// v31.1.0 (CIRISPersist#665 review) — **is `candidate` strictly newer than
/// `stored`?** The anti-rollback half of the replacement rule.
///
/// Both doors onto this plane ask it, and neither may write an older statement
/// over a newer one. It is the same discipline the SERVE-NODE half of
/// `bake_assembled_genesis` (deleted in v62.0.0) had (`valid_from` must advance), finally applied to the
/// delegation half — which had no recency check of any kind, which is how the
/// boot seed came to roll a live re-ceremony back to the compiled-in bytes.
///
/// # The clock, and why it is not simply `asserted_at`
///
/// On a **v31-shaped** row `asserted_at` is inside the signed envelope and
/// [`check_instant_binding`](crate::federation::admission::check_instant_binding)
/// requires the column to equal it, so the column is as trustworthy as the
/// signature. On a **pre-v31** row it is not in the envelope at all — the whole
/// reason #598 bound it — so the column is unsigned material that anything with
/// raw corpus access can stamp. Reading it as a clock would hand that writer a
/// permanent pin: set a legacy row's `asserted_at` to 2030 and no future
/// binary could ever supersede it.
///
/// So **shape is the version signal, and it is consulted first**: a legacy row
/// predates the v31 envelope by construction — that is what makes it legacy —
/// and therefore never gets to assert its own recency. Only once both rows are
/// v31-conformant, and both instants are consequently signed, does the
/// comparison become a timestamp comparison.
///
/// A legacy CANDIDATE is never newer than anything. Neither door has a reason
/// to install one: the compiled-in bundle of any binary carrying this code is
/// v31-shaped, and a bundle that is not cannot pass `put_attestation` anyway.
///
/// # Tier 1
///
/// Pure — two shape classifications and a timestamp compare. No directory read,
/// no crypto. Authenticity is a separate question, asked by
/// [`stored_row_is_verifiable_holder_statement`]; this one asks only "which came
/// later", and the caller must satisfy BOTH before replacing anything.
fn candidate_is_strictly_newer(
    candidate: &super::Attestation,
    stored: &super::Attestation,
) -> bool {
    use crate::federation::migration::{classify_shape, RowShape};
    // Evaluated at each row's OWN instant — the #650 rule. `classify_shape`
    // discards the argument today, but passing the wall clock would be the
    // wrong argument to pass to a question about a stored artifact.
    //
    // **The two sides are normalized differently, and that asymmetry is
    // load-bearing.** A CANDIDATE arrives from a bundle and has not been through
    // `put_attestation` yet, so its envelope is not canonical at rest (#647) —
    // classifying it raw reports `Legacy` for every bundle row ever written,
    // including the compiled-in one, and a candidate that cannot establish its
    // own shape can never supersede anything. Measured, not reasoned: this is
    // what the upgrade witness caught, and without the normalization the v30
    // rows survive a re-bake untouched.
    //
    // A STORED row gets no such courtesy. It has already been through a door,
    // so a non-canonical envelope on it is a genuine #647 violation rather than
    // a not-yet-normalized artifact — and normalizing it here would let an
    // injected row launder itself into looking v31-shaped. Judged as it lies:
    // fail-secure.
    let candidate_v31 = candidate_is_v31_conformant_as_stored(candidate);
    let stored_v31 = matches!(
        classify_shape(stored, stored.asserted_at),
        RowShape::V31Conformant
    );
    match (candidate_v31, stored_v31) {
        // Both instants are signed and bound. Now a clock is meaningful.
        (true, true) => candidate.asserted_at > stored.asserted_at,
        // The stored row predates the signed-instant envelope by construction,
        // so it loses without its unsigned column being consulted at all.
        (true, false) => true,
        // Never install an older-shaped row over anything, and never let one
        // claim to be newer.
        (false, _) => false,
    }
}

/// v31.1.0 (CIRISPersist#665 review) — **THE INVARIANT THIS PLANE ACTUALLY
/// OWES: can it meet quorum RIGHT NOW?**
///
/// Counts the DISTINCT SEATED HOLDERS whose scrub over this row's own envelope
/// verifies against the node's directory-pinned pubkeys, and compares that to
/// the threshold re-derived from the node's own revocation-folded roster —
/// [`family_quorum_over`](crate::federation::trust_root::family_quorum_over),
/// the same body the charter plane and the mesh-config plane count with. One
/// implementation of m-of-n-over-a-row; this is a third caller, not a third
/// opinion.
///
/// # Why this exists, and why it is not a fourth special case
///
/// [`verify_delegation_plane_seeded`] has now reported `Entrenched` on a plane
/// that could not confer THREE times, and each time the fix was correct for the
/// case in front of it and wrong as a rule:
///
/// 1. it verified no signature at all — any stored bytes with the right content
///    hash passed;
/// 2. it gained whole-row comparison, but only on the SEED path, so damage
///    landing after boot was invisible to every live query;
/// 3. it gained whole-row comparison on the read path too — but only where a
///    baked comparand EXISTS. The floor rule then deliberately introduced a
///    path where the stored row is legitimately *not* the baked row, and that
///    path had no wholeness check at all, because there was nothing to compare
///    against.
///
/// The through-line is that byte-equality against a compiled-in artifact was
/// never the property. It was a PROXY that happened to imply the property, and
/// each new legitimate way for a row to differ from the artifact silently
/// removed the implication while leaving the code looking careful.
///
/// The property is this: **every conferral row on this plane still carries at
/// least the threshold of distinct verified seated-holder signatures.** That is
/// what `family_quorum_over` answers, it needs no comparand, and it holds for a
/// baked row, a newer ceremony's row, and any row a future path decides to
/// accept. Anyone adding such a path should preserve THIS, not copy whichever
/// comparison happens to be nearby.
///
/// # Errors
///
/// [`Error`](super::Error) if the accord family or the roster cannot be read.
/// A node that cannot answer must not be told its root is sound.
/// `Ok(None)` means this node has no accord family at all. That is a
/// PRE-GENESIS fact and [`verify_family_seeded`] is the leg that owns it — it
/// runs ahead of this one in the boot sequence — so this leg neither
/// double-reports it nor pretends to have counted a quorum without a roster.
async fn delegation_row_accord_quorum<D>(
    dir: &D,
    row: &super::Attestation,
) -> Result<Option<crate::federation::trust_root::CharterQuorum>, super::Error>
where
    D: super::FederationDirectory + ?Sized,
{
    // The authority behind EVERY genesis delegation row is the accord holders'
    // quorum — that is what the ceremony is — so all three are counted against
    // the humanity-accord family regardless of which subject they attest.
    let family_key_id = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let Some(family) = dir.lookup_family(family_key_id).await? else {
        return Ok(None);
    };
    crate::federation::trust_root::family_quorum_over(dir, row, &family)
        .await
        .map(Some)
}

/// v31.1.0 (CIRISPersist#665 review) — **may this stored row be served on in
/// place of the compiled-in artifact?** Only if it STRICTLY SUPERSEDES it.
///
/// A one-line predicate with a name, because the distinction it encodes is one
/// character wide and was wrong: the check asked *"the baked row is not newer
/// than the stored one"*, which is TRUE when the two are the same age. A stored
/// row of the same envelope-bound vintage as the compiled-in artifact but with
/// DIFFERENT content therefore read as a successor, and posture could reach
/// `Entrenched` on a plane where neither statement supersedes the other.
///
/// Equal time with different content is not a successor. It is an AMBIGUITY,
/// and `Entrenched` is the strongest claim this plane makes — conferring it on
/// a state the node cannot adjudicate is the same class as the other rounds of
/// this review: a gate reporting something it cannot back. **The successor has
/// to win, not tie.**
///
/// Split out so the rule is drivable on its own. The end-to-end path is not: a
/// stored row must be a VERIFIED holder statement to reach it, and forging one
/// of equal vintage with different content needs holder keys. This predicate is
/// pure, so `equal_vintage_is_not_a_successor_665` drives the rule itself
/// rather than a caller that happens to reach it.
///
/// # The baked side is normalized HERE (CIRISPersist#973)
///
/// [`candidate_is_strictly_newer`] judges its second argument as a STORED row
/// and does not normalize it. The compiled-in bundle row is not canonical at
/// rest, so handed raw it classifies `Legacy` and loses to every conformant
/// stored row: the posture leg passed it raw, and a stored row OLDER than the
/// bake — or of the same vintage with different content — read as its
/// successor. `Entrenched` was reported on a root the binary's own bake had
/// not replaced. The unit witness above this function normalized the baked
/// row in its fixture, which is why it never saw the caller's shape. A baked
/// row that cannot be normalized supersedes nothing and is superseded by
/// nothing: `false`.
fn stored_is_acceptable_successor(stored: &super::Attestation, baked: &super::Attestation) -> bool {
    match baked_row_as_stored(baked) {
        Ok(baked_as_stored) => candidate_is_strictly_newer(stored, &baked_as_stored),
        Err(_) => false,
    }
}

/// v31.1.0 (CIRISPersist#665 review) — **the deterministic doors
/// `put_attestation` will run, asked BEFORE anything is deleted.**
///
/// Every replacement on this plane is delete-then-insert, so a refusal at the
/// insert leaves the old row gone and the retry hitting the same refusal —
/// stable, not transient. The recovery story ("a crash leaves it `Absent`,
/// which boots and re-installs") covers a CRASH and not a REFUSAL. So the
/// checks whose refusal would simply RECUR run here, while the row that is
/// about to be destroyed is still present, and a refusal costs nothing.
///
/// # The wall clock is the one that matters, and it is the one that was missing
///
/// The first version of this preflight asked
/// [`candidate_is_v31_conformant_as_stored`], which classifies at the ROW'S OWN
/// instant (#650, deliberately — shape is not a freshness question). But
/// `put_attestation`'s instant gate evaluates against `Utc::now()` with
/// [`DEFAULT_MAX_TOUCH_SKEW`](crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW),
/// and those two disagree by construction for exactly one input: **a ceremony
/// produced on a machine whose clock runs ahead.** Such a bundle is
/// v31-conformant at its own instant, passes recency, gets the installed row
/// purged — and is then refused by the wall-clock gate, with the constitutional
/// row already deleted and every earlier id in the loop already replaced.
///
/// Nothing exotic triggers it. It is a ceremony machine with a fast clock, in
/// the release whose purpose is running that ceremony. So the preflight asks
/// the gate the way the door asks it, against the same clock, and a
/// shape-only preflight is not enough.
///
/// Deliberately NOT preflighted: the write quota. It is neither pure nor
/// deterministic, and a transient refusal is exactly the kind a later attempt
/// fixes — pre-empting it would trade a recoverable retry for a refusal.
///
/// # Errors
///
/// The refusal `put_attestation` would have produced, so the caller can quote it.
pub(crate) fn preflight_replacement_admission(
    row: &super::Attestation,
) -> Result<(), super::Error> {
    check_genesis_attestation_reserved(row)?;
    // Judged in the form it will be STORED — a bundle row is not canonical at
    // rest until the door canonicalizes it, and the gates below run after that.
    let normalized = baked_row_as_stored(row)?;
    super::admission::check_envelope_size_admission(&normalized.attestation_envelope)?;
    if let crate::federation::migration::RowShape::Legacy { why } =
        crate::federation::migration::classify_shape(&normalized, normalized.asserted_at)
    {
        return Err(super::Error::InvalidArgument(format!(
            "replacement row {} is not v31-shaped: {why}",
            normalized.attestation_id
        )));
    }
    // THE WALL-CLOCK GATE, asked exactly as the write door asks it.
    super::admission::check_instant_binding(
        &normalized,
        crate::host::clock::now(),
        super::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    Ok(())
}

/// v31.1.0 (CIRISPersist#665 review) — is `row` v31-conformant **in the form it
/// would be stored**, i.e. with its envelope canonicalized as
/// `put_attestation` canonicalizes it (#647)?
///
/// Only ever asked of a CANDIDATE — a row from a bundle that has not been
/// through a write door. See [`candidate_is_strictly_newer`] for why a stored
/// row must never be normalized before being classified.
///
/// A row that cannot be canonicalized at all is not conformant.
fn candidate_is_v31_conformant_as_stored(row: &super::Attestation) -> bool {
    use crate::federation::migration::{classify_shape, RowShape};
    let Ok(normalized) = baked_row_as_stored(row) else {
        return false;
    };
    matches!(
        classify_shape(&normalized, normalized.asserted_at),
        RowShape::V31Conformant
    )
}

/// v31.1.0 (CIRISPersist#665) — **is this stored row a real statement by this
/// node's seated accord holders?**
///
/// The authenticity half of the replacement rule — *"is it REAL"*, asked before
/// *"are we NEWER"* ([`candidate_is_strictly_newer`]). Both must pass before any
/// row is deleted, and this one must pass before the plane is allowed to serve
/// on the row at all.
///
/// Three legs, and the third is the one that is easy to miss:
///
/// 1. [`check_genesis_attestation_reserved`] — federation-tier, and attested by
///    a seated accord holder on THIS node's effective roster (the #660
///    reservation, re-asked against a row already in the corpus rather than one
///    arriving at a door);
/// 2. the scrub signature verifies, under `Strict` hybrid policy, against that
///    attester's REGISTERED pubkeys, over the row's OWN envelope;
/// 3. the digest that verification RETURNS — `SHA-256` of the canonical
///    envelope — is exactly the row's stored `original_content_hash`.
///
/// Leg 3 is not redundant with leg 2. `original_content_hash` is a COLUMN and
/// the signature covers the ENVELOPE, so a row can carry a perfectly valid
/// holder signature beside a content hash that was rewritten afterwards. Taking
/// the return value rather than just the `Ok` binds the unsigned column back to
/// the signed bytes.
///
/// Renamed from `stored_row_is_prior_ceremony` in the #665 review: it never
/// established "prior", only "real", and reading it as the former is exactly
/// how a legitimate NEWER ceremony came to be treated as a supersedable
/// predecessor. Recency is now a separate question with its own name.
///
/// Returns `false` on ANY doubt, including a directory error while resolving
/// the attester: this gates a destructive write, so an unanswerable question
/// must not authorize one.
async fn stored_row_is_verifiable_holder_statement<D>(dir: &D, stored: &super::Attestation) -> bool
where
    D: super::FederationDirectory + ?Sized,
{
    // Leg 1 — federation-tier, authored by a seated accord holder. Pure, and
    // cheapest, so it leads: no signature work is spent on a row that could
    // never have been a ceremony row in the first place.
    if check_genesis_attestation_reserved(stored).is_err() {
        return false;
    }
    // Legs 2 and 3 — the signature verifies over this row's OWN envelope, AND
    // the digest it returns is the row's stored `original_content_hash`. The
    // return value is what binds the unsigned column to the signed bytes; see
    // `seed_delegation_plane` for why leg 3 is not redundant.
    let verified = crate::federation::tier_ingest::verify_envelope_hybrid_signature(
        dir,
        &stored.attesting_key_id,
        &stored.attestation_envelope,
        &stored.scrub_signature_classical,
        stored.scrub_signature_pqc.as_deref(),
    )
    .await;
    matches!(verified, Ok(digest) if digest == stored.original_content_hash)
}

#[cfg(test)]
mod tests {
    //! v62 (E3): every earlier witness here read the baked JSON genesis
    //! (`canonical_genesis_bundle()`, the accord-holder / family / canonical
    //! seeds, the delegation plane, the test-ceremony seam) and is deleted with
    //! it. A node now boots pre-genesis and roots from a `ceg-genesis-bundle/2`
    //! at the import door; these witnesses install the test ceremony through
    //! that door (`edition2::fixture_genesis`) and read the state back.

    use crate::federation::edition2::fixture_genesis as g;
    use crate::federation::edition2::genesis::genesis_in_force;
    use crate::federation::FederationDirectory;

    /// I2660 body: the standard test ceremony installs through the door, its
    /// holders and serve seats are the bundle's, the accord is named, each
    /// seat stands as canonical (ruling C), and a second install is a no-op.
    async fn i2660_the_test_ceremony_roots_through_the_door<D>(d: &D)
    where
        D: FederationDirectory + ?Sized,
    {
        let c = g::bundle_v2();
        let installed = g::install_v2(d).await.expect("I2660: install");
        assert_eq!(installed.object_id, c.object_id, "I2660: the bundle placed");
        assert_eq!(installed.version, c.version);

        let f = genesis_in_force(d).await.expect("I2660: read back");
        assert!(f.is_held(), "I2660: a Valid root is held");
        assert_eq!(f.family_key_id(), Some(g::FAMILY_KEY_ID));
        let holders: Vec<&str> = f
            .holders()
            .iter()
            .map(|h| h.identity_ref.as_str())
            .collect();
        for i in 0..c.holders.len() {
            assert!(
                holders.contains(&c.holder_identity_ref(i)),
                "I2660: holder {i} is seated"
            );
        }
        for i in 0..c.seats.len() {
            assert!(
                f.is_canonical(c.serve_node_identity_ref(i)),
                "I2660: serve seat {i} stands as canonical"
            );
        }
        assert!(
            !f.is_canonical(c.holder_identity_ref(0)),
            "I2660: a holder is not a serve seat"
        );

        let again = g::install_v2(d)
            .await
            .expect("I2660: a second install is Ok");
        assert_eq!(again.object_id, installed.object_id, "I2660: idempotent");
    }

    /// **I2660** (sqlite): the test ceremony roots through the bundle/2 door.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2660_the_test_ceremony_roots_through_the_door_sqlite() {
        let d = crate::store::test_backend::test_backend();
        i2660_the_test_ceremony_roots_through_the_door(&d).await;
    }

    /// **I2660** (postgres twin).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn i2660_the_test_ceremony_roots_through_the_door_postgres() {
        use crate::store::backend::Backend as _;
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .expect("connect");
        d.run_migrations().await.expect("migrate");
        i2660_the_test_ceremony_roots_through_the_door(&d).await;
        eprintln!("i2660_the_test_ceremony_roots_through_the_door_postgres: RAN");
    }

    /// **I2661**: a fresh node holds no genesis. Nothing is seeded at boot
    /// from a compiled-in artifact; nothing is rooted until a bundle arrives.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2661_a_fresh_node_holds_no_genesis() {
        let d = crate::store::test_backend::test_backend();
        let f = genesis_in_force(&d).await.expect("read");
        assert!(!f.is_held(), "I2661: nothing held before a bundle arrives");
        assert!(f.family_key_id().is_none());
        assert!(!f.is_canonical(g::bundle_v2().serve_node_identity_ref(0)));
    }
}

/// v38.0.0 (CIRISPersist#738) — **the process environment is not a fixture.**
///
/// The test-anchor tests used to live here as lib unit tests, arming the
/// override by mutating `CIRIS_TESTING_MODE` / `CIRIS_TEST_TRUST_ROOT*` /
/// `ENVIRONMENT` — process-globals every concurrently-scheduled test that
/// touches the roster reads through `effective_accord_holder_records()`.
/// Under `cargo test` (threads, one process) the arm window collapsed the
/// constitutional roster to one synthetic key for EVERY overlapping test:
/// 21 tests red in parallel, green serially, across genesis / trust_root /
/// register / accord_carriage — and a panic inside an armed test leaked the
/// arm for the remainder of the run, because disarm was a tail call, not a
/// guard. `#[serial_test::serial]` was never the remedy: it serialized the
/// six mutators against each other and against none of the ~50 readers, and
/// it is a documented no-op under nextest anyway (src/test_pg.rs).
///
/// The tests live in `tests/test_anchor_env.rs` now — an integration target
/// is its own PROCESS under both runners, so the mutation cannot reach the
/// lib's unit tests — with an RAII guard so a panicking test cannot leak
/// the arm even within its own process. This tripwire keeps the class out:
/// no code under src/ may mutate the anchor env vars again. (Needle split
/// so the scan cannot match itself.)
#[cfg(test)]
mod test_anchor_env_hygiene {
    #[test]
    fn no_src_code_mutates_the_anchor_environment_738() {
        let set = format!("set{}", "_var");
        let remove = format!("remove{}", "_var");
        let vars = [
            "CIRIS_TESTING_MODE",
            "CIRIS_TEST_TRUST_ROOT",
            "ENVIRONMENT",
            "CIRIS_ENV",
        ];
        let mut offenders = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    for (i, line) in text.lines().enumerate() {
                        let mutates = line.contains(&set) || line.contains(&remove);
                        if mutates && vars.iter().any(|v| line.contains(v)) {
                            offenders.push(format!("{}:{}", p.display(), i + 1));
                        }
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "src/ code mutates the anchor environment — that is the #738 class \
             (process-global state under concurrent tests). Env-mutating tests belong in \
             tests/test_anchor_env.rs, their own process:\n{offenders:#?}"
        );
    }
}
