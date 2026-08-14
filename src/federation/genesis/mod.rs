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
pub use bundle::{
    bake_assembled_genesis, parse_genesis_bundle, verify_bundle_quorum, BakeItemOutcome,
    GenesisAuthorization, GenesisBakeReport, GenesisBundle,
};

pub mod posture;
pub use posture::{
    constitutional_seat, genesis_posture, require_constitutional_root, GenesisFault, GenesisLeg,
    GenesisPosture, ROOT_REQUIRING_GATES,
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
    )
    .expect("the synthesized test-anchor envelope is a JSON object");
    envelope
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
///   `Ed25519Fallback` link policy verifies classical-only or full-hybrid).
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
    use sha2::{Digest, Sha256};

    /// The i-th comma-separated slot of `var`, trimmed; `None` when the var
    /// is unset or the slot is missing/empty.
    fn env_slot(var: &str, i: usize) -> Option<String> {
        let raw = std::env::var(var).ok()?;
        let slot = raw.split(',').nth(i)?.trim().to_owned();
        (!slot.is_empty()).then_some(slot)
    }

    let keys = ciris_verify_core::test_anchor::test_trust_root_override()?;
    let ts: chrono::DateTime<chrono::Utc> = ACCORD_FAMILY_FOUNDED_AT
        .parse()
        .expect("ACCORD_FAMILY_FOUNDED_AT is a valid RFC-3339 constant");
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
        out.push(SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: key_id.clone(),
                pubkey_ed25519_base64,
                pqc_completed_at: pqc_pubkey.as_ref().map(|_| ts),
                pubkey_ml_dsa_65_base64: pqc_pubkey,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::ACCORD_HOLDER.to_owned(),
                identity_ref: key_id.clone(),
                valid_from: ts,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: scrub_ed
                    .unwrap_or_else(|| B64.encode(b"test-anchor-placeholder")),
                scrub_signature_pqc: scrub_pqc,
                scrub_key_id: key_id.clone(),
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
        });
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
    use crate::federation::types::{Family, FamilyMember};
    let founded_at = ACCORD_FAMILY_FOUNDED_AT
        .parse()
        .expect("ACCORD_FAMILY_FOUNDED_AT is a valid RFC-3339 constant");
    // #449 — founder seats follow the EFFECTIVE roster so the family stays
    // coherent with the seeded holders (test or baked) by construction.
    let members = effective_accord_holder_records()
        .iter()
        .map(|sr| FamilyMember {
            key_id: sr.record.key_id.clone(),
            joined_at: founded_at,
            role: Some("founder".to_owned()),
        })
        .collect();
    Family {
        family_key_id: ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID.to_owned(),
        family_name: "HUMANITY_ACCORD".to_owned(),
        members,
        founded_at,
        consensus_protocol: ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL.to_owned(),
        consensus_protocol_entrenched: true,
        persist_row_hash: String::new(),
    }
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
    let family = accord_family_genesis_record();
    // v31.0.0 (CIRISPersist#648) — THE property that keeps a second assemble
    // from becoming a replacement. An already-entrenched family is a no-op and
    // has been since #386; making the pre-genesis state reachable must not make
    // OVERWRITING an established root reachable, so this early return is
    // load-bearing rather than an optimisation. A new ceremony ADDS a root
    // (roots co-exist and are addressed per-`root_ref`); nothing here mutates
    // one that already stands.
    if dir
        .lookup_family(&family.family_key_id)
        .await
        .map_err(|e| GenesisFault::unreadable(LEG, format!("lookup_family: {e}")))?
        .is_some()
    {
        return Ok(()); // already entrenched (reboot) — idempotent no-op.
    }
    // v21.0.0 (CIRISPersist#502 E4) — `put_family` now hybrid-Strict-verifies
    // an authority signature; the baked HUMANITY_ACCORD family is a
    // bake-what-exists declaration with no private key to sign with
    // (`family_key_id` is keyless by design, see `put_family_local`'s doc).
    // Use the trusted-local bypass, exactly as this boot path always has.
    dir.put_family_local(family).await.map_err(|e| {
        GenesisFault::absent(
            LEG,
            format!("seed accord family: {e} (are A1/B1/C1 seeded first?)"),
        )
    })
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
/// Unlike the placeholder, this artifact IS bakeable via
/// [`bake_assembled_genesis`]: it carries the authorizations the quorum gate
/// requires.
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
pub fn canonical_genesis_bundle() -> &'static GenesisBundle {
    use std::sync::OnceLock;
    static PARSED: OnceLock<GenesisBundle> = OnceLock::new();
    PARSED.get_or_init(|| {
        parse_genesis_bundle(CANONICAL_SEED_JSON)
            .expect("embedded canonical_seed.json must be a valid GenesisBundle")
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
    if baked_delegation_row(attestation_id).is_some() {
        return Ok(());
    }
    Err(super::Error::InvalidArgument(format!(
        "refusing to purge attestation {attestation_id} through the genesis re-bake door \
         (CIRISPersist#665): it is not one of the baked genesis delegation ids {:?}. This door \
         exists only to let the compiled-in bundle replace its OWN previous ceremony's rows — \
         the general purge path is `purge_attestation_v31`, and it refuses exclusion-bearing \
         rows on purpose",
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
/// delegation plane has no second door: [`bake_assembled_genesis`], the host's
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
        //    `node` row, #394) → `adopt_scrub_upgrade`: upgrade it to the baked
        //    scrubbed canonical. NO `owner_of` gate (a fresh canonical has no
        //    owner graph), which the replicated-apply Upgrade path would impose.
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
            Some(row) if row.scrub_key_id == row.key_id => {
                dir.adopt_scrub_upgrade(sr.clone()).await.map(|_| ())
            }
            Some(_) => {
                use crate::federation::register::ReplicatedKeyOutcome as O;
                match dir.apply_replicated_key_record(sr.clone()).await {
                    Ok(O::Superseded | O::Unchanged | O::Upgraded | O::Inserted) => Ok(()),
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
    use crate::federation::types::identity_type;
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
        if !identity_type::set_contains(&row.identity_type, identity_type::CANONICAL) {
            return Err(GenesisFault::divergent(
                LEG,
                format!(
                    "seeded canonical server {} lost its `canonical` role (identity_type={:?})",
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
/// A row present whose `original_content_hash` is not the baked one is
/// [`GenesisFault::divergent`] — not a stale artifact but a SUBSTITUTED
/// conferral row, and the one case here that must not serve. Same split, and
/// the same reasoning, as the canonical leg's squatting check.
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
        // holder's `key_id`, a corrupted signature — and now ROLLBACK, a
        // holder-signed row OLDER than the compiled-in one, which the old
        // equality check accepted or rejected purely by accident of hashing.
        // The single thing that stops being called tampering is a newer,
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
            let rolled_back = candidate_is_strictly_newer(want, &row);
            if !real || rolled_back {
                return Err(GenesisFault::divergent(
                    LEG,
                    format!(
                        "delegation row {id} is present with a content hash that is not the baked \
                         one (stored {}, baked {}) and is {} — a substituted conferral row",
                        row.original_content_hash,
                        want.original_content_hash,
                        if real {
                            "OLDER than the compiled-in artifact (a rollback)"
                        } else {
                            "not a verifiable statement by a seated accord holder"
                        },
                    ),
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
    }
    Ok(())
}

/// v31.0.0 — the refusal a PRE-v31 delegation row must produce: one of the two
/// envelope-binding gates, named in the message.
///
/// Asserted as a SET rather than as `#643` alone. Both gates refuse the stale
/// bundle, the tier order decides which speaks first, and pinning one issue
/// number made a witness that broke when the other gate widened — while the
/// property it exists to prove never changed.
#[cfg(test)]
pub(crate) fn is_v31_binding_refusal(msg: &str) -> bool {
    msg.contains("CIRISPersist#643") || msg.contains("CIRISPersist#598")
}

/// v30.6.0 (CIRISPersist#622) — the THREE-BACKEND genesis witness.
///
/// # Why this exists
///
/// `federation_attestations.attestation_id` was `UUID PRIMARY KEY` on Postgres
/// while the baked ceremony bundle carries SYMBOLIC ids — `genesis-charter`,
/// `genesis-grant:…`, `genesis-lifecycle`. The driver refused the write before
/// any persist logic ran, so **every Postgres node failed genesis and every
/// SQLite node was immune**: same binary, same constant, same value. Two
/// production agents crash-looped 151 and 223 times (CIRISServer#381 /
/// CIRISAgent#1020).
///
/// persist had already NAMED this trap — *"memory tolerates what postgres
/// rejects"* — and built a three-backend witness for it. That witness works.
/// **The genesis path simply was not under it**, so the trap reached production
/// instead of a fixture. This closes that gap: the bundle every node actually
/// bakes is installed and verified through the REAL directory on all three
/// backends.
///
/// Run against the pre-V121 Postgres schema this fails with
/// `attestation_id is not a valid UUID`, which is the dye test.
///
/// # v31.0.0 (CIRISPersist#648) — the delegation-plane half is regime-branched
///
/// The KEY plane assertions below are unchanged and still run on every backend:
/// they are the #622 witness and nothing about #648 touches them.
///
/// The ATTESTATION half cannot pass while the baked bundle predates #643 — its
/// rows carry no signed `row` mirror, so `put_attestation` refuses them at
/// every backend, deliberately and correctly. This witness is therefore
/// branched on [`bundle_delegation_plane_v31_shaped`] rather than skipped:
///
/// - **pre-v31 bundle** — assert the rows are REFUSED, with the #643 reason,
///   and that NOTHING was written. That is a real property of a real build and
///   it is the state 31.0.0 ships in; asserting it is not a carve-out, it is
///   the honest form of the same test.
/// - **re-signed bundle (31.1.0)** — assert the original: installs on every
///   backend, byte-exact id round-trip.
///
/// The branch is taken from the ARTIFACT, so 31.1.0's re-bake flips this back
/// to the install assertions without anyone editing the test.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn exercise_genesis_seed_installs(dir: &dyn super::FederationDirectory) {
    // NOTE: each leg seeds the accord holders BEFORE calling this, via the
    // concrete `seed_genesis_accord_holders` (it is a backend method, not a
    // `FederationDirectory` one). Holders must exist first because
    // `verify_bundle_quorum` and the m-of-n put gate re-derive the roster from
    // THIS node's directory — the #377 rule, never the roster the bundle
    // carries — so the seats have to be there before anything is tallied
    // against them.

    seed_family_and_canonical(dir)
        .await
        .expect("the baked genesis bundle must install on EVERY backend");
    verify_family_seeded(dir)
        .await
        .expect("accord family must verify after seeding");
    verify_canonical_seeded(dir)
        .await
        .expect("canonical servers must verify after seeding");

    // **THE PART THAT WAS BREAKING.** `seed_family_and_canonical` installs KEYS;
    // the bundle's ATTESTATIONS — the rows carrying the symbolic ids
    // `genesis-charter`, `genesis-grant:…`, `genesis-lifecycle` — are written by
    // the host as stage 1 of boot. That write is what Postgres refused while
    // `attestation_id` was `UUID`, and it is why a witness that only seeds keys
    // passes on the broken schema and proves nothing. (It did: the first version
    // of this body was green on unfixed Postgres.)
    let bundle = canonical_genesis_bundle();
    let row_bound = bundle_delegation_plane_v31_shaped(bundle);
    for att in &bundle.attestations {
        let id = &att.attestation.attestation_id;
        match &row_bound {
            // ── 31.1.0 and after: the re-signed bundle installs, as it always
            //    should have. This arm is the original #622 assertion verbatim.
            Ok(()) => {
                // v31.1.0 — ALREADY-PRESENT is success, not failure. Boot now
                // seeds the delegation plane (`seed_delegation_plane`), so on a
                // directory that has booted, these rows are already in. The
                // property #622 holds is "this bundle is installable on every
                // backend", and a primary-key conflict is that property having
                // already been satisfied — not a backend that refused it.
                //
                // v31.1.0 (CIRISPersist#665) — through the SHARED predicate. The
                // three-backend duplicate-key test was first written HERE, as an
                // inline `Conflict || "UNIQUE constraint" || "duplicate key"`
                // chain, and was not carried to `seed_delegation_plane` — which
                // matched `Conflict` alone and therefore treated a lost seed race
                // as "still absent". One transcription of a predicate is a
                // predicate; two are a disagreement waiting to happen.
                match dir.put_attestation(att.clone()).await {
                    Ok(()) => {}
                    Err(e) if e.is_duplicate_key() => {}
                    Err(e) => {
                        panic!("genesis attestation {id:?} must install on EVERY backend: {e}")
                    }
                }
                let back = dir
                    .get_attestation(id)
                    .await
                    .expect("read back")
                    .unwrap_or_else(|| panic!("genesis attestation {id:?} vanished after write"));
                // Byte-exact: a backend that rewrote the id (to a UUID, say)
                // would break every signature over the envelope that names it.
                assert_eq!(
                    back.attestation_id, *id,
                    "the id the ceremony SIGNED must round-trip unchanged"
                );
            }
            // ── 31.0.0: the baked bundle predates #643. The rows are refused,
            //    on EVERY backend, for the SAME reason — which is itself the
            //    three-backend property #622 exists to hold, just with the
            //    outcome the current artifact actually earns. A backend that
            //    ADMITTED one of these would be a backend with a hole in the
            //    binding gate, and this reds on it.
            Err(_) => {
                let err = dir.put_attestation(att.clone()).await.expect_err(
                    "a pre-v31 genesis attestation must be REFUSED by an envelope-binding \
                     gate on EVERY backend",
                );
                assert_eq!(
                    err.kind(),
                    "federation_invalid_argument",
                    "the refusal is an envelope-binding gate, not a backend accident"
                );
                assert!(
                    is_v31_binding_refusal(&err.to_string()),
                    "the refusal names an envelope-binding gate (#643 mirror or #598 \
                     instants): {err}"
                );
                assert!(
                    dir.get_attestation(id).await.expect("read back").is_none(),
                    "a refused genesis row writes NOTHING — verify-before-mutation"
                );
            }
        }
    }
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

/// v31.0.0 (CIRISPersist#660) — write a decoy row under an ORDINARY id, and
/// return that id, so a SQL leg can then rename it onto a genesis id beneath
/// persist (the "however it got there" case: a direct `UPDATE`, a restored
/// backup, a pre-#660 corpus). The write goes through the real door, so what
/// gets renamed is a genuinely well-formed row and not a fixture artefact.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn seed_decoy_attestation(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) -> String {
    use crate::federation::tier_ingest::test_support as ts;
    // Distinguishing part FIRST — `seed_for` truncates key_ids at 32 bytes.
    let attester = format!("{tag}-660-decoy-signer");
    ts::register_identity_key(
        dir,
        &attester,
        crate::federation::types::identity_type::AGENT,
    )
    .await;
    let id = format!("{tag}-660-decoy");
    dir.put_attestation(super::SignedAttestation {
        attestation: ts::seal_row(&attester, ordinary_scores_row(&id, &attester)),
    })
    .await
    .expect("the decoy row is ordinary and must be admitted");
    id
}

/// v31.0.0 (CIRISPersist#660) — **the squat witness, on every backend.**
///
/// A peer could deny a node its boot with ONE ordinary attestation. The baked
/// genesis ids were reserved nowhere, so a `scores` row written under
/// `genesis-charter` made [`verify_delegation_plane_seeded`] report `Divergent`,
/// which [`GenesisFault::refuses_boot`] — and took the primary key the real
/// ceremony needs, making the denial permanent.
///
/// Three properties, and the third is the one that keeps the fix honest:
///
/// 1. **BOTH doors refuse.** `put_attestation` AND the local door
///    (`attestation_insert_local`, whose `attestation_id` is caller-supplied).
///    The local one is not a formality — it is the cheaper attack, because
///    `get_attestation` does not filter by tier, so a local-tier row is already
///    enough to take the key and flip the posture.
/// 2. **Nothing is written, and the posture does NOT become divergent.** This
///    is the "verify that, do not assume it" half: reservation is only a fix if
///    `Divergent` actually stops being reachable by this route.
/// 3. **The ceremony's own rows still pass the reservation.** A gate that
///    reserved the ids by refusing everything would also refuse genesis, and the
///    node would simply fail differently. Asserted against the baked artifact,
///    so a re-bake that changes the ids re-checks itself.
///
/// The rogue row is FULLY SEALED before it is offered — mirror stamped, instants
/// stamped, hybrid-signed — so it is a row every other gate would admit. A
/// witness built from a malformed row would pass against a deleted reservation,
/// which is the failure mode this file has already paid for once.
///
/// The refusal is asserted on the TYPED `kind()`, never on an issue number in a
/// message.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn exercise_genesis_id_squat_refused(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, identity_type,
    };

    const RESERVED: &str = "federation_genesis_attestation_reserved";

    // Trap paid for today: `test_support::seed_for` truncates key_ids at 32
    // bytes, so two ids sharing a 32-byte prefix ARE one identity. The
    // distinguishing part goes FIRST.
    let rogue = format!("{tag}-660-squatter");
    ts::register_identity_key(dir, &rogue, identity_type::AGENT).await;

    // (3) The reservation must not refuse the ceremony it exists to protect.
    for sa in &canonical_genesis_bundle().attestations {
        check_genesis_attestation_reserved(&sa.attestation).unwrap_or_else(|e| {
            panic!(
                "[{tag}] the BAKED row {:?} must pass its own reservation — a gate that \
                 refuses genesis has not reserved the id, it has deleted it: {e}",
                sa.attestation.attestation_id
            )
        });
    }

    let posture_before = posture::genesis_posture(dir).await;

    for id in genesis_delegation_ids() {
        // ── door 1: the federation door. A fully sealed, otherwise-admissible
        //    row — the strongest form of the claim.
        let err = dir
            .put_attestation(super::SignedAttestation {
                attestation: ts::seal_row(&rogue, ordinary_scores_row(id, &rogue)),
            })
            .await
            .expect_err("a squat on a baked genesis id must be REFUSED at the federation door");
        assert_eq!(
            err.kind(),
            RESERVED,
            "[{tag}] {id}: the refusal must be the RESERVATION, not a neighbouring gate \
             that happened to fire first: {err}"
        );
        assert!(
            dir.get_attestation(id).await.expect("read back").is_none(),
            "[{tag}] {id}: a refused squat writes NOTHING — and the primary key stays free \
             for the ceremony"
        );

        // ── door 2: the LOCAL door, where `attestation_id` is caller-supplied
        //    and `check_reserved_prefix_admission` is deliberately deferred to
        //    promotion. Deferring THIS one the same way would leave the whole
        //    attack open, because taking the key is the attack.
        let err = dir
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: Some(id.to_owned()),
                attesting_key_id: rogue.clone(),
                attested_key_id: None,
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: Some(1.0),
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({
                        "id": id, "dimension": "trust:demo:v1", "score": 1.0, "confidence": 0.9,
                    }),
                )
                .expect("envelope"),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect_err("a squat on a baked genesis id must be REFUSED at the LOCAL door too");
        assert_eq!(
            err.kind(),
            RESERVED,
            "[{tag}] {id}: the local door must refuse with the same typed reservation: {err}"
        );
        assert!(
            dir.get_attestation(id).await.expect("read back").is_none(),
            "[{tag}] {id}: a refused local squat writes NOTHING — note `get_attestation` does \
             NOT filter by tier, which is exactly why this door had to be gated"
        );

        // ── the TIER half, on its own. The two rows above are BOTH refused by
        //    the accord-holder half, so neither of them can tell whether the
        //    federation-tier half runs at all — a mutation deleting it survived
        //    this witness until this leg existed.
        //
        //    `put_attestation` accepts `tier = "local"` (see
        //    `check_capacity_never_local` for why that door is tier-blind), so a
        //    LOCAL-tier row offered at the FEDERATION door isolates the tier
        //    arm: it must be refused naming `tier`, not `attesting_key_id`.
        //    That distinction is what a seated accord holder writing a
        //    local-tier row would otherwise exploit to take the primary key
        //    without ever touching the federation plane.
        let mut local_tier = ordinary_scores_row(id, &rogue);
        local_tier.tier = attestation_tier::LOCAL.to_owned();
        local_tier.cohort_scope = cohort_scope::SELF.to_owned();
        let err = dir
            .put_attestation(super::SignedAttestation {
                attestation: ts::seal_row(&rogue, local_tier),
            })
            .await
            .expect_err("a local-tier row under a genesis id must be REFUSED");
        assert_eq!(
            err.kind(),
            RESERVED,
            "[{tag}] {id}: local-tier squat must hit the reservation: {err}"
        );
        match &err {
            super::Error::GenesisAttestationReserved { field, .. } => assert_eq!(
                field, "tier",
                "[{tag}] {id}: the TIER half must be the one that refuses a local-tier row — \
                 if `attesting_key_id` answers here, the tier arm is dead code and a seated \
                 holder could stage a local-tier row under this id"
            ),
            other => panic!("[{tag}] {id}: {other:?}"),
        }
        assert!(
            dir.get_attestation(id).await.expect("read back").is_none(),
            "[{tag}] {id}: a refused local-tier squat writes NOTHING"
        );
    }

    // (2) `Divergent` is not reachable by this route. Stated as an equality
    // against the posture BEFORE the attempts rather than as `!= divergent`: a
    // squat must not move the posture at all.
    let posture_after = posture::genesis_posture(dir).await;
    assert_ne!(
        posture_after.as_str(),
        "divergent",
        "[{tag}] a refused squat must never produce CONSTITUTIONAL DIVERGENCE — that arm \
         refuses boot, which is the remote denial #660 closes"
    );
    assert_eq!(
        posture_before.as_str(),
        posture_after.as_str(),
        "[{tag}] a refused squat must not move the posture at all"
    );
}

/// v31.0.0 (CIRISPersist#660) — **the other half: a corpus that contains one
/// anyway.**
///
/// Reservation closes the write doors. It cannot close a restored backup, a
/// direct `UPDATE`, or a corpus written by a pre-#660 binary — so the classifier
/// still has to answer for that row, and the answer still has to be defensible.
///
/// It is: `Divergent` on the delegation leg, which
/// [`GenesisFault::refuses_boot`], with a banner naming what happened. That is
/// the CORRECT verdict once squatting is unreachable remotely — a divergent
/// delegation row now necessarily means an established root was altered beneath
/// persist, which is precisely the case #648 built the arm for. Before #660 the
/// same verdict was wrong, because a peer chose it for you.
///
/// The caller injects the row (each backend's own bypass — a raw INSERT, a state
/// push); the assertion is shared so the three legs cannot disagree about what
/// "defensible" means.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn assert_injected_squat_is_divergent(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    let fault = verify_delegation_plane_seeded(dir)
        .await
        .expect_err("an injected squat must be classified, never passed");
    assert_eq!(
        fault.as_str(),
        "divergent",
        "[{tag}] a substituted conferral row is DIVERGENT, not absent: {fault}"
    );
    assert_eq!(
        fault.leg(),
        GenesisLeg::Delegation,
        "[{tag}] and it is the delegation leg that diverged: {fault}"
    );
    assert!(
        fault.refuses_boot(),
        "[{tag}] a root altered beneath persist must not serve: {fault}"
    );
    let posture: GenesisPosture = fault.into();
    assert_eq!(
        posture.as_str(),
        "divergent",
        "[{tag}] and the posture says so"
    );
    let banner = posture
        .banner()
        .unwrap_or_else(|| panic!("[{tag}] a divergent posture MUST carry an operator banner"));
    assert!(
        banner.contains("CONSTITUTIONAL DIVERGENCE") && banner.contains("Do not serve"),
        "[{tag}] the banner must tell the operator not to serve: {banner}"
    );
}

/// v31.1.0 (CIRISPersist#665) — **the PREVIOUS ceremony's delegation rows, as
/// the ceremony actually produced them.**
///
/// Not synthesized. This is the verbatim `attestations` array of the bundle
/// baked at CIRISPersist#557 (`git show a718fb5 -- canonical_seed.json`) — the
/// artifact every v30 node in the fleet is holding right now: same three ids,
/// A1-attested with B1 co-scrubbing, and a different envelope and
/// `original_content_hash` from the 31.1.0 re-bake.
///
/// Vendoring the real predecessor rather than hand-rolling a "looks previous"
/// row is the point. The upgrade this fix has to survive is a fact about two
/// specific artifacts, and a fabricated stand-in would prove a property of the
/// fabrication: it would be trivial to build one that happens to satisfy the
/// three legs of [`stored_row_is_verifiable_holder_statement`] while the real v30 rows do
/// not. These verify against the seeded A1 anchor because A1 signed them.
///
/// # Panics
///
/// If the vendored JSON stops parsing as `[Attestation]`.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) fn prior_ceremony_delegation_rows() -> Vec<super::Attestation> {
    let rows: Vec<super::Attestation> =
        serde_json::from_str(include_str!("prior_ceremony_delegation_rows.json"))
            .expect("the vendored v30 ceremony rows must parse as [Attestation]");
    assert_eq!(
        rows.len(),
        canonical_genesis_bundle().attestations.len(),
        "the vendored predecessor must cover the same plane the baked bundle does"
    );
    rows
}

/// v31.1.0 (CIRISPersist#665) — the vendored PREVIOUS ceremony's row for `id`.
///
/// # Panics
///
/// If `id` is not one of the ids the predecessor bundle carried.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) fn prior_ceremony_row(id: &str) -> super::Attestation {
    prior_ceremony_delegation_rows()
        .into_iter()
        .find(|r| r.attestation_id == id)
        .unwrap_or_else(|| panic!("the v30 ceremony carried no row {id}"))
}

/// v31.1.0 (CIRISPersist#665) — seed the KEY plane and stop: holders, the
/// accord family, the canonical serve nodes — everything
/// [`seed_family_and_canonical`] does EXCEPT the delegation plane.
///
/// The race witness needs a directory where `put_attestation` of a genesis row
/// will be admitted (so the attester, the family and the canonical subject all
/// have to be live) but where the plane itself is still empty, because
/// "half-seeded" is only observable against rows that have not been installed
/// yet.
///
/// The caller seeds the accord holders first — that is a backend method, not a
/// [`FederationDirectory`](super::FederationDirectory) one, so it cannot be
/// reached from here.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn seed_key_plane_only(dir: &dyn super::FederationDirectory, tag: &str) {
    verify_anchor_seeded(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] anchors: {e}"));
    seed_accord_family(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] accord family: {e}"));
    verify_family_seeded(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] family verify: {e}"));
    seed_canonical_servers(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] canonical servers: {e}"));
    verify_canonical_seeded(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] canonical verify: {e}"));
    for sa in &canonical_genesis_bundle().attestations {
        assert!(
            dir.get_attestation(&sa.attestation.attestation_id)
                .await
                .expect("read back")
                .is_none(),
            "[{tag}] the KEY plane seed must not have installed the delegation plane"
        );
    }
}

/// v31.1.0 (CIRISPersist#665) — **THE UPGRADE WITNESS: a node holding the
/// PREVIOUS ceremony's delegation rows must boot, and must end up entrenched on
/// the NEW root.**
///
/// This is the P1 finding stated as an assertion. Before the fix,
/// [`seed_delegation_plane`] skipped any id it found present, so an upgraded
/// node kept its v30 rows, [`verify_delegation_plane_seeded`] saw content
/// hashes that are not the baked ones, and returned `Divergent` — the one
/// posture arm that REFUSES TO BOOT. A re-bake would have bricked the entire
/// upgrading fleet, on precisely the path v31.0.0 built the `Absent`-boots
/// discipline to keep alive.
///
/// The caller installs the predecessor beneath the write doors (each backend's
/// own bypass — the v30 rows carry no #643 `row` mirror, so `put_attestation`
/// refuses them, exactly as it would refuse them today on a fresh node). The
/// assertions are shared so the three legs cannot disagree about what surviving
/// an upgrade means.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn assert_rebake_supersedes_prior_ceremony(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    // Precondition — the injection really did leave this node on the old root.
    // Without this the witness could pass on a node that was never upgraded.
    for baked in canonical_genesis_bundle().attestations.iter() {
        let id = &baked.attestation.attestation_id;
        let row = dir
            .get_attestation(id)
            .await
            .expect("read back")
            .unwrap_or_else(|| panic!("[{tag}] the predecessor row {id} must be installed"));
        assert_ne!(
            row.original_content_hash, baked.attestation.original_content_hash,
            "[{tag}] the fixture must start on the PREVIOUS ceremony's content for {id}, \
             otherwise this witness proves nothing"
        );
    }

    // (1) BOOT. This is the assertion that was false: the seed must not fail,
    // and — the part that matters — must not leave the old rows in place.
    seed_delegation_plane(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] an upgrading node must seed, not fault: {e}"));

    // (2) ENTRENCHED ON THE NEW ROOT. `verify_delegation_plane_seeded` is
    // deliberately unchanged by this fix — it still calls a stored hash that is
    // not the baked one `Divergent`. It passing here is the whole proof that
    // the rows were REPLACED rather than tolerated.
    verify_delegation_plane_seeded(dir)
        .await
        .unwrap_or_else(|e| {
            panic!("[{tag}] after the re-bake the plane must verify against the NEW root: {e}")
        });
    for baked in canonical_genesis_bundle().attestations.iter() {
        let id = &baked.attestation.attestation_id;
        let row = dir
            .get_attestation(id)
            .await
            .expect("read back")
            .unwrap_or_else(|| panic!("[{tag}] {id} vanished across the replacement"));
        assert_eq!(
            row.original_content_hash, baked.attestation.original_content_hash,
            "[{tag}] {id} must now carry the BAKED content hash"
        );
        assert_eq!(
            row.attestation_id, *id,
            "[{tag}] the id the ceremony SIGNED must round-trip unchanged"
        );
    }
    let posture = posture::genesis_posture(dir).await;
    assert_eq!(
        posture.as_str(),
        "entrenched",
        "[{tag}] an upgraded node ends entrenched, not divergent and not pre-genesis"
    );

    // (3) IDEMPOTENT. Boot runs every start; the second pass must find the
    // plane current and touch nothing. A replacement arm that re-fired every
    // boot would be deleting and re-inserting the constitutional root forever.
    for sa in &canonical_genesis_bundle().attestations {
        let stored = dir
            .get_attestation(&sa.attestation.attestation_id)
            .await
            .expect("read back");
        assert_eq!(
            install_or_supersede_delegation_row(dir, sa, stored)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] the second boot must be a no-op: {e}")),
            DelegationRowOutcome::AlreadyCurrent,
            "[{tag}] a settled plane is AlreadyCurrent on every later boot"
        );
    }
    verify_delegation_plane_seeded(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] and it still verifies after a second pass: {e}"));
}

/// v31.1.0 (CIRISPersist#665 review) — **THE REFUSED CLASSES, as one table.**
///
/// The replacement rule is only as good as what it still says no to, so every
/// class that must NOT be able to replace a delegation row is asserted here
/// rather than argued in prose. The caller has a plane seeded with the baked
/// artifact; each case is evaluated through the real
/// [`install_or_supersede_delegation_row`] and the real
/// [`verify_delegation_plane_seeded`].
///
/// The classes, and why each is here:
///
/// - **rollback by an older holder statement** — the v30 artifact offered as
///   the candidate against the installed v31 row. Real signatures, real
///   holders, genuinely older; the case a bare "is it holder-signed" test would
///   wave through, and the reason recency is a separate question.
/// - **a legacy row with a stamped `asserted_at`** — the subtle one. On a
///   pre-v31 row `asserted_at` is NOT in the signed envelope, so raw corpus
///   access can set it to 2030; if recency read that column the row would pin
///   the node to the old root forever. Shape decides instead, so the stamp is
///   ignored. This must not rest on reasoning alone.
/// - **a fabricated row claiming a seated holder** — `A1` in
///   `attesting_key_id`, federation tier, plausible envelope, signature that
///   verifies against nothing.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn assert_refused_replacement_classes(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    let baked = &canonical_genesis_bundle().attestations[0];
    let id = &baked.attestation.attestation_id;
    let installed = dir
        .get_attestation(id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] the baked plane must be seeded first"));

    // ── ROLLBACK: the v30 artifact offered against the installed v31 row ──
    // Real ceremony, real holders, real signatures — and older. Offered the way
    // an older binary would offer it: as the thing to install.
    let older = super::SignedAttestation {
        attestation: prior_ceremony_row(id),
    };
    assert!(
        !candidate_is_strictly_newer(&older.attestation, &installed),
        "[{tag}] the v30 artifact must not read as newer than the installed v31 row"
    );
    let outcome = install_or_supersede_delegation_row(dir, &older, Some(installed.clone()))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a rollback attempt must not fault the boot: {e}"));
    assert_eq!(
        outcome,
        DelegationRowOutcome::LeftAsNewerCeremony,
        "[{tag}] an OLDER holder statement must never replace a newer one — that is the \
         downgrade an old binary would otherwise force on an upgraded node"
    );
    let after = dir
        .get_attestation(id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] {id} vanished"));
    assert_eq!(
        after.original_content_hash, baked.attestation.original_content_hash,
        "[{tag}] and the installed row is untouched"
    );

    // ── LEGACY ROW WITH A STAMPED `asserted_at` ──
    // The pre-v31 envelope carries no signed instant, so this column is
    // unsigned material. Stamped far into the future it must STILL lose to a
    // v31-shaped candidate: shape decides, not the stamp.
    let mut stamped = prior_ceremony_row(id);
    stamped.asserted_at = "2030-01-01T00:00:00Z".parse().expect("fixed instant");
    assert!(
        stamped.asserted_at > baked.attestation.asserted_at,
        "[{tag}] the fixture must actually claim to be newer, or it proves nothing"
    );
    assert!(
        candidate_is_strictly_newer(&baked.attestation, &stamped),
        "[{tag}] a LEGACY row must not be able to pin the node with an unsigned `asserted_at`: \
         it predates the signed-instant envelope by construction, so shape decides and the \
         baked v31 artifact still supersedes it"
    );

    // ── FABRICATED ROW CLAIMING A SEATED HOLDER ──
    // `A1`, federation tier, everything a pure gate can check — and a signature
    // over nothing. Reservation cannot stop this (it is written beneath the
    // doors); authenticity must.
    let mut forged = baked.attestation.clone();
    // A DIFFERENT STATEMENT, not the baked one with broken signatures — that
    // would be the damage case, which is repaired rather than refused. What an
    // attacker actually wants is to change what the root CONFERS, so the
    // envelope is what moves.
    forged.attestation_envelope["scope"] = serde_json::json!(["infra:attest", "infra:everything"]);
    forged.original_content_hash = "11".repeat(32);
    forged.scrub_signature_classical = "AA".repeat(32);
    forged.scrub_signature_pqc = None;
    forged.additional_scrubs = Vec::new();
    assert!(
        envelope_matches_baked(&forged, &baked.attestation)
            .map(|m| !m)
            .unwrap_or(true),
        "[{tag}] the forgery must be a DIFFERENT statement, or it is the damage case"
    );
    assert!(
        check_genesis_attestation_reserved(&forged).is_ok(),
        "[{tag}] the forgery must pass every PURE gate — otherwise this witnesses the pure gate, \
         not the signature check"
    );
    assert!(
        !stored_row_is_verifiable_holder_statement(dir, &forged).await,
        "[{tag}] a row claiming a seated holder without that holder's signature is NOT a \
         verifiable statement, whatever its columns say"
    );
    let outcome = install_or_supersede_delegation_row(dir, baked, Some(forged))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a forgery must be classified, not faulted: {e}"));
    assert_eq!(
        outcome,
        DelegationRowOutcome::LeftAsSubstituted,
        "[{tag}] a forged row is left in place for the posture leg to refuse, never silently \
         overwritten — overwriting it would repair the damage and report nothing"
    );
}

/// v31.1.0 (CIRISPersist#665 review) — **THE BELOW-QUORUM WITNESS: a row with no
/// baked comparand must still prove it can confer.**
///
/// The case that forced the invariant to be stated directly rather than
/// inferred. A row that is legitimately NOT the compiled-in artifact — the floor
/// rule accepts those on purpose — has nothing to be byte-compared against, so
/// every wholeness proxy silently stops applying to it. Drop its
/// `additional_scrubs` beneath persist and: its base holder signature still
/// verifies, its content still differs from the baked row exactly as a newer
/// ceremony's would, and its recency still passes. Three green proxies over a
/// trust root that `family_quorum_over` cannot bring to threshold.
///
/// The fixture uses the vendored v30 row as the stand-in for "a real
/// holder-signed row that is not the baked one", damaged the same way. It is the
/// shape of the hole that matters — no comparand, base signature intact, quorum
/// gone — not which side of the baked artifact it sits on.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn assert_below_quorum_row_cannot_confer(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    let id = &canonical_genesis_bundle().attestations[0]
        .attestation
        .attestation_id;
    let stored = dir
        .get_attestation(id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] the damaged row {id} must be installed"));

    // The proxies the old code trusted all still say "sound".
    assert!(
        stored.additional_scrubs.is_empty(),
        "[{tag}] the fixture must have dropped the co-signatures"
    );
    assert!(
        stored_row_is_verifiable_holder_statement(dir, &stored).await,
        "[{tag}] and the BASE holder signature must still verify — that is precisely why the \
         authenticity legs were not enough on their own"
    );

    // The property does not.
    let quorum = delegation_row_accord_quorum(dir, &stored)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the quorum must be countable: {e}"))
        .unwrap_or_else(|| panic!("[{tag}] the accord family must be seeded for this witness"));
    assert!(
        !quorum.met(),
        "[{tag}] the fixture must actually be below threshold, or this proves nothing: {}",
        quorum.describe()
    );

    let fault = verify_delegation_plane_seeded(dir).await.expect_err(
        "a delegation plane that cannot reach its accord quorum must NOT read as sound — the \
         agent-mode gate is open over whatever this reports",
    );
    assert_eq!(
        fault.as_str(),
        "divergent",
        "[{tag}] a root below quorum is divergence: {fault}"
    );
    assert!(
        fault.to_string().contains("CANNOT CONFER"),
        "[{tag}] and the refusal names the property that failed, not a proxy: {fault}"
    );
    assert_eq!(
        posture::genesis_posture(dir).await.as_str(),
        "divergent",
        "[{tag}] and a live query agrees"
    );
}

/// v31.1.0 (CIRISPersist#665) — **THE NODE'S OWN SEED IS NOT A PEER.**
///
/// After a full genesis seed on a fresh directory, the peer-write quota must
/// have observed NOTHING: no tracked peers, no denials.
///
/// # Why this is a real property and not test bookkeeping
///
/// `tracked_peers` is the token that separates *"nobody has talked to us"* from
/// *"peers have, and none were denied"* — and
/// [`node_state`](crate::federation::node_state) reads `tracked_peers > 0` as
/// the condition that lifts the peer-quota band out of `unknown` into `green`.
/// So a single spurious peer does not merely look untidy: every fresh node
/// reports a TESTED quota, and an operator loses exactly the distinction the
/// typed standings exist to preserve — `slot_denials == 0` becomes
/// indistinguishable between "clean" and "never exercised".
///
/// 31.1.0 introduced that regression by making boot install the delegation
/// plane through `put_attestation`, which charges the quota: a fresh engine came
/// up having "observed" `A1`, a peer no peer had ever spoken as. The compiled-in
/// bundle is this binary's own artifact, not traffic.
///
/// # Why it is asserted HERE, in Rust
///
/// It was caught by `tests/python/test_node_state_surface.py`, which CI runs and
/// **`certify.sh full` does not** — so the release gate was structurally blind
/// to it. Restating the invariant at the Rust layer puts it under nextest, which
/// both run. The python test keeps its own assertion; this is the one that fails
/// first and on every leg.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) fn assert_genesis_seed_is_not_peer_traffic(
    quota: &crate::federation::replication::admission::PeerWriteQuota,
    tag: &str,
) {
    assert_eq!(
        quota.tracked_peers(),
        0,
        "[{tag}] a freshly seeded node must have observed NO peers — the compiled-in genesis \
         bundle is this binary's own artifact, not traffic. `tracked_peers > 0` is what lifts \
         the peer-quota band out of `unknown`, so counting the seed reports a TESTED quota on \
         a node nobody has ever talked to"
    );
    assert_eq!(
        quota.slot_denials(),
        0,
        "[{tag}] and nothing was denied a bucket"
    );
}

/// v31.1.0 (CIRISPersist#665 review) — **THE ROLLING-DEPLOYMENT WITNESS: a
/// stale initializer must not delete the row that overtook it.**
///
/// Two engine versions initializing one database is what a fleet upgrade IS, so
/// this is the ordinary case, not an exotic one. The old engine reads the plane,
/// classifies a row as supersedable, and then — between that read and its
/// write — the new engine installs a newer ceremony row. Deleting by id alone,
/// the stale initializer removed a NEWER constitutional statement and installed
/// its own older baked one: the exact rollback the floor rule refuses, performed
/// by the one caller that had already decided it was entitled to write.
///
/// The window is reproduced exactly, and deterministically, the same way the
/// seed race is: [`install_or_supersede_delegation_row`] takes the classifying
/// read as a PARAMETER, so the witness hands it the STALE row while the corpus
/// holds the row that overtook it. No timing dependence, and the compare runs
/// against the real backend's real stored state.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn assert_stale_initializer_cannot_delete_the_winner(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    let baked = &canonical_genesis_bundle().attestations[0];
    let id = &baked.attestation.attestation_id;

    // What the STALE initializer read: the previous ceremony's row, which it
    // correctly classified as supersedable.
    let stale_read = prior_ceremony_row(id);

    // What is ACTUALLY stored by now: the winner's row — the current baked
    // artifact, installed by the newer engine after that read.
    let winner = dir
        .get_attestation(id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] the winner's row must be installed"));
    assert_ne!(
        winner.persist_row_hash, stale_read.persist_row_hash,
        "[{tag}] the fixture must have the corpus genuinely AHEAD of the stale read"
    );

    // The stale initializer acts on its obsolete classification.
    let outcome = install_or_supersede_delegation_row(dir, baked, Some(stale_read))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a lost classification race must not fault boot: {e}"));
    assert_eq!(
        outcome,
        DelegationRowOutcome::RaceLostReclassify,
        "[{tag}] the compare-and-delete must DECLINE — the row it was told to replace is not the \
         row that is there"
    );

    // And nothing was destroyed.
    let after = dir
        .get_attestation(id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] the winner's row was DELETED by a stale initializer"));
    assert_eq!(
        after.persist_row_hash, winner.persist_row_hash,
        "[{tag}] the winner's row must be byte-untouched — reclassify, never remove"
    );
    verify_delegation_plane_seeded(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] and the plane still verifies: {e}"));
}

/// v31.1.0 (CIRISPersist#665 review) — **THE SUCCESSOR WITNESS: an authenticated
/// re-ceremony supersedes the boot-seeded plane, and a rollback bundle does
/// not.**
///
/// Both halves of the second review P1, through the real
/// [`bake_assembled_genesis`](bundle::bake_assembled_genesis) with two REAL
/// artifacts — no synthesized bundle, because a fabricated one would prove a
/// property of the fabrication and the whole question here is whether real
/// quorum-verified ceremony bytes can land.
///
/// The caller arrives with a plane holding the PREVIOUS ceremony's rows.
///
/// Before this cut the bake's delegation loop was a bare `put_attestation`, and
/// #665 gave the boot seed the same three ids — so on any node that had ever
/// booted, every re-ceremony collided on all three, reported `Skipped`, and
/// returned a partially applied bake while retaining the old plane. The
/// documented candidate re-mint path was unusable on every node in the fleet.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn assert_ceremony_supersedes_boot_seeded_plane(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    // The v31 bundle offered as a CEREMONY over the v30 plane — the upgrade a
    // real re-mint performs.
    let report = bundle::bake_assembled_genesis(dir, CANONICAL_SEED_JSON)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a quorum-verified re-ceremony must land: {e}"));
    for (id, outcome) in &report.attestations {
        assert!(
            matches!(
                outcome,
                bundle::BakeItemOutcome::ReAnchored
                    | bundle::BakeItemOutcome::Anchored
                    | bundle::BakeItemOutcome::AlreadyPresent
            ),
            "[{tag}] the ceremony must APPLY to {id}, not report it skipped: {outcome:?}. A bake \
             that returns success while retaining the old delegation plane is the finding"
        );
    }
    for sa in &canonical_genesis_bundle().attestations {
        let id = &sa.attestation.attestation_id;
        let row = dir
            .get_attestation(id)
            .await
            .expect("read back")
            .unwrap_or_else(|| panic!("[{tag}] {id} missing after the ceremony"));
        assert_eq!(
            row.original_content_hash, sa.attestation.original_content_hash,
            "[{tag}] {id} must carry the CEREMONY's content, not the superseded plane's"
        );
    }
    verify_delegation_plane_seeded(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] and the plane verifies after the ceremony: {e}"));

    // The bake is IDEMPOTENT on a plane it has already applied — the second run
    // must not re-anchor, or a re-ceremony would delete and re-install the
    // constitutional root every time it ran.
    let again = bundle::bake_assembled_genesis(dir, CANONICAL_SEED_JSON)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a repeated ceremony must be a no-op: {e}"));
    for (id, outcome) in &again.attestations {
        assert_eq!(
            *outcome,
            bundle::BakeItemOutcome::AlreadyPresent,
            "[{tag}] {id} is already the ceremony's own row on the second pass"
        );
    }

    // NOTE — the delegation loop's ANTI-ROLLBACK half is deliberately NOT
    // witnessed through `bake_assembled_genesis` here. Offering the v30 bundle
    // over a current plane is refused by the SERVE-NODE loop's `valid_from`
    // check before the delegation loop is ever reached, so an assertion here
    // would pass while testing the wrong loop — and the only way to reach the
    // delegation loop with an older attestation is a bundle assembled to do it,
    // which is a fabricated artifact proving a property of the fabrication.
    // Delegation anti-rollback is witnessed where it can be witnessed honestly:
    // on the predicate (`candidate_is_strictly_newer`) and on the boot path
    // (`LeftAsNewerCeremony`), both in `assert_refused_replacement_classes`.
}

/// v31.1.0 (CIRISPersist#665 review) — **THE DAMAGE WITNESS: a stored genesis
/// row whose signatures were altered beneath persist is repaired, not reported
/// entrenched.**
///
/// The caller has already seeded the baked plane and then damaged
/// `genesis-charter` in the sharpest way available: it emptied
/// `additional_scrubs`, dropping B1's co-signature, while leaving the signed
/// envelope and `original_content_hash` untouched.
///
/// That row is not a cosmetic problem. `genesis-charter` IS the family charter,
/// and [`family_quorum_over`](crate::federation::trust_root) counts DISTINCT
/// VERIFIED co-signatures over its envelope — so a thinned scrub set takes the
/// constitutional trust root from 2-of-3 to 1 and it stops validating, while
/// nothing on the boot path notices: the old `AlreadyCurrent` test compared
/// `original_content_hash` (a digest of the ENVELOPE alone) and
/// `verify_delegation_plane_seeded` asks only for that same hash and the v31
/// shape. Neither verifies a signature. The node reported `entrenched` on a root
/// that could no longer be accepted by a peer — a fail-OPEN banner, which is
/// the exact class the delegation leg was added to catch.
///
/// The witness opens by proving the blindness rather than assuming it.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn assert_damaged_current_row_is_repaired(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    let baked = &canonical_genesis_bundle().attestations[0];
    let id = &baked.attestation.attestation_id;

    // (0) THE DAMAGE IS REAL, AND THE READ PATH CATCHES IT.
    //
    // This assertion is INVERTED from its first form, and the inversion is the
    // point. It used to assert that the posture leg PASSES here, labelled "that
    // blindness is the finding" — correctly identifying a fail-open and then
    // leaving it standing on the READ path while fixing only the SEED path.
    // `genesis_posture` never calls the seed, so every live query
    // (`Engine::genesis_posture`, `NodeState::genesis` → `StateBand::Green`,
    // CIRISServer's agent-mode gate) answered from this leg alone, and damage
    // landing after boot was invisible to all of them — on a threat model whose
    // premise is a writer with raw corpus access, who does not wait for a
    // restart.
    let damaged = dir
        .get_attestation(id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] the damaged row {id} must be installed"));
    assert!(
        damaged.additional_scrubs.is_empty(),
        "[{tag}] the fixture must actually have dropped the co-signature, or this proves nothing"
    );
    assert_eq!(
        damaged.original_content_hash, baked.attestation.original_content_hash,
        "[{tag}] and must have left the ENVELOPE digest intact — that is the whole point: the \
         damage is invisible to a content-hash check, so only a whole-row comparison finds it"
    );
    let fault = verify_delegation_plane_seeded(dir).await.expect_err(
        "a row whose co-signature set was thinned below quorum must NOT read as sound — this is \
         the live-query fail-open, and it is what CIRISServer#398 gates agent mode on",
    );
    assert_eq!(
        fault.as_str(),
        "divergent",
        "[{tag}] and it is divergence — a root altered beneath persist: {fault}"
    );
    assert_eq!(
        posture::genesis_posture(dir).await.as_str(),
        "divergent",
        "[{tag}] the posture a LIVE QUERY sees says so too — that is the half that was missing"
    );

    // (1) THE SEED REPAIRS IT.
    seed_delegation_plane(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the seed must repair the row, not fault: {e}"));

    let repaired = dir
        .get_attestation(id)
        .await
        .expect("read back")
        .unwrap_or_else(|| panic!("[{tag}] {id} vanished across the repair"));
    assert_eq!(
        repaired.additional_scrubs.len(),
        baked.attestation.additional_scrubs.len(),
        "[{tag}] the co-signature set must be restored from the baked artifact — a charter \
         missing a scrub is a trust root that silently stops reaching its threshold"
    );
    assert_eq!(
        repaired.additional_scrubs, baked.attestation.additional_scrubs,
        "[{tag}] and restored EXACTLY, not merely to the right length"
    );
    assert_eq!(
        repaired.scrub_signature_classical, baked.attestation.scrub_signature_classical,
        "[{tag}] the base scrub is the baked one"
    );
    assert_eq!(
        repaired.original_content_hash, baked.attestation.original_content_hash,
        "[{tag}] and the row still carries the baked content"
    );
    assert_eq!(
        posture::genesis_posture(dir).await.as_str(),
        "entrenched",
        "[{tag}] and the node serves on a root that is now whole"
    );

    // (2) IDEMPOTENT. The repaired row must read as current on the next boot;
    // if it does not, every start would delete and re-install the trust root.
    let stored = dir.get_attestation(id).await.expect("read back");
    assert_eq!(
        install_or_supersede_delegation_row(dir, baked, stored)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the boot after a repair must be a no-op: {e}")),
        DelegationRowOutcome::AlreadyCurrent,
        "[{tag}] a repaired row is AlreadyCurrent, not repaired again"
    );
}

/// v31.1.0 (CIRISPersist#665) — **THE RACE WITNESS: a duplicate insert leaves
/// the node FULLY seeded, not half-seeded.**
///
/// The P2 finding stated as an assertion. Two engines initializing one database
/// both read a missing row and both write it; the loser's `put_attestation`
/// comes back with a primary-key collision. That collision is
/// [`Error::Backend`](super::Error::Backend) on all three backends — memory and
/// sqlite render it `UNIQUE constraint failed: …`, postgres `SQLSTATE 23505:
/// duplicate key value …` — and NEVER `Error::Conflict`, which is all the
/// original code matched. So the loser fell through to the fault arm, returned
/// `absent`, and **abandoned the rest of the plane**. If the winner then exited
/// after its first insert, the node was left permanently half-seeded until
/// somebody restarted it.
///
/// # Why this drives the seam instead of racing two tasks
///
/// A timing race is not a witness. Memory and sqlite do no I/O in
/// `put_attestation`, so their futures never yield and two joined seeders run
/// strictly one after the other — the collision would simply never occur, and
/// the test would pass while proving nothing (and a MUTANT would pass with it).
///
/// The loser's position is fully described by one fact: **it acts on a `None`
/// read while the row exists.** [`install_or_supersede_delegation_row`] takes
/// that read as a parameter, so the witness can put the directory in the real
/// post-race state — the winner's row genuinely written through the real door,
/// by the real backend — and hand the seed the stale `None` the loser was
/// holding. The error the seed then sees is the backend's own, not a fixture's.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn exercise_duplicate_insert_leaves_plane_fully_seeded(
    dir: &dyn super::FederationDirectory,
    tag: &str,
) {
    let bundle = canonical_genesis_bundle();
    let first = &bundle.attestations[0];

    // THE WINNER. A real write, through the real door, on the real backend.
    dir.put_attestation(first.clone())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the winning engine's insert must land: {e}"));

    // THE LOSER, acting on the read it took before that write. This call is the
    // regression: it must absorb the collision and report the plane seeded.
    let outcome = install_or_supersede_delegation_row(dir, first, None)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "[{tag}] losing a primary-key race is boot NORMALITY — the row is present, which \
                 is what the seed wanted. Reporting a fault here is what abandoned the rest of \
                 the plane and left nodes half-seeded: {e}"
            )
        });
    assert_eq!(
        outcome,
        DelegationRowOutcome::Raced,
        "[{tag}] and it is named as a race, not silently conflated with a fresh install"
    );

    // AND THE PLANE COMPLETES. The half-seeding is the actual harm: the loser
    // must go on to install the rows the winner never reached.
    for sa in bundle.attestations.iter().skip(1) {
        assert!(
            dir.get_attestation(&sa.attestation.attestation_id)
                .await
                .expect("read back")
                .is_none(),
            "[{tag}] the fixture must start with the rest of the plane UNSEEDED, or the \
             half-seeding claim is untested"
        );
    }
    seed_delegation_plane(dir)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the loser must finish seeding the plane: {e}"));
    verify_delegation_plane_seeded(dir)
        .await
        .unwrap_or_else(|e| {
            panic!("[{tag}] and the plane must verify, not be half-installed: {e}")
        });
    for sa in &bundle.attestations {
        let id = &sa.attestation.attestation_id;
        let row = dir
            .get_attestation(id)
            .await
            .expect("read back")
            .unwrap_or_else(|| {
                panic!("[{tag}] {id} was never installed — the node is half-seeded")
            });
        assert_eq!(
            row.original_content_hash, sa.attestation.original_content_hash,
            "[{tag}] {id} carries the baked content"
        );
    }
    assert_eq!(
        posture::genesis_posture(dir).await.as_str(),
        "entrenched",
        "[{tag}] a node that lost a seed race still boots entrenched"
    );

    // The duplicate-key predicate is measured against THIS backend's real
    // error, not assumed: the whole finding was that it is not `Conflict`.
    let dup = dir
        .put_attestation(first.clone())
        .await
        .expect_err("a second insert of a present id must fail");
    assert!(
        dup.is_duplicate_key(),
        "[{tag}] this backend's duplicate-key error must be recognized by the ONE shared \
         predicate (kind={}, err={dup})",
        dup.kind()
    );
    assert_eq!(
        dup.kind(),
        "federation_backend",
        "[{tag}] and it is `Backend`, not `Conflict` — which is exactly why matching \
         `Error::Conflict` alone silently never fired"
    );
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
    seed_delegation_plane(dir).await?;
    verify_delegation_plane_seeded(dir).await?;
    Ok(())
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
/// [`bake_assembled_genesis`](super::genesis::bundle::bake_assembled_genesis),
/// which installs a quorum-verified ceremony bundle. Until the #665 review they
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
        Ok(()) => Ok(DelegationRowOutcome::Installed),
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
        Err(e) => Err(GenesisFault::absent(
            LEG,
            format!("delegation row {id} could not be installed: {e}"),
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
    if let Err(e) = check_genesis_attestation_reserved(&sa.attestation) {
        return Err(GenesisFault::absent(
            LEG,
            format!(
                "refusing to remove the installed delegation row {id}: the replacement would be \
                 refused at the write door anyway ({e}) — nothing deleted"
            ),
        ));
    }
    if !candidate_is_v31_conformant_as_stored(&sa.attestation) {
        return Err(GenesisFault::absent(
            LEG,
            format!(
                "refusing to remove the installed delegation row {id}: the replacement is not \
                 v31-shaped and `put_attestation` would refuse it deterministically — nothing \
                 deleted"
            ),
        ));
    }
    if let Err(e) =
        super::admission::check_envelope_size_admission(&sa.attestation.attestation_envelope)
    {
        return Err(GenesisFault::absent(
            LEG,
            format!(
                "refusing to remove the installed delegation row {id}: the replacement envelope \
                 would be refused at the write door ({e}) — nothing deleted"
            ),
        ));
    }

    match dir
        .purge_genesis_delegation_row_v31(id, expected_persist_row_hash)
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
            return Err(GenesisFault::absent(
                LEG,
                format!(
                    "delegation row {id} needs replacing and this directory has no re-bake \
                     replacement door: {e}"
                ),
            ))
        }
        Err(e) => {
            return Err(GenesisFault::absent(
                LEG,
                format!("delegation row {id} could not be removed for replacement: {e}"),
            ))
        }
    }
    match dir.put_attestation(sa.clone()).await {
        Ok(()) => Ok(outcome),
        // Somebody else completed the same replacement first. The plane holds
        // the baked row either way, which is what this was for.
        Err(e) if e.is_duplicate_key() => Ok(DelegationRowOutcome::Raced),
        Err(e) => Err(GenesisFault::absent(
            LEG,
            format!("baked delegation row {id} could not be installed over its predecessor: {e}"),
        )),
    }
}

/// v31.1.0 (CIRISPersist#665 review) — **is `candidate` strictly newer than
/// `stored`?** The anti-rollback half of the replacement rule.
///
/// Both doors onto this plane ask it, and neither may write an older statement
/// over a newer one. It is the same discipline the SERVE-NODE half of
/// [`bake_assembled_genesis`](super::genesis::bundle::bake_assembled_genesis)
/// has always had (`valid_from` must advance), finally applied to the
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
    /// v31.0.0 (CIRISPersist#660) — **the delegation leg's verdict must not
    /// depend on the wall clock.**
    ///
    /// [`bundle_delegation_plane_v31_shaped`] and the shape half of
    /// [`verify_delegation_plane_seeded`] were two hand-rolled copies of
    /// [`classify_shape`](crate::federation::migration::classify_shape), and
    /// both passed `Utc::now()` to `check_instant_binding` where the classifier
    /// deliberately passes the ROW'S OWN `asserted_at` (#650).
    ///
    /// `check_instant_binding`'s fourth arm is a FRESHNESS bound — reject
    /// `asserted_at > now + max_skew` — so on a node whose clock lags (a VM
    /// snapshot restore, a container up before NTP) a perfectly bound delegation
    /// row reads as "not v31-shaped". On the posture path that demotes a fully
    /// entrenched root to `pre_genesis`, raises the PRE-GENESIS banner and tells
    /// the host to refuse agent mode — a self-inflicted outage from a clock.
    ///
    /// The fixture is the difference stated directly: a row sealed one hour in
    /// the FUTURE relative to the checking clock. Correctly bound, wrong only if
    /// the wall clock is the reference. Freshness is still enforced where it
    /// belongs (the put doors, promotion, `check_reseal_admission`), all against
    /// the true clock — this leg is asking about shape.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn delegation_plane_shape_is_clock_independent_660() {
        use crate::federation::tier_ingest::test_support as ts;

        let signer = "660clock-signer";
        let mut row = super::ordinary_scores_row("660clock-row", signer);
        // One hour AHEAD of the checking clock: the exact input the skew arm
        // rejects and the binding does not care about.
        row.asserted_at = chrono::Utc::now() + chrono::Duration::hours(1);
        ts::seal_row_in_place(signer, &mut row);
        // Canonical at rest (#647), the way a real put door leaves the row: the
        // seal stamps `weight: 1.0` into the mirror and JCS renders that `1`.
        // `original_content_hash` is already SHA-256 of the CANONICAL form, so
        // this only settles the stored bytes — it does not disturb the seal.
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut row.attestation_envelope)
            .expect("canonicalize");

        let bundle = super::GenesisBundle {
            version: 2,
            family_key_id: "humanity-accord".to_owned(),
            holders: Vec::new(),
            serve_nodes: Vec::new(),
            consensus_protocol: "quorum:2/3".to_owned(),
            attestations: vec![crate::federation::SignedAttestation { attestation: row }],
            authorizations: Vec::new(),
            produced_at: "2026-08-12T00:00:00Z".to_owned(),
        };

        super::bundle_delegation_plane_v31_shaped(&bundle).unwrap_or_else(|why| {
            panic!(
                "a correctly bound delegation row must be v31-SHAPED regardless of where the \
                 wall clock happens to be — shape is not freshness: {why}"
            )
        });

        // And the dye test: the SAME row read through the wall clock is refused,
        // which is what makes the assertion above a difference rather than a
        // tautology. If this ever stops failing, the fixture has gone stale and
        // the assertion above proves nothing.
        let skewed = crate::federation::admission::check_instant_binding(
            &bundle.attestations[0].attestation,
            chrono::Utc::now(),
            crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
        );
        assert!(
            skewed.is_err(),
            "the fixture must actually trip the wall-clock skew arm, or this witness is \
             measuring nothing"
        );
    }

    /// **CIRISPersist#557 — the CEREMONY DRY RUN.** Installs a candidate
    /// re-mint bundle through the REAL gates and asserts it roots to the
    /// FAMILY under quorum — the validation promised on #557 before any
    /// bundle is treated as the root ("one dry session is far cheaper than
    /// discovering the grant shape was wrong after baking").
    ///
    /// Skips cleanly when no candidate is present, so it lives in the suite
    /// as the permanent ceremony harness: point `GENESIS3` at the next
    /// bundle and the same assertions run.
    ///
    /// The three assertions the ceremony hangs on, and why each:
    /// - `root_kind == Family` — a subtly-wrong family shape otherwise
    ///   DEGRADES to a working single-key root (CIRISServer's transition-risk
    ///   flag: silent success is how this reaches production);
    /// - `conferral_plane == FamilyQuorum` — the grant was attributed by
    ///   SIGNATURE (2 seated holders), never by a granter field naming a
    ///   keyless family;
    /// - all four `infra:*` scopes — the v23.1.0 bake conferred `serve` alone.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn genesis_candidate_bundle_roots_to_the_family_under_quorum_557() {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, trust_root_valid, ConferralPlane, RootKind,
            TRUST_ACCEPTS_DIMENSION,
        };
        use crate::federation::{FederationDirectory, SignedAttestation};
        use crate::store::{Backend as _, SqliteBackend};

        let path =
            std::env::var("GENESIS3").unwrap_or_else(|_| "/home/emoore/genesis_3.json".into());
        let Ok(raw) = std::fs::read_to_string(&path) else {
            eprintln!("skipping #557 dry run: no candidate bundle at {path}");
            return;
        };
        let b: GenesisBundle =
            serde_json::from_str(&raw).expect("candidate parses as GenesisBundle");
        const CANONICAL: &str = "ciris-canonical-1-d7bdeu223k";
        const FAMILY: &str = "humanity-accord";

        let sq = SqliteBackend::open_in_memory().await.expect("open");
        sq.run_migrations().await.expect("migrations");

        // Holders FIRST: verify_bundle_quorum re-derives the roster from THIS
        // node's directory (the #377 rule — never the roster the bundle
        // carries), so the seats must be seeded before the quorum can be
        // re-tallied against them.
        sq.seed_genesis_accord_holders(&b.holders)
            .await
            .expect("holders seed");
        let n = verify_bundle_quorum(&sq, &b)
            .await
            .expect("bundle quorum verifies");
        eprintln!("DRYRUN quorum: {n} authorizations verified");
        seed_accord_family(&sq).await.expect("family row");
        for rec in &b.serve_nodes {
            sq.put_public_key(rec.clone())
                .await
                .expect("serve node admits");
        }
        // v31.0.0 (CIRISPersist#648) — the dry run's FIRST finding is whether
        // the candidate is even in the right regime. A bundle whose delegation
        // plane predates #643 carries no signed `row` mirror, so every
        // `put_attestation` refuses it; that is the gate closing the
        // verb-substitution and authority-injection attacks and it is not to be
        // weakened to bake a stale artifact.
        //
        // So the dry run REPORTS that verdict instead of asserting through it.
        // For a pre-v31 candidate the honest ceremony finding is "re-sign under
        // the #643 envelope shape and run this again" — which is precisely the
        // operator's 31.0.0 → 31.1.0 plan — and the refusal is asserted rather
        // than skipped. For a re-signed candidate the full trust-root walk runs
        // as before, on the artifact, with nobody editing the test.
        if let Err(why) = bundle_delegation_plane_v31_shaped(&b) {
            eprintln!("DRYRUN: candidate is PRE-v31 (delegation plane not row-bound): {why}");
            for att in &b.attestations {
                let err = sq
                    .put_attestation(SignedAttestation {
                        attestation: att.attestation.clone(),
                    })
                    .await
                    .expect_err("a pre-#643 candidate attestation must be REFUSED, not baked");
                assert!(
                    is_v31_binding_refusal(&err.to_string()),
                    "the refusal names an envelope-binding gate (#643 mirror or #598 \
                     instants): {err}"
                );
            }
            eprintln!(
                "DRYRUN: PASS (pre-v31 regime) — quorum verified over {n} authorizations, keys \
                 admitted, and all {} delegation rows correctly REFUSED by the #643 gate. \
                 FINDING: this candidate must be re-signed under the #643 envelope shape \
                 before it can serve as a trust root. The trust-root walk below returns with \
                 the re-baked bundle in 31.1.0.",
                b.attestations.len()
            );
            return;
        }
        for att in &b.attestations {
            sq.put_attestation(SignedAttestation {
                attestation: att.attestation.clone(),
            })
            .await
            .unwrap_or_else(|e| {
                panic!("attestation {} admits: {e}", att.attestation.attestation_id)
            });
        }
        eprintln!(
            "DRYRUN install: holders + family + serve + {} attestations",
            b.attestations.len()
        );

        // A fresh node's own trust:accepts -> the FAMILY (what first boot writes).
        let node = "dryrun-fresh-node";
        crate::federation::tier_ingest::test_support::register_hybrid_key(&sq, node).await;
        let edge_id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": edge_id,
            "dimension": TRUST_ACCEPTS_DIMENSION,
            "scope": ["infra:serve", "infra:attest", "infra:store", "infra:transport"],
        });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(node, &envelope);
        let now = chrono::Utc::now();
        sq.put_attestation(SignedAttestation {
            attestation: crate::federation::Attestation {
                attestation_id: edge_id.clone(),
                attesting_key_id: node.to_owned(),
                attested_key_id: FAMILY.to_owned(),
                attestation_type: crate::federation::types::attestation_type::DELEGATES_TO
                    .to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: node.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("node trust:accepts -> family admits");

        let verdict = trust_root_valid(&sq, node, FAMILY).await.expect("verdict");
        eprintln!("DRYRUN verdict: {verdict:?}");
        assert_eq!(
            verdict.root_kind,
            RootKind::Family,
            "#557: the root is the FAMILY, not a seat"
        );
        assert!(
            verdict.valid,
            "#557: family root must be VALID: {verdict:?}"
        );

        for scope in [
            "infra:serve",
            "infra:attest",
            "infra:store",
            "infra:transport",
        ] {
            let grant = capability_roots_to_trusted_root(&sq, node, CANONICAL, scope)
                .await
                .expect("walk")
                .unwrap_or_else(|| {
                    panic!("#557: canonical must hold {scope} under the family root")
                });
            eprintln!(
                "DRYRUN {scope}: root={} plane={:?}",
                grant.root_key_id, grant.conferral_plane
            );
            assert_eq!(grant.root_key_id, FAMILY, "{scope}: roots to the FAMILY");
            assert_eq!(
                grant.conferral_plane,
                ConferralPlane::FamilyQuorum,
                "{scope}: quorum plane"
            );
        }
        eprintln!("DRYRUN: PASS — quorum-rooted, all four infra scopes, no single seat");
    }

    use super::*;
    use crate::federation::types::identity_type;

    /// The baked seed parses, is the 3-holder set, and every record satisfies
    /// the `root_binding` terminus shape: self-signed `accord_holder` whose
    /// Ed25519 pubkey is a pinned anchor key (CIRISPersist#347 req a/b/c).
    #[test]
    fn accord_holder_seed_parses_and_matches_anchor() {
        let recs = accord_holder_genesis_records();
        assert_eq!(recs.len(), 3, "the HUMANITY_ACCORD trio");

        let anchor: std::collections::HashSet<[u8; 32]> =
            ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor()
                .into_iter()
                .collect();
        assert_eq!(anchor.len(), 3, "anchor is the 3 founder pubkeys");

        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        for sr in recs {
            let r = &sr.record;
            assert_eq!(r.scrub_key_id, r.key_id, "{} must be self-signed", r.key_id);
            assert_eq!(
                r.identity_type,
                identity_type::ACCORD_HOLDER,
                "{} is an accord_holder terminus",
                r.key_id
            );
            let ed: [u8; 32] = B64
                .decode(&r.pubkey_ed25519_base64)
                .expect("ed25519 b64")
                .try_into()
                .expect("32 bytes");
            assert!(
                anchor.contains(&ed),
                "{}'s pubkey must be a pinned anchor key",
                r.key_id
            );
        }
    }

    /// End-to-end (CIRISPersist#347): seed the REAL #268 ceremony records into
    /// a fresh backend, the fail-secure presence check passes, and the seeded
    /// A1 holder **roots** via the default `root_binding` — its own self-signed
    /// terminus, pubkey ∈ the pinned anchor, with the real ceremony
    /// scrub-signature verifying over its canonical envelope (the v12.0.0
    /// canonical-bytes path, now exercised against a genuine artifact).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn seeded_real_holder_roots_via_root_binding() {
        use crate::federation::rooting::root_binding;
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .seed_genesis_accord_holders(accord_holder_genesis_records())
            .await
            .expect("genesis seed");

        // Fail-secure presence check passes on a freshly-seeded node.
        verify_anchor_seeded(&backend).await.expect("anchor live");

        // The real A1 ceremony record roots as its own terminus.
        let a1 = &accord_holder_genesis_records()[0].record;
        assert_eq!(a1.key_id, "A1");
        let verdict = root_binding(&backend, &a1.key_id, &a1.pubkey_ed25519_base64).await;
        assert!(
            verdict.is_confirmed(),
            "seeded real A1 must root (self-signed accord_holder ∈ anchor, real sig over canonical), got {verdict:?}"
        );
    }

    /// v13.3.0 (CIRISPersist#386) — the baked accord FAMILY record is the
    /// entrenched `quorum:2/3` HUMANITY_ACCORD over the A1/B1/C1 founder seats,
    /// coherent with the seeded holder rows.
    #[test]
    fn accord_family_genesis_is_entrenched_2of3_over_the_holders() {
        let fam = accord_family_genesis_record();
        assert_eq!(fam.family_key_id, "humanity-accord");
        assert_eq!(fam.consensus_protocol, "quorum:2/3");
        assert!(fam.consensus_protocol_entrenched);
        let seats: std::collections::BTreeSet<&str> =
            fam.members.iter().map(|m| m.key_id.as_str()).collect();
        let holders: std::collections::BTreeSet<&str> = accord_holder_genesis_records()
            .iter()
            .map(|sr| sr.record.key_id.as_str())
            .collect();
        assert_eq!(seats, holders, "family seats == the seeded holder key_ids");
        assert!(fam
            .members
            .iter()
            .all(|m| m.role.as_deref() == Some("founder")));
    }

    /// v23.0.0 (CIRISPersist#551 item 1) — the embedded seed asset round-trips
    /// as a `GenesisBundle` through the SAME door an operator artifact enters
    /// ([`parse_genesis_bundle`]).
    ///
    /// v23.1.0 (CIRISPersist#554) — **the seed is now the real production
    /// trust root**, so this test asserts its CONTENT, not merely its shape.
    /// Until this cut the asset was a bundle-shaped placeholder — `holders 0,
    /// attestations 0, authorizations 0` — and every assertion here was
    /// satisfied by emptiness. A test that passes on a placeholder cannot tell
    /// you the bake happened. Each field below is pinned to what the June 2026
    /// hardware ceremony actually produced, so a regression to a placeholder
    /// (or a silently swapped artifact) fails loudly rather than returning
    /// green on nothing.
    #[test]
    fn embedded_seed_is_a_genesis_bundle_551() {
        let b = canonical_genesis_bundle();
        assert_eq!(b.version, 2);
        assert_eq!(b.family_key_id, "humanity-accord");
        assert_eq!(b.consensus_protocol, "quorum:2/3");

        // The holder roster: A1/B1/C1 on YubiKeys, each carrying REAL custody
        // evidence (#554 — the arm that made these representable).
        let holders: Vec<&str> = b.holders.iter().map(|h| h.record.key_id.as_str()).collect();
        assert_eq!(holders, ["A1", "B1", "C1"], "the accord holder roster");
        for h in &b.holders {
            assert!(
                h.record.claims_role(identity_type::ACCORD_HOLDER),
                "{} must claim accord_holder",
                h.record.key_id
            );
            assert!(
                h.record.attestation_evidence.is_some(),
                "{} must carry custody evidence — a holder without it is the \
                 unrepresentable case #554 fixed",
                h.record.key_id
            );
        }

        // The delegation plane and the holder quorum are PRESENT — this is the
        // condition #551 said must stop being invisible, now satisfied rather
        // than merely observable.
        let atts: Vec<&str> = b
            .attestations
            .iter()
            .map(|a| a.attestation.attestation_id.as_str())
            .collect();
        // v24.1.0 (CIRISPersist#557) — the QUORUM-ROOTED bake. The grant id
        // lost its `-serve` qualifier when the ceremony started conferring the
        // full infra set (the v23.1.0 bundle granted `infra:serve` alone), and
        // the charter/lifecycle rows now name the FAMILY rather than a seat.
        assert_eq!(
            atts,
            [
                "genesis-charter",
                "genesis-grant:ciris-canonical-1-d7bdeu223k",
                "genesis-lifecycle",
            ],
            "charter + serve grant + lifecycle — the delegation plane"
        );
        let auths: Vec<&str> = b
            .authorizations
            .iter()
            .map(|a| a.holder_key_id.as_str())
            .collect();
        assert_eq!(auths, ["A1", "B1"], "2-of-3 holder authorizations");
        for a in &b.authorizations {
            assert!(
                !a.signature_classical.is_empty() && !a.signature_pqc.is_empty(),
                "{} must authorize with BOTH halves — hybrid, not classical-only",
                a.holder_key_id
            );
        }

        // Byte-faithfulness of the wrapped record: the seeded row is the one
        // the ceremony blessed, container change notwithstanding.
        assert_eq!(b.serve_nodes.len(), 1, "the canonical serve node");
        assert_eq!(
            b.serve_nodes[0].record.key_id,
            "ciris-canonical-1-d7bdeu223k"
        );
        // v24.1.0 — the quorum-rooted ceremony's own instant. Pinned so a
        // re-bake is a DELIBERATE edit here, never a silent artifact swap.
        assert_eq!(
            b.serve_nodes[0].record.valid_from.to_rfc3339(),
            "2026-07-31T13:58:22.147317128+00:00"
        );
    }

    /// v23.0.0 (CIRISPersist#551 item 1) — a legacy bare `[{record}]` seed is
    /// REFUSED with the typed `GenesisBundleInvalid`, by a message that names
    /// the shape it got. The pre-v23 failure mode was the opposite of loud: a
    /// record list seeded an inert node that rooted and reported healthy.
    #[tokio::test]
    async fn legacy_bare_record_list_seed_is_refused_loudly_551() {
        let legacy = r#"[{"record":{"key_id":"ciris-canonical-1-d7bdeu223k"}}]"#;
        let err = parse_genesis_bundle(legacy).expect_err("a bare record list is not a seed");
        assert!(
            matches!(err, crate::federation::Error::GenesisBundleInvalid { .. }),
            "must be the TYPED refusal, got {err:?}"
        );
        let msg = err.to_string();
        for want in [
            "bare JSON array of 1 element(s)",
            "DELETED in v23.0.0 (CIRISPersist#551 item 1)",
            "no charter, no conferral, no liveness witness",
        ] {
            assert!(msg.contains(want), "refusal must say {want:?}, got: {msg}");
        }

        // The same refusal through the operator-facing door — one parse door,
        // one message, so an artifact and the seed asset cannot disagree.
        let backend = crate::store::memory::MemoryBackend::new();
        let baked = super::bake_assembled_genesis(&backend, legacy)
            .await
            .expect_err("bake must refuse the legacy shape identically");
        assert!(baked.to_string().contains("bare JSON array"));
    }

    /// v13.4.0 (CIRISPersist#390) — the baked canonical seed parses, is
    /// `canonical`, and is **2-of-3 accord-conferred**: primary scrub A1 + a
    /// distinct additional anchor scrub (B1), ≥2 distinct scrubbers.
    #[test]
    fn canonical_seed_is_a_bundle_and_is_2of3_accord_conferred() {
        let recs = &canonical_genesis_bundle().serve_nodes;
        assert_eq!(recs.len(), 1, "the founding canonical server");
        let r = &recs[0].record;
        assert_eq!(r.key_id, "ciris-canonical-1-d7bdeu223k");
        assert!(identity_type::set_contains(
            &r.identity_type,
            identity_type::CANONICAL
        ));
        assert_eq!(r.scrub_key_id, "A1", "primary scrub");
        assert!(
            r.additional_scrubs.iter().any(|s| s.scrub_key_id == "B1"),
            "co-scrub by a second distinct anchor holder (B1)"
        );
        assert!(
            r.distinct_scrub_count() >= 2,
            "must be a >=2 accord co-scrub, got {}",
            r.distinct_scrub_count()
        );
    }

    /// v13.4.0 (CIRISPersist#390) — end-to-end: seed holders → family → the
    /// 2-of-3 canonical server. The canonical record is admitted THROUGH the
    /// 2-of-3 `check_canonical_role_admission` gate against the seeded A1/B1
    /// anchor, `verify_canonical_seeded` passes, and `is_canonical` /
    /// `list_canonical_servers` report it. Re-seed is idempotent.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn seeded_2of3_canonical_server_is_admitted_and_listed() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .seed_genesis_accord_holders(accord_holder_genesis_records())
            .await
            .expect("holder seed");
        seed_accord_family(&backend).await.expect("family seed");
        // The 2-of-3 canonical verifies against the just-seeded A1/B1 anchor.
        seed_canonical_servers(&backend)
            .await
            .expect("canonical seed (2-of-3 must admit)");
        verify_canonical_seeded(&backend)
            .await
            .expect("canonical live");

        let node = &canonical_genesis_bundle().serve_nodes[0].record;
        assert!(
            crate::federation::is_canonical(&backend, &node.key_id)
                .await
                .expect("is_canonical"),
            "{} must be canonical on a fresh node",
            node.key_id
        );
        let listed = backend.list_canonical_servers().await.expect("list");
        assert!(
            listed.iter().any(|r| r.key_id == node.key_id),
            "list_canonical_servers must include {}",
            node.key_id
        );

        seed_canonical_servers(&backend)
            .await
            .expect("idempotent re-seed");
    }

    /// v13.4.2 (CIRISPersist#394) — the boot-panic regression: the **canonical
    /// node itself** already holds `ciris-canonical-1` as its OWN self-signed
    /// `node` row (it minted the identity). The genesis seed MUST **upgrade**
    /// that row to the 2-of-3 scrubbed canonical (via `adopt_scrub_upgrade`),
    /// not error on it (which `put_public_key` did → boot abort). After the
    /// seed the node self-roots as canonical; re-seed is idempotent.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn canonical_seed_upgrades_the_nodes_own_self_signed_row() {
        use crate::federation::{FederationDirectory, SignedKeyRecord};
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .seed_genesis_accord_holders(accord_holder_genesis_records())
            .await
            .expect("holder seed");
        seed_accord_family(&backend).await.expect("family seed");

        // Pre-seed ciris-canonical-1 as the node's OWN self-signed `node` row —
        // same pubkeys as the baked record, but self-signed and not canonical.
        let baked = &canonical_genesis_bundle().serve_nodes[0].record;
        let mut own = baked.clone();
        own.scrub_key_id = own.key_id.clone(); // self-signed
        own.identity_type = identity_type::NODE.to_owned();
        own.additional_scrubs.clear();
        own.capability_roles.clear();
        // v24.1.0 (CIRISPersist#557) — strip the roles from the SIGNED
        // ENVELOPE too, not just the column. `claims_role` reads BOTH
        // surfaces, and from the quorum-rooted bake the envelope carries
        // `infra:attest` — which `check_infra_attest_role_admission` refuses
        // without accord co-scrub. That refusal is CORRECT and is exactly
        // what this fixture simulates the absence of: a node that registered
        // ITSELF cannot claim an accord-conferred role. Clearing only the
        // column left the envelope claiming it, so the pre-seed was refused
        // by the very gate the seed upgrade exists to satisfy.
        if let Some(obj) = own.registration_envelope.as_object_mut() {
            obj.insert("roles".into(), serde_json::json!([]));
        }
        backend
            .put_public_key(SignedKeyRecord { record: own })
            .await
            .expect("pre-seed the node's own self-signed row");
        assert!(
            !crate::federation::is_canonical(&backend, &baked.key_id)
                .await
                .unwrap(),
            "the self-signed row is NOT canonical yet"
        );

        // The genesis seed must UPGRADE it (not error → boot abort).
        seed_canonical_servers(&backend)
            .await
            .expect("must upgrade the pre-existing self-signed row, not error");
        verify_canonical_seeded(&backend)
            .await
            .expect("canonical live after upgrade");
        assert!(
            crate::federation::is_canonical(&backend, &baked.key_id)
                .await
                .unwrap(),
            "the node self-roots as canonical after the upgrade"
        );

        // Reboot idempotence — a second seed over the now-scrubbed row is a no-op.
        seed_canonical_servers(&backend)
            .await
            .expect("idempotent re-seed over the upgraded row");
    }

    /// v13.7.0 (CIRISPersist#410) — the genesis seed must SUPERSEDE (not fatally
    /// Conflict → boot-brick) when a node already holds a DIFFERENT anchor-scrubbed
    /// record for the canonical key_id — the :4243→:4242 re-bake on an upgraded
    /// fleet node. `adopt_scrub_upgrade` returned a fatal "already anchored to a
    /// different record" here; the fix routes it through the #405 supersede path.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn canonical_seed_supersedes_a_prior_anchor_scrubbed_record() {
        use crate::federation::{FederationDirectory, SignedKeyRecord};
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .seed_genesis_accord_holders(accord_holder_genesis_records())
            .await
            .expect("holder seed");
        seed_accord_family(&backend).await.expect("family seed");

        // Pre-seed a PRIOR anchor-scrubbed row for the canonical key_id: same
        // pubkey as the baked record, scrubbed by A1 (scrub_key_id != key_id),
        // but a `node` row (so put_public_key's canonical gate doesn't re-verify
        // the now-stale scrubs) whose envelope `valid_from` is strictly OLDER
        // than the baked record's — i.e. "the address before the re-bake".
        let baked = &canonical_genesis_bundle().serve_nodes[0].record;
        assert_ne!(baked.scrub_key_id, baked.key_id, "baked is anchor-scrubbed");
        let mut old = baked.clone();
        old.identity_type = identity_type::NODE.to_owned();
        old.additional_scrubs.clear();
        old.capability_roles.clear();
        let mut env = old.registration_envelope.clone();
        // v24.1.0 (CIRISPersist#557) — see the sibling fixture: the SIGNED
        // ENVELOPE'S roles must go too, or this "prior" row still claims the
        // accord-conferred `infra:attest` the quorum-rooted bake introduced.
        env["roles"] = serde_json::json!([]);
        env["valid_from"] = serde_json::json!("2026-06-01T00:00:00+00:00");
        old.registration_envelope = env.clone();
        old.original_content_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            crate::verify::canonical::ceg_produce_canonicalize(&env).expect("canonicalize"),
        ));
        backend
            .put_public_key(SignedKeyRecord { record: old })
            .await
            .expect("pre-seed the prior anchor-scrubbed row");
        assert!(
            !crate::federation::is_canonical(&backend, &baked.key_id)
                .await
                .unwrap(),
            "the prior (node) row is NOT canonical yet"
        );

        // The genesis seed must SUPERSEDE it — not fatal-Conflict → boot brick.
        seed_canonical_servers(&backend)
            .await
            .expect("must supersede the prior anchor-scrubbed row, not brick");
        verify_canonical_seeded(&backend)
            .await
            .expect("canonical live after supersede");
        assert!(
            crate::federation::is_canonical(&backend, &baked.key_id)
                .await
                .unwrap(),
            "canonical conferred after the supersede"
        );
        // The corrected (baked) envelope actually propagated in place.
        let row = FederationDirectory::lookup_public_key(&backend, &baked.key_id)
            .await
            .unwrap()
            .expect("row present");
        assert_eq!(
            row.registration_envelope["valid_from"], baked.registration_envelope["valid_from"],
            "the baked (newer) envelope superseded the prior one"
        );

        // Reboot idempotence — a second seed over the now-baked row is a no-op.
        seed_canonical_servers(&backend)
            .await
            .expect("idempotent re-seed over the superseded row");
    }

    /// v13.3.0 (CIRISPersist#386) — end-to-end on a fresh backend: seed the
    /// holders, then `seed_accord_family` entrenches the keyless family row
    /// (its member seats FK-free now, validated at write-time against the
    /// just-seeded holders), `verify_family_seeded` passes, and `lookup_family`
    /// resolves the `quorum:2/3` row. Re-seeding is idempotent. A family whose
    /// member is NOT a registered key is rejected (the invariant that replaced
    /// the dropped FK).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn seeded_accord_family_resolves_and_is_idempotent() {
        use crate::federation::types::{Family, FamilyMember};
        use crate::federation::FederationDirectory;
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .seed_genesis_accord_holders(accord_holder_genesis_records())
            .await
            .expect("holder seed");
        // Family MUST go after the holders (members validated at write time).
        seed_accord_family(&backend).await.expect("family seed");
        verify_family_seeded(&backend).await.expect("family live");

        let fam = backend
            .lookup_family("humanity-accord")
            .await
            .expect("lookup")
            .expect("family row present on a seeded node");
        assert_eq!(fam.consensus_protocol, "quorum:2/3");
        assert!(fam.consensus_protocol_entrenched);
        assert_eq!(fam.members.len(), 3);

        // Idempotent re-seed (reboot) — no error, no duplicate.
        seed_accord_family(&backend)
            .await
            .expect("idempotent re-seed");

        // The v13.3.0 invariant: a family with an UNREGISTERED member is refused.
        // v21.0.0 (#502 E4) — sign with a dedicated, freshly-registered
        // authority key (NOT A1/B1/C1 — those carry REAL ceremony pubkeys the
        // test's deterministic `sign_envelope` cannot sign for) so the new
        // admission gate passes and the unregistered-MEMBER check fires.
        crate::federation::tier_ingest::test_support::register_hybrid_key(
            &backend,
            "test-fam-authority",
        )
        .await;
        let bad = Family {
            family_key_id: "test-fam".into(),
            family_name: "T".into(),
            members: vec![FamilyMember {
                key_id: "not-a-registered-key".into(),
                joined_at: fam.founded_at,
                role: Some("founder".into()),
            }],
            founded_at: fam.founded_at,
            consensus_protocol: "quorum:1/1".into(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        };
        let err = backend
            .put_family(crate::federation::tier_ingest::test_support::sign_family(
                "test-fam-authority",
                bad,
            ))
            .await
            .expect_err("a family with an unregistered member must be refused");
        assert!(
            format!("{err:?}").contains("not a registered"),
            "expected member-not-registered error, got {err:?}"
        );
    }

    /// Postgres twin of the e2e seed→root test (no pg/sqlite asymmetry).
    /// Skips when `CIRIS_PERSIST_TEST_PG_URL` is unset. Exercises the pg
    /// genesis insert against the V048 `accord_holder_requires_attestation`
    /// CHECK constraint (satisfied by the seeded custody evidence).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_seeded_real_holder_roots_via_root_binding() {
        use crate::federation::rooting::root_binding;
        use crate::store::backend::Backend as _;
        use crate::store::postgres::PostgresBackend;

        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // clean any prior A1/B1/C1 rows so the seed path is exercised fresh.
        // v13.2.0 (CIRISPersist#383): the canonical add-gate tests seed TEST
        // A1/B1/C1 (test hybrid keys) into the shared pg and leave `canonical`
        // rows whose `scrub_key_id` FKs to A1 — so drop those referencing rows
        // in the SAME statement (FK-atomic), else deleting A1/B1/C1 fails and a
        // divergent test-key anchor survives to squat the real seed.
        let client = backend.pool().get().await.unwrap();
        let _ = client
            .execute(
                "DELETE FROM cirislens.federation_keys \
                 WHERE key_id = ANY($1) OR identity_type LIKE '%canonical%'",
                &[&vec!["A1".to_string(), "B1".to_string(), "C1".to_string()]],
            )
            .await;
        backend
            .seed_genesis_accord_holders(accord_holder_genesis_records())
            .await
            .expect("pg genesis seed");
        verify_anchor_seeded(&backend)
            .await
            .expect("pg anchor live");

        let a1 = &accord_holder_genesis_records()[0].record;
        let verdict = root_binding(&backend, &a1.key_id, &a1.pubkey_ed25519_base64).await;
        assert!(
            verdict.is_confirmed(),
            "pg seeded real A1 must root, got {verdict:?}"
        );
    }
}

/// v17.1.0 (CIRISPersist#449) — the test-anchor genesis relaxation, exercised
/// ONLY on a `test-anchor` build (`cargo nextest run --features
/// sqlite,test-anchor`). Env mutation is safe under nextest's
/// process-per-test isolation; each test still cleans up after itself for the
/// in-process `cargo test` runner.
#[cfg(all(test, feature = "test-anchor", feature = "sqlite"))]
mod test_anchor_tests {
    use super::*;
    use crate::store::backend::Backend as _;
    use crate::store::sqlite::SqliteBackend;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    /// Arm the override with a fresh SW test root; returns its pubkey b64.
    fn arm_test_anchor() -> String {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        let pk_b64 = B64.encode(ed.verifying_key().to_bytes());
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var("CIRIS_TEST_TRUST_ROOT", &pk_b64);
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("CIRIS_ENV");
        std::env::remove_var("CIRIS_ENVIRONMENT");
        pk_b64
    }

    fn disarm_test_anchor() {
        std::env::remove_var("CIRIS_TESTING_MODE");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT_PQC");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT_SCRUB");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT_SCRUB_PQC");
        std::env::remove_var("ENVIRONMENT");
    }

    /// The #449 repro, fixed: under the armed override the full genesis-seed
    /// boot path succeeds against the SWAPPED anchor — the SW holder row is
    /// seeded and verified (present == live anchor at n=1), the family's
    /// founder seats follow the test roster, and the unseedable baked 2-of-3
    /// canonical is skipped instead of bricking the boot.
    /// **CIRISPersist#545 — the synthesizer's own output must round-trip
    /// through `put_public_key`.** The v22.0.0 regression: the test-anchor
    /// genesis emits the honest `SoftwareOnly_TEST` custody marker, and the
    /// hardware-attestation policy's serde gate required a non-optional
    /// `platform_attestation` — so persist refused its OWN synthesized accord
    /// holders with `malformed: missing field platform_attestation`, before
    /// any tier logic could honour the marker.
    ///
    /// Nothing here caught it because the genesis tests seed through
    /// `seed_genesis_accord_holders` — a privileged path — while every HOST
    /// feeds the roster to `put_public_key`. A fixture that reaches past the
    /// real gate certifies nothing about it (the AV-77 lesson, again). This
    /// is the "does our own output satisfy our own gate?" property, the #541
    /// preserve-set≡verified-set check in roster form — and it is the test
    /// CIRISServer asked for in #545, verbatim.
    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn synthesized_accord_holders_round_trip_through_put_public_key_545() {
        let _pk = arm_test_anchor();

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let dir: &dyn crate::federation::FederationDirectory = &backend;

        let records = effective_accord_holder_records();
        assert!(
            !records.is_empty(),
            "#545: a live test anchor must synthesize a non-empty roster"
        );
        for rec in records.iter().cloned() {
            let key_id = rec.record.key_id.clone();
            dir.put_public_key(rec).await.unwrap_or_else(|e| {
                panic!(
                    "#545: put_public_key must ADMIT the synthesizer's own \
                     accord holder {key_id}: {e}"
                )
            });
        }
    }

    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn test_anchor_boot_seeds_swapped_roster_sqlite() {
        let pk_b64 = arm_test_anchor();

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed the SW test-root holder");
        seed_family_and_canonical(&backend)
            .await
            .expect("#449: the genesis-seed boot path must succeed in test mode");

        let dir: &dyn crate::federation::FederationDirectory = &backend;
        // The SW holder row is live with the override pubkey.
        let row = dir
            .lookup_public_key("test-accord-holder-0")
            .await
            .unwrap()
            .expect("the synthesized test holder is seeded");
        assert_eq!(row.pubkey_ed25519_base64, pk_b64);
        assert_eq!(
            row.identity_type,
            crate::federation::types::identity_type::ACCORD_HOLDER
        );
        // The baked A1/B1/C1 are NOT seeded (the roster is swapped, not merged).
        let baked_a1 = &accord_holder_genesis_records()[0].record.key_id;
        assert!(dir.lookup_public_key(baked_a1).await.unwrap().is_none());
        // Family seats follow the test roster.
        let fam = dir
            .lookup_family(ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID)
            .await
            .unwrap()
            .expect("family seeded");
        assert_eq!(fam.members.len(), 1);
        assert_eq!(fam.members[0].key_id, "test-accord-holder-0");
        // The baked canonical bake was skipped, not force-inserted.
        assert!(backend.list_canonical_servers().await.unwrap().is_empty());

        disarm_test_anchor();
    }

    /// Without the runtime flag the feature is inert: the effective roster is
    /// the baked trio, byte-identical to a prod build.
    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn test_anchor_inert_without_runtime_flag() {
        disarm_test_anchor();
        let recs = effective_accord_holder_records();
        assert_eq!(recs.len(), 3, "baked A1/B1/C1 when the mode is unarmed");
        assert_eq!(
            recs[0].record.key_id,
            accord_holder_genesis_records()[0].record.key_id
        );
    }

    /// The anti-production tripwire (re-checked through verify's shared gate):
    /// an explicit prod signal defeats the override even with the test flag +
    /// root set — the effective roster stays baked.
    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn test_anchor_prod_tripwire_defeats_override() {
        let _ = arm_test_anchor();
        std::env::set_var("ENVIRONMENT", "production");
        let recs = effective_accord_holder_records();
        assert_eq!(recs.len(), 3, "prod signal must defeat the test override");
        disarm_test_anchor();
    }

    /// v17.2.0 (CIRISPersist#451) — the persist-tier END-TO-END proving the
    /// full harness test model with REAL crypto and ZERO verification
    /// relaxation (per the harness owner's directive):
    ///
    /// 1. arm the override with a SW hybrid root the test holds the private
    ///    halves of, including the #451 PQC pubkey + self-scrub env halves;
    /// 2. a full `Engine` BUILDS in test mode (the #449 repro at Engine
    ///    tier), seeding a PQC-COMPLETE `test-accord-holder-0` carrying the
    ///    harness-supplied REAL self-scrub;
    /// 3. a node record hybrid-scrubbed by the SW root
    ///    (`produce_scrubbed_key_record`, the exact server-tier bless path)
    ///    ADMITS through `register_federation_key` — the always-on
    ///    `HybridPolicy::Strict` verifies both halves against the seeded row;
    /// 4. persist's own `root_binding` CONFIRMS the blessed node, chain
    ///    terminating at `test-accord-holder-0` — pinning the #451 rooting
    ///    contract: WITH the env-supplied self-scrub the terminus verifies
    ///    (without it, persist-side rooting through the placeholder terminus
    ///    does not confirm; verify-side anchor-membership rooting is
    ///    unaffected either way).
    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn test_anchor_e2e_sw_root_blesses_node_and_roots() {
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
        use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};
        use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner};

        // SW root + node hybrid identities — Boxed and built BEFORE any
        // await (multi-KiB ML-DSA signers on 2 MB test stacks).
        let root = Box::new(HybridSigningIdentity::new(
            "test-accord-holder-0",
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let node = Box::new(HybridSigningIdentity::new(
            "test-node-1",
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let root_member = root.directory_member().unwrap();
        let node_member = node.directory_member().unwrap();

        // The HARNESS half of the #451 contract: self-scrub over persist's
        // pinned synthesized envelope (classical + bound PQC, sign_bound).
        //
        // v31.0.0 (CIRISVerify 13.1.0) — through
        // `test_anchor_registration_envelope`, NOT a transcribed literal. This
        // test stood in for CIRISServer's harness by re-writing the envelope by
        // hand, so when 13.1.0 moved the preimage the producer and its own
        // witness moved apart and the terminus stopped rooting. Calling the
        // shared function is what makes this leg a real e2e rather than two
        // copies of a string agreeing with each other.
        let envelope = super::test_anchor_registration_envelope(
            "test-accord-holder-0",
            &root_member.ed25519_public_key_base64,
            root_member.mldsa65_public_key_base64.as_deref(),
        );
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope).unwrap();
        let (scrub_ed, scrub_pqc) = root.sign_bound(&canonical).await.unwrap();

        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var(
            "CIRIS_TEST_TRUST_ROOT",
            &root_member.ed25519_public_key_base64,
        );
        std::env::set_var(
            "CIRIS_TEST_TRUST_ROOT_PQC",
            root_member
                .mldsa65_public_key_base64
                .as_deref()
                .expect("hybrid root has an ML-DSA pubkey"),
        );
        std::env::set_var("CIRIS_TEST_TRUST_ROOT_SCRUB", &scrub_ed);
        std::env::set_var("CIRIS_TEST_TRUST_ROOT_SCRUB_PQC", &scrub_pqc);
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("CIRIS_ENV");
        std::env::remove_var("CIRIS_ENVIRONMENT");

        // (2) A full Engine builds in test mode.
        let signer = std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
            ed25519_dalek::SigningKey::from_bytes(&[0x6Cu8; 32]),
            "test-anchor-e2e-steward".to_string(),
            None,
            None,
        ));
        let engine = crate::engine::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("#451: a test-mode Engine must build");

        // The seeded holder is PQC-complete and carries the REAL self-scrub.
        let dir = engine.federation_directory();
        let row = dir
            .lookup_public_key("test-accord-holder-0")
            .await
            .unwrap()
            .expect("test holder seeded");
        assert_eq!(
            row.pubkey_ml_dsa_65_base64.as_deref(),
            root_member.mldsa65_public_key_base64.as_deref(),
            "#451: seeded row must carry the env-supplied ML-DSA pubkey"
        );
        assert!(row.pqc_completed_at.is_some());
        assert_eq!(row.scrub_signature_classical, scrub_ed);
        assert_eq!(row.scrub_signature_pqc.as_deref(), Some(scrub_pqc.as_str()));

        // (3) Node bless: the SW root hybrid-scrubs a node registration —
        // the exact server-tier path (CIRISServer harness test_bless).
        let verify_rec = produce_scrubbed_key_record(
            root.as_ref(),
            ScrubTarget {
                key_id: "test-node-1".into(),
                pubkey_ed25519_base64: node_member.ed25519_public_key_base64.clone(),
                pubkey_ml_dsa_65_base64: node_member
                    .mldsa65_public_key_base64
                    .clone()
                    .expect("hybrid node has an ML-DSA pubkey"),
                identity_type: crate::federation::types::identity_type::NODE.to_owned(),
                roles: Vec::new(),
            },
            "2026-07-14T00:00:00Z",
            &[],
        )
        .await
        .expect("produce the SW-scrubbed node record");
        // Wire-identical shapes: verify's SignedKeyRecord → persist's.
        let persist_rec: crate::federation::SignedKeyRecord =
            serde_json::from_value(serde_json::to_value(&verify_rec).unwrap())
                .expect("verify→persist SignedKeyRecord wire round-trip");

        // (4) Admitted under the always-on Strict hybrid gate.
        engine
            .register_federation_key(persist_rec)
            .await
            .expect("#451: the SW-root hybrid scrub must admit under Strict");

        // (5) persist-side rooting CONFIRMS through the verifying terminus.
        // Refutable only when the postgres variant is compiled in — the two
        // cfg arms keep clippy clean in BOTH feature configs (irrefutable-let
        // with postgres off, let-else with it on).
        #[cfg(feature = "postgres")]
        let crate::engine::BackendDispatch::Sqlite(sq) = engine.backend() else {
            panic!("sqlite engine expected");
        };
        #[cfg(not(feature = "postgres"))]
        let crate::engine::BackendDispatch::Sqlite(sq) = engine.backend();
        let verdict = crate::federation::rooting::root_binding(
            &**sq,
            "test-node-1",
            &node_member.ed25519_public_key_base64,
        )
        .await;
        assert!(
            verdict.is_confirmed(),
            "#451: the blessed node must root via persist's own root_binding, got {verdict:?}"
        );
        let chain = verdict.chain().unwrap();
        assert!(chain.terminates_at_steward_bootstrap);
        assert_eq!(
            chain.chain.last().unwrap().key_id,
            "test-accord-holder-0",
            "#451: the chain terminates at the SW test root"
        );

        disarm_test_anchor();
    }
}
