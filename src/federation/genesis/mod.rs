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
    bake_assembled_genesis, verify_bundle_quorum, BakeItemOutcome, GenesisAuthorization,
    GenesisBakeReport, GenesisBundle,
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
///   pinned: classical = Ed25519 over
///   `JCS({"key_id":"test-accord-holder-{i}","test_anchor":true})` (the
///   exact envelope synthesized here); PQC = the bound hybrid form
///   (`SelfSigner::sign_bound` over the same canonical bytes). When present
///   the seeded terminus is a fully scrub-VERIFYING rooting root — persist's
///   own `root_binding` Confirms a chain terminating here (its
///   `Ed25519Fallback` link policy verifies classical-only or full-hybrid).
///   When absent: a non-verifying placeholder — the seed + presence checks +
///   verify-side anchor-membership rooting still work, but persist-side
///   `root_binding` will NOT confirm through this terminus (the pinned
///   contract the #451 e2e documents).
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
        let envelope = serde_json::json!({ "key_id": key_id, "test_anchor": true });
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
            .expect("canonicalize test-anchor envelope");
        // #451 — optional PQC pubkey + real self-scrub signatures (see the
        // doc contract above). The PQC scrub only rides alongside a
        // classical one (it is the BOUND half of a hybrid pair).
        let pqc_pubkey = env_slot("CIRIS_TEST_TRUST_ROOT_PQC", i);
        let scrub_ed = env_slot("CIRIS_TEST_TRUST_ROOT_SCRUB", i);
        let scrub_pqc = scrub_ed
            .as_ref()
            .and_then(|_| env_slot("CIRIS_TEST_TRUST_ROOT_SCRUB_PQC", i));
        out.push(SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: key_id.clone(),
                pubkey_ed25519_base64: B64.encode(ed),
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
                roles: Vec::new(),
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
fn test_anchor_override_active() -> bool {
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
/// squatting a holder `key_id`). Run at boot right after the seed; `Err` is a
/// constitutional-safety fault the caller surfaces as
/// [`EngineError::GenesisSeed`](crate::engine::EngineError::GenesisSeed).
pub async fn verify_anchor_seeded<D>(dir: &D) -> Result<(), String>
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

    let records = effective_accord_holder_records();
    for sr in records.iter() {
        let r = &sr.record;
        let row = dir
            .lookup_public_key(&r.key_id)
            .await
            .map_err(|e| format!("lookup {}: {e}", r.key_id))?
            .ok_or_else(|| format!("accord holder {} not seeded", r.key_id))?;
        // A conflicting pre-existing row (same key_id, different pubkey) must
        // fail — `ON CONFLICT DO NOTHING` would have skipped our insert.
        if row.pubkey_ed25519_base64 != r.pubkey_ed25519_base64 {
            return Err(format!(
                "accord holder {} present with a divergent pubkey (anchor squatting)",
                r.key_id
            ));
        }
        let ed: [u8; 32] = B64
            .decode(&row.pubkey_ed25519_base64)
            .map_err(|e| format!("{} pubkey b64: {e}", r.key_id))?
            .try_into()
            .map_err(|_| format!("{} pubkey not 32 bytes", r.key_id))?;
        if !anchor.contains(&ed) {
            return Err(format!(
                "seeded holder {} is not a pinned anchor key",
                r.key_id
            ));
        }
        present.insert(ed);
    }
    if present != anchor {
        return Err(format!(
            "seeded anchor set (n={}) does not equal accord_holder_bootstrap_anchor() (n={})",
            present.len(),
            anchor.len()
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
pub async fn seed_accord_family<D>(dir: &D) -> Result<(), String>
where
    D: super::FederationDirectory + ?Sized,
{
    let family = accord_family_genesis_record();
    if dir
        .lookup_family(&family.family_key_id)
        .await
        .map_err(|e| format!("lookup_family: {e}"))?
        .is_some()
    {
        return Ok(()); // already entrenched (reboot) — idempotent no-op.
    }
    // v21.0.0 (CIRISPersist#502 E4) — `put_family` now hybrid-Strict-verifies
    // an authority signature; the baked HUMANITY_ACCORD family is a
    // bake-what-exists declaration with no private key to sign with
    // (`family_key_id` is keyless by design, see `put_family_local`'s doc).
    // Use the trusted-local bypass, exactly as this boot path always has.
    dir.put_family_local(family)
        .await
        .map_err(|e| format!("seed accord family: {e} (are A1/B1/C1 seeded first?)"))
}

/// Fail-secure presence check (CIRISPersist#386): the baked HUMANITY_ACCORD
/// family row is live with its entrenched `quorum:2/3` protocol and the full
/// A1/B1/C1 founder seat set. Run at boot right after [`seed_accord_family`];
/// `Err` is surfaced as
/// [`EngineError::GenesisSeed`](crate::engine::EngineError::GenesisSeed).
pub async fn verify_family_seeded<D>(dir: &D) -> Result<(), String>
where
    D: super::FederationDirectory + ?Sized,
{
    let expected = accord_family_genesis_record();
    let row = dir
        .lookup_family(&expected.family_key_id)
        .await
        .map_err(|e| format!("lookup_family: {e}"))?
        .ok_or_else(|| format!("accord family {} not seeded", expected.family_key_id))?;
    if row.consensus_protocol != expected.consensus_protocol || !row.consensus_protocol_entrenched {
        return Err(format!(
            "seeded accord family {} has non-entrenched / divergent protocol (got {:?}, entrenched={})",
            expected.family_key_id, row.consensus_protocol, row.consensus_protocol_entrenched
        ));
    }
    let seats: std::collections::BTreeSet<&str> =
        row.members.iter().map(|m| m.key_id.as_str()).collect();
    let want: std::collections::BTreeSet<&str> =
        expected.members.iter().map(|m| m.key_id.as_str()).collect();
    if seats != want {
        return Err(format!(
            "seeded accord family {} seats {seats:?} != the founder set {want:?}",
            expected.family_key_id
        ));
    }
    Ok(())
}

/// The baked **canonical genesis server** record — the operator's
/// `ciris-canonical-1-d7bdeu223k` node, now **2-of-3 accord-co-scrubbed** (A1
/// primary + B1 in `additional_scrubs`, over a byte-identical envelope)
/// (CIRISPersist#390, v13.4.0). This REPLACES the 1-of-N record #383 removed:
/// with canonical ADD requiring a 2-of-3 accord co-scrub, a single-anchor
/// founding record was a first-strike weakness. Bake-what-was-conferred (live
/// YubiKey scrub sigs), the same trust model as [`accord_holder_genesis_records`]
/// — NOT a constant-derived artifact.
const CANONICAL_SEED_JSON: &str = include_str!("canonical_seed.json");

/// Parse-once accessor for the baked 2-of-3 canonical genesis record(s).
///
/// # Panics
///
/// Panics if the embedded JSON is malformed (build-time-checked constant;
/// caught by [`tests::canonical_seed_parses_and_is_2of3_accord_conferred`]).
pub fn canonical_genesis_records() -> &'static [SignedKeyRecord] {
    use std::sync::OnceLock;
    static PARSED: OnceLock<Vec<SignedKeyRecord>> = OnceLock::new();
    PARSED.get_or_init(|| {
        serde_json::from_str(CANONICAL_SEED_JSON)
            .expect("embedded canonical_seed.json must be valid [SignedKeyRecord]")
    })
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
pub async fn seed_canonical_servers<D>(dir: &D) -> Result<(), String>
where
    D: super::FederationDirectory + ?Sized,
{
    for sr in canonical_genesis_records() {
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
            .map_err(|e| format!("lookup canonical {kid}: {e}"))?;
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
                    Ok(O::Refused) => {
                        tracing::warn!(
                            key_id = %kid,
                            "genesis canonical seed: baked record REFUSED over the existing \
                             anchor-scrubbed row (existing is same-or-newer) — skipping"
                        );
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        };
        res.map_err(|e| {
            format!("seed canonical server {kid}: {e} (are A1/B1 holders + accord family seeded first?)")
        })?;
    }
    Ok(())
}

/// Fail-secure presence check (CIRISPersist#390): every baked canonical record
/// is live with matching pubkey and the `canonical` role still conferred. Run
/// at boot right after [`seed_canonical_servers`]; `Err` surfaces as
/// [`EngineError::GenesisSeed`](crate::engine::EngineError::GenesisSeed).
pub async fn verify_canonical_seeded<D>(dir: &D) -> Result<(), String>
where
    D: super::FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type;
    for sr in canonical_genesis_records() {
        let r = &sr.record;
        let row = dir
            .lookup_public_key(&r.key_id)
            .await
            .map_err(|e| format!("lookup {}: {e}", r.key_id))?
            .ok_or_else(|| format!("canonical server {} not seeded", r.key_id))?;
        if row.pubkey_ed25519_base64 != r.pubkey_ed25519_base64 {
            return Err(format!(
                "canonical server {} present with a divergent pubkey (squatting)",
                r.key_id
            ));
        }
        if !identity_type::set_contains(&row.identity_type, identity_type::CANONICAL) {
            return Err(format!(
                "seeded canonical server {} lost its `canonical` role (identity_type={:?})",
                r.key_id, row.identity_type
            ));
        }
    }
    Ok(())
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
pub async fn seed_family_and_canonical<D>(dir: &D) -> Result<(), String>
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
    Ok(())
}

#[cfg(test)]
mod tests {
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

    /// v13.4.0 (CIRISPersist#390) — the baked canonical seed parses, is
    /// `canonical`, and is **2-of-3 accord-conferred**: primary scrub A1 + a
    /// distinct additional anchor scrub (B1), ≥2 distinct scrubbers.
    #[test]
    fn canonical_seed_parses_and_is_2of3_accord_conferred() {
        let recs = canonical_genesis_records();
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

        let node = &canonical_genesis_records()[0].record;
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
        let baked = &canonical_genesis_records()[0].record;
        let mut own = baked.clone();
        own.scrub_key_id = own.key_id.clone(); // self-signed
        own.identity_type = identity_type::NODE.to_owned();
        own.additional_scrubs.clear();
        own.roles.clear();
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
        let baked = &canonical_genesis_records()[0].record;
        assert_ne!(baked.scrub_key_id, baked.key_id, "baked is anchor-scrubbed");
        let mut old = baked.clone();
        old.identity_type = identity_type::NODE.to_owned();
        old.additional_scrubs.clear();
        old.roles.clear();
        let mut env = old.registration_envelope.clone();
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

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
        let envelope = serde_json::json!({ "key_id": "test-accord-holder-0", "test_anchor": true });
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
        let crate::engine::BackendDispatch::Sqlite(sq) = engine.backend() else {
            panic!("sqlite engine expected");
        };
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
