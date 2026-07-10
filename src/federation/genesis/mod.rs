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

    let anchor: HashSet<[u8; 32]> =
        ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor()
            .into_iter()
            .collect();
    let mut present: HashSet<[u8; 32]> = HashSet::new();

    for sr in accord_holder_genesis_records() {
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
    let members = accord_holder_genesis_records()
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
    dir.put_family(crate::federation::SignedFamily { family })
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
        use crate::federation::{FederationDirectory, SignedFamily};
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
            .put_family(SignedFamily { family: bad })
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
