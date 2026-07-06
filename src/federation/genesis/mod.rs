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

// v13.2.0 (CIRISPersist#383) — the 1-of-N canonical genesis seed (#380,
// `ciris-canonical-1-d7bdeu223k` scrubbed by A1 ALONE) was REMOVED here
// (`CANONICAL_SEED_JSON` / `canonical_genesis_records` / `seed_canonical_servers`
// / `verify_canonical_seeded`). A single-anchor founding record is a
// first-strike weakness: with canonical ADD now a 2-of-3 accord co-scrub
// (`check_canonical_role_admission`), a 1-of-N baked genesis would be a
// permanent grandfathered exception. A fresh node therefore ships with an
// EMPTY canonical set until the operator bakes the 2-of-3 replacement. The
// accord-holder rooting anchor (A1/B1/C1) above is untouched.

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
