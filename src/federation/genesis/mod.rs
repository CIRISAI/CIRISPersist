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

/// The baked **canonical genesis server** record(s) — the A1-scrub-signed
/// `ciris-canonical-1-…` node produced by the operator's Trust Root
/// add-canonical ceremony (CIRISServer#164 / CIRISPersist#380, v13.1.0),
/// embedded verbatim. Its `identity_type` set contains `canonical` and its
/// `scrub_key_id` is `A1`; only the **node** record is baked — the A1
/// holder anchor is already baked in [`ACCORD_HOLDER_SEED_JSON`].
///
/// Byte-fidelity (CIRISPersist#380 Q4): the record is embedded exactly as
/// the ceremony produced it (the scrub signature covers the canonical bytes
/// of `registration_envelope`); it is NOT re-canonicalized here.
const CANONICAL_SEED_JSON: &str = include_str!("canonical_seed.json");

/// Parse-once accessor for the baked canonical genesis server record(s).
///
/// # Panics
///
/// Panics if the embedded JSON is malformed — a build-time-checked constant
/// (caught by [`tests::canonical_seed_parses_and_is_accord_conferred`]).
pub fn canonical_genesis_records() -> &'static [SignedKeyRecord] {
    use std::sync::OnceLock;
    static PARSED: OnceLock<Vec<SignedKeyRecord>> = OnceLock::new();
    PARSED.get_or_init(|| {
        serde_json::from_str(CANONICAL_SEED_JSON)
            .expect("embedded canonical_seed.json must be valid [SignedKeyRecord]")
    })
}

/// First-boot-seed the baked canonical genesis server record(s)
/// (CIRISPersist#380). Generic over [`FederationDirectory`] so it stays
/// **pg/sqlite-symmetric** — there is no backend-specific seed method.
///
/// Unlike [`SqliteBackend::seed_genesis_accord_holders`](crate::store::sqlite::SqliteBackend::seed_genesis_accord_holders)
/// (a raw genesis-trusted insert of the *rooting anchor* rows), the canonical
/// record is admitted **through the ordinary
/// [`check_canonical_role_admission`](crate::federation::admission::check_canonical_role_admission)
/// gate** that runs inside [`FederationDirectory::put_public_key`] — the gate
/// this substrate enforces on every write path. That is the point: the baked
/// record proves itself *accord-conferred* (A1 ∈ the pinned anchor, resolved
/// live from the just-seeded holder rows), rather than being force-inserted.
/// It MUST therefore run **after** [`accord_holder_genesis_records`] are
/// seeded (so `A1` resolves).
///
/// Idempotent: a byte-identical row already present is a `put_public_key`
/// no-op. A `key_id` collision with *different* content (a squatter) surfaces
/// as an `Err` the caller raises as a genesis-seed fault (fail-secure).
pub async fn seed_canonical_servers<D>(dir: &D) -> Result<(), String>
where
    D: super::FederationDirectory + ?Sized,
{
    for sr in canonical_genesis_records() {
        dir.put_public_key(sr.clone()).await.map_err(|e| {
            format!(
                "seed canonical server {}: {e} (is A1 seeded + in anchor?)",
                sr.record.key_id
            )
        })?;
    }
    Ok(())
}

/// Fail-secure presence check (CIRISPersist#380): every baked canonical
/// record is live in `federation_keys` with its `identity_type` set still
/// carrying `canonical` and matching pubkey (no squatter). Run at boot right
/// after [`seed_canonical_servers`]; `Err` is surfaced as
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

    /// v13.1.0 (CIRISPersist#380) — the baked canonical seed parses, carries
    /// the `canonical` role, is A1-scrub-conferred (NOT self-signed), and its
    /// scrubber A1's pubkey equals the baked accord anchor (so the canonical
    /// admission gate will resolve + admit it live).
    #[test]
    fn canonical_seed_parses_and_is_accord_conferred() {
        let recs = canonical_genesis_records();
        assert!(!recs.is_empty(), "at least the founding canonical server");
        let a1 = &accord_holder_genesis_records()[0].record;
        assert_eq!(a1.key_id, "A1");
        for sr in recs {
            let r = &sr.record;
            assert!(
                identity_type::set_contains(&r.identity_type, identity_type::CANONICAL),
                "{} must carry the `canonical` role, got {:?}",
                r.key_id,
                r.identity_type
            );
            assert_ne!(
                r.scrub_key_id, r.key_id,
                "{} must be accord-conferred, not self-signed",
                r.key_id
            );
            assert_eq!(
                r.scrub_key_id, "A1",
                "{} is scrub-signed by the A1 accord holder",
                r.key_id
            );
        }
    }

    /// v13.1.0 (CIRISPersist#380) — end-to-end on a fresh backend: seed the
    /// accord holders, then the canonical server admits **through the
    /// canonical gate** (A1 resolved live), `verify_canonical_seeded` passes,
    /// and `is_canonical` / `list_canonical_servers` report it — exactly what
    /// a fresh node ships with. Re-seeding is idempotent.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn seeded_canonical_server_is_admitted_and_listed() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .seed_genesis_accord_holders(accord_holder_genesis_records())
            .await
            .expect("accord seed");
        // Canonical seed must go AFTER accord (gate resolves A1 live).
        seed_canonical_servers(&backend)
            .await
            .expect("canonical seed");
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

        // Idempotent re-seed (reboot) — no error, no duplication.
        seed_canonical_servers(&backend)
            .await
            .expect("idempotent re-seed");
        assert_eq!(
            backend.list_canonical_servers().await.expect("list2").len(),
            listed.len(),
            "re-seed must not duplicate"
        );
    }

    /// v13.1.0 (CIRISPersist#380) — canonical seed BEFORE the accord holders
    /// fails closed: with A1 absent, the canonical admission gate refuses to
    /// confer the role (the ordering invariant the boot path guarantees).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn canonical_seed_without_accord_anchor_fails_closed() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // No accord holders seeded → A1 absent → gate must refuse.
        let err = seed_canonical_servers(&backend)
            .await
            .expect_err("must fail closed without A1");
        assert!(
            err.contains("canonical server"),
            "fail-closed seed error, got: {err}"
        );
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
        let client = backend.pool().get().await.unwrap();
        let _ = client
            .execute(
                "DELETE FROM cirislens.federation_keys WHERE key_id = ANY($1)",
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
