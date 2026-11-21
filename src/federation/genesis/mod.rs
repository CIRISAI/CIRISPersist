//! v62.0.0 (json-cut, slice C5-fix1; CIRISPersist ceremony gap 1) — **what
//! is left of the earlier genesis module: the posture, and nothing that gives
//! standing.**
//!
//! v62.0.0 (GB-fix1): a v62.0 build BAKES the real `ceg-genesis-bundle/2`
//! (HUMANITY_ACCORD v1, bundle `cb9ada31…deb5`, minted 2026-11-21) in
//! [`edition2::genesis::BAKED_BUNDLES`](super::edition2::genesis::BAKED_BUNDLES),
//! and a store holding no bundle imports it at open THROUGH THE IMPORT DOOR
//! ([`edition2::genesis::import_baked_genesis`](super::edition2::genesis::import_baked_genesis)),
//! like any other bundle; importing is not accepting (a node roots nothing
//! until it, or its owner, accepts the root). Nothing below is a second path.
//!
//! The earlier production genesis is gone: the baked `ceg-genesis-bundle/1`
//! (`canonical_seed.json`, the v4 amend), the baked A1/B1/C1 accord-holder
//! records (`accord_holder_seed.json`), the boot seeds that installed them, the
//! pinned-row exemptions and the id-squat reserve over the baked ids, the
//! purge door for baked delegation rows, and the test-anchor holder block are
//! all deleted. The ONLY genesis is the one ingested at the import door
//! ([`edition2::genesis::put_genesis_bundle`](super::edition2::genesis::put_genesis_bundle)),
//! read back through
//! [`edition2::genesis::genesis_in_force`](super::edition2::genesis::genesis_in_force):
//! its holders are the accord roster
//! ([`admission::accord_holder_roster`](super::admission::accord_holder_roster)),
//! its seats are the canonical standing. A node that holds none has no
//! canonical, no holders and no seats, and every gate that asks fails closed.

/// The genesis posture (C1: re-derived from the bundles in force).
pub mod posture;
pub use posture::{
    constitutional_seat, genesis_posture, require_constitutional_root, GenesisFault, GenesisLeg,
    GenesisPosture, ROOT_REQUIRING_GATES,
};

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

/// The fixed founding instant of a test-built accord family (deterministic
/// `persist_row_hash` across backends).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
const ACCORD_FAMILY_FOUNDED_AT: &str = "2026-05-01T00:00:00Z";

/// A HUMANITY_ACCORD-shaped family record over a given founder set — a test
/// builder (v62.0.0, C5-fix1: the baked accord family it once seeded is
/// deleted). A genesis version names no predecessor.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) fn accord_family_genesis_record_for<'a>(
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
