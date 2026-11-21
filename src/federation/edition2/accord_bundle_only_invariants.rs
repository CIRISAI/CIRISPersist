//! v62.0.0 (RL-fix7; CC 2.6.1.11, CC 4.2.6, CC 3.4.7 as corrected at
//! `13829f5`) — **the accord's facts are the genesis bundle in force, and no
//! row.** Its roster (holders), its parameters (charter), its seats and a
//! holder's recovery live only in the bundle; a row that would carry one is
//! refused BY NAME at the door, by its bytes, before anything is kept, the
//! same on a rooted node (`install_v2`) and a rootless one. Each body runs on
//! sqlite and postgres, rootless and rooted.
//!
//! - **I2350** a `trust:charter:v1` naming the accord is refused
//!   `accord_charter_is_the_bundle`: at the charter gate
//!   (`trust_root::check_family_charter_admission`) and through the
//!   statement door (`ingest::put_statement`), with nothing kept (no typed
//!   row, no fold hold) — whoever signs it.
//! - **I2351** a `group:roster` version of the accord's family (a founding,
//!   a roster change or a recovery as a roster version: one door, one name)
//!   is refused `accord_version_is_a_bundle` at the group door, before its
//!   count, with nothing kept and no family row written.
//! - **I2352** a KEYED root's own self-charter `delegates_to(root → root)` is
//!   not the accord's charter row: the gate passes it, unchanged.
//! - **I2353** the refusals are the same with and without a root: the two
//!   runners of each backend (rootless, then `install_v2`) assert the same
//!   names.

use super::fixture_switch as e2;
use super::ingest::StatementOutcome;
use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
use crate::federation::{malformed_row, Attestation, Error, FederationDirectory};

const ACCORD: &str = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;

/// A `delegates_to(attesting → attested)` row labelled `trust:charter:v1`,
/// well-formed by its own bytes (scope and pre-rotation commitment).
fn charter_row(attesting: &str, attested: &str, id: &str) -> Attestation {
    let ts = crate::host::clock::now();
    Attestation {
        attestation_id: id.to_owned(),
        attesting_key_id: attesting.to_owned(),
        attested_key_id: attested.to_owned(),
        attestation_type: attestation_type::DELEGATES_TO.to_owned(),
        weight: None,
        asserted_at: ts,
        expires_at: None,
        attestation_envelope: serde_json::json!({
            "id": id,
            "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
            "scope": [
                crate::federation::trust_root::INFRA_SERVE_SCOPE,
                crate::federation::trust_root::INFRA_ATTEST_SCOPE,
            ],
            crate::federation::envelope::paths::PRE_ROTATION_COMMITMENT: "ab".repeat(32),
        }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: attesting.to_owned(),
        scrub_timestamp: ts,
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

/// `out` is the refusal `token`, by name.
fn refused_by<T: std::fmt::Debug>(out: Result<T, Error>, token: &str, what: &str) {
    match out {
        Err(Error::MalformedRow { reason, .. }) => {
            assert_eq!(reason, token, "{what}: refused by name");
        }
        other => panic!("{what}: refused `{token}` by name, got {other:?}"),
    }
}

/// I2350–I2353 on one directory. `rooted`: the ceremony's bundle is
/// installed first (`install_v2`); else the node is rootless.
pub(crate) async fn accord_rows_are_refused(d: &dyn FederationDirectory, rooted: bool, tag: &str) {
    if rooted {
        super::fixture_genesis::install_v2(d)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the ceremony installs: {e}"));
    }
    assert_eq!(
        super::genesis::genesis_in_force(d)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the genesis reads: {e}"))
            .is_held(),
        rooted,
        "[{tag}] the node is {} as set up",
        if rooted { "rooted" } else { "rootless" }
    );

    // ── I2350 — a charter naming the accord, at the gate ──
    let seed = "rl7-accord-charter-signer";
    let signer = e2::put_key(d, seed, &["user"]).await;
    let by_gate = charter_row(&signer, ACCORD, &format!("rl7-charter-{tag}"));
    refused_by(
        crate::federation::trust_root::check_family_charter_admission(d, &by_gate).await,
        malformed_row::ACCORD_CHARTER_IS_THE_BUNDLE,
        &format!("[{tag}] I2350: the charter gate"),
    );
    // … and through the statement door, nothing kept.
    let row = e2::row_of(&by_gate, seed);
    let id = super::voices::carried_row_id(&row)
        .unwrap_or_else(|| panic!("[{tag}] I2350: the row carries its statement"));
    refused_by(
        e2::put_signed(d, &row).await,
        malformed_row::ACCORD_CHARTER_IS_THE_BUNDLE,
        &format!("[{tag}] I2350: the statement door"),
    );
    assert!(
        d.get_attestation(&id.hex())
            .await
            .unwrap_or_else(|e| panic!("[{tag}] get_attestation reads: {e}"))
            .is_none(),
        "[{tag}] I2350: no typed row is kept"
    );
    assert!(
        super::fold::why_held(d, &id)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] why_held reads: {e}"))
            .is_none(),
        "[{tag}] I2350: nothing is held (refused, not waiting)"
    );

    // ── I2351 — a roster version of the accord's family ──
    let member = "rl7-accord-version-signer";
    let member_kid = e2::put_key(d, member, &["user"]).await;
    let at = e2::ms(crate::host::clock::now()) + 1_000;
    let family: crate::federation::types::Family = serde_json::from_value(serde_json::json!({
        "family_key_id": ACCORD,
        "family_name": "rl7 rival accord",
        "members": [{ "key_id": member_kid, "joined_at": "2026-11-18T00:00:00Z" }],
        "founded_at": "2026-11-18T00:00:00Z",
        "consensus_protocol": "quorum:1/1",
        "persist_row_hash": "",
    }))
    .unwrap_or_else(|e| panic!("[{tag}] I2351: a family record: {e}"));
    let key = e2::signing_key(member);
    let voices = super::group_fixtures::roster_voices(
        &super::group::GroupRecord::Family(family),
        1,
        None,
        at,
        &[&key],
    );
    let version = super::group_fixtures::row_id_of(&voices[0]);
    let out: Result<StatementOutcome, Error> =
        Box::pin(super::group_fixtures::put_voices(d, &voices)).await;
    refused_by(
        out,
        malformed_row::ACCORD_VERSION_IS_A_BUNDLE,
        &format!("[{tag}] I2351: the group door"),
    );
    assert!(
        super::fold::why_held(d, &version)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] why_held reads: {e}"))
            .is_none(),
        "[{tag}] I2351: the version is not kept (no count, no hold)"
    );
    assert!(
        d.lookup_family(ACCORD)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] lookup_family reads: {e}"))
            .is_none(),
        "[{tag}] I2351: no family row is written for the accord"
    );

    // ── I2352 — a keyed root's own self-charter is not the accord's row ──
    let root = e2::put_key(d, "rl7-keyed-root", &["user"]).await;
    crate::federation::trust_root::check_family_charter_admission(
        d,
        &charter_row(&root, &root, &format!("rl7-self-{tag}")),
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] I2352: a keyed self-charter passes the gate: {e}"));
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::accord_rows_are_refused;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    /// I2350–I2352 on a rootless node (I2353: the same names as rooted).
    #[tokio::test]
    async fn i2350_accord_rows_are_refused_rootless_sqlite() {
        let d = fresh().await;
        Box::pin(accord_rows_are_refused(&d, false, "sqlite rootless")).await;
    }

    /// I2350–I2352 on a rooted node (I2353).
    #[tokio::test]
    async fn i2353_accord_rows_are_refused_rooted_sqlite() {
        let d = fresh().await;
        Box::pin(accord_rows_are_refused(&d, true, "sqlite rooted")).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::accord_rows_are_refused;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i2350_accord_rows_are_refused_rootless_postgres() {
        let Some(d) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(accord_rows_are_refused(&d, false, "postgres rootless")).await;
    }

    #[tokio::test]
    async fn i2353_accord_rows_are_refused_rooted_postgres() {
        let Some(d) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(accord_rows_are_refused(&d, true, "postgres rooted")).await;
    }
}
