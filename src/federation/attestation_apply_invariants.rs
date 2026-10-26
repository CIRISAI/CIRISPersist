//! v60.0.0 — `apply_planned`'s read-back and store-error arms, witnessed in
//! the lib on both SQL backends, so the observe-sites mutation scope (which
//! builds `--lib` and runs only its own named witnesses) reaches them. The
//! sqlite-only unit tests in `attestation_apply.rs` assert the same outcomes,
//! but outside the scope's filter, and none of them counts the read-back.
//!
//! - **I1340** — the §6.1 read-back (`get_attestation` after the write) runs
//!   only for a structural composer that carries a references target, and
//!   only on the planned path: a fresh row and a non-composer row carrying a
//!   `references_attestation_id` are read by the plan and the write door and
//!   nothing else, a plan-free fresh row inserts without asking the store
//!   what it did, and a composer replay is read back and named
//!   `Deduplicated`. Each `&&` of the predicate and of the
//!   read-back guard turned into `||` reads a row it must not.
//! - **I1341** — the write's error arm: a duplicate id the plan could not
//!   see is the typed `StoreConflict` refusal, and any other write error
//!   (an unregistered author) propagates as an error, never that refusal.

use crate::federation::attestation_apply::{
    AttestationRefusalReason, ReplicatedAttestationOutcome,
};
use crate::federation::directory_double::FaultInjectingDirectory;
use crate::federation::types::{attestation_tier, attestation_type};
use crate::federation::{read_probe, Attestation, FederationDirectory, SignedAttestation};
use std::sync::Arc;

/// A sealed federation-tier row of `attestation_type` by `author`, carrying
/// `extra` in its envelope.
fn sealed(id: &str, author: &str, ty: &str, extra: serde_json::Value) -> Attestation {
    let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture instant")
        .with_timezone(&chrono::Utc);
    let mut envelope = serde_json::json!({
        "dimension": "identity_binding:v1",
        "score": 1.0,
        "confidence": 0.9,
    });
    if let (Some(obj), Some(more)) = (envelope.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            obj.insert(k.clone(), v.clone());
        }
    }
    let mut row = Attestation {
        attestation_id: id.to_owned(),
        attesting_key_id: author.to_owned(),
        attested_key_id: author.to_owned(),
        attestation_type: ty.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: author.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    crate::federation::tier_ingest::test_support::seal_row_in_place(author, &mut row);
    row
}

fn fresh_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn scores(author: &str, extra: serde_json::Value) -> Attestation {
    sealed(&fresh_id(), author, attestation_type::SCORES, extra)
}

fn withdraws(id: &str, author: &str, target: &str) -> Attestation {
    sealed(
        id,
        author,
        attestation_type::WITHDRAWS,
        serde_json::json!({
            crate::federation::envelope::paths::REFERENCES_ATTESTATION_ID: target,
        }),
    )
}

/// Apply `row` through `dir`; the outcome and how many times the apply read
/// the row's own id back (`get_attestation`, the read probe).
async fn apply_counting(
    dir: &dyn FederationDirectory,
    row: Attestation,
) -> (ReplicatedAttestationOutcome, usize) {
    let id = row.attestation_id.clone();
    let _ = read_probe::take();
    let outcome = dir
        .apply_replicated_attestation(SignedAttestation { attestation: row })
        .await
        .expect("apply");
    let reads = read_probe::take()
        .iter()
        .filter(|r| r.is(crate::observe::Door::GetAttestation.label(), &id))
        .count();
    (outcome, reads)
}

/// How many times the write door itself reads a fresh row's own id while it
/// stores it (a backend's own business: sqlite and postgres differ).
async fn write_door_reads(dir: &dyn FederationDirectory, row: Attestation) -> usize {
    let id = row.attestation_id.clone();
    let _ = read_probe::take();
    dir.put_attestation(SignedAttestation { attestation: row })
        .await
        .expect("I1340 baseline put");
    read_probe::take()
        .iter()
        .filter(|r| r.is(crate::observe::Door::GetAttestation.label(), &id))
        .count()
}

async fn i1340(dir: Arc<dyn FederationDirectory>, tag: &str) {
    let author = format!("i1340-author-{tag}");
    crate::federation::tier_ingest::test_support::register_hybrid_key(&*dir, &author).await;
    // The plan's one read on top of the write door's own.
    let planned = 1 + write_door_reads(&*dir, scores(&author, serde_json::json!({}))).await;

    // A fresh non-composer row: no read-back.
    let (outcome, reads) = apply_counting(&*dir, scores(&author, serde_json::json!({}))).await;
    assert_eq!(
        outcome,
        ReplicatedAttestationOutcome::Inserted,
        "{tag} I1340 fresh"
    );
    assert_eq!(
        reads, planned,
        "{tag} I1340 a fresh non-composer row is read by the plan and the write door only"
    );

    // A non-composer row carrying a references target: still no read-back
    // (the predicate needs BOTH the composer type and the target).
    let target = scores(&author, serde_json::json!({}));
    let target_id = target.attestation_id.clone();
    dir.apply_replicated_attestation(SignedAttestation {
        attestation: target,
    })
    .await
    .expect("target");
    let referencing = scores(
        &author,
        serde_json::json!({
            crate::federation::envelope::paths::REFERENCES_ATTESTATION_ID: target_id,
        }),
    );
    let (outcome, reads) = apply_counting(&*dir, referencing).await;
    assert_eq!(
        outcome,
        ReplicatedAttestationOutcome::Inserted,
        "{tag} I1340 referencing"
    );
    assert_eq!(
        reads, planned,
        "{tag} I1340 a non-composer row with a references target is not read back"
    );

    // The control: a composer replay IS read back — `Deduplicated` is the
    // read-back's own verdict, so the outcome is the proof it ran.
    let (outcome, _) = apply_counting(&*dir, withdraws(&fresh_id(), &author, &target_id)).await;
    assert_eq!(
        outcome,
        ReplicatedAttestationOutcome::Inserted,
        "{tag} I1340 first withdraws"
    );
    let replay_id = fresh_id();
    let (outcome, _) = apply_counting(&*dir, withdraws(&replay_id, &author, &target_id)).await;
    assert_eq!(
        outcome,
        ReplicatedAttestationOutcome::Deduplicated,
        "{tag} I1340 the composer replay"
    );
    assert!(
        dir.get_attestation(&replay_id)
            .await
            .expect("get")
            .is_none(),
        "{tag} I1340 Deduplicated wrote nothing"
    );

    // Plan-free (this directory cannot answer `get_attestation`): no
    // read-back is attempted, so a fresh row inserts.
    let planless = FaultInjectingDirectory::new(dir.clone()).unsupported("get_attestation");
    assert_eq!(
        planless
            .apply_replicated_attestation(SignedAttestation {
                attestation: scores(&author, serde_json::json!({})),
            })
            .await
            .expect("I1340 a plan-free apply never asks the store what it did"),
        ReplicatedAttestationOutcome::Inserted,
        "{tag} I1340 plan-free fresh"
    );
}

async fn i1341(dir: Arc<dyn FederationDirectory>, tag: &str) {
    let author = format!("i1341-author-{tag}");
    crate::federation::tier_ingest::test_support::register_hybrid_key(&*dir, &author).await;

    // A duplicate id the plan could not see: the typed store conflict.
    let id = fresh_id();
    let first = sealed(
        &id,
        &author,
        attestation_type::SCORES,
        serde_json::json!({}),
    );
    dir.apply_replicated_attestation(SignedAttestation { attestation: first })
        .await
        .expect("first");
    let rival = sealed(
        &id,
        &author,
        attestation_type::SCORES,
        serde_json::json!({"note": "i1341 rival mint"}),
    );
    let planless = FaultInjectingDirectory::new(dir.clone()).unsupported("get_attestation");
    assert_eq!(
        planless
            .apply_replicated_attestation(SignedAttestation { attestation: rival })
            .await
            .expect("I1341 a store conflict is an outcome"),
        ReplicatedAttestationOutcome::Refused {
            reason: AttestationRefusalReason::StoreConflict
        },
        "{tag} I1341 duplicate id"
    );

    // Any other write error is an error, not that refusal: a row by an
    // author this node holds no key for.
    let stranger = format!("i1341-unregistered-{tag}");
    let unknown = sealed(
        &fresh_id(),
        &stranger,
        attestation_type::SCORES,
        serde_json::json!({}),
    );
    let e = dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: unknown,
        })
        .await
        .expect_err("I1341 a write the door refuses propagates");
    assert!(
        !e.is_duplicate_key(),
        "{tag} I1341 the fixture's error is not a duplicate key: {e}"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;

    fn dir() -> Arc<dyn FederationDirectory> {
        Arc::new(crate::store::test_backend::test_backend())
    }

    #[tokio::test]
    async fn i1340_the_read_back_is_the_composers_alone() {
        i1340(dir(), "sqlite").await;
    }

    #[tokio::test]
    async fn i1341_only_a_duplicate_key_is_a_store_conflict() {
        i1341(dir(), "sqlite").await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::store::Backend as _;

    async fn dir() -> Option<Arc<dyn FederationDirectory>> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(Arc::new(b))
    }

    #[tokio::test]
    async fn i1340_the_read_back_is_the_composers_alone() {
        let Some(d) = dir().await else { return };
        i1340(d, "postgres").await;
    }

    #[tokio::test]
    async fn i1341_only_a_duplicate_key_is_a_store_conflict() {
        let Some(d) = dir().await else { return };
        i1341(d, "postgres").await;
    }
}
