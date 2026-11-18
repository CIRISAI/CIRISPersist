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
//!   what it did, and a composer is read back (v61, CIRISPersist#1157: a
//!   distinct same-triple composer is stored, never `Deduplicated`). Each `&&` of the predicate and of the
//!   read-back guard turned into `||` reads a row it must not.
//! - **I1341** — the write's error arm: a write error (an unregistered
//!   author) propagates as an error, never the `StoreConflict` refusal.
//!   v62.0.0: the duplicate-id leg (a rival mint under a peer-chosen id) is
//!   deleted: an edition-2 row id is computed from the row, so a rival mint
//!   is a different id, and a re-offer of the same row is the same bytes.
//!
//! v62.0.0 (slice E6) — every row is an edition-2 row (`fixture_switch`):
//! `row_of` signs the earlier-shaped fixture, the author's key is its
//! `key:record` (`put_key`), ids are node-computed, and a composer names its
//! target by `refs.target` (`composer_of`).

use crate::federation::attestation_apply::ReplicatedAttestationOutcome;
use crate::federation::directory_double::FaultInjectingDirectory;
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::types::{attestation_tier, attestation_type};
use crate::federation::{read_probe, Attestation, FederationDirectory, SignedAttestation};
use std::sync::Arc;

/// A signed federation-tier row of `attestation_type` by the key of seed
/// `author`, carrying `extra` in its envelope: the earlier-shaped fixture,
/// signed as an edition-2 statement (`row_of`), so its id is computed. The
/// dimension is a registered family (`capacity:{factor}`).
fn sealed(id: &str, author: &str, ty: &str, extra: serde_json::Value) -> Attestation {
    // v62.0.0 — an edition-2 row id is computed from the row, so two
    // fixtures of one author and envelope are one row unless they differ:
    // each call takes its own millisecond.
    static TICK: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture instant")
        .with_timezone(&chrono::Utc)
        + chrono::Duration::milliseconds(TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let mut envelope = serde_json::json!({
        "dimension": "capacity:integrity",
        "score": 1.0,
        "confidence": 0.9,
    });
    if let (Some(obj), Some(more)) = (envelope.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            obj.insert(k.clone(), v.clone());
        }
    }
    let row = Attestation {
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
    e2::row_of(&row, author)
}

fn fresh_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn scores(author: &str, extra: serde_json::Value) -> Attestation {
    sealed(&fresh_id(), author, attestation_type::SCORES, extra)
}

/// A `withdraws` by `author` naming `target` (`refs.target`, the target's
/// family).
fn withdraws(author: &str, target: &Attestation) -> Attestation {
    e2::composer_of(attestation_type::WITHDRAWS, target, author)
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
    let _ = e2::put_key(
        &*dir,
        &author,
        // v62.0.0 — a `user` key: its record covers every instant, and the
        // fixtures are dated 2026-01-01 (E0 fixed-instant rule).
        &[crate::federation::types::identity_type::USER],
    )
    .await;
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
        attestation: target.clone(),
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

    // The control: a composer IS read back (one read on top of the planned
    // path's). v61 (CIRISPersist#1157, CC rc14 3.1.9.4): a DISTINCT row of
    // the same `(type, attester, reference)` triple is no replay — it is
    // stored and ranked read-time — so the read-back confirms an insert.
    let (outcome, reads) = apply_counting(&*dir, withdraws(&author, &target)).await;
    assert_eq!(
        outcome,
        ReplicatedAttestationOutcome::Inserted,
        "{tag} I1340 first withdraws"
    );
    assert_eq!(
        reads,
        planned + 1,
        "{tag} I1340 a composer carrying a references target is read back"
    );
    // A distinct composer of the same triple: another instant, so another
    // row (and id).
    let mut second = withdraws(&author, &target);
    second.asserted_at += chrono::Duration::seconds(1);
    if let Some(o) = second.attestation_envelope.as_object_mut() {
        if o.contains_key("asserted_at") {
            o.insert(
                "asserted_at".to_owned(),
                serde_json::json!(second
                    .asserted_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            );
        }
    }
    let second = e2::row_of(&second, &author);
    let second_id = second.attestation_id.clone();
    let (outcome, _) = apply_counting(&*dir, second).await;
    assert_eq!(
        outcome,
        ReplicatedAttestationOutcome::Inserted,
        "{tag} I1340 a distinct same-triple composer is stored, not swallowed"
    );
    assert!(
        dir.get_attestation(&second_id)
            .await
            .expect("get")
            .is_some(),
        "{tag} I1340 the distinct composer is held"
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
    // A write error the door refuses is an error, not the store-conflict
    // refusal: a row by an author this node holds no key for.
    let stranger = format!("i1341-unregistered-{tag}");
    let unknown = scores(&stranger, serde_json::json!({}));
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
    async fn i1341_a_refused_write_is_no_store_conflict() {
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
    async fn i1341_a_refused_write_is_no_store_conflict() {
        let Some(d) = dir().await else { return };
        i1341(d, "postgres").await;
    }
}
