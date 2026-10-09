//! v53.1.2 (CIRISPersist#984 row 16, CC 3.3.3 "a `withdraws` ends a proof")
//! — **withdrawing a location proof.**
//!
//! `federation_location_proofs.withdrawn_at` (V068) had readers (the
//! geographic-constraint fold) and no writer on any backend. The door is a
//! RE-SIGNED row — the signing envelope covers `withdrawn_at`, so a column
//! stamped behind the signature would leave a held row that no longer
//! verifies, and the replication plane serves signed rows only.
//!
//! - **I519** (memory, sqlite, postgres) — the proof's own attester ends it
//!   (the fold reads it as not in force; the served row carries the
//!   withdrawal and verifies); a stranger is refused by standing; a LIVE
//!   delegate of the subject who did not attest the proof is refused by name;
//!   a re-offer that is not a withdrawal is refused; a second withdrawal is a
//!   no-op that keeps the first instant.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::location::member_in_geographic_constraint;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::LocationProof;
    use crate::federation::{Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// **I519** — only the attester ends a proof.
    pub(crate) async fn i519_only_the_attester_ends_a_proof(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (subject, delegate, stranger) = (
            format!("i519-s-{tag}"),
            format!("i519-d-{tag}"),
            format!("i519-x-{tag}"),
        );
        for k in [&subject, &delegate, &stranger] {
            ts::register_hybrid_key(d, k).await;
        }
        let cell = h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        let at: DateTime<Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
        let proof = |withdrawn_at: Option<DateTime<Utc>>| LocationProof {
            subject_key_id: subject.clone(),
            cell_id: cell.clone(),
            cell_resolution: 7,
            asserted_at: at,
            valid_until: None,
            attestation_evidence: None,
            withdrawn_at,
            persist_row_hash: String::new(),
        };
        d.put_location_proof(ts::sign_location_proof(&subject, proof(None)))
            .await
            .unwrap_or_else(|e| panic!("I519 the proof: {e}"));
        let in_force = || async {
            member_in_geographic_constraint(
                &cell,
                &d.list_location_proofs_for(&subject).await.unwrap(),
                Utc::now(),
            )
        };
        assert!(
            in_force().await,
            "I519 precondition — the proof is in force"
        );
        let t1 = at + Duration::hours(1);
        // A stranger: refused by standing, nothing ends.
        let r = d
            .withdraw_location_proof(ts::sign_location_proof(&stranger, proof(Some(t1))))
            .await;
        assert!(
            matches!(r, Err(Error::LocationAuthorityUnauthorized { .. })),
            "I519 a stranger's withdrawal is refused by standing: {r:?}"
        );
        assert!(in_force().await, "I519 the stranger ended nothing");
        // A live delegate of the subject passes standing but did not attest
        // the proof: refused by name.
        ts::put_delegates_to(d, &subject, &delegate, None)
            .await
            .expect("I519 the delegation");
        let r = d
            .withdraw_location_proof(ts::sign_location_proof(&delegate, proof(Some(t1))))
            .await;
        assert!(
            r.as_ref().is_err_and(|e| e
                .to_string()
                .contains("location_proof_withdraw_not_the_attester")),
            "I519 a delegate who did not attest the proof cannot end it: {r:?}"
        );
        assert!(in_force().await, "I519 the delegate ended nothing");
        // A re-offer that is not a withdrawal.
        let r = d
            .withdraw_location_proof(ts::sign_location_proof(&subject, proof(None)))
            .await;
        assert!(
            r.as_ref().is_err_and(|e| e
                .to_string()
                .contains("location_proof_withdraw_not_a_withdrawal")),
            "I519 a row with no withdrawn_at is not a withdrawal: {r:?}"
        );
        // The attester ends it.
        d.withdraw_location_proof(ts::sign_location_proof(&subject, proof(Some(t1))))
            .await
            .unwrap_or_else(|e| panic!("I519 the attester withdraws: {e}"));
        assert!(!in_force().await, "I519 the proof is no longer in force");
        let held = d.list_location_proofs_for(&subject).await.unwrap();
        assert_eq!(held.len(), 1, "I519 one row, in history: {held:?}");
        assert_eq!(
            held[0].withdrawn_at,
            Some(t1),
            "I519 the withdrawal instant"
        );
        // Idempotent: a second withdrawal keeps the first instant.
        d.withdraw_location_proof(ts::sign_location_proof(
            &subject,
            proof(Some(t1 + Duration::hours(1))),
        ))
        .await
        .expect("I519 a re-offer is a no-op");
        let held = d.list_location_proofs_for(&subject).await.unwrap();
        assert_eq!(
            held[0].withdrawn_at,
            Some(t1),
            "I519 the first instant stands"
        );
        // The served row carries the withdrawal and verifies as signed.
        let served = d
            .list_signed_location_proofs_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.proof.location_proof.subject_key_id == subject)
            .expect("I519 the row is served");
        assert_eq!(served.proof.location_proof.withdrawn_at, Some(t1));
        crate::federation::verify_location_proof_admission(d, &served.proof)
            .await
            .unwrap_or_else(|e| panic!("I519 the served withdrawal verifies as signed: {e}"));
    }
}

#[cfg(test)]
pub(crate) mod reindex_bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::LocationProof;
    use crate::federation::wire_index::content_hash_of_bytes;
    use crate::federation::{FederationDirectory, SignedLocationProof};
    use chrono::{DateTime, Duration, Utc};

    fn proof(
        subject: &str,
        cell: &str,
        at: DateTime<Utc>,
        withdrawn_at: Option<DateTime<Utc>>,
    ) -> LocationProof {
        LocationProof {
            subject_key_id: subject.to_owned(),
            cell_id: cell.to_owned(),
            cell_resolution: 7,
            asserted_at: at,
            valid_until: None,
            attestation_evidence: None,
            withdrawn_at,
            persist_row_hash: String::new(),
        }
    }

    fn cell() -> String {
        h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string()
    }

    /// The row as A serves it for `subject`, and its wire content hash (what
    /// `settle_if_held` / `lookup_signed_record_by_content_hash` key on).
    async fn served(d: &dyn FederationDirectory, subject: &str) -> (SignedLocationProof, String) {
        let s = d
            .list_signed_location_proofs_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.proof.location_proof.subject_key_id == subject)
            .expect("the row is served");
        let hash = content_hash_of_bytes(&serde_json::to_vec(&s.proof).unwrap());
        (s.proof, hash)
    }

    /// **I523** (v53.1.3, Codex on #985 P1, #986) — **a withdrawal is
    /// re-indexed.** The withdraw door rewrote the row's hash and signatures
    /// and returned without `index_stored_record`, so the signed wire index
    /// kept the OLD content hash: a peer re-offering the withdrawal found no
    /// entry under its hash (full apply), and the old hash reloaded bytes that
    /// no longer matched. After: the withdrawn row's hash resolves to the row;
    /// the pre-withdrawal hash resolves to nothing.
    pub(crate) async fn i523_a_withdrawal_is_reindexed(d: &dyn FederationDirectory, tag: &str) {
        let subject = format!("i523-s-{tag}");
        ts::register_hybrid_key(d, &subject).await;
        let (cell, at) = (
            cell(),
            "2026-10-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        d.put_location_proof(ts::sign_location_proof(
            &subject,
            proof(&subject, &cell, at, None),
        ))
        .await
        .expect("the proof");
        let (_, hash0) = served(d, &subject).await;
        assert!(
            d.lookup_signed_record_by_content_hash("LocationProof", &hash0)
                .await
                .unwrap()
                .is_some(),
            "I523 precondition — the put indexed the row"
        );
        d.withdraw_location_proof(ts::sign_location_proof(
            &subject,
            proof(&subject, &cell, at, Some(at + Duration::hours(1))),
        ))
        .await
        .expect("the withdrawal");
        let (withdrawn, hash1) = served(d, &subject).await;
        assert!(withdrawn.location_proof.withdrawn_at.is_some());
        let found = d
            .lookup_signed_record_by_content_hash("LocationProof", &hash1)
            .await
            .unwrap();
        assert_eq!(
            found.as_deref(),
            Some(serde_json::to_vec(&withdrawn).unwrap().as_slice()),
            "I523 the withdrawn row resolves under its own content hash"
        );
        assert!(
            d.lookup_signed_record_by_content_hash("LocationProof", &hash0)
                .await
                .unwrap()
                .is_none(),
            "I523 the pre-withdrawal hash resolves to nothing"
        );
        // **I574** (v54.0.0, #995 row 5) — and the listing no longer
        // ADVERTISES it: the re-index upserted the new hash and left the
        // `(kind, old_hash)` row behind, so anti-entropy kept offering a hash
        // whose point read answers `None`.
        let listed = d
            .list_wire_hashes_since("LocationProof", None, 10_000)
            .await
            .unwrap();
        assert!(
            listed.contains(&hash1),
            "I574 the withdrawn row's hash is listed"
        );
        assert!(
            !listed.contains(&hash0),
            "I574 the pre-withdrawal hash is no longer advertised: {listed:?}"
        );
        // A rebuild leaves the one current mapping.
        d.rebuild_signed_wire_index().await.unwrap();
        let listed = d
            .list_wire_hashes_since("LocationProof", None, 10_000)
            .await
            .unwrap();
        assert!(listed.contains(&hash1) && !listed.contains(&hash0));
    }

    /// **I599** (v54.0.0, Codex on PR #1050) — **a re-index is one step per
    /// record.** `first` re-indexes the proof and is paused after reading the
    /// stored bytes, before replacing the mapping; meanwhile `second` (the
    /// same backend, or another pool on the same postgres database) withdraws
    /// the proof, which re-indexes it under the new bytes; then `first`
    /// resumes. Before the fix the paused re-index pruned the newer hash and
    /// wrote its stale one, so the listing advertised a hash the point read
    /// rejects. After: exactly one mapping, the withdrawn row's, and every
    /// listed hash resolves.
    pub(crate) async fn i599_a_concurrent_reindex_leaves_one_mapping<Fut>(
        first: &dyn FederationDirectory,
        second: &dyn FederationDirectory,
        arm: impl FnOnce() -> std::sync::Arc<crate::store::test_hooks::Pause>,
        reindex_first: impl FnOnce(String) -> Fut,
        tag: &str,
    ) where
        Fut: std::future::Future<Output = Result<(), crate::federation::Error>>,
    {
        let subject = format!("i599-s-{tag}");
        ts::register_hybrid_key(first, &subject).await;
        let (cell, at) = (
            cell(),
            "2026-10-03T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        first
            .put_location_proof(ts::sign_location_proof(
                &subject,
                proof(&subject, &cell, at, None),
            ))
            .await
            .expect("the proof");
        let (_, hash0) = served(first, &subject).await;
        let key = crate::federation::wire_index::record_key(&[
            ("subject_key_id", &subject),
            (
                "asserted_at",
                &crate::federation::wire_index::locator_instant(&at),
            ),
        ]);
        // Armed only now: the put above re-indexed too and must not take it.
        let pause = arm();
        let withdrawal = ts::sign_location_proof(
            &subject,
            proof(&subject, &cell, at, Some(at + Duration::hours(1))),
        );
        let (r_first, (r_second, second_ran_free)) = tokio::join!(reindex_first(key), async {
            pause.reached().await;
            let w = second.withdraw_location_proof(withdrawal);
            tokio::pin!(w);
            match tokio::time::timeout(std::time::Duration::from_secs(3), &mut w).await {
                Ok(r) => {
                    pause.resume();
                    (r, true)
                }
                Err(_) => {
                    pause.resume();
                    (w.await, false)
                }
            }
        });
        r_first.expect("the first re-index");
        r_second.expect("the withdrawal");
        let (_, hash1) = served(first, &subject).await;
        assert_ne!(
            hash0, hash1,
            "I599 precondition: the withdrawal changed the bytes"
        );
        let listed = first
            .list_wire_hashes_since("LocationProof", None, 10_000)
            .await
            .unwrap();
        let mine: Vec<&String> = listed
            .iter()
            .filter(|h| **h == hash0 || **h == hash1)
            .collect();
        for h in &listed {
            assert!(
                first
                    .lookup_signed_record_by_content_hash("LocationProof", h)
                    .await
                    .unwrap()
                    .is_some(),
                "I599 a listed hash the point read rejects: {h} (stale = {}; the withdrawal \
                 finished while the re-index was held: {second_ran_free})",
                *h == hash0
            );
        }
        assert_eq!(
            mine,
            vec![&hash1],
            "I599 exactly one mapping for the record, the withdrawn row's (withdrawal ran \
             while the re-index was held: {second_ran_free})"
        );
        assert!(
            !second_ran_free,
            "I599 the withdrawal's re-index must wait for the held one"
        );
    }

    /// **I524** (v53.1.3, Codex on #985 P2, #986) — **the withdrawal write is
    /// a compare-and-set.** Two valid withdrawals of one proof decided `Apply`
    /// from the same `None` read; the later UPDATE overwrote the first's
    /// instant and signature. With `… AND withdrawn_at IS NULL`, the loser
    /// writes nothing, re-reads, and answers already-withdrawn. `arm` plants
    /// the rival at the point between the door's read and its write.
    // The rival seam exists on sqlite and postgres only (memory writes under
    // one lock); the no-backend shapes build this module without a runner.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i524_the_withdrawal_write_is_a_compare_and_set<B>(
        b: &B,
        tag: &str,
        arm: fn(&B, SignedLocationProof),
    ) where
        B: FederationDirectory + Sync,
    {
        let subject = format!("i524-s-{tag}");
        ts::register_hybrid_key(b, &subject).await;
        let (cell, at) = (
            cell(),
            "2026-10-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        b.put_location_proof(ts::sign_location_proof(
            &subject,
            proof(&subject, &cell, at, None),
        ))
        .await
        .expect("the proof");
        let (ta, tb) = (at + Duration::hours(1), at + Duration::hours(2));
        let rival = ts::sign_location_proof(&subject, proof(&subject, &cell, at, Some(tb)));
        arm(b, rival);
        // A reads the row unwithdrawn and decides Apply; the rival (B, at tb)
        // lands before A's write; A's write must not overwrite it.
        b.withdraw_location_proof(ts::sign_location_proof(
            &subject,
            proof(&subject, &cell, at, Some(ta)),
        ))
        .await
        .expect("I524 the loser answers already-withdrawn, not an error");
        let held = b.list_location_proofs_for(&subject).await.unwrap();
        assert_eq!(
            held[0].withdrawn_at,
            Some(tb),
            "I524 the withdrawal that landed first stands: {held:?}"
        );
        let (srv, _) = served(b, &subject).await;
        assert_eq!(srv.location_proof.withdrawn_at, Some(tb));
        crate::federation::verify_location_proof_admission(b, &srv)
            .await
            .expect("I524 the served row is the first withdrawal, whole: its signature verifies");
    }
}

#[cfg(test)]
pub(crate) mod peer_bodies {
    use crate::federation::location::member_in_geographic_constraint;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::LocationProof;
    use crate::federation::{Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// **I522** (v53.1.2, CIRISPersist#984 row 19) — **a peer applies a
    /// withdrawal through the replication door.** A's attester withdraws
    /// (the I519 door); B, holding the original, is offered A's served signed
    /// row through `put_location_proof`: the held PK with an offer that
    /// differs only by `withdrawn_at` is routed through the one withdrawal
    /// predicate and applied, so B's in-force fold excludes the proof. A
    /// stranger's "withdrawal" is refused by standing; a live delegate's by
    /// name (not the attester). Before: sqlite/postgres refused the offer on
    /// the primary key and memory overwrote the row unchecked.
    pub(crate) async fn i522_a_peer_applies_a_withdrawal(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (subject, delegate, stranger) = (
            format!("i522-s-{tag}"),
            format!("i522-d-{tag}"),
            format!("i522-x-{tag}"),
        );
        for d in [a, b] {
            for k in [&subject, &delegate, &stranger] {
                ts::register_hybrid_key(d, k).await;
            }
        }
        let cell = h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        let proof = |at: DateTime<Utc>, withdrawn_at: Option<DateTime<Utc>>| LocationProof {
            subject_key_id: subject.clone(),
            cell_id: cell.clone(),
            cell_resolution: 7,
            asserted_at: at,
            valid_until: None,
            attestation_evidence: None,
            withdrawn_at,
            persist_row_hash: String::new(),
        };
        async fn in_force_on(d: &dyn FederationDirectory, cell: &str, subject: &str) -> bool {
            member_in_geographic_constraint(
                cell,
                &d.list_location_proofs_for(subject).await.unwrap(),
                Utc::now(),
            )
        }
        macro_rules! in_force {
            ($d:expr) => {
                in_force_on($d, &cell, &subject)
            };
        }
        let at1: DateTime<Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
        let original = ts::sign_location_proof(&subject, proof(at1, None));
        a.put_location_proof(original.clone())
            .await
            .expect("A holds the proof");
        b.put_location_proof(original)
            .await
            .expect("B holds the proof");
        assert!(in_force!(b).await, "I522 precondition — in force on B");
        let t1 = at1 + Duration::hours(1);
        a.withdraw_location_proof(ts::sign_location_proof(&subject, proof(at1, Some(t1))))
            .await
            .expect("I522 A's attester withdraws");
        let served = a
            .list_signed_location_proofs_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.proof.location_proof.subject_key_id == subject)
            .expect("I522 A serves the row");
        assert_eq!(served.proof.location_proof.withdrawn_at, Some(t1));
        b.put_location_proof(served.proof)
            .await
            .unwrap_or_else(|e| panic!("I522 B applies A's served withdrawal: {e}"));
        assert!(
            !in_force!(b).await,
            "I522 B's fold excludes the withdrawn proof"
        );
        let held = b.list_location_proofs_for(&subject).await.unwrap();
        assert_eq!(held.len(), 1, "I522 one row on B: {held:?}");
        assert_eq!(
            held[0].withdrawn_at,
            Some(t1),
            "I522 the attester's instant"
        );
        // A second proof held on B only; a live delegate of the subject who
        // did not attest it offers a "withdrawal": refused by name, in force.
        let at2 = at1 + Duration::days(1);
        b.put_location_proof(ts::sign_location_proof(&subject, proof(at2, None)))
            .await
            .expect("B holds a second proof");
        ts::put_delegates_to(b, &subject, &delegate, None)
            .await
            .expect("the delegation on B");
        let r = b
            .put_location_proof(ts::sign_location_proof(&delegate, proof(at2, Some(t1))))
            .await;
        assert!(
            r.as_ref().is_err_and(|e| e
                .to_string()
                .contains("location_proof_withdraw_not_the_attester")),
            "I522 a delegate who did not attest the proof cannot end it through replication: {r:?}"
        );
        assert!(in_force!(b).await, "I522 the second proof stands");
        // A stranger's: refused by standing.
        let r = b
            .put_location_proof(ts::sign_location_proof(&stranger, proof(at2, Some(t1))))
            .await;
        assert!(
            matches!(r, Err(Error::LocationAuthorityUnauthorized { .. })),
            "I522 a stranger's withdrawal is refused by standing: {r:?}"
        );
        assert!(in_force!(b).await, "I522 the second proof still stands");
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i519() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i519_only_the_attester_ends_a_proof(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i523() {
                    let Some(d) = $fresh.await else { return };
                    super::super::reindex_bodies::i523_a_withdrawal_is_reindexed(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i522() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    super::super::peer_bodies::i522_a_peer_applies_a_withdrawal(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
    }

    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    /// I599 on one backend (memory, sqlite): both writers share it.
    macro_rules! i599_single {
        ($b:expr) => {{
            let b = $b;
            let br = &b;
            super::reindex_bodies::i599_a_concurrent_reindex_leaves_one_mapping(
                &b as &dyn crate::federation::FederationDirectory,
                &b as &dyn crate::federation::FederationDirectory,
                || br.test_hooks().arm_pause("wire_index_before_write"),
                |key| async move { br.index_stored_record("LocationProof", &key).await },
                &suffix(),
            )
            .await;
        }};
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i599_memory() {
        i599_single!(crate::store::memory::MemoryBackend::new());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i599_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        i599_single!(b);
    }

    /// I599 on postgres: TWO backends, two pools, one database.
    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i599_postgres() {
        use crate::federation::FederationDirectory;
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("i599_postgres: no base DSN — SKIPPED");
            return;
        };
        let b1 = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b1.run_migrations().await.unwrap();
        let b2 = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        let b1r = &b1;
        super::reindex_bodies::i599_a_concurrent_reindex_leaves_one_mapping(
            &b1 as &dyn FederationDirectory,
            &b2 as &dyn FederationDirectory,
            || b1r.test_hooks().arm_pause("wire_index_before_write"),
            |key| async move { b1r.index_stored_record("LocationProof", &key).await },
            &suffix(),
        )
        .await;
        eprintln!("i599_postgres: RAN on {dsn}");
    }

    /// I524 needs the backend's own rival seam (memory writes under one lock
    /// and has no race to witness).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i524_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::reindex_bodies::i524_the_withdrawal_write_is_a_compare_and_set(
            &b,
            &suffix(),
            |b, rival| b.test_hooks().arm_rival_location_proof_withdrawal(rival),
        )
        .await
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i524_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::reindex_bodies::i524_the_withdrawal_write_is_a_compare_and_set(
            &b,
            &suffix(),
            |b, rival| b.test_hooks().arm_rival_location_proof_withdrawal(rival),
        )
        .await
    }
}
