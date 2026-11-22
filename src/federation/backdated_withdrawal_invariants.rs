//! v62.0.0 (KR-fix19; CC 2.4.1.1, CC 2.6.7, as ruled 2026-11-21) — **I4317:
//! a retraction dated BEFORE its target is refused `withdrawal_backdated`; one
//! dated AT its target's instant is admitted.**
//!
//! A `withdraws` / `recants` whose signed `asserted_at` is strictly before
//! its held target's is refused (`admission::check_retraction_not_backdated`):
//! it can never become valid, so it is a refusal, not a hold. Both instants
//! are signed and held, so every node decides alike.
//!
//! For each of `withdraws` and `recants`, each door (the statement door a
//! local producer uses, and the wire door a peer's statement arrives
//! through) and each arrival order (target first; retraction first):
//!
//! - dated one second BEFORE the target: no retraction row lands and the
//!   target stands. Target first, the statement door REFUSES it by name and
//!   keeps nothing. Retraction first, it waits `link_unheld`; when the target
//!   lands it is judged and refused, and what stays held names
//!   `withdrawal_backdated` in its detail;
//! - dated EQUAL to the target (a slow clock's case): it lands, on either
//!   order.
//!
//! **I4318**: `Engine::withdraw_statement_draft` refuses an instant before
//! the target's and drafts the target's own instant.
//!
//! sqlite and postgres.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::WITHDRAWAL_BACKDATED;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold::reason::LINK_UNHELD;
    use crate::federation::edition2::ingest::apply_replicated_statement;
    use crate::federation::edition2::names::RowId;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{Attestation, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// A plain `scores` row by `by` about itself, dated five minutes ago at
    /// a whole millisecond (the instant an edition-2 statement states).
    fn target_row(by: &str, n: usize) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "dimension": format!("evidence:safety_battery:capture:b{n}:c:v1"),
            "id": id,
        });
        let mut r = ts::bare_attestation(&id, by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = DateTime::<Utc>::from_timestamp_millis(
            (Utc::now() - Duration::minutes(5)).timestamp_millis(),
        )
        .expect("an instant");
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(by, &mut r);
        r
    }

    #[derive(Clone, Copy, Debug)]
    enum Door {
        Statement,
        Wire,
    }

    /// Offer `row`'s statement through `door`: its row id, and the refusal's
    /// text when the door refused it.
    async fn offer(
        d: &dyn FederationDirectory,
        door: Door,
        row: &Attestation,
    ) -> (RowId, Option<String>) {
        let st = e2::carried_statement(row).expect("a statement");
        let id = RowId::of_statement(&st).expect("a row id");
        let refused = match door {
            Door::Statement => e2::put_signed(d, row).await.err().map(|e| e.to_string()),
            Door::Wire => Box::pin(apply_replicated_statement(d, &st, &id.0))
                .await
                .err()
                .map(|e| e.to_string()),
        };
        (id, refused)
    }

    async fn held(d: &dyn FederationDirectory, id: &RowId) -> Option<(String, String)> {
        d.fold_held(id)
            .await
            .expect("fold_held")
            .map(|h| (h.reason, h.detail))
    }

    async fn landed(d: &dyn FederationDirectory, id: &RowId) -> bool {
        d.get_attestation(&id.hex())
            .await
            .expect("get_attestation")
            .is_some()
    }

    /// **I4317.**
    pub(crate) async fn i4317_a_backdated_retraction_is_refused(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let seed = format!("i4317-{s}");
        ts::register_hybrid_key_as(
            d,
            &seed,
            &seed,
            crate::federation::types::identity_type::USER,
        )
        .await;
        let by = e2::kid(&seed);
        let mut n = 0;
        for kind in [attestation_type::WITHDRAWS, attestation_type::RECANTS] {
            for door in [Door::Statement, Door::Wire] {
                for target_first in [true, false] {
                    n += 1;
                    let what = format!(
                        "I4317 {kind}, {door:?} door, {}",
                        if target_first {
                            "target first"
                        } else {
                            "retraction first"
                        }
                    );
                    let target = target_row(&by, n);
                    let tid =
                        RowId::of_statement(&e2::carried_statement(&target).expect("a statement"))
                            .expect("a row id");
                    let before = e2::composer_of_at(
                        kind,
                        &target,
                        &seed,
                        target.asserted_at - Duration::seconds(1),
                    );
                    let equal = e2::composer_of_at(kind, &target, &seed, target.asserted_at);
                    let wid = if target_first {
                        e2::put_signed(d, &target)
                            .await
                            .unwrap_or_else(|e| panic!("{what}: the target lands: {e}"));
                        let (wid, refused) = offer(d, door, &before).await;
                        if matches!(door, Door::Statement) {
                            let text = refused.unwrap_or_else(|| {
                                panic!("{what}: dated before its target, it is REFUSED")
                            });
                            assert!(
                                text.contains(WITHDRAWAL_BACKDATED),
                                "{what}: refused by name: {text}"
                            );
                            assert!(
                                held(d, &wid).await.is_none(),
                                "{what}: a refusal keeps nothing"
                            );
                        }
                        wid
                    } else {
                        let (wid, _) = offer(d, door, &before).await;
                        // The statement door keeps it, waiting for the
                        // target. The wire door may instead keep nothing and
                        // ask the peer to offer it again: then the peer does,
                        // once the target is here.
                        let waiting = held(d, &wid).await.map(|(r, _)| r);
                        assert!(
                            waiting.as_deref() == Some(LINK_UNHELD)
                                || (waiting.is_none() && matches!(door, Door::Wire)),
                            "{what}: before its target it waits for the target: {waiting:?}"
                        );
                        e2::put_signed(d, &target)
                            .await
                            .unwrap_or_else(|e| panic!("{what}: the target lands: {e}"));
                        if waiting.is_none() {
                            offer(d, door, &before).await;
                        } else {
                            // Judged when the target landed: what stays held
                            // says why.
                            let (reason, detail) = held(d, &wid)
                                .await
                                .unwrap_or_else(|| panic!("{what}: the kept statement stays held"));
                            assert!(
                                detail.contains(WITHDRAWAL_BACKDATED),
                                "{what}: judged against the target and refused by name \
                                 ({reason}): {detail}"
                            );
                        }
                        wid
                    };
                    assert!(
                        !landed(d, &wid).await,
                        "{what}: dated before its target, no retraction row lands"
                    );
                    assert!(landed(d, &tid).await, "{what}: the target stands");

                    // EQUAL to the target's instant: admitted (a slow clock
                    // retracts a fresh row by stating the row's own instant).
                    let (eid, refused) = offer(d, door, &equal).await;
                    assert!(
                        landed(d, &eid).await && held(d, &eid).await.is_none(),
                        "{what}: dated AT its target's instant, it lands: {refused:?}"
                    );
                }
            }
        }
        // And the other order for the equal instant: retraction first.
        let target = target_row(&by, 99);
        let equal = e2::composer_of_at(
            attestation_type::WITHDRAWS,
            &target,
            &seed,
            target.asserted_at,
        );
        let (eid, _) = offer(d, Door::Statement, &equal).await;
        assert_eq!(
            held(d, &eid).await.map(|(r, _)| r).as_deref(),
            Some(LINK_UNHELD),
            "I4317: an equal-instant retraction that arrives first waits for its target"
        );
        e2::put_signed(d, &target)
            .await
            .expect("I4317: the target lands");
        assert!(
            landed(d, &eid).await && held(d, &eid).await.is_none(),
            "I4317: and lands when the target arrives"
        );
    }

    /// **I4318.** The draft verb says so before a hardware signer signs:
    /// `asserted_at_ms` before the target's is refused `withdrawal_backdated`;
    /// the target's own instant drafts.
    pub(crate) async fn i4318_the_draft_verb_refuses_a_backdated_instant(e: &crate::Engine) {
        let dir = e.federation_directory();
        let d: &dyn FederationDirectory = dir.as_dyn_directory();
        let seed = format!("i4318-{}", uuid::Uuid::new_v4().simple());
        ts::register_hybrid_key_as(
            d,
            &seed,
            &seed,
            crate::federation::types::identity_type::USER,
        )
        .await;
        let by = e2::kid(&seed);
        let target = target_row(&by, 0);
        e2::put_signed(d, &target)
            .await
            .expect("I4318: the target lands");
        let tid = e2::rid(&target);
        let t_ms = u64::try_from(target.asserted_at.timestamp_millis()).expect("after 1970");
        let kid_hex = hex::encode(e2::kid_digest(&seed));
        let err = e
            .withdraw_statement_draft(&tid, &by, &kid_hex, t_ms - 1)
            .await
            .expect_err("I4318: an instant before the target's is not drafted");
        assert!(
            err.to_string()
                .contains(crate::federation::admission::WITHDRAWAL_BACKDATED),
            "I4318: named withdrawal_backdated: {err}"
        );
        e.withdraw_statement_draft(&tid, &by, &kid_hex, t_ms)
            .await
            .expect("I4318: the target's own instant drafts");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4317_a_backdated_retraction_is_refused_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4317_a_backdated_retraction_is_refused(
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4317_a_backdated_retraction_is_refused_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4317_a_backdated_retraction_is_refused(
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4318_the_draft_verb_refuses_a_backdated_instant_sqlite() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4318-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("I4318: a sqlite Engine");
        Box::pin(super::bodies::i4318_the_draft_verb_refuses_a_backdated_instant(&e)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4318_the_draft_verb_refuses_a_backdated_instant_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4318-engine"),
            &dsn,
        )
        .await
        .expect("I4318: a postgres Engine");
        Box::pin(super::bodies::i4318_the_draft_verb_refuses_a_backdated_instant(&e)).await;
    }
}
