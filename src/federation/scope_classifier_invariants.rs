//! v47.0.0 (CIRISPersist#897, #796, #797, `FSD/SCOPE_CLASSIFIER.md`) —
//! **one scope, one question, every gate.**
//!
//! #893 and #897 are the same defect from opposite directions: for one
//! `cohort_scope`, persist's gates asked different questions. Each gate had a
//! test, and each test compared its gate to a constant, so no test ever asked
//! one gate what another had answered. I145 does exactly that: it asks the
//! write, widen, hold and read gates about ONE row and asserts the admitted
//! sets are equal to EACH OTHER, so a gate that drifts is red against its
//! siblings.

/// The I145 / I147 bodies, one per backend runner.
#[cfg(any(test, feature = "test-anchor"))]
pub mod bodies {
    use crate::ceg::list::drive_query_invariants::bodies::{seed_room, seed_row};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::read::AttestationFilter;
    use crate::scope::{caller_scope_from_directory, CallerScope};
    use std::collections::BTreeSet;

    fn set(v: &[&String]) -> BTreeSet<String> {
        v.iter().map(|s| (*s).clone()).collect()
    }

    /// **I145 — one `affiliations` row, asked of every gate.**
    ///
    /// Affiliation A holds the producer and `member`. Affiliation B holds the
    /// producer and `only_b` — so `only_b` shares a room with the producer but
    /// is not in A: the #893 trap, a gate answering from the producer's rooms
    /// instead of the row's.
    pub async fn i145_one_row_every_gate<B>(b: &B, s: &str)
    where
        B: crate::federation::FederationDirectory + crate::ceg::ReadEngine + Sync,
    {
        use crate::federation::types::cohort_scope as cs;
        let producer = format!("i145-producer-{s}");
        let member = format!("i145-member-{s}");
        let only_b = format!("i145-only-b-{s}");
        let room_a = format!("i145-aff-a-{s}");
        let room_b = format!("i145-aff-b-{s}");
        for k in [&producer, &member, &only_b] {
            ts::register_identity_key(b, k, crate::federation::types::identity_type::USER).await;
        }
        seed_room(b, &room_a, &[&producer, &member]).await;
        seed_room(b, &room_b, &[&producer, &only_b]).await;
        let callers = [&member, &only_b];
        let expected = set(&[&member]);

        // ── write (AV-45, through the put door) ────────────────────────────
        // Each caller tries to place its OWN row in A. Only a member of A may.
        let mut write = BTreeSet::new();
        for c in callers {
            let id = format!("i145-w-{c}");
            if seed_row(b, &id, c, cs::AFFILIATIONS, Some(&room_a), "file:doc:v1")
                .await
                .is_ok()
            {
                write.insert(c.clone());
            }
        }
        // …and a row naming NO affiliation is nobody's to write.
        assert!(
            seed_row(
                b,
                &format!("i145-noroom-{s}"),
                &producer,
                cs::AFFILIATIONS,
                None,
                "file:doc:v1"
            )
            .await
            .is_err(),
            "I145/write: an `affiliations` row naming no affiliation is refused — the at-rest \
             tier already refuses to store one (`resolve_write_tier`), so AV-45 admitting it was \
             persist disagreeing with itself"
        );

        // ── widen (the crossing's audience) ────────────────────────────────
        let roomless = crate::federation::Audience::from_cohort_scope(cs::AFFILIATIONS, None);
        assert!(
            roomless.is_err(),
            "I145/widen: an `affiliations` audience names its affiliation, as `community` \
             does — got {roomless:?}"
        );
        let placed =
            crate::federation::Audience::from_cohort_scope(cs::AFFILIATIONS, Some(&room_a))
                .expect("I145/widen: an affiliations audience WITH its room");
        assert_eq!(
            placed.cohort_target(),
            Some(room_a.as_str()),
            "I145/widen: the audience carries the room it was placed in"
        );

        // The row every read/hold leg asks about: the producer's, placed in A.
        let id = format!("i145-row-{s}");
        seed_row(
            b,
            &id,
            &producer,
            cs::AFFILIATIONS,
            Some(&room_a),
            "file:doc:v1",
        )
        .await
        .expect("I145: the producer is in A and places the row there");

        // ── hold (who this row is sent to) ─────────────────────────────────
        let mut hold = BTreeSet::new();
        for c in callers {
            if crate::federation::replication::hold::is_audience(
                b,
                cs::AFFILIATIONS,
                Some(&room_a),
                &producer,
                |_| false,
                c,
            )
            .await
            .unwrap()
            {
                hold.insert(c.clone());
            }
        }

        // ── read: the scores plane (every backend, the Rust twin on memory) ─
        let mut read_scores = BTreeSet::new();
        for c in callers {
            let page = <B as crate::federation::FederationDirectory>::list_scores(
                b,
                c,
                AttestationFilter {
                    cohort_scope: Some(cs::AFFILIATIONS.into()),
                    dimension_prefixes: vec!["file:".into()],
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
            if page.items.iter().any(|a| a.attestation_id == id) {
                read_scores.insert(c.clone());
            }
        }
        assert!(
            !CallerScope::Unauthenticated.admits(cs::AFFILIATIONS, &producer, Some(&room_a), None),
            "I145/read: an unauthenticated caller reads no `affiliations` row (CC 4.4.3.2.1: \
             community tier, readers are members)"
        );

        // THE ASSERTION: the gates agree with each other, then with the rule.
        assert_eq!(
            write, hold,
            "I145: the WRITE gate and the HOLD path disagree about who is in this row's room"
        );
        assert_eq!(
            hold, read_scores,
            "I145: the HOLD path and the READ gate (scores plane) disagree"
        );
        assert_eq!(write, expected, "I145: only a member of A, by every gate");

        // ── read: the relational plane (sqlite / postgres) ─────────────────
        if let Err(crate::ceg::Error::Backend(msg)) = crate::ceg::ReadEngine::list_attestations(
            b,
            AttestationFilter::default(),
            None,
            1,
            CallerScope::Unauthenticated,
        )
        .await
        {
            if msg.contains("no relational read substrate") {
                return;
            }
        }
        let idr: &str = &id;
        let rel = |scope: CallerScope| async move {
            crate::ceg::ReadEngine::list_attestations(
                b,
                AttestationFilter {
                    cohort_scope: Some(cs::AFFILIATIONS.into()),
                    ..Default::default()
                },
                None,
                100,
                scope,
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .any(|a| a.attestation_id == idr)
        };
        let mut read_rel = BTreeSet::new();
        for c in callers {
            if rel(caller_scope_from_directory(b, c).await.unwrap()).await {
                read_rel.insert(c.clone());
            }
        }
        assert_eq!(
            read_scores, read_rel,
            "I145: the two read doors disagree about this row"
        );
        assert!(
            !rel(CallerScope::Unauthenticated).await,
            "I145/read: the relational door serves no `affiliations` row to an unauthenticated \
             caller"
        );
    }

    /// **I147 — unresolved is not "not a member"** (#797).
    ///
    /// A write naming a room this directory has never seen cannot be answered
    /// yet: the roster may simply not have arrived. It still refuses — fail
    /// secure — but by a name a caller can retry on.
    pub async fn i147_unresolved_is_not_not_a_member<B>(b: &B, s: &str)
    where
        B: crate::federation::FederationDirectory + Sync,
    {
        use crate::federation::types::cohort_scope as cs;
        let writer = format!("i147-writer-{s}");
        let other = format!("i147-other-{s}");
        ts::register_identity_key(b, &writer, crate::federation::types::identity_type::USER).await;
        ts::register_identity_key(b, &other, crate::federation::types::identity_type::USER).await;
        let kind =
            |r: Result<crate::federation::AttestationOutcome, crate::federation::Error>| match r {
                Err(crate::federation::Error::WriteScopeRefused(reason)) => reason.kind(),
                Err(e) => panic!("I147: expected a typed scope refusal, got {e}"),
                Ok(_) => "admitted",
            };
        for scope in [cs::COMMUNITY, cs::AFFILIATIONS] {
            let unseen = format!("i147-unseen-{scope}-{s}");
            assert_eq!(
                kind(
                    seed_row(
                        b,
                        &format!("i147-u-{scope}-{s}"),
                        &writer,
                        scope,
                        Some(&unseen),
                        "file:doc:v1"
                    )
                    .await
                ),
                "scope_membership_unresolved",
                "I147/{scope}: a room this directory has never seen is UNRESOLVED (retryable), \
                 not 'not a member' (terminal)"
            );
            let theirs = format!("i147-theirs-{scope}-{s}");
            seed_room(b, &theirs, &[&other]).await;
            assert_eq!(
                kind(
                    seed_row(
                        b,
                        &format!("i147-t-{scope}-{s}"),
                        &writer,
                        scope,
                        Some(&theirs),
                        "file:doc:v1"
                    )
                    .await
                ),
                "scope_no_community_membership",
                "I147/{scope}: a KNOWN room the writer is not in is terminal"
            );
            let ours = format!("i147-ours-{scope}-{s}");
            seed_room(b, &ours, &[&writer]).await;
            assert_eq!(
                kind(
                    seed_row(
                        b,
                        &format!("i147-o-{scope}-{s}"),
                        &writer,
                        scope,
                        Some(&ours),
                        "file:doc:v1"
                    )
                    .await
                ),
                "admitted",
                "I147/{scope}: a member lands"
            );
        }
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i145() {
                    let Some(b) = $fresh.await else { return };
                    super::super::bodies::i145_one_row_every_gate(&b, &super::suffix()).await
                }

                #[tokio::test]
                async fn i147() {
                    let Some(b) = $fresh.await else { return };
                    super::super::bodies::i147_unresolved_is_not_not_a_member(&b, &super::suffix())
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
}
