//! v61 S2 (CIRISPersist#1155 / #1157; CC rc14 3.1.9.4,
//! `CLM-composer-convergent-rank`) — **a composer is idempotent on its
//! `attestation_id`, and distinct same-type rows from one attester on one
//! target are ranked read-time within one audience.** sqlite and postgres.
//!
//! - **I1506** — one `self` row placed into TWO rooms leaves both placements
//!   stored and live. Before v61 the second placement carried the first's
//!   `(supersedes, author, self_id)` triple and was swallowed as a
//!   `ComposerReplay` (witnessed red before the fix).
//! - **I1507** — the author's community-born composers naming the placed
//!   head: an edit is admitted and becomes the visible head (the placement
//!   hidden); a second, later edit naming the same head is admitted too
//!   (both stored) and outranks the first; an exact replay is a no-op; the
//!   head's withdrawal leaves nothing visible; a non-member's composer is
//!   refused.
//! - **I1508** — two nodes converge: one takes X then Y, the other Y then X,
//!   and both read the same live head; an equal-instant tie goes to the lower
//!   `attestation_id` bytewise on both.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::membership_acceptance_invariants::bodies::{found_community, reg};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
    use crate::federation::{
        Attestation, Audience, CrossingBasis, FederationDirectory, MeshCrossingOutcome,
        SignedAttestation,
    };
    use chrono::{DateTime, Duration, Utc};

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    /// The live rows `author` signed, as the room reader asks (the CEG list
    /// under the default `Live` view).
    pub(crate) async fn live_ids<B>(d: &B, author: &str) -> Vec<String>
    where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        let filter = crate::read::AttestationFilter {
            attesting_key_id: Some(author.to_owned()),
            ..Default::default()
        };
        let scope = crate::scope::caller_scope_from_directory(d, author)
            .await
            .expect("caller scope");
        let page = d
            .list_attestations(filter, None, 1000, scope)
            .await
            .expect("live read");
        let mut ids: Vec<String> = page.items.into_iter().map(|r| r.attestation_id).collect();
        ids.sort();
        ids
    }

    /// `author`'s own `self` row, crossed into the mesh (the prior a
    /// placement widens).
    pub(crate) async fn self_row(d: &dyn FederationDirectory, author: &str) -> Attestation {
        let mut row = crate::federation::bootstrap_admission::test_support::scores_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            author,
            "trust:demo:v1",
        );
        row.tier = attestation_tier::LOCAL.to_owned();
        row.cohort_scope = cohort_scope::SELF.to_owned();
        ts::reseal(&mut row);
        let id = row.attestation_id.clone();
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("the self write");
        let local = d.get_attestation(&id).await.unwrap().unwrap();
        let ci = ts::describe_own(&local, CrossingBasis::ProducerAuthority);
        d.enter_mesh(&id, &ci, &ts::actor_reseal(&local))
            .await
            .expect("the crossing");
        d.get_attestation(&id).await.unwrap().unwrap()
    }

    /// Place `prior` into `room`; the placement row.
    pub(crate) async fn place(
        d: &dyn FederationDirectory,
        prior: &Attestation,
        room: &str,
    ) -> Attestation {
        let out = ts::widen(
            d,
            prior,
            Audience::Community {
                community_key_id: room.to_owned(),
            },
            &[],
        )
        .await
        .expect("the placement");
        let MeshCrossingOutcome::Crossed(report) = out else {
            panic!("a placement crosses: {out:?}");
        };
        d.get_attestation(&report.attestation_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("placement {} is stored", report.attestation_id))
    }

    /// `signer`'s community-born composer of `kind` naming `head` in `room`,
    /// at `asserted_at`, carrying `body` (an edit's new content).
    pub(crate) fn composer(
        signer: &str,
        kind: &str,
        head: &Attestation,
        room: &str,
        asserted_at: DateTime<Utc>,
        body: &str,
        id: Option<&str>,
    ) -> Attestation {
        let id = id
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut env = serde_json::json!({
            "references_attestation_id": head.attestation_id,
            "community_key_id": room,
        });
        if kind == attestation_type::SUPERSEDES {
            env["dimension"] = serde_json::json!("trust:demo:v1");
            env["score"] = serde_json::json!(
                crate::federation::namespace::registry::in_class_score("trust:demo:v1")
            );
            env["confidence"] = serde_json::json!(0.9);
            env["body"] = serde_json::json!(body);
        }
        let mut r = ts::bare_attestation(&id, signer, signer, &env);
        r.attestation_type = kind.to_owned();
        r.weight = None;
        r.cohort_scope = cohort_scope::COMMUNITY.to_owned();
        r.asserted_at = ms(asserted_at);
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(signer, &mut r);
        r
    }

    async fn put(
        d: &dyn FederationDirectory,
        r: &Attestation,
    ) -> Result<(), crate::federation::Error> {
        d.put_attestation(SignedAttestation {
            attestation: r.clone(),
        })
        .await
        .map(|_| ())
    }

    /// **I1506** — one row, two rooms, two live placements.
    pub(crate) async fn i1506_one_row_two_rooms_two_placements<B>(d: &B, s: &str)
    where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        let (author, a, b) = (
            format!("i1506-author-{s}"),
            format!("i1506-ra-{s}"),
            format!("i1506-rb-{s}"),
        );
        ts::register_hybrid_key_as(
            d,
            &author,
            &author,
            crate::federation::types::identity_type::USER,
        )
        .await;
        reg(d, &[&a, &b]).await;
        for r in [&a, &b] {
            found_community(d, r, "quorum:1/1", &[&author], &[])
                .await
                .unwrap();
        }
        let prior = self_row(d, &author).await;
        let pa = place(d, &prior, &a).await;
        let pb = place(d, &prior, &b).await;
        assert_ne!(pa.attestation_id, pb.attestation_id, "I1506: two rows");
        assert_eq!(
            crate::federation::admission::envelope_cohort_target(&pb.attestation_envelope).unwrap(),
            Some(b.as_str()),
            "I1506: the second room's placement names the second room"
        );
        let live = live_ids(d, &author).await;
        assert!(
            live.contains(&pa.attestation_id) && live.contains(&pb.attestation_id),
            "I1506: both placements live ({live:?})"
        );
        assert!(
            !live.contains(&prior.attestation_id),
            "I1506: the prior is hidden"
        );
    }

    /// **I1507** — the author's composers naming the placed head.
    pub(crate) async fn i1507_the_authors_composers_name_the_placed_head<B>(d: &B, s: &str)
    where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        let (author, stranger, room) = (
            format!("i1507-author-{s}"),
            format!("i1507-stranger-{s}"),
            format!("i1507-room-{s}"),
        );
        for k in [&author, &stranger] {
            ts::register_hybrid_key_as(d, k, k, crate::federation::types::identity_type::USER)
                .await;
        }
        reg(d, &[&room]).await;
        found_community(d, &room, "quorum:1/1", &[&author], &[])
            .await
            .unwrap();
        let prior = self_row(d, &author).await;
        let p = place(d, &prior, &room).await;
        let t = Utc::now() - Duration::minutes(10);
        let e1 = composer(
            &author,
            attestation_type::SUPERSEDES,
            &p,
            &room,
            t,
            "first edit",
            None,
        );
        put(d, &e1)
            .await
            .expect("I1507: the author's edit is admitted");
        let live = live_ids(d, &author).await;
        assert!(
            live.contains(&e1.attestation_id),
            "I1507: the edit is the head"
        );
        assert!(
            !live.contains(&p.attestation_id),
            "I1507: the placement is hidden"
        );
        // A second, later edit naming the SAME head: not a replay.
        let e2 = composer(
            &author,
            attestation_type::SUPERSEDES,
            &p,
            &room,
            t + Duration::minutes(1),
            "second edit",
            None,
        );
        put(d, &e2)
            .await
            .expect("I1507: a distinct second edit is admitted");
        assert!(
            d.get_attestation(&e2.attestation_id)
                .await
                .unwrap()
                .is_some()
                && d.get_attestation(&e1.attestation_id)
                    .await
                    .unwrap()
                    .is_some(),
            "I1507: both edits stored"
        );
        let live = live_ids(d, &author).await;
        assert!(
            live.contains(&e2.attestation_id) && !live.contains(&e1.attestation_id),
            "I1507: the later edit outranks the earlier ({live:?})"
        );
        // An exact replay is a no-op.
        put(d, &e2).await.expect("I1507: the replay");
        assert_eq!(live_ids(d, &author).await, live, "I1507: nothing changed");
        // Withdrawing the head leaves nothing of the message visible.
        let w = composer(
            &author,
            attestation_type::WITHDRAWS,
            &e2,
            &room,
            t + Duration::minutes(2),
            "",
            None,
        );
        put(d, &w)
            .await
            .expect("I1507: the author withdraws the head");
        let live = live_ids(d, &author).await;
        for gone in [&p, &e1, &e2] {
            assert!(
                !live.contains(&gone.attestation_id),
                "I1507: {} is not visible after the head is withdrawn ({live:?})",
                gone.attestation_id
            );
        }
        // A non-member's composer naming the head is refused.
        let x = composer(
            &stranger,
            attestation_type::SUPERSEDES,
            &p,
            &room,
            t + Duration::minutes(3),
            "not mine",
            None,
        );
        put(d, &x).await.expect_err("I1507: a stranger's composer");
        assert!(d
            .get_attestation(&x.attestation_id)
            .await
            .unwrap()
            .is_none());
    }

    /// The fixed pair for I1508: a room on `d` with `author`'s placement.
    pub(crate) async fn convergence_room(
        d: &dyn FederationDirectory,
        author: &str,
        room: &str,
    ) -> Attestation {
        ts::register_hybrid_key_as(
            d,
            author,
            author,
            crate::federation::types::identity_type::USER,
        )
        .await;
        reg(d, &[room]).await;
        found_community(d, room, "quorum:1/1", &[author], &[])
            .await
            .unwrap();
        let prior = self_row(d, author).await;
        place(d, &prior, room).await
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod two_node {
    use super::bodies::{composer, convergence_room, live_ids};
    use crate::federation::types::attestation_type::SUPERSEDES;
    use crate::federation::{FederationDirectory, SignedAttestation};
    use chrono::{Duration, Utc};

    /// **I1508** — order does not matter; a tie goes to the lower id.
    pub(crate) async fn i1508_two_nodes_converge_on_one_head<B>(a: &B, b: &B, s: &str)
    where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        let (author, room) = (format!("i1508-author-{s}"), format!("i1508-room-{s}"));
        let p = convergence_room(a, &author, &room).await;
        // B holds the room and the placement as a peer delivers them.
        convergence_room_on_peer(a, b, &author, &room, &p).await;
        let t = Utc::now() - Duration::minutes(10);
        let x = composer(&author, SUPERSEDES, &p, &room, t, "x", None);
        let y = composer(
            &author,
            SUPERSEDES,
            &p,
            &room,
            t + Duration::minutes(1),
            "y",
            None,
        );
        for r in [&x, &y] {
            a.apply_replicated_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .expect("I1508: A applies");
        }
        for r in [&y, &x] {
            b.apply_replicated_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .expect("I1508: B applies");
        }
        let (la, lb) = (live_ids(a, &author).await, live_ids(b, &author).await);
        assert!(
            la.contains(&y.attestation_id),
            "I1508: the later is A's head ({la:?})"
        );
        assert!(
            !la.contains(&x.attestation_id),
            "I1508: the earlier is hidden on A"
        );
        assert!(
            lb.contains(&y.attestation_id),
            "I1508: the later is B's head ({lb:?})"
        );
        assert!(
            !lb.contains(&x.attestation_id),
            "I1508: the earlier is hidden on B"
        );
        // A tie on the signed instant: the lower attestation_id bytewise.
        let at = t + Duration::minutes(5);
        let lo = composer(
            &author,
            SUPERSEDES,
            &p,
            &room,
            at,
            "lo",
            Some("00000000-0000-4000-8000-000000000001"),
        );
        let hi = composer(
            &author,
            SUPERSEDES,
            &p,
            &room,
            at,
            "hi",
            Some("ffffffff-0000-4000-8000-000000000001"),
        );
        for (n, order) in [(a, [&hi, &lo]), (b, [&lo, &hi])] {
            for r in order {
                n.apply_replicated_attestation(SignedAttestation {
                    attestation: r.clone(),
                })
                .await
                .expect("I1508: the tie applies");
            }
            let live = live_ids(n, &author).await;
            assert!(
                live.contains(&lo.attestation_id) && !live.contains(&hi.attestation_id),
                "I1508: the lower id wins the tie ({live:?})"
            );
        }
    }

    async fn convergence_room_on_peer<B>(
        a: &B,
        b: &B,
        author: &str,
        room: &str,
        p: &crate::federation::Attestation,
    ) where
        B: FederationDirectory + crate::read::ReadEngine,
    {
        use crate::federation::membership_acceptance_invariants::bodies::reg;
        use crate::federation::tier_ingest::test_support as ts;
        ts::register_hybrid_key_as(
            b,
            author,
            author,
            crate::federation::types::identity_type::USER,
        )
        .await;
        reg(b, &[room]).await;
        let rec = a
            .list_signed_communities_since(None, 1000)
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.community.community.community_key_id == room)
            .expect("A serves the room");
        b.put_community(rec.community)
            .await
            .expect("I1508: B takes the room");
        b.apply_replicated_attestation(SignedAttestation {
            attestation: p.clone(),
        })
        .await
        .expect("I1508: B takes the placement");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                #[tokio::test]
                async fn i1506_one_row_two_rooms_two_placements() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1506_one_row_two_rooms_two_placements(&d, &suffix())
                        .await
                }
                #[tokio::test]
                async fn i1507_the_authors_composers_name_the_placed_head() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1507_the_authors_composers_name_the_placed_head(
                        &d,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i1508_two_nodes_converge_on_one_head() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    super::super::two_node::i1508_two_nodes_converge_on_one_head(&a, &b, &suffix())
                        .await
                }
            }
        };
    }

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
