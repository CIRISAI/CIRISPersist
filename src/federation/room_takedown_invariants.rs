//! v61.4.0 (CIRISPersist#1260; CC 4.5.3, CC 4.5.5, CC 4.4.3.3.1) — **a room
//! moderator takes down a message or a file placed in the room.**
//!
//! Room content is written the way CIRISEdge writes it (`chat.rs`
//! `chat_row_shaped`, `files.rs` `file_row_at`): a `scores` row authored at
//! `self` scope and `local` tier, naming the room by `community_key_id`,
//! carrying a `community_dek` blob pointer under `content` and citing the
//! bytes in `evidence_refs`. It enters the mesh (`enter_mesh`) and is placed
//! in the room by a `supersedes` widening the author signs
//! (`FederationDirectory::widen_audience`, the door Edge's `share` takes).
//! Only the widening replicates.
//!
//! - **I1746** (two nodes; sqlite and postgres) — the takedown delivered
//!   through the planes. A is the author's node (it holds the `self` row and
//!   the widening); B is a member's node and receives the widening through
//!   `apply_replicated_attestation`. On B the room's founder takes the
//!   message down and the founder's `takedown` deputy the file
//!   (`community_standards`); both tombstones apply and withhold, and the
//!   same notices apply on A. A plain member of the room and a founder of
//!   another room are refused `takedown_unauthorised` on both nodes, and
//!   nothing is tombstoned. The `review` holder's `reversed` ruling, placed
//!   at the room's scope, is found and lifts the withholding. Once the
//!   author withdraws a placement (the `withdraws` delivered to B), its
//!   content binds into no room on either node and the founder is refused.
//! - **I1750** (two nodes; sqlite and postgres) — the two-person room: the
//!   founder takes the other member's placed message down on the founder's
//!   node and the notice applies on the author's; the member cannot take the
//!   founder's message down.
//! - **I1747** (sqlite and postgres) — the read.
//!   `attestations_binding_content_with_placements` returns the `scores`
//!   rows `attestations_binding_content` returns, plus the room placement;
//!   not a widening to `federation` scope. `attestations_binding_content`
//!   (the bytes plane, `subject_of_content`) is unchanged: it returns no
//!   `supersedes` row.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::doors_takedown_invariants::bodies::{delegate, notice, Claimant};
    use crate::federation::room_roster_authority_invariants::bodies::make_group;
    use crate::federation::steward_purge::purge_withheld;
    use crate::federation::takedown_reversal_invariants::bodies::{ruling, sha_bytes, sha_hex};
    use crate::federation::takedown_tombstone::{self as td, token};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, consensus_protocol,
    };
    use crate::federation::{
        Attestation, Audience, CrossingBasis, FederationDirectory, MeshCrossingOutcome,
        SignedAttestation,
    };

    const NODE: &str = "c-node-1";
    const BASIS: &str = "community_standards";

    /// Edge's room row: `self` / `local`, the room by `community_key_id`, a
    /// `community_dek` pointer under `content`, the bytes cited in
    /// `evidence_refs`. `file` makes it a `file:v1` row with a filename;
    /// otherwise a `chat:message:v1` message.
    fn edge_room_row(author: &str, room: &str, sha: &str, file: bool) -> Attestation {
        let mut env = serde_json::json!({
            "dimension": if file { "file:v1" } else { "chat:message:v1" },
            "community_key_id": room,
            "content": {
                "community_key_id": room,
                "tier": "community_dek",
                "content_sha256": sha,
                "content_field": "body",
                "media_type": if file { "image/jpeg" } else { "text/plain" },
            },
            "evidence_refs": [sha],
        });
        if file {
            env["filename"] = serde_json::json!("boat.jpg");
        } else {
            env["score"] = serde_json::json!(1.0);
            env["content_type"] = serde_json::json!("text/plain");
        }
        let id = format!(
            "{}-{}",
            if file { "file" } else { "chat" },
            uuid::Uuid::new_v4().simple()
        );
        let mut r = ts::bare_attestation(&id, author, author, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::SELF.into();
        r.tier = attestation_tier::LOCAL.into();
        r.subject_key_ids = vec![author.to_owned()];
        ts::reseal(&mut r);
        r
    }

    /// Write `row` on the author's node, enter it into the mesh, and place
    /// it at `audience` by the author's widening. Returns the `self` row's id
    /// and the widening.
    async fn write_and_place(
        d: &dyn FederationDirectory,
        row: Attestation,
        audience: Audience,
    ) -> (String, Attestation) {
        let id = row.attestation_id.clone();
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("the author's self row");
        let local = d.get_attestation(&id).await.unwrap().unwrap();
        d.enter_mesh(
            &id,
            &ts::describe_own(&local, CrossingBasis::ProducerAuthority),
            &ts::actor_reseal(&local),
        )
        .await
        .expect("the crossing");
        let prior = d.get_attestation(&id).await.unwrap().unwrap();
        assert_eq!(prior.cohort_scope, cohort_scope::SELF);
        let out = ts::widen(d, &prior, audience, &[])
            .await
            .expect("the placement");
        let MeshCrossingOutcome::Crossed(report) = out else {
            panic!("a placement crosses: {out:?}");
        };
        let w = d
            .get_attestation(&report.attestation_id)
            .await
            .unwrap()
            .expect("the widening is stored");
        assert_eq!(w.attestation_type, attestation_type::SUPERSEDES);
        (id, w)
    }

    fn room_audience(room: &str) -> Audience {
        Audience::Community {
            community_key_id: room.to_owned(),
        }
    }

    /// `issuer`'s `withdraws` of `target`, born in `room` as Edge's chat
    /// composers are (`chat.rs` `RowShape::composer`: `community` scope,
    /// federation tier, the room by `community_key_id`).
    fn withdraws(issuer: &str, target: &Attestation, room: &str) -> Attestation {
        let mut env = crate::federation::replication::withdraws_attestation_envelope(
            &target.attestation_id,
            &target.attestation_type,
        );
        env["dimension"] = serde_json::json!("chat:message:v1");
        env["community_key_id"] = serde_json::json!(room);
        env["kind"] = serde_json::json!(attestation_type::WITHDRAWS);
        env["reason_code"] = serde_json::json!("sent_in_error");
        let mut w = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), issuer, issuer, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.cohort_scope = cohort_scope::COMMUNITY.into();
        w.subject_key_ids = vec![issuer.to_owned()];
        w.weight = None;
        ts::seal_row_in_place(issuer, &mut w);
        w
    }

    async fn deliver(to: &dyn FederationDirectory, row: &Attestation) {
        let out = to
            .apply_replicated_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("delivery of {}: {e}", row.attestation_id));
        assert!(
            to.get_attestation(&row.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "{} is held after delivery: {out:?}",
            row.attestation_id
        );
    }

    fn who(k: &str) -> Claimant {
        Claimant { id: k.to_owned() }
    }

    /// `identity` occurs through `node`: its laptop, on every directory.
    async fn occurs_through(ds: &[&dyn FederationDirectory], identity: &str, node: &str) {
        for d in ds {
            d.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: identity.to_owned(),
                occurrence_key_id: node.to_owned(),
                device_class: crate::federation::types::device_class::LAPTOP.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap_or_else(|e| panic!("occurrence {node} of {identity}: {e}"));
        }
    }

    /// **I1746** — the takedown delivered through the planes. `node_a` and
    /// `node_b` are the two directories' declared node keys.
    pub(crate) async fn i1746_a_room_moderator_takes_down_placed_content(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        node_a: &str,
        node_b: &str,
        s: &str,
    ) {
        for d in [a, b] {
            for n in [node_a, node_b] {
                if d.lookup_public_key(n).await.unwrap().is_none() {
                    ts::register_hybrid_key_as(
                        d,
                        n,
                        n,
                        crate::federation::types::identity_type::NODE,
                    )
                    .await;
                }
            }
        }
        let tag = format!("i1746-{s}");
        let other_tag = format!("i1746x-{s}");
        let mut room = String::new();
        let mut keys = Vec::new();
        let mut other = Vec::new();
        for d in [a, b] {
            (room, keys) = make_group(
                d,
                &tag,
                consensus_protocol::MAJORITY,
                &["f", "author", "plain", "deputy"],
                1,
                None,
                None,
            )
            .await;
            (_, other) = make_group(
                d,
                &other_tag,
                consensus_protocol::MAJORITY,
                &["o", "m"],
                1,
                None,
                None,
            )
            .await;
        }
        let (founder, author, plain, deputy) = (&keys[0], &keys[1], &keys[2], &keys[3]);
        let other_founder = &other[0];
        // A is the author's laptop; B is the founder's, a member's node.
        occurs_through(&[a, b], author, node_a).await;
        occurs_through(&[a, b], founder, node_b).await;
        // The founder appoints its deputy on B; the appointment reaches A.
        let appointment = delegate(b, founder, deputy, &["takedown", "review"]).await;

        deliver(a, &b.get_attestation(&appointment).await.unwrap().unwrap()).await;

        // The author writes a message, a file and a second message, and
        // places each in the room, on A.
        let (sha_msg, sha_file, sha_gone) = (
            sha_hex(&format!("{tag}-msg")),
            sha_hex(&format!("{tag}-file")),
            sha_hex(&format!("{tag}-gone")),
        );
        let (msg_prior, msg) = write_and_place(
            a,
            edge_room_row(author, &room, &sha_msg, false),
            room_audience(&room),
        )
        .await;
        let (file_prior, file) = write_and_place(
            a,
            edge_room_row(author, &room, &sha_file, true),
            room_audience(&room),
        )
        .await;
        let (gone_prior, gone) = write_and_place(
            a,
            edge_room_row(author, &room, &sha_gone, false),
            room_audience(&room),
        )
        .await;

        // Only the widenings reach B.
        for (prior, w) in [
            (&msg_prior, &msg),
            (&file_prior, &file),
            (&gone_prior, &gone),
        ] {
            deliver(b, w).await;
            assert!(
                b.get_attestation(prior).await.unwrap().is_none(),
                "I1746: the self row never reaches B"
            );
        }

        // On both nodes the content binds into the room, with the author as
        // its subject.
        for (node, d) in [("A", a), ("B", b)] {
            for sha in [&sha_msg, &sha_file] {
                let binding = td::content_binding(d, sha).await.unwrap().unwrap();
                assert!(
                    binding.communities.contains(&room),
                    "I1746 {node}: the placement binds {sha} into the room: {binding:?}"
                );
                assert!(
                    binding.subjects.contains(author),
                    "I1746 {node}: the author is the subject: {binding:?}"
                );
            }
        }

        // Refused on both nodes: a plain member, another room's founder.
        for (node, d) in [("B", b), ("A", a)] {
            for k in [plain, other_founder] {
                let e = td::takedown_tombstone(d, &notice(&who(k), &sha_msg, BASIS), NODE)
                    .await
                    .expect_err("I1746: no duty over the room's content");
                assert_eq!(e.kind(), token::UNAUTHORISED, "I1746 {node} {k}: {e}");
                assert_eq!(d.purge_tombstoned("blob", &sha_msg).await.unwrap(), None);
            }
        }

        // The founder takes the message down, and the deputy the file, on B.
        let msg_notice = notice(&who(founder), &sha_msg, BASIS);
        let file_notice = notice(&who(deputy), &sha_file, BASIS);
        let by_founder = td::takedown_tombstone(b, &msg_notice, NODE)
            .await
            .expect("I1746: the room's founder takes the message down on B");
        assert!(by_founder.tombstoned);
        let by_deputy = td::takedown_tombstone(b, &file_notice, NODE)
            .await
            .expect("I1746: the founder's takedown deputy takes the file down on B");
        assert!(by_deputy.tombstoned);
        // The same notices apply on A, re-asked on A's own state.
        for n in [&msg_notice, &file_notice] {
            td::takedown_tombstone(a, n, NODE)
                .await
                .expect("I1746: the notice applies on the author's node");
        }
        for (node, d) in [("A", a), ("B", b)] {
            for sha in [&sha_msg, &sha_file] {
                assert!(
                    d.purge_tombstoned("blob", sha).await.unwrap().is_some(),
                    "I1746 {node}: {sha} is tombstoned"
                );
                assert!(
                    purge_withheld(d, &sha_bytes(sha)).await.unwrap().is_some(),
                    "I1746 {node}: {sha} is withheld"
                );
            }
        }

        // The review holder reverses the message's takedown at the room's
        // scope: the reversal is found through the placement.
        let notice_row = by_founder
            .notice_attestation_id
            .clone()
            .expect("a notice row");
        let e = b
            .put_attestation(SignedAttestation {
                attestation: ruling(
                    plain,
                    &notice_row,
                    "reversed",
                    cohort_scope::COMMUNITY,
                    &room,
                ),
            })
            .await
            .expect_err("I1746: a plain member does not rule");
        assert_eq!(e.kind(), "federation_delegated_scope_unauthorized", "{e}");
        b.put_attestation(SignedAttestation {
            attestation: ruling(
                deputy,
                &notice_row,
                "reversed",
                cohort_scope::COMMUNITY,
                &room,
            ),
        })
        .await
        .expect("I1746: the review deputy's reversal");
        assert!(
            td::takedown_reversal(b, &by_founder.notice_id)
                .await
                .unwrap()
                .is_some(),
            "I1746: the reversal names the takedown"
        );
        assert!(
            purge_withheld(b, &sha_bytes(&sha_msg))
                .await
                .unwrap()
                .is_none(),
            "I1746: the reversal lifts the withholding"
        );
        assert!(
            purge_withheld(b, &sha_bytes(&sha_file))
                .await
                .unwrap()
                .is_some(),
            "I1746: the file's takedown stands"
        );

        // A withdrawn placement binds nothing: the author withdraws the third
        // placement on A, and the withdraws reaches B.
        let w = withdraws(author, &gone, &room);
        a.put_attestation(SignedAttestation {
            attestation: w.clone(),
        })
        .await
        .expect("I1746: the author withdraws the placement");
        deliver(
            b,
            &a.get_attestation(&w.attestation_id).await.unwrap().unwrap(),
        )
        .await;
        for (node, d) in [("A", a), ("B", b)] {
            let binding = td::content_binding(d, &sha_gone).await.unwrap().unwrap();
            assert!(
                binding.communities.is_empty(),
                "I1746 {node}: a withdrawn placement binds no room: {binding:?}"
            );
            let e = td::takedown_tombstone(d, &notice(&who(founder), &sha_gone, BASIS), NODE)
                .await
                .expect_err("I1746: no room holds the duty over withdrawn content");
            assert_eq!(e.kind(), token::UNAUTHORISED, "I1746 {node}: {e}");
        }
    }

    /// **I1750** — the two-person room (CC 4.5.5): a room of a founder and
    /// one other member. The founder's node receives the member's placement
    /// and takes the member's message down there; the notice applies on the
    /// author's node too. The member takes down their own placed message on
    /// the founder's node, as its subject (C536 (a), CC 4.5.5 (a)); the member,
    /// who is no moderator, cannot take down the founder's message (they are
    /// its author's peer, not its subject).
    pub(crate) async fn i1750_a_founder_takes_down_in_a_room_of_two(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        node_a: &str,
        node_b: &str,
        s: &str,
    ) {
        for d in [a, b] {
            for n in [node_a, node_b] {
                if d.lookup_public_key(n).await.unwrap().is_none() {
                    ts::register_hybrid_key_as(
                        d,
                        n,
                        n,
                        crate::federation::types::identity_type::NODE,
                    )
                    .await;
                }
            }
        }
        let tag = format!("i1750-{s}");
        let mut room = String::new();
        let mut keys = Vec::new();
        for d in [a, b] {
            (room, keys) = make_group(
                d,
                &tag,
                consensus_protocol::MAJORITY,
                &["f", "member"],
                1,
                None,
                None,
            )
            .await;
        }
        let (founder, member) = (&keys[0], &keys[1]);
        occurs_through(&[a, b], member, node_a).await;
        occurs_through(&[a, b], founder, node_b).await;

        let sha = sha_hex(&format!("{tag}-msg"));
        let (_, placed) = write_and_place(
            a,
            edge_room_row(member, &room, &sha, false),
            room_audience(&room),
        )
        .await;
        deliver(b, &placed).await;
        let n = notice(&who(founder), &sha, BASIS);
        td::takedown_tombstone(b, &n, NODE)
            .await
            .expect("I1750: the founder takes the other member's message down");
        td::takedown_tombstone(a, &n, NODE)
            .await
            .expect("I1750: the notice applies on the author's node");
        for d in [a, b] {
            assert!(purge_withheld(d, &sha_bytes(&sha)).await.unwrap().is_some());
        }

        // C536 (a) (CC 4.5.5 (a), "the target content's own subject"): the
        // author takes down their own placed message, on the founder's node,
        // which holds only the placement: its signed subjects are the
        // author's.
        let sha_own = sha_hex(&format!("{tag}-own"));
        let (_, placed_own) = write_and_place(
            a,
            edge_room_row(member, &room, &sha_own, false),
            room_audience(&room),
        )
        .await;
        deliver(b, &placed_own).await;
        let own = td::takedown_tombstone(b, &notice(&who(member), &sha_own, BASIS), NODE)
            .await
            .expect("I1750: the content's subject takes it down where only the placement is held");
        assert!(own.tombstoned);

        // The other way round: the founder's message, the member's notice.
        let sha_f = sha_hex(&format!("{tag}-founder"));
        let (_, placed_f) = write_and_place(
            b,
            edge_room_row(founder, &room, &sha_f, false),
            room_audience(&room),
        )
        .await;
        deliver(a, &placed_f).await;
        let e = td::takedown_tombstone(a, &notice(&who(member), &sha_f, BASIS), NODE)
            .await
            .expect_err("I1750: a plain member holds no takedown over a peer's message");
        assert_eq!(e.kind(), token::UNAUTHORISED, "I1750: {e}");
    }

    /// **I1747** — the read, and the bytes-plane read beside it unchanged.
    pub(crate) async fn i1747_the_binding_read_with_placements(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let tag = format!("i1747-{s}");
        let (room, keys) = make_group(
            d,
            &tag,
            consensus_protocol::MAJORITY,
            &["f", "author"],
            1,
            None,
            None,
        )
        .await;
        let author = &keys[1];
        let sha = sha_hex(&format!("{tag}-a"));
        let (prior_id, placed) = write_and_place(
            d,
            edge_room_row(author, &room, &sha, false),
            room_audience(&room),
        )
        .await;
        // A row with no room, widened to `federation` scope.
        let sha_pub = sha_hex(&format!("{tag}-b"));
        let mut public = edge_room_row(author, &room, &sha_pub, false);
        public
            .attestation_envelope
            .as_object_mut()
            .unwrap()
            .remove("community_key_id");
        public.attestation_envelope["content"]["tier"] = serde_json::json!("plaintext");
        public.attestation_envelope["content"]["community_key_id"] = serde_json::json!("");
        ts::reseal(&mut public);
        let (_, widened) = write_and_place(d, public, Audience::Federation).await;

        let ids = |rows: Vec<Attestation>| {
            let mut v: Vec<String> = rows.into_iter().map(|r| r.attestation_id).collect();
            v.sort();
            v
        };
        let mut both = vec![prior_id.clone(), placed.attestation_id.clone()];
        both.sort();
        assert_eq!(
            ids(d
                .attestations_binding_content_with_placements(&sha)
                .await
                .unwrap()),
            both,
            "I1747: the self row and its room placement"
        );
        assert_eq!(
            ids(d.attestations_binding_content(&sha).await.unwrap()),
            vec![prior_id],
            "I1747: the bytes-plane read is unchanged: no supersedes"
        );
        let pub_rows = ids(d
            .attestations_binding_content_with_placements(&sha_pub)
            .await
            .unwrap());
        assert!(
            !pub_rows.contains(&widened.attestation_id),
            "I1747: a widening to federation scope places nothing in a room: {pub_rows:?}"
        );
        assert_eq!(
            pub_rows,
            ids(d.attestations_binding_content(&sha_pub).await.unwrap()),
            "I1747: outside a room the two reads agree"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite(node: &str) -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, node).await;
        b
    }

    #[cfg(feature = "postgres")]
    async fn postgres(node: &str) -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, node).await;
        Some(b)
    }

    fn nodes(s: &str) -> (String, String) {
        (format!("i1746-node-a-{s}"), format!("i1746-node-b-{s}"))
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1746_sqlite() {
        let s = suffix();
        let (na, nb) = nodes(&s);
        let (a, b) = (sqlite(&na).await, sqlite(&nb).await);
        super::bodies::i1746_a_room_moderator_takes_down_placed_content(&a, &b, &na, &nb, &s).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1746_postgres() {
        let s = suffix();
        let (na, nb) = nodes(&s);
        let (Some(a), Some(b)) = (postgres(&na).await, postgres(&nb).await) else {
            return;
        };
        super::bodies::i1746_a_room_moderator_takes_down_placed_content(&a, &b, &na, &nb, &s).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1750_sqlite() {
        let s = suffix();
        let (na, nb) = nodes(&s);
        let (a, b) = (sqlite(&na).await, sqlite(&nb).await);
        super::bodies::i1750_a_founder_takes_down_in_a_room_of_two(&a, &b, &na, &nb, &s).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1750_postgres() {
        let s = suffix();
        let (na, nb) = nodes(&s);
        let (Some(a), Some(b)) = (postgres(&na).await, postgres(&nb).await) else {
            return;
        };
        super::bodies::i1750_a_founder_takes_down_in_a_room_of_two(&a, &b, &na, &nb, &s).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1747_sqlite() {
        super::bodies::i1747_the_binding_read_with_placements(&sqlite("dt-node").await, &suffix())
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1747_postgres() {
        let Some(d) = postgres("dt-node").await else {
            return;
        };
        super::bodies::i1747_the_binding_read_with_placements(&d, &suffix()).await;
    }
}
