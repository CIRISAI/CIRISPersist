//! v48.0.0 (CIRISPersist#860, `FSD/ROOM_ROSTER_PLANES.md` §4) — **a room's
//! roster converges both ways.** A room (and a family) is a keyless
//! identifier: the membership planes reference the group table, never
//! `federation_keys`; growth is an append plane like removal; one fold
//! decides.
//!
//! I163 and I165 need the DEK epoch counter, which lives on `BlobStorage`
//! (sqlite + postgres); I164 and I166 are pure directory folds and run on
//! memory too.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::blobs::BlobStorage;
    use crate::federation::community_dek::lifecycle_support as dek;
    use crate::federation::operational::test_support as ops;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, identity_type, Community, CommunityMember,
        CommunityMembershipRevocation, FamilyMembershipRevocation,
    };
    use crate::federation::FederationDirectory;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// A room whose id is registered as NO key: two seeded members, founded
    /// and signed by the first (a room is not a person, so a member is the
    /// authority).
    pub async fn keyless_room<B>(b: &B, tag: &str) -> (String, String, String)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let room = format!("{tag}-room");
        let alice = format!("{tag}-alice");
        let bob = format!("{tag}-bob");
        dek::seed_member(b, &alice, &format!("{alice}-occ")).await;
        dek::seed_member(b, &bob, &format!("{bob}-occ")).await;
        assert!(
            b.lookup_public_key(&room).await.unwrap().is_none(),
            "{tag}: the room id is not a key"
        );
        let roster = [&alice, &bob]
            .into_iter()
            .map(|k| CommunityMember {
                key_id: k.clone(),
                joined_at: at("2026-01-01T00:00:00Z"),
                role: None,
            })
            .collect();
        b.put_community(ts::sign_community(
            &alice,
            Community {
                community_key_id: room.clone(),
                community_name: "keyless room".into(),
                members: roster,
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: consensus_protocol::MAJORITY.to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: a keyless room is admitted today: {e}"));
        (room, alice, bob)
    }

    fn revocation(
        room: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
    ) -> CommunityMembershipRevocation {
        CommunityMembershipRevocation {
            community_key_id: room.to_owned(),
            removed_identity_key_id: member.to_owned(),
            removed_at: effective_at,
            effective_at,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        }
    }

    /// **I163 — a keyless room (and a keyless family) can revoke.**
    pub async fn i163_a_keyless_room_can_revoke<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (room, alice, bob) = keyless_room(b, tag).await;
        // The rotation is observed the way the lifecycle witnesses observe it:
        // the minter's next seal lands at the next epoch.
        let before = crate::federation::community_dek::orchestrate::encrypt_and_cascade_community(
            b,
            &room,
            b"before",
            None,
            Some(&alice),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: seal before: {e}"));
        b.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &alice,
            revocation(&room, &bob, at("2026-02-01T00:00:00Z")),
        ))
        .await
        .unwrap_or_else(|e| {
            panic!("{tag} I163: a room that is not a key must still be able to revoke: {e}")
        });
        let active: Vec<String> = b
            .active_community_members(&room)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert_eq!(active, vec![alice.clone()], "{tag} I163: bob is gone");
        let after = crate::federation::community_dek::orchestrate::encrypt_and_cascade_community(
            b,
            &room,
            b"after",
            None,
            Some(&alice),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: seal after: {e}"));
        assert_eq!(
            after.epoch,
            before.epoch + 1,
            "{tag} I163: the §15 rotation is reachable for a keyless room"
        );
        assert!(
            !after.granted.iter().any(|g| g.contains(&bob)),
            "{tag} I163: the rotated epoch is not wrapped for the removed member: {:?}",
            after.granted
        );

        // The family twin: a keyless family (the doctrine) can revoke a seat.
        let fam = format!("{tag}-fam");
        let holders: Vec<String> = (0..2).map(|i| format!("{tag}-h{i}")).collect();
        for h in &holders {
            ops::register_typed_key(b, h, identity_type::NODE)
                .await
                .unwrap();
        }
        assert!(b.lookup_public_key(&fam).await.unwrap().is_none());
        ops::seed_test_family(b, &fam, &holders, "quorum:2/2")
            .await
            .unwrap();
        b.put_family_membership_revocation(ts::sign_family_membership_revocation(
            &holders[0],
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: holders[1].clone(),
                removed_at: at("2026-02-01T00:00:00Z"),
                effective_at: at("2026-02-01T00:00:00Z"),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| {
            panic!("{tag} I163: a keyless family must be able to revoke a seat: {e}")
        });
        let seats: Vec<String> = b
            .active_family_members(&fam)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert_eq!(
            seats,
            vec![holders[0].clone()],
            "{tag} I163: the seat is gone"
        );
    }

    fn widening(
        room: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::types::CommunityMembershipWidening {
        crate::federation::types::CommunityMembershipWidening {
            community_key_id: room.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: effective_at,
            effective_at,
            role: None,
            persist_row_hash: String::new(),
        }
    }

    /// A room on a plain directory (no blob storage needed): two seeded
    /// `user` members, founded and signed by the first, the room id no key.
    pub async fn keyless_room_dir(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, String, String) {
        keyless_room_dir_with(d, tag, consensus_protocol::MAJORITY).await
    }

    /// [`keyless_room_dir`] under a chosen consensus protocol.
    pub async fn keyless_room_dir_with(
        d: &dyn FederationDirectory,
        tag: &str,
        protocol: &str,
    ) -> (String, String, String) {
        let room = format!("{tag}-room");
        let alice = format!("{tag}-alice");
        let bob = format!("{tag}-bob");
        for k in [&alice, &bob] {
            ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
        }
        let roster = [&alice, &bob]
            .into_iter()
            .map(|k| CommunityMember {
                key_id: k.clone(),
                joined_at: at("2026-01-01T00:00:00Z"),
                role: None,
            })
            .collect();
        d.put_community(ts::sign_community(
            &alice,
            Community {
                community_key_id: room.clone(),
                community_name: "keyless room".into(),
                members: roster,
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: protocol.to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: room: {e}"));
        (room, alice, bob)
    }

    async fn roster(d: &dyn FederationDirectory, room: &str) -> Vec<String> {
        let mut v: Vec<String> = d
            .active_community_members(room)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        v.sort();
        v
    }

    /// Replicate the room record from `a` to `b` the way a peer does: the
    /// served signed record, applied through `put_community`.
    async fn replicate_room(a: &dyn FederationDirectory, b: &dyn FederationDirectory, room: &str) {
        let served = a.list_signed_communities_since(None, 100).await.unwrap();
        let rec = served
            .into_iter()
            .map(|s| s.community)
            .find(|s| s.community.community_key_id == room)
            .expect("the room is served");
        b.put_community(rec).await.unwrap();
    }

    /// **I164 — a widening converges.** Two directories; the record is
    /// byte-identical on both before and after; the widening row, served by
    /// A and applied on B, makes B's fold equal A's. A spec over the GROWN
    /// RECORD (edge's v47 shape) is refused.
    pub async fn i164_a_widening_converges(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (room, alice, bob) = keyless_room_dir(a, tag).await;
        let carol = format!("{tag}-carol");
        for d in [a, b] {
            ts::register_hybrid_key_as(d, &carol, &carol, identity_type::USER).await;
        }
        // B holds the original record, as a peer would.
        for k in [&alice, &bob] {
            ts::register_hybrid_key_as(b, k, k, identity_type::USER).await;
        }
        replicate_room(a, b, &room).await;
        let record_before_a = a.lookup_community(&room).await.unwrap().unwrap();
        let record_before_b = b.lookup_community(&room).await.unwrap().unwrap();
        assert_eq!(
            record_before_a, record_before_b,
            "{tag} I164: same bytes on both nodes"
        );

        // A widens carol through the local door — the spec is over the widening row.
        let member = CommunityMember {
            key_id: carol.clone(),
            joined_at: at("2026-03-01T00:00:00Z"),
            role: None,
        };
        let spec = ts::widening_admit_spec(&alice, &room, &member);
        let added = a
            .add_community_member(&room, member.clone(), &spec)
            .await
            .unwrap_or_else(|e| panic!("{tag} I164: widen on A: {e}"));
        assert!(added, "{tag} I164: a new row");
        assert_eq!(
            roster(a, &room).await,
            vec![alice.clone(), bob.clone(), carol.clone()]
        );
        assert!(
            !a.add_community_member(&room, member.clone(), &spec)
                .await
                .unwrap(),
            "{tag} I164: the byte-identical row is a no-op"
        );
        assert_eq!(
            a.lookup_community(&room).await.unwrap().unwrap(),
            record_before_a,
            "{tag} I164: the RECORD did not move on A — growth rides the plane"
        );

        // The widening row travels; B applies it; B's fold = A's; B's record unchanged.
        let served = a
            .list_signed_community_membership_widenings_since(None, 100)
            .await
            .unwrap();
        assert_eq!(
            served.len(),
            1,
            "{tag} I164: one widening served: {served:?}"
        );
        let (resume_at, resume_id) = served[0].resume_pair();
        assert!(
            resume_id.contains(&carol),
            "{tag} I164: the resume id names the member"
        );
        b.put_community_membership_widening(served[0].widening.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I164: the widening applies on B: {e}"));
        assert_eq!(
            roster(b, &room).await,
            roster(a, &room).await,
            "{tag} I164: B converged"
        );
        assert_eq!(
            b.lookup_community(&room).await.unwrap().unwrap(),
            record_before_b,
            "{tag} I164: the RECORD did not move on B — no fork"
        );
        // The cursor placed at the served row yields nothing more.
        assert!(a
            .list_signed_community_membership_widenings_since(Some((resume_at, resume_id)), 100)
            .await
            .unwrap()
            .is_empty());

        // A spec over the GROWN RECORD — edge's v47 shape — no longer verifies.
        let dave = format!("{tag}-dave");
        ts::register_hybrid_key_as(a, &dave, &dave, identity_type::USER).await;
        let mut grown = a.lookup_community(&room).await.unwrap().unwrap();
        let dave_member = CommunityMember {
            key_id: dave.clone(),
            joined_at: at("2026-03-02T00:00:00Z"),
            role: None,
        };
        grown.members.push(dave_member.clone());
        grown.persist_row_hash = String::new();
        let (_h, classical, pqc) = ts::sign_envelope(&alice, &grown.signing_envelope());
        let stale_spec = crate::federation::cohort::AdmitSpec {
            authority_key_id: alice.clone(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        };
        let err = a
            .add_community_member(&room, dave_member, &stale_spec)
            .await
            .expect_err("I164: a scrub over the grown record is not a scrub over the widening");
        assert!(
            err.kind().contains("unverified") || err.to_string().contains("verify"),
            "{tag} I164: refused for the signature: {err}"
        );
        assert_eq!(roster(a, &room).await, vec![alice, bob, carol]);
    }

    /// **I165 — order does not matter.** The four events applied in three
    /// orders on three directories yield one fold, and the repeat is a no-op.
    pub async fn i165_order_does_not_matter(dirs: [&dyn FederationDirectory; 3], tag: &str) {
        let t1 = at("2026-03-01T00:00:00Z");
        let t2 = at("2026-03-02T00:00:00Z");
        let t3 = at("2026-03-03T00:00:00Z");
        let t4 = at("2026-03-04T00:00:00Z");
        let mut rooms = Vec::new();
        for (i, d) in dirs.iter().enumerate() {
            let tg = format!("{tag}-{i}");
            let (room, alice, _bob) = keyless_room_dir(*d, &tg).await;
            let carol = format!("{tg}-carol");
            ts::register_hybrid_key_as(*d, &carol, &carol, identity_type::USER).await;
            let w1 = ts::sign_community_membership_widening(&alice, widening(&room, &carol, t1));
            let r2 =
                ts::sign_community_membership_revocation(&alice, revocation(&room, &carol, t2));
            let w3 = ts::sign_community_membership_widening(&alice, widening(&room, &carol, t3));
            let r4 =
                ts::sign_community_membership_revocation(&alice, revocation(&room, &carol, t4));
            let events: Vec<(&str, usize)> = match i {
                0 => vec![("w", 1), ("r", 2), ("w", 3), ("r", 4)],
                1 => vec![("r", 4), ("w", 3), ("r", 2), ("w", 1)],
                _ => vec![("r", 2), ("r", 4), ("w", 1), ("w", 3)],
            };
            for (kind, n) in events {
                match (kind, n) {
                    ("w", 1) => d.put_community_membership_widening(w1.clone()).await,
                    ("w", 3) => d.put_community_membership_widening(w3.clone()).await,
                    ("r", 2) => d.put_community_membership_revocation(r2.clone()).await,
                    _ => d.put_community_membership_revocation(r4.clone()).await,
                }
                .unwrap_or_else(|e| panic!("{tg} I165: every row admits in every order: {e}"));
            }
            // The exact repeat of r2 is a no-op (#861 kept); the fold is one.
            d.put_community_membership_revocation(r2.clone())
                .await
                .unwrap();
            assert_eq!(
                d.list_community_membership_revocations_for(&room)
                    .await
                    .unwrap()
                    .len(),
                2,
                "{tg} I165: two removal events, the repeat added nothing"
            );
            assert_eq!(
                d.list_community_membership_widenings_for(&room)
                    .await
                    .unwrap()
                    .len(),
                2
            );
            rooms.push((room, carol));
        }
        for (i, d) in dirs.iter().enumerate() {
            let (room, carol) = &rooms[i];
            let now_after = roster(*d, room).await;
            assert!(
                !now_after.contains(carol),
                "{tag}-{i} I165: after t4 carol is out: {now_after:?}"
            );
            // The fold at an instant between t3 and t4: carol is in.
            let rec = d.lookup_community(room).await.unwrap().unwrap();
            let ws = d
                .list_community_membership_widenings_for(room)
                .await
                .unwrap();
            let rs = d
                .list_community_membership_revocations_for(room)
                .await
                .unwrap();
            let at_t3 = crate::federation::active_roster_at(
                &rec.members,
                &ws,
                &rs,
                t3 + chrono::Duration::hours(1),
            );
            assert!(
                at_t3.iter().any(|m| &m.key_id == carol),
                "{tag}-{i} I165: between t3 and t4 carol is in"
            );
            let at_t2 = crate::federation::active_roster_at(
                &rec.members,
                &ws,
                &rs,
                t2 + chrono::Duration::hours(1),
            );
            assert!(!at_t2.iter().any(|m| &m.key_id == carol));
            // A tie at one instant: the removal wins.
            let tie = crate::federation::active_roster_at(
                &rec.members,
                &[widening(room, carol, t4)],
                &[revocation(room, carol, t4)],
                t4,
            );
            assert!(
                !tie.iter().any(|m| &m.key_id == carol),
                "{tag} I165: a tie removes"
            );
        }
    }

    /// **I166 — a raw roster read is a wrong read.** After a widening every
    /// read-time gate sees the member; after her revocation none does.
    pub async fn i166_a_raw_roster_read_is_a_wrong_read(d: &dyn FederationDirectory, tag: &str) {
        // FOUNDER_ONLY with no founder on the record: the moderator gate
        // refuses until a founder is WIDENED in, and refuses again once she
        // is revoked — a leg only the fold can pass.
        let (room, alice, _bob) =
            keyless_room_dir_with(d, tag, consensus_protocol::FOUNDER_ONLY).await;
        let record0 = d.lookup_community(&room).await.unwrap().unwrap();
        assert!(
            crate::federation::admission::check_no_moderator_federate_admission(d, &record0)
                .await
                .is_err(),
            "{tag} I166: control — no founder on the record, no moderator"
        );
        let carol = format!("{tag}-carol");
        ts::register_hybrid_key_as(d, &carol, &carol, identity_type::USER).await;
        let member = CommunityMember {
            key_id: carol.clone(),
            joined_at: at("2026-03-01T00:00:00Z"),
            role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.into()),
        };
        d.add_community_member(
            &room,
            member.clone(),
            &ts::widening_admit_spec(&alice, &room, &member),
        )
        .await
        .unwrap();
        let record = d.lookup_community(&room).await.unwrap().unwrap();
        assert!(
            !record.members.iter().any(|m| m.key_id == carol),
            "{tag} I166: the record does not carry the widening — every gate must fold"
        );
        assert!(
            crate::federation::is_active_community_member(d, &room, &carol)
                .await
                .unwrap(),
            "{tag} I166: the fold sees carol"
        );
        // The gates that used to read `community.members`.
        crate::federation::admission::check_no_moderator_federate_admission(d, &record)
            .await
            .unwrap_or_else(|e| panic!("{tag} I166: the widened founder is the moderator: {e}"));
        let authority = crate::federation::admission::community_authority_set_for(d, &record)
            .await
            .unwrap();
        assert!(
            authority.contains(&carol),
            "{tag} I166: community_authority_set folds"
        );
        let wrap_set =
            crate::federation::community_dek::orchestrate::active_member_key_ids(d, &record)
                .await
                .unwrap();
        assert!(
            wrap_set.contains(&carol),
            "{tag} I166: the DEK wrap set folds: {wrap_set:?}"
        );

        d.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &alice,
            revocation(&room, &carol, at("2026-04-01T00:00:00Z")),
        ))
        .await
        .unwrap();
        assert!(
            !crate::federation::is_active_community_member(d, &room, &carol)
                .await
                .unwrap()
        );
        assert!(
            crate::federation::admission::check_no_moderator_federate_admission(d, &record)
                .await
                .is_err(),
            "{tag} I166: revoked, no moderator again"
        );
        let authority = crate::federation::admission::community_authority_set_for(d, &record)
            .await
            .unwrap();
        assert!(!authority.contains(&carol));
        let wrap_set =
            crate::federation::community_dek::orchestrate::active_member_key_ids(d, &record)
                .await
                .unwrap();
        assert!(
            !wrap_set.contains(&carol),
            "{tag} I166: not wrapped after removal"
        );
    }

    /// **I167 — the since-read resumes across the three-part id.**
    pub async fn i167_the_since_read_resumes_across_the_three_part_id(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (room, alice, bob) = keyless_room_dir(d, tag).await;
        let t1 = at("2026-03-01T00:00:00Z");
        let t2 = at("2026-03-02T00:00:00Z");
        let t3 = at("2026-03-03T00:00:00Z");
        d.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &alice,
            revocation(&room, &bob, t1),
        ))
        .await
        .unwrap();
        d.put_community_membership_widening(ts::sign_community_membership_widening(
            &alice,
            widening(&room, &bob, t2),
        ))
        .await
        .unwrap();
        d.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &alice,
            revocation(&room, &bob, t3),
        ))
        .await
        .unwrap();
        let all = d
            .list_signed_community_membership_revocations_since(None, 100)
            .await
            .unwrap();
        let mine: Vec<_> = all
            .iter()
            .filter(|s| {
                s.revocation
                    .community_membership_revocation
                    .community_key_id
                    == room
            })
            .collect();
        assert_eq!(
            mine.len(),
            2,
            "{tag} I167: two removals of one member are two served rows"
        );
        let (at1, id1) = mine[0].resume_pair();
        assert!(
            id1.contains(&t1.to_rfc3339()) || id1.contains("2026-03-01"),
            "{tag} I167: the id carries the instant: {id1}"
        );
        let rest = d
            .list_signed_community_membership_revocations_since(Some((at1, id1)), 100)
            .await
            .unwrap();
        let rest: Vec<_> = rest
            .iter()
            .filter(|s| {
                s.revocation
                    .community_membership_revocation
                    .community_key_id
                    == room
            })
            .collect();
        assert_eq!(
            rest.len(),
            1,
            "{tag} I167: the cursor between the two resumes at the second"
        );
        assert_eq!(
            rest[0]
                .revocation
                .community_membership_revocation
                .effective_at,
            t3
        );
        assert!(
            !roster(d, &room).await.contains(&bob),
            "{tag} I167: bob is out after t3"
        );
        // Both removals are content-hash addressable and distinct: the
        // wire-index key names WHICH removal (the three-part PK).
        let mut seen = std::collections::BTreeSet::new();
        for s in &mine {
            let hash = crate::federation::wire_index::content_hash_of(&s.revocation).unwrap();
            let bytes = d
                .lookup_signed_record_by_content_hash("CommunityMembershipRevocation", &hash)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{tag} I167: revocation {hash} is addressable by hash"));
            let back: crate::federation::SignedCommunityMembershipRevocation =
                serde_json::from_slice(&bytes).unwrap();
            assert!(
                seen.insert(back.community_membership_revocation.effective_at),
                "{tag} I167: each hash resolves to its own removal"
            );
        }
        assert_eq!(seen.len(), 2);
        // The widening is addressable the same way.
        let served_w = d
            .list_signed_community_membership_widenings_since(None, 100)
            .await
            .unwrap();
        let w = served_w
            .iter()
            .find(|w| w.widening.community_membership_widening.community_key_id == room)
            .expect("the widening is served");
        let whash = crate::federation::wire_index::content_hash_of(&w.widening).unwrap();
        let wbytes = d
            .lookup_signed_record_by_content_hash("CommunityMembershipWidening", &whash)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{tag} I167: the widening is addressable by hash"));
        let wback: crate::federation::SignedCommunityMembershipWidening =
            serde_json::from_slice(&wbytes).unwrap();
        assert_eq!(wback, w.widening, "{tag} I167: byte-exact by hash");
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[cfg(feature = "sqlite")]
    mod sqlite {
        #[tokio::test]
        async fn i163() {
            use crate::store::Backend as _;
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            super::super::bodies::i163_a_keyless_room_can_revoke(
                &b,
                &format!("i163-{}", super::suffix()),
            )
            .await
        }
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i164() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i164_a_widening_converges(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i164-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i165() {
                    let (Some(a), Some(b), Some(c)) = ($fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    super::super::bodies::i165_order_does_not_matter(
                        [
                            &a as &dyn FederationDirectory,
                            &b as &dyn FederationDirectory,
                            &c as &dyn FederationDirectory,
                        ],
                        &format!("i165-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i166() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i166_a_raw_roster_read_is_a_wrong_read(
                        &d as &dyn FederationDirectory,
                        &format!("i166-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i167() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i167_the_since_read_resumes_across_the_three_part_id(
                        &d as &dyn FederationDirectory,
                        &format!("i167-{}", super::suffix()),
                    )
                    .await
                }
            }
        };
    }

    dyn_runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres_dyn, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    mod postgres {
        #[tokio::test]
        async fn i163() {
            use crate::store::Backend as _;
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                return;
            };
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            super::super::bodies::i163_a_keyless_room_can_revoke(
                &b,
                &format!("i163-{}", super::suffix()),
            )
            .await
        }
    }
}
