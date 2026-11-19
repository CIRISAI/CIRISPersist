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
    use crate::federation::edition2::fixture_switch as e2;

    use crate::federation::room_roster_authority_invariants::bodies::{revoke_by, widen_by};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        identity_type, Community, CommunityMember, CommunityMembershipRevocation,
        FamilyMembershipRevocation,
    };
    use crate::federation::FederationDirectory;

    /// v62 (E4, round 3): a key seed for `name` in the test tagged `tag`.
    /// A test signer seeds from the FIRST 32 BYTES of its seed, so
    /// `format!("{tag}-{name}")` with a long tag gives every name ONE key
    /// (and a room the same id as its members): `members` then repeats a key
    /// and the roster payload is refused. The tag is folded into a short
    /// digest after the distinguishing name.
    pub(crate) fn sd(name: &str, tag: &str) -> String {
        use sha2::Digest as _;
        let h = hex::encode(sha2::Sha256::digest(tag.as_bytes()));
        format!("{name}-{}", &h[..16])
    }

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
        let room = sd("room", tag);
        let alice = sd("alice", tag);
        let bob = sd("bob", tag);
        dek::seed_member(b, &alice, &format!("{alice}-occ")).await;
        dek::seed_member(b, &bob, &format!("{bob}-occ")).await;
        assert!(
            b.lookup_public_key(&e2::kid(&room))
                .await
                .unwrap()
                .is_none(),
            "{tag}: the room id is not a key"
        );
        let roster = [&alice, &bob]
            .into_iter()
            .map(|k| CommunityMember {
                key_id: k.clone(),
                joined_at: at("2026-01-01T00:00:00Z"),
                // v49.0.0 (#908): alice founds the room — under founder_only
                // her signature alone is the protocol (CC 4.4.3.4.2).
                role: (*k == alice)
                    .then(|| crate::federation::admission::MEMBER_ROLE_FOUNDER.into()),
            })
            .collect();
        // v62 (E4, flip wave 2): the record is its `group:roster` voices
        // (T1); the returned ids are the identity-refs the typed rows use.
        let signed = ts::sign_community(
            &alice,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: room.clone(),
                community_name: "keyless room".into(),
                members: roster,
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: "quorum:1/1".into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        e2::put_voices(
            b,
            &e2::community_voices(&signed, 1, None, ms(at("2026-01-01T00:00:00Z"))),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: a keyless room is admitted today: {e}"));
        (e2::kid(&room), e2::kid(&alice), e2::kid(&bob))
    }

    fn ms(t: chrono::DateTime<chrono::Utc>) -> u64 {
        u64::try_from(t.timestamp_millis()).expect("after the epoch")
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
        revoke_by(
            b,
            &[&alice],
            revocation(&room, &bob, at("2026-02-01T00:00:00Z")),
        )
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
        // v62 (E4): its holders are `node` keys, so its rows are now-relative
        // (CC 2.4.1.1: a node key's rows lapse with its record).
        let fam_s = sd("fam", tag);
        let fam = e2::kid(&fam_s);
        let holders: Vec<String> = (0..2).map(|i| sd(&format!("h{i}"), tag)).collect();
        for h in &holders {
            e2::put_key(b, h, &[identity_type::NODE]).await;
        }
        assert!(b.lookup_public_key(&fam).await.unwrap().is_none());
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let family = crate::federation::types::Family {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            family_key_id: fam_s.clone(),
            family_name: format!("{tag} family"),
            members: holders
                .iter()
                .enumerate()
                .map(|(i, k)| crate::federation::types::FamilyMember {
                    key_id: k.clone(),
                    joined_at: now,
                    role: (i == 0).then(|| "founder".to_owned()),
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "quorum:2/2".to_owned(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        e2::put_voices(
            b,
            &e2::family_voices(&ts::sign_family(&holders[0], family), 1, None, ms(now)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I163: the family: {e}"));
        let (head, _) = e2::held_head(b, &fam)
            .await
            .expect("I163: the family's head");
        // v49.0.0 (#910): signed by the family's own `quorum:2/2` — both seats.
        let signed = ts::sign_family_revocation_by_consensus(
            b,
            FamilyMembershipRevocation {
                family_key_id: fam_s.clone(),
                removed_identity_key_id: holders[1].clone(),
                removed_at: now,
                effective_at: now,
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        )
        .await;
        e2::put_voices(b, &e2::family_revocation_voices(&signed, Some(&head)))
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
            vec![e2::kid(&holders[0])],
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
        keyless_room_dir_with(d, tag, "quorum:1/1").await
    }

    /// [`keyless_room_dir`] under a chosen consensus protocol.
    pub async fn keyless_room_dir_with(
        d: &dyn FederationDirectory,
        tag: &str,
        protocol: &str,
    ) -> (String, String, String) {
        // v62 (round 3, L1) — the role LEADS the seed. A test signer seeds
        // from a key name's first 32 bytes (`seed_for`), and a caller's tag is
        // often a 32-hex uuid: `{tag}-alice` and `{tag}-bob` were then ONE
        // keypair, so the roster named one member twice and `group:roster`
        // refused it (`members` is not [* roster-member]).
        let room = format!("room-{tag}");
        let alice = format!("alice-{tag}");
        let bob = format!("bob-{tag}");
        for k in [&alice, &bob] {
            e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let roster = [&alice, &bob]
            .into_iter()
            .map(|k| CommunityMember {
                key_id: k.clone(),
                joined_at: at("2026-01-01T00:00:00Z"),
                // v49.0.0 (#908): alice founds the room — under founder_only
                // her signature alone is the protocol (CC 4.4.3.4.2).
                role: (*k == alice)
                    .then(|| crate::federation::admission::MEMBER_ROLE_FOUNDER.into()),
            })
            .collect();
        let signed = ts::sign_community(
            &alice,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: room.clone(),
                community_name: "keyless room".into(),
                members: roster,
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: protocol.to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        e2::put_voices(
            d,
            &e2::community_voices(&signed, 1, None, ms(at("2026-01-01T00:00:00Z"))),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: room: {e}"));
        (e2::kid(&room), e2::kid(&alice), e2::kid(&bob))
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

    /// **I164 — a widening converges.** Two directories hold the same room
    /// (the same founding statements); A widens carol; the same widening
    /// statements reach B; B's fold equals A's, and neither RECORD moves
    /// (growth rides the membership plane). A repeat of the widening is a
    /// no-op that writes no second row.
    ///
    /// v62 (E4, flip wave 3): the legs about the earlier `AdmitSpec` (an
    /// unsigned exact retry, #936; a scrub over the GROWN record, edge's v47
    /// shape) and the signed-JSON since-read's resume pair are gone: an
    /// edition-2 widening is its signers' voices, verified by the door, and
    /// it is served by `edition2_statements_since`.
    pub async fn i164_a_widening_converges(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (room, alice, bob) = keyless_room_dir(a, tag).await;
        let (room_b, _, _) = keyless_room_dir(b, tag).await;
        assert_eq!(room, room_b, "{tag} I164: one room");
        let carol = e2::kid(&sd("carol", tag));
        for d in [a, b] {
            e2::put_key(d, &carol, &[identity_type::USER]).await;
        }
        let record_before_a = a.lookup_community(&room).await.unwrap().unwrap();
        let record_before_b = b.lookup_community(&room).await.unwrap().unwrap();
        assert_eq!(
            record_before_a, record_before_b,
            "{tag} I164: same record on both nodes"
        );
        let grow = || widening(&room, &carol, at("2026-03-01T00:00:00Z"));
        widen_by(a, &[&alice], grow())
            .await
            .unwrap_or_else(|e| panic!("{tag} I164: widen on A: {e}"));
        let mut want = vec![alice.clone(), bob.clone(), carol.clone()];
        want.sort();
        assert_eq!(roster(a, &room).await, want, "{tag} I164: carol is in on A");
        // The identical widening again: a no-op, no second row.
        widen_by(a, &[&alice], grow())
            .await
            .unwrap_or_else(|e| panic!("{tag} I164: the identical widening is Ok: {e}"));
        assert_eq!(
            a.list_community_membership_widenings_for(&room)
                .await
                .unwrap()
                .len(),
            1,
            "{tag} I164: the repeat wrote no row"
        );
        assert_eq!(
            a.lookup_community(&room).await.unwrap().unwrap(),
            record_before_a,
            "{tag} I164: the RECORD did not move on A — growth rides the plane"
        );
        // The same widening reaches B.
        widen_by(b, &[&alice], grow())
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
            // v62 (E4, flip wave 2): carol is an edition-2 key; each event is
            // its signers' `membership:{stage}` voices naming the roster's
            // held version (the widenings with carol's consent held first).
            let carol = e2::put_key(*d, &sd("carol", &tg), &[identity_type::USER]).await;
            let events: Vec<(&str, usize)> = match i {
                0 => vec![("w", 1), ("r", 2), ("w", 3), ("r", 4)],
                1 => vec![("r", 4), ("w", 3), ("r", 2), ("w", 1)],
                _ => vec![("r", 2), ("r", 4), ("w", 1), ("w", 3)],
            };
            for (kind, n) in events {
                match (kind, n) {
                    ("w", 1) => widen_by(*d, &[&alice], widening(&room, &carol, t1))
                        .await
                        .map(|_| ()),
                    ("w", 3) => widen_by(*d, &[&alice], widening(&room, &carol, t3))
                        .await
                        .map(|_| ()),
                    ("r", 2) => revoke_by(*d, &[&alice], revocation(&room, &carol, t2))
                        .await
                        .map(|_| ()),
                    _ => revoke_by(*d, &[&alice], revocation(&room, &carol, t4))
                        .await
                        .map(|_| ()),
                }
                .unwrap_or_else(|e| panic!("{tg} I165: every row admits in every order: {e}"));
            }
            // The exact repeat of r2 is a no-op (the same statements); the
            // fold is one.
            revoke_by(*d, &[&alice], revocation(&room, &carol, t2))
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
            // The record's own members count FROM THE RECORD, never from
            // their signer-chosen `joined_at`: a founding member stamped
            // later than the instant asked about is still in (a peer that
            // seeds the room from a skewed clock must not refuse an earlier
            // mint — I77) — and her revocation at any instant still removes.
            let late = crate::federation::types::CommunityMember {
                key_id: sd("late", tag),
                joined_at: t4 + chrono::Duration::days(30),
                role: None,
            };
            let mut with_late = rec.members.clone();
            with_late.push(late.clone());
            let before_join = crate::federation::active_roster_at(&with_late, &[], &[], t2);
            assert!(
                before_join.iter().any(|m| m.key_id == late.key_id),
                "{tag} I165: a record member is in before her joined_at"
            );
            let removed = crate::federation::active_roster_at(
                &with_late,
                &[],
                &[revocation(room, &late.key_id, t2)],
                t3,
            );
            assert!(
                !removed.iter().any(|m| m.key_id == late.key_id),
                "{tag} I165: her revocation removes her regardless of joined_at"
            );
        }
    }

    /// **I166 — a raw roster read is a wrong read.** After a widening every
    /// read-time gate sees the member; after her revocation none does.
    pub async fn i166_a_raw_roster_read_is_a_wrong_read(d: &dyn FederationDirectory, tag: &str) {
        // v49.0.0 (#908) — reshaped: a founder can no longer be widened into
        // a founderless founder_only room (no one has standing there). The
        // point is unchanged: every gate FOLDS. Sole founder alice widens
        // carol (a founder) in; alice leaves; carol, the last member, leaves.
        // The record still lists alice as founder throughout — a raw read
        // would keep finding a moderator, an authority and a wrap target.
        use crate::federation::admission::{
            check_no_moderator_federate_admission, community_authority_set_for, MEMBER_ROLE_FOUNDER,
        };
        // v62 (E4, flip wave 2): edition-2 keys, the record as its voices,
        // carol's widening with her consent held first, the leavings as
        // `membership:removal` voices; ids are identity-refs.
        let room_s = sd("room", tag);
        let alice = e2::kid(&sd("alice", tag));
        let carol = e2::kid(&sd("carol", tag));
        for k in [&alice, &carol] {
            e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let room = e2::kid(&room_s);
        let signed = ts::sign_community(
            &alice,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: room_s.clone(),
                community_name: "i166 room".into(),
                members: vec![CommunityMember {
                    key_id: alice.clone(),
                    joined_at: at("2026-01-01T00:00:00Z"),
                    role: Some(MEMBER_ROLE_FOUNDER.into()),
                }],
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: "quorum:1/1".into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        e2::put_voices(
            d,
            &e2::community_voices(&signed, 1, None, ms(at("2026-01-01T00:00:00Z"))),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: room: {e}"));
        let record = d.lookup_community(&room).await.unwrap().unwrap();
        check_no_moderator_federate_admission(d, &record)
            .await
            .unwrap_or_else(|e| panic!("{tag} I166: control — founder alice moderates: {e}"));
        widen_by(
            d,
            &[&alice],
            crate::federation::types::CommunityMembershipWidening {
                community_key_id: room.clone(),
                member_key_id: carol.clone(),
                joined_at: at("2026-03-01T00:00:00Z"),
                effective_at: at("2026-03-01T00:00:00Z"),
                role: Some(MEMBER_ROLE_FOUNDER.into()),
                persist_row_hash: String::new(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I166: alice widens carol: {e}"));
        let record = d.lookup_community(&room).await.unwrap().unwrap();
        assert!(
            !record.members.iter().any(|m| m.key_id == carol),
            "{tag} I166: the record does not carry the widening — every gate must fold"
        );
        assert!(
            community_authority_set_for(d, &record)
                .await
                .unwrap()
                .contains(&carol),
            "{tag} I166: the authority set folds in carol"
        );
        let wrap = crate::federation::community_dek::orchestrate::active_member_key_ids(d, &record)
            .await
            .unwrap();
        assert!(
            wrap.contains(&carol),
            "{tag} I166: the DEK wrap set folds in carol: {wrap:?}"
        );

        // alice leaves (carol remains a founder, so the last-founder rule holds).
        revoke_by(
            d,
            &[&alice],
            revocation(&room, &alice, at("2026-04-01T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I166: alice leaves: {e}"));
        assert!(
            !community_authority_set_for(d, &record)
                .await
                .unwrap()
                .contains(&alice),
            "{tag} I166: the record still lists founder alice; the authority set must not"
        );
        // carol, the last member, leaves: the room is empty by the fold.
        revoke_by(
            d,
            &[&carol],
            revocation(&room, &carol, at("2026-04-02T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I166: carol leaves: {e}"));
        assert!(
            check_no_moderator_federate_admission(d, &record).await.is_err(),
            "{tag} I166: no member is left, so no moderator — a raw read of the record would still find founder alice"
        );
        let wrap = crate::federation::community_dek::orchestrate::active_member_key_ids(d, &record)
            .await
            .unwrap();
        assert!(wrap.is_empty(), "{tag} I166: nobody is wrapped: {wrap:?}");
    }

    // v62 (E4, flip wave 3): I167 ("the since-read resumes across the
    // three-part id") is DELETED: it witnesses the resume pair of the
    // signed-JSON roster since-read (`list_signed_community_membership_
    // revocations_since`), the earlier served wire. Edition-2 statements are
    // served by `edition2_statements_since`, whose cursor is its own witness.
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
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
            }
        };
    }

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
