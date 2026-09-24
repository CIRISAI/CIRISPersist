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
        let epoch_before = b
            .community_dek_current_epoch(&room, &alice)
            .await
            .unwrap_or_else(|e| panic!("{tag}: epoch read: {e}"));
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
        let epoch_after = b.community_dek_current_epoch(&room, &alice).await.unwrap();
        assert_eq!(
            epoch_after,
            epoch_before + 1,
            "{tag} I163: the §15 rotation is reachable for a keyless room"
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
