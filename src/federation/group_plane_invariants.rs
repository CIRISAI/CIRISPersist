//! v61 (CIRISPersist#991 planes 2 and 3; CC 3.1.3, 3.1.3.2;
//! `CLM-planes-as-rows`, `CLM-cosigned-rows`) — **a group's record and its
//! roster planes are rows, and the tables are their projections.**
//!
//! I1484 — the family plane: the record is a `group:roster:v1` row placed at
//! the family; a co-signed widening is a `membership:widening:v1` row whose
//! co-signature rides as `additional_scrubs`; a widening short of the
//! protocol's quorum is refused and leaves no row; a co-signed removal is a
//! `membership:removal:v1` row, a member's own leaving a
//! `membership:resignation:v1` row; the roster lists what the rows say; and
//! every family projection is byte-equal to its from-rows rebuild.
//!
//! I1485 — the same, on the room plane.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::group_plane::{
        self as gp, GroupPlaneStore, GroupPlaneTable, GROUP_KIND_MEMBER,
    };
    use crate::federation::membership_acceptance::test_support::ConsentedWidening as _;
    use crate::federation::silo_projection::check_projection_rebuild;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        identity_type, Attestation, Community, CommunityMember, CommunityMembershipRevocation,
        CommunityMembershipWidening, Family, FamilyMember, FamilyMembershipRevocation,
        FamilyMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// The rows of `dimension` the plane holds for `table`.
    async fn rows<D>(d: &D, table: GroupPlaneTable, dimension: &str) -> Vec<Attestation>
    where
        D: GroupPlaneStore + ?Sized,
    {
        d.read_group_plane(table)
            .await
            .expect("read group plane")
            .rows
            .into_iter()
            .filter(|r| {
                crate::federation::admission::envelope_dimension(&r.attestation_envelope)
                    == Some(dimension)
            })
            .collect()
    }

    /// The projection row of `table` linked to its row, for every signed row.
    async fn all_linked<D>(d: &D, table: GroupPlaneTable, tag: &str)
    where
        D: GroupPlaneStore + AttestationStore,
    {
        let read = d.read_group_plane(table).await.expect("read group plane");
        for (signed, id) in &read.live {
            assert!(
                id.is_some(),
                "{tag}: {} row of {} holds no row",
                table.as_str(),
                signed.group_key_id()
            );
        }
        check_projection_rebuild(d, table.projection())
            .await
            .unwrap_or_else(|e| panic!("{tag}: {} rebuild: {e}", table.as_str()));
    }

    async fn user(d: &dyn FederationDirectory, k: &str) {
        ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
    }

    /// Every plane row of `table` carries the group plane's placement.
    fn assert_placed(rows: &[Attestation], kind: gp::GroupKind, group: &str, tag: &str) {
        for r in rows {
            assert_eq!(r.cohort_scope, kind.as_str(), "{tag}: placed at the group");
            assert_eq!(
                r.attestation_envelope[GROUP_KIND_MEMBER],
                kind.as_str(),
                "{tag}: group_kind"
            );
            assert_eq!(
                r.attestation_envelope[kind.target_member()],
                group,
                "{tag}: cohort target"
            );
            assert!(
                r.scrub_signature_pqc.is_some(),
                "{tag}: a plane row's signature is hybrid"
            );
        }
    }

    fn short_refusal(e: &Error, tag: &str) {
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{tag}: a widening short of the quorum is a roster-authority refusal, got {e}"
        );
    }

    /// I1484 — the family plane as rows.
    pub(crate) async fn i1484_family_plane<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        let dd: &dyn FederationDirectory = d;
        let fam = format!("fam-{tag}");
        let [ann, ben, cat, dan] = ["ann", "ben", "cat", "dan"].map(|n| format!("{n}-{tag}"));
        for k in [&ann, &ben, &cat, &dan] {
            user(dd, k).await;
        }
        let founded = at("2026-01-01T00:00:00Z");
        let record = ts::sign_family(
            &ann,
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: [&ann, &ben, &cat]
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: (*k).clone(),
                        joined_at: founded,
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: founded,
                consensus_protocol: "quorum:2/3".to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        d.put_family(record).await.expect("family admitted");

        // Admit: the record is a `group:roster:v1` row at the family.
        let roster = rows(d, GroupPlaneTable::Families, gp::GROUP_ROSTER_DIMENSION).await;
        let roster: Vec<_> = roster
            .into_iter()
            .filter(|r| r.attested_key_id == fam)
            .collect();
        assert_eq!(roster.len(), 1, "{tag}: one record row");
        assert_eq!(
            roster[0].attesting_key_id, ann,
            "{tag}: attester is the signer"
        );
        assert_placed(&roster, gp::GroupKind::Family, &fam, tag);
        all_linked(d, GroupPlaneTable::Families, tag).await;

        // Cosign-short: one signature under quorum:2/3 moves nothing.
        let w = FamilyMembershipWidening {
            family_key_id: fam.clone(),
            member_key_id: dan.clone(),
            joined_at: at("2026-02-01T00:00:00Z"),
            effective_at: at("2026-02-01T00:00:00Z"),
            role: None,
            persist_row_hash: String::new(),
        };
        let short = d
            .put_family_membership_widening_consented(ts::sign_family_membership_widening(
                &ann,
                w.clone(),
            ))
            .await
            .expect_err("one of three is short of quorum:2/3");
        short_refusal(&short, tag);
        assert!(
            rows(
                d,
                GroupPlaneTable::FamilyWidenings,
                gp::MEMBERSHIP_WIDENING_DIMENSION
            )
            .await
            .iter()
            .all(|r| r.attested_key_id != dan),
            "{tag}: a refused widening leaves no row"
        );

        // Widen: ann + ben's co-signature.
        let mut signed = ts::sign_family_membership_widening(&ann, w);
        ts::cosign_family_membership_widening(&mut signed, &ben);
        d.put_family_membership_widening_consented(signed)
            .await
            .expect("2 of 3 widen");
        let widenings: Vec<_> = rows(
            d,
            GroupPlaneTable::FamilyWidenings,
            gp::MEMBERSHIP_WIDENING_DIMENSION,
        )
        .await
        .into_iter()
        .filter(|r| r.attested_key_id == dan)
        .collect();
        assert_eq!(widenings.len(), 1, "{tag}: one widening row");
        assert_eq!(
            widenings[0]
                .additional_scrubs
                .iter()
                .map(|s| s.scrub_key_id.as_str())
                .collect::<Vec<_>>(),
            vec![ben.as_str()],
            "{tag}: the co-signature rides as additional_scrubs"
        );
        assert_placed(&widenings, gp::GroupKind::Family, &fam, tag);

        // Revoke: ann + ben remove cat.
        let removal = FamilyMembershipRevocation {
            family_key_id: fam.clone(),
            removed_identity_key_id: cat.clone(),
            removed_at: at("2026-03-01T00:00:00Z"),
            effective_at: at("2026-03-01T00:00:00Z"),
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        let mut signed = ts::sign_family_membership_revocation(&ann, removal);
        ts::cosign_family_membership_revocation(&mut signed, &ben);
        d.put_family_membership_revocation(signed)
            .await
            .expect("2 of 3 remove");
        let removals = rows(
            d,
            GroupPlaneTable::FamilyRevocations,
            gp::MEMBERSHIP_REMOVAL_DIMENSION,
        )
        .await;
        assert_eq!(
            removals.iter().filter(|r| r.attested_key_id == cat).count(),
            1,
            "{tag}: one removal row"
        );
        assert_placed(&removals, gp::GroupKind::Family, &fam, tag);

        // Resign: dan leaves on his own signature.
        let leave = FamilyMembershipRevocation {
            family_key_id: fam.clone(),
            removed_identity_key_id: dan.clone(),
            removed_at: at("2026-04-01T00:00:00Z"),
            effective_at: at("2026-04-01T00:00:00Z"),
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        d.put_family_membership_revocation(ts::sign_family_membership_revocation(&dan, leave))
            .await
            .expect("a member leaves on their own signature");
        let resignations = rows(
            d,
            GroupPlaneTable::FamilyRevocations,
            gp::MEMBERSHIP_RESIGNATION_DIMENSION,
        )
        .await;
        assert_eq!(resignations.len(), 1, "{tag}: one resignation row");
        assert_eq!(
            resignations[0].attesting_key_id, dan,
            "{tag}: the leaver signs"
        );

        // List: the roster is what the rows say.
        let mut active: Vec<String> = d
            .active_family_members(&fam)
            .await
            .expect("roster")
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        active.sort();
        assert_eq!(active, vec![ann.clone(), ben.clone()], "{tag}: the roster");

        // Rebuild: every family table is byte-equal to its rows.
        for t in [
            GroupPlaneTable::Families,
            GroupPlaneTable::FamilyWidenings,
            GroupPlaneTable::FamilyRevocations,
        ] {
            all_linked(d, t, tag).await;
        }
    }

    /// I1485 — the room plane as rows.
    pub(crate) async fn i1485_room_plane<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        let dd: &dyn FederationDirectory = d;
        let room = format!("room-{tag}");
        let [ann, ben, cat, dan] = ["ann", "ben", "cat", "dan"].map(|n| format!("{n}-{tag}"));
        for k in [&ann, &ben, &cat, &dan] {
            user(dd, k).await;
        }
        let founded = at("2026-01-01T00:00:00Z");
        d.put_community(ts::sign_community(
            &ann,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: room.clone(),
                community_name: "room".into(),
                members: [&ann, &ben, &cat]
                    .iter()
                    .enumerate()
                    .map(|(i, k)| CommunityMember {
                        key_id: (*k).clone(),
                        joined_at: founded,
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: founded,
                consensus_protocol: "quorum:2/3".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("room admitted");
        let roster: Vec<_> = rows(d, GroupPlaneTable::Communities, gp::GROUP_ROSTER_DIMENSION)
            .await
            .into_iter()
            .filter(|r| r.attested_key_id == room)
            .collect();
        assert_eq!(roster.len(), 1, "{tag}: one record row");
        assert_placed(&roster, gp::GroupKind::Community, &room, tag);
        all_linked(d, GroupPlaneTable::Communities, tag).await;

        let w = CommunityMembershipWidening {
            community_key_id: room.clone(),
            member_key_id: dan.clone(),
            joined_at: at("2026-02-01T00:00:00Z"),
            effective_at: at("2026-02-01T00:00:00Z"),
            role: None,
            persist_row_hash: String::new(),
        };
        let short = d
            .put_community_membership_widening_consented(ts::sign_community_membership_widening(
                &ann,
                w.clone(),
            ))
            .await
            .expect_err("one of three is short of quorum:2/3");
        short_refusal(&short, tag);
        let mut signed = ts::sign_community_membership_widening(&ann, w);
        ts::cosign_community_membership_widening(&mut signed, &ben);
        d.put_community_membership_widening_consented(signed)
            .await
            .expect("2 of 3 widen");
        let widenings: Vec<_> = rows(
            d,
            GroupPlaneTable::CommunityWidenings,
            gp::MEMBERSHIP_WIDENING_DIMENSION,
        )
        .await
        .into_iter()
        .filter(|r| r.attested_key_id == dan)
        .collect();
        assert_eq!(widenings.len(), 1, "{tag}: one widening row");
        assert_eq!(widenings[0].additional_scrubs.len(), 1, "{tag}: co-signed");
        assert_placed(&widenings, gp::GroupKind::Community, &room, tag);

        let mut signed = ts::sign_community_membership_revocation(
            &ann,
            CommunityMembershipRevocation {
                community_key_id: room.clone(),
                removed_identity_key_id: cat.clone(),
                removed_at: at("2026-03-01T00:00:00Z"),
                effective_at: at("2026-03-01T00:00:00Z"),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_community_membership_revocation(&mut signed, &ben);
        d.put_community_membership_revocation(signed)
            .await
            .expect("2 of 3 remove");
        assert_eq!(
            rows(
                d,
                GroupPlaneTable::CommunityRevocations,
                gp::MEMBERSHIP_REMOVAL_DIMENSION
            )
            .await
            .iter()
            .filter(|r| r.attested_key_id == cat)
            .count(),
            1,
            "{tag}: one removal row"
        );
        d.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &dan,
            CommunityMembershipRevocation {
                community_key_id: room.clone(),
                removed_identity_key_id: dan.clone(),
                removed_at: at("2026-04-01T00:00:00Z"),
                effective_at: at("2026-04-01T00:00:00Z"),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("a member leaves on their own signature");
        assert_eq!(
            rows(
                d,
                GroupPlaneTable::CommunityRevocations,
                gp::MEMBERSHIP_RESIGNATION_DIMENSION
            )
            .await
            .len(),
            1,
            "{tag}: one resignation row"
        );
        let mut active: Vec<String> = d
            .active_community_members(&room)
            .await
            .expect("roster")
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        active.sort();
        assert_eq!(active, vec![ann.clone(), ben.clone()], "{tag}: the roster");
        for t in [
            GroupPlaneTable::Communities,
            GroupPlaneTable::CommunityWidenings,
            GroupPlaneTable::CommunityRevocations,
        ] {
            all_linked(d, t, tag).await;
        }
    }
}

#[cfg(test)]
mod run {
    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i1484() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1484_family_plane(&d, &super::tag()).await;
                }
                #[tokio::test]
                async fn i1485() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1485_room_plane(&d, &super::tag()).await;
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
