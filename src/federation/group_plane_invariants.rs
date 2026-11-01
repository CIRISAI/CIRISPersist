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
//!
//! I1486 — the rows replicate: a second node that receives nothing but the
//! first node's attestation rows (through `apply_replicated_attestation`)
//! folds the same record and roster, and its projections rebuild byte-equal;
//! a row one byte off its carried object, or stripped of a co-signature, is
//! refused and leaves nothing.
//!
//! I1487 — the retraction of a cosigned row is a cosigned `withdraws` under
//! the same protocol: one signature under `quorum:2/3` is refused, two are
//! admitted and the roster event leaves the projection (the rebuild still
//! byte-equal); a resignation is withdrawn only by its signer; a group's
//! record is never withdrawn.
//!
//! I1488 — the rows are served to the group's membership-plane audience: a
//! private family's rows reach a member and the member a row names, never a
//! stranger.
//!
//! I1490 — the rebuild gate can fail: a roster event whose row is gone, or a
//! projection column that no row says, is a red naming the table.
//!
//! I1491 — the row carries the bytes its signer signed: a nanosecond-signed
//! record replicates to a node that admits it (on a backend that keeps
//! microseconds, a row minted from the read-back would not verify); the
//! receiver's signature rule takes the row and refuses it one byte off; a
//! re-offer of a held row settles; and a roster event re-put under the same key
//! with other co-signers leaves the row that matches what the store kept.
//!
//! I1489 — an upgraded node: a v60 schema (through V205) holds signed typed
//! records and roster events with no rows; V206/V207 and the rehome at open
//! give every one its row, checked by a from-disk count (no signed projection
//! row names no row; the plane holds one row per signed object), every
//! projection rebuilds byte-equal, and a second rehome links nothing.
//!
//! I1497 — the member listing retires with no successor (the steward's ruling:
//! no outward member listing). A v60 node (through V208) holds a private
//! room's listing rows (two members listed `public`) and a peer's
//! advertisement of a listing hash. After V209, by a from-disk count, the
//! table is gone and so is the advertisement. A non-member's node receives
//! none of the room's planes, whichever member a row names (the listed ones
//! included), while a member's still does. The envelope vocabulary no longer
//! names `listed`.

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
            let Some(id) = id else {
                panic!(
                    "{tag}: {} row of {} holds no row",
                    table.as_str(),
                    signed.group_key_id()
                );
            };
            // The row is served: it resolves by its Attestation-kind hash.
            let row = d
                .get_attestation(id)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{tag}: row {id} is held"));
            let hash = crate::federation::wire_index::content_hash_of(&row).unwrap();
            assert!(
                d.lookup_signed_record_by_content_hash("Attestation", &hash)
                    .await
                    .unwrap()
                    .is_some(),
                "{tag}: row {id} resolves by its wire hash"
            );
        }
        check_projection_rebuild(d, table.projection())
            .await
            .unwrap_or_else(|e| panic!("{tag}: {} rebuild: {e}", table.as_str()));
    }

    pub(crate) async fn user(d: &dyn FederationDirectory, k: &str) {
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

    /// A family `fam-{tag}` of ann (founder), ben and cat under `quorum:2/3`,
    /// dan widened by ann + ben, cat removed by ann + ben, through the local
    /// doors on `d`. Returns the family id and the four keys.
    async fn family_with_history<D>(d: &D, tag: &str) -> (String, [String; 4])
    where
        D: FederationDirectory,
    {
        family_with_history_under(d, tag, "quorum:2/3").await
    }

    /// [`family_with_history`] under `protocol`.
    async fn family_with_history_under<D>(d: &D, tag: &str, protocol: &str) -> (String, [String; 4])
    where
        D: FederationDirectory,
    {
        let fam = format!("fam-{tag}");
        let keys = ["ann", "ben", "cat", "dan"].map(|n| format!("{n}-{tag}"));
        let [ann, ben, cat, dan] = &keys;
        let founded = at("2026-01-01T00:00:00Z");
        d.put_family(ts::sign_family(
            ann,
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: [ann, ben, cat]
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: (*k).clone(),
                        joined_at: founded,
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: founded,
                consensus_protocol: protocol.to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("family admitted");
        let mut w = ts::sign_family_membership_widening(
            ann,
            FamilyMembershipWidening {
                family_key_id: fam.clone(),
                member_key_id: dan.clone(),
                joined_at: at("2026-02-01T00:00:00Z"),
                effective_at: at("2026-02-01T00:00:00Z"),
                role: None,
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_family_membership_widening(&mut w, ben);
        d.put_family_membership_widening_consented(w)
            .await
            .expect("2 of 3 widen");
        let mut r = ts::sign_family_membership_revocation(
            ann,
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: cat.clone(),
                removed_at: at("2026-03-01T00:00:00Z"),
                effective_at: at("2026-03-01T00:00:00Z"),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_family_membership_revocation(&mut r, ben);
        d.put_family_membership_revocation(r)
            .await
            .expect("2 of 3 remove");
        (fam, keys)
    }

    async fn sorted_active(d: &dyn FederationDirectory, fam: &str) -> Vec<String> {
        let mut v: Vec<String> = d
            .active_family_members(fam)
            .await
            .expect("roster")
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        v.sort();
        v
    }

    /// I1486 — the group plane replicates as rows.
    pub(crate) async fn i1486_rows_replicate<D>(a: &D, b: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        for d in [a, b] {
            for n in ["ann", "ben", "cat", "dan"] {
                user(d, &format!("{n}-{tag}")).await;
            }
        }
        let (fam, _) = family_with_history(a, tag).await;
        let rows: Vec<Attestation> = a
            .list_attestations_since(None, 10_000)
            .await
            .expect("A's rows")
            .into_iter()
            .map(|s| s.attestation)
            .collect();
        let widening = rows
            .iter()
            .find(|r| {
                crate::federation::admission::envelope_dimension(&r.attestation_envelope)
                    == Some(gp::MEMBERSHIP_WIDENING_DIMENSION)
            })
            .expect("A holds the widening row")
            .clone();
        // A row one byte off its object, and one stripped of its co-signature,
        // are refused before anything lands.
        let mut tampered = widening.clone();
        tampered.attestation_envelope[gp::WIDENING_MEMBER]["family_membership_widening"]["role"] =
            "founder".into();
        let mut stripped = widening.clone();
        stripped.additional_scrubs.clear();
        for (bad, what) in [(tampered, "tampered"), (stripped, "stripped")] {
            let e = b
                .apply_replicated_attestation(crate::federation::SignedAttestation {
                    attestation: bad,
                })
                .await
                .expect_err("a row off its object is refused");
            assert_eq!(e.kind(), "federation_malformed_row", "{tag}: {what}: {e}");
        }
        // B takes A's rows, in A's order, and nothing else.
        for row in rows {
            let id = row.attestation_id.clone();
            b.apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: row,
            })
            .await
            .unwrap_or_else(|e| panic!("{tag}: B applies {id}: {e}"));
        }
        let (da, db): (&dyn FederationDirectory, &dyn FederationDirectory) = (a, b);
        assert_eq!(
            sorted_active(db, &fam).await,
            sorted_active(da, &fam).await,
            "{tag}: B folds A's roster"
        );
        assert_eq!(
            db.lookup_family(&fam)
                .await
                .unwrap()
                .expect("B holds the record"),
            da.lookup_family(&fam)
                .await
                .unwrap()
                .expect("A holds the record"),
            "{tag}: one record"
        );
        for t in [
            GroupPlaneTable::Families,
            GroupPlaneTable::FamilyWidenings,
            GroupPlaneTable::FamilyRevocations,
        ] {
            all_linked(b, t, tag).await;
        }
    }

    /// A `withdraws` of `target` signed by `signer` and co-signed by
    /// `cosigners` over its final envelope bytes, placed where its target is.
    fn withdraws_of(signer: &str, cosigners: &[&str], target: &Attestation) -> Attestation {
        use crate::federation::envelope::paths;
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let mut envelope = serde_json::json!({
            paths::REFERENCES_ATTESTATION_ID: target.attestation_id,
            paths::WITHDRAWAL_REASON: "the group retracts the roster event",
            paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(asserted_at),
        });
        for k in [GROUP_KIND_MEMBER, "family_key_id", "community_key_id"] {
            if let Some(v) = target.attestation_envelope.get(k) {
                envelope[k] = v.clone();
            }
        }
        let mut row = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: signer.to_owned(),
            // A row placed at a group names no party but its producer (AV-84).
            attested_key_id: signer.to_owned(),
            attestation_type: crate::federation::types::attestation_type::WITHDRAWS.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: target.cohort_scope.clone(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::seal_row_in_place(signer, &mut row);
        for c in cosigners {
            let (_, classical, pqc) = ts::sign_envelope(c, &row.attestation_envelope);
            row.additional_scrubs
                .push(crate::federation::types::ScrubSig {
                    scrub_key_id: (*c).to_owned(),
                    scrub_signature_classical: classical,
                    scrub_signature_pqc: pqc,
                    cosigned_at: None,
                });
        }
        row
    }

    /// The one `dimension` row of family `fam` the plane holds for `table`.
    async fn one<D>(d: &D, fam: &str, dimension: &str, table: GroupPlaneTable) -> Attestation
    where
        D: GroupPlaneStore + ?Sized,
    {
        rows(d, table, dimension)
            .await
            .into_iter()
            .find(|r| r.attestation_envelope["family_key_id"] == fam)
            .unwrap_or_else(|| panic!("a {dimension} row"))
    }

    async fn put_row(d: &dyn FederationDirectory, row: Attestation) -> Result<(), Error> {
        d.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    /// I1487 — a cosigned row is retracted by a cosigned `withdraws`.
    pub(crate) async fn i1487_cosigned_withdraws<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        let dd: &dyn FederationDirectory = d;
        for n in ["ann", "ben", "cat", "dan"] {
            user(dd, &format!("{n}-{tag}")).await;
        }
        let (fam, [ann, ben, cat, dan]) = family_with_history(d, tag).await;
        let widening = one(
            d,
            &fam,
            gp::MEMBERSHIP_WIDENING_DIMENSION,
            GroupPlaneTable::FamilyWidenings,
        )
        .await;
        let record = one(
            d,
            &fam,
            gp::GROUP_ROSTER_DIMENSION,
            GroupPlaneTable::Families,
        )
        .await;
        assert!(
            sorted_active(dd, &fam).await.contains(&dan),
            "{tag}: dan seated"
        );

        // One signature under quorum:2/3 does not retract the group's widening,
        // its own author included.
        let short = withdraws_of(&ann, &[], &widening);
        let e = put_row(dd, short.clone())
            .await
            .expect_err("one of three is short");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{tag}: short withdraws: {e}"
        );
        assert!(dd
            .get_attestation(&short.attestation_id)
            .await
            .unwrap()
            .is_none());
        // Two signatures retract it: dan leaves the roster and the projection.
        let retraction = withdraws_of(&ann, &[&ben], &widening);
        put_row(dd, retraction.clone())
            .await
            .expect("2 of 3 retract the widening");
        assert_eq!(
            dd.get_attestation(&retraction.attestation_id)
                .await
                .unwrap()
                .expect("the retraction is held")
                .withdraws_admission_rule,
            Some(1),
            "{tag}: the widening's own signer leads the retraction: rule 1"
        );
        assert!(
            !sorted_active(dd, &fam).await.contains(&dan),
            "{tag}: the retracted widening seats nobody"
        );
        all_linked(d, GroupPlaneTable::FamilyWidenings, tag).await;
        // The group's record is never withdrawn, cosigned or not: a withdraws
        // of it means dissolution, which is refused by name until S2 (#1143).
        // Its own signer alone, a quorum, and the whole roster are all
        // refused, store nothing and leave the roster where it was.
        let before = sorted_active(dd, &fam).await;
        for cosigners in [
            &[][..],
            &[ben.as_str()][..],
            &[ben.as_str(), cat.as_str()][..],
        ] {
            let dissolve = withdraws_of(&ann, cosigners, &record);
            let e = put_row(dd, dissolve.clone())
                .await
                .expect_err("a group record is not withdrawn");
            let msg = e.to_string();
            assert!(
                matches!(e, Error::InvalidArgument(_))
                    && msg.contains(gp::GROUP_RECORD_WITHDRAWS_REFUSED)
                    && msg.contains("dissolution"),
                "{tag}: record withdraws with {} cosigner(s): {e}",
                cosigners.len()
            );
            assert!(
                dd.get_attestation(&dissolve.attestation_id)
                    .await
                    .unwrap()
                    .is_none(),
                "{tag}: a refused dissolution stores nothing"
            );
        }
        assert_eq!(
            sorted_active(dd, &fam).await,
            before,
            "{tag}: a refused dissolution leaves the roster"
        );
        all_linked(d, GroupPlaneTable::Families, tag).await;
        // A resignation is its signer's alone.
        let mut leave = ts::sign_family_membership_revocation(
            &ben,
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: ben.clone(),
                removed_at: at("2026-04-01T00:00:00Z"),
                effective_at: at("2026-04-01T00:00:00Z"),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        leave.cosignatures.clear();
        d.put_family_membership_revocation(leave)
            .await
            .expect("ben resigns");
        let resignation = one(
            d,
            &fam,
            gp::MEMBERSHIP_RESIGNATION_DIMENSION,
            GroupPlaneTable::FamilyRevocations,
        )
        .await;
        let e = put_row(dd, withdraws_of(&ann, &[], &resignation))
            .await
            .expect_err("another key does not withdraw a resignation");
        assert_eq!(e.kind(), "federation_withdraws_not_admitted", "{tag}: {e}");
        all_linked(d, GroupPlaneTable::FamilyRevocations, tag).await;
    }

    /// I1488 — a private group's rows go to its membership-plane audience.
    pub(crate) async fn i1488_rows_reach_the_group_audience<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        use crate::federation::replication_audience::may_receive;
        let dd: &dyn FederationDirectory = d;
        for n in ["ann", "ben", "cat", "dan", "eve"] {
            user(dd, &format!("{n}-{tag}")).await;
        }
        let (fam, [ann, _ben, cat, _dan]) = family_with_history(d, tag).await;
        let eve = format!("eve-{tag}");
        let removal = one(
            d,
            &fam,
            gp::MEMBERSHIP_REMOVAL_DIMENSION,
            GroupPlaneTable::FamilyRevocations,
        )
        .await;
        let record = one(
            d,
            &fam,
            gp::GROUP_ROSTER_DIMENSION,
            GroupPlaneTable::Families,
        )
        .await;
        for row in [&record, &removal] {
            assert!(
                may_receive(dd, &ann, row).await.unwrap().allowed(),
                "{tag}: a member receives {}",
                row.attestation_id
            );
            assert!(
                !may_receive(dd, &eve, row).await.unwrap().allowed(),
                "{tag}: a stranger never receives a private group's {}",
                row.attestation_id
            );
        }
        assert!(
            may_receive(dd, &cat, &removal).await.unwrap().allowed(),
            "{tag}: the removed member receives the row that names them"
        );
    }

    /// A room `room-{tag}` of ann (founder), ben and cat under `quorum:2/3`,
    /// dan widened and cat removed by ann + ben, through the local doors.
    pub(crate) async fn room_with_history<D>(d: &D, tag: &str) -> String
    where
        D: FederationDirectory,
    {
        let room = format!("room-{tag}");
        let [ann, ben, cat, dan] = ["ann", "ben", "cat", "dan"].map(|n| format!("{n}-{tag}"));
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
        let mut w = ts::sign_community_membership_widening(
            &ann,
            CommunityMembershipWidening {
                community_key_id: room.clone(),
                member_key_id: dan.clone(),
                joined_at: at("2026-02-01T00:00:00Z"),
                effective_at: at("2026-02-01T00:00:00Z"),
                role: None,
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_community_membership_widening(&mut w, &ben);
        d.put_community_membership_widening_consented(w)
            .await
            .expect("2 of 3 widen");
        let mut r = ts::sign_community_membership_revocation(
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
        ts::cosign_community_membership_revocation(&mut r, &ben);
        d.put_community_membership_revocation(r)
            .await
            .expect("2 of 3 remove");
        room
    }

    /// The from-disk counts I1489 reads, each a SQL statement over one schema
    /// prefix (`""` on sqlite, `"cirislens."` on postgres).
    pub(crate) fn signed_without_row_sql(schema: &str, table: GroupPlaneTable) -> String {
        format!(
            "SELECT COUNT(*) FROM {schema}{} WHERE attestation_id IS NULL \
               AND authority_key_id IS NOT NULL AND authority_key_id <> ''",
            table.as_str()
        )
    }

    /// Signed rows of `table`, whatever they point at.
    pub(crate) fn signed_sql(schema: &str, table: GroupPlaneTable) -> String {
        format!(
            "SELECT COUNT(*) FROM {schema}{} \
              WHERE authority_key_id IS NOT NULL AND authority_key_id <> ''",
            table.as_str()
        )
    }

    /// Group-plane rows on the attestation plane.
    pub(crate) fn plane_rows_sql(schema: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM {schema}federation_attestations \
              WHERE attestation_type = 'scores' AND dimension IN \
                ('{}', '{}', '{}', '{}')",
            gp::GROUP_ROSTER_DIMENSION,
            gp::MEMBERSHIP_WIDENING_DIMENSION,
            gp::MEMBERSHIP_REMOVAL_DIMENSION,
            gp::MEMBERSHIP_RESIGNATION_DIMENSION
        )
    }

    /// I1489, before the upgrade: the v60 node holds signed typed records and
    /// roster events (seeded through its own doors), and no group-plane row.
    /// Returns the tag's group ids.
    pub(crate) async fn i1489_seed_v60<D>(old: &D, tag: &str) -> (String, String)
    where
        D: FederationDirectory,
    {
        for n in ["ann", "ben", "cat", "dan"] {
            user(old, &format!("{n}-{tag}")).await;
        }
        let (fam, _) = family_with_history(old, tag).await;
        let room = room_with_history(old, tag).await;
        // A trusted-local family the runner then gives an Ed25519-only
        // signature: held signed, but with no hybrid signature to mint a row
        // from.
        old.put_family_local(Family {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            family_key_id: ed25519_only_family(tag),
            family_name: "ed25519-only".into(),
            members: vec![FamilyMember {
                key_id: format!("ann-{tag}"),
                joined_at: at("2026-01-01T00:00:00Z"),
                role: Some("founder".to_owned()),
            }],
            founded_at: at("2026-01-01T00:00:00Z"),
            consensus_protocol: "founder_only".to_owned(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("a trusted-local family");
        (fam, room)
    }

    /// The I1489 family held with an Ed25519-only signature.
    pub(crate) fn ed25519_only_family(tag: &str) -> String {
        format!("ed-{tag}")
    }

    /// The SQL that gives it that signature, on `schema`.
    pub(crate) fn ed25519_only_sql(schema: &str, tag: &str) -> String {
        format!(
            "UPDATE {schema}federation_families SET authority_key_id = 'ann-{tag}', \
                scrub_signature_classical = 'c2ln', scrub_signature_pqc = NULL \
              WHERE family_key_id = '{}'",
            ed25519_only_family(tag)
        )
    }

    /// I1489, after V206/V207 and the rehome at open: every signed object
    /// that can have a row has one, from disk; the one that cannot is held
    /// without one, named by the rebuild gate and counted by the rehome.
    pub(crate) async fn i1489_after_upgrade<D>(
        d: &D,
        tag: &str,
        signed_before: i64,
        plane_after: i64,
        unlinked_after: i64,
    ) where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        assert!(signed_before >= 7, "{tag}: the v60 node held its records");
        assert_eq!(
            unlinked_after, 1,
            "{tag}: only the Ed25519-only record is held without its row"
        );
        assert_eq!(
            plane_after,
            signed_before - 1,
            "{tag}: one row per hybrid-signed object, from disk"
        );
        for t in GroupPlaneTable::ALL {
            if t == GroupPlaneTable::Families {
                continue;
            }
            all_linked(d, t, tag).await;
        }
        let red = check_projection_rebuild(d, GroupPlaneTable::Families.projection())
            .await
            .expect_err("a signed family held without its row is a red");
        assert!(
            red.to_string().contains("federation_families"),
            "{tag}: the gate names the table: {red}"
        );
        let again = crate::federation::group_plane::rehome_group_records(d)
            .await
            .expect("rehome again");
        assert_eq!(
            again,
            crate::federation::group_plane::GroupRehomeReport {
                linked: 0,
                without_row: 1,
            },
            "{tag}: the rehome is once; the Ed25519-only record stays counted"
        );
    }

    /// I1497, before the upgrade: the SQL that gives a v60 node's room
    /// `room` two listing rows (ben and dan listed `public`, as V156 stored
    /// them) and a peer's advertisement of a listing hash, on `schema`.
    pub(crate) fn i1497_seed_listing_sql(schema: &str, room: &str, tag: &str) -> String {
        format!(
            "INSERT INTO {schema}federation_community_membership_listings \
                (community_key_id, member_key_id, effective_at, listed, persist_row_hash, \
                 authority_key_id, scrub_signature_classical, admitted_at) \
             VALUES ('{room}', 'ben-{tag}', '2026-04-01T00:00:00Z', 'public', 'h-ben', \
                     'ben-{tag}', 'c2ln', '2026-04-01T00:00:00Z'), \
                    ('{room}', 'dan-{tag}', '2026-04-02T00:00:00Z', 'public', 'h-dan', \
                     'dan-{tag}', 'c2ln', '2026-04-02T00:00:00Z'); \
             INSERT INTO {schema}known_wire_hashes \
                (kind, content_hash, last_advertised_at, advertised_by) \
             VALUES ('CommunityMembershipListing', '{}', \
                     '2026-04-02T00:00:00.000000+00:00', 'a-peer');",
            "ef".repeat(32)
        )
    }

    /// I1497, the from-disk count of a v60 node's listing rows.
    pub(crate) fn i1497_listing_rows_sql(schema: &str) -> String {
        format!("SELECT count(*) FROM {schema}federation_community_membership_listings")
    }

    /// I1497, the from-disk count of the kind's advertisements.
    pub(crate) fn i1497_listing_adverts_sql(schema: &str) -> String {
        format!(
            "SELECT count(*) FROM {schema}known_wire_hashes \
              WHERE kind = 'CommunityMembershipListing'"
        )
    }

    /// I1497, after V209: the room the listings named serves no non-member,
    /// whichever member a row names; a member is still served.
    pub(crate) async fn i1497_no_non_member_view<D>(d: &D, room: &str, tag: &str)
    where
        D: FederationDirectory,
    {
        use crate::federation::replication_audience::may_receive_group_plane;
        use crate::federation::types::cohort_scope;
        let eve = format!("eve-{tag}");
        user(d, &eve).await;
        let [ann, ben, dan] = ["ann", "ben", "dan"].map(|n| format!("{n}-{tag}"));
        for named in [None, Some(ben.as_str()), Some(dan.as_str())] {
            let v = may_receive_group_plane(d, &eve, cohort_scope::COMMUNITY, room, named)
                .await
                .expect("the audience gate answers");
            assert!(
                !v.allowed(),
                "{tag}: I1497 a non-member receives the room's plane (row naming {named:?}): {v:?}"
            );
        }
        assert!(
            may_receive_group_plane(d, &ann, cohort_scope::COMMUNITY, room, None)
                .await
                .expect("the audience gate answers")
                .allowed(),
            "{tag}: I1497 a member is still served (the gate is not shut for everyone)"
        );
        let vocab = crate::federation::envelope::envelope_vocabulary_json();
        assert!(
            !vocab["universal_paths"]
                .as_array()
                .expect("universal_paths")
                .iter()
                .any(|p| p == "listed"),
            "{tag}: I1497 the envelope vocabulary still names `listed`"
        );
    }

    /// I1490 — the rebuild gate goes red; the runner then renames the family
    /// in its projection table ([`i1490_tamper_sql`]).
    pub(crate) async fn i1490_the_gate_can_fail<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        let dd: &dyn FederationDirectory = d;
        for n in ["ann", "ben", "cat", "dan"] {
            user(dd, &format!("{n}-{tag}")).await;
        }
        let (fam, _) = family_with_history(d, tag).await;
        for t in [
            GroupPlaneTable::Families,
            GroupPlaneTable::FamilyWidenings,
            GroupPlaneTable::FamilyRevocations,
        ] {
            all_linked(d, t, tag).await;
        }
        // A roster event whose row is gone is held without one.
        let widening = one(
            d,
            &fam,
            gp::MEMBERSHIP_WIDENING_DIMENSION,
            GroupPlaneTable::FamilyWidenings,
        )
        .await;
        assert!(d
            .delete_attestation(&widening.attestation_id, None)
            .await
            .unwrap());
        let red = check_projection_rebuild(d, GroupPlaneTable::FamilyWidenings.projection())
            .await
            .expect_err("a widening held without its row is a red");
        assert!(
            red.to_string()
                .contains("federation_family_membership_widenings"),
            "{tag}: {red}"
        );
        // A projection column no row says: the runner tampers next.
        check_projection_rebuild(d, GroupPlaneTable::Families.projection())
            .await
            .expect("the record is its row before the tamper");
    }

    /// I1490, after the runner's tamper: the record no longer is its row.
    pub(crate) async fn i1490_after_tamper<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        let red = check_projection_rebuild(d, GroupPlaneTable::Families.projection())
            .await
            .expect_err("a renamed record is not its row");
        assert!(
            red.to_string().contains("federation_families"),
            "{tag}: {red}"
        );
    }

    /// The SQL that renames I1490's family in its projection, on `schema`.
    pub(crate) fn i1490_tamper_sql(schema: &str, tag: &str) -> String {
        format!(
            "UPDATE {schema}federation_families SET family_name = 'renamed' \
              WHERE family_key_id = 'fam-{tag}'"
        )
    }

    /// I1491 — the row carries the bytes its signer signed.
    pub(crate) async fn i1491_the_row_is_the_signed_bytes<D>(a: &D, b: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        for d in [a, b] {
            for n in ["ann", "ben", "cat"] {
                user(d, &format!("{n}-{tag}")).await;
            }
        }
        let [ann, ben, cat] = ["ann", "ben", "cat"].map(|n| format!("{n}-{tag}"));
        let fam = format!("nsfam-{tag}");
        // Nanoseconds a microsecond backend does not keep.
        let founded: chrono::DateTime<chrono::Utc> =
            "2026-01-01T00:00:00.123456789Z".parse().unwrap();
        a.put_family(ts::sign_family(
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
        ))
        .await
        .expect("a nanosecond-signed family is admitted");
        let record = one(
            a,
            &fam,
            gp::GROUP_ROSTER_DIMENSION,
            GroupPlaneTable::Families,
        )
        .await;
        // The receiver's signature rule: the row, and not one byte off it.
        crate::federation::tier_ingest::verify_row_hybrid_signature(a, &record)
            .await
            .expect("the row verifies as its object");
        let mut off = record.clone();
        off.attestation_envelope[gp::GROUP_RECORD_MEMBER]["family"]["family_name"] =
            "renamed".into();
        assert!(
            crate::federation::tier_ingest::verify_row_hybrid_signature(a, &off)
                .await
                .is_err(),
            "{tag}: a row one byte off its object does not verify"
        );
        // B takes the row, and a re-offer settles.
        use crate::federation::attestation_apply::ReplicatedAttestationOutcome as O;
        let first = b
            .apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: record.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("{tag}: B admits the nanosecond-signed row: {e}"));
        assert_eq!(first, O::Inserted, "{tag}: B admits the row");
        let again = b
            .apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: record.clone(),
            })
            .await
            .unwrap();
        assert_eq!(again, O::Unchanged, "{tag}: a held row's re-offer settles");
        all_linked(b, GroupPlaneTable::Families, tag).await;

        // A removal re-put under the same key with another co-signer: the
        // store keeps the first, and the row follows what it kept.
        let removal = FamilyMembershipRevocation {
            family_key_id: fam.clone(),
            removed_identity_key_id: cat.clone(),
            removed_at: at("2026-03-01T00:00:00Z"),
            effective_at: at("2026-03-01T00:00:00Z"),
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        let mut by_ben = ts::sign_family_membership_revocation(&ann, removal.clone());
        ts::cosign_family_membership_revocation(&mut by_ben, &ben);
        a.put_family_membership_revocation(by_ben)
            .await
            .expect("2 of 3 remove");
        let mut by_cat = ts::sign_family_membership_revocation(&ann, removal);
        ts::cosign_family_membership_revocation(&mut by_cat, &cat);
        a.put_family_membership_revocation(by_cat)
            .await
            .expect("an exact-key re-put is the idempotent no-op");
        all_linked(a, GroupPlaneTable::FamilyRevocations, tag).await;
        let rows = rows(
            a,
            GroupPlaneTable::FamilyRevocations,
            gp::MEMBERSHIP_REMOVAL_DIMENSION,
        )
        .await;
        let mine: Vec<_> = rows
            .iter()
            .filter(|r| r.attestation_envelope["family_key_id"] == fam.as_str())
            .collect();
        assert_eq!(mine.len(), 1, "{tag}: one removal row");
        assert_eq!(
            mine[0]
                .additional_scrubs
                .iter()
                .map(|s| s.scrub_key_id.as_str())
                .collect::<Vec<_>>(),
            vec![ben.as_str()],
            "{tag}: the row is the removal the store kept"
        );
    }

    /// I1492 — a retraction moves the roster in a direction, and the
    /// group's protocol reads it: under `reverse_quorum` one member may
    /// retract a widening (a removal: protective), never a removal (an
    /// addition: m of n).
    pub(crate) async fn i1492_a_retraction_has_a_direction<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        let dd: &dyn FederationDirectory = d;
        for n in ["ann", "ben", "cat", "dan"] {
            user(dd, &format!("{n}-{tag}")).await;
        }
        let (fam, [ann, _ben, _cat, dan]) =
            family_with_history_under(d, tag, "reverse_quorum:2/3:86400").await;
        let removal = one(
            d,
            &fam,
            gp::MEMBERSHIP_REMOVAL_DIMENSION,
            GroupPlaneTable::FamilyRevocations,
        )
        .await;
        let e = put_row(dd, withdraws_of(&ann, &[], &removal))
            .await
            .expect_err("one member does not put a removed member back");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{tag}: {e}"
        );
        let widening = one(
            d,
            &fam,
            gp::MEMBERSHIP_WIDENING_DIMENSION,
            GroupPlaneTable::FamilyWidenings,
        )
        .await;
        put_row(dd, withdraws_of(&ann, &[], &widening))
            .await
            .expect("one member may retract a widening: protective");
        assert!(
            !sorted_active(dd, &fam).await.contains(&dan),
            "{tag}: the retracted widening seats nobody"
        );
    }

    /// I1489, last: after the runner clears every widening's pointer, the
    /// rehome links each back and counts it (and still counts the
    /// Ed25519-only record).
    pub(crate) async fn i1489_relinked<D>(d: &D, tag: &str, cleared: i64)
    where
        D: FederationDirectory + GroupPlaneStore + AttestationStore,
    {
        assert!(cleared >= 2, "{tag}: the runner cleared the widenings");
        let report = crate::federation::group_plane::rehome_group_records(d)
            .await
            .expect("rehome after the pointers were cleared");
        assert_eq!(
            report,
            crate::federation::group_plane::GroupRehomeReport {
                linked: u64::try_from(cleared).unwrap(),
                without_row: 1,
            },
            "{tag}: every cleared pointer is linked back, and counted"
        );
        all_linked(d, GroupPlaneTable::FamilyWidenings, tag).await;
        all_linked(d, GroupPlaneTable::CommunityWidenings, tag).await;
    }

    /// The SQL that clears the widenings' pointers, on `schema`.
    pub(crate) fn i1489_clear_sql(schema: &str) -> String {
        format!(
            "UPDATE {schema}federation_family_membership_widenings SET attestation_id = NULL; \
             UPDATE {schema}federation_community_membership_widenings SET attestation_id = NULL;"
        )
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
                #[tokio::test]
                async fn i1486() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i1486_rows_replicate(&a, &b, &super::tag()).await;
                }
                #[tokio::test]
                async fn i1488() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1488_rows_reach_the_group_audience(&d, &super::tag())
                        .await;
                }
                #[tokio::test]
                async fn i1491() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i1491_the_row_is_the_signed_bytes(&a, &b, &super::tag())
                        .await;
                }
                #[tokio::test]
                async fn i1492() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1492_a_retraction_has_a_direction(&d, &super::tag())
                        .await;
                }
                #[tokio::test]
                async fn i1487() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1487_cosigned_withdraws(&d, &super::tag()).await;
                }
            }
        };
    }

    async fn i1489_counts<F, Fut>(count: F, schema: &str) -> (i64, i64)
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = i64>,
    {
        use crate::federation::group_plane::GroupPlaneTable;
        let mut signed = 0;
        let mut unlinked = 0;
        for t in GroupPlaneTable::ALL {
            signed += count(super::bodies::signed_sql(schema, t)).await;
            unlinked += count(super::bodies::signed_without_row_sql(schema, t)).await;
        }
        (signed, unlinked)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1489_sqlite() {
        use crate::store::Backend as _;
        let t = tag();
        let old = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        old.run_migrations_through(205).await.unwrap();
        super::bodies::i1489_seed_v60(&old, &t).await;
        old.test_execute(&super::bodies::ed25519_only_sql("", &t))
            .await;
        let mut before = 0;
        for tb in crate::federation::group_plane::GroupPlaneTable::ALL {
            before += old.test_count(&super::bodies::signed_sql("", tb)).await;
        }
        assert_eq!(
            old.test_count(&super::bodies::plane_rows_sql("")).await,
            0,
            "{t}: no group-plane row before the upgrade"
        );
        old.run_migrations().await.unwrap();
        let (signed, unlinked) = i1489_counts(
            |q| {
                let old = &old;
                async move { old.test_count(&q).await }
            },
            "",
        )
        .await;
        assert_eq!(signed, before, "{t}: the upgrade keeps every record");
        let plane = old.test_count(&super::bodies::plane_rows_sql("")).await;
        super::bodies::i1489_after_upgrade(&old, &t, before, plane, unlinked).await;
        let cleared = old
            .test_count(&super::bodies::signed_sql(
                "",
                crate::federation::group_plane::GroupPlaneTable::FamilyWidenings,
            ))
            .await
            + old
                .test_count(&super::bodies::signed_sql(
                    "",
                    crate::federation::group_plane::GroupPlaneTable::CommunityWidenings,
                ))
                .await;
        old.test_execute(&super::bodies::i1489_clear_sql("")).await;
        super::bodies::i1489_relinked(&old, &t, cleared).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1489_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag();
        let old = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        old.run_migrations_through(205).await.unwrap();
        super::bodies::i1489_seed_v60(&old, &t).await;
        let s = "cirislens.";
        old.test_execute(&super::bodies::ed25519_only_sql(s, &t))
            .await;
        let mut before = 0;
        for tb in crate::federation::group_plane::GroupPlaneTable::ALL {
            before += old.test_count(&super::bodies::signed_sql(s, tb)).await;
        }
        assert_eq!(
            old.test_count(&super::bodies::plane_rows_sql(s)).await,
            0,
            "{t}: no group-plane row before the upgrade"
        );
        old.run_migrations().await.unwrap();
        let (signed, unlinked) = i1489_counts(
            |q| {
                let old = &old;
                async move { old.test_count(&q).await }
            },
            s,
        )
        .await;
        assert_eq!(signed, before, "{t}: the upgrade keeps every record");
        let plane = old.test_count(&super::bodies::plane_rows_sql(s)).await;
        super::bodies::i1489_after_upgrade(&old, &t, before, plane, unlinked).await;
        let cleared = old
            .test_count(&super::bodies::signed_sql(
                s,
                crate::federation::group_plane::GroupPlaneTable::FamilyWidenings,
            ))
            .await
            + old
                .test_count(&super::bodies::signed_sql(
                    s,
                    crate::federation::group_plane::GroupPlaneTable::CommunityWidenings,
                ))
                .await;
        old.test_execute(&super::bodies::i1489_clear_sql(s)).await;
        super::bodies::i1489_relinked(&old, &t, cleared).await;
        eprintln!("i1489_postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1497_sqlite() {
        use crate::store::Backend as _;
        let t = tag();
        let old = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        old.run_migrations_through(208).await.unwrap();
        for n in ["ann", "ben", "cat", "dan"] {
            super::bodies::user(&old, &format!("{n}-{t}")).await;
        }
        let room = super::bodies::room_with_history(&old, &t).await;
        old.test_execute(&super::bodies::i1497_seed_listing_sql("", &room, &t))
            .await;
        assert_eq!(
            old.test_count(&super::bodies::i1497_listing_rows_sql(""))
                .await,
            2,
            "{t}: the v60 node holds two listing rows"
        );
        assert_eq!(
            old.test_count(&super::bodies::i1497_listing_adverts_sql(""))
                .await,
            1
        );
        old.run_migrations().await.unwrap();
        assert_eq!(
            old.test_count(
                "SELECT count(*) FROM sqlite_master \
                  WHERE name = 'federation_community_membership_listings'"
            )
            .await,
            0,
            "{t}: I1497 V209 drops the listing table"
        );
        assert_eq!(
            old.test_count(&super::bodies::i1497_listing_adverts_sql(""))
                .await,
            0,
            "{t}: I1497 V209 deletes the kind's advertisements"
        );
        super::bodies::i1497_no_non_member_view(&old, &room, &t).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1497_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag();
        let s = "cirislens.";
        let old = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        old.run_migrations_through(208).await.unwrap();
        for n in ["ann", "ben", "cat", "dan"] {
            super::bodies::user(&old, &format!("{n}-{t}")).await;
        }
        let room = super::bodies::room_with_history(&old, &t).await;
        old.test_execute(&super::bodies::i1497_seed_listing_sql(s, &room, &t))
            .await;
        assert_eq!(
            old.test_count(&super::bodies::i1497_listing_rows_sql(s))
                .await,
            2,
            "{t}: the v60 node holds two listing rows"
        );
        assert_eq!(
            old.test_count(&super::bodies::i1497_listing_adverts_sql(s))
                .await,
            1
        );
        old.run_migrations().await.unwrap();
        assert_eq!(
            old.test_count(
                "SELECT count(*) FROM information_schema.tables \
                  WHERE table_schema = 'cirislens' \
                    AND table_name = 'federation_community_membership_listings'"
            )
            .await,
            0,
            "{t}: I1497 V209 drops the listing table"
        );
        assert_eq!(
            old.test_count(&super::bodies::i1497_listing_adverts_sql(s))
                .await,
            0,
            "{t}: I1497 V209 deletes the kind's advertisements"
        );
        super::bodies::i1497_no_non_member_view(&old, &room, &t).await;
        eprintln!("i1497_postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1490_sqlite() {
        use crate::store::Backend as _;
        let t = tag();
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        super::bodies::i1490_the_gate_can_fail(&d, &t).await;
        d.test_execute(&super::bodies::i1490_tamper_sql("", &t))
            .await;
        super::bodies::i1490_after_tamper(&d, &t).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1490_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag();
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        super::bodies::i1490_the_gate_can_fail(&d, &t).await;
        d.test_execute(&super::bodies::i1490_tamper_sql("cirislens.", &t))
            .await;
        super::bodies::i1490_after_tamper(&d, &t).await;
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
