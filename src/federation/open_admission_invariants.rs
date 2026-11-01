//! v61 S2 (CIRISPersist#1123; CC 4.5.13, 4.4.3.2, 4.4.3.4.2, 3.2) —
//! **one voice never decides who is in a room.** sqlite and postgres.
//!
//! - **I1500** — `founder_only` is refused for a community above the family
//!   (`federation_community_consensus_protocol_violation`, rule
//!   `founder_only_above_family`) at the local record door and the supersede
//!   door, and a replicated version may not move a stored room onto it. A
//!   family and an affiliation keep it; a legacy room a peer delivers is kept
//!   as data and its next version must leave `founder_only`.
//! - **I1501** — `open:self_admit` is admissible only on a `public` room; a
//!   family or a private room that names it is refused, and a record still
//!   carrying the retired `admission` member is refused by name.
//! - **I1502** — under `open:self_admit` the joiner's own signature, after
//!   their acceptance of the founder's standing proposal, is the group's side
//!   of their admission; a founder's signature for them is not; a member's
//!   self-promotion and a non-founder's standing proposal are refused; every
//!   other protocol refuses a self-signed admission.
//! - **I1503** — a removal under `open:self_admit` takes two distinct voices
//!   besides the member removed: one voice is refused, two are admitted.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::FOUNDER_ONLY_ABOVE_FAMILY;
    use crate::federation::membership_acceptance::RULE_ACCEPTANCE_UNRESOLVED;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_affiliation, found_community, found_family, found_public_room, proposal, put, reg,
        reply, widen_community,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::COMMUNITY;
    use crate::federation::types::consensus_protocol::{FOUNDER_ONLY, OPEN_SELF_ADMIT};
    use crate::federation::types::{
        Community, CommunityMember, CommunityMembershipRevocation, SignedCommunity,
    };
    use crate::federation::{
        Error, FederationDirectory, ReplicatedCommunityOutcome, ReplicatedCommunityRefusal,
        ROSTER_CONSENSUS_INSUFFICIENT,
    };
    use chrono::{DateTime, Duration, Utc};

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    /// The rule a refusal names, whichever typed error carries it.
    fn rule(e: &Error) -> String {
        match e {
            Error::CommunityConsensusProtocolViolation { rule, .. }
            | Error::RosterAuthorityUnauthorized { rule, .. }
            | Error::MembershipAcceptanceRefused { rule, .. } => (*rule).to_owned(),
            other => format!("{other:?}"),
        }
    }

    async fn active(d: &dyn FederationDirectory, cid: &str, k: &str) -> bool {
        d.active_community_members(cid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == k)
    }

    fn record(cid: &str, founders: &[&str], protocol: &str) -> Community {
        Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: cid.to_owned(),
            community_name: "I1500 room".into(),
            members: founders
                .iter()
                .map(|k| CommunityMember {
                    key_id: (*k).to_owned(),
                    joined_at: ms(Utc::now() - Duration::days(1)),
                    role: Some("founder".into()),
                })
                .collect(),
            founded_at: ms(Utc::now() - Duration::days(1)),
            consensus_protocol: protocol.to_owned(),
            policy_blob: None,
            persist_row_hash: String::new(),
        }
    }

    fn signed(founder: &str, c: Community) -> SignedCommunity {
        ts::sign_community(founder, c)
    }

    /// **I1500** — `founder_only` above the family.
    pub(crate) async fn i1500_founder_only_is_refused_above_the_family(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (founder, room, aff, fam, legacy, kept) = (
            format!("i1500-f-{s}"),
            format!("i1500-room-{s}"),
            format!("i1500-aff-{s}"),
            format!("i1500-fam-{s}"),
            format!("i1500-legacy-{s}"),
            format!("i1500-kept-{s}"),
        );
        reg(d, &[&founder, &room, &aff, &fam, &legacy, &kept]).await;
        // The local door refuses a NEW founder_only room, by name, storing
        // nothing.
        let e = d
            .put_community(signed(&founder, record(&room, &[&founder], FOUNDER_ONLY)))
            .await
            .expect_err("I1500: founder_only above the family");
        assert_eq!(rule(&e), FOUNDER_ONLY_ABOVE_FAMILY, "I1500: {e}");
        assert_eq!(
            e.kind(),
            "federation_community_consensus_protocol_violation",
            "I1500: the infrastructure token, no new one"
        );
        assert!(d.lookup_community(&room).await.unwrap().is_none());
        // A family and an affiliation keep founder_only.
        found_family(d, &fam, FOUNDER_ONLY, &[&founder], &[])
            .await
            .expect("I1500: a family's protocol");
        found_affiliation(d, &aff, FOUNDER_ONLY, &[&founder], &[])
            .await
            .expect("I1500: an affiliation keeps founder_only (CC 4.4.3.2.8)");
        // A LEGACY room a peer delivers is kept as data and folds.
        let outcome = d
            .apply_replicated_community(signed(
                &founder,
                record(&legacy, &[&founder], FOUNDER_ONLY),
            ))
            .await
            .expect("I1500: the replicated door");
        assert_eq!(outcome, ReplicatedCommunityOutcome::Inserted, "I1500");
        assert!(active(d, &legacy, &founder).await, "I1500: it folds");
        // Its next version on the local supersede door must leave founder_only.
        let held = d.lookup_community(&legacy).await.unwrap().expect("held");
        let mut next = held.clone();
        next.community_name = "renamed".into();
        next.prev_head_digest = held.persist_row_hash.clone();
        next.persist_row_hash = String::new();
        let e = d
            .supersede_community(signed(&founder, next.clone()), None)
            .await
            .expect_err("I1500: a legacy room's next version keeps founder_only");
        assert_eq!(rule(&e), FOUNDER_ONLY_ABOVE_FAMILY, "I1500: {e}");
        next.consensus_protocol = "quorum:1/1".into();
        d.supersede_community(signed(&founder, next), None)
            .await
            .expect("I1500: the version that leaves founder_only is admitted");
        // A peer may not move a stored room ONTO founder_only.
        found_community(d, &kept, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let held = d.lookup_community(&kept).await.unwrap().expect("held");
        let mut onto = held.clone();
        onto.consensus_protocol = FOUNDER_ONLY.into();
        onto.prev_head_digest = held.persist_row_hash.clone();
        onto.persist_row_hash = String::new();
        let outcome = d
            .apply_replicated_community(signed(&founder, onto))
            .await
            .expect("I1500: a typed outcome");
        assert_eq!(
            outcome,
            ReplicatedCommunityOutcome::Refused {
                reason: ReplicatedCommunityRefusal::DegradesConformance
            },
            "I1500: a stored room never moves onto one voice"
        );
        assert_eq!(
            d.lookup_community(&kept)
                .await
                .unwrap()
                .unwrap()
                .consensus_protocol,
            "quorum:1/1",
            "I1500: the stored record stands"
        );
    }

    /// **I1501** — `open:self_admit` only on a public room.
    pub(crate) async fn i1501_open_self_admit_only_on_a_public_room(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (founder, private, fam, public) = (
            format!("i1501-f-{s}"),
            format!("i1501-priv-{s}"),
            format!("i1501-fam-{s}"),
            format!("i1501-pub-{s}"),
        );
        reg(d, &[&founder, &private, &fam, &public]).await;
        let e = found_community(d, &private, OPEN_SELF_ADMIT, &[&founder], &[])
            .await
            .expect_err("I1501: a private room");
        assert_eq!(
            rule(&e),
            crate::federation::public_room::PUBLIC_RULE_OPEN_ADMISSION_NOT_PUBLIC,
            "I1501: {e}"
        );
        let e = found_family(d, &fam, OPEN_SELF_ADMIT, &[&founder], &[])
            .await
            .expect_err("I1501: a family is never public");
        assert!(
            matches!(e, Error::ConsensusProtocolMalformed { .. }),
            "I1501: {e:?}"
        );
        found_public_room(d, &public, OPEN_SELF_ADMIT, &[&founder], &[])
            .await
            .expect("I1501: a public room admits openly");
        assert_eq!(
            d.lookup_community(&public)
                .await
                .unwrap()
                .unwrap()
                .consensus_protocol,
            OPEN_SELF_ADMIT,
            "I1501: the protocol is stored as signed (the V210 CHECK admits it)"
        );
    }

    /// The founder's standing proposal into `cid`, and `joiner`'s acceptance.
    async fn accept_standing(
        d: &dyn FederationDirectory,
        founder: &str,
        cid: &str,
        joiner: &str,
        at: DateTime<Utc>,
    ) -> crate::federation::Attestation {
        let mut p = proposal(
            founder,
            COMMUNITY,
            cid,
            "",
            None,
            at,
            Some(Duration::days(7)),
        );
        p.subject_key_ids.clear();
        ts::seal_row_in_place(founder, &mut p);
        put(d, &p).await.expect("the founder's standing proposal");
        put(
            d,
            &reply(joiner, joiner, &p, true, at + Duration::seconds(1)),
        )
        .await
        .expect("the joiner's own acceptance");
        p
    }

    /// **I1502** — self-admission.
    pub(crate) async fn i1502_the_joiner_admits_themselves(d: &dyn FederationDirectory, s: &str) {
        let (founder, joiner, late, cid, closed) = (
            format!("i1502-f-{s}"),
            format!("i1502-j-{s}"),
            format!("i1502-l-{s}"),
            format!("i1502-pub-{s}"),
            format!("i1502-closed-{s}"),
        );
        reg(d, &[&founder, &joiner, &late, &cid, &closed]).await;
        found_public_room(d, &cid, OPEN_SELF_ADMIT, &[&founder], &[])
            .await
            .unwrap();
        let at = Utc::now() - Duration::hours(1);
        let p = accept_standing(d, &founder, &cid, &joiner, at).await;
        // The founder signing FOR the joiner is not the joiner's own admission.
        let e = widen_community(
            d,
            &cid,
            &[&founder],
            &joiner,
            None,
            at + Duration::seconds(2),
        )
        .await
        .expect_err("I1502: a founder's widening of the joiner");
        assert_eq!(rule(&e), ROSTER_CONSENSUS_INSUFFICIENT, "I1502: {e}");
        assert!(!active(d, &cid, &joiner).await);
        // The joiner's own signature is the group's side.
        widen_community(
            d,
            &cid,
            &[&joiner],
            &joiner,
            None,
            at + Duration::seconds(3),
        )
        .await
        .expect("I1502: the joiner admits themselves");
        assert!(active(d, &cid, &joiner).await, "I1502: the joiner is in");
        // Without their acceptance a self-signed widening is still no consent.
        let e = widen_community(d, &cid, &[&late], &late, None, at + Duration::seconds(4))
            .await
            .expect_err("I1502: no acceptance");
        assert_eq!(rule(&e), RULE_ACCEPTANCE_UNRESOLVED, "I1502: {e}");
        // A seated member's self-promotion is a role change: two voices.
        let e = widen_community(
            d,
            &cid,
            &[&joiner],
            &joiner,
            Some("founder"),
            at + Duration::seconds(5),
        )
        .await
        .expect_err("I1502: a member promotes themselves");
        assert_eq!(rule(&e), ROSTER_CONSENSUS_INSUFFICIENT, "I1502: {e}");
        // Joining confers no authority: a member's standing proposal is refused.
        let mut q = proposal(
            &joiner,
            COMMUNITY,
            &cid,
            "",
            None,
            at,
            Some(Duration::days(7)),
        );
        q.subject_key_ids.clear();
        ts::seal_row_in_place(&joiner, &mut q);
        put(d, &q)
            .await
            .expect_err("I1502: a non-founder's standing proposal");
        let _ = p;
        // Every other protocol refuses a self-signed admission.
        found_community(d, &closed, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let p = proposal(
            &founder,
            COMMUNITY,
            &closed,
            &late,
            None,
            at,
            Some(Duration::days(7)),
        );
        put(d, &p).await.unwrap();
        put(d, &reply(&late, &late, &p, true, at + Duration::seconds(1)))
            .await
            .unwrap();
        let e = widen_community(d, &closed, &[&late], &late, None, at + Duration::seconds(2))
            .await
            .expect_err("I1502: a self-signed admission under quorum:1/1");
        assert!(
            rule(&e) == ROSTER_CONSENSUS_INSUFFICIENT
                || rule(&e) == crate::federation::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
            "I1502: {e}"
        );
        widen_community(
            d,
            &closed,
            &[&founder],
            &late,
            None,
            at + Duration::seconds(3),
        )
        .await
        .expect("I1502: the founder's widening admits under quorum:1/1");
    }

    async fn remove(
        d: &dyn FederationDirectory,
        cid: &str,
        signers: &[&str],
        member: &str,
        at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let mut r = ts::sign_community_membership_revocation(
            signers[0],
            CommunityMembershipRevocation {
                community_key_id: cid.to_owned(),
                removed_identity_key_id: member.to_owned(),
                removed_at: ms(at),
                effective_at: ms(at),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut r, c);
        }
        d.put_community_membership_revocation(r).await
    }

    /// **I1503** — a removal under `open:self_admit` takes two voices.
    pub(crate) async fn i1503_removal_takes_two_voices(d: &dyn FederationDirectory, s: &str) {
        let (f1, f2, f3, joiner, cid) = (
            format!("i1503-f1-{s}"),
            format!("i1503-f2-{s}"),
            format!("i1503-f3-{s}"),
            format!("i1503-j-{s}"),
            format!("i1503-pub-{s}"),
        );
        reg(d, &[&f1, &f2, &f3, &joiner, &cid]).await;
        found_public_room(d, &cid, OPEN_SELF_ADMIT, &[&f1, &f2, &f3], &[])
            .await
            .unwrap();
        let at = Utc::now() - Duration::hours(2);
        accept_standing(d, &f1, &cid, &joiner, at).await;
        widen_community(
            d,
            &cid,
            &[&joiner],
            &joiner,
            None,
            at + Duration::seconds(2),
        )
        .await
        .unwrap();
        assert!(active(d, &cid, &joiner).await);
        // One voice never excludes — a founder's included.
        let e = remove(d, &cid, &[&f1], &joiner, at + Duration::minutes(1))
            .await
            .expect_err("I1503: one voice");
        assert_eq!(rule(&e), ROSTER_CONSENSUS_INSUFFICIENT, "I1503: {e}");
        assert!(active(d, &cid, &joiner).await, "I1503: still in");
        // Two distinct voices remove.
        remove(d, &cid, &[&f1, &f2], &joiner, at + Duration::minutes(2))
            .await
            .expect("I1503: two voices");
        assert!(!active(d, &cid, &joiner).await, "I1503: removed");
        // Leaving stays a member's own act: no floor on a resignation.
        remove(d, &cid, &[&f3], &f3, at + Duration::minutes(3))
            .await
            .expect("I1503: a resignation needs no one");
        assert!(!active(d, &cid, &f3).await);
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! case {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(&d as &dyn FederationDirectory, &suffix())
                                .await
                        }
                    };
                }
                case!(i1500_founder_only_is_refused_above_the_family);
                case!(i1501_open_self_admit_only_on_a_public_room);
                case!(i1502_the_joiner_admits_themselves);
                case!(i1503_removal_takes_two_voices);
            }
        };
    }

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
