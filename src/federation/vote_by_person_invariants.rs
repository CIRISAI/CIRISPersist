//! CIRISPersist#1198 (CC 4.5.13, `CLM-vote-once-per-person`; CC 3.3.6.3) —
//! **a vote counts once per person.** A roster seats a key; the person is the
//! fedID whose self roster the key belongs to; a tally counts fedIDs. sqlite
//! and postgres, through the real doors.
//!
//! - **I1525** — a person's two devices are one voice: on a ballot (second
//!   device unseated, or both seated), on an objection, on a dismissal's
//!   m-of-n, in the numerator and the denominator; an actor's other device is
//!   recused with the actor.
//! - **I1526** — a person's disagreeing rows are no voice, from two devices
//!   or from one key, and every row stays held. The latest-instant fold is
//!   gone.
//! - **I1527** — a withdrawal by any key of the same fedID leaves one voice;
//!   a key of another self cannot withdraw the row, and a person who
//!   withdrew everything has not spoken.
//! - **I1528** — a key of another self does not count: the door refuses it,
//!   and a row held anyway is no voice.
//! - **I1529** — an evicted device's vote is void at the count: a row cast
//!   before the eviction, a row backdated past it, and a seated device's row.
//!   The person's other device keeps the voice.
//! - **I1530** — a membership change counts persons: two seats of one self
//!   are one voice of the denominator and the numerator, a second device
//!   signs for its seated person, another self and an evicted device do not,
//!   in a room and in a family; the removal floor holds.
//! - **I1531** — no row order, in arrival or in `asserted_at`, changes the
//!   count.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::steward_liveness_test_support::{store, withdraws_of};
    use crate::federation::cohort::Cohort;
    use crate::federation::membership_acceptance::test_support::ConsentedWidening as _;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, found_public_room, reg,
    };
    use crate::federation::reverse_quorum::test_support::{
        register_user_key, seed_community, signed_row,
    };
    use crate::federation::reverse_quorum::{
        ballot_envelope, dismissal_envelope, objection_envelope, record_objection_against,
        record_objection_ballot_against, record_objection_dismissal, resolve_reverse_quorum_for,
        ActionRef, ObjectionEscalation, ObjectionOutcome, ObjectionRefusalReason,
        ReverseQuorumFold, ReverseQuorumStanding,
    };
    use crate::federation::self_roster_invariants::bodies::add;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::consensus_protocol::{MAJORITY, OPEN_SELF_ADMIT, UNANIMOUS};
    use crate::federation::types::{
        CommunityMember, CommunityMembershipRevocation, CommunityMembershipWidening,
        FamilyMembershipWidening,
    };
    use crate::federation::{
        Attestation, Error, FederationDirectory, IdentityOccurrenceRevocation,
        ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED, ROSTER_CONSENSUS_INSUFFICIENT,
    };
    use chrono::{DateTime, Duration, DurationRound, Utc};

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        t.duration_trunc(Duration::milliseconds(1)).unwrap()
    }

    /// The escalating protocol every ballot witness declares. The action is
    /// two hours old, so the window and the steward deadline have passed and
    /// the respondent pool is what the fold reports.
    const ESCALATING: &str = "reverse_quorum:2/9:3600+escalate:600:3";

    /// `d` becomes a live second device of the self `f`.
    async fn device(d: &dyn FederationDirectory, f: &str, device: &str) {
        add(d, f, f, device, ms(Utc::now()))
            .await
            .unwrap_or_else(|e| panic!("{device} joins {f}: {e}"));
    }

    /// `device` is evicted from `f`, effective just now. The instant sits
    /// strictly after every assertion of the pair (the #421 rule).
    async fn evict(d: &dyn FederationDirectory, f: &str, device: &str) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let at = ms(Utc::now());
        d.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: f.to_owned(),
            occurrence_key_id: device.to_owned(),
            revoked_at: at,
            effective_at: at,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("evict {device}: {e}"));
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    /// One action under objection in one room: a roster row's content hash, as
    /// the roster fold names it, with one objection filed by `objector`.
    struct Case {
        room: String,
        actor: String,
        action_id: String,
        action_at: DateTime<Utc>,
        objection: String,
    }

    impl Case {
        fn action(&self) -> ActionRef<'_> {
            ActionRef {
                actor_key_id: &self.actor,
                action_id: &self.action_id,
                asserted_at: self.action_at,
            }
        }

        /// A ballot on the case's objection, unsubmitted.
        fn ballot(&self, author: &str, upholds: bool, at: DateTime<Utc>) -> Attestation {
            signed_row(
                &uuid::Uuid::new_v4().to_string(),
                author,
                &self.actor,
                ballot_envelope(
                    Cohort::Community,
                    &self.room,
                    &self.action_id,
                    &self.objection,
                    upholds,
                    "my answer",
                ),
                at,
                &[],
            )
        }

        async fn cast(
            &self,
            d: &dyn FederationDirectory,
            author: &str,
            upholds: bool,
        ) -> Attestation {
            let row = self.ballot(author, upholds, ms(Utc::now()));
            assert_eq!(
                record_objection_ballot_against(d, &row, self.action())
                    .await
                    .expect("ballot door"),
                ObjectionOutcome::Admitted,
                "the ballot of {author} is admitted"
            );
            row
        }

        async fn fold(&self, d: &dyn FederationDirectory) -> ReverseQuorumFold {
            resolve_reverse_quorum_for(
                d,
                Cohort::Community,
                &self.room,
                self.action(),
                Utc::now() + Duration::seconds(1),
            )
            .await
            .expect("resolve")
        }

        async fn pool(&self, d: &dyn FederationDirectory) -> ObjectionEscalation {
            self.fold(d)
                .await
                .escalation
                .into_iter()
                .find(|e| e.objection_id == self.objection)
                .expect("the objection escalated")
        }
    }

    fn objection_row(c: &Case, author: &str, id: &str, at: DateTime<Utc>) -> Attestation {
        signed_row(
            id,
            author,
            &c.actor,
            objection_envelope(Cohort::Community, &c.room, &c.action_id, "undo this"),
            at,
            &[],
        )
    }

    /// A new action in `room` by `actor`, its objection filed by `objector`.
    async fn case(
        d: &dyn FederationDirectory,
        room: &str,
        actor: &str,
        objector: &str,
        tag: &str,
    ) -> Case {
        let action_id = crate::federation::wire_index::content_hash_of_bytes(
            format!("vote-by-person-{tag}-{}", uuid::Uuid::new_v4()).as_bytes(),
        );
        let mut c = Case {
            room: room.to_owned(),
            actor: actor.to_owned(),
            action_id,
            action_at: Utc::now() - Duration::hours(2),
            objection: uuid::Uuid::new_v4().to_string(),
        };
        let o = objection_row(
            &c,
            objector,
            &c.objection,
            c.action_at + Duration::minutes(5),
        );
        assert_eq!(
            record_objection_against(d, &o, c.action())
                .await
                .expect("objection door"),
            ObjectionOutcome::Admitted,
            "the objection is admitted"
        );
        c.objection = o.attestation_id;
        c
    }

    /// The keys of a witness: `names`, each `{tag}-{name}`, registered user
    /// keys. Returned in order.
    async fn people<const N: usize>(
        d: &dyn FederationDirectory,
        tag: &str,
        names: [&str; N],
    ) -> [String; N] {
        let keys = names.map(|n| format!("{tag}-{n}"));
        for k in &keys {
            register_user_key(d, k).await;
        }
        keys
    }

    /// **I1525** — a person's two devices are one voice.
    pub(crate) async fn i1525_two_devices_are_one_voice(d: &dyn FederationDirectory, tag: &str) {
        let [f, p, pd, q, r, actor, actor2] =
            people(d, tag, ["f", "p", "pd", "q", "r", "actor", "actor2"]).await;
        device(d, &p, &pd).await;
        device(d, &actor, &actor2).await;

        // ── The second device is not seated: it votes as its person.
        let room = format!("{tag}-unseated");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;
        let a = c.cast(d, &p, false).await;
        let b = c.cast(d, &pd, false).await;
        c.cast(d, &r, true).await;
        let e = c.pool(d).await;
        assert_eq!(
            (e.respondents, e.uphold_ballots, e.overrule_ballots),
            (2, 1, 1),
            "I1525: p's two devices agree, one voice: {e:?}"
        );
        assert_eq!(e.counted_ballot_ids.len(), 2, "I1525: {e:?}");
        assert!(
            [&a.attestation_id, &b.attestation_id]
                .iter()
                .any(|id| e.counted_ballot_ids.contains(id)),
            "I1525: one of p's rows stands for the voice: {e:?}"
        );

        // ── An actor's other device is recused with them.
        let recused = c.ballot(&actor2, true, ms(Utc::now()));
        assert_eq!(
            record_objection_ballot_against(d, &recused, c.action())
                .await
                .expect("door")
                .refusal(),
            Some(ObjectionRefusalReason::ActorRecused),
            "I1525: the actor's second device is the actor"
        );

        // ── Both devices seated: one voice, numerator and denominator.
        let room = format!("{tag}-seated");
        let seats = [&f, &p, &pd, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;
        c.cast(d, &p, true).await;
        c.cast(d, &pd, true).await;
        let fold = c.fold(d).await;
        assert_eq!(fold.roster_size, 5, "I1525: two seats, one self: {fold:?}");
        let e = &fold.escalation[0];
        assert_eq!(
            (e.respondents, e.uphold_ballots),
            (1, 1),
            "I1525: both seated, one voice: {e:?}"
        );

        // ── An objection and a dismissal count persons too.
        let room = format!("{tag}-objectors");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, "reverse_quorum:2/5:86400").await;
        let c = case(d, &room, &actor, &p, tag).await;
        let second = objection_row(&c, &pd, &uuid::Uuid::new_v4().to_string(), ms(Utc::now()));
        assert_eq!(
            record_objection_against(d, &second, c.action())
                .await
                .expect("door"),
            ObjectionOutcome::Admitted,
            "I1525: a second device objects as its person"
        );
        let fold = c.fold(d).await;
        assert_eq!(fold.distinct_objectors, 1, "I1525: {fold:?}");
        assert_eq!(
            fold.standing,
            ReverseQuorumStanding::WindowOpen,
            "I1525: one person's two rows reverse nothing"
        );
        let third = objection_row(&c, &q, &uuid::Uuid::new_v4().to_string(), ms(Utc::now()));
        record_objection_against(d, &third, c.action())
            .await
            .expect("door");
        let fold = c.fold(d).await;
        assert_eq!(fold.distinct_objectors, 2, "I1525: {fold:?}");
        assert_eq!(fold.standing, ReverseQuorumStanding::Reversed, "I1525");

        // A dismissal of q's objection needs three of five persons: p's two
        // devices and r are two.
        let dismiss = |cosigners: &[&str]| {
            signed_row(
                &uuid::Uuid::new_v4().to_string(),
                &r,
                &c.actor,
                dismissal_envelope(
                    Cohort::Community,
                    &c.room,
                    &c.action_id,
                    &third.attestation_id,
                    "no",
                ),
                ms(Utc::now()),
                cosigners,
            )
        };
        let short = record_objection_dismissal(d, &dismiss(&[p.as_str(), pd.as_str()]))
            .await
            .expect("door");
        assert_eq!(
            (short.quorum.counted, short.quorum.required),
            (2, 3),
            "I1525: p's two devices are one signature of the m-of-n: {short:?}"
        );
        let met = record_objection_dismissal(d, &dismiss(&[pd.as_str(), f.as_str()]))
            .await
            .expect("door");
        assert_eq!(
            met.outcome,
            ObjectionOutcome::Admitted,
            "I1525: a second device signs for its person: {met:?}"
        );
    }

    /// **I1526** — disagreeing rows are no voice; every row stays held.
    pub(crate) async fn i1526_disagreement_is_no_voice(d: &dyn FederationDirectory, tag: &str) {
        let [f, p, pd, q, r, s, actor] =
            people(d, tag, ["f", "p", "pd", "q", "r", "s", "actor"]).await;
        device(d, &p, &pd).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &s, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;

        let held = [
            c.cast(d, &p, true).await,
            c.cast(d, &pd, false).await,
            // One key changing its answer with no withdrawal: the retired
            // latest-instant fold counted the later row.
            c.cast(d, &r, false).await,
        ];
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let later = c.cast(d, &r, true).await;
        c.cast(d, &s, true).await;

        let e = c.pool(d).await;
        assert_eq!(
            (e.respondents, e.uphold_ballots, e.overrule_ballots),
            (1, 1, 0),
            "I1526: p and r are at odds with themselves, only s has spoken: {e:?}"
        );
        for row in held.iter().chain([&later]) {
            assert!(
                d.get_attestation(&row.attestation_id)
                    .await
                    .expect("read")
                    .is_some(),
                "I1526: every vote row is kept"
            );
        }
    }

    /// **I1527** — a withdrawal by any key of the same fedID leaves one voice.
    pub(crate) async fn i1527_a_sibling_withdrawal_leaves_one(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [f, p, pd, q, r, actor] = people(d, tag, ["f", "p", "pd", "q", "r", "actor"]).await;
        device(d, &p, &pd).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;

        let uphold = c.cast(d, &p, true).await;
        let overrule = c.cast(d, &pd, false).await;
        assert_eq!(c.pool(d).await.respondents, 0, "I1527: at odds");

        // Another self's key may not withdraw it, and its attempt changes
        // nothing.
        store(d, &withdraws_of(&r, &r, &uphold.attestation_id))
            .await
            .expect_err("I1527: a key of another self withdraws nothing");
        assert_eq!(c.pool(d).await.respondents, 0, "I1527: still at odds");

        // The sibling device withdraws the row the first device signed.
        store(d, &withdraws_of(&pd, &pd, &uphold.attestation_id))
            .await
            .unwrap_or_else(|e| panic!("I1527: a sibling key withdraws: {e}"));
        let e = c.pool(d).await;
        assert_eq!(
            (e.respondents, e.uphold_ballots, e.overrule_ballots),
            (1, 0, 1),
            "I1527: the withdrawal leaves one standing: {e:?}"
        );
        assert_eq!(e.counted_ballot_ids, vec![overrule.attestation_id.clone()]);

        // Nothing left: the person has not spoken.
        store(d, &withdraws_of(&p, &p, &overrule.attestation_id))
            .await
            .unwrap_or_else(|e| panic!("I1527: the other way round: {e}"));
        assert_eq!(c.pool(d).await.respondents, 0, "I1527: all withdrawn");

        // A fresh row is a new voice.
        c.cast(d, &p, true).await;
        let e = c.pool(d).await;
        assert_eq!((e.respondents, e.uphold_ballots), (1, 1), "I1527: {e:?}");
    }

    /// **I1528** — a key of another self does not count.
    pub(crate) async fn i1528_another_self_does_not_count(d: &dyn FederationDirectory, tag: &str) {
        let [f, p, q, r, actor, o, od] =
            people(d, tag, ["f", "p", "q", "r", "actor", "o", "od"]).await;
        device(d, &o, &od).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;
        for stranger in [&o, &od] {
            let row = c.ballot(stranger, true, ms(Utc::now()));
            assert_eq!(
                record_objection_ballot_against(d, &row, c.action())
                    .await
                    .expect("door")
                    .refusal(),
                Some(ObjectionRefusalReason::NotACohortMember),
                "I1528: {stranger} is not of the room"
            );
            // Held anyway (a replicated row): no voice.
            d.put_attestation(crate::federation::SignedAttestation { attestation: row })
                .await
                .expect("held");
        }
        assert_eq!(c.pool(d).await.respondents, 0, "I1528: no voice");
    }

    /// **I1529** — an evicted device's vote is void at the count.
    pub(crate) async fn i1529_an_evicted_devices_vote_is_void(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [f, p, pd, ps, q, r, actor] =
            people(d, tag, ["f", "p", "pd", "ps", "q", "r", "actor"]).await;
        device(d, &p, &pd).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;

        // Cast while live: one voice.
        let cast_at = ms(Utc::now());
        c.cast(d, &pd, true).await;
        assert_eq!(c.pool(d).await.respondents, 1, "I1529: live, it counts");

        evict(d, &p, &pd).await;
        assert_eq!(
            c.pool(d).await.respondents,
            0,
            "I1529: the row is held and the device is gone"
        );

        // Signed after the eviction, unbackdated: not of the room.
        let late = c.ballot(&pd, true, ms(Utc::now()));
        assert_eq!(
            record_objection_ballot_against(d, &late, c.action())
                .await
                .expect("door")
                .refusal(),
            Some(ObjectionRefusalReason::NotACohortMember),
            "I1529: an evicted device is no member's device"
        );

        // Signed after the eviction and dated before it: a signer-chosen
        // instant reinstates nothing.
        let backdated = c.ballot(&pd, true, cast_at);
        assert_eq!(
            record_objection_ballot_against(d, &backdated, c.action())
                .await
                .expect("door"),
            ObjectionOutcome::Admitted,
            "I1529: at its claimed instant the key was live"
        );
        assert_eq!(c.pool(d).await.respondents, 0, "I1529: still void");

        // The person keeps their voice on the keys they still hold.
        c.cast(d, &p, false).await;
        let e = c.pool(d).await;
        assert_eq!((e.respondents, e.overrule_ballots), (1, 1), "I1529: {e:?}");

        // A SEATED device, evicted: the seat stands for its person, whose
        // other key answers; the device's own row is void.
        device(d, &p, &ps).await;
        let room = format!("{tag}-seated");
        let seats = [&f, &ps, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;
        c.cast(d, &ps, true).await;
        evict(d, &p, &ps).await;
        assert_eq!(c.pool(d).await.respondents, 0, "I1529: seated and evicted");
        assert_eq!(c.fold(d).await.roster_size, 5, "I1529: p keeps the seat");
        c.cast(d, &p, false).await;
        let e = c.pool(d).await;
        assert_eq!((e.respondents, e.overrule_ballots), (1, 1), "I1529: {e:?}");
    }

    fn insufficient(e: &Error) -> bool {
        matches!(
            e,
            Error::RosterAuthorityUnauthorized { rule, .. }
                if *rule == ROSTER_CONSENSUS_INSUFFICIENT
                    || *rule == ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED
        )
    }

    async fn widen(
        d: &dyn FederationDirectory,
        room: &str,
        member: &str,
        signers: &[&str],
    ) -> Result<(), Error> {
        let at = ms(Utc::now());
        let mut w = ts::sign_community_membership_widening(
            signers[0],
            CommunityMembershipWidening {
                community_key_id: room.to_owned(),
                member_key_id: member.to_owned(),
                joined_at: at,
                effective_at: at,
                role: None,
                persist_row_hash: String::new(),
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_widening(&mut w, c);
        }
        d.put_community_membership_widening_consented(w).await
    }

    async fn remove(
        d: &dyn FederationDirectory,
        room: &str,
        member: &str,
        signers: &[&str],
    ) -> Result<(), Error> {
        let at = ms(Utc::now());
        let mut r = ts::sign_community_membership_revocation(
            signers[0],
            CommunityMembershipRevocation {
                community_key_id: room.to_owned(),
                removed_identity_key_id: member.to_owned(),
                removed_at: at,
                effective_at: at,
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

    async fn seated(d: &dyn FederationDirectory, room: &str, k: &str) -> bool {
        let roster: Vec<CommunityMember> = d.active_community_members(room).await.unwrap();
        roster.iter().any(|m| m.key_id == k)
    }

    /// **I1530** — a membership change counts persons.
    pub(crate) async fn i1530_a_membership_change_counts_persons(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [p, pd, q, r, x, y, z, o, od] =
            ["p", "pd", "q", "r", "x", "y", "z", "o", "od"].map(|n| format!("{tag}-{n}"));
        let (room, unseated) = (format!("{tag}-room"), format!("{tag}-unseated"));
        reg(d, &[&p, &pd, &q, &r, &x, &y, &z, &o, &od, &room, &unseated]).await;
        device(d, &p, &pd).await;
        device(d, &o, &od).await;

        // ── Two seats of one self: a person of two, not two of three.
        found_community(d, &room, MAJORITY, &[&p, &pd, &q], &[])
            .await
            .unwrap();
        let e = widen(d, &room, &x, &[&p, &pd])
            .await
            .expect_err("I1530: one person's two seats are one voice of two");
        assert!(insufficient(&e), "I1530: {e}");
        assert!(!seated(d, &room, &x).await, "I1530: x stays out");
        widen(d, &room, &x, &[&p, &q])
            .await
            .unwrap_or_else(|e| panic!("I1530: two persons of two: {e}"));
        assert!(seated(d, &room, &x).await, "I1530: x is in");

        // ── A device that holds no seat signs for its seated person; a key
        //    of another self does not, and an evicted device does not.
        found_community(d, &unseated, MAJORITY, &[&p, &q, &r], &[])
            .await
            .unwrap();
        let e = widen(d, &unseated, &y, &[&p, &pd])
            .await
            .expect_err("I1530: one person's two devices are one voice of three");
        assert!(insufficient(&e), "I1530: {e}");
        let e = widen(d, &unseated, &y, &[&q, &od])
            .await
            .expect_err("I1530: a key of another self does not count");
        assert!(insufficient(&e), "I1530: {e}");
        widen(d, &unseated, &y, &[&q, &pd])
            .await
            .unwrap_or_else(|e| panic!("I1530: pd signs as p: {e}"));
        assert!(seated(d, &unseated, &y).await, "I1530: y is in");
        evict(d, &p, &pd).await;
        let e = widen(d, &unseated, &z, &[&q, &pd])
            .await
            .expect_err("I1530: an evicted device signs for nobody");
        assert!(insufficient(&e), "I1530: {e}");
    }

    /// **I1531** — no row order changes the count.
    pub(crate) async fn i1531_no_order_changes_the_count(d: &dyn FederationDirectory, tag: &str) {
        let [f, p, pd, q, r, actor] = people(d, tag, ["f", "p", "pd", "q", "r", "actor"]).await;
        device(d, &p, &pd).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let rows: [(&str, bool); 3] = [(&p, true), (&pd, false), (&r, true)];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let c = case(d, &room, &actor, &q, tag).await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let base = ms(Utc::now()) - Duration::milliseconds(10);
            for (pos, i) in order.into_iter().enumerate() {
                let (who, upholds) = rows[i];
                // The instant follows the order too: position 2 is latest.
                let at = base + Duration::milliseconds(pos as i64);
                let row = c.ballot(who, upholds, at);
                assert_eq!(
                    record_objection_ballot_against(d, &row, c.action())
                        .await
                        .expect("door"),
                    ObjectionOutcome::Admitted,
                    "I1531 {order:?}: {who}"
                );
            }
            let e = c.pool(d).await;
            assert_eq!(
                (e.respondents, e.uphold_ballots, e.overrule_ballots),
                (1, 1, 0),
                "I1531 {order:?}: p is at odds, r has spoken: {e:?}"
            );
        }
    }

    /// **I1530 (the removal floor and a family)** — sits apart so a red here
    /// is read as the floor, not the count.
    pub(crate) async fn i1530b_the_floor_counts_persons(d: &dyn FederationDirectory, tag: &str) {
        let [p, pd, q, r, x, f1, f2, j] =
            ["p", "pd", "q", "r", "x", "f1", "f2", "j"].map(|n| format!("{tag}-{n}"));
        let (unan, open, fam) = (
            format!("{tag}-unan"),
            format!("{tag}-open"),
            format!("{tag}-fam"),
        );
        reg(d, &[&p, &pd, &q, &r, &x, &f1, &f2, &j, &unan, &open, &fam]).await;
        device(d, &p, &pd).await;

        // `unanimous`: every OTHER person, and those voices a strict majority
        // of persons. p, q, r are three people on four seats.
        found_community(d, &unan, UNANIMOUS, &[&p, &pd, &q, &r], &[])
            .await
            .unwrap();
        let e = remove(d, &unan, &r, &[&p, &pd])
            .await
            .expect_err("I1530: p is one of the two other persons");
        assert!(insufficient(&e), "I1530: {e}");
        assert!(seated(d, &unan, &r).await, "I1530: r stays");
        remove(d, &unan, &r, &[&pd, &q])
            .await
            .unwrap_or_else(|e| panic!("I1530: both other persons: {e}"));
        assert!(!seated(d, &unan, &r).await, "I1530: r is gone");

        // The removal floor (`CLM-removal-floor-every-protocol`): one person's
        // two devices are one voice under open admission.
        found_public_room(d, &open, OPEN_SELF_ADMIT, &[&p, &f1, &f2, &j], &[])
            .await
            .unwrap();
        let e = remove(d, &open, &j, &[&p, &pd])
            .await
            .expect_err("I1530: two devices never remove");
        assert!(insufficient(&e), "I1530: {e}");
        assert!(seated(d, &open, &j).await, "I1530: j stays");
        remove(d, &open, &j, &[&pd, &f1])
            .await
            .unwrap_or_else(|e| panic!("I1530: two persons remove: {e}"));
        assert!(!seated(d, &open, &j).await, "I1530: j is gone");

        // A family runs the same fold.
        found_family(d, &fam, MAJORITY, &[&p, &pd, &q], &[])
            .await
            .unwrap();
        let widen_family = |signers: &[&str]| {
            let at = ms(Utc::now());
            let mut w = ts::sign_family_membership_widening(
                signers[0],
                FamilyMembershipWidening {
                    family_key_id: fam.clone(),
                    member_key_id: x.clone(),
                    joined_at: at,
                    effective_at: at,
                    role: None,
                    persist_row_hash: String::new(),
                },
            );
            for c in &signers[1..] {
                ts::cosign_family_membership_widening(&mut w, c);
            }
            w
        };
        let e = d
            .put_family_membership_widening_consented(widen_family(&[&p, &pd]))
            .await
            .expect_err("I1530: a family's two seats of one self are one voice");
        assert!(insufficient(&e), "I1530: {e}");
        d.put_family_membership_widening_consented(widen_family(&[&pd, &q]))
            .await
            .unwrap_or_else(|e| panic!("I1530: two persons of a family: {e}"));
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        panic!("no CIRIS_PERSIST_TEST_PG base DSN");
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    /// **I1530 (held rows)** — an event held under the per-key count stays in
    /// the fold (the #1200 posture), and the door refuses the same event now.
    #[test]
    fn i1530c_a_held_event_stands_and_a_new_one_is_refused() {
        use crate::federation::key_person::KeySelves;
        use crate::federation::types::consensus_protocol::MAJORITY;
        use crate::federation::types::CommunityMember;
        use crate::federation::{
            authorized_roster_at, authorized_roster_state_at, roster_event_standing, RosterEvent,
            RosterRules, NO_NODE_BEARING_SEATS,
        };
        let t: chrono::DateTime<chrono::Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let member = |k: &str| CommunityMember {
            key_id: k.into(),
            joined_at: t,
            role: Some("founder".to_owned()),
        };
        let persons = KeySelves::of_devices(&[("p", "pd", false)]);
        let rules = RosterRules {
            protocol: MAJORITY,
            subkind: None,
            policy_blob: None,
            node_bearing: &NO_NODE_BEARING_SEATS,
            persons: &persons,
        };
        let record = vec![member("p"), member("pd"), member("q")];
        let event = RosterEvent {
            effective_at: t,
            is_add: true,
            member: member("x"),
            signers: ["p".to_owned(), "pd".to_owned()].into_iter().collect(),
            moderator_roots: Default::default(),
            reversed: false,
        };
        let state = authorized_roster_state_at(&record, rules, &[], t);
        roster_event_standing(rules, &state, &event)
            .expect_err("I1530: the door counts one person of two");
        let roster = authorized_roster_at(&record, rules, &[event], t);
        assert!(
            roster.iter().any(|m| m.key_id == "x"),
            "I1530: the row already held stands"
        );
    }

    on_every_backend!(i1525, bodies::i1525_two_devices_are_one_voice);
    on_every_backend!(i1526, bodies::i1526_disagreement_is_no_voice);
    on_every_backend!(i1527, bodies::i1527_a_sibling_withdrawal_leaves_one);
    on_every_backend!(i1528, bodies::i1528_another_self_does_not_count);
    on_every_backend!(i1529, bodies::i1529_an_evicted_devices_vote_is_void);
    on_every_backend!(i1530, bodies::i1530_a_membership_change_counts_persons);
    on_every_backend!(i1530b, bodies::i1530b_the_floor_counts_persons);
    on_every_backend!(i1531, bodies::i1531_no_order_changes_the_count);
}
