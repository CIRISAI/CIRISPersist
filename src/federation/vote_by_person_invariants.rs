//! CIRISPersist#1198 (CC 4.5.13, `CLM-vote-once-per-person`; CC 3.3.6.3) —
//! **a vote counts once per person.** A roster seats a key; the person is the
//! fedID whose self roster the key belongs to; a tally counts fedIDs. sqlite
//! and postgres, through the real doors.
//!
//! - **I1525** — a person's two devices are one voice: on a ballot (second
//!   device unseated, or both seated), on an objection, on a dismissal's
//!   m-of-n, in the numerator and the denominator; an actor's other device is
//!   recused with the actor; a held dismissal carried by two seats of one self
//!   no longer clears.
//! - **I1526** — a person's disagreeing rows are no voice, from two devices
//!   or from one key, and every row stays held. The latest-instant fold is
//!   gone.
//! - **I1527** — a withdrawal by any key of the same fedID leaves one voice;
//!   a key of another self's withdrawal is held and retracts nothing, and a
//!   person who withdrew everything has not spoken.
//! - **I1528** — a key of another self does not count: its row is admitted
//!   and held, and is no voice.
//! - **I1529** — an evicted device's vote is void at the count: a row cast
//!   before the eviction, a row after it, one backdated past it, and a seated
//!   device's row.
//!   The person's other device keeps the voice.
//! - **I1530** — a membership change counts persons: two seats of one self
//!   are one voice of the denominator and the numerator, a second device
//!   signs for its seated person, another self and an evicted device do not,
//!   in a room and in a family; the removal floor holds.
//! - **I1532** (`group_plane_invariants`) — a cosigned `withdraws` of a roster
//!   event counts persons, a second device signing for its seated person.
//! - **I1533** (CC's ruling on #1198, item 1) — the count reads no clock: a
//!   held revocation ends a key's voice whatever instant it names, expiry
//!   ends nothing, and two values of `now` give one count.
//! - **I1534** (item 2) — every verifiable vote row is admitted and the fold
//!   voids it: a ballot held before its occurrence row counts the moment that
//!   row is held, and two nodes reach one count in either arrival order.
//! - **I1535** (item 3) — an evicted seat stays its person's, in a
//!   `founder_only` family: the person's other key acts, the evicted one does
//!   not.
//! - **I1536** (item 5) — a recanted row is not live, as a withdrawn one.
//! - **I1537** (CC's second ruling, item 1) — `deadline_passed` is a window
//!   answer: it runs from this node's first-held instant, never a signed one,
//!   it closes and never reopens, and a held steward ruling beats it.
//! - **I1538** (item 3) — a vote row naming something not yet held is held and
//!   counts once the fold can resolve it, in either arrival order; one naming
//!   something never held counts for nothing; a dismissal short of its floor
//!   is held and counts for nothing until its cosigners' standing is held.
//! - **I1539** (item 4) — `ActorRecused` reads the exact key from the row and
//!   its held target; where the target is not yet held the ballot waits for
//!   the fold, which recuses the actor.
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
        record_objection_ballot, record_objection_ballot_against, record_objection_dismissal,
        resolve_reverse_quorum_for, ActionRef, EscalationOutcome, ObjectionEscalation,
        ObjectionOutcome, ObjectionRefusalReason, ReverseQuorumFold, ReverseQuorumStanding,
        StewardTierStanding,
    };
    use crate::federation::self_roster_invariants::bodies::add;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::consensus_protocol::{
        FOUNDER_ONLY, MAJORITY, OPEN_SELF_ADMIT, UNANIMOUS,
    };
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

        // ── An actor's other device is recused with them: the row is admitted,
        //    since the door may not yet hold the occurrence, and the fold
        //    voids it.
        c.cast(d, &actor2, true).await;
        assert_eq!(
            c.pool(d).await.respondents,
            2,
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

        // The dismissal m-of-n's denominator is persons too: three of five,
        // where six seats would ask four.
        let lone = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &r,
            &c.actor,
            dismissal_envelope(Cohort::Community, &c.room, &c.action_id, &c.objection, "no"),
            ms(Utc::now()),
            &[],
        );
        let short = record_objection_dismissal(d, &lone).await.expect("door");
        assert_eq!(
            (short.quorum.roster_size, short.quorum.required),
            (5, 3),
            "I1525: {short:?}"
        );

        // A dismissal held from before this count, carried by two seats of one
        // self, stops clearing: three keys, two persons (a named adopter
        // delta, CC's ruling on #1198, item 4).
        let held = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &r,
            &c.actor,
            dismissal_envelope(
                Cohort::Community,
                &c.room,
                &c.action_id,
                &c.objection,
                "carried by keys",
            ),
            ms(Utc::now()),
            &[p.as_str(), pd.as_str()],
        );
        d.put_attestation(crate::federation::SignedAttestation { attestation: held })
            .await
            .expect("held");
        let fold = c.fold(d).await;
        assert!(
            fold.dismissed_objection_ids.is_empty(),
            "I1525: two persons of five do not dismiss: {fold:?}"
        );

        // A reversal's cap at the roster is a cap at the persons on it.
        let room = format!("{tag}-capped");
        let seats = [&f, &p, &pd, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, "reverse_quorum:6/6:86400").await;
        let c = case(d, &room, &actor, &q, tag).await;
        assert_eq!(c.fold(d).await.required, 5, "I1525: six seats, five people");

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

        // Another self's key withdraws nothing: the row is admitted, carries
        // no admission rule, and the fold ignores it.
        let foreign = withdraws_of(&r, &r, &uphold.attestation_id);
        store(d, &foreign)
            .await
            .unwrap_or_else(|e| panic!("I1527: the row is verifiable: {e}"));
        assert_eq!(
            d.get_attestation(&foreign.attestation_id)
                .await
                .unwrap()
                .expect("held")
                .withdraws_admission_rule,
            None,
            "I1527: no reader may honour it as an admitted retraction"
        );
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

        // An objection is a vote row too: a stranger's withdrawal of it is
        // held and ignored, the person's sibling key retracts it.
        let c = case(d, &room, &actor, &p, tag).await;
        store(d, &withdraws_of(&r, &r, &c.objection))
            .await
            .unwrap_or_else(|e| panic!("I1527: held: {e}"));
        assert_eq!(c.fold(d).await.distinct_objectors, 1, "I1527: still raised");
        store(d, &withdraws_of(&pd, &pd, &c.objection))
            .await
            .unwrap_or_else(|e| panic!("I1527: a sibling retracts: {e}"));
        assert_eq!(c.fold(d).await.distinct_objectors, 0, "I1527: retracted");
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
            c.cast(d, stranger, true).await;
            let objection = objection_row(
                &c,
                stranger,
                &uuid::Uuid::new_v4().to_string(),
                c.action_at + Duration::minutes(6),
            );
            assert_eq!(
                record_objection_against(d, &objection, c.action())
                    .await
                    .expect("door"),
                ObjectionOutcome::Admitted,
                "I1528: a verifiable row is admitted"
            );
        }
        let fold = c.fold(d).await;
        assert_eq!(fold.escalation[0].respondents, 0, "I1528: no voice");
        assert_eq!(fold.distinct_objectors, 1, "I1528: q's objection alone");
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

        // Signed after the eviction: admitted, held, void.
        c.cast(d, &pd, true).await;
        assert_eq!(c.pool(d).await.respondents, 0, "I1529: void after it too");

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

    /// **I1533** — the count reads no clock.
    pub(crate) async fn i1533_the_count_reads_no_clock(d: &dyn FederationDirectory, tag: &str) {
        let [f, p, pd, pe, q, r, s, actor] =
            people(d, tag, ["f", "p", "pd", "pe", "q", "r", "s", "actor"]).await;
        device(d, &p, &pd).await;
        // pe's assertion expires almost at once.
        let at = ms(Utc::now());
        d.put_identity_occurrence(
            ts::signed_content_only_occurrence_until(
                &s,
                &s,
                &pe,
                at,
                Some(at + Duration::milliseconds(40)),
            )
            .await,
        )
        .await
        .unwrap_or_else(|e| panic!("I1533: pe joins s: {e}"));
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &s, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;

        // An expired device still votes: only a held revocation ends a voice.
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        c.cast(d, &pe, true).await;
        let e = c.pool(d).await;
        assert_eq!(
            (e.respondents, e.uphold_ballots),
            (1, 1),
            "I1533: expiry voids nothing at the count: {e:?}"
        );

        // A revocation dated in the future is held, so the voice is over now.
        let cast = c.cast(d, &pd, false).await;
        let later = ms(Utc::now()) + Duration::days(30);
        d.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: p.clone(),
            occurrence_key_id: pd.clone(),
            revoked_at: later,
            effective_at: later,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("I1533: the revocation lands: {e}"));
        assert_eq!(
            c.pool(d).await.respondents,
            1,
            "I1533: a held revocation ends the voice, whatever instant it names"
        );
        assert!(
            d.get_attestation(&cast.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I1533: the row stays held"
        );

        // Two values of `now`, before and long after the rows' instants, give
        // one count. A row dated after `now` is counted: `now` is not an input.
        let answer = |e: ObjectionEscalation| {
            (
                e.respondents,
                e.uphold_ballots,
                e.overrule_ballots,
                e.counted_ballot_ids,
            )
        };
        let mut answers = Vec::new();
        for now in [
            c.action_at + Duration::hours(1) + Duration::minutes(11),
            Utc::now() + Duration::days(3650),
        ] {
            let fold = resolve_reverse_quorum_for(d, Cohort::Community, &c.room, c.action(), now)
                .await
                .expect("resolve");
            answers.push(answer(fold.escalation[0].clone()));
        }
        assert_eq!(answers[0], answers[1], "I1533: `now` is not an input");
        assert_eq!(answers[0].0, 1, "I1533: {answers:?}");

        // The clock gates admission: a row dated far ahead is refused at the
        // door by the universal signed-instant gate.
        let ahead = c.ballot(&r, true, ms(Utc::now()) + Duration::days(36_500));
        record_objection_ballot_against(d, &ahead, c.action())
            .await
            .expect_err("I1533: the door refuses a row past its skew");
    }

    /// **I1534** — a ballot held before its occurrence, on one node.
    pub(crate) async fn i1534_a_ballot_before_its_occurrence(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [f, p, pd, q, r, actor] = people(d, tag, ["f", "p", "pd", "q", "r", "actor"]).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;

        // The device's ballot arrives first, and is held. Its key is not yet
        // anyone's.
        c.cast(d, &pd, true).await;
        assert_eq!(c.pool(d).await.respondents, 0, "I1534: not yet p's");

        // The moment the occurrence is held, it is p's voice.
        device(d, &p, &pd).await;
        let e = c.pool(d).await;
        assert_eq!((e.respondents, e.uphold_ballots), (1, 1), "I1534: {e:?}");

        // A second objection by one key is admitted too: one voice.
        let again = objection_row(
            &c,
            &q,
            &uuid::Uuid::new_v4().to_string(),
            c.action_at + Duration::minutes(6),
        );
        assert_eq!(
            record_objection_against(d, &again, c.action())
                .await
                .expect("door"),
            ObjectionOutcome::Admitted,
            "I1534: nothing is refused for arriving second"
        );
        assert_eq!(c.fold(d).await.distinct_objectors, 1, "I1534: one voice");
    }

    /// **I1534 (two nodes)** — either arrival order, one count. `first` takes
    /// the occurrence then the ballot, `second` the ballot then the
    /// occurrence.
    pub(crate) async fn i1534b_either_arrival_order(
        first: &dyn FederationDirectory,
        second: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [f, p, pd, q, r, actor] =
            ["f", "p", "pd", "q", "r", "actor"].map(|n| format!("{tag}-{n}"));
        let room = format!("{tag}-room");
        let action_id = crate::federation::wire_index::content_hash_of_bytes(tag.as_bytes());
        let action_at = Utc::now() - Duration::hours(2);
        let mut c = Case {
            room: room.clone(),
            actor: actor.clone(),
            action_id,
            action_at,
            objection: uuid::Uuid::new_v4().to_string(),
        };
        let objection = objection_row(&c, &q, &c.objection, action_at + Duration::minutes(5));
        c.objection = objection.attestation_id.clone();
        for d in [first, second] {
            for k in [&f, &p, &pd, &q, &r, &actor] {
                register_user_key(d, k).await;
            }
            let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
            seed_community(d, &room, &seats, ESCALATING).await;
            record_objection_against(d, &objection, c.action())
                .await
                .expect("door");
        }
        let occurrence = ts::signed_content_only_occurrence(&p, &p, &pd, ms(Utc::now())).await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let ballot = c.ballot(&pd, false, ms(Utc::now()));
        first
            .put_identity_occurrence(occurrence.clone())
            .await
            .expect("occurrence");
        for d in [first, second] {
            assert_eq!(
                record_objection_ballot_against(d, &ballot, c.action())
                    .await
                    .expect("door"),
                ObjectionOutcome::Admitted,
                "I1534: admitted in either order"
            );
        }
        second
            .put_identity_occurrence(occurrence)
            .await
            .expect("occurrence");
        let (a, b) = (c.pool(first).await, c.pool(second).await);
        assert_eq!(
            (a.respondents, a.overrule_ballots, &a.counted_ballot_ids),
            (b.respondents, b.overrule_ballots, &b.counted_ballot_ids),
            "I1534: every node holding the same rows reaches the same count"
        );
        assert_eq!((a.respondents, a.overrule_ballots), (1, 1), "I1534: {a:?}");
    }

    /// **I1535** — an evicted founder seat in a `founder_only` family.
    pub(crate) async fn i1535_an_evicted_seat_stays_the_persons(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [p, ps, q, x, y] = ["p", "ps", "q", "x", "y"].map(|n| format!("{tag}-{n}"));
        let fam = format!("{tag}-fam");
        reg(d, &[&p, &ps, &q, &x, &y, &fam]).await;
        device(d, &p, &ps).await;
        found_family(d, &fam, FOUNDER_ONLY, &[&ps, &q], &[])
            .await
            .unwrap_or_else(|e| panic!("I1535: founded: {e}"));
        evict(d, &p, &ps).await;
        let widen = |signer: &str, member: &str| {
            let at = ms(Utc::now());
            ts::sign_family_membership_widening(
                signer,
                FamilyMembershipWidening {
                    family_key_id: fam.clone(),
                    member_key_id: member.to_owned(),
                    joined_at: at,
                    effective_at: at,
                    role: None,
                    persist_row_hash: String::new(),
                },
            )
        };
        let e = d
            .put_family_membership_widening_consented(widen(&ps, &x))
            .await
            .expect_err("I1535: the evicted key signs for nobody");
        assert!(insufficient(&e), "I1535: {e}");
        d.put_family_membership_widening_consented(widen(&p, &y))
            .await
            .unwrap_or_else(|e| panic!("I1535: a lost phone wedges nothing: {e}"));
    }

    /// **I1536** — a recanted row is not live.
    pub(crate) async fn i1536_a_recant_leaves_the_other_row(
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
        assert_eq!(c.pool(d).await.respondents, 0, "I1536: at odds");
        ts::put_retraction(d, &p, &p, &uphold.attestation_id, "recants")
            .await
            .unwrap_or_else(|e| panic!("I1536: p recants p's row: {e}"));
        let e = c.pool(d).await;
        assert_eq!(
            e.counted_ballot_ids,
            vec![overrule.attestation_id.clone()],
            "I1536: the recant leaves the other row standing: {e:?}"
        );
    }

    /// **I1537** — the deadline is this node's window.
    pub(crate) async fn i1537_the_deadline_is_a_window(d: &dyn FederationDirectory, tag: &str) {
        let [f, p, q, r, actor] = people(d, tag, ["f", "p", "q", "r", "actor"]).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        // The action is signed two hours ago, past the signed window. This
        // node has only just held its objection.
        let before = Utc::now() - Duration::seconds(1);
        let c = case(d, &room, &actor, &q, tag).await;
        let first_held = d
            .vote_window_first_held(&c.action_id)
            .await
            .expect("read")
            .expect("the door noted the window");
        assert!(first_held >= before, "I1537: {first_held}");
        let at = |now| resolve_reverse_quorum_for(d, Cohort::Community, &room, c.action(), now);
        let early = at(Utc::now()).await.expect("resolve");
        assert_eq!(
            early.escalation[0].steward,
            StewardTierStanding::Awaiting,
            "I1537: the window runs from first-held, not a signed instant: {early:?}"
        );
        let deadline = early.steward_deadline.expect("a declared tier");
        let closed = deadline + Duration::seconds(1);
        let late = at(closed).await.expect("resolve");
        assert_eq!(
            late.escalation[0].steward,
            StewardTierStanding::Silent,
            "I1537: the window closed: {late:?}"
        );

        // It never reopens: a second objection held afterwards moves nothing.
        let again = objection_row(
            &c,
            &r,
            &uuid::Uuid::new_v4().to_string(),
            c.action_at + Duration::minutes(6),
        );
        record_objection_against(d, &again, c.action())
            .await
            .expect("door");
        let after = at(closed).await.expect("resolve");
        assert_eq!(
            after.steward_deadline,
            Some(deadline),
            "I1537: one deadline"
        );
        assert!(
            after
                .escalation
                .iter()
                .all(|e| e.steward == StewardTierStanding::Silent),
            "I1537: a closed window stays closed: {after:?}"
        );

        // A held row beats a window: the steward's ruling, signed after the
        // close, decides. `f` is the founder and the one duty-holder.
        let ruling = c.ballot(&f, true, ms(Utc::now()));
        assert_eq!(
            record_objection_ballot_against(d, &ruling, c.action())
                .await
                .expect("door"),
            ObjectionOutcome::Admitted,
            "I1537: the ruling is held"
        );
        let ruled = at(closed).await.expect("resolve");
        let e = ruled
            .escalation
            .iter()
            .find(|e| e.objection_id == c.objection)
            .expect("escalated");
        assert_eq!(
            (e.steward, e.outcome),
            (StewardTierStanding::Upheld, EscalationOutcome::NotEscalated),
            "I1537: the held ruling beats the closed window: {e:?}"
        );
    }

    /// **I1537 (two nodes)** — one tally, each node's own tier, and they
    /// converge. The rows are the same; `early` first held them a day ago.
    pub(crate) async fn i1537b_the_tally_is_shared_the_tier_is_not(
        early: &dyn FederationDirectory,
        late: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [f, p, q, r, actor] = ["f", "p", "q", "r", "actor"].map(|n| format!("{tag}-{n}"));
        let room = format!("{tag}-room");
        let action_id = crate::federation::wire_index::content_hash_of_bytes(tag.as_bytes());
        let action_at = Utc::now() - Duration::hours(2);
        let mut c = Case {
            room: room.clone(),
            actor: actor.clone(),
            action_id,
            action_at,
            objection: uuid::Uuid::new_v4().to_string(),
        };
        let objection = objection_row(&c, &q, &c.objection, action_at + Duration::minutes(5));
        c.objection = objection.attestation_id.clone();
        let ballot = c.ballot(&p, false, ms(Utc::now()));
        early
            .note_vote_window(&c.action_id, Utc::now() - Duration::days(1))
            .await
            .expect("window");
        for d in [early, late] {
            for k in [&f, &p, &q, &r, &actor] {
                register_user_key(d, k).await;
            }
            let seats = [&f, &p, &q, &r, &actor].map(|k| k.clone());
            seed_community(d, &room, &seats, ESCALATING).await;
            record_objection_against(d, &objection, c.action())
                .await
                .expect("door");
            record_objection_ballot_against(d, &ballot, c.action())
                .await
                .expect("door");
        }
        let fold =
            |d, now| resolve_reverse_quorum_for(d, Cohort::Community, &room, c.action(), now);
        let now = Utc::now();
        let (a, b) = (
            fold(early, now).await.expect("resolve"),
            fold(late, now).await.expect("resolve"),
        );
        let tally = |f: &ReverseQuorumFold| {
            let e = &f.escalation[0];
            (
                e.respondents,
                e.uphold_ballots,
                e.overrule_ballots,
                e.counted_ballot_ids.clone(),
            )
        };
        assert_eq!(tally(&a), tally(&b), "I1537: the tally is one");
        assert_eq!(a.escalation[0].steward, StewardTierStanding::Silent);
        assert_eq!(b.escalation[0].steward, StewardTierStanding::Awaiting);
        let closed = b.steward_deadline.expect("tier") + Duration::seconds(1);
        let (a, b) = (
            fold(early, closed).await.expect("resolve"),
            fold(late, closed).await.expect("resolve"),
        );
        assert_eq!(
            a.escalation[0].steward, b.escalation[0].steward,
            "I1537: converged"
        );
        assert_eq!(a.escalation[0].outcome, b.escalation[0].outcome, "I1537");
    }

    fn dismissal_row(c: &Case, author: &str, cosigners: &[&str], names: &str) -> Attestation {
        signed_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            &c.actor,
            dismissal_envelope(Cohort::Community, &c.room, &c.action_id, names, "no"),
            ms(Utc::now()),
            cosigners,
        )
    }

    /// **I1538** — either arrival order, one count. `first` takes the
    /// objection then the ballot and dismissal; `second` the reverse.
    pub(crate) async fn i1538_a_row_waits_for_what_it_names(
        first: &dyn FederationDirectory,
        second: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [f, p, q, r, s, actor] =
            ["f", "p", "q", "r", "s", "actor"].map(|n| format!("{tag}-{n}"));
        let room = format!("{tag}-room");
        let action_id = crate::federation::wire_index::content_hash_of_bytes(tag.as_bytes());
        let action_at = Utc::now() - Duration::hours(2);
        let mut c = Case {
            room: room.clone(),
            actor: actor.clone(),
            action_id,
            action_at,
            objection: uuid::Uuid::new_v4().to_string(),
        };
        let objection = objection_row(&c, &q, &c.objection, action_at + Duration::minutes(5));
        c.objection = objection.attestation_id.clone();
        for d in [first, second] {
            for k in [&f, &p, &q, &r, &s, &actor] {
                register_user_key(d, k).await;
            }
            let seats = [&f, &p, &q, &r, &s, &actor].map(|k| k.clone());
            seed_community(d, &room, &seats, ESCALATING).await;
        }
        let ballot = c.ballot(&p, false, ms(Utc::now()));
        let other = uuid::Uuid::new_v4().to_string();
        // Short of its floor when it lands; the read re-counts.
        let dismissal = dismissal_row(&c, &r, &[p.as_str(), s.as_str()], &c.objection);
        // Names an objection nobody ever held.
        let stray_ballot = Case {
            room: room.clone(),
            actor: actor.clone(),
            action_id: c.action_id.clone(),
            action_at,
            objection: other.clone(),
        }
        .ballot(&s, true, ms(Utc::now()));
        let stray_dismissal = dismissal_row(&c, &s, &[], &other);

        // first: what is named, then what names it.
        record_objection_against(first, &objection, c.action())
            .await
            .expect("door");
        for (d, tag_order) in [(first, "after"), (second, "before")] {
            assert_eq!(
                record_objection_ballot_against(d, &ballot, c.action())
                    .await
                    .expect("door"),
                ObjectionOutcome::Admitted,
                "I1538: a ballot {tag_order} its objection"
            );
            assert_eq!(
                record_objection_ballot_against(d, &stray_ballot, c.action())
                    .await
                    .expect("door"),
                ObjectionOutcome::Admitted,
                "I1538: a ballot naming nothing held is held"
            );
            for row in [&dismissal, &stray_dismissal] {
                assert_eq!(
                    record_objection_dismissal(d, row)
                        .await
                        .expect("door")
                        .outcome,
                    ObjectionOutcome::Admitted,
                    "I1538: a dismissal {tag_order} its objection"
                );
            }
        }
        record_objection_against(second, &objection, c.action())
            .await
            .expect("door");
        for d in [first, second] {
            let fold = c.fold(d).await;
            assert_eq!(fold.escalation.len(), 1, "I1538: the stray named nothing");
            let e = &fold.escalation[0];
            assert_eq!(
                (e.respondents, e.overrule_ballots),
                (1, 1),
                "I1538: p's ballot counts, the stray does not: {e:?}"
            );
            assert!(
                fold.dismissed_objection_ids.is_empty(),
                "I1538: three of six persons is short of the floor: {fold:?}"
            );
            assert_eq!(fold.distinct_objectors, 1, "I1538: {fold:?}");
        }
    }

    /// **I1539** — recusal waits for the target.
    pub(crate) async fn i1539_recusal_reads_the_held_target(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [f, p, q, actor] = people(d, tag, ["f", "p", "q", "actor"]).await;
        let room = format!("{tag}-room");
        let seats = [&f, &p, &q, &actor].map(|k| k.clone());
        seed_community(d, &room, &seats, ESCALATING).await;
        let c = case(d, &room, &actor, &q, tag).await;

        // The attestation door reads the target by id. This action is no held
        // row, so the actor's own ballot is held for the fold.
        let own = c.ballot(&actor, false, ms(Utc::now()));
        assert_eq!(
            record_objection_ballot(d, &own).await.expect("door"),
            ObjectionOutcome::Admitted,
            "I1539: with no held target the ballot waits"
        );
        assert_eq!(c.pool(d).await.respondents, 0, "I1539: the fold recuses");

        // Given the target, the door reads the exact key and refuses.
        let again = c.ballot(&actor, false, ms(Utc::now()));
        assert_eq!(
            record_objection_ballot_against(d, &again, c.action())
                .await
                .expect("door")
                .refusal(),
            Some(ObjectionRefusalReason::ActorRecused),
            "I1539: the exact key, from the row and its target"
        );
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

        // The member a removal names is a person: their other device is never
        // one of its voices, and the removal of one seat needs nobody of theirs.
        let open2 = format!("{tag}-open2");
        reg(d, &[&open2]).await;
        found_public_room(d, &open2, OPEN_SELF_ADMIT, &[&p, &pd, &f1, &f2], &[])
            .await
            .unwrap();
        let e = remove(d, &open2, &pd, &[&p, &f1])
            .await
            .expect_err("I1530: p is the person named, one voice is left");
        assert!(insufficient(&e), "I1530: {e}");
        remove(d, &open2, &pd, &[&f1, &f2])
            .await
            .unwrap_or_else(|e| panic!("I1530: two other persons: {e}"));
        assert!(!seated(d, &open2, &pd).await, "I1530: pd is gone");

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

        // The quorum-gated supersede counts persons too.
        let fam2 = format!("{tag}-fam2");
        reg(d, &[&fam2]).await;
        found_family(d, &fam2, MAJORITY, &[&p, &pd, &q], &[])
            .await
            .unwrap();
        let members = [p.clone(), pd.clone(), q.clone(), x.clone()];
        let change = d
            .build_membership_change_envelope(
                Cohort::Family,
                &fam2,
                &members,
                false,
                Some(MAJORITY),
            )
            .await
            .unwrap_or_else(|e| panic!("I1530: build change: {e}"));
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let sign = |keys: &[&String]| {
            keys.iter()
                .map(|k| ts::threshold_sign(k, &bytes))
                .collect::<Vec<_>>()
        };
        let e = d
            .verify_membership_quorum(Cohort::Family, &fam2, &change, &sign(&[&p, &pd]))
            .await
            .expect_err("I1530: one person of two");
        assert!(e.to_string().contains("not authorized"), "I1530: {e}");
        d.verify_membership_quorum(Cohort::Family, &fam2, &change, &sign(&[&p, &q]))
            .await
            .unwrap_or_else(|e| panic!("I1530: two persons of two: {e}"));
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

    /// Two empty nodes of one backend.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1534b_sqlite() {
        use crate::store::Backend as _;
        let a = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        a.run_migrations().await.unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1534b_either_arrival_order(&a, &b, &tag("s")).await;
        let c = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        c.run_migrations().await.unwrap();
        d.run_migrations().await.unwrap();
        bodies::i1538_a_row_waits_for_what_it_names(&c, &d, &tag("s")).await;
        bodies::i1537b_the_tally_is_shared_the_tier_is_not(&a, &b, &tag("s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1534b_postgres() {
        use crate::store::Backend as _;
        let dsn = || crate::test_pg::empty_dsn().expect("no CIRIS_PERSIST_TEST_PG base DSN");
        let a = crate::store::postgres::PostgresBackend::connect(&dsn())
            .await
            .unwrap();
        let b = crate::store::postgres::PostgresBackend::connect(&dsn())
            .await
            .unwrap();
        a.run_migrations().await.unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1534b_either_arrival_order(&a, &b, &tag("p")).await;
        let c = crate::store::postgres::PostgresBackend::connect(&dsn())
            .await
            .unwrap();
        let d = crate::store::postgres::PostgresBackend::connect(&dsn())
            .await
            .unwrap();
        c.run_migrations().await.unwrap();
        d.run_migrations().await.unwrap();
        bodies::i1538_a_row_waits_for_what_it_names(&c, &d, &tag("p")).await;
        bodies::i1537b_the_tally_is_shared_the_tier_is_not(&a, &b, &tag("p")).await;
    }

    on_every_backend!(i1537, bodies::i1537_the_deadline_is_a_window);
    on_every_backend!(i1539, bodies::i1539_recusal_reads_the_held_target);
    on_every_backend!(i1533, bodies::i1533_the_count_reads_no_clock);
    on_every_backend!(i1534, bodies::i1534_a_ballot_before_its_occurrence);
    on_every_backend!(i1535, bodies::i1535_an_evicted_seat_stays_the_persons);
    on_every_backend!(i1536, bodies::i1536_a_recant_leaves_the_other_row);
    on_every_backend!(i1525, bodies::i1525_two_devices_are_one_voice);
    on_every_backend!(i1526, bodies::i1526_disagreement_is_no_voice);
    on_every_backend!(i1527, bodies::i1527_a_sibling_withdrawal_leaves_one);
    on_every_backend!(i1528, bodies::i1528_another_self_does_not_count);
    on_every_backend!(i1529, bodies::i1529_an_evicted_devices_vote_is_void);
    on_every_backend!(i1530, bodies::i1530_a_membership_change_counts_persons);
    on_every_backend!(i1530b, bodies::i1530b_the_floor_counts_persons);
    on_every_backend!(i1531, bodies::i1531_no_order_changes_the_count);
}
