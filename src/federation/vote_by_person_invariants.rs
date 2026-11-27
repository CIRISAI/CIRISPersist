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
//! - **I1540** — an objection arriving through
//!   `apply_replicated_attestation` opens the window as a local one does.
//! - **I1541** — the window's receipt is written in the row's transaction, so
//!   a failed write leaves neither: the door and the replicated path both
//!   surface it, and a re-offer lands the row and the receipt together.
//! - **I1542** — V213 backfills a populated V212 store: each action's window
//!   is its earliest held objection, a cohort of `self` and a ballot open
//!   none, and the store boots and folds.
//! - **I1531** — no row order, in arrival or in `asserted_at`, changes the
//!   count.

//!
//! v62.0.0 (wave 3, slice E6) — **deleted:** I1525–I1529, I1531, I1533,
//! I1534 (+b), I1536, I1537 (+b), I1538, I1539, I1540, I1541 and their
//! runners/helpers (`Case`, `case`, `objection_row`, `quiet_case`,
//! `dismissal_row`, `people`, the vote-window rename fixtures). They are the
//! `reverse_quorum` ballot/objection/dismissal fold, and `reverse_quorum` is
//! refused in v62 (RULINGS, "Kernel departures adopted"). **Flipped** (T1
//! v3): I1530, I1530b, I1535 run on edition-2 planes (see `bodies`); the
//! I1530b quorum-gated supersede leg is a T1 version (v+1, one voice per
//! signer) instead of the JCS change envelope + `ThresholdSignature`s.
//! I1530c is a pure fold test.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    //! v62.0.0 (wave 3, slice E6; T1 v3) — edition-2 planes: keys by kid, a
    //! device is an O1 occurrence bind (two voices), a room/family is T1's
    //! roster voices, a widening is its member's proposal + acceptance rows
    //! (`put_signed`) and then its signers' voices, a removal its signers'
    //! voices, all naming the held head. A change short of its protocol is
    //! `Pending` (its voices kept, the roster unchanged): the earlier form's
    //! `roster_consensus_insufficient`.
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, found_public_room, proposal, put, reg, reply,
    };
    use crate::federation::occurrence_consent_invariants::bodies::put_bind;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY};
    use crate::federation::types::consensus_protocol::{
        FOUNDER_ONLY, MAJORITY, OPEN_SELF_ADMIT, UNANIMOUS,
    };
    use crate::federation::types::{
        CommunityMember, CommunityMembershipRevocation, CommunityMembershipWidening,
        FamilyMembershipWidening,
    };
    use crate::federation::{
        Error, FederationDirectory, IdentityOccurrenceRevocation,
        ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED, ROSTER_CONSENSUS_INSUFFICIENT,
    };
    use chrono::{DateTime, Duration, DurationRound, Utc};

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        t.duration_trunc(Duration::milliseconds(1)).unwrap()
    }

    fn now_ms() -> u64 {
        u64::try_from(Utc::now().timestamp_millis()).expect("after the epoch")
    }

    /// `device` becomes a live second device of the self `f`: O1's two-voice
    /// `identity:occurrence` bind (a roster of one, so `f`'s voice lands it).
    async fn device(d: &dyn FederationDirectory, f: &str, device: &str) {
        put_bind(d, f, device, "phone", now_ms() - 1_000).await;
    }

    /// `device` is evicted from `f`, effective just now. The instant sits
    /// strictly after every assertion of the pair (the #421 rule).
    async fn evict(d: &dyn FederationDirectory, f: &str, device: &str) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let at = ms(Utc::now());
        d.put_identity_occurrence_revocation_edition2(
            IdentityOccurrenceRevocation {
                identity_key_id: e2::kid(f),
                occurrence_key_id: e2::kid(device),
                revoked_at: at,
                effective_at: at,
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
            crate::federation::DoorToken::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("evict {device}: {e}"));
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    /// Did a roster change fall short of its protocol (its voices kept, the
    /// roster unchanged), or meet the earlier count rule's refusal?
    fn short(r: &Result<StatementOutcome, Error>) -> bool {
        match r {
            Ok(StatementOutcome::Pending { .. }) => true,
            Err(Error::RosterAuthorityUnauthorized { rule, .. }) => {
                *rule == ROSTER_CONSENSUS_INSUFFICIENT
                    || *rule == ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED
            }
            _ => false,
        }
    }

    /// Did a roster change land?
    fn landed(r: &Result<StatementOutcome, Error>) -> bool {
        matches!(r, Ok(StatementOutcome::Row { .. }))
    }

    async fn head(
        d: &dyn FederationDirectory,
        group: &str,
    ) -> crate::federation::edition2::names::RowId {
        e2::held_head(d, &e2::kid(group))
            .await
            .unwrap_or_else(|| panic!("{group}: a held head"))
            .0
    }

    /// `member`'s proposal (by `signers[0]`) and acceptance, held as
    /// edition-2 rows: the growth gate (T1 I2999 / I3004).
    async fn consent(
        d: &dyn FederationDirectory,
        scope: &str,
        group: &str,
        member: &str,
        by: &str,
    ) {
        let at = Utc::now() - Duration::seconds(30);
        let invite = proposal(by, scope, group, member, None, at, Some(Duration::days(7)));
        put(d, &invite).await.expect("the proposal is held");
        put(
            d,
            &reply(member, member, &invite, true, at + Duration::seconds(1)),
        )
        .await
        .expect("the acceptance is held");
    }

    /// A widening of `member` into the community `room`, voiced by `signers`.
    async fn widen(
        d: &dyn FederationDirectory,
        room: &str,
        member: &str,
        signers: &[&str],
    ) -> Result<StatementOutcome, Error> {
        consent(d, COMMUNITY, room, member, signers[0]).await;
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
        let h = head(d, room).await;
        e2::put_voices(d, &e2::community_widening_voices(&w, Some(&h))).await
    }

    /// A removal of `member` from the community `room`, voiced by `signers`.
    async fn remove(
        d: &dyn FederationDirectory,
        room: &str,
        member: &str,
        signers: &[&str],
    ) -> Result<StatementOutcome, Error> {
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
                leaf: crate::federation::types::RevocationLeaf::Removal,
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut r, c);
        }
        let h = head(d, room).await;
        e2::put_voices(d, &e2::community_revocation_voices(&r, Some(&h))).await
    }

    /// A widening of `member` into the family `fam`, voiced by `signers`.
    async fn widen_family(
        d: &dyn FederationDirectory,
        fam: &str,
        member: &str,
        signers: &[&str],
    ) -> Result<StatementOutcome, Error> {
        consent(d, FAMILY, fam, member, signers[0]).await;
        let at = ms(Utc::now());
        let mut w = ts::sign_family_membership_widening(
            signers[0],
            FamilyMembershipWidening {
                family_key_id: fam.to_owned(),
                member_key_id: member.to_owned(),
                joined_at: at,
                effective_at: at,
                role: None,
                persist_row_hash: String::new(),
            },
        );
        for c in &signers[1..] {
            ts::cosign_family_membership_widening(&mut w, c);
        }
        let h = head(d, fam).await;
        e2::put_voices(d, &e2::family_widening_voices(&w, Some(&h))).await
    }

    async fn seated(d: &dyn FederationDirectory, room: &str, k: &str) -> bool {
        let roster: Vec<CommunityMember> =
            d.active_community_members(&e2::kid(room)).await.unwrap();
        roster.iter().any(|m| m.key_id == e2::kid(k))
    }

    async fn family_seated(d: &dyn FederationDirectory, fam: &str, k: &str) -> bool {
        d.active_family_members(&e2::kid(fam))
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == e2::kid(k))
    }

    /// **I1535** — an evicted founder seat in a `founder_only` family: the
    /// evicted key signs for nobody; the person's other key acts.
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
        let r = widen_family(d, &fam, &x, &[&ps]).await;
        assert!(short(&r), "I1535: the evicted key signs for nobody: {r:?}");
        assert!(!family_seated(d, &fam, &x).await);
        let r = widen_family(d, &fam, &y, &[&p]).await;
        assert!(landed(&r), "I1535: a lost phone wedges nothing: {r:?}");
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
        let w = widen(d, &room, &x, &[&p, &pd]).await;
        assert!(
            short(&w),
            "I1530: one person's two seats are one voice of two: {w:?}"
        );
        assert!(!seated(d, &room, &x).await, "I1530: x stays out");
        let w = widen(d, &room, &x, &[&p, &q]).await;
        assert!(landed(&w), "I1530: two persons of two: {w:?}");
        assert!(seated(d, &room, &x).await, "I1530: x is in");

        // ── A device that holds no seat signs for its seated person; a key
        //    of another self does not, and an evicted device does not.
        found_community(d, &unseated, MAJORITY, &[&p, &q, &r], &[])
            .await
            .unwrap();
        let w = widen(d, &unseated, &y, &[&p, &pd]).await;
        assert!(
            short(&w),
            "I1530: one person's two devices are one voice of three: {w:?}"
        );
        let w = widen(d, &unseated, &y, &[&q, &od]).await;
        assert!(
            short(&w),
            "I1530: a key of another self does not count: {w:?}"
        );
        let w = widen(d, &unseated, &y, &[&q, &pd]).await;
        assert!(landed(&w), "I1530: pd signs as p: {w:?}");
        assert!(seated(d, &unseated, &y).await, "I1530: y is in");
        evict(d, &p, &pd).await;
        let w = widen(d, &unseated, &z, &[&q, &pd]).await;
        assert!(
            short(&w),
            "I1530: an evicted device signs for nobody: {w:?}"
        );
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
        let w = remove(d, &unan, &r, &[&p, &pd]).await;
        assert!(short(&w), "I1530: p is one of the two other persons: {w:?}");
        assert!(seated(d, &unan, &r).await, "I1530: r stays");
        let w = remove(d, &unan, &r, &[&pd, &q]).await;
        assert!(landed(&w), "I1530: both other persons: {w:?}");
        assert!(!seated(d, &unan, &r).await, "I1530: r is gone");

        // The removal floor (`CLM-removal-floor-every-protocol`): one person's
        // two devices are one voice under open admission.
        found_public_room(d, &open, OPEN_SELF_ADMIT, &[&p, &f1, &f2, &j], &[])
            .await
            .unwrap();
        let w = remove(d, &open, &j, &[&p, &pd]).await;
        assert!(short(&w), "I1530: two devices never remove: {w:?}");
        assert!(seated(d, &open, &j).await, "I1530: j stays");
        let w = remove(d, &open, &j, &[&pd, &f1]).await;
        assert!(landed(&w), "I1530: two persons remove: {w:?}");
        assert!(!seated(d, &open, &j).await, "I1530: j is gone");

        // The member a removal names is a person: their other device is never
        // one of its voices, and the removal of one seat needs nobody of theirs.
        let open2 = format!("{tag}-open2");
        reg(d, &[&open2]).await;
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let open2 = found_public_room(d, &open2, OPEN_SELF_ADMIT, &[&p, &pd, &f1, &f2], &[])
            .await
            .unwrap();
        let w = remove(d, &open2, &pd, &[&p, &f1]).await;
        assert!(
            short(&w),
            "I1530: p is the person named, one voice is left: {w:?}"
        );
        let w = remove(d, &open2, &pd, &[&f1, &f2]).await;
        assert!(landed(&w), "I1530: two other persons: {w:?}");
        assert!(!seated(d, &open2, &pd).await, "I1530: pd is gone");

        // A family runs the same fold.
        found_family(d, &fam, MAJORITY, &[&p, &pd, &q], &[])
            .await
            .unwrap();
        let w = widen_family(d, &fam, &x, &[&p, &pd]).await;
        assert!(
            short(&w),
            "I1530: a family's two seats of one self are one voice: {w:?}"
        );
        let w = widen_family(d, &fam, &x, &[&pd, &q]).await;
        assert!(landed(&w), "I1530: two persons of a family: {w:?}");

        // The quorum of a later VERSION counts persons too (T1 §6: a version
        // is v+1 naming the held head, one voice per signer).
        let fam2 = format!("{tag}-fam2");
        reg(d, &[&fam2]).await;
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let fam2 = found_family(d, &fam2, MAJORITY, &[&p, &pd, &q], &[])
            .await
            .unwrap();
        let (h, version) = e2::held_head(d, &e2::kid(&fam2))
            .await
            .expect("I1530: fam2's head");
        let held = d
            .lookup_family(&e2::kid(&fam2))
            .await
            .unwrap()
            .expect("I1530: fam2 is held");
        let mut next = held.clone();
        next.family_name = format!("{} (renamed)", held.family_name);
        let record =
            crate::federation::edition2::group::GroupRecord::Family(e2::family_with_kids(&next));
        // v62.0.0 (E6-fix8) — ONE instant for every voice of the version: the
        // instant is in the signed payload, so voices stamped at two clocks are
        // two different versions, and the second put counted q alone.
        let at = now_ms();
        let voices = |signers: &[&str]| {
            let keys: Vec<_> = signers.iter().map(|s| e2::signing_key(s)).collect();
            let refs: Vec<&_> = keys.iter().collect();
            e2::roster_voices(&record, version + 1, Some(&h), at, &refs)
        };
        let w = e2::put_voices(d, &voices(&[&p, &pd])).await;
        assert!(short(&w), "I1530: one person of two: {w:?}");
        let w = e2::put_voices(d, &voices(&[&q])).await;
        assert!(landed(&w), "I1530: two persons of two: {w:?}");
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
                        eprintln!(
                            "{} postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED",
                            stringify!($name)
                        );
                        return;
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
            is_resignation: false,
        };
        let state = authorized_roster_state_at(&record, rules, &[], t);
        let hw = crate::federation::authorized_roster_high_water_at(&record, rules, &[], t);
        roster_event_standing(rules, &state, hw, &event)
            .expect_err("I1530: the door counts one person of two");
        let roster = authorized_roster_at(&record, rules, &[event], t);
        assert!(
            roster.iter().any(|m| m.key_id == "x"),
            "I1530: the row already held stands"
        );
    }

    on_every_backend!(i1535, bodies::i1535_an_evicted_seat_stays_the_persons);
    on_every_backend!(i1530, bodies::i1530_a_membership_change_counts_persons);
    on_every_backend!(i1530b, bodies::i1530b_the_floor_counts_persons);
}
