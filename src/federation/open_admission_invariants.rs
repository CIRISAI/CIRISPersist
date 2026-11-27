//! v61 S2 (CIRISPersist#1123; CC 4.5.13, 4.4.3.2, 4.4.3.4.2, 3.2) —
//! **one voice never decides who is in a room.** sqlite and postgres.
//!
//! - **I1500** — `founder_only` is refused for a community above the family
//!   (`federation_community_consensus_protocol_violation`, rule
//!   `founder_only_above_family`) at the local record door and the supersede
//!   door, and a replicated version may not move a stored room onto it. A
//!   family and an affiliation keep it; a legacy room a peer delivers is kept
//!   as data and its next version must leave `founder_only`.
//! - **I1518** (v61 S2) — such a stored room admits exactly ONE event, on the
//!   local and the replicated door: the escape, a supersede whose only change
//!   is `consensus_protocol` leaving `founder_only`, signed by a founder.
//!   A proposal, a widening, a removal (a resignation excepted), a version
//!   that keeps `founder_only`, an escape that changes members and an escape
//!   no founder signed are refused `founder_only_above_family`; after the
//!   escape a widening under `majority` is admitted.
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
//! - **I1504** (CIRISPersist#1063) — a public room's live standing proposal
//!   is served on request to a non-member: the member's node reads it
//!   ([`public_room::live_standing_proposal`](crate::federation::public_room::live_standing_proposal)),
//!   the requester's node is in its audience and admits it on the replicated
//!   door, the requester accepts on their own node, and the member's node
//!   admits the acceptance and the requester's own widening. A withdrawn
//!   proposal is no longer live; a private room has none.
//! - **I1624** (v61.1.0, CIRISPersist#1188) — the live standing proposal is
//!   re-judged at the read: a public room not under `open:self_admit` serves
//!   none (even holding a founder's, stored before the room was); an
//!   invitation is not one; a resigned founder's is not live; a founder's
//!   occurrence key signs a live one; a stranger's `withdraws`, held before
//!   the proposal, retires nothing.
//! - **I1505** (CIRISPersist#1100 item 2(i)) — under `reverse_quorum` a
//!   WIDENING is reversible by the same objection fold as a removal: `m`
//!   distinct in-window objectors take the added member back off; one
//!   objector does not, even where `m` is 1 (the two-path count minimum, one
//!   voice never decides who is in a room).
//! - **I1515** (v61 S2) — the removal window under `open:self_admit`. A
//!   roster cosignature carries no signed instant of its own (every scrub
//!   covers the same `signing_envelope`), so CC's per-cosignature bound falls
//!   back to the local door's receipt: a two-voice removal whose `removed_at`
//!   lies more than 259 200 s before receipt is refused
//!   (`roster_removal_outside_window`); one inside the window is admitted; a
//!   resignation is not a counted removal and is not bounded; the replicated
//!   door applies a stale removal another node admitted, as data.
//!
//! v62.0.0 (JSON cut, E13) — **edition 2.** Every key is an E0 identity-ref;
//! every room and family is founded by its founders' `group:roster` voices
//! (E5's `found_*`); a version is the roster's v+1 naming the held head
//! (T1.api §6); a widening or removal is its `membership:{stage}` voices
//! naming the head; a membership event short of the group's protocol is kept
//! `Pending` (the voice held, nothing admitted) where the earlier door
//! refused `roster_consensus_insufficient`, and the witnesses accept either
//! (the member stays out). Two nodes exchange edition-2 statements through
//! the FILTERED serve path (`edition2::serve::statements_served_to`, the
//! receiver as requester) into the receiver's replicated statement door
//! (`apply_replicated_statement`). A founder's occurrence key is bound by
//! O1's `identity:occurrence` (`e2::put_bind`).
//!
//! **Deleted (no edition-2 meaning):** the LEGACY `founder_only` room above
//! the family — a v61 record a peer delivered and this node kept as data — and
//! everything only it admits: I1500's legacy arm, **I1518** (its one escape)
//! and **I1518b** (the escape replicated). No edition-2 door stores such a
//! room (a `group:roster` version is judged at the record door, which refuses
//! `founder_only` above the family), and v62 carries no v61 store. I1500's
//! "a stored room never moves ONTO `founder_only`" stays, as a v+1 version.
//! I1505 (`reverse_quorum` widenings) was deleted earlier (E5).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use ciris_crypto::composite::CompositeSigningKey;

    use crate::federation::admission::FOUNDER_ONLY_ABOVE_FAMILY;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::{GroupRecord, MembershipRecord};
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::membership_acceptance::RULE_ACCEPTANCE_UNRESOLVED;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_affiliation, found_community, found_family, found_public_room, found_public_room_at,
        id_of, proposal, put, reg, reply,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::COMMUNITY;
    use crate::federation::types::consensus_protocol::{FOUNDER_ONLY, OPEN_SELF_ADMIT};
    use crate::federation::types::{
        Community, CommunityMembershipRevocation, CommunityMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory, ROSTER_CONSENSUS_INSUFFICIENT};
    use chrono::{DateTime, Duration, Utc};

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    /// The rule a refusal names, whichever typed error carries it.
    pub(crate) fn rule(e: &Error) -> String {
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

    fn keys_of(signers: &[&str]) -> Vec<CompositeSigningKey> {
        signers.iter().map(|s| e2::signing_key(s)).collect()
    }

    /// v62.0.0 (E13) — **NOT admitted**: an edition-2 membership event the
    /// group's protocol does not admit is either kept `Pending` (the voices
    /// held, short of the protocol) or refused by one of `rules`. Anything
    /// else (it landed, or another refusal) fails `what`.
    pub(crate) fn not_admitted(out: Result<StatementOutcome, Error>, rules: &[&str], what: &str) {
        match out {
            Ok(StatementOutcome::Pending { .. }) => {}
            Err(e) if rules.contains(&rule(&e).as_str()) => {}
            other => panic!("{what}: expected Pending or one of {rules:?}, got {other:?}"),
        }
    }

    /// The typed row landed.
    pub(crate) fn landed(out: Result<StatementOutcome, Error>, what: &str) {
        match out {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{what}: expected the row to land, got {other:?}"),
        }
    }

    /// v62.0.0 (E13) — the room's next version (T1.api §6): the held record
    /// with `edit` applied, at the held head's version + 1 naming it, one
    /// `group:roster` voice per signer.
    async fn next_version(
        d: &dyn FederationDirectory,
        cid: &str,
        edit: impl FnOnce(&mut Community),
        signers: &[&str],
    ) -> Result<StatementOutcome, Error> {
        let mut next = d.lookup_community(cid).await.unwrap().expect("held");
        edit(&mut next);
        next.prev_head_digest = String::new();
        next.persist_row_hash = String::new();
        let (head, v) = e2::held_head(d, cid).await.expect("a held roster head");
        let k = keys_of(signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        e2::put_voices(
            d,
            &e2::roster_voices(
                &GroupRecord::Community(next),
                v + 1,
                Some(&head),
                e2::ms(Utc::now()),
                &refs,
            ),
        )
        .await
    }

    /// v62.0.0 (E13) — `member` widened into `cid` by `signers`' voices
    /// (`membership:widening`, naming the held head), the outcome as the
    /// door gave it. The member's consent is the caller's.
    pub(crate) async fn widen(
        d: &dyn FederationDirectory,
        cid: &str,
        signers: &[&str],
        member: &str,
        role: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<StatementOutcome, Error> {
        let (head, _) = e2::held_head(d, cid).await.expect("a held roster head");
        let w = MembershipRecord::CommunityWidening(CommunityMembershipWidening {
            community_key_id: cid.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: ms(at),
            effective_at: ms(at),
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        });
        let k = keys_of(signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        e2::put_voices(d, &e2::membership_voices(&w, Some(&head), &refs)).await
    }

    /// v62.0.0 (E13) — the `membership:removal` voices of `signers` removing
    /// `member` from `cid` at `at`, naming the held head.
    async fn removal_voices(
        d: &dyn FederationDirectory,
        cid: &str,
        signers: &[&str],
        member: &str,
        at: DateTime<Utc>,
    ) -> Vec<Vec<u8>> {
        let (head, _) = e2::held_head(d, cid).await.expect("a held roster head");
        let r = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
            community_key_id: cid.to_owned(),
            removed_identity_key_id: member.to_owned(),
            removed_at: ms(at),
            effective_at: ms(at),
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        });
        let k = keys_of(signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        e2::membership_voices(&r, Some(&head), &refs)
    }

    pub(crate) async fn remove(
        d: &dyn FederationDirectory,
        cid: &str,
        signers: &[&str],
        member: &str,
        at: DateTime<Utc>,
    ) -> Result<StatementOutcome, Error> {
        let voices = removal_voices(d, cid, signers, member, at).await;
        e2::put_voices(d, &voices).await
    }

    /// **I1500** — `founder_only` above the family.
    pub(crate) async fn i1500_founder_only_is_refused_above_the_family(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (founder, room, aff, fam, kept) = (
            format!("i1500-f-{s}"),
            format!("i1500-room-{s}"),
            format!("i1500-aff-{s}"),
            format!("i1500-fam-{s}"),
            format!("i1500-kept-{s}"),
        );
        reg(d, &[&founder, &room, &aff, &fam, &kept]).await;
        let (founder, room, aff, fam, kept) = (
            id_of(&founder),
            id_of(&room),
            id_of(&aff),
            id_of(&fam),
            id_of(&kept),
        );
        // The record door refuses a NEW founder_only room, by name, storing
        // nothing.
        let e = found_community(d, &room, FOUNDER_ONLY, &[&founder], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let _aff = found_affiliation(d, &aff, FOUNDER_ONLY, &[&founder], &[])
            .await
            .expect("I1500: an affiliation keeps founder_only (CC 4.4.3.2.8)");
        // A stored room never moves ONTO founder_only: its v+1 is refused.
        // GID-fix6 — rebound to the RETURNED (derived) id.
        let kept = found_community(d, &kept, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let held = d.lookup_community(&kept).await.unwrap().expect("held");
        let e = next_version(
            d,
            &kept,
            |c| c.consensus_protocol = FOUNDER_ONLY.into(),
            &[&founder],
        )
        .await
        .expect_err("I1500: a version onto founder_only");
        assert_eq!(rule(&e), FOUNDER_ONLY_ABOVE_FAMILY, "I1500: {e}");
        assert_eq!(
            d.lookup_community(&kept).await.unwrap().unwrap(),
            held,
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
        let (founder, private, fam, public) = (
            id_of(&founder),
            id_of(&private),
            id_of(&fam),
            id_of(&public),
        );
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let public = found_public_room(d, &public, OPEN_SELF_ADMIT, &[&founder], &[])
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

    /// A standing proposal (no invitee) by `signer` into `cid`, at `at`.
    pub(crate) fn standing(
        signer: &str,
        cid: &str,
        at: DateTime<Utc>,
    ) -> crate::federation::Attestation {
        let mut p = proposal(
            signer,
            COMMUNITY,
            cid,
            "",
            None,
            at,
            Some(Duration::days(7)),
        );
        p.subject_key_ids.clear();
        ts::seal_row_in_place(signer, &mut p);
        p
    }

    /// v62.0.0 (E13 fix1; CC 2.7 rc21 X14, CC 4.4.3.17) — **a joiner whose
    /// signature counts**: a public room joiner's acceptance of a STANDING
    /// proposal concludes only from a key with a live federation-scope owner
    /// binding (`public_room::joiner_owner_bound`). So the joiner is a NODE
    /// key `joiner` owned by the person `owner`: the owner's binding, dated
    /// now-relative, and the node's own voice over it (the binding lands at
    /// its second voice). Returns the joiner's identity-ref.
    pub(crate) async fn bound_joiner(
        d: &dyn FederationDirectory,
        joiner: &str,
        owner: &str,
    ) -> String {
        use crate::federation::types::identity_type::{NODE, USER};
        let owner = e2::put_key(d, owner, &[USER]).await;
        let joiner = e2::put_key(d, joiner, &[NODE]).await;
        let mut row =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner, &joiner);
        row.asserted_at = ms(Utc::now() - Duration::minutes(5));
        row.scrub_timestamp = row.asserted_at;
        ts::seal_row_in_place(&owner, &mut row);
        e2::put_signed(d, &row)
            .await
            .expect("the owner's voice over the joiner's binding");
        let st = e2::carried_statement(&row).expect("the binding carries its statement");
        landed(
            e2::put_statement(d, &e2::voice_of(&st, &joiner)).await,
            "the joiner's voice over its owner binding",
        );
        joiner
    }

    /// The founder's standing proposal into `cid`, and `joiner`'s acceptance.
    async fn accept_standing(
        d: &dyn FederationDirectory,
        founder: &str,
        cid: &str,
        joiner: &str,
        at: DateTime<Utc>,
    ) -> crate::federation::Attestation {
        let p = standing(founder, cid, at);
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
        reg(d, &[&founder, &late, &cid, &closed]).await;
        let joiner = bound_joiner(d, &joiner, &format!("i1502-o-{s}")).await;
        let (founder, late, cid, closed) =
            (id_of(&founder), id_of(&late), id_of(&cid), id_of(&closed));
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_public_room(d, &cid, OPEN_SELF_ADMIT, &[&founder], &[])
            .await
            .unwrap();
        let at = Utc::now() - Duration::hours(1);
        accept_standing(d, &founder, &cid, &joiner, at).await;
        // The founder signing FOR the joiner is not the joiner's own admission.
        not_admitted(
            widen(
                d,
                &cid,
                &[&founder],
                &joiner,
                None,
                at + Duration::seconds(2),
            )
            .await,
            &[ROSTER_CONSENSUS_INSUFFICIENT],
            "I1502: a founder's widening of the joiner",
        );
        assert!(!active(d, &cid, &joiner).await);
        // The joiner's own signature is the group's side.
        landed(
            widen(
                d,
                &cid,
                &[&joiner],
                &joiner,
                None,
                at + Duration::seconds(3),
            )
            .await,
            "I1502: the joiner admits themselves",
        );
        assert!(active(d, &cid, &joiner).await, "I1502: the joiner is in");
        // Without their acceptance a self-signed widening is still no consent.
        // v62.0.0 (E13 fix2; CC 2.7.3) — the missing acceptance is another
        // row: the widening is HELD (or, outside a fold, refused by the rule).
        not_admitted(
            widen(d, &cid, &[&late], &late, None, at + Duration::seconds(4)).await,
            &[RULE_ACCEPTANCE_UNRESOLVED],
            "I1502: no acceptance",
        );
        assert!(!active(d, &cid, &late).await, "I1502: late is not in");
        // A seated member's self-promotion is a role change: two voices.
        not_admitted(
            widen(
                d,
                &cid,
                &[&joiner],
                &joiner,
                Some("founder"),
                at + Duration::seconds(5),
            )
            .await,
            &[ROSTER_CONSENSUS_INSUFFICIENT],
            "I1502: a member promotes themselves",
        );
        assert!(
            d.active_community_members(&cid)
                .await
                .unwrap()
                .iter()
                .any(|m| m.key_id == joiner && m.role.as_deref() != Some("founder")),
            "I1502: the joiner is still a plain member"
        );
        // Joining confers no authority: a member's standing proposal is refused.
        put(d, &standing(&joiner, &cid, at))
            .await
            .expect_err("I1502: a non-founder's standing proposal");
        // Every other protocol refuses a self-signed admission.
        // GID-fix6 — rebound to the RETURNED (derived) id.
        let closed = found_community(d, &closed, "quorum:1/1", &[&founder], &[])
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
        not_admitted(
            widen(d, &closed, &[&late], &late, None, at + Duration::seconds(2)).await,
            &[
                ROSTER_CONSENSUS_INSUFFICIENT,
                crate::federation::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
            ],
            "I1502: a self-signed admission under quorum:1/1",
        );
        assert!(!active(d, &closed, &late).await);
        landed(
            widen(
                d,
                &closed,
                &[&founder],
                &late,
                None,
                at + Duration::seconds(3),
            )
            .await,
            "I1502: the founder's widening admits under quorum:1/1",
        );
        assert!(active(d, &closed, &late).await);
    }

    /// v62.0.0 (K2-fix18) — `seed` self-declares minor (the subject-signed
    /// self rung); returns the held row, for its withdrawal.
    async fn declare_minor(
        d: &dyn FederationDirectory,
        seed: &str,
    ) -> crate::federation::Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut a = ts::bare_attestation(&id, seed, seed, &serde_json::json!({ "id": id }));
        a.attestation_type = "age_self_declared:band:minor:v1".to_owned();
        ts::seal_row_in_place(seed, &mut a);
        e2::put_signed(d, &a)
            .await
            .expect("the self-declared minor row");
        a
    }

    /// v62.0.0 (K2-fix18) — `seed` withdraws its own `row`.
    async fn withdraw_own(
        d: &dyn FederationDirectory,
        row: &crate::federation::Attestation,
        seed: &str,
    ) {
        let w = e2::composer_of(
            crate::federation::types::attestation_type::WITHDRAWS,
            row,
            seed,
        );
        landed(
            e2::put_signed(d, &w).await,
            "the withdrawal of the minor row",
        );
    }

    /// v62.0.0 (K2-fix18; CC 3.4.13 Q5, CC 5.4.6; class 2) — **I2051–I2053:
    /// a public room never lists a minor; the derived plane is untouched.**
    /// The room is `public` under `quorum:1/1` (an invitation the founder
    /// widens), so the joiner is a PERSON key; the open-join path needs a
    /// federation owner binding (`joiner_owner_unbound`), which K2-fix17
    /// already holds for a minor owner.
    ///
    /// - **I2051** — the growth lands and the person is listed; THEN the
    ///   person self-declares minor: the growth re-folds to held
    ///   (`minor_public_roster_entry`), the person is not listed; they
    ///   withdraw the row: listed again, with no new growth.
    /// - **I2052** — the other order: the minor row first, then the
    ///   invitation, acceptance and growth: not admitted (held); withdrawn:
    ///   listed.
    /// - **I2053** — the derived plane: the same minor joins a PRIVATE room
    ///   (`quorum:1/1`, not `public`): listed there, while the minor row
    ///   stands.
    pub(crate) async fn i2051_i2053_a_public_room_never_lists_a_minor(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (founder, p1, p2, pubr, privr) = (
            format!("i2051-f-{s}"),
            format!("i2051-p1-{s}"),
            format!("i2051-p2-{s}"),
            format!("i2051-pub-{s}"),
            format!("i2051-priv-{s}"),
        );
        reg(d, &[&founder, &p1, &p2, &pubr, &privr]).await;
        let (f, k1, k2, cid, priv_cid) = (
            id_of(&founder),
            id_of(&p1),
            id_of(&p2),
            id_of(&pubr),
            id_of(&privr),
        );
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_public_room(d, &cid, "quorum:1/1", &[&f], &[])
            .await
            .expect("a public room under quorum:1/1");
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let priv_cid = found_community(d, &priv_cid, "quorum:1/1", &[&f], &[])
            .await
            .expect("a private room");
        let at = Utc::now() - Duration::hours(1);
        let invite = |room: String, who: String, t: DateTime<Utc>| {
            let f = f.clone();
            async move {
                let p = proposal(&f, COMMUNITY, &room, &who, None, t, Some(Duration::days(7)));
                put(d, &p).await.expect("the founder's invitation");
                put(d, &reply(&who, &who, &p, true, t + Duration::seconds(1)))
                    .await
                    .expect("the person's acceptance");
            }
        };

        // ── I2051: listed, then a minor row, then its withdrawal.
        invite(cid.clone(), k1.clone(), at).await;
        landed(
            widen(d, &cid, &[&f], &k1, None, at + Duration::seconds(2)).await,
            "I2051: the growth lands",
        );
        assert!(active(d, &cid, &k1).await, "I2051: listed (no age row)");
        let m1 = declare_minor(d, &p1).await;
        assert!(
            !active(d, &cid, &k1).await,
            "I2051: a LATER minor row takes the person off the public roster (re-fold)"
        );
        withdraw_own(d, &m1, &p1).await;
        assert!(
            active(d, &cid, &k1).await,
            "I2051: withdrawn, listed again with no new growth"
        );

        // ── I2052: the minor row first.
        let m2 = declare_minor(d, &p2).await;
        invite(cid.clone(), k2.clone(), at + Duration::seconds(10)).await;
        not_admitted(
            widen(d, &cid, &[&f], &k2, None, at + Duration::seconds(12)).await,
            &[crate::federation::membership_acceptance::RULE_MINOR_PUBLIC_ROSTER_ENTRY],
            "I2052: a minor's growth on a public room",
        );
        assert!(!active(d, &cid, &k2).await, "I2052: not listed");

        // ── I2053: the derived plane — a private room lists the same minor.
        invite(priv_cid.clone(), k2.clone(), at + Duration::seconds(20)).await;
        landed(
            widen(d, &priv_cid, &[&f], &k2, None, at + Duration::seconds(22)).await,
            "I2053: a private room's growth of the minor lands",
        );
        assert!(
            active(d, &priv_cid, &k2).await,
            "I2053: the minor is in their private room while the row stands"
        );

        withdraw_own(d, &m2, &p2).await;
        assert!(
            active(d, &cid, &k2).await,
            "I2052: withdrawn, the held growth concludes: listed"
        );
    }

    /// **I1515** — the removal window under `open:self_admit`.
    pub(crate) async fn i1515_removal_window_under_open_self_admit(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::consensus::OPEN_SELF_ADMIT_REMOVAL_WINDOW_SECS as WINDOW;
        let k = |n: &str| format!("i1515-{n}-{s}");
        let (f1, f2, f3, f4, f5, cid) = (k("f1"), k("f2"), k("f3"), k("f4"), k("f5"), k("pub"));
        reg(d, &[&f1, &f2, &f3, &f4, &f5, &cid]).await;
        let (f1, f2, f3, f4, f5, cid) = (
            id_of(&f1),
            id_of(&f2),
            id_of(&f3),
            id_of(&f4),
            id_of(&f5),
            id_of(&cid),
        );
        let now = Utc::now();
        // GID-fix6 — rebound to the RETURNED (derived) id.
        let cid = found_public_room_at(
            d,
            &cid,
            OPEN_SELF_ADMIT,
            &[&f1, &f2, &f3, &f4, &f5],
            now - Duration::days(10),
        )
        .await
        .unwrap();
        assert_eq!(WINDOW, 259_200, "I1515: CC's window, 72 hours");
        // A resignation is a member's own act, not a counted removal.
        landed(
            remove(d, &cid, &[&f5], &f5, now - Duration::days(5)).await,
            "I1515: a stale resignation is not bounded",
        );
        assert!(!active(d, &cid, &f5).await, "I1515: f5 left");
        // Two voices, asserted four days before receipt: outside the window.
        let stale = removal_voices(d, &cid, &[&f1, &f2], &f3, now - Duration::days(4)).await;
        let e = e2::put_voices(d, &stale)
            .await
            .expect_err("I1515: a removal older than the window at the local door");
        assert_eq!(
            rule(&e),
            crate::federation::ROSTER_REMOVAL_OUTSIDE_WINDOW,
            "I1515: {e}"
        );
        assert!(active(d, &cid, &f3).await, "I1515: f3 still in");
        // The replicated door applies it as data: another node admitted it in
        // time, and this node's clock is no witness to when the voices signed.
        for v in &stale {
            crate::federation::edition2::ingest::apply_replicated_statement(
                d,
                v,
                &e2::row_id_of(v).0,
            )
            .await
            .unwrap_or_else(|e| panic!("I1515: the replicated door: {e}"));
        }
        assert!(
            !active(d, &cid, &f3).await,
            "I1515: f3 removed by the replica"
        );
        // Inside the window, at the local door: admitted.
        landed(
            remove(
                d,
                &cid,
                &[&f1, &f2],
                &f4,
                now - Duration::seconds(WINDOW - 120),
            )
            .await,
            "I1515: a removal inside the window",
        );
        assert!(!active(d, &cid, &f4).await, "I1515: f4 removed");
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
        reg(d, &[&f1, &f2, &f3, &cid]).await;
        let joiner = bound_joiner(d, &joiner, &format!("i1503-o-{s}")).await;
        let (f1, f2, f3, cid) = (id_of(&f1), id_of(&f2), id_of(&f3), id_of(&cid));
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_public_room(d, &cid, OPEN_SELF_ADMIT, &[&f1, &f2, &f3], &[])
            .await
            .unwrap();
        let at = Utc::now() - Duration::hours(2);
        accept_standing(d, &f1, &cid, &joiner, at).await;
        landed(
            widen(
                d,
                &cid,
                &[&joiner],
                &joiner,
                None,
                at + Duration::seconds(2),
            )
            .await,
            "I1503: the joiner admits themselves",
        );
        assert!(active(d, &cid, &joiner).await);
        // One voice never excludes — a founder's included.
        not_admitted(
            remove(d, &cid, &[&f1], &joiner, at + Duration::minutes(1)).await,
            &[ROSTER_CONSENSUS_INSUFFICIENT],
            "I1503: one voice",
        );
        assert!(active(d, &cid, &joiner).await, "I1503: still in");
        // Two distinct voices remove.
        landed(
            remove(d, &cid, &[&f1, &f2], &joiner, at + Duration::minutes(2)).await,
            "I1503: two voices",
        );
        assert!(!active(d, &cid, &joiner).await, "I1503: removed");
        // Leaving stays a member's own act: no floor on a resignation.
        landed(
            remove(d, &cid, &[&f3], &f3, at + Duration::minutes(3)).await,
            "I1503: a resignation needs no one",
        );
        assert!(!active(d, &cid, &f3).await);
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod two_node {
    use super::bodies::{landed, remove, standing, widen};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_public_room, id_of, proposal, put, reg, reply,
    };
    use crate::federation::public_room::live_standing_proposal;
    use crate::federation::replication_audience::may_receive;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::COMMUNITY;
    use crate::federation::types::consensus_protocol::OPEN_SELF_ADMIT;
    use crate::federation::types::{attestation_type, device_class};
    use crate::federation::{Error, FederationDirectory};
    use chrono::{Duration, Utc};

    /// v62.0.0 (E13) — **`from`'s statements to `to`** through the FILTERED
    /// serve path (`edition2::serve::statements_served_to`, `requester` the
    /// receiving node; the store's raw since-read is never a serve surface),
    /// each into `to`'s replicated statement door under the id it names.
    async fn replicate(
        from: &dyn FederationDirectory,
        to: &dyn FederationDirectory,
        requester: &str,
    ) {
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                1000,
                Some(requester),
            )
            .await
            .expect("serve statements");
            for st in &page.statements {
                match crate::federation::edition2::names::RowId::of_statement(&st.bytes) {
                    Some(id) => {
                        crate::federation::edition2::ingest::apply_replicated_statement(
                            to, &st.bytes, &id.0,
                        )
                        .await
                        .unwrap_or_else(|e| panic!("a replicated statement: {e}"));
                    }
                    None => {
                        e2::put_statement(to, &st.bytes)
                            .await
                            .unwrap_or_else(|e| panic!("a replicated statement: {e}"));
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }

    /// **I1504** — a public room's standing proposal, on request.
    ///
    /// v62.0.0 (E13) — depends on T1.serve.patch: the filtered serve path's
    /// group-plane arm (a room's roster and membership voices served to its
    /// audience, I3006–I3008).
    pub(crate) async fn i1504_a_standing_proposal_is_served_on_request(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        s: &str,
    ) {
        let (founder, joiner, cid, private) = (
            format!("i1504-f-{s}"),
            format!("i1504-j-{s}"),
            format!("i1504-pub-{s}"),
            format!("i1504-priv-{s}"),
        );
        for n in [a, b] {
            reg(n, &[&founder, &cid, &private]).await;
        }
        // v62.0.0 (E13 fix1; X14) — the joiner is an owner-bound NODE key;
        // its binding reaches B with A's statements (a commons row).
        let joiner = super::bodies::bound_joiner(a, &joiner, &format!("i1504-o-{s}")).await;
        let (founder, cid, private) = (id_of(&founder), id_of(&cid), id_of(&private));
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_public_room(a, &cid, OPEN_SELF_ADMIT, &[&founder], &[])
            .await
            .unwrap();
        let at = Utc::now() - Duration::hours(1);
        assert!(
            live_standing_proposal(a, &cid).await.unwrap().is_none(),
            "I1504: control — no proposal yet"
        );
        let p = standing(&founder, &cid, at);
        put(a, &p).await.unwrap();
        // The member's node answers the request with the live proposal ...
        let served = live_standing_proposal(a, &cid)
            .await
            .unwrap()
            .expect("I1504: the live standing proposal");
        assert_eq!(served.attestation_id, p.attestation_id, "I1504");
        // ... which the requester's node may receive ...
        assert!(
            may_receive(a, &joiner, &served).await.unwrap().allowed(),
            "I1504: a non-member's node is in a public room's audience"
        );
        // ... and admits on its replicated door, with the room's roster: A's
        // statements served to the requester.
        replicate(a, b, &b.node_key_id().unwrap_or_else(|| joiner.clone())).await;
        assert!(
            b.lookup_community(&cid).await.unwrap().is_some(),
            "I1504: B takes the room"
        );
        // v62.0.0 (E13 fix2) — on a miss, say why B holds it (the fold's
        // reason), so a red here names its own cause.
        let why = crate::federation::edition2::fold::why_held(
            b,
            &crate::federation::edition2::names::RowId(e2::rid_digest(&p)),
        )
        .await
        .unwrap()
        .map(|h| h.reason);
        assert!(
            b.get_attestation(&p.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I1504: the requester's node stores the proposal (held for {why:?})"
        );
        // The requester accepts on their own node; the member's node admits
        // the acceptance and the requester's own widening.
        let acc = reply(&joiner, &joiner, &served, true, at + Duration::seconds(1));
        put(b, &acc).await.expect("I1504: the acceptance on B");
        replicate(b, a, &a.node_key_id().unwrap_or_else(|| founder.clone())).await;
        assert!(
            a.get_attestation(&acc.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I1504: A admits the acceptance"
        );
        landed(
            widen(
                a,
                &cid,
                &[&joiner],
                &joiner,
                None,
                at + Duration::seconds(2),
            )
            .await,
            "I1504: the joiner's own widening",
        );
        assert!(a
            .active_community_members(&cid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == joiner));
        // A withdrawn standing proposal is no longer live.
        let mut w = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &founder,
            &founder,
            &serde_json::json!({ "references_attestation_id": p.attestation_id }),
        );
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.cohort_scope = COMMUNITY.into();
        w.attestation_envelope["community_key_id"] = serde_json::json!(cid);
        ts::seal_row_in_place(&founder, &mut w);
        put(a, &w).await.expect("I1504: the founder withdraws it");
        assert!(
            live_standing_proposal(a, &cid).await.unwrap().is_none(),
            "I1504: withdrawn, not live"
        );
        // A private room has no standing proposal to serve.
        // GID-fix6 — rebound to the RETURNED (derived) id.
        let private = found_community(a, &private, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        assert!(live_standing_proposal(a, &private).await.unwrap().is_none());
    }

    /// **I1624** (CIRISPersist#1188, the six `live_standing_proposal`
    /// survivors; CIRISPersist#1063, CC 3.2) — **the live standing proposal
    /// is re-judged at the read.** What the door admitted is asked again
    /// against the room as it is now:
    ///
    /// - a `public` room that is not under `open:self_admit` serves none,
    ///   even holding a founder's standing proposal (one held before the room
    ///   was, which the door could not judge);
    /// - an invitation (a proposal naming its invitee) is not a standing
    ///   proposal;
    /// - a standing proposal whose founder has since resigned is not live;
    /// - a founder's standing proposal signed on the founder's occurrence
    ///   key is live (the proposer is the founder, not the key);
    /// - only the proposer's own `withdraws` retires one: a stranger's,
    ///   held before the proposal arrived, does not.
    pub(crate) async fn i1624_a_standing_proposal_is_judged_at_the_read(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i1624-{n}-{s}");
        let (f, f2, dv, x, j, cid, quorum_room) = (
            k("f"),
            k("f2"),
            k("dv"),
            k("x"),
            k("j"),
            k("pub"),
            k("pubq"),
        );
        reg(d, &[&f, &f2, &dv, &x, &j, &cid, &quorum_room]).await;
        let (f, f2, dv, x, j, cid, quorum_room) = (
            id_of(&f),
            id_of(&f2),
            id_of(&dv),
            id_of(&x),
            id_of(&j),
            id_of(&cid),
            id_of(&quorum_room),
        );
        let at = Utc::now() - Duration::hours(1);

        // A public room under quorum:1/1, its founder's standing proposal held
        // before the room was: not an open room, so none is served.
        // v62.0.0 (E13 fix2; CC 2.7.3) — a proposal for a room not held yet
        // WAITS (kept, concluding nothing); once the room lands it is judged
        // against it, and a room that is not open never concludes it. The
        // read serves none either way.
        let early = standing(&f, &quorum_room, at);
        e2::put_signed(d, &early)
            .await
            .expect("I1624: a proposal for a group not held here is kept");
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let quorum_room = found_public_room(d, &quorum_room, "quorum:1/1", &[&f], &[])
            .await
            .expect("I1624: a public room under quorum:1/1");
        let early_id = crate::federation::edition2::names::RowId(e2::rid_digest(&early));
        assert!(
            d.get_attestation(&early.attestation_id)
                .await
                .unwrap()
                .is_none()
                && crate::federation::edition2::fold::why_held(d, &early_id)
                    .await
                    .unwrap()
                    .is_some(),
            "I1624: the founder's standing proposal for a room that is not open is held"
        );
        assert!(
            live_standing_proposal(d, &quorum_room)
                .await
                .unwrap()
                .is_none(),
            "I1624: a public room that is not open serves no standing proposal"
        );

        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_public_room(d, &cid, OPEN_SELF_ADMIT, &[&f, &f2], &[])
            .await
            .unwrap();
        // An invitation is not a standing proposal.
        put(
            d,
            &proposal(&f, COMMUNITY, &cid, &j, None, at, Some(Duration::days(7))),
        )
        .await
        .expect("I1624: a founder's invitation");
        assert!(
            live_standing_proposal(d, &cid).await.unwrap().is_none(),
            "I1624: an invitation is not served as the standing proposal"
        );

        // A founder's standing proposal, then the founder resigns.
        let by_f2 = standing(&f2, &cid, at + Duration::minutes(1));
        put(d, &by_f2).await.expect("I1624: f2's standing proposal");
        assert_eq!(
            live_standing_proposal(d, &cid)
                .await
                .unwrap()
                .map(|p| p.attestation_id),
            Some(by_f2.attestation_id.clone()),
            "I1624: f2's standing proposal is live while f2 is a founder"
        );
        landed(
            remove(d, &cid, &[&f2], &f2, Utc::now() - Duration::minutes(30)).await,
            "I1624: f2 resigns",
        );
        assert!(
            live_standing_proposal(d, &cid).await.unwrap().is_none(),
            "I1624: a resigned founder's standing proposal is not live"
        );

        // The founder's occurrence key signs one: the proposer is the founder.
        // v62.0.0 (E13) — the occurrence is O1's `identity:occurrence` bind
        // (author f, identity f, occurrence dv; both voices).
        landed(
            e2::put_bind(
                d,
                &f,
                &f,
                &dv,
                device_class::SERVER,
                &e2::BindOptions::default(),
            )
            .await,
            "I1624: the occurrence binding, both halves",
        );
        let by_device = standing(&dv, &cid, at + Duration::minutes(2));
        put(d, &by_device)
            .await
            .expect("I1624: the founder's standing proposal on its occurrence key");
        assert_eq!(
            live_standing_proposal(d, &cid)
                .await
                .unwrap()
                .map(|p| p.attestation_id),
            Some(by_device.attestation_id.clone()),
            "I1624: a founder's occurrence-signed standing proposal is live"
        );

        // A stranger's withdraws, offered before the proposal it names.
        let later = standing(&f, &cid, at + Duration::minutes(3));
        let mut w = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &x,
            &x,
            &serde_json::json!({
                "references_attestation_id": later.attestation_id,
                "withdrawal_reason": "I1624",
            }),
        );
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.weight = None;
        ts::seal_row_in_place(&x, &mut w);
        // v62.0.0 (E13) — the edition-2 door may hold a composer whose target
        // is not held yet, or refuse it retryably
        // (`federation_withdraws_target_unheld`); either way it is held once
        // the target is, and it still retires nothing.
        let early_w = put(d, &w).await;
        put(d, &later)
            .await
            .expect("I1624: f's later standing proposal");
        if let Err(e) = early_w {
            assert!(
                matches!(e, Error::WithdrawsTargetUnheld { .. }),
                "I1624: a withdraws before its target waits retryably: {e:?}"
            );
            put(d, &w)
                .await
                .expect("I1624: the stranger's withdraws once its target is held");
        }
        assert!(
            d.list_attestations_referencing(&later.attestation_id)
                .await
                .unwrap()
                .iter()
                .any(|c| c.attestation_id == w.attestation_id),
            "I1624: the stranger's withdraws references the proposal (else this proves nothing)"
        );
        assert_eq!(
            live_standing_proposal(d, &cid)
                .await
                .unwrap()
                .map(|p| p.attestation_id),
            Some(later.attestation_id.clone()),
            "I1624: a stranger's withdraws retires no standing proposal"
        );
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
                case!(i1515_removal_window_under_open_self_admit);
                case!(i2051_i2053_a_public_room_never_lists_a_minor);

                #[tokio::test]
                async fn i1624_a_standing_proposal_is_judged_at_the_read() {
                    let Some(d) = $fresh.await else { return };
                    super::super::two_node::i1624_a_standing_proposal_is_judged_at_the_read(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }

                #[tokio::test]
                async fn i1504_a_standing_proposal_is_served_on_request() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    super::super::two_node::i1504_a_standing_proposal_is_served_on_request(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
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
