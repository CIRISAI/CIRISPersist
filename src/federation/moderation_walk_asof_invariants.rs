//! v49.0.0 (CIRISPersist#908, `FSD/ROOM_ROSTER_AUTHORITY.md` §2 "Named
//! moderators keep standing, judged at the change's instant", §3 "Walk") — **the
//! moderation walk read at an instant, within one room.**
//!
//! [`moderation_reach_of_at`](crate::federation::admission::moderation_reach_of_at)
//! is the SAME body as `moderation_reach_of`, read through a lens: an edge
//! counts only if asserted by the instant and not expired at it; a retraction
//! counts only if asserted by the instant (CC 4.2, CC 2.4.1
//! `withdraws-isn't-retroactive`); an edge scoped to another room is not
//! followed (CC 4.5.4).
//!
//! Every assertion below is paired with the filter it pins. Remove the filter
//! and exactly that assertion goes red:
//!
//! | filter | assertion that fails without it |
//! |---|---|
//! | edge `asserted_at <= t` | not reached before the appointment |
//! | gate (a) retraction `asserted_at <= t` | reached between appointment and granter retraction |
//! | gate (b) retraction `asserted_at <= t` | reached between appointment and subject resignation |
//! | `expires_at > t` | not reached after expiry |
//! | community scoping | the other room's appointee is not reached |
//!
//! The unset reading (`moderation_reach_of`) is asserted unchanged: it still
//! drops a retracted edge, and still follows edges of every room.
//!
//! The instants are taken from the STORED rows rather than chosen, so the
//! witness never fights the put door's signed-instant binding (#598).

/// The backend-agnostic witness body; `run` instantiates it per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub mod bodies {
    use crate::federation::admission::steward_liveness_test_support::{
        register, signed_row, store,
    };
    use crate::federation::admission::{
        moderation_reach_of, moderation_reach_of_at, DELEGATION_SCOPE_MODERATE, MEMBER_ROLE_FOUNDER,
    };
    use crate::federation::edition2::fixture_switch as fx;
    use crate::federation::tier_ingest::test_support::{
        moderate_delegation_attestation, sign_community,
    };
    use crate::federation::types::{attestation_type, identity_type, Community, CommunityMember};
    use crate::federation::{Attestation, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// A `moderate` appointment `granter → recipient`, optionally naming a
    /// room in its signed envelope and optionally expiring.
    fn appointment(
        granter: &str,
        recipient: &str,
        community_id: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "id": id,
            "scope": [DELEGATION_SCOPE_MODERATE],
            "sub_delegation": false,
        });
        if let Some(c) = community_id {
            envelope["community_id"] = serde_json::Value::String(c.to_owned());
        }
        // The skeleton (switch off), then ONE edition-2 signing step after
        // the subject and the end are set.
        // CP2 skeleton: the builder's unsigned shape, re-signed as edition 2
        // (`row_of`) before any door.
        let mut row = fx::with_earlier_form(|| {
            signed_row(granter, recipient, attestation_type::DELEGATES_TO, envelope)
        });
        // The rc3 shape: the binding names the key it is about, which is what
        // lets the RECIPIENT resign it (CEG §3.2.3 rule 2).
        row.subject_key_ids = vec![recipient.to_owned()];
        row.expires_at = expires_at;
        fx::row_of(&row, granter)
    }

    /// A `founder_only` room whose single founder is `founder`.
    async fn room(dir: &dyn FederationDirectory, room: &str, founder: &str) {
        let now = Utc::now();
        // Wave 2 (T1): the founding roster's voice through the edition-2
        // door; the room lands under `fx::kid(room)`.
        let signed = sign_community(
            founder,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: room.to_owned(),
                community_name: format!("as-of room {room}"),
                members: vec![CommunityMember {
                    key_id: founder.to_owned(),
                    joined_at: now,
                    role: Some(MEMBER_ROLE_FOUNDER.to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "quorum:1/1".into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        fx::put_voices(dir, &fx::community_voices(&signed, 1, None, fx::ms(now)))
            .await
            .unwrap_or_else(|e| panic!("room {room}: {e}"));
    }

    /// Store `row` and return it AS STORED (the instants the walk will read).
    async fn put(dir: &dyn FederationDirectory, row: &Attestation, what: &str) -> Attestation {
        if row.attestation_type == attestation_type::DELEGATES_TO {
            // v62 (E3b-fix4; CC 2.6.1.9, E0.api v1.15): an own-act delegation waits
            // for the delegate's voice; `land_delegation` puts the author's row, then
            // that voice (a door refusal stays an Err).
            fx::land_delegation(dir, row)
                .await
                .unwrap_or_else(|e| panic!("{what}: {e}"));
        } else {
            store(dir, row)
                .await
                .unwrap_or_else(|e| panic!("{what}: {e}"));
        }
        dir.get_attestation(&row.attestation_id)
            .await
            .expect("read back")
            .unwrap_or_else(|| panic!("{what}: stored"))
    }

    /// Let the wall clock move so two rows get distinct `asserted_at`.
    async fn tick() {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    fn mid(a: DateTime<Utc>, b: DateTime<Utc>) -> DateTime<Utc> {
        assert!(a < b, "fixture: {a} must precede {b}");
        a + (b - a) / 2
    }

    async fn at(
        dir: &dyn FederationDirectory,
        root: &str,
        room: &str,
        t: DateTime<Utc>,
    ) -> Vec<String> {
        // Edition 2: the walk names keys by identity-ref; `root` is a seed.
        moderation_reach_of_at(dir, &fx::kid(root), room, t)
            .await
            .expect("moderation_reach_of_at")
    }

    async fn unset(dir: &dyn FederationDirectory, root: &str) -> Vec<String> {
        moderation_reach_of(dir, &fx::kid(root))
            .await
            .expect("moderation_reach_of")
    }

    /// I175's walk half: a moderator's standing belongs to the instant.
    #[allow(clippy::too_many_lines)]
    pub async fn exercise_moderation_walk_as_of(dir: &dyn FederationDirectory, tag: &str) {
        let alice = format!("{tag}-alice");
        let here = format!("{tag}-room");
        let there = format!("{tag}-other-room");
        // `user` roots (steward-bound by role); `primitive` recipients — a
        // `user → user` duty edge is a steward-binding and refused, and a
        // `node` may hold only `infra:*` scopes.
        register(dir, &alice, &[identity_type::USER]).await;
        for r in [&here, &there] {
            register(dir, r, &[identity_type::USER]).await;
        }
        let [mo, mo2, mo3, mo_here, mo_there] =
            ["mo", "mo2", "mo3", "mo-here", "mo-there"].map(|k| format!("{tag}-{k}"));
        for k in [&mo, &mo2, &mo3, &mo_here, &mo_there] {
            register(dir, k, &[identity_type::PRIMITIVE]).await;
        }
        room(dir, &here, &alice).await;
        room(dir, &there, &alice).await;

        // ── gate (a): the GRANTER retracts (bare §11.10 edge-retraction) ──
        // The canonical `moderate` appointment fixture (no room, no expiry).
        let e = put(
            dir,
            &moderate_delegation_attestation(&uuid::Uuid::new_v4().to_string(), &alice, &mo),
            "appoint mo",
        )
        .await;
        tick().await;
        // v62 (E3b r3): an edition-2 `withdraws` is a composer naming its
        // target by row id (`fx::composer_of`); the §11.10 bare
        // edge-retraction (a withdraws carrying only `id`, no target) has no
        // edition-2 form (`id` is not a member of the composer payload). The
        // granter's retraction is its withdraws OF the appointment.
        let w = put(
            dir,
            &fx::composer_of(attestation_type::WITHDRAWS, &e, &alice),
            "alice withdraws mo",
        )
        .await;
        let (t0, t2) = (e.asserted_at, w.asserted_at);
        let t1 = mid(t0, t2);
        assert!(
            at(dir, &alice, &fx::kid(&here), t1)
                .await
                .contains(&fx::kid(&mo)),
            "[{tag}] gate (a): mo is a moderator between appointment ({t0}) and the granter's \
             retraction ({t2}) — a later retraction does not reach back (CC 2.4.1)"
        );
        assert!(
            at(dir, &alice, &fx::kid(&here), t0)
                .await
                .contains(&fx::kid(&mo)),
            "[{tag}] the appointment counts AT its own instant (asserted_at <= t)"
        );
        assert!(
            !at(dir, &alice, &fx::kid(&here), t2)
                .await
                .contains(&fx::kid(&mo)),
            "[{tag}] gate (a): the retraction counts AT its own instant"
        );
        assert!(
            !at(dir, &alice, &fx::kid(&here), t2 + Duration::seconds(1))
                .await
                .contains(&fx::kid(&mo)),
            "[{tag}] gate (a): after the retraction mo has no standing"
        );
        assert!(
            !at(dir, &alice, &fx::kid(&here), t0 - Duration::seconds(1))
                .await
                .contains(&fx::kid(&mo)),
            "[{tag}] before the appointment mo had no standing — an edge not yet asserted did \
             not exist"
        );
        assert!(
            !unset(dir, &alice).await.contains(&fx::kid(&mo)),
            "[{tag}] the unset walk is unchanged: a retracted edge confers nothing"
        );

        // ── gate (b): the RECIPIENT resigns (rule-2 withdraws naming the edge) ──
        let e2 = put(dir, &appointment(&alice, &mo2, None, None), "appoint mo2").await;
        tick().await;
        let w2 = put(
            dir,
            &fx::composer_of(attestation_type::WITHDRAWS, &e2, &mo2),
            "mo2 resigns",
        )
        .await;
        assert_eq!(
            w2.withdraws_admission_rule,
            Some(2),
            "[{tag}] the resignation must be the rule-2 (non-granter) arm, so only gate (b) \
             sees it — otherwise this block does not isolate gate (b)"
        );
        let t1b = mid(e2.asserted_at, w2.asserted_at);
        assert!(
            at(dir, &alice, &fx::kid(&here), t1b)
                .await
                .contains(&fx::kid(&mo2)),
            "[{tag}] gate (b): mo2 is a moderator between appointment and resignation"
        );
        assert!(
            !at(
                dir,
                &alice,
                &fx::kid(&here),
                w2.asserted_at + Duration::seconds(1)
            )
            .await
            .contains(&fx::kid(&mo2)),
            "[{tag}] gate (b): after the resignation mo2 has no standing"
        );
        assert!(
            !unset(dir, &alice).await.contains(&fx::kid(&mo2)),
            "[{tag}] the unset walk is unchanged on gate (b)"
        );

        // ── expiry ──
        let e3 = put(
            dir,
            &appointment(&alice, &mo3, None, Some(Utc::now() + Duration::hours(1))),
            "appoint mo3 until +1h",
        )
        .await;
        let x = e3.expires_at.expect("stored expiry");
        assert!(
            at(dir, &alice, &fx::kid(&here), e3.asserted_at)
                .await
                .contains(&fx::kid(&mo3)),
            "[{tag}] an unexpired appointment counts"
        );
        assert!(
            !at(dir, &alice, &fx::kid(&here), x)
                .await
                .contains(&fx::kid(&mo3)),
            "[{tag}] an appointment has expired AT its expires_at"
        );
        assert!(
            !at(dir, &alice, &fx::kid(&here), x + Duration::seconds(1))
                .await
                .contains(&fx::kid(&mo3)),
            "[{tag}] an expired appointment is not reached"
        );
        assert!(
            unset(dir, &alice).await.contains(&fx::kid(&mo3)),
            "[{tag}] the unset walk does not consult expires_at (byte-identical pre-v49)"
        );

        // ── community scoping (CC 4.5.4) ──
        put(
            dir,
            &appointment(&alice, &mo_here, Some(&fx::kid(&here)), None),
            "appoint mo-here for this room",
        )
        .await;
        put(
            dir,
            &appointment(&alice, &mo_there, Some(&fx::kid(&there)), None),
            "appoint mo-there for the other room",
        )
        .await;
        let later = Utc::now() + Duration::minutes(1);
        let in_here = at(dir, &alice, &fx::kid(&here), later).await;
        assert!(
            in_here.contains(&fx::kid(&mo_here)),
            "[{tag}] an appointment naming this room is followed: {in_here:?}"
        );
        assert!(
            !in_here.contains(&fx::kid(&mo_there)),
            "[{tag}] an appointment naming ANOTHER room is not followed: {in_here:?}"
        );
        assert!(
            in_here.contains(&fx::kid(&mo3)),
            "[{tag}] an appointment naming no room is followed (compatibility): {in_here:?}"
        );
        let in_there = at(dir, &alice, &fx::kid(&there), later).await;
        assert!(
            in_there.contains(&fx::kid(&mo_there)) && !in_there.contains(&fx::kid(&mo_here)),
            "[{tag}] the other room sees only its own appointee: {in_there:?}"
        );
        let all = unset(dir, &alice).await;
        assert!(
            all.contains(&fx::kid(&mo_here)) && all.contains(&fx::kid(&mo_there)),
            "[{tag}] the unset walk follows every room, as before: {all:?}"
        );
    }

    /// Did the voice land the typed row (not `Pending`, not refused)?
    fn landed(
        r: &Result<crate::federation::edition2::ingest::StatementOutcome, crate::federation::Error>,
    ) -> bool {
        matches!(
            r,
            Ok(crate::federation::edition2::ingest::StatementOutcome::Row { .. })
        )
    }

    /// The held roster head of room `here` (a seed).
    async fn head(
        dir: &dyn FederationDirectory,
        here: &str,
    ) -> crate::federation::edition2::names::RowId {
        fx::held_head(dir, &fx::kid(here))
            .await
            .expect("the room's roster head is held")
            .0
    }

    /// Wave 2 (T1 "partly"): **a widening through the edition-2 door.** The
    /// member's consent first, as edition-2 rows: `proposer`'s proposal
    /// naming the room by its identity-ref, then `member`'s acceptance of it
    /// (both `put_signed`); then `signer`'s widening voice over the held
    /// roster head. Returns the widening's outcome.
    async fn widen_e2(
        dir: &dyn FederationDirectory,
        here: &str,
        proposer: &str,
        signer: &str,
        member: &str,
        role: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, crate::federation::Error>
    {
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        use crate::federation::tier_ingest::test_support::sign_community_membership_widening;
        use crate::federation::types::{cohort_scope, CommunityMembershipWidening};
        let p = proposal_row(
            proposer,
            cohort_scope::COMMUNITY,
            &fx::kid(here),
            member,
            role,
            at,
        );
        fx::put_signed(dir, &p)
            .await
            .unwrap_or_else(|e| panic!("the proposal for {member}: {e}"));
        fx::put_signed(dir, &acceptance_row(member, &p, at))
            .await
            .unwrap_or_else(|e| panic!("{member}'s acceptance: {e}"));
        let w = sign_community_membership_widening(
            signer,
            CommunityMembershipWidening {
                community_key_id: here.to_owned(),
                member_key_id: member.to_owned(),
                joined_at: at,
                effective_at: at,
                role: role.map(str::to_owned),
                persist_row_hash: String::new(),
            },
        );
        let h = head(dir, here).await;
        fx::put_voices(dir, &fx::community_widening_voices(&w, Some(&h))).await
    }

    /// Wave 2 (T1): `signer`'s voice on the removal of `member` from room
    /// `here`, over the held roster head.
    async fn remove_e2(
        dir: &dyn FederationDirectory,
        here: &str,
        signer: &str,
        member: &str,
        reason: Option<&str>,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, crate::federation::Error>
    {
        use crate::federation::tier_ingest::test_support::sign_community_membership_revocation;
        use crate::federation::types::CommunityMembershipRevocation;
        let at = Utc::now();
        let r = sign_community_membership_revocation(
            signer,
            CommunityMembershipRevocation {
                community_key_id: here.to_owned(),
                removed_identity_key_id: member.to_owned(),
                removed_at: at,
                effective_at: at,
                reason: reason.map(str::to_owned),
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        let h = head(dir, here).await;
        fx::put_voices(dir, &fx::community_revocation_voices(&r, Some(&h))).await
    }

    /// The room's active roster, as identity-refs.
    async fn roster(dir: &dyn FederationDirectory, here: &str) -> Vec<String> {
        dir.active_community_members(&fx::kid(here))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect()
    }

    /// **I175 — a moderator's roster change belongs to its instant** (FSD §2,
    /// operator ruling; CC 4.2 liveness at the act, CC 2.4.1 not retroactive).
    /// Founder alice appoints mo (`moderate`, this room); mo widens hank while
    /// the appointment is live; alice withdraws it; hank STAYS; a widening by
    /// mo after the withdrawal, or dated before the appointment, does not
    /// land (wave 2: refused, or held `Pending` short of standing).
    pub async fn exercise_moderator_change_belongs_to_its_instant(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let alice = format!("{tag}-alice");
        let here = format!("{tag}-room");
        register(dir, &alice, &[identity_type::USER]).await;
        let mo = format!("{tag}-mo");
        register(dir, &mo, &[identity_type::PRIMITIVE]).await;
        let [hank, ivy, jay] = ["hank", "ivy", "jay"].map(|k| format!("{tag}-{k}"));
        for k in [&hank, &ivy, &jay] {
            register(dir, k, &[identity_type::USER]).await;
        }
        room(dir, &here, &alice).await;
        let e = put(
            dir,
            &appointment(&alice, &mo, Some(&fx::kid(&here)), None),
            "appoint mo",
        )
        .await;
        let t0 = e.asserted_at;
        tick().await;
        let r = widen_e2(dir, &here, &alice, &mo, &hank, None, Utc::now()).await;
        assert!(
            landed(&r),
            "[{tag}] I175: mo widens hank while appointed: {r:?}"
        );
        let r = widen_e2(
            dir,
            &here,
            &alice,
            &mo,
            &jay,
            None,
            t0 - Duration::seconds(5),
        )
        .await;
        assert!(
            !landed(&r),
            "[{tag}] I175: a widening dated before the appointment has no moderator standing: {r:?}"
        );
        tick().await;
        // v62 (E3b r3): the granter's withdraws OF the appointment (an
        // edition-2 composer naming its target; see gate (a) above).
        put(
            dir,
            &fx::composer_of(attestation_type::WITHDRAWS, &e, &alice),
            "alice withdraws mo",
        )
        .await;
        tick().await;
        let r = widen_e2(dir, &here, &alice, &mo, &ivy, None, Utc::now()).await;
        assert!(
            !landed(&r),
            "[{tag}] I175: after the withdrawal mo has no standing: {r:?}"
        );
        let roster = roster(dir, &here).await;
        assert!(
            roster.contains(&fx::kid(&hank)),
            "[{tag}] I175: hank, widened while mo was appointed, stays after the withdrawal"
        );
        assert!(
            !roster.contains(&fx::kid(&ivy)) && !roster.contains(&fx::kid(&jay)),
            "[{tag}] I175: {roster:?}"
        );
    }

    /// **I1524 (CIRISPersist#1200, CC 4.5.13) — a moderator removes nobody.**
    /// Founder alice appoints mo, and mo may still widen; mo's own voice on
    /// a removal does not land and the member stays; the protocol's voice
    /// removes.
    pub async fn exercise_a_moderator_removes_nobody(dir: &dyn FederationDirectory, tag: &str) {
        let [alice, mo, hank] = ["alice", "mo", "hank"].map(|k| format!("{tag}-{k}"));
        let here = format!("{tag}-room");
        register(dir, &alice, &[identity_type::USER]).await;
        register(dir, &mo, &[identity_type::PRIMITIVE]).await;
        register(dir, &hank, &[identity_type::USER]).await;
        room(dir, &here, &alice).await;
        put(
            dir,
            &appointment(&alice, &mo, Some(&fx::kid(&here)), None),
            "appoint mo",
        )
        .await;
        tick().await;
        let r = widen_e2(dir, &here, &alice, &mo, &hank, None, Utc::now()).await;
        assert!(landed(&r), "[{tag}] I1524: mo widens hank: {r:?}");
        tick().await;
        let r = remove_e2(dir, &here, &mo, &hank, None).await;
        assert!(
            !landed(&r),
            "[{tag}] I1524: a moderator's voice alone removes nobody: {r:?}"
        );
        assert!(
            roster(dir, &here).await.contains(&fx::kid(&hank)),
            "[{tag}] I1524: hank stays after mo's removal does not land"
        );
        tick().await;
        let r = remove_e2(dir, &here, &alice, &hank, None).await;
        assert!(landed(&r), "[{tag}] I1524: the protocol removes: {r:?}");
        assert!(
            !roster(dir, &here).await.contains(&fx::kid(&hank)),
            "[{tag}] I1524: hank is gone after the protocol's removal"
        );
    }

    /// **I175b — an appointment belongs to the epoch it was issued in**
    /// (operator ruling 2026-09-25; CC 4.2.6 "past actions validly decided
    /// stand", CC 4.5.4 lapse = withdrawal or inactivity only). (1) Founder
    /// alice appoints mo and then LEAVES the room: mo is still a moderator —
    /// removal is not a slash. (2) carol appoints mo2 while a plain member and
    /// is only later made a founder: mo2 never held the duty — the appointer
    /// had no authority when appointing.
    pub async fn exercise_an_appointment_belongs_to_its_epoch(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [alice, bob, carol] = ["alice", "bob", "carol"].map(|k| format!("{tag}-{k}"));
        let [mo, mo2] = ["mo", "mo2"].map(|k| format!("{tag}-{k}"));
        let [hank, ivy] = ["hank", "ivy"].map(|k| format!("{tag}-{k}"));
        for k in [&alice, &bob, &carol, &hank, &ivy] {
            register(dir, k, &[identity_type::USER]).await;
        }
        for k in [&mo, &mo2] {
            register(dir, k, &[identity_type::PRIMITIVE]).await;
        }
        let here = format!("{tag}-room");
        let now = Utc::now();
        let seat = |k: &str, founder: bool| CommunityMember {
            key_id: k.to_owned(),
            joined_at: now,
            role: founder.then(|| MEMBER_ROLE_FOUNDER.to_owned()),
        };
        // Wave 2 (T1): the founding roster's voices (alice, then bob and
        // carol through `founding_cosignatures`) through the edition-2 door.
        let founding = sign_community(
            &alice,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: here.clone(),
                community_name: format!("epoch room {here}"),
                members: vec![seat(&alice, true), seat(&bob, true), seat(&carol, false)],
                founded_at: now,
                consensus_protocol: "quorum:1/1".into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        fx::put_voices(dir, &fx::community_voices(&founding, 1, None, fx::ms(now)))
            .await
            .unwrap_or_else(|e| panic!("room: {e}"));
        // (1) alice appoints mo, then leaves.
        put(
            dir,
            &appointment(&alice, &mo, Some(&fx::kid(&here)), None),
            "appoint mo",
        )
        .await;
        tick().await;
        let r = remove_e2(dir, &here, &alice, &alice, Some("left")).await;
        assert!(
            landed(&r),
            "[{tag}] alice leaves (bob remains a founder): {r:?}"
        );
        tick().await;
        let r = widen_e2(dir, &here, &bob, &mo, &hank, None, Utc::now()).await;
        assert!(
            landed(&r),
            "[{tag}] I175b: alice left, mo's appointment stands — mo widens hank: {r:?}"
        );
        // (2) carol appoints mo2 BEFORE she is a founder; bob then makes her one.
        put(
            dir,
            &appointment(&carol, &mo2, Some(&fx::kid(&here)), None),
            "carol appoints mo2",
        )
        .await;
        tick().await;
        let r = widen_e2(
            dir,
            &here,
            &bob,
            &bob,
            &carol,
            Some(MEMBER_ROLE_FOUNDER),
            Utc::now(),
        )
        .await;
        assert!(landed(&r), "[{tag}] bob makes carol a founder: {r:?}");
        tick().await;
        let r = widen_e2(dir, &here, &bob, &mo2, &ivy, None, Utc::now()).await;
        assert!(
            !landed(&r),
            "[{tag}] I175b: an appointment issued while carol had no authority never \
             conferred the duty: {r:?}"
        );
        let roster = roster(dir, &here).await;
        assert!(
            roster.contains(&fx::kid(&hank)) && !roster.contains(&fx::kid(&ivy)),
            "[{tag}] I175b: {roster:?}"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn moderation_walk_as_of_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_moderation_walk_as_of(&b, &format!("mao-{}", suffix())).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn moderation_walk_as_of_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_moderation_walk_as_of(&b, &format!("mao-{}", suffix())).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_moderator_removes_nobody_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_a_moderator_removes_nobody(&b, &format!("i1524-{}", suffix()))
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn a_moderator_removes_nobody_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_a_moderator_removes_nobody(&b, &format!("i1524-{}", suffix()))
            .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn moderator_change_belongs_to_its_instant_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_moderator_change_belongs_to_its_instant(
            &b,
            &format!("i175-{}", suffix()),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn moderator_change_belongs_to_its_instant_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_moderator_change_belongs_to_its_instant(
            &b,
            &format!("i175-{}", suffix()),
        )
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn an_appointment_belongs_to_its_epoch_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_an_appointment_belongs_to_its_epoch(
            &b,
            &format!("i175b-{}", suffix()),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn an_appointment_belongs_to_its_epoch_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::exercise_an_appointment_belongs_to_its_epoch(
            &b,
            &format!("i175b-{}", suffix()),
        )
        .await;
    }
}
