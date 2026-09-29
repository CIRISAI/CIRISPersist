//! v50.0.0 — the three small CC rc5 adopts (`FSD/SECOND_DEVICE.md` §8),
//! witnessed on every backend.
//!
//! - **#925** (CC 3.2 "Infrastructure does not vote") — a `node`-bearing key
//!   cannot be seated as founder of an `infrastructure` community at any
//!   door (record, supersede, widening), and a seat that pre-dates the gate
//!   does not vote in the fold. Clause A (CC 3.4.7.3): a fused
//!   `{node,agent}` / `{node,user}` key is not minted.
//! - **#927** (CC 3.2 conformance) — an `infrastructure` community declares a
//!   `quorum:M/N` protocol or is refused.
//! - **#928** (CC 4.1.1) — every delegation walk defaults to 5 hops; a 6-hop
//!   chain confers only under an explicit `max_depth = 6`, and a chain past
//!   the cap is reported as too deep, never as absent.

/// The backend-agnostic witness bodies; `runners` instantiates them.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub mod bodies {
    use crate::federation::admission::steward_liveness_test_support::{register, signed_row};
    use crate::federation::admission::{
        self, ReachabilityVerdict, DELEGATION_SCOPE_CONSENT_REVOCATION, DELEGATION_SCOPE_MODERATE,
        INFRA_RULE_NODE_BEARING_FOUNDER, INFRA_RULE_PROTOCOL_NOT_QUORUM,
        MAX_MODERATION_DELEGATION_DEPTH,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, identity_type as it, Community, CommunityMember,
        CommunityMembershipWidening,
    };
    use crate::federation::{
        Attestation, DelegationDepthOutcome, Error, FederationDirectory, SignedAttestation,
        SignedKeyRecord, DEFAULT_DELEGATION_DEPTH,
    };

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    fn seat(key: &str, role: &str) -> CommunityMember {
        CommunityMember {
            key_id: key.to_owned(),
            joined_at: at("2026-01-01T00:00:00Z"),
            role: Some(role.to_owned()),
        }
    }

    fn infra_room(room: &str, protocol: &str, members: Vec<CommunityMember>) -> Community {
        Community {
            community_key_id: room.to_owned(),
            community_name: "trust root".into(),
            members,
            founded_at: at("2026-01-01T00:00:00Z"),
            consensus_protocol: protocol.to_owned(),
            policy_blob: Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
            persist_row_hash: String::new(),
        }
    }

    /// An AUTHORIZED infrastructure room id (its key is `substrate_persist`),
    /// so the steward-binding carve-out applies and only the #925/#927 gates
    /// can refuse a node member.
    async fn authorized_room_key(d: &dyn FederationDirectory, room: &str) {
        ts::register_hybrid_key_as(d, room, room, it::SUBSTRATE_PERSIST).await;
    }

    /// Plant a LEGACY infrastructure record the way a node receives one from a
    /// peer: through the replicated entry (CIRISPersist#931), which admits it
    /// as data where the local door would refuse it. Returns the store result
    /// so call sites read like the door they replace.
    async fn plant_legacy(
        d: &dyn FederationDirectory,
        signed: crate::federation::SignedCommunity,
    ) -> Result<(), Error> {
        match d.apply_replicated_community(signed).await? {
            crate::federation::ReplicatedCommunityOutcome::Inserted
            | crate::federation::ReplicatedCommunityOutcome::Unchanged => Ok(()),
            other => Err(Error::Backend(format!("legacy plant: {other:?}"))),
        }
    }

    fn violation_rule(e: &Error) -> &'static str {
        match e {
            Error::CommunityConsensusProtocolViolation { rule, .. } => rule,
            other => panic!("expected CommunityConsensusProtocolViolation, got {other}"),
        }
    }

    /// The IDENTITY signs `{identity → occurrence}`, asserted at `t`: a
    /// unilateral claim, which the occurrence gate admits (the signer is the
    /// identity itself) and which does NOT make the occurrence node-bearing
    /// (review H1).
    async fn identity_claims_at(
        d: &dyn FederationDirectory,
        identity: &str,
        occurrence: &str,
        t: chrono::DateTime<chrono::Utc>,
    ) {
        d.put_identity_occurrence(
            ts::signed_content_only_occurrence(identity, identity, occurrence, t).await,
        )
        .await
        .expect("the identity's claim is admitted");
    }

    /// The OCCURRENCE signs the same binding itself, asserted at `t` (its
    /// agreement). Admitted because the identity's claim already made it an
    /// active occurrence.
    async fn occurrence_agrees_at(
        d: &dyn FederationDirectory,
        identity: &str,
        occurrence: &str,
        t: chrono::DateTime<chrono::Utc>,
    ) {
        d.put_identity_occurrence(
            ts::signed_content_only_occurrence(occurrence, identity, occurrence, t).await,
        )
        .await
        .expect("the occurrence's own row is admitted");
    }

    async fn identity_claims(d: &dyn FederationDirectory, identity: &str, occurrence: &str) {
        identity_claims_at(d, identity, occurrence, ago(3)).await;
    }

    async fn occurrence_agrees(d: &dyn FederationDirectory, identity: &str, occurrence: &str) {
        occurrence_agrees_at(d, identity, occurrence, ago(1)).await;
    }

    /// Both halves, the agreement asserted at `t`: the key is an occurrence of
    /// `identity` by its own consent from `t` on.
    async fn occurrence_of_at(
        d: &dyn FederationDirectory,
        identity: &str,
        occurrence: &str,
        t: chrono::DateTime<chrono::Utc>,
    ) {
        identity_claims_at(d, identity, occurrence, t - chrono::Duration::seconds(1)).await;
        occurrence_agrees_at(d, identity, occurrence, t).await;
    }

    /// Both halves, now.
    async fn occurrence_of(d: &dyn FederationDirectory, identity: &str, occurrence: &str) {
        occurrence_of_at(d, identity, occurrence, ago(1)).await;
    }

    /// `secs` seconds ago (negative: in the future), millisecond-truncated.
    fn ago(secs: i64) -> chrono::DateTime<chrono::Utc> {
        let t = chrono::Utc::now() - chrono::Duration::seconds(secs);
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
    }

    fn widening_at(
        room: &str,
        member: &str,
        t: chrono::DateTime<chrono::Utc>,
    ) -> CommunityMembershipWidening {
        CommunityMembershipWidening {
            community_key_id: room.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: t,
            effective_at: t,
            role: Some("member".into()),
            persist_row_hash: String::new(),
        }
    }

    async fn widen_by(
        d: &dyn FederationDirectory,
        signer: &str,
        room: &str,
        member: &str,
        t: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        d.put_community_membership_widening(ts::sign_community_membership_widening(
            signer,
            widening_at(room, member, t),
        ))
        .await
    }

    async fn active(d: &dyn FederationDirectory, room: &str) -> Vec<String> {
        d.active_community_members(room)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect()
    }

    /// **#925 review H1 — an identity's claim over a key is not the key's
    /// agreement.** A `node` key N signs `{identity: N, occurrence: H}` for a
    /// human founder H. The gate admits the row (its signer is the identity),
    /// but H is NOT node-bearing: an infrastructure record naming H as founder
    /// is admitted, and H's scrub still admits a roster change. Once H signs
    /// the binding itself, H is node-bearing and the same record is refused.
    pub async fn identity_claim_alone_is_not_node_bearing_founder(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let human = format!("human-{tag}");
        let attacker = format!("attacker-{tag}");
        let newcomer = format!("newcomer-{tag}");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        ts::register_hybrid_key_as(d, &attacker, &attacker, it::NODE).await;
        ts::register_hybrid_key_as(d, &newcomer, &newcomer, it::USER).await;
        identity_claims(d, &attacker, &human).await;
        assert!(
            d.list_identity_occurrences_by_occurrence_key(&human)
                .await
                .unwrap()
                .iter()
                .any(|io| io.identity_key_id == attacker),
            "{tag}: precondition — the claim is stored on the plane"
        );
        // v51.2.0 (CIRISPersist#932) — stored, but it resolves NOTHING: the
        // attacker is not the human's principal (H1 applied to the resolver).
        assert!(
            !d.active_identities_for_occurrence(&human)
                .await
                .unwrap()
                .contains(&attacker),
            "{tag}: #932 — a unilateral signed claim is not a principal"
        );
        // Controls: the occurrence's OWN agreement resolves, and a
        // trusted-local anchor (this node's `self_at_login`, no signature)
        // resolves — the two shapes production writes.
        let agreed = format!("agreed-device-{tag}");
        ts::register_hybrid_key_as(d, &agreed, &agreed, it::USER).await;
        identity_claims(d, &human, &agreed).await;
        assert!(
            !d.active_identities_for_occurrence(&agreed)
                .await
                .unwrap()
                .contains(&human),
            "{tag}: #932 — the identity's claim alone does not resolve the device"
        );
        occurrence_agrees(d, &human, &agreed).await;
        assert_eq!(
            d.active_identities_for_occurrence(&agreed).await.unwrap(),
            vec![human.clone()],
            "{tag}: #932 — the occurrence's agreement resolves it"
        );
        let anchor = format!("local-device-{tag}");
        ts::register_hybrid_key_as(d, &anchor, &anchor, it::USER).await;
        d.put_identity_occurrence_local(
            ts::signed_content_only_occurrence(&human, &human, &anchor, ago(1))
                .await
                .identity_occurrence,
        )
        .await
        .expect("a trusted-local anchor is stored");
        assert_eq!(
            d.active_identities_for_occurrence(&anchor).await.unwrap(),
            vec![human.clone()],
            "{tag}: #932 — a trusted-local anchor resolves"
        );
        assert!(
            !crate::federation::is_node_bearing_key(d, &human)
                .await
                .unwrap(),
            "{tag}: H1 — a node's unilateral claim does not make the human node-bearing"
        );
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        d.put_community(ts::sign_community(
            &human,
            infra_room(&room, "quorum:1/1", vec![seat(&human, "founder")]),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: H1 — the human is still a founder: {e}"));
        d.put_community_membership_widening(ts::sign_community_membership_widening(
            &human,
            CommunityMembershipWidening {
                community_key_id: room.clone(),
                member_key_id: newcomer.clone(),
                joined_at: at("2026-02-01T00:00:00Z"),
                effective_at: at("2026-02-01T00:00:00Z"),
                role: Some("member".into()),
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: H1 — the human's scrub still votes: {e}"));
        // The human agrees: now it IS node-bearing.
        occurrence_agrees(d, &attacker, &human).await;
        assert!(crate::federation::is_node_bearing_key(d, &human)
            .await
            .unwrap());
        let room_b = format!("root-b-{tag}");
        authorized_room_key(d, &room_b).await;
        let err = d
            .put_community(ts::sign_community(
                &human,
                infra_room(&room_b, "quorum:1/1", vec![seat(&human, "founder")]),
            ))
            .await
            .expect_err("a binding the key signed itself counts");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_NODE_BEARING_FOUNDER,
            "{err}"
        );
    }

    /// **#925 — `node_key_cannot_be_infrastructure_founder`.** Every door
    /// that can seat a founder refuses a `node`-bearing one with
    /// `hard_case:community_consensus_protocol_violation`, and stores nothing:
    /// the record door (a key whose own set holds `node`, and a key that is an
    /// occurrence of a `node` identity), the supersede door, and the widening
    /// door. The same key as `role: member` is admitted (serve, store,
    /// replicate).
    pub async fn node_key_cannot_be_infrastructure_founder(d: &dyn FederationDirectory, tag: &str) {
        let human = format!("human-{tag}");
        let install = format!("install-{tag}");
        let relay_identity = format!("relay-id-{tag}");
        let relay_occ = format!("relay-occ-{tag}");
        let late = format!("late-install-{tag}");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        ts::register_hybrid_key_as(d, &install, &install, it::NODE).await;
        ts::register_hybrid_key_as(d, &late, &late, it::NODE).await;
        ts::register_hybrid_key_as(d, &relay_identity, &relay_identity, it::NODE).await;
        // The occurrence's OWN record is not `node`: only the identity it is
        // an occurrence of is — and the occurrence signed that binding itself.
        ts::register_hybrid_key_as(d, &relay_occ, &relay_occ, it::PRIMITIVE).await;
        occurrence_of(d, &relay_identity, &relay_occ).await;

        // (1) the record door — the key's own set holds `node`.
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        let err = d
            .put_community(ts::sign_community(
                &human,
                infra_room(
                    &room,
                    "quorum:2/2",
                    vec![seat(&human, "founder"), seat(&install, "founder")],
                ),
            ))
            .await
            .expect_err("#925: a node key is never an infrastructure founder");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_NODE_BEARING_FOUNDER,
            "{err}"
        );
        assert_eq!(
            err.kind(),
            "federation_community_consensus_protocol_violation"
        );
        assert!(
            err.to_string()
                .contains("hard_case:community_consensus_protocol_violation"),
            "the CC 3.4.2 token names the refusal: {err}"
        );
        assert!(d.lookup_community(&room).await.unwrap().is_none());

        // (1b) through the occurrence: the key's own record is `primitive`,
        // the identity it agreed to be an occurrence of is `node`.
        let room_b = format!("root-b-{tag}");
        authorized_room_key(d, &room_b).await;
        let err = d
            .put_community(ts::sign_community(
                &human,
                infra_room(
                    &room_b,
                    "quorum:2/2",
                    vec![seat(&human, "founder"), seat(&relay_occ, "founder")],
                ),
            ))
            .await
            .expect_err("#925: node-bearing through the occurrence it is of");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_NODE_BEARING_FOUNDER,
            "{err}"
        );

        // (2) conformant: the install joins as a member.
        d.put_community(ts::sign_community(
            &human,
            infra_room(
                &room,
                "quorum:1/1",
                vec![seat(&human, "founder"), seat(&install, "member")],
            ),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: a node key joins as member: {e}"));

        // (3) the supersede door: promoting the install to founder.
        let err = d
            .supersede_community(
                ts::sign_community(
                    &human,
                    infra_room(
                        &room,
                        "quorum:2/2",
                        vec![seat(&human, "founder"), seat(&install, "founder")],
                    ),
                ),
                None,
            )
            .await
            .expect_err("#925: a supersede cannot seat a node founder");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_NODE_BEARING_FOUNDER,
            "{err}"
        );

        // (4) the widening door: seating another node key as founder.
        let w = |role: &str| CommunityMembershipWidening {
            community_key_id: room.clone(),
            member_key_id: late.clone(),
            joined_at: at("2026-02-01T00:00:00Z"),
            effective_at: at("2026-02-01T00:00:00Z"),
            role: Some(role.to_owned()),
            persist_row_hash: String::new(),
        };
        let err = d
            .put_community_membership_widening(ts::sign_community_membership_widening(
                &human,
                w("founder"),
            ))
            .await
            .expect_err("#925: a widening cannot seat a node founder");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_NODE_BEARING_FOUNDER,
            "{err}"
        );
        d.put_community_membership_widening(ts::sign_community_membership_widening(
            &human,
            w("member"),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: a node key widened in as member: {e}"));
        let founders: Vec<String> = d
            .active_community_members(&room)
            .await
            .unwrap()
            .into_iter()
            .filter(|m| m.role.as_deref() == Some("founder"))
            .map(|m| m.key_id)
            .collect();
        assert_eq!(founders, vec![human.clone()]);
    }

    /// **#925 — the fold vector** (runs where the room is replicated DATA —
    /// a legacy `quorum:1/2` record the M1 parser would refuse if authored
    /// here). Founders `{human, install}`: the install alone widens `second`;
    /// the install then agrees to be an occurrence of a `node` identity; a
    /// widening signed by the install alone no longer admits (its seat is
    /// dropped, not counted), the human's does, and `second` — admitted
    /// before the binding — still stands.
    pub async fn node_founder_seat_does_not_vote(
        d: &dyn FederationDirectory,
        tag: &str,
        _host: &str,
    ) {
        let human = format!("human-{tag}");
        let install = format!("install-{tag}");
        let node_identity = format!("node-id-{tag}");
        let newcomer = format!("newcomer-{tag}");
        let second = format!("second-{tag}");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        ts::register_hybrid_key_as(d, &install, &install, it::PRIMITIVE).await;
        ts::register_hybrid_key_as(d, &node_identity, &node_identity, it::NODE).await;
        ts::register_hybrid_key_as(d, &newcomer, &newcomer, it::USER).await;
        ts::register_hybrid_key_as(d, &second, &second, it::USER).await;
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        plant_legacy(
            d,
            ts::sign_community(
                &human,
                infra_room(
                    &room,
                    "quorum:1/2",
                    vec![seat(&human, "founder"), seat(&install, "founder")],
                ),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: the legacy room: {e}"));
        widen_by(d, &install, &room, &second, ago(100))
            .await
            .unwrap_or_else(|e| panic!("{tag}: control — a founder's scrub admits: {e}"));
        occurrence_of_at(d, &node_identity, &install, ago(80)).await;
        let err = widen_by(d, &install, &room, &newcomer, ago(60))
            .await
            .expect_err("#925: the node seat's scrub does not admit under quorum:1/2");
        assert!(
            matches!(err, Error::RosterAuthorityUnauthorized { .. }),
            "refused by the roster standing gate: {err}"
        );
        assert!(!active(d, &room).await.contains(&newcomer));
        widen_by(d, &human, &room, &newcomer, ago(50))
            .await
            .unwrap_or_else(|e| panic!("{tag}: the human founder's scrub admits: {e}"));
        assert!(
            active(d, &room).await.contains(&second),
            "{tag}: item 5 — `second`, admitted before the binding, still stands"
        );
    }

    /// **#925 review item 5 — node-bearing is judged at the change's
    /// instant** (v49: live at the act's instant, no ending retroactive). Founders
    /// `{human, install}`, `quorum:1/2` (replicated data):
    /// (1) the install alone widens `second` at t1;
    /// (2) the install is bound to a `node` identity, asserted t2 > t1 —
    ///     `second` still stands;
    /// (3) an install-only widening at t3 > t2 is refused, a human-signed one
    ///     admitted;
    /// (4) the binding is revoked effective t4 — an install-only widening at t5
    ///     is admitted, and (3)'s refused row is still absent;
    /// (5) control: a binding asserted before t1 makes the install's step-1
    ///     widening fail.
    pub async fn node_bearing_is_judged_at_the_change_instant(
        d: &dyn FederationDirectory,
        tag: &str,
        _host: &str,
    ) {
        let human = format!("human-{tag}");
        let install = format!("install-{tag}");
        let install2 = format!("install2-{tag}");
        let node_identity = format!("node-id-{tag}");
        let [second, third, refused, fifth] =
            ["second", "third", "refused", "fifth"].map(|n| format!("{n}-{tag}"));
        for k in [&human, &second, &third, &refused, &fifth] {
            ts::register_hybrid_key_as(d, k, k, it::USER).await;
        }
        ts::register_hybrid_key_as(d, &install, &install, it::PRIMITIVE).await;
        ts::register_hybrid_key_as(d, &install2, &install2, it::PRIMITIVE).await;
        ts::register_hybrid_key_as(d, &node_identity, &node_identity, it::NODE).await;
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        plant_legacy(
            d,
            ts::sign_community(
                &human,
                infra_room(
                    &room,
                    "quorum:1/2",
                    vec![seat(&human, "founder"), seat(&install, "founder")],
                ),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: the legacy room: {e}"));
        let (t1, t2, t3, t4, t5) = (ago(200), ago(160), ago(120), ago(80), ago(40));
        // (1)
        widen_by(d, &install, &room, &second, t1)
            .await
            .unwrap_or_else(|e| panic!("{tag}: (1) {e}"));
        // (2)
        occurrence_of_at(d, &node_identity, &install, t2).await;
        assert!(
            active(d, &room).await.contains(&second),
            "{tag}: (2) a binding asserted after t1 does not reach back to t1"
        );
        // (3)
        widen_by(d, &install, &room, &refused, t3)
            .await
            .expect_err("(3) the install is node-bearing at t3");
        widen_by(d, &human, &room, &third, t3 + chrono::Duration::seconds(1))
            .await
            .unwrap_or_else(|e| panic!("{tag}: (3) the human's scrub admits: {e}"));
        // (4)
        d.put_identity_occurrence_revocation(
            ts::signed_occurrence_revocation(&node_identity, &node_identity, &install, t4).await,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: (4) the revocation: {e}"));
        widen_by(d, &install, &room, &fifth, t5)
            .await
            .unwrap_or_else(|e| panic!("{tag}: (4) the binding ended at t4: {e}"));
        let now = active(d, &room).await;
        for k in [&second, &third, &fifth] {
            assert!(now.contains(k), "{tag}: (4) {k} stands");
        }
        assert!(
            !now.contains(&refused),
            "{tag}: (4) the ending is not retroactive — (3)'s refusal stands"
        );
        // (5) control
        let room2 = format!("root2-{tag}");
        authorized_room_key(d, &room2).await;
        plant_legacy(
            d,
            ts::sign_community(
                &human,
                infra_room(
                    &room2,
                    "quorum:1/2",
                    vec![seat(&human, "founder"), seat(&install2, "founder")],
                ),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: the control room: {e}"));
        occurrence_of_at(d, &node_identity, &install2, ago(240)).await;
        widen_by(d, &install2, &room2, &second, t1)
            .await
            .expect_err("(5) a binding asserted before t1 makes the install node-bearing at t1");
    }

    /// **#925 review M2 — the last-founder rule.** A `node`-bearing founder is
    /// not a founder a change leaves behind: with founders `{human, install}`
    /// and a member, once the install is `node`-bearing the human cannot leave
    /// (it would leave members and no founder). Control: before the binding,
    /// the same leave is admitted in a twin room.
    pub async fn node_bearing_founder_holds_no_last_founder_power(
        d: &dyn FederationDirectory,
        tag: &str,
        _host: &str,
    ) {
        let human = format!("human-{tag}");
        let install = format!("install-{tag}");
        let node_identity = format!("node-id-{tag}");
        let member = format!("member-{tag}");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        ts::register_hybrid_key_as(d, &member, &member, it::USER).await;
        ts::register_hybrid_key_as(d, &install, &install, it::PRIMITIVE).await;
        ts::register_hybrid_key_as(d, &node_identity, &node_identity, it::NODE).await;
        let leave = |room: &str, t| {
            ts::sign_community_membership_revocation(
                &human,
                crate::federation::types::CommunityMembershipRevocation {
                    community_key_id: room.to_owned(),
                    removed_identity_key_id: human.clone(),
                    removed_at: t,
                    effective_at: t,
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
        };
        for (room, bound) in [
            (format!("root-{tag}"), true),
            (format!("twin-{tag}"), false),
        ] {
            authorized_room_key(d, &room).await;
            plant_legacy(
                d,
                ts::sign_community(
                    &human,
                    infra_room(
                        &room,
                        "quorum:1/2",
                        vec![
                            seat(&human, "founder"),
                            seat(&install, "founder"),
                            seat(&member, "member"),
                        ],
                    ),
                ),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag}: room: {e}"));
            if bound {
                occurrence_of_at(d, &node_identity, &install, ago(100)).await;
                let err = d
                    .put_community_membership_revocation(leave(&room, ago(50)))
                    .await
                    .expect_err("M2: the only non-node founder cannot leave");
                match err {
                    Error::RosterAuthorityUnauthorized { rule, .. } => {
                        assert_eq!(rule, crate::federation::ROSTER_LAST_FOUNDER, "{tag}")
                    }
                    other => panic!("{tag}: expected the last-founder rule, got {other}"),
                }
            } else {
                // The twin's install is bound too (the binding is per key), so
                // its control leave is dated BEFORE the binding.
                d.put_community_membership_revocation(leave(&room, ago(150)))
                    .await
                    .unwrap_or_else(|e| panic!("{tag}: control — a founder remains: {e}"));
            }
        }
    }

    /// **#925 review M2 — no moderation root.** A `node`-bearing founder roots
    /// no `moderate` chain in an infrastructure room. Two twin rooms under
    /// `quorum:2/2` (so only moderator standing admits a lone deputy): in one
    /// the appointing founder is `node`-bearing when it appoints, in the other
    /// it is not. The first deputy's lone widening is refused, the second's
    /// admitted. (An appointment made while its root held authority keeps
    /// standing after — v49's no-retroactive-ending ruling — so the binding
    /// precedes the appointment here.)
    pub async fn node_bearing_founder_roots_no_moderation(
        d: &dyn FederationDirectory,
        tag: &str,
        _host: &str,
    ) {
        let human = format!("human-{tag}");
        let node_identity = format!("node-id-{tag}");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        ts::register_hybrid_key_as(d, &node_identity, &node_identity, it::NODE).await;
        for (name, bound) in [("bound", true), ("free", false)] {
            let install = format!("install-{name}-{tag}");
            let deputy = format!("deputy-{name}-{tag}");
            let newcomer = format!("newcomer-{name}-{tag}");
            ts::register_hybrid_key_as(d, &install, &install, it::USER).await;
            ts::register_hybrid_key_as(d, &newcomer, &newcomer, it::USER).await;
            ts::register_hybrid_key_as(d, &deputy, &deputy, it::PRIMITIVE).await;
            let room = format!("root-{name}-{tag}");
            authorized_room_key(d, &room).await;
            d.put_community(ts::sign_community(
                &human,
                infra_room(
                    &room,
                    "quorum:2/2",
                    vec![seat(&human, "founder"), seat(&install, "founder")],
                ),
            ))
            .await
            .unwrap_or_else(|e| panic!("{tag}: room: {e}"));
            if bound {
                occurrence_of_at(d, &node_identity, &install, ago(5)).await;
            }
            let id = uuid::Uuid::new_v4().to_string();
            let mut edge = signed_row(
                &install,
                &deputy,
                attestation_type::DELEGATES_TO,
                serde_json::json!({
                    "id": id, "scope": [DELEGATION_SCOPE_MODERATE], "community_id": room,
                }),
            );
            ts::reseal(&mut edge);
            d.put_attestation(SignedAttestation { attestation: edge })
                .await
                .unwrap_or_else(|e| panic!("{tag}: the moderate edge: {e}"));
            let r = widen_by(d, &deputy, &room, &newcomer, ago(-5)).await;
            if bound {
                assert!(
                    matches!(r, Err(Error::RosterAuthorityUnauthorized { .. })),
                    "{tag}: M2 — a node-bearing founder roots no moderation chain: {r:?}"
                );
            } else {
                r.unwrap_or_else(|e| panic!("{tag}: control — the founder's deputy admits: {e}"));
            }
        }
    }

    /// **#925 review M2/P3** — `node_bearing_founder_is_no_reverse_quorum_duty_holder`:
    /// the body lives beside the reverse-quorum fold's own witnesses (it needs
    /// their signed-row and objection helpers).
    pub async fn node_bearing_founder_is_no_reverse_quorum_duty_holder(
        d: &dyn FederationDirectory,
        tag: &str,
        _host: &str,
    ) {
        crate::federation::reverse_quorum::test_support::exercise_node_bearing_founder_is_no_reverse_quorum_duty_holder(
            d, tag,
        )
        .await;
    }

    /// **#927 — an `infrastructure` community declares `quorum:M/N`.** Every
    /// other canonical form is refused at the record door (and at the
    /// supersede door), not floored; the same forms stay admissible for a
    /// community that is not `infrastructure`.
    pub async fn infrastructure_protocol_must_be_quorum(d: &dyn FederationDirectory, tag: &str) {
        let human = format!("human-{tag}");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        for (i, p) in [
            // review M1 — `quorum:0/N` parses, and admits a change no founder
            // signed: not conformant.
            "quorum:0/1",
            "quorum:0/3",
            // review M1 — a single founder must not admit unilaterally.
            "quorum:1/2",
            "quorum:1/3",
            "founder_only",
            "majority",
            "unanimous",
            "weighted:uniform_half",
            "reverse_quorum:1/1:86400",
        ]
        .iter()
        .enumerate()
        {
            let room = format!("root-{i}-{tag}");
            authorized_room_key(d, &room).await;
            let err = d
                .put_community(ts::sign_community(
                    &human,
                    infra_room(&room, p, vec![seat(&human, "founder")]),
                ))
                .await
                .expect_err("#927: an infrastructure community is quorum:M/N");
            assert_eq!(
                violation_rule(&err),
                INFRA_RULE_PROTOCOL_NOT_QUORUM,
                "{p}: {err}"
            );
            assert!(d.lookup_community(&room).await.unwrap().is_none(), "{p}");
            // Not infrastructure: the same protocol is admitted.
            let mut plain = infra_room(&format!("{room}-plain"), p, vec![seat(&human, "founder")]);
            plain.policy_blob = None;
            d.put_community(ts::sign_community(&human, plain))
                .await
                .unwrap_or_else(|e| panic!("{tag}: {p} outside infrastructure: {e}"));
        }
        let room = format!("root-ok-{tag}");
        authorized_room_key(d, &room).await;
        d.put_community(ts::sign_community(
            &human,
            infra_room(&room, "quorum:1/1", vec![seat(&human, "founder")]),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: quorum:1/1 is conformant: {e}"));
        // Review (M1 loophole) — N is the founder count: M is read absolutely,
        // so `quorum:1/1` over three founders would let one of them admit
        // alone, and `quorum:2/3` over two would demand a founder who is not
        // there.
        let three = vec![
            seat(&human, "founder"),
            seat(&format!("f2-{tag}"), "founder"),
            seat(&format!("f3-{tag}"), "founder"),
        ];
        for (i, (p, founders)) in [
            ("quorum:1/1", three.clone()),
            ("quorum:2/3", three[..2].to_vec()),
        ]
        .into_iter()
        .enumerate()
        {
            let room = format!("root-n{i}-{tag}");
            authorized_room_key(d, &room).await;
            let err = d
                .put_community(ts::sign_community(&human, infra_room(&room, p, founders)))
                .await
                .expect_err("N must be the founder count");
            assert_eq!(
                violation_rule(&err),
                crate::federation::admission::INFRA_RULE_QUORUM_N_NOT_FOUNDERS,
                "{p}: {err}"
            );
        }
        let room3 = format!("root-23-{tag}");
        authorized_room_key(d, &room3).await;
        d.put_community(ts::sign_community(
            &human,
            infra_room(&room3, "quorum:2/3", three),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: quorum:2/3 over three founders: {e}"));
        // An infrastructure community with NO founder has no admission quorum.
        let none = format!("root-none-{tag}");
        authorized_room_key(d, &none).await;
        let err = d
            .put_community(ts::sign_community(
                &human,
                infra_room(&none, "quorum:1/1", vec![seat(&human, "member")]),
            ))
            .await
            .expect_err("no founder");
        assert_eq!(
            violation_rule(&err),
            crate::federation::admission::INFRA_RULE_NO_FOUNDER,
            "{err}"
        );
        let err = d
            .supersede_community(
                ts::sign_community(
                    &human,
                    infra_room(&room, "majority", vec![seat(&human, "founder")]),
                ),
                None,
            )
            .await
            .expect_err("#927: a supersede cannot lower the protocol form");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_PROTOCOL_NOT_QUORUM,
            "{err}"
        );
    }

    /// **#925 review M5 — the replicated `Insert` admits a fused key minted
    /// elsewhere** (gated data: Clause B and the steward gates apply wherever
    /// it acts), while a local mint of the same shape is refused. Every
    /// outcome of the replicated door is TYPED (`Ok`), so the caller's
    /// replication cursor records it and advances — a refusal is never an
    /// `Err` that would be re-polled: a pubkey swap over the admitted key is
    /// `Refused { pubkey_swap }`.
    pub async fn clause_a_replicated_insert_admits_a_fused_key(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::register::{KeyRefusalReason, ReplicatedKeyOutcome};
        let fused = it::join_set([it::NODE, it::AGENT]);
        let remote = format!("remote-fused-{tag}");
        let out = d
            .apply_replicated_key_record(SignedKeyRecord {
                record: ts::replicated_key_record(&remote, &fused, &remote, &remote, "n1"),
            })
            .await
            .unwrap_or_else(|e| panic!("{tag}: M5 — the replicated insert is typed: {e}"));
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Inserted,
            "{tag}: admitted as data"
        );
        assert_eq!(
            d.lookup_public_key(&remote)
                .await
                .unwrap()
                .unwrap()
                .identity_type,
            fused
        );
        let mut swapped = ts::replicated_key_record(&remote, &fused, &remote, &remote, "n2");
        let (other_ed, _) = ts::hybrid_pubkeys(&format!("other-{tag}"));
        swapped.pubkey_ed25519_base64 = other_ed;
        let out = d
            .apply_replicated_key_record(SignedKeyRecord { record: swapped })
            .await
            .unwrap_or_else(|e| panic!("{tag}: a refusal is typed, never an Err: {e}"));
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::PubkeySwap
            }
        );
        let local = format!("local-fused-{tag}");
        let err = d
            .put_public_key(SignedKeyRecord {
                record: ts::replicated_key_record(&local, &fused, &local, &local, "n1"),
            })
            .await
            .expect_err("a LOCAL mint of a fused key is refused");
        assert!(
            matches!(err, Error::NodeIdentityNotExclusive { .. }),
            "{err}"
        );
    }

    /// **#925/#927 review M6 + final check (CIRISPersist#931) — the DOOR, not
    /// the signer, decides.** Both nodes KNOW their own key (the production
    /// shape: the Engine always sets it), and every record is signed by a
    /// HUMAN founder, as infrastructure records normally are.
    ///
    /// - On node A, a `founder_only` infrastructure record put through the
    ///   LOCAL door is refused — whoever signed it.
    /// - The same record through the REPLICATED entry is admitted as data
    ///   (`Inserted`); re-applied identically it is `Unchanged`; and an
    ///   identical re-put through the local door settles too.
    /// - A changed record through the local door is judged and refused; a
    ///   supersede is judged and refused.
    /// - Node B syncs it from A's signed since-read through its replicated
    ///   entry.
    pub async fn infrastructure_record_authored_elsewhere_is_data(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::ReplicatedCommunityOutcome as Out;
        let human = format!("human-{tag}");
        for d in [a, b] {
            ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        }
        let room = format!("legacy-{tag}");
        let legacy = ts::sign_community(
            &human,
            infra_room(&room, "founder_only", vec![seat(&human, "founder")]),
        );
        let err = a
            .put_community(legacy.clone())
            .await
            .expect_err("the local door judges a record whoever signed it");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_PROTOCOL_NOT_QUORUM,
            "{err}"
        );
        assert!(a.lookup_community(&room).await.unwrap().is_none());
        assert_eq!(
            a.apply_replicated_community(legacy.clone()).await.unwrap(),
            Out::Inserted,
            "{tag}: the replicated entry admits a legacy record as data"
        );
        assert_eq!(
            a.apply_replicated_community(legacy.clone()).await.unwrap(),
            Out::Unchanged
        );
        a.put_community(legacy).await.unwrap_or_else(|e| {
            panic!("{tag}: an identical re-put settles on the local door: {e}")
        });
        let stored = a.lookup_community(&room).await.unwrap().expect("stored");
        let mut changed = stored.clone();
        changed.persist_row_hash = String::new();
        changed.community_name = "renamed".into();
        let err = a
            .put_community(ts::sign_community(&human, changed))
            .await
            .expect_err("a changed record through the local door is judged");
        assert!(
            matches!(
                err,
                Error::CommunityConsensusProtocolViolation { .. } | Error::Conflict(_)
            ),
            "{tag}: {err}"
        );
        let err = a
            .supersede_community(
                ts::sign_community(
                    &human,
                    infra_room(&room, "majority", vec![seat(&human, "founder")]),
                ),
                None,
            )
            .await
            .expect_err("a supersede is always judged");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_PROTOCOL_NOT_QUORUM,
            "{err}"
        );
        let served = a
            .list_signed_communities_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.community.community.community_key_id == room)
            .expect("A serves the legacy record")
            .community;
        assert_eq!(
            b.apply_replicated_community(served).await.unwrap(),
            Out::Inserted,
            "{tag}: a fresh node syncs it through its replicated entry"
        );
    }

    /// **#925 review, H3's fifth door — `add_peer_record` is a local mint.**
    /// An operator-added peer record carries a caller-supplied
    /// `identity_type`; a `{node,agent}` / `{node,user}` one is refused by the
    /// Clause A error and nothing is stored.
    pub async fn clause_a_peer_record_is_a_local_mint(d: &dyn FederationDirectory, tag: &str) {
        for actor in [it::AGENT, it::USER] {
            let k = format!("peer-fused-{actor}-{tag}");
            let (ed, _) = ts::hybrid_pubkeys(&k);
            let err = d
                .add_peer_record(&k, &ed, &it::join_set([it::NODE, actor]), None)
                .await
                .expect_err("Clause A on the peer door");
            assert!(
                matches!(err, Error::NodeIdentityNotExclusive { .. }),
                "{tag}: {actor}: {err}"
            );
            assert!(d.lookup_public_key(&k).await.unwrap().is_none());
        }
    }

    /// **Review, M1 loophole — a roster change may not make N stale; a
    /// founder may still leave.** A conformant `quorum:2/3` infrastructure room
    /// of three founders:
    /// - a widening that adds a fourth founder (two founders signing) is
    ///   refused (`INFRA_RULE_QUORUM_N_NOT_FOUNDERS`);
    /// - a plain member is admitted;
    /// - two founders removing the third is refused;
    /// - the third founder leaving on their OWN signature is admitted (v49's
    ///   consent floor, ruled 2026-09-27): N is the founder count AS ADMITTED.
    pub async fn infrastructure_founder_count_is_fixed_by_the_record(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let [h1, h2, h3, h4, m] = ["h1", "h2", "h3", "h4", "m"].map(|n| format!("{n}-{tag}"));
        for k in [&h1, &h2, &h3, &h4, &m] {
            ts::register_hybrid_key_as(d, k, k, it::USER).await;
        }
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        d.put_community(ts::sign_community(
            &h1,
            infra_room(
                &room,
                "quorum:2/3",
                vec![
                    seat(&h1, "founder"),
                    seat(&h2, "founder"),
                    seat(&h3, "founder"),
                ],
            ),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: conformant room: {e}"));
        let by_two = |mut w: crate::federation::SignedCommunityMembershipWidening| {
            ts::cosign_community_membership_widening(&mut w, &h2);
            w
        };
        let mut founder = widening_at(&room, &h4, ago(40));
        founder.role = Some("founder".into());
        let err = d
            .put_community_membership_widening(by_two(ts::sign_community_membership_widening(
                &h1, founder,
            )))
            .await
            .expect_err("adding a founder would leave N stale");
        assert_eq!(
            violation_rule(&err),
            crate::federation::admission::INFRA_RULE_QUORUM_N_NOT_FOUNDERS,
            "{err}"
        );
        d.put_community_membership_widening(by_two(ts::sign_community_membership_widening(
            &h1,
            widening_at(&room, &m, ago(30)),
        )))
        .await
        .unwrap_or_else(|e| panic!("{tag}: a plain member is admitted: {e}"));
        let removal = |signer: &String, t| {
            ts::sign_community_membership_revocation(
                signer,
                crate::federation::types::CommunityMembershipRevocation {
                    community_key_id: room.clone(),
                    removed_identity_key_id: h3.clone(),
                    removed_at: t,
                    effective_at: t,
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
        };
        let mut by_others = removal(&h1, ago(20));
        ts::cosign_community_membership_revocation(&mut by_others, &h2);
        let err = d
            .put_community_membership_revocation(by_others)
            .await
            .expect_err("other founders removing a founder would leave N stale");
        assert_eq!(
            violation_rule(&err),
            crate::federation::admission::INFRA_RULE_QUORUM_N_NOT_FOUNDERS,
            "{err}"
        );
        d.put_community_membership_revocation(removal(&h3, ago(10)))
            .await
            .unwrap_or_else(|e| panic!("{tag}: a founder may leave on their own signature: {e}"));
        assert!(!active(d, &room).await.contains(&h3));
    }

    /// **Final check — a conformant room never degrades through the
    /// replicated door.** A `quorum:2/2` infrastructure room of two founders,
    /// stored here. A peer offers a supersede carrying a valid proof (both
    /// founders signed the change) that would turn it `founder_only`, or seat a
    /// `node` key as a third founder: the replicated entry refuses both,
    /// `Refused { degrades_conformance }`. A LEGACY room (planted as data under
    /// `majority`) still syncs the same kind of supersede (`Superseded`).
    pub async fn replicated_supersede_never_degrades_a_conformant_room(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::{ReplicatedCommunityOutcome as Out, ReplicatedCommunityRefusal};
        let [h1, h2, n] = ["h1", "h2", "n"].map(|k| format!("{k}-{tag}"));
        ts::register_hybrid_key_as(d, &h1, &h1, it::USER).await;
        ts::register_hybrid_key_as(d, &h2, &h2, it::USER).await;
        ts::register_hybrid_key_as(d, &n, &n, it::NODE).await;
        let founders2 = || vec![seat(&h1, "founder"), seat(&h2, "founder")];
        let offer = |room: &str, protocol: &str, members: Vec<CommunityMember>| {
            let (h1, h2) = (h1.clone(), h2.clone());
            let room = room.to_owned();
            let protocol = protocol.to_owned();
            async move {
                let prior = d.lookup_community(&room).await.unwrap().expect("stored");
                let keys: Vec<String> = members.iter().map(|m| m.key_id.clone()).collect();
                let change = d
                    .build_membership_change_envelope(
                        crate::federation::cohort::Cohort::Community,
                        &room,
                        &keys,
                        false,
                        Some(&protocol),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("build change: {e}"));
                let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
                let mut signed = ts::sign_community(&h1, infra_room(&room, &protocol, members));
                signed.supersede_proof = Some(crate::federation::types::GroupSupersedeProof {
                    prior_persist_row_hash: prior.persist_row_hash,
                    change_envelope: change,
                    quorum_signatures: vec![
                        ts::threshold_sign(&h1, &bytes),
                        ts::threshold_sign(&h2, &bytes),
                    ],
                });
                d.apply_replicated_community(signed).await
            }
        };
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        d.put_community(ts::sign_community(
            &h1,
            infra_room(&room, "quorum:2/2", founders2()),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: conformant room: {e}"));
        let mut with_node = founders2();
        with_node.push(seat(&n, "founder"));
        for (what, protocol, members) in [
            ("founder_only", "founder_only", founders2()),
            ("a node founder", "quorum:3/3", with_node),
        ] {
            assert_eq!(
                offer(&room, protocol, members).await.unwrap(),
                Out::Refused {
                    reason: ReplicatedCommunityRefusal::DegradesConformance
                },
                "{tag}: {what}: a conformant room does not degrade"
            );
            assert_eq!(
                d.lookup_community(&room)
                    .await
                    .unwrap()
                    .unwrap()
                    .consensus_protocol,
                "quorum:2/2",
                "{tag}: {what}: nothing changed"
            );
        }
        let legacy = format!("legacy-{tag}");
        plant_legacy(
            d,
            ts::sign_community(&h1, infra_room(&legacy, "majority", founders2())),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: legacy room: {e}"));
        assert_eq!(
            offer(&legacy, "founder_only", founders2()).await.unwrap(),
            Out::Superseded,
            "{tag}: a legacy room still syncs"
        );
    }

    /// **#925 ask 5 — Clause A at the key-record door.** A `{node,agent}` or
    /// `{node,user}` key is refused by name and not stored; `node` beside a
    /// non-actor role stays admissible.
    pub async fn clause_a_fused_key_is_not_minted(d: &dyn FederationDirectory, tag: &str) {
        for actor in [it::AGENT, it::USER] {
            let k = format!("fused-{actor}-{tag}");
            let (ed, pq) = ts::hybrid_pubkeys(&k);
            let mut rec = fixture_record(&k, &ed, pq);
            rec.identity_type = it::join_set([it::NODE, actor]);
            let err = d
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .expect_err("Clause A");
            assert!(
                matches!(err, Error::NodeIdentityNotExclusive { .. }),
                "{actor}: refused by the Clause A error: {err}"
            );
            assert!(d.lookup_public_key(&k).await.unwrap().is_none());
        }
        register(
            d,
            &format!("node-primitive-{tag}"),
            &[it::NODE, it::PRIMITIVE],
        )
        .await;
    }

    fn fixture_record(k: &str, ed: &str, pq: Option<String>) -> crate::federation::KeyRecord {
        let now = chrono::Utc::now();
        crate::federation::KeyRecord {
            key_id: k.to_owned(),
            pubkey_ed25519_base64: ed.to_owned(),
            pubkey_ml_dsa_65_base64: pq,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: it::NODE.to_owned(),
            identity_ref: k.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": k }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: k.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: Some(
                crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(
                ),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    fn edge(granter: &str, recipient: &str, scope: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = signed_row(
            granter,
            recipient,
            attestation_type::DELEGATES_TO,
            serde_json::json!({ "id": id, "scope": [scope], "sub_delegation": true }),
        );
        ts::reseal(&mut row);
        row
    }

    /// `root → k1 → … → k{hops}`, every edge carrying `scope`. Returns the
    /// chain's keys, root first. Every key id leads with its distinguishing
    /// part: the test signers seed from a key id's FIRST 32 bytes.
    async fn chain(
        d: &dyn FederationDirectory,
        tag: &str,
        hops: usize,
        scope: &str,
    ) -> Vec<String> {
        let keys: Vec<String> = (0..=hops).map(|i| format!("k{i}-{tag}")).collect();
        register(d, &keys[0], &[it::USER]).await;
        for k in &keys[1..] {
            register(d, k, &[it::PRIMITIVE]).await;
        }
        for w in keys.windows(2) {
            d.put_attestation(SignedAttestation {
                attestation: edge(&w[0], &w[1], scope),
            })
            .await
            .unwrap_or_else(|e| panic!("{tag}: edge {} → {}: {e}", w[0], w[1]));
        }
        keys
    }

    /// **#928 — the general walk.** A 6-hop chain: at the default the graph
    /// stops at 5 hops and SAYS it stopped (`BeyondCapSelfVerify`); at an
    /// explicit `max_depth = 6` it reaches the sixth key. A 5-hop chain at the
    /// default is complete (`WithinCap`) — "too deep" is not "nothing there".
    pub async fn delegation_graph_defaults_to_five_hops(d: &dyn FederationDirectory, tag: &str) {
        let keys = chain(d, &format!("g6-{tag}"), 6, "infra:serve").await;
        let g = crate::federation::build_delegation_graph(d, &keys[0], None)
            .await
            .unwrap();
        assert_eq!(g.max_depth, DEFAULT_DELEGATION_DEPTH);
        assert!(
            !g.edges.iter().any(|e| e.to_key == keys[6]),
            "{tag}: 6th hop not at default"
        );
        assert_eq!(g.depth_outcome, DelegationDepthOutcome::BeyondCapSelfVerify);
        let g = crate::federation::build_delegation_graph(d, &keys[0], Some(6))
            .await
            .unwrap();
        assert!(
            g.edges.iter().any(|e| e.to_key == keys[6]),
            "{tag}: explicit 6 reaches it"
        );
        assert_eq!(g.depth_outcome, DelegationDepthOutcome::WithinCap);
        // The ceiling still bounds an explicit request.
        let g = crate::federation::build_delegation_graph(d, &keys[0], Some(64))
            .await
            .unwrap();
        assert_eq!(g.max_depth, crate::federation::MAX_DELEGATION_DEPTH);
        let five = chain(d, &format!("g5-{tag}"), 5, "infra:serve").await;
        let g = crate::federation::build_delegation_graph(d, &five[0], None)
            .await
            .unwrap();
        assert!(g.edges.iter().any(|e| e.to_key == five[5]));
        assert_eq!(g.depth_outcome, DelegationDepthOutcome::WithinCap);
    }

    /// **#928 — the withdraws walk.** A 6-hop `consent_revocation` chain to
    /// the target's subject: the admission gate (which runs at the default)
    /// refuses with `beyond_delegation_depth_cap: true`; the walk at an
    /// explicit 6 reaches. An issuer with no chain is refused with `false`.
    pub async fn withdraws_walk_depth_defaults_to_five_hops(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let keys = chain(
            d,
            &format!("w6-{tag}"),
            6,
            DELEGATION_SCOPE_CONSENT_REVOCATION,
        )
        .await;
        let producer = format!("producer-{tag}");
        register(d, &producer, &[it::PRIMITIVE]).await;
        let mut target = signed_row(
            &producer,
            &keys[6],
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": "x:y" }),
        );
        target.subject_key_ids = vec![keys[6].clone()];
        let subject: std::collections::HashSet<String> = std::iter::once(keys[6].clone()).collect();
        match admission::resolve_withdraws_admission_rule(d, &keys[0], &target).await {
            Err(Error::WithdrawsNotAdmitted {
                beyond_delegation_depth_cap,
                ..
            }) => assert!(
                beyond_delegation_depth_cap,
                "{tag}: the refusal says the chain is too deep"
            ),
            other => panic!("{tag}: a 6-hop proxy chain at the default: {other:?}"),
        }
        assert!(
            !admission::issuer_reaches_target_via_consent_revocation_delegation(
                d,
                &keys[0],
                &subject,
                DEFAULT_DELEGATION_DEPTH,
            )
            .await
            .unwrap()
        );
        assert!(
            admission::issuer_reaches_target_via_consent_revocation_delegation(
                d, &keys[0], &subject, 6,
            )
            .await
            .unwrap(),
            "{tag}: an explicit max_depth = 6 reaches"
        );
        let stranger = format!("stranger-{tag}");
        register(d, &stranger, &[it::USER]).await;
        match admission::resolve_withdraws_admission_rule(d, &stranger, &target).await {
            Err(Error::WithdrawsNotAdmitted {
                beyond_delegation_depth_cap,
                ..
            }) => assert!(!beyond_delegation_depth_cap, "{tag}: nothing there"),
            other => panic!("{tag}: a stranger: {other:?}"),
        }
    }

    /// **#928 review H2 (final check, V157) — a `withdraws` retires at the
    /// depth it was ADMITTED under.** A 6-hop `consent_revocation` chain to the
    /// subject of content rows binding blobs.
    ///
    /// - (A) At the default depth (5), a `withdraws` stored by the deferred arm
    ///   (its target absent at admission) does NOT retire the bytes once the
    ///   target lands: it is recorded at 5, and the chain is 6 deep.
    /// - (B) The same shape with the target present is refused at admission,
    ///   `beyond_delegation_depth_cap = true`.
    /// - (C) With the host's explicit opt-in to 6, a deferred `withdraws` over
    ///   the same chain is recorded at 6 and DOES retire.
    ///
    /// A row stored before V157 is backfilled at 16 (the migration), and a row
    /// with nothing recorded reads as 16 — `withdraws_admission_depth_is_backfilled`.
    pub async fn withdraws_retire_at_their_admission_depth(
        d: &dyn FederationDirectory,
        tag: &str,
        opt_in: &(dyn Fn(usize) + Sync),
    ) {
        use crate::federation::blob_tombstone::{binding_state, BindingState};
        use sha2::Digest as _;
        let keys = chain(
            d,
            &format!("h2-{tag}"),
            6,
            DELEGATION_SCOPE_CONSENT_REVOCATION,
        )
        .await;
        let author = format!("author-{tag}");
        register(d, &author, &[it::PRIMITIVE]).await;
        let bind = |id: &str, sha: &[u8; 32]| {
            let env = serde_json::json!({
                "id": id, "dimension": "file:doc:v1", "cohort_scope": "federation",
                "evidence_refs": [hex::encode(sha)]
            });
            let mut row = ts::bare_attestation(id, &author, &author, &env);
            row.attestation_type = attestation_type::SCORES.into();
            row.cohort_scope = "federation".into();
            row.subject_key_ids = vec![keys[6].clone()];
            ts::seal_row_in_place(&author, &mut row);
            row
        };
        let withdraws = |id: &str, target: &str| {
            let env = serde_json::json!({
                "references_attestation_id": target,
                "withdrawal_reason": "CC 2.3",
            });
            let mut w = ts::bare_attestation(id, &keys[0], &keys[0], &env);
            w.attestation_type = attestation_type::WITHDRAWS.into();
            w.cohort_scope = "federation".into();
            ts::seal_row_in_place(&keys[0], &mut w);
            w
        };
        let put = |row: Attestation| async move {
            d.put_attestation(SignedAttestation { attestation: row })
                .await
                .map(|_| ())
        };
        let uuid = || uuid::Uuid::new_v4().to_string();
        let sha = |n: &str| -> [u8; 32] { sha2::Sha256::digest(format!("{n}-{tag}")).into() };
        // (A) default depth, deferred arm.
        let (ra, wa, sha_a) = (uuid(), uuid(), sha("a"));
        put(withdraws(&wa, &ra))
            .await
            .unwrap_or_else(|e| panic!("{tag}: (A) the deferred withdraws: {e}"));
        assert_eq!(
            d.withdraws_admission_depth(&wa).await.unwrap(),
            Some(crate::federation::DEFAULT_DELEGATION_DEPTH),
            "{tag}: (A) recorded at the default"
        );
        put(bind(&ra, &sha_a))
            .await
            .unwrap_or_else(|e| panic!("{tag}: (A) the bound row: {e}"));
        assert_eq!(
            binding_state(d, &sha_a).await.unwrap(),
            BindingState::Live,
            "{tag}: (A) a 6-hop withdraws admitted at 5 does not retire by arriving first"
        );
        // (B) default depth, target present.
        let (rb, wb, sha_b) = (uuid(), uuid(), sha("b"));
        put(bind(&rb, &sha_b)).await.unwrap();
        match put(withdraws(&wb, &rb)).await {
            Err(Error::WithdrawsNotAdmitted {
                beyond_delegation_depth_cap,
                ..
            }) => assert!(beyond_delegation_depth_cap, "{tag}: (B) too deep"),
            other => panic!("{tag}: (B) a 6-hop withdraws at admission: {other:?}"),
        }
        assert_eq!(binding_state(d, &sha_b).await.unwrap(), BindingState::Live);
        // (C) the host opts in to 6.
        opt_in(6);
        let (rc, wc, sha_c) = (uuid(), uuid(), sha("c"));
        put(withdraws(&wc, &rc))
            .await
            .unwrap_or_else(|e| panic!("{tag}: (C) the deferred withdraws: {e}"));
        assert_eq!(d.withdraws_admission_depth(&wc).await.unwrap(), Some(6));
        put(bind(&rc, &sha_c)).await.unwrap();
        assert_eq!(
            binding_state(d, &sha_c).await.unwrap(),
            BindingState::Withdrawn {
                attestation_id: rc.clone(),
                withdraws_id: wc.clone(),
            },
            "{tag}: (C) admitted at 6, the 6-hop chain retires"
        );
        // (D) the PUB read form every consumer shares re-derives at the ROW's
        // depth: a legacy-depth (16) row retires, the 5-depth deferred row of
        // (A) is refused, (C)'s 6-depth row retires.
        opt_in(crate::federation::MAX_DELEGATION_DEPTH);
        let (rd, wd) = (uuid(), uuid());
        put(withdraws(&wd, &rd)).await.unwrap();
        put(bind(&rd, &sha("d"))).await.unwrap();
        let get = |id: String| async move { d.get_attestation(&id).await.unwrap().expect("held") };
        let as_admitted = |row: Attestation| async move {
            crate::federation::admission::check_withdraws_admission_as_admitted(d, &row).await
        };
        assert_eq!(d.withdraws_admission_depth(&wd).await.unwrap(), Some(16));
        assert_eq!(as_admitted(get(wd.clone()).await).await.unwrap(), Some(3));
        assert!(matches!(
            as_admitted(get(wa.clone()).await).await,
            Err(Error::WithdrawsNotAdmitted { .. })
        ));
        assert_eq!(as_admitted(get(wc.clone()).await).await.unwrap(), Some(3));
        opt_in(crate::federation::DEFAULT_DELEGATION_DEPTH);
    }

    /// A `withdraws` by a fresh issuer naming an absent target (the deferred
    /// arm): admitted, and recorded at the node's depth.
    pub async fn deferred_withdraws(d: &dyn FederationDirectory, tag: &str) -> Attestation {
        let issuer = format!("issuer-{tag}");
        register(d, &issuer, &[it::USER]).await;
        let env = serde_json::json!({
            "references_attestation_id": format!("absent-{tag}"),
            "withdrawal_reason": "CC 2.3",
        });
        let mut w = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), &issuer, &issuer, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.cohort_scope = "federation".into();
        ts::seal_row_in_place(&issuer, &mut w);
        w
    }

    /// **Final check (3d) — the local-tier door records the depth too.** A
    /// local-tier `withdraws` becomes a federation row IN PLACE at
    /// `enter_mesh`, where the bytes-plane fold sees it, so the local write
    /// records the node's depth exactly as `put_attestation` does.
    pub async fn local_withdraws_records_its_depth(d: &dyn FederationDirectory, tag: &str) {
        let issuer = format!("local-issuer-{tag}");
        register(d, &issuer, &[it::USER]).await;
        let input = crate::federation::types::LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: issuer.clone(),
            attested_key_id: None,
            attestation_type: attestation_type::WITHDRAWS.into(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "dimension": "file:doc:v1",
                    "references_attestation_id": format!("absent-{tag}"),
                    "withdrawal_reason": "CC 2.3",
                }),
            )
            .unwrap(),
            subject_key_ids: vec![],
            cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let id = d
            .attestation_insert_local(input)
            .await
            .unwrap_or_else(|e| panic!("{tag}: a local-tier withdraws: {e}"));
        assert_eq!(
            d.withdraws_admission_depth(&id).await.unwrap(),
            Some(crate::federation::DEFAULT_DELEGATION_DEPTH),
            "{tag}: the local door records the node's depth"
        );
    }

    /// **Final check — the depth is written with the row, and repaired.** The
    /// caller breaks the depth store (`break_store`), heals it (`heal_store`)
    /// and forgets one row's depth (`forget`), in its own dialect:
    /// - with the depth store broken, the put FAILS and leaves no attestation
    ///   row (one transaction);
    /// - healed, the put lands and records the default depth;
    /// - with that depth forgotten, an identical re-put is `AlreadyHeld` and
    ///   records it again (idempotent repair).
    pub async fn withdraws_depth_is_written_with_the_row<B, BF, H, HF, G, GF>(
        d: &dyn FederationDirectory,
        tag: &str,
        break_store: B,
        heal_store: H,
        forget: G,
    ) where
        B: Fn() -> BF,
        BF: std::future::Future<Output = ()>,
        H: Fn() -> HF,
        HF: std::future::Future<Output = ()>,
        G: Fn(String) -> GF,
        GF: std::future::Future<Output = ()>,
    {
        let w = deferred_withdraws(d, tag).await;
        let id = w.attestation_id.clone();
        break_store().await;
        d.put_attestation(SignedAttestation {
            attestation: w.clone(),
        })
        .await
        .expect_err("the depth write fails, so the put fails");
        assert!(
            d.get_attestation(&id).await.unwrap().is_none(),
            "{tag}: one transaction — no row without its depth"
        );
        heal_store().await;
        d.put_attestation(SignedAttestation {
            attestation: w.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("{tag}: healed, the put lands: {e}"));
        assert_eq!(
            d.withdraws_admission_depth(&id).await.unwrap(),
            Some(crate::federation::DEFAULT_DELEGATION_DEPTH)
        );
        forget(id.clone()).await;
        assert_eq!(d.withdraws_admission_depth(&id).await.unwrap(), None);
        assert_eq!(
            d.put_attestation(SignedAttestation { attestation: w })
                .await
                .unwrap(),
            crate::federation::AttestationOutcome::AlreadyHeld
        );
        assert_eq!(
            d.withdraws_admission_depth(&id).await.unwrap(),
            Some(crate::federation::DEFAULT_DELEGATION_DEPTH),
            "{tag}: an identical re-put repairs the missing depth"
        );
    }

    /// **#925 review H3 — Clause A on the doors that REWRITE a key record.**
    /// A self-signed `node` key upgraded by an owner's scrub to
    /// `{node, agent}` is refused by name (`upgrade`, the replicated `Upgrade`
    /// arm's door) and the stored set is unchanged; a supersede to a fused set
    /// (`supersede`, the replicated `Supersede` arm's door) likewise. Control:
    /// the same upgrade keeping `node` alone is adopted.
    pub async fn clause_a_on_the_rewrite_doors<U, UF, S, SF>(
        d: &dyn FederationDirectory,
        tag: &str,
        upgrade: U,
        supersede: S,
    ) where
        U: Fn(SignedKeyRecord) -> UF,
        UF: std::future::Future<
            Output = Result<crate::federation::register::AdoptScrubOutcome, Error>,
        >,
        S: Fn(SignedKeyRecord) -> SF,
        SF: std::future::Future<
            Output = Result<crate::federation::register::ReplicatedKeyOutcome, Error>,
        >,
    {
        let owner = format!("owner-{tag}");
        ts::register_hybrid_key_as(d, &owner, &owner, it::USER).await;
        let scrubbed = |k: &str, set: &str| {
            let (ed, pq) = ts::hybrid_pubkeys(k);
            let mut rec = fixture_record(k, &ed, pq);
            rec.identity_type = set.to_owned();
            rec.scrub_key_id = owner.clone();
            SignedKeyRecord { record: rec }
        };
        let fused = it::join_set([it::NODE, it::AGENT]);
        let k = format!("fusing-{tag}");
        ts::register_hybrid_key_as(d, &k, &k, it::NODE).await;
        let err = upgrade(scrubbed(&k, &fused))
            .await
            .expect_err("H3: an upgrade cannot fuse node with agent");
        assert!(
            matches!(err, Error::NodeIdentityNotExclusive { .. }),
            "{tag}: the upgrade door refuses by the Clause A error: {err}"
        );
        assert_eq!(
            d.lookup_public_key(&k)
                .await
                .unwrap()
                .unwrap()
                .identity_type,
            it::NODE,
            "{tag}: nothing stored"
        );
        let err = supersede(scrubbed(&k, &fused))
            .await
            .expect_err("H3: a supersede cannot fuse node with agent");
        assert!(
            matches!(err, Error::NodeIdentityNotExclusive { .. }),
            "{tag}: the supersede door refuses by the Clause A error: {err}"
        );
        // Review H3 (strengthened) — `node` never moves on a rewrite: adding it
        // to a non-node key, or removing it from a node key, is refused on both
        // doors and nothing is stored.
        for (name, stored, offered) in [
            ("adding", it::USER, it::NODE),
            ("removing", it::NODE, it::PRIMITIVE),
        ] {
            let k = format!("{name}-{tag}");
            ts::register_hybrid_key_as(d, &k, &k, stored).await;
            let err = upgrade(scrubbed(&k, offered))
                .await
                .expect_err("H3: an upgrade cannot move `node`");
            assert!(
                matches!(err, Error::NodeIdentityImmutable { .. }),
                "{tag}: {name} on the upgrade door: {err}"
            );
            let err = supersede(scrubbed(&k, offered))
                .await
                .expect_err("H3: a supersede cannot move `node`");
            assert!(
                matches!(err, Error::NodeIdentityImmutable { .. }),
                "{tag}: {name} on the supersede door: {err}"
            );
            assert_eq!(
                d.lookup_public_key(&k)
                    .await
                    .unwrap()
                    .unwrap()
                    .identity_type,
                stored,
                "{tag}: {name}: nothing stored"
            );
        }
        let ok = format!("keeping-{tag}");
        ts::register_hybrid_key_as(d, &ok, &ok, it::NODE).await;
        upgrade(scrubbed(&ok, it::NODE))
            .await
            .unwrap_or_else(|e| panic!("{tag}: control — a node-only upgrade adopts: {e}"));
    }

    /// **#928 — the moderation walk.** Its bound IS the CC default; a 6-hop
    /// `moderate` chain is `BeyondDepthCap` at it and `Reachable` at 6.
    pub async fn moderation_walk_depth_defaults_to_five_hops(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        assert_eq!(MAX_MODERATION_DELEGATION_DEPTH, DEFAULT_DELEGATION_DEPTH);
        let keys = chain(d, &format!("m6-{tag}"), 6, DELEGATION_SCOPE_MODERATE).await;
        let at_default = admission::reachable_under_scope_with_reasons(
            d,
            &keys[0],
            &keys[6],
            DELEGATION_SCOPE_MODERATE,
            MAX_MODERATION_DELEGATION_DEPTH,
        )
        .await
        .unwrap();
        assert_eq!(at_default, ReachabilityVerdict::BeyondDepthCap, "{tag}");
        let at_six = admission::reachable_under_scope_with_reasons(
            d,
            &keys[0],
            &keys[6],
            DELEGATION_SCOPE_MODERATE,
            6,
        )
        .await
        .unwrap();
        assert_eq!(at_six, ReachabilityVerdict::Reachable, "{tag}");
        // Within the cap and unreached is still SignerUnreached.
        let other = format!("elsewhere-{tag}");
        register(d, &other, &[it::PRIMITIVE]).await;
        let short = chain(d, &format!("m2-{tag}"), 2, DELEGATION_SCOPE_MODERATE).await;
        assert_eq!(
            admission::reachable_under_scope_with_reasons(
                d,
                &short[0],
                &other,
                DELEGATION_SCOPE_MODERATE,
                MAX_MODERATION_DELEGATION_DEPTH,
            )
            .await
            .unwrap(),
            ReachabilityVerdict::SignerUnreached
        );
    }

    // ─── PR #921 review (Codex) — F2, F3, F4 ────────────────────────────

    /// A replicated supersede of `room` to `(protocol, members)`, carrying a
    /// valid proof both founders signed over the change. Built BEFORE any
    /// fault is armed: the envelope build reads the roster planes too.
    async fn founders_supersede_offer(
        d: &dyn FederationDirectory,
        room: &str,
        protocol: &str,
        members: Vec<CommunityMember>,
        founders: [&str; 2],
    ) -> crate::federation::SignedCommunity {
        let prior = d.lookup_community(room).await.unwrap().expect("stored");
        let keys: Vec<String> = members.iter().map(|m| m.key_id.clone()).collect();
        let change = d
            .build_membership_change_envelope(
                crate::federation::cohort::Cohort::Community,
                room,
                &keys,
                false,
                Some(protocol),
            )
            .await
            .unwrap_or_else(|e| panic!("build change: {e}"));
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let mut signed = ts::sign_community(founders[0], infra_room(room, protocol, members));
        signed.supersede_proof = Some(crate::federation::types::GroupSupersedeProof {
            prior_persist_row_hash: prior.persist_row_hash,
            change_envelope: change,
            quorum_signatures: founders
                .iter()
                .map(|f| ts::threshold_sign(f, &bytes))
                .collect(),
        });
        signed
    }

    /// A conformant `quorum:2/2` infrastructure room of two human founders,
    /// stored through the local door. Returns `(room, h1, h2)`.
    async fn conformant_room(d: &dyn FederationDirectory, tag: &str) -> (String, String, String) {
        let [h1, h2] = ["h1", "h2"].map(|k| format!("{k}-{tag}"));
        ts::register_hybrid_key_as(d, &h1, &h1, it::USER).await;
        ts::register_hybrid_key_as(d, &h2, &h2, it::USER).await;
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        d.put_community(ts::sign_community(
            &h1,
            infra_room(
                &room,
                "quorum:2/2",
                vec![seat(&h1, "founder"), seat(&h2, "founder")],
            ),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: conformant room: {e}"));
        (room, h1, h2)
    }

    /// **PR #921 review (Codex, F2) — the gate.** The stored row's
    /// conformance is re-judged to decide "legacy or not"; a read that FAILS
    /// inside that judgement is not the row being non-conformant. Through the
    /// fault double (the gate composes through the directory it is handed):
    /// with the node-bearing read failing, the gate returns the read error,
    /// never `Ok` (the legacy pass). A room that is non-conformant by its
    /// PROTOCOL is decided before any read, so it stays legacy with the read
    /// failing.
    pub async fn f2_a_failed_read_is_not_legacy_at_the_gate(
        inner: std::sync::Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        use crate::federation::directory_double::FaultInjectingDirectory;
        const READ: &str = "list_identity_occurrences_by_occurrence_key";
        let d = inner.as_ref();
        let (room, h1, h2) = conformant_room(d, tag).await;
        let founders = || vec![seat(&h1, "founder"), seat(&h2, "founder")];
        let offered = infra_room(&room, "founder_only", founders());
        let clean = FaultInjectingDirectory::new(inner.clone());
        let e = admission::check_replicated_supersede_does_not_degrade(&clean, &offered)
            .await
            .expect_err("a conformant stored room refuses a degrading offer");
        assert_eq!(violation_rule(&e), INFRA_RULE_PROTOCOL_NOT_QUORUM, "{tag}");
        let failing = FaultInjectingDirectory::new(inner.clone()).erroring(READ);
        match admission::check_replicated_supersede_does_not_degrade(&failing, &offered).await {
            Err(Error::Backend(m)) => assert!(m.contains(READ), "{tag}: {m}"),
            other => panic!(
                "{tag}: a failed read of the stored row's founders is not legacy \
                 non-conformance — the gate must propagate it, got {other:?}"
            ),
        }
        let legacy = format!("legacy-{tag}");
        plant_legacy(
            d,
            ts::sign_community(&h1, infra_room(&legacy, "majority", founders())),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: legacy room: {e}"));
        admission::check_replicated_supersede_does_not_degrade(
            &failing,
            &infra_room(&legacy, "founder_only", founders()),
        )
        .await
        .unwrap_or_else(|e| {
            panic!("{tag}: a room non-conformant by its protocol is legacy, read or no read: {e}")
        });
    }

    /// **PR #921 review (Codex, F2) — the door.** The same, end to end, with
    /// a TRANSIENT failure: the node-bearing read fails once (inside the
    /// replicated door's re-judgement of the stored row) and succeeds after.
    /// `apply_replicated_community` must return the error — not `Superseded`
    /// — and the stored row is unchanged. Offered again with every read
    /// succeeding, it is refused `degrades_conformance`.
    pub async fn f2_b_a_transient_failure_never_degrades_at_the_door(
        d: &dyn FederationDirectory,
        tag: &str,
        fail_next_occurrence_read: &(dyn Fn(u32) + Sync),
    ) {
        use crate::federation::{ReplicatedCommunityOutcome as Out, ReplicatedCommunityRefusal};
        let (room, h1, h2) = conformant_room(d, tag).await;
        let founders = vec![seat(&h1, "founder"), seat(&h2, "founder")];
        let offer = founders_supersede_offer(d, &room, "founder_only", founders, [&h1, &h2]).await;
        fail_next_occurrence_read(1);
        let got = d.apply_replicated_community(offer.clone()).await;
        assert!(
            matches!(&got, Err(Error::Backend(m)) if m.contains("injected transient")),
            "{tag}: a transient read failure is an error, never a degrading supersede: {got:?}"
        );
        assert_eq!(
            d.lookup_community(&room)
                .await
                .unwrap()
                .unwrap()
                .consensus_protocol,
            "quorum:2/2",
            "{tag}: the stored row is unchanged"
        );
        fail_next_occurrence_read(0);
        assert_eq!(
            d.apply_replicated_community(offer).await.unwrap(),
            Out::Refused {
                reason: ReplicatedCommunityRefusal::DegradesConformance
            },
            "{tag}: with the read answering, the offer is judged"
        );
    }

    /// **PR #921 review (Codex, F3) — the outcome is what the WRITE did.** A
    /// rival apply of the same record lands after anything the caller read
    /// and before this write (the backend's test hook). The write then
    /// changes nothing, so the outcome is `Unchanged`: an insert that lost
    /// the race is not `Inserted`, a supersede that lost it is not
    /// `Superseded`.
    pub(crate) async fn f3_a_the_outcome_is_what_the_write_did(
        d: &dyn FederationDirectory,
        tag: &str,
        arm_rival: &(dyn Fn(crate::store::test_hooks::RivalPoint, crate::federation::SignedCommunity)
              + Sync),
    ) {
        use crate::federation::ReplicatedCommunityOutcome as Out;
        use crate::store::test_hooks::RivalPoint;
        let [h1, h2] = ["h1", "h2"].map(|k| format!("{k}-{tag}"));
        ts::register_hybrid_key_as(d, &h1, &h1, it::USER).await;
        ts::register_hybrid_key_as(d, &h2, &h2, it::USER).await;
        let founders = || vec![seat(&h1, "founder"), seat(&h2, "founder")];
        let room = format!("race-{tag}");
        let v1 = ts::sign_community(&h1, infra_room(&room, "majority", founders()));
        arm_rival(RivalPoint::DoorStart, v1.clone());
        assert_eq!(
            d.apply_replicated_community(v1.clone()).await.unwrap(),
            Out::Unchanged,
            "{tag}: the rival inserted it first; this write inserted nothing"
        );
        assert_eq!(
            d.apply_replicated_community(v1).await.unwrap(),
            Out::Unchanged
        );
        let v2 = founders_supersede_offer(d, &room, "founder_only", founders(), [&h1, &h2]).await;
        arm_rival(RivalPoint::DoorStart, v2.clone());
        assert_eq!(
            d.apply_replicated_community(v2.clone()).await.unwrap(),
            Out::Unchanged,
            "{tag}: the rival superseded first; this write superseded nothing"
        );
        assert_eq!(
            d.lookup_community(&room)
                .await
                .unwrap()
                .unwrap()
                .consensus_protocol,
            "founder_only"
        );
        // The rival lands INSIDE the write: after the occupied-id decision
        // said "insert" (the insert then finds the row), and after the proof
        // was admitted against the prior (the supersede's own re-check then
        // finds the offered version already held).
        let room3 = format!("inner-{tag}");
        let u1 = ts::sign_community(&h1, infra_room(&room3, "majority", founders()));
        arm_rival(RivalPoint::BeforeInsert, u1.clone());
        assert_eq!(
            d.apply_replicated_community(u1).await.unwrap(),
            Out::Unchanged,
            "{tag}: the insert lost to a rival insert of the same record"
        );
        let u2 = founders_supersede_offer(d, &room3, "founder_only", founders(), [&h1, &h2]).await;
        arm_rival(RivalPoint::BeforeSupersede, u2.clone());
        assert_eq!(
            d.apply_replicated_community(u2).await.unwrap(),
            Out::Unchanged,
            "{tag}: the supersede lost to a rival supersede of the same record"
        );
        // Without a rival, each outcome is still reported.
        let room2 = format!("solo-{tag}");
        let w1 = ts::sign_community(&h1, infra_room(&room2, "majority", founders()));
        assert_eq!(
            d.apply_replicated_community(w1).await.unwrap(),
            Out::Inserted
        );
        let w2 = founders_supersede_offer(d, &room2, "founder_only", founders(), [&h1, &h2]).await;
        assert_eq!(
            d.apply_replicated_community(w2).await.unwrap(),
            Out::Superseded
        );
    }

    /// **PR #921 review (Codex, F3) — two applies of one record, joined.**
    /// Exactly one reports the change; the other reports `Unchanged` — never
    /// two `Inserted`, never two `Superseded`. (On the memory backend the
    /// join does not interleave; `f3_a` pins the interleaving everywhere.)
    pub async fn f3_b_concurrent_applies_report_one_change(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::ReplicatedCommunityOutcome as Out;
        let [h1, h2] = ["h1", "h2"].map(|k| format!("{k}-{tag}"));
        ts::register_hybrid_key_as(d, &h1, &h1, it::USER).await;
        ts::register_hybrid_key_as(d, &h2, &h2, it::USER).await;
        let founders = || vec![seat(&h1, "founder"), seat(&h2, "founder")];
        let room = format!("join-{tag}");
        let v1 = ts::sign_community(&h1, infra_room(&room, "majority", founders()));
        let (a, b) = tokio::join!(
            d.apply_replicated_community(v1.clone()),
            d.apply_replicated_community(v1)
        );
        let mut got = vec![a.unwrap(), b.unwrap()];
        got.sort_by_key(|o| format!("{o:?}"));
        assert_eq!(got, vec![Out::Inserted, Out::Unchanged], "{tag}: insert");
        let v2 = founders_supersede_offer(d, &room, "founder_only", founders(), [&h1, &h2]).await;
        let (a, b) = tokio::join!(
            d.apply_replicated_community(v2.clone()),
            d.apply_replicated_community(v2)
        );
        let mut got = vec![a.unwrap(), b.unwrap()];
        got.sort_by_key(|o| format!("{o:?}"));
        assert_eq!(
            got,
            vec![Out::Superseded, Out::Unchanged],
            "{tag}: supersede"
        );
    }

    /// **PR #921 review (Codex, F4) — a zero cap reports what it cut.** With
    /// `max_depth = 0` (accepted: the capsule op passes it through) the walk
    /// follows nothing, and a root WITH a delegation is past the cap
    /// (`BeyondCapSelfVerify`), not complete; a root without one is
    /// `WithinCap`. The scoped walks: the moderation classifier says
    /// `BeyondDepthCap`, and the withdraws gate's refusal carries
    /// `beyond_delegation_depth_cap: true`.
    pub async fn f4_a_zero_depth_reports_the_cut(d: &dyn FederationDirectory, tag: &str) {
        let keys = chain(d, &format!("z1-{tag}"), 1, "infra:serve").await;
        let g = crate::federation::build_delegation_graph(d, &keys[0], Some(0))
            .await
            .unwrap();
        assert_eq!(g.max_depth, 0);
        assert!(g.edges.is_empty(), "{tag}: a zero cap follows nothing");
        assert_eq!(
            g.depth_outcome,
            DelegationDepthOutcome::BeyondCapSelfVerify,
            "{tag}: the root delegates — the chain is past a zero cap"
        );
        let lone = format!("lone-{tag}");
        register(d, &lone, &[it::USER]).await;
        let g = crate::federation::build_delegation_graph(d, &lone, Some(0))
            .await
            .unwrap();
        assert_eq!(g.depth_outcome, DelegationDepthOutcome::WithinCap, "{tag}");
        // The moderation classifier.
        let m = chain(d, &format!("zm-{tag}"), 1, DELEGATION_SCOPE_MODERATE).await;
        assert_eq!(
            admission::reachable_under_scope_with_reasons(
                d,
                &m[0],
                &m[1],
                DELEGATION_SCOPE_MODERATE,
                0
            )
            .await
            .unwrap(),
            ReachabilityVerdict::BeyondDepthCap,
            "{tag}: moderation at a zero cap"
        );
        assert_eq!(
            admission::reachable_under_scope_with_reasons(
                d,
                &lone,
                &m[1],
                DELEGATION_SCOPE_MODERATE,
                0
            )
            .await
            .unwrap(),
            ReachabilityVerdict::SignerUnreached,
            "{tag}: a root that delegates nothing"
        );
        // The withdraws gate's proxy walk.
        let w = chain(
            d,
            &format!("zw-{tag}"),
            1,
            DELEGATION_SCOPE_CONSENT_REVOCATION,
        )
        .await;
        let producer = format!("producer-{tag}");
        register(d, &producer, &[it::PRIMITIVE]).await;
        let mut target = signed_row(
            &producer,
            &w[1],
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": "x:y" }),
        );
        target.subject_key_ids = vec![w[1].clone()];
        match admission::resolve_withdraws_admission_rule_at(d, &w[0], &target, 0).await {
            Err(Error::WithdrawsNotAdmitted {
                beyond_delegation_depth_cap,
                ..
            }) => assert!(
                beyond_delegation_depth_cap,
                "{tag}: the refusal says the chain is past a zero cap"
            ),
            other => panic!("{tag}: a 1-hop proxy chain at depth 0: {other:?}"),
        }
        assert_eq!(
            admission::resolve_withdraws_admission_rule_at(d, &w[0], &target, 1)
                .await
                .unwrap(),
            3,
            "{tag}: at depth 1 the proxy reaches"
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
                            super::super::bodies::$name(
                                &d as &dyn FederationDirectory,
                                &format!("{}-{}", stringify!($name), suffix()),
                            )
                            .await
                        }
                    };
                }
                case!(node_key_cannot_be_infrastructure_founder);
                case!(infrastructure_protocol_must_be_quorum);
                case!(clause_a_fused_key_is_not_minted);
                case!(delegation_graph_defaults_to_five_hops);
                case!(withdraws_walk_depth_defaults_to_five_hops);
                case!(moderation_walk_depth_defaults_to_five_hops);
                case!(identity_claim_alone_is_not_node_bearing_founder);
                case!(clause_a_peer_record_is_a_local_mint);
                case!(infrastructure_founder_count_is_fixed_by_the_record);
                case!(replicated_supersede_never_degrades_a_conformant_room);
                case!(local_withdraws_records_its_depth);
                case!(clause_a_replicated_insert_admits_a_fused_key);
                // PR #921 review (Codex).
                case!(f3_b_concurrent_applies_report_one_change);
                case!(f4_a_zero_depth_reports_the_cut);
                #[tokio::test]
                async fn f2_a_failed_read_is_not_legacy_at_the_gate() {
                    let Some(d) = $fresh.await else { return };
                    let inner: std::sync::Arc<dyn FederationDirectory> = std::sync::Arc::new(d);
                    super::super::bodies::f2_a_failed_read_is_not_legacy_at_the_gate(
                        inner,
                        &format!("f2a-{}", suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn f2_b_a_transient_failure_never_degrades_at_the_door() {
                    let Some(d) = $fresh.await else { return };
                    let arm = |n: u32| {
                        d.test_hooks()
                            .fail_next("list_identity_occurrences_by_occurrence_key", n)
                    };
                    super::super::bodies::f2_b_a_transient_failure_never_degrades_at_the_door(
                        &d as &dyn FederationDirectory,
                        &format!("f2b-{}", suffix()),
                        &arm,
                    )
                    .await
                }
                #[tokio::test]
                async fn f3_a_the_outcome_is_what_the_write_did() {
                    let Some(d) = $fresh.await else { return };
                    let arm = |at, rival| d.test_hooks().arm_rival_community_write(at, rival);
                    super::super::bodies::f3_a_the_outcome_is_what_the_write_did(
                        &d as &dyn FederationDirectory,
                        &format!("f3a-{}", suffix()),
                        &arm,
                    )
                    .await
                }
            }
        };
    }

    /// Runners whose backend KNOWS its own key (`set_node_key_id`), so a
    /// record signed by anyone else is replicated data (review M6): the legacy
    /// `quorum:1/2` rooms the fold witnesses need are admitted that way.
    macro_rules! keyed_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! keyed {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            let s = suffix();
                            let host = format!("host-{s}");
                            d.set_node_key_id(host.clone());
                            super::super::bodies::$name(
                                &d as &dyn FederationDirectory,
                                &format!("{}-{}", stringify!($name), s),
                                &host,
                            )
                            .await
                        }
                    };
                }
                keyed!(node_founder_seat_does_not_vote);
                keyed!(node_bearing_is_judged_at_the_change_instant);
                keyed!(node_bearing_founder_holds_no_last_founder_power);
                keyed!(node_bearing_founder_roots_no_moderation);
                keyed!(node_bearing_founder_is_no_reverse_quorum_duty_holder);
                #[tokio::test]
                async fn withdraws_retire_at_their_admission_depth() {
                    let Some(d) = $fresh.await else { return };
                    let s = suffix();
                    d.set_node_key_id(format!("host-{s}"));
                    let opt_in = |n: usize| d.set_withdraws_delegation_depth(n);
                    super::super::bodies::withdraws_retire_at_their_admission_depth(
                        &d as &dyn FederationDirectory,
                        &format!("wd-{s}"),
                        &opt_in,
                    )
                    .await
                }
                #[tokio::test]
                async fn infrastructure_record_authored_elsewhere_is_data() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    let s = suffix();
                    // Both nodes know their own key — the production shape.
                    a.set_node_key_id(format!("host-a-{s}"));
                    b.set_node_key_id(format!("host-b-{s}"));
                    super::super::bodies::infrastructure_record_authored_elsewhere_is_data(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("m6-{s}"),
                    )
                    .await
                }
            }
        };
    }

    dyn_runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    keyed_runners!(memory_keyed, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    keyed_runners!(sqlite_keyed, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    keyed_runners!(postgres_keyed, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    /// Final check — the depth write shares the row's transaction (sqlite).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn withdraws_depth_is_written_with_the_row_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let sql = |q: &'static str| {
            let b = &b;
            async move {
                b.write(move |c| c.execute_batch(q)).await.unwrap();
            }
        };
        super::bodies::withdraws_depth_is_written_with_the_row(
            &b as &dyn crate::federation::FederationDirectory,
            &format!("wdepth-{}", suffix()),
            || sql("ALTER TABLE federation_withdraws_admission_depths RENAME TO broken_depths"),
            || sql("ALTER TABLE broken_depths RENAME TO federation_withdraws_admission_depths"),
            |id: String| {
                let b = &b;
                async move {
                    b.write(move |c| {
                        c.execute(
                            "DELETE FROM federation_withdraws_admission_depths WHERE attestation_id = ?1",
                            [id],
                        )
                    })
                    .await
                    .unwrap();
                }
            },
        )
        .await;
    }

    /// Final check — the postgres twin.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn withdraws_depth_is_written_with_the_row_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let sql = |q: &'static str| {
            let b = &b;
            async move {
                b.get_client()
                    .await
                    .unwrap()
                    .batch_execute(q)
                    .await
                    .unwrap();
            }
        };
        super::bodies::withdraws_depth_is_written_with_the_row(
            &b as &dyn crate::federation::FederationDirectory,
            &format!("wdepth-{}", suffix()),
            || {
                sql(
                    "ALTER TABLE cirislens.federation_withdraws_admission_depths \
                     RENAME TO broken_depths",
                )
            },
            || {
                sql("ALTER TABLE cirislens.broken_depths \
                     RENAME TO federation_withdraws_admission_depths")
            },
            |id: String| {
                let b = &b;
                async move {
                    b.get_client()
                        .await
                        .unwrap()
                        .execute(
                            "DELETE FROM cirislens.federation_withdraws_admission_depths \
                             WHERE attestation_id = $1",
                            &[&id],
                        )
                        .await
                        .unwrap();
                }
            },
        )
        .await;
    }

    /// Review H3 — the rewrite doors are inherent on the SQL backends.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn clause_a_on_the_rewrite_doors_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::clause_a_on_the_rewrite_doors(
            &b as &dyn crate::federation::FederationDirectory,
            &format!("clause-a-rw-{}", suffix()),
            |r| b.adopt_scrub_upgrade(r),
            |r| b.supersede_canonical_record(r),
        )
        .await;
    }

    /// Review H3 — the postgres twin.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn clause_a_on_the_rewrite_doors_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::clause_a_on_the_rewrite_doors(
            &b as &dyn crate::federation::FederationDirectory,
            &format!("clause-a-rw-{}", suffix()),
            |r| b.adopt_scrub_upgrade(r),
            |r| b.supersede_canonical_record(r),
        )
        .await;
    }

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
}
