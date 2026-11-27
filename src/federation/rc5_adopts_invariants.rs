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
    use crate::federation::admission::steward_liveness_test_support::signed_row;
    use crate::federation::admission::{
        self, ReachabilityVerdict, DELEGATION_SCOPE_CONSENT_REVOCATION, DELEGATION_SCOPE_MODERATE,
        INFRA_RULE_PROTOCOL_NOT_QUORUM, MAX_MODERATION_DELEGATION_DEPTH,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, identity_type as it, Community, CommunityMember,
        CommunityMembershipWidening,
    };
    use crate::federation::{
        Attestation, DelegationDepthOutcome, Error, FederationDirectory, DEFAULT_DELEGATION_DEPTH,
    };

    /// v62.0.0 (JSON cut, E7) — a dimension Verify's family matcher
    /// registers (the fixtures' `x:y` is not; an edition-2 row of it is refused).
    const DIMENSION: &str = "coherence_standing:cab:v1";

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
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: room.to_owned(),
            community_name: "trust root".into(),
            members,
            founded_at: at("2026-01-01T00:00:00Z"),
            consensus_protocol: protocol.to_owned(),
            policy_blob: Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
            persist_row_hash: String::new(),
        }
    }

    /// The infrastructure room's own key, registered as `substrate_persist`
    /// (the v61 fixture shape). v62.0.0 (CC rc20 3.4.7.1, #1274): this no
    /// longer AUTHORIZES the room — the carve-out is a conformant record
    /// rooted in this node's trust set — so a witness needing an unstewarded
    /// node member steward-binds it.
    async fn authorized_room_key(d: &dyn FederationDirectory, room: &str) {
        ts::register_hybrid_key_as(d, room, room, it::SUBSTRATE_PERSIST).await;
    }

    /// v62.0.0 (JSON cut, E7; T1 v3) — a widening that LANDS: the member's
    /// proposal and acceptance as edition-2 rows, then the widening voiced by
    /// `signers` naming the room's held head.
    async fn widen_voiced(
        d: &dyn FederationDirectory,
        room: &str,
        signers: &[&str],
        member: &str,
        role: Option<&str>,
        t: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, Error> {
        use crate::federation::membership_acceptance_invariants::bodies::{proposal, put, reply};
        let p = proposal(
            signers[0],
            crate::federation::types::cohort_scope::COMMUNITY,
            room,
            member,
            role,
            t - chrono::Duration::seconds(3),
            Some(chrono::Duration::days(7)),
        );
        put(d, &p).await?;
        put(
            d,
            &reply(member, member, &p, true, t - chrono::Duration::seconds(2)),
        )
        .await?;
        let mut w = ts::sign_community_membership_widening(
            signers[0],
            CommunityMembershipWidening {
                community_key_id: room.to_owned(),
                member_key_id: member.to_owned(),
                joined_at: t,
                effective_at: t,
                role: role.map(str::to_owned),
                persist_row_hash: String::new(),
                record_row_id: None,
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_widening(&mut w, c);
        }
        let head = e2::held_head(d, &e2::kid(room)).await.map(|(h, _)| h);
        e2::put_voices(d, &e2::community_widening_voices(&w, head.as_ref())).await
    }

    /// v62.0.0 (JSON cut, E7) — a `membership:removal` of `member`, voiced by
    /// `signers`, naming the room's held head.
    async fn remove_voiced(
        d: &dyn FederationDirectory,
        room: &str,
        signers: &[&str],
        member: &str,
        t: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, Error> {
        let mut r = ts::sign_community_membership_revocation(
            signers[0],
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: room.to_owned(),
                removed_identity_key_id: member.to_owned(),
                removed_at: t,
                effective_at: t,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
                record_row_id: None,
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut r, c);
        }
        let head = e2::held_head(d, &e2::kid(room)).await.map(|(h, _)| h);
        e2::put_voices(d, &e2::community_revocation_voices(&r, head.as_ref())).await
    }

    /// A roster version v+1 of `room` naming its held head (T1 §6).
    async fn supersede_voiced(
        d: &dyn FederationDirectory,
        signed: &crate::federation::SignedCommunity,
        room: &str,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, Error> {
        let (head, version) = e2::held_head(d, &e2::kid(room))
            .await
            .expect("the room is held");
        e2::put_voices(
            d,
            &e2::community_voices(signed, version + 1, Some(&head), now_ms()),
        )
        .await
    }

    /// Now, POSIX ms (a roster version's `asserted_at`).
    fn now_ms() -> u64 {
        u64::try_from(chrono::Utc::now().timestamp_millis()).expect("after 1970")
    }

    /// v62.0.0 (JSON cut, E7; T1 §3) — found a room: its founding
    /// `group:roster` version (one voice per listed founder) through the
    /// edition-2 entry. The door's refusals are the record door's.
    async fn found(
        d: &dyn FederationDirectory,
        signed: crate::federation::SignedCommunity,
    ) -> Result<(), Error> {
        e2::put_voices(d, &e2::community_voices(&signed, 1, None, now_ms()))
            .await
            .map(|_| ())
    }

    /// v62.0.0 (round 3) — [`found`], keeping the door's outcome.
    async fn found_outcome(
        d: &dyn FederationDirectory,
        signed: crate::federation::SignedCommunity,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, Error> {
        e2::put_voices(d, &e2::community_voices(&signed, 1, None, now_ms())).await
    }

    /// v62.0.0 (round 3; CC 2.7.3, wave GC1) — the roster row is HELD: kept,
    /// concluding nothing, re-folded when the founder's key plane or the
    /// authorized roster changes. GC1 turned the node-bearing-founder and
    /// stale-N refusals into fold holds
    /// (`community_consensus_protocol_violation`); the reason tokens are a
    /// G-wave's to pin.
    fn held(r: &Result<crate::federation::edition2::ingest::StatementOutcome, Error>) -> bool {
        matches!(
            r,
            Ok(crate::federation::edition2::ingest::StatementOutcome::Pending { .. })
        )
    }

    fn violation_rule(e: &Error) -> &'static str {
        match e {
            Error::CommunityConsensusProtocolViolation { rule, .. } => rule,
            other => panic!("expected CommunityConsensusProtocolViolation, got {other}"),
        }
    }

    /// `secs` seconds ago (negative: in the future), millisecond-truncated.
    fn ago(secs: i64) -> chrono::DateTime<chrono::Utc> {
        let t = chrono::Utc::now() - chrono::Duration::seconds(secs);
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
    }

    async fn active(d: &dyn FederationDirectory, room: &str) -> Vec<String> {
        d.active_community_members(room)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect()
    }

    /// **#925 — `node_key_cannot_be_infrastructure_founder`.** Every door
    /// that can seat a founder refuses a `node`-bearing one with
    /// `hard_case:community_consensus_protocol_violation`, and stores nothing:
    /// the record door (a key whose own set holds `node`, and a key that is an
    /// occurrence of a `node` identity), the supersede door, and the widening
    /// door. The same key as `role: member` is admitted (serve, store,
    /// replicate).
    pub async fn node_key_cannot_be_infrastructure_founder(d: &dyn FederationDirectory, tag: &str) {
        // v62.0.0 (JSON cut, E7) — edition-2 keys; node-bearing per O1.api v3:
        // a key whose own record carries `node`, or a non-person key bound
        // under a node identity (the node authors, the key's own voice is its
        // agreement). Rooms, versions and widenings are voiced statements.
        let human = format!("human-{tag}");
        let install = format!("install-{tag}");
        let relay_identity = format!("relay-id-{tag}");
        let relay_occ = format!("relay-occ-{tag}");
        let late = format!("late-install-{tag}");
        e2::put_key(d, &human, &[it::USER]).await;
        e2::put_key(d, &install, &[it::NODE]).await;
        e2::put_key(d, &late, &[it::NODE]).await;
        e2::put_key(d, &relay_identity, &[it::NODE]).await;
        // The occurrence's OWN record is not `node`: only the identity it is
        // bound under is, and its own voice is its agreement.
        e2::put_key(d, &relay_occ, &[it::PRIMITIVE]).await;
        crate::federation::edition2::fixture_occurrence::put_bind(
            d,
            &relay_identity,
            &relay_identity,
            &relay_occ,
            "service",
            &crate::federation::edition2::fixture_occurrence::BindOptions::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: relay-occ bound under the node identity: {e}"));
        // The room's node members are steward-bound by the human (CC 3.2), as
        // before: a room that is not an authorized infrastructure community.
        for node in [&install, &late] {
            e2::put_signed(
                d,
                &signed_row(
                    &human,
                    &e2::kid(node),
                    attestation_type::DELEGATES_TO,
                    serde_json::json!({
                        "id": uuid::Uuid::new_v4().to_string(),
                        "scope": ["infra:serve"],
                    }),
                ),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag}: steward-bind {node}: {e}"));
        }

        // (1) the record door: the key's own set holds `node`.
        // v62.0.0 (round 6, E7) — its OWN room: a held founding is a version
        // 1 the store keeps (CC 2.7.3), so the conformant founding in (2)
        // under the same id would be a rival version 1, not a founding.
        let room_a = format!("root-a-{tag}");
        authorized_room_key(d, &room_a).await;
        let r = found_outcome(
            d,
            ts::sign_community(
                &human,
                infra_room(
                    &room_a,
                    "quorum:2/2",
                    vec![seat(&human, "founder"), seat(&install, "founder")],
                ),
            ),
        )
        .await;
        assert!(
            held(&r),
            "#925: a node key is never an infrastructure founder (held): {r:?}"
        );
        assert!(d
            .lookup_community(&e2::kid(&room_a))
            .await
            .unwrap()
            .is_none());
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;

        // (1b) through the bind: the key's own record is `primitive`, the
        // identity it is bound under is `node`.
        let room_b = format!("root-b-{tag}");
        authorized_room_key(d, &room_b).await;
        let r = found_outcome(
            d,
            ts::sign_community(
                &human,
                infra_room(
                    &room_b,
                    "quorum:2/2",
                    vec![seat(&human, "founder"), seat(&relay_occ, "founder")],
                ),
            ),
        )
        .await;
        assert!(
            held(&r),
            "#925: node-bearing through the bind (held): {r:?}"
        );
        assert!(d
            .lookup_community(&e2::kid(&room_b))
            .await
            .unwrap()
            .is_none());

        // (2) conformant: the install joins as a member.
        found(
            d,
            ts::sign_community(
                &human,
                infra_room(
                    &room,
                    "quorum:1/1",
                    vec![seat(&human, "founder"), seat(&install, "member")],
                ),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: a node key joins as member: {e}"));

        // (3) the supersede (version v+1): promoting the install to founder.
        let err = supersede_voiced(
            d,
            &ts::sign_community(
                &human,
                infra_room(
                    &room,
                    "quorum:2/2",
                    vec![seat(&human, "founder"), seat(&install, "founder")],
                ),
            ),
            &room,
        )
        .await;
        assert!(
            held(&err),
            "#925: a supersede cannot seat a node founder (held): {err:?}"
        );

        // (4) the widening: seating another node key as founder (proposal and
        // acceptance held, T1 v3); as a member it is admitted.
        let r = widen_voiced(d, &room, &[&human], &late, Some("founder"), ago(5)).await;
        assert!(
            held(&r),
            "#925: a widening cannot seat a node founder (held): {r:?}"
        );
        widen_voiced(d, &room, &[&human], &late, Some("member"), ago(4))
            .await
            .unwrap_or_else(|e| panic!("{tag}: a node key widened in as member: {e}"));
        let founders: Vec<String> = d
            .active_community_members(&e2::kid(&room))
            .await
            .unwrap()
            .into_iter()
            .filter(|m| m.role.as_deref() == Some("founder"))
            .map(|m| m.key_id)
            .collect();
        assert_eq!(founders, vec![e2::kid(&human)]);
    }

    /// **#927 — an `infrastructure` community declares `quorum:M/N`.** Every
    /// other canonical form is refused at the record door (and at the
    /// supersede door), not floored; the same forms stay admissible for a
    /// community that is not `infrastructure`.
    pub async fn infrastructure_protocol_must_be_quorum(d: &dyn FederationDirectory, tag: &str) {
        // v62.0.0 (JSON cut, E7) — edition-2 keys and `group:roster` voices
        // (T1 §3): the record door's conformance rules answer the same way,
        // and a room is keyed by its identity-ref.
        let human = format!("human-{tag}");
        e2::put_key(d, &human, &[it::USER]).await;
        for (i, p) in [
            // review M1 — `quorum:0/N` parses, and admits a change no founder
            // signed: not conformant.
            "quorum:0/1",
            "quorum:0/3",
            // review M1 — a single founder must not admit unilaterally.
            "quorum:1/2",
            "quorum:1/3",
            // v62.0.0 (TR-fix2; CC rc21 3.2 T7) — `quorum:1/N` is
            // non-conformant, 1/1 included.
            "quorum:1/1",
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
            let err = found(
                d,
                ts::sign_community(&human, infra_room(&room, p, vec![seat(&human, "founder")])),
            )
            .await
            .expect_err("#927: an infrastructure community is quorum:M/N");
            assert_eq!(
                violation_rule(&err),
                INFRA_RULE_PROTOCOL_NOT_QUORUM,
                "{p}: {err}"
            );
            assert!(
                d.lookup_community(&e2::kid(&room)).await.unwrap().is_none(),
                "{p}"
            );
            // Not infrastructure: the same protocol is admitted — except
            // `founder_only`, which v61 refuses for every community above
            // the family (CIRISPersist#1123, CC 4.5.13).
            let mut plain = infra_room(&format!("{room}-plain"), p, vec![seat(&human, "founder")]);
            plain.policy_blob = None;
            let put = found(d, ts::sign_community(&human, plain)).await;
            if *p == crate::federation::types::consensus_protocol::FOUNDER_ONLY {
                let err = put.expect_err("founder_only above the family");
                assert_eq!(
                    violation_rule(&err),
                    crate::federation::admission::FOUNDER_ONLY_ABOVE_FAMILY,
                    "{tag}: {err}"
                );
            } else {
                put.unwrap_or_else(|e| panic!("{tag}: {p} outside infrastructure: {e}"));
            }
        }
        // v62.0.0 (TR-fix2) — the conformant shape is `quorum:2/3` over three
        // founders (`root-23` below); `quorum:1/1` is refused above.
        // Review (M1 loophole) — N is the founder count: M is read absolutely,
        // so `quorum:1/1` over three founders would let one of them admit
        // alone, and `quorum:2/3` over two would demand a founder who is not
        // there.
        // v52.0.0 (#955, Q1) — founding members co-sign, so they are keys.
        for f in [format!("f2-{tag}"), format!("f3-{tag}")] {
            e2::put_key(d, &f, &[it::USER]).await;
        }
        let three = vec![
            seat(&human, "founder"),
            seat(&format!("f2-{tag}"), "founder"),
            seat(&format!("f3-{tag}"), "founder"),
        ];
        for (i, (p, founders)) in [
            ("quorum:2/2", three.clone()),
            ("quorum:2/3", three[..2].to_vec()),
        ]
        .into_iter()
        .enumerate()
        {
            let room = format!("root-n{i}-{tag}");
            authorized_room_key(d, &room).await;
            let err = found(
                d,
                ts::sign_community(&human, infra_room(&room, p, founders)),
            )
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
        found(
            d,
            ts::sign_community(&human, infra_room(&room3, "quorum:2/3", three)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: quorum:2/3 over three founders: {e}"));
        // An infrastructure community with NO founder has no admission quorum.
        let none = format!("root-none-{tag}");
        authorized_room_key(d, &none).await;
        let err = found(
            d,
            ts::sign_community(
                &human,
                infra_room(&none, "quorum:2/3", vec![seat(&human, "member")]),
            ),
        )
        .await
        .expect_err("no founder");
        assert_eq!(
            violation_rule(&err),
            crate::federation::admission::INFRA_RULE_NO_FOUNDER,
            "{err}"
        );
        // T1 §6: the supersede is version v+1 naming the held head.
        // v62.0.0 (BF17) — the conformant room is `room3` (TR-fix2 removed
        // the `quorum:1/1` room this supersede used to name).
        let (head, version) = e2::held_head(d, &e2::kid(&room3))
            .await
            .expect("the conformant room is held");
        let err = e2::put_voices(
            d,
            &e2::community_voices(
                &ts::sign_community(
                    &human,
                    infra_room(&room3, "majority", vec![seat(&human, "founder")]),
                ),
                version + 1,
                Some(&head),
                now_ms(),
            ),
        )
        .await
        .expect_err("#927: a supersede cannot lower the protocol form");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_PROTOCOL_NOT_QUORUM,
            "{err}"
        );
    }

    /// The statements of `signed` as version `version` of its room, each put
    /// as a PEER offers it: under its row id (the replicated statement door,
    /// `ingest::put_statement` with an offered id). The first refusal returns.
    async fn offer_replicated(
        d: &dyn FederationDirectory,
        signed: &crate::federation::SignedCommunity,
        version: u64,
        head: Option<&crate::federation::edition2::names::RowId>,
    ) -> Result<crate::federation::edition2::ingest::StatementOutcome, Error> {
        use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
        use crate::federation::edition2::names::RowId;
        let mut last = None;
        for v in e2::community_voices(signed, version, head, now_ms()) {
            let id = RowId::of_statement(&v)
                .expect("a roster voice names its row")
                .0;
            last = Some(put_statement(d, &v, Some(&id), INGEST_TIER).await?);
        }
        Ok(last.expect("a signed community has a voice"))
    }

    /// The protocol of the room this node holds at `room` (a seed), if any.
    async fn held_protocol(d: &dyn FederationDirectory, room: &str) -> Option<String> {
        d.lookup_community(&e2::kid(room))
            .await
            .unwrap()
            .map(|c| c.consensus_protocol)
    }

    /// **I4100–I4103 (IM-fix1; Eric's ruling 2026-11-21, CC 3.2) — an
    /// infrastructure room's `M` is the strict majority of its founder
    /// count**, at every door that judges its protocol, refused by name
    /// (`quorum_m_not_strict_majority`):
    ///
    /// - **I4100, founding.** `quorum:2/3` over three founders and
    ///   `quorum:3/5` over five land. `quorum:3/3` over three, and
    ///   `quorum:2/5` and `quorum:4/5` over five, are refused with the rule
    ///   and nothing is stored. (Before this cut each of the three was a
    ///   conformant `quorum:M/N` whose `N` is the founder count, and landed.)
    /// - **I4101, a supersede that keeps `N` and changes `M`** (`3/5` →
    ///   `4/5`, the same five founders) is refused with the rule; the held
    ///   head is unchanged.
    /// - **I4102, a supersede that changes the founder count restates both.**
    ///   Five founders become three: keeping `quorum:3/5` is refused
    ///   `quorum_n_not_founder_count`; `quorum:3/3` is refused with the rule;
    ///   `quorum:2/3`, the new strict majority, is admitted and becomes the
    ///   held protocol.
    /// - **I4103, a replicated version** (each statement offered under its
    ///   row id): a founding at `quorum:2/5` and a supersede of a held
    ///   conformant room to `quorum:4/5` are refused with the rule, and
    ///   nothing is stored or moved. Under edition 2 a replicated roster
    ///   version takes the door the local one takes.
    pub async fn infrastructure_quorum_m_is_the_strict_majority(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::{
            INFRA_RULE_QUORUM_M_NOT_STRICT_MAJORITY, INFRA_RULE_QUORUM_N_NOT_FOUNDERS,
        };
        // Seeds lead with their distinguishing part (a test signer seeds from
        // the first 32 bytes of its name).
        let f: Vec<String> = (0..5).map(|i| format!("a{i}-{tag}")).collect();
        for k in &f {
            e2::put_key(d, k, &[it::USER]).await;
        }
        let founders = |n: usize| -> Vec<CommunityMember> {
            f[..n].iter().map(|k| seat(k, "founder")).collect()
        };
        let room_of = |name: &str| format!("{name}-{tag}");
        // ── I4100: founding ───────────────────────────────────────────────
        for (name, p, n) in [("ok23", "quorum:2/3", 3), ("ok35", "quorum:3/5", 5)] {
            let room = room_of(name);
            authorized_room_key(d, &room).await;
            found(
                d,
                ts::sign_community(&f[0], infra_room(&room, p, founders(n))),
            )
            .await
            .unwrap_or_else(|e| panic!("I4100: {p} over {n} founders is conformant: {e}"));
            assert_eq!(
                held_protocol(d, &room).await.as_deref(),
                Some(p),
                "I4100: {p} over {n} founders lands"
            );
        }
        for (name, p, n) in [
            ("no33", "quorum:3/3", 3),
            ("no25", "quorum:2/5", 5),
            ("no45", "quorum:4/5", 5),
        ] {
            let room = room_of(name);
            authorized_room_key(d, &room).await;
            let err = found(
                d,
                ts::sign_community(&f[0], infra_room(&room, p, founders(n))),
            )
            .await
            .expect_err("I4100: M is the strict majority of the founder count");
            assert_eq!(
                violation_rule(&err),
                INFRA_RULE_QUORUM_M_NOT_STRICT_MAJORITY,
                "I4100: {p} over {n} founders: {err}"
            );
            let expected = crate::federation::admission::strict_majority(n);
            assert!(
                err.to_string()
                    .contains(&format!("expected M = {expected}")),
                "I4100: the refusal names the expected M: {err}"
            );
            assert_eq!(
                held_protocol(d, &room).await,
                None,
                "I4100: {p} over {n} founders: nothing is stored"
            );
        }

        // ── I4101: a supersede that keeps N and changes M ─────────────────
        let room = room_of("ok35");
        let err = supersede_voiced(
            d,
            &ts::sign_community(&f[0], infra_room(&room, "quorum:4/5", founders(5))),
            &room,
        )
        .await
        .expect_err("I4101: a supersede cannot move M off the strict majority");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_QUORUM_M_NOT_STRICT_MAJORITY,
            "I4101: {err}"
        );
        assert_eq!(
            held_protocol(d, &room).await.as_deref(),
            Some("quorum:3/5"),
            "I4101: the held head is unchanged"
        );

        // ── I4103: a replicated version ───────────────────────────────────
        // (before I4102 moves the room's head)
        let (head, version) = e2::held_head(d, &e2::kid(&room))
            .await
            .expect("I4103: the conformant room is held");
        let err = offer_replicated(
            d,
            &ts::sign_community(&f[0], infra_room(&room, "quorum:4/5", founders(5))),
            version + 1,
            Some(&head),
        )
        .await
        .expect_err("I4103: a replicated supersede off the strict majority");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_QUORUM_M_NOT_STRICT_MAJORITY,
            "I4103 supersede: {err}"
        );
        assert_eq!(
            held_protocol(d, &room).await.as_deref(),
            Some("quorum:3/5"),
            "I4103: the held head is unchanged"
        );
        let peer_room = room_of("rep25");
        authorized_room_key(d, &peer_room).await;
        let err = offer_replicated(
            d,
            &ts::sign_community(&f[0], infra_room(&peer_room, "quorum:2/5", founders(5))),
            1,
            None,
        )
        .await
        .expect_err("I4103: a replicated founding off the strict majority");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_QUORUM_M_NOT_STRICT_MAJORITY,
            "I4103 founding: {err}"
        );
        assert_eq!(
            held_protocol(d, &peer_room).await,
            None,
            "I4103: a replicated non-conformant founding is not stored"
        );

        // ── I4102: a supersede that changes the founder count ─────────────
        let err = supersede_voiced(
            d,
            &ts::sign_community(&f[0], infra_room(&room, "quorum:3/5", founders(3))),
            &room,
        )
        .await
        .expect_err("I4102: three founders under a declared N = 5");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_QUORUM_N_NOT_FOUNDERS,
            "I4102: N is restated: {err}"
        );
        let err = supersede_voiced(
            d,
            &ts::sign_community(&f[0], infra_room(&room, "quorum:3/3", founders(3))),
            &room,
        )
        .await
        .expect_err("I4102: N restated, M not the new strict majority");
        assert_eq!(
            violation_rule(&err),
            INFRA_RULE_QUORUM_M_NOT_STRICT_MAJORITY,
            "I4102: {err}"
        );
        // Three of the five founders (the prior `quorum:3/5`'s count) voice
        // the version that restates both N and M.
        supersede_voiced(
            d,
            &ts::sign_community(&f[0], infra_room(&room, "quorum:2/3", founders(3))),
            &room,
        )
        .await
        .unwrap_or_else(|e| panic!("I4102: restated at the new strict majority: {e}"));
        assert_eq!(
            held_protocol(d, &room).await.as_deref(),
            Some("quorum:2/3"),
            "I4102: the version at the new strict majority is the held head"
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
        // v62.0.0 (JSON cut, E7) — edition-2 keys; the room, its widenings and
        // its removals are voiced statements (T1 §3, v3); ids are identity-refs.
        let [h1, h2, h3, h4, m] = ["h1", "h2", "h3", "h4", "m"].map(|n| format!("{n}-{tag}"));
        for k in [&h1, &h2, &h3, &h4, &m] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        let room = format!("root-{tag}");
        authorized_room_key(d, &room).await;
        found(
            d,
            ts::sign_community(
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
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: conformant room: {e}"));
        let r = widen_voiced(d, &room, &[&h1, &h2], &h4, Some("founder"), ago(40)).await;
        assert!(
            held(&r),
            "adding a founder would leave N stale (held): {r:?}"
        );
        widen_voiced(d, &room, &[&h1, &h2], &m, Some("member"), ago(30))
            .await
            .unwrap_or_else(|e| panic!("{tag}: a plain member is admitted: {e}"));
        let r = remove_voiced(d, &room, &[&h1, &h2], &h3, ago(20)).await;
        assert!(
            held(&r),
            "other founders removing a founder would leave N stale (held): {r:?}"
        );
        remove_voiced(d, &room, &[&h3], &h3, ago(10))
            .await
            .unwrap_or_else(|e| panic!("{tag}: a founder may leave on their own signature: {e}"));
        assert!(!active(d, &e2::kid(&room)).await.contains(&e2::kid(&h3)));
    }

    /// v62.0.0 (JSON cut, E7) — `granter` is a SEED (`signed_row` signs
    /// through the earlier-form helper, which seeds from the name); the
    /// recipient is an identity-ref. The sealed row is an edition-2 statement.
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
        // v62.0.0 (JSON cut, E7) — edition-2 keys; the chain is returned as
        // identity-refs, root first. The edges are signed by the seeds.
        let seeds: Vec<String> = (0..=hops).map(|i| format!("k{i}-{tag}")).collect();
        let mut keys = vec![e2::put_key(d, &seeds[0], &[it::USER]).await];
        for k in &seeds[1..] {
            keys.push(e2::put_key(d, k, &[it::PRIMITIVE]).await);
        }
        for i in 0..hops {
            // v62.0.0 (round 6, E7) — each edge lands with the voices its
            // family names (E0's `land_delegation`: the delegate's own voice,
            // CC 2.6.1.9); short of one it is held and the walk stops there.
            let (out, missing) = e2::land_delegation(d, &edge(&seeds[i], &keys[i + 1], scope))
                .await
                .unwrap_or_else(|e| panic!("{tag}: edge {} → {}: {e}", seeds[i], seeds[i + 1]));
            assert!(
                missing.is_empty()
                    && !matches!(
                        out,
                        crate::federation::edition2::ingest::StatementOutcome::Pending { .. }
                    ),
                "{tag}: edge {} → {} lands: {out:?}, unvoiced {missing:?}",
                seeds[i],
                seeds[i + 1]
            );
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
        e2::put_key(d, &producer, &[it::PRIMITIVE]).await;
        let mut target = signed_row(
            &producer,
            &keys[6],
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": DIMENSION }),
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
        let stranger = e2::put_key(d, &format!("stranger-{tag}"), &[it::USER]).await;
        match admission::resolve_withdraws_admission_rule(d, &stranger, &target).await {
            Err(Error::WithdrawsNotAdmitted {
                beyond_delegation_depth_cap,
                ..
            }) => assert!(!beyond_delegation_depth_cap, "{tag}: nothing there"),
            other => panic!("{tag}: a stranger: {other:?}"),
        }
    }

    /// **Final check (3d) — the local-tier door records the depth too.** A
    /// local-tier `withdraws` becomes a federation row IN PLACE at
    /// `enter_mesh`, where the bytes-plane fold sees it, so the local write
    /// records the node's depth exactly as `put_attestation` does.
    pub async fn local_withdraws_records_its_depth(d: &dyn FederationDirectory, tag: &str) {
        let issuer = e2::put_key(d, &format!("local-issuer-{tag}"), &[it::USER]).await;
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
                    "dimension": "file:v1",
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
        let other = e2::put_key(d, &format!("elsewhere-{tag}"), &[it::PRIMITIVE]).await;
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
        let lone = e2::put_key(d, &format!("lone-{tag}"), &[it::USER]).await;
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
        e2::put_key(d, &producer, &[it::PRIMITIVE]).await;
        let mut target = signed_row(
            &producer,
            &w[1],
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": DIMENSION }),
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
                // v62.0.0 (JSON cut, E7) — FLIPPED bodies: no earlier-form wrap.
                macro_rules! flipped {
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
                flipped!(node_key_cannot_be_infrastructure_founder);
                flipped!(infrastructure_protocol_must_be_quorum);
                // IM-fix1 (I4100–I4103).
                flipped!(infrastructure_quorum_m_is_the_strict_majority);
                flipped!(delegation_graph_defaults_to_five_hops);
                flipped!(withdraws_walk_depth_defaults_to_five_hops);
                flipped!(moderation_walk_depth_defaults_to_five_hops);
                flipped!(clause_a_peer_record_is_a_local_mint);
                flipped!(infrastructure_founder_count_is_fixed_by_the_record);
                flipped!(local_withdraws_records_its_depth);
                // PR #921 review (Codex).
                flipped!(f4_a_zero_depth_reports_the_cut);
            }
        };
    }

    // v62.0.0 (JSON cut, E7) — the keyed runners (a backend that knows its
    // own key, for the legacy `quorum:1/2` rooms planted as replicated data)
    // are gone: every body they ran was deleted (legacy planting, reverse
    // quorum, the person-as-node-bearing premise) or now runs unkeyed.

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

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
