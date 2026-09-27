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
        attestation_type, device_class, identity_type as it, Community, CommunityMember,
        CommunityMembershipWidening, IdentityOccurrence,
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

    fn violation_rule(e: &Error) -> &'static str {
        match e {
            Error::CommunityConsensusProtocolViolation { rule, .. } => rule,
            other => panic!("expected CommunityConsensusProtocolViolation, got {other}"),
        }
    }

    /// Bind `occurrence` as a trusted-local occurrence of `identity`.
    async fn occurrence_of(d: &dyn FederationDirectory, identity: &str, occurrence: &str) {
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: device_class::SERVER.into(),
            hardware_attestation: None,
            asserted_at: at("2026-01-02T00:00:00Z"),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("occurrence stored");
    }

    /// **#925 — `node_key_cannot_be_infrastructure_founder`.** Every door
    /// that can seat a founder refuses a `node`-bearing one with
    /// `hard_case:community_consensus_protocol_violation`, and stores nothing:
    /// the record door (a key whose own set holds `node`, and a key that is an
    /// occurrence of a `node` identity), the supersede door, and the widening
    /// door. The same key as `role: member` is admitted (serve, store,
    /// replicate).
    pub async fn node_key_cannot_be_infrastructure_founder(d: &dyn FederationDirectory, tag: &str) {
        let human = format!("{tag}-human");
        let install = format!("{tag}-install");
        let relay_identity = format!("{tag}-relay-id");
        let relay_occ = format!("{tag}-relay-occ");
        let late = format!("{tag}-late-install");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        ts::register_hybrid_key_as(d, &install, &install, it::NODE).await;
        ts::register_hybrid_key_as(d, &late, &late, it::NODE).await;
        ts::register_hybrid_key_as(d, &relay_identity, &relay_identity, it::NODE).await;
        // The occurrence's OWN record is not `node`: only the identity it is
        // an occurrence of is.
        ts::register_hybrid_key_as(d, &relay_occ, &relay_occ, it::PRIMITIVE).await;
        occurrence_of(d, &relay_identity, &relay_occ).await;

        // (1) the record door — the key's own set holds `node`.
        let room = format!("{tag}-root");
        authorized_room_key(d, &room).await;
        let err = d
            .put_community(ts::sign_community(
                &human,
                infra_room(
                    &room,
                    "quorum:1/2",
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

        // (1b) through the occurrence: the key's own record is `steward`, the
        // identity it is an occurrence of is `node`.
        let room_b = format!("{tag}-root-b");
        authorized_room_key(d, &room_b).await;
        let err = d
            .put_community(ts::sign_community(
                &human,
                infra_room(
                    &room_b,
                    "quorum:1/2",
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
                        "quorum:1/2",
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

    /// **#925 — the fold vector.** A room admitted BEFORE its second founder
    /// became `node`-bearing (the key is later bound as an occurrence of a
    /// `node` identity — a pre-gate row). Under `quorum:1/2` over founders
    /// `{human, node}`, a widening signed by the node alone does NOT admit —
    /// its seat is dropped, not counted — and the human's signature does.
    pub async fn node_founder_seat_does_not_vote(d: &dyn FederationDirectory, tag: &str) {
        let human = format!("{tag}-human");
        let install = format!("{tag}-install");
        let node_identity = format!("{tag}-node-id");
        let newcomer = format!("{tag}-newcomer");
        let second = format!("{tag}-second");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        ts::register_hybrid_key_as(d, &install, &install, it::PRIMITIVE).await;
        ts::register_hybrid_key_as(d, &node_identity, &node_identity, it::NODE).await;
        ts::register_hybrid_key_as(d, &newcomer, &newcomer, it::USER).await;
        ts::register_hybrid_key_as(d, &second, &second, it::USER).await;
        let room = format!("{tag}-root");
        authorized_room_key(d, &room).await;
        d.put_community(ts::sign_community(
            &human,
            infra_room(
                &room,
                "quorum:1/2",
                vec![seat(&human, "founder"), seat(&install, "founder")],
            ),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: the pre-gate room: {e}"));

        let w = |member: &str, day: &str| CommunityMembershipWidening {
            community_key_id: room.clone(),
            member_key_id: member.to_owned(),
            joined_at: at(day),
            effective_at: at(day),
            role: Some("member".into()),
            persist_row_hash: String::new(),
        };
        // Control: before the install is node-bearing, its scrub is a founder's.
        d.put_community_membership_widening(ts::sign_community_membership_widening(
            &install,
            w(&second, "2026-02-01T00:00:00Z"),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: control — a founder's scrub admits: {e}"));

        // Now the install becomes node-bearing.
        occurrence_of(d, &node_identity, &install).await;

        let err = d
            .put_community_membership_widening(ts::sign_community_membership_widening(
                &install,
                w(&newcomer, "2026-02-02T00:00:00Z"),
            ))
            .await
            .expect_err("#925: the node seat's scrub does not admit under quorum:1/2");
        assert!(
            matches!(err, Error::RosterAuthorityUnauthorized { .. }),
            "refused by the roster standing gate: {err}"
        );
        assert!(!d
            .active_community_members(&room)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == newcomer));
        d.put_community_membership_widening(ts::sign_community_membership_widening(
            &human,
            w(&newcomer, "2026-02-03T00:00:00Z"),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: the human founder's scrub admits: {e}"));
    }

    /// **#927 — an `infrastructure` community declares `quorum:M/N`.** Every
    /// other canonical form is refused at the record door (and at the
    /// supersede door), not floored; the same forms stay admissible for a
    /// community that is not `infrastructure`.
    pub async fn infrastructure_protocol_must_be_quorum(d: &dyn FederationDirectory, tag: &str) {
        let human = format!("{tag}-human");
        ts::register_hybrid_key_as(d, &human, &human, it::USER).await;
        for (i, p) in [
            "founder_only",
            "majority",
            "unanimous",
            "weighted:uniform_half",
            "reverse_quorum:1/1:86400",
        ]
        .iter()
        .enumerate()
        {
            let room = format!("{tag}-root-{i}");
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
        let room = format!("{tag}-root-ok");
        authorized_room_key(d, &room).await;
        d.put_community(ts::sign_community(
            &human,
            infra_room(&room, "quorum:1/1", vec![seat(&human, "founder")]),
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: quorum:1/1 is conformant: {e}"));
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

    /// **#925 ask 5 — Clause A at the key-record door.** A `{node,agent}` or
    /// `{node,user}` key is refused by name and not stored; `node` beside a
    /// non-actor role stays admissible.
    pub async fn clause_a_fused_key_is_not_minted(d: &dyn FederationDirectory, tag: &str) {
        for actor in [it::AGENT, it::USER] {
            let k = format!("{tag}-fused-{actor}");
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
            &format!("{tag}-node-primitive"),
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
    /// chain's keys, root first.
    async fn chain(
        d: &dyn FederationDirectory,
        tag: &str,
        hops: usize,
        scope: &str,
    ) -> Vec<String> {
        let keys: Vec<String> = (0..=hops).map(|i| format!("{tag}-k{i}")).collect();
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
        let keys = chain(d, &format!("{tag}-g6"), 6, "infra:serve").await;
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
        let five = chain(d, &format!("{tag}-g5"), 5, "infra:serve").await;
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
            &format!("{tag}-w6"),
            6,
            DELEGATION_SCOPE_CONSENT_REVOCATION,
        )
        .await;
        let producer = format!("{tag}-producer");
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
        let stranger = format!("{tag}-stranger");
        register(d, &stranger, &[it::USER]).await;
        match admission::resolve_withdraws_admission_rule(d, &stranger, &target).await {
            Err(Error::WithdrawsNotAdmitted {
                beyond_delegation_depth_cap,
                ..
            }) => assert!(!beyond_delegation_depth_cap, "{tag}: nothing there"),
            other => panic!("{tag}: a stranger: {other:?}"),
        }
    }

    /// **#928 — the moderation walk.** Its bound IS the CC default; a 6-hop
    /// `moderate` chain is `BeyondDepthCap` at it and `Reachable` at 6.
    pub async fn moderation_walk_depth_defaults_to_five_hops(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        assert_eq!(MAX_MODERATION_DELEGATION_DEPTH, DEFAULT_DELEGATION_DEPTH);
        let keys = chain(d, &format!("{tag}-m6"), 6, DELEGATION_SCOPE_MODERATE).await;
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
        let other = format!("{tag}-elsewhere");
        register(d, &other, &[it::PRIMITIVE]).await;
        let short = chain(d, &format!("{tag}-m2"), 2, DELEGATION_SCOPE_MODERATE).await;
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
                case!(node_founder_seat_does_not_vote);
                case!(infrastructure_protocol_must_be_quorum);
                case!(clause_a_fused_key_is_not_minted);
                case!(delegation_graph_defaults_to_five_hops);
                case!(withdraws_walk_depth_defaults_to_five_hops);
                case!(moderation_walk_depth_defaults_to_five_hops);
            }
        };
    }

    dyn_runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
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
