//! v62.0.0 slice E1 — the CC 1.0-rc20 rules persist adopts on today's
//! (earlier-form, JSON) wire, witnessed on every backend (CIRISPersist#1274).
//!
//! - **I1870** (CC 3.4.7.1 / 2.4.1.1) — the identity set rule: `node` never
//!   with `agent`, and `user` or `accord_holder` never with `node` or
//!   `agent`, refused on every key-record door, the replicated insert
//!   included.
//! - **I1871** (CC 3.4.7.1) — `substrate_persist` is a key type that confers
//!   no authority: not in the authority set, no conferral mode, asserted by a
//!   store under its own key with no ceremony; a self-claimed one opens no
//!   infrastructure carve-out (the v61.4.1 residual, flipped by item 9).
//! - **I1872 / I1873** (CC 3.3.6.2) — the X-Wing keys `transit_xwing_pubkey`
//!   and `onion_hop_xwing_pubkey`: 1216 bytes, typed accessors, and the
//!   per-half reuse refusals (`self_at_login::test_support::run_xwing_matrix`).
//! - **I1874 / I1875** — the re-bind witness and THE RULE (a seat-published
//!   X-Wing key is not live): `tests/xwing_rebind_1274.rs`.
//! - **I1878 / I1879 / I1887** (deleted v62.0.0, slice E6): the co-scrub
//!   canonical conferral and the earlier-form key-record conflict typing.
//!   Canonical standing is the `serve_nodes` of the bundle/2 in force; an
//!   edition-2 key id is its thumbprint, so a pubkey change under one id
//!   cannot be expressed.
//! - **I1880** (CC 2.4 / 2.6.1.9) — a licensure row short of its quorum
//!   authority waits (`affiliation_licence_invariants::i1214`).
//! - **I1881–I1885** (CC 3.2 / 4.4.3.4 / 6.1.8 N1 / 5.4.6) — the infrastructure
//!   carve-out is ONE predicate: a conformant infrastructure record rooted in
//!   this node's trust set. A conformant rooted community exempts its node
//!   members (I1881) and never an agent (I1882); a self-declared unrooted one
//!   gets nothing (I1883); a `founder_only` / `majority` / node-founded record
//!   is not conformant (I1884); and every treatment reads the one predicate
//!   (I1885, from disk).

/// The pure (no-backend) witnesses.
#[cfg(test)]
mod pure {
    use crate::federation::register::check_node_identity_exclusive;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type as it;
    use crate::federation::Error;

    /// **I1870 (pure)** — every pair the rule names is refused, under the token
    /// that names it, and every other pair is admitted. CC 3.4.7.1: "Two pairs
    /// MUST NOT cohabit: `node` with `agent`, and `user` or `accord_holder` with
    /// `node` or `agent`. … Cohabitation is general; those exclusions are its
    /// only exceptions."
    /// The rule's input: a record of `set` as a struct. v62.0.0: built in
    /// the earlier form on purpose (`with_earlier_form`), because the
    /// edition-2 builder admits its record and a mixed set never admits; the
    /// rule reads only `identity_type`.
    fn rule_input(set: &str) -> crate::federation::KeyRecord {
        // CP2 skeleton: a pure rule's input struct; it reaches no door.
        crate::federation::edition2::fixture_switch::with_earlier_form(|| {
            ts::replicated_key_record("i1870-k", set, "i1870-k", "i1870-k", "n")
        })
    }

    #[test]
    fn i1870_the_identity_set_rule_names_every_pair() {
        let person = [it::USER, it::ACCORD_HOLDER];
        let machine = [it::NODE, it::AGENT];
        for a in it::ALL {
            for b in it::ALL {
                if a >= b {
                    continue;
                }
                let set = it::join_set([*a, *b]);
                let rec = rule_input(&set);
                let node_case = (*a == it::NODE || *b == it::NODE)
                    && [*a, *b].iter().any(|t| *t == it::AGENT || *t == it::USER);
                let mixed = [*a, *b].iter().any(|t| person.contains(t))
                    && [*a, *b].iter().any(|t| machine.contains(t));
                match check_node_identity_exclusive(&rec) {
                    Err(Error::NodeIdentityNotExclusive { .. }) => {
                        assert!(node_case, "I1870: {set} is not the node case");
                    }
                    Err(Error::IdentitySetMixesPersonAndMachine { .. }) => {
                        assert!(
                            mixed && !node_case,
                            "I1870: {set} is not a person+machine set"
                        );
                    }
                    Ok(()) => assert!(
                        !node_case && !mixed,
                        "I1870: {set} must be refused (CC 3.4.7.1)"
                    ),
                    Err(e) => panic!("I1870: {set}: unexpected {e}"),
                }
            }
        }
        // The three sets v62 newly refuses, named.
        for set in [
            it::join_set([it::USER, it::AGENT]),
            it::join_set([it::ACCORD_HOLDER, it::NODE]),
            it::join_set([it::ACCORD_HOLDER, it::AGENT]),
        ] {
            let rec = rule_input(&set);
            let err = check_node_identity_exclusive(&rec).expect_err("refused");
            assert_eq!(
                err.kind(),
                "federation_identity_set_mixes_person_and_machine",
                "I1870: {set}"
            );
        }
    }
}

/// **I1885** (from disk) — every infrastructure treatment reads the ONE
/// predicate, and no reader keys the carve-out on `substrate_persist`.
#[cfg(test)]
mod from_disk_1885 {
    fn strip_comments(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn i1885_every_treatment_reads_the_one_predicate() {
        let root = env!("CARGO_MANIFEST_DIR");
        for (file, what) in [
            ("src/federation/community_dek.rs", "the DEK skip"),
            ("src/federation/at_rest_cascade.rs", "the at-rest cascade"),
            (
                "src/federation/replication_audience.rs",
                "the Commons audience",
            ),
        ] {
            let src = strip_comments(&std::fs::read_to_string(format!("{root}/{file}")).unwrap());
            assert!(
                src.contains("is_authorized_infrastructure_community("),
                "I1885: {what} ({file}) reads the one predicate"
            );
        }
        let adm = strip_comments(
            &std::fs::read_to_string(format!("{root}/src/federation/admission.rs")).unwrap(),
        );
        let body = &adm[adm
            .find("pub async fn is_authorized_infrastructure_community<F>(")
            .unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(
            !body.contains("SUBSTRATE_PERSIST"),
            "I1885: the carve-out reads no key type (CC 3.4.7.1)"
        );
        assert!(
            body.contains("is_conformant_infrastructure_record")
                && body.contains("infrastructure_rooted_here"),
            "I1885: the predicate is (i) AND (ii)"
        );
    }
}

/// The pure half of I1871.
#[cfg(test)]
mod pure_1871 {
    use crate::federation::types::identity_type as it;

    /// **I1871 (pure)** — CC 3.4.7.1: "`substrate_persist` is a key type that
    /// confers no authority. A store asserts it under its own key, and no
    /// ceremony or co-scrub confers it."
    #[test]
    fn i1871_substrate_persist_is_no_authority_claim() {
        assert!(
            !it::AUTHORITY_CONFERRING_IDENTITY_TYPES.contains(&it::SUBSTRATE_PERSIST),
            "I1871: substrate_persist is not authority-conferring"
        );
        assert_eq!(
            it::conferral_mode(it::SUBSTRATE_PERSIST),
            None,
            "I1871: no ceremony confers it"
        );
        assert_eq!(it::SELF_REPORT_IDENTITY_TYPES, [it::SUBSTRATE_PERSIST]);
        // The families reserved to it are self-reports only.
        for rule in crate::federation::admission::default_reserved_prefix_rules() {
            if rule
                .required_identity_types
                .iter()
                .any(|t| t == it::SUBSTRATE_PERSIST)
            {
                assert!(
                    crate::federation::admission::SUBSTRATE_SELF_REPORT_PREFIXES
                        .contains(&rule.pattern_prefix.as_str()),
                    "I1871: {} keyed on substrate_persist is not a self-report family",
                    rule.pattern_prefix
                );
            }
        }
    }
}

/// The backend-agnostic witness bodies; `runners` instantiates them.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::canonical_community_invariants::bodies::{
        rooted_infrastructure_room_e2, SetNodeKey,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::types::identity_type as it;
    use crate::federation::{Error, FederationDirectory};

    /// **I1881** — a CONFORMANT, ROOTED infrastructure community (the CC 3.2
    /// worked example: `quorum:2/3`, three human founders, rooted in this
    /// node's trust set) is authorized: its node member needs no steward
    /// binding, and it needs no moderator. CC 3.2: "With no owner, a key MAY
    /// trust and serve `infrastructure` communities and does nothing more."
    ///
    /// v62.0.0 (wave 4, slice E6) — the room is E5's
    /// `rooted_infrastructure_room_e2` (T1 voices, W1's rooted root), no
    /// longer the earlier canonical trust-root community (lead ruling 1).
    /// Green once W1's `infrastructure_rooted_here` fix lands (E5).
    pub(crate) async fn i1881_a_conformant_rooted_community_is_authorized<B>(
        b: &B,
        tag: &str,
    ) -> String
    where
        B: FederationDirectory
            + crate::federation::attestation_query::AttestationQueryExec
            + SetNodeKey
            + Sync,
    {
        let d: &dyn FederationDirectory = b;
        let node = format!("i1881-node-{tag}");
        e2::put_key(d, &node, &[it::NODE]).await;
        let room =
            rooted_infrastructure_room_e2(b, &format!("i1881-room-{tag}"), &[&node], tag).await;
        let row = d
            .lookup_community(&room)
            .await
            .unwrap()
            .expect("I1881: the rooted infrastructure room is held");
        assert!(
            crate::federation::canonical_community::is_rooted(d, &room)
                .await
                .unwrap(),
            "I1881: rooted"
        );
        assert!(
            crate::federation::admission::is_conformant_infrastructure_record(d, &row)
                .await
                .unwrap(),
            "I1881: conformant"
        );
        assert!(
            crate::federation::admission::is_authorized_infrastructure_community(d, &row)
                .await
                .unwrap(),
            "I1881: conformant AND rooted here ⇒ authorized"
        );
        crate::federation::admission::check_community_membership_steward_binding(d, &row)
            .await
            .expect("I1881: an unstewarded NODE member is exempt");
        crate::federation::admission::check_no_moderator_federate_admission(d, &row)
            .await
            .expect("I1881: an authorized infrastructure community needs no moderator");
        room
    }

    /// **I1882** — an AGENT member of the same rooted infrastructure
    /// community, with no live steward binding, is refused. Agents are never
    /// exempt (CC 3.2: "Authority MUST root in an accountable human, never in a
    /// bare node").
    pub(crate) async fn i1882_an_agent_is_never_exempt<B>(b: &B, tag: &str)
    where
        B: FederationDirectory
            + crate::federation::attestation_query::AttestationQueryExec
            + SetNodeKey
            + Sync,
    {
        let d: &dyn FederationDirectory = b;
        let room = i1881_a_conformant_rooted_community_is_authorized(b, tag).await;
        // v62.0.0 — an edition-2 agent key (`key:record` through the door).
        let agent = e2::put_key(d, &format!("i1882-agent-{tag}"), &[it::AGENT]).await;
        let mut row = d
            .lookup_community(&room)
            .await
            .unwrap()
            .expect("I1882: the room is held");
        row.members.push(crate::federation::types::CommunityMember {
            key_id: agent.clone(),
            joined_at: row.founded_at,
            role: Some("member".to_owned()),
        });
        match crate::federation::admission::check_community_membership_steward_binding(d, &row)
            .await
        {
            Err(Error::UnstewardedCommunityMember {
                member_key_id,
                member_role,
                ..
            }) => {
                assert_eq!(member_key_id, agent, "I1882 (the agent's kid)");
                assert_eq!(member_role, it::AGENT, "I1882");
            }
            other => panic!("I1882: an unstewarded agent must be refused, got {other:?}"),
        }
    }

    /// The self-declared shape: labelled `infrastructure`, a `quorum:1/1` with
    /// a human founder, its own key a SELF-CLAIMED `substrate_persist`, a node
    /// member with no steward; never stored as a trust-root row.
    async fn self_declared(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> crate::federation::types::Community {
        // v62.0.0 — edition-2 keys: each is the kid of its seed.
        let room = e2::put_key(d, &format!("i1883-room-{tag}"), &[it::SUBSTRATE_PERSIST]).await;
        let founder = e2::put_key(d, &format!("i1883-founder-{tag}"), &[it::USER]).await;
        let node = e2::put_key(d, &format!("i1883-node-{tag}"), &[it::NODE]).await;
        let at: chrono::DateTime<chrono::Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        crate::federation::types::Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: room,
            community_name: "self-declared".into(),
            members: vec![
                crate::federation::types::CommunityMember {
                    key_id: founder,
                    joined_at: at,
                    role: Some("founder".to_owned()),
                },
                crate::federation::types::CommunityMember {
                    key_id: node,
                    joined_at: at,
                    role: Some("member".to_owned()),
                },
            ],
            founded_at: at,
            consensus_protocol: "quorum:1/1".to_owned(),
            policy_blob: Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
            persist_row_hash: String::new(),
        }
    }

    /// **I1883** — a SELF-DECLARED, UNROOTED infrastructure community gets
    /// none of the treatments: not authorized (so no moderator exemption
    /// either: the gate then asks for a steward-bound authority, which its
    /// human founder is); its unstewarded node member is refused. (The DEK skip,
    /// the at-rest cascade and the Commons audience read the same predicate,
    /// I1885.) The record is conformant in shape, so the refusal is (ii)'s.
    pub(crate) async fn i1883_a_self_declared_community_gets_nothing(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let row = self_declared(d, tag).await;
        assert!(
            crate::federation::admission::is_conformant_infrastructure_record(d, &row)
                .await
                .unwrap(),
            "I1883: conformant in shape (so (ii) is what refuses)"
        );
        assert!(
            !crate::federation::admission::is_authorized_infrastructure_community(d, &row)
                .await
                .unwrap(),
            "I1883: unrooted ⇒ not authorized, whatever its key claims"
        );
        assert!(
            matches!(
                crate::federation::admission::check_community_membership_steward_binding(d, &row)
                    .await,
                Err(Error::UnstewardedCommunityMember { .. })
            ),
            "I1883: its node member needs a steward binding"
        );
    }

    /// **I1884** — conformance (i): a `founder_only`, `unanimous`, bare
    /// `majority` or malformed protocol is not a conformant infrastructure
    /// record, nor is one whose founder is node- or agent-bearing, nor one
    /// with no founder (CC 3.2 "Infrastructure does not vote").
    pub(crate) async fn i1884_conformance_is_the_record(d: &dyn FederationDirectory, tag: &str) {
        let base = self_declared(d, tag).await;
        let conformant = |c: crate::federation::types::Community| async move {
            crate::federation::admission::is_conformant_infrastructure_record(d, &c)
                .await
                .unwrap()
        };
        assert!(conformant(base.clone()).await, "I1884: the control");
        for p in [
            "founder_only",
            "unanimous",
            "majority",
            "quorum:0/1",
            "quorum:2/1",
            "quorum:x",
        ] {
            let mut c = base.clone();
            c.consensus_protocol = p.to_owned();
            assert!(!conformant(c).await, "I1884: {p} is not conformant");
        }
        for (n, t) in [it::NODE, it::AGENT].into_iter().enumerate() {
            let k = e2::put_key(d, &format!("i1884-founder-{n}-{tag}"), &[t]).await;
            let mut c = base.clone();
            c.members[0].key_id = k;
            assert!(
                !conformant(c).await,
                "I1884: a {t} founder is not conformant"
            );
        }
        let mut c = base.clone();
        c.members[0].role = Some("member".to_owned());
        assert!(!conformant(c).await, "I1884: no founder");
        let mut c = base;
        c.policy_blob = Some(serde_json::json!({ "cohort_subkind": "community" }));
        assert!(!conformant(c).await, "I1884: not labelled infrastructure");
    }

    /// **I1871** — a `substrate_persist` key is asserted by a store under its
    /// own key: a self-signed registration is admitted with no co-scrub, and
    /// it carries no conferral (it is not canonical, and the privileged-type
    /// gate has nothing to demand of it).
    ///
    /// **The residual leg, flipped.** Until item 9 this leg pinned the v61.4.1
    /// behaviour (a self-claimed `substrate_persist` community key opened the
    /// infrastructure carve-out). v62 closes it: the leg now asserts NO
    /// carve-out.
    pub(crate) async fn i1871_substrate_persist_confers_nothing(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // v62.0.0 — the store's self-signed `key:record` (edition 2): its
        // own key signs it, no co-signer.
        let seed = format!("i1871-store-{tag}");
        let rec = e2::key_row(&seed, &[it::SUBSTRATE_PERSIST]);
        crate::federation::admission::check_privileged_identity_type_admission(d, &rec)
            .await
            .expect("I1871: the privileged-type gate demands nothing of it");
        e2::put_statement(d, &e2::key_record(&seed, &[it::SUBSTRATE_PERSIST]))
            .await
            .expect("I1871: a store asserts it under its own key, no ceremony");
        let k = e2::kid(&seed);
        assert!(
            !crate::federation::is_canonical(d, &k).await.unwrap(),
            "I1871: it carries no conferral"
        );
        // v62.0.0 — the v61 residual, FLIPPED on purpose (item 9): a
        // self-claimed `substrate_persist` community key opens no carve-out.
        // The pre-v62 leg pinned the opposite (a self-grantable carve-out).
        let room = crate::federation::types::Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: k.clone(),
            community_name: "self-claimed".into(),
            members: vec![],
            founded_at: "2026-01-01T00:00:00Z".parse().unwrap(),
            consensus_protocol: "quorum:1/1".to_owned(),
            policy_blob: Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
            persist_row_hash: String::new(),
        };
        assert!(
            !crate::federation::admission::is_authorized_infrastructure_community(d, &room)
                .await
                .unwrap(),
            "I1871: a self-claimed substrate_persist key grants no infrastructure carve-out \
             (CC 3.4.7.1: nothing is admitted on its strength)"
        );
    }

    /// **I1870** — the identity set rule at the key-plane door (CC 3.4.7.1,
    /// CC 2.4.1.1: "A set that holds `user` or `accord_holder` together with
    /// `node` or `agent` is malformed and refused"). v62.0.0: a key is its
    /// `key:record` statement, and the replicated apply is the local door
    /// (`edition2::ingest::apply_replicated_statement` runs `put_statement`
    /// under the offered id), so a mixed set is refused at `put_statement`
    /// and nothing is projected; a single-role key passes both doors. (The
    /// replicated leg of a mixed set is not offered: its offered id cannot be
    /// computed without admitting the record, and an arbitrary id would be
    /// refused `row_id_mismatch`, a leg that could not fail.)
    pub(crate) async fn i1870_the_identity_set_rule_holds_on_every_door(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::edition2::ingest::{
            apply_replicated_statement, ReplicatedStatementOutcome,
        };
        // DEPENDS ON THE CUT-A IDENTITY-SET FIX: the `node+agent` case is red
        // until `put_statement`'s `key:record` arm runs persist's `node` rule
        // (Verify refuses only a person+machine mix).
        // (what, the set, does persist's `node` rule name it)
        let cases: [(&str, [&str; 2], bool); 5] = [
            ("node+agent", [it::NODE, it::AGENT], true),
            ("node+user", [it::NODE, it::USER], true),
            ("user+agent", [it::USER, it::AGENT], false),
            ("accord_holder+node", [it::ACCORD_HOLDER, it::NODE], false),
            ("accord_holder+agent", [it::ACCORD_HOLDER, it::AGENT], false),
        ];
        let refused_under_its_token = |err: &Error, node_rule: bool| match err {
            // Verify's end rule refuses a person+machine set first
            // (`key_record_mixed_roles`), `node+user` included.
            Error::IdentitySetMixesPersonAndMachine { .. } => true,
            // `node+agent` is no person+machine mix: only persist's `node`
            // rule refuses it.
            Error::NodeIdentityNotExclusive { .. } => node_rule,
            _ => false,
        };
        for (n, (what, set, node_rule)) in cases.into_iter().enumerate() {
            let local = format!("i1870-local-{n}-{tag}");
            let err = e2::put_statement(d, &e2::key_record(&local, &set))
                .await
                .expect_err("I1870: a local mint of a mixed set is refused");
            assert!(
                refused_under_its_token(&err, node_rule),
                "I1870 {what}: local mint refused under its token, got {err}"
            );
            assert!(
                d.lookup_public_key(&e2::kid(&local))
                    .await
                    .unwrap()
                    .is_none(),
                "I1870 {what}: nothing projected locally"
            );
        }
        // The controls: a single role passes both doors.
        for (n, role) in [it::USER, it::AGENT, it::NODE].into_iter().enumerate() {
            let local = e2::put_key(d, &format!("i1870-ok-local-{n}-{tag}"), &[role]).await;
            assert!(
                d.lookup_public_key(&local).await.unwrap().is_some(),
                "I1870 control {role}: admitted locally"
            );
            let st = e2::key_record(&format!("i1870-ok-remote-{n}-{tag}"), &[role]);
            let offered = e2::admit(&st).row_id.0;
            assert!(
                matches!(
                    apply_replicated_statement(d, &st, &offered).await,
                    Ok(ReplicatedStatementOutcome::Admitted(_))
                ),
                "I1870 control {role}: admitted from the replicated door"
            );
        }
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
                case!(i1870_the_identity_set_rule_holds_on_every_door);
                case!(i1871_substrate_persist_confers_nothing);
                case!(i1883_a_self_declared_community_gets_nothing);
                case!(i1884_conformance_is_the_record);
                #[tokio::test]
                async fn i1881_a_conformant_rooted_community_is_authorized() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1881_a_conformant_rooted_community_is_authorized(
                        &d,
                        &suffix(),
                    )
                    .await;
                }
                #[tokio::test]
                async fn i1882_an_agent_is_never_exempt() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1882_an_agent_is_never_exempt(&d, &suffix()).await
                }
                #[tokio::test]
                async fn i1872_i1873_xwing_matrix() {
                    let Some(d) = $fresh.await else { return };
                    crate::federation::self_at_login::test_support::run_xwing_matrix(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
            }
        };
    }

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
