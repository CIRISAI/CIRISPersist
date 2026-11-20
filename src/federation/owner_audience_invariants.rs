//! v62.0.0 (v62 P5c; CC rc21 3.3.6, CC 3.2, CC 3.3.7 / 6.1.5.3) —
//! **I3118–I3121: a node's human is its OWNER.** A machine key (`node` /
//! `agent`) is never an occurrence of a person, so every "whose device is
//! this" read takes the owner binding. sqlite and postgres.
//!
//! - **I3118** — a person's PHONE node: owned by a live owner binding (the
//!   node's own voice on it: WHO), and holding its own self-occurrence (its
//!   key under its own node identity) that says `device_class: phone` (WHAT
//!   KIND). It is in the person's `self` audience: `devices_of`,
//!   `owner_node_receives`, `audience_nodes`, `owner_nodes_receiving`,
//!   `principals_of` and `human_of` all name it, with no occurrence of the
//!   person anywhere.
//! - **I3119** — a node with no self-occurrence, or one whose self-occurrence
//!   has ended, is SERVER class (fail-closed): it is the owner's device
//!   (`owner_node_class`), it receives a community the owner is in by default,
//!   and it gets no `self` content.
//! - **I3120** — nothing is derived from a forbidden occurrence: with the
//!   earlier form shut, a held row binding a NODE key under the person (an
//!   upgraded store's; the door refuses a new one) makes that node no device
//!   of the person on any read, and gives it no human.
//! - **I3121** — an agent's human is its owner, by the agent's owner binding
//!   (`human_of` / `principals_of`), and an OWNED agent is its own class
//!   (`OwnedAgent`, whatever its self-occurrence says) within its owner's
//!   `self` for delivery: it receives the owner's `self` content, the rooms
//!   as any member node, and no `family` unless listed. An agent the owner
//!   does not own (unowned, or another person's) never receives it; one the
//!   owner's allow list excludes does not either.
//! - **I3123** — the literal `"self"` cohorts entry, ONE rule for every
//!   class (CC rc21 6.1 / 3.3.7): a SERVER-class node whose owner's list is
//!   `["self"]` receives `self`; an owned agent with `["fam1"]` receives no
//!   `self` and `fam1`; one with `[fam1, "self"]` receives both. A `self` row
//!   the node authored, or one about the node, reaches it whatever its list
//!   says (`may_receive`'s origin and refers-to arms).
//! - **I3122** — the DEVICE door (`rekey_community_member_device_add`) treats
//!   a node the member OWNS as their device once the earlier form is shut:
//!   with no `(person, node)` occurrence (forbidden), rule 3
//!   (`device_rekey_not_an_occurrence`) no longer refuses the owned node and
//!   the door goes on to its next rule; while the earlier form is open, the
//!   earlier rule still refuses it by name.
//!
//! Mutations: drop the owned half of `devices_of` / `OwnerAudience` and
//! I3118 reds; read the class from anything but the live self-occurrence
//! (or default it to `phone`) and I3118 / I3119 red; drop the
//! `occurrence_counts` filter from `active_identities_for_occurrence` (or
//! from `counted_occurrences`) and I3120 reds; drop the owner fallback from
//! `self_collective::human_of` and I3118 / I3121 red; make
//! `at_rest_cascade::orchestrate::is_member_device` ignore the switch either
//! way and one leg of I3122 reds.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::replication_audience::{
        audience_nodes, devices_of, occurrence_counts, owner_node_class, owner_node_receives,
        owner_nodes_receiving, NodeClass, OwnerCohort,
    };
    use crate::federation::self_collective::{human_of, principals_of};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{cohort_scope, device_class, identity_type, Attestation};
    use crate::federation::FederationDirectory;

    fn now_ms() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis() - 60_000,
        )
        .expect("ms")
    }

    /// `owner_seed` owns `machine_seed` by a live owner binding, the
    /// machine's own voice on it (C557): WHO the machine's human is. Returns
    /// the stored binding.
    async fn own(d: &dyn FederationDirectory, owner_seed: &str, machine_seed: &str) -> Attestation {
        let mut b = ts::owner_binding_attestation(
            &uuid::Uuid::new_v4().to_string(),
            owner_seed,
            &e2::kid(machine_seed),
        );
        let at = now_ms();
        b.asserted_at = at;
        b.scrub_timestamp = at;
        ts::reseal(&mut b);
        e2::put_signed(d, &b)
            .await
            .expect("the owner's binding is admitted");
        let st = e2::carried_statement(&b).expect("a flipped binding carries its statement");
        e2::put_statement(d, &e2::voice_of(&st, machine_seed))
            .await
            .expect("the machine's voice on its owner binding is admitted");
        b
    }

    /// `machine`'s own SELF-occurrence (its key under its own identity, a
    /// machine under a machine, which CC rc21 allows): WHAT KIND of device it
    /// is. `valid_until` ends it.
    async fn self_occurrence(
        d: &dyn FederationDirectory,
        machine: &str,
        class: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), crate::federation::Error> {
        d.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
            identity_key_id: machine.to_owned(),
            occurrence_key_id: machine.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: now_ms() - chrono::Duration::minutes(5),
            valid_until,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
    }

    async fn owner_of(d: &dyn FederationDirectory, k: &str) -> Option<String> {
        crate::federation::admission::owner_of(d, k)
            .await
            .expect("owner_of")
    }

    /// **I3118** — the owned node is the person's device by its binding.
    pub async fn i3118_an_owned_node_is_in_its_owners_audience(d: &dyn FederationDirectory) {
        let alice = e2::put_key(d, "i3118-alice", &[identity_type::USER]).await;
        let node = e2::put_key(d, "i3118-node", &[identity_type::NODE]).await;
        own(d, "i3118-alice", "i3118-node").await;
        self_occurrence(d, &node, device_class::PHONE, None)
            .await
            .expect("I3118: the node's own self-occurrence is admitted");
        assert_eq!(
            owner_of(d, &node).await,
            Some(alice.clone()),
            "I3118: fixture"
        );
        assert!(
            d.list_identity_occurrences_for(&alice)
                .await
                .unwrap()
                .iter()
                .all(|o| o.occurrence_key_id != node),
            "I3118: no occurrence of the person names the node"
        );

        let devices = devices_of(d, &alice).await.unwrap();
        let rec = devices
            .iter()
            .find(|o| o.occurrence_key_id == node)
            .expect("I3118: the owned node is one of the owner's devices");
        assert_eq!(rec.identity_key_id, alice, "I3118");
        assert_eq!(
            rec.device_class,
            device_class::PHONE,
            "I3118: the class is the node's own self-occurrence's"
        );
        assert_eq!(
            owner_node_class(d, &alice, &node).await.unwrap(),
            Some(NodeClass::Personal),
            "I3118"
        );
        assert!(
            owner_node_receives(d, &alice, &node, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3118: the owner's self content reaches it"
        );
        assert!(
            audience_nodes(d, cohort_scope::SELF, Some(&alice))
                .await
                .unwrap()
                .contains(&node),
            "I3118: in the self audience"
        );
        assert_eq!(
            owner_nodes_receiving(d, &alice, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            vec![node.clone()],
            "I3118"
        );
        assert!(
            principals_of(d, &node).await.unwrap().contains(&alice),
            "I3118: the owner is the node's principal"
        );
        assert_eq!(
            human_of(d, &node).await.unwrap(),
            Some(alice.clone()),
            "I3118: the node's human"
        );
    }

    /// **I3119** — no stated class is server class.
    pub async fn i3119_an_unstated_class_is_server(d: &dyn FederationDirectory) {
        let alice = e2::put_key(d, "i3119-alice", &[identity_type::USER]).await;
        let node = e2::put_key(d, "i3119-node", &[identity_type::NODE]).await;
        own(d, "i3119-alice", "i3119-node").await;
        assert_eq!(
            owner_node_class(d, &alice, &node).await.unwrap(),
            Some(NodeClass::Server),
            "I3119: the owner's device, server class"
        );
        assert!(
            !owner_node_receives(d, &alice, &node, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3119: no self content on a server-class node"
        );
        assert!(
            owner_node_receives(
                d,
                &alice,
                &node,
                OwnerCohort::Group {
                    scope: cohort_scope::COMMUNITY,
                    target: "i3119-room",
                },
            )
            .await
            .unwrap(),
            "I3119: a server-class node receives its owner's rooms by default"
        );
        assert!(
            !audience_nodes(d, cohort_scope::SELF, Some(&alice))
                .await
                .unwrap()
                .contains(&node),
            "I3119"
        );

        // A self-occurrence that has ENDED says nothing: still server.
        let ended = e2::put_key(d, "i3119-ended", &[identity_type::NODE]).await;
        own(d, "i3119-alice", "i3119-ended").await;
        // (A door that refuses an already-ended row leaves none: the same.)
        let _ = self_occurrence(
            d,
            &ended,
            device_class::PHONE,
            Some(now_ms() - chrono::Duration::minutes(1)),
        )
        .await;
        assert_eq!(
            owner_node_class(d, &alice, &ended).await.unwrap(),
            Some(NodeClass::Server),
            "I3119: only a LIVE self-occurrence states the class"
        );
        assert!(
            !owner_node_receives(d, &alice, &ended, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3119"
        );
    }

    /// **I3120** — a forbidden occurrence derives nothing once the earlier
    /// form is shut.
    pub async fn i3120_nothing_is_derived_from_a_forbidden_occurrence(d: &dyn FederationDirectory) {
        let alice = e2::put_key(d, "i3120-alice", &[identity_type::USER]).await;
        let node = e2::put_key(d, "i3120-node", &[identity_type::NODE]).await;
        // The forbidden pair, through the trusted-local door. Since v62 the
        // door refuses it (`occurrence_binds_machine_to_person`); an upgraded
        // store may still hold one. Either way the reads below must not
        // derive the node's human from it.
        let at = now_ms();
        let planted = d
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: alice.clone(),
                occurrence_key_id: node.clone(),
                device_class: device_class::LAPTOP.to_owned(),
                hardware_attestation: None,
                asserted_at: at,
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .is_ok();
        async {
            assert!(
                !occurrence_counts(d, &alice, &node).await.unwrap(),
                "I3120: a node under a person never counts"
            );
            assert!(
                !d.active_identities_for_occurrence(&node)
                    .await
                    .unwrap()
                    .contains(&alice),
                "I3120: the node is no occurrence of the person"
            );
            assert!(
                devices_of(d, &alice)
                    .await
                    .unwrap()
                    .iter()
                    .all(|o| o.occurrence_key_id != node),
                "I3120: not one of the person's devices"
            );
            assert!(
                !owner_node_receives(d, &alice, &node, OwnerCohort::SelfContent)
                    .await
                    .unwrap(),
                "I3120: no self content"
            );
            assert!(
                !audience_nodes(d, cohort_scope::SELF, Some(&alice))
                    .await
                    .unwrap()
                    .contains(&node),
                "I3120: not in the self audience"
            );
            assert_eq!(
                human_of(d, &node).await.unwrap(),
                None,
                "I3120: an unowned node has no human"
            );
            assert!(
                !principals_of(d, &node).await.unwrap().contains(&alice),
                "I3120"
            );
        }
        .await;
        if planted {
            // Control: while the earlier form is open the earlier path is
            // still read (a trusted-local row resolves, #932), so the plant
            // was a real one and the shut reads above refused it.
            assert!(
                d.active_identities_for_occurrence(&node)
                    .await
                    .unwrap()
                    .contains(&alice),
                "I3120 control: the earlier path reads the row while the form is open"
            );
        }
    }

    /// The owner's `consent:replication` grant FOR `node`, carrying
    /// `cohorts` (JSON as it travels), put as the owner's edition-2 row.
    async fn allow_list(
        d: &dyn FederationDirectory,
        owner_seed: &str,
        node: &str,
        cohorts: serde_json::Value,
    ) {
        let g = crate::federation::replication_audience_invariants::bodies::grant(
            owner_seed,
            Some(node),
            Some(cohorts),
        );
        e2::put_signed(d, &g)
            .await
            .expect("the owner's allow list for the node is admitted");
    }

    /// **I3123** — the literal `"self"` entry, one rule for every class.
    pub async fn i3123_the_self_entry_is_one_rule(d: &dyn FederationDirectory) {
        use crate::federation::consent_grammar::{parse_grant_payload, CohortEntry};
        use crate::federation::replication_audience::{may_receive, Verdict};
        let alice = e2::put_key(d, "i3123-alice", &[identity_type::USER]).await;
        let fam1 = "i3123-fam1";
        let family = OwnerCohort::Group {
            scope: cohort_scope::FAMILY,
            target: fam1,
        };
        let fam_entry = serde_json::json!({ "scope": cohort_scope::FAMILY, "target": fam1 });

        // The grammar: the literal parses, sorts after every group entry,
        // and round-trips as the literal.
        let env = serde_json::json!({ "payload": {
            "grants": "replication",
            "attestation_prefixes": ["i3123:"],
            "for_key_id": "k",
            "cohorts": [fam_entry.clone(), "self"],
        }});
        let p = parse_grant_payload(&env).expect("I3123: [fam1, \"self\"] parses");
        assert_eq!(
            p.cohorts.as_deref().map(|c| c.last().cloned()),
            Some(Some(CohortEntry::self_entry())),
            "I3123"
        );
        assert_eq!(
            serde_json::to_value(CohortEntry::self_entry()).unwrap(),
            serde_json::json!("self"),
            "I3123: the self entry travels as the literal"
        );
        for bad in [
            serde_json::json!(["self", fam_entry.clone()]),
            serde_json::json!([{ "scope": "self", "target": "" }]),
            serde_json::json!(["selfish"]),
        ] {
            let env = serde_json::json!({ "payload": {
                "grants": "replication", "attestation_prefixes": ["i3123:"],
                "for_key_id": "k", "cohorts": bad.clone(),
            }});
            assert!(
                parse_grant_payload(&env).is_err(),
                "I3123: {bad} is refused (unsorted, the object form, or not the literal)"
            );
        }

        // (a) A SERVER-class node (no self-occurrence) whose list is ["self"].
        let server = e2::put_key(d, "i3123-server", &[identity_type::NODE]).await;
        own(d, "i3123-alice", "i3123-server").await;
        assert!(
            !owner_node_receives(d, &alice, &server, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3123 control: no list, server class: no self"
        );
        allow_list(d, "i3123-alice", &server, serde_json::json!(["self"])).await;
        assert!(
            owner_node_receives(d, &alice, &server, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3123 (a): a server-class node with [\"self\"] receives self"
        );
        assert!(
            !owner_node_receives(d, &alice, &server, family)
                .await
                .unwrap(),
            "I3123 (a): and only what the list names"
        );

        // (b) An owned agent with ["fam1"]: fam1, no self.
        let only_fam = e2::put_key(d, "i3123-agentf", &[identity_type::AGENT]).await;
        own(d, "i3123-alice", "i3123-agentf").await;
        allow_list(
            d,
            "i3123-alice",
            &only_fam,
            serde_json::json!([fam_entry.clone()]),
        )
        .await;
        assert!(
            !owner_node_receives(d, &alice, &only_fam, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3123 (b): [fam1] carries no self"
        );
        assert!(
            owner_node_receives(d, &alice, &only_fam, family)
                .await
                .unwrap(),
            "I3123 (b): fam1 reaches it"
        );

        // (c) An owned agent with [fam1, "self"]: both.
        let both = e2::put_key(d, "i3123-agentb", &[identity_type::AGENT]).await;
        own(d, "i3123-alice", "i3123-agentb").await;
        allow_list(
            d,
            "i3123-alice",
            &both,
            serde_json::json!([fam_entry.clone(), "self"]),
        )
        .await;
        assert!(
            owner_node_receives(d, &alice, &both, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3123 (c): self"
        );
        assert!(
            owner_node_receives(d, &alice, &both, family).await.unwrap(),
            "I3123 (c): and fam1"
        );

        // (d) The always-served `self` rows reach the [fam1] agent whatever
        // its list says: one it authored, one about it. Control: alice's own
        // `self` row about herself does not.
        let self_row = |author: &str, about: &str| -> crate::federation::types::Attestation {
            let mut r = {
                ts::bare_attestation(
                    &uuid::Uuid::new_v4().to_string(),
                    author,
                    about,
                    &serde_json::json!({ "dimension": "identity_binding:v1" }),
                )
            };
            r.cohort_scope = cohort_scope::SELF.to_owned();
            r
        };
        assert!(
            matches!(
                may_receive(d, &only_fam, &self_row(&only_fam, &only_fam))
                    .await
                    .unwrap(),
                Verdict::Yes(_)
            ),
            "I3123 (d): a self row the agent authored reaches it"
        );
        assert!(
            matches!(
                may_receive(d, &only_fam, &self_row(&alice, &only_fam))
                    .await
                    .unwrap(),
                Verdict::Yes(_)
            ),
            "I3123 (d): a self row about the agent reaches it"
        );
        assert!(
            !may_receive(d, &only_fam, &self_row(&alice, &alice))
                .await
                .unwrap()
                .allowed(),
            "I3123 (d) control: alice's other self rows do not"
        );
        assert!(
            may_receive(d, &both, &self_row(&alice, &alice))
                .await
                .unwrap()
                .allowed(),
            "I3123 (d) control: they do reach the agent whose list names \"self\""
        );
    }

    /// **I3122** — the device door takes the owner relation once the earlier
    /// form is shut. `b`'s node key must be set (the door's rule 0).
    pub async fn i3122_the_device_door_takes_the_owner_relation<B>(b: &B)
    where
        B: crate::federation::BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::rekey_community_member_device_add;
        use crate::federation::{Error, DEVICE_REKEY_RULE_NOT_AN_OCCURRENCE};
        let d: &dyn FederationDirectory = b;
        let alice = e2::put_key(d, "i3122-alice", &[identity_type::USER]).await;
        let node = e2::put_key(d, "i3122-node", &[identity_type::NODE]).await;
        own(d, "i3122-alice", "i3122-node").await;
        assert_eq!(
            owner_of(d, &node).await,
            Some(alice.clone()),
            "I3122: fixture"
        );
        // No room is held: a door that passes rule 3 stops at rule 4's
        // lookup, by name.
        let room = "i3122-room";
        let now = chrono::Utc::now();

        // v62.0.0 (slice F) — the doors are shut: the earlier rule's
        // "open" leg is gone with the earlier form.
        let shut = rekey_community_member_device_add(b, room, &alice, &node, &alice, now)
            .await
            .expect_err("I3122: the door stops at the unknown room (shut)");
        assert!(
            !matches!(
                shut,
                Error::DeviceRekeyRefused { rule, .. } if rule == DEVICE_REKEY_RULE_NOT_AN_OCCURRENCE
            ),
            "I3122: once shut, the owned node IS the member's device: {shut}"
        );
        assert!(
            matches!(shut, Error::InvalidArgument(ref m) if m.contains("unknown community_key_id")),
            "I3122: the door went past rule 3 to the room lookup: {shut}"
        );
    }

    /// **I3121** — an agent's human is its owner, and an OWNED agent is
    /// within its owner's `self` for delivery (Eric's ruling via CC).
    pub async fn i3121_an_owned_agent_is_within_its_owners_self(d: &dyn FederationDirectory) {
        use crate::federation::replication_audience_invariants::bodies::grant;
        let alice = e2::put_key(d, "i3121-alice", &[identity_type::USER]).await;
        let bob = e2::put_key(d, "i3121-bob", &[identity_type::USER]).await;
        let agent = e2::put_key(d, "i3121-agent", &[identity_type::AGENT]).await;
        own(d, "i3121-alice", "i3121-agent").await;
        // Its own self-occurrence says `phone`: an agent is never a person's
        // device class.
        self_occurrence(d, &agent, device_class::PHONE, None)
            .await
            .expect("I3121: the agent's own self-occurrence is admitted");
        assert_eq!(
            owner_of(d, &agent).await,
            Some(alice.clone()),
            "I3121: fixture"
        );

        // WHO: the agent's human is its owner.
        assert_eq!(
            human_of(d, &agent).await.unwrap(),
            Some(alice.clone()),
            "I3121: the agent's human is its owner"
        );
        assert!(principals_of(d, &agent).await.unwrap().contains(&alice));
        let rec = devices_of(d, &alice)
            .await
            .unwrap()
            .into_iter()
            .find(|o| o.occurrence_key_id == agent)
            .expect("I3121: the owned agent is listed");
        assert_eq!(
            rec.device_class,
            device_class::AGENT,
            "I3121: its own class"
        );
        assert_eq!(
            owner_node_class(d, &alice, &agent).await.unwrap(),
            Some(NodeClass::OwnedAgent),
            "I3121"
        );

        // An OWNED agent: the owner's self content, the rooms, no family
        // by default.
        let family = OwnerCohort::Group {
            scope: cohort_scope::FAMILY,
            target: "i3121-fam",
        };
        let room = OwnerCohort::Group {
            scope: cohort_scope::COMMUNITY,
            target: "i3121-room",
        };
        assert!(
            owner_node_receives(d, &alice, &agent, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3121: an owned agent receives its owner's self content"
        );
        assert!(
            audience_nodes(d, cohort_scope::SELF, Some(&alice))
                .await
                .unwrap()
                .contains(&agent),
            "I3121: in the owner's self audience"
        );
        assert!(
            !owner_node_receives(d, &alice, &agent, family)
                .await
                .unwrap(),
            "I3121: no family by default"
        );
        assert!(
            owner_node_receives(d, &alice, &agent, room).await.unwrap(),
            "I3121: the rooms as any member node"
        );

        // An agent NOT owned by this owner: never this owner's self content.
        let stray = e2::put_key(d, "i3121-stray", &[identity_type::AGENT]).await;
        assert!(
            !owner_node_receives(d, &alice, &stray, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3121: an unowned agent gets none of alice's self content"
        );
        let bobs = e2::put_key(d, "i3121-bobs", &[identity_type::AGENT]).await;
        own(d, "i3121-bob", "i3121-bobs").await;
        assert!(
            !owner_node_receives(d, &alice, &bobs, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3121: bob's agent gets none of alice's self content"
        );
        assert!(
            owner_node_receives(d, &bob, &bobs, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3121 control: it gets bob's"
        );

        // EXCLUDED: the owner's allow list for the agent, present and not
        // naming `"self"` (CC rc21 3.3.7: a present list is exact for `self`
        // too) — and a family the list names reaches it.
        let excluded = e2::put_key(d, "i3121-excl", &[identity_type::AGENT]).await;
        own(d, "i3121-alice", "i3121-excl").await;
        let g = grant(
            "i3121-alice",
            Some(&excluded),
            Some(serde_json::json!([{ "scope": cohort_scope::FAMILY, "target": "i3121-fam" }])),
        );
        e2::put_signed(d, &g)
            .await
            .expect("I3121: alice's allow list for the agent is admitted");
        assert!(
            !owner_node_receives(d, &alice, &excluded, OwnerCohort::SelfContent)
                .await
                .unwrap(),
            "I3121: an agent the owner's allow list excludes gets no self content"
        );
        assert!(
            owner_node_receives(d, &alice, &excluded, family)
                .await
                .unwrap(),
            "I3121: the family the list names reaches it"
        );
        assert!(
            !owner_node_receives(d, &alice, &excluded, room)
                .await
                .unwrap(),
            "I3121: a room the list does not name does not"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i3118() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3118_an_owned_node_is_in_its_owners_audience(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i3119() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3119_an_unstated_class_is_server(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i3120() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3120_nothing_is_derived_from_a_forbidden_occurrence(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i3123() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3123_the_self_entry_is_one_rule(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i3121() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3121_an_owned_agent_is_within_its_owners_self(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
            }
        };
    }
    /// I3122 needs the concrete backend (the device door takes
    /// `BlobStorage`) with its node key set (the door's rule 0).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3122_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.set_node_key_id("i3122-host");
        super::bodies::i3122_the_device_door_takes_the_owner_relation(&b).await;
    }
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3122_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.set_node_key_id("i3122-host");
        super::bodies::i3122_the_device_door_takes_the_owner_relation(&b).await;
    }

    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
