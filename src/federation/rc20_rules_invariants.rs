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
//! - **I1878 / I1879** (CC 4.2.1 / 3.4.7.1 / 8.11.27) — the canonical standing
//!   is the accord's conferral: a v61 earlier-form `canonical,node` record
//!   resolves by its verifying co-scrub; a `canonical` label whose co-scrub
//!   does not verify is inert; the forward form ({node}, `infra:serve`, the
//!   co-scrub) resolves; one anchor scrub is no conferral; a forged forward
//!   co-scrub confers nothing.
//! - **I1887** — the key-record store path's conflicts are typed.
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
                let rec = ts::replicated_key_record("i1870-k", &set, "i1870-k", "i1870-k", "n");
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
            let rec = ts::replicated_key_record("i1870-k", &set, "i1870-k", "i1870-k", "n");
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
    use crate::federation::register::{KeyRefusalReason, ReplicatedKeyOutcome};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type as it;
    use crate::federation::{Error, FederationDirectory, SignedKeyRecord};

    /// The accord roster (production ids, deterministic TEST keys: safe only
    /// on a fresh backend of this test's own) and the baked lineage id, which
    /// keeps the pre-floor bar.
    async fn canonical_fixture(
        d: &dyn FederationDirectory,
    ) -> (
        Vec<crate::federation::operational::test_support::Identity>,
        String,
    ) {
        use crate::federation::operational::test_support as ops;
        let accord: Vec<ops::Identity> =
            crate::federation::admission::accord_holder_roster_key_ids()
                .iter()
                .map(|k| ops::Identity::new(k))
                .collect();
        for a in &accord {
            ops::register_accord_holder(d, a).await.unwrap();
        }
        let g = crate::federation::genesis::canonical_genesis_bundle().serve_nodes[0]
            .record
            .key_id
            .clone();
        (accord, g)
    }

    /// **I1878 (part 1)** — a v61 canonical (the earlier-form envelope
    /// `"identity_type": "canonical,node"`, `infra:serve`, the accord's 2-of-3
    /// co-scrub) is admitted and resolves by its conferral. Returns the record
    /// the runner plants through the genesis seed door (which runs no
    /// conferral gate, as a row stored before the gate would be): a
    /// `canonical,node` label whose co-scrub does not verify.
    pub(crate) async fn i1878_earlier_form_resolves(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> crate::federation::KeyRecord {
        use crate::federation::operational::test_support as ops;
        let (accord, g) = canonical_fixture(d).await;
        let v61 = ops::signed_canonical_record_with_roles(
            &g,
            "canonical,node",
            ops::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": g }),
            &[&accord[0], &accord[1]],
        );
        d.put_public_key(SignedKeyRecord { record: v61 })
            .await
            .expect("I1878: the v61-shaped canonical is admitted");
        assert!(
            crate::federation::is_canonical(d, &g).await.unwrap(),
            "I1878: a v61 canonical resolves by its verifying co-scrub (CC 8.11.27)"
        );
        // The inert label: a `canonical,node` record whose second scrub is
        // forged (it names a real accord key but is another key's signature).
        let inert_id = format!("i1878-inert-{tag}");
        let mut inert = ops::signed_canonical_record(
            &inert_id,
            "canonical,node",
            ops::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            serde_json::json!({ "key_id": inert_id }),
            &[&accord[0], &accord[1]],
        );
        let forged = ops::signed_canonical_record(
            &inert_id,
            "canonical,node",
            ops::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            serde_json::json!({ "key_id": inert_id, "other": true }),
            &[&accord[1]],
        );
        inert.additional_scrubs[0].scrub_signature_classical = forged.scrub_signature_classical;
        inert.additional_scrubs[0].scrub_signature_pqc = forged.scrub_signature_pqc;
        assert!(
            d.put_public_key(SignedKeyRecord {
                record: inert.clone()
            })
            .await
            .is_err(),
            "I1878: the door refuses the forged co-scrub"
        );
        inert
    }

    /// **I1878 (part 2)** — after the runner planted `inert_id`: the label is
    /// inert. CC 3.4.7.1: "A conferral is not a label."
    pub(crate) async fn i1878_the_label_is_inert(d: &dyn FederationDirectory, inert_id: &str) {
        assert!(
            d.lookup_public_key(inert_id).await.unwrap().is_some(),
            "I1878: the planted row is held"
        );
        assert!(
            !crate::federation::is_canonical(d, inert_id).await.unwrap(),
            "I1878: `canonical` in a stored identity_type confers nothing without its co-scrub"
        );
    }

    /// **I1879** — the forward form: identity_type {node}, `infra:serve`, the
    /// accord's co-scrub, resolves canonical (CC 4.2.1: "That co-scrub is the
    /// key's canonical standing"). One anchor scrub alone is recognition, not a
    /// conferral; a forged forward co-scrub is admitted and inert. Returns the
    /// canonical's key id and the one-scrub node's, for the runner's listing.
    pub(crate) async fn i1879_forward_form_resolves(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, String) {
        use crate::federation::operational::test_support as ops;
        let (accord, g) = canonical_fixture(d).await;
        // A forged forward co-scrub, on another key: the forward form is READ,
        // not gated, so it is admitted as an ordinary node record and is
        // never canonical (its co-scrub does not verify).
        let forged_id = format!("i1879-forged-{tag}");
        let mut forged = ops::signed_canonical_record_with_roles(
            &forged_id,
            "node",
            ops::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": forged_id }),
            &[&accord[0], &accord[1]],
        );
        forged.additional_scrubs[0].scrub_signature_classical =
            forged.scrub_signature_classical.clone();
        assert!(crate::federation::admission::presents_canonical_conferral(
            &forged
        ));
        d.put_public_key(SignedKeyRecord { record: forged })
            .await
            .expect("I1879: a forward-form record is not refused at the door");
        assert!(
            !crate::federation::is_canonical(d, &forged_id)
                .await
                .unwrap(),
            "I1879: a forged forward co-scrub confers nothing"
        );
        let fwd = ops::signed_canonical_record_with_roles(
            &g,
            "node",
            ops::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": g }),
            &[&accord[0], &accord[1]],
        );
        assert!(crate::federation::admission::presents_canonical_conferral(
            &fwd
        ));
        d.put_public_key(SignedKeyRecord { record: fwd })
            .await
            .expect("I1879: the forward-form canonical is admitted");
        assert!(
            crate::federation::is_canonical(d, &g).await.unwrap(),
            "I1879: {{node}} + infra:serve + the accord's co-scrub is canonical"
        );
        assert!(
            it::parse_set(
                &d.lookup_public_key(&g)
                    .await
                    .unwrap()
                    .unwrap()
                    .identity_type
            ) == [it::NODE]
        );
        // One anchor scrub alone: admitted (recognition), never canonical.
        let one = format!("i1879-one-{tag}");
        let rec = ops::signed_canonical_record_with_roles(
            &one,
            "node",
            ops::PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": one }),
            &[&accord[0]],
        );
        assert!(!crate::federation::admission::presents_canonical_conferral(
            &rec
        ));
        d.put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("I1879: a one-scrub node is admitted");
        assert!(
            !crate::federation::is_canonical(d, &one).await.unwrap(),
            "I1879: one anchor scrub is no conferral"
        );
        (g, one)
    }

    /// **I1881** — a CONFORMANT, ROOTED infrastructure community (the CC 3.2
    /// worked example: `quorum:2/3`, three human founders, the accord's 2-of-3
    /// co-scrub) is authorized: its node member needs no steward binding, and
    /// it needs no moderator. CC 3.2: "With no owner, a key MAY trust and serve
    /// `infrastructure` communities and does nothing more."
    pub(crate) async fn i1881_a_conformant_rooted_community_is_authorized(
        d: &dyn FederationDirectory,
    ) {
        use crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID as CANON;
        use crate::federation::canonical_community_invariants::bodies as cci;
        cci::stand_up(d).await;
        let row = cci::canonical_row(&cci::FOUNDERS);
        d.put_community(cci::signed(row.clone(), &["A1", "B1"]))
            .await
            .expect("I1881: the rooted trust-root community is admitted");
        assert!(
            crate::federation::canonical_community::is_rooted(d, CANON)
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
    }

    /// **I1882** — an AGENT member of the same rooted infrastructure
    /// community, with no live steward binding, is refused. Agents are never
    /// exempt (CC 3.2: "Authority MUST root in an accountable human, never in a
    /// bare node").
    pub(crate) async fn i1882_an_agent_is_never_exempt(d: &dyn FederationDirectory) {
        use crate::federation::canonical_community_invariants::bodies as cci;
        i1881_a_conformant_rooted_community_is_authorized(d).await;
        let agent = "i1882-agent";
        ts::register_hybrid_key_as(d, agent, agent, it::AGENT).await;
        let mut row = cci::canonical_row(&cci::FOUNDERS);
        row.members.push(crate::federation::types::CommunityMember {
            key_id: agent.to_owned(),
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
                assert_eq!(member_key_id, agent, "I1882");
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
        let room = format!("i1883-room-{tag}");
        let founder = format!("i1883-founder-{tag}");
        let node = format!("i1883-node-{tag}");
        ts::register_hybrid_key_as(d, &room, &room, it::SUBSTRATE_PERSIST).await;
        ts::register_hybrid_key_as(d, &founder, &founder, it::USER).await;
        ts::register_hybrid_key_as(d, &node, &node, it::NODE).await;
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
            let k = format!("i1884-founder-{n}-{tag}");
            ts::register_hybrid_key_as(d, &k, &k, t).await;
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

    /// **I1887** (CIRISPersist#1274 item 8) — the key-record store path's
    /// conflicts are TYPED: the same key registered again with another record
    /// is `same_key_different_record`, and other pubkeys under the key id are
    /// `pubkey_change`. Until v62 both were one untyped `Conflict`.
    pub(crate) async fn i1887_key_record_conflicts_are_typed(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::register::KeyRecordConflictReason as R;
        let k = format!("i1887-k-{tag}");
        d.put_public_key(SignedKeyRecord {
            record: ts::replicated_key_record(&k, it::USER, &k, &k, "n1"),
        })
        .await
        .expect("I1887: the first record");
        let mut same_key = ts::replicated_key_record(&k, it::USER, &k, &k, "n1");
        same_key.identity_ref = format!("elsewhere-{tag}");
        match d.put_public_key(SignedKeyRecord { record: same_key }).await {
            Err(Error::KeyRecordConflict {
                reason: R::SameKeyDifferentRecord,
                ..
            }) => {}
            other => panic!("I1887: the same key, another record: {other:?}"),
        }
        let mut swapped = ts::replicated_key_record(&k, it::USER, &k, &k, "n1");
        swapped.pubkey_ed25519_base64 = ts::hybrid_pubkeys(&format!("other-{tag}")).0;
        let err = d
            .put_public_key(SignedKeyRecord { record: swapped })
            .await
            .expect_err("I1887: a pubkey swap is refused");
        assert!(
            matches!(
                err,
                Error::KeyRecordConflict {
                    reason: R::PubkeyChange,
                    ..
                }
            ),
            "I1887: other pubkeys under the key id: {err:?}"
        );
        assert_eq!(err.kind(), "federation_key_record_conflict_pubkey_change");
        assert!(
            err.is_duplicate_key(),
            "I1887: still a conflict to its callers"
        );
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
        let k = format!("i1871-store-{tag}");
        let rec = ts::replicated_key_record(&k, it::SUBSTRATE_PERSIST, &k, &k, "n1");
        crate::federation::admission::check_privileged_identity_type_admission(d, &rec)
            .await
            .expect("I1871: the privileged-type gate demands nothing of it");
        d.put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("I1871: a store asserts it under its own key, no ceremony");
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

    /// **I1870** — the identity set rule on BOTH key-record doors (CC 3.4.7.1,
    /// CC 2.4.1.1: "A set that holds `user` or `accord_holder` together with
    /// `node` or `agent` is malformed and refused"). The local mint refuses
    /// with the error; the replicated insert refuses TYPED (so the cursor
    /// advances) and stores nothing. A single-role key passes both doors.
    pub(crate) async fn i1870_the_identity_set_rule_holds_on_every_door(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let cases: [(&str, String, KeyRefusalReason); 5] = [
            (
                "node+agent",
                it::join_set([it::NODE, it::AGENT]),
                KeyRefusalReason::NodeIdentityFused,
            ),
            (
                "node+user",
                it::join_set([it::NODE, it::USER]),
                KeyRefusalReason::NodeIdentityFused,
            ),
            (
                "user+agent",
                it::join_set([it::USER, it::AGENT]),
                KeyRefusalReason::IdentitySetMixed,
            ),
            (
                "accord_holder+node",
                it::join_set([it::ACCORD_HOLDER, it::NODE]),
                KeyRefusalReason::IdentitySetMixed,
            ),
            (
                "accord_holder+agent",
                it::join_set([it::ACCORD_HOLDER, it::AGENT]),
                KeyRefusalReason::IdentitySetMixed,
            ),
        ];
        for (n, (what, set, reason)) in cases.into_iter().enumerate() {
            let local = format!("i1870-local-{n}-{tag}");
            let err = d
                .put_public_key(SignedKeyRecord {
                    record: ts::replicated_key_record(&local, &set, &local, &local, "n1"),
                })
                .await
                .expect_err("I1870: a local mint of a mixed set is refused");
            let want_node = reason == KeyRefusalReason::NodeIdentityFused;
            assert!(
                if want_node {
                    matches!(err, Error::NodeIdentityNotExclusive { .. })
                } else {
                    matches!(err, Error::IdentitySetMixesPersonAndMachine { .. })
                },
                "I1870 {what}: local mint refused under its token, got {err}"
            );
            assert!(
                d.lookup_public_key(&local).await.unwrap().is_none(),
                "I1870 {what}: nothing stored locally"
            );
            let remote = format!("i1870-remote-{n}-{tag}");
            let out = d
                .apply_replicated_key_record(SignedKeyRecord {
                    record: ts::replicated_key_record(&remote, &set, &remote, &remote, "n1"),
                })
                .await
                .unwrap_or_else(|e| panic!("I1870 {what}: the replicated refusal is typed: {e}"));
            assert_eq!(
                out,
                ReplicatedKeyOutcome::Refused { reason },
                "I1870 {what}: the replicated insert refuses (CC rc20 removed the carve-out)"
            );
            assert!(
                d.lookup_public_key(&remote).await.unwrap().is_none(),
                "I1870 {what}: nothing stored from the replicated door"
            );
        }
        // The controls: a single role passes both doors.
        for (n, role) in [it::USER, it::AGENT, it::NODE].into_iter().enumerate() {
            let local = format!("i1870-ok-local-{n}-{tag}");
            d.put_public_key(SignedKeyRecord {
                record: ts::replicated_key_record(&local, role, &local, &local, "n1"),
            })
            .await
            .unwrap_or_else(|e| panic!("I1870 control {role}: admitted locally: {e}"));
            let remote = format!("i1870-ok-remote-{n}-{tag}");
            assert_eq!(
                d.apply_replicated_key_record(SignedKeyRecord {
                    record: ts::replicated_key_record(&remote, role, &remote, &remote, "n1"),
                })
                .await
                .unwrap(),
                ReplicatedKeyOutcome::Inserted,
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
                case!(i1887_key_record_conflicts_are_typed);
                case!(i1883_a_self_declared_community_gets_nothing);
                case!(i1884_conformance_is_the_record);
                #[tokio::test]
                async fn i1881_a_conformant_rooted_community_is_authorized() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1881_a_conformant_rooted_community_is_authorized(&d)
                        .await
                }
                #[tokio::test]
                async fn i1882_an_agent_is_never_exempt() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1882_an_agent_is_never_exempt(&d).await
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

    macro_rules! canonical_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i1878_a_v61_canonical_resolves_and_a_label_is_inert() {
                    let Some(b) = $fresh.await else { return };
                    let tag = suffix();
                    let inert = super::super::bodies::i1878_earlier_form_resolves(
                        &b as &dyn FederationDirectory,
                        &tag,
                    )
                    .await;
                    let inert_id = inert.key_id.clone();
                    b.seed_genesis_accord_holders(&[crate::federation::SignedKeyRecord {
                        record: inert,
                    }])
                    .await
                    .expect("plant the pre-gate row");
                    super::super::bodies::i1878_the_label_is_inert(
                        &b as &dyn FederationDirectory,
                        &inert_id,
                    )
                    .await;
                    let listed: Vec<String> = b
                        .list_canonical_servers()
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|r| r.key_id)
                        .collect();
                    let g = crate::federation::genesis::canonical_genesis_bundle().serve_nodes[0]
                        .record
                        .key_id
                        .clone();
                    assert_eq!(
                        listed,
                        vec![g],
                        "I1878: listed by conferral, the label inert"
                    );
                }
                #[tokio::test]
                async fn i1879_the_forward_form_resolves() {
                    let Some(b) = $fresh.await else { return };
                    let (g, one) = super::super::bodies::i1879_forward_form_resolves(
                        &b as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await;
                    let listed: Vec<String> = b
                        .list_canonical_servers()
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|r| r.key_id)
                        .collect();
                    assert!(listed.contains(&g), "I1879: the forward form is listed");
                    assert!(!listed.contains(&one), "I1879: a one-scrub node is not");
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    canonical_runners!(sqlite_canonical, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    canonical_runners!(postgres_canonical, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
