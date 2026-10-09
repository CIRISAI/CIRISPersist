//! v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — **affiliations: the supersede
//! that could not be written, the cohort nothing declared, and the config
//! record nothing typed.**
//!
//! - **I568** (sqlite, postgres) — the V089 CHECK. At V181 a supersession of an
//!   affiliation is refused by `federation_group_versions`' cohort CHECK (the
//!   bug, pinned); V182 applies over a populated history (a community's prior
//!   version, recorded at V181, survives byte-identical), the same supersession
//!   then writes its prior version under `affiliations`, and the CHECK still
//!   refuses a value outside the vocabulary (the rebuild kept it).
//! - **I569** (memory, sqlite, postgres) — the discriminator. A record declares
//!   its cohort at founding (`policy_blob.cohort_scope`); every door that addresses a
//!   held record under the other cohort is refused
//!   `federation_affiliation_cohort_mismatch`: both supersede doors (both
//!   directions), a supersession that flips the declared cohort, the membership
//!   write doors, and an attestation placed at the wrong `cohort_scope`. An
//!   unknown cohort value and a config on a plain community are refused at
//!   founding.
//! - **I570** (pure, and at the door on all three backends) — the typed config
//!   record: resolution (explicit, else preset, else the no-op default) and
//!   one refusal per validation rule; an invalid record is refused at founding
//!   and on supersession.
//! - **I571** (memory, sqlite, postgres) — the replicated amendment path: an
//!   affiliation amended by quorum on A and applied on B records its prior
//!   version under `affiliations` on B, and a replicated version relabelling
//!   the held affiliation is refused.

/// Backend-agnostic bodies.
#[cfg(test)]
pub mod bodies {
    use crate::federation::affiliation_config::{self as ac, rule};
    use crate::federation::cohort::Cohort;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, consensus_protocol, identity_type,
        Community, CommunityMember,
    };
    use crate::federation::{Error, FederationDirectory};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// A founder_only record `id` of `members` (the first is the founder),
    /// carrying `policy_blob`.
    pub fn record(id: &str, members: &[&str], policy_blob: Option<serde_json::Value>) -> Community {
        Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: id.to_owned(),
            community_name: id.to_owned(),
            members: members
                .iter()
                .enumerate()
                .map(|(i, k)| CommunityMember {
                    key_id: (*k).to_owned(),
                    joined_at: at("2026-01-01T00:00:00Z"),
                    role: (i == 0).then(|| "founder".to_owned()),
                })
                .collect(),
            founded_at: at("2026-01-01T00:00:00Z"),
            consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
            policy_blob,
            persist_row_hash: String::new(),
        }
    }

    /// `policy_blob` declaring `affiliations`, with `config` when given.
    pub fn affiliation_blob(config: Option<serde_json::Value>) -> serde_json::Value {
        let mut b = serde_json::json!({ ac::POLICY_COHORT_FIELD: "affiliations" });
        if let Some(c) = config {
            b[ac::POLICY_AFFILIATION_CONFIG_FIELD] = c;
        }
        b
    }

    /// Register `keys` as users.
    pub async fn users(d: &dyn FederationDirectory, keys: &[&str]) {
        for k in keys {
            ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
        }
    }

    /// Found `c`, signed by its first member.
    pub async fn found(d: &dyn FederationDirectory, c: Community) -> Result<(), Error> {
        let signer = c.members[0].key_id.clone();
        d.put_community(ts::sign_community(&signer, c))
            .await
            .map(|_| ())
    }

    /// The held record renamed, naming the held head (a valid next version).
    pub async fn next_version(d: &dyn FederationDirectory, id: &str, name: &str) -> Community {
        let held = d.lookup_community(id).await.unwrap().expect("held");
        let mut next = held.clone();
        next.community_name = name.to_owned();
        next.prev_head_digest = held.persist_row_hash.clone();
        next.persist_row_hash = String::new();
        next
    }

    fn signed(c: &Community) -> crate::federation::SignedCommunity {
        ts::sign_community(&c.members[0].key_id, c.clone())
    }

    fn expect_mismatch(
        r: Result<impl std::fmt::Debug, Error>,
        declared: &str,
        addressed: &str,
        what: &str,
    ) {
        match r {
            Err(Error::AffiliationCohortMismatch {
                declared: d,
                addressed: a,
                ..
            }) => assert_eq!((d, a), (declared, addressed), "{what}"),
            other => {
                panic!("{what}: expected federation_affiliation_cohort_mismatch, got {other:?}")
            }
        }
    }

    fn expect_rule(r: Result<impl std::fmt::Debug, Error>, want: &str, what: &str) {
        match r {
            Err(Error::AffiliationConfigInvalid { rule, .. }) => assert_eq!(rule, want, "{what}"),
            other => panic!(
                "{what}: expected federation_affiliation_config_invalid ({want}), got {other:?}"
            ),
        }
    }

    /// A member's own chat row placed at `scope` naming `group`.
    fn placed_row(producer: &str, scope: &str, group: &str) -> crate::federation::Attestation {
        let mut r = crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: producer.to_owned(),
            attested_key_id: producer.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": "chat:message:v1",
                "community_id": group,
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: producer.to_owned(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![producer.to_owned()],
            withdraws_admission_rule: None,
            cohort_scope: scope.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::seal_row_in_place(producer, &mut r);
        r
    }

    async fn place(
        d: &dyn FederationDirectory,
        r: crate::federation::Attestation,
    ) -> Result<(), Error> {
        d.put_attestation(crate::federation::SignedAttestation { attestation: r })
            .await
            .map(|_| ())
    }

    /// Found the plain community `{tag}-c` and supersede it once, so the
    /// history table holds a `community` row; returns the id.
    pub async fn seed_community_history(d: &dyn FederationDirectory, tag: &str) -> String {
        let (c, f) = (format!("{tag}-c"), format!("{tag}-cf"));
        users(d, &[&f]).await;
        found(d, record(&c, &[&f], None))
            .await
            .expect("seed: community founds");
        let next = next_version(d, &c, "seeded").await;
        d.supersede_community(signed(&next), None)
            .await
            .expect("seed: a community supersedes at any version");
        c
    }

    /// **I568 (after V182)** — a supersession of an affiliation writes, and
    /// its prior version is recorded under `affiliations`.
    pub async fn i568_affiliation_supersedes(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> Result<(), Error> {
        let (aff, f) = (format!("{tag}-aff"), format!("{tag}-founder"));
        users(d, &[&f]).await;
        found(d, record(&aff, &[&f], Some(affiliation_blob(None)))).await?;
        let next = next_version(d, &aff, "renamed").await;
        d.supersede_affiliations(signed(&next), None).await?;
        let history = d.list_group_versions(Cohort::Affiliations, &aff).await?;
        assert!(
            history.iter().any(|v| v.version == 1),
            "{tag} I568: the prior version is recorded under `affiliations`: {history:?}"
        );
        Ok(())
    }

    /// **I569** — see the module doc.
    pub async fn i569_the_cohort_is_declared(d: &dyn FederationDirectory, tag: &str) {
        let (plain, aff) = (format!("{tag}-plain"), format!("{tag}-aff"));
        let (f, m) = (format!("{tag}-founder"), format!("{tag}-member"));
        users(d, &[&f, &m]).await;
        found(d, record(&plain, &[&f, &m], None))
            .await
            .expect("I569: a plain community founds");
        found(d, record(&aff, &[&f, &m], Some(affiliation_blob(None))))
            .await
            .expect("I569: an affiliation founds");

        // Both supersede doors, both directions.
        let p2 = next_version(d, &plain, "p2").await;
        expect_mismatch(
            d.supersede_affiliations(signed(&p2), None).await,
            "community",
            "affiliations",
            "I569: supersede_affiliations on a plain community",
        );
        let a2 = next_version(d, &aff, "a2").await;
        expect_mismatch(
            d.supersede_community(signed(&a2), None).await,
            "affiliations",
            "community",
            "I569: supersede_community on an affiliation",
        );
        // A supersession that flips the declared cohort.
        let mut flipped = next_version(d, &aff, "flipped").await;
        flipped.policy_blob = None;
        expect_mismatch(
            d.supersede_affiliations(signed(&flipped), None).await,
            "community",
            "affiliations",
            "I569: an affiliation cannot supersede itself into a community",
        );
        // Control: the right door admits.
        d.supersede_affiliations(signed(&a2), None)
            .await
            .expect("I569: supersede_affiliations on an affiliation admits");
        // The held record decides, not the new version's label: a version
        // declaring `community` offered at the community door over a held
        // affiliation.
        let mut relabel = next_version(d, &aff, "relabel").await;
        relabel.policy_blob = None;
        expect_mismatch(
            d.supersede_community(signed(&relabel), None).await,
            "affiliations",
            "community",
            "I569: the community door over a held affiliation, relabelled",
        );

        // The membership write doors refuse before any signature is read.
        let spec = crate::federation::cohort::AdmitSpec {
            authority_key_id: f.clone(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            cosignatures: Vec::new(),
        };
        let member = crate::federation::cohort::RosterMember {
            key_id: format!("{tag}-joiner"),
            joined_at: chrono::Utc::now(),
            role: None,
        };
        expect_mismatch(
            d.add_member(Cohort::Affiliations, &plain, member.clone(), &spec)
                .await,
            "community",
            "affiliations",
            "I569: add_member(affiliations) on a plain community",
        );
        expect_mismatch(
            d.add_member(Cohort::Community, &aff, member, &spec).await,
            "affiliations",
            "community",
            "I569: add_member(community) on an affiliation",
        );
        let revoke = ts::sign_revoke_spec(
            Cohort::Community,
            &m,
            &aff,
            &m,
            chrono::Utc::now(),
            None,
            vec![],
        );
        expect_mismatch(
            d.revoke_member(Cohort::Community, &aff, &m, revoke).await,
            "affiliations",
            "community",
            "I569: revoke_member(community) on an affiliation",
        );

        // An attestation placed at the wrong cohort_scope.
        expect_mismatch(
            place(d, placed_row(&m, cohort_scope::AFFILIATIONS, &plain)).await,
            "community",
            "affiliations",
            "I569: an affiliations-scoped row naming a plain community",
        );
        expect_mismatch(
            place(d, placed_row(&m, cohort_scope::COMMUNITY, &aff)).await,
            "affiliations",
            "community",
            "I569: a community-scoped row naming an affiliation",
        );
        place(d, placed_row(&m, cohort_scope::AFFILIATIONS, &aff))
            .await
            .expect("I569: a member's affiliations-scoped row naming the affiliation admits");
        place(d, placed_row(&m, cohort_scope::COMMUNITY, &plain))
            .await
            .expect("I569: a member's community-scoped row naming the community admits");

        // Founding: an unknown cohort, and a config on a plain community.
        expect_rule(
            found(
                d,
                record(
                    &format!("{tag}-bogus"),
                    &[&f],
                    Some(serde_json::json!({ ac::POLICY_COHORT_FIELD: "guild" })),
                ),
            )
            .await,
            rule::COHORT_UNKNOWN,
            "I569: an unknown declared cohort is refused, never read as community",
        );
        expect_rule(
            found(
                d,
                record(
                    &format!("{tag}-cfg"),
                    &[&f],
                    Some(serde_json::json!({ "affiliation_config": { "affiliation_archetype": "informal_adhoc" } })),
                ),
            )
            .await,
            rule::CONFIG_ON_COMMUNITY,
            "I569: a config on a plain community is refused",
        );
    }

    /// **I571** — the replicated amendment path. A amends an affiliation by
    /// quorum; B applies A's served record and records the prior version under
    /// `affiliations` (it always wrote `community`). A version that relabels
    /// the held affiliation as a community is refused on the replicated door.
    pub async fn i571_a_replicated_affiliation_amendment(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        // The distinguishing part of a key id LEADS: the test signer seeds
        // from its first 32 bytes.
        let keys: Vec<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let id = format!("{tag}-aff");
        let mut founding = record(&id, &refs, Some(affiliation_blob(None)));
        founding.consensus_protocol = consensus_protocol::MAJORITY.to_owned();
        for d in [a, b] {
            users(d, &refs).await;
            found(d, founding.clone())
                .await
                .unwrap_or_else(|e| panic!("{tag} I571: founding: {e}"));
        }
        let change = a
            .build_membership_change_envelope(
                Cohort::Affiliations,
                &id,
                &keys,
                false,
                Some(consensus_protocol::UNANIMOUS),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I571: build change: {e}"));
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let sigs = [&keys[0], &keys[1]]
            .iter()
            .map(|k| ts::threshold_sign(k, &bytes))
            .collect();
        let mut v2 = next_version(a, &id, "renamed").await;
        v2.consensus_protocol = consensus_protocol::UNANIMOUS.to_owned();
        a.supersede_affiliations_with_quorum(signed(&v2), change, sigs)
            .await
            .unwrap_or_else(|e| panic!("{tag} I571: A's quorum amendment: {e}"));
        let served = a
            .list_signed_communities_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.community.community.community_key_id == id)
            .expect("served")
            .community;

        // A relabelled copy of the same amendment: B holds an affiliation.
        let mut relabelled = served.clone();
        relabelled.community.policy_blob = None;
        let relabelled = crate::federation::SignedCommunity {
            supersede_proof: served.supersede_proof.clone(),
            ..ts::sign_community(&keys[0], relabelled.community)
        };
        expect_mismatch(
            b.put_community(relabelled).await,
            "affiliations",
            "community",
            "I571: a replicated version relabelling the affiliation",
        );

        b.put_community(served)
            .await
            .unwrap_or_else(|e| panic!("{tag} I571: B applies A's amendment: {e}"));
        let aff = b
            .list_group_versions(Cohort::Affiliations, &id)
            .await
            .unwrap();
        assert!(
            aff.iter().any(|v| v.version == 1 && !v.is_current),
            "{tag} I571: B recorded the prior version under `affiliations`: {aff:?}"
        );
        assert!(
            b.list_group_versions(Cohort::Community, &id)
                .await
                .unwrap()
                .iter()
                .all(|v| v.is_current),
            "{tag} I571: and not under `community`"
        );
    }

    /// **I570 (door)** — an invalid config is refused at founding and on
    /// supersession; a valid one founds and resolves.
    pub async fn i570_the_config_is_checked_at_the_door(d: &dyn FederationDirectory, tag: &str) {
        let (aff, f, m) = (
            format!("{tag}-aff"),
            format!("{tag}-founder"),
            format!("{tag}-member"),
        );
        users(d, &[&f, &m]).await;
        expect_rule(
            found(
                d,
                record(
                    &aff,
                    &[&f, &m],
                    Some(affiliation_blob(Some(
                        serde_json::json!({ "role_term": 400 }),
                    ))),
                ),
            )
            .await,
            rule::ROLE_TERM_OUT_OF_RANGE,
            "I570: founding with a role term past the one-year ceiling",
        );
        found(
            d,
            record(
                &aff,
                &[&f, &m],
                Some(affiliation_blob(Some(serde_json::json!({
                    "affiliation_archetype": "informal_adhoc",
                    "role_term": 90,
                    "compartments": [{ "name": "board", "members": [f.clone()] }],
                })))),
            ),
        )
        .await
        .expect("I570: a valid affiliation founds");
        let held = d.lookup_community(&aff).await.unwrap().unwrap();
        let resolved = ac::resolved_affiliation_config(&held)
            .unwrap()
            .expect("an affiliation resolves");
        assert_eq!(
            resolved.classification_scheme.classes[0].name,
            ac::DEFAULT_CLASS
        );
        let mut bad = next_version(d, &aff, "bad").await;
        bad.policy_blob = Some(affiliation_blob(Some(serde_json::json!({
            "compartments": [{ "name": "board", "members": [format!("{tag}-stranger")] }],
        }))));
        expect_rule(
            d.supersede_affiliations(signed(&bad), None).await,
            rule::COMPARTMENT_INVALID,
            "I570: a supersession naming a compartment member off the roster",
        );
    }

    /// **I570 (pure)** — resolution and every validation rule.
    pub fn i570_resolution_and_rules() {
        let roster: std::collections::BTreeSet<&str> = ["f", "m"].into_iter().collect();
        let cfg = |v: serde_json::Value| -> ac::AffiliationConfig {
            serde_json::from_value(v).expect("parses")
        };
        // Resolution: default, preset, explicit over preset.
        let r = ac::AffiliationConfig::default().resolve();
        assert_eq!(r.classification_scheme.classes.len(), 1);
        assert_eq!(r.classification_scheme.classes[0].name, ac::DEFAULT_CLASS);
        assert_eq!(
            r.retention_policy,
            ac::RetentionPolicy::RotateForward(ac::RotateForward::RotateForward)
        );
        let r = cfg(serde_json::json!({ "affiliation_archetype": "informal_adhoc" })).resolve();
        assert_eq!(r.membership_basis, vec![ac::MembershipBasis::RoleAssigned]);
        let r = cfg(serde_json::json!({ "affiliation_archetype": "igo" })).resolve();
        assert_eq!(
            r.classification_scheme
                .classes
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["Unclassified", "Confidential", "Strictly-Confidential"]
        );
        let r = cfg(serde_json::json!({
            "affiliation_archetype": "igo",
            "membership_basis": "voluntary-total",
            "classification_scheme": { "classes": [{ "name": "open" }] },
        }))
        .resolve();
        assert_eq!(
            r.membership_basis,
            vec![ac::MembershipBasis::VoluntaryTotal]
        );
        assert_eq!(r.classification_scheme.classes[0].name, "open");
        // Unknown limbs ride verbatim.
        let c = cfg(serde_json::json!({ "legal_hold": { "hold_id": "h1" } }));
        assert!(c.other.contains_key("legal_hold"));

        let refused = |v: serde_json::Value| -> &'static str {
            match cfg(v).validate("g", &roster) {
                Err(Error::AffiliationConfigInvalid { rule, .. }) => rule,
                other => panic!("expected a refusal, got {other:?}"),
            }
        };
        assert_eq!(
            refused(serde_json::json!({ "role_term": 0 })),
            rule::ROLE_TERM_OUT_OF_RANGE
        );
        assert_eq!(
            refused(serde_json::json!({ "role_term": 366 })),
            rule::ROLE_TERM_OUT_OF_RANGE
        );
        cfg(serde_json::json!({ "role_term": 365 }))
            .validate("g", &roster)
            .expect("365 is the ceiling");
        assert_eq!(
            refused(serde_json::json!({ "classification_scheme": { "classes": [] } })),
            rule::CLASSIFICATION_INVALID
        );
        assert_eq!(
            refused(
                serde_json::json!({ "classification_scheme": { "classes": [{ "name": "a" }, { "name": "a" }] } })
            ),
            rule::CLASSIFICATION_INVALID
        );
        assert_eq!(
            refused(
                serde_json::json!({ "retention_policy": { "secret": { "delete_after": 30 } } })
            ),
            rule::RETENTION_UNKNOWN_CLASS
        );
        assert_eq!(
            refused(
                serde_json::json!({ "retention_policy": { "internal": { "retain_minimum": 90, "delete_after": 30 } } })
            ),
            rule::RETENTION_FLOOR_ABOVE_CEILING
        );
        assert_eq!(
            refused(
                serde_json::json!({ "retention_policy": { "internal": { "retain_minimum": "permanent", "delete_after": 30 } } })
            ),
            rule::RETENTION_FLOOR_ABOVE_CEILING
        );
        cfg(serde_json::json!({ "retention_policy": { "internal": { "retain_minimum": 30, "delete_after": 90 } } }))
            .validate("g", &roster)
            .expect("a floor under its ceiling");
        assert_eq!(
            refused(serde_json::json!({ "compartments": [{ "name": "c", "members": ["x"] }] })),
            rule::COMPARTMENT_INVALID
        );
        assert_eq!(
            refused(serde_json::json!({ "compartments": [{ "name": "c" }, { "name": "c" }] })),
            rule::COMPARTMENT_INVALID
        );
        assert_eq!(
            refused(
                serde_json::json!({ "classification_scheme": { "classes": [{ "name": "a", "compartment": "ghost" }] } })
            ),
            rule::COMPARTMENT_INVALID
        );
        assert_eq!(
            refused(serde_json::json!({ "hierarchy": { "depth_cap": 0 } })),
            rule::HIERARCHY_DEPTH_OUT_OF_RANGE
        );
        assert_eq!(
            refused(serde_json::json!({ "hierarchy": { "depth_cap": 17 } })),
            rule::HIERARCHY_DEPTH_OUT_OF_RANGE
        );
        assert_eq!(
            refused(serde_json::json!({ "designated_officials": [{ "role": "", "key_id": "f" }] })),
            rule::DESIGNATED_OFFICIAL_INVALID
        );
        // Malformed is a refusal: an unknown preset does not resolve.
        let c = record(
            "g",
            &["f"],
            Some(affiliation_blob(Some(
                serde_json::json!({ "affiliation_archetype": "guild_hall" }),
            ))),
        );
        match ac::check_community_record(&c) {
            Err(Error::AffiliationConfigInvalid { rule, .. }) => {
                assert_eq!(rule, rule::CONFIG_MALFORMED)
            }
            other => panic!("an unknown archetype must be refused, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn i570_pure() {
        super::bodies::i570_resolution_and_rules();
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test(flavor = "multi_thread")]
                async fn i568() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i568_affiliation_supersedes(
                        &d as &dyn FederationDirectory,
                        &format!("i568-{}", super::suffix()),
                    )
                    .await
                    .expect("I568: an affiliation supersedes");
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i569() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i569_the_cohort_is_declared(
                        &d as &dyn FederationDirectory,
                        &format!("i569-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i571() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i571_a_replicated_affiliation_amendment(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i571-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i570() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i570_the_config_is_checked_at_the_door(
                        &d as &dyn FederationDirectory,
                        &format!("i570-{}", super::suffix()),
                    )
                    .await
                }
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

    /// I568 at V181 then V182, sqlite: red before, green after, the
    /// populated history preserved, the CHECK kept.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i568_v089_check_then_v182_sqlite() {
        use crate::federation::FederationDirectory;
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations_through(181).await.unwrap();
        let tag = format!("i568s-{}", suffix());
        let community = super::bodies::seed_community_history(&b, &tag).await;
        let err = super::bodies::i568_affiliation_supersedes(&b, &format!("{tag}-pre"))
            .await
            .expect_err("I568: at V181 the V089 CHECK refuses an affiliations history row");
        assert!(
            err.to_string().contains("CHECK"),
            "I568: refused by the cohort CHECK, not by a neighbour: {err}"
        );
        let before: (String, String) = b
            .read(move |c| {
                c.query_row(
                    "SELECT snapshot, persist_row_hash FROM federation_group_versions WHERE group_key_id = ?1",
                    [&community],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let community2 = format!("{tag}-c");
        let after: (String, String) = b
            .read(move |c| {
                c.query_row(
                    "SELECT snapshot, persist_row_hash FROM federation_group_versions WHERE group_key_id = ?1",
                    [&community2],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "I568: V182 preserves the populated history byte-identical"
        );
        super::bodies::i568_affiliation_supersedes(
            &b as &dyn FederationDirectory,
            &format!("{tag}-post"),
        )
        .await
        .expect("I568: after V182 an affiliation supersedes");
        let bogus = b
            .write(|c| {
                c.execute(
                    "INSERT INTO federation_group_versions (cohort, group_key_id, version, snapshot, \
                     superseded_at, persist_row_hash) VALUES ('guild', 'g', 1, '{}', 'x', 'h')",
                    [],
                )
            })
            .await;
        assert!(
            bogus.is_err(),
            "I568: the rebuilt table keeps the cohort CHECK"
        );
    }

    /// I568 at V181 then V182, postgres.
    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i568_v089_check_then_v182_postgres() {
        use crate::federation::FederationDirectory;
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations_through(181).await.unwrap();
        let tag = format!("i568p-{}", suffix());
        let community = super::bodies::seed_community_history(&b, &tag).await;
        let err = super::bodies::i568_affiliation_supersedes(&b, &format!("{tag}-pre"))
            .await
            .expect_err("I568: at V181 the V089 CHECK refuses an affiliations history row");
        // The backend reports the driver error as `db error`; the history
        // insert is what refused, and the table itself says why: an
        // `affiliations` row is a CHECK violation (SQLSTATE 23514) at V181.
        assert!(
            err.to_string().contains("insert group version"),
            "I568: refused at the history insert, not by a neighbour: {err}"
        );
        let direct = b
            .get_client()
            .await
            .unwrap()
            .execute(
                "INSERT INTO cirislens.federation_group_versions (cohort, group_key_id, version, \
                 snapshot, superseded_at, persist_row_hash) VALUES ('affiliations', 'g', 1, '{}', now(), 'h')",
                &[],
            )
            .await
            .expect_err("I568: V089's CHECK refuses `affiliations`");
        assert_eq!(
            direct.code(),
            Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION),
            "I568: the refusal is the cohort CHECK: {direct:?}"
        );
        let read = |id: String| {
            let b = &b;
            async move {
                let row = b
                    .get_client()
                    .await
                    .unwrap()
                    .query_one(
                        "SELECT snapshot::text, persist_row_hash FROM cirislens.federation_group_versions \
                         WHERE group_key_id = $1",
                        &[&id],
                    )
                    .await
                    .unwrap();
                (row.get::<_, String>(0), row.get::<_, String>(1))
            }
        };
        let before = read(community.clone()).await;
        b.run_migrations().await.unwrap();
        assert_eq!(
            before,
            read(community).await,
            "I568: V182 preserves the populated history"
        );
        super::bodies::i568_affiliation_supersedes(
            &b as &dyn FederationDirectory,
            &format!("{tag}-post"),
        )
        .await
        .expect("I568: after V182 an affiliation supersedes");
        let bogus = b
            .get_client()
            .await
            .unwrap()
            .execute(
                "INSERT INTO cirislens.federation_group_versions (cohort, group_key_id, version, \
                 snapshot, superseded_at, persist_row_hash) VALUES ('guild', 'g', 1, '{}', now(), 'h')",
                &[],
            )
            .await;
        assert!(
            bogus.is_err(),
            "I568: the rebuilt CHECK still refuses an unknown cohort"
        );
    }
}
