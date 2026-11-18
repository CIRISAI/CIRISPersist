//! v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — **affiliations: the supersede
//! that could not be written, the cohort nothing declared, and the config
//! record nothing typed.**
//!
//! - **I592** (sqlite, postgres) — the V089 CHECK. At V181 a supersession of an
//!   affiliation is refused by `federation_group_versions`' cohort CHECK (the
//!   bug, pinned); V182 applies over a populated history (a community's prior
//!   version, recorded at V181, survives byte-identical), the same supersession
//!   then writes its prior version under `affiliations`, and the CHECK still
//!   refuses a value outside the vocabulary (the rebuild kept it).
//! - **I593** (memory, sqlite, postgres) — the discriminator. A record declares
//!   its cohort at founding (`policy_blob.cohort_scope`); every door that addresses a
//!   held record under the other cohort is refused
//!   `federation_affiliation_cohort_mismatch`: a version declaring the other
//!   cohort (both directions; v62: the one roster door, the held record
//!   decides), and an attestation placed at the wrong `cohort_scope`. An
//!   unknown cohort value and a config on a plain community are refused at
//!   founding.
//! - **I594** (pure, and at the door on all three backends) — the typed config
//!   record: resolution (explicit, else preset, else the no-op default) and
//!   one refusal per validation rule; an invalid record is refused at founding
//!   and on supersession.
//! - **I606** (memory, sqlite, postgres; Codex round 2 on PR #1050) — the
//!   discriminator on the uniform READS. `lookup_group`, `active_members`,
//!   `active_member_keys` and `groups_of` merged both variants, so an
//!   objection labelled as an affiliation's was evaluated against a community
//!   of the same id, and the FFI lookup and list reported `community` for an
//!   affiliation. Each read now refuses a held record of the other cohort
//!   `federation_affiliation_cohort_mismatch`, a reverse lookup lists each
//!   record under its own cohort only, and a looked-up record reports the
//!   cohort it declares.
//! - **I595** (memory, sqlite, postgres) — the replicated amendment path: an
//!   affiliation amended by quorum on A and applied on B records its prior
//!   version under `affiliations` on B, and a replicated version relabelling
//!   the held affiliation is refused.

/// Backend-agnostic bodies.
#[cfg(test)]
pub mod bodies {
    use crate::federation::affiliation_config::{self as ac, rule};
    use crate::federation::cohort::Cohort;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::GroupRecord;
    use crate::federation::edition2::ingest::{
        apply_replicated_statement, ReplicatedStatementOutcome, StatementOutcome,
    };
    use crate::federation::edition2::names::RowId;
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
            consensus_protocol: "quorum:1/1".into(),
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

    /// Found `c`, signed by its first member (wave 2, T1): the founding
    /// roster's voices (the founder's and every listed member's) through the
    /// edition-2 door. The record lands under `e2::kid(id)`, its members
    /// under `e2::kid(member)`.
    pub async fn found(d: &dyn FederationDirectory, c: Community) -> Result<(), Error> {
        let signer = c.members[0].key_id.clone();
        let signed = ts::sign_community(&signer, c);
        e2::put_voices(
            d,
            &e2::community_voices(&signed, 1, None, e2::ms(chrono::Utc::now())),
        )
        .await
        .map(|_| ())
    }

    /// A later version of the held record (wave 2, T1): the roster's own row
    /// at the version after the held head, naming it by `refs.head`, with
    /// the voices of `next`'s listed members.
    pub async fn supersede(d: &dyn FederationDirectory, next: &Community) -> Result<(), Error> {
        let voices =
            e2::community_voices_naming_held(d, &signed(next), e2::ms(chrono::Utc::now())).await;
        e2::put_voices(d, &voices).await.map(|_| ())
    }

    /// The held record (under `e2::kid(id)`) renamed, as seeds again (the
    /// builders sign with the seed; the twin maps to identity-refs), naming
    /// the held head (a valid next version).
    pub async fn next_version(d: &dyn FederationDirectory, id: &str, name: &str) -> Community {
        let held = d
            .lookup_community(&e2::kid(id))
            .await
            .unwrap()
            .expect("held");
        let mut held = held;
        held.community_key_id = e2::seed_of(&held.community_key_id);
        for m in &mut held.members {
            m.key_id = e2::seed_of(&m.key_id);
        }
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
        let r = crate::federation::Attestation {
            attestation_id: String::new(),
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
        // Edition 2: the literal is the payload; the row is the door's
        // mapping of the producer's statement over it.
        crate::federation::edition2::fixture_switch::row_of(&r, producer)
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
        // Wave 2: the distinguishing part of an id LEADS (a test key seeds
        // from its first 32 bytes, and so does its identity-ref).
        let (c, f) = (format!("c-{tag}"), format!("cf-{tag}"));
        users(d, &[&f]).await;
        found(d, record(&c, &[&f], None))
            .await
            .expect("seed: community founds");
        let next = next_version(d, &c, "seeded").await;
        supersede(d, &next)
            .await
            .expect("seed: a community supersedes at any version");
        c
    }

    /// **I592 (after V182)** — a supersession of an affiliation writes, and
    /// its prior version is recorded under `affiliations`.
    pub async fn i592_affiliation_supersedes(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> Result<(), Error> {
        let (aff, f) = (format!("aff-{tag}"), format!("founder-{tag}"));
        users(d, &[&f]).await;
        found(d, record(&aff, &[&f], Some(affiliation_blob(None)))).await?;
        let next = next_version(d, &aff, "renamed").await;
        supersede(d, &next).await?;
        let history = d
            .list_group_versions(Cohort::Affiliations, &e2::kid(&aff))
            .await?;
        assert!(
            history.iter().any(|v| v.version == 1),
            "{tag} I592: the prior version is recorded under `affiliations`: {history:?}"
        );
        Ok(())
    }

    /// **I606** — see the module doc.
    pub async fn i606_the_uniform_reads_are_cohort_checked(d: &dyn FederationDirectory, tag: &str) {
        let (plain, aff) = (format!("plain-{tag}"), format!("aff-{tag}"));
        let (f, m) = (format!("founder-{tag}"), format!("member-{tag}"));
        users(d, &[&f, &m]).await;
        found(d, record(&plain, &[&f, &m], None))
            .await
            .expect("I606: a plain community founds");
        found(d, record(&aff, &[&f, &m], Some(affiliation_blob(None))))
            .await
            .expect("I606: an affiliation founds");
        // The records are held under their identity-refs.
        let (plain, aff, f) = (e2::kid(&plain), e2::kid(&aff), e2::kid(&f));

        // The point reads refuse the other cohort, both directions.
        for (id, declared, addressed, cohort) in [
            (&plain, "community", "affiliations", Cohort::Affiliations),
            (&aff, "affiliations", "community", Cohort::Community),
        ] {
            expect_mismatch(
                d.lookup_group(cohort, id).await,
                declared,
                addressed,
                &format!("I606: lookup_group({addressed}) on a held {declared}"),
            );
            expect_mismatch(
                d.active_members(cohort, id).await,
                declared,
                addressed,
                &format!("I606: active_members({addressed}) on a held {declared}"),
            );
            expect_mismatch(
                d.active_member_keys(cohort, id).await,
                declared,
                addressed,
                &format!("I606: active_member_keys({addressed}) on a held {declared}"),
            );
        }
        // The right cohort reads, and reports the cohort the record declares
        // (what the FFI lookup serializes).
        for (id, cohort) in [(&plain, Cohort::Community), (&aff, Cohort::Affiliations)] {
            let g = d
                .lookup_group(cohort, id)
                .await
                .expect("I606: the right cohort reads")
                .expect("I606: held");
            assert_eq!(
                g.cohort, cohort,
                "I606: lookup_group reports the declared cohort"
            );
            assert_eq!(
                d.active_members(cohort, id).await.expect("roster").len(),
                2,
                "I606: active_members under the declared cohort"
            );
        }
        // The reverse lookup lists each record under its own cohort only.
        for (cohort, mine, other) in [
            (Cohort::Community, &plain, &aff),
            (Cohort::Affiliations, &aff, &plain),
        ] {
            let gs = d.groups_of(cohort, &f).await.expect("groups_of");
            let ids: Vec<&str> = gs.iter().map(|g| g.group_key_id.as_str()).collect();
            assert!(
                ids.contains(&mine.as_str()) && !ids.contains(&other.as_str()),
                "I606: groups_of({}) lists {mine} and not {other}: {ids:?}",
                cohort.as_str()
            );
            assert!(
                gs.iter().all(|g| g.cohort == cohort),
                "I606: every group groups_of({}) lists reports that cohort: {gs:?}",
                cohort.as_str()
            );
        }
        // v62 (E3): the reverse_quorum objection leg is deleted
        // (`reverse_quorum` is refused in v62; RULINGS "Kernel departures").
    }

    /// **I593** — see the module doc.
    ///
    /// v62.0.0 (E3b) — edition 2 has ONE roster door (`group:roster` →
    /// `put_community`): a version addresses the cohort it declares, and the
    /// held record decides. The earlier pair of supersede doors collapses to
    /// a version labelled for the other cohort, both directions. The
    /// membership write-door legs (`add_member` / `revoke_member` addressed
    /// to the other cohort) are DELETED: a `membership:{stage}` row names its
    /// group and carries no cohort, so there is no wrong cohort to address.
    pub async fn i593_the_cohort_is_declared(d: &dyn FederationDirectory, tag: &str) {
        // The distinguishing part of an id LEADS (a test key, and its
        // identity-ref, seeds from its first 32 bytes).
        let (plain, aff) = (format!("plain-{tag}"), format!("aff-{tag}"));
        let (f, m) = (format!("founder-{tag}"), format!("member-{tag}"));
        users(d, &[&f, &m]).await;
        found(d, record(&plain, &[&f, &m], None))
            .await
            .expect("I593: a plain community founds");
        found(d, record(&aff, &[&f, &m], Some(affiliation_blob(None))))
            .await
            .expect("I593: an affiliation founds");

        // A plain community's version declaring `affiliations`.
        let mut p2 = next_version(d, &plain, "p2").await;
        p2.policy_blob = Some(affiliation_blob(None));
        expect_mismatch(
            supersede(d, &p2).await,
            "community",
            "affiliations",
            "I593: a plain community's version declaring `affiliations`",
        );
        // An affiliation's version declaring `community`: the held record
        // decides, not the new version's label.
        let mut relabel = next_version(d, &aff, "relabel").await;
        relabel.policy_blob = None;
        expect_mismatch(
            supersede(d, &relabel).await,
            "affiliations",
            "community",
            "I593: an affiliation's version relabelled as a community",
        );
        // Control: an affiliation's own version admits, and stays one.
        let a2 = next_version(d, &aff, "a2").await;
        supersede(d, &a2)
            .await
            .expect("I593: an affiliation's version declaring `affiliations` admits");
        let (plain_id, aff_id) = (e2::kid(&plain), e2::kid(&aff));
        assert_eq!(
            d.lookup_group(Cohort::Affiliations, &aff_id)
                .await
                .expect("I593: the affiliation reads under its cohort")
                .expect("I593: held")
                .cohort,
            Cohort::Affiliations,
            "I593: the superseded record still declares `affiliations`"
        );

        // An attestation placed at the wrong cohort_scope.
        expect_mismatch(
            place(d, placed_row(&m, cohort_scope::AFFILIATIONS, &plain_id)).await,
            "community",
            "affiliations",
            "I593: an affiliations-scoped row naming a plain community",
        );
        expect_mismatch(
            place(d, placed_row(&m, cohort_scope::COMMUNITY, &aff_id)).await,
            "affiliations",
            "community",
            "I593: a community-scoped row naming an affiliation",
        );
        place(d, placed_row(&m, cohort_scope::AFFILIATIONS, &aff_id))
            .await
            .expect("I593: a member's affiliations-scoped row naming the affiliation admits");
        place(d, placed_row(&m, cohort_scope::COMMUNITY, &plain_id))
            .await
            .expect("I593: a member's community-scoped row naming the community admits");

        // Founding: an unknown cohort, and a config on a plain community.
        expect_rule(
            found(
                d,
                record(
                    &format!("bogus-{tag}"),
                    &[&f],
                    Some(serde_json::json!({ ac::POLICY_COHORT_FIELD: "guild" })),
                ),
            )
            .await,
            rule::COHORT_UNKNOWN,
            "I593: an unknown declared cohort is refused, never read as community",
        );
        expect_rule(
            found(
                d,
                record(
                    &format!("cfg-{tag}"),
                    &[&f],
                    Some(serde_json::json!({ "affiliation_config": { "affiliation_archetype": "informal_adhoc" } })),
                ),
            )
            .await,
            rule::CONFIG_ON_COMMUNITY,
            "I593: a config on a plain community is refused",
        );
    }

    /// v62.0.0 (E3b, E13's pattern) — **what `from` serves `requester`** of
    /// the rows `rows`: every statement (each voice) of those rows on the
    /// FILTERED serve path (`edition2::serve::statements_served_to`; the
    /// store's raw since-read is never a serve surface), in `from`'s
    /// admission order.
    async fn served(
        from: &dyn FederationDirectory,
        requester: &str,
        rows: &[RowId],
    ) -> Vec<(Vec<u8>, RowId)> {
        let mut out = Vec::new();
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
            for st in page.statements {
                if let Some(id) = RowId::of_statement(&st.bytes) {
                    if rows.contains(&id) {
                        out.push((st.bytes, id));
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert!(
            !out.is_empty(),
            "{requester} is served the rows it asked for"
        );
        out
    }

    /// Each served statement through `to`'s replicated statement door
    /// (`apply_replicated_statement`), under the id it names.
    async fn deliver(
        to: &dyn FederationDirectory,
        statements: &[(Vec<u8>, RowId)],
    ) -> Vec<ReplicatedStatementOutcome> {
        let mut out = Vec::new();
        for (bytes, id) in statements {
            out.push(
                apply_replicated_statement(to, bytes, &id.0)
                    .await
                    .unwrap_or_else(|e| panic!("a replicated statement: {e}")),
            );
        }
        out
    }

    /// `voices` through `to`'s replicated statement door, in order; the
    /// first refusal (`Ok(())` when every voice was kept).
    async fn first_refusal(to: &dyn FederationDirectory, voices: &[Vec<u8>]) -> Result<(), Error> {
        for v in voices {
            apply_replicated_statement(to, v, &e2::row_id_of(v).0).await?;
        }
        Ok(())
    }

    /// **I595** — the replicated amendment path. A amends an affiliation by
    /// quorum; B applies A's served version and records the prior version
    /// under `affiliations` (it always wrote `community`). A version that
    /// relabels the held affiliation as a community is refused on the
    /// replicated door.
    ///
    /// v62.0.0 (E3b) — the amendment is an edition-2 roster version (T1.api
    /// §6): version 2 naming the founding by `refs.head`, one voice per
    /// signer of the prior roster. Short of the held `majority` it is
    /// `Pending` and the head does not move; the second voice lands it.
    /// Replication is A's statements served to B (requester: B's node key,
    /// else a member's identity-ref) into B's replicated statement door.
    pub async fn i595_a_replicated_affiliation_amendment(
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
        let id = format!("aff-{tag}");
        let gid = e2::kid(&id);
        let mut founding = record(&id, &refs, Some(affiliation_blob(None)));
        founding.consensus_protocol = consensus_protocol::MAJORITY.to_owned();
        for d in [a, b] {
            users(d, &refs).await;
        }
        // A founds: every listed member voices the founding roster.
        let founded_at = e2::ms(chrono::Utc::now() - chrono::Duration::minutes(10));
        let founding_voices = e2::community_voices(&signed(&founding), 1, None, founded_at);
        match e2::put_voices(a, &founding_voices).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{tag} I595: founding on A: {other:?}"),
        }
        let v1 = e2::row_id_of(&founding_voices[0]);

        // A's amendment: renamed, and the protocol moved to unanimous, voiced
        // by two of the three (the held majority).
        let mut v2 = next_version(a, &id, "renamed").await;
        v2.consensus_protocol = consensus_protocol::UNANIMOUS.to_owned();
        let (ka, kb) = (e2::signing_key(&keys[0]), e2::signing_key(&keys[1]));
        let amended_at = e2::ms(chrono::Utc::now());
        let v2_voices = e2::roster_voices(
            &GroupRecord::Community(e2::community_with_kids(&v2)),
            2,
            Some(&v1),
            amended_at,
            &[&ka, &kb],
        );
        match e2::put_voices(a, &v2_voices[..1]).await {
            Ok(StatementOutcome::Pending { .. }) => {}
            other => panic!("{tag} I595: one voice of three is short of majority: {other:?}"),
        }
        assert_eq!(
            e2::held_head(a, &gid).await.map(|(_, v)| v),
            Some(1),
            "{tag} I595: a short amendment does not move A's head"
        );
        match e2::put_voices(a, &v2_voices[1..]).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{tag} I595: the second voice lands A's amendment: {other:?}"),
        }
        let v2_id = e2::row_id_of(&v2_voices[0]);

        // B takes the founding A serves it.
        let requester = b.node_key_id().unwrap_or_else(|| e2::kid(&keys[0]));
        deliver(b, &served(a, &requester, &[v1]).await).await;
        assert!(
            b.lookup_community(&gid).await.unwrap().is_some(),
            "{tag} I595: B holds the affiliation"
        );

        // A relabelled copy of the same amendment: B holds an affiliation.
        let mut relabelled = v2.clone();
        relabelled.policy_blob = None;
        let relabel_voices = e2::roster_voices(
            &GroupRecord::Community(e2::community_with_kids(&relabelled)),
            2,
            Some(&v1),
            amended_at,
            &[&ka, &kb],
        );
        expect_mismatch(
            first_refusal(b, &relabel_voices).await,
            "affiliations",
            "community",
            "I595: a replicated version relabelling the affiliation",
        );

        // B applies A's amendment.
        let outs = deliver(b, &served(a, &requester, &[v2_id]).await).await;
        assert!(
            matches!(
                outs.last(),
                Some(ReplicatedStatementOutcome::Admitted(
                    StatementOutcome::Row { .. }
                ))
            ),
            "{tag} I595: B applies A's amendment: {outs:?}"
        );
        assert_eq!(
            e2::held_head(b, &gid).await.map(|(h, v)| (h == v2_id, v)),
            Some((true, 2)),
            "{tag} I595: B's head is A's amendment"
        );
        let aff = b
            .list_group_versions(Cohort::Affiliations, &gid)
            .await
            .unwrap();
        assert!(
            aff.iter().any(|v| v.version == 1 && !v.is_current),
            "{tag} I595: B recorded the prior version under `affiliations`: {aff:?}"
        );
        assert!(
            b.list_group_versions(Cohort::Community, &gid)
                .await
                .unwrap()
                .iter()
                .all(|v| v.is_current),
            "{tag} I595: and not under `community`"
        );
    }

    /// **I594 (door)** — an invalid config is refused at founding and on
    /// supersession; a valid one founds and resolves.
    pub async fn i594_the_config_is_checked_at_the_door(d: &dyn FederationDirectory, tag: &str) {
        let (aff, f, m) = (
            format!("aff-{tag}"),
            format!("founder-{tag}"),
            format!("member-{tag}"),
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
            "I594: founding with a role term past the one-year ceiling",
        );
        found(
            d,
            record(
                &aff,
                &[&f, &m],
                Some(affiliation_blob(Some(serde_json::json!({
                    "affiliation_archetype": "informal_adhoc",
                    "role_term": 90,
                    "compartments": [{ "name": "board", "members": [e2::kid(&f)] }],
                })))),
            ),
        )
        .await
        .expect("I594: a valid affiliation founds");
        let held = d.lookup_community(&e2::kid(&aff)).await.unwrap().unwrap();
        let resolved = ac::resolved_affiliation_config(&held)
            .unwrap()
            .expect("an affiliation resolves");
        assert_eq!(
            resolved.classification_scheme.classes[0].name,
            ac::DEFAULT_CLASS
        );
        let mut bad = next_version(d, &aff, "bad").await;
        bad.policy_blob = Some(affiliation_blob(Some(serde_json::json!({
            "compartments": [{ "name": "board", "members": [e2::kid(&format!("stranger-{tag}"))] }],
        }))));
        expect_rule(
            supersede(d, &bad).await,
            rule::COMPARTMENT_INVALID,
            "I594: a supersession naming a compartment member off the roster",
        );
    }

    /// **I594 (pure)** — resolution and every validation rule.
    pub fn i594_resolution_and_rules() {
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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn i594_pure() {
        super::bodies::i594_resolution_and_rules();
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test(flavor = "multi_thread")]
                async fn i592() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i592_affiliation_supersedes(
                        &d as &dyn FederationDirectory,
                        &format!("i592-{}", super::suffix()),
                    )
                    .await
                    .expect("I592: an affiliation supersedes");
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i593() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i593_the_cohort_is_declared(
                        &d as &dyn FederationDirectory,
                        &format!("i593-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i606() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i606_the_uniform_reads_are_cohort_checked(
                        &d as &dyn FederationDirectory,
                        &format!("i606-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i595() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i595_a_replicated_affiliation_amendment(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i595-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i594() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i594_the_config_is_checked_at_the_door(
                        &d as &dyn FederationDirectory,
                        &format!("i594-{}", super::suffix()),
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
