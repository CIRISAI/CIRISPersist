//! v53.1.5 — **I533–I536: the audience resolver's and the consent fold's
//! reads are bounded by what the fold can use, and answer exactly as the
//! whole-slice reads did.**
//!
//! CIRISServer's canonical node (0.5.222 / persist 53.1.4, ~22k federation
//! attestations over ~2.5k keys) sat ~500 MB above v52 at rest and grew with
//! state. Three reads loaded an unbounded row set and decoded every envelope
//! per call: `owner_allow_list` (every row the owner ever authored),
//! `is_public_group` (every row about the group) and the scoped consent fold
//! (every row about the target, twice per call, cloned per steward; the
//! scorer asked it once per agent per tick — +416 MB live).
//!
//! The v53.1.4 bodies are kept here VERBATIM as the oracles. Memory, sqlite,
//! postgres.
//!
//! - **I533** `owner_allow_list` equals its v53.1.4 body for every
//!   (owner, node) over a directory of live, superseded, withdrawn, recanted,
//!   lapsed and intersecting grants, grants for other nodes and other
//!   dimensions.
//! - **I534** `is_public_group` equals its v53.1.4 body across a named
//!   charter, an unnamed one, a recanted one, no charter, a key root with and
//!   without a live charter, a plain room, the accord family.
//! - **I535** boundedness: the whole-slice read probe records every
//!   `list_attestations_for` / `_by` with its key; no new door reads the
//!   owner, group or target slice; every v53.1.4 body does.
//! - **I536** `resolve_consent_state`, `resolve_scoped_stance` and
//!   `resolve_scoped_stance_by_principals` equal their v53.1.4 bodies across
//!   subjects, scopes, qualifiers, stewards, causal edges, recants, retain
//!   bounds and unrelated rows about the same target; and the same
//!   boundedness leg.

#[cfg(test)]
pub(crate) mod bodies {
    use std::collections::{BTreeSet, HashSet};

    use crate::federation::consent::{self, ScopedStance};
    use crate::federation::consent_grammar::{parse_grant_payload, CohortEntry, GRANT_DIMENSION};
    use crate::federation::hard_case::ConsentState;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::{
        admission, consent_by_humans as cbh, replication_audience as ra, Attestation, Error,
        FederationDirectory, SignedAttestation,
    };

    // ── the v53.1.4 bodies, verbatim ────────────────────────────────────

    /// `replication_audience::owner_allow_list` as v53.1.4 shipped it.
    pub async fn owner_allow_list_reference(
        dir: &dyn FederationDirectory,
        owner: &str,
        node: &str,
    ) -> Result<Option<BTreeSet<CohortEntry>>, Error> {
        let rows = dir.list_attestations_by(owner).await?;
        let retired: HashSet<&str> = rows
            .iter()
            .filter(|r| crate::federation::precedence::is_structural_composer(&r.attestation_type))
            .filter_map(|r| {
                crate::federation::precedence::references_attestation_id_from_envelope(
                    &r.attestation_envelope,
                )
            })
            .collect();
        let now = chrono::Utc::now();
        let mut acc: Option<BTreeSet<CohortEntry>> = None;
        for g in &rows {
            if g.attesting_key_id != owner
                || admission::envelope_dimension(&g.attestation_envelope) != Some(GRANT_DIMENSION)
                || cbh::for_key_id_of(&g.attestation_envelope) != Some(node)
                || retired.contains(g.attestation_id.as_str())
                || g.expires_at.is_some_and(|e| e <= now)
            {
                continue;
            }
            let Ok(policy) = parse_grant_payload(&g.attestation_envelope) else {
                continue;
            };
            if policy.valid_until.is_some_and(|v| v <= now) {
                continue;
            }
            if let Some(list) = policy.cohorts {
                let set: BTreeSet<CohortEntry> = list.into_iter().collect();
                acc = Some(match acc {
                    None => set,
                    Some(prev) => prev.intersection(&set).cloned().collect(),
                });
            }
        }
        Ok(acc)
    }

    /// `replication_audience::is_public_group` as v53.1.4 shipped it.
    pub async fn is_public_group_reference(
        dir: &dyn FederationDirectory,
        group: &str,
    ) -> Result<bool, Error> {
        if group == crate::federation::canonical_community::accord_family_key_id() {
            return Ok(true);
        }
        if crate::federation::ownership_reclaim::ReclaimPolicy::from_deployment_pin()
            .is_some_and(|p| p.wa_family_key_id == group)
        {
            return Ok(true);
        }
        match dir.lookup_community(group).await {
            Ok(Some(c)) => {
                if admission::is_authorized_infrastructure_community(dir, &c).await? {
                    return Ok(true);
                }
                if matches!(
                    crate::federation::canonical_community::stored_standing(dir, group).await?,
                    crate::federation::canonical_community::StoredStanding::Rooted(_)
                ) {
                    return Ok(true);
                }
            }
            Ok(None) | Err(Error::Unsupported { .. }) => {}
            Err(e) => return Err(e),
        }
        use crate::federation::canonical_community::{charter_in_force, HeadCharter};
        let named = match charter_in_force(dir, group).await?.1 {
            HeadCharter::Named(digest) => Some(digest),
            HeadCharter::KeyRoot => None,
            _ => return Ok(false),
        };
        let about = dir.list_attestations_for(group).await?;
        let refs: Vec<&Attestation> = about.iter().collect();
        let dead = crate::federation::precedence::retired_ids(&refs);
        Ok(about.iter().any(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attested_key_id == group
                && !dead.contains(&a.attestation_id)
                && admission::envelope_dimension(&a.attestation_envelope)
                    == Some(crate::federation::trust_root::TRUST_CHARTER_DIMENSION)
                && named.as_deref().is_none_or(|d| a.persist_row_hash == d)
        }))
    }

    /// The trait's default `resolve_consent_state` as v53.1.4 shipped it.
    pub async fn resolve_consent_state_reference(
        dir: &dyn FederationDirectory,
        target: &str,
        subject: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ConsentState, Error> {
        let rows = dir.list_attestations_for(target).await?;
        Ok(consent::fold_stance(&rows, subject, now, None))
    }

    /// The trait's default `resolve_scoped_stance` as v53.1.4 shipped it.
    pub async fn resolve_scoped_stance_reference(
        dir: &dyn FederationDirectory,
        target: &str,
        subject: &str,
        scope: &str,
        qualifier: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ScopedStance, Error> {
        let rows = dir.list_attestations_for(target).await?;
        Ok(consent::fold_scoped_stance(
            &rows, subject, now, scope, qualifier,
        ))
    }

    /// `consent_by_humans::resolve_scoped_stance_by_principals` as v53.1.4
    /// shipped it (its first read being the default above).
    pub async fn resolve_scoped_stance_by_principals_reference(
        dir: &dyn FederationDirectory,
        target: &str,
        subject: &str,
        scope: &str,
        qualifier: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ScopedStance, Error> {
        let mut folded = vec![
            resolve_scoped_stance_reference(dir, target, subject, scope, qualifier, now).await?,
        ];
        let stewards = admission::steward_bindings_of(dir, subject).await?;
        if !stewards.is_empty() {
            let rows = dir.list_attestations_for(target).await?;
            for p in &stewards {
                if p == subject {
                    continue;
                }
                let universe: Vec<Attestation> = rows
                    .iter()
                    .filter(|a| {
                        a.attesting_key_id != *p
                            || crate::federation::precedence::is_structural_composer(
                                &a.attestation_type,
                            )
                            || cbh::for_key_id_of(&a.attestation_envelope) == Some(subject)
                    })
                    .cloned()
                    .collect();
                folded.push(consent::fold_scoped_stance(
                    &universe, p, now, scope, qualifier,
                ));
            }
        }
        let stances: Vec<ConsentState> = folded.iter().map(|s| s.state).collect();
        Ok(ScopedStance {
            state: cbh::combine_principal_stances(&stances),
            retain_until: folded.iter().filter_map(|s| s.retain_until).min(),
        })
    }

    // ── fixtures ─────────────────────────────────────────────────────────

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        admission::truncate_to_substrate_resolution(s.parse().unwrap())
    }

    async fn keys(d: &dyn FederationDirectory, keys: &[(&str, &str)]) {
        for (k, t) in keys {
            ts::register_hybrid_key_as(d, k, k, t).await;
        }
    }

    async fn put(d: &dyn FederationDirectory, a: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .map(|_| ())
    }

    /// A `scores` row by `author` about `attested` carrying `env`, sealed.
    fn scores(
        author: &str,
        attested: &str,
        mut env: serde_json::Value,
        asserted: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        env["id"] = serde_json::Value::String(id.clone());
        let mut r = ts::bare_attestation(&id, author, attested, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = asserted;
        r.scrub_timestamp = asserted;
        ts::seal_row_in_place(author, &mut r);
        r
    }

    /// `author`'s `consent:replication:v1` grant, optionally FOR `for_key`,
    /// with `cohorts` / `valid_until` as given.
    fn grant(
        author: &str,
        for_key: Option<&str>,
        cohorts: Option<&[(&str, &str)]>,
        valid_until: Option<&str>,
    ) -> Attestation {
        let mut payload = serde_json::json!({
            "grants": "replication",
            "attestation_prefixes": ["i533:"],
        });
        if let Some(k) = for_key {
            payload["for_key_id"] = k.into();
        }
        if let Some(c) = cohorts {
            let mut v: Vec<(String, String)> = c
                .iter()
                .map(|(s, t)| ((*s).to_owned(), (*t).to_owned()))
                .collect();
            v.sort();
            payload["cohorts"] = serde_json::Value::Array(
                v.into_iter()
                    .map(|(s, t)| serde_json::json!({ "scope": s, "target": t }))
                    .collect(),
            );
        }
        if let Some(u) = valid_until {
            payload["valid_until"] = u.into();
        }
        scores(
            author,
            author,
            serde_json::json!({ "dimension": GRANT_DIMENSION, "payload": payload }),
            chrono::Utc::now(),
        )
    }

    /// A structural composer of `kind` by `author`, attested to `attested`,
    /// naming `target` in `references_attestation_id`.
    fn composer(author: &str, attested: &str, kind: &str, target: &Attestation) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "id": id,
            "references_attestation_id": target.attestation_id,
        });
        let mut r = ts::bare_attestation(&id, author, attested, &env);
        r.attestation_type = kind.to_owned();
        ts::seal_row_in_place(author, &mut r);
        r
    }

    /// `consent:state:<stance>:v1` by `subject` about `target` naming
    /// `scope` (a bare string or an array), optionally FOR `for_key`, with
    /// extra envelope members.
    fn state(
        subject: &str,
        target: &str,
        stance: &str,
        scope: serde_json::Value,
        for_key: Option<&str>,
        asserted: &str,
        extra: &[(&str, serde_json::Value)],
    ) -> Attestation {
        let mut env = serde_json::json!({
            "dimension": format!("consent:state:{stance}:v1"),
            "scope": scope,
        });
        if let Some(f) = for_key {
            env[cbh::FOR_KEY_ID] = serde_json::Value::String(f.to_owned());
        }
        for (k, v) in extra {
            env[*k] = v.clone();
        }
        scores(subject, target, env, at(asserted))
    }

    // ── I533 ─────────────────────────────────────────────────────────────

    /// The owners and nodes I533 compares over; every pair is asked.
    pub struct AllowCorpus {
        pub owners: Vec<String>,
        pub nodes: Vec<String>,
    }

    pub async fn seed_allow_corpus(d: &dyn FederationDirectory, s: &str) -> AllowCorpus {
        let owners: Vec<String> = (1..=5).map(|i| format!("i533-o{i}-{s}")).collect();
        let nodes: Vec<String> = (1..=3).map(|i| format!("i533-n{i}-{s}")).collect();
        let (o1, o2, o3, o4, o5) = (&owners[0], &owners[1], &owners[2], &owners[3], &owners[4]);
        let (n1, n2, n3) = (&nodes[0], &nodes[1], &nodes[2]);
        let mut reg: Vec<(&str, &str)> = owners.iter().map(|k| (k.as_str(), USER)).collect();
        reg.extend(nodes.iter().map(|k| (k.as_str(), NODE)));
        keys(d, &reg).await;

        // o1: two live lists FOR n1 (they intersect); a list-less grant FOR
        // n2; a grant FOR nobody; a listed grant FOR n3, withdrawn by o1.
        put(
            d,
            grant(
                o1,
                Some(n1),
                Some(&[("community", "r1"), ("family", "f1")]),
                None,
            ),
        )
        .await
        .unwrap();
        put(
            d,
            grant(
                o1,
                Some(n1),
                Some(&[("community", "r1"), ("community", "r2")]),
                None,
            ),
        )
        .await
        .unwrap();
        put(d, grant(o1, Some(n2), None, None)).await.unwrap();
        put(d, grant(o1, None, None, None)).await.unwrap();
        let g13 = grant(o1, Some(n3), Some(&[("community", "r9")]), None);
        put(d, g13.clone()).await.unwrap();
        put(d, composer(o1, o1, attestation_type::WITHDRAWS, &g13))
            .await
            .expect("o1 withdraws its own grant");

        // o2: a listed grant FOR n1 superseded by o2; a listed grant FOR n2
        // that stands.
        let g21 = grant(o2, Some(n1), Some(&[("community", "r1")]), None);
        put(d, g21.clone()).await.unwrap();
        let mut sup = grant(
            o2,
            Some(n1),
            Some(&[("community", "r1"), ("family", "f2")]),
            None,
        );
        sup.attestation_type = attestation_type::SUPERSEDES.to_owned();
        sup.attestation_envelope["references_attestation_id"] =
            serde_json::Value::String(g21.attestation_id.clone());
        ts::reseal(&mut sup);
        put(d, sup).await.expect("o2 supersedes its own grant");
        put(d, grant(o2, Some(n2), Some(&[("family", "f2")]), None))
            .await
            .unwrap();

        // o3: a listed grant FOR n1 whose policy lapsed (`valid_until` in the
        // past); an EMPTY list FOR n2; a live list FOR n3 beside an
        // unrelated consent:state row and an unrelated dimension.
        put(
            d,
            grant(
                o3,
                Some(n1),
                Some(&[("community", "r1")]),
                Some("2026-01-01T00:00:00Z"),
            ),
        )
        .await
        .unwrap();
        put(d, grant(o3, Some(n2), Some(&[]), None)).await.unwrap();
        put(d, grant(o3, Some(n3), Some(&[("community", "r3")]), None))
            .await
            .unwrap();
        put(
            d,
            state(
                o3,
                n3,
                "granted",
                "analyze".into(),
                Some(n3),
                "2026-06-01T00:00:00Z",
                &[],
            ),
        )
        .await
        .unwrap();
        put(
            d,
            scores(
                o3,
                o3,
                serde_json::json!({ "dimension": "config:i533:v1", "payload": { "for_key_id": n3 } }),
                chrono::Utc::now(),
            ),
        )
        .await
        .unwrap();

        // o4: a listed grant FOR n1, recanted by o4.
        let g41 = grant(o4, Some(n1), Some(&[("community", "r4")]), None);
        put(d, g41.clone()).await.unwrap();
        put(d, composer(o4, o4, attestation_type::RECANTS, &g41))
            .await
            .expect("o4 recants its own grant");

        // o5: a listed grant FOR n1 — another owner's, invisible to o1..o4.
        put(d, grant(o5, Some(n1), Some(&[("community", "r5")]), None))
            .await
            .unwrap();
        AllowCorpus { owners, nodes }
    }

    fn set(pairs: &[(&str, &str)]) -> BTreeSet<CohortEntry> {
        pairs
            .iter()
            .map(|(s, t)| CohortEntry {
                scope: (*s).to_owned(),
                target: (*t).to_owned(),
            })
            .collect()
    }

    /// **I533** — `owner_allow_list` equals its v53.1.4 body for every
    /// (owner, node), and the literal expectations hold.
    pub async fn i533_owner_allow_list_matches_the_whole_slice_body(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let c = seed_allow_corpus(d, s).await;
        let nobody = format!("i533-nobody-{s}");
        let mut asked = 0usize;
        for o in &c.owners {
            for n in c.nodes.iter().chain(std::iter::once(&nobody)) {
                let new = ra::owner_allow_list(d, o, n).await.unwrap();
                let old = owner_allow_list_reference(d, o, n).await.unwrap();
                assert_eq!(new, old, "I533: {o} → {n}");
                asked += 1;
            }
        }
        assert_eq!(asked, 20);
        let (o1, o2, o3, o4) = (&c.owners[0], &c.owners[1], &c.owners[2], &c.owners[3]);
        let (n1, n2, n3) = (&c.nodes[0], &c.nodes[1], &c.nodes[2]);
        assert_eq!(
            ra::owner_allow_list(d, o1, n1).await.unwrap(),
            Some(set(&[("community", "r1")])),
            "I533: two live lists intersect"
        );
        assert_eq!(
            ra::owner_allow_list(d, o1, n2).await.unwrap(),
            None,
            "no cohorts member"
        );
        assert_eq!(
            ra::owner_allow_list(d, o1, n3).await.unwrap(),
            None,
            "withdrawn"
        );
        assert_eq!(
            ra::owner_allow_list(d, o2, n1).await.unwrap(),
            Some(set(&[("community", "r1"), ("family", "f2")])),
            "I533: the superseding row stands, the superseded one is retired"
        );
        assert_eq!(
            ra::owner_allow_list(d, o3, n1).await.unwrap(),
            None,
            "lapsed policy"
        );
        assert_eq!(
            ra::owner_allow_list(d, o3, n2).await.unwrap(),
            Some(set(&[])),
            "empty list"
        );
        assert_eq!(
            ra::owner_allow_list(d, o4, n1).await.unwrap(),
            None,
            "recanted"
        );
    }

    // ── I534 ─────────────────────────────────────────────────────────────

    /// A `trust:charter:v1` `delegates_to` toward `root`, attested by `a`
    /// and co-signed by `b`.
    fn charter(id: &str, root: &str, a: &str, b: &str) -> Attestation {
        use crate::federation::trust_root::{
            test_pre_rotation_commitment, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
            TRUST_CHARTER_DIMENSION,
        };
        let env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": test_pre_rotation_commitment(&[
                format!("{root}-succ-a"),
                format!("{root}-succ-b"),
            ])
            .unwrap(),
        });
        crate::federation::accord_test_support::co_signed_trust_attestation(
            id,
            a,
            root,
            attestation_type::DELEGATES_TO,
            env,
            &[b],
        )
    }

    /// Point `fid`'s head at `digest`.
    async fn name_charter(d: &dyn FederationDirectory, fid: &str, a: &str, digest: String) {
        let held = d.lookup_family(fid).await.unwrap().unwrap();
        let signed = crate::federation::types::SignedFamily {
            family: {
                let mut f = held.clone();
                f.persist_row_hash = String::new();
                f.prev_head_digest = held.persist_row_hash.clone();
                f.charter_digest = digest;
                f
            },
            authority_key_id: a.to_owned(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            supersede_proof: None,
            cosignatures: Vec::new(),
        };
        d.supersede_group_row(
            crate::federation::cohort::Cohort::Family,
            serde_json::to_value(&signed).unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("I534: the naming version of {fid}: {e}"));
    }

    /// The groups I534 asks about, with their expected answer where one is
    /// pinned.
    pub async fn seed_group_corpus(
        d: &dyn FederationDirectory,
        s: &str,
    ) -> Vec<(String, Option<bool>)> {
        use crate::federation::replication_audience_invariants::bodies as rab;
        let (a, b) = (format!("i534-a-{s}"), format!("i534-b-{s}"));
        rab::users(d, &[&a, &b]).await;
        let mut out: Vec<(String, Option<bool>)> = Vec::new();

        // fam1: a charter the head names — public.
        let fam1 = format!("i534-fam1-{s}");
        rab::family(d, &fam1, &[&a, &b]).await;
        let c1 = charter(&format!("i534-c1-{s}"), &fam1, &a, &b);
        put(d, c1.clone()).await.expect("fam1 charter");
        let digest = d
            .get_attestation(&c1.attestation_id)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        name_charter(d, &fam1, &a, digest).await;
        out.push((fam1, Some(true)));

        // fam2: a charter the head does NOT name — private.
        let fam2 = format!("i534-fam2-{s}");
        rab::family(d, &fam2, &[&a, &b]).await;
        put(d, charter(&format!("i534-c2-{s}"), &fam2, &a, &b))
            .await
            .expect("fam2 charter");
        out.push((fam2, Some(false)));

        // fam3: a named charter, recanted by its attester — private again.
        let fam3 = format!("i534-fam3-{s}");
        rab::family(d, &fam3, &[&a, &b]).await;
        let c3 = charter(&format!("i534-c3-{s}"), &fam3, &a, &b);
        put(d, c3.clone()).await.expect("fam3 charter");
        let digest = d
            .get_attestation(&c3.attestation_id)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        name_charter(d, &fam3, &a, digest).await;
        put(d, composer(&a, &fam3, attestation_type::RECANTS, &c3))
            .await
            .expect("fam3 charter recanted");
        out.push((fam3, Some(false)));

        // fam4: no charter.
        let fam4 = format!("i534-fam4-{s}");
        rab::family(d, &fam4, &[&a, &b]).await;
        out.push((fam4, Some(false)));

        // k1: a key root with a live charter row — public; k2: the same,
        // recanted; k3: a bare key.
        let (k1, k2, k3) = (
            format!("i534-k1-{s}"),
            format!("i534-k2-{s}"),
            format!("i534-k3-{s}"),
        );
        rab::users(d, &[&k1, &k2, &k3]).await;
        put(d, charter(&format!("i534-ck1-{s}"), &k1, &a, &b))
            .await
            .expect("k1 charter");
        let ck2 = charter(&format!("i534-ck2-{s}"), &k2, &a, &b);
        put(d, ck2.clone()).await.expect("k2 charter");
        put(d, composer(&a, &k2, attestation_type::RECANTS, &ck2))
            .await
            .expect("k2 charter recanted");
        out.push((k1, Some(true)));
        out.push((k2, Some(false)));
        out.push((k3, Some(false)));

        // A plain room, and the accord family.
        let room = format!("i534-room-{s}");
        rab::room(d, &room, &[&a]).await;
        out.push((room, Some(false)));
        out.push((
            crate::federation::canonical_community::accord_family_key_id().to_owned(),
            Some(true),
        ));
        out
    }

    /// **I534** — `is_public_group` equals its v53.1.4 body for every group.
    pub async fn i534_is_public_group_matches_the_whole_slice_body(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let groups = seed_group_corpus(d, s).await;
        for (g, expect) in &groups {
            let new = ra::is_public_group(d, g).await.unwrap();
            let old = is_public_group_reference(d, g).await.unwrap();
            assert_eq!(new, old, "I534: {g}");
            if let Some(e) = expect {
                assert_eq!(new, *e, "I534: {g}");
            }
        }
    }

    // ── I536 ─────────────────────────────────────────────────────────────

    pub struct ConsentCorpus {
        pub target: String,
        pub subjects: Vec<String>,
    }

    pub async fn seed_consent_corpus(d: &dyn FederationDirectory, s: &str) -> ConsentCorpus {
        let target = format!("i536-canon-{s}");
        let alice = format!("i536-alice-{s}");
        let node = format!("i536-node-{s}");
        let agent = format!("i536-agent-{s}");
        let bob = format!("i536-bob-{s}");
        let carol = format!("i536-carol-{s}");
        let dave = format!("i536-dave-{s}");
        let other = format!("i536-other-{s}");
        keys(
            d,
            &[
                (&target, NODE),
                (&alice, USER),
                (&node, NODE),
                (&agent, AGENT),
                (&bob, USER),
                (&carol, USER),
                (&dave, USER),
                (&other, NODE),
            ],
        )
        .await;
        // alice stewards the node (owner binding) and the agent (occurrence).
        put(
            d,
            ts::owner_binding_attestation(&format!("i536-ob-{s}"), &alice, &node),
        )
        .await
        .unwrap();
        d.put_identity_occurrence_local(crate::federation::IdentityOccurrence {
            identity_key_id: alice.clone(),
            occurrence_key_id: agent.clone(),
            device_class: "agent".to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("occurrence row");

        // The node's own legacy grant; alice's analyze grant FOR the node,
        // then her revocation naming it on the causal plane; alice's view
        // grant FOR the agent; alice's analyze grant naming nobody.
        put(
            d,
            state(
                &node,
                &target,
                "granted",
                "analyze".into(),
                None,
                "2026-05-01T00:00:00Z",
                &[],
            ),
        )
        .await
        .unwrap();
        let ga = state(
            &alice,
            &target,
            "granted",
            "analyze".into(),
            Some(&node),
            "2026-06-01T00:00:00Z",
            &[],
        );
        put(d, ga.clone()).await.unwrap();
        put(
            d,
            state(
                &alice,
                &target,
                "revoked",
                "analyze".into(),
                Some(&node),
                "2026-06-02T00:00:00Z",
                &[(
                    crate::federation::envelope::paths::CONSENT_SUPERSEDES,
                    serde_json::Value::String(ga.attestation_id.clone()),
                )],
            ),
        )
        .await
        .unwrap();
        put(
            d,
            state(
                &alice,
                &target,
                "granted",
                serde_json::json!(["view", "analyze"]),
                Some(&agent),
                "2026-06-03T00:00:00Z",
                &[],
            ),
        )
        .await
        .unwrap();
        put(
            d,
            state(
                &alice,
                &target,
                "granted",
                "analyze".into(),
                None,
                "2026-06-04T00:00:00Z",
                &[],
            ),
        )
        .await
        .unwrap();

        // bob: a retain-bounded grant long past its window.
        put(
            d,
            state(
                &bob,
                &target,
                "granted",
                serde_json::json!(["analyze", "retain:1d"]),
                None,
                "2026-04-01T00:00:00Z",
                &[],
            ),
        )
        .await
        .unwrap();

        // carol: a grant, recanted by carol (attested to the target).
        let gc = state(
            &carol,
            &target,
            "granted",
            "analyze".into(),
            None,
            "2026-05-10T00:00:00Z",
            &[],
        );
        put(d, gc.clone()).await.unwrap();
        put(d, composer(&carol, &target, attestation_type::RECANTS, &gc))
            .await
            .expect("carol recants her own grant");

        // dave: a class-qualified grant, and a blanket revoke of `view`.
        put(
            d,
            state(
                &dave,
                &target,
                "granted",
                "analyze".into(),
                None,
                "2026-05-10T00:00:00Z",
                &[("content_class", "x".into())],
            ),
        )
        .await
        .unwrap();
        put(
            d,
            state(
                &dave,
                &target,
                "revoked",
                "view".into(),
                None,
                "2026-05-11T00:00:00Z",
                &[],
            ),
        )
        .await
        .unwrap();

        // Unrelated rows about the same target: the target's own self-reports
        // (CC 3.4.5: a `config:*` row is attested by its subject), a
        // `consent:` dimension outside `consent:state:`, and a consent row
        // about ANOTHER target by alice.
        for i in 0..5 {
            put(
                d,
                scores(
                    &target,
                    &target,
                    serde_json::json!({ "dimension": format!("config:i536-{i}:v1"), "n": i }),
                    chrono::Utc::now(),
                ),
            )
            .await
            .unwrap();
        }
        // A `consent:` row outside `consent:state:` about the target — the
        // canonical's ~3.2k `consent:community_trust:v1` rows are this shape
        // (CC 3.3.1: the node's own row, admitted only under a held owner
        // binding — alice's).
        put(
            d,
            ts::owner_binding_attestation(&format!("i536-obt-{s}"), &alice, &target),
        )
        .await
        .unwrap();
        let mut ct = scores(
            &target,
            &target,
            serde_json::json!({
                "dimension": crate::federation::community_trust_consent::COMMUNITY_TRUST_DIMENSION,
                "score": 1.0,
            }),
            chrono::Utc::now(),
        );
        ct.subject_key_ids = vec![alice.clone(), bob.clone()];
        ts::reseal(&mut ct);
        put(d, ct)
            .await
            .expect("a community_trust row about the target");
        put(
            d,
            state(
                &alice,
                &other,
                "revoked",
                "analyze".into(),
                Some(&node),
                "2026-06-05T00:00:00Z",
                &[],
            ),
        )
        .await
        .unwrap();

        ConsentCorpus {
            target,
            subjects: vec![
                node,
                agent,
                alice,
                bob,
                carol,
                dave,
                other,
                format!("i536-nobody-{s}"),
            ],
        }
    }

    /// **I536** — the three consent doors equal their v53.1.4 bodies for
    /// every subject × scope × qualifier, and the literal expectations hold.
    pub async fn i536_consent_doors_match_the_whole_slice_bodies(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let c = seed_consent_corpus(d, s).await;
        let now = chrono::Utc::now();
        let t = c.target.as_str();
        let mut asked = 0usize;
        for subject in &c.subjects {
            let new = d.resolve_consent_state(t, subject, now).await.unwrap();
            let old = resolve_consent_state_reference(d, t, subject, now)
                .await
                .unwrap();
            assert_eq!(new, old, "I536 unscoped: {subject}");
            for scope in ["analyze", "view", "share:cohort:x"] {
                for qualifier in [None, Some("x")] {
                    let new = d
                        .resolve_scoped_stance(t, subject, scope, qualifier, now)
                        .await
                        .unwrap();
                    let old = resolve_scoped_stance_reference(d, t, subject, scope, qualifier, now)
                        .await
                        .unwrap();
                    assert_eq!(new, old, "I536 scoped: {subject} {scope} {qualifier:?}");
                    let new = cbh::resolve_scoped_stance_by_principals(
                        d, t, subject, scope, qualifier, now,
                    )
                    .await
                    .unwrap();
                    let old = resolve_scoped_stance_by_principals_reference(
                        d, t, subject, scope, qualifier, now,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        new, old,
                        "I536 by principals: {subject} {scope} {qualifier:?}"
                    );
                    asked += 1;
                }
            }
        }
        assert_eq!(asked, 48);
        let (node, agent, bob, carol) = (
            &c.subjects[0],
            &c.subjects[1],
            &c.subjects[3],
            &c.subjects[4],
        );
        let by = |subject: &String, scope: &'static str| {
            let subject = subject.clone();
            async move {
                cbh::resolve_scoped_consent_by_principals(d, t, &subject, scope, None, now)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            by(node, "analyze").await,
            ConsentState::Revoked,
            "alice's revoke stops the node"
        );
        assert_eq!(
            by(agent, "view").await,
            ConsentState::Granted,
            "alice's grant covers the agent"
        );
        assert_eq!(by(agent, "analyze").await, ConsentState::Granted);
        assert_ne!(
            by(bob, "analyze").await,
            ConsentState::Revoked,
            "bob's retain-bounded grant is not a refusal"
        );
        assert_ne!(
            by(carol, "analyze").await,
            ConsentState::Granted,
            "a recanted grant does not grant"
        );
    }

    // ── I535 — boundedness ───────────────────────────────────────────────

    /// The whole-slice reads a door made over `key`, from the probe.
    fn slice_reads_over(
        log: &[(&'static str, String, usize)],
        method: &str,
        key: &str,
    ) -> Vec<usize> {
        log.iter()
            .filter(|(m, k, _)| *m == method && k == key)
            .map(|(_, _, n)| *n)
            .collect()
    }

    /// **I535** — no new door reads the whole slice it used to: the probe
    /// ([`crate::federation::read_probe`]) records every
    /// `list_attestations_for` / `list_attestations_by` with its key, and
    /// across every door call none is keyed on the owner (allow list), the
    /// group (public group) or the target (consent). The v53.1.4 bodies, run
    /// on the same directory, DO make those reads — the probe is armed, and
    /// this is the red the old code shows.
    pub async fn i535_the_bounded_reads_never_touch_the_whole_slice(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::read_probe;
        let allow = seed_allow_corpus(d, s).await;
        let groups = seed_group_corpus(d, s).await;
        let consent = seed_consent_corpus(d, s).await;
        let now = chrono::Utc::now();

        let _ = read_probe::take();
        for o in &allow.owners {
            for n in &allow.nodes {
                ra::owner_allow_list(d, o, n).await.unwrap();
                let log = read_probe::take();
                assert!(
                    slice_reads_over(&log, "list_attestations_by", o).is_empty(),
                    "I535: owner_allow_list({o}, {n}) read the owner's whole slice: {log:?}"
                );
                owner_allow_list_reference(d, o, n).await.unwrap();
                let log = read_probe::take();
                assert!(
                    !slice_reads_over(&log, "list_attestations_by", o).is_empty(),
                    "I535: the v53.1.4 body reads the owner's whole slice — the probe is armed"
                );
            }
        }
        for (g, _) in &groups {
            ra::is_public_group(d, g).await.unwrap();
            let log = read_probe::take();
            assert!(
                slice_reads_over(&log, "list_attestations_for", g).is_empty(),
                "I535: is_public_group({g}) read the group's whole slice: {log:?}"
            );
        }
        // The reference reads the slice only past the config / community
        // arms; a family with a charter reaches it.
        is_public_group_reference(d, &groups[0].0).await.unwrap();
        let log = read_probe::take();
        assert!(
            !slice_reads_over(&log, "list_attestations_for", &groups[0].0).is_empty(),
            "I535: the v53.1.4 is_public_group reads the group's whole slice — the probe is armed"
        );
        let t = consent.target.as_str();
        for subject in &consent.subjects {
            for scope in ["analyze", "view"] {
                cbh::resolve_scoped_stance_by_principals(d, t, subject, scope, None, now)
                    .await
                    .unwrap();
                d.resolve_scoped_stance(t, subject, scope, None, now)
                    .await
                    .unwrap();
                d.resolve_consent_state(t, subject, now).await.unwrap();
                let log = read_probe::take();
                assert!(
                    slice_reads_over(&log, "list_attestations_for", t).is_empty(),
                    "I535: the consent doors ({subject}, {scope}) read the target's whole \
                     slice: {log:?}"
                );
                resolve_scoped_stance_by_principals_reference(d, t, subject, scope, None, now)
                    .await
                    .unwrap();
                let log = read_probe::take();
                assert!(
                    !slice_reads_over(&log, "list_attestations_for", t).is_empty(),
                    "I535: the v53.1.4 consent body reads the target's whole slice — the probe \
                     is armed"
                );
            }
        }
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! case {
                    ($name:ident, $body:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$body(&d as &dyn FederationDirectory, &suffix())
                                .await
                        }
                    };
                }
                case!(i533, i533_owner_allow_list_matches_the_whole_slice_body);
                case!(i534, i534_is_public_group_matches_the_whole_slice_body);
                case!(i535, i535_the_bounded_reads_never_touch_the_whole_slice);
                case!(i536, i536_consent_doors_match_the_whole_slice_bodies);
            }
        };
    }

    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

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
