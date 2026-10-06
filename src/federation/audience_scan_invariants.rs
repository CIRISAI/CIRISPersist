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
//! - **I537** sized: at the canonical's shape (2,461 rows about the target,
//!   ~15 KB envelopes; a 330-row author; a 500-row root) the new doors
//!   return a handful of rows and under 1% of the bytes the v53.1.4 bodies
//!   read — asserted as rows and envelope bytes, never wall time.
//! - **I538** the scorer's pass at the canonical's shape (sqlite, postgres):
//!   900 agents over a node with ~2,400 rows about it; no call reads the
//!   node's slice, the pass decodes under 5% of what the v53.1.4 bodies
//!   decode.

#[cfg(test)]
pub(crate) mod bodies {
    use std::collections::{BTreeSet, HashSet};

    use crate::federation::consent::{self, ScopedStance};
    use crate::federation::consent_grammar::{parse_grant_payload, CohortEntry, GRANT_DIMENSION};
    use crate::federation::hard_case::ConsentState;
    use crate::federation::read_probe;
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
    /// The whole-slice reads a door made over `key`, from the probe.
    fn slice_reads_over(log: &[read_probe::Read], method: &str, key: &str) -> Vec<usize> {
        log.iter()
            .filter(|r| r.method == method && r.key == key)
            .map(|r| r.rows)
            .collect()
    }

    /// (rows, bytes) returned by every read keyed on `key`, whatever the method.
    fn reads_keyed_on(log: &[read_probe::Read], key: &str) -> (usize, usize) {
        log.iter()
            .filter(|r| r.key == key)
            .fold((0, 0), |(r, b), x| (r + x.rows, b + x.bytes))
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

    // ── I537 — sized ─────────────────────────────────────────────────────

    /// ~15 KB of envelope, the canonical's agent-authored average (15.3 KB).
    fn blob(i: usize) -> String {
        format!("{i:08}:").repeat(15 * 1024 / 9)
    }

    /// `put`, waiting out the untracked-tail byte quota (v24.3.0): fresh
    /// keys share one tail bucket, and a corpus this size refuses with
    /// "retry after 1s" — the quota is the door's, not this witness's.
    async fn put_patiently(d: &dyn FederationDirectory, row: Attestation, what: &str) {
        for attempt in 0..120 {
            match put(d, row.clone()).await {
                Ok(()) => return,
                Err(e) if e.to_string().contains("rate limited") && attempt < 119 => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(e) => panic!("{what}: {e}"),
            }
        }
    }

    /// `n` self-reports by `k` about `k`, one per leaf, each ~15 KB (the
    /// renewal rule re-reads the attester's live rows per put, so this is
    /// for the hundreds, not the thousands).
    async fn bulk_self_reports(d: &dyn FederationDirectory, k: &str, tag: &str, n: usize) {
        for i in 0..n {
            put_patiently(
                d,
                scores(
                    k,
                    k,
                    serde_json::json!({ "dimension": format!("config:{tag}-{i}:v1"), "blob": blob(i) }),
                    chrono::Utc::now(),
                ),
                &format!("I537 bulk row {i} for {k}"),
            )
            .await;
        }
    }

    /// `n` rows about `target`, each a `consent:state:granted` statement
    /// (~15 KB) from its own registered user — the shape of the thousands
    /// of rows a node accumulates from the people and agents it serves.
    async fn bulk_rows_about(d: &dyn FederationDirectory, target: &str, tag: &str, n: usize) {
        for i in 0..n {
            let u = format!("{tag}-u{i}");
            ts::register_hybrid_key_as(d, &u, &u, USER).await;
            let row = state(
                &u,
                target,
                "granted",
                "view".into(),
                None,
                "2026-03-01T00:00:00Z",
                &[("blob", blob(i).into())],
            );
            put_patiently(d, row, &format!("I537 bulk row {i} about {target}")).await;
        }
    }

    /// **I537** — the bounds at the canonical's shape. Rows attested to the
    /// consent target: 2,461 (the canonical-1 count), ~15 KB each; the allow
    /// list's owner: 330 authored rows (~5 MB, the largest single author);
    /// a key root with 500 rows about it. Asserted as ROWS and ENVELOPE
    /// BYTES returned by every read keyed on the target / owner / root,
    /// relative to the bounded set — never wall time. The v53.1.4 bodies
    /// read the whole slice back; the new doors read a handful of rows.
    pub async fn i537_sized_reads_are_bounded_by_the_set_the_fold_uses(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let now = chrono::Utc::now();
        // (a) the consent target: the small corpus (13 rows about T, of
        // which the node's principals own 4 consent:state rows) plus the
        // canonical's bulk — strangers' consent rows to 2,461 rows about T.
        let consent = seed_consent_corpus(d, s).await;
        let t = consent.target.as_str();
        let node = consent.subjects[0].as_str();
        bulk_rows_about(d, t, "i537t", 2_461 - 13).await;
        // (b) the allow list's owner: 330 authored rows beside one grant.
        let (owner, dev) = (format!("i537-owner-{s}"), format!("i537-dev-{s}"));
        keys(d, &[(&owner, USER), (&dev, NODE)]).await;
        bulk_self_reports(d, &owner, "i537o", 330).await;
        put(
            d,
            grant(&owner, Some(&dev), Some(&[("community", "r1")]), None),
        )
        .await
        .unwrap();
        // (c) a key root with a live charter among 500 rows about it.
        let (root, a, b) = (
            format!("i537-root-{s}"),
            format!("i537-a-{s}"),
            format!("i537-b-{s}"),
        );
        keys(d, &[(&root, USER), (&a, USER), (&b, USER)]).await;
        put(d, charter(&format!("i537-charter-{s}"), &root, &a, &b))
            .await
            .expect("I537 charter");
        bulk_rows_about(d, &root, "i537r", 500).await;

        let _ = read_probe::take();

        // The consent doors for the node.
        cbh::resolve_scoped_stance_by_principals(d, t, node, "analyze", None, now)
            .await
            .unwrap();
        d.resolve_scoped_stance(t, node, "analyze", None, now)
            .await
            .unwrap();
        d.resolve_consent_state(t, node, now).await.unwrap();
        let (new_rows, new_bytes) = reads_keyed_on(&read_probe::take(), t);
        resolve_scoped_stance_by_principals_reference(d, t, node, "analyze", None, now)
            .await
            .unwrap();
        let (old_rows, old_bytes) = reads_keyed_on(&read_probe::take(), t);
        eprintln!(
            "I537 consent (three doors, one call each) keyed on the target: new {new_rows} rows / \
             {new_bytes} bytes; v53.1.4 by-principals alone {old_rows} rows / {old_bytes} bytes"
        );
        assert!(
            old_rows >= 2 * 2_461,
            "the v53.1.4 body reads the slice twice: {old_rows}"
        );
        assert!(
            new_rows <= 3 * 6,
            "three doors × (the node's and alice's consent rows + nothing else): {new_rows}"
        );
        assert!(
            new_bytes * 100 < old_bytes,
            "new {new_bytes} bytes is not under 1% of the v53.1.4 {old_bytes}"
        );

        // The allow list for the owner's device.
        assert_eq!(
            ra::owner_allow_list(d, &owner, &dev).await.unwrap(),
            Some(set(&[("community", "r1")]))
        );
        let (new_rows, new_bytes) = reads_keyed_on(&read_probe::take(), &owner);
        owner_allow_list_reference(d, &owner, &dev).await.unwrap();
        let (old_rows, old_bytes) = reads_keyed_on(&read_probe::take(), &owner);
        eprintln!(
            "I537 owner_allow_list keyed on the owner: new {new_rows} rows / {new_bytes} bytes; \
             v53.1.4 {old_rows} rows / {old_bytes} bytes"
        );
        assert!(old_rows >= 331, "{old_rows}");
        assert_eq!(new_rows, 1, "the one grant, and no composer");
        assert!(new_bytes * 100 < old_bytes, "{new_bytes} vs {old_bytes}");

        // The key root.
        assert!(ra::is_public_group(d, &root).await.unwrap());
        let (new_rows, new_bytes) = reads_keyed_on(&read_probe::take(), &root);
        is_public_group_reference(d, &root).await.unwrap();
        let (old_rows, old_bytes) = reads_keyed_on(&read_probe::take(), &root);
        eprintln!(
            "I537 is_public_group keyed on the root: new {new_rows} rows / {new_bytes} bytes; \
             v53.1.4 {old_rows} rows / {old_bytes} bytes"
        );
        assert!(old_rows >= 501, "{old_rows}");
        assert_eq!(new_rows, 1, "the one charter row, and no composer");
        assert!(new_bytes * 100 < old_bytes, "{new_bytes} vs {old_bytes}");
    }

    // ── I538 — the scorer's pass at the canonical's shape ────────────────

    /// The totals one scorer pass decoded, from the probe.
    #[derive(Default, Debug, Clone, Copy)]
    pub struct PassTotals {
        pub rows: usize,
        pub bytes: usize,
        /// Rows returned by reads keyed on the target node, summed.
        pub rows_keyed_on_target: usize,
        /// The largest single call's rows keyed on the target.
        pub max_rows_keyed_on_target_per_agent: usize,
    }

    /// **I538** — the scorer's per-pass sequence at the canonical's shape
    /// (CIRISServer's capped run: the FIRST pass took the node from 110 MB
    /// to 2,040 MB in ~40 s). The target node T carries ~2,400 rows about
    /// it (every agent's `analyze` consent, the stewards' FOR grants, T's
    /// `consent:community_trust` rows, T's own config self-reports); 20
    /// stewards; 900 agents, each an occurrence of a steward, each with a
    /// 15 KB capacity score from T. Per agent the scorer asks
    /// `resolve_scoped_consent_by_principals(T, agent, "analyze")` and
    /// `list_attestations(attested = agent, type = scores, prefix
    /// `capacity:`, limit 512)`; once per pass `list_trace_summaries`.
    /// Asserted from the probe: no call reads T's slice (every read keyed
    /// on T returns the agent's / its steward's consent rows only), and the
    /// pass's rows keyed on T are a small multiple of the agent count. The
    /// v53.1.4 bodies run on a 1-in-10 sample for the comparison.
    pub async fn i538_the_scorers_pass_reads_each_agents_slice_not_the_nodes<B>(d: &B, s: &str)
    where
        B: FederationDirectory + crate::read::ReadEngine + Sync,
    {
        const AGENTS: usize = 900;
        const STEWARDS: usize = 20;
        let now = chrono::Utc::now();
        let t = format!("i538-canon-{s}");
        let stewards: Vec<String> = (0..STEWARDS).map(|i| format!("i538-s{i}-{s}")).collect();
        let agents: Vec<String> = (0..AGENTS).map(|i| format!("i538-a{i}-{s}")).collect();
        let mut reg: Vec<(&str, &str)> = vec![(t.as_str(), NODE)];
        reg.extend(stewards.iter().map(|k| (k.as_str(), USER)));
        reg.extend(agents.iter().map(|k| (k.as_str(), AGENT)));
        keys(d, &reg).await;
        // T's owner (its community_trust rows need a held binding).
        put_patiently(
            d,
            ts::owner_binding_attestation(&format!("i538-ob-{s}"), &stewards[0], &t),
            "I538 owner binding",
        )
        .await;
        let started = std::time::Instant::now();
        for (i, a) in agents.iter().enumerate() {
            let steward = &stewards[i % STEWARDS];
            d.put_identity_occurrence_local(crate::federation::IdentityOccurrence {
                identity_key_id: steward.clone(),
                occurrence_key_id: a.clone(),
                device_class: "agent".to_owned(),
                hardware_attestation: None,
                asserted_at: now,
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .expect("occurrence row");
            // The agent's own analyze consent to T — what lets T score it.
            put_patiently(
                d,
                state(
                    a,
                    &t,
                    "granted",
                    "analyze".into(),
                    None,
                    "2026-05-01T00:00:00Z",
                    &[],
                ),
                "I538 agent consent",
            )
            .await;
            // Every third agent: its steward's grant FOR it, too.
            if i % 3 == 0 {
                put_patiently(
                    d,
                    state(
                        steward,
                        &t,
                        "granted",
                        "analyze".into(),
                        Some(a),
                        "2026-05-02T00:00:00Z",
                        &[],
                    ),
                    "I538 steward grant",
                )
                .await;
            }
            // T's 15 KB capacity score about the agent (CC#46: admitted under
            // the agent's live analyze consent covering T).
            let mut score = scores(
                &t,
                a,
                serde_json::json!({ "dimension": "capacity:core_identity:v1", "score": 0.5, "blob": blob(i) }),
                now,
            );
            score.subject_key_ids = vec![a.clone()];
            ts::reseal(&mut score);
            put_patiently(d, score, "I538 capacity score").await;
        }
        // T's community_trust rows (100) and self-reports (1,100): the rest
        // of the ~2,400 rows about it.
        for i in 0..100 {
            let mut ct = scores(
                &t,
                &t,
                serde_json::json!({
                    "dimension": crate::federation::community_trust_consent::COMMUNITY_TRUST_DIMENSION,
                    "score": 1.0,
                }),
                now + chrono::Duration::milliseconds(i),
            );
            ct.subject_key_ids = vec![stewards[0].clone(), agents[i as usize].clone()];
            ts::reseal(&mut ct);
            put_patiently(d, ct, "I538 community_trust").await;
        }
        for i in 0..1_100 {
            put_patiently(
                d,
                scores(
                    &t,
                    &t,
                    serde_json::json!({ "dimension": format!("config:i538-{i}:v1"), "n": i }),
                    now,
                ),
                "I538 self-report",
            )
            .await;
        }
        let about_t = FederationDirectory::list_attestations_for(d, &t)
            .await
            .unwrap()
            .len();
        eprintln!(
            "I538 seeded in {:?}: {about_t} rows about T, {AGENTS} agents, {STEWARDS} stewards",
            started.elapsed()
        );
        assert!(
            about_t >= 2_300,
            "the canonical's shape: {about_t} rows about T"
        );
        let _ = read_probe::take();

        // ── the pass, through the new doors ──
        let scope = crate::scope::CallerScope::Unauthenticated;
        let mut new = PassTotals::default();
        let pass_started = std::time::Instant::now();
        for a in &agents {
            cbh::resolve_scoped_consent_by_principals(d, &t, a, "analyze", None, now)
                .await
                .unwrap();
            let page = d
                .list_attestations(
                    crate::read::AttestationFilter {
                        attested_key_id: Some(a.clone()),
                        attestation_type: Some(attestation_type::SCORES.to_owned()),
                        dimension_prefixes: vec!["capacity:".to_owned()],
                        ..Default::default()
                    },
                    None,
                    512,
                    scope.clone(),
                )
                .await
                .unwrap();
            assert_eq!(page.items.len(), 1, "the agent's one capacity score");
            let log = read_probe::take();
            let (rows_t, _) = reads_keyed_on(&log, &t);
            new.rows += log.iter().map(|r| r.rows).sum::<usize>();
            new.bytes += log.iter().map(|r| r.bytes).sum::<usize>();
            new.rows_keyed_on_target += rows_t;
            new.max_rows_keyed_on_target_per_agent =
                new.max_rows_keyed_on_target_per_agent.max(rows_t);
            // The agent's own consent rows about T plus its steward's (a
            // steward authored FOR grants for a third of its 45 agents: 15
            // rows) — O(the principals' rows), never the slice.
            assert!(
                rows_t <= 64,
                "I538 {a}: reads keyed on T returned {rows_t} rows — the agent's and its \
                 steward's consent rows about T, never T's slice: {log:?}"
            );
        }
        d.list_trace_summaries(
            crate::read::TraceFilter::default(),
            None,
            500,
            scope.clone(),
        )
        .await
        .unwrap();
        let pass_elapsed = pass_started.elapsed();

        // ── the v53.1.4 bodies on every tenth agent ──
        let mut old = PassTotals::default();
        let mut sampled = 0usize;
        for a in agents.iter().step_by(10) {
            resolve_scoped_stance_by_principals_reference(d, &t, a, "analyze", None, now)
                .await
                .unwrap();
            let log = read_probe::take();
            let (rows_t, _) = reads_keyed_on(&log, &t);
            old.rows += log.iter().map(|r| r.rows).sum::<usize>();
            old.bytes += log.iter().map(|r| r.bytes).sum::<usize>();
            old.rows_keyed_on_target += rows_t;
            old.max_rows_keyed_on_target_per_agent =
                old.max_rows_keyed_on_target_per_agent.max(rows_t);
            sampled += 1;
        }
        eprintln!(
            "I538 pass over {AGENTS} agents in {pass_elapsed:?} — NEW doors: {} rows / {} bytes \
             decoded, {} rows keyed on T (max {} per agent). v53.1.4 consent body on {sampled} \
             agents: {} rows / {} bytes, {} rows keyed on T (max {} per agent) — ×10 for the \
             pass: {} rows / {} bytes.",
            new.rows,
            new.bytes,
            new.rows_keyed_on_target,
            new.max_rows_keyed_on_target_per_agent,
            old.rows,
            old.bytes,
            old.rows_keyed_on_target,
            old.max_rows_keyed_on_target_per_agent,
            old.rows * 10,
            old.bytes * 10
        );
        assert!(
            old.max_rows_keyed_on_target_per_agent >= about_t,
            "the v53.1.4 body reads T's whole slice per agent: {old:?}"
        );
        assert!(
            new.rows_keyed_on_target <= 64 * AGENTS,
            "the pass's reads keyed on T must be O(agents), not O(agents × slice): {new:?}"
        );
        assert!(
            new.rows * 10 < old.rows * 10 / 20,
            "the new pass decodes under 5% of the v53.1.4 pass's rows: {new:?} vs ×10 {old:?}"
        );
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
                case!(i537, i537_sized_reads_are_bounded_by_the_set_the_fold_uses);
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

    /// I538 needs the CEG list read (`ReadEngine`), which the memory
    /// backend does not serve: sqlite and postgres.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i538_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i538_the_scorers_pass_reads_each_agents_slice_not_the_nodes(&b, &suffix())
            .await
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i538_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i538_the_scorers_pass_reads_each_agents_slice_not_the_nodes(&b, &suffix())
            .await
    }
}
