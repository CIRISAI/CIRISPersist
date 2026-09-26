//! v50.0.0 (CIRISPersist#919; `FSD/SECOND_DEVICE.md` §1) — **the consent
//! sweep never widens a placed row.**
//!
//! A row whose signed envelope names a cohort target
//! ([`admission::COHORT_TARGET_ENVELOPE_FIELDS`](crate::federation::admission::COHORT_TARGET_ENVELOPE_FIELDS))
//! was PLACED there by its emitter (CC 3.1.9, CC 5.2). A covering consent
//! grant says nothing about that row's audience, and a widening names no room
//! (`build_widening` carries only the NEW placement's target), so widening it
//! hides it from the room's own fold. CIRISServer measured exactly that: a
//! self-room KeyPackage widened to `federation` seconds after `share` placed
//! it, and the owner's second device never joined.
//!
//! I186 — (a) a self-scoped row naming a self room, (b) a family-scoped row
//! naming its family: neither is a widening candidate, and after the sweep
//! each is unchanged with no widening; (c) a self-scoped row naming NO
//! target under the same grant IS widened (#530's repair still runs);
//! (d) the room-keyed fold still finds (a)'s row after the sweep; (e) memory,
//! sqlite and postgres return the same candidate set for the same fixture.

/// The backend-agnostic candidate-read body; `run` instantiates it per
/// backend and (e) compares the three.
#[cfg(test)]
pub mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// A federation-tier `scores` row by `signer` at `scope`, its envelope
    /// carrying `extra` members (the cohort target, or none).
    fn row(id: &str, signer: &str, scope: &str, extra: serde_json::Value) -> Attestation {
        let mut envelope = serde_json::json!({
            "dimension": "trust:demo:v1", "score": 1.0, "confidence": 0.9,
        });
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                envelope[k] = v.clone();
            }
        }
        let (och, ed_sig, pqc_sig) = ts::sign_envelope(signer, &envelope);
        let at = chrono::Utc::now();
        let mut r = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: signer.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: Some(1.0),
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: scope.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::reseal(&mut r);
        r
    }

    async fn put(d: &dyn FederationDirectory, a: Attestation) {
        let id = a.attestation_id.clone();
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .unwrap_or_else(|e| panic!("I186: put {id}: {e}"));
    }

    /// The fixture's row names, in the order (a)…(c). Every PLACED row names
    /// its target under ONE alias, so each alias is exercised on its own — an
    /// exclusion that reads only `community_key_id` leaves the others
    /// candidates.
    pub const PLACED: &[&str] = &[
        "a-room-community-key-id",
        "a-room-community-id",
        "a-room-cohort-key-id",
        "b-family",
        "b-self-names-family",
    ];
    /// The rows that ARE stranded: no target, or an EMPTY target (not
    /// populated — [`crate::federation::admission::envelope_cohort_target`]
    /// reads it as no target, and the candidate read must agree).
    pub const STRANDED: &[&str] = &["c-stranded", "c-empty-target"];

    /// Seed the fixture on `d` and return the candidate read's ids that
    /// belong to it, suffix stripped and sorted (so three backends compare).
    pub async fn i186_candidate_set(d: &dyn FederationDirectory, s: &str) -> Vec<String> {
        // The distinguishing part LEADS every key id: the test signer seeds
        // from a key id's first 32 bytes.
        let node = format!("node-{s}");
        let owner = format!("owner-{s}");
        ts::register_identity_key(d, &node, NODE).await;
        ts::register_hybrid_key_as(d, &owner, &owner, USER).await;
        let (fam, members) = crate::federation::family_roster_invariants::bodies::make_family(
            d,
            s,
            "household",
            crate::federation::types::consensus_protocol::UNANIMOUS,
            &["member"],
            1,
        )
        .await;
        let member = &members[0];

        let id = |name: &str| format!("{name}-{s}");
        // (a) a self room: the owner's key names the room (Edge's
        // `key_package_attestation_in` shape), under each alias.
        for (name, alias) in [
            ("a-room-community-key-id", "community_key_id"),
            ("a-room-community-id", "community_id"),
            ("a-room-cohort-key-id", "cohort_key_id"),
        ] {
            put(
                d,
                row(
                    &id(name),
                    &node,
                    cohort_scope::SELF,
                    serde_json::json!({ alias: owner }),
                ),
            )
            .await;
        }
        // (b) a family row naming its family, by a member.
        put(
            d,
            row(
                &id("b-family"),
                member,
                cohort_scope::FAMILY,
                serde_json::json!({ "family_key_id": fam }),
            ),
        )
        .await;
        // …and a `self` row naming the family alias: placement is read from
        // the ENVELOPE, not from `cohort_scope`.
        put(
            d,
            row(
                &id("b-self-names-family"),
                &node,
                cohort_scope::SELF,
                serde_json::json!({ "family_key_id": fam }),
            ),
        )
        .await;
        // (c) stranded: no target at all, and an empty one.
        put(
            d,
            row(
                &id("c-stranded"),
                &node,
                cohort_scope::SELF,
                serde_json::json!({}),
            ),
        )
        .await;
        put(
            d,
            row(
                &id("c-empty-target"),
                &node,
                cohort_scope::SELF,
                serde_json::json!({ "community_key_id": "" }),
            ),
        )
        .await;

        let tail = format!("-{s}");
        let mut got: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            // A page of 1: the keyset cursor must still walk past the
            // excluded rows (an exclusion applied after the LIMIT would end
            // the walk on the first all-excluded page).
            let page = d
                .list_widening_candidates(cursor.as_deref(), 1)
                .await
                .expect("I186: candidate read");
            let Some(last) = page.last() else { break };
            cursor = Some(last.attestation_id.clone());
            got.extend(
                page.iter()
                    .filter_map(|a| a.attestation_id.strip_suffix(&tail).map(str::to_owned)),
            );
        }
        got.sort();
        let mut want: Vec<String> = STRANDED.iter().map(|n| (*n).to_owned()).collect();
        want.sort();
        assert_eq!(
            got, want,
            "I186: the candidate read returns the STRANDED rows only — a row naming a cohort \
             target ({:?}) was placed by its emitter and is never a candidate (CIRISPersist#919)",
            PLACED
        );
        got
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i186_candidate_read() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i186_candidate_set(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await;
                }
            }
        };
    }

    async fn memory() -> Option<crate::store::memory::MemoryBackend> {
        Some(crate::store::memory::MemoryBackend::new())
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> Option<crate::store::sqlite::SqliteBackend> {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    /// The two SQL renderings are built from the one constant: every alias
    /// is spelled in each (a hand-edited rendering that dropped one would
    /// leave the SQL backends admitting rows memory excludes).
    #[test]
    fn i186_the_sql_renderings_name_every_alias() {
        use crate::federation::admission as adm;
        let lite = adm::sqlite_envelope_names_no_cohort_target("e");
        let pg = adm::postgres_envelope_names_no_cohort_target("e");
        for f in adm::COHORT_TARGET_ENVELOPE_FIELDS {
            assert!(
                lite.contains(&format!("'$.{f}'")),
                "sqlite misses {f}: {lite}"
            );
            assert!(
                pg.contains(&format!("-> '{f}'")),
                "postgres misses {f}: {pg}"
            );
        }
    }

    runners!(on_memory, super::memory());
    #[cfg(feature = "sqlite")]
    runners!(on_sqlite, super::sqlite());
    #[cfg(feature = "postgres")]
    runners!(on_postgres, super::postgres());

    /// **I186 (e) — the three backends return the same candidate set for the
    /// same fixture.** The SQL backends and memory each carry their own read;
    /// this is what keeps them one rule.
    #[tokio::test]
    async fn i186e_backends_agree_on_the_candidate_set() {
        use crate::federation::FederationDirectory;
        let s = suffix();
        let mut sets: Vec<(&str, Vec<String>)> = Vec::new();
        let m = memory().await.expect("memory");
        sets.push((
            "memory",
            super::bodies::i186_candidate_set(&m as &dyn FederationDirectory, &s).await,
        ));
        #[cfg(feature = "sqlite")]
        {
            let q = sqlite().await.expect("sqlite");
            sets.push((
                "sqlite",
                super::bodies::i186_candidate_set(&q as &dyn FederationDirectory, &s).await,
            ));
        }
        #[cfg(feature = "postgres")]
        if let Some(p) = postgres().await {
            sets.push((
                "postgres",
                super::bodies::i186_candidate_set(&p as &dyn FederationDirectory, &s).await,
            ));
        }
        for (name, set) in &sets[1..] {
            assert_eq!(
                set, &sets[0].1,
                "I186 (e): {name} and memory disagree on the widening candidates"
            );
        }
    }

    /// **I186 (a)–(d) through the sweep itself** (`promote_consented_backlog`
    /// is an engine verb; the engine runs on sqlite and postgres).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn i186_the_sweep_leaves_placed_rows_in_place(engine: crate::Engine, s: &str) {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::{NODE, USER};
        use crate::federation::types::{attestation_type, cohort_scope, Family, FamilyMember};
        use crate::federation::EmitAttestationInput;

        let node = engine
            .register_self_federation_key("node", "ref", None, serde_json::json!({}), vec![])
            .await
            .expect("register self");
        let dir = engine.federation_directory();
        let owner = format!("owner-{s}");
        let peer = format!("peer-{s}");
        ts::register_hybrid_key_as(&*dir, &owner, &owner, USER).await;
        ts::register_identity_key(&*dir, &peer, NODE).await;
        // The node is a member of the owner's family.
        let fam = format!("fam-{s}");
        let joined: chrono::DateTime<chrono::Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        dir.put_family(ts::sign_family(
            &owner,
            Family {
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: [&owner, &node]
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: (*k).clone(),
                        joined_at: joined,
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: joined,
                consensus_protocol: crate::federation::types::consensus_protocol::UNANIMOUS
                    .to_owned(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("I186: family");

        let emit = |scope: &'static str, target: serde_json::Value, tag: &str| {
            let mut value = serde_json::json!({
                "dimension": "trust:demo:v1", "score": 1.0, "confidence": 0.9,
                "note": format!("{tag}-{s}"),
            });
            if let Some(obj) = target.as_object() {
                for (k, v) in obj {
                    value[k] = v.clone();
                }
            }
            let envelope = crate::federation::envelope::EnvelopeCore::from_value(value).unwrap();
            EmitAttestationInput::with_envelope(attestation_type::SCORES, envelope, scope)
        };
        // (a) the self room: `community_key_id = <owner>` at `self`.
        let room_row = engine
            .emit_attestation_self(emit(
                cohort_scope::SELF,
                serde_json::json!({ "community_key_id": owner }),
                "a",
            ))
            .await
            .expect("I186: the self-room row");
        // (b) the family row.
        let family_row = engine
            .emit_attestation_self(emit(
                cohort_scope::FAMILY,
                serde_json::json!({ "family_key_id": fam }),
                "b",
            ))
            .await
            .expect("I186: the family row");
        // (c) the stranded row: `self`, no target.
        let stranded = engine
            .emit_attestation_self(emit(cohort_scope::SELF, serde_json::json!({}), "c"))
            .await
            .expect("I186: the stranded row");

        let before_room = dir.get_attestation(&room_row).await.unwrap().expect("a");
        let before_family = dir.get_attestation(&family_row).await.unwrap().expect("b");

        // A federation-audience grant covering the rows' dimension. Its emit
        // runs the sweep (the (c) hook); run it again explicitly.
        let grant = serde_json::json!({
            "dimension": crate::federation::consent_peer_set::DIMENSION,
            "subject_key_ids": [peer],
            "payload": {
                "grants": "replication",
                "attestation_prefixes": ["trust:"],
                "audience": "federation",
            },
            "subject_kind": "consent_replication",
        });
        let mut input = EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            crate::federation::envelope::EnvelopeCore::from_value(grant).unwrap(),
            cohort_scope::FEDERATION,
        );
        input.subject_key_ids = vec![peer.clone()];
        engine
            .emit_attestation_self(input)
            .await
            .expect("I186: grant");
        engine.promote_consented_backlog().await.expect("sweep");

        let by_node = dir.list_attestations_by(&node).await.unwrap();
        let widenings_of = |id: &str| -> Vec<String> {
            by_node
                .iter()
                .filter(|a| {
                    a.attestation_type == attestation_type::SUPERSEDES
                        && crate::federation::precedence::references_attestation_id_from_envelope(
                            &a.attestation_envelope,
                        ) == Some(id)
                })
                .map(|a| a.cohort_scope.clone())
                .collect()
        };
        // (c) first: the fix is narrow — #530's repair still runs.
        assert_eq!(
            widenings_of(&stranded),
            vec![cohort_scope::FEDERATION.to_owned()],
            "I186 (c): a stranded self row under a federation grant is widened (#530)"
        );
        // (a), (b): no widening, and the row is byte-for-byte what it was.
        for (label, before) in [
            ("(a) self room", &before_room),
            ("(b) family", &before_family),
        ] {
            assert!(
                widenings_of(&before.attestation_id).is_empty(),
                "I186 {label}: a row naming its cohort target was PLACED; the sweep must not \
                 widen it (CIRISPersist#919): {:?}",
                widenings_of(&before.attestation_id)
            );
            let after = dir
                .get_attestation(&before.attestation_id)
                .await
                .unwrap()
                .expect("row");
            assert_eq!(
                (
                    &after.tier,
                    &after.cohort_scope,
                    &after.persist_row_hash,
                    &after.attestation_envelope
                ),
                (
                    &before.tier,
                    &before.cohort_scope,
                    &before.persist_row_hash,
                    &before.attestation_envelope
                ),
                "I186 {label}: the placed row is unchanged"
            );
        }
        let candidates: Vec<String> = dir
            .list_widening_candidates(None, 512)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert!(
            !candidates.contains(&room_row) && !candidates.contains(&family_row),
            "I186: neither placed row is a candidate: {candidates:?}"
        );
        // (d) the room-keyed fold (Edge's `rows_in_room` shape): the node's
        // rows naming the room, with every row a `supersedes` by the same
        // attester stands for dropped (CC 4.4.3.3.1). It still finds (a).
        let superseded: Vec<&str> = by_node
            .iter()
            .filter(|a| a.attestation_type == attestation_type::SUPERSEDES)
            .filter_map(|a| {
                crate::federation::precedence::references_attestation_id_from_envelope(
                    &a.attestation_envelope,
                )
            })
            .collect();
        let in_room: Vec<&str> = by_node
            .iter()
            .filter(|a| {
                crate::federation::admission::envelope_cohort_target(&a.attestation_envelope)
                    .ok()
                    .flatten()
                    == Some(owner.as_str())
                    && !superseded.contains(&a.attestation_id.as_str())
            })
            .map(|a| a.attestation_id.as_str())
            .collect();
        assert_eq!(
            in_room,
            vec![room_row.as_str()],
            "I186 (d): the room's own fold still finds the placed row after the sweep"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i186_sweep_on_sqlite() {
        let s = suffix();
        let signer =
            crate::federation::tier_ingest::test_support::local_signer(&format!("i186n-{s}"));
        let engine = crate::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        i186_the_sweep_leaves_placed_rows_in_place(engine, &s).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i186_sweep_on_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let s = suffix();
        let signer =
            crate::federation::tier_ingest::test_support::local_signer(&format!("i186n-{s}"));
        let engine = crate::Engine::with_signer(signer, &dsn)
            .await
            .expect("engine");
        i186_the_sweep_leaves_placed_rows_in_place(engine, &s).await;
    }
}
