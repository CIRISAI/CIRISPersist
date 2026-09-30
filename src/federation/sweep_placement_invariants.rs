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
//! A self FILE row names its room in a second place: Edge writes it with no
//! top-level target, and the owner only in the blob pointer's slot
//! (`content.community_key_id`), which is what Edge's self-room file read
//! keys on. That slot is a placement too
//! ([`crate::federation::blob_pointer::names_pointer_owner`]).
//!
//! I186 — on CIRISServer's self-files ladder (self FILE rows in Edge's real
//! shape and the MLS KeyPackage in the owner's self room, a family file row, a consent grant
//! covering `file:` and `chat:` at `federation`): (a) no self-room row is a
//! widening candidate, and after the sweep none has a widening ANYWHERE in the
//! corpus — metadata (filename, pointer) never leaves the room; this holds for
//! a placed row still LOCAL when the sweep runs (pass 1, which widens from the
//! local page); (b) the same for the family row; (c) a self row naming NO
//! target under the same grant IS widened (#530's repair still runs); (d) the
//! second device's room read (rows naming the room, minus every row a
//! `supersedes` stands for) lists the original rows, unsuperseded; (e) memory,
//! sqlite and postgres return the same candidate set for the same fixture.
//! `Engine::widen_audience`, the one deliberate path, stays callable for a
//! placed row.

/// The backend-agnostic candidate-read body; `run` instantiates it per
/// backend and (e) compares the three.
#[cfg(test)]
pub mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// A self FILE row's envelope (CIRISServer's self-files ladder): the
    /// filename and the blob pointer are the metadata that must not leave the
    /// room; only the bytes are sealed.
    pub fn file_envelope(id: &str) -> serde_json::Value {
        serde_json::json!({
            "dimension": "file:doc:v1",
            "filename": format!("{id}.txt"),
            "blob_sha256": "ab".repeat(32),
            "size": 42,
        })
    }

    /// The at-rest sha a fixture row's pointer names: unique per row.
    pub fn sha_of(id: &str) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(id.as_bytes()))
    }

    /// Edge's blob pointer (`group_content::BlobPointer`), its owner slot
    /// `community_key_id` naming the room the bytes are held in.
    pub fn edge_pointer(id: &str, owner_slot: &str) -> serde_json::Value {
        serde_json::json!({
            "community_key_id": owner_slot,
            "tier": "invisible_encrypted",
            "content_sha256": sha_of(id),
            "content_field": "body",
            "media_type": "text/plain",
        })
    }

    /// **A self file row exactly as Edge v32.1.0 writes it** (`files.rs`
    /// `file_row`): `file:v1`, the pointer under `content`, the filename, the
    /// citation — and NO top-level cohort target (`scope_room.rs`: a self room
    /// has no `cohort_target_field`; Edge's own test asserts "a self row names
    /// no cohort target"). The owner lives only in the pointer's slot, which
    /// is what Edge's self-room file read keys on (`files.rs`
    /// `file.pointer.community_key_id == room.content_group_id()`).
    pub fn edge_self_file_envelope(id: &str, owner: &str) -> serde_json::Value {
        serde_json::json!({
            "dimension": "file:v1",
            "content": edge_pointer(id, owner),
            "filename": format!("{id}.jpg"),
            "evidence_refs": [sha_of(id)],
        })
    }

    /// A self-room MLS handshake row (Edge's `key_package_attestation_in`).
    pub fn chat_envelope(id: &str) -> serde_json::Value {
        serde_json::json!({
            "dimension": "chat:key_package:v1",
            "key_package": format!("kp-{id}"),
        })
    }

    /// A federation-tier `scores` row by `signer` at `scope` over `envelope`,
    /// plus `extra` members (the cohort target, or none).
    fn row(
        id: &str,
        signer: &str,
        scope: &str,
        mut envelope: serde_json::Value,
        extra: serde_json::Value,
    ) -> Attestation {
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
        "a-edge-file",
        "a-edge-attachment",
        "a-room-community-key-id",
        "a-room-community-id",
        "a-room-cohort-key-id",
        "b-family",
        "b-self-names-family",
    ];
    /// The rows that ARE stranded: no target, or an EMPTY target (not
    /// populated — [`crate::federation::admission::envelope_cohort_target`]
    /// reads it as no target, and the candidate read must agree).
    ///
    /// `c-pointer-no-owner` carries a pointer whose owner slot is EMPTY (a
    /// non-community pointer): the slot names no room, so it is stranded.
    /// `c-pointer-nested` carries a pointer WITH an owner one level under an
    /// object member: the pointer scan reads top-level members and array
    /// items only, so it is stranded too — and a SQL form that walked deeper
    /// would disagree with memory on (e).
    pub const STRANDED: &[&str] = &[
        "c-stranded",
        "c-empty-target",
        "c-pointer-no-owner",
        "c-pointer-nested",
    ];

    /// Seed the fixture on `d` and return the candidate read's ids that
    /// belong to it, suffix stripped and sorted (so three backends compare).
    /// Asserts nothing: (e) compares the sets, so a backend that drifts is
    /// caught by the comparison, not only by its own expectation.
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
        // (a) a self room: the owner's key names the room, under each alias —
        // two self FILE rows and one MLS handshake row.
        for (name, alias, envelope) in [
            (
                "a-room-community-key-id",
                "community_key_id",
                file_envelope as fn(&str) -> serde_json::Value,
            ),
            ("a-room-community-id", "community_id", chat_envelope),
            ("a-room-cohort-key-id", "cohort_key_id", file_envelope),
        ] {
            put(
                d,
                row(
                    &id(name),
                    &node,
                    cohort_scope::SELF,
                    envelope(&id(name)),
                    serde_json::json!({ alias: owner }),
                ),
            )
            .await;
        }
        // (a) Edge's REAL self file row: no top-level target, the owner in
        // the pointer's slot only.
        put(
            d,
            row(
                &id("a-edge-file"),
                &node,
                cohort_scope::SELF,
                edge_self_file_envelope(&id("a-edge-file"), &owner),
                serde_json::json!({}),
            ),
        )
        .await;
        // …and a pointer inside an ARRAY member (a list of attachments): the
        // pointer scan reads array items too, so the SQL forms must.
        put(
            d,
            row(
                &id("a-edge-attachment"),
                &node,
                cohort_scope::SELF,
                serde_json::json!({
                    "dimension": "file:v1",
                    "filename": format!("{}.jpg", id("a-edge-attachment")),
                    "attachments": [edge_pointer(&id("a-edge-attachment"), &owner)],
                }),
                serde_json::json!({}),
            ),
        )
        .await;
        // (b) a family row naming its family, by a member.
        put(
            d,
            row(
                &id("b-family"),
                member,
                cohort_scope::FAMILY,
                file_envelope(&id("b-family")),
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
                file_envelope(&id("b-self-names-family")),
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
                file_envelope(&id("c-stranded")),
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
                file_envelope(&id("c-empty-target")),
                serde_json::json!({ "community_key_id": "" }),
            ),
        )
        .await;

        put(
            d,
            row(
                &id("c-pointer-no-owner"),
                &node,
                cohort_scope::SELF,
                serde_json::json!({
                    "dimension": "file:v1",
                    "content": edge_pointer(&id("c-pointer-no-owner"), ""),
                }),
                serde_json::json!({}),
            ),
        )
        .await;
        put(
            d,
            row(
                &id("c-pointer-nested"),
                &node,
                cohort_scope::SELF,
                serde_json::json!({
                    "dimension": "file:v1",
                    "meta": { "content": edge_pointer(&id("c-pointer-nested"), &owner) },
                }),
                serde_json::json!({}),
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
        got
    }

    /// **I186 — the candidate read returns the stranded rows only**, on `d`.
    pub async fn i186_candidate_read_is_stranded_only(d: &dyn FederationDirectory, s: &str) {
        let got = i186_candidate_set(d, s).await;
        let mut want: Vec<String> = STRANDED.iter().map(|n| (*n).to_owned()).collect();
        want.sort();
        assert_eq!(
            got, want,
            "I186: the candidate read returns the STRANDED rows only — a row naming a cohort \
             target ({:?}) was placed by its emitter and is never a candidate (CIRISPersist#919)",
            PLACED
        );
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
                    super::super::bodies::i186_candidate_read_is_stranded_only(
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
        // …and each carries the pointer owner-slot arm. The markers are the
        // arm's OWN spellings (the alias arm also spells `community_key_id`,
        // so a bare count of it cannot tell the arm is there).
        for (name, sql, markers) in [
            (
                "sqlite",
                &lite,
                [
                    "json_tree(",
                    "ptr.value, '$.content_sha256'",
                    "ptr.value, '$.community_key_id'",
                ],
            ),
            (
                "postgres",
                &pg,
                [
                    "jsonb_array_elements(",
                    "ptr.v ->> 'content_sha256'",
                    "ptr.v ->> 'community_key_id'",
                ],
            ),
        ] {
            for m in markers {
                assert!(
                    sql.contains(m),
                    "{name} misses the pointer owner-slot arm ({m:?}): {sql}"
                );
            }
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
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("I186: family");

        use super::bodies::{chat_envelope, edge_self_file_envelope, file_envelope};
        let emit = |scope: &'static str,
                    mut envelope: serde_json::Value,
                    target: serde_json::Value| {
            if let Some(obj) = target.as_object() {
                for (k, v) in obj {
                    envelope[k] = v.clone();
                }
            }
            let envelope = crate::federation::envelope::EnvelopeCore::from_value(envelope).unwrap();
            EmitAttestationInput::with_envelope(attestation_type::SCORES, envelope, scope)
        };
        let in_room = serde_json::json!({ "community_key_id": owner });
        // (a) the self room, as Edge v32.1.0 places it: two self FILE rows in
        // Edge's real shape (the owner ONLY in the pointer's slot, no
        // top-level target) and the MLS KeyPackage (top-level
        // `community_key_id = <owner>`, `chat.rs`).
        let mut placed: Vec<String> = Vec::new();
        for i in 0..2 {
            placed.push(
                engine
                    .emit_attestation_self(emit(
                        cohort_scope::SELF,
                        edge_self_file_envelope(&format!("a-file{i}-{s}"), &owner),
                        serde_json::json!({}),
                    ))
                    .await
                    .expect("I186: a self-room file row"),
            );
        }
        let room_chat = engine
            .emit_attestation_self(emit(
                cohort_scope::SELF,
                chat_envelope(&format!("a-kp-{s}")),
                in_room.clone(),
            ))
            .await
            .expect("I186: the self-room KeyPackage");
        placed.push(room_chat.clone());
        // …and one placed row that is still LOCAL: the sweep's pass 1 enters
        // it into the mesh and would widen it right after, from the local
        // page — a trigger the candidate read never sees.
        // Edge authors every file row LOCAL at `self`; this is that row.
        let local_env = edge_self_file_envelope(&format!("a-local-{s}"), &owner);
        let room_local = dir
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: node.clone(),
                attested_key_id: None,
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    local_env,
                )
                .unwrap(),
                subject_key_ids: vec![node.clone()],
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("I186: the local self-room file row");
        placed.push(room_local.clone());
        let room_rows: Vec<String> = placed.clone();
        // (b) a family file row.
        let family_row = engine
            .emit_attestation_self(emit(
                cohort_scope::FAMILY,
                file_envelope(&format!("b-file-{s}")),
                serde_json::json!({ "family_key_id": fam }),
            ))
            .await
            .expect("I186: the family row");
        placed.push(family_row.clone());
        // (c) the stranded row: a self file row naming NO target.
        let stranded = engine
            .emit_attestation_self(emit(
                cohort_scope::SELF,
                file_envelope(&format!("c-file-{s}")),
                serde_json::json!({}),
            ))
            .await
            .expect("I186: the stranded row");

        let mut before = Vec::new();
        for id in &placed {
            before.push(dir.get_attestation(id).await.unwrap().expect("placed row"));
        }

        // The ladder's consent grant: federation audience, covering `file:`
        // and `chat:`. Its emit runs the sweep (the (c) hook); run it again
        // explicitly, as the host tick would.
        let grant = serde_json::json!({
            "dimension": crate::federation::consent_peer_set::DIMENSION,
            "subject_key_ids": [peer],
            "payload": {
                "grants": "replication",
                "attestation_prefixes": ["file:", "chat:"],
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

        // The whole corpus, every tier and scope (the one unfiltered read).
        let mut corpus = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = dir
                .list_attestations_for_migration(cursor.as_deref(), 512)
                .await
                .unwrap();
            let Some(last) = page.last() else { break };
            cursor = Some(last.attestation_id.clone());
            corpus.extend(page);
        }
        let widenings_of = |id: &str| -> Vec<String> {
            corpus
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
        // (d) THE SECOND DEVICE'S READ, modelled on Edge v32.1.0: a file is in
        // the self room when its POINTER's owner slot is the room
        // (`files::in_room`: `file.pointer.community_key_id ==
        // room.content_group_id()`); a chat row when its top-level
        // `community_key_id` is (`chat::rows_in_room`). Both read
        // `LifecycleView::Live`: a row some `supersedes` stands for is hidden
        // (CC 4.4.3.3.1). The originals must be listed, all of them, with an
        // EMPTY supersedes chain.
        let superseded: Vec<&str> = corpus
            .iter()
            .filter(|a| a.attestation_type == attestation_type::SUPERSEDES)
            .filter_map(|a| {
                crate::federation::precedence::references_attestation_id_from_envelope(
                    &a.attestation_envelope,
                )
            })
            .collect();
        for id in &room_rows {
            assert!(
                !superseded.contains(&id.as_str()),
                "I186 (d): the supersedes chain of placed row {id} is not empty — Edge's live \
                 listing hides it, and the second device lists nothing"
            );
        }
        let in_self_room = |a: &crate::federation::Attestation| -> bool {
            let env = &a.attestation_envelope;
            let file_in_room = env.get("dimension").and_then(serde_json::Value::as_str)
                == Some("file:v1")
                && env
                    .get("content")
                    .and_then(|p| p.get("community_key_id"))
                    .and_then(serde_json::Value::as_str)
                    == Some(owner.as_str());
            let chat_in_room = env
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|d| d.starts_with("chat:"))
                && env
                    .get("community_key_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(owner.as_str());
            file_in_room || chat_in_room
        };
        let mut live_in_room: Vec<String> = corpus
            .iter()
            .filter(|a| in_self_room(a) && !superseded.contains(&a.attestation_id.as_str()))
            .map(|a| a.attestation_id.clone())
            .collect();
        live_in_room.sort();
        let mut want = room_rows.clone();
        want.sort();
        assert_eq!(
            live_in_room, want,
            "I186 (d): the second device's room read lists the original rows, unsuperseded"
        );

        // (a), (b) — METADATA NEVER LEAVES THE ROOM: no `supersedes` anywhere
        // in the corpus stands for a placed row, no other row carries its
        // filename, and the row itself is what it was.
        for b in &before {
            let id = b.attestation_id.as_str();
            assert!(
                widenings_of(id).is_empty(),
                "I186: placed row {id} ({}) was widened to {:?} — its filename and pointer left \
                 the room it names (CIRISPersist#919)",
                b.attestation_envelope["dimension"],
                widenings_of(id)
            );
            if let Some(name) = b.attestation_envelope.get("filename") {
                let copies: Vec<(&str, &str)> = corpus
                    .iter()
                    .filter(|a| {
                        a.attestation_id != id
                            && a.attestation_envelope.get("filename") == Some(name)
                    })
                    .map(|a| (a.attestation_id.as_str(), a.cohort_scope.as_str()))
                    .collect();
                assert!(
                    copies.is_empty(),
                    "I186: the filename of {id} is carried by another row: {copies:?}"
                );
            }
            let after = dir.get_attestation(id).await.unwrap().expect("row");
            assert_eq!(
                (&after.cohort_scope, &after.attestation_envelope),
                (&b.cohort_scope, &b.attestation_envelope),
                "I186: placed row {id} keeps its scope and its bytes"
            );
            if b.tier == crate::federation::types::attestation_tier::FEDERATION {
                assert_eq!(
                    after.persist_row_hash, b.persist_row_hash,
                    "I186: placed row {id} is unchanged"
                );
            }
        }
        // The local placed row still ENTERED the mesh, at its own scope: it
        // replicates to the owner's devices; only the widening is refused.
        let local_after = dir
            .get_attestation(&room_local)
            .await
            .unwrap()
            .expect("row");
        assert_eq!(
            (local_after.tier.as_str(), local_after.cohort_scope.as_str()),
            (
                crate::federation::types::attestation_tier::FEDERATION,
                cohort_scope::SELF
            ),
            "I186: pass 1 still enters a placed local row into the mesh at `self`"
        );
        let candidates: Vec<String> = dir
            .list_widening_candidates(None, 512)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        for id in &placed {
            assert!(
                !candidates.contains(id),
                "I186: placed row {id} is a candidate: {candidates:?}"
            );
        }
        // The one DELIBERATE path stays callable: a host publishing a placed
        // row wider is the member's choice (`Engine::widen_audience`).
        let chat_row = dir.get_attestation(&room_chat).await.unwrap().expect("row");
        let ci = crate::federation::crossing::describe(
            &chat_row,
            crate::federation::Audience::Federation,
            crate::federation::CrossingBasis::ProducerAuthority,
        )
        .expect("describable");
        let outcome = engine
            .widen_audience(&room_chat, &ci, None, &[])
            .await
            .expect("I186: the explicit widening");
        assert!(
            matches!(outcome, crate::federation::MeshCrossingOutcome::Crossed(_)),
            "I186: an explicit host widening of a placed row is not refused: {outcome:?}"
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
