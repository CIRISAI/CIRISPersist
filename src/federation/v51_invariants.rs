//! v51.0.0 invariants that need a real backend door (the parser-level and
//! engine-level ones live beside their code):
//!
//! - **I122 (CIRISPersist#923)** — the sealed-descriptor doors: "may open the
//!   descriptor" ⇔ "may open the bytes" — member opens, stranger is
//!   `NotGranted`, a plaintext row is `InvalidArgument`, a descriptor sealed for
//!   another blob (or the blob's own ciphertext) fails after authorization, the
//!   plaintext cap holds. On sqlite and postgres over the two-node community
//!   ladder (#876's fixture).
//! - **I128 (CIRISPersist#945)** — the Live listing honours every admitted
//!   retraction (an owner's, a subject's), on every backend.
//! - **I126 (CIRISPersist#941)** — the live owner of a NODE may withdraw a
//!   row that node attested (rule 1 lifted to the producer's principal, CC
//!   3.4.7.3) — but only a row produced while the issuer already owned the
//!   node; a stranger is refused. On memory, sqlite and postgres.
//! - **I125 (CIRISPersist#933)** — on postgres, `put_attestation`'s three
//!   projections run INSIDE the row's transaction: a projection that fails
//!   rolls the row back (no committed, unprojected `withdraws`), and the
//!   retry — with the projection answering — inserts and projects.
//!
//! The fault is a `cfg(test)` one-shot inside the postgres door
//! (`store::test_hooks`, the PR #921 review shape): a wrapping double cannot
//! reach a backend's own transaction.

#[cfg(all(test, feature = "postgres"))]
mod postgres {
    use crate::federation::admission::steward_liveness_test_support::signed_row;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it};
    use crate::federation::{Error, FederationDirectory};
    use crate::store::Backend as _;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// I125 — a failed `consent_peer_set` projection leaves NO row; the retry
    /// inserts. The same statement sequence that committed the row and then
    /// projected it as autocommit (v17.4.0 … v50.0.0) would have left the row
    /// with its revocation never folded, and the retry would have dedupped to
    /// `AlreadyHeld` without re-projecting.
    #[tokio::test]
    async fn i125_a_failed_projection_rolls_the_row_back_on_postgres() {
        // v62.0.0 (JSON cut, E7) — edition-2 keys; the row is a statement put
        // through the one entry, whose door is the same transaction.
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::StatementOutcome;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let d: &dyn FederationDirectory = &b;
        let s = suffix();
        let granter = e2::put_key(d, &format!("g933-{s}"), &[it::USER]).await;
        let recipient = e2::put_key(d, &format!("r933-{s}"), &[it::PRIMITIVE]).await;
        let mut row = signed_row(
            &granter,
            &recipient,
            attestation_type::DELEGATES_TO,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "scope": ["infra:serve"] }),
        );
        ts::reseal(&mut row);
        let id = row.attestation_id.clone();

        // v62.0.0 (round 6, E7) — the delegation is COUNTED (CC 2.6.1.9: the
        // delegate's own voice), so it concludes, and projects, only when its
        // last voice lands: each attempt lands it with every voice its family
        // names (E0's `second_signer_voices` + `land_with_voices`).
        let (voices, missing) = e2::second_signer_voices(d, &row).await.unwrap();
        assert!(
            missing.is_empty(),
            "I125: every voice is in hand: {missing:?}"
        );
        let voices: Vec<&str> = voices.iter().map(String::as_str).collect();
        b.test_hooks().fail_next("pg_project_consent_peer_set", 1);
        let got = e2::land_with_voices(d, &row, &voices).await;
        assert!(
            matches!(&got, Err(Error::Backend(m)) if m.contains("injected transient")),
            "the projection's failure is the door's failure: {got:?}"
        );
        assert!(
            d.get_attestation(&id).await.unwrap().is_none(),
            "I125: a failed projection leaves no committed row (it ran inside the transaction)"
        );

        b.test_hooks().fail_next("pg_project_consent_peer_set", 0);
        let again = e2::land_with_voices(d, &row, &voices).await.unwrap();
        assert!(
            matches!(again, StatementOutcome::Row { new: true, .. }),
            "the retry INSERTS (never already-held over an unprojected row): {again:?}"
        );
        assert!(d.get_attestation(&id).await.unwrap().is_some());
    }

    // v62.0.0 (JSON cut, E7) — I125b (a DIFFERENT row under an occupied id
    // is refused and projects nothing) is deleted: an edition-2 row id is
    // computed from its bytes, so a different row cannot carry a held row's id
    // (an offered id that is not the computed one is `row_id_mismatch`,
    // `edition2::ingest_invariants` I1909).
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod descriptor {
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY, FEDERATION};
    use crate::federation::{BlobBody, BlobError, BlobStorage, FederationDirectory};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// I122 — see the module doc.
    pub(crate) async fn i122_the_descriptor_opens_for_whoever_opens_the_bytes<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        let r = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"the room's bytes", None, None)
            .await
            .expect("A seals a community blob");
        assert_eq!(r.tier, CryptoTier::CommunityDek);
        let sha = r.at_rest_sha256;
        let plaintext = br#"{"format":"image/jpeg","name":"cat.jpg"}"#;

        // the minter's node seals and opens
        let sealed = e
            .seal_descriptor_for_blob(&sha, &l.node_a, plaintext)
            .await
            .expect("the sealer of the bytes seals the descriptor");
        assert_eq!(
            e.open_descriptor_for_blob(&sha, &l.node_a, &sealed, None)
                .await
                .unwrap(),
            plaintext,
            "round trip"
        );
        // the producer's own shape check admits what the door produced
        {
            use base64::Engine as _;
            crate::federation::media_source::check_sealed_descriptor_shape(
                &base64::engine::general_purpose::STANDARD.encode(&sealed),
            )
            .expect("the struct member's shape");
        }
        // a member's node (bob's, granted A's epoch on A — I188's precondition) opens it too
        assert_eq!(
            e.open_descriptor_for_blob(&sha, &l.node_b, &sealed, None)
                .await
                .unwrap(),
            plaintext,
            "a member who may open the bytes may open the descriptor"
        );
        // #923 amendment 1 (CIRISEdge#710 D8) — a blob sealed under its ROW's
        // associated data: the descriptor opens only under that row's data; a
        // pointer transplanted onto another row (or presented with none)
        // reveals nothing, refused AFTER authorization
        let row1: &[u8] = b"row-1|author|2026-09-28T00:00:00Z|media";
        let bound = e
            .put_blob_scoped(
                COMMUNITY,
                Some(&l.comm),
                b"row-bound bytes",
                None,
                Some(row1),
            )
            .await
            .expect("a row-bound community blob");
        let sealed_bound = e
            .seal_descriptor_for_blob(&bound.at_rest_sha256, &l.node_a, plaintext)
            .await
            .unwrap();
        assert_eq!(
            e.open_descriptor_for_blob(&bound.at_rest_sha256, &l.node_a, &sealed_bound, Some(row1))
                .await
                .unwrap(),
            plaintext,
            "the referencing row opens its descriptor"
        );
        for other in [Some(&b"row-2|author|2026-09-28T00:00:01Z|media"[..]), None] {
            let t = e
                .open_descriptor_for_blob(&bound.at_rest_sha256, &l.node_a, &sealed_bound, other)
                .await;
            assert!(
                !matches!(t, Ok(_) | Err(BlobError::NotGranted { .. })),
                "a transplanted pointer ({other:?}) must reveal nothing: {t:?}"
            );
        }
        // a stranger is NotGranted on both doors and learns nothing
        let stranger = format!("em-stranger-{run}");
        assert!(
            matches!(
                e.open_descriptor_for_blob(&sha, &stranger, &sealed, None)
                    .await,
                Err(BlobError::NotGranted { .. })
            ),
            "a stranger cannot open the descriptor"
        );
        assert!(
            matches!(
                e.seal_descriptor_for_blob(&sha, &stranger, plaintext).await,
                Err(BlobError::NotGranted { .. })
            ),
            "a stranger cannot seal one either"
        );
        // a plaintext row has nothing to seal under
        let p = e
            .put_blob_scoped(FEDERATION, None, b"public bytes", None, None)
            .await
            .expect("a plaintext blob");
        assert_eq!(p.tier, CryptoTier::Plaintext);
        assert!(
            matches!(
                e.seal_descriptor_for_blob(&p.at_rest_sha256, &l.node_a, plaintext)
                    .await,
                Err(BlobError::InvalidArgument(_))
            ),
            "a plaintext row is InvalidArgument at the seal door"
        );
        assert!(
            matches!(
                e.open_descriptor_for_blob(&p.at_rest_sha256, &l.node_a, &sealed, None)
                    .await,
                Err(BlobError::InvalidArgument(_))
            ),
            "and at the open door"
        );
        // a descriptor sealed for blob 1 does not open against blob 2 (AAD), and the
        // refusal is AFTER authorization — never NotGranted
        let r2 = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"other bytes", None, None)
            .await
            .unwrap();
        let cross = e
            .open_descriptor_for_blob(&r2.at_rest_sha256, &l.node_a, &sealed, None)
            .await;
        assert!(
            !matches!(cross, Ok(_) | Err(BlobError::NotGranted { .. })),
            "lifted onto another blob: refused after authorization, got {cross:?}"
        );
        // the blob's own ciphertext presented as a descriptor does not open (domain separation)
        let Some(BlobBody::Inline(body)) = l.ba.get_blob(&sha).await.unwrap() else {
            panic!("inline body")
        };
        let as_descriptor = e
            .open_descriptor_for_blob(&sha, &l.node_a, &body, None)
            .await;
        assert!(
            !matches!(as_descriptor, Ok(_) | Err(BlobError::NotGranted { .. })),
            "the bytes' ciphertext is not a descriptor: {as_descriptor:?}"
        );
        // the plaintext cap
        let big = vec![
            b'x';
            crate::federation::at_rest_cascade::orchestrate::SEALED_DESCRIPTOR_PLAINTEXT_MAX
                + 1
        ];
        assert!(
            matches!(
                e.seal_descriptor_for_blob(&sha, &l.node_a, &big).await,
                Err(BlobError::InvalidArgument(_))
            ),
            "over the descriptor cap"
        );
    }

    macro_rules! runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::*;
                #[tokio::test]
                async fn i122() {
                    // v62.0.0 (JSON cut, E7) — the ladder is kid-keyed (E4) and its room
                    // lands as voices (E6).
                    let Some((a, b)) = $dsns else { return };
                    i122_the_descriptor_opens_for_whoever_opens_the_bytes(&a, &b, &suffix(), $pick)
                        .await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as Pick<crate::store::sqlite::SqliteBackend>
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as Pick<crate::store::postgres::PostgresBackend>
    );
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod live_fold {
    //! **I128 (CIRISPersist#945)** — the Live listing honours EVERY admitted
    //! retraction, not only the author's own. v51.0.0's #941 admitted a node
    //! owner's `withdraws` over a node-authored row (stamped
    //! `withdraws_admission_rule = 1`), and the consolidated fold
    //! (`precedence::retired_ids`) retired it — but the five scores-plane Live
    //! filters (sqlite ×2, postgres ×2, memory) hid a row only when the
    //! retracting row's attester was the target's attester, so an admitted
    //! owner's (or subject's, or delegate's) withdrawal was stored as withdrawn
    //! and still listed as Live. Edge's `lifecycle_of` mirrored it
    //! (CIRISEdge#712).
    use crate::federation::consent_peer_set::test_support::grant;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it};
    use crate::federation::FederationDirectory;
    use crate::read::{AttestationFilter, LifecycleView};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    async fn listed(
        d: &dyn FederationDirectory,
        node: &str,
        lifecycle: LifecycleView,
    ) -> Vec<String> {
        d.list_scores(
            "",
            AttestationFilter {
                attesting_key_id: Some(node.to_owned()),
                lifecycle,
                ..AttestationFilter::default()
            },
            None,
            100,
        )
        .await
        .expect("list_scores")
        .items
        .into_iter()
        .map(|a| a.attestation_id)
        .collect()
    }

    /// Returns `(node, a, b)` so a backend's runner can also read the second
    /// Live filter (`ReadEngine::list_attestations`, sqlite and postgres).
    pub(crate) async fn i128_the_live_listing_honours_every_admitted_retraction(
        d: &dyn FederationDirectory,
    ) -> (String, String, String) {
        let s = suffix();
        let (owner, node, peer, stranger) = (
            format!("lf-owner-{s}"),
            format!("lf-node-{s}"),
            format!("lf-peer-{s}"),
            format!("lf-stranger-{s}"),
        );
        // v62.0.0 (JSON cut, E7) — edition-2 keys (ids are identity-refs; the
        // earlier-form helpers resolve a minted kid to its seed, E0 v1.9),
        // rows through the one entry, ids node-computed.
        let owner = e2::put_key(d, &owner, &[it::USER]).await;
        let node = e2::put_key(d, &node, &[it::NODE]).await;
        let peer = e2::put_key(d, &peer, &[it::USER]).await;
        let stranger = e2::put_key(d, &stranger, &[it::USER]).await;
        let put = |a: crate::federation::Attestation| async move { e2::put_signed(d, &a).await };
        // The owner binds the node; the node's own voice completes it (C557).
        // Re-dated NOW-relative (the node's voice is a node-key row, CC 2.4.1.1).
        let at = crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::hours(1),
        );
        let mut ob = ts::owner_binding_attestation("", &owner, &node);
        ob.asserted_at = at;
        ob.scrub_timestamp = at;
        ob.attestation_envelope[crate::federation::envelope::paths::ASSERTED_AT] =
            serde_json::Value::String(crate::federation::admission::render_signed_instant(at));
        ts::reseal(&mut ob);
        put(ob.clone()).await.expect("the owner binds the node");
        e2::put_statement(
            d,
            &e2::voice_of(&e2::carried_statement(&ob).expect("carried"), &node),
        )
        .await
        .expect("the node's voice on its owner binding");
        // two node-authored rows naming the peer as subject
        let mut ids = Vec::new();
        let mut rows = Vec::new();
        for id in [
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        ] {
            let g = grant(&id, &node, &peer);
            ids.push(g.attestation_id.clone());
            rows.push(g.clone());
            assert!(
                matches!(
                    put(g).await.expect("stored"),
                    StatementOutcome::Row { new: true, .. }
                ),
                "a fresh grant lands"
            );
        }
        let (a, b) = (ids[0].clone(), ids[1].clone());
        let live = listed(d, &node, LifecycleView::Live).await;
        assert!(
            live.contains(&a) && live.contains(&b),
            "precondition: {live:?}"
        );
        // v62.0.0 (round 6, E7) — every withdraws is an edition-2 composer
        // (`e2::composer_of`: `refs.target` = the target's row id, the
        // target's family). The shared `withdraws_of` returns the earlier
        // sealed literal for a composer, which retracts nothing on edition 2.
        let wd = |who: &str, target: &crate::federation::Attestation| {
            e2::composer_of(attestation_type::WITHDRAWS, target, who)
        };
        // control: a stranger's withdrawal concludes nothing (refused, or
        // held under CC 2.7.3), and the row stays live
        let r = put(wd(&stranger, &rows[0])).await;
        assert!(
            matches!(r, Err(_) | Ok(StatementOutcome::Pending { .. })),
            "a stranger's withdrawal is refused: {r:?}"
        );
        assert!(
            listed(d, &node, LifecycleView::Live).await.contains(&a),
            "a stranger's withdrawal hides nothing"
        );
        // the node's OWNER withdraws A (#941, rule 1 lifted to the principal)
        let wa = wd(&owner, &rows[0]);
        let wa_id = wa.attestation_id.clone();
        put(wa).await.expect("the owner's withdrawal is admitted");
        assert_eq!(
            d.get_attestation(&wa_id)
                .await
                .unwrap()
                .expect("stored")
                .withdraws_admission_rule,
            Some(1),
            "the door recorded the admitting rule"
        );
        // the SUBJECT withdraws B (rule 2)
        let wb = wd(&peer, &rows[1]);
        let wb_id = wb.attestation_id.clone();
        put(wb).await.expect("the subject's revocation is admitted");
        assert_eq!(
            d.get_attestation(&wb_id)
                .await
                .unwrap()
                .expect("stored")
                .withdraws_admission_rule,
            Some(2)
        );
        let live = listed(d, &node, LifecycleView::Live).await;
        assert!(
            !live.contains(&a) && !live.contains(&b),
            "I128: an admitted non-author retraction hides the row: {live:?}"
        );
        let withdrawn = listed(d, &node, LifecycleView::IncludeWithdrawn).await;
        assert!(
            withdrawn.contains(&a) && withdrawn.contains(&b),
            "IncludeWithdrawn still shows them: {withdrawn:?}"
        );
        assert!(
            d.list_consent_peers(&node).await.unwrap().is_empty(),
            "the consolidated fold agrees (the replication peer set is empty)"
        );
        (node, a, b)
    }

    /// The second Live filter: `ReadEngine::list_attestations` (the generic
    /// listing behind `Engine::list_attestations`), on the backends that
    /// implement it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i128_on_list_attestations<B>(b: &B, node: &str, a: &str, bb: &str)
    where
        B: crate::read::ReadEngine + Sync,
    {
        let ids = |lifecycle: LifecycleView| async move {
            b.list_attestations(
                AttestationFilter {
                    attesting_key_id: Some(node.to_owned()),
                    lifecycle,
                    ..AttestationFilter::default()
                },
                None,
                100,
                crate::scope::CallerScope::Unauthenticated,
            )
            .await
            .expect("list_attestations")
            .items
            .into_iter()
            .map(|x| x.attestation_id)
            .collect::<Vec<_>>()
        };
        let live = ids(LifecycleView::Live).await;
        assert!(
            !live.contains(&a.to_owned()) && !live.contains(&bb.to_owned()),
            "I128 (list_attestations): admitted non-author retractions hide: {live:?}"
        );
        let withdrawn = ids(LifecycleView::IncludeWithdrawn).await;
        assert!(
            withdrawn.contains(&a.to_owned()) && withdrawn.contains(&bb.to_owned()),
            "{withdrawn:?}"
        );
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr, $read_engine:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i128() {
                    let Some(d) = $fresh.await else { return };
                    let (node, a, b) =
                        super::i128_the_live_listing_honours_every_admitted_retraction(
                            &d as &dyn crate::federation::FederationDirectory,
                        )
                        .await;
                    if $read_engine {
                        super::i128_on_list_attestations(&d, &node, &a, &b).await;
                    }
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        async {
            use crate::store::Backend as _;
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        },
        true
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        async {
            use crate::store::Backend as _;
            let dsn = crate::test_pg::empty_dsn()?;
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        },
        true
    );
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod owner_withdraw {
    use crate::federation::admission::steward_liveness_test_support::signed_row;
    use crate::federation::admission::{owner_of, resolve_withdraws_admission_rule};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it};
    use crate::federation::{Attestation, Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// v62.0.0 (JSON cut, E7) — a registered dimension (the fixtures' `x:y`
    /// is not).
    const DIMENSION: &str = "coherence_standing:cab:v1";

    /// v62.0.0 (JSON cut, E7) — `owner` binds `node` at `at` (NOW-relative:
    /// the node's voice is a node-key row, CC 2.4.1.1), optionally expiring:
    /// the owner's row, re-dated from the builder's fixed instant and
    /// re-sealed, then the node's own voice (C557). Returns the stored row.
    async fn bind(
        d: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        at: DateTime<Utc>,
        expires: Option<DateTime<Utc>>,
    ) -> Attestation {
        let at = crate::federation::admission::truncate_to_substrate_resolution(at);
        let mut ob = ts::owner_binding_attestation("", owner, node);
        ob.asserted_at = at;
        ob.scrub_timestamp = at;
        ob.attestation_envelope[crate::federation::envelope::paths::ASSERTED_AT] =
            serde_json::Value::String(crate::federation::admission::render_signed_instant(at));
        ob.expires_at = expires;
        ts::reseal(&mut ob);
        e2::put_signed(d, &ob).await.expect("the owner binding");
        e2::put_statement(
            d,
            &e2::voice_of(&e2::carried_statement(&ob).expect("carried"), node),
        )
        .await
        .expect("the node's voice on its owner binding");
        ob
    }

    /// A row `node` produced at `at` about `subject` (not stored).
    fn produced(node: &str, subject: &str, at: Option<DateTime<Utc>>) -> Attestation {
        let mut row = signed_row(
            node,
            subject,
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": DIMENSION }),
        );
        if let Some(at) = at {
            row.asserted_at = crate::federation::admission::truncate_to_substrate_resolution(at);
            row.scrub_timestamp = row.asserted_at;
            ts::reseal(&mut row);
        }
        row
    }

    /// I126 — see the module doc. v62.0.0 (JSON cut, E7): edition-2 keys
    /// (identity-refs), owner bindings with the node's voice, every instant
    /// now-relative; a binding's era is its own `asserted_at` (no more fixed
    /// 2026-05-01 stamp).
    pub(crate) async fn i126_the_owner_withdraws_its_nodes_row(d: &dyn FederationDirectory) {
        let s = suffix();
        let owner = e2::put_key(d, &format!("ow-owner-{s}"), &[it::USER]).await;
        let node = e2::put_key(d, &format!("ow-node-{s}"), &[it::NODE]).await;
        let stranger = e2::put_key(d, &format!("ow-stranger-{s}"), &[it::USER]).await;
        let subject = e2::put_key(d, &format!("ow-subject-{s}"), &[it::USER]).await;
        let bound_at = Utc::now() - Duration::hours(2);
        bind(d, &owner, &node, bound_at, None).await;
        // a row the node produced AFTER the binding
        let after = produced(&node, &subject, None);
        assert_eq!(
            resolve_withdraws_admission_rule(d, &owner, &after)
                .await
                .unwrap(),
            1,
            "the node's live owner withdraws the node's row (rule 1, the producer's principal)"
        );
        assert!(
            matches!(
                resolve_withdraws_admission_rule(d, &stranger, &after).await,
                Err(Error::WithdrawsNotAdmitted { .. })
            ),
            "a stranger is refused"
        );
        // a row the node produced BEFORE the owner's binding
        let before = produced(&node, &subject, Some(bound_at - Duration::hours(1)));
        assert!(
            matches!(
                resolve_withdraws_admission_rule(d, &owner, &before).await,
                Err(Error::WithdrawsNotAdmitted { .. })
            ),
            "the owner did not own the node when that row was produced"
        );
        // the node itself still withdraws its own rows (rule 1 unchanged)
        assert_eq!(
            resolve_withdraws_admission_rule(d, &node, &before)
                .await
                .unwrap(),
            1
        );
        // PR #943 review — A→B→A. The first owner's binding LAPSES, the node is
        // bound to another owner and produces a row, that owner withdraws its
        // binding, and the first owner binds the node again. The first owner
        // did not own the node when B's row was produced — refused.
        let node2 = e2::put_key(d, &format!("ow-node2-{s}"), &[it::NODE]).await;
        let other = e2::put_key(d, &format!("ow-other-{s}"), &[it::USER]).await;
        let lapses_at =
            put_lapsing_owner_binding(d, &owner, &node2, std::time::Duration::ZERO).await;
        sleep_past(lapses_at).await;
        assert_eq!(
            owner_of(d, &node2).await.unwrap(),
            None,
            "precondition: the first binding lapsed"
        );
        let ob2 = bind(d, &other, &node2, Utc::now(), None).await;
        assert_eq!(owner_of(d, &node2).await.unwrap(), Some(other.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let under_other = produced(&node2, &subject, None);
        assert_eq!(
            resolve_withdraws_admission_rule(d, &other, &under_other)
                .await
                .unwrap(),
            1,
            "the owner at the row's instant withdraws it"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // v62.0.0 (round 6, E7) — an edition-2 composer of the held binding.
        e2::put_signed(
            d,
            &e2::composer_of(attestation_type::WITHDRAWS, &ob2, &other),
        )
        .await
        .expect("B withdraws its binding");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        bind(d, &owner, &node2, Utc::now(), None).await;
        assert_eq!(
            owner_of(d, &node2).await.unwrap(),
            Some(owner.clone()),
            "precondition: the first owner owns the node again, alone"
        );
        assert!(
            matches!(
                resolve_withdraws_admission_rule(d, &owner, &under_other).await,
                Err(Error::WithdrawsNotAdmitted { .. })
            ),
            "A→B→A: the returning owner did not own the node when B's row was produced"
        );
        // the hand-off: C owns node3 and withdraws its binding; A binds node3
        // and the node produces a row. C's era ended before the row, so A —
        // the only owner in force then — retracts it.
        let node3 = e2::put_key(d, &format!("ow-node3-{s}"), &[it::NODE]).await;
        let prior = e2::put_key(d, &format!("ow-prior-{s}"), &[it::USER]).await;
        let obc = bind(d, &prior, &node3, Utc::now() - Duration::minutes(10), None).await;
        e2::put_signed(
            d,
            &e2::composer_of(attestation_type::WITHDRAWS, &obc, &prior),
        )
        .await
        .expect("C withdraws its binding");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        bind(d, &owner, &node3, Utc::now(), None).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let under_a = produced(&node3, &subject, None);
        assert_eq!(
            resolve_withdraws_admission_rule(d, &owner, &under_a)
                .await
                .unwrap(),
            1,
            "a hand-off: the previous owner's era ended before the row"
        );
    }

    /// The first window a lapsing binding is given, and how many times it is
    /// doubled before the helper gives up (300 ms → 9.6 s).
    const LAPSE_WINDOW_MS: i64 = 300;
    const LAPSE_ATTEMPTS: u32 = 6;

    /// CIRISPersist#1011 — store `owner → node`, expiring a short window after
    /// it is stamped, and return that expiry once `owner_of` has been SEEN to
    /// name `owner`. A `None` read that FINISHED after the expiry is a lapse,
    /// not a verdict: retry with a fresh binding and twice the window. A `None`
    /// read that finished before the expiry is still a failure.
    ///
    /// `stall_first` delays the first attempt's read, standing in for a slow
    /// put (the witness below).
    async fn put_lapsing_owner_binding(
        d: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        stall_first: std::time::Duration,
    ) -> DateTime<Utc> {
        let mut window = Duration::milliseconds(LAPSE_WINDOW_MS);
        for attempt in 0..LAPSE_ATTEMPTS {
            let stamped = Utc::now();
            let expires = stamped + window;
            bind(d, owner, node, stamped, Some(expires)).await;
            if attempt == 0 {
                tokio::time::sleep(stall_first).await;
            }
            let read = owner_of(d, node).await.unwrap();
            let read_done = Utc::now();
            if read.as_deref() == Some(owner) {
                return expires;
            }
            assert!(
                read.is_none() && read_done >= expires,
                "owner_of read {read:?} by {read_done}, while {owner}'s binding was live until {expires}"
            );
            window = window * 2;
        }
        panic!("{owner}'s binding lapsed before every read ({LAPSE_ATTEMPTS} attempts)");
    }

    /// Sleep until 100 ms past `instant`.
    async fn sleep_past(instant: DateTime<Utc>) {
        let left = instant + Duration::milliseconds(100) - Utc::now();
        if let Ok(left) = left.to_std() {
            tokio::time::sleep(left).await;
        }
    }

    /// CIRISPersist#1011 witness — the interleaving that failed I126 on the
    /// hosted runner, forced: the first binding lapses between the put and
    /// the read. The helper must still return a binding it saw live, and
    /// that binding must then lapse.
    #[tokio::test]
    #[cfg(feature = "sqlite")]
    async fn i126_lapsing_binding_survives_a_put_slower_than_its_window() {
        let d = crate::store::test_backend::test_backend();
        let d = &d as &dyn FederationDirectory;
        let s = suffix();
        let owner = e2::put_key(d, &format!("ow-owner-{s}"), &[it::USER]).await;
        let node = e2::put_key(d, &format!("ow-node-{s}"), &[it::NODE]).await;
        let stall = std::time::Duration::from_millis(LAPSE_WINDOW_MS as u64 + 100);
        let lapses_at = put_lapsing_owner_binding(d, &owner, &node, stall).await;
        assert!(
            lapses_at - Utc::now() < Duration::milliseconds(2 * LAPSE_WINDOW_MS),
            "the binding returned is the retry's, not one with an unbounded window"
        );
        sleep_past(lapses_at).await;
        assert_eq!(owner_of(d, &node).await.unwrap(), None, "and it lapses");
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i126() {
                    let Some(d) = $fresh.await else { return };
                    super::i126_the_owner_withdraws_its_nodes_row(
                        &d as &dyn crate::federation::FederationDirectory,
                    )
                    .await
                }
            }
        };
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

/// **I127 (CIRISPersist#942)** — the custody view, on sqlite and postgres over
/// the two-node community ladder (#876's fixture): a community blob lists the
/// members of its sealing epoch and counts this node's copy; a self blob lists
/// the owner's grant recipients and (v53.0.0) counts copies from custody
/// reports, every unreported device `unknown`; a commons blob lists no access and is
/// observable; a stranger is `NotGranted` and learns nothing.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod custody {
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::types::cohort_scope::{COMMUNITY, FEDERATION, SELF};
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    pub(crate) async fn i127_the_custody_view<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        // community
        let c = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"room bytes", None, None)
            .await
            .unwrap();
        let v = e.blob_custody(&c.at_rest_sha256, &l.node_a).await.unwrap();
        assert_eq!(v.tier, "community_dek");
        assert!(
            v.held_here && v.copies_observable && v.copies_known >= 1,
            "{v:?}"
        );
        let devices: Vec<&String> = v.access.iter().flat_map(|a| &a.devices).collect();
        assert!(
            devices.contains(&&l.node_a) && devices.contains(&&l.node_b),
            "both members' devices: {v:?}"
        );
        assert!(v.access.iter().all(|a| a.via == "community_epoch_grant"));
        // self
        let s = e
            .put_blob_scoped(SELF, Some(&l.alice), b"my bytes", None, None)
            .await
            .unwrap();
        let v = e.blob_custody(&s.at_rest_sha256, &l.node_a).await.unwrap();
        assert_eq!(v.tier, "invisible_encrypted");
        assert!(v.held_here);
        // v53.0.0 (CIRISPersist#942 part 2, CC 3.1.3.3) — self/family copies
        // are counted from custody reports. v55.0.0 (CIRISPersist#989): the
        // write files the writing device's own holding claim at `self`, so
        // node A is `here`; every other device, with no report, is `unknown`
        // (never a copy, never `none`), and the one copy counted is A's.
        assert!(
            v.copies_observable,
            "self/family copies are observable through custody reports: {v:?}"
        );
        assert_eq!(
            v.copies_known, 1,
            "only this node's own copy, before any other report: {v:?}"
        );
        assert!(
            v.device_custody.iter().all(|d| {
                use crate::federation::custody_ack::CustodyVerdict as V;
                if d.device_key_id == l.node_a {
                    d.state == V::Here
                } else {
                    d.state == V::Unknown
                }
            }),
            "the writer's claim is here; every other device is unknown: {v:?}"
        );
        assert!(
            v.device_custody.iter().any(|d| d.device_key_id == l.node_a),
            "the writing device is in the view: {v:?}"
        );
        assert!(
            v.why
                .as_deref()
                .is_some_and(|w| w.contains("within the cohort") && w.contains("unknown, not none")),
            "{v:?}"
        );
        assert!(
            v.access
                .iter()
                .flat_map(|a| &a.devices)
                .all(|d| d != crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT),
            "persist's self-retention row never appears as a device"
        );
        assert!(
            !v.access.is_empty(),
            "the owner's device holds a key: {v:?}"
        );
        // commons
        let p = e
            .put_blob_scoped(FEDERATION, None, b"public bytes", None, None)
            .await
            .unwrap();
        let v = e.blob_custody(&p.at_rest_sha256, &l.node_a).await.unwrap();
        assert_eq!(v.tier, "plaintext");
        assert!(v.access.is_empty() && v.copies_observable, "{v:?}");
        // a stranger learns nothing
        let stranger = format!("cu-stranger-{run}");
        assert!(
            matches!(
                e.blob_custody(&c.at_rest_sha256, &stranger).await,
                Err(BlobError::NotGranted { .. })
            ),
            "a stranger is refused the community blob's custody view"
        );
        assert!(
            matches!(
                e.blob_custody(&s.at_rest_sha256, &stranger).await,
                Err(BlobError::NotGranted { .. })
            ),
            "and the self blob's"
        );
    }

    macro_rules! runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::*;
                #[tokio::test]
                async fn i127() {
                    // v62.0.0 (JSON cut, E7) — the ladder is kid-keyed (E4) and its room
                    // lands as voices (E6).
                    let Some((a, b)) = $dsns else { return };
                    i127_the_custody_view(&a, &b, &suffix(), $pick).await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as Pick<crate::store::sqlite::SqliteBackend>
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as Pick<crate::store::postgres::PostgresBackend>
    );
}
