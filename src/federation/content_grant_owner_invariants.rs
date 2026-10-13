//! v55.0.0 (found by CIRISEdge's v55 adopt) — **the dirty loop emits a
//! self/family blob's content-axis rows to the owner's devices.**
//!
//! `key_grant::dirty_axes` took a content axis's owner from the row's epoch
//! binding (`community_key_id`), which a self or family row does not have, and
//! fell back to the node's own key: the audience rule then withheld every
//! recipient, nothing was emitted, and the ledger cleared anyway, so nothing
//! ever retried. A device re-classed into the owner's audience got its stream
//! rows and never its content row.
//!
//! - **I762** (sqlite, postgres) — a self blob on a node with two owner
//!   devices: the dirty loop emits the content row to the second device, owned
//!   by the owner, and only then does the ledger clear.
//! - **I763** (sqlite, postgres) — the same for a family blob.
//! - **I764** (sqlite, postgres) — a mis-built axis (owned by the node key)
//!   is reported and stays dirty, never cleared; two dirty-loop passes inside
//!   [`MISBUILT_AXIS_RETRY`](crate::federation::key_grant::MISBUILT_AXIS_RETRY)
//!   plan (and log) it once and skip it once.
//! - **I765** (sqlite, postgres) — a legacy v2 DAG's chunk 0 (granted through
//!   `grant_dek_to_cohort`, no emission) reaches the owner's second device
//!   through the dirty loop, with no manual emit.
//! - **I769** (sqlite, postgres) — THE UPGRADED NODE. v54 shipped the owner
//!   bug, so every v54 node holds self/family content axes marked emitted
//!   with no rows. V192 (`key_grant_rows_reemit`, slice B's SET → rows step)
//!   resets EVERY emission axis dirty, content axes included, and the boot
//!   sweep then emits under the fixed owner: the seeded v54 state (blob,
//!   ledger clean, no row) reaches the owner's second device after V192 and a
//!   boot; V192 replayed and a second boot emit nothing more.
//! - **I766** (sqlite, postgres) — a LEGITIMATE withholding still clears: the
//!   signer holds no wrap of its own (a server-class occurrence) and the only
//!   recipient's occurrence was revoked, so every recipient is withheld and
//!   the axis is not mis-built: nothing emitted, the ledger cleared.

pub(crate) mod bodies {
    use crate::federation::epoch_minter_invariants::bodies::Pick;
    use crate::federation::key_grant::{
        emit_dirty_axes, is_key_grant_row, misbuilt_axis_state, KeyGrantAxis, KeyGrantRow,
    };
    use crate::federation::nested_manifest_invariants::bodies::{pair, Pair};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{FAMILY, SELF};
    use crate::federation::{BlobStorage, FederationDirectory};

    /// The content-axis rows `signer` holds for `sha` addressed to
    /// `recipient`.
    async fn content_rows_to<B>(
        b: &B,
        signer: &str,
        sha: &[u8; 32],
        recipient: &str,
    ) -> Vec<KeyGrantRow>
    where
        B: FederationDirectory + Sync,
    {
        b.list_attestations_for_dimension_prefix(
            recipient,
            Some(signer),
            crate::federation::key_grant::KEY_GRANT_CONTENT_DIMENSION,
        )
        .await
        .unwrap()
        .iter()
        .filter(|a| is_key_grant_row(a))
        .filter_map(|a| KeyGrantRow::from_attestation(a).ok())
        .filter(|r| {
            matches!(&r.axis, KeyGrantAxis::Content { at_rest_sha256, .. }
                if *at_rest_sha256 == hex::encode(sha))
        })
        .collect()
    }

    async fn dirty<B: BlobStorage + Sync>(b: &B, me: &str, sha: &[u8; 32]) -> bool {
        b.blob_list_key_grant_dirty(me).await.unwrap().contains(sha)
    }

    /// The loop every host runs, then the row to the second device and the
    /// ledger state.
    async fn loop_reaches_the_second_device<B>(
        p: &Pair<B>,
        sha: &[u8; 32],
        scope: &str,
        group: &str,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        assert!(
            dirty(p.sa.as_ref(), &p.key_a, sha).await,
            "{tag}: the sealed blob's wraps are owed"
        );
        assert!(
            content_rows_to(p.sa.as_ref(), &p.key_a, sha, &p.key_b)
                .await
                .is_empty(),
            "{tag}: nothing emitted before the loop"
        );
        p.a.emit_pending_key_grants()
            .await
            .unwrap_or_else(|e| panic!("{tag}: the dirty loop: {e}"));
        let rows = content_rows_to(p.sa.as_ref(), &p.key_a, sha, &p.key_b).await;
        assert_eq!(
            rows.len(),
            1,
            "{tag}: the dirty loop emitted the content row to the second device"
        );
        assert!(
            matches!(&rows[0].axis, KeyGrantAxis::Content { owner_key_id, cohort_scope, .. }
                if owner_key_id == group && cohort_scope == scope),
            "{tag}: the row names the blob's owner, not the node: {:?}",
            rows[0].axis
        );
        assert!(
            !dirty(p.sa.as_ref(), &p.key_a, sha).await,
            "{tag}: the ledger cleared once the row was emitted"
        );
    }

    /// **I762** — see the module doc.
    pub(crate) async fn i762_a_self_blob_reaches_the_owners_second_device<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        let p = pair(dsn_a, dsn_b, run, pick, "i762").await;
        let sealed = encrypt_and_cascade(
            p.sa.as_ref(),
            SELF,
            &p.owner,
            b"my photo",
            None,
            None,
            Some(&p.key_a),
        )
        .await
        .expect("I762: A seals a self blob");
        assert!(
            sealed.granted.contains(&p.key_b),
            "I762: {:?}",
            sealed.granted
        );
        assert_eq!(
            p.sa.blob_provenance(&sealed.at_rest_sha256)
                .await
                .unwrap()
                .map(|r| (r.community_key_id, r.group_key_id)),
            Some((None, Some(p.owner.clone()))),
            "I762: a self row names its owner as the group, with no binding"
        );
        loop_reaches_the_second_device(&p, &sealed.at_rest_sha256, SELF, &p.owner, "I762").await;
    }

    /// **I763** — see the module doc.
    pub(crate) async fn i763_a_family_blob_reaches_the_owners_second_device<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        use crate::federation::types::identity_type::USER;
        let p = pair(dsn_a, dsn_b, run, pick, "i763").await;
        let fam = format!("i763-fam-{run}");
        ts::register_hybrid_key_as(p.sa.as_ref(), &fam, &fam, USER).await;
        p.sa.put_family(ts::sign_family(
            &fam,
            crate::federation::types::Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "I763 Household".into(),
                members: vec![crate::federation::types::FamilyMember {
                    key_id: p.owner.clone(),
                    joined_at: chrono::Utc::now(),
                    role: None,
                }],
                founded_at: chrono::Utc::now(),
                consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                    .to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("I763: seed the family");
        let sealed = encrypt_and_cascade(
            p.sa.as_ref(),
            FAMILY,
            &fam,
            b"the household budget",
            None,
            None,
            Some(&p.key_a),
        )
        .await
        .expect("I763: A seals a family blob");
        assert!(
            sealed.granted.contains(&p.key_b),
            "I763: {:?}",
            sealed.granted
        );
        loop_reaches_the_second_device(&p, &sealed.at_rest_sha256, FAMILY, &fam, "I763").await;
    }

    /// **I764** — see the module doc.
    pub(crate) async fn i764_a_misbuilt_axis_stays_dirty_and_is_reported<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        let p = pair(dsn_a, dsn_b, run, pick, "i764").await;
        let sealed = encrypt_and_cascade(
            p.sa.as_ref(),
            SELF,
            &p.owner,
            b"my photo",
            None,
            None,
            Some(&p.key_a),
        )
        .await
        .expect("I764: A seals a self blob");
        let sha = sealed.at_rest_sha256;
        // The pre-fix axis: owned by the NODE's key.
        let wrong = KeyGrantAxis::Content {
            at_rest_sha256: hex::encode(sha),
            cohort_scope: SELF.into(),
            owner_key_id: p.key_a.clone(),
        };
        // (1) One emission: reported, nothing emitted, the ledger still dirty.
        let e =
            p.a.emit_key_grant(&wrong)
                .await
                .unwrap()
                .expect("I764: the blob has wraps");
        assert!(e.attestation_ids.is_empty(), "I764 (1): {e:?}");
        assert!(e.withheld.contains(&p.key_a), "I764 (1): {e:?}");
        assert!(e.misbuilt.is_some(), "I764 (1): reported mis-built: {e:?}");
        assert!(
            dirty(p.sa.as_ref(), &p.key_a, &sha).await,
            "I764 (1): a mis-built axis is never cleared"
        );
        // (2) Two dirty-loop passes inside the interval: planned (and
        // logged) once, skipped once, still dirty.
        let engine = &p.a;
        let pass = || {
            emit_dirty_axes(&p.key_a, vec![wrong.clone()], move |axis| async move {
                engine.emit_key_grant(&axis).await
            })
        };
        let first = pass().await;
        assert_eq!(
            (first.emitted, first.misbuilt, first.backed_off),
            (0, 1, 0),
            "I764 (2)"
        );
        let second = pass().await;
        assert_eq!(
            (second.emitted, second.misbuilt, second.backed_off),
            (0, 0, 1),
            "I764 (2)"
        );
        let st = misbuilt_axis_state(&p.key_a, &wrong).expect("I764 (2): the state is kept");
        assert_eq!(
            (st.planned, st.skipped),
            (1, 1),
            "I764 (2): one plan, one skip"
        );
        assert!(
            dirty(p.sa.as_ref(), &p.key_a, &sha).await,
            "I764 (2): still dirty"
        );
        // (3) The real loop builds the right axis: emitted, then cleared.
        loop_reaches_the_second_device(&p, &sha, SELF, &p.owner, "I764 (3)").await;
    }

    /// **I765** — see the module doc.
    pub(crate) async fn i765_a_legacy_v2_chunk_zero_reaches_the_owners_second_device<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let p = pair(dsn_a, dsn_b, run, pick, "i765").await;
        let stream = format!("i765-{run}");
        let segs: Vec<Vec<u8>> = (0..3).map(|i| vec![i as u8 + 1; 90]).collect();
        let dag = crate::federation::chunk_dag_cascade::test_support::write_legacy_v2_dag(
            &p.a,
            p.sa.as_ref(),
            SELF,
            &p.owner,
            &stream,
            &segs,
            None,
        )
        .await
        .expect("I765: the v52 writer");
        let chunk0 = dag.chunk_sha256[0];
        p.a.emit_pending_key_grants()
            .await
            .expect("I765: the dirty loop");
        assert_eq!(
            content_rows_to(p.sa.as_ref(), &p.key_a, &chunk0, &p.key_b)
                .await
                .len(),
            1,
            "I765: chunk 0's content row reached the second device through the dirty loop"
        );
        assert!(
            !dirty(p.sa.as_ref(), &p.key_a, &chunk0).await,
            "I765: chunk 0's ledger cleared after its row"
        );
    }

    /// **I766** — see the module doc.
    pub(crate) async fn i766_a_legitimate_withholding_still_clears<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        use crate::federation::types::{
            device_class, IdentityOccurrence, IdentityOccurrenceRevocation,
        };
        let p = pair(dsn_a, dsn_b, run, pick, "i766").await;
        // The sealing node re-classed to a server: it receives none of its
        // owner's self content (#963), so it holds no wrap of its own.
        let kem_a =
            crate::federation::nested_manifest_invariants::bodies::kem_of(p.sa.as_ref()).await;
        p.sa.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: p.owner.clone(),
            occurrence_key_id: p.key_a.clone(),
            device_class: device_class::SERVER.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: Some(kem_a),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();
        let sealed = encrypt_and_cascade(
            p.sa.as_ref(),
            SELF,
            &p.owner,
            b"my photo",
            None,
            None,
            Some(&p.key_a),
        )
        .await
        .expect("I766: A seals a self blob");
        assert!(
            sealed.granted.contains(&p.key_b) && !sealed.granted.contains(&p.key_a),
            "I766: only the second device holds a wrap: {:?}",
            sealed.granted
        );
        let sha = sealed.at_rest_sha256;
        let at = chrono::Utc::now();
        p.sa.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: p.owner.clone(),
            occurrence_key_id: p.key_b.clone(),
            revoked_at: at,
            effective_at: at,
            reason: Some("lost device (I766)".into()),
            witness_set: vec![],
            persist_row_hash: String::new(),
        })
        .await
        .expect("I766: revoke the second device");
        let axis = KeyGrantAxis::Content {
            at_rest_sha256: hex::encode(sha),
            cohort_scope: SELF.into(),
            owner_key_id: p.owner.clone(),
        };
        let e =
            p.a.emit_key_grant(&axis)
                .await
                .unwrap()
                .expect("I766: the blob has a wrap");
        assert!(
            e.attestation_ids.is_empty() && e.withheld == vec![p.key_b.clone()],
            "I766: every recipient withheld: {e:?}"
        );
        assert!(
            e.misbuilt.is_none(),
            "I766: an audience change is not mis-built: {e:?}"
        );
        assert!(
            !dirty(p.sa.as_ref(), &p.key_a, &sha).await,
            "I766: a legitimate withholding clears"
        );
    }

    /// Replay V192's bytes over a backend, as the migration runner does on a
    /// node that took v54's migrations.
    pub(crate) type ReplayV192<B> =
        fn(&B) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

    /// **I769** — see the module doc.
    pub(crate) async fn i769_an_upgraded_node_re_emits_v54s_cleared_content_axes<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        replay_v192: ReplayV192<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        let p = pair(dsn_a, dsn_b, run, pick, "i769").await;
        let sealed = encrypt_and_cascade(
            p.sa.as_ref(),
            SELF,
            &p.owner,
            b"a v54 photo",
            None,
            None,
            Some(&p.key_a),
        )
        .await
        .expect("I769: A seals a self blob");
        let sha = sealed.at_rest_sha256;
        // ── v54 state: the axis planned under the node key, every recipient
        // withheld, and marked emitted anyway. No row.
        let wm =
            p.sa.blob_key_grant_watermark(&sha)
                .await
                .unwrap()
                .expect("a grant exists");
        p.sa.blob_mark_key_grant_emitted(&sha, wm).await.unwrap();
        assert!(
            !dirty(p.sa.as_ref(), &p.key_a, &sha).await,
            "I769 precondition: the v54 ledger is clean"
        );
        assert!(
            content_rows_to(p.sa.as_ref(), &p.key_a, &sha, &p.key_b)
                .await
                .is_empty(),
            "I769 precondition: no row"
        );
        p.a.emit_pending_key_grants().await.unwrap();
        assert!(
            content_rows_to(p.sa.as_ref(), &p.key_a, &sha, &p.key_b)
                .await
                .is_empty(),
            "I769 precondition: a clean ledger is never revisited without the upgrade"
        );
        // ── the upgrade: V192, then a boot (the boot sweep).
        replay_v192(p.sa.as_ref()).await;
        assert!(
            dirty(p.sa.as_ref(), &p.key_a, &sha).await,
            "I769: V192 marks the content axis dirty"
        );
        let alias = format!("i769-a-{run}");
        let boot = || async {
            crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), dsn_a)
                .await
                .expect("the upgraded node boots")
        };
        let booted = boot().await;
        assert_eq!(
            content_rows_to(p.sa.as_ref(), &p.key_a, &sha, &p.key_b)
                .await
                .len(),
            1,
            "I769: the boot sweep re-emitted the content row to the second device"
        );
        assert!(
            !dirty(p.sa.as_ref(), &p.key_a, &sha).await,
            "I769: and the ledger is clean again"
        );
        // Once: V192 replayed and a second boot emit nothing more.
        drop(booted);
        replay_v192(p.sa.as_ref()).await;
        let _again = boot().await;
        assert_eq!(
            content_rows_to(p.sa.as_ref(), &p.key_a, &sha, &p.key_b)
                .await
                .len(),
            1,
            "I769: the re-emit is idempotent"
        );
    }

    macro_rules! runners {
        ($modname:ident, $dsn:expr, $pick:expr) => {
            mod $modname {
                use super::*;
                fn run() -> String {
                    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
                }
                #[tokio::test]
                async fn i762() {
                    let Some((a, b)) = $dsn else { return };
                    i762_a_self_blob_reaches_the_owners_second_device(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i763() {
                    let Some((a, b)) = $dsn else { return };
                    i763_a_family_blob_reaches_the_owners_second_device(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i764() {
                    let Some((a, b)) = $dsn else { return };
                    i764_a_misbuilt_axis_stays_dirty_and_is_reported(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i766() {
                    let Some((a, b)) = $dsn else { return };
                    i766_a_legitimate_withholding_still_clears(&a, &b, &run(), $pick).await
                }
                #[tokio::test]
                async fn i765() {
                    let Some((a, b)) = $dsn else { return };
                    i765_a_legacy_v2_chunk_zero_reaches_the_owners_second_device(
                        &a,
                        &b,
                        &run(),
                        $pick,
                    )
                    .await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i769_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let dsn = format!("sqlite:///{}", dir.path().join("a.db").display());
        let run = uuid::Uuid::new_v4().simple().to_string()[..12].to_owned();
        i769_an_upgraded_node_re_emits_v54s_cleared_content_axes(
            &dsn,
            "sqlite::memory:",
            &run,
            |e: &crate::Engine| e.sqlite_backend().unwrap().clone(),
            |b: &crate::store::sqlite::SqliteBackend| {
                Box::pin(async move {
                    let conn = b.conn_handle();
                    let conn = conn.lock();
                    conn.execute_batch(include_str!(
                        "../../migrations/sqlite/lens/V192__key_grant_rows_reemit.sql"
                    ))
                    .expect("V192 replays");
                })
            },
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i769_postgres() {
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        let run = uuid::Uuid::new_v4().simple().to_string()[..12].to_owned();
        i769_an_upgraded_node_re_emits_v54s_cleared_content_axes(
            &a,
            &b,
            &run,
            |e: &crate::Engine| e.postgres_backend().unwrap().clone(),
            |b: &crate::store::postgres::PostgresBackend| {
                Box::pin(async move {
                    b.get_client()
                        .await
                        .unwrap()
                        .batch_execute(include_str!(
                            "../../migrations/postgres/lens/V192__key_grant_rows_reemit.sql"
                        ))
                        .await
                        .expect("V192 replays");
                })
            },
        )
        .await;
    }

    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        |e: &crate::Engine| e.sqlite_backend().unwrap().clone()
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        crate::test_pg::empty_dsn().zip(crate::test_pg::empty_dsn()),
        |e: &crate::Engine| e.postgres_backend().unwrap().clone()
    );
}
