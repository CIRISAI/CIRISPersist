//! v47.2.0 (CIRISPersist#853, #862, `FSD/BYTES_PLANE_TOMBSTONE.md` §4) —
//! **CC 2.3 at the bytes plane**: a withdrawn reference stops the bytes on
//! every door that reads them, the stored admission rule is never consulted,
//! one live binding keeps the bytes, the resolver sees the pointer shape, and
//! `evict_blob` retracts before it deletes.

/// The I149–I153 bodies, one per backend runner (sqlite + postgres: the
/// memory backend has no blob storage).
#[cfg(all(
    any(test, feature = "test-anchor"),
    any(feature = "sqlite", feature = "postgres")
))]
pub mod bodies {
    use crate::federation::blob_tombstone::{binding_state, BindingState};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{BlobError, BlobStorage, FederationDirectory, SignedAttestation};

    /// A federation-tier content row by `author`, about `subjects`, that
    /// binds `sha_hex` by a **pointer member** (the chat shape: no
    /// `evidence_refs`) when `by_pointer`, else by `evidence_refs`.
    async fn bind_row<B>(
        b: &B,
        id: &str,
        author: &str,
        subjects: &[&str],
        sha_hex: &str,
        by_pointer: bool,
    ) where
        B: FederationDirectory + Sync,
    {
        let env = if by_pointer {
            serde_json::json!({
                "id": id, "dimension": "file:doc:v1", "cohort_scope": "federation",
                "content": {"content_sha256": sha_hex, "community_key_id": "", "tier": "invisible_encrypted"}
            })
        } else {
            serde_json::json!({
                "id": id, "dimension": "file:doc:v1", "cohort_scope": "federation",
                "evidence_refs": [sha_hex]
            })
        };
        let mut row = ts::bare_attestation(id, author, author, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.cohort_scope = "federation".into();
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        ts::seal_row_in_place(author, &mut row);
        b.put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("bind_row {id}: {e}"));
    }

    /// A `withdraws` by `issuer` naming `target_id`, through the real door.
    async fn withdraw<B>(
        b: &B,
        id: &str,
        issuer: &str,
        target_id: &str,
    ) -> Result<(), crate::federation::Error>
    where
        B: FederationDirectory + Sync,
    {
        let env = serde_json::json!({
            "references_attestation_id": target_id,
            "withdrawal_reason": "CC 2.3",
        });
        let mut w = ts::bare_attestation(id, issuer, issuer, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.cohort_scope = "federation".into();
        ts::seal_row_in_place(issuer, &mut w);
        b.put_attestation(SignedAttestation { attestation: w })
            .await
            .map(|_| ())
    }

    /// A federation-scope blob announced by a node signer seeded from
    /// `label` (registered under its DERIVED key, which is the key every
    /// row and claim below is authored by). Returns `(sha, derived_key_id)`.
    async fn seal_blob<B>(b: &B, label: &str, body: &[u8]) -> ([u8; 32], String)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let signer =
            crate::federation::at_rest_cascade::blob_invariants::node_signer(b, label).await;
        let sha = crate::federation::at_rest_cascade::orchestrate::put_blob_scoped(
            b,
            &signer,
            crate::federation::types::cohort_scope::FEDERATION,
            None,
            body,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("seal_blob: {e}"))
        .at_rest_sha256;
        (sha, signer.derived_key_id())
    }

    fn kind_of(r: &Result<Vec<u8>, BlobError>) -> &'static str {
        match r {
            Ok(_) => "ok",
            Err(e) => e.kind(),
        }
    }

    /// **I149 — a withdrawn reference stops the bytes on every read door.**
    /// The subject who withdraws is NOT the author (rule 2): the case CC 2.3
    /// exists for and the one edge's witness could not exercise.
    pub async fn i149_a_withdrawn_reference_stops_the_bytes<B>(
        b: &B,
        engine: &crate::Engine,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let subject = format!("i149-subject-{s}");
        let stranger = format!("i149-stranger-{s}");
        for k in [&subject, &stranger] {
            ts::register_identity_key(b, k, crate::federation::types::identity_type::USER).await;
        }
        let (sha, author) = seal_blob(
            b,
            &format!("i149-author-{s}"),
            b"the subject appears in this file",
        )
        .await;
        let sha_hex = hex::encode(sha);
        let row = format!("i149-row-{s}");
        bind_row(b, &row, &author, &[&author, &subject], &sha_hex, true).await;

        // Before: bound and live, and every door reads.
        assert_eq!(
            binding_state(b as &dyn FederationDirectory, &sha)
                .await
                .unwrap(),
            BindingState::Live,
            "I149: live before"
        );
        assert_eq!(
            kind_of(&engine.read_blob_as(&sha, &author, None).await),
            "ok",
            "I149: reads before"
        );
        assert!(
            engine.serve_blob_to_peer(&sha, "peer").await.is_ok(),
            "I149: serves before"
        );

        // The SUBJECT withdraws the row (rule 2 — not the author).
        let w = format!("i149-w-{s}");
        withdraw(b, &w, &subject, &row)
            .await
            .expect("I149: a subject's withdraws is admitted (rule 2)");

        // After: every door refuses with the typed arm, naming the blob.
        assert_eq!(
            binding_state(b as &dyn FederationDirectory, &sha)
                .await
                .unwrap(),
            BindingState::Withdrawn {
                attestation_id: row.clone(),
                withdraws_id: w.clone()
            },
            "I149: the fold says withdrawn"
        );
        let r = engine.read_blob_as(&sha, &author, None).await;
        assert!(
            matches!(&r, Err(BlobError::Withdrawn { sha256_hex, .. }) if *sha256_hex == sha_hex),
            "I149: read_blob_as after a subject's withdraws: {r:?}"
        );
        assert_eq!(kind_of(&r), "blob_withdrawn");
        let r = engine.read_blob_range_as(&sha, &author, 0, 4, None).await;
        assert!(
            matches!(&r, Err(BlobError::Withdrawn { .. })),
            "I149: read_blob_range_as after a subject's withdraws: {r:?}"
        );
        let r = engine.serve_blob_to_peer(&sha, "peer").await;
        assert!(
            matches!(&r, Err(BlobError::Withdrawn { .. })),
            "I149: the SERVE door answers Withdrawn — never NotHeld, which walks the fetcher \
             around the mesh: {r:?}"
        );
        // A commons-tier blob authorizes ANY viewer, so a "stranger" is an
        // authorized viewer here and correctly sees `Withdrawn` (the refusal
        // names only what a holder of the rows already sees on the wire).
        let r = engine.read_blob_as(&sha, &stranger, None).await;
        assert!(
            matches!(&r, Err(BlobError::Withdrawn { .. })),
            "I149: on a commons blob every viewer is authorized: {r:?}"
        );

        // The ORDER claim — authorization before the fold, so a stranger learns
        // nothing — is made on a SEALED tier: a community blob a keyed member
        // occurrence can read (the cohort-lifecycle fixture), bound and
        // withdrawn the same way. The member sees `Withdrawn`; a stranger is
        // `NotGranted` and never sees the tombstone.
        let comm = format!("i149-comm-{s}");
        let alice = format!("i149-alice-{s}");
        let alice_occ = format!("i149-alice-occ-{s}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            b,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let minter = crate::federation::at_rest_cascade::blob_invariants::node_signer(
            b,
            &format!("i149-minter-{s}"),
        )
        .await
        .derived_key_id();
        let sealed = crate::federation::community_dek::orchestrate::encrypt_and_cascade_community(
            b,
            &comm,
            b"sealed: the subject appears here too",
            None,
            Some(&minter),
        )
        .await
        .unwrap_or_else(|e| panic!("I149: seal at the community tier: {e}"))
        .at_rest_sha256;
        assert_eq!(
            kind_of(&engine.read_blob_as(&sealed, &alice_occ, None).await),
            "ok",
            "I149: the member occurrence reads the sealed blob before"
        );
        let sealed_row = format!("i149-sealed-row-{s}");
        bind_row(
            b,
            &sealed_row,
            &alice,
            &[&alice, &subject],
            &hex::encode(sealed),
            true,
        )
        .await;
        withdraw(b, &format!("i149-sealed-w-{s}"), &subject, &sealed_row)
            .await
            .expect("I149: the subject withdraws the sealed row");
        let r = engine.read_blob_as(&sealed, &alice_occ, None).await;
        assert!(
            matches!(&r, Err(BlobError::Withdrawn { .. })),
            "I149: the member sees Withdrawn on the sealed, withdrawn blob: {r:?}"
        );
        let r = engine.read_blob_as(&sealed, &stranger, None).await;
        assert!(
            matches!(&r, Err(BlobError::NotGranted { .. })),
            "I149: a stranger is NotGranted FIRST on a sealed blob and never sees the tombstone: {r:?}"
        );
    }

    /// **I150 — the stored rule is not consulted.** The same stored value
    /// (`withdraws_admission_rule = None`, admitted out of order) yields
    /// opposite verdicts depending only on the authority re-derived NOW.
    pub async fn i150_the_stored_rule_is_never_consulted<B>(b: &B, engine: &crate::Engine, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let subject = format!("i150-subject-{s}");
        let third = format!("i150-third-{s}");
        for k in [&subject, &third] {
            ts::register_identity_key(b, k, crate::federation::types::identity_type::USER).await;
        }
        let (sha, author) = seal_blob(b, &format!("i150-author-{s}"), b"out of order").await;
        let row = format!("i150-row-{s}");
        // OUT OF ORDER, twice: each withdraws lands BEFORE its target, so the
        // write door admits it with rule = None. The two rows differ only in
        // who signed the deferred withdraws — a SUBJECT (entitled) on row A,
        // a THIRD PARTY (not) on row B. The stored column is `None` on both;
        // only the authority re-derived against the landed target differs.
        let sha_b = seal_blob(b, &format!("i150-author-b-{s}"), b"out of order, too")
            .await
            .0;
        let row_b = format!("i150-row-b-{s}");
        let w_subject = format!("i150-w-subject-{s}");
        let w_third = format!("i150-w-third-{s}");
        withdraw(b, &w_subject, &subject, &row)
            .await
            .expect("I150: deferred admission (target absent)");
        withdraw(b, &w_third, &third, &row_b)
            .await
            .expect("I150: deferred admission (target absent)");
        for w in [&w_subject, &w_third] {
            assert_eq!(
                b.get_attestation(w)
                    .await
                    .unwrap()
                    .unwrap()
                    .withdraws_admission_rule,
                None,
                "I150: precondition — a withdraws admitted ahead of its target stores rule None"
            );
        }
        // Now both targets land, and only NOW can authority be derived.
        bind_row(
            b,
            &row,
            &author,
            &[&author, &subject],
            &hex::encode(sha),
            true,
        )
        .await;
        bind_row(
            b,
            &row_b,
            &author,
            &[&author, &subject],
            &hex::encode(sha_b),
            true,
        )
        .await;
        assert_eq!(
            binding_state(b as &dyn FederationDirectory, &sha).await.unwrap(),
            BindingState::Withdrawn {
                attestation_id: row.clone(),
                withdraws_id: w_subject.clone()
            },
            "I150/A: the SUBJECT's deferred withdraws (stored None) retires the bytes — a fold that \
             trusts the stored rule cannot produce this"
        );
        assert_eq!(
            kind_of(&engine.read_blob_as(&sha, &author, None).await),
            "blob_withdrawn"
        );
        assert_eq!(
            binding_state(b as &dyn FederationDirectory, &sha_b).await.unwrap(),
            BindingState::Live,
            "I150/B: the THIRD PARTY's deferred withdraws (also stored None) retires nothing — a fold \
             that reads None as retired makes replication a remote-delete primitive"
        );
        assert_eq!(
            kind_of(&engine.read_blob_as(&sha_b, &author, None).await),
            "ok"
        );
    }

    /// **I151 — one live binding keeps the bytes.**
    pub async fn i151_one_live_binding_keeps_the_bytes<B>(b: &B, engine: &crate::Engine, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let c = format!("i151-c-{s}");
        ts::register_identity_key(b, &c, crate::federation::types::identity_type::USER).await;
        let (sha, a) = seal_blob(b, &format!("i151-a-{s}"), b"quoted twice").await;
        let hx = hex::encode(sha);
        let (r1, r2) = (format!("i151-r1-{s}"), format!("i151-r2-{s}"));
        bind_row(b, &r1, &a, &[&a], &hx, true).await;
        bind_row(b, &r2, &c, &[&c], &hx, false).await; // the other reference shape
        withdraw(b, &format!("i151-w1-{s}"), &a, &r1).await.unwrap();
        assert_eq!(
            binding_state(b as &dyn FederationDirectory, &sha)
                .await
                .unwrap(),
            BindingState::Live,
            "I151: one binding withdrawn, one live — the bytes stay"
        );
        assert_eq!(kind_of(&engine.read_blob_as(&sha, &a, None).await), "ok");
        withdraw(b, &format!("i151-w2-{s}"), &c, &r2).await.unwrap();
        assert!(
            matches!(
                binding_state(b as &dyn FederationDirectory, &sha)
                    .await
                    .unwrap(),
                BindingState::Withdrawn { .. }
            ),
            "I151: both withdrawn"
        );
        assert_eq!(
            kind_of(&engine.read_blob_as(&sha, &a, None).await),
            "blob_withdrawn"
        );
    }

    /// **I152 — the resolver sees the pointer shape** (#862 part 2), and an
    /// unreadable pointer at that sha still counts as binding.
    pub async fn i152_the_resolver_sees_the_pointer_shape<B>(b: &B, s: &str)
    where
        B: FederationDirectory + Sync,
    {
        let a = format!("i152-a-{s}");
        ts::register_identity_key(b, &a, crate::federation::types::identity_type::USER).await;
        let sha_hex = "ab".repeat(32);
        let (p, e, bad) = (
            format!("i152-p-{s}"),
            format!("i152-e-{s}"),
            format!("i152-bad-{s}"),
        );
        bind_row(b, &p, &a, &[&a], &sha_hex, true).await;
        bind_row(b, &e, &a, &[&a], &sha_hex, false).await;
        // Pointer-shaped at these bytes but unreadable (a non-string tier).
        let env = serde_json::json!({
            "id": bad, "dimension": "file:doc:v1", "cohort_scope": "federation",
            "content": {"content_sha256": sha_hex, "community_key_id": "", "tier": 7}
        });
        let mut row = ts::bare_attestation(&bad, &a, &a, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.cohort_scope = "federation".into();
        row.subject_key_ids = vec![a.clone()];
        ts::seal_row_in_place(&a, &mut row);
        b.put_attestation(SignedAttestation { attestation: row }).await.expect("I152: the malformed-pointer row is stored (its pointer is refused where it is USED)");
        let mut got: Vec<String> = b
            .attestations_binding_content(&sha_hex)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.attestation_id)
            .collect();
        got.sort();
        let mut want = vec![p.clone(), e.clone(), bad.clone()];
        want.sort();
        assert_eq!(got, want, "I152: the resolver returns the pointer shape, the evidence_refs shape, AND the unreadable pointer (a row that plainly references these bytes)");
    }

    /// **I153 — `evict_blob` retracts before it deletes, and aborts on a
    /// refused retraction** (#862 part 1; I18's contract for one sha).
    pub async fn i153_evict_blob_retracts_then_deletes<B>(b: &B, engine: &crate::Engine, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let prefix = crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX;
        // The announcing key is the ENGINE's own local signer: `evict_blob`
        // retracts THIS node's claims, which are the ones that key made. The
        // runner seeds the engine from the label below; the assert pins it.
        let signer =
            crate::federation::at_rest_cascade::blob_invariants::node_signer(b, "node-tomb").await;
        let node = signer.derived_key_id();
        assert_eq!(
            engine.local_derived_key_id().await.unwrap(),
            node,
            "I153: the runner's engine must be signed by the label this body rebuilds"
        );
        let withdraws_by = |n: String| async move {
            b.list_attestations_by(&n)
                .await
                .unwrap()
                .into_iter()
                .filter(|a| a.attestation_type == attestation_type::WITHDRAWS)
                .count()
        };
        // This node announces a blob (put_blob_signing_at emits holds_bytes).
        let body = format!("held by this node {s}").into_bytes();
        let sha = *blake_free_sha(&body);
        b.put_blob_signing_at(
            crate::federation::types::cohort_scope::FEDERATION,
            crate::federation::StorageFloor::resolved(
                crate::federation::types::cohort_scope::CryptoTier::Plaintext,
            ),
            &sha,
            crate::federation::BlobBody::Inline(body.clone()),
            None,
            &node,
            &signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .expect("I153: announce");
        assert!(
            b.list_attestations_by(&node)
                .await
                .unwrap()
                .iter()
                .any(|a| a.attestation_type.starts_with(prefix)),
            "I153: precondition — a holds_bytes claim"
        );
        assert_eq!(withdraws_by(node.clone()).await, 0);

        let rep = engine
            .evict_blob(&sha, chrono::Utc::now())
            .await
            .unwrap_or_else(|e| panic!("I153: evict_blob: {e}"));
        assert_eq!(
            rep.withdraws_emitted, 1,
            "I153: exactly one withdraws for this node's claim"
        );
        assert!(rep.blob_deleted, "I153: and the bytes are gone");
        assert!(!b.has_blob(&sha).await.unwrap(), "I153: deleted");
        assert_eq!(withdraws_by(node.clone()).await, 1, "I153: one retraction");
        assert!(
            !b.list_local_holders(&sha).await.unwrap().contains(&node),
            "I153: this node no longer lists itself as a holder"
        );
        // A REFUSED retraction ABORTS (I18's contract for one sha): announce a
        // second blob, then evict it with a `now` far outside the admission
        // skew, so the withdraws cannot be admitted. The bytes and the claim
        // must survive, and the error must surface — a door that deleted
        // first would report a retraction that never happened.
        let body2 = format!("held by this node, second {s}").into_bytes();
        let sha2 = *blake_free_sha(&body2);
        b.put_blob_signing_at(
            crate::federation::types::cohort_scope::FEDERATION,
            crate::federation::StorageFloor::resolved(
                crate::federation::types::cohort_scope::CryptoTier::Plaintext,
            ),
            &sha2,
            crate::federation::BlobBody::Inline(body2),
            None,
            &node,
            &signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .expect("I153: announce the second blob");
        let far_future = chrono::Utc::now() + chrono::Duration::days(3650);
        let res = engine.evict_blob(&sha2, far_future).await;
        assert!(
            res.is_err(),
            "I153: a retraction that cannot be admitted must ABORT the eviction, got {res:?}"
        );
        assert!(
            b.has_blob(&sha2).await.unwrap(),
            "I153: the bytes were DELETED although the retraction failed"
        );
        assert!(
            b.list_local_holders(&sha2).await.unwrap().contains(&node),
            "I153: the claim survives a failed eviction"
        );

        // Retry after success: no second retraction, nothing held.
        let again = engine.evict_blob(&sha, chrono::Utc::now()).await.unwrap();
        assert_eq!(
            (again.withdraws_emitted, again.blob_deleted),
            (0, false),
            "I153: a retry is a no-op"
        );
        assert_eq!(withdraws_by(node).await, 1, "I153: never double-retracts");
    }

    /// The at-rest sha of a plaintext body is its sha256 (the storage floor
    /// stores plaintext bytes verbatim).
    fn blake_free_sha(body: &[u8]) -> Box<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(body);
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        Box::new(out)
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i149() {
                    let Some((engine, b)) = $fresh.await else {
                        return;
                    };
                    super::super::bodies::i149_a_withdrawn_reference_stops_the_bytes(
                        &*b,
                        &engine,
                        &super::suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i150() {
                    let Some((engine, b)) = $fresh.await else {
                        return;
                    };
                    super::super::bodies::i150_the_stored_rule_is_never_consulted(
                        &*b,
                        &engine,
                        &super::suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i151() {
                    let Some((engine, b)) = $fresh.await else {
                        return;
                    };
                    super::super::bodies::i151_one_live_binding_keeps_the_bytes(
                        &*b,
                        &engine,
                        &super::suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i152() {
                    let Some((_engine, b)) = $fresh.await else {
                        return;
                    };
                    super::super::bodies::i152_the_resolver_sees_the_pointer_shape(
                        &*b,
                        &super::suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i153() {
                    let Some((engine, b)) = $fresh.await else {
                        return;
                    };
                    super::super::bodies::i153_evict_blob_retracts_then_deletes(
                        &*b,
                        &engine,
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        let signer = crate::federation::tier_ingest::test_support::local_signer("node-tomb");
        let engine = crate::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .unwrap();
        let b = engine.sqlite_backend().expect("sqlite").clone();
        Some((engine, b))
    });

    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        let dsn = crate::test_pg::empty_dsn()?;
        let signer = crate::federation::tier_ingest::test_support::local_signer("node-tomb");
        let engine = crate::Engine::with_signer(signer, &dsn).await.unwrap();
        let b = engine.postgres_backend().expect("postgres").clone();
        Some((engine, b))
    });
}
