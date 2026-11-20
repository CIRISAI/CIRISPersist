//! v47.2.0 (CIRISPersist#853, #862, `FSD/BYTES_PLANE_TOMBSTONE.md` §4) —
//! **CC 2.3 at the bytes plane**: a withdrawn reference stops the bytes on
//! every door that reads them, the stored admission rule is never consulted,
//! one live binding keeps the bytes, the resolver sees the pointer shape, and
//! `evict_blob` retracts before it deletes, and (v53.0.1, I149b) a custody
//! report is a holding fact, never a binding.

/// The I149–I153 bodies, one per backend runner (sqlite + postgres: the
/// memory backend has no blob storage).
#[cfg(all(
    any(test, feature = "test-anchor"),
    any(feature = "sqlite", feature = "postgres")
))]
pub mod bodies {
    use crate::federation::blob_tombstone::{binding_state, BindingState};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    /// A federation-tier content row by `author`, about `subjects`, that
    /// binds `sha_hex` by a **pointer member** (the chat shape: no
    /// `evidence_refs`) when `by_pointer`, else by `evidence_refs`. Returns
    /// the node-computed row id (v62: `id` is only a label).
    async fn bind_row<B>(
        b: &B,
        id: &str,
        author: &str,
        subjects: &[&str],
        sha_hex: &str,
        by_pointer: bool,
    ) -> String
    where
        B: FederationDirectory + Sync,
    {
        let env = if by_pointer {
            serde_json::json!({
                "id": id, "dimension": "file:v1", "cohort_scope": "federation",
                "content": {"content_sha256": sha_hex, "community_key_id": "", "tier": "invisible_encrypted"}
            })
        } else {
            serde_json::json!({
                "id": id, "dimension": "file:v1", "cohort_scope": "federation",
                "evidence_refs": [sha_hex]
            })
        };
        // v62 (E4): the earlier-shaped literal, then the author's edition-2
        // statement of it through the statement door.
        let mut row = ts::bare_attestation(id, author, author, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.cohort_scope = "federation".into();
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        let stored = e2::try_put_row(b, &row, author)
            .await
            .unwrap_or_else(|e| panic!("bind_row {id}: {e}"));
        e2::rid(&stored)
    }

    /// A `withdraws` by `issuer` naming `target_id`, through the real door.
    /// Returns its node-computed row id. v62: a composer carries its
    /// target's family, so the target must be held.
    async fn withdraw<B>(
        b: &B,
        id: &str,
        issuer: &str,
        target_id: &str,
    ) -> Result<String, crate::federation::Error>
    where
        B: FederationDirectory + Sync,
    {
        let target = b.get_attestation(target_id).await?.ok_or_else(|| {
            crate::federation::Error::InvalidArgument(format!("withdraw {id}: target not held"))
        })?;
        let env = serde_json::json!({
            "references_attestation_id": target_id,
            // v62 (E4 round 3): a composer's payload is the common members and
            // `refs.target` only (P1e); `withdrawal_reason` is not one.
        });
        let mut w = ts::bare_attestation(id, issuer, issuer, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.cohort_scope = "federation".into();
        let st = e2::statement_of_family(&w, issuer, &e2::family_of(&target));
        e2::put_statement(b, &st).await?;
        Ok(e2::rid(&e2::row_of_statement(&st, "federation")))
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
            e2::put_key(b, k, &[crate::federation::types::identity_type::USER]).await;
        }
        let (sha, author) = seal_blob(
            b,
            &format!("i149-author-{s}"),
            b"the subject appears in this file",
        )
        .await;
        let sha_hex = hex::encode(sha);
        let row = bind_row(
            b,
            &format!("i149-row-{s}"),
            &author,
            &[&author, &subject],
            &sha_hex,
            true,
        )
        .await;

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
        let w = withdraw(b, &format!("i149-w-{s}"), &subject, &row)
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
        let r = engine.read_blob_as(&sha, &e2::kid(&stranger), None).await;
        assert!(
            matches!(&r, Err(BlobError::Withdrawn { .. })),
            "I149: on a commons blob every viewer is authorized: {r:?}"
        );

        // The ORDER claim — authorization before the fold, so a stranger learns
        // nothing — is made on a SEALED tier: a community blob a keyed member
        // occurrence can read (the cohort-lifecycle fixture), bound and
        // withdrawn the same way. The member sees `Withdrawn`; a stranger is
        // `NotGranted` and never sees the tombstone.
        let comm = crate::federation::edition2::fixture_switch::kid(&format!("i149-comm-{s}")); // v62 (E4): the typed row is keyed by identity-ref
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
        // v62 (E4-fix6; cut B): the minter is named by the signer's
        // federation id (its composite identity-ref).
        .federation_id()
        .await;
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
            // v62 (E4-fix6): the viewer is named by its identity-ref.
            kind_of(
                &engine
                    .read_blob_as(&sealed, &e2::kid(&alice_occ), None)
                    .await
            ),
            "ok",
            "I149: the member occurrence reads the sealed blob before"
        );
        let sealed_row = bind_row(
            b,
            &format!("i149-sealed-row-{s}"),
            &alice,
            &[&alice, &subject],
            &hex::encode(sealed),
            true,
        )
        .await;
        withdraw(b, &format!("i149-sealed-w-{s}"), &subject, &sealed_row)
            .await
            .expect("I149: the subject withdraws the sealed row");
        let r = engine
            .read_blob_as(&sealed, &e2::kid(&alice_occ), None)
            .await;
        assert!(
            matches!(&r, Err(BlobError::Withdrawn { .. })),
            "I149: the member sees Withdrawn on the sealed, withdrawn blob: {r:?}"
        );
        let r = engine
            .read_blob_as(&sealed, &e2::kid(&stranger), None)
            .await;
        assert!(
            matches!(&r, Err(BlobError::NotGranted { .. })),
            "I149: a stranger is NotGranted FIRST on a sealed blob and never sees the tombstone: {r:?}"
        );
    }

    // v62 (E4): I150 ("the stored rule is not consulted") is deleted. Its
    // premise is a `withdraws` admitted AHEAD of its target and stored with
    // rule None; an edition-2 composer names its target by `refs.target` and
    // carries the target's family, so it waits until the target is held and
    // is never stored ahead of it. The fold's re-derivation is still
    // witnessed by I149 (a subject's withdraws) and I151.

    /// **I151 — one live binding keeps the bytes.**
    pub async fn i151_one_live_binding_keeps_the_bytes<B>(b: &B, engine: &crate::Engine, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let c = format!("i151-c-{s}");
        e2::put_key(b, &c, &[crate::federation::types::identity_type::USER]).await;
        let (sha, a) = seal_blob(b, &format!("i151-a-{s}"), b"quoted twice").await;
        let hx = hex::encode(sha);
        let r1 = bind_row(b, &format!("i151-r1-{s}"), &a, &[&a], &hx, true).await;
        // the other reference shape
        let r2 = bind_row(b, &format!("i151-r2-{s}"), &c, &[&c], &hx, false).await;
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

    /// A federation-tier `custody:ack:v1` `here` by `device` for `sha`: the
    /// row node B holds once a device's report reaches it (CIRISEdge#763).
    /// v55.0.0 (CIRISPersist#989, CC 3.1.3.3 rule 1) — placed at the
    /// content's scope: [`seal_blob`] writes Commons content, so `federation`.
    #[cfg(test)]
    async fn custody_here<B>(b: &B, id: &str, device: &str, sha: &[u8; 32])
    where
        B: FederationDirectory + Sync,
    {
        let mut env = crate::federation::custody_ack::custody_ack_envelope(
            sha,
            crate::federation::custody_ack::CustodyState::Here,
            Some(4096),
            crate::federation::types::cohort_scope::FEDERATION,
            None,
        )
        .expect("custody envelope");
        env["id"] = serde_json::json!(id);
        let mut row = ts::bare_attestation(id, device, device, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.cohort_scope = crate::federation::types::cohort_scope::FEDERATION.into();
        ts::seal_row_in_place(device, &mut row);
        b.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("custody_here {id}: {e}"));
    }

    /// **I149b — a custody report is a holding fact, never a binding**
    /// (v53.0.1; CC 2.3 + CC 3.1.3.3; found by CIRISEdge#763). A device that
    /// filed `here` for a file kept it Live after its author withdrew it, read
    /// it and served it, and was counted a subject of it.
    ///
    /// - (a) the file row withdrawn, the device's `here` standing: Withdrawn,
    ///   and every door refuses;
    /// - (b) the report does not make the device a subject (or duty holder)
    ///   of the content;
    /// - (d) a GENUINE second referencing row still keeps the bytes Live, so
    ///   the exclusion is the custody family only.
    #[cfg(test)]
    pub async fn i149b_a_custody_report_is_not_a_binding<B>(b: &B, engine: &crate::Engine, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let device = crate::federation::custody_ack_invariants::bodies::device(
            b as &dyn FederationDirectory,
            &format!("i149b-{s}"),
        )
        .await;
        let (sha, author) = seal_blob(b, &format!("i149b-author-{s}"), b"alice's self file").await;
        let hx = hex::encode(sha);
        let file = bind_row(
            b,
            &format!("i149b-file-{s}"),
            &author,
            &[&author],
            &hx,
            false,
        )
        .await;
        custody_here(b, &format!("i149b-ack-{s}"), &device, &sha).await;

        let mut ids: Vec<String> = b
            .attestations_binding_content(&hx)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.attestation_id)
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            vec![file.clone()],
            "I149b: the resolver returns the file row only — a custody report binds nothing"
        );
        // (b)
        let subjects =
            crate::federation::admission::subject_of_content(b as &dyn FederationDirectory, &hx)
                .await
                .unwrap();
        assert!(
            !subjects.contains(&device),
            "I149b(b): the reporting device is not a subject of the content: {subjects:?}"
        );

        // (a)
        withdraw(b, &format!("i149b-w-{s}"), &author, &file)
            .await
            .unwrap();
        assert!(
            matches!(
                binding_state(b as &dyn FederationDirectory, &sha)
                    .await
                    .unwrap(),
                BindingState::Withdrawn { .. }
            ),
            "I149b(a): the author withdrew the only binding; the device's `here` keeps nothing Live"
        );
        assert_eq!(
            kind_of(&engine.read_blob_as(&sha, &author, None).await),
            "blob_withdrawn",
            "I149b(a): the read door refuses"
        );
        assert!(
            engine.serve_blob_to_peer(&sha, "peer").await.is_err(),
            "I149b(a): the serve door refuses"
        );

        // (d) — a genuine second reference keeps a second blob Live.
        let (sha2, a2) = seal_blob(b, &format!("i149b-a2-{s}"), b"quoted twice").await;
        let hx2 = hex::encode(sha2);
        let r1 = bind_row(b, &format!("i149b-r1-{s}"), &a2, &[&a2], &hx2, false).await;
        bind_row(b, &format!("i149b-r2-{s}"), &a2, &[&a2], &hx2, true).await;
        custody_here(b, &format!("i149b-ack2-{s}"), &device, &sha2).await;
        withdraw(b, &format!("i149b-w1-{s}"), &a2, &r1)
            .await
            .unwrap();
        assert_eq!(
            binding_state(b as &dyn FederationDirectory, &sha2)
                .await
                .unwrap(),
            BindingState::Live,
            "I149b(d): one genuine reference still stands — the exclusion is custody only"
        );
        assert_eq!(kind_of(&engine.read_blob_as(&sha2, &a2, None).await), "ok");
    }

    /// **I152 — the resolver sees the pointer shape** (#862 part 2), and an
    /// unreadable pointer at that sha still counts as binding.
    pub async fn i152_the_resolver_sees_the_pointer_shape<B>(b: &B, s: &str)
    where
        B: FederationDirectory + Sync,
    {
        let a = format!("i152-a-{s}");
        e2::put_key(b, &a, &[crate::federation::types::identity_type::USER]).await;
        let sha_hex = "ab".repeat(32);
        let (p, e, bad) = (
            format!("i152-p-{s}"),
            format!("i152-e-{s}"),
            format!("i152-bad-{s}"),
        );
        let p = bind_row(b, &p, &a, &[&a], &sha_hex, true).await;
        let e = bind_row(b, &e, &a, &[&a], &sha_hex, false).await;
        // Pointer-shaped at these bytes but unreadable (a non-string tier).
        let env = serde_json::json!({
            "id": bad, "dimension": "file:v1", "cohort_scope": "federation",
            "content": {"content_sha256": sha_hex, "community_key_id": "", "tier": 7}
        });
        let mut row = ts::bare_attestation(&bad, &a, &a, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.cohort_scope = "federation".into();
        row.subject_key_ids = vec![a.clone()];
        let bad = e2::rid(&e2::try_put_row(b, &row, &a).await.expect(
            "I152: the malformed-pointer row is stored (its pointer is refused where it is USED)",
        ));
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
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        // The announcing key is the ENGINE's own local signer: `evict_blob`
        // retracts THIS node's claims, which are the ones that key made. The
        // runner seeds the engine from the label below; the assert pins it.
        let signer =
            crate::federation::at_rest_cascade::blob_invariants::node_signer(b, "node-tomb").await;
        // v62 (E4 round 3; cut B): the engine names its local signer by the
        // signer's federation id (the composite identity-ref).
        assert_eq!(
            engine.local_derived_key_id().await.unwrap(),
            signer.federation_id().await,
            "I153: the runner's engine must be signed by the label this body rebuilds"
        );
        // v62 (E4, wave 4; cut B): the node states its rows (the holding
        // claim, the eviction's `withdraws`) under its composite identity-ref.
        let node = signer.federation_id().await;
        let withdraws_by = |n: String| async move {
            b.all_attestations_by(&n)
                .await
                .unwrap()
                .into_iter()
                .filter(|a| a.attestation_type == attestation_type::WITHDRAWS)
                .count()
        };
        // This node announces a blob (put_blob_signing_at emits the holding
        // claim, `custody:ack:v1` — v55.0.0).
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
            None,
        )
        .await
        .expect("I153: announce");
        assert!(
            b.all_attestations_by(&node)
                .await
                .unwrap()
                .iter()
                .any(crate::federation::custody_ack::is_custody_row),
            "I153: precondition — a holding claim"
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
        // v62 (E4-fix6; ruling 4): the far-future-`now` abort leg is DELETED.
        // It made the retraction inadmissible by passing an instant outside
        // the admission skew; in v62 the node states its `withdraws` at its
        // own clock (CC 2.4.1.1: a stamped instant is the signer's; the
        // emission helper ignores the caller's `now`), so that row cannot be
        // built. The abort contract itself is unchanged in
        // `holding_claim::retract_own_claims` (an emission error aborts
        // before any byte is deleted).

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
                async fn i149b() {
                    let Some((engine, b)) = $fresh.await else {
                        return;
                    };
                    super::super::bodies::i149b_a_custody_report_is_not_a_binding(
                        &*b,
                        &engine,
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
