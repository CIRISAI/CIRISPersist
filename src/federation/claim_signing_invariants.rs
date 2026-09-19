//! CIRISPersist#851 (`FSD/BLOB_REPLICATION.md` §20.5) — **the holder
//! claim crosses the federation-tier gate.**
//!
//! A `holds_bytes` claim is FEDERATION-tier: the attestation cursor serves
//! it and every peer runs it through the tier ingest gate, which requires a
//! hybrid Ed25519 + ML-DSA-65 signature (CC 5.3.2.4.3.1). A classical-only
//! claim is confined to local tier — served, and refused by every peer. An
//! Engine that has a [`LocalSigner`](crate::signing::LocalSigner) therefore
//! signs the claim hybrid, and I79 witnesses the crossing end to end through
//! the Engine doors: A writes, A's stored claim carries the PQC half, B
//! admits it.

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use crate::federation::key_grant_invariants::two_node::{
        introduce, seed_community_everywhere, Node,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
    use crate::federation::types::identity_type::USER;
    use crate::federation::{
        BlobStorage, EncryptionPubkeys, FederationDirectory, SignedAttestation,
    };

    /// **I79 — a holder claim signed by an Engine with a LocalSigner is
    /// hybrid, and a peer admits it.** Before #851 §20.5 the claim was
    /// signed classical-only (`scrub_signature_pqc: None`): A's cursor served
    /// it and B refused it at the federation-tier ingest gate ("PQC signature
    /// without pubkey"), so no peer ever learned who held the bytes.
    #[tokio::test]
    async fn i79_holds_bytes_claim_is_hybrid_signed_and_a_peer_admits_it_sqlite() {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let (alias_a, alias_b) = (format!("i79-a-{run}"), format!("i79-b-{run}"));
        let engine_a =
            crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), "sqlite::memory:")
                .await
                .unwrap();
        let engine_b =
            crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_b), "sqlite::memory:")
                .await
                .unwrap();
        for (e, alias) in [(&engine_a, &alias_a), (&engine_b, &alias_b)] {
            e.register_self_federation_key(USER, alias, None, serde_json::json!({}), vec![])
                .await
                .expect("register the engine's own key");
        }
        let (sa, sb) = (
            engine_a.sqlite_backend().unwrap().clone(),
            engine_b.sqlite_backend().unwrap().clone(),
        );
        let kem =
            |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            };
        let a = Node {
            backend: sa.as_ref(),
            signer: ts::local_signer(&alias_a),
            key: engine_a.local_derived_key_id().await.unwrap(),
            kem: kem(sa.load_or_init_content_kem_identity().await.unwrap()),
        };
        let b = Node {
            backend: sb.as_ref(),
            signer: ts::local_signer(&alias_b),
            key: engine_b.local_derived_key_id().await.unwrap(),
            kem: kem(sb.load_or_init_content_kem_identity().await.unwrap()),
        };
        introduce(&[&a, &b], &[&alias_a, &alias_b]).await;
        let comm = format!("i79-comm-{run}");
        let (alice, bob) = (format!("i79-alice-{run}"), format!("i79-bob-{run}"));
        seed_community_everywhere(&[&a, &b], &comm, &[(&alice, Some(&a)), (&bob, Some(&b))]).await;

        // A writes through THE door; the door announces the sealed bytes.
        let r = engine_a
            .put_blob_scoped(COMMUNITY, Some(&comm), b"i79 minutes", None, None)
            .await
            .expect("A's scoped put");
        assert_eq!(r.tier, CryptoTier::CommunityDek);

        // The stored claim carries BOTH halves: it is a federation-tier row.
        let claims: Vec<_> = sa
            .list_attestations_since(None, 1_000)
            .await
            .unwrap()
            .into_iter()
            .map(|served| served.attestation)
            .filter(|row| row.attestation_type.starts_with("holds_bytes:"))
            .collect();
        assert_eq!(
            claims.len(),
            1,
            "I79: A's write announced exactly one claim"
        );
        let claim = claims.into_iter().next().unwrap();
        assert_eq!(
            claim.attesting_key_id, a.key,
            "I79: the HOLDER claims (I23)"
        );
        assert_eq!(
            claim.scrub_key_id, a.key,
            "I79: signed by the holder's derived key"
        );
        assert!(
            claim.scrub_signature_pqc.is_some(),
            "I79: an Engine with a LocalSigner signs the holds_bytes claim HYBRID — a \
             classical-only claim is confined to local tier (CC 5.3.2.4.3.1) and every peer \
             refuses it; row {} (tier={}) carries no PQC half",
            claim.attestation_type,
            claim.tier
        );

        // B admits it through the Engine door — the federation-tier gate.
        let outcome = engine_b
            .apply_replicated_attestation(SignedAttestation { attestation: claim })
            .await;
        assert!(
            outcome.is_ok(),
            "I79: the peer admits A's hybrid-signed holder claim at the federation-tier \
             ingest gate, got {outcome:?}"
        );

        // ── leg 2: the COMMONS door (`Engine::put_blob_signing`) ─────────
        // The same defect at the other production door: the trait default
        // `put_blob_signing` is classical-only; the Engine door must reach
        // the floor with its LocalSigner.
        use sha2::Digest as _;
        let public = b"i79 commons bytes";
        let sha: [u8; 32] = sha2::Sha256::digest(public).into();
        engine_a
            .put_blob_signing(
                &sha,
                crate::federation::BlobBody::Inline(public.to_vec()),
                None,
                &a.key,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("A's commons put");
        let commons: Vec<_> = sa
            .list_attestations_since(None, 1_000)
            .await
            .unwrap()
            .into_iter()
            .map(|served| served.attestation)
            .filter(|row| {
                row.attestation_type == crate::federation::holds_bytes_attestation_type(&sha)
            })
            .collect();
        assert_eq!(commons.len(), 1, "I79/2: the commons door announced once");
        let claim = commons.into_iter().next().unwrap();
        assert_eq!(
            claim.scrub_key_id, a.key,
            "I79/2: signed by the holder's derived key"
        );
        assert!(
            claim.scrub_signature_pqc.is_some(),
            "I79/2: the commons door announces HYBRID when the Engine has a LocalSigner; \
             row {} (tier={}) carries no PQC half",
            claim.attestation_type,
            claim.tier
        );
        let outcome = engine_b
            .apply_replicated_attestation(SignedAttestation { attestation: claim })
            .await;
        assert!(
            outcome.is_ok(),
            "I79/2: the peer admits A's commons claim at the federation-tier gate, got \
             {outcome:?}"
        );
    }

    /// **I80 — a `LocalSigner` with no ML-DSA-65 half cannot sign a claim.**
    /// Hybrid/PQC only, no legacy fallback (operator ruling, §20.5): a
    /// classical-only producer does not announce — it REFUSES, rather than
    /// minting a federation-tier claim every peer's ingest gate discards.
    #[tokio::test]
    async fn i80_a_pqc_less_local_signer_cannot_sign_a_claim() {
        use crate::federation::blobs::sign_holds_bytes_claim;
        use crate::signing::LocalSigner;
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x51u8; 32]);
        let local = LocalSigner::from_parts(ed, "i80-classical-only".to_owned(), None, None);
        assert!(
            local.pqc_signer().is_none(),
            "I80: precondition — no PQC signer"
        );
        let key = local.derived_key_id();
        let err = sign_holds_bytes_claim(
            &local,
            &[0x80u8; 32],
            &key,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            1,
        )
        .await
        .expect_err("I80: a classical-only producer must not announce");
        let msg = err.to_string();
        assert!(
            msg.contains("hybrid-only") && msg.contains("ML-DSA-65"),
            "I80: the refusal names the rule: {msg}"
        );
    }

    /// **I81 — the signer of a claim IS its claimed attester.** A LocalSigner
    /// belonging to another identity never signs (an Engine whose composed
    /// signer and LocalSigner differ, `from_shared_with_local`): the claim
    /// would be attributed to one key and signed by another, which every peer
    /// refuses. There is no classical fallback to drop to — it REFUSES.
    #[tokio::test]
    async fn i81_a_local_signer_that_is_not_the_attester_refuses() {
        use crate::federation::blobs::sign_holds_bytes_claim;
        let attester = crate::federation::tier_ingest::test_support::local_signer("i81-attester");
        let other = crate::federation::tier_ingest::test_support::local_signer("i81-other");
        assert_ne!(attester.derived_key_id(), other.derived_key_id());
        let key = attester.derived_key_id();
        let sha = [0x81u8; 32];
        let (id, now) = (uuid::Uuid::new_v4(), chrono::Utc::now());
        let err = sign_holds_bytes_claim(&other, &sha, &key, id, now, 1)
            .await
            .expect_err("I81: a foreign LocalSigner must not sign this attester's claim");
        let msg = err.to_string();
        assert!(
            msg.contains("hybrid-only") && msg.contains("not the claimed attester"),
            "I81: the refusal names the mismatch: {msg}"
        );
        // The attester's own LocalSigner signs, hybrid, attributed to itself.
        let own = sign_holds_bytes_claim(&attester, &sha, &key, id, now, 1)
            .await
            .expect("I81: the attester signs its own claim");
        assert!(own.scrub_signature_pqc.is_some(), "I81: hybrid");
        assert_eq!(own.scrub_key_id, key);
    }

    /// **I83 — an Engine with no PQC LocalSigner cannot announce, and stores
    /// nothing under a claim it cannot make.** The commons door refuses
    /// before the row exists; nothing is left for a peer to refuse later.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i83_an_engine_without_a_local_signer_cannot_announce_sqlite() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::{BlobBody, BlobStorage};
        use crate::store::Backend as _;
        use std::sync::Arc;
        let backend = Arc::new(
            crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap(),
        );
        backend.run_migrations().await.unwrap();
        let local = ts::local_signer("i83-node");
        let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            crate::signing::LocalSignerHardwareAdapter::new(local.clone()),
        );
        // `from_shared` — a node with no LocalSigner at all.
        let engine = crate::Engine::from_shared(
            crate::engine::BackendDispatch::Sqlite(backend.clone()),
            signer,
        );
        let body = b"i83 commons bytes".to_vec();
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&body).into()
        };
        let err = engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(body),
                None,
                &local.derived_key_id(),
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect_err("I83: no LocalSigner, no announcement");
        let msg = err.to_string();
        assert!(
            msg.contains("hybrid-only") && msg.contains("cannot announce"),
            "I83: the refusal names the rule: {msg}"
        );
        assert!(
            backend.get_blob(&sha).await.unwrap().is_none(),
            "I83: the refused write stored no bytes"
        );
    }

    /// **I88 (review round seven) — the announcing preflight asks the question
    /// the CASCADE will ask later.** An Ed25519-only `LocalSigner` that IS this
    /// node's identity passes both earlier clauses (it exists; it matches), so
    /// before this the commons door persisted ciphertext and minted grants and
    /// only THEN failed inside `sign_hybrid` — leaving an orphaned blob whose
    /// key was never federated, the exact state §20.5 exists to prevent. The
    /// refusal must happen before the cascade mutates storage.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i88_a_pqc_less_announcing_engine_refuses_before_the_cascade_writes_sqlite() {
        use crate::federation::BlobStorage;
        use crate::signing::LocalSigner;
        use crate::store::Backend as _;
        use std::sync::Arc;
        let backend = Arc::new(
            crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap(),
        );
        backend.run_migrations().await.unwrap();

        // The engine's ONE identity is classical-only: the composed signer and
        // the LocalSigner are the same key, so the identity clause passes and
        // only the PQC clause can refuse.
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x88u8; 32]);
        let local = Arc::new(LocalSigner::from_parts(
            ed,
            "i88-classical-only".to_owned(),
            None,
            None,
        ));
        assert!(
            local.pqc_signer().is_none(),
            "I88: precondition — the LocalSigner has no ML-DSA-65 half"
        );
        let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            crate::signing::LocalSignerHardwareAdapter::new(local.clone()),
        );
        let engine = crate::Engine::from_shared_with_local(
            crate::engine::BackendDispatch::Sqlite(backend.clone()),
            signer,
            Some(local.clone()),
        );

        let node_key = local.derived_key_id();

        // The commons door: the blob is addressed by a sha the CALLER knows, so
        // "was anything stored?" is directly observable — no guessing at a
        // ciphertext address.
        let body = b"i88 commons bytes that must never be stored".to_vec();
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&body).into()
        };
        assert!(
            backend.get_blob(&sha).await.unwrap().is_none(),
            "I88: precondition — nothing stored at this address yet"
        );

        let err = engine
            .put_blob_signing(
                &sha,
                crate::federation::BlobBody::Inline(body),
                None,
                &node_key,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect_err("I88: a PQC-less announcing engine must refuse the commons door");
        // The orphan check FIRST — it is the claim. A deeper gate
        // (`sign_holds_bytes_claim`) also refuses a PQC-less signer, so the
        // ERROR alone cannot tell a preflight from a late failure; only the
        // absence of stored bytes can.
        assert!(
            backend.get_blob(&sha).await.unwrap().is_none(),
            "I88: the refused door stored NO bytes — it refused BEFORE writing, \
             not after"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("hybrid-only") && msg.contains("ML-DSA-65"),
            "I88: the refusal names the rule: {msg}"
        );
        assert!(
            msg.contains("BEFORE any cascade writes"),
            "I88: the refusal is the PREFLIGHT, not the late signing failure: {msg}"
        );

        // Leg 2 — the CASCADE door, which is where the orphan actually lives.
        // The commons door signs before it stores, so nothing is left behind
        // there; `put_blob_scoped` mints the epoch DEK and seals FIRST and only
        // then signs, so without the preflight it strands key material and
        // ciphertext for a blob whose grant set can never be emitted.
        let comm = "community-i88";
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend.as_ref(),
            comm,
            &[("i88-alice", "i88-alice-occ")],
        )
        .await;
        for epoch in 0..2u64 {
            assert!(
                backend
                    .community_dek_get_self_retention(comm, &node_key, epoch)
                    .await
                    .expect("I88: baseline DEK read")
                    .is_none(),
                "I88: precondition — no epoch {epoch} DEK before the scoped write"
            );
        }
        let err = engine
            .put_blob_scoped(
                crate::federation::types::cohort_scope::COMMUNITY,
                Some(comm),
                b"i88 community bytes that must never be sealed",
                None,
                None,
            )
            .await
            .expect_err("I88: a PQC-less announcing engine must refuse the cascade door");
        assert!(
            err.to_string().contains("BEFORE any cascade writes"),
            "I88: the cascade door refuses at the preflight: {err}"
        );
        for epoch in 0..2u64 {
            assert!(
                backend
                    .community_dek_get_self_retention(comm, &node_key, epoch)
                    .await
                    .expect("I88: DEK read after the refusal")
                    .is_none(),
                "I88: the refused cascade minted NO epoch {epoch} DEK — it never ran"
            );
        }
    }

    /// **I89 (review round eight) — ONE predicate, asked by every announcing
    /// door.** Round six added the identity check to `Engine::announcing_signer`
    /// and round seven added the PQC check there and in the PyO3 door; the PyO3
    /// door still had no identity check, so a hardware-signer engine carrying a
    /// distinct legacy local key would attribute and sign the holder claim as
    /// that unrelated key, recording the wrong node as holder. The mismatch
    /// needs real hardware to reproduce through the Python surface, so the
    /// predicate is extracted and witnessed HERE, where both doors call it.
    #[test]
    fn i89_the_announcing_predicate_refuses_a_foreign_or_pqc_less_signer() {
        use crate::federation::blobs::check_announcing_signer;
        use crate::signing::LocalSigner;

        let node = crate::federation::tier_ingest::test_support::local_signer("i89-node");
        let node_key = node.derived_key_id();
        assert!(
            node.pqc_signer().is_some(),
            "I89: precondition — the node signer is hybrid"
        );

        // The engine's own hybrid signer is admitted.
        check_announcing_signer(&node, &node_key)
            .expect("I89: this node's own hybrid LocalSigner announces");

        // A FOREIGN hybrid signer is refused — the round-eight hole. It has a
        // PQC half, so only the identity clause can reject it.
        let foreign = crate::federation::tier_ingest::test_support::local_signer("i89-foreign");
        assert_ne!(
            foreign.derived_key_id(),
            node_key,
            "I89: precondition — the foreign signer is a different identity"
        );
        let err = check_announcing_signer(&foreign, &node_key)
            .expect_err("I89: a LocalSigner that is not this node must not announce");
        let msg = err.to_string();
        assert!(
            msg.contains("is not its node identity") && msg.contains("wrong node as holder"),
            "I89: the refusal names WHY it matters: {msg}"
        );

        // A PQC-less signer that IS this node is refused on the other clause,
        // and the message says the refusal precedes any write.
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x89u8; 32]);
        let classical = LocalSigner::from_parts(ed, "i89-classical".to_owned(), None, None);
        let classical_key = classical.derived_key_id();
        let err = check_announcing_signer(&classical, &classical_key)
            .expect_err("I89: a PQC-less LocalSigner must not announce");
        let msg = err.to_string();
        assert!(
            msg.contains("ML-DSA-65") && msg.contains("BEFORE any cascade writes"),
            "I89: the refusal names the rule and WHEN it fires: {msg}"
        );

        // Both clauses at once still refuses, and identity is reported first —
        // it is the one that would record the wrong node.
        let err = check_announcing_signer(&classical, &node_key)
            .expect_err("I89: foreign AND PQC-less refuses");
        assert!(
            err.to_string().contains("is not its node identity"),
            "I89: identity is the clause reported when both fail: {err}"
        );
    }

    /// **I89 (b) — every announcing accessor ROUTES to the shared predicate.**
    /// I89 proves the predicate is right; this proves both doors ask it, which
    /// is the part that actually failed. `include_str!` rather than a runtime
    /// read, so the assertion is fixed at compile time against THIS tree and
    /// cannot drift with the working directory
    /// (`feedback_from_disk_gates_are_not_hermetic`).
    #[test]
    fn i89b_both_announcing_doors_route_to_the_shared_predicate() {
        const ENGINE_RS: &str = include_str!("../engine.rs");
        const PYO3_RS: &str = include_str!("../ffi/pyo3.rs");

        // The Rust door.
        let engine_fn = ENGINE_RS
            .split("async fn announcing_signer(")
            .nth(1)
            .expect("I89 (b): Engine::announcing_signer exists");
        let engine_body = &engine_fn[..engine_fn.find("\n    }").expect("fn end")];
        assert!(
            engine_body.contains("check_announcing_signer("),
            "I89 (b): Engine::announcing_signer must ask the shared predicate, not its own copy"
        );

        // The PyO3 door.
        let py_fn = PYO3_RS
            .split("fn announcing_signer_any(")
            .nth(1)
            .expect("I89 (b): PyEngine::announcing_signer_any exists");
        let py_body = &py_fn[..py_fn.find("\n    }").expect("fn end")];
        assert!(
            py_body.contains("check_announcing_signer("),
            "I89 (b): the PyO3 door must ask the SAME predicate — it announced through a \
             foreign key for a whole review round because it had its own checks"
        );

        // And neither door re-spells a clause locally, which is how they drifted.
        for (name, body) in [("Engine", engine_body), ("PyEngine", py_body)] {
            assert!(
                !body.contains("pqc_signer().is_none()"),
                "I89 (b): {name}'s door re-spells the PQC clause instead of delegating"
            );
            assert!(
                !body.contains("is not its node identity"),
                "I89 (b): {name}'s door re-spells the identity clause instead of delegating"
            );
        }

        // I89 (c), review round ten — the accessors delegating is NOT enough,
        // because a door can skip the accessor entirely. `put_blob_scoped` and
        // `seal_stream_scoped` on the PyO3 surface each took the LocalSigner
        // with their own existence-only check — copied, message and all, from
        // the accessor — so an Ed25519-only signer reached the cascade, which
        // minted the epoch DEK and sealed before `sign_hybrid` failed.
        //
        // Every site that reaches for `self.local_signer` in order to SIGN must
        // be covered by the preflight. Asserted structurally: each occurrence
        // of the take-the-signer idiom must have the preflight within the
        // window that follows it, before anything can be stored.
        const IDIOM: &str = "let local = self.local_signer.clone().ok_or_else(";
        let mut sites = 0usize;
        for (off, _) in PYO3_RS.match_indices(IDIOM) {
            sites += 1;
            let window_end = (off + 2600).min(PYO3_RS.len());
            let window = &PYO3_RS[off..window_end];
            assert!(
                window.contains("check_announcing_signer(")
                    || window.contains("announcing_signer_any("),
                "I89 (c): a PyO3 door takes the LocalSigner to sign without the shared \
                 preflight, near byte {off}. Existence is not the question — identity and \
                 the ML-DSA-65 half are, and asking them AFTER the cascade writes is how a \
                 blob is stranded without its key."
            );
        }
        // I89 (d), round ten — the preflight must not cost an IPC round trip per
        // write. `local_derived_key_id_async` reads `signer.public_key()`, which
        // on a real hardware signer is the ~80ms dbus call #137 exists to avoid,
        // and routing every door through the preflight calls it on every write.
        // The composed signer is fixed for the Engine's life, so the id is
        // memoized; assert that, because losing it is a silent regression no
        // test would otherwise fail on.
        let derive_fn = PYO3_RS
            .split("async fn local_derived_key_id_async(")
            .nth(1)
            .expect("I89 (d): the derivation helper exists");
        let derive_body = &derive_fn[..derive_fn.find("\n    }").expect("fn end")];
        assert!(
            derive_body.contains("derived_key_id_memo"),
            "I89 (d): the node-identity derivation must be memoized — every announcing door \
             now asks for it, and on a hardware signer each read is an IPC round trip"
        );

        assert!(
            sites >= 4,
            "I89 (c): expected several take-the-signer sites in the PyO3 surface, found \
             {sites} — if the idiom was renamed this gate stopped looking, which is worse \
             than a failure"
        );
    }

    /// **I84 (CC 2.3.2.1, the CC 2.3 audit) — a malformed subject is REFUSED
    /// at the gate, never normalized into acceptance.** The consequence of
    /// admitting one is silent and permanent: a subject nobody can match under
    /// withdraws rules 2/3 is a row nobody can ever revoke, with no error
    /// raised anywhere.
    #[test]
    fn i84_malformed_subject_key_ids_are_refused_at_the_gate() {
        let ok = |v: &str| {
            crate::federation::validate_subject_key_ids(&[v.to_owned()])
                .unwrap_or_else(|e| panic!("I84: {v:?} is well-formed: {e}"));
        };
        let refused = |v: &str, why: &str| {
            let err = crate::federation::validate_subject_key_ids(&[v.to_owned()])
                .expect_err(&format!("I84: {v:?} must be refused ({why})"));
            assert!(
                err.to_string().contains("CC 2.3.2.1"),
                "I84: the refusal cites the clause: {err}"
            );
        };
        // Well-formed: a derived key id, and a full canonical digest.
        ok("actor-a-rssebwawts");
        ok(&format!("canonical:sha256:{}", "a".repeat(64)));
        // The reject vectors.
        refused("", "empty");
        refused("Actor-A", "uppercase");
        refused("actor-a ", "trailing space");
        refused(" actor-a", "leading space");
        refused("actor a", "internal space");
        refused(
            &format!("canonical:md5:{}", "a".repeat(32)),
            "wrong hash family",
        );
        refused(
            &format!("canonical:sha256:{}", "a".repeat(63)),
            "short digest",
        );
        refused(
            &format!("canonical:sha256:{}", "z".repeat(64)),
            "non-hex digest",
        );

        // I84 (c), review round seven — the digest clause is spelled out, NOT
        // borrowed from the general uppercase check, so it holds on the gate
        // where that check is deliberately skipped. `is_ascii_hexdigit()`
        // accepts `A`-`F`; an uppercase digest admitted at ingest never matches
        // the lowercase canonical binding under withdraws rules 2/3, so the
        // subject is unrevocable by its canonical identity.
        use crate::federation::SubjectGate;
        for gate in [SubjectGate::Emit, SubjectGate::Ingest] {
            let upper = format!("canonical:sha256:{}", "A".repeat(64));
            let err =
                crate::federation::validate_subject_key_ids_at(std::slice::from_ref(&upper), gate)
                    .expect_err("I84 (c): an UPPERCASE canonical digest is refused on BOTH gates");
            assert!(
                err.to_string().contains("CC 2.3.2.1"),
                "I84 (c): the refusal cites the clause on {gate:?}: {err}"
            );
            // Mixed case is the same defect, and the likelier spelling.
            let mixed = format!("canonical:sha256:{}{}", "A".repeat(32), "b".repeat(32));
            crate::federation::validate_subject_key_ids_at(&[mixed], gate)
                .expect_err("I84 (c): a MIXED-case canonical digest is refused on BOTH gates");
            // The lowercase form still passes on both gates — the clause
            // narrows the alphabet, it does not close the canonical door.
            let lower = format!("canonical:sha256:{}", "9f".repeat(32));
            crate::federation::validate_subject_key_ids_at(&[lower], gate).unwrap_or_else(|e| {
                panic!("I84 (c): lowercase hex stays admissible on {gate:?}: {e}")
            });

            // I84 (d), review round nine — the PREFIX is part of the canonical
            // spelling too. `strip_prefix` is case-sensitive, so a `Canonical:`
            // id never entered the canonical branch at all: it fell through as
            // an ordinary subject, and Ingest skips the general uppercase
            // clause. Every alternate spelling of an id that LOOKS canonical is
            // the same unrevocable-subject defect.
            let hex = "9f".repeat(32);
            // Each refusal must also name WHICH part of the spelling is wrong.
            // Without that the hash-family clause is a survivable mutant: the
            // generic "is not sha256" branch already refuses
            // `canonical:SHA256:…`, so only the diagnosis distinguishes them,
            // and an operator staring at a rejected subject needs it.
            for (variant, why) in [
                (
                    format!("Canonical:sha256:{hex}"),
                    "canonical prefix is not lowercase",
                ),
                (
                    format!("CANONICAL:sha256:{hex}"),
                    "canonical prefix is not lowercase",
                ),
                (
                    format!("cAnOnIcAl:sha256:{hex}"),
                    "canonical prefix is not lowercase",
                ),
                (
                    format!("canonical:SHA256:{hex}"),
                    "canonical hash family is not lowercase",
                ),
                (
                    format!("canonical:Sha256:{hex}"),
                    "canonical hash family is not lowercase",
                ),
            ] {
                let err = crate::federation::validate_subject_key_ids_at(
                    std::slice::from_ref(&variant),
                    gate,
                )
                .expect_err(
                    "I84 (d): an alternate canonical spelling must be refused on BOTH gates",
                );
                // On Emit the general uppercase clause legitimately fires
                // first, so either reason is correct there. On Ingest that
                // clause is deliberately absent, which makes the specific
                // clause the ONLY thing refusing — so there the diagnosis is
                // the assertion, and it is what keeps the clause load-bearing.
                let msg = err.to_string();
                if gate == SubjectGate::Ingest {
                    assert!(
                        msg.contains(why),
                        "I84 (d): {variant:?} on Ingest must be refused AS {why:?}, got: {msg}"
                    );
                } else {
                    assert!(
                        msg.contains(why) || msg.contains("uppercase"),
                        "I84 (d): {variant:?} on Emit must name the spelling defect: {msg}"
                    );
                }
            }
            // A subject that merely BEGINS with those letters is not canonical
            // and stays admissible — the clause keys on the `:` at byte 9.
            crate::federation::validate_subject_key_ids_at(
                std::slice::from_ref(&"canonicalish-actor".to_owned()),
                gate,
            )
            .unwrap_or_else(|e| {
                panic!("I84 (d): a non-canonical lookalike stays admissible on {gate:?}: {e}")
            });
        }
    }

    /// **I85 (CC 3, the CC 2.3 audit) — a `withdraws` naming a `key_grant`
    /// row is refused, not admitted inert.** A shared key cannot be
    /// retroactively un-shared; admitting the row would leave a revocation
    /// the emitter believes took effect and nothing enforces. Forward secrecy
    /// on this axis is rotation (§15).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i85_a_withdraws_naming_a_key_grant_row_is_refused_sqlite() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::USER;
        use crate::federation::FederationDirectory;
        use crate::store::Backend as _;
        let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let run = uuid::Uuid::new_v4().simple().to_string();
        let minter = format!("i85-minter-{run}");
        ts::register_identity_key(&backend, &minter, USER).await;
        // A stored key_grant carrier row, and a withdraws naming it.
        // A stored key_grant carrier, sealed the way every admissible row is
        // (instants + the #643 mirror), then a withdraws naming it.
        let target_id = format!("kg-{run}");
        let mut carrier = ts::bare_attestation(
            &target_id,
            &minter,
            &minter,
            &serde_json::json!({ "id": target_id, "kind": "key_grant" }),
        );
        carrier.attestation_type =
            crate::federation::key_grant::KEY_GRANT_EPOCH_ATTESTATION_TYPE.to_owned();
        let carrier = ts::seal_row(&minter, carrier);
        backend
            .apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: carrier,
            })
            .await
            .expect("I85: the carrier row stores");
        let w_id = format!("w-{run}");
        let mut w = ts::bare_attestation(
            &w_id,
            &minter,
            &minter,
            &serde_json::json!({
                "id": w_id,
                "kind": "withdraws",
                "references_attestation_id": target_id,
            }),
        );
        w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.to_owned();
        let w = ts::seal_row(&minter, w);
        let err = crate::federation::admission::check_withdraws_admission(&backend, &w)
            .await
            .expect_err("I85: a withdraws on a key_grant row must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be retroactively un-shared") && msg.contains("rotate"),
            "I85: the refusal says why and names the remedy: {msg}"
        );
        // (b) PR #852 review — the DEFERRED case: the same withdraws arriving
        // BEFORE its target. Nothing rechecks a deferred row when its target
        // lands, so the verdict that needs no target — the declared type —
        // is given now.
        let absent = format!("kg-absent-{run}");
        let mut deferred = ts::bare_attestation(
            &format!("w2-{run}"),
            &minter,
            &minter,
            &serde_json::json!({
                "id": format!("w2-{run}"),
                "kind": "withdraws",
                "references_attestation_id": absent,
                "references_attestation_type":
                    crate::federation::key_grant::KEY_GRANT_EPOCH_ATTESTATION_TYPE,
            }),
        );
        deferred.attestation_type =
            crate::federation::types::attestation_type::WITHDRAWS.to_owned();
        let deferred = ts::seal_row(&minter, deferred);
        let err = crate::federation::admission::check_withdraws_admission(&backend, &deferred)
            .await
            .expect_err("I85 (b): a deferred withdraws declaring a key_grant target is refused");
        assert!(
            err.to_string()
                .contains("cannot be retroactively un-shared"),
            "I85 (b): {err}"
        );
    }

    /// **I86 (PR #852 review) — the row records the AUTHOR, the claim the
    /// HOLDER.** A proxy write (bytes whose author is a peer) stores the peer
    /// as `author_key_id` and announces under this node; losing the author
    /// made proxy content look locally authored and slipped the stop-tier
    /// proxy-serve refusal.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i86_a_proxy_write_records_the_peer_author_and_announces_as_the_node_sqlite() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::USER;
        use crate::federation::{BlobBody, BlobStorage};
        use crate::store::Backend as _;
        use std::sync::Arc;
        let backend = Arc::new(
            crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap(),
        );
        backend.run_migrations().await.unwrap();
        let run = uuid::Uuid::new_v4().simple().to_string();
        let local = ts::local_signer(&format!("i86-node-{run}"));
        let node = local.derived_key_id();
        let peer = format!("i86-peer-{run}");
        for k in [&node, &peer] {
            ts::register_hybrid_key_as(backend.as_ref(), k, k, USER).await;
        }
        let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            crate::signing::LocalSignerHardwareAdapter::new(local.clone()),
        );
        let engine = crate::Engine::from_shared_with_local(
            crate::engine::BackendDispatch::Sqlite(backend.clone()),
            signer,
            Some(local.clone()),
        );
        let body = b"i86 proxy bytes".to_vec();
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&body).into()
        };
        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(body),
                None,
                &peer,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("I86: a proxy write below the stop tier succeeds");
        // The ROW's author is the peer — what `serve_blob_to_peer` reads to
        // decide proxy-ness.
        let prov = backend
            .blob_provenance(&sha)
            .await
            .unwrap()
            .expect("I86: the row exists");
        assert_eq!(
            prov.author_key_id.as_deref(),
            Some(peer.as_str()),
            "I86: the row records the peer as author"
        );
        // The CLAIM is this node's, and it is hybrid.
        assert_eq!(
            backend.list_holders(&sha).await.unwrap(),
            vec![node.clone()],
            "I86: the holder claim is this node's (I23)"
        );
        let claim = backend
            .list_attestations_by(&node)
            .await
            .unwrap()
            .into_iter()
            .find(|a| {
                a.attestation_type
                    .starts_with(crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX)
            })
            .expect("I86: the claim is stored under the node");
        assert!(claim.scrub_signature_pqc.is_some(), "I86: hybrid claim");
    }

    /// **I87 (PR #852 review) — a LocalOnly adopt needs no announcing signer.**
    /// A hardware/classical engine may hold received bytes; only `Announce`
    /// requires the PQC LocalSigner.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i87_local_only_adoption_works_without_a_local_signer_sqlite() {
        use crate::federation::at_rest_cascade::{fresh_dek, seal};
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
        use crate::federation::{AdoptDisposition, BlobProvenance, BlobStorage};
        use crate::store::Backend as _;
        use std::sync::Arc;
        let backend = Arc::new(
            crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap(),
        );
        backend.run_migrations().await.unwrap();
        let run = uuid::Uuid::new_v4().simple().to_string();
        // The node, its community and the peer author — seeded by the same
        // two-node helpers every §20 witness uses, so the node is a member
        // (the operator rule: a node holds only what it is party to, #846).
        use crate::federation::key_grant_invariants::two_node::{
            node_as, seed_community_everywhere,
        };
        let n = node_as(
            backend.as_ref(),
            &format!("i87-node-{run}"),
            crate::federation::types::identity_type::NODE,
        )
        .await;
        let node = n.key.clone();
        let author = format!("i87-author-{run}");
        let comm = format!("i87-comm-{run}");
        seed_community_everywhere(&[&n], &comm, &[(&author, Some(&n))]).await;
        let local = ts::local_signer(&format!("i87-node-{run}"));
        assert_eq!(local.derived_key_id(), node);
        let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            crate::signing::LocalSignerHardwareAdapter::new(local.clone()),
        );
        // No LocalSigner at all — the documented hardware/classical shape.
        let engine = crate::Engine::from_shared(
            crate::engine::BackendDispatch::Sqlite(backend.clone()),
            signer,
        );
        let envelope = seal(&fresh_dek().unwrap(), b"i87 received bytes", None)
            .unwrap()
            .to_bytes();
        let sha = engine
            .adopt_sealed_blob(
                &envelope,
                BlobProvenance {
                    author_key_id: author.clone(),
                    cohort_scope: COMMUNITY.into(),
                    community_key_id: Some(comm.clone()),
                    epoch: Some(0),
                    tier: CryptoTier::CommunityDek,
                },
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("I87: LocalOnly adoption emits no claim and needs no LocalSigner");
        assert!(backend.get_blob(&sha.sha256).await.unwrap().is_some());
        assert!(
            backend.list_holders(&sha.sha256).await.unwrap().is_empty(),
            "I87: LocalOnly announces nothing"
        );
    }

    /// **I84 (b) — the subject gate runs on INGEST, not only on emit.** A
    /// remote signer can hybrid-sign a row carrying a malformed subject; the
    /// backend's own admission must refuse it, or replication stores the same
    /// unmatchable revocation authority the emit path rejects.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i84b_a_replicated_row_with_a_malformed_subject_is_refused_sqlite() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::USER;
        use crate::federation::FederationDirectory;
        use crate::store::Backend as _;
        let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let run = uuid::Uuid::new_v4().simple().to_string();
        let signer = format!("i84b-signer-{run}");
        ts::register_identity_key(&backend, &signer, USER).await;
        let id = format!("i84b-{run}");
        let mut row = ts::bare_attestation(
            &id,
            &signer,
            &signer,
            &serde_json::json!({ "id": id, "kind": "scores" }),
        );
        row.attestation_type = crate::federation::types::attestation_type::SCORES.to_owned();
        // The malformed subject a remote signer can perfectly well sign.
        row.subject_key_ids = vec![format!("canonical:sha256:{}", "a".repeat(63))];
        let row = ts::seal_row(&signer, row);
        let err = backend
            .apply_replicated_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect_err("I84 (b): the ingest gate refuses a malformed subject");
        assert!(
            err.to_string().contains("CC 2.3.2.1"),
            "I84 (b): the refusal cites the clause: {err}"
        );
        // …and the ONE clause ingest does not carry, named rather than
        // silent: a raw base64 pubkey subject (uppercase) still admits,
        // because cirisnode's moderation corpus predates the rule. The emit
        // gate refuses it, so no NEW row can carry one.
        let b64_subject = "vHy8tWNjdfodgkNNRmck2SN39TuYBpXdSdJtDOEiBaU=".to_owned();
        crate::federation::validate_subject_key_ids_at(
            std::slice::from_ref(&b64_subject),
            crate::federation::SubjectGate::Ingest,
        )
        .expect("I84 (b): ingest admits the pre-existing uppercase corpus");
        crate::federation::validate_subject_key_ids(std::slice::from_ref(&b64_subject))
            .expect_err("I84 (b): emit refuses it, so no new row carries one");
    }
}
