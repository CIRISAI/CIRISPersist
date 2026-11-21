//! CIRISPersist#851 (`FSD/BLOB_REPLICATION.md` §20.5) — **the holder
//! claim crosses the federation-tier gate.**
//!
//! A holding claim (v55.0.0: `custody:ack:v1`, CIRISPersist#989; the
//! `holds_bytes` carrier before it) rides the federation plane: the attestation cursor serves
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
        introduce_as, seed_community_everywhere, Node,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
    use crate::federation::types::identity_type::NODE;
    use crate::federation::{
        BlobStorage, EncryptionPubkeys, FederationDirectory, SignedAttestation,
    };

    /// **I79 — a holder claim signed by an Engine with a LocalSigner is
    /// hybrid, and a peer admits it.** Before #851 §20.5 the claim was
    /// signed classical-only (`scrub_signature_pqc: None`): A's cursor served
    /// it and B refused it at the federation-tier ingest gate ("PQC signature
    /// without pubkey"), so no peer ever learned who held the bytes.
    #[tokio::test]
    async fn i79_holding_claim_is_hybrid_signed_and_a_peer_admits_it_sqlite() {
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
        // v62.0.0 (E11-fix4; CC rc21 3.3.6) — the engines are MACHINES: each is
        // a member's device node (`place_device`, an owner binding onto a NODE
        // key), so each registers, and is introduced, as a NODE.
        for (e, _alias) in [(&engine_a, &alias_a), (&engine_b, &alias_b)] {
            e.register_self_federation_key(NODE, None, None)
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
        introduce_as(&[&a, &b], &[&alias_a, &alias_b], NODE).await;
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
        // v62.0.0 (RL-fix2c) — A SERVES these claims to B below: A's node is
        // rooted (the serve wait, CC 5.3.4), so the read is A's serve path.
        crate::federation::edition2::serve_wait_invariants::test_support::root_this_node(&*sa)
            .await;
        let claims: Vec<_> = sa
            .list_attestations_since(None, 1_000)
            .await
            .unwrap()
            .into_iter()
            .map(|served| served.attestation)
            .filter(|row| {
                crate::federation::custody_ack::parse_custody_ack(row)
                    .ok()
                    .flatten()
                    .is_some()
            })
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
            crate::federation::edition2::fixture_switch::carried_statement(&claim).is_some(),
            "I79: an Engine with a LocalSigner signs the holding claim HYBRID — a \
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
                crate::federation::custody_ack::parse_custody_ack(row)
                    .ok()
                    .flatten()
                    .is_some_and(|a| a.blob_sha256_hex == hex::encode(sha))
            })
            .collect();
        assert_eq!(commons.len(), 1, "I79/2: the commons door announced once");
        let claim = commons.into_iter().next().unwrap();
        assert_eq!(
            claim.scrub_key_id, a.key,
            "I79/2: signed by the holder's derived key"
        );
        assert!(
            crate::federation::edition2::fixture_switch::carried_statement(&claim).is_some(),
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

    // v62.0.0 (T2-fix10; CC 6.1.3, ruling 4): I80 and I81 DELETED. They
    // witnessed `sign_holding_claim`, the bound-hybrid claim signer, which is
    // gone: a holding claim is a composite edition-2 statement
    // (`emit_holding_claim`), whose signer is the statement's own `iss`.

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
                &local.federation_id().await,
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
        let engine = crate::Engine::try_from_shared_with_local(
            crate::engine::BackendDispatch::Sqlite(backend.clone()),
            signer,
            Some(local.clone()),
        )
        .expect("a shared engine view: no node_key_conflict");

        let node_key = local.federation_id().await;

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
        // (the announce through `emit_holding_claim`) also refuses a PQC-less signer, so the
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
        let node_key = node.federation_id_now();
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
            foreign.federation_id_now(),
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
        let classical_key = classical.federation_id_now();
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
        // borrowed from the general uppercase check. `is_ascii_hexdigit()`
        // accepts `A`-`F`; an uppercase digest never matches the lowercase
        // canonical binding under withdraws rules 2/3, so the subject would be
        // unrevocable by its canonical identity. v60.0.0 (#854): there is ONE
        // gate, and the canonical clauses run before the general uppercase
        // one, so each refusal names its own defect.
        let gate = |ids: &[String]| crate::federation::validate_subject_key_ids(ids);
        let upper = format!("canonical:sha256:{}", "A".repeat(64));
        let err = gate(std::slice::from_ref(&upper))
            .expect_err("I84 (c): an UPPERCASE canonical digest is refused");
        assert!(
            err.to_string()
                .contains("canonical sha256 digest is not 64 lowercase hex"),
            "I84 (c): the refusal names the digest: {err}"
        );
        // Mixed case is the same defect, and the likelier spelling.
        let mixed = format!("canonical:sha256:{}{}", "A".repeat(32), "b".repeat(32));
        gate(&[mixed]).expect_err("I84 (c): a MIXED-case canonical digest is refused");
        // The lowercase form still passes — the clause narrows the alphabet,
        // it does not close the canonical door.
        let lower = format!("canonical:sha256:{}", "9f".repeat(32));
        gate(&[lower]).unwrap_or_else(|e| panic!("I84 (c): lowercase hex stays admissible: {e}"));

        // I84 (d), review round nine — the PREFIX and the HASH FAMILY are part
        // of the canonical spelling too. Each refusal must name WHICH part is
        // wrong: the general uppercase clause would refuse these too, so the
        // diagnosis is what keeps the specific clauses load-bearing.
        let hex = "9f".repeat(32);
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
            let err = gate(std::slice::from_ref(&variant))
                .expect_err("I84 (d): an alternate canonical spelling must be refused");
            assert!(
                err.to_string().contains(why),
                "I84 (d): {variant:?} must be refused AS {why:?}, got: {err}"
            );
        }
        // Another hash family is "not sha256", not a case error, whatever its
        // length (the family clause compares only a 7-byte `sha256:`).
        for other in [
            format!("canonical:blake3:{hex}"),
            "canonical:md5".to_owned(),
        ] {
            let err = gate(std::slice::from_ref(&other))
                .expect_err("I84 (d): a non-sha256 canonical family is refused");
            assert!(
                err.to_string().contains("canonical id is not sha256"),
                "I84 (d): {other:?} names the family, not its case: {err}"
            );
        }
        // A subject that merely BEGINS with those letters is not canonical and
        // stays admissible — the clause keys on the `:` at byte 9.
        gate(std::slice::from_ref(&"canonicalish-actor".to_owned()))
            .unwrap_or_else(|e| panic!("I84 (d): a non-canonical lookalike stays admissible: {e}"));
        // And an ordinary uppercase subject is refused AS uppercase.
        let err = gate(std::slice::from_ref(&"Actor-X".to_owned()))
            .expect_err("I84: an uppercase subject is refused");
        assert!(err.to_string().contains("uppercase"), "I84: {err}");
    }

    /// **I85 (CC 3, CC 3.3.2 rc7) — a `withdraws` or `recants` naming a
    /// `key_grant` row is refused, not admitted inert.** A shared key cannot
    /// be retroactively un-shared; admitting the row would leave a revocation
    /// the emitter believes took effect and nothing enforces. Forward secrecy
    /// on this axis is rotation (§15).
    ///
    /// v62.0.0 (CP2, X1) — edition 2, sqlite and postgres. The target is a
    /// real `key_grant:{axis}:v1` statement (`typed_fixtures::key_grant_statement`,
    /// the content axis) mapped to its row, held under its node-computed id
    /// (seeded below the doors: this witness is about the composer gate, not
    /// the key-grant row's own admission, which needs a sealed blob and its
    /// audience). Each composer is an edition-2 `withdraws` / `recants` by
    /// the grant's own sealer (`fixture_switch::composer_of`: `refs.target` the
    /// row id, the header the target's family), and
    /// `admission::check_withdraws_admission` refuses both.
    ///
    /// Deleted with the earlier form: the retired v54 key-grant SET carrier
    /// (`key_grant:epoch:v1` as an attestation type; a v62 node deletes the
    /// earlier store at upgrade, so none is ever held), and the deferred leg
    /// keyed on the earlier envelope's `references_attestation_type` (an
    /// edition-2 composer states the target's family in its header, never as a
    /// payload member).
    ///
    /// v62.0.0 (E6-fix8) — the runner builds the target ONCE and hands the
    /// same row to the seed and to the body. `held_key_grant_row` stamps the
    /// statement at the clock, so a second call minted a different statement
    /// (another row id) and the precondition read the wrong id.
    async fn i85_body(
        d: &dyn crate::federation::FederationDirectory,
        minter: &str,
        target: crate::federation::Attestation,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::key_grant::is_key_grant_row;
        assert!(
            is_key_grant_row(&target),
            "I85 precondition: the mapped row is a key-grant row: {:?}",
            target.attestation_envelope
        );
        assert_eq!(
            d.get_attestation(&target.attestation_id)
                .await
                .expect("read")
                .map(|r| r.attestation_id),
            Some(target.attestation_id.clone()),
            "I85 precondition: the key-grant row is held under its row id"
        );
        // v55.0.0 (#989, CC 3.3.2 rc7) — a withdraws or a recants naming the
        // ROW is refused, the sealer's own recants included.
        for kind in [
            crate::federation::types::attestation_type::WITHDRAWS,
            crate::federation::types::attestation_type::RECANTS,
        ] {
            let c = e2::composer_of(kind, &target, minter);
            assert_eq!(
                e2::rid(&target),
                target.attestation_id,
                "I85: the composer names the held row by its id"
            );
            let err = crate::federation::admission::check_withdraws_admission(d, &c)
                .await
                .expect_err("I85: a composer naming a key-grant row is refused");
            let msg = err.to_string();
            assert!(
                msg.contains("cannot be retroactively un-shared") && msg.contains("rotate"),
                "I85 ({kind} of the row): the refusal says why and names the remedy: {msg}"
            );
        }
    }

    /// The key-grant row I85 names: `minter`'s content-axis wrap of a blob to
    /// a recipient, as an edition-2 statement mapped to its row (its
    /// `attestation_id` is the node-computed row id).
    fn held_key_grant_row(minter: &str, run: &str) -> crate::federation::Attestation {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRow};
        let sha: [u8; 32] =
            <sha2::Sha256 as sha2::Digest>::digest(format!("i85-blob-{run}").as_bytes()).into();
        let row = KeyGrantRow {
            axis: KeyGrantAxis::Content {
                at_rest_sha256: hex::encode(sha),
                cohort_scope: crate::federation::types::cohort_scope::SELF.into(),
                owner_key_id: e2::kid(minter),
            },
            wrap: crate::federation::GrantWrap {
                recipient_key_id: e2::kid(&format!("i85-recipient-{run}")),
                wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "{}".into(),
            },
        };
        let at_ms = e2::ms(crate::host::clock::now() - chrono::Duration::minutes(5));
        let st = e2::key_grant_statement(minter, &row, at_ms);
        e2::row_of_statement(&st, crate::federation::types::attestation_tier::FEDERATION)
    }

    /// The SQL every backend seeds the held row with (below the doors).
    fn i85_seed_params(
        target: &crate::federation::Attestation,
    ) -> (String, String, String, String, String, String) {
        (
            target.attestation_id.clone(),
            target.attesting_key_id.clone(),
            target.attested_key_id.clone(),
            target.attestation_type.clone(),
            target.attestation_envelope.to_string(),
            target.cohort_scope.clone(),
        )
    }

    #[tokio::test]
    async fn i85_a_withdraws_naming_a_key_grant_row_is_refused_sqlite() {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::types::identity_type::USER;
        use crate::store::Backend as _;
        let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let run = uuid::Uuid::new_v4().simple().to_string();
        let minter = format!("i85-minter-{run}");
        e2::put_key(&backend, &minter, &[USER]).await;
        let target = held_key_grant_row(&minter, &run);
        let (id, iss, sub, ty, env, scope) = i85_seed_params(&target);
        {
            let conn = backend.conn_handle();
            let conn = conn.lock();
            conn.execute(
                "INSERT INTO federation_attestations (\
                    attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, tier, \
                    cohort_scope, admitted_at\
                 ) VALUES (?1, ?2, ?3, ?4, NULL, '2026-01-01T00:00:00Z', NULL, ?5, x'00', \
                    'c2ln', NULL, ?2, '2026-01-01T00:00:00Z', NULL, '0', 'federation', ?6, \
                    '2026-01-01T00:00:00Z')",
                rusqlite::params![id, iss, sub, ty, env, scope],
            )
            .expect("I85: the held key-grant row is seeded");
        }
        i85_body(&backend, &minter, target).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i85_a_withdraws_naming_a_key_grant_row_is_refused_postgres() {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::types::identity_type::USER;
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        backend.run_migrations().await.unwrap();
        let run = uuid::Uuid::new_v4().simple().to_string();
        let minter = format!("i85-minter-{run}");
        e2::put_key(&backend, &minter, &[USER]).await;
        let target = held_key_grant_row(&minter, &run);
        let (id, iss, sub, ty, env, scope) = i85_seed_params(&target);
        backend
            .get_client()
            .await
            .unwrap()
            .execute(
                "INSERT INTO cirislens.federation_attestations (\
                    attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, tier, \
                    cohort_scope, admitted_at\
                 ) VALUES ($1, $2, $3, $4, NULL, '2026-01-01T00:00:00Z'::timestamptz, NULL, $5, \
                    '\\x00'::bytea, 'c2ln', NULL, $2, '2026-01-01T00:00:00Z'::timestamptz, NULL, \
                    '0', 'federation', $6, '2026-01-01T00:00:00Z'::timestamptz)",
                &[&id, &iss, &sub, &ty, &env, &scope],
            )
            .await
            .expect("I85: the held key-grant row is seeded");
        i85_body(&backend, &minter, target).await;
    }

    /// **I86 (PR #852 review) — the row records the AUTHOR, the claim the
    /// HOLDER.** A proxy write (bytes whose author is a peer) stores the peer
    /// as `author_key_id` and announces under this node; losing the author
    /// made proxy content look locally authored and slipped the stop-tier
    /// proxy-serve refusal.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i86_a_proxy_write_records_the_peer_author_and_announces_as_the_node_sqlite() {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
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
        let alias = format!("i86-node-{run}");
        let local = ts::local_signer(&alias);
        // v62.0.0 — edition-2 keys: the node's own (its LocalSigner signs as
        // `kid(alias)`) and the peer author's.
        let _node =
            crate::federation::edition2::fixture_switch::put_key(backend.as_ref(), &alias, &[USER])
                .await;
        let peer = crate::federation::edition2::fixture_switch::put_key(
            backend.as_ref(),
            &format!("i86-peer-{run}"),
            &[USER],
        )
        .await;
        let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            crate::signing::LocalSignerHardwareAdapter::new(local.clone()),
        );
        let engine = crate::Engine::try_from_shared_with_local(
            crate::engine::BackendDispatch::Sqlite(backend.clone()),
            signer,
            Some(local.clone()),
        )
        .expect("a shared engine view: no node_key_conflict");
        // v62.0.0 — the node's key is an edition-2 `key:record`; its id is the
        // identity-ref.
        let node = engine
            .register_self_federation_key(USER, None, None)
            .await
            .expect("I86: the node registers");
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
            .all_attestations_by(&node)
            .await
            .unwrap()
            .into_iter()
            .find(|a| {
                crate::federation::custody_ack::parse_custody_ack(a)
                    .ok()
                    .flatten()
                    .is_some_and(|c| c.blob_sha256_hex == hex::encode(sha))
            })
            .expect("I86: the claim is stored under the node");
        assert!(
            crate::federation::edition2::fixture_switch::carried_statement(&claim).is_some(),
            "I86: the claim is an edition-2 statement"
        );
    }

    // v62.0.0 (E6-fix8) — I87 ("a LocalOnly adopt needs no LocalSigner") is
    // DELETED: its premise is a classical-only engine (`Engine::from_shared`,
    // no LocalSigner) party to a room. Such an engine names itself by the
    // earlier derived id (`local_derived_key_id`, read-checked), not an
    // edition-2 identity-ref (CC 2.6.1.1), so no roster names it and it is
    // party to nothing (`NotPartyTo`). A v62 node holds a composite signer.
    /// **I84 (b) — the subject gate is ONE gate.** v60.0.0 (#854, I1172):
    /// ingest and emit ask the same validator, so a raw base64 pubkey subject
    /// (uppercase), the shape cirisnode's retired Contributions carried, is
    /// refused by it.
    ///
    /// v62.0.0 (slice E6) — the replicated-row legs are deleted: an edition-2
    /// subject is an identity-ref by encoding (`IdentityRefs`), so a signer
    /// cannot offer a malformed text subject at the statement door; the
    /// validator the earlier door ran is witnessed by I84 and here.
    #[test]
    fn i84b_the_one_subject_gate_refuses_a_base64_subject() {
        let b64_subject = "vHy8tWNjdfodgkNNRmck2SN39TuYBpXdSdJtDOEiBaU=".to_owned();
        let err = crate::federation::validate_subject_key_ids(std::slice::from_ref(&b64_subject))
            .expect_err("I1172: the one gate refuses an uppercase subject");
        assert!(
            err.to_string().contains("uppercase"),
            "I1172: the refusal names the clause: {err}"
        );
        let short = format!("canonical:sha256:{}", "a".repeat(63));
        let err = crate::federation::validate_subject_key_ids(std::slice::from_ref(&short))
            .expect_err("I84 (b): a short canonical digest is refused");
        assert!(
            err.to_string().contains("CC 2.3.2.1"),
            "I84 (b): the refusal cites the clause: {err}"
        );
    }
}
