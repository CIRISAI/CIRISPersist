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
        let err = sign_holds_bytes_claim(&other, &sha, &key, id, now)
            .await
            .expect_err("I81: a foreign LocalSigner must not sign this attester's claim");
        let msg = err.to_string();
        assert!(
            msg.contains("hybrid-only") && msg.contains("not the claimed attester"),
            "I81: the refusal names the mismatch: {msg}"
        );
        // The attester's own LocalSigner signs, hybrid, attributed to itself.
        let own = sign_holds_bytes_claim(&attester, &sha, &key, id, now)
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
    }
}
