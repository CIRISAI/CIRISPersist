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

    /// **I80 — a classical-only `LocalSigner` keeps the classical claim.**
    /// A `LocalSigner` built without a PQC signer (`from_parts(.., None,
    /// None)`) is a classical-only producer: `sign_holds_bytes_claim` falls
    /// back to the classical path — no error, no PQC half, and the SAME
    /// classical signature the signer-only path produces (Ed25519 is
    /// deterministic), so the fallback IS the pre-#851 claim.
    #[tokio::test]
    async fn i80_a_pqc_less_local_signer_keeps_the_classical_claim() {
        use crate::federation::blobs::sign_holds_bytes_claim;
        use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x51u8; 32]);
        let local = std::sync::Arc::new(LocalSigner::from_parts(
            ed,
            "i80-classical-only".to_owned(),
            None,
            None,
        ));
        assert!(
            local.pqc_signer().is_none(),
            "I80: precondition — no PQC signer"
        );
        let adapter = LocalSignerHardwareAdapter::new(local.clone());
        let key = local.derived_key_id();
        let sha = [0x80u8; 32];
        let (id, now) = (uuid::Uuid::new_v4(), chrono::Utc::now());
        let with = sign_holds_bytes_claim(&adapter, Some(&*local), &sha, &key, id, now)
            .await
            .expect("I80: a PQC-less LocalSigner is a classical-only producer, not an error");
        assert!(
            with.scrub_signature_pqc.is_none(),
            "I80: no PQC signer, no PQC half"
        );
        assert_eq!(with.scrub_key_id, key, "I80: the derived key id, as before");
        let without = sign_holds_bytes_claim(&adapter, None, &sha, &key, id, now)
            .await
            .unwrap();
        assert_eq!(
            with.scrub_signature_classical, without.scrub_signature_classical,
            "I80: the fallback is the classical path — byte-identical signature"
        );
        assert_eq!(
            with.original_content_hash_hex,
            without.original_content_hash_hex
        );
    }
}
