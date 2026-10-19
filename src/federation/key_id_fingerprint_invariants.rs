//! v59.0.0 (CIRISPersist#1103; CC 2.6.8 rc9 `957d1dd`,
//! `CLM-key-id-fingerprint-verified`) — **I1153: a key id names its own
//! key**, on every backend.
//!
//! At first contact (a `key:record:v1` row offered through the attestation
//! door) and at registration (`Engine::register_federation_key`, in
//! `register.rs`'s tests): an id that does not end in `-<fp>` of its own
//! Ed25519 key is refused `federation_malformed_row` /
//! `key_id_fingerprint_mismatch`; a matching id admits; a `device-<hex>-<fp>`
//! id admits; a bundle-pinned anchor and a held family's id are exempt (keyed
//! off the bundle and the families: the same id under another key is not);
//! a key already held under a non-matching id is grandfathered — it still
//! resolves — but is refused when offered again under that id.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::register;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type as it;
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    /// `key_id`'s self-signed record as a `key:record:v1` row (first contact).
    fn row_of(key_id: &str) -> SignedAttestation {
        let record = ts::replicated_key_record(key_id, it::AGENT, key_id, key_id, "i1153");
        SignedAttestation {
            attestation: crate::federation::key_plane::plan_key_record_row(&record, &None)
                .expect("a self-signed record plans its row"),
        }
    }

    fn refused(r: Result<impl std::fmt::Debug, Error>, what: &str) {
        match r {
            Err(
                e @ Error::MalformedRow {
                    reason: "key_id_fingerprint_mismatch",
                    ..
                },
            ) => assert_eq!(e.kind(), "federation_malformed_row"),
            other => panic!("I1153: {what}: expected key_id_fingerprint_mismatch, got {other:?}"),
        }
    }

    /// **I1153** at the first-contact door and at the rule itself.
    pub(crate) async fn i1153_a_key_id_names_its_own_key(d: &dyn FederationDirectory, tag: &str) {
        // A mismatched id: refused, nothing held.
        let bad = format!("i1153-bad-{tag}");
        refused(d.put_attestation(row_of(&bad)).await, "a mismatched id");
        assert!(d.lookup_public_key(&bad).await.unwrap().is_none());

        // A matching id admits.
        let good = ts::fp_key_id(&format!("i1153-good-{tag}"));
        d.put_attestation(row_of(&good))
            .await
            .expect("I1153: a matching id admits");
        assert!(d.lookup_public_key(&good).await.unwrap().is_some());

        // device-<hex>-<fp>: the roster-id form is a separate rule.
        let device = ts::fp_key_id(&format!("device-{}", tag.replace('-', "")));
        assert!(device.starts_with("device-"));
        d.put_attestation(row_of(&device))
            .await
            .expect("I1153: a device-<hex>-<fp> id admits");

        // A bundle-pinned anchor is exempt — under ITS key only.
        let bundle = crate::federation::genesis::canonical_genesis_bundle();
        let anchor = &bundle.holders[0].record;
        assert!(
            register::key_id_fingerprint(&anchor.pubkey_ed25519_base64)
                .is_some_and(|fp| !anchor.key_id.ends_with(&format!("-{fp}"))),
            "I1153: the premise — the anchor's id carries no fingerprint"
        );
        register::check_key_id_fingerprint(d, anchor)
            .await
            .expect("I1153: a bundle-pinned anchor is exempt");
        let mut impostor = anchor.clone();
        impostor.pubkey_ed25519_base64 = ts::hybrid_pubkeys(&format!("i1153-imp-{tag}")).0;
        refused(
            register::check_key_id_fingerprint(d, &impostor).await,
            "the anchor's id under another key",
        );

        // A held family's id is exempt; the same id before the family is not.
        let (author, fam) = (format!("i1153-author-{tag}"), format!("i1153-fam-{tag}"));
        ts::register_hybrid_key(d, &author).await;
        let fam_record = ts::replicated_key_record(&fam, it::AGENT, &fam, &fam, "i1153");
        refused(
            register::check_key_id_fingerprint(d, &fam_record).await,
            "a family id before its family is held",
        );
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .unwrap();
        d.put_family(ts::sign_family(
            &author,
            crate::federation::types::Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: format!("i1153-family-{tag}"),
                members: vec![crate::federation::types::FamilyMember {
                    key_id: author.clone(),
                    joined_at: now,
                    role: Some("founder".to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("I1153: the family");
        register::check_key_id_fingerprint(d, &fam_record)
            .await
            .expect("I1153: a held family's id is exempt");

        // Grandfathered: held under a non-matching id, it resolves; offered
        // again under that id, it is refused.
        let old = format!("i1153-old-{tag}");
        ts::register_hybrid_key(d, &old).await;
        assert!(d.lookup_public_key(&old).await.unwrap().is_some());
        let again = ts::replicated_key_record(&old, it::AGENT, &old, &old, "i1153-again");
        let row = crate::federation::key_plane::plan_key_record_row(&again, &None).unwrap();
        refused(
            d.put_attestation(SignedAttestation { attestation: row })
                .await,
            "a grandfathered id offered again",
        );
        assert!(
            d.lookup_public_key(&old).await.unwrap().is_some(),
            "I1153: the grandfathered key still resolves"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1153_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i1153_a_key_id_names_its_own_key(&b, &tag("m")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1153_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1153_a_key_id_names_its_own_key(&b, &tag("s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1153_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1153_a_key_id_names_its_own_key(&b, &tag("p")).await;
        eprintln!("i1153_postgres: RAN");
    }
}
