//! v61 (CIRISPersist#1146) — **a restart that re-registers the same key is
//! a no-op success.**
//!
//! An agent-embedded node calls `Engine::register_self_federation_key` on every
//! boot. The key is the same, the envelope is freshly signed, so the row hash
//! differs and the put refused it `Conflict`. The rule: when the held row for
//! the node's own `key_id` states the same pubkeys (Ed25519 and PQC),
//! `identity_type`, `identity_ref`, roles and expiry, the call returns the held
//! `key_id` and writes nothing. Any difference is still `Conflict`, and the
//! replicated put keeps its exact-hash rule.
//!
//! One body, run on sqlite (a file both engines open) and postgres (one
//! database both engines open).

/// The witness body: two engines over one store, the second a "restart".
pub(crate) mod bodies {
    use crate::federation::types::identity_type::NODE;
    use crate::federation::{Error, SignedKeyRecord};

    /// A hybrid signer whose Ed25519 key is `alias`'s deterministic key and
    /// whose ML-DSA-65 key is derived from `pqc_alias`: same `key_id`, a
    /// different PQC leg when the two aliases differ.
    fn signer(alias: &str, pqc_alias: &str) -> std::sync::Arc<crate::signing::LocalSigner> {
        let seed = |s: &str| {
            let mut seed = [0x11u8; 32];
            for (i, b) in s.bytes().take(32).enumerate() {
                seed[i] = b;
            }
            seed
        };
        let pqc = std::sync::Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&seed(pqc_alias), pqc_alias)
                .expect("mldsa seed length"),
        );
        std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
            ed25519_dalek::SigningKey::from_bytes(&seed(alias)),
            alias.to_owned(),
            Some(pqc),
            Some(pqc_alias.to_owned()),
        ))
    }

    async fn engine(dsn: &str, alias: &str, pqc_alias: &str) -> crate::Engine {
        crate::Engine::with_signer_pre_genesis(signer(alias, pqc_alias), dsn)
            .await
            .expect("engine")
    }

    /// I1146: restart Ok and byte-identical; a changed role, a changed PQC key
    /// and a changed expiry are `Conflict`; the replicated put of a fresh
    /// envelope is still `Conflict`.
    pub(crate) async fn i1146_restart_is_a_no_op(dsn: &str, tag: &str) {
        let alias = format!("{tag}-1146-node");
        let first = engine(dsn, &alias, &alias).await;
        let key_id = first
            .register_self_federation_key(
                NODE,
                &alias,
                None,
                serde_json::json!({"boot": 1}),
                vec!["serve".to_owned()],
            )
            .await
            .expect("I1146: first registration");
        let dir = first.federation_directory();
        let held = dir
            .lookup_public_key(&key_id)
            .await
            .unwrap()
            .expect("held row");
        drop(first);

        // A restart: a second engine, the same key, a FRESH envelope.
        let restarted = engine(dsn, &alias, &alias).await;
        let again = restarted
            .register_self_federation_key(
                NODE,
                &alias,
                None,
                serde_json::json!({"boot": 2}),
                vec!["serve".to_owned()],
            )
            .await
            .expect("I1146: a restart that re-registers the same key is Ok");
        assert_eq!(again, key_id);
        let after = restarted
            .federation_directory()
            .lookup_public_key(&key_id)
            .await
            .unwrap()
            .expect("held row");
        assert_eq!(
            (
                &after.persist_row_hash,
                &after.registration_envelope,
                &after.original_content_hash,
                &after.scrub_signature_classical,
                &after.scrub_signature_pqc,
            ),
            (
                &held.persist_row_hash,
                &held.registration_envelope,
                &held.original_content_hash,
                &held.scrub_signature_classical,
                &held.scrub_signature_pqc,
            ),
            "I1146: the held row is kept byte for byte"
        );

        // A changed role is a real change.
        let changed_role = restarted
            .register_self_federation_key(
                NODE,
                &alias,
                None,
                serde_json::json!({"boot": 3}),
                vec!["serve".to_owned(), "relay".to_owned()],
            )
            .await;
        assert!(
            matches!(changed_role, Err(Error::Conflict(_))),
            "I1146: a changed role is Conflict: {changed_role:?}"
        );

        // A changed expiry is a real change.
        let changed_expiry = restarted
            .register_self_federation_key(
                NODE,
                &alias,
                Some(chrono::Utc::now() + chrono::Duration::days(30)),
                serde_json::json!({"boot": 4}),
                vec!["serve".to_owned()],
            )
            .await;
        assert!(
            matches!(changed_expiry, Err(Error::Conflict(_))),
            "I1146: a changed expiry is Conflict: {changed_expiry:?}"
        );
        drop(restarted);

        // The same Ed25519 key with a different PQC key: same key_id.
        let swapped = engine(dsn, &alias, &format!("{tag}-1146-other-pqc")).await;
        let changed_pqc = swapped
            .register_self_federation_key(
                NODE,
                &alias,
                None,
                serde_json::json!({"boot": 5}),
                vec!["serve".to_owned()],
            )
            .await;
        assert!(
            matches!(changed_pqc, Err(Error::Conflict(_))),
            "I1146: a changed PQC key is Conflict: {changed_pqc:?}"
        );

        // The replicated put keeps its exact-hash rule: the same key, a fresh
        // envelope, is a Conflict there.
        let mut fresh = held.clone();
        fresh.registration_envelope["boot"] = serde_json::json!(6);
        fresh.persist_row_hash = String::new();
        let put = swapped
            .federation_directory()
            .put_public_key(SignedKeyRecord { record: fresh })
            .await;
        assert!(
            matches!(put, Err(Error::Conflict(_))),
            "I1146: the replicated put of a fresh envelope is still Conflict: {put:?}"
        );
        let unchanged = swapped
            .federation_directory()
            .lookup_public_key(&key_id)
            .await
            .unwrap()
            .expect("held row");
        assert_eq!(unchanged.persist_row_hash, held.persist_row_hash);
    }
    /// I-IFP-9 — **the key record's signed `valid_from` is a CC 2.6.2
    /// instant** (CC 2.6.1.7's preimage table, beside `valid_until`). The
    /// self-registration door refuses a caller envelope whose `valid_from` is
    /// offset-form or carries nine fractional digits, admits `.sssZ` and keeps
    /// it, and with no `valid_from` writes one `.sssZ`, the same instant the
    /// record carries.
    pub(crate) async fn i_ifp_9_self_registration_valid_from(dsn: &str, tag: &str) {
        use crate::verify::canonical_validation::validate_canonical_datetime;
        let alias = format!("{tag}-ifp9-node");
        let e = engine(dsn, &alias, &alias).await;
        for bad in [
            "2026-06-23T03:16:34.499535577+00:00",
            "2026-06-23T03:16:34.499535577Z",
            "2026-06-23T03:16:34.499+00:00",
        ] {
            let r = e
                .register_self_federation_key(
                    NODE,
                    &alias,
                    None,
                    serde_json::json!({ "valid_from": bad }),
                    vec![],
                )
                .await;
            match r {
                Err(Error::InvalidArgument(why)) => {
                    assert!(
                        why.contains("valid_from"),
                        "I-IFP-9: names the member: {why}"
                    )
                }
                other => panic!("I-IFP-9: {bad:?} is refused InvalidArgument: {other:?}"),
            }
        }
        let good = "2026-06-23T03:16:34.499Z";
        let key_id = e
            .register_self_federation_key(
                NODE,
                &alias,
                None,
                serde_json::json!({ "valid_from": good }),
                vec![],
            )
            .await
            .expect("I-IFP-9: a .sssZ valid_from is admitted");
        let held = e
            .federation_directory()
            .lookup_public_key(&key_id)
            .await
            .unwrap()
            .expect("held row");
        assert_eq!(
            held.registration_envelope["valid_from"], good,
            "I-IFP-9: kept"
        );
        assert_eq!(
            crate::federation::admission::render_signed_instant(held.valid_from),
            good,
            "I-IFP-9: the record carries the signed instant"
        );
        drop(e);

        let alias = format!("{tag}-ifp9-fresh");
        let e = engine(dsn, &alias, &alias).await;
        let key_id = e
            .register_self_federation_key(NODE, &alias, None, serde_json::json!({}), vec![])
            .await
            .expect("I-IFP-9: registration");
        let held = e
            .federation_directory()
            .lookup_public_key(&key_id)
            .await
            .unwrap()
            .expect("held row");
        let written = held.registration_envelope["valid_from"]
            .as_str()
            .expect("I-IFP-9: the emitter writes valid_from")
            .to_owned();
        validate_canonical_datetime(&written).expect("I-IFP-9: written .sssZ");
        assert_eq!(
            crate::federation::admission::render_signed_instant(held.valid_from),
            written,
            "I-IFP-9: the record carries the written instant"
        );
    }
}

#[cfg(test)]
mod tests {
    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1146_restart_is_a_no_op_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
        super::bodies::i1146_restart_is_a_no_op(&dsn, &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1146_restart_is_a_no_op_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::bodies::i1146_restart_is_a_no_op(&dsn, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i_ifp_9_self_registration_valid_from_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
        super::bodies::i_ifp_9_self_registration_valid_from(&dsn, &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i_ifp_9_self_registration_valid_from_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::bodies::i_ifp_9_self_registration_valid_from(&dsn, &tag()).await;
    }
}
