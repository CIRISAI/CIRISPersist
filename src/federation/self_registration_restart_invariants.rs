//! v61 (CIRISPersist#1146), re-read for v62.0.0 (JSON-cut slice B) — **a
//! restart that re-registers the same key is a no-op success.**
//!
//! An agent-embedded node calls `Engine::register_self_federation_key` on
//! every boot. Since v62 the registration is a self-signed `key:record`
//! edition-2 statement of the engine's composite key, and the call returns
//! the key's identity-ref.
//!
//! - **I1146** — a restart that states the same identity set and evidence
//!   signs nothing: the held record is the only one, byte for byte. A
//!   changed identity set, or an asked end, is a real change: a further
//!   record of the same key, admitted (a key record is not a single-valued
//!   row; CC 2.4.1.1). A different composite key is a different identity.
//! - **I2202** — the identity-ref is `local_derived_key_id()`; a classical-only
//!   engine refuses `composite_signing_unavailable` and stores nothing; a
//!   `node` record with no asked end ends 365 days out (CC 2.4.1.1's window);
//!   a `user` record carries none.
//!
//! One body, run on sqlite (a file both engines open) and postgres (one
//! database both engines open).

/// The witness body: two engines over one store, the second a "restart".
pub(crate) mod bodies {
    use crate::federation::edition2::emit::COMPOSITE_SIGNING_UNAVAILABLE;
    use crate::federation::edition2::ingest::{held_keys_for_kid, kid_of_identity_ref};
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::Error;
    use ciris_verify_core::edition2::keys::KEY_RECORD_MAX_SECS;

    /// A composite signer: Ed25519 from `alias`, ML-DSA-65 from `pqc_alias`.
    pub(crate) fn signer(
        alias: &str,
        pqc_alias: &str,
    ) -> std::sync::Arc<crate::signing::LocalSigner> {
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

    /// The held `key:record` statements of `iref`.
    async fn records(e: &crate::Engine, iref: &str) -> Vec<Vec<u8>> {
        e.federation_directory()
            .edition2_statements_about("key:record", iref)
            .await
            .unwrap()
    }

    /// I1146 under edition 2.
    pub(crate) async fn i1146_restart_is_a_no_op(dsn: &str, tag: &str) {
        let alias = format!("{tag}-1146-node");
        let first = engine(dsn, &alias, &alias).await;
        let iref = first
            .register_self_federation_key(NODE, None, None)
            .await
            .expect("I1146: first registration");
        let held = records(&first, &iref).await;
        assert_eq!(held.len(), 1, "I1146: one record");
        drop(first);

        // A restart: a second engine, the same key.
        let restarted = engine(dsn, &alias, &alias).await;
        let again = restarted
            .register_self_federation_key(NODE, None, None)
            .await
            .expect("I1146: a restart that re-registers the same key is Ok");
        assert_eq!(again, iref);
        assert_eq!(
            records(&restarted, &iref).await,
            held,
            "I1146: nothing is signed; the held record is kept byte for byte"
        );

        // A changed identity set is a further record of the same key.
        restarted
            .register_self_federation_key("node,witness", None, None)
            .await
            .expect("I1146: a changed set is a further record");
        assert_eq!(
            records(&restarted, &iref).await.len(),
            2,
            "I1146: two records"
        );

        // An asked end is a real change too.
        let asked = chrono::Utc::now() + chrono::Duration::days(30);
        restarted
            .register_self_federation_key(NODE, Some(asked), None)
            .await
            .expect("I1146: an asked end is a further record");
        assert_eq!(records(&restarted, &iref).await.len(), 3);
        drop(restarted);

        // A different ML-DSA half is a different composite key: a different
        // identity, never a conflict over the first.
        let swapped = engine(dsn, &alias, &format!("{tag}-1146-other-pqc")).await;
        let other = swapped
            .register_self_federation_key(NODE, None, None)
            .await
            .expect("I1146: another key registers");
        assert_ne!(
            other, iref,
            "I1146: another composite, another identity-ref"
        );
        assert_eq!(records(&swapped, &iref).await.len(), 3, "I1146: untouched");
    }

    /// I2202 — the identity-ref, the classical-only refusal, the end rule.
    pub(crate) async fn i2202_register_self_returns_the_identity_ref(dsn: &str, tag: &str) {
        let alias = format!("{tag}-2202-node");
        let e = engine(dsn, &alias, &alias).await;
        let iref = e
            .register_self_federation_key(NODE, None, None)
            .await
            .expect("I2202: registration");
        assert!(
            iref.starts_with(ciris_verify_core::edition2::IDENTITY_REF_PREFIX),
            "I2202: an identity-ref: {iref}"
        );
        assert_eq!(
            e.local_derived_key_id().await.unwrap(),
            iref,
            "I2202: local_derived_key_id is the identity-ref"
        );
        let kid = kid_of_identity_ref(&iref).expect("I2202: names a kid");
        let keys = held_keys_for_kid(e.federation_directory().as_ref(), &kid)
            .await
            .unwrap();
        let valid = keys.valid_records(&kid).expect("I2202: a valid record");
        assert_eq!(valid.len(), 1);
        let r = &valid[0].record;
        assert_eq!(r.identity_type, vec!["node".to_owned()]);
        assert_eq!(
            r.valid_until,
            Some(r.asserted_at + KEY_RECORD_MAX_SECS * 1000),
            "I2202: a node record with no asked end ends at the window"
        );
        // The projection the earlier-form gates read.
        let projected = e
            .federation_directory()
            .lookup_public_key(&iref)
            .await
            .unwrap()
            .expect("I2202: projected into federation_keys");
        assert_eq!(projected.identity_type, "node");
        drop(e);

        // A user record carries no end.
        let user_alias = format!("{tag}-2202-user");
        let u = engine(dsn, &user_alias, &user_alias).await;
        let uref = u
            .register_self_federation_key(USER, None, None)
            .await
            .expect("I2202: a user registers");
        let ukid = kid_of_identity_ref(&uref).unwrap();
        let keys = held_keys_for_kid(u.federation_directory().as_ref(), &ukid)
            .await
            .unwrap();
        assert_eq!(
            keys.valid_records(&ukid).unwrap()[0].record.valid_until,
            None
        );
        drop(u);

        // A classical-only engine produces nothing on the mesh.
        let c_alias = format!("{tag}-2202-classical");
        let classical = std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
            ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]),
            c_alias.clone(),
            None,
            None,
        ));
        let c = crate::Engine::with_signer_pre_genesis(classical, dsn)
            .await
            .expect("engine");
        match c.register_self_federation_key(NODE, None, None).await {
            Err(Error::InvalidArgument(m)) if m.starts_with(COMPOSITE_SIGNING_UNAVAILABLE) => {}
            other => panic!("I2202: composite_signing_unavailable, got {other:?}"),
        }
        match c
            .emit_attestation_self(crate::federation::EmitAttestationInput::with_envelope(
                "scores",
                crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({"dimension": "health:liveness:v1"}),
                )
                .unwrap(),
                crate::federation::types::cohort_scope::FEDERATION,
            ))
            .await
        {
            Err(Error::InvalidArgument(m)) if m.starts_with(COMPOSITE_SIGNING_UNAVAILABLE) => {}
            other => panic!("I2202: a classical-only engine emits nothing, got {other:?}"),
        }
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
    async fn i2202_register_self_returns_the_identity_ref_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
        Box::pin(super::bodies::i2202_register_self_returns_the_identity_ref(
            &dsn,
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2202_register_self_returns_the_identity_ref_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(super::bodies::i2202_register_self_returns_the_identity_ref(
            &dsn,
            &tag(),
        ))
        .await;
    }
}
