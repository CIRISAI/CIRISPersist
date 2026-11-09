//! v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — **I1568: the public Rust
//! verify API accepts only `Strict`.**
//!
//! The Python doors (I1560, I1561) and the capsule (I1562) refused every
//! policy but `Strict`, but a Rust caller of `verify::hybrid::verify_hybrid`
//! or `verify_hybrid_via_directory` could still pass `Ed25519Fallback`. Both
//! now ask `require_strict_policy` first; persist's two PINNED classical-only
//! planes call the crate-private twin `verify_hybrid_with_policy`.
//!
//! - **I1568 (unit)** `verify_hybrid`: `verify::hybrid`'s
//!   `i1568_public_verify_hybrid_refuses_every_policy_but_strict`.
//! - **I1568 (trace)** `verify_trace_hybrid`: `verify::ed25519`'s
//!   `i1568_verify_trace_hybrid_refuses_every_policy_but_strict`.
//! - **I1568 (this module, sqlite + postgres)** `verify_hybrid_via_directory`
//!   over a registered hybrid key: a genuine hybrid signature verifies under
//!   `Strict`; the SAME signature under `Ed25519Fallback` or `SoftFreshness`
//!   is refused `PolicyViolation` (with both PQC halves present the policy
//!   would otherwise be ignored and the call would verify, so the refusal is
//!   the gate); and an UNKNOWN key under a non-strict policy is refused with
//!   the policy token, not `verify_unknown_key` — the gate runs before the
//!   directory lookup.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::FederationDirectory;
    use crate::verify::hybrid::{
        verify_hybrid_via_directory, HybridPolicy, VerifyError, VerifyOutcome,
        VERIFY_POLICY_VIOLATION,
    };

    /// I1568 — `verify_hybrid_via_directory` refuses every policy but
    /// `Strict`, before the lookup.
    pub(crate) async fn i1568_via_directory_refuses_every_policy_but_strict<D>(dir: &D, tag: &str)
    where
        D: FederationDirectory + ?Sized,
    {
        // The distinguishing part first: test seeds take a key_id's first 32
        // bytes.
        let key = format!("{tag}-i1568-signer");
        ts::register_hybrid_key(dir, &key).await;
        let msg = b"CIRISPersist#1233 I1568 via directory".as_slice();
        let sig = ts::threshold_sign(&key, msg);
        let pqc = sig.mldsa65_signature_base64.clone();

        let strict = verify_hybrid_via_directory(
            dir,
            msg,
            &key,
            &sig.ed25519_signature_base64,
            pqc.as_deref(),
            HybridPolicy::Strict,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("I1568 {tag}: a genuine hybrid signature verifies: {e}"));
        assert_eq!(strict, VerifyOutcome::HybridVerified, "I1568 {tag}");

        let unknown = verify_hybrid_via_directory(
            dir,
            msg,
            "i1568-no-such-key",
            &sig.ed25519_signature_base64,
            pqc.as_deref(),
            HybridPolicy::Strict,
            None,
        )
        .await
        .expect_err("I1568: an unknown key under Strict");
        assert!(
            unknown.to_string().contains("verify_unknown_key"),
            "I1568 {tag}: under Strict an unknown key reaches the lookup: {unknown}"
        );

        for policy in [
            HybridPolicy::Ed25519Fallback,
            HybridPolicy::SoftFreshness {
                window: std::time::Duration::from_secs(86_400),
            },
        ] {
            let err = verify_hybrid_via_directory(
                dir,
                msg,
                &key,
                &sig.ed25519_signature_base64,
                pqc.as_deref(),
                policy,
                Some(std::time::Duration::from_secs(1)),
            )
            .await
            .expect_err("I1568: a non-strict policy over a VALID signature is refused");
            assert!(
                matches!(err, VerifyError::PolicyViolation { policy: p } if p == policy),
                "I1568 {tag}: {policy:?} is a policy violation: {err:?}"
            );
            assert_eq!(err.kind(), VERIFY_POLICY_VIOLATION, "I1568 {tag}");

            let err = verify_hybrid_via_directory(
                dir,
                msg,
                "i1568-no-such-key",
                &sig.ed25519_signature_base64,
                None,
                policy,
                None,
            )
            .await
            .expect_err("I1568: a non-strict policy for an unknown key is refused");
            assert_eq!(
                err.kind(),
                VERIFY_POLICY_VIOLATION,
                "I1568 {tag}: {policy:?} is refused before the lookup: {err}"
            );
            assert!(
                !err.to_string().contains("verify_unknown_key"),
                "I1568 {tag}: the lookup never ran: {err}"
            );
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1568_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1568_via_directory_refuses_every_policy_but_strict(&b, &tag("s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1568_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("1233 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1568_via_directory_refuses_every_policy_but_strict(&b, &tag("p")).await;
        eprintln!("i1568 postgres: RAN");
    }
}
