//! v60.0.0 (CIRISPersist#1114; CC 2.6.1.7, rc10 `99bf187`) — **I1309–I1311:
//! three refusals of the signed object get their own `federation_malformed_row`
//! reasons**, on every backend, through `put_attestation`.
//!
//! - **I1309 (`content_hash_mismatch`)** — a row whose `original_content_hash`
//!   is not the SHA-256 of JCS(its envelope) is refused with the reason (it was
//!   `federation_tier_unverified` with a free-text reason); the same row with
//!   its true hash admits.
//! - **I1310 (`envelope_row_member_unknown`)** — a signed `row` mirror with an
//!   eighth member is refused with the reason (it was
//!   `envelope_member_invalid`); a mirror MISSING a member stays
//!   `envelope_member_invalid`, so the new reason names only the extra member.
//! - **I1311 (`subject_key_id_malformed`)** — a `subject_key_ids` element that
//!   is neither a canonical lowercase key_id nor the tagged canonical form is
//!   refused with the reason at the attestation door (it was
//!   `federation_invalid_argument`), and the validator itself says the same.
//!
//! The three are rc10 tokens (CC 2.6.1.7 at `99bf187`, after the `v1.0-rc9`
//! tag persist vendors), pinned as "named by no CC text at the pin" in
//! `namespace::cc_manifests` I1308 until the next CC re-pin.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::malformed_row;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, Attestation};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    fn ms_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("ms")
    }

    /// A self-report by `who`, sealed (mirror stamped, hybrid-signed).
    fn sealed(who: &str, n: u32) -> Attestation {
        let env = serde_json::json!({ "dimension": "config:i1309-act:v1", "n": n });
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = ts::bare_attestation(&id, who, who, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = ms_now();
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(who, &mut r);
        r
    }

    /// Re-sign the envelope as it stands, without re-stamping the mirror.
    fn resign_only(who: &str, r: &mut Attestation) {
        let (och, sc, sp) = ts::sign_envelope(who, &r.attestation_envelope);
        r.original_content_hash = och;
        r.scrub_signature_classical = sc;
        r.scrub_signature_pqc = sp;
    }

    fn reason(e: Error, what: &str) -> &'static str {
        assert_eq!(e.kind(), "federation_malformed_row", "{what}: {e}");
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => panic!("{what}: expected a malformed row, got {other:?}"),
        }
    }

    async fn put(d: &dyn FederationDirectory, r: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .map(|_| ())
    }

    /// **I1309** — `content_hash_mismatch`.
    pub(crate) async fn i1309_content_hash_mismatch(d: &dyn FederationDirectory, tag: &str) {
        let a = format!("i1309-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;
        let mut bad = sealed(&a, 1);
        bad.original_content_hash = "0".repeat(64);
        let e = put(d, bad)
            .await
            .expect_err("I1309: a wrong hash is refused");
        assert_eq!(
            reason(e, "I1309"),
            malformed_row::CONTENT_HASH_MISMATCH,
            "I1309"
        );
        put(d, sealed(&a, 2))
            .await
            .expect("I1309: the true hash admits");
    }

    /// **I1310** — `envelope_row_member_unknown`; a missing member stays
    /// `envelope_member_invalid`.
    pub(crate) async fn i1310_envelope_row_member_unknown(d: &dyn FederationDirectory, tag: &str) {
        let a = format!("i1310-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;
        let mut extra = sealed(&a, 1);
        extra.attestation_envelope["row"]["relay_note"] = serde_json::json!("x");
        resign_only(&a, &mut extra);
        let e = put(d, extra)
            .await
            .expect_err("I1310: an eighth mirror member is refused");
        assert_eq!(
            reason(e, "I1310"),
            malformed_row::ENVELOPE_ROW_MEMBER_UNKNOWN,
            "I1310"
        );
        let mut missing = sealed(&a, 2);
        missing.attestation_envelope["row"]
            .as_object_mut()
            .expect("mirror")
            .remove("cohort_scope");
        resign_only(&a, &mut missing);
        let e = put(d, missing)
            .await
            .expect_err("I1310: a missing mirror member is refused");
        assert_eq!(
            reason(e, "I1310 missing"),
            malformed_row::ENVELOPE_MEMBER_INVALID,
            "I1310: a missing member is not an unknown one"
        );
        put(d, sealed(&a, 3))
            .await
            .expect("I1310: the closed seven admit");
    }

    /// **I1311** — `subject_key_id_malformed`.
    pub(crate) async fn i1311_subject_key_id_malformed(d: &dyn FederationDirectory, tag: &str) {
        let a = format!("i1311-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;
        for bad_id in [
            "Actor-A".to_owned(),
            "actor a".to_owned(),
            format!("canonical:sha256:{}", "A".repeat(64)),
        ] {
            let mut r = sealed(&a, 1);
            r.subject_key_ids = vec![bad_id.clone()];
            ts::seal_row_in_place(&a, &mut r);
            let e = put(d, r)
                .await
                .expect_err("I1311: a malformed subject is refused");
            assert_eq!(
                reason(e, "I1311"),
                malformed_row::SUBJECT_KEY_ID_MALFORMED,
                "I1311 {bad_id:?}"
            );
            let e = crate::federation::validate_subject_key_ids(&[bad_id]).unwrap_err();
            assert_eq!(
                reason(e, "I1311 validator"),
                malformed_row::SUBJECT_KEY_ID_MALFORMED
            );
        }
        let mut ok = sealed(&a, 2);
        ok.subject_key_ids = vec![format!("canonical:sha256:{}", "9f".repeat(32))];
        ts::seal_row_in_place(&a, &mut ok);
        put(d, ok).await.expect("I1311: a canonical subject admits");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("1114 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i1309, bodies::i1309_content_hash_mismatch);
    on_every_backend!(i1310, bodies::i1310_envelope_row_member_unknown);
    on_every_backend!(i1311, bodies::i1311_subject_key_id_malformed);
}
