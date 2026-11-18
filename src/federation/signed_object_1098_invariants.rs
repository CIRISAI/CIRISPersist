//! CIRISPersist#1098 (CC 2.6.1.1.1 and 2.6.1.7) — **I1478, I1479, I1493, I1494: the
//! signed-object cleanup**, and I1496 and I1498 from the CC re-vendors, on
//! every backend, through `put_attestation`.
//!
//! v62.0.0 (slice E6) — **I1478, I1479, I1494 and I1498 are deleted**: they
//! are the earlier form's JSON signed-object rules (an explicit JSON `null`
//! member and the `row` mirror, a `witnesses[]` set sorted by JCS string,
//! CC's JSON `signed_object_vectors.json`, the untyped JSON `listed`
//! member). An edition-2 row is a CDE payload under a COSE statement, whose
//! encoding rules Verify's door checks (`edition2::door_invariants`).
//! **I1493** keeps its reader legs and its store leg, minus the
//! earlier-form "the content hash is the producer's" pin; **I1496** is a
//! persist polarity gate and is flipped as is. Rows are edition-2 statements
//! signed by edition-2 keys (`fixture_switch`).
//!
//! - **I1478 (F4, `envelope_member_null`)** — an optional envelope member
//!   written as an explicit JSON `null`, at the top level or inside the `row`
//!   mirror, is refused `federation_malformed_row` / `envelope_member_null`
//!   naming the member; the same row with the member absent admits.
//! - **I1479 (F5, `witnesses[]` is a set)** — a `witnesses` array sorted by
//!   each element's JCS string and carrying no repeat admits; an out-of-order
//!   pair and a repeat are refused `federation_set_semantics_unsorted`; a
//!   `witnesses` that is not an array is `envelope_member_invalid`.
//! - **I1493 (F2, a bare scope token)** — `"scope": "retain"` admits as the
//!   one-element set `["retain"]` denotes: every scope reader answers the same
//!   for both forms, and the stored envelope keeps the bare token (signed
//!   bytes are never normalised).
//! - **I1494 (the 14 vectors)** — CC's `signed_object_vectors.json` at the
//!   vendored tag, replayed: each admit vector's signed row (and each recipe's
//!   reconstructed one) admits with its published content hash, and each
//!   refuse vector is refused with the persist token its CC refusal names.
//!   The three vectors persist answers differently are recorded in
//!   `DIVERGENCES` with the ruling that keeps each, a latch both ways.
//! - **I1496 (rc12, `observation:access_assumption` at `+1.0` only)** — the
//!   leaf the rc12 registry adds admits a score of `1.0` and refuses any other
//!   with `score_outside_declared_polarity` (CC 3.1.9.4; its first-person rule
//!   is CIRISPersist#1115). Carried from the rc12 side branch, where it was
//!   I1482 (v59.1.2 shipped I1480–I1483).
//! - **I1498 (rc13, `listed` retired)** — CC removed `listed` from CC 2.1, the
//!   defaults table and the signed object, and persist no longer types it
//!   (#991). At admission it is an unknown envelope member like any other
//!   `signed:envelope-extra`: carried untyped, a value of any type admits (a
//!   non-boolean was ill-typed while it was a typed member), the stored bytes
//!   keep it as signed, and only the general rule refuses it, as
//!   `envelope_member_null` when written `null`.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, Attestation};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    fn ms_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("ms")
    }

    /// The earlier-shaped self-report by `who` carrying `extra` members
    /// (under a fresh `config:{scope}` leaf), unsigned.
    fn shaped(who: &str, extra: serde_json::Value) -> Attestation {
        let leaf = uuid::Uuid::new_v4().simple().to_string();
        let mut env = serde_json::json!({ "dimension": format!("config:act{}:v1", &leaf[..8]) });
        for (k, v) in extra.as_object().expect("extra is an object") {
            env[k] = v.clone();
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = e2::with_earlier_form(|| ts::bare_attestation(&id, who, who, &env));
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = ms_now();
        r.scrub_timestamp = r.asserted_at;
        r
    }

    /// [`shaped`], signed by the key of seed `who`: an edition-2 statement.
    fn sealed_with(who: &str, extra: serde_json::Value) -> Attestation {
        e2::row_of(&shaped(who, extra), who)
    }

    async fn put(d: &dyn FederationDirectory, r: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .map(|_| ())
    }

    /// **I1493** — a bare scope token admits as the one-element array it
    /// denotes, and the stored envelope keeps the bare token.
    pub(crate) async fn i1493_a_bare_scope_token(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::admission::delegation_scope_set;
        use crate::federation::consent::named_scopes;
        let a = format!("i1493-{tag}");
        let _ = e2::put_key(d, &a, &[it::USER]).await;
        let bare = sealed_with(&a, serde_json::json!({ "scope": "retain" }));
        let array = sealed_with(&a, serde_json::json!({ "scope": ["retain"] }));
        assert_eq!(
            named_scopes(&bare),
            named_scopes(&array),
            "I1493 consent reader"
        );
        assert_eq!(
            delegation_scope_set(&bare.attestation_envelope),
            delegation_scope_set(&array.attestation_envelope),
            "I1493 delegation reader"
        );
        assert!(
            crate::federation::trust_root::scope_contains(&bare.attestation_envelope, "retain")
                && crate::federation::trust_root::scope_contains(
                    &array.attestation_envelope,
                    "retain"
                ),
            "I1493 scope_contains"
        );
        let bare_id = bare.attestation_id.clone();
        put(d, bare).await.expect("I1493: a bare token admits");
        put(d, array).await.expect("I1493: the array admits");
        let stored = d
            .get_attestation(&bare_id)
            .await
            .expect("read")
            .expect("I1493: the bare-token row is held");
        assert_eq!(
            stored.attestation_envelope["scope"],
            serde_json::json!("retain"),
            "I1493: the stored envelope keeps the bare token"
        );
    }

    /// **I1496** — `observation:access_assumption` admits `+1.0` only.
    pub(crate) async fn i1496_access_assumption_is_plus_one_only(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let a = format!("i1496-{tag}");
        let _ = e2::put_key(d, &a, &[it::USER]).await;
        let row = |score: f64| {
            let mut r = shaped(&a, serde_json::json!({ "score": score }));
            r.attestation_envelope["dimension"] =
                serde_json::json!("observation:access_assumption:v1");
            r.subject_key_ids = vec![e2::kid(&a)];
            e2::row_of(&r, &a)
        };
        for score in [0.5, -1.0, 0.0] {
            let e = put(d, row(score))
                .await
                .expect_err("I1496: a score other than +1.0 is refused");
            assert!(
                e.to_string().contains("score_outside_declared_polarity"),
                "I1496 score {score}: {e}"
            );
        }
        put(d, row(1.0))
            .await
            .expect("I1496: +1.0 admits on the vendored registry");
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
                        eprintln!("1098 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
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

    on_every_backend!(i1493, bodies::i1493_a_bare_scope_token);
    on_every_backend!(i1496, bodies::i1496_access_assumption_is_plus_one_only);
}
