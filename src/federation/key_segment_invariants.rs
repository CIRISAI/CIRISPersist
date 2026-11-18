//! v62 (CC rc21, CC 3.1 "A shape beyond the class") — **a key in a family
//! name is its bare thumbprint segment**, and the licensure authority gate
//! matches a v62 key through it, on every backend.
//!
//! - **I2965** — the board is a v62 key (an identity-ref). Its licences name
//!   it as `licensure:<segment>:v1`:
//!   - (a) the board's own licence admits and folds
//!     (`status_set_for(holder, <identity-ref>)` is `{issued}`);
//!   - (b) a licence by the board's `license`-scoped officer, naming the edge,
//!     admits: the door read the authority as the board's key;
//!   - (c) the same licence by a key with no edge from the board is refused
//!     `licensure_delegator_not_authority`, and nothing is stored;
//!   - (d) the officer's licence folds as the board's.
//! - **I2966** — a key-shaped segment with trailing bits is a malformed row
//!   (`envelope_member_invalid`) at the direct and replicated doors, and
//!   nothing is stored. CC rc21: a licence whose dimension carries the board's
//!   URN (`licensure:urn:ietf:params:oauth:ckt:sha-256:<…>:v1`) matches NO
//!   family: the key-segment gate does not refuse it (the door gives its
//!   normal unclaimed-dimension answer, at both doors), it names no authority,
//!   and it is not the board's licensure.
//!
//! Earlier-form (JSON) rows, as the rest of the suite until the fixture flip;
//! the dimension's spelling is the same in edition 2.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::steward_liveness_test_support::{
        register, signed_row, store,
    };
    use crate::federation::admission::DELEGATION_SCOPE_LICENSE;
    use crate::federation::licensure::{licensure_stem_of, status_set_for, LicensureStatus};
    use crate::federation::namespace::key_segment::tests::{kid, segment};
    use crate::federation::tier_ingest::test_support::reseal;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{
        malformed_row, Attestation, Error, FederationDirectory, SignedAttestation,
    };
    use std::collections::BTreeSet;

    const REFUSAL: &str = "licensure_delegator_not_authority";

    /// A licence on `holder` whose dimension is `{stem}:v1`, verbatim.
    fn licence(issuer: &str, holder: &str, stem: &str, delegation_id: Option<&str>) -> Attestation {
        let mut envelope = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": format!("{stem}:v1"),
            "status": "issued",
            "score": 1.0,
            "confidence": 0.9,
        });
        if let Some(d) = delegation_id {
            envelope["delegation_id"] = serde_json::Value::String(d.to_owned());
        }
        let mut row = signed_row(issuer, holder, attestation_type::SCORES, envelope);
        reseal(&mut row);
        row
    }

    fn assert_malformed(e: &Error, what: &str) {
        match e {
            Error::MalformedRow { reason, .. } => {
                assert_eq!(*reason, malformed_row::ENVELOPE_MEMBER_INVALID, "{what}")
            }
            other => panic!("{what}: expected a malformed row, got {other:?}"),
        }
    }

    /// **I2965 + I2966** — see the module doc.
    pub(crate) async fn i2965_the_licensure_gate_matches_a_v62_key(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // The test signer seeds from the first 32 bytes of a key id and every
        // identity-ref shares its first 34, so exactly ONE identity-ref key
        // is registered here.
        let board = kid('Q');
        let stem = licensure_stem_of(&board);
        assert_eq!(stem, format!("licensure:{}", segment('Q')));
        let holder = format!("{tag}-holder");
        let holder2 = format!("{tag}-holder2");
        let clerk = format!("{tag}-clerk");
        let stranger = format!("{tag}-stranger");
        register(d, &board, &[identity_type::USER]).await;
        for k in [&holder, &holder2] {
            register(d, k, &[identity_type::USER]).await;
        }
        for k in [&clerk, &stranger] {
            register(d, k, &[identity_type::PRIMITIVE]).await;
        }

        // (a) The board's own licence, its key written bare.
        store(d, &licence(&board, &holder, &stem, None))
            .await
            .unwrap_or_else(|e| panic!("I2965 (a): the board's own licence admits: {e}"));
        assert_eq!(
            status_set_for(d, &holder, &board, chrono::Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "I2965 (a): asked by the board's key id, the fold reads its licence"
        );

        // (b) The board's licensing officer.
        let mut edge = signed_row(
            &board,
            &clerk,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "scope": [DELEGATION_SCOPE_LICENSE],
            }),
        );
        edge.subject_key_ids = vec![clerk.clone()];
        reseal(&mut edge);
        store(d, &edge)
            .await
            .unwrap_or_else(|e| panic!("I2965 (b): the board appoints its officer: {e}"));
        store(
            d,
            &licence(&clerk, &holder2, &stem, Some(&edge.attestation_id)),
        )
        .await
        .unwrap_or_else(|e| panic!("I2965 (b): the officer's licence admits: {e}"));

        // (c) A key with no edge from the board.
        let forged = licence(&stranger, &holder, &stem, Some(&edge.attestation_id));
        let err = store(d, &forged)
            .await
            .expect_err("I2965 (c): a stranger's licence for the board is refused");
        assert!(
            err.to_string().contains(REFUSAL),
            "I2965 (c): refused by the licensure gate, got {err}"
        );
        assert!(d
            .get_attestation(&forged.attestation_id)
            .await
            .expect("read")
            .is_none());

        // (d) The officer's licence is the board's licensure.
        assert_eq!(
            status_set_for(d, &holder2, &board, chrono::Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "I2965 (d): the officer's licence folds as the board's"
        );

        // I2966 — a second spelling of the segment (trailing bits) is a
        // malformed row, at the direct and replicated doors.
        let mut bits = segment('Q');
        bits.pop();
        bits.push('B');
        let row = licence(&board, &holder, &format!("licensure:{bits}"), None);
        assert_malformed(
            &store(d, &row).await.expect_err("trailing bits"),
            "I2966 (direct): trailing bits",
        );
        let e = d
            .apply_replicated_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .expect_err("trailing bits");
        assert_malformed(&e, "I2966 (replicated): trailing bits");
        assert!(d
            .get_attestation(&row.attestation_id)
            .await
            .expect("read")
            .is_none());

        // I2966 — CC rc21: the board's URN written where the authority goes
        // matches NO family. The key-segment gate does not refuse it; the door
        // gives its normal answer for a dimension no family claims (whatever
        // that is on this door), and nothing is admitted AS the board's
        // licensure.
        let urn_stem = format!("licensure:{board}");
        let urn_dim = format!("{urn_stem}:v1");
        assert_eq!(
            crate::federation::namespace::matcher::match_family(&urn_dim).family,
            None,
            "I2966: a URN in the authority position matches no family"
        );
        assert_eq!(
            crate::federation::licensure::authority_of(&urn_dim),
            None,
            "I2966: a URN names no authority"
        );
        let direct = licence(&board, &holder, &urn_stem, None);
        let wired = licence(&board, &holder, &urn_stem, None);
        let outcomes = [
            ("direct", store(d, &direct).await.err()),
            (
                "replicated",
                d.apply_replicated_attestation(SignedAttestation { attestation: wired })
                    .await
                    .err(),
            ),
        ];
        for (door, err) in outcomes {
            if let Some(Error::MalformedRow { reason, .. }) = &err {
                assert_ne!(
                    *reason,
                    malformed_row::ENVELOPE_MEMBER_INVALID,
                    "I2966 ({door}): a URN dimension is not the key-segment gate's refusal: {err:?}"
                );
            }
        }
        assert_eq!(
            status_set_for(d, &holder, &board, chrono::Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "I2966: a URN-dimension row is not the board's licensure (only (a)'s licence is)"
        );
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
    async fn i2965_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i2965_the_licensure_gate_matches_a_v62_key(&b, &tag("s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2965_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("I2965 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i2965_the_licensure_gate_matches_a_v62_key(&b, &tag("p")).await;
        eprintln!("i2965_postgres: RAN");
    }
}
