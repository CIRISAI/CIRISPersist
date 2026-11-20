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
//! Edition-2 rows (the fixture switch): seeds sign, the stored ids are their
//! identity-refs, and a key in a dimension is its bare segment.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::steward_liveness_test_support::signed_row;
    use crate::federation::admission::DELEGATION_SCOPE_LICENSE;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::apply_replicated_statement;
    use crate::federation::edition2::names::RowId;
    use crate::federation::licensure::{licensure_stem_of, status_set_for, LicensureStatus};
    use crate::federation::namespace::key_segment::tests::segment;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{malformed_row, Attestation, Error, FederationDirectory};
    use std::collections::BTreeSet;

    const REFUSAL: &str = "licensure_delegator_not_authority";

    /// A licence by `issuer` (a SEED) on `holder` (a seed) whose dimension is
    /// `{stem}:v1`, verbatim, as an edition-2 statement (the fixture switch).
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
        signed_row(issuer, holder, attestation_type::SCORES, envelope)
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
        // Seeds sign; the stored ids are their identity-refs (E0).
        let board_seed = format!("{tag}-brd");
        let holder_seed = format!("{tag}-hld");
        let holder2_seed = format!("{tag}-hl2");
        let clerk_seed = format!("{tag}-clk");
        let stranger_seed = format!("{tag}-str");
        let board = e2::put_key(d, &board_seed, &[identity_type::USER]).await;
        let holder = e2::put_key(d, &holder_seed, &[identity_type::USER]).await;
        let holder2 = e2::put_key(d, &holder2_seed, &[identity_type::USER]).await;
        let _ = e2::put_key(d, &clerk_seed, &[identity_type::PRIMITIVE]).await;
        let _ = e2::put_key(d, &stranger_seed, &[identity_type::PRIMITIVE]).await;
        let stem = licensure_stem_of(&board);
        assert_eq!(stem, format!("licensure:{}", e2::kid_thumb(&board_seed)));

        // (a) The board's own licence, its key written bare.
        e2::put_signed(d, &licence(&board_seed, &holder_seed, &stem, None))
            .await
            .unwrap_or_else(|e| panic!("I2965 (a): the board's own licence admits: {e}"));
        assert_eq!(
            status_set_for(d, &holder, &board, chrono::Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "I2965 (a): asked by the board's key id, the fold reads its licence"
        );

        // (b) The board's licensing officer: the edge lands with the
        // delegate's own voice (`self:delegates_to`'s second signer).
        let edge = signed_row(
            &board_seed,
            &clerk_seed,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "scope": [DELEGATION_SCOPE_LICENSE],
            }),
        );
        e2::put_signed(d, &edge)
            .await
            .unwrap_or_else(|e| panic!("I2965 (b): the board appoints its officer: {e}"));
        let st = e2::carried_statement(&edge).expect("the edge's statement");
        e2::put_statement(d, &e2::voice_of(&st, &clerk_seed))
            .await
            .unwrap_or_else(|e| panic!("I2965 (b): the officer's voice over its edge: {e}"));
        let edge_id = e2::rid(&edge);
        e2::put_signed(
            d,
            &licence(&clerk_seed, &holder2_seed, &stem, Some(&edge_id)),
        )
        .await
        .unwrap_or_else(|e| panic!("I2965 (b): the officer's licence admits: {e}"));

        // (c) A key with no edge from the board. v62.0.0 (CC 2.7, the
        // CC27 refuse-versus-hold rulings): whether the issuer is the board's
        // delegate reads OTHER rows, so it is the fold's: the licence is HELD
        // (`Pending`) for the licensure gate's reason and concludes nothing,
        // never refused at the door. It lands no typed row.
        let forged = licence(&stranger_seed, &holder_seed, &stem, Some(&edge_id));
        let out = e2::put_signed(d, &forged)
            .await
            .unwrap_or_else(|e| panic!("I2965 (c): a stranger's licence is held: {e}"));
        assert!(
            matches!(
                out,
                crate::federation::edition2::ingest::StatementOutcome::Pending { .. }
            ),
            "I2965 (c): a stranger's licence for the board is held, not admitted: {out:?}"
        );
        let id = crate::federation::edition2::voices::carried_row_id(&forged)
            .expect("the licence carries its statement");
        assert_eq!(
            crate::federation::edition2::fold::why_held(d, &id)
                .await
                .expect("read")
                .map(|h| h.reason)
                .as_deref(),
            Some(REFUSAL),
            "I2965 (c): held for the licensure gate's reason"
        );
        assert!(d
            .get_attestation(&e2::rid(&forged))
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
        let row = licence(
            &board_seed,
            &holder_seed,
            &format!("licensure:{bits}"),
            None,
        );
        assert_malformed(
            &e2::put_signed(d, &row).await.expect_err("trailing bits"),
            "I2966 (direct): trailing bits",
        );
        let st = e2::carried_statement(&row).expect("the row's statement");
        let e = apply_replicated_statement(d, &st, &e2::rid_digest(&row))
            .await
            .expect_err("trailing bits");
        assert_malformed(&e, "I2966 (replicated): trailing bits");
        assert!(d
            .get_attestation(&e2::rid(&row))
            .await
            .expect("read")
            .is_none());

        // I2966 — CC rc21: the board's URN written where the authority goes
        // matches NO family. The key-segment gate does not refuse it; the
        // door gives its normal answer for a dimension no family claims (the
        // edition-2 door: the dimension does not resolve to the family the
        // statement declares), and nothing is admitted as the board's
        // licensure.
        let urn_dim = format!("licensure:{board}:v1");
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
        let id = uuid::Uuid::new_v4().to_string();
        let mut shape = crate::federation::tier_ingest::test_support::bare_attestation(
            &id,
            &board_seed,
            &holder_seed,
            &serde_json::json!({
                "id": id,
                "dimension": urn_dim,
                "status": "issued",
                "score": 1.0,
                "confidence": 0.9,
            }),
        );
        shape.attestation_type = attestation_type::SCORES.to_owned();
        let urn_st = e2::statement_of_family(
            &shape,
            &board_seed,
            &ciris_verify_core::namespace_match::family_id("licensure:{authority_id}"),
        );
        let urn_id = RowId::of_statement(&urn_st).expect("a row statement");
        let direct = e2::put_statement(d, &urn_st).await.err();
        let wired = apply_replicated_statement(d, &urn_st, &urn_id.0)
            .await
            .err();
        for (door, err) in [("direct", direct), ("replicated", wired)] {
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
