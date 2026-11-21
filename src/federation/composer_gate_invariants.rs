//! v62.0.0 (PIN-fix2; CIRISVerify 23.4.1, CC part 3 l.2543) — **I2433: the
//! dimension gate asks a `withdraws` / `recants` its TARGET's dimension.**
//!
//! At 23.4.1 a `withdraws` / `recants` carries no `dimension` (Verify refuses
//! one), so the dimension gate (`DimensionAdmissionPolicy`, the reserved
//! family rules that "ride a structural composer", CC part 3 l.2543) would
//! read none and stop asking. [`composer_gate_dimension`] gives it the held
//! target's, through the one resolver the put doors pass Verify
//! (`edition2::typed::held_target_row`). On sqlite and postgres:
//!
//! - a withdrawal of a held row: the gate reads the target's dimension, and
//!   the withdrawal itself states none;
//! - under `Enforce`, that dimension refuses an unentitled signer as it would
//!   on the target (the reserved-prefix rule, I374's case), so the gate is
//!   asked, not skipped;
//! - a withdrawal of a row NOT held: the gate does not run on nothing; the
//!   composer waits (`federation_withdraws_target_unheld`, held `link_unheld`).
//!
//! [`composer_gate_dimension`]: super::attestation_admit::composer_gate_dimension

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::{envelope_dimension, DimensionAdmissionPolicy};
    use crate::federation::attestation_admit::composer_gate_dimension;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::row_type::{with_enforcement, RowTypeEnforcement};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{Attestation, FederationDirectory};

    const DIM: &str = "evidence:safety_battery:capture:a:c:v1";

    fn scores(by: &str, dimension: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({ "dimension": dimension, "id": id });
        let mut r = ts::bare_attestation(&id, by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = chrono::Utc::now() - chrono::Duration::minutes(5);
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(by, &mut r);
        r
    }

    pub(crate) async fn i2433_body(d: &dyn FederationDirectory, s: &str) {
        let seed = format!("i2433-{s}");
        ts::register_hybrid_key_as(
            d,
            &seed,
            &seed,
            crate::federation::types::identity_type::USER,
        )
        .await;
        let by = e2::kid(&seed);

        // A held target, and its withdrawal.
        let target = scores(&by, DIM);
        e2::put_signed(d, &target)
            .await
            .expect("I2433 the target lands");
        let w = e2::composer_of(attestation_type::WITHDRAWS, &target, &seed);
        assert_eq!(
            envelope_dimension(&w.attestation_envelope),
            None,
            "I2433 a withdrawal states no dimension of its own"
        );
        let got = composer_gate_dimension(d, &w)
            .await
            .expect("I2433 the target is held");
        assert_eq!(
            got.as_deref(),
            Some(DIM),
            "I2433 the gate reads the TARGET's dimension"
        );

        // The gate is asked of that dimension: under Enforce a reserved
        // dimension refuses an unentitled signer (I374's case, on WITHDRAWS).
        with_enforcement(RowTypeEnforcement::Enforce, async {
            let p = DimensionAdmissionPolicy::default();
            p.check(attestation_type::WITHDRAWS, got.as_deref(), "user")
                .expect("I2433 an open family's withdrawal passes");
            let e = p
                .check(
                    attestation_type::WITHDRAWS,
                    Some("system:health:v1"),
                    "user",
                )
                .expect_err("I2433 a reserved target dimension is asked of the withdrawal");
            assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
        })
        .await;

        // A target not held: the composer waits, the gate is never skipped.
        let ghost = scores(&by, "evidence:safety_battery:capture:a2:c:v1");
        let w2 = e2::composer_of(attestation_type::WITHDRAWS, &ghost, &seed);
        let e = composer_gate_dimension(d, &w2)
            .await
            .expect_err("I2433 an unheld target is waited for");
        assert_eq!(e.kind(), "federation_withdraws_target_unheld", "I2433: {e}");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2433_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i2433_body(&b, &suffix()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2433_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i2433_body(&b, &suffix()).await;
    }
}
