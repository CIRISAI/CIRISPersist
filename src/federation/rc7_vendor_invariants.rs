//! v55.0.0 (CIRISPersist#753, slice A0) — I700–I709, the CC v1.0-rc7
//! re-vendor.
//!
//! - **I700** / **I701** (pure, `namespace::registry`) — the temporary rc6
//!   carrier exception admits exactly the two retired carriers, and a
//!   from-disk gate fails once a 55.0.0-or-later release is cut with it still
//!   in place.
//! - **I702** (pure, `admission`) — every held-shut prefix is registered,
//!   tracked, and refuses its own sample.
//! - **I703** a `settlement:*` row (CC 3.3.10) admits from an ordinary signer
//!   at federation tier on both arms — `self` (private, the default) and
//!   `federation` (opt-in auditable) — and the payee's
//!   `settlement:received:*` counter-attestation admits too.
//! - **I704** a `settlement:*` row carrying a payment-processor identifier is
//!   refused `federation_payment_processor_identifier`; nothing is stored.
//! - **I705** a `ledger:*` row (CC 3.3.10.1) by its owner admits at federation
//!   tier (the staging latch is gone); one signed by a key that does not act
//!   for the owner is refused `federation_signer_not_acting_for`; the L1
//!   binding still refuses a foreign `ledger_id`. Nothing refused is stored.
//! - **I706** the dimensions rc7 registers and persist has no door for —
//!   `key_grant:{axis}:v1` and `membership:{widening|removal|resignation}:v1`
//!   — are refused `federation_dimension_rejected` /
//!   `registered_family_held_shut` on `scores` and on a composer; nothing is
//!   stored.
//!
//! Each runs on memory, sqlite and postgres (postgres through
//! `CIRIS_PERSIST_TEST_PG_URL`; without it the leg returns at once).

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_emit::{assemble, stamp_and_canonicalize};
    use crate::federation::envelope::EnvelopeCore;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{cohort_scope, EmitAttestationInput, SignedAttestation};
    use crate::federation::{Attestation, FederationDirectory};

    pub(crate) struct Who {
        pub signer: std::sync::Arc<crate::signing::LocalSigner>,
        pub key: String,
    }

    pub(crate) async fn who<B: FederationDirectory + Sync>(b: &B, alias: &str) -> Who {
        let signer = ts::local_signer(alias);
        let key = signer.derived_key_id();
        ts::register_hybrid_key_as(b, &key, alias, USER).await;
        Who { signer, key }
    }

    fn input(t: &str, scope: &str, env: serde_json::Value) -> EmitAttestationInput {
        EmitAttestationInput::with_envelope(t, EnvelopeCore::from_value(env).unwrap(), scope)
    }

    /// A signed row as a peer would send it, assembled past the emit gates.
    async fn signed(w: &Who, mut i: EmitAttestationInput) -> Attestation {
        let canonical = stamp_and_canonicalize(&mut i, &w.key, chrono::Utc::now()).unwrap();
        let sig = w.signer.sign_hybrid(&canonical).await.unwrap();
        assemble(w.key.clone(), &canonical, sig, i).unwrap().0
    }

    async fn put<B: FederationDirectory + Sync>(
        b: &B,
        row: Attestation,
    ) -> Result<(), crate::federation::Error> {
        b.put_attestation(SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    async fn refused<B: FederationDirectory + Sync>(
        b: &B,
        row: Attestation,
        kind: &str,
        why: &str,
    ) {
        let id = row.attestation_id.clone();
        let e = put(b, row).await.expect_err(why);
        assert_eq!(e.kind(), kind, "{why}: {e}");
        assert!(
            b.get_attestation(&id).await.unwrap().is_none(),
            "{why}: a refused row is not stored"
        );
    }

    /// **I703** — settlement rows admit from the payer, on the private and the
    /// public arm, and the payee's counter-attestation admits.
    pub async fn i703_settlement_admits_on_both_arms<B: FederationDirectory + Sync>(
        b: &B,
        s: &str,
    ) {
        let payer = who(b, &format!("i703-payer-{s}")).await;
        let payee = who(b, &format!("i703-payee-{s}")).await;
        let settlement = |dim: &str| {
            serde_json::json!({
                "dimension": dim,
                "score": 1,
                "confidence": 1,
                "subject_kind": "settlement",
                "settled_action_ref": format!("contribution-{s}"),
                "rail": "base:usdc",
                "settlement_ref":
                    "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
                "amount_commitment": "12.50",
            })
        };
        for scope in [cohort_scope::SELF, cohort_scope::FEDERATION] {
            let r = signed(
                &payer,
                input("scores", scope, settlement("settlement:paid:v1")),
            )
            .await;
            let id = r.attestation_id.clone();
            put(b, r)
                .await
                .unwrap_or_else(|e| panic!("I703 a {scope} settlement:paid:v1 row admits: {e}"));
            assert!(
                b.get_attestation(&id).await.unwrap().is_some(),
                "I703 {scope}"
            );
        }
        let r = signed(
            &payee,
            input(
                "scores",
                cohort_scope::SELF,
                settlement("settlement:received:paid:v1"),
            ),
        )
        .await;
        put(b, r)
            .await
            .unwrap_or_else(|e| panic!("I703 the payee's counter-attestation admits: {e}"));
    }

    /// **I704** — a payment-processor identifier anywhere in a settlement
    /// envelope is refused, on either arm.
    pub async fn i704_settlement_refuses_processor_ids<B: FederationDirectory + Sync>(
        b: &B,
        s: &str,
    ) {
        let payer = who(b, &format!("i704-payer-{s}")).await;
        for (scope, field, value) in [
            (cohort_scope::SELF, "settlement_ref", "ch_3NkQ2bL7x9"),
            (cohort_scope::FEDERATION, "note", "cus_Q1w2e3r4"),
        ] {
            let mut env = serde_json::json!({
                "dimension": "settlement:paid:v1",
                "score": 1,
                "confidence": 1,
                "rail": "x402",
                "settled_action_ref": format!("contribution-{s}"),
            });
            env[field] = serde_json::json!(value);
            let r = signed(&payer, input("scores", scope, env)).await;
            refused(
                b,
                r,
                "federation_payment_processor_identifier",
                "I704 a settlement row carries no payment-processor identifier",
            )
            .await;
        }
        // The scan is the settlement family's: the same token on an ordinary
        // dimension is not this gate's business.
        let r = signed(
            &payer,
            input(
                "scores",
                cohort_scope::FEDERATION,
                serde_json::json!({
                    "dimension": "chat:message:v1",
                    "score": 1, "confidence": 1, "note": "ch_3NkQ2bL7x9",
                }),
            ),
        )
        .await;
        put(b, r)
            .await
            .expect("I704 the processor scan reaches settlement rows only");
    }

    /// **I705** — the ledger family graduated: the owner's row admits, a
    /// stranger's row about the owner is refused, a foreign id is refused.
    pub async fn i705_ledger_owner_rule<B: FederationDirectory + Sync>(b: &B, s: &str) {
        let owner = who(b, &format!("i705-owner-{s}")).await;
        let stranger = who(b, &format!("i705-stranger-{s}")).await;
        let lid = crate::ledgers::standard::derive_ledger_id(&owner.key, "usd", "1").unwrap();
        let head = |id: &str| {
            serde_json::json!({
                "dimension": "ledger:head:usd:v1",
                "score": 1, "confidence": 1,
                "ledger_id": id, "sequence": 7,
            })
        };
        let r = signed(
            &owner,
            input("scores", cohort_scope::FEDERATION, head(&lid)),
        )
        .await;
        let id = r.attestation_id.clone();
        put(b, r)
            .await
            .unwrap_or_else(|e| panic!("I705 the owner's ledger:head row admits: {e}"));
        assert!(b.get_attestation(&id).await.unwrap().is_some());

        let mut i = input("scores", cohort_scope::FEDERATION, head(&lid));
        i.attested_key_id = Some(owner.key.clone());
        let r = signed(&stranger, i).await;
        refused(
            b,
            r,
            "federation_signer_not_acting_for",
            "I705 a ledger row by a key that does not act for its owner",
        )
        .await;

        let r = signed(
            &owner,
            input(
                "scores",
                cohort_scope::FEDERATION,
                head("ledger-not-derived"),
            ),
        )
        .await;
        refused(
            b,
            r,
            "federation_dimension_rejected",
            "I705 the L1 binding refuses a foreign ledger_id",
        )
        .await;
    }

    /// **I706** — the dimensions rc7 opens and persist holds shut.
    pub async fn i706_held_dimensions_refused<B: FederationDirectory + Sync>(b: &B, s: &str) {
        let w = who(b, &format!("i706-{s}")).await;
        for dim in [
            "key_grant:content:v1",
            "key_grant:epoch:v1",
            "key_grant:stream:v1",
            "membership:widening:v1",
            "membership:removal:v1",
            "membership:resignation:v1",
        ] {
            for t in ["scores", "delegates_to"] {
                let mut i = input(
                    t,
                    cohort_scope::FEDERATION,
                    serde_json::json!({"dimension": dim, "score": 1, "confidence": 1}),
                );
                if t == "delegates_to" {
                    i.attested_key_id = Some(w.key.clone());
                }
                let r = signed(&w, i).await;
                let id = r.attestation_id.clone();
                let e = put(b, r)
                    .await
                    .expect_err("I706 a held dimension is refused");
                assert!(
                    matches!(
                        &e,
                        crate::federation::Error::DimensionRejected { reason, .. }
                            if *reason
                                == crate::federation::admission::REGISTERED_FAMILY_HELD_SHUT_REASON
                    ),
                    "I706 {t} {dim}: {e}"
                );
                assert!(b.get_attestation(&id).await.unwrap().is_none());
            }
        }
    }

    #[cfg(test)]
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                fn suffix() -> String {
                    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
                }
                #[tokio::test]
                async fn i703() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i703_settlement_admits_on_both_arms(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i704() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i704_settlement_refuses_processor_ids(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i705() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i705_ledger_owner_rule(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i706() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i706_held_dimensions_refused(&b, &suffix()).await
                }
            }
        };
    }
    runners!(memory, async { Some(crate::store::MemoryBackend::new()) });
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
