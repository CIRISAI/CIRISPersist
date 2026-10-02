//! CIRISPersist#975 (CC 2.4, "The row-type slot is closed") — I370–I379.
//!
//! The gate ships REPORTING (`row_type::ROW_TYPE_ENFORCEMENT = Report`), so
//! every refusal witness runs its door under
//! [`with_enforcement`](super::row_type::with_enforcement)`(Enforce, …)` — the
//! branch a later release turns on must be the branch measured now — and every
//! report witness runs it under the shipped constant.
//!
//! - **I370** an unregistered type is refused at the local put, the replication
//!   apply and the emit under `Enforce`; nothing is stored.
//! - **I371** CC's 39 `row_type_vectors` replay through [`classify`].
//! - **I372** the carrier shape: every violation refused (always enforced);
//!   today's `holds_bytes` and `key_grant` rows satisfy it.
//! - **I373** a carrier token is never a `dimension`.
//! - **I374** the dimension gate follows the dimension onto the four composers
//!   (CC 2.4 ask 3): refused under `Enforce`, counted under `Report`; persist's
//!   own composer dimensions admit.
//! - **I375** under `Report` an unregistered type admits, is served, and is
//!   counted by stem.
//! - **I376** a held unregistered row is not served or replicated under
//!   `Enforce`, IS reported, and is not deleted; the SQL predicate agrees with
//!   [`classify`] on every vector, per dialect.
//! - **I377** age and capacity assurance resolve identically from the legacy
//!   type-slot shape and from `scores` + `dimension`; the subject-must-not-emit
//!   rule holds on the dimension.
//! - **I378** from disk: the gate sits beside the binding at every door, and
//!   both serve reads carry the filter on every backend.
//! - **I379** the baked genesis bundle uses registered types only.
//!
//! [`classify`]: super::row_type::classify

#[cfg(test)]
mod pure {
    use crate::federation::admission::DimensionAdmissionPolicy;
    use crate::federation::namespace::registry;
    use crate::federation::row_type::{
        carrier_shape_violation, check_row_type, classify, with_enforcement, CarrierShapeViolation,
        RowTypeClass, RowTypeEnforcement, ATTESTATION_TYPE_UNREGISTERED,
    };
    use crate::federation::types::attestation_type::{DELEGATES_TO, SUPERSEDES, WITHDRAWS};
    use crate::federation::Attestation;

    fn vectors() -> Vec<serde_json::Value> {
        let v: serde_json::Value =
            serde_json::from_str(crate::federation::namespace::matcher::VECTORS_JSON).unwrap();
        v["row_type_vectors"].as_array().unwrap().clone()
    }

    /// I371 — CC's reference classes, byte for byte.
    #[test]
    fn i371_cc_row_type_vectors_replay() {
        let vs = vectors();
        assert_eq!(vs.len(), 39, "CC rc6 publishes 39 row-type vectors");
        assert_eq!(
            registry::row_types().unwrap().refusal,
            ATTESTATION_TYPE_UNREGISTERED,
            "the refusal token is CC's"
        );
        for v in vs {
            let t = v["attestation_type"].as_str().unwrap();
            let got = match classify(t) {
                RowTypeClass::Structural => Some("structural"),
                RowTypeClass::Carrier(_) => Some("carrier"),
                RowTypeClass::Unregistered => None,
            };
            assert_eq!(got, v["class"].as_str(), "{t:?}: {}", v["why"]);
            assert_eq!(
                got.is_none(),
                v["refusal"] == ATTESTATION_TYPE_UNREGISTERED,
                "{t:?}"
            );
            if let RowTypeClass::Carrier(c) = classify(t) {
                assert_eq!(Some(c.token.as_str()), v["name"].as_str(), "{t:?}");
            }
        }
        // Beyond CC's list: the design's own probes.
        for t in [
            "foo",
            "scores ",
            " scores",
            "key_grant:epoch:v2",
            "consent",
            "watchlist_config",
        ] {
            assert_eq!(classify(t), RowTypeClass::Unregistered, "{t:?}");
        }
    }

    fn row(attestation_type: &str, envelope: serde_json::Value) -> Attestation {
        let now = chrono::Utc::now();
        Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: "k".into(),
            attested_key_id: "k".into(),
            attestation_type: attestation_type.into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: String::new(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![],
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: vec![],
        }
    }

    /// I372 — every part of the carrier shape, and today's real rows.
    #[test]
    fn i372_carrier_shape() {
        let hb = crate::federation::blobs::holds_bytes_attestation_row(
            &[7u8; 32],
            "holder",
            "hb-1",
            chrono::Utc::now(),
            3,
        );
        assert_eq!(check_row_type(&hb).unwrap(), classify(&hb.attestation_type));
        assert!(matches!(
            classify(&hb.attestation_type),
            RowTypeClass::Carrier(_)
        ));

        let kg = "key_grant:epoch:v1";
        let ok = || {
            row(
                kg,
                serde_json::json!({"kind": "key_grant", "axis": "epoch"}),
            )
        };
        let RowTypeClass::Carrier(c) = classify(kg) else {
            panic!("key_grant:epoch:v1 is a carrier")
        };
        assert_eq!(carrier_shape_violation(&ok(), c), None);

        let cases: Vec<(Attestation, CarrierShapeViolation)> = vec![
            (
                {
                    let mut r = ok();
                    r.attested_key_id = "other".into();
                    r
                },
                CarrierShapeViolation::NotSelfAttested,
            ),
            (
                row(kg, serde_json::json!({"kind": "holds_bytes"})),
                CarrierShapeViolation::KindDisagrees,
            ),
            (
                row(kg, serde_json::json!({})),
                CarrierShapeViolation::KindDisagrees,
            ),
            (
                row(
                    kg,
                    serde_json::json!({"kind": "key_grant", "dimension": "x:v1"}),
                ),
                CarrierShapeViolation::CarriesDimension,
            ),
            (
                row(kg, serde_json::json!({"kind": "key_grant", "score": 1})),
                CarrierShapeViolation::CarriesScore,
            ),
            (
                row(
                    kg,
                    serde_json::json!({"kind": "key_grant", "confidence": 1}),
                ),
                CarrierShapeViolation::CarriesConfidence,
            ),
            (
                {
                    let mut r = ok();
                    r.weight = Some(0.5);
                    r
                },
                CarrierShapeViolation::CarriesWeight,
            ),
            (
                {
                    let mut r = ok();
                    r.subject_key_ids = vec!["s".into()];
                    r
                },
                CarrierShapeViolation::CarriesSubjects,
            ),
        ];
        for (r, want) in cases {
            assert_eq!(carrier_shape_violation(&r, c), Some(want));
            // Enforced in BOTH modes — the shape is not behind the switch.
            let e = check_row_type(&r).expect_err("a malformed carrier is refused");
            assert_eq!(e.kind(), "federation_carrier_row_malformed");
            assert!(e.to_string().contains(want.as_str()), "{e}");
        }
        // A structural row carries whatever its own gates allow.
        assert!(check_row_type(&row("scores", serde_json::json!({"dimension": "x:v1"}))).is_ok());
    }

    /// I372 — the real key-grant emit input (all three axes) assembles into a
    /// carrier of the right shape: what `KeyGrantSet::emit_input` builds is
    /// what the gate admits.
    #[test]
    fn i372_key_grant_emit_input_is_a_carrier() {
        for t in [
            "key_grant:epoch:v1",
            "key_grant:content:v1",
            "key_grant:stream:v1",
        ] {
            let RowTypeClass::Carrier(c) = classify(t) else {
                panic!("{t} is a registered carrier")
            };
            assert_eq!(
                c.kind,
                crate::federation::key_grant::KEY_GRANT_ENVELOPE_KIND
            );
        }
        assert!(matches!(
            classify(&crate::federation::holds_bytes_attestation_type(&[0xab; 32])),
            RowTypeClass::Carrier(c) if c.kind == "holds_bytes"
        ));
    }

    /// I374 — the composer dimension gate, as the put doors call it.
    #[tokio::test]
    async fn i374_composer_dimension_gate_follows_the_dimension() {
        let p = DimensionAdmissionPolicy::default();
        // Persist's own composer dimensions admit under ENFORCE.
        with_enforcement(RowTypeEnforcement::Enforce, async {
            for (t, d) in [
                (DELEGATES_TO, "self:delegates_to:v1"),
                (DELEGATES_TO, "self:delegates_to:agent_occurrence:v1"),
                (DELEGATES_TO, "ownership:responsible_party:node:v1"),
                (DELEGATES_TO, "trust:charter:v1"),
                (DELEGATES_TO, "trust:confers:v1"),
                (DELEGATES_TO, "trust:accepts:v1"),
            ] {
                p.check(t, Some(d), "user")
                    .unwrap_or_else(|e| panic!("{t} {d}: {e}"));
            }
            // No dimension: untouched, on every composer.
            for t in [DELEGATES_TO, SUPERSEDES, WITHDRAWS, "recants"] {
                p.check(t, None, "user").unwrap();
                p.check(t, Some("  "), "user").unwrap();
            }
            // A reserved dimension from an unauthorized emitter is refused.
            let e = p
                .check(DELEGATES_TO, Some("system:health:v1"), "user")
                .expect_err("ask 3: the reserved-prefix rule follows the dimension");
            assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
            let e = p
                .check(SUPERSEDES, Some("accord:human_dignity:v1"), "agent")
                .expect_err("accord:* needs an accord holder on any type");
            assert_eq!(
                e.kind(),
                "federation_accord_dimension_requires_accord_holder"
            );
            let e = p
                .check(WITHDRAWS, Some("delegation:duty"), "user")
                .expect_err("the version tail is required on a composer's dimension too");
            assert_eq!(e.kind(), "federation_dimension_rejected");
            // A carrier or an unregistered type is not asked here.
            p.check("key_grant:epoch:v1", Some("system:health:v1"), "user")
                .unwrap();
            p.check("consent", Some("system:health:v1"), "user")
                .unwrap();
        })
        .await;
        // Under the shipped REPORT setting the same refusal is counted, not raised.
        let before = composer_count("delegates_to:federation_reserved_prefix_emitter_mismatch");
        p.check(DELEGATES_TO, Some("system:health:v1"), "user")
            .expect("v53 reports ask 3");
        assert!(
            composer_count("delegates_to:federation_reserved_prefix_emitter_mismatch") > before,
            "the report counts what enforcement would refuse"
        );
    }

    fn composer_count(label: &str) -> u64 {
        crate::federation::row_type::composer_dimension_would_refuse_total()
            .into_iter()
            .find(|(l, _)| l == label)
            .map_or(0, |(_, n)| n)
    }

    /// I376 (sqlite) — the generated SQL predicate agrees with [`classify`] on
    /// every CC vector and on the design's probes.
    #[cfg(feature = "sqlite")]
    #[test]
    fn i376_sqlite_predicate_agrees_with_the_classifier() {
        use crate::federation::row_type::registered_row_type_sql;
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let pred = registered_row_type_sql("t", crate::federation::row_type::SqlDialect::Sqlite);
        let mut probes: Vec<String> = vectors()
            .iter()
            .map(|v| v["attestation_type"].as_str().unwrap().to_owned())
            .collect();
        probes.extend(
            [
                "holds_bytes:sha256:0a1b2c3d4e5f6a7b",
                "holds_bytes:sha256:0a1b2c3d\r",
                "consent",
                "key_grant:stream:v1x",
                "xkey_grant:stream:v1",
            ]
            .map(str::to_owned),
        );
        for t in probes {
            let sql_says: bool = conn
                .query_row(&format!("SELECT {pred} FROM (SELECT ?1 AS t)"), [&t], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(
                sql_says,
                classify(&t) != RowTypeClass::Unregistered,
                "{t:?} under {pred}"
            );
        }
    }

    /// I378 — from disk. The gate sits beside the binding at the three put
    /// doors; the promotion door, the emit mint and the local doors ask it; both
    /// serve reads filter on every backend.
    #[test]
    fn i378_the_gate_is_wired_at_every_door() {
        fn strip(src: &str) -> String {
            src.lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n")
        }
        fn body<'a>(src: &'a str, open: &str) -> &'a str {
            let i = src.find(open).unwrap_or_else(|| panic!("{open} not found"));
            let rest = &src[i..];
            let end = rest[1..]
                .find("\n    async fn ")
                .map_or(rest.len(), |j| j + 1);
            &rest[..end]
        }
        for (name, src) in [
            ("memory", include_str!("../store/memory.rs")),
            ("sqlite", include_str!("../store/sqlite.rs")),
            ("postgres", include_str!("../store/postgres.rs")),
        ] {
            let s = strip(src);
            let put = body(&s, "async fn put_attestation_with_origin(");
            let bind = "crate::federation::admission::check_row_column_binding(&row)?;";
            let gate = "crate::federation::row_type::admit_row_type(&row)?;";
            let after_bind = put
                .split(bind)
                .nth(1)
                .unwrap_or_else(|| panic!("{name}: the put door binds the row"));
            assert!(
                after_bind.trim_start().starts_with(gate),
                "{name}: the row-type gate must sit IMMEDIATELY after the binding (#975)"
            );
            for read in [
                "async fn list_attestations_since(",
                "async fn list_attestation_log(",
            ] {
                let b = body(&s, read);
                assert!(
                    b.contains("row_type::serve_filter_sql")
                        || b.contains("row_type::served_under_enforcement"),
                    "{name} {read}: the serve read carries the row-type filter"
                );
            }
        }
        let adm = strip(include_str!("admission.rs"));
        let promo = body(&adm, "pub async fn check_promotion_admission(");
        assert!(
            promo.contains("row_type::check_row_type(row)?"),
            "the promotion door"
        );
        let local = body(&adm, "pub fn check_local_tier_eligibility(");
        assert!(
            local.contains("row_type::admit_local_row_type(attestation_type)?"),
            "the local doors"
        );
        let emit = strip(include_str!("attestation_emit.rs"));
        assert!(
            body(&emit, "pub fn assemble(").contains("row_type::check_row_type(&row)?"),
            "the emit mint"
        );
        // The gate names no row type: the registry is the list.
        let gate = strip(include_str!("row_type.rs"));
        for lit in [
            "\"holds_bytes",
            "\"key_grant",
            "\"delegates_to\"",
            "\"withdraws\"",
        ] {
            assert!(
                !gate.contains(lit),
                "row_type.rs spells {lit} — read the registry instead"
            );
        }
    }

    /// I379 — the baked bundles carry registered types only, so the gate
    /// cannot refuse the seed under either setting.
    #[test]
    fn i379_the_baked_bundles_use_registered_types() {
        for (name, src) in [
            (
                "canonical_seed",
                include_str!("genesis/canonical_seed.json"),
            ),
            (
                "prior_ceremony_delegation_rows",
                include_str!("genesis/prior_ceremony_delegation_rows.json"),
            ),
            (
                "accord_holder_seed",
                include_str!("genesis/accord_holder_seed.json"),
            ),
        ] {
            let v: serde_json::Value = serde_json::from_str(src).unwrap();
            let mut seen = 0;
            walk(&v, &mut |t| {
                seen += 1;
                assert_ne!(classify(t), RowTypeClass::Unregistered, "{name}: {t:?}");
            });
            let _ = seen;
        }
        fn walk(v: &serde_json::Value, f: &mut dyn FnMut(&str)) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, x) in m {
                        if k == "attestation_type" {
                            if let Some(t) = x.as_str() {
                                f(t);
                            }
                        }
                        walk(x, f);
                    }
                }
                serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, f)),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_emit::{
        assemble, emit_with_local_signer, stamp_and_canonicalize,
    };
    use crate::federation::envelope::EnvelopeCore;
    use crate::federation::row_type::{with_enforcement, RowTypeEnforcement};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{EmitAttestationInput, SignedAttestation};
    use crate::federation::{Attestation, FederationDirectory};

    const ENFORCE: RowTypeEnforcement = RowTypeEnforcement::Enforce;

    pub(crate) struct Who {
        pub signer: std::sync::Arc<crate::signing::LocalSigner>,
        pub key: String,
    }

    pub(crate) async fn who<B: FederationDirectory + Sync>(b: &B, alias: &str, role: &str) -> Who {
        let signer = ts::local_signer(alias);
        let key = signer.derived_key_id();
        ts::register_hybrid_key_as(b, &key, alias, role).await;
        Who { signer, key }
    }

    fn input(t: &str, env: serde_json::Value) -> EmitAttestationInput {
        EmitAttestationInput::with_envelope(
            t,
            EnvelopeCore::from_value(env).unwrap(),
            crate::federation::types::cohort_scope::FEDERATION,
        )
    }

    /// A signed row of any type, assembled under the shipped (Report) setting —
    /// the shape a peer that never ran the gate would send.
    async fn signed(w: &Who, mut i: EmitAttestationInput) -> Attestation {
        let canonical = stamp_and_canonicalize(&mut i, &w.key, chrono::Utc::now()).unwrap();
        let sig = w.signer.sign_hybrid(&canonical).await.unwrap();
        assemble(w.key.clone(), &canonical, sig, i).unwrap().0
    }

    fn admitted_count(stem: &str) -> u64 {
        crate::federation::row_type::unregistered_admitted_total()
            .into_iter()
            .find(|(l, _)| l == stem)
            .map_or(0, |(_, n)| n)
    }

    /// The types I370 probes. Each is unregistered; the last two sit under a
    /// carrier stem.
    const PROBES: [&str; 5] = [
        "foo",
        "scores ",
        "SCORES",
        "key_grant:epoch:v2",
        "holds_bytes:sha256:0A1B2C3D",
    ];

    /// **I370** — refused at the local put, the replication apply and the emit
    /// under `Enforce`; nothing stored.
    pub async fn i370_unregistered_refused_at_every_door<B: FederationDirectory + Sync>(
        b: &B,
        s: &str,
    ) {
        let w = who(b, &format!("i370-{s}"), USER).await;
        for (n, t) in PROBES.iter().enumerate() {
            // `size` so the media-source gate (CC 5.3.2.5), which reads any
            // `holds_bytes`-prefixed type, has nothing to say first.
            let r = signed(
                &w,
                input(
                    t,
                    serde_json::json!({"id": format!("i370-{s}-{n}"), "size": 3}),
                ),
            )
            .await;
            let id = r.attestation_id.clone();
            for authored in [true, false] {
                let row = SignedAttestation {
                    attestation: r.clone(),
                };
                let e = with_enforcement(ENFORCE, async {
                    if authored {
                        b.put_attestation_authored(row).await
                    } else {
                        b.put_attestation(row).await
                    }
                })
                .await
                .expect_err("an unregistered type is refused under enforcement");
                assert_eq!(
                    e.kind(),
                    "federation_attestation_type_unregistered",
                    "{t:?}: {e}"
                );
            }
            assert!(
                b.get_attestation(&id).await.unwrap().is_none(),
                "{t:?}: nothing stored"
            );
            let e = with_enforcement(
                ENFORCE,
                emit_with_local_signer(
                    b,
                    &w.signer,
                    input(t, serde_json::json!({"id": "x", "size": 3})),
                ),
            )
            .await
            .expect_err("the emit mint refuses it too");
            assert_eq!(
                e.kind(),
                "federation_attestation_type_unregistered",
                "{t:?}"
            );
        }
    }

    /// **I372 (door)** — a carrier of the wrong shape is refused where it is
    /// minted (the emit recipe) and at the put door, under the SHIPPED setting:
    /// the shape is not behind the switch.
    pub async fn i372_malformed_carrier_refused<B: FederationDirectory + Sync>(b: &B, s: &str) {
        let w = who(b, &format!("i372-{s}"), USER).await;
        let bad = || {
            input(
                "key_grant:epoch:v1",
                serde_json::json!({"kind": "key_grant", "dimension": "x:v1"}),
            )
        };
        let e = emit_with_local_signer(b, &w.signer, bad())
            .await
            .expect_err("the mint refuses the shape");
        assert_eq!(e.kind(), "federation_carrier_row_malformed");
        // A peer's row of the same shape: built past the mint, offered to the
        // replication door.
        let mut i = bad();
        let canonical = stamp_and_canonicalize(&mut i, &w.key, chrono::Utc::now()).unwrap();
        let sig = w.signer.sign_hybrid(&canonical).await.unwrap();
        let mut row = with_enforcement(RowTypeEnforcement::Report, async {
            // `assemble` refuses it, so take the row the well-formed twin
            // assembles and graft the claim member into the envelope BEFORE the
            // mirror is stamped — the shape a non-persist producer would send.
            let mut ok = input(
                "key_grant:epoch:v1",
                serde_json::json!({"kind": "key_grant"}),
            );
            let c = stamp_and_canonicalize(&mut ok, &w.key, chrono::Utc::now()).unwrap();
            let sg = w.signer.sign_hybrid(&c).await.unwrap();
            assemble(w.key.clone(), &c, sg, ok).unwrap().0
        })
        .await;
        let _ = (canonical, sig);
        row.attestation_envelope["dimension"] = serde_json::json!("x:v1");
        let id = row.attestation_id.clone();
        let e = b
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("the put door refuses a malformed carrier");
        assert_eq!(e.kind(), "federation_carrier_row_malformed", "{e}");
        assert!(b.get_attestation(&id).await.unwrap().is_none());
    }

    /// **I373** — a carrier token is never a dimension. On `scores` it is
    /// refused under the shipped setting (R2(b) gates `key_grant:`; the
    /// `holds_bytes` token has no version tail). On a composer `key_grant:` is
    /// refused by R2(b) always, and the `holds_bytes` token by the ask-3
    /// dimension gate, so under `Enforce`.
    pub async fn i373_carrier_token_is_not_a_dimension<B: FederationDirectory + Sync>(
        b: &B,
        s: &str,
    ) {
        let w = who(b, &format!("i373-{s}"), USER).await;
        for dim in ["key_grant:epoch:v1", "holds_bytes:sha256:0a1b2c3d"] {
            for t in ["scores", "delegates_to"] {
                let mut i = input(
                    t,
                    serde_json::json!({"dimension": dim, "score": 1, "confidence": 1}),
                );
                if t == "delegates_to" {
                    i.attested_key_id = Some(w.key.clone());
                }
                let r = signed(&w, i).await;
                let e = with_enforcement(
                    ENFORCE,
                    b.put_attestation(SignedAttestation { attestation: r }),
                )
                .await
                .expect_err("a carrier token is never a dimension");
                assert!(
                    matches!(
                        e.kind(),
                        "federation_namespace_family_unregistered"
                            | "federation_dimension_rejected"
                    ),
                    "{t} {dim}: {e}"
                );
            }
        }
        // `scores` refuses both under the SHIPPED setting.
        for dim in ["key_grant:epoch:v1", "holds_bytes:sha256:0a1b2c3d"] {
            let r = signed(
                &w,
                input(
                    "scores",
                    serde_json::json!({"dimension": dim, "score": 1, "confidence": 1}),
                ),
            )
            .await;
            b.put_attestation(SignedAttestation { attestation: r })
                .await
                .expect_err("scores: a carrier token is never a dimension");
        }
    }

    /// **I375 + I376** — under `Report` an unregistered row admits, is served
    /// and counted; under `Enforce` the held row is neither served nor
    /// replicated, IS reported, and is not deleted.
    pub async fn i375_i376_report_then_withhold<B: FederationDirectory + Sync>(b: &B, s: &str) {
        let w = who(b, &format!("i375-{s}"), USER).await;
        let t = "zz_i375_unregistered";
        let before = admitted_count(t);
        let r = signed(&w, input(t, serde_json::json!({"id": format!("i375-{s}")}))).await;
        let id = r.attestation_id.clone();
        b.put_attestation(SignedAttestation { attestation: r })
            .await
            .expect("I375: v53 admits an unregistered type and reports it");
        assert!(admitted_count(t) > before, "I375: counted by stem");

        let served = |v: Vec<crate::federation::ServedAttestation>| {
            v.iter().any(|a| a.attestation.attestation_id == id)
        };
        let logged = |p: crate::read::ScoresPage| p.items.iter().any(|a| a.attestation_id == id);
        assert!(
            served(b.list_attestations_since(None, 10_000).await.unwrap()),
            "I375: served"
        );
        assert!(
            logged(b.list_attestation_log(None, None, 10_000).await.unwrap()),
            "I375: replicable"
        );

        with_enforcement(ENFORCE, async {
            assert!(
                !served(b.list_attestations_since(None, 10_000).await.unwrap()),
                "I376: not served under enforcement"
            );
            assert!(
                !logged(b.list_attestation_log(None, None, 10_000).await.unwrap()),
                "I376: not replicated under enforcement"
            );
            // A registered row on the same plane still is.
            let ok = signed(
                &w,
                input(
                    "scores",
                    serde_json::json!({"dimension": "i376:probe:v1", "score": 1, "confidence": 1}),
                ),
            )
            .await;
            let ok_id = ok.attestation_id.clone();
            b.put_attestation(SignedAttestation { attestation: ok })
                .await
                .unwrap();
            assert!(
                b.list_attestations_since(None, 10_000)
                    .await
                    .unwrap()
                    .iter()
                    .any(|a| a.attestation.attestation_id == ok_id),
                "I376: the filter withholds only the unregistered type"
            );
            let report = crate::federation::row_type::row_type_report(b.as_dyn_directory())
                .await
                .unwrap();
            assert_eq!(report.enforcement, "enforce");
            let held = report
                .held_unregistered
                .iter()
                .find(|h| h.attestation_type == t)
                .expect("I376: the held row is reported");
            assert_eq!((held.count, held.type_stem.as_str()), (1, t));
            assert!(
                !report
                    .held_unregistered
                    .iter()
                    .any(|h| h.attestation_type == "scores"),
                "only unregistered types are reported"
            );
        })
        .await;
        assert!(
            b.get_attestation(&id).await.unwrap().is_some(),
            "I376: never deleted"
        );
    }

    /// **I377** — age and capacity assurance from both shapes. The witness
    /// holds a conferred `infra:attest:assurance` scope (the runner seeds it);
    /// the subject-must-not-emit rule binds the dimension shape too.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i377_assurance_reads_both_shapes<B: FederationDirectory + Sync>(
        b: &B,
        w: &Who,
        s: &str,
    ) {
        use crate::federation::age::{age_band, AgeBand};
        use crate::federation::capacity::{capacity_state, CapacityState};
        let legacy = who(b, &format!("i377-legacy-{s}"), USER).await;
        let modern = who(b, &format!("i377-modern-{s}"), USER).await;
        let age = "age_assurance:government:adult:v1";
        let cap = "capacity_assurance:panel:financial:incapacitated:v1";
        for tok in [age, cap] {
            // Legacy: the token IS the type.
            let mut i = input(tok, serde_json::json!({"id": format!("{tok}-{s}-l")}));
            i.attested_key_id = Some(legacy.key.clone());
            emit_with_local_signer(b, &w.signer, i)
                .await
                .unwrap_or_else(|e| panic!("legacy {tok}: {e}"));
            // CC 2.4: `scores` + dimension.
            let mut i = input(
                "scores",
                serde_json::json!({"dimension": tok, "score": 1, "confidence": 1}),
            );
            i.attested_key_id = Some(modern.key.clone());
            emit_with_local_signer(b, &w.signer, i)
                .await
                .unwrap_or_else(|e| panic!("scores {tok}: {e}"));
        }
        let d = b.as_dyn_directory();
        for k in [&legacy.key, &modern.key] {
            assert_eq!(
                age_band(d, k).await.unwrap(),
                AgeBand::Adult,
                "I377 age {k}"
            );
            assert_eq!(
                capacity_state(d, k, "financial").await.unwrap(),
                CapacityState::Incapacitated,
                "I377 capacity {k}"
            );
        }
        // Subject-must-not-emit, on the dimension.
        for (tok, kind) in [
            (age, "federation_age_assurance_self_emission_rejected"),
            (cap, "federation_capacity_self_emission_rejected"),
        ] {
            let i = input(
                "scores",
                serde_json::json!({"dimension": tok, "score": 1, "confidence": 1}),
            );
            let e = emit_with_local_signer(b, &w.signer, i)
                .await
                .expect_err("a subject must not emit its own assurance in the scores shape");
            assert_eq!(e.kind(), kind, "{tok}");
        }
        // The whole rule follows the claim: a non-witness is refused.
        let mut i = input(
            "scores",
            serde_json::json!({"dimension": age, "score": 1, "confidence": 1}),
        );
        i.attested_key_id = Some(modern.key.clone());
        let e = emit_with_local_signer(b, &legacy.signer, i)
            .await
            .expect_err("only a conferred witness emits assurance");
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
        // ...and the role alone is not enough: a witness with NO conferred
        // `infra:attest:assurance` scope is refused on the dimension shape as
        // on the type shape (the rule's delegation-scope arm, not layer 1b).
        let bare = who(
            b,
            &format!("i377-bare-witness-{s}"),
            crate::federation::types::identity_type::WITNESS,
        )
        .await;
        for tok in [age, cap] {
            let mut i = input(
                "scores",
                serde_json::json!({"dimension": tok, "score": 1, "confidence": 1}),
            );
            i.attested_key_id = Some(modern.key.clone());
            let e = emit_with_local_signer(b, &bare.signer, i)
                .await
                .expect_err("the witness role without the conferred scope does not emit assurance");
            assert_eq!(
                e.kind(),
                "federation_reserved_prefix_emitter_mismatch",
                "{tok}"
            );
            assert!(e.to_string().contains("delegated scope"), "{tok}: {e}");
        }
    }

    /// The witness for I377, conferred `infra:attest:assurance` by a root
    /// `node` trusts. The runner has set `node` as the directory's node key.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn witness<B: FederationDirectory + Sync>(b: &B, node: &str, s: &str) -> Who {
        let w = who(
            b,
            &format!("i377-witness-{s}"),
            crate::federation::types::identity_type::WITNESS,
        )
        .await;
        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            b.as_dyn_directory(),
            node,
            &format!("i377-root-{s}"),
            &w.key,
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        w
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
                async fn i370() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i370_unregistered_refused_at_every_door(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i372_door() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i372_malformed_carrier_refused(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i373() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i373_carrier_token_is_not_a_dimension(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i375_i376() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i375_i376_report_then_withhold(&b, &suffix()).await
                }
                // The conferral fixture (`r2_test_support`) needs a SQL backend
                // feature; the memory runner rides along when one is built.
                #[cfg(any(feature = "sqlite", feature = "postgres"))]
                #[tokio::test]
                async fn i377() {
                    let Some(b) = $fresh.await else { return };
                    let s = suffix();
                    let node = format!("i377-node-{s}");
                    b.set_node_key_id(node.clone());
                    let w = bodies::witness(&b, &node, &s).await;
                    bodies::i377_assurance_reads_both_shapes(&b, &w, &s).await
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

/// I376 (postgres) — the generated predicate agrees with the classifier on
/// every vector, evaluated by the server.
#[cfg(all(test, feature = "postgres"))]
mod pg_predicate {
    use crate::federation::row_type::{
        classify, registered_row_type_sql, RowTypeClass, SqlDialect,
    };

    #[tokio::test]
    async fn i376_postgres_predicate_agrees_with_the_classifier() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(conn);
        let pred = registered_row_type_sql("t", SqlDialect::Postgres);
        let v: serde_json::Value =
            serde_json::from_str(crate::federation::namespace::matcher::VECTORS_JSON).unwrap();
        let mut probes: Vec<String> = v["row_type_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["attestation_type"].as_str().unwrap().to_owned())
            .collect();
        probes.extend(
            [
                "holds_bytes:sha256:0a1b2c3d4e5f6a7b",
                "consent",
                "key_grant:stream:v1x",
            ]
            .map(str::to_owned),
        );
        for t in probes {
            if t.contains('\0') {
                continue;
            }
            let row = client
                .query_one(
                    &format!("SELECT {pred} FROM (SELECT $1::text AS t) q"),
                    &[&t],
                )
                .await
                .unwrap();
            let sql_says: bool = row.get(0);
            assert_eq!(
                sql_says,
                classify(&t) != RowTypeClass::Unregistered,
                "{t:?} under {pred}"
            );
        }
    }
}
