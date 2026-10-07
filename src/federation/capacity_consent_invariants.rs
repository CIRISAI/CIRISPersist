//! CIRISPersist#1013 — I548: the consent-before-scoring gate and a scorer's
//! precheck ask ONE fold,
//! [`capacity_consent_stance`](super::consent_by_humans::capacity_consent_stance):
//! by principals (#857), scope `analyze:<family>` (#866 C1). Through v53.1.7
//! the gate folded the subject's own rows only, so the canonical's thirteen
//! agents — each consented by its steward on a row naming it in `for_key_id`,
//! nothing authored by the agent — passed Server's precheck and were refused
//! at emit. One body per invariant, generic over the directory, run on
//! memory, sqlite and postgres.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::admission::ConsentGatedFamily;
    use crate::federation::consent_by_humans as cbh;
    use crate::federation::consent_scope_invariants::bodies::{at, put, row, stance};
    use crate::federation::hard_case::ConsentState;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::{Attestation, FederationDirectory, IdentityOccurrence};

    /// The parties of one case: the canonical (attester, a node), the agent
    /// (subject), its steward (a user-role key the agent is an occurrence
    /// of), and a sibling machine the same steward also stewards.
    struct Parties {
        canonical: String,
        agent: String,
        steward: String,
        sibling: String,
    }

    async fn parties(d: &dyn FederationDirectory, tag: &str) -> Parties {
        let p = Parties {
            canonical: format!("i548-canon-{tag}"),
            agent: format!("i548-agent-{tag}"),
            steward: format!("i548-steward-{tag}"),
            sibling: format!("i548-sib-{tag}"),
        };
        ts::register_identity_key(d, &p.canonical, NODE).await;
        ts::register_identity_key(d, &p.agent, AGENT).await;
        ts::register_identity_key(d, &p.steward, USER).await;
        ts::register_identity_key(d, &p.sibling, AGENT).await;
        for machine in [&p.agent, &p.sibling] {
            d.put_identity_occurrence_local(IdentityOccurrence {
                identity_key_id: p.steward.clone(),
                occurrence_key_id: machine.clone(),
                device_class: "agent".to_owned(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .expect("occurrence row");
        }
        assert_eq!(
            crate::federation::admission::steward_bindings_of(d, &p.agent)
                .await
                .unwrap(),
            vec![p.steward.clone()],
            "I548 precondition: the steward stands behind the agent"
        );
        p
    }

    /// A `consent:state:<stance>:v1` row by `author` covering `attester`,
    /// scope `scope`, optionally FOR `for_key`, optionally expiring.
    #[allow(clippy::too_many_arguments)]
    fn consent(
        id: &str,
        author: &str,
        attester: &str,
        state: &str,
        scope: &str,
        for_key: Option<&str>,
        asserted: &str,
        expires: Option<&str>,
    ) -> Attestation {
        let extras = match for_key {
            Some(k) => serde_json::json!({ cbh::FOR_KEY_ID: k }),
            None => serde_json::json!({}),
        };
        stance(
            id,
            author,
            attester,
            state,
            serde_json::json!(scope),
            extras,
            asserted,
            expires,
        )
    }

    /// A third-party `capacity:*` score by `attester` about `subject` — the
    /// row the canonical's scorer emits.
    fn capacity_score(id: &str, attester: &str, subject: &str) -> Attestation {
        let asserted = at("2026-09-01T00:00:00Z");
        let env = serde_json::json!({"id": id, "dimension": "capacity:sustained_coherence:v1",
            "score": 0.8, "confidence": 0.9,
            crate::federation::envelope::paths::ASSERTED_AT: asserted.to_rfc3339()});
        let mut r = row(id, attester, subject, env, Vec::new(), asserted, None);
        r.weight = Some(0.8);
        ts::reseal(&mut r);
        r
    }

    /// The gate's verdict (`put_attestation` of the score) and the precheck's
    /// stance, side by side. A refusal must be the consent gate's own.
    async fn verdicts(d: &dyn FederationDirectory, p: &Parties, id: &str) -> (bool, ConsentState) {
        let gate = match put(d, capacity_score(id, &p.canonical, &p.agent)).await {
            Ok(()) => true,
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    "federation_consent_gate_refused",
                    "I548: refused by the consent gate, not another one: {e}"
                );
                false
            }
        };
        let stance = cbh::capacity_consent_stance(
            d,
            &p.canonical,
            &p.agent,
            ConsentGatedFamily::Capacity,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        (gate, stance)
    }

    /// **I548a — the production shape admits.** One row: authored by the
    /// user-role steward, attested to the canonical, `consent:state:granted:v1`,
    /// bare `analyze`, `for_key_id` = the agent, no expiry, nothing authored by
    /// the agent. Refused by the gate through v53.1.7.
    pub async fn i548a_the_stewards_grant_for_the_machine_admits(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let p = parties(d, &format!("a-{s}")).await;
        put(
            d,
            consent(
                &format!("i548a-g-{s}"),
                &p.steward,
                &p.canonical,
                "granted",
                "analyze",
                Some(&p.agent),
                "2026-08-01T00:00:00Z",
                None,
            ),
        )
        .await
        .expect("I548a: the steward's grant admits");
        assert_eq!(
            d.resolve_scoped_consent(&p.canonical, &p.agent, "analyze", None, chrono::Utc::now())
                .await
                .unwrap(),
            ConsentState::Unspecified,
            "I548a precondition: the subject-only fold sees nothing (the defect's input)"
        );
        let (gate, stance) = verdicts(d, &p, &format!("i548a-score-{s}")).await;
        assert_eq!(stance, ConsentState::Granted, "I548a: the precheck grants");
        assert!(
            gate,
            "I548a: the gate admits what the precheck grants (#1013)"
        );
    }

    /// **I548b — a grant narrowed to ANOTHER family is refused by both; one
    /// narrowed to THIS family is admitted by both.** The gate and the
    /// precheck ask `analyze:capacity`, never bare `analyze`.
    pub async fn i548b_the_family_narrowing_is_asked_by_both(d: &dyn FederationDirectory, s: &str) {
        let p = parties(d, &format!("b-{s}")).await;
        put(
            d,
            consent(
                &format!("i548b-trust-{s}"),
                &p.agent,
                &p.canonical,
                "granted",
                "analyze:trust",
                None,
                "2026-08-01T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        let (gate, stance) = verdicts(d, &p, &format!("i548b-score-trust-{s}")).await;
        assert!(!gate, "I548b: `analyze:trust` does not cover capacity");
        assert_ne!(
            stance,
            ConsentState::Granted,
            "I548b: …and the precheck agrees"
        );
        put(
            d,
            consent(
                &format!("i548b-cap-{s}"),
                &p.agent,
                &p.canonical,
                "granted",
                "analyze:capacity",
                None,
                "2026-08-01T00:00:01Z",
                None,
            ),
        )
        .await
        .unwrap();
        let (gate, stance) = verdicts(d, &p, &format!("i548b-score-cap-{s}")).await;
        assert_eq!(
            stance,
            ConsentState::Granted,
            "I548b: `analyze:capacity` covers the family the gate asks"
        );
        assert!(gate, "I548b: …and the gate admits it");
    }

    /// **I548c — the agreement matrix.** For every case, the gate's verdict
    /// equals `capacity_consent_stance == Granted`, and both equal the case's
    /// expected verdict.
    pub async fn i548c_gate_and_precheck_agree(d: &dyn FederationDirectory, s: &str) {
        // (case, expected admit, rows: (author, state, scope, for_key, asserted, expires))
        #[derive(Clone, Copy)]
        enum Who {
            Agent,
            Steward,
        }
        #[derive(Clone, Copy)]
        enum For {
            Nobody,
            Agent,
            Sibling,
        }
        type Seed = (
            Who,
            &'static str,
            &'static str,
            For,
            &'static str,
            Option<&'static str>,
        );
        let cases: &[(&str, bool, &[Seed])] = &[
            (
                "subject-only-grant",
                true,
                &[(
                    Who::Agent,
                    "granted",
                    "analyze",
                    For::Nobody,
                    "2026-08-01T00:00:00Z",
                    None,
                )],
            ),
            (
                "steward-only-grant",
                true,
                &[(
                    Who::Steward,
                    "granted",
                    "analyze",
                    For::Agent,
                    "2026-08-01T00:00:00Z",
                    None,
                )],
            ),
            (
                "steward-grant-for-another-machine",
                false,
                &[(
                    Who::Steward,
                    "granted",
                    "analyze",
                    For::Sibling,
                    "2026-08-01T00:00:00Z",
                    None,
                )],
            ),
            (
                "steward-revoke-plus-subject-grant",
                false,
                &[
                    (
                        Who::Agent,
                        "granted",
                        "analyze",
                        For::Nobody,
                        "2026-08-01T00:00:00Z",
                        None,
                    ),
                    (
                        Who::Steward,
                        "revoked",
                        "analyze",
                        For::Agent,
                        "2026-08-02T00:00:00Z",
                        None,
                    ),
                ],
            ),
            (
                "expired",
                false,
                &[(
                    Who::Steward,
                    "granted",
                    "analyze",
                    For::Agent,
                    "2026-08-01T00:00:00Z",
                    Some("2026-08-15T00:00:00Z"),
                )],
            ),
            (
                "narrowed-to-this-family",
                true,
                &[(
                    Who::Steward,
                    "granted",
                    "analyze:capacity",
                    For::Agent,
                    "2026-08-01T00:00:00Z",
                    None,
                )],
            ),
            (
                "narrowed-to-another-family",
                false,
                &[(
                    Who::Steward,
                    "granted",
                    "analyze:trust",
                    For::Agent,
                    "2026-08-01T00:00:00Z",
                    None,
                )],
            ),
        ];
        for (n, (case, expect, seeds)) in cases.iter().enumerate() {
            let p = parties(d, &format!("c{n}-{s}")).await;
            for (i, (who, state, scope, for_key, asserted, expires)) in seeds.iter().enumerate() {
                let author = match who {
                    Who::Agent => &p.agent,
                    Who::Steward => &p.steward,
                };
                let for_key = match for_key {
                    For::Nobody => None,
                    For::Agent => Some(p.agent.as_str()),
                    For::Sibling => Some(p.sibling.as_str()),
                };
                put(
                    d,
                    consent(
                        &format!("i548c-{n}-{i}-{s}"),
                        author,
                        &p.canonical,
                        state,
                        scope,
                        for_key,
                        asserted,
                        *expires,
                    ),
                )
                .await
                .unwrap_or_else(|e| panic!("I548c {case}: seed {i} admits: {e}"));
            }
            let (gate, stance) = verdicts(d, &p, &format!("i548c-score-{n}-{s}")).await;
            assert_eq!(
                gate,
                stance == ConsentState::Granted,
                "I548c {case}: the gate ({gate}) and the precheck ({stance:?}) disagree"
            );
            assert_eq!(gate, *expect, "I548c {case}: verdict (stance {stance:?})");
        }
    }

    /// **I548d — the refusal names the scope it asked.**
    pub async fn i548d_the_refusal_names_the_asked_scope(d: &dyn FederationDirectory, s: &str) {
        let p = parties(d, &format!("d-{s}")).await;
        let err = put(
            d,
            capacity_score(&format!("i548d-score-{s}"), &p.canonical, &p.agent),
        )
        .await
        .expect_err("I548d: no consent, no score");
        let msg = err.to_string();
        assert!(
            msg.contains("\"analyze:capacity\" scope"),
            "I548d: the refusal names `analyze:capacity`: {msg}"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i548a() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i548a_the_stewards_grant_for_the_machine_admits(&b, &super::suffix())
                        .await
                }
                #[tokio::test]
                async fn i548b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i548b_the_family_narrowing_is_asked_by_both(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i548c() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i548c_gate_and_precheck_agree(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i548d() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i548d_the_refusal_names_the_asked_scope(&b, &super::suffix()).await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
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

    /// **I548e — from disk: the gate, the Engine and the PyO3 door all reach
    /// the one fold.** A gate that folds the subject alone again, or a door
    /// that re-spells the walk, reds here before it reds in production.
    #[test]
    fn i548e_one_fold_every_door() {
        const ADM: &str = include_str!("admission.rs");
        const ENGINE: &str = include_str!("../engine.rs");
        const PYO3: &str = include_str!("../ffi/pyo3.rs");
        let strip = |body: &str| -> String {
            body.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let gate = ADM
            .split("pub async fn check_capacity_consent_admission(")
            .nth(1)
            .expect("gate");
        let gate = strip(&gate[..gate.find("\n}\n").expect("gate end")]);
        assert!(
            gate.contains("consent_by_humans::capacity_consent_stance("),
            "I548e: the gate asks the one fold"
        );
        assert!(
            !gate.contains("resolve_scoped_consent("),
            "I548e: the gate folds the subject alone again"
        );
        let e = ENGINE
            .split("pub async fn capacity_consent_stance(")
            .nth(1)
            .expect("Engine door");
        let e = strip(&e[..e.find("\n    }\n").expect("end")]);
        assert!(
            e.contains("consent_by_humans::capacity_consent_stance("),
            "I548e: the Engine door delegates to the module"
        );
        let py = PYO3
            .split("    fn capacity_consent_stance(")
            .nth(1)
            .expect("PyO3 door");
        let py = strip(&py[..py.find("\n    }\n").expect("end")]);
        assert!(
            py.contains("engine.capacity_consent_stance("),
            "I548e: the PyO3 mirror delegates to the Engine"
        );
    }
}
