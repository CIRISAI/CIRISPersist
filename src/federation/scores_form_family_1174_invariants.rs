//! v61.1.0 (CIRISPersist#1174, the v62 family census) — **I1590–I1596: a
//! `scores`-form row meets every gate its classic-form twin meets.**
//!
//! A family rides one of two forms: the classic form carries it in the
//! `attestation_type` slot (`health:liveness:v1`), the `scores` form in the
//! envelope `dimension` (`attestation_type = scores`, CC 2.4). Four gates
//! keyed on the type slot or a prefix string, so the `scores` form met none
//! of them. Each now asks [`row_type::claim_token`](super::row_type::claim_token).
//! Every leg below is run once per form, through the real `put_attestation`
//! door, and asserts the same verdict, the same refusal kind and the same
//! reason for both.
//!
//! - **I1590** (unit) the classifier: a `scores` row's family is its
//!   dimension, any other row's its type; a composer's verb names no family.
//! - **I1591** (sqlite, postgres) `health:liveness:` — a service attesting its
//!   own liveness is refused (`invariant_registry_self_emission_forbidden`); a
//!   monitor's row about another service is admitted.
//! - **I1592** (sqlite, postgres) `hard_case:` — an `agent` key is refused as
//!   the emitter; a `substrate_persist` key's row ABOUT ANOTHER PARTY is
//!   refused without `infra:record_hard_case` and, in the `scores` form, never
//!   reaches `hard_case_events`; a `substrate_persist` or `node` key's row about
//!   itself is admitted; with the conferral the third-party row is admitted and
//!   (scores form) projects with its signer as the emitter.
//! - **I1593** (sqlite, postgres) CC 3.4.3 substrate self-report — a
//!   `substrate_persist` key's `system:*` row about another key is refused
//!   (`substrate_self_report_names_another_party`); about itself it is
//!   admitted; an `agent` key about itself is refused as the emitter.
//! - **I1594** (sqlite, postgres) `trace_summary:` — a summary whose signer is
//!   not among its `subject_key_ids` is refused (`trace_dimension_invalid`);
//!   one naming its signer is admitted.
//! - **I1595** (unit) [`SUBSTRATE_SELF_REPORT_PREFIXES`](super::admission::SUBSTRATE_SELF_REPORT_PREFIXES)
//!   is exactly the rule table's `substrate_persist`-only rows, and the
//!   `hard_case:` arm's stem is the hard_case door's.
//! - **I1596** (unit) [`trace_family_token`](super::admission::trace_family_token):
//!   the family in either form, else the envelope dimension (the #473 reach
//!   over composers and typed rows is unchanged).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::steward_liveness_test_support::register;
    use crate::federation::hard_case::test_support::DeclaresNode;
    use crate::federation::hard_case::{self, HardCaseEvent, HardCaseFilter};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, cohort_scope, delegation_scope, identity_type as it,
    };
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    /// The two forms a family rides.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Form {
        /// The family in the `attestation_type` slot.
        Classic,
        /// `attestation_type = scores`, the family in the envelope `dimension`.
        Scores,
    }

    /// Both forms, in the order every leg runs them.
    pub(crate) const FORMS: [Form; 2] = [Form::Classic, Form::Scores];

    /// A sealed, federation-tier, self-scoped row of `family` in `form`, by
    /// `signer` about `about`, naming `subjects`, with `extra` merged into its
    /// envelope. The classic twin carries NO `dimension`, so its family is
    /// reachable through the type slot alone.
    pub(crate) fn row(
        form: Form,
        family: &str,
        signer: &str,
        about: &str,
        subjects: &[&str],
        extra: &serde_json::Value,
        id: Option<String>,
    ) -> Attestation {
        let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut env = serde_json::json!({ "id": id });
        if let Some(members) = extra.as_object() {
            for (k, v) in members {
                env[k.as_str()] = v.clone();
            }
        }
        if form == Form::Scores {
            env["dimension"] = serde_json::json!(family);
        }
        let mut r = ts::bare_attestation(&id, signer, about, &env);
        r.attestation_type = match form {
            Form::Classic => family.to_owned(),
            Form::Scores => attestation_type::SCORES.to_owned(),
        };
        r.weight = None;
        r.cohort_scope = cohort_scope::SELF.to_owned();
        r.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        ts::seal_row_in_place(signer, &mut r);
        r
    }

    async fn put(d: &dyn FederationDirectory, r: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .map(|_| ())
    }

    async fn held(d: &dyn FederationDirectory, id: &str) -> bool {
        d.get_attestation(id).await.expect("get").is_some()
    }

    /// `r` is refused with `kind`, the refusal names `needle`, and nothing is
    /// stored.
    async fn refused(
        d: &dyn FederationDirectory,
        r: Attestation,
        kind: &str,
        needle: &str,
        what: &str,
    ) {
        let id = r.attestation_id.clone();
        let err = put(d, r)
            .await
            .expect_err(&format!("{what}: must be refused"));
        assert_eq!(err.kind(), kind, "{what}: refused at the wrong gate: {err}");
        assert!(
            err.to_string().contains(needle),
            "{what}: the refusal must name {needle:?}: {err}"
        );
        assert!(!held(d, &id).await, "{what}: a refused row is not stored");
    }

    /// `r` is admitted and stored.
    async fn admitted(d: &dyn FederationDirectory, r: Attestation, what: &str) {
        let id = r.attestation_id.clone();
        put(d, r)
            .await
            .unwrap_or_else(|e| panic!("{what}: must be admitted: {e}"));
        assert!(held(d, &id).await, "{what}: an admitted row is stored");
    }

    /// The `hard_case_events` entry for `event_id`, if one is listed.
    async fn listed(d: &dyn FederationDirectory, event_id: &str) -> Option<HardCaseEvent> {
        d.list_hard_case_events(HardCaseFilter::default())
            .await
            .expect("list")
            .into_iter()
            .find(|e| e.event_id == event_id)
    }

    /// I1591 — `health:liveness:` self-emission, in both forms.
    pub(crate) async fn i1591_health_liveness_self_ban_in_both_forms(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "health:liveness:v1";
        let service = format!("i1591-service-{tag}");
        let monitor = format!("i1591-monitor-{tag}");
        register(d, &service, &[it::AGENT]).await;
        register(d, &monitor, &[it::AGENT]).await;
        let score = serde_json::json!({ "score": 1.0 });
        for form in FORMS {
            refused(
                d,
                row(form, FAMILY, &service, &service, &[], &score, None),
                "federation_dimension_rejected",
                crate::federation::invariant::INVARIANT_SELF_EMISSION_REASON,
                &format!("I1591 {form:?}: a service attesting its own liveness"),
            )
            .await;
            admitted(
                d,
                row(form, FAMILY, &monitor, &service, &[], &score, None),
                &format!("I1591 {form:?}: a monitor's row about another service"),
            )
            .await;
        }
    }

    /// I1592 — the `hard_case:` emitter rule, in both forms.
    pub(crate) async fn i1592_hard_case_emitter_rule_in_both_forms<B>(b: &B, tag: &str)
    where
        B: FederationDirectory + DeclaresNode,
    {
        let d: &dyn FederationDirectory = b;
        let family = hard_case::hard_case_dimension(hard_case::kind::CONSENT_SLA_BREACH);
        let node = format!("i1592-node-{tag}");
        let root = format!("i1592-root-{tag}");
        let author = format!("i1592-persist-{tag}");
        let node_key = format!("i1592-nodekey-{tag}");
        let agent = format!("i1592-agent-{tag}");
        let victim = format!("i1592-victim-{tag}");
        b.declare_node_key_for_test(&node);
        register(d, &author, &[it::SUBSTRATE_PERSIST]).await;
        register(d, &node_key, &[it::NODE]).await;
        register(d, &agent, &[it::AGENT]).await;
        register(d, &victim, &[it::USER]).await;
        let none = serde_json::json!({});

        // A third-party event with a body the projection reads, written at the
        // id the projection derives — the census row: a peer's `scores` row
        // that would otherwise land in `hard_case_events`.
        let about_victim = |n: &str| {
            let event = HardCaseEvent {
                event_id: format!("i1592-{tag}-{n}"),
                kind: hard_case::kind::CONSENT_SLA_BREACH.to_owned(),
                target_key_id: Some(victim.clone()),
                subject_key_id: None,
                detail: serde_json::json!({ "sla_days": 30 }),
                emitted_at: chrono::DateTime::<chrono::Utc>::from_timestamp(1_790_000_000, 0)
                    .expect("instant"),
                emitter_key_id: String::new(),
            };
            let body = hard_case::hard_case_envelope(&event).expect("envelope")
                [hard_case::BODY_MEMBER]
                .clone();
            let id = hard_case::hard_case_attestation_id(&event.event_id);
            let mut extra = serde_json::Map::new();
            extra.insert(hard_case::BODY_MEMBER.to_owned(), body);
            (event.event_id, id, serde_json::Value::Object(extra))
        };

        for form in FORMS {
            refused(
                d,
                row(form, &family, &agent, &agent, &[], &none, None),
                "federation_reserved_prefix_emitter_mismatch",
                it::SUBSTRATE_PERSIST,
                &format!("I1592 {form:?}: an agent key as a hard_case emitter"),
            )
            .await;
            let (event_id, id, body) = about_victim(&format!("{form:?}-refused"));
            refused(
                d,
                row(form, &family, &author, &victim, &[], &body, Some(id)),
                "federation_reserved_prefix_emitter_mismatch",
                delegation_scope::INFRA_RECORD_HARD_CASE,
                &format!("I1592 {form:?}: a hard_case row about another party, no conferral"),
            )
            .await;
            assert!(
                listed(d, &event_id).await.is_none(),
                "I1592 {form:?}: a refused row never reaches hard_case_events"
            );
            admitted(
                d,
                row(form, &family, &author, &author, &[], &none, None),
                &format!("I1592 {form:?}: a substrate_persist key's row about itself"),
            )
            .await;
            admitted(
                d,
                row(form, &family, &node_key, &node_key, &[], &none, None),
                &format!("I1592 {form:?}: a node key's row about itself (the hard_case door)"),
            )
            .await;
        }

        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            d,
            &node,
            &root,
            &author,
            delegation_scope::INFRA_RECORD_HARD_CASE,
        )
        .await;
        for form in FORMS {
            let (event_id, id, body) = about_victim(&format!("{form:?}-conferred"));
            admitted(
                d,
                row(form, &family, &author, &victim, &[], &body, Some(id)),
                &format!("I1592 {form:?}: a conferred hard_case row about another party"),
            )
            .await;
            if form == Form::Scores {
                let event = listed(d, &event_id)
                    .await
                    .expect("I1592: the conferred scores row projects");
                assert_eq!(
                    event.emitter_key_id, author,
                    "I1592: the emitter is the row's signer"
                );
            }
        }
    }

    /// I1593 — CC 3.4.3: a substrate self-report is about its signer.
    pub(crate) async fn i1593_substrate_self_report_attester_in_both_forms(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        let persist = format!("i1593-persist-{tag}");
        let agent = format!("i1593-agent-{tag}");
        let other = format!("i1593-other-{tag}");
        register(d, &persist, &[it::SUBSTRATE_PERSIST]).await;
        register(d, &agent, &[it::AGENT]).await;
        register(d, &other, &[it::USER]).await;
        let score = serde_json::json!({ "score": 1.0 });
        for form in FORMS {
            refused(
                d,
                row(form, FAMILY, &persist, &other, &[], &score, None),
                "federation_dimension_rejected",
                crate::federation::admission::SUBSTRATE_SELF_REPORT_SUBJECT_REASON,
                &format!("I1593 {form:?}: a substrate self-report about another key"),
            )
            .await;
            admitted(
                d,
                row(form, FAMILY, &persist, &persist, &[], &score, None),
                &format!("I1593 {form:?}: a substrate self-report about itself"),
            )
            .await;
            refused(
                d,
                row(form, FAMILY, &agent, &agent, &[], &score, None),
                "federation_reserved_prefix_emitter_mismatch",
                it::SUBSTRATE_PERSIST,
                &format!("I1593 {form:?}: an agent key's substrate self-report"),
            )
            .await;
        }
    }

    /// I1594 — `trace_summary:` is its producer's own, in both forms.
    pub(crate) async fn i1594_trace_summary_self_emission_in_both_forms(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "trace_summary:digest:v1";
        let agent = format!("i1594-agent-{tag}");
        let other = format!("i1594-other-{tag}");
        register(d, &agent, &[it::AGENT]).await;
        register(d, &other, &[it::AGENT]).await;
        let score = serde_json::json!({ "score": 1.0 });
        for form in FORMS {
            refused(
                d,
                row(form, FAMILY, &agent, &agent, &[&other], &score, None),
                "federation_trace_dimension_invalid",
                "trace_summary:",
                &format!("I1594 {form:?}: a summary whose signer is not its subject"),
            )
            .await;
            admitted(
                d,
                row(form, FAMILY, &agent, &agent, &[&agent], &score, None),
                &format!("I1594 {form:?}: a summary naming its own signer"),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod unit {
    use crate::federation::admission::{
        default_reserved_prefix_rules, trace_family_token, HARD_CASE_FAMILY_PREFIX,
        SUBSTRATE_SELF_REPORT_PREFIXES,
    };
    use crate::federation::row_type::claim_token_of;
    use crate::federation::types::{attestation_type, identity_type};

    /// I1590 — the family classifier.
    #[test]
    fn i1590_the_family_is_the_dimension_on_scores_and_the_type_elsewhere() {
        let dim = Some("hard_case:consent_sla_breach:v1");
        assert_eq!(claim_token_of(attestation_type::SCORES, dim), dim);
        assert_eq!(claim_token_of(attestation_type::SCORES, None), None);
        assert_eq!(
            claim_token_of(
                "hard_case:consent_sla_breach:v1",
                Some("identity_binding:v1")
            ),
            Some("hard_case:consent_sla_breach:v1"),
            "a typed row's family is its type, whatever label its envelope carries"
        );
        assert_eq!(
            claim_token_of(attestation_type::WITHDRAWS, dim),
            Some(attestation_type::WITHDRAWS),
            "a composer's token is its verb, which names no family"
        );
    }

    /// I1595 — the attester rule's families are the rule table's
    /// `substrate_persist`-only rows, exactly.
    #[test]
    fn i1595_substrate_self_report_prefixes_are_the_tables() {
        let mut table: Vec<String> = default_reserved_prefix_rules()
            .into_iter()
            .filter(|r| r.required_identity_types == [identity_type::SUBSTRATE_PERSIST])
            .map(|r| r.pattern_prefix)
            .collect();
        table.sort();
        let mut pinned: Vec<String> = SUBSTRATE_SELF_REPORT_PREFIXES
            .iter()
            .map(|p| (*p).to_owned())
            .collect();
        pinned.sort();
        assert_eq!(pinned, table);
        assert_eq!(HARD_CASE_FAMILY_PREFIX, "hard_case:");
    }

    /// I1596 — the trace gate's token: the family in either form, else the
    /// envelope dimension.
    #[test]
    fn i1596_the_trace_gate_reads_the_family_in_either_form() {
        let ts = "trace_summary:digest:v1";
        assert_eq!(trace_family_token(ts, None), Some(ts), "the classic form");
        assert_eq!(
            trace_family_token(ts, Some("identity_binding:v1")),
            Some(ts),
            "the type slot wins over an unrelated label"
        );
        assert_eq!(
            trace_family_token(attestation_type::SCORES, Some(ts)),
            Some(ts)
        );
        assert_eq!(
            trace_family_token(attestation_type::WITHDRAWS, Some("trace:complete:v1")),
            Some("trace:complete:v1"),
            "a composer labelled trace:* is held to the gate, as before"
        );
        assert_eq!(
            trace_family_token("age_self_declared:band:adult:v1", Some("trace:complete:v1")),
            Some("trace:complete:v1"),
            "a typed row labelled trace:* is held to the gate, as before"
        );
        assert_eq!(trace_family_token(attestation_type::SCORES, None), None);
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
                        eprintln!("1174 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
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

    on_every_backend!(i1591, bodies::i1591_health_liveness_self_ban_in_both_forms);
    on_every_backend!(i1592, bodies::i1592_hard_case_emitter_rule_in_both_forms);
    on_every_backend!(
        i1593,
        bodies::i1593_substrate_self_report_attester_in_both_forms
    );
    on_every_backend!(
        i1594,
        bodies::i1594_trace_summary_self_emission_in_both_forms
    );
}
