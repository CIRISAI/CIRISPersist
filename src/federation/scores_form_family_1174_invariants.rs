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
//! - **I1592** (sqlite, postgres) `hard_case:` — v62.0.0 (D2; CC 3.4.7): a
//!   person's key and a `substrate_persist` label are refused (no node); a
//!   node owned under a binding carrying `infra:attest` lands its row about
//!   itself, and its row whose body names another party is HELD
//!   `reserved_family_unseated` until the owner's binding carries
//!   `infra:record_hard_case`, when it re-folds, concludes and projects with
//!   the node as its emitter. No root is read.
//! - **I1593** (sqlite, postgres) CC 3.4.3 substrate self-report — a
//!   `substrate_persist` key's `system:*` row about another key is refused
//!   (`substrate_self_report_names_another_party`). v62.0.0 (D1; CC 3.4.7):
//!   about itself it is refused too, because the label opens nothing; the
//!   family's duty is `infra:attest` from a node's OWNER (landed by I6600,
//!   `self_report_duty_invariants`). **I1607** (sqlite, postgres) v62.0.0:
//!   the same row about another key is REFUSED at every door: offered by a
//!   peer (`put_attestation`), replicated (`apply_replicated_attestation`)
//!   and at the local tier (v61.1 admitted the first two under report).
//! - **I1594** (sqlite, postgres) `trace_summary:` — a summary whose signer is
//!   not among its `subject_key_ids` is refused (`trace_dimension_invalid`);
//!   one naming its signer is admitted.
//! - **I1595** (unit) [`SUBSTRATE_SELF_REPORT_PREFIXES`](super::admission::SUBSTRATE_SELF_REPORT_PREFIXES)
//!   is exactly the rule table's owner-conferred rows (v62.0.0, D1; until then
//!   its `substrate_persist`-only rows), and the
//!   `hard_case:` arm's stem is the hard_case door's.
//! - **I1596** (unit) [`trace_family_token`](super::admission::trace_family_token):
//!   the family in either form, else the envelope dimension (the #473 reach
//!   over composers and typed rows is unchanged).
//!
//! v62.0.0 (slice E6) — **the classic form is gone.** An edition-2 statement's
//! row type is one of Verify's five (`scores`, `delegates_to`, `supersedes`,
//! `withdraws`, `recants`) and its family is the protected header's -70002,
//! so a family can no longer ride the type slot: every backend leg runs the
//! one form left (`scores`, the family in `dimension`, the header's family
//! resolved from it). Keys are edition-2 `key:record`s (`put_key`): a fixture
//! signs with the SEED, every comparison reads the KID. The unit legs (I1590,
//! I1595, I1596) keep both forms: they witness the pure classifier, which
//! still reads a typed row.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::test_support::DeclaresNode;
    use crate::federation::hard_case::{self, HardCaseEvent, HardCaseFilter};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, cohort_scope, delegation_scope, identity_type as it,
    };
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    /// The form a family rides. v62.0.0: `scores` only (see the header).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Form {
        /// `attestation_type = scores`, the family in the envelope `dimension`.
        Scores,
    }

    /// The forms every leg runs.
    pub(crate) const FORMS: [Form; 1] = [Form::Scores];

    /// A federation-tier, self-scoped row of `family` in `form`, signed by the
    /// key of seed `signer` about `about`, naming `subjects`, with `extra`
    /// merged into its envelope: an edition-2 row (`row_of`), its id
    /// computed.
    pub(crate) fn row(
        form: Form,
        family: &str,
        signer: &str,
        about: &str,
        subjects: &[&str],
        extra: &serde_json::Value,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({ "id": id });
        if let Some(members) = extra.as_object() {
            for (k, v) in members {
                env[k.as_str()] = v.clone();
            }
        }
        match form {
            Form::Scores => env["dimension"] = serde_json::json!(family),
        }
        let mut r = ts::bare_attestation(&id, signer, about, &env);
        r.attestation_type = attestation_type::SCORES.to_owned();
        r.weight = None;
        r.cohort_scope = cohort_scope::SELF.to_owned();
        r.subject_key_ids = subjects.iter().map(|s| e2::kid_or_keep(s)).collect();
        e2::row_of(&r, signer)
    }

    /// Register the key of `seed` with `types`; its kid.
    async fn register(d: &dyn FederationDirectory, seed: &str, types: &[&str]) -> String {
        e2::put_key(d, seed, types).await
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
                row(form, FAMILY, &service, &service, &[], &score),
                "federation_dimension_rejected",
                crate::federation::invariant::INVARIANT_SELF_EMISSION_REASON,
                &format!("I1591 {form:?}: a service attesting its own liveness"),
            )
            .await;
            admitted(
                d,
                row(form, FAMILY, &monitor, &service, &[], &score),
                &format!("I1591 {form:?}: a monitor's row about another service"),
            )
            .await;
        }
    }

    /// I1592 — the `hard_case:` emitter rule, in both forms. v62.0.0 (D2; CC
    /// 3.4.7): the duty is the node's OWNER's (`infra:attest` about itself,
    /// `infra:record_hard_case` about another party), read in its owner
    /// binding; no label opens the family and no root is read.
    pub(crate) async fn i1592_hard_case_emitter_rule_in_both_forms<B>(b: &B, tag: &str)
    where
        B: FederationDirectory + DeclaresNode,
    {
        use crate::federation::edition2::fold::reason::gc1::RESERVED_FAMILY_UNSEATED;
        use crate::federation::edition2::names::RowId;
        use crate::federation::edition2::verdict::row_state;
        let d: &dyn FederationDirectory = b;
        let family = hard_case::hard_case_dimension(hard_case::kind::CONSENT_SLA_BREACH);
        let node = format!("i1592-node-{tag}");
        let owner = format!("i1592-owner-{tag}");
        let label = format!("i1592-persist-{tag}");
        let person = format!("i1592-person-{tag}");
        let victim = format!("i1592-victim-{tag}");
        b.declare_node_key_for_test(&e2::kid(&node));
        let node_kid = register(d, &node, &[it::NODE]).await;
        register(d, &label, &[it::SUBSTRATE_PERSIST]).await;
        register(d, &person, &[it::USER]).await;
        let victim_kid = register(d, &victim, &[it::USER]).await;
        let none = serde_json::json!({});

        // A third-party event with a body the projection reads — the census
        // row: a peer's `scores` row that would land in `hard_case_events`.
        let about_victim = |n: &str| {
            let event = HardCaseEvent {
                event_id: format!("i1592-{tag}-{n}"),
                kind: hard_case::kind::CONSENT_SLA_BREACH.to_owned(),
                target_key_id: Some(victim_kid.clone()),
                subject_key_id: None,
                detail: serde_json::json!({ "sla_days": 30 }),
                emitted_at: chrono::DateTime::<chrono::Utc>::from_timestamp(1_790_000_000, 0)
                    .expect("instant"),
                emitter_key_id: String::new(),
            };
            let body = hard_case::hard_case_envelope(&event).expect("envelope")
                [hard_case::BODY_MEMBER]
                .clone();
            let mut extra = serde_json::Map::new();
            extra.insert(hard_case::BODY_MEMBER.to_owned(), body);
            (event.event_id, serde_json::Value::Object(extra))
        };
        // The row as this node's producer states it (its head named): its
        // id, after the put.
        let put_stated = |r: Attestation| async move {
            let st = e2::carried_statement(&r).expect("an edition-2 row");
            let headed = e2::with_head_resolved(d, &st, None)
                .await
                .expect("the head read");
            let id = RowId::of_statement(&headed).expect("a row statement");
            (id, e2::put_statement(d, &headed).await.map(|_| ()))
        };

        for form in FORMS {
            // A key that is no node, labelled or not: refused (the key plane).
            for signer in [&person, &label] {
                refused(
                    d,
                    row(form, &family, signer, signer, &[], &none),
                    "federation_reserved_prefix_emitter_mismatch",
                    RESERVED_FAMILY_UNSEATED,
                    &format!("I1592 {form:?}: {signer} is no node"),
                )
                .await;
            }
        }
        // The node, owned, its binding carrying infra:attest (rootless).
        crate::federation::admission::r2_test_support::confer_from_owner(
            d,
            &owner,
            &node,
            &[delegation_scope::INFRA_ATTEST],
        )
        .await;
        let mut held_ids = Vec::new();
        for form in FORMS {
            let (event_id, body) = about_victim(&format!("{form:?}-held"));
            let (id, put) = put_stated(row(form, &family, &node, &node, &[], &body)).await;
            put.unwrap_or_else(|e| panic!("I1592 {form:?}: kept, not refused: {e}"));
            let state = row_state(d, &id).await.expect("state");
            assert_eq!(
                state.held().map(|h| h.reason.as_str()),
                Some(RESERVED_FAMILY_UNSEATED),
                "I1592 {form:?}: a body naming another party needs infra:record_hard_case: {state:?}"
            );
            assert!(
                listed(d, &event_id).await.is_none(),
                "I1592 {form:?}: a held row never reaches hard_case_events"
            );
            held_ids.push((event_id, id));
            let (id, put) = put_stated(row(form, &family, &node, &node, &[], &none)).await;
            put.unwrap_or_else(|e| panic!("I1592 {form:?}: the node's own row: {e}"));
            assert!(
                row_state(d, &id).await.expect("state").is_concluded(),
                "I1592 {form:?}: a node's row about itself lands under infra:attest"
            );
        }

        crate::federation::admission::r2_test_support::confer_from_owner(
            d,
            &owner,
            &node,
            &[delegation_scope::INFRA_RECORD_HARD_CASE],
        )
        .await;
        for (event_id, id) in held_ids {
            assert!(
                row_state(d, &id).await.expect("state").is_concluded(),
                "I1592: the held row re-folds and concludes under infra:record_hard_case"
            );
            let event = listed(d, &event_id)
                .await
                .expect("I1592: the conferred scores row projects");
            assert_eq!(
                event.emitter_key_id, node_kid,
                "I1592: the emitter is the row's signer"
            );
        }
    }

    /// I1593 — CC 3.4.3: a substrate self-report is about its signer.
    pub(crate) async fn i1593_substrate_self_report_attester_in_both_forms(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        let persist = format!("i1593-persist-{tag}");
        let other = format!("i1593-other-{tag}");
        register(d, &persist, &[it::SUBSTRATE_PERSIST]).await;
        register(d, &other, &[it::USER]).await;
        let score = serde_json::json!({ "score": 1.0 });
        for form in FORMS {
            // v61.1.0 — refused at this node's own write door; v62.0.0 (D1)
            // at a peer's and the replicated door too (I1607).
            let r = row(form, FAMILY, &persist, &other, &[], &score);
            let id = r.attestation_id.clone();
            let err = d
                .put_attestation_authored(SignedAttestation { attestation: r })
                .await
                .expect_err("I1593: this node's own substrate self-report about another key");
            assert_eq!(
                err.kind(),
                "federation_dimension_rejected",
                "I1593 {form:?}: {err}"
            );
            assert!(
                err.to_string()
                    .contains(crate::federation::admission::SUBSTRATE_SELF_REPORT_SUBJECT_REASON),
                "I1593 {form:?}: {err}"
            );
            assert!(!held(d, &id).await, "I1593 {form:?}: not stored");
            // v62.0.0 (D1; CC 3.4.7 "No key declares itself into a duty") —
            // about itself it is refused too: the label is not the duty, and
            // the signer is no node (`OwnerConferral::NotANode`, read from
            // the key plane: a refusal, never a hold).
            refused(
                d,
                row(form, FAMILY, &persist, &persist, &[], &score),
                "federation_reserved_prefix_emitter_mismatch",
                crate::federation::edition2::fold::reason::gc1::RESERVED_FAMILY_UNSEATED,
                &format!("I1593 {form:?}: a substrate_persist label's report about itself"),
            )
            .await;
        }
    }

    /// I1607 (v62.0.0, D1; CC 3.4.7 "The signer is the node the row is about")
    /// — a substrate self-report about another key is REFUSED at every door:
    /// offered by a peer (`put_attestation`), replicated
    /// (`apply_replicated_attestation`) and at the local tier, each with
    /// `substrate_self_report_names_another_party`, and nothing is stored.
    /// v61.1 admitted the first two under report (the
    /// `persist_substrate_self_report_would_refuse_total` counter, deleted).
    pub(crate) async fn i1607_a_peers_self_report_about_another_key_is_refused(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        let persist = format!("i1607-persist-{tag}");
        let other = format!("i1607-other-{tag}");
        let persist_kid = register(d, &persist, &[it::SUBSTRATE_PERSIST]).await;
        let other_kid = register(d, &other, &[it::USER]).await;
        let score = serde_json::json!({ "score": 1.0 });
        let names_another = |e: &Error, what: &str| {
            assert_eq!(e.kind(), "federation_dimension_rejected", "{what}: {e}");
            assert!(
                e.to_string()
                    .contains(crate::federation::admission::SUBSTRATE_SELF_REPORT_SUBJECT_REASON),
                "{what}: {e}"
            );
        };
        for form in FORMS {
            let r = row(form, FAMILY, &persist, &other, &[], &score);
            let id = r.attestation_id.clone();
            let err = put(d, r)
                .await
                .expect_err("I1607: a peer's self-report about another key");
            names_another(&err, &format!("I1607 {form:?}: the peer door"));
            assert!(
                !held(d, &id).await,
                "I1607 {form:?}: not stored (peer door)"
            );
            let r = row(form, FAMILY, &persist, &other, &[], &score);
            let id = r.attestation_id.clone();
            let err = d
                .apply_replicated_attestation(SignedAttestation { attestation: r })
                .await
                .expect_err("I1607: a replicated self-report about another key");
            names_another(&err, &format!("I1607 {form:?}: the replicated door"));
            assert!(
                !held(d, &id).await,
                "I1607 {form:?}: not stored (replicated)"
            );
        }
        // The local-tier door is this node's own write: refused.
        let err = d
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: persist_kid.clone(),
                attested_key_id: Some(other_kid.clone()),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({ "dimension": FAMILY, "score": 1.0 }),
                )
                .expect("envelope"),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect_err("I1607: the local-tier door refuses it");
        assert!(
            err.to_string()
                .contains(crate::federation::admission::SUBSTRATE_SELF_REPORT_SUBJECT_REASON),
            "I1607: refused by the self-report rule at the local door: {err}"
        );
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
                row(form, FAMILY, &agent, &agent, &[&other], &score),
                "federation_trace_dimension_invalid",
                "trace_summary:",
                &format!("I1594 {form:?}: a summary whose signer is not its subject"),
            )
            .await;
            admitted(
                d,
                row(form, FAMILY, &agent, &agent, &[&agent], &score),
                &format!("I1594 {form:?}: a summary naming its own signer"),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod unit {
    use crate::federation::admission::{
        default_reserved_prefix_rules, trace_family_token, DutyConferrer, HARD_CASE_FAMILY_PREFIX,
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
    /// owner-conferred rows, exactly (v62.0.0, D1: they name no identity
    /// type, and no rule names `substrate_persist`).
    #[test]
    fn i1595_substrate_self_report_prefixes_are_the_tables() {
        assert!(
            default_reserved_prefix_rules().iter().all(|r| !r
                .required_identity_types
                .iter()
                .any(|t| t == identity_type::SUBSTRATE_PERSIST)),
            "I1595: no rule opens a family on the substrate_persist label (CC 3.4.7)"
        );
        let mut table: Vec<String> = default_reserved_prefix_rules()
            .into_iter()
            .filter(|r| r.conferred_by == DutyConferrer::Owner)
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
        i1607,
        bodies::i1607_a_peers_self_report_about_another_key_is_refused
    );
    on_every_backend!(
        i1594,
        bodies::i1594_trace_summary_self_emission_in_both_forms
    );
}
