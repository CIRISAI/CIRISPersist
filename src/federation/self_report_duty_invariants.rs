//! v62.0.0 (D1; CC 3.4.3, CC 3.4.7) — **I6600–I6605: a node's report about
//! itself counts only under `infra:attest` conferred by its OWNER.**
//!
//! CC 3.4.3: "`system:*` and the substrate families … are a node's reports
//! about itself. The signer is the node the row is about and holds
//! `infra:attest` from its owner (CC 3.4.7). … A row on these prefixes from
//! any other signer concludes nothing." CC 3.4.7: "No key declares itself
//! into a duty. `identity_type` on a key record is the key's own statement
//! about itself. No admission decision reads it to open a reserved family."
//!
//! The five families (`admission::SUBSTRATE_SELF_REPORT_PREFIXES`) are
//! `DutyConferrer::Owner` rules: the door asks
//! `admission::owner_confers_for_act` (the node's live two-voice owner
//! binding, at the row's instant, carrying `infra:attest` or the family's
//! `infra:attest:{family}`). Every leg goes through the real statement door
//! (`ingest::put_statement`), the row stated as this node's producer states
//! it (`fixture_switch::with_head_resolved`: an owned node's report names its
//! owner-binding row as `refs.head`), and reads the ONE verdict
//! (`verdict::row_state`).
//!
//! - **I6600** — an OWNED, ROOTLESS node (no node identity, no root, no trust
//!   set) whose binding carries `infra:attest`: its report on each of the
//!   five families names its binding as `refs.head` and LANDS.
//! - **I6601** — an owned node whose binding carries no `infra:attest` (the
//!   default `infra:serve` / `infra:network_presence`): each report is HELD
//!   `reserved_family_unseated`, concluding nothing.
//! - **I6602** — the label opens nothing: a key labelled `{node,
//!   substrate_persist}` under such a binding is held as I6601; a key
//!   labelled `substrate_persist` alone, and a person's key, are REFUSED
//!   (no node: read from the key plane), nothing kept.
//! - **I6603** — both arrival orders, two nodes: node B receives the report
//!   (stated on node A, naming its binding) BEFORE the binding: held
//!   `reserved_family_unseated`; the owner's statement and the node's voice
//!   land the binding, and the report re-folds and concludes.
//! - **I6604** — an UNOWNED node's report names no head and is refused
//!   `act_names_no_head` by the head rule at the funnel, which runs before
//!   any attestation gate: the duty gate is never reached.
//! - **I6605** — a node holding the duty files a report about ANOTHER key:
//!   refused `substrate_self_report_names_another_party` at the statement
//!   door, the peer door and the replicated door; nothing kept.
//! - **I6607** (D1.rev2) — a stranger's `withdraws` of a node's report is
//!   HELD `withdraws_not_admitted` (`admission::check_withdraws_admission`:
//!   no rule admits it); the report stays concluded.
//! - **I6608** (D1.rev2) — after the owner withdraws the binding, the node's
//!   `supersedes` of its own report is refused `act_names_no_head` as its
//!   producer states it (no binding in force), and HELD
//!   `reserved_family_unseated` when it names the ENDED binding
//!   (`admission::check_composer_owner_duty`); the report stays concluded.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::r2_test_support::confer_from_owner;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold::reason::gc1::RESERVED_FAMILY_UNSEATED;
    use crate::federation::edition2::names::{self, RowId};
    use crate::federation::edition2::verdict::{row_state, RowState};
    use crate::federation::scores_form_family_1174_invariants::bodies::{row, Form};
    use crate::federation::types::{attestation_tier, delegation_scope as ds, identity_type as it};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    /// One dimension on each of the five self-report families.
    pub(crate) const FAMILIES: [&str; 5] = [
        "system:health:n_eff_measurable:v1",
        "audit_chain:hash_continuity:v1",
        "corpus_health:n_eff_measurable:v1",
        "identity_continuity:relational_anchor:v1",
        "federation_directory:replication_lag:v1",
    ];

    /// The `family` row by the key of seed `signer` about the key of seed
    /// `about`, as `d`'s producer states it (its head resolved over `d`):
    /// its row id and its statement.
    async fn report(
        d: &dyn FederationDirectory,
        family: &str,
        signer: &str,
        about: &str,
    ) -> (RowId, Vec<u8>) {
        let r = row(
            Form::Scores,
            family,
            signer,
            about,
            &[],
            &serde_json::json!({ "score": 1.0 }),
        );
        let st = e2::carried_statement(&r).expect("an edition-2 row carries its statement");
        let headed = e2::with_head_resolved(d, &st, None)
            .await
            .expect("the head read");
        let id = RowId::of_statement(&headed).expect("a row statement");
        (id, headed)
    }

    async fn state(d: &dyn FederationDirectory, id: &RowId) -> RowState {
        row_state(d, id).await.expect("the verdict read")
    }

    /// The reason `s` is held for, if it is held.
    fn held_for(s: &RowState) -> Option<String> {
        s.held().map(|h| h.reason.clone())
    }

    /// The row `refs.head` names in `statement`.
    fn named_head(statement: &[u8]) -> Option<RowId> {
        names::of_statement_names(statement).and_then(|(_, n)| names::single(&n, "head"))
    }

    /// `node` (a `node` key) is owned by `owner`, its binding carrying
    /// `scopes` beside the defaults; the binding row id as `node`'s head.
    async fn owned(
        d: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        node_types: &[&str],
        scopes: &[&str],
    ) -> RowId {
        e2::put_key(d, node, node_types).await;
        confer_from_owner(d, owner, node, scopes).await;
        crate::federation::edition2::head_rule::owner_binding_row(d, &e2::kid(node), false, 0)
            .await
            .expect("the binding read")
            .expect("the node is owned")
    }

    /// I6600 — an owned, rootless node lands its reports about itself.
    pub(crate) async fn i6600_an_owned_rootless_node_lands_its_reports(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let node = format!("i6600-node-{tag}");
        let owner = format!("i6600-owner-{tag}");
        assert!(
            d.node_key_id().is_none(),
            "I6600: this directory has no node identity, so no root can be read here"
        );
        let binding = owned(d, &owner, &node, &[it::NODE], &[ds::INFRA_ATTEST]).await;
        for family in FAMILIES {
            let (id, st) = report(d, family, &node, &node).await;
            assert_eq!(
                named_head(&st),
                Some(binding),
                "I6600 {family}: an owned node's report names its owner binding as refs.head"
            );
            e2::put_statement(d, &st)
                .await
                .unwrap_or_else(|e| panic!("I6600 {family}: admitted: {e}"));
            let s = state(d, &id).await;
            assert!(
                s.is_concluded(),
                "I6600 {family}: lands under the owner's infra:attest, no root: {s:?}"
            );
        }
    }

    /// I6601 — owned, but the binding carries no `infra:attest`: held.
    pub(crate) async fn i6601_a_binding_without_the_scope_holds_the_report(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let node = format!("i6601-node-{tag}");
        let owner = format!("i6601-owner-{tag}");
        owned(d, &owner, &node, &[it::NODE], &[]).await;
        for family in FAMILIES {
            let (id, st) = report(d, family, &node, &node).await;
            e2::put_statement(d, &st)
                .await
                .unwrap_or_else(|e| panic!("I6601 {family}: kept, not refused: {e}"));
            let s = state(d, &id).await;
            assert!(
                !s.is_concluded(),
                "I6601 {family}: concludes nothing: {s:?}"
            );
            assert_eq!(
                held_for(&s).as_deref(),
                Some(RESERVED_FAMILY_UNSEATED),
                "I6601 {family}: {s:?}"
            );
        }
    }

    /// I6602 — the `substrate_persist` label opens nothing.
    pub(crate) async fn i6602_the_label_opens_nothing(d: &dyn FederationDirectory, tag: &str) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        // A labelled node under a binding without the scope: held as I6601.
        let labelled = format!("i6602-labelled-{tag}");
        let owner = format!("i6602-owner-{tag}");
        owned(
            d,
            &owner,
            &labelled,
            &[it::NODE, it::SUBSTRATE_PERSIST],
            &[],
        )
        .await;
        let (id, st) = report(d, FAMILY, &labelled, &labelled).await;
        e2::put_statement(d, &st)
            .await
            .unwrap_or_else(|e| panic!("I6602: the labelled node's report is kept: {e}"));
        let s = state(d, &id).await;
        assert_eq!(
            held_for(&s).as_deref(),
            Some(RESERVED_FAMILY_UNSEATED),
            "I6602: a {{node, substrate_persist}} key without the owner's infra:attest: {s:?}"
        );
        // A key that is no node: refused from the key plane, nothing kept.
        for (seed, types) in [
            (format!("i6602-label-{tag}"), vec![it::SUBSTRATE_PERSIST]),
            (format!("i6602-person-{tag}"), vec![it::USER]),
        ] {
            e2::put_key(d, &seed, &types).await;
            let (id, st) = report(d, FAMILY, &seed, &seed).await;
            let err = e2::put_statement(d, &st)
                .await
                .expect_err("I6602: a key that is no node holds no node's duty");
            assert_eq!(
                err.kind(),
                "federation_reserved_prefix_emitter_mismatch",
                "I6602 {types:?}: {err}"
            );
            assert!(
                err.to_string().contains(RESERVED_FAMILY_UNSEATED),
                "I6602 {types:?}: the refusal names the token: {err}"
            );
            assert_eq!(
                state(d, &id).await,
                RowState::Absent,
                "I6602 {types:?}: nothing kept"
            );
        }
    }

    /// I6603 — the report before its binding (node B), then the binding.
    pub(crate) async fn i6603_a_report_before_its_binding_waits_then_lands(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        let node = format!("i6603-node-{tag}");
        let owner = format!("i6603-owner-{tag}");
        // Node A: the binding, then the report stated over it (it names it).
        e2::put_key(a, &node, &[it::NODE]).await;
        let binding = confer_from_owner(a, &owner, &node, &[ds::INFRA_ATTEST]).await;
        let (id, st) = report(a, FAMILY, &node, &node).await;
        assert!(
            named_head(&st).is_some(),
            "I6603: the report names its binding"
        );
        e2::put_statement(a, &st)
            .await
            .unwrap_or_else(|e| panic!("I6603 A: {e}"));
        assert!(
            state(a, &id).await.is_concluded(),
            "I6603 A: binding first, then the report: lands"
        );
        // Node B: the keys, then the report BEFORE the binding.
        e2::put_key(b, &node, &[it::NODE]).await;
        e2::put_key(b, &owner, &[it::USER]).await;
        e2::put_statement(b, &st)
            .await
            .unwrap_or_else(|e| panic!("I6603 B: the report is kept, not refused: {e}"));
        let s = state(b, &id).await;
        assert_eq!(
            held_for(&s).as_deref(),
            Some(RESERVED_FAMILY_UNSEATED),
            "I6603 B: no binding held yet: concludes nothing: {s:?}"
        );
        let owner_st = e2::carried_statement(&binding).expect("the owner's statement");
        let voice = e2::voice_of(&owner_st, &node);
        e2::put_statement(b, &owner_st)
            .await
            .unwrap_or_else(|e| panic!("I6603 B: the owner's statement: {e}"));
        e2::put_statement(b, &voice)
            .await
            .unwrap_or_else(|e| panic!("I6603 B: the node's voice: {e}"));
        let s = state(b, &id).await;
        assert!(
            s.is_concluded(),
            "I6603 B: the binding landed: the report re-folds and lands: {s:?}"
        );
    }

    /// I6604 — an unowned node: the head rule refuses first.
    pub(crate) async fn i6604_an_unowned_nodes_report_is_refused_by_the_head_rule(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let node = format!("i6604-node-{tag}");
        e2::put_key(d, &node, &[it::NODE]).await;
        for family in FAMILIES {
            let (id, st) = report(d, family, &node, &node).await;
            assert!(
                named_head(&st).is_none(),
                "I6604 {family}: an unowned node has no binding to name"
            );
            let err = e2::put_statement(d, &st)
                .await
                .expect_err("I6604: an unowned node signs no report");
            assert!(
                matches!(
                    &err,
                    Error::MalformedRow { reason, .. }
                        if *reason == crate::federation::malformed_row::ACT_NAMES_NO_HEAD
                ),
                "I6604 {family}: the head rule refuses it before the duty is asked: {err:?}"
            );
            assert_eq!(state(d, &id).await, RowState::Absent, "I6604 {family}");
        }
    }

    /// I6605 — a duty holder's report about another key: refused everywhere.
    pub(crate) async fn i6605_a_report_about_another_key_is_refused_at_every_door(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        let node = format!("i6605-node-{tag}");
        let owner = format!("i6605-owner-{tag}");
        let other = format!("i6605-other-{tag}");
        owned(d, &owner, &node, &[it::NODE], &[ds::INFRA_ATTEST]).await;
        e2::put_key(d, &other, &[it::USER]).await;
        let names_another = |e: &Error, what: &str| {
            assert_eq!(e.kind(), "federation_dimension_rejected", "{what}: {e}");
            assert!(
                e.to_string()
                    .contains(crate::federation::admission::SUBSTRATE_SELF_REPORT_SUBJECT_REASON),
                "{what}: {e}"
            );
        };
        let (id, st) = report(d, FAMILY, &node, &other).await;
        let err = e2::put_statement(d, &st)
            .await
            .expect_err("I6605: the statement door");
        names_another(&err, "I6605: the statement door");
        let projected = e2::row_of_statement(&st, attestation_tier::FEDERATION);
        let err = d
            .put_attestation(SignedAttestation {
                attestation: projected.clone(),
            })
            .await
            .expect_err("I6605: the peer door");
        names_another(&err, "I6605: the peer door");
        let err = d
            .apply_replicated_attestation(SignedAttestation {
                attestation: projected,
            })
            .await
            .expect_err("I6605: the replicated door");
        names_another(&err, "I6605: the replicated door");
        assert_eq!(state(d, &id).await, RowState::Absent, "I6605: nothing kept");
    }

    /// `statement` re-signed by `seed`'s key with `head` in `refs.head`: a
    /// row as a peer might forward it, naming a head this node's producer
    /// would not state (an ended binding).
    fn resigned_with_head(statement: &[u8], seed: &str, head: &RowId) -> Vec<u8> {
        use ciris_verify_core::cde::Value;
        let (protected, payload) =
            crate::federation::edition2::liveness::statement_parts(statement).expect("a statement");
        let text_at = |v: Option<&Value>| v.and_then(Value::as_text).map(str::to_owned);
        let row_type = text_at(protected.get_int(-70001)).expect("row type");
        let family = text_at(protected.get_int(-70002)).expect("family");
        let iss = text_at(protected.get_int(15).and_then(|c| c.get_int(1))).expect("iss");
        let sub = text_at(protected.get_int(15).and_then(|c| c.get_int(2))).expect("sub");
        let payload = crate::federation::edition2::head_rule::with_head(payload, head)
            .expect("the head joins refs");
        ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(seed),
            &iss,
            &sub,
            &row_type,
            &family,
            &payload,
            vec![],
        )
        .expect("re-sign")
    }

    /// I6607 — a stranger's withdrawal of a node's report: held, the report
    /// stays concluded.
    pub(crate) async fn i6607_a_strangers_withdrawal_of_a_report_concludes_nothing(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        let node = format!("i6607-node-{tag}");
        let owner = format!("i6607-owner-{tag}");
        let stranger = format!("i6607-stranger-{tag}");
        owned(d, &owner, &node, &[it::NODE], &[ds::INFRA_ATTEST]).await;
        e2::put_key(d, &stranger, &[it::USER]).await;
        let (id, st) = report(d, FAMILY, &node, &node).await;
        e2::put_statement(d, &st)
            .await
            .unwrap_or_else(|e| panic!("I6607: the report lands: {e}"));
        assert!(
            state(d, &id).await.is_concluded(),
            "I6607: the report lands"
        );
        let report_row = e2::row_of_statement(&st, attestation_tier::FEDERATION);
        let w = e2::composer_of("withdraws", &report_row, &stranger);
        let w_st = e2::carried_statement(&w).expect("the withdrawal's statement");
        let w_id = RowId::of_statement(&w_st).expect("a row id");
        e2::put_statement(d, &w_st)
            .await
            .unwrap_or_else(|e| panic!("I6607: the withdrawal is kept, not refused: {e}"));
        let s = state(d, &w_id).await;
        assert_eq!(
            held_for(&s).as_deref(),
            Some(crate::federation::edition2::fold::reason::WITHDRAWS_NOT_ADMITTED),
            "I6607: no withdraws rule admits a stranger (admission::check_withdraws_admission): {s:?}"
        );
        assert!(
            state(d, &id).await.is_concluded(),
            "I6607: the node's report stays concluded"
        );
    }

    /// I6608 — a node's supersede of its own report after its owner binding
    /// ended: the producer states no head (refused `act_names_no_head`); a
    /// supersede naming the ENDED binding is held `reserved_family_unseated`.
    pub(crate) async fn i6608_a_supersede_after_the_binding_ended_concludes_nothing(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const FAMILY: &str = "system:health:n_eff_measurable:v1";
        let node = format!("i6608-node-{tag}");
        let owner = format!("i6608-owner-{tag}");
        e2::put_key(d, &node, &[it::NODE]).await;
        let binding = confer_from_owner(d, &owner, &node, &[ds::INFRA_ATTEST]).await;
        let binding_id =
            crate::federation::edition2::head_rule::owner_binding_row(d, &e2::kid(&node), false, 0)
                .await
                .expect("the binding read")
                .expect("I6608: owned");
        let (id, st) = report(d, FAMILY, &node, &node).await;
        e2::put_statement(d, &st)
            .await
            .unwrap_or_else(|e| panic!("I6608: the report lands: {e}"));
        assert!(
            state(d, &id).await.is_concluded(),
            "I6608: the report lands"
        );
        // The owner ends the binding.
        e2::put_signed(d, &e2::composer_of("withdraws", &binding, &owner))
            .await
            .unwrap_or_else(|e| panic!("I6608: the owner withdraws the binding: {e}"));
        let later = crate::host::clock::now() + chrono::Duration::seconds(2);
        let report_row = e2::row_of_statement(&st, attestation_tier::FEDERATION);
        let sup = e2::composer_of_at("supersedes", &report_row, &node, later);
        let sup_st = e2::carried_statement(&sup).expect("the supersede's statement");
        // (a) as the producer states it: no binding in force, so no head.
        let produced = e2::with_head_resolved(d, &sup_st, None)
            .await
            .expect("the head read");
        let err = e2::put_statement(d, &produced)
            .await
            .expect_err("I6608: an ended binding names no head");
        assert!(
            matches!(
                &err,
                Error::MalformedRow { reason, .. }
                    if *reason == crate::federation::malformed_row::ACT_NAMES_NO_HEAD
            ),
            "I6608: the head rule refuses the produced supersede: {err:?}"
        );
        // (b) naming the ended binding: the duty is read at its instant.
        let forwarded = resigned_with_head(&sup_st, &node, &binding_id);
        let f_id = RowId::of_statement(&forwarded).expect("a row id");
        e2::put_statement(d, &forwarded)
            .await
            .unwrap_or_else(|e| panic!("I6608: kept, not refused: {e}"));
        let s = state(d, &f_id).await;
        assert_eq!(
            held_for(&s).as_deref(),
            Some(RESERVED_FAMILY_UNSEATED),
            "I6608: no binding in force at the supersede's instant (check_composer_owner_duty): \
             {s:?}"
        );
        assert!(
            state(d, &id).await.is_concluded(),
            "I6608: the report itself stays concluded"
        );
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
                        eprintln!("D1 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
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

    on_every_backend!(
        i6600,
        bodies::i6600_an_owned_rootless_node_lands_its_reports
    );
    on_every_backend!(
        i6601,
        bodies::i6601_a_binding_without_the_scope_holds_the_report
    );
    on_every_backend!(i6602, bodies::i6602_the_label_opens_nothing);
    on_every_backend!(
        i6604,
        bodies::i6604_an_unowned_nodes_report_is_refused_by_the_head_rule
    );
    on_every_backend!(
        i6605,
        bodies::i6605_a_report_about_another_key_is_refused_at_every_door
    );
    on_every_backend!(
        i6607,
        bodies::i6607_a_strangers_withdrawal_of_a_report_concludes_nothing
    );
    on_every_backend!(
        i6608,
        bodies::i6608_a_supersede_after_the_binding_ended_concludes_nothing
    );

    /// I6603 runs on two nodes of one backend.
    mod i6603 {
        use super::*;

        #[cfg(feature = "sqlite")]
        #[tokio::test(flavor = "multi_thread")]
        async fn sqlite() {
            use crate::store::Backend as _;
            let a = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            a.run_migrations().await.unwrap();
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            bodies::i6603_a_report_before_its_binding_waits_then_lands(&a, &b, &tag("s")).await;
        }

        #[cfg(feature = "postgres")]
        #[tokio::test(flavor = "multi_thread")]
        async fn postgres() {
            use crate::store::Backend as _;
            let (Some(da), Some(db)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn())
            else {
                eprintln!("D1 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                return;
            };
            let a = crate::store::postgres::PostgresBackend::connect(&da)
                .await
                .unwrap();
            a.run_migrations().await.unwrap();
            let b = crate::store::postgres::PostgresBackend::connect(&db)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            bodies::i6603_a_report_before_its_binding_waits_then_lands(&a, &b, &tag("p")).await;
            eprintln!("i6603: RAN");
        }
    }
}
