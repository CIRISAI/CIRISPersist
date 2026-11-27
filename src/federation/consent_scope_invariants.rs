//! CIRISPersist#866 / #867 — witnesses for `FSD/CONTEXTUAL_INTEGRITY_ENVELOPE.md`
//! §7 (I104–I111): the consent scope token grammar, the covering rule, the
//! `retain:<window>` bound, the transfer grant's `principle`, and the
//! substrate-emitted `consent:state:expired` row. One body per invariant,
//! generic over the directory, run by every backend that folds consent
//! (memory, sqlite, postgres), so the three cannot diverge; the engine-level
//! bodies (the promoter, the expiry sweep) run on sqlite.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::consent::ScopedStance;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::ConsentState;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
    use crate::federation::{admission, Attestation, FederationDirectory};

    /// A federation-tier row signed by `signer` over `envelope`, targeting
    /// `target`, with `subject_key_ids`.
    ///
    /// v62.0.0 (JSON cut, E5) — an edition-2 statement signed by `signer`'s
    /// composite (a seed, or an identity-ref `e2::put_key` returned), mapped
    /// through the door ([`e2::row_of`]): its `attestation_id` is the
    /// node-computed row id ([`e2::rid`]), never `id`.
    pub(crate) fn row(
        id: &str,
        signer: &str,
        target: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
        at: chrono::DateTime<chrono::Utc>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Attestation {
        let r = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        e2::row_of(&r, signer)
    }

    pub(crate) fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        admission::truncate_to_substrate_resolution(s.parse().unwrap())
    }

    /// `consent:state:<stance>:v1` by `subject` about `target`, the `scope`
    /// member exactly as given (string, array, or anything else), plus
    /// `extras` merged into the envelope. (Eight arguments on purpose: a
    /// witness fixture spells every axis it sets.)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stance(
        id: &str,
        subject: &str,
        target: &str,
        stance: &str,
        scope: serde_json::Value,
        extras: serde_json::Value,
        asserted: &str,
        expires: Option<&str>,
    ) -> Attestation {
        let asserted = at(asserted);
        let mut env = serde_json::json!({
            "id": id,
            "dimension": format!("consent:state:{stance}:v1"),
            crate::federation::envelope::paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(asserted),
        });
        // A `null` scope is a row with no scope member (absent, never `null`).
        if !scope.is_null() {
            env["scope"] = scope;
        }
        if let (Some(obj), Some(extra)) = (env.as_object_mut(), extras.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        row(
            id,
            subject,
            target,
            env,
            Vec::new(),
            asserted,
            expires.map(at),
        )
    }

    /// v62.0.0 (JSON cut, E5) — the row's carried edition-2 statement through
    /// the one entry (`e2::put_signed` → `ingest::put_statement`), which runs
    /// every attestation gate the JSON door ran.
    pub(crate) async fn put(
        d: &dyn FederationDirectory,
        a: Attestation,
    ) -> Result<(), crate::federation::Error> {
        e2::put_signed(d, &a).await.map(|_| ())
    }

    /// E5-fix1 (round 3) — the fold reason a put row is HELD with, `None`
    /// when it landed. v62 GC1 (CC 2.7.3): the subject's consent is other
    /// rows, so a score short of it is held `consent_gate_refused` (and
    /// re-folds when a grant lands), never refused (ruling 5: assert the
    /// wait).
    pub(crate) async fn held_reason(d: &dyn FederationDirectory, a: Attestation) -> Option<String> {
        use crate::federation::edition2::{fold, ingest::StatementOutcome};
        match e2::put_signed(d, &a).await.expect("the row is offered") {
            StatementOutcome::Pending { row_id, .. } => Some(
                fold::why_held(d, &row_id)
                    .await
                    .expect("why held")
                    .expect("a held row carries its reason")
                    .reason,
            ),
            _ => None,
        }
    }

    /// **I104 — the door refuses a malformed scope token by name, and admits
    /// a well-formed non-canonical kind.**
    pub async fn i104_the_door_refuses_malformed_tokens(d: &dyn FederationDirectory, s: &str) {
        let (subject, target) = (format!("i104-s-{s}"), format!("i104-t-{s}"));
        let subject = e2::put_key(d, &subject, &[USER]).await;
        let target = e2::put_key(d, &target, &[USER]).await;
        let refused: &[(&str, serde_json::Value, &str)] = &[
            ("retain-window", serde_json::json!("retain:soon"), "retain"),
            (
                "share-cohort",
                serde_json::json!(["share:cohort:everyone"]),
                "everyone",
            ),
            (
                "analyze-two",
                serde_json::json!("analyze:capacity:extra"),
                "analyze",
            ),
            ("upper", serde_json::json!("Share"), "Share"),
            ("empty-seg", serde_json::json!("share::x"), "share::x"),
            ("bad-char", serde_json::json!("view:a b"), "view:a b"),
        ];
        for (n, scope, names) in refused {
            let a = stance(
                &format!("i104-{n}-{s}"),
                &subject,
                &target,
                "granted",
                scope.clone(),
                serde_json::json!({}),
                "2026-05-01T00:00:00Z",
                None,
            );
            let err = put(d, a)
                .await
                .expect_err(&format!("I104: `{scope}` is refused at the ingest door"));
            assert_eq!(
                err.kind(),
                "federation_consent_scope_token_invalid",
                "I104: typed refusal for `{scope}`: {err}"
            );
            assert!(
                err.to_string().contains(names),
                "I104: the refusal names the offending token `{names}`: {err}"
            );
        }
        // The local door, too.
        let local = crate::federation::types::LocalAttestationInput {
            attestation_id: Some(format!("i104-local-{s}")),
            attesting_key_id: subject.clone(),
            attested_key_id: Some(target.clone()),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({
                    "dimension": "consent:state:granted:v1",
                    "scope": "retain:soon",
                }),
            )
            .unwrap(),
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let err = d
            .attestation_upsert_local(local)
            .await
            .expect_err("I104: the local door refuses a malformed token too");
        assert_eq!(err.kind(), "federation_consent_scope_token_invalid");

        // Well-formed: the five canonical kinds with their sub forms, and a
        // non-canonical kind (Server's `view`) with a generic sub.
        for (n, scope) in [
            (
                "canon",
                serde_json::json!([
                    "retain:90d",
                    "share:cohort:family",
                    "analyze:capacity",
                    "train:x",
                    "publish"
                ]),
            ),
            ("view", serde_json::json!("view")),
            ("view-sub", serde_json::json!("view:x-y:z_1")),
            ("junk-shape", serde_json::json!(5)),
        ] {
            put(
                d,
                stance(
                    &format!("i104-ok-{n}-{s}"),
                    &subject,
                    &target,
                    "granted",
                    scope.clone(),
                    serde_json::json!({}),
                    "2026-05-01T00:00:00Z",
                    None,
                ),
            )
            .await
            .unwrap_or_else(|e| panic!("I104: `{scope}` is admitted: {e}"));
        }
        // And an unknown kind is not persist's to veto.
        assert_eq!(
            d.resolve_scoped_consent(
                &target,
                &subject,
                "view:x-y",
                None,
                at("2026-06-01T00:00:00Z")
            )
            .await
            .unwrap(),
            ConsentState::Granted,
            "I104: a bare `view` grant covers `view:x-y` under the generic rule"
        );
    }

    /// **I106 — `retain:<window>` is a lifecycle bound, not a match criterion.**
    pub async fn i106_retain_window_is_a_bound(d: &dyn FederationDirectory, s: &str) {
        let (subject, target) = (format!("i106-s-{s}"), format!("i106-t-{s}"));
        let subject = e2::put_key(d, &subject, &[USER]).await;
        let target = e2::put_key(d, &target, &[USER]).await;
        put(
            d,
            stance(
                &format!("i106-g1-{s}"),
                &subject,
                &target,
                "granted",
                serde_json::json!(["retain:1d", "share"]),
                serde_json::json!({}),
                "2026-05-01T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        let t = |h: i64| at("2026-05-01T00:00:00Z") + chrono::Duration::hours(h);
        let within = d
            .resolve_scoped_stance(&target, &subject, "retain", None, t(1))
            .await
            .unwrap();
        assert_eq!(
            within,
            ScopedStance {
                state: ConsentState::Granted,
                retain_until: Some(t(24)),
            },
            "I106: within the window the stance is Granted and names its bound"
        );
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "retain", None, t(1))
                .await
                .unwrap(),
            ConsentState::Granted
        );
        let lapsed = d
            .resolve_scoped_stance(&target, &subject, "retain", None, t(48))
            .await
            .unwrap();
        assert_eq!(
            lapsed,
            ScopedStance {
                state: ConsentState::Expired,
                retain_until: Some(t(24)),
            },
            "I106: past the window the retain stance is Expired, bound still named"
        );
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "retain", None, t(48))
                .await
                .unwrap(),
            ConsentState::Expired,
            "I106: the old door agrees"
        );
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "share", None, t(48))
                .await
                .unwrap(),
            ConsentState::Granted,
            "I106: the window bounds `retain` only; `share` on the same row is untouched"
        );
        // A later, longer window extends.
        put(
            d,
            stance(
                &format!("i106-g2-{s}"),
                &subject,
                &target,
                "granted",
                serde_json::json!("retain:3d"),
                serde_json::json!({}),
                "2026-05-02T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            d.resolve_scoped_stance(&target, &subject, "retain", None, t(48))
                .await
                .unwrap(),
            ScopedStance {
                state: ConsentState::Granted,
                retain_until: Some(t(24 + 72)),
            },
            "I106: a later retain:3d extends the bound"
        );
    }

    /// **I106b — the deletion-window watch honours a lapsed retain window
    /// on the rows the target holds about the subject.**
    pub async fn i106b_the_watch_honours_the_retain_window(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::deletion_window::{kind, run_deletion_window_watch};
        let (subject, producer) = (format!("i106b-s-{s}"), format!("i106b-p-{s}"));
        let subject = e2::put_key(d, &subject, &[USER]).await;
        let producer = e2::put_key(d, &producer, &[USER]).await;
        // The producer holds a row ABOUT the subject, with no deletion_window.
        // v62.0.0 (E5) — a registered dimension: the edition-2 door refuses
        // open vocabulary (`i106b:held:v1` was one).
        let held = row(
            &format!("i106b-held-{s}"),
            &producer,
            &subject,
            serde_json::json!({"id": format!("i106b-held-{s}"), "dimension": "coherence_standing:cab:v1", "score": 1.0,
                crate::federation::envelope::paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(at("2026-05-01T00:00:00Z"))}),
            vec![subject.clone()],
            at("2026-05-01T00:00:00Z"),
            None,
        );
        let held_id = e2::rid(&held);
        put(d, held).await.unwrap();
        // The subject lets the producer retain for one day.
        put(
            d,
            stance(
                &format!("i106b-g-{s}"),
                &subject,
                &producer,
                "granted",
                serde_json::json!("retain:1d"),
                serde_json::json!({}),
                "2026-05-01T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        let t = |h: i64| at("2026-05-01T00:00:00Z") + chrono::Duration::hours(h);
        let early = run_deletion_window_watch(d, t(1)).await.unwrap();
        assert_eq!(
            early.retain_window_breaches, 0,
            "I106b: within the window, no breach"
        );
        let late = run_deletion_window_watch(d, t(48)).await.unwrap();
        assert_eq!(
            late.retain_window_breaches, 1,
            "I106b: past the window, the held row is a breach"
        );
        let filter = || crate::federation::hard_case::HardCaseFilter {
            kind: Some(kind::RETAIN_WINDOW_BREACH.to_owned()),
            since: None,
            emitter_key_id: None,
        };
        let events = d.list_hard_case_events(filter()).await.unwrap();
        assert!(
            events.iter().any(|e| e.detail["subject_key_id"] == subject
                && e.detail["attestation_id"] == held_id
                && e.detail["basis"] == "retain_window"),
            "I106b: the breach names the row, the subject and its basis: {events:?}"
        );
        let again = run_deletion_window_watch(d, t(49)).await.unwrap();
        assert_eq!(
            again.retain_window_breaches, 1,
            "I106b: counted again, recorded once"
        );
        assert_eq!(
            d.list_hard_case_events(filter())
                .await
                .unwrap()
                .iter()
                .filter(|e| e.detail["attestation_id"] == held_id)
                .count(),
            1,
            "I106b: idempotent on the deterministic event id"
        );
    }

    /// **I107 — the CC's literal composition pattern is inert, and pinned so.**
    pub async fn i107_the_cc_literal_pattern_is_inert(d: &dyn FederationDirectory, s: &str) {
        let (subject, target) = (format!("i107-s-{s}"), format!("i107-t-{s}"));
        let subject = e2::put_key(d, &subject, &[USER]).await;
        let target = e2::put_key(d, &target, &[USER]).await;
        // A bare granted row + a `consent:scope:analyze` companion row.
        put(
            d,
            stance(
                &format!("i107-bare-{s}"),
                &subject,
                &target,
                "granted",
                serde_json::Value::Null,
                serde_json::json!({}),
                "2026-05-01T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        put(
            d,
            row(
                &format!("i107-companion-{s}"),
                &subject,
                &target,
                serde_json::json!({"id": format!("i107-companion-{s}"), "dimension": "consent:scope:analyze:v1", "score": 1.0,
                    crate::federation::envelope::paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(at("2026-05-01T00:00:00Z"))}),
                Vec::new(),
                at("2026-05-01T00:00:00Z"),
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "analyze", None, at("2026-06-01T00:00:00Z"))
                .await
                .unwrap(),
            ConsentState::Unspecified,
            "I107: a companion row confers nothing; the envelope member is the carrier (CIRISConstitution#103)"
        );
    }

    /// **I111 — a substrate-emitted `consent:state:expired` row enters the
    /// fold only through a resolved edge to the subject's own lapsed grant.**
    pub async fn i111_an_expired_row_enters_only_through_its_edge(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (subject, target, node, stranger) = (
            format!("i111-s-{s}"),
            format!("i111-t-{s}"),
            format!("i111-n-{s}"),
            format!("i111-x-{s}"),
        );
        let subject = e2::put_key(d, &subject, &[USER]).await;
        let target = e2::put_key(d, &target, &[USER]).await;
        let node = e2::put_key(d, &node, &[USER]).await;
        let stranger = e2::put_key(d, &stranger, &[USER]).await;
        let grant = stance(
            &format!("i111-g-{s}"),
            &subject,
            &target,
            "granted",
            serde_json::json!("share"),
            serde_json::json!({}),
            "2026-05-01T00:00:00Z",
            Some("2026-05-02T00:00:00Z"),
        );
        // v62.0.0 (E5) — an expired row's edge names the grant's row id.
        let g = e2::rid(&grant);
        put(d, grant).await.unwrap();
        let now = at("2026-05-03T00:00:00Z");
        let expired = |id: &str, by: &str, names: Option<&str>, asserted: &str| {
            let mut extras = serde_json::json!({});
            if let Some(n) = names {
                extras[crate::federation::envelope::paths::CONSENT_SUPERSEDES] =
                    serde_json::Value::String(n.to_owned());
            }
            stance(
                id,
                by,
                &target,
                "expired",
                serde_json::json!("share"),
                extras,
                asserted,
                None,
            )
        };
        // (a) no edge → ignored.
        put(
            d,
            expired(
                &format!("i111-e-noedge-{s}"),
                &node,
                None,
                "2026-05-02T00:00:01Z",
            ),
        )
        .await
        .unwrap();
        // (b) an edge to a grant the subject did not author → ignored.
        let other_grant = stance(
            &format!("i111-og-{s}"),
            &stranger,
            &target,
            "granted",
            serde_json::json!("share"),
            serde_json::json!({}),
            "2026-05-01T00:00:00Z",
            Some("2026-05-02T00:00:00Z"),
        );
        let other_g = e2::rid(&other_grant);
        put(d, other_grant).await.unwrap();
        put(
            d,
            expired(
                &format!("i111-e-other-{s}"),
                &node,
                Some(&other_g),
                "2026-05-02T00:00:01Z",
            ),
        )
        .await
        .unwrap();
        // (c) an edge to the subject's grant, asserted BEFORE it lapsed → ignored (early expiry).
        put(
            d,
            expired(
                &format!("i111-e-early-{s}"),
                &node,
                Some(&g),
                "2026-05-01T12:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "share", None, at("2026-05-01T18:00:00Z"))
                .await
                .unwrap(),
            ConsentState::Granted,
            "I111: before the lapse, three unbound/early expired rows change nothing"
        );
        // (d) the real one: an edge to the subject's grant, asserted at/after its lapse.
        put(
            d,
            expired(
                &format!("i111-e-bound-{s}"),
                &node,
                Some(&g),
                "2026-05-02T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "share", None, now)
                .await
                .unwrap(),
            ConsentState::Expired,
            "I111: the bound expired row ends the grant it names"
        );
        // (e) a later fresh grant re-opens (the edge ends THAT grant, not the subject's future).
        put(
            d,
            stance(
                &format!("i111-g2-{s}"),
                &subject,
                &target,
                "granted",
                serde_json::json!("share"),
                serde_json::json!({}),
                "2026-05-04T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "share", None, at("2026-05-05T00:00:00Z"))
                .await
                .unwrap(),
            ConsentState::Granted,
            "I111: a later grant re-opens consent"
        );
    }

    /// **I112 — the capacity gate asks `analyze:capacity`: a grant narrowed
    /// to another family does not cover it; a bare grant and a grant narrowed
    /// to this family do.**
    pub async fn i112_the_gate_honours_the_family_narrowing(d: &dyn FederationDirectory, s: &str) {
        let (scorer, subject) = (format!("i112-p-{s}"), format!("i112-s-{s}"));
        let scorer = e2::put_key(d, &scorer, &[USER]).await;
        let subject = e2::put_key(d, &subject, &[USER]).await;
        let score = |n: &str| {
            let id = format!("i112-score-{n}-{s}");
            let env = serde_json::json!({"id": id, "dimension": "capacity:core_identity:v1", "score": 1.0, "confidence": 0.9,
                crate::federation::envelope::paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(at("2026-05-02T00:00:00Z"))});
            let mut r = row(
                &id,
                &scorer,
                &subject,
                env,
                Vec::new(),
                at("2026-05-02T00:00:00Z"),
                None,
            );
            r.weight = Some(1.0);
            // v62.0.0 (E5) — `weight` is not carried by the mapping (E0.api
            // §3); the re-seal is kept so the row's column is re-derived.
            ts::reseal(&mut r);
            r
        };
        assert_eq!(
            held_reason(d, score("none")).await.as_deref(),
            Some(crate::federation::edition2::fold::reason::gc1::CONSENT_GATE_REFUSED),
            "I112: no consent, no score (held)"
        );
        // Narrowed to a DIFFERENT family: still refused.
        put(
            d,
            stance(
                &format!("i112-g-trust-{s}"),
                &subject,
                &scorer,
                "granted",
                serde_json::json!("analyze:trust"),
                serde_json::json!({}),
                "2026-05-01T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            held_reason(d, score("trust")).await.as_deref(),
            Some(crate::federation::edition2::fold::reason::gc1::CONSENT_GATE_REFUSED),
            "I112: `analyze:trust` does not cover capacity scoring (held)"
        );
        // Narrowed to THIS family: admitted.
        put(
            d,
            stance(
                &format!("i112-g-cap-{s}"),
                &subject,
                &scorer,
                "granted",
                serde_json::json!("analyze:capacity"),
                serde_json::json!({}),
                "2026-05-01T00:00:01Z",
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            held_reason(d, score("cap")).await,
            None,
            "I112: `analyze:capacity` covers it"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    /// E5-fix3 (round 6; CP2) — **a LOCAL-tier `trace:complete:v1` as an
    /// edition-2 statement**, the setup row the sweep witnesses promote. The
    /// earlier fixture wrote an unsigned row through `attestation_insert_local`;
    /// at the shut doors an unsigned trace never crosses
    /// (`ingest::refuse_unsigned_trace_crossing`, P7's ruling), so the sweep
    /// skipped it. This one is signed by an `agent` key (a trace is authored by
    /// its agent, CC 3.1.5 R4), names its blob by `manifest` (the
    /// `trace:{form}:{version}` payload), is dated inside the agent key's
    /// window, and crosses on its own statement
    /// (`TierPromotionCustody::of_statement`). Returns its row id.
    async fn e2_local_trace(
        d: &dyn crate::federation::FederationDirectory,
        agent_seed: &str,
        trace_id: &str,
    ) -> String {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
        let agent = e2::put_key(d, agent_seed, &["agent"]).await;
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(e2::key_window_start_ms(agent_seed) + 150 * 86_400_000).expect("ms"),
        )
        .expect("an instant");
        let literal = crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: agent.clone(),
            attested_key_id: agent.clone(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": "trace:complete:v1",
                "trace_id": trace_id,
                "agent_id_hash": format!("agent-hash-{trace_id}"),
                "manifest": {
                    "schema": "trace_manifest:v1",
                    "content_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "byte_len": 2_000_000,
                    "component_count": 16,
                },
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: agent.clone(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![agent.clone()],
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope::SELF.to_owned(),
            tier: attestation_tier::LOCAL.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        let row = e2::row_of(&literal, agent_seed);
        e2::put_signed(d, &row)
            .await
            .unwrap_or_else(|e| panic!("the local trace {trace_id} lands: {e}"));
        e2::rid(&row)
    }

    /// **I105 — the covering rule, per kind.**
    #[test]
    fn i105_the_covering_rule() {
        use crate::federation::consent_scope::{covers, parse_scope_token as p};
        let c = |g: &str, q: &str| covers(&p(g).unwrap(), &p(q).unwrap());
        // share: a narrowing in the cohort widening order.
        assert!(
            c("share", "share:cohort:family"),
            "a bare grant is the widest"
        );
        assert!(c("share", "share"));
        assert!(c("share:cohort:family", "share:cohort:family"));
        assert!(c("share:cohort:family", "share:cohort:self"));
        assert!(
            !c("share:cohort:family", "share"),
            "a bare ask means federation"
        );
        assert!(!c("share:cohort:family", "share:cohort:community"));
        assert!(
            c("share:cohort:federation", "share"),
            "cohort:federation IS the widest"
        );
        // analyze: an information-type narrowing.
        assert!(c("analyze", "analyze:capacity"));
        assert!(c("analyze:capacity", "analyze:capacity"));
        assert!(!c("analyze:capacity", "analyze"));
        assert!(!c("analyze:capacity", "analyze:trust"));
        // retain: a bound, never a match criterion.
        assert!(c("retain:90d", "retain"));
        assert!(c("retain", "retain"));
        assert!(
            c("retain:1h", "retain:90d"),
            "the window is not compared; the sweep reads it"
        );
        // kinds never cross.
        assert!(!c("share", "analyze"));
        assert!(!c("retain", "share"));
        // non-canonical: generic hierarchical narrowing, persist assigns no meaning.
        assert!(c("view", "view:x"));
        assert!(c("view:x", "view:x:y"));
        assert!(!c("view:x", "view"));
        assert!(!c("view:x", "view:z"));
        assert!(c("train", "train:anything:at:all"));
        assert!(!c("train:a", "train"));
        // retain_until is derived from the grant's own instant.
        let g = p("retain:90d").unwrap();
        let t0: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        assert_eq!(
            crate::federation::consent_scope::retain_until(&g, t0),
            Some(t0 + chrono::Duration::days(90))
        );
        assert_eq!(
            crate::federation::consent_scope::retain_until(&p("retain").unwrap(), t0),
            None
        );
        assert_eq!(
            crate::federation::consent_scope::retain_until(&p("share").unwrap(), t0),
            None
        );
        // the parser's refusals are typed and name the token.
        for bad in [
            "",
            "Share",
            "retain:soon",
            "retain:0d",
            "share:cohort:everyone",
            "share:x",
            "analyze:a:b",
            "view:a b",
            "share::x",
            ":share",
        ] {
            let e = p(bad).expect_err(bad);
            assert!(e.to_string().contains(bad) || bad.is_empty(), "{bad}: {e}");
        }
    }

    /// **I106c — a lapsed retain window is a withdrawal the subject signed
    /// in advance: the retention verdict is HardDelete, rare or not.**
    #[test]
    fn i106c_a_lapsed_window_is_withdrawal_for_retention() {
        use crate::federation::consent::ScopedStance;
        use crate::federation::hard_case::ConsentState;
        use crate::fountain::{retention_action_with_retain_window, RetentionAction};
        let t0: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        let live = ScopedStance {
            state: ConsentState::Granted,
            retain_until: Some(t0 + chrono::Duration::days(1)),
        };
        let lapsed = ScopedStance {
            state: ConsentState::Expired,
            retain_until: Some(t0 + chrono::Duration::days(1)),
        };
        let none = ScopedStance {
            state: ConsentState::Unspecified,
            retain_until: None,
        };
        let later = t0 + chrono::Duration::days(2);
        assert_eq!(
            retention_action_with_retain_window(ConsentState::Granted, &live, t0, true),
            RetentionAction::RetainRare
        );
        assert_eq!(
            retention_action_with_retain_window(ConsentState::Granted, &lapsed, later, true),
            RetentionAction::HardDelete,
            "rare does not outrank a signed bound"
        );
        assert_eq!(
            retention_action_with_retain_window(ConsentState::Granted, &lapsed, later, false),
            RetentionAction::HardDelete
        );
        assert_eq!(
            retention_action_with_retain_window(ConsentState::Granted, &none, later, false),
            RetentionAction::RetainNonRare,
            "no window: the all-scope stance decides, as before"
        );
        assert_eq!(
            retention_action_with_retain_window(ConsentState::Revoked, &none, later, true),
            RetentionAction::HardDelete,
            "revocation still overrides rarity"
        );
    }

    /// **I110 — from disk: one matcher, one spelling of the kinds, and the
    /// gate on every door.**
    #[test]
    fn i110_one_matcher_every_door() {
        const SCOPE: &str = include_str!("consent_scope.rs");
        const CONSENT: &str = include_str!("consent.rs");
        const TYPES: &str = include_str!("types.rs");
        const ADMISSION: &str = include_str!("admission.rs");
        const SQLITE: &str = include_str!("../store/sqlite.rs");
        const PG: &str = include_str!("../store/postgres.rs");
        assert_eq!(
            SCOPE.matches("pub fn covers(").count(),
            1,
            "I110: one covering rule"
        );
        assert!(
            CONSENT.contains("consent_scope::covers(") || CONSENT.contains("covers("),
            "I110: the fold matches through it"
        );
        assert!(
            !CONSENT.contains("named.contains(&scope)"),
            "I110: exact-equality matching is gone"
        );
        for kind in ["retain", "share", "analyze", "train", "publish"] {
            assert_eq!(
                TYPES.matches(&format!("= \"{kind}\";")).count(),
                1,
                "I110: `{kind}` is spelled once, in transmission_principle"
            );
            assert!(
                !SCOPE.contains(&format!("\"{kind}\"")),
                "I110: consent_scope.rs reaches `{kind}` through the vocabulary, not a literal"
            );
        }
        assert!(
            !CONSENT.contains("consent:scope"),
            "I107/I110: no fold selects a consent:scope:* companion row"
        );
        // v56.0.0 (CIRISPersist#934 step 1) — the ingest door's gate lives in
        // the shared attestation plan, once; each backend's
        // `put_attestation_with_origin` is a call into it (held there by
        // `store::parity::shared_doors_decide_nothing_in_a_backend`). The local
        // door's plan (door 2) runs it there too: two calls, one file.
        const ADMIT: &str = include_str!("attestation_admit.rs");
        for (name, text, n) in [
            ("attestation_admit.rs", ADMIT, 2),
            ("admission.rs", ADMISSION, 1),
        ] {
            let calls = text.matches("check_consent_scope_tokens(").count();
            assert!(calls >= n, "I110: {name} calls the scope-token gate at its doors ({calls} < {n}: the shared ingest plan; local per backend; promotion)");
        }
        // Every backend's ingest and local doors are the shared doors.
        for (name, text) in [("sqlite.rs", SQLITE), ("postgres.rs", PG)] {
            for door in [
                "attestation_admit::put_attestation_planned(",
                "attestation_admit::write_local_attestation_planned(",
            ] {
                assert!(
                    text.contains(door),
                    "I110: {name}'s attestation door is not the shared `{door}`"
                );
            }
        }
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i104() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i104_the_door_refuses_malformed_tokens(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i106() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i106_retain_window_is_a_bound(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i106b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i106b_the_watch_honours_the_retain_window(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i107() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i107_the_cc_literal_pattern_is_inert(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i111() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i111_an_expired_row_enters_only_through_its_edge(&b, &super::suffix())
                        .await
                }
                #[tokio::test]
                async fn i112() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i112_the_gate_honours_the_family_narrowing(&b, &super::suffix()).await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "inv-node").await;
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
        crate::federation::hard_case::test_support::declare_node(&b, "inv-node").await;
        Some(b)
    });

    /// **I108 — the promoter reads `principle`: only `share` / `publish`
    /// propagate, and the report names what it declined.**
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i108_the_promoter_declines_by_principle() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_tier, cohort_scope};
        use crate::federation::FederationDirectory;
        let run = suffix();
        let engine =
            crate::Engine::with_signer(ts::local_signer(&format!("i108-{run}")), "sqlite::memory:")
                .await
                .unwrap();
        let node = engine
            .register_self_federation_key("primitive", None, None)
            .await
            .unwrap();
        let sq = engine.sqlite_backend().unwrap().clone();
        let _ = &node;
        let row_id = e2_local_trace(
            sq.as_ref(),
            &format!("i108-agent-{run}"),
            &format!("i108-{run}"),
        )
        .await;
        // One grant per PEER: the V109 projection keys `(node, peer)`, so a
        // second grant to the same peer replaces the first and it is no longer
        // live — the two principles must name different peers to coexist.
        let grant = |principle: &str| {
            let envelope = crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
                "dimension": crate::federation::consent_peer_set::DIMENSION,
                "subject_key_ids": [format!("i108-peer-{principle}-{run}")],
                "payload": {"grants": "replication", "attestation_prefixes": ["trace:"], "audience": "federation", "principle": principle},
                "subject_kind": "consent_replication",
            })).unwrap();
            let mut input = crate::federation::EmitAttestationInput::with_envelope(
                crate::federation::types::attestation_type::SCORES,
                envelope,
                cohort_scope::FEDERATION,
            );
            input.subject_key_ids = vec![format!("i108-peer-{principle}-{run}")];
            input
        };
        engine
            .emit_attestation_self(grant("train"))
            .await
            .expect("a train grant is grammar-legal");
        let report = engine.promote_consented_backlog().await.unwrap();
        assert_eq!(report.promoted, 0, "I108: a `train` grant promotes nothing");
        assert_eq!(
            report.declined_by_principle, 1,
            "I108: and the report says so"
        );
        assert_eq!(
            sq.get_attestation(&row_id).await.unwrap().unwrap().tier,
            attestation_tier::LOCAL,
            "I108: the row stayed local"
        );
        engine.emit_attestation_self(grant("share")).await.unwrap();
        let report = engine.promote_consented_backlog().await.unwrap();
        assert_eq!(
            report.declined_by_principle, 1,
            "I108: the train grant is still declined, by name"
        );
        // E5-fix1 (round 3) — `share` propagates: the row CROSSES. v62 P8
        // crosses an edition-2 local row in place (its own statement) and
        // RESTATES an earlier-form one as a new federation row (the local
        // row stays local, `Crossed` names the stated row), so the witness is
        // the sweep's own count, not the local row's tier.
        assert_eq!(report.promoted, 1, "I108: `share` propagates: {report:?}");
        // E5-fix3 — the setup row is an edition-2 local statement, so it
        // crosses on its own statement, in place.
        assert_eq!(
            sq.get_attestation(&row_id).await.unwrap().unwrap().tier,
            attestation_tier::FEDERATION,
            "I108: `share` propagates the row itself"
        );
    }

    /// **v50.0.0 (CIRISPersist#924 review, MEDIUM-3) — a grant-covered row on
    /// a shape the CC 3.1.7 R3 grammar refuses is COUNTED, not silently
    /// passed over.** One local row on a pre-rc5 shape (`trace:complete`, no
    /// version segment) and one conformant sibling, both under a `share`
    /// grant on `trace:`: the conformant row crosses, the old-shape row stays
    /// local and the report names it. Consent only ever narrows onto the
    /// grammar; this is what makes the narrowing visible.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sweep_counts_grant_covered_rows_the_grammar_refuses_924() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_tier, cohort_scope};
        use crate::federation::FederationDirectory;
        let run = suffix();
        let engine =
            crate::Engine::with_signer(ts::local_signer(&format!("u924-{run}")), "sqlite::memory:")
                .await
                .unwrap();
        let node = engine
            .register_self_federation_key("primitive", None, None)
            .await
            .unwrap();
        let sq = engine.sqlite_backend().unwrap().clone();
        let _ = &node;
        // A row stored BEFORE v50 on a pre-rc5 shape: v50's own door refuses
        // the unversioned shape, so the row is written conformant and its
        // stored dimension rewritten underneath, as a v49 store holds it.
        // E5-fix3 — both rows are edition-2 local statements (`e2_local_trace`).
        let old_id = e2_local_trace(
            sq.as_ref(),
            &format!("u924-agent-o-{run}"),
            &format!("u924-old-{run}"),
        )
        .await;
        sq.rewrite_dimension_for_test(&old_id, "trace:complete");
        let new_id = e2_local_trace(
            sq.as_ref(),
            &format!("u924-agent-n-{run}"),
            &format!("u924-new-{run}"),
        )
        .await;
        let envelope = crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
            "dimension": crate::federation::consent_peer_set::DIMENSION,
            "subject_key_ids": [format!("u924-peer-{run}")],
            "payload": {"grants": "replication", "attestation_prefixes": ["trace:"],
                        "audience": "federation", "principle": "share"},
            "subject_kind": "consent_replication",
        }))
        .unwrap();
        let mut input = crate::federation::EmitAttestationInput::with_envelope(
            crate::federation::types::attestation_type::SCORES,
            envelope,
            cohort_scope::FEDERATION,
        );
        input.subject_key_ids = vec![format!("u924-peer-{run}")];
        engine.emit_attestation_self(input).await.unwrap();

        let report = engine.promote_consented_backlog().await.unwrap();
        assert_eq!(report.skipped_unmatched_dimension, 1, "{report:?}");
        assert_eq!(
            report.unmatched_dimension_examples,
            vec!["trace:complete".to_owned()]
        );
        assert_eq!(
            sq.get_attestation(&old_id).await.unwrap().unwrap().tier,
            attestation_tier::LOCAL,
            "the old-shape row is not promoted"
        );
        // E5-fix3 — the conformant sibling CROSSES on its own statement, in
        // place.
        assert_eq!(report.promoted, 1, "its conformant sibling is: {report:?}");
        assert_eq!(
            sq.get_attestation(&new_id).await.unwrap().unwrap().tier,
            attestation_tier::FEDERATION,
            "its conformant sibling is"
        );
    }

    /// **I109 — the sweep records a lapsed grant as `consent:state:expired`
    /// with its edge, signed by the node, once.**
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i109_the_sweep_records_expiry_with_its_edge() {
        use super::bodies::{at, put, stance};
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::hard_case::ConsentState;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::USER;
        use crate::federation::FederationDirectory;
        let run = suffix();
        let engine =
            crate::Engine::with_signer(ts::local_signer(&format!("i109-{run}")), "sqlite::memory:")
                .await
                .unwrap();
        let node = engine
            .register_self_federation_key("primitive", None, None)
            .await
            .unwrap();
        let sq = engine.sqlite_backend().unwrap().clone();
        let d: &dyn FederationDirectory = sq.as_ref();
        let (subject, target) = (format!("i109-s-{run}"), format!("i109-t-{run}"));
        let subject = e2::put_key(d, &subject, &[USER]).await;
        let target = e2::put_key(d, &target, &[USER]).await;
        let grant = stance(
            &format!("i109-g-{run}"),
            &subject,
            &target,
            "granted",
            serde_json::json!(["share", "retain:1d"]),
            serde_json::json!({"content_class": "medical"}),
            "2026-05-01T00:00:00Z",
            Some("2026-05-03T00:00:00Z"),
        );
        // v62.0.0 (E5) — the expired row's edge names the grant's row id.
        let g = e2::rid(&grant);
        put(d, grant).await.unwrap();
        // Before any lapse: nothing to record.
        let r = engine
            .run_consent_expiry_sweep(at("2026-05-01T12:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            (r.grants_seen, r.lapsed, r.emitted),
            (1, 0, 0),
            "I109: {r:?}"
        );
        // The retain window (1d) lapses before expires_at (2d): the EARLIER bound is the lapse.
        let r = engine
            .run_consent_expiry_sweep(at("2026-05-02T06:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            (r.lapsed, r.emitted, r.already_recorded),
            (1, 1, 0),
            "I109: {r:?}"
        );
        let expired: Vec<_> = d
            .all_attestations_for(&target)
            .await
            .unwrap()
            .into_iter()
            .filter(|a| {
                crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                    .is_some_and(|x| x.starts_with("consent:state:expired"))
            })
            .collect();
        assert_eq!(expired.len(), 1, "I109: one expired row");
        let e = &expired[0];
        assert_eq!(
            e.attesting_key_id, node,
            "I109: signed by the node — substrate-emitted (CC 3.3.1)"
        );
        assert_eq!(
            e.attestation_envelope[crate::federation::envelope::paths::CONSENT_SUPERSEDES],
            g,
            "I109: names the grant it ends"
        );
        assert_eq!(
            e.attestation_envelope["scope"],
            serde_json::json!(["share", "retain:1d"]),
            "I109: the scope is carried over"
        );
        assert_eq!(e.attestation_envelope["content_class"], "medical");
        // E5-fix3 (CC 2.6.2) — the record's instant is its SIGNER's (the node
        // signs when it saw the lapse), never the lapse itself, which precedes
        // this node's key; the fold binds it only when asserted at or after
        // the lapse.
        assert!(
            e.asserted_at >= at("2026-05-02T00:00:00Z"),
            "I109: asserted when the node signed, at or after the lapse: {}",
            e.asserted_at
        );
        assert_eq!(
            e.subject_key_ids,
            vec![subject.clone()],
            "I109: the subject whose consent lapsed is the data subject"
        );
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "share", None, at("2026-05-02T06:00:00Z"))
                .await
                .unwrap(),
            ConsentState::Expired
        );
        // Idempotent.
        let r = engine
            .run_consent_expiry_sweep(at("2026-05-04T00:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            (r.lapsed, r.emitted, r.already_recorded),
            (1, 0, 1),
            "I109: recorded once: {r:?}"
        );
        // A later grant re-opens; the sweep leaves it alone until IT lapses.
        put(
            d,
            stance(
                &format!("i109-g2-{run}"),
                &subject,
                &target,
                "granted",
                serde_json::json!("share"),
                serde_json::json!({}),
                "2026-05-05T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            d.resolve_scoped_consent(&target, &subject, "share", None, at("2026-05-06T00:00:00Z"))
                .await
                .unwrap(),
            ConsentState::Granted
        );
        let r = engine
            .run_consent_expiry_sweep(at("2026-05-06T00:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            (r.grants_seen, r.lapsed, r.emitted),
            (2, 1, 0),
            "I109: {r:?}"
        );
    }
}
