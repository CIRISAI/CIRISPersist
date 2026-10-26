//! v60.1.0 (docs/V61_TASK_PLAN.md §2 slice B) — **the consumer asks**, each
//! witnessed on every backend through the doors a consumer calls.
//!
//! - **I1360 (CIRISPersist#1117; CC 4.2.6 / CC 4.5.1.2)** — the accord
//!   threshold is ONE function: `accord_threshold(n) = ⌊n/2⌋ + 1`, and the
//!   threshold this node reports over its standing roster is the one its
//!   co-scrub gate counts against. Two holder signatures confer over a roster
//!   of three (the reported `m` is 2) and do not over a roster of four (the
//!   reported `m` is 3); a roster id this node holds no key for counts toward
//!   neither.
//! - **I1361 (CIRISPersist#1119; CC 5.4.6 item 4)** — `infra:relay` is
//!   conferred on the accord plane exactly as `infra:serve` is: a key record
//!   claiming it under a two-of-three holder co-scrub reads `true` through
//!   `has_accord_conferred_role`, and the same claim scrubbed only by an
//!   out-of-roster key reads `false`. No new row kind.
//! - **I1362 (CIRISPersist#1064, CIRISEdge)** — the reason a door raises on
//!   `federation_dimension_rejected` classifies through persist's own
//!   predicate (`dimension_rejected_reason::is_retryable`): a self-report on a
//!   morally-charged stem is refused at `put_attestation`, its token is in the
//!   closed set and terminal, and a re-offer of the same bytes is refused the
//!   same way. (The key-grant twin rides I742's doors: `signer_not_minter`
//!   terminal, `recipient_not_in_audience` retryable.)
//! - **I1363 (CIRISPersist#1095, CIRISEdge; CC rc9)** — an A/V call record is
//!   one self-subject `chat:call:v1` row per attendee (attester = subject =
//!   the attendee), placed at the ROOM's scope like a chat row: (a) each
//!   member's row admits and a non-member's is refused; (b) a member reads the
//!   rows by subject, and the call's attendees are the union of subjects over
//!   the rows sharing a `call_id`, while a non-member reads none; (c) an
//!   attendee's own `withdraws` retracts their row and the other attendee's
//!   stands; nothing is superseded.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::{
        accord_threshold, accord_threshold_over_roster, has_accord_conferred_role_over_roster,
        AccordThreshold,
    };
    use crate::federation::operational::test_support::{
        confer_roles, register_accord_holder, signed_canonical_record_with_roles, Identity,
        PLACEHOLDER_SUBJECT_ED25519_BASE64,
    };
    use crate::federation::types::delegation_scope;
    use crate::federation::FederationDirectory;

    /// **I1360** — see the module doc.
    pub(crate) async fn i1360_accord_threshold_is_the_gates_threshold(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // The rule, by value: a strict majority, and an empty roster is
        // unreachable.
        for (n, m) in [
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (5, 3),
            (6, 4),
            (7, 4),
        ] {
            assert_eq!(accord_threshold(n), m, "I1360: accord_threshold({n})");
            assert!(2 * accord_threshold(n) > n, "I1360: strict majority of {n}");
        }

        // Three holders registered; a key co-scrubbed by two of them.
        let subject = format!("i1360-subject-{tag}");
        let roster = confer_roles(d, &subject, &["infra:serve"], &format!("i1360-{tag}"))
            .await
            .expect("I1360: the two-holder co-scrub stores");
        assert_eq!(roster.len(), 3);
        assert_eq!(
            accord_threshold_over_roster(d, &roster).await.unwrap(),
            AccordThreshold { m: 2, n: 3 },
            "I1360: three holders held here, two required"
        );
        assert!(
            has_accord_conferred_role_over_roster(d, &subject, "infra:serve", &roster)
                .await
                .unwrap(),
            "I1360: two of three meets the reported m = 2"
        );

        // A roster id this node holds no key for counts toward neither side.
        let mut with_unheld = roster.clone();
        with_unheld.push(format!("i1360-unheld-{tag}"));
        assert_eq!(
            accord_threshold_over_roster(d, &with_unheld).await.unwrap(),
            AccordThreshold { m: 2, n: 3 },
            "I1360: an unheld holder is not on the standing roster"
        );
        assert!(
            has_accord_conferred_role_over_roster(d, &subject, "infra:serve", &with_unheld)
                .await
                .unwrap(),
            "I1360: the gate counts the same standing roster"
        );

        // A fourth holder registered: the reported m moves to 3, and the same
        // two signatures no longer confer.
        let fourth = Identity::new(&format!("i1360-{tag}-h3"));
        register_accord_holder(d, &fourth).await.unwrap();
        let mut four = roster.clone();
        four.push(fourth.key_id.clone());
        assert_eq!(
            accord_threshold_over_roster(d, &four).await.unwrap(),
            AccordThreshold { m: 3, n: 4 },
            "I1360: four holders, three required"
        );
        assert!(
            !has_accord_conferred_role_over_roster(d, &subject, "infra:serve", &four)
                .await
                .unwrap(),
            "I1360: two of four is below the reported m = 3, and the gate agrees"
        );
    }

    /// **I1361** — see the module doc.
    pub(crate) async fn i1361_infra_relay_is_accord_conferred(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let relay = delegation_scope::INFRA_RELAY;
        let subject = format!("i1361-relay-{tag}");
        let roster = confer_roles(d, &subject, &[relay], &format!("i1361-{tag}"))
            .await
            .expect("I1361: the co-scrubbed relay standing stores");
        assert!(
            has_accord_conferred_role_over_roster(d, &subject, relay, &roster)
                .await
                .unwrap(),
            "I1361: a holder-co-scrubbed infra:relay reads conferred"
        );
        assert!(
            !has_accord_conferred_role_over_roster(
                d,
                &subject,
                delegation_scope::INFRA_SERVE,
                &roster
            )
            .await
            .unwrap(),
            "I1361: a relay standing is not a serve seat"
        );

        // The same claim, scrubbed only by a registered out-of-roster key.
        let self_id = format!("i1361-self-{tag}");
        let scrubber = Identity::new(&format!("i1361-selfscrub-{tag}"));
        register_accord_holder(d, &scrubber).await.unwrap();
        let record = signed_canonical_record_with_roles(
            &self_id,
            crate::federation::types::identity_type::NODE,
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            vec![relay.to_owned()],
            serde_json::json!({ "key_id": self_id }),
            &[&scrubber],
        );
        d.put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await
            .expect("I1361: a self-scrubbed record still stores");
        assert!(
            !has_accord_conferred_role_over_roster(d, &self_id, relay, &roster)
                .await
                .unwrap(),
            "I1361: a self-claimed infra:relay buys nothing"
        );
    }

    /// **I1362** — see the module doc.
    pub(crate) async fn i1362_a_dimension_refusal_classifies_terminal(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::dimension_rejected_reason;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::attestation_type;
        use crate::federation::{Error, SignedAttestation};

        let who = format!("i1362-{tag}");
        ts::register_hybrid_key(d, &who).await;
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({ "id": id, "dimension": "i1362x:deception_rate:v1" });
        let mut row = ts::bare_attestation(&id, &who, &who, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.subject_key_ids = vec![who.clone()];
        ts::seal_row_in_place(&who, &mut row);
        for attempt in ["first offer", "re-offer"] {
            let err = d
                .put_attestation(SignedAttestation {
                    attestation: row.clone(),
                })
                .await
                .expect_err("I1362: a morally-charged stem is refused");
            let Error::DimensionRejected { reason, .. } = err else {
                panic!("I1362 ({attempt}): expected DimensionRejected, got {err:?}");
            };
            assert_eq!(reason, "morally_charged_stem", "I1362 ({attempt})");
            assert_eq!(
                dimension_rejected_reason::is_retryable(reason),
                Some(false),
                "I1362 ({attempt}): the raised token is in the closed set and terminal"
            );
        }
        assert!(d.get_attestation(&id).await.unwrap().is_none());
    }

    /// **I1363** — see the module doc.
    pub(crate) async fn i1363_a_call_record_is_one_self_row_per_attendee(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_type, cohort_scope, Attestation};
        use crate::federation::SignedAttestation;
        use crate::read::{AttestationFilter, LifecycleView};

        let room = format!("chat:room:v1:i1363-{tag}");
        let (alice, bob, carol) = (
            format!("i1363-alice-{tag}"),
            format!("i1363-bob-{tag}"),
            format!("i1363-carol-{tag}"),
        );
        ts::register_hybrid_key(d, &room).await;
        for k in [&alice, &bob, &carol] {
            ts::register_user_role_key(d, k).await;
        }
        ts::seed_two_member_community(d, &room, &alice, &bob).await;
        let call_id = uuid::Uuid::new_v4().to_string();

        let call_row = |who: &str| -> Attestation {
            let id = uuid::Uuid::new_v4().to_string();
            let mut r = ts::bare_attestation(
                &id,
                who,
                who,
                &serde_json::json!({
                    "id": id,
                    "dimension": "chat:call:v1",
                    "call_id": call_id,
                    "community_key_id": room,
                    "started_at": "2026-10-26T12:00:00Z",
                }),
            );
            r.attestation_type = attestation_type::SCORES.to_owned();
            r.weight = None;
            r.cohort_scope = cohort_scope::COMMUNITY.to_owned();
            r.subject_key_ids = vec![who.to_owned()];
            ts::seal_row_in_place(who, &mut r);
            r
        };

        // (a) Each member's own row admits; a non-member's is refused.
        let (a_row, b_row) = (call_row(&alice), call_row(&bob));
        let (a_id, b_id) = (a_row.attestation_id.clone(), b_row.attestation_id.clone());
        for r in [a_row, b_row] {
            d.put_attestation(SignedAttestation { attestation: r })
                .await
                .unwrap_or_else(|e| panic!("I1363 (a): a member's chat:call:v1 row admits: {e}"));
        }
        let c_row = call_row(&carol);
        let c_id = c_row.attestation_id.clone();
        assert!(
            d.put_attestation(SignedAttestation { attestation: c_row })
                .await
                .is_err(),
            "I1363 (a): a non-member cannot place a call row in the room"
        );
        assert!(d.get_attestation(&c_id).await.unwrap().is_none());

        // (b) Read by subject, as a member and as a non-member.
        let by_subject = |subject: &str, lifecycle: LifecycleView| AttestationFilter {
            subject_key_id: Some(subject.to_owned()),
            dimension_prefixes: vec!["chat:call:".to_owned()],
            lifecycle,
            ..Default::default()
        };
        let read = |caller: String, subject: String, lifecycle: LifecycleView| {
            let filter = by_subject(&subject, lifecycle);
            async move {
                d.list_scores(&caller, filter, None, 50)
                    .await
                    .unwrap()
                    .items
                    .into_iter()
                    .map(|r| r.attestation_id)
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(
            read(bob.clone(), alice.clone(), LifecycleView::Live).await,
            vec![a_id.clone()],
            "I1363 (b): a member reads the other attendee's row by subject"
        );
        assert_eq!(
            read(alice.clone(), bob.clone(), LifecycleView::Live).await,
            vec![b_id.clone()],
            "I1363 (b): per attendee"
        );
        assert!(
            read(carol.clone(), alice.clone(), LifecycleView::Live)
                .await
                .is_empty(),
            "I1363 (b): a non-member reads no row of the room"
        );
        let mut attendees = std::collections::BTreeSet::new();
        for who in [&alice, &bob, &carol] {
            for id in read(alice.clone(), who.clone(), LifecycleView::Live).await {
                let row = d.get_attestation(&id).await.unwrap().unwrap();
                if row.attestation_envelope["call_id"] == serde_json::json!(call_id) {
                    attendees.extend(row.subject_key_ids);
                }
            }
        }
        assert_eq!(
            attendees,
            [alice.clone(), bob.clone()].into_iter().collect(),
            "I1363 (b): the attendees are the union of subjects over the call's rows"
        );

        // (c) Alice withdraws her own row; Bob's stands.
        ts::put_retraction(d, &alice, &alice, &a_id, attestation_type::WITHDRAWS)
            .await
            .unwrap_or_else(|e| panic!("I1363 (c): the attendee withdraws their own row: {e}"));
        assert!(
            read(bob.clone(), alice.clone(), LifecycleView::Live)
                .await
                .is_empty(),
            "I1363 (c): the withdrawn row is no longer live"
        );
        assert_eq!(
            read(bob.clone(), alice.clone(), LifecycleView::IncludeWithdrawn).await,
            vec![a_id.clone()],
            "I1363 (c): the row is retracted, not destroyed"
        );
        assert_eq!(
            read(alice.clone(), bob.clone(), LifecycleView::Live).await,
            vec![b_id.clone()],
            "I1363 (c): the other attendee's row stands"
        );
        // A non-subject cannot withdraw it.
        assert!(
            ts::put_retraction(d, &alice, &bob, &b_id, attestation_type::WITHDRAWS)
                .await
                .is_err(),
            "I1363 (c): nobody withdraws another attendee's row"
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
                        eprintln!("v601 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
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

    on_every_backend!(i1360, bodies::i1360_accord_threshold_is_the_gates_threshold);
    on_every_backend!(i1361, bodies::i1361_infra_relay_is_accord_conferred);
    on_every_backend!(i1362, bodies::i1362_a_dimension_refusal_classifies_terminal);
    on_every_backend!(
        i1363,
        bodies::i1363_a_call_record_is_one_self_row_per_attendee
    );

    /// v60.1.0 (CIRISPersist#1064) — **every `DimensionRejected` reason is
    /// classified exactly once.** The closed set holds each token once, the
    /// retryable set is inside it, an unknown token answers `None`, and every
    /// construction site in `src/` (comments stripped) raises a token
    /// expression this census names — a new token at a new site fails here.
    #[test]
    fn every_dimension_rejected_reason_is_classified_once() {
        use crate::federation::admission::{
            dimension_rejected_reason as dr, DimensionRejectionReason,
        };
        let mut seen = std::collections::BTreeSet::new();
        for t in dr::ALL {
            assert!(seen.insert(*t), "{t:?} listed twice");
            assert!(dr::is_retryable(t).is_some(), "{t:?}");
        }
        for t in dr::RETRYABLE {
            assert!(dr::ALL.contains(t), "{t:?} retryable but not in ALL");
        }
        for r in DimensionRejectionReason::ALL {
            assert!(dr::ALL.contains(&r.as_str()), "{r:?} unclassified");
        }
        assert_eq!(dr::ALL.len(), DimensionRejectionReason::ALL.len() + 3);
        assert_eq!(dr::is_retryable("registered_family_held_shut"), Some(false));
        assert_eq!(dr::is_retryable("not_a_reason"), None);

        // The construction sites, from disk.
        let known_exprs = [
            "LEDGER_BINDING_REASON",
            "REGISTERED_FAMILY_HELD_SHUT_REASON",
            "INVARIANT_SELF_EMISSION_REASON",
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![root];
        let mut sites = 0usize;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text: String = std::fs::read_to_string(&path)
                    .unwrap()
                    .lines()
                    .map(|l| l.split("//").next().unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join("\n");
                for (at, _) in text.match_indices("DimensionRejected {") {
                    let window = &text[at..(at + 400).min(text.len())];
                    let window = &window[..window.find('}').unwrap_or(window.len())];
                    let Some(r) = window.find("reason:") else {
                        continue; // a pattern, not a construction
                    };
                    let expr = window[r + "reason:".len()..]
                        .split(',')
                        .next()
                        .unwrap()
                        .trim();
                    if expr == "&'static str" {
                        continue; // the arm's declaration in `federation::Error`
                    }
                    sites += 1;
                    let named = known_exprs.contains(&expr)
                        || (expr.starts_with("DimensionRejectionReason::")
                            && expr.ends_with(".as_str()"));
                    assert!(
                        named,
                        "{}: DimensionRejected raises reason `{expr}`, which \
                         dimension_rejected_reason::ALL does not classify",
                        path.display()
                    );
                }
            }
        }
        assert!(
            sites >= 8,
            "the scan found {sites} construction sites — it is broken"
        );
    }
}
