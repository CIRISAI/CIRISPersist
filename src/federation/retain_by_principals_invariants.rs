//! CIRISPersist#1015 (ruled 2026-10-09) — I570: **a steward's `retain`
//! window naming the machine bounds the retention sweeps.** Both sweeps (the
//! fountain eviction door, `Engine::evict_fountain_content_by_consent`, and
//! the deletion-window watch) ask
//! [`retain_bound_by_principals`](super::consent_by_humans::retain_bound_by_principals):
//! the subject's own `retain` rows and each steward's `retain` rows naming the
//! subject in `for_key_id`, the MINIMUM live window, and the principal whose
//! window governed. Through v53 both folded the subject's rows alone and kept
//! content past a human's window. One body per invariant, generic over the
//! directory, run on memory, sqlite and postgres.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::consent_by_humans as cbh;
    use crate::federation::consent_scope_invariants::bodies::{at, put, row, stance};
    use crate::federation::deletion_window::{kind, run_deletion_window_watch};
    use crate::federation::hard_case::HardCaseFilter;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::{FederationDirectory, IdentityOccurrence};
    use crate::fountain::retention::{consent_retention_verdict, RetentionAction};

    const T0: &str = "2026-05-01T00:00:00Z";

    fn day(d: i64) -> chrono::DateTime<chrono::Utc> {
        at(T0) + chrono::Duration::days(d)
    }

    /// The parties: the holder (a node keeping content about the agent), the
    /// agent (the subject), its steward, and a sibling machine the same
    /// steward also stewards.
    pub(crate) struct Parties {
        pub holder: String,
        pub agent: String,
        pub steward: String,
        pub sibling: String,
    }

    pub(crate) async fn parties(d: &dyn FederationDirectory, tag: &str) -> Parties {
        let p = Parties {
            holder: format!("i570-holder-{tag}"),
            agent: format!("i570-agent-{tag}"),
            steward: format!("i570-steward-{tag}"),
            sibling: format!("i570-sib-{tag}"),
        };
        ts::register_identity_key(d, &p.holder, NODE).await;
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
            "I570 precondition: the steward stands behind the agent"
        );
        p
    }

    /// `consent:state:granted:v1` by `author` to the holder, scope
    /// `retain:<window>`, optionally FOR `for_key`, optionally expiring.
    async fn retain(
        d: &dyn FederationDirectory,
        id: &str,
        author: &str,
        holder: &str,
        window: &str,
        for_key: Option<&str>,
        expires: Option<&str>,
    ) {
        let extras = match for_key {
            Some(k) => serde_json::json!({ cbh::FOR_KEY_ID: k }),
            None => serde_json::json!({}),
        };
        put(
            d,
            stance(
                id,
                author,
                holder,
                "granted",
                serde_json::json!(format!("retain:{window}")),
                extras,
                T0,
                expires,
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("I570: retain row {id} admits: {e}"));
    }

    /// Who signed a `retain` row in a case.
    #[derive(Clone, Copy)]
    enum Who {
        Agent,
        Steward,
    }
    /// What the row names in `for_key_id`.
    #[derive(Clone, Copy)]
    enum For {
        Nobody,
        Agent,
        Sibling,
    }
    /// Whose window must govern.
    #[derive(Clone, Copy, Debug)]
    enum Gov {
        Agent,
        Steward,
    }

    /// **I570a — the four ruled cases, through the eviction verdict.** For
    /// each: the bound is the expected principal's window, the verdict keeps
    /// the content the day before it ends and hard-deletes it the day after,
    /// and `governed_by` names that principal.
    pub async fn i570a_the_minimum_live_window_governs_eviction(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        type Seed = (Who, &'static str, For, Option<&'static str>);
        let cases: &[(&str, &[Seed], i64, Gov)] = &[
            (
                "steward-shorter",
                &[
                    (Who::Agent, "90d", For::Nobody, None),
                    (Who::Steward, "30d", For::Agent, None),
                ],
                30,
                Gov::Steward,
            ),
            (
                "machine-shorter",
                &[
                    (Who::Agent, "10d", For::Nobody, None),
                    (Who::Steward, "30d", For::Agent, None),
                ],
                10,
                Gov::Agent,
            ),
            (
                // The steward's 5d row expired (signed `expires_at`) on day 2:
                // it bounds nothing, so the machine's 30d governs.
                "steward-row-expired",
                &[
                    (Who::Agent, "30d", For::Nobody, None),
                    (Who::Steward, "5d", For::Agent, Some("2026-05-03T00:00:00Z")),
                ],
                30,
                Gov::Agent,
            ),
            (
                "steward-row-names-a-sibling",
                &[
                    (Who::Agent, "30d", For::Nobody, None),
                    (Who::Steward, "5d", For::Sibling, None),
                ],
                30,
                Gov::Agent,
            ),
            (
                "steward-row-names-nobody",
                &[
                    (Who::Agent, "30d", For::Nobody, None),
                    (Who::Steward, "5d", For::Nobody, None),
                ],
                30,
                Gov::Agent,
            ),
        ];
        for (n, (case, seeds, ends, gov)) in cases.iter().enumerate() {
            let p = parties(d, &format!("a{n}-{s}")).await;
            for (i, (who, window, for_key, expires)) in seeds.iter().enumerate() {
                let author = match who {
                    Who::Agent => &p.agent,
                    Who::Steward => &p.steward,
                };
                let for_key = match for_key {
                    For::Nobody => None,
                    For::Agent => Some(p.agent.as_str()),
                    For::Sibling => Some(p.sibling.as_str()),
                };
                retain(
                    d,
                    &format!("i570a-{n}-{i}-{s}"),
                    author,
                    &p.holder,
                    window,
                    for_key,
                    *expires,
                )
                .await;
            }
            let want_gov = match gov {
                Gov::Agent => &p.agent,
                Gov::Steward => &p.steward,
            };
            let (before, bound) =
                consent_retention_verdict(d, &p.holder, &p.agent, false, day(ends - 1))
                    .await
                    .unwrap();
            assert_eq!(
                bound.stance.retain_until,
                Some(day(*ends)),
                "I570a {case}: the bound is the {gov:?}'s window"
            );
            assert_eq!(
                bound.governed_by.as_deref(),
                Some(want_gov.as_str()),
                "I570a {case}: governed_by names the {gov:?}"
            );
            assert!(
                !before.is_hard_delete(),
                "I570a {case}: kept the day before the window ends ({before:?})"
            );
            let (after, _) = consent_retention_verdict(d, &p.holder, &p.agent, true, day(ends + 1))
                .await
                .unwrap();
            assert_eq!(
                after,
                RetentionAction::HardDelete,
                "I570a {case}: deleted the day after, rare or not"
            );
        }
    }

    /// **I570b — the deletion-window watch records the breach at the
    /// steward's window, and its audit row names the steward.** The holder
    /// keeps a row about the agent; the agent allows 90 days, the steward 30
    /// for this machine. On day 31 the row is a breach; the subject-only fold
    /// saw no breach until day 91.
    pub async fn i570b_the_watch_breaches_at_the_stewards_window(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let p = parties(d, &format!("b-{s}")).await;
        let held_id = format!("i570b-held-{s}");
        put(
            d,
            row(
                &held_id,
                &p.holder,
                &p.agent,
                serde_json::json!({"id": held_id, "dimension": "i570b:held:v1", "score": 1.0,
                    crate::federation::envelope::paths::ASSERTED_AT: at(T0).to_rfc3339()}),
                vec![p.agent.clone()],
                at(T0),
                None,
            ),
        )
        .await
        .expect("I570b: the held row admits");
        retain(
            d,
            &format!("i570b-own-{s}"),
            &p.agent,
            &p.holder,
            "90d",
            None,
            None,
        )
        .await;
        retain(
            d,
            &format!("i570b-st-{s}"),
            &p.steward,
            &p.holder,
            "30d",
            Some(&p.agent),
            None,
        )
        .await;
        let early = run_deletion_window_watch(d, day(29)).await.unwrap();
        assert_eq!(early.retain_window_breaches, 0, "I570b: day 29, no breach");
        let late = run_deletion_window_watch(d, day(31)).await.unwrap();
        assert_eq!(
            late.retain_window_breaches, 1,
            "I570b: day 31, past the steward's window, the held row is a breach"
        );
        let events = d
            .list_hard_case_events(HardCaseFilter {
                kind: Some(kind::RETAIN_WINDOW_BREACH.to_owned()),
                since: None,
            })
            .await
            .unwrap();
        let ev = events
            .iter()
            .find(|e| e.detail["attestation_id"] == held_id)
            .unwrap_or_else(|| panic!("I570b: the breach row is recorded: {events:?}"));
        assert_eq!(
            ev.detail["retain_governed_by"], p.steward,
            "I570b: the audit row names the steward whose window governed"
        );
        assert_eq!(ev.detail["retain_until"], day(30).to_rfc3339());
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
                async fn i570a() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i570a_the_minimum_live_window_governs_eviction(&b, &super::suffix())
                        .await
                }
                #[tokio::test]
                async fn i570b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i570b_the_watch_breaches_at_the_stewards_window(&b, &super::suffix())
                        .await
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

    /// **I570c — from disk: both sweeps ask the principal bound.** The
    /// Engine's eviction door runs `consent_retention_verdict` (which asks
    /// `retain_bound_by_principals`), and the deletion-window watch asks
    /// `retain_bound_by_principals`; neither folds the subject alone.
    #[test]
    fn i570c_both_sweeps_ask_the_principal_bound() {
        const ENGINE: &str = include_str!("../engine.rs");
        const WATCH: &str = include_str!("deletion_window.rs");
        const RET: &str = include_str!("../fountain/retention.rs");
        let strip = |body: &str| -> String {
            body.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let body_of = |src: &str, sig: &str, end: &str| -> String {
            let b = src.split(sig).nth(1).unwrap_or_else(|| panic!("{sig}"));
            strip(&b[..b.find(end).expect("end")])
        };
        let e = body_of(
            ENGINE,
            "pub async fn evict_fountain_content_by_consent(",
            "\n    }\n",
        );
        assert!(
            e.contains("retention::consent_retention_verdict("),
            "I570c: the eviction door runs the shared verdict"
        );
        assert!(
            !e.contains("resolve_scoped_stance(") && !e.contains("resolve_consent_state("),
            "I570c: the eviction door re-spells a fold"
        );
        let v = body_of(RET, "pub async fn consent_retention_verdict(", "\n}\n");
        assert!(
            v.contains("consent_by_humans::retain_bound_by_principals("),
            "I570c: the verdict asks the principal bound"
        );
        let w = body_of(WATCH, "pub async fn run_deletion_window_watch(", "\n}\n");
        assert!(
            w.contains("consent_by_humans::retain_bound_by_principals("),
            "I570c: the watch asks the principal bound"
        );
        assert!(
            !w.contains("resolve_scoped_stance("),
            "I570c: the watch folds the subject alone again"
        );
    }
}
