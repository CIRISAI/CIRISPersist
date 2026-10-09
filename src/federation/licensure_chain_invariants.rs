//! v54.0.0 (CIRISPersist#1032, #1035; ruled at #1036 items 1 and 2) — **the
//! licensure chain, judged at the licence's signed instant.**
//!
//! A `licensure:{A}` row issued by a key other than `A` names the
//! `delegates_to` edge it was issued under (`delegation_id`). Two properties:
//!
//! 1. **#1032 — the chain is judged at the row's signed `asserted_at`.** Every
//!    link must be live at that instant: asserted by it, not expired at it,
//!    its signed term (`delegation_valid_from` / `delegation_valid_until` /
//!    `valid_until`) open at it, and not retracted by it. So a term-bound
//!    officer lapses, an edge valid at issuance but expired at receipt still
//!    admits, and a later withdrawal never reclassifies a licence already
//!    issued. The instant-less `license` / `grant` reachability read judges
//!    NOW, never the timeless graph.
//! 2. **#1035 — the gate and the fold use ONE chain function.** The door
//!    refuses what the fold would exclude and the fold finds what the door
//!    admitted: a two-hop delegate's issuance is FOUND, and the named edge
//!    must be a live `license` edge onto the emitter on that chain.
//!
//! Every assertion names the mutant it kills (see the CHANGELOG entry).
//!
//! The rows are the adopter's shape (CIRISRegistry FSD-005 §7.2 / CSD-122): a
//! `scores` row on the SUBJECT key, `dimension: licensure:{A}:v1`, a `status`,
//! and `delegation_id` naming the `license` edge when the issuer is a
//! delegate. Officers are `primitive` keys: a `user → user` `delegates_to` is
//! a steward-binding and the CC 3.2 gate refuses it, independently of scope.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub mod bodies {
    use crate::federation::admission::steward_liveness_test_support::{
        bare_edge_retraction, register, signed_row, store,
    };
    use crate::federation::admission::{
        reachable_under_scope, DELEGATION_SCOPE_GRANT, DELEGATION_SCOPE_LICENSE,
        DELEGATION_VALID_FROM_FIELD, DELEGATION_VALID_UNTIL_FIELD, MAX_MODERATION_DELEGATION_DEPTH,
    };
    use crate::federation::licensure::{status_set_for, LicensureStatus};
    use crate::federation::tier_ingest::test_support::reseal;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{Attestation, Error, FederationDirectory};
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use std::collections::BTreeSet;

    /// The refusal token the door must carry.
    pub(crate) const REFUSAL: &str = "licensure_delegator_not_authority";

    /// A wall-clock base truncated to the substrate's resolution, so the
    /// instants a fixture chooses are the instants a backend stores.
    pub(crate) fn base() -> DateTime<Utc> {
        Utc::now().trunc_subsecs(3)
    }

    /// `delegates_to(granter → recipient)` carrying `scopes`, signed at
    /// `asserted_at`, with any extra envelope members (a term, sub-delegation).
    pub(crate) fn edge(
        granter: &str,
        recipient: &str,
        scopes: &[&str],
        asserted_at: DateTime<Utc>,
        extra: &[(&str, serde_json::Value)],
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "id": id,
            "scope": scopes.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        });
        for (k, v) in extra {
            envelope[*k] = v.clone();
        }
        let mut row = signed_row(granter, recipient, attestation_type::DELEGATES_TO, envelope);
        row.subject_key_ids = vec![recipient.to_owned()];
        row.asserted_at = asserted_at;
        row.scrub_timestamp = asserted_at;
        reseal(&mut row);
        row
    }

    /// The adopter's licence row: `scores` on the subject, `licensure:{A}:v1`,
    /// a status, and (when issued by a delegate) the edge it was issued under.
    pub(crate) fn licence(
        issuer: &str,
        holder: &str,
        authority: &str,
        status: &str,
        delegation_id: Option<&str>,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "id": id,
            "dimension": format!("licensure:{authority}:v1"),
            "status": status,
            "score": 1.0,
            "confidence": 0.9,
        });
        if let Some(d) = delegation_id {
            envelope["delegation_id"] = serde_json::Value::String(d.to_owned());
        }
        let mut row = signed_row(issuer, holder, attestation_type::SCORES, envelope);
        row.asserted_at = asserted_at;
        row.scrub_timestamp = asserted_at;
        reseal(&mut row);
        row
    }

    /// Store `row` and read it back AS STORED.
    pub(crate) async fn put(
        dir: &dyn FederationDirectory,
        row: &Attestation,
    ) -> Result<Attestation, Error> {
        store(dir, row).await?;
        Ok(dir
            .get_attestation(&row.attestation_id)
            .await?
            .expect("a stored row reads back"))
    }

    pub(crate) async fn must_put(
        dir: &dyn FederationDirectory,
        row: &Attestation,
        what: &str,
    ) -> Attestation {
        put(dir, row)
            .await
            .unwrap_or_else(|e| panic!("{what}: {e}"))
    }

    /// `row` is refused with the licensure refusal, and nothing was stored.
    pub(crate) async fn must_refuse(dir: &dyn FederationDirectory, row: &Attestation, what: &str) {
        let err = put(dir, row)
            .await
            .expect_err(&format!("{what}: must be refused at the door"));
        assert!(
            format!("{err}").contains(REFUSAL),
            "{what}: refused, but not by the licensure gate: {err}"
        );
        assert!(
            dir.get_attestation(&row.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "{what}: a refused row must not be stored"
        );
    }

    pub(crate) async fn keys(dir: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let authority = format!("{tag}-board");
        let holder = format!("{tag}-holder");
        register(dir, &authority, &[identity_type::USER]).await;
        register(dir, &holder, &[identity_type::USER]).await;
        (authority, holder)
    }

    pub(crate) async fn officer(dir: &dyn FederationDirectory, tag: &str, name: &str) -> String {
        let k = format!("{tag}-{name}");
        register(dir, &k, &[identity_type::PRIMITIVE]).await;
        k
    }

    pub(crate) fn rfc3339(t: DateTime<Utc>) -> serde_json::Value {
        serde_json::Value::String(t.to_rfc3339())
    }

    /// #1032 — **a term-bound officer lapses for licence authority, judged at
    /// the licence's signed `asserted_at`.**
    pub async fn exercise_term_bound_officer_lapses_for_licence(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (board, holder) = keys(dir, tag).await;
        let now = base();
        let (t_edge, t_term_end) = (now - Duration::hours(3), now - Duration::hours(1));

        // An officer appointed three hours ago for a two-hour term.
        let clerk = officer(dir, tag, "clerk").await;
        let term = must_put(
            dir,
            &edge(
                &board,
                &clerk,
                &[DELEGATION_SCOPE_LICENSE],
                t_edge,
                &[(DELEGATION_VALID_UNTIL_FIELD, rfc3339(t_term_end))],
            ),
            "the board appoints a term-bound licensing officer",
        )
        .await;

        // (a) Issued INSIDE the term, received now (after the term): ADMITS.
        // Kills: judging at receipt (`as_of = now`).
        let in_term = licence(
            &clerk,
            &holder,
            &board,
            "issued",
            Some(&term.attestation_id),
            now - Duration::hours(2),
        );
        must_put(
            dir,
            &in_term,
            &format!(
                "[{tag}] #1032: a licence signed while the officer's term was open is the \
                 board's licence even though the term has closed by receipt"
            ),
        )
        .await;
        assert_eq!(
            status_set_for(dir, &holder, &board, Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] #1032: the fold judges the same instant the door did — the in-term \
             issuance is in the board's licensure"
        );

        // (b) Issued AFTER the term closed: REFUSED.
        // Kills: dropping the term from the lens; dropping the lens.
        must_refuse(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "probation",
                Some(&term.attestation_id),
                now,
            ),
            &format!("[{tag}] #1032: an officer whose `delegation_valid_until` has passed"),
        )
        .await;

        // (c) Signed BEFORE the edge existed: REFUSED.
        // Kills: dropping the lens (`asserted_at <= t` on the edge).
        must_refuse(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "restricted",
                Some(&term.attestation_id),
                now - Duration::hours(4),
            ),
            &format!("[{tag}] #1032: a licence dated before the appointment"),
        )
        .await;

        // (d) A FUTURE term (`delegation_valid_from` after issuance): REFUSED.
        // Kills: dropping the `delegation_valid_from` arm.
        let deputy = officer(dir, tag, "deputy").await;
        let future = must_put(
            dir,
            &edge(
                &board,
                &deputy,
                &[DELEGATION_SCOPE_LICENSE],
                t_edge,
                &[(
                    DELEGATION_VALID_FROM_FIELD,
                    rfc3339(now + Duration::hours(1)),
                )],
            ),
            "the board appoints an officer whose term starts in an hour",
        )
        .await;
        must_refuse(
            dir,
            &licence(
                &deputy,
                &holder,
                &board,
                "issued",
                Some(&future.attestation_id),
                now,
            ),
            &format!("[{tag}] #1032: an officer whose term has not begun"),
        )
        .await;

        // (e) The `valid_until` spelling (CC 2.1) closes a term the same way.
        // Kills: reading only `delegation_valid_until`.
        let temp = officer(dir, tag, "temp").await;
        let old_spelling = must_put(
            dir,
            &edge(
                &board,
                &temp,
                &[DELEGATION_SCOPE_LICENSE],
                t_edge,
                &[("valid_until", rfc3339(t_term_end))],
            ),
            "the board appoints an officer with a `valid_until` term",
        )
        .await;
        must_refuse(
            dir,
            &licence(
                &temp,
                &holder,
                &board,
                "issued",
                Some(&old_spelling.attestation_id),
                now,
            ),
            &format!("[{tag}] #1032: an officer whose `valid_until` has passed"),
        )
        .await;

        // (f) A term nobody can read is not an open term (fail toward LESS
        // authority). Kills: treating a malformed term as absent.
        let odd = officer(dir, tag, "odd").await;
        let malformed = must_put(
            dir,
            &edge(
                &board,
                &odd,
                &[DELEGATION_SCOPE_LICENSE],
                t_edge,
                &[(
                    DELEGATION_VALID_UNTIL_FIELD,
                    serde_json::json!("next tuesday"),
                )],
            ),
            "the door stores an edge whose term is unreadable (the lens judges it)",
        )
        .await;
        must_refuse(
            dir,
            &licence(
                &odd,
                &holder,
                &board,
                "issued",
                Some(&malformed.attestation_id),
                now,
            ),
            &format!("[{tag}] #1032: an officer whose term is unreadable"),
        )
        .await;
    }

    /// #1032 — **a later withdrawal stops future issuance and does not
    /// reclassify a licence already issued** (#1036 ruling item 2).
    pub async fn exercise_withdrawal_does_not_reclassify_issued_licence(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (board, holder) = keys(dir, tag).await;
        let now = base();
        let clerk = officer(dir, tag, "clerk").await;
        let appointment = must_put(
            dir,
            &edge(
                &board,
                &clerk,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(3),
                &[],
            ),
            "the board appoints a licensing officer",
        )
        .await;
        must_put(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "issued",
                Some(&appointment.attestation_id),
                now - Duration::hours(2),
            ),
            "the officer licenses the holder",
        )
        .await;

        // The board withdraws the officer now (the §11.10 edge retraction).
        must_put(
            dir,
            &bare_edge_retraction(&board, &clerk),
            "the board withdraws the officer",
        )
        .await;

        // Kills: the fold resolving the CURRENT graph.
        assert_eq!(
            status_set_for(dir, &holder, &board, Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] #1032: withdrawing the officer must not reclassify the licence the \
             officer issued while appointed — the authority ends it with `suspended` / \
             `revoked`, not by withdrawing a link"
        );

        // Future issuance stops. Kills: judging the gate on a stale instant.
        must_refuse(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "probation",
                Some(&appointment.attestation_id),
                base() + Duration::seconds(1),
            ),
            &format!("[{tag}] #1032: an officer issuing after the withdrawal"),
        )
        .await;
    }

    /// #1032 — **the `grant` walk honours the term too.** The instant-less
    /// read judges NOW: a lapsed term, or one not yet begun, confers nothing.
    pub async fn exercise_grant_walk_honours_the_term(dir: &dyn FederationDirectory, tag: &str) {
        let (owner, _) = keys(dir, tag).await;
        let now = base();
        let reach = |to: String| {
            let owner = owner.clone();
            async move {
                reachable_under_scope(
                    dir,
                    &owner,
                    &to,
                    DELEGATION_SCOPE_GRANT,
                    MAX_MODERATION_DELEGATION_DEPTH,
                )
                .await
                .expect("reachable_under_scope")
            }
        };

        let live = officer(dir, tag, "live").await;
        must_put(
            dir,
            &edge(
                &owner,
                &live,
                &[DELEGATION_SCOPE_GRANT],
                now - Duration::hours(1),
                &[(
                    DELEGATION_VALID_UNTIL_FIELD,
                    rfc3339(now + Duration::hours(1)),
                )],
            ),
            "a grant officer inside the term",
        )
        .await;
        assert!(
            reach(live).await,
            "[{tag}] #1032: control — an open term confers `grant`"
        );

        let lapsed = officer(dir, tag, "lapsed").await;
        must_put(
            dir,
            &edge(
                &owner,
                &lapsed,
                &[DELEGATION_SCOPE_GRANT],
                now - Duration::hours(3),
                &[(
                    DELEGATION_VALID_UNTIL_FIELD,
                    rfc3339(now - Duration::hours(1)),
                )],
            ),
            "a grant officer whose term closed",
        )
        .await;
        assert!(
            !reach(lapsed).await,
            "[{tag}] #1032: a lapsed `grant` term confers nothing — the instant-less read \
             judges NOW, never the timeless graph"
        );

        let early = officer(dir, tag, "early").await;
        must_put(
            dir,
            &edge(
                &owner,
                &early,
                &[DELEGATION_SCOPE_GRANT],
                now - Duration::hours(1),
                &[(
                    DELEGATION_VALID_FROM_FIELD,
                    rfc3339(now + Duration::hours(1)),
                )],
            ),
            "a grant officer whose term has not begun",
        )
        .await;
        assert!(
            !reach(early).await,
            "[{tag}] #1032: a term that has not begun confers nothing"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    /// One `#[tokio::test]` per backend for each body.
    macro_rules! on_every_backend {
        ($body:ident, $memory:ident, $sqlite:ident, $postgres:ident, $prefix:literal) => {
            #[tokio::test]
            async fn $memory() {
                let d = crate::store::memory::MemoryBackend::new();
                super::bodies::$body(&d, &format!("{}-{}", $prefix, suffix())).await;
            }

            #[cfg(feature = "sqlite")]
            #[tokio::test]
            async fn $sqlite() {
                use crate::store::Backend as _;
                let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                super::bodies::$body(&b, &format!("{}-{}", $prefix, suffix())).await;
            }

            #[cfg(feature = "postgres")]
            #[tokio::test]
            async fn $postgres() {
                use crate::store::Backend as _;
                let Some(dsn) = crate::test_pg::empty_dsn() else {
                    return;
                };
                let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                super::bodies::$body(&b, &format!("{}-{}", $prefix, suffix())).await;
            }
        };
    }

    on_every_backend!(
        exercise_term_bound_officer_lapses_for_licence,
        term_bound_officer_lapses_for_licence_1032_memory,
        term_bound_officer_lapses_for_licence_1032_sqlite,
        term_bound_officer_lapses_for_licence_1032_postgres,
        "lic-term"
    );
    on_every_backend!(
        exercise_withdrawal_does_not_reclassify_issued_licence,
        withdrawal_does_not_reclassify_issued_licence_1032_memory,
        withdrawal_does_not_reclassify_issued_licence_1032_sqlite,
        withdrawal_does_not_reclassify_issued_licence_1032_postgres,
        "lic-wd"
    );
    on_every_backend!(
        exercise_grant_walk_honours_the_term,
        grant_walk_honours_the_term_1032_memory,
        grant_walk_honours_the_term_1032_sqlite,
        grant_walk_honours_the_term_1032_postgres,
        "grant-term"
    );
}
