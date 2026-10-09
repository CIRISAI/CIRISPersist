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
//!    officer lapses, and a later withdrawal never reclassifies a licence
//!    already issued. The instant-less `license` / `grant` reachability read
//!    judges NOW, never the timeless graph.
//!
//!    **#1049 — in this cut the DOOR also judges at receipt.** With no
//!    past-freshness window on `asserted_at`, the signed instant alone lets
//!    a withdrawn officer date a licence inside their old term. So the door
//!    requires the chain at receipt AND at the signed instant: a licence
//!    signed in term but received after it is REFUSED here, and a backdated
//!    licence from a withdrawn officer or a departed founder is refused. The
//!    FOLD keeps the signed instant: it reads only rows the door admitted.
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
        licences_issued_under, licensure_issuance_at, reachable_under_scope,
        resolve_licensure_authority, LicensureChainBreak, LicensureIssuance,
        DELEGATION_SCOPE_GRANT, DELEGATION_SCOPE_LICENSE, DELEGATION_VALID_FROM_FIELD,
        DELEGATION_VALID_UNTIL_FIELD, MAX_MODERATION_DELEGATION_DEPTH,
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

        // (a) Issued INSIDE the term, received now (after the term). The
        // CC-ruled signed-instant rule admits it, but in this cut the door
        // also judges at receipt (#1049: no past-freshness window yet), so it
        // is REFUSED, and the fold has nothing to count.
        // Kills: the door judging at the signed instant alone.
        let in_term = licence(
            &clerk,
            &holder,
            &board,
            "issued",
            Some(&term.attestation_id),
            now - Duration::hours(2),
        );
        must_refuse(
            dir,
            &in_term,
            &format!(
                "[{tag}] #1049: a licence signed while the officer's term was open but \
                 received after it closed is refused at receipt in this cut"
            ),
        )
        .await;
        assert_eq!(
            status_set_for(dir, &holder, &board, Utc::now())
                .await
                .expect("fold"),
            BTreeSet::new(),
            "[{tag}] #1049: a refused licence is not in the board's licensure"
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

    /// #1049 — **a backdated licence is refused at receipt.** Without a
    /// past-freshness window, the signed `asserted_at` is the signer's to
    /// choose. Both bypasses are closed by the door's receipt check:
    ///
    /// - (a) an officer the board has WITHDRAWN dates a licence inside the
    ///   appointment's old live window;
    /// - (b) a founder who has LEFT a `founder_only` affiliation dates a direct
    ///   issuance inside their tenure (refused `not_authority_at_receipt`).
    ///
    /// - (c) the door still judges at the signed instant too: a licence dated
    ///   before an open-ended appointment existed is refused, so the door
    ///   never admits a row the fold would exclude.
    ///
    /// Kills: the door judging at the signed `asserted_at` alone (arms (a)
    /// and (b) admit), dropping the authority-at-receipt clause (arm (b)
    /// admits), and dropping the signed-instant verdict (arm (c) admits).
    pub async fn exercise_backdated_licence_is_refused_at_receipt(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::room_roster_authority_invariants::bodies::make_group;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{consensus_protocol, CommunityMembershipRevocation};
        let (board, holder) = keys(dir, tag).await;
        let now = base();

        // (a) The withdrawn officer.
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
            &bare_edge_retraction(&board, &clerk),
            "the board withdraws the officer",
        )
        .await;
        must_refuse(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "issued",
                Some(&appointment.attestation_id),
                now - Duration::hours(2),
            ),
            &format!(
                "[{tag}] #1049: a withdrawn officer dating a licence inside the old \
                 appointment"
            ),
        )
        .await;

        // (c) The door ALSO judges at the signed instant, so it never admits
        // a row the fold would exclude: a licence dated before an open-ended
        // appointment existed is live at receipt and refused.
        // Kills: the door dropping its signed-instant verdict.
        let registrar = officer(dir, tag, "registrar").await;
        let open_ended = must_put(
            dir,
            &edge(
                &board,
                &registrar,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(1),
                &[],
            ),
            "the board appoints an open-ended officer",
        )
        .await;
        must_refuse(
            dir,
            &licence(
                &registrar,
                &holder,
                &board,
                "issued",
                Some(&open_ended.attestation_id),
                now - Duration::hours(2),
            ),
            &format!("[{tag}] #1049: a licence dated before the appointment existed"),
        )
        .await;

        // (b) The departed founder. alice and carol found a founder_only
        // affiliation; alice leaves an hour ago, then dates a direct issuance
        // two hours ago, when she was still a founder.
        let (aff, k) = make_group(
            dir,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["alice", "carol", "bob"],
            2,
            None,
            None,
        )
        .await;
        let alice = k[0].clone();
        let at_leave = now - Duration::hours(1);
        dir.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &alice,
            CommunityMembershipRevocation {
                community_key_id: aff.clone(),
                removed_identity_key_id: alice.clone(),
                removed_at: at_leave,
                effective_at: at_leave,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] alice leaves (carol remains a founder): {e}"));
        let backdated = licence(
            &alice,
            &holder,
            &aff,
            "issued",
            None,
            now - Duration::hours(2),
        );
        let err = put(dir, &backdated)
            .await
            .expect_err("a departed founder's backdated issuance must be refused");
        assert!(
            format!("{err}").contains(REFUSAL)
                && format!("{err}")
                    .contains(crate::federation::admission::LICENSURE_NOT_AUTHORITY_AT_RECEIPT),
            "[{tag}] #1049: refused as not the authority at receipt: {err}"
        );
        assert!(
            dir.get_attestation(&backdated.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "[{tag}] #1049: the refused row is not stored"
        );
        // Over-refusal control: a current founder's direct issuance admits.
        must_put(
            dir,
            &licence(
                &k[1],
                &holder,
                &aff,
                "issued",
                None,
                now - Duration::minutes(30),
            ),
            "a current founder issues directly",
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

    /// `row` is refused by the licensure gate with `reason`'s token.
    pub(crate) async fn must_refuse_as(
        dir: &dyn FederationDirectory,
        row: &Attestation,
        reason: LicensureChainBreak,
        what: &str,
    ) {
        let err = put(dir, row)
            .await
            .expect_err(&format!("{what}: must be refused at the door"));
        let text = format!("{err}");
        assert!(
            text.contains(REFUSAL) && text.contains(reason.as_str()),
            "{what}: expected `{REFUSAL}: {}`, got {err}",
            reason.as_str()
        );
        assert!(
            dir.get_attestation(&row.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "{what}: a refused row must not be stored"
        );
    }

    fn ids(rows: &[Attestation]) -> BTreeSet<String> {
        rows.iter().map(|r| r.attestation_id.clone()).collect()
    }

    /// #1035 — **the gate and the fold agree on chain depth, and the named
    /// edge is verified.** A two-hop delegate's admitted issuance is FOUND by
    /// the fold and by the list-by-authority read; a row naming an edge that is
    /// not its own live `license` edge is refused, with the reason.
    #[allow(clippy::too_many_lines)]
    pub async fn exercise_gate_and_fold_share_one_chain(dir: &dyn FederationDirectory, tag: &str) {
        let (board, holder) = keys(dir, tag).await;
        let now = base();
        let manager = officer(dir, tag, "manager").await;
        let clerk = officer(dir, tag, "clerk").await;

        // board → manager (may sub-delegate) → clerk: a two-hop `license` chain.
        let hop1 = must_put(
            dir,
            &edge(
                &board,
                &manager,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(3),
                &[("sub_delegation", serde_json::json!(true))],
            ),
            "the board appoints a licensing manager who may sub-delegate",
        )
        .await;
        let hop2 = must_put(
            dir,
            &edge(
                &manager,
                &clerk,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::minutes(170),
                &[],
            ),
            "the manager appoints a clerk",
        )
        .await;

        // The two-hop clerk's issuance: admitted AND found.
        // Kills: the fold requiring the named edge to be the authority's own.
        let two_hop = must_put(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "issued",
                Some(&hop2.attestation_id),
                now - Duration::hours(2),
            ),
            &format!("[{tag}] #1035: the two-hop clerk's licence admits"),
        )
        .await;
        assert_eq!(
            status_set_for(dir, &holder, &board, Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] #1035: a licence the door ADMITTED under a two-hop chain must be in the \
             board's fold — the gate and the fold judge ONE chain"
        );
        assert_eq!(
            licensure_issuance_at(
                dir,
                &resolve_licensure_authority(dir, &board)
                    .await
                    .expect("resolve"),
                &two_hop,
                two_hop.asserted_at,
            )
            .await
            .expect("verdict"),
            LicensureIssuance::Delegated {
                delegation_id: hop2.attestation_id.clone()
            },
            "[{tag}] #1035: the stored row keeps the `delegation_id` it was signed with, \
             and the verdict names it"
        );
        assert_eq!(
            two_hop.attestation_envelope["delegation_id"],
            serde_json::json!(hop2.attestation_id),
            "[{tag}] #1035: `delegation_id` is kept on the stored row"
        );

        // The named edge must be onto the EMITTER. `hop1` is live and on the
        // chain, but it delegates to the manager, not the clerk.
        // Kills: dropping the onto-emitter check.
        must_refuse_as(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "probation",
                Some(&hop1.attestation_id),
                now,
            ),
            LicensureChainBreak::NamedEdgeNotOntoEmitter,
            &format!("[{tag}] #1035: a row naming someone else's edge"),
        )
        .await;

        // The named row must be a `license` delegation.
        // Kills: dropping the type/scope check (the reason token changes).
        must_refuse_as(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "probation",
                Some(&two_hop.attestation_id),
                now,
            ),
            LicensureChainBreak::NamedEdgeNotLicense,
            &format!("[{tag}] #1035: a row naming a licence instead of an edge"),
        )
        .await;

        // The named row must exist.
        must_refuse_as(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "probation",
                Some(&uuid::Uuid::new_v4().to_string()),
                now,
            ),
            LicensureChainBreak::NamedEdgeAbsent,
            &format!("[{tag}] #1035: a row naming an edge nobody holds"),
        )
        .await;

        // THE `let _ = delegation_id;` CASE. The clerk holds a live chain, but
        // the row names a DIFFERENT edge onto the clerk — one a stranger signed,
        // on no chain from the board. The old gate admitted it (any chain to
        // the emitter passed, whatever the row named).
        // Kills: the gate ignoring `delegation_id`.
        let stranger = officer(dir, tag, "stranger").await;
        let side = must_put(
            dir,
            &edge(
                &stranger,
                &clerk,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(3),
                &[],
            ),
            "a stranger 'appoints' the clerk",
        )
        .await;
        must_refuse_as(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "probation",
                Some(&side.attestation_id),
                now,
            ),
            LicensureChainBreak::NotOnLiveChain,
            &format!("[{tag}] #1035: a row naming an edge that is not on the board's chain"),
        )
        .await;

        // ── list-by-authority: exactly the fold's verdict, per row ──
        let holder2 = format!("{tag}-holder2");
        register(dir, &holder2, &[identity_type::USER]).await;
        let direct = must_put(
            dir,
            &licence(
                &board,
                &holder2,
                &board,
                "issued",
                None,
                now - Duration::hours(1),
            ),
            "the board licenses a second holder itself",
        )
        .await;
        // A candidate issuer's TESTIMONY (no delegation claimed) is not listed.
        // Kills: dropping the verdict filter from the list.
        let testimony = must_put(
            dir,
            &licence(
                &clerk,
                &holder2,
                &board,
                "suspended",
                None,
                now - Duration::minutes(30),
            ),
            "the clerk writes testimony about the board's licence",
        )
        .await;
        // A neighbouring authority sharing the byte prefix is not listed.
        // Kills: dropping the exact authority-segment check.
        let neighbour = must_put(
            dir,
            &licence(
                &board,
                &holder2,
                &format!("{board}corp"),
                "issued",
                None,
                now - Duration::minutes(20),
            ),
            "the board writes under a different authority id",
        )
        .await;
        let listed = licences_issued_under(dir, &board)
            .await
            .expect("licences_issued_under");
        assert_eq!(
            ids(&listed),
            BTreeSet::from([
                two_hop.attestation_id.clone(),
                direct.attestation_id.clone()
            ]),
            "[{tag}] #1035: the board's licences are its own and the two-hop clerk's — not \
             the clerk's testimony ({}), not `licensure:{board}corp` ({})",
            testimony.attestation_id,
            neighbour.attestation_id
        );
        assert_eq!(
            listed[0].attestation_id, direct.attestation_id,
            "[{tag}] #1035: newest first"
        );

        // Withdrawing the manager later does not unlist (or un-fold) what the
        // clerk issued while the chain was live.
        must_put(
            dir,
            &bare_edge_retraction(&board, &manager),
            "the board withdraws the manager",
        )
        .await;
        assert!(
            ids(&licences_issued_under(dir, &board).await.expect("list"))
                .contains(&two_hop.attestation_id),
            "[{tag}] #1035/#1032: the list reads the same signed-instant verdict as the fold"
        );
    }

    /// #1035 / #1036 ruling item 1 — **a `licensure:{community_key_id}` row's
    /// authority set is the community's**: a chain rooted at a founder of a
    /// `founder_only` affiliation admits and folds; under a protocol that
    /// needs a quorum, no single-signed chain stands for the affiliation.
    pub async fn exercise_community_authority_roots_the_chain(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::room_roster_authority_invariants::bodies::make_group;
        use crate::federation::types::consensus_protocol;
        let now = base();
        let holder = format!("{tag}-holder");
        register(dir, &holder, &[identity_type::USER]).await;

        // A founder_only affiliation: alice founds it.
        let (aff, keys) = make_group(
            dir,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["alice", "bob"],
            1,
            None,
            None,
        )
        .await;
        let (alice, bob) = (keys[0].clone(), keys[1].clone());
        let officer_k = officer(dir, tag, "officer").await;
        let appointment = must_put(
            dir,
            &edge(
                &alice,
                &officer_k,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(2),
                &[],
            ),
            "the founder appoints a licensing officer for the affiliation",
        )
        .await;
        // Kills: resolving the community id as a bare key.
        let by_officer = must_put(
            dir,
            &licence(
                &officer_k,
                &holder,
                &aff,
                "issued",
                Some(&appointment.attestation_id),
                now - Duration::hours(1),
            ),
            &format!("[{tag}] #1036.1: a chain rooted at the affiliation's founder admits"),
        )
        .await;
        // The founder's own direct row is the affiliation's (founder_only says
        // one founder suffices); a non-founder member's is testimony.
        let by_founder = must_put(
            dir,
            &licence(
                &alice,
                &holder,
                &aff,
                "probation",
                None,
                now - Duration::minutes(50),
            ),
            "the founder issues directly",
        )
        .await;
        must_put(
            dir,
            &licence(
                &bob,
                &holder,
                &aff,
                "revoked",
                None,
                now - Duration::minutes(40),
            ),
            "a non-founder member writes testimony",
        )
        .await;
        assert_eq!(
            status_set_for(dir, &holder, &aff, Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued, LicensureStatus::Probation]),
            "[{tag}] #1036.1: the officer's and the founder's rows are the affiliation's; a \
             non-founder's absorbing `revoked` is testimony and binds nobody"
        );
        assert_eq!(
            ids(&licences_issued_under(dir, &aff).await.expect("list")),
            BTreeSet::from([by_officer.attestation_id, by_founder.attestation_id]),
            "[{tag}] #1036.1: the list-by-authority roots at the affiliation's founders"
        );

        // A majority affiliation: no single founder's chain stands for it.
        // Kills: treating every protocol as founder_only.
        let (maj, mkeys) = make_group(
            dir,
            &format!("{tag}-mj"),
            consensus_protocol::MAJORITY,
            &["carol", "dave"],
            1,
            None,
            None,
        )
        .await;
        let officer2 = officer(dir, tag, "officer2").await;
        let lone = must_put(
            dir,
            &edge(
                &mkeys[0],
                &officer2,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(2),
                &[],
            ),
            "one founder of a majority affiliation appoints an officer alone",
        )
        .await;
        must_refuse_as(
            dir,
            &licence(
                &officer2,
                &holder,
                &maj,
                "issued",
                Some(&lone.attestation_id),
                now - Duration::hours(1),
            ),
            LicensureChainBreak::AuthorityActsByQuorum,
            &format!("[{tag}] #1036.1: a single founder's chain under `majority`"),
        )
        .await;
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
        exercise_backdated_licence_is_refused_at_receipt,
        backdated_licence_is_refused_at_receipt_1049_memory,
        backdated_licence_is_refused_at_receipt_1049_sqlite,
        backdated_licence_is_refused_at_receipt_1049_postgres,
        "lic-backdate"
    );
    on_every_backend!(
        exercise_grant_walk_honours_the_term,
        grant_walk_honours_the_term_1032_memory,
        grant_walk_honours_the_term_1032_sqlite,
        grant_walk_honours_the_term_1032_postgres,
        "grant-term"
    );
    on_every_backend!(
        exercise_gate_and_fold_share_one_chain,
        gate_and_fold_share_one_chain_1035_memory,
        gate_and_fold_share_one_chain_1035_sqlite,
        gate_and_fold_share_one_chain_1035_postgres,
        "lic-one"
    );
    on_every_backend!(
        exercise_community_authority_roots_the_chain,
        community_authority_roots_the_chain_1035_memory,
        community_authority_roots_the_chain_1035_sqlite,
        community_authority_roots_the_chain_1035_postgres,
        "lic-aff"
    );
}
