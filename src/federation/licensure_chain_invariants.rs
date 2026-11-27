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
//!    **v60.0.0 (#1036 item 2, #1049) — the door judges at the signed
//!    instant too, bounded by W.** A licence signed inside an open term and
//!    received after it closed admits; a row signed more than W (72 h) before
//!    receipt must also hold at receipt, or it is `asserted_at_stale`. Before
//!    v60 the door judged at receipt as well (no window existed yet).
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
        register, signed_row, store,
    };
    use crate::federation::admission::{
        licences_issued_under, licensure_issuance_at, reachable_under_scope,
        resolve_licensure_authority, LicensureChainBreak, LicensureIssuance,
        DELEGATION_SCOPE_GRANT, DELEGATION_SCOPE_LICENSE, DELEGATION_VALID_FROM_FIELD,
        DELEGATION_VALID_UNTIL_FIELD, MAX_MODERATION_DELEGATION_DEPTH,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::licensure::{status_set_for, LicensureStatus};
    use crate::federation::tier_ingest::test_support::reseal;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{Attestation, Error, FederationDirectory};
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use std::collections::BTreeSet;

    /// v62.0.0 — the fixtures follow the switch: edition 2 by default, the
    /// earlier form inside a test HELD under it (`affiliation_licence`'s,
    /// whose groups ride the typed plane). `key` becomes live.
    pub(crate) async fn reg(dir: &dyn FederationDirectory, key: &str, types: &[&str]) {
        if e2::emit_edition2() {
            let _ = e2::put_key(dir, key, types).await;
        } else {
            register(dir, key, types).await;
        }
    }

    /// The id a key-taking read names `x` by: its kid under edition 2, the
    /// label in a held test.
    pub(crate) fn key_id(x: &str) -> String {
        if e2::emit_edition2() {
            e2::kid_or_keep(x)
        } else {
            x.to_owned()
        }
    }

    /// A key in a family name: its bare thumbprint under edition 2 (CC rc21;
    /// P2b's gates compare by thumbprint), the label in a held test.
    pub(crate) fn authority_segment(x: &str) -> String {
        if e2::emit_edition2() {
            e2::kid_thumb(x)
        } else {
            x.to_owned()
        }
    }

    /// v62.0.0 — what [`put`] reports for a counted row the door HELD short
    /// of its protocol (`StatementOutcome::Pending`).
    pub(crate) const PENDING: &str = "edition2_held_pending";

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
        // v62.0.0: an earlier-form signing helper takes a SEED, never a kid
        // (E0 v1.4); `make_group` hands back kids.
        let mut row = signed_row(
            &e2::seed_of(granter),
            recipient,
            attestation_type::DELEGATES_TO,
            envelope,
        );
        row.subject_key_ids = vec![recipient.to_owned()];
        row.asserted_at = asserted_at;
        row.scrub_timestamp = asserted_at;
        reseal(&mut row);
        row
    }

    /// v62.0.0 (E2-fix3) — the granter's `withdraws` of the `delegates_to`
    /// row `edge` (the §11.10 edge retraction). Edition 2 has no target-less
    /// composer (a `withdraws` names its target, `refs.target`), so the
    /// retraction names the edge row by its row id; the earlier form keeps
    /// the bare granter → recipient retraction.
    pub(crate) fn edge_withdrawal(granter: &str, edge: &Attestation) -> Attestation {
        if e2::emit_edition2() {
            e2::composer_of(attestation_type::WITHDRAWS, edge, granter)
        } else {
            crate::federation::admission::steward_liveness_test_support::bare_edge_retraction(
                granter,
                &edge.attested_key_id,
            )
        }
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
            // v62.0.0: a key in a family name is its bare thumbprint.
            "dimension": format!("licensure:{}:v1", authority_segment(authority)),
            "status": status,
            "score": 1.0,
            "confidence": 0.9,
        });
        if let Some(d) = delegation_id {
            envelope["delegation_id"] = serde_json::Value::String(d.to_owned());
        }
        let mut row = signed_row(
            &e2::seed_of(issuer),
            holder,
            attestation_type::SCORES,
            envelope,
        );
        row.asserted_at = asserted_at;
        row.scrub_timestamp = asserted_at;
        reseal(&mut row);
        row
    }

    /// v62.0.0 (CC 2.4.1.3, CLM-licence-authority-quorum) — the cosigners of
    /// a COUNTED licence row, by its row id: each is one more edition-2 voice
    /// over the row's payload, put after the row ([`put`]). Process-wide (the
    /// affiliation runners use a multi-thread runtime).
    static COSIGNERS: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<String, Vec<String>>>,
    > = std::sync::LazyLock::new(Default::default);

    /// Note `cosigners` (seeds or minted kids) as the further voices of
    /// `row`, which [`put`] offers after the row.
    pub(crate) fn note_cosigners(row: &Attestation, cosigners: &[&str]) {
        COSIGNERS
            .lock()
            .expect("cosigners")
            .entry(row.attestation_id.clone())
            .or_default()
            .extend(cosigners.iter().map(|c| (*c).to_owned()));
    }

    /// The authority community a `licensure:{thumb}:v1` row names, as the
    /// store keys it (the identity-ref `authority_of` answers), when this node
    /// holds a roster for it that is counted (any protocol but
    /// `founder_only`, whose founder's row stands alone).
    async fn counted_authority(
        dir: &dyn FederationDirectory,
        row: &Attestation,
    ) -> Result<Option<String>, Error> {
        let Some(dimension) = row
            .attestation_envelope
            .get("dimension")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(None);
        };
        // `authority_of` answers the KEY spelling of the dimension's segment
        // (P2's key-segment parser).
        let Some(authority) = crate::federation::licensure::authority_of(dimension) else {
            return Ok(None);
        };
        let group = authority.to_string();
        // GID-fix6 — the authority's room by the id the store keys it: the
        // key spelling `authority_of` answers, else the held group the
        // dimension's segment names (an affiliation's derived id; GID-fix3).
        let held = match dir.lookup_community(&group).await? {
            Some(c) => Some(c),
            None => crate::federation::admission::held_group_of_segment_id(dir, &group).await?,
        };
        Ok(held
            .filter(|c| {
                c.consensus_protocol != crate::federation::types::consensus_protocol::FOUNDER_ONLY
            })
            .map(|c| c.community_key_id))
    }

    /// Offer `row` at its door, returning the row as offered and the door's
    /// outcome (`None` for an earlier-form row through `put_attestation`).
    ///
    /// v62.0.0 (CC 2.4.1.3, CC 2.7.4, wave V1b): a licence under a COUNTED
    /// authority community is restated as a counted row (no `author`,
    /// `e2::counted_row_of`) naming the community's held roster version
    /// (`refs.head`), so a short row is HELD (`Pending`) and each noted
    /// cosigner's voice (`voices_of`) counts toward the protocol; every other
    /// edition-2 row goes as its own statement.
    pub(crate) async fn offer(
        dir: &dyn FederationDirectory,
        row: &Attestation,
    ) -> Result<
        (
            Attestation,
            Option<crate::federation::edition2::ingest::StatementOutcome>,
        ),
        Error,
    > {
        if e2::carried_statement(row).is_none() {
            store(dir, row).await?;
            return Ok((row.clone(), None));
        }
        let mut cosigners = COSIGNERS
            .lock()
            .expect("cosigners")
            .get(&row.attestation_id)
            .cloned()
            .unwrap_or_default();
        // v62.0.0 (wave V1b, CC 3.2 / C557): an owner binding lands only with
        // the bound node's own voice; without it the door holds it Pending.
        // One on behalf of an affiliation is COUNTED (CC ruling (a), V1b
        // `check_owner_binding_counted`): it names the affiliation's held
        // roster version as `refs.head`, and the members' voices count over
        // it at the affiliation's protocol. v62.0.0 (BIND-1; CC rc22 rule
        // `owner-binding`) — the affiliation is the one `on_behalf_of` names;
        // a placement (`community_id`) is counted by nobody.
        let mut row = row.clone();
        if row.attestation_type == attestation_type::DELEGATES_TO
            && crate::federation::admission::is_owner_binding_envelope(&row.attestation_envelope)
        {
            let named =
                crate::federation::admission::owner_binding_on_behalf_of(&row.attestation_envelope)
                    .map(str::to_owned);
            // v62.0.0 (E2-fix3; K2.api) — a plain owner binding (no
            // affiliation, no further cosigner) lands through K2's shared
            // helper: the owner's statement, then the bound key's voice.
            if named.is_none() && cosigners.is_empty() {
                let out =
                    e2::land_owner_binding(dir, &row, &e2::seed_of(&row.attested_key_id)).await?;
                return Ok((row, Some(out)));
            }
            cosigners.push(e2::seed_of(&row.attested_key_id));
            if let Some(community) = named {
                if row.attestation_envelope.get("refs").is_none() {
                    if let Some((head, _)) = e2::held_head(dir, &community).await {
                        let mut shape = row.clone();
                        shape.attestation_envelope["refs"] =
                            serde_json::json!({ "head": [2, [-16, head.hex()]] });
                        row = e2::row_of(&shape, &e2::seed_of(&row.attesting_key_id));
                    }
                }
            }
        }
        // v62.0.0 (CC 4.4.3.12, V1b officer arm): an affiliation's officer
        // appointment (a `delegates_to` that is no owner binding, naming the
        // affiliation as `community_id`), and a quorum's `withdraws` naming
        // the affiliation, are COUNTED: no author (`e2::counted_row_of`),
        // naming the affiliation's held roster version as `refs.head`; the
        // members' voices count at its protocol.
        let appointment_like = (row.attestation_type == attestation_type::DELEGATES_TO
            && !crate::federation::admission::is_owner_binding_envelope(&row.attestation_envelope))
            || row.attestation_type == attestation_type::WITHDRAWS;
        if appointment_like && row.attestation_envelope.get("refs").is_none() {
            let named = row
                .attestation_envelope
                .get("community_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            if let Some(community) = named {
                if let Some((head, _)) = e2::held_head(dir, &community).await {
                    let mut shape = row.clone();
                    let mut refs = serde_json::json!({ "head": [2, [-16, head.hex()]] });
                    // A `withdraws` keeps its target beside the head (the codec
                    // writes `refs.target` itself only when no `refs` is given).
                    if let Some(target) = shape
                        .attestation_envelope
                        .as_object_mut()
                        .and_then(|o| o.remove("references_attestation_id"))
                    {
                        refs["target"] = serde_json::json!([2, [-16, target]]);
                    }
                    shape.attestation_envelope["refs"] = refs;
                    let seed = e2::seed_of(&row.attesting_key_id);
                    row = if row.attestation_type == attestation_type::WITHDRAWS {
                        // V1b `check_counted_withdrawal`: the group's withdrawal
                        // of a counted row is counted in the TARGET's family
                        // (`self:delegates_to`); `community_id` was only this
                        // fixture's marker, so it does not ride the payload.
                        let target_id = shape.attestation_envelope["refs"]["target"][1][1]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        let target = dir
                            .get_attestation(&target_id)
                            .await?
                            .expect("the withdrawn appointment is held");
                        // v62.0.0 (E2-fix3) — nor does the earlier envelope's
                        // `id`: a composer's payload has no such member (its
                        // row id is node-computed).
                        if let Some(o) = shape.attestation_envelope.as_object_mut() {
                            o.remove("community_id");
                            o.remove("id");
                        }
                        e2::row_of_statement(
                            &e2::counted_statement_of_family(
                                &shape,
                                &seed,
                                &e2::family_of(&target),
                            ),
                            &shape.tier,
                        )
                    } else {
                        e2::counted_row_of(&shape, &seed)
                    };
                }
            }
        }
        let row = match counted_authority(dir, &row).await? {
            Some(group) => {
                let (head, _) = e2::held_head(dir, &group)
                    .await
                    .expect("the authority's roster is held");
                let mut shape = row.clone();
                shape.attestation_envelope["refs"] =
                    serde_json::json!({ "head": [2, [-16, head.hex()]] });
                e2::counted_row_of(&shape, &e2::seed_of(&row.attesting_key_id))
            }
            None => row,
        };
        // v62.0.0 (E2-fix7; K2-fix4, CC 2.7.3 / CC 2.7.5) — an authored
        // delegation waits for the voices its family's model names (the
        // delegate's, and a machine delegate's owner's): the roles the door
        // will ask for are voiced here (`second_signer_voices`, the resolved
        // model's parties), beside any noted cosigner. A counted row names
        // none.
        let (needed, _unvoiced) = e2::second_signer_voices(dir, &row).await?;
        for seed in needed {
            if !cosigners.contains(&seed) {
                cosigners.push(seed);
            }
        }
        let mut out = e2::put_signed(dir, &row).await?;
        let seeds: Vec<&str> = cosigners.iter().map(String::as_str).collect();
        for voice in e2::voices_of(&row, &seeds) {
            out = e2::put_statement(dir, &voice).await?;
        }
        Ok((row, Some(out)))
    }

    /// Store `row` and read it back AS STORED.
    pub(crate) async fn put(
        dir: &dyn FederationDirectory,
        row: &Attestation,
    ) -> Result<Attestation, Error> {
        let (row, out) = offer(dir, row).await?;
        match dir.get_attestation(&row.attestation_id).await? {
            Some(stored) => Ok(stored),
            // v62.0.0: a counted row short of its protocol is HELD, not
            // stored: no typed row reads back. Reported as a refusal so the
            // `must_refuse*` witnesses see it; the outcome names the hold.
            //
            // v62.0.0 (E2-fix3; CC 2.7.3) — a gate that reads OTHER rows (the
            // licensure chain, the authority's roster, an earlier revision)
            // HOLDS the row with its reason instead of refusing it. The fold's
            // record of why (`fold::why_held`: the reason token and the
            // gate's refusal text) rides the report, so a witness asserts
            // the WAIT by the gate's own token; a counted row merely short of
            // its voices has no fold reason (`why_held` is `None`).
            None => {
                let why = match &out {
                    Some(crate::federation::edition2::ingest::StatementOutcome::Pending {
                        row_id,
                        ..
                    }) => crate::federation::edition2::fold::why_held(dir, row_id)
                        .await?
                        .map(|h| format!(" held {}: {}", h.reason, h.detail)),
                    _ => None,
                };
                Err(Error::InvalidArgument(format!(
                    "{PENDING}: {} ({out:?}){}",
                    row.attestation_id,
                    why.unwrap_or_default()
                )))
            }
        }
    }

    /// v62.0.0 (E2-fix3; CC 2.7.3) — **the fold's hold behind a [`put`]
    /// result**: `(reason, detail)` when the door HELD the row on a fold
    /// condition (a gate that reads OTHER rows records its reason token and
    /// its refusal's text, `fold::why_held`); `None` for anything else.
    pub(crate) fn held_reason(r: &Result<Attestation, Error>) -> Option<(String, String)> {
        let Err(Error::InvalidArgument(m)) = r else {
            return None;
        };
        let (_, held) = m.strip_prefix(PENDING)?.split_once(" held ")?;
        let (reason, detail) = held.split_once(": ")?;
        Some((reason.to_owned(), detail.to_owned()))
    }

    /// v62.0.0 (E2-fix3; CC 2.7.3) — **the gate's refusal message behind a
    /// [`put`] result**: an `InvalidArgument` refusal's message, or, for a row
    /// the door HELD on a fold condition, the same gate's message as the fold
    /// recorded it ([`held_reason`]'s detail). `None` for anything else.
    pub(crate) fn refusal_message(r: &Result<Attestation, Error>) -> Option<String> {
        if let Some((_, detail)) = held_reason(r) {
            return Some(
                detail
                    .strip_prefix("invalid argument: ")
                    .unwrap_or(&detail)
                    .to_owned(),
            );
        }
        match r {
            Err(Error::InvalidArgument(m)) if !m.starts_with(PENDING) => Some(m.clone()),
            _ => None,
        }
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
        reg(dir, &authority, &[identity_type::USER]).await;
        reg(dir, &holder, &[identity_type::USER]).await;
        (authority, holder)
    }

    pub(crate) async fn officer(dir: &dyn FederationDirectory, tag: &str, name: &str) -> String {
        let k = format!("{tag}-{name}");
        reg(dir, &k, &[identity_type::PRIMITIVE]).await;
        k
    }

    pub(crate) fn rfc3339(t: DateTime<Utc>) -> serde_json::Value {
        serde_json::Value::String(crate::federation::admission::render_signed_instant(t))
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

        // (a) Issued INSIDE the term, received now (after the term). v60.0.0
        // (#1036 item 2): judged at the signed instant, inside W, it ADMITS
        // and is the board's licensure — a later lapse does not reclassify a
        // licence already issued.
        // Kills: the door also judging at receipt (the v54 rule).
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
                "[{tag}] #1036.2: a licence signed while the officer's term was open, received \
                 after it closed, inside W"
            ),
        )
        .await;
        assert_eq!(
            status_set_for(dir, &key_id(&holder), &key_id(&board), Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] #1036.2: the in-term licence is the board's licensure"
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
        // authority). v60.0.0 (#1048): the door refuses such an edge outright
        // (`term_unreadable`); the lens's own reading is witnessed pure (I1230).
        // Kills: treating a malformed term as absent at the door.
        let odd = officer(dir, tag, "odd").await;
        let unreadable = edge(
            &board,
            &odd,
            &[DELEGATION_SCOPE_LICENSE],
            t_edge,
            &[(
                DELEGATION_VALID_UNTIL_FIELD,
                // v61 — a non-string: a string not `.sssZ` is refused by
                // the CC 2.6.2 shape gate before the term gate reads it.
                serde_json::json!(20_261_103),
            )],
        );
        match put(dir, &unreadable).await {
            Err(Error::DelegationTermRequired { rule, .. }) => assert_eq!(
                rule,
                crate::federation::admission::delegation_term_rule::TERM_UNREADABLE,
                "[{tag}] #1048: an unreadable term"
            ),
            other => panic!("[{tag}] #1048: an unreadable term must be refused: {other:?}"),
        }
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
            &edge_withdrawal(&board, &appointment),
            "the board withdraws the officer",
        )
        .await;

        // Kills: the fold resolving the CURRENT graph.
        assert_eq!(
            status_set_for(dir, &key_id(&holder), &key_id(&board), Utc::now())
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

    /// #1049 / #1036 item 2 — **the signed instant stands inside W; beyond it
    /// the standing must hold at receipt.**
    ///
    /// - (a) an officer the board has WITHDRAWN dates a licence inside the
    ///   appointment's old live window, two hours ago: inside W the signed
    ///   instant stands and it ADMITS (the exposure CC accepted with W);
    /// - (a') the same officer dates one four days ago (beyond W), inside an
    ///   appointment made five days ago: REFUSED `asserted_at_stale`, plane
    ///   `licensure`;
    /// - (b) a founder who has LEFT a `founder_only` affiliation dates a direct
    ///   issuance inside their tenure, inside W: ADMITS;
    /// - (c) the door judges at the signed instant: a licence dated before an
    ///   open-ended appointment existed is refused, so the door never admits a
    ///   row the fold would exclude.
    ///
    /// Kills: the door judging at receipt (arms (a), (b) refuse), dropping the
    /// W gate (arm (a') admits), and dropping the signed-instant verdict (arm
    /// (c) admits).
    pub async fn exercise_backdated_licence_is_bounded_by_w(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::room_roster_authority_invariants::bodies::make_group;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{consensus_protocol, CommunityMembershipRevocation};
        let (board, holder) = keys(dir, tag).await;
        let now = base();

        // (a) / (a') The withdrawn officer.
        let clerk = officer(dir, tag, "clerk").await;
        let appointment = must_put(
            dir,
            &edge(
                &board,
                &clerk,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::days(5),
                &[],
            ),
            "the board appoints a licensing officer five days ago",
        )
        .await;
        must_put(
            dir,
            &edge_withdrawal(&board, &appointment),
            "the board withdraws the officer",
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
            &format!(
                "[{tag}] #1036.2: a withdrawn officer's licence dated inside the old \
                 appointment and inside W"
            ),
        )
        .await;
        let stale = licence(
            &clerk,
            &holder,
            &board,
            "probation",
            Some(&appointment.attestation_id),
            now - Duration::days(4),
        );
        let r = put(dir, &stale).await;
        // v62.0.0 (E2-fix3; CC 2.7.3) — the officer's standing at receipt is
        // OTHER rows, so an edition-2 licence beyond W is HELD
        // `asserted_at_stale` (the refusal's text as the detail); the earlier
        // form refuses it typed.
        if let Some((reason, detail)) = held_reason(&r) {
            assert_eq!(
                reason,
                crate::federation::edition2::fold::reason::ASSERTED_AT_STALE,
                "[{tag}] #1049: held `asserted_at_stale`: {detail}"
            );
            assert!(
                detail.starts_with("asserted_at_stale:"),
                "[{tag}] #1049: the hold's detail leads with the token: {detail}"
            );
        } else {
            let err = r.expect_err("a withdrawn officer's licence dated beyond W must be refused");
            assert!(
                matches!(&err, Error::AssertedAtStale { plane, standing_for, .. }
                    if *plane == "licensure" && *standing_for == board),
                "[{tag}] #1049: refused `asserted_at_stale` on the licensure plane: {err:?}"
            );
            assert!(
                format!("{err}").starts_with("asserted_at_stale:"),
                "[{tag}] #1049: the Display leads with the token: {err}"
            );
        }
        assert!(
            dir.get_attestation(&stale.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "[{tag}] #1049: the refused row is not stored"
        );

        // (c) The door judges at the signed instant: a licence dated before
        // an open-ended appointment existed is live at receipt and refused.
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
            &format!("[{tag}] #1032: a licence dated before the appointment existed"),
        )
        .await;

        // (b) The departed founder. alice and carol found a founder_only
        // affiliation; alice leaves an hour ago, then dates a direct issuance
        // two hours ago, when she was still a founder: inside W it stands.
        let (aff, k) = make_group(
            dir,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["alice", "carol", "bob"],
            2,
            // v62 (E4 round 3): `founder_only` above the family only as a
            // declared affiliation (CC 4.5.13, 4.4.3.2.8).
            Some(crate::federation::affiliation_invariants::bodies::affiliation_blob(None)),
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
                leaf: crate::federation::types::RevocationLeaf::Resignation,
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] alice leaves (carol remains a founder): {e}"));
        let backdated = must_put(
            dir,
            &licence(
                &alice,
                &holder,
                &aff,
                "issued",
                None,
                now - Duration::minutes(110),
            ),
            &format!("[{tag}] #1036.2: a departed founder's issuance dated inside her tenure"),
        )
        .await;
        assert!(
            crate::federation::admission::row_was_issued_under_authority(dir, &backdated, &aff)
                .await
                .expect("verdict"),
            "[{tag}] #1036.2: judged at its signed instant, it is the affiliation's"
        );
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
                    &key_id(&owner),
                    &key_id(&to),
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
        // v62.0.0 (E2-fix3; CC 2.7.3, wave GC1) — the chain is OTHER rows, so
        // an edition-2 licence off its chain is HELD with the gate's reason
        // (`fold::reason::gc1::LICENSURE_DELEGATOR_NOT_AUTHORITY`, the
        // refusal's text as the detail), not refused: the witness asserts
        // that wait, by the same reason token, and that nothing is stored.
        if let Error::InvalidArgument(m) = &err {
            if m.starts_with(PENDING) {
                let held = m.split_once(" held ").map_or_else(
                    || panic!("{what}: expected the licensure hold, got a wait with no fold reason: {m}"),
                    |(_, h)| h,
                );
                assert!(
                    held.starts_with(&format!(
                        "{}: {REFUSAL}: {}: ",
                        crate::federation::edition2::fold::reason::gc1::LICENSURE_DELEGATOR_NOT_AUTHORITY,
                        reason.as_str()
                    )),
                    "{what}: expected the hold `{REFUSAL}: {}`, got {m}",
                    reason.as_str()
                );
                assert!(
                    dir.get_attestation(&row.attestation_id)
                        .await
                        .expect("read")
                        .is_none(),
                    "{what}: a held row must not be stored"
                );
                return;
            }
        }
        let text = format!("{err}");
        assert!(
            text.contains(REFUSAL) && text.contains(reason.as_str()),
            "{what}: expected `{REFUSAL}: {}`, got {err}",
            reason.as_str()
        );
        // v54.1.0 (#1042 follow-up C) — typed: the kind and the reason token,
        // never prose.
        assert_eq!(
            err.kind(),
            "federation_licensure_delegator_not_authority",
            "{what}: {err}"
        );
        assert!(
            matches!(&err, Error::LicensureDelegatorNotAuthority { reason: r, attesting_key_id, .. }
                if *r == reason.as_str() && *attesting_key_id == row.attesting_key_id),
            "{what}: the typed reason is `{}`: {err:?}",
            reason.as_str()
        );
        // v55.0.0 (CIRISPersist#1055) — the Display begins with the refusal
        // token: the `invalid argument:` prefix made logs read it as an
        // InvalidArgument.
        assert!(
            text.starts_with(&format!("{REFUSAL}: {}: ", reason.as_str())),
            "{what}: the Display begins with the refusal token: {text}"
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
            status_set_for(dir, &key_id(&holder), &key_id(&board), Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] #1035: a licence the door ADMITTED under a two-hop chain must be in the \
             board's fold — the gate and the fold judge ONE chain"
        );
        assert_eq!(
            licensure_issuance_at(
                dir,
                &resolve_licensure_authority(dir, &key_id(&board))
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
        // A `delegates_to` onto the emitter that does not carry `license` is
        // not a licence delegation either. Kills: the type OR scope test
        // weakened to AND (the edge would fall through to the walk and be
        // refused under another reason).
        let not_license = must_put(
            dir,
            &edge(&manager, &clerk, &["consent_revocation"], now, &[]),
            "#1035 an edge onto the clerk without `license`",
        )
        .await;
        must_refuse_as(
            dir,
            &licence(
                &clerk,
                &holder,
                &board,
                "probation",
                Some(&not_license.attestation_id),
                now,
            ),
            LicensureChainBreak::NamedEdgeNotLicense,
            &format!("[{tag}] #1035: a row naming an edge without `license`"),
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
        reg(dir, &holder2, &[identity_type::USER]).await;
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
        let listed = licences_issued_under(dir, &key_id(&board))
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
            &edge_withdrawal(&board, &hop1),
            "the board withdraws the manager",
        )
        .await;
        assert!(
            ids(&licences_issued_under(dir, &key_id(&board))
                .await
                .expect("list"))
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
        reg(dir, &holder, &[identity_type::USER]).await;

        // A founder_only affiliation: alice founds it.
        let (aff, keys) = make_group(
            dir,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["alice", "bob"],
            1,
            // v62 (E4 round 3): `founder_only` above the family only as a
            // declared affiliation (CC 4.5.13, 4.4.3.2.8).
            Some(crate::federation::affiliation_invariants::bodies::affiliation_blob(None)),
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
            status_set_for(dir, &key_id(&holder), &key_id(&aff), Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued, LicensureStatus::Probation]),
            "[{tag}] #1036.1: the officer's and the founder's rows are the affiliation's; a \
             non-founder's absorbing `revoked` is testimony and binds nobody"
        );
        assert_eq!(
            ids(&licences_issued_under(dir, &key_id(&aff))
                .await
                .expect("list")),
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

    /// **I604** (v54.0.0, Codex round 2 on PR #1050) — **a founder's licence is
    /// judged against the record in force when it was signed.** Founders F and
    /// G found a `founder_only` community; F issues a licence directly at
    /// `t1`; G then supersedes the record with a roster that omits F. The
    /// roots were seeded from the CURRENT record, so F was a root at no
    /// instant and both folds dropped the licence the door had admitted. Now:
    /// the fold and the list-by-authority still carry F's `t1` licence, and a
    /// `revoked` F signs after the supersession is testimony that binds nobody.
    pub async fn exercise_superseded_founder_keeps_issued_licence(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::room_roster_authority_invariants::bodies::make_group;
        use crate::federation::types::consensus_protocol;
        let now = base();
        let holder = format!("{tag}-holder");
        reg(dir, &holder, &[identity_type::USER]).await;
        let (room, keys) = make_group(
            dir,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["g", "f"],
            2,
            None,
            None,
        )
        .await;
        let (g, f) = (keys[0].clone(), keys[1].clone());
        let issued = must_put(
            dir,
            &licence(&f, &holder, &room, "issued", None, now - Duration::hours(1)),
            &format!("[{tag}] I604: founder F issues while a founder"),
        )
        .await;
        // G supersedes the record without F. v61 (CIRISPersist#1123): the
        // legacy founder_only room's next version leaves founder_only, which
        // the supersede door refuses above the family. v61 S2: and that
        // version is the escape ALONE (the protocol, nothing else), so the
        // room first leaves founder_only and then drops F under its new
        // protocol.
        let held = dir.lookup_community(&room).await.unwrap().expect("held");
        let mut escape = held.clone();
        escape.consensus_protocol = "quorum:1/2".to_owned();
        escape.prev_head_digest = held.persist_row_hash.clone();
        escape.persist_row_hash = String::new();
        dir.supersede_community(
            crate::federation::tier_ingest::test_support::sign_community(&g, escape),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I604: the escape from founder_only: {e}"));
        let held = dir.lookup_community(&room).await.unwrap().expect("held");
        let mut next = held.clone();
        next.members.retain(|m| m.key_id != f);
        next.consensus_protocol = "quorum:1/1".to_owned();
        next.prev_head_digest = held.persist_row_hash.clone();
        next.persist_row_hash = String::new();
        dir.supersede_community(
            crate::federation::tier_ingest::test_support::sign_community(&g, next),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I604: G supersedes the record without F: {e}"));
        assert!(
            !dir.lookup_community(&room)
                .await
                .unwrap()
                .expect("held")
                .members
                .iter()
                .any(|m| m.key_id == f),
            "[{tag}] I604 precondition: the live record no longer names F"
        );
        assert_eq!(
            status_set_for(dir, &key_id(&holder), &key_id(&room), Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] I604: F's licence, signed while F was a founder, still binds"
        );
        assert!(
            ids(&licences_issued_under(dir, &key_id(&room))
                .await
                .expect("list"))
            .contains(&issued.attestation_id),
            "[{tag}] I604: the list-by-authority still finds F's licence"
        );
        // After the supersession F is no founder. F's new row, an absorbing
        // `revoked`, is testimony (the door admits a non-authority row as
        // testimony, #1036.1) and binds nobody. The pause puts its signed
        // instant strictly after the supersession this node applied.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let late = must_put(
            dir,
            &licence(
                &f,
                &holder,
                &room,
                "revoked",
                None,
                Utc::now().trunc_subsecs(3),
            ),
            &format!("[{tag}] I604: F's row after the supersession is admitted as testimony"),
        )
        .await;
        assert!(
            !crate::federation::admission::row_was_issued_under_authority(dir, &late, &room)
                .await
                .expect("verdict"),
            "[{tag}] I604: F's row after the supersession is not the authority's"
        );
        assert_eq!(
            status_set_for(dir, &key_id(&holder), &key_id(&room), Utc::now())
                .await
                .expect("fold"),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] I604: F's later `revoked` binds nobody; the `t1` licence stands"
        );
        assert!(
            !ids(&licences_issued_under(dir, &key_id(&room))
                .await
                .expect("list"))
            .contains(&late.attestation_id),
            "[{tag}] I604: the list-by-authority does not carry F's later row"
        );
    }

    /// **I610** (v54.0.0, Codex round 3 on PR #1050) — **a community's id is
    /// not its own issuer.** An infrastructure community's id is ALSO its
    /// substrate key (`is_authorized_infrastructure_community` reads that
    /// key), so a row that key signs has `attesting_key_id == authority_id`.
    /// The door short-circuited on that equality and admitted a row claiming
    /// a delegation (`delegation_id`) that names no edge, without reading the
    /// community's authority set; the fold, which resolves the authority
    /// first, classified the stored row unresolved. Now the door resolves
    /// first and only a KEY authority is its own issuer: the row is refused,
    /// and the door and the chain function agree on it. The same key's row
    /// that claims no delegation is testimony, admitted, binding nobody.
    pub async fn exercise_community_id_is_not_its_own_issuer(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::emitter_resolves_to_authority;
        use crate::federation::room_roster_authority_invariants::bodies::make_group;
        use crate::federation::types::consensus_protocol;
        let now = base();
        let holder = format!("{tag}-holder");
        reg(dir, &holder, &[identity_type::USER]).await;
        let (room, _founders) = make_group(
            dir,
            &format!("{tag}-infra"),
            consensus_protocol::FOUNDER_ONLY,
            &["alice"],
            1,
            // v62 (E4 round 3): `founder_only` above the family only as a
            // declared affiliation (CC 4.5.13, 4.4.3.2.8).
            // v62.0.0 (E2-fix7; CC 2.4.1.2.1) — a licence has no public
            // default: the charter declares the licence class public, and the
            // federation-scope control row carries that class.
            Some(
                crate::federation::affiliation_invariants::bodies::affiliation_blob(Some(
                    serde_json::json!({ "licence_audiences": { (crate::federation::affiliation_licence_invariants::bodies::PUBLIC_CLASS): "federation" } }),
                )),
            ),
            None,
        )
        .await;
        // The community's id resolves to a key as well.
        reg(dir, &room, &[identity_type::SUBSTRATE_PERSIST]).await;
        assert!(
            matches!(
                resolve_licensure_authority(dir, &key_id(&room))
                    .await
                    .expect("resolve"),
                crate::federation::admission::LicensureAuthority::Community(_)
            ),
            "[{tag}] I610 premise: the authority id resolves to the community"
        );
        let claimed = licence(
            &room,
            &holder,
            &room,
            "issued",
            Some(&uuid::Uuid::new_v4().to_string()),
            now - Duration::minutes(30),
        );
        let authority = resolve_licensure_authority(dir, &key_id(&room))
            .await
            .expect("resolve");
        assert!(
            matches!(
                licensure_issuance_at(dir, &authority, &claimed, claimed.asserted_at)
                    .await
                    .expect("chain"),
                LicensureIssuance::Unresolved { .. }
            ),
            "[{tag}] I610 premise: the chain function classifies the row unresolved"
        );
        must_refuse(
            dir,
            &claimed,
            &format!("[{tag}] I610: the community's key signs a delegated issuance naming no edge"),
        )
        .await;
        assert!(
            !emitter_resolves_to_authority(dir, &room, &room)
                .await
                .expect("reader"),
            "[{tag}] I610: the community's key is not in its founder_only authority set"
        );
        let testimony = must_put(
            dir,
            &crate::federation::affiliation_licence_invariants::bodies::classed(licence(
                &room,
                &holder,
                &room,
                "revoked",
                None,
                now - Duration::minutes(20),
            )),
            &format!("[{tag}] I610 control: the same key's row claiming no delegation"),
        )
        .await;
        assert!(
            !crate::federation::admission::row_was_issued_under_authority(dir, &testimony, &room)
                .await
                .expect("verdict"),
            "[{tag}] I610 control: that row is testimony, not the community's"
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
        ($body:ident, $sqlite:ident, $postgres:ident, $prefix:literal) => {
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
        term_bound_officer_lapses_for_licence_1032_sqlite,
        term_bound_officer_lapses_for_licence_1032_postgres,
        "lic-term"
    );
    on_every_backend!(
        exercise_withdrawal_does_not_reclassify_issued_licence,
        withdrawal_does_not_reclassify_issued_licence_1032_sqlite,
        withdrawal_does_not_reclassify_issued_licence_1032_postgres,
        "lic-wd"
    );
    on_every_backend!(
        exercise_backdated_licence_is_bounded_by_w,
        backdated_licence_is_bounded_by_w_1049_sqlite,
        backdated_licence_is_bounded_by_w_1049_postgres,
        "lic-backdate"
    );
    on_every_backend!(
        exercise_grant_walk_honours_the_term,
        grant_walk_honours_the_term_1032_sqlite,
        grant_walk_honours_the_term_1032_postgres,
        "grant-term"
    );
    on_every_backend!(
        exercise_gate_and_fold_share_one_chain,
        gate_and_fold_share_one_chain_1035_sqlite,
        gate_and_fold_share_one_chain_1035_postgres,
        "lic-one"
    );
    on_every_backend!(
        exercise_community_authority_roots_the_chain,
        community_authority_roots_the_chain_1035_sqlite,
        community_authority_roots_the_chain_1035_postgres,
        "lic-aff"
    );
    on_every_backend!(
        exercise_superseded_founder_keeps_issued_licence,
        i604_superseded_founder_keeps_issued_licence_sqlite,
        i604_superseded_founder_keeps_issued_licence_postgres,
        "i604"
    );
    on_every_backend!(
        exercise_community_id_is_not_its_own_issuer,
        i610_community_id_is_not_its_own_issuer_sqlite,
        i610_community_id_is_not_its_own_issuer_postgres,
        "i610"
    );
}
