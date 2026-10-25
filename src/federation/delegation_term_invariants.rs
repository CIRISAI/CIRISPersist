//! v60.0.0 (CIRISPersist#1048, CC 2.4 / CC 4.4.3.2.8 C, CIRISConstitution#163)
//! — **a term-bearing `delegates_to` carries a bounded term, and an
//! affiliation's `role_term` bounds the edges its walks follow.**
//!
//! CC: "`delegation_valid_until` is REQUIRED, at most one year after
//! `delegation_valid_from`, on any edge carrying `sub_delegation`, `license`,
//! `grant`, `moderate`, `takedown`, `review` or `slash`, or sitting in an
//! affiliation's `hierarchy`; a perpetual or over-ceiling edge is refused
//! `delegation_term_required`." v54.0.0 enforced the one-year ceiling in the
//! walks' lens only, and only on a term naming both ends; nothing refused a
//! perpetual edge, and an affiliation's own `role_term` bound nothing.
//!
//! - **I1230** (pure) — the lens ([`delegation_term_live_at`]): a term naming
//!   only its end is measured from the signed `asserted_at`; a walk rooted at
//!   an affiliation reads its `role_term`; an unreadable term is never live;
//!   the bounds apply to term-bearing edges only; and a perpetual term-bearing
//!   edge already stored stays live (nothing is retroactive).
//! - **I1234** (pure) — the grandfather ruling: an edge signed before
//!   [`DELEGATION_TERM_ADOPTED_AT`] keeps the v54 reading (a one-ended term
//!   has no span, an affiliation's `role_term` does not bound it, a two-ended
//!   term past the ceiling is not live).
//!
//! [`DELEGATION_TERM_ADOPTED_AT`]: crate::federation::admission::DELEGATION_TERM_ADOPTED_AT
//! - **I1231** (sqlite, postgres) — the admission gate on the put door:
//!   each of the seven triggers without an upper bound is refused
//!   `term_missing` and not stored; a term naming only its start is
//!   perpetual; the ceiling from either start; an unreadable member; an edge
//!   naming an affiliation is held to its `role_term` whatever its scope; the
//!   trust plane and an owner-binding are not gated; an edge that is not
//!   term-bearing keeps its term optional.
//! - **I1232** (sqlite, postgres) — #1048 item 1, the walks: a licence
//!   issued under a `license` edge whose term is inside the year but longer
//!   than the authority affiliation's `role_term` is refused
//!   `not_on_live_chain_at_asserted_at`, one inside it admits, and the same
//!   long edge under a plain community admits. The moderation walk scoped to
//!   an affiliation drops an appointment longer than its `role_term`.
//! - **I1235** (sqlite, postgres) — the promotion chokepoint re-runs the
//!   gate: an untermed term-bearing edge does not cross; a termed one does.
//! - **I1233** (sqlite) — the producer doors: `Engine::add_moderator` and
//!   `Engine::grant_delegation` without a term are refused
//!   `federation_delegation_term_required`, and with one they admit.
//!
//! [`delegation_term_live_at`]: crate::federation::admission

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub mod bodies {
    use crate::federation::admission::{
        delegation_term_rule as rule, DELEGATION_SCOPE_GRANT, DELEGATION_SCOPE_LICENSE,
        DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW, DELEGATION_SCOPE_SLASH,
        DELEGATION_SCOPE_TAKEDOWN, DELEGATION_VALID_FROM_FIELD, DELEGATION_VALID_UNTIL_FIELD,
    };
    use crate::federation::licensure_chain_invariants::bodies::{
        base, edge, licence, must_put, must_refuse_as, officer,
    };
    use crate::federation::room_roster_authority_invariants::bodies::make_group;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, consensus_protocol, identity_type};
    use crate::federation::{Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    fn instant(t: DateTime<Utc>) -> serde_json::Value {
        serde_json::Value::String(t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    }

    /// A `delegates_to(granter → recipient)` carrying exactly `envelope` (no
    /// term is added), sealed by `granter` and offered at the put door.
    async fn put_raw(
        d: &dyn FederationDirectory,
        granter: &str,
        recipient: &str,
        envelope: serde_json::Value,
    ) -> Result<String, Error> {
        let row = raw_edge(granter, recipient, envelope);
        let id = row.attestation_id.clone();
        d.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await?;
        Ok(id)
    }

    /// The sealed `delegates_to(granter → recipient)` [`put_raw`] offers.
    fn raw_edge(
        granter: &str,
        recipient: &str,
        mut envelope: serde_json::Value,
    ) -> crate::federation::Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        envelope["references_attestation_id"] = serde_json::Value::String(id.clone());
        let mut row = ts::bare_attestation(&id, granter, recipient, &envelope);
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        ts::seal_row_in_place(granter, &mut row);
        row
    }

    /// **I1235** — the promotion chokepoint re-runs the term gate: a
    /// term-bearing edge with no term does not cross to the federation tier
    /// (whether an edge sits in an affiliation's hierarchy is directory state
    /// that can change after the local write), and the same edge with a term
    /// does. Kills: dropping `check_delegation_term_admission` from
    /// `check_promotion_admission` (no mutant deletes a call; this is the
    /// reachability witness).
    pub async fn i1235_promotion_re_runs_the_term_gate(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::admission::check_promotion_admission;
        let granter = format!("{tag}-granter");
        let r = format!("{tag}-r");
        ts::register_hybrid_key_as(d, &granter, &granter, identity_type::USER).await;
        ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
        let untermed = raw_edge(
            &granter,
            &r,
            serde_json::json!({ "scope": [DELEGATION_SCOPE_GRANT] }),
        );
        match check_promotion_admission(d, &untermed, None).await {
            Err(Error::DelegationTermRequired { rule: got, .. }) => {
                assert_eq!(got, rule::TERM_MISSING, "[{tag}] I1235: the rule");
            }
            other => panic!("[{tag}] I1235: an untermed grant edge crossed: {other:?}"),
        }
        let termed = raw_edge(
            &granter,
            &r,
            serde_json::json!({
                "scope": [DELEGATION_SCOPE_GRANT],
                DELEGATION_VALID_UNTIL_FIELD: instant(Utc::now() + Duration::days(30)),
            }),
        );
        if let Err(e) = check_promotion_admission(d, &termed, None).await {
            panic!(
                "[{tag}] I1235 control: a termed edge must cross, got {} ({e})",
                e.kind()
            );
        }
    }

    /// Unwrap a `DelegationTermRequired` with `want`, or panic naming what came
    /// back instead — a neighbouring refusal is not this gate.
    fn expect_refused(r: Result<String, Error>, want: &str, what: &str) {
        match r {
            Err(Error::DelegationTermRequired { rule, .. }) => {
                assert_eq!(rule, want, "{what}: the refusal names the rule");
            }
            Err(e) => panic!(
                "{what}: expected federation_delegation_term_required ({want}), got {} ({e})",
                e.kind()
            ),
            Ok(id) => panic!("{what}: the edge {id} was ADMITTED"),
        }
    }

    fn expect_admitted(r: Result<String, Error>, what: &str) {
        if let Err(e) = r {
            panic!("{what}: must be admitted, got {} ({e})", e.kind());
        }
    }

    /// No `delegates_to` from `from` to `to` is stored.
    async fn assert_no_edge(d: &dyn FederationDirectory, from: &str, to: &str, what: &str) {
        assert!(
            !d.list_attestations_by(from)
                .await
                .unwrap()
                .iter()
                .any(|r| r.attestation_type == attestation_type::DELEGATES_TO
                    && r.attested_key_id == to),
            "{what}: a refused edge must not be stored"
        );
    }

    /// **I1231** — the admission gate. See the module doc.
    #[allow(clippy::too_many_lines)]
    pub async fn i1231_term_bearing_edge_carries_a_bounded_term(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let k = |n: &str| format!("{tag}-{n}");
        let granter = k("granter");
        ts::register_hybrid_key_as(d, &granter, &granter, identity_type::USER).await;
        let now = Utc::now();
        let day = Duration::days(1);
        let mut n = 0;
        let mut recipient = || {
            n += 1;
            k(&format!("r{n}"))
        };

        // (1) Every trigger, without an upper bound: refused, not stored.
        // Kills: a trigger missing from the term-bearing set.
        let triggers: [(&str, serde_json::Value); 7] = [
            (
                "license",
                serde_json::json!({ "scope": [DELEGATION_SCOPE_LICENSE] }),
            ),
            (
                "grant",
                serde_json::json!({ "scope": [DELEGATION_SCOPE_GRANT] }),
            ),
            (
                "moderate",
                serde_json::json!({ "scope": [DELEGATION_SCOPE_MODERATE] }),
            ),
            (
                "takedown",
                serde_json::json!({ "scope": [DELEGATION_SCOPE_TAKEDOWN] }),
            ),
            (
                "review",
                serde_json::json!({ "scope": DELEGATION_SCOPE_REVIEW }),
            ),
            (
                "slash",
                serde_json::json!({ "scope": ["act_on_behalf", DELEGATION_SCOPE_SLASH] }),
            ),
            (
                "sub_delegation",
                serde_json::json!({ "scope": ["act_on_behalf"], "sub_delegation": true }),
            ),
        ];
        for (what, envelope) in triggers {
            let r = recipient();
            ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
            expect_refused(
                put_raw(d, &granter, &r, envelope.clone()).await,
                rule::TERM_MISSING,
                &format!("[{tag}] I1231(1) {what} with no term"),
            );
            assert_no_edge(d, &granter, &r, &format!("[{tag}] I1231(1) {what}")).await;
            // The same edge with a term inside the year admits.
            let mut termed = envelope;
            termed[DELEGATION_VALID_UNTIL_FIELD] = instant(now + day * 30);
            expect_admitted(
                put_raw(d, &granter, &r, termed).await,
                &format!("[{tag}] I1231(1) {what} with a 30-day term"),
            );
        }

        // (2) A term naming only its start is perpetual. Kills: reading
        // `delegation_valid_from` as a term.
        let r = recipient();
        ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
        expect_refused(
            put_raw(
                d,
                &granter,
                &r,
                serde_json::json!({
                    "scope": [DELEGATION_SCOPE_GRANT],
                    DELEGATION_VALID_FROM_FIELD: instant(now),
                }),
            )
            .await,
            rule::TERM_MISSING,
            &format!("[{tag}] I1231(2) a term naming only its start"),
        );

        // (3) A term naming only its end is measured from the signed
        // `asserted_at`. Kills: no span for a one-ended term (v54.0.0).
        for (days, ok) in [(366, false), (364, true)] {
            let r = recipient();
            ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
            let got = put_raw(
                d,
                &granter,
                &r,
                serde_json::json!({
                    "scope": [DELEGATION_SCOPE_GRANT],
                    DELEGATION_VALID_UNTIL_FIELD: instant(now + day * days),
                }),
            )
            .await;
            let what = format!("[{tag}] I1231(3) until-only, {days} days after signing");
            if ok {
                expect_admitted(got, &what);
            } else {
                expect_refused(got, rule::OVER_CEILING, &what);
            }
        }
        // The older spelling `valid_until` is the same bound.
        let r = recipient();
        ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
        expect_refused(
            put_raw(
                d,
                &granter,
                &r,
                serde_json::json!({
                    "scope": [DELEGATION_SCOPE_GRANT],
                    "valid_until": instant(now + day * 400),
                }),
            )
            .await,
            rule::OVER_CEILING,
            &format!("[{tag}] I1231(3) `valid_until` 400 days after signing"),
        );

        // (4) Both ends: the span is from `delegation_valid_from`.
        for (days, ok) in [(366, false), (365, true)] {
            let r = recipient();
            ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
            let from = now + day * 10;
            let got = put_raw(
                d,
                &granter,
                &r,
                serde_json::json!({
                    "scope": [DELEGATION_SCOPE_MODERATE],
                    DELEGATION_VALID_FROM_FIELD: instant(from),
                    DELEGATION_VALID_UNTIL_FIELD: instant(from + day * days),
                }),
            )
            .await;
            let what = format!("[{tag}] I1231(4) a {days}-day term");
            if ok {
                expect_admitted(got, &what);
            } else {
                expect_refused(got, rule::OVER_CEILING, &what);
            }
        }

        // (5) An unreadable member is a refusal, never "no bound".
        let r = recipient();
        ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
        expect_refused(
            put_raw(
                d,
                &granter,
                &r,
                serde_json::json!({
                    "scope": [DELEGATION_SCOPE_LICENSE],
                    DELEGATION_VALID_FROM_FIELD: "last spring",
                    DELEGATION_VALID_UNTIL_FIELD: instant(now + day * 30),
                }),
            )
            .await,
            rule::TERM_UNREADABLE,
            &format!("[{tag}] I1231(5) an unreadable delegation_valid_from"),
        );

        // (6) Not term-bearing: the term stays optional, and a start-only term
        // is open-ended. Kills: gating every `delegates_to`.
        for (what, envelope) in [
            (
                "perpetual",
                serde_json::json!({ "scope": ["act_on_behalf"] }),
            ),
            (
                "start-only",
                serde_json::json!({
                    "scope": ["act_on_behalf"],
                    DELEGATION_VALID_FROM_FIELD: instant(now),
                }),
            ),
            (
                "two years",
                serde_json::json!({
                    "scope": ["act_on_behalf"],
                    DELEGATION_VALID_UNTIL_FIELD: instant(now + day * 730),
                }),
            ),
        ] {
            let r = recipient();
            ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
            expect_admitted(
                put_raw(d, &granter, &r, envelope).await,
                &format!("[{tag}] I1231(6) act_on_behalf, {what}"),
            );
        }

        // (7) An edge naming an affiliation sits in its hierarchy: it needs a
        // term whatever its scope, and the charter's `role_term` (90 days)
        // bounds it. Kills: the hierarchy arm, and the role_term bound.
        let (aff, aff_keys) = make_group(
            d,
            &k("aff"),
            consensus_protocol::FOUNDER_ONLY,
            &["f"],
            1,
            Some(
                crate::federation::affiliation_invariants::bodies::affiliation_blob(Some(
                    serde_json::json!({ "role_term": 90 }),
                )),
            ),
            None,
        )
        .await;
        let (plain, plain_keys) = make_group(
            d,
            &k("plain"),
            consensus_protocol::FOUNDER_ONLY,
            &["f"],
            1,
            None,
            None,
        )
        .await;
        let in_group = |c: &str, until: Option<DateTime<Utc>>| {
            let mut e = serde_json::json!({ "scope": ["act_on_behalf"], "community_id": c });
            if let Some(u) = until {
                e[DELEGATION_VALID_UNTIL_FIELD] = instant(u);
            }
            e
        };
        for (what, until, want) in [
            ("no term", None, Some(rule::TERM_MISSING)),
            (
                "100 days",
                Some(now + day * 100),
                Some(rule::OVER_ROLE_TERM),
            ),
            ("80 days", Some(now + day * 80), None),
        ] {
            let r = recipient();
            ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
            let got = put_raw(d, &aff_keys[0], &r, in_group(&aff, until)).await;
            let what = format!("[{tag}] I1231(7) an edge in the affiliation's hierarchy, {what}");
            match want {
                Some(w) => expect_refused(got, w, &what),
                None => expect_admitted(got, &what),
            }
        }
        // A plain community has no hierarchy and no charter term.
        let r = recipient();
        ts::register_hybrid_key_as(d, &r, &r, identity_type::PRIMITIVE).await;
        expect_admitted(
            put_raw(d, &plain_keys[0], &r, in_group(&plain, None)).await,
            &format!("[{tag}] I1231(7) an edge naming a plain community, no term"),
        );

        // (8) Not gated: an owner-binding (CC 3.2 governs its lapse) even when
        // it grants `sub_delegation`. Kills: dropping the owner-binding
        // exemption.
        let node = k("node");
        ts::register_hybrid_key_as(d, &node, &node, identity_type::NODE).await;
        expect_admitted(
            put_raw(
                d,
                &granter,
                &node,
                serde_json::json!({
                    "dimension": crate::federation::types::owner_binding::DIMENSION,
                    "delegation_purpose": crate::federation::types::owner_binding::PURPOSE,
                    "scope": ["infra:serve"],
                    "sub_delegation": true,
                }),
            )
            .await,
            &format!("[{tag}] I1231(8) an owner-binding granting sub_delegation, no term"),
        );
        // A charter (the trust plane) carrying a moderation scope. Kills:
        // dropping the trust-plane exemption.
        expect_admitted(
            put_raw(
                d,
                &granter,
                &granter,
                serde_json::json!({
                    "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
                    "scope": ["infra:serve", DELEGATION_SCOPE_MODERATE],
                    "pre_rotation_commitment":
                        crate::federation::trust_root::test_pre_rotation_commitment(
                            &[format!("{granter}-successor")],
                        )
                        .expect("commitment"),
                }),
            )
            .await,
            &format!("[{tag}] I1231(8) a charter carrying `moderate`, no term"),
        );
    }

    /// **I1232** — #1048 item 1, the walks read the affiliation's `role_term`.
    pub async fn i1232_walks_read_the_affiliations_role_term(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let now = base();
        let holder = format!("{tag}-holder");
        ts::register_hybrid_key_as(d, &holder, &holder, identity_type::USER).await;
        // v60.0.0 (#1036 item 3) — the licence class this witness issues is
        // declared public, so the audience gate stays out of the way.
        let blob = crate::federation::affiliation_invariants::bodies::affiliation_blob(Some(
            serde_json::json!({
                "role_term": 90,
                "licence_audiences": { "professional_full": "federation" },
            }),
        ));
        let (aff, aff_keys) = make_group(
            d,
            &format!("{tag}-aff"),
            consensus_protocol::FOUNDER_ONLY,
            &["alice"],
            1,
            Some(blob),
            None,
        )
        .await;
        let (plain, plain_keys) = make_group(
            d,
            &format!("{tag}-plain"),
            consensus_protocol::FOUNDER_ONLY,
            &["bob"],
            1,
            None,
            None,
        )
        .await;
        let appointed = now - Duration::hours(2);
        let term = |days: i64| {
            [(
                DELEGATION_VALID_UNTIL_FIELD,
                instant(appointed + Duration::days(days)),
            )]
        };

        // A 200-day `license` edge: inside the constitutional year, so the
        // door admits it (it names no community), but past the affiliation's
        // 90-day charter term.
        let long = officer(d, tag, "long").await;
        let long_edge = must_put(
            d,
            &edge(
                &aff_keys[0],
                &long,
                &[DELEGATION_SCOPE_LICENSE],
                appointed,
                &term(200),
            ),
            "the founder appoints a 200-day licensing officer",
        )
        .await;
        must_refuse_as(
            d,
            &crate::federation::affiliation_licence_invariants::bodies::classed(licence(
                &long,
                &holder,
                &aff,
                "issued",
                Some(&long_edge.attestation_id),
                now - Duration::hours(1),
            )),
            crate::federation::admission::LicensureChainBreak::NotOnLiveChain,
            &format!("[{tag}] I1232: an officer whose term is past the affiliation's role_term"),
        )
        .await;
        // An 80-day officer is inside the charter term. Kills: a role_term
        // read as zero, or applied to every term.
        let short = officer(d, tag, "short").await;
        let short_edge = must_put(
            d,
            &edge(
                &aff_keys[0],
                &short,
                &[DELEGATION_SCOPE_LICENSE],
                appointed,
                &term(80),
            ),
            "the founder appoints an 80-day licensing officer",
        )
        .await;
        must_put(
            d,
            &crate::federation::affiliation_licence_invariants::bodies::classed(licence(
                &short,
                &holder,
                &aff,
                "issued",
                Some(&short_edge.attestation_id),
                now - Duration::hours(1),
            )),
            &format!("[{tag}] I1232: an officer inside the affiliation's role_term issues"),
        )
        .await;
        // The same 200-day edge under a plain community: no charter term.
        // Kills: a role_term invented for a community.
        let plain_long = officer(d, tag, "plain-long").await;
        let plain_edge = must_put(
            d,
            &edge(
                &plain_keys[0],
                &plain_long,
                &[DELEGATION_SCOPE_LICENSE],
                appointed,
                &term(200),
            ),
            "a plain community's founder appoints a 200-day officer",
        )
        .await;
        must_put(
            d,
            &licence(
                &plain_long,
                &holder,
                &plain,
                "issued",
                Some(&plain_edge.attestation_id),
                now - Duration::hours(1),
            ),
            &format!("[{tag}] I1232: a plain community's 200-day officer issues"),
        )
        .await;

        // The moderation walk scoped to the affiliation: an appointment that
        // names no room (absent-as-unscoped) with a 200-day term is dropped,
        // an 80-day one is followed; scoped to the plain community, the
        // 200-day appointment is followed.
        let mods: Vec<String> = ["mod-long", "mod-short"]
            .iter()
            .map(|n| format!("{tag}-{n}"))
            .collect();
        for (m, days) in mods.iter().zip([200, 80]) {
            ts::register_hybrid_key_as(d, m, m, identity_type::PRIMITIVE).await;
            for founder in [&aff_keys[0], &plain_keys[0]] {
                must_put(
                    d,
                    &edge(
                        founder,
                        m,
                        &[DELEGATION_SCOPE_MODERATE],
                        appointed,
                        &term(days),
                    ),
                    "a moderation appointment",
                )
                .await;
            }
        }
        let reach = |root: String, room: String| async move {
            crate::federation::admission::moderation_reach_of_at(d, &root, &room, now)
                .await
                .expect("walk")
        };
        let in_aff = reach(aff_keys[0].clone(), aff.clone()).await;
        assert!(
            !in_aff.contains(&mods[0]) && in_aff.contains(&mods[1]),
            "[{tag}] I1232: the affiliation's moderation walk drops the 200-day appointment and \
             follows the 80-day one: {in_aff:?}"
        );
        let in_plain = reach(plain_keys[0].clone(), plain.clone()).await;
        assert!(
            in_plain.contains(&mods[0]) && in_plain.contains(&mods[1]),
            "[{tag}] I1232: a plain community's walk follows both: {in_plain:?}"
        );
    }
}

/// **I1230** — the lens, pure. See the module doc.
#[cfg(test)]
mod lens {
    use crate::federation::admission::{
        delegation_term_live_at_for_test as live, DELEGATION_SCOPE_GRANT,
        DELEGATION_VALID_FROM_FIELD, DELEGATION_VALID_UNTIL_FIELD,
    };
    use chrono::{Duration, Utc};

    fn edge(envelope: serde_json::Value) -> crate::federation::Attestation {
        let mut row = crate::federation::tier_ingest::test_support::bare_attestation(
            "i1230", "a", "b", &envelope,
        );
        row.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        // Signed after the rules took effect (the grandfather arms set their
        // own instant).
        row.asserted_at = Utc::now();
        row
    }

    fn at(t: chrono::DateTime<Utc>) -> serde_json::Value {
        serde_json::Value::String(t.to_rfc3339())
    }

    #[test]
    fn i1230_the_lens_bounds_a_term_bearing_edge() {
        let e = |extra: serde_json::Value| {
            let mut env = serde_json::json!({ "scope": [DELEGATION_SCOPE_GRANT] });
            for (k, v) in extra.as_object().unwrap() {
                env[k] = v.clone();
            }
            edge(env)
        };
        let day = Duration::days(1);
        // Until-only, from the signed asserted_at. Kills: no span when only
        // the end is named.
        let r = e(serde_json::json!({}));
        let signed = r.asserted_at;
        let until_only = |days: i64| {
            let mut row = e(serde_json::json!({
                DELEGATION_VALID_UNTIL_FIELD: at(signed + Duration::days(days)),
            }));
            row.asserted_at = signed;
            row
        };
        assert!(
            !live(&until_only(366), signed + day, None),
            "366 days after signing"
        );
        assert!(
            live(&until_only(365), signed + day, None),
            "365 days after signing"
        );
        // The walk's role_term. Kills: ignoring the lens's role_term.
        assert!(
            !live(&until_only(100), signed + day, Some(90 * 86_400)),
            "100 days under a 90-day role_term"
        );
        assert!(
            live(&until_only(80), signed + day, Some(90 * 86_400)),
            "80 days under a 90-day role_term"
        );
        // Unreadable: never live.
        let odd = e(serde_json::json!({ DELEGATION_VALID_FROM_FIELD: "soon" }));
        assert!(!live(&odd, signed + day, None), "an unreadable term");
        // Both ends, past the ceiling.
        let both = e(serde_json::json!({
            DELEGATION_VALID_FROM_FIELD: at(signed),
            DELEGATION_VALID_UNTIL_FIELD: at(signed + day * 366),
        }));
        assert!(!live(&both, signed + day, None), "a 366-day two-ended term");
        // Not term-bearing: no bound applies. Kills: bounding every edge.
        let mut plain = edge(serde_json::json!({
            "scope": ["act_on_behalf"],
            DELEGATION_VALID_UNTIL_FIELD: at(signed + day * 730),
        }));
        plain.asserted_at = signed;
        assert!(
            live(&plain, signed + day, Some(90 * 86_400)),
            "act_on_behalf: the ceiling governs term-bearing edges"
        );
        // A perpetual term-bearing edge already stored stays live: the
        // admission gate refuses new ones; the lens is not retroactive.
        assert!(
            live(&e(serde_json::json!({})), signed + day * 1000, None),
            "a stored perpetual edge (admitted before the gate)"
        );
    }

    /// **I1234** — the grandfather ruling (CIRISPersist#1048, 2026-10-09):
    /// an edge signed before the term rules took effect keeps conferring
    /// under the reading it was admitted with. Kills: dropping the
    /// adoption-instant test (each arm below reads the v60 bound instead).
    #[test]
    fn i1234_an_edge_signed_before_adoption_keeps_the_v54_reading() {
        let adopted: chrono::DateTime<Utc> =
            crate::federation::admission::DELEGATION_TERM_ADOPTED_AT
                .parse()
                .unwrap();
        let signed = adopted - Duration::days(30);
        let day = Duration::days(1);
        let old = |extra: serde_json::Value| {
            let mut env = serde_json::json!({ "scope": [DELEGATION_SCOPE_GRANT] });
            for (k, v) in extra.as_object().unwrap() {
                env[k] = v.clone();
            }
            let mut row = edge(env);
            row.asserted_at = signed;
            row
        };
        // A one-ended term has no span under the v54 reading.
        let until_only = old(serde_json::json!({
            DELEGATION_VALID_UNTIL_FIELD: at(signed + day * 400),
        }));
        assert!(
            live(&until_only, signed + day, None),
            "I1234: a pre-adoption until-only edge is not measured from its asserted_at"
        );
        // The affiliation's role_term does not bound it.
        let short = old(serde_json::json!({
            DELEGATION_VALID_UNTIL_FIELD: at(signed + day * 100),
        }));
        assert!(
            live(&short, signed + day, Some(90 * 86_400)),
            "I1234: a pre-adoption edge is not held to a role_term"
        );
        // The v54 ceiling still binds a term naming both ends.
        let both = old(serde_json::json!({
            DELEGATION_VALID_FROM_FIELD: at(signed),
            DELEGATION_VALID_UNTIL_FIELD: at(signed + day * 366),
        }));
        assert!(
            !live(&both, signed + day, None),
            "I1234: the v54 ceiling on a two-ended term"
        );
        // The same until-only edge signed after adoption IS measured.
        let mut fresh = until_only.clone();
        fresh.asserted_at = adopted + day;
        assert!(
            !live(&fresh, adopted + day * 2, None),
            "I1234 control: post-adoption, 400 days from signing is past the ceiling"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    /// sqlite and postgres only (S5 retires the memory backend).
    macro_rules! on_every_backend {
        ($body:ident, $sqlite:ident, $postgres:ident, $prefix:literal) => {
            #[cfg(feature = "sqlite")]
            #[tokio::test(flavor = "multi_thread")]
            async fn $sqlite() {
                use crate::store::Backend as _;
                let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                super::bodies::$body(&b, &format!("{}-{}", $prefix, suffix())).await;
            }

            #[cfg(feature = "postgres")]
            #[tokio::test(flavor = "multi_thread")]
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
        i1231_term_bearing_edge_carries_a_bounded_term,
        i1231_sqlite,
        i1231_postgres,
        "i1231"
    );
    on_every_backend!(
        i1235_promotion_re_runs_the_term_gate,
        i1235_sqlite,
        i1235_postgres,
        "i1235"
    );
    on_every_backend!(
        i1232_walks_read_the_affiliations_role_term,
        i1232_sqlite,
        i1232_postgres,
        "i1232"
    );
}
