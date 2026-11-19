//! v59.0.0 (CIRISPersist#1099; CC 3.3.6.3) — **I1130–I1139: the self-roster
//! door and the steward predicate, on every backend.**
//!
//! v62 (E3): the self-roster door is O1's `identity:occurrence` counted
//! voices with S1's two paths and S1b's edition-2 evictions (T2's
//! `identity:occurrence_revocation`), CC 3.3.6.4. Every witness below runs on
//! edition 2; an assent is the same payload signed as the self by a roster key,
//! an objection an `objection:raised:v1` answer naming the row id. Deleted (the
//! earlier proposal / vote / receipt machinery has no edition-2 object, or O1
//! witnesses the property): I1130 (O1 I3020), I1135, I1138, I1139, I1143,
//! I1156 (O1 I3020/I3022, I3045–I3047), I1140 (O1 I3030), I1151. I1141's
//! `withdraws` of the genesis key's `key:record:v1` row is dropped (no edition-2
//! counterpart). No refusal token is pinned for a fold condition (CC 2.7).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::self_roster as sr;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, Attestation};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    /// Now, at the millisecond (the occurrence gate's resolution).
    pub(crate) fn ms_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("ms")
    }

    /// The node's clock moved forward by `secs` (the purge clock's test seam).
    pub(crate) fn advance(secs: i64) {
        crate::federation::steward_purge::test_clock::set(Some(
            chrono::Utc::now() + chrono::Duration::seconds(secs),
        ));
    }

    /// The node's clock back to the system's.
    pub(crate) fn reset_clock() {
        crate::federation::steward_purge::test_clock::set(None);
    }

    /// v62 (E3): one `identity:occurrence` statement (O1). `signer` (a seed)
    /// signs as `iss`: as the occurrence key itself (`iss == occurrence`, the
    /// own voice, role `occurrence_key`) or as the identity (an approval: the
    /// identity's genesis key, or a live roster key through its seat). The row's
    /// `sub` is the occurrence key and its `author` the identity.
    pub(crate) async fn occ_voice(
        d: &dyn FederationDirectory,
        signer: &str,
        iss: &str,
        identity: &str,
        occurrence: &str,
    ) -> Vec<u8> {
        occ_voice_at(d, signer, iss, identity, occurrence, ms_now()).await
    }

    /// The identity's current roster head (`refs.head`, required on every
    /// roster row, CC 3.3.6.4; O1 fix 3).
    pub(crate) async fn roster_head(
        d: &dyn FederationDirectory,
        identity: &str,
    ) -> crate::federation::edition2::names::RowId {
        crate::federation::edition2::occurrence::current_roster_head(d, &e2::kid(identity))
            .await
            .expect("the roster head reads")
            .unwrap_or_else(|| panic!("no roster head for {identity}: its key record is held"))
    }

    /// [`occ_voice`] asserted at `at` (the proposer's signed instant), on
    /// the identity's CURRENT roster head. A further voice of a held
    /// proposal names the same head while nothing lands between them.
    pub(crate) async fn occ_voice_at(
        d: &dyn FederationDirectory,
        signer: &str,
        iss: &str,
        identity: &str,
        occurrence: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Vec<u8> {
        let head = roster_head(d, identity).await;
        occ_voice_on(signer, iss, identity, occurrence, at, &head)
    }

    /// [`occ_voice_at`] on the named `head`.
    pub(crate) fn occ_voice_on(
        signer: &str,
        iss: &str,
        identity: &str,
        occurrence: &str,
        at: chrono::DateTime<chrono::Utc>,
        head: &crate::federation::edition2::names::RowId,
    ) -> Vec<u8> {
        use ciris_verify_core::cde::{self, Value};
        let t = |s: &str| Value::Text(s.to_owned());
        let mut m: Vec<(Value, Value)> = vec![
            (t("asserted_at"), Value::Uint(e2::ms(at))),
            (t("author"), t(&e2::kid(identity))),
            (t("identity_key_id"), t(&e2::kid(identity))),
            (t("occurrence_key_id"), t(&e2::kid(occurrence))),
            (
                t("device_class"),
                t(crate::federation::types::device_class::PHONE),
            ),
            (
                t("refs"),
                Value::Map(vec![(
                    t("head"),
                    ciris_verify_core::edition2::row_ref(&head.0),
                )]),
            ),
        ];
        m.sort_by_key(|(k, _)| cde::encode(k));
        ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(signer),
            &e2::kid(iss),
            &e2::kid(occurrence),
            "scores",
            "identity:occurrence",
            &Value::Map(m),
            vec![],
        )
        .expect("an identity:occurrence statement signs")
    }

    /// v62 (E3): `device` binds under `identity` through O1's door: the
    /// device's own voice first (held, lands nothing), then each approver's
    /// statement as the identity, in order. The last outcome.
    pub(crate) async fn bind(
        d: &dyn FederationDirectory,
        identity: &str,
        device: &str,
        approvers: &[&str],
    ) -> StatementOutcome {
        bind_at(d, identity, device, approvers, ms_now()).await
    }

    /// [`bind`] with every voice asserted at `at`.
    pub(crate) async fn bind_at(
        d: &dyn FederationDirectory,
        identity: &str,
        device: &str,
        approvers: &[&str],
        at: chrono::DateTime<chrono::Utc>,
    ) -> StatementOutcome {
        // One bind, one head: every voice names the head it was built on.
        let head = roster_head(d, identity).await;
        let own = e2::put_statement(
            d,
            &occ_voice_on(device, device, identity, device, at, &head),
        )
        .await
        .expect("the occurrence key's own voice is kept");
        assert!(
            matches!(own, StatementOutcome::Voice { .. }),
            "the own voice alone lands nothing: {own:?}"
        );
        let mut last = own;
        for a in approvers {
            last = e2::put_statement(d, &occ_voice_on(a, identity, identity, device, at, &head))
                .await
                .unwrap_or_else(|e| panic!("{a}'s approval of {device} under {identity}: {e}"));
        }
        last
    }

    /// v62 (E3): a three-key self `{f, d1, d2}` through O1's door (S1): d1
    /// lands at one key; d2 is proposed by d1 (held: `Pending`) and f's approval
    /// completes the strict majority.
    pub(crate) async fn three_e2(d: &dyn FederationDirectory, f: &str, d1: &str, d2: &str) {
        for k in [f, d1, d2] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        assert!(matches!(
            bind(d, f, d1, &[f]).await,
            StatementOutcome::Row { .. }
        ));
        let at = ms_now();
        assert!(matches!(
            bind_at(d, f, d2, &[d1], at).await,
            StatementOutcome::Pending { .. }
        ));
        let landed = e2::put_statement(d, &occ_voice_at(d, f, f, f, d2, at).await)
            .await
            .expect("the fixture's quorum approval");
        assert!(
            matches!(landed, StatementOutcome::Row { .. }),
            "the fixture's third key landed by quorum: {landed:?}"
        );
    }

    /// v62 (E3): is `device` an active occurrence of `f`, by identity-ref?
    pub(crate) async fn active_e2(d: &dyn FederationDirectory, f: &str, device: &str) -> bool {
        let dev = e2::kid(device);
        d.list_identity_occurrences_active(&e2::kid(f))
            .await
            .expect("active")
            .iter()
            .any(|o| o.occurrence_key_id == dev)
    }

    /// v62 (E3; O1 S1b, T2): `signer`'s `identity:occurrence_revocation` voice
    /// evicting `target` from self `f`, signed AS the self, at `at`. Every
    /// roster key's voice over the same revocation (same instant) counts.
    pub(crate) async fn evict_voice_at(
        d: &dyn crate::federation::FederationDirectory,
        signer: &str,
        f: &str,
        target: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Vec<u8> {
        let rev = crate::federation::types::IdentityOccurrenceRevocation {
            identity_key_id: e2::kid(f),
            occurrence_key_id: e2::kid(target),
            revoked_at: at,
            effective_at: at,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        };
        e2::occurrence_revocation_voice(d, signer, true, &rev, None, &[], &[], e2::ms(at)).await
    }

    /// The proposal id of a roster change: its row id (O1 S1).
    pub(crate) fn row_hex(statement: &[u8]) -> String {
        crate::federation::edition2::names::RowId::of_statement(statement)
            .expect("a statement has a row id")
            .hex()
    }

    /// Put `statement`; the outcome (a refusal panics: the caller expects a
    /// kept voice or a landing).
    pub(crate) async fn put_st(d: &dyn FederationDirectory, statement: &[u8]) -> StatementOutcome {
        e2::put_statement(d, statement)
            .await
            .unwrap_or_else(|e| panic!("a voice is kept or lands: {e}"))
    }

    /// Did the statement land the change (not merely kept as a voice)?
    pub(crate) fn landed(o: &StatementOutcome) -> bool {
        matches!(o, StatementOutcome::Row { .. })
    }

    /// `voter`'s `objection:{raised|assent}:v1` answer naming proposal
    /// `proposal` of self `f` (O1 S1's answer shape), as an edition-2 statement.
    pub(crate) async fn answer(
        d: &dyn FederationDirectory,
        voter: &str,
        f: &str,
        proposal: &str,
        assent: bool,
    ) {
        let now = ms_now();
        let a = Attestation {
            attestation_id: String::new(),
            attesting_key_id: e2::kid(voter),
            attested_key_id: e2::kid(f),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": if assent { "objection:assent:v1" } else { "objection:raised:v1" },
                "score": if assent { 1.0 } else { -1.0 },
                "confidence": 1.0,
                "cohort": "self",
                "cohort_key_id": e2::kid(f),
                "objects_to_attestation_id": proposal,
                "grounds": "",
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: e2::kid(voter),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        e2::put_statement(d, &e2::statement_of(&a, voter))
            .await
            .expect("an answer is kept");
    }

    /// `who` signs something now (a self-report through the codec): any
    /// signed act answers.
    pub(crate) async fn act_e2(d: &dyn FederationDirectory, who: &str) {
        let now = ms_now();
        let mut r = ts::bare_attestation(
            "",
            who,
            who,
            &serde_json::json!({ "dimension": "config:i1132_act:v1", "n": 1 }),
        );
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = now;
        r.scrub_timestamp = now;
        e2::put_row(d, &r, who).await;
    }

    /// v62 (E3): `author`'s owner binding of `node`, then the node's own
    /// voice, which an owner binding counts (C557).
    /// v62 (E3b, round 3): both through the EDITION-2 door. The binding is a
    /// counted row (V1b): the author's statement alone is kept `Pending`
    /// there, and the node's voice lands it. The JSON door
    /// (`put_attestation`) answers the same shortfall as the refusal
    /// `owner_binding_counted_short`, so it cannot carry a counted row.
    pub(crate) async fn put_binding(
        d: &dyn FederationDirectory,
        author: &str,
        node: &str,
    ) -> Result<(), Error> {
        put_binding_row(d, &binding(author, node), node).await
    }

    /// [`put_binding`] of a built (e.g. re-dated) binding `row` of `node`.
    pub(crate) async fn put_binding_row(
        d: &dyn FederationDirectory,
        row: &Attestation,
        node: &str,
    ) -> Result<(), Error> {
        // K2.api: the shared landing (owner's statement, then the bound
        // node's voice; asserts Row).
        ts::put_sealed_owner_binding(d, row, node).await
    }

    /// **I1131** — two keys: an addition is a proposal; the other key's
    /// assent lands it.
    pub(crate) async fn i1131_two_keys_quorum(d: &dyn FederationDirectory, tag: &str) {
        // v62 (E3): O1's counted voices (CC 3.3.6.4). A roster change lands at a
        // strict majority of the live roster signing as the identity; the
        // proposer counts; short of it the statement is a kept voice.
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        for k in [&f, &d1, &d2] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        let one = bind(d, &f, &d1, &[&f]).await;
        assert!(
            matches!(one, StatementOutcome::Row { .. }),
            "I1131: at one key the identity's approval lands: {one:?}"
        );
        assert!(active_e2(d, &f, &d1).await, "I1131: d1 is active");
        // Two keys: d1 proposes d2 (its approval as f); 1 of 2 is no majority.
        let at = ms_now();
        let short = bind_at(d, &f, &d2, &[&d1], at).await;
        assert!(
            matches!(short, StatementOutcome::Pending { .. }),
            "I1131: one voice of two is kept, not landed: {short:?}"
        );
        assert!(
            !active_e2(d, &f, &d2).await,
            "I1131: the kept voice is not an effect"
        );
        // f's assent: the SAME payload (the same instant), signed as the self.
        let assent = e2::put_statement(d, &occ_voice_at(d, &f, &f, &f, &d2, at).await)
            .await
            .expect("I1131: f's approval");
        assert!(
            matches!(assent, StatementOutcome::Row { .. }),
            "I1131: the second voice makes a strict majority: {assent:?}"
        );
        assert!(active_e2(d, &f, &d2).await, "I1131: d2 landed at once");
    }

    /// **I1132** — the lone path: an unanswered eviction lands after W_self;
    /// a target that spoke is evictable only by quorum.
    pub(crate) async fn i1132_lone_path_and_silence(d: &dyn FederationDirectory, tag: &str) {
        // v62 (E3; O1 S1b): an edition-2 eviction, the lone path.
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        three_e2(d, &f, &d1, &d2).await;
        let me = e2::kid(&f);
        let o = put_st(d, &evict_voice_at(d, &d1, &f, &d2, ms_now()).await).await;
        assert!(
            !landed(&o),
            "I1132: d1's eviction of d2 at three keys is held: {o:?}"
        );
        assert!(active_e2(d, &f, &d2).await, "I1132: not before the window");
        advance(sr::W_SELF_SECS - 60);
        sr::execute_for(d, &me).await.expect("execute");
        assert!(active_e2(d, &f, &d2).await, "I1132: not a minute early");
        advance(sr::W_SELF_SECS + 1);
        sr::execute_for(d, &me).await.expect("execute");
        reset_clock();
        assert!(
            !active_e2(d, &f, &d2).await,
            "I1132: unanswered, the eviction landed by the lone path"
        );

        // A target that speaks closes the lone path.
        let (g, e1, e2k) = (format!("g-{tag}"), format!("e1-{tag}"), format!("e2-{tag}"));
        three_e2(d, &g, &e1, &e2k).await;
        let o = put_st(d, &evict_voice_at(d, &e1, &g, &e2k, ms_now()).await).await;
        assert!(!landed(&o), "I1132 (b): {o:?}");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        act_e2(d, &e2k).await;
        advance(10 * sr::W_SELF_SECS);
        sr::execute_for(d, &e2::kid(&g)).await.expect("execute");
        reset_clock();
        assert!(
            active_e2(d, &g, &e2k).await,
            "I1132: a target that signed since the proposal is evictable only by quorum"
        );
    }

    /// **I1133** — the thief: one key's lone eviction of another at three
    /// keys does not land, and once the owner's keys object it never does.
    pub(crate) async fn i1133_the_thief_cannot_evict(d: &dyn FederationDirectory, tag: &str) {
        // v62 (E3; O1 S1b): the thief's edition-2 eviction, objected to by a
        // strict majority of the other roster keys, never lands.
        let (f, thief, owner) = (format!("f-{tag}"), format!("t-{tag}"), format!("o-{tag}"));
        three_e2(d, &f, &thief, &owner).await;
        let st = evict_voice_at(d, &thief, &f, &owner, ms_now()).await;
        let p = row_hex(&st);
        let o = put_st(d, &st).await;
        assert!(!landed(&o), "I1133: the thief's eviction is held: {o:?}");
        assert!(active_e2(d, &f, &owner).await, "I1133: refused at age 0");
        answer(d, &owner, &f, &p, false).await;
        answer(d, &f, &f, &p, false).await;
        advance(10 * sr::W_SELF_SECS);
        sr::execute_for(d, &e2::kid(&f)).await.expect("execute");
        reset_clock();
        assert!(
            active_e2(d, &f, &owner).await,
            "I1133: answered, the thief's eviction never lands"
        );
    }

    /// **I1134** — an assent from a key evicted since is void.
    pub(crate) async fn i1134_an_evicted_keys_vote_is_void(d: &dyn FederationDirectory, tag: &str) {
        // v62 (E3; O1 S1/S1b): an assent is the same payload signed as the self
        // by a roster key; an evicted key's assent is void.
        let (f, d1, d2, d3, d4) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("d2-{tag}"),
            format!("d3-{tag}"),
            format!("d4-{tag}"),
        );
        three_e2(d, &f, &d1, &d2).await;
        for k in [&d3, &d4] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        // {f, d1, d2} → {f, d1, d2, d3}: f proposes, d1 assents (2 of 3).
        let t3 = ms_now();
        assert!(!landed(&bind_at(d, &f, &d3, &[&f], t3).await));
        assert!(landed(
            &put_st(d, &occ_voice_at(d, &d1, &f, &f, &d3, t3).await).await
        ));
        assert!(active_e2(d, &f, &d3).await);
        // d2 proposes d4 (1 of 4); d1 assents (2 of 4: no majority yet).
        let t4 = ms_now();
        assert!(!landed(&bind_at(d, &f, &d4, &[&d2], t4).await));
        assert!(!landed(
            &put_st(d, &occ_voice_at(d, &d1, &f, &f, &d4, t4).await).await
        ));
        assert!(!active_e2(d, &f, &d4).await, "I1134: 2 of 4 is no majority");
        // d1 is evicted by quorum: f proposes, d2 and d3 assent (3 of 4).
        let te = ms_now();
        assert!(!landed(
            &put_st(d, &evict_voice_at(d, &f, &f, &d1, te).await).await
        ));
        assert!(!landed(
            &put_st(d, &evict_voice_at(d, &d2, &f, &d1, te).await).await
        ));
        assert!(landed(
            &put_st(d, &evict_voice_at(d, &d3, &f, &d1, te).await).await
        ));
        assert!(!active_e2(d, &f, &d1).await, "I1134: d1 evicted");
        sr::execute_for(d, &e2::kid(&f)).await.expect("execute");
        // {f, d2, d3}: d4's proposal has d2 (proposer) + d1 (void) = 1 of 3.
        assert!(
            !active_e2(d, &f, &d4).await,
            "I1134: the evicted d1's assent made a majority of the smaller roster"
        );
        // The evicted key is off the roster the quorum is counted over too.
        let d5 = format!("d5-{tag}");
        e2::put_key(d, &d5, &[it::USER]).await;
        let t5 = ms_now();
        assert!(!landed(&bind_at(d, &f, &d5, &[&f], t5).await));
        assert!(
            landed(&put_st(d, &occ_voice_at(d, &d2, &f, &f, &d5, t5).await).await),
            "I1134: 2 of the live 3 lands; the quorum was counted over a roster that kept d1"
        );
        assert!(active_e2(d, &f, &d5).await);
        // {f, d2, d3, d5}: d4 needs 3 — d2, then d3 and d5. d2's first
        // proposal stood on the head d1's eviction succeeded, so it is VOID
        // here (CC 2.7.8); d2 proposes d4 again on the current head.
        assert!(!landed(&bind_at(d, &f, &d4, &[&d2], t4).await));
        assert!(!landed(
            &put_st(d, &occ_voice_at(d, &d3, &f, &f, &d4, t4).await).await
        ));
        assert!(!active_e2(d, &f, &d4).await, "I1134: 2 of 4 is no majority");
        assert!(landed(
            &put_st(d, &occ_voice_at(d, &d5, &f, &f, &d4, t4).await).await
        ));
        assert!(active_e2(d, &f, &d4).await, "I1134: live assents land it");
    }

    /// **I1136** — the window is the node's: a backdated proposal is as young
    /// as its arrival.
    pub(crate) async fn i1136_the_window_is_the_nodes(d: &dyn FederationDirectory, tag: &str) {
        // v62 (E3): O1 S1. The lone path's window runs from THIS node's
        // receipt, never from the signed instant.
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        for k in [&f, &d1, &d2] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        let backdated = ms_now() - chrono::Duration::seconds(2 * sr::W_SELF_SECS);
        // d1 signs as f at `backdated`: it must be f's key THEN (way (d) of
        // the key-of-issuer check reads its occurrence live at the
        // statement's instant), so its bind is asserted just before.
        assert!(matches!(
            bind_at(d, &f, &d1, &[&f], backdated - chrono::Duration::minutes(1)).await,
            StatementOutcome::Row { .. }
        ));
        let held = bind_at(d, &f, &d2, &[&d1], backdated).await;
        assert!(
            matches!(held, StatementOutcome::Pending { .. }),
            "I1136: d1's proposal at two keys is a kept voice: {held:?}"
        );
        let me = e2::kid(&f);
        sr::execute_for(d, &me).await.expect("execute");
        assert!(
            !active_e2(d, &f, &d2).await,
            "I1136: a proposal signed two windows ago landed on arrival"
        );
        let s = sr::standing(d, &me).await.unwrap();
        let crate::federation::two_path::TwoPathDecision::Pending {
            earliest_lone_at: Some(opens),
            ..
        } = s[0].decision
        else {
            panic!("I1136: {s:?}");
        };
        assert!(
            opens > chrono::Utc::now(),
            "I1136: the window opens in the future"
        );
    }

    /// A `consent:replication:v1` grant by `author` to `peer`, FOR `node`.
    fn grant(author: &str, peer: &str, node: &str) -> Attestation {
        let env = serde_json::json!({
            "dimension": crate::federation::consent_peer_set::DIMENSION,
            "payload": {
                "grants": "replication",
                "attestation_prefixes": ["i1137:"],
                crate::federation::consent_by_humans::FOR_KEY_ID: node,
            },
        });
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = ts::bare_attestation(&id, author, author, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.subject_key_ids = vec![peer.to_owned()];
        r.asserted_at = ms_now();
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(author, &mut r);
        r
    }

    /// `author`'s owner-binding of `node`, signed now.
    fn binding(author: &str, node: &str) -> Attestation {
        let mut r = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), author, node);
        r.asserted_at = ms_now();
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(author, &mut r);
        r
    }

    /// **I1137** — THE steward predicate at both gates.
    pub(crate) async fn i1137_a_second_device_acts_as_its_self(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::consent_by_humans as cbh;
        let (f, d1, node, peer) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("n-{tag}"),
            format!("p-{tag}"),
        );
        let (g, e1, peer2) = (format!("g-{tag}"), format!("e1-{tag}"), format!("q-{tag}"));
        // v62 (E3): edition-2 keys; the devices bind through O1's door; ids
        // compared as identity-refs.
        for k in [&f, &d1, &peer, &g, &e1, &peer2] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        e2::put_key(d, &node, &[it::NODE]).await;
        let (node_k, peer_k) = (e2::kid(&node), e2::kid(&peer));
        assert!(matches!(
            bind(d, &f, &d1, &[&f]).await,
            StatementOutcome::Row { .. }
        ));
        assert!(matches!(
            bind(d, &g, &e1, &[&g]).await,
            StatementOutcome::Row { .. }
        ));
        put_binding(d, &f, &node)
            .await
            .expect("I1137: f owns the node");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        // The consent fold.
        let mine = grant(&d1, &peer, &node_k);
        crate::federation::edition2::fixture_switch::put_signed(d, &mine)
            .await
            .expect("I1137: d1's grant is admitted");
        assert!(
            cbh::grant_is_authored_for(d, &mine, &node_k).await.unwrap(),
            "I1137: a live roster key of the owner authors as the owner"
        );
        let theirs = grant(&e1, &peer2, &node_k);
        crate::federation::edition2::fixture_switch::put_signed(d, &theirs)
            .await
            .expect("I1137: e1's grant is admitted");
        assert!(
            !cbh::grant_is_authored_for(d, &theirs, &node_k)
                .await
                .unwrap(),
            "I1137: a key of another self is not the node's steward"
        );
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node_k).await.unwrap(),
            vec![peer_k.clone()],
            "I1137: the second device's grant counts; another self's does not"
        );

        // The one-responsible-steward gate.
        put_binding(d, &d1, &node)
            .await
            .expect("I1137: d1 restates its self's binding: the same one steward");
        assert_eq!(
            crate::federation::admission::owner_of(d, &node_k)
                .await
                .unwrap(),
            Some(e2::kid(&f)),
            "I1137: the node has one owner, the self"
        );
        // I2843 (K2) — another self's key binding the node is HELD, not
        // refused: the seat counts two selves, so the node reads as unowned
        // (fail-closed), never as whichever self bound first.
        put_binding(d, &e1, &node)
            .await
            .expect("I2843: another self's key binding the node is held");
        match crate::federation::admission::owner_of(d, &node_k).await {
            Err(Error::AmbiguousNodeOwner { owners, .. }) => assert!(
                owners.contains(&e2::kid(&f)) && owners.len() == 2,
                "I2843: the two selves are the counted owners: {owners:?}"
            ),
            other => panic!("I2843: two selves bound the node, got {other:?}"),
        }
    }

    /// **I1161** (#1109) — `nodes_owned_by` places a node a roster key
    /// announced. A device joined by approval (`<fedID>-<fp>`) binds a node;
    /// `owner_of` credits the binding to the self, and the reverse walk now
    /// returns it. A node another self's roster key bound is that self's,
    /// and a node a key bound AFTER its eviction is that key's own, so
    /// neither is the self's. For every node, `n ∈ nodes_owned_by(f) ⟺
    /// owner_of(n) == f`.
    pub(crate) async fn i1161_nodes_owned_by_places_a_roster_keys_node(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // v62 (E3; O1 S1/S1b): edition-2 binds, owner bindings with the node's
        // voice, and an edition-2 eviction; ids compared as identity-refs.
        use crate::federation::admission::{nodes_owned_by, owner_of};
        use std::collections::BTreeSet;
        let (f, d1, d2) = (
            format!("f-{tag}"),
            format!("f-{tag}-fp1"),
            format!("f-{tag}-fp2"),
        );
        let (g, e1) = (format!("g-{tag}"), format!("g-{tag}-fp1"));
        let nodes: Vec<String> = ["own", "dev", "other", "evicted"]
            .iter()
            .map(|n| format!("n-{n}-{tag}"))
            .collect();
        let [own, dev, other, evicted] = &nodes[..] else {
            unreachable!()
        };
        three_e2(d, &f, &d1, &d2).await;
        for k in [&g, &e1] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        assert!(landed(&bind(d, &g, &e1, &[&g]).await), "g's second key");
        for n in &nodes {
            e2::put_key(d, n, &[it::NODE]).await;
        }
        put_binding(d, &f, own)
            .await
            .expect("I1161: f binds a node with its own key");
        put_binding(d, &d1, dev)
            .await
            .expect("I1161: f's approved device binds a node with its roster key");
        put_binding(d, &e1, other)
            .await
            .expect("I1161: g's roster key binds a node");

        // d2 leaves f's roster by quorum, then binds a node as itself.
        let te = ms_now();
        assert!(!landed(
            &put_st(d, &evict_voice_at(d, &f, &f, &d2, te).await).await
        ));
        assert!(landed(
            &put_st(d, &evict_voice_at(d, &d1, &f, &d2, te).await).await
        ));
        assert!(!active_e2(d, &f, &d2).await, "I1161: d2 was evicted");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        put_binding(d, &d2, evicted)
            .await
            .expect("I1161: an evicted key binds a node as itself");

        let k = |s: &str| e2::kid(s);
        assert_eq!(owner_of(d, &k(dev)).await.unwrap(), Some(k(&f)));
        assert_eq!(owner_of(d, &k(evicted)).await.unwrap(), Some(k(&d2)));
        let set = |v: Vec<String>| v.into_iter().collect::<BTreeSet<String>>();
        let mine = nodes_owned_by(d, &k(&f)).await.unwrap();
        assert_eq!(
            set(mine.clone()),
            set(vec![k(dev), k(own)]),
            "I1161: f owns its own node and its roster key's, nothing else"
        );
        assert_eq!(
            set(nodes_owned_by(d, &k(&g)).await.unwrap()),
            set(vec![k(other)]),
            "I1161: g's roster key's node is g's"
        );
        assert_eq!(
            set(nodes_owned_by(d, &k(&d2)).await.unwrap()),
            set(vec![k(evicted)]),
            "I1161: the evicted key's later node is its own"
        );
        for n in &nodes {
            assert_eq!(
                mine.contains(&k(n)),
                owner_of(d, &k(n)).await.unwrap() == Some(k(&f)),
                "I1161: {n}: nodes_owned_by and owner_of agree"
            );
        }
    }

    /// **I1342** (v60.0.0) — `nodes_owned_by` walks `owner_of` only for an
    /// owner-binding's node. A `delegates_to` the person signed for any other
    /// purpose (a `moderate` delegation to a peer) names no candidate, so the
    /// reverse walk reads nothing about its grantee; the owner-binding's node
    /// is walked and placed (the control). Since the verdict is `owner_of`,
    /// over-admitting a candidate changes no answer, only what is read, so
    /// I1161 cannot see the seek's filter and the read probe can.
    pub(crate) async fn i1342_the_seek_walks_owner_bindings_only(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::{self, nodes_owned_by};
        use crate::federation::read_probe;
        let (f, peer, node) = (format!("f-{tag}"), format!("p-{tag}"), format!("n-{tag}"));
        // v62 (E3): edition-2 keys; ids compared as identity-refs.
        for k in [&f, &peer] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        e2::put_key(d, &node, &[it::NODE]).await;
        put_binding(d, &f, &node)
            .await
            .expect("I1342: f binds a node");
        let (node_k, peer_k) = (e2::kid(&node), e2::kid(&peer));
        crate::federation::grant_scope_invariants::bodies::put_delegation(
            d,
            &f,
            &f,
            &peer,
            admission::DELEGATION_SCOPE_MODERATE,
            ms_now(),
            None,
        )
        .await;
        let _ = read_probe::take();
        assert_eq!(
            nodes_owned_by(d, &e2::kid(&f)).await.unwrap(),
            vec![node_k.clone()],
            "I1342: f owns its bound node, and the delegate is not a node"
        );
        let log = read_probe::take();
        assert!(
            log.iter().any(|r| r.door_key() == node_k),
            "I1342: the owner-binding's node is walked (the probe sees the walk)"
        );
        let stray: Vec<_> = log.iter().filter(|r| r.door_key() == peer_k).collect();
        assert!(
            stray.is_empty(),
            "I1342: a non-owner delegates_to names no candidate, so nothing reads its grantee: {stray:?}"
        );
    }

    /// **I1141** — the genesis key is evictable (CC 3.3.6.3, rc9 69fd22e):
    /// another roster key's `withdraws` of the self pair `(F, F)`'s occurrence
    /// row is a proposal, lands by quorum, and then the genesis key is off the
    /// roster, cannot sign for the self, and is no steward — while the fedID
    /// string keeps naming the self, its other keys act as it, and its key
    /// record stays a valid key. The genesis key's own `withdraws` of that row
    /// retires its transport self-occurrence and evicts nothing; a `withdraws`
    /// of the genesis key's `key:record:v1` row evicts nothing.
    pub(crate) async fn i1141_the_genesis_key_is_evictable(d: &dyn FederationDirectory, tag: &str) {
        // v62 (E3; O1 S1b): the genesis key's eviction is another roster key's
        // edition-2 revocation of `(F, F)`, landed by quorum. (The earlier
        // `withdraws` of the genesis key's `key:record:v1` row has no edition-2
        // counterpart: a key's own end is `key:revocation`.)
        let (f, d1, d2, d3) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("d2-{tag}"),
            format!("d3-{tag}"),
        );
        for k in [&f, &d1, &d2, &d3] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        let me = e2::kid(&f);
        assert!(
            landed(&put_st(d, &occ_voice(d, &f, &f, &f, &f).await).await),
            "the transport self-occurrence"
        );
        assert!(landed(&bind(d, &f, &d1, &[&f]).await), "one key");
        let t2 = ms_now();
        assert!(!landed(&bind_at(d, &f, &d2, &[&f], t2).await));
        assert!(landed(
            &put_st(d, &occ_voice_at(d, &d1, &f, &f, &d2, t2).await).await
        ));

        let te = ms_now();
        let o = put_st(d, &evict_voice_at(d, &d1, &f, &f, te).await).await;
        assert!(
            !landed(&o),
            "I1141: d1 proposes the genesis key's eviction: {o:?}"
        );
        assert!(sr::roster_now(d, &me).await.unwrap().contains(&me));
        assert!(landed(
            &put_st(d, &evict_voice_at(d, &d2, &f, &f, te).await).await
        ));
        let roster = sr::roster_now(d, &me).await.unwrap();
        assert!(
            !roster.contains(&me)
                && roster.contains(&e2::kid(&d1))
                && roster.contains(&e2::kid(&d2)),
            "I1141: the genesis key left the roster: {roster:?}"
        );
        let now = chrono::Utc::now();
        assert!(!sr::acts_as_steward_at(d, &me, &me, now).await.unwrap());
        assert!(
            sr::acts_as_steward_at(d, &me, &e2::kid(&d1), now)
                .await
                .unwrap(),
            "I1141: the fedID string survives; a live roster key acts as it"
        );
        // The evicted genesis key no longer signs for the self (not pinned to
        // a token: CC 2.7).
        let t3 = ms_now();
        put_st(d, &occ_voice_at(d, &d3, &d3, &f, &d3, t3).await).await;
        // v62 (CC 2.7.3): its statement is not refused but HELD (the signer
        // no longer acts for the self: a fold condition), and lands nothing.
        let by_evicted = e2::put_statement(d, &occ_voice_at(d, &f, &f, &f, &d3, t3).await).await;
        assert!(
            !matches!(by_evicted, Ok(StatementOutcome::Row { .. })),
            "I1141: an evicted genesis key signs for the self: {by_evicted:?}"
        );
        assert!(
            !active_e2(d, &f, &d3).await,
            "I1141: the evicted genesis key's statement binds nothing"
        );
        // {d1, d2}: d1's addition needs d2.
        assert!(!landed(
            &put_st(d, &occ_voice_at(d, &d1, &f, &f, &d3, t3).await).await
        ));
        assert!(landed(
            &put_st(d, &occ_voice_at(d, &d2, &f, &f, &d3, t3).await).await
        ));
        assert!(
            active_e2(d, &f, &d3).await,
            "I1141: the self goes on without its genesis key"
        );

        // The key record stays held: every row the genesis key signed while
        // live still verifies.
        assert!(d.lookup_public_key(&me).await.unwrap().is_some());

        // The genesis key revoking its own pair is not an eviction: it retires
        // the transport self-occurrence, at once.
        let (g, e1) = (format!("g-{tag}"), format!("e1-{tag}"));
        for k in [&g, &e1] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        assert!(landed(
            &put_st(d, &occ_voice(d, &g, &g, &g, &g).await).await
        ));
        assert!(landed(&bind(d, &g, &e1, &[&g]).await), "one key");
        assert!(
            landed(&put_st(d, &evict_voice_at(d, &g, &g, &g, ms_now()).await).await),
            "I1141: g retires its transport self-occurrence at once"
        );
        assert!(
            !active_e2(d, &g, &g).await,
            "I1141: the self pair is retired"
        );
        assert!(
            sr::roster_now(d, &e2::kid(&g))
                .await
                .unwrap()
                .contains(&e2::kid(&g)),
            "I1141: the genesis key's own revocation evicted it"
        );
    }

    /// **I1142** — the steward check's instant is bounded by W at admission
    /// (CIRISPersist#1049): an evicted key signing inside its old live window
    /// but more than W ago is refused `asserted_at_stale`, at the consent
    /// gate and at the owner-binding gate; a live roster key inside W passes.
    pub(crate) async fn i1142_an_evicted_key_cannot_sign_into_its_old_window(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::consent_by_humans as cbh;
        let (f, d1, d2, node, peer) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("d2-{tag}"),
            format!("n-{tag}"),
            format!("p-{tag}"),
        );
        // v62 (E3; O1 S1/S1b): edition-2 keys, binds and eviction.
        for k in [&f, &d1, &d2, &peer] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        e2::put_key(d, &node, &[it::NODE]).await;
        let node_k = e2::kid(&node);
        let days = |n: i64| ms_now() - chrono::Duration::days(n);
        // d1 live since five days ago; d2 added through the door.
        assert!(
            landed(&bind_at(d, &f, &d1, &[&f], days(5)).await),
            "one key"
        );
        let t2 = ms_now();
        assert!(!landed(&bind_at(d, &f, &d2, &[&f], t2).await));
        assert!(landed(
            &put_st(d, &occ_voice_at(d, &d1, &f, &f, &d2, t2).await).await
        ));
        put_binding(d, &f, &node)
            .await
            .expect("I1142: f owns the node");
        // Evict d1 by quorum: f proposes, d2 assents.
        let te = ms_now();
        assert!(!landed(
            &put_st(d, &evict_voice_at(d, &f, &f, &d1, te).await).await
        ));
        assert!(landed(
            &put_st(d, &evict_voice_at(d, &d2, &f, &d1, te).await).await
        ));
        assert!(!active_e2(d, &f, &d1).await, "I1142: d1 evicted");

        let mut stale = grant(&d1, &peer, &node_k);
        stale.asserted_at = days(4);
        stale.scrub_timestamp = stale.asserted_at;
        ts::seal_row_in_place(&d1, &mut stale);
        let e = d
            .put_attestation(SignedAttestation { attestation: stale })
            .await
            .expect_err("I1142: the evicted d1's backdated grant");
        assert!(
            matches!(e, Error::AssertedAtStale { .. })
                && e.kind() == "federation_invalid_argument"
                && e.to_string().starts_with(sr::ASSERTED_AT_STALE),
            "I1142: {e}"
        );

        let mut stale_bind = binding(&d1, &node);
        stale_bind.asserted_at = days(4);
        stale_bind.scrub_timestamp = stale_bind.asserted_at;
        ts::seal_row_in_place(&d1, &mut stale_bind);
        // v62 (E3b, round 3): through the edition-2 door, where the roster W
        // bound (`check_owner_binding_roster_fresh`) runs before the count.
        let e = e2::put_signed(d, &stale_bind)
            .await
            .expect_err("I1142: the evicted d1's backdated owner-binding");
        assert!(
            matches!(e, Error::AssertedAtStale { .. })
                && e.kind() == "federation_invalid_argument"
                && e.to_string().starts_with(sr::ASSERTED_AT_STALE),
            "I1142: {e}"
        );

        // A live roster key inside W passes, and counts.
        let mut fresh = grant(&d2, &peer, &node_k);
        fresh.asserted_at = ms_now();
        fresh.scrub_timestamp = fresh.asserted_at;
        ts::seal_row_in_place(&d2, &mut fresh);
        crate::federation::edition2::fixture_switch::put_signed(d, &fresh)
            .await
            .expect("I1142: d2's grant now is inside W");
        assert!(cbh::grant_is_authored_for(d, &fresh, &node_k)
            .await
            .unwrap());
    }

    /// **I1149** — W bounds only a key that is NOT live now (CC 3.3.6.3, rc9
    /// 69fd22e): a still-live roster key's consent grant and owner-binding,
    /// signed more than W ago, admit on the node that saw them and on a fresh
    /// node the history is replayed to.
    pub(crate) async fn i1149_a_live_keys_old_rows_replicate(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::consent_by_humans as cbh;
        let (f, d1, node, peer) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("n-{tag}"),
            format!("p-{tag}"),
        );
        let days = |n: i64| ms_now() - chrono::Duration::days(n);
        // v62 (E3): edition-2 keys and binds (O1); ids compared as
        // identity-refs; the owner binding counts the node's voice (C557).
        for d in [a, b] {
            for k in [&f, &d1, &peer] {
                e2::put_key(d, k, &[it::USER]).await;
            }
            e2::put_key(d, &node, &[it::NODE]).await;
        }
        let node_k = e2::kid(&node);
        // d1 live since five days ago, and still live; f owns the node since
        // then. d1 acts for f on f's standing — so W is asked — at 4 and 3.5
        // days ago, both more than W.
        assert!(matches!(
            bind_at(a, &f, &d1, &[&f], days(5)).await,
            StatementOutcome::Row { .. }
        ));
        let mut own = binding(&f, &node);
        own.asserted_at = days(5) + chrono::Duration::hours(1);
        own.scrub_timestamp = own.asserted_at;
        ts::seal_row_in_place(&f, &mut own);
        let node_voice = e2::voice_of(
            &e2::carried_statement(&own).expect("an edition-2 binding"),
            &node,
        );
        put_binding_row(a, &own, &node)
            .await
            .expect("I1149: f owns the node");
        let mut old = grant(&d1, &peer, &node_k);
        old.asserted_at = days(4);
        old.scrub_timestamp = old.asserted_at;
        ts::seal_row_in_place(&d1, &mut old);
        a.put_attestation(SignedAttestation {
            attestation: old.clone(),
        })
        .await
        .expect("I1149: a live key's grant older than W admits");
        let mut bind = binding(&d1, &node);
        bind.asserted_at = days(4) + chrono::Duration::hours(12);
        bind.scrub_timestamp = bind.asserted_at;
        ts::seal_row_in_place(&d1, &mut bind);
        let bind_voice = e2::voice_of(
            &e2::carried_statement(&bind).expect("an edition-2 binding"),
            &node,
        );
        put_binding_row(a, &bind, &node)
            .await
            .expect("I1149: a live key's owner-binding restatement older than W admits");

        // The fresh node: the roster, then A's attestation stream.
        assert!(matches!(
            bind_at(b, &f, &d1, &[&f], days(5)).await,
            StatementOutcome::Row { .. }
        ));
        // The node's voice travels with the statement plane, not the
        // attestation stream.
        e2::put_statement(b, &node_voice)
            .await
            .expect("I1149: the node's voice on B");
        e2::put_statement(b, &bind_voice)
            .await
            .expect("I1149: the node's voice on d1's restatement, on B");
        let mut since = None;
        loop {
            let page = a
                .list_attestations_since(since.clone(), 1_000)
                .await
                .unwrap();
            let Some(last) = page.last() else { break };
            since = Some(last.resume_pair());
            for s in &page {
                let _ = b
                    .apply_replicated_attestation(SignedAttestation {
                        attestation: s.attestation.clone(),
                    })
                    .await;
            }
            if page.len() < 1_000 {
                break;
            }
        }
        for (what, id) in [
            ("owner-binding", &bind.attestation_id),
            ("grant", &old.attestation_id),
        ] {
            assert!(
                b.get_attestation(id).await.unwrap().is_some(),
                "I1149: the fresh node refused the live key's old {what}"
            );
        }
        assert!(cbh::grant_is_authored_for(b, &old, &node_k).await.unwrap());
    }

    /// A copy of the vendored CC policy table whose `self_roster_add` row is
    /// outside the self corridor (its window under the 24 h floor).
    fn table_with_self_window_below_floor() -> crate::federation::governance_policy::PolicyTable {
        let mut v: serde_json::Value = serde_json::from_str(
            crate::federation::namespace::cc_manifests::GOVERNANCE_POLICY_JSON,
        )
        .unwrap();
        for r in v["families"].as_array_mut().unwrap() {
            if r["family"] == "self_roster_add" {
                r["window_class"] = "none".into();
                r["window_secs"] = 0.into();
            }
        }
        crate::federation::governance_policy::PolicyTable::parse(&v.to_string()).unwrap()
    }

    fn policy_refused(r: Result<(), Error>, what: &str) {
        let Err(e) = r else {
            panic!("{what}: expected the corridor refusal, got Ok");
        };
        assert_eq!(e.kind(), "federation_governance_policy_refused", "{what}");
        match e {
            Error::GovernancePolicyRefused { family, reason } => assert_eq!(
                (family.as_str(), reason),
                ("self_roster_add", "window_below_floor"),
                "{what}"
            ),
            other => panic!("{what}: expected the corridor refusal, got {other:?}"),
        }
    }

    /// **I1307** (v60.0.0 S6v; CC 4.5.13, `CLM-policy-corridor`) — the
    /// corridor runs at admission: under a policy table whose self-roster row
    /// is outside the self corridor, the door refuses every roster change
    /// `federation_governance_policy_refused` / `window_below_floor` — the
    /// one-key addition that would land at once, and the two-key addition that
    /// would be held — and nothing is written: no occurrence, no proposal row,
    /// no receipt. The sweep and the standing read refuse alike. Under the
    /// vendored table the same changes land and are held as before.
    pub(crate) async fn i1307_the_corridor_runs_at_admission(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // v62 (E3): O1 S1 runs the same two-path decision (the CC 4.5.13
        // policy rows) on an edition-2 roster change.
        use crate::federation::governance_policy::test_table;
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        for k in [&f, &d1, &d2] {
            e2::put_key(d, k, &[it::USER]).await;
        }
        let me = e2::kid(&f);
        assert!(matches!(
            bind(d, &f, &d1, &[&f]).await,
            StatementOutcome::Row { .. }
        ));
        test_table::set(Some(table_with_self_window_below_floor()));
        let at = ms_now();
        e2::put_statement(d, &occ_voice_at(d, &d2, &d2, &f, &d2, at).await)
            .await
            .expect("I1307: the occurrence key's own voice is kept");
        policy_refused(
            e2::put_statement(d, &occ_voice_at(d, &d1, &f, &f, &d2, at).await)
                .await
                .map(|_| ()),
            "I1307: two keys, outside the corridor",
        );
        assert!(
            d.list_open_edition2_roster_proposals(Some(&me))
                .await
                .unwrap()
                .is_empty(),
            "I1307: no proposal is held"
        );
        assert!(!active_e2(d, &f, &d2).await);
        policy_refused(
            sr::execute_for(d, &me).await.map(|_| ()),
            "I1307: the sweep",
        );
        policy_refused(sr::standing(d, &me).await.map(|_| ()), "I1307: standing");
        test_table::set(None);
        let held = e2::put_statement(d, &occ_voice_at(d, &d1, &f, &f, &d2, at).await)
            .await
            .expect("I1307: two keys, the vendored table");
        assert!(
            matches!(held, StatementOutcome::Pending { .. }),
            "I1307: held: {held:?}"
        );
        assert_eq!(sr::standing(d, &me).await.unwrap().len(), 1);
    }

    async fn pause() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    /// **I1710–I1712** (CIRISPersist#1159, CSD/4 T10) — three holders of one
    /// self's rows reach one roster.
    ///
    /// The shape: genesis key `f`; `d2` added at one key (lands at once); `d3`
    /// added by quorum (`f` proposes, `d2` assents); `f` proposes evicting
    /// `d3` and `d2` co-signs (2 of 3).
    ///
    /// - **I1710 (in order)** — on `a`, where every row was decided as it was
    ///   signed, the eviction lands: the roster is `{f, d2}`.
    /// - **I1711 (a fresh node, the whole stream)** — `c` receives `a`'s
    ///   stream in `a`'s order and lands the same roster at once.
    /// - **I1712 (the late joiner, #1159)** — `b` is `d3`'s own device: it
    ///   holds its own occurrence BEFORE the stream (the pairing flow). v62
    ///   (the CC 2.7 ruling: a roster row counts over the roster AT THE HEAD
    ///   IT NAMES, and a row waits for what it names): `f`'s add of `d3`
    ///   names `a`'s head (`d2`'s bind), which `b` does not hold, so on `b`
    ///   it WAITS (`Pending`), nothing lands. Fed `a`'s statements, `b`'s
    ///   fold re-runs it as its head lands, and `b` holds `a`'s roster: no
    ///   window, no interim verdict of `b`'s own.
    ///
    /// Mutations that turn this red:
    /// - the gate counting over the roster NOW instead of at the named head:
    ///   `d3` lands on `b` at one key (I1712 `Pending`).
    /// - a waiting row whose head lands is not re-folded: `b` never converges
    ///   (I1712 final).
    pub(crate) async fn i1710_every_holder_reaches_one_roster(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        c: &dyn FederationDirectory,
        tag: &str,
    ) {
        // v62 (E3; O1 S1/S1b): the roster's statements are the replicated
        // unit. `a` decides as it signs; `c` and `b` receive `a`'s statements.
        let (f, d2, d3) = (format!("f-{tag}"), format!("d2-{tag}"), format!("d3-{tag}"));
        for d in [a, b, c] {
            for k in [&f, &d2, &d3] {
                e2::put_key(d, k, &[it::USER]).await;
            }
        }
        let me = e2::kid(&f);
        let mut log: Vec<Vec<u8>> = Vec::new();
        let mut put_a = |st: Vec<u8>| {
            log.push(st.clone());
            st
        };

        // I1710 — `a`, in order.
        let t2 = ms_now();
        let s = put_a(occ_voice_at(a, &d2, &d2, &f, &d2, t2).await);
        put_st(a, &s).await;
        let s = put_a(occ_voice_at(a, &f, &f, &f, &d2, t2).await);
        assert!(
            landed(&put_st(a, &s).await),
            "I1710: at one key d2's add lands at once"
        );
        pause().await;
        let t3 = ms_now();
        let own_d3 = put_a(occ_voice_at(a, &d3, &d3, &f, &d3, t3).await);
        put_st(a, &own_d3).await;
        let f_d3 = put_a(occ_voice_at(a, &f, &f, &f, &d3, t3).await);
        assert!(!landed(&put_st(a, &f_d3).await), "I1710: f adds d3: held");
        let s = put_a(occ_voice_at(a, &d2, &f, &f, &d3, t3).await);
        assert!(landed(&put_st(a, &s).await), "I1710: d3 landed by quorum");
        pause().await;
        let te = ms_now();
        let s = put_a(evict_voice_at(a, &f, &f, &d3, te).await);
        assert!(
            !landed(&put_st(a, &s).await),
            "I1710: f proposes evicting d3"
        );
        let s = put_a(evict_voice_at(a, &d2, &f, &d3, te).await);
        assert!(
            landed(&put_st(a, &s).await),
            "I1710: f and d2 are 2 of 3; the eviction landed"
        );
        let want = sr::roster_now(a, &me).await.unwrap();
        assert_eq!(
            want,
            [me.clone(), e2::kid(&d2)]
                .into_iter()
                .collect::<std::collections::BTreeSet<String>>(),
            "I1710: the in-order roster"
        );

        // I1711 — `c`, a fresh node, every statement in `a`'s order.
        for st in &log {
            let _ = e2::put_statement(c, st).await;
        }
        sr::execute_for(c, &me).await.expect("execute");
        assert_eq!(
            sr::roster_now(c, &me).await.unwrap(),
            want,
            "I1711: a fresh node fed a's statements folds a's roster"
        );

        // I1712 — `b`, d3's own device: its own bind first. v62 (O1 fix 7;
        // the CC 2.7 ruling): f's statement names a's roster head (d2's
        // bind), which b does not hold, so it WAITS on b (held, concluding
        // nothing): never decided over "b's roster as it stood". Fed a's
        // statements, b's fold re-runs it as its head lands and b holds a's
        // roster, with no window and in any order.
        put_st(b, &own_d3).await;
        let early = put_st(b, &f_d3).await;
        assert!(
            matches!(early, StatementOutcome::Pending { .. }),
            "I1712: f's add of d3 waits on b for the head it names: {early:?}"
        );
        assert!(
            !active_e2(b, &f, &d3).await,
            "I1712: nothing lands on b before its head"
        );
        for st in &log {
            let _ = e2::put_statement(b, st).await;
        }
        sr::execute_for(b, &me).await.expect("execute");
        assert_eq!(
            sr::roster_now(b, &me).await.unwrap(),
            want,
            "I1712: the late joiner holds a's roster"
        );
    }

    /// **I1713** (CIRISPersist#1159) — why I1712's interim is not "fixed" by
    /// judging an addition on the roster at its signed `asserted_at`: that
    /// instant is the signer's. A thief holding `f` (still live) signs a key
    /// of its own in, backdated to before `d1` joined, when `f` was the only
    /// key. Judged at that instant it would land at one key — and a replay in
    /// signed order would then re-judge `d1`'s own add on `{f, thief}` and
    /// drop it. On the roster as it stands (three keys) it is a proposal,
    /// pending, and nothing lands.
    ///
    /// Mutation: `gate`/`plan` deciding on the roster at the proposal's
    /// `asserted_at` (or `decide_all` replaying adds in signed order from the
    /// genesis roster) lands the thief's key — red.
    pub(crate) async fn i1713_a_backdated_add_is_decided_on_the_roster_now(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // v62 (E3): O1 S1. A backdated add is counted on the roster as it
        // stands at the decision: at three keys one voice is kept, not landed.
        let (f, d1, d2, thief) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("d2-{tag}"),
            format!("t-{tag}"),
        );
        let before = ms_now() - chrono::Duration::hours(1);
        e2::put_key(d, &thief, &[it::USER]).await;
        three_e2(d, &f, &d1, &d2).await;
        let r = bind_at(d, &f, &thief, &[&f], before).await;
        assert!(
            matches!(r, StatementOutcome::Pending { .. }),
            "I1713: a backdated add at three keys must be held: {r:?}"
        );
        sr::execute_for(d, &e2::kid(&f)).await.expect("execute");
        assert!(
            !active_e2(d, &f, &thief).await,
            "I1713: the backdated add landed at one key"
        );
        assert!(
            active_e2(d, &f, &d1).await && active_e2(d, &f, &d2).await,
            "I1713: the roster's own keys stay"
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
                    bodies::reset_clock();
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!(
                            "self_roster postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED"
                        );
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    bodies::reset_clock();
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    /// **I1162** (#1111) — the harness window needs the live override: the
    /// env value is the window only when the test-anchor override is active,
    /// and a value outside `1..=W_SELF_SECS` is no value. The lone path
    /// landing on the short window, end to end on sqlite and postgres, is
    /// `tests/self_roster_test_window_1111.rs` (it arms the process env, which
    /// no test under src/ may do: #738).
    #[cfg(feature = "test-anchor")]
    #[test]
    fn i1162_the_test_window_needs_the_live_override() {
        use crate::federation::self_roster::{test_window as tw, w_self_secs, W_SELF_SECS};
        assert_eq!(
            tw::window(true, Some(2)),
            2,
            "I1162: armed, the env's window"
        );
        assert_eq!(
            tw::window(false, Some(2)),
            W_SELF_SECS,
            "I1162: the env without the override is inert"
        );
        assert_eq!(tw::window(true, None), W_SELF_SECS, "I1162: no value");
        assert_eq!(tw::window(false, None), W_SELF_SECS, "I1162: neither");
        assert_eq!(
            w_self_secs(),
            W_SELF_SECS,
            "I1162: no lib test arms the override"
        );
        assert_eq!(tw::parse_secs(None), None, "I1162: unset");
        assert_eq!(tw::parse_secs(Some(" 2 ")), Some(2), "I1162: whole seconds");
        assert_eq!(tw::parse_secs(Some("1")), Some(1), "I1162: the floor");
        assert_eq!(
            tw::parse_secs(Some(&W_SELF_SECS.to_string())),
            Some(W_SELF_SECS),
            "I1162: the ceiling"
        );
        for bad in ["0", "-5", "86401", "2.5", "two", ""] {
            assert_eq!(tw::parse_secs(Some(bad)), None, "I1162: {bad:?}");
        }
    }

    /// **I1162** (#1111), from disk — a build without `test-anchor` carries
    /// no read of the window variable: every mention of it, and every
    /// environment read in `self_roster.rs`, sits inside the
    /// `#[cfg(feature = "test-anchor")]` module `test_window`, and the one
    /// call into that module sits under the same `cfg`.
    #[test]
    fn i1162_only_a_test_anchor_build_reads_the_window_env() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/federation/self_roster.rs");
        let text = std::fs::read_to_string(&path).expect("self_roster.rs");
        let code: Vec<&str> = text
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect();
        let fence = "#[cfg(feature = \"test-anchor\")]";
        let open = code
            .iter()
            .position(|l| l.trim() == "pub mod test_window {")
            .expect("I1162: the test_window module");
        assert_eq!(code[open - 1].trim(), fence, "I1162: test_window is fenced");
        let close = open
            + code[open..]
                .iter()
                .position(|l| *l == "}")
                .expect("I1162: test_window closes");
        let needles = ["CIRIS_TEST_W_SELF_SECS", "env::var", "env_secs("];
        for (i, line) in code.iter().enumerate() {
            if (open..=close).contains(&i) || !needles.iter().any(|n| line.contains(n)) {
                continue;
            }
            // The one call outside: `w_self_secs`'s fenced block.
            let fenced = code[..i].iter().rev().take(6).any(|l| l.trim() == fence);
            assert!(
                line.contains("test_window::env_secs()") && fenced,
                "I1162: self_roster.rs:{} reads the window env outside the fence: {line}",
                i + 1
            );
        }
        assert!(
            text.contains("CIRIS_TEST_W_SELF_SECS"),
            "I1162: the scan reads the file that names the variable"
        );
    }

    on_every_backend!(i1131, bodies::i1131_two_keys_quorum);
    on_every_backend!(i1132, bodies::i1132_lone_path_and_silence);
    on_every_backend!(i1133, bodies::i1133_the_thief_cannot_evict);
    on_every_backend!(i1134, bodies::i1134_an_evicted_keys_vote_is_void);
    on_every_backend!(i1136, bodies::i1136_the_window_is_the_nodes);
    on_every_backend!(i1137, bodies::i1137_a_second_device_acts_as_its_self);
    on_every_backend!(
        i1161,
        bodies::i1161_nodes_owned_by_places_a_roster_keys_node
    );
    on_every_backend!(i1342, bodies::i1342_the_seek_walks_owner_bindings_only);
    on_every_backend!(i1307, bodies::i1307_the_corridor_runs_at_admission);
    on_every_backend!(i1141, bodies::i1141_the_genesis_key_is_evictable);
    on_every_backend!(
        i1142,
        bodies::i1142_an_evicted_key_cannot_sign_into_its_old_window
    );

    mod i1149 {
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
            bodies::i1149_a_live_keys_old_rows_replicate(&a, &b, &tag("s")).await;
        }

        #[cfg(feature = "postgres")]
        #[tokio::test(flavor = "multi_thread")]
        async fn postgres() {
            use crate::store::Backend as _;
            let Some(dsn_a) = crate::test_pg::empty_dsn() else {
                return;
            };
            let Some(dsn_b) = crate::test_pg::empty_dsn() else {
                return;
            };
            let a = crate::store::postgres::PostgresBackend::connect(&dsn_a)
                .await
                .unwrap();
            a.run_migrations().await.unwrap();
            let b = crate::store::postgres::PostgresBackend::connect(&dsn_b)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            bodies::i1149_a_live_keys_old_rows_replicate(&a, &b, &tag("p")).await;
            eprintln!("i1149: RAN");
        }
    }

    on_every_backend!(
        i1713,
        bodies::i1713_a_backdated_add_is_decided_on_the_roster_now
    );

    /// I1710–I1712 need three nodes: the in-order holder, a fresh node fed
    /// the whole stream, and the late joiner that held its own row first.
    mod i1710 {
        use super::*;

        #[cfg(feature = "sqlite")]
        #[tokio::test(flavor = "multi_thread")]
        async fn sqlite() {
            use crate::store::Backend as _;
            let mut nodes = Vec::new();
            for _ in 0..3 {
                let n = crate::store::sqlite::SqliteBackend::open_in_memory()
                    .await
                    .unwrap();
                n.run_migrations().await.unwrap();
                nodes.push(n);
            }
            bodies::i1710_every_holder_reaches_one_roster(
                &nodes[0],
                &nodes[1],
                &nodes[2],
                &tag("s"),
            )
            .await;
            bodies::reset_clock();
        }

        #[cfg(feature = "postgres")]
        #[tokio::test(flavor = "multi_thread")]
        async fn postgres() {
            use crate::store::Backend as _;
            let mut nodes = Vec::new();
            for _ in 0..3 {
                let Some(dsn) = crate::test_pg::empty_dsn() else {
                    eprintln!("i1710 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                    return;
                };
                let n = crate::store::postgres::PostgresBackend::connect(&dsn)
                    .await
                    .unwrap();
                n.run_migrations().await.unwrap();
                nodes.push(n);
            }
            bodies::i1710_every_holder_reaches_one_roster(
                &nodes[0],
                &nodes[1],
                &nodes[2],
                &tag("p"),
            )
            .await;
            bodies::reset_clock();
            eprintln!("i1710: RAN");
        }
    }
}
