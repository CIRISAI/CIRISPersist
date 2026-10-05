//! v53.0.0 (CIRISPersist#942 part 2, CC 3.1.3.3) — **custody reports**,
//! witnessed on every backend.
//!
//! - **I400** — a live `here` (inside 72 h) reads `here`, names its size and is
//!   challengeable.
//! - **I401** — the 72 h boundary, both sides: exactly 72 h old still counts;
//!   one second later the device is `unknown`, never `none` and never a copy.
//! - **I402** — the latest report wins: a newer `none` overrides an older
//!   `here`, and a newer `here` overrides an older `none`.
//! - **I403** — `received`: a delivery receipt with no later live report
//!   (an expired `here` plus a receipt); a live report newer than the receipt
//!   keeps its own verdict.
//! - **I404** — no report and no receipt: `unknown`.
//! - **I405** — a third-party report (`attesting` ≠ the device) is refused.
//! - **I406** — a report placed at a cohort the device is not in is refused;
//!   a member's report at the same cohort is admitted.
//! - **I407** — malformed is a refusal: `here` without size, `none` with size,
//!   an unknown state, a missing state, a bad digest, a commons placement;
//!   and a signed instant more than the skew bound ahead of the receiving
//!   node's clock.
//! - **I408** — a report is never in the audience of a node outside its
//!   cohort (the replication audience predicate the send/hold doors use).
//! - **I409** — nothing stored is a verdict: withdrawing the latest report
//!   re-derives the device's custody from the one before it.
//! - **I400e / I409e** (sqlite, postgres) — the Engine door: a node reports
//!   `here` for a blob it holds (size from the stored row), the custody view
//!   and `blob_custody` count it, `here` for a blob it does not hold is
//!   refused, and a stranger learns nothing.
//! - **I512** (sqlite, postgres; v53.1.2, CIRISPersist#984 row 7) — the
//!   report's cohort target is the held row's: a caller value that differs is
//!   malformed, one that matches is accepted, `None` resolves to the row's.
//! - **I513** (#984 row 8) — a `stream_id` folds receipts only when the blob
//!   is of that stream; any other stream is refused.
//! - **I514** (#984 row 9) — the custody door tells a shared backend its node
//!   key before asking as that node; the stored report is the node's.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::custody_ack::{
        custody_ack_envelope, device_custody_of, CustodyState, CustodyVerdict,
        CUSTODY_ACK_DIMENSION,
    };
    use crate::federation::envelope::EnvelopeCore;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type as at;
    use crate::federation::types::cohort_scope as cs;
    use crate::federation::types::identity_type as it;
    use crate::federation::{EmitAttestationInput, Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// A fixed, millisecond-aligned base instant in the recent past, so every
    /// signed instant below is behind the receiving node's clock.
    pub(crate) fn base() -> DateTime<Utc> {
        let t = Utc::now() - Duration::days(10);
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
    }

    fn blob(tag: &str) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(tag.as_bytes()).into()
    }

    /// Emit `env` (an object) as a `scores` row signed by `signer`, about
    /// `attested` (`None` = the signer), placed at `scope`, stamped at `at`.
    async fn emit(
        d: &dyn FederationDirectory,
        signer: &str,
        attested: Option<&str>,
        mut env: serde_json::Value,
        scope: &str,
        at: DateTime<Utc>,
    ) -> Result<String, Error> {
        env["asserted_at"] =
            serde_json::json!(crate::federation::admission::render_signed_instant(at));
        let core: EnvelopeCore = serde_json::from_value(env).expect("envelope");
        let mut input = EmitAttestationInput::with_envelope(at::SCORES, core, scope);
        input.attested_key_id = attested.map(str::to_owned);
        crate::federation::attestation_emit::emit_with_local_signer(d, &signer_of(signer), input)
            .await
            .map(|e| e.attestation_id)
    }

    /// [`report`], returning the door's answer instead of insisting on it.
    pub(crate) async fn try_report(
        d: &dyn FederationDirectory,
        device: &str,
        sha: &[u8; 32],
        state: CustodyState,
        at: DateTime<Utc>,
    ) -> Result<String, Error> {
        let size = (state == CustodyState::Here).then_some(4096);
        let env = custody_ack_envelope(sha, state, size, cs::SELF, None).expect("envelope");
        emit(d, device, None, env, cs::SELF, at).await
    }

    pub(crate) async fn report(
        d: &dyn FederationDirectory,
        device: &str,
        sha: &[u8; 32],
        state: CustodyState,
        at: DateTime<Utc>,
    ) -> String {
        let size = (state == CustodyState::Here).then_some(4096);
        let env = custody_ack_envelope(sha, state, size, cs::SELF, None).expect("envelope");
        emit(d, device, None, env, cs::SELF, at)
            .await
            .expect("a device's own report is admitted")
    }

    /// A device: the key the test signer for `dev-{tag}` derives, registered
    /// with that signer's pubkeys. `identity_type` is `user` so the device can
    /// sit on a community roster without a steward (the fixture's seat rule).
    pub(crate) async fn device(d: &dyn FederationDirectory, tag: &str) -> String {
        let k = device_as(d, tag, it::USER).await;
        // v53.0.0 (#963, CC 6.1.5.3) — a device is a CLAIMED device: since S1
        // a key no owner has claimed is in no `self` cohort (an unclaimed key
        // is no one's device), so a report it places at `self` would be
        // refused `custody_ack_outside_cohort`. The device is its owner's
        // personal laptop here, which is what these witnesses are about.
        let owner = format!("{k}-owner");
        ts::register_hybrid_key_as(d, &owner, &owner, it::USER).await;
        d.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
            identity_key_id: owner.clone(),
            occurrence_key_id: k.clone(),
            device_class: crate::federation::types::device_class::LAPTOP.to_owned(),
            hardware_attestation: None,
            asserted_at: Utc::now() - Duration::days(30),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("claim {owner} → {k}: {e}"));
        k
    }

    /// [`device`], registered as `identity_type` (a claimed NODE, for the
    /// durability witnesses whose devices sit in an owner's audience).
    pub(crate) async fn device_as(
        d: &dyn FederationDirectory,
        tag: &str,
        identity_type: &str,
    ) -> String {
        // The test signer seeds from an id's FIRST 32 BYTES, and the derived id
        // normalizes `_` to `-`: so the alias is already normalized (the
        // derived id then shares its first 32 bytes, and a fixture signing as
        // the derived id signs with the same key), and any role suffix a caller
        // put at the END of `tag` is moved to the FRONT (two devices of one
        // test must not share a seed).
        let (head, role) = tag.rsplit_once("--").unwrap_or((tag, "d"));
        let alias = format!("{role}-dev-{head}")
            .replace('_', "-")
            .to_lowercase();
        let k = ts::local_signer(&alias).derived_key_id();
        assert_eq!(
            &k.as_bytes()[..32],
            &alias.as_bytes()[..32],
            "seed-sharing derived id"
        );
        ts::register_hybrid_key_as(d, &k, &alias, identity_type).await;
        ALIASES.with(|m| m.borrow_mut().insert(k.clone(), alias));
        k
    }

    thread_local! {
        /// derived key → the alias whose seed signs for it.
        static ALIASES: std::cell::RefCell<std::collections::HashMap<String, String>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    fn signer_of(key: &str) -> std::sync::Arc<crate::signing::LocalSigner> {
        let alias = ALIASES
            .with(|m| m.borrow().get(key).cloned())
            .expect("a registered device");
        ts::local_signer(&alias)
    }

    async fn verdict(
        d: &dyn FederationDirectory,
        dev: &str,
        sha: &[u8; 32],
        receipt: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> crate::federation::custody_ack::DeviceCustody {
        device_custody_of(d, dev, &hex::encode(sha), receipt, now)
            .await
            .expect("fold")
    }

    fn refused(r: Result<String, Error>, token: &str, what: &str) {
        match r {
            Err(e) => assert!(
                e.to_string().contains(token),
                "{what}: refused, but not by `{token}`: {e}"
            ),
            Ok(id) => panic!("{what}: ADMITTED as {id}, expected `{token}`"),
        }
    }

    /// **I400** — a live `here`.
    pub(crate) async fn i400_a_live_here_is_a_copy(d: &dyn FederationDirectory, tag: &str) {
        let dev = device(d, tag).await;
        let sha = blob(tag);
        let t0 = base();
        report(d, &dev, &sha, CustodyState::Here, t0).await;
        let v = verdict(d, &dev, &sha, None, t0 + Duration::hours(71)).await;
        assert_eq!(v.state, CustodyVerdict::Here, "I400 {v:?}");
        assert_eq!(v.size, Some(4096), "I400 the size rides a live here");
        assert!(
            v.challengeable,
            "I400 a live here naming its size is challengeable"
        );
        assert_eq!(
            v.reported_at,
            Some(t0),
            "I400 the signed instant, not a server read"
        );
    }

    /// **I401** — the 72 h boundary, both sides.
    pub(crate) async fn i401_the_seventy_two_hour_boundary(d: &dyn FederationDirectory, tag: &str) {
        let dev = device(d, tag).await;
        let sha = blob(tag);
        let t0 = base();
        report(d, &dev, &sha, CustodyState::Here, t0).await;
        let at72 = verdict(d, &dev, &sha, None, t0 + Duration::hours(72)).await;
        assert_eq!(
            at72.state,
            CustodyVerdict::Here,
            "I401 exactly 72 h old still counts"
        );
        let after = verdict(
            d,
            &dev,
            &sha,
            None,
            t0 + Duration::hours(72) + Duration::seconds(1),
        )
        .await;
        assert_eq!(
            after.state,
            CustodyVerdict::Unknown,
            "I401 one second past 72 h is unknown — never none, never a copy"
        );
        assert!(
            !after.challengeable && after.size.is_none(),
            "I401 {after:?}"
        );
        assert_eq!(
            after.reported_at,
            Some(t0),
            "I401 the lapsed instant is still shown"
        );
    }

    /// **I402** — the latest report wins, in both directions.
    pub(crate) async fn i402_the_latest_report_wins(d: &dyn FederationDirectory, tag: &str) {
        let dev = device(d, tag).await;
        let t0 = base();
        let dropped = blob(&format!("{tag}-dropped"));
        report(d, &dev, &dropped, CustodyState::Here, t0).await;
        report(
            d,
            &dev,
            &dropped,
            CustodyState::None,
            t0 + Duration::hours(1),
        )
        .await;
        let v = verdict(d, &dev, &dropped, None, t0 + Duration::hours(2)).await;
        assert_eq!(
            v.state,
            CustodyVerdict::None,
            "I402 a newer none overrides here"
        );
        let fetched = blob(&format!("{tag}-fetched"));
        report(d, &dev, &fetched, CustodyState::None, t0).await;
        report(
            d,
            &dev,
            &fetched,
            CustodyState::Here,
            t0 + Duration::hours(1),
        )
        .await;
        let v = verdict(d, &dev, &fetched, None, t0 + Duration::hours(2)).await;
        assert_eq!(
            v.state,
            CustodyVerdict::Here,
            "I402 a newer here overrides none"
        );
        // one blob's report never answers for another
        let other = verdict(d, &dev, &blob(&format!("{tag}-other")), None, t0).await;
        assert_eq!(
            other.state,
            CustodyVerdict::Unknown,
            "I402 reports are per blob"
        );
    }

    /// **I403** — `received`.
    pub(crate) async fn i403_a_receipt_without_a_later_live_report(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let dev = device(d, tag).await;
        let sha = blob(tag);
        let t0 = base();
        report(d, &dev, &sha, CustodyState::Here, t0).await;
        let v = verdict(
            d,
            &dev,
            &sha,
            Some(t0 + Duration::hours(1)),
            t0 + Duration::hours(73),
        )
        .await;
        assert_eq!(
            v.state,
            CustodyVerdict::Received,
            "I403 expired here + receipt"
        );
        let v = verdict(
            d,
            &dev,
            &sha,
            Some(t0 - Duration::hours(1)),
            t0 + Duration::hours(2),
        )
        .await;
        assert_eq!(
            v.state,
            CustodyVerdict::Here,
            "I403 a live report newer than the receipt keeps its own verdict"
        );
        let v = verdict(
            d,
            &dev,
            &sha,
            Some(t0 + Duration::hours(1)),
            t0 + Duration::hours(2),
        )
        .await;
        assert_eq!(
            v.state,
            CustodyVerdict::Received,
            "I403 a receipt newer than the live report outranks it"
        );
        let none_dev = device(d, &format!("{tag}--n")).await;
        let v = verdict(d, &none_dev, &sha, Some(t0), t0 + Duration::hours(1)).await;
        assert_eq!(
            v.state,
            CustodyVerdict::Received,
            "I403 a receipt alone reads received"
        );
    }

    /// **I404** — nothing: `unknown`.
    pub(crate) async fn i404_no_report_is_unknown(d: &dyn FederationDirectory, tag: &str) {
        let dev = device(d, tag).await;
        let v = verdict(d, &dev, &blob(tag), None, base()).await;
        assert_eq!(v.state, CustodyVerdict::Unknown, "I404 {v:?}");
        assert!(v.reported_at.is_none() && !v.challengeable, "I404 {v:?}");
    }

    /// **I405** — a third-party report is refused.
    pub(crate) async fn i405_a_third_party_report_is_refused(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let dev = device(d, tag).await;
        let other = device(d, &format!("{tag}--x")).await;
        let env =
            custody_ack_envelope(&blob(tag), CustodyState::Here, Some(1), cs::SELF, None).unwrap();
        refused(
            emit(d, &other, Some(&dev), env, cs::SELF, base()).await,
            "custody_ack_not_self_report",
            "I405 another key reporting the device's custody",
        );
        assert_eq!(
            verdict(d, &dev, &blob(tag), None, base()).await.state,
            CustodyVerdict::Unknown,
            "I405 nothing was written"
        );
    }

    /// **I406** — outside the cohort is refused; inside is admitted.
    pub(crate) async fn i406_a_report_outside_the_cohort_is_refused(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let a = device_as(d, &format!("{tag}--a"), it::USER).await;
        let b = device_as(d, &format!("{tag}--b"), it::USER).await;
        let outsider = device_as(d, &format!("{tag}--o"), it::USER).await;
        let community = format!("cust-comm-{tag}");
        ts::seed_two_member_community(d, &community, &a, &b).await;
        let sha = blob(tag);
        let env = |state| {
            custody_ack_envelope(&sha, state, Some(9), cs::COMMUNITY, Some(&community)).unwrap()
        };
        emit(d, &a, None, env(CustodyState::Here), cs::COMMUNITY, base())
            .await
            .expect("I406 a member's report at its community is admitted");
        let r = emit(
            d,
            &outsider,
            None,
            env(CustodyState::Here),
            cs::COMMUNITY,
            base(),
        )
        .await;
        assert!(
            r.is_err(),
            "I406 an outsider's report at the community is refused: {r:?}"
        );
        assert_eq!(
            verdict(d, &outsider, &sha, None, base() + Duration::hours(1))
                .await
                .state,
            CustodyVerdict::Unknown,
            "I406 nothing was written for the outsider"
        );
    }

    /// **I407** — malformed is a refusal; a future instant is refused.
    pub(crate) async fn i407_malformed_is_a_refusal(d: &dyn FederationDirectory, tag: &str) {
        let dev = device(d, tag).await;
        let hex_sha = hex::encode(blob(tag));
        let row = |extra: serde_json::Value| {
            let mut env = serde_json::json!({
                "dimension": CUSTODY_ACK_DIMENSION,
                "evidence_refs": [hex_sha],
                "score": 1.0,
                "confidence": 1.0,
            });
            for (k, v) in extra.as_object().unwrap() {
                env[k] = v.clone();
            }
            env
        };
        let t = base();
        for (what, env) in [
            (
                "here without size",
                row(serde_json::json!({"custody_state": "here"})),
            ),
            (
                "none with size",
                row(serde_json::json!({"custody_state": "none", "size": 3})),
            ),
            (
                "an unknown state",
                row(serde_json::json!({"custody_state": "maybe", "size": 3})),
            ),
            ("no state", row(serde_json::json!({}))),
            (
                "a digest that is not 64 lowercase hex",
                row(serde_json::json!({"custody_state": "none", "evidence_refs": ["AB"]})),
            ),
            (
                "two blobs in one report",
                row(
                    serde_json::json!({"custody_state": "none", "evidence_refs": [hex_sha, hex_sha]}),
                ),
            ),
        ] {
            refused(
                emit(d, &dev, None, env, cs::SELF, t).await,
                "custody_ack_malformed",
                &format!("I407 {what}"),
            );
        }
        refused(
            emit(
                d,
                &dev,
                None,
                row(serde_json::json!({"custody_state": "none"})),
                cs::FEDERATION,
                t,
            )
            .await,
            "custody_ack_malformed",
            "I407 a commons placement",
        );
        // The signer's instant may run at most 300 s ahead of the receiving
        // node's clock (the universal instant gate's bound): a future-dated
        // `here` cannot stay live.
        // A literal, not the constant: a witness that computed its instant
        // from the bound would move with any mutation of the bound.
        let future = Utc::now() + Duration::seconds(300 + 60);
        let r = emit(
            d,
            &dev,
            None,
            row(serde_json::json!({"custody_state": "here", "size": 1})),
            cs::SELF,
            future,
        )
        .await;
        assert!(
            r.is_err(),
            "I407 a report dated past the skew bound is refused: {r:?}"
        );
        let near = Utc::now() + Duration::seconds(60);
        emit(
            d,
            &dev,
            None,
            row(serde_json::json!({"custody_state": "here", "size": 1})),
            cs::SELF,
            near,
        )
        .await
        .expect("I407 an instant inside the skew bound is admitted");
    }

    /// **I408** — never in the audience of a node outside the cohort.
    pub(crate) async fn i408_a_report_never_reaches_an_outsider(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::replication::hold::is_audience;
        let a = device_as(d, &format!("{tag}--a"), it::USER).await;
        let b = device_as(d, &format!("{tag}--b"), it::USER).await;
        let outsider = device_as(d, &format!("{tag}--o"), it::USER).await;
        let community = format!("cust-aud-{tag}");
        ts::seed_two_member_community(d, &community, &a, &b).await;
        let sha = blob(tag);
        let env = custody_ack_envelope(
            &sha,
            CustodyState::Here,
            Some(9),
            cs::COMMUNITY,
            Some(&community),
        )
        .unwrap();
        emit(d, &a, None, env, cs::COMMUNITY, base())
            .await
            .expect("I408 admitted");
        let audience = |node: String| {
            let community = community.clone();
            let a = a.clone();
            async move {
                is_audience(d, cs::COMMUNITY, Some(&community), &a, |_| false, &node)
                    .await
                    .unwrap()
            }
        };
        assert!(
            audience(b.clone()).await,
            "I408 the other member is in the audience"
        );
        assert!(!audience(outsider.clone()).await, "I408 an outsider is not");
        // the self leg: a CLAIMED device (since S1 an unclaimed key is in no
        // self cohort, so `a` — a bare room member — could not place one)
        let c = device(d, &format!("{tag}--c")).await;
        let self_env =
            custody_ack_envelope(&sha, CustodyState::None, None, cs::SELF, None).unwrap();
        emit(d, &c, None, self_env, cs::SELF, base())
            .await
            .expect("I408 self admitted");
        assert!(
            !is_audience(d, cs::SELF, None, &c, |_| false, &outsider)
                .await
                .unwrap(),
            "I408 a self report never reaches a node that is not the device's own"
        );
    }

    /// **I409** — withdrawing the latest report re-derives from the one before.
    pub(crate) async fn i409_nothing_stored_is_a_verdict(d: &dyn FederationDirectory, tag: &str) {
        let dev = device(d, tag).await;
        let sha = blob(tag);
        let t0 = base();
        report(d, &dev, &sha, CustodyState::Here, t0).await;
        let latest = report(d, &dev, &sha, CustodyState::None, t0 + Duration::hours(1)).await;
        assert_eq!(
            verdict(d, &dev, &sha, None, t0 + Duration::hours(2))
                .await
                .state,
            CustodyVerdict::None
        );
        let mut env = serde_json::json!({
            "references_attestation_id": latest,
            "withdrawal_reason": "custody witness",
        });
        env["asserted_at"] =
            serde_json::json!(crate::federation::admission::render_signed_instant(
                t0 + Duration::hours(1) + Duration::minutes(1)
            ));
        let core: EnvelopeCore = serde_json::from_value(env).unwrap();
        crate::federation::attestation_emit::emit_with_local_signer(
            d,
            &signer_of(&dev),
            EmitAttestationInput::with_envelope(at::WITHDRAWS, core, cs::SELF),
        )
        .await
        .expect("I409 the device withdraws its own report");
        assert_eq!(
            verdict(d, &dev, &sha, None, t0 + Duration::hours(2))
                .await
                .state,
            CustodyVerdict::Here,
            "I409 the view re-derives: the withdrawn none no longer decides"
        );
    }
}

/// The Engine door, on sqlite and postgres (memory has no blob store).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod engine_bodies {
    use crate::federation::custody_ack::{CustodyState, CustodyVerdict};
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Ladder, Pick};
    use crate::federation::types::cohort_scope::{COMMUNITY, SELF};
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    /// **I400e / I409e** — the door, the view and `blob_custody`.
    pub(crate) async fn i400e_the_engine_door<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        let s = e
            .put_blob_scoped(SELF, Some(&l.alice), b"my bytes", None, None)
            .await
            .unwrap();
        let head = l.ba.blob_head(&s.at_rest_sha256).await.unwrap().unwrap();
        e.put_custody_ack(&s.at_rest_sha256, CustodyState::Here, None, None, None)
            .await
            .expect("I400e the node reports a blob it holds");
        let v = e
            .custody_view(&s.at_rest_sha256, &l.node_a, None)
            .await
            .unwrap();
        let mine = v
            .devices
            .iter()
            .find(|d| d.device_key_id == l.node_a)
            .unwrap_or_else(|| panic!("I400e the node is named: {v:?}"));
        assert_eq!(mine.state, CustodyVerdict::Here, "I400e {v:?}");
        assert_eq!(
            mine.size,
            Some(head.size_bytes),
            "I400e the size is the stored row's"
        );
        assert!(v.copies_here >= 1, "I400e {v:?}");
        let c = e.blob_custody(&s.at_rest_sha256, &l.node_a).await.unwrap();
        assert!(
            c.copies_observable,
            "I400e self copies are observable now: {c:?}"
        );
        assert!(
            c.device_custody
                .iter()
                .any(|d| d.device_key_id == l.node_a && d.state == CustodyVerdict::Here),
            "I400e blob_custody carries the same fold: {c:?}"
        );
        assert!(c.copies_known >= 1, "I400e {c:?}");
        // a copy the node does not hold is not reportable
        let mut absent = s.at_rest_sha256;
        absent[0] ^= 0xff;
        let r = e
            .put_custody_ack(&absent, CustodyState::Here, None, None, None)
            .await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("custody_ack_here_not_held")),
            "I400e here for a blob not held: {r:?}"
        );
        let r = e
            .put_custody_ack(&absent, CustodyState::None, None, None, None)
            .await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("custody_ack_malformed")),
            "I400e none with no row names the cohort: {r:?}"
        );
        e.put_custody_ack(&absent, CustodyState::None, Some(SELF), None, None)
            .await
            .expect("I400e none for a dropped blob at its named cohort");
        let r = e
            .put_custody_ack(
                &s.at_rest_sha256,
                CustodyState::None,
                Some(COMMUNITY),
                None,
                None,
            )
            .await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("custody_ack_malformed")),
            "I400e a cohort that differs from the held row's: {r:?}"
        );
        // I409e — a newer none is the verdict, re-derived on every read.
        e.put_custody_ack(&s.at_rest_sha256, CustodyState::None, None, None, None)
            .await
            .expect("I409e the node reports it dropped the copy");
        let v = e
            .custody_view(&s.at_rest_sha256, &l.node_a, None)
            .await
            .unwrap();
        let mine = v
            .devices
            .iter()
            .find(|d| d.device_key_id == l.node_a)
            .unwrap();
        assert_eq!(mine.state, CustodyVerdict::None, "I409e {v:?}");
        // community: the target is read from the sealing epoch
        let c = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"room bytes", None, None)
            .await
            .unwrap();
        e.put_custody_ack(&c.at_rest_sha256, CustodyState::Here, None, None, None)
            .await
            .expect("I400e a member reports a community blob; the target comes from the epoch");
        // a stranger learns nothing
        let stranger = format!("cust-stranger-{run}");
        assert!(
            matches!(
                e.custody_view(&s.at_rest_sha256, &stranger, None).await,
                Err(BlobError::NotGranted { .. })
            ),
            "I400e a stranger is refused the custody view"
        );
    }

    /// The stored custody row `id` names (its envelope and its signer).
    async fn stored<B: FederationDirectory + Sync>(
        b: &B,
        id: &str,
    ) -> crate::federation::Attestation {
        b.get_attestation(id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the custody row {id} is stored"))
    }

    /// **I512** (v53.1.2, CIRISPersist#984 row 7) — **a caller-named cohort
    /// target is read against the held row.** With the blob held, the report's
    /// community (or family) is the row's own — the sealing epoch's community,
    /// the V177 group of a self/family row — and a caller value that differs
    /// is `custody_ack_malformed`; one that matches is accepted; `None` resolves
    /// to the row's. Before, the caller's value was written as given: a
    /// device in two rooms could file A's blob as a copy held for room B.
    pub(crate) async fn i512_the_target_is_the_rows<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::replication_audience_invariants::bodies as ra;
        use crate::federation::types::cohort_scope::FAMILY;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        let ba = l.ba.as_ref();
        // A second room and two families alice is in: every target below is
        // a cohort the reporting device IS in, so only the row can refuse.
        let comm_b = format!("em-comm-b-{run}");
        ra::room(ba as &dyn FederationDirectory, &comm_b, &[&l.alice]).await;
        let (fam_a, fam_b) = (format!("em-fam-a-{run}"), format!("em-fam-b-{run}"));
        ra::family(ba as &dyn FederationDirectory, &fam_a, &[&l.alice]).await;
        ra::family(ba as &dyn FederationDirectory, &fam_b, &[&l.alice]).await;
        let c = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"room A bytes", None, None)
            .await
            .unwrap()
            .at_rest_sha256;
        let f = e
            .put_blob_encrypted_self_family(FAMILY, &fam_a, b"family A bytes", None)
            .await
            .unwrap()
            .at_rest_sha256;
        for (what, sha, scope, own, other, member) in [
            ("community", c, COMMUNITY, &l.comm, &comm_b, "community_id"),
            ("family", f, FAMILY, &fam_a, &fam_b, "family_key_id"),
        ] {
            let r = e
                .put_custody_ack(&sha, CustodyState::Here, None, Some(other), None)
                .await;
            assert!(
                r.as_ref()
                    .is_err_and(|e| e.to_string().contains("custody_ack_malformed")),
                "I512 {what}: a target that is not the row's is malformed: {r:?}"
            );
            for named in [Some(own.as_str()), None] {
                let id = e
                    .put_custody_ack(&sha, CustodyState::Here, Some(scope), named, None)
                    .await
                    .unwrap_or_else(|e| panic!("I512 {what} target {named:?}: {e}"));
                let row = stored(ba, &id).await;
                assert_eq!(
                    row.attestation_envelope
                        .get(member)
                        .and_then(|v| v.as_str()),
                    Some(own.as_str()),
                    "I512 {what} target {named:?}: the envelope names the row's {member}"
                );
            }
        }
    }

    /// The one-leaf log of inline blob `sha` on A, with an STH and a delivery
    /// receipt from node B. Returns the stream id.
    async fn receipted_stream<B>(l: &Ladder<B>, run: &str, sha: &[u8; 32]) -> String
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::stream_receipt::{receipt_signing_bytes, DeliveryReceipt};
        let sid = crate::federation::stream_sth::inline_blob_stream_id(sha);
        let sth = l.engine_a.sign_stream_sth(&sid, &[*sha], 1).await.unwrap();
        l.ba.put_stream_sth(sth.clone(), &l.node_a).await.unwrap();
        let subscriber =
            crate::federation::tier_ingest::test_support::local_signer(&format!("em-b-{run}"));
        assert_eq!(subscriber.derived_key_id(), l.node_b);
        let bytes = receipt_signing_bytes(&l.node_b, &sid, 0, &sth.root_hash, 1);
        l.ba.put_delivery_receipt(DeliveryReceipt {
            stream_id: sid.clone(),
            subscriber_key_id: l.node_b.clone(),
            epoch: 0,
            k: 1,
            chunk_root: sth.root_hash,
            signature: subscriber.sign_hybrid(&bytes).await.unwrap(),
        })
        .await
        .expect("the receipt is stored");
        sid
    }

    /// **I513** (v53.1.2, CIRISPersist#984 row 8) — **a `stream_id` folds
    /// receipts into a blob's view only when the blob is of that stream**: its
    /// own one-leaf log, a stream it sits at as a chunk (V175), or the stream
    /// of the chunks its manifest names (V176). Any other stream is
    /// `InvalidArgument`. Before, any stream's receipts were folded in, so an
    /// unrelated stream's subscriber read `received` for a blob it never got.
    pub(crate) async fn i513_receipts_fold_only_for_the_blobs_stream<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        let x = e
            .put_blob_scoped(SELF, Some(&l.alice), b"blob X", None, None)
            .await
            .unwrap()
            .at_rest_sha256;
        let y = e
            .put_blob_scoped(SELF, Some(&l.alice), b"blob Y", None, None)
            .await
            .unwrap()
            .at_rest_sha256;
        let s_y = receipted_stream(&l, run, &y).await;
        let r = e.custody_view(&x, &l.node_a, Some(&s_y)).await;
        assert!(
            matches!(&r, Err(BlobError::InvalidArgument(m)) if m.contains("not the blob's stream")),
            "I513 an unrelated stream is refused: {r:?}"
        );
        // Control: X's own log, receipted, folds node B as `received`.
        let s_x = receipted_stream(&l, run, &x).await;
        let v = e.custody_view(&x, &l.node_a, Some(&s_x)).await.unwrap();
        let b = v
            .devices
            .iter()
            .find(|d| d.device_key_id == l.node_b)
            .unwrap_or_else(|| panic!("I513 the receipting subscriber is listed: {v:?}"));
        assert_eq!(b.state, CustodyVerdict::Received, "I513 {v:?}");
        assert!(v.receipts_consulted);
        // And Y's subscriber never appears in X's view through X's own stream
        // either: the fold reads the named stream's receipts only.
        let v = e.custody_view(&y, &l.node_a, None).await.unwrap();
        assert!(
            v.devices.iter().all(|d| d.device_key_id != l.node_b),
            "I513 no stream named, no receipt folded: {v:?}"
        );
    }

    /// An AUTHORIZED infrastructure room (its key typed `substrate_persist`,
    /// `cohort_subkind: infrastructure`, founded by alice under `quorum:1/1`)
    /// on A: the one room shape that resolves to the PLAINTEXT tier.
    async fn infra_room<B>(l: &Ladder<B>, run: &str, tag: &str) -> String
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{identity_type, Community, CommunityMember};
        let room = format!("em-infra-{tag}-{run}");
        let ba = l.ba.as_ref();
        ts::register_hybrid_key_as(ba, &room, &room, identity_type::SUBSTRATE_PERSIST).await;
        let joined = chrono::Utc::now() - chrono::Duration::days(3);
        let c = Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: room.clone(),
            community_name: "infra".into(),
            members: vec![CommunityMember {
                key_id: l.alice.clone(),
                joined_at: joined,
                role: Some("founder".into()),
            }],
            founded_at: joined,
            consensus_protocol: "quorum:1/1".into(),
            policy_blob: Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
            persist_row_hash: String::new(),
        };
        ba.put_community(ts::sign_community(&l.alice, c))
            .await
            .unwrap_or_else(|e| panic!("the infrastructure room {room}: {e}"));
        room
    }

    /// **I525** (v53.1.3, Codex on #985, #986) — **the row-target arm reads
    /// every room shape.** A PLAINTEXT room blob (an infrastructure
    /// community: no DEK binding) and an `affiliations` blob (a binding under
    /// `affiliations`, not `community`) both fell to `row_target = None`, so a
    /// caller's room was trusted. The arm now reads the binding OR the row's
    /// V177 group for `community | affiliations`.
    pub(crate) async fn i525_the_target_arm_reads_every_room_shape<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::replication_audience_invariants::bodies as ra;
        use crate::federation::types::cohort_scope::AFFILIATIONS;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        let ba = l.ba.as_ref();
        let other = format!("em-comm-o-{run}");
        ra::room(ba as &dyn FederationDirectory, &other, &[&l.alice]).await;
        // A plaintext room blob: the row carries the group (#986 item 4), and
        // the custody arm reads it where no binding exists (item 3).
        let room = infra_room(&l, run, "i525").await;
        let p = e
            .put_blob_scoped(COMMUNITY, Some(&room), b"plaintext room bytes", None, None)
            .await
            .unwrap();
        assert_eq!(
            p.tier,
            crate::federation::types::cohort_scope::CryptoTier::Plaintext,
            "I525 precondition — an infrastructure room is plaintext"
        );
        let r = e
            .put_custody_ack(
                &p.at_rest_sha256,
                CustodyState::Here,
                None,
                Some(&other),
                None,
            )
            .await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("custody_ack_malformed")),
            "I525 plaintext room: a target that is not the row's is malformed: {r:?}"
        );
        let id = e
            .put_custody_ack(
                &p.at_rest_sha256,
                CustodyState::Here,
                None,
                Some(&room),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("I525 plaintext room, its own target: {e}"));
        let row = stored(ba, &id).await;
        assert_eq!(
            row.attestation_envelope
                .get("community_id")
                .and_then(|v| v.as_str()),
            Some(room.as_str()),
            "I525 the envelope names the row's room"
        );
        // An affiliations blob: sealed under the room's DEK, bound under the
        // `affiliations` cohort. A report naming another room is refused —
        // today for its SCOPE (`affiliations` is not a custody cohort, CC
        // 3.1.3.3), so the arm's `affiliations` reading is pinned by the
        // plaintext room above and this leg records the scope refusal.
        let a = e
            .put_blob_scoped(
                AFFILIATIONS,
                Some(&l.comm),
                b"affiliations bytes",
                None,
                None,
            )
            .await
            .unwrap();
        let r = e
            .put_custody_ack(
                &a.at_rest_sha256,
                CustodyState::Here,
                None,
                Some(&other),
                None,
            )
            .await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("custody_ack_malformed")),
            "I525 affiliations: a report naming another room is malformed: {r:?}"
        );
    }

    /// **I526** (v53.1.3, Codex on #985, #986) — **a plaintext room write
    /// carries the group.** `put_blob_with_scope`'s INSERT stamped no
    /// `group_key_id`, and a plaintext row has no DEK binding, so every
    /// plaintext room blob's audience was `Unresolvable`.
    pub(crate) async fn i526_a_plaintext_room_write_carries_the_group<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::durability::DeficitAudience;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let room = infra_room(&l, run, "i526").await;
        let p = l
            .engine_a
            .put_blob_scoped(COMMUNITY, Some(&room), b"plaintext room bytes", None, None)
            .await
            .unwrap();
        let prov =
            l.ba.blob_provenance(&p.at_rest_sha256)
                .await
                .unwrap()
                .expect("the row");
        assert_eq!(
            prov.group_key_id.as_deref(),
            Some(room.as_str()),
            "I526 the plaintext room row records its room: {prov:?}"
        );
        assert_eq!(
            prov.community_key_id, None,
            "I526 a plaintext row has no binding"
        );
        let d = l
            .engine_a
            .durability_deficit(&p.at_rest_sha256, &l.node_a, None)
            .await
            .unwrap();
        assert!(
            !matches!(d.audience, DeficitAudience::Unresolvable),
            "I526 the audience resolves from the row's group: {d:?}"
        );
    }

    /// A shared `BackendDispatch` over a backend handle, and a way to make the
    /// handle forget its node key — a handle the constructor could not tell
    /// (a hardware signer that answers asynchronously).
    pub(crate) type Share<B> = fn(std::sync::Arc<B>) -> crate::engine::BackendDispatch;
    pub(crate) type Forget<B> = fn(&B);

    /// **I514** (v53.1.2, CIRISPersist#984 row 9) — **the custody door tells
    /// the backend its node key before it asks as that node.** A shared
    /// Engine whose backend does not know its key reported `here` for a sealed
    /// DAG as `""`: the completeness check, asked as nobody, read
    /// `Unverifiable` and refused a copy the node holds whole. The door now
    /// derives the key first; the stored report is the node's.
    pub(crate) async fn i514_the_custody_door_knows_its_node<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        share: Share<B>,
        forget: Forget<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let stream = format!("i514-{run}");
        for (i, seg) in [&b"first"[..], &b"second"[..]].into_iter().enumerate() {
            l.engine_a
                .put_blob_chunk_scoped(SELF, Some(&l.alice), &stream, i as u64, seg, 0, None)
                .await
                .unwrap();
        }
        let root = l
            .engine_a
            .seal_stream_scoped(SELF, Some(&l.alice), &stream, None, None)
            .await
            .unwrap()
            .manifest_sha256;
        // The ladder's own signer (deterministic by alias), as a host would
        // rebuild it: the report is signed by it, so the engine needs it.
        let local =
            crate::federation::tier_ingest::test_support::local_signer(&format!("em-a-{run}"));
        let shared = crate::Engine::from_shared_with_local(
            share(l.ba.clone()),
            l.engine_a.signer().clone(),
            Some(local),
        );
        forget(l.ba.as_ref());
        assert!(
            l.ba.node_key_id().is_none(),
            "I514 precondition — the handle does not know its node key"
        );
        let id = shared
            .put_custody_ack(&root, CustodyState::Here, None, None, None)
            .await
            .unwrap_or_else(|e| panic!("I514 the node reports a DAG it holds whole: {e}"));
        let row = stored(l.ba.as_ref(), &id).await;
        assert_eq!(
            row.attesting_key_id, l.node_a,
            "I514 the report is the node's own"
        );
        assert_eq!(
            l.ba.node_key_id().as_deref(),
            Some(l.node_a.as_str()),
            "I514 the door told the backend its key"
        );
        let v = shared.custody_view(&root, &l.node_a, None).await.unwrap();
        assert!(
            v.devices
                .iter()
                .any(|d| d.device_key_id == l.node_a && d.state == CustodyVerdict::Here),
            "I514 the node is a copy: {v:?}"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! case {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(
                                &d as &dyn FederationDirectory,
                                &format!("{}-{}", stringify!($name), suffix()),
                            )
                            .await
                        }
                    };
                }
                case!(i400_a_live_here_is_a_copy);
                case!(i401_the_seventy_two_hour_boundary);
                case!(i402_the_latest_report_wins);
                case!(i403_a_receipt_without_a_later_live_report);
                case!(i404_no_report_is_unknown);
                case!(i405_a_third_party_report_is_refused);
                case!(i406_a_report_outside_the_cohort_is_refused);
                case!(i407_malformed_is_a_refusal);
                case!(i408_a_report_never_reaches_an_outsider);
                case!(i409_nothing_stored_is_a_verdict);
            }
        };
    }

    dyn_runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "sqlite")]
    macro_rules! sqlite_engine_case {
        ($name:ident, $body:ident) => {
            #[tokio::test]
            async fn $name() {
                super::engine_bodies::$body(
                    "sqlite::memory:",
                    "sqlite::memory:",
                    &suffix(),
                    (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                        as crate::federation::epoch_minter_invariants::bodies::Pick<
                            crate::store::sqlite::SqliteBackend,
                        >,
                )
                .await;
            }
        };
    }
    #[cfg(feature = "sqlite")]
    sqlite_engine_case!(i512_sqlite, i512_the_target_is_the_rows);
    #[cfg(feature = "sqlite")]
    sqlite_engine_case!(i513_sqlite, i513_receipts_fold_only_for_the_blobs_stream);
    #[cfg(feature = "sqlite")]
    sqlite_engine_case!(i525_sqlite, i525_the_target_arm_reads_every_room_shape);
    #[cfg(feature = "sqlite")]
    sqlite_engine_case!(i526_sqlite, i526_a_plaintext_room_write_carries_the_group);
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i514_sqlite() {
        super::engine_bodies::i514_the_custody_door_knows_its_node(
            "sqlite::memory:",
            "sqlite::memory:",
            &suffix(),
            (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::sqlite::SqliteBackend,
                >,
            crate::engine::BackendDispatch::Sqlite,
            |b| b.forget_node_key_id(),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    macro_rules! postgres_engine_case {
        ($name:ident, $body:ident) => {
            #[tokio::test]
            async fn $name() {
                let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn())
                else {
                    return;
                };
                super::engine_bodies::$body(
                    &a,
                    &b,
                    &suffix(),
                    (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                        as crate::federation::epoch_minter_invariants::bodies::Pick<
                            crate::store::postgres::PostgresBackend,
                        >,
                )
                .await;
            }
        };
    }
    #[cfg(feature = "postgres")]
    postgres_engine_case!(i512_postgres, i512_the_target_is_the_rows);
    #[cfg(feature = "postgres")]
    postgres_engine_case!(i513_postgres, i513_receipts_fold_only_for_the_blobs_stream);
    #[cfg(feature = "postgres")]
    postgres_engine_case!(i525_postgres, i525_the_target_arm_reads_every_room_shape);
    #[cfg(feature = "postgres")]
    postgres_engine_case!(i526_postgres, i526_a_plaintext_room_write_carries_the_group);
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i514_postgres() {
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        super::engine_bodies::i514_the_custody_door_knows_its_node(
            &a,
            &b,
            &suffix(),
            (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::postgres::PostgresBackend,
                >,
            crate::engine::BackendDispatch::Postgres,
            |b| b.forget_node_key_id(),
        )
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i400e_the_engine_door_sqlite() {
        super::engine_bodies::i400e_the_engine_door(
            "sqlite::memory:",
            "sqlite::memory:",
            &suffix(),
            (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::sqlite::SqliteBackend,
                >,
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i400e_the_engine_door_postgres() {
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        super::engine_bodies::i400e_the_engine_door(
            &a,
            &b,
            &suffix(),
            (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::postgres::PostgresBackend,
                >,
        )
        .await;
    }
}
