//! v59.0.0 (CIRISPersist#1099; CC 3.3.6.3) — **I1130–I1139: the self-roster
//! door and the steward predicate, on every backend.**
//!
//! - **I1130 (one key)** — at one key the addition is unilateral: the
//!   genesis key adds a device and it is active at once; no proposal is held.
//! - **I1131 (quorum)** — at two keys a device's addition is a PROPOSAL: the
//!   door returns `federation_self_roster_not_landed` / `pending`, the device
//!   is not active, the proposal row is held; the other key's assent lands it
//!   at once (`lands_quorum`) and the device is active.
//! - **I1132 (lone path, silence)** — at three keys an eviction with no
//!   answer lands after `W_self` on the node's clock (`lands_lone`, the target
//!   is revoked); a target that signed anything since the proposal arrived is
//!   evictable only by quorum.
//! - **I1133 (the thief)** — `unilateral3_stolen` at the door: one key's
//!   framed revocation of another at three keys does not land; once the
//!   target and the third key object it never does.
//! - **I1134 (void votes)** — an assent from a key evicted since is void.
//! - **I1135 (one open per proposer)** — a proposer's second proposal is
//!   refused while its first is open; another proposer's is not.
//! - **I1136 (node clock)** — a proposal the signer backdated two windows is
//!   as young as its arrival.
//! - **I1137 (steward gate)** — a second device of the same self authors a
//!   consent grant that counts and restates the owner-binding as the same one
//!   steward; a key of another self does neither.
//! - **I1138 (compat)** — a pending addition is served neither framed nor as
//!   an `identity:occurrence:v1` row; once it lands it is served both ways.
//! - **I1140 (a node is not a roster key)** — a node its owner bound
//!   publishes its own occurrence; its signature on a user-role key's is
//!   refused `proposer_not_on_roster`, and nothing is held.
//! - **I1141 (genesis eviction)** — another roster key's framed revocation of
//!   the self pair lands by quorum; the genesis key leaves the roster, cannot
//!   sign for the self, and is no steward; the fedID string survives.
//! - **I1142 (W bound)** — an evicted key signing inside its old live window
//!   but more than W ago is refused `asserted_at_stale` at both steward gates.
//! - **I1139 (two nodes)** — a proposal and its assent delivered through the
//!   attestation plane land on the receiving node too.

#[cfg(test)]
pub(crate) mod bodies {
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

    /// A self `f` with user-role devices `devices`, registered.
    pub(crate) async fn keys(d: &dyn FederationDirectory, ids: &[&str]) {
        for k in ids {
            ts::register_hybrid_key_as(d, k, k, it::USER).await;
        }
    }

    /// `signer` signs `device` in as an occurrence of `f`, asserted at `at`.
    pub(crate) async fn add(
        d: &dyn FederationDirectory,
        signer: &str,
        f: &str,
        device: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        d.put_identity_occurrence(ts::signed_content_only_occurrence(signer, f, device, at).await)
            .await
    }

    /// Is `device` an active occurrence of `f`?
    pub(crate) async fn active(d: &dyn FederationDirectory, f: &str, device: &str) -> bool {
        d.list_identity_occurrences_active(f)
            .await
            .expect("active")
            .iter()
            .any(|o| o.occurrence_key_id == device)
    }

    /// The pending refusal's proposal id (panics on any other outcome).
    pub(crate) fn pending(r: Result<(), Error>, what: &str) -> String {
        match r {
            Err(Error::SelfRosterNotLanded {
                decision: "pending",
                proposal_id,
                ..
            }) => proposal_id,
            other => panic!("{what}: expected a pending proposal, got {other:?}"),
        }
    }

    /// `voter` answers proposal `p` of self `f`.
    pub(crate) async fn vote(
        d: &dyn FederationDirectory,
        voter: &str,
        f: &str,
        p: &str,
        assent: bool,
    ) {
        let env = sr::vote_envelope(f, p, assent);
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = ts::bare_attestation(&id, voter, f, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = ms_now();
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(voter, &mut r);
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .expect("an answer is admitted");
    }

    /// `who` signs something (a self-report): any signed act answers.
    pub(crate) async fn act(d: &dyn FederationDirectory, who: &str) {
        let env = serde_json::json!({ "dimension": "config:i1132-act:v1", "n": 1 });
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = ts::bare_attestation(&id, who, who, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = ms_now();
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(who, &mut r);
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .expect("a signed act is admitted");
    }

    /// A three-key self `{f, d1, d2}`: f adds d1 (one key, at once), then d1
    /// is proposed by f and assented by d1... — built through the door itself.
    pub(crate) async fn three(d: &dyn FederationDirectory, f: &str, d1: &str, d2: &str) {
        keys(d, &[f, d1, d2]).await;
        add(d, f, f, d1, ms_now()).await.expect("one key: lands");
        let p = pending(add(d, f, f, d2, ms_now()).await, "two keys: f adds d2");
        vote(d, d1, f, &p, true).await;
        assert!(
            active(d, f, d2).await,
            "the fixture's third key landed by quorum"
        );
    }

    async fn settle(d: &dyn FederationDirectory, f: &str) {
        sr::execute_for(d, f).await.expect("execute");
    }

    /// **I1130** — one key: the addition is unilateral.
    pub(crate) async fn i1130_one_key_adds_at_once(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1) = (format!("f-{tag}"), format!("d1-{tag}"));
        keys(d, &[&f, &d1]).await;
        add(d, &f, &f, &d1, ms_now())
            .await
            .expect("I1130: at one key the add lands at once");
        assert!(active(d, &f, &d1).await, "I1130: d1 is active");
        assert!(
            d.list_open_self_roster_proposals(Some(&f))
                .await
                .unwrap()
                .is_empty(),
            "I1130: no proposal is held"
        );
    }

    /// **I1131** — two keys: an addition is a proposal; the other key's
    /// assent lands it.
    pub(crate) async fn i1131_two_keys_quorum(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        keys(d, &[&f, &d1, &d2]).await;
        add(d, &f, &f, &d1, ms_now()).await.expect("one key");
        let err = add(d, &d1, &f, &d2, ms_now()).await;
        let Err(Error::SelfRosterNotLanded {
            decision,
            needs,
            ref proposal_id,
            kind,
            ..
        }) = err
        else {
            panic!("I1131: d1's add at two keys must be held, got {err:?}");
        };
        assert_eq!((decision, needs, kind), ("pending", 1, "add"));
        assert!(
            !active(d, &f, &d2).await,
            "I1131: the proposal is not an effect"
        );
        let row = d
            .get_attestation(proposal_id)
            .await
            .unwrap()
            .expect("I1131: the proposal row is held");
        assert!(sr::is_proposal_row(&row), "I1131: {row:?}");
        let standing = sr::standing(d, &f).await.unwrap();
        assert_eq!(standing.len(), 1, "I1131: {standing:?}");
        assert!(matches!(
            standing[0].decision,
            crate::federation::two_path::TwoPathDecision::Pending { needs: 1, .. }
        ));
        vote(d, &f, &f, proposal_id, true).await;
        assert!(
            active(d, &f, &d2).await,
            "I1131: the assent made a strict majority; d2 landed at once"
        );
        assert!(
            d.list_open_self_roster_proposals(Some(&f))
                .await
                .unwrap()
                .is_empty(),
            "I1131: the proposal is settled"
        );
    }

    /// **I1132** — the lone path: an unanswered eviction lands after W_self;
    /// a target that spoke is evictable only by quorum.
    pub(crate) async fn i1132_lone_path_and_silence(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        three(d, &f, &d1, &d2).await;
        let w = ts::occurrence_withdrawal(d, &d1, &f, &d2, ms_now()).await;
        let _p = pending(
            d.put_attestation(w).await.map(|_| ()),
            "I1132: d1's eviction of d2 at three keys",
        );
        assert!(active(d, &f, &d2).await, "I1132: not before the window");
        advance(sr::W_SELF_SECS - 60);
        settle(d, &f).await;
        assert!(active(d, &f, &d2).await, "I1132: not a minute early");
        advance(sr::W_SELF_SECS + 1);
        settle(d, &f).await;
        reset_clock();
        assert!(
            !active(d, &f, &d2).await,
            "I1132: unanswered, the eviction landed by the lone path"
        );

        // A target that speaks closes the lone path.
        let (g, e1, e2) = (format!("g-{tag}"), format!("e1-{tag}"), format!("e2-{tag}"));
        three(d, &g, &e1, &e2).await;
        let w = ts::occurrence_withdrawal(d, &e1, &g, &e2, ms_now()).await;
        let _ = pending(d.put_attestation(w).await.map(|_| ()), "I1132 (b)");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        act(d, &e2).await;
        advance(10 * sr::W_SELF_SECS);
        settle(d, &g).await;
        reset_clock();
        assert!(
            active(d, &g, &e2).await,
            "I1132: a target that signed since the proposal is evictable only by quorum"
        );
    }

    /// **I1133** — the thief: one key's lone eviction of another at three
    /// keys does not land, and once the owner's keys object it never does.
    pub(crate) async fn i1133_the_thief_cannot_evict(d: &dyn FederationDirectory, tag: &str) {
        let (f, thief, owner) = (format!("f-{tag}"), format!("t-{tag}"), format!("o-{tag}"));
        three(d, &f, &thief, &owner).await;
        let rev = ts::signed_occurrence_revocation(&thief, &f, &owner, ms_now()).await;
        let p = pending(
            d.put_identity_occurrence_revocation(rev).await,
            "I1133: the thief's eviction",
        );
        assert!(active(d, &f, &owner).await, "I1133: refused at age 0");
        vote(d, &owner, &f, &p, false).await;
        vote(d, &f, &f, &p, false).await;
        advance(10 * sr::W_SELF_SECS);
        settle(d, &f).await;
        reset_clock();
        assert!(
            active(d, &f, &owner).await,
            "I1133: answered, the thief's eviction never lands"
        );
    }

    /// **I1134** — an assent from a key evicted since is void.
    pub(crate) async fn i1134_an_evicted_keys_vote_is_void(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1, d2, d3, d4) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("d2-{tag}"),
            format!("d3-{tag}"),
            format!("d4-{tag}"),
        );
        three(d, &f, &d1, &d2).await;
        keys(d, &[&d3, &d4]).await;
        // {f, d1, d2} → {f, d1, d2, d3}: f proposes, d1 assents (2 of 3).
        let p3 = pending(add(d, &f, &f, &d3, ms_now()).await, "f adds d3");
        vote(d, &d1, &f, &p3, true).await;
        assert!(active(d, &f, &d3).await);
        // d2 proposes d4 (1 of 4); d1 assents (2 of 4: no majority yet).
        let p4 = pending(add(d, &d2, &f, &d4, ms_now()).await, "d2 adds d4");
        vote(d, &d1, &f, &p4, true).await;
        assert!(!active(d, &f, &d4).await, "I1134: 2 of 4 is no majority");
        // d1 is evicted by quorum: f proposes, d2 and d3 assent (3 of 4).
        let w = ts::occurrence_withdrawal(d, &f, &f, &d1, ms_now()).await;
        let pe = pending(d.put_attestation(w).await.map(|_| ()), "f evicts d1");
        vote(d, &d2, &f, &pe, true).await;
        vote(d, &d3, &f, &pe, true).await;
        assert!(!active(d, &f, &d1).await, "I1134: d1 evicted");
        settle(d, &f).await;
        // {f, d2, d3}: d4's proposal has d2 (proposer) + d1 (void) = 1 of 3.
        assert!(
            !active(d, &f, &d4).await,
            "I1134: the evicted d1's assent made a majority of the smaller roster"
        );
        // The evicted key is off the roster the quorum is counted over too: f
        // proposes d5 and d2 assents, 2 of the live 3 (a roster that kept d1
        // would need 3 of 4).
        let d5 = format!("d5-{tag}");
        keys(d, &[&d5]).await;
        let p5 = pending(add(d, &f, &f, &d5, ms_now()).await, "f adds d5");
        vote(d, &d2, &f, &p5, true).await;
        assert!(
            active(d, &f, &d5).await,
            "I1134: 2 of the live 3 lands; the quorum was counted over a roster that kept d1"
        );
        // {f, d2, d3, d5}: d4 needs 3 — d2, then d3 and d5.
        vote(d, &d3, &f, &p4, true).await;
        assert!(!active(d, &f, &d4).await, "I1134: 2 of 4 is no majority");
        vote(d, &d5, &f, &p4, true).await;
        assert!(active(d, &f, &d4).await, "I1134: live assents land it");
    }

    /// **I1135** — one open proposal per proposer, never a global cap.
    pub(crate) async fn i1135_one_open_per_proposer(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1, a, b) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("a-{tag}"),
            format!("b-{tag}"),
        );
        keys(d, &[&f, &d1, &a, &b]).await;
        add(d, &f, &f, &d1, ms_now()).await.expect("one key");
        let _ = pending(add(d, &d1, &f, &a, ms_now()).await, "d1's first");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        match add(d, &d1, &f, &b, ms_now()).await {
            Err(Error::SelfRosterNotLanded {
                decision: "proposer_has_open_proposal",
                ..
            }) => {}
            other => panic!("I1135: d1's second open proposal: {other:?}"),
        }
        let _ = pending(add(d, &f, &f, &b, ms_now()).await, "I1135: f is not capped");
    }

    /// **I1136** — the window is the node's: a backdated proposal is as young
    /// as its arrival.
    pub(crate) async fn i1136_the_window_is_the_nodes(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        keys(d, &[&f, &d1, &d2]).await;
        add(d, &f, &f, &d1, ms_now()).await.expect("one key");
        let backdated = ms_now() - chrono::Duration::seconds(2 * sr::W_SELF_SECS);
        let _ = pending(add(d, &d1, &f, &d2, backdated).await, "I1136");
        settle(d, &f).await;
        assert!(
            !active(d, &f, &d2).await,
            "I1136: a proposal signed two windows ago landed on arrival"
        );
        let s = sr::standing(d, &f).await.unwrap();
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
        keys(d, &[&f, &d1, &peer, &g, &e1, &peer2]).await;
        ts::register_hybrid_key_as(d, &node, &node, it::NODE).await;
        add(d, &f, &f, &d1, ms_now()).await.expect("f's second key");
        add(d, &g, &g, &e1, ms_now()).await.expect("g's second key");
        d.put_attestation(SignedAttestation {
            attestation: binding(&f, &node),
        })
        .await
        .expect("I1137: f owns the node");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        // The consent fold.
        let mine = grant(&d1, &peer, &node);
        d.put_attestation(SignedAttestation {
            attestation: mine.clone(),
        })
        .await
        .expect("I1137: d1's grant is admitted");
        assert!(
            cbh::grant_is_authored_for(d, &mine, &node).await.unwrap(),
            "I1137: a live roster key of the owner authors as the owner"
        );
        let theirs = grant(&e1, &peer2, &node);
        d.put_attestation(SignedAttestation {
            attestation: theirs.clone(),
        })
        .await
        .expect("I1137: e1's grant is admitted");
        assert!(
            !cbh::grant_is_authored_for(d, &theirs, &node).await.unwrap(),
            "I1137: a key of another self is not the node's steward"
        );
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            vec![peer.clone()],
            "I1137: the second device's grant counts; another self's does not"
        );

        // The one-responsible-steward gate.
        d.put_attestation(SignedAttestation {
            attestation: binding(&d1, &node),
        })
        .await
        .expect("I1137: d1 restates its self's binding: the same one steward");
        assert_eq!(
            crate::federation::admission::owner_of(d, &node)
                .await
                .unwrap(),
            Some(f.clone()),
            "I1137: the node has one owner, the self"
        );
        match d
            .put_attestation(SignedAttestation {
                attestation: binding(&e1, &node),
            })
            .await
        {
            Err(Error::NodeAlreadyOwned { .. }) => {}
            other => panic!("I1137: another self's key binding the node: {other:?}"),
        }
    }

    /// **I1140** — a node is not a roster key: a node its owner bound may
    /// still publish its own occurrence under the owner, but its signature on
    /// a user-role key's occurrence is refused (`proposer_not_on_roster`) and
    /// no proposal is held.
    pub(crate) async fn i1140_a_node_does_not_add_roster_keys(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (f, node, dev) = (format!("f-{tag}"), format!("n-{tag}"), format!("v-{tag}"));
        keys(d, &[&f, &dev]).await;
        ts::register_hybrid_key_as(d, &node, &node, it::NODE).await;
        d.put_attestation(SignedAttestation {
            attestation: binding(&f, &node),
        })
        .await
        .expect("I1140: f owns the node");
        add(d, &node, &f, &node, ms_now())
            .await
            .expect("I1140: a node publishes its own occurrence under its owner");
        match add(d, &node, &f, &dev, ms_now()).await {
            Err(Error::SelfRosterNotLanded {
                decision: "proposer_not_on_roster",
                ..
            }) => {}
            other => panic!("I1140: a node adding a user-role key: {other:?}"),
        }
        assert!(!active(d, &f, &dev).await);
        assert!(d
            .list_open_self_roster_proposals(Some(&f))
            .await
            .unwrap()
            .is_empty());
    }

    /// **I1141** — the genesis key is evictable: another roster key's framed
    /// revocation of the self pair is a proposal, lands by quorum, and then
    /// the genesis key is off the roster, cannot sign for the self, and is no
    /// steward — while the fedID string keeps naming the self and its other
    /// keys act as it. The genesis key revoking its own pair (its transport
    /// self-occurrence) lands at once and evicts nothing.
    pub(crate) async fn i1141_the_genesis_key_is_evictable(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1, d2, d3) = (
            format!("f-{tag}"),
            format!("d1-{tag}"),
            format!("d2-{tag}"),
            format!("d3-{tag}"),
        );
        three(d, &f, &d1, &d2).await;
        keys(d, &[&d3]).await;
        let rev = ts::signed_occurrence_revocation(&d1, &f, &f, ms_now()).await;
        let p = pending(
            d.put_identity_occurrence_revocation(rev).await,
            "I1141: d1 proposes the genesis key's eviction",
        );
        assert!(sr::roster_now(d, &f).await.unwrap().contains(&f));
        vote(d, &d2, &f, &p, true).await;
        let roster = sr::roster_now(d, &f).await.unwrap();
        assert!(
            !roster.contains(&f) && roster.contains(&d1) && roster.contains(&d2),
            "I1141: the genesis key left the roster: {roster:?}"
        );
        let now = chrono::Utc::now();
        assert!(!sr::acts_as_steward_at(d, &f, &f, now).await.unwrap());
        assert!(
            sr::acts_as_steward_at(d, &f, &d1, now).await.unwrap(),
            "I1141: the fedID string survives; a live roster key acts as it"
        );
        match add(d, &f, &f, &d3, ms_now()).await {
            Err(Error::SignerDoesNotActFor { .. }) => {}
            other => panic!("I1141: an evicted genesis key signs for the self: {other:?}"),
        }
        // {d1, d2}: d1's addition needs d2.
        let p3 = pending(add(d, &d1, &f, &d3, ms_now()).await, "I1141: d1 adds d3");
        vote(d, &d2, &f, &p3, true).await;
        assert!(
            active(d, &f, &d3).await,
            "I1141: the self goes on without its genesis key"
        );

        // The genesis key retiring its own pair is not an eviction.
        let (g, e1) = (format!("g-{tag}"), format!("e1-{tag}"));
        keys(d, &[&g, &e1]).await;
        add(d, &g, &g, &e1, ms_now()).await.expect("one key");
        d.put_identity_occurrence_revocation(
            ts::signed_occurrence_revocation(&g, &g, &g, ms_now()).await,
        )
        .await
        .expect("I1141: the genesis key retires its own self pair at once");
        assert!(
            sr::roster_now(d, &g).await.unwrap().contains(&g),
            "I1141: its own revocation evicts nothing"
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
        keys(d, &[&f, &d1, &d2, &peer]).await;
        ts::register_hybrid_key_as(d, &node, &node, it::NODE).await;
        let days = |n: i64| ms_now() - chrono::Duration::days(n);
        // d1 live since five days ago; d2 added through the door.
        add(d, &f, &f, &d1, days(5)).await.expect("one key");
        let p2 = pending(add(d, &f, &f, &d2, ms_now()).await, "f adds d2");
        vote(d, &d1, &f, &p2, true).await;
        d.put_attestation(SignedAttestation {
            attestation: binding(&f, &node),
        })
        .await
        .expect("I1142: f owns the node");
        // Evict d1 by quorum: f proposes, d2 assents.
        let w = ts::occurrence_withdrawal(d, &f, &f, &d1, ms_now()).await;
        let pe = pending(d.put_attestation(w).await.map(|_| ()), "f evicts d1");
        vote(d, &d2, &f, &pe, true).await;
        assert!(!active(d, &f, &d1).await, "I1142: d1 evicted");

        let mut stale = grant(&d1, &peer, &node);
        stale.asserted_at = days(4);
        stale.scrub_timestamp = stale.asserted_at;
        ts::seal_row_in_place(&d1, &mut stale);
        let e = d
            .put_attestation(SignedAttestation { attestation: stale })
            .await
            .expect_err("I1142: the evicted d1's backdated grant");
        assert!(e.to_string().contains(sr::ASSERTED_AT_STALE), "I1142: {e}");

        let mut stale_bind = binding(&d1, &node);
        stale_bind.asserted_at = days(4);
        stale_bind.scrub_timestamp = stale_bind.asserted_at;
        ts::seal_row_in_place(&d1, &mut stale_bind);
        let e = d
            .put_attestation(SignedAttestation {
                attestation: stale_bind,
            })
            .await
            .expect_err("I1142: the evicted d1's backdated owner-binding");
        assert!(e.to_string().contains(sr::ASSERTED_AT_STALE), "I1142: {e}");

        // A live roster key inside W passes, and counts.
        let mut fresh = grant(&d2, &peer, &node);
        fresh.asserted_at = ms_now();
        fresh.scrub_timestamp = fresh.asserted_at;
        ts::seal_row_in_place(&d2, &mut fresh);
        d.put_attestation(SignedAttestation {
            attestation: fresh.clone(),
        })
        .await
        .expect("I1142: d2's grant now is inside W");
        assert!(cbh::grant_is_authored_for(d, &fresh, &node).await.unwrap());
    }

    /// **I1138** — compat: pending is served neither framed nor as a row.
    pub(crate) async fn i1138_pending_is_not_served(d: &dyn FederationDirectory, tag: &str) {
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        keys(d, &[&f, &d1, &d2]).await;
        add(d, &f, &f, &d1, ms_now()).await.expect("one key");
        let p = pending(add(d, &d1, &f, &d2, ms_now()).await, "I1138");
        let framed = |d2: String| async move {
            d.list_signed_identity_occurrences_since(None, 10_000)
                .await
                .unwrap()
                .iter()
                .any(|s| s.occurrence.identity_occurrence.occurrence_key_id == d2)
        };
        let as_row = |d2: String| async move {
            crate::federation::key_plane::test_support::served_identity_occurrences(d, 10_000)
                .await
                .unwrap()
                .iter()
                .any(|s| s.occurrence.identity_occurrence.occurrence_key_id == d2)
        };
        assert!(
            !framed(d2.clone()).await,
            "I1138: a pending add is served framed"
        );
        assert!(
            !as_row(d2.clone()).await,
            "I1138: a pending add is served as a row"
        );
        vote(d, &f, &f, &p, true).await;
        assert!(
            framed(d2.clone()).await,
            "I1138: the landed add is served framed"
        );
        assert!(
            as_row(d2.clone()).await,
            "I1138: the landed add is served as a row"
        );
    }

    /// **I1139** — two nodes: node A's proposal and assent, delivered through
    /// the attestation plane, land on node B.
    pub(crate) async fn i1139_two_nodes_land_alike(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        for d in [a, b] {
            keys(d, &[&f, &d1, &d2]).await;
            add(d, &f, &f, &d1, ms_now()).await.expect("one key");
        }
        let p = pending(add(a, &d1, &f, &d2, ms_now()).await, "I1139 on A");
        vote(a, &f, &f, &p, true).await;
        assert!(active(a, &f, &d2).await, "I1139: landed on A");
        // Deliver A's attestation stream to B (the replication apply door).
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
        settle(b, &f).await;
        assert!(
            active(b, &f, &d2).await,
            "I1139: B landed the delivered proposal by the delivered assent"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[tokio::test(flavor = "multi_thread")]
                async fn memory() {
                    let b = crate::store::memory::MemoryBackend::new();
                    $body(&b, &tag("m")).await;
                    bodies::reset_clock();
                }

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

    on_every_backend!(i1130, bodies::i1130_one_key_adds_at_once);
    on_every_backend!(i1131, bodies::i1131_two_keys_quorum);
    on_every_backend!(i1132, bodies::i1132_lone_path_and_silence);
    on_every_backend!(i1133, bodies::i1133_the_thief_cannot_evict);
    on_every_backend!(i1134, bodies::i1134_an_evicted_keys_vote_is_void);
    on_every_backend!(i1135, bodies::i1135_one_open_per_proposer);
    on_every_backend!(i1136, bodies::i1136_the_window_is_the_nodes);
    on_every_backend!(i1137, bodies::i1137_a_second_device_acts_as_its_self);
    on_every_backend!(i1138, bodies::i1138_pending_is_not_served);
    on_every_backend!(i1140, bodies::i1140_a_node_does_not_add_roster_keys);
    on_every_backend!(i1141, bodies::i1141_the_genesis_key_is_evictable);
    on_every_backend!(
        i1142,
        bodies::i1142_an_evicted_key_cannot_sign_into_its_old_window
    );

    mod i1139 {
        use super::*;

        #[tokio::test(flavor = "multi_thread")]
        async fn memory() {
            let (a, b) = (
                crate::store::memory::MemoryBackend::new(),
                crate::store::memory::MemoryBackend::new(),
            );
            bodies::i1139_two_nodes_land_alike(&a, &b, &tag("m")).await;
        }

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
            bodies::i1139_two_nodes_land_alike(&a, &b, &tag("s")).await;
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
            bodies::i1139_two_nodes_land_alike(&a, &b, &tag("p")).await;
            eprintln!("i1139: RAN");
        }
    }
}
