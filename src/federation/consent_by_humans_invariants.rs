//! CIRISPersist#857 — witnesses for `FSD/CONSENT_BY_HUMANS.md` §5. One body
//! per invariant, generic over the directory, run by every backend that folds
//! consent (memory, sqlite, postgres), so the three cannot diverge.
//!
//! v62.0.0 (JSON cut, E7) — every key is an edition-2 `key:record`
//! (`e2::put_key`, which returns the identity-ref the folds key on), and every
//! row an edition-2 statement (`e2::row_of`) signed by its author's SEED. A
//! row id is node-computed, so a body reads it off the row (`rid`). Peers a
//! grant names ride `subject_key_ids`, which the codec writes as
//! identity-refs (`e2::kid`).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::ConsentState;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{
        admission, consent_by_humans as cbh, Attestation, FederationDirectory, IdentityOccurrence,
        SignedAttestation,
    };

    /// A federation-tier row signed by the key of SEED `signer` over
    /// `envelope`, targeting `target` (an identity-ref, or a seed the codec
    /// maps), with `subject_key_ids`: an edition-2 statement mapped onto the
    /// typed row (v62.0.0, E7).
    fn row(
        signer: &str,
        ty: &str,
        target: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let r = Attestation {
            attestation_id: String::new(),
            attesting_key_id: e2::kid(signer),
            attested_key_id: target.to_owned(),
            attestation_type: ty.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: e2::kid(signer),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        e2::row_of(&r, signer)
    }

    /// v62.0.0 (CC 2.4.1.1) — a node / agent key's rows lapse when its record
    /// ends, so every fixture instant is NOW-RELATIVE: the bodies' dates
    /// (written against 2026-06-01) keep their spacing, shifted so that
    /// 2026-06-01T00:00:00Z falls at today's UTC midnight minus 7 days.
    fn relative(at: &str) -> chrono::DateTime<chrono::Utc> {
        let written: chrono::DateTime<chrono::Utc> = at.parse().unwrap();
        let origin: chrono::DateTime<chrono::Utc> = "2026-06-01T00:00:00Z".parse().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("midnight")
            .and_utc();
        today - chrono::Duration::days(7) + (written - origin)
    }

    /// `consent:state:<stance>:v1` by `subject` about `target`, naming `scope`,
    /// optionally FOR `for_key`.
    fn state(
        id: &str,
        subject: &str,
        target: &str,
        stance: &str,
        scope: &str,
        for_key: Option<&str>,
        at: &str,
    ) -> Attestation {
        let at = admission::truncate_to_substrate_resolution(relative(at));
        let mut env = serde_json::json!({
            "id": id,
            "dimension": format!("consent:state:{stance}:v1"),
            "scope": scope,
            crate::federation::envelope::paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(at),
        });
        if let Some(f) = for_key {
            env[cbh::FOR_KEY_ID] = serde_json::Value::String(f.to_owned());
        }
        row(
            subject,
            attestation_type::SCORES,
            target,
            env,
            Vec::new(),
            at,
        )
    }

    /// A `consent:replication:v1` grant by `author` (a SEED) to `peer`,
    /// optionally FOR `for_key` (an identity-ref). `id` keeps two grants
    /// distinct rows (the row id is over the payload).
    fn grant(id: &str, author: &str, peer: &str, for_key: Option<&str>) -> Attestation {
        let mut payload = serde_json::json!({
            "grants": "replication",
            "attestation_prefixes": ["i96-fixture:"],
            "label": id,
        });
        if let Some(f) = for_key {
            payload[cbh::FOR_KEY_ID] = serde_json::Value::String(f.to_owned());
        }
        row(
            author,
            attestation_type::SCORES,
            &e2::kid(author),
            serde_json::json!({"dimension": crate::federation::consent_peer_set::DIMENSION, "payload": payload}),
            vec![peer.to_owned()],
            chrono::Utc::now(),
        )
    }

    /// A PLAIN conferral `delegates_to(user → agent)` — the `self_at_login`
    /// delegation shape, no custody marker: a job, not stewardship. `user`
    /// is a SEED, `agent` an identity-ref.
    fn conferral(id: &str, user: &str, agent: &str) -> Attestation {
        let at = relative("2026-05-01T00:00:00Z");
        row(
            user,
            attestation_type::DELEGATES_TO,
            agent,
            serde_json::json!({"id": id, "kind": "delegates_to", "delegate_key_id": agent, "scope": ["act_on_behalf", "message_io"], "sub_delegation": false}),
            Vec::new(),
            at,
        )
    }

    /// v62.0.0 (lead ruling; O1.api) — `owner` (a SEED) anchors `agent` (a
    /// SEED): an agent is never an occurrence of a person (a key is a person's
    /// or a machine's, never both). The anchor is the owner-authored
    /// `ownership:responsible_party:agent` binding plus the agent's own voice.
    async fn own_agent(d: &dyn FederationDirectory, owner: &str, agent: &str) {
        let at = u64::try_from(chrono::Utc::now().timestamp_millis()).expect("after 1970");
        e2::put_agent_owner_binding(d, owner, agent, at).await;
    }

    /// The held owner binding `owner → agent` (both identity-refs).
    async fn owner_binding_row(
        d: &dyn FederationDirectory,
        owner: &str,
        agent: &str,
    ) -> Attestation {
        d.list_attestations_for(agent)
            .await
            .unwrap()
            .into_iter()
            .find(|a| {
                a.attesting_key_id == owner
                    && a.attestation_type == attestation_type::DELEGATES_TO
                    && a.attestation_envelope
                        .get("dimension")
                        .and_then(|v| v.as_str())
                        .is_some_and(|dim| dim.starts_with("ownership:"))
            })
            .expect("the owner binding is held")
    }

    /// `owner` (a SEED) binds
    /// node's own statement over it (RULINGS: an owner binding needs the
    /// node's cosignature, C557).
    async fn bind_owner(d: &dyn FederationDirectory, owner: &str, node: &str) {
        // The builder dates its binding 2026-05-01; the node's voice is a
        // node-key row, which must be now-relative (CC 2.4.1.1), so the
        // binding is re-dated and re-sealed before the voice is taken.
        let mut row = ts::owner_binding_attestation("", owner, node);
        let at = admission::truncate_to_substrate_resolution(relative("2026-05-01T00:00:00Z"));
        row.asserted_at = at;
        row.scrub_timestamp = at;
        row.attestation_envelope[crate::federation::envelope::paths::ASSERTED_AT] =
            serde_json::Value::String(admission::render_signed_instant(at));
        ts::reseal(&mut row);
        put(d, row.clone()).await.expect("the owner binding");
        let voice = e2::voice_of(
            &e2::carried_statement(&row).expect("the binding carries its statement"),
            node,
        );
        e2::put_statement(d, &voice)
            .await
            .expect("the node's voice on its owner binding");
    }

    async fn put(
        d: &dyn FederationDirectory,
        a: Attestation,
    ) -> Result<(), crate::federation::Error> {
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .map(|_| ())
    }

    /// The trusted-local occurrence row: `occurrence` as an occurrence of `identity`.
    async fn occurrence(
        d: &dyn FederationDirectory,
        identity: &str,
        occurrence_key: &str,
        class: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence_key.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("occurrence row");
    }

    /// **I94** — the occurrence anchor: an agent bound as an occurrence of a
    /// `user` identity has that human in every steward fold — WHILE the
    /// agent's transport self-row exists beside it. A conferral does not
    /// steward. A revoked occurrence stops anchoring.
    pub async fn i94_occurrence_anchor_with_the_self_row_present(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (alice_s, agent_s) = (format!("i94-alice-{s}"), format!("i94-agent-{s}"));
        let alice = e2::put_key(d, &alice_s, &[USER]).await;
        let agent = e2::put_key(d, &agent_s, &[AGENT]).await;
        // Server compose's transport self-occurrence: identity = the agent itself.
        occurrence(d, &agent, &agent, "agent", None).await;
        assert!(
            admission::steward_bindings_of(d, &agent)
                .await
                .unwrap()
                .is_empty(),
            "I94: the self-row anchors nobody"
        );
        assert!(!admission::is_steward_bound(d, &agent).await.unwrap());
        assert_eq!(
            cbh::consent_principals_of(d, &agent).await.unwrap(),
            vec![agent.clone()],
            "I94: {{k}} only"
        );

        // A conferral (the login delegation's shape) is a job, not stewardship.
        put(d, conferral(&format!("i94-conf-{s}"), &alice_s, &agent))
            .await
            .expect("I94: a conferral admits");
        assert!(
            admission::steward_bindings_of(d, &agent)
                .await
                .unwrap()
                .is_empty(),
            "I94: a conferral does not steward (Clause D)"
        );

        // v62.0.0 (lead ruling) — the human anchors the agent through the
        // OWNER relation (an agent is never an occurrence of a person), beside
        // the agent's self-row.
        own_agent(d, &alice_s, &agent_s).await;
        assert_eq!(
            admission::steward_bindings_of(d, &agent).await.unwrap(),
            vec![alice.clone()],
            "I94: the human anchors the agent"
        );
        assert!(
            admission::is_steward_bound(d, &agent).await.unwrap(),
            "I94: is_steward_bound agrees"
        );
        assert_eq!(
            admission::steward_binding_chain(d, &agent).await.unwrap(),
            vec![alice.clone(), agent.clone()],
            "I94: the chain is human → agent"
        );
        let mut p = cbh::consent_principals_of(d, &agent).await.unwrap();
        p.sort();
        let mut want = vec![agent.clone(), alice.clone()];
        want.sort();
        assert_eq!(p, want, "I94: {{k}} ∪ stewards");

        // The owner WITHDRAWS the binding: the anchor is gone, the self-row
        // still anchors nobody.
        let binding = owner_binding_row(d, &alice, &agent).await;
        e2::put_signed(d, &e2::composer_of("withdraws", &binding, &alice_s))
            .await
            .expect("I94: the owner withdraws the binding");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(
            admission::steward_bindings_of(d, &agent)
                .await
                .unwrap()
                .is_empty(),
            "I94: a withdrawn binding anchors nobody"
        );
    }

    /// **I95** — the scoped fold keyed by the machine walks to the human ON
    /// ROWS THAT NAME THE MACHINE, and combines principals as a reverse quorum.
    pub async fn i95_scoped_consent_by_principals(d: &dyn FederationDirectory, s: &str) {
        use ConsentState::*;
        let now = chrono::Utc::now();
        let (canonical_s, alice_s, node_s, sibling_s) = (
            format!("i95-canon-{s}"),
            format!("i95-alice-{s}"),
            format!("i95-node-{s}"),
            format!("i95-sib-{s}"),
        );
        let canonical = e2::put_key(d, &canonical_s, &[NODE]).await;
        let alice = e2::put_key(d, &alice_s, &[USER]).await;
        let node = e2::put_key(d, &node_s, &[NODE]).await;
        let sibling = e2::put_key(d, &sibling_s, &[AGENT]).await;
        bind_owner(d, &alice_s, &node_s).await;
        own_agent(d, &alice_s, &sibling_s).await;
        let by = |subject: String, target: String| async move {
            cbh::resolve_scoped_consent_by_principals(d, &target, &subject, "analyze", None, now)
                .await
                .unwrap()
        };
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Unspecified,
            "I95: no human stance, no consent"
        );

        // alice grants FOR the sibling agent: nothing for the node.
        put(
            d,
            state(
                &format!("i95-gs-{s}"),
                &alice_s,
                &canonical,
                "granted",
                "analyze",
                Some(&sibling),
                "2026-06-01T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Unspecified,
            "I95: a row naming ANOTHER agent is Unspecified for this one"
        );
        assert_eq!(
            by(sibling.clone(), canonical.clone()).await,
            Granted,
            "I95: …and Granted for the one it names"
        );
        // alice grants naming nobody: nothing for the node either.
        put(
            d,
            state(
                &format!("i95-gn-{s}"),
                &alice_s,
                &canonical,
                "granted",
                "analyze",
                None,
                "2026-06-01T00:00:01Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Unspecified,
            "I95: a row naming no machine is Unspecified for a machine"
        );
        assert_eq!(
            by(alice.clone(), canonical.clone()).await,
            Granted,
            "I95: keyed by the human, the human's own stance, whatever it names"
        );

        // alice grants FOR the node: the node's consent is its owner's — and
        // the strict fold keyed by the node still answers nothing (the defect).
        put(
            d,
            state(
                &format!("i95-g-{s}"),
                &alice_s,
                &canonical,
                "granted",
                "analyze",
                Some(&node),
                "2026-06-01T00:00:02Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Granted,
            "I95: the row naming the node governs it"
        );
        assert_eq!(
            d.resolve_scoped_consent(&canonical, &node, "analyze", None, now)
                .await
                .unwrap(),
            Unspecified,
            "I95: the strict fold keyed by the node is the defect, kept visible"
        );

        // Legacy: a MACHINE-authored grant still counts — {k} is in the set.
        let legacy_s = format!("i95-legacy-{s}");
        let legacy = e2::put_key(d, &legacy_s, &[AGENT]).await;
        let t2 = e2::put_key(d, &format!("i95-t2-{s}"), &[NODE]).await;
        put(
            d,
            state(
                &format!("i95-lg-{s}"),
                &legacy_s,
                &t2,
                "granted",
                "analyze",
                None,
                "2026-06-01T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(legacy.clone(), t2.clone()).await,
            Granted,
            "I95: a legacy machine-authored grant keeps counting"
        );

        // Two principals: the agent's own legacy row + its steward's row naming it.
        let agent_s = format!("i95-agent-{s}");
        let agent = e2::put_key(d, &agent_s, &[AGENT]).await;
        let t3 = e2::put_key(d, &format!("i95-t3-{s}"), &[NODE]).await;
        own_agent(d, &alice_s, &agent_s).await;
        put(
            d,
            state(
                &format!("i95-g3-{s}"),
                &alice_s,
                &t3,
                "granted",
                "analyze",
                Some(&agent),
                "2026-06-01T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(agent.clone(), t3.clone()).await,
            Granted,
            "I95: steward grant + agent silent → Granted"
        );
        put(
            d,
            state(
                &format!("i95-ag-{s}"),
                &agent_s,
                &t3,
                "granted",
                "analyze",
                None,
                "2026-06-01T12:00:00Z",
            ),
        )
        .await
        .unwrap();
        put(
            d,
            state(
                &format!("i95-r3-{s}"),
                &alice_s,
                &t3,
                "revoked",
                "analyze",
                Some(&agent),
                "2026-06-02T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(agent.clone(), t3.clone()).await,
            Revoked,
            "I95: agent's own grant + steward revoke → Revoked (reverse quorum on the stop)"
        );
        put(
            d,
            state(
                &format!("i95-g3b-{s}"),
                &alice_s,
                &t3,
                "granted",
                "analyze",
                Some(&agent),
                "2026-06-03T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(by(agent.clone(), t3.clone()).await, Granted, "I95: the SAME steward re-granting newer than its own revoke → Granted (latest-wins within one principal)");
    }

    /// **I829** (v54.1.0, Codex round 4 on PR #1057) — a hard-deleted grant
    /// stops authorising: the steward's grant FOR the node projects into
    /// `consent_peer_set_for`; after the attestation's hard delete and
    /// `purge_attestation_projections` (the sequence `purge_finalize` and the
    /// reaper run) `consent_peers_by_principals` no longer names the peer.
    pub async fn i829_a_deleted_grant_stops_authorising(d: &dyn FederationDirectory, s: &str) {
        let (alice_s, node_s, p1) = (
            format!("i829-alice-{s}"),
            format!("i829-node-{s}"),
            format!("i829-p1-{s}"),
        );
        e2::put_key(d, &alice_s, &[USER]).await;
        let node = e2::put_key(d, &node_s, &[NODE]).await;
        bind_owner(d, &alice_s, &node_s).await;
        let g = grant(&format!("i829-g-{s}"), &alice_s, &p1, Some(&node));
        let gid = g.attestation_id.clone();
        put(d, g).await.unwrap();
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            vec![e2::kid(&p1)],
            "I829 control: the steward's grant names the node's peer"
        );
        assert!(
            d.purge_attestation_v31(&gid).await.unwrap(),
            "the grant is hard-deleted"
        );
        d.purge_attestation_projections(&gid).await.unwrap();
        assert!(
            cbh::consent_peers_by_principals(d, &node)
                .await
                .unwrap()
                .is_empty(),
            "I829: a hard-deleted grant no longer authorises its peer"
        );
    }

    /// **I96** — the peer set by principals: own peers ∪ the steward's grants
    /// that NAME the machine; a grant for a sibling contributes nothing.
    pub async fn i96_consent_peers_by_principals(d: &dyn FederationDirectory, s: &str) {
        let (alice_s, node_s, sibling_s, p1, p2, p3, p4) = (
            format!("i96-alice-{s}"),
            format!("i96-node-{s}"),
            format!("i96-sib-{s}"),
            format!("i96-p1-{s}"),
            format!("i96-p2-{s}"),
            format!("i96-p3-{s}"),
            format!("i96-p4-{s}"),
        );
        let _alice = e2::put_key(d, &alice_s, &[USER]).await;
        let node = e2::put_key(d, &node_s, &[NODE]).await;
        let sibling = e2::put_key(d, &sibling_s, &[AGENT]).await;
        bind_owner(d, &alice_s, &node_s).await;
        own_agent(d, &alice_s, &sibling_s).await;
        // The owner grants replication FOR the node to p1 and p2, FOR the
        // sibling to p4; the node itself to nobody — the split-key home.
        put(d, grant(&format!("i96-g1-{s}"), &alice_s, &p1, Some(&node)))
            .await
            .unwrap();
        put(d, grant(&format!("i96-g2-{s}"), &alice_s, &p2, Some(&node)))
            .await
            .unwrap();
        put(
            d,
            grant(&format!("i96-g4-{s}"), &alice_s, &p4, Some(&sibling)),
        )
        .await
        .unwrap();
        assert!(d.list_consent_peers(&node).await.unwrap().is_empty(), "I96 precondition: the strict projection keyed by the node is EMPTY — the zero-traces defect");
        let mut want = vec![e2::kid(&p1), e2::kid(&p2)];
        want.sort();
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            want,
            "I96: keyed by the node, the owner's grants naming it — and NOT the sibling's"
        );
        assert_eq!(
            cbh::consent_peers_by_principals(d, &sibling).await.unwrap(),
            vec![e2::kid(&p4)],
            "I96: the sibling gets only its own"
        );
        // A legacy node-authored grant is unioned in, not lost.
        put(d, grant(&format!("i96-g3-{s}"), &node_s, &p3, None))
            .await
            .unwrap();
        let mut want3 = vec![e2::kid(&p1), e2::kid(&p2), e2::kid(&p3)];
        want3.sort();
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            want3,
            "I96: {{k}} ∪ stewards-naming-k, deduped, sorted"
        );
        // A stranger's grant naming the node contributes nothing: not a steward.
        let mallory = format!("i96-mallory-{s}");
        e2::put_key(d, &mallory, &[USER]).await;
        put(
            d,
            grant(
                &format!("i96-gm-{s}"),
                &mallory,
                &format!("i96-px-{s}"),
                Some(&node),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            want3,
            "I96: a non-steward naming the machine consents for nothing"
        );
    }

    /// **I96 (b)** — a MACHINE author naming another key is refused at
    /// admission; a human may name any key; an unknown member still rejects.
    pub async fn i96b_for_key_id_admission(d: &dyn FederationDirectory, s: &str) {
        let (alice_s, node_s, other_s) = (
            format!("i96b-alice-{s}"),
            format!("i96b-node-{s}"),
            format!("i96b-other-{s}"),
        );
        e2::put_key(d, &alice_s, &[USER]).await;
        let node = e2::put_key(d, &node_s, &[NODE]).await;
        let other = e2::put_key(d, &other_s, &[AGENT]).await;
        put(
            d,
            grant(&format!("i96b-self-{s}"), &node_s, "p", Some(&node)),
        )
        .await
        .expect("I96 (b): a machine naming ITSELF admits");
        let err = put(d, grant(&format!("i96b-x-{s}"), &node_s, "p", Some(&other)))
            .await
            .expect_err("I96 (b): a machine naming ANOTHER key is refused");
        assert!(
            err.to_string().contains("for_key_id"),
            "I96 (b): the refusal names the member: {err}"
        );
        put(
            d,
            grant(&format!("i96b-h-{s}"), &alice_s, "p", Some(&other)),
        )
        .await
        .expect("I96 (b): a human may name any key");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i94() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i94_occurrence_anchor_with_the_self_row_present(&b, &super::suffix())
                        .await
                }
                #[tokio::test]
                async fn i95() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i95_scoped_consent_by_principals(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i96() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i96_consent_peers_by_principals(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i829() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i829_a_deleted_grant_stops_authorising(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i96b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i96b_for_key_id_admission(&b, &super::suffix()).await
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

    /// **I97 — two nodes: the login ceremony's occurrence anchor crosses.**
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i97_login_anchor_crosses_and_the_far_node_walks_to_the_human() {
        use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::{AGENT, USER};
        use crate::federation::FederationDirectory;
        let run = super::run::suffix();
        let mk = |alias: String| async move {
            let e =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            e.register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                None,
                None,
            )
            .await
            .unwrap();
            e
        };
        let (a, b) = (
            mk(format!("i97-a-{run}")).await,
            mk(format!("i97-b-{run}")).await,
        );
        let (sa, sb) = (
            a.sqlite_backend().unwrap().clone(),
            b.sqlite_backend().unwrap().clone(),
        );
        let alice_label = format!("i97-alice-{run}");
        let alice_signer = ts::local_signer(&alice_label);
        // v62.0.0 (JSON cut, E7) — the three keys are edition-2 records on
        // both nodes; the identity the ceremony signs as is alice's
        // identity-ref (E0: `signing_key` follows `local_signer`'s alias).
        let alice = e2::kid(&alice_label);
        let (app_s, agent_s) = (format!("i97-app-{run}"), format!("i97-agent-{run}"));
        let (app, agent) = (e2::kid(&app_s), e2::kid(&agent_s));
        for s in [&sa, &sb] {
            e2::put_key(s.as_ref(), &alice_label, &[USER]).await;
            e2::put_key(s.as_ref(), &app_s, &[USER]).await;
            e2::put_key(s.as_ref(), &agent_s, &[AGENT]).await;
        }
        let keys = || {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let (_x, xp, _m, mp) =
                crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(xp),
                ml_kem_768_base64: B64.encode(mp),
            }
        };
        a.self_at_login(SelfAtLoginInput {
            identity_key_id: alice.clone(),
            identity_signer: Some(alice_signer),
            app: SelfAtLoginOccurrence {
                occurrence_key_id: app.clone(),
                identity_key_id: None,
                occurrence_signer: None,
                transport: None,
                device_class: "phone".into(),
                hardware_attestation: None,
                encryption_pubkeys: Some(keys()),
                transport_destinations: vec![],
            },
            agent: SelfAtLoginOccurrence {
                occurrence_key_id: agent.clone(),
                identity_key_id: None,
                occurrence_signer: None,
                transport: None,
                device_class: "agent".into(),
                hardware_attestation: None,
                encryption_pubkeys: Some(keys()),
                transport_destinations: vec![],
            },
            bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
            delegation_scope: None,
        })
        .await
        .expect("I97: the login ceremony on A");
        assert_eq!(
            crate::federation::admission::steward_bindings_of(sa.as_ref(), &agent)
                .await
                .unwrap(),
            vec![alice.clone()],
            "I97: on A the human stewards the agent"
        );
        let mut crossed = 0;
        for served in crate::federation::key_plane::test_support::served_identity_occurrences(
            sa.as_dyn_directory(),
            1_000,
        )
        .await
        .unwrap()
        {
            if served.occurrence.identity_occurrence.occurrence_key_id == agent {
                sb.put_identity_occurrence(served.occurrence)
                    .await
                    .expect("I97: B admits the agent's occurrence through the gated door");
                crossed += 1;
            }
        }
        assert_eq!(crossed, 1, "I97: the anchor was on the plane");
        assert_eq!(
            crate::federation::admission::steward_bindings_of(sb.as_ref(), &agent)
                .await
                .unwrap(),
            vec![alice.clone()],
            "I97: on B the same human stewards the agent"
        );
        let mut p =
            crate::federation::consent_by_humans::consent_principals_of(sb.as_ref(), &agent)
                .await
                .unwrap();
        p.sort();
        let mut want = vec![agent.clone(), alice];
        want.sort();
        assert_eq!(p, want, "I97: {{agent, human}} on the far node");
    }

    /// **I94 (b) + I98 — from disk.** The three clause-(2) sites use the one
    /// helper; the combine rule is one function every door reaches.
    #[test]
    fn i94b_i98_one_helper_one_rule_every_door() {
        const ADM: &str = include_str!("admission.rs");
        const MODULE: &str = include_str!("consent_by_humans.rs");
        const PYO3: &str = include_str!("../ffi/pyo3.rs");
        // v54.1.0 (#1041) — `steward_bindings_of` is the key set of
        // `steward_binding_paths_of`, which carries the walk's body.
        {
            let body = ADM
                .split("pub async fn steward_bindings_of(")
                .nth(1)
                .expect("steward_bindings_of");
            let body = &body[..body.find("\n}\n").expect("fn end")];
            assert!(
                body.contains("steward_binding_paths_of("),
                "I94 (b): steward_bindings_of is the labelled walk's key set"
            );
        }
        for f in [
            "pub async fn is_steward_bound(",
            "pub async fn steward_binding_paths_of(",
            "pub async fn steward_binding_chain(",
        ] {
            let body = ADM.split(f).nth(1).expect(f);
            let body = &body[..body.find("\n}\n").expect("fn end")];
            assert!(
                body.contains("user_identity_anchors_of("),
                "I94 (b): {f} resolves the occurrence half through the one helper"
            );
            assert!(
                !body.contains("lookup_identity_for_occurrence("),
                "I94 (b): {f} still reads LIMIT 1"
            );
        }
        assert_eq!(
            MODULE.matches("pub fn combine_principal_stances(").count(),
            1
        );
        for (name, text) in [("pyo3.rs", PYO3), ("admission.rs", ADM)] {
            assert!(
                !text.contains("fn combine_principal_stances("),
                "I98: {name} re-defines the combine rule"
            );
        }
        let door = MODULE
            .split("pub async fn resolve_scoped_consent_by_principals")
            .nth(1)
            .unwrap();
        assert!(
            door.contains("combine_principal_stances("),
            "I98: the scoped door calls the rule"
        );
        const ENGINE: &str = include_str!("../engine.rs");
        for f in [
            "consent_peers_by_principals",
            "resolve_scoped_consent_by_principals",
        ] {
            let d = ENGINE.split(&format!("pub async fn {f}(")).nth(1).expect(f);
            let body = &d[..d.find("\n    }\n").expect("end")];
            assert!(
                body.contains(&format!("consent_by_humans::{f}(")),
                "I98: the Engine door `{f}` delegates to the module"
            );
        }
        for f in [
            "consent_peers_by_principals",
            "resolve_scoped_consent_by_principals",
        ] {
            let d = PYO3.split(&format!("    fn {f}(")).nth(1).expect(f);
            let body = &d[..d.find("\n    }\n").expect("end")];
            assert!(
                body.contains(&format!("engine.{f}(")),
                "I98: the PyO3 mirror `{f}` delegates to the Engine"
            );
        }
    }
}
