//! v53.0.0 (CIRISPersist#963 / CIRISEdge#761, CC 3.3.7 / 5.4.6 / 6.1.5.3) —
//! **I390–I399: one audience resolver, per-node cohort allow lists.**
//! Memory, sqlite, postgres (I395's membership-plane fixtures need a SQL
//! backend's reply arm: sqlite, postgres).
//!
//! - **I390** public groups reach every peer; a private group's planes do not.
//! - **I391** a private cohort's audience excludes a non-member's node.
//! - **I392** a revoked occurrence drops the node from its owner's audience.
//! - **I393** the operator's example: an allow list naming `work` keeps
//!   `adulthub` off the work laptop — at the cohort view, the receiver's hold
//!   decision and the sender's set; the owner's phone (no list) keeps both.
//! - **I394** class defaults: a server/agent occurrence gets no `self` or
//!   `family` content but its owner's rooms; a laptop gets everything.
//! - **I395** a live invitee's node receives the private group's planes; a
//!   declined invitation stops it.
//! - **I396** an empty list is explicitly none (self still follows the
//!   class); the grammar and admission refuse malformed lists, a list on a
//!   grant with no `for_key_id`, and a list on a node's grant for itself.
//! - **I397** origin and refers-to: a node receives its own grant and its own
//!   rows whatever its list says; a sibling node does not receive them.
//! - **I398** the receiver's `is_audience` and the cohort's `audience_nodes`
//!   agree on a four-node fixture over every scope (one resolver, both sides).
//! - **I399** several live lists intersect; withdrawing one leaves the other.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::replication_audience as ra;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY, SELF};
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{
        attestation_type, device_class, Community, CommunityMember, Family, FamilyMember,
        IdentityOccurrence, IdentityOccurrenceRevocation, RosterCosignature,
    };
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};
    use chrono::{DateTime, Duration, Utc};

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    fn ago(days: i64) -> DateTime<Utc> {
        ms(Utc::now() - Duration::days(days))
    }

    pub(crate) async fn users(d: &dyn FederationDirectory, keys: &[&str]) {
        for k in keys {
            ts::register_hybrid_key_as(d, k, k, USER).await;
        }
    }

    pub(crate) async fn nodes(d: &dyn FederationDirectory, keys: &[&str]) {
        for k in keys {
            ts::register_hybrid_key_as(d, k, k, NODE).await;
        }
    }

    /// `owner` claims `node` as a device of class `class` (a trusted-local
    /// occurrence: the binding this node produced for its own user).
    async fn claim(d: &dyn FederationDirectory, owner: &str, node: &str, class: &str) {
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: owner.to_owned(),
            occurrence_key_id: node.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: ago(2),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("claim {owner} → {node}: {e}"));
        // a claimed node carries its owner binding too (the send set's NODES)
        d.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(
                &uuid::Uuid::new_v4().to_string(),
                owner,
                node,
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("owner binding {owner} → {node}: {e}"));
    }

    async fn unclaim(d: &dyn FederationDirectory, owner: &str, node: &str) {
        d.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: owner.to_owned(),
            occurrence_key_id: node.to_owned(),
            revoked_at: ago(1),
            effective_at: ago(1),
            reason: None,
            witness_set: vec![owner.to_owned()],
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("unclaim {owner} → {node}: {e}"));
    }

    fn cosign(signer: &str, envelope: &serde_json::Value) -> RosterCosignature {
        let (_h, classical, pqc) = ts::sign_envelope(signer, envelope);
        RosterCosignature {
            authority_key_id: signer.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    pub(crate) async fn room(d: &dyn FederationDirectory, cid: &str, founders: &[&str]) {
        ts::register_identity_key(d, cid, USER).await;
        let c = Community {
            community_key_id: cid.to_owned(),
            community_name: "room".into(),
            members: founders
                .iter()
                .map(|k| CommunityMember {
                    key_id: (*k).to_owned(),
                    joined_at: ago(3),
                    role: Some("founder".into()),
                })
                .collect(),
            founded_at: ago(3),
            consensus_protocol: "founder_only".into(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        let env = c.signing_envelope();
        let mut signed = ts::sign_community(founders[0], c);
        signed.cosignatures = founders[1..].iter().map(|f| cosign(f, &env)).collect();
        d.put_community(signed)
            .await
            .unwrap_or_else(|e| panic!("room {cid}: {e}"));
    }

    pub(crate) async fn family(d: &dyn FederationDirectory, fid: &str, founders: &[&str]) {
        let f = Family {
            family_key_id: fid.to_owned(),
            family_name: "household".into(),
            members: founders
                .iter()
                .map(|k| FamilyMember {
                    key_id: (*k).to_owned(),
                    joined_at: ago(3),
                    role: Some("founder".into()),
                })
                .collect(),
            founded_at: ago(3),
            consensus_protocol: "founder_only".into(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        let env = f.signing_envelope();
        let mut signed = ts::sign_family(founders[0], f);
        signed.cosignatures = founders[1..].iter().map(|k| cosign(k, &env)).collect();
        d.put_family(signed)
            .await
            .unwrap_or_else(|e| panic!("family {fid}: {e}"));
    }

    /// `author`'s `consent:replication` grant FOR `for_key`, with `cohorts`
    /// (raw JSON, so the malformed shapes can be offered too).
    pub(crate) fn grant(
        author: &str,
        for_key: Option<&str>,
        cohorts: Option<serde_json::Value>,
    ) -> Attestation {
        let mut payload = serde_json::json!({
            "grants": "replication",
            "attestation_prefixes": ["i39x:"],
        });
        if let Some(k) = for_key {
            payload["for_key_id"] = k.into();
        }
        if let Some(c) = cohorts {
            payload["cohorts"] = c;
        }
        let env = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": crate::federation::consent_grammar::GRANT_DIMENSION,
            "payload": payload,
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), author, author, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        ts::seal_row_in_place(author, &mut r);
        r
    }

    pub(crate) async fn put(d: &dyn FederationDirectory, a: &Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation {
            attestation: a.clone(),
        })
        .await
        .map(|_| ())
    }

    async fn withdraw(d: &dyn FederationDirectory, author: &str, target: &Attestation) {
        let id = uuid::Uuid::new_v4().to_string();
        let env =
            serde_json::json!({ "id": id, "references_attestation_id": target.attestation_id });
        let mut r = ts::bare_attestation(&id, author, author, &env);
        r.attestation_type = attestation_type::WITHDRAWS.into();
        ts::seal_row_in_place(author, &mut r);
        put(d, &r).await.expect("withdraws admitted");
    }

    pub(crate) fn entries(pairs: &[(&str, &str)]) -> serde_json::Value {
        let mut v: Vec<(String, String)> = pairs
            .iter()
            .map(|(s, t)| ((*s).to_owned(), (*t).to_owned()))
            .collect();
        v.sort();
        serde_json::Value::Array(
            v.into_iter()
                .map(|(s, t)| serde_json::json!({ "scope": s, "target": t }))
                .collect(),
        )
    }

    async fn in_audience(
        d: &dyn FederationDirectory,
        scope: &str,
        target: &str,
        node: &str,
    ) -> bool {
        ra::audience_nodes(d, scope, Some(target))
            .await
            .unwrap()
            .contains(node)
    }

    /// The receiver's decision for content at `scope`/`target` authored by
    /// `author` (no operator family predicate: production never installs one).
    async fn holds(
        d: &dyn FederationDirectory,
        node: &str,
        scope: &str,
        target: Option<&str>,
        author: &str,
    ) -> bool {
        crate::federation::replication::hold::is_audience(d, scope, target, author, |_| false, node)
            .await
            .unwrap()
    }

    /// **I390** — public groups reach every peer; a private group's planes do not.
    pub(crate) async fn i390_public_groups(d: &dyn FederationDirectory, s: &str) {
        let (owner, stranger, cid) = (
            format!("i390-o-{s}"),
            format!("i390-x-{s}"),
            format!("i390-c-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&stranger]).await;
        room(d, &cid, &[&owner]).await;
        let accord = crate::federation::canonical_community::accord_family_key_id();
        assert!(
            ra::is_public_group(d, accord).await.unwrap(),
            "I390 the accord family is public"
        );
        assert_eq!(
            ra::audience_nodes(d, FAMILY, Some(accord)).await.unwrap(),
            ra::Audience::Everyone,
            "I390 a public group's audience is every peer"
        );
        assert!(
            ra::may_receive_group_plane(d, &stranger, FAMILY, accord, None)
                .await
                .unwrap()
                .allowed(),
            "I390 a non-member receives a public group's planes"
        );
        assert!(
            !ra::is_public_group(d, &cid).await.unwrap(),
            "I390 a plain room is private"
        );
        assert_eq!(
            ra::may_receive_group_plane(d, &stranger, COMMUNITY, &cid, None)
                .await
                .unwrap(),
            ra::Verdict::No(ra::Reason::NotInAudience),
            "I390 a non-member does not receive a private room's planes"
        );
        assert!(
            ra::may_receive_group_plane(d, &stranger, COMMUNITY, &cid, Some(&stranger))
                .await
                .unwrap()
                .allowed(),
            "I390 the member a row names receives it (a revocation reaches the removed)"
        );
    }

    /// **I391** — a private cohort's audience excludes a non-member's node.
    pub(crate) async fn i391_private_excludes_non_members(d: &dyn FederationDirectory, s: &str) {
        let (owner, other, laptop, cid) = (
            format!("i391-o-{s}"),
            format!("i391-y-{s}"),
            format!("i391-l-{s}"),
            format!("i391-c-{s}"),
        );
        users(d, &[&owner, &other]).await;
        nodes(d, &[&laptop]).await;
        claim(d, &other, &laptop, device_class::LAPTOP).await;
        room(d, &cid, &[&owner]).await;
        assert!(
            !in_audience(d, COMMUNITY, &cid, &laptop).await,
            "I391 a non-member's laptop is outside"
        );
        assert!(
            !holds(d, &laptop, COMMUNITY, Some(&cid), &owner).await,
            "I391 and does not hold it"
        );
    }

    /// **I392** — a revoked occurrence drops the node.
    pub(crate) async fn i392_revoked_occurrence_drops_the_node(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner, laptop, cid) = (
            format!("i392-o-{s}"),
            format!("i392-l-{s}"),
            format!("i392-c-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop]).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        room(d, &cid, &[&owner]).await;
        assert!(
            in_audience(d, COMMUNITY, &cid, &laptop).await,
            "I392 precondition — the claimed laptop is in"
        );
        unclaim(d, &owner, &laptop).await;
        assert!(
            !in_audience(d, COMMUNITY, &cid, &laptop).await,
            "I392 the unclaimed laptop is out"
        );
        assert!(
            !holds(d, &laptop, COMMUNITY, Some(&cid), &owner).await,
            "I392 and holds nothing of the room"
        );
    }

    /// **I393** — the operator's example: adulthub stays off the work laptop.
    pub(crate) async fn i393_allow_list_keeps_a_room_off_a_node(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner, laptop, phone, adult, work, fam) = (
            format!("i393-o-{s}"),
            format!("i393-l-{s}"),
            format!("i393-p-{s}"),
            format!("i393-adulthub-{s}"),
            format!("i393-work-{s}"),
            format!("i393-f-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &phone]).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        claim(d, &owner, &phone, device_class::PHONE).await;
        room(d, &adult, &[&owner]).await;
        room(d, &work, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        put(
            d,
            &grant(&owner, Some(&laptop), Some(entries(&[(COMMUNITY, &work)]))),
        )
        .await
        .expect("I393 the owner's grant for the work laptop is admitted");
        // the cohort view
        assert!(
            in_audience(d, COMMUNITY, &work, &laptop).await,
            "I393 work reaches the work laptop"
        );
        assert!(
            !in_audience(d, COMMUNITY, &adult, &laptop).await,
            "I393 adulthub does not"
        );
        assert!(
            !in_audience(d, FAMILY, &fam, &laptop).await,
            "I393 an unlisted family does not either"
        );
        assert!(
            in_audience(d, COMMUNITY, &adult, &phone).await,
            "I393 the phone (no list) keeps adulthub"
        );
        // the receiver
        assert!(
            !holds(d, &laptop, COMMUNITY, Some(&adult), &owner).await,
            "I393 the laptop holds no adulthub row"
        );
        assert!(
            holds(d, &laptop, COMMUNITY, Some(&work), &owner).await,
            "I393 it holds work rows"
        );
        assert!(
            holds(d, &phone, COMMUNITY, Some(&adult), &owner).await,
            "I393 the phone holds adulthub rows"
        );
        assert!(
            !holds(d, &laptop, FAMILY, Some(&fam), &owner).await,
            "I393 the laptop holds no family row"
        );
        assert!(
            holds(d, &laptop, SELF, None, &owner).await,
            "I393 self follows the class (laptop: yes)"
        );
        // the sender
        let sent = crate::federation::self_collective::send_set_for(d, &owner, FAMILY)
            .await
            .unwrap();
        assert!(
            !sent.contains(&laptop) && sent.contains(&phone),
            "I393 the family send set skips the laptop: {sent:?}"
        );
    }

    /// **I394** — class defaults.
    pub(crate) async fn i394_class_defaults(d: &dyn FederationDirectory, s: &str) {
        let (owner, server, agent, laptop, cid, fam) = (
            format!("i394-o-{s}"),
            format!("i394-s-{s}"),
            format!("i394-a-{s}"),
            format!("i394-l-{s}"),
            format!("i394-c-{s}"),
            format!("i394-f-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&server, &agent, &laptop]).await;
        claim(d, &owner, &server, device_class::SERVER).await;
        claim(d, &owner, &agent, device_class::AGENT).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        room(d, &cid, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        for n in [&server, &agent] {
            assert!(
                !holds(d, n, SELF, None, &owner).await,
                "I394 a server-class node holds no self content"
            );
            assert!(
                !holds(d, n, FAMILY, Some(&fam), &owner).await,
                "I394 nor family content"
            );
            assert!(
                holds(d, n, COMMUNITY, Some(&cid), &owner).await,
                "I394 but its owner's rooms"
            );
            assert!(
                !in_audience(d, SELF, &owner, n).await,
                "I394 the self audience skips it"
            );
        }
        assert!(
            holds(d, &laptop, SELF, None, &owner).await,
            "I394 a laptop holds self content"
        );
        assert!(
            holds(d, &laptop, FAMILY, Some(&fam), &owner).await,
            "I394 and family content"
        );
        assert!(
            in_audience(d, SELF, &owner, &laptop).await,
            "I394 the self audience has the laptop"
        );
        // a server named in the list receives that family
        put(
            d,
            &grant(&owner, Some(&server), Some(entries(&[(FAMILY, &fam)]))),
        )
        .await
        .unwrap();
        assert!(
            holds(d, &server, FAMILY, Some(&fam), &owner).await,
            "I394 a listed family reaches the server"
        );
        assert!(
            !holds(d, &server, SELF, None, &owner).await,
            "I394 self is never listed: still none"
        );
        assert!(
            !holds(d, &server, COMMUNITY, Some(&cid), &owner).await,
            "I394 the list is exact: the room is now off"
        );
    }

    /// **I395** — a live invitee's node receives the private group's planes.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i395_live_invitee_receives_the_planes(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance_invariants::bodies as ma;
        let (cid, founder, k, knode) = (
            format!("i395-c-{s}"),
            format!("i395-f-{s}"),
            format!("i395-k-{s}"),
            format!("i395-n-{s}"),
        );
        ma::reg(d, &[&cid, &founder, &k]).await;
        nodes(d, &[&knode]).await;
        claim(d, &k, &knode, device_class::PHONE).await;
        ma::found_community(d, &cid, "founder_only", &[&founder], &[])
            .await
            .unwrap();
        assert!(
            !ra::may_receive_group_plane(d, &knode, COMMUNITY, &cid, None)
                .await
                .unwrap()
                .allowed(),
            "I395 precondition — before the invitation K's node is outside"
        );
        let now = Utc::now();
        let p = ma::proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        ma::put(d, &p).await.unwrap();
        assert!(
            ra::may_receive_group_plane(d, &knode, COMMUNITY, &cid, None)
                .await
                .unwrap()
                .allowed(),
            "I395 a live invitee's node receives the planes (full history)"
        );
        ma::put(d, &ma::reply(&k, &k, &p, false, now))
            .await
            .unwrap();
        assert!(
            !ra::may_receive_group_plane(d, &knode, COMMUNITY, &cid, None)
                .await
                .unwrap()
                .allowed(),
            "I395 a declined invitation is not live"
        );
    }

    /// **I396** — empty = explicitly none; malformed lists are refused.
    pub(crate) async fn i396_empty_list_and_refusals(d: &dyn FederationDirectory, s: &str) {
        let (owner, laptop, cid) = (
            format!("i396-o-{s}"),
            format!("i396-l-{s}"),
            format!("i396-c-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop]).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        room(d, &cid, &[&owner]).await;
        put(
            d,
            &grant(&owner, Some(&laptop), Some(serde_json::json!([]))),
        )
        .await
        .unwrap();
        assert!(
            !holds(d, &laptop, COMMUNITY, Some(&cid), &owner).await,
            "I396 [] is explicitly none"
        );
        assert!(
            holds(d, &laptop, SELF, None, &owner).await,
            "I396 self still follows the class"
        );
        let bad = [
            (
                "unsorted",
                serde_json::json!([{"scope":"community","target":"b"},{"scope":"community","target":"a"}]),
            ),
            (
                "duplicate",
                serde_json::json!([{"scope":"family","target":"a"},{"scope":"family","target":"a"}]),
            ),
            (
                "self listed",
                serde_json::json!([{"scope":"self","target":"a"}]),
            ),
            (
                "empty target",
                serde_json::json!([{"scope":"family","target":""}]),
            ),
            (
                "unknown member",
                serde_json::json!([{"scope":"family","target":"a","x":1}]),
            ),
        ];
        for (why, c) in bad {
            assert!(
                put(d, &grant(&owner, Some(&laptop), Some(c)))
                    .await
                    .is_err(),
                "I396 refused: {why}"
            );
        }
        assert!(
            put(d, &grant(&owner, None, Some(entries(&[(COMMUNITY, &cid)]))))
                .await
                .is_err(),
            "I396 a list on a grant naming no node is refused"
        );
        let e = put(
            d,
            &grant(&laptop, Some(&laptop), Some(entries(&[(COMMUNITY, &cid)]))),
        )
        .await
        .expect_err("I396 a node's grant for itself carries no list");
        assert!(
            e.to_string().contains("consent_cohorts_not_owner_grant"),
            "I396 {e}"
        );
    }

    /// **I397** — origin and refers-to reach the node whatever its list says.
    pub(crate) async fn i397_origin_and_refers_to(d: &dyn FederationDirectory, s: &str) {
        let (owner, laptop, sibling) = (
            format!("i397-o-{s}"),
            format!("i397-l-{s}"),
            format!("i397-s-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &sibling]).await;
        claim(d, &owner, &laptop, device_class::SERVER).await;
        claim(d, &owner, &sibling, device_class::SERVER).await;
        let g = grant(&owner, Some(&laptop), Some(serde_json::json!([])));
        put(d, &g).await.unwrap();
        assert_eq!(
            ra::may_receive(d, &laptop, &g).await.unwrap(),
            ra::Verdict::Yes(ra::Reason::RefersTo),
            "I397 the node receives the grant FOR it"
        );
        assert!(
            !ra::may_receive(d, &sibling, &g).await.unwrap().allowed(),
            "I397 a sibling node does not"
        );
        let mut own = ts::bare_attestation("i397-own", &laptop, &laptop, &serde_json::json!({}));
        own.cohort_scope = SELF.into();
        assert_eq!(
            ra::may_receive(d, &laptop, &own).await.unwrap(),
            ra::Verdict::Yes(ra::Reason::Origin),
            "I397 a row the node signed reaches it"
        );
    }

    /// **I398** — the receiver and the cohort view agree, four nodes × scopes.
    pub(crate) async fn i398_receiver_agrees_with_the_cohort_view(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner, other, cid, fam) = (
            format!("i398-o-{s}"),
            format!("i398-y-{s}"),
            format!("i398-c-{s}"),
            format!("i398-f-{s}"),
        );
        let ns: Vec<String> = (0..4).map(|i| format!("i398-n{i}-{s}")).collect();
        users(d, &[&owner, &other]).await;
        nodes(d, &ns.iter().map(String::as_str).collect::<Vec<_>>()).await;
        claim(d, &owner, &ns[0], device_class::LAPTOP).await;
        claim(d, &owner, &ns[1], device_class::SERVER).await;
        claim(d, &owner, &ns[2], device_class::PHONE).await;
        claim(d, &other, &ns[3], device_class::LAPTOP).await;
        room(d, &cid, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        put(
            d,
            &grant(&owner, Some(&ns[2]), Some(entries(&[(FAMILY, &fam)]))),
        )
        .await
        .unwrap();
        for n in &ns {
            for (scope, target) in [
                (SELF, owner.as_str()),
                (FAMILY, fam.as_str()),
                (COMMUNITY, cid.as_str()),
            ] {
                let t = (scope != SELF).then_some(target);
                assert_eq!(
                    holds(d, n, scope, t, &owner).await,
                    in_audience(d, scope, target, n).await,
                    "I398 {n} at {scope}: the receiver and the cohort view disagree"
                );
            }
        }
    }

    /// **I399** — live lists intersect; withdrawing one leaves the other.
    pub(crate) async fn i399_lists_intersect_until_withdrawn(d: &dyn FederationDirectory, s: &str) {
        let (owner, laptop, a, b) = (
            format!("i399-o-{s}"),
            format!("i399-l-{s}"),
            format!("i399-a-{s}"),
            format!("i399-b-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop]).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        room(d, &a, &[&owner]).await;
        room(d, &b, &[&owner]).await;
        let wide = grant(
            &owner,
            Some(&laptop),
            Some(entries(&[(COMMUNITY, &a), (COMMUNITY, &b)])),
        );
        put(d, &wide).await.unwrap();
        let narrow = grant(&owner, Some(&laptop), Some(entries(&[(COMMUNITY, &a)])));
        put(d, &narrow).await.unwrap();
        assert!(
            holds(d, &laptop, COMMUNITY, Some(&a), &owner).await,
            "I399 a is in both lists"
        );
        assert!(
            !holds(d, &laptop, COMMUNITY, Some(&b), &owner).await,
            "I399 a live narrowing holds"
        );
        withdraw(d, &owner, &narrow).await;
        assert!(
            holds(d, &laptop, COMMUNITY, Some(&b), &owner).await,
            "I399 withdrawn, the wider list governs"
        );
        withdraw(d, &owner, &wide).await;
        assert!(
            holds(d, &laptop, COMMUNITY, Some(&b), &owner).await,
            "I399 no list: the laptop default (all)"
        );
    }
}

/// The KEY half (coordinator ruling on #963): a node denied a cohort's
/// content gets no key for it. SQL backends (the cascades need blob storage).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod key_bodies {
    use super::bodies::{entries, family, grant, nodes, put, room, users};
    use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY, SELF};
    use crate::federation::types::{device_class, IdentityOccurrence};
    use crate::federation::{BlobStorage, FederationDirectory, SignedAttestation};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    /// `owner` claims `node` (class `class`) with real content-KEM keys, and
    /// binds it as its owner.
    async fn keyed_claim<B>(b: &B, owner: &str, node: &str, class: &str)
    where
        B: FederationDirectory + Sync,
    {
        let (_xp, x_pub, _mp, ml_pub) =
            crate::federation::identity_aggregate::mint_content_kem_keypair().expect("kem");
        b.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: owner.to_owned(),
            occurrence_key_id: node.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now() - chrono::Duration::days(2),
            valid_until: None,
            encryption_pubkeys: Some(crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(&ml_pub),
            }),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("keyed claim {owner} → {node}: {e}"));
        b.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(
                &uuid::Uuid::new_v4().to_string(),
                owner,
                node,
            ),
        })
        .await
        .unwrap();
    }

    async fn minter<B: FederationDirectory + Sync>(b: &B, s: &str) -> String {
        crate::federation::at_rest_cascade::blob_invariants::node_signer(b, &format!("mint-{s}"))
            .await
            .derived_key_id()
    }

    async fn self_family_granted<B>(b: &B, scope: &str, group: &str) -> Vec<String>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        encrypt_and_cascade(b, scope, group, b"i39x content", None, None, None)
            .await
            .unwrap_or_else(|e| panic!("seal at {scope}: {e}"))
            .granted
    }

    /// The room epoch a seal used, and that epoch's wrap recipients.
    async fn room_epoch<B>(b: &B, cid: &str, minter: &str) -> (u64, Vec<String>)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let r = encrypt_and_cascade_community(b, cid, b"i39x room", None, Some(minter))
            .await
            .unwrap_or_else(|e| panic!("seal in {cid}: {e}"));
        let rec = b
            .community_dek_member_grant_recipients(cid, &r.minter_key_id, r.epoch)
            .await
            .unwrap();
        (r.epoch, rec)
    }

    /// **I393b** — the denied laptop gets no key for the room or the family it
    /// is denied; the phone with no list gets both; self still reaches it.
    pub(crate) async fn i393b_a_denied_node_gets_no_key<B>(b: &B, s: &str)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let (owner, laptop, phone, adult, work, fam) = (
            format!("i393b-o-{s}"),
            format!("i393b-l-{s}"),
            format!("i393b-p-{s}"),
            format!("i393b-adulthub-{s}"),
            format!("i393b-work-{s}"),
            format!("i393b-f-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &phone]).await;
        keyed_claim(b, &owner, &laptop, device_class::LAPTOP).await;
        keyed_claim(b, &owner, &phone, device_class::PHONE).await;
        room(d, &adult, &[&owner]).await;
        room(d, &work, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        put(
            d,
            &grant(&owner, Some(&laptop), Some(entries(&[(COMMUNITY, &work)]))),
        )
        .await
        .unwrap();
        let fg = self_family_granted(b, FAMILY, &fam).await;
        assert!(
            fg.contains(&phone) && !fg.contains(&laptop),
            "I393b family wraps: {fg:?}"
        );
        let sg = self_family_granted(b, SELF, &owner).await;
        assert!(
            sg.contains(&phone) && sg.contains(&laptop),
            "I393b self follows the class: {sg:?}"
        );
        let m = minter(b, s).await;
        let (_, ar) = room_epoch(b, &adult, &m).await;
        assert!(
            ar.contains(&phone) && !ar.contains(&laptop),
            "I393b adulthub's epoch key: {ar:?}"
        );
        let (_, wr) = room_epoch(b, &work, &m).await;
        assert!(
            wr.contains(&laptop),
            "I393b the listed room's key reaches the laptop: {wr:?}"
        );
    }

    /// **I394b** — a server-class agent and server get no self or family key,
    /// but do get their owner's room key (CC 3.3.7).
    pub(crate) async fn i394b_server_class_keys<B>(b: &B, s: &str)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let (owner, agent, server, laptop, cid, fam) = (
            format!("i394b-o-{s}"),
            format!("i394b-a-{s}"),
            format!("i394b-s-{s}"),
            format!("i394b-l-{s}"),
            format!("i394b-c-{s}"),
            format!("i394b-f-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&agent, &server, &laptop]).await;
        keyed_claim(b, &owner, &agent, device_class::AGENT).await;
        keyed_claim(b, &owner, &server, device_class::SERVER).await;
        keyed_claim(b, &owner, &laptop, device_class::LAPTOP).await;
        room(d, &cid, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        for (scope, group) in [(SELF, owner.as_str()), (FAMILY, fam.as_str())] {
            let g = self_family_granted(b, scope, group).await;
            assert!(
                g.contains(&laptop) && !g.contains(&agent) && !g.contains(&server),
                "I394b {scope}: no key for the server class: {g:?}"
            );
        }
        let (_, r) = room_epoch(b, &cid, &minter(b, s).await).await;
        assert!(
            r.contains(&agent) && r.contains(&server) && r.contains(&laptop),
            "I394b the room key reaches every class: {r:?}"
        );
    }

    /// **I392c** — a deny added later: the next seal rotates the room's
    /// epoch, and the new epoch's key does not reach the denied laptop.
    pub(crate) async fn i392c_a_later_deny_rotates_the_room_epoch<B>(b: &B, s: &str)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let (owner, laptop, phone, cid) = (
            format!("i392c-o-{s}"),
            format!("i392c-l-{s}"),
            format!("i392c-p-{s}"),
            format!("i392c-c-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &phone]).await;
        keyed_claim(b, &owner, &laptop, device_class::LAPTOP).await;
        keyed_claim(b, &owner, &phone, device_class::PHONE).await;
        room(d, &cid, &[&owner]).await;
        let m = minter(b, s).await;
        let (e0, r0) = room_epoch(b, &cid, &m).await;
        assert!(
            r0.contains(&laptop),
            "I392c precondition — the laptop holds e{e0}"
        );
        put(
            d,
            &grant(&owner, Some(&laptop), Some(serde_json::json!([]))),
        )
        .await
        .unwrap();
        let (e1, r1) = room_epoch(b, &cid, &m).await;
        assert!(e1 > e0, "I392c the deny rotated the epoch: e{e0} → e{e1}");
        assert!(
            !r1.contains(&laptop) && r1.contains(&phone),
            "I392c the new epoch's key skips the denied laptop: {r1:?}"
        );
        let again = encrypt_and_cascade_community(b, &cid, b"i392c steady", None, Some(&m))
            .await
            .unwrap();
        assert_eq!(
            again.epoch, e1,
            "I392c no further rotation once the set is steady"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr, [$($extra:ident),*]) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! case {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(&d as &dyn FederationDirectory, &suffix()).await
                        }
                    };
                }
                case!(i390_public_groups);
                case!(i391_private_excludes_non_members);
                case!(i392_revoked_occurrence_drops_the_node);
                case!(i393_allow_list_keeps_a_room_off_a_node);
                case!(i394_class_defaults);
                case!(i396_empty_list_and_refusals);
                case!(i397_origin_and_refers_to);
                case!(i398_receiver_agrees_with_the_cohort_view);
                case!(i399_lists_intersect_until_withdrawn);
                $(case!($extra);)*
            }
        };
    }

    dyn_runners!(
        memory,
        async { Some(crate::store::memory::MemoryBackend::new()) },
        []
    );

    #[cfg(feature = "sqlite")]
    dyn_runners!(
        sqlite,
        async {
            use crate::store::Backend as _;
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        },
        [i395_live_invitee_receives_the_planes]
    );

    #[cfg(feature = "postgres")]
    dyn_runners!(
        postgres,
        async {
            use crate::store::Backend as _;
            let dsn = crate::test_pg::empty_dsn()?;
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        },
        [i395_live_invitee_receives_the_planes]
    );
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod key_runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! key_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                macro_rules! case {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(b) = $fresh.await else { return };
                            crate::federation::replication_audience_invariants::key_bodies::$name(
                                &b,
                                &suffix(),
                            )
                            .await
                        }
                    };
                }
                case!(i393b_a_denied_node_gets_no_key);
                case!(i394b_server_class_keys);
                case!(i392c_a_later_deny_rotates_the_room_epoch);
            }
        };
    }

    #[cfg(feature = "sqlite")]
    key_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    key_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
