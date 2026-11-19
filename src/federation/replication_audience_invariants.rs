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
//! - **I394** class defaults: a server-class node gets no `self` or `family`
//!   content but its owner's rooms; an OWNED agent gets `self` and the rooms
//!   but no `family` (v62, P5c update 4); a laptop gets everything.
//! - **I395** a live invitee's node receives the private group's planes; a
//!   declined invitation stops it.
//! - **I396** an empty list is explicitly none, `self` included (v62, P5c
//!   update 5: a present list without the literal `"self"` entry excludes
//!   `self` for every class); the grammar and admission refuse malformed lists, a list on a
//!   grant with no `for_key_id`, and a list on a node's grant for itself.
//! - **I397** origin and refers-to: a node receives its own grant and its own
//!   rows whatever its list says; a sibling node does not receive them.
//! - **I398** the receiver's `is_audience` and the cohort's `audience_nodes`
//!   agree on a four-node fixture over every scope (one resolver, both sides).
//! - **I399** several live lists intersect; withdrawing one leaves the other.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    /// v62 (E3): an id as the edition-2 rows carry it: a seed becomes its
    /// identity-ref (`kid_or_keep`; an identity-ref, a 64-hex row id or a
    /// `canonical:` / `sha256:` name is kept). Inside `with_earlier_form_async`
    /// (earlier-form fixtures) the seed is kept as it is.
    pub(crate) fn kr(s: &str) -> String {
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            crate::federation::edition2::fixture_switch::kid_or_keep(s)
        } else {
            s.to_owned()
        }
    }
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

    /// The owner bindings `claim` put under edition 2, by `(owner, node)`, so
    /// `unclaim` can withdraw the exact row (its id is node-computed).
    fn claimed(
    ) -> &'static std::sync::Mutex<std::collections::HashMap<(String, String), Attestation>> {
        static CLAIMED: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<(String, String), Attestation>>,
        > = std::sync::OnceLock::new();
        CLAIMED.get_or_init(Default::default)
    }

    /// `owner` owns `node`.
    ///
    /// v62 (E3; O1.api v3, the person/machine exclusion): a node is never
    /// bound under a person's key as a device, on any path, so there is no
    /// occurrence here. Under edition 2:
    /// - the node is node-bearing by its own `key:record` (`put_key(node, [node])`);
    /// - the person owns it through an OWNER BINDING
    ///   (`ownership:{relation}:node`): the owner's statement, then the
    ///   node's own voice (C557).
    ///
    /// `class` is the node's own self-occurrence's `device_class` (P5c update
    /// 1); the owner binding carries no class.
    /// Seeds in; the rows carry `kid(seed)`.
    pub(crate) async fn claim(d: &dyn FederationDirectory, owner: &str, node: &str, class: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        if !e2::emit_edition2() {
            return claim_earlier(d, owner, node, class).await;
        }
        claim_with(d, owner, node, class, &e2::BindOptions::default()).await
    }

    /// v62 (E3b) — `claim` under edition 2, with the self-occurrence's
    /// further members in `opts` (`encryption_pubkeys` for a node that must
    /// be able to hold keys: `key_bodies::keyed_claim`).
    ///
    /// The binding is re-dated now − 5 min and resealed by the owner: the
    /// builder's fixed instant (2026-05-01) lies before a node key's default
    /// record window (180 days back), so the node's voice over it would not
    /// be live (E13's `bind_on`, the same fix). Node-signed rows are
    /// now-relative.
    pub(crate) async fn claim_with(
        d: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        class: &str,
        opts: &crate::federation::edition2::fixture_switch::BindOptions,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        e2::put_key(d, node, &[NODE]).await;
        let mut binding =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), owner, &e2::kid(node));
        binding.asserted_at = ms(Utc::now() - Duration::minutes(5));
        binding.scrub_timestamp = binding.asserted_at;
        ts::seal_row_in_place(owner, &mut binding);
        // K2.api: the shared landing (owner's statement, then the node's
        // voice; asserts Row).
        ts::put_sealed_owner_binding(d, &binding, node)
            .await
            .unwrap_or_else(|e| panic!("owner binding {owner} → {node}: {e}"));
        // P5c (update 1): the owner binding says WHO the human is; WHAT KIND
        // of device the node is comes from its own self-occurrence (O1's
        // edition-2 self pair: identity = occurrence = the node key).
        e2::put_bind(d, node, node, node, class, opts)
            .await
            .unwrap_or_else(|e| panic!("{node}'s self-occurrence as {class}: {e}"));
        claimed()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((owner.to_owned(), node.to_owned()), binding);
    }

    /// `owner` disowns `node`: under edition 2, the owner's `withdraws` of the
    /// owner binding `claim` put (the target's family, `refs.target`).
    async fn unclaim(d: &dyn FederationDirectory, owner: &str, node: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        if !e2::emit_edition2() {
            return unclaim_earlier(d, owner, node).await;
        }
        let binding = claimed()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(owner.to_owned(), node.to_owned()))
            .cloned()
            .unwrap_or_else(|| panic!("unclaim {owner} → {node}: never claimed"));
        let w = e2::composer_of("withdraws", &binding, owner);
        e2::put_signed(d, &w)
            .await
            .unwrap_or_else(|e| panic!("unclaim {owner} → {node}: {e}"));
    }

    async fn claim_earlier(d: &dyn FederationDirectory, owner: &str, node: &str, class: &str) {
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

    async fn unclaim_earlier(d: &dyn FederationDirectory, owner: &str, node: &str) {
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
            consensus_protocol: "quorum:1/1".into(),
            policy_blob: None,
            persist_row_hash: String::new(),
            prev_head_digest: String::new(),
            charter_digest: String::new(),
        };
        let env = c.signing_envelope();
        let mut signed = ts::sign_community(founders[0], c);
        signed.cosignatures = founders[1..].iter().map(|f| cosign(f, &env)).collect();
        // v62 (E3): switch-aware. Under edition 2 the founding roster is the
        // founders' `group:roster` voices (T1); ids go in as seeds and are
        // stored as `kid(seed)`. Under `with_earlier_form_async` it stays the
        // earlier typed put.
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            let voices = crate::federation::edition2::fixture_switch::community_voices(
                &signed,
                1,
                None,
                crate::federation::edition2::fixture_switch::ms(chrono::Utc::now()),
            );
            crate::federation::edition2::fixture_switch::put_voices(d, &voices)
                .await
                .unwrap_or_else(|e| panic!("room {cid}: {e}"));
        } else {
            d.put_community(signed)
                .await
                .unwrap_or_else(|e| panic!("room {cid}: {e}"));
        }
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
            prev_head_digest: String::new(),
            charter_digest: String::new(),
        };
        let env = f.signing_envelope();
        let mut signed = ts::sign_family(founders[0], f);
        signed.cosignatures = founders[1..].iter().map(|k| cosign(k, &env)).collect();
        // v62 (E3): switch-aware, as `room`.
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            let voices = crate::federation::edition2::fixture_switch::family_voices(
                &signed,
                1,
                None,
                crate::federation::edition2::fixture_switch::ms(chrono::Utc::now()),
            );
            crate::federation::edition2::fixture_switch::put_voices(d, &voices)
                .await
                .unwrap_or_else(|e| panic!("family {fid}: {e}"));
        } else {
            d.put_family(signed)
                .await
                .unwrap_or_else(|e| panic!("family {fid}: {e}"));
        }
    }

    /// `author`'s `consent:replication` grant FOR `for_key`, with `cohorts`
    /// (raw JSON, so the malformed shapes can be offered too).
    fn grant_unsealed(
        author: &str,
        for_key: Option<&str>,
        cohorts: Option<serde_json::Value>,
    ) -> Attestation {
        let mut payload = serde_json::json!({
            "grants": "replication",
            "attestation_prefixes": ["i39x:"],
        });
        if let Some(k) = for_key {
            payload["for_key_id"] = kr(k).into();
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
        r
    }

    /// `author`'s `consent:replication` grant, sealed (a row the door admits).
    pub(crate) fn grant(
        author: &str,
        for_key: Option<&str>,
        cohorts: Option<serde_json::Value>,
    ) -> Attestation {
        let mut r = grant_unsealed(author, for_key, cohorts);
        ts::seal_row_in_place(author, &mut r);
        r
    }

    /// v62 (E3): offer a grant that the door may REFUSE (a malformed
    /// `cohorts` list, a list on the wrong grant). Sealing through the fixture
    /// (`seal_row_in_place`) admits the row and panics on a refusal, so the
    /// statement is signed without admitting and handed to the door, whose
    /// refusal comes back as the `Err`. Under the earlier form it is the
    /// earlier put. "Malformed is a refusal": a codec failure here is a
    /// fixture bug, so it panics naming the payload.
    pub(crate) async fn try_put_grant(
        d: &dyn FederationDirectory,
        author: &str,
        for_key: Option<&str>,
        cohorts: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        use crate::federation::edition2::fixture_switch as e2;
        if !e2::emit_edition2() {
            return put(d, &grant(author, for_key, cohorts)).await;
        }
        let r = grant_unsealed(author, for_key, cohorts);
        let st = e2::try_statement_of(&r, author).unwrap_or_else(|e| {
            panic!(
                "the codec cannot state this grant ({e}): {}",
                r.attestation_envelope
            )
        });
        e2::put_statement(d, &st).await.map(|_| ())
    }

    pub(crate) async fn put(d: &dyn FederationDirectory, a: &Attestation) -> Result<(), Error> {
        // v62 (E3): a flipped row goes through the one statement door
        // (E0: `put_attestation` does not route a carried statement).
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            return crate::federation::edition2::fixture_switch::put_signed(d, a)
                .await
                .map(|_| ());
        }
        d.put_attestation(SignedAttestation {
            attestation: a.clone(),
        })
        .await
        .map(|_| ())
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn withdraw_pub(
        d: &dyn FederationDirectory,
        author: &str,
        target: &Attestation,
    ) {
        withdraw(d, author, target).await
    }

    /// v62 (E3): an edition-2 composer carrying the target's family.
    async fn withdraw(d: &dyn FederationDirectory, author: &str, target: &Attestation) {
        let r =
            crate::federation::edition2::fixture_switch::composer_of("withdraws", target, author);
        put(d, &r).await.expect("withdraws admitted");
    }

    pub(crate) fn entries(pairs: &[(&str, &str)]) -> serde_json::Value {
        let mut v: Vec<(String, String)> = pairs
            .iter()
            .map(|(s, t)| ((*s).to_owned(), kr(t)))
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
        ra::audience_nodes(d, scope, Some(&*kr(target)))
            .await
            .unwrap()
            .contains(&kr(node))
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
        crate::federation::replication::hold::is_audience(
            d,
            scope,
            target.map(kr).as_deref(),
            &kr(author),
            |_| false,
            &kr(node),
        )
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
        // v62 (E3, ruling 1): the accord family record is gone (bundle/2);
        // its public-group legs are deleted.
        assert!(
            !ra::is_public_group(d, &kr(&cid)).await.unwrap(),
            "I390 a plain room is private"
        );
        assert_eq!(
            ra::may_receive_group_plane(d, &kr(&stranger), COMMUNITY, &kr(&cid), None)
                .await
                .unwrap(),
            ra::Verdict::No(ra::Reason::NotInAudience),
            "I390 a non-member does not receive a private room's planes"
        );
        assert!(
            ra::may_receive_group_plane(
                d,
                &kr(&stranger),
                COMMUNITY,
                &kr(&cid),
                Some(&*kr(&stranger))
            )
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
        let (owner, laptop, bare, phone, adult, work, fam) = (
            format!("i393-o-{s}"),
            format!("i393-l-{s}"),
            format!("i393-bare-{s}"),
            format!("i393-p-{s}"),
            format!("i393-adulthub-{s}"),
            format!("i393-work-{s}"),
            format!("i393-f-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &bare, &phone]).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        claim(d, &owner, &bare, device_class::LAPTOP).await;
        claim(d, &owner, &phone, device_class::PHONE).await;
        room(d, &adult, &[&owner]).await;
        room(d, &work, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        // v62 (P5c update 5, CC rc21 3.3.7): a present list carries `self`
        // only through the literal `"self"` entry, sorted after the group
        // entries. The work laptop's list names `work` and `self`; the `bare`
        // laptop's names `work` alone.
        let mut work_and_self = entries(&[(COMMUNITY, &work)]);
        work_and_self
            .as_array_mut()
            .expect("entries is an array")
            .push(serde_json::Value::String("self".into()));
        put(d, &grant(&owner, Some(&laptop), Some(work_and_self)))
            .await
            .expect("I393 the owner's grant for the work laptop is admitted");
        put(
            d,
            &grant(&owner, Some(&bare), Some(entries(&[(COMMUNITY, &work)]))),
        )
        .await
        .expect("I393 the owner's grant for the bare laptop is admitted");
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
        // v62 (P5c update 5, CC rc21 6.1 / 3.3.7): one rule for `self` —
        // a present allow list carries `self` iff it names the literal
        // `"self"` entry, for every class.
        assert!(
            holds(d, &laptop, SELF, None, &owner).await,
            "I393 a list naming \"self\" keeps self (work laptop: yes)"
        );
        assert!(
            !holds(d, &bare, SELF, None, &owner).await,
            "I393 a list without \"self\" excludes self (bare laptop: no)"
        );
        assert!(
            holds(d, &bare, COMMUNITY, Some(&work), &owner).await
                && !holds(d, &bare, COMMUNITY, Some(&adult), &owner).await,
            "I393 the bare laptop's group entries still rule its rooms"
        );
        // the sender
        let sent = crate::federation::self_collective::send_set_for(d, &kr(&owner), FAMILY)
            .await
            .unwrap();
        assert!(
            !sent.contains(&kr(&laptop)) && sent.contains(&kr(&phone)),
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
        // v62 (P5c update 4): an `agent`-class device its owner OWNS is
        // `OwnedAgent` — within the owner's `self` (no list), no `family` by
        // default, the rooms. The server class gets no `self`.
        for (n, gets_self) in [(&server, false), (&agent, true)] {
            assert_eq!(
                holds(d, n, SELF, None, &owner).await,
                gets_self,
                "I394 self content: server no, owned agent yes ({n})"
            );
            assert!(
                !holds(d, n, FAMILY, Some(&fam), &owner).await,
                "I394 no family content ({n})"
            );
            assert!(
                holds(d, n, COMMUNITY, Some(&cid), &owner).await,
                "I394 but its owner's rooms ({n})"
            );
            assert_eq!(
                in_audience(d, SELF, &owner, n).await,
                gets_self,
                "I394 the self audience: server no, owned agent yes ({n})"
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
        ma::found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        assert!(
            !ra::may_receive_group_plane(d, &kr(&knode), COMMUNITY, &kr(&cid), None)
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
            ra::may_receive_group_plane(d, &kr(&knode), COMMUNITY, &kr(&cid), None)
                .await
                .unwrap()
                .allowed(),
            "I395 a live invitee's node receives the planes (full history)"
        );
        ma::put(d, &ma::reply(&k, &k, &p, false, now))
            .await
            .unwrap();
        assert!(
            !ra::may_receive_group_plane(d, &kr(&knode), COMMUNITY, &kr(&cid), None)
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
        // v62 (P5c update 5): `[]` names no `"self"` entry, so self is
        // excluded too.
        assert!(
            !holds(d, &laptop, SELF, None, &owner).await,
            "I396 [] excludes self as well"
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
                try_put_grant(d, &owner, Some(&laptop), Some(c))
                    .await
                    .is_err(),
                "I396 refused: {why}"
            );
        }
        assert!(
            try_put_grant(d, &owner, None, Some(entries(&[(COMMUNITY, &cid)])))
                .await
                .is_err(),
            "I396 a list on a grant naming no node is refused"
        );
        let e = try_put_grant(
            d,
            &laptop,
            Some(&laptop),
            Some(entries(&[(COMMUNITY, &cid)])),
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
            ra::may_receive(d, &kr(&laptop), &g).await.unwrap(),
            ra::Verdict::Yes(ra::Reason::RefersTo),
            "I397 the node receives the grant FOR it"
        );
        assert!(
            !ra::may_receive(d, &kr(&sibling), &g)
                .await
                .unwrap()
                .allowed(),
            "I397 a sibling node does not"
        );
        // A key-grant row TO the server-class laptop, at a family it may not
        // receive, does not reach it by naming it (coordinator ruling; v55.0.0
        // #989: refers-to delivery is governed by the audience).
        let fam = format!("i397-f-{s}");
        family(d, &fam, &[&owner]).await;
        // v62.0.0 (E3b round 3): these unsealed rows are read straight by
        // `may_receive`, so they name the keys by their identity-refs (`kr`),
        // as the stored rows do.
        let mut row = ts::bare_attestation(
            "i397-row",
            &kr(&sibling),
            &kr(&laptop),
            &serde_json::json!({
                "dimension": crate::federation::key_grant::KEY_GRANT_CONTENT_DIMENSION,
                "family_key_id": kr(&fam),
            }),
        );
        row.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        row.cohort_scope = FAMILY.into();
        assert!(
            !ra::may_receive(d, &kr(&laptop), &row)
                .await
                .unwrap()
                .allowed(),
            "I397 a key-grant row to a device outside the cohort's audience does not reach it"
        );
        // And a retired SET (rc6) reaches nobody but its signer.
        let mut set = ts::bare_attestation(
            "i397-set",
            &kr(&sibling),
            &kr(&sibling),
            &serde_json::json!({ "family_key_id": kr(&fam) }),
        );
        set.attestation_type = "key_grant:content:v1".into();
        set.cohort_scope = FAMILY.into();
        set.subject_key_ids = vec![kr(&laptop)];
        assert!(
            !ra::may_receive(d, &kr(&laptop), &set)
                .await
                .unwrap()
                .allowed(),
            "I397 a retired key-grant set is served to nobody"
        );
        let mut own = ts::bare_attestation(
            "i397-own",
            &kr(&laptop),
            &kr(&laptop),
            &serde_json::json!({}),
        );
        own.cohort_scope = SELF.into();
        assert_eq!(
            ra::may_receive(d, &kr(&laptop), &own).await.unwrap(),
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

    /// **I398b** (CIRISEdge#761, CC 3.1.3.2) — a proposal reaches every node
    /// whose principals include its invitee K, whatever K's node's class or
    /// list: the invitee is not a member, so no cohort view admits it. A
    /// stranger's node is not reached.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i398b_a_proposal_reaches_the_invitees_nodes(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance_invariants::bodies as ma;
        let (cid, founder, k, kphone, kserver, stranger, snode) = (
            format!("i398b-c-{s}"),
            format!("i398b-f-{s}"),
            format!("i398b-k-{s}"),
            format!("i398b-kp-{s}"),
            format!("i398b-ks-{s}"),
            format!("i398b-x-{s}"),
            format!("i398b-xn-{s}"),
        );
        ma::reg(d, &[&cid, &founder, &k, &stranger]).await;
        nodes(d, &[&kphone, &kserver, &snode]).await;
        claim(d, &k, &kphone, device_class::PHONE).await;
        claim(d, &k, &kserver, device_class::SERVER).await;
        claim(d, &stranger, &snode, device_class::PHONE).await;
        ma::found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let p = ma::proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            Utc::now(),
            Some(Duration::days(7)),
        );
        ma::put(d, &p).await.unwrap();
        for n in [&kphone, &kserver] {
            assert_eq!(
                ra::may_receive(d, &kr(n), &p).await.unwrap(),
                ra::Verdict::Yes(ra::Reason::RefersTo),
                "I398b the invitee's node {n} receives the proposal (CC 3.1.3.2)"
            );
        }
        assert!(
            !ra::may_receive(d, &kr(&snode), &p).await.unwrap().allowed(),
            "I398b a stranger's node does not"
        );
    }

    /// v59.1.1 — the creator's view of a pair-room invitee's node: the
    /// invitee's announced owner binding `delegates_to(k → node)`.
    /// v62.0.0 (E3b round 3): the binding carries the node's own voice
    /// (`owner_of` counts it only then, `owner_binding_counted_short`). The
    /// earlier `unagreed_row` — an identity-signed `(k, node)` occurrence row —
    /// is gone: a node is never a person's occurrence in v62
    /// (`occurrence_binds_machine_to_person`), and a bind offered on the
    /// author's voice alone is never held.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn invitee_seen_from_the_creator(d: &dyn FederationDirectory, k: &str, node: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        nodes(d, &[node]).await;
        let mut binding =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), k, &e2::kid(node));
        binding.asserted_at = ms(Utc::now() - Duration::minutes(5));
        binding.scrub_timestamp = binding.asserted_at;
        ts::seal_row_in_place(k, &mut binding);
        // K2.api: the shared landing (owner's statement, then the node's
        // voice; asserts Row).
        ts::put_sealed_owner_binding(d, &binding, node)
            .await
            .unwrap_or_else(|e| panic!("owner binding {k} → {node}: {e}"));
    }

    /// A pair-room proposal of `invitee` by `creator` into a fresh room.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn pair_room_proposal(
        d: &dyn FederationDirectory,
        cid: &str,
        creator: &str,
        invitee: &str,
    ) -> Attestation {
        use crate::federation::membership_acceptance_invariants::bodies as ma;
        ma::reg(d, &[cid, creator]).await;
        ma::found_community(d, cid, "quorum:1/1", &[creator], &[])
            .await
            .unwrap();
        let p = ma::proposal(
            creator,
            COMMUNITY,
            cid,
            invitee,
            None,
            Utc::now(),
            Some(Duration::days(7)),
        );
        ma::put(d, &p).await.unwrap();
        p
    }

    /// **I1470** (v59.1.1, CIRISServer's shape — live chat; v62.0.0 E3b
    /// round 3) — the creator holds the invitee's owner binding for the
    /// invitee's node, and no occurrence row: ownership is the only fact (in
    /// v62 the only way a person's node is theirs, P5c). The owner binding
    /// lifts the node to the invitee, so the invitation reaches it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i1470_an_owner_binding_lifts_the_invitees_node(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::self_collective::principals_of;
        let (cid, creator, k, knode) = (
            format!("i1470-c-{s}"),
            format!("i1470-f-{s}"),
            format!("i1470-k-{s}"),
            format!("i1470-kn-{s}"),
        );
        users(d, &[&k]).await;
        invitee_seen_from_the_creator(d, &k, &knode).await;
        assert_eq!(
            crate::federation::admission::owner_of(d, &kr(&knode))
                .await
                .unwrap(),
            Some(kr(&k)),
            "I1470 precondition — the owner binding names the invitee"
        );
        assert_eq!(
            principals_of(d, &kr(&knode)).await.unwrap(),
            vec![kr(&k)],
            "I1470 the owned node's principal is its owner"
        );
        let p = pair_room_proposal(d, &cid, &creator, &k).await;
        assert_eq!(
            ra::may_receive(d, &kr(&knode), &p).await.unwrap(),
            ra::Verdict::Yes(ra::Reason::RefersTo),
            "I1470 the invitee's node receives the pair-room invitation"
        );
        // I1473 (v59.1.1, the second link — CIRISServer live chat): the same
        // node receives the GROUP's record and membership planes as a live
        // invitee's node, through the same principal fold.
        assert_eq!(
            ra::may_receive_group_plane(d, &kr(&knode), COMMUNITY, &kr(&cid), None)
                .await
                .unwrap(),
            ra::Verdict::Yes(ra::Reason::Cohort),
            "I1473 the invitee's node receives the room's record and membership planes"
        );
    }

    /// **I398c** — an acceptance or decline goes back to the proposer's
    /// nodes (resolved from the proposal it answers), and to nobody else
    /// outside the group's plane.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i398c_an_answer_returns_to_the_proposers_nodes(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance_invariants::bodies as ma;
        let (cid, founder, fnode, k, j, stranger, snode) = (
            format!("i398c-c-{s}"),
            format!("i398c-f-{s}"),
            format!("i398c-fn-{s}"),
            format!("i398c-k-{s}"),
            format!("i398c-j-{s}"),
            format!("i398c-x-{s}"),
            format!("i398c-xn-{s}"),
        );
        ma::reg(d, &[&cid, &founder, &k, &j, &stranger]).await;
        nodes(d, &[&fnode, &snode]).await;
        claim(d, &founder, &fnode, device_class::SERVER).await;
        claim(d, &stranger, &snode, device_class::PHONE).await;
        ma::found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        // A server-class node that denies the room as CONTENT still gets the
        // ceremony: a roster row is not content.
        put(
            d,
            &grant(&founder, Some(&fnode), Some(serde_json::json!([]))),
        )
        .await
        .unwrap();
        let now = Utc::now();
        let pk = ma::proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        let pj = ma::proposal(
            &founder,
            COMMUNITY,
            &cid,
            &j,
            None,
            now,
            Some(Duration::days(7)),
        );
        ma::put(d, &pk).await.unwrap();
        ma::put(d, &pj).await.unwrap();
        let accept = ma::reply(&k, &k, &pk, true, now);
        let decline = ma::reply(&j, &j, &pj, false, now);
        ma::put(d, &accept).await.unwrap();
        ma::put(d, &decline).await.unwrap();
        for (a, what) in [(&accept, "acceptance"), (&decline, "decline")] {
            assert_eq!(
                ra::may_receive(d, &kr(&fnode), a).await.unwrap(),
                ra::Verdict::Yes(ra::Reason::RefersTo),
                "I398c the {what} returns to the proposer's node"
            );
            assert!(
                !ra::may_receive(d, &kr(&snode), a).await.unwrap().allowed(),
                "I398c a stranger's node does not receive the {what}"
            );
        }
    }

    /// **I398d** — `affiliations` is the room's plane (CC 4.4.3.2.8: an
    /// affiliation runs all the community machinery). A proposal placed at
    /// `affiliations` is admitted, counts as a live invitation when the group
    /// is asked about at `community`, and its answer matches it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i398d_affiliations_is_the_rooms_plane(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance as mac;
        use crate::federation::membership_acceptance_invariants::bodies as ma;
        use crate::federation::types::cohort_scope::AFFILIATIONS;
        let (cid, founder, k, knode) = (
            format!("i398d-c-{s}"),
            format!("i398d-f-{s}"),
            format!("i398d-k-{s}"),
            format!("i398d-n-{s}"),
        );
        ma::reg(d, &[&cid, &founder, &k]).await;
        nodes(d, &[&knode]).await;
        claim(d, &k, &knode, device_class::PHONE).await;
        // v54.0.0 (#1034) — an affiliations proposal names an affiliation.
        ma::found_affiliation(d, &cid, "founder_only", &[&founder], &[])
            .await
            .unwrap();
        let now = Utc::now();
        let p = ma::proposal(
            &founder,
            AFFILIATIONS,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        ma::put(d, &p)
            .await
            .expect("I398d an affiliations proposal is admitted");
        assert_eq!(
            mac::live_invitees_of(d, COMMUNITY, &kr(&cid), &[kr(&founder)])
                .await
                .unwrap(),
            vec![kr(&k)],
            "I398d the affiliations proposal is a live invitation of the room"
        );
        assert!(
            ra::may_receive_group_plane(d, &kr(&knode), COMMUNITY, &kr(&cid), None)
                .await
                .unwrap()
                .allowed(),
            "I398d the invitee's node receives the room's planes"
        );
        let a = ma::reply(&k, &k, &p, true, now);
        ma::put(d, &a).await.unwrap();
        assert_eq!(
            mac::answered_proposal_of(d, &a)
                .await
                .unwrap()
                .map(|r| r.attestation_id),
            Some(p.attestation_id.clone()),
            "I398d the answer matches its affiliations proposal"
        );
    }

    /// v62 (E3b) — what `from` serves `requester` of the rows `rows`: every
    /// statement (each voice) of those rows on cut B's FILTERED serve path
    /// (`edition2::serve::statements_served_to`), in `from`'s admission
    /// order. Empty when the path withholds them (E13's `served`, without
    /// its non-empty assert: I398e asserts a withholding too).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn served_rows(
        from: &dyn FederationDirectory,
        requester: &str,
        rows: &[crate::federation::edition2::names::RowId],
    ) -> Vec<(Vec<u8>, crate::federation::edition2::names::RowId)> {
        use crate::federation::edition2::names::RowId;
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                1000,
                Some(requester),
            )
            .await
            .expect("serve statements");
            for st in page.statements {
                if let Some(id) = RowId::of_statement(&st.bytes) {
                    if rows.contains(&id) {
                        out.push((st.bytes, id));
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        out
    }

    /// v62 (E3b) — the statement `row` carries, as its author pushes it to a
    /// node the sender's verdict (`may_receive`) names: the bytes and the row
    /// id they name.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn pushed(row: &Attestation) -> Vec<(Vec<u8>, crate::federation::edition2::names::RowId)> {
        use crate::federation::edition2::fixture_switch as e2;
        let st = e2::carried_statement(row).expect("a flipped row carries its statement");
        let id = e2::row_id_of(&st);
        vec![(st, id)]
    }

    /// v62 (E3b) — each statement through `to`'s replicated statement door
    /// (`edition2::ingest::apply_replicated_statement`), under the id it
    /// names; every one must be admitted (new here) or already held.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn deliver(
        to: &dyn FederationDirectory,
        statements: &[(Vec<u8>, crate::federation::edition2::names::RowId)],
        what: &str,
    ) {
        use crate::federation::edition2::ingest::{
            apply_replicated_statement, ReplicatedStatementOutcome,
        };
        for (bytes, id) in statements {
            match apply_replicated_statement(to, bytes, &id.0)
                .await
                .unwrap_or_else(|e| panic!("{what}: a replicated statement: {e}"))
            {
                ReplicatedStatementOutcome::Admitted(_)
                | ReplicatedStatementOutcome::Unchanged(_) => {}
                ReplicatedStatementOutcome::Refused { reason } => {
                    panic!("{what}: the replicated statement is refused: {reason:?}")
                }
            }
        }
    }

    /// **I398e** — two nodes, through `may_receive` as the sender's verdict:
    /// A (the room's) sends the proposal to K's node B; B, holding no roster,
    /// sends K's acceptance back to the proposer's node.
    ///
    /// v62 (E3b): on E5's flipped `membership_acceptance_invariants::bodies`
    /// (`reg`, `id_of`, `found_community`, `proposal`, `reply`, `put`); the
    /// group ids and signers are the ids the directory keys them by
    /// (`ma::id_of`). Nothing crosses by a local put any more:
    /// - A learns K's owner binding (a commons row) the way a peer does: B's
    ///   FILTERED serve path with A's node (`fnode`) as the requester
    ///   (`statements_served_to`), then A's `apply_replicated_statement`
    ///   (E13's pattern). The binding and the node's voice cross.
    /// - The proposal crosses on A's filtered serve path to K's node (T1:
    ///   a proposal is delivered to its invitee's node). The acceptance is
    ///   still PUSHED where the sender's verdict sends it (`may_receive`,
    ///   this witness's subject): `delivered_keys` names no proposer for an
    ///   answer, and B holds no roster, so B's serve path has no rule that
    ///   reaches the proposer (a gap for the serve owner, T1).
    /// - B's filtered serve path withholds the acceptance from the
    ///   proposer's node it cannot resolve (the same "no binding" fact as the
    ///   sender's verdict).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i398e_the_ceremony_crosses_two_nodes(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::membership_acceptance_invariants::bodies as ma;
        let (cid, founder, fnode, k, knode) = (
            format!("i398e-c-{s}"),
            format!("i398e-f-{s}"),
            format!("i398e-fn-{s}"),
            format!("i398e-k-{s}"),
            format!("i398e-kn-{s}"),
        );
        for d in [a, b] {
            ma::reg(d, &[&cid, &founder, &k]).await;
            nodes(d, &[&fnode, &knode]).await;
        }
        claim(a, &founder, &fnode, device_class::LAPTOP).await;
        claim(b, &k, &knode, device_class::PHONE).await;
        // The ids the directory keys them by (E5: `reg` puts `kid(seed)`).
        let (cid_k, founder_k, k_k) = (ma::id_of(&cid), ma::id_of(&founder), ma::id_of(&k));
        ma::found_community(a, &cid_k, "quorum:1/1", &[&founder_k], &[])
            .await
            .unwrap();
        let now = Utc::now();
        let p = ma::proposal(
            &founder_k,
            COMMUNITY,
            &cid_k,
            &k_k,
            None,
            now,
            Some(Duration::days(7)),
        );
        ma::put(a, &p).await.unwrap();
        assert!(
            !ra::may_receive(a, &kr(&knode), &p).await.unwrap().allowed(),
            "I398e precondition — A does not know K's node is K's"
        );
        // A learns K's binding the way a peer does: B serves it (a commons
        // row: the binding and the node's voice) to A's node, and A applies
        // each statement at its replicated door.
        let binding = claimed()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(k.clone(), knode.clone()))
            .cloned()
            .expect("I398e fixture — K's binding on B");
        let binding_id = e2::row_id_of(
            &e2::carried_statement(&binding).expect("the binding carries its statement"),
        );
        let carried = served_rows(b, &kr(&fnode), &[binding_id]).await;
        assert!(
            carried.len() >= 2,
            "I398e B serves A's node K's binding and the node's voice: {} statement(s)",
            carried.len()
        );
        deliver(a, &carried, "I398e K's binding onto A").await;
        assert!(
            ra::may_receive(a, &kr(&knode), &p).await.unwrap().allowed(),
            "I398e A sends the proposal to K's node"
        );
        // v62.0.0 (E3b round 3) — T1's delivered-key rule
        // (`group_serve::delivered_to_requester`): a proposal is served to
        // its invitee's node, so the proposal now crosses on A's FILTERED
        // serve path (requester: K's node), not by a push.
        let proposal_id = pushed(&p)[0].1;
        let to_k = served_rows(a, &kr(&knode), &[proposal_id]).await;
        assert!(
            !to_k.is_empty(),
            "I398e A's serve path serves the proposal to K's node"
        );
        deliver(b, &to_k, "I398e B admits the proposal (no roster held)").await;
        let acc = ma::reply(&k_k, &k_k, &p, true, now);
        ma::put(b, &acc)
            .await
            .expect("I398e B admits K's acceptance");
        assert!(
            ra::may_receive(b, &kr(&founder), &acc)
                .await
                .unwrap()
                .allowed(),
            "I398e B sends the acceptance back to the proposer"
        );
        assert!(
            !ra::may_receive(b, &kr(&fnode), &acc)
                .await
                .unwrap()
                .allowed(),
            "I398e B cannot resolve a node of the proposer it holds no binding for"
        );
        let acc_id = pushed(&acc)[0].1;
        assert!(
            served_rows(b, &kr(&fnode), &[acc_id]).await.is_empty(),
            "I398e B's serve path withholds the acceptance from that node too"
        );
        deliver(a, &pushed(&acc), "I398e A admits the acceptance").await;
        assert!(
            ra::may_receive(a, &kr(&fnode), &acc)
                .await
                .unwrap()
                .allowed(),
            "I398e on A the acceptance reaches the proposer's node"
        );
        let again = pushed(&acc);
        deliver(a, &again, "I398e the acceptance re-delivered").await;
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

    /// **I2689** (v62.0.0, E3b round 3) — a COMPOSER over a consent grant
    /// is not a grant. In edition 2 a `withdraws` is stated in its target's
    /// family, so it carries the grant's dimension and no grant `payload`.
    /// The closed grant grammar (#510) judges the grant itself and never a
    /// composer over it, so the withdraws lands. A malformed grant is still
    /// refused at the same door (sqlite and pg through `dyn_runners`).
    pub(crate) async fn i2689_a_composer_over_a_grant_is_not_a_grant(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner, laptop) = (format!("i2689-o-{s}"), format!("i2689-l-{s}"));
        users(d, &[&owner]).await;
        nodes(d, &[&laptop]).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        let g = grant(&owner, Some(&laptop), Some(serde_json::json!([])));
        put(d, &g).await.expect("I2689 the grant is admitted");
        let w = crate::federation::edition2::fixture_switch::composer_of("withdraws", &g, &owner);
        assert_eq!(
            crate::federation::admission::envelope_dimension(&w.attestation_envelope),
            Some(crate::federation::consent_grammar::GRANT_DIMENSION),
            "I2689 precondition: the composer carries the grant's dimension"
        );
        put(d, &w)
            .await
            .expect("I2689 a withdraws of a grant is not judged as a grant");
        let bad = serde_json::json!([{"scope":"family","target":""}]);
        assert!(
            try_put_grant(d, &owner, Some(&laptop), Some(bad))
                .await
                .is_err(),
            "I2689 a malformed grant is still refused by the grant grammar"
        );
    }
}

/// The KEY half (coordinator ruling on #963): a node denied a cohort's
/// content gets no key for it. SQL backends (the cascades need blob storage).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod key_bodies {
    // v62 (E3b): every id handed to a production read, and every expected
    // member of a recipient set, is `kr(seed)` (the identity-ref the
    // edition-2 rows carry); the fixtures (`users`, `nodes`, `claim_with`,
    // `room`, `family`, `grant`) take seeds.
    use super::bodies::{entries, family, grant, kr, nodes, put, room, users};
    use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY, SELF};
    use crate::federation::types::device_class;
    use crate::federation::{BlobStorage, FederationDirectory};

    /// `owner` owns `node` (its self-occurrence's class `class`), and the
    /// node holds real content-KEM keys.
    ///
    /// v62 (E3b; P5c, O1): a node is never bound under a person
    /// (`occurrence_binds_machine_to_person`), so there is no `(owner, node)`
    /// occurrence. WHO: the owner binding plus the node's voice
    /// (`bodies::claim_with`). WHAT KIND, and the keys a wrap is sealed to:
    /// the node's OWN self-occurrence (identity = occurrence = the node key),
    /// carrying `class` and `encryption_pubkeys` (a CBOR map of the raw
    /// `x25519` / `ml_kem_768` public halves, as E13's `anchor_self_on`).
    async fn keyed_claim<B>(b: &B, owner: &str, node: &str, class: &str)
    where
        B: FederationDirectory + Sync,
    {
        use ciris_verify_core::cde::Value;
        let (_xp, x_pub, _mp, ml_pub) =
            crate::federation::identity_aggregate::mint_content_kem_keypair().expect("kem");
        let enc = Value::Map(vec![
            (Value::Text("x25519".into()), Value::Bytes(x_pub.to_vec())),
            (Value::Text("ml_kem_768".into()), Value::Bytes(ml_pub)),
        ]);
        let opts = e2::BindOptions {
            extra: vec![("encryption_pubkeys", enc)],
            ..e2::BindOptions::default()
        };
        super::bodies::claim_with(b as &dyn FederationDirectory, owner, node, class, &opts).await;
    }

    async fn minter<B: FederationDirectory + Sync>(b: &B, s: &str) -> String {
        crate::federation::at_rest_cascade::blob_invariants::node_signer(b, &format!("mint-{s}"))
            .await
            .derived_key_id()
    }

    /// The recipients of a seal at `scope` / `group` (a seed; read as `kr`).
    async fn self_family_granted<B>(b: &B, scope: &str, group: &str) -> Vec<String>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        encrypt_and_cascade(b, scope, &kr(group), b"i39x content", None, None, None)
            .await
            .unwrap_or_else(|e| panic!("seal at {scope}: {e}"))
            .granted
    }

    /// The room epoch a seal used, and that epoch's wrap recipients
    /// (`cid` a seed; read as `kr`).
    async fn room_epoch<B>(b: &B, cid: &str, minter: &str) -> (u64, Vec<String>)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let cid = kr(cid);
        let r = encrypt_and_cascade_community(b, &cid, b"i39x room", None, Some(minter))
            .await
            .unwrap_or_else(|e| panic!("seal in {cid}: {e}"));
        let rec = b
            .community_dek_member_grant_recipients(&cid, &r.minter_key_id, r.epoch)
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
        let (lk, pk) = (kr(&laptop), kr(&phone));
        let fg = self_family_granted(b, FAMILY, &fam).await;
        assert!(
            fg.contains(&pk) && !fg.contains(&lk),
            "I393b family wraps: {fg:?}"
        );
        // v62 (P5c update 5, CC rc21 3.3.7): a present allow list without
        // the literal `"self"` entry excludes `self` for every class; the
        // laptop's list names only `work`.
        let sg = self_family_granted(b, SELF, &owner).await;
        assert!(
            sg.contains(&pk) && !sg.contains(&lk),
            "I393b a list without \"self\" excludes self: {sg:?}"
        );
        let m = minter(b, s).await;
        let (_, ar) = room_epoch(b, &adult, &m).await;
        assert!(
            ar.contains(&pk) && !ar.contains(&lk),
            "I393b adulthub's epoch key: {ar:?}"
        );
        let (_, wr) = room_epoch(b, &work, &m).await;
        assert!(
            wr.contains(&lk),
            "I393b the listed room's key reaches the laptop: {wr:?}"
        );
    }

    /// **I394b** — a server gets no self or family key, an owned agent gets
    /// self but no family key (P5c update 4), and both get their owner's room
    /// key (CC 3.3.7).
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
        let (ak, sk, lk) = (kr(&agent), kr(&server), kr(&laptop));
        // v62 (P5c update 4): an `agent`-class device its owner OWNS is
        // `OwnedAgent`: within its owner's `self` (no list), no `family` by
        // default. The server class gets neither.
        let g = self_family_granted(b, SELF, &owner).await;
        assert!(
            g.contains(&lk) && g.contains(&ak) && !g.contains(&sk),
            "I394b self: the laptop and the owned agent, not the server: {g:?}"
        );
        let g = self_family_granted(b, FAMILY, &fam).await;
        assert!(
            g.contains(&lk) && !g.contains(&ak) && !g.contains(&sk),
            "I394b family: no key for the server class or the owned agent: {g:?}"
        );
        let (_, r) = room_epoch(b, &cid, &minter(b, s).await).await;
        assert!(
            r.contains(&ak) && r.contains(&sk) && r.contains(&lk),
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
        let (lk, pk) = (kr(&laptop), kr(&phone));
        let (e0, r0) = room_epoch(b, &cid, &m).await;
        assert!(
            r0.contains(&lk),
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
            !r1.contains(&lk) && r1.contains(&pk),
            "I392c the new epoch's key skips the denied laptop: {r1:?}"
        );
        let again = encrypt_and_cascade_community(b, &kr(&cid), b"i392c steady", None, Some(&m))
            .await
            .unwrap();
        assert_eq!(
            again.epoch, e1,
            "I392c no further rotation once the set is steady"
        );
    }

    /// The owner's deny-everything grant for `node`, admitted; the row.
    async fn deny_all<B: FederationDirectory + Sync>(
        b: &B,
        owner: &str,
        node: &str,
    ) -> crate::federation::Attestation {
        let g = grant(owner, Some(node), Some(serde_json::json!([])));
        put(b as &dyn FederationDirectory, &g).await.unwrap();
        g
    }

    /// **I397e** (v53.0.0, #963) — a cohort the owner ALLOWS on a node after
    /// the fact (here: withdrawing the grant that denied it) reaches the node
    /// with its EARLIER keys: the family blob sealed while it was denied, and
    /// the room epoch minted while it was denied. The write door that admits
    /// the withdrawal runs the same walk a re-class does.
    pub(crate) async fn i397e_an_allow_after_the_fact_brings_the_earlier_keys<B>(
        b: &B,
        s: &str,
        set_node: fn(&B, String),
    ) where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let (owner, laptop, phone, cid, fam) = (
            format!("i397e-o-{s}"),
            format!("i397e-l-{s}"),
            format!("i397e-p-{s}"),
            format!("i397e-c-{s}"),
            format!("i397e-f-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &phone]).await;
        keyed_claim(b, &owner, &laptop, device_class::LAPTOP).await;
        keyed_claim(b, &owner, &phone, device_class::PHONE).await;
        room(d, &cid, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        let m = minter(b, s).await;
        set_node(b, m.clone());
        let (lk, pk) = (kr(&laptop), kr(&phone));
        let deny = deny_all(b, &owner, &laptop).await;
        let sealed = encrypt_and_cascade(b, FAMILY, &kr(&fam), b"i397e family", None, None, None)
            .await
            .unwrap();
        assert!(
            sealed.granted.contains(&pk) && !sealed.granted.contains(&lk),
            "I397e precondition — the denied laptop gets no family key: {:?}",
            sealed.granted
        );
        let (e0, r0) = room_epoch(b, &cid, &m).await;
        assert!(
            !r0.contains(&lk) && r0.contains(&pk),
            "I397e precondition — nor the room's e{e0}: {r0:?}"
        );

        super::bodies::withdraw_pub(d, &owner, &deny).await;
        assert!(
            b.get_at_rest_grant(&sealed.at_rest_sha256, &lk)
                .await
                .unwrap()
                .is_some(),
            "I397e the allowed laptop holds the family blob sealed while it was denied"
        );
        let held = b
            .community_dek_member_grant_recipients(&kr(&cid), &m, e0)
            .await
            .unwrap();
        assert!(
            held.contains(&lk),
            "I397e and the room epoch minted while it was denied: {held:?}"
        );
    }

    /// **I397f** (v53.0.0, #963) — a cohort the owner DENIES after the fact:
    /// the door admitting the deny hands the node nothing, the room's epoch
    /// rolls at the next seal and skips it, and later family content skips it.
    pub(crate) async fn i397f_a_deny_after_the_fact_rolls_and_grants_nothing<B>(
        b: &B,
        s: &str,
        set_node: fn(&B, String),
    ) where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let (owner, laptop, phone, cid, fam) = (
            format!("i397f-o-{s}"),
            format!("i397f-l-{s}"),
            format!("i397f-p-{s}"),
            format!("i397f-c-{s}"),
            format!("i397f-f-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &phone]).await;
        keyed_claim(b, &owner, &laptop, device_class::LAPTOP).await;
        keyed_claim(b, &owner, &phone, device_class::PHONE).await;
        room(d, &cid, &[&owner]).await;
        family(d, &fam, &[&owner]).await;
        let m = minter(b, s).await;
        set_node(b, m.clone());
        let (lk, pk) = (kr(&laptop), kr(&phone));
        let (e0, r0) = room_epoch(b, &cid, &m).await;
        assert!(
            r0.contains(&lk),
            "I397f precondition — the laptop holds e{e0}"
        );
        let before = encrypt_and_cascade(b, FAMILY, &kr(&fam), b"i397f before", None, None, None)
            .await
            .unwrap();
        assert!(
            before.granted.contains(&lk),
            "I397f precondition — and family"
        );

        deny_all(b, &owner, &laptop).await;
        let after = encrypt_and_cascade(b, FAMILY, &kr(&fam), b"i397f after", None, None, None)
            .await
            .unwrap();
        assert!(
            !after.granted.contains(&lk) && after.granted.contains(&pk),
            "I397f family content after the deny skips the laptop: {:?}",
            after.granted
        );
        let (e1, r1) = room_epoch(b, &cid, &m).await;
        assert!(
            e1 > e0,
            "I397f the deny rolled the room epoch: e{e0} → e{e1}"
        );
        assert!(
            !r1.contains(&lk) && r1.contains(&pk),
            "I397f the new epoch skips the denied laptop: {r1:?}"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
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
                case!(i2689_a_composer_over_a_grant_is_not_a_grant);
                $(case!($extra);)*
            }
        };
    }

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
        [
            i395_live_invitee_receives_the_planes,
            i398b_a_proposal_reaches_the_invitees_nodes,
            i1470_an_owner_binding_lifts_the_invitees_node,
            i398c_an_answer_returns_to_the_proposers_nodes,
            i398d_affiliations_is_the_rooms_plane
        ]
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
        [
            i395_live_invitee_receives_the_planes,
            i398b_a_proposal_reaches_the_invitees_nodes,
            i1470_an_owner_binding_lifts_the_invitees_node,
            i398c_an_answer_returns_to_the_proposers_nodes,
            i398d_affiliations_is_the_rooms_plane
        ]
    );

    /// I398e — two directories of one backend kind.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i398e_sqlite() {
        use crate::federation::FederationDirectory;
        use crate::store::Backend as _;
        let mk = || async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            b
        };
        let (a, b) = (mk().await, mk().await);
        super::bodies::i398e_the_ceremony_crosses_two_nodes(
            &a as &dyn FederationDirectory,
            &b as &dyn FederationDirectory,
            &suffix(),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i398e_postgres() {
        use crate::federation::FederationDirectory;
        use crate::store::Backend as _;
        let (Some(da), Some(db)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn())
        else {
            return;
        };
        let a = crate::store::postgres::PostgresBackend::connect(&da)
            .await
            .unwrap();
        a.run_migrations().await.unwrap();
        let b = crate::store::postgres::PostgresBackend::connect(&db)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i398e_the_ceremony_crosses_two_nodes(
            &a as &dyn FederationDirectory,
            &b as &dyn FederationDirectory,
            &suffix(),
        )
        .await;
    }
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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod consent_change_runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }
    use crate::federation::replication_audience_invariants::key_bodies as kb;

    #[cfg(feature = "sqlite")]
    mod sqlite {
        use super::{kb, suffix};
        use crate::store::sqlite::SqliteBackend;
        async fn fresh() -> SqliteBackend {
            use crate::store::Backend as _;
            let b = SqliteBackend::open_in_memory().await.unwrap();
            b.run_migrations().await.unwrap();
            b
        }
        fn set_node(b: &SqliteBackend, k: String) {
            b.set_node_key_id(k)
        }
        #[tokio::test]
        async fn i397e() {
            kb::i397e_an_allow_after_the_fact_brings_the_earlier_keys(
                &fresh().await,
                &suffix(),
                set_node,
            )
            .await
        }
        #[tokio::test]
        async fn i397f() {
            kb::i397f_a_deny_after_the_fact_rolls_and_grants_nothing(
                &fresh().await,
                &suffix(),
                set_node,
            )
            .await
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::{kb, suffix};
        use crate::store::postgres::PostgresBackend;
        async fn fresh() -> Option<PostgresBackend> {
            use crate::store::Backend as _;
            let dsn = crate::test_pg::empty_dsn()?;
            let b = PostgresBackend::connect(&dsn).await.unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        }
        fn set_node(b: &PostgresBackend, k: String) {
            b.set_node_key_id(k)
        }
        #[tokio::test]
        async fn i397e() {
            let Some(b) = fresh().await else { return };
            kb::i397e_an_allow_after_the_fact_brings_the_earlier_keys(&b, &suffix(), set_node).await
        }
        #[tokio::test]
        async fn i397f() {
            let Some(b) = fresh().await else { return };
            kb::i397f_a_deny_after_the_fact_rolls_and_grants_nothing(&b, &suffix(), set_node).await
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod codex_978_i505 {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::replication_audience as ra;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        test_pre_rotation_commitment, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
        TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::attestation_type::DELEGATES_TO;
    use crate::federation::FederationDirectory;

    /// **I505 — a family is public only by the charter its HEAD names** (Codex
    /// on #978; CC 3.2 T6): a live `trust:charter:v1` row the head does not
    /// name confers nothing and widens nothing; once a version names it, the
    /// family is public.
    async fn public_only_by_the_named_charter(d: &dyn FederationDirectory, tag: &str) {
        let fid = format!("i505-family-{tag}");
        let (a, b) = (format!("i505-a-{tag}"), format!("i505-b-{tag}"));
        super::bodies::users(d, &[&a, &b]).await;
        // Wave 2 (T1): the family is founded through the edition-2 door (both
        // founders' voices) and held under its identity-ref.
        let now = chrono::Utc::now();
        let founding = ts::sign_family(
            &a,
            crate::federation::types::Family {
                family_key_id: fid.clone(),
                family_name: "household".into(),
                members: [&a, &b]
                    .iter()
                    .map(|k| crate::federation::types::FamilyMember {
                        key_id: (*k).clone(),
                        joined_at: now - chrono::Duration::days(3),
                        role: Some("founder".into()),
                    })
                    .collect(),
                founded_at: now - chrono::Duration::days(3),
                consensus_protocol: "founder_only".into(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
                prev_head_digest: String::new(),
                charter_digest: String::new(),
            },
        );
        e2::put_voices(d, &e2::family_voices(&founding, 1, None, e2::ms(now)))
            .await
            .unwrap_or_else(|e| panic!("{tag} I505: the family founds: {e}"));
        let fid_ref = e2::kid(&fid);
        assert!(
            !ra::is_public_group(d, &fid_ref).await.unwrap(),
            "{tag} I505: control — no charter, private"
        );
        // A live charter row, stored AHEAD of the version that adopts it.
        let id = format!("i505-charter-{tag}");
        // v62 (E3): no self-reference: a `references_attestation_id` names a
        // held row by its node-computed id, and this row has none yet.
        let env = serde_json::json!({
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": test_pre_rotation_commitment(&[
                format!("{fid}-succ-a"),
                format!("{fid}-succ-b"),
            ])
            .unwrap(),
        });
        // v62.0.0 (E3b round 3): a co-signed charter is a COUNTED
        // `trust:charter:v1` row (E0's `counted_row_of`, as roster_head's
        // `put_charter`): only a counted row has a role for a further voice;
        // an authored row refuses one `iss_not_in_role`.
        let mut draft = ts::bare_attestation(&id, &a, &fid, &env);
        draft.attestation_type = DELEGATES_TO.to_owned();
        let charter = e2::counted_row_of(&draft, &a);
        // v62 (E3): the row id is node-computed; read it off the row.
        let charter_id = e2::rid(&charter);
        // The co-signer is a further voice, put after the row.
        let voices =
            crate::federation::edition2::fixture_switch::voices_of(&charter, &[b.as_str()]);
        crate::federation::edition2::fixture_switch::put_signed(d, &charter)
            .await
            .unwrap_or_else(|e| panic!("{tag} I505: the charter row admits: {e}"));
        for v in voices {
            crate::federation::edition2::fixture_switch::put_statement(d, &v)
                .await
                .unwrap_or_else(|e| panic!("{tag} I505: the co-signer's voice: {e}"));
        }
        let digest = d
            .get_attestation(&charter_id)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        assert!(
            !ra::is_public_group(d, &fid_ref).await.unwrap(),
            "{tag} I505: a charter the head does not name widens nothing"
        );
        // The version that names it: the roster's own row at the next
        // version, naming the held head by `refs.head`, every founder voicing.
        let mut next = founding.family.clone();
        next.charter_digest = digest;
        let next = ts::sign_family(&a, next);
        let voices = e2::family_voices_naming_held(d, &next, e2::ms(chrono::Utc::now())).await;
        e2::put_voices(d, &voices)
            .await
            .unwrap_or_else(|e| panic!("{tag} I505: the naming version: {e}"));
        assert!(
            ra::is_public_group(d, &fid_ref).await.unwrap(),
            "{tag} I505: the head names the charter — public"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i505_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        public_only_by_the_named_charter(&d, "sqlite").await;
    }

    /// v62.0.0 (E3b round 3): I505 on postgres (every store test runs on
    /// both backends). The tag is unique per run: the family id is derived
    /// from it, and a reused pg database keeps earlier runs' rows.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn i505_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        let tag = format!("pg-{}", uuid::Uuid::new_v4().simple());
        public_only_by_the_named_charter(&d, &tag).await;
    }
}
