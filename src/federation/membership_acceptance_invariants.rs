//! v52.0.0 (CIRISPersist#955; FSD `MEMBERSHIP_ACCEPTANCE.md` §8) — **I210–I219:
//! nobody joins a family or community without their own signed acceptance.**
//! Memory, sqlite, postgres (the read arm's SQL twin on sqlite / postgres).

pub(crate) mod bodies {
    use crate::federation::membership_acceptance::{
        ACCEPTANCE_DIMENSION, DECLINE_DIMENSION, PROPOSAL_DIMENSION, RULE_ACCEPTANCE_MISMATCH,
        RULE_ACCEPTANCE_UNRESOLVED, RULE_DECLINED, RULE_PROPOSAL_EXPIRED, RULE_PROPOSAL_UNRESOLVED,
        RULE_REPLY_CONFLICT, RULE_SUPERSEDE_CANNOT_ADD,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY};
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{
        attestation_type, Community, CommunityMember, CommunityMembershipWidening, Family,
        FamilyMember, FamilyMembershipWidening, RosterCosignature, SignedAttestation,
    };
    use crate::federation::{Attestation, Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    pub(crate) fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    pub(crate) fn rule_of(e: &Error) -> &'static str {
        match e {
            Error::MembershipAcceptanceRefused { rule, .. } => rule,
            other => panic!("expected MembershipAcceptanceRefused, got {other:?}"),
        }
    }

    /// v62.0.0 (flip wave 2, E5) — `register_identity_key` follows the switch
    /// (E0.api v1.2): an edition-2 `key:record` (`user`, from 0, no end) named
    /// `e2::kid(seed)` under the switch, the earlier JSON record when held.
    pub(crate) async fn reg<D: FederationDirectory + ?Sized>(d: &D, keys: &[&str]) {
        for k in keys {
            ts::register_identity_key(d, k, USER).await;
        }
    }

    fn cosign(signer: &str, envelope: &serde_json::Value) -> RosterCosignature {
        let (_h, classical, pqc) = ts::sign_envelope(signer, envelope);
        RosterCosignature {
            authority_key_id: signer.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// A community founded by `founders[0]`, the others co-signing; every
    /// founder listed as `founder`, plus `unsigned` members who did not sign.
    pub(crate) async fn found_community<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
    ) -> Result<(), Error> {
        found_room(d, cid, protocol, founders, unsigned, None).await
    }

    /// v54.0.0 (CIRISPersist#1034) — [`found_community`] declaring itself an
    /// affiliation (`policy_blob.cohort_scope`).
    pub(crate) async fn found_affiliation<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
    ) -> Result<(), Error> {
        let blob = serde_json::json!({
            crate::federation::affiliation_config::POLICY_COHORT_FIELD: "affiliations"
        });
        found_room(d, cid, protocol, founders, unsigned, Some(blob)).await
    }

    /// v61 (CIRISPersist#1123) — [`found_community`] as a `public` room
    /// (`policy_blob.cohort_subkind: public`).
    pub(crate) async fn found_public_room<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
    ) -> Result<(), Error> {
        let blob = serde_json::json!({
            "cohort_subkind": crate::federation::public_room::COHORT_SUBKIND_PUBLIC
        });
        found_room(d, cid, protocol, founders, unsigned, Some(blob)).await
    }

    /// v61 S2 (CIRISPersist#1143) — [`found_community`] carrying `policy_blob`
    /// (an affiliation with its config).
    pub(crate) async fn found_room_with_blob<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
        policy_blob: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        found_room(d, cid, protocol, founders, unsigned, policy_blob).await
    }

    /// v61 S2 — [`found_public_room`] founded (and its seats taken) at
    /// `founded_at`, for a witness whose roster events lie further back than
    /// the default day.
    pub(crate) async fn found_public_room_at<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        protocol: &str,
        founders: &[&str],
        founded_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let blob = serde_json::json!({
            "cohort_subkind": crate::federation::public_room::COHORT_SUBKIND_PUBLIC
        });
        found_room_at(d, cid, protocol, founders, &[], Some(blob), founded_at).await
    }

    async fn found_room<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
        policy_blob: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let founded_at = Utc::now() - Duration::days(1);
        found_room_at(
            d,
            cid,
            protocol,
            founders,
            unsigned,
            policy_blob,
            founded_at,
        )
        .await
    }

    async fn found_room_at<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
        policy_blob: Option<serde_json::Value>,
        founded_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let members = founders
            .iter()
            .map(|k| ((*k).to_owned(), Some("founder".to_owned())))
            .chain(unsigned.iter().map(|k| ((*k).to_owned(), None)))
            .map(|(key_id, role)| CommunityMember {
                key_id,
                joined_at: ms(founded_at),
                role,
            })
            .collect();
        let c = Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: cid.to_owned(),
            community_name: "I21x co-op".into(),
            members,
            founded_at: ms(founded_at),
            consensus_protocol: protocol.to_owned(),
            policy_blob,
            persist_row_hash: String::new(),
        };
        let env = c.signing_envelope();
        let mut signed = ts::sign_community(founders[0], c);
        signed.cosignatures = founders[1..].iter().map(|f| cosign(f, &env)).collect();
        // v62.0.0 (JSON cut, flip wave 2, E5) — under the switch the roster
        // enters as its edition-2 `group:roster` voices (T1.api §3: one per
        // founder, keyed by identity-refs; a roster listing an `unsigned`
        // member who has not voiced it is held `Pending`). A held
        // (earlier-form) caller keeps `put_community`.
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            use crate::federation::edition2::group_fixtures as gf;
            let voices = gf::community_voices(
                &signed,
                1,
                None,
                crate::federation::edition2::fixture_switch::ms(founded_at),
            );
            return gf::put_voices(d, &voices).await.map(|_| ());
        }
        d.put_community(signed).await.map(|_| ())
    }

    pub(crate) async fn found_family<D: FederationDirectory + ?Sized>(
        d: &D,
        fid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
    ) -> Result<(), Error> {
        let members = founders
            .iter()
            .map(|k| ((*k).to_owned(), Some("founder".to_owned())))
            .chain(unsigned.iter().map(|k| ((*k).to_owned(), None)))
            .map(|(key_id, role)| FamilyMember {
                key_id,
                joined_at: ms(Utc::now() - Duration::days(1)),
                role,
            })
            .collect();
        let f = Family {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            family_key_id: fid.to_owned(),
            family_name: "I21x household".into(),
            members,
            founded_at: ms(Utc::now() - Duration::days(1)),
            consensus_protocol: protocol.to_owned(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        let env = f.signing_envelope();
        let mut signed = ts::sign_family(founders[0], f);
        signed.cosignatures = founders[1..].iter().map(|f| cosign(f, &env)).collect();
        // v62.0.0 (flip wave 2, E5) — as `found_room_at`: the roster's
        // edition-2 voices under the switch, `put_family` when held.
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            use crate::federation::edition2::group_fixtures as gf;
            let at =
                crate::federation::edition2::fixture_switch::ms(Utc::now() - Duration::days(1));
            let voices = gf::family_voices(&signed, 1, None, at);
            return gf::put_voices(d, &voices).await.map(|_| ());
        }
        d.put_family(signed).await
    }

    fn row(
        signer: &str,
        attested: &str,
        scope: &str,
        envelope: serde_json::Value,
        asserted_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        subjects: Vec<String>,
    ) -> Attestation {
        let mut r = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            signer,
            attested,
            &envelope,
        );
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = scope.into();
        r.asserted_at = ms(asserted_at);
        r.scrub_timestamp = ms(asserted_at);
        r.expires_at = expires_at.map(ms);
        r.subject_key_ids = subjects;
        ts::seal_row_in_place(signer, &mut r);
        r
    }

    fn target_key(scope: &str) -> &'static str {
        if scope == FAMILY {
            "family_key_id"
        } else {
            "community_key_id"
        }
    }

    /// CC 2.x `group_kind`: `family` | `community` (an affiliation is a
    /// community record, CC 4.4.3.2.8).
    fn group_kind(scope: &str) -> &'static str {
        if scope == FAMILY {
            "family"
        } else {
            "community"
        }
    }

    /// An inviter's proposal of `invitee` into `group`.
    pub(crate) fn proposal(
        proposer: &str,
        scope: &str,
        group: &str,
        invitee: &str,
        role: Option<&str>,
        asserted_at: DateTime<Utc>,
        ttl: Option<Duration>,
    ) -> Attestation {
        let mut env = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": PROPOSAL_DIMENSION,
            "group_kind": group_kind(scope),
            target_key(scope): group,
        });
        // Absent when no role is offered (CC 2.6.1.7: never `null`).
        if let Some(role) = role {
            env["role"] = role.into();
        }
        row(
            proposer,
            proposer,
            scope,
            env,
            asserted_at,
            ttl.map(|t| asserted_at + t),
            vec![invitee.to_owned()],
        )
    }

    /// `signer`'s reply (as `member`) to `p`; `role` defaults to the offered one.
    pub(crate) fn reply(
        signer: &str,
        member: &str,
        p: &Attestation,
        accept: bool,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        let group = p
            .attestation_envelope
            .get(target_key(&p.cohort_scope))
            .cloned()
            .unwrap_or_default();
        let mut env = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": if accept { ACCEPTANCE_DIMENSION } else { DECLINE_DIMENSION },
            "group_kind": group_kind(&p.cohort_scope),
            target_key(&p.cohort_scope): group,
            "references_attestation_id": p.attestation_id,
            "proposal_hash": p.original_content_hash,
        });
        if accept {
            if let Some(role) = p.attestation_envelope.get("role").filter(|v| !v.is_null()) {
                env["role"] = role.clone();
            }
        }
        row(
            signer,
            member,
            &p.cohort_scope,
            env,
            asserted_at,
            None,
            vec![],
        )
    }

    // X2 pass 2: GC6's edition-2 door helpers, dropped when E5's rewrite of this
    // file won a conflict over the hunk that carried them.
    /// v62.0.0 (wave GC6; CC 2.7.3) — **the EDITION-2 door** these bodies
    /// run on (the earlier-form JSON door, [`put`], is shut in v62): the row's
    /// carried statement through `ingest::put_statement`, a fold attempt.
    ///
    /// A row the door HOLDS (kept, concluding nothing) is checked here (no
    /// typed row, its statement kept, a reason recorded) and returned as
    /// [`held_error`] of its reason, so each refusal-shaped assertion below
    /// now asserts the row was HELD with that token. A refusal of the bytes
    /// or the key plane passes through unchanged.
    pub(crate) async fn put_e2<D: FederationDirectory + ?Sized>(
        d: &D,
        a: &Attestation,
    ) -> Result<(), Error> {
        use crate::federation::edition2::{fixture_switch as e2, fold, ingest::StatementOutcome};
        match e2::put_signed(d, a).await? {
            StatementOutcome::Pending { row_id, .. } => {
                let held = fold::why_held(d, &row_id)
                    .await?
                    .expect("GC6: a held row carries its reason");
                assert!(
                    d.get_attestation(&row_id.hex()).await?.is_none(),
                    "GC6: held, not concluded: {held:?}"
                );
                assert!(
                    !d.edition2_voices(&row_id).await?.is_empty(),
                    "GC6: held, its statement kept: {held:?}"
                );
                Err(held_error(&held.reason, &held.detail))
            }
            _ => Ok(()),
        }
    }

    /// E5-fix1 (round 3) — a group-plane outcome as the refusal-shaped
    /// answer the I21x bodies assert: a widening the membership gate HOLDS
    /// (`Pending`: no acceptance yet, an expired proposal, ...) is returned
    /// as [`held_error`] of its fold reason, never as `Ok`; a landed or
    /// joined voice is `Ok`.
    pub(crate) async fn settled<D: FederationDirectory + ?Sized>(
        d: &D,
        out: crate::federation::edition2::ingest::StatementOutcome,
    ) -> Result<(), Error> {
        use crate::federation::edition2::{fold, ingest::StatementOutcome};
        match out {
            StatementOutcome::Pending { row_id, .. } => {
                let held = fold::why_held(d, &row_id)
                    .await?
                    .expect("a held group voice carries its reason");
                Err(held_error(&held.reason, &held.detail))
            }
            _ => Ok(()),
        }
    }

    /// The refusal-shaped error of a HELD row: its membership token as
    /// `MembershipAcceptanceRefused` (so `rule_of` reads it), else an
    /// `InvalidArgument` naming the reason and the gate's detail.
    pub(crate) fn held_error(reason: &str, detail: &str) -> Error {
        const RULES: &[&str] = &[
            RULE_ACCEPTANCE_UNRESOLVED,
            RULE_PROPOSAL_UNRESOLVED,
            RULE_DECLINED,
            RULE_PROPOSAL_EXPIRED,
            RULE_ACCEPTANCE_MISMATCH,
            RULE_REPLY_CONFLICT,
            RULE_SUPERSEDE_CANNOT_ADD,
            crate::federation::membership_acceptance::RULE_OPEN_PROPOSAL_NOT_OPEN,
            crate::federation::membership_acceptance::RULE_JOINER_OWNER_UNBOUND,
        ];
        match RULES.iter().copied().find(|r| *r == reason) {
            Some(rule) => Error::MembershipAcceptanceRefused {
                group_key_id: String::new(),
                member_key_id: String::new(),
                rule,
            },
            None => Error::InvalidArgument(format!("held {reason}: {detail}")),
        }
    }

    /// v62.0.0 (JSON cut, wave 3, E5) — a row carrying its edition-2
    /// statement enters through the one entry (`e2::put_signed`, every gate
    /// runs); a held (earlier-form) row through the JSON door.
    pub(crate) async fn put<D: FederationDirectory + ?Sized>(
        d: &D,
        a: &Attestation,
    ) -> Result<(), Error> {
        use crate::federation::edition2::fixture_switch as e2;
        if e2::carried_statement(a).is_some() {
            return e2::put_signed(d, a).await.map(|_| ());
        }
        d.put_attestation(SignedAttestation {
            attestation: a.clone(),
        })
        .await
        .map(|_| ())
    }

    /// v62.0.0 (wave 3, E5) — the id the directory keys a registered seed by:
    /// its identity-ref under the switch (`reg` puts `e2::kid(seed)`'s
    /// record), the seed when held.
    pub(crate) fn id_of(k: &str) -> String {
        use crate::federation::edition2::fixture_switch as e2;
        if e2::emit_edition2() {
            e2::kid_or_keep(k)
        } else {
            k.to_owned()
        }
    }

    pub(crate) async fn widen_community<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        signers: &[&str],
        member: &str,
        role: Option<&str>,
        effective_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let mut w = ts::sign_community_membership_widening(
            signers[0],
            CommunityMembershipWidening {
                community_key_id: cid.to_owned(),
                member_key_id: member.to_owned(),
                joined_at: ms(effective_at),
                effective_at: ms(effective_at),
                role: role.map(str::to_owned),
                persist_row_hash: String::new(),
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_widening(&mut w, c);
        }
        // v62.0.0 (JSON cut, flip wave 2, E5) — under the switch the widening
        // enters as its `membership:widening` voices naming the room's held
        // roster head (T1.api §3 "partly": the growth gate wants the member's
        // proposal and acceptance held as edition-2 rows, the caller's job).
        // A held (earlier-form) caller keeps the JSON door.
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            use crate::federation::edition2::group_fixtures as gf;
            let group = crate::federation::edition2::fixture_switch::kid(cid);
            let head = gf::held_head(d, &group).await.map(|(h, _)| h);
            let voices = gf::community_widening_voices(&w, head.as_ref());
            return settled(d, gf::put_voices(d, &voices).await?).await;
        }
        d.put_community_membership_widening(w).await
    }

    pub(crate) async fn widen_family<D: FederationDirectory + ?Sized>(
        d: &D,
        fid: &str,
        signer: &str,
        member: &str,
        role: Option<&str>,
        effective_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let w = ts::sign_family_membership_widening(
            signer,
            FamilyMembershipWidening {
                family_key_id: fid.to_owned(),
                member_key_id: member.to_owned(),
                joined_at: ms(effective_at),
                effective_at: ms(effective_at),
                role: role.map(str::to_owned),
                persist_row_hash: String::new(),
            },
        );
        // v62.0.0 (flip wave 2, E5) — as `widen_community`.
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            use crate::federation::edition2::group_fixtures as gf;
            let group = crate::federation::edition2::fixture_switch::kid(fid);
            let head = gf::held_head(d, &group).await.map(|(h, _)| h);
            let voices = gf::family_widening_voices(&w, head.as_ref());
            return settled(d, gf::put_voices(d, &voices).await?).await;
        }
        d.put_family_membership_widening(w).await
    }

    async fn active_in_community<D: FederationDirectory + ?Sized>(
        d: &D,
        cid: &str,
        k: &str,
    ) -> bool {
        d.active_community_members(cid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == k)
    }

    // ── I210 ──────────────────────────────────────────────────────────────
    /// **I210 — the proposal reaches its invitee and nobody else.** K (not a
    /// member) reads the proposal naming K; a stranger does not; K reads no
    /// other room row. Rust twin on every backend; SQL twin through
    /// `ReadEngine::list_attestations` on sqlite / postgres.
    pub async fn i210_the_proposal_reaches_its_invitee<B>(d: &B, s: &str)
    where
        B: FederationDirectory + crate::ceg::ReadEngine,
    {
        use crate::scope::caller_scope_from_directory;
        let (cid, founder, k, stranger) = (
            format!("i210-c-{s}"),
            format!("i210-f-{s}"),
            format!("i210-k-{s}"),
            format!("i210-x-{s}"),
        );
        reg(d, &[&cid, &founder, &k, &stranger]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, founder, k, stranger) =
            (id_of(&cid), id_of(&founder), id_of(&k), id_of(&stranger));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .expect("I210: the founder founds the room");
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            Utc::now(),
            Some(Duration::days(7)),
        );
        put_e2(d, &p)
            .await
            .expect("I210: the founder's proposal is admitted");
        let reads = |caller: &str| {
            let caller = caller.to_owned();
            let founder = founder.clone();
            let p = p.clone();
            async move {
                let scope = caller_scope_from_directory(d, &caller).await.unwrap();
                let rust =
                    scope.admits_membership_proposal(
                        &p.cohort_scope,
                        Some(PROPOSAL_DIMENSION),
                        &p.subject_key_ids,
                    ) || scope.admits(&p.cohort_scope, &p.attested_key_id, Some(&cid_of(&p)), None);
                let sql = match crate::ceg::ReadEngine::list_attestations(
                    d,
                    crate::ceg::AttestationFilter {
                        attesting_key_id: Some(founder),
                        dimension_prefixes: vec!["membership:".into()],
                        ..Default::default()
                    },
                    None,
                    10,
                    scope,
                )
                .await
                {
                    Ok(page) => Some(page.items.len()),
                    Err(crate::ceg::Error::Backend(m))
                        if m.contains("no relational read substrate") =>
                    {
                        None
                    }
                    Err(e) => panic!("I210: list_attestations: {e}"),
                };
                (rust, sql)
            }
        };
        let (rust, sql) = reads(&k).await;
        assert!(rust, "I210: the invitee reads its proposal (Rust twin)");
        if let Some(n) = sql {
            assert_eq!(n, 1, "I210: the invitee reads its proposal (SQL twin)");
        }
        let (rust, sql) = reads(&stranger).await;
        assert!(!rust, "I210: a stranger does not (Rust twin)");
        if let Some(n) = sql {
            assert_eq!(n, 0, "I210: a stranger does not (SQL twin)");
        }
        let (rust, sql) = reads(&founder).await;
        assert!(rust, "I210: the member reads it (Rust twin)");
        if let Some(n) = sql {
            assert_eq!(n, 1, "I210: the member reads it (SQL twin)");
        }
    }

    fn cid_of(p: &Attestation) -> String {
        crate::federation::admission::envelope_cohort_target(&p.attestation_envelope)
            .unwrap()
            .unwrap_or_default()
            .to_owned()
    }

    // ── I211 ──────────────────────────────────────────────────────────────
    /// **I211 — K's reply is admitted at a group K is not in; a stranger's is
    /// not; a reply ahead of its proposal is retryable.**
    pub async fn i211_the_reply_arm<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        let (cid, founder, k, stranger) = (
            format!("i211-c-{s}"),
            format!("i211-f-{s}"),
            format!("i211-k-{s}"),
            format!("i211-x-{s}"),
        );
        reg(d, &[&cid, &founder, &k, &stranger]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, founder, k, stranger) =
            (id_of(&cid), id_of(&founder), id_of(&k), id_of(&stranger));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            Utc::now(),
            Some(Duration::days(7)),
        );
        // ahead of its proposal: retryable, then admitted once it lands
        let early = reply(&k, &k, &p, true, Utc::now());
        let e = put_e2(d, &early)
            .await
            .expect_err("I211: a reply ahead of its proposal");
        assert_eq!(rule_of(&e), RULE_PROPOSAL_UNRESOLVED, "I211: {e}");
        assert!(crate::federation::membership_acceptance::is_retryable_rule(
            rule_of(&e)
        ));
        put_e2(d, &p).await.unwrap();
        // a stranger replying as K (their own signature, K's name): mismatch
        let forged = reply(&stranger, &k, &p, true, Utc::now());
        let e = put_e2(d, &forged)
            .await
            .expect_err("I211: a stranger's reply");
        // refused BY NAME at the reply arm (the signer does not act for the
        // invitee), not left to a later, unrelated standing gate
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_MISMATCH, "I211: {e:?}");
        // a stranger replying as themselves: not the invitee
        let own = reply(&stranger, &stranger, &p, true, Utc::now());
        let e = put_e2(d, &own)
            .await
            .expect_err("I211: a non-invitee's reply");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_MISMATCH, "I211: {e}");
        put_e2(d, &early)
            .await
            .expect("I211: the invitee's acceptance is admitted on retry");
        assert!(
            !active_in_community(d, &cid, &k).await,
            "I211: accepting is not joining"
        );
    }

    pub async fn i212_growth_needs_acceptance<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        let (cid, fid, founder, k, j) = (
            format!("i212-c-{s}"),
            format!("i212-f-{s}"),
            format!("i212-founder-{s}"),
            format!("i212-k-{s}"),
            format!("i212-j-{s}"),
        );
        reg(d, &[&cid, &fid, &founder, &k, &j]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, fid, founder, k, j) = (
            id_of(&cid),
            id_of(&fid),
            id_of(&founder),
            id_of(&k),
            id_of(&j),
        );
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let now = Utc::now();
        let e = widen_community(d, &cid, &[&founder], &k, None, now)
            .await
            .expect_err("I212: a widening without an acceptance");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_UNRESOLVED, "I212: {e}");
        assert!(!active_in_community(d, &cid, &k).await);
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &p).await.unwrap();
        put_e2(d, &reply(&k, &k, &p, true, now)).await.unwrap();
        widen_community(d, &cid, &[&founder], &k, None, now)
            .await
            .expect("I212: with the acceptance the widening is admitted");
        assert!(active_in_community(d, &cid, &k).await, "I212: K is in");
        // a role change of an active member is not a growth
        widen_community(
            d,
            &cid,
            &[&founder],
            &k,
            Some("moderator"),
            now + Duration::seconds(1),
        )
        .await
        .expect("I212: a role change needs no acceptance");
        // v61 (CIRISPersist#1123) — `founder_only` is refused above the
        // family, so the room is `quorum:1/1`, under which any member invites:
        // K (a plain member) may. The founders-only proposer rule on a room is
        // `open:self_admit`'s (I1502); on a family it is witnessed below.
        put(
            d,
            &proposal(&k, COMMUNITY, &cid, &j, None, now, Some(Duration::days(7))),
        )
        .await
        .expect("I212: a member's proposal under quorum:1/1");
        // the family plane, the same rule
        found_family(d, &fid, "founder_only", &[&founder], &[])
            .await
            .unwrap();
        // only a founder invites into a founder_only family either: K is no
        // member at all, and is refused whatever the membership gate says;
        // a non-founder member is refused by the proposer rule
        let pk = proposal(&k, FAMILY, &fid, &j, None, now, Some(Duration::days(7)));
        put_e2(d, &pk)
            .await
            .expect_err("I212: a non-member's family proposal");
        let m = format!("i212-m-{s}");
        reg(d, &[&m]).await;
        let m = id_of(&m);
        let pm = proposal(
            &founder,
            FAMILY,
            &fid,
            &m,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &pm).await.unwrap();
        put_e2(d, &reply(&m, &m, &pm, true, now)).await.unwrap();
        widen_family(d, &fid, &founder, &m, None, now)
            .await
            .expect("I212: a member (not a founder) joins the family");
        let e = put(
            d,
            &proposal(&m, FAMILY, &fid, &j, None, now, Some(Duration::days(7))),
        )
        .await
        .expect_err("I212: a non-founder member's proposal under founder_only (family)");
        assert!(
            matches!(e, Error::InvalidArgument(ref msg) if msg.contains("founder_only")),
            "I212: {e:?}"
        );
        let e = widen_family(d, &fid, &founder, &j, None, now)
            .await
            .expect_err("I212: a family widening without an acceptance");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_UNRESOLVED, "I212: {e}");
        let pf = proposal(
            &founder,
            FAMILY,
            &fid,
            &j,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &pf).await.unwrap();
        put_e2(d, &reply(&j, &j, &pf, true, now)).await.unwrap();
        widen_family(d, &fid, &founder, &j, None, now)
            .await
            .expect("I212: the family widening with an acceptance");
    }

    // ── I213 ──────────────────────────────────────────────────────────────
    /// **I213 — a decline is terminal; the opposite reply is refused.**
    pub async fn i213_decline_is_terminal<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        let (cid, founder, k) = (
            format!("i213-c-{s}"),
            format!("i213-f-{s}"),
            format!("i213-k-{s}"),
        );
        reg(d, &[&cid, &founder, &k]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, founder, k) = (id_of(&cid), id_of(&founder), id_of(&k));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let now = Utc::now();
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &p).await.unwrap();
        put_e2(d, &reply(&k, &k, &p, false, now))
            .await
            .expect("I213: K declines");
        let e = put_e2(d, &reply(&k, &k, &p, true, now))
            .await
            .expect_err("I213: an acceptance after the decline");
        assert_eq!(rule_of(&e), RULE_REPLY_CONFLICT, "I213: {e}");
        let e = widen_community(d, &cid, &[&founder], &k, None, now)
            .await
            .expect_err("I213: no growth after a decline");
        // a decline-only history is TERMINAL, never the retryable "not held
        // yet" (CIRISEdge#754 found the gate ranked declines only among
        // acceptances)
        assert_eq!(rule_of(&e), RULE_DECLINED, "I213: {e}");
        // an acceptance first, then a decline: the decline is refused too, and
        // a later proposal is a new invitation
        let p2 = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &p2).await.unwrap();
        put_e2(d, &reply(&k, &k, &p2, true, now)).await.unwrap();
        let e = put_e2(d, &reply(&k, &k, &p2, false, now))
            .await
            .expect_err("I213: a decline after the acceptance");
        assert_eq!(rule_of(&e), RULE_REPLY_CONFLICT, "I213: {e}");
        widen_community(d, &cid, &[&founder], &k, None, now)
            .await
            .expect("I213: the second invitation, accepted, admits");
        // J declines one invitation and accepts another that has since
        // expired: with an acceptance on record the decline does not decide,
        // and the answer is EXPIRED, not declined
        let j = format!("i213-j-{s}");
        reg(d, &[&j]).await;
        let j = id_of(&j);
        let pa = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &j,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &pa).await.unwrap();
        put_e2(d, &reply(&j, &j, &pa, false, now)).await.unwrap();
        let t0 = now - Duration::days(20);
        let pb = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &j,
            None,
            t0,
            Some(Duration::days(7)),
        );
        put_e2(d, &pb).await.unwrap();
        put_e2(d, &reply(&j, &j, &pb, true, t0)).await.unwrap();
        let e = widen_community(d, &cid, &[&founder], &j, None, now)
            .await
            .expect_err("I213: growth past the accepted invitation's expiry");
        assert_eq!(rule_of(&e), RULE_PROPOSAL_EXPIRED, "I213: {e}");
    }

    // ── I214 ──────────────────────────────────────────────────────────────
    /// **I214 — expiry is judged on the signed instants; the proposal's TTL
    /// is required and bounded; a withdrawn proposal is expired.**
    pub async fn i214_expiry_on_signed_instants<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        let (cid, founder, k, j, m) = (
            format!("i214-c-{s}"),
            format!("i214-f-{s}"),
            format!("i214-k-{s}"),
            format!("i214-j-{s}"),
            format!("i214-m-{s}"),
        );
        reg(d, &[&cid, &founder, &k, &j, &m]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, founder, k, j, m) = (
            id_of(&cid),
            id_of(&founder),
            id_of(&k),
            id_of(&j),
            id_of(&m),
        );
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let t0 = Utc::now() - Duration::days(20);
        for ttl in [None, Some(Duration::seconds(0)), Some(Duration::days(31))] {
            let e = put_e2(d, &proposal(&founder, COMMUNITY, &cid, &k, None, t0, ttl))
                .await
                .expect_err("I214: a proposal with no / zero / >30-day TTL");
            // v62.0.0 (wave GC6) — the TTL is the row's own bytes: refused
            // (never held), by the gate or by the edition-2 payload check.
            assert!(
                matches!(e, Error::InvalidArgument(ref m) if !m.starts_with("held "))
                    || matches!(e, Error::MalformedRow { .. }),
                "I214: {e:?}"
            );
        }
        // proposal at t0, live 7 days (expired now)
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            t0,
            Some(Duration::days(7)),
        );
        put_e2(d, &p).await.unwrap();
        // the acceptance signed after the expiry
        put_e2(d, &reply(&k, &k, &p, true, t0 + Duration::days(8)))
            .await
            .unwrap();
        let e = widen_community(d, &cid, &[&founder], &k, None, t0 + Duration::days(1))
            .await
            .expect_err("I214: an acceptance signed after expires_at");
        assert_eq!(rule_of(&e), RULE_PROPOSAL_EXPIRED, "I214: {e}");
        // accepted in time, but the growth signed after the expiry
        let pj = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &j,
            None,
            t0,
            Some(Duration::days(7)),
        );
        put_e2(d, &pj).await.unwrap();
        put_e2(d, &reply(&j, &j, &pj, true, t0 + Duration::days(1)))
            .await
            .unwrap();
        let e = widen_community(d, &cid, &[&founder], &j, None, t0 + Duration::days(9))
            .await
            .expect_err("I214: a growth signed after expires_at");
        assert_eq!(rule_of(&e), RULE_PROPOSAL_EXPIRED, "I214: {e}");
        widen_community(d, &cid, &[&founder], &j, None, t0 + Duration::days(2))
            .await
            .expect("I214: in time on both instants, the growth admits");
        // a proposal its proposer withdrew is expired
        let now = Utc::now();
        let pm = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &m,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &pm).await.unwrap();
        put_e2(d, &reply(&m, &m, &pm, true, now)).await.unwrap();
        let mut w = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &founder,
            &founder,
            &serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "references_attestation_id": pm.attestation_id,
                "withdrawal_reason": "rescinded",
            }),
        );
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.weight = None;
        ts::seal_row_in_place(&founder, &mut w);
        put_e2(d, &w)
            .await
            .expect("I214: the proposer withdraws the proposal");
        let e = widen_community(d, &cid, &[&founder], &m, None, now)
            .await
            .expect_err("I214: a withdrawn proposal");
        assert_eq!(rule_of(&e), RULE_PROPOSAL_EXPIRED, "I214: {e}");
    }

    // ── I215 ──────────────────────────────────────────────────────────────
    /// **I215 — group, hash and role must agree.**
    pub async fn i215_mismatch<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        let (cid, founder, k) = (
            format!("i215-c-{s}"),
            format!("i215-f-{s}"),
            format!("i215-k-{s}"),
        );
        reg(d, &[&cid, &founder, &k]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, founder, k) = (id_of(&cid), id_of(&founder), id_of(&k));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let now = Utc::now();
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            Some("member"),
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &p).await.unwrap();
        // a wrong hash
        let mut bad = p.clone();
        bad.original_content_hash = "00".repeat(32);
        let e = put_e2(d, &reply(&k, &k, &bad, true, now))
            .await
            .expect_err("I215: a reply binding another hash");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_MISMATCH, "I215: {e}");
        // a wrong role
        let mut r = reply(&k, &k, &p, true, now);
        r.attestation_envelope["role"] = "moderator".into();
        ts::seal_row_in_place(&k, &mut r);
        let e = put_e2(d, &r)
            .await
            .expect_err("I215: a reply accepting another role");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_MISMATCH, "I215: {e}");
        put_e2(d, &reply(&k, &k, &p, true, now)).await.unwrap();
        // the growth at another role than offered
        let e = widen_community(d, &cid, &[&founder], &k, Some("moderator"), now)
            .await
            .expect_err("I215: a growth at another role");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_MISMATCH, "I215: {e}");
        widen_community(d, &cid, &[&founder], &k, Some("member"), now)
            .await
            .expect("I215: at the offered role it admits");
    }

    // ── I216 ──────────────────────────────────────────────────────────────
    /// **I216 — a founding record admits only the members who signed it.**
    pub async fn i216_founding_signers<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        // v62.0.0 (JSON cut, E5) — on edition 2 a founding roster is its
        // founders' voices (T1.api §1): a roster listing a member who has not
        // voiced it is kept `Pending` and lands nothing (it is no longer
        // refused by name). The forged-co-signature arm and the served
        // `cosignatures` count are earlier-form proof shapes (T1.api §6
        // "delete"): a voice is a statement the door verifies.
        let (c1, c2, f1, f2, founder, cofounder, k) = (
            format!("i216-c1-{s}"),
            format!("i216-c2-{s}"),
            format!("i216-f1-{s}"),
            format!("i216-f2-{s}"),
            format!("i216-a-{s}"),
            format!("i216-b-{s}"),
            format!("i216-k-{s}"),
        );
        reg(d, &[&c1, &c2, &f1, &f2, &founder, &cofounder, &k]).await;
        found_community(d, &c1, "majority", &[&founder], &[&k])
            .await
            .expect("I216: an unsigned founding member leaves the roster pending");
        assert!(
            d.lookup_community(&id_of(&c1)).await.unwrap().is_none(),
            "I216: nothing stored"
        );
        found_community(d, &c2, "majority", &[&founder, &cofounder], &[])
            .await
            .expect("I216: every founding member signed");
        assert!(
            d.lookup_community(&id_of(&c2)).await.unwrap().is_some(),
            "I216: the fully voiced room lands"
        );
        found_family(d, &f1, "majority", &[&founder], &[&k])
            .await
            .expect("I216: an unsigned founding family member leaves it pending");
        assert!(
            d.lookup_family(&id_of(&f1)).await.unwrap().is_none(),
            "I216: nothing stored"
        );
        found_family(d, &f2, "majority", &[&founder, &cofounder], &[])
            .await
            .expect("I216: a co-signed family founding");
        assert!(
            d.lookup_family(&id_of(&f2)).await.unwrap().is_some(),
            "I216: the fully voiced family lands"
        );
    }

    // ── I217 ──────────────────────────────────────────────────────────────
    /// **I217 — a supersede never adds a member.**
    pub async fn i217_supersede_cannot_add<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        let (cid, founder, k) = (
            format!("i217-c-{s}"),
            format!("i217-f-{s}"),
            format!("i217-k-{s}"),
        );
        reg(d, &[&cid, &founder, &k]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, founder, k) = (id_of(&cid), id_of(&founder), id_of(&k));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let mut c = d.lookup_community(&cid).await.unwrap().unwrap();
        c.prev_head_digest = c.persist_row_hash.clone();
        c.members.push(CommunityMember {
            key_id: k.clone(),
            joined_at: ms(Utc::now()),
            role: None,
        });
        c.community_name = "renamed".into();
        // v62.0.0 (wave 3, E5) — under the switch a supersede is the roster's
        // next version naming the held head (T1.api §6), voiced by the founder;
        // when held, the JSON supersede door.
        let supersede = |c: crate::federation::types::Community| {
            let (cid, founder) = (cid.clone(), founder.clone());
            async move {
                use crate::federation::edition2::fixture_switch as e2;
                use crate::federation::edition2::group_fixtures as gf;
                if e2::emit_edition2() {
                    let (head, version) = gf::held_head(d, &cid).await.expect("I217: a held head");
                    let voices = gf::community_voices(
                        &ts::sign_community(&founder, c),
                        version + 1,
                        Some(&head),
                        e2::ms(Utc::now()),
                    );
                    settled(d, gf::put_voices(d, &voices).await?).await
                } else {
                    d.supersede_community(ts::sign_community(&founder, c), None)
                        .await
                        .map(|_| ())
                }
            }
        };
        let e = supersede(c.clone())
            .await
            .expect_err("I217: a supersede adding K");
        assert_eq!(rule_of(&e), RULE_SUPERSEDE_CANNOT_ADD, "I217: {e}");
        c.members.pop();
        supersede(c)
            .await
            .expect("I217: a supersede renaming only is admitted");
    }

    // ── I218 ──────────────────────────────────────────────────────────────
    /// **I218 — under a quorum protocol an accepted member still needs the
    /// group: accepted, awaiting the group.**
    pub async fn i218_accepted_awaiting_the_group<D: FederationDirectory + ?Sized>(d: &D, s: &str) {
        let (cid, a, b, c, k) = (
            format!("i218-c-{s}"),
            format!("i218-a-{s}"),
            format!("i218-b-{s}"),
            format!("i218-cc-{s}"),
            format!("i218-k-{s}"),
        );
        reg(d, &[&cid, &a, &b, &c, &k]).await;
        // v62.0.0 (wave 3, E5) — named by the ids the directory keys them by.
        let (cid, a, b, c, k) = (id_of(&cid), id_of(&a), id_of(&b), id_of(&c), id_of(&k));
        found_community(d, &cid, "majority", &[&a, &b, &c], &[])
            .await
            .unwrap();
        let now = Utc::now();
        let p = proposal(&a, COMMUNITY, &cid, &k, None, now, Some(Duration::days(7)));
        put(d, &p).await.expect("I218: one inviter proposes");
        put(d, &reply(&k, &k, &p, true, now)).await.unwrap();
        // v62.0.0 (wave 3, E5) — one voice of three is kept `Pending` (T1.api
        // §6: a quorum short does not move the head); the second voice of the
        // same widening completes it.
        // E5-fix1 (round 3) — `settled` answers the held voice as the
        // refusal-shaped `held count_short` (ruling 5: assert the wait).
        let e = widen_community(d, &cid, &[&a], &k, None, now)
            .await
            .expect_err("I218: one signature of three is held, pending the group");
        assert!(
            matches!(&e, Error::InvalidArgument(m)
            if m.starts_with(&format!(
                "held {}",
                crate::federation::edition2::fold::reason::COUNT_SHORT
            ))),
            "I218: {e:?}"
        );
        assert!(
            !active_in_community(d, &cid, &k).await,
            "I218: accepted, awaiting the group"
        );
        widen_community(d, &cid, &[&a, &b], &k, None, now)
            .await
            .expect("I218: at the group's majority it admits");
        assert!(
            active_in_community(d, &cid, &k).await,
            "I218: the majority lands the growth"
        );
    }

    // ── I219 ──────────────────────────────────────────────────────────────
    /// **I219 — two nodes, end to end through the planes.** The proposal on A
    /// reaches K's node B (which holds no roster); K accepts on B; A admits
    /// the acceptance and the widening; B, handed the room and the widening,
    /// admits both — and B refuses the widening before the acceptance exists
    /// there, exactly as A's local door would.
    pub async fn i219_two_nodes<D: FederationDirectory + ?Sized>(a: &D, b: &D, s: &str) {
        // v62.0.0 (JSON cut, E5) — the two nodes exchange edition-2
        // STATEMENTS through cut B's FILTERED serve path
        // (`edition2::serve::statements_served_to`, with the receiver as the
        // requester; the store's raw `edition2_statements_since` is never a
        // serve surface); the receiver puts each through its own door. Every
        // key is named by its identity-ref.
        use crate::federation::edition2::fixture_switch as e2;
        async fn replicate<D: FederationDirectory + ?Sized>(from: &D, to: &D, requester: &str) {
            let mut cursor = None;
            loop {
                let page = crate::federation::edition2::serve::statements_served_to(
                    from,
                    cursor.as_ref(),
                    1000,
                    Some(requester),
                )
                .await
                .expect("I219: serve statements");
                for st in &page.statements {
                    e2::put_statement(to, &st.bytes)
                        .await
                        .unwrap_or_else(|e| panic!("I219: a replicated statement: {e}"));
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
        }
        let (cid, founder, k) = (
            format!("i219-c-{s}"),
            format!("i219-f-{s}"),
            format!("i219-k-{s}"),
        );
        for n in [a, b] {
            reg(n, &[&cid, &founder, &k]).await;
        }
        found_community(a, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let (cid, founder, k) = (id_of(&cid), id_of(&founder), id_of(&k));
        let now = Utc::now();
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        put(a, &p).await.unwrap();
        // B holds no roster for the room: the subject's node stores the proposal.
        assert!(b.lookup_community(&cid).await.unwrap().is_none());
        e2::put_signed(b, &p)
            .await
            .expect("I219: K's node stores the proposal addressed to K");
        let acc = reply(&k, &k, &p, true, now);
        put(b, &acc).await.expect("I219: K accepts on its own node");
        e2::put_signed(a, &acc)
            .await
            .expect("I219: A admits K's acceptance");
        widen_community(a, &cid, &[&founder], &k, None, now)
            .await
            .expect("I219: A admits the growth");
        // B gets the room and the growth as A's statements; the widening is
        // judged again on B, and passes because the acceptance is held there.
        // The requester is B's node (its node key when set, else K, whose
        // node B is).
        let requester = b.node_key_id().unwrap_or_else(|| k.clone());
        replicate(a, b, &requester).await;
        assert!(
            active_in_community(b, &cid, &k).await,
            "I219: B admits the growth too"
        );
        // a third member, invited on A but whose acceptance never reached B:
        // B refuses the growth, retryably
        let j = format!("i219-j-{s}");
        for n in [a, b] {
            reg(n, &[&j]).await;
        }
        let j = id_of(&j);
        let pj = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &j,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(a, &pj).await.unwrap();
        put_e2(a, &reply(&j, &j, &pj, true, now)).await.unwrap();
        widen_community(a, &cid, &[&founder], &j, None, now)
            .await
            .unwrap();
        let e = widen_community(b, &cid, &[&founder], &j, None, now)
            .await
            .expect_err("I219: B has no acceptance for J");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_UNRESOLVED, "I219: {e}");
        let _ = RULE_DECLINED;
    }
}

#[cfg(test)]
mod run {
    use super::bodies;

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::bodies;
                #[tokio::test]
                async fn i210() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i210_the_proposal_reaches_its_invitee(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i211() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i211_the_reply_arm(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i212() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i212_growth_needs_acceptance(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i213() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i213_decline_is_terminal(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i214() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i214_expiry_on_signed_instants(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i215() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i215_mismatch(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i216() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i216_founding_signers(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i217() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i217_supersede_cannot_add(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i218() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i218_accepted_awaiting_the_group(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i219() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    bodies::i219_two_nodes(&a, &b, &bodies::suffix()).await
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
}
