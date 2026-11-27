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
    ) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
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
            // v62.0.0 (GID-fixtures-mech, .rev2) — the room's DERIVED id,
            // which the codec recorded for the name `cid`
            // (`fixture_switch::room_id`: it panics if no founding did).
            gf::put_voices(d, &voices).await?;
            return Ok(crate::federation::edition2::fixture_switch::room_id(cid));
        }
        d.put_community(signed).await.map(|_| cid.to_owned())
    }

    pub(crate) async fn found_family<D: FederationDirectory + ?Sized>(
        d: &D,
        fid: &str,
        protocol: &str,
        founders: &[&str],
        unsigned: &[&str],
    ) -> Result<String, Error> {
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
            gf::put_voices(d, &voices).await?;
            return Ok(crate::federation::edition2::fixture_switch::room_id(fid));
        }
        d.put_family(signed).await.map(|()| fid.to_owned())
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
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
        // E5-fix2 (round 6) — the proposer's standing is read from the roster
        // (other rows, CC 2.7.3): the proposal is HELD, and `put_e2` answers a
        // hold as its refusal-shaped error (its detail is the gate's text).
        let e = put_e2(
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
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
                // E5-fix2 (round 6) — the target by its node-computed row id
                // (`refs.target`), never the JSON row's chosen id.
                "references_attestation_id": crate::federation::edition2::fixture_switch::rid(&pm),
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let c1 = found_community(d, &c1, "majority", &[&founder], &[&k])
            .await
            .expect("I216: an unsigned founding member leaves the roster pending");
        assert!(
            d.lookup_community(&id_of(&c1)).await.unwrap().is_none(),
            "I216: nothing stored"
        );
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let c2 = found_community(d, &c2, "majority", &[&founder, &cofounder], &[])
            .await
            .expect("I216: every founding member signed");
        assert!(
            d.lookup_community(&id_of(&c2)).await.unwrap().is_some(),
            "I216: the fully voiced room lands"
        );
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let f1 = found_family(d, &f1, "majority", &[&founder], &[&k])
            .await
            .expect("I216: an unsigned founding family member leaves it pending");
        assert!(
            d.lookup_family(&id_of(&f1)).await.unwrap().is_none(),
            "I216: nothing stored"
        );
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let f2 = found_family(d, &f2, "majority", &[&founder, &cofounder], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "quorum:1/1", &[&founder], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(d, &cid, "majority", &[&a, &b, &c], &[])
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let cid = found_community(a, &cid, "quorum:1/1", &[&founder], &[])
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

    // ── I4419 ─────────────────────────────────────────────────────────────
    /// **I4419** (WD-fix16; the join carriage as Constitution ruled 11-23) —
    /// alice's node NA (store A) and bob's node NB (store B) are placed at
    /// NOTHING public: NA at `self` + room R, NB at `self` only. Everything
    /// crosses by the serve rule (`deliver_served`), except the two
    /// envelopes, which are built by the producers and admitted row by row
    /// through the receiver's ordinary door:
    /// - B pulls A: nothing of R (no roster, no proposal, no occurrence of
    ///   alice);
    /// - THE INVITATION (`join_invitation_rows`) on B: the proposal is held
    ///   (R's roster is not), and alice's occurrence is held;
    /// - bob accepts on B and re-signs NB at R: HELD on B (no roster there);
    /// - THE ANSWER (`join_answer_rows`) on A: bob's occurrence, the
    ///   acceptance, and NB's R-placed binding are admitted (the invitee who
    ///   answered places its node: `owner_binding_placed_by_an_invitee`);
    ///   A's owner fold names bob as NB's owner;
    /// - A widens R to bob; B pulls A: B now holds R and bob is a member;
    /// - a third node C, handed the same link traffic (every pull from A and
    ///   B, as C's node) but no envelope, holds nothing naming R.
    pub async fn i4419_the_join_carriage<D: FederationDirectory + ?Sized>(
        a: &D,
        b: &D,
        c: &D,
        s: &str,
    ) {
        use crate::federation::edition2::fixture_occurrence::put_occurrence_signed;
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::key_grant_invariants::two_node::{
            deliver_served, deliver_statements, place_device_at_groups, re_sign_owner_binding,
        };
        use crate::federation::membership_acceptance::{join_answer_rows, join_invitation_rows};
        use crate::federation::types::identity_type::NODE;
        use crate::federation::types::{device_class, IdentityOccurrence};
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let k = |n: &str| format!("i4419-{n}-{s}");
        let (cid, alice, bob) = (k("room"), k("alice"), k("bob"));
        for n in [a, b, c] {
            reg(n, &[&cid, &alice, &bob]).await;
        }
        let room = found_community(a, &cid, "quorum:1/1", &[&alice], &[])
            .await
            .unwrap();
        let (room, alice, bob) = (id_of(&room), id_of(&alice), id_of(&bob));
        let kem = || {
            let (_xp, x, _mp, ml) =
                crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x),
                ml_kem_768_base64: B64.encode(&ml),
            }
        };
        // The nodes and the persons' devices, each on its own store.
        let (na_seed, nb_seed, nc_seed) = (k("nodea"), k("nodeb"), k("nodec"));
        ts::register_hybrid_key_as(a, &na_seed, &na_seed, NODE).await;
        ts::register_hybrid_key_as(b, &nb_seed, &nb_seed, NODE).await;
        ts::register_hybrid_key_as(c, &nc_seed, &nc_seed, NODE).await;
        let (na, nb, nc) = (e2::kid(&na_seed), e2::kid(&nb_seed), e2::kid(&nc_seed));
        let (da_seed, db_seed) = (k("deva"), k("devb"));
        ts::register_hybrid_key_as(a, &da_seed, &da_seed, USER).await;
        ts::register_hybrid_key_as(b, &db_seed, &db_seed, USER).await;
        let (da, db) = (e2::kid(&da_seed), e2::kid(&db_seed));
        let occ = |identity: &str, device: &str| IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: device.to_owned(),
            device_class: device_class::PHONE.into(),
            hardware_attestation: None,
            asserted_at: Utc::now(),
            valid_until: None,
            encryption_pubkeys: Some(kem()),
            transport_binding: None,
            persist_row_hash: String::new(),
        };
        put_occurrence_signed(a, occ(&alice, &da))
            .await
            .expect("I4419: alice's device on A");
        put_occurrence_signed(b, occ(&bob, &db))
            .await
            .expect("I4419: bob's device on B");
        place_device_at_groups(
            a.as_dyn_directory(),
            &alice,
            &na,
            &na_seed,
            device_class::SERVER,
            Some(kem()),
            &[(COMMUNITY, &room)],
        )
        .await;
        place_device_at_groups(
            b.as_dyn_directory(),
            &bob,
            &nb,
            &nb_seed,
            device_class::SERVER,
            Some(kem()),
            &[],
        )
        .await;
        async fn holds<E: FederationDirectory + ?Sized>(
            d: &E,
            identity: &str,
            device: &str,
        ) -> bool {
            d.list_identity_occurrences_for(identity)
                .await
                .unwrap()
                .iter()
                .any(|o| o.occurrence_key_id == device)
        }
        // The link traffic: every pull, by the serve rule.
        deliver_served(a, b, &nb).await;
        deliver_served(b, a, &na).await;
        assert!(
            b.lookup_community(&room).await.unwrap().is_none(),
            "I4419: before the invitation B holds nothing of R"
        );
        assert!(
            !holds(b, &alice, &da).await,
            "I4419: before the invitation B holds no occurrence of alice"
        );
        // THE INVITATION, built on A, admitted on B row by row.
        let now = Utc::now();
        let p = proposal(
            &alice,
            COMMUNITY,
            &room,
            &bob,
            None,
            now,
            Some(Duration::days(7)),
        );
        put(a, &p).await.expect("I4419: alice invites bob on A");
        let invitation = join_invitation_rows(a, &p.attestation_id)
            .await
            .expect("I4419: the invitation's rows");
        deliver_statements(b, &invitation)
            .await
            .unwrap_or_else(|e| panic!("I4419: B admits the invitation's rows: {e}"));
        assert!(
            b.get_attestation(&p.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I4419: the proposal is held on B (R's roster is not)"
        );
        assert!(
            b.lookup_community(&room).await.unwrap().is_none(),
            "I4419: the invitee holds nothing of R's roster (CC 2.7.8)"
        );
        assert!(
            holds(b, &alice, &da).await,
            "I4419: alice's occurrence rode the invitation"
        );
        // bob answers on B and re-signs NB at R (held there).
        let acc = reply(&bob, &bob, &p, true, now);
        put(b, &acc).await.expect("I4419: bob accepts on B");
        let resigned = re_sign_owner_binding(
            b.as_dyn_directory(),
            &bob,
            &nb,
            &nb_seed,
            COMMUNITY,
            Some(&room),
        )
        .await;
        assert!(
            !matches!(
                resigned,
                crate::federation::edition2::ingest::StatementOutcome::Row { .. }
            ),
            "I4419: on B, with no roster of R, the R-placed binding is held: {resigned:?}"
        );
        // THE ANSWER, built on B, admitted on A row by row.
        let answer = join_answer_rows(b, &acc.attestation_id, &room)
            .await
            .expect("I4419: the answer's rows");
        deliver_statements(a, &answer)
            .await
            .unwrap_or_else(|e| panic!("I4419: A admits the answer's rows: {e}"));
        assert!(
            a.get_attestation(&acc.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I4419: the acceptance is held on A"
        );
        assert!(
            holds(a, &bob, &db).await,
            "I4419: bob's occurrence rode the answer"
        );
        assert_eq!(
            crate::federation::admission::owner_of(a, &nb)
                .await
                .unwrap(),
            Some(bob.clone()),
            "I4419: NB's R-placed binding is admitted on A: its owner is bob"
        );
        // The widening seats bob; the welcome is ordinary cohort delivery.
        widen_community(a, &room, &[&alice], &bob, None, now)
            .await
            .expect("I4419: A seats bob");
        deliver_served(a, b, &nb).await;
        assert!(
            b.lookup_community(&room).await.unwrap().is_some(),
            "I4419: seated, B is served R"
        );
        assert!(
            active_in_community(b, &room, &bob).await,
            "I4419: B holds bob as a member of R"
        );
        // The third node: the same link traffic, no envelope.
        deliver_served(a, c, &nc).await;
        deliver_served(b, c, &nc).await;
        assert!(
            c.lookup_community(&room).await.unwrap().is_none(),
            "I4419: C holds no roster of R"
        );
        assert!(
            c.get_attestation(&p.attestation_id)
                .await
                .unwrap()
                .is_none()
                && c.get_attestation(&acc.attestation_id)
                    .await
                    .unwrap()
                    .is_none(),
            "I4419: C holds neither the proposal nor the answer"
        );
        assert!(
            !holds(c, &alice, &da).await && !holds(c, &bob, &db).await,
            "I4419: C holds no person's occurrence placed at R"
        );
        assert_ne!(
            crate::federation::admission::owner_of(c, &nb)
                .await
                .unwrap(),
            Some(bob.clone()),
            "I4419: C cannot name NB's owner"
        );
    }

    // ── I4420 ─────────────────────────────────────────────────────────────
    /// **I4420** (WD-fix16 part 2; the negatives of WD-fix16a's gate
    /// `owner_binding_placed_by_an_invitee`) — on the store that holds room
    /// R's roster, an owner binding placed at R is NOT admitted, but HELD
    /// (the generic write-scope gate's hold, `write_scope_refused`: a row
    /// naming a held group whose owner is no member waits for the roster to
    /// change, CC 2.7.3, never refused), when its owner is:
    /// - not an invitee of R at all;
    /// - an invitee with NO held acceptance (it has not answered);
    /// - an invitee whose invitation LAPSED (a proposal past its expiry: the
    ///   acceptance of it is not held, and it is no live invitation).
    ///
    /// In each case the owner fold does not name the owner for the node.
    pub async fn i4420_the_invitee_gate_admits_only_an_answered_invitation<
        D: FederationDirectory + ?Sized,
    >(
        a: &D,
        s: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::key_grant_invariants::two_node::re_sign_owner_binding;
        use crate::federation::types::identity_type::NODE;
        let k = |n: &str| format!("i4420-{n}-{s}");
        let (cid, alice, x, y, z) = (k("room"), k("alice"), k("xout"), k("ynoans"), k("zlapsed"));
        reg(a, &[&cid, &alice, &x, &y, &z]).await;
        let room = found_community(a, &cid, "quorum:1/1", &[&alice], &[])
            .await
            .unwrap();
        let (room, alice, x, y, z) = (id_of(&room), id_of(&alice), id_of(&x), id_of(&y), id_of(&z));
        let now = Utc::now();
        // y: invited, never answers.
        let py = proposal(
            &alice,
            COMMUNITY,
            &room,
            &y,
            None,
            now,
            Some(Duration::days(7)),
        );
        put(a, &py).await.expect("I4420: y is invited");
        // z: invited by a proposal that had lapsed when z answered.
        let pz = proposal(
            &alice,
            COMMUNITY,
            &room,
            &z,
            None,
            now - Duration::days(8),
            Some(Duration::days(7)),
        );
        let _ = put_e2(a, &pz).await;
        let _ = put_e2(a, &reply(&z, &z, &pz, true, now)).await;
        for (owner, label) in [(&x, "not an invitee"), (&y, "unanswered"), (&z, "lapsed")] {
            let node_seed = k(&format!("node{label}").replace(' ', ""));
            ts::register_hybrid_key_as(a, &node_seed, &node_seed, NODE).await;
            let node = e2::kid(&node_seed);
            let out = re_sign_owner_binding(
                a.as_dyn_directory(),
                owner,
                &node,
                &node_seed,
                COMMUNITY,
                Some(&room),
            )
            .await;
            assert!(
                !matches!(out, StatementOutcome::Row { .. }),
                "I4420: a binding placed at R by an owner who is {label} is not admitted: {out:?}"
            );
            assert_ne!(
                crate::federation::admission::owner_of(a, &node)
                    .await
                    .unwrap(),
                Some(owner.clone()),
                "I4420: {label}: the owner fold does not name the owner"
            );
        }
    }

    // ── I4422 ─────────────────────────────────────────────────────────────
    /// **I4422** (WD-fix16e; CC 3.1.3.2, the room-key form) — a PRIVATE room
    /// (`membership: private`) takes no identity-key carriage:
    /// - `join_invitation_rows` refuses its proposal by name (InvalidArgument
    ///   naming the private room), where the same producer serves a room
    ///   with no `membership` (absent reads public);
    /// - `join_answer_rows` refuses on a node that holds the room's record;
    /// - the proposer's invitee gate admits no identity-key owner binding at
    ///   it, although the invitee has answered: `owner_of` does not name the
    ///   owner.
    pub async fn i4422_a_private_room_takes_no_identity_carriage<
        D: FederationDirectory + ?Sized,
    >(
        a: &D,
        s: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::key_grant_invariants::two_node::re_sign_owner_binding;
        use crate::federation::membership_acceptance::{join_answer_rows, join_invitation_rows};
        use crate::federation::types::identity_type::NODE;
        let k = |n: &str| format!("i4422-{n}-{s}");
        let (pcid, vcid, alice, bob) = (k("private"), k("visible"), k("alice"), k("bob"));
        reg(a, &[&pcid, &vcid, &alice, &bob]).await;
        let private = found_room_with_blob(
            a,
            &pcid,
            "quorum:1/1",
            &[&alice],
            &[],
            Some(serde_json::json!({ "membership": "private" })),
        )
        .await
        .unwrap();
        let visible = found_community(a, &vcid, "quorum:1/1", &[&alice], &[])
            .await
            .unwrap();
        let (private, visible, alice, bob) =
            (id_of(&private), id_of(&visible), id_of(&alice), id_of(&bob));
        let now = Utc::now();
        // The visible room: the producer serves the invitation.
        let pv = proposal(
            &alice,
            COMMUNITY,
            &visible,
            &bob,
            None,
            now,
            Some(Duration::days(7)),
        );
        put(a, &pv)
            .await
            .expect("I4422: the visible room's invitation");
        join_invitation_rows(a, &pv.attestation_id)
            .await
            .expect("I4422: an identity-seated room's invitation is produced");
        // The private room: refused by name.
        let pp = proposal(
            &alice,
            COMMUNITY,
            &private,
            &bob,
            None,
            now,
            Some(Duration::days(7)),
        );
        put(a, &pp)
            .await
            .expect("I4422: the private room's invitation row");
        let e = join_invitation_rows(a, &pp.attestation_id)
            .await
            .expect_err("I4422: no identity-key invitation for a private room");
        assert!(
            matches!(&e, Error::InvalidArgument(m) if m.contains("PRIVATE room")),
            "I4422: refused by name: {e:?}"
        );
        // bob answers; the answer producer and the invitee gate both refuse.
        let acc = reply(&bob, &bob, &pp, true, now);
        let _ = put_e2(a, &acc).await;
        let e = join_answer_rows(a, &acc.attestation_id, &private)
            .await
            .expect_err("I4422: no identity-key answer for a private room");
        assert!(
            matches!(&e, Error::InvalidArgument(m) if m.contains("PRIVATE room")),
            "I4422: refused by name: {e:?}"
        );
        let nb_seed = k("nodeb");
        ts::register_hybrid_key_as(a, &nb_seed, &nb_seed, NODE).await;
        let nb = e2::kid(&nb_seed);
        let out = re_sign_owner_binding(
            a.as_dyn_directory(),
            &bob,
            &nb,
            &nb_seed,
            COMMUNITY,
            Some(&private),
        )
        .await;
        assert!(
            !matches!(
                out,
                crate::federation::edition2::ingest::StatementOutcome::Row { .. }
            ),
            "I4422: an identity-key binding at a private room is not admitted: {out:?}"
        );
        assert_ne!(
            crate::federation::admission::owner_of(a, &nb)
                .await
                .unwrap(),
            Some(bob.clone()),
            "I4422: the owner fold does not name bob"
        );
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
                async fn i4422() {
                    let Some(a) = $fresh.await else { return };
                    Box::pin(bodies::i4422_a_private_room_takes_no_identity_carriage(
                        &a,
                        &bodies::suffix(),
                    ))
                    .await
                }
                #[tokio::test]
                async fn i4420() {
                    let Some(a) = $fresh.await else { return };
                    Box::pin(
                        bodies::i4420_the_invitee_gate_admits_only_an_answered_invitation(
                            &a,
                            &bodies::suffix(),
                        ),
                    )
                    .await
                }
                #[tokio::test]
                async fn i4419() {
                    let (Some(a), Some(b), Some(c)) = ($fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    Box::pin(bodies::i4419_the_join_carriage(
                        &a,
                        &b,
                        &c,
                        &bodies::suffix(),
                    ))
                    .await
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
