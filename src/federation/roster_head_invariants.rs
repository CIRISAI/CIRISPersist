//! v53.0.0 (CC 3.2 T6, rc7 `36432c6`) — **roster rows and the head.**
//! I450–I459.
//!
//! The conferring quorum covers a roster row with a new version; the substrate
//! never synthesises one and enforces three consequences:
//!
//! - **I450** (i) a version of a conferring family that does not reflect an
//!   effective revocation is refused `lineage_version_disagrees_with_roster_fold`
//!   naming the key; the version that drops the seat is admitted.
//! - **I451** (i) the same for a widening, and for a widening that re-roles a
//!   seat: the version must carry the seat AND its role.
//! - **I452** (i) only a witnessed lineage is judged: a family whose head names
//!   no charter takes a version the planes disagree with.
//! - **I453** the one comparison on the community arm: a revocation of a room
//!   names exactly its key until a record reflects it, and only while it is
//!   after the floor (the held head's instant) and effective at the instant.
//! - **I454** (ii) a row older than one `witness_cadence_secs` that no version
//!   covers lags the head (`lineage_head_lags_roster`, served on the witness
//!   view with its keys and instant); a younger row does not; the covering
//!   version clears it.
//! - **I455** (ii) with witnessed mode on a witness's cosign of the lagging held
//!   head is refused `lineage_head_lags_roster`; with it off the cosign is
//!   stored and the lag is still reported.
//! - **I456** (iii) the removal takes effect at its `effective_at`, before any
//!   version covers it: the fold drops the seat while the head still lists it.
//! - **I457** the accord's version needs signatures from a strict majority of
//!   its STANDING roster — two of five is short where `quorum:2/3` reads two,
//!   three is enough, and one key's two signatures count once.
//! - **I458** from disk: every version door runs consequence (i), the cosign
//!   door runs (ii), and the accord head door counts the standing majority.
//! - **I459** (ii) an authorized accord `roster_change` decision anchored on the
//!   held accord head, with its window closed, lags the head; one anchored on
//!   another head, an unauthorized one, or one whose window is open does not.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::canonical_community::root_witness_view;
    use crate::federation::lineage_witness::{
        LineageCosignOutcome, LineageCosignRefusal, LineageHeadCosign,
    };
    use crate::federation::membership_acceptance::test_support::ConsentedWidening as _;
    use crate::federation::operational::test_support as ops;
    use crate::federation::roster_head::{
        fold_disagreement, roster_lag, LineageRecord, LINEAGE_HEAD_LAGS_ROSTER,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::{
        attestation_type, identity_type, Family, FamilyMember, FamilyMembershipRevocation,
        FamilyMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    const PROTOCOL: &str = "quorum:2/3";

    fn hours(h: i64) -> chrono::Duration {
        chrono::Duration::hours(h)
    }

    /// Three registered holders; the distinguishing part LEADS the key id (the
    /// test signer seeds from its first 32 bytes).
    async fn holders(d: &dyn FederationDirectory, tag: &str) -> Vec<String> {
        let keys: Vec<String> = (0..3).map(|i| format!("rh{i}-{tag}")).collect();
        for k in &keys {
            ops::register_typed_key(d, k, identity_type::NODE)
                .await
                .unwrap_or_else(|e| panic!("{tag}: register {k}: {e}"));
        }
        keys
    }

    /// A conferring family: its founding head names a charter (`digest`).
    async fn conferring(d: &dyn FederationDirectory, tag: &str, keys: &[String]) -> String {
        let fam = format!("rf-{tag}");
        ops::seed_test_family_naming(d, &fam, keys, PROTOCOL, &"ab".repeat(32))
            .await
            .unwrap();
        fam
    }

    async fn head(d: &dyn FederationDirectory, fam: &str) -> Family {
        d.lookup_family(fam).await.unwrap().expect("family held")
    }

    /// `who` leaves `fam` on their own signature, effective `at`.
    async fn leave(
        d: &dyn FederationDirectory,
        fam: &str,
        who: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        d.put_family_membership_revocation(ts::sign_family_membership_revocation(
            who,
            FamilyMembershipRevocation {
                family_key_id: fam.to_owned(),
                removed_identity_key_id: who.to_owned(),
                removed_at: at,
                effective_at: at,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("{who} leaves {fam}: {e}"));
    }

    /// `member` widened into `fam` with `role`, signed by `signers`.
    async fn widen(
        d: &dyn FederationDirectory,
        fam: &str,
        member: &str,
        role: Option<&str>,
        at: chrono::DateTime<chrono::Utc>,
        signers: &[&str],
    ) {
        let w = FamilyMembershipWidening {
            family_key_id: fam.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: at,
            effective_at: at,
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        };
        let mut s = ts::sign_family_membership_widening(signers[0], w);
        for c in &signers[1..] {
            ts::cosign_family_membership_widening(&mut s, c);
        }
        d.put_family_membership_widening_consented(s)
            .await
            .unwrap_or_else(|e| panic!("{member} widened into {fam}: {e}"));
    }

    /// A version of `fam` with `members`, naming the held head, through the
    /// local supersede door, signed by `signer`.
    async fn version(
        d: &dyn FederationDirectory,
        fam: &str,
        members: Vec<FamilyMember>,
        signer: &str,
    ) -> Result<u32, Error> {
        let held = head(d, fam).await;
        let mut next = held.clone();
        next.members = members;
        next.prev_head_digest = held.persist_row_hash.clone();
        next.persist_row_hash = String::new();
        d.supersede_family(ts::sign_family(signer, next), None)
            .await
    }

    fn without(held: &Family, key: &str) -> Vec<FamilyMember> {
        held.members
            .iter()
            .filter(|m| m.key_id != key)
            .cloned()
            .collect()
    }

    fn with(held: &Family, key: &str, role: Option<&str>) -> Vec<FamilyMember> {
        let mut out = without(held, key);
        out.push(FamilyMember {
            key_id: key.to_owned(),
            joined_at: held.founded_at,
            role: role.map(str::to_owned),
        });
        out
    }

    fn disagrees(e: &Error, key: &str) -> bool {
        matches!(e, Error::LineageVersionDisagreesWithFold { keys, .. } if keys == &[key.to_owned()])
            && e.kind() == crate::federation::roster_head::LINEAGE_VERSION_DISAGREES_WITH_FOLD
    }

    /// **I450** — (i) an effective revocation the version does not reflect.
    pub async fn i450_a_version_reflects_a_revocation(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = conferring(d, tag, &keys).await;
        leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
        let held = head(d, &fam).await;
        let e = version(d, &fam, held.members.clone(), &keys[0])
            .await
            .expect_err("a version still listing the leaver is refused");
        assert!(disagrees(&e, &keys[2]), "{tag} I450: {e:?}");
        assert_eq!(head(d, &fam).await, held, "{tag} I450: nothing written");
        version(d, &fam, without(&held, &keys[2]), &keys[0])
            .await
            .unwrap_or_else(|e| panic!("{tag} I450: the version dropping the seat: {e}"));
    }

    /// **I451** — (i) a widening, and a re-role, the version does not reflect.
    pub async fn i451_a_version_reflects_a_widening(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = conferring(d, tag, &keys).await;
        let joiner = format!("rj-{tag}");
        ops::register_typed_key(d, &joiner, identity_type::NODE)
            .await
            .unwrap();
        widen(
            d,
            &fam,
            &joiner,
            Some("member"),
            chrono::Utc::now() - hours(1),
            &[&keys[0], &keys[1]],
        )
        .await;
        let held = head(d, &fam).await;
        let e = version(d, &fam, held.members.clone(), &keys[0])
            .await
            .expect_err("a version without the widened seat is refused");
        assert!(disagrees(&e, &joiner), "{tag} I451 seat: {e:?}");
        let e = version(d, &fam, with(&held, &joiner, Some("founder")), &keys[0])
            .await
            .expect_err("the seat with another role is refused");
        assert!(disagrees(&e, &joiner), "{tag} I451 role: {e:?}");
        version(d, &fam, with(&held, &joiner, Some("member")), &keys[0])
            .await
            .unwrap_or_else(|e| panic!("{tag} I451: the covering version: {e}"));
    }

    /// **I452** — (i) judges only a witnessed lineage.
    pub async fn i452_only_a_witnessed_lineage_is_judged(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = format!("rn-{tag}");
        ops::seed_test_family(d, &fam, &keys, PROTOCOL)
            .await
            .unwrap();
        leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
        let held = head(d, &fam).await;
        assert!(
            !LineageRecord::Family(&held).is_witnessed(),
            "{tag} I452: a head naming no charter is no lineage"
        );
        version(d, &fam, held.members.clone(), &keys[0])
            .await
            .unwrap_or_else(|e| panic!("{tag} I452: not judged: {e}"));
        assert!(
            roster_lag(d, &fam, chrono::Utc::now())
                .await
                .unwrap()
                .is_none(),
            "{tag} I452: and never lags"
        );
    }

    /// **I453** — the one comparison on the community arm.
    pub async fn i453_the_community_arm(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::types::{Community, CommunityMember, CommunityMembershipRevocation};
        let keys: Vec<String> = (0..3).map(|i| format!("rc{i}-{tag}")).collect();
        for k in &keys {
            ops::register_typed_key(d, k, identity_type::USER)
                .await
                .unwrap();
        }
        let id = format!("rr-{tag}");
        let founded_at = chrono::Utc::now() - hours(3);
        let row = Community {
            community_key_id: id.clone(),
            community_name: id.clone(),
            members: keys
                .iter()
                .map(|k| CommunityMember {
                    key_id: k.clone(),
                    joined_at: founded_at,
                    role: Some("founder".to_owned()),
                })
                .collect(),
            founded_at,
            consensus_protocol: PROTOCOL.to_owned(),
            policy_blob: None,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        };
        d.put_community(ts::sign_community(&keys[0], row))
            .await
            .unwrap_or_else(|e| panic!("{tag} I453: the room: {e}"));
        let at = chrono::Utc::now() - hours(1);
        d.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &keys[2],
            CommunityMembershipRevocation {
                community_key_id: id.clone(),
                removed_identity_key_id: keys[2].clone(),
                removed_at: at,
                effective_at: at,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag} I453: the leave: {e}"));
        let held = d.lookup_community(&id).await.unwrap().unwrap();
        let now = chrono::Utc::now();
        assert_eq!(
            fold_disagreement(d, LineageRecord::Community(&held), None, now)
                .await
                .unwrap(),
            vec![keys[2].clone()],
            "{tag} I453: the record still lists the leaver"
        );
        let mut reflected = held.clone();
        reflected.members.retain(|m| m.key_id != keys[2]);
        assert!(
            fold_disagreement(d, LineageRecord::Community(&reflected), None, now)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I453: a record reflecting the row"
        );
        assert!(
            fold_disagreement(d, LineageRecord::Community(&held), None, at - hours(1))
                .await
                .unwrap()
                .is_empty(),
            "{tag} I453: before the row took effect"
        );
        assert!(
            fold_disagreement(d, LineageRecord::Community(&held), Some(at), now)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I453: a row at or before the floor is the held head's, not this one's"
        );
    }

    /// A charter of `fam` scrubbed by every holder, carrying `extra`.
    fn charter(
        fam: &str,
        id: &str,
        keys: &[String],
        extra: serde_json::Value,
    ) -> crate::federation::Attestation {
        let commitment = crate::federation::trust_root::test_pre_rotation_commitment(&[
            format!("{fam}-succ-a"),
            format!("{fam}-succ-b"),
        ])
        .unwrap();
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
        });
        if let (Some(e), Some(x)) = (env.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                e.insert(k.clone(), v.clone());
            }
        }
        let cosigners: Vec<&str> = keys[1..].iter().map(String::as_str).collect();
        ops::co_signed_trust_attestation(
            id,
            &keys[0],
            fam,
            attestation_type::DELEGATES_TO,
            env,
            &cosigners,
        )
    }

    /// A family chartered with `extra` (a cadence, a quorum) and versioned to
    /// name it: the charter in force.
    async fn chartered(
        d: &dyn FederationDirectory,
        tag: &str,
        keys: &[String],
        extra: serde_json::Value,
    ) -> String {
        let fam = format!("rk-{tag}");
        ops::seed_test_family(d, &fam, keys, PROTOCOL)
            .await
            .unwrap();
        let c = charter(&fam, &format!("{fam}-charter"), keys, extra);
        let digest = ops::charter_digest_of(&c);
        d.put_attestation(crate::federation::SignedAttestation { attestation: c })
            .await
            .expect("charter admitted");
        ops::version_family_naming_charter(d, &fam, &digest, keys)
            .await
            .unwrap_or_else(|e| panic!("{tag}: the version naming the charter: {e}"));
        fam
    }

    /// **I454** — (ii) an uncovered row older than one cadence lags the head.
    pub async fn i454_an_uncovered_row_lags_the_head(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = chartered(
            d,
            tag,
            &keys,
            serde_json::json!({ "witness_cadence_secs": 3600 }),
        )
        .await;
        let now = chrono::Utc::now();
        assert!(
            roster_lag(d, &fam, now).await.unwrap().is_none(),
            "{tag} I454: a covered head does not lag"
        );
        // A row younger than one cadence does not lag yet.
        leave(d, &fam, &keys[2], now - chrono::Duration::minutes(10)).await;
        assert!(
            roster_lag(d, &fam, now).await.unwrap().is_none(),
            "{tag} I454: younger than the cadence"
        );
        // One cadence later it does.
        let later = now + hours(1);
        let lag = roster_lag(d, &fam, later)
            .await
            .unwrap()
            .expect("an hour on, the uncovered leave lags");
        assert_eq!(lag.token, LINEAGE_HEAD_LAGS_ROSTER, "{tag} I454");
        assert_eq!(lag.uncovered_keys, vec![keys[2].clone()], "{tag} I454");
        assert_eq!(lag.cadence_secs, 3600, "{tag} I454");
        assert_eq!(
            lag.head_digest,
            head(d, &fam).await.persist_row_hash,
            "{tag} I454: the head that lags"
        );
        assert!(
            (lag.since - (now - chrono::Duration::minutes(10)))
                .num_seconds()
                .abs()
                <= 1,
            "{tag} I454: since the row's effective instant: {lag:?}"
        );
        let view = root_witness_view(d, &fam, later).await.unwrap().unwrap();
        assert_eq!(
            view.roster_lag.as_ref(),
            Some(&lag),
            "{tag} I454: served on the witness view"
        );
        let held = head(d, &fam).await;
        version(d, &fam, without(&held, &keys[2]), &keys[0])
            .await
            .unwrap_or_else(|e| panic!("{tag} I454: the covering version: {e}"));
        assert!(
            roster_lag(d, &fam, later).await.unwrap().is_none(),
            "{tag} I454: the covering version clears the lag"
        );
    }

    fn cosign(
        fam: &Family,
        witness: &str,
        signed_at: chrono::DateTime<chrono::Utc>,
    ) -> LineageHeadCosign {
        let mut c = LineageHeadCosign {
            lineage_key_id: fam.family_key_id.clone(),
            head_digest_sha256_hex: fam.persist_row_hash.clone(),
            head_asserted_at: fam.founded_at.to_rfc3339(),
            prior_head_digest_sha256_hex: None,
            signed_at: signed_at.to_rfc3339(),
            witness_key_id: witness.to_owned(),
            signature_classical: String::new(),
            signature_pqc: None,
        };
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&c.signing_envelope())
            .expect("cosign envelope canonicalizes");
        let sig = ts::threshold_sign(witness, &bytes);
        c.signature_classical = sig.ed25519_signature_base64;
        c.signature_pqc = sig.mldsa65_signature_base64;
        c
    }

    /// **I455** — (ii) witnesses do not cosign a lagging head; with witnessed
    /// mode off the lag is only reported.
    pub async fn i455_a_lagging_head_is_not_cosigned(d: &dyn FederationDirectory, tag: &str) {
        let witness = format!("rw-{tag}");
        ts::register_hybrid_key_as(d, &witness, &witness, identity_type::WITNESS).await;
        for (mode, extra) in [
            ("on", serde_json::json!({ "witness_quorum": 2 })),
            ("off", serde_json::json!({})),
        ] {
            let tag = format!("{tag}{mode}");
            let keys = holders(d, &tag).await;
            let fam = chartered(d, &tag, &keys, extra).await;
            // No cadence declared: an uncovered row lags from its instant.
            leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
            let held = head(d, &fam).await;
            let lag = roster_lag(d, &fam, chrono::Utc::now()).await.unwrap();
            assert!(lag.is_some(), "{tag} I455: lags in either mode");
            let out = d
                .put_lineage_head_cosign(cosign(&held, &witness, chrono::Utc::now()))
                .await
                .unwrap();
            match mode {
                "on" => {
                    assert_eq!(
                        out,
                        LineageCosignOutcome::Refused {
                            reason: LineageCosignRefusal::HeadLagsRoster
                        },
                        "{tag} I455: witnesses do not cosign a lagging head"
                    );
                    assert_eq!(
                        LineageCosignRefusal::HeadLagsRoster.as_str(),
                        LINEAGE_HEAD_LAGS_ROSTER,
                        "{tag} I455: the token CC names"
                    );
                    // The covering version is cosignable.
                    version(d, &fam, without(&held, &keys[2]), &keys[0])
                        .await
                        .unwrap();
                    let covered = head(d, &fam).await;
                    let out = d
                        .put_lineage_head_cosign(cosign(&covered, &witness, chrono::Utc::now()))
                        .await
                        .unwrap();
                    assert_eq!(
                        out,
                        LineageCosignOutcome::Inserted,
                        "{tag} I455: the covering head"
                    );
                }
                _ => {
                    assert_eq!(
                        out,
                        LineageCosignOutcome::Inserted,
                        "{tag} I455: witnessed mode off changes nothing but the report"
                    );
                    let view = root_witness_view(d, &fam, chrono::Utc::now())
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(view.roster_lag.is_some(), "{tag} I455: reported");
                }
            }
        }
    }

    /// **I456** — (iii) the removal takes effect before any version covers it.
    pub async fn i456_the_removal_does_not_wait(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = conferring(d, tag, &keys).await;
        let before = head(d, &fam).await;
        leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
        let active: Vec<String> = d
            .active_family_members(&fam)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(
            !active.contains(&keys[2]),
            "{tag} I456: the fold dropped the seat: {active:?}"
        );
        let held = head(d, &fam).await;
        assert_eq!(held, before, "{tag} I456: no version was synthesised");
        assert!(
            held.members.iter().any(|m| m.key_id == keys[2]),
            "{tag} I456: the head still lists it"
        );
    }

    /// **I457** — the accord's version counts a strict majority of its
    /// STANDING roster.
    pub async fn i457_a_standing_majority(d: &dyn FederationDirectory, tag: &str) {
        let keys: Vec<String> = (0..5).map(|i| format!("rs{i}-{tag}")).collect();
        for k in &keys {
            ops::register_typed_key(d, k, identity_type::NODE)
                .await
                .unwrap();
        }
        let fam = format!("rm-{tag}");
        ops::seed_test_family(d, &fam, &keys, PROTOCOL)
            .await
            .unwrap();
        let env = serde_json::json!({ "family_key_id": fam, "members": [] });
        let bytes = ciris_verify_core::accord_genesis::accord_family_signing_bytes(&env).unwrap();
        let proof = |signers: &[&str]| crate::federation::types::GroupSupersedeProof {
            prior_persist_row_hash: String::new(),
            change_envelope: env.clone(),
            quorum_signatures: signers
                .iter()
                .map(|k| ts::threshold_sign(k, &bytes))
                .collect(),
        };
        let fam = fam.as_str();
        let signed = |p: crate::federation::types::GroupSupersedeProof| async move {
            crate::federation::tier_ingest::accord_standing_majority_signed(d, fam, &p)
                .await
                .unwrap()
        };
        assert!(
            !signed(proof(&[&keys[0], &keys[1]])).await,
            "{tag} I457: two of five is short of the standing majority"
        );
        assert!(
            !signed(proof(&[&keys[0], &keys[0], &keys[1]])).await,
            "{tag} I457: one key's two signatures count once"
        );
        assert!(
            signed(proof(&[&keys[0], &keys[1], &keys[2]])).await,
            "{tag} I457: three of five is the standing majority"
        );
        let outsider = format!("ro-{tag}");
        ops::register_typed_key(d, &outsider, identity_type::NODE)
            .await
            .unwrap();
        assert!(
            !signed(proof(&[&keys[0], &keys[1], &outsider])).await,
            "{tag} I457: a key off the roster counts nothing"
        );
    }

    /// **I459** — (ii) an uncovered authorized accord roster change lags the
    /// accord head.
    pub async fn i459_an_uncovered_accord_decision_lags(d: &dyn FederationDirectory, tag: &str) {
        use ciris_verify_core::accord_live_quorum::{AccordAction, AccordDecision, AccordProposal};
        ops::register_genesis_accord_roster(d).await.unwrap();
        crate::federation::genesis::seed_accord_family(d)
            .await
            .unwrap();
        let accord = crate::federation::canonical_community::accord_family_key_id();
        let held = head(d, accord).await;
        let now = chrono::Utc::now();
        let decide = |n: &str, anchor: &str, closes: chrono::DateTime<chrono::Utc>, ok: bool| {
            let nonce = format!("{n}-{tag}");
            let anchor = anchor.to_owned();
            async move {
                d.issue_accord_nonce(accord, &nonce).await.unwrap();
                let proposal = AccordProposal {
                    family_key_id: accord.to_owned(),
                    action: AccordAction::RosterChange,
                    nonce,
                    window_until: closes.to_rfc3339(),
                    prior_family_digest: anchor,
                    payload_sha256: "cd".repeat(32),
                };
                d.put_accord_proposal(proposal.clone(), None).await.unwrap();
                d.put_accord_decision(AccordDecision {
                    proposal: proposal.clone(),
                    live_set: vec![],
                    yes: 2,
                    no: 0,
                    abstain: 0,
                    authorized: ok,
                })
                .await
                .unwrap();
                proposal.digest()
            }
        };
        decide("other", &"ef".repeat(32), now - hours(2), true).await;
        decide("refused", &held.persist_row_hash, now - hours(2), false).await;
        decide("open", &held.persist_row_hash, now + hours(2), true).await;
        assert!(
            roster_lag(d, accord, now).await.unwrap().is_none(),
            "{tag} I459: another anchor, a refusal and an open window do not lag"
        );
        let digest = decide("due", &held.persist_row_hash, now - hours(2), true).await;
        let lag = roster_lag(d, accord, now)
            .await
            .unwrap()
            .expect("an authorized roster change on the head lags it");
        assert_eq!(lag.uncovered_decisions, vec![digest], "{tag} I459");
        assert!(lag.uncovered_keys.is_empty(), "{tag} I459");
        assert_eq!(lag.head_digest, held.persist_row_hash, "{tag} I459");
    }
}

#[cfg(test)]
mod pure {
    fn code_of(file: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body of `fn name` in `code` (to the next item at the same indent).
    fn body<'a>(code: &'a str, name: &str) -> &'a str {
        let start = code
            .find(name)
            .unwrap_or_else(|| panic!("{name} not found"));
        let rest = &code[start..];
        let end = rest[1..]
            .find("\nfn ")
            .or_else(|| rest[1..].find("\npub(crate) async fn "))
            .or_else(|| rest[1..].find("\nasync fn "))
            .or_else(|| rest[1..].find("\npub async fn "))
            .map_or(rest.len(), |i| i + 1);
        &rest[..end]
    }

    /// **I458** — from disk, comments stripped: every version door runs
    /// consequence (i) before its write, the cosign door runs (ii), and the
    /// accord head door counts the standing majority.
    #[test]
    fn i458_every_door_runs_its_consequence() {
        let ga = code_of("src/federation/group_amendment.rs");
        for door in [
            "pub(crate) async fn route_occupied_family",
            "pub(crate) async fn supersede_family_signed",
            "pub(crate) async fn supersede_community_signed",
        ] {
            let b = body(&ga, door);
            let check = b
                .find("roster_head::check_version_covers_fold(")
                .unwrap_or_else(|| panic!("I458: {door} runs consequence (i)"));
            let write = b
                .find("supersede_group_row(")
                .unwrap_or_else(|| panic!("I458: {door} writes"));
            assert!(check < write, "I458: {door} judges BEFORE it writes");
        }
        let cc = code_of("src/federation/canonical_community.rs");
        let b = body(&cc, "pub(crate) async fn apply_trust_root_chain_counted");
        let check = b
            .find("roster_head::check_version_covers_fold_since(")
            .expect("I458: the trust-root chain apply runs consequence (i)");
        assert!(
            check < b.find("supersede_group_row(").expect("writes"),
            "I458: the chain apply judges before it writes"
        );
        let lw = code_of("src/federation/lineage_witness.rs");
        let b = body(&lw, "pub async fn admit_lineage_head_cosign");
        assert!(
            b.contains("roster_head::roster_lag(")
                && b.contains("LineageCosignRefusal::HeadLagsRoster"),
            "I458: the cosign door refuses a lagging head"
        );
        // The door RETURNS the count's verdict (its tail expression), so a
        // call whose result is dropped does not pass. While the accord is three
        // holders `quorum:2/3` IS the standing majority, so no behaviour can tell
        // the leg apart; I457 witnesses the count itself.
        let ti = code_of("src/federation/tier_ingest.rs");
        let b = body(&ti, "async fn is_accord_head_version");
        let flat: String = b.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains(
                "accord_standing_majority_signed(directory, &offered.family_key_id, proof).await }"
            ),
            "I458: the accord head door returns the standing-majority count"
        );
    }
}

#[cfg(test)]
mod run {
    use super::bodies;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::{bodies, suffix};
                #[tokio::test]
                async fn i450() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i450_a_version_reflects_a_revocation(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i451() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i451_a_version_reflects_a_widening(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i452() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i452_only_a_witnessed_lineage_is_judged(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i453() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i453_the_community_arm(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i454() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i454_an_uncovered_row_lags_the_head(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i455() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i455_a_lagging_head_is_not_cosigned(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i456() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i456_the_removal_does_not_wait(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i457() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i457_a_standing_majority(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i459() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i459_an_uncovered_accord_decision_lags(&b, &suffix()).await
                }
            }
        };
    }
    runners!(memory, async { Some(crate::store::MemoryBackend::new()) });
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
