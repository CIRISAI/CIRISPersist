//! v60.0.0 (CIRISPersist#988 item 1, #803, #854) — **the cirisnode classes
//! are rows, admitted by the plane's own doors.**
//!
//! - **I1167** (memory, sqlite, postgres) — each class, planned by
//!   `rows::plan_*` and signed by its contributor's federation key, is a
//!   `scores` row the plane admits: a Contribution, a vote on it (attested to
//!   its author), a moderation event (admitted for the community's named
//!   moderator, refused for a stranger by the moderation gate), a slashing
//!   (its subject the accused), a reconsideration filed by the slashed party
//!   (the v59 subject-standing rule) and refused from a stranger, and a
//!   ruling admitted from the review-holder and refused from the subject. A
//!   vote on a Contribution not held is `cirisnode_not_found`. The promotion
//!   record's target rule and the delivery attestation's announcement rule
//!   read the same rows.
//! - **I1168** (unit, `rows::tests`) — the retired objects are refused by
//!   name: `cirisnode_key_grant_retired`, `cirisnode_typed_object_retired`.
//! - **I1170** (sqlite, postgres engines) — a takedown notice is a row: the
//!   Engine files it (`cirisnode_put_contribution` with the
//!   `takedown_notice` subject kind → `takedown_notice:{basis}:v1`), the put
//!   door admits it under CC 4.5.5, and `cirisnode_process_takedown_admission`
//!   drives the existing tombstone door with it (the report names the row).
//!   A stranger's notice row is refused at the put door
//!   (`takedown_unauthorised`) and stored nowhere; a `steward_purge` notice
//!   row is held shut. The Engine's balance doors project into the ledgers
//!   (the read returns the row id), the rehome moves a pre-V203 balance, and
//!   the delivery attestation lands on a held announcement row and is refused
//!   for one not held.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::cirisnode::rows::{self, refusal};
    use crate::cirisnode::types::{Cell, ContributionType};
    use crate::cirisnode::{
        ContributionInput, ModerationInput, ReconsiderationRequestInput,
        ReconsiderationRulingInput, SlashingInput, TargetRowKind, VoteInput,
    };
    use crate::federation::doors_takedown_invariants::bodies::community_of;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::{EmitAttestationInput, FederationDirectory};

    /// A contributor: a signer and its registered federation key id.
    pub(crate) struct Who {
        pub(crate) signer: std::sync::Arc<crate::signing::LocalSigner>,
        pub(crate) id: String,
    }

    /// The alias is padded to 32 bytes, so the derived id (`<alias>-<fp>`)
    /// seeds the SAME test key as the alias (the test signer seeds from an
    /// id's first 32 bytes): fixtures that sign as the id (a community
    /// founder's cosignature) and the `LocalSigner` agree.
    pub(crate) async fn who<D>(d: &D, alias: &str) -> Who
    where
        D: FederationDirectory + ?Sized,
    {
        let mut alias = alias.to_owned();
        while alias.len() < 32 {
            alias.push('0');
        }
        let signer = ts::local_signer(&alias);
        let id = signer.derived_key_id();
        ts::register_hybrid_key_as(d, &id, &alias, USER).await;
        Who { signer, id }
    }

    pub(crate) async fn emit<D>(
        d: &D,
        w: &Who,
        row: EmitAttestationInput,
    ) -> Result<String, crate::federation::Error>
    where
        D: FederationDirectory + Sync + ?Sized,
    {
        crate::federation::attestation_emit::emit_with_local_signer(d, &w.signer, row)
            .await
            .map(|e| e.attestation_id)
    }

    fn contribution(kind: &str, payload: serde_json::Value) -> ContributionInput {
        ContributionInput {
            contribution_type: ContributionType::Proposal,
            subject: Cell {
                domain: "health".into(),
                language: "en".into(),
                subject: Some(kind.into()),
            },
            payload,
            witness_set: None,
        }
    }

    /// A `federation_announcement` Contribution body (FSD §4.5-symmetric).
    pub(crate) fn announcement() -> ContributionInput {
        contribution(
            crate::cirisnode::SUBJECT_KIND,
            serde_json::json!({
                "priority": "advisory",
                "kind": "threat_advisory",
                "title": "t",
                "body": "b",
                "authority_class": "root_wa",
                "expires_at": chrono::Utc::now() + chrono::Duration::days(1),
            }),
        )
    }

    // ── I1167 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1167_each_class_is_an_admitted_row<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + Sync,
    {
        let dir: &dyn FederationDirectory = d;
        let author = who(d, &format!("i1167-author-{tag}")).await;
        let voter = who(d, &format!("i1167-voter-{tag}")).await;
        let moderator = who(d, &format!("i1167-mod-{tag}")).await;
        let target = who(d, &format!("i1167-target-{tag}")).await;
        let stranger = who(d, &format!("i1167-stranger-{tag}")).await;
        let comm = format!("i1167-comm-{tag}");
        community_of(dir, &comm, &moderator.id).await;

        // A Contribution.
        let cid = emit(
            d,
            &author,
            rows::plan_contribution_row(&contribution(
                "arc_question",
                serde_json::json!({"question_id": "q1"}),
            ))
            .unwrap(),
        )
        .await
        .expect("I1167: a Contribution row");
        let c = d.get_attestation(&cid).await.unwrap().unwrap();
        assert_eq!(
            c.attestation_envelope["dimension"],
            "contribution:arc_question:v1"
        );
        assert_eq!(c.attesting_key_id, author.id);
        assert_eq!(c.tier, "federation");
        assert!(c.scrub_signature_pqc.is_some(), "I1167: hybrid-signed");

        // A vote on it: attested to its author.
        let vid = emit(
            d,
            &voter,
            rows::plan_vote_row(
                dir,
                &VoteInput {
                    contribution_id: cid.clone(),
                    score: 0.5,
                    detail: Some(serde_json::json!({"kind": "proposal_adoption"})),
                    rationale: None,
                },
            )
            .await
            .unwrap(),
        )
        .await
        .expect("I1167: a vote row");
        let v = d.get_attestation(&vid).await.unwrap().unwrap();
        assert_eq!(
            v.attestation_envelope["dimension"],
            format!("vote:{cid}:v1")
        );
        assert_eq!(
            v.attested_key_id, author.id,
            "I1167: a vote is on the author"
        );
        let page = rows::list_votes(dir, &cid, None, None, 10).await.unwrap();
        assert_eq!(page.items.len(), 1);
        let e = rows::plan_vote_row(
            dir,
            &VoteInput {
                contribution_id: "not-held".into(),
                score: 0.5,
                detail: None,
                rationale: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "cirisnode_not_found", "I1167: {e}");
        let page = rows::list_contributions(dir, &author.id, &Default::default(), None, 10)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);

        // A moderation event: the moderation gate decides who may file.
        let accusation = ModerationInput {
            target_contributor: target.id.clone(),
            allegation_type: "rogue_vote".into(),
            community_id: comm.clone(),
            payload: serde_json::json!({"evidence_refs": []}),
        };
        let e = emit(
            d,
            &stranger,
            rows::plan_moderation_row(&accusation).unwrap(),
        )
        .await
        .expect_err("I1167: a stranger holds no moderate duty");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I1167: {e}"
        );
        let mid = emit(
            d,
            &moderator,
            rows::plan_moderation_row(&accusation).unwrap(),
        )
        .await
        .expect("I1167: the named moderator files");
        // A vote names a Contribution row: a held row of another family is
        // refused as such, not voted on.
        let e = rows::plan_vote_row(
            dir,
            &VoteInput {
                contribution_id: mid.clone(),
                score: 0.5,
                detail: None,
                rationale: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "cirisnode_invalid_argument", "I1167: {e}");
        let m = d.get_attestation(&mid).await.unwrap().unwrap();
        assert_eq!(
            m.attestation_envelope["dimension"],
            "moderation:rogue_vote:v1"
        );
        assert_eq!(m.attested_key_id, target.id);

        // A slashing: its subject the accused.
        let sid = emit(
            d,
            &moderator,
            rows::plan_slashing_row(
                dir,
                &SlashingInput {
                    moderation_id: mid.clone(),
                    outcome: "proven_rogue".into(),
                    payload: serde_json::json!({}),
                },
            )
            .await
            .unwrap(),
        )
        .await
        .expect("I1167: a slashing row");
        let sl = d.get_attestation(&sid).await.unwrap().unwrap();
        assert_eq!(sl.subject_key_ids, vec![target.id.clone()]);

        // A reconsideration: the slashed party files (subject standing).
        let filing = ReconsiderationRequestInput {
            slashing_id: sid.clone(),
            grounds: "new_evidence".into(),
            payload: serde_json::json!({}),
        };
        let e = emit(
            d,
            &stranger,
            rows::plan_reconsideration_request_row(dir, &filing)
                .await
                .unwrap(),
        )
        .await
        .expect_err("I1167: a stranger has no standing to file");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I1167: {e}"
        );
        let rid = emit(
            d,
            &target,
            rows::plan_reconsideration_request_row(dir, &filing)
                .await
                .unwrap(),
        )
        .await
        .expect("I1167: the slashed party files");
        // The ruling: the review-holder rules; the subject does not.
        let ruling = ReconsiderationRulingInput {
            request_id: rid.clone(),
            outcome: "reversed".into(),
            payload: serde_json::json!({}),
        };
        let e = emit(
            d,
            &target,
            rows::plan_reconsideration_ruling_row(dir, &ruling)
                .await
                .unwrap(),
        )
        .await
        .expect_err("I1167: the subject does not rule on its own filing");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I1167: {e}"
        );
        let ruled = emit(
            d,
            &moderator,
            rows::plan_reconsideration_ruling_row(dir, &ruling)
                .await
                .unwrap(),
        )
        .await
        .expect("I1167: the review-holder rules");

        // The promotion record's target rule reads the same rows.
        rows::check_promotion_targets(dir, TargetRowKind::Contribution, std::slice::from_ref(&cid))
            .await
            .expect("I1167: a held Contribution is promotable");
        rows::check_promotion_targets(dir, TargetRowKind::ReconsiderationAttestation, &[ruled])
            .await
            .expect("I1167: a held ruling is promotable");
        for (kind, id) in [
            (TargetRowKind::Contribution, vid.clone()),
            (TargetRowKind::ReconsiderationAttestation, rid),
            (TargetRowKind::Vote, "not-held".to_owned()),
        ] {
            rows::check_promotion_targets(dir, kind, &[id])
                .await
                .expect_err("I1167: a target off the kind's family is refused");
        }
        // The announcement rule.
        rows::check_announcement_held(dir, &cid)
            .await
            .expect_err("I1167: an arc_question is not an announcement");
        let aid = emit(
            d,
            &author,
            rows::plan_contribution_row(&announcement()).unwrap(),
        )
        .await
        .expect("I1167: an announcement row");
        rows::check_announcement_held(dir, &aid)
            .await
            .expect("I1167: a held announcement row");
        // The author's Contributions, paged: both rows, newest first; a page of
        // one holds one and names the next; a limit outside 1..=MAX_PAGE is
        // refused.
        let all = rows::list_contributions(dir, &author.id, &Default::default(), None, 10)
            .await
            .unwrap();
        assert_eq!(all.items.len(), 2, "I1167: both Contributions");
        let one = rows::list_contributions(dir, &author.id, &Default::default(), None, 1)
            .await
            .unwrap();
        assert_eq!(one.items.len(), 1);
        assert!(
            one.next_cursor.is_some(),
            "I1167: a page of one names the next"
        );
        // The filter narrows: each field alone excludes what it does not name.
        for f in [
            rows::ContributionsFilter {
                domain: Some("elsewhere".into()),
                ..Default::default()
            },
            rows::ContributionsFilter {
                language: Some("sw".into()),
                ..Default::default()
            },
            rows::ContributionsFilter {
                contribution_type: Some(ContributionType::DeferralRequest),
                ..Default::default()
            },
            rows::ContributionsFilter {
                subject_kind: Some("prompt_edit".into()),
                ..Default::default()
            },
        ] {
            let p = rows::list_contributions(dir, &author.id, &f, None, 10)
                .await
                .unwrap();
            assert!(p.items.is_empty(), "I1167: {f:?} names neither row");
        }
        let kind = rows::ContributionsFilter {
            subject_kind: Some("arc_question".into()),
            domain: Some("health".into()),
            language: Some("en".into()),
            contribution_type: Some(ContributionType::Proposal),
        };
        let p = rows::list_contributions(dir, &author.id, &kind, None, 10)
            .await
            .unwrap();
        assert_eq!(p.items.len(), 1, "I1167: the arc_question alone");
        for bad in [0, crate::federation::attestation_query::MAX_PAGE + 1] {
            let e = rows::list_contributions(dir, &author.id, &Default::default(), None, bad)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), "cirisnode_invalid_argument", "I1167 limit {bad}");
        }
        let e = rows::plan_contribution_row(&contribution(
            crate::cirisnode::KEY_GRANT_SUBJECT_KIND,
            serde_json::json!({}),
        ))
        .unwrap_err();
        assert_eq!(e.kind(), refusal::KEY_GRANT_RETIRED);
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod engine_bodies {
    use super::bodies::announcement;
    use crate::cirisnode::rows;
    use crate::cirisnode::types::{Cell, ContributionType, CreditsUpdate};
    use crate::cirisnode::{ContributionInput, LegalBasis, NodeCoreService, TakedownNoticePayload};
    use crate::federation::doors_takedown_invariants::bodies::establish;
    use crate::federation::takedown_tombstone::token;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::Engine;

    /// An engine whose own key is registered. The alias is padded to 32
    /// bytes so the derived id seeds the same test key (a community founded
    /// with the engine's key cosigns as it).
    pub(crate) async fn engine(dsn: &str, alias: &str) -> Engine {
        let mut alias = alias.to_owned();
        while alias.len() < 32 {
            alias.push('0');
        }
        let alias = alias.as_str();
        let e = Engine::with_signer_pre_genesis(ts::local_signer(alias), dsn)
            .await
            .unwrap();
        e.register_self_federation_key(USER, alias, None, serde_json::json!({}), vec![])
            .await
            .expect("register the engine's own key");
        e
    }

    fn notice_body(sha: &str, basis: LegalBasis) -> ContributionInput {
        ContributionInput {
            contribution_type: ContributionType::Proposal,
            subject: Cell {
                domain: "media".into(),
                language: "en".into(),
                subject: Some(crate::cirisnode::TAKEDOWN_NOTICE_SUBJECT_KIND.into()),
            },
            payload: serde_json::to_value(TakedownNoticePayload {
                content_sha256: sha.to_owned(),
                perceptual_hash: None,
                content_holder_key_ids: vec![],
                legal_basis: basis,
                jurisdiction: "US".into(),
                good_faith_statement: "good faith".into(),
                claim_text: "claim".into(),
                evidence_refs: vec![sha.to_owned()],
                counter_notice_channel: None,
                expires_at: chrono::Utc::now() + chrono::Duration::days(30),
            })
            .unwrap(),
            witness_set: None,
        }
    }

    // ── I1170 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1170_a_takedown_notice_is_a_row(dsn: &str, tag: &str) {
        let alias = format!("i1170-node-{tag}");
        let e = engine(dsn, &alias).await;
        let me = e.local_derived_key_id().await.unwrap();
        let dir = e.federation_directory();
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            format!("i1170-{tag}").as_bytes(),
        ));
        // A stranger's notice row, signed by its own key: refused at the put
        // door, stored nowhere.
        let stranger = super::bodies::who(dir.as_ref(), &format!("i1170-stranger-{tag}")).await;
        establish(dir.as_ref(), &format!("i1170-producer-{tag}"), &me, &sha).await;
        let p: TakedownNoticePayload =
            serde_json::from_value(notice_body(&sha, LegalBasis::Dmca512).payload).unwrap();
        let row = rows::plan_takedown_notice_row(&p, &stranger.id).unwrap();
        let err = super::bodies::emit(dir.as_ref(), &stranger, row)
            .await
            .expect_err("I1170: the stranger holds no takedown duty");
        assert_eq!(err.kind(), token::UNAUTHORISED, "I1170: {err}");
        // The steward purge's leaf is held shut.
        let mut purge = rows::plan_takedown_notice_row(&p, &stranger.id).unwrap();
        let mut v = purge.attestation_envelope.to_value();
        v["dimension"] = serde_json::json!("takedown_notice:steward_purge:v1");
        v["legal_basis"] = serde_json::json!("steward_purge");
        purge.attestation_envelope =
            crate::federation::envelope::EnvelopeCore::from_value(v).unwrap();
        let err = super::bodies::emit(dir.as_ref(), &stranger, purge)
            .await
            .expect_err("I1170: the steward purge notice row is held shut");
        assert!(
            err.to_string().contains("registered_family_held_shut"),
            "I1170: {err}"
        );

        // This node, the content's signed subject, files the notice row.
        let nid = e
            .cirisnode_put_contribution(&notice_body(&sha, LegalBasis::NcmecCsam))
            .await
            .expect("I1170: the subject files the notice row");
        let held = dir.get_attestation(&nid).await.unwrap().unwrap();
        assert_eq!(
            held.attestation_envelope["dimension"],
            "takedown_notice:ncmec_csam:v1"
        );
        assert_eq!(held.attestation_envelope["claimant_key_id"], me);
        // The claimant's notice rows, narrowed by content and a half-open
        // [since, until) window on the signed instant.
        let at = held.asserted_at;
        let sec = chrono::Duration::seconds(1);
        for (content, since, until, want) in [
            (Some(sha.as_str()), None, None, 1),
            (Some("00"), None, None, 0),
            (None, Some(at), None, 1),
            (None, Some(at + sec), None, 0),
            (None, None, Some(at), 0),
            (None, None, Some(at + sec), 1),
            (None, Some(at - sec), Some(at + sec), 1),
        ] {
            let page = rows::list_takedowns(dir.as_ref(), &me, content, since, until, None, 10)
                .await
                .unwrap();
            assert_eq!(
                page.items.len(),
                want,
                "I1170: content {content:?} since {since:?} until {until:?}"
            );
        }
        let report = e
            .cirisnode_process_takedown_admission(&nid)
            .await
            .expect("I1170: the notice row drives the tombstone door");
        assert!(report.tombstoned);
        assert_eq!(report.notice_attestation_id.as_deref(), Some(nid.as_str()));
        assert_eq!(report.legal_basis, "ncmec_csam");
        assert_eq!(
            dir.purge_tombstoned("blob", &sha).await.unwrap(),
            Some(report.notice_id.clone())
        );
        let err = e
            .cirisnode_process_takedown_admission("not-a-notice")
            .await
            .expect_err("I1170: no notice row by that id");
        assert_eq!(err.kind(), token::UNAUTHORISED);

        // The balance doors project; the read names the row.
        let alice = super::bodies::who(dir.as_ref(), &format!("i1170-alice-{tag}")).await;
        let bid = e
            .cirisnode_update_credits_ledger(&CreditsUpdate {
                contributor_id: alice.id.clone(),
                domain: "health".into(),
                language: "en".into(),
                subject: "arc_question".into(),
                new_balance: 6.5,
                source_contribution: nid.clone(),
            })
            .await
            .expect("I1170: a credits row");
        let ledger = match e.node_core_service() {
            #[cfg(feature = "postgres")]
            crate::engine::NodeCoreDispatch::Postgres(b) => {
                b.get_credits_ledger(&alice.id, "health", "en", "arc_question")
                    .await
            }
            #[cfg(feature = "sqlite")]
            crate::engine::NodeCoreDispatch::Sqlite(b) => {
                b.get_credits_ledger(&alice.id, "health", "en", "arc_question")
                    .await
            }
        }
        .unwrap()
        .expect("I1170: the ledger holds the balance");
        assert_eq!((ledger.balance, ledger.attestation_id), (6.5, Some(bid)));
        e.check_silo_projection(crate::federation::silo_projection::SiloProjection::CreditsLedger)
            .await
            .expect("I1170: the ledger is its rebuild");
        assert_eq!(e.cirisnode_rehome_ledgers().await.unwrap(), 0);

        // The delivery attestation lands on a held announcement row only.
        let aid = e.cirisnode_put_contribution(&announcement()).await.unwrap();
        let att = crate::cirisnode::DeliveryAttestation {
            announcement_id: "not-held".into(),
            announcement_canonical_hash_base64: crate::cirisnode::encode_canonical_hash_base64(
                &[7u8; 32],
            ),
            peer_key_id: me.clone(),
            peer_pubkey_ed25519_base64: String::new(),
            received_at: chrono::Utc::now(),
            transport_id: crate::cirisnode::TransportMedium::Reticulum,
            signature_classical_base64: crate::cirisnode::encode_signature_base64(&[0u8; 64]),
            signature_pqc_base64: None,
        };
        let put = |a: crate::cirisnode::DeliveryAttestation| async {
            match e.node_core_service() {
                #[cfg(feature = "postgres")]
                crate::engine::NodeCoreDispatch::Postgres(b) => b.put_delivery_attestation(a).await,
                #[cfg(feature = "sqlite")]
                crate::engine::NodeCoreDispatch::Sqlite(b) => b.put_delivery_attestation(a).await,
            }
        };
        let err = put(att.clone())
            .await
            .expect_err("I1170: no such announcement");
        assert_eq!(err.kind(), "cirisnode_invalid_argument", "I1170: {err}");
        let mut on_held = att;
        on_held.announcement_id = aid.clone();
        let err = put(on_held)
            .await
            .expect_err("I1170: the signature is still asked");
        assert_eq!(
            err.kind(),
            "cirisnode_signature",
            "I1170: a held announcement passes the row rule; the forged signature does not"
        );
        doors_return_their_rows(&e, &me, &alice.id, &aid, tag).await;
    }

    /// I1170 (doors) — every Engine row door returns the id of the row it
    /// signed and put, signed by this engine, on its family.
    async fn doors_return_their_rows(e: &Engine, me: &str, alice: &str, aid: &str, tag: &str) {
        let dir = e.federation_directory();
        let comm = format!("i1170-comm-{tag}");
        crate::federation::doors_takedown_invariants::bodies::community_of(dir.as_ref(), &comm, me)
            .await;
        let held_on = |id: String, family: &'static str| {
            let dir = dir.clone();
            async move {
                let row = dir
                    .get_attestation(&id)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("I1170: {family} row {id:?} is held"));
                assert_eq!(
                    row.attesting_key_id, me,
                    "I1170: {family} signed by the engine"
                );
                assert!(
                    row.attestation_envelope["dimension"]
                        .as_str()
                        .is_some_and(|d| d.starts_with(family)),
                    "I1170: {family}: {:?}",
                    row.attestation_envelope["dimension"]
                );
                id
            }
        };
        let vid = e
            .cirisnode_cast_vote(&crate::cirisnode::VoteInput {
                contribution_id: aid.to_owned(),
                score: 1.0,
                detail: None,
                rationale: Some("yes".into()),
            })
            .await
            .expect("I1170: a vote through the Engine");
        held_on(vid, "vote:").await;
        let mid = e
            .cirisnode_put_moderation_event(&crate::cirisnode::ModerationInput {
                target_contributor: alice.to_owned(),
                allegation_type: "rogue_vote".into(),
                community_id: comm.clone(),
                payload: serde_json::json!({}),
            })
            .await
            .expect("I1170: the room's moderator files");
        let mid = held_on(mid, "moderation:").await;
        let sid = e
            .cirisnode_put_slashing_attestation(&crate::cirisnode::SlashingInput {
                moderation_id: mid,
                outcome: "proven_rogue".into(),
                payload: serde_json::json!({}),
            })
            .await
            .expect("I1170: a slashing through the Engine");
        let sid = held_on(sid, "slashing:").await;
        let rid = e
            .cirisnode_put_reconsideration_request(&crate::cirisnode::ReconsiderationRequestInput {
                slashing_id: sid,
                grounds: "new_evidence".into(),
                payload: serde_json::json!({}),
            })
            .await
            .expect("I1170: the room's review-holder files");
        let rid = held_on(rid, "reconsideration:").await;
        let ruled = e
            .cirisnode_put_reconsideration_attestation(
                &crate::cirisnode::ReconsiderationRulingInput {
                    request_id: rid,
                    outcome: "upheld".into(),
                    payload: serde_json::json!({}),
                },
            )
            .await
            .expect("I1170: the review-holder rules");
        held_on(ruled, "reconsideration:").await;
        let xid = e
            .cirisnode_update_expertise_ledger(&crate::cirisnode::ExpertiseUpdate {
                contributor_id: alice.to_owned(),
                domain: "health".into(),
                language: "en".into(),
                new_expertise: 0.25,
                new_active_tier: true,
                source_contribution: aid.to_owned(),
            })
            .await
            .expect("I1170: an expertise row");
        let xid = held_on(xid, "expertise:").await;
        let ledger = match e.node_core_service() {
            #[cfg(feature = "postgres")]
            crate::engine::NodeCoreDispatch::Postgres(b) => {
                b.get_expertise_ledger(alice, "health", "en").await
            }
            #[cfg(feature = "sqlite")]
            crate::engine::NodeCoreDispatch::Sqlite(b) => {
                b.get_expertise_ledger(alice, "health", "en").await
            }
        }
        .unwrap()
        .expect("I1170: the expertise ledger holds it");
        assert_eq!((ledger.expertise, ledger.attestation_id), (0.25, Some(xid)));
    }

    /// I1170 (rehome) — a pre-V203 balance is moved by the Engine's rehome.
    pub(crate) async fn i1170_the_rehome_moves_a_legacy_balance(
        e: &Engine,
        insert: impl std::future::Future<Output = ()>,
    ) {
        insert.await;
        let silo = crate::federation::silo_projection::SiloProjection::ExpertiseLedger;
        e.check_silo_projection(silo)
            .await
            .expect_err("I1170: a legacy balance is red");
        assert_eq!(e.cirisnode_rehome_ledgers().await.unwrap(), 1);
        e.check_silo_projection(silo)
            .await
            .expect("I1170: rehomed, the ledger is its rebuild");
        assert_eq!(e.cirisnode_rehome_ledgers().await.unwrap(), 0);
    }
}

#[cfg(test)]
mod run {
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1167_sqlite() {
        use crate::store::Backend as _;
        let s = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        s.run_migrations().await.unwrap();
        super::bodies::i1167_each_class_is_an_admitted_row(&s, &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1167_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let p = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        p.run_migrations().await.unwrap();
        super::bodies::i1167_each_class_is_an_admitted_row(&p, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1170_sqlite_engine() {
        super::engine_bodies::i1170_a_takedown_notice_is_a_row("sqlite::memory:", &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1170_postgres_engine() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        super::engine_bodies::i1170_a_takedown_notice_is_a_row(&dsn, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1170_rehome_sqlite_engine() {
        let t = tag();
        let e = super::engine_bodies::engine("sqlite::memory:", &format!("i1170r-{t}")).await;
        let sq = e.sqlite_backend().expect("sqlite").clone();
        let sql = format!(
            "INSERT INTO cirisnode_expertise_ledger (contributor_id, domain, language, \
             expertise, is_active) VALUES ('{}', 'health', 'en', 0.5, 1)",
            e.local_derived_key_id().await.unwrap()
        );
        super::engine_bodies::i1170_the_rehome_moves_a_legacy_balance(&e, async move {
            sq.test_execute(&sql).await
        })
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1170_rehome_postgres_engine() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag();
        let e = super::engine_bodies::engine(&dsn, &format!("i1170r-{t}")).await;
        let pg = e.postgres_backend().expect("postgres").clone();
        let sql = format!(
            "INSERT INTO cirisnode.expertise_ledger (contributor_id, domain, language, \
             expertise, is_active) VALUES ('{}', 'health', 'en', 0.5, TRUE)",
            e.local_derived_key_id().await.unwrap()
        );
        super::engine_bodies::i1170_the_rehome_moves_a_legacy_balance(&e, async move {
            pg.test_execute(&sql).await
        })
        .await;
    }
}
