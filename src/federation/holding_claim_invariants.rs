//! v55.0.0 (CIRISPersist#989, #1053, #975; CC 3.1.3.3 / 2.4 / 3.2;
//! CIRISConstitution#141, #142) — **the one holding claim and the public
//! room**, witnessed.
//!
//! Pure (every build with tests):
//!
//! - **I707** — the claim is placed at the content's scope: Commons-tier
//!   content at `federation` with no target, sealed content at its own cohort
//!   and group; a sealed family or room that names no group is refused.
//! - **I708** — the claim row: a `scores` row on `custody:ack:v1`, `here`,
//!   attested by and about the holder, citing the full digest, carrying the
//!   size, `expires_at` exactly 72 h after the signed instant, passing the
//!   door's own binding gates; no row of a retired type is built.
//! - **I709** — a retired carrier (`holds_bytes:*`, any spelling) is refused
//!   `attestation_type_unregistered` under BOTH row-type modes, at the row
//!   door and the local door, and left out of the serve filter in both.
//! - **I710** — the report parse admits `federation` and `affiliations`
//!   placements and refuses an `expires_at` that is not the 72 h window; the
//!   envelope builder refuses a target at `federation` or `self`.
//! - **I711** — a holding claim is retracted by its signer alone: the door
//!   refuses another key's `withdraws`, and the fold never lets one retire it.
//!
//! On every backend (`dyn FederationDirectory`):
//!
//! - **I712** — `admission: open` only on a `public` room; an `admission`
//!   value other than `open` is malformed; no version crosses the `public`
//!   boundary.
//! - **I713** — open admission: a founder's standing proposal of an open
//!   public room is admitted (a non-founder's, or one for a room that is not
//!   open, is refused); any requester's own acceptance of it is admitted and
//!   satisfies the growth gate; once the room is no longer open the standing
//!   proposal seats nobody.
//! - **I714** — the `community:listing:v1` door: off `federation`, no room,
//!   no moderator, a room that is not public, a misstated policy, or a signer
//!   that is neither founder nor moderate-holder is refused; the founder's
//!   listing is admitted, and the read fold names the room's one live listing.
//!
//! On sqlite and postgres (the blob doors):
//!
//! - **I715** — the commons door claims at `federation`: one `custody:ack:v1`
//!   `here` by this node, sized as stored, indexed for the wire, read back by
//!   `list_holders` / `list_holders_sized` / `list_held_by`; no `holds_bytes`
//!   row exists.
//! - **I716** — two nodes, the real planes: a sealed community write is
//!   claimed at the ROOM's scope (never `federation`); a member node learns
//!   the holder only through the advertised hashes and the apply door; a node
//!   outside the room is not in the claim's audience.
//! - **I717** — the claim's scope is the content's at admission: a claim
//!   about a held blob placed at another scope is refused
//!   `custody_ack_scope_mismatch`, and `put_holding_claim` refuses a wrong
//!   scope, a wrong size and a blob it does not hold.
//! - **I718** — a retired `holds_bytes` row a node still holds is stored and
//!   reported, never served and never read as a holder; one arriving from a
//!   peer is refused.
//! - **I719** — eviction retracts this node's own claims, at the claim's
//!   scope, and nobody else's.
//! - **I720** — a `public` room is Commons tier: its writes are plaintext and
//!   claimed at `federation`, and the community DEK cascade refuses it.
//! - **I722** — the self door, end to end through the Engine: a `self` write
//!   on the owner's own device is claimed at `self` (never `federation`), and
//!   so is one on another owner's device — a `self` report's principal is the
//!   device, so it never reaches the directory.
//! - **I723** — two nodes, the advertisement plane: a Commons write is
//!   claimed at `federation`; a node sharing no cohort with the writer, and
//!   holding no copy, discovers the writer as a live, sized holder.
//! - **I724** — a listing ahead of its room's record is refused retryably
//!   (`scope_membership_unresolved`) and admitted when re-offered after it.
//! - **I725** — the re-ack: a day-old claim on held bytes is renewed by one
//!   pass, a claim on evicted bytes is not, and a second pass renews nothing.
//! - **I726** — the upgrade conversion: this node's OWN retired rc6 claim on
//!   bytes it holds is claimed once as custody:ack:v1; a peer's is inert.
//! - **I721** — from disk: no production source builds a `holds_bytes` row
//!   type; the stem is named only by the retired list
//!   (`registry::RETIRED_CARRIER_STEMS`).

#[cfg(test)]
mod pure {
    use crate::federation::custody_ack::{
        custody_ack_envelope, parse_custody_ack, CustodyState, CUSTODY_ACK_DIMENSION,
        CUSTODY_LIVE_SECS,
    };
    use crate::federation::holding_claim::{holding_claim_row, ClaimScope};
    use crate::federation::row_type::{self, RowTypeEnforcement};
    use crate::federation::types::cohort_scope::{self as cs, CryptoTier};
    use chrono::{Duration, Utc};

    const SHA: [u8; 32] = [0x5a; 32];

    /// **I707** — the scope table.
    #[test]
    fn i707_the_claim_is_placed_at_the_contents_scope() {
        for scope in [cs::FEDERATION, cs::SPECIES, cs::COMMUNITY] {
            let s = ClaimScope::of_content(CryptoTier::Plaintext, scope, Some("room")).unwrap();
            assert_eq!(s.cohort_scope(), cs::FEDERATION, "I707 {scope}");
            assert_eq!(
                s.target(),
                None,
                "I707 {scope}: the commons names no target"
            );
            assert!(s.is_directory());
        }
        let s = ClaimScope::of_content(CryptoTier::InvisibleEncrypted, cs::SELF, Some("owner"))
            .unwrap();
        assert_eq!(
            (s.cohort_scope(), s.target()),
            (cs::SELF, None),
            "I707 self"
        );
        let s = ClaimScope::of_content(CryptoTier::InvisibleEncrypted, cs::FAMILY, Some("fam"))
            .unwrap();
        assert_eq!((s.cohort_scope(), s.target()), (cs::FAMILY, Some("fam")));
        for scope in [cs::COMMUNITY, cs::AFFILIATIONS] {
            let s = ClaimScope::of_content(CryptoTier::CommunityDek, scope, Some("room")).unwrap();
            assert_eq!((s.cohort_scope(), s.target()), (scope, Some("room")));
            assert!(
                !s.is_directory(),
                "I707 a room's claim is never the directory"
            );
        }
        for (tier, scope) in [
            (CryptoTier::InvisibleEncrypted, cs::FAMILY),
            (CryptoTier::CommunityDek, cs::COMMUNITY),
        ] {
            let e = ClaimScope::of_content(tier, scope, None).unwrap_err();
            assert!(
                e.to_string().contains("holding_claim_scope_unresolved"),
                "I707 {scope} without a group: {e}"
            );
        }
        let e = ClaimScope::of_content(CryptoTier::CommunityDek, cs::FEDERATION, Some("x"))
            .unwrap_err();
        assert!(e.to_string().contains("holding_claim_scope_unresolved"));
    }

    /// **I708** — the row shape and its own gates.
    #[test]
    fn i708_the_claim_row() {
        let now = Utc::now() - Duration::minutes(1);
        for (tier, scope, group) in [
            (CryptoTier::Plaintext, cs::FEDERATION, None),
            (CryptoTier::CommunityDek, cs::COMMUNITY, Some("room")),
            (CryptoTier::InvisibleEncrypted, cs::SELF, None),
        ] {
            let sc = ClaimScope::of_content(tier, scope, group).unwrap();
            let r = holding_claim_row(&SHA, "holder", "id-1", now, 4096, &sc).unwrap();
            assert_eq!(r.attestation_type, "scores", "I708");
            assert_eq!(
                crate::federation::admission::envelope_dimension(&r.attestation_envelope),
                Some(CUSTODY_ACK_DIMENSION)
            );
            assert_eq!(r.attesting_key_id, "holder");
            assert_eq!(r.attested_key_id, "holder", "I708 a holder self-report");
            assert_eq!(
                r.cohort_scope,
                sc.cohort_scope(),
                "I708 placed at the content's scope"
            );
            assert_eq!(
                r.expires_at,
                Some(r.asserted_at + Duration::seconds(CUSTODY_LIVE_SECS)),
                "I708 freshness is the row's: exactly 72 h"
            );
            assert!(
                !r.attestation_type.starts_with("holds_bytes"),
                "I708 no retired type is built"
            );
            let ack = parse_custody_ack(&r).unwrap().expect("a custody report");
            assert_eq!(ack.state, CustodyState::Here);
            assert_eq!(ack.size, Some(4096));
            assert_eq!(ack.blob_sha256_hex, hex::encode(SHA));
            crate::federation::admission::check_row_column_binding(&r).expect("I708 mirror");
            crate::federation::admission::check_instant_binding(
                &r,
                Utc::now(),
                crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
            )
            .expect("I708 instants");
            row_type::check_row_type(&r).expect("I708 one of the five");
        }
        let sc = ClaimScope::of_content(CryptoTier::Plaintext, cs::FEDERATION, None).unwrap();
        assert!(
            holding_claim_row(&SHA, "holder", "id", now, 0, &sc).is_err(),
            "I708 every blob carries its size (CC 5.3.2.5)"
        );
    }

    /// **I709** — a retired carrier, under both modes.
    #[tokio::test]
    async fn i709_a_retired_carrier_is_refused_in_both_modes() {
        let sc = ClaimScope::of_content(CryptoTier::Plaintext, cs::FEDERATION, None).unwrap();
        let mut r = holding_claim_row(&SHA, "holder", "id", Utc::now(), 7, &sc).unwrap();
        for mode in [RowTypeEnforcement::Report, RowTypeEnforcement::Enforce] {
            for t in [
                "holds_bytes:sha256:5a5a5a5a",
                "holds_bytes:sha256:5a5a5a5a5a5a5a5a",
                "holds_bytes:anything",
            ] {
                r.attestation_type = t.to_owned();
                let row = r.clone();
                let got = row_type::with_enforcement(mode, async move {
                    (
                        row_type::check_row_type(&row),
                        row_type::admit_local_row_type(&row.attestation_type),
                        row_type::served_under_enforcement(&row),
                        row_type::serve_filter_sql(
                            "attestation_type",
                            row_type::SqlDialect::Sqlite,
                        ),
                    )
                })
                .await;
                let (row_door, local_door, served, filter) = got;
                assert!(
                    row_door
                        .as_ref()
                        .is_err_and(|e| e.kind() == "federation_attestation_type_unregistered"),
                    "I709 {mode:?} {t}: the row door refuses: {row_door:?}"
                );
                assert!(
                    local_door.is_err(),
                    "I709 {mode:?} {t}: the local door refuses"
                );
                assert!(!served, "I709 {mode:?} {t}: never served");
                assert!(
                    filter.is_some(),
                    "I709 {mode:?}: the serve reads carry a filter in both modes"
                );
            }
        }
        // the Report filter leaves out exactly the retired stem
        let f = row_type::not_retired_carrier_sql("attestation_type");
        assert!(f.contains("'holds_bytes:'"), "I709 {f}");
        assert!(
            row_type::retired_carrier("holds_bytesX").is_none()
                && row_type::retired_carrier("scores").is_none(),
            "I709 the stem, and only the stem"
        );
    }

    /// **I710** — placements and the freshness window.
    #[test]
    fn i710_placements_and_the_window() {
        let sc = ClaimScope::of_content(CryptoTier::CommunityDek, cs::AFFILIATIONS, Some("aff"))
            .unwrap();
        let r = holding_claim_row(&SHA, "holder", "id", Utc::now(), 1, &sc).unwrap();
        assert!(
            parse_custody_ack(&r).unwrap().is_some(),
            "I710 affiliations"
        );
        let mut long = r.clone();
        long.expires_at = Some(long.asserted_at + Duration::seconds(CUSTODY_LIVE_SECS + 1));
        let e = parse_custody_ack(&long).unwrap_err();
        assert!(e.to_string().contains("custody_ack_malformed"), "I710 {e}");
        let mut short = r.clone();
        short.expires_at = Some(short.asserted_at + Duration::hours(24));
        assert!(
            parse_custody_ack(&short).is_err(),
            "I710 a second TTL is refused"
        );
        let mut legacy = r;
        legacy.expires_at = None;
        assert!(
            parse_custody_ack(&legacy).unwrap().is_some(),
            "I710 a pre-v55 report (no expires_at) is read by its instant"
        );
        for scope in [cs::FEDERATION, cs::SELF] {
            assert!(
                custody_ack_envelope(&SHA, CustodyState::Here, Some(1), scope, Some("t")).is_err(),
                "I710 {scope} names no target"
            );
        }
    }

    /// **I711** — the signer alone retracts.
    #[test]
    fn i711_a_holding_claim_is_retracted_by_its_signer_alone() {
        let sc = ClaimScope::of_content(CryptoTier::Plaintext, cs::FEDERATION, None).unwrap();
        let claim = holding_claim_row(&SHA, "holder", "claim-1", Utc::now(), 1, &sc).unwrap();
        let mut w = claim.clone();
        w.attestation_type = "withdraws".into();
        w.attesting_key_id = "moderator".into();
        w.withdraws_admission_rule = Some(3);
        let e =
            crate::federation::custody_ack::check_custody_withdraws_signer(&w, &claim).unwrap_err();
        assert!(
            e.to_string()
                .contains("custody_ack_withdraws_not_the_holder"),
            "I711 {e}"
        );
        assert!(
            !crate::federation::precedence::retraction_entitled(&w, &claim),
            "I711 a resolved rule never lets another key retire a holding claim"
        );
        w.attesting_key_id = "holder".into();
        crate::federation::custody_ack::check_custody_withdraws_signer(&w, &claim)
            .expect("I711 the holder retracts its own");
        assert!(crate::federation::precedence::retraction_entitled(
            &w, &claim
        ));
    }
}

#[cfg(test)]
pub(crate) mod dyn_bodies {
    use crate::federation::membership_acceptance::test_support::{acceptance_row, proposal_row};
    use crate::federation::membership_acceptance::{
        check_growth_accepted, RULE_OPEN_PROPOSAL_NOT_OPEN,
    };
    use crate::federation::public_room::{
        live_listing, ADMISSION_OPEN, COHORT_SUBKIND_PUBLIC, LISTING_DIMENSION,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope as cs;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{Community, CommunityMember};
    use crate::federation::{
        attestation_emit, EmitAttestationInput, Error, FederationDirectory, SignedAttestation,
    };
    use chrono::{Duration, Utc};

    /// A key whose derived id shares its first 32 bytes with its alias, so the
    /// fixture's seeded signer (`seal_row_in_place`, `sign_community`) and the
    /// alias's `LocalSigner` are the SAME keypair, registered once.
    async fn key(d: &dyn FederationDirectory, role: &str, tag: &str) -> (String, String) {
        let alias = format!("{role}-key-{tag}-0123456789abcdef")
            .replace('_', "-")
            .to_lowercase();
        let k = ts::local_signer(&alias).derived_key_id();
        assert_eq!(
            &k.as_bytes()[..32],
            &alias.as_bytes()[..32],
            "seed-sharing id"
        );
        ts::register_hybrid_key_as(d, &k, &alias, USER).await;
        (k, alias)
    }

    fn room(id: &str, founder: &str, member: Option<&str>, policy: serde_json::Value) -> Community {
        let mut members = vec![CommunityMember {
            key_id: founder.to_owned(),
            joined_at: Utc::now() - Duration::days(1),
            role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
        }];
        if let Some(m) = member {
            members.push(CommunityMember {
                key_id: m.to_owned(),
                joined_at: Utc::now() - Duration::days(1),
                role: None,
            });
        }
        Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: id.to_owned(),
            community_name: "Public Co-op".into(),
            members,
            founded_at: Utc::now() - Duration::days(1),
            consensus_protocol: crate::federation::types::consensus_protocol::FOUNDER_ONLY
                .to_owned(),
            policy_blob: Some(policy),
            persist_row_hash: String::new(),
        }
    }

    async fn put_room(d: &dyn FederationDirectory, c: Community) -> Result<(), Error> {
        let founder = c.members[0].key_id.clone();
        ts::register_hybrid_key_as(d, &c.community_key_id, &c.community_key_id, USER).await;
        d.put_community(ts::sign_community(&founder, c))
            .await
            .map(|_| ())
    }

    fn rule_of(e: &Error) -> String {
        match e {
            Error::CommunityConsensusProtocolViolation { rule, .. }
            | Error::MembershipAcceptanceRefused { rule, .. } => (*rule).to_owned(),
            other => other.to_string(),
        }
    }

    fn open_policy() -> serde_json::Value {
        serde_json::json!({"cohort_subkind": COHORT_SUBKIND_PUBLIC, "admission": ADMISSION_OPEN})
    }

    /// **I712** — `admission: open` and the `public` boundary.
    pub(crate) async fn i712_open_admission_only_on_a_public_room(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (founder, _) = key(d, "i712f", tag).await;
        let e = put_room(
            d,
            room(
                &format!("i712-priv-{tag}"),
                &founder,
                None,
                serde_json::json!({"admission": ADMISSION_OPEN}),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(
            rule_of(&e),
            crate::federation::public_room::PUBLIC_RULE_OPEN_ADMISSION_NOT_PUBLIC,
            "I712 {e}"
        );
        let bad =
            serde_json::json!({"cohort_subkind": COHORT_SUBKIND_PUBLIC, "admission": "anyone"});
        let e = put_room(d, room(&format!("i712-bad-{tag}"), &founder, None, bad))
            .await
            .unwrap_err();
        assert_eq!(
            rule_of(&e),
            crate::federation::public_room::PUBLIC_RULE_ADMISSION_MALFORMED,
            "I712 {e}"
        );
        let id = format!("i712-pub-{tag}");
        put_room(d, room(&id, &founder, None, open_policy()))
            .await
            .expect("I712 an open public room is admitted");
        // A later version that leaves the `public` side is refused, before
        // anything about the amendment itself is asked.
        let mut private = room(&id, &founder, None, serde_json::json!({}));
        private.prev_head_digest = d
            .lookup_community(&id)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        let e = d
            .put_community(ts::sign_community(&founder, private))
            .await
            .unwrap_err();
        assert_eq!(
            rule_of(&e),
            crate::federation::public_room::PUBLIC_RULE_SUBKIND_CROSSES_PUBLIC,
            "I712 {e}"
        );
    }

    /// **I713** — the standing proposal.
    pub(crate) async fn i713_open_admission_rides_a_standing_proposal(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (founder, _) = key(d, "i713f", tag).await;
        let (stranger, _) = key(d, "i713s", tag).await;
        let (joiner, _) = key(d, "i713j", tag).await;
        let id = format!("i713-pub-{tag}");
        put_room(d, room(&id, &founder, None, open_policy()))
            .await
            .unwrap();
        let shut = format!("i713-shut-{tag}");
        put_room(
            d,
            room(
                &shut,
                &founder,
                None,
                serde_json::json!({"cohort_subkind": COHORT_SUBKIND_PUBLIC}),
            ),
        )
        .await
        .unwrap();
        let at = Utc::now() - Duration::hours(1);
        let standing = |by: &str, group: &str| {
            let mut p = proposal_row(by, cs::COMMUNITY, group, "", None, at);
            p.subject_key_ids.clear();
            ts::seal_row_in_place(by, &mut p);
            p
        };
        let e = d
            .put_attestation(SignedAttestation {
                attestation: standing(&founder, &shut),
            })
            .await
            .unwrap_err();
        assert_eq!(
            rule_of(&e),
            RULE_OPEN_PROPOSAL_NOT_OPEN,
            "I713 a public room that is not open takes no standing proposal: {e}"
        );
        let e = d
            .put_attestation(SignedAttestation {
                attestation: standing(&stranger, &id),
            })
            .await
            .unwrap_err();
        assert!(
            rule_of(&e) == RULE_OPEN_PROPOSAL_NOT_OPEN || !e.to_string().is_empty(),
            "I713 a non-member's standing proposal is refused: {e}"
        );
        let p = standing(&founder, &id);
        d.put_attestation(SignedAttestation {
            attestation: p.clone(),
        })
        .await
        .expect("I713 the founder's standing proposal is admitted");
        d.put_attestation(SignedAttestation {
            attestation: acceptance_row(&joiner, &p, at + Duration::minutes(1)),
        })
        .await
        .expect("I713 any requester's own acceptance is admitted");
        check_growth_accepted(
            d,
            cs::COMMUNITY,
            &id,
            &joiner,
            None,
            at + Duration::minutes(2),
        )
        .await
        .expect("I713 the acceptance satisfies the growth gate");
    }

    /// **I775** (Codex r2 on #1065) — a `public` room is a public group to
    /// the replication audience (`is_public_group`, through the one
    /// `is_public_community` predicate): its community-scoped rows, the
    /// subjectless standing proposal a non-member needs to join among them,
    /// fan out to a non-member; a private room is not public and its rows do
    /// not.
    pub(crate) async fn i775_a_public_rooms_rows_reach_non_members(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::replication_audience::{is_public_group, may_receive};
        let (founder, _) = key(d, "i775f", tag).await;
        let (outsider, _) = key(d, "i775o", tag).await;
        let id = format!("i775-pub-{tag}");
        put_room(d, room(&id, &founder, None, open_policy()))
            .await
            .unwrap();
        let private = format!("i775-priv-{tag}");
        put_room(d, room(&private, &founder, None, serde_json::json!({})))
            .await
            .unwrap();
        assert!(
            is_public_group(d, &id).await.unwrap(),
            "I775 a public room is public"
        );
        assert!(
            !is_public_group(d, &private).await.unwrap(),
            "I775 a private room is not"
        );
        let at = Utc::now() - Duration::hours(1);
        let mut p = proposal_row(&founder, cs::COMMUNITY, &id, "", None, at);
        p.subject_key_ids.clear();
        ts::seal_row_in_place(&founder, &mut p);
        d.put_attestation(SignedAttestation {
            attestation: p.clone(),
        })
        .await
        .expect("I775 the founder's standing proposal");
        assert!(
            may_receive(d, &outsider, &p).await.unwrap().allowed(),
            "I775 the standing proposal reaches a non-member"
        );
        let mut q = p.clone();
        q.attestation_envelope["community_id"] = serde_json::json!(private);
        assert!(
            !may_receive(d, &outsider, &q).await.unwrap().allowed(),
            "I775 a private room's row does not"
        );
    }

    async fn listing(
        d: &dyn FederationDirectory,
        alias: &str,
        scope: &str,
        members: serde_json::Value,
    ) -> Result<String, Error> {
        let mut env = serde_json::json!({
            "dimension": LISTING_DIMENSION, "score": 1.0, "confidence": 1.0
        });
        for (k, v) in members.as_object().unwrap() {
            env[k] = v.clone();
        }
        let core: crate::federation::envelope::EnvelopeCore = serde_json::from_value(env).unwrap();
        let input = EmitAttestationInput::with_envelope("scores", core, scope);
        attestation_emit::emit_with_local_signer(d, &ts::local_signer(alias), input)
            .await
            .map(|e| e.attestation_id)
    }

    /// **I724** — a listing whose room record is not held yet waits for it:
    /// the signer's authority lives in the record, so the row is refused
    /// RETRYABLY (`scope_membership_unresolved`), and the SAME row, re-offered
    /// after the record lands, is admitted.
    pub(crate) async fn i724_a_listing_waits_for_its_room(d: &dyn FederationDirectory, tag: &str) {
        let (founder, _) = key(d, "i724f", tag).await;
        let id = format!("i724-pub-{tag}");
        let env = serde_json::json!({
            "dimension": LISTING_DIMENSION, "score": 1.0, "confidence": 1.0,
            "community_key_id": id, "cohort_subkind": COHORT_SUBKIND_PUBLIC,
            "admission": ADMISSION_OPEN, "moderator": "m", "name": "n", "description": "d",
            "id": format!("i724-listing-{tag}"),
        });
        let mut row =
            ts::bare_attestation(&format!("i724-listing-{tag}"), &founder, &founder, &env);
        row.attestation_type = crate::federation::types::attestation_type::SCORES.into();
        row.cohort_scope = cs::FEDERATION.into();
        ts::seal_row_in_place(&founder, &mut row);
        let e = d
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                e,
                Error::WriteScopeRefused(crate::scope::ScopeRefusalReason::MembershipUnresolved)
            ),
            "I724 a listing ahead of its room is the retryable ordering gap: {e}"
        );
        assert!(
            d.get_attestation(&row.attestation_id)
                .await
                .unwrap()
                .is_none(),
            "I724 nothing stored"
        );
        put_room(d, room(&id, &founder, None, open_policy()))
            .await
            .unwrap();
        d.put_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("I724 the same listing, re-offered after the record, is admitted");
        assert_eq!(
            live_listing(d, &id)
                .await
                .unwrap()
                .map(|r| r.attestation_id),
            Some(row.attestation_id)
        );
    }

    /// **I776** (Codex r2 on #1065) — the live listing is chosen among rows
    /// not expired at the read instant: while the latest listing has expired
    /// and an older one is live, the older one is returned; once every
    /// listing has expired there is none.
    pub(crate) async fn i776_an_expired_listing_is_not_live(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (founder, _) = key(d, "i776f", tag).await;
        let id = format!("i776-pub-{tag}");
        put_room(d, room(&id, &founder, None, open_policy()))
            .await
            .unwrap();
        let now = Utc::now();
        let put = |n: &str, asserted: chrono::DateTime<Utc>, expires: chrono::DateTime<Utc>| {
            let env = serde_json::json!({
                "dimension": LISTING_DIMENSION, "score": 1.0, "confidence": 1.0,
                "community_key_id": id, "cohort_subkind": COHORT_SUBKIND_PUBLIC,
                "admission": ADMISSION_OPEN, "moderator": "m", "name": n, "description": "d",
                "id": format!("i776-{n}-{tag}"),
            });
            let mut row =
                ts::bare_attestation(&format!("i776-{n}-{tag}"), &founder, &founder, &env);
            row.attestation_type = crate::federation::types::attestation_type::SCORES.into();
            row.cohort_scope = cs::FEDERATION.into();
            row.asserted_at = asserted;
            row.expires_at = Some(expires);
            ts::seal_row_in_place(&founder, &mut row);
            row
        };
        let older = put(
            "older",
            now - Duration::minutes(2),
            now + Duration::milliseconds(1500),
        );
        let newer = put(
            "newer",
            now - Duration::minutes(1),
            now + Duration::milliseconds(500),
        );
        for r in [&older, &newer] {
            d.put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .expect("I776 a listing");
        }
        let live = || async {
            live_listing(d, &id)
                .await
                .unwrap()
                .map(|r| r.attestation_id)
        };
        assert_eq!(
            live().await,
            Some(newer.attestation_id.clone()),
            "I776 precondition"
        );
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        assert_eq!(
            live().await,
            Some(older.attestation_id.clone()),
            "I776 the latest listing expired: the older live one is the room's"
        );
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        assert_eq!(
            live().await,
            None,
            "I776 every listing expired: none is live"
        );
    }

    /// **I714** — the listing door and the one live listing.
    pub(crate) async fn i714_the_listing_door(d: &dyn FederationDirectory, tag: &str) {
        let (founder, founder_alias) = key(d, "i714f", tag).await;
        let (other, other_alias) = key(d, "i714o", tag).await;
        let pubroom = format!("i714-pub-{tag}");
        put_room(d, room(&pubroom, &founder, Some(&other), open_policy()))
            .await
            .unwrap();
        let private = format!("i714-priv-{tag}");
        put_room(d, room(&private, &founder, None, serde_json::json!({})))
            .await
            .unwrap();
        let good = |room: &str| {
            serde_json::json!({
                "community_key_id": room, "cohort_subkind": COHORT_SUBKIND_PUBLIC,
                "admission": ADMISSION_OPEN, "moderator": "m", "name": "n", "description": "d",
            })
        };
        let refused = |r: Result<String, Error>, token: &str| {
            let e = r.expect_err(token);
            assert!(e.to_string().contains(token), "I714 {token}: {e}");
        };
        refused(
            listing(d, &founder_alias, cs::COMMUNITY, good(&pubroom)).await,
            "community_listing_not_federation",
        );
        let mut no_mod = good(&pubroom);
        no_mod.as_object_mut().unwrap().remove("moderator");
        refused(
            listing(d, &founder_alias, cs::FEDERATION, no_mod).await,
            "community_listing_malformed",
        );
        refused(
            listing(d, &founder_alias, cs::FEDERATION, good(&private)).await,
            "community_listing_room_not_public",
        );
        let mut lie = good(&pubroom);
        lie["admission"] = serde_json::json!("invite");
        refused(
            listing(d, &founder_alias, cs::FEDERATION, lie).await,
            "community_listing_malformed",
        );
        refused(
            listing(d, &other_alias, cs::FEDERATION, good(&pubroom)).await,
            "community_listing_signer_not_authorized",
        );
        let _ = other;
        assert!(live_listing(d, &pubroom).await.unwrap().is_none());
        let id = listing(d, &founder_alias, cs::FEDERATION, good(&pubroom))
            .await
            .expect("I714 the founder's listing is admitted");
        assert_eq!(
            live_listing(d, &pubroom)
                .await
                .unwrap()
                .map(|r| r.attestation_id),
            Some(id),
            "I714 the room's one live listing"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod blob_bodies {
    use crate::federation::custody_ack::{CustodyState, CUSTODY_ACK_DIMENSION};
    use crate::federation::holding_claim::ClaimScope;
    use crate::federation::key_grant_invariants::two_node::{
        introduce_as, node_as, seed_community_everywhere,
    };
    use crate::federation::types::cohort_scope::{self as cs, CryptoTier};
    use crate::federation::types::identity_type::NODE;
    use crate::federation::{Attestation, BlobBody, BlobStorage, FederationDirectory};

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }

    /// Every holding claim `holder` made about `sha`.
    pub(crate) async fn claims_of<B: FederationDirectory + Sync>(
        d: &B,
        holder: &str,
        sha: &[u8; 32],
    ) -> Vec<Attestation> {
        d.list_attestations_by_dimension_citing(holder, CUSTODY_ACK_DIMENSION, &hex::encode(sha))
            .await
            .unwrap()
    }

    /// The retired-type seam both blob backends carry.
    pub(crate) trait LegacySeam {
        fn set_type<'a>(
            &'a self,
            id: &'a str,
            ty: &'a str,
            envelope: Option<&'a serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
        /// The row's access-tracking columns `(access_count,
        /// last_accessed_at)`, read below every door (Codex r2 on #1065).
        fn access_stats<'a>(
            &'a self,
            sha: &'a [u8; 32],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (i64, String)> + Send + 'a>>;
    }
    #[cfg(feature = "sqlite")]
    impl LegacySeam for crate::store::sqlite::SqliteBackend {
        fn set_type<'a>(
            &'a self,
            id: &'a str,
            ty: &'a str,
            envelope: Option<&'a serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.test_seam_set_attestation_type(id, ty, envelope)
                    .await
                    .unwrap()
            })
        }
        fn access_stats<'a>(
            &'a self,
            sha: &'a [u8; 32],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (i64, String)> + Send + 'a>>
        {
            Box::pin(async move {
                let conn = self.conn_handle();
                let conn = conn.lock();
                conn.query_row(
                    "SELECT access_count, COALESCE(last_accessed_at, '') FROM federation_blobs \
                      WHERE sha256 = ?1",
                    rusqlite::params![sha.to_vec()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
            })
        }
    }
    #[cfg(feature = "postgres")]
    impl LegacySeam for crate::store::postgres::PostgresBackend {
        fn set_type<'a>(
            &'a self,
            id: &'a str,
            ty: &'a str,
            envelope: Option<&'a serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.test_seam_set_attestation_type(id, ty, envelope)
                    .await
                    .unwrap()
            })
        }
        fn access_stats<'a>(
            &'a self,
            sha: &'a [u8; 32],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (i64, String)> + Send + 'a>>
        {
            Box::pin(async move {
                let row = self
                    .get_client()
                    .await
                    .unwrap()
                    .query_one(
                        "SELECT access_count::BIGINT, COALESCE(last_accessed_at::TEXT, '') \
                           FROM cirislens.federation_blobs WHERE sha256 = $1",
                        &[&sha.to_vec()],
                    )
                    .await
                    .unwrap();
                (row.get(0), row.get(1))
            })
        }
    }

    /// **I715** — the commons door.
    pub(crate) async fn i715_the_commons_door_claims_at_federation<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let n = node_as(b, &format!("i715-holder-{s}"), NODE).await;
        let bytes = format!("i715 public bytes {s}").into_bytes();
        let sha = sha256_of(&bytes);
        b.put_blob_signing_scoped(
            cs::FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes.clone()),
            None,
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .expect("I715 the announcing put");
        let claims = claims_of(b, &n.key, &sha).await;
        assert_eq!(claims.len(), 1, "I715 one claim");
        let c = &claims[0];
        assert_eq!(c.cohort_scope, cs::FEDERATION, "I715 the directory scope");
        assert_eq!(c.attestation_type, "scores");
        assert_eq!(
            c.attestation_envelope["custody_state"], "here",
            "I715 {c:?}"
        );
        assert_eq!(c.attestation_envelope["size"], bytes.len() as u64);
        assert!(c.expires_at.is_some(), "I715 the row carries its freshness");
        assert!(
            b.list_attestations_by(&n.key)
                .await
                .unwrap()
                .iter()
                .all(|a| !a.attestation_type.starts_with("holds_bytes")),
            "I715 no retired row is written"
        );
        assert_eq!(b.list_holders(&sha).await.unwrap(), vec![n.key.clone()]);
        let sized = b.list_holders_sized(&sha).await.unwrap();
        assert_eq!(sized.len(), 1);
        assert_eq!(sized[0].size, bytes.len() as u64, "I715 the signed size");
        assert!(b.list_held_by(&n.key).await.unwrap().contains(&sha));
        // the claim is on the wire the moment it is written (#870)
        let key =
            crate::federation::wire_index::record_key(&[("attestation_id", &c.attestation_id)]);
        assert!(
            crate::federation::wire_index::entry_as_stored(b, "Attestation", &key)
                .await
                .unwrap()
                .is_some(),
            "I715 indexed"
        );
    }

    /// **I716** — the room's claim, through the real planes.
    pub(crate) async fn i716_a_room_claim_stays_in_the_room<B>(a: &B, b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        use crate::federation::replication::hold::is_audience;
        let na = node_as(a, &format!("i716-a-{s}"), NODE).await;
        let nb = node_as(b, &format!("i716-b-{s}"), NODE).await;
        let outsider = node_as(b, &format!("i716-o-{s}"), NODE).await;
        introduce_as(
            &[&na, &nb],
            &[&format!("i716-a-{s}"), &format!("i716-b-{s}")],
            NODE,
        )
        .await;
        let comm = format!("i716-comm-{s}");
        let (alice, bob) = (format!("i716-alice-{s}"), format!("i716-bob-{s}"));
        seed_community_everywhere(
            &[&na, &nb],
            &comm,
            &[(&alice, Some(&na)), (&bob, Some(&nb))],
        )
        .await;
        let put = put_blob_scoped(
            a,
            &na.signer,
            cs::COMMUNITY,
            Some(&comm),
            format!("room body {s}").as_bytes(),
            None,
            None,
        )
        .await
        .expect("I716 A's room write");
        let sha = put.at_rest_sha256;
        let claims = claims_of(a, &na.key, &sha).await;
        assert_eq!(claims.len(), 1, "I716 one claim");
        assert_eq!(
            claims[0].cohort_scope,
            cs::COMMUNITY,
            "I716 the claim is at the ROOM's scope — never federation (CIRISConstitution#141)"
        );
        assert_eq!(
            crate::federation::admission::envelope_cohort_target(&claims[0].attestation_envelope)
                .unwrap(),
            Some(comm.as_str())
        );
        assert!(b.list_holders(&sha).await.unwrap().is_empty());
        let delivered =
            crate::federation::holder_claim_index_invariants::bodies::deliver_attestation_plane(
                a, b,
            )
            .await;
        assert!(delivered >= 1, "I716 the claim crossed");
        assert_eq!(
            b.list_holders(&sha).await.unwrap(),
            vec![na.key.clone()],
            "I716 the member node learned the holder through the planes"
        );
        assert!(
            !is_audience(
                b,
                cs::COMMUNITY,
                Some(&comm),
                &na.key,
                |_| false,
                &outsider.key
            )
            .await
            .unwrap(),
            "I716 a node outside the room is not the claim's audience"
        );
    }

    /// **I723** — the advertisement plane survives the unification: a Commons
    /// write on A is claimed at `federation`, crosses to a node that shares no
    /// cohort with A (B is seated only in a room A is not in), and B — which
    /// holds no copy — discovers A as a live holder, sized for the fetch
    /// (CC 3.1.3.3 rule 1; CC 3.1.9.1, 5.3.2.1).
    pub(crate) async fn i723_a_commons_claim_is_discovered_across_cohorts<B>(a: &B, b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::replication::hold::is_audience;
        let na = node_as(a, &format!("i723-a-{s}"), NODE).await;
        let nb = node_as(b, &format!("i723-b-{s}"), NODE).await;
        let stranger = node_as(b, &format!("i723-s-{s}"), NODE).await;
        introduce_as(
            &[&na, &nb],
            &[&format!("i723-a-{s}"), &format!("i723-b-{s}")],
            NODE,
        )
        .await;
        // B's only cohort is a room A has no seat in.
        let comm = format!("i723-comm-{s}");
        let bob = format!("i723-bob-{s}");
        seed_community_everywhere(&[&nb], &comm, &[(&bob, Some(&nb))]).await;
        let bytes = format!("i723 commons bytes {s}").into_bytes();
        let sha = sha256_of(&bytes);
        a.put_blob_signing_scoped(
            cs::FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes.clone()),
            None,
            &na.key,
            &na.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .expect("I723 A's commons write");
        assert!(!b.has_blob(&sha).await.unwrap(), "I723 B holds no copy");
        assert!(b.list_holders(&sha).await.unwrap().is_empty());
        let delivered =
            crate::federation::holder_claim_index_invariants::bodies::deliver_attestation_plane(
                a, b,
            )
            .await;
        assert!(delivered >= 1, "I723 the claim crossed");
        assert_eq!(
            b.list_holders(&sha).await.unwrap(),
            vec![na.key.clone()],
            "I723 B, outside every cohort of A's, discovers A as the holder"
        );
        let sized = b.list_holders_sized(&sha).await.unwrap();
        assert_eq!(sized.len(), 1, "I723 {sized:?}");
        assert_eq!(
            sized[0].size,
            bytes.len() as u64,
            "I723 the advertised size is what the fetch is sized by"
        );
        assert!(
            b.list_held_by(&na.key).await.unwrap().contains(&sha),
            "I723 the holder's advertised set names the blob on B"
        );
        assert!(
            is_audience(b, cs::FEDERATION, None, &na.key, |_| false, &stranger.key)
                .await
                .unwrap(),
            "I723 a federation claim's audience is every node"
        );
    }

    /// **I725** — the re-ack (CC 3.1.3.3 rule 5). Two claims signed 70 h ago,
    /// one about bytes since evicted: one pass renews the held one (live again
    /// for 72 h from now) and not the evicted one, which lapses; a second pass
    /// renews nothing (idempotent); a claim younger than a day is left alone.
    pub(crate) async fn i725_the_reack_renews_what_is_held<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::holding_claim::{live_holders, reack_own_claims};
        let n = node_as(b, &format!("i725-holder-{s}"), NODE).await;
        let now = chrono::Utc::now();
        let then = now - chrono::Duration::hours(70);
        let mut shas = Vec::new();
        for i in 0..2 {
            let bytes = format!("i725 bytes {i} {s}").into_bytes();
            let sha = sha256_of(&bytes);
            b.put_blob_signing_scoped(
                cs::FEDERATION,
                None,
                &sha,
                BlobBody::Inline(bytes),
                None,
                &n.key,
                &n.signer,
                then,
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("I725 a claim signed 70 h ago");
            shas.push(sha);
        }
        let (kept, evicted) = (shas[0], shas[1]);
        assert!(b.delete_blob(&evicted).await.unwrap(), "I725 bytes evicted");
        let later = now + chrono::Duration::hours(10);
        for sha in [&kept, &evicted] {
            assert!(
                live_holders(b, sha, later).await.unwrap().is_empty(),
                "I725 precondition: unrenewed, the claim lapses at 72 h"
            );
        }
        let r = reack_own_claims(b, &n.signer, now).await.unwrap();
        assert_eq!(
            (r.scanned, r.renewed, r.not_held, r.failed),
            (2, 1, 1, 0),
            "I725 one pass: {r:?}"
        );
        assert_eq!(
            live_holders(b, &kept, later).await.unwrap(),
            vec![n.key.clone()],
            "I725 the held blob's claim is renewed past its old lapse"
        );
        assert!(
            live_holders(b, &evicted, later).await.unwrap().is_empty(),
            "I725 a claim about evicted bytes is never renewed"
        );
        let again = reack_own_claims(b, &n.signer, now).await.unwrap();
        assert_eq!(
            (again.renewed, again.fresh),
            (0, 1),
            "I725 idempotent: the renewed claim is fresh: {again:?}"
        );
        assert_eq!(
            claims_of(b, &n.key, &kept).await.len(),
            2,
            "I725 one renewal, not one per pass"
        );
    }

    /// **I771** (Codex r2 on #1065) — the maintenance reads are not
    /// accesses: an hourly re-ack pass (renewing one stale claim and finding
    /// one fresh), the holder directory reads and the local-holder read leave
    /// every claimed blob's `access_count` and `last_accessed_at` as they were,
    /// so a cold blob is not kept hot against the storage-budget sweeper.
    pub(crate) async fn i771_the_reack_scan_is_not_an_access<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync + LegacySeam,
    {
        use crate::federation::holding_claim::reack_own_claims;
        let n = node_as(b, &format!("i771-holder-{s}"), NODE).await;
        let now = chrono::Utc::now();
        let mut shas = Vec::new();
        for (i, at) in [now - chrono::Duration::hours(70), now]
            .into_iter()
            .enumerate()
        {
            let bytes = format!("i771 bytes {i} {s}").into_bytes();
            let sha = sha256_of(&bytes);
            b.put_blob_signing_scoped(
                cs::FEDERATION,
                None,
                &sha,
                BlobBody::Inline(bytes),
                None,
                &n.key,
                &n.signer,
                at,
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("I771 a claimed blob");
            shas.push(sha);
        }
        let mut before = Vec::new();
        for sha in &shas {
            before.push(b.access_stats(sha).await);
        }
        let r = reack_own_claims(b, &n.signer, now).await.unwrap();
        assert_eq!((r.scanned, r.renewed, r.fresh), (2, 1, 1), "I771 {r:?}");
        for sha in &shas {
            let _ = b.list_holders(sha).await.unwrap();
            let _ = b.list_local_holders(sha).await.unwrap();
        }
        for (sha, was) in shas.iter().zip(&before) {
            assert_eq!(
                &b.access_stats(sha).await,
                was,
                "I771 the re-ack and the holder reads did not touch the access columns"
            );
        }
    }

    /// **I726** — the upgrade conversion. A blob this node holds whose only
    /// claim is its OWN retired rc6 row (the real rc6 envelope: `kind` and the
    /// full digest in `evidence_refs`) is claimed once by the re-ack, at the
    /// content's scope; a PEER's retired row about a blob this node holds
    /// converts nothing (CC 2.4: inert); a second pass converts nothing.
    pub(crate) async fn i726_the_reack_converts_its_own_retired_claims<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync + LegacySeam,
    {
        use crate::federation::holding_claim::reack_own_claims;
        let n = node_as(b, &format!("i726-holder-{s}"), NODE).await;
        let peer = node_as(b, &format!("i726-peer-{s}"), NODE).await;
        let mut shas = Vec::new();
        for (who, i) in [(&n, 0), (&peer, 1)] {
            let bytes = format!("i726 bytes {i} {s}").into_bytes();
            let sha = sha256_of(&bytes);
            b.put_blob_signing_scoped(
                cs::FEDERATION,
                None,
                &sha,
                BlobBody::Inline(bytes),
                None,
                &who.key,
                &who.signer,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
            // What a v54 node left: the same claim, as the rc6 carrier.
            let claim = claims_of(b, &who.key, &sha).await.remove(0);
            let rc6 = serde_json::json!({
                "kind": "holds_bytes", "evidence_refs": [hex::encode(sha)],
            });
            b.set_type(
                &claim.attestation_id,
                &format!("holds_bytes:sha256:{}", &hex::encode(sha)[..8]),
                Some(&rc6),
            )
            .await;
            assert!(claims_of(b, &who.key, &sha).await.is_empty());
            shas.push(sha);
        }
        let (own, peers) = (shas[0], shas[1]);
        assert!(
            b.list_holders(&own).await.unwrap().is_empty(),
            "I726 dark after upgrade"
        );
        let now = chrono::Utc::now();
        let r = reack_own_claims(b, &n.signer, now).await.unwrap();
        assert_eq!(
            (r.converted, r.failed),
            (1, 0),
            "I726 one conversion: {r:?}"
        );
        let c = claims_of(b, &n.key, &own).await;
        assert_eq!(c.len(), 1);
        assert_eq!(
            c[0].cohort_scope,
            cs::FEDERATION,
            "I726 at the content's scope"
        );
        assert_eq!(b.list_holders(&own).await.unwrap(), vec![n.key.clone()]);
        assert!(
            claims_of(b, &n.key, &peers).await.is_empty()
                && b.list_holders(&peers).await.unwrap().is_empty(),
            "I726 a peer's retired row converts nothing"
        );
        let again = reack_own_claims(b, &n.signer, now).await.unwrap();
        assert_eq!(again.converted, 0, "I726 once: {again:?}");
        assert_eq!(claims_of(b, &n.key, &own).await.len(), 1);
    }

    /// **I778** (Codex r3 on #1065) — no holding claim about withheld bytes.
    /// With **I802** (CIRISEdge v55): `blob_custody` reports `withheld` naming
    /// the notice; `list_holders`, `list_local_holders` and `list_held_by`
    /// name no holder of / no withheld blob; an ordinary blob is untouched.
    /// A counter-notice takedown keeps the bytes on disk through its window;
    /// a blob this node announced only under the retired rc6 carrier (no
    /// custody row yet) is NOT converted by the re-ack (counted `withheld`,
    /// no `here` claim, still dark), `emit_holding_claim` called directly is
    /// `Purged` naming the notice, and the custody-report door refuses `here`.
    pub(crate) async fn i778_no_holding_claim_about_withheld_bytes<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync + LegacySeam,
    {
        use crate::federation::doors_takedown_invariants::bodies::{claimant, establish, notice};
        use crate::federation::holding_claim::{emit_holding_claim, reack_own_claims};
        let n = node_as(b, &format!("i778-holder-{s}"), NODE).await;
        let bytes = format!("i778 bytes {s}").into_bytes();
        let sha = sha256_of(&bytes);
        b.put_blob_signing_scoped(
            cs::FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes),
            None,
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
        let claim = claims_of(b, &n.key, &sha).await.remove(0);
        let rc6 = serde_json::json!({
            "kind": "holds_bytes", "evidence_refs": [hex::encode(sha)],
        });
        b.set_type(
            &claim.attestation_id,
            &format!("holds_bytes:sha256:{}", &hex::encode(sha)[..8]),
            Some(&rc6),
        )
        .await;
        assert!(
            claims_of(b, &n.key, &sha).await.is_empty(),
            "I778 precondition"
        );
        // A counter-notice takedown: the bytes stay, withheld.
        let owner = claimant(0xa1);
        let dir = b.as_dyn_directory();
        establish(dir, "i778-producer", &owner.id, &hex::encode(sha)).await;
        let t = crate::federation::takedown_tombstone::takedown_tombstone(
            dir,
            &notice(&owner, &hex::encode(sha), "dmca_512"),
            "i778-node",
        )
        .await
        .expect("I778 the takedown");
        assert!(
            t.tombstoned && b.blob_head(&sha).await.unwrap().is_some(),
            "I778 held, withheld"
        );
        let r = reack_own_claims(b, &n.signer, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            (r.converted, r.withheld, r.failed),
            (0, 1, 0),
            "I778 the conversion skips the withheld blob: {r:?}"
        );
        assert!(
            claims_of(b, &n.key, &sha).await.is_empty()
                && b.list_holders(&sha).await.unwrap().is_empty(),
            "I778 no `here` claim: the holder stays dark"
        );
        let e = emit_holding_claim(b, &n.signer, &sha, chrono::Utc::now())
            .await
            .expect_err("I778 a direct emission is refused");
        assert!(
            matches!(&e, crate::federation::BlobError::Purged { notice_id, .. } if *notice_id == t.notice_id),
            "I778 {e:?}"
        );
        let e = crate::federation::custody_ack::custody_ack_input_for(
            b,
            &sha,
            crate::federation::custody_ack::CustodyState::Here,
            None,
            None,
            None,
        )
        .await
        .expect_err("I778 the custody door refuses `here`");
        assert!(
            matches!(
                &e,
                crate::federation::Error::PurgeRefused { token, body }
                    if *token == crate::federation::steward_purge::token::BLOB_PURGED
                        && body["notice_id"] == t.notice_id.as_str()
                        && body["sha256_hex"] == hex::encode(sha).as_str()
                        && body["retryable"] == false
            ),
            "I778 the custody door's refusal is PurgeRefused `blob_purged`: {e:?}"
        );
        // I802 (CIRISEdge v55) — the custody view flags the takedown, and the
        // holder reads that feed fan-out and adopt suggestions name nothing.
        let other = format!("i778-other {s}").into_bytes();
        let other_sha = sha256_of(&other);
        b.put_blob_signing_scoped(
            cs::FEDERATION,
            None,
            &other_sha,
            BlobBody::Inline(other),
            None,
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
        let c = crate::federation::blob_custody::blob_custody(b, &sha, &n.key)
            .await
            .expect("I802 the custody view");
        assert_eq!(
            c.withheld.as_deref(),
            Some(t.notice_id.as_str()),
            "I802 {c:?}"
        );
        let c = crate::federation::blob_custody::blob_custody(b, &other_sha, &n.key)
            .await
            .unwrap();
        assert_eq!(c.withheld, None, "I802 an ordinary blob is not flagged");
        assert!(
            b.list_holders(&sha).await.unwrap().is_empty(),
            "I802 list_holders"
        );
        assert!(
            b.list_local_holders(&sha).await.unwrap().is_empty(),
            "I802 list_local_holders"
        );
        let held = b.list_held_by(&n.key).await.unwrap();
        assert!(
            !held.contains(&sha) && held.contains(&other_sha),
            "I802 list_held_by drops the withheld blob only: {held:?}"
        );
        assert_eq!(
            b.list_holders(&other_sha).await.unwrap(),
            vec![n.key.clone()]
        );
        // A blob whose LIVE claim stands (the directory-level takedown
        // retracts no claim): the holder reads still name nothing.
        let claimed = format!("i778-claimed {s}").into_bytes();
        let claimed_sha = sha256_of(&claimed);
        b.put_blob_signing_scoped(
            cs::FEDERATION,
            None,
            &claimed_sha,
            BlobBody::Inline(claimed),
            None,
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
        assert_eq!(
            b.list_holders(&claimed_sha).await.unwrap(),
            vec![n.key.clone()],
            "I802 precondition: a live claim"
        );
        establish(dir, "i778-producer", &owner.id, &hex::encode(claimed_sha)).await;
        crate::federation::takedown_tombstone::takedown_tombstone(
            dir,
            &notice(&owner, &hex::encode(claimed_sha), "dmca_512"),
            "i778-node",
        )
        .await
        .expect("I802 the second takedown");
        assert!(
            !claims_of(b, &n.key, &claimed_sha).await.is_empty(),
            "I802 precondition: the claim row stands"
        );
        assert!(
            b.list_holders(&claimed_sha).await.unwrap().is_empty(),
            "I802 list_holders names no holder of withheld bytes"
        );
        assert!(
            b.list_local_holders(&claimed_sha).await.unwrap().is_empty(),
            "I802 list_local_holders names none either"
        );
        assert!(
            !b.list_held_by(&n.key).await.unwrap().contains(&claimed_sha),
            "I802 list_held_by drops it"
        );
    }

    /// **I803** (Codex r4 on #1065) — the auto-spawned re-ack sweeper runs
    /// its FIRST pass at spawn: an upgraded node (a blob announced only under
    /// the retired rc6 carrier, no custody row, so dark to v55's holder
    /// reads) is a listed holder again with no interval elapsed.
    pub(crate) async fn i803_the_reack_sweeper_converts_at_spawn<B>(
        engine: &crate::Engine,
        b: &B,
        s: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync + LegacySeam,
    {
        let me = engine.local_derived_key_id().await.unwrap();
        let bytes = format!("i803 bytes {s}").into_bytes();
        let sha = sha256_of(&bytes);
        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                None,
                &me,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("I803 the node announces a blob");
        // What a v54 node left: the same claim, as the rc6 carrier.
        let claim = claims_of(b, &me, &sha).await.remove(0);
        let rc6 = serde_json::json!({
            "kind": "holds_bytes", "evidence_refs": [hex::encode(sha)],
        });
        b.set_type(
            &claim.attestation_id,
            &format!("holds_bytes:sha256:{}", &hex::encode(sha)[..8]),
            Some(&rc6),
        )
        .await;
        assert!(
            b.list_holders(&sha).await.unwrap().is_empty(),
            "I803 precondition: dark after the upgrade"
        );
        let sweeper = engine
            .spawn_reack_sweeper()
            .expect("I803 the engine has a PQC local signer");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut seen = false;
        while std::time::Instant::now() < deadline {
            if b.list_holders(&sha).await.unwrap().contains(&me) {
                seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let _ = sweeper.stop().await;
        assert!(
            seen,
            "I803 the first pass ran at spawn: the node is a listed holder within seconds, not \
             after the {:?} interval",
            crate::federation::holding_claim::HOLDING_CLAIM_REACK_SWEEP_INTERVAL
        );
    }

    /// **I717** — the content's scope, at admission and at the announce door.
    pub(crate) async fn i717_the_claim_scope_is_the_contents<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        let n = node_as(b, &format!("i717-a-{s}"), NODE).await;
        let comm = format!("i717-comm-{s}");
        let alice = format!("i717-alice-{s}");
        seed_community_everywhere(&[&n], &comm, &[(&alice, Some(&n))]).await;
        let put = put_blob_scoped(b, &n.signer, cs::COMMUNITY, Some(&comm), b"x", None, None)
            .await
            .unwrap();
        let sha = put.at_rest_sha256;
        let head = b.blob_head(&sha).await.unwrap().unwrap();
        let wrong = ClaimScope::of_content(CryptoTier::Plaintext, cs::FEDERATION, None).unwrap();
        // the attestation door: a federation claim about the held room blob
        let claim = crate::federation::holding_claim::sign_holding_claim(
            &n.signer,
            &sha,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            head.size_bytes,
            &wrong,
        )
        .await
        .unwrap();
        let e = b.put_holding_claim(&sha, claim, &wrong).await.unwrap_err();
        assert!(
            e.to_string().contains("custody_ack_scope_mismatch"),
            "I717 the announce door: {e}"
        );
        let env = crate::federation::custody_ack::custody_ack_envelope(
            &sha,
            CustodyState::Here,
            Some(head.size_bytes),
            cs::FEDERATION,
            None,
        )
        .unwrap();
        let core: crate::federation::envelope::EnvelopeCore = serde_json::from_value(env).unwrap();
        let input =
            crate::federation::EmitAttestationInput::with_envelope("scores", core, cs::FEDERATION);
        let e = crate::federation::attestation_emit::emit_with_local_signer(b, &n.signer, input)
            .await
            .unwrap_err();
        assert!(
            e.to_string().contains("custody_ack_scope_mismatch"),
            "I717 the attestation door: {e}"
        );
        // the right scope, the wrong size
        let right = crate::federation::holding_claim::content_claim_scope(b, &sha)
            .await
            .unwrap()
            .unwrap();
        let claim = crate::federation::holding_claim::sign_holding_claim(
            &n.signer,
            &sha,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            head.size_bytes + 1,
            &right,
        )
        .await
        .unwrap();
        assert!(b.put_holding_claim(&sha, claim, &right).await.is_err());
        // a blob not held
        let mut absent = sha;
        absent[0] ^= 0xff;
        let claim = crate::federation::holding_claim::sign_holding_claim(
            &n.signer,
            &absent,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            1,
            &right,
        )
        .await
        .unwrap();
        assert!(matches!(
            b.put_holding_claim(&absent, claim, &right).await,
            Err(crate::federation::BlobError::NotHeld { .. })
        ));
    }

    /// **I718** — a retired row a node holds.
    pub(crate) async fn i718_a_held_retired_row_is_inert<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync + LegacySeam,
    {
        let n = node_as(b, &format!("i718-holder-{s}"), NODE).await;
        let bytes = format!("i718 bytes {s}").into_bytes();
        let sha = sha256_of(&bytes);
        b.put_blob_signing_scoped(
            cs::FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes),
            None,
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
        let claim = claims_of(b, &n.key, &sha).await.remove(0);
        let legacy_type = format!("holds_bytes:sha256:{}", &hex::encode(sha)[..8]);
        b.set_type(&claim.attestation_id, &legacy_type, None).await;
        assert!(
            b.get_attestation(&claim.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I718 stored, not deleted"
        );
        let served = b.list_attestations_since(None, 100_000).await.unwrap();
        assert!(
            served
                .iter()
                .all(|r| r.attestation.attestation_id != claim.attestation_id),
            "I718 never served (CC 2.4)"
        );
        assert!(
            b.list_holders(&sha).await.unwrap().is_empty(),
            "I718 never read as a holder"
        );
        let report = crate::federation::row_type::row_type_report(b)
            .await
            .unwrap();
        assert!(
            report
                .held_unregistered
                .iter()
                .any(|h| h.attestation_type == legacy_type),
            "I718 reported to the operator"
        );
        let mut from_peer = b
            .get_attestation(&claim.attestation_id)
            .await
            .unwrap()
            .unwrap();
        // A peer's own retired row: its signed mirror names the retired type
        // and its own id, so the column binding agrees and the row reaches
        // the row-type slot.
        from_peer.attestation_id = uuid::Uuid::new_v4().to_string();
        crate::federation::envelope::RowMirror::stamp_row(&mut from_peer).unwrap();
        let e = b
            .apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: from_peer,
            })
            .await
            .unwrap_err();
        assert_eq!(
            e.kind(),
            "federation_attestation_type_unregistered",
            "I718 a retired row from a peer is refused: {e}"
        );
    }

    /// **I719** — eviction retracts this node's own claims only.
    pub(crate) async fn i719_eviction_retracts_only_its_own_claims<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let n = node_as(b, &format!("i719-node-{s}"), NODE).await;
        let p = node_as(b, &format!("i719-peer-{s}"), NODE).await;
        let bytes = format!("i719 bytes {s}").into_bytes();
        let sha = sha256_of(&bytes);
        b.put_blob_signing_scoped(
            cs::FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes.clone()),
            None,
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
        // the peer's own claim about the same bytes (it holds a copy too)
        let sc = ClaimScope::of_content(CryptoTier::Plaintext, cs::FEDERATION, None).unwrap();
        let claim = crate::federation::holding_claim::sign_holding_claim(
            &p.signer,
            &sha,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            bytes.len() as u64,
            &sc,
        )
        .await
        .unwrap();
        b.put_holding_claim(&sha, claim, &sc).await.unwrap();
        let mut holders = b.list_holders(&sha).await.unwrap();
        holders.sort();
        let mut both = vec![n.key.clone(), p.key.clone()];
        both.sort();
        assert_eq!(holders, both, "I719 two holders");
        let r = b
            .evict_actor(&p.key, &n.signer, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(r.blobs_evicted, 1, "I719 this node's copy went");
        assert_eq!(
            r.withdraws_emitted, 1,
            "I719 this node retracted its OWN claim"
        );
        assert!(!b.has_blob(&sha).await.unwrap());
        assert_eq!(
            crate::federation::holding_claim::live_holders(b, &sha, chrono::Utc::now())
                .await
                .unwrap(),
            vec![p.key.clone()],
            "I719 the peer's claim stands (CC 3.1.3.3 rule 4)"
        );
        let state = crate::federation::holding_claim::holder_claims(b, &sha, chrono::Utc::now())
            .await
            .unwrap();
        assert!(
            state
                .iter()
                .all(|c| c.holder_key_id != n.key || c.state == CustodyState::Here),
            "I719 {state:?}"
        );
        assert!(
            !state.iter().any(|c| c.holder_key_id == n.key),
            "I719 this node's claim is retracted"
        );
    }

    /// **I720** — a `public` room is Commons tier.
    pub(crate) async fn i720_a_public_room_is_commons_tier<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        use crate::federation::tier_ingest::test_support as ts;
        let n = node_as(b, &format!("i720-node-{s}"), NODE).await;
        let comm = format!("i720-pub-{s}");
        let alice = format!("i720-alice-{s}");
        seed_community_everywhere(&[&n], &comm, &[(&alice, Some(&n))]).await;
        // make the seeded room public (a fresh room: nothing crosses)
        let mut c = b.lookup_community(&comm).await.unwrap().unwrap();
        let comm2 = format!("{comm}-2");
        ts::register_hybrid_key_as(
            b,
            &comm2,
            &comm2,
            crate::federation::types::identity_type::USER,
        )
        .await;
        c.community_key_id = comm2.clone();
        c.policy_blob = Some(serde_json::json!({"cohort_subkind": "public"}));
        c.prev_head_digest = String::new();
        b.put_community(ts::sign_community(&comm2, c))
            .await
            .unwrap();
        assert_eq!(
            crate::federation::at_rest_cascade::resolve_write_tier(b, cs::COMMUNITY, Some(&comm2))
                .await
                .unwrap(),
            CryptoTier::Plaintext,
            "I720 public is Commons tier"
        );
        let put = put_blob_scoped(
            b,
            &n.signer,
            cs::COMMUNITY,
            Some(&comm2),
            b"post",
            None,
            None,
        )
        .await
        .expect("I720 a post into a public room");
        assert_eq!(put.tier, CryptoTier::Plaintext);
        let claims = claims_of(b, &n.key, &put.at_rest_sha256).await;
        assert_eq!(claims.len(), 1);
        assert_eq!(
            claims[0].cohort_scope,
            cs::FEDERATION,
            "I720 holding claims at federation scope (CC 3.2)"
        );
        let e = crate::federation::community_dek::orchestrate::encrypt_and_cascade_community(
            b,
            &comm2,
            b"no",
            None,
            Some(&n.key),
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("cohort_subkind:public"), "I720 {e}");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod engine_bodies {
    use super::blob_bodies::claims_of;
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::types::cohort_scope::{CryptoTier, FEDERATION, SELF};
    use crate::federation::{BlobStorage, FederationDirectory};

    /// **I722** — the self door claims at `self`, and only on a device.
    pub(crate) async fn i722_the_self_door_claims_within_self<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        // node A is Alice's laptop (the ladder seats it as her occurrence).
        let put = l
            .engine_a
            .put_blob_scoped(SELF, Some(&l.alice), b"alice's own note", None, None)
            .await
            .expect("I722 a self write");
        assert_eq!(put.tier, CryptoTier::InvisibleEncrypted);
        let claims = claims_of(l.ba.as_ref(), &l.node_a, &put.at_rest_sha256).await;
        assert_eq!(claims.len(), 1, "I722 the device claims its copy");
        assert_eq!(
            claims[0].cohort_scope, SELF,
            "I722 a self claim stays at self — never the federation directory"
        );
        assert!(
            claims.iter().all(|c| c.cohort_scope != FEDERATION),
            "I722 structurally invisible content is never advertised"
        );
        // Node B is Bob's device, not Alice's: a self write it makes for Alice
        // is claimed at `self` too — a `self` report's principal is the
        // device itself (custody:ack:v1 names no owner), so it reaches only
        // B's own owner's devices and never the directory (CC 3.1.3.3 rules
        // 1–2).
        let put_b = l
            .engine_b
            .put_blob_scoped(
                SELF,
                Some(&l.alice),
                b"held for alice elsewhere",
                None,
                None,
            )
            .await
            .expect("I722 a self write on a node that is not her device");
        assert!(l.bb.has_blob(&put_b.at_rest_sha256).await.unwrap());
        let claims_b = claims_of(l.bb.as_ref(), &l.node_b, &put_b.at_rest_sha256).await;
        assert!(
            claims_b.iter().all(|c| c.cohort_scope == SELF),
            "I722 node B's claim stays at self: {claims_b:?}"
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
                            super::super::dyn_bodies::$name(
                                &d as &dyn FederationDirectory,
                                &suffix(),
                            )
                            .await
                        }
                    };
                }
                case!(i712_open_admission_only_on_a_public_room);
                case!(i713_open_admission_rides_a_standing_proposal);
                case!(i775_a_public_rooms_rows_reach_non_members);
                case!(i714_the_listing_door);
                case!(i776_an_expired_listing_is_not_live);
                case!(i724_a_listing_waits_for_its_room);
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
    #[tokio::test]
    async fn i803_the_reack_sweeper_converts_at_spawn_sqlite() {
        let alias = format!("i803-{}", suffix());
        let engine = crate::Engine::with_signer_pre_genesis(
            crate::federation::tier_ingest::test_support::local_signer(&alias),
            "sqlite::memory:",
        )
        .await
        .unwrap();
        engine
            .register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                &alias,
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .unwrap();
        let b = engine.sqlite_backend().unwrap().clone();
        super::blob_bodies::i803_the_reack_sweeper_converts_at_spawn(
            &engine,
            b.as_ref(),
            &suffix(),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i803_the_reack_sweeper_converts_at_spawn_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let alias = format!("i803-{}", suffix());
        let engine = crate::Engine::with_signer_pre_genesis(
            crate::federation::tier_ingest::test_support::local_signer(&alias),
            &dsn,
        )
        .await
        .unwrap();
        engine
            .register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                &alias,
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .unwrap();
        let b = engine.postgres_backend().unwrap().clone();
        super::blob_bodies::i803_the_reack_sweeper_converts_at_spawn(
            &engine,
            b.as_ref(),
            &suffix(),
        )
        .await;
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    macro_rules! blob_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::blob_bodies;
                use super::suffix;
                macro_rules! one {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(b) = $fresh.await else { return };
                            blob_bodies::$name(&b, &suffix()).await
                        }
                    };
                }
                one!(i715_the_commons_door_claims_at_federation);
                one!(i717_the_claim_scope_is_the_contents);
                one!(i718_a_held_retired_row_is_inert);
                one!(i719_eviction_retracts_only_its_own_claims);
                one!(i720_a_public_room_is_commons_tier);
                one!(i725_the_reack_renews_what_is_held);
                one!(i726_the_reack_converts_its_own_retired_claims);
                one!(i771_the_reack_scan_is_not_an_access);
                one!(i778_no_holding_claim_about_withheld_bytes);
                #[tokio::test]
                async fn i723_a_commons_claim_is_discovered_across_cohorts() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    blob_bodies::i723_a_commons_claim_is_discovered_across_cohorts(
                        &a,
                        &b,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i716_a_room_claim_stays_in_the_room() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    blob_bodies::i716_a_room_claim_stays_in_the_room(&a, &b, &suffix()).await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    blob_runners!(blob_sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    blob_runners!(blob_postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i722_the_self_door_claims_within_self_sqlite() {
        super::engine_bodies::i722_the_self_door_claims_within_self(
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
    async fn i722_the_self_door_claims_within_self_postgres() {
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        super::engine_bodies::i722_the_self_door_claims_within_self(
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

    /// **I721** — from disk: no production source builds a `holds_bytes` row
    /// type. Comments and every test-gated item are stripped
    /// (`crate::test_cfg::is_test_only_cfg`); the only production mentions of
    /// the stem are the retired list that refuses it.
    #[test]
    fn i721_no_production_source_builds_a_holds_bytes_row() {
        fn production(src: &str) -> String {
            let mut out = Vec::new();
            let mut skip_depth: Option<i32> = None;
            let mut depth = 0i32;
            let mut pending = false;
            for line in src.lines() {
                let code = match line.find("//") {
                    Some(i) => &line[..i],
                    None => line,
                };
                if skip_depth.is_none() && crate::test_cfg::is_test_only_cfg(line) {
                    pending = true;
                    continue;
                }
                let opens = code.matches('{').count() as i32;
                let closes = code.matches('}').count() as i32;
                if pending && opens > 0 {
                    skip_depth = Some(depth);
                    pending = false;
                }
                depth += opens - closes;
                if let Some(d) = skip_depth {
                    if depth <= d {
                        skip_depth = None;
                    }
                    continue;
                }
                out.push(code.to_owned());
            }
            out.join("\n")
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        fn walk(d: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        walk(&root, &mut files);
        assert!(
            files.len() > 100,
            "I721 the walk found {} files",
            files.len()
        );
        // The retired list itself, and the prefix census's "not a family"
        // note that the stem's literal there obliges (family_rules.rs).
        let allowed = [
            "federation/namespace/registry.rs",
            "federation/family_rules.rs",
        ];
        let mut offenders = Vec::new();
        for f in &files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.ends_with("_invariants.rs") || allowed.iter().any(|a| rel == *a) {
                continue;
            }
            let prod = production(&std::fs::read_to_string(f).unwrap());
            if prod.contains("\"holds_bytes:") || prod.contains("\"holds_bytes\"") {
                offenders.push(rel);
            }
        }
        assert!(
            offenders.is_empty(),
            "I721: production source still spells a `holds_bytes` row type (CC 2.4 rc7 retired \
             it; the holding claim is custody:ack:v1): {offenders:?}"
        );
    }
}
