//! v61.3.0 (CIRISPersist#1252; CC 3.3.4 step 2, CC 3.1.3 `cosign:{state}`,
//! CC 2.4, CC 4.5.13; `CLM-cosign-collection-held`) — **I1730–I1743: the
//! cosign hold**, on sqlite and postgres.
//!
//! Each witness names the hand-mutation that turns it red (run once, by hand,
//! against a committed checkpoint; the release notes carry the table).
//!
//! - **I1730** a short widening at the primary's local door is held: the
//!   roster is unchanged, the door returns `RosterChangeNotLanded`, the
//!   pending row is held under its quorum key with an open receipt.
//! - **I1731** a short event that ANOTHER check also refuses is refused
//!   exactly as before (the missing acceptance of a growth; the last-founder
//!   rule): `roster_consensus_insufficient`, and nothing held.
//! - **I1732** only the local door of the primary's node holds: the same
//!   short event at a non-primary node's local door, or arriving replicated,
//!   holds nothing.
//! - **I1733** one open hold per proposer per group.
//! - **I1734** a stranger cannot fill a hold; a self-roster assent is never
//!   read as a cosignature.
//! - **I1735** the audience of a cosign row: the group's active members at the
//!   event's instant, in a public room too; the invitee is not served it, the
//!   member a removal names is.
//! - **I1736** two nodes assemble one act from different subsets with
//!   different ML-DSA bytes: both land, carry equal wire hashes, and each
//!   other's offer settles `held_equivalent` (no refusal booked; a second diff
//!   round offers nothing).
//! - **I1737** expiry drops only the pending and signature rows; the assembled
//!   event still lands after expiry; a settled hold's re-offer is refused.
//! - **I1738** the proposer's `withdraws` of the pending row ends it; a
//!   `withdraws` of a signature row is refused.
//! - **I1739** a cosigned row admitted before the cut keeps its id, its ref
//!   moves once to the act's, and an old-shape offer settles held.
//! - **I1740** one hash derivation: the point read resolves the act's ref and
//!   not `sha256(bytes)`, and no attestation ref is taken anywhere else.
//! - **I1741** the executor lands once the protocol is met, through the
//!   admission hook and through the sweep alone; an `open:self_admit` removal's
//!   window is read against the hold's first receipt.
//! - **I1742** withdraws by id: a cosigned `withdraws` naming another node's
//!   row of the same act retracts the act here through the alias; before the
//!   alias it is the retryable `federation_withdraws_target_unheld`.
//! - **I1743** the window policy: under the floor refused, the default
//!   applies.
//! - **I1744** freshness W on cosign rows: a since-removed member's row
//!   signed more than W before receipt is `asserted_at_stale`; inside W it is
//!   judged as any member's; a member still standing signs at any age.
//! - **I1748** (v61.4.0, CIRISPersist#1250) a short refusal carries the
//!   door's count: `have`, `need` and the eligible signers, under
//!   `roster_consensus_insufficient` only.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_floor_invariants::bodies::{active, ms, rule};
    use crate::federation::attestation_apply::ReplicatedAttestationOutcome as Outcome;
    use crate::federation::cosign::{self, Executed};
    use crate::federation::group_plane::{self, GroupSigned};
    use crate::federation::membership_acceptance::test_support::consent_community_widening;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_public_room, found_room_with_blob, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        Attestation, CommunityMembershipRevocation, CommunityMembershipWidening, RosterCosignature,
    };
    use crate::federation::{
        Error, FederationDirectory, SignedAttestation, SignedCommunityMembershipRevocation,
        SignedCommunityMembershipWidening, ROSTER_CONSENSUS_INSUFFICIENT,
    };
    use chrono::{DateTime, Duration, Utc};

    /// A backend whose node identity a witness can set.
    pub(crate) trait Node:
        FederationDirectory
        + crate::federation::group_plane::GroupPlaneStore
        + crate::read::ReadEngine
    {
        fn set_node(&self, key_id: &str);
    }

    /// A room `cid` under `protocol`, founded by `founders` (each a founder),
    /// with `m` registered (the invitee). The node speaks for `founders[0]`.
    pub(crate) struct Room {
        pub(crate) cid: String,
        pub(crate) founders: Vec<String>,
        pub(crate) m: String,
    }

    impl Room {
        fn a(&self) -> &str {
            &self.founders[0]
        }
    }

    fn keys(tag: &str, n: &str, count: usize) -> Vec<String> {
        (0..count).map(|i| format!("{n}-f{i}-{tag}")).collect()
    }

    pub(crate) async fn room<D: Node>(
        d: &D,
        tag: &str,
        n: &str,
        protocol: &str,
        count: usize,
    ) -> Room {
        let founders = keys(tag, n, count);
        let m = format!("{n}-m-{tag}");
        let cid = format!("{n}-room-{tag}");
        let all: Vec<&str> = founders
            .iter()
            .map(String::as_str)
            .chain([m.as_str()])
            .collect();
        reg(d, &all).await;
        let f: Vec<&str> = founders.iter().map(String::as_str).collect();
        found_community(d, &cid, protocol, &f, &[])
            .await
            .unwrap_or_else(|e| panic!("{n}: the room founds: {e}"));
        d.set_node(&founders[0]);
        Room { cid, founders, m }
    }

    /// The same room on a second node (the same keys, the same protocol).
    async fn room_again<D: Node>(d: &D, r: &Room, protocol: &str) {
        let all: Vec<&str> = r
            .founders
            .iter()
            .map(String::as_str)
            .chain([r.m.as_str()])
            .collect();
        reg(d, &all).await;
        let f: Vec<&str> = r.founders.iter().map(String::as_str).collect();
        found_community(d, &r.cid, protocol, &f, &[])
            .await
            .expect("the room founds on the second node");
        d.set_node(&r.founders[0]);
    }

    /// A widening of `member` into `r.cid` signed by `signer` at `t`.
    fn widening_by(
        r: &Room,
        signer: &str,
        member: &str,
        t: DateTime<Utc>,
    ) -> SignedCommunityMembershipWidening {
        ts::sign_community_membership_widening(
            signer,
            CommunityMembershipWidening {
                community_key_id: r.cid.clone(),
                member_key_id: member.to_owned(),
                joined_at: t,
                effective_at: t,
                role: None,
                persist_row_hash: String::new(),
            },
        )
    }

    /// Remove `target` from `r.cid` at `t`, signed by every other founder.
    async fn remove_founder(d: &dyn FederationDirectory, r: &Room, target: &str, t: DateTime<Utc>) {
        let others: Vec<&str> = r
            .founders
            .iter()
            .map(String::as_str)
            .filter(|f| *f != target)
            .collect();
        let mut removal = ts::sign_community_membership_revocation(
            others[0],
            CommunityMembershipRevocation {
                community_key_id: r.cid.clone(),
                removed_identity_key_id: target.to_owned(),
                removed_at: t,
                effective_at: t,
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        for o in &others[1..] {
            ts::cosign_community_membership_revocation(&mut removal, o);
        }
        d.put_community_membership_revocation(removal)
            .await
            .expect("the founder is removed by the rest");
        assert!(!active(d, &r.cid, target).await);
    }

    fn at() -> DateTime<Utc> {
        ms(Utc::now() - Duration::minutes(30))
    }

    fn widening(r: &Room, member: &str, t: DateTime<Utc>) -> SignedCommunityMembershipWidening {
        ts::sign_community_membership_widening(
            r.a(),
            CommunityMembershipWidening {
                community_key_id: r.cid.clone(),
                member_key_id: member.to_owned(),
                joined_at: t,
                effective_at: t,
                role: None,
                persist_row_hash: String::new(),
            },
        )
    }

    fn cosigned(
        w: &SignedCommunityMembershipWidening,
        signers: &[&str],
    ) -> SignedCommunityMembershipWidening {
        let mut w = w.clone();
        for s in signers {
            ts::cosign_community_membership_widening(&mut w, s);
        }
        w
    }

    fn cosignature_of(w: &SignedCommunityMembershipWidening, signer: &str) -> RosterCosignature {
        let mut x = w.clone();
        x.cosignatures.clear();
        ts::cosign_community_membership_widening(&mut x, signer);
        x.cosignatures.remove(0)
    }

    fn signature_row(w: &SignedCommunityMembershipWidening, signer: &str) -> Attestation {
        cosign::signature_row(
            &GroupSigned::CommunityWidening(w.clone()),
            &cosignature_of(w, signer),
        )
        .expect("a signature row")
    }

    fn quorum_key(w: &SignedCommunityMembershipWidening) -> String {
        cosign::quorum_key_of(&GroupSigned::CommunityWidening(w.clone())).expect("quorum key")
    }

    async fn put(d: &dyn FederationDirectory, row: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    async fn consent(d: &dyn FederationDirectory, w: &SignedCommunityMembershipWidening) {
        consent_community_widening(d, w)
            .await
            .expect("the invitee accepts first");
    }

    fn not_landed(e: &Error) -> Option<&str> {
        match e {
            Error::RosterChangeNotLanded { quorum_key, .. } => Some(quorum_key),
            _ => None,
        }
    }

    async fn held(d: &dyn FederationDirectory, id: &str) -> bool {
        d.get_attestation(id).await.unwrap().is_some()
    }

    async fn outcome_of(d: &dyn FederationDirectory, qk: &str) -> Option<String> {
        d.cosign_receipt(qk).await.unwrap().and_then(|r| r.outcome)
    }

    /// Hold a short widening of `r.m` signed by `r.a()` alone.
    async fn hold<D: Node>(d: &D, r: &Room) -> (SignedCommunityMembershipWidening, String) {
        let w = widening(r, &r.m, at());
        consent(d, &w).await;
        let e = d
            .put_community_membership_widening(w.clone())
            .await
            .expect_err("a short widening does not land");
        let qk = not_landed(&e)
            .unwrap_or_else(|| panic!("held, not refused: {e:?}"))
            .to_owned();
        assert_eq!(qk, quorum_key(&w));
        (w, qk)
    }

    /// **I1730** — the shortfall holds. Mutation: `hold_inner` returns
    /// `Ok(None)` first thing (no hold is ever taken) → the door returns the
    /// pre-#1252 `roster_consensus_insufficient`, and this witness is red.
    pub(crate) async fn i1730_the_shortfall_holds<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1730", "unanimous", 3).await;
        let (w, qk) = hold(d, &r).await;
        assert!(
            !active(d, &r.cid, &r.m).await,
            "I1730: the roster is unchanged"
        );
        let pending = d
            .get_attestation(&qk)
            .await
            .unwrap()
            .expect("I1730: the pending row");
        assert_eq!(pending.attesting_key_id, r.a());
        assert_eq!(pending.attested_key_id, r.m);
        let receipt = d
            .cosign_receipt(&qk)
            .await
            .unwrap()
            .expect("I1730: a receipt");
        assert!(receipt.outcome.is_none(), "I1730: the hold is open");
        assert_eq!(receipt.group_key_id, r.cid);
        assert_eq!(receipt.proposer_key_id, r.a());
        assert_eq!(
            Error::RosterChangeNotLanded {
                group_key_id: String::new(),
                member_key_id: String::new(),
                direction: "widening",
                quorum_key: qk.clone(),
                signers: 1,
            }
            .kind(),
            "federation_roster_change_not_landed"
        );
        // A re-offer of the same short event is the same hold.
        let again = d
            .put_community_membership_widening(w)
            .await
            .expect_err("I1730: still short");
        assert_eq!(not_landed(&again), Some(qk.as_str()), "I1730: {again:?}");
    }

    /// **I1731** — a short event another check refuses is refused as before.
    /// Mutations: (a) `check_roster_authority_over` ignores the acceptance's
    /// refusal under a short verdict → the un-accepted widening is held: red;
    /// (b) `roster_event_verdict` returns `ConsensusShort` instead of the
    /// shortfall `Refuse` when the last-founder rule fails → the founder's
    /// removal is held: red.
    pub(crate) async fn i1731_another_refusal_still_refuses<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1731", "unanimous", 3).await;
        // (a) no acceptance from the invitee.
        let w = widening(&r, &r.m, at());
        let e = d
            .put_community_membership_widening(w.clone())
            .await
            .expect_err("I1731a: refused");
        assert_eq!(rule(&e), ROSTER_CONSENSUS_INSUFFICIENT, "I1731a: {e:?}");
        assert!(!held(d, &quorum_key(&w)).await, "I1731a: nothing held");
        // (b) the last founder: a room of one founder and two members; the
        // removal of the founder signed by one member is short AND leaves no
        // founder.
        let n = format!("i1731b-room-{tag}");
        let (f, x, y) = (
            format!("i1731b-f-{tag}"),
            format!("i1731b-x-{tag}"),
            format!("i1731b-y-{tag}"),
        );
        reg(d, &[&f, &x, &y]).await;
        found_community(d, &n, "unanimous", &[&f], &[])
            .await
            .expect("I1731b: the room founds");
        // The founder seats two members alone (the room is the founder).
        d.set_node(&f);
        for (i, k) in [&x, &y].into_iter().enumerate() {
            let t = ms(Utc::now() - Duration::hours(2) + Duration::minutes(i as i64));
            let mut seat = ts::sign_community_membership_widening(
                &f,
                CommunityMembershipWidening {
                    community_key_id: n.clone(),
                    member_key_id: k.clone(),
                    joined_at: t,
                    effective_at: t,
                    role: None,
                    persist_row_hash: String::new(),
                },
            );
            if i == 1 {
                ts::cosign_community_membership_widening(&mut seat, &x);
            }
            consent(d, &seat).await;
            d.put_community_membership_widening(seat)
                .await
                .expect("I1731b: seated");
        }
        d.set_node(&x);
        let removal = ts::sign_community_membership_revocation(
            &x,
            CommunityMembershipRevocation {
                community_key_id: n.clone(),
                removed_identity_key_id: f.clone(),
                removed_at: at(),
                effective_at: at(),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        let qk = cosign::quorum_key_of(&GroupSigned::CommunityRevocation(removal.clone())).unwrap();
        let e = d
            .put_community_membership_revocation(removal)
            .await
            .expect_err("I1731b: refused");
        assert_eq!(rule(&e), ROSTER_CONSENSUS_INSUFFICIENT, "I1731b: {e:?}");
        assert!(!held(d, &qk).await, "I1731b: nothing held");
        assert!(active(d, &n, &f).await, "I1731b: the founder stays");
    }

    /// **I1732** — only the local door of the primary's node holds.
    /// Mutations: drop the `speaks_for` test in `hold_inner` → the non-primary
    /// node holds: red; drop the `applying_replicated_group_row` test → the
    /// replicated row is held: red.
    pub(crate) async fn i1732_only_the_primarys_local_door_holds<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1732", "unanimous", 3).await;
        let w = widening(&r, &r.m, at());
        consent(d, &w).await;
        let qk = quorum_key(&w);
        // A node that speaks for another founder.
        d.set_node(&r.founders[1]);
        let e = d
            .put_community_membership_widening(w.clone())
            .await
            .expect_err("I1732: refused at a non-primary node");
        assert_eq!(rule(&e), ROSTER_CONSENSUS_INSUFFICIENT, "I1732: {e:?}");
        assert!(
            !held(d, &qk).await,
            "I1732: nothing held off the primary's node"
        );
        // The primary's node, the event arriving replicated.
        d.set_node(r.a());
        let row = group_plane::plan_group_row(&GroupSigned::CommunityWidening(w))
            .unwrap()
            .expect("a row");
        let applied = d
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await;
        assert!(
            !matches!(&applied, Err(e) if not_landed(e).is_some()),
            "I1732: a replicated event is never held: {applied:?}"
        );
        assert!(!held(d, &qk).await, "I1732: nothing held from a replica");
        assert!(!active(d, &r.cid, &r.m).await);
    }

    /// **I1733** — one open hold per proposer per group. Mutation: drop the
    /// open-receipt test in `admit_row` → the second pending row reaches the
    /// partial UNIQUE index, which refuses it as a backend failure, and the
    /// `cosign_open_pending_exists` assertion is red.
    pub(crate) async fn i1733_one_open_hold_per_proposer<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1733", "unanimous", 3).await;
        let (_w, qk) = hold(d, &r).await;
        let m2 = format!("i1733-m2-{tag}");
        reg(d, &[&m2]).await;
        let w2 = widening(&r, &m2, at() + Duration::minutes(1));
        consent(d, &w2).await;
        let e = d
            .put_community_membership_widening(w2.clone())
            .await
            .expect_err("I1733: the second short event");
        assert_eq!(
            rule(&e),
            ROSTER_CONSENSUS_INSUFFICIENT,
            "I1733: refused as before: {e:?}"
        );
        assert!(!held(d, &quorum_key(&w2)).await, "I1733: no second hold");
        // The second pending row offered as a row (another device of the
        // proposer minted it) is refused by name.
        let pending2 = cosign::pending_row(&GroupSigned::CommunityWidening(w2)).unwrap();
        let e = put(d, pending2).await.expect_err("I1733: refused");
        assert!(
            e.to_string().contains(cosign::COSIGN_OPEN_PENDING_EXISTS),
            "I1733: {e}"
        );
        let open = d.list_open_cosign_receipts().await.unwrap();
        assert_eq!(
            open.iter().filter(|o| o.group_key_id == r.cid).count(),
            1,
            "I1733: one open hold"
        );
        assert_eq!(
            open.iter()
                .find(|o| o.group_key_id == r.cid)
                .unwrap()
                .quorum_key,
            qk
        );
    }

    /// **I1734** — a stranger cannot fill a hold; an assent is no
    /// cosignature. Mutation: drop the `members.contains(&signer)` test in
    /// `admit_row` → the stranger's signature row is stored: red.
    pub(crate) async fn i1734_a_stranger_cannot_fill_a_hold<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1734", "unanimous", 3).await;
        let (w, qk) = hold(d, &r).await;
        let stranger = format!("i1734-s-{tag}");
        reg(d, &[&stranger]).await;
        let row = signature_row(&w, &stranger);
        let id = row.attestation_id.clone();
        let e = put(d, row)
            .await
            .expect_err("I1734: a stranger's cosignature");
        assert_eq!(rule(&e), cosign::COSIGN_SIGNER_NOT_MEMBER, "I1734: {e:?}");
        assert!(!held(d, &id).await, "I1734: not stored");
        // The invitee is no member either.
        let e = put(d, signature_row(&w, &r.m))
            .await
            .expect_err("I1734: the invitee's cosignature");
        assert_eq!(rule(&e), cosign::COSIGN_SIGNER_NOT_MEMBER, "I1734: {e:?}");
        // A self-roster assent naming the hold is not a cosignature.
        for f in &r.founders[1..] {
            let mut assent = Attestation {
                attestation_id: uuid::Uuid::new_v4().to_string(),
                attesting_key_id: f.clone(),
                attested_key_id: f.clone(),
                attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
                weight: None,
                asserted_at: crate::federation::admission::truncate_to_substrate_resolution(
                    Utc::now(),
                ),
                expires_at: None,
                attestation_envelope: crate::federation::self_roster::vote_envelope(f, &qk, true),
                original_content_hash: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: f.clone(),
                scrub_timestamp: Utc::now(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            };
            ts::seal_row_in_place(f, &mut assent);
            let _ = put(d, assent).await;
        }
        assert_eq!(
            cosign::execute_for(d, &qk).await.unwrap(),
            Executed::Open,
            "I1734: assents are never merged"
        );
        assert!(!active(d, &r.cid, &r.m).await);
    }

    /// **I1735** — the audience of a cosign row. Mutations: drop the current-
    /// member filter in `cosign::may_receive` → the since-removed member is
    /// served: red; drop the first arm
    /// of `may_receive` → a non-member is served the pending row (the
    /// federation-scoped row falls to the generic arms; the invitee, its
    /// `attested_key_id`, would be too): red.
    pub(crate) async fn i1735_a_hold_reaches_members_only<D: Node>(d: &D, tag: &str) {
        use crate::federation::replication_audience::may_receive;
        let r = room(d, tag, "i1735", "unanimous", 3).await;
        let (w, qk) = hold(d, &r).await;
        let pending = d.get_attestation(&qk).await.unwrap().unwrap();
        let sig = signature_row(&w, &r.founders[1]);
        let stranger = format!("i1735-s-{tag}");
        reg(d, &[&stranger]).await;
        for row in [&pending, &sig] {
            for f in &r.founders {
                assert!(
                    may_receive(d, f, row).await.unwrap().allowed(),
                    "I1735: a member is served"
                );
            }
            assert!(
                !may_receive(d, &stranger, row).await.unwrap().allowed(),
                "I1735: a non-member is refused"
            );
            assert!(
                !may_receive(d, &r.m, row).await.unwrap().allowed(),
                "I1735: the invitee is refused"
            );
        }
        // A removal's target is a member, and is served.
        let removal = ts::sign_community_membership_revocation(
            r.a(),
            CommunityMembershipRevocation {
                community_key_id: r.cid.clone(),
                removed_identity_key_id: r.founders[2].clone(),
                removed_at: at(),
                effective_at: at(),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        let pending = cosign::pending_row(&GroupSigned::CommunityRevocation(removal)).unwrap();
        assert!(
            may_receive(d, &r.founders[2], &pending)
                .await
                .unwrap()
                .allowed(),
            "I1735: the removal's target is served"
        );
        // A public room is not widened: its cosign rows reach members only.
        let p = format!("i1735-public-{tag}");
        let f: Vec<&str> = r.founders.iter().map(String::as_str).collect();
        found_public_room(d, &p, "unanimous", &f, &[])
            .await
            .expect("I1735: a public room");
        let pw = ts::sign_community_membership_widening(
            r.a(),
            CommunityMembershipWidening {
                community_key_id: p.clone(),
                member_key_id: r.m.clone(),
                joined_at: at(),
                effective_at: at(),
                role: None,
                persist_row_hash: String::new(),
            },
        );
        let pending = cosign::pending_row(&GroupSigned::CommunityWidening(pw)).unwrap();
        assert!(
            !may_receive(d, &stranger, &pending).await.unwrap().allowed(),
            "I1735: a public room's hold is not public"
        );
        assert!(may_receive(d, r.a(), &pending).await.unwrap().allowed());
        // rc18 — a member at the signed instant who was removed since is
        // served nothing (a member still is).
        let q = room(d, tag, "i1735q", "majority", 4).await;
        let w = widening(&q, &q.m, at());
        let pending = cosign::pending_row(&GroupSigned::CommunityWidening(w)).unwrap();
        let gone = q.founders[3].clone();
        assert!(may_receive(d, &gone, &pending).await.unwrap().allowed());
        remove_founder(d, &q, &gone, ms(Utc::now() - Duration::minutes(10))).await;
        assert!(
            !may_receive(d, &gone, &pending).await.unwrap().allowed(),
            "I1735: a member removed after the signed instant is refused"
        );
        assert!(may_receive(d, &q.founders[1], &pending)
            .await
            .unwrap()
            .allowed());
    }

    /// **I1736** — two nodes, different subsets and different ML-DSA bytes.
    /// Mutations: `held_equivalent` returns `Ok(None)` → each node refuses the
    /// other's row (`group_plane_refused`): red; `attestation_wire_hash` hashes
    /// the row's own bytes → the two refs differ: red.
    pub(crate) async fn i1736_two_subsets_land_alike<D: Node>(a: &D, b: &D, tag: &str) {
        use crate::federation::wire_index::attestation_wire_hash_hex;
        let r = room(a, tag, "i1736", "majority", 4).await;
        room_again(b, &r, "majority").await;
        let w = widening(&r, &r.m, at());
        consent(a, &w).await;
        consent(b, &w).await;
        let f = &r.founders;
        // Node A: a + {f1, f2}; node B: a + {f1 signed again, f3}.
        let on_a = cosigned(&w, &[&f[1], &f[2]]);
        let on_b = cosigned(&w, &[&f[1], &f[3]]);
        a.put_community_membership_widening(on_a.clone())
            .await
            .expect("I1736: node A lands");
        b.put_community_membership_widening(on_b.clone())
            .await
            .expect("I1736: node B lands");
        let row_of = |s: &SignedCommunityMembershipWidening| {
            group_plane::plan_group_row(&GroupSigned::CommunityWidening(s.clone()))
                .unwrap()
                .unwrap()
        };
        let (row_a, row_b) = (row_of(&on_a), row_of(&on_b));
        assert_ne!(row_a.attestation_id, row_b.attestation_id, "two rows");
        assert!(held(a, &row_a.attestation_id).await && held(b, &row_b.attestation_id).await);
        assert_eq!(
            attestation_wire_hash_hex(&row_a),
            attestation_wire_hash_hex(&row_b),
            "I1736: one act, one ref"
        );
        // Each offers its row to the other: held, no refusal.
        for (node, row) in [(b, row_a.clone()), (a, row_b.clone())] {
            let o = node
                .apply_replicated_attestation(SignedAttestation { attestation: row })
                .await
                .expect("I1736: the offer settles");
            assert_eq!(o, Outcome::HeldEquivalent, "I1736: {o:?}");
        }
        assert!(active(a, &r.cid, &r.m).await && active(b, &r.cid, &r.m).await);
        // The same signer's signature row under other ML-DSA bytes (the
        // fixture signer is deterministic, so the other bytes are forged:
        // the id is `quorum key ‖ signer`, never the bytes) settles held and
        // writes nothing; it is never a conflict.
        let (pa, _qk) = {
            let x = widening(&r, &format!("i1736-m2-{tag}"), at() + Duration::minutes(2));
            let m2 = x.community_membership_widening.member_key_id.clone();
            reg(a, &[&m2]).await;
            consent(a, &x).await;
            let e = a
                .put_community_membership_widening(x.clone())
                .await
                .unwrap_err();
            (x, not_landed(&e).expect("held").to_owned())
        };
        let sig = signature_row(&pa, &f[1]);
        a.put_attestation(SignedAttestation {
            attestation: sig.clone(),
        })
        .await
        .expect("a cosignature");
        let mut other = sig.clone();
        other.scrub_signature_pqc = Some("AAAA".into());
        other.additional_scrubs[0].scrub_signature_pqc = Some("AAAA".into());
        let o = a
            .apply_replicated_attestation(SignedAttestation { attestation: other })
            .await
            .expect("I1736: the same signer's other bytes");
        assert_eq!(o, Outcome::HeldEquivalent, "I1736: {o:?}");
        assert_eq!(
            a.get_attestation(&sig.attestation_id)
                .await
                .unwrap()
                .unwrap()
                .persist_row_hash,
            sig.persist_row_hash,
            "I1736: the held signature row is untouched"
        );
        // A second diff round: the two nodes advertise the same ref for the
        // act, so neither has anything the other lacks.
        let refs = |rows: Vec<(&'static str, String, String)>| -> Vec<String> {
            rows.into_iter().map(|(_, h, _)| h).collect()
        };
        let ref_a = attestation_wire_hash_hex(&row_a);
        let on_a_refs = refs(
            crate::federation::wire_index::all_kind_hash_keys(a)
                .await
                .unwrap(),
        );
        let on_b_refs = refs(
            crate::federation::wire_index::all_kind_hash_keys(b)
                .await
                .unwrap(),
        );
        assert!(
            on_a_refs.contains(&ref_a) && on_b_refs.contains(&ref_a),
            "I1736: both advertise the act"
        );
        assert!(
            a.lookup_signed_record_by_content_hash("Attestation", &ref_a)
                .await
                .unwrap()
                .is_some()
                && b.lookup_signed_record_by_content_hash("Attestation", &ref_a)
                    .await
                    .unwrap()
                    .is_some(),
            "I1736: the act's ref resolves on both"
        );
    }

    /// **I1737** — expiry and the re-hold bound. Mutations: the too-old test in
    /// `admit_row` dropped → the stale pending row begins a hold: red;
    /// `execute_for` drops the rows but does
    /// not settle the receipt `expired` → the receipt reads open (and a
    /// re-offer would be held again): red.
    pub(crate) async fn i1737_expiry_drops_only_the_hold<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1737", "unanimous", 3).await;
        let (w, qk) = hold(d, &r).await;
        let sig = signature_row(&w, &r.founders[1]);
        let sig_id = sig.attestation_id.clone();
        put(d, sig).await.expect("I1737: a member's cosignature");
        assert!(held(d, &sig_id).await);
        // The node's clock runs past the window.
        let window = cosign::window_secs(
            group_plane::GroupKind::Community,
            group_plane::GroupPlaneFamily::Widening,
            None,
        )
        .unwrap();
        crate::federation::steward_purge::test_clock::set(Some(
            Utc::now() + Duration::seconds(window + 60),
        ));
        let done = cosign::execute_for(d, &qk).await;
        crate::federation::steward_purge::test_clock::set(None);
        assert_eq!(done.unwrap(), Executed::Expired, "I1737");
        assert!(
            !held(d, &qk).await && !held(d, &sig_id).await,
            "I1737: dropped"
        );
        assert_eq!(
            outcome_of(d, &qk).await.as_deref(),
            Some(cosign::outcome::EXPIRED)
        );
        assert!(
            d.lookup_community(&r.cid).await.unwrap().is_some(),
            "I1737: nothing else is dropped"
        );
        // A settled hold is not held again.
        let pending = cosign::pending_row(&GroupSigned::CommunityWidening(w.clone())).unwrap();
        let e = put(d, pending)
            .await
            .expect_err("I1737: a settled re-offer");
        assert!(
            e.to_string().contains(cosign::COSIGN_PENDING_SETTLED),
            "I1737: {e}"
        );
        // rc18 — no hold BEGINS for an event signed more than one window
        // before this node's receipt (its signer still a member).
        let m2 = format!("i1737-m2-{tag}");
        reg(d, &[&m2]).await;
        let stale = widening(&r, &m2, ms(Utc::now() - Duration::seconds(window + 3600)));
        let e = put(
            d,
            cosign::pending_row(&GroupSigned::CommunityWidening(stale.clone())).unwrap(),
        )
        .await
        .expect_err("I1737: too old to begin holding");
        assert!(
            e.to_string().contains(cosign::COSIGN_PENDING_TOO_OLD),
            "I1737: {e}"
        );
        assert!(d
            .cosign_receipt(&quorum_key(&stale))
            .await
            .unwrap()
            .is_none());
        // The assembled event lands though the hold lapsed: the door never
        // asks the window.
        let f = &r.founders;
        d.put_community_membership_widening(cosigned(&w, &[&f[1], &f[2]]))
            .await
            .expect("I1737: the assembled event lands");
        assert!(active(d, &r.cid, &r.m).await);
    }

    /// **I1738** — withdrawal. Mutations: drop the `check_withdraws_target`
    /// call at the attestation door → the signature row's withdrawal is
    /// admitted: red; `withdrawn_by_proposer` answers `false` → the hold stays
    /// open after its proposer withdrew it: red.
    pub(crate) async fn i1738_the_proposer_withdraws<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1738", "unanimous", 3).await;
        let (w, qk) = hold(d, &r).await;
        let sig = signature_row(&w, &r.founders[1]);
        put(d, sig.clone()).await.expect("a cosignature");
        // A cosignature already sent is irrevocable.
        let e = put(d, withdraws_of(&r.founders[1], &[], &sig))
            .await
            .expect_err("I1738: withdrawing a cosignature");
        assert!(
            e.to_string().contains(cosign::COSIGN_SIGNATURE_IRREVOCABLE),
            "I1738: {e}"
        );
        // The proposer withdraws the pending row.
        let pending = d.get_attestation(&qk).await.unwrap().unwrap();
        put(d, withdraws_of(r.a(), &[], &pending))
            .await
            .expect("I1738: the proposer withdraws");
        assert_eq!(
            outcome_of(d, &qk).await.as_deref(),
            Some(cosign::outcome::WITHDRAWN)
        );
        assert!(!held(d, &qk).await, "I1738: no longer held or served");
        assert!(!held(d, &sig.attestation_id).await);
        let again = cosign::pending_row(&GroupSigned::CommunityWidening(w)).unwrap();
        assert!(
            put(d, again).await.is_err(),
            "I1738: a withdrawn hold is not held again"
        );
    }

    /// A `withdraws` of `target` signed by `signer`, co-signed by `cosigners`.
    fn withdraws_of(signer: &str, cosigners: &[&str], target: &Attestation) -> Attestation {
        use crate::federation::envelope::paths;
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(Utc::now());
        let mut envelope = serde_json::json!({
            paths::REFERENCES_ATTESTATION_ID: target.attestation_id,
            paths::WITHDRAWAL_REASON: "cosign witness",
            paths::ASSERTED_AT: crate::federation::admission::render_signed_instant(asserted_at),
        });
        // Placed where its target is (the group plane's cohort target).
        for k in [
            group_plane::GROUP_KIND_MEMBER,
            "family_key_id",
            "community_key_id",
        ] {
            if let Some(v) = target.attestation_envelope.get(k) {
                envelope[k] = v.clone();
            }
        }
        let mut row = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: signer.to_owned(),
            attestation_type: crate::federation::types::attestation_type::WITHDRAWS.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: target.cohort_scope.clone(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::seal_row_in_place(signer, &mut row);
        for c in cosigners {
            let (_, classical, pqc) = ts::sign_envelope(c, &row.attestation_envelope);
            row.additional_scrubs
                .push(crate::federation::types::ScrubSig {
                    scrub_key_id: (*c).to_owned(),
                    scrub_signature_classical: classical,
                    scrub_signature_pqc: pqc,
                    cosigned_at: None,
                });
        }
        row
    }

    /// **I1739** — a cosigned row from before the cut. Mutation: the at-open
    /// pass skips `index_stored_record` → the old `sha256(bytes)` ref still
    /// resolves and the act's does not: red.
    pub(crate) async fn i1739_a_pre_upgrade_row<D: Node>(
        d: &D,
        tag: &str,
        reopen: impl AsyncFnOnce(&D),
        seed_old_ref: impl AsyncFnOnce(&D, &str, &str),
    ) {
        use crate::federation::wire_index::{attestation_wire_hash_hex, content_hash_of};
        let r = room(d, tag, "i1739", "unanimous", 3).await;
        let w = widening(&r, &r.m, at());
        consent(d, &w).await;
        let f = &r.founders;
        let full = cosigned(&w, &[&f[1], &f[2]]);
        d.put_community_membership_widening(full.clone())
            .await
            .expect("I1739: lands");
        let row = group_plane::plan_group_row(&GroupSigned::CommunityWidening(full.clone()))
            .unwrap()
            .unwrap();
        assert!(
            held(d, &row.attestation_id).await,
            "I1739: the id is not re-keyed"
        );
        let old = content_hash_of(&row).unwrap();
        let new = attestation_wire_hash_hex(&row);
        assert_ne!(old, new);
        // The index as a 61.2 node wrote it.
        let rk =
            crate::federation::wire_index::record_key(&[("attestation_id", &row.attestation_id)]);
        seed_old_ref(d, &old, &rk).await;
        reopen(d).await;
        assert!(
            d.lookup_signed_record_by_content_hash("Attestation", &new)
                .await
                .unwrap()
                .is_some(),
            "I1739: the act's ref resolves after open"
        );
        assert!(
            d.lookup_signed_record_by_content_hash("Attestation", &old)
                .await
                .unwrap()
                .is_none(),
            "I1739: the old ref moved"
        );
        // A 61.2 peer's offer of the act with other ML-DSA bytes settles held.
        let other = cosigned(&w, &[&f[2], &f[1]]);
        let offered = group_plane::plan_group_row(&GroupSigned::CommunityWidening(other))
            .unwrap()
            .unwrap();
        assert_ne!(offered.attestation_id, row.attestation_id);
        let o = d
            .apply_replicated_attestation(SignedAttestation {
                attestation: offered,
            })
            .await
            .unwrap();
        assert_eq!(o, Outcome::HeldEquivalent, "I1739");
        let o = d
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap();
        assert_eq!(o, Outcome::Unchanged, "I1739: the held row itself");
    }

    /// **I1740 (round trip)** — the point read resolves the act's ref.
    /// Mutation: the backend's self-check hashes `sha256(bytes)` again → the
    /// act's ref no longer resolves: red.
    pub(crate) async fn i1740_the_point_read_resolves_the_act<D: Node>(d: &D, tag: &str) {
        use crate::federation::wire_index::{attestation_wire_hash_hex, content_hash_of};
        let r = room(d, tag, "i1740", "unanimous", 3).await;
        let w = widening(&r, &r.m, at());
        consent(d, &w).await;
        let f = &r.founders;
        let full = cosigned(&w, &[&f[1], &f[2]]);
        d.put_community_membership_widening(full.clone())
            .await
            .expect("lands");
        let row = group_plane::plan_group_row(&GroupSigned::CommunityWidening(full))
            .unwrap()
            .unwrap();
        let bytes = d
            .lookup_signed_record_by_content_hash("Attestation", &attestation_wire_hash_hex(&row))
            .await
            .unwrap()
            .expect("I1740: the act's ref resolves");
        let served: Attestation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(served.attestation_id, row.attestation_id);
        assert!(
            d.lookup_signed_record_by_content_hash("Attestation", &content_hash_of(&row).unwrap())
                .await
                .unwrap()
                .is_none(),
            "I1740: sha256(bytes) is not the ref of a cosigned row"
        );
        // A row with no cosignature keeps sha256(bytes).
        let pending_like = cosign::pending_row(&GroupSigned::CommunityWidening(w)).unwrap();
        assert_eq!(
            attestation_wire_hash_hex(&pending_like),
            content_hash_of(&pending_like).unwrap()
        );
    }

    /// **I1741** — the executor. Mutations: `execute_for` skips `offer` (the
    /// merged event is never re-offered) → nothing lands by the hook or the
    /// sweep: red; `check_open_self_admit_removal_window` reads the clock
    /// instead of `executing_received_at` → the window gate refuses the
    /// executor's re-offer judged at the hold's receipt: red.
    pub(crate) async fn i1741_the_executor_lands<D: Node>(d: &D, tag: &str) {
        // Through the hook.
        let r = room(d, tag, "i1741h", "unanimous", 3).await;
        let (w, qk) = hold(d, &r).await;
        put(d, signature_row(&w, &r.founders[1])).await.expect("b");
        assert!(!active(d, &r.cid, &r.m).await, "I1741: still short");
        assert!(outcome_of(d, &qk).await.is_none());
        put(d, signature_row(&w, &r.founders[2])).await.expect("c");
        assert!(active(d, &r.cid, &r.m).await, "I1741: the hook lands it");
        assert_eq!(
            outcome_of(d, &qk).await.as_deref(),
            Some(cosign::outcome::LANDED)
        );
        // Through the sweep alone.
        let r = room(d, tag, "i1741s", "unanimous", 3).await;
        let (w, qk) = hold(d, &r).await;
        cosign::test_hook::suppress(true);
        let put_b = put(d, signature_row(&w, &r.founders[1])).await;
        let put_c = put(d, signature_row(&w, &r.founders[2])).await;
        cosign::test_hook::suppress(false);
        put_b.expect("b");
        put_c.expect("c");
        assert!(!active(d, &r.cid, &r.m).await, "I1741: the hook was off");
        assert!(
            cosign::execute_due(d).await.unwrap() >= 1,
            "I1741: the sweep lands it"
        );
        assert!(active(d, &r.cid, &r.m).await);
        assert_eq!(
            outcome_of(d, &qk).await.as_deref(),
            Some(cosign::outcome::LANDED)
        );
        // An `open:self_admit` removal held at receipt, cosigned after its
        // window: judged against the hold's first receipt.
        let p = format!("i1741o-room-{tag}");
        let (x, y, z) = (
            format!("i1741o-x-{tag}"),
            format!("i1741o-y-{tag}"),
            format!("i1741o-z-{tag}"),
        );
        reg(d, &[&x, &y, &z]).await;
        found_room_with_blob(
            d,
            &p,
            crate::federation::types::consensus_protocol::OPEN_SELF_ADMIT,
            &[&x, &y, &z],
            &[],
            Some(serde_json::json!({
                "cohort_subkind": crate::federation::public_room::COHORT_SUBKIND_PUBLIC
            })),
        )
        .await
        .expect("an open room");
        d.set_node(&x);
        let t = ms(Utc::now() - Duration::minutes(1));
        let removal = ts::sign_community_membership_revocation(
            &x,
            CommunityMembershipRevocation {
                community_key_id: p.clone(),
                removed_identity_key_id: z.clone(),
                removed_at: t,
                effective_at: t,
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        let e = d
            .put_community_membership_revocation(removal.clone())
            .await
            .expect_err("I1741: one voice is short");
        let qk = not_landed(&e)
            .unwrap_or_else(|| panic!("I1741: the removal holds: {e:?}"))
            .to_owned();
        // Past the removal window from `removed_at`, inside the hold window
        // from this node's receipt.
        let late = Utc::now()
            + Duration::seconds(
                crate::federation::consensus::OPEN_SELF_ADMIT_REMOVAL_WINDOW_SECS - 30,
            );
        let mut y_signed: SignedCommunityMembershipRevocation = removal.clone();
        ts::cosign_community_membership_revocation(&mut y_signed, &y);
        let row = cosign::signature_row(
            &GroupSigned::CommunityRevocation(removal),
            &y_signed.cosignatures[0],
        )
        .unwrap();
        crate::federation::steward_purge::test_clock::set(Some(late));
        let landed = put(d, row).await;
        crate::federation::steward_purge::test_clock::set(None);
        landed.expect("I1741: the second voice");
        assert_eq!(
            outcome_of(d, &qk).await.as_deref(),
            Some(cosign::outcome::LANDED),
            "I1741: the window is read at the hold's receipt"
        );
        assert!(!active(d, &p, &z).await);
        // The window gate itself: a removal re-offered by the executor long
        // after its window from `removed_at` is judged at the hold's first
        // receipt (inside it), and refused when judged at the door's clock.
        let t = ms(Utc::now() - Duration::minutes(1));
        let removal = ts::sign_community_membership_revocation(
            &x,
            CommunityMembershipRevocation {
                community_key_id: p.clone(),
                removed_identity_key_id: y.clone(),
                removed_at: t,
                effective_at: t,
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        let late = Utc::now()
            + Duration::seconds(
                crate::federation::consensus::OPEN_SELF_ADMIT_REMOVAL_WINDOW_SECS + 60,
            );
        let at_door = crate::federation::community_admit::check_open_self_admit_removal_window(
            d, &removal, late,
        )
        .await
        .expect_err("I1741: judged at the door's clock, outside the window");
        assert_eq!(
            rule(&at_door),
            crate::federation::ROSTER_REMOVAL_OUTSIDE_WINDOW
        );
        cosign::test_executing(
            Utc::now(),
            crate::federation::community_admit::check_open_self_admit_removal_window(
                d, &removal, late,
            ),
        )
        .await
        .expect("I1741: judged at the hold's first receipt, inside the window");
    }

    /// **I1742** — withdraws by id, and the retraction from stored rows.
    /// Mutations: `resolve_withdraws_target` ignores the alias table → the
    /// withdraws stays the retryable gap after the alias lands: red;
    /// `act_retracted` ignores the aliases (the rebuild bypasses the alias) →
    /// the rebuild disagrees with the live table: red; the lifecycle
    /// predicate's alias clause removed → the read fold serves B's row: red.
    pub(crate) async fn i1742_withdraws_by_id<D: Node>(a: &D, b: &D, tag: &str) {
        let r = room(a, tag, "i1742", "majority", 4).await;
        room_again(b, &r, "majority").await;
        let w = widening(&r, &r.m, at());
        consent(a, &w).await;
        consent(b, &w).await;
        let f = &r.founders;
        let on_a = cosigned(&w, &[&f[1], &f[2]]);
        let on_b = cosigned(&w, &[&f[1], &f[3]]);
        a.put_community_membership_widening(on_a.clone())
            .await
            .expect("A");
        b.put_community_membership_widening(on_b.clone())
            .await
            .expect("B");
        let row_b = group_plane::plan_group_row(&GroupSigned::CommunityWidening(on_b))
            .unwrap()
            .unwrap();
        assert!(held(b, &row_b.attestation_id).await);
        let row_a = group_plane::plan_group_row(&GroupSigned::CommunityWidening(on_a))
            .unwrap()
            .unwrap();
        // A cosigned withdraws naming node A's row, by a majority of the five.
        let wd = withdraws_of(&f[0], &[&f[1], &f[2]], &row_a);
        a.apply_replicated_attestation(SignedAttestation {
            attestation: wd.clone(),
        })
        .await
        .expect("I1742: A retracts");
        assert!(!active(a, &r.cid, &r.m).await, "I1742: retracted on A");
        // On B, before the alias: the retryable gap.
        let e = b
            .apply_replicated_attestation(SignedAttestation {
                attestation: wd.clone(),
            })
            .await
            .expect_err("I1742: B does not hold the id yet");
        assert_eq!(
            e.kind(),
            "federation_withdraws_target_unheld",
            "I1742: {e:?}"
        );
        assert!(active(b, &r.cid, &r.m).await);
        // A's row arrives: held equivalent, the alias recorded.
        let o = b
            .apply_replicated_attestation(SignedAttestation {
                attestation: row_a.clone(),
            })
            .await
            .unwrap();
        assert_eq!(o, Outcome::HeldEquivalent);
        assert!(b
            .cosign_alias(&row_a.attestation_id)
            .await
            .unwrap()
            .is_some());
        // The re-offered withdraws resolves through the alias.
        b.apply_replicated_attestation(SignedAttestation { attestation: wd })
            .await
            .expect("I1742: the withdraws lands on B");
        assert!(!active(b, &r.cid, &r.m).await, "I1742: B retracts the act");
        // The retraction holds whatever B recomputes from its stored rows.
        // (1) The projection rebuild from rows agrees with the live table.
        let rebuilt =
            group_plane::projection_rebuild(b, group_plane::GroupPlaneTable::CommunityWidenings)
                .await
                .unwrap();
        assert_eq!(
            rebuilt.live, rebuilt.rebuilt,
            "I1742: the rebuild keeps the retraction"
        );
        // (2) The at-open pass brings nothing back.
        group_plane::rehome_group_records(b).await.unwrap();
        assert!(
            !active(b, &r.cid, &r.m).await,
            "I1742: still retracted after open"
        );
        // (3) Every row of the act offered again settles held: B's own, A's,
        // and a third subset nobody named.
        let third = group_plane::plan_group_row(&GroupSigned::CommunityWidening(cosigned(
            &w,
            &[&f[2], &f[3]],
        )))
        .unwrap()
        .unwrap();
        for row in [row_b.clone(), row_a.clone(), third] {
            let o = b
                .apply_replicated_attestation(SignedAttestation { attestation: row })
                .await
                .expect("I1742: a row of the retracted act settles");
            assert!(
                matches!(o, Outcome::HeldEquivalent | Outcome::Unchanged),
                "I1742: {o:?}"
            );
        }
        assert!(
            !active(b, &r.cid, &r.m).await,
            "I1742: no offer re-lands the act"
        );
        // (4) The read fold (the CEG list, `Live`) hides the withdrawn row on
        // both nodes: A's by its own id, B's through the alias.
        for (node, row) in [(a, &row_a), (b, &row_b)] {
            let filter = crate::read::AttestationFilter {
                attested_key_id: Some(r.m.clone()),
                ..Default::default()
            };
            let scope = crate::scope::caller_scope_from_directory(node, &f[1])
                .await
                .expect("caller scope");
            let page = node
                .list_attestations(filter, None, 1000, scope)
                .await
                .expect("live read");
            assert!(
                !page
                    .items
                    .iter()
                    .any(|i| i.attestation_id == row.attestation_id),
                "I1742: the read fold resolves the withdraws (through the alias on B)"
            );
        }
    }

    /// **I1744** — freshness W on cosign rows (CC 2.6.7, rc18). Mutation: drop
    /// the W test in `admit_row` → the since-removed member's backdated row
    /// meets `cosign_pending_too_old` instead of `asserted_at_stale`: red.
    /// **I1748** (CIRISPersist#1250; CC 4.4.3.4.2) — a short refusal carries
    /// the door's count. At a node that does not speak for the primary (the
    /// door refuses rather than holds), a `unanimous` room of three founders:
    /// one signature is `have 1, need 3`, two are `have 2, need 3`, every
    /// eligible founder named; the third lands it. A `majority` room of four:
    /// one signature is `have 1, need 3`. A member removed from that room who
    /// signs alone is told `have 0, need 2` and NOT the eligible signers (CC
    /// 5.2: roster information goes to members only). A refusal under another
    /// rule (a stranger's widening, `roster_authority_not_established`)
    /// carries no count. Mutation: the door's `refusal` drops the shortfall →
    /// red; the door tells every caller the list → red.
    pub(crate) async fn i1748_a_short_refusal_carries_the_count<D: Node>(d: &D, tag: &str) {
        use crate::federation::consensus::ConsensusShortfall;
        fn short_of(e: &Error) -> (&'static str, Option<ConsensusShortfall>) {
            match e {
                Error::RosterAuthorityUnauthorized {
                    rule, shortfall, ..
                } => (rule, shortfall.clone()),
                other => panic!("I1748: a roster standing refusal, got {other:?}"),
            }
        }
        let sorted = |v: &[String]| {
            let mut v = v.to_vec();
            v.sort();
            v
        };

        let r = room(d, tag, "i1748", "unanimous", 3).await;
        let w = widening(&r, &r.m, at());
        consent(d, &w).await;
        d.set_node(&r.founders[1]);
        for (signers, have) in [(vec![], 1), (vec![r.founders[1].as_str()], 2)] {
            let e = d
                .put_community_membership_widening(cosigned(&w, &signers))
                .await
                .expect_err("I1748: short");
            assert_eq!(
                short_of(&e),
                (
                    ROSTER_CONSENSUS_INSUFFICIENT,
                    Some(ConsensusShortfall {
                        have,
                        need: 3,
                        eligible_signer_key_ids: Some(sorted(&r.founders)),
                    })
                ),
                "I1748 unanimous, {have} signed"
            );
            assert_eq!(
                e.kind(),
                "federation_roster_authority_unauthorized",
                "I1748: the kind() token is unchanged"
            );
        }
        d.put_community_membership_widening(cosigned(&w, &[&r.founders[1], &r.founders[2]]))
            .await
            .expect("I1748: every founder signs, and it lands");
        assert!(active(d, &r.cid, &r.m).await);

        let r4 = room(d, tag, "i1748m", "majority", 4).await;
        let w4 = widening(&r4, &r4.m, at());
        consent(d, &w4).await;
        d.set_node(&r4.founders[1]);
        let e = d
            .put_community_membership_widening(w4)
            .await
            .expect_err("I1748: one of four");
        assert_eq!(
            short_of(&e),
            (
                ROSTER_CONSENSUS_INSUFFICIENT,
                Some(ConsensusShortfall {
                    have: 1,
                    need: 3,
                    eligible_signer_key_ids: Some(sorted(&r4.founders)),
                })
            ),
            "I1748 majority of four"
        );

        // An outsider (CC 5.2): a member removed from the room signs a
        // widening alone. The counts are told; the eligible signers, roster
        // information, are not.
        let gone = r4.founders[3].clone();
        remove_founder(d, &r4, &gone, at()).await;
        d.set_node(&r4.founders[1]);
        let e = d
            .put_community_membership_widening(widening_by(
                &r4,
                &gone,
                &r4.m,
                at() + Duration::minutes(1),
            ))
            .await
            .expect_err("I1748: a removed member's widening");
        assert_eq!(
            short_of(&e),
            (
                ROSTER_CONSENSUS_INSUFFICIENT,
                Some(ConsensusShortfall {
                    have: 0,
                    need: 2,
                    eligible_signer_key_ids: None,
                })
            ),
            "I1748: an outsider is told the count, never the roster"
        );

        let stranger = format!("i1748-x-{tag}");
        reg(d, &[&stranger]).await;
        let by_stranger = widening_by(&r4, &stranger, &stranger, at());
        let e = d
            .put_community_membership_widening(by_stranger)
            .await
            .expect_err("I1748: a stranger's widening");
        let (rule, shortfall) = short_of(&e);
        assert_ne!(rule, ROSTER_CONSENSUS_INSUFFICIENT, "I1748: {e:?}");
        assert_eq!(shortfall, None, "I1748: another rule carries no count");
    }

    /// **I1751** (CIRISPersist#1201; CC 4.4.3.4.2.1) — below `M` a room
    /// counts its whole roster, and `M` latches once reached. A room founded
    /// alone at `quorum:3/4` seats its second member on the founder's
    /// signature (plus the acceptance), its third on both members'
    /// (one alone is `have 1, need 2`); at three members `M` binds, so the
    /// fourth needs three (two are `have 2, need 3`). Two members then resign;
    /// the room of two that once reached `M` is stalled: both signatures are
    /// `have 2, need 3` and the refusal says stalled. The high-water read
    /// answers 4. The node is not the primary's, so a short event is refused
    /// rather than held. Mutation: `quorum_need` ignores the high water (a
    /// roster below `M` always counts itself) → the stalled room admits: red.
    pub(crate) async fn i1751_below_m_counts_the_roster_and_m_latches<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1751", "quorum:3/4", 1).await;
        let f0 = r.founders[0].clone();
        let mk: Vec<String> = (1..=4).map(|i| format!("i1751-m{i}-{tag}")).collect();
        reg(d, &mk.iter().map(String::as_str).collect::<Vec<_>>()).await;
        d.set_node(&format!("i1751-elsewhere-{tag}"));
        let t0 = ms(Utc::now() - Duration::hours(3));
        let at_i = |i: i64| t0 + Duration::minutes(i);
        let count = |e: &Error| match e {
            Error::RosterAuthorityUnauthorized {
                rule, shortfall, ..
            } => (*rule, shortfall.as_ref().map(|s| (s.have, s.need))),
            other => panic!("I1751: a standing refusal, got {other:?}"),
        };
        let seat = |member: &str, signers: &[&str], i: i64| {
            let w = widening_by(&r, signers[0], member, at_i(i));
            cosigned(&w, &signers[1..])
        };
        // The second member: the founder alone, the room being one.
        let w = seat(&mk[0], &[&f0], 1);
        consent(d, &w).await;
        d.put_community_membership_widening(w)
            .await
            .expect("I1751: a room of one seats its second on the founder's word");
        // The third: one of two is short; both seat.
        let w = seat(&mk[1], &[&f0], 2);
        consent(d, &w).await;
        let e = d
            .put_community_membership_widening(w)
            .await
            .expect_err("I1751: one of two");
        assert_eq!(
            count(&e),
            (ROSTER_CONSENSUS_INSUFFICIENT, Some((1, 2))),
            "{e:?}"
        );
        let w = seat(&mk[1], &[&f0, &mk[0]], 3);
        consent(d, &w).await;
        d.put_community_membership_widening(w)
            .await
            .expect("I1751: both members seat the third");
        // At three members M binds: two are short of three.
        let w = seat(&mk[2], &[&f0, &mk[0]], 4);
        consent(d, &w).await;
        let e = d
            .put_community_membership_widening(w)
            .await
            .expect_err("I1751: M binds at three");
        assert_eq!(
            count(&e),
            (ROSTER_CONSENSUS_INSUFFICIENT, Some((2, 3))),
            "{e:?}"
        );
        let w = seat(&mk[2], &[&f0, &mk[0], &mk[1]], 5);
        consent(d, &w).await;
        d.put_community_membership_widening(w)
            .await
            .expect("I1751: three seat the fourth");
        // Two resign: the room of two once reached M.
        for (i, k) in [(6, &mk[1]), (7, &mk[2])] {
            d.put_community_membership_revocation(ts::sign_community_membership_revocation(
                k,
                CommunityMembershipRevocation {
                    community_key_id: r.cid.clone(),
                    removed_identity_key_id: k.clone(),
                    removed_at: at_i(i),
                    effective_at: at_i(i),
                    reason: None,
                    witness_set: Vec::new(),
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("I1751: a resignation needs no one");
        }
        let w = seat(&mk[3], &[&f0, &mk[0]], 8);
        consent(d, &w).await;
        let e = d
            .put_community_membership_widening(w)
            .await
            .expect_err("I1751: a room that reached M and shrank is stalled");
        assert_eq!(
            count(&e),
            (ROSTER_CONSENSUS_INSUFFICIENT, Some((2, 3))),
            "{e:?}"
        );
        assert!(!active(d, &r.cid, &mk[3]).await);
        let record = d.lookup_community(&r.cid).await.unwrap().unwrap();
        assert_eq!(
            crate::federation::community_roster_high_water_at(d, &record, Utc::now())
                .await
                .unwrap(),
            4,
            "I1751: the high water is the largest roster the lineage held"
        );
    }

    pub(crate) async fn i1744_freshness_w_on_cosign_rows<D: Node>(d: &D, tag: &str) {
        let r = room(d, tag, "i1744", "majority", 4).await;
        let gone = r.founders[3].clone();
        let t0 = ms(Utc::now() - Duration::hours(2));
        // `gone` signs at t0, a member then; removed at t1 > t0.
        let w_gone = widening_by(&r, &gone, &r.m, t0);
        remove_founder(d, &r, &gone, ms(Utc::now() - Duration::minutes(20))).await;
        let pending = cosign::pending_row(&GroupSigned::CommunityWidening(w_gone.clone())).unwrap();
        let w_secs = crate::federation::self_roster::PAST_FRESHNESS_W_SECS;
        // Backdated past W at receipt: refused asserted_at_stale.
        crate::federation::steward_purge::test_clock::set(Some(
            Utc::now() + Duration::seconds(w_secs),
        ));
        let stale = put(d, pending.clone()).await;
        crate::federation::steward_purge::test_clock::set(None);
        let e = stale.expect_err("I1744: a since-removed member's backdated row");
        assert!(
            matches!(&e, Error::AssertedAtStale { author, plane: "cosign", .. } if *author == gone),
            "I1744: {e:?}"
        );
        assert!(e.to_string().contains("asserted_at_stale"), "I1744: {e}");
        assert!(!held(d, &pending.attestation_id).await);
        // The same member's row inside W is judged normally (a member at the
        // signed instant): admitted.
        put(d, pending.clone())
            .await
            .expect("I1744: inside W, judged as any member's row");
        assert!(held(d, &pending.attestation_id).await);
        // A still-active member's row older than W is admitted.
        let sig = signature_row(&w_gone, &r.founders[1]);
        cosign::test_hook::suppress(true);
        crate::federation::steward_purge::test_clock::set(Some(
            Utc::now() + Duration::seconds(w_secs),
        ));
        let late = put(d, sig.clone()).await;
        crate::federation::steward_purge::test_clock::set(None);
        cosign::test_hook::suppress(false);
        late.expect("I1744: a member still standing signs at any age");
        assert!(held(d, &sig.attestation_id).await);
    }

    /// **I1743** — the window policy. Mutation: `check_window_value` admits
    /// any integer → the record under the floor is admitted: red.
    pub(crate) async fn i1743_the_window_policy<D: Node>(d: &D, tag: &str) {
        use crate::federation::group_plane::{GroupKind, GroupPlaneFamily};
        let k = format!("i1743-f-{tag}");
        reg(d, &[&k]).await;
        let low = format!("i1743-low-{tag}");
        let e = found_room_with_blob(
            d,
            &low,
            "unanimous",
            &[&k],
            &[],
            Some(serde_json::json!({ "cosign_window_secs": 3600 })),
        )
        .await
        .expect_err("I1743: a window under the floor");
        assert!(
            matches!(&e, Error::GovernancePolicyRefused { reason, .. } if *reason == cosign::WINDOW_BELOW_FLOOR),
            "I1743: {e:?}"
        );
        assert!(d.lookup_community(&low).await.unwrap().is_none());
        let high = format!("i1743-high-{tag}");
        found_room_with_blob(
            d,
            &high,
            "unanimous",
            &[&k],
            &[],
            Some(serde_json::json!({ "cosign_window_secs": 400_000 })),
        )
        .await
        .expect("I1743: a window at or over the floor");
        let blob = d
            .lookup_community(&high)
            .await
            .unwrap()
            .unwrap()
            .policy_blob;
        assert_eq!(
            cosign::window_secs(
                GroupKind::Community,
                GroupPlaneFamily::Widening,
                blob.as_ref()
            )
            .unwrap(),
            400_000
        );
        for (kind, dir) in [
            (GroupKind::Community, GroupPlaneFamily::Widening),
            (GroupKind::Community, GroupPlaneFamily::Removal),
            (GroupKind::Family, GroupPlaneFamily::Widening),
        ] {
            assert_eq!(
                cosign::window_secs(kind, dir, None).unwrap(),
                cosign::WINDOW_FLOOR_SECS,
                "I1743: the class default"
            );
        }
        // A family never reads a blob.
        assert_eq!(
            cosign::window_secs(
                GroupKind::Family,
                GroupPlaneFamily::Removal,
                Some(&serde_json::json!({ "cosign_window_secs": 3600 }))
            )
            .unwrap(),
            cosign::WINDOW_FLOOR_SECS
        );
    }
}

#[cfg(test)]
mod from_disk {
    //! **I1740 (from disk)** — one hash derivation: every attestation ref the
    //! wire index takes, and every backend's point-read self-check, goes
    //! through `attestation_wire_hash` / `reload_record_hashed`.

    fn read(rel: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
            .unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn code(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Mutation: `all_kind_hash_keys` hashes `content_hash_of(&a.attestation)`
    /// again → red.
    #[test]
    fn i1740_one_hash_derivation_from_disk() {
        let wire = code(&read("src/federation/wire_index.rs"));
        let prod = wire.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "content_hash_of(&a)",
            "content_hash_of(&row)",
            "content_hash_of(&a.attestation)",
        ] {
            assert!(
                !prod.contains(forbidden),
                "I1740: wire_index.rs takes an attestation ref as {forbidden}"
            );
        }
        assert!(
            prod.matches("attestation_wire_hash_hex(&").count() >= 4,
            "I1740: the rebuild, the subject refs and the reload each use the one rule"
        );
        assert!(prod.contains("reload_record_hashed(dir, kind, record_key_json)"));
        for backend in ["src/store/sqlite.rs", "src/store/postgres.rs"] {
            let src = code(&read(backend));
            assert!(
                src.contains("wire_index::reload_record_hashed(self, kind, &record_key)"),
                "I1740: {backend}'s point-read self-check asks the one derivation"
            );
            assert!(
                !src.contains(
                    "let recomputed = crate::federation::wire_index::content_hash_of_bytes"
                ),
                "I1740: {backend} recomputes a ref of its own"
            );
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    #[cfg(feature = "sqlite")]
    impl bodies::Node for crate::store::sqlite::SqliteBackend {
        fn set_node(&self, key_id: &str) {
            self.set_node_key_id(key_id);
        }
    }

    #[cfg(feature = "postgres")]
    impl bodies::Node for crate::store::postgres::PostgresBackend {
        fn set_node(&self, key_id: &str) {
            self.set_node_key_id(key_id);
        }
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("1252 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test]
                async fn sqlite() {
                    $body(&super::sqlite().await, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test]
                async fn postgres() {
                    let Some(b) = super::postgres().await else {
                        return;
                    };
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    macro_rules! on_two_nodes {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test]
                async fn sqlite() {
                    let (a, b) = (super::sqlite().await, super::sqlite().await);
                    $body(&a, &b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test]
                async fn postgres() {
                    let Some(a) = super::postgres().await else {
                        return;
                    };
                    let Some(b) = super::postgres().await else {
                        return;
                    };
                    $body(&a, &b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i1730, bodies::i1730_the_shortfall_holds);
    on_every_backend!(i1731, bodies::i1731_another_refusal_still_refuses);
    on_every_backend!(i1732, bodies::i1732_only_the_primarys_local_door_holds);
    on_every_backend!(i1733, bodies::i1733_one_open_hold_per_proposer);
    on_every_backend!(i1734, bodies::i1734_a_stranger_cannot_fill_a_hold);
    on_every_backend!(i1735, bodies::i1735_a_hold_reaches_members_only);
    on_two_nodes!(i1736, bodies::i1736_two_subsets_land_alike);
    on_every_backend!(i1737, bodies::i1737_expiry_drops_only_the_hold);
    on_every_backend!(i1738, bodies::i1738_the_proposer_withdraws);
    on_every_backend!(i1740, bodies::i1740_the_point_read_resolves_the_act);
    on_every_backend!(i1741, bodies::i1741_the_executor_lands);
    on_two_nodes!(i1742, bodies::i1742_withdraws_by_id);
    on_every_backend!(i1743, bodies::i1743_the_window_policy);
    on_every_backend!(i1744, bodies::i1744_freshness_w_on_cosign_rows);
    on_every_backend!(i1748, bodies::i1748_a_short_refusal_carries_the_count);
    on_every_backend!(i1751, bodies::i1751_below_m_counts_the_roster_and_m_latches);

    mod i1739 {
        use super::*;

        #[cfg(feature = "sqlite")]
        #[tokio::test]
        async fn sqlite() {
            let b = super::sqlite().await;
            bodies::i1739_a_pre_upgrade_row(
                &b,
                &tag("s"),
                async |b: &crate::store::sqlite::SqliteBackend| {
                    b.reindex_cosigned_group_rows_at_open().await.unwrap();
                },
                async |b: &crate::store::sqlite::SqliteBackend, old: &str, rk: &str| {
                    b.test_seed_wire_index("Attestation", old, rk).await;
                },
            )
            .await;
        }

        #[cfg(feature = "postgres")]
        #[tokio::test]
        async fn postgres() {
            let Some(b) = super::postgres().await else {
                return;
            };
            bodies::i1739_a_pre_upgrade_row(
                &b,
                &tag("p"),
                async |b: &crate::store::postgres::PostgresBackend| {
                    b.reindex_cosigned_group_rows_at_open().await.unwrap();
                },
                async |b: &crate::store::postgres::PostgresBackend, old: &str, rk: &str| {
                    b.test_seed_wire_index("Attestation", old, rk).await;
                },
            )
            .await;
            eprintln!("i1739: RAN");
        }
    }
}
