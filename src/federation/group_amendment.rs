//! v49.0.0 (CIRISPersist#910 item 5, `FSD/ROOM_ROSTER_AUTHORITY.md` §10) — a
//! group amendment replicates.
//!
//! Once membership and roles ride the widening planes, what is left on a
//! family or community record — its name, `consensus_protocol`, a community's
//! `policy_blob` — changes only through `supersede_*_with_quorum`. Before
//! v49.0.0 that rewrite reached no peer: the replicated `put_family` kept its
//! first copy and `put_community` refused a differing record (#758).
//!
//! A superseded record now carries a [`GroupSupersedeProof`], and the
//! replicated door routes an occupied id through [`route_occupied_family`] /
//! [`plan_occupied_community`] — one decision for both group kinds:
//!
//! - no stored row: the caller inserts, as before;
//! - identical content (the same `persist_row_hash`): a no-op, as before;
//! - differing content with no proof: refused ([`Error::Conflict`], the #758
//!   shape — now for families too, which used to keep their first copy
//!   silently on SQL and overwrite on memory);
//! - a proof naming a prior version this node does not hold: refused as
//!   STALE ([`Error::Conflict`]; retryable — the intermediate version may not
//!   have arrived) — v62.0.0 (kernel pass 2, I2811): only when the version's
//!   own `prev_head_digest` names the held head (or none). A version naming
//!   another version, whose proof names that same version, is a TIP (CC
//!   2.7.8): it passes the same checks against THIS node's head and is held
//!   beside it ([`ReplicatedCommunityOutcome::HeldAsTip`]); the head does
//!   not move;
//! - otherwise the change envelope must describe the offered record and
//!   [`FederationDirectory::verify_membership_quorum`] must admit it against
//!   THIS node's prior roster under the group's own protocol. Then the record
//!   is applied as a supersede (version bump + history row). Every check
//!   re-derives from the receiving node's verified state; the proof carries
//!   no authority of its own.

use super::cohort::Cohort;
use super::edition2::fold::{self, reason, Dep};
use super::group_supersede_admit::HeadVerdict;
use super::types::{GroupSupersedeProof, SignedCommunity, SignedFamily};
use super::{Error, FederationDirectory};
use crate::kernel::head::HeadReading;

/// v50.0.0 (CIRISPersist#925/#931, review) — which door a community record
/// entered through. The door, never the signer, decides whether the CC 3.2
/// infrastructure conformance gate runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityDoor {
    /// `put_community`: a record authored or submitted on this node. The full
    /// gate runs, whoever signed.
    Local,
    /// `apply_replicated_community`: a record received from a peer. A legacy
    /// non-conformant record is admitted as data; the fold's gates apply.
    ReplicatedApply,
}

/// v50.0.0 (CIRISPersist#931) — the typed outcome of
/// [`FederationDirectory::apply_replicated_community`]. The refusals are
/// typed, so a replication cursor records them and advances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicatedCommunityOutcome {
    /// No record under this id; stored.
    Inserted,
    /// The identical record was already held.
    Unchanged,
    /// A differing record under an occupied id carried a supersede proof this
    /// node's own state authorizes; applied as a supersede.
    Superseded,
    /// Not admitted; nothing changed.
    Refused {
        /// Why.
        reason: ReplicatedCommunityRefusal,
    },
    /// v62.0.0 (kernel pass 2, I2811; CC 2.7.8) — the version names another
    /// version than the held head: held as a tip beside it
    /// (`federation_group_tips`); the head did not move. APPENDED.
    HeldAsTip,
}

/// v50.0.0 (CIRISPersist#931) — why a replicated community record was refused.
/// Closed, snake_case, APPEND-ONLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicatedCommunityRefusal {
    /// A differing record under an occupied id with no proof, or a proof over
    /// a prior version this node does not hold ([`Error::Conflict`]).
    ConflictingRecord,
    /// v50.0.0 (final check) — the record would supersede a CONFORMANT
    /// stored infrastructure record with a non-conformant one (a weakening
    /// supersede, CC 3.2).
    DegradesConformance,
    /// v61 (CIRISPersist#1148) — THIS node is not in the record's audience
    /// (`replication_audience::may_receive_community_record` for its own
    /// key): a replicated door stores only what this node may receive.
    /// APPENDED.
    NotInAudience,
}

/// v50.0.0 (PR #921 review, Codex F3) — what a community write DID, as the
/// write itself saw it: under the serialization the write uses (memory's
/// state lock, sqlite's one writer connection, the postgres statement's own
/// row count, a supersede's prior-hash check under its lock). The typed
/// outcome of [`FederationDirectory::apply_replicated_community`] is a
/// function of this and nothing read before it: a pre-read raced a concurrent
/// apply of the same record, and the door's idempotent no-op still reported
/// `Inserted` / `Superseded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommunityWrite {
    /// The row was stored where none was.
    Inserted,
    /// The identical row was already held; nothing was written.
    Unchanged,
    /// The held row was replaced by the offered version.
    Superseded,
    /// v62.0.0 (kernel pass 2) — the offered version was held as a tip; the
    /// held row was not replaced.
    HeldAsTip,
}

/// v50.0.0 (#931; PR #921 review F3) — the store step's result as a typed
/// outcome: the write's own report, a [`Error::Conflict`] is a typed refusal,
/// a conformance violation is `degrades_conformance`; every other error
/// propagates.
pub(crate) fn replicated_community_outcome(
    stored: Result<CommunityWrite, Error>,
) -> Result<ReplicatedCommunityOutcome, Error> {
    match stored {
        Ok(CommunityWrite::Inserted) => Ok(ReplicatedCommunityOutcome::Inserted),
        Ok(CommunityWrite::Unchanged) => Ok(ReplicatedCommunityOutcome::Unchanged),
        Ok(CommunityWrite::Superseded) => Ok(ReplicatedCommunityOutcome::Superseded),
        Ok(CommunityWrite::HeldAsTip) => Ok(ReplicatedCommunityOutcome::HeldAsTip),
        Err(Error::Conflict(_)) => Ok(ReplicatedCommunityOutcome::Refused {
            reason: ReplicatedCommunityRefusal::ConflictingRecord,
        }),
        Err(Error::CommunityConsensusProtocolViolation { .. }) => {
            Ok(ReplicatedCommunityOutcome::Refused {
                reason: ReplicatedCommunityRefusal::DegradesConformance,
            })
        }
        Err(e) => Err(e),
    }
}

/// v38.2.0 (#758) / PR #921 review F3 — the insert arm's own verdict when its
/// insert found the id occupied (read inside the write): the identical row is
/// `Unchanged`; a differing one is the #758 [`Error::Conflict`].
pub(crate) fn community_insert_lost_to(
    stored_hash: &str,
    offered_hash: &str,
    community_key_id: &str,
) -> Result<CommunityWrite, Error> {
    super::community_reput_verdict(stored_hash, offered_hash, community_key_id)
        .map(|()| CommunityWrite::Unchanged)
}

/// What the replicated door does after the occupied-id decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OccupiedRoute {
    /// No row under this id — the caller inserts.
    Insert,
    /// Settled here: an identical re-put (`Unchanged`, a no-op) or an
    /// amendment applied as a supersede (`Superseded`). The caller writes
    /// nothing more.
    Settled(CommunityWrite),
}

/// The shape both group kinds share for the decision.
struct Offer<'a> {
    cohort: Cohort,
    kind: &'static str,
    group_key_id: &'a str,
    offered_hash: String,
    member_key_ids: std::collections::BTreeSet<&'a str>,
    consensus_protocol: &'a str,
    /// A family's `consensus_protocol_entrenched`; `None` for a community.
    entrenched: Option<bool>,
    proof: Option<&'a GroupSupersedeProof>,
    /// v62.0.0 (kernel pass 2) — the version's own signed `prev_head_digest`:
    /// the version it succeeds, which its proof must name.
    prev_head_digest: &'a str,
}

/// What this node holds under the offered id.
struct Stored {
    persist_row_hash: String,
    entrenched: bool,
}

/// v49.0.0 (#910.5) — the occupied-id decision for a replicated
/// [`SignedFamily`]. Call AFTER the record's own authority scrub has verified.
pub(crate) async fn route_occupied_family<F>(
    dir: &F,
    family: &SignedFamily,
) -> Result<OccupiedRoute, Error>
where
    F: FederationDirectory + ?Sized,
{
    let f = &family.family;
    // v62.0.0 (wave GC5; CC 2.7.3) — the held head, its versions and the
    // roster planes the composition below folds are inputs of this row.
    fold::reads(Dep::key(&f.family_key_id));
    let Some(held) = dir.lookup_family(&f.family_key_id).await? else {
        // v52.0.0 (#955, Q1) — a founding record admits only its signers.
        check_family_founding(dir, family).await?;
        return Ok(OccupiedRoute::Insert);
    };
    let offered_hash = super::types::compute_persist_row_hash(f)?;
    // v52.0.0 (#956) — a differing record under a dissolved id is refused;
    // a dissolution changes nothing but `dissolved_at` and is the one the
    // quorum signed. (An identical re-offer stays a no-op below.)
    if held.persist_row_hash != offered_hash {
        super::family_dissolution::refuse_if_family_ended(dir, &held).await?;
        super::family_dissolution::check_dissolve_is_terminal_only(&held, f)?;
        if let Some(proof) = family.supersede_proof.as_ref() {
            super::family_dissolution::check_dissolution_matches_envelope(
                f,
                &proof.change_envelope,
            )?;
        }
    }
    let offer = Offer {
        cohort: Cohort::Family,
        kind: "family",
        group_key_id: &f.family_key_id,
        offered_hash,
        member_key_ids: f.members.iter().map(|m| m.key_id.as_str()).collect(),
        consensus_protocol: &f.consensus_protocol,
        entrenched: Some(f.consensus_protocol_entrenched),
        proof: family.supersede_proof.as_ref(),
        prev_head_digest: &f.prev_head_digest,
    };
    let stored = Stored {
        persist_row_hash: held.persist_row_hash.clone(),
        entrenched: held.consensus_protocol_entrenched,
    };
    if !admit_amendment(dir, &offer, &stored).await? {
        return Ok(OccupiedRoute::Settled(CommunityWrite::Unchanged));
    }
    super::admission::check_family_consensus_protocol_form(&f.consensus_protocol)?;
    super::admission::validate_family_members(dir, f).await?;
    // v53.0.0 (CC 3.2 T6, consequence (i)) — a family version carries no
    // signed instant, so it is judged at admission.
    super::roster_head::check_version_covers_fold(
        dir,
        super::roster_head::LineageRecord::Family(f),
        crate::host::clock::now(),
    )
    .await?;
    let snapshot = serde_json::to_value(family)
        .map_err(|e| Error::Backend(format!("family amendment snapshot serialize: {e}")))?;
    dir.supersede_group_row(Cohort::Family, snapshot, Some(authorization(&offer)))
        .await?;
    // v62.0.0 (kernel pass 2, I2811) — a version the executor held as a tip
    // left the head where it was.
    let head = dir
        .lookup_family(&f.family_key_id)
        .await?
        .map(|h| h.persist_row_hash);
    Ok(OccupiedRoute::Settled(written_as(
        head.as_deref(),
        &offer.offered_hash,
    )))
}

/// v62.0.0 (kernel pass 2, I2811) — what a supersede that returned `Ok` did,
/// read from the head the group holds after it: the offered version is the
/// head (`Superseded`), or it was held as a tip beside it (`HeldAsTip`).
fn written_as(head_after: Option<&str>, offered_hash: &str) -> CommunityWrite {
    if head_after == Some(offered_hash) {
        CommunityWrite::Superseded
    } else {
        CommunityWrite::HeldAsTip
    }
}

/// v57.0.0 (CIRISPersist#934 step 2) — what an occupied community id gets,
/// as the shared plan decided it ([`plan_occupied_community`]); written by
/// [`apply_occupied_community`] after the plan returns.
#[derive(Debug)]
pub(crate) enum OccupiedCommunity {
    /// No row under this id, and the founding signers are admitted: insert.
    Insert,
    /// The identical record is held: a no-op.
    Unchanged,
    /// A trust-root row (offered or held): applied by its CHAIN, version by
    /// version, through the shared supersede door.
    TrustRootChain,
    /// An amendment this node's own state authorizes: applied as a supersede
    /// under `cohort`, its history row carrying `authorization`.
    Supersede {
        /// The cohort the held record declares (#1034).
        cohort: Cohort,
        /// The history row's `change_authorization`.
        authorization: serde_json::Value,
    },
}

/// v49.0.0 (#910.5) — the occupied-id DECISION for a [`SignedCommunity`].
/// Call AFTER the record's own authority scrub and the community admission
/// checks have passed. v57.0.0 (#934 step 2): reads only, so the shared plan
/// ends in it; [`apply_occupied_community`] writes what it decided.
pub(crate) async fn plan_occupied_community<F>(
    dir: &F,
    community: &SignedCommunity,
) -> Result<OccupiedCommunity, Error>
where
    F: FederationDirectory + ?Sized,
{
    let c = &community.community;
    // v62.0.0 (wave GC5; CC 2.7.3) — the held head is an input of this row.
    fold::reads(Dep::key(&c.community_key_id));
    let Some(stored) = dir.lookup_community(&c.community_key_id).await? else {
        // v52.0.0 (#955, Q1) — a founding record admits only its signers.
        check_community_founding(dir, community).await?;
        return Ok(OccupiedCommunity::Insert);
    };
    // v50.0.0 (CIRISPersist#926 re-check, HIGH-A) — a trust-root row is
    // applied by its CHAIN, not by the one-hop proof below: version by version
    // from the one this node holds (or, over a squat that never passed the
    // door, from the accord birth). The door already judged the whole chain.
    let offered_hash = super::types::compute_persist_row_hash(c)?;
    if super::canonical_community::is_trust_root_grade(c)
        || super::canonical_community::is_trust_root_grade(&stored)
    {
        return Ok(OccupiedCommunity::TrustRootChain);
    }
    // v54.0.0 (CIRISPersist#1034) — the version names the cohort the held
    // record declares, and its history row is recorded under it (an
    // affiliation's prior versions are `affiliations`, as the local supersede
    // door records them).
    let cohort = super::affiliation_config::declared_cohort(c)?;
    // v62.0.0 (wave GC5) — the HELD record's cohort is another row's word:
    // a mismatch holds the version (`federation_affiliation_cohort_mismatch`).
    super::affiliation_config::check_record_is(&stored, cohort)
        .map_err(super::affiliation_config::hold_cohort_mismatch)?;
    let offer = Offer {
        cohort,
        kind: "community",
        group_key_id: &c.community_key_id,
        offered_hash,
        member_key_ids: c.members.iter().map(|m| m.key_id.as_str()).collect(),
        consensus_protocol: &c.consensus_protocol,
        entrenched: None,
        proof: community.supersede_proof.as_ref(),
        prev_head_digest: &c.prev_head_digest,
    };
    let stored = Stored {
        persist_row_hash: stored.persist_row_hash,
        entrenched: false,
    };
    if !admit_amendment(dir, &offer, &stored).await? {
        return Ok(OccupiedCommunity::Unchanged);
    }
    Ok(OccupiedCommunity::Supersede {
        cohort,
        authorization: authorization(&offer),
    })
}

/// v57.0.0 (CIRISPersist#934 step 2) — write what [`plan_occupied_community`]
/// decided, through the shared supersede door. A supersede that lost its race
/// to the same record is `Unchanged` (PR #921 review F3); a trust-root chain
/// that found the id empty after all inserts, behind the founding check.
pub(crate) async fn apply_occupied_community<F>(
    dir: &F,
    community: &SignedCommunity,
    occupied: OccupiedCommunity,
) -> Result<OccupiedRoute, Error>
where
    F: FederationDirectory + ?Sized,
{
    let c = &community.community;
    match occupied {
        OccupiedCommunity::Insert => Ok(OccupiedRoute::Insert),
        OccupiedCommunity::Unchanged => Ok(OccupiedRoute::Settled(CommunityWrite::Unchanged)),
        OccupiedCommunity::TrustRootChain => {
            let offered_hash = super::types::compute_persist_row_hash(c)?;
            let applied =
                super::canonical_community::apply_trust_root_chain_counted(dir, community).await;
            match lost_race(dir, &c.community_key_id, &offered_hash, applied).await? {
                None => {
                    check_community_founding(dir, community).await?;
                    Ok(OccupiedRoute::Insert)
                }
                Some(0) => Ok(OccupiedRoute::Settled(CommunityWrite::Unchanged)),
                Some(_) => Ok(OccupiedRoute::Settled(CommunityWrite::Superseded)),
            }
        }
        OccupiedCommunity::Supersede {
            cohort,
            authorization,
        } => {
            let offered_hash = super::types::compute_persist_row_hash(c)?;
            let snapshot = serde_json::to_value(community).map_err(|e| {
                Error::Backend(format!("community amendment snapshot serialize: {e}"))
            })?;
            let written = dir
                .supersede_group_row(cohort, snapshot, Some(authorization))
                .await
                .map(|_| Some(1));
            Ok(
                match lost_race(dir, &c.community_key_id, &offered_hash, written).await? {
                    Some(0) => OccupiedRoute::Settled(CommunityWrite::Unchanged),
                    _ => {
                        // v62.0.0 (kernel pass 2, I2811) — held as a tip, or
                        // the head
                        let head = dir
                            .lookup_community(&c.community_key_id)
                            .await?
                            .map(|h| h.persist_row_hash);
                        OccupiedRoute::Settled(written_as(head.as_deref(), &offered_hash))
                    }
                },
            )
        }
    }
}

/// v52.0.0 (CIRISPersist#955, Q1) — a founding family admits only the members
/// who signed it (its authority or a co-signer).
async fn check_family_founding<F>(dir: &F, family: &SignedFamily) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // v52.0.0 (#956) — a family is never founded dissolved.
    super::family_dissolution::check_founding_not_dissolved(&family.family)?;
    let signers: Vec<&str> = std::iter::once(family.authority_key_id.as_str())
        .chain(
            family
                .cosignatures
                .iter()
                .map(|c| c.authority_key_id.as_str()),
        )
        .collect();
    let members: Vec<&str> = family
        .family
        .members
        .iter()
        .map(|m| m.key_id.as_str())
        .collect();
    super::membership_acceptance::check_founding_signers(
        dir,
        &family.family.family_key_id,
        &members,
        &signers,
    )
    .await
}

/// v52.0.0 (CIRISPersist#955, Q1) — the community twin of
/// [`check_family_founding`].
async fn check_community_founding<F>(dir: &F, community: &SignedCommunity) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let signers: Vec<&str> = std::iter::once(community.authority_key_id.as_str())
        .chain(
            community
                .cosignatures
                .iter()
                .map(|c| c.authority_key_id.as_str()),
        )
        .collect();
    super::membership_acceptance::check_community_founding_signers(
        dir,
        &community.community,
        &signers,
    )
    .await
}

/// PR #921 review (Codex F3) — a supersede that lost its race. The
/// supersede checks the prior version its proof names UNDER the backend's
/// write serialization; a concurrent apply of the same record that got there
/// first makes that check fail stale ([`Error::Conflict`]). If the row now
/// held IS the offered version, this write changed nothing and the record is
/// held: `Some(0)` (`Unchanged`), not a refusal. Any other result passes
/// through: `Ok(n)` is what the write did (`None`: nothing stored, insert),
/// and a Conflict over a row that differs from the offer stays a Conflict.
async fn lost_race<F>(
    dir: &F,
    community_key_id: &str,
    offered_hash: &str,
    written: Result<Option<usize>, Error>,
) -> Result<Option<usize>, Error>
where
    F: FederationDirectory + ?Sized,
{
    match written {
        Err(Error::Conflict(m)) => {
            // v62.0.0 (wave GC5; CC 2.7.3) — the race is decided by the row
            // held after it: another row. A differing winner holds this
            // version (`group_occupied_by_another_version`), concluding
            // nothing; it re-folds when the group's head moves.
            fold::reads(Dep::key(community_key_id));
            match dir.lookup_community(community_key_id).await? {
                Some(held) if held.persist_row_hash == offered_hash => Ok(Some(0)),
                _ => Err(fold::hold(reason::GROUP_OCCUPIED, Error::Conflict(m))),
            }
        }
        other => other,
    }
}

/// `Ok(false)` — identical content, nothing to do. `Ok(true)` — an amendment
/// this node's own state authorizes; the caller applies it. `Err` — refused.
async fn admit_amendment<F>(dir: &F, offer: &Offer<'_>, stored: &Stored) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if stored.persist_row_hash == offer.offered_hash {
        return Ok(false);
    }
    // v62.0.0 (wave GC5; CC 2.7.3) — every check below reads the head this
    // node holds (another row): unmet, the version is HELD, concluding
    // nothing, and re-folds when the group's head moves.
    fold::reads(Dep::key(offer.group_key_id));
    let Some(proof) = offer.proof else {
        return Err(fold::hold(
            reason::GROUP_OCCUPIED,
            group_reput_refusal(
                offer.kind,
                offer.group_key_id,
                &stored.persist_row_hash,
                &offer.offered_hash,
            ),
        ));
    };
    // v62.0.0 (kernel pass 2, I2811) — the proof names the version the
    // offered version names: the held head (a successor), or another (a tip,
    // judged below against this node's head and held beside it).
    check_proof_names_versions_prior(
        offer.kind,
        offer.group_key_id,
        proof,
        offer.prev_head_digest,
        &stored.persist_row_hash,
    )?;
    if let Some(offered_entrenched) = offer.entrenched {
        check_family_entrenchment(
            stored.entrenched,
            offered_entrenched,
            &proof.change_envelope,
        )?;
    }
    super::assert_change_envelope_matches(
        offer.group_key_id,
        &offer.member_key_ids,
        offer.consensus_protocol,
        &proof.change_envelope,
    )?;
    // v52.0.0 (#955, Q2) — an amendment never adds; joining is proposal →
    // acceptance → widening, which carries the signed instant expiry needs.
    super::membership_acceptance::check_supersede_adds_no_member(
        offer.group_key_id,
        &offer.member_key_ids.iter().copied().collect::<Vec<_>>(),
        &super::membership_acceptance::supersede_allowed_members(
            dir,
            offer.cohort,
            offer.group_key_id,
        )
        .await?,
    )?;
    // v62.0.0 (RESIGN-3; CC 3.1.3.2) — every amendment is the group's
    // counted version: one dropping only its own signer meets the quorum like
    // any other (the self-leave arm of #956 is retired; a member's own
    // leaving is the `membership:resignation` leaf).
    dir.verify_membership_quorum(offer.cohort, offer.group_key_id, &proof.change_envelope)
        .await?;
    Ok(true)
}

/// The history row's `change_authorization` — the same shape the local
/// `supersede_*_with_quorum` records.
fn authorization(offer: &Offer<'_>) -> serde_json::Value {
    let proof = offer
        .proof
        .expect("admit_amendment returned true only with a proof");
    serde_json::json!({
        "change_envelope": proof.change_envelope,
        "quorum_signatures": proof.quorum_signatures,
    })
}

/// v49.0.0 (#910.5) — a differing record under an occupied id with no
/// supersede proof. The community arm is the #758 verdict, word for word; the
/// family arm is the same refusal (families kept their first copy silently).
fn group_reput_refusal(kind: &str, group_key_id: &str, stored: &str, offered: &str) -> Error {
    if kind == "community" {
        if let Err(e) = super::community_reput_verdict(stored, offered, group_key_id) {
            return e;
        }
    }
    Error::Conflict(format!(
        "{kind} {group_key_id} already exists with DIFFERENT content (stored \
         persist_row_hash {stored}, offered {offered}) — a re-put of identical content is \
         an idempotent no-op, but a differing record under an occupied id is refused \
         unless it carries a supersede_proof (CIRISPersist#758, #910)"
    ))
}

/// v49.0.0 (#910.5) — the proof must name the version THIS node holds. Also
/// run inside each backend's supersede transaction, so a concurrent write
/// between the check above and the UPDATE cannot slip a proof past it.
pub(crate) fn check_proof_names_prior(
    kind: &str,
    group_key_id: &str,
    proof: &GroupSupersedeProof,
    stored_persist_row_hash: &str,
) -> Result<(), Error> {
    if proof.prior_persist_row_hash == stored_persist_row_hash {
        return Ok(());
    }
    Err(stale_proof(
        kind,
        group_key_id,
        &proof.prior_persist_row_hash,
        stored_persist_row_hash,
    ))
}

/// v53.0.0 (CC 3.2 T6, operator ruling B-1 on CIRISConstitution#136) — **a
/// version names the head it succeeds.** The record at a version IS the
/// lineage head, and its signed `prev_head_digest` must be the
/// `persist_row_hash` of the version this node holds: a version that names
/// another predecessor (or none) is not the successor of this head. Run inside
/// each backend's supersede transaction, against the row it replaces, so the
/// check and the write see the same head. The one exception is an accord birth
/// the trust-root door stores over a squat or a stalled chain: its
/// `authorization` names the replaced row, and a birth names no predecessor.
/// An insert under an unoccupied id is
/// not judged: a node that never held the earlier versions takes the served
/// version as it finds it, as it always has (a served family carries no
/// chain), so a non-empty value there is not evidence of anything.
///
/// v62.0.0 (kernel pass 2, I2811; CC 2.7.8) — **a fork is held as a tip.**
/// The version that does not name the held head is no longer refused: the
/// kernel's reading of the two versions
/// ([`crate::kernel::head::head_answer`]) is a tip beside the head (or a
/// row waiting for the head it names), and the answer is
/// [`HeadVerdict::Tip`]: the executor holds it, the head does not move.
/// The former rule ([`prev_head_names_held`]) still decides
/// [`HeadVerdict::Extends`], and is the differential's reference.
pub(crate) fn check_prev_head_names_held(
    kind: &str,
    group_key_id: &str,
    offered_prev_head_digest: &str,
    stored_persist_row_hash: &str,
    authorization: Option<&serde_json::Value>,
) -> Result<HeadVerdict, Error> {
    let verdict = prev_head_names_held(
        kind,
        group_key_id,
        offered_prev_head_digest,
        stored_persist_row_hash,
        authorization,
    );
    // v62.0.0 (slice C, I1838) — the differential witness: the kernel holds
    // a version that does not name the held head as a tip (CC 2.7.8).
    crate::kernel::witness::held_head(
        group_key_id,
        stored_persist_row_hash,
        offered_prev_head_digest,
        offered_prev_head_digest.is_empty() && authorization.is_some(),
        verdict.is_ok(),
    );
    let reading = crate::kernel::head::head_answer(
        group_key_id,
        Some(stored_persist_row_hash),
        offered_prev_head_digest,
    )
    .value;
    match (verdict, reading) {
        (Ok(()), _) => Ok(HeadVerdict::Extends),
        (Err(_), HeadReading::Tip) => Ok(HeadVerdict::Tip),
        // the kernel reads a version that names no held head as a tip; one
        // that names the held head is admitted above, so this arm is the
        // former refusal, kept rather than turned into an admission.
        // v62.0.0 (wave GC5; CC 2.7.3) — it reads the held head (another
        // row): the version is HELD (`lineage_prev_head_mismatch`),
        // concluding nothing, never refused.
        (Err(e), HeadReading::Extends | HeadReading::NothingHeld) => {
            Err(fold::hold(reason::LINEAGE_PREV_HEAD_MISMATCH, e))
        }
    }
}

/// v62.0.0 (kernel pass 2, I2811) — **the proof rides on the version it
/// proves.** A `supersede_proof` names the prior its quorum replaced; the
/// version's own signed `prev_head_digest` names the version it succeeds.
/// When the version names the held head (or none), the proof must name the
/// held head ([`check_proof_names_prior`]: a STALE proof otherwise,
/// retryable). When it names another version, it is a tip, and the proof
/// must name that same version: a proof naming a third is a contradiction
/// inside one row, refused for its shape before the kernel (CIRISKernel
/// `DIFFERENCES.md` row 8).
pub(crate) fn check_proof_names_versions_prior(
    kind: &str,
    group_key_id: &str,
    proof: &GroupSupersedeProof,
    offered_prev_head_digest: &str,
    stored_persist_row_hash: &str,
) -> Result<(), Error> {
    if offered_prev_head_digest.is_empty() || offered_prev_head_digest == stored_persist_row_hash {
        // v62.0.0 (wave GC5; CC 2.7.3) — STALE reads the held head: the
        // version waits for the intermediate one (held, re-folded). The
        // contradiction below is inside the row itself: a door refusal.
        return check_proof_names_prior(kind, group_key_id, proof, stored_persist_row_hash)
            .map_err(|e| fold::hold(reason::STALE_SUPERSEDE_PROOF, e));
    }
    if proof.prior_persist_row_hash == offered_prev_head_digest {
        return Ok(());
    }
    Err(Error::Conflict(format!(
        "{kind} {group_key_id}: supersede_proof_contradicts_prev_head — the proof replaces \
         persist_row_hash {named:?}, but the version it rides on names prev_head_digest \
         {offered_prev_head_digest:?}; a proof and its version name one prior (CC 2.7.8)",
        named = proof.prior_persist_row_hash
    )))
}

/// [`check_prev_head_names_held`]'s rule.
fn prev_head_names_held(
    kind: &str,
    group_key_id: &str,
    offered_prev_head_digest: &str,
    stored_persist_row_hash: &str,
    authorization: Option<&serde_json::Value>,
) -> Result<(), Error> {
    if offered_prev_head_digest == stored_persist_row_hash {
        return Ok(());
    }
    // An accord BIRTH that the trust-root door stores over a squat or a
    // stalled chain does not succeed the row it replaces: it is a new
    // lineage's first version (empty prev), recorded as a replacement of
    // exactly the held row.
    let replaces_held = authorization.is_some_and(|a| {
        [
            super::canonical_community::BIRTH_REPLACES_UNROOTED,
            super::canonical_community::REBIRTH_REPLACES_STALLED,
        ]
        .iter()
        .any(|label| a.get(*label).and_then(|v| v.as_str()) == Some(stored_persist_row_hash))
    });
    if offered_prev_head_digest.is_empty() && replaces_held {
        return Ok(());
    }
    Err(Error::Conflict(format!(
        "{kind} {group_key_id}: lineage_prev_head_mismatch — the version names \
         prev_head_digest {named:?}, but this node holds head {stored_persist_row_hash}; \
         a version must name the head it succeeds (CC 3.2 T6)",
        named = offered_prev_head_digest
    )))
}

/// The STALE refusal, spelled once for the pre-check and the in-transaction
/// check.
fn stale_proof(kind: &str, group_key_id: &str, named: &str, held: &str) -> Error {
    Error::Conflict(format!(
        "{kind} {group_key_id}: stale supersede_proof — it replaces persist_row_hash \
         {named}, but this node holds {held}; retryable: the intermediate version may not \
         have arrived yet (CIRISPersist#910)"
    ))
}

/// v49.0.0 (#910.5) — an entrenched family stays entrenched, and the change
/// envelope the quorum signed must say what the offered record says. verify's
/// structural gate refuses an envelope that lifts entrenchment; this binds the
/// RECORD to that envelope (verify-A-store-B).
pub(crate) fn check_family_entrenchment(
    stored_entrenched: bool,
    offered_entrenched: bool,
    change_envelope: &serde_json::Value,
) -> Result<(), Error> {
    if stored_entrenched && !offered_entrenched {
        // v62.0.0 (wave GC5; CC 2.7.3) — the stored head's entrenchment is
        // another row's: held (`family_entrenched`). The envelope-vs-row
        // clause below reads only the offered bytes: a door refusal.
        return Err(fold::hold(
            reason::FAMILY_ENTRENCHED,
            Error::InvalidArgument(
                "supersede: an entrenched family refuses an amendment that lifts \
                 consensus_protocol_entrenched"
                    .to_string(),
            ),
        ));
    }
    let envelope_entrenched = change_envelope.get("consensus_protocol_entrenched")
        == Some(&serde_json::Value::Bool(true));
    if envelope_entrenched != offered_entrenched {
        return Err(Error::InvalidArgument(format!(
            "supersede: change_envelope consensus_protocol_entrenched {envelope_entrenched} != \
             superseding row {offered_entrenched}"
        )));
    }
    Ok(())
}

/// #249 Cut G2 / v31.0.0 (#651) — the gated family supersede every local door
/// shares: the protocol form, the authorship gate, then the SIGNED wrapper
/// (with whatever `supersede_proof` the caller verified) as the snapshot.
/// Superseding is not a lesser act than creating — it replaces what creation
/// established — so it is gated identically, and before any write.
pub(crate) async fn supersede_family_signed<F>(
    dir: &F,
    new: SignedFamily,
    authorization: Option<serde_json::Value>,
) -> Result<u32, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (JSON-cut slice F) — the one shared earlier-form refusal,
    // before any parse or verify (CC 2.6.1.12).
    super::edition2::door::refuse_earlier_form("family")?;
    super::admission::check_family_consensus_protocol_form(&new.family.consensus_protocol)?;
    // v62.0.0 (wave GC5) — the held head and its roster planes are inputs.
    fold::reads(Dep::key(&new.family.family_key_id));
    super::verify_family_admission(dir, &new).await?;
    // v52.0.0 (#956) — a dissolved family admits no change, on either door.
    super::family_dissolution::refuse_if_held_family_dissolved(dir, &new.family.family_key_id)
        .await?;
    // v52.0.0 (#955, Q2) — an amendment never adds a member. v62.0.0
    // (RL-fix7): the accord's recovery and roster change, the exceptions
    // v53.0.0 made, are genesis bundles; `verify_family_admission` above
    // refuses every version of the accord.
    let allowed = super::membership_acceptance::supersede_allowed_members(
        dir,
        Cohort::Family,
        &new.family.family_key_id,
    )
    .await?;
    super::membership_acceptance::check_supersede_adds_no_member(
        &new.family.family_key_id,
        &new.family
            .members
            .iter()
            .map(|m| m.key_id.as_str())
            .collect::<Vec<_>>(),
        &allowed,
    )?;
    // v53.0.0 (CC 3.2 T6, consequence (i)) — a version of a witnessed lineage
    // reflects the roster planes; a family version carries no signed instant,
    // so it is judged at admission.
    super::roster_head::check_version_covers_fold(
        dir,
        super::roster_head::LineageRecord::Family(&new.family),
        crate::host::clock::now(),
    )
    .await?;
    // The snapshot is the SIGNED WRAPPER, not the bare record: the record and
    // the signature that authorizes it travel together, because the way they
    // go stale is by being able to move apart (#651).
    let snapshot = serde_json::to_value(&new)
        .map_err(|e| Error::Backend(format!("supersede_family snapshot serialize: {e}")))?;
    dir.supersede_group_row(Cohort::Family, snapshot, authorization)
        .await
}

/// The community / affiliations twin of [`supersede_family_signed`]; `cohort`
/// picks the history discriminator (CC 4.4.3.2.8 / #308 — both share the
/// `federation_communities` row). `generic_quorum_skipped` is true when the
/// caller skipped the folded-roster quorum because a trust root's chain held
/// (the founders' link stands in for it); if the chain no longer holds here,
/// the supersede is refused, never written unquorate.
pub(crate) async fn supersede_community_signed<F>(
    dir: &F,
    cohort: Cohort,
    new: SignedCommunity,
    authorization: Option<serde_json::Value>,
    generic_quorum_skipped: bool,
) -> Result<u32, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (JSON-cut slice F) — the one shared earlier-form refusal,
    // before any parse or verify (CC 2.6.1.12).
    super::edition2::door::refuse_earlier_form("community")?;
    super::check_consensus_protocol_form(&new.community.consensus_protocol)?;
    // v62.0.0 (wave GC5) — the held head and its roster planes are inputs.
    fold::reads(Dep::key(&new.community.community_key_id));
    // v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — the held record is the
    // cohort this door addresses, the new version declares the same cohort,
    // and an affiliation's config validates against the new roster.
    super::affiliation_config::check_group_cohort(dir, cohort, &new.community.community_key_id)
        .await?;
    super::affiliation_config::check_record_is(&new.community, cohort)?;
    super::affiliation_config::check_community_record(&new.community)?;
    super::verify_community_admission(dir, &new).await?;
    // v62.0.0 (LINEAGE-L6b (b)) — the v61 S2 "room stored under
    // founder_only" gates are DELETED: no such room can exist on a v62 node
    // (the edition upgrade deletes the earlier store, CC "nothing carries";
    // every edition-2 roster version, replicated or not, takes the record
    // door's Local branch, which refuses founder_only above the family;
    // the earlier-form replicated door is shut). A guard nothing reaches is
    // a comment (P/LINEAGE-L6b-b.md: the producer grep).
    // v52.0.0 (#955, Q2) — an amendment never adds a member. The one
    // exception is a trust-root founders' amendment (#926 HIGH-3: its founder
    // seats move ONLY through the record): a founder it seats signed that very
    // version, and signing the record is consent (Q1) — no proposal, so no
    // expiry to judge.
    let mut allowed = super::membership_acceptance::supersede_allowed_members(
        dir,
        cohort,
        &new.community.community_key_id,
    )
    .await?;
    if super::canonical_community::is_trust_root_grade(&new.community) {
        for signer in std::iter::once(new.authority_key_id.as_str())
            .chain(new.cosignatures.iter().map(|c| c.authority_key_id.as_str()))
        {
            allowed.insert(signer.to_owned());
            // KR-fix10 — a signer seats itself and its own person; a node
            // signer seats nobody but itself.
            if let Some(person) = super::admission::consenting_person(dir, signer).await? {
                allowed.insert(person);
            }
        }
    }
    super::membership_acceptance::check_supersede_adds_no_member(
        &new.community.community_key_id,
        &new.community
            .members
            .iter()
            .map(|m| m.key_id.as_str())
            .collect::<Vec<_>>(),
        &allowed,
    )?;
    // v50.0.0 (CIRISPersist#925/#927, CC 3.2) — the supersede is gated as the
    // record it replaces was: an infrastructure record stays quorum:M/N with
    // no node-bearing founder.
    super::admission::check_infrastructure_community_conformance(
        dir.as_dyn_directory(),
        &new.community,
        crate::host::clock::now(),
    )
    .await?;
    // v50.0.0 (CIRISPersist#926) — a trust-root row amends only as a verified
    // founders' link of the held version, and is stored carrying its chain.
    let new =
        super::canonical_community::prepare_trust_root_supersede(dir, new, generic_quorum_skipped)
            .await?;
    // v53.0.0 (CC 3.2 T6, consequence (i)) — judged at the version's own
    // signer-stamped instant (a trust-root link's `amended_at`).
    super::roster_head::check_version_covers_fold(
        dir,
        super::roster_head::LineageRecord::Community(&new.community),
        super::canonical_community::head_instant(&new),
    )
    .await?;
    let snapshot = serde_json::to_value(&new).map_err(|e| {
        Error::Backend(format!(
            "supersede_{} snapshot serialize: {e}",
            cohort.as_str()
        ))
    })?;
    dir.supersede_group_row(cohort, snapshot, authorization)
        .await
}

/// The group id a `supersede_group_row` snapshot (a signed wrapper) names —
/// read before the backend consumes the snapshot, for the stale message and
/// the re-index after commit. Empty for a snapshot that does not decode; the
/// backend's own decode refuses that one.
pub(crate) fn snapshot_group_key_id(cohort: Cohort, snapshot: &serde_json::Value) -> String {
    let (record, key) = match cohort {
        Cohort::Family => ("family", "family_key_id"),
        _ => ("community", "community_key_id"),
    };
    snapshot
        .get(record)
        .and_then(|r| r.get(key))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(entrenched: bool) -> serde_json::Value {
        serde_json::json!({ "consensus_protocol_entrenched": entrenched })
    }

    /// v49.0.0 (#910.5) — an entrenched family refuses an amendment that
    /// lifts entrenchment, and the record's entrenchment must be the one the
    /// quorum signed, in both directions.
    #[test]
    fn entrenchment_is_kept_and_bound_to_the_envelope() {
        assert!(check_family_entrenchment(false, false, &envelope(false)).is_ok());
        assert!(check_family_entrenchment(true, true, &envelope(true)).is_ok());
        let lifted = check_family_entrenchment(true, false, &envelope(false))
            .expect_err("an entrenched family stays entrenched");
        assert!(
            lifted.to_string().contains("entrenched family refuses"),
            "{lifted}"
        );
        for (record, signed) in [(true, false), (false, true)] {
            let e = check_family_entrenchment(false, record, &envelope(signed))
                .expect_err("the record's entrenchment is the one the quorum signed");
            assert!(e.to_string().contains("change_envelope"), "{e}");
        }
    }

    /// The stale refusal is a retryable Conflict naming both hashes.
    #[test]
    fn a_proof_over_another_version_is_stale() {
        let proof = GroupSupersedeProof {
            prior_persist_row_hash: "aa".into(),
            change_envelope: serde_json::Value::Null,
            quorum_signatures: vec![],
        };
        assert!(check_proof_names_prior("family", "f", &proof, "aa").is_ok());
        match check_proof_names_prior("family", "f", &proof, "bb") {
            Err(Error::Conflict(m)) => {
                assert!(
                    m.contains("stale") && m.contains("aa") && m.contains("bb"),
                    "{m}"
                )
            }
            other => panic!("expected a stale Conflict, got {other:?}"),
        }
    }
}
