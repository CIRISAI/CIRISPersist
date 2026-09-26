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
//! [`route_occupied_community`] — one decision for both group kinds:
//!
//! - no stored row: the caller inserts, as before;
//! - identical content (the same `persist_row_hash`): a no-op, as before;
//! - differing content with no proof: refused ([`Error::Conflict`], the #758
//!   shape — now for families too, which used to keep their first copy
//!   silently on SQL and overwrite on memory);
//! - a proof naming a prior version this node does not hold: refused as
//!   STALE ([`Error::Conflict`]; retryable — the intermediate version may not
//!   have arrived);
//! - otherwise the change envelope must describe the offered record and
//!   [`FederationDirectory::verify_membership_quorum`] must admit it against
//!   THIS node's prior roster under the group's own protocol. Then the record
//!   is applied as a supersede (version bump + history row). Every check
//!   re-derives from the receiving node's verified state; the proof carries
//!   no authority of its own.

use super::cohort::Cohort;
use super::types::{GroupSupersedeProof, SignedCommunity, SignedFamily};
use super::{Error, FederationDirectory};

/// What the replicated door does after the occupied-id decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OccupiedRoute {
    /// No row under this id — the caller inserts.
    Insert,
    /// Settled here: an identical re-put (no-op) or an amendment applied as a
    /// supersede. The caller writes nothing more.
    Settled,
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
    let Some(stored) = dir.lookup_family(&f.family_key_id).await? else {
        return Ok(OccupiedRoute::Insert);
    };
    let offer = Offer {
        cohort: Cohort::Family,
        kind: "family",
        group_key_id: &f.family_key_id,
        offered_hash: super::types::compute_persist_row_hash(f)?,
        member_key_ids: f.members.iter().map(|m| m.key_id.as_str()).collect(),
        consensus_protocol: &f.consensus_protocol,
        entrenched: Some(f.consensus_protocol_entrenched),
        proof: family.supersede_proof.as_ref(),
    };
    let stored = Stored {
        persist_row_hash: stored.persist_row_hash,
        entrenched: stored.consensus_protocol_entrenched,
    };
    if !admit_amendment(dir, &offer, &stored).await? {
        return Ok(OccupiedRoute::Settled);
    }
    super::check_consensus_protocol_form(&f.consensus_protocol)?;
    super::admission::validate_family_members(dir, f).await?;
    let snapshot = serde_json::to_value(family)
        .map_err(|e| Error::Backend(format!("family amendment snapshot serialize: {e}")))?;
    dir.supersede_group_row(Cohort::Family, snapshot, Some(authorization(&offer)))
        .await?;
    Ok(OccupiedRoute::Settled)
}

/// v49.0.0 (#910.5) — the occupied-id decision for a replicated
/// [`SignedCommunity`]. Call AFTER the record's own authority scrub and the
/// community admission checks have passed.
pub(crate) async fn route_occupied_community<F>(
    dir: &F,
    community: &SignedCommunity,
) -> Result<OccupiedRoute, Error>
where
    F: FederationDirectory + ?Sized,
{
    let c = &community.community;
    let Some(stored) = dir.lookup_community(&c.community_key_id).await? else {
        return Ok(OccupiedRoute::Insert);
    };
    let offer = Offer {
        cohort: Cohort::Community,
        kind: "community",
        group_key_id: &c.community_key_id,
        offered_hash: super::types::compute_persist_row_hash(c)?,
        member_key_ids: c.members.iter().map(|m| m.key_id.as_str()).collect(),
        consensus_protocol: &c.consensus_protocol,
        entrenched: None,
        proof: community.supersede_proof.as_ref(),
    };
    let stored = Stored {
        persist_row_hash: stored.persist_row_hash,
        entrenched: false,
    };
    if !admit_amendment(dir, &offer, &stored).await? {
        return Ok(OccupiedRoute::Settled);
    }
    let snapshot = serde_json::to_value(community)
        .map_err(|e| Error::Backend(format!("community amendment snapshot serialize: {e}")))?;
    dir.supersede_group_row(Cohort::Community, snapshot, Some(authorization(&offer)))
        .await?;
    Ok(OccupiedRoute::Settled)
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
    let Some(proof) = offer.proof else {
        return Err(group_reput_refusal(
            offer.kind,
            offer.group_key_id,
            &stored.persist_row_hash,
            &offer.offered_hash,
        ));
    };
    check_proof_names_prior(
        offer.kind,
        offer.group_key_id,
        proof,
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
    dir.verify_membership_quorum(
        offer.cohort,
        offer.group_key_id,
        &proof.change_envelope,
        &proof.quorum_signatures,
    )
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
        return Err(Error::InvalidArgument(
            "supersede: an entrenched family refuses an amendment that lifts \
             consensus_protocol_entrenched"
                .to_string(),
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
    super::check_consensus_protocol_form(&new.family.consensus_protocol)?;
    super::verify_family_admission(dir, &new).await?;
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
/// `federation_communities` row).
pub(crate) async fn supersede_community_signed<F>(
    dir: &F,
    cohort: Cohort,
    new: SignedCommunity,
    authorization: Option<serde_json::Value>,
) -> Result<u32, Error>
where
    F: FederationDirectory + ?Sized,
{
    super::check_consensus_protocol_form(&new.community.consensus_protocol)?;
    super::verify_community_admission(dir, &new).await?;
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
