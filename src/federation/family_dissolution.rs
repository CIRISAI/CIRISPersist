//! v52.0.0 (CIRISPersist#956) — **a quorum-family's LEAVE and DISSOLVE
//! replicate as amendments.**
//!
//! Since v49 a family record rewrite reaches a peer only as a quorum-proved
//! amendment (`supersede_family_with_quorum` locally, the occupied-id route
//! on replication apply). Two acts had no shape there:
//!
//! - **Dissolve.** An empty roster is refused (`group has no members`), so a
//!   dissolved group stayed live on every peer. A dissolution is now a
//!   TERMINAL amendment: the record is the held record with `dissolved_at`
//!   set and nothing else changed, the quorum signs a change envelope that
//!   carries the same `dissolved_at` (the JCS signing bytes cover it), and it
//!   is judged as an `Add` (a change that moves no one — the strict
//!   direction). A dissolved family has no active members, and every later
//!   write naming it — supersede, widening, revocation, a row placed at it, a
//!   membership reply — is refused [`Error::GroupDissolved`].
//! - **Leave.** Leaving is the member's own act and needs no quorum
//!   (CIRISConstitution#133: forward-only, by the member alone). An amendment
//!   whose ONLY change is removing one member from the record — every other
//!   seat byte-identical, name, founding instant, protocol and entrenchment
//!   unchanged, not a dissolution — is admitted on THAT member's signature
//!   over the change envelope alone, on the local door and on apply.
//!
//! Every check re-derives from the receiving node's own held record.

use super::types::Family;
use super::{Error, FederationDirectory};

/// The change-envelope member a dissolution's quorum signs.
pub const DISSOLVED_AT_MEMBER: &str = "dissolved_at";

/// Refuse when `family` is dissolved.
pub fn refuse_if_dissolved(family: &Family) -> Result<(), Error> {
    match family.dissolved_at {
        Some(dissolved_at) => Err(Error::GroupDissolved {
            group_key_id: family.family_key_id.clone(),
            dissolved_at,
        }),
        None => Ok(()),
    }
}

/// Refuse when the family this directory holds under `family_key_id` is
/// dissolved. An unknown family passes (the caller's own gate decides that).
pub async fn refuse_if_held_family_dissolved<F>(dir: &F, family_key_id: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    match dir.lookup_family(family_key_id).await? {
        Some(f) => refuse_if_dissolved(&f),
        None => Ok(()),
    }
}

/// A founding record is never dissolved.
pub fn check_founding_not_dissolved(offered: &Family) -> Result<(), Error> {
    if offered.dissolved_at.is_some() {
        return Err(Error::InvalidArgument(format!(
            "family {}: a founding record cannot be dissolved; dissolution is a quorum-verified \
             amendment of a held family (CIRISPersist#956)",
            offered.family_key_id
        )));
    }
    Ok(())
}

/// The record's `dissolved_at` is the one the quorum signed: both absent, or
/// both present and the same instant.
pub fn check_dissolution_matches_envelope(
    offered: &Family,
    change_envelope: &serde_json::Value,
) -> Result<(), Error> {
    let signed = match change_envelope.get(DISSOLVED_AT_MEMBER) {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&chrono::Utc))
                .ok_or_else(|| {
                    Error::InvalidArgument(format!(
                        "supersede: change_envelope {DISSOLVED_AT_MEMBER} {v} is not an RFC 3339 \
                         instant"
                    ))
                })?,
        ),
    };
    if signed != offered.dissolved_at {
        return Err(Error::InvalidArgument(format!(
            "supersede: change_envelope {DISSOLVED_AT_MEMBER} {signed:?} != superseding row {:?} \
             — the dissolution the quorum signed is the one stored (CIRISPersist#956)",
            offered.dissolved_at
        )));
    }
    Ok(())
}

/// A dissolution changes nothing but `dissolved_at`.
pub fn check_dissolve_is_terminal_only(stored: &Family, offered: &Family) -> Result<(), Error> {
    if offered.dissolved_at.is_none() {
        return Ok(());
    }
    let same = stored.family_name == offered.family_name
        && stored.founded_at == offered.founded_at
        && stored.consensus_protocol == offered.consensus_protocol
        && stored.consensus_protocol_entrenched == offered.consensus_protocol_entrenched
        && stored.members == offered.members;
    if !same {
        return Err(Error::InvalidArgument(format!(
            "family {}: a dissolution is terminal and changes nothing but dissolved_at \
             (CIRISPersist#956)",
            offered.family_key_id
        )));
    }
    Ok(())
}

/// The member an amendment removes when that removal is its ONLY change:
/// every other seat identical and in order, name, founding instant, protocol
/// and entrenchment unchanged, neither record dissolved. `None` otherwise.
#[must_use]
pub fn self_leave_member<'a>(stored: &'a Family, offered: &Family) -> Option<&'a str> {
    if stored.dissolved_at.is_some()
        || offered.dissolved_at.is_some()
        || stored.family_name != offered.family_name
        || stored.founded_at != offered.founded_at
        || stored.consensus_protocol != offered.consensus_protocol
        || stored.consensus_protocol_entrenched != offered.consensus_protocol_entrenched
        || stored.members.len() != offered.members.len() + 1
    {
        return None;
    }
    let leaver = stored
        .members
        .iter()
        .find(|m| !offered.members.iter().any(|o| o.key_id == m.key_id))?;
    let rest: Vec<_> = stored
        .members
        .iter()
        .filter(|m| m.key_id != leaver.key_id)
        .collect();
    (rest.len() == offered.members.len() && rest.iter().zip(&offered.members).all(|(a, b)| *a == b))
        .then_some(leaver.key_id.as_str())
}

/// The leaver's own signature over the change envelope, and nothing else, is
/// the authority for a self-leave. The envelope must name the held roster in
/// `supersedes.prior_member_key_ids` (anti-replay, as the quorum path) and
/// must not carry a dissolution.
pub async fn verify_self_leave_signature<F>(
    dir: &F,
    stored: &Family,
    change_envelope: &serde_json::Value,
    signatures: &[ciris_verify_core::threshold::ThresholdSignature],
    leaver: &str,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::threshold::ThresholdMember;
    let refuse = |detail: &str| {
        Error::InvalidArgument(format!(
            "self-leave from family {}: {detail} (CIRISPersist#956)",
            stored.family_key_id
        ))
    };
    if !matches!(
        change_envelope.get(DISSOLVED_AT_MEMBER),
        None | Some(serde_json::Value::Null)
    ) {
        return Err(refuse("a self-leave does not dissolve"));
    }
    let claimed_prior: Vec<&str> = change_envelope
        .get("supersedes")
        .and_then(|s| s.get("prior_member_key_ids"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .ok_or_else(|| refuse("the change envelope is missing `supersedes`"))?;
    let held: Vec<&str> = stored.members.iter().map(|m| m.key_id.as_str()).collect();
    if claimed_prior != held {
        return Err(refuse(
            "supersedes.prior_member_key_ids does not match the held roster",
        ));
    }
    let Some(sig) = signatures.iter().find(|s| s.member_id == leaver) else {
        return Err(refuse("the leaver did not sign"));
    };
    let Some(rec) = dir.lookup_public_key(leaver).await? else {
        return Err(refuse("the leaver's key is not registered here"));
    };
    let member = ThresholdMember {
        member_id: rec.key_id,
        ed25519_public_key_base64: rec.pubkey_ed25519_base64,
        mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
        role: None,
    };
    let bytes = ciris_verify_core::accord_genesis::accord_family_signing_bytes(change_envelope)
        .map_err(|e| refuse(&format!("canonicalize: {e}")))?;
    ciris_verify_core::threshold::verify_threshold_signatures(
        &bytes,
        std::slice::from_ref(&member),
        std::slice::from_ref(sig),
        1,
    )
    .map_err(|e| refuse(&format!("the leaver's signature does not verify: {e}")))?;
    Ok(())
}
