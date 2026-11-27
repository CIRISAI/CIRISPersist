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
//!   (CIRISConstitution#133: forward-only, by the member alone). v62.0.0
//!   (RESIGN-3; CC 3.1.3.2) — that act is the `membership:resignation`
//!   leaf, and nothing else. The v52 arm that admitted an amendment dropping
//!   only its signer on that signer's voice alone is RETIRED: a version is
//!   the group's counted row, judged by its quorum like any other.
//!
//! Every check re-derives from the receiving node's own held record.

use super::edition2::fold::{self, reason, Dep};
use super::types::Family;
use super::{Error, FederationDirectory};

/// The change-envelope member a dissolution's quorum signs.
pub const DISSOLVED_AT_MEMBER: &str = "dissolved_at";

/// Refuse when `family` is dissolved.
///
/// v62.0.0 (wave GC7; CC 2.7.3) — `family` is the HELD record, another row
/// than the one being judged: the refusal is a fold condition. Under a fold
/// attempt the row is held (reason `group_dissolved`) and re-folds when the
/// family's record changes; outside one it is the refusal it was.
pub fn refuse_if_dissolved(family: &Family) -> Result<(), Error> {
    fold::reads(Dep::key(&family.family_key_id));
    match family.dissolved_at {
        Some(dissolved_at) => Err(fold::hold(
            reason::GROUP_DISSOLVED,
            Error::GroupDissolved {
                group_key_id: family.family_key_id.clone(),
                dissolved_at,
            },
        )),
        None => Ok(()),
    }
}

/// Refuse when the family this directory holds under `family_key_id` is
/// dissolved. An unknown family passes (the caller's own gate decides that).
pub async fn refuse_if_held_family_dissolved<F>(dir: &F, family_key_id: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave GC7) — read even when absent: a dissolution that lands
    // later re-folds the row.
    fold::reads(Dep::key(family_key_id));
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
///
/// v62.0.0 (wave GC7; CC 2.7.3) — `stored` is the head the dissolution
/// supersedes (another row): held, reason `dissolution_not_terminal_only`,
/// under a fold attempt.
pub fn check_dissolve_is_terminal_only(stored: &Family, offered: &Family) -> Result<(), Error> {
    if offered.dissolved_at.is_none() {
        return Ok(());
    }
    fold::reads(Dep::key(&stored.family_key_id));
    let same = stored.family_name == offered.family_name
        && stored.founded_at == offered.founded_at
        && stored.consensus_protocol == offered.consensus_protocol
        && stored.consensus_protocol_entrenched == offered.consensus_protocol_entrenched
        && stored.members == offered.members;
    if !same {
        return Err(fold::hold(
            reason::DISSOLUTION_NOT_TERMINAL_ONLY,
            Error::InvalidArgument(format!(
                "family {}: a dissolution is terminal and changes nothing but dissolved_at \
                 (CIRISPersist#956)",
                offered.family_key_id
            )),
        ));
    }
    Ok(())
}
