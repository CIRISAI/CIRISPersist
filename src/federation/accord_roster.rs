//! v53.0.0 (CC 4.2.6 / CC 3.2 T6, rc7 `5a4b057`) — **the accord's roster
//! change**, the third shape of the accord's one door.
//!
//! A roster change (add / remove / swap) is a new version of the accord's
//! family record. It is admitted iff:
//!
//! - it names the held head (`prev_head_digest`, the proof's prior);
//! - it changes nothing but `members`, `charter_digest` and the head link;
//! - its change envelope ([`ROSTER_CHANGE_KIND`]) lists the seat changes it
//!   carries, each bound to an AUTHORIZED accord `roster_change` decision
//!   anchored on the held head, whose window has closed and whose
//!   `payload_sha256` is the digest of exactly that change
//!   ([`seat_change_digest`]); applied to the held roster in order, the
//!   changes produce the offered roster;
//! - yes-cosigns over the envelope come from a strict majority of the
//!   STANDING roster — the roster of the head it succeeds, never the live set
//!   (CC 4.2.6: `2·yes > N_standing`);
//! - every holder it adds signed the record (signing the record is consent,
//!   CIRISPersist#955 Q1);
//! - the charter its `charter_digest` names covers exactly its roster
//!   ([`check_charter_covers_roster`], run for every accord version: the head
//!   door, a recovery and this door). An added holder's recovery commitment is
//!   committed in the charter at seating (CC 4.2.6), so a change that adds a
//!   holder names a re-scrubbed charter.
//!
//! A removed holder keeps fire authority until the decision's window closes
//! (lame duck): that is the accord-decision tally's, which this door does not
//! touch — the version is admitted only once the window has closed.

use super::types::SignedFamily;
use super::{Error, FederationDirectory};

/// The change envelope's `kind`.
pub const ROSTER_CHANGE_KIND: &str = "ciris.accord_roster_change.v1";

fn refuse<T>(token: &str, detail: impl std::fmt::Display) -> Result<T, Error> {
    Err(Error::CharterInvalid {
        detail: format!("{token}: {detail}"),
    })
}

/// One seat change as an accord decision binds it: the keys removed and the
/// seats added, each sorted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeatChange {
    /// Holder keys removed.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Seats added.
    #[serde(default)]
    pub add: Vec<SeatAdd>,
}

/// One seat a roster change adds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeatAdd {
    /// The holder key seated.
    pub key_id: String,
    /// Its role on the roster.
    #[serde(default)]
    pub role: Option<String>,
}

/// **The digest an accord `roster_change` proposal binds as its
/// `payload_sha256`**: lowercase hex SHA-256 of JCS
/// `{family_key_id, remove: [sorted], add: [{key_id, role}] sorted by key_id}`.
///
/// # Errors
///
/// Canonicalization failure.
pub fn seat_change_digest(family_key_id: &str, change: &SeatChange) -> Result<String, Error> {
    use sha2::Digest as _;
    let mut remove = change.remove.clone();
    remove.sort();
    let mut add: Vec<serde_json::Value> = change
        .add
        .iter()
        .map(|m| serde_json::json!({ "key_id": m.key_id, "role": m.role }))
        .collect();
    add.sort_by(|a, b| a["key_id"].as_str().cmp(&b["key_id"].as_str()));
    let v = serde_json::json!({ "family_key_id": family_key_id, "remove": remove, "add": add });
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(&v)
        .map_err(|e| Error::InvalidArgument(format!("seat change canonicalize: {e}")))?;
    Ok(hex::encode(sha2::Sha256::digest(&bytes)))
}

/// **Verify an offered accord version as a roster change.** `Ok(None)` when it
/// is not this shape (another family, no proof, another envelope kind);
/// `Ok(Some(added))` — the holders it seats — when it verifies whole; an
/// error naming the refusal when it is this shape and does not.
///
/// # Errors
///
/// [`Error::CharterInvalid`] carrying an `accord_roster_change_*` token;
/// directory read failures.
pub async fn verify_accord_roster_change<F>(
    directory: &F,
    signed: &SignedFamily,
) -> Result<Option<Vec<String>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    if signed.family.family_key_id != accord {
        return Ok(None);
    }
    let Some(proof) = signed.supersede_proof.as_ref() else {
        return Ok(None);
    };
    let env = &proof.change_envelope;
    if env.get("kind").and_then(|k| k.as_str()) != Some(ROSTER_CHANGE_KIND) {
        return Ok(None);
    }
    let offered = &signed.family;
    let Some(held) = directory.lookup_family(accord).await? else {
        return refuse("accord_roster_change_no_held_accord", accord);
    };
    let field = |k: &str| env.get(k).and_then(|v| v.as_str()).unwrap_or_default();
    if field("family_key_id") != accord
        || field("prior_persist_row_hash") != held.persist_row_hash
        || proof.prior_persist_row_hash != held.persist_row_hash
        || offered.prev_head_digest != held.persist_row_hash
        || field("next_persist_row_hash") != super::types::compute_persist_row_hash(offered)?
    {
        return refuse(
            "accord_roster_change_unbound",
            "the envelope must name the accord, the held head it succeeds and this version",
        );
    }
    if offered.family_name != held.family_name
        || offered.founded_at != held.founded_at
        || offered.consensus_protocol != held.consensus_protocol
        || offered.consensus_protocol_entrenched != held.consensus_protocol_entrenched
        || offered.dissolved_at != held.dissolved_at
    {
        return refuse(
            "accord_roster_change_not_seats",
            "a roster change changes the seats (and the charter it names), nothing else",
        );
    }
    // The seat changes, each bound to an authorized decision on this head.
    let changes = env
        .get("changes")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty());
    let Some(changes) = changes else {
        return refuse("accord_roster_change_uncovered", "no decision is named");
    };
    let mut seats: std::collections::BTreeMap<String, Option<String>> = held
        .members
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    let now = chrono::Utc::now();
    let mut seen = std::collections::BTreeSet::new();
    for c in changes {
        let digest = c
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !seen.insert(digest.to_owned()) {
            return refuse(
                "accord_roster_change_uncovered",
                "a decision is named twice",
            );
        }
        let change: SeatChange = serde_json::from_value(c.clone())
            .map_err(|e| Error::InvalidArgument(format!("roster change: {e}")))?;
        let Some(decision) = directory.get_accord_decision(digest).await? else {
            return refuse(
                "accord_roster_change_uncovered",
                format!("no decision {digest}"),
            );
        };
        let p = &decision.decision.proposal;
        let closed = chrono::DateTime::parse_from_rfc3339(&p.window_until)
            .map(|t| t.with_timezone(&chrono::Utc) <= now)
            .unwrap_or(false);
        if !decision.decision.authorized
            || p.action != ciris_verify_core::accord_live_quorum::AccordAction::RosterChange
            || p.family_key_id != accord
            || p.prior_family_digest != held.persist_row_hash
            || !closed
            || p.payload_sha256 != seat_change_digest(accord, &change)?
        {
            return refuse(
                "accord_roster_change_uncovered",
                format!(
                    "decision {digest} is not an authorized roster change of the held head, \
                     closed, binding exactly this seat change"
                ),
            );
        }
        for k in &change.remove {
            if seats.remove(k).is_none() {
                return refuse(
                    "accord_roster_change_uncovered",
                    format!("{k} holds no seat"),
                );
            }
        }
        for m in &change.add {
            if seats.insert(m.key_id.clone(), m.role.clone()).is_some() {
                return refuse(
                    "accord_roster_change_uncovered",
                    format!("{} already holds a seat", m.key_id),
                );
            }
        }
    }
    let offered_seats: std::collections::BTreeMap<String, Option<String>> = offered
        .members
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    if offered_seats != seats {
        return refuse(
            "accord_roster_change_uncovered",
            "the offered roster is not the held roster with the decided changes applied",
        );
    }
    // Yes-cosigns: a strict majority of the STANDING roster (the held head's).
    let standing: Vec<String> = held.members.iter().map(|m| m.key_id.clone()).collect();
    if !super::tier_ingest::standing_majority_signed_by(directory, &standing, proof).await? {
        return refuse(
            "accord_roster_change_short",
            format!(
                "yes-cosigns from fewer than a strict majority of the standing roster \
                 ({} of {})",
                ciris_verify_core::accord_genesis::strict_majority(standing.len()),
                standing.len()
            ),
        );
    }
    // Every added holder consents by signing the record.
    let record_signers: std::collections::BTreeSet<&str> =
        std::iter::once(signed.authority_key_id.as_str())
            .chain(
                signed
                    .cosignatures
                    .iter()
                    .map(|c| c.authority_key_id.as_str()),
            )
            .collect();
    let added: Vec<String> = offered_seats
        .keys()
        .filter(|k| !held.members.iter().any(|m| &&m.key_id == k))
        .cloned()
        .collect();
    if let Some(k) = added.iter().find(|k| !record_signers.contains(k.as_str())) {
        return refuse(
            "accord_roster_change_unconsented",
            format!("added holder {k} did not sign the version that seats them"),
        );
    }
    Ok(Some(added))
}

/// **The charter an accord version names covers EXACTLY its roster** (CC 4.2.6,
/// R2c ruling (a)): every seat has a recovery commitment in force and the
/// charter names no key that holds no seat. A seat whose key a recovery seated
/// takes that recovery's commitment, and the key it replaced is not a stray:
/// `recovery` is the offered version's own recovery statement, if it is one;
/// the recorded ones are read from the chain.
///
/// # Errors
///
/// [`Error::CharterInvalid`] `accord_recovery_commitment_missing` /
/// `accord_recovery_commitment_stray` / `accord_charter_not_held`.
pub async fn check_charter_covers_roster<F>(
    directory: &F,
    offered: &super::types::Family,
    recovery: Option<&serde_json::Value>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::envelope::paths::RECOVERY_COMMITMENTS;
    if offered.charter_digest.is_empty() {
        return refuse(
            "accord_recovery_commitment_missing",
            "the accord's version names no charter, so no holder has a recovery commitment",
        );
    }
    let charter = directory
        .list_attestations_for(&offered.family_key_id)
        .await?
        .into_iter()
        .find(|a| a.persist_row_hash == offered.charter_digest);
    let Some(charter) = charter else {
        return refuse(
            "accord_charter_not_held",
            format!(
                "the charter {} the version names is not held here (retryable: it may not \
                 have arrived)",
                offered.charter_digest
            ),
        );
    };
    let commitments: std::collections::BTreeMap<String, String> = charter
        .attestation_envelope
        .get(RECOVERY_COMMITMENTS)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let mut statements =
        super::accord_recovery::recorded_statements(directory, &offered.family_key_id).await?;
    if let Some(r) = recovery {
        statements.push(r.clone());
    }
    let key = |s: &serde_json::Value, k: &str| {
        s.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let replaced: std::collections::BTreeSet<String> = statements
        .iter()
        .map(|s| key(s, "old_holder_key_id"))
        .collect();
    let recovered: std::collections::BTreeSet<String> = statements
        .iter()
        .map(|s| key(s, "new_holder_key_id"))
        .collect();
    let roster: Vec<&str> = offered.members.iter().map(|m| m.key_id.as_str()).collect();
    charter_commitments_cover(&commitments, &roster, &replaced, &recovered)
        .or_else(|(token, detail)| refuse(token, detail))
}

/// **The one coverage rule**, pure: `commitments` (a charter's
/// `recovery_commitments`) cover `roster` exactly — every seat has an entry or
/// was seated by a recovery (`recovered`), and every entry is a seat or a key a
/// recovery replaced (`replaced`). Shared by the accord version door and the
/// genesis bundle check.
///
/// # Errors
///
/// `(token, detail)`: `accord_recovery_commitment_missing` or
/// `accord_recovery_commitment_stray`.
pub fn charter_commitments_cover(
    commitments: &std::collections::BTreeMap<String, String>,
    roster: &[&str],
    replaced: &std::collections::BTreeSet<String>,
    recovered: &std::collections::BTreeSet<String>,
) -> Result<(), (&'static str, String)> {
    if let Some(missing) = roster
        .iter()
        .find(|k| !commitments.contains_key(**k) && !recovered.contains(**k))
    {
        return Err((
            "accord_recovery_commitment_missing",
            format!(
                "holder {missing} has no recovery commitment in the charter the version names \
                 (CC 4.2.6: committed in the charter at seating)"
            ),
        ));
    }
    if let Some(stray) = commitments
        .keys()
        .find(|k| !roster.contains(&k.as_str()) && !replaced.contains(*k))
    {
        return Err((
            "accord_recovery_commitment_stray",
            format!("the charter commits a recovery key for {stray}, which holds no seat"),
        ));
    }
    Ok(())
}
