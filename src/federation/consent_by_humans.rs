//! CIRISPersist#857 (`FSD/CONSENT_BY_HUMANS.md`) — **consent is by humans,
//! for THIS machine.**
//!
//! The consent that governs what a machine may do with a HUMAN's data — ship
//! traces, replicate, analyze — is the human's, **on a row that names the
//! machine**. An agent still consents for itself within its own agency
//! (partnership acceptance, a shutdown request); that consent is its own and
//! this module leaves it exactly where it is. Every consumer used to perform
//! that walk for itself, and one performed it on the wrong axis for six
//! releases (CIRISServer 0.5.203–0.5.209: the write side keyed by the node,
//! the read side by the engine; zero traces from every split-key home; every
//! test green because the test asked with the key the writer used). The
//! substrate owns the identity model, so it answers the question.
//!
//! The walk is [`steward_bindings_of`](super::admission::steward_bindings_of)
//! — the one fold that already answers "which humans stand behind `k`" —
//! and nothing else (no fourth decider, #720). The operator's constraint
//! (2026-09-17): a human's consent is for THIS agent, never for every machine
//! the human stewards; so a steward's row counts for `k` only when it names
//! `k` in [`FOR_KEY_ID`].

use super::hard_case::ConsentState;
use super::{Error, FederationDirectory};

/// The member that names the machine a human-authored consent row is FOR.
/// On a `consent:replication:v1` grant it is `payload.for_key_id` (a member
/// of the closed grammar — `CONSENT_GRAMMAR_HASH` re-pinned for it); on a
/// `consent:state:*` row it is the envelope member `for_key_id`.
pub const FOR_KEY_ID: &str = "for_key_id";

/// `envelope.for_key_id` (state rows) or `envelope.payload.for_key_id`
/// (replication grants), whichever the row carries.
#[must_use]
pub fn for_key_id_of(envelope: &serde_json::Value) -> Option<&str> {
    envelope
        .get(FOR_KEY_ID)
        .and_then(|v| v.as_str())
        .or_else(|| envelope.get("payload")?.get(FOR_KEY_ID)?.as_str())
}

/// `{k} ∪ steward_bindings_of(k)`, sorted and deduped.
///
/// `k` itself is in the set on purpose, for two different reasons by role.
/// An AGENT has agency and consents for itself within it — it accepts a
/// partnership, it answers a shutdown request — so its own rows are its own
/// consent, not a fallback. A NODE has no agency; its own rows are the legacy
/// machine-authored grants that keep counting until superseded, the state
/// every split-key home is in today. What neither may do is consent on a
/// human's behalf or for another machine (`check_consent_for_key_admission`).
/// A HUMAN key is the identity case (clause 1 of the steward fold), so a
/// caller keyed on either axis gets one answer. An empty steward set is NOT
/// widened to a human: a machine has no human standing behind it until one
/// stands there.
pub async fn consent_principals_of(
    directory: &dyn FederationDirectory,
    k: &str,
) -> Result<Vec<String>, Error> {
    let mut out = super::admission::steward_bindings_of(directory, k).await?;
    out.push(k.to_owned());
    out.sort();
    out.dedup();
    Ok(out)
}

/// **The combine rule** — one function, both doors, spelled once (I98).
///
/// Over the per-principal stances: any `Revoked` → `Revoked`; else any
/// `Granted` → `Granted`; else any `Expired` → `Expired`; else
/// `Unspecified`. A **reverse quorum on the stop** under the accord-ops
/// invariant: any one human standing behind a machine can withdraw its
/// consent for it, and no human's grant overrides another's revocation. A
/// grant beside a silent principal still grants (silence is not refusal); a
/// grant beside an expired one still grants (expiry is lapse, not
/// withdrawal). Within one principal the fold's latest-wins and scope
/// asymmetry are untouched — this composes stances, it does not derive them.
#[must_use]
pub fn combine_principal_stances(stances: &[ConsentState]) -> ConsentState {
    if stances.contains(&ConsentState::Revoked) {
        ConsentState::Revoked
    } else if stances.contains(&ConsentState::Granted) {
        ConsentState::Granted
    } else if stances.contains(&ConsentState::Expired) {
        ConsentState::Expired
    } else {
        ConsentState::Unspecified
    }
}

/// `k`'s own live peers (the strict V109 projection) ∪ the peers of each
/// steward's grants whose `for_key_id == k` (the V147 projection). A
/// steward's grant for a sibling agent contributes nothing. Sorted, deduped.
pub async fn consent_peers_by_principals(
    directory: &dyn FederationDirectory,
    k: &str,
) -> Result<Vec<String>, Error> {
    let stewards = super::admission::steward_bindings_of(directory, k).await?;
    let mut out = directory.list_consent_peers(k).await?;
    for (author, peer) in directory.list_consent_peers_for(k).await? {
        if stewards.contains(&author) {
            out.push(peer);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// `k`'s own stance (the existing fold, unchanged) and, for each steward `p`,
/// the fold over `p`'s rows that name `k` — combined by
/// [`combine_principal_stances`]. A steward's row naming another key, or
/// none, is not in `k`'s universe and folds to `Unspecified` for `k`.
pub async fn resolve_scoped_consent_by_principals(
    directory: &dyn FederationDirectory,
    target_key_id: &str,
    subject_key_id: &str,
    scope: &str,
    qualifier: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ConsentState, Error> {
    let mut stances = vec![
        directory
            .resolve_scoped_consent(target_key_id, subject_key_id, scope, qualifier, now)
            .await?,
    ];
    let stewards = super::admission::steward_bindings_of(directory, subject_key_id).await?;
    if !stewards.is_empty() {
        // The steward's universe for `k`: only the rows that name `k`. Rows
        // that do not are removed from the universe, not merely out-sorted,
        // so a human's blanket-looking row never governs a machine it did not
        // name. Composers (withdraws/recants/supersedes) are kept: they carry
        // no `for_key_id` and the fold reads them for retraction only.
        let rows = directory.list_attestations_for(target_key_id).await?;
        for p in &stewards {
            if p == subject_key_id {
                continue;
            }
            let universe: Vec<super::Attestation> = rows
                .iter()
                .filter(|a| {
                    a.attesting_key_id != *p
                        || super::precedence::is_structural_composer(&a.attestation_type)
                        || for_key_id_of(&a.attestation_envelope) == Some(subject_key_id)
                })
                .cloned()
                .collect();
            stances.push(super::consent::fold_stance(
                &universe,
                p,
                now,
                Some((scope, qualifier)),
            ));
        }
    }
    Ok(combine_principal_stances(&stances))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i95_combine_rule_is_a_reverse_quorum_on_the_stop() {
        use ConsentState::*;
        assert_eq!(combine_principal_stances(&[]), Unspecified);
        assert_eq!(combine_principal_stances(&[Unspecified]), Unspecified);
        assert_eq!(combine_principal_stances(&[Granted]), Granted);
        assert_eq!(
            combine_principal_stances(&[Granted, Unspecified]),
            Granted,
            "silence is not refusal"
        );
        assert_eq!(
            combine_principal_stances(&[Granted, Expired]),
            Granted,
            "expiry is lapse, not withdrawal"
        );
        assert_eq!(
            combine_principal_stances(&[Granted, Revoked]),
            Revoked,
            "any one human can stop"
        );
        assert_eq!(
            combine_principal_stances(&[Revoked, Granted, Granted]),
            Revoked
        );
        assert_eq!(combine_principal_stances(&[Expired, Unspecified]), Expired);
        assert_eq!(combine_principal_stances(&[Expired, Revoked]), Revoked);
    }

    #[test]
    fn for_key_id_is_read_from_either_placement() {
        let state =
            serde_json::json!({"dimension": "consent:state:granted:v1", "for_key_id": "agent-1"});
        let grant = serde_json::json!({"dimension": "consent:replication:v1", "payload": {"grants": "transfer", "attestation_prefixes": ["trace:"], "for_key_id": "agent-1"}});
        let none = serde_json::json!({"dimension": "consent:state:granted:v1"});
        assert_eq!(for_key_id_of(&state), Some("agent-1"));
        assert_eq!(for_key_id_of(&grant), Some("agent-1"));
        assert_eq!(for_key_id_of(&none), None);
    }
}
