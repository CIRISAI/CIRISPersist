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
///
/// v59.0.0 (CIRISPersist#1099, CC 3.3.6.3) — a steward's grant is one its
/// author signs AS a steward ([`grant_is_authored_by_a_steward`]): the
/// steward's own key, or a live roster key of the steward's self at the
/// grant's `asserted_at`. Read over the live grants themselves (the V147
/// projection's sources), so the ONE predicate decides here and in
/// [`grant_is_authored_for`].
pub async fn consent_peers_by_principals(
    directory: &dyn FederationDirectory,
    k: &str,
) -> Result<Vec<String>, Error> {
    let stewards = super::admission::steward_bindings_of(directory, k).await?;
    let mut out = directory.list_consent_peers(k).await?;
    for g in directory.list_live_consent_grants_for(k).await? {
        if grant_is_authored_by_a_steward(directory, &stewards, &g).await? {
            out.extend(g.subject_key_ids.iter().cloned());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// v59.0.0 (CIRISPersist#1099, CC 3.3.6.3, `CLM-self-roster-authority`) — is
/// `grant`'s author one of `stewards`, acting as that steward at the grant's
/// signed instant ([`acts_as_steward_at`](super::self_roster::acts_as_steward_at))?
async fn grant_is_authored_by_a_steward(
    directory: &dyn FederationDirectory,
    stewards: &[String],
    grant: &super::Attestation,
) -> Result<bool, Error> {
    for s in stewards {
        if super::self_roster::acts_as_steward_at(
            directory,
            s,
            &grant.attesting_key_id,
            grant.asserted_at,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v48.0.0 (CIRISPersist#905) — **the grants that cover `k`'s egress, by
/// principals**: `k`'s own live grants ∪ the live grants each of `k`'s
/// stewards authored naming `k` in `for_key_id`. The same set
/// [`consent_peers_by_principals`] spells for peers, spelled once more for
/// GRANTS because the promotion sweep needs the rows (their grammar, their
/// audience), not the peer names. Deduped by `attestation_id`, newest first.
/// A steward's grant for a sibling machine contributes nothing.
pub async fn live_egress_grants_by_principals(
    directory: &dyn super::FederationDirectory,
    k: &str,
) -> Result<Vec<super::Attestation>, Error> {
    let mut out = directory.list_live_consent_grants_by(k).await?;
    let mut seen: std::collections::HashSet<String> =
        out.iter().map(|a| a.attestation_id.clone()).collect();
    for g in directory.list_live_consent_grants_for(k).await? {
        if grant_is_authored_for(directory, &g, k).await? && seen.insert(g.attestation_id.clone()) {
            out.push(g);
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
    Ok(out)
}

/// v48.0.0 (CIRISPersist#905) — **is `grant` a consent grant FOR `machine`,
/// by principals?** True when the machine authored it itself, or when a
/// steward bound to the machine authored it naming the machine in
/// `for_key_id`. The ONE predicate the promotion sweep's loader and the
/// mesh crossing's `check_grant_covers` both ask — spelled once so "whose
/// consent covers this producer" cannot drift between the two doors.
///
/// v59.0.0 (CIRISPersist#1099, CC 3.3.6.3) — "a steward authored it" is "a
/// steward, or a live roster key of the steward's self at the grant's
/// `asserted_at`" ([`acts_as_steward_at`](super::self_roster::acts_as_steward_at)):
/// a second device of the same person signs as that person; a key of another
/// self does not.
pub async fn grant_is_authored_for(
    directory: &dyn super::FederationDirectory,
    grant: &super::Attestation,
    machine: &str,
) -> Result<bool, Error> {
    if grant.attesting_key_id == machine {
        return Ok(true);
    }
    if for_key_id_of(&grant.attestation_envelope) != Some(machine) {
        return Ok(false);
    }
    let stewards = super::admission::steward_bindings_of(directory, machine).await?;
    grant_is_authored_by_a_steward(directory, &stewards, grant).await
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
    Ok(resolve_scoped_stance_by_principals(
        directory,
        target_key_id,
        subject_key_id,
        scope,
        qualifier,
        now,
    )
    .await?
    .state)
}

/// v53.1.8 (CIRISPersist#1013) — **may `attester` emit a `family` score about
/// `subject`?** The ONE fold the consent-before-scoring gate
/// ([`check_capacity_consent_admission`](super::admission::check_capacity_consent_admission))
/// asks, and the one a scorer's precheck asks before it emits, so the two
/// cannot disagree.
///
/// It walks the principals ([`resolve_scoped_consent_by_principals`]: the
/// subject's own rows, and each steward's rows that name the subject in
/// [`FOR_KEY_ID`]) and asks the family-narrowed scope `analyze:<family>`
/// (#866 C1): a bare `analyze` grant covers it, a grant narrowed to this
/// family covers it, a grant narrowed to another family does not. Before this
/// cut the gate folded only the subject's own rows and a precheck asked bare
/// `analyze`; a steward's grant for the machine passed the precheck and was
/// refused at emit.
///
/// v54.1.0 (CIRISPersist#1041) — kept for one release as a thin wrapper over
/// [`capacity_consent_stance_with_basis`], which the gate asks and which also
/// names the rows the stance rests on.
pub async fn capacity_consent_stance(
    directory: &dyn FederationDirectory,
    attester_key_id: &str,
    subject_key_id: &str,
    family: super::admission::ConsentGatedFamily,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ConsentState, Error> {
    Ok(
        capacity_consent_stance_with_basis(directory, attester_key_id, subject_key_id, family, now)
            .await?
            .0,
    )
}

/// v54.1.0 (CIRISPersist#1041) — [`capacity_consent_stance`] WITH its
/// [`ConsentBasis`]: the consent rows the stance rests on at `now`, each with
/// the principal that authored it and the path that principal stands behind
/// the subject by. The one fold the consent-before-scoring gate asks; a
/// scorer that records the basis in its capacity envelope records what the
/// gate will decide on, because the gate runs this same function.
pub async fn capacity_consent_stance_with_basis(
    directory: &dyn FederationDirectory,
    attester_key_id: &str,
    subject_key_id: &str,
    family: super::admission::ConsentGatedFamily,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(ConsentState, ConsentBasis), Error> {
    let scope = family.analyze_scope();
    crate::observe::fold(
        crate::observe::Fold::ResolveScopedStanceByPrincipals,
        async {
            let folded = per_principal_stances(
                directory,
                attester_key_id, // the consent edge points AT the attester
                subject_key_id,  // and is authored by the subject or a steward naming it
                &scope,
                None,
                now,
            )
            .await?;
            let state = combine_per_principal(&folded).0.state;
            Ok((state, ConsentBasis::of(state, &folded)))
        },
    )
    .await
}

/// v54.1.0 (CIRISPersist#1041) — how a consent row's author stands behind the
/// subject. Stable tokens (serde snake_case); append-only.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPrincipalPath {
    /// The subject's own rows (an agent consents for itself; a node's legacy
    /// machine-authored grants; a `user`-role subject is its own human).
    Subject,
    /// A steward the subject is an ACTIVE occurrence of (clause 2 of
    /// [`steward_bindings_of`](super::admission::steward_bindings_of)), on a
    /// row naming the subject in [`FOR_KEY_ID`].
    OccurrenceOf,
    /// A steward with a LIVE `delegates_to` to the subject (clause 3: an
    /// owner-binding to a person, any delegation to a node), on a row naming
    /// the subject in [`FOR_KEY_ID`].
    DelegatesTo,
}

impl ConsentPrincipalPath {
    /// The stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::OccurrenceOf => "occurrence_of",
            Self::DelegatesTo => "delegates_to",
        }
    }
}

/// v54.1.0 (CIRISPersist#1041) — one row a combined stance rests on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsentBasisRow {
    /// The principal whose fold this row decided: the subject, or a steward.
    pub principal: String,
    /// How `principal` stands behind the subject (more than one when two
    /// steward clauses both hold).
    pub paths: Vec<ConsentPrincipalPath>,
    /// The deciding row's `attestation_id`: the grant that granted, the row
    /// that revoked, the grant whose window lapsed.
    pub attestation_id: String,
}

/// v54.1.0 (CIRISPersist#1041) — **which consent rows a stance rests on.**
///
/// Under the combine rule ([`combine_principal_stances`]) the combined state
/// is decided by every principal whose own fold reached it: for `Granted`,
/// each principal whose fold granted (any one suffices, so all are named); for
/// `Revoked`, each principal that revoked; for `Expired`, each principal whose
/// grant lapsed. `rows` names exactly those principals' deciding rows, the
/// subject first, then stewards by key. `Unspecified` has no basis and `rows`
/// is empty, which is how a gate gap reads apart from an expired grant.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsentBasis {
    /// The deciding rows, see the type doc.
    pub rows: Vec<ConsentBasisRow>,
}

impl ConsentBasis {
    /// The basis of `state` over per-principal folds: each fold that reached
    /// `state` and kept a deciding row.
    fn of(state: ConsentState, folded: &[PrincipalFold]) -> Self {
        Self {
            rows: folded
                .iter()
                .filter(|f| f.stance.state == state)
                .filter_map(|f| {
                    Some(ConsentBasisRow {
                        principal: f.principal.clone(),
                        paths: f.paths.clone(),
                        attestation_id: f.governing.clone()?,
                    })
                })
                .collect(),
        }
    }

    /// The deciding rows' ids, in [`Self::rows`] order (the `evidence_refs` a
    /// scorer writes).
    #[must_use]
    pub fn attestation_ids(&self) -> Vec<&str> {
        self.rows
            .iter()
            .map(|r| r.attestation_id.as_str())
            .collect()
    }
}

/// v44.8.0 (CIRISPersist#866 C1b) — [`resolve_scoped_consent_by_principals`]
/// WITH its bound ([`super::consent::ScopedStance`]): the stance combined by
/// [`combine_principal_stances`], and `retain_until` the **tightest** window
/// any principal signed — a human's `retain:30d` for this machine bounds the
/// machine's own `retain:90d`, never the other way. The one body both doors
/// run.
pub async fn resolve_scoped_stance_by_principals(
    directory: &dyn FederationDirectory,
    target_key_id: &str,
    subject_key_id: &str,
    scope: &str,
    qualifier: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<super::consent::ScopedStance, Error> {
    crate::observe::fold(
        crate::observe::Fold::ResolveScopedStanceByPrincipals,
        resolve_scoped_stance_by_principals_body(
            directory,
            target_key_id,
            subject_key_id,
            scope,
            qualifier,
            now,
        ),
    )
    .await
}

/// [`resolve_scoped_stance_by_principals`]'s fold, run inside its
/// [`crate::observe::fold`].
async fn resolve_scoped_stance_by_principals_body(
    directory: &dyn FederationDirectory,
    target_key_id: &str,
    subject_key_id: &str,
    scope: &str,
    qualifier: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<super::consent::ScopedStance, Error> {
    let folded = per_principal_stances(
        directory,
        target_key_id,
        subject_key_id,
        scope,
        qualifier,
        now,
    )
    .await?;
    Ok(combine_per_principal(&folded).0)
}

/// One principal's fold for the subject: its stance, the row that decided
/// it, and how the principal stands behind the subject.
struct PrincipalFold {
    principal: String,
    paths: Vec<ConsentPrincipalPath>,
    stance: super::consent::ScopedStance,
    governing: Option<String>,
}

/// The stance each principal folds to, the subject first, with the row that
/// decided it and the principal's path (v54.1.0, #1041). The ONE walk [`resolve_scoped_stance_by_principals`] and
/// [`retain_bound_by_principals`] both combine, so "whose rows count for
/// this machine" cannot drift between the consent door and the sweeps.
async fn per_principal_stances(
    directory: &dyn FederationDirectory,
    target_key_id: &str,
    subject_key_id: &str,
    scope: &str,
    qualifier: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<PrincipalFold>, Error> {
    // v53.1.5 — ONE bounded read for every principal (the subject and each
    // steward), shared by the subject's own fold and the per-steward folds;
    // before this cut the target's whole slice was read twice per call (the
    // default `resolve_scoped_stance`, then again here) and cloned once per
    // steward. The subject's stance is the same body the default
    // `resolve_scoped_stance` runs, over the same rows.
    let stewards = super::admission::steward_binding_paths_of(directory, subject_key_id).await?;
    let mut principals: Vec<&str> = vec![subject_key_id];
    principals.extend(
        stewards
            .keys()
            .map(String::as_str)
            .filter(|p| *p != subject_key_id),
    );
    let rows = super::consent::scoped_fold_rows(directory, target_key_id, &principals).await?;
    let refs: Vec<&super::Attestation> = rows.iter().collect();
    let fold_of = |principal: &str,
                   paths: Vec<ConsentPrincipalPath>,
                   universe: &[&super::Attestation]|
     -> PrincipalFold {
        let (stance, winner) = super::consent::fold_scoped_stance_refs_with_winner(
            universe, principal, now, scope, qualifier,
        );
        PrincipalFold {
            principal: principal.to_owned(),
            paths,
            stance,
            governing: winner.map(|w| w.attestation_id.clone()),
        }
    };
    let mut folded = vec![fold_of(
        subject_key_id,
        vec![ConsentPrincipalPath::Subject],
        &refs,
    )];
    // The steward's universe for `k`: only the rows that name `k`. Rows
    // that do not are removed from the universe, not merely out-sorted,
    // so a human's blanket-looking row never governs a machine it did not
    // name. Composers (withdraws/recants/supersedes) are kept: they carry
    // no `for_key_id` and the fold reads them for retraction only.
    for (p, steward_paths) in &stewards {
        if p == subject_key_id {
            continue;
        }
        let universe: Vec<&super::Attestation> = rows
            .iter()
            .filter(|a| {
                a.attesting_key_id != *p
                    || super::precedence::is_structural_composer(&a.attestation_type)
                    || for_key_id_of(&a.attestation_envelope) == Some(subject_key_id)
            })
            .collect();
        let paths = steward_paths
            .iter()
            .filter_map(|sp| match sp {
                super::admission::StewardPath::OccurrenceOf => {
                    Some(ConsentPrincipalPath::OccurrenceOf)
                }
                super::admission::StewardPath::DelegatesTo => {
                    Some(ConsentPrincipalPath::DelegatesTo)
                }
                // Clause (1) names `k` itself, which is the subject's own fold.
                super::admission::StewardPath::SelfUser => None,
            })
            .collect();
        folded.push(fold_of(p, paths, &universe));
    }
    Ok(folded)
}

/// Combine per-principal stances: the state by [`combine_principal_stances`],
/// `retain_until` the TIGHTEST window any principal signed, and the principal
/// whose window that is (the subject wins a tie: it is folded first and
/// `min_by_key` keeps the first minimum).
fn combine_per_principal(
    folded: &[PrincipalFold],
) -> (super::consent::ScopedStance, Option<String>) {
    let stances: Vec<ConsentState> = folded.iter().map(|f| f.stance.state).collect();
    let governing = folded
        .iter()
        .filter_map(|f| f.stance.retain_until.map(|u| (&f.principal, u)))
        .min_by_key(|(_, u)| *u);
    (
        super::consent::ScopedStance {
            state: combine_principal_stances(&stances),
            retain_until: governing.map(|(_, u)| u),
        },
        governing.map(|(p, _)| p.clone()),
    )
}

/// v54.0.0 (CIRISPersist#1015) — what bounds how long `holder` may retain
/// what it holds about `subject`: the `retain` stance by principals and the
/// principal whose window governs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetainBound {
    /// The `retain` stance by principals; `retain_until` is the tightest live
    /// window any principal signed for this machine.
    pub stance: super::consent::ScopedStance,
    /// The principal whose `retain:<window>` is `stance.retain_until`: the
    /// subject itself, or a steward on a row naming the subject in
    /// [`FOR_KEY_ID`]. `None` when no window bounds the retention.
    pub governed_by: Option<String>,
}

/// v54.0.0 (CIRISPersist#1015, ruled 2026-10-09) — **the bound a retention
/// sweep asks before it keeps or evicts**: the subject's own `retain` rows and
/// each steward's `retain` rows naming the subject (`for_key_id`), folded per
/// principal by the same walk the consent door runs, with the MINIMUM live
/// window. A steward's `retain:30d` for this machine bounds the machine's own
/// `retain:90d`: the data is deleted at the shorter window. A steward row that
/// has expired (its signed `expires_at` passed), or that names another
/// machine, bounds nothing. Through v53 both sweeps (the fountain eviction
/// door and the deletion-window watch) folded the subject's rows alone and
/// kept content past a human's window.
pub async fn retain_bound_by_principals(
    directory: &dyn FederationDirectory,
    holder_key_id: &str,
    subject_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RetainBound, Error> {
    crate::observe::fold(
        crate::observe::Fold::ResolveScopedStanceByPrincipals,
        async {
            let folded = per_principal_stances(
                directory,
                holder_key_id,
                subject_key_id,
                super::types::transmission_principle::RETAIN,
                None,
                now,
            )
            .await?;
            let (stance, governed_by) = combine_per_principal(&folded);
            Ok(RetainBound {
                stance,
                governed_by,
            })
        },
    )
    .await
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
