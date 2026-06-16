//! §19.1 witness comparison → verdict handling (CIRISPersist#228 item 2 —
//! the security-critical part).
//!
//! Over the **verified** corpus set persist calls
//! [`ciris_verify_core::holonomic::compare_witnesses`] and routes the
//! verdict (N4 / WW-vs-§10.1.6):
//!
//! - [`WitnessComparison::Equivocation`] → **retain + emit a
//!   `hard_case:*`**, NEVER reconcile. Two validly-signed roots from one
//!   `(peer_id, epoch_id, namespace_set)` are non-repudiable; persist
//!   does not delete/merge the pair.
//! - [`WitnessComparison::Divergent`] → **trigger the EXISTING V058 R1/Q1
//!   quorum-merge** for `revocation` / `partner_record` / `org_membership`.
//!   The witness is a divergence DETECTOR that TRIGGERS the merge — it
//!   MUST NOT decide the merge, MUST NOT replace `monotonic_quorum` /
//!   `revision` anti-rollback, and there is NO "reconstitute from any
//!   fragment" path. A `WitnessReconcileAction::TriggerQuorumMerge` is a
//!   directive the caller fulfils by re-running the merge resolver over
//!   the stored rows; the witness root never enters that resolution.
//! - [`WitnessComparison::Consistent`] → no action.
//!
//! plus the **anti-rollback eclipse guard** (N4):
//! [`accept_if_monotonic`] — a peer's witness may only be acted on as
//! newer if its `epoch_id` strictly advances the last accepted epoch for
//! that peer.

use ciris_verify_core::holonomic::{compare_witnesses, Equivocation, WitnessComparison};

use super::types::StoredWitness;
use crate::witness::WitnessAdmitError;

/// `hard_case:*` suffix persist emits on a non-repudiable witness
/// equivocation (N4). Open vocabulary; this is the named-here canonical
/// kind for the §19.1 equivocation case.
pub const WITNESS_EQUIVOCATION: &str = "witness_equivocation";

/// The action persist must take after comparing a verified witness set.
///
/// This is the **only** bridge from the witness layer to the trust-record
/// reconciliation surface, and it is deliberately a directive, not a
/// decision: `TriggerQuorumMerge` names the rollback-sensitive
/// subject_kinds whose EXISTING §10.1.6 merge must re-run; it carries no
/// merge winner and no witness root, so the witness can never decide the
/// merge or bypass `monotonic_quorum` / `revision`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessReconcileAction {
    /// All roots agreed — nothing to do.
    NoAction,
    /// One peer published conflicting roots for the same identity. The
    /// pair is RETAINED (non-repudiable) and surfaced as a `hard_case:*`;
    /// NEVER reconciled. Carries the equivocation proofs to emit.
    Equivocation(Vec<Equivocation>),
    /// Distinct peers reported different roots — a divergence signal.
    /// Re-run the EXISTING quorum-merge for the rollback-sensitive
    /// subject_kinds. The witness does NOT decide the merge.
    TriggerQuorumMerge,
}

/// The trust-record subject_kinds whose §10.1.6 quorum-merge a `Divergent`
/// witness verdict triggers (CIRISPersist#228 item 2). A divergence on
/// any of these must route through the EXISTING merge — never a
/// fragment-pick — because a "reconstitute from any fragment" path on a
/// `revocation` resurrects a revoked key (the worst-case bug).
pub const QUORUM_MERGE_SUBJECT_KINDS: &[&str] = &["revocation", "partner_record", "org_membership"];

/// Classify a set of **already-verified** witnesses into the action
/// persist must take. PRECONDITION: every input passed
/// [`admit_witness`](super::admit::admit_witness) — this is NOT the
/// verification path (verify-core's `compare_witnesses` trusts the
/// signatures were checked at the gate).
#[must_use]
pub fn classify(
    verified: &[ciris_verify_core::holonomic::WholenessWitness],
) -> WitnessReconcileAction {
    match compare_witnesses(verified) {
        WitnessComparison::Consistent => WitnessReconcileAction::NoAction,
        WitnessComparison::Divergent => WitnessReconcileAction::TriggerQuorumMerge,
        WitnessComparison::Equivocation(proofs) => WitnessReconcileAction::Equivocation(proofs),
    }
}

/// Classify a set of [`StoredWitness`] corpus rows. Decodes each row back
/// to the verify-core shape and runs [`classify`]. A malformed stored
/// root is a substrate-corruption error, not a verdict.
pub fn classify_stored(
    verified: &[StoredWitness],
) -> Result<WitnessReconcileAction, WitnessAdmitError> {
    let mut shaped = Vec::with_capacity(verified.len());
    for w in verified {
        shaped.push(w.as_verify_witness()?);
    }
    Ok(classify(&shaped))
}

/// N4 anti-rollback / eclipse guard: a peer's witness may be acted on as
/// newer ONLY if its `epoch_id` strictly advances `last_accepted_epoch`
/// for that peer. A stale or replayed epoch (`<= last_accepted_epoch`) is
/// rejected — an eclipsing adversary cannot replay an old signed witness
/// to roll a peer's state back.
///
/// `last_accepted_epoch` is `None` when persist has never accepted a
/// witness from the peer (the first witness always advances).
#[must_use]
pub fn accept_if_monotonic(last_accepted_epoch: Option<u64>, candidate_epoch: u64) -> bool {
    match last_accepted_epoch {
        None => true,
        Some(prev) => candidate_epoch > prev,
    }
}

/// Build the `hard_case:witness_equivocation` event for one equivocation
/// proof (CIRISPersist#146 emitter). `target_key_id` = the equivocating
/// peer; `detail` carries the epoch, namespace set, and the two conflicting
/// roots (hex) so the case is a self-contained non-repudiable record.
/// `emitted_at` is the observation instant (caller passes `now`).
#[must_use]
pub fn equivocation_hard_case(
    proof: &Equivocation,
    emitted_at: chrono::DateTime<chrono::Utc>,
) -> crate::federation::HardCaseEvent {
    let root_a = super::types::encode_root_hex(&proof.roots.0);
    let root_b = super::types::encode_root_hex(&proof.roots.1);
    crate::federation::HardCaseEvent {
        // Deterministic id keyed on (peer, epoch, both roots) so a re-scan
        // of the same equivocation is idempotent (no duplicate row).
        event_id: format!(
            "{WITNESS_EQUIVOCATION}:{}:{}:{}:{}",
            proof.peer_id, proof.epoch_id, root_a, root_b
        ),
        kind: WITNESS_EQUIVOCATION.to_owned(),
        target_key_id: Some(proof.peer_id.clone()),
        subject_key_id: None,
        detail: serde_json::json!({
            "peer_id": proof.peer_id,
            "epoch_id": proof.epoch_id,
            "claim_namespaces": proof.claim_namespaces,
            "root_a": root_a,
            "root_b": root_b,
        }),
        emitted_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::holonomic::{compute_merkle_root, WholenessWitness};

    fn ww(peer: &str, epoch: u64, ns: &[&str], leaf: &[u8]) -> WholenessWitness {
        WholenessWitness {
            peer_id: peer.into(),
            epoch_id: epoch,
            claim_namespaces: ns.iter().map(|s| s.to_string()).collect(),
            merkle_root: compute_merkle_root(&[leaf.to_vec()]),
            leaf_count: 1,
            observed_at_unix_ms: 0,
            witness_version: 1,
        }
    }

    #[test]
    fn consistent_is_no_action() {
        let set = vec![
            ww("a", 1, &["scores:medical"], b"x"),
            ww("b", 1, &["scores:medical"], b"x"),
        ];
        assert_eq!(classify(&set), WitnessReconcileAction::NoAction);
    }

    #[test]
    fn divergent_triggers_quorum_merge_only() {
        let set = vec![
            ww("a", 1, &["scores:medical"], b"x"),
            ww("b", 1, &["scores:medical"], b"y"),
        ];
        // The action is a TRIGGER, never a winner — the witness does not
        // decide the merge.
        assert_eq!(classify(&set), WitnessReconcileAction::TriggerQuorumMerge);
    }

    #[test]
    fn equivocation_is_retained_and_surfaced_not_reconciled() {
        let set = vec![
            ww("a", 7, &["a:ns", "b:ns"], b"x"),
            ww("a", 7, &["b:ns", "a:ns"], b"y"),
        ];
        match classify(&set) {
            WitnessReconcileAction::Equivocation(proofs) => {
                assert_eq!(proofs.len(), 1);
                assert_eq!(proofs[0].peer_id, "a");
            }
            other => panic!("expected equivocation, got {other:?}"),
        }
    }

    #[test]
    fn anti_rollback_rejects_stale_or_replayed_epoch() {
        assert!(
            accept_if_monotonic(None, 0),
            "first witness always accepted"
        );
        assert!(accept_if_monotonic(Some(5), 6), "advancing epoch accepted");
        assert!(!accept_if_monotonic(Some(5), 5), "replay rejected");
        assert!(!accept_if_monotonic(Some(5), 4), "rollback rejected");
    }

    #[test]
    fn equivocation_hard_case_is_deterministic() {
        let proof = Equivocation {
            peer_id: "a".into(),
            epoch_id: 7,
            claim_namespaces: vec!["a:ns".into()],
            roots: ([1u8; 32], [2u8; 32]),
        };
        let now = chrono::Utc::now();
        let e1 = equivocation_hard_case(&proof, now);
        let e2 = equivocation_hard_case(&proof, now);
        assert_eq!(e1.event_id, e2.event_id);
        assert_eq!(e1.kind, WITNESS_EQUIVOCATION);
        assert_eq!(e1.target_key_id.as_deref(), Some("a"));
    }
}
