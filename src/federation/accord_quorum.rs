//! #302 (FSD-004) — accord live-quorum storage substrate.
//!
//! The durable half of the constitutional kill-switch's decimation-recovery
//! live quorum. CIRISVerify ships the **stateless** machinery in
//! [`ciris_verify_core::accord_live_quorum`] (CIRISVerify#150 / #98); the
//! CIRISServer Phase-3 runtime (CIRISServer#122) drives it and writes the
//! wire objects + anti-replay state **through** persist. Persist is the
//! storage substrate, so the tables are ours (V091) — the live-quorum
//! sibling of the `federation_keys` accord-holder storage.
//!
//! Division of labour (from #302): **persist stores + dedups + verifies
//! participations + holds nonce/halt state; the SERVER runs the tally**
//! (`verify_fire_by_live_quorum` etc. re-verify every participation at tally
//! time — persist stores the inputs + the server's frozen `AccordDecision`).
//!
//! Load-bearing rule: store the verify-core canonical objects **verbatim**
//! and DERIVE the indexed columns from them via verify-core
//! ([`AccordProposal::digest`] etc.) — never trust a caller-supplied digest,
//! never re-derive the bytes by hand.
//!
//! **Recovery (`verify_recovery_supersede`, H7) is deliberately absent** —
//! it bends entrenchment for the captured-roster case and cannot go live
//! until the CIRIS Constitution sanctions it (CIRISAccord#4). This module
//! handles `fire` / `roster_change` / `resume` only.

use chrono::{DateTime, Utc};
use ciris_verify_core::accord_live_quorum::{AccordDecision, AccordParticipation, AccordProposal};
use ciris_verify_core::threshold::ThresholdMember;

use super::types::compute_persist_row_hash;
use super::Error;

/// Parse an RFC-3339 timestamp (the verify-core wire form) into a UTC
/// instant for the indexed timestamp columns. Fail-closed on a malformed
/// `window_until` / `signed_at` — a row with an unparseable window can't be
/// filtered by the C2 server-arrival gate.
fn parse_rfc3339(field: &str, value: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            Error::InvalidArgument(format!("accord {field} not RFC-3339 ({value:?}): {e}"))
        })
}

// ─────────────────────────────────────────────────────────────────────
// Prepared write columns — derived from the verify-core objects, ready for
// the backends to INSERT. Backends do the SQL; this module owns the
// derivation + verification so all three stay byte-identical.
// ─────────────────────────────────────────────────────────────────────

/// The indexed + verbatim columns for an `accord_proposal` INSERT, derived
/// from a verify-core [`AccordProposal`].
pub(crate) struct PreparedProposal {
    pub proposal_digest: String,
    pub family_key_id: String,
    pub action: String,
    pub nonce: String,
    pub window_until: DateTime<Utc>,
    pub prior_family_digest: String,
    pub payload_sha256: String,
    pub proposal_json: serde_json::Value,
    pub authority_signature: Option<serde_json::Value>,
    pub persist_row_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Derive the `accord_proposal` columns from the verify-core object. The
/// digest is `AccordProposal::digest()` (never caller-supplied); the action
/// is the canonical token. Stores the object verbatim.
pub(crate) fn prepare_proposal(
    proposal: &AccordProposal,
    authority_signature: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
) -> Result<PreparedProposal, Error> {
    let window_until = parse_rfc3339("proposal.window_until", &proposal.window_until)?;
    let proposal_json = serde_json::to_value(proposal)
        .map_err(|e| Error::Backend(format!("serialize accord proposal: {e}")))?;
    Ok(PreparedProposal {
        proposal_digest: proposal.digest(),
        family_key_id: proposal.family_key_id.clone(),
        action: proposal.action.as_str().to_owned(),
        nonce: proposal.nonce.clone(),
        window_until,
        prior_family_digest: proposal.prior_family_digest.clone(),
        payload_sha256: proposal.payload_sha256.clone(),
        persist_row_hash: compute_persist_row_hash(proposal)?,
        proposal_json,
        authority_signature,
        created_at,
    })
}

/// The columns for an `accord_participation` INSERT, after a fail-closed
/// verify-core verification.
pub(crate) struct PreparedParticipation {
    pub proposal_digest: String,
    pub member_id: String,
    /// The M6 dedup key — the member's PINNED Ed25519 pubkey (base64), NOT
    /// the self-attested `member_id` string.
    pub pinned_pubkey: String,
    pub vote: String,
    pub window_until: DateTime<Utc>,
    pub signed_at: DateTime<Utc>,
    pub server_arrival_at: DateTime<Utc>,
    pub participation_json: serde_json::Value,
    pub persist_row_hash: String,
}

/// Verify a participation against the stored proposal + the caller-supplied
/// standing roster, then derive its INSERT columns. Fail-closed:
///
/// 1. The participation's `member_id` MUST resolve to a member of the
///    standing roster (C3 — L ⊆ standing roster; the live set only narrows
///    which standing signers count).
/// 2. [`AccordParticipation::verify`] (verify-core) MUST pass — it binds the
///    proposal digest, family, member seat, vote + window inside the hybrid
///    signature (C1/M3/M5). Persist verifies BEFORE the row lands.
///
/// The M6 dedup key is the member's PINNED Ed25519 pubkey (so a relay can't
/// double-count a holder by varying the `member_id` string). C2: the caller
/// passes `server_arrival_at` (the authoritative arrival instant) — never
/// the advisory `signed_at`.
pub(crate) fn verify_and_prepare_participation(
    proposal: &AccordProposal,
    participation: &AccordParticipation,
    standing_roster: &[ThresholdMember],
    server_arrival_at: DateTime<Utc>,
) -> Result<PreparedParticipation, Error> {
    // (1) member ∈ standing roster (C3).
    let member = standing_roster
        .iter()
        .find(|m| m.member_id == participation.member_id)
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "accord participation: member {:?} is not in the standing roster (C3)",
                participation.member_id
            ))
        })?;
    // (2) verify-core fail-closed verify (sig + proposal-digest + family +
    //     seat consistency). Binds participation to THIS proposal.
    participation.verify(member, proposal).map_err(|e| {
        Error::InvalidArgument(format!(
            "accord participation verify failed (fail-closed): {e}"
        ))
    })?;

    let window_until = parse_rfc3339("participation.window_until", &participation.window_until)?;
    let signed_at = parse_rfc3339("participation.signed_at", &participation.signed_at)?;
    let participation_json = serde_json::to_value(participation)
        .map_err(|e| Error::Backend(format!("serialize accord participation: {e}")))?;
    Ok(PreparedParticipation {
        proposal_digest: participation.proposal_digest.clone(),
        member_id: participation.member_id.clone(),
        pinned_pubkey: member.ed25519_public_key_base64.clone(),
        vote: participation.vote.as_str().to_owned(),
        window_until,
        signed_at,
        server_arrival_at,
        participation_json,
        persist_row_hash: compute_persist_row_hash(participation)?,
    })
}

/// The columns for an `accord_decision` INSERT (the frozen-L snapshot, M2).
pub(crate) struct PreparedDecision {
    pub proposal_digest: String,
    pub family_key_id: String,
    pub authorized: bool,
    pub yes: i64,
    pub no: i64,
    pub abstain: i64,
    pub live_set: serde_json::Value,
    pub window_until: DateTime<Utc>,
    pub steward_signatures: Option<serde_json::Value>,
    pub decision_json: serde_json::Value,
    pub persist_row_hash: String,
    pub decided_at: DateTime<Utc>,
}

/// Derive the `accord_decision` columns from the verify-core
/// [`AccordDecision`]. The decision is IMMUTABLE once written (M2): backends
/// reject a differing re-PUT and no-op an identical one (keyed on the
/// `persist_row_hash`). `steward_signatures` carries the |L|<L_FLOOR backstop
/// sigs (H6) when present.
pub(crate) fn prepare_decision(
    decision: &AccordDecision,
    steward_signatures: Option<serde_json::Value>,
    decided_at: DateTime<Utc>,
) -> Result<PreparedDecision, Error> {
    let window_until = parse_rfc3339(
        "decision.proposal.window_until",
        &decision.proposal.window_until,
    )?;
    let live_set = serde_json::to_value(&decision.live_set)
        .map_err(|e| Error::Backend(format!("serialize accord live_set: {e}")))?;
    let decision_json = serde_json::to_value(decision)
        .map_err(|e| Error::Backend(format!("serialize accord decision: {e}")))?;
    Ok(PreparedDecision {
        proposal_digest: decision.proposal.digest(),
        family_key_id: decision.proposal.family_key_id.clone(),
        authorized: decision.authorized,
        yes: decision.yes as i64,
        no: decision.no as i64,
        abstain: decision.abstain as i64,
        live_set,
        window_until,
        steward_signatures,
        persist_row_hash: compute_persist_row_hash(decision)?,
        decision_json,
        decided_at,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Read row types — what list/get return. The verbatim `*_json` round-trips
// back to the verify-core object for the server's tally.
// ─────────────────────────────────────────────────────────────────────

/// A stored `accord_proposal`: the verbatim verify-core object + the
/// server-supplied authority signature envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredProposal {
    /// The verbatim verify-core proposal (round-trips for the server tally).
    pub proposal: AccordProposal,
    /// The server-supplied authority-signature envelope, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_signature: Option<serde_json::Value>,
    /// Substrate row hash (canonical SHA-256 of the stored proposal).
    pub persist_row_hash: String,
    /// When persist admitted the proposal.
    pub created_at: DateTime<Utc>,
}

/// A stored `accord_participation`: the verbatim verify-core object + the
/// authoritative server-arrival instant (C2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredParticipation {
    /// The verbatim verify-core participation (incl. the hybrid signature).
    pub participation: AccordParticipation,
    /// The member's PINNED Ed25519 pubkey — the M6 dedup key.
    pub pinned_pubkey: String,
    /// The AUTHORITATIVE arrival instant persist stamped (C2 window clock);
    /// `participation.signed_at` is advisory only.
    pub server_arrival_at: DateTime<Utc>,
    /// Substrate row hash (canonical SHA-256 of the stored participation).
    pub persist_row_hash: String,
}

/// A stored `accord_decision`: the verbatim frozen-L snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredDecision {
    /// The verbatim verify-core frozen-L decision snapshot (M2, immutable).
    pub decision: AccordDecision,
    /// The |L|<L_FLOOR steward-backstop signatures (H6), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steward_signatures: Option<serde_json::Value>,
    /// Substrate row hash (canonical SHA-256 of the stored decision).
    pub persist_row_hash: String,
    /// When persist admitted the decision.
    pub decided_at: DateTime<Utc>,
}

/// The active CONSTITUTIONAL halt for a family (H2). `None` when no halt is
/// active (a resume cleared it).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveHalt {
    /// The accord family the halt applies to.
    pub family_key_id: String,
    /// The active CONSTITUTIONAL halt id (a resume binds `sha256(this)`).
    pub active_halt_id: String,
    /// When the halt became active.
    pub set_at: DateTime<Utc>,
}

/// #302 — shared test fixtures for the backend parity tests (build a proposal
/// + a validly-signed participation that passes verify-core's verify).
#[cfg(test)]
pub(crate) mod test_fixtures {
    use super::*;
    use crate::federation::operational::test_support::Identity;
    use ciris_verify_core::accord_live_quorum::{AccordAction, Vote};
    use ciris_verify_core::threshold::ThresholdSignature;

    /// A `fire` proposal over `family` with `nonce` (far-future window).
    pub fn proposal(family: &str, nonce: &str) -> AccordProposal {
        AccordProposal {
            family_key_id: family.to_owned(),
            action: AccordAction::Fire,
            nonce: nonce.to_owned(),
            window_until: "2031-01-01T00:00:00Z".to_owned(),
            prior_family_digest: "prior-family-digest-abc".to_owned(),
            payload_sha256: "payload-sha256-def".to_owned(),
        }
    }

    /// A participation by `id` on `proposal` with `vote`, hybrid-signed so
    /// [`AccordParticipation::verify`] passes against `id.member()`.
    pub fn signed_participation(
        id: &Identity,
        proposal: &AccordProposal,
        vote: Vote,
    ) -> AccordParticipation {
        let mut p = AccordParticipation {
            family_key_id: proposal.family_key_id.clone(),
            proposal_digest: proposal.digest(),
            member_id: id.key_id.clone(),
            vote,
            window_until: proposal.window_until.clone(),
            signed_at: "2025-06-01T00:00:00Z".to_owned(),
            signature: ThresholdSignature {
                member_id: id.key_id.clone(),
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        // canonical_bytes excludes the signature, so sign over it then set.
        p.signature = id.threshold_sig(&p.canonical_bytes());
        p
    }

    /// #302 — the full accord live-quorum storage flow, run against ANY
    /// backend so the three impls assert identical behaviour from ONE source
    /// (no pg/sqlite/memory asymmetry): M4 nonce fail-closed,
    /// verify-before-mutation (C3 roster + verify-core verify), M6 dedup by
    /// pinned pubkey, decision immutability (M2), active-halt clear-on-resume
    /// (H2).
    pub async fn exercise_accord_storage<B>(backend: &B, suffix: &str)
    where
        B: crate::federation::FederationDirectory + ?Sized,
    {
        use crate::federation::Error;
        use ciris_verify_core::accord_live_quorum::{AccordDecision, LiveQuorumTally};

        // Scope family + nonce by `suffix` so the pg parity test (shared DB)
        // doesn't collide across runs; the standing-roster anchor below is
        // this proposal's own `prior_family_digest`.
        let family = format!("fam-{suffix}");
        let nonce = format!("nonce-{suffix}");
        let alice = Identity::new("alice");
        let bob = Identity::new("bob");
        let roster = vec![alice.member(), bob.member()];
        let prop = proposal(&family, &nonce);
        let anchor = prop.prior_family_digest.clone();
        let digest = prop.digest();

        // M4 fail-closed: proposal before its nonce is issued → rejected.
        let err = backend
            .put_accord_proposal(prop.clone(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "M4: {err:?}");
        // Issue the nonce → admitted (+ idempotent re-PUT).
        backend.issue_accord_nonce(&family, &nonce).await.unwrap();
        backend
            .put_accord_proposal(prop.clone(), None)
            .await
            .unwrap();
        backend
            .put_accord_proposal(prop.clone(), None)
            .await
            .unwrap();
        assert!(backend
            .get_accord_proposal(&digest)
            .await
            .unwrap()
            .is_some());
        // Anchor index returns exactly this proposal (digest match below
        // guards against cross-run rows sharing the fixed anchor).
        assert!(backend
            .list_accord_proposals_by_anchor("fire", &anchor)
            .await
            .unwrap()
            .iter()
            .any(|p| p.proposal.digest() == digest));

        // Participation referencing an unknown proposal → rejected.
        let unknown = proposal(&family, &format!("{nonce}-other"));
        assert!(backend
            .put_accord_participation(signed_participation(&alice, &unknown, Vote::Yes), &roster)
            .await
            .is_err());

        // Valid participation; re-PUT idempotent (one row).
        let pa_yes = signed_participation(&alice, &prop, Vote::Yes);
        backend
            .put_accord_participation(pa_yes.clone(), &roster)
            .await
            .unwrap();
        backend
            .put_accord_participation(pa_yes, &roster)
            .await
            .unwrap();
        let parts = backend.list_accord_participations(&digest).await.unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].pinned_pubkey,
            alice.member().ed25519_public_key_base64
        );

        // M6: alice voting DIFFERENTLY on the same proposal → Conflict.
        let err = backend
            .put_accord_participation(signed_participation(&alice, &prop, Vote::No), &roster)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Conflict(_)), "M6: {err:?}");

        // Member outside the standing roster → rejected (C3).
        let carol = Identity::new("carol");
        assert!(backend
            .put_accord_participation(signed_participation(&carol, &prop, Vote::Yes), &roster)
            .await
            .is_err());

        // Decision immutability (M2).
        let tally = LiveQuorumTally {
            live_set: vec!["alice".to_owned()],
            yes: 1,
            no: 0,
            abstain: 0,
        };
        backend
            .put_accord_decision(AccordDecision::new(prop.clone(), &tally, true), None)
            .await
            .unwrap();
        backend
            .put_accord_decision(AccordDecision::new(prop.clone(), &tally, true), None)
            .await
            .unwrap(); // idempotent
        let err = backend
            .put_accord_decision(AccordDecision::new(prop.clone(), &tally, false), None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Conflict(_)), "M2: {err:?}");
        assert!(
            backend
                .get_accord_decision(&digest)
                .await
                .unwrap()
                .unwrap()
                .decision
                .authorized
        );

        // Active halt (H2): set; wrong-id resume no-ops; right-id clears.
        backend.set_active_halt(&family, "halt-X").await.unwrap();
        assert_eq!(
            backend
                .get_active_halt(&family)
                .await
                .unwrap()
                .unwrap()
                .active_halt_id,
            "halt-X"
        );
        backend
            .clear_active_halt(&family, "halt-WRONG")
            .await
            .unwrap();
        assert!(backend.get_active_halt(&family).await.unwrap().is_some());
        backend.clear_active_halt(&family, "halt-X").await.unwrap();
        assert!(backend.get_active_halt(&family).await.unwrap().is_none());
    }
}
