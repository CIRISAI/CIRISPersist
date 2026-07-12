//! v12.7.0 (CIRISPersist#365, CC 3.4.7.2 `consent-counter`) — the
//! **Counter-RII `consent_role`** resolver.
//!
//! `federation_keys.consent_role` is the role token (see the
//! [`consent_role`](super::types::consent_role) vocabulary — `temporary`
//! / `partnered` / `anonymous` / `authorized_review` / `peer`, with
//! `unregistered` as the stored no-role default) that gates Counter-RII
//! probe detection (RATCHET `FSD/COUNTER_RII_DETECTION.md`; Lean
//! `ConsentGate.lean`). Per CC 3.4.7.2 it is a **`federation_keys`
//! identity field** — a sibling to `identity_type`, NOT an envelope
//! primitive — and the clause states implementations MAY now build the
//! substrate (no longer a reserved slot). The COLUMN itself already
//! shipped in V020 (v1.3.0, the CIRISAgent#760 §RC "consent role lock"
//! that CC 3.4.7.2 ratifies — `TEXT NOT NULL DEFAULT 'unregistered'`);
//! v12.7.0 puts it on the wire ([`KeyRecord::consent_role`](super::KeyRecord),
//! `None` ⇔ the stored `'unregistered'`) and exposes this resolver.
//!
//! **What persist owns (and does NOT own).** The three ratified
//! semantics split by responsibility:
//!
//! - **OQ-1 (non-recursive revocation — SUBSTRATE):** a subsequent
//!   revocation OVERWRITES the prior value; the field is flat, bounded,
//!   and carries NO embedded chain. Persist implements this as the
//!   natural UPDATE/overwrite of the single mutable V020 column via
//!   [`super::FederationDirectory::set_consent_role`] (revoke = set
//!   `None` = reset to `'unregistered'`). The field is excluded from
//!   `compute_persist_row_hash` so the overwrite never disturbs the
//!   signed-registration hash.
//! - **OQ-2 (`peer` blanket suppression — CONSUMER):** a `peer`
//!   `consent_role` escapes Counter-RII detection at any `trust_mode`.
//!   Persist STORES + EXPOSES the role; edge's `ProbePatternObserver`
//!   reads it (via [`consent_role_of`]) and suppresses the
//!   advisory-only `ratchet:flag:counter_rii:*` signal. Persist houses
//!   no detector, so it applies no suppression itself.
//! - **OQ-3 (`authorized_review` strict post-window — CONSUMER):** an
//!   `authorized_review` role is signal-eligible immediately at
//!   `t > window_end`. Same split — persist carries the role; the
//!   consumer enforces the window.
//!
//! So this module is the STORE + EXPOSE + OQ-1 half; OQ-2 / OQ-3 are
//! consumer-applied signals on the field persist now carries.

use super::{Error, FederationDirectory};

/// v12.7.0 (CIRISPersist#365, CC 3.4.7.2) — resolve the Counter-RII
/// `consent_role` of `key_id`.
///
/// Returns `Ok(Some(role))` when the key exists and carries an assigned
/// role; `Ok(None)` when the key exists with no assigned role (the
/// stored `'unregistered'` default — including after an OQ-1
/// revoke-overwrite) **or** when `key_id` is absent. The resolver is
/// deliberately total: an absent key and a role-less key are both "no
/// assigned Counter-RII role", which a consumer treats identically
/// (detection applies normally, no suppression). The returned token is
/// one of the assigned [`consent_role`](super::types::consent_role)
/// tokens; the consumer interprets it — persist does not gate on the
/// value here.
pub async fn consent_role_of(
    dir: &dyn FederationDirectory,
    key_id: &str,
) -> Result<Option<String>, Error> {
    Ok(dir
        .lookup_public_key(key_id)
        .await?
        .and_then(|record| record.consent_role))
}

/// v16.1.0 (CIRISPersist#389) — the envelope's `dimension` string (the same
/// axis admission keys on), read straight off the stored
/// `attestation_envelope`. Shared by the consent folds
/// ([`resolve_consent_state`](super::FederationDirectory::resolve_consent_state)
/// / [`resolve_scoped_consent`](super::FederationDirectory::resolve_scoped_consent)).
pub fn envelope_dimension(a: &super::Attestation) -> Option<&str> {
    a.attestation_envelope
        .get("dimension")
        .and_then(|v| v.as_str())
}

/// v16.1.0 (CIRISPersist#389) — THE `consent:state:*` dimension → stance
/// classifier, the single mapping both consent folds share (so the closed-set
/// rule cannot drift). A `consent:state:*` value outside the closed set — or
/// no candidate at all — is `Unspecified` (forward-compat: an unknown stance
/// value never silently reads as granted).
pub fn consent_state_of(dimension: Option<&str>) -> super::hard_case::ConsentState {
    use super::hard_case::ConsentState;
    match dimension {
        Some(d) if d.starts_with("consent:state:granted") => ConsentState::Granted,
        Some(d) if d.starts_with("consent:state:revoked") => ConsentState::Revoked,
        Some(d) if d.starts_with("consent:state:expired") => ConsentState::Expired,
        _ => ConsentState::Unspecified,
    }
}

/// v16.1.0 (CIRISPersist#389) — does the attestation's envelope name `scope`?
/// Accepts BOTH envelope shapes: a bare string (`"scope": "view"`) and an
/// array set (`"scope": ["view", …]`) — the same duality
/// `delegation_scope_set` reads. A scope-less envelope names nothing
/// (fail-closed for scoped queries).
pub fn envelope_names_scope(a: &super::Attestation, scope: &str) -> bool {
    match a.attestation_envelope.get("scope") {
        Some(serde_json::Value::String(s)) => s == scope,
        Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(scope)),
        _ => false,
    }
}
