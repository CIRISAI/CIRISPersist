//! N5/N6 retention-decision wiring (CEG 1.0-RC11 §19.3; CIRISPersist#228
//! items 4–5 / #229 item 2).
//!
//! persist treats `retention_priority` as opaque (#227). The N5 gate
//! (revocation overrides rarity) and the N6 gate (an unverified holding
//! claim must not count toward rarity) are persist's job on top of that
//! opaque ordering. Both are decided by the FROZEN verify-core verdict
//! functions — persist does not re-roll the policy:
//!
//! - [`ciris_verify_core::holonomic::retention_decision`] →
//!   [`RetentionAction`]: a withdrawn/revoked `content_id` is
//!   `EvictEligible` regardless of rarity (the §8.1.11.3 deletion-SLA
//!   always wins), routed to the v8.1.0
//!   [`evict_fountain_content_hard_delete`](crate::store::Backend::evict_fountain_content_hard_delete)
//!   path.
//! - [`ciris_verify_core::holonomic::holding_claim_counts_toward_rarity`]
//!   (N6) — an unverified/unchallenged claim MUST NOT lower another
//!   peer's retention priority.

use ciris_verify_core::holonomic::{
    holding_claim_counts_toward_rarity, retention_decision, ConsentState as VerifyConsentState,
    RetentionDecision,
};

use crate::federation::hard_case::ConsentState as PersistConsentState;

/// What the retention decision asks persist to DO with a content unit's
/// fountain symbols. The translation of the verify-core
/// [`RetentionDecision`] into a persist eviction routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionAction {
    /// Revoked/withdrawn → route to the v8.1.0 hard-delete path (drop ALL
    /// symbols regardless of `retention_priority`; revocation overrides
    /// rarity). Maps from [`RetentionDecision::EvictEligible`].
    HardDelete,
    /// May be retained, rarity-bias may keep it alive. The symbols stay
    /// under the opaque `retention_priority` tier ordering.
    /// [`RetentionDecision::RetainRare`].
    RetainRare,
    /// May be retained but MUST NOT be kept solely by rarity (LRU/tier
    /// eligible). [`RetentionDecision::RetainNonRare`].
    RetainNonRare,
}

impl RetentionAction {
    /// True iff this action means "drop everything now" — the caller MUST
    /// route to `evict_fountain_content_hard_delete`, NOT the tiered path.
    #[must_use]
    pub fn is_hard_delete(self) -> bool {
        matches!(self, RetentionAction::HardDelete)
    }
}

/// Map persist's resolved [`ConsentState`](PersistConsentState) (§8.1.11.1
/// resolution over the stored `consent:state:*` / `withdraws` records)
/// onto the verify-core [`ConsentState`](VerifyConsentState) the
/// retention verdict keys on. `Revoked` → `Withdrawn` (the dominating
/// deletion signal); `Granted` → `Active`; `Expired`/`Unspecified` →
/// `Unknown` (fail-secure: never earns rare-retention).
#[must_use]
pub fn map_consent_state(state: PersistConsentState) -> VerifyConsentState {
    match state {
        PersistConsentState::Granted => VerifyConsentState::Active,
        PersistConsentState::Revoked => VerifyConsentState::Withdrawn,
        PersistConsentState::Expired | PersistConsentState::Unspecified => {
            VerifyConsentState::Unknown
        }
    }
}

/// N5: decide the retention action for a content unit from its resolved
/// consent state and rarity. Calls the FROZEN verify-core
/// [`retention_decision`] — `Withdrawn → EvictEligible` ALWAYS, so a high
/// rarity score can never override the deletion-SLA. `is_rare` is the
/// edge's opaque rarity signal; persist passes it through and does NOT
/// interpret it beyond this verdict.
#[must_use]
pub fn resolve_retention_action(consent: PersistConsentState, is_rare: bool) -> RetentionAction {
    match retention_decision(map_consent_state(consent), is_rare) {
        RetentionDecision::EvictEligible => RetentionAction::HardDelete,
        RetentionDecision::RetainRare => RetentionAction::RetainRare,
        RetentionDecision::RetainNonRare => RetentionAction::RetainNonRare,
    }
}

/// N6: may an inbound `FountainHoldingClaim` count toward another peer's
/// rarity calculation? Only if its possession is PROVEN (it answered a
/// symbol challenge / carries a proof-of-possession). An unverified claim
/// MUST NOT lower retention priority — else rarity is a forgeable
/// force-evict channel. Thin pass-through to the frozen verify-core gate
/// so persist's rarity-input filter is byte-identical to the spec.
#[must_use]
pub fn holding_claim_counts(possession_proven: bool) -> bool {
    holding_claim_counts_toward_rarity(possession_proven)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_is_hard_delete_regardless_of_rarity() {
        // N5: a revoked content is HardDelete even when marked rare.
        assert_eq!(
            resolve_retention_action(PersistConsentState::Revoked, true),
            RetentionAction::HardDelete
        );
        assert_eq!(
            resolve_retention_action(PersistConsentState::Revoked, false),
            RetentionAction::HardDelete
        );
        assert!(resolve_retention_action(PersistConsentState::Revoked, true).is_hard_delete());
    }

    #[test]
    fn granted_rare_is_retain_rare() {
        assert_eq!(
            resolve_retention_action(PersistConsentState::Granted, true),
            RetentionAction::RetainRare
        );
        assert_eq!(
            resolve_retention_action(PersistConsentState::Granted, false),
            RetentionAction::RetainNonRare
        );
    }

    #[test]
    fn unknown_never_earns_rare_retention() {
        // Expired / Unspecified → Unknown → RetainNonRare even if "rare".
        assert_eq!(
            resolve_retention_action(PersistConsentState::Expired, true),
            RetentionAction::RetainNonRare
        );
        assert_eq!(
            resolve_retention_action(PersistConsentState::Unspecified, true),
            RetentionAction::RetainNonRare
        );
    }

    #[test]
    fn n6_unverified_holding_claim_does_not_count() {
        assert!(!holding_claim_counts(false));
        assert!(holding_claim_counts(true));
    }
}
