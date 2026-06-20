//! v6.5.0 (CIRISPersist#183, CEG §8.1.12.7) — the **"self at login"**
//! substrate vocabulary: the attestation-envelope builders + scope
//! tokens + the [`TransportDestination`] type the `Engine`-level login
//! flow ([`crate::Engine::self_at_login`]) composes.
//!
//! # The §8.1.12.7 model
//!
//! An app (`device_class: phone | laptop`) and an agent
//! (`device_class: agent`) are **two occurrences of ONE user identity**.
//! At login they are:
//!
//! 1. **Co-admitted** as two [`crate::federation::IdentityOccurrence`]
//!    rows under one `identity_key` (#153 `put_identity_occurrence`).
//! 2. **Self-DEK-cascaded** so both decrypt the user's
//!    `cohort_scope: self` content (§8.1.12.4 — composed over v6.2.0
//!    [`crate::federation::at_rest_cascade::orchestrate::rekey_self_occurrence_add`]).
//! 3. **Partnered** — a bilateral `consent:partnership_grant` +
//!    `consent:partnership_accept` pair sharing a `bilateral_pair_id`.
//! 4. **Delegated** — `delegates_to(user → agent occurrence)` with the
//!    §8.1.12.7 scope set
//!    `[act_on_behalf, message_io, network_presence, sub_delegation]`.
//! 5. **Promoted** to federation tier (§10.1.5 / #172
//!    [`crate::Engine::attestation_promote`]) so peers verify the
//!    agent's authority — the "show up on the network" emit.
//!
//! These builders produce the attestation **envelopes** (the
//! `attestation_envelope` JSON); the `Engine` flow wraps them in
//! [`crate::federation::types::LocalAttestationInput`] and drives the
//! local-write → promote path. Every envelope carries a `"dimension"`
//! (the local-tier upsert key + §7.5/§10.1.3 gate axis) per the
//! `LocalAttestationInput` contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── §8.1.12.7 delegation scope tokens ─────────────────────────────

/// "act on the user's behalf" — the agent occurrence may take action
/// attributable to the user.
pub const SCOPE_ACT_ON_BEHALF: &str = "act_on_behalf";
/// "send/receive messages as the user" — message I/O authority.
pub const SCOPE_MESSAGE_IO: &str = "message_io";
/// "be present on the network as the user" — the reachability /
/// presence authority that the [`TransportDestination`] rows realize.
pub const SCOPE_NETWORK_PRESENCE: &str = "network_presence";
/// "delegate onward" — the agent may itself issue bounded
/// sub-delegations (FSD-002 §2.2.1 transitive depth).
pub const SCOPE_SUB_DELEGATION: &str = "sub_delegation";

/// The full §8.1.12.7 user→agent delegation scope **set**, in canonical
/// (sorted) order. This is what [`delegates_to_agent_envelope`] stamps
/// when the caller does not narrow it.
pub const SELF_AT_LOGIN_DELEGATION_SCOPE: [&str; 4] = [
    SCOPE_ACT_ON_BEHALF,
    SCOPE_MESSAGE_IO,
    SCOPE_NETWORK_PRESENCE,
    SCOPE_SUB_DELEGATION,
];

// ─── dimension axes ────────────────────────────────────────────────

/// `dimension` for the `delegates_to` login delegation envelope. The
/// `:v1` version segment satisfies the §13.1 dimension-versioning gate
/// (`require_version_segment`); structural primitives are gate-exempt
/// but we version uniformly so a future consumer can gate on it.
pub const DIMENSION_DELEGATES_TO_AGENT: &str = "self:delegates_to:agent_occurrence:v1";
/// v9.3.0 (CIRISPersist#249) — `dimension` for the GENERAL `delegates_to`
/// envelope ([`delegates_to_envelope`]), the §11.10 grant/owner-bind/
/// add-moderator emit ceremonies' edge axis. `delegates_to` is a
/// structural primitive (gate-exempt from the §13.1 dimension gate — only
/// `scores` passes through [`crate::federation::admission::DimensionAdmissionPolicy`]),
/// so this is advisory/routing, not load-bearing; carried for uniformity
/// with [`DIMENSION_DELEGATES_TO_AGENT`].
pub const DIMENSION_DELEGATES_TO: &str = "self:delegates_to:v1";
/// `dimension` for the partnership-grant consent envelope. Carries the
/// `:v1` version segment the `scores` admission gate
/// (`require_version_segment`) requires.
pub const DIMENSION_PARTNERSHIP_GRANT: &str = "consent:partnership_grant:v1";
/// `dimension` for the partnership-accept consent envelope.
pub const DIMENSION_PARTNERSHIP_ACCEPT: &str = "consent:partnership_accept:v1";

// ─── envelope builders ─────────────────────────────────────────────

/// v6.5.0 (CEG §8.1.12.7) — the `delegates_to` envelope binding a user
/// identity to its agent occurrence with a bounded scope **set**.
///
/// The `scope` is emitted as a JSON array (a set) — the shape
/// [`crate::federation::admission`]'s rule-3/4 walk already accepts for
/// set-containment. Passing the default
/// [`SELF_AT_LOGIN_DELEGATION_SCOPE`] yields the four §8.1.12.7 tokens;
/// a caller MAY narrow it (e.g. an agent that should not sub-delegate).
///
/// Wire shape (sorted-keys when canonicalized):
///
/// ```json
/// {
///   "agent_occurrence_key_id": "<agent occurrence key>",
///   "bilateral_pair_id": "<shared pair id>",
///   "dimension": "self:delegates_to:agent_occurrence",
///   "kind": "delegates_to",
///   "scope": ["act_on_behalf", "message_io", "network_presence", "sub_delegation"]
/// }
/// ```
pub fn delegates_to_agent_envelope(
    agent_occurrence_key_id: &str,
    bilateral_pair_id: &str,
    scope: &[&str],
) -> serde_json::Value {
    serde_json::json!({
        "kind": "delegates_to",
        "dimension": DIMENSION_DELEGATES_TO_AGENT,
        "agent_occurrence_key_id": agent_occurrence_key_id,
        "bilateral_pair_id": bilateral_pair_id,
        "scope": scope,
    })
}

/// v9.3.0 (CIRISPersist#249, CEG §3.2.1 / §11.10) — the **general**
/// `delegates_to` envelope: "I authorize `delegate_key_id` within
/// `scopes`", with an explicit `sub_delegation` deputization flag. This is
/// the builder the §249 Cut C emit ceremonies
/// ([`crate::Engine::grant_delegation`] and its specializations
/// `owner_bind` / `add_moderator`) stamp; the login-specific
/// [`delegates_to_agent_envelope`] is the §8.1.12.7 specialization (it
/// additionally carries `agent_occurrence_key_id` + `bilateral_pair_id`).
///
/// The `scope` is emitted as a JSON array (a set) — the exact shape the
/// [`crate::federation::admission`] duty walk's
/// `delegation_scope_grants` / `delegation_scope_set` accept for
/// set-containment + §11.10 `⊆`-parent attenuation. `sub_delegation` is a
/// top-level bool the §11.10 deputization gate
/// ([`crate::federation::admission`]'s `delegation_grants_sub_delegation`)
/// reads — a delegate WITHOUT it is a leaf (may exercise the duty, may not
/// deputize onward). An edge built here is therefore directly admissible
/// by `is_named_moderator` / `is_owner_bound` / `check_moderation_admission`.
///
/// Wire shape (sorted-keys when canonicalized):
///
/// ```json
/// {
///   "delegate_key_id": "<delegate key>",
///   "dimension": "self:delegates_to:v1",
///   "kind": "delegates_to",
///   "scope": ["moderate"],
///   "sub_delegation": false
/// }
/// ```
pub fn delegates_to_envelope(
    delegate_key_id: &str,
    scopes: &[String],
    sub_delegation: bool,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "delegates_to",
        "dimension": DIMENSION_DELEGATES_TO,
        "delegate_key_id": delegate_key_id,
        "scope": scopes,
        "sub_delegation": sub_delegation,
    })
}

/// v6.5.0 (CEG §8.1.12.7) — the user-side `consent:partnership_grant`
/// envelope: "I (user) offer a bilateral partnership to this agent
/// occurrence", keyed by a shared `bilateral_pair_id`.
pub fn partnership_grant_envelope(
    partner_occurrence_key_id: &str,
    bilateral_pair_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "partnership_grant",
        "dimension": DIMENSION_PARTNERSHIP_GRANT,
        "partner_occurrence_key_id": partner_occurrence_key_id,
        "bilateral_pair_id": bilateral_pair_id,
    })
}

/// v6.5.0 (CEG §8.1.12.7) — the agent-side `consent:partnership_accept`
/// envelope: "I (agent occurrence) accept the partnership offered under
/// this `bilateral_pair_id`". The matching half of
/// [`partnership_grant_envelope`].
pub fn partnership_accept_envelope(
    partner_occurrence_key_id: &str,
    bilateral_pair_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "partnership_accept",
        "dimension": DIMENSION_PARTNERSHIP_ACCEPT,
        "partner_occurrence_key_id": partner_occurrence_key_id,
        "bilateral_pair_id": bilateral_pair_id,
    })
}

// ─── transport_destination (§5.6.8.8.1) ────────────────────────────

/// v6.5.0 (CIRISPersist#183, CEG §5.6.8.8.1) — one reachable network
/// address for one identity_occurrence (the "show up on the network"
/// reachability row). Backed by the V078 `transport_destinations`
/// table.
///
/// Reachability is mutable + disposable: a stale address is dropped and
/// re-registered, not signed or revoked — so (unlike the V069
/// occurrence binding) this row carries no signature / `persist_row_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDestination {
    /// The occurrence this address reaches — a
    /// `federation_keys.key_id` (the occurrence key bound via
    /// `put_identity_occurrence`).
    pub occurrence_key_id: String,
    /// Open vocab: `"reticulum"` / `"websocket"` / `"https"` /
    /// operator-defined.
    pub transport_kind: String,
    /// The reachable address (a Reticulum destination hash, a `wss://`
    /// URL, …).
    pub destination: String,
    /// When the address was (re)asserted.
    pub asserted_at: DateTime<Utc>,
    /// Advisory liveness — operators sweep stale destinations. `None`
    /// until first observed. NOT a lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_envelope_carries_full_scope_set_and_dimension() {
        let env =
            delegates_to_agent_envelope("agent-occ", "pair-1", &SELF_AT_LOGIN_DELEGATION_SCOPE);
        assert_eq!(env["dimension"], DIMENSION_DELEGATES_TO_AGENT);
        let scope = env["scope"].as_array().unwrap();
        assert_eq!(scope.len(), 4);
        assert!(scope.iter().any(|v| v == SCOPE_ACT_ON_BEHALF));
        assert!(scope.iter().any(|v| v == SCOPE_SUB_DELEGATION));
    }

    #[test]
    fn general_delegates_to_envelope_admissible_shape() {
        // #249 Cut C — the general builder emits `scope` as an array-set +
        // a top-level `sub_delegation` bool, the exact shape the §11.10 duty
        // walk's containment + deputization checks read.
        let env = delegates_to_envelope(
            "delegate-key",
            &["moderate".to_string(), "review".to_string()],
            true,
        );
        assert_eq!(env["kind"], "delegates_to");
        assert_eq!(env["dimension"], DIMENSION_DELEGATES_TO);
        assert_eq!(env["delegate_key_id"], "delegate-key");
        assert_eq!(env["sub_delegation"], true);
        let scope = env["scope"].as_array().unwrap();
        assert!(scope.iter().any(|v| v == "moderate"));
        assert!(scope.iter().any(|v| v == "review"));
    }

    #[test]
    fn partnership_pair_shares_bilateral_id() {
        let g = partnership_grant_envelope("agent-occ", "pair-7");
        let a = partnership_accept_envelope("user-occ", "pair-7");
        assert_eq!(g["bilateral_pair_id"], a["bilateral_pair_id"]);
        assert_eq!(g["dimension"], DIMENSION_PARTNERSHIP_GRANT);
        assert_eq!(a["dimension"], DIMENSION_PARTNERSHIP_ACCEPT);
    }
}
