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
/// envelope ([`delegates_to_envelope`]), the §11.10 grant/steward-bind/
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
/// `steward_bind` / `add_moderator`) stamp; the login-specific
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
/// by `is_named_moderator` / `is_steward_bound` / `check_moderation_admission`.
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

/// v13.2.0 (CIRISPersist#378, CC 3.2 rc2 single-owner) — the **owner-binding**
/// `delegates_to(user → node)` envelope: "I (user) am the single responsible
/// steward of `node`". The ownership specialization of
/// [`delegates_to_envelope`]: it stamps the CC 1.13.3.3 / CC 3.2 ownership
/// [`DIMENSION`](super::types::owner_binding::DIMENSION) (what the single-owner
/// admission gate + [`owner_of`](super::admission::owner_of) key on) plus the
/// producer-side [`PURPOSE`](super::types::owner_binding::PURPOSE) marker
/// (`delegation_purpose`). This is the ONE `delegates_to` shape that is
/// single-valued (a node has at most one owner) — distinct from the general
/// (multi-parent) act-on-behalf / hierarchy grammar `delegates_to_envelope`
/// builds. `scope` SHOULD be `infra:*`-only (the owner-binding carries only
/// server-class authority); `sub_delegation` is `false` (a leaf ownership
/// binding, not a deputization). The two constants stay byte-identical to
/// CIRISServer's `auth::ownership` shape (the wire is the contract).
pub fn owner_binding_delegates_to_envelope(
    node_key_id: &str,
    infra_scopes: &[String],
) -> serde_json::Value {
    use super::types::owner_binding;
    serde_json::json!({
        "kind": "delegates_to",
        "dimension": owner_binding::DIMENSION,
        "delegation_purpose": owner_binding::PURPOSE,
        "delegate_key_id": node_key_id,
        "scope": infra_scopes,
        "sub_delegation": false,
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

/// v13.9.0 (CIRISPersist#413, CC 3.3.6.2 / part_3 §1056, §1331) — the trust
/// provenance of a [`TransportDestination`] binding. The substrate ADMITS and
/// RECORDS the binding either way; the trust that the announced key actually
/// owns the destination is composed by the CONSUMER (routing prefers `Rooted`
/// over `Advisory`; content gates on trust — CC 6 N1), never a substrate verdict.
/// The AV-42 spoof (an adversary announcing a canonical `key_id` with its own
/// destination) is defeated by that routing-time PREFERENCE, not by refusing the
/// write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BindingProvenance {
    /// The binding is backed by a federation-key-signed `identity_occurrence` /
    /// `root_binding` that verified the announced key against `federation_keys`
    /// (part_3 §1054) — **authoritative**. The back-compat default: pre-#413
    /// rows were all authoritative-by-assumption (canonical priming), so an
    /// untagged row reads as `Rooted`.
    #[default]
    Rooted,
    /// A self-consistent announce whose federation key is unknown / not-yet-
    /// rooted (part_3 §1056) — a **routing hint only, never an authorization**.
    Advisory,
}

impl BindingProvenance {
    /// Stable wire token (`"rooted"` / `"advisory"`) for the TEXT column.
    pub fn as_str(&self) -> &'static str {
        match self {
            BindingProvenance::Rooted => "rooted",
            BindingProvenance::Advisory => "advisory",
        }
    }
    /// Parse from the stored token; unknown/NULL ⇒ the back-compat `Rooted`.
    pub fn from_token(s: Option<&str>) -> Self {
        match s {
            Some("advisory") => BindingProvenance::Advisory,
            _ => BindingProvenance::Rooted,
        }
    }
}

/// v6.5.0 (CIRISPersist#183, CEG §5.6.8.8.1) — one reachable network
/// address for one identity_occurrence (the "show up on the network"
/// reachability row). Backed by the `transport_destinations` table
/// (V078; route-table shape since V105).
///
/// v17.0.0 (CIRISPersist#443) — this is now a **superseding route table**:
/// the authoritative key is `(occurrence_key_id, transport_kind)` (one live
/// route per peer per transport), `destination` is payload, and supersession
/// is `(epoch, asserted_at)`-lexicographic (never last-physical-writer-wins).
/// A row written via the SIGNED replication path additionally stores its
/// detached signature container (see [`SignedTransportDestination`]); a
/// trusted-local write carries none.
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
    /// v13.5.0 (CIRISPersist#397) — the transport-tier **Ed25519 pubkey**,
    /// base64 (standard alphabet) of the 32 raw bytes. For `transport_kind:
    /// reticulum` this is the peer's RNS transport identity Ed25519 (the
    /// keyring-backed, edge-owned key, CIRISEdge#99) that pairs with the
    /// `destination` dest-hash to let any peer `prime_peer` an explicit-hash
    /// canonical that cannot announce (CIRISEdge#214). `None` for pre-#397
    /// rows and non-Reticulum kinds (websocket / https carry no RNS transport
    /// key). Distinct from the identity-tier Ed25519 — NOT derivable from it
    /// (§5.6.8.8.2 key-separation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_ed25519_pubkey_base64: Option<String>,
    /// v13.8.0 (CIRISPersist#411) — the transport-tier **X25519 (KEX) pubkey**,
    /// base64 (standard alphabet) of the 32 raw bytes: the FIRST 32 of the
    /// 64-byte Reticulum transport identity (`x25519(32) ‖ ed25519(32)`, whose
    /// `sha256[..16]` is the `destination` dest-hash). Replication SEALS
    /// envelopes to a peer with this key, so it MUST survive a restart — persist
    /// is the source of truth for rooted-peer transport state; the node/edge
    /// reloads it on boot (`list_all_transport_destinations`), never re-announces.
    /// `None` for pre-#411 rows and non-Reticulum kinds. **Key separation
    /// (§5.6.8.8.2):** this is the TRANSPORT-tier link key, distinct from the
    /// identity-tier content-encryption X25519 in `EncryptionPubkeys` — NOT
    /// derivable from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_x25519_pubkey_base64: Option<String>,
    /// v13.9.0 (CIRISPersist#413, CC 3.3.6.2) — the binding's trust provenance:
    /// [`BindingProvenance::Rooted`] (federation-key-verified, authoritative) vs
    /// [`BindingProvenance::Advisory`] (self-consistent announce, routing-hint
    /// only). The substrate admits + records both; competing claims on one
    /// dest-hash (different `occurrence_key_id`s) all coexist — the AV-42 spoof
    /// is resolved by the consumer PREFERRING `Rooted` at routing time, never by
    /// a substrate reject. `#[serde(default)]` ⇒ pre-#413 records read as
    /// `Rooted` (their authoritative-by-assumption intent).
    #[serde(default)]
    pub binding_provenance: BindingProvenance,
    /// v17.0.0 (CIRISPersist#443) — the **durable monotonic supersession
    /// counter** (the edge-side `RootedPeer.epoch` finally has a durable
    /// home). Supersession is `(epoch, asserted_at)`-lexicographic: a put
    /// applies iff its `epoch` is strictly greater, or equal with a strictly
    /// newer `asserted_at` — so mesh convergence never rides wall clocks
    /// alone and a delayed/replayed frame carrying an older assertion can
    /// never clobber a newer binding. `#[serde(default)]` ⇒ pre-#443 records
    /// (and capsule peers built against an older wheel) read as epoch 0.
    #[serde(default)]
    pub epoch: u64,
    /// v17.0.0 (CIRISPersist#443) — the **replicated tombstone**: when set,
    /// the route is RETIRED. Retirement travels as a signed put with a higher
    /// `(epoch, asserted_at)`, so the monotonic guard keeps older gossip from
    /// resurrecting the route. Retired rows are EXCLUDED from the three
    /// `list_transport_destinations*` reads but INCLUDED in the signed
    /// replication read (tombstones must gossip).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
}

/// v17.0.0 (CIRISPersist#443) — a **signed** transport-destination submission:
/// the route-plane mirror of
/// [`SignedIdentityOccurrence`](crate::federation::types::SignedIdentityOccurrence) /
/// [`SignedIdentityOccurrenceRevocation`](crate::federation::types::SignedIdentityOccurrenceRevocation).
///
/// Before this, the replication plane applied a BARE unsigned
/// [`TransportDestination`] through the plain local upsert — no signature and
/// no check that the delivering origin has authority over `occurrence_key_id`,
/// so any cohort node could overwrite the durable route (with an
/// attacker-chosen `binding_provenance: Rooted`) for any key_id — the
/// CIRISEdge#336 confused deputy. Now the replicated apply
/// ([`put_signed_transport_destination`](crate::federation::FederationDirectory::put_signed_transport_destination))
/// MUST carry a hybrid signature over the exact producer envelope, verified
/// against the PINNED federation pubkeys of `attesting_key_id` plus
/// `signer_acts_for` — a bare unsigned record on the replication path no
/// longer deserializes (breaking, intended; CIRISEdge#336 adopts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTransportDestination {
    /// Persist's typed projection of the route row (what gets stored). Its
    /// members are parsed FROM [`Self::signed_envelope`]; the signature is
    /// verified over `signed_envelope`, not over this projection, so the §0.9
    /// member-presence discipline is preserved (persist never
    /// re-canonicalizes). `last_seen_at` is advisory liveness and is NOT
    /// signed material.
    pub transport_destination: TransportDestination,
    /// The claimed signer — a `federation_keys.key_id`. MUST be the route's
    /// own `occurrence_key_id` or a key bound as an occurrence of it
    /// (`signer_acts_for` — a peer cannot sign a victim's route with its own
    /// unrelated key).
    pub attesting_key_id: String,
    /// The EXACT route envelope the producer signed (signature container
    /// stripped), as received — the bytes the gate JCS-canonicalizes.
    /// Byte-exact by construction (never rebuilt from the typed projection).
    /// `binding_provenance` is read ONLY from here, never from an
    /// unauthenticated wire field.
    pub signed_envelope: serde_json::Value,
    /// The detached hybrid signature over `JCS(signed_envelope)` (Ed25519
    /// over the bytes; ML-DSA-65 over `bytes ‖ ed25519_sig`). Same container
    /// type as the occurrence/revocation planes — the producer is the same
    /// envelope-generic `produce_signed_identity_occurrence`.
    pub signature: ciris_verify_core::transport_binding::TransportBindingSignature,
}

/// v17.0.0 (CIRISPersist#443) — outcome of a
/// [`put_signed_transport_destination`](crate::federation::FederationDirectory::put_signed_transport_destination)
/// monotonic apply. Modeled on
/// [`ReplicatedKeyOutcome`](crate::federation::register::ReplicatedKeyOutcome)
/// (a sibling, not a reuse: the Key plane's `Upgraded` transition has no
/// route-table analog, and route refusals carry a reason). Serde tokens are
/// snake_case, so the wire shape mirrors the Key plane's.
///
/// A `Refused` is a *policy* outcome, not an error: the anti-entropy route
/// plane receives unsolicited records, so "this record is not admitted
/// against the current row" resolves to `Refused` (fail-closed,
/// deterministic, safe to re-offer) rather than aborting the apply loop.
/// Signature/authority failures still surface as `Err` — they mean the
/// record itself is inadmissible, not merely stale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportDestinationApplyOutcome {
    /// No row existed for `(occurrence_key_id, transport_kind)` — inserted.
    Inserted,
    /// The existing row was replaced: the incoming `(epoch, asserted_at)` is
    /// strictly greater (lexicographic). Retirement (a tombstone put) also
    /// lands here.
    Superseded,
    /// The row already carries this exact typed content — idempotent no-op.
    Unchanged,
    /// NOT applied: the incoming `(epoch, asserted_at)` is older, or equal
    /// with different content (a same-clock fork — fail-closed). The existing
    /// row is untouched; the record is safe to re-offer.
    Refused {
        /// Why the record was not admitted against the current row.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v13.9.0 (CIRISPersist#413) — `BindingProvenance` back-compat: an untagged
    /// (pre-#413, NULL) row reads as `Rooted` (its authoritative-by-assumption
    /// intent); an unknown token also fails safe to `Rooted`; tokens round-trip.
    #[test]
    fn binding_provenance_token_back_compat() {
        assert_eq!(BindingProvenance::default(), BindingProvenance::Rooted);
        assert_eq!(
            BindingProvenance::from_token(None),
            BindingProvenance::Rooted
        );
        assert_eq!(
            BindingProvenance::from_token(Some("advisory")),
            BindingProvenance::Advisory
        );
        assert_eq!(
            BindingProvenance::from_token(Some("rooted")),
            BindingProvenance::Rooted
        );
        assert_eq!(
            BindingProvenance::from_token(Some("nonsense")),
            BindingProvenance::Rooted
        );
        assert_eq!(BindingProvenance::Rooted.as_str(), "rooted");
        assert_eq!(BindingProvenance::Advisory.as_str(), "advisory");
    }

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
    fn owner_binding_envelope_carries_ownership_dimension_and_purpose() {
        // #378 (CC 3.2 rc2) — the owner-binding specialization stamps the
        // ownership dimension + producer-side purpose marker (what the
        // single-owner gate + owner_of key on), sub_delegation always false.
        use super::super::types::owner_binding;
        let env = owner_binding_delegates_to_envelope(
            "node-key",
            &[
                "infra:serve".to_string(),
                "infra:network_presence".to_string(),
            ],
        );
        assert_eq!(env["kind"], "delegates_to");
        assert_eq!(env["dimension"], owner_binding::DIMENSION);
        assert_eq!(env["delegation_purpose"], owner_binding::PURPOSE);
        assert_eq!(env["delegate_key_id"], "node-key");
        assert_eq!(env["sub_delegation"], false);
        let scope = env["scope"].as_array().unwrap();
        assert!(scope
            .iter()
            .all(|v| v.as_str().unwrap().starts_with("infra:")));
    }

    #[test]
    fn partnership_pair_shares_bilateral_id() {
        let g = partnership_grant_envelope("agent-occ", "pair-7");
        let a = partnership_accept_envelope("user-occ", "pair-7");
        assert_eq!(g["bilateral_pair_id"], a["bilateral_pair_id"]);
        assert_eq!(g["dimension"], DIMENSION_PARTNERSHIP_GRANT);
        assert_eq!(a["dimension"], DIMENSION_PARTNERSHIP_ACCEPT);
    }

    /// v17.0.0 (#443) — a BARE unsigned `TransportDestination` payload does
    /// NOT deserialize as a `SignedTransportDestination`: the replication
    /// path's structural refusal of the pre-#443 confused-deputy wire shape
    /// (a peer can no longer push an unauthenticated route). Also: the #443
    /// fields are serde-defaulted, so a pre-#443 record (no epoch /
    /// retired_at) still decodes — capsule ABI back-compat.
    #[test]
    fn bare_unsigned_transport_destination_refused_on_signed_plane() {
        let bare = serde_json::json!({
            "occurrence_key_id": "occ-1",
            "transport_kind": "reticulum",
            "destination": "d1",
            "asserted_at": "2026-06-10T00:00:00Z",
            "binding_provenance": "rooted",
        });
        // Pre-#443 back-compat: the bare TYPED row still decodes, epoch 0, live.
        let td: TransportDestination = serde_json::from_value(bare.clone()).unwrap();
        assert_eq!(td.epoch, 0);
        assert!(td.retired_at.is_none());
        // ...but it is NOT admissible as a signed record (missing container).
        assert!(
            serde_json::from_value::<SignedTransportDestination>(bare).is_err(),
            "a bare unsigned route must not deserialize as SignedTransportDestination"
        );
    }
}

/// v17.0.0 (CIRISPersist#443) — shared, backend-agnostic conformance matrices
/// for the transport route table, run by the sqlite / postgres / memory test
/// suites against `&dyn FederationDirectory` so the three backends cannot
/// drift (the CIRISConformance parity rule). `suffix` scopes every fixture id
/// so runs against a shared test DB (postgres) don't collide.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("test timestamp")
    }

    /// A minimal live route row (local-put shape: no signature container).
    pub(crate) fn route(
        occ: &str,
        kind: &str,
        dest: &str,
        epoch: u64,
        asserted: &str,
    ) -> TransportDestination {
        TransportDestination {
            occurrence_key_id: occ.into(),
            transport_kind: kind.into(),
            destination: dest.into(),
            asserted_at: ts(asserted),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: None,
            transport_x25519_pubkey_base64: None,
            binding_provenance: BindingProvenance::Rooted,
            epoch,
            retired_at: None,
        }
    }

    /// A `federation_keys` fixture with REAL hybrid pubkeys (so the #443
    /// signature gate can verify envelopes signed by the matching signer).
    /// `put_public_key` does not itself hybrid-verify the registration, so
    /// the scrub fields stay placeholders — only the PUBKEYS must be real.
    fn fixture_key(key_id: &str, ed_pk: String, mldsa_pk: Option<String>) -> KeyRecord {
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: ts("2026-05-01T00:00:00Z"),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: ts("2026-05-01T00:00:00Z"),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// **The (epoch, asserted_at) monotonic-guard matrix** for the trusted-
    /// LOCAL put: newer supersedes (in place — never a second row per kind),
    /// older asserted_at at the same epoch is refused, an older epoch is
    /// refused even with a newer wall clock, and a higher epoch wins even
    /// with an older wall clock (epoch dominates — clock skew cannot roll a
    /// route back). Plus list ordering + the local remove.
    pub(crate) async fn run_transport_route_guard_matrix(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let occ_id = format!("route-guard-occ-{suffix}");
        let occ = occ_id.as_str();
        let ws_dest_id = format!("wss://route-guard-{suffix}");
        let ws_dest = ws_dest_id.as_str();

        // (1) Fresh insert.
        dir.put_transport_destination(&route(occ, "reticulum", "d1", 0, "2026-06-10T00:00:00Z"))
            .await
            .expect("insert");
        // (2) Same epoch, newer asserted_at, rotated destination → SUPERSEDES
        // in place (the dest-hash rotation that used to append a row).
        dir.put_transport_destination(&route(occ, "reticulum", "d2", 0, "2026-06-11T00:00:00Z"))
            .await
            .expect("rotate");
        let rows = dir.list_transport_destinations_for(occ).await.unwrap();
        assert_eq!(rows.len(), 1, "rotation must not append: {rows:?}");
        assert_eq!(rows[0].destination, "d2");
        // (3) Same epoch, OLDER asserted_at → silent no-op (replayed frame).
        dir.put_transport_destination(&route(
            occ,
            "reticulum",
            "d-stale",
            0,
            "2026-06-09T00:00:00Z",
        ))
        .await
        .expect("stale put is not an error");
        assert_eq!(
            dir.list_transport_destinations_for(occ).await.unwrap()[0].destination,
            "d2",
            "an older assertion must not clobber a newer binding"
        );
        // (4) Epoch advance supersedes...
        dir.put_transport_destination(&route(occ, "reticulum", "d3", 2, "2026-06-12T00:00:00Z"))
            .await
            .expect("epoch advance");
        // ...and an OLDER epoch is refused even with a NEWER wall clock.
        dir.put_transport_destination(&route(
            occ,
            "reticulum",
            "d-old-epoch",
            1,
            "2026-07-01T00:00:00Z",
        ))
        .await
        .expect("old-epoch put is not an error");
        let rows = dir.list_transport_destinations_for(occ).await.unwrap();
        assert_eq!(rows[0].destination, "d3", "epoch guard: {rows:?}");
        assert_eq!(rows[0].epoch, 2);
        // (5) A HIGHER epoch wins even with an older asserted_at (epoch
        // dominates the lexicographic order).
        dir.put_transport_destination(&route(occ, "reticulum", "d4", 3, "2026-06-01T00:00:00Z"))
            .await
            .expect("higher epoch, older clock");
        let rows = dir.list_transport_destinations_for(occ).await.unwrap();
        assert_eq!(rows[0].destination, "d4");
        assert_eq!(rows[0].epoch, 3);

        // (6) A second transport_kind is an independent route row; list_all
        // orders by the route key (occurrence_key_id, transport_kind).
        dir.put_transport_destination(&route(occ, "websocket", ws_dest, 0, "2026-06-10T00:00:00Z"))
            .await
            .expect("second kind");
        let all = dir.list_all_transport_destinations().await.unwrap();
        let keys: Vec<(String, String)> = all
            .iter()
            .map(|r| (r.occurrence_key_id.clone(), r.transport_kind.clone()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "list_all must order by (occ, kind)");
        assert_eq!(all.iter().filter(|r| r.occurrence_key_id == occ).count(), 2);

        // (7) by-destination sees the live claimant; local remove keys on the
        // CURRENT destination and is idempotent.
        assert_eq!(
            dir.list_transport_destinations_by_destination(ws_dest)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(dir
            .remove_transport_destination(occ, "websocket", ws_dest)
            .await
            .unwrap());
        assert!(!dir
            .remove_transport_destination(occ, "websocket", ws_dest)
            .await
            .unwrap());
        assert_eq!(
            dir.list_transport_destinations_for(occ)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// **The authenticated-apply + tombstone matrix** for
    /// `put_signed_transport_destination`, with REAL hybrid crypto:
    /// - a valid self-signed route is admitted (`Inserted`), its
    ///   `binding_provenance` honored from the VERIFIED envelope;
    /// - a byte-identical replay is `Unchanged`;
    /// - a forged signature / an unrelated-but-registered signer / a typed
    ///   projection diverging from the envelope are each `Err` (fail-closed);
    /// - an acts-for occurrence key of the subject is admitted;
    /// - an older `(epoch, asserted_at)` replay is `Refused`; a same-clock
    ///   fork is `Refused`;
    /// - a signed RETIREMENT (`retired_at`, higher epoch) supersedes; the
    ///   retired route disappears from every `list_*` read but keeps
    ///   gossiping via the signed reads; older gossip cannot resurrect it;
    /// - a trusted-local put that supersedes a signed row drops the stored
    ///   signature container.
    pub(crate) async fn run_signed_transport_route_matrix(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
        use ciris_verify_core::self_at_login::HybridSigningIdentity;
        use ciris_verify_core::transport_binding::produce_signed_identity_occurrence;
        use TransportDestinationApplyOutcome as Outcome;

        let alice_id = format!("sig-alice-{suffix}");
        let phone_id = format!("sig-alice-phone-{suffix}");
        let mallory_id = format!("sig-mallory-{suffix}");

        // Box the hybrid signers and build them BEFORE any await — a multi-KiB
        // ML-DSA signer held across an await inlines into the caller's future
        // and overflows the 2MB test stack.
        let alice = Box::new(HybridSigningIdentity::new(
            &alice_id,
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let phone = Box::new(HybridSigningIdentity::new(
            &phone_id,
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let mallory = Box::new(HybridSigningIdentity::new(
            &mallory_id,
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        for (id, ident) in [
            (&alice_id, alice.as_ref()),
            (&phone_id, phone.as_ref()),
            (&mallory_id, mallory.as_ref()),
        ] {
            let member = ident.directory_member().unwrap();
            dir.put_public_key(SignedKeyRecord {
                record: fixture_key(
                    id,
                    member.ed25519_public_key_base64.clone(),
                    member.mldsa65_public_key_base64.clone(),
                ),
            })
            .await
            .expect("register fixture key");
        }
        // Bind the phone key as an occurrence of alice, so it may act-for
        // routes whose subject is alice.
        dir.put_identity_occurrence_local(crate::federation::IdentityOccurrence {
            identity_key_id: alice_id.clone(),
            occurrence_key_id: phone_id.clone(),
            device_class: crate::federation::types::device_class::AGENT.into(),
            hardware_attestation: None,
            asserted_at: ts("2026-06-01T00:00:00Z"),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind acts-for occurrence");

        // The envelope IS the serialized typed row (minus the unsigned
        // last_seen_at, which route() leaves None) — projection ≡ envelope by
        // construction; the gate re-derives every field from the envelope.
        let mut r1 = route(&alice_id, "reticulum", "d1", 0, "2026-06-10T00:00:00Z");
        r1.binding_provenance = BindingProvenance::Advisory;
        let (env1, sig1) =
            produce_signed_identity_occurrence(alice.as_ref(), serde_json::to_value(&r1).unwrap())
                .await
                .unwrap();
        let s1 = SignedTransportDestination {
            transport_destination: r1.clone(),
            attesting_key_id: alice_id.clone(),
            signed_envelope: env1.clone(),
            signature: sig1.clone(),
        };

        // (1) Valid self-signed → Inserted; provenance honored from the
        // VERIFIED envelope (Advisory in, Advisory stored — no unauthenticated
        // Rooted upgrade possible).
        assert_eq!(
            dir.put_signed_transport_destination(&s1).await.unwrap(),
            Outcome::Inserted
        );
        let rows = dir
            .list_transport_destinations_for(&alice_id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].binding_provenance, BindingProvenance::Advisory);

        // (2) Byte-identical replay → Unchanged.
        assert_eq!(
            dir.put_signed_transport_destination(&s1).await.unwrap(),
            Outcome::Unchanged
        );

        // (3) Forged signature → Err; row untouched.
        let mut bad = s1.clone();
        bad.signature.ed25519_signature_base64 = B64.encode([0u8; 64]);
        let err = dir
            .put_signed_transport_destination(&bad)
            .await
            .expect_err("forged signature must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");

        // (4) Unrelated-but-REGISTERED signer: mallory validly signs the
        // victim's envelope with her own key → signer_acts_for rejects.
        let (m_env, m_sig) = produce_signed_identity_occurrence(
            mallory.as_ref(),
            serde_json::to_value(&r1).unwrap(),
        )
        .await
        .unwrap();
        let err = dir
            .put_signed_transport_destination(&SignedTransportDestination {
                transport_destination: r1.clone(),
                attesting_key_id: mallory_id.clone(),
                signed_envelope: m_env,
                signature: m_sig,
            })
            .await
            .expect_err("a peer's route assertion for a victim must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");

        // (5) Divergent typed projection (envelope says d1, typed claims
        // attacker-dest) → Err.
        let mut divergent = s1.clone();
        divergent.transport_destination.destination = "attacker-dest".into();
        let err = dir
            .put_signed_transport_destination(&divergent)
            .await
            .expect_err("typed projection diverging from the envelope must be rejected");
        assert!(format!("{err}").contains("diverges"), "got {err}");
        // ... including a provenance-only divergence (the AV-42 upgrade).
        let mut prov_divergent = s1.clone();
        prov_divergent.transport_destination.binding_provenance = BindingProvenance::Rooted;
        let err = dir
            .put_signed_transport_destination(&prov_divergent)
            .await
            .expect_err("typed Rooted over an Advisory envelope must be rejected");
        assert!(format!("{err}").contains("diverges"), "got {err}");

        // (6) Acts-for: the phone key (a bound occurrence of alice) signs the
        // epoch-1 rotation → Superseded.
        let r2 = route(&alice_id, "reticulum", "d2", 1, "2026-06-11T00:00:00Z");
        let (env2, sig2) =
            produce_signed_identity_occurrence(phone.as_ref(), serde_json::to_value(&r2).unwrap())
                .await
                .unwrap();
        let s2 = SignedTransportDestination {
            transport_destination: r2.clone(),
            attesting_key_id: phone_id.clone(),
            signed_envelope: env2,
            signature: sig2,
        };
        assert_eq!(
            dir.put_signed_transport_destination(&s2).await.unwrap(),
            Outcome::Superseded
        );

        // (7) Older (epoch, asserted_at) replay → Refused (never an error).
        assert!(matches!(
            dir.put_signed_transport_destination(&s1).await.unwrap(),
            Outcome::Refused { .. }
        ));

        // (8) Same (epoch, asserted_at), DIFFERENT content → Refused
        // (a same-clock fork is fail-closed, not last-writer-wins).
        let fork = route(&alice_id, "reticulum", "d2-fork", 1, "2026-06-11T00:00:00Z");
        let (fork_env, fork_sig) = produce_signed_identity_occurrence(
            alice.as_ref(),
            serde_json::to_value(&fork).unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            dir.put_signed_transport_destination(&SignedTransportDestination {
                transport_destination: fork.clone(),
                attesting_key_id: alice_id.clone(),
                signed_envelope: fork_env,
                signature: fork_sig,
            })
            .await
            .unwrap(),
            Outcome::Refused { .. }
        ));

        // (9) Signed RETIREMENT: retired_at set, higher epoch → Superseded.
        let mut tomb = route(&alice_id, "reticulum", "d2", 2, "2026-06-12T00:00:00Z");
        tomb.retired_at = Some(ts("2026-06-12T00:00:00Z"));
        let (tomb_env, tomb_sig) = produce_signed_identity_occurrence(
            alice.as_ref(),
            serde_json::to_value(&tomb).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            dir.put_signed_transport_destination(&SignedTransportDestination {
                transport_destination: tomb.clone(),
                attesting_key_id: alice_id.clone(),
                signed_envelope: tomb_env.clone(),
                signature: tomb_sig,
            })
            .await
            .unwrap(),
            Outcome::Superseded
        );
        // Retired ⇒ gone from every list_* read...
        assert!(dir
            .list_transport_destinations_for(&alice_id)
            .await
            .unwrap()
            .is_empty());
        assert!(!dir
            .list_all_transport_destinations()
            .await
            .unwrap()
            .iter()
            .any(|r| r.occurrence_key_id == alice_id));
        assert!(dir
            .list_transport_destinations_by_destination("d2")
            .await
            .unwrap()
            .iter()
            .all(|r| r.occurrence_key_id != alice_id));
        // ...but the tombstone keeps gossiping via the signed reads,
        // byte-exact.
        let signed_rows = dir
            .list_signed_transport_destinations_for(&alice_id)
            .await
            .unwrap();
        assert_eq!(signed_rows.len(), 1, "tombstones must gossip");
        assert_eq!(signed_rows[0].signed_envelope, tomb_env);
        assert!(signed_rows[0].transport_destination.retired_at.is_some());
        let records = dir
            .list_signed_records(
                crate::federation::namespace::ReplicatedKind::TransportDestination,
                &alice_id,
            )
            .await
            .unwrap();
        assert_eq!(
            records.len(),
            1,
            "list_signed_records carries the tombstone"
        );
        let round_trip: SignedTransportDestination =
            serde_json::from_value(records[0].canonical_json.clone()).unwrap();
        assert_eq!(round_trip.signed_envelope, tomb_env);

        // (10) A replayed OLDER live put cannot resurrect the retired route.
        assert!(matches!(
            dir.put_signed_transport_destination(&s2).await.unwrap(),
            Outcome::Refused { .. }
        ));
        assert!(dir
            .list_transport_destinations_for(&alice_id)
            .await
            .unwrap()
            .is_empty());
        // ...and neither can a stale LOCAL put (silent no-op).
        dir.put_transport_destination(&route(
            &alice_id,
            "reticulum",
            "d-necromancer",
            1,
            "2026-07-01T00:00:00Z",
        ))
        .await
        .unwrap();
        assert!(dir
            .list_transport_destinations_for(&alice_id)
            .await
            .unwrap()
            .is_empty());

        // (11) v21.4.0 (#515) — SIGNED WINS THE SHARED KEY: a trusted-local
        // put, even at a HIGHER epoch, can NEITHER resurrect a signed
        // retirement NOR demote the signature container. The tombstone was
        // signed intent; an unsigned writer carries nothing that outranks
        // it. (Pre-#515 this leg asserted the opposite — the local put
        // re-established the route and dropped the signature — which is
        // exactly the demotion recipe the live canonical hit.)
        dir.put_transport_destination(&route(
            &alice_id,
            "reticulum",
            "d3",
            3,
            "2026-06-13T00:00:00Z",
        ))
        .await
        .unwrap();
        assert!(
            dir.list_transport_destinations_for(&alice_id)
                .await
                .unwrap()
                .is_empty(),
            "an unsigned put must not resurrect a signed retirement"
        );
        assert_eq!(
            dir.list_signed_transport_destinations_for(&alice_id)
                .await
                .unwrap()
                .len(),
            1,
            "the signed tombstone keeps gossiping"
        );

        // (12) Re-establishment comes SIGNED: an epoch-3 signed rotation by
        // the bound occurrence re-opens the route through the signed plane.
        let r3 = route(&alice_id, "reticulum", "d3", 3, "2026-06-13T00:00:00Z");
        let (env3, sig3) =
            produce_signed_identity_occurrence(phone.as_ref(), serde_json::to_value(&r3).unwrap())
                .await
                .unwrap();
        let s3 = SignedTransportDestination {
            transport_destination: r3.clone(),
            attesting_key_id: phone_id.clone(),
            signed_envelope: env3,
            signature: sig3,
        };
        assert!(matches!(
            dir.put_signed_transport_destination(&s3).await.unwrap(),
            Outcome::Superseded | Outcome::Inserted
        ));
        let rows = dir
            .list_transport_destinations_for(&alice_id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].destination, "d3");
        assert_eq!(
            dir.list_signed_transport_destinations_for(&alice_id)
                .await
                .unwrap()
                .len(),
            1,
            "the signed re-establishment replaces the tombstone on the signed plane"
        );

        // (13) v21.17.1 (#541) — THE PRESERVE SET MUST EQUAL THE VERIFIED SET.
        // An unsigned SAME-CONTENT liveness refresh at a later clock — exactly
        // what edge's announce write-through issues every round — sails
        // through #515's guard, because #515 only compared destination + both
        // transport pubkeys. Pre-#541 it then rewrote the typed `asserted_at`
        // (and `epoch` / `binding_provenance` / `retired_at`) while preserving
        // the signature and the byte-exact envelope, desynchronising the row
        // from its own signature. `verify_signed_transport_destination` checks
        // all nine of those fields, so every peer refused the replicated row
        // with `typed asserted_at diverges from the signed envelope` — and the
        // #393 item-2 gate, which needs that binding to attribute inbound
        // frames, then dropped everything from the sender. That is how the
        // trace plane went dark while every component reported healthy.
        // Note this was not a rare interleaving: the monotonic guard REQUIRES
        // `excluded.asserted_at > stored.asserted_at`, so every refresh the
        // guard accepted corrupted the row BY CONSTRUCTION.
        dir.put_transport_destination(&route(
            &alice_id,
            "reticulum",
            "d3",
            3,
            "2026-06-14T00:00:00Z",
        ))
        .await
        .unwrap();
        let signed_rows = dir
            .list_signed_transport_destinations_for(&alice_id)
            .await
            .unwrap();
        assert_eq!(signed_rows.len(), 1);
        let env_asserted = signed_rows[0]
            .signed_envelope
            .get("asserted_at")
            .and_then(|v| v.as_str())
            .expect("the signed envelope carries asserted_at");
        assert_eq!(
            ts(env_asserted),
            signed_rows[0].transport_destination.asserted_at,
            "an unsigned liveness refresh must NEVER desynchronise a signed row \
             from its own envelope — the signature and the fields it attests to \
             move as one unit (#541)"
        );
        assert_eq!(
            signed_rows[0].transport_destination.asserted_at,
            ts("2026-06-13T00:00:00Z"),
            "the SIGNED clock is authoritative: an unsigned writer must not \
             advance a signed row's asserted_at (#541)"
        );
        assert_eq!(
            signed_rows[0].transport_destination.epoch, 3,
            "nor its epoch (#541)"
        );

        // (14) v21.17.1 (#541) — close the loop with the REAL verifier, not a
        // field comparison: after the unsigned refresh, the row read back through
        // the replication path must still pass `verify_signed_transport_destination`.
        // (A hand-rolled field check rebuilds the two-lists problem inside the test;
        // the verifier IS the list.)
        crate::federation::admission::verify_signed_transport_destination(dir, &signed_rows[0])
            .await
            .expect(
                "an unsigned liveness refresh must leave a signed transport_destination \
                 still verifiable by a remote peer (#541)",
            );
    }

    /// v21.17.1 (CIRISPersist#541) — THE INVARIANT, mechanically: no sequence of
    /// local writes may render a signed row unverifiable by a remote peer. This
    /// is the `identity_occurrence` half of the class the transport matrix's leg
    /// 13/14 pins for `transport_destination` — insert a signed row, apply an
    /// arbitrary unsigned local write on the same key at an ADVANCED clock (an
    /// equal-clock write proves nothing: the monotonic guard no-ops it), read
    /// back through the real `list_signed_*` replication path, and re-run the
    /// family's `verify_signed_*` asserting it STILL passes. Run identically
    /// across memory + sqlite + postgres (the audit found the backends
    /// disagreeing). Also pins the fail-OPEN KEM gap (now closed) and the
    /// memory/sqlite double-revoke asymmetry.
    pub(crate) async fn exercise_signed_row_survives_local_write(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
        use ciris_verify_core::self_at_login::HybridSigningIdentity;
        use ciris_verify_core::transport_binding::{
            compute_destination_hash, produce_signed_identity_occurrence,
        };

        let alice_id = format!("io-alice-{suffix}");
        let phone_id = format!("io-phone-{suffix}");

        // Box the signer + build BEFORE any await (2MB test-stack guard).
        let alice = Box::new(HybridSigningIdentity::new(
            &alice_id,
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let member = alice.directory_member().unwrap();
        dir.put_public_key(SignedKeyRecord {
            record: fixture_key(
                &alice_id,
                member.ed25519_public_key_base64.clone(),
                member.mldsa65_public_key_base64.clone(),
            ),
        })
        .await
        .expect("register identity key");
        dir.put_public_key(SignedKeyRecord {
            record: fixture_key(&phone_id, B64.encode([9u8; 32]), None),
        })
        .await
        .expect("register occurrence key");

        // A signed identity_occurrence carrying BOTH a transport_binding and the
        // content-KEM pair — the envelope is authoritative, the typed row mirrors it.
        let transport_ed = [0x01u8; 32];
        let transport_x = [0x02u8; 32];
        let content_x = [0x03u8; 32];
        let ml_kem = vec![0x11u8; 1184];
        let app = "ciris.federation";
        let aspects = vec!["announce".to_string(), "v1".to_string()];
        let dest_hash =
            compute_destination_hash(app, &aspects, &transport_x, &transport_ed).unwrap();
        let envelope = serde_json::json!({
            "identity_key_id": alice_id,
            "occurrence_key_id": phone_id,
            "transport_destination": {
                "reticulum_x25519_pubkey": B64.encode(transport_x),
                "reticulum_ed25519_pubkey": B64.encode(transport_ed),
                "destination_hash": B64.encode(dest_hash),
                "app_name": app,
                "aspects": aspects,
            },
            "encryption_pubkeys": {
                "x25519_base64": B64.encode(content_x),
                "ml_kem_768_base64": B64.encode(&ml_kem),
            },
            "asserted_at": "2026-06-14T00:00:00.000Z",
        });
        let (signed_envelope, signature) =
            produce_signed_identity_occurrence(alice.as_ref(), envelope)
                .await
                .unwrap();
        let typed = |x: &[u8], kem: &[u8]| crate::federation::IdentityOccurrence {
            identity_key_id: alice_id.clone(),
            occurrence_key_id: phone_id.clone(),
            device_class: crate::federation::types::device_class::AGENT.into(),
            hardware_attestation: None,
            asserted_at: ts("2026-06-14T00:00:00Z"),
            valid_until: None,
            encryption_pubkeys: Some(crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x),
                ml_kem_768_base64: B64.encode(kem),
            }),
            transport_binding: Some(crate::federation::types::OccurrenceTransportBinding {
                reticulum_x25519_pubkey_base64: B64.encode(transport_x),
                reticulum_ed25519_pubkey_base64: B64.encode(transport_ed),
                destination_hash_base64: B64.encode(dest_hash),
                app_name: app.into(),
                aspects: aspects.clone(),
            }),
            persist_row_hash: String::new(),
        };
        let signed = crate::federation::SignedIdentityOccurrence {
            identity_occurrence: typed(&content_x, &ml_kem),
            attesting_key_id: alice_id.clone(),
            signed_envelope: signed_envelope.clone(),
            signature: signature.clone(),
        };
        dir.put_identity_occurrence(signed.clone())
            .await
            .expect("signed identity_occurrence admits");
        crate::federation::admission::verify_signed_identity_occurrence(dir, &signed)
            .await
            .expect("baseline: the stored signed occurrence verifies");

        // THE ATTACK — an unsigned local self-write on the SAME key at an advanced
        // clock, content-only (transport_binding: None), exactly like engine.rs's
        // login/DEK co-admit. Pre-#541 this NULLed the envelope-covered columns
        // while keeping the signature; the replicated row then diverged.
        dir.put_identity_occurrence_local(crate::federation::IdentityOccurrence {
            identity_key_id: alice_id.clone(),
            occurrence_key_id: phone_id.clone(),
            device_class: crate::federation::types::device_class::AGENT.into(),
            hardware_attestation: None,
            asserted_at: ts("2026-06-20T00:00:00Z"),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("the content-only local self-write is accepted (no-op on the signed row)");

        // Read back through the REAL replication path and re-run the REAL verifier.
        let rows = dir
            .list_signed_identity_occurrences_for(&alice_id)
            .await
            .expect("signed read");
        assert_eq!(rows.len(), 1, "({suffix}) the signed occurrence survives");
        assert!(
            rows[0].identity_occurrence.transport_binding.is_some(),
            "({suffix}) the local write must NOT have NULLed the signed transport_binding"
        );
        crate::federation::admission::verify_signed_identity_occurrence(dir, &rows[0])
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({suffix}) a signed identity_occurrence must remain verifiable after any \
                     unsigned local write — got {e}"
                )
            });

        // The fail-OPEN KEM gap, now closed: a typed row whose ml_kem_768 diverges
        // from the signed envelope (x25519 unchanged) must be REJECTED. Pre-#541
        // the verifier compared only x25519 and silently ACCEPTED this.
        let kem_diverged = crate::federation::SignedIdentityOccurrence {
            identity_occurrence: typed(&content_x, &[0x22u8; 1184]),
            attesting_key_id: alice_id.clone(),
            signed_envelope,
            signature,
        };
        let err =
            crate::federation::admission::verify_signed_identity_occurrence(dir, &kem_diverged)
                .await
                .expect_err("({suffix}) a diverged content-KEM key must fail closed (#541)");
        assert!(
            format!("{err}").contains("diverges"),
            "({suffix}) KEM divergence rejected as a divergence: {err}"
        );

        // The double-revoke asymmetry: a second local revocation on the same key
        // is REFUSED on every backend (memory used to silently overwrite
        // effective_at — "the whole attack").
        let rev = |secs: i64| crate::federation::types::IdentityOccurrenceRevocation {
            identity_key_id: alice_id.clone(),
            occurrence_key_id: phone_id.clone(),
            revoked_at: ts("2026-07-01T00:00:00Z") + chrono::Duration::seconds(secs),
            effective_at: ts("2026-07-01T00:00:00Z") + chrono::Duration::seconds(secs),
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        };
        dir.put_identity_occurrence_revocation_local(rev(0))
            .await
            .expect("first local revocation admits");
        dir.put_identity_occurrence_revocation_local(rev(100))
            .await
            .expect_err(
                "({suffix}) a second local revocation on the same key must be refused (#541)",
            );
    }

    /// **The #446 composite-projection matrix** (trusted-local occurrence
    /// plane; the signed plane is covered by the sqlite gate test, which
    /// shares the same projection code path). Invariant: every ACCEPTED
    /// occurrence carrying a `transport_binding` has its route materialized
    /// in `transport_destinations` as a LOCAL derived row — visible to the
    /// plain reads, invisible to the signed replication read (no
    /// double-carriage) — superseding on the occurrence's own asserted_at
    /// clock, retired by the occurrence's revocation, and revived by a newer
    /// occurrence.
    pub(crate) async fn run_binding_projection_matrix(dir: &dyn FederationDirectory, suffix: &str) {
        use crate::federation::types::{
            device_class, IdentityOccurrence, IdentityOccurrenceRevocation,
            OccurrenceTransportBinding,
        };
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let identity = format!("proj-id-{suffix}");
        let occ = format!("proj-occ-{suffix}");
        for k in [&identity, &occ] {
            let ed = B64.encode([0x22u8; 32]);
            dir.put_public_key(SignedKeyRecord {
                record: fixture_key(k, ed, None),
            })
            .await
            .expect("register projection fixture key");
        }

        let binding = |tag: u8| OccurrenceTransportBinding {
            reticulum_x25519_pubkey_base64: B64.encode([tag; 32]),
            reticulum_ed25519_pubkey_base64: B64.encode([tag.wrapping_add(1); 32]),
            destination_hash_base64: B64.encode([tag; 16]),
            app_name: "ciris.federation".into(),
            aspects: vec!["announce".into()],
        };
        let occ_row = |asserted: &str, tag: u8| IdentityOccurrence {
            identity_key_id: identity.clone(),
            occurrence_key_id: occ.clone(),
            device_class: device_class::AGENT.into(),
            hardware_attestation: None,
            asserted_at: ts(asserted),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: Some(binding(tag)),
            persist_row_hash: String::new(),
        };

        // (1) Accepted local put with a binding → the route is MATERIALIZED:
        // reticulum kind, dest + both transport pubkeys from the binding,
        // Rooted from context, (epoch=0, asserted_at=occurrence clock).
        dir.put_identity_occurrence_local(occ_row("2026-07-01T00:00:00Z", 0x10))
            .await
            .expect("(1) local occurrence put");
        let rows = dir.list_transport_destinations_for(&occ).await.unwrap();
        assert_eq!(rows.len(), 1, "(1) exactly one projected route");
        let r = &rows[0];
        assert_eq!(r.transport_kind, OccurrenceTransportBinding::TRANSPORT_KIND);
        // v21.3.0 (#512) — the projected destination is canonical HEX.
        assert_eq!(r.destination, hex::encode([0x10u8; 16]));
        assert_eq!(
            r.transport_x25519_pubkey_base64.as_deref(),
            Some(B64.encode([0x10u8; 32]).as_str())
        );
        assert_eq!(
            r.transport_ed25519_pubkey_base64.as_deref(),
            Some(B64.encode([0x11u8; 32]).as_str())
        );
        assert_eq!(r.binding_provenance, BindingProvenance::Rooted);
        assert_eq!(r.epoch, 0);
        assert_eq!(r.asserted_at, ts("2026-07-01T00:00:00Z"));
        // No double-carriage: the projected row is LOCAL-derived, so the
        // signed replication read must not emit it (the occurrence plane is
        // the single replication authority for this route).
        assert!(
            dir.list_signed_transport_destinations_for(&occ)
                .await
                .unwrap()
                .is_empty(),
            "(1) a projected route must not replicate on the route plane"
        );

        // (2) A newer occurrence supersedes the projection in lockstep.
        dir.put_identity_occurrence_local(occ_row("2026-07-02T00:00:00Z", 0x20))
            .await
            .expect("(2) newer local occurrence put");
        let rows = dir.list_transport_destinations_for(&occ).await.unwrap();
        assert_eq!(rows.len(), 1, "(2) superseded in place, never a 2nd row");
        assert_eq!(rows[0].destination, hex::encode([0x20u8; 16]));

        // (3) De-projection: revoking the occurrence retires the projected
        // route — a revoked occurrence must not leave a live routable peer.
        dir.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: identity.clone(),
            occurrence_key_id: occ.clone(),
            revoked_at: ts("2026-07-03T00:00:00Z"),
            effective_at: ts("2026-07-03T00:00:00Z"),
            reason: None,
            witness_set: vec![identity.clone()],
            persist_row_hash: String::new(),
        })
        .await
        .expect("(3) local occurrence revocation");
        assert!(
            dir.list_transport_destinations_for(&occ)
                .await
                .unwrap()
                .is_empty(),
            "(3) the projected route must be retired with its occurrence"
        );

        // (4) A NEWER occurrence re-materializes (revives) the route — the
        // (epoch, asserted_at) guard supersedes the retired row and clears
        // retired_at.
        dir.put_identity_occurrence_local(occ_row("2026-07-04T00:00:00Z", 0x30))
            .await
            .expect("(4) re-established occurrence put");
        let rows = dir.list_transport_destinations_for(&occ).await.unwrap();
        assert_eq!(rows.len(), 1, "(4) a newer occurrence revives the route");
        assert_eq!(rows[0].destination, hex::encode([0x30u8; 16]));
    }
}
