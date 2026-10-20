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
    /// Parse from the stored or enveloped token. An ABSENT token (NULL, a
    /// pre-#413 row) is the back-compat `Rooted`.
    ///
    /// # Errors
    ///
    /// v52.0.0 — a PRESENT token that is neither `"rooted"` nor `"advisory"`
    /// refuses by name. Until v52 it read as `Rooted`, so a signed transport
    /// destination whose envelope carried any unknown token was admitted as
    /// authoritative (malformed is a refusal, not absence).
    pub fn from_token(s: Option<&str>) -> Result<Self, crate::federation::Error> {
        match s {
            None | Some("rooted") => Ok(BindingProvenance::Rooted),
            Some("advisory") => Ok(BindingProvenance::Advisory),
            Some(other) => Err(crate::federation::Error::InvalidArgument(format!(
                "binding_provenance token {other:?} is neither \"rooted\" nor \"advisory\" \
                 — refused (an unknown token is malformed, never the authoritative default)"
            ))),
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

// ─── transit KEX pair (CC 3.3.6.2 rc8, CIRISPersist#1077) ───────────

/// v56.0.0 (CIRISPersist#1077, CC 3.3.6.2 at rc8 2a7ed97) — the
/// `signed_envelope` member carrying a relay's **transit KEX public key pair**
/// `{x25519, ml_kem_768}`: the static pair a non-member relay publishes for the
/// CC 5.3.3.5 E1 hop-by-hop hybrid key exchange. The construction (pattern,
/// labels, KDF, KATs) is CIRISVerify#309's; persist only stores, admits and
/// serves the pair.
///
/// Wire shape inside the signed envelope (sorted keys under JCS):
///
/// ```json
/// "transit_kex_pubkeys": {
///   "ml_kem_768_base64": "<base64 of exactly 1184 bytes>",
///   "x25519_base64": "<base64 of exactly 32 bytes>"
/// }
/// ```
///
/// **Envelope-only.** The pair is deliberately NOT a field of the typed
/// [`TransportDestination`] projection. Edge's route plane syncs by
/// `content_hash_of(SignedTransportDestination)` (the whole wrapper: the
/// projection plus the verbatim envelope), so a serialized projection field
/// would hash the same row differently on a v55 node and an upgraded one and
/// churn forever. With the pair only in the envelope, the wrapper's bytes are
/// identical across versions, and the pair is still hash-covered because the
/// envelope is. Read it with [`SignedTransportDestination::transit_kex_pair`].
pub const TRANSIT_KEX_PUBKEYS_MEMBER: &str = "transit_kex_pubkeys";
/// The x25519 member inside [`TRANSIT_KEX_PUBKEYS_MEMBER`] (standard base64).
pub const TRANSIT_KEX_X25519_MEMBER: &str = "x25519_base64";
/// The ML-KEM-768 member inside [`TRANSIT_KEX_PUBKEYS_MEMBER`] (standard base64).
pub const TRANSIT_KEX_ML_KEM_768_MEMBER: &str = "ml_kem_768_base64";
/// Exact raw length of the transit x25519 public key.
pub const TRANSIT_KEX_X25519_LEN: usize = 32;
/// Exact raw length of the transit ML-KEM-768 encapsulation key.
pub const TRANSIT_KEX_ML_KEM_768_LEN: usize = 1184;

/// v56.0.0 (CIRISPersist#1077) — a relay's decoded transit KEX public key pair,
/// as read from a signed transport-destination envelope by
/// [`SignedTransportDestination::transit_kex_pair`]. The lengths are carried in
/// the types, so a value of this struct is always a well-formed pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitKexPair {
    /// The static X25519 public key (32 raw bytes).
    pub x25519: [u8; TRANSIT_KEX_X25519_LEN],
    /// The static ML-KEM-768 encapsulation key (1184 raw bytes).
    pub ml_kem_768: Box<[u8; TRANSIT_KEX_ML_KEM_768_LEN]>,
}

/// v59.0.0 (CIRISPersist#1106, CIRISEdge) — why a transit pair fails
/// [`check_transit_kex_pair`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitKexRefusal {
    /// The transit X25519 is byte-equal to one of the other keys.
    X25519Reuse,
    /// The transit ML-KEM-768 encapsulation key is byte-equal to one of them.
    MlKem768Reuse,
}

impl TransitKexRefusal {
    /// The stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X25519Reuse => "transit_kex_x25519_reuse",
            Self::MlKem768Reuse => "transit_kex_ml_kem_768_reuse",
        }
    }
}

/// v59.0.0 (CIRISPersist#1106, CIRISEdge) — the keys a transit pair must be
/// separated from, in FOUR named groups (the groups
/// [`transit_kex_pair_for`] gathers), typed so a caller cannot mislabel one.
/// Each key is raw bytes (base64-decoded).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitKexOtherKeys {
    /// (a) The node's federation signing keys: Ed25519 (32 bytes) and
    /// ML-DSA-65 (1952 bytes).
    pub federation_signing: Vec<Vec<u8>>,
    /// (b) The node's transport identity: Reticulum X25519 and Ed25519, from
    /// its occurrence binding and every live transport binding (including the
    /// row's own link keys).
    pub transport_identity: Vec<Vec<u8>>,
    /// (c) The occurrence's `encryption_pubkeys` (X25519, ML-KEM-768), where
    /// present.
    pub encryption: Vec<Vec<u8>>,
    /// (d) The federation signing keys of each identity the occurrence is
    /// bound under.
    pub bound_identity_signing: Vec<Vec<u8>>,
}

impl TransitKexOtherKeys {
    fn all(&self) -> impl Iterator<Item = &[u8]> {
        self.federation_signing
            .iter()
            .chain(&self.transport_identity)
            .chain(&self.encryption)
            .chain(&self.bound_identity_signing)
            .map(Vec::as_slice)
    }
}

/// v59.0.0 (CIRISPersist#1106, CIRISEdge; CC 3.3.6.2 key separation) —
/// **THE transit-pair separation rule, pure.** The pair's X25519 and
/// ML-KEM-768 keys must not be byte-equal to any key in `other_keys`. The
/// admission gate's in-row check, the resolver [`transit_kex_pair_for`] and the
/// genesis bundle's serve-node rows all call this, so the rule exists once.
///
/// # The `other_keys` contract ([`TransitKexOtherKeys`])
///
/// [`transit_kex_pair_for`] fills all four groups from the directory: (a) the
/// node's federation signing keys; (b) its transport identity from its
/// occurrence binding and every live transport binding; (c) the occurrence's
/// `encryption_pubkeys`; (d) the federation signing keys of each identity the
/// occurrence is bound under.
///
/// A caller holding only a node's `key_id`, its transport identity and its
/// federation key (CIRISEdge's offline emit and pairing pin) passes **(a) +
/// (b)**. Omitting (c) + (d) weakens only the CROSS-ROW half of the check
/// (reuse of a key published on another plane), which the stored check —
/// [`transit_kex_pair_for`] at use — closes. Keys of different lengths never
/// compare equal, so passing every key you hold is always safe.
///
/// # Errors
///
/// The first [`TransitKexRefusal`] found.
pub fn check_transit_kex_pair(
    pair: &TransitKexPair,
    other_keys: &TransitKexOtherKeys,
) -> Result<(), TransitKexRefusal> {
    for k in other_keys.all() {
        if k == &pair.x25519[..] {
            return Err(TransitKexRefusal::X25519Reuse);
        }
        if k == &pair.ml_kem_768[..] {
            return Err(TransitKexRefusal::MlKem768Reuse);
        }
    }
    Ok(())
}

/// v56.0.0 (CIRISPersist#1077) — THE one reading of the transit KEX pair from a
/// signed transport-destination envelope; the admission gate and the accessor
/// both call it, so what admits is what reads.
///
/// - member absent ⇒ `Ok(None)` (the v55 shape, unchanged);
/// - member present but not an object (including `null`) ⇒
///   [`malformed_row::ENVELOPE_MEMBER_INVALID`](crate::federation::malformed_row::ENVELOPE_MEMBER_INVALID);
/// - only one of the two members, or neither ⇒
///   [`malformed_row::TRANSIT_KEX_HALF_PAIR`](crate::federation::malformed_row::TRANSIT_KEX_HALF_PAIR);
/// - a member that is not a string or not standard base64 ⇒
///   `ENVELOPE_MEMBER_INVALID`;
/// - a member that decodes to anything but exactly 32 / 1184 bytes ⇒
///   [`malformed_row::TRANSIT_KEX_WRONG_LENGTH`](crate::federation::malformed_row::TRANSIT_KEX_WRONG_LENGTH).
///
/// Unknown members inside the pair object are tolerated, as unknown members of
/// the envelope are (the forward-compatible §0.9 member-presence parse).
///
/// # Errors
///
/// [`crate::federation::Error::MalformedRow`] on plane `transport_destination`,
/// with one of the reasons above.
pub fn transit_kex_pair_from_envelope(
    envelope: &serde_json::Value,
) -> Result<Option<TransitKexPair>, crate::federation::Error> {
    use crate::federation::{malformed_row, Error};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    const PLANE: &str = "transport_destination";

    let Some(member) = envelope.get(TRANSIT_KEX_PUBKEYS_MEMBER) else {
        return Ok(None);
    };
    let Some(obj) = member.as_object() else {
        return Err(Error::malformed_row(
            PLANE,
            malformed_row::ENVELOPE_MEMBER_INVALID,
            format!(
                "signed transport_destination envelope `{TRANSIT_KEX_PUBKEYS_MEMBER}` must be an \
                 object {{{TRANSIT_KEX_X25519_MEMBER}, {TRANSIT_KEX_ML_KEM_768_MEMBER}}}, got \
                 {member}"
            ),
        ));
    };
    let (x, m) = match (
        obj.get(TRANSIT_KEX_X25519_MEMBER),
        obj.get(TRANSIT_KEX_ML_KEM_768_MEMBER),
    ) {
        (Some(x), Some(m)) => (x, m),
        (x, m) => {
            let missing = match (x, m) {
                (None, None) => {
                    format!(
                        "both `{TRANSIT_KEX_X25519_MEMBER}` and `{TRANSIT_KEX_ML_KEM_768_MEMBER}`"
                    )
                }
                (None, _) => format!("`{TRANSIT_KEX_X25519_MEMBER}`"),
                _ => format!("`{TRANSIT_KEX_ML_KEM_768_MEMBER}`"),
            };
            return Err(Error::malformed_row(
                PLANE,
                malformed_row::TRANSIT_KEX_HALF_PAIR,
                format!(
                    "signed transport_destination `{TRANSIT_KEX_PUBKEYS_MEMBER}` is missing \
                     {missing}: the transit KEX pair is both members or the member is absent \
                     (CC 3.3.6.2)"
                ),
            ));
        }
    };
    let decode = |label: &str, v: &serde_json::Value| -> Result<Vec<u8>, Error> {
        let s = v.as_str().ok_or_else(|| {
            Error::malformed_row(
                PLANE,
                malformed_row::ENVELOPE_MEMBER_INVALID,
                format!("`{TRANSIT_KEX_PUBKEYS_MEMBER}.{label}` must be a base64 string"),
            )
        })?;
        B64.decode(s).map_err(|e| {
            Error::malformed_row(
                PLANE,
                malformed_row::ENVELOPE_MEMBER_INVALID,
                format!("`{TRANSIT_KEX_PUBKEYS_MEMBER}.{label}` is not standard base64: {e}"),
            )
        })
    };
    // The exact-length rule IS the conversion into the fixed-size types: there
    // is no second check that could drift from it, and no panic path.
    let wrong_length = |label: &str, want: usize, got: usize| {
        Error::malformed_row(
            PLANE,
            malformed_row::TRANSIT_KEX_WRONG_LENGTH,
            format!(
                "`{TRANSIT_KEX_PUBKEYS_MEMBER}.{label}` must decode to exactly {want} bytes, \
                 got {got}"
            ),
        )
    };
    let x = decode(TRANSIT_KEX_X25519_MEMBER, x)?;
    let m = decode(TRANSIT_KEX_ML_KEM_768_MEMBER, m)?;
    let x25519 = <[u8; TRANSIT_KEX_X25519_LEN]>::try_from(x.as_slice())
        .map_err(|_| wrong_length(TRANSIT_KEX_X25519_MEMBER, TRANSIT_KEX_X25519_LEN, x.len()))?;
    let m_len = m.len();
    let ml_kem_768 = Box::<[u8; TRANSIT_KEX_ML_KEM_768_LEN]>::try_from(m.into_boxed_slice())
        .map_err(|_| {
            wrong_length(
                TRANSIT_KEX_ML_KEM_768_MEMBER,
                TRANSIT_KEX_ML_KEM_768_LEN,
                m_len,
            )
        })?;
    Ok(Some(TransitKexPair { x25519, ml_kem_768 }))
}

/// v56.0.0 (CIRISPersist#1077) — do two signed envelopes carry the same transit
/// KEX member (both absent, or byte-equal JSON)? The three backends'
/// `put_signed_transport_destination` call this before answering `Unchanged`:
/// the pair is envelope-only, so an equal typed projection at an equal
/// `(epoch, asserted_at)` no longer means equal content. A same-clock re-sign
/// that changes the pair is a fork and is `Refused`, never kept silently as
/// the old pair.
#[must_use]
pub fn same_transit_kex_member(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get(TRANSIT_KEX_PUBKEYS_MEMBER) == b.get(TRANSIT_KEX_PUBKEYS_MEMBER)
}

impl SignedTransportDestination {
    /// v56.0.0 (CIRISPersist#1077, CC 3.3.6.2 rc8) — this binding's transit KEX
    /// pair, read from [`Self::signed_envelope`] by
    /// [`transit_kex_pair_from_envelope`] (exact 32 / 1184-byte lengths, both
    /// members or neither). `Ok(None)` is a binding that publishes no pair; per
    /// CC 3.3.6.2 such a node **cannot relay**.
    ///
    /// **Consumer rule:** for per-peer resolution call
    /// [`transit_kex_pair_for`] (CIRISPersist#1078), not this raw read: it
    /// takes the pair only from a live [`BindingProvenance::Rooted`] binding
    /// and returns `None` when the pair reuses any key on the node's current
    /// occurrence. This accessor reads one row's envelope, nothing more. A row
    /// read back from persist has already passed admission, so this only errs
    /// on a value built outside persist.
    ///
    /// # Errors
    ///
    /// [`crate::federation::Error::MalformedRow`] on plane
    /// `transport_destination` (`transit_kex_half_pair`,
    /// `transit_kex_wrong_length`, `envelope_member_invalid`).
    pub fn transit_kex_pair(&self) -> Result<Option<TransitKexPair>, crate::federation::Error> {
        transit_kex_pair_from_envelope(&self.signed_envelope)
    }

    /// v56.0.0 (CIRISPersist#1077) — the binding's trust provenance, read from
    /// the stored typed projection (which admission proved equal to the signed
    /// envelope's token).
    #[must_use]
    pub fn binding_provenance(&self) -> BindingProvenance {
        self.transport_destination.binding_provenance
    }

    /// v56.0.0 (CIRISPersist#1077) — [`Self::transit_kex_pair`] for a
    /// [`BindingProvenance::Rooted`] binding, `Ok(None)` for an `Advisory`
    /// one (a routing hint never supplies a hop key). The read a relay
    /// resolver should use.
    ///
    /// # Errors
    ///
    /// As [`Self::transit_kex_pair`].
    pub fn rooted_transit_kex_pair(
        &self,
    ) -> Result<Option<TransitKexPair>, crate::federation::Error> {
        match self.binding_provenance() {
            BindingProvenance::Rooted => self.transit_kex_pair(),
            BindingProvenance::Advisory => Ok(None),
        }
    }
}

/// v56.0.0 (CIRISPersist#1078, CC 3.3.6.2 rc8) — **the per-peer transit KEX
/// resolver**: the pair a consumer may use to key a hop to the relay
/// `occurrence_key_id`, or `None` when that node carries no valid transit pair
/// and so cannot relay. CIRISEdge and every other consumer call this for
/// per-peer resolution, never the raw [`SignedTransportDestination::transit_kex_pair`].
///
/// Admission enforces only the in-row key separation (the arrival-order-free
/// part, CC 3.2 T8 vii). The cross-row case is closed HERE, at use,
/// deterministically over the rows as held (no clock, no write):
///
/// 1. read the node's signed transport destinations; take the pair only from
///    live (unretired) [`BindingProvenance::Rooted`] bindings. No such binding,
///    or none carrying a pair ⇒ `None`. Two live Rooted bindings that carry
///    DIFFERENT pairs ⇒ `None` (an ambiguous hop key is no hop key).
/// 2. gather every key on the node's current occurrence rows
///    ([`list_identity_occurrences_by_occurrence_key`]): `encryption_pubkeys`
///    x25519 / ML-KEM-768, the occurrence transport binding's Reticulum
///    x25519 / ed25519, the pinned federation signing keys (ed25519 and
///    ML-DSA-65) of the occurrence key and of each identity it is bound under,
///    and the transport keys of the node's live bindings.
/// 3. the transit x25519 or ML-KEM-768 bytes equal to ANY of them ⇒ `None`;
///    otherwise `Some(pair)`.
///
/// [`list_identity_occurrences_by_occurrence_key`]: crate::federation::FederationDirectory::list_identity_occurrences_by_occurrence_key
///
/// # Errors
///
/// A backend read error; a stored binding whose pair does not parse (it
/// passed admission, so this means a corrupted row).
pub async fn transit_kex_pair_for<D: crate::federation::FederationDirectory + ?Sized>(
    dir: &D,
    occurrence_key_id: &str,
) -> Result<Option<TransitKexPair>, crate::federation::Error> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let bindings = dir
        .list_signed_transport_destinations_for(occurrence_key_id)
        .await?;
    let live: Vec<&SignedTransportDestination> = bindings
        .iter()
        .filter(|b| b.transport_destination.retired_at.is_none())
        .collect();
    let mut pair: Option<TransitKexPair> = None;
    for b in &live {
        let Some(p) = b.rooted_transit_kex_pair()? else {
            continue;
        };
        match &pair {
            None => pair = Some(p),
            Some(q) if *q == p => {}
            Some(_) => return Ok(None),
        }
    }
    let Some(pair) = pair else {
        return Ok(None);
    };

    let dec = |b64: Option<&str>| b64.and_then(|s| B64.decode(s).ok());
    let mut others = TransitKexOtherKeys::default();
    for b in &live {
        let td = &b.transport_destination;
        others
            .transport_identity
            .extend(dec(td.transport_x25519_pubkey_base64.as_deref()));
        others
            .transport_identity
            .extend(dec(td.transport_ed25519_pubkey_base64.as_deref()));
    }
    let occurrences = dir
        .list_identity_occurrences_by_occurrence_key(occurrence_key_id)
        .await?;
    let mut bound: Vec<String> = Vec::new();
    for o in &occurrences {
        if let Some(k) = &o.encryption_pubkeys {
            others.encryption.extend(dec(Some(&k.x25519_base64)));
            others.encryption.extend(dec(Some(&k.ml_kem_768_base64)));
        }
        if let Some(t) = &o.transport_binding {
            others
                .transport_identity
                .extend(dec(Some(&t.reticulum_x25519_pubkey_base64)));
            others
                .transport_identity
                .extend(dec(Some(&t.reticulum_ed25519_pubkey_base64)));
        }
        bound.push(o.identity_key_id.clone());
    }
    if let Some(k) = dir.lookup_public_key(occurrence_key_id).await? {
        others
            .federation_signing
            .extend(dec(Some(&k.pubkey_ed25519_base64)));
        others
            .federation_signing
            .extend(dec(k.pubkey_ml_dsa_65_base64.as_deref()));
    }
    bound.sort();
    bound.dedup();
    for id in bound.iter().filter(|id| *id != occurrence_key_id) {
        if let Some(k) = dir.lookup_public_key(id).await? {
            others
                .bound_identity_signing
                .extend(dec(Some(&k.pubkey_ed25519_base64)));
            others
                .bound_identity_signing
                .extend(dec(k.pubkey_ml_dsa_65_base64.as_deref()));
        }
    }
    if check_transit_kex_pair(&pair, &others).is_err() {
        return Ok(None);
    }
    Ok(Some(pair))
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

    /// v59.0.0 (CIRISPersist#1106) — the pure separation rule: a pair that
    /// reuses none of the other keys passes; one whose X25519 or ML-KEM-768
    /// equals a supplied key is refused with that half's token; keys of other
    /// lengths never collide.
    #[test]
    fn check_transit_kex_pair_refuses_a_reused_key_1106() {
        let pair = TransitKexPair {
            x25519: [7u8; TRANSIT_KEX_X25519_LEN],
            ml_kem_768: Box::new([9u8; TRANSIT_KEX_ML_KEM_768_LEN]),
        };
        let fed = TransitKexOtherKeys {
            federation_signing: vec![vec![1u8; 32], vec![2u8; 1952]],
            ..Default::default()
        };
        assert_eq!(check_transit_kex_pair(&pair, &fed), Ok(()));
        // Each of the four groups is consulted.
        for group in 0..4 {
            let mut k = fed.clone();
            let reused = vec![7u8; 32];
            match group {
                0 => k.federation_signing.push(reused),
                1 => k.transport_identity.push(reused),
                2 => k.encryption.push(reused),
                _ => k.bound_identity_signing.push(reused),
            }
            assert_eq!(
                check_transit_kex_pair(&pair, &k),
                Err(TransitKexRefusal::X25519Reuse),
                "group {group}"
            );
        }
        let mut k = fed.clone();
        k.encryption.push(vec![9u8; TRANSIT_KEX_ML_KEM_768_LEN]);
        assert_eq!(
            check_transit_kex_pair(&pair, &k),
            Err(TransitKexRefusal::MlKem768Reuse)
        );
        assert_eq!(
            TransitKexRefusal::X25519Reuse.as_str(),
            "transit_kex_x25519_reuse"
        );
        assert_eq!(
            check_transit_kex_pair(&pair, &TransitKexOtherKeys::default()),
            Ok(())
        );
    }

    /// v13.9.0 (CIRISPersist#413) — `BindingProvenance` back-compat: an untagged
    /// (pre-#413, NULL) row reads as `Rooted` (its authoritative-by-assumption
    /// intent); tokens round-trip. **I279** (v52.0.0): an unknown PRESENT token
    /// refuses; until v52 it read as `Rooted`, the fail-open this pins.
    #[test]
    fn binding_provenance_token_back_compat() {
        assert_eq!(BindingProvenance::default(), BindingProvenance::Rooted);
        assert_eq!(
            BindingProvenance::from_token(None).unwrap(),
            BindingProvenance::Rooted
        );
        assert_eq!(
            BindingProvenance::from_token(Some("advisory")).unwrap(),
            BindingProvenance::Advisory
        );
        assert_eq!(
            BindingProvenance::from_token(Some("rooted")).unwrap(),
            BindingProvenance::Rooted
        );
        for bad in ["nonsense", "Rooted", "ROOTED", ""] {
            assert!(
                matches!(
                    BindingProvenance::from_token(Some(bad)),
                    Err(crate::federation::Error::InvalidArgument(_))
                ),
                "I279: {bad:?} must refuse, never read as Rooted"
            );
        }
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
            capability_roles: Vec::new(),
            // v47.3.0 (#901, FSD §3.6) — every synthetic identity is hardware-attested.
            attestation_evidence: Some(
                crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(
                ),
            ),
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
        // v54.1.0 (#1042 follow-up) — the signature verifies; mallory is not
        // (yet) an occurrence of alice: the signer-acts-for refusal, typed.
        assert_eq!(err.kind(), "federation_signer_not_acting_for");

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

        // (15) I279 (v52.0.0) — an UNKNOWN provenance token in the signed
        // envelope refuses. Until v52 it read as `Rooted`, matched the typed
        // `Rooted` row, and was admitted as authoritative.
        let r_bad = route(&alice_id, "i279", "d-bad", 0, "2026-06-20T00:00:00Z");
        let mut env_bad = serde_json::to_value(&r_bad).unwrap();
        env_bad["binding_provenance"] = serde_json::json!("ROOTED");
        let (env_bad, sig_bad) = produce_signed_identity_occurrence(alice.as_ref(), env_bad)
            .await
            .unwrap();
        let bad = SignedTransportDestination {
            transport_destination: r_bad,
            attesting_key_id: alice_id.clone(),
            signed_envelope: env_bad,
            signature: sig_bad,
        };
        let e = dir
            .put_signed_transport_destination(&bad)
            .await
            .expect_err("I279: an unknown provenance token must refuse, never read as Rooted");
        assert!(
            e.to_string().contains("binding_provenance"),
            "I279: refused by name: {e}"
        );
        assert!(
            dir.list_transport_destinations_for(&alice_id)
                .await
                .unwrap()
                .iter()
                .all(|r| r.transport_kind != "i279"),
            "I279: nothing stored"
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
            // v31.0.0 (CIRISVerify 13.1.0) - `attesting_key_id` is BOUND into the
            // signed bytes. It is a `SignedIdentityOccurrence` field living
            // OUTSIDE them, so nothing tied the signer named on the wrapper to
            // the signer the envelope is about: Mallory could re-present a
            // victim's genuine envelope under her own transport destination and
            // the signature still verified. Verify now refuses the pair as
            // SubjectMismatch. Same spelling as verify's own fixture.
            "attesting_key_id": alice_id,
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

    /// v56.0.0 (CIRISPersist#1077, CC 3.3.6.2 rc8) — an envelope value for a
    /// route row with an optional transit KEX member spliced in verbatim.
    pub(crate) fn envelope_with_transit_kex(
        row: &TransportDestination,
        member: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut env = serde_json::to_value(row).expect("route row to value");
        if let Some(m) = member {
            env.as_object_mut()
                .expect("route envelope is an object")
                .insert(TRANSIT_KEX_PUBKEYS_MEMBER.into(), m);
        }
        env
    }

    /// A well-formed `transit_kex_pubkeys` member from fill bytes.
    pub(crate) fn transit_kex_member(x_fill: u8, m_fill: u8) -> serde_json::Value {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        serde_json::json!({
            TRANSIT_KEX_X25519_MEMBER: B64.encode([x_fill; TRANSIT_KEX_X25519_LEN]),
            TRANSIT_KEX_ML_KEM_768_MEMBER: B64.encode(vec![m_fill; TRANSIT_KEX_ML_KEM_768_LEN]),
        })
    }

    /// `e` is the terminal `MalformedRow` on the route plane for `reason`.
    pub(crate) fn expect_route_malformed(e: &crate::federation::Error, reason: &str, what: &str) {
        assert!(
            matches!(
                e,
                crate::federation::Error::MalformedRow { plane: "transport_destination", reason: r, .. }
                    if *r == reason
            ),
            "{what}: expected MalformedRow {{ transport_destination, {reason} }}, got {} ({e:?})",
            e.kind()
        );
    }

    /// **The transit KEX matrix** (v56.0.0, CIRISPersist#1077), run on the
    /// memory, sqlite and postgres backends. Every envelope is REALLY signed by
    /// a registered key that may act for the route, so each refusal is the
    /// pair rule's and not the signature gate's.
    ///
    /// - **I1011** a well-formed pair admits; the envelope is stored verbatim;
    ///   `list_signed_transport_destinations_for` / `_since` and the
    ///   content-hash point read re-serve it with the member intact; the
    ///   accessor reads the pair back.
    /// - **I1012** (backend leg) one member alone, an empty pair, and wrong
    ///   lengths (31, 33, 1183, 1185) refuse by name; the stored row is
    ///   untouched. A row with neither member admits and reads `None`.
    /// - **I1014** rotation rides `(epoch, asserted_at)`: a higher epoch with a
    ///   new pair supersedes; the older row is then `Refused`.
    /// - **I1015** a same-clock re-sign that changes only the pair is
    ///   `Refused` (the projection is equal, the content is not), and the exact
    ///   replay stays `Unchanged`.
    /// - **I1016** key separation: a transit x25519 equal to the row's own
    ///   Reticulum link x25519 refuses (`transit_kex_key_reuse`).
    pub(crate) async fn run_transit_kex_matrix(dir: &dyn FederationDirectory, suffix: &str) {
        use crate::federation::malformed_row as mr;
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
        use ciris_verify_core::self_at_login::HybridSigningIdentity;
        use ciris_verify_core::transport_binding::produce_signed_identity_occurrence;
        use TransportDestinationApplyOutcome as Outcome;

        let relay_id = format!("tkex-relay-{suffix}");
        let relay = Box::new(HybridSigningIdentity::new(
            &relay_id,
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let member = relay.directory_member().unwrap();
        dir.put_public_key(SignedKeyRecord {
            record: fixture_key(
                &relay_id,
                member.ed25519_public_key_base64.clone(),
                member.mldsa65_public_key_base64.clone(),
            ),
        })
        .await
        .expect("register relay key");

        let sign = |row: TransportDestination, m: Option<serde_json::Value>| {
            let env = envelope_with_transit_kex(&row, m);
            let relay = relay.as_ref();
            let relay_id = relay_id.clone();
            async move {
                let (env, sig) = produce_signed_identity_occurrence(relay, env)
                    .await
                    .expect("sign route envelope");
                SignedTransportDestination {
                    transport_destination: row,
                    attesting_key_id: relay_id,
                    signed_envelope: env,
                    signature: sig,
                }
            }
        };
        let kind = "reticulum";

        // I1012 — the v55 shape: neither member admits, accessor reads None.
        let r0 = route(&relay_id, kind, "d0", 0, "2026-10-13T00:00:00Z");
        let s0 = sign(r0.clone(), None).await;
        assert_eq!(
            dir.put_signed_transport_destination(&s0).await.unwrap(),
            Outcome::Inserted,
            "I1012: a row with no pair admits (v55 shape)"
        );
        assert_eq!(s0.transit_kex_pair().unwrap(), None);

        // I1011 — a well-formed pair admits and is served verbatim.
        let r1 = route(&relay_id, kind, "d1", 1, "2026-10-13T01:00:00Z");
        let s1 = sign(r1.clone(), Some(transit_kex_member(0x11, 0x22))).await;
        assert_eq!(
            dir.put_signed_transport_destination(&s1).await.unwrap(),
            Outcome::Superseded,
            "I1011: a pair-bearing row supersedes the pairless one"
        );
        let held = dir
            .list_signed_transport_destinations_for(&relay_id)
            .await
            .unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].signed_envelope, s1.signed_envelope,
            "I1011: the envelope is stored and re-served verbatim (_for)"
        );
        let pair = held[0]
            .transit_kex_pair()
            .unwrap()
            .expect("I1011: pair reads back");
        assert_eq!(pair.x25519, [0x11; TRANSIT_KEX_X25519_LEN]);
        assert!(pair.ml_kem_768.iter().all(|b| *b == 0x22));
        assert_eq!(
            held[0].rooted_transit_kex_pair().unwrap(),
            Some(pair.clone())
        );
        let served = dir
            .list_signed_transport_destinations_since(None, 10_000)
            .await
            .unwrap();
        let mine: Vec<_> = served
            .iter()
            .filter(|s| s.destination.transport_destination.occurrence_key_id == relay_id)
            .collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(
            mine[0].destination, s1,
            "I1011: the serve cursor re-serves the exact signed row (_since)"
        );
        assert_eq!(
            mine[0].destination.transit_kex_pair().unwrap(),
            Some(pair.clone())
        );
        let hash = crate::federation::wire_index::content_hash_of(&s1).unwrap();
        let bytes = dir
            .lookup_signed_record_by_content_hash("TransportDestination", &hash)
            .await
            .unwrap()
            .expect("I1011: the pair-bearing row is point-readable by its content hash");
        assert_eq!(bytes, serde_json::to_vec(&s1).unwrap());
        let back: SignedTransportDestination = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.transit_kex_pair().unwrap(), Some(pair.clone()));

        // I1012 — malformed pairs refuse by name, each REALLY signed; the
        // stored row is untouched.
        let x_ok = B64.encode([0x33u8; TRANSIT_KEX_X25519_LEN]);
        let m_ok = B64.encode(vec![0x44u8; TRANSIT_KEX_ML_KEM_768_LEN]);
        let cases: Vec<(&str, serde_json::Value, &str)> = vec![
            (
                "x25519 alone",
                serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: x_ok }),
                mr::TRANSIT_KEX_HALF_PAIR,
            ),
            (
                "ml_kem alone",
                serde_json::json!({ TRANSIT_KEX_ML_KEM_768_MEMBER: m_ok }),
                mr::TRANSIT_KEX_HALF_PAIR,
            ),
            (
                "empty pair",
                serde_json::json!({}),
                mr::TRANSIT_KEX_HALF_PAIR,
            ),
            (
                "x25519 31",
                serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: B64.encode([1u8; 31]), TRANSIT_KEX_ML_KEM_768_MEMBER: m_ok }),
                mr::TRANSIT_KEX_WRONG_LENGTH,
            ),
            (
                "x25519 33",
                serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: B64.encode([1u8; 33]), TRANSIT_KEX_ML_KEM_768_MEMBER: m_ok }),
                mr::TRANSIT_KEX_WRONG_LENGTH,
            ),
            (
                "ml_kem 1183",
                serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: x_ok, TRANSIT_KEX_ML_KEM_768_MEMBER: B64.encode(vec![1u8; 1183]) }),
                mr::TRANSIT_KEX_WRONG_LENGTH,
            ),
            (
                "ml_kem 1185",
                serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: x_ok, TRANSIT_KEX_ML_KEM_768_MEMBER: B64.encode(vec![1u8; 1185]) }),
                mr::TRANSIT_KEX_WRONG_LENGTH,
            ),
            (
                "null member",
                serde_json::Value::Null,
                mr::ENVELOPE_MEMBER_INVALID,
            ),
        ];
        for (i, (what, m, reason)) in cases.into_iter().enumerate() {
            let r = route(
                &relay_id,
                kind,
                "bad",
                50 + i as u64,
                "2026-10-13T02:00:00Z",
            );
            let s = sign(r, Some(m)).await;
            let e = dir
                .put_signed_transport_destination(&s)
                .await
                .expect_err(what);
            expect_route_malformed(&e, reason, &format!("I1012 {what}"));
        }
        let still = dir
            .list_signed_transport_destinations_for(&relay_id)
            .await
            .unwrap();
        assert_eq!(
            still[0], s1,
            "I1012: refusals leave the stored row untouched"
        );

        // I1016 — key separation: transit x25519 == the row's RNS link x25519.
        let mut r_reuse = route(&relay_id, kind, "reuse", 90, "2026-10-13T02:00:00Z");
        r_reuse.transport_x25519_pubkey_base64 = Some(B64.encode([0x55u8; 32]));
        let s_reuse = sign(r_reuse.clone(), Some(transit_kex_member(0x55, 0x66))).await;
        let e = dir
            .put_signed_transport_destination(&s_reuse)
            .await
            .expect_err("I1016: transit x25519 reusing the link key");
        expect_route_malformed(&e, mr::TRANSIT_KEX_KEY_REUSE, "I1016");
        // ... while the transport ed25519 and the signer's ed25519 are a
        // different algorithm (CC 3.3.6.1: not byte-comparable), so an equal
        // 32 bytes there is NOT an admission refusal; the resolver
        // (`transit_kex_pair_for`) judges every key at use.
        let mut r_ed = route(&relay_id, kind, "reuse-ed", 89, "2026-10-13T02:00:00Z");
        r_ed.transport_ed25519_pubkey_base64 = Some(B64.encode([0x57u8; 32]));
        let s_ed = sign(r_ed, Some(transit_kex_member(0x57, 0x66))).await;
        assert_eq!(
            dir.put_signed_transport_destination(&s_ed).await.unwrap(),
            Outcome::Superseded,
            "I1016: the in-row duty is the link key only"
        );
        // ... a distinct link key on the same row admits (the check is the
        // equality, not the presence of a link key).
        r_reuse.transport_x25519_pubkey_base64 = Some(B64.encode([0x56u8; 32]));
        let s_sep = sign(r_reuse, Some(transit_kex_member(0x55, 0x66))).await;
        assert_eq!(
            dir.put_signed_transport_destination(&s_sep).await.unwrap(),
            Outcome::Superseded,
            "I1016: a transit x25519 distinct from the link key admits"
        );
        // I1014 — rotation: a higher epoch with a new pair supersedes.
        let r2 = route(&relay_id, kind, "d2", 100, "2026-10-13T03:00:00Z");
        let s2 = sign(r2.clone(), Some(transit_kex_member(0x77, 0x88))).await;
        assert_eq!(
            dir.put_signed_transport_destination(&s2).await.unwrap(),
            Outcome::Superseded,
            "I1014: a higher epoch with a new pair supersedes"
        );
        let now = dir
            .list_signed_transport_destinations_for(&relay_id)
            .await
            .unwrap();
        assert_eq!(
            now[0].transit_kex_pair().unwrap().unwrap().x25519,
            [0x77; TRANSIT_KEX_X25519_LEN],
            "I1014: the rotated pair is the one served"
        );
        // ... and the older pair-bearing row is Refused, as today.
        assert!(
            matches!(
                dir.put_signed_transport_destination(&s1).await.unwrap(),
                Outcome::Refused { .. }
            ),
            "I1014: an older row cannot roll the pair back"
        );
        // ... nor can the epoch-90 row it superseded.
        assert!(matches!(
            dir.put_signed_transport_destination(&s_sep).await.unwrap(),
            Outcome::Refused { .. }
        ));

        // I1015 — same (epoch, asserted_at), same projection, different pair:
        // a fork, Refused; the stored pair is unchanged.
        let s2_fork = sign(r2.clone(), Some(transit_kex_member(0x99, 0xAA))).await;
        assert_eq!(s2_fork.transport_destination, s2.transport_destination);
        assert!(
            matches!(
                dir.put_signed_transport_destination(&s2_fork)
                    .await
                    .unwrap(),
                Outcome::Refused { .. }
            ),
            "I1015: a same-clock re-sign that changes only the pair is a fork"
        );
        // ... and a same-clock re-sign that DROPS the pair is the same fork.
        let s2_drop = sign(r2.clone(), None).await;
        assert!(matches!(
            dir.put_signed_transport_destination(&s2_drop)
                .await
                .unwrap(),
            Outcome::Refused { .. }
        ));
        let now = dir
            .list_signed_transport_destinations_for(&relay_id)
            .await
            .unwrap();
        assert_eq!(
            now[0], s2,
            "I1015: the stored row is still the first epoch-100 row"
        );
        // ... while the exact replay, and a re-signature of the SAME envelope
        // (ML-DSA is randomized, so the signature bytes differ), stay Unchanged.
        assert_eq!(
            dir.put_signed_transport_destination(&s2).await.unwrap(),
            Outcome::Unchanged
        );
        let s2_resig = sign(r2, Some(transit_kex_member(0x77, 0x88))).await;
        assert_eq!(
            dir.put_signed_transport_destination(&s2_resig)
                .await
                .unwrap(),
            Outcome::Unchanged,
            "I1015: same pair, same projection, fresh signature is idempotent"
        );
    }

    /// **The transit KEX resolver matrix** (v56.0.0, CIRISPersist#1078, CC
    /// 3.3.6.2 rc8), run on memory, sqlite and postgres:
    /// [`transit_kex_pair_for`] judged over the rows as held.
    ///
    /// - **I1017** a clean pair on a live Rooted binding resolves to it.
    /// - **I1018** a pair whose x25519 equals the occurrence's content-KEM
    ///   x25519 resolves to `None`; likewise its ML-KEM-768 against the
    ///   content-KEM ML-KEM-768.
    /// - **I1019** a pair whose x25519 equals the OWNER identity's federation
    ///   ed25519 (a key on the occurrence, not in the route row, so admission
    ///   cannot see it) resolves to `None`.
    /// - **I1020** an `Advisory` binding resolves to `None`.
    /// - **I1021** a node with no binding resolves to `None`.
    /// - **I1022** two live Rooted bindings carrying different pairs resolve
    ///   to `None`; a retired binding's pair is never used.
    pub(crate) async fn run_transit_kex_resolver_matrix(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
        use ciris_verify_core::self_at_login::HybridSigningIdentity;
        use ciris_verify_core::transport_binding::produce_signed_identity_occurrence;
        use TransportDestinationApplyOutcome as Outcome;

        let owner_id = format!("tkr-owner-{suffix}");
        let owner = Box::new(HybridSigningIdentity::new(
            &owner_id,
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let owner_member = owner.directory_member().unwrap();
        dir.put_public_key(SignedKeyRecord {
            record: fixture_key(
                &owner_id,
                owner_member.ed25519_public_key_base64.clone(),
                owner_member.mldsa65_public_key_base64.clone(),
            ),
        })
        .await
        .expect("register owner key");

        // One node per scenario: a registered hybrid key, bound as an
        // occurrence of the owner with content-KEM keys from `kem` fills.
        let mut nodes = Vec::new();
        for (tag, kem_x, kem_m) in [
            ("clean", 0xC1u8, 0xC2u8),
            ("kemx", 0xD1, 0xD2),
            ("kemm", 0xE1, 0xE2),
            ("ownerkey", 0xF1, 0xF2),
            ("adv", 0xB1, 0xB2),
            ("none", 0xA1, 0xA2),
            ("two", 0x91, 0x92),
        ] {
            let id = format!("tkr-{tag}-{suffix}");
            let ident = Box::new(HybridSigningIdentity::new(
                &id,
                Ed25519Signer::random().unwrap(),
                MlDsa65Signer::new().unwrap(),
            ));
            let m = ident.directory_member().unwrap();
            dir.put_public_key(SignedKeyRecord {
                record: fixture_key(
                    &id,
                    m.ed25519_public_key_base64.clone(),
                    m.mldsa65_public_key_base64.clone(),
                ),
            })
            .await
            .expect("register node key");
            dir.put_identity_occurrence_local(crate::federation::IdentityOccurrence {
                identity_key_id: owner_id.clone(),
                occurrence_key_id: id.clone(),
                device_class: crate::federation::types::device_class::AGENT.into(),
                hardware_attestation: None,
                asserted_at: ts("2026-10-01T00:00:00Z"),
                valid_until: None,
                encryption_pubkeys: Some(crate::federation::types::EncryptionPubkeys {
                    x25519_base64: B64.encode([kem_x; 32]),
                    ml_kem_768_base64: B64.encode(vec![kem_m; TRANSIT_KEX_ML_KEM_768_LEN]),
                }),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .expect("bind node occurrence");
            nodes.push((tag, id, ident));
        }
        let node = |tag: &str| {
            let (_, id, ident) = nodes.iter().find(|(t, _, _)| *t == tag).unwrap();
            (id.clone(), ident.as_ref())
        };
        async fn put(
            dir: &dyn FederationDirectory,
            ident: &HybridSigningIdentity,
            row: TransportDestination,
            member: Option<serde_json::Value>,
        ) -> Outcome {
            let env = envelope_with_transit_kex(&row, member);
            let (env, sig) = produce_signed_identity_occurrence(ident, env)
                .await
                .unwrap();
            dir.put_signed_transport_destination(&SignedTransportDestination {
                transport_destination: row.clone(),
                attesting_key_id: row.occurrence_key_id.clone(),
                signed_envelope: env,
                signature: sig,
            })
            .await
            .expect("admit route")
        }
        let at = "2026-10-13T00:00:00Z";

        // I1017 — a clean pair resolves.
        let (id, ident) = node("clean");
        put(
            dir,
            ident,
            route(&id, "reticulum", "d", 1, at),
            Some(transit_kex_member(0x01, 0x02)),
        )
        .await;
        let got = transit_kex_pair_for(dir, &id)
            .await
            .unwrap()
            .expect("I1017: clean pair resolves");
        assert_eq!(got.x25519, [0x01; TRANSIT_KEX_X25519_LEN]);

        // I1018 — equal to the occurrence's content-KEM x25519 / ML-KEM-768.
        let (id, ident) = node("kemx");
        assert_eq!(
            put(
                dir,
                ident,
                route(&id, "reticulum", "d", 1, at),
                Some(transit_kex_member(0xD1, 0x03))
            )
            .await,
            Outcome::Inserted,
            "I1018: admission cannot see the occurrence's keys and admits"
        );
        assert_eq!(
            transit_kex_pair_for(dir, &id).await.unwrap(),
            None,
            "I1018: a transit x25519 equal to the content-KEM x25519 is no valid pair"
        );
        let (id, ident) = node("kemm");
        put(
            dir,
            ident,
            route(&id, "reticulum", "d", 1, at),
            Some(transit_kex_member(0x04, 0xE2)),
        )
        .await;
        assert_eq!(
            transit_kex_pair_for(dir, &id).await.unwrap(),
            None,
            "I1018: a transit ML-KEM-768 equal to the content-KEM ML-KEM-768 is no valid pair"
        );

        // I1019 — equal to the owner identity's federation ed25519.
        let (id, ident) = node("ownerkey");
        let mut m = transit_kex_member(0x00, 0x05);
        m[TRANSIT_KEX_X25519_MEMBER] =
            serde_json::Value::String(owner_member.ed25519_public_key_base64.clone());
        put(dir, ident, route(&id, "reticulum", "d", 1, at), Some(m)).await;
        assert_eq!(transit_kex_pair_for(dir, &id).await.unwrap(), None, "I1019");

        // I1020 — an Advisory binding never supplies a hop key.
        let (id, ident) = node("adv");
        let mut r = route(&id, "reticulum", "d", 1, at);
        r.binding_provenance = BindingProvenance::Advisory;
        put(dir, ident, r, Some(transit_kex_member(0x06, 0x07))).await;
        assert_eq!(transit_kex_pair_for(dir, &id).await.unwrap(), None, "I1020");

        // I1021 — no binding at all.
        let (id, _) = node("none");
        assert_eq!(transit_kex_pair_for(dir, &id).await.unwrap(), None, "I1021");
        assert_eq!(
            transit_kex_pair_for(dir, &format!("tkr-unknown-{suffix}"))
                .await
                .unwrap(),
            None,
            "I1021: an unknown node"
        );

        // I1022 — two live Rooted bindings disagree ⇒ None; once one is
        // retired, the other's pair resolves.
        let (id, ident) = node("two");
        put(
            dir,
            ident,
            route(&id, "reticulum", "d", 1, at),
            Some(transit_kex_member(0x08, 0x09)),
        )
        .await;
        put(
            dir,
            ident,
            route(&id, "websocket", "wss://n", 1, at),
            Some(transit_kex_member(0x0A, 0x0B)),
        )
        .await;
        assert_eq!(
            transit_kex_pair_for(dir, &id).await.unwrap(),
            None,
            "I1022: ambiguous"
        );
        let mut retired = route(&id, "websocket", "wss://n", 2, "2026-10-13T01:00:00Z");
        retired.retired_at = Some(ts("2026-10-13T01:00:00Z"));
        put(dir, ident, retired, Some(transit_kex_member(0x0A, 0x0B))).await;
        let got = transit_kex_pair_for(dir, &id)
            .await
            .unwrap()
            .expect("I1022: retired pair ignored");
        assert_eq!(got.x25519, [0x08; TRANSIT_KEX_X25519_LEN]);
    }
}

/// v56.0.0 (CIRISPersist#1077, CC 3.3.6.2 rc8) — the pure transit KEX
/// witnesses: the cross-version hash lockstep KAT, the parser KATs, and the
/// v55-reader tolerance (from bytes and from disk).
#[cfg(test)]
mod transit_kex_tests {
    use super::test_support::{envelope_with_transit_kex, transit_kex_member};
    use super::*;
    use crate::federation::malformed_row as mr;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    /// The v55.0.0 `TransportDestination`, field for field and attribute for
    /// attribute (`self_at_login.rs` at ca6bdf60): the reader an un-upgraded
    /// node runs.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct V55TransportDestination {
        occurrence_key_id: String,
        transport_kind: String,
        destination: String,
        asserted_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_seen_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport_ed25519_pubkey_base64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport_x25519_pubkey_base64: Option<String>,
        #[serde(default)]
        binding_provenance: BindingProvenance,
        #[serde(default)]
        epoch: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retired_at: Option<DateTime<Utc>>,
    }

    /// The v55.0.0 `SignedTransportDestination` wrapper.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct V55SignedTransportDestination {
        transport_destination: V55TransportDestination,
        attesting_key_id: String,
        signed_envelope: serde_json::Value,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature,
    }

    /// The fixed pair-bearing row the KAT pins. The projection is PARSED from
    /// the envelope, as a node builds it, so a projection field that picked
    /// the pair up would show in the bytes.
    fn kat_row() -> SignedTransportDestination {
        let row = TransportDestination {
            occurrence_key_id: "kat-relay".into(),
            transport_kind: "reticulum".into(),
            destination: "kat-dest".into(),
            asserted_at: "2026-10-13T00:00:00Z".parse().unwrap(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: None,
            transport_x25519_pubkey_base64: Some(B64.encode([0x0Au8; 32])),
            binding_provenance: BindingProvenance::Rooted,
            epoch: 7,
            retired_at: None,
        };
        let env = envelope_with_transit_kex(&row, Some(transit_kex_member(0x11, 0x22)));
        let projection: TransportDestination = serde_json::from_value(env.clone()).unwrap();
        SignedTransportDestination {
            transport_destination: projection,
            attesting_key_id: "kat-relay".into(),
            signed_envelope: env,
            signature: ciris_verify_core::transport_binding::TransportBindingSignature {
                ed25519_signature_base64: "ZWQyNTUxOQ==".into(),
                mldsa65_signature_base64: Some("bWxkc2E2NQ==".into()),
            },
        }
    }

    /// The pinned content hash of [`kat_row`] (`sha256(serde_json::to_vec)`,
    /// what `wire_index::content_hash_of` and CIRISEdge's route plane compute).
    /// Recomputed independently from the expected wire bytes (struct-order
    /// projection, sorted-key envelope, compact separators) in Python's
    /// `hashlib`, not read back from this code.
    const KAT_CONTENT_HASH: &str =
        "14da66a0045da51be64ec2fbfb501c57fd8faf745b8320de625b2fee371965e2";

    /// **I1010 (pure, the lockstep KAT).** One pair-bearing row serializes to
    /// the same bytes under the v56 reader and a v55 reader: the projection
    /// carries nothing of the pair, the pair rides only in the envelope (and so
    /// is still hash-covered), and the content hash is pinned. The accessor
    /// returns the pair.
    #[test]
    fn transit_kex_i1010_wrapper_bytes_identical_across_versions() {
        let row = kat_row();
        let bytes = serde_json::to_vec(&row).unwrap();

        // FIRST, the pinned hash: a projection that picked the pair up changes
        // these bytes, and this is the assertion that must say so.
        let h = crate::federation::wire_index::content_hash_of(&row).unwrap();
        assert_eq!(h, KAT_CONTENT_HASH, "I1010: pinned content hash");

        // The projection carries nothing of the pair.
        let proj = serde_json::to_value(&row.transport_destination).unwrap();
        assert!(
            proj.as_object()
                .unwrap()
                .keys()
                .all(|k| !k.contains("transit_kex")),
            "I1010: the typed projection must not serialize the pair: {proj}"
        );
        // The pair is in the wrapper exactly once: inside the envelope.
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(text.matches(TRANSIT_KEX_PUBKEYS_MEMBER).count(), 1);

        // A v55 reader parses the same bytes and re-serializes them unchanged.
        let v55: V55SignedTransportDestination = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&v55).unwrap(), bytes, "I1010: v55 bytes");
        // ... and so does the v56 reader.
        let v56: SignedTransportDestination = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&v56).unwrap(), bytes, "I1010: v56 bytes");
        // A v55 reader that builds its projection FROM the envelope agrees.
        let v55_proj: V55TransportDestination =
            serde_json::from_value(row.signed_envelope.clone()).unwrap();
        assert_eq!(serde_json::to_value(&v55_proj).unwrap(), proj);

        assert_eq!(
            h,
            crate::federation::wire_index::content_hash_of(&v55).unwrap(),
            "I1010: v55 and v56 compute the same content hash"
        );

        // The accessor returns the pair.
        let pair = row.transit_kex_pair().unwrap().unwrap();
        assert_eq!(pair.x25519, [0x11; TRANSIT_KEX_X25519_LEN]);
        assert_eq!(
            &pair.ml_kem_768[..],
            &[0x22u8; TRANSIT_KEX_ML_KEM_768_LEN][..]
        );
        assert_eq!(row.rooted_transit_kex_pair().unwrap(), Some(pair));
        // An Advisory binding never supplies a hop key.
        let mut adv = row.clone();
        adv.transport_destination.binding_provenance = BindingProvenance::Advisory;
        assert_eq!(adv.binding_provenance(), BindingProvenance::Advisory);
        assert_eq!(adv.rooted_transit_kex_pair().unwrap(), None);
        assert!(adv.transit_kex_pair().unwrap().is_some());
    }

    /// **I1012 (pure, the length and both-or-neither KATs).**
    #[test]
    fn transit_kex_i1012_parser_kats() {
        let parse = |m: Option<serde_json::Value>| {
            transit_kex_pair_from_envelope(&match m {
                Some(m) => serde_json::json!({ "destination": "d", TRANSIT_KEX_PUBKEYS_MEMBER: m }),
                None => serde_json::json!({ "destination": "d" }),
            })
        };
        let refused = |m: serde_json::Value, reason: &str, what: &str| {
            let e = parse(Some(m)).expect_err(what);
            super::test_support::expect_route_malformed(&e, reason, what);
        };
        let x = |n: usize| B64.encode(vec![1u8; n]);
        // Neither: the v55 shape.
        assert_eq!(parse(None).unwrap(), None);
        // Both, exact lengths.
        assert!(parse(Some(transit_kex_member(1, 2))).unwrap().is_some());
        // One alone, or neither inside the object.
        refused(
            serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: x(32) }),
            mr::TRANSIT_KEX_HALF_PAIR,
            "x alone",
        );
        refused(
            serde_json::json!({ TRANSIT_KEX_ML_KEM_768_MEMBER: x(1184) }),
            mr::TRANSIT_KEX_HALF_PAIR,
            "ml_kem alone",
        );
        refused(serde_json::json!({}), mr::TRANSIT_KEX_HALF_PAIR, "empty");
        // Exact lengths, each side, both directions.
        for n in [0usize, 31, 33, 64] {
            refused(
                serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: x(n), TRANSIT_KEX_ML_KEM_768_MEMBER: x(1184) }),
                mr::TRANSIT_KEX_WRONG_LENGTH,
                &format!("x25519 {n}"),
            );
        }
        for n in [1183usize, 1185, 1088, 1568] {
            refused(
                serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: x(32), TRANSIT_KEX_ML_KEM_768_MEMBER: x(n) }),
                mr::TRANSIT_KEX_WRONG_LENGTH,
                &format!("ml_kem {n}"),
            );
        }
        // Ill-typed.
        refused(serde_json::Value::Null, mr::ENVELOPE_MEMBER_INVALID, "null");
        refused(
            serde_json::json!("pair"),
            mr::ENVELOPE_MEMBER_INVALID,
            "string",
        );
        refused(
            serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: 5, TRANSIT_KEX_ML_KEM_768_MEMBER: x(1184) }),
            mr::ENVELOPE_MEMBER_INVALID,
            "number",
        );
        refused(
            serde_json::json!({ TRANSIT_KEX_X25519_MEMBER: "!!not base64!!", TRANSIT_KEX_ML_KEM_768_MEMBER: x(1184) }),
            mr::ENVELOPE_MEMBER_INVALID,
            "not base64",
        );
        // Unknown members inside the pair are tolerated (forward-compatible).
        let mut m = transit_kex_member(1, 2);
        m.as_object_mut()
            .unwrap()
            .insert("future".into(), serde_json::json!(1));
        assert!(parse(Some(m)).unwrap().is_some());
        // The three new reasons are in the closed set.
        for r in [
            mr::TRANSIT_KEX_HALF_PAIR,
            mr::TRANSIT_KEX_WRONG_LENGTH,
            mr::TRANSIT_KEX_KEY_REUSE,
        ] {
            assert!(mr::ALL.contains(&r), "{r}");
        }
    }

    /// **I1013 (pure).** A v55-shaped reader admits a pair-bearing envelope:
    /// the typed projection parse tolerates the member, and no container on
    /// this plane says `deny_unknown_fields` (checked from disk, comments
    /// stripped, over the attribute block of each struct).
    #[test]
    fn transit_kex_i1013_v55_reader_tolerates_the_member() {
        let row = kat_row();
        let td: TransportDestination = serde_json::from_value(row.signed_envelope.clone())
            .expect("I1013: the v56 projection parses a pair-bearing envelope");
        assert_eq!(td, row.transport_destination);
        assert_eq!(td.destination, "kat-dest");
        assert_eq!(td.epoch, 7);
        let v55: V55TransportDestination = serde_json::from_value(row.signed_envelope.clone())
            .expect("I1013: the v55 projection parses a pair-bearing envelope");
        assert_eq!(v55.destination, "kat-dest");

        let src = include_str!("self_at_login.rs");
        let lines: Vec<&str> = src.lines().collect();
        for name in [
            "pub struct TransportDestination {",
            "pub struct SignedTransportDestination {",
        ] {
            let at = lines
                .iter()
                .position(|l| l.trim_start() == name)
                .unwrap_or_else(|| panic!("I1013: `{name}` not found on disk"));
            // The contiguous attribute / doc block above the struct.
            let mut i = at;
            while i > 0 {
                let l = lines[i - 1].trim_start();
                if l.starts_with("#[") || l.starts_with("///") || l.starts_with("//") {
                    i -= 1;
                } else {
                    break;
                }
            }
            for l in &lines[i..at] {
                let code = l.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                assert!(
                    !code.contains("deny_unknown_fields"),
                    "I1013: `{name}` must not deny unknown fields (a v55 node must keep \
                     admitting pair-bearing envelopes): {code}"
                );
            }
        }
    }
}
