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
/// steward of `node`". This is the ONE `delegates_to` shape that is
/// single-valued (a node has at most one owner), distinct from the general
/// (multi-parent) grammar [`delegates_to_envelope`] builds.
///
/// v62.0.0 (BIND-1; CC rc22 462260c rule `owner-binding`) — the members it
/// states, and no others: the ownership
/// [`DIMENSION`](super::types::owner_binding::DIMENSION);
/// `delegation_purpose` = [`PURPOSE`](super::types::owner_binding::PURPOSE)
/// (`owner_binding`, the one spelling); `scope` = the caller's `infra:*`
/// tokens as a SET (CC 2.6.1.2: sorted, no repeat). It no longer states
/// `kind`, `delegate_key_id` or `sub_delegation` (not members of the rule;
/// the bound key is the statement's `sub`). The emitter adds `cohort_scope`
/// (always), `author`, `asserted_at`, and the term
/// (`delegation_valid_from` / `delegation_valid_until`, ms-time) where one is
/// stated; a caller adds the placement (`community_id` / `family_id`) or
/// `on_behalf_of` where it means one.
pub fn owner_binding_delegates_to_envelope(infra_scopes: &[String]) -> serde_json::Value {
    use super::types::owner_binding;
    serde_json::json!({
        "dimension": owner_binding::DIMENSION,
        "delegation_purpose": owner_binding::PURPOSE,
        "scope": scope_set(infra_scopes),
    })
}

/// v62.0.0 (BIND-3; CC 3.2, CC 5.4.6; Constitution's ruling on the login
/// placement, P/FREEZE.md) — **which producer states a node's owner binding.**
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerBindingProducer {
    /// A person's device at login, the owner's pen in the process
    /// (`Engine::steward_bind` / `grant_delegation(.., Some(owner_binding))`):
    /// the placement the owner CHOSE at first setup, `self` where the owner
    /// chose nothing. It never writes `federation` on its own.
    Login,
    /// A serve seat (the ceremony; `Engine::owner_binding_draft`,
    /// [`owner_binding_draft_envelope`]): `federation`, always. A seat must
    /// have an announced owner, else `serve_seat_owner_unannounced`.
    ServeSeat,
}

/// v62.0.0 (BIND-3) — the placement an owner chose for a node's binding: a
/// scope, and the group it names where the scope is a group's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChosenPlacement {
    /// The `cohort_scope` the owner chose.
    pub scope: String,
    /// The room (`community` / `affiliations`) or family (`family`) the
    /// binding is placed at; `None` at `self` / `federation`.
    pub group: Option<String>,
}

/// v62.0.0 (BIND-3) — **where a node's owner binding rows go**: the first
/// row's scope (and group), and whether the owner announces (a SECOND row at
/// `federation`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerBindingPlacement {
    /// The first row's `cohort_scope`.
    pub scope: String,
    /// The first row's group (`community_id` for `community` /
    /// `affiliations`, `family_id` for `family`).
    pub group: Option<String>,
    /// The owner announces: a further row at `federation`.
    pub announce: bool,
}

impl OwnerBindingPlacement {
    /// The placement member the first row names its group under, if any.
    #[must_use]
    pub fn group_member(&self) -> Option<&'static str> {
        use super::types::cohort_scope as cs;
        match self.scope.as_str() {
            cs::COMMUNITY | cs::AFFILIATIONS => Some("community_id"),
            cs::FAMILY => Some("family_id"),
            _ => None,
        }
    }

    /// The announcing row: `federation`, no group.
    #[must_use]
    pub fn federation() -> Self {
        Self {
            scope: super::types::cohort_scope::FEDERATION.to_owned(),
            group: None,
            announce: false,
        }
    }
}

/// v62.0.0 (BIND-3; Constitution's ruling on the login placement: "the LOGIN
/// producer writes the placement the owner chose at first setup, and `self`
/// where the owner chose nothing. It NEVER writes `federation` on its own.
/// Owner chose to announce ⇒ the self-or-first row PLUS the federation row,
/// by that choice. The SERVE-SEAT producer ⇒ federation") — **the ONE place a
/// node owner binding's placement is chosen**, by `producer` and the owner's
/// `chosen` placement:
///
/// | producer | chosen | rows |
/// |---|---|---|
/// | `Login` | none | `self` |
/// | `Login` | `federation` | `self`, then `federation` (announce) |
/// | `Login` | `community` / `affiliations` / `family` + group | that group |
/// | `Login` | `self` | `self` |
/// | `ServeSeat` | none or `federation` | `federation` |
///
/// # Errors
/// `InvalidArgument` (`owner_binding_placement_refused`): a seat given any
/// other scope; a group scope with no group, or a group at a scope that names
/// none; a commons scope other than `federation` (`species`, `biosphere`: no
/// owner binding is placed there).
pub fn node_owner_binding_placement(
    producer: OwnerBindingProducer,
    chosen: Option<&ChosenPlacement>,
) -> Result<OwnerBindingPlacement, super::Error> {
    use super::types::cohort_scope as cs;
    let refused = |why: String| {
        super::Error::InvalidArgument(format!("owner_binding_placement_refused: {why}"))
    };
    match producer {
        OwnerBindingProducer::ServeSeat => match chosen {
            None => Ok(OwnerBindingPlacement::federation()),
            Some(c) if c.scope == cs::FEDERATION && c.group.is_none() => {
                Ok(OwnerBindingPlacement::federation())
            }
            Some(c) => Err(refused(format!(
                "a serve seat's owner binding is placed at federation, not {:?} (CC 5.4.6)",
                c.scope
            ))),
        },
        OwnerBindingProducer::Login => {
            let Some(c) = chosen else {
                return Ok(OwnerBindingPlacement {
                    scope: cs::SELF.to_owned(),
                    group: None,
                    announce: false,
                });
            };
            let plan = match c.scope.as_str() {
                cs::SELF => OwnerBindingPlacement {
                    scope: cs::SELF.to_owned(),
                    group: None,
                    announce: false,
                },
                cs::FEDERATION => OwnerBindingPlacement {
                    scope: cs::SELF.to_owned(),
                    group: None,
                    announce: true,
                },
                cs::COMMUNITY | cs::AFFILIATIONS | cs::FAMILY => OwnerBindingPlacement {
                    scope: c.scope.clone(),
                    group: c.group.clone(),
                    announce: false,
                },
                other => return Err(refused(format!("no owner binding is placed at {other:?}"))),
            };
            if plan.group_member().is_some() != c.group.is_some() {
                return Err(refused(format!(
                    "a placement at {:?} names a group exactly when the scope is a group's \
                     (got {:?})",
                    c.scope, c.group
                )));
            }
            Ok(plan)
        }
    }
}

/// v62.0.0 (BIND-1; CC 2.6.1.2) — `scopes` as a set: sorted by the bytewise
/// order of their deterministic encodings (so a shorter text first), without
/// repeats.
#[must_use]
pub fn scope_set(scopes: &[String]) -> Vec<String> {
    let set: std::collections::BTreeSet<&str> = scopes.iter().map(String::as_str).collect();
    let mut v: Vec<String> = set.into_iter().map(str::to_owned).collect();
    v.sort_by_cached_key(|s| {
        ciris_verify_core::cde::encode(&ciris_verify_core::cde::Value::Text(s.clone()))
    });
    v
}

/// v62.0.0 (KR-fix11; CC 3.2 "the first binding", CC 3.1.3.2: a serve seat's
/// owner binding is carried at `federation`) — **the owner binding's envelope
/// for a signer whose pen is elsewhere** (the operator's own person key, held
/// on hardware): exactly the members the software producer states
/// (`Engine::steward_bind(.., Some(owner_binding::PURPOSE))`:
/// [`owner_binding_delegates_to_envelope`] through `EnvelopeCore`), placed
/// by the SERVE-SEAT producer at `cohort_scope: federation` (v62.0.0 BIND-3,
/// [`node_owner_binding_placement`]; the login producer places at `self`
/// unless its owner chose). Hand it to
/// `Engine::statement_draft("delegates_to", &envelope, owner_iss,
/// owner_kid_hex, node_key_id, asserted_at_ms, None)`, or call
/// `Engine::owner_binding_draft`, which does. Both producers then state the
/// row through `emit::row_payload`.
///
/// `infra_scopes` is the CALLER's list (persist fixes none): `infra:*` tokens
/// only, e.g. `infra:serve`, `infra:network_presence`, `infra:attest`.
///
/// # Errors
/// `InvalidArgument`: no scope, or a token outside `infra:*`.
pub fn owner_binding_draft_envelope(
    _node_key_id: &str,
    infra_scopes: &[String],
) -> Result<serde_json::Value, super::Error> {
    let set: std::collections::HashSet<String> = infra_scopes.iter().cloned().collect();
    if infra_scopes.is_empty() || !super::admission::scopes_are_infra_only(&set) {
        return Err(super::Error::InvalidArgument(format!(
            "owner binding: its scope is infra:* tokens only, and at least one; got \
             {infra_scopes:?}"
        )));
    }
    let mut envelope = super::envelope::EnvelopeCore::from_value(
        owner_binding_delegates_to_envelope(infra_scopes),
    )?
    .to_value();
    // v62.0.0 (BIND-3) — the serve-seat producer: federation, always.
    let placement = node_owner_binding_placement(OwnerBindingProducer::ServeSeat, None)?;
    if let Some(o) = envelope.as_object_mut() {
        o.insert(
            "cohort_scope".into(),
            serde_json::Value::String(placement.scope),
        );
        o.retain(|_, v| !v.is_null());
    }
    Ok(envelope)
}

/// v62.0.0 (KR-fix11) — **the self-check a ceremony tool runs on a signed
/// owner binding before it submits it** (pure: no store). The statement is a
/// `delegates_to` of the ownership family, `sub` = `node_key_id`, AUTHORED by
/// its signer (`author` = `iss` = `owner_iss`), on the owner-binding
/// dimension, placed at `cohort_scope: federation`, and its `scope` is
/// `infra:*` only and carries every token of `required_scopes`.
///
/// It does not verify the signature (the door does) and does not know
/// whether the node has voiced it.
///
/// # Errors
/// `InvalidArgument` naming the first thing that is wrong.
pub fn check_owner_binding_statement(
    statement: &[u8],
    owner_iss: &str,
    node_key_id: &str,
    required_scopes: &[&str],
) -> Result<(), super::Error> {
    owner_binding_shape(statement, owner_iss, node_key_id, required_scopes)
        .map_err(|f| super::Error::InvalidArgument(format!("owner binding: {f}")))
}

/// v62.0.0 (KR-fix12) — **what is wrong with a signed owner binding**, by
/// name, so a ceremony tool can print which check failed
/// ([`OwnerBindingFault::token`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerBindingFault {
    /// The bytes are not a row statement.
    NotAStatement,
    /// Not a `delegates_to` of the ownership family on the owner-binding
    /// dimension.
    NotAnOwnerBinding(String),
    /// The signature does not verify under the owner's key (Verify's label:
    /// `bad_signature`, `kid_mismatch`, `malformed:…`, ...). A wrong key or a
    /// truncated signature from the signing step lands here.
    SignatureInvalid(String),
    /// The owner's key is not held, or not live at the statement's instant
    /// (the Engine form only).
    OwnerKeyNotLive(String),
    /// `iss` / `author` is not the expected owner.
    OwnerMismatch,
    /// The owner's key is not a person's (`user`): a `node` or `agent` key
    /// owns nothing, and the owner folds would ignore the row for ever.
    OwnerNotAPerson(String),
    /// `sub` is not the node.
    NodeMismatch,
    /// Not placed at `cohort_scope: federation`.
    NotAtFederation,
    /// A scope token outside `infra:*`, or no scope.
    ScopeNotInfra(String),
    /// A required scope is missing.
    ScopeMissing(String),
}

impl OwnerBindingFault {
    /// The fault's stable name.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::NotAStatement => "owner_binding_not_a_statement",
            Self::NotAnOwnerBinding(_) => "owner_binding_wrong_row",
            Self::SignatureInvalid(_) => "owner_binding_signature_invalid",
            Self::OwnerKeyNotLive(_) => "owner_binding_owner_key_not_live",
            Self::OwnerMismatch => "owner_binding_owner_mismatch",
            Self::OwnerNotAPerson(_) => super::admission::OWNER_BINDING_OWNER_NOT_A_PERSON,
            Self::NodeMismatch => "owner_binding_node_mismatch",
            Self::NotAtFederation => "owner_binding_not_at_federation",
            Self::ScopeNotInfra(_) => "owner_binding_scope_not_infra",
            Self::ScopeMissing(_) => "owner_binding_scope_missing",
        }
    }
}

impl std::fmt::Display for OwnerBindingFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = match self {
            Self::NotAStatement
            | Self::OwnerMismatch
            | Self::NodeMismatch
            | Self::NotAtFederation => "",
            Self::NotAnOwnerBinding(d)
            | Self::SignatureInvalid(d)
            | Self::OwnerKeyNotLive(d)
            | Self::OwnerNotAPerson(d)
            | Self::ScopeNotInfra(d)
            | Self::ScopeMissing(d) => d.as_str(),
        };
        if detail.is_empty() {
            f.write_str(self.token())
        } else {
            write!(f, "{}: {detail}", self.token())
        }
    }
}

/// The shape checks of an owner binding (no key, no store).
fn owner_binding_shape(
    statement: &[u8],
    owner_iss: &str,
    node_key_id: &str,
    required_scopes: &[&str],
) -> Result<(), OwnerBindingFault> {
    use ciris_verify_core::cde::Value;
    use OwnerBindingFault as F;
    let (family, row_type) =
        super::edition2::emit::family_of_statement(statement).ok_or(F::NotAStatement)?;
    if row_type != super::types::attestation_type::DELEGATES_TO {
        return Err(F::NotAnOwnerBinding(format!(
            "row type {row_type:?}, not delegates_to"
        )));
    }
    if super::edition2::emit::family_of_dimension(super::types::owner_binding::DIMENSION).as_deref()
        != Some(family.as_str())
    {
        return Err(F::NotAnOwnerBinding(format!(
            "family {family:?} is not the ownership family"
        )));
    }
    let (protected, payload) =
        super::edition2::liveness::statement_parts(statement).ok_or(F::NotAStatement)?;
    let claim = |n: i64| {
        protected
            .get_int(15)
            .and_then(|c| c.get_int(n))
            .and_then(Value::as_text)
    };
    let text = |k: &str| payload.get_text(k).and_then(Value::as_text);
    if text("dimension") != Some(super::types::owner_binding::DIMENSION) {
        return Err(F::NotAnOwnerBinding(
            "its dimension is not the owner binding's".into(),
        ));
    }
    if claim(1) != Some(owner_iss) || text("author") != Some(owner_iss) {
        return Err(F::OwnerMismatch);
    }
    if claim(2) != Some(node_key_id) {
        return Err(F::NodeMismatch);
    }
    if text("cohort_scope") != Some(super::types::cohort_scope::FEDERATION) {
        return Err(F::NotAtFederation);
    }
    let scope: Vec<&str> = payload
        .get_text("scope")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_text).collect())
        .unwrap_or_default();
    if scope.is_empty() || scope.iter().any(|t| !t.starts_with("infra:")) {
        return Err(F::ScopeNotInfra(format!("{scope:?}")));
    }
    if let Some(missing) = required_scopes.iter().find(|t| !scope.contains(t)) {
        return Err(F::ScopeMissing((*missing).to_owned()));
    }
    Ok(())
}

/// v62.0.0 (KR-fix12) — **THE self-check a ceremony tool runs on a signed
/// owner binding before it submits it, signature included.** Pure: no store,
/// no clock (the instant is the statement's own).
///
/// 1. the statement VERIFIES under `owner_key`, the owner's public key the
///    caller supplies (Verify's `verify_row_statement` over a directory
///    holding that one key): a signature made with another key, or cut short
///    by the signing step, is [`OwnerBindingFault::SignatureInvalid`];
/// 2. `owner_identity_type` (the owner's key record's `identity_type`, as the
///    caller knows it) names `user`: an owner binding signed by a `node` or
///    `agent` key is [`OwnerBindingFault::OwnerNotAPerson`]. The folds ignore
///    such a row silently (`owner_of` stays `None`, nothing ever lands);
/// 3. the shape: a `delegates_to` of the ownership family on the owner-binding
///    dimension, authored by the owner (the identity-ref of `owner_key`),
///    `sub` = `node_key_id`, at `cohort_scope: federation`, `scope` `infra:*`
///    only and carrying every token of `required_scopes`.
///
/// It does not know whether the key is LIVE on a given node (its window, a
/// revocation): `Engine::check_owner_binding` asks that node's key plane.
///
/// # Errors
/// The first [`OwnerBindingFault`].
pub fn verify_owner_binding_statement(
    statement: &[u8],
    owner_key: &ciris_crypto::composite::CompositePublicKey,
    owner_identity_type: &str,
    node_key_id: &str,
    required_scopes: &[&str],
) -> Result<(), OwnerBindingFault> {
    use super::edition2::self_check::{verify_statement_signature, SignerKey, StatementFault};
    use OwnerBindingFault as F;
    let kid = ciris_verify_core::edition2::thumbprint(owner_key);
    let owner_iss = ciris_verify_core::edition2::identity_ref(&kid);
    // KR-fix14 — the ONE signature self-check, shared with the root
    // acceptance's and the generic one.
    match verify_statement_signature(statement, SignerKey::PublicKey(owner_key)) {
        Ok(()) => {}
        Err(StatementFault::NotAStatement) => return Err(F::NotAStatement),
        Err(f) => return Err(F::SignatureInvalid(f.to_string())),
    }
    owner_is_a_person(owner_identity_type)?;
    owner_binding_shape(statement, &owner_iss, node_key_id, required_scopes)
}

/// An owner is a PERSON: its key record names `user`.
fn owner_is_a_person(identity_type: &str) -> Result<(), OwnerBindingFault> {
    use super::types::identity_type as it;
    if it::set_contains(identity_type, it::USER) {
        Ok(())
    } else {
        Err(OwnerBindingFault::OwnerNotAPerson(format!(
            "the owner's key is typed {identity_type:?}, not user"
        )))
    }
}

/// v62.0.0 (KR-fix12) — [`verify_owner_binding_statement`] against a NODE's
/// own key plane (`Engine::check_owner_binding`): the owner's key is the one
/// this directory holds for the statement's `iss`, LIVE at the statement's
/// instant, and its held record names `user`. `Ok(None)`: nothing is wrong.
///
/// The signature and the key's liveness are Verify's `verify_row_statement`
/// over the keys this node holds for the signer
/// (`edition2::ingest::held_keys_for`): the key plane the door reads, with
/// its windows and revocations. It is NOT `door::admit_row`: the family's
/// rules (authorship, second signers) and the admission gates are the door's
/// own and are not run here; the shape this check needs is
/// `owner_binding_shape`'s. (The pure forms go through
/// `edition2::self_check::verify_statement_signature`; this one differs only
/// in where the key comes from.)
///
/// # Errors
/// Directory reads.
pub async fn check_owner_binding_held<F>(
    directory: &F,
    statement: &[u8],
    node_key_id: &str,
    required_scopes: &[&str],
) -> Result<Option<OwnerBindingFault>, super::Error>
where
    F: super::FederationDirectory + ?Sized,
{
    use ciris_verify_core::cde::Value;
    use ciris_verify_core::edition2::{verify_row_statement, Verdict};
    use OwnerBindingFault as Fault;
    let Some((protected, _)) = super::edition2::liveness::statement_parts(statement) else {
        return Ok(Some(Fault::NotAStatement));
    };
    let Some(owner_iss) = protected
        .get_int(15)
        .and_then(|c| c.get_int(1))
        .and_then(Value::as_text)
        .map(str::to_owned)
    else {
        return Ok(Some(Fault::NotAStatement));
    };
    let keys = super::edition2::ingest::held_keys_for(directory, statement).await?;
    match verify_row_statement(statement, &keys) {
        Verdict::Valid(_) => {}
        Verdict::Invalid(i) => {
            return Ok(Some(Fault::SignatureInvalid(
                super::edition2::door::invalid_label(&i),
            )))
        }
        Verdict::Waiting { .. } => {
            return Ok(Some(Fault::OwnerKeyNotLive(format!(
                "this node holds no live key record for {owner_iss} at the statement's instant"
            ))))
        }
    }
    let Some(record) = directory.lookup_public_key(&owner_iss).await? else {
        return Ok(Some(Fault::OwnerKeyNotLive(format!(
            "this node holds no key record for {owner_iss}"
        ))));
    };
    if let Err(f) = owner_is_a_person(&record.identity_type) {
        return Ok(Some(f));
    }
    Ok(owner_binding_shape(statement, &owner_iss, node_key_id, required_scopes).err())
}

/// v61 (CIRISPersist#1126; CC 4.4.3.4.3.1, CC 3.3.5) — a partnership
/// half is a **`consent_record`** row: `subject_kind: "consent_record"`, the
/// `stance`, the singular `subject_key_id` naming the PARTNER (the agent
/// occurrence on the grant, the user identity on the accept), the shared
/// `bilateral_pair_id`, and the claim's own `asserted_at` in the CC 2.6.2
/// form. No `valid_until`: a PARTNERED pair has no expiry. `stance: "revoked"`
/// on the same dimension ends the partnership (a revoked `consent_record`
/// transits the local tier and never rests there, CC 10.1.3).
///
/// Wire shape (sorted-keys when canonicalized):
///
/// ```json
/// {
///   "asserted_at": "2026-11-01T12:00:00.000Z",
///   "bilateral_pair_id": "<shared pair id>",
///   "dimension": "consent:partnership_grant:v1",
///   "stance": "granted",
///   "subject_key_id": "<the partner>",
///   "subject_kind": "consent_record"
/// }
/// ```
///
/// Pre-v61 halves were bare `scores` (`kind`, `partner_occurrence_key_id`, no
/// `stance`); that shape is refused at admission
/// ([`PARTNERSHIP_SHAPE_RETIRED_REASON`]).
pub fn partnership_envelope(
    dimension: &str,
    partner_key_id: &str,
    bilateral_pair_id: &str,
    stance: &str,
    asserted_at: DateTime<Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "dimension": dimension,
        "subject_kind": crate::federation::types::consent_record::SUBJECT_KIND,
        "stance": stance,
        "subject_key_id": partner_key_id,
        "bilateral_pair_id": bilateral_pair_id,
        "asserted_at": crate::federation::admission::render_signed_instant(asserted_at),
    })
}

/// v6.5.0 (CEG §8.1.12.7) — the user-side `consent:partnership_grant`
/// half: "I (user) partner with this agent occurrence", keyed by a shared
/// `bilateral_pair_id`. v61: a `consent_record`
/// ([`partnership_envelope`], `stance: granted`).
pub fn partnership_grant_envelope(
    partner_occurrence_key_id: &str,
    bilateral_pair_id: &str,
    asserted_at: DateTime<Utc>,
) -> serde_json::Value {
    partnership_envelope(
        DIMENSION_PARTNERSHIP_GRANT,
        partner_occurrence_key_id,
        bilateral_pair_id,
        crate::federation::types::consent_record::stance::GRANTED,
        asserted_at,
    )
}

/// v6.5.0 (CEG §8.1.12.7) — the agent-side `consent:partnership_accept`
/// half: "I (agent occurrence) accept the partnership offered under this
/// `bilateral_pair_id`"; the partner is the user identity. v61: a
/// `consent_record` ([`partnership_envelope`], `stance: granted`).
pub fn partnership_accept_envelope(
    partner_identity_key_id: &str,
    bilateral_pair_id: &str,
    asserted_at: DateTime<Utc>,
) -> serde_json::Value {
    partnership_envelope(
        DIMENSION_PARTNERSHIP_ACCEPT,
        partner_identity_key_id,
        bilateral_pair_id,
        crate::federation::types::consent_record::stance::GRANTED,
        asserted_at,
    )
}

/// v61 (CIRISPersist#1126) — the reason a pre-v61 bare-`scores`
/// partnership half carries at admission: a `consent:partnership_grant` /
/// `consent:partnership_accept` row that is not a `consent_record`.
pub const PARTNERSHIP_SHAPE_RETIRED_REASON: &str = "partnership_shape_retired";

/// v61 (CIRISPersist#1126, CC 4.4.3.4.3.1) — **a partnership half is a
/// `consent_record`.** A `scores` row on `consent:partnership_grant` or
/// `consent:partnership_accept` without `subject_kind: "consent_record"` is
/// the retired bare shape, refused at every door a row enters by (the
/// federation put and the local write). A `withdraws` or `recants` naming a
/// half's dimension is not a half and passes; the `consent_record` gate
/// ([`check_consent_record_admission`](crate::federation::admission::check_consent_record_admission))
/// then asks the record's own rules.
///
/// # Errors
/// [`Error::DimensionRejected`](crate::federation::Error::DimensionRejected)
/// with [`PARTNERSHIP_SHAPE_RETIRED_REASON`].
pub fn check_partnership_shape(
    attestation_type: &str,
    envelope: &serde_json::Value,
) -> Result<(), crate::federation::Error> {
    let Some(dimension) = crate::federation::admission::envelope_dimension(envelope) else {
        return Ok(());
    };
    let is_half = ["consent:partnership_grant:", "consent:partnership_accept:"]
        .iter()
        .any(|p| dimension.starts_with(p));
    if !is_half || attestation_type != crate::federation::types::attestation_type::SCORES {
        return Ok(());
    }
    if crate::federation::admission::envelope_subject_kind(envelope)
        == Some(crate::federation::types::consent_record::SUBJECT_KIND)
    {
        return Ok(());
    }
    Err(crate::federation::Error::DimensionRejected {
        dimension: dimension.to_owned(),
        reason: PARTNERSHIP_SHAPE_RETIRED_REASON,
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
    /// When the address was (re)asserted. A signed member: serialized in the
    /// CC 2.6.2 form `.sssZ` (v61).
    #[serde(with = "crate::federation::admission::signed_instant_serde")]
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::federation::admission::signed_instant_serde::option"
    )]
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
    pub signature: crate::federation::types::RetiredPairSignature,
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

impl TransitKexPair {
    /// v62.0.0 (ceremony gap 3, item 3; CC 3.3.6.2) — **the pair an X-Wing
    /// transit key carries**: X-Wing is `pk_M ‖ pk_X`, so its ML-KEM-768
    /// encapsulation key is bytes `0..1184` and its X25519 key bytes
    /// `1184..1216`. An edition-2 seat or bound node publishes only the
    /// X-Wing form (`transit_xwing_pubkey`); this is the same key, read as
    /// the two-member pair a hop key consumer takes.
    #[must_use]
    pub fn from_xwing(key: &XWingPublicKey) -> Self {
        let mut x25519 = [0u8; TRANSIT_KEX_X25519_LEN];
        x25519.copy_from_slice(key.x25519());
        let mut ml_kem_768 = Box::new([0u8; TRANSIT_KEX_ML_KEM_768_LEN]);
        ml_kem_768.copy_from_slice(key.ml_kem_768());
        Self { x25519, ml_kem_768 }
    }
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
    pub(crate) fn all(&self) -> impl Iterator<Item = &[u8]> {
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

/// v56.0.0 (CIRISPersist#1077); v62.0.0 (CC rc20 3.3.6.2, #1274) — do two
/// signed envelopes carry the same ENVELOPE-ONLY key members (each absent, or
/// byte-equal JSON): `transit_kex_pubkeys`, `transit_xwing_pubkey` and
/// `onion_hop_xwing_pubkey`? The backends' `put_signed_transport_destination`
/// ask this before answering `Unchanged`: the keys are envelope-only, so an
/// equal typed projection at an equal `(epoch, asserted_at)` does not mean
/// equal content. A same-clock re-sign that changes any of them is a fork and
/// is `Refused`, never kept silently as the old key. (Was
/// `same_transit_kex_member`, which compared the pair alone.)
#[must_use]
pub fn same_envelope_key_members(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    ENVELOPE_KEY_MEMBERS.iter().all(|m| a.get(m) == b.get(m))
}

/// v62.0.0 — every envelope-only key member of a transport destination.
pub const ENVELOPE_KEY_MEMBERS: [&str; 3] = [
    TRANSIT_KEX_PUBKEYS_MEMBER,
    TRANSIT_XWING_PUBKEY_MEMBER,
    ONION_HOP_XWING_PUBKEY_MEMBER,
];

// ─── X-Wing transport keys (CC rc20 3.3.6.2 / 5.3.3.10 / 5.4.6) ─────────

/// v62.0.0 (CC rc20 3.3.6.2, CIRISPersist#1274) — the relay's **X-Wing transit
/// public key**, beside the earlier-form [`TRANSIT_KEX_PUBKEYS_MEMBER`] pair:
/// "exactly 1216 bytes, the X-Wing public key `pk_M ‖ pk_X`, the ML-KEM-768
/// encapsulation key of 1184 bytes then the X25519 key of 32 bytes." On
/// today's JSON wire it is the standard base64 of those bytes. Envelope-only,
/// like the pair. Read it with [`SignedTransportDestination::transit_xwing_pubkey`];
/// resolve a peer's with [`transit_xwing_pubkey_for`], which applies the
/// seated-serve-node rule.
pub const TRANSIT_XWING_PUBKEY_MEMBER: &str = "transit_xwing_pubkey";
/// v62.0.0 (CC rc20 3.3.6.2 "The onion hop key", CC 5.4.6) — the node's static
/// **X-Wing onion hop public key**, 1216 bytes, standard base64 on the JSON
/// wire. It replaces the earlier form's two-member `onion_hop_pubkeys` (CC
/// 8.11.20), which persist never read, admitted or served (CIRISPersist#1181
/// was open; CIRISEdge's hop tier ran on the transit-pair stand-in), so there
/// is no stored old form to keep reading. Envelope-only: "It lives in the
/// signed envelope only, never in a typed column".
pub const ONION_HOP_XWING_PUBKEY_MEMBER: &str = "onion_hop_xwing_pubkey";
/// The X-Wing public key's exact raw length (`pk_M ‖ pk_X`).
pub const XWING_PUBKEY_LEN: usize = 1216;
/// Bytes `0..1184` of an X-Wing public key: the ML-KEM-768 encapsulation key.
pub const XWING_ML_KEM_768_LEN: usize = 1184;
/// Bytes `1184..1216` of an X-Wing public key: the X25519 key.
pub const XWING_X25519_LEN: usize = 32;

/// v62.0.0 — a decoded X-Wing public key; the length is in the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XWingPublicKey(Box<[u8; XWING_PUBKEY_LEN]>);

impl XWingPublicKey {
    /// From exactly 1216 raw bytes; `None` for any other length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Box::<[u8; XWING_PUBKEY_LEN]>::try_from(bytes.to_vec().into_boxed_slice())
            .ok()
            .map(Self)
    }
    /// The whole key, `pk_M ‖ pk_X`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; XWING_PUBKEY_LEN] {
        &self.0
    }
    /// `pk_M`, bytes `0..1184`.
    #[must_use]
    pub fn ml_kem_768(&self) -> &[u8] {
        &self.0[..XWING_ML_KEM_768_LEN]
    }
    /// `pk_X`, bytes `1184..1216`.
    #[must_use]
    pub fn x25519(&self) -> &[u8] {
        &self.0[XWING_ML_KEM_768_LEN..]
    }
}

/// v62.0.0 — THE one reading of an X-Wing member (`member` is
/// [`TRANSIT_XWING_PUBKEY_MEMBER`] or [`ONION_HOP_XWING_PUBKEY_MEMBER`]) from a
/// signed transport-destination envelope; admission and the accessors both
/// call it.
///
/// - absent ⇒ `Ok(None)`;
/// - not a string (an explicit `null` included), or not standard base64 ⇒
///   [`malformed_row::ENVELOPE_MEMBER_INVALID`](crate::federation::malformed_row::ENVELOPE_MEMBER_INVALID);
/// - anything but exactly 1216 bytes ⇒
///   [`malformed_row::XWING_PUBKEY_WRONG_LENGTH`](crate::federation::malformed_row::XWING_PUBKEY_WRONG_LENGTH).
///
/// # Errors
///
/// [`crate::federation::Error::MalformedRow`] on plane `transport_destination`.
pub fn xwing_pubkey_from_envelope(
    envelope: &serde_json::Value,
    member: &'static str,
) -> Result<Option<XWingPublicKey>, crate::federation::Error> {
    use crate::federation::{malformed_row, Error};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    const PLANE: &str = "transport_destination";
    let Some(v) = envelope.get(member) else {
        return Ok(None);
    };
    let s = v.as_str().ok_or_else(|| {
        Error::malformed_row(
            PLANE,
            malformed_row::ENVELOPE_MEMBER_INVALID,
            format!("`{member}` must be a standard-base64 string (CC 3.3.6.2), got {v}"),
        )
    })?;
    let raw = B64.decode(s).map_err(|e| {
        Error::malformed_row(
            PLANE,
            malformed_row::ENVELOPE_MEMBER_INVALID,
            format!("`{member}` is not standard base64: {e}"),
        )
    })?;
    XWingPublicKey::from_bytes(&raw).map(Some).ok_or_else(|| {
        Error::malformed_row(
            PLANE,
            malformed_row::XWING_PUBKEY_WRONG_LENGTH,
            format!(
                "`{member}` must decode to exactly {XWING_PUBKEY_LEN} bytes (pk_M 1184 ‖ pk_X 32, \
                 CC 3.3.6.2), got {}",
                raw.len()
            ),
        )
    })
}

/// v62.0.0 — which X-Wing key a reuse check is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XWingKeyRole {
    /// [`TRANSIT_XWING_PUBKEY_MEMBER`].
    Transit,
    /// [`ONION_HOP_XWING_PUBKEY_MEMBER`].
    OnionHop,
}

/// v62.0.0 (CC rc20 3.3.6.2) — why an X-Wing key fails the per-half reuse
/// rule. "The reuse refusals read the key's halves, bytes 0..1184 and bytes
/// 1184..1216."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XWingReuseRefusal {
    /// The transit key's ML-KEM-768 half is another key on the row.
    TransitMlKem768Reuse,
    /// The transit key's X25519 half is another key on the row.
    TransitX25519Reuse,
    /// The hop key's ML-KEM-768 half is another key on the row.
    OnionHopMlKem768Reuse,
    /// The hop key's X25519 half is another key on the row.
    OnionHopX25519Reuse,
}

impl XWingReuseRefusal {
    /// The stable token (the [`crate::federation::malformed_row`] reason).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        use crate::federation::malformed_row as mr;
        match self {
            Self::TransitMlKem768Reuse => mr::TRANSIT_XWING_ML_KEM_768_REUSE,
            Self::TransitX25519Reuse => mr::TRANSIT_XWING_X25519_REUSE,
            Self::OnionHopMlKem768Reuse => mr::ONION_HOP_ML_KEM_768_REUSE,
            Self::OnionHopX25519Reuse => mr::ONION_HOP_X25519_REUSE,
        }
    }
}

/// v62.0.0 (CC rc20 3.3.6.2) — **the per-half reuse rule, pure.** Each half of
/// `key` (`0..1184`, `1184..1216`) must not be byte-equal to any of `others`
/// (raw keys, and halves of other X-Wing keys, as the caller gathers them).
/// The ML-KEM half is checked first.
///
/// # Errors
///
/// The first [`XWingReuseRefusal`] found.
pub fn check_xwing_halves<'a>(
    role: XWingKeyRole,
    key: &XWingPublicKey,
    others: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), XWingReuseRefusal> {
    let (m, x) = match role {
        XWingKeyRole::Transit => (
            XWingReuseRefusal::TransitMlKem768Reuse,
            XWingReuseRefusal::TransitX25519Reuse,
        ),
        XWingKeyRole::OnionHop => (
            XWingReuseRefusal::OnionHopMlKem768Reuse,
            XWingReuseRefusal::OnionHopX25519Reuse,
        ),
    };
    let others: Vec<&[u8]> = others.into_iter().collect();
    if others.iter().any(|k| *k == key.ml_kem_768()) {
        return Err(m);
    }
    if others.iter().any(|k| *k == key.x25519()) {
        return Err(x);
    }
    Ok(())
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

    /// v62.0.0 (CC rc20 3.3.6.2, #1274) — this row's `transit_xwing_pubkey`,
    /// as signed (one row's envelope, nothing more).
    ///
    /// **Consumer rule:** this raw read does NOT say the key is LIVE. A seated
    /// serve node's X-Wing transit key is live only when an admitted
    /// `transport:canonical_rebind` carries exactly this row; resolve a peer's
    /// key with [`transit_xwing_pubkey_for`], never with this.
    ///
    /// # Errors
    ///
    /// As [`xwing_pubkey_from_envelope`].
    pub fn transit_xwing_pubkey(&self) -> Result<Option<XWingPublicKey>, crate::federation::Error> {
        xwing_pubkey_from_envelope(&self.signed_envelope, TRANSIT_XWING_PUBKEY_MEMBER)
    }

    /// v62.0.0 (CC rc20 3.3.6.2, CC 5.4.6) — this row's
    /// `onion_hop_xwing_pubkey`, as signed.
    ///
    /// # Errors
    ///
    /// As [`xwing_pubkey_from_envelope`].
    pub fn onion_hop_xwing_pubkey(
        &self,
    ) -> Result<Option<XWingPublicKey>, crate::federation::Error> {
        xwing_pubkey_from_envelope(&self.signed_envelope, ONION_HOP_XWING_PUBKEY_MEMBER)
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
/// v62.0.0 (ceremony gap 3, item 3) — **the X-Wing form.** For a seat of the
/// genesis bundle in force the pair is its X-Wing transit key, the bundle
/// binding's or the latest counted re-bind's
/// ([`seat_transit_key`](crate::federation::edition2::transport_rebind::seat_transit_key)),
/// split by [`TransitKexPair::from_xwing`]; steps 1–3 do not run (Verify's
/// reader separates a binding's X-Wing members). A node that is not a seat
/// and carries no earlier-form pair answers its edition-2 bind's X-Wing key
/// ([`bind_transit_xwing_for`](crate::federation::edition2::occurrence::bind_transit_xwing_for)),
/// which applies the cross-row rule itself.
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
    // v62.0.0 (ceremony gap 3, item 3; CC 3.3.6.2 "A seat's transit key") —
    // a seat of the genesis bundle in force: its pair is its X-Wing transit
    // key, the bundle binding's or the latest counted re-bind's, as
    // [`transit_xwing_pubkey_for`] reads it. A binding the seat publishes
    // itself is not read.
    let in_force = crate::federation::edition2::genesis::genesis_in_force(dir).await?;
    if let Some(seat) = in_force.seat(occurrence_key_id) {
        let key =
            crate::federation::edition2::transport_rebind::seat_transit_key(dir, &in_force, seat)
                .await?;
        return Ok(XWingPublicKey::from_bytes(&key).map(|k| TransitKexPair::from_xwing(&k)));
    }
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
        // v62.0.0 (ceremony gap 3, item 3) — no earlier-form pair: the
        // edition-2 bind's X-Wing transit key, for a node that is not a seat.
        return Ok(
            super::edition2::occurrence::bind_transit_xwing_for(dir, occurrence_key_id)
                .await?
                .map(|k| TransitKexPair::from_xwing(&k)),
        );
    };

    let others = other_keys_of(dir, occurrence_key_id, &live).await?;
    if check_transit_kex_pair(&pair, &others).is_err() {
        return Ok(None);
    }
    Ok(Some(pair))
}

/// v62.0.0 (#1274) — every key on the node's current occurrence that a
/// transport key must be separated from at use (the four
/// [`TransitKexOtherKeys`] groups), shared by [`transit_kex_pair_for`] and
/// [`transit_xwing_pubkey_for`] so the cross-row rule exists once.
pub(crate) async fn other_keys_of<D: crate::federation::FederationDirectory + ?Sized>(
    dir: &D,
    occurrence_key_id: &str,
    live: &[&SignedTransportDestination],
) -> Result<TransitKexOtherKeys, crate::federation::Error> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let dec = |b64: Option<&str>| b64.and_then(|s| B64.decode(s).ok());
    let mut others = TransitKexOtherKeys::default();
    for b in live {
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
    Ok(others)
}

/// v62.0.0 (CC rc20 3.3.6.2 "A seat's transit key", CIRISPersist#1274) — **the
/// per-peer X-Wing transit key resolver**: the `transit_xwing_pubkey` a dialler
/// may seal a link to `occurrence_key_id` with, or `None`.
///
/// 1. Read it only from live (unretired) [`BindingProvenance::Rooted`]
///    bindings; none, or two live bindings carrying different keys ⇒ `None`.
/// 2. **THE RULE.** For a seat of the genesis bundle in force the key is the
///    bundle binding's, moved only by a counted edition-2 re-bind
///    (`edition2::transport_rebind::seat_transit_key`); a binding the seat
///    publishes itself is not read. CC 3.3.6.2: "A seated serve node's new
///    transit key moves by `transport:canonical_rebind`, counted by the
///    accord's holders, before the handshake changes." v62.0.0 (C5-fix1): the
///    earlier-form seat check over the baked v4 bundle is deleted; no
///    earlier-form genesis seats a node.
/// 3. The cross-row rule at use: a half equal to any key on the node's current
///    occurrence (as [`transit_kex_pair_for`] gathers them), or to a half of
///    the live row's earlier-form pair ⇒ `None`.
///
/// # Errors
///
/// A backend read error; a stored binding whose key does not parse.
pub async fn transit_xwing_pubkey_for<D: crate::federation::FederationDirectory + ?Sized>(
    dir: &D,
    occurrence_key_id: &str,
) -> Result<Option<XWingPublicKey>, crate::federation::Error> {
    // v62.0.0 (wave W1; CC 3.3.6.2 "A seat's transit key") — a seat of the
    // genesis bundle in force: its key is the bundle binding's, moved only
    // by a counted `transport:canonical_rebind`; a binding the seat
    // publishes itself is not read (`edition2::transport_rebind`).
    let in_force = crate::federation::edition2::genesis::genesis_in_force(dir).await?;
    if let Some(seat) = in_force.seat(occurrence_key_id) {
        let key =
            crate::federation::edition2::transport_rebind::seat_transit_key(dir, &in_force, seat)
                .await?;
        return Ok(XWingPublicKey::from_bytes(&key));
    }
    let bindings = dir
        .list_signed_transport_destinations_for(occurrence_key_id)
        .await?;
    let live: Vec<&SignedTransportDestination> = bindings
        .iter()
        .filter(|b| b.transport_destination.retired_at.is_none())
        .collect();
    let mut found: Option<(XWingPublicKey, &SignedTransportDestination)> = None;
    for b in &live {
        if b.binding_provenance() != BindingProvenance::Rooted {
            continue;
        }
        let Some(k) = b.transit_xwing_pubkey()? else {
            continue;
        };
        match &found {
            None => found = Some((k, b)),
            Some((q, _)) if *q == k => {}
            Some(_) => return Ok(None),
        }
    }
    let Some((key, _)) = found else {
        // v62.0.0 (wave O1; E8's finding) — no route-plane key: the
        // edition-2 bind's, for a node that is not a seat.
        return super::edition2::occurrence::bind_transit_xwing_for(dir, occurrence_key_id).await;
    };
    let others = other_keys_of(dir, occurrence_key_id, &live).await?;
    let mut pair_halves: Vec<Vec<u8>> = Vec::new();
    for b in &live {
        if let Some(p) = b.transit_kex_pair()? {
            pair_halves.push(p.x25519.to_vec());
            pair_halves.push(p.ml_kem_768.to_vec());
        }
    }
    if check_xwing_halves(
        XWingKeyRole::Transit,
        &key,
        others.all().chain(pair_halves.iter().map(Vec::as_slice)),
    )
    .is_err()
    {
        return Ok(None);
    }
    Ok(Some(key))
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

    /// v62.0.0 (BIND-3; Constitution's ruling on the login placement) —
    /// **I6630: the placement table.** Login with no choice is `self`; login
    /// choosing `federation` is `self` plus the announcement; a group choice
    /// is that group, named by its member; a serve seat is `federation`
    /// whatever it is handed, and any other scope is refused; a group scope
    /// without its group, a group at `self`, and a commons scope other than
    /// `federation` are refused by name.
    #[test]
    fn i6630_the_owner_binding_placement_table() {
        use crate::federation::types::cohort_scope as cs;
        use OwnerBindingProducer::{Login, ServeSeat};
        let chose = |scope: &str, group: Option<&str>| ChosenPlacement {
            scope: scope.to_owned(),
            group: group.map(str::to_owned),
        };
        let plan = |p, c: Option<&ChosenPlacement>| node_owner_binding_placement(p, c);
        let at = |scope: &str, group: Option<&str>, announce: bool| OwnerBindingPlacement {
            scope: scope.to_owned(),
            group: group.map(str::to_owned),
            announce,
        };
        assert_eq!(plan(Login, None).unwrap(), at(cs::SELF, None, false));
        assert_eq!(
            plan(Login, Some(&chose(cs::SELF, None))).unwrap(),
            at(cs::SELF, None, false)
        );
        assert_eq!(
            plan(Login, Some(&chose(cs::FEDERATION, None))).unwrap(),
            at(cs::SELF, None, true),
            "announcing is the self row plus a federation row"
        );
        let room = plan(Login, Some(&chose(cs::COMMUNITY, Some("g-room")))).unwrap();
        assert_eq!(room, at(cs::COMMUNITY, Some("g-room"), false));
        assert_eq!(room.group_member(), Some("community_id"));
        let fam = plan(Login, Some(&chose(cs::FAMILY, Some("g-fam")))).unwrap();
        assert_eq!(fam.group_member(), Some("family_id"));
        assert_eq!(
            plan(ServeSeat, None).unwrap(),
            at(cs::FEDERATION, None, false)
        );
        assert_eq!(
            plan(ServeSeat, Some(&chose(cs::FEDERATION, None))).unwrap(),
            at(cs::FEDERATION, None, false)
        );
        for (p, c) in [
            (ServeSeat, chose(cs::SELF, None)),
            (ServeSeat, chose(cs::COMMUNITY, Some("g"))),
            (Login, chose(cs::COMMUNITY, None)),
            (Login, chose(cs::SELF, Some("g"))),
            (Login, chose(cs::FEDERATION, Some("g"))),
            (Login, chose(cs::SPECIES, None)),
            (Login, chose(cs::BIOSPHERE, None)),
        ] {
            let e = plan(p, Some(&c)).expect_err("refused");
            assert!(
                e.to_string().contains("owner_binding_placement_refused"),
                "{p:?} {c:?}: {e}"
            );
        }
        // The serve-seat producer's draft envelope is placed at federation.
        let env = owner_binding_draft_envelope(
            "n",
            &[crate::federation::types::delegation_scope::INFRA_SERVE.to_owned()],
        )
        .unwrap();
        assert_eq!(env["cohort_scope"], cs::FEDERATION);
    }

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
        // ownership dimension + producer-side purpose marker (what owner_of
        // keys on), sub_delegation always false.
        use super::super::types::owner_binding;
        // v62.0.0 (BIND-1) — the rule's members only, the scope a sorted set.
        let env = owner_binding_delegates_to_envelope(&[
            "infra:serve".to_string(),
            "infra:network_presence".to_string(),
            "infra:serve".to_string(),
        ]);
        assert_eq!(env["dimension"], owner_binding::DIMENSION);
        assert_eq!(env["delegation_purpose"], "owner_binding");
        for gone in ["kind", "delegate_key_id", "sub_delegation"] {
            assert!(env.get(gone).is_none(), "BIND-1: {gone} is not a member");
        }
        // CDE order is by the ENCODED bytes, so the shorter text sorts
        // first (its length is in the head byte).
        assert_eq!(
            env["scope"],
            serde_json::json!(["infra:serve", "infra:network_presence"]),
            "BIND-1: a set in CDE order, no repeat"
        );
    }

    #[test]
    fn partnership_pair_shares_bilateral_id() {
        let at = chrono::Utc::now();
        let g = partnership_grant_envelope("agent-occ", "pair-7", at);
        let a = partnership_accept_envelope("user-occ", "pair-7", at);
        assert_eq!(g["bilateral_pair_id"], a["bilateral_pair_id"]);
        assert_eq!(g["dimension"], DIMENSION_PARTNERSHIP_GRANT);
        assert_eq!(a["dimension"], DIMENSION_PARTNERSHIP_ACCEPT);
    }

    /// v61 (CIRISPersist#1126, CC 4.4.3.4.3.1) — the two halves are
    /// `consent_record` rows with exactly the pinned member set: the six
    /// envelope members (the row's type and attester ride its `row` mirror),
    /// the partner in the singular `subject_key_id`, no `valid_until`.
    #[test]
    fn partnership_halves_are_consent_records_1126() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-11-01T12:00:00.123456Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let g = partnership_grant_envelope("agent-occ", "pair-7", at);
        let keys: Vec<&str> = g.as_object().unwrap().keys().map(String::as_str).collect();
        let mut keys = keys;
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "asserted_at",
                "bilateral_pair_id",
                "dimension",
                "stance",
                "subject_key_id",
                "subject_kind"
            ]
        );
        assert_eq!(g["subject_kind"], "consent_record");
        assert_eq!(g["stance"], "granted");
        assert_eq!(g["subject_key_id"], "agent-occ");
        assert_eq!(g["asserted_at"], "2026-11-01T12:00:00.123Z");
        let a = partnership_accept_envelope("user-occ", "pair-7", at);
        assert_eq!(a["subject_key_id"], "user-occ");
        assert!(
            crate::federation::admission::check_consent_record_admission(
                crate::federation::types::attestation_type::SCORES,
                &g,
                crate::federation::types::attestation_tier::LOCAL,
            )
            .is_ok()
        );
        assert!(
            check_partnership_shape(crate::federation::types::attestation_type::SCORES, &g).is_ok()
        );
    }

    /// v61 (CIRISPersist#1126) — the pre-v61 bare `scores` half is refused
    /// `partnership_shape_retired`; a retraction naming the dimension, and any
    /// other dimension, pass.
    #[test]
    fn the_bare_partnership_shape_is_refused_1126() {
        use crate::federation::types::attestation_type::{SCORES, WITHDRAWS};
        for dim in [DIMENSION_PARTNERSHIP_GRANT, DIMENSION_PARTNERSHIP_ACCEPT] {
            let bare = serde_json::json!({
                "kind": "partnership_grant",
                "dimension": dim,
                "partner_occurrence_key_id": "agent-occ",
                "bilateral_pair_id": "pair-7",
            });
            assert!(matches!(
                check_partnership_shape(SCORES, &bare),
                Err(crate::federation::Error::DimensionRejected { reason, .. })
                    if reason == PARTNERSHIP_SHAPE_RETIRED_REASON
            ));
            assert!(check_partnership_shape(WITHDRAWS, &bare).is_ok());
        }
        let other = serde_json::json!({ "dimension": "consent:state:granted:v1" });
        assert!(check_partnership_shape(SCORES, &other).is_ok());
        assert!(crate::federation::admission::dimension_rejected_reason::ALL
            .contains(&PARTNERSHIP_SHAPE_RETIRED_REASON));
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
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::FederationDirectory;

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("test timestamp")
    }

    /// A minimal live route row (local-put shape: no signature container).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
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

    /// **The (epoch, asserted_at) monotonic-guard matrix** for the trusted-
    /// LOCAL put: newer supersedes (in place — never a second row per kind),
    /// older asserted_at at the same epoch is refused, an older epoch is
    /// refused even with a newer wall clock, and a higher epoch wins even
    /// with an older wall clock (epoch dominates — clock skew cannot roll a
    /// route back). Plus list ordering + the local remove.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
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

    /// v62.0.0 (wave E8) — **the edition-2 bind builders** the route matrices
    /// share. A route is no longer a signed object of its own: it is the
    /// `transport_destination` member of an `identity:occurrence` bind
    /// (`edition2::occurrence`), projected into `transport_destinations` after
    /// the bind's write commits (#446). A bind is the occurrence key's own
    /// statement (`iss` = `sub` = the occurrence) and the author's (the
    /// identity, or an agent's owner) over ONE payload; each voice is signed by
    /// an E0 seed key ([`crate::federation::edition2::fixture_switch`]).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) mod e2bind {
        use chrono::{DateTime, Utc};
        use ciris_verify_core::cde::{self, Value};
        use ciris_verify_core::edition2::sign_row_statement;

        use crate::federation::edition2::door::AdmittedRow;
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::{
            held_keys_for, StatementOutcome, STATEMENT_MEMBER,
        };
        use crate::federation::edition2::occurrence::OCCURRENCE_FAMILY;
        use crate::federation::self_at_login::TransportDestination;
        use crate::federation::types::{IdentityOccurrence, IdentityOccurrenceRevocation};
        use crate::federation::{Error, FederationDirectory};

        /// The Reticulum application name every fixture route announces.
        pub(crate) const APP: &str = "ciris.federation";

        /// This node's clock, POSIX ms. Node and agent keys sign rows dated
        /// relative to it (their records end, CC 2.4.1.1).
        pub(crate) fn now_ms() -> u64 {
            e2::ms(crate::host::clock::now())
        }

        /// The instant of `ms`.
        pub(crate) fn at(ms: u64) -> DateTime<Utc> {
            DateTime::<Utc>::from_timestamp_millis(i64::try_from(ms).expect("ms in range"))
                .expect("a representable instant")
        }

        /// A CBOR map of text keys, in the deterministic order.
        pub(crate) fn map(mut m: Vec<(&str, Value)>) -> Value {
            m.sort_by_key(|(k, _)| cde::encode(&Value::Text((*k).to_owned())));
            Value::Map(
                m.into_iter()
                    .map(|(k, v)| (Value::Text(k.to_owned()), v))
                    .collect(),
            )
        }

        /// A `transport_destination` member (CC 3.3.6.2: exactly five
        /// members) over these two link keys, its `destination_hash` derived
        /// (CC 3.3.6.3); and the route destination it projects (#512: the
        /// hash, canonical hex).
        pub(crate) fn transport(x25519: [u8; 32], ed25519: [u8; 32]) -> (Value, String) {
            let aspects = vec!["announce".to_owned(), "v1".to_owned()];
            let dest = ciris_verify_core::transport_binding::compute_destination_hash(
                APP, &aspects, &x25519, &ed25519,
            )
            .expect("a destination hash");
            let member = map(vec![
                ("reticulum_x25519_pubkey", Value::Bytes(x25519.to_vec())),
                ("reticulum_ed25519_pubkey", Value::Bytes(ed25519.to_vec())),
                ("destination_hash", Value::Bytes(dest.to_vec())),
                ("app_name", Value::Text(APP.to_owned())),
                (
                    "aspects",
                    Value::Array(aspects.into_iter().map(Value::Text).collect()),
                ),
            ]);
            (member, hex::encode(dest))
        }

        /// [`transport`] from a fill byte: link x25519 `[tag; 32]`, link
        /// ed25519 `[tag + 1; 32]`.
        pub(crate) fn transport_tag(tag: u8) -> (Value, String) {
            transport([tag; 32], [tag.wrapping_add(1); 32])
        }

        /// An `encryption_pubkeys` member (exactly `x25519` 32 bytes and
        /// `ml_kem_768` 1184 bytes).
        pub(crate) fn encryption(x25519: [u8; 32], ml_kem_768: &[u8]) -> Value {
            map(vec![
                ("x25519", Value::Bytes(x25519.to_vec())),
                ("ml_kem_768", Value::Bytes(ml_kem_768.to_vec())),
            ])
        }

        /// One bind: what its payload states. Keys are E0 seeds (or kids).
        #[derive(Clone, Debug)]
        pub(crate) struct Bind {
            pub(crate) author: String,
            pub(crate) identity: String,
            pub(crate) occurrence: String,
            pub(crate) device_class: &'static str,
            pub(crate) asserted_at_ms: u64,
            pub(crate) valid_until_ms: Option<u64>,
            pub(crate) extra: Vec<(&'static str, Value)>,
            /// `refs.head` (required, CC 3.3.6.4): the roster row the bind
            /// stands on. [`Bind::headed`] states the identity's current one.
            pub(crate) head: Option<crate::federation::edition2::names::RowId>,
        }

        impl Bind {
            /// A bind of `occurrence` under `identity`, authored by `author`
            /// (the identity itself; an agent identity's owner).
            pub(crate) fn new(
                author: &str,
                identity: &str,
                occurrence: &str,
                device_class: &'static str,
                asserted_at_ms: u64,
            ) -> Self {
                Bind {
                    author: author.to_owned(),
                    identity: identity.to_owned(),
                    occurrence: occurrence.to_owned(),
                    device_class,
                    asserted_at_ms,
                    valid_until_ms: None,
                    extra: Vec::new(),
                    head: None,
                }
            }

            /// v62 (O1 fix 3) — state `refs.head` = the identity's current
            /// roster head (`occurrence::current_roster_head`), unless one is
            /// stated already. Call it when the bind is built: every voice of
            /// one bind names the same head.
            ///
            /// # Panics
            /// The identity's key record is not held.
            pub(crate) async fn headed(mut self, dir: &dyn FederationDirectory) -> Self {
                if self.head.is_none() {
                    self.head = crate::federation::edition2::occurrence::current_roster_head(
                        dir,
                        &e2::kid(&self.identity),
                    )
                    .await
                    .expect("e2bind: the roster head reads")
                    .or_else(|| panic!("e2bind: no roster head for {}", self.identity));
                }
                self
            }

            /// State this `refs.head` (a sync builder's form of [`Bind::headed`]).
            #[must_use]
            pub(crate) fn on_head(
                mut self,
                head: Option<crate::federation::edition2::names::RowId>,
            ) -> Self {
                self.head = head;
                self
            }

            /// One more payload member.
            #[must_use]
            pub(crate) fn with(mut self, member: &'static str, value: Value) -> Self {
                self.extra.push((member, value));
                self
            }

            /// The bind's end (`valid_until`, half-open).
            #[must_use]
            pub(crate) fn until(mut self, valid_until_ms: u64) -> Self {
                self.valid_until_ms = Some(valid_until_ms);
                self
            }

            /// The payload every voice of this bind signs.
            pub(crate) fn payload(&self) -> Value {
                let mut m = vec![
                    ("asserted_at", Value::Uint(self.asserted_at_ms)),
                    ("author", Value::Text(e2::kid(&self.author))),
                    ("identity_key_id", Value::Text(e2::kid(&self.identity))),
                    ("occurrence_key_id", Value::Text(e2::kid(&self.occurrence))),
                    ("device_class", Value::Text(self.device_class.to_owned())),
                ];
                if let Some(u) = self.valid_until_ms {
                    m.push(("valid_until", Value::Uint(u)));
                }
                for (k, v) in &self.extra {
                    m.push((*k, v.clone()));
                }
                if let Some(h) = &self.head {
                    m.push((
                        "refs",
                        map(vec![("head", ciris_verify_core::edition2::row_ref(&h.0))]),
                    ));
                }
                map(m)
            }

            /// `signer`'s statement over this bind, as `iss` (a seed or kid).
            pub(crate) fn voice(&self, signer: &str, iss: &str) -> Vec<u8> {
                sign_row_statement(
                    &e2::signing_key(signer),
                    &e2::kid(iss),
                    &e2::kid(&self.occurrence),
                    "scores",
                    OCCURRENCE_FAMILY,
                    &self.payload(),
                    vec![],
                )
                .expect("e2bind: sign a bind voice")
            }

            /// The occurrence key's own statement (`iss` = `sub`).
            pub(crate) fn own_voice(&self) -> Vec<u8> {
                self.voice(&self.occurrence, &self.occurrence)
            }

            /// The author's statement, by the author's own key.
            pub(crate) fn author_voice(&self) -> Vec<u8> {
                self.voice(&self.author, &self.author)
            }

            /// The voices in the door's order; the self pair has one.
            pub(crate) fn voices(&self) -> Vec<Vec<u8>> {
                if e2::kid(&self.author) == e2::kid(&self.occurrence) {
                    vec![self.own_voice()]
                } else {
                    vec![self.own_voice(), self.author_voice()]
                }
            }
        }

        /// One statement through the one entry (`ingest::put_statement`).
        ///
        /// # Errors
        /// The door's refusal.
        pub(crate) async fn put(
            dir: &dyn FederationDirectory,
            statement: &[u8],
        ) -> Result<StatementOutcome, Error> {
            Box::pin(e2::put_statement(dir, statement)).await
        }

        /// These voices, in order; the last outcome. A replay re-offers the
        /// SAME bytes: a composite signature is randomized, so signing the
        /// bind again is a new statement of the same row.
        ///
        /// # Panics
        /// A voice is refused.
        pub(crate) async fn put_voices(
            dir: &dyn FederationDirectory,
            voices: &[Vec<u8>],
        ) -> StatementOutcome {
            let mut last = None;
            for v in voices {
                last = Some(
                    put(dir, v)
                        .await
                        .unwrap_or_else(|e| panic!("e2bind: a bind voice refused: {e}")),
                );
            }
            last.expect("e2bind: a bind has a voice")
        }

        /// A bind's voices, freshly signed, in order; the last outcome.
        ///
        /// # Panics
        /// A voice is refused.
        pub(crate) async fn put_bind(dir: &dyn FederationDirectory, b: &Bind) -> StatementOutcome {
            let b = b.clone().headed(dir).await;
            put_voices(dir, &b.voices()).await
        }

        /// The stable reason of a refusal: a malformed row's token, else the
        /// error kind.
        pub(crate) fn reason(e: &Error) -> String {
            match e {
                Error::MalformedRow { reason, .. } => (*reason).to_owned(),
                other => other.kind().to_owned(),
            }
        }

        /// Is `o` a `Row` outcome with this `new`?
        pub(crate) fn is_row(o: &StatementOutcome, new: bool) -> bool {
            matches!(o, StatementOutcome::Row { new: n, .. } if *n == new)
        }

        /// The live routes of `occurrence` (a seed or kid).
        pub(crate) async fn routes(
            dir: &dyn FederationDirectory,
            occurrence: &str,
        ) -> Vec<TransportDestination> {
            dir.list_transport_destinations_for(&e2::kid(occurrence))
                .await
                .expect("route read")
        }

        /// The held occurrence row of `occurrence` under `identity`.
        pub(crate) async fn held(
            dir: &dyn FederationDirectory,
            identity: &str,
            occurrence: &str,
        ) -> Option<IdentityOccurrence> {
            let occ = e2::kid(occurrence);
            dir.list_identity_occurrences_for(&e2::kid(identity))
                .await
                .expect("occurrence read")
                .into_iter()
                .find(|o| o.occurrence_key_id == occ)
        }

        /// The author statement the signed occurrence listing serves for
        /// `occurrence` under `identity` (`signed_envelope.ceg_statement`,
        /// O1's listing), if any: what a peer receives and re-verifies.
        pub(crate) async fn served(
            dir: &dyn FederationDirectory,
            identity: &str,
            occurrence: &str,
        ) -> Option<Vec<u8>> {
            let occ = e2::kid(occurrence);
            dir.list_signed_identity_occurrences_for(&e2::kid(identity))
                .await
                .expect("signed occurrence read")
                .into_iter()
                .find(|s| s.identity_occurrence.occurrence_key_id == occ)
                .and_then(|s| {
                    s.signed_envelope
                        .get(STATEMENT_MEMBER)
                        .and_then(serde_json::Value::as_str)
                        .map(|h| hex::decode(h).expect("ceg_statement is hex"))
                })
        }

        /// A held statement through the door again (the verifier IS the
        /// door), over the keys this directory holds for it.
        ///
        /// # Errors
        /// The door's refusal.
        pub(crate) async fn readmit(
            dir: &dyn FederationDirectory,
            statement: &[u8],
        ) -> Result<AdmittedRow, Error> {
            let keys = held_keys_for(dir, statement).await?;
            e2::try_admit(statement, &keys)
        }

        /// A payload member of a statement, as bytes.
        pub(crate) fn payload_bytes(statement: &[u8], member: &str) -> Option<Vec<u8>> {
            crate::federation::edition2::liveness::statement_parts(statement).and_then(|(_, p)| {
                p.get_text(member)
                    .and_then(Value::as_bytes)
                    .map(<[u8]>::to_vec)
            })
        }

        /// One voice of an `identity:occurrence_revocation` row (T2):
        /// `signer` as the identity, revoking at `revoked_at_ms`.
        pub(crate) async fn revocation_voice(
            dir: &dyn crate::federation::FederationDirectory,
            signer: &str,
            identity: &str,
            occurrence: &str,
            revoked_at_ms: u64,
        ) -> Vec<u8> {
            e2::occurrence_revocation_voice(
                dir,
                signer,
                true,
                &IdentityOccurrenceRevocation {
                    identity_key_id: identity.to_owned(),
                    occurrence_key_id: occurrence.to_owned(),
                    revoked_at: at(revoked_at_ms),
                    effective_at: at(revoked_at_ms),
                    reason: None,
                    witness_set: Vec::new(),
                    persist_row_hash: String::new(),
                },
                None,
                &[],
                &[],
                revoked_at_ms,
            )
            .await
        }
    }

    /// v62.0.0 (wave E8; was the #443 signed route matrix) — **the route a
    /// bind projects, under forgery, replay, rotation and retirement**,
    /// through the edition-2 `identity:occurrence` door, on sqlite and
    /// postgres. A user `alice` binds her `phone` (a user-typed device key);
    /// every route assertion reads the projected `transport_destinations`.
    ///
    /// - **I3310** the phone's own statement alone is a `Voice` and binds
    ///   nothing; alice's statement over the same payload lands the bind
    ///   (`Row`, new) and projects one `Rooted` route at the bind's instant.
    /// - **I3312** a forged statement (a flipped signature byte) is refused
    ///   `edition2_statement_invalid`; **I3313** mallory's key signing as alice
    ///   is refused `kid_not_of_iss`; **I3314** an author statement with no
    ///   occurrence-key voice held is refused, retryable,
    ///   `federation_attester_key_unknown`; **I3315** mallory authoring a bind
    ///   of alice's identity is refused `edition2_payload_invalid`. Each binds
    ///   nothing and moves no route.
    /// - **I3311** re-offering the same statements is the SAME row id and is
    ///   idempotent (`Row`, `new = false`): never a second route.
    /// - **I3316** rotation: the phone itself, acting for alice (its live
    ///   occurrence seats it as a key of alice), signs a newer bind with a new
    ///   transport; the route follows it.
    /// - **I3317** a replayed OLDER bind cannot displace the newer one: the
    ///   newest route wins. **I3318** a same-instant fork (a different
    ///   transport at the held bind's `asserted_at`) displaces nothing.
    /// - **I3319** retirement: `identity:occurrence_revocation`, voiced by a
    ///   strict majority of alice's roster (alice and the phone), removes the
    ///   route from every `list_*` read; the bind and the revocation stay held
    ///   (they gossip as statements; no route is on the signed route plane).
    /// - **I3320** after the revocation a replayed older bind resurrects
    ///   nothing, nor does a stale local route put; a NEWER bind re-establishes
    ///   the route.
    /// - **I3321** a local route refresh moves neither the bind's statements
    ///   nor its instant: the served statement still re-admits (#541's
    ///   invariant, edition 2).
    /// - **I3322** a member outside the family's payload (an earlier-form
    ///   `binding_provenance` token) is refused `edition2_payload_invalid`,
    ///   never read as `Rooted`; nothing is stored.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn run_signed_transport_route_matrix(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::malformed_row as mr;
        use crate::federation::types::device_class::{LAPTOP, PHONE};
        use crate::federation::types::OccurrenceTransportBinding;
        use ciris_verify_core::cde::Value;
        use e2bind::{
            at, held, is_row, put, put_bind, put_voices, readmit, reason, revocation_voice, routes,
            served, transport_tag, Bind,
        };

        let alice = format!("sig-alice-{suffix}");
        let phone = format!("sig-alice-phone-{suffix}");
        let laptop = format!("sig-alice-laptop-{suffix}");
        let mallory = format!("sig-mallory-{suffix}");
        for k in [&alice, &phone, &laptop, &mallory] {
            e2::put_key(dir, k, &["user"]).await;
        }
        let ph = e2::kid(&phone);
        let now = e2bind::now_ms();
        let t = |mins: u64| now - mins * 60_000;

        // I3310 — the phone's own statement alone binds nothing.
        let (td1, d1) = transport_tag(0x10);
        let b1 = Bind::new(&alice, &alice, &phone, PHONE, t(60))
            .headed(dir)
            .await
            .with("transport_destination", td1);
        let (own1, auth1) = (b1.own_voice(), b1.author_voice());
        let out = put(dir, &own1).await.expect("I3310: the own voice");
        assert!(
            matches!(out, StatementOutcome::Voice { new: true, .. }),
            "I3310: the occurrence key's own statement is held as a voice: {out:?}"
        );
        assert!(
            routes(dir, &phone).await.is_empty(),
            "I3310: a voice alone projects no route"
        );

        // I3312 — a forged statement: alice's voice with a flipped signature
        // byte (the COSE_Sign1 signature is its last member).
        let mut forged = auth1.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        let e = put(dir, &forged)
            .await
            .expect_err("I3312: a forged statement");
        assert_eq!(reason(&e), mr::EDITION2_STATEMENT_INVALID, "I3312: {e}");

        // I3313 — mallory's key signing as alice over the same payload.
        let e = put(dir, &b1.voice(&mallory, &alice))
            .await
            .expect_err("I3313: a key not of alice signing as alice");
        assert_eq!(reason(&e), mr::KID_NOT_OF_ISS, "I3313: {e}");

        // I3314 — an author statement with no occurrence-key voice held.
        let b_laptop = Bind::new(&alice, &alice, &laptop, LAPTOP, t(60))
            .headed(dir)
            .await
            .with("transport_destination", transport_tag(0x60).0);
        let e = put(dir, &b_laptop.author_voice())
            .await
            .expect_err("I3314: the author before the occurrence key");
        assert_eq!(
            reason(&e),
            "federation_attester_key_unknown",
            "I3314: retryable, naming the occurrence key: {e}"
        );
        assert!(
            held(dir, &alice, &laptop).await.is_none(),
            "I3314: nothing bound"
        );
        assert!(routes(dir, &laptop).await.is_empty(), "I3314: no route");

        // I3315 — mallory authoring a bind of alice's identity.
        let b_m = Bind::new(&mallory, &alice, &phone, PHONE, t(60))
            .headed(dir)
            .await
            .with("transport_destination", transport_tag(0x61).0);
        let e = put(dir, &b_m.author_voice())
            .await
            .expect_err("I3315: an identity is bound by itself");
        assert_eq!(reason(&e), mr::EDITION2_PAYLOAD_INVALID, "I3315: {e}");

        assert!(
            held(dir, &alice, &phone).await.is_none() && routes(dir, &phone).await.is_empty(),
            "I3312-I3315: the refusals bound nothing and projected nothing"
        );

        // I3310 — alice's statement lands the bind and projects the route.
        let out = put(dir, &auth1).await.expect("I3310: alice's statement");
        assert!(is_row(&out, true), "I3310: the bind lands: {out:?}");
        let rows = routes(dir, &phone).await;
        assert_eq!(rows.len(), 1, "I3310: one projected route: {rows:?}");
        assert_eq!(
            rows[0].transport_kind,
            OccurrenceTransportBinding::TRANSPORT_KIND
        );
        assert_eq!(rows[0].destination, d1);
        assert_eq!(rows[0].binding_provenance, BindingProvenance::Rooted);
        assert_eq!(rows[0].asserted_at, at(t(60)));

        // I3311 — the same statements again: one row id, idempotent.
        assert_eq!(
            e2::row_id_of(&own1),
            e2::row_id_of(&auth1),
            "I3311: two voices of one row"
        );
        let out = put(dir, &own1).await.expect("I3311: own voice again");
        assert!(
            matches!(out, StatementOutcome::Voice { new: false, .. }),
            "I3311: {out:?}"
        );
        let out = put(dir, &auth1).await.expect("I3311: alice's voice again");
        assert!(is_row(&out, false), "I3311: Row, not new: {out:?}");
        let rows = routes(dir, &phone).await;
        assert_eq!(rows.len(), 1, "I3311: never a second route");
        assert_eq!(rows[0].destination, d1);

        // I3316 — rotation: the phone, acting for alice, signs a newer bind.
        let (td2, d2) = transport_tag(0x20);
        let b2 = Bind::new(&alice, &alice, &phone, PHONE, t(50))
            .headed(dir)
            .await
            .with("transport_destination", td2);
        let auth2 = b2.voice(&phone, &alice);
        put(dir, &b2.own_voice()).await.expect("I3316: own voice");
        let out = put(dir, &auth2)
            .await
            .expect("I3316: the phone signs as alice through its occurrence");
        assert!(is_row(&out, true), "I3316: {out:?}");
        let rows = routes(dir, &phone).await;
        assert_eq!(rows.len(), 1, "I3316: superseded in place");
        assert_eq!(
            rows[0].destination, d2,
            "I3316: the route follows the newest bind"
        );
        assert_eq!(rows[0].asserted_at, at(t(50)));
        assert_eq!(
            served(dir, &alice, &phone).await.as_deref(),
            Some(auth2.as_slice())
        );

        // I3317 — a replayed OLDER bind cannot displace the newer one.
        put(dir, &own1).await.expect("I3317: old own voice");
        let out = put(dir, &auth1).await.expect("I3317: old author voice");
        assert!(is_row(&out, false), "I3317: {out:?}");
        assert_eq!(
            routes(dir, &phone).await[0].destination,
            d2,
            "I3317: the newest route wins"
        );

        // I3318 — a same-instant fork displaces nothing (fail-closed, never
        // last-writer-wins).
        let (td_fork, d_fork) = transport_tag(0x2F);
        let fork = Bind::new(&alice, &alice, &phone, PHONE, t(50))
            .headed(dir)
            .await
            .with("transport_destination", td_fork);
        let out = put_bind(dir, &fork).await;
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I3318: {out:?}"
        );
        let rows = routes(dir, &phone).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].destination, d2, "I3318: the fork is not the route");
        assert_ne!(d_fork, d2);
        assert_eq!(
            served(dir, &alice, &phone).await.as_deref(),
            Some(auth2.as_slice())
        );

        // I3319 — retirement: alice's roster is {alice, phone}; a strict
        // majority (both) revokes the phone's occurrence.
        let rv_alice = revocation_voice(dir, &alice, &alice, &phone, t(40)).await;
        let rv_phone = revocation_voice(dir, &phone, &alice, &phone, t(40)).await;
        let out = put(dir, &rv_alice)
            .await
            .expect("I3319: alice's revocation voice");
        assert!(
            matches!(out, StatementOutcome::Pending { new: true, .. }),
            "I3319: one of two roster keys is short: {out:?}"
        );
        assert_eq!(
            routes(dir, &phone).await.len(),
            1,
            "I3319: nothing retired short"
        );
        let out = put(dir, &rv_phone)
            .await
            .expect("I3319: the phone's revocation voice");
        assert!(is_row(&out, true), "I3319: the majority lands it: {out:?}");
        assert!(
            routes(dir, &phone).await.is_empty(),
            "I3319: the revoked occurrence's route is retired"
        );
        assert!(!dir
            .list_all_transport_destinations()
            .await
            .unwrap()
            .iter()
            .any(|r| r.occurrence_key_id == ph));
        assert!(dir
            .list_transport_destinations_by_destination(&d2)
            .await
            .unwrap()
            .iter()
            .all(|r| r.occurrence_key_id != ph));
        assert!(
            dir.list_signed_transport_destinations_for(&ph)
                .await
                .unwrap()
                .is_empty(),
            "I3319: a projected route is local; the occurrence plane carries it"
        );
        assert_eq!(
            served(dir, &alice, &phone).await.as_deref(),
            Some(auth2.as_slice()),
            "I3319: the bind keeps gossiping as its statements"
        );
        assert_eq!(
            dir.edition2_voices(&e2::row_id_of(&rv_alice))
                .await
                .unwrap()
                .len(),
            2,
            "I3319: both revocation voices are held"
        );

        // I3320 — a replayed older bind resurrects nothing...
        put(dir, &own1).await.expect("I3320: old own voice");
        let out = put(dir, &auth1).await.expect("I3320: old author voice");
        assert!(is_row(&out, false), "I3320: {out:?}");
        assert!(routes(dir, &phone).await.is_empty(), "I3320: still retired");
        // ...nor does a stale LOCAL put (a silent no-op).
        dir.put_transport_destination(&route(
            &ph,
            OccurrenceTransportBinding::TRANSPORT_KIND,
            "d-necromancer",
            0,
            "2026-07-01T00:00:00Z",
        ))
        .await
        .unwrap();
        assert!(
            routes(dir, &phone).await.is_empty(),
            "I3320: a stale local put"
        );
        // ...while a NEWER bind re-establishes the route.
        let (td3, d3) = transport_tag(0x30);
        let b3 = Bind::new(&alice, &alice, &phone, PHONE, t(30))
            .headed(dir)
            .await
            .with("transport_destination", td3);
        let v3 = b3.voices();
        let out = put_voices(dir, &v3).await;
        assert!(is_row(&out, true), "I3320: {out:?}");
        let rows = routes(dir, &phone).await;
        assert_eq!(rows.len(), 1, "I3320: re-established");
        assert_eq!(rows[0].destination, d3);

        // I3321 — a local liveness refresh of the route at a later clock
        // moves neither the bind's statements nor its instant.
        let mut refresh = rows[0].clone();
        refresh.asserted_at = at(t(20));
        dir.put_transport_destination(&refresh).await.unwrap();
        let st = served(dir, &alice, &phone)
            .await
            .expect("I3321: the bind is served");
        assert_eq!(st, v3[1], "I3321: the served statement is the bind's");
        readmit(dir, &st)
            .await
            .expect("I3321: a peer re-admits the served statement after a local write");
        assert_eq!(
            held(dir, &alice, &phone).await.expect("held").asserted_at,
            at(t(30)),
            "I3321: the bind's own instant is authoritative"
        );

        // I3322 — a member outside the family's payload refuses by name.
        let bad = Bind::new(&alice, &alice, &phone, PHONE, t(10))
            .headed(dir)
            .await
            .with("transport_destination", transport_tag(0x70).0)
            .with("binding_provenance", Value::Text("ROOTED".into()));
        let e = put(dir, &bad.own_voice())
            .await
            .expect_err("I3322: an unknown member");
        assert_eq!(reason(&e), mr::EDITION2_PAYLOAD_INVALID, "I3322: {e}");
        assert_eq!(
            routes(dir, &phone).await[0].destination,
            d3,
            "I3322: nothing stored"
        );
    }

    /// v62.0.0 (wave E8; was the #541 signed-row-survives-local-write
    /// invariant) — **no local write renders a bind unverifiable**, and the
    /// first revocation to land fixes the instants, on sqlite and postgres.
    ///
    /// - **I3323** a bind carrying a transport destination and the
    ///   content-KEM pair; then the engine's trusted-local self-write on the
    ///   SAME pair at an advanced clock, content-only (`transport_binding`
    ///   and `encryption_pubkeys` absent, as the login co-admit writes it).
    ///   The bind is untouched (O1: the local door never overwrites an
    ///   edition-2 bind): the signed listing serves the same author
    ///   statement, it re-admits through the door, and the typed row still
    ///   equals what the statement states.
    /// - **I3324** the occurrence revoked (a strict majority of the roster);
    ///   a second revocation of the same pair at other instants is admitted
    ///   but moves nothing: one revocation, the first's `effective_at`. The
    ///   trusted-local door refuses a second revocation of the pair.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn exercise_signed_row_survives_local_write(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::types::device_class::PHONE;
        use e2bind::{
            at, encryption, held, is_row, put, put_voices, readmit, revocation_voice, served,
            transport, Bind,
        };

        let alice = format!("io-alice-{suffix}");
        let phone = format!("io-phone-{suffix}");
        for k in [&alice, &phone] {
            e2::put_key(dir, k, &["user"]).await;
        }
        let (a, ph) = (e2::kid(&alice), e2::kid(&phone));
        let now = e2bind::now_ms();
        let t = |mins: u64| now - mins * 60_000;

        let (td, _) = transport([0x01; 32], [0x02; 32]);
        let b = Bind::new(&alice, &alice, &phone, PHONE, t(60))
            .headed(dir)
            .await
            .with("transport_destination", td)
            .with(
                "encryption_pubkeys",
                encryption([0x03; 32], &[0x11u8; 1184]),
            );
        let voices = b.voices();
        assert!(
            is_row(&put_voices(dir, &voices).await, true),
            "I3323: the bind lands"
        );

        // The statement and the typed row it projects, as one unit.
        let check = |what: &'static str| {
            let author_voice = voices[1].clone();
            let (alice, phone) = (alice.clone(), phone.clone());
            async move {
                let st = served(dir, &alice, &phone)
                    .await
                    .unwrap_or_else(|| panic!("({suffix}) {what}: the bind is served"));
                assert_eq!(st, author_voice, "({suffix}) {what}: the same statement");
                let admitted = readmit(dir, &st).await.unwrap_or_else(|e| {
                    panic!("({suffix}) {what}: the served statement must re-admit: {e}")
                });
                let stated = crate::federation::edition2::occurrence::read_payload(&admitted)
                    .expect("the bind's payload reads");
                let row = held(dir, &alice, &phone).await.expect("the bind is held");
                assert!(
                    row.transport_binding.is_some(),
                    "({suffix}) {what}: the transport binding is held"
                );
                assert_eq!(
                    (
                        &row.transport_binding,
                        &row.encryption_pubkeys,
                        row.asserted_at
                    ),
                    (
                        &stated.transport_binding,
                        &stated.encryption_pubkeys,
                        stated.asserted_at
                    ),
                    "({suffix}) {what}: the typed row is what the statement states"
                );
            }
        };
        Box::pin(check("I3323 baseline")).await;

        // THE ATTACK — the trusted-local self-write on the same pair, later,
        // content-only.
        dir.test_seam_put_identity_occurrence(crate::federation::IdentityOccurrence {
            identity_key_id: a.clone(),
            occurrence_key_id: ph.clone(),
            device_class: PHONE.into(),
            hardware_attestation: None,
            asserted_at: at(t(10)),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("I3323: the content-only local self-write is accepted (a no-op on the bind)");
        assert_eq!(
            dir.list_signed_identity_occurrences_for(&a)
                .await
                .unwrap()
                .len(),
            1,
            "({suffix}) I3323: the bind survives"
        );
        Box::pin(check("I3323 after the local write")).await;

        // I3324 — the first revocation to land fixes the instants.
        let r1 = revocation_voice(dir, &alice, &alice, &phone, t(40)).await;
        let r2 = revocation_voice(dir, &phone, &alice, &phone, t(40)).await;
        assert!(matches!(
            put(dir, &r1).await.expect("I3324: first voice"),
            StatementOutcome::Pending { .. }
        ));
        assert!(
            is_row(&put(dir, &r2).await.expect("I3324: second voice"), true),
            "I3324: the roster majority lands the revocation"
        );
        put(
            dir,
            &revocation_voice(dir, &alice, &alice, &phone, t(20)).await,
        )
        .await
        .expect("I3324: a later revocation of a revoked pair is admitted");
        let revs: Vec<_> = dir
            .list_identity_occurrence_revocations_for(&a)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.occurrence_key_id == ph)
            .collect();
        assert_eq!(
            revs.len(),
            1,
            "({suffix}) I3324: one revocation of the pair"
        );
        assert_eq!(
            revs[0].effective_at,
            at(t(40)),
            "({suffix}) I3324: the first revocation's instant stands"
        );
        dir.put_identity_occurrence_revocation_edition2(
            crate::federation::types::IdentityOccurrenceRevocation {
                identity_key_id: a.clone(),
                occurrence_key_id: ph.clone(),
                revoked_at: at(t(5)),
                effective_at: at(t(5)),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
            crate::federation::DoorToken::new(),
        )
        .await
        .expect_err("I3324: a second local revocation of the pair is refused (#541)");
    }

    /// v62.0.0 (wave E8; was the #446 composite-projection matrix) — **every
    /// landed bind carrying a transport destination projects its route**, as
    /// a LOCAL derived row (the plain reads see it, the signed route plane
    /// never carries it), on the bind's own clock; on sqlite and postgres.
    ///
    /// - **I3325** (1) the route is materialized exactly (kind, the
    ///   destination hash as hex, both link keys, `Rooted`, epoch 0, the
    ///   bind's instant); (2) a newer bind supersedes it in place; a replayed
    ///   older bind displaces nothing; (3) the occurrence's revocation retires
    ///   it; (4) a newer bind revives it.
    /// - **I3326** an agent's occurrence binds the AGENT's own identity,
    ///   authored by its owner, with the agent key's own voice: it lands and
    ///   projects NO route (an agent is reached through its node, CC 3.4.7.3
    ///   Clause A). The same agent key under the owner's (a person's)
    ///   identity is refused `occurrence_mixes_person_and_machine`, as
    ///   `agent` and as `laptop`.
    /// - **I3327** the window is half-open: a bind whose `valid_until` is
    ///   ahead projects its route; a bind whose `valid_until` has passed
    ///   projects none. (Depends on O1's fix: the projection and the route
    ///   reads honour `valid_until`, half-open.)
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn run_binding_projection_matrix(dir: &dyn FederationDirectory, suffix: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::malformed_row as mr;
        use crate::federation::types::device_class::{AGENT, LAPTOP, PHONE};
        use crate::federation::types::OccurrenceTransportBinding;
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use e2bind::{
            at, held, is_row, put, put_bind, put_voices, reason, revocation_voice, routes,
            transport_tag, Bind,
        };

        let identity = format!("proj-id-{suffix}");
        let occ = format!("proj-occ-{suffix}");
        for k in [&identity, &occ] {
            e2::put_key(dir, k, &["user"]).await;
        }
        let o = e2::kid(&occ);
        let now = e2bind::now_ms();
        let t = |mins: u64| now - mins * 60_000;

        // (1) The route is materialized from the landed bind.
        let (td1, d1) = transport_tag(0x10);
        let b1 = Bind::new(&identity, &identity, &occ, PHONE, t(60))
            .headed(dir)
            .await
            .with("transport_destination", td1);
        let v1 = b1.voices();
        assert!(
            is_row(&put_voices(dir, &v1).await, true),
            "I3325 (1) the bind lands"
        );
        let rows = routes(dir, &occ).await;
        assert_eq!(rows.len(), 1, "I3325 (1) exactly one projected route");
        let r = &rows[0];
        assert_eq!(r.occurrence_key_id, o);
        assert_eq!(r.transport_kind, OccurrenceTransportBinding::TRANSPORT_KIND);
        assert_eq!(
            r.destination, d1,
            "I3325 (1) the hash, canonical hex (#512)"
        );
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
        assert_eq!(r.asserted_at, at(t(60)));
        assert!(
            dir.list_signed_transport_destinations_for(&o)
                .await
                .unwrap()
                .is_empty(),
            "I3325 (1) a projected route never replicates on the route plane"
        );

        // (2) A newer bind supersedes in lockstep; an older one replayed
        // displaces nothing.
        let (td2, d2) = transport_tag(0x20);
        let b2 = Bind::new(&identity, &identity, &occ, PHONE, t(50))
            .headed(dir)
            .await
            .with("transport_destination", td2);
        assert!(is_row(&put_bind(dir, &b2).await, true), "I3325 (2)");
        let rows = routes(dir, &occ).await;
        assert_eq!(
            rows.len(),
            1,
            "I3325 (2) superseded in place, never a 2nd row"
        );
        assert_eq!(rows[0].destination, d2);
        assert!(
            is_row(&put_voices(dir, &v1).await, false),
            "I3325 (2) replay"
        );
        assert_eq!(
            routes(dir, &occ).await[0].destination,
            d2,
            "I3325 (2) the newest route wins"
        );

        // (3) De-projection: the occurrence's revocation (the roster
        // {identity, occ}, both voices) retires the route.
        put(
            dir,
            &revocation_voice(dir, &identity, &identity, &occ, t(40)).await,
        )
        .await
        .expect("I3325 (3) first revocation voice");
        let out = put(
            dir,
            &revocation_voice(dir, &occ, &identity, &occ, t(40)).await,
        )
        .await
        .expect("I3325 (3) second revocation voice");
        assert!(is_row(&out, true), "I3325 (3) {out:?}");
        assert!(
            routes(dir, &occ).await.is_empty(),
            "I3325 (3) the route is retired with its occurrence"
        );

        // (4) A NEWER bind revives the route.
        let (td3, d3) = transport_tag(0x30);
        let b3 = Bind::new(&identity, &identity, &occ, PHONE, t(30))
            .headed(dir)
            .await
            .with("transport_destination", td3);
        assert!(is_row(&put_bind(dir, &b3).await, true), "I3325 (4)");
        let rows = routes(dir, &occ).await;
        assert_eq!(rows.len(), 1, "I3325 (4) a newer bind revives the route");
        assert_eq!(rows[0].destination, d3);

        // I3326 — an agent: its own identity, its owner authoring.
        let owner = format!("proj-owner-{suffix}");
        let agent = format!("proj-agent-{suffix}");
        let agent_key = format!("proj-agent-key-{suffix}");
        e2::put_key(dir, &owner, &["user"]).await;
        e2::put_key(dir, &agent, &["agent"]).await;
        e2::put_key(dir, &agent_key, &["agent"]).await;
        for class in [AGENT, LAPTOP] {
            let under_person = Bind::new(&owner, &owner, &agent_key, class, t(25))
                .headed(dir)
                .await
                .with("transport_destination", transport_tag(0x41).0);
            let e = put(dir, &under_person.own_voice())
                .await
                .expect_err("I3326: an agent key under a person");
            assert_eq!(
                reason(&e),
                mr::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
                "I3326 ({class}): {e}"
            );
        }
        assert!(
            held(dir, &owner, &agent_key).await.is_none(),
            "I3326: nothing bound"
        );
        e2::put_agent_owner_binding(dir, &owner, &agent, t(40)).await;
        let b_agent = Bind::new(&owner, &agent, &agent_key, AGENT, t(20))
            .headed(dir)
            .await
            .with("transport_destination", transport_tag(0x40).0);
        assert!(
            is_row(&put_bind(dir, &b_agent).await, true),
            "I3326: the owner's statement and the agent key's own land the bind"
        );
        assert!(
            held(dir, &agent, &agent_key).await.is_some(),
            "I3326: bound under the agent's own identity"
        );
        assert!(
            routes(dir, &agent_key).await.is_empty(),
            "I3326: an agent's occurrence projects no route"
        );

        // I3327 — the window is half-open. A bind still in force projects its
        // route...
        let live_id = format!("proj-live-id-{suffix}");
        let live_occ = format!("proj-live-occ-{suffix}");
        let exp_id = format!("proj-exp-id-{suffix}");
        let exp_occ = format!("proj-exp-occ-{suffix}");
        for k in [&live_id, &live_occ, &exp_id, &exp_occ] {
            e2::put_key(dir, k, &["user"]).await;
        }
        let live = Bind::new(&live_id, &live_id, &live_occ, PHONE, t(10))
            .headed(dir)
            .await
            .until(now + 3_600_000)
            .with("transport_destination", transport_tag(0x50).0);
        assert!(is_row(&put_bind(dir, &live).await, true), "I3327 live bind");
        assert_eq!(
            routes(dir, &live_occ).await.len(),
            1,
            "I3327: a bind in force projects its route"
        );
        // ...and a bind whose `valid_until` has passed projects none.
        let expired = Bind::new(&exp_id, &exp_id, &exp_occ, PHONE, t(120))
            .headed(dir)
            .await
            .until(t(60))
            .with("transport_destination", transport_tag(0x51).0);
        put_bind(dir, &expired).await;
        assert!(
            routes(dir, &exp_occ).await.is_empty(),
            "I3327: an occurrence past its valid_until has no route"
        );
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

    /// v62.0.0 slice E1 (CIRISPersist#1274; CC rc20 3.3.6.2), rewritten in
    /// wave E8 onto the edition-2 bind — **the X-Wing matrix**, run on sqlite
    /// and postgres (`rc20_rules_invariants`). A node binds its own key (the
    /// self pair: one statement, `server`), carrying its transport
    /// destination and the X-Wing keys at the payload's top level; every
    /// refusal is the X-Wing rule's at the `identity:occurrence` door.
    ///
    /// - **I1872 / I3328** both members admit; the held statement the signed
    ///   occurrence listing serves is the one put, and its members read back
    ///   as 1216 bytes split 1184 / 32; a wrong length (1215, 1217, 0) refuses
    ///   `xwing_pubkey_wrong_length`; a member that is not a byte string
    ///   (text, `null`, a map) refuses `edition2_payload_invalid`.
    /// - **I1873 / I3329** the per-half reuse refusals, bytes 0..1184 and
    ///   1184..1216, against every other key on the row: the Reticulum link
    ///   x25519 and ed25519, the signer's own Ed25519, `encryption_pubkeys`
    ///   (both halves), and the other X-Wing key (named under the hop key's
    ///   token). The held bind never moves.
    /// - **I3330** two same-instant binds that differ only in an X-Wing key:
    ///   the LOWER row id holds (CC 3.5.1; nothing ranks by arrival, CC
    ///   2.7.2), in either arrival order; the exact replay is idempotent
    ///   (`Row`, `new = false`).
    /// - **I3331** (depends on O1's fix) the resolvers read the bind: a
    ///   non-seat node's `transit_xwing_pubkey_for` and
    ///   `onion_hop_xwing_pubkey_for` answer its held bind's keys.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn run_xwing_matrix(dir: &dyn FederationDirectory, suffix: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::malformed_row as mr;
        use crate::federation::types::device_class::SERVER;
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use ciris_verify_core::cde::Value;
        use e2bind::{
            encryption, is_row, map, payload_bytes, put, reason, routes, served, transport, Bind,
        };

        let relay = format!("xwing-relay-{suffix}");
        let relay_kid = e2::put_key(dir, &relay, &["node"]).await;
        let signer_ed = B64
            .decode(
                dir.lookup_public_key(&relay_kid)
                    .await
                    .unwrap()
                    .expect("the relay's key is held")
                    .pubkey_ed25519_base64,
            )
            .expect("the relay's Ed25519 half");
        let now = e2bind::now_ms();
        let t = |mins: u64| now - mins * 60_000;

        let xw = |m: &[u8], x: &[u8]| Value::Bytes([m, x].concat());
        let t_m = vec![0xA1u8; XWING_ML_KEM_768_LEN];
        let t_x = [0xA2u8; XWING_X25519_LEN];
        let h_m = vec![0xB1u8; XWING_ML_KEM_768_LEN];
        let h_x = [0xB2u8; XWING_X25519_LEN];
        let link = [0x55u8; 32];
        let ted = [0x56u8; 32];
        let enc_x = [0x57u8; 32];
        let enc_m = vec![0x58u8; XWING_ML_KEM_768_LEN];
        let (td, _) = transport(link, ted);
        // A node self's binds land without a roster count (no sibling rule
        // reads them), so one head for all of them is enough.
        let relay_head =
            crate::federation::edition2::occurrence::current_roster_head(dir, &e2::kid(&relay))
                .await
                .expect("the relay's roster head reads");
        let node_bind = |asserted_at_ms: u64| {
            Bind::new(&relay, &relay, &relay, SERVER, asserted_at_ms)
                .on_head(relay_head)
                .with("transport_destination", td.clone())
        };

        // I1872 / I3328 — both members admit and read back from the held
        // statement.
        let s1 = node_bind(t(60))
            .with(TRANSIT_XWING_PUBKEY_MEMBER, xw(&t_m, &t_x))
            .with(ONION_HOP_XWING_PUBKEY_MEMBER, xw(&h_m, &h_x))
            .own_voice();
        assert!(
            is_row(&put(dir, &s1).await.expect("I1872: the bind"), true),
            "I1872: a bind carrying both X-Wing keys lands"
        );
        let held = served(dir, &relay, &relay)
            .await
            .expect("I3328: the bind is served");
        assert_eq!(held, s1, "I3328: the held statement is the one put");
        let t_key = XWingPublicKey::from_bytes(
            &payload_bytes(&held, TRANSIT_XWING_PUBKEY_MEMBER).expect("I1872: transit key"),
        )
        .expect("I1872: 1216 bytes");
        assert_eq!(
            t_key.ml_kem_768(),
            t_m.as_slice(),
            "I1872: pk_M is bytes 0..1184"
        );
        assert_eq!(t_key.x25519(), &t_x[..], "I1872: pk_X is bytes 1184..1216");
        let h_key = XWingPublicKey::from_bytes(
            &payload_bytes(&held, ONION_HOP_XWING_PUBKEY_MEMBER).expect("I1872: hop key"),
        )
        .expect("I1872: 1216 bytes");
        assert_eq!(h_key.ml_kem_768(), h_m.as_slice());
        assert_eq!(h_key.x25519(), &h_x[..]);
        assert_eq!(
            routes(dir, &relay).await.len(),
            1,
            "I3328: the node's bind projects its route"
        );

        // I1872 — malformed members refuse by name; the held bind stands.
        for member_name in [TRANSIT_XWING_PUBKEY_MEMBER, ONION_HOP_XWING_PUBKEY_MEMBER] {
            for (what, v, why) in [
                (
                    "1215 bytes",
                    Value::Bytes(vec![7u8; 1215]),
                    mr::XWING_PUBKEY_WRONG_LENGTH,
                ),
                (
                    "1217 bytes",
                    Value::Bytes(vec![7u8; 1217]),
                    mr::XWING_PUBKEY_WRONG_LENGTH,
                ),
                (
                    "empty",
                    Value::Bytes(Vec::new()),
                    mr::XWING_PUBKEY_WRONG_LENGTH,
                ),
                ("null", Value::Null, mr::EDITION2_PAYLOAD_INVALID),
                (
                    "text",
                    Value::Text(B64.encode(vec![7u8; XWING_PUBKEY_LEN])),
                    mr::EDITION2_PAYLOAD_INVALID,
                ),
                (
                    "a map",
                    map(vec![("x25519", Value::Bytes(vec![0u8; 32]))]),
                    mr::EDITION2_PAYLOAD_INVALID,
                ),
            ] {
                let st = node_bind(t(55)).with(member_name, v).own_voice();
                let e = put(dir, &st).await.expect_err(what);
                assert_eq!(reason(&e), why, "I1872 {member_name} {what}: {e}");
            }
        }

        // I1873 / I3329 — per-half reuse against every other key on the row.
        /// `(what, member, key, extra members, refusal reason)`.
        type ReuseCase<'a> = (
            &'a str,
            &'static str,
            Value,
            Vec<(&'static str, Value)>,
            &'a str,
        );
        let with_transit = || vec![(TRANSIT_XWING_PUBKEY_MEMBER, xw(&t_m, &t_x))];
        let cases: Vec<ReuseCase> = vec![
            (
                "transit pk_M = encryption_pubkeys.ml_kem_768",
                TRANSIT_XWING_PUBKEY_MEMBER,
                xw(&enc_m, &t_x),
                vec![],
                mr::TRANSIT_XWING_ML_KEM_768_REUSE,
            ),
            (
                "transit pk_X = encryption_pubkeys.x25519",
                TRANSIT_XWING_PUBKEY_MEMBER,
                xw(&t_m, &enc_x),
                vec![],
                mr::TRANSIT_XWING_X25519_REUSE,
            ),
            (
                "transit pk_X = the link x25519",
                TRANSIT_XWING_PUBKEY_MEMBER,
                xw(&t_m, &link),
                vec![],
                mr::TRANSIT_XWING_X25519_REUSE,
            ),
            (
                "transit pk_X = the link ed25519",
                TRANSIT_XWING_PUBKEY_MEMBER,
                xw(&t_m, &ted),
                vec![],
                mr::TRANSIT_XWING_X25519_REUSE,
            ),
            (
                "transit pk_X = the signer's ed25519",
                TRANSIT_XWING_PUBKEY_MEMBER,
                xw(&t_m, &signer_ed),
                vec![],
                mr::TRANSIT_XWING_X25519_REUSE,
            ),
            (
                "hop pk_M = the transit pk_M",
                ONION_HOP_XWING_PUBKEY_MEMBER,
                xw(&t_m, &h_x),
                with_transit(),
                mr::ONION_HOP_ML_KEM_768_REUSE,
            ),
            (
                "hop pk_X = the transit pk_X",
                ONION_HOP_XWING_PUBKEY_MEMBER,
                xw(&h_m, &t_x),
                with_transit(),
                mr::ONION_HOP_X25519_REUSE,
            ),
            (
                "hop pk_M = encryption_pubkeys.ml_kem_768",
                ONION_HOP_XWING_PUBKEY_MEMBER,
                xw(&enc_m, &h_x),
                vec![],
                mr::ONION_HOP_ML_KEM_768_REUSE,
            ),
            (
                "hop pk_X = encryption_pubkeys.x25519",
                ONION_HOP_XWING_PUBKEY_MEMBER,
                xw(&h_m, &enc_x),
                vec![],
                mr::ONION_HOP_X25519_REUSE,
            ),
            (
                "hop pk_X = the link x25519",
                ONION_HOP_XWING_PUBKEY_MEMBER,
                xw(&h_m, &link),
                vec![],
                mr::ONION_HOP_X25519_REUSE,
            ),
        ];
        for (what, member_name, key, extra, why) in cases {
            let mut b = node_bind(t(50)).with("encryption_pubkeys", encryption(enc_x, &enc_m));
            for (k, v) in extra {
                b = b.with(k, v);
            }
            let st = b.with(member_name, key).own_voice();
            let e = put(dir, &st).await.expect_err(what);
            assert_eq!(reason(&e), why, "I1873 {what}: {e}");
        }
        assert_eq!(
            served(dir, &relay, &relay).await.as_deref(),
            Some(s1.as_slice()),
            "I1872/I1873: refusals leave the held bind untouched"
        );

        // The control: separated halves on a row carrying every other key
        // land, and supersede.
        let ok = node_bind(t(40))
            .with("encryption_pubkeys", encryption(enc_x, &enc_m))
            .with(TRANSIT_XWING_PUBKEY_MEMBER, xw(&t_m, &t_x))
            .with(ONION_HOP_XWING_PUBKEY_MEMBER, xw(&h_m, &h_x))
            .own_voice();
        assert!(
            is_row(&put(dir, &ok).await.expect("I1873 control"), true),
            "I1873 control: separated keys land"
        );
        assert_eq!(
            served(dir, &relay, &relay).await.as_deref(),
            Some(ok.as_slice())
        );

        // I3330 — two binds of the same node at the same instant that differ
        // only in an X-Wing key: the LOWER row id holds (CC 3.5.1; nothing
        // ranks by arrival, CC 2.7.2), whichever arrives first. The exact
        // replay of a held statement is idempotent.
        let same_instant = |at: u64, transit_x: [u8; 32]| {
            node_bind(at)
                .with("encryption_pubkeys", encryption(enc_x, &enc_m))
                .with(TRANSIT_XWING_PUBKEY_MEMBER, xw(&t_m, &transit_x))
                .with(ONION_HOP_XWING_PUBKEY_MEMBER, xw(&h_m, &h_x))
                .own_voice()
        };
        let lower = |a: &Vec<u8>, b: &Vec<u8>| -> Vec<u8> {
            if e2::row_id_of(a) < e2::row_id_of(b) {
                a.clone()
            } else {
                b.clone()
            }
        };
        // (a) The held bind first, the fork second.
        let fork = same_instant(t(40), [0xA3u8; 32]);
        put(dir, &fork)
            .await
            .expect("I3330: the fork is a well-formed bind");
        assert_eq!(
            served(dir, &relay, &relay).await,
            Some(lower(&ok, &fork)),
            "I3330 (held first): the lower row id holds"
        );
        assert!(
            is_row(&put(dir, &ok).await.expect("I3330: replay"), false),
            "I3330: the exact replay is Row, not new"
        );
        // (b) The fork first, the other second (a later instant, so both are
        // newer than (a)).
        let fork2 = same_instant(t(30), [0xA4u8; 32]);
        let other2 = same_instant(t(30), t_x);
        put(dir, &fork2)
            .await
            .expect("I3330: the second fork is a well-formed bind");
        put(dir, &other2)
            .await
            .expect("I3330: the second pair's other bind is well-formed");
        let winner = lower(&fork2, &other2);
        assert_eq!(
            served(dir, &relay, &relay).await,
            Some(winner.clone()),
            "I3330 (fork first): the lower row id holds, whatever the arrival order"
        );
        let winner_transit = payload_bytes(&winner, TRANSIT_XWING_PUBKEY_MEMBER)
            .expect("I3330: the winner carries the transit key");

        // I3331 (depends on O1's fix: the resolvers read edition-2 binds) — a
        // node that is not a seat: its held bind's X-Wing keys resolve, the
        // cross-row rule passed (every other key on the row is distinct).
        assert_eq!(
            transit_xwing_pubkey_for(dir, &relay_kid)
                .await
                .unwrap()
                .map(|k| k.as_bytes().to_vec()),
            Some(winner_transit),
            "I3331: a non-seat's held bind's transit key resolves"
        );
        // v62.0.0 (BIND-3; CC 5.4.6 "relayable exactly when its
        // owner-binding is announced") — no relay hop until its owner
        // announces it (an explicit fixture step).
        assert_eq!(
            crate::federation::edition2::occurrence::onion_hop_xwing_pubkey_for(dir, &relay_kid)
                .await
                .unwrap(),
            None,
            "I3331: an unannounced non-seat is no onion hop"
        );
        let relay_owner = format!("xwing-relay-owner-{suffix}");
        e2::put_key(dir, &relay_owner, &["user"]).await;
        crate::federation::edition2::fixture_occurrence::announce_node_owner_seeds(
            dir,
            &relay_owner,
            &relay,
            now - 60_000,
        )
        .await;
        assert_eq!(
            crate::federation::edition2::occurrence::onion_hop_xwing_pubkey_for(dir, &relay_kid)
                .await
                .unwrap()
                .map(|k| k.as_bytes().to_vec()),
            Some([h_m.as_slice(), &h_x[..]].concat()),
            "I3331: announced, a non-seat's bind onion hop key resolves"
        );
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
        signature: crate::federation::types::RetiredPairSignature,
    }

    /// The fixed pair-bearing row the KAT pins. The projection is PARSED from
    /// the envelope, as a node builds it, so a projection field that picked
    /// the pair up would show in the bytes.
    fn kat_row() -> SignedTransportDestination {
        let row = TransportDestination {
            occurrence_key_id: "kat-relay".into(),
            transport_kind: "reticulum".into(),
            destination: "kat-dest".into(),
            // v61 (CC 2.6.2) — a millisecond the v55 reader's chrono
            // default also writes with three digits, so the two serializations
            // agree. A whole-second instant does not: chrono writes `…:00Z`
            // and v61 writes `…:00.000Z`, which is the canonical form.
            asserted_at: "2026-10-13T00:00:00.123Z".parse().unwrap(),
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
            signature: crate::federation::types::RetiredPairSignature {
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
    ///
    /// v61 (CC 2.6.2) — re-pinned for the KAT's instant moving to
    /// `2026-10-13T00:00:00.123Z`. This value was read from the code's own
    /// output at that change, not recomputed independently; the v56 lockstep
    /// property this pins (the projection carries nothing of the pair) is
    /// unchanged and is asserted below.
    const KAT_CONTENT_HASH: &str =
        "46e8e4057a9130aff67c2aa32f4d7892e97a4f1ddd9e959e841edf86f4c68b60";

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
