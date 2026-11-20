//! Cold-start binding-rooting primitive (CIRISPersist#94, v1.12.0).
//!
//! # What this module is
//!
//! This is the **CIRIS 3.0 critical-path node**: it replaces
//! trust-on-first-use on CIRISEdge's `PeerResolver` cold-start path.
//! When a peer is seen for the first time, the resolver has a claimed
//! `(key_id, pubkey)` binding off the wire. Rather than accepting it
//! ("trust on first use"), the resolver calls [`root_binding`], which:
//!
//!  1. Confirms the `key_id` resolves to a real `federation_keys`
//!     directory row.
//!  2. Confirms the claimed Ed25519 pubkey matches that row's
//!     `pubkey_ed25519_base64`.
//!  3. Walks that row's **recursive-provenance chain** to the steward
//!     bootstrap, verifying each link's scrub-signature cryptographically.
//!
//! The result is a typed [`RootingVerdict`] — `Confirmed` or
//! `Rejected` with a typed [`RootingRejection`]. There is no third
//! state (MISSION.md §1.6 — fail-honest).
//!
//! # The recursive-provenance four-tuple
//!
//! Every `federation_keys` row carries the v0.1.3 scrub-signing
//! four-tuple (`docs/FEDERATION_DIRECTORY.md` §"Schema sketch"):
//!
//!  * `original_content_hash` — `sha256(canonical(registration_envelope))`,
//!    the bytes the scrub-signature was computed over.
//!  * `scrub_signature_classical` (+ `scrub_signature_pqc`) — the
//!    Ed25519 (and, once the cold-path PQC sign completes, ML-DSA-65)
//!    signature over `original_content_hash`.
//!  * `scrub_key_id` — the **parent**: the `key_id` of the row that
//!    signed THIS row. A bootstrap row is self-signed
//!    (`scrub_key_id == key_id`).
//!  * `scrub_timestamp` — when the scrub-signature was issued.
//!
//! "Every row signed by another, terminating at the steward
//! bootstrap" is the literal walk: follow `scrub_key_id` parent-ward,
//! verifying each link's signature against the parent row's pubkey,
//! until a self-signed `identity_type == "steward"` row is reached.
//!
//! # Crypto goes through CIRISVerify
//!
//! Each link's scrub-signature is verified through
//! `crate::verify::hybrid::verify_hybrid` (deleted v62.0.0) — the existing hybrid
//! Ed25519 + ML-DSA-65 verify path, which delegates to
//! `ciris_crypto`. This module never rolls its own crypto
//! (MISSION.md §1.4 — the crypto-through-CIRISVerify invariant).
//!
//! # Not a trust oracle
//!
//! A `Confirmed` verdict states **"this `key_id`'s claimed binding is
//! rooted in the directory's recursive-provenance chain, which
//! terminates at a steward bootstrap"**. It authenticates
//! *origin / provenance*. It does **not** state "this key is
//! trusted" — trust is a policy decision the consumer composes by
//! walking attestations / revocations / trust grants. Storing or
//! returning a provenance fact never *confers* trust (MISSION.md
//! §1.4 — the apophatic bound; the federation-wide
//! authenticate-origin-never-confer-trust invariant).
//!
//! # Scope (Finding G — decided)
//!
//! This primitive roots **federation-key bindings (trust anchors)
//! only**. A transport identity is routing-only — it is NOT a signed
//! `federation_keys`-class row and is **outside** the
//! recursive-provenance chain. Transport identities are never rooted
//! here and never walked into the chain.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.
// each closure's typed return signature load-bearing for error

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{FederationDirectory, KeyRecord};
// #465: the scrub-signature crypto now routes through verify's provenance walk
// (verify_provenance_chain_with_policy_and_terminus), so rooting no longer uses
// persist's verify_hybrid / HybridPolicy directly.

/// Maximum provenance-chain depth before the walk gives up and
/// rejects with [`RootingRejection::OverDepth`].
///
/// The real federation provenance graph is shallow — a row chains
/// `key → intermediate steward → bootstrap steward`, rarely more than
/// a handful of hops. This cap is a safety bound against a
/// maliciously- or accidentally-constructed long chain, not a real
/// operational limit. Cycle detection ([`RootingRejection::CycleDetected`])
/// catches loops independently; this catches an unbounded *acyclic*
/// chain.
pub const MAX_PROVENANCE_DEPTH: usize = 64;

/// `identity_type` values that mark a self-signed row as a legitimate
/// **trust-root terminus** for the provenance walk. Historically only
/// `steward`; CIRISPersist#344 (v12.0) adds `accord_holder` because the
/// HUMANITY_ACCORD holders (A1/B1/C1) ARE the trusted primitive keyset —
/// the mesh roots to them directly.
///
/// **This identity check is only a coarse sanity gate.** The load-bearing
/// trust decision is [`root_binding`]'s **anchor-membership** check: the
/// terminus's Ed25519 pubkey MUST be one of the pinned accord-holder anchor
/// keys ([`ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor`]).
/// A self-signed `steward`/`accord_holder` row that a peer merely *asserts*
/// (pubkey not in the anchor) is rejected with
/// [`RootingRejection::TerminusNotInAnchor`] — closing the spoof-a-steward
/// gap that an identity-type-only check leaves open.
const STEWARD_IDENTITY_TYPE: &str = super::types::identity_type::STEWARD;
const ACCORD_HOLDER_IDENTITY_TYPE: &str = super::types::identity_type::ACCORD_HOLDER;

/// `true` iff `identity_type` (a CEG 1.0-RC5 §7.0.1 comma-joined role SET,
/// read by set-membership — e.g. `"steward,accord_holder"`) carries a
/// trust-root role (`steward` or `accord_holder`).
fn is_trusted_root_identity(identity_type: &str) -> bool {
    identity_type
        .split(',')
        .any(|role| role == STEWARD_IDENTITY_TYPE || role == ACCORD_HOLDER_IDENTITY_TYPE)
}

// ─────────────────────────────────────────────────────────────────────
// Cross-repo contract types — ratification surface
// ─────────────────────────────────────────────────────────────────────

/// One link in a row's recursive-provenance chain — the v0.1.3
/// scrub-signing four-tuple plus the identity fields a verifier needs
/// to recognize a steward bootstrap.
///
/// # Cross-repo contract
///
/// **This type, [`ProvenanceChain`], [`RootingVerdict`], and
/// [`RootingRejection`] are the CIRISPersist#94 ratification
/// surface.** CIRISVerify WS-4 verifies the chain verify-side off its
/// registry-local `trusted_primitive_keys`; CIRISEdge #28 Phase 3
/// builds its `PeerResolver` cold-start path against
/// [`RootingVerdict`]. Field names + JSON shape are the contract —
/// changing them is a cross-repo coordination event.
///
/// One [`ProvenanceLink`] corresponds to exactly one
/// `federation_keys` row. The four-tuple is:
/// `original_content_hash`, `scrub_signature_classical`
/// (+ `scrub_signature_pqc`), `scrub_key_id`, `scrub_timestamp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceLink {
    /// `key_id` of the `federation_keys` row this link describes.
    pub key_id: String,
    /// Row's Ed25519 public key, base64 standard. The link's
    /// signature is verified against the *parent's* pubkey, but this
    /// field lets a verifier reconstruct the whole walk independently.
    pub pubkey_ed25519_base64: String,
    /// Row's ML-DSA-65 public key, base64 standard. `None` while the
    /// row is hybrid-pending (cold-path PQC sign not yet complete).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// `identity_type` of the row (`agent` / `primitive` / `steward` /
    /// `partner`). A verifier checks this is `steward` on the
    /// terminating self-signed link.
    pub identity_type: String,
    /// `identity_ref` of the row (steward role / primitive name / …).
    pub identity_ref: String,
    /// Four-tuple #1 — `sha256(canonical(registration_envelope))`,
    /// hex-encoded. Cross-checked against the recomputed canonical hash;
    /// NOT itself the signed bytes (see [`Self::registration_envelope`]).
    pub original_content_hash: String,
    /// The row's `registration_envelope` — the object the scrub-signature
    /// actually covers (via its JCS canonicalization). CIRISPersist#344:
    /// the signature is over `canonical(registration_envelope)`, matching
    /// the producer (`ciris_verify_core::produce_self_key_record`,
    /// `sign_bound(&canonical)`) and the write-path
    /// [`verify_key_registration`](super::register) — NOT over the hash.
    /// `#[serde(default)]` for back-compat of older serialized chains
    /// (which then cannot re-verify signatures, only structure).
    #[serde(default)]
    pub registration_envelope: serde_json::Value,
    /// Four-tuple #2a — Ed25519 scrub-signature over
    /// `canonical(registration_envelope)`, base64 standard. Always present.
    pub scrub_signature_classical: String,
    /// Four-tuple #2b — ML-DSA-65 scrub-signature over
    /// `canonical || classical_sig` (bound signature), base64 standard.
    /// `None` while the row is hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// Four-tuple #3 — `key_id` of the parent row that signed this
    /// row. Equal to [`Self::key_id`] iff this is a self-signed
    /// bootstrap link.
    pub scrub_key_id: String,
    /// Four-tuple #4 — RFC 3339 timestamp the scrub-signature was
    /// issued.
    pub scrub_timestamp: String,
    /// `true` iff this link is the self-signed bootstrap
    /// (`scrub_key_id == key_id`).
    pub is_self_signed: bool,
}

impl ProvenanceLink {
    /// Build a [`ProvenanceLink`] from a directory [`KeyRecord`].
    fn from_record(record: &KeyRecord) -> Self {
        ProvenanceLink {
            key_id: record.key_id.clone(),
            pubkey_ed25519_base64: record.pubkey_ed25519_base64.clone(),
            pubkey_ml_dsa_65_base64: record.pubkey_ml_dsa_65_base64.clone(),
            identity_type: record.identity_type.clone(),
            identity_ref: record.identity_ref.clone(),
            original_content_hash: record.original_content_hash.clone(),
            registration_envelope: record.registration_envelope.clone(),
            scrub_signature_classical: record.scrub_signature_classical.clone(),
            scrub_signature_pqc: record.scrub_signature_pqc.clone(),
            scrub_key_id: record.scrub_key_id.clone(),
            scrub_timestamp: record.scrub_timestamp.to_rfc3339(),
            is_self_signed: record.scrub_key_id == record.key_id,
        }
    }
}

/// A `federation_keys` row plus its full recursive-provenance chain —
/// the **verify-consumable provenance read** (CIRISVerify WS-4).
///
/// # Cross-repo contract
///
/// Returned by [`provenance_chain`]. CIRISVerify verifies the chain
/// verify-side: it walks [`Self::chain`] from index 0 (the queried
/// row) to the last element (the steward bootstrap), recomputing each
/// link's signature against the next link's pubkey, then checks the
/// bootstrap link against its registry-local `trusted_primitive_keys`
/// anchor. Persist's own verification verdict is reported separately
/// by [`root_binding`]; this read is the *raw material* for an
/// independent verify-side check.
///
/// `chain[0].key_id == queried_key_id`. `chain` is ordered
/// leaf → root: `chain[i].scrub_key_id == chain[i+1].key_id` for
/// every `i < chain.len() - 1`, and the final element is self-signed
/// (`is_self_signed == true`).
///
/// **This read does not itself verify signatures** — it returns the
/// chain so the verifier can. (Persist's verifying counterpart is
/// [`root_binding`].) If the chain cannot be assembled (unknown
/// `key_id`, a `scrub_key_id` pointing at a missing row, or a cycle),
/// [`provenance_chain`] returns a [`RootingRejection`] instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceChain {
    /// The `key_id` the chain was assembled for. Equals
    /// `chain[0].key_id`.
    pub key_id: String,
    /// Leaf → root ordered links. First element is the queried row;
    /// last element is the self-signed steward bootstrap.
    pub chain: Vec<ProvenanceLink>,
    /// `true` iff the final link is a self-signed row whose
    /// `identity_type == "steward"`. When `false`, the chain
    /// structurally terminates somewhere other than a steward
    /// bootstrap and a verifier must treat it as unrooted.
    pub terminates_at_steward_bootstrap: bool,
}

/// Typed reason a [`RootingVerdict`] is `Rejected`.
///
/// # Cross-repo contract
///
/// Part of the CIRISPersist#94 ratification surface. Every variant is
/// a distinct, machine-actionable failure — CIRISEdge's resolver and
/// CIRISVerify branch on the variant. `serde` tag is the variant
/// name; the payload carries the offending detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RootingRejection {
    /// The queried `key_id` does not resolve to any `federation_keys`
    /// directory row. (Replaces TOFU's "accept anything" — an unknown
    /// key is rejected, not provisionally trusted.)
    UnknownKeyId {
        /// The `key_id` that was not found.
        key_id: String,
    },
    /// The `key_id` resolves to a row, but the claimed Ed25519 pubkey
    /// does not match the row's `pubkey_ed25519_base64`.
    PubkeyMismatch {
        /// The `key_id` whose binding was being confirmed.
        key_id: String,
        /// The Ed25519 pubkey the caller claimed (base64).
        claimed_pubkey_ed25519_base64: String,
        /// The Ed25519 pubkey the directory row actually holds.
        directory_pubkey_ed25519_base64: String,
    },
    /// A row in the provenance walk names a `scrub_key_id` that does
    /// not resolve to any `federation_keys` row — the chain is broken.
    BrokenProvenanceLink {
        /// The row whose parent reference dangles.
        key_id: String,
        /// The `scrub_key_id` that pointed at a missing row.
        missing_parent_key_id: String,
    },
    /// A link's scrub-signature did not verify against the parent
    /// row's pubkey (or a self-signed link did not verify against its
    /// own pubkey). The chain is cryptographically unsound.
    UnsignedProvenanceLink {
        /// The row whose scrub-signature failed to verify.
        key_id: String,
        /// The `key_id` whose pubkey the signature was checked
        /// against (the parent, or `key_id` itself when self-signed).
        signed_by_key_id: String,
        /// Stable error token from the verify path.
        detail: String,
    },
    /// The walk reached a self-signed row, but that row's
    /// `identity_type` carries neither a `steward` nor an
    /// `accord_holder` role — the chain terminates somewhere other than
    /// a trust-root bootstrap.
    NotRootedAtSteward {
        /// The self-signed row the chain terminated at.
        key_id: String,
        /// That row's `identity_type` (no trust-root role).
        identity_type: String,
    },
    /// The chain terminated at a self-signed trust-root-typed row whose
    /// Ed25519 pubkey is **not** one of the pinned accord-holder anchor
    /// keys (CIRISPersist#344). This is the load-bearing anti-spoof gate:
    /// an identity-type check alone would let a peer root to a
    /// `steward`/`accord_holder` row it merely self-asserted; requiring
    /// the terminus pubkey ∈ the pinned anchor means only the real
    /// HUMANITY_ACCORD holders (A1/B1/C1) — whose keys a peer cannot
    /// forge — are valid roots.
    TerminusNotInAnchor {
        /// The self-signed terminus row.
        key_id: String,
        /// Its Ed25519 pubkey (base64) — absent from the trusted anchor.
        terminus_pubkey_ed25519_base64: String,
    },
    /// A `key_id` was encountered twice on the same walk — the
    /// provenance graph contains a cycle. Rejected rather than looped.
    CycleDetected {
        /// The `key_id` seen for the second time.
        key_id: String,
    },
    /// The walk exceeded [`MAX_PROVENANCE_DEPTH`] hops without
    /// reaching a self-signed bootstrap — an unbounded acyclic chain.
    OverDepth {
        /// The depth cap that was hit.
        max_depth: usize,
    },
    /// A directory backend call failed mid-walk (DB error, etc.).
    /// Distinct from the structural / cryptographic rejections — a
    /// transient backend fault, not a statement about the binding.
    /// Still a rejection: fail-honest, never "assume OK".
    DirectoryError {
        /// Backend error string.
        detail: String,
    },
}

impl RootingRejection {
    /// Stable string-token for telemetry / structured logging.
    /// Mirrors the `kind()` convention on persist's other error
    /// types (THREAT_MODEL.md AV-15).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::UnknownKeyId { .. } => "rooting_unknown_key_id",
            Self::PubkeyMismatch { .. } => "rooting_pubkey_mismatch",
            Self::BrokenProvenanceLink { .. } => "rooting_broken_provenance_link",
            Self::UnsignedProvenanceLink { .. } => "rooting_unsigned_provenance_link",
            Self::NotRootedAtSteward { .. } => "rooting_not_rooted_at_steward",
            Self::TerminusNotInAnchor { .. } => "rooting_terminus_not_in_anchor",
            Self::CycleDetected { .. } => "rooting_cycle_detected",
            Self::OverDepth { .. } => "rooting_over_depth",
            Self::DirectoryError { .. } => "rooting_directory_error",
        }
    }
}

/// Typed verdict from [`root_binding`] — the cold-start binding-rooting
/// result. **There are exactly two states** (MISSION.md §1.6 —
/// fail-honest; no silent pass, no third state).
///
/// # Cross-repo contract
///
/// The CIRISPersist#94 ratification surface. CIRISEdge's
/// `PeerResolver` matches on this to decide whether a cold-start peer
/// binding is rooted; CIRISVerify WS-4 cross-checks it against the
/// chain from [`provenance_chain`].
///
/// # Not a trust statement
///
/// `Confirmed` means **the claimed binding is rooted in the
/// directory's recursive-provenance chain, terminating at a steward
/// bootstrap** — it authenticates origin/provenance. It is NOT "this
/// key is trusted" (MISSION.md §1.4). A consumer still composes trust
/// policy (attestations, revocations, trust grants) on top.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum RootingVerdict {
    /// The `key_id` resolves to a directory row, the claimed Ed25519
    /// pubkey matches it, and the recursive-provenance chain verifies
    /// — every link's scrub-signature checks out — all the way up to
    /// a self-signed steward bootstrap.
    Confirmed {
        /// The full verified provenance chain, leaf → root. The last
        /// element is the steward bootstrap. Carried so the caller
        /// can hand it to CIRISVerify / cache it / audit it without
        /// a second directory round-trip.
        chain: ProvenanceChain,
    },
    /// The binding could not be rooted. See [`RootingRejection`] for
    /// the typed cause. The caller MUST NOT treat a `Rejected`
    /// binding as provisionally trusted — that would reintroduce the
    /// trust-on-first-use behavior this primitive replaces.
    Rejected {
        /// The typed rejection reason.
        #[serde(flatten)]
        rejection: RootingRejection,
    },
}

impl RootingVerdict {
    /// `true` iff this verdict is [`RootingVerdict::Confirmed`].
    pub fn is_confirmed(&self) -> bool {
        matches!(self, RootingVerdict::Confirmed { .. })
    }

    /// Borrow the verified chain when `Confirmed`; `None` otherwise.
    pub fn chain(&self) -> Option<&ProvenanceChain> {
        match self {
            RootingVerdict::Confirmed { chain } => Some(chain),
            RootingVerdict::Rejected { .. } => None,
        }
    }

    /// Borrow the rejection reason when `Rejected`; `None` otherwise.
    pub fn rejection(&self) -> Option<&RootingRejection> {
        match self {
            RootingVerdict::Rejected { rejection } => Some(rejection),
            RootingVerdict::Confirmed { .. } => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Chain assembly — the verify-consumable read
// ─────────────────────────────────────────────────────────────────────

/// Assemble the recursive-provenance chain for `key_id` — the
/// **verify-consumable provenance read** (CIRISVerify WS-4).
///
/// Walks `scrub_key_id` parent-ward from the queried row, collecting
/// one [`ProvenanceLink`] per `federation_keys` row, until a
/// self-signed row is reached. Returns the row plus its full chain so
/// CIRISVerify can verify the chain verify-side off its
/// registry-local `trusted_primitive_keys`.
///
/// **This read does not verify signatures** — it returns the raw
/// chain. The verifying counterpart is [`root_binding`].
///
/// # Errors
///
/// Returns `Err(RootingRejection)` when the chain cannot be assembled:
///
///  * [`RootingRejection::UnknownKeyId`] — `key_id` resolves to no row.
///  * [`RootingRejection::BrokenProvenanceLink`] — a `scrub_key_id`
///    points at a missing row.
///  * [`RootingRejection::CycleDetected`] — a `key_id` repeats.
///  * [`RootingRejection::OverDepth`] — more than
///    [`MAX_PROVENANCE_DEPTH`] hops without a self-signed terminus.
///  * [`RootingRejection::DirectoryError`] — a backend call failed.
///
/// A successfully-assembled chain whose terminus is self-signed but
/// **not** a steward is NOT an error here — it is returned with
/// [`ProvenanceChain::terminates_at_steward_bootstrap`] set to
/// `false`. The structural walk succeeded; whether that terminus is
/// an acceptable root is a verify-side judgment. [`root_binding`]
/// treats it as [`RootingRejection::NotRootedAtSteward`].
pub async fn provenance_chain<F>(
    directory: &F,
    key_id: &str,
) -> Result<ProvenanceChain, RootingRejection>
where
    F: FederationDirectory + ?Sized,
{
    let mut chain: Vec<ProvenanceLink> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut current = key_id.to_owned();

    loop {
        if chain.len() >= MAX_PROVENANCE_DEPTH {
            return Err(RootingRejection::OverDepth {
                max_depth: MAX_PROVENANCE_DEPTH,
            });
        }

        // Cycle guard — a key_id seen twice on the same walk.
        if !seen.insert(current.clone()) {
            return Err(RootingRejection::CycleDetected { key_id: current });
        }

        let record = directory.lookup_public_key(&current).await.map_err(|e| {
            RootingRejection::DirectoryError {
                detail: format!("{e}"),
            }
        })?;

        let record = match record {
            Some(r) => r,
            None => {
                // The very first lookup missing → unknown key_id.
                // A later lookup missing → a dangling parent ref.
                return Err(if chain.is_empty() {
                    RootingRejection::UnknownKeyId { key_id: current }
                } else {
                    // The previous link named `current` as its parent.
                    RootingRejection::BrokenProvenanceLink {
                        key_id: chain.last().map(|l| l.key_id.clone()).unwrap_or_default(),
                        missing_parent_key_id: current,
                    }
                });
            }
        };

        let link = ProvenanceLink::from_record(&record);
        let is_self_signed = link.is_self_signed;
        let parent = link.scrub_key_id.clone();
        let terminus_identity_type = link.identity_type.clone();
        chain.push(link);

        if is_self_signed {
            // CIRISPersist#344: a trust-root terminus carries `steward` OR
            // `accord_holder` (set-membership, comma-joined roles). The
            // *pubkey-in-anchor* gate in `root_binding` is what actually
            // pins trust; this only classifies the terminus shape.
            let terminates_at_steward_bootstrap = is_trusted_root_identity(&terminus_identity_type);
            return Ok(ProvenanceChain {
                key_id: key_id.to_owned(),
                chain,
                terminates_at_steward_bootstrap,
            });
        }

        current = parent;
    }
}

// ─────────────────────────────────────────────────────────────────────
// root_binding — the cold-start binding-rooting primitive
// ─────────────────────────────────────────────────────────────────────

/// v47.4.0 (CIRISPersist#805) — the tracing target a rooting rejection is
/// reported on where the verdict is produced.
pub const ROOTING_LOG_TARGET: &str = "ciris_persist::rooting";

/// Cold-start binding-rooting primitive (CIRISPersist#94).
///
/// On first contact with a federation peer, confirm the claimed
/// `(key_id, pubkey)` binding against the `federation_keys` directory
/// and verify the row's recursive-provenance chain up to a **pinned
/// trust-root** bootstrap. **This replaces trust-on-first-use** —
/// CIRISEdge's `PeerResolver` calls it on its cold-start path.
///
/// This wrapper pins the trusted terminus anchor to the accord holders of the
/// INGESTED genesis (the Ed25519 halves of the composite keys
/// `edition2::genesis::genesis_in_force` seats) — the accord holders ARE the
/// mesh's trusted primitive keyset (CIRISPersist#344). v62.0.0 (C5-fix1;
/// ceremony gap 1): Verify's baked A1/B1/C1 keyset
/// (`accord_holder_bootstrap_anchor`) no longer anchors anything; a node that
/// holds no genesis has an EMPTY anchor and every binding is `Rejected`. Use
/// [`root_binding_anchored`] to supply a different anchor (tests).
///
/// Returns [`RootingVerdict::Confirmed`] iff ALL hold:
///
///  1. `key_id` resolves to a `federation_keys` directory row.
///  2. `claimed_pubkey_ed25519_base64` equals that row's
///     `pubkey_ed25519_base64` (exact string match — both are base64
///     standard of the 32 raw bytes).
///  3. The recursive-provenance chain assembles (no break, no cycle,
///     within depth) and terminates at a **self-signed** row carrying a
///     trust-root role (`steward` or `accord_holder`).
///  4. **The terminus's Ed25519 pubkey is one of the pinned anchor keys**
///     — the load-bearing anti-spoof gate (step 3 is only a coarse
///     identity-shape check; this is what actually pins trust to the
///     un-forgeable accord holders).
///  5. Every link's scrub-signature verifies cryptographically: each
///     row's `scrub_signature_*` over its `original_content_hash`,
///     checked against the **parent** row's pubkey (the self-signed
///     bootstrap is checked against its own pubkey).
///
/// Otherwise returns [`RootingVerdict::Rejected`] with the typed
/// [`RootingRejection`]. No third state (MISSION.md §1.6).
///
/// # Crypto path
///
/// Each link's signature is verified by DELEGATING to CIRISVerify's
/// provenance walk (CIRISPersist#465) — never persist-local crypto. The
/// verify policy is
/// [`ciris_verify_core::threshold::HybridPolicy::RequireHybrid`]: EVERY
/// link must carry a valid bound ML-DSA-65 scrub-signature, and a
/// classical-only link is REJECTED as
/// [`RootingRejection::UnsignedProvenanceLink`].
///
/// **Doc correction (v37.0.0):** this paragraph claimed
/// `HybridPolicy::Ed25519Fallback` — "a hybrid-pending link is verified
/// on its Ed25519 signature alone" — which has been false since #465
/// tightened the walk to `RequireHybrid` (see the inline comment at the
/// delegation site). The stale text described a classical-only link as
/// rootable when the gate refuses it, which is precisely backwards for a
/// federation binding gate (F-AV-14 / AV-8). Corrected during the v37.0.0
/// policy sweep; the code was already correct and did not change.
///
/// # Not a trust statement
///
/// See [`RootingVerdict`] — `Confirmed` authenticates provenance, it
/// does not confer trust.
pub async fn root_binding<F>(
    directory: &F,
    key_id: &str,
    claimed_pubkey_ed25519_base64: &str,
) -> RootingVerdict
where
    F: FederationDirectory + ?Sized,
{
    // Secure by default: the trusted anchor is the accord holders of the
    // ingested genesis. Every existing caller (CIRISEdge's cold-start
    // announce path) therefore gets anchor enforcement with no code change —
    // the terminus MUST be one of the genesis's accord holders, not any
    // self-signed steward a peer asserts. No genesis held (or a store that
    // cannot answer) ⇒ the empty anchor ⇒ `Rejected`: fail closed. Tests
    // inject their own anchor via [`root_binding_anchored`].
    let anchor: Vec<[u8; 32]> = match super::edition2::genesis::genesis_in_force(directory).await {
        Ok(in_force) => in_force
            .holders()
            .iter()
            .filter_map(|h| super::edition2::composite::ed25519_public(&h.key))
            .collect(),
        Err(_) => Vec::new(),
    };
    root_binding_anchored(directory, key_id, claimed_pubkey_ed25519_base64, &anchor).await
}

/// v47.4.0 (CIRISPersist#805, FSD §3.3) — the one place a rooting rejection
/// is REPORTED: every caller (announce-admit, the FFI, a consumer's
/// regression pin) gets the failing link and verify's text on
/// [`ROOTING_LOG_TARGET`] without touching their code. The verdict itself
/// is unchanged — see `root_binding_anchored_inner` for the walk.
pub async fn root_binding_anchored<F>(
    directory: &F,
    key_id: &str,
    claimed_pubkey_ed25519_base64: &str,
    trusted_anchor: &[[u8; 32]],
) -> RootingVerdict
where
    F: FederationDirectory + ?Sized,
{
    let verdict = root_binding_anchored_inner(
        directory,
        key_id,
        claimed_pubkey_ed25519_base64,
        trusted_anchor,
    )
    .await;
    if let RootingVerdict::Rejected { rejection } = &verdict {
        tracing::warn!(
            target: ROOTING_LOG_TARGET,
            key_id = %key_id,
            kind = rejection.kind(),
            detail = ?rejection,
            "root_binding rejected"
        );
    }
    verdict
}

/// [`root_binding`] with an explicit trusted-terminus **anchor** — the core
/// primitive. The terminus's Ed25519 pubkey must appear in `trusted_anchor`
/// (a slice of raw 32-byte keys) or the binding is rejected with
/// [`RootingRejection::TerminusNotInAnchor`]. Production callers use the
/// [`root_binding`] wrapper (accord-holder anchor); this form exists so tests
/// (and any alternative pinning) can supply their own anchor.
///
/// See [`root_binding`] for the full step-by-step contract; this adds **step
/// 5**: terminus-pubkey ∈ `trusted_anchor`.
async fn root_binding_anchored_inner<F>(
    directory: &F,
    key_id: &str,
    claimed_pubkey_ed25519_base64: &str,
    trusted_anchor: &[[u8; 32]],
) -> RootingVerdict
where
    F: FederationDirectory + ?Sized,
{
    // Step 1+2: resolve the queried row and confirm the claimed
    // pubkey. We look it up directly (rather than relying on the
    // chain's leaf) so a pubkey mismatch is reported before any
    // chain walk — the cheapest, most specific rejection first.
    let leaf = match directory.lookup_public_key(key_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return RootingVerdict::Rejected {
                rejection: RootingRejection::UnknownKeyId {
                    key_id: key_id.to_owned(),
                },
            }
        }
        Err(e) => {
            return RootingVerdict::Rejected {
                rejection: RootingRejection::DirectoryError {
                    detail: format!("{e}"),
                },
            }
        }
    };

    if leaf.pubkey_ed25519_base64 != claimed_pubkey_ed25519_base64 {
        return RootingVerdict::Rejected {
            rejection: RootingRejection::PubkeyMismatch {
                key_id: key_id.to_owned(),
                claimed_pubkey_ed25519_base64: claimed_pubkey_ed25519_base64.to_owned(),
                directory_pubkey_ed25519_base64: leaf.pubkey_ed25519_base64,
            },
        };
    }

    // Step 3: assemble the recursive-provenance chain.
    let chain = match provenance_chain(directory, key_id).await {
        Ok(c) => c,
        Err(rejection) => return RootingVerdict::Rejected { rejection },
    };

    // The chain must terminate at a trust-root bootstrap (a self-signed
    // `steward` or `accord_holder` row). A structurally valid chain that
    // roots at, e.g., a self-signed `agent` row is NOT rooted — fail-honest.
    if !chain.terminates_at_steward_bootstrap {
        // `chain` is non-empty (provenance_chain always pushes the
        // leaf) and its last element is self-signed.
        let terminus = chain.chain.last().expect("chain is non-empty");
        return RootingVerdict::Rejected {
            rejection: RootingRejection::NotRootedAtSteward {
                key_id: terminus.key_id.clone(),
                identity_type: terminus.identity_type.clone(),
            },
        };
    }

    // Step 3b (CIRISPersist#344 — the load-bearing anti-spoof gate): the
    // terminus's Ed25519 pubkey MUST be a pinned trusted-anchor key. The
    // identity-type check above is only a coarse shape gate — WITHOUT this,
    // a peer that gets a self-signed `steward`/`accord_holder` row admitted
    // (self-signed registration is permitted) could root to it and spoof a
    // rooted binding. Pinning the terminus to the un-forgeable accord-holder
    // anchor (A1/B1/C1) means only the real holders are valid roots.
    let terminus = chain.chain.last().expect("chain is non-empty");
    match BASE64.decode(terminus.pubkey_ed25519_base64.as_bytes()) {
        Ok(raw) if raw.len() == 32 => {
            let mut ed = [0u8; 32];
            ed.copy_from_slice(&raw);
            if !trusted_anchor.contains(&ed) {
                return RootingVerdict::Rejected {
                    rejection: RootingRejection::TerminusNotInAnchor {
                        key_id: terminus.key_id.clone(),
                        terminus_pubkey_ed25519_base64: terminus.pubkey_ed25519_base64.clone(),
                    },
                };
            }
        }
        // A terminus whose pubkey cannot be decoded to 32 bytes can never be
        // in the anchor — reject fail-secure (same token; the decode fault
        // and the not-in-anchor case both mean "not a pinned root").
        _ => {
            return RootingVerdict::Rejected {
                rejection: RootingRejection::TerminusNotInAnchor {
                    key_id: terminus.key_id.clone(),
                    terminus_pubkey_ed25519_base64: terminus.pubkey_ed25519_base64.clone(),
                },
            };
        }
    }

    // Step 4: verify every link's scrub-signature by DELEGATING to CIRISVerify's
    // provenance walk (CIRISPersist#465 — deletes persist's forked crypto
    // re-implementation, crypto-DRY assessment #1). v10.4.0 fixed the JCS-envelope
    // preimage and v10.5.0 (CIRISVerify#208) parameterized the terminus role set,
    // so persist finally roots THROUGH verify instead of re-implementing the walk.
    // We pass persist's own accepted-terminus roles ({steward, accord_holder},
    // matching `is_trusted_root_identity`) and `RequireHybrid` — TIGHTENING the
    // former `Ed25519Fallback`: a federation binding gate MUST reject a
    // classical-only link (F-AV-14 / AV-8), and the two trust-root verifiers now
    // agree on PQC-mandatoriness. Production genesis is full-hybrid, so nothing
    // real breaks. Steps 3 + 3b already pinned the terminus ROLE and ANCHOR with
    // persist's exact rejection tokens (the #94 edge contract), so verify's
    // redundant re-checks pass here and its only live failure mode is crypto →
    // mapped to `UnsignedProvenanceLink` (same `.kind()` token as the old fork).
    // The two `ProvenanceChain`/`ProvenanceLink` types are field-identical, so
    // the map is a serde round-trip; the anchor is `[u8;32]` → `Vec<u8>`.
    let verify_chain: ciris_verify_core::provenance::ProvenanceChain =
        match serde_json::to_value(&chain).and_then(serde_json::from_value) {
            Ok(vc) => vc,
            Err(e) => {
                return RootingVerdict::Rejected {
                    rejection: RootingRejection::UnsignedProvenanceLink {
                        key_id: chain.key_id.clone(),
                        signed_by_key_id: chain.key_id.clone(),
                        detail: format!("map provenance chain to verify type: {e}"),
                    },
                };
            }
        };
    let verify_anchor: Vec<Vec<u8>> = trusted_anchor.iter().map(|k| k.to_vec()).collect();
    if let Err(e) = ciris_verify_core::provenance::verify_provenance_chain_with_policy_and_terminus(
        &verify_chain,
        &verify_anchor,
        ciris_verify_core::threshold::HybridPolicy::RequireHybrid,
        &[STEWARD_IDENTITY_TYPE, ACCORD_HOLDER_IDENTITY_TYPE],
    ) {
        let failing = verify_provenance_error_key_id(&e).unwrap_or_else(|| chain.key_id.clone());
        return RootingVerdict::Rejected {
            rejection: RootingRejection::UnsignedProvenanceLink {
                key_id: failing.clone(),
                signed_by_key_id: failing,
                detail: format!("verify provenance: {e}"),
            },
        };
    }

    RootingVerdict::Confirmed { chain }
}

/// Extract the failing link's `key_id` from a verify [`ProvenanceError`] for the
/// [`RootingRejection::UnsignedProvenanceLink`] mapping (CIRISPersist#465).
/// Variants that name no specific link (empty chain, queried-key mismatch,
/// terminus shape/role, over-depth) return `None` → caller falls back to the
/// queried `key_id`.
fn verify_provenance_error_key_id(
    e: &ciris_verify_core::provenance::ProvenanceError,
) -> Option<String> {
    use ciris_verify_core::provenance::ProvenanceError as E;
    match e {
        E::BrokenLink { key_id, .. }
        | E::SelfSignedMidChain { key_id, .. }
        | E::BadContentHash { key_id, .. }
        | E::ContentHashMismatch { key_id, .. }
        | E::BadSignatureEncoding { key_id, .. }
        | E::BadKeyEncoding { key_id, .. }
        | E::ParentMissingPqcKey { key_id, .. }
        | E::ScrubSignatureInvalid { key_id, .. }
        | E::UntrustedAnchor { key_id, .. }
        | E::LinkNotHybrid { key_id, .. } => Some(key_id.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v21.3.0 (CIRISPersist#508) — `root_binding` / `root_binding_anchored`
    /// (and `provenance_chain`) are callable with `&dyn FederationDirectory`
    /// (`F: ?Sized`), the handle CIRISServer actually holds
    /// (`engine.federation_directory()` → `Arc<dyn FederationDirectory>`) —
    /// the server-side E6 prime-time re-anchoring depends on this. A
    /// compile-time witness: the fn below never runs, it just fails the
    /// build if the bounds regress to `Sized`.
    #[allow(dead_code)]
    async fn dyn_directory_callable_508(dir: &dyn crate::federation::FederationDirectory) {
        let _ = root_binding(dir, "k", "pk").await;
        let _ = root_binding_anchored(dir, "k", "pk", &[[0u8; 32]]).await;
        let _ = provenance_chain(dir, "k").await;
    }

    #[test]
    fn rejection_kinds_are_stable() {
        assert_eq!(
            RootingRejection::UnknownKeyId { key_id: "k".into() }.kind(),
            "rooting_unknown_key_id"
        );
        assert_eq!(
            RootingRejection::CycleDetected { key_id: "k".into() }.kind(),
            "rooting_cycle_detected"
        );
        assert_eq!(
            RootingRejection::OverDepth { max_depth: 64 }.kind(),
            "rooting_over_depth"
        );
    }

    #[test]
    fn verdict_json_shape_is_tagged() {
        let confirmed = RootingVerdict::Confirmed {
            chain: ProvenanceChain {
                key_id: "k".into(),
                chain: vec![],
                terminates_at_steward_bootstrap: true,
            },
        };
        let json = serde_json::to_value(&confirmed).unwrap();
        assert_eq!(json["verdict"], "confirmed");

        let rejected = RootingVerdict::Rejected {
            rejection: RootingRejection::UnknownKeyId {
                key_id: "missing".into(),
            },
        };
        let json = serde_json::to_value(&rejected).unwrap();
        assert_eq!(json["verdict"], "rejected");
        // RootingRejection is `#[serde(flatten)]`'d, so its own
        // `reason` tag + payload sit at the top level.
        assert_eq!(json["reason"], "unknown_key_id");
        assert_eq!(json["key_id"], "missing");
    }

    #[test]
    fn verdict_accessors() {
        let confirmed = RootingVerdict::Confirmed {
            chain: ProvenanceChain {
                key_id: "k".into(),
                chain: vec![],
                terminates_at_steward_bootstrap: true,
            },
        };
        assert!(confirmed.is_confirmed());
        assert!(confirmed.chain().is_some());
        assert!(confirmed.rejection().is_none());

        let rejected = RootingVerdict::Rejected {
            rejection: RootingRejection::OverDepth { max_depth: 64 },
        };
        assert!(!rejected.is_confirmed());
        assert!(rejected.chain().is_none());
        assert!(rejected.rejection().is_some());
    }

    /// The trust-root identity classifier (CIRISPersist#344): a pure
    /// `accord_holder` terminus (the real A1/B1/C1 shape), `steward`, and the
    /// multi-role set all qualify; non-root roles do not.
    #[test]
    fn trusted_root_identity_accepts_steward_and_accord_holder() {
        assert!(is_trusted_root_identity("steward"));
        assert!(is_trusted_root_identity("accord_holder"));
        assert!(is_trusted_root_identity("steward,accord_holder"));
        assert!(is_trusted_root_identity("witness,accord_holder"));
        assert!(!is_trusted_root_identity("agent"));
        assert!(!is_trusted_root_identity("primitive"));
        assert!(!is_trusted_root_identity("node,witness"));
    }
}

// v62.0.0 (JSON cut, E5) — the sqlite and postgres conformance suites
// (`conformance_helpers`, `sqlite_conformance`, `postgres_conformance`) are
// deleted: every case built a JSON key record scrub-signed over
// sha256(JCS(registration_envelope)), linked by `scrub_key_id`, rooted at an
// Ed25519 anchor, or rewired those links in raw SQL. That is the earlier
// form's key provenance (a co-scrub chain); an edition-2 key is its
// `key:record` statement, verified at the door. The pure tests above stay.
