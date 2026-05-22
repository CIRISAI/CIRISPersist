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
//! [`crate::verify::hybrid::verify_hybrid`] — the existing hybrid
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

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::{FederationDirectory, KeyRecord};
use crate::verify::hybrid::{verify_hybrid, HybridPolicy};

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

/// `identity_type` value marking a row as a steward — the trust-root
/// class. The recursive-provenance walk terminates only at a
/// **self-signed steward** row (the bootstrap).
const STEWARD_IDENTITY_TYPE: &str = super::types::identity_type::STEWARD;

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
    /// hex-encoded. The bytes the scrub-signature covers.
    pub original_content_hash: String,
    /// Four-tuple #2a — Ed25519 scrub-signature over
    /// `original_content_hash`, base64 standard. Always present.
    pub scrub_signature_classical: String,
    /// Four-tuple #2b — ML-DSA-65 scrub-signature over
    /// `original_content_hash || classical_sig` (bound signature),
    /// base64 standard. `None` while the row is hybrid-pending.
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
    /// `identity_type` is not `steward` — the chain terminates
    /// somewhere other than a steward bootstrap.
    NotRootedAtSteward {
        /// The self-signed row the chain terminated at.
        key_id: String,
        /// That row's `identity_type` (anything but `steward`).
        identity_type: String,
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
    F: FederationDirectory,
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
            let terminates_at_steward_bootstrap = terminus_identity_type == STEWARD_IDENTITY_TYPE;
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

/// Cold-start binding-rooting primitive (CIRISPersist#94).
///
/// On first contact with a federation peer, confirm the claimed
/// `(key_id, pubkey)` binding against the `federation_keys` directory
/// and verify the row's recursive-provenance chain up to a steward
/// bootstrap. **This replaces trust-on-first-use** — CIRISEdge's
/// `PeerResolver` calls it on its cold-start path.
///
/// Returns [`RootingVerdict::Confirmed`] iff ALL hold:
///
///  1. `key_id` resolves to a `federation_keys` directory row.
///  2. `claimed_pubkey_ed25519_base64` equals that row's
///     `pubkey_ed25519_base64` (exact string match — both are base64
///     standard of the 32 raw bytes).
///  3. The recursive-provenance chain assembles (no break, no cycle,
///     within depth) and terminates at a **self-signed steward**
///     bootstrap.
///  4. Every link's scrub-signature verifies cryptographically: each
///     row's `scrub_signature_*` over its `original_content_hash`,
///     checked against the **parent** row's pubkey (the self-signed
///     bootstrap is checked against its own pubkey).
///
/// Otherwise returns [`RootingVerdict::Rejected`] with the typed
/// [`RootingRejection`]. No third state (MISSION.md §1.6).
///
/// # Crypto path
///
/// Each link's signature is verified through
/// [`crate::verify::hybrid::verify_hybrid`] (`ciris_crypto` under the
/// hood) — never persist-local crypto. The verify policy is
/// [`HybridPolicy::Ed25519Fallback`]: a hybrid-pending link (cold-path
/// ML-DSA-65 sign not yet complete) is verified on its Ed25519
/// signature alone. Provenance rooting authenticates *origin*; the PQC
/// posture of a link is a separate, freshness-policy concern the
/// caller layers on via [`provenance_chain`] + its own
/// [`HybridPolicy`]. A link that DOES carry a PQC signature is
/// verified hybrid (both signatures must pass).
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
    F: FederationDirectory,
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

    // The chain must terminate at a steward bootstrap. A structurally
    // valid chain that roots at, e.g., a self-signed `agent` row is
    // NOT rooted — fail-honest rather than accept.
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

    // Step 4: verify every link's scrub-signature. Each row was
    // signed by its parent (`scrub_key_id`); the self-signed
    // bootstrap signed itself. We need the parent's pubkey to verify,
    // so build a quick index of the links we already hold.
    if let Err(rejection) = verify_chain_signatures(&chain) {
        return RootingVerdict::Rejected { rejection };
    }

    RootingVerdict::Confirmed { chain }
}

/// Verify every link's scrub-signature against the pubkey of the row
/// that signed it. Returns the first [`RootingRejection`] on failure;
/// `Ok(())` when every link verifies.
///
/// The signature input is the **`original_content_hash` bytes** — per
/// `docs/FEDERATION_DIRECTORY.md` §"Schema sketch", the scrub-signature
/// is "Ed25519 over `original_content_hash`" (`original_content_hash`
/// is itself `sha256(canonical(registration_envelope))`). The hybrid
/// PQC component, when present, signs the bound input
/// `original_content_hash || classical_sig`; [`verify_hybrid`] applies
/// the bound-signature rule internally.
fn verify_chain_signatures(chain: &ProvenanceChain) -> Result<(), RootingRejection> {
    use std::collections::HashMap;

    // Index links by key_id so each link can find its parent's pubkey.
    let by_key: HashMap<&str, &ProvenanceLink> =
        chain.chain.iter().map(|l| (l.key_id.as_str(), l)).collect();

    for link in &chain.chain {
        // The signer of `link` is `link.scrub_key_id` — equal to
        // `link.key_id` for the self-signed bootstrap.
        let signer = by_key.get(link.scrub_key_id.as_str()).ok_or_else(|| {
            // Should be unreachable: provenance_chain only terminates
            // on a self-signed row or a structural error, so every
            // non-terminal link's parent is the next link in `chain`.
            // Belt-and-braces: a missing signer is a broken link.
            RootingRejection::BrokenProvenanceLink {
                key_id: link.key_id.clone(),
                missing_parent_key_id: link.scrub_key_id.clone(),
            }
        })?;

        // The bytes the scrub-signature covers: original_content_hash.
        let signed_bytes = hex::decode(&link.original_content_hash).map_err(|e| {
            RootingRejection::UnsignedProvenanceLink {
                key_id: link.key_id.clone(),
                signed_by_key_id: link.scrub_key_id.clone(),
                detail: format!("original_content_hash hex decode: {e}"),
            }
        })?;

        // Crypto through the CIRISVerify path. Ed25519Fallback: a
        // hybrid-pending link verifies on Ed25519 alone; a link that
        // carries a PQC signature is verified hybrid (both required).
        let outcome = verify_hybrid(
            &signed_bytes,
            &link.scrub_signature_classical,
            link.scrub_signature_pqc.as_deref(),
            &signer.pubkey_ed25519_base64,
            signer.pubkey_ml_dsa_65_base64.as_deref(),
            HybridPolicy::Ed25519Fallback,
            None,
        );

        if let Err(e) = outcome {
            return Err(RootingRejection::UnsignedProvenanceLink {
                key_id: link.key_id.clone(),
                signed_by_key_id: link.scrub_key_id.clone(),
                detail: e.kind().to_owned(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

// ─────────────────────────────────────────────────────────────────────
// Conformance test helpers — shared by the SQLite + Postgres suites.
//
// Build real, scrub-signed federation_keys rows. The scrub-signature
// is Ed25519 over `original_content_hash` (per FEDERATION_DIRECTORY.md
// §"Schema sketch") — `original_content_hash` itself being
// `sha256(canonical(registration_envelope))`. The helpers sign with
// raw `ed25519_dalek` keys so the verify path under test
// (`verify_hybrid`) exercises real cryptography end-to-end.
// ─────────────────────────────────────────────────────────────────────
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod conformance_helpers {
    use super::super::types::{algorithm, identity_type, KeyRecord};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::{DateTime, Utc};
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest, Sha256};

    /// A test identity — a deterministic Ed25519 keypair plus the
    /// `key_id` it is registered under.
    pub struct TestKey {
        pub key_id: String,
        pub signing_key: SigningKey,
    }

    impl TestKey {
        pub fn new(key_id: &str, seed: u8) -> Self {
            TestKey {
                key_id: key_id.to_owned(),
                signing_key: SigningKey::from_bytes(&[seed; 32]),
            }
        }

        pub fn pubkey_b64(&self) -> String {
            B64.encode(self.signing_key.verifying_key().to_bytes())
        }
    }

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .unwrap()
            .into()
    }

    /// Build a scrub-signed [`KeyRecord`] for `subject`, signed by
    /// `signer` (use `signer == subject` for a self-signed bootstrap).
    ///
    /// `identity_type` controls whether a self-signed row counts as a
    /// steward bootstrap.
    pub fn signed_record(subject: &TestKey, signer: &TestKey, identity_type: &str) -> KeyRecord {
        let envelope = serde_json::json!({ "key_id": subject.key_id });
        // original_content_hash = sha256(canonical(envelope)). The
        // exact canonical form does not matter for the rooting test
        // as long as the signature is computed over the same bytes
        // that land in original_content_hash — which is the contract.
        let canonical = serde_json::to_vec(&envelope).unwrap();
        let digest = Sha256::digest(&canonical);
        let original_content_hash = hex::encode(digest);

        // scrub-signature: Ed25519 over the original_content_hash bytes.
        let sig = signer.signing_key.sign(digest.as_slice());

        KeyRecord {
            key_id: subject.key_id.clone(),
            pubkey_ed25519_base64: subject.pubkey_b64(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: subject.key_id.clone(),
            valid_from: ts(),
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash,
            scrub_signature_classical: B64.encode(sig.to_bytes()),
            scrub_signature_pqc: None,
            scrub_key_id: signer.key_id.clone(),
            scrub_timestamp: ts(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
        }
    }

    /// Like [`signed_record`] but the scrub-signature is over the
    /// WRONG bytes — a deliberately broken / unsigned provenance link.
    pub fn corrupt_signed_record(
        subject: &TestKey,
        signer: &TestKey,
        identity_type: &str,
    ) -> KeyRecord {
        let mut rec = signed_record(subject, signer, identity_type);
        // Sign garbage instead of the original_content_hash.
        let sig = signer.signing_key.sign(b"not-the-content-hash");
        rec.scrub_signature_classical = B64.encode(sig.to_bytes());
        rec
    }

    pub fn steward() -> &'static str {
        identity_type::STEWARD
    }
    pub fn agent() -> &'static str {
        identity_type::AGENT
    }
    pub fn primitive() -> &'static str {
        identity_type::PRIMITIVE
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_conformance {
    use super::conformance_helpers::*;
    use super::*;
    use crate::federation::{FederationDirectory, SignedKeyRecord};
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;

    async fn fresh() -> SqliteBackend {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
    }

    async fn put(backend: &SqliteBackend, rec: KeyRecord) {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }

    /// Confirmed: valid chain agent → primitive → steward bootstrap.
    #[tokio::test]
    async fn sqlite_confirmed_chain_to_steward_bootstrap() {
        let backend = fresh().await;
        let steward_k = TestKey::new("steward-root", 0x01);
        let primitive_k = TestKey::new("primitive-mid", 0x02);
        let agent_k = TestKey::new("agent-leaf", 0x03);

        // steward self-signs; primitive signed by steward; agent by primitive.
        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;
        put(
            &backend,
            signed_record(&primitive_k, &steward_k, primitive()),
        )
        .await;
        put(&backend, signed_record(&agent_k, &primitive_k, agent())).await;

        let verdict = root_binding(&backend, "agent-leaf", &agent_k.pubkey_b64()).await;
        assert!(
            verdict.is_confirmed(),
            "expected Confirmed, got {verdict:?}"
        );
        let chain = verdict.chain().unwrap();
        assert_eq!(chain.chain.len(), 3, "agent → primitive → steward");
        assert_eq!(chain.chain[0].key_id, "agent-leaf");
        assert_eq!(chain.chain[2].key_id, "steward-root");
        assert!(chain.terminates_at_steward_bootstrap);
        assert!(chain.chain[2].is_self_signed);
    }

    /// Rejected: unknown key_id.
    #[tokio::test]
    async fn sqlite_rejected_unknown_key_id() {
        let backend = fresh().await;
        let verdict = root_binding(&backend, "no-such-key", "AAAA").await;
        assert!(matches!(
            verdict.rejection(),
            Some(RootingRejection::UnknownKeyId { .. })
        ));
    }

    /// Rejected: pubkey mismatch.
    #[tokio::test]
    async fn sqlite_rejected_pubkey_mismatch() {
        let backend = fresh().await;
        let steward_k = TestKey::new("steward-root", 0x11);
        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;

        // Claim a pubkey that is not the row's.
        let verdict = root_binding(&backend, "steward-root", "WRONGPUBKEY=").await;
        match verdict.rejection() {
            Some(RootingRejection::PubkeyMismatch { key_id, .. }) => {
                assert_eq!(key_id, "steward-root");
            }
            other => panic!("expected PubkeyMismatch, got {other:?}"),
        }
    }

    /// Rejected: a broken/unsigned provenance link — the agent row's
    /// scrub-signature does not verify against its parent's pubkey.
    #[tokio::test]
    async fn sqlite_rejected_unsigned_provenance_link() {
        let backend = fresh().await;
        let steward_k = TestKey::new("steward-root", 0x21);
        let agent_k = TestKey::new("agent-leaf", 0x22);

        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;
        // Agent row signed over the WRONG bytes.
        put(
            &backend,
            corrupt_signed_record(&agent_k, &steward_k, agent()),
        )
        .await;

        let verdict = root_binding(&backend, "agent-leaf", &agent_k.pubkey_b64()).await;
        match verdict.rejection() {
            Some(RootingRejection::UnsignedProvenanceLink { key_id, .. }) => {
                assert_eq!(key_id, "agent-leaf");
            }
            other => panic!("expected UnsignedProvenanceLink, got {other:?}"),
        }
    }

    /// Rejected: a dangling parent reference — scrub_key_id points at
    /// a key_id that has no row.
    ///
    /// V004's `scrub_key_must_exist` FK normally prevents this; a
    /// dangling parent ref can only arise from legacy data or a
    /// directory with the FK disabled. We provoke it directly (insert
    /// self-signed, then point `scrub_key_id` at a ghost with the
    /// PRAGMA off) so the structural defence in `provenance_chain` —
    /// `BrokenProvenanceLink` rather than a panic — is exercised.
    #[tokio::test]
    async fn sqlite_rejected_broken_provenance_link() {
        let backend = fresh().await;
        let agent_k = TestKey::new("agent-leaf", 0x32);
        // Insert self-signed so the FK is satisfied at write time.
        put(&backend, signed_record(&agent_k, &agent_k, agent())).await;
        // Now repoint scrub_key_id at a non-existent ghost with the
        // FK pragma disabled — representing legacy / FK-off data.
        let conn = backend.conn_handle();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            conn.execute(
                "UPDATE federation_keys SET scrub_key_id = 'ghost-parent' \
                 WHERE key_id = 'agent-leaf'",
                [],
            )
            .unwrap();
            conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        })
        .await
        .unwrap();

        let verdict = root_binding(&backend, "agent-leaf", &agent_k.pubkey_b64()).await;
        match verdict.rejection() {
            Some(RootingRejection::BrokenProvenanceLink {
                key_id,
                missing_parent_key_id,
            }) => {
                assert_eq!(key_id, "agent-leaf");
                assert_eq!(missing_parent_key_id, "ghost-parent");
            }
            other => panic!("expected BrokenProvenanceLink, got {other:?}"),
        }
    }

    /// Rejected: chain terminates at a self-signed row that is NOT a
    /// steward (a self-signed `agent` root).
    #[tokio::test]
    async fn sqlite_rejected_not_rooted_at_steward() {
        let backend = fresh().await;
        // Self-signed agent — structurally a terminus, but not a steward.
        let agent_k = TestKey::new("agent-root", 0x41);
        put(&backend, signed_record(&agent_k, &agent_k, agent())).await;

        let verdict = root_binding(&backend, "agent-root", &agent_k.pubkey_b64()).await;
        match verdict.rejection() {
            Some(RootingRejection::NotRootedAtSteward {
                key_id,
                identity_type,
            }) => {
                assert_eq!(key_id, "agent-root");
                assert_eq!(identity_type, "agent");
            }
            other => panic!("expected NotRootedAtSteward, got {other:?}"),
        }
    }

    /// Rejected: a cycle — two rows each naming the other as parent.
    ///
    /// A true cycle cannot be inserted parent-first (the FK rejects
    /// the first row), so we seed `a` self-signed, insert `b` signed
    /// by `a`, then UPDATE `a.scrub_key_id = b` — both endpoints
    /// exist, the FK is satisfied, and the graph now has an a↔b loop.
    #[tokio::test]
    async fn sqlite_rejected_cycle_detected() {
        let backend = fresh().await;
        let a = TestKey::new("cycle-a", 0x51);
        let b = TestKey::new("cycle-b", 0x52);
        put(&backend, signed_record(&a, &a, primitive())).await;
        put(&backend, signed_record(&b, &a, primitive())).await;
        let conn = backend.conn_handle();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE federation_keys SET scrub_key_id = 'cycle-b' \
                 WHERE key_id = 'cycle-a'",
                [],
            )
            .unwrap();
        })
        .await
        .unwrap();

        let verdict = root_binding(&backend, "cycle-a", &a.pubkey_b64()).await;
        assert!(
            matches!(
                verdict.rejection(),
                Some(RootingRejection::CycleDetected { .. })
            ),
            "expected CycleDetected, got {verdict:?}"
        );
    }

    /// The verify-consumable read returns the row + full four-tuple
    /// chain, ordered leaf → root, terminating at the steward.
    #[tokio::test]
    async fn sqlite_provenance_chain_read_returns_full_chain() {
        let backend = fresh().await;
        let steward_k = TestKey::new("steward-root", 0x61);
        let primitive_k = TestKey::new("primitive-mid", 0x62);
        let agent_k = TestKey::new("agent-leaf", 0x63);
        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;
        put(
            &backend,
            signed_record(&primitive_k, &steward_k, primitive()),
        )
        .await;
        put(&backend, signed_record(&agent_k, &primitive_k, agent())).await;

        let chain = provenance_chain(&backend, "agent-leaf").await.unwrap();
        assert_eq!(chain.key_id, "agent-leaf");
        assert_eq!(chain.chain.len(), 3);
        // leaf → root ordering: each link's scrub_key_id is the next
        // link's key_id.
        for i in 0..chain.chain.len() - 1 {
            assert_eq!(chain.chain[i].scrub_key_id, chain.chain[i + 1].key_id);
        }
        assert!(chain.terminates_at_steward_bootstrap);
        // Every link carries the full four-tuple.
        for link in &chain.chain {
            assert!(!link.original_content_hash.is_empty());
            assert!(!link.scrub_signature_classical.is_empty());
            assert!(!link.scrub_key_id.is_empty());
            assert!(!link.scrub_timestamp.is_empty());
        }
        assert!(chain.chain[2].is_self_signed);
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres_conformance {
    use super::conformance_helpers::*;
    use super::*;
    use crate::federation::{FederationDirectory, SignedKeyRecord};
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    /// Delete the test rows. federation_keys has a self-referential
    /// FK on scrub_key_id, so children must go before parents — we
    /// just delete every row whose key_id is in `key_ids`, retrying
    /// is unnecessary because DELETE of the whole set in one statement
    /// satisfies the deferred-or-immediate FK once all are gone.
    async fn pg_cleanup(backend: &PostgresBackend, key_ids: &[&str]) {
        let client = backend.pool().get().await.unwrap();
        for id in key_ids {
            // attestations / revocations / detection events could
            // reference these; the conformance suite writes none, so
            // a direct delete is sufficient. Order children-first by
            // deleting non-self-signed rows before self-signed roots
            // is not required because the suite's rows form a tree
            // and we delete leaf-ward callers explicitly per-test.
            let _ = client
                .execute(
                    "DELETE FROM cirislens.federation_keys WHERE key_id = $1",
                    &[id],
                )
                .await;
        }
    }

    async fn put(backend: &PostgresBackend, rec: KeyRecord) {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }

    /// Confirmed: valid chain agent → primitive → steward bootstrap.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_confirmed_chain_to_steward_bootstrap() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let ids = [
            "rooting-pg-agent",
            "rooting-pg-primitive",
            "rooting-pg-steward",
        ];
        // children-first delete: agent, primitive, then steward.
        pg_cleanup(&backend, &ids).await;

        let steward_k = TestKey::new("rooting-pg-steward", 0x81);
        let primitive_k = TestKey::new("rooting-pg-primitive", 0x82);
        let agent_k = TestKey::new("rooting-pg-agent", 0x83);
        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;
        put(
            &backend,
            signed_record(&primitive_k, &steward_k, primitive()),
        )
        .await;
        put(&backend, signed_record(&agent_k, &primitive_k, agent())).await;

        let verdict = root_binding(&backend, "rooting-pg-agent", &agent_k.pubkey_b64()).await;
        assert!(
            verdict.is_confirmed(),
            "expected Confirmed, got {verdict:?}"
        );
        let chain = verdict.chain().unwrap();
        assert_eq!(chain.chain.len(), 3);
        assert_eq!(chain.chain[2].key_id, "rooting-pg-steward");
        assert!(chain.terminates_at_steward_bootstrap);

        pg_cleanup(&backend, &ids).await;
    }

    /// Rejected: unknown key_id, pubkey mismatch.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_rejected_unknown_and_mismatch() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let verdict = root_binding(&backend, "rooting-pg-nonexistent", "AAAA").await;
        assert!(matches!(
            verdict.rejection(),
            Some(RootingRejection::UnknownKeyId { .. })
        ));

        let ids = ["rooting-pg-mismatch"];
        pg_cleanup(&backend, &ids).await;
        let steward_k = TestKey::new("rooting-pg-mismatch", 0x84);
        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;
        let verdict = root_binding(&backend, "rooting-pg-mismatch", "WRONGPUBKEY=").await;
        assert!(matches!(
            verdict.rejection(),
            Some(RootingRejection::PubkeyMismatch { .. })
        ));
        pg_cleanup(&backend, &ids).await;
    }

    /// Rejected: unsigned provenance link, not-rooted-at-steward.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_rejected_unsigned_and_not_steward() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // unsigned link
        let ids = ["rooting-pg-u-agent", "rooting-pg-u-steward"];
        pg_cleanup(&backend, &ids).await;
        let steward_k = TestKey::new("rooting-pg-u-steward", 0x85);
        let agent_k = TestKey::new("rooting-pg-u-agent", 0x86);
        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;
        put(
            &backend,
            corrupt_signed_record(&agent_k, &steward_k, agent()),
        )
        .await;
        let verdict = root_binding(&backend, "rooting-pg-u-agent", &agent_k.pubkey_b64()).await;
        assert!(matches!(
            verdict.rejection(),
            Some(RootingRejection::UnsignedProvenanceLink { .. })
        ));
        pg_cleanup(&backend, &ids).await;

        // not-rooted-at-steward
        let ids2 = ["rooting-pg-selfagent"];
        pg_cleanup(&backend, &ids2).await;
        let self_agent = TestKey::new("rooting-pg-selfagent", 0x87);
        put(&backend, signed_record(&self_agent, &self_agent, agent())).await;
        let verdict =
            root_binding(&backend, "rooting-pg-selfagent", &self_agent.pubkey_b64()).await;
        assert!(matches!(
            verdict.rejection(),
            Some(RootingRejection::NotRootedAtSteward { .. })
        ));
        pg_cleanup(&backend, &ids2).await;
    }

    /// Rejected: cycle detected.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_rejected_cycle_detected() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let ids = ["rooting-pg-cyc-a", "rooting-pg-cyc-b"];
        pg_cleanup(&backend, &ids).await;

        let a = TestKey::new("rooting-pg-cyc-a", 0x88);
        let b = TestKey::new("rooting-pg-cyc-b", 0x89);
        // Insert b first signed by a, then a signed by b. Postgres'
        // scrub_key_must_exist FK is DEFERRABLE INITIALLY DEFERRED but
        // each put_public_key is its own transaction — so insert the
        // pair in dependency order is impossible for a true cycle.
        // We seed both with self-signed placeholders then... instead,
        // exploit the deferred FK: not available cross-transaction.
        // So: insert `a` self-signed first to satisfy b's FK, insert
        // b (signed by a), then UPDATE a's scrub_key_id to b.
        put(&backend, signed_record(&a, &a, primitive())).await;
        put(&backend, signed_record(&b, &a, primitive())).await;
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "UPDATE cirislens.federation_keys SET scrub_key_id = $1 WHERE key_id = $2",
                &[&"rooting-pg-cyc-b", &"rooting-pg-cyc-a"],
            )
            .await
            .unwrap();
        drop(client);

        let verdict = root_binding(&backend, "rooting-pg-cyc-a", &a.pubkey_b64()).await;
        assert!(
            matches!(
                verdict.rejection(),
                Some(RootingRejection::CycleDetected { .. })
            ),
            "expected CycleDetected, got {verdict:?}"
        );

        // cleanup: break the cycle before delete (FK).
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "UPDATE cirislens.federation_keys SET scrub_key_id = key_id \
                 WHERE key_id = ANY($1)",
                &[&&ids[..]],
            )
            .await
            .unwrap();
        drop(client);
        pg_cleanup(&backend, &ids).await;
    }

    /// The verify-consumable read returns the full four-tuple chain.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_provenance_chain_read_returns_full_chain() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let ids = ["rooting-pg-r-agent", "rooting-pg-r-steward"];
        pg_cleanup(&backend, &ids).await;

        let steward_k = TestKey::new("rooting-pg-r-steward", 0x8A);
        let agent_k = TestKey::new("rooting-pg-r-agent", 0x8B);
        put(&backend, signed_record(&steward_k, &steward_k, steward())).await;
        put(&backend, signed_record(&agent_k, &steward_k, agent())).await;

        let chain = provenance_chain(&backend, "rooting-pg-r-agent")
            .await
            .unwrap();
        assert_eq!(chain.chain.len(), 2);
        assert_eq!(chain.chain[0].key_id, "rooting-pg-r-agent");
        assert_eq!(chain.chain[1].key_id, "rooting-pg-r-steward");
        assert!(chain.terminates_at_steward_bootstrap);
        for link in &chain.chain {
            assert!(!link.original_content_hash.is_empty());
            assert!(!link.scrub_signature_classical.is_empty());
        }

        pg_cleanup(&backend, &ids).await;
    }
}
