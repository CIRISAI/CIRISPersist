//! Federation directory wire-format types.
//!
//! These shapes are the source of truth for both persist's backends
//! and CIRISRegistry's vendored
//! `rust-registry/src/federation/types.rs`. Field names + types must
//! match field-for-field between the two repos.
//!
//! # PQC strategy (v0.2.0): hot-path Ed25519, cold-path ML-DSA-65
//!
//! **Hybrid Ed25519 + ML-DSA-65 is the only signing scheme across
//! the federation.** Every row in the historical audit chain
//! converges to fully hybrid-signed. But the WRITE PATH accepts
//! Ed25519-only rows initially with the ML-DSA-65 signature
//! attached on the cold path — see `docs/FEDERATION_DIRECTORY.md`
//! §"Trust contract — eventual consistency as a federation
//! primitive" for the architectural rationale.
//!
//! Writer contract:
//!   1. Sign canonical_bytes with Ed25519 (synchronous, hot path).
//!   2. Write the row (PQC fields may be `None` at this step).
//!   3. **IMMEDIATELY** kick off ML-DSA-65 signing on the cold
//!      path — not delayed, not batched, just off the synchronous
//!      request path.
//!   4. Call `attach_pqc_signature` once the ML-DSA-65 sign
//!      completes. `pqc_completed_at` is timestamped.
//!
//! When quantum threat materializes, persist's runtime policy
//! flips (`require_pqc_on_write=true`); the kickoff step folds
//! into the synchronous path and PQC fields become required at
//! write time.
//!
//! Every key in the federation has TWO public-key components:
//!   - `pubkey_ed25519_base64` — 32 raw bytes, base64 standard, REQUIRED
//!   - `pubkey_ml_dsa_65_base64` — 1952 raw bytes, base64 standard,
//!     populated by `attach_pqc_signature` (`Option<String>`)
//!
//! Every signature in the federation has TWO components, bound:
//!   - `scrub_signature_classical` — `Ed25519.sign(canonical_bytes)`,
//!     REQUIRED
//!   - `scrub_signature_pqc` — `ML-DSA-65.sign(canonical_bytes ||
//!     classical_sig)`, populated by `attach_pqc_signature`
//!     (`Option<String>`)
//!
//! The bound signature pattern (PQC covers `data || classical`)
//! prevents stripping attacks where an attacker who breaks Ed25519
//! could otherwise replace the PQC signature with their own. This
//! matches CIRISVerify's `ManifestSignature` and `HybridSignature`
//! contracts (`ciris-verify-core/src/security/function_integrity.rs:149`,
//! `ciris-crypto/src/types.rs:156`).
//!
//! # Identity, algorithm, and attestation type strings
//!
//! Persist stores `identity_type` and `attestation_type` as TEXT
//! columns (not enums) so new values can be added by either side
//! without a schema break. `algorithm` is also TEXT but only
//! `"hybrid"` is accepted — the schema enforces it
//! (`CHECK (algorithm = 'hybrid')`), and persist's runtime rejects
//! writes with any other value. The column exists for forward compat
//! against future PQC schemes (ML-DSA-87, ML-DSA + ML-KEM, etc.) that
//! may emerge as the federation evolves.
//!
//! # Canonical hashing
//!
//! [`KeyRecord::persist_row_hash`] is computed server-side by persist
//! via `crate::verify::canonical::PythonJsonDumpsCanonicalizer` (sorted
//! keys, no whitespace, `ensure_ascii=True`) over the row's
//! user-visible fields. Consumers store the hex string verbatim and
//! string-compare on cache divergence checks. Same shape for
//! [`Attestation::persist_row_hash`] and
//! [`Revocation::persist_row_hash`].
//!
//! See `docs/FEDERATION_DIRECTORY.md` §"persist_row_hash —
//! server-computed for cache divergence" for the architectural
//! rationale.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Identity classification per persist's `identity_type` column.
///
/// **Vocabulary stability (v2.4.0, CIRISPersist#102 Ask 1).** The
/// column is free-form TEXT in the schema — consumers may extend.
/// Persist publishes these five values as the canonical vocabulary
/// per FSD-002 §7 (HUMANITY_ACCORD layer); see
/// `docs/FEDERATION_DIRECTORY.md` §"Schema sketch" for per-value
/// rationale.
pub mod identity_type {
    /// Agent trace-signing keys.
    pub const AGENT: &str = "agent";
    /// Primitive build-signing keys (ciris-persist, ciris-agent, etc.).
    pub const PRIMITIVE: &str = "primitive";
    /// Steward keys (registry, persist, lens, agent — the trust roots).
    pub const STEWARD: &str = "steward";
    /// Per-org partner keys for commercial onboarding.
    pub const PARTNER: &str = "partner";
    /// HUMANITY_ACCORD key material — the three hardware-attested
    /// human-held kill-switch keys per FSD-002 §7.2. Only rows with
    /// this identity_type may emit `accord:*` attestations
    /// (FSD-002 §4.1 / §7.1 — the federation's one constitutional
    /// asymmetry); the admission gate in [`super::admission`]
    /// enforces this at write time.
    pub const ACCORD_HOLDER: &str = "accord_holder";
    /// v3.0.0 (CIRISPersist#116, CEG 0.2 §5.3 / §7.2) — the running
    /// persist instance's self-reporting key. Only `federation_keys`
    /// rows with this identity_type may emit attestations on the
    /// substrate-self-report prefixes (`system:*`, `audit_chain:*`,
    /// `corpus_health:*`, `identity_continuity:*`,
    /// `federation_directory:*`). The admission gate in
    /// [`super::admission::default_reserved_prefix_rules`] enforces
    /// this.
    pub const SUBSTRATE_PERSIST: &str = "substrate_persist";
    /// v3.0.0 (CIRISPersist#116, CEG 0.2 §7.6 / §10.3) — registered
    /// transparency-log witnesses. Only `federation_keys` rows with
    /// this identity_type may emit `transparency_log:cosigned:*`
    /// attestations. The substrate-conformance migration path moves
    /// the 0.x interim per-region `registry_witnesses` table over to
    /// `federation_keys` rows with this identity_type, per CEG §10.3.
    pub const WITNESS: &str = "witness";
    /// v3.6.0 (CIRISPersist#134, CEG 0.3 §11.5.3) — Policy J
    /// trusted-publisher identity. Only `federation_keys` rows with
    /// this identity_type may emit publisher-curated content ratings
    /// (`content_rating:*` reserved-prefix attestations). The
    /// admission gate in
    /// [`super::admission::default_reserved_prefix_rules`] enforces
    /// this.
    pub const TRUSTED_PUBLISHER: &str = "trusted_publisher";
}

/// Algorithm strings matching persist's `algorithm` column.
///
/// **v0.2.0+ federation_keys writes MUST use [`HYBRID`].** Schema
/// enforces this with `CHECK (algorithm = 'hybrid')`. Other values
/// remain in this module only as forward-compat placeholders for
/// hypothetical future migration paths (e.g., upgrading legacy
/// agent trace-signing keys at v0.4.0+ if the agent fleet remains
/// Ed25519-only at that time — but the federation directory itself
/// is hybrid all the way down).
pub mod algorithm {
    /// Hybrid Ed25519 + ML-DSA-65. **The only valid value for
    /// federation_keys writes from v0.2.0 onward.** Bound signature
    /// protocol per CIRISVerify `HybridSignature`:
    /// `classical_sig = Ed25519.sign(canonical)`,
    /// `pqc_sig = ML-DSA-65.sign(canonical || classical_sig)`.
    /// Verification requires both signatures.
    pub const HYBRID: &str = "hybrid";
}

/// Attestation type vocabulary — the **one workhorse + four
/// structural** primitives per FSD-002 §2.
///
/// **v2.4.0 clean-break replacement (CIRISPersist#102 Ask 2).** The
/// pre-v2.4.0 vocabulary (`vouches_for` / `witnesses` / `referred` /
/// `delegated_to`) was speculative and never reached a downstream
/// consumer — persist was the only writer and the wire shape was
/// unfinalized. The 2.4.0 cut replaces the constants in lockstep
/// with the FSD-002 unified-primitive model; no migration is needed
/// (the column is free-form TEXT) and no deprecation aliases are
/// kept (per `feedback_clean_break_renames.md` — alias scaffolding
/// is rejected; rename + remove ship in the same cut, flagged in
/// CHANGELOG).
///
/// **Why `recants` is distinct from `withdraws`** (per FSD-002 v1.2
/// PRIOR_ART_SCAN Bucket 1): no prior wire format (PGP / SPKI /
/// W3C VC) typed *epistemic-error-admission* as a wire primitive.
/// `withdraws` is "I no longer stand behind this attestation"
/// (good-faith retraction; no claim that it was false at issuance);
/// `recants` is "this attestation was false at issuance — I admit
/// epistemic error". Persist keeps them distinct on the wire even
/// when consumer UIs collapse them.
pub mod attestation_type {
    /// The unified workhorse primitive per FSD-002 §2.1. Every claim
    /// about an entity — positive / negative, identity / capability /
    /// behavior / state / commitment — is a `scores` attestation on
    /// a named `dimension` with `score ∈ [-1, +1]` + `confidence ∈
    /// [0, 1]` + optional evidence refs in the envelope.
    pub const SCORES: &str = "scores";
    /// Structural primitive: "A authorizes B to sign on A's behalf
    /// within scope S" (FSD-002 §2.2.1). Bounded scope; default
    /// transitive depth = 2.
    pub const DELEGATES_TO: &str = "delegates_to";
    /// Structural primitive: "this row replaces a prior attestation
    /// by the same attester" (FSD-002 §2.2.2). Consumers walking
    /// history apply latest-wins per (attesting_key_id, dimension,
    /// attested_key_id).
    pub const SUPERSEDES: &str = "supersedes";
    /// Structural primitive: "I retract my prior attestation"
    /// (FSD-002 §2.2.3). Does NOT claim the original was false at
    /// issuance — good-faith withdrawal.
    pub const WITHDRAWS: &str = "withdraws";
    /// Structural primitive: "my prior attestation was false at
    /// issuance" (FSD-002 §2.2.4). Admits epistemic error.
    /// Wire-distinct from [`WITHDRAWS`] even when consumer UIs
    /// collapse the two — see module-level note.
    pub const RECANTS: &str = "recants";
}

/// `federation_keys` row.
///
/// Field order matters for serde default JSON serialization (field
/// declaration order is the JSON key order). CIRISRegistry's vendored
/// shape mirrors this declaration order; changes here require a
/// matching change there to preserve `persist_row_hash` parity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Canonical key identifier (matches `signature_key_id` on the
    /// trace-verification wire).
    pub key_id: String,
    /// Ed25519 32-byte raw public key, base64 standard. 44 chars.
    /// Always required.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 1952-byte raw public key, base64 standard.
    /// ~2604 chars. `None` until the cold-path PQC sign completes
    /// via `attach_pqc_signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// Algorithm string. **v0.2.0+ writes MUST be [`algorithm::HYBRID`].**
    pub algorithm: String,
    /// Identity classification ([`identity_type::AGENT`], etc.).
    pub identity_type: String,
    /// Logical identity reference (shape varies by `identity_type`).
    pub identity_ref: String,
    /// When the key became valid.
    pub valid_from: DateTime<Utc>,
    /// When the key expires (`None` = no expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Canonical bytes of the registration envelope (verbatim).
    pub registration_envelope: serde_json::Value,
    /// SHA-256 of canonical(registration_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 signature: `Ed25519.sign(canonical_bytes)`.
    /// Base64-encoded (88 chars for 64-byte sig). Always required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 signature: `ML-DSA-65.sign(canonical || classical_sig)`.
    /// Bound to the classical signature to prevent stripping attacks.
    /// Base64-encoded (~4412 chars for 3309-byte sig — FIPS 204 final,
    /// `c_tilde_bytes=48`; closes CIRISPersist#8). The pre-FIPS-204-final
    /// figure of 3293 bytes was the round-3 era size; live `ml-dsa = 0.1.0-rc.3`
    /// and CIRISVerify v1.8.5 both emit 3309. Empirically confirmed by
    /// CIRISBridge's lens-steward bootstrap producing 4412-char base64
    /// signatures via `dilithium-py.ML_DSA_65.sign`.
    /// `None` until the cold-path PQC sign completes via
    /// `attach_pqc_signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` of the row that signed THIS row. Bootstrap rows have
    /// `scrub_key_id == key_id` (self-signed); all others reference
    /// an existing `federation_keys` row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the cold-path PQC components were attached. `None` while
    /// the row is hybrid-pending (Ed25519-only); populated by
    /// `attach_pqc_signature` once ML-DSA-65 fills in. Telemetry +
    /// observability signal — auditable answer to "when did this row
    /// become hybrid-secure?"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,
    /// **Server-computed.** Hex-encoded SHA-256 over the canonical
    /// bytes of this row (via persist's
    /// `PythonJsonDumpsCanonicalizer`). Consumers store + string-
    /// compare; they don't reproduce the canonicalizer. Closes the
    /// shortest-round-trip drift class of cache-divergence bugs.
    pub persist_row_hash: String,
    /// v1.3.0 (CIRISPersist#46) — Per-row role tags. Determines what
    /// the key is authorized to do at the persist API boundary:
    /// `cirislens_pipeline_writer` gates `POST /api/v1/pipeline/ingest`;
    /// `cirislens_secrets_reader` / `_writer` / `_admin` gate the
    /// secrets routes. Empty default — pre-V020 rows + new rows that
    /// didn't declare roles deserialize to `vec![]`. The `#[serde(default)]`
    /// keeps the wire shape backward-compatible with v1.2.x writers
    /// that don't know about the field yet.
    #[serde(default)]
    pub roles: Vec<String>,
    /// v2.5.0 (CIRISPersist#102 Ask 8) — Hardware-attestation evidence
    /// captured at key-binding time. REQUIRED for `identity_type =
    /// 'accord_holder'` rows (FSD-002 §7.3 + FEDERATION_ANNOUNCEMENT
    /// §4.5.2); the V048 schema CHECK + the
    /// [`HardwareAttestationPolicy`](super::HardwareAttestationPolicy)
    /// admission hook both enforce this.
    ///
    /// Shape is `{platform_attestation: <PlatformAttestation JSON>,
    /// nonce_captured_at: "<RFC3339>"}` — see
    /// [`super::hardware_attestation::AttestationEvidence`].
    ///
    /// `None` for non-accord-holder rows. Backward-compatible default
    /// — pre-V048 reads return `None` and the field is
    /// `skip_serializing_if = "Option::is_none"` so old `persist_row_hash`
    /// computations stay stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_evidence: Option<serde_json::Value>,
}

impl KeyRecord {
    /// True iff both PQC components have been attached. Consumers
    /// composing strict-hybrid trust policy refuse rows where this
    /// returns false.
    pub fn is_pqc_complete(&self) -> bool {
        self.pubkey_ml_dsa_65_base64.is_some()
            && self.scrub_signature_pqc.is_some()
            && self.pqc_completed_at.is_some()
    }

    /// True iff the row is in the cold-path PQC-signing window
    /// (Ed25519-only, ML-DSA-65 in flight). Consumers composing
    /// soft-hybrid + freshness policies use this with their own age
    /// threshold to decide whether the row is acceptably-pending vs
    /// concerning-stale.
    pub fn is_pqc_pending(&self) -> bool {
        !self.is_pqc_complete()
    }
}

/// `federation_attestations` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// UUID identifier for this attestation row.
    pub attestation_id: String,
    /// Key making the attestation (must exist in `federation_keys`).
    pub attesting_key_id: String,
    /// Key being attested (must exist in `federation_keys`).
    pub attested_key_id: String,
    /// Attestation type ([`attestation_type::SCORES`] /
    /// [`attestation_type::DELEGATES_TO`] / [`attestation_type::SUPERSEDES`]
    /// / [`attestation_type::WITHDRAWS`] / [`attestation_type::RECANTS`]).
    pub attestation_type: String,
    /// Optional weight signal carried by the attester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
    /// When the attestation was made.
    pub asserted_at: DateTime<Utc>,
    /// When the attestation expires (`None` = no expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Canonical bytes of the attestation envelope.
    pub attestation_envelope: serde_json::Value,
    /// SHA-256 of canonical(attestation_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 sig over canonical bytes. Base64. Required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 sig over (canonical || classical_sig). Base64.
    /// `None` while the row is hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the PQC components were attached. `None` while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
    /// v3.7.0 (CIRISPersist#146, CEG 0.6 §4.2). Optional list of
    /// consent-holder key_ids for this attestation. Each entry MAY be
    /// a `federation_keys.key_id` OR a canonical-hash identifier
    /// (CEG 0.6 §4.2.2). Default `[]` = status quo (producer-only
    /// authority). The substrate does NOT FK-enforce that entries
    /// resolve to `federation_keys` rows — canonical-hash subjects
    /// (Discord user-ids, external party identifiers) are valid
    /// entries per the CEG 0.6 design.
    ///
    /// The 4-rule broadened `withdraws` admission gate (CEG §3.2.3)
    /// reads this field at admission time; see
    /// [`Self::withdraws_admission_rule`] for the per-rule audit
    /// metadata recorded post-admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_key_ids: Vec<String>,
    /// v3.7.0 (CIRISPersist#146, CEG 0.6 §3.2.3). Per-rule audit
    /// metadata: which of the 4 admission rules admitted this
    /// withdraws.
    ///
    /// `Some(1)` — producer self-revocation (`issuer.key_id == T.attesting_key_id`).
    /// `Some(2)` — subject self-revocation (`issuer.key_id ∈ T.subject_key_ids`, CEG 0.6 NEW).
    /// `Some(3)` — `delegates_to` proxy chain with `consent_revocation` scope (CEG 0.6 NEW).
    /// `Some(4)` — `delegates_to` chain via any of 1-3.
    /// `None`    — non-withdraws row, or pre-v3.8.0 withdraws written
    ///             before the admission gate landed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdraws_admission_rule: Option<u8>,
    /// v3.9.0 (CIRISPersist#150, CEG 0.4 §4.2.4). Producer-side
    /// visibility scope. Closed-set values: `self | family | community
    /// | affiliations | species | biosphere | federation`. Default
    /// `"federation"` (preserves pre-v3.9.0 semantic; producers
    /// writing new content explicitly tag self/family/etc.). Orthogonal
    /// to `subject_key_ids` (revocability authority) — see CEG §4.2.4.
    ///
    /// **v3.9.0 ships the schema + round-trip only.** Admission-gate
    /// enforcement, the §8.1.8.1 promotion ceremony, and read-time
    /// viewer-vs-scope filtering land in v3.10.0.
    #[serde(
        default = "default_cohort_scope",
        skip_serializing_if = "is_default_cohort_scope"
    )]
    pub cohort_scope: String,
}

/// v3.9.0 (CIRISPersist#150) — default cohort_scope for backward compat.
/// Pre-v3.9.0 attestations had no cohort_scope; reading them under the
/// new schema returns the column DEFAULT 'federation', so the Rust
/// default matches.
fn default_cohort_scope() -> String {
    "federation".to_string()
}

/// True iff the cohort_scope equals the default. Used by serde
/// `skip_serializing_if` so legacy rows' canonical bytes /
/// `persist_row_hash` stay stable across the v3.9.0 schema bump —
/// federation-scope rows omit the field entirely from JSON output.
fn is_default_cohort_scope(s: &String) -> bool {
    s == "federation"
}

/// v3.9.0 (CIRISPersist#150) — closed-set cohort_scope values per
/// CEG 0.4 §4.2.4. Producers MUST emit one of these or rely on the
/// substrate-side default of `federation`. `global` is intentionally
/// NOT a value — it's a §8.1.8 feed name aggregating
/// `{species, biosphere, federation}`, not a wire enum value.
pub mod cohort_scope {
    /// Locally-held content (locality dividend per
    /// FEDERATION_SCALING_MODEL §9.5). Never emits federation-tier
    /// holds_bytes; substrate-local-only.
    pub const SELF: &str = "self";
    /// Content shared with a partnered family/group (CEG §8.1.8).
    /// Visible to peers with `trust:partnered` or `trust:direct`.
    pub const FAMILY: &str = "family";
    /// Community-tier content per CEG §8.1.8. Visible to peers per
    /// the community's policy_blob cohort_scope (#127 #48-A).
    pub const COMMUNITY: &str = "community";
    /// Affiliations tier (CEG §8.1.8).
    pub const AFFILIATIONS: &str = "affiliations";
    /// Species tier (CEG §8.1.8 — broader-than-community human
    /// audience).
    pub const SPECIES: &str = "species";
    /// Biosphere tier (CEG §8.1.8 — including non-human stakeholders).
    pub const BIOSPHERE: &str = "biosphere";
    /// Federation-wide visibility (CEG §8.1.8). Status-quo
    /// pre-v3.9.0 semantic.
    pub const FEDERATION: &str = "federation";

    /// True iff `s` is one of the closed-set values. Substrate
    /// admission-gate work in v3.10.0+ uses this for early rejection
    /// of malformed envelopes.
    pub fn is_valid(s: &str) -> bool {
        matches!(
            s,
            SELF | FAMILY | COMMUNITY | AFFILIATIONS | SPECIES | BIOSPHERE | FEDERATION
        )
    }

    /// v3.9.2 (CIRISPersist#153 Ask 5, CEG 0.7 §10.1.4) — the
    /// structural-invisibility classification.
    ///
    /// True iff content tagged with this `cohort_scope` is
    /// **structurally invisible** to the federation: the substrate
    /// MUST NOT emit a `holds_bytes:sha256:*` directory attestation
    /// for it, and MUST NOT propagate it beyond the self-collective /
    /// family scope via any directory or discovery surface. A
    /// non-member peer cannot issue a ContentFetch for it and cannot
    /// even discover the bytes exist — the `holds_bytes` row *is* the
    /// discovery surface, so not emitting it is the privacy primitive
    /// (the ciris.ai/cewp "the wire format can't carry them" claim).
    ///
    /// True for [`SELF`] and [`FAMILY`]. False for `community` /
    /// `affiliations` / `species` / `biosphere` / `federation`, which
    /// federate per status quo and emit `holds_bytes` normally — CEG
    /// 0.8 §8.1.13.3 is explicit that community content is NOT
    /// suppressed (communities can be large; per-member byte-level
    /// invisibility is infeasible, and the community privacy property
    /// is cohort-filtered visibility, not byte-level invisibility).
    ///
    /// This is the locality dividend of FEDERATION_SCALING_MODEL §9.5:
    /// self/family bytes never cost the federation a directory entry.
    pub fn suppresses_holds_bytes(s: &str) -> bool {
        matches!(s, SELF | FAMILY)
    }
}

impl Attestation {
    /// True iff PQC components have been attached.
    pub fn is_pqc_complete(&self) -> bool {
        self.scrub_signature_pqc.is_some() && self.pqc_completed_at.is_some()
    }
}

/// `federation_revocations` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    /// UUID identifier for this revocation row.
    pub revocation_id: String,
    /// Key being revoked.
    pub revoked_key_id: String,
    /// Key issuing the revocation.
    pub revoking_key_id: String,
    /// Free-form reason; consumers parse if they care.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the revocation was issued.
    pub revoked_at: DateTime<Utc>,
    /// When the revocation takes effect (may be retroactive or future).
    pub effective_at: DateTime<Utc>,
    /// Canonical bytes of the revocation envelope.
    pub revocation_envelope: serde_json::Value,
    /// SHA-256 of canonical(revocation_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 sig over canonical bytes. Base64. Required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 sig over (canonical || classical_sig). Base64.
    /// `None` while the row is hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the PQC components were attached. `None` while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,

    /// v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2 R1) — region that first observed this revocation
    /// (closed set: `us` / `eu` / `apac`, see
    /// [`crate::federation::verify_coord::region`]). Drives the Q1
    /// quorum-write tracking + R1 τ_propagate accounting.
    ///
    /// `#[serde(default, skip_serializing_if = …)]`: the default
    /// value [`crate::federation::verify_coord::region::US`] is
    /// skipped from canonical bytes so pre-v3.11 rows (which had no
    /// region field) and explicit `us` rows hash identically — the
    /// same backward-compat discipline v3.9.0 used for `cohort_scope`.
    #[serde(
        default = "default_observed_region",
        skip_serializing_if = "is_default_observed_region"
    )]
    pub observed_region: String,

    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

fn default_observed_region() -> String {
    crate::federation::verify_coord::region::US.to_owned()
}

fn is_default_observed_region(s: &str) -> bool {
    s == crate::federation::verify_coord::region::US
}

impl Revocation {
    /// True iff PQC components have been attached.
    pub fn is_pqc_complete(&self) -> bool {
        self.scrub_signature_pqc.is_some() && self.pqc_completed_at.is_some()
    }

    /// v3.11.0 (CIRISPersist#143) — the **signed_timestamp** the Q1
    /// merge comparator reads (tier 2). Mapped from
    /// [`Revocation::scrub_timestamp`], the timestamp pinned into the
    /// signed scrub envelope.
    ///
    /// Exposed as a named accessor so the spec mapping
    /// (`signed_timestamp` in CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2) is verbatim in the substrate API, without storing the
    /// same value twice on the row.
    pub fn signed_timestamp(&self) -> DateTime<Utc> {
        self.scrub_timestamp
    }

    /// v3.11.0 (CIRISPersist#143) — the **canonical_bytes_hash** the
    /// Q1 merge comparator reads (tier 3, deterministic tie-break).
    /// Mapped from [`Revocation::original_content_hash`], the hex
    /// SHA-256 of the canonical revocation envelope.
    pub fn canonical_bytes_hash(&self) -> &str {
        &self.original_content_hash
    }
}

/// One hybrid-pending federation row — minimum fields the sweep
/// needs to recompute the cold-path bound-signature input. Returned
/// by [`super::FederationDirectory::list_hybrid_pending_keys`] /
/// `_attestations` / `_revocations` (CIRISPersist#11, v0.3.2).
///
/// `id` is the row's primary key (`key_id` for `federation_keys`,
/// `attestation_id` / `revocation_id` for the others). `envelope` is
/// the JSONB column the original Ed25519 signature was computed over
/// — canonical bytes are recomputed via
/// `PythonJsonDumpsCanonicalizer::canonicalize_value` to feed the
/// bound-signature input. `classical_sig_b64` is the base64-encoded
/// Ed25519 signature that PQC will sign over alongside the canonical
/// bytes per the bound-signature contract.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridPendingRow {
    /// Primary key of the hybrid-pending row.
    pub id: String,
    /// JSONB envelope the row's classical signature was computed over.
    pub envelope: serde_json::Value,
    /// Base64-encoded Ed25519 signature stored on the row.
    pub classical_sig_b64: String,
}

/// Wraps a [`KeyRecord`] payload that the caller has signed but
/// persist has not yet stored. Persist verifies the scrub-signature
/// on receipt before writing. The wrapper exists so write-path
/// signatures match read-path shapes (which include `persist_row_hash`
/// populated by persist) without forcing callers to compute that hash
/// themselves. On `put_public_key`, persist ignores the caller's
/// `persist_row_hash` field and computes its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedKeyRecord {
    /// The record being submitted. `persist_row_hash` is ignored on
    /// write — persist computes its own.
    pub record: KeyRecord,
}

/// Wraps an [`Attestation`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The attestation being submitted.
    pub attestation: Attestation,
}

/// Wraps a [`Revocation`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedRevocation {
    /// The revocation being submitted.
    pub revocation: Revocation,
}

// ─── Trust hierarchy (v1.3.0, CIRISPersist#46 + #47) ───────────────
//
// Persist absorbs NodeCore's `crate::trust` module surface at the
// M2 cut. See FSD TRUST_HIERARCHY.md §4.1 and the NodeCore
// `src/trust.rs` source (commit be82bd9) for the architectural
// rationale. Shapes mirror NodeCore exactly so NodeCore can
// replace its local placeholder trait definition with
// `pub use ciris_persist::federation::FederationDirectory` once
// this release ships.

/// Trust type axis. Mirrors CIRISAgent ConsentService taxonomy;
/// tracks CIRISAgent#760 §RC consent_role lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustType {
    /// Default. Most peer-to-peer agent-to-agent observations.
    Temporary,
    /// Bilateral approval (CIRISAgent#760 / LensCore ConsentService scope).
    Partnered,
    /// Anonymous trust grant.
    Anonymous,
}

impl TrustType {
    /// Wire-shaped string. Matches the federation_keys.trust_type
    /// CHECK constraint vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Temporary => "temporary",
            Self::Partnered => "partnered",
            Self::Anonymous => "anonymous",
        }
    }

    /// Parse from the wire-shaped string. Returns `None` on
    /// vocabulary mismatch.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "temporary" => Self::Temporary,
            "partnered" => Self::Partnered,
            "anonymous" => Self::Anonymous,
            _ => return None,
        })
    }
}

/// Trust relationship axis. New axis introduced by FSD
/// TRUST_HIERARCHY.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRelationship {
    /// Peer trust — `K_B` can act directly with the grantor.
    Direct,
    /// Vouching delegation — `K_B` can vouch for other keys within
    /// `trust_domains` only.
    Registry,
}

impl TrustRelationship {
    /// Wire-shaped string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Registry => "registry",
        }
    }

    /// Parse from the wire-shaped string.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "direct" => Self::Direct,
            "registry" => Self::Registry,
            _ => return None,
        })
    }
}

/// A trust grant — what the grantor declared. The persist write
/// path materializes this into a row on `federation_keys` (UPSERT
/// on `key_id`, preserving the pubkey + signature envelope from the
/// prior `put_public_key`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrant {
    /// Subject of the grant — the trusted key.
    pub key: String,
    /// Type axis.
    pub trust_type: TrustType,
    /// Relationship axis.
    pub trust_relationship: TrustRelationship,
    /// Domain scope. Required when `trust_relationship = Registry`;
    /// `None` for `Direct` grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domains: Option<Vec<String>>,
    /// Grantor key. Must differ from `key` per the
    /// `trusted_by != key` integrity rule (no self-trust).
    pub trusted_by: String,
    /// `None` = open-ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// A row from the directory — the grant + its `trusted_at`
/// timestamp. Returned by
/// [`super::FederationDirectory::lookup_trust`] and
/// [`super::FederationDirectory::list_trusted_keys`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustRow {
    /// Subject of the grant.
    pub key: String,
    /// Type axis.
    pub trust_type: TrustType,
    /// Relationship axis.
    pub trust_relationship: TrustRelationship,
    /// Domain scope (`Some` when relationship = Registry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domains: Option<Vec<String>>,
    /// Grantor key.
    pub trusted_by: String,
    /// When the grant was created.
    pub trusted_at: DateTime<Utc>,
    /// `None` = open-ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filter for [`super::FederationDirectory::list_trusted_keys`].
/// All fields AND-composed; every field optional.
#[derive(Debug, Clone, Default)]
pub struct TrustFilter {
    /// Narrow by type axis.
    pub trust_type: Option<TrustType>,
    /// Narrow by relationship axis.
    pub trust_relationship: Option<TrustRelationship>,
    /// Narrow to registries vouching for `domain`. Only meaningful
    /// with `trust_relationship = Some(Registry)`.
    pub domain: Option<String>,
    /// If `false` (default), expired rows are filtered server-side
    /// via `WHERE expires_at IS NULL OR expires_at > NOW()`.
    pub include_expired: bool,
}

// ─── Peer metadata (v3.1.0, CIRISPersist#117) ──────────────────────
//
// The peer-mutation surface CIRISEdge v0.13.0 stubbed under UniFFI's
// `PEER_MUTATION_FOLLOWUP` constant lands here. Operator-local
// per-instance metadata (alias / trust / notes / policy / transport
// identity) — distinct from the federation-shared identity carried by
// `federation_keys` rows. See `migrations/postgres/lens/V051__*.sql`
// for the sibling-table architectural rationale.

/// Operator's trust class for a federation peer. Closed-set vocabulary
/// mirrored by the V051 `federation_peer_metadata.trust` CHECK
/// constraint via [`as_wire_str`](Self::as_wire_str) /
/// [`from_wire_str`](Self::from_wire_str) — same shape as
/// [`crate::store::VerificationSource`] (v2.0 CIRISPersist#91).
///
/// Default is [`Untrusted`](Self::Untrusted) — newly-added peers come
/// in unranked; the operator promotes via [`super::FederationDirectory
/// ::update_peer_trust`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// No trust claim yet. Default for newly-added peers.
    #[default]
    Untrusted,
    /// Operator has marked this peer as trusted.
    Trusted,
    /// Operator allows interaction under restrictions (e.g., read-
    /// only, throttled). Persist does not enforce the restrictions —
    /// that's a consumer-side composition.
    Restricted,
    /// Operator has blocked this peer. Persist still keeps the row
    /// (the block IS the operator-state we're persisting); consumers
    /// honor it.
    Blocked,
}

impl TrustClass {
    /// The TEXT-column wire form (`'untrusted'` / `'trusted'` /
    /// `'restricted'` / `'blocked'`). Matches the V051 CHECK-constraint
    /// value set.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            TrustClass::Untrusted => "untrusted",
            TrustClass::Trusted => "trusted",
            TrustClass::Restricted => "restricted",
            TrustClass::Blocked => "blocked",
        }
    }

    /// Parse the TEXT-column wire form. `None` for any value outside
    /// the closed set — the caller surfaces it as a backend decode
    /// error (the DB CHECK constraint should make this unreachable on
    /// reads, but writes via [`update_peer_trust`](super::
    /// FederationDirectory::update_peer_trust) use the typed variant
    /// directly).
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "untrusted" => Some(TrustClass::Untrusted),
            "trusted" => Some(TrustClass::Trusted),
            "restricted" => Some(TrustClass::Restricted),
            "blocked" => Some(TrustClass::Blocked),
            _ => None,
        }
    }
}

/// Opaque consumer-defined policy blob for a peer. Persist round-trips
/// the JSON verbatim; the shape is owned by CIRISEdge's UniFFI
/// `PeerPolicy` type. Stored as JSONB on Postgres + TEXT-as-JSON on
/// SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerPolicyBlob(pub serde_json::Value);

impl PeerPolicyBlob {
    /// Construct a blob from a `serde_json::Value`.
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// Borrow the underlying JSON value.
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    /// Consume into the underlying JSON value.
    pub fn into_value(self) -> serde_json::Value {
        self.0
    }
}

/// `federation_peer_metadata` row — read shape.
///
/// Returned by reads through the peer-metadata surface (future
/// methods; the v3.1.0 cut ships writes only, mirroring the v0.2.0
/// federation_keys/_attestations write-only initial cut). The row
/// carries `persist_row_hash` populated server-side via
/// [`compute_persist_row_hash`] over the rest of the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMetadataRow {
    /// FK to `federation_keys.key_id`.
    pub key_id: String,
    /// Operator-local display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Operator's trust class.
    pub trust: TrustClass,
    /// Operator-local notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Opaque policy blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_blob: Option<PeerPolicyBlob>,
    /// Opaque transport identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_identity: Option<String>,
    /// Soft-remove marker. `None` = live row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<DateTime<Utc>>,
    /// First insertion time.
    pub inserted_at: DateTime<Utc>,
    /// Last mutation time (bumped on every `update_*` call).
    pub updated_at: DateTime<Utc>,
    /// Server-computed canonical-bytes hash.
    pub persist_row_hash: String,
}

/// Compute the canonical-bytes hash for a row used for
/// `persist_row_hash`. Persist calls this server-side on every write
/// path so consumers don't have to.
///
/// Uses [`crate::verify::canonical::PythonJsonDumpsCanonicalizer`] —
/// the same shape persist uses for trace canonical bytes — over the
/// row's serde-default JSON representation **excluding** the
/// `persist_row_hash` field itself (else the hash would depend on
/// itself).
///
/// Returns the hex-encoded SHA-256 string.
pub fn compute_persist_row_hash<T: Serialize>(row: &T) -> Result<String, super::Error> {
    use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
    use sha2::{Digest, Sha256};

    // Serialize → Value → drop `persist_row_hash` field if present →
    // canonicalize → hash. Dropping `persist_row_hash` keeps the hash
    // stable across populate/depopulate cycles (read response carries
    // the field; write submission may or may not).
    let mut value = serde_json::to_value(row)
        .map_err(|e| super::Error::Backend(format!("serialize for hash: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("persist_row_hash");
    }
    let bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&value)
        .map_err(|e| super::Error::Backend(format!("canonicalize for hash: {e}")))?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key_record() -> KeyRecord {
        KeyRecord {
            key_id: "persist-steward".into(),
            // Test fixture only — 32 zero bytes for Ed25519 placeholder.
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            // Hybrid-complete fixture — both pubkeys + both sigs +
            // pqc_completed_at populated.
            pubkey_ml_dsa_65_base64: Some("AA".repeat(100)),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::STEWARD.into(),
            identity_ref: "persist".into(),
            valid_from: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            valid_until: None,
            registration_envelope: serde_json::json!({"role": "persist-steward"}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJlX2NsYXNzaWNhbA==".into(),
            scrub_signature_pqc: Some("c2lnbmF0dXJlX3BxYw==".into()),
            scrub_key_id: "persist-steward".into(),
            scrub_timestamp: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            pqc_completed_at: Some(
                DateTime::parse_from_rfc3339("2026-05-01T00:00:01Z")
                    .unwrap()
                    .into(),
            ),
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        }
    }

    /// Hybrid-pending shape — Ed25519-only, PQC fields None. The
    /// soft-PQC write window per §"Trust contract" in
    /// FEDERATION_DIRECTORY.md.
    fn fixture_hybrid_pending() -> KeyRecord {
        KeyRecord {
            pubkey_ml_dsa_65_base64: None,
            scrub_signature_pqc: None,
            pqc_completed_at: None,
            ..fixture_key_record()
        }
    }

    #[test]
    fn pqc_complete_vs_pending() {
        assert!(fixture_key_record().is_pqc_complete());
        assert!(!fixture_key_record().is_pqc_pending());
        assert!(!fixture_hybrid_pending().is_pqc_complete());
        assert!(fixture_hybrid_pending().is_pqc_pending());
    }

    #[test]
    fn persist_row_hash_is_deterministic() {
        let row = fixture_key_record();
        let h1 = compute_persist_row_hash(&row).unwrap();
        let h2 = compute_persist_row_hash(&row).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic across calls");
        assert_eq!(h1.len(), 64, "hex sha256 is 64 chars");
    }

    #[test]
    fn persist_row_hash_excludes_self() {
        // Two rows differing ONLY in their persist_row_hash field
        // should hash to the same value (the field excludes itself).
        let mut row1 = fixture_key_record();
        let mut row2 = fixture_key_record();
        row1.persist_row_hash = "before".into();
        row2.persist_row_hash = "after".into();
        assert_eq!(
            compute_persist_row_hash(&row1).unwrap(),
            compute_persist_row_hash(&row2).unwrap()
        );
    }

    #[test]
    fn persist_row_hash_changes_with_content() {
        let row1 = fixture_key_record();
        let mut row2 = fixture_key_record();
        row2.identity_ref = "different".into();
        assert_ne!(
            compute_persist_row_hash(&row1).unwrap(),
            compute_persist_row_hash(&row2).unwrap()
        );
    }

    #[test]
    fn key_record_serde_round_trip() {
        let row = fixture_key_record();
        let json = serde_json::to_string(&row).unwrap();
        let deser: KeyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(row, deser);
    }
}
