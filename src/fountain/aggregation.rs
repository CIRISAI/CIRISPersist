//! §19.7 inter-object aggregation — the **forever-memory** storage half
//! (CEG 1.0-RC14 §19.7 / CIRISPersist#230, v8.4.0).
//!
//! §19.7 reframes retirement as ONE pressure-driven monotonic fidelity
//! descent toward a **noise floor** (the individual-recoverability
//! boundary). Two mechanical degradation operators ride that one axis:
//!
//!   * **Operator 1 — intra-object fade** (shipped v8.0–8.2): drop symbols
//!     by `retention_priority` down to a per-tier keep-count
//!     ([`super::eviction::FountainTier`]); the manifest survives.
//!   * **Operator 2 — inter-object aggregation** (v8.3, gated v8.4): N
//!     source items → 1 composite (codec-side tile / downsample /
//!     statistical composite), recursed into a **mipmap pyramid** →
//!     **O(log T)** forever-memory. Each source's contribution sits BELOW
//!     the noise floor (individually unrecoverable), but the collective
//!     **blur** (the composite) persists forever — **descent never
//!     terminates at zero**.
//!
//! # persist is codec-free; this is the OPAQUE-bytes firewall
//! The N→1 resampling compute is codec-side (edge — CIRISEdge#133/#134);
//! persist stores + orchestrates. The composite **is** a
//! [`super::types::FountainManifestV1`] (the edge fountain-encodes it like
//! any content, with `corpus_kind = "aggregate:<source_corpus_kind>"`), so
//! it rides the EXISTING #225 hybrid-manifest admit gate
//! ([`super::admit::check_admission_via_envelope`]) unchanged.
//!
//! # v8.4.0 — the §19.7 CONFORM step (closes the #230 residual)
//! v8.3.0 stored `aggregation_meta` **opaque** because the §19.7 wire shape
//! was not yet frozen. CEG RC14 / CIRISRegistry#89 froze §19.7.1/.1.1/.3 and
//! CIRISVerify v5.10.0 ships the `holonomic::aggregation` verifiers. persist
//! now CONSUMES them (the second-impl conformance role):
//!
//!   * **Store-path admission gate (§19.7.1, §10.1.5.1.1 PQC-mandatory).**
//!     `put_aggregated_tier` parses the §19.7.1 wire fields persist receives
//!     ALONGSIDE the opaque bytes ([`AggregationMetaVerifyInputsV1`]) into the
//!     verify-core wire [`ciris_verify_core::holonomic::AggregationMetaV1`],
//!     resolves the aggregator hybrid pubkeys off the composite manifest
//!     envelope (the aggregator IS the composite's producer; same convention
//!     as [`super::admit::check_admission_via_envelope`]), and calls
//!     [`ciris_verify_core::holonomic::verify_aggregation_meta`]. A
//!     missing/invalid ML-DSA-65 half is REJECTED **before** any write
//!     (verify-before-mutation; never store-then-quarantine). The
//!     `aggregation_meta` STORAGE column stays opaque BYTEA/BLOB — the V086
//!     schema is unchanged. The verification inputs are admission-only; they
//!     are NOT persisted.
//!   * **Descent integrity (§19.7.1.1).** `descend_aggregated_sources`
//!     re-derives the committed `member_commitment` from the caller-supplied
//!     source member set via
//!     [`ciris_verify_core::holonomic::verify_member_commitment`] BEFORE
//!     descending — a forged member set cannot drive eviction. The descent
//!     order is the canonical
//!     [`ciris_verify_core::holonomic::descend_order`].
//!   * **EjectionVerdict alignment (§19.7.3).** persist's internal verdict
//!     enum is removed; persist re-exports and drives
//!     [`ciris_verify_core::holonomic::ejection_verdict`] directly
//!     (`Withdrawn → EjectHardDelete`, capacity pressure → `EjectToTier`,
//!     else `Keep`). This is the canonical superset of the v8.2.0
//!     `retention_decision` path (they agree: revocation → hard-delete).

use serde::{Deserialize, Serialize};

// NOTE (#435): the v3 fns (`passes_multiplicity_gate` / `mass_commitment` /
// `verify_mass_commitment`) are NOT re-exported at the `holonomic::` root the
// way their older siblings are (a verify v10.0.0 re-export gap, path-direct
// works fine) — imported from `holonomic::aggregation` directly.
pub use ciris_verify_core::holonomic::aggregation::{
    descend_order, mass_commitment, passes_multiplicity_gate, verify_mass_commitment,
};
pub use ciris_verify_core::holonomic::{
    ejection_verdict, member_commitment, passes_dominance_gate, verify_aggregation_meta,
    verify_member_commitment, AggregationMetaVerification, EjectionVerdict,
};

/// §19.7.1.2 (CIRISVerify#167 / CIRISPersist#357) — the CC 6.1.2 noise-floor
/// dominance floor persist enforces at admission: a composite's **effective**
/// source count (`n_eff`) must be at least this fraction of its raw
/// `source_count`, else one source supplies too much of the mass and the
/// "aggregate" leaks a recoverable dominant source (the 900/1000 case →
/// `n_eff ≈ 1`). `0.5` = effective N must be ≥ half of raw N.
///
/// **Fail-closed:** [`passes_dominance_gate`] is `false` for a version-1 tier
/// (no *signed* `n_eff`), so a v1 tier is rejected — this is the intended
/// §19.7.1.2 posture (a dominated aggregator cannot bypass the floor by
/// declaring the pre-#167 schema). Pinned here; twins with CIRISConstitution#6.
pub const MIN_DOMINANCE_RATIO: f64 = 0.5;

/// §19.7.1.3 (CIRISVerify#191 / CIRISPersist#435, CC 6.1.2.1.2 R9) — the
/// **content-similarity multiplicity floor** persist enforces at admission,
/// alongside [`MIN_DOMINANCE_RATIO`]. A tier passes iff its signed largest
/// content-similar cluster is at most `1/n_min` of its raw `source_count`
/// (`max_source_multiplicity · n_min ≤ source_count`).
///
/// `n_min = 2` ⇒ no content-similar cluster may exceed **half** the fold. The
/// 900-near-duplicates-under-distinct-ids case (`max_source_multiplicity = 900`,
/// `source_count = 1000`) yields `1800 > 1000` → **rejected** — the fold the
/// mass-based [`passes_dominance_gate`] honestly admits (900 distinct members at
/// equal mass carry a truthful `n_eff = 1000`) but whose composite blur IS the
/// data subject.
///
/// **Fail-closed:** [`passes_multiplicity_gate`] is `false` for a v1/v2 tier (no
/// *signed* `max_source_multiplicity`) — the flag-day hard cut CIRISVerify#191
/// declares (no deprecation window; nothing is deployed on v3-less writers).
///
/// `n_min` is **`corpus_kind`-pinned** (CC 6.1.2 `(R, ε)` — two conformant impls
/// MUST agree); [`multiplicity_n_min_for`] is the pin. Twins with
/// CIRISConstitution#6.
pub const DEFAULT_MULTIPLICITY_N_MIN: u32 = 2;

/// The `corpus_kind`-pinned multiplicity floor `n_min` the §19.7.1.3 gate uses
/// for a given corpus. Pinned in ONE place so persist and every other conformant
/// impl agree (CC 6.1.2 `(R, ε)`); today every corpus takes the
/// [`DEFAULT_MULTIPLICITY_N_MIN`] floor, and a corpus needing a stricter floor
/// (a higher `n_min` ⇒ a smaller admissible cluster) gets an arm here rather
/// than a caller-supplied knob — a caller-tunable `n_min` would let a dominated
/// aggregator pick its own floor.
// The match-shape is deliberate: per-corpus pins land HERE, centrally, rather
// than as caller knobs. Allow the single-binding lint until a second arm exists.
#[allow(clippy::match_single_binding)]
pub fn multiplicity_n_min_for(corpus_kind: &str) -> u32 {
    match corpus_kind {
        // No corpus currently pins a stricter floor than the default.
        _ => DEFAULT_MULTIPLICITY_N_MIN,
    }
}

/// `corpus_kind` prefix for an aggregate composite: a composite folding
/// `"trace"` sources has `corpus_kind = "aggregate:trace"`.
pub const AGGREGATE_CORPUS_PREFIX: &str = "aggregate:";

/// Compose the composite's `corpus_kind` from the folded sources'
/// `source_corpus_kind` (`"trace"` → `"aggregate:trace"`). Recursion
/// nests (`"aggregate:trace"` → `"aggregate:aggregate:trace"`).
pub fn aggregate_corpus_kind(source_corpus_kind: &str) -> String {
    format!("{AGGREGATE_CORPUS_PREFIX}{source_corpus_kind}")
}

/// The §19.7.1 normative wire fields + the bound-hybrid signature persist
/// receives ALONGSIDE the opaque `aggregation_meta` so it can run the
/// PQC-mandatory store-path gate ([`verify_aggregation_meta`]) at admission.
///
/// These are **admission-only verification inputs** — persist does NOT
/// persist them (the storage column [`AggregationMetaV1::aggregation_meta`]
/// stays opaque BYTEA/BLOB; the V086 schema is unchanged). They reconstruct
/// the verify-core wire [`ciris_verify_core::holonomic::AggregationMetaV1`]
/// whose §19.7.1 canonical preimage the aggregator signed. The aggregator
/// hybrid pubkeys are NOT carried here — they are resolved off the composite
/// manifest envelope (`pubkey_ed25519` / `pubkey_ml_dsa_65`), bound into the
/// verify so a forged pubkey fails the signature (the same argument
/// [`super::admit::check_admission_via_envelope`] makes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationMetaVerifyInputsV1 {
    /// §19.7.1 schema version (`1`).
    pub version: u32,
    /// The root content this pyramid is for (the §19.7.1 wire field; need
    /// NOT equal persist's navigation `aggregate_content_id`).
    pub content_id: String,
    /// `"trace" | "blob" | "av_chunk" | …` (the §19.7.1 wire field).
    pub corpus_kind: String,
    /// §19.7.1 tier (`0` = source granularity; higher = more aggregated).
    pub tier: u32,
    /// Opaque codec id, e.g. `"raptorq-pyramid-v1"`.
    pub aggregation_algorithm_id: String,
    /// N members aggregated into this tier (the descent fan-in).
    pub source_count: u32,
    /// §19.7.1.2 (CIRISVerify#167) — signed effective-source-count
    /// (inverse-Simpson `n_eff = (Σmᵢ)²/Σmᵢ²`). **Signed only when
    /// `version >= 2`**; a v1 tier's preimage does NOT include it, so its
    /// value is verification-neutral (persist re-emits it into the
    /// verify-core meta so a version-2 tier's canonical preimage — which
    /// appends `u32(n_eff)` — reproduces byte-for-byte). `#[serde(default)]`
    /// so pre-#167 stored/wire inputs (no `n_eff`) still parse; a v1 tier
    /// defaults to `0`, which is fine (not in its preimage, and it fails
    /// [`ciris_verify_core::holonomic::passes_dominance_gate`] closed).
    #[serde(default)]
    pub n_eff: u32,
    /// §19.7.1.3 (CIRISVerify#191 / CC 6.1.2.1.2 R9) — the signed
    /// **content-similarity multiplicity**: the size of the largest cluster of
    /// members whose pairwise content similarity exceeds the `corpus_kind`-pinned
    /// threshold, computed by the aggregator at fold time (edge — the only point
    /// holding member payloads). Closes what the mass-based [`Self::n_eff`]
    /// cannot see: 900 near-duplicate contents folded as 900 *distinct members at
    /// equal mass* honestly yield `n_eff == 1000`, yet the composite blur IS the
    /// data subject. **Signed only when `version >= 3`**; a v1/v2 tier lacks the
    /// surface and **fails closed** at
    /// [`ciris_verify_core::holonomic::passes_multiplicity_gate`] (flag-day cut,
    /// no deprecation window). `#[serde(default)]` so pre-v3 wire inputs parse.
    #[serde(default)]
    pub max_source_multiplicity: u32,
    /// §19.7.1.3 (CIRISVerify#191) — Merkle root over the per-member masses —
    /// base16 (hex) of the raw 32 bytes. Makes both `n_eff` AND the clustering
    /// **auditable**: an auditor holding the members + their masses recomputes
    /// this root ([`ciris_verify_core::holonomic::verify_mass_commitment`]) and
    /// can *prove* a lying `n_eff`/multiplicity from held evidence — converting
    /// "slashable in principle" into "mechanically provable". **Signed only when
    /// `version >= 3`**; empty for a pre-v3 tier (not in its preimage).
    #[serde(default)]
    pub mass_commitment_hex: String,
    /// §19.7.1.1 Merkle root over the source member ids — base16 (hex) of the
    /// raw 32 bytes. Mirrors the stored
    /// [`AggregationMetaV1::member_commitment`] (which is the SAME hex value).
    pub member_commitment_hex: String,
    /// What survives below the floor (codec-specific, canonical).
    pub noise_floor_descriptor: String,
    /// Ed25519 signature over the §19.7.1 preimage — base64.
    pub sig_ed25519_b64: String,
    /// ML-DSA-65 signature over `preimage ‖ ed25519_sig` — base64. The
    /// PQC-mandatory half: empty/absent ⇒ rejected at the gate.
    pub sig_ml_dsa_65_b64: String,
}

impl AggregationMetaVerifyInputsV1 {
    /// Reconstruct the verify-core wire shape whose §19.7.1 canonical
    /// preimage the aggregator signed. Errors if `member_commitment_hex` is
    /// not 32 bytes of hex (a malformed commitment).
    pub fn to_verify_meta(
        &self,
    ) -> Result<ciris_verify_core::holonomic::AggregationMetaV1, AggregationMetaError> {
        let mc = decode_member_commitment_hex(&self.member_commitment_hex)?;
        // #435 (CIRISVerify#191) — the v3 mass commitment. Absent/empty on a
        // pre-v3 tier (not in its preimage), where the all-zero root is
        // verification-neutral; a v3 tier's preimage appends it, so a malformed
        // value must fail loudly rather than silently zero out.
        let mass_c = if self.mass_commitment_hex.is_empty() {
            [0u8; 32]
        } else {
            decode_mass_commitment_hex(&self.mass_commitment_hex)?
        };
        Ok(ciris_verify_core::holonomic::AggregationMetaV1 {
            version: self.version,
            content_id: self.content_id.clone(),
            corpus_kind: self.corpus_kind.clone(),
            tier: self.tier,
            aggregation_algorithm_id: self.aggregation_algorithm_id.clone(),
            source_count: self.source_count,
            n_eff: self.n_eff,
            max_source_multiplicity: self.max_source_multiplicity,
            mass_commitment: mass_c,
            member_commitment: mc,
            noise_floor_descriptor: self.noise_floor_descriptor.clone(),
        })
    }
}

/// Why the §19.7.1 store-path admission gate rejected an aggregation meta.
/// Stable `kind()` tokens for telemetry / PyO3 sanitization (mirrors the
/// fountain-admit tokens). PQC-mandatory: a missing/invalid ML-DSA-65 half is
/// `HybridRequired` and the tier is NEVER persisted.
#[derive(Debug, thiserror::Error)]
pub enum AggregationMetaError {
    /// The §19.7.1 bound-hybrid signature failed to verify against the
    /// aggregator pubkeys (a half mismatched, the ML-DSA-65 half was
    /// missing/invalid, a malformed key/sig, or the meta did not match the
    /// signed preimage). §10.1.5.1.1: rejected BEFORE persistence.
    #[error("aggregation_meta §19.7.1 bound-hybrid verify failed (PQC-mandatory)")]
    HybridRequired,
    /// The composite manifest envelope did not carry the aggregator's
    /// `pubkey_ed25519` / `pubkey_ml_dsa_65` needed to verify the meta.
    #[error("aggregation_meta verify: composite manifest envelope missing aggregator {0}")]
    MissingAggregatorPubkey(&'static str),
    /// A base64 / base16 verification input failed to decode.
    #[error("aggregation_meta verify: malformed verification input ({0})")]
    MalformedInput(&'static str),
    /// The stored navigation `member_commitment` did not equal the §19.7.1
    /// wire `member_commitment` (the two MUST be the same root — else persist
    /// would store a commitment the signature does not cover).
    #[error("aggregation_meta verify: stored member_commitment != signed §19.7.1 commitment")]
    MemberCommitmentMismatch,
    /// §19.7.1.2 (CIRISVerify#167 / CIRISPersist#357) — the tier's authenticated
    /// effective-source-count `n_eff` is below the [`MIN_DOMINANCE_RATIO`] floor
    /// (a dominated fold: one source supplies too much of the mass, so the
    /// aggregate is not a genuine noise-floor composite). Fail-closed: a
    /// version-1 tier carries no signed `n_eff` and is rejected here.
    #[error(
        "aggregation_meta §19.7.1.2 dominance gate: effective source count below \
         the noise-floor ratio (n_eff too low, or a version-1 tier with no signed n_eff)"
    )]
    Dominated,
    /// §19.7.1.3 (CIRISVerify#191 / CIRISPersist#435, CC 6.1.2.1.2 R9) — the
    /// tier's authenticated **content-similarity multiplicity** violates the
    /// `corpus_kind`-pinned floor ([`multiplicity_n_min_for`]): a cluster of
    /// near-duplicate members is too large a share of the fold, so the composite
    /// blur IS the data subject even though the mass-based `n_eff` is honest
    /// (the 900-near-duplicates-under-distinct-ids case the
    /// [`Self::Dominated`] gate admits). **Fail-closed:** a v1/v2 tier carries no
    /// signed `max_source_multiplicity` and is rejected here — the CIRISVerify#191
    /// flag-day cut.
    #[error(
        "aggregation_meta §19.7.1.3 multiplicity gate: content-similar cluster exceeds the \
         corpus-pinned floor (max_source_multiplicity too high, or a pre-v3 tier with no \
         signed multiplicity surface)"
    )]
    Multiplicity,
}

impl AggregationMetaError {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::HybridRequired => "aggregation_meta_hybrid_required",
            Self::MissingAggregatorPubkey(_) => "aggregation_meta_missing_pubkey",
            Self::MalformedInput(_) => "aggregation_meta_invalid",
            Self::MemberCommitmentMismatch => "aggregation_meta_member_commitment",
            Self::Dominated => "aggregation_meta_dominated",
            Self::Multiplicity => "aggregation_meta_multiplicity",
        }
    }
}

/// Decode a 32-byte member-commitment hex string into the raw root verify-core
/// expects. Public so the engine's §19.7.1.1 descent-integrity gate can rebuild
/// the verify-core meta from the stored navigation commitment.
pub fn aggregation_member_commitment_from_hex(hex: &str) -> Result<[u8; 32], AggregationMetaError> {
    decode_member_commitment_hex(hex)
}

/// Decode a 32-byte member-commitment hex string into the raw root verify-core
/// expects.
fn decode_member_commitment_hex(hex: &str) -> Result<[u8; 32], AggregationMetaError> {
    let bytes = hex_decode(hex).ok_or(AggregationMetaError::MalformedInput(
        "member_commitment_hex not hex",
    ))?;
    bytes
        .try_into()
        .map_err(|_| AggregationMetaError::MalformedInput("member_commitment_hex not 32 bytes"))
}

/// #435 (CIRISVerify#191) — decode the §19.7.1.3 v3 mass-commitment hex (the
/// Merkle root over per-member masses). Same 32-byte discipline as the member
/// commitment; a NON-EMPTY malformed value fails loudly (the caller treats
/// empty as the pre-v3 absent case).
fn decode_mass_commitment_hex(hex: &str) -> Result<[u8; 32], AggregationMetaError> {
    let bytes = hex_decode(hex).ok_or(AggregationMetaError::MalformedInput(
        "mass_commitment_hex not hex",
    ))?;
    bytes
        .try_into()
        .map_err(|_| AggregationMetaError::MalformedInput("mass_commitment_hex not 32 bytes"))
}

/// Minimal lowercase/uppercase hex decode (no extra dep — the codec-dep rule).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// The §19.7 aggregation provenance persist records for a composite — the
/// few navigation scalars persist needs, the opaque wire payload, AND (v8.4.0)
/// the §19.7.1 verification inputs that drive the store-path gate.
///
/// One record per composite (keyed by the composite's
/// [`aggregate_content_id`](Self::aggregate_content_id) =
/// `FountainManifestV1::content_id`). persist STORES `member_commitment` +
/// `aggregation_meta` (opaque); it VERIFIES the §19.7.1 bound-hybrid signature
/// over [`verification`](Self::verification) at admission and never persists
/// those inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationMetaV1 {
    /// The composite's `FountainContentV1` content_id (PK; one aggregation
    /// record per composite). The composite's `corpus_kind` is
    /// `"aggregate:<source_corpus_kind>"`.
    pub aggregate_content_id: String,
    /// What was folded: `"trace" | "blob" | "av_chunk" | "aggregate:..."`
    /// (for recursion).
    pub source_corpus_kind: String,
    /// Pyramid level: `0` = individual; level `L` folds `N` level-`(L-1)`
    /// items.
    pub aggregation_level: u64,
    /// `N` — the N→1 fan-in ratio at this fold.
    pub fan_in: u64,
    /// Merkle root (hex) over the folded source content_ids — proves
    /// membership WITHOUT storing N ids and WITHOUT making any source
    /// individually recoverable. STORED; equals the §19.7.1
    /// [`AggregationMetaVerifyInputsV1::member_commitment_hex`] (checked at
    /// admission).
    pub member_commitment: String,
    /// **OPAQUE** §19.7 aggregation wire payload. persist NEVER parses this —
    /// it is stored byte-for-byte (BYTEA on PG / BLOB on SQLite). The
    /// wire-churn firewall (V086 unchanged): whatever the §19.7 contract
    /// finalizes lives here without a migration change.
    #[serde(with = "crate::fountain::aggregation::meta_bytes_b64")]
    pub aggregation_meta: Vec<u8>,
    /// v8.4.0 (§19.7.1) — the canonical wire fields + bound-hybrid signature
    /// persist verifies at admission (PQC-mandatory store-path gate). NOT
    /// persisted (the storage column stays opaque).
    pub verification: AggregationMetaVerifyInputsV1,
}

impl AggregationMetaV1 {
    /// Run the §19.7.1 PQC-mandatory store-path gate (§10.1.5.1.1):
    ///
    /// 1. the stored navigation `member_commitment` (hex) MUST equal the
    ///    §19.7.1 wire commitment (else persist would store a root the
    ///    signature does not cover);
    /// 2. reconstruct the verify-core wire meta and verify its bound-hybrid
    ///    signature over the §19.7.1 canonical preimage against the aggregator
    ///    pubkeys (resolved off the composite manifest envelope). A
    ///    missing/invalid ML-DSA-65 half is rejected.
    ///
    /// On `Ok(())` the meta is admissible and the caller may persist. On
    /// `Err`, NOTHING is written (verify-before-mutation).
    pub fn verify_for_admission(
        &self,
        manifest: &super::types::FountainManifestV1,
    ) -> Result<(), AggregationMetaError> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        // (1) Stored navigation commitment MUST match the signed §19.7.1 one.
        //     Compare case-insensitively (both are hex of the same 32 bytes).
        if !self
            .member_commitment
            .eq_ignore_ascii_case(&self.verification.member_commitment_hex)
        {
            return Err(AggregationMetaError::MemberCommitmentMismatch);
        }

        // (2) Aggregator pubkeys ride the composite manifest envelope (the
        //     aggregator IS the composite's producer). Bound into the verify —
        //     a forged pubkey fails the signature.
        let ed_pub_b64 = manifest
            .envelope
            .get("pubkey_ed25519")
            .and_then(|v| v.as_str())
            .ok_or(AggregationMetaError::MissingAggregatorPubkey(
                "pubkey_ed25519",
            ))?;
        let mldsa_pub_b64 = manifest
            .envelope
            .get("pubkey_ml_dsa_65")
            .and_then(|v| v.as_str())
            // PQC-mandatory: absent PQC pubkey ⇒ cannot verify the mandatory
            // half ⇒ reject (never accept classical-only).
            .ok_or(AggregationMetaError::HybridRequired)?;

        let ed_pub = BASE64
            .decode(ed_pub_b64)
            .map_err(|_| AggregationMetaError::MalformedInput("pubkey_ed25519 base64"))?;
        let mldsa_pub = BASE64
            .decode(mldsa_pub_b64)
            .map_err(|_| AggregationMetaError::MalformedInput("pubkey_ml_dsa_65 base64"))?;
        let sig_ed = BASE64
            .decode(&self.verification.sig_ed25519_b64)
            .map_err(|_| AggregationMetaError::MalformedInput("sig_ed25519 base64"))?;
        // An empty PQC sig is the hard-cut classical-only signal — reject
        // before even decoding (mirrors the #225 fountain hard cut).
        if self.verification.sig_ml_dsa_65_b64.is_empty() {
            return Err(AggregationMetaError::HybridRequired);
        }
        let sig_mldsa = BASE64
            .decode(&self.verification.sig_ml_dsa_65_b64)
            .map_err(|_| AggregationMetaError::MalformedInput("sig_ml_dsa_65 base64"))?;

        let verify_meta = self.verification.to_verify_meta()?;
        match verify_aggregation_meta(&verify_meta, &sig_ed, &sig_mldsa, &ed_pub, &mldsa_pub) {
            AggregationMetaVerification::HybridVerified => {
                // §19.7.1.2 (CIRISVerify#167 / CIRISPersist#357) — dominance
                // gate. Only now that the bound-hybrid signature authenticated
                // `n_eff` is the effective-source-count trustworthy; reject a
                // dominated fold (and, fail-closed, any version-1 tier that
                // carries no signed n_eff). §10.1.5.1.1: BEFORE persistence.
                if !passes_dominance_gate(&verify_meta, MIN_DOMINANCE_RATIO) {
                    return Err(AggregationMetaError::Dominated);
                }
                // §19.7.1.3 (CIRISVerify#191 / CIRISPersist#435) — multiplicity
                // gate, the content-similarity sibling BOTH must pass: the
                // authenticated `max_source_multiplicity` must respect the
                // corpus-pinned floor. Rejects the 900-near-duplicates-under-
                // distinct-ids fold the mass gate honestly admits (equal masses
                // ⇒ truthful n_eff = 1000, yet the composite blur IS the data
                // subject). Fail-closed for a pre-v3 tier (no signed
                // multiplicity surface — the CIRISVerify#191 flag-day cut).
                if !passes_multiplicity_gate(
                    &verify_meta,
                    multiplicity_n_min_for(&verify_meta.corpus_kind),
                ) {
                    return Err(AggregationMetaError::Multiplicity);
                }
                Ok(())
            }
            AggregationMetaVerification::Failed => Err(AggregationMetaError::HybridRequired),
        }
    }
}

/// The stored aggregation record (read shape) — the persisted columns plus
/// persist's `aggregated_at_unix_ms` stamp. NOTE: the §19.7.1 verification
/// inputs are admission-only and are NOT part of the stored record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationRecordV1 {
    /// See [`AggregationMetaV1::aggregate_content_id`].
    pub aggregate_content_id: String,
    /// See [`AggregationMetaV1::source_corpus_kind`].
    pub source_corpus_kind: String,
    /// See [`AggregationMetaV1::aggregation_level`].
    pub aggregation_level: u64,
    /// See [`AggregationMetaV1::fan_in`].
    pub fan_in: u64,
    /// See [`AggregationMetaV1::member_commitment`].
    pub member_commitment: String,
    /// See [`AggregationMetaV1::aggregation_meta`] — opaque bytes.
    #[serde(with = "crate::fountain::aggregation::meta_bytes_b64")]
    pub aggregation_meta: Vec<u8>,
    /// When persist recorded the fold (epoch ms).
    pub aggregated_at_unix_ms: i64,
}

/// base64 (de)serialization for the opaque `aggregation_meta` over the
/// JSON-over-FFI boundary. The bytes stay opaque — base64 is only the
/// JSON-safe transport encoding (raw bytes can be non-UTF-8).
pub(crate) mod meta_bytes_b64 {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b64 = String::deserialize(d)?;
        BASE64
            .decode(b64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// v8.4.0 (§19.7.3) — route verify-core's [`EjectionVerdict`] onto a persist
/// eviction action. The verdict (driven by
/// [`ejection_verdict`]`(consent, under_capacity_pressure)`) is canonical;
/// for [`EjectionVerdict::EjectToTier`] persist supplies the concrete target
/// [`FountainTier`](super::eviction::FountainTier) (the verify-core verdict is
/// tier-agnostic — WHICH tier is persist's storage decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EjectionAction {
    /// Above the floor / no pressure — retain at current fidelity (no-op).
    Keep,
    /// One downward step — degrade to the target tier (operator-1 fade) via
    /// [`crate::store::Backend::evict_fountain_content_to_tier`].
    EjectToTier(super::eviction::FountainTier),
    /// Forced below the floor — drop every still-recoverable symbol via
    /// [`crate::store::Backend::evict_fountain_content_hard_delete`]. The
    /// manifest survives as `EnvelopeOnly`; any composite this source folded
    /// into is untouched (descent never terminates at zero).
    EjectHardDelete,
    /// v8.6.0 (§19.7.3, verify v5.11.0 / CEG RC16) — shed **exactly one**
    /// pyramid stratum: the tier-`u32` [`AggregationMetaV1`] composite, leaving
    /// BOTH the finer (lower-level) AND coarser (higher-level) composites
    /// intact. The tier-granular form of [`EjectionAction::EjectToTier`] — it
    /// sheds ONE intermediate stratum rather than degrading a source object.
    /// Mechanically this hard-deletes the tier-`u32` composite's symbols
    /// (manifest survives as `EnvelopeOnly` provenance) via
    /// [`evict_aggregated_tier_on_backend`]. Composes with hard-delete: a tier
    /// already below the noise floor is unreachable, so this never resurrects
    /// erased content. Carries the stratum tier index.
    EjectAggregatedTierOnly(u32),
}

impl EjectionAction {
    /// Stable string-token (telemetry / logs).
    pub fn label(&self) -> &'static str {
        match self {
            EjectionAction::Keep => "keep",
            EjectionAction::EjectToTier(_) => "eject_to_tier",
            EjectionAction::EjectHardDelete => "eject_hard_delete",
            EjectionAction::EjectAggregatedTierOnly(_) => "eject_aggregated_tier_only",
        }
    }

    /// Resolve the persist action from the canonical §19.7.3
    /// [`ejection_verdict`] plus the persist-side target tier used when the
    /// verdict is a tier-shed. A `Keep`/`EjectHardDelete` verdict ignores
    /// `target_tier`; `EjectToTier` with `target_tier = None` (or `Full`) is a
    /// no-op `Keep` (nothing dropped — full fidelity retained).
    #[must_use]
    pub fn from_verdict(
        verdict: EjectionVerdict,
        target_tier: Option<super::eviction::FountainTier>,
    ) -> EjectionAction {
        match verdict {
            EjectionVerdict::Keep => EjectionAction::Keep,
            EjectionVerdict::EjectHardDelete => EjectionAction::EjectHardDelete,
            EjectionVerdict::EjectToTier => match target_tier {
                None | Some(super::eviction::FountainTier::Full) => EjectionAction::Keep,
                Some(t) => EjectionAction::EjectToTier(t),
            },
            // v8.6.0 (§19.7.3): the tier-granular stratum-shed. The verdict
            // carries WHICH pyramid stratum to shed; persist sheds that exact
            // composite (`target_tier` is irrelevant — it is a stratum index,
            // not a fidelity tier).
            EjectionVerdict::EjectAggregatedTierOnly { tier } => {
                EjectionAction::EjectAggregatedTierOnly(tier)
            }
        }
    }
}

/// v8.4.0 (CEG 1.0-RC14 §19.7 / CIRISPersist#230) — §19.7 descent
/// orchestration over a backend, gated on the §19.7.1.1 descent-integrity
/// check and driven by the canonical §19.7.3 verdict. The single shared
/// implementation the engine dispatch and the FFI dispatch both call (so the
/// gate is byte-identical across PG / SQLite).
///
/// 1. **§19.7.1.1 descent integrity.** Load the stored aggregation record for
///    `aggregate_content_id`; the caller-supplied source content_ids MUST
///    re-derive its committed `member_commitment`
///    ([`verify_member_commitment`]) — a forged member set is REJECTED
///    ([`AggregationMetaError::MemberCommitmentMismatch`]) and cannot drive
///    eviction. Sources descend in the canonical [`descend_order`].
/// 2. **§19.7.3 verdict.** Per-source step = [`ejection_verdict`]`(consent,
///    under_capacity_pressure)` mapped onto a persist [`EjectionAction`]
///    (`EjectToTier` uses `target_tier`). The composite (collective blur) is
///    NEVER touched — descent never terminates at zero. Returns total symbol
///    rows evicted.
pub async fn descend_aggregated_sources_on_backend<B: crate::store::Backend>(
    backend: &B,
    aggregate_content_id: &str,
    sources: &[(String, String)],
    consent: ciris_verify_core::holonomic::ConsentState,
    under_capacity_pressure: bool,
    target_tier: Option<super::eviction::FountainTier>,
) -> Result<u64, crate::store::Error> {
    let record = backend
        .get_aggregation(aggregate_content_id)
        .await?
        .ok_or_else(|| {
            crate::store::Error::Backend(format!(
                "descend: no aggregation record for {aggregate_content_id}"
            ))
        })?;
    let member_ids: Vec<String> = sources.iter().map(|(id, _)| id.clone()).collect();
    let verify_meta = ciris_verify_core::holonomic::AggregationMetaV1 {
        version: 1,
        content_id: aggregate_content_id.to_owned(),
        corpus_kind: record.source_corpus_kind.clone(),
        tier: 0,
        aggregation_algorithm_id: String::new(),
        source_count: member_ids.len() as u32,
        // §19.7.1.2 (#167): v1 neutral placeholder (n_eff == source_count).
        // This meta drives only `verify_member_commitment` (membership), and a
        // v1 preimage excludes n_eff, so the value is verification-neutral.
        n_eff: member_ids.len() as u32,
        // §19.7.1.3 (#435): same v1-neutral rule — this rebuild feeds ONLY the
        // membership check, never the multiplicity/mass gates (a v1 preimage
        // excludes both), so zero placeholders are verification-neutral.
        max_source_multiplicity: 0,
        mass_commitment: [0u8; 32],
        member_commitment: aggregation_member_commitment_from_hex(&record.member_commitment)
            .map_err(crate::store::Error::AggregationMetaRejected)?,
        noise_floor_descriptor: String::new(),
    };
    if !verify_member_commitment(&verify_meta, &member_ids) {
        return Err(crate::store::Error::AggregationMetaRejected(
            AggregationMetaError::MemberCommitmentMismatch,
        ));
    }

    let verdict = ejection_verdict(consent, under_capacity_pressure);
    let action = EjectionAction::from_verdict(verdict, target_tier);
    let ordered = descend_order(&member_ids);
    let corpus_of: std::collections::HashMap<&str, &str> = sources
        .iter()
        .map(|(id, corpus)| (id.as_str(), corpus.as_str()))
        .collect();

    let mut total = 0u64;
    for content_id in &ordered {
        let corpus_kind = corpus_of[content_id.as_str()];
        total += match action {
            EjectionAction::Keep => 0,
            EjectionAction::EjectToTier(tier) => {
                backend
                    .evict_fountain_content_to_tier(content_id, corpus_kind, tier)
                    .await?
            }
            EjectionAction::EjectHardDelete => {
                backend
                    .evict_fountain_content_hard_delete(content_id, corpus_kind)
                    .await?
            }
            // v8.6.0 (§19.7.3): a stratum-shed targets a COMPOSITE, not the
            // per-source descent driven here — it is the dedicated
            // [`evict_aggregated_tier_on_backend`] entry point. The
            // source-fold descent never sheds a pyramid stratum, so this is a
            // no-op on this path (the verdict mapping cannot reach it: the
            // source-descent verdict is `ejection_verdict(consent, pressure)`,
            // which only yields Keep / EjectToTier / EjectHardDelete).
            EjectionAction::EjectAggregatedTierOnly(_) => 0,
        };
    }
    Ok(total)
}

/// v8.6.0 (§19.7.3 / verify v5.11.0 / CEG RC16) — execute an
/// [`EjectionAction::EjectAggregatedTierOnly`]: shed **exactly one** pyramid
/// stratum — the tier-`tier` `content_aggregation` composite — leaving BOTH the
/// finer (lower-level) AND coarser (higher-level) composites' symbols intact.
///
/// The tier-granular form of `EjectToTier`: rather than degrading a source
/// object or the whole item, it drops the SYMBOLS of the ONE composite at
/// `aggregation_level == tier`, leaving that composite's manifest as the
/// always-retained `EnvelopeOnly` provenance ("this stratum existed with
/// signature X"). It composes existing primitives — it is effectively
/// `evict_fountain_content_hard_delete` on the tier-`tier` composite's
/// `aggregate_content_id`:
///
/// 1. **Resolve the stratum.** Load the stored aggregation record for
///    `aggregate_content_id` ([`crate::store::Backend::get_aggregation`]).
///    Unknown composite ⇒ `Ok(0)` no-op (composes with hard-delete: a stratum
///    already erased / below the floor is unreachable — this never resurrects
///    erased content).
/// 2. **Stratum guard.** The resolved composite's `aggregation_level` MUST
///    equal the requested `tier`; otherwise the caller named a stratum at the
///    wrong level and NOTHING is shed (`Ok(0)`) — we never shed a different
///    level than asked.
/// 3. **Shed exactly that composite.** Hard-delete the tier-`tier` composite's
///    symbols via [`crate::store::Backend::evict_fountain_content_hard_delete`]
///    on `aggregate_content_id` with `corpus_kind = "aggregate:<source>"`
///    ([`aggregate_corpus_kind`]). Composites at other levels are SEPARATE
///    `content_aggregation` rows with their OWN `aggregate_content_id`s and are
///    never touched. Returns the number of symbol rows shed.
pub async fn evict_aggregated_tier_on_backend<B: crate::store::Backend>(
    backend: &B,
    aggregate_content_id: &str,
    tier: u32,
) -> Result<u64, crate::store::Error> {
    let Some(record) = backend.get_aggregation(aggregate_content_id).await? else {
        // Unknown / already-erased stratum — no-op. Never resurrects content.
        return Ok(0);
    };
    // Stratum guard: only shed if the composite is actually at the named tier.
    if record.aggregation_level != u64::from(tier) {
        return Ok(0);
    }
    let corpus_kind = aggregate_corpus_kind(&record.source_corpus_kind);
    backend
        .evict_fountain_content_hard_delete(aggregate_content_id, &corpus_kind)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::holonomic::ConsentState;

    #[test]
    fn aggregate_corpus_kind_prefixes_and_nests() {
        assert_eq!(aggregate_corpus_kind("trace"), "aggregate:trace");
        assert_eq!(
            aggregate_corpus_kind("aggregate:trace"),
            "aggregate:aggregate:trace"
        );
    }

    #[test]
    fn hex_decode_round_trips_and_rejects_bad() {
        assert_eq!(hex_decode("00ff7f"), Some(vec![0x00, 0xff, 0x7f]));
        assert_eq!(hex_decode("AABB"), Some(vec![0xaa, 0xbb]));
        assert_eq!(hex_decode("0"), None, "odd length");
        assert_eq!(hex_decode("zz"), None, "non-hex");
    }

    /// §19.7.1.3 (#435) — the literal CC 6.1.2.1.2 R9 case at the pinned floor:
    /// 900 near-duplicates among 1000 distinct-id members, equal masses (an
    /// HONEST `n_eff = 1000` that clears the mass gate) — rejected by the
    /// multiplicity gate; the balanced fold passes; pre-v3 fails closed.
    #[test]
    fn multiplicity_gate_rejects_the_900_of_1000_fold() {
        let meta =
            |version: u32, multiplicity: u32| ciris_verify_core::holonomic::AggregationMetaV1 {
                version,
                content_id: "c".into(),
                corpus_kind: "trace".into(),
                tier: 1,
                aggregation_algorithm_id: "raptorq-pyramid-v1".into(),
                source_count: 1000,
                n_eff: 1000, // honest: 1000 distinct members at equal mass
                max_source_multiplicity: multiplicity,
                mass_commitment: [0u8; 32],
                member_commitment: [0u8; 32],
                noise_floor_descriptor: String::new(),
            };
        let n_min = multiplicity_n_min_for("aggregate:trace");
        assert_eq!(n_min, DEFAULT_MULTIPLICITY_N_MIN);
        // 900 · 2 = 1800 > 1000 → the R9 false-erasure is REJECTED.
        assert!(!passes_multiplicity_gate(&meta(3, 900), n_min));
        // ...even though the mass gate honestly admits it (n_eff == N).
        assert!(passes_dominance_gate(&meta(3, 900), MIN_DOMINANCE_RATIO));
        // A genuinely-diverse fold passes: 500 · 2 = 1000 ≤ 1000.
        assert!(passes_multiplicity_gate(&meta(3, 500), n_min));
        // Flag-day: a v2 tier (no signed multiplicity) fails CLOSED.
        assert!(!passes_multiplicity_gate(&meta(2, 1), n_min));
    }

    /// #435 — the v3 mass-commitment wire decode: empty ⇒ pre-v3 neutral zero
    /// root; malformed non-empty ⇒ loud reject (never silently zeroed).
    #[test]
    fn mass_commitment_hex_decode_empty_neutral_malformed_loud() {
        let inputs = |hex: &str| AggregationMetaVerifyInputsV1 {
            version: 3,
            content_id: "c".into(),
            corpus_kind: "trace".into(),
            tier: 1,
            aggregation_algorithm_id: "a".into(),
            source_count: 2,
            n_eff: 2,
            max_source_multiplicity: 1,
            mass_commitment_hex: hex.into(),
            member_commitment_hex: "00".repeat(32),
            noise_floor_descriptor: String::new(),
            sig_ed25519_b64: String::new(),
            sig_ml_dsa_65_b64: String::new(),
        };
        assert_eq!(
            inputs("").to_verify_meta().unwrap().mass_commitment,
            [0u8; 32],
            "empty = pre-v3 absent, neutral zero root"
        );
        let good = "11".repeat(32);
        assert_eq!(
            inputs(&good).to_verify_meta().unwrap().mass_commitment,
            [0x11u8; 32]
        );
        assert!(
            inputs("zz").to_verify_meta().is_err(),
            "malformed non-empty mass hex must fail loudly"
        );
        assert!(
            inputs("1234").to_verify_meta().is_err(),
            "wrong-length mass hex must fail loudly"
        );
    }

    #[test]
    fn ejection_action_maps_verdict_plus_tier() {
        use super::super::eviction::FountainTier;
        // §19.7.3: revoked → hard delete regardless of target tier.
        assert_eq!(
            EjectionAction::from_verdict(
                ejection_verdict(ConsentState::Withdrawn, true),
                Some(FountainTier::T3)
            ),
            EjectionAction::EjectHardDelete
        );
        // Capacity pressure on a live item → tier-shed to the persist target.
        assert_eq!(
            EjectionAction::from_verdict(
                ejection_verdict(ConsentState::Active, true),
                Some(FountainTier::T3)
            ),
            EjectionAction::EjectToTier(FountainTier::T3)
        );
        // No pressure → keep.
        assert_eq!(
            EjectionAction::from_verdict(ejection_verdict(ConsentState::Active, false), None),
            EjectionAction::Keep
        );
        // Tier-shed with a None/Full target degrades to a no-op Keep.
        assert_eq!(
            EjectionAction::from_verdict(EjectionVerdict::EjectToTier, None),
            EjectionAction::Keep
        );
        assert_eq!(
            EjectionAction::from_verdict(EjectionVerdict::EjectToTier, Some(FountainTier::Full)),
            EjectionAction::Keep
        );
        assert_eq!(EjectionAction::EjectHardDelete.label(), "eject_hard_delete");
    }
}
