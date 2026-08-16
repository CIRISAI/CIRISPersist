// v3.6.0: media-sharing enum variants are wire constants; their
// semantics live in this module's doc-block (above) and at the
// [`LegalBasis`] type-level — not in per-variant rustdoc. Mirrors the
// same `#![allow(missing_docs)]` call from
// `cirisnode::federation_announcement`.
#![allow(missing_docs)]

//! Media-sharing substrate (CIRISPersist#134, v3.6.0).
//!
//! Two new `subject_kind` values on `cirisnode.contributions`:
//!
//!   - [`TAKEDOWN_NOTICE_SUBJECT_KIND`] — content-claimant assertion that
//!     bytes under the named SHA-256 must be evicted from holders'
//!     storage. The persist write path runs the typed
//!     [`TakedownNoticePayload`] shape validator, projects the
//!     `content_sha256` + `legal_basis` into dedicated indexed columns
//!     (V054), and the takedown handler
//!     ([`super::takedown_handler::process_takedown_admission`]) emits
//!     `withdraws` attestations against every live `holds_bytes` row
//!     for the SHA + optionally `evict_actor`s for immediate-eviction
//!     bases.
//!
//!   - [`KEY_GRANT_SUBJECT_KIND`] — key-distribution envelope binding a
//!     wrapped DEK to a recipient `key_id` over a `content_sha256` (or
//!     scope tier). Persist projects `content_sha256` +
//!     `recipient_key_id` into V054 columns; consumers index by either
//!     axis. Bond-sale composition and registry-license issuance share
//!     this row shape per the one-key primitive
//!     ([[project_one_key_primitive]]).
//!
//! # Upstream contracts
//!
//! CEG 0.3 §5.6.8.4 + §11.4 + §11.5 (Registry commit a7d95cd) closed
//! CIRISRegistry#38 (vocabulary + per-basis discipline + wrap-algorithm
//! identity + retire emission shape) and CIRISRegistry#39 (hash-DB
//! operator policy — self-hosted PDQ default, option a).
//! CIRISNodeCore#24 (counter-notice carrier shape) remains open;
//! TODO markers retained at the relevant call sites.
//!
//! The lock-in:
//!
//!   - [`LegalBasis`] vocabulary: 10 values, 5+4+1 discipline split.
//!   - [`WrapAlgorithm`]: v34.0.0 (#704) leaves ONE variant, the PQC
//!     hybrid `X25519MlKem768Aes256GcmHkdfSha256`. The classical-only v1
//!     is GONE rather than superseded — there is no algorithm to choose,
//!     so there is no wrong choice to make.

use std::collections::HashSet;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::Error;

/// Wire constant — `subject_kind` for content-claim takedown rows on
/// `cirisnode.contributions`. Matches the V054 partial-CHECK
/// vocabulary.
pub const TAKEDOWN_NOTICE_SUBJECT_KIND: &str = "takedown_notice";

/// Wire constant — `subject_kind` for key-distribution rows on
/// `cirisnode.contributions`.
pub const KEY_GRANT_SUBJECT_KIND: &str = "key_grant";

// ── LegalBasis ──────────────────────────────────────────────────────

/// Closed-set vocabulary of legal / policy bases under which a
/// `takedown_notice` is filed.
///
/// CEG 0.3 §5.6.8.4 + §11.4 (Registry commit a7d95cd, closes
/// CIRISRegistry#38) locked the 10-value closed set with a 5+4+1
/// discipline split:
///
///   - **Immediate-removal (5)**: [`Self::TvecTerrorist`],
///     [`Self::NcmecCsam`], [`Self::GifctCip`],
///     [`Self::PerceptualHashCsam`], [`Self::CourtOrder`].
///     Persist evicts the blob holders immediately alongside emitting
///     `withdraws`.
///   - **Expeditious-with-counter-notice (4)**: [`Self::Dmca512`],
///     [`Self::DsaArticle16`], [`Self::OsaIllegalContent`],
///     [`Self::CommunityStandards`]. Persist emits `withdraws` and
///     schedules a delayed eviction the operator can preempt with a
///     counter-notice.
///   - **Compose-with-age-gate (1)**: [`Self::AvmsdAgeInappropriate`].
///     Persist emits `withdraws` but does NOT evict; the
///     receiver-side display gate filters at read time per Policy J
///     (CEG 0.3 §8.1.10).
///
/// Three helpers project policy onto the variant:
///
///   - [`Self::admits_counter_notice`] — `true` for the four
///     counter-noticed bases.
///   - [`Self::requires_immediate_eviction`] — `true` for the five
///     immediate-removal bases.
///   - [`Self::composes_with_age_gate`] — `true` only for
///     `AvmsdAgeInappropriate`.
///
/// # CEG 0.3 §5.6.8.4 + §11.4 — LegalBasis locked
///
/// Vocabulary + per-basis discipline locked upstream. The enum gets
/// a coordinated rev only when CEG bumps to a later version with
/// additional bases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LegalBasis {
    #[serde(rename = "dmca_512")]
    Dmca512,
    #[serde(rename = "dsa_article_16")]
    DsaArticle16,
    #[serde(rename = "tvec_terrorist")]
    TvecTerrorist,
    #[serde(rename = "ncmec_csam")]
    NcmecCsam,
    #[serde(rename = "gifct_cip")]
    GifctCip,
    #[serde(rename = "community_standards")]
    CommunityStandards,
    #[serde(rename = "perceptual_hash_csam")]
    PerceptualHashCsam,
    #[serde(rename = "osa_illegal_content")]
    OsaIllegalContent,
    #[serde(rename = "avmsd_age_inappropriate")]
    AvmsdAgeInappropriate,
    #[serde(rename = "court_order")]
    CourtOrder,
}

impl LegalBasis {
    /// Wire-shaped string — matches the V054 CHECK constraint
    /// vocabulary on `takedown_legal_basis`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dmca512 => "dmca_512",
            Self::DsaArticle16 => "dsa_article_16",
            Self::TvecTerrorist => "tvec_terrorist",
            Self::NcmecCsam => "ncmec_csam",
            Self::GifctCip => "gifct_cip",
            Self::CommunityStandards => "community_standards",
            Self::PerceptualHashCsam => "perceptual_hash_csam",
            Self::OsaIllegalContent => "osa_illegal_content",
            Self::AvmsdAgeInappropriate => "avmsd_age_inappropriate",
            Self::CourtOrder => "court_order",
        }
    }

    /// Parse from the wire-shaped string. Returns `None` on vocabulary
    /// mismatch.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "dmca_512" => Self::Dmca512,
            "dsa_article_16" => Self::DsaArticle16,
            "tvec_terrorist" => Self::TvecTerrorist,
            "ncmec_csam" => Self::NcmecCsam,
            "gifct_cip" => Self::GifctCip,
            "community_standards" => Self::CommunityStandards,
            "perceptual_hash_csam" => Self::PerceptualHashCsam,
            "osa_illegal_content" => Self::OsaIllegalContent,
            "avmsd_age_inappropriate" => Self::AvmsdAgeInappropriate,
            "court_order" => Self::CourtOrder,
            _ => return None,
        })
    }

    /// `true` iff this basis schedules a counter-notice window before
    /// the eviction is applied (instead of evicting immediately).
    ///
    /// CEG 0.3 §5.6.8.4 + §11.4 locked the expeditious-with-counter-notice
    /// set to four bases: DMCA §512, DSA art. 16, OSA illegal content,
    /// and Community Standards.
    pub fn admits_counter_notice(self) -> bool {
        matches!(
            self,
            Self::Dmca512 | Self::DsaArticle16 | Self::OsaIllegalContent | Self::CommunityStandards
        )
    }

    /// `true` iff this basis REQUIRES `evict_actor` to run alongside
    /// the `withdraws` attestation (no counter-notice window).
    ///
    /// CEG 0.3 §5.6.8.4 + §11.4 locked the immediate-removal set to
    /// five bases: TVEC, NCMEC CSAM, GIFCT CIP, perceptual-hash CSAM,
    /// and court orders. CourtOrder moved into this set (was
    /// expeditious in the architect's draft); TvecTerrorist moved in
    /// (was operator-policy in the draft).
    pub fn requires_immediate_eviction(self) -> bool {
        matches!(
            self,
            Self::TvecTerrorist
                | Self::NcmecCsam
                | Self::GifctCip
                | Self::PerceptualHashCsam
                | Self::CourtOrder
        )
    }

    /// `true` iff this basis composes with the [Policy J](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/CEG.md#811-policy-j-trusted-publisher)
    /// age-assurance gate. The takedown_handler emits withdraws AND
    /// attaches the age-assurance gate per Policy J, but does NOT
    /// trigger eviction. The blob stays in `federation_blobs`; the
    /// receiver-side display gate filters at read time.
    ///
    /// CEG 0.3 §5.6.8.4: only `AvmsdAgeInappropriate` belongs in this
    /// new discipline category.
    pub fn composes_with_age_gate(self) -> bool {
        matches!(self, Self::AvmsdAgeInappropriate)
    }

    /// Counter-notice window in days for the basis. Persist defaults:
    /// 10 days for DMCA §512, 14 days for DSA art. 16, 14 days for OSA
    /// illegal content, 30 days for community-standards appeals. `None`
    /// for non-counter-noticed bases.
    ///
    /// # TODO(CIRISNodeCore#24)
    ///
    /// Counter-notice carrier shape pending upstream spec. NodeCore
    /// locks the carrier; these constants ship as the functional
    /// default until that lands.
    pub fn counter_notice_window_days(self) -> Option<u32> {
        match self {
            Self::Dmca512 => Some(10),
            Self::DsaArticle16 => Some(14),
            Self::OsaIllegalContent => Some(14),
            Self::CommunityStandards => Some(30),
            _ => None,
        }
    }
}

// ── MultimediaConfig ────────────────────────────────────────────────

/// v3.6.0 (CIRISPersist#134) — operator config for the media-sharing
/// path. Sibling of [`ReplicationConfig`](crate::federation::ReplicationConfig).
///
/// Three knobs:
///
///   - [`Self::counter_notice_window_days`] — wall-clock window
///     (in days) that the
///     [`takedown_handler`](crate::cirisnode::takedown_handler::process_takedown_admission)
///     applies to counter-noticed bases. Persist default is 14 (matches
///     the DSA art. 16 sane-default). Operators with a 10-day DMCA
///     §512 policy or a 30-day community-standards appeal policy
///     override per deployment.
///
///   - [`Self::immediate_legal_bases`] — set of [`LegalBasis`] values
///     for which the handler runs [`evict_actor`](crate::federation::BlobStorage::evict_actor)
///     immediately (in addition to emitting `withdraws`). CEG 0.3
///     §11.4 locks the default at the 5-basis immediate-removal set:
///     [`LegalBasis::TvecTerrorist`], [`LegalBasis::NcmecCsam`],
///     [`LegalBasis::GifctCip`], [`LegalBasis::PerceptualHashCsam`],
///     [`LegalBasis::CourtOrder`]. Operators may widen or narrow.
///
///   - [`Self::age_gate_legal_bases`] — set of [`LegalBasis`] values
///     that compose with the Policy J age-assurance gate (CEG 0.3
///     §8.1.10): emit `withdraws` AND attach the age gate, but do NOT
///     evict. Default `{AvmsdAgeInappropriate}`.
///
/// # TODO(CIRISNodeCore#24)
///
/// Counter-notice carrier shape pending upstream spec. Persist ships
/// a single global `counter_notice_window_days` knob as the v1
/// default until upstream locks the per-basis carrier.
#[derive(Debug, Clone)]
pub struct MultimediaConfig {
    /// Global counter-notice window in days. Default 14 (DSA art. 16
    /// sane-default).
    pub counter_notice_window_days: u32,

    /// Set of legal bases that trigger immediate eviction. CEG 0.3
    /// §11.4 default: the five immediate-removal bases. Operator
    /// override either widens (e.g. add `OsaIllegalContent` for
    /// non-counter-noticed jurisdictions) or narrows (e.g. drop
    /// `CourtOrder` until manual review).
    pub immediate_legal_bases: HashSet<LegalBasis>,

    /// Set of legal bases that compose with the Policy J age-assurance
    /// gate. CEG 0.3 §8.1.10 default: `{AvmsdAgeInappropriate}`.
    /// Operator override accepts additional bases the deployment
    /// wants gated rather than evicted.
    pub age_gate_legal_bases: HashSet<LegalBasis>,
}

impl Default for MultimediaConfig {
    fn default() -> Self {
        let mut immediate = HashSet::with_capacity(5);
        immediate.insert(LegalBasis::TvecTerrorist);
        immediate.insert(LegalBasis::NcmecCsam);
        immediate.insert(LegalBasis::GifctCip);
        immediate.insert(LegalBasis::PerceptualHashCsam);
        immediate.insert(LegalBasis::CourtOrder);
        let mut age_gate = HashSet::with_capacity(1);
        age_gate.insert(LegalBasis::AvmsdAgeInappropriate);
        Self {
            counter_notice_window_days: 14,
            immediate_legal_bases: immediate,
            age_gate_legal_bases: age_gate,
        }
    }
}

impl MultimediaConfig {
    /// True iff the basis is in [`Self::immediate_legal_bases`].
    /// Replaces the hardcoded
    /// [`LegalBasis::requires_immediate_eviction`] check at the
    /// `takedown_handler` call site.
    pub fn is_immediate(&self, basis: LegalBasis) -> bool {
        self.immediate_legal_bases.contains(&basis)
    }

    /// True iff the basis is in [`Self::age_gate_legal_bases`].
    /// Replaces the hardcoded
    /// [`LegalBasis::composes_with_age_gate`] check at the
    /// `takedown_handler` call site.
    pub fn is_age_gated(&self, basis: LegalBasis) -> bool {
        self.age_gate_legal_bases.contains(&basis)
    }
}

/// JSON wire shape for [`MultimediaConfig`] — used by
/// `PyEngine::set_multimedia_config_json` to round-trip the config
/// across the FFI boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultimediaConfigWire {
    /// Counter-notice window in days.
    pub counter_notice_window_days: u32,
    /// Wire-string LegalBasis values that trigger immediate eviction.
    pub immediate_legal_bases: Vec<String>,
    /// Wire-string LegalBasis values that compose with the Policy J
    /// age-assurance gate. Defaults to empty on the wire if not set —
    /// caller's responsibility to round-trip the default if they want
    /// it preserved.
    #[serde(default)]
    pub age_gate_legal_bases: Vec<String>,
}

impl MultimediaConfigWire {
    /// Decode the wire shape into a typed [`MultimediaConfig`].
    /// Returns [`Error::InvalidArgument`] on unknown LegalBasis variant.
    pub fn into_config(self) -> Result<MultimediaConfig, Error> {
        let immediate = decode_basis_set(&self.immediate_legal_bases, "immediate_legal_bases")?;
        let age_gate = decode_basis_set(&self.age_gate_legal_bases, "age_gate_legal_bases")?;
        Ok(MultimediaConfig {
            counter_notice_window_days: self.counter_notice_window_days,
            immediate_legal_bases: immediate,
            age_gate_legal_bases: age_gate,
        })
    }

    /// Encode a [`MultimediaConfig`] back to the wire shape (e.g. for
    /// a `get_multimedia_config_json` accessor on PyEngine).
    pub fn from_config(cfg: &MultimediaConfig) -> Self {
        let mut immediate: Vec<String> = cfg
            .immediate_legal_bases
            .iter()
            .map(|b| b.as_str().to_owned())
            .collect();
        immediate.sort();
        let mut age_gate: Vec<String> = cfg
            .age_gate_legal_bases
            .iter()
            .map(|b| b.as_str().to_owned())
            .collect();
        age_gate.sort();
        Self {
            counter_notice_window_days: cfg.counter_notice_window_days,
            immediate_legal_bases: immediate,
            age_gate_legal_bases: age_gate,
        }
    }
}

fn decode_basis_set(names: &[String], field: &str) -> Result<HashSet<LegalBasis>, Error> {
    let mut out = HashSet::with_capacity(names.len());
    for s in names {
        let basis = LegalBasis::from_wire_str(s).ok_or_else(|| {
            Error::InvalidArgument(format!(
                "MultimediaConfigWire: unknown LegalBasis variant {s:?} in {field}"
            ))
        })?;
        out.insert(basis);
    }
    Ok(out)
}

// ── TakedownNoticePayload ───────────────────────────────────────────

/// `takedown_notice` payload — JSONB on `cirisnode.contributions.payload`.
///
/// The `content_sha256` + `legal_basis` fields are additionally
/// projected onto the dedicated `media_content_sha256` +
/// `takedown_legal_basis` columns (V054) so reads don't dig into JSONB
/// and the cross-column CHECK fires on direct-SQL bypass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TakedownNoticePayload {
    /// SHA-256 of the content body, hex-encoded (64 lowercase hex).
    pub content_sha256: String,

    /// Optional perceptual / robust hash discriminator (PDQ, PhotoDNA,
    /// Arachnid Shield digest, etc.). Vendor format is opaque to
    /// persist — operators store and forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perceptual_hash: Option<String>,

    /// Federation `key_id`s of the holders the claimant identifies as
    /// having the bytes. Persist uses [`super::super::federation::BlobStorage::list_holders`]
    /// authoritatively, so this field is documentation /
    /// claim-provenance only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_holder_key_ids: Vec<String>,

    /// `key_id` of the entity filing the claim. Persist does not
    /// verify ownership / standing — the [`AdmissionGate`](crate::federation::AdmissionGate)
    /// is the trust-weighted admission surface.
    pub claimant_key_id: String,

    /// Closed-set legal basis under which the notice is filed.
    pub legal_basis: LegalBasis,

    /// ISO-3166-1 alpha-2 jurisdiction code. Free-form to admit
    /// regional sub-codes; persist does not validate.
    pub jurisdiction: String,

    /// "Good faith" statement required by some bases (DMCA §512(c)(3)(A)(v)
    /// notably). Free-form text; persist stores verbatim.
    pub good_faith_statement: String,

    /// Free-form claim narrative.
    pub claim_text: String,

    /// Evidence references — URLs, IPFS CIDs, prior contribution IDs,
    /// etc. Persist stores verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,

    /// Counter-notice channel — operator-defined contact for the
    /// counter-notice carrier shape that NodeCore#24 locks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_notice_channel: Option<String>,

    /// When the notice was filed by the claimant.
    pub asserted_at: DateTime<Utc>,

    /// When the notice is no longer relevant. REQUIRED to bound replay
    /// risk (mirroring `FederationAnnouncementPayload::expires_at`).
    pub expires_at: DateTime<Utc>,
}

// ── KeyGrantPayload ─────────────────────────────────────────────────

/// `key_grant` payload — JSONB on `cirisnode.contributions.payload`.
///
/// The `content_sha256` + `recipient_key_id` fields are additionally
/// projected onto the dedicated `media_content_sha256` +
/// `key_grant_recipient_key_id` columns (V054) for indexed reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyGrantPayload {
    /// Federation `key_id` of the recipient — the entity authorized to
    /// unwrap the DEK.
    pub recipient_key_id: String,

    /// SHA-256 of the content body the granted key encrypts, hex-encoded.
    /// Present iff the grant is **content-addressed**; `None` for a
    /// **stream/epoch-addressed** streaming grant (see [`Self::stream_id`]
    /// / [`Self::stream_epoch`]). Exactly one addressing mode holds —
    /// enforced by [`extract_key_grant_payload`] (mirrors the V064
    /// `cirisnode.contributions` XOR CHECK; CEG 0.15 §10.5.3 RC1-1c).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,

    /// `federation_streams` stream id the epoch-DEK is scoped to.
    /// Present iff the grant is **stream/epoch-addressed** (the §10.5.3
    /// streaming cascade); `None` for a content-addressed grant.
    /// Projected onto `key_grant_stream_id` (V064) for indexed reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Key-rotation epoch within [`Self::stream_id`] the wrapped DEK
    /// covers. Present iff stream/epoch-addressed. Projected onto
    /// `key_grant_stream_epoch` (V064).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_epoch: Option<u64>,

    /// Base64-encoded wrapped DEK. The wrap algorithm is named below.
    pub wrapped_dek_base64: String,

    /// Wrap algorithm identifier. Content grants use v1; **stream/epoch
    /// grants MUST use v2** (PQC hybrid — see [`WrapAlgorithm`] and CEG
    /// §10.5.3: "a Consumer MUST reject a streaming epoch grant carrying
    /// `wrap_algorithm: v1`", enforced at ingest).
    pub wrap_algorithm: WrapAlgorithm,

    /// Symmetric-ratchet version the key was wrapped under.
    pub ratchet_version: u32,

    /// Validity window for the grant (start..end as RFC 3339 pair).
    pub key_validity_window: KeyValidityWindow,

    /// Scope of the grant. See [`KeyGrantScope`].
    pub scope: KeyGrantScope,

    /// Scope identifier — interpretation depends on [`Self::scope`].
    /// For [`KeyGrantScope::SingleContent`] this is the
    /// `content_sha256`; for [`KeyGrantScope::GroupMember`] /
    /// [`KeyGrantScope::SubscriptionTier`] it's the group / tier id.
    pub scope_id: String,

    /// Rotation chain — prior `attestation_id`s in chronological
    /// order; the head of the chain is the grant being rotated FROM.
    /// Empty for the first grant in a chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotation_chain: Vec<String>,
}

/// Closed-set wrap algorithm vocabulary.
///
/// # v1 — CEG 0.3 §5.6.8.4 — HPKE RFC 9180 base mode, KEM X25519, AEAD AES-128-GCM
///
/// Locked by CEG 0.3 (Registry commit a7d95cd, closes CIRISRegistry#38).
/// Wire string: `"hpke_rfc9180_base_x25519_aes_gcm"`.
///
/// # v2 — CEG 0.15 §10.5.3 — X25519 + ML-KEM-768 hybrid (FIPS 203), PQC at rest
///
/// **MANDATORY for streaming epoch-DEK grants** (the §10.5.3 cascade);
/// a content grant may stay v1, but a stream/epoch grant carrying v1 is
/// rejected at ingest. Wraps with the `ciris-crypto::key_grant`
/// `wrap_dek_for_recipient_v2` construction. The payload wire string
/// `"x25519_mlkem768_aes256_gcm_hkdf_sha256"` names that construction.
///
/// **RATIFIED** at v25.1.0 (CIRISPersist#582): CC 5.1 (class rule CC 3.3.2,
/// CIRISVerify#234) pins this snake_case spelling as *the single wire
/// identifier*, closing the propose-then-ratify loop this doc block opened
/// against CIRISRegistry#64. `ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2`
/// now carries the same string; the hyphenated form verify shipped through
/// v11.0.0 is a non-conformant alias that MUST be rejected and MUST NOT be
/// normalized before comparison — which is why
/// [`WrapAlgorithm::from_wire_str`] matches exactly and folds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WrapAlgorithm {
    /// X25519 + ML-KEM-768 hybrid DEK wrap (FIPS 203), AES-256-GCM +
    /// HKDF-SHA-256. CEG 0.15 §10.5.3; mandatory for streaming epoch
    /// grants. Maps to `ciris-crypto`'s `KEY_GRANT_ALGORITHM_V2`.
    #[serde(rename = "x25519_mlkem768_aes256_gcm_hkdf_sha256")]
    X25519MlKem768Aes256GcmHkdfSha256,
}

impl WrapAlgorithm {
    /// Wire-shaped string — matches the locked vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X25519MlKem768Aes256GcmHkdfSha256 => "x25519_mlkem768_aes256_gcm_hkdf_sha256",
        }
    }

    /// Parse from the wire-shaped string. Returns `None` on vocabulary
    /// mismatch.
    ///
    /// v25.1.0 (CIRISPersist#582, CC 5.1 / CIRISVerify#234) — the v2 arm
    /// defers to `ciris_crypto::key_grant::key_grant_algorithm_v2_accepts`,
    /// the **only sanctioned comparison** for that identifier, instead of
    /// re-spelling it here. Two validators for one artifact must share ONE
    /// predicate, or the vocabulary drifts the moment one of them is edited.
    ///
    /// `accept_legacy_hyphenated = false`: the hyphenated form is
    /// non-conformant and is refused at the parse door. The predicate
    /// deliberately does **not** normalize — folding `-` → `_` would make two
    /// distinct wire identifiers compare equal and defeat CC 5.1's
    /// single-identifier rule. Already-stored hyphenated values are retired by
    /// [`crate::maintenance::vocabulary`] (superseded, never rewritten), not
    /// laundered here.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        if ciris_crypto::key_grant::key_grant_algorithm_v2_accepts(s, false) {
            return Some(Self::X25519MlKem768Aes256GcmHkdfSha256);
        }
        // v34.0.0 (#704) — v1 is GONE, not superseded. The fleet directive is
        // that classical-only paths do not exist to be chosen; keeping a
        // per-scope "reject v1" rule would imply v1 still lives somewhere.
        //
        // A stored v1 grant now fails HERE, and the caller renders the token it
        // saw — so an operator sees the algorithm name and this release rather
        // than a generic parse failure that looks like corruption.
        None
    }

    /// Whether this is the PQC-hybrid v2 wrap (the only algorithm a
    /// streaming epoch-DEK grant may carry; CEG §10.5.3).
    pub fn is_streaming_pqc_v2(self) -> bool {
        matches!(self, Self::X25519MlKem768Aes256GcmHkdfSha256)
    }
}

/// `key_grant` scope. v1 supports three:
///
///   - [`Self::SingleContent`] — one grant per content blob.
///   - [`Self::GroupMember`] — one grant per group, applies to every
///     blob the group covers.
///   - [`Self::SubscriptionTier`] — one grant per tier; the
///     content the tier covers is operator-defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyGrantScope {
    SingleContent,
    GroupMember,
    SubscriptionTier,
    /// One grant per `(stream_id, epoch)` — the streaming epoch-DEK
    /// cascade (CEG 0.15 §10.5.3). `scope_id` is the `stream_id`.
    StreamEpoch,
    /// v34.0.0 (CIRISPersist#704, CIRISEdge#492) — one grant per
    /// `(netname, epoch)`: the IFAC transit passphrase for scoped transit.
    /// `scope_id` is the IFAC `netname`.
    ///
    /// Structurally IDENTICAL to [`Self::StreamEpoch`] — an `(id, epoch)` pair
    /// with one grant set per epoch, rotated by superseding the set and
    /// converged by reading it. That is why this is a second VALUE of the
    /// epoch-addressed mechanism rather than a third addressing category: a
    /// parallel copy would be N implementations of one invariant agreeing only
    /// because someone diffed them (#663).
    TransitMembership,
}

impl KeyGrantScope {
    /// Does this scope address by `(scope_id, epoch)` rather than by content?
    ///
    /// The one definition of "epoch-addressed", so the XOR, the column
    /// projection and the reads cannot disagree about which scopes are which.
    #[must_use]
    pub fn is_epoch_addressed(self) -> bool {
        matches!(self, Self::StreamEpoch | Self::TransitMembership)
    }
}

impl KeyGrantScope {
    /// Wire-shaped string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleContent => "single_content",
            Self::GroupMember => "group_member",
            Self::SubscriptionTier => "subscription_tier",
            Self::StreamEpoch => "stream_epoch",
            Self::TransitMembership => "transit_membership",
        }
    }
}

/// Validity window for a [`KeyGrantPayload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyValidityWindow {
    /// When the grant becomes valid.
    pub not_before: DateTime<Utc>,
    /// When the grant expires.
    pub not_after: DateTime<Utc>,
}

// ── Extractors / validators ─────────────────────────────────────────

const SHA256_HEX_LEN: usize = 64;

fn validate_hex_64(field: &str, value: &str) -> Result<(), Error> {
    if value.len() != SHA256_HEX_LEN || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidArgument(format!(
            "{field} must be 64 lowercase-hex chars (got len={})",
            value.len()
        )));
    }
    // Pin lowercase — the V054 CHECK enforces `[0-9a-f]`, so an
    // uppercase-hex submission fails admission either way; catch it
    // earlier with the typed error.
    if value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Error::InvalidArgument(format!(
            "{field} must be lowercase hex"
        )));
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidArgument(format!("{field} is empty")));
    }
    Ok(())
}

fn validate_base64(field: &str, value: &str) -> Result<(), Error> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map(|_| ())
        .map_err(|e| Error::InvalidArgument(format!("{field} not valid base64: {e}")))
}

/// Decode + validate a `takedown_notice` payload from the JSONB column.
/// Returns `Ok(None)` for non-takedown rows (mirrors the
/// [`super::federation_announcement::extract_announcement_payload`]
/// shape) and `Ok(Some(payload))` after the shape validators run.
///
/// Validation:
///   - `content_sha256` is hex-64 lowercase.
///   - `claimant_key_id` / `jurisdiction` / `claim_text` /
///     `good_faith_statement` non-empty.
///   - `legal_basis` is a known [`LegalBasis`] variant (enforced by
///     serde — unknown vocabularies fail decode).
pub fn extract_takedown_notice_payload(
    subject_kind: &str,
    payload: &serde_json::Value,
) -> Result<Option<TakedownNoticePayload>, Error> {
    if subject_kind != TAKEDOWN_NOTICE_SUBJECT_KIND {
        return Ok(None);
    }
    let typed: TakedownNoticePayload = serde_json::from_value(payload.clone())
        .map_err(|e| Error::InvalidArgument(format!("takedown_notice payload shape: {e}")))?;
    validate_hex_64("content_sha256", &typed.content_sha256)?;
    validate_non_empty("claimant_key_id", &typed.claimant_key_id)?;
    validate_non_empty("jurisdiction", &typed.jurisdiction)?;
    validate_non_empty("claim_text", &typed.claim_text)?;
    validate_non_empty("good_faith_statement", &typed.good_faith_statement)?;
    if typed.expires_at <= typed.asserted_at {
        return Err(Error::InvalidArgument(
            "takedown_notice: expires_at must be after asserted_at".into(),
        ));
    }
    Ok(Some(typed))
}

/// Decode + validate a `key_grant` payload from the JSONB column.
/// Returns `Ok(None)` for non-grant rows.
///
/// Validation (common):
///   - `recipient_key_id` / `scope_id` non-empty.
///   - `wrapped_dek_base64` is valid base64.
///   - `key_validity_window.not_after > not_before`.
///
/// Addressing — **exactly one mode** (mirrors the V064
/// `cirisnode.contributions` XOR CHECK; CEG 0.15 §10.5.3 RC1-1c):
///   - **content-addressed**: `content_sha256` is `Some` hex-64
///     lowercase; `stream_id` / `stream_epoch` are `None`.
///   - **stream/epoch-addressed**: `stream_id` is `Some` non-empty AND
///     `stream_epoch` is `Some`; `content_sha256` is `None`. The grant
///     **MUST** carry `wrap_algorithm: v2` (PQC hybrid) — a v1 wrap on a
///     streaming epoch grant is rejected here (CEG §10.5.3: "a Consumer
///     MUST reject a streaming epoch grant carrying `wrap_algorithm:
///     v1`"). `scope` must be [`KeyGrantScope::StreamEpoch`].
pub fn extract_key_grant_payload(
    subject_kind: &str,
    payload: &serde_json::Value,
) -> Result<Option<KeyGrantPayload>, Error> {
    if subject_kind != KEY_GRANT_SUBJECT_KIND {
        return Ok(None);
    }
    let typed: KeyGrantPayload = serde_json::from_value(payload.clone())
        .map_err(|e| Error::InvalidArgument(format!("key_grant payload shape: {e}")))?;
    validate_non_empty("recipient_key_id", &typed.recipient_key_id)?;
    validate_non_empty("scope_id", &typed.scope_id)?;
    validate_base64("wrapped_dek_base64", &typed.wrapped_dek_base64)?;
    if typed.key_validity_window.not_after <= typed.key_validity_window.not_before {
        return Err(Error::InvalidArgument(
            "key_grant: key_validity_window.not_after must be after not_before".into(),
        ));
    }

    // Exactly-one addressing mode (XOR), matching the V064 constraint.
    let content_addressed = typed.content_sha256.is_some();
    let stream_addressed = typed.stream_id.is_some() || typed.stream_epoch.is_some();
    match (content_addressed, stream_addressed) {
        (true, true) => {
            return Err(Error::InvalidArgument(
                "key_grant: content_sha256 and stream_id/stream_epoch are mutually exclusive \
                 (exactly one addressing mode; CEG §10.5.3 RC1-1c)"
                    .into(),
            ));
        }
        (false, false) => {
            return Err(Error::InvalidArgument(
                "key_grant: must be addressed — set content_sha256 (content) OR \
                 stream_id + stream_epoch (streaming epoch)"
                    .into(),
            ));
        }
        (true, false) => {
            // Content-addressed: hex-64 sha, no stream fields.
            let sha = typed
                .content_sha256
                .as_deref()
                .expect("content_addressed => Some");
            validate_hex_64("content_sha256", sha)?;

            // v34.0.0 (#704) — the ADDRESSING and the declared SCOPE must
            // agree. A content-addressed payload declaring an epoch-addressed
            // scope projects `scope_kind` NOT NULL beside a NULL `scope_id`,
            // which the V129 CHECK (postgres) and trigger (sqlite) refuse.
            //
            // So it already failed closed — but as an opaque backend error,
            // raised twice, once per dialect, describing a constraint name
            // rather than the caller's mistake. The invariant belongs to the
            // payload, so it is checked once, here, and says what is wrong.
            if typed.scope.is_epoch_addressed() {
                return Err(Error::InvalidArgument(format!(
                    "key_grant: content-addressed grant declares scope={}, which is \
                     epoch-addressed. A content grant carries no (scope_id, epoch), so \
                     the two cannot both hold — set scope to a content scope, or address \
                     the grant by scope_id + epoch",
                    typed.scope.as_str()
                )));
            }
        }
        (false, true) => {
            // Stream/epoch-addressed: both fields present, v2 wrap required.
            validate_non_empty("stream_id", typed.stream_id.as_deref().unwrap_or_default())?;
            if typed.stream_epoch.is_none() {
                return Err(Error::InvalidArgument(
                    "key_grant: stream/epoch-addressed grant requires stream_epoch".into(),
                ));
            }
            if !typed.wrap_algorithm.is_streaming_pqc_v2() {
                return Err(Error::InvalidArgument(format!(
                    "key_grant: streaming epoch grant MUST use wrap_algorithm v2 \
                     (x25519_mlkem768_aes256_gcm_hkdf_sha256), got {} — CEG §10.5.3 \
                     rejects wrap_algorithm: v1 on a streaming epoch grant",
                    typed.wrap_algorithm.as_str()
                )));
            }
            // v34.0.0 (#704) — was pinned to `StreamEpoch`, which would now
            // reject every transit grant. The check is the same one the write
            // path and the V129 rule use, so all three agree by construction
            // rather than by three people writing the same `matches!`.
            if !typed.scope.is_epoch_addressed() {
                return Err(Error::InvalidArgument(format!(
                    "key_grant: scope-epoch-addressed grant requires an epoch-addressed \
                     scope (stream_epoch | transit_membership), got {}",
                    typed.scope.as_str()
                )));
            }
        }
    }
    Ok(Some(typed))
}

/// v16 (CIRISPersist#432, CC 5.1 `CLM-epoch-keying`) — assert an
/// envelope IS a `key_grant` Contribution before the dedicated
/// [`super::NodeCoreService::put_key_grant`] write runs.
///
/// Fail-closed admission for the first-class grant emission path:
///
///   - `contribution_type` MUST be `proposal` — grants ride the
///     `proposal` discriminator sub-discriminated by `subject_kind`
///     (the V011 CHECK pins the 7-value `contribution_type`
///     vocabulary; there is deliberately NO `key_grant`
///     contribution_type — see `retire_key_grants` + every existing
///     grant row).
///   - `subject.subject` (subject_kind) MUST be
///     [`KEY_GRANT_SUBJECT_KIND`].
///   - The payload MUST validate as a [`KeyGrantPayload`] in exactly
///     one addressing mode (content-addressed XOR
///     stream/epoch-addressed) via [`extract_key_grant_payload`].
///
/// Returns the validated payload so the caller can inspect the
/// addressing mode without re-decoding. Signature/trust admission is
/// NOT run here — `put_contribution` (which `put_key_grant`
/// delegates to) owns that discipline.
pub fn require_key_grant_envelope(
    env: &super::types::ContributionEnvelope,
) -> Result<KeyGrantPayload, Error> {
    if env.contribution_type != super::types::ContributionType::Proposal {
        return Err(Error::InvalidArgument(
            "put_key_grant: key_grant Contributions ride contribution_type=proposal \
             (sub-discriminated by subject_kind); no other contribution_type is admitted"
                .into(),
        ));
    }
    let subject_kind = env.subject.subject.as_deref().unwrap_or_default();
    if subject_kind != KEY_GRANT_SUBJECT_KIND {
        return Err(Error::InvalidArgument(format!(
            "put_key_grant: subject_kind must be '{KEY_GRANT_SUBJECT_KIND}', got '{subject_kind}'"
        )));
    }
    extract_key_grant_payload(subject_kind, &env.payload)?.ok_or_else(|| {
        // Unreachable: subject_kind matched above, so the extractor
        // either returns Some or errs. Fail closed regardless.
        Error::Internal("put_key_grant: key_grant payload extraction returned None".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_sha256() -> String {
        "a".repeat(64)
    }

    fn fixture_takedown(basis: LegalBasis) -> TakedownNoticePayload {
        TakedownNoticePayload {
            content_sha256: fixture_sha256(),
            perceptual_hash: None,
            content_holder_key_ids: vec!["holder-1".into()],
            claimant_key_id: "claimant-1".into(),
            legal_basis: basis,
            jurisdiction: "US".into(),
            good_faith_statement: "I have a good-faith belief that the use is unauthorized.".into(),
            claim_text: "Copyright claim over content_sha256.".into(),
            evidence_refs: vec![],
            counter_notice_channel: None,
            asserted_at: DateTime::parse_from_rfc3339("2026-05-29T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            expires_at: DateTime::parse_from_rfc3339("2027-05-29T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    fn fixture_key_grant() -> KeyGrantPayload {
        KeyGrantPayload {
            recipient_key_id: "recipient-1".into(),
            content_sha256: Some(fixture_sha256()),
            stream_id: None,
            stream_epoch: None,
            wrapped_dek_base64: base64::engine::general_purpose::STANDARD.encode([0u8; 48]),
            wrap_algorithm: WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256,
            ratchet_version: 1,
            key_validity_window: KeyValidityWindow {
                not_before: DateTime::parse_from_rfc3339("2026-05-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                not_after: DateTime::parse_from_rfc3339("2027-05-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            },
            scope: KeyGrantScope::SingleContent,
            scope_id: fixture_sha256(),
            rotation_chain: vec![],
        }
    }

    #[test]
    fn legal_basis_round_trips_wire_str() {
        for b in [
            LegalBasis::Dmca512,
            LegalBasis::DsaArticle16,
            LegalBasis::TvecTerrorist,
            LegalBasis::NcmecCsam,
            LegalBasis::GifctCip,
            LegalBasis::CommunityStandards,
            LegalBasis::PerceptualHashCsam,
            LegalBasis::OsaIllegalContent,
            LegalBasis::AvmsdAgeInappropriate,
            LegalBasis::CourtOrder,
        ] {
            assert_eq!(LegalBasis::from_wire_str(b.as_str()), Some(b));
        }
        assert!(LegalBasis::from_wire_str("nonsense").is_none());
    }

    #[test]
    fn admits_counter_notice_matches_ceg_0_3_locked_set() {
        // CEG 0.3 §5.6.8.4 + §11.4: four expeditious-with-counter-notice
        // bases.
        for b in [
            LegalBasis::Dmca512,
            LegalBasis::DsaArticle16,
            LegalBasis::OsaIllegalContent,
            LegalBasis::CommunityStandards,
        ] {
            assert!(b.admits_counter_notice(), "{b:?} must admit counter");
        }
        for b in [
            LegalBasis::TvecTerrorist,
            LegalBasis::NcmecCsam,
            LegalBasis::GifctCip,
            LegalBasis::PerceptualHashCsam,
            LegalBasis::AvmsdAgeInappropriate,
            LegalBasis::CourtOrder,
        ] {
            assert!(!b.admits_counter_notice(), "{b:?} must not admit counter");
        }
    }

    #[test]
    fn requires_immediate_eviction_matches_ceg_0_3_locked_set() {
        // CEG 0.3 §5.6.8.4 + §11.4: five immediate-removal bases.
        for b in [
            LegalBasis::TvecTerrorist,
            LegalBasis::NcmecCsam,
            LegalBasis::GifctCip,
            LegalBasis::PerceptualHashCsam,
            LegalBasis::CourtOrder,
        ] {
            assert!(b.requires_immediate_eviction(), "{b:?}");
        }
        for b in [
            LegalBasis::Dmca512,
            LegalBasis::DsaArticle16,
            LegalBasis::OsaIllegalContent,
            LegalBasis::CommunityStandards,
            LegalBasis::AvmsdAgeInappropriate,
        ] {
            assert!(!b.requires_immediate_eviction(), "{b:?}");
        }
    }

    /// CEG 0.3 §11.4 regression: CourtOrder moves into the
    /// immediate-removal set (was expeditious in the architect's draft).
    #[test]
    fn legal_basis_court_order_is_immediate_eviction() {
        assert!(LegalBasis::CourtOrder.requires_immediate_eviction());
        assert!(!LegalBasis::CourtOrder.admits_counter_notice());
    }

    /// CEG 0.3 §5.6.8.4: `AvmsdAgeInappropriate` belongs in the
    /// new compose-with-age-gate discipline category — neither
    /// immediate-eviction nor counter-noticed.
    #[test]
    fn legal_basis_avmsd_age_inappropriate_composes_with_age_gate() {
        let basis = LegalBasis::AvmsdAgeInappropriate;
        assert!(basis.composes_with_age_gate());
        assert!(!basis.requires_immediate_eviction());
        assert!(!basis.admits_counter_notice());
        // All other bases do NOT compose with the age gate.
        for b in [
            LegalBasis::Dmca512,
            LegalBasis::DsaArticle16,
            LegalBasis::OsaIllegalContent,
            LegalBasis::CommunityStandards,
            LegalBasis::TvecTerrorist,
            LegalBasis::NcmecCsam,
            LegalBasis::GifctCip,
            LegalBasis::PerceptualHashCsam,
            LegalBasis::CourtOrder,
        ] {
            assert!(!b.composes_with_age_gate(), "{b:?}");
        }
    }

    /// CEG 0.3 closed set: the 10 LegalBasis variants split into
    /// exactly 5 (immediate) + 4 (counter-noticed) + 1 (age-gate).
    /// No variant ends up in two categories or in zero.
    #[test]
    fn legal_basis_locked_set_matches_ceg_0_3() {
        let all = [
            LegalBasis::Dmca512,
            LegalBasis::DsaArticle16,
            LegalBasis::TvecTerrorist,
            LegalBasis::NcmecCsam,
            LegalBasis::GifctCip,
            LegalBasis::CommunityStandards,
            LegalBasis::PerceptualHashCsam,
            LegalBasis::OsaIllegalContent,
            LegalBasis::AvmsdAgeInappropriate,
            LegalBasis::CourtOrder,
        ];
        let immediate = all
            .iter()
            .filter(|b| b.requires_immediate_eviction())
            .count();
        let counter = all.iter().filter(|b| b.admits_counter_notice()).count();
        let age_gate = all.iter().filter(|b| b.composes_with_age_gate()).count();
        assert_eq!(immediate, 5);
        assert_eq!(counter, 4);
        assert_eq!(age_gate, 1);
        // Exhaustive: every basis falls in exactly one category.
        for b in all {
            let cats = (b.requires_immediate_eviction() as u8)
                + (b.admits_counter_notice() as u8)
                + (b.composes_with_age_gate() as u8);
            assert_eq!(cats, 1, "{b:?} must be in exactly one CEG 0.3 category");
        }
    }

    #[test]
    fn counter_notice_window_defaults_match_ceg_0_3() {
        assert_eq!(LegalBasis::Dmca512.counter_notice_window_days(), Some(10));
        assert_eq!(
            LegalBasis::DsaArticle16.counter_notice_window_days(),
            Some(14)
        );
        // CEG 0.3: OsaIllegalContent + CommunityStandards are now
        // counter-noticed; persist defaults 14 days and 30 days.
        assert_eq!(
            LegalBasis::OsaIllegalContent.counter_notice_window_days(),
            Some(14)
        );
        assert_eq!(
            LegalBasis::CommunityStandards.counter_notice_window_days(),
            Some(30)
        );
        // Immediate-removal bases have no counter-notice window.
        assert_eq!(LegalBasis::NcmecCsam.counter_notice_window_days(), None);
        assert_eq!(LegalBasis::CourtOrder.counter_notice_window_days(), None);
        // Age-gate basis has no counter-notice window either (it
        // composes with Policy J instead).
        assert_eq!(
            LegalBasis::AvmsdAgeInappropriate.counter_notice_window_days(),
            None
        );
    }

    /// v34.0.0 (#704) — the surviving algorithm round-trips, and the RETIRED
    /// v1 token is refused.
    ///
    /// Replaces `wrap_algorithm_hpke_rfc9180_wire_str_round_trip`, which pinned
    /// the v1 wire string as the value `as_str()` returns. After the blanket
    /// rename that test asserted the v2 variant renders the v1 token — a
    /// contradiction that would have compiled and failed loudly, but for the
    /// wrong reason.
    ///
    /// The v1 leg is kept as a NEGATIVE: `from_wire_str` must refuse
    /// `hpke_rfc9180_base_x25519_aes_gcm`, so a stored classical grant is
    /// rejected at parse rather than silently mapped onto the PQC variant.
    #[test]
    fn only_the_pqc_wrap_round_trips_and_v1_is_refused_704() {
        let alg = WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256;
        assert_eq!(alg.as_str(), "x25519_mlkem768_aes256_gcm_hkdf_sha256");
        assert_eq!(
            WrapAlgorithm::from_wire_str("x25519_mlkem768_aes256_gcm_hkdf_sha256"),
            Some(alg)
        );

        // THE RETIREMENT, asserted rather than assumed: the classical token is
        // no longer a value this type can hold.
        assert!(
            WrapAlgorithm::from_wire_str("hpke_rfc9180_base_x25519_aes_gcm").is_none(),
            "v1 is GONE — a stored classical grant must fail at parse, not be \
             folded onto the PQC variant"
        );

        let serialized = serde_json::to_string(&alg).unwrap();
        let back: WrapAlgorithm = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back, alg);
    }

    #[test]
    fn extract_takedown_notice_payload_returns_none_for_non_matching_kind() {
        let payload = serde_json::to_value(fixture_takedown(LegalBasis::Dmca512)).unwrap();
        let out = extract_takedown_notice_payload("federation_announcement", &payload).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn extract_takedown_notice_payload_validates_shape() {
        let typed = fixture_takedown(LegalBasis::Dmca512);
        let value = serde_json::to_value(&typed).unwrap();
        let parsed = extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &value)
            .unwrap()
            .unwrap();
        assert_eq!(parsed, typed);
    }

    #[test]
    fn extract_takedown_notice_payload_rejects_uppercase_sha() {
        let mut typed = fixture_takedown(LegalBasis::Dmca512);
        typed.content_sha256 = "A".repeat(64);
        let value = serde_json::to_value(&typed).unwrap();
        let err =
            extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn extract_takedown_notice_payload_rejects_short_sha() {
        let mut typed = fixture_takedown(LegalBasis::Dmca512);
        typed.content_sha256 = "abc".into();
        let value = serde_json::to_value(&typed).unwrap();
        let err =
            extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn extract_takedown_notice_payload_rejects_empty_claim_text() {
        let mut typed = fixture_takedown(LegalBasis::Dmca512);
        typed.claim_text = String::new();
        let value = serde_json::to_value(&typed).unwrap();
        let err =
            extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn extract_takedown_notice_payload_rejects_unknown_legal_basis() {
        // Serialize an envelope whose `legal_basis` is a literal that
        // does not map to any LegalBasis variant.
        let typed = fixture_takedown(LegalBasis::Dmca512);
        let mut value = serde_json::to_value(&typed).unwrap();
        value["legal_basis"] = serde_json::Value::String("nonsense_basis".into());
        let err =
            extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn extract_key_grant_payload_returns_none_for_non_matching_kind() {
        let payload = serde_json::to_value(fixture_key_grant()).unwrap();
        let out = extract_key_grant_payload("federation_announcement", &payload).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn extract_key_grant_payload_validates_shape() {
        let typed = fixture_key_grant();
        let value = serde_json::to_value(&typed).unwrap();
        let parsed = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value)
            .unwrap()
            .unwrap();
        assert_eq!(parsed, typed);
    }

    #[test]
    fn extract_key_grant_payload_rejects_invalid_base64_dek() {
        let mut typed = fixture_key_grant();
        typed.wrapped_dek_base64 = "not!base64@@".into();
        let value = serde_json::to_value(&typed).unwrap();
        let err = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn extract_key_grant_payload_rejects_inverted_validity_window() {
        let mut typed = fixture_key_grant();
        std::mem::swap(
            &mut typed.key_validity_window.not_before,
            &mut typed.key_validity_window.not_after,
        );
        let value = serde_json::to_value(&typed).unwrap();
        let err = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    // ── Cut C3b: stream/epoch addressing (CEG §10.5.3) ──────────────

    /// A valid stream/epoch-addressed grant: no content_sha256, stream
    /// fields set, v2 wrap, StreamEpoch scope.
    fn fixture_stream_grant() -> KeyGrantPayload {
        KeyGrantPayload {
            recipient_key_id: "recipient-1".into(),
            content_sha256: None,
            stream_id: Some("stream-abc".into()),
            stream_epoch: Some(7),
            wrapped_dek_base64: base64::engine::general_purpose::STANDARD.encode([0u8; 48]),
            wrap_algorithm: WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256,
            ratchet_version: 1,
            key_validity_window: KeyValidityWindow {
                not_before: DateTime::parse_from_rfc3339("2026-05-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                not_after: DateTime::parse_from_rfc3339("2027-05-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            },
            scope: KeyGrantScope::StreamEpoch,
            scope_id: "stream-abc".into(),
            rotation_chain: vec![],
        }
    }

    #[test]
    fn extract_stream_epoch_grant_validates() {
        let typed = fixture_stream_grant();
        let value = serde_json::to_value(&typed).unwrap();
        let parsed = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value)
            .unwrap()
            .unwrap();
        assert_eq!(parsed, typed);
        assert!(parsed.wrap_algorithm.is_streaming_pqc_v2());
    }

    // v34.0.0 (#704) — `stream_grant_with_v1_wrap_is_rejected` DELETED, not
    // flipped to v2.
    //
    // It asserted "a streaming epoch grant carrying wrap_algorithm v1 MUST be
    // rejected". With v1 removed from the enum that state is UNCONSTRUCTIBLE,
    // so the test could only have been rewritten into something that no longer
    // checks what its name claims. The rule it enforced at runtime is now
    // enforced by the type system, which is strictly stronger: not "we refuse
    // it" but "it cannot be expressed".

    #[test]
    fn grant_with_both_addressing_modes_is_rejected() {
        let mut typed = fixture_stream_grant();
        typed.content_sha256 = Some("a".repeat(64)); // now BOTH set
        let value = serde_json::to_value(&typed).unwrap();
        let err = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(ref m) if m.contains("mutually exclusive")));
    }

    #[test]
    fn grant_with_no_addressing_is_rejected() {
        let mut typed = fixture_stream_grant();
        typed.stream_id = None;
        typed.stream_epoch = None; // neither content nor stream
        let value = serde_json::to_value(&typed).unwrap();
        let err = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(ref m) if m.contains("must be addressed")));
    }

    #[test]
    fn stream_grant_requires_stream_epoch_scope() {
        let mut typed = fixture_stream_grant();
        typed.scope = KeyGrantScope::GroupMember; // wrong scope
        let value = serde_json::to_value(&typed).unwrap();
        let err = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("epoch-addressed scope")),
            "got: {err:?}"
        );
    }

    /// v34.0.0 (#704) — a content-addressed grant declaring an EPOCH-addressed
    /// scope is refused HERE, with a typed error naming the contradiction.
    ///
    /// It already failed closed before this: the projection writes `scope_kind`
    /// NOT NULL beside a NULL `scope_id`, which the V129 CHECK (postgres) and
    /// trigger (sqlite) refuse. But that refusal arrives as an opaque backend
    /// error naming a constraint, raised separately per dialect — two copies of
    /// one rule, and neither tells the caller what they did wrong.
    ///
    /// The invariant belongs to the payload, so it is checked once.
    #[test]
    fn content_addressed_grant_may_not_declare_an_epoch_scope_704() {
        for scope in [KeyGrantScope::StreamEpoch, KeyGrantScope::TransitMembership] {
            let mut typed = fixture_key_grant(); // content-addressed
            typed.scope = scope;
            let value = serde_json::to_value(&typed).unwrap();
            let err = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value).unwrap_err();
            assert!(
                matches!(err, Error::InvalidArgument(ref m)
                    if m.contains("epoch-addressed") && m.contains(scope.as_str())),
                "the refusal must name the offending scope, not a constraint: {err:?}"
            );
        }
    }

    /// The transit scope is accepted on the epoch-addressed path — the point of
    /// the generalization. Without this leg the widened check above could be
    /// refusing everything and the negative tests would not notice.
    #[test]
    fn a_transit_membership_grant_is_epoch_addressable_704() {
        let mut typed = fixture_stream_grant();
        typed.scope = KeyGrantScope::TransitMembership;
        typed.scope_id = "ciris-transit-net".to_owned();
        let value = serde_json::to_value(&typed).unwrap();
        assert!(
            extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value)
                .unwrap()
                .is_some(),
            "transit membership must validate on the epoch-addressed path"
        );
    }

    #[test]
    fn content_grant_carries_the_pqc_wrap_704() {
        // v34.0.0 (#704) — every grant is v2 now, content-addressed
        // included. The old assertion here pinned the content default to
        // v1, which was the live classical-only path this release removes.
        let typed = fixture_key_grant();
        assert_eq!(
            typed.wrap_algorithm,
            WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256
        );
        let value = serde_json::to_value(&typed).unwrap();
        assert!(extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value)
            .unwrap()
            .is_some());
    }

    #[test]
    fn wrap_algorithm_v2_wire_round_trip() {
        assert_eq!(
            WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256.as_str(),
            "x25519_mlkem768_aes256_gcm_hkdf_sha256"
        );
        assert_eq!(
            WrapAlgorithm::from_wire_str("x25519_mlkem768_aes256_gcm_hkdf_sha256"),
            Some(WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256)
        );
        // serde rename matches the wire string.
        assert_eq!(
            serde_json::to_string(&WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256).unwrap(),
            r#""x25519_mlkem768_aes256_gcm_hkdf_sha256""#
        );
    }

    /// v25.1.0 (CIRISPersist#582, CC 5.1 / CIRISVerify#234) — persist's enum
    /// and verify's constant name ONE construction, and a `#[serde(rename)]`
    /// attribute cannot be a `const`. So the equality is asserted here: if
    /// verify re-spells the identifier again, this fires instead of persist
    /// silently serializing a form nothing else accepts.
    #[test]
    fn v2_wire_string_is_verifys_ratified_identifier() {
        assert_eq!(
            WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256.as_str(),
            ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2,
            "the serde rename + as_str spelling must equal verify's constant"
        );
        // The non-conformant hyphenated alias is REFUSED at the parse door,
        // and is NOT normalized into the conformant form.
        assert_eq!(
            WrapAlgorithm::from_wire_str(
                ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED
            ),
            None,
            "CC 5.1: the hyphenated alias is non-conformant and MUST NOT be \
             normalized before comparison"
        );
    }

    #[test]
    fn legal_basis_serde_matches_snake_case() {
        assert_eq!(
            serde_json::to_string(&LegalBasis::NcmecCsam).unwrap(),
            r#""ncmec_csam""#
        );
        let parsed: LegalBasis = serde_json::from_str(r#""dmca_512""#).unwrap();
        assert_eq!(parsed, LegalBasis::Dmca512);
    }

    // ── MultimediaConfig tests ──────────────────────────────────────

    #[test]
    fn multimedia_config_default_immediate_bases() {
        // CEG 0.3 §11.4: 5 immediate-removal bases.
        let cfg = MultimediaConfig::default();
        assert_eq!(cfg.counter_notice_window_days, 14);
        assert_eq!(cfg.immediate_legal_bases.len(), 5);
        assert!(cfg.is_immediate(LegalBasis::NcmecCsam));
        assert!(cfg.is_immediate(LegalBasis::TvecTerrorist));
        assert!(cfg.is_immediate(LegalBasis::GifctCip));
        assert!(cfg.is_immediate(LegalBasis::PerceptualHashCsam));
        assert!(cfg.is_immediate(LegalBasis::CourtOrder));
        // Counter-noticed bases default to non-immediate.
        assert!(!cfg.is_immediate(LegalBasis::Dmca512));
        assert!(!cfg.is_immediate(LegalBasis::DsaArticle16));
        assert!(!cfg.is_immediate(LegalBasis::OsaIllegalContent));
        assert!(!cfg.is_immediate(LegalBasis::CommunityStandards));
    }

    #[test]
    fn multimedia_config_default_age_gate_bases() {
        // CEG 0.3 §8.1.10: AvmsdAgeInappropriate is the only default.
        let cfg = MultimediaConfig::default();
        assert_eq!(cfg.age_gate_legal_bases.len(), 1);
        assert!(cfg.is_age_gated(LegalBasis::AvmsdAgeInappropriate));
        assert!(!cfg.is_age_gated(LegalBasis::CourtOrder));
        assert!(!cfg.is_age_gated(LegalBasis::Dmca512));
    }

    #[test]
    fn multimedia_config_wire_round_trip() {
        let cfg = MultimediaConfig::default();
        let wire = MultimediaConfigWire::from_config(&cfg);
        let back = wire.into_config().unwrap();
        assert_eq!(
            back.counter_notice_window_days,
            cfg.counter_notice_window_days
        );
        assert_eq!(back.immediate_legal_bases, cfg.immediate_legal_bases);
        assert_eq!(back.age_gate_legal_bases, cfg.age_gate_legal_bases);
    }

    #[test]
    fn multimedia_config_wire_rejects_unknown_basis() {
        let wire = MultimediaConfigWire {
            counter_notice_window_days: 10,
            immediate_legal_bases: vec!["nonsense_basis".into()],
            age_gate_legal_bases: vec![],
        };
        let err = wire.into_config().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn multimedia_config_wire_rejects_unknown_age_gate_basis() {
        let wire = MultimediaConfigWire {
            counter_notice_window_days: 14,
            immediate_legal_bases: vec![],
            age_gate_legal_bases: vec!["unknown_age_gate".into()],
        };
        let err = wire.into_config().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn multimedia_config_operator_override_admits_court_order() {
        let cfg = MultimediaConfig::default();
        assert!(cfg.is_immediate(LegalBasis::CourtOrder));
        // CEG 0.3 §11.4: the hardcoded helper agrees with the default.
        assert!(LegalBasis::CourtOrder.requires_immediate_eviction());
    }

    // ── v16 (#432): require_key_grant_envelope (put_key_grant gate) ──

    /// Wrap a payload in a proposal-typed key_grant envelope shell.
    /// Signature is a dummy — the shape gate deliberately does NOT
    /// verify signatures (put_contribution owns that).
    fn fixture_grant_envelope(
        payload: &KeyGrantPayload,
    ) -> crate::cirisnode::types::ContributionEnvelope {
        use crate::cirisnode::types::{Cell, ContributionEnvelope, ContributionType};
        ContributionEnvelope {
            contribution_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            contribution_type: ContributionType::Proposal,
            author_id: "author-1".into(),
            subject: Cell {
                domain: "stream-dom".into(),
                language: "en".into(),
                subject: Some(KEY_GRANT_SUBJECT_KIND.into()),
            },
            payload: serde_json::to_value(payload).unwrap(),
            witness_set: None,
            signature: crate::cirisnode::types::HybridSignature {
                ed25519: "sig".into(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        }
    }

    #[test]
    fn require_key_grant_envelope_admits_stream_epoch_grant() {
        let payload = fixture_stream_grant();
        let env = fixture_grant_envelope(&payload);
        let parsed = require_key_grant_envelope(&env).unwrap();
        assert_eq!(parsed, payload);
        assert_eq!(parsed.stream_id.as_deref(), Some("stream-abc"));
        assert_eq!(parsed.stream_epoch, Some(7));
    }

    #[test]
    fn require_key_grant_envelope_admits_content_grant() {
        let payload = fixture_key_grant();
        let env = fixture_grant_envelope(&payload);
        let parsed = require_key_grant_envelope(&env).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn require_key_grant_envelope_rejects_non_proposal_type() {
        // Grants ride contribution_type=proposal — any other
        // discriminator is rejected fail-closed even with a valid
        // key_grant payload + subject_kind.
        let mut env = fixture_grant_envelope(&fixture_stream_grant());
        env.contribution_type = crate::cirisnode::types::ContributionType::ModerationEvent;
        let err = require_key_grant_envelope(&env).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("contribution_type=proposal")),
            "got: {err:?}"
        );
    }

    #[test]
    fn require_key_grant_envelope_rejects_wrong_subject_kind() {
        let mut env = fixture_grant_envelope(&fixture_stream_grant());
        env.subject.subject = Some("arc_question".into());
        let err = require_key_grant_envelope(&env).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("subject_kind")),
            "got: {err:?}"
        );
        // Missing subject_kind entirely is equally rejected.
        env.subject.subject = None;
        let err = require_key_grant_envelope(&env).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got: {err:?}");
    }

    // v34.0.0 (#704) — `require_key_grant_envelope_rejects_malformed_payload`
    // DELETED rather than flipped.
    //
    // It asserted that a v1 wrap on a stream/epoch grant fails the gate. With
    // v1 removed from the enum that input is unconstructible, so there is no
    // malformed payload of this shape left to reject — the gate's rule is now
    // the type system's.
    //
    // Recorded because of HOW it nearly shipped: a blanket
    // `s.replace(v1_variant, v2_variant)` rewrote it into a test that set v2,
    // expected a refusal, and failed. A mechanical rename cannot tell a fixture
    // from an assertion, and this one asserted the thing being deleted.
}
