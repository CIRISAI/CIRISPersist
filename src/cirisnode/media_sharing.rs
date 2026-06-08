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
//!   - [`WrapAlgorithm`]: `HpkeRfc9180BaseX25519AesGcm` is the v1
//!     algorithm (wire string `hpke_rfc9180_base_x25519_aes_gcm`).
//!   - `retire_key_grants` emission shape: fresh `key_grant`
//!     Contribution with `rotation_chain` extended by the prior
//!     `contribution_id` (CEG §5.6.8.4 option b — supersession, not
//!     withdraws).
//!
//! Substrate-protective takedown override semantics
//! (`CIRISNodeCore#24`) remain pending — persist defers to
//! `AdmissionGate` at `put_contribution`. If/when operator-config
//! admits a takedown-signer bypass, this module gains the override
//! surface.

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
/// `wrap_dek_for_recipient_v2` construction (`KEY_GRANT_ALGORITHM_V2 =
/// "x25519-mlkem768-aes256-gcm-hkdf-sha256"`, v4.10.0). The payload wire
/// string `"x25519_mlkem768_aes256_gcm_hkdf_sha256"` names that
/// construction; **pending CIRISRegistry ratification (CIRISRegistry#64)**
/// — the CEG mandates `wrap_algorithm: v2` but does not yet pin the
/// payload enum string (unlike v1's §5.6.8.4-pinned string), so this is
/// proposed via the same propose-then-ratify path as the STREAM-nonce
/// epoch encoding (CIRISRegistry#63). If the registry ratifies a
/// different string, only this serde rename changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WrapAlgorithm {
    /// HPKE RFC 9180 base mode, KEM X25519, AEAD AES-128-GCM. Locked
    /// by CEG 0.3 §5.6.8.4. The content-addressed-grant default.
    #[serde(rename = "hpke_rfc9180_base_x25519_aes_gcm")]
    HpkeRfc9180BaseX25519AesGcm,

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
            Self::HpkeRfc9180BaseX25519AesGcm => "hpke_rfc9180_base_x25519_aes_gcm",
            Self::X25519MlKem768Aes256GcmHkdfSha256 => "x25519_mlkem768_aes256_gcm_hkdf_sha256",
        }
    }

    /// Parse from the wire-shaped string. Returns `None` on vocabulary
    /// mismatch.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "hpke_rfc9180_base_x25519_aes_gcm" => Some(Self::HpkeRfc9180BaseX25519AesGcm),
            "x25519_mlkem768_aes256_gcm_hkdf_sha256" => {
                Some(Self::X25519MlKem768Aes256GcmHkdfSha256)
            }
            _ => None,
        }
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
    /// cascade (CEG 0.15 §10.5.3). `scope_id` is the `stream_id`. The
    /// only scope a stream/epoch-addressed grant may carry.
    StreamEpoch,
}

impl KeyGrantScope {
    /// Wire-shaped string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleContent => "single_content",
            Self::GroupMember => "group_member",
            Self::SubscriptionTier => "subscription_tier",
            Self::StreamEpoch => "stream_epoch",
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
            if typed.scope != KeyGrantScope::StreamEpoch {
                return Err(Error::InvalidArgument(format!(
                    "key_grant: stream/epoch-addressed grant requires scope=stream_epoch, got {}",
                    typed.scope.as_str()
                )));
            }
        }
    }
    Ok(Some(typed))
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
            wrap_algorithm: WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm,
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

    #[test]
    fn wrap_algorithm_hpke_rfc9180_wire_str_round_trip() {
        let alg = WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm;
        assert_eq!(alg.as_str(), "hpke_rfc9180_base_x25519_aes_gcm");
        assert_eq!(
            WrapAlgorithm::from_wire_str("hpke_rfc9180_base_x25519_aes_gcm"),
            Some(alg)
        );
        assert!(WrapAlgorithm::from_wire_str("x25519_aes256_gcm_hkdf_sha256").is_none());
        // serde round-trip: serialize → string → deserialize.
        let serialized = serde_json::to_string(&alg).unwrap();
        assert_eq!(serialized, r#""hpke_rfc9180_base_x25519_aes_gcm""#);
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

    #[test]
    fn stream_grant_with_v1_wrap_is_rejected() {
        // The normative §10.5.3 check: a streaming epoch grant carrying
        // wrap_algorithm v1 MUST be rejected.
        let mut typed = fixture_stream_grant();
        typed.wrap_algorithm = WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm;
        let value = serde_json::to_value(&typed).unwrap();
        let err = extract_key_grant_payload(KEY_GRANT_SUBJECT_KIND, &value).unwrap_err();
        match err {
            Error::InvalidArgument(m) => assert!(
                m.contains("wrap_algorithm v2") && m.contains("v1"),
                "expected reject-v1 message, got: {m}"
            ),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

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
        assert!(matches!(err, Error::InvalidArgument(ref m) if m.contains("scope=stream_epoch")));
    }

    #[test]
    fn content_grant_still_accepts_v1() {
        // Backward compat: a content-addressed grant with v1 wrap is
        // unaffected by the streaming reject-v1 rule.
        let typed = fixture_key_grant();
        assert_eq!(
            typed.wrap_algorithm,
            WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm
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
}
