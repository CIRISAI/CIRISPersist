// v3.6.0: media-sharing enum variants are wire constants; their
// semantics live in this module's doc-block (above) and at the
// [`LegalBasis`] type-level — not in per-variant rustdoc. Mirrors the
// same `#![allow(missing_docs)]` call from
// `cirisnode::federation_announcement`.
#![allow(missing_docs)]

//! Media-sharing substrate (CIRISPersist#134, v3.6.0; v60.0.0).
//!
//! - [`TAKEDOWN_NOTICE_SUBJECT_KIND`] — a content-claimant's assertion that
//!   bytes under the named SHA-256 must be taken down. v60.0.0
//!   (CIRISPersist#803, CC 3.1.1 / CC 3.3.2): the notice is a
//!   `takedown_notice:{basis}:v1` `scores` ROW, signed by its claimant
//!   (`super::rows::plan_takedown_notice_row`); its admission is the
//!   duty-holder gate (`takedown_tombstone::check_takedown_notice_row_admission`)
//!   and its execution the CC 2.3 tombstone
//!   ([`super::takedown_handler::process_takedown_admission`]).
//!
//! - [`KEY_GRANT_SUBJECT_KIND`] — RETIRED in v60.0.0 (CIRISPersist#988
//!   item 1). A `key_grant` Contribution duplicated the key-grant plane
//!   (`key_grant:{axis}:v1`, `crate::federation::key_grant`) as a second,
//!   unreplicated, classical-only door; a Contribution naming the subject
//!   kind is refused by name (`super::rows::refusal::KEY_GRANT_RETIRED`).
//!
//! [`LegalBasis`] is CC 3.3.2's closed vocabulary, in CC's wire spelling.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::Error;

/// Wire constant — the `subject_kind` of a takedown notice (CC 3.3.2).
pub const TAKEDOWN_NOTICE_SUBJECT_KIND: &str = "takedown_notice";

/// Wire constant — the RETIRED `key_grant` Contribution subject kind
/// (v60.0.0): named so the refusal can name it.
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
    #[serde(rename = "dmca512")]
    Dmca512,
    #[serde(rename = "dsa_article16")]
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
    /// The CC 3.3.2 wire string — the `{basis}` of the notice row's
    /// `takedown_notice:{basis}:v1` dimension. v60.0.0 (CIRISPersist#803):
    /// `dmca512` / `dsa_article16`, CC's closed vocabulary; the pre-v60
    /// `dmca_512` / `dsa_article_16` spellings are gone (V203 rewrote the
    /// recorded headers).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dmca512 => "dmca512",
            Self::DsaArticle16 => "dsa_article16",
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
            "dmca512" => Self::Dmca512,
            "dsa_article16" => Self::DsaArticle16,
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

// ── TakedownNoticePayload ───────────────────────────────────────────

/// The CC 3.3.2 `takedown_notice` body a claimant files: the members of the
/// notice row (`super::rows::plan_takedown_notice_row`). v60.0.0 — the row
/// is signed by its claimant, so `claimant_key_id` and `asserted_at` are the
/// ROW's (the planner stamps them from the signer and the signed instant)
/// and are not carried here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakedownNoticePayload {
    /// SHA-256 of the content body, hex-encoded (64 lowercase hex).
    pub content_sha256: String,

    /// Optional perceptual / robust hash discriminator (PDQ, PhotoDNA,
    /// Arachnid Shield digest, etc.). Vendor format is opaque to persist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perceptual_hash: Option<String>,

    /// Federation `key_id`s of the holders the claimant identifies as
    /// having the bytes. Claim-provenance only; persist reads holders from
    /// the holding claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_holder_key_ids: Vec<String>,

    /// Closed-set legal basis under which the notice is filed.
    pub legal_basis: LegalBasis,

    /// ISO-3166-1 alpha-2 jurisdiction code (free-form sub-codes admitted).
    pub jurisdiction: String,

    /// "Good faith" statement required by some bases.
    pub good_faith_statement: String,

    /// Free-form claim narrative.
    pub claim_text: String,

    /// Evidence references — URLs, CIDs, row ids. Never makes the notice a
    /// binding of the content (`takedown_tombstone::content_binding` skips
    /// notice rows).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,

    /// Counter-notice channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_notice_channel: Option<String>,

    /// When the notice stops authorising. REQUIRED to bound replay risk; it
    /// is the row's `expires_at`.
    pub expires_at: DateTime<Utc>,
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

/// Decode + validate a `takedown_notice` payload from the JSONB column.
/// Returns `Ok(None)` for non-takedown rows (mirrors the
/// [`super::federation_announcement::extract_announcement_payload`]
/// shape) and `Ok(Some(payload))` after the shape validators run.
///
/// Validation:
///   - `content_sha256` is hex-64 lowercase.
///   - `jurisdiction` / `claim_text` / `good_faith_statement` non-empty.
///
/// The notice's signer, `claimant_key_id` and `asserted_at` are the ROW's
/// (v60.0.0): the planner stamps them, the payload does not carry them.
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
    validate_non_empty("jurisdiction", &typed.jurisdiction)?;
    validate_non_empty("claim_text", &typed.claim_text)?;
    validate_non_empty("good_faith_statement", &typed.good_faith_statement)?;
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
            legal_basis: basis,
            jurisdiction: "US".into(),
            good_faith_statement: "I have a good-faith belief that the use is unauthorized.".into(),
            claim_text: "Copyright claim over content_sha256.".into(),
            evidence_refs: vec![],
            counter_notice_channel: None,
            expires_at: DateTime::parse_from_rfc3339("2027-05-29T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    const ALL: [LegalBasis; 10] = [
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

    #[test]
    fn legal_basis_round_trips_wire_str() {
        for b in ALL {
            assert_eq!(LegalBasis::from_wire_str(b.as_str()), Some(b));
            assert_eq!(
                serde_json::to_value(b).unwrap(),
                serde_json::json!(b.as_str()),
                "serde and as_str are one spelling"
            );
        }
        assert!(LegalBasis::from_wire_str("nonsense").is_none());
        // v60.0.0 (#803) — the pre-v60 spellings are not this type's.
        assert!(LegalBasis::from_wire_str("dmca_512").is_none());
        assert!(LegalBasis::from_wire_str("dsa_article_16").is_none());
    }

    /// v60.0.0 (#803, CC 3.3.2) — every `LegalBasis` wire string IS a
    /// registry basis of `takedown_notice:{basis}:v1`, byte for byte, and the
    /// registry's only other basis is the steward purge's.
    #[test]
    fn legal_basis_is_the_registrys_closed_vocabulary() {
        let (values, open) = crate::federation::namespace::matcher::placeholder_values(
            "takedown_notice:{basis}",
            "{basis}",
        )
        .expect("rc8 registers takedown_notice:{basis}:v1 with a closed basis");
        assert!(!open);
        let ours: Vec<String> = ALL.iter().map(|b| b.as_str().to_owned()).collect();
        for b in &ours {
            assert!(values.contains(b), "{b:?} is not a registry basis");
        }
        let rest: Vec<&String> = values.iter().filter(|v| !ours.contains(v)).collect();
        assert_eq!(
            rest,
            [&crate::federation::steward_purge::STEWARD_PURGE_BASIS.to_owned()],
            "the registry's only basis outside LegalBasis is the steward purge's"
        );
    }

    #[test]
    fn admits_counter_notice_matches_ceg_0_3_locked_set() {
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
    fn legal_basis_locked_set_matches_ceg_0_3() {
        let immediate = ALL
            .iter()
            .filter(|b| b.requires_immediate_eviction())
            .count();
        let counter = ALL.iter().filter(|b| b.admits_counter_notice()).count();
        let age_gate = ALL.iter().filter(|b| b.composes_with_age_gate()).count();
        assert_eq!((immediate, counter, age_gate), (5, 4, 1));
        for b in ALL {
            let cats = u8::from(b.requires_immediate_eviction())
                + u8::from(b.admits_counter_notice())
                + u8::from(b.composes_with_age_gate());
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
        assert_eq!(
            LegalBasis::OsaIllegalContent.counter_notice_window_days(),
            Some(14)
        );
        assert_eq!(
            LegalBasis::CommunityStandards.counter_notice_window_days(),
            Some(30)
        );
        assert_eq!(LegalBasis::NcmecCsam.counter_notice_window_days(), None);
        assert_eq!(
            LegalBasis::AvmsdAgeInappropriate.counter_notice_window_days(),
            None
        );
    }

    /// The tombstone door's basis table and `LegalBasis` are one CC 4.5.3
    /// table: every basis classifies the same way through both.
    #[test]
    fn the_basis_table_is_one_table() {
        use crate::federation::takedown_tombstone::{basis_disposition, TakedownDisposition};
        for b in ALL {
            let d = basis_disposition(b.as_str())
                .unwrap_or_else(|| panic!("{} has no disposition", b.as_str()));
            let expected = if b.requires_immediate_eviction() {
                TakedownDisposition::DestroyOnReceipt
            } else if b.composes_with_age_gate() {
                TakedownDisposition::AgeGate
            } else {
                TakedownDisposition::WithholdThenDelete {
                    window_days: i64::from(b.counter_notice_window_days().unwrap()),
                }
            };
            assert_eq!(d, expected, "{}", b.as_str());
        }
    }

    #[test]
    fn extract_takedown_notice_payload_validates_shape() {
        let payload = serde_json::to_value(fixture_takedown(LegalBasis::Dmca512)).unwrap();
        assert!(
            extract_takedown_notice_payload("federation_announcement", &payload)
                .unwrap()
                .is_none()
        );
        assert!(
            extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &payload)
                .unwrap()
                .is_some()
        );
        let mut upper = fixture_takedown(LegalBasis::Dmca512);
        upper.content_sha256 = "A".repeat(64);
        let v = serde_json::to_value(upper).unwrap();
        assert!(extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &v).is_err());
        let mut empty = fixture_takedown(LegalBasis::Dmca512);
        empty.claim_text = String::new();
        let v = serde_json::to_value(empty).unwrap();
        assert!(extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &v).is_err());
        let mut v = serde_json::to_value(fixture_takedown(LegalBasis::Dmca512)).unwrap();
        v["legal_basis"] = serde_json::json!("dmca_512");
        assert!(
            extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &v).is_err(),
            "the pre-v60 spelling is refused"
        );
        let mut v = serde_json::to_value(fixture_takedown(LegalBasis::Dmca512)).unwrap();
        v["claimant_key_id"] = serde_json::json!("someone");
        assert!(
            extract_takedown_notice_payload(TAKEDOWN_NOTICE_SUBJECT_KIND, &v).is_err(),
            "the claimant is the row's signer, never a payload member"
        );
    }
}
