// v2.1: the FSD §2.1 / §3.2.1 enum variants are the cross-repo wire
// contract; their semantics live in the FSD, not in per-variant
// rustdoc copies. Allow `missing_docs` at the file level — mirrors
// the same call made in `cirisnode::types`.
#![allow(missing_docs)]

//! `federation_announcement` subject_kind + `federation_delivery_attestations`
//! row schema (CIRISPersist#101, v2.1).
//!
//! Mirrors `~/CIRISNodeCore/FSD/FEDERATION_ANNOUNCEMENT.md` §2.1
//! (announcement payload) + §3.2.1 (ratified `DeliveryAttestation`
//! wire shape, locked 2026-05-27). Field names, serde tags, enum
//! variants are byte-for-byte the FSD's — these structs cross the
//! NodeCore↔Edge↔Persist wire and any divergence is a coordinated
//! wire break.
//!
//! # The constitutional asymmetry (FSD §4.5)
//!
//! `AccordCarrier` priority MUST be paired with `HumanityAccord`
//! authority, and `HumanityAccord` MAY ONLY sign `AccordCarrier`.
//! The two halves of the rule are enforced both at the DB layer
//! (V046 CHECK / trigger) and in [`enforce_constitutional_asymmetry`]
//! before the row reaches the DB — so a malformed announcement gets
//! a typed [`Error::FederationAnnouncementAuthorityMismatch`] from
//! persist's admission path rather than a backend-mapped CHECK
//! violation. Either guard is sufficient; both run for defense in
//! depth.
//!
//! # Delivery attestation
//!
//! Per FSD §3.2.1 the per-peer `DeliveryAttestation` is one-to-one
//! with the wire struct: `(announcement_id, peer_key_id)` PK,
//! `announcement_canonical_hash` pins the bytes the peer received,
//! `transport_id` enumerates the carrier medium, hybrid
//! Ed25519+ML-DSA-65 signature follows persist's AV-33 bound-
//! signature convention. The canonical-bytes encoder lives in
//! [`DeliveryAttestation::canonical_bytes`] and mirrors CIRISEdge's
//! `src/transport/attestation.rs` `AttestationPayload::canonical_bytes`
//! length-prefixed injective layout.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::Error;

// ─── FSD §2.1 wire types ────────────────────────────────────────────

/// Wire constant — new row in `CIRISNodeCore/SCHEMA.md` §3.2.
pub const SUBJECT_KIND: &str = "federation_announcement";

/// Domain-separation tag for [`DeliveryAttestation::canonical_bytes`]
/// — FSD §3.2.1. **Locked** wire constant; changing it is a
/// coordinated NodeCore + Edge + Persist break.
pub const DELIVERY_ATTESTATION_DOMAIN: &[u8] = b"ciris-edge-delivery-attestation-v1";

/// Federation announcement payload — mirrors FSD §2.1 byte-for-byte.
///
/// Stored as JSONB in `cirisnode.contributions.payload` for
/// `subject_kind = 'federation_announcement'` rows. The
/// [`Self::priority`] / [`Self::authority_class`] fields are
/// additionally projected into the dedicated
/// `announcement_priority` / `announcement_authority_class`
/// columns so the constitutional CHECK + read-side filters don't
/// have to dig into the JSONB on every row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationAnnouncementPayload {
    /// Priority class. Drives receiver behavior, witness-set
    /// requirement, and substrate-delivery class.
    pub priority: AnnouncementPriority,

    /// What kind of announcement this is.
    pub kind: AnnouncementKind,

    /// Short label for operator UIs and audit-chain summaries.
    pub title: String,

    /// Full announcement body. Plain text or markdown.
    pub body: String,

    /// Trust class the signer claims to act under.
    pub authority_class: AuthorityClass,

    /// Present iff `kind == AccordCarrier`. Carries the 77-byte
    /// accord payload for the existing `accord/executor.py` to
    /// execute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accord_payload: Option<AccordCarrier>,

    /// Optional back-ref to an earlier announcement this one
    /// supersedes / amends / retracts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,

    /// When the announcement is no longer relevant. REQUIRED to
    /// bound replay risk.
    pub expires_at: DateTime<Utc>,

    /// Supporting references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

/// `AnnouncementPriority` per FSD §2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementPriority {
    Informational,
    Advisory,
    Urgent,
    AccordCarrier,
}

impl AnnouncementPriority {
    /// Wire-shaped string — matches the V046 CHECK constraint
    /// vocabulary on `announcement_priority`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Advisory => "advisory",
            Self::Urgent => "urgent",
            Self::AccordCarrier => "accord_carrier",
        }
    }

    /// Parse from the wire-shaped string. Returns `None` on
    /// vocabulary mismatch.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "informational" => Self::Informational,
            "advisory" => Self::Advisory,
            "urgent" => Self::Urgent,
            "accord_carrier" => Self::AccordCarrier,
            _ => return None,
        })
    }
}

/// `AnnouncementKind` per FSD §2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementKind {
    Deprecation,
    PolicyUpdate,
    MissionUpdate,
    ThreatAdvisory,
    KeyRotation,
    PilotPhaseChange,
    AccordCarrier,
    Custom(String),
}

/// `AuthorityClass` per FSD §2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClass {
    BootstrapSeed,
    RootWa,
    WaQuorum,
    HumanityAccord,
}

impl AuthorityClass {
    /// Wire-shaped string — matches the V046 CHECK constraint
    /// vocabulary on `announcement_authority_class`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapSeed => "bootstrap_seed",
            Self::RootWa => "root_wa",
            Self::WaQuorum => "wa_quorum",
            Self::HumanityAccord => "humanity_accord",
        }
    }

    /// Parse from the wire-shaped string.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "bootstrap_seed" => Self::BootstrapSeed,
            "root_wa" => Self::RootWa,
            "wa_quorum" => Self::WaQuorum,
            "humanity_accord" => Self::HumanityAccord,
            _ => return None,
        })
    }
}

/// `AccordCarrier` payload per FSD §2.1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccordCarrier {
    /// The 77-byte accord payload per CIRISAgent's `AccordPayload`.
    /// Length is not statically enforced at the type level — payload
    /// length lives at the agent-executor's verifier — but persist
    /// preserves the bytes verbatim through JSONB serialization (the
    /// `byte_array` round-trip test below pins this against
    /// `serde_json` truncation regressions).
    pub payload_bytes: Vec<u8>,

    /// Optional human-readable rationale (audit-chain only; not
    /// used for execution).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Enforce the constitutional asymmetry (FSD §4.5):
///
/// - `AnnouncementPriority::AccordCarrier` MUST be signed by
///   `AuthorityClass::HumanityAccord`.
/// - `AuthorityClass::HumanityAccord` MAY ONLY sign
///   `AnnouncementPriority::AccordCarrier`.
/// - `AnnouncementKind::AccordCarrier` MUST coincide with
///   `AnnouncementPriority::AccordCarrier` (FSD §2.1: the
///   `AccordCarrier` kind is present iff the priority is
///   `AccordCarrier`).
///
/// Returns [`Error::FederationAnnouncementAuthorityMismatch`] on
/// any violation. The DB CHECK / trigger from V046 enforces the
/// same rule independently — the asymmetry holds against both
/// admission paths.
pub fn enforce_constitutional_asymmetry(
    payload: &FederationAnnouncementPayload,
) -> Result<(), Error> {
    let priority_is_accord = matches!(payload.priority, AnnouncementPriority::AccordCarrier);
    let authority_is_humanity = matches!(payload.authority_class, AuthorityClass::HumanityAccord);
    let kind_is_accord = matches!(payload.kind, AnnouncementKind::AccordCarrier);

    if priority_is_accord && !authority_is_humanity {
        return Err(Error::FederationAnnouncementAuthorityMismatch(format!(
            "priority=accord_carrier requires authority_class=humanity_accord (got {})",
            payload.authority_class.as_str()
        )));
    }
    if authority_is_humanity && !priority_is_accord {
        return Err(Error::FederationAnnouncementAuthorityMismatch(format!(
            "authority_class=humanity_accord may only sign priority=accord_carrier (got {})",
            payload.priority.as_str()
        )));
    }
    if kind_is_accord && !priority_is_accord {
        return Err(Error::FederationAnnouncementAuthorityMismatch(
            "kind=accord_carrier requires priority=accord_carrier".into(),
        ));
    }
    if priority_is_accord && !kind_is_accord {
        return Err(Error::FederationAnnouncementAuthorityMismatch(
            "priority=accord_carrier requires kind=accord_carrier".into(),
        ));
    }
    Ok(())
}

// ─── FSD §3.2.1 delivery_attestation wire types ─────────────────────

/// Transport medium per FSD §3.2.1. Medium tag only — sub-path /
/// interface intentionally not recorded for v0.1 (topology-disclosure
/// conservative default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMedium {
    Reticulum,
    TcpTls,
    HttpOverTls,
    Other,
}

impl TransportMedium {
    /// Wire-shaped string — matches the V046 CHECK constraint
    /// vocabulary on `transport_id`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reticulum => "reticulum",
            Self::TcpTls => "tcp_tls",
            Self::HttpOverTls => "http_over_tls",
            Self::Other => "other",
        }
    }

    /// Parse from the wire-shaped string.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "reticulum" => Self::Reticulum,
            "tcp_tls" => Self::TcpTls,
            "http_over_tls" => Self::HttpOverTls,
            "other" => Self::Other,
            _ => return None,
        })
    }
}

/// Per-peer delivery attestation — mirrors FSD §3.2.1 ratified
/// wire shape (locked 2026-05-27).
///
/// PK on `(announcement_id, peer_key_id)`. Idempotent on replay
/// (FSD §3.2.1 "AV: replayed attestation" — second insert is a
/// no-op).
///
/// # Wire encoding for byte fields
///
/// Following the persist + CIRISEdge convention
/// (`AnnounceAttestation`, `federation_keys.scrub_signature_*`):
/// raw byte fields ride the JSON wire as base64-standard strings.
/// The FSD §3.2.1 Rust struct names typed `[u8; 32]` /
/// `Ed25519Signature` / `MlDsa65Signature` fields; persist stores
/// the raw bytes server-side (BYTEA / BLOB), but the FFI / JSON
/// boundary serializes them as base64 strings to keep callers free
/// of binary-aware codecs. The base64-decoded byte sequence is what
/// participates in [`Self::canonical_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAttestation {
    /// The announcement this attestation acknowledges. Same shape as
    /// `ContributionEnvelope::contribution_id` (UUID string).
    pub announcement_id: String,

    /// SHA-256 of the full canonicalized Contribution envelope of
    /// the announcement (INCLUDING its authority signature). Pins
    /// the exact bytes the peer received. 32 bytes raw, base64-
    /// standard on the wire (44 chars).
    pub announcement_canonical_hash_base64: String,

    /// The peer that is acknowledging receipt — `federation_keys.key_id`
    /// from persist's directory.
    pub peer_key_id: String,

    /// Base64 of the peer's Ed25519 pubkey (denormalized for offline
    /// verification convenience; MUST match
    /// `federation_keys[peer_key_id].pubkey_ed25519`).
    pub peer_pubkey_ed25519_base64: String,

    /// When the peer's edge accepted the validated announcement.
    pub received_at: DateTime<Utc>,

    /// Transport medium the announcement arrived over.
    pub transport_id: TransportMedium,

    /// MANDATORY classical Ed25519 signature (64 bytes raw) over
    /// the canonical-bytes encoding. Base64-standard on the wire.
    pub signature_classical_base64: String,

    /// OPTIONAL PQC ML-DSA-65 signature (3309 bytes raw, FIPS 204
    /// final) over `canonical_bytes || signature_classical` per the
    /// persist AV-33 bound-signature convention. Base64-standard on
    /// the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_pqc_base64: Option<String>,
}

impl DeliveryAttestation {
    /// The exact bytes the peer's federation key signs / a verifier
    /// checks.
    ///
    /// Layout (FSD §3.2.1 + CIRISEdge `AttestationPayload::canonical_bytes`
    /// pattern, all integer length prefixes big-endian u64):
    ///
    /// ```text
    /// DOMAIN
    ///   ‖ u64_be(announcement_id.len())          ‖ announcement_id
    ///   ‖ announcement_canonical_hash            (32B raw, base64-decoded)
    ///   ‖ u64_be(peer_key_id.len())              ‖ peer_key_id
    ///   ‖ u64_be(peer_pubkey_b64.len())          ‖ peer_pubkey_b64
    ///   ‖ i64_be(received_at.timestamp_millis()) (8B fixed)
    ///   ‖ u64_be(transport_id_str.len())         ‖ transport_id_str
    /// ```
    ///
    /// `DOMAIN` is [`DELIVERY_ATTESTATION_DOMAIN`]. The length
    /// prefixes make the encoding injective: distinct field tuples
    /// never share a byte string, so a signature is bound to exactly
    /// one attestation tuple.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if
    /// `announcement_canonical_hash_base64` is not base64 of exactly
    /// 32 bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let announcement_id = self.announcement_id.as_bytes();
        let peer_key_id = self.peer_key_id.as_bytes();
        let peer_pubkey = self.peer_pubkey_ed25519_base64.as_bytes();
        let transport = self.transport_id.as_str().as_bytes();
        let canonical_hash = self.canonical_hash_bytes()?;

        let cap = DELIVERY_ATTESTATION_DOMAIN.len()
            + 8 + announcement_id.len()
            + canonical_hash.len()
            + 8 + peer_key_id.len()
            + 8 + peer_pubkey.len()
            + 8 // received_at i64
            + 8 + transport.len();
        let mut out = Vec::with_capacity(cap);

        out.extend_from_slice(DELIVERY_ATTESTATION_DOMAIN);
        out.extend_from_slice(&(announcement_id.len() as u64).to_be_bytes());
        out.extend_from_slice(announcement_id);
        out.extend_from_slice(&canonical_hash);
        out.extend_from_slice(&(peer_key_id.len() as u64).to_be_bytes());
        out.extend_from_slice(peer_key_id);
        out.extend_from_slice(&(peer_pubkey.len() as u64).to_be_bytes());
        out.extend_from_slice(peer_pubkey);
        out.extend_from_slice(&self.received_at.timestamp_millis().to_be_bytes());
        out.extend_from_slice(&(transport.len() as u64).to_be_bytes());
        out.extend_from_slice(transport);

        Ok(out)
    }

    /// Decode [`Self::announcement_canonical_hash_base64`] to raw
    /// 32 bytes. Returns [`Error::InvalidArgument`] on base64-decode
    /// failure or length mismatch.
    pub fn canonical_hash_bytes(&self) -> Result<[u8; 32], Error> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.announcement_canonical_hash_base64.as_bytes())
            .map_err(|e| {
                Error::InvalidArgument(format!(
                    "announcement_canonical_hash_base64 not base64: {e}"
                ))
            })?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            Error::InvalidArgument(format!(
                "announcement_canonical_hash_base64 must decode to 32 bytes (got {})",
                raw.len()
            ))
        })?;
        Ok(arr)
    }

    /// Decode the mandatory classical Ed25519 signature to raw bytes
    /// (expected 64). Returns [`Error::InvalidArgument`] on
    /// base64-decode failure or wrong length.
    pub fn signature_classical_bytes(&self) -> Result<[u8; 64], Error> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.signature_classical_base64.as_bytes())
            .map_err(|e| {
                Error::InvalidArgument(format!("signature_classical_base64 not base64: {e}"))
            })?;
        let arr: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
            Error::InvalidArgument(format!(
                "signature_classical_base64 must decode to 64 bytes (got {})",
                raw.len()
            ))
        })?;
        Ok(arr)
    }

    /// Decode the optional PQC ML-DSA-65 signature to raw bytes.
    /// Returns `Ok(None)` if absent; `Err(InvalidArgument)` on
    /// base64-decode failure.
    pub fn signature_pqc_bytes(&self) -> Result<Option<Vec<u8>>, Error> {
        match &self.signature_pqc_base64 {
            None => Ok(None),
            Some(s) => base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map(Some)
                .map_err(|e| Error::InvalidArgument(format!("signature_pqc_base64: {e}"))),
        }
    }
}

/// Convenience: base64-encode a 32-byte canonical hash for callers
/// that hold the raw bytes (e.g. fresh SHA-256 output).
pub fn encode_canonical_hash_base64(hash: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Convenience: base64-encode a 64-byte Ed25519 signature.
pub fn encode_signature_base64(sig: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(sig)
}

/// Decode + validate a federation_announcement payload from the
/// JSONB column. Returns the typed payload + a final pass through
/// [`enforce_constitutional_asymmetry`] so that callers writing
/// into `cirisnode.contributions` get the same wire-format
/// rejection persist's admission applies.
///
/// `subject_kind` is the row's `subject_kind` column; the function
/// returns `Ok(None)` for non-announcement rows (preserves the
/// shared call site between announcement and non-announcement
/// contributions) and `Ok(Some(payload))` after the asymmetry pass.
pub fn extract_announcement_payload(
    subject_kind: &str,
    payload: &serde_json::Value,
) -> Result<Option<FederationAnnouncementPayload>, Error> {
    if subject_kind != SUBJECT_KIND {
        return Ok(None);
    }
    let typed: FederationAnnouncementPayload =
        serde_json::from_value(payload.clone()).map_err(|e| {
            Error::InvalidArgument(format!("federation_announcement payload shape: {e}"))
        })?;
    enforce_constitutional_asymmetry(&typed)?;
    Ok(Some(typed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_round_trip_via_wire_str() {
        for p in [
            AnnouncementPriority::Informational,
            AnnouncementPriority::Advisory,
            AnnouncementPriority::Urgent,
            AnnouncementPriority::AccordCarrier,
        ] {
            let s = p.as_str();
            assert_eq!(AnnouncementPriority::from_wire_str(s), Some(p));
        }
        assert!(AnnouncementPriority::from_wire_str("invalid").is_none());
    }

    #[test]
    fn authority_round_trip_via_wire_str() {
        for a in [
            AuthorityClass::BootstrapSeed,
            AuthorityClass::RootWa,
            AuthorityClass::WaQuorum,
            AuthorityClass::HumanityAccord,
        ] {
            let s = a.as_str();
            assert_eq!(AuthorityClass::from_wire_str(s), Some(a));
        }
    }

    #[test]
    fn transport_round_trip_via_wire_str() {
        for t in [
            TransportMedium::Reticulum,
            TransportMedium::TcpTls,
            TransportMedium::HttpOverTls,
            TransportMedium::Other,
        ] {
            assert_eq!(TransportMedium::from_wire_str(t.as_str()), Some(t));
        }
    }

    #[test]
    fn priority_serde_matches_fsd_snake_case() {
        // FSD §2.1 declares `#[serde(rename_all = "snake_case")]`.
        // AccordCarrier → "accord_carrier".
        assert_eq!(
            serde_json::to_string(&AnnouncementPriority::AccordCarrier).unwrap(),
            r#""accord_carrier""#
        );
        let parsed: AnnouncementPriority = serde_json::from_str(r#""urgent""#).unwrap();
        assert_eq!(parsed, AnnouncementPriority::Urgent);
    }

    #[test]
    fn authority_serde_matches_fsd_snake_case() {
        assert_eq!(
            serde_json::to_string(&AuthorityClass::HumanityAccord).unwrap(),
            r#""humanity_accord""#
        );
    }

    #[test]
    fn announcement_kind_serde_custom_variant_round_trips() {
        let k = AnnouncementKind::Custom("operator_defined".into());
        let s = serde_json::to_string(&k).unwrap();
        let back: AnnouncementKind = serde_json::from_str(&s).unwrap();
        assert_eq!(k, back);
    }

    fn fixture_payload(
        priority: AnnouncementPriority,
        authority: AuthorityClass,
        kind: AnnouncementKind,
        accord_payload: Option<AccordCarrier>,
    ) -> FederationAnnouncementPayload {
        FederationAnnouncementPayload {
            priority,
            kind,
            title: "test".into(),
            body: "test body".into(),
            authority_class: authority,
            accord_payload,
            supersedes: None,
            expires_at: DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            evidence_refs: vec![],
        }
    }

    #[test]
    fn asymmetry_accepts_humanity_accord_carrier() {
        let p = fixture_payload(
            AnnouncementPriority::AccordCarrier,
            AuthorityClass::HumanityAccord,
            AnnouncementKind::AccordCarrier,
            Some(AccordCarrier {
                payload_bytes: vec![0u8; 77],
                rationale: Some("drill".into()),
            }),
        );
        enforce_constitutional_asymmetry(&p).unwrap();
    }

    #[test]
    fn asymmetry_accepts_non_accord_advisory() {
        let p = fixture_payload(
            AnnouncementPriority::Advisory,
            AuthorityClass::RootWa,
            AnnouncementKind::PolicyUpdate,
            None,
        );
        enforce_constitutional_asymmetry(&p).unwrap();
    }

    #[test]
    fn asymmetry_rejects_accord_signed_by_root_wa() {
        let p = fixture_payload(
            AnnouncementPriority::AccordCarrier,
            AuthorityClass::RootWa,
            AnnouncementKind::AccordCarrier,
            None,
        );
        let err = enforce_constitutional_asymmetry(&p).unwrap_err();
        assert!(
            matches!(err, Error::FederationAnnouncementAuthorityMismatch(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn asymmetry_rejects_humanity_signing_urgent() {
        let p = fixture_payload(
            AnnouncementPriority::Urgent,
            AuthorityClass::HumanityAccord,
            AnnouncementKind::PolicyUpdate,
            None,
        );
        let err = enforce_constitutional_asymmetry(&p).unwrap_err();
        assert!(matches!(
            err,
            Error::FederationAnnouncementAuthorityMismatch(_)
        ));
    }

    #[test]
    fn asymmetry_rejects_accord_priority_with_non_accord_kind() {
        let p = fixture_payload(
            AnnouncementPriority::AccordCarrier,
            AuthorityClass::HumanityAccord,
            AnnouncementKind::PolicyUpdate,
            None,
        );
        let err = enforce_constitutional_asymmetry(&p).unwrap_err();
        assert!(matches!(
            err,
            Error::FederationAnnouncementAuthorityMismatch(_)
        ));
    }

    #[test]
    fn asymmetry_rejects_accord_kind_with_non_accord_priority() {
        let p = fixture_payload(
            AnnouncementPriority::Urgent,
            AuthorityClass::HumanityAccord,
            AnnouncementKind::AccordCarrier,
            None,
        );
        let err = enforce_constitutional_asymmetry(&p).unwrap_err();
        assert!(matches!(
            err,
            Error::FederationAnnouncementAuthorityMismatch(_)
        ));
    }

    #[test]
    fn accord_carrier_77_byte_payload_round_trip() {
        // The accord payload is 77 bytes per the CIRISAgent
        // `AccordPayload` schema. Serialize → JSON → deserialize and
        // confirm byte-equal restoration. `serde_json` represents
        // `Vec<u8>` as a JSON number array by default, which preserves
        // each byte exactly (no base64 truncation, no encoding drift).
        let payload_bytes: Vec<u8> = (0u8..77).collect();
        let ac = AccordCarrier {
            payload_bytes: payload_bytes.clone(),
            rationale: Some("kill switch drill".into()),
        };
        let s = serde_json::to_string(&ac).unwrap();
        let back: AccordCarrier = serde_json::from_str(&s).unwrap();
        assert_eq!(back.payload_bytes.len(), 77);
        assert_eq!(back.payload_bytes, payload_bytes);
    }

    // ── delivery_attestation canonical-bytes golden ────────────────

    fn fixture_attestation() -> DeliveryAttestation {
        DeliveryAttestation {
            announcement_id: "11111111-1111-1111-1111-111111111111".into(),
            announcement_canonical_hash_base64: encode_canonical_hash_base64(&[0xAB; 32]),
            peer_key_id: "edge-peer-01".into(),
            peer_pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            received_at: DateTime::parse_from_rfc3339("2026-06-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            transport_id: TransportMedium::Reticulum,
            signature_classical_base64: encode_signature_base64(&[0u8; 64]),
            signature_pqc_base64: None,
        }
    }

    /// Length-prefixed injective: distinct fields must produce
    /// distinct canonical bytes. Same property CIRISEdge's
    /// `AttestationPayload::canonical_bytes` pins.
    #[test]
    fn canonical_bytes_are_injective() {
        let a = fixture_attestation().canonical_bytes().unwrap();

        let mut b_att = fixture_attestation();
        b_att.peer_key_id = "edge-peer-02".into();
        let b = b_att.canonical_bytes().unwrap();
        assert_ne!(a, b);

        let mut c_att = fixture_attestation();
        c_att.announcement_canonical_hash_base64 = encode_canonical_hash_base64(&[0xCD; 32]);
        let c = c_att.canonical_bytes().unwrap();
        assert_ne!(a, c);

        let mut d_att = fixture_attestation();
        d_att.transport_id = TransportMedium::TcpTls;
        let d = d_att.canonical_bytes().unwrap();
        assert_ne!(a, d);

        let mut e_att = fixture_attestation();
        e_att.received_at = DateTime::parse_from_rfc3339("2026-06-01T00:00:00.001Z")
            .unwrap()
            .with_timezone(&Utc);
        let e = e_att.canonical_bytes().unwrap();
        assert_ne!(a, e);
    }

    /// Length-prefixed: distinct fields adjacent in the encoding
    /// cannot alias. `"ab"+"c"` vs `"a"+"bc"` style — a naive concat
    /// without prefixes would collide; with length prefixes it must
    /// not. Pins the FSD §3.2.1 + CIRISEdge §3.4 confusability rule.
    #[test]
    fn canonical_bytes_resist_field_confusion() {
        let mut a_att = fixture_attestation();
        a_att.peer_key_id = "ab".into();
        a_att.peer_pubkey_ed25519_base64 = "cZ".into();
        let a = a_att.canonical_bytes().unwrap();

        let mut b_att = fixture_attestation();
        b_att.peer_key_id = "a".into();
        b_att.peer_pubkey_ed25519_base64 = "bcZ".into();
        let b = b_att.canonical_bytes().unwrap();

        assert_ne!(a, b, "length-prefixed encoding must not alias");
    }

    /// Golden vector: a fixed attestation produces a fixed byte
    /// string. This vector is the cross-repo wire contract — any
    /// change here is a coordinated NodeCore+Edge+Persist break.
    #[test]
    fn canonical_bytes_golden_vector() {
        let att = fixture_attestation();
        let bytes = att.canonical_bytes().unwrap();

        // Reconstruct the expected layout manually so the test
        // catches any regression in the encoder (drift between this
        // golden + the encoder's actual output is the regression
        // signal).
        let mut expected = Vec::new();
        expected.extend_from_slice(b"ciris-edge-delivery-attestation-v1");
        // announcement_id len + bytes
        let id = b"11111111-1111-1111-1111-111111111111";
        expected.extend_from_slice(&(id.len() as u64).to_be_bytes());
        expected.extend_from_slice(id);
        // canonical_hash 32 bytes of 0xAB (raw, base64-decoded)
        expected.extend_from_slice(&[0xAB; 32]);
        // peer_key_id len + bytes
        let pkid = b"edge-peer-01";
        expected.extend_from_slice(&(pkid.len() as u64).to_be_bytes());
        expected.extend_from_slice(pkid);
        // peer pubkey len + bytes
        let pp = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        expected.extend_from_slice(&(pp.len() as u64).to_be_bytes());
        expected.extend_from_slice(pp);
        // received_at i64 ms = 2026-06-01T00:00:00Z = 1780272000000
        let ts_ms: i64 = 1_780_272_000_000;
        expected.extend_from_slice(&ts_ms.to_be_bytes());
        // transport_id len + bytes ("reticulum")
        let t = b"reticulum";
        expected.extend_from_slice(&(t.len() as u64).to_be_bytes());
        expected.extend_from_slice(t);

        assert_eq!(
            bytes, expected,
            "delivery-attestation canonical bytes drifted from FSD §3.2.1 wire contract"
        );
    }

    #[test]
    fn delivery_attestation_json_round_trip() {
        let att = fixture_attestation();
        let s = serde_json::to_string(&att).unwrap();
        let back: DeliveryAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(att, back);
    }

    #[test]
    fn delivery_attestation_with_pqc_round_trip() {
        let mut att = fixture_attestation();
        att.signature_pqc_base64 = Some(encode_signature_base64(&vec![0xFE; 3309]));
        let s = serde_json::to_string(&att).unwrap();
        let back: DeliveryAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(att, back);
        assert_eq!(
            back.signature_pqc_bytes().unwrap().map(|v| v.len()),
            Some(3309)
        );
    }

    #[test]
    fn canonical_hash_bytes_rejects_wrong_length() {
        let mut att = fixture_attestation();
        att.announcement_canonical_hash_base64 =
            base64::engine::general_purpose::STANDARD.encode([0u8; 16]); // only 16 bytes
        let err = att.canonical_bytes().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got: {err:?}");
    }

    #[test]
    fn signature_classical_bytes_rejects_wrong_length() {
        let mut att = fixture_attestation();
        att.signature_classical_base64 =
            base64::engine::general_purpose::STANDARD.encode([0u8; 32]); // 32 instead of 64
        let err = att.signature_classical_bytes().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }
}
