//! Trust grant payload + projection types (FSD §3.2 + §4.4).
//!
//! Trust grants are signed Contribution events that materialize rows in
//! `federation_trust_grants`. Every event also appends a leaf to the
//! per-tenant Merkle tree (`merkle_leaves`) and triggers a fresh STH
//! (`merkle_sth_log`).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The four purposes a trust grant can authorize. Each maps to a
/// purpose-specific scope grammar per FSD §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustPurpose {
    /// Manifest / build / artifact attestation. Scope grammar:
    /// `manifest:<id>` | `channel:<name>` | `artifact:<hash>` | `*`
    Technical,
    /// Domain-scoped resolver routing. Scope is a free-form lowercase
    /// domain identifier (mirrors V020 trust_domains entries).
    Deferral,
    /// Contribution authorship + voting. Scope grammar:
    /// `<contribution_type>` | `<contribution_type>:<subject_kind>` |
    /// `vote:<contribution_type>:<subject_kind>` | `*`. Concrete strings
    /// align with NodeCore SCHEMA §3.1/§3.2 + the 15 subject_kinds
    /// shipped in NodeCore 871ebab.
    Contribution,
    /// Access to advertised peer services (LLM/embedding/tool RPC).
    /// Scope grammar: `service:<kind>` | `service:<kind>:<resource>` | `*`.
    /// Per-invocation RPC rides edge transport; chain records
    /// service_announcement / service_deprecation / service_usage_summary
    /// via Contribution-purpose grants.
    Service,
}

impl TrustPurpose {
    /// Stable string for SQL / wire / debug. Lowercase to match the
    /// CHECK constraint on federation_trust_grants.purpose.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Technical => "technical",
            Self::Deferral => "deferral",
            Self::Contribution => "contribution",
            Self::Service => "service",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "technical" => Some(Self::Technical),
            "deferral" => Some(Self::Deferral),
            "contribution" => Some(Self::Contribution),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

/// Trust grant payload — the `subject_kind="trust_grant"` Contribution
/// payload per NodeCore SCHEMA §3.2 / §4.x and CIRISPersist FSD §3.2.
///
/// Granter is `author_id` at the envelope level (not duplicated here).
/// Revocation is a re-issuance with `expires_at = now()` (§3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrantPayload {
    pub grantee_key: String,
    pub purpose: TrustPurpose,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub rationale: String,
}

/// One trust grant row from `federation_trust_grants` (the projection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrantRow {
    pub grant_id: Uuid,
    pub grantee_key: String,
    pub granter_key: String,
    pub purpose: TrustPurpose,
    pub scope: String,
    pub granted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    pub chain_event_id: i64,
    #[serde(with = "crate::federation::serde_bytes_b64")]
    pub chain_event_hash: Vec<u8>,
    pub tenant_id: String,
}

/// Filter for `list_trust_grants` (FSD §4.3 read API).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustGrantFilter {
    pub grantee_key: Option<String>,
    pub granter_key: Option<String>,
    pub purpose: Option<TrustPurpose>,
    pub scope_prefix: Option<String>,
    #[serde(default)]
    pub include_revoked: bool,
    #[serde(default)]
    pub include_expired: bool,
}

/// Receipt returned by `Engine.grant_trust` — the chain event id, the
/// post-emit STH (always fresh per FSD §4.4 every-append cadence), and
/// the grant_id assigned by the projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrantReceipt {
    pub grant_id: Uuid,
    pub chain_event_id: i64,
    #[serde(with = "crate::federation::serde_bytes_b64")]
    pub chain_event_hash: Vec<u8>,
    pub tenant_id: String,
    pub tree_size_at_emit: u64,
    pub sth: ciris_verify_core::transparency::SignedTreeHead,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_purpose_round_trip() {
        for p in [
            TrustPurpose::Technical,
            TrustPurpose::Deferral,
            TrustPurpose::Contribution,
            TrustPurpose::Service,
        ] {
            assert_eq!(TrustPurpose::parse_str(p.as_str()), Some(p));
        }
        assert_eq!(TrustPurpose::parse_str("bogus"), None);
    }

    #[test]
    fn payload_round_trip() {
        let p = TrustGrantPayload {
            grantee_key: "B64KEY".into(),
            purpose: TrustPurpose::Contribution,
            scope: "proposal:registry_vouch".into(),
            expires_at: None,
            rationale: "qualified for medical_deferral routing".into(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: TrustGrantPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.purpose, TrustPurpose::Contribution);
        assert_eq!(back.scope, p.scope);
    }
}
