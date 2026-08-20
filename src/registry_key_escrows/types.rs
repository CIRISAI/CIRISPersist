//! Row types and vocabularies for the `registry_key_escrows` family.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Registry's `KeyEscrowType` vocabulary (proto v1.1.0), as strings — the
/// SQL CHECK pins the same set in both dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowType {
    /// Steward L3C holds the encrypted key.
    Steward,
    /// Legal escrow per company requirements.
    Attorney,
    /// Two stewards required to recover.
    DualCustody,
}

impl EscrowType {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            EscrowType::Steward => "steward",
            EscrowType::Attorney => "attorney",
            EscrowType::DualCustody => "dual_custody",
        }
    }
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "steward" => Some(EscrowType::Steward),
            "attorney" => Some(EscrowType::Attorney),
            "dual_custody" => Some(EscrowType::DualCustody),
            _ => None,
        }
    }
}

/// Escrow lifecycle. `Active` is the only non-terminal state; the three
/// terminal states are immutable — a custody outcome pins, never flips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Active,
    Recovered,
    Revoked,
    Expired,
}

impl EscrowStatus {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            EscrowStatus::Active => "active",
            EscrowStatus::Recovered => "recovered",
            EscrowStatus::Revoked => "revoked",
            EscrowStatus::Expired => "expired",
        }
    }
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(EscrowStatus::Active),
            "recovered" => Some(EscrowStatus::Recovered),
            "revoked" => Some(EscrowStatus::Revoked),
            "expired" => Some(EscrowStatus::Expired),
            _ => None,
        }
    }
    /// Terminal states refuse every further transition.
    pub fn is_terminal(self) -> bool {
        !matches!(self, EscrowStatus::Active)
    }
}

/// One row of `key_escrows` — custody METADATA (who holds a recovery copy
/// of which key, under what discipline, until when), never key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEscrowRow {
    pub escrow_id: String,
    pub key_id: String,
    pub org_id: String,
    pub escrow_type: EscrowType,
    pub custodian: String,
    pub status: EscrowStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
