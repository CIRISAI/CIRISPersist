//! cirislens audit log wire types (v0.8.1, CIRISPersist#35).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One audit log entry. Mirrors the `cirislens.audit_log` row shape.
///
/// AV-49 hash-chain semantics: `prev_hash` is sha256 of the
/// preceding entry's canonical bytes (or [`super::GENESIS_PREV_HASH`]
/// for the chain's first entry); `entry_hash` is sha256 of THIS
/// entry's canonical bytes (with the `signature` field stripped per
/// the persist-wide canonicalizer rule).
///
/// Self-signed identity: `actor_id` IS the Ed25519 pubkey
/// (base64-encoded) per the v0.7.1 model used by cirisnode envelopes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub entry_id: String,
    pub sequence_number: i64,
    pub tenant_id: String,
    pub actor_id: String,
    pub action_type: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub payload: serde_json::Value,
    /// 32-byte sha256. Serialized as a base64-encoded string on the
    /// wire (via `serde_bytes`-compatible encoding); stored as BYTEA
    /// in Postgres.
    #[serde(with = "serde_bytes_b64")]
    pub prev_hash: Vec<u8>,
    #[serde(with = "serde_bytes_b64")]
    pub entry_hash: Vec<u8>,
    pub recorded_at: DateTime<Utc>,
    /// Base64 Ed25519 signature. Empty during entry construction;
    /// caller fills in after signing canonical bytes.
    pub signature: String,
}

mod serde_bytes_b64 {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        B64.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

/// Filter for [`super::AuditService::list_entries`]. `tenant_id` is
/// required (AV-51 — no cross-tenant reads on this surface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_before: Option<DateTime<Utc>>,
}

/// `(recorded_at, entry_id)` cursor for the list_entries page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCursor {
    pub version: String,
    pub last_ts: DateTime<Utc>,
    pub last_id: String,
}

impl AuditCursor {
    pub fn from_trailing(last_ts: DateTime<Utc>, last_id: String) -> Self {
        Self {
            version: "v1".to_owned(),
            last_ts,
            last_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditListPage {
    pub items: Vec<AuditEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<AuditCursor>,
}

/// AV-50 chain-walk result. Either the whole walked range is
/// integral (`Ok`) or the first break is reported with its
/// diagnostic (`Break`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ChainVerifyOutcome {
    /// Every entry in `[from_sequence, to_sequence]` verified
    /// cleanly: entry_hash matches canonical bytes, prev_hash
    /// matches preceding entry, sequence is contiguous, signature
    /// verifies.
    Ok,
    /// First break observed at `at_sequence` with the indicated
    /// reason category.
    Break {
        at_sequence: i64,
        reason: ChainBreakReason,
        /// Human-readable detail (NOT a stable token).
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainBreakReason {
    /// Re-derived `entry_hash` from canonical bytes didn't match the
    /// stored value.
    EntryHashMismatch,
    /// `prev_hash` didn't match the preceding entry's `entry_hash`.
    PrevHashMismatch,
    /// Sequence numbers aren't contiguous (gap or duplicate).
    SequenceGap,
    /// Ed25519 signature didn't verify against `actor_id`.
    SignatureFailure,
    /// Genesis entry (`sequence_number=1`) had non-zero `prev_hash`.
    GenesisPrevHashNotZero,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub tenant_id: String,
    pub from_sequence: i64,
    pub to_sequence: i64,
    pub entries_walked: usize,
    pub outcome: ChainVerifyOutcome,
}

/// Filter for [`super::AuditService::query_by_correlation_id`] (v1.0.0;
/// CIRISAgent#756 Q4). Bounded time window + result cap. The default
/// `limit` is 100; implementations cap at 1000.
#[derive(Debug, Clone)]
pub struct CorrelationQuery {
    /// Optional inclusive lower bound on `recorded_at`.
    pub time_window_start: Option<DateTime<Utc>>,
    /// Optional inclusive upper bound on `recorded_at`.
    pub time_window_end: Option<DateTime<Utc>>,
    /// Result-set cap. Default 100; clamped to [1, 1000] by the impl.
    pub limit: usize,
}

impl Default for CorrelationQuery {
    fn default() -> Self {
        Self {
            time_window_start: None,
            time_window_end: None,
            limit: 100,
        }
    }
}

/// Maximum `limit` honored by [`super::AuditService::query_by_correlation_id`].
/// Values above this cap are clamped, not rejected — caller-controlled
/// page sizes are clamped to bound backend cost.
pub const CORRELATION_QUERY_MAX_LIMIT: usize = 1000;

/// Stable reference to an audit log row (v1.0.0; CIRISAgent#756 #2).
///
/// Returned by [`super::AuditService::try_claim_event`] inside a
/// [`crate::ClaimResult`]. Identifies a row uniquely across the
/// federation: `(tenant_id, sequence_number)` is the per-tenant
/// natural key (UNIQUE on V014), `entry_id` is the global UUID.
/// Callers attach downstream work to whichever of the three handles
/// matches their addressing scheme.
/// Canonical audit event type vocabulary (CIRISAgent#756 Q2).
///
/// 21 values across handler / system / wallet event classes. Sourced
/// from CIRISAgent's `AuditEventType` enum (`ciris_engine/schemas/
/// audit/core.py`); persist mirrors the wire-shape exactly so the
/// agent's cutover can pass `action_type` strings through unchanged.
///
/// # Evolution
///
/// Additive-only per the agent team's commit on CIRISAgent#756.
/// New values added by appending to this enum + (for Postgres
/// deployments) `ALTER TABLE ... ADD CONSTRAINT` in a minor release;
/// the agent commits to bumping vocab in lockstep.
///
/// # Why typed when the trait surface keeps `String`
///
/// `AuditEntry.action_type` is `String` to keep the substrate
/// compatible with other consumers (CIRISLensCore / CIRISEdge
/// writing their own audit envelopes with different vocab). This
/// enum is a CONVENIENCE for callers that want compile-time
/// vocab enforcement — call `.as_str()` to get the wire-shaped
/// string for INSERT. Postgres deployments get additional DB-level
/// enforcement via migration V018 (NOT VALID, so legacy rows skip);
/// SQLite enforcement is convention-only for v1.0.0 (the table
/// rebuild required for `ALTER TABLE ADD CHECK` is deferred — see
/// the migration directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Handler actions (10)
    HandlerActionSpeak,
    HandlerActionMemorize,
    HandlerActionRecall,
    HandlerActionForget,
    HandlerActionTool,
    HandlerActionDefer,
    HandlerActionReject,
    HandlerActionPonder,
    HandlerActionObserve,
    HandlerActionTaskComplete,

    // System events (5)
    SystemEvent,
    SecurityEvent,
    ConfigChange,
    ServiceLifecycle,
    ErrorEvent,

    // Wallet events (6)
    WalletFundsReceived,
    WalletFundsSent,
    WalletTransferFailed,
    WalletSwapCompleted,
    WalletSwapFailed,
    WalletSecurityEvent,
}

impl AuditEventType {
    /// Wire-shaped string. Matches CIRISAgent's `AuditEventType` enum
    /// values + the Postgres V018 CHECK vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HandlerActionSpeak => "handler_action_speak",
            Self::HandlerActionMemorize => "handler_action_memorize",
            Self::HandlerActionRecall => "handler_action_recall",
            Self::HandlerActionForget => "handler_action_forget",
            Self::HandlerActionTool => "handler_action_tool",
            Self::HandlerActionDefer => "handler_action_defer",
            Self::HandlerActionReject => "handler_action_reject",
            Self::HandlerActionPonder => "handler_action_ponder",
            Self::HandlerActionObserve => "handler_action_observe",
            Self::HandlerActionTaskComplete => "handler_action_task_complete",
            Self::SystemEvent => "system_event",
            Self::SecurityEvent => "security_event",
            Self::ConfigChange => "config_change",
            Self::ServiceLifecycle => "service_lifecycle",
            Self::ErrorEvent => "error_event",
            Self::WalletFundsReceived => "wallet_funds_received",
            Self::WalletFundsSent => "wallet_funds_sent",
            Self::WalletTransferFailed => "wallet_transfer_failed",
            Self::WalletSwapCompleted => "wallet_swap_completed",
            Self::WalletSwapFailed => "wallet_swap_failed",
            Self::WalletSecurityEvent => "wallet_security_event",
        }
    }

    /// Parse from the wire-shaped string. Returns `None` for any
    /// value outside the canonical vocabulary. Use at the persist
    /// API boundary when typed enforcement matters; the trait
    /// surface keeps `String` for compatibility with non-agent
    /// consumers.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "handler_action_speak" => Self::HandlerActionSpeak,
            "handler_action_memorize" => Self::HandlerActionMemorize,
            "handler_action_recall" => Self::HandlerActionRecall,
            "handler_action_forget" => Self::HandlerActionForget,
            "handler_action_tool" => Self::HandlerActionTool,
            "handler_action_defer" => Self::HandlerActionDefer,
            "handler_action_reject" => Self::HandlerActionReject,
            "handler_action_ponder" => Self::HandlerActionPonder,
            "handler_action_observe" => Self::HandlerActionObserve,
            "handler_action_task_complete" => Self::HandlerActionTaskComplete,
            "system_event" => Self::SystemEvent,
            "security_event" => Self::SecurityEvent,
            "config_change" => Self::ConfigChange,
            "service_lifecycle" => Self::ServiceLifecycle,
            "error_event" => Self::ErrorEvent,
            "wallet_funds_received" => Self::WalletFundsReceived,
            "wallet_funds_sent" => Self::WalletFundsSent,
            "wallet_transfer_failed" => Self::WalletTransferFailed,
            "wallet_swap_completed" => Self::WalletSwapCompleted,
            "wallet_swap_failed" => Self::WalletSwapFailed,
            "wallet_security_event" => Self::WalletSecurityEvent,
            _ => return None,
        })
    }
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventRef {
    /// `cirislens.audit_log.entry_id` (UUID v4, 36-char hyphenated).
    pub entry_id: String,
    /// `cirislens.audit_log.tenant_id` — the chain selector.
    pub tenant_id: String,
    /// Per-tenant monotonic sequence number.
    pub sequence_number: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_serde_round_trip() {
        let entry = AuditEntry {
            entry_id: "abc".into(),
            sequence_number: 7,
            tenant_id: "tnt-x".into(),
            actor_id: "pubkey-base64".into(),
            action_type: "task_signed".into(),
            subject_kind: "task".into(),
            subject_id: "t-1".into(),
            payload: serde_json::json!({"signed_at": "2026-05-13"}),
            prev_hash: vec![0xab; 32],
            entry_hash: vec![0xcd; 32],
            recorded_at: Utc::now(),
            signature: "sig-b64".into(),
        };
        let s = serde_json::to_string(&entry).unwrap();
        // Hashes serialize as base64 strings, not byte arrays.
        assert!(s.contains("prev_hash"));
        let back: AuditEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn chain_outcome_break_serde() {
        let out = ChainVerifyOutcome::Break {
            at_sequence: 5,
            reason: ChainBreakReason::PrevHashMismatch,
            detail: "expected aa, got bb".into(),
        };
        let s = serde_json::to_string(&out).unwrap();
        assert!(s.contains("\"outcome\":\"break\""));
        assert!(s.contains("\"reason\":\"prev_hash_mismatch\""));
    }

    #[test]
    fn chain_outcome_ok_serde() {
        let out = ChainVerifyOutcome::Ok;
        let s = serde_json::to_string(&out).unwrap();
        assert_eq!(s, "{\"outcome\":\"ok\"}");
    }

    #[test]
    fn audit_cursor_from_trailing() {
        let c = AuditCursor::from_trailing(Utc::now(), "entry-7".into());
        assert_eq!(c.version, "v1");
        assert_eq!(c.last_id, "entry-7");
    }
}
