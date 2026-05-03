//! Outbound queue row + filter shapes (CIRISPersist#16).

use chrono::{DateTime, Utc};

/// Server-generated outbound row identifier (UUID, hex+dashes).
/// Returned to callers as `DurableHandle::queue_id`. Persist
/// generates these at `enqueue_outbound` time;
/// `claim_pending_outbound` returns rows with their existing ids.
pub type QueueId = String;

/// State-machine status of an outbound row. Always one of five
/// values; schema CHECK enforces it. Two terminal states
/// (`delivered`, `abandoned`); three working states (`pending`,
/// `sending`, `awaiting_ack`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundStatus {
    /// Row is queued, eligible for `claim_pending_outbound`.
    Pending,
    /// Claimed by a dispatcher worker; transport-attempt in flight.
    Sending,
    /// Transport landed; waiting for the receiver's ACK envelope to
    /// match via `match_ack_to_outbound`.
    AwaitingAck,
    /// Terminal: transport landed and ACK received (or
    /// `requires_ack=false` and transport landed).
    Delivered,
    /// Terminal: max_attempts hit, ttl_seconds expired, or operator
    /// cancellation. See [`AbandonedReason`].
    Abandoned,
}

impl OutboundStatus {
    /// Wire-format string representation used in SQL writes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sending => "sending",
            Self::AwaitingAck => "awaiting_ack",
            Self::Delivered => "delivered",
            Self::Abandoned => "abandoned",
        }
    }

    /// Inverse of `as_str`. Returns `None` on unknown — caller
    /// surfaces as `Error::Backend` rather than panic.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "sending" => Some(Self::Sending),
            "awaiting_ack" => Some(Self::AwaitingAck),
            "delivered" => Some(Self::Delivered),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    /// Terminal states (`delivered`, `abandoned`) — no transitions
    /// out except via operator surface (replay_abandoned).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Delivered | Self::Abandoned)
    }
}

/// Why a row reached `Abandoned`. Mirrors the schema's
/// `abandoned_reason` CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonedReason {
    /// `attempt_count >= max_attempts` after a transport failure.
    MaxAttempts,
    /// `now() - enqueued_at > ttl_seconds`. Sweep-driven.
    TtlExpired,
    /// Explicit operator action via `cancel_outbound`.
    OperatorCancel,
}

impl AbandonedReason {
    /// Wire-format string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MaxAttempts => "max_attempts",
            Self::TtlExpired => "ttl_expired",
            Self::OperatorCancel => "operator_cancel",
        }
    }

    /// Inverse of `as_str`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "max_attempts" => Some(Self::MaxAttempts),
            "ttl_expired" => Some(Self::TtlExpired),
            "operator_cancel" => Some(Self::OperatorCancel),
            _ => None,
        }
    }
}

/// Result of `mark_transport_failed`. `Retrying { attempt }` when
/// the row stays alive (attempt_count++, scheduled for next try);
/// `Abandoned` when the failure pushed past `max_attempts` or
/// `ttl_seconds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundFailureOutcome {
    /// The row survives this failure; will be re-claimed at
    /// `next_attempt_after`. `attempt` is the new attempt_count
    /// after increment.
    Retrying {
        /// New value of `attempt_count` post-increment.
        attempt: i32,
    },
    /// The failure exhausted the row's retry budget or TTL window.
    /// Row is now in `abandoned` state.
    Abandoned,
}

/// Filter for `list_outbound`. All fields optional; combine with
/// AND. Used by ops dashboards.
#[derive(Debug, Clone, Default)]
pub struct OutboundFilter {
    /// Restrict to rows with this status.
    pub status: Option<OutboundStatus>,
    /// Restrict to rows where `destination_key_id = this`.
    pub destination_key_id: Option<String>,
    /// Restrict to rows where `sender_key_id = this`.
    pub sender_key_id: Option<String>,
    /// Restrict to rows where `message_type = this`.
    pub message_type: Option<String>,
    /// Restrict to rows where `enqueued_at >= this`.
    pub enqueued_after: Option<DateTime<Utc>>,
}

/// Row shape returned by `claim_pending_outbound`,
/// `outbound_status`, `list_outbound`, `match_ack_to_outbound`. Maps
/// 1:1 onto `cirislens.edge_outbound_queue` columns.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboundRow {
    /// Server-generated row identifier (UUID).
    pub queue_id: QueueId,

    // ── Identity ────────────────────────────────────────────────
    /// Sender peer's `federation_keys.key_id`.
    pub sender_key_id: String,
    /// Destination peer's `federation_keys.key_id`.
    pub destination_key_id: String,

    // ── Wire format ─────────────────────────────────────────────
    /// CIRISEdge MessageType discriminant string.
    pub message_type: String,
    /// CIRISEdge wire-format version (independent of trace
    /// schema_version).
    pub edge_schema_version: String,
    /// Envelope bytes verbatim — what the dispatcher hands to the
    /// transport layer.
    pub envelope_bytes: Vec<u8>,
    /// Content hash for ACK matching (receiver's ACK envelope's
    /// `in_reply_to` field equals this).
    pub body_sha256: [u8; 32],
    /// Length in bytes of `envelope_bytes`.
    pub body_size_bytes: i32,

    // ── State ───────────────────────────────────────────────────
    /// Current status.
    pub status: OutboundStatus,
    /// Wall-clock at enqueue.
    pub enqueued_at: DateTime<Utc>,
    /// Earliest time a dispatcher claim is allowed.
    pub next_attempt_after: DateTime<Utc>,
    /// Wall-clock of the most recent claim/transport-attempt.
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// Wall-clock when the transport reported successful delivery.
    pub transport_delivered_at: Option<DateTime<Utc>>,
    /// Wall-clock at terminal `delivered`.
    pub delivered_at: Option<DateTime<Utc>>,
    /// Wall-clock at terminal `abandoned`.
    pub abandoned_at: Option<DateTime<Utc>>,
    /// Set iff status=`abandoned`.
    pub abandoned_reason: Option<AbandonedReason>,

    // ── Per-row policy ──────────────────────────────────────────
    /// Transport attempts taken so far.
    pub attempt_count: i32,
    /// Maximum attempts before abandon.
    pub max_attempts: i32,
    /// Time-to-live from enqueue.
    pub ttl_seconds: i64,
    /// Most-recent transport error class (`transport_unreachable`,
    /// `protocol_error`, etc.).
    pub last_error_class: Option<String>,
    /// Most-recent transport error detail string.
    pub last_error_detail: Option<String>,
    /// Transport identifier of the most recent attempt
    /// (`reticulum`, `https`, `mock`, etc.).
    pub last_transport: Option<String>,

    // ── ACK contract ────────────────────────────────────────────
    /// Whether the message-type policy required an ACK.
    pub requires_ack: bool,
    /// Maximum wait between transport_delivered and ack_received
    /// before sweep_ack_timeouts retries/abandons. Required when
    /// `requires_ack=true`.
    pub ack_timeout_seconds: Option<i64>,
    /// Receiver's ACK envelope verbatim (set by mark_ack_received).
    pub ack_envelope_bytes: Option<Vec<u8>>,
    /// Wall-clock when the ACK was matched + recorded.
    pub ack_received_at: Option<DateTime<Utc>>,

    // ── Multi-instance dispatch claim ───────────────────────────
    /// Earliest time another dispatcher worker may re-claim this
    /// row (set by `claim_pending_outbound`; cleared on
    /// mark_transport_*).
    pub claimed_until: Option<DateTime<Utc>>,
    /// Worker identifier that holds the claim.
    pub claimed_by: Option<String>,
}
