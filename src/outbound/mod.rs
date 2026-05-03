//! Edge outbound queue — durable substrate for federation peer-to-
//! peer durable messaging (CIRISPersist#16, CIRISEdge OQ-09).
//!
//! v0.4.0 — the substrate edge's `send_durable()` rests on. Edge ships
//! two outbound channels: `send()` (ephemeral; caller-owned retry)
//! and `send_durable()` (must eventually land across edge restart;
//! edge-owned retry; caller gets a `DurableHandle` to observe the
//! outcome). Delivery class lives on the message type:
//! `BuildManifestPublication::DELIVERY = Durable`,
//! `AccordEventsBatch::DELIVERY = Ephemeral`.
//!
//! # Why persist owns this
//!
//! Same architectural-closure pattern as `canonicalize_envelope`
//! (CIRISPersist#7), the cold-path PQC fill-in (#10), per-key DSAR
//! (#15), `verify_hybrid` (#14): byte-stable substrate operations
//! belong in persist, not duplicated across N consumers. If persist
//! doesn't ship durable transport, edge implements its own, lens
//! implements its own, registry implements its own. They drift. The
//! Phase 1 Durable message types map onto Accord obligations
//! (BuildManifestPublication → Fidelity & Transparency;
//! DSARRequest/Response → Justice; AttestationGossip → Integrity;
//! PublicKeyRegistration → Identity continuity). Each "best-effort
//! delivery" is an Accord obligation operationally violated.
//!
//! # State machine
//!
//! ```text
//!   enqueue → pending → sending ─┬─ (transport ok, no ack) → delivered
//!                                ├─ (transport ok, ack req) → awaiting_ack
//!                                │                              ↓
//!                                │                          delivered (ack received)
//!                                │                              ↓
//!                                │                          abandoned (ack timeout → max_attempts)
//!                                └─ (transport failed) → pending (retry) | abandoned
//! ```
//!
//! `abandoned_reason ∈ {max_attempts, ttl_expired, operator_cancel}`
//!
//! # Multi-instance dispatch (CIRISEdge OQ-06)
//!
//! `claim_pending_outbound` uses optimistic claim via `SELECT FOR
//! UPDATE SKIP LOCKED + UPDATE`. Concurrent dispatcher workers get
//! disjoint batches. Expired claims (worker crashed mid-flight)
//! revert via `sweep_expired_claims`.

pub mod types;

pub use types::{
    AbandonedReason, OutboundFailureOutcome, OutboundFilter, OutboundRow, OutboundStatus, QueueId,
};

use chrono::{DateTime, Utc};
use std::future::Future;

/// Edge outbound queue trait — the durable substrate's read+write
/// surface. Same shape discipline as
/// [`crate::federation::FederationDirectory`]: trait carries the
/// public contract; backends (memory, postgres, sqlite) implement
/// the trait in [`crate::store`].
///
/// Async surface uses Rust 1.75+ `async fn in trait` directly;
/// futures are constrained `Send` so backends can be used from
/// `tokio::spawn`-style multi-threaded contexts.
pub trait OutboundQueue: Send + Sync {
    // ── Sender side ─────────────────────────────────────────────

    /// Insert a new outbound row in `pending` state. Returns the
    /// server-generated `queue_id` the caller stores in its
    /// `DurableHandle`.
    ///
    /// Per-row policy (`max_attempts`, `ttl_seconds`,
    /// `ack_timeout_seconds`) is copied from the message-type
    /// policy at enqueue time — policy changes don't retroactively
    /// break in-flight rows.
    #[allow(clippy::too_many_arguments)]
    fn enqueue_outbound(
        &self,
        sender_key_id: &str,
        destination_key_id: &str,
        message_type: &str,
        edge_schema_version: &str,
        envelope_bytes: &[u8],
        body_sha256: &[u8; 32],
        body_size_bytes: i32,
        requires_ack: bool,
        ack_timeout_seconds: Option<i64>,
        max_attempts: i32,
        ttl_seconds: i64,
        initial_next_attempt_after: DateTime<Utc>,
    ) -> impl Future<Output = Result<QueueId, Error>> + Send;

    // ── Dispatch loop ───────────────────────────────────────────

    /// Atomic claim of up to `batch_size` `pending` rows whose
    /// `next_attempt_after <= now()`. Sets `status='sending'` +
    /// `claimed_until = now() + claim_duration_seconds` +
    /// `claimed_by = caller_id`. Returns the claimed rows; concurrent
    /// dispatcher workers see disjoint batches via `FOR UPDATE SKIP
    /// LOCKED` (Postgres) / row-level lock (SQLite).
    fn claim_pending_outbound(
        &self,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> impl Future<Output = Result<Vec<OutboundRow>, Error>> + Send;

    /// Transport reports the bytes left successfully. Transitions
    /// `sending → delivered` when `!requires_ack`, or
    /// `sending → awaiting_ack` when `requires_ack`. Sets
    /// `transport_delivered_at = now()`, clears the claim.
    fn mark_transport_delivered(
        &self,
        queue_id: &QueueId,
        transport: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Transport reports failure. Sets `last_error_class +
    /// last_error_detail + last_transport`, increments
    /// `attempt_count`, clears the claim. If `attempt_count >=
    /// max_attempts` OR `now() - enqueued_at > ttl_seconds`,
    /// transitions to `abandoned` with the corresponding reason.
    /// Otherwise sets `next_attempt_after` to the caller-supplied
    /// backoff target and reverts to `pending` for re-claim.
    fn mark_transport_failed(
        &self,
        queue_id: &QueueId,
        error_class: &str,
        error_detail: &str,
        transport: &str,
        next_attempt_after: DateTime<Utc>,
    ) -> impl Future<Output = Result<OutboundFailureOutcome, Error>> + Send;

    /// Receiver-visible `replay_detected` reject → `delivered`
    /// (idempotent recovery). When the receiver's replay window
    /// expires before our ACK arrives, the next retry sees a
    /// `replay_detected` rejection at the receiver — the body was
    /// already accepted, so semantically the delivery succeeded.
    fn mark_replay_resolved(
        &self,
        queue_id: &QueueId,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    // ── ACK side ────────────────────────────────────────────────

    /// Look up an `awaiting_ack` row by the receiver's ACK envelope's
    /// `in_reply_to` field (which equals our `body_sha256`). Returns
    /// `None` if no row is in-flight for that hash — possibly because
    /// the ACK landed after the timeout sweep abandoned the row, or
    /// because of a spoofed ACK from a peer whose key isn't a
    /// legitimate destination.
    ///
    /// AV-1 (lookup_public_key gate) is the upstream defence against
    /// spoofed ACKs: persist's verify pipeline rejects ACK envelopes
    /// signed by unknown keys before this method is called. By the
    /// time `match_ack_to_outbound` runs, the ACK envelope's
    /// signature has been verified.
    fn match_ack_to_outbound(
        &self,
        in_reply_to_sha256: &[u8; 32],
    ) -> impl Future<Output = Result<Option<OutboundRow>, Error>> + Send;

    /// Record the receiver's ACK envelope on a matched
    /// `awaiting_ack` row and transition to `delivered`. Stores
    /// `ack_envelope_bytes` + `ack_received_at = now()`.
    fn mark_ack_received(
        &self,
        queue_id: &QueueId,
        ack_envelope_bytes: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    // ── Background sweeps ───────────────────────────────────────

    /// Walk `awaiting_ack` rows whose
    /// `transport_delivered_at + ack_timeout_seconds < now()`. Each
    /// such row gets `mark_transport_failed`-style treatment
    /// (attempt_count++, retry-or-abandon decision, next_attempt_after
    /// scheduled). Returns the count of rows touched.
    fn sweep_ack_timeouts(&self) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Walk rows whose `enqueued_at + ttl_seconds < now()` AND
    /// status is not terminal (delivered/abandoned). Transition to
    /// `abandoned` with `abandoned_reason = 'ttl_expired'`. Returns
    /// the count.
    fn sweep_ttl_expired(&self) -> impl Future<Output = Result<i64, Error>> + Send;

    /// Walk `sending` rows whose `claimed_until < now()` (the
    /// dispatcher worker that claimed them crashed before reporting
    /// transport result). Revert to `pending` for re-claim. Returns
    /// the count.
    fn sweep_expired_claims(&self) -> impl Future<Output = Result<i64, Error>> + Send;

    // ── Inspection (DurableHandle backing) ──────────────────────

    /// Look up a row by `queue_id`. Returns `None` if absent.
    /// Backs `CIRISEdge::DurableHandle::status()`.
    fn outbound_status(
        &self,
        queue_id: &QueueId,
    ) -> impl Future<Output = Result<Option<OutboundRow>, Error>> + Send;

    // ── Operator surface ────────────────────────────────────────

    /// Filter-paginated list of outbound rows. Used for ops
    /// dashboards ("what's queued for peer X / what's stuck in
    /// awaiting_ack / what's been abandoned today").
    fn list_outbound(
        &self,
        filter: OutboundFilter,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<OutboundRow>, Error>> + Send;

    /// Operator-driven cancellation. Transitions a non-terminal row
    /// to `abandoned` with `abandoned_reason = 'operator_cancel'`.
    /// Idempotent: cancelling an already-terminal row is a no-op.
    fn cancel_outbound(&self, queue_id: &QueueId)
        -> impl Future<Output = Result<(), Error>> + Send;

    /// Operator-driven replay of an abandoned row: reset to
    /// `pending`, attempt_count=0, next_attempt_after=now(). For
    /// recovery scenarios (transport was wedged for hours, peer
    /// is back online, want to retry abandoned rows). The caller
    /// is responsible for verifying the row's content + destination
    /// is still appropriate before replaying.
    fn replay_abandoned(
        &self,
        queue_id: &QueueId,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Edge outbound queue errors. Same shape discipline as
/// [`crate::federation::Error`] (typed variants, stable
/// `kind()` tokens).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments (zero-length envelope,
    /// negative max_attempts, requires_ack=true with ack_timeout=None,
    /// etc.). Schema CHECK constraints catch these too; persist
    /// raises this variant before the SQL roundtrip when the gate
    /// is local.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// `queue_id` does not resolve to a row. Idempotent operations
    /// (cancel, mark_replay_resolved) treat this as a no-op rather
    /// than an error; non-idempotent operations
    /// (mark_transport_delivered against a non-claimed row) raise.
    #[error("queue_id not found: {0}")]
    NotFound(String),

    /// State-machine violation — e.g., `mark_ack_received` on a
    /// `pending` row, or `mark_transport_delivered` on a row not in
    /// `sending`. The state-machine invariants are enforced by both
    /// persist (single transaction) and the schema CHECK constraints.
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),

    /// Backend-level error (DB connection, serialization, etc.).
    #[error("backend: {0}")]
    Backend(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidArgument(_) => "outbound_invalid_argument",
            Self::NotFound(_) => "outbound_not_found",
            Self::InvalidTransition(_) => "outbound_invalid_transition",
            Self::Backend(_) => "outbound_backend",
        }
    }
}
