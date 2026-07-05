// This module's whole point is a C-ABI vtable that crosses the
// cdylib boundary. Every safety boundary is documented at the
// call site; the crate-wide #![deny(unsafe_code)] is overridden
// here because there is no other way to implement an FFI ABI.
// Audit-visible: every use of `unsafe` in this file is paired
// with the contract that justifies it. Confined to this module
// so release-wheel reviewers see one diff that owns the surface.
#![allow(unsafe_code)]

//! ABI-stable `OutboundQueue` dispatch capsule (CIRISPersist#320 audit).
//!
//! # Why this exists
//!
//! [`crate::outbound::OutboundQueue`] is a `Send + Sync` trait whose
//! async methods return `-> impl Future + Send` (RPITIT) — it is
//! therefore **NOT object-safe** (`Arc<dyn OutboundQueue>` will not
//! compile). The pre-audit cross-module surface
//! (`PyEngine::outbound_queue_capsule`) hands a consumer wheel
//! (CIRISEdge) a raw [`crate::engine::BackendDispatch`] enum through a
//! `PyCapsule`. The consumer then `match`es the variant and calls
//! `OutboundQueue` methods on the concrete backend struct — dispatching
//! **statically**, against the consumer's *own* compiled view of
//! persist's backend struct layout.
//!
//! That is the same structural hazard as the
//! [`crate::ffi::directory_capsule`] vtable-skew (#320): a Rust type
//! whose in-memory contract is not guaranteed stable across persist
//! versions is passed by-value across the static-vs-wheel boundary.
//! Here it is worse in one dimension — the dispatch is not even through
//! a `dyn` vtable but through the consumer's monomorphized copy of
//! persist's `PostgresBackend` / `SqliteBackend` field layout. When
//! CIRISEdge is built against persist v11.2.0's backend struct and then,
//! at runtime, receives a `BackendDispatch` produced by a v11.7.0
//! persist wheel whose struct fields moved, every field access / method
//! call reinterprets memory at the wrong offset → corruption. Same class
//! as the cross-tokio aliasing at CIRISPersist#156 (fixed by
//! [`crate::ffi::executor_capsule`]) and the libsqlite3 cross-cdylib
//! SIGSEGV at CIRISPersist#141.
//!
//! # The fix
//!
//! Cross the boundary with a **C-ABI vtable** ([`OutboundQueueVTable`])
//! and a **uniform serialized bytes-in / bytes-out** op protocol. The
//! consumer serializes an [`OutboundQueueOp`] (persist-owned,
//! append-only enum), hands the bytes through
//! [`OutboundQueueVTable::build_op`], which runs **inside persist's
//! `.so`**. Persist deserializes the op, matches it to the concrete
//! `OutboundQueue` method, and calls that method **against persist's own
//! compiled backend** — the only layout that is guaranteed to match,
//! because persist built it. Because `OutboundQueue` is not object-safe,
//! the dispatch matches the [`crate::engine::BackendDispatch`] variant
//! and calls the concrete backend's method through a single generic
//! helper ([`dispatch_outbound_op`]) — Postgres and Sqlite behave
//! identically (no backend asymmetry). The result is serialized to an
//! [`OutboundQueueOpResult`] and handed back through a callback.
//!
//! Every method — regardless of heterogeneous argument/return types —
//! flows through the one `bytes -> OutboundQueueOp -> dispatch ->
//! OutboundQueueOpResult -> bytes` path, so there is exactly ONE stable
//! ABI surface to audit, not one per trait method.
//!
//! # Spawn reuse
//!
//! `build_op` does not run the future itself; an `OutboundQueue` call is
//! `async`. It returns a type-erased boxed future
//! ([`crate::ffi::executor_capsule::TaskOpaque`]) that the consumer
//! spawns through the EXISTING [`crate::ffi::executor_capsule`] — so the
//! future is polled by persist's tokio worker pool, and no new
//! runtime/spawn machinery is introduced here. The two capsules compose:
//! `outbound_queue_ops_capsule` builds the op-future; `executor_capsule`
//! spawns it.
//!
//! # The contract the consumer MUST honor
//!
//! Identical to [`crate::ffi::directory_capsule`]:
//!
//! - `result_cb` is invoked **exactly once**, from a persist worker
//!   thread, with a pointer + length to the serialized
//!   [`OutboundQueueOpResult`]. The bytes are valid ONLY during the
//!   callback — the consumer MUST copy them before returning.
//! - `result_ctx` is an opaque consumer pointer passed back verbatim; it
//!   MUST remain valid until `result_cb` fires and be safe to use from
//!   persist's worker thread (`result_cb` + `result_ctx` must be `Send`).
//! - The spawned future obeys the [`crate::ffi::executor_capsule`]
//!   tokio-primitive constraint: it must not touch the consumer crate's
//!   tokio thread-locals. Its only async work is persist's own
//!   `OutboundQueue` methods, which is always correct.
//!
//! # ABI version
//!
//! Consumers MUST verify [`OutboundQueueVTable::abi_version`] equals
//! [`OUTBOUND_QUEUE_ABI_VERSION`] at capsule-receive time. Persist bumps
//! the version on any breaking change to the vtable layout (NOT on
//! append-only [`OutboundQueueOp`] growth — see that type's docs).
//!
//! # Error flattening
//!
//! [`crate::outbound::Error`] is not guaranteed serde-round-trippable,
//! so every method failure is flattened to
//! [`OutboundQueueOpResult::Err`]`(String)` carrying `Error::to_string()`.
//! The consumer maps that back to a generic error on its side.

use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::engine::BackendDispatch;
use crate::outbound::{
    OutboundFailureOutcome, OutboundFilter, OutboundQueue, OutboundRow, QueueId,
};

// Reuse the executor capsule's type-erased future pointer + the boxed
// future shape it already knows how to spawn. The op-future produced
// here is spawned by the consumer through `executor_capsule`, so the
// two must agree on the exact boxed-future type.
use crate::ffi::executor_capsule::TaskOpaque;

/// The boxed-future shape [`crate::ffi::executor_capsule`] spawns. The
/// pointer returned by [`OutboundQueueVTable::build_op`] is a
/// `Box<BoxedFut>` cast to `*mut TaskOpaque`, byte-identical to what the
/// executor capsule's `spawn` reconstructs.
type BoxedFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// ABI version of [`OutboundQueueVTable`]. Bumped on any breaking change
/// to the vtable's layout or function-pointer signatures.
///
/// INDEPENDENT of [`OutboundQueueOp`]'s wire growth: appending a new
/// [`OutboundQueueOp`] variant does NOT bump this, because the vtable
/// signature (`build_op` takes opaque bytes) is unchanged. Consumers
/// MUST check the field at capsule-receive time:
///
/// ```ignore
/// use ciris_persist::ffi::outbound_queue_capsule::{
///     OutboundQueueHandle, OUTBOUND_QUEUE_ABI_VERSION,
/// };
///
/// let handle: OutboundQueueHandle = unsafe { /* read from PyCapsule */ };
/// assert_eq!(
///     handle.vtable.abi_version,
///     OUTBOUND_QUEUE_ABI_VERSION,
///     "persist outbound_queue_ops_capsule ABI version mismatch — pin floor too low"
/// );
/// ```
pub const OUTBOUND_QUEUE_ABI_VERSION: u32 = 1;

/// An [`OutboundQueue`] operation, serialized by the consumer and
/// dispatched inside persist's `.so`.
///
/// # APPEND-ONLY — the ABI depends on it
///
/// Same discipline as [`crate::ffi::directory_capsule::DirectoryOp`]:
/// `serde_json`'s externally-tagged representation keys each variant by
/// NAME, so the strict rule is auditability, not ordinal stability:
///
/// - **New operations MUST be added at the END.** Never insert in the
///   middle, reorder, remove, rename, or change an existing variant's
///   field set/types.
/// - An older consumer never constructs the newer variants; a newer
///   consumer talking to an older wheel that lacks a variant gets a
///   clean deserialize failure → the wheel builds an
///   [`OutboundQueueOpResult::Err`] rather than misdispatching.
///
/// Every argument type here derives `serde::{Serialize, Deserialize}`.
/// One variant per [`OutboundQueue`] trait method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutboundQueueOp {
    /// [`OutboundQueue::enqueue_outbound`].
    EnqueueOutbound {
        /// Sender peer's `federation_keys.key_id`.
        sender_key_id: String,
        /// Destination peer's `federation_keys.key_id`.
        destination_key_id: String,
        /// CIRISEdge MessageType discriminant string.
        message_type: String,
        /// CIRISEdge wire-format version.
        edge_schema_version: String,
        /// Envelope bytes verbatim.
        envelope_bytes: Vec<u8>,
        /// Content hash for ACK matching (32 bytes).
        body_sha256: [u8; 32],
        /// Length in bytes of `envelope_bytes`.
        body_size_bytes: i32,
        /// Whether the message-type policy requires an ACK.
        requires_ack: bool,
        /// ACK timeout (required when `requires_ack`).
        ack_timeout_seconds: Option<i64>,
        /// Maximum transport attempts before abandon.
        max_attempts: i32,
        /// Time-to-live from enqueue.
        ttl_seconds: i64,
        /// Earliest time a dispatcher claim is allowed.
        initial_next_attempt_after: chrono::DateTime<chrono::Utc>,
    },
    /// [`OutboundQueue::claim_pending_outbound`].
    ClaimPendingOutbound {
        /// Max rows to claim.
        batch_size: i64,
        /// Claim lease duration.
        claim_duration_seconds: i64,
        /// Worker identifier taking the claim.
        claimed_by: String,
    },
    /// [`OutboundQueue::mark_transport_delivered`].
    MarkTransportDelivered {
        /// The claimed row's id.
        queue_id: QueueId,
        /// Transport identifier that delivered.
        transport: String,
    },
    /// [`OutboundQueue::mark_transport_failed`].
    MarkTransportFailed {
        /// The claimed row's id.
        queue_id: QueueId,
        /// Transport error class.
        error_class: String,
        /// Transport error detail.
        error_detail: String,
        /// Transport identifier that failed.
        transport: String,
        /// Caller-supplied backoff target for the next attempt.
        next_attempt_after: chrono::DateTime<chrono::Utc>,
    },
    /// [`OutboundQueue::mark_replay_resolved`].
    MarkReplayResolved {
        /// The row whose receiver-side replay reject means delivered.
        queue_id: QueueId,
    },
    /// [`OutboundQueue::match_ack_to_outbound`].
    MatchAckToOutbound {
        /// The ACK envelope's `in_reply_to` (= our `body_sha256`).
        in_reply_to_sha256: [u8; 32],
    },
    /// [`OutboundQueue::mark_ack_received`].
    MarkAckReceived {
        /// The matched `awaiting_ack` row.
        queue_id: QueueId,
        /// Receiver's ACK envelope verbatim.
        ack_envelope_bytes: Vec<u8>,
    },
    /// [`OutboundQueue::sweep_ack_timeouts`].
    SweepAckTimeouts {},
    /// [`OutboundQueue::sweep_ttl_expired`].
    SweepTtlExpired {},
    /// [`OutboundQueue::sweep_expired_claims`].
    SweepExpiredClaims {},
    /// [`OutboundQueue::outbound_status`].
    OutboundStatusOf {
        /// The row to look up.
        queue_id: QueueId,
    },
    /// [`OutboundQueue::list_outbound`].
    ListOutbound {
        /// Filter (all fields optional, combined with AND).
        filter: OutboundFilter,
        /// Page cap.
        limit: i64,
    },
    /// [`OutboundQueue::cancel_outbound`].
    CancelOutbound {
        /// The row to operator-cancel.
        queue_id: QueueId,
    },
    /// [`OutboundQueue::replay_abandoned`].
    ReplayAbandoned {
        /// The abandoned row to reset to `pending`.
        queue_id: QueueId,
    },
}

/// The mirror of each [`OutboundQueueOp`]'s return, plus the flattened
/// error.
///
/// One `Ok*` variant per return SHAPE — identical shapes share a variant
/// (all `()` returns collapse to [`OutboundQueueOpResult::Unit`]; the
/// three `i64`-count sweeps to [`OutboundQueueOpResult::Count`]; the two
/// `Vec<OutboundRow>` returns to [`OutboundQueueOpResult::Rows`]; the two
/// `Option<OutboundRow>` returns to [`OutboundQueueOpResult::MaybeRow`]).
///
/// Same append-only discipline as [`OutboundQueueOp`].
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutboundQueueOpResult {
    /// Any method failure, flattened from `Error::to_string()`. The
    /// structured [`crate::outbound::Error`] does not cross the ABI.
    Err(String),
    /// The `()` returns: `mark_transport_delivered`,
    /// `mark_replay_resolved`, `mark_ack_received`, `cancel_outbound`,
    /// `replay_abandoned`.
    Unit,
    /// `enqueue_outbound`.
    Enqueued(QueueId),
    /// `claim_pending_outbound`, `list_outbound`.
    Rows(Vec<OutboundRow>),
    /// `mark_transport_failed`.
    FailureOutcome(OutboundFailureOutcome),
    /// `match_ack_to_outbound`, `outbound_status`.
    MaybeRow(Option<OutboundRow>),
    /// `sweep_ack_timeouts`, `sweep_ttl_expired`, `sweep_expired_claims`.
    Count(i64),
}

/// Run one [`OutboundQueueOp`] against a concrete backend `q` and wrap
/// the outcome.
///
/// Generic over the concrete backend type `Q: OutboundQueue`. Because
/// `OutboundQueue` is RPITIT / not object-safe, there is no
/// `&dyn OutboundQueue` — [`dispatch_outbound_op`] selects `Q` by
/// matching the [`BackendDispatch`] variant, then calls this ONE body.
/// The body runs INSIDE persist's `.so`, against persist's own compiled
/// backend method — the whole point of the #320 audit. A method `Err(e)`
/// flattens to [`OutboundQueueOpResult::Err`]`(e.to_string())`.
async fn run_outbound_op<Q: OutboundQueue>(q: &Q, op: OutboundQueueOp) -> OutboundQueueOpResult {
    match op {
        OutboundQueueOp::EnqueueOutbound {
            sender_key_id,
            destination_key_id,
            message_type,
            edge_schema_version,
            envelope_bytes,
            body_sha256,
            body_size_bytes,
            requires_ack,
            ack_timeout_seconds,
            max_attempts,
            ttl_seconds,
            initial_next_attempt_after,
        } => match q
            .enqueue_outbound(
                &sender_key_id,
                &destination_key_id,
                &message_type,
                &edge_schema_version,
                &envelope_bytes,
                &body_sha256,
                body_size_bytes,
                requires_ack,
                ack_timeout_seconds,
                max_attempts,
                ttl_seconds,
                initial_next_attempt_after,
            )
            .await
        {
            Ok(id) => OutboundQueueOpResult::Enqueued(id),
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::ClaimPendingOutbound {
            batch_size,
            claim_duration_seconds,
            claimed_by,
        } => match q
            .claim_pending_outbound(batch_size, claim_duration_seconds, &claimed_by)
            .await
        {
            Ok(v) => OutboundQueueOpResult::Rows(v),
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::MarkTransportDelivered {
            queue_id,
            transport,
        } => match q.mark_transport_delivered(&queue_id, &transport).await {
            Ok(()) => OutboundQueueOpResult::Unit,
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::MarkTransportFailed {
            queue_id,
            error_class,
            error_detail,
            transport,
            next_attempt_after,
        } => match q
            .mark_transport_failed(
                &queue_id,
                &error_class,
                &error_detail,
                &transport,
                next_attempt_after,
            )
            .await
        {
            Ok(o) => OutboundQueueOpResult::FailureOutcome(o),
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::MarkReplayResolved { queue_id } => {
            match q.mark_replay_resolved(&queue_id).await {
                Ok(()) => OutboundQueueOpResult::Unit,
                Err(e) => OutboundQueueOpResult::Err(e.to_string()),
            }
        }
        OutboundQueueOp::MatchAckToOutbound { in_reply_to_sha256 } => {
            match q.match_ack_to_outbound(&in_reply_to_sha256).await {
                Ok(v) => OutboundQueueOpResult::MaybeRow(v),
                Err(e) => OutboundQueueOpResult::Err(e.to_string()),
            }
        }
        OutboundQueueOp::MarkAckReceived {
            queue_id,
            ack_envelope_bytes,
        } => match q.mark_ack_received(&queue_id, &ack_envelope_bytes).await {
            Ok(()) => OutboundQueueOpResult::Unit,
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::SweepAckTimeouts {} => match q.sweep_ack_timeouts().await {
            Ok(n) => OutboundQueueOpResult::Count(n),
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::SweepTtlExpired {} => match q.sweep_ttl_expired().await {
            Ok(n) => OutboundQueueOpResult::Count(n),
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::SweepExpiredClaims {} => match q.sweep_expired_claims().await {
            Ok(n) => OutboundQueueOpResult::Count(n),
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::OutboundStatusOf { queue_id } => {
            match q.outbound_status(&queue_id).await {
                Ok(v) => OutboundQueueOpResult::MaybeRow(v),
                Err(e) => OutboundQueueOpResult::Err(e.to_string()),
            }
        }
        OutboundQueueOp::ListOutbound { filter, limit } => {
            match q.list_outbound(filter, limit).await {
                Ok(v) => OutboundQueueOpResult::Rows(v),
                Err(e) => OutboundQueueOpResult::Err(e.to_string()),
            }
        }
        OutboundQueueOp::CancelOutbound { queue_id } => match q.cancel_outbound(&queue_id).await {
            Ok(()) => OutboundQueueOpResult::Unit,
            Err(e) => OutboundQueueOpResult::Err(e.to_string()),
        },
        OutboundQueueOp::ReplayAbandoned { queue_id } => {
            match q.replay_abandoned(&queue_id).await {
                Ok(()) => OutboundQueueOpResult::Unit,
                Err(e) => OutboundQueueOpResult::Err(e.to_string()),
            }
        }
    }
}

/// Run one [`OutboundQueueOp`] against the concrete backend held by
/// `dispatch`.
///
/// Safe Rust — the body that runs INSIDE persist's `.so`. Both backend
/// variants call the SAME generic [`run_outbound_op`], so Postgres and
/// Sqlite behave identically (no backend asymmetry). This is the persist
/// side of the #320-audit fix: the `OutboundQueue` method resolves
/// against persist's own compiled backend, never a consumer's skewed
/// monomorphization.
pub async fn dispatch_outbound_op(
    dispatch: &BackendDispatch,
    op: OutboundQueueOp,
) -> OutboundQueueOpResult {
    match dispatch {
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(b) => run_outbound_op(b.as_ref(), op).await,
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(b) => run_outbound_op(b.as_ref(), op).await,
    }
}

/// C-ABI callback the consumer supplies to receive the serialized
/// [`OutboundQueueOpResult`]. Invoked exactly once, from a persist worker
/// thread. The `(ptr, len)` bytes are valid ONLY during the call.
pub type ResultCallback =
    unsafe extern "C" fn(ctx: *mut c_void, result_ptr: *const u8, result_len: usize);

/// C-ABI function-pointer table for the outbound-queue dispatcher.
///
/// `#[repr(C)]`; safe to stash in a static and hand its address across
/// the cdylib boundary. The function pointers live inside persist's
/// `.so`, so calling them transfers control into persist — where the
/// concrete `OutboundQueue` method dispatch uses persist's own compiled
/// backend.
#[repr(C)]
pub struct OutboundQueueVTable {
    /// ABI version — see [`OUTBOUND_QUEUE_ABI_VERSION`]. Offset 0;
    /// consumers read it via `&'static OutboundQueueVTable`.
    pub abi_version: u32,
    /// Reserved padding for natural 8-byte alignment. MUST be zero in v1.
    pub _reserved: u32,
    /// Deserialize the op from `op_ptr/op_len`, build the boxed
    /// op-future, and return it as a `*mut TaskOpaque` for the consumer
    /// to spawn via [`crate::ffi::executor_capsule`]. The future, when
    /// polled, runs the op against the backend and calls
    /// `result_cb(result_ctx, ...)` once with the serialized
    /// [`OutboundQueueOpResult`].
    ///
    /// On a parse failure the returned future still fires `result_cb`
    /// once — with a serialized [`OutboundQueueOpResult::Err`] — so the
    /// consumer's completion path is uniform.
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by
    ///   [`build_persist_outbound_queue`] for this same vtable (a
    ///   `Box::into_raw`'d `Box<BackendDispatch>`). Mismatched `data`
    ///   ↔ `vtable` pairings are UB.
    /// - `op_ptr` MUST point at `op_len` initialized, readable bytes for
    ///   the duration of this call. They are parsed before the call
    ///   returns; the consumer may free them afterward.
    /// - `result_cb` + `result_ctx` MUST satisfy the module-level
    ///   contract: `result_cb` is called exactly once from a persist
    ///   worker thread, `result_ctx` stays valid until then, and the pair
    ///   is `Send`.
    /// - The returned `*mut TaskOpaque` MUST be spawned exactly once
    ///   through persist's `executor_capsule` (or dropped by
    ///   reconstructing `Box<Pin<Box<dyn Future<Output=()> + Send>>>`);
    ///   any other use is UB.
    pub build_op: unsafe extern "C" fn(
        data: *mut c_void,
        op_ptr: *const u8,
        op_len: usize,
        result_cb: ResultCallback,
        result_ctx: *mut c_void,
    ) -> *mut TaskOpaque,
    /// Drop the handle — drops the inner [`BackendDispatch`] (and its
    /// backend `Arc`). Called by the consumer when the capsule is dropped
    /// (Python GC).
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by
    ///   [`build_persist_outbound_queue`] for this same vtable.
    /// - MUST be called exactly once per capsule. Double-drop is UB.
    pub drop: unsafe extern "C" fn(data: *mut c_void),
}

/// The capsule contents — opaque data pointer + vtable.
///
/// Consumers receive this via a `PyCapsule` whose pointer (after the
/// name-tag check) IS a `*mut OutboundQueueHandle`. Treat the fields as
/// opaque; invoke only through the vtable's function pointers.
#[repr(C)]
pub struct OutboundQueueHandle {
    /// Opaque payload pointer: persist's vtable expects a
    /// `Box::into_raw`'d `Box<BackendDispatch>`. Boxing gives a thin
    /// pointer to the (owned) dispatch enum.
    pub data: *mut c_void,
    /// Reference to a static vtable inside `ciris_persist.abi3.so`.
    pub vtable: &'static OutboundQueueVTable,
}

// SAFETY: `OutboundQueueHandle` is Send+Sync — the underlying
// `BackendDispatch` is `Send + Sync` (an enum of `Arc<Backend>` where
// the backends are `Send + Sync`), and the vtable is a 'static
// reference. Consumers stash the capsule pointer in structures that
// cross threads; marking these makes the expectation explicit, matching
// `Directory` / `AsyncExecutor`.
unsafe impl Send for OutboundQueueHandle {}
unsafe impl Sync for OutboundQueueHandle {}

/// Persist's outbound-queue vtable instance. Address-stable for the
/// process lifetime — this is what a consumer's
/// `OutboundQueueHandle.vtable` targets.
pub static PERSIST_OUTBOUND_QUEUE_VTABLE: OutboundQueueVTable = OutboundQueueVTable {
    abi_version: OUTBOUND_QUEUE_ABI_VERSION,
    _reserved: 0,
    build_op: persist_outbound_build_op,
    drop: persist_outbound_drop,
};

/// Bundles the consumer-supplied completion callback and its opaque
/// context so the pair can be captured into the boxed op-future (which
/// persist spawns onto a worker thread). Marked `Send` because the
/// `build_op` contract requires the consumer's `result_cb` +
/// `result_ctx` pair to be `Send`.
struct SendCompletion {
    cb: ResultCallback,
    ctx: *mut c_void,
}
// SAFETY: the `build_op` contract requires the consumer's
// `result_cb` + `result_ctx` pair to be `Send` (used exactly once from a
// persist worker thread). We hold the fn pointer + the raw ctx and hand
// them back verbatim; we never deref the ctx here.
unsafe impl Send for SendCompletion {}

/// Implementation of [`OutboundQueueVTable::build_op`].
///
/// # Safety
/// See [`OutboundQueueVTable::build_op`]. MUST be invoked only through
/// the vtable function pointer, never directly from outside persist's
/// `.so`.
unsafe extern "C" fn persist_outbound_build_op(
    data: *mut c_void,
    op_ptr: *const u8,
    op_len: usize,
    result_cb: ResultCallback,
    result_ctx: *mut c_void,
) -> *mut TaskOpaque {
    // SAFETY: per the vtable contract, `data` is a `Box::into_raw`'d
    // `Box<BackendDispatch>` owned by the capsule. We borrow it (do NOT
    // reconstruct the Box — that would drop the capsule's owned value)
    // and clone the enum, which clones the inner backend `Arc` (bumping
    // its refcount). The clone is ours to move into the future; the
    // capsule keeps its own, freed later by `persist_outbound_drop`.
    let dispatch: BackendDispatch = unsafe {
        let boxed_ref: &BackendDispatch = &*(data as *const BackendDispatch);
        boxed_ref.clone()
    };

    // SAFETY: per the vtable contract, `op_ptr`/`op_len` name `op_len`
    // readable, initialized bytes valid for the duration of this call.
    // `serde_json::from_slice` reads them synchronously here; nothing
    // retains the borrow past this function.
    let op_bytes: &[u8] = unsafe { std::slice::from_raw_parts(op_ptr, op_len) };
    let parsed: Result<OutboundQueueOp, String> =
        serde_json::from_slice::<OutboundQueueOp>(op_bytes).map_err(|e| e.to_string());

    // Capture the consumer callback + context in a Send bundle so the
    // future (spawned onto persist's worker pool) may hold it.
    let completion = SendCompletion {
        cb: result_cb,
        ctx: result_ctx,
    };

    let fut: BoxedFut = Box::pin(async move {
        // Keep the cloned dispatch + completion bundle alive across the
        // await (owned, moved into the future — never the raw ptr).
        let dispatch = dispatch;
        let completion = completion;
        let result: OutboundQueueOpResult = match parsed {
            Ok(op) => dispatch_outbound_op(&dispatch, op).await,
            Err(msg) => OutboundQueueOpResult::Err(format!("outbound op parse failure: {msg}")),
        };
        // Serialization of `OutboundQueueOpResult` cannot realistically
        // fail (owned data, no non-string map keys). If it somehow did,
        // fall back to a serialized Err so the consumer's completion path
        // still fires with well-formed bytes.
        let bytes = serde_json::to_vec(&result).unwrap_or_else(|e| {
            serde_json::to_vec(&OutboundQueueOpResult::Err(format!(
                "outbound op result serialize failure: {e}"
            )))
            .expect("Err(String) serialization is infallible")
        });
        // SAFETY: `completion.cb` + `completion.ctx` (= the consumer's
        // `result_cb`/`result_ctx`) satisfy the vtable contract: valid,
        // Send, called exactly once from this worker thread. `bytes`
        // outlives the synchronous call (dropped only after the callback
        // returns); the consumer copies before returning.
        unsafe {
            (completion.cb)(completion.ctx, bytes.as_ptr(), bytes.len());
        }
    });

    // Double-box to a thin pointer, byte-identical to the shape
    // `executor_capsule::persist_spawn` reconstructs.
    let wrapped: Box<BoxedFut> = Box::new(fut);
    Box::into_raw(wrapped) as *mut TaskOpaque
}

/// Implementation of [`OutboundQueueVTable::drop`].
///
/// # Safety
/// See [`OutboundQueueVTable::drop`]. Single-drop only; double-drop is
/// UB.
unsafe extern "C" fn persist_outbound_drop(data: *mut c_void) {
    // SAFETY: per the vtable contract, `data` was produced by
    // `Box::into_raw(Box::new(dispatch))` in
    // `build_persist_outbound_queue`. Reconstruct the Box to drop it (and
    // the inner backend Arc).
    let _boxed: Box<BackendDispatch> = unsafe { Box::from_raw(data as *mut BackendDispatch) };
    // Drop runs here; if this was the last Arc, the backend refcount
    // decrements on the persist side.
}

/// Construct an [`OutboundQueueHandle`] backed by `dispatch`. The
/// returned value is what `outbound_queue_ops_capsule` wraps in a
/// `PyCapsule`.
///
/// The [`BackendDispatch`] is boxed (`Box<BackendDispatch>`) to obtain a
/// thin `*mut c_void` payload; the vtable's `build_op`/`drop` interpret
/// `data` accordingly.
pub fn build_persist_outbound_queue(dispatch: BackendDispatch) -> OutboundQueueHandle {
    let boxed: Box<BackendDispatch> = Box::new(dispatch);
    OutboundQueueHandle {
        data: Box::into_raw(boxed) as *mut c_void,
        vtable: &PERSIST_OUTBOUND_QUEUE_VTABLE,
    }
}

/// Build a `PyCapsule` wrapping a fresh [`OutboundQueueHandle`] backed by
/// `dispatch`, with a destructor that calls the vtable's `drop` at GC
/// time (CIRISPersist#320 audit).
///
/// Confined to this module because the FFI capsule construction needs
/// `unsafe` for `PyCapsule::new_with_value_and_destructor` — the same
/// `#![deny(unsafe_code)]`-override rationale as
/// [`crate::ffi::directory_capsule::build_capsule_with_destructor`].
///
/// The capsule payload pointer is a `Box::into_raw`'d
/// `Box<OutboundQueueHandle>`. The destructor reconstructs the box and
/// invokes `vtable.drop(data)` before deallocating the envelope.
#[cfg(feature = "_pyffi")]
pub fn build_capsule_with_destructor<'py>(
    py: pyo3::Python<'py>,
    dispatch: BackendDispatch,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyCapsule>> {
    use pyo3::types::PyCapsule;
    let handle = build_persist_outbound_queue(dispatch);
    let boxed_handle: Box<OutboundQueueHandle> = Box::new(handle);
    let raw: *mut OutboundQueueHandle = Box::into_raw(boxed_handle);
    // SAFETY: `raw` was just produced by `Box::into_raw`; PyCapsule calls
    // the destructor exactly once at GC. The destructor reconstructs the
    // Box (recovering ownership) before invoking `vtable.drop` on the
    // inner data pointer.
    unsafe {
        PyCapsule::new_with_value_and_destructor(
            py,
            raw as usize,
            c"ciris_persist::outbound_queue_ops_v1",
            |raw_usize, _ctx| {
                let raw_ptr = raw_usize as *mut OutboundQueueHandle;
                if raw_ptr.is_null() {
                    return;
                }
                // SAFETY: `raw_ptr` is the pointer we `Box::into_raw`'d;
                // the only path into this destructor is PyCapsule's
                // single-fire GC.
                let handle: Box<OutboundQueueHandle> = Box::from_raw(raw_ptr);
                (handle.vtable.drop)(handle.data);
                // Box deallocates the OutboundQueueHandle envelope here.
            },
        )
    }
}

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod tests {
    use super::*;
    use crate::federation::types::{algorithm, identity_type, KeyRecord};
    use crate::federation::{FederationDirectory, SignedKeyRecord};
    use crate::store::backend::Backend;
    use crate::store::sqlite::SqliteBackend;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use std::sync::mpsc;
    use std::sync::Arc;

    // ── shared helpers ─────────────────────────────────────────────

    /// A minimal-but-valid `SignedKeyRecord` — the sqlite `put_public_key`
    /// admission gate requires a real 32-byte Ed25519 pubkey + `hybrid`
    /// algorithm, but does NOT verify a signature, so a deterministic seed
    /// suffices to satisfy the `edge_outbound_queue` FK on
    /// `federation_keys(key_id)`.
    fn valid_key_record(key_id: &str, seed: u8) -> SignedKeyRecord {
        let vk = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        let now = chrono::Utc::now();
        SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.into(),
                pubkey_ed25519_base64: B64.encode(vk.to_bytes()),
                pubkey_ml_dsa_65_base64: None,
                algorithm: algorithm::HYBRID.into(),
                identity_type: identity_type::PRIMITIVE.into(),
                identity_ref: key_id.into(),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": key_id }),
                original_content_hash: "deadbeef".into(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.into(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        }
    }

    async fn sqlite_dispatch() -> BackendDispatch {
        let backend = SqliteBackend::open_in_memory()
            .await
            .expect("open in-memory sqlite");
        backend
            .run_migrations()
            .await
            .expect("run migrations (creates edge_outbound_queue)");
        // Seed the sender + destination federation_keys rows the outbound
        // FK references (real backends enforce it; SQLite has FKs ON).
        backend
            .put_public_key(valid_key_record("sender-1", 1))
            .await
            .expect("register sender key");
        backend
            .put_public_key(valid_key_record("dest-1", 2))
            .await
            .expect("register destination key");
        BackendDispatch::Sqlite(Arc::new(backend))
    }

    fn test_runtime() -> Arc<tokio::runtime::Runtime> {
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build tokio runtime"),
        )
    }

    /// Drive one op through the C-ABI against a runtime Arc (the shape
    /// the executor capsule consumes).
    fn run_op(
        rt: &Arc<tokio::runtime::Runtime>,
        handle: &OutboundQueueHandle,
        op: &OutboundQueueOp,
    ) -> OutboundQueueOpResult {
        let op_bytes = serde_json::to_vec(op).expect("serialize op");
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let boxed_tx: Box<mpsc::Sender<Vec<u8>>> = Box::new(tx);
        let ctx: *mut c_void = Box::into_raw(boxed_tx) as *mut c_void;

        unsafe extern "C" fn cb(ctx: *mut c_void, ptr: *const u8, len: usize) {
            // SAFETY: single-fire boxed Sender; readable (ptr,len) for the call.
            let tx: Box<mpsc::Sender<Vec<u8>>> =
                unsafe { Box::from_raw(ctx as *mut mpsc::Sender<Vec<u8>>) };
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            let _ = tx.send(bytes);
        }

        // SAFETY: matched data/vtable; readable op bytes; Send valid ctx/cb.
        let task_ptr = unsafe {
            (handle.vtable.build_op)(handle.data, op_bytes.as_ptr(), op_bytes.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("op result must arrive");
        // SAFETY: single-drop, matched vtable.
        unsafe { (executor.vtable.drop)(executor.data) };
        serde_json::from_slice(&bytes).expect("deserialize OutboundQueueOpResult")
    }

    #[test]
    fn abi_version_pinned_at_1() {
        assert_eq!(OUTBOUND_QUEUE_ABI_VERSION, 1);
        assert_eq!(PERSIST_OUTBOUND_QUEUE_VTABLE.abi_version, 1);
    }

    #[test]
    fn vtable_abi_version_at_offset_zero() {
        // Consumers read `vtable.abi_version` via
        // `&'static OutboundQueueVTable`, so the field MUST be at offset 0.
        let v = &PERSIST_OUTBOUND_QUEUE_VTABLE;
        let base = v as *const _ as usize;
        let version_field = &v.abi_version as *const _ as usize;
        assert_eq!(version_field, base, "abi_version must be at offset 0");
    }

    #[test]
    fn enqueue_then_status_round_trips() {
        let rt = test_runtime();
        let dispatch = rt.block_on(sqlite_dispatch());
        let handle = build_persist_outbound_queue(dispatch.clone());

        let now = chrono::Utc::now();
        let enqueue = OutboundQueueOp::EnqueueOutbound {
            sender_key_id: "sender-1".into(),
            destination_key_id: "dest-1".into(),
            message_type: "AttestationGossip".into(),
            edge_schema_version: "1.0.0".into(),
            envelope_bytes: b"hello".to_vec(),
            body_sha256: [7u8; 32],
            body_size_bytes: 5,
            requires_ack: false,
            ack_timeout_seconds: None,
            max_attempts: 3,
            ttl_seconds: 3600,
            initial_next_attempt_after: now,
        };
        let queue_id = match run_op(&rt, &handle, &enqueue) {
            OutboundQueueOpResult::Enqueued(id) => id,
            other => panic!("expected Enqueued, got {other:?}"),
        };

        // OutboundStatusOf via the capsule → MaybeRow(Some(row)).
        let looked = run_op(
            &rt,
            &handle,
            &OutboundQueueOp::OutboundStatusOf {
                queue_id: queue_id.clone(),
            },
        );
        let via_capsule = match looked {
            OutboundQueueOpResult::MaybeRow(v) => v,
            other => panic!("expected MaybeRow, got {other:?}"),
        };

        // Assert it matches calling the method directly on the backend.
        let via_direct = rt
            .block_on(dispatch_direct_status(&dispatch, &queue_id))
            .expect("direct status");
        assert_eq!(
            via_capsule, via_direct,
            "capsule result must equal direct call"
        );
        let row = via_capsule.expect("row present");
        assert_eq!(row.queue_id, queue_id);
        assert_eq!(row.envelope_bytes, b"hello");
        assert_eq!(row.body_sha256, [7u8; 32]);

        // SAFETY: single-drop, matched vtable.
        unsafe { (handle.vtable.drop)(handle.data) };
    }

    /// Direct `outbound_status` on the concrete backend — the ground
    /// truth the capsule round-trip is compared against.
    async fn dispatch_direct_status(
        dispatch: &BackendDispatch,
        queue_id: &QueueId,
    ) -> Result<Option<OutboundRow>, crate::outbound::Error> {
        match dispatch {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.outbound_status(queue_id).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.outbound_status(queue_id).await,
        }
    }

    #[test]
    fn unknown_queue_id_flattens_to_err_variant() {
        // mark_transport_delivered on a non-existent/non-claimed row
        // errors on both backends; proves the Err(String) flattening
        // path across the ABI.
        let rt = test_runtime();
        let dispatch = rt.block_on(sqlite_dispatch());
        let handle = build_persist_outbound_queue(dispatch.clone());

        let res = run_op(
            &rt,
            &handle,
            &OutboundQueueOp::MarkTransportDelivered {
                queue_id: "no-such-queue-id".into(),
                transport: "mock".into(),
            },
        );
        assert!(
            matches!(res, OutboundQueueOpResult::Err(_)),
            "unknown queue_id ⇒ Err(String), got {res:?}"
        );

        // SAFETY: single-drop, matched vtable.
        unsafe { (handle.vtable.drop)(handle.data) };
    }

    #[test]
    fn malformed_op_bytes_fire_err_callback() {
        // A parse failure must STILL fire the callback with a serialized
        // Err (uniform completion path), never leak the future.
        let rt = test_runtime();
        let dispatch = rt.block_on(sqlite_dispatch());
        let handle = build_persist_outbound_queue(dispatch);

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let ctx: *mut c_void = Box::into_raw(Box::new(tx)) as *mut c_void;
        unsafe extern "C" fn cb(ctx: *mut c_void, ptr: *const u8, len: usize) {
            // SAFETY: single-fire boxed Sender; readable (ptr,len).
            let tx: Box<mpsc::Sender<Vec<u8>>> =
                unsafe { Box::from_raw(ctx as *mut mpsc::Sender<Vec<u8>>) };
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            let _ = tx.send(bytes);
        }
        let garbage = b"{not valid json";
        // SAFETY: matched data/vtable; readable bytes; Send valid ctx/cb.
        let task_ptr = unsafe {
            (handle.vtable.build_op)(handle.data, garbage.as_ptr(), garbage.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("parse-failure callback must still fire");
        let res: OutboundQueueOpResult = serde_json::from_slice(&bytes).expect("deserialize");
        assert!(matches!(res, OutboundQueueOpResult::Err(_)), "got {res:?}");

        // SAFETY: single-drop, matched vtables.
        unsafe { (executor.vtable.drop)(executor.data) };
        unsafe { (handle.vtable.drop)(handle.data) };
    }
}
