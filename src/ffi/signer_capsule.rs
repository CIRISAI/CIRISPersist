// This module's whole point is a C-ABI vtable that crosses the
// cdylib boundary. Every safety boundary is documented at the
// call site; the crate-wide #![deny(unsafe_code)] is overridden
// here because there is no other way to implement an FFI ABI.
// Audit-visible: every use of `unsafe` in this file is paired
// with the contract that justifies it. Confined to this module
// so release-wheel reviewers see one diff that owns the surface.
#![allow(unsafe_code)]

//! ABI-stable keyring-signer dispatch capsule — **SECURITY-CRITICAL**
//! (CIRISPersist#320 audit).
//!
//! # Why this exists — and why it is the highest-stakes capsule
//!
//! [`crate::signing::KeyringSignerHandle`] carries raw trait objects:
//! `signer: Arc<dyn ciris_keyring::HardwareSigner>` and
//! `pqc_signer: Option<Arc<dyn ciris_keyring::PqcSigner>>`. The pre-audit
//! cross-module surface (`PyEngine::keyring_signer_capsule`) hands a
//! consumer wheel (CIRISEdge) these `Arc<dyn …>` values by-value through
//! a `PyCapsule`. The consumer then calls `.sign(...)` / `.public_key()`
//! on them.
//!
//! **A `dyn Trait` vtable is not ABI-stable.** Rust guarantees no stable
//! slot order for a trait object's method pointers across compiler
//! versions, crate versions, or builds. When CIRISEdge is compiled
//! against persist v11.2.0's view of `HardwareSigner` and at runtime
//! receives an `Arc<dyn HardwareSigner>` produced by a v11.7.0 persist
//! wheel, the consumer computes the slot index for `sign` using **its
//! own** statically-resolved vtable layout — but the fat pointer targets
//! the wheel's vtable, whose slot at that index may be an entirely
//! different method (e.g. `attestation`, `generate_key`, or
//! `public_key`).
//!
//! For the directory capsule (#320) that class produced a hang. **Here
//! the failure mode is worse: a misdispatch signs.** If the `sign` slot
//! index resolves to a different signing method — or, across the classical
//! (`HardwareSigner`) vs PQC (`PqcSigner`) trait boundary, to the wrong
//! signer entirely — the process emits a signature computed over the
//! wrong input, with the wrong key, or under the wrong algorithm
//! (Ed25519 where ML-DSA-65 was intended, or vice versa). That is a
//! silent forged-signature / key-confusion bug: bytes that verify as a
//! valid CIRIS signature but were never authorized as such. Same
//! structural class as the cross-tokio aliasing at CIRISPersist#156 and
//! the libsqlite3 cross-cdylib SIGSEGV at CIRISPersist#141 — but with
//! cryptographic-integrity stakes.
//!
//! # The fix
//!
//! Cross the boundary with a **C-ABI vtable** ([`SignerVTable`]) and a
//! **uniform serialized bytes-in / bytes-out** op protocol. The consumer
//! serializes a [`SignerOp`] (persist-owned, append-only enum), hands the
//! bytes through [`SignerVTable::build_op`], which runs **inside persist's
//! `.so`**. Persist deserializes the op and calls the concrete
//! `HardwareSigner`/`PqcSigner` method **using persist's own compiled
//! vtable** — the only vtable guaranteed to match the trait object's
//! layout, because persist built both. Crucially, persist's own code
//! statically resolves `Sign` → `HardwareSigner::sign` and `PqcSign` →
//! `PqcSigner::sign`, so the classical-vs-PQC and method-slot selection
//! can never be skewed by a consumer's stale layout. The result — raw
//! signature / public-key **bytes** — is serialized to a
//! [`SignerOpResult`] and handed back through a callback.
//!
//! Results are raw `Vec<u8>` — persist does NOT round-trip
//! `ciris_crypto` signature/pubkey types across the ABI. The consumer
//! receives the exact signature or public-key bytes the underlying signer
//! produced, byte-identical to a direct in-`.so` call.
//!
//! # Spawn reuse
//!
//! `build_op` does not run the future itself; a signer call is `async`
//! (HSM I/O on hardware paths). It returns a type-erased boxed future
//! ([`crate::ffi::executor_capsule::TaskOpaque`]) that the consumer
//! spawns through the EXISTING [`crate::ffi::executor_capsule`] — polled
//! by persist's tokio worker pool. The two capsules compose:
//! `signer_ops_capsule` builds the op-future; `executor_capsule` spawns
//! it.
//!
//! # The contract the consumer MUST honor
//!
//! Identical to [`crate::ffi::directory_capsule`]:
//!
//! - `result_cb` is invoked **exactly once**, from a persist worker
//!   thread, with a pointer + length to the serialized [`SignerOpResult`].
//!   The bytes are valid ONLY during the callback — copy before
//!   returning.
//! - `result_ctx` is an opaque consumer pointer passed back verbatim; it
//!   MUST remain valid until `result_cb` fires and be safe to use from
//!   persist's worker thread (`result_cb` + `result_ctx` must be `Send`).
//! - The spawned future obeys the [`crate::ffi::executor_capsule`]
//!   tokio-primitive constraint: it must not touch the consumer crate's
//!   tokio thread-locals. Its only async work is persist's own signer
//!   methods, which is always correct.
//!
//! # ABI version
//!
//! Consumers MUST verify [`SignerVTable::abi_version`] equals
//! [`SIGNER_ABI_VERSION`] at capsule-receive time. Persist bumps the
//! version on any breaking change to the vtable layout (NOT on
//! append-only [`SignerOp`] growth — see that type's docs).
//!
//! # Error flattening
//!
//! `ciris_keyring::KeyringError` is not guaranteed serde-round-trippable,
//! so every signer failure is flattened to [`SignerOpResult::Err`]`(String)`
//! carrying the error string. Absence of a PQC signer is NOT an error: it
//! is represented as `Ok(None)` inside the PQC result variants (see
//! [`SignerOp::PqcSign`] / [`SignerOp::PqcPublicKey`]).

use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::signing::KeyringSignerHandle;
use ciris_keyring::{HardwareSigner, PqcSigner};

// Reuse the executor capsule's type-erased future pointer + the boxed
// future shape it already knows how to spawn.
use crate::ffi::executor_capsule::TaskOpaque;

/// The boxed-future shape [`crate::ffi::executor_capsule`] spawns. The
/// pointer returned by [`SignerVTable::build_op`] is a `Box<BoxedFut>`
/// cast to `*mut TaskOpaque`, byte-identical to what the executor
/// capsule's `spawn` reconstructs.
type BoxedFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// ABI version of [`SignerVTable`]. Bumped on any breaking change to the
/// vtable's layout or function-pointer signatures.
///
/// INDEPENDENT of [`SignerOp`]'s wire growth: appending a new
/// [`SignerOp`] variant does NOT bump this. Consumers MUST check the
/// field at capsule-receive time:
///
/// ```ignore
/// use ciris_persist::ffi::signer_capsule::{Signer, SIGNER_ABI_VERSION};
///
/// let signer: Signer = unsafe { /* read from PyCapsule */ };
/// assert_eq!(
///     signer.vtable.abi_version,
///     SIGNER_ABI_VERSION,
///     "persist signer_ops_capsule ABI version mismatch — pin floor too low"
/// );
/// ```
pub const SIGNER_ABI_VERSION: u32 = 1;

/// A keyring-signer operation, serialized by the consumer and dispatched
/// inside persist's `.so`.
///
/// # APPEND-ONLY — the ABI depends on it
///
/// Same discipline as [`crate::ffi::directory_capsule::DirectoryOp`]:
///
/// - **New operations MUST be added at the END.** Never insert in the
///   middle, reorder, remove, rename, or change an existing variant's
///   field set/types.
/// - An older consumer never constructs the newer variants; a newer
///   consumer talking to an older wheel that lacks a variant gets a clean
///   deserialize failure → the wheel builds a [`SignerOpResult::Err`]
///   rather than misdispatching.
///
/// The op NAME selects the signer + method **inside persist's `.so`**,
/// where the classical-vs-PQC selection and the method-slot resolution
/// are persist's own — never a consumer's skewed vtable layout. This is
/// the property that makes wrong-algorithm signing impossible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignerOp {
    /// Classical Ed25519 sign: `signer.sign(data).await`. Result:
    /// [`SignerOpResult::Signature`] (64-byte Ed25519 signature bytes).
    Sign {
        /// The bytes to sign.
        data: Vec<u8>,
    },
    /// PQC ML-DSA-65 sign: `pqc_signer.sign(data).await`. Result:
    /// [`SignerOpResult::MaybeSignature`] — `Some(sig)` (3309-byte
    /// ML-DSA-65 signature bytes) when a PQC signer is configured, `None`
    /// when it is absent.
    PqcSign {
        /// The bytes to sign.
        data: Vec<u8>,
    },
    /// Classical public key: `signer.public_key().await`. Result:
    /// [`SignerOpResult::PublicKey`] (32-byte Ed25519 public key bytes).
    PublicKey {},
    /// PQC public key: `pqc_signer.public_key().await`. Result:
    /// [`SignerOpResult::MaybePublicKey`] — `Some(pk)` (1952-byte
    /// ML-DSA-65 public key bytes) when configured, `None` when absent.
    PqcPublicKey {},
    /// The signer's stable key id. Result: [`SignerOpResult::KeyId`].
    KeyId {},
}

/// The mirror of each [`SignerOp`]'s return, plus the flattened error.
///
/// Results are raw bytes — persist does NOT round-trip `ciris_crypto`
/// signature/pubkey types across the ABI. Same append-only discipline as
/// [`SignerOp`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignerOpResult {
    /// Any signer failure, flattened from the keyring error string. The
    /// structured `ciris_keyring::KeyringError` does not cross the ABI.
    Err(String),
    /// `Sign` — classical Ed25519 signature bytes.
    Signature(Vec<u8>),
    /// `PqcSign` — ML-DSA-65 signature bytes, or `None` if the host has
    /// no PQC signer configured (NOT an error).
    MaybeSignature(Option<Vec<u8>>),
    /// `PublicKey` — classical Ed25519 public key bytes.
    PublicKey(Vec<u8>),
    /// `PqcPublicKey` — ML-DSA-65 public key bytes, or `None` if the host
    /// has no PQC signer configured (NOT an error).
    MaybePublicKey(Option<Vec<u8>>),
    /// `KeyId` — the signer's stable identifier.
    KeyId(String),
}

/// Run one [`SignerOp`] against `handle` and wrap the outcome.
///
/// Safe Rust — the body that runs INSIDE persist's `.so`, so every
/// `handle.signer.sign(...)` / `handle.pqc_signer.…` call resolves
/// through persist's own compiled `HardwareSigner`/`PqcSigner` vtable
/// (the whole point of the #320 audit). Because persist's own code
/// statically maps each op variant to the exact trait method, the
/// classical-vs-PQC signer and the method slot can never be confused by a
/// consumer's stale layout. A method `Err(e)` flattens to
/// [`SignerOpResult::Err`]; an absent PQC signer flattens to `Ok(None)`.
pub async fn dispatch_signer_op(handle: &KeyringSignerHandle, op: SignerOp) -> SignerOpResult {
    match op {
        SignerOp::Sign { data } => match handle.signer.sign(&data).await {
            Ok(sig) => SignerOpResult::Signature(sig),
            Err(e) => SignerOpResult::Err(e.to_string()),
        },
        SignerOp::PqcSign { data } => match handle.pqc_signer.as_ref() {
            Some(pqc) => match pqc.sign(&data).await {
                Ok(sig) => SignerOpResult::MaybeSignature(Some(sig)),
                Err(e) => SignerOpResult::Err(e.to_string()),
            },
            None => SignerOpResult::MaybeSignature(None),
        },
        SignerOp::PublicKey {} => match handle.signer.public_key().await {
            Ok(pk) => SignerOpResult::PublicKey(pk),
            Err(e) => SignerOpResult::Err(e.to_string()),
        },
        SignerOp::PqcPublicKey {} => match handle.pqc_signer.as_ref() {
            Some(pqc) => match pqc.public_key().await {
                Ok(pk) => SignerOpResult::MaybePublicKey(Some(pk)),
                Err(e) => SignerOpResult::Err(e.to_string()),
            },
            None => SignerOpResult::MaybePublicKey(None),
        },
        SignerOp::KeyId {} => SignerOpResult::KeyId(handle.key_id.clone()),
    }
}

/// C-ABI callback the consumer supplies to receive the serialized
/// [`SignerOpResult`]. Invoked exactly once, from a persist worker
/// thread. The `(ptr, len)` bytes are valid ONLY during the call.
pub type ResultCallback =
    unsafe extern "C" fn(ctx: *mut c_void, result_ptr: *const u8, result_len: usize);

/// C-ABI function-pointer table for the keyring-signer dispatcher.
///
/// `#[repr(C)]`; safe to stash in a static and hand its address across
/// the cdylib boundary. The function pointers live inside persist's
/// `.so`, so calling them transfers control into persist — where the
/// concrete signer method dispatch uses persist's own (matching) vtable.
#[repr(C)]
pub struct SignerVTable {
    /// ABI version — see [`SIGNER_ABI_VERSION`]. Offset 0; consumers read
    /// it via `&'static SignerVTable`.
    pub abi_version: u32,
    /// Reserved padding for natural 8-byte alignment. MUST be zero in v1.
    pub _reserved: u32,
    /// Deserialize the op from `op_ptr/op_len`, build the boxed op-future,
    /// and return it as a `*mut TaskOpaque` for the consumer to spawn via
    /// [`crate::ffi::executor_capsule`]. The future, when polled, runs the
    /// signer op and calls `result_cb(result_ctx, ...)` once with the
    /// serialized [`SignerOpResult`].
    ///
    /// On a parse failure the returned future still fires `result_cb`
    /// once — with a serialized [`SignerOpResult::Err`] — so the
    /// consumer's completion path is uniform.
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by
    ///   [`build_persist_signer`] for this same vtable (a
    ///   `Box::into_raw`'d `Box<KeyringSignerHandle>`). Mismatched `data`
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
    /// Drop the signer handle — drops the inner `Arc<dyn HardwareSigner>`
    /// (and the optional `Arc<dyn PqcSigner>`). Called by the consumer
    /// when the capsule is dropped (Python GC).
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by
    ///   [`build_persist_signer`] for this same vtable.
    /// - MUST be called exactly once per capsule. Double-drop is UB.
    pub drop: unsafe extern "C" fn(data: *mut c_void),
}

/// The capsule contents — opaque data pointer + vtable.
///
/// Consumers receive this via a `PyCapsule` whose pointer (after the
/// name-tag check) IS a `*mut Signer`. Treat the fields as opaque; invoke
/// only through the vtable's function pointers.
#[repr(C)]
pub struct Signer {
    /// Opaque payload pointer: persist's vtable expects a
    /// `Box::into_raw`'d `Box<KeyringSignerHandle>`. Boxing the handle
    /// gives a thin `*mut c_void` to the struct (whose `Arc<dyn …>`
    /// fields are themselves fat pointers).
    pub data: *mut c_void,
    /// Reference to a static vtable inside `ciris_persist.abi3.so`.
    pub vtable: &'static SignerVTable,
}

// SAFETY: `Signer` is Send+Sync — the underlying `KeyringSignerHandle`
// holds `Arc<dyn HardwareSigner>` / `Arc<dyn PqcSigner>`, both traits
// `Send + Sync`, so the Arcs are `Send + Sync`; the vtable is a 'static
// reference. Consumers stash the capsule pointer in structures that cross
// threads; marking these makes the expectation explicit, matching
// `Directory` / `AsyncExecutor`.
unsafe impl Send for Signer {}
unsafe impl Sync for Signer {}

/// Persist's signer vtable instance. Address-stable for the process
/// lifetime — this is what a consumer's `Signer.vtable` targets.
pub static PERSIST_SIGNER_VTABLE: SignerVTable = SignerVTable {
    abi_version: SIGNER_ABI_VERSION,
    _reserved: 0,
    build_op: persist_signer_build_op,
    drop: persist_signer_drop,
};

/// Bundles the consumer-supplied completion callback and its opaque
/// context so the pair can be captured into the boxed op-future. Marked
/// `Send` because the `build_op` contract requires the consumer's
/// `result_cb` + `result_ctx` pair to be `Send`.
struct SendCompletion {
    cb: ResultCallback,
    ctx: *mut c_void,
}
// SAFETY: the `build_op` contract requires the consumer's
// `result_cb` + `result_ctx` pair to be `Send` (used exactly once from a
// persist worker thread). We hold the fn pointer + the raw ctx and hand
// them back verbatim; we never deref the ctx here.
unsafe impl Send for SendCompletion {}

/// Implementation of [`SignerVTable::build_op`].
///
/// # Safety
/// See [`SignerVTable::build_op`]. MUST be invoked only through the vtable
/// function pointer, never directly from outside persist's `.so`.
unsafe extern "C" fn persist_signer_build_op(
    data: *mut c_void,
    op_ptr: *const u8,
    op_len: usize,
    result_cb: ResultCallback,
    result_ctx: *mut c_void,
) -> *mut TaskOpaque {
    // SAFETY: per the vtable contract, `data` is a `Box::into_raw`'d
    // `Box<KeyringSignerHandle>` owned by the capsule. We borrow it (do
    // NOT reconstruct the Box — that would drop the capsule's owned
    // value) and clone the signer `Arc`s + key_id into a fresh owned
    // handle, bumping the Arc refcounts. The clone is ours to move into
    // the future; the capsule keeps its own, freed later by
    // `persist_signer_drop`.
    let handle: KeyringSignerHandle = unsafe {
        let borrowed: &KeyringSignerHandle = &*(data as *const KeyringSignerHandle);
        let signer: Arc<dyn HardwareSigner> = borrowed.signer.clone();
        let pqc_signer: Option<Arc<dyn PqcSigner>> = borrowed.pqc_signer.clone();
        let key_id: String = borrowed.key_id.clone();
        KeyringSignerHandle {
            signer,
            pqc_signer,
            key_id,
        }
    };

    // SAFETY: per the vtable contract, `op_ptr`/`op_len` name `op_len`
    // readable, initialized bytes valid for the duration of this call.
    // `serde_json::from_slice` reads them synchronously here; nothing
    // retains the borrow past this function.
    let op_bytes: &[u8] = unsafe { std::slice::from_raw_parts(op_ptr, op_len) };
    let parsed: Result<SignerOp, String> =
        serde_json::from_slice::<SignerOp>(op_bytes).map_err(|e| e.to_string());

    // Capture the consumer callback + context in a Send bundle so the
    // future (spawned onto persist's worker pool) may hold it.
    let completion = SendCompletion {
        cb: result_cb,
        ctx: result_ctx,
    };

    let fut: BoxedFut = Box::pin(async move {
        // Keep the cloned handle + completion bundle alive across the
        // await (owned, moved into the future — never the raw ptr).
        let handle = handle;
        let completion = completion;
        let result: SignerOpResult = match parsed {
            Ok(op) => dispatch_signer_op(&handle, op).await,
            Err(msg) => SignerOpResult::Err(format!("signer op parse failure: {msg}")),
        };
        // Serialization of `SignerOpResult` cannot realistically fail
        // (owned bytes/strings). If it somehow did, fall back to a
        // serialized Err so the consumer's completion path still fires
        // with well-formed bytes.
        let bytes = serde_json::to_vec(&result).unwrap_or_else(|e| {
            serde_json::to_vec(&SignerOpResult::Err(format!(
                "signer op result serialize failure: {e}"
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

/// Implementation of [`SignerVTable::drop`].
///
/// # Safety
/// See [`SignerVTable::drop`]. Single-drop only; double-drop is UB.
unsafe extern "C" fn persist_signer_drop(data: *mut c_void) {
    // SAFETY: per the vtable contract, `data` was produced by
    // `Box::into_raw(Box::new(handle))` in `build_persist_signer`.
    // Reconstruct the Box to drop it (and the inner signer Arcs).
    let _boxed: Box<KeyringSignerHandle> =
        unsafe { Box::from_raw(data as *mut KeyringSignerHandle) };
    // Drop runs here; if these were the last Arcs, the signer refcounts
    // decrement on the persist side.
}

/// Construct a [`Signer`] backed by `handle`. The returned value is what
/// `signer_ops_capsule` wraps in a `PyCapsule`.
///
/// The [`KeyringSignerHandle`] is boxed (`Box<KeyringSignerHandle>`) to
/// obtain a thin `*mut c_void` payload; the vtable's `build_op`/`drop`
/// interpret `data` accordingly.
pub fn build_persist_signer(handle: KeyringSignerHandle) -> Signer {
    let boxed: Box<KeyringSignerHandle> = Box::new(handle);
    Signer {
        data: Box::into_raw(boxed) as *mut c_void,
        vtable: &PERSIST_SIGNER_VTABLE,
    }
}

/// Build a `PyCapsule` wrapping a fresh [`Signer`] backed by `handle`,
/// with a destructor that calls the vtable's `drop` at GC time
/// (CIRISPersist#320 audit).
///
/// Confined to this module because the FFI capsule construction needs
/// `unsafe` for `PyCapsule::new_with_value_and_destructor` — the same
/// `#![deny(unsafe_code)]`-override rationale as
/// [`crate::ffi::directory_capsule::build_capsule_with_destructor`].
///
/// The capsule payload pointer is a `Box::into_raw`'d `Box<Signer>`. The
/// destructor reconstructs the box and invokes `vtable.drop(data)` before
/// deallocating the envelope.
#[cfg(feature = "pyo3")]
pub fn build_capsule_with_destructor<'py>(
    py: pyo3::Python<'py>,
    handle: KeyringSignerHandle,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyCapsule>> {
    use pyo3::types::PyCapsule;
    let signer = build_persist_signer(handle);
    let boxed_signer: Box<Signer> = Box::new(signer);
    let raw: *mut Signer = Box::into_raw(boxed_signer);
    // SAFETY: `raw` was just produced by `Box::into_raw`; PyCapsule calls
    // the destructor exactly once at GC. The destructor reconstructs the
    // Box (recovering ownership) before invoking `vtable.drop` on the
    // inner data pointer.
    unsafe {
        PyCapsule::new_with_value_and_destructor(
            py,
            raw as usize,
            c"ciris_persist::signer_ops_v1",
            |raw_usize, _ctx| {
                let raw_ptr = raw_usize as *mut Signer;
                if raw_ptr.is_null() {
                    return;
                }
                // SAFETY: `raw_ptr` is the pointer we `Box::into_raw`'d;
                // the only path into this destructor is PyCapsule's
                // single-fire GC.
                let signer: Box<Signer> = Box::from_raw(raw_ptr);
                (signer.vtable.drop)(signer.data);
                // Box deallocates the Signer envelope here.
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
    use ed25519_dalek::SigningKey;
    use std::sync::mpsc;

    // ── shared helpers ─────────────────────────────────────────────

    /// A software Ed25519-only signer handle (no PQC), plus the raw seed
    /// so tests can reproduce the direct signature.
    fn ed25519_handle(seed: [u8; 32]) -> KeyringSignerHandle {
        let local = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&seed),
            "signer-test".into(),
            None,
            None,
        ));
        let signer: Arc<dyn HardwareSigner> = Arc::new(LocalSignerHardwareAdapter::new(local));
        KeyringSignerHandle {
            signer,
            pqc_signer: None,
            key_id: "signer-test".into(),
        }
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
    fn run_op(rt: &Arc<tokio::runtime::Runtime>, signer: &Signer, op: &SignerOp) -> SignerOpResult {
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
            (signer.vtable.build_op)(signer.data, op_bytes.as_ptr(), op_bytes.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("op result must arrive");
        // SAFETY: single-drop, matched vtable.
        unsafe { (executor.vtable.drop)(executor.data) };
        serde_json::from_slice(&bytes).expect("deserialize SignerOpResult")
    }

    #[test]
    fn abi_version_pinned_at_1() {
        assert_eq!(SIGNER_ABI_VERSION, 1);
        assert_eq!(PERSIST_SIGNER_VTABLE.abi_version, 1);
    }

    #[test]
    fn vtable_abi_version_at_offset_zero() {
        // Consumers read `vtable.abi_version` via `&'static SignerVTable`,
        // so the field MUST be at offset 0.
        let v = &PERSIST_SIGNER_VTABLE;
        let base = v as *const _ as usize;
        let version_field = &v.abi_version as *const _ as usize;
        assert_eq!(version_field, base, "abi_version must be at offset 0");
    }

    #[test]
    fn sign_round_trips_byte_identical_to_direct() {
        // SECURITY-CRITICAL round-trip: the capsule signature bytes MUST
        // equal a direct `signer.sign` call — proving the sign ran in
        // persist's `.so` against persist's own vtable (no algorithm/slot
        // skew). Ed25519 is deterministic, so bytes are exactly equal.
        let rt = test_runtime();
        let handle = ed25519_handle([0x11u8; 32]);
        // Keep a direct clone of the signer Arc for the ground-truth call.
        let direct_signer: Arc<dyn HardwareSigner> = handle.signer.clone();
        let signer = build_persist_signer(handle);

        let msg = b"security-critical-sign".to_vec();
        let res = run_op(&rt, &signer, &SignerOp::Sign { data: msg.clone() });
        let via_capsule = match res {
            SignerOpResult::Signature(sig) => sig,
            other => panic!("expected Signature, got {other:?}"),
        };
        let via_direct = rt.block_on(direct_signer.sign(&msg)).expect("direct sign");
        assert_eq!(
            via_capsule, via_direct,
            "capsule signature bytes must equal direct signer.sign bytes"
        );
        assert_eq!(via_capsule.len(), 64, "Ed25519 signature is 64 bytes");

        // SAFETY: single-drop, matched vtable.
        unsafe { (signer.vtable.drop)(signer.data) };
    }

    #[test]
    fn public_key_round_trips() {
        let rt = test_runtime();
        let handle = ed25519_handle([0x22u8; 32]);
        let direct_signer: Arc<dyn HardwareSigner> = handle.signer.clone();
        let signer = build_persist_signer(handle);

        let res = run_op(&rt, &signer, &SignerOp::PublicKey {});
        let via_capsule = match res {
            SignerOpResult::PublicKey(pk) => pk,
            other => panic!("expected PublicKey, got {other:?}"),
        };
        let via_direct = rt
            .block_on(direct_signer.public_key())
            .expect("direct public_key");
        assert_eq!(via_capsule, via_direct);
        assert_eq!(via_capsule.len(), 32, "Ed25519 public key is 32 bytes");

        // And the key id round-trips too.
        let key_id = run_op(&rt, &signer, &SignerOp::KeyId {});
        assert!(
            matches!(key_id, SignerOpResult::KeyId(ref s) if s == "signer-test"),
            "got {key_id:?}"
        );

        // SAFETY: single-drop, matched vtable.
        unsafe { (signer.vtable.drop)(signer.data) };
    }

    #[test]
    fn absent_pqc_returns_none_not_err() {
        // The Ed25519-only handle has no PQC signer; PqcSign / PqcPublicKey
        // MUST return Ok(None) inside the Maybe* variants — NOT a
        // top-level Err (absence is a legitimate config, not a failure).
        let rt = test_runtime();
        let handle = ed25519_handle([0x33u8; 32]);
        let signer = build_persist_signer(handle);

        let sign = run_op(
            &rt,
            &signer,
            &SignerOp::PqcSign {
                data: b"whatever".to_vec(),
            },
        );
        assert!(
            matches!(sign, SignerOpResult::MaybeSignature(None)),
            "absent PQC signer ⇒ MaybeSignature(None), got {sign:?}"
        );

        let pk = run_op(&rt, &signer, &SignerOp::PqcPublicKey {});
        assert!(
            matches!(pk, SignerOpResult::MaybePublicKey(None)),
            "absent PQC signer ⇒ MaybePublicKey(None), got {pk:?}"
        );

        // SAFETY: single-drop, matched vtable.
        unsafe { (signer.vtable.drop)(signer.data) };
    }

    #[test]
    fn malformed_op_bytes_fire_err_callback() {
        // A parse failure must STILL fire the callback with a serialized
        // Err (uniform completion path), never leak the future.
        let rt = test_runtime();
        let handle = ed25519_handle([0x44u8; 32]);
        let signer = build_persist_signer(handle);

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
            (signer.vtable.build_op)(signer.data, garbage.as_ptr(), garbage.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("parse-failure callback must still fire");
        let res: SignerOpResult = serde_json::from_slice(&bytes).expect("deserialize");
        assert!(matches!(res, SignerOpResult::Err(_)), "got {res:?}");

        // SAFETY: single-drop, matched vtables.
        unsafe { (executor.vtable.drop)(executor.data) };
        unsafe { (signer.vtable.drop)(signer.data) };
    }
}
