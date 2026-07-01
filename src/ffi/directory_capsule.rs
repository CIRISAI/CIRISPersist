// This module's whole point is a C-ABI vtable that crosses the
// cdylib boundary. Every safety boundary is documented at the
// call site; the crate-wide #![deny(unsafe_code)] is overridden
// here because there is no other way to implement an FFI ABI.
// Audit-visible: every use of `unsafe` in this file is paired
// with the contract that justifies it. Confined to this module
// so release-wheel reviewers see one diff that owns the surface.
#![allow(unsafe_code)]

//! ABI-stable `FederationDirectory` dispatch capsule (CIRISPersist#320).
//!
//! # Why this exists
//!
//! [`crate::federation::FederationDirectory`] is an object-safe
//! `#[async_trait]` trait, and the pre-#320 cross-module surface
//! (`PyEngine::federation_directory_capsule`) hands a consumer wheel
//! (CIRISEdge) a raw `Arc<dyn FederationDirectory>` through a
//! `PyCapsule`. The consumer then calls trait methods on it.
//!
//! The problem is the **vtable of a `dyn Trait` is not ABI-stable**.
//! Rust makes no guarantee that the *slot order* of a trait object's
//! method pointers is stable across compiler versions, across crate
//! versions, or even across builds. When CIRISEdge is compiled against
//! persist v11.2.0's trait definition and then, at runtime, receives an
//! `Arc<dyn FederationDirectory>` produced by a v11.5.0 persist wheel,
//! the consumer computes a slot index for (say) `put_transport_destination`
//! using **its own** statically-resolved vtable layout — but the fat
//! pointer it received points at the wheel's vtable, whose slot at that
//! index may be an entirely different method (e.g.
//! `lookup_shared_instance_lease`). The call dispatches to the wrong
//! method body → the #320 hang (and, in the general case, memory-unsafe
//! argument reinterpretation).
//!
//! Same structural class as the cross-tokio aliasing at CIRISPersist#156
//! (fixed by [`crate::ffi::executor_capsule`]) and the libsqlite3
//! cross-cdylib SIGSEGV at CIRISPersist#141: a Rust type whose in-memory
//! contract is not guaranteed stable is passed by-value across the
//! static-vs-wheel boundary.
//!
//! # The fix
//!
//! Cross the boundary with a **C-ABI vtable** ([`DirectoryVTable`]) and
//! a **uniform serialized bytes-in / bytes-out** op protocol. The
//! consumer serializes a [`DirectoryOp`] (persist-owned, append-only
//! enum), hands the bytes through [`DirectoryVTable::build_op`], which
//! runs **inside persist's `.so`**. Persist deserializes the op,
//! matches it to the concrete `FederationDirectory` method, and calls
//! that method **using persist's own compiled vtable** — the only
//! vtable that is guaranteed to match the trait object's layout,
//! because persist built both. The result is serialized to a
//! [`DirectoryOpResult`] and handed back through a callback.
//!
//! Because every method — regardless of its heterogeneous argument and
//! return types — flows through the one `bytes -> DirectoryOp ->
//! dispatch -> DirectoryOpResult -> bytes` path, there is exactly ONE
//! stable ABI surface to audit, not one per trait method.
//!
//! # Spawn reuse
//!
//! `build_op` does not run the future itself; a `FederationDirectory`
//! call is `async`. It returns a type-erased boxed future
//! ([`crate::ffi::executor_capsule::TaskOpaque`]) that the consumer
//! spawns through the EXISTING [`crate::ffi::executor_capsule`] — so the
//! future is polled by persist's tokio worker pool, and no new
//! runtime/spawn machinery is introduced here. The two capsules compose:
//! `directory_ops_capsule` builds the op-future; `executor_capsule`
//! spawns it.
//!
//! # The contract the consumer MUST honor
//!
//! - `result_cb` is invoked **exactly once**, from a persist worker
//!   thread, when the op completes. It receives a pointer + length to
//!   the serialized [`DirectoryOpResult`]. The bytes are valid ONLY for
//!   the duration of the callback — the consumer MUST copy them before
//!   returning.
//! - `result_ctx` is an opaque consumer pointer passed back verbatim to
//!   `result_cb`. It MUST remain valid until `result_cb` fires, and MUST
//!   be safe to move to (and use from) persist's worker thread — i.e.
//!   the consumer's `result_cb` + `result_ctx` pair must be `Send`.
//! - The spawned future obeys the same tokio-primitive constraint as
//!   [`crate::ffi::executor_capsule`]: its body runs on a persist worker
//!   thread, so it must not touch the consumer crate's tokio
//!   thread-local primitives. The only async work it performs is calling
//!   persist's own `FederationDirectory` methods, which is always
//!   correct.
//!
//! # ABI version
//!
//! Consumers MUST verify [`DirectoryVTable::abi_version`] equals
//! [`DIRECTORY_ABI_VERSION`] at capsule-receive time. Persist bumps the
//! version on any breaking change to the vtable layout (NOT on
//! append-only [`DirectoryOp`] growth — see that type's docs).
//!
//! # Error flattening
//!
//! [`crate::federation::Error`] is not guaranteed serde-round-trippable,
//! so every method failure is flattened to
//! [`DirectoryOpResult::Err`]`(String)` carrying `Error::to_string()`.
//! The consumer maps that back to a generic error on its side; the
//! structured error variant does not cross the ABI.

use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::federation::admission::{reachable_under_scope_with_reasons, ReachabilityVerdict};
use crate::federation::operational::{OrgMembership, Organization};
use crate::federation::types::{KeyRecord, PeerMetadataRow};
use crate::federation::{self_at_login, shared_instance};
use crate::federation::{
    FederationDirectory, SignedAttestation, SignedCommunity, SignedFamily,
    SignedIdentityOccurrence, SignedKeyRecord, SignedLocationProof, SignedRevocation,
};
use crate::fountain::{FountainHeldMeta, FountainTier};

// Reuse the executor capsule's type-erased future pointer + the boxed
// future shape it already knows how to spawn. The op-future produced
// here is spawned by the consumer through `executor_capsule`, so the
// two must agree on the exact boxed-future type.
use crate::ffi::executor_capsule::TaskOpaque;

/// The boxed-future shape [`crate::ffi::executor_capsule`] spawns. The
/// pointer returned by [`DirectoryVTable::build_op`] is a
/// `Box<BoxedFut>` cast to `*mut TaskOpaque`, byte-identical to what the
/// executor capsule's `spawn` reconstructs.
type BoxedFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// ABI version of [`DirectoryVTable`]. Bumped on any breaking change to
/// the vtable's layout or function-pointer signatures.
///
/// This is INDEPENDENT of [`DirectoryOp`]'s wire growth: appending a new
/// [`DirectoryOp`] variant does NOT bump this, because the vtable
/// signature (`build_op` takes opaque bytes) is unchanged — an older
/// consumer simply never emits the new variant, and a well-formed op it
/// does emit still round-trips. The version guards the *C-ABI shape*
/// (function-pointer count/order/signatures), which the serialized-op
/// design keeps stable across op growth.
///
/// Consumers MUST check the field at capsule-receive time:
///
/// ```ignore
/// use ciris_persist::ffi::directory_capsule::{Directory, DIRECTORY_ABI_VERSION};
///
/// let directory: Directory = unsafe { /* read from PyCapsule */ };
/// assert_eq!(
///     directory.vtable.abi_version,
///     DIRECTORY_ABI_VERSION,
///     "persist directory_capsule ABI version mismatch — pin floor too low"
/// );
/// ```
pub const DIRECTORY_ABI_VERSION: u32 = 1;

/// A `FederationDirectory` operation, serialized by the consumer and
/// dispatched inside persist's `.so`.
///
/// # APPEND-ONLY — the ABI depends on it
///
/// This enum is the wire contract between a persist wheel and every
/// consumer built against a (possibly older) persist. `serde_json`'s
/// externally-tagged representation keys each variant by NAME, not by
/// ordinal, so the immediate hazard is not reordering-by-index — but the
/// discipline is still strict, to keep the contract auditable:
///
/// - **New operations MUST be added at the END.** Never insert in the
///   middle, never reorder, never remove a variant, never rename one,
///   never change an existing variant's field set or field types.
/// - A consumer built against an older persist simply never constructs
///   the newer variants; a newer consumer talking to an older wheel that
///   lacks a variant gets a clean deserialize failure → the wheel builds
///   a [`DirectoryOpResult::Err`] rather than misdispatching.
///
/// Every argument type here derives `serde::{Serialize, Deserialize}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectoryOp {
    /// [`FederationDirectory::lookup_public_key`].
    LookupPublicKey {
        /// The `federation_keys.key_id` to fetch.
        key_id: String,
    },
    /// [`FederationDirectory::put_transport_destination`].
    PutTransportDestination {
        /// The reachable-address row to register/refresh.
        destination: self_at_login::TransportDestination,
    },
    /// [`FederationDirectory::list_transport_destinations_for`].
    ListTransportDestinationsFor {
        /// The occurrence whose reachable addresses to list.
        occurrence_key_id: String,
    },
    /// [`FederationDirectory::lookup_shared_instance_lease`].
    LookupSharedInstanceLease {
        /// The named singleton whose current lease owner to look up.
        instance_name: String,
    },
    /// [`FederationDirectory::try_acquire_shared_instance`].
    AcquireSharedInstanceLease {
        /// The named singleton to try to acquire.
        instance_name: String,
        /// The acquiring process's PID.
        owner_pid: i32,
        /// The acquiring process's hostname.
        owner_hostname: String,
        /// Staleness threshold; `None` ⇒ the backend default.
        stale_after: Option<std::time::Duration>,
    },
    /// [`FederationDirectory::heartbeat_shared_instance`].
    HeartbeatSharedInstance {
        /// The held lease to refresh.
        lease: shared_instance::SharedInstanceLease,
    },
    /// [`FederationDirectory::release_shared_instance_lease`].
    ReleaseSharedInstanceLease {
        /// The held lease to release (ownership-checked).
        lease: shared_instance::SharedInstanceLease,
    },
    /// [`FederationDirectory::list_keys_by_identity_type`] with
    /// [`crate::federation::types::identity_type::ACCORD_HOLDER`] — the
    /// 2-of-3 constitutional verification set (CIRISEdge#19).
    ListAccordHolders {},
    /// [`FederationDirectory::put_revocation`].
    PutRevocation {
        /// The signed revocation to admit.
        revocation: SignedRevocation,
    },
    /// [`FederationDirectory::put_public_key`].
    PutPublicKey {
        /// The signed pubkey row to admit.
        record: SignedKeyRecord,
    },
    /// [`FederationDirectory::put_location_proof`].
    PutLocationProof {
        /// The signed location proof to admit.
        proof: SignedLocationProof,
    },
    /// [`FederationDirectory::put_identity_occurrence`].
    PutIdentityOccurrence {
        /// The signed identity-occurrence binding to admit.
        occurrence: SignedIdentityOccurrence,
    },
    /// [`FederationDirectory::put_family`].
    PutFamily {
        /// The signed family row to admit.
        family: SignedFamily,
    },
    /// [`FederationDirectory::put_community`].
    PutCommunity {
        /// The signed community row to admit.
        community: SignedCommunity,
    },
    /// [`FederationDirectory::put_attestation`].
    PutAttestation {
        /// The signed attestation to admit.
        attestation: SignedAttestation,
    },
    /// [`FederationDirectory::peer_metadata_for`].
    PeerMetadataFor {
        /// The peer `key_id` whose metadata row to read.
        key_id: String,
    },
    /// [`FederationDirectory::list_org_memberships_since`].
    ListOrgMembershipsSince {
        /// Cursor: rows with `asserted_at > since` (None ⇒ from start).
        since: Option<chrono::DateTime<chrono::Utc>>,
        /// Page cap.
        limit: u32,
    },
    /// [`FederationDirectory::list_organizations_since`].
    ListOrganizationsSince {
        /// Cursor: rows with `asserted_at > since` (None ⇒ from start).
        since: Option<chrono::DateTime<chrono::Utc>>,
        /// Page cap.
        limit: u32,
    },
    /// [`FederationDirectory::list_held_fountain_content`].
    ListHeldFountainContent {
        /// The publisher whose fountain holdings to enumerate.
        publisher_key_id: String,
    },
    /// [`FederationDirectory::evict_fountain_content_to_tier`].
    EvictFountainContentToTier {
        /// The content unit to evict.
        content_id: String,
        /// The corpus the content lives in.
        corpus_kind: String,
        /// The target eviction tier (keep-count).
        tier: FountainTier,
    },
    /// [`FederationDirectory::evict_fountain_content_hard_delete`].
    EvictFountainContentHardDelete {
        /// The content unit to hard-delete symbols for.
        content_id: String,
        /// The corpus the content lives in.
        corpus_kind: String,
    },
    /// The free fn
    /// [`reachable_under_scope_with_reasons`](crate::federation::admission::reachable_under_scope_with_reasons)`(dir,
    /// root, signer_key, required_scope, max_depth)`.
    ReachableUnderScope {
        /// The issuer (trust root) the walk seeds from.
        root: String,
        /// The target key the walk tries to reach.
        signer_key: String,
        /// The scope every edge on the path must carry.
        required_scope: String,
        /// Depth cap for the delegation walk.
        max_depth: u32,
    },
    /// The **security-critical** composite verify (CIRISPersist#320 audit /
    /// CIRISEdge#245). The free fn
    /// [`verify_hybrid_via_directory`](crate::verify::hybrid::verify_hybrid_via_directory)`(dir,
    /// …)` does MULTIPLE directory lookups + the Ed25519/ML-DSA-65 hybrid
    /// verification internally — a raw-`dyn` vtable misdispatch here would
    /// silently verify against the wrong method (accept a forged signature),
    /// so this MUST run inside persist's `.so`. `canonical_bytes` is the
    /// exact bytes the signatures cover.
    VerifyHybridViaDirectory {
        /// The canonical bytes the signatures were computed over.
        canonical_bytes: Vec<u8>,
        /// The claimed signing key id (resolved against the directory).
        signing_key_id: String,
        /// Base64 Ed25519 signature.
        ed25519_sig_b64: String,
        /// Base64 ML-DSA-65 signature (absent for classical-only rows).
        ml_dsa_65_sig_b64: Option<String>,
        /// The hybrid-verification policy.
        policy: crate::verify::hybrid::HybridPolicy,
        /// Optional row age for the replay / freshness window.
        row_age: Option<std::time::Duration>,
    },
    /// The free fn
    /// [`build_delegation_graph`](crate::federation::topology::build_delegation_graph)`(dir,
    /// from_key, max_depth)` — walks the delegation graph via multiple
    /// directory lookups (CIRISNodeCore trust-depth; CIRISPersist#320 audit).
    BuildDelegationGraph {
        /// The key the delegation walk seeds from.
        from_key: String,
        /// Depth cap for the walk.
        max_depth: u32,
    },
}

/// The mirror of each [`DirectoryOp`]'s return, plus the flattened error.
///
/// One `Ok*` variant per return SHAPE — identical shapes share a variant
/// (all `()` returns collapse to [`DirectoryOpResult::Unit`], both
/// eviction `u64` returns to [`DirectoryOpResult::U64`], and the three
/// `Option<SharedInstanceLease>`-returning ops to
/// [`DirectoryOpResult::SharedLease`]).
///
/// Same append-only discipline as [`DirectoryOp`].
//
// `large_enum_variant` allowed: this is a transient wire type — built,
// serialized to bytes, and dropped within a single op-future. It is
// never held in bulk or in a collection, so the size disparity between
// `Unit`/`U64` and the record-carrying variants is immaterial; boxing
// the payloads would only obscure the 1:1 method-return mapping.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectoryOpResult {
    /// Any method failure, flattened from `Error::to_string()`. The
    /// structured [`crate::federation::Error`] does not cross the ABI;
    /// the consumer maps this to a generic error on its side.
    Err(String),
    /// The `()` returns: `put_transport_destination`, `put_revocation`,
    /// `put_public_key`, `put_location_proof`, `put_identity_occurrence`,
    /// `put_family`, `put_community`, `put_attestation`,
    /// `release_shared_instance_lease`.
    Unit,
    /// `lookup_public_key`.
    PublicKey(Option<KeyRecord>),
    /// `list_keys_by_identity_type` (accord holders).
    KeyRecords(Vec<KeyRecord>),
    /// `list_transport_destinations_for`.
    TransportDestinations(Vec<self_at_login::TransportDestination>),
    /// `lookup_shared_instance_lease`, `try_acquire_shared_instance`,
    /// `heartbeat_shared_instance`.
    SharedLease(Option<shared_instance::SharedInstanceLease>),
    /// `peer_metadata_for`.
    PeerMetadata(Option<PeerMetadataRow>),
    /// `list_org_memberships_since`.
    OrgMemberships(Vec<OrgMembership>),
    /// `list_organizations_since`.
    Organizations(Vec<Organization>),
    /// `list_held_fountain_content`.
    FountainHeld(Vec<FountainHeldMeta>),
    /// `evict_fountain_content_to_tier`,
    /// `evict_fountain_content_hard_delete`.
    U64(u64),
    /// `reachable_under_scope_with_reasons`.
    Reachability(ReachabilityVerdict),
    /// `verify_hybrid_via_directory` — the verify VERDICT is preserved
    /// intact (`Ok(VerifyOutcome)`); an operational `VerifyError` is
    /// flattened to `Err(String)` INSIDE this variant (NOT the top-level
    /// `Err`), so the consumer always distinguishes "verification ran and
    /// produced this outcome" from "verify could not run". A wrong-method
    /// misdispatch is impossible: the whole verify executed in persist's
    /// `.so` against persist's own vtable.
    HybridVerify(Result<crate::verify::hybrid::VerifyOutcome, String>),
    /// `build_delegation_graph`.
    DelegationGraph(crate::federation::topology::DelegationGraph),
}

/// Run one [`DirectoryOp`] against `dir` and wrap the outcome.
///
/// This is safe Rust — it is the body that runs INSIDE persist's `.so`,
/// so every `dir.method(...)` call resolves through persist's own
/// compiled `FederationDirectory` vtable (the whole point of #320). A
/// method `Err(e)` flattens to [`DirectoryOpResult::Err`]`(e.to_string())`.
pub async fn dispatch_directory_op(
    dir: &dyn FederationDirectory,
    op: DirectoryOp,
) -> DirectoryOpResult {
    use crate::federation::types::identity_type;
    match op {
        DirectoryOp::LookupPublicKey { key_id } => match dir.lookup_public_key(&key_id).await {
            Ok(v) => DirectoryOpResult::PublicKey(v),
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::PutTransportDestination { destination } => {
            match dir.put_transport_destination(&destination).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::ListTransportDestinationsFor { occurrence_key_id } => {
            match dir
                .list_transport_destinations_for(&occurrence_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::TransportDestinations(v),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::LookupSharedInstanceLease { instance_name } => {
            match dir.lookup_shared_instance_lease(&instance_name).await {
                Ok(v) => DirectoryOpResult::SharedLease(v),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::AcquireSharedInstanceLease {
            instance_name,
            owner_pid,
            owner_hostname,
            stale_after,
        } => match dir
            .try_acquire_shared_instance(&instance_name, owner_pid, &owner_hostname, stale_after)
            .await
        {
            Ok(v) => DirectoryOpResult::SharedLease(v),
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::HeartbeatSharedInstance { lease } => {
            match dir.heartbeat_shared_instance(&lease).await {
                Ok(v) => DirectoryOpResult::SharedLease(v),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::ReleaseSharedInstanceLease { lease } => {
            match dir.release_shared_instance_lease(&lease).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::ListAccordHolders {} => {
            match dir
                .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
                .await
            {
                Ok(v) => DirectoryOpResult::KeyRecords(v),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::PutRevocation { revocation } => match dir.put_revocation(revocation).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::PutPublicKey { record } => match dir.put_public_key(record).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::PutLocationProof { proof } => match dir.put_location_proof(proof).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::PutIdentityOccurrence { occurrence } => {
            match dir.put_identity_occurrence(occurrence).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::PutFamily { family } => match dir.put_family(family).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::PutCommunity { community } => match dir.put_community(community).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::PutAttestation { attestation } => match dir.put_attestation(attestation).await
        {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::PeerMetadataFor { key_id } => match dir.peer_metadata_for(&key_id).await {
            Ok(v) => DirectoryOpResult::PeerMetadata(v),
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::ListOrgMembershipsSince { since, limit } => {
            match dir.list_org_memberships_since(since, limit).await {
                Ok(v) => DirectoryOpResult::OrgMemberships(v),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::ListOrganizationsSince { since, limit } => {
            match dir.list_organizations_since(since, limit).await {
                Ok(v) => DirectoryOpResult::Organizations(v),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::ListHeldFountainContent { publisher_key_id } => {
            match dir.list_held_fountain_content(&publisher_key_id).await {
                Ok(v) => DirectoryOpResult::FountainHeld(v),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::EvictFountainContentToTier {
            content_id,
            corpus_kind,
            tier,
        } => match dir
            .evict_fountain_content_to_tier(&content_id, &corpus_kind, tier)
            .await
        {
            Ok(n) => DirectoryOpResult::U64(n),
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::EvictFountainContentHardDelete {
            content_id,
            corpus_kind,
        } => match dir
            .evict_fountain_content_hard_delete(&content_id, &corpus_kind)
            .await
        {
            Ok(n) => DirectoryOpResult::U64(n),
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::ReachableUnderScope {
            root,
            signer_key,
            required_scope,
            max_depth,
        } => match reachable_under_scope_with_reasons(
            dir,
            &root,
            &signer_key,
            &required_scope,
            max_depth as usize,
        )
        .await
        {
            Ok(v) => DirectoryOpResult::Reachability(v),
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::VerifyHybridViaDirectory {
            canonical_bytes,
            signing_key_id,
            ed25519_sig_b64,
            ml_dsa_65_sig_b64,
            policy,
            row_age,
        } => {
            // The verify runs entirely here — inside persist's `.so`, against
            // persist's own vtable — so no consumer-side vtable skew can
            // reach the signature-check lookups. The VerifyOutcome verdict is
            // preserved intact; a VerifyError flattens INSIDE HybridVerify.
            let outcome = crate::verify::hybrid::verify_hybrid_via_directory(
                dir,
                &canonical_bytes,
                &signing_key_id,
                &ed25519_sig_b64,
                ml_dsa_65_sig_b64.as_deref(),
                policy,
                row_age,
            )
            .await;
            DirectoryOpResult::HybridVerify(outcome.map_err(|e| e.to_string()))
        }
        DirectoryOp::BuildDelegationGraph {
            from_key,
            max_depth,
        } => {
            match crate::federation::topology::build_delegation_graph(
                dir,
                &from_key,
                max_depth as usize,
            )
            .await
            {
                Ok(g) => DirectoryOpResult::DelegationGraph(g),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
    }
}

/// C-ABI callback the consumer supplies to receive the serialized
/// [`DirectoryOpResult`]. Invoked exactly once, from a persist worker
/// thread. The `(ptr, len)` bytes are valid ONLY during the call.
pub type ResultCallback =
    unsafe extern "C" fn(ctx: *mut c_void, result_ptr: *const u8, result_len: usize);

/// C-ABI function-pointer table for the directory dispatcher.
///
/// `#[repr(C)]`; safe to stash in a static and hand its address across
/// the cdylib boundary. The function pointers live inside persist's
/// `.so`, so calling them transfers control into persist — where the
/// concrete `FederationDirectory` method dispatch uses persist's own
/// (matching) vtable.
#[repr(C)]
pub struct DirectoryVTable {
    /// ABI version — see [`DIRECTORY_ABI_VERSION`]. Offset 0; consumers
    /// read it via `&'static DirectoryVTable`.
    pub abi_version: u32,
    /// Reserved padding for natural 8-byte alignment. MUST be zero in v1.
    pub _reserved: u32,
    /// Deserialize the op from `op_ptr/op_len`, build the boxed op-future,
    /// and return it as a `*mut TaskOpaque` for the consumer to spawn via
    /// [`crate::ffi::executor_capsule`]. The future, when polled, runs the
    /// op against the directory and calls `result_cb(result_ctx, ...)`
    /// once with the serialized [`DirectoryOpResult`].
    ///
    /// On a parse failure the returned future still fires `result_cb`
    /// once — with a serialized [`DirectoryOpResult::Err`] — so the
    /// consumer's completion path is uniform.
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by
    ///   [`build_persist_directory`] for this same vtable (a
    ///   `Box::into_raw`'d `Box<Arc<dyn FederationDirectory>>`).
    ///   Mismatched `data` ↔ `vtable` pairings are UB.
    /// - `op_ptr` MUST point at `op_len` initialized, readable bytes for
    ///   the duration of this call. They are copied/parsed before the
    ///   call returns; the consumer may free them afterward.
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
    /// Drop the directory handle — drops the inner
    /// `Arc<dyn FederationDirectory>`. Called by the consumer when the
    /// capsule is dropped (Python GC).
    ///
    /// # Safety
    /// - `data` MUST be a value previously produced by
    ///   [`build_persist_directory`] for this same vtable.
    /// - MUST be called exactly once per capsule. Double-drop is UB.
    pub drop: unsafe extern "C" fn(data: *mut c_void),
}

/// The capsule contents — opaque data pointer + vtable.
///
/// Consumers receive this via a `PyCapsule` whose pointer (after the
/// name-tag check) IS a `*mut Directory`. Treat the fields as opaque;
/// invoke only through the vtable's function pointers.
#[repr(C)]
pub struct Directory {
    /// Opaque payload pointer: persist's vtable expects a
    /// `Box::into_raw`'d `Box<Arc<dyn FederationDirectory>>`. The extra
    /// `Box` is required because `Arc<dyn Trait>` is a *fat* pointer
    /// (data + vtable halves) and cannot be flattened into a single thin
    /// `*mut c_void`; boxing it gives a thin pointer to the fat one.
    pub data: *mut c_void,
    /// Reference to a static vtable inside `ciris_persist.abi3.so`.
    pub vtable: &'static DirectoryVTable,
}

// SAFETY: `Directory` is Send+Sync — the underlying
// `Arc<dyn FederationDirectory>` is `Send + Sync` (the trait requires
// `Send + Sync`), and the vtable is a 'static reference. Consumers stash
// the capsule pointer in structures that cross threads; marking these
// makes the expectation explicit, matching `AsyncExecutor`.
unsafe impl Send for Directory {}
unsafe impl Sync for Directory {}

/// Persist's directory vtable instance. Address-stable for the process
/// lifetime — this is what a consumer's `Directory.vtable` targets.
pub static PERSIST_DIRECTORY_VTABLE: DirectoryVTable = DirectoryVTable {
    abi_version: DIRECTORY_ABI_VERSION,
    _reserved: 0,
    build_op: persist_directory_build_op,
    drop: persist_directory_drop,
};

/// Bundles the consumer-supplied completion callback and its opaque
/// context so the pair can be captured into the boxed op-future (which
/// persist spawns onto a worker thread). The raw `*mut c_void` context
/// is not `Send` on its own; the whole bundle is marked `Send` because
/// the `build_op` contract requires the consumer's `result_cb` +
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

/// Implementation of [`DirectoryVTable::build_op`].
///
/// # Safety
/// See [`DirectoryVTable::build_op`]. MUST be invoked only through the
/// vtable function pointer, never directly from outside persist's `.so`.
unsafe extern "C" fn persist_directory_build_op(
    data: *mut c_void,
    op_ptr: *const u8,
    op_len: usize,
    result_cb: ResultCallback,
    result_ctx: *mut c_void,
) -> *mut TaskOpaque {
    // SAFETY: per the vtable contract, `data` is a `Box::into_raw`'d
    // `Box<Arc<dyn FederationDirectory>>` owned by the capsule. We borrow
    // it (do NOT reconstruct the Box — that would drop the capsule's
    // owned value) and clone the Arc, bumping the refcount. The clone is
    // ours to move into the future; the capsule keeps its own Arc, freed
    // later by `persist_directory_drop`.
    let dir: Arc<dyn FederationDirectory> = unsafe {
        let boxed_ref: &Arc<dyn FederationDirectory> =
            &*(data as *const Arc<dyn FederationDirectory>);
        boxed_ref.clone()
    };

    // SAFETY: per the vtable contract, `op_ptr`/`op_len` name `op_len`
    // readable, initialized bytes valid for the duration of this call.
    // `serde_json::from_slice` reads them synchronously here; nothing
    // retains the borrow past this function.
    let op_bytes: &[u8] = unsafe { std::slice::from_raw_parts(op_ptr, op_len) };
    let parsed: Result<DirectoryOp, String> =
        serde_json::from_slice::<DirectoryOp>(op_bytes).map_err(|e| e.to_string());

    // Capture the consumer callback + context in a Send bundle so the
    // future (spawned onto persist's worker pool) may hold it.
    let completion = SendCompletion {
        cb: result_cb,
        ctx: result_ctx,
    };

    let fut: BoxedFut = Box::pin(async move {
        // Keep the cloned Arc + completion bundle alive across the await.
        let dir = dir;
        let completion = completion;
        let result: DirectoryOpResult = match parsed {
            Ok(op) => dispatch_directory_op(dir.as_ref(), op).await,
            Err(msg) => DirectoryOpResult::Err(format!("directory op parse failure: {msg}")),
        };
        // Serialization of `DirectoryOpResult` cannot realistically fail
        // (owned data, no non-string map keys). If it somehow did, fall
        // back to a serialized Err so the consumer's completion path
        // still fires with well-formed bytes.
        let bytes = serde_json::to_vec(&result).unwrap_or_else(|e| {
            serde_json::to_vec(&DirectoryOpResult::Err(format!(
                "directory op result serialize failure: {e}"
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

/// Implementation of [`DirectoryVTable::drop`].
///
/// # Safety
/// See [`DirectoryVTable::drop`]. Single-drop only; double-drop is UB.
unsafe extern "C" fn persist_directory_drop(data: *mut c_void) {
    // SAFETY: per the vtable contract, `data` was produced by
    // `Box::into_raw(Box::new(arc))` in `build_persist_directory`.
    // Reconstruct the Box to drop it (and the inner Arc).
    let _boxed: Box<Arc<dyn FederationDirectory>> =
        unsafe { Box::from_raw(data as *mut Arc<dyn FederationDirectory>) };
    // Drop runs here; if this was the last Arc, the backend refcount
    // decrements on the persist side.
}

/// Construct a [`Directory`] backed by `dir`. The returned value is what
/// `directory_ops_capsule` wraps in a `PyCapsule`.
///
/// The `Arc<dyn FederationDirectory>` is a fat pointer, so it is boxed
/// (`Box<Arc<dyn ...>>`) to obtain a thin `*mut c_void` payload; the
/// vtable's `build_op`/`drop` interpret `data` accordingly.
pub fn build_persist_directory(dir: Arc<dyn FederationDirectory>) -> Directory {
    let boxed: Box<Arc<dyn FederationDirectory>> = Box::new(dir);
    Directory {
        data: Box::into_raw(boxed) as *mut c_void,
        vtable: &PERSIST_DIRECTORY_VTABLE,
    }
}

/// Build a `PyCapsule` wrapping a fresh [`Directory`] backed by `dir`,
/// with a destructor that calls the vtable's `drop` at GC time
/// (CIRISPersist#320).
///
/// Confined to this module because the FFI capsule construction needs
/// `unsafe` for `PyCapsule::new_with_value_and_destructor` — the same
/// `#![deny(unsafe_code)]`-override rationale as
/// [`crate::ffi::executor_capsule::build_capsule_with_destructor`].
///
/// The capsule payload pointer is a `Box::into_raw`'d `Box<Directory>`.
/// The destructor reconstructs the box and invokes `vtable.drop(data)`
/// before deallocating the envelope.
#[cfg(feature = "_pyffi")]
pub fn build_capsule_with_destructor<'py>(
    py: pyo3::Python<'py>,
    dir: Arc<dyn FederationDirectory>,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyCapsule>> {
    use pyo3::types::PyCapsule;
    let directory = build_persist_directory(dir);
    let boxed_directory: Box<Directory> = Box::new(directory);
    let raw: *mut Directory = Box::into_raw(boxed_directory);
    // SAFETY: `raw` was just produced by `Box::into_raw`; PyCapsule calls
    // the destructor exactly once at GC. The destructor reconstructs the
    // Box (recovering ownership) before invoking `vtable.drop` on the
    // inner data pointer.
    unsafe {
        PyCapsule::new_with_value_and_destructor(
            py,
            raw as usize,
            c"ciris_persist::directory_ops_v1",
            |raw_usize, _ctx| {
                let raw_ptr = raw_usize as *mut Directory;
                if raw_ptr.is_null() {
                    return;
                }
                // SAFETY: `raw_ptr` is the pointer we `Box::into_raw`'d;
                // the only path into this destructor is PyCapsule's
                // single-fire GC.
                let directory: Box<Directory> = Box::from_raw(raw_ptr);
                (directory.vtable.drop)(directory.data);
                // Box deallocates the Directory envelope here.
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryBackend;
    use std::sync::mpsc;

    // ── shared helpers ─────────────────────────────────────────────

    fn memory_directory() -> (Arc<dyn FederationDirectory>, Directory) {
        let backend: Arc<MemoryBackend> = Arc::new(MemoryBackend::new());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());
        (dir, directory)
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
        directory: &Directory,
        op: &DirectoryOp,
    ) -> DirectoryOpResult {
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
            (directory.vtable.build_op)(directory.data, op_bytes.as_ptr(), op_bytes.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("op result must arrive");
        // SAFETY: single-drop, matched vtable.
        unsafe { (executor.vtable.drop)(executor.data) };
        serde_json::from_slice(&bytes).expect("deserialize DirectoryOpResult")
    }

    fn sample_key_record(key_id: &str) -> KeyRecord {
        let now = chrono::Utc::now();
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: "AAAA".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
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
        }
    }

    #[test]
    fn abi_version_pinned_at_1() {
        assert_eq!(DIRECTORY_ABI_VERSION, 1);
        assert_eq!(PERSIST_DIRECTORY_VTABLE.abi_version, 1);
    }

    #[test]
    fn vtable_abi_version_at_offset_zero() {
        // Consumers read `vtable.abi_version` via `&'static DirectoryVTable`,
        // so the field MUST be at offset 0.
        let v = &PERSIST_DIRECTORY_VTABLE;
        let base = v as *const _ as usize;
        let version_field = &v.abi_version as *const _ as usize;
        assert_eq!(version_field, base, "abi_version must be at offset 0");
    }

    #[test]
    fn put_then_lookup_public_key_round_trips() {
        let rt = test_runtime();
        let (dir, directory) = memory_directory();
        let rec = sample_key_record("primitive-abc");

        // PutPublicKey via the capsule → Unit.
        let put = run_op(
            &rt,
            &directory,
            &DirectoryOp::PutPublicKey {
                record: SignedKeyRecord {
                    record: rec.clone(),
                },
            },
        );
        assert!(
            matches!(put, DirectoryOpResult::Unit),
            "put ⇒ Unit, got {put:?}"
        );

        // LookupPublicKey via the capsule → PublicKey(Some(..)).
        let looked = run_op(
            &rt,
            &directory,
            &DirectoryOp::LookupPublicKey {
                key_id: "primitive-abc".into(),
            },
        );
        let via_capsule = match looked {
            DirectoryOpResult::PublicKey(v) => v,
            other => panic!("expected PublicKey, got {other:?}"),
        };

        // Assert it matches calling the method directly on the backend.
        let via_direct = rt
            .block_on(dir.lookup_public_key("primitive-abc"))
            .expect("direct lookup");
        assert_eq!(
            via_capsule, via_direct,
            "capsule result must equal direct call"
        );
        assert_eq!(via_capsule.expect("some").key_id, "primitive-abc");

        // Keep `directory.data` owned by us; drop it through the vtable.
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn put_then_list_transport_destinations_round_trips() {
        let rt = test_runtime();
        let (dir, directory) = memory_directory();

        // A transport destination needs its occurrence key on file (FK on
        // real backends); MemoryBackend's put_transport_destination is
        // permissive, so we assert the round-trip shape either way.
        let dest = self_at_login::TransportDestination {
            occurrence_key_id: "occ-1".into(),
            transport_kind: "reticulum".into(),
            destination: "abcd".into(),
            asserted_at: chrono::Utc::now(),
            last_seen_at: Some(chrono::Utc::now()),
        };

        let put = run_op(
            &rt,
            &directory,
            &DirectoryOp::PutTransportDestination {
                destination: dest.clone(),
            },
        );
        // MemoryBackend may accept (Unit) or refuse (Err) — either is a
        // valid ABI round-trip; the point is the bytes made it back.
        let direct_put = rt.block_on(dir.put_transport_destination(&dest));
        match (&put, &direct_put) {
            (DirectoryOpResult::Unit, Ok(())) => {}
            (DirectoryOpResult::Err(_), Err(_)) => {}
            (a, b) => panic!("capsule/direct put mismatch: {a:?} vs {b:?}"),
        }

        let listed = run_op(
            &rt,
            &directory,
            &DirectoryOp::ListTransportDestinationsFor {
                occurrence_key_id: "occ-1".into(),
            },
        );
        let via_direct = rt.block_on(dir.list_transport_destinations_for("occ-1"));
        match (listed, via_direct) {
            (DirectoryOpResult::TransportDestinations(v), Ok(w)) => assert_eq!(v, w),
            (DirectoryOpResult::Err(_), Err(_)) => {}
            (a, b) => panic!("capsule/direct list mismatch: {a:?} vs {b:?}"),
        }

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn reachable_under_scope_no_trust_roots() {
        let rt = test_runtime();
        let (dir, directory) = memory_directory();

        let verdict = run_op(
            &rt,
            &directory,
            &DirectoryOp::ReachableUnderScope {
                root: "issuer-x".into(),
                signer_key: "target-y".into(),
                required_scope: "moderation".into(),
                max_depth: 3,
            },
        );
        let via_direct = rt
            .block_on(reachable_under_scope_with_reasons(
                dir.as_ref(),
                "issuer-x",
                "target-y",
                "moderation",
                3,
            ))
            .expect("direct reachability");
        match verdict {
            DirectoryOpResult::Reachability(v) => assert_eq!(v, via_direct),
            other => panic!("expected Reachability, got {other:?}"),
        }

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn verify_hybrid_via_directory_round_trips_and_preserves_verdict() {
        // CIRISPersist#320 audit / CIRISEdge#245 — the security-critical op.
        // Unknown key → verify_hybrid_via_directory returns Err(Crypto
        // "verify_unknown_key"); the op must preserve it INSIDE HybridVerify
        // (not collapse to the top-level Err), byte-identical to the direct
        // call — proving the verify ran entirely inside persist's `.so`.
        let rt = test_runtime();
        let (dir, directory) = memory_directory();

        let op = DirectoryOp::VerifyHybridViaDirectory {
            canonical_bytes: b"canonical".to_vec(),
            signing_key_id: "no-such-key".into(),
            ed25519_sig_b64: "AAAA".into(),
            ml_dsa_65_sig_b64: None,
            policy: crate::verify::hybrid::HybridPolicy::Strict,
            row_age: None,
        };
        let res = run_op(&rt, &directory, &op);
        let via_direct = rt.block_on(crate::verify::hybrid::verify_hybrid_via_directory(
            dir.as_ref(),
            b"canonical",
            "no-such-key",
            "AAAA",
            None,
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        ));
        match res {
            DirectoryOpResult::HybridVerify(got) => {
                // Byte-identical to the direct call (verdict preserved intact).
                assert_eq!(got, via_direct.map_err(|e| e.to_string()));
                // And it's the stable unknown-key token, INSIDE HybridVerify —
                // not the top-level Err (which is reserved for other ops).
                match got {
                    Err(s) => assert!(s.contains("verify_unknown_key"), "got {s}"),
                    Ok(o) => panic!("expected verify Err for unknown key, got {o:?}"),
                }
            }
            other => panic!("expected HybridVerify, got {other:?}"),
        }

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn build_delegation_graph_round_trips() {
        // CIRISNodeCore trust-depth path (CIRISPersist#320 audit). An empty
        // directory yields a root-only graph; the op result must equal the
        // direct call, serialized through the ABI.
        let rt = test_runtime();
        let (dir, directory) = memory_directory();

        let res = run_op(
            &rt,
            &directory,
            &DirectoryOp::BuildDelegationGraph {
                from_key: "root-key".into(),
                max_depth: 3,
            },
        );
        let via_direct = rt
            .block_on(crate::federation::topology::build_delegation_graph(
                dir.as_ref(),
                "root-key",
                3,
            ))
            .expect("direct build_delegation_graph");
        match res {
            DirectoryOpResult::DelegationGraph(g) => {
                // Compare via JSON (DelegationGraph is Serialize) — the ABI
                // path serialized it, so structural equality is the contract.
                assert_eq!(
                    serde_json::to_value(&g).unwrap(),
                    serde_json::to_value(&via_direct).unwrap()
                );
            }
            other => panic!("expected DelegationGraph, got {other:?}"),
        }

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn backend_error_flattens_to_err_variant() {
        // MemoryBackend has no `lookup_shared_instance_lease` impl (the
        // default trait impl errors), so this proves the Err(String)
        // flattening path across the ABI.
        let rt = test_runtime();
        let (dir, directory) = memory_directory();

        let res = run_op(
            &rt,
            &directory,
            &DirectoryOp::LookupSharedInstanceLease {
                instance_name: "rns-singleton".into(),
            },
        );
        assert!(
            matches!(res, DirectoryOpResult::Err(_)),
            "unimplemented backend method ⇒ Err(String), got {res:?}"
        );
        // Direct call also errors — same class.
        assert!(rt
            .block_on(dir.lookup_shared_instance_lease("rns-singleton"))
            .is_err());

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn malformed_op_bytes_fire_err_callback() {
        // A parse failure must STILL fire the callback with a serialized
        // Err (uniform completion path), never leak the future.
        let rt = test_runtime();
        let (_dir, directory) = memory_directory();

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
            (directory.vtable.build_op)(directory.data, garbage.as_ptr(), garbage.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("parse-failure callback must still fire");
        let res: DirectoryOpResult = serde_json::from_slice(&bytes).expect("deserialize");
        assert!(matches!(res, DirectoryOpResult::Err(_)), "got {res:?}");

        // SAFETY: single-drop, matched vtables.
        unsafe { (executor.vtable.drop)(executor.data) };
        unsafe { (directory.vtable.drop)(directory.data) };
    }
}
