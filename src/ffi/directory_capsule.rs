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
use crate::federation::operational::{
    OrgMembership, Organization, PartnerRecord, SignedOrgMembership, SignedOrganization,
    SignedPartnerRecord,
};
use crate::federation::types::{
    Attestation, Community, CommunityMembershipRevocation, Family, FamilyMembershipRevocation,
    HybridPendingRow, IdentityOccurrence, IdentityOccurrenceRevocation, KeyRecord, LocationProof,
    PeerMetadataRow, Revocation, SignedCommunityMembershipRevocation,
    SignedFamilyMembershipRevocation, SignedIdentityOccurrenceRevocation,
};
use crate::federation::{accord_quorum, cohort, self_at_login, shared_instance, types, Error};
use crate::federation::{
    FederationDirectory, SignedAttestation, SignedCommunity, SignedFamily,
    SignedIdentityOccurrence, SignedKeyRecord, SignedLocationProof, SignedRevocation,
};
use crate::ffi::executor_capsule::AsyncExecutor;
use crate::fountain::{FountainHeldMeta, FountainTier};

// Reuse the executor capsule's type-erased future pointer + the boxed
// future shape it already knows how to spawn. The op-future produced
// here is spawned by the consumer through `executor_capsule`, so the
// two must agree on the exact boxed-future type.
use crate::ffi::executor_capsule::TaskOpaque;

/// CIRISPersist#320 diagnostic — env-gated (`CIRIS_PERSIST_TRACE`) trace of the
/// directory-ops-proxy boundary, so a transport-bring-up hang localizes to an
/// exact stage/op. **Silent** unless the env var is set (checked once, cached),
/// so it is zero-cost in production. The consumer (edge) side logs
/// `SEND`/`RECV`; the persist-`.so` side logs `BUILD_OP`/`EXECUTE`/`COMPLETE`/
/// `CALLBACK`. A stall shows as the last stage printed with no follow-up:
///   * `SEND` with no `BUILD_OP`  → the op never crossed the FFI / spawned.
///   * `EXECUTE` with no `COMPLETE` → the directory method itself hung.
///   * `COMPLETE` with no `RECV`  → the result callback / consumer recv broke.
#[inline]
pub(crate) fn dtrace_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static ON: AtomicU8 = AtomicU8::new(0); // 0=unknown, 1=off, 2=on
    match ON.load(Ordering::Relaxed) {
        0 => {
            let v = if std::env::var_os("CIRIS_PERSIST_TRACE").is_some() {
                2
            } else {
                1
            };
            ON.store(v, Ordering::Relaxed);
            v == 2
        }
        v => v == 2,
    }
}

#[inline]
pub(crate) fn dtrace(stage: &str, op: &str) {
    if dtrace_enabled() {
        // Truncate the op preview so a large payload doesn't flood the log.
        let op = if op.len() > 90 { &op[..90] } else { op };
        eprintln!("[ciris_persist directory_op] {stage} {op}");
    }
}

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
    /// [`FederationDirectory::add_peer_record`](crate::federation::
    /// FederationDirectory::add_peer_record) — insert a peer row
    /// (CIRISPersist#333; the 6 peer-mutation ops edge's
    /// `federation_directory_for_edge` invokes via UniFFI `peer_*` +
    /// `reseed_canonical_bootstrap_peers`).
    AddPeerRecord {
        /// The peer's key id.
        key_id: String,
        /// Base64 Ed25519 public key.
        pubkey_ed25519_base64: String,
        /// The `federation_keys.identity_type` for the row.
        identity_type: String,
        /// Optional transport identity (RNS/Reticulum address).
        transport_identity: Option<String>,
    },
    /// [`FederationDirectory::remove_peer_record`](crate::federation::
    /// FederationDirectory::remove_peer_record) — soft (`hard=false`) or
    /// hard delete of a peer row.
    RemovePeerRecord {
        /// The peer's key id.
        key_id: String,
        /// `true` = DELETE the federation_keys row (CASCADE); `false` =
        /// mark `removed_at`.
        hard: bool,
    },
    /// [`FederationDirectory::update_peer_alias`](crate::federation::
    /// FederationDirectory::update_peer_alias).
    UpdatePeerAlias {
        /// The peer's key id.
        key_id: String,
        /// New alias, or `None` to clear.
        alias: Option<String>,
    },
    /// [`FederationDirectory::update_peer_trust`](crate::federation::
    /// FederationDirectory::update_peer_trust).
    UpdatePeerTrust {
        /// The peer's key id.
        key_id: String,
        /// The new trust class.
        trust: types::TrustClass,
    },
    /// [`FederationDirectory::update_peer_notes`](crate::federation::
    /// FederationDirectory::update_peer_notes).
    UpdatePeerNotes {
        /// The peer's key id.
        key_id: String,
        /// New operator notes, or `None` to clear.
        notes: Option<String>,
    },
    /// [`FederationDirectory::update_peer_policy`](crate::federation::
    /// FederationDirectory::update_peer_policy).
    UpdatePeerPolicy {
        /// The peer's key id.
        key_id: String,
        /// The opaque consumer-owned policy blob (round-tripped JSON).
        policy: types::PeerPolicyBlob,
    },
    /// [`FederationDirectory::apply_replicated_key_record`] (#375) — the
    /// #371 upgrade-aware, `owner_of`-gated replicated Key-plane apply.
    /// Routed so capsule consumers (CIRISEdge's anti-entropy bridge, which
    /// holds an `Arc<dyn FederationDirectory>` = [`OpsDirectory`]) reach the
    /// real backend upgrade path instead of the trait default's insert-only
    /// `put_public_key` DO-NOTHING. APPEND-ONLY: added at the end.
    ApplyReplicatedKeyRecord {
        /// The signed pubkey row to apply (fresh insert or scrub-upgrade).
        record: SignedKeyRecord,
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
    /// `apply_replicated_key_record` (#375) — the upgrade-aware apply
    /// OUTCOME (`Inserted` / `Upgraded` / `Unchanged` / `Refused`). A
    /// `Refused` is a *policy* outcome carried HERE, NOT flattened to the
    /// top-level [`DirectoryOpResult::Err`] (which is reserved for a real
    /// backend error that means the apply could not run). APPEND-ONLY.
    ReplicatedKeyOutcome(crate::federation::register::ReplicatedKeyOutcome),
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
        // #375 — the whole apply (plan + adopt_scrub_upgrade) runs INSIDE
        // persist's .so against persist's own vtable, so the capsule
        // consumer gets the real upgrade-aware outcome, not DO-NOTHING.
        DirectoryOp::ApplyReplicatedKeyRecord { record } => {
            match dir.apply_replicated_key_record(record).await {
                Ok(outcome) => DirectoryOpResult::ReplicatedKeyOutcome(outcome),
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
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
        DirectoryOp::AddPeerRecord {
            key_id,
            pubkey_ed25519_base64,
            identity_type,
            transport_identity,
        } => match dir
            .add_peer_record(
                &key_id,
                &pubkey_ed25519_base64,
                &identity_type,
                transport_identity,
            )
            .await
        {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::RemovePeerRecord { key_id, hard } => {
            match dir.remove_peer_record(&key_id, hard).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::UpdatePeerAlias { key_id, alias } => {
            match dir.update_peer_alias(&key_id, alias).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::UpdatePeerTrust { key_id, trust } => {
            match dir.update_peer_trust(&key_id, trust).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::UpdatePeerNotes { key_id, notes } => {
            match dir.update_peer_notes(&key_id, notes).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            }
        }
        DirectoryOp::UpdatePeerPolicy { key_id, policy } => {
            match dir.update_peer_policy(&key_id, policy).await {
                Ok(()) => DirectoryOpResult::Unit,
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

    // #320 trace: owned preview of the op JSON (op_bytes is only valid for
    // this synchronous call; the future runs later on a worker thread).
    // Allocated only when tracing is on — zero-cost in production.
    let op_preview: String = if dtrace_enabled() {
        String::from_utf8_lossy(op_bytes).into_owned()
    } else {
        String::new()
    };
    dtrace("BUILD_OP", &op_preview);

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
        dtrace("EXECUTE", &op_preview);
        let result: DirectoryOpResult = match parsed {
            Ok(op) => dispatch_directory_op(dir.as_ref(), op).await,
            Err(msg) => DirectoryOpResult::Err(format!("directory op parse failure: {msg}")),
        };
        dtrace("COMPLETE", &op_preview);
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
        dtrace("CALLBACK", &op_preview);
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

// ── #329: consumer-side FederationDirectory proxy ──────────────────

/// The consumer-side `FederationDirectory` proxy — the mirror of
/// [`build_persist_directory`] (the producer half).
///
/// A consumer (CIRISEdge#245) receives a [`Directory`] capsule (through a
/// `PyCapsule`) and an [`AsyncExecutor`] capsule from persist. Wrapping
/// them in an `OpsDirectory` yields a drop-in
/// `Arc<dyn FederationDirectory>`: every trait call is serialized to a
/// [`DirectoryOp`], routed through the capsule's `build_op` (which runs
/// the concrete method inside persist's `.so`, against persist's own
/// vtable), spawned on persist's runtime via the executor capsule, and
/// its [`DirectoryOpResult`] mapped back to the method's return — so the
/// consumer never hand-writes a single trait-method stub, and never
/// dispatches through a skewed `dyn` vtable (the #320 hazard).
///
/// Only the methods with a [`DirectoryOp`] variant are routed; every
/// other REQUIRED method returns [`Error::Unsupported`] (the remedy is to
/// add the op in persist). Methods with a trait DEFAULT body that have no
/// op are left inherited — their default bodies compose other trait
/// methods, which themselves route (or surface `Unsupported`).
struct OpsDirectory {
    /// The received directory capsule handle (opaque `data` + `&'static`
    /// vtable). `Directory` is already `Send + Sync`.
    directory: Directory,
    /// The executor capsule used to spawn each op's `TaskOpaque` onto
    /// persist's tokio runtime. `AsyncExecutor` is already `Send + Sync`.
    executor: Arc<AsyncExecutor>,
}

// `OpsDirectory` auto-derives `Send + Sync`: `Directory` carries explicit
// `unsafe impl Send/Sync`, and `Arc<AsyncExecutor>` is `Send + Sync`
// because `AsyncExecutor` is. No additional `unsafe impl` is required.

impl OpsDirectory {
    /// The C-ABI completion callback persist invokes exactly once, from a
    /// persist worker thread, when an op's future finishes. It delivers
    /// the serialized [`DirectoryOpResult`] back to the awaiting proxy
    /// method through the boxed [`tokio::sync::oneshot::Sender`] stashed
    /// in `ctx`.
    ///
    /// # Safety
    /// Invoked only as the `result_cb` handed to `build_op` in
    /// [`OpsDirectory::run_op`]; that pairing is the only provenance of
    /// `ctx`/`(ptr, len)`. MUST NOT be called directly.
    unsafe extern "C" fn result_trampoline(ctx: *mut c_void, ptr: *const u8, len: usize) {
        // SAFETY: `ctx` is the `Box::into_raw`'d
        // `oneshot::Sender<Vec<u8>>` created in `run_op` for THIS op. The
        // `build_op` contract fires the callback exactly once, so we
        // reclaim (and drop) the Box exactly once here — no leak, no
        // double-free.
        let tx = unsafe { Box::from_raw(ctx as *mut tokio::sync::oneshot::Sender<Vec<u8>>) };
        // SAFETY: per the `ResultCallback` contract, `(ptr, len)` name
        // `len` readable, initialized bytes valid ONLY for the duration
        // of this call. `.to_vec()` copies them out before we return;
        // nothing retains the borrow past this function.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        // The receiver may have been dropped (the proxy method's future
        // was cancelled). Ignore the send error — the copied bytes are
        // simply discarded.
        let _ = tx.send(bytes);
    }

    /// Serialize `op`, route it through the directory capsule's
    /// `build_op`, spawn the returned task on persist's runtime via the
    /// executor capsule, and await the serialized [`DirectoryOpResult`].
    ///
    /// The `tokio::sync::oneshot` tx/rx used here live in THIS
    /// (consumer-side) proxy method — never inside the spawned future —
    /// so the cross-tokio constraint documented in
    /// [`crate::ffi::executor_capsule`] is not engaged: send/recv is
    /// waker-based with no runtime affinity. A blocking `std` channel is
    /// deliberately avoided; the proxy methods are `async` and must not
    /// park a consumer worker thread.
    async fn run_op(&self, op: &DirectoryOp) -> Result<DirectoryOpResult, Error> {
        let op_bytes = serde_json::to_vec(op).map_err(|e| {
            Error::Backend(format!("directory ops proxy: op serialize failure: {e}"))
        })?;
        // #320 trace (consumer side): op preview for SEND/RECV bracketing.
        // Allocated only when tracing is on — zero-cost in production.
        let op_preview: String = if dtrace_enabled() {
            String::from_utf8_lossy(&op_bytes).into_owned()
        } else {
            String::new()
        };
        dtrace("SEND", &op_preview);

        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        // Hand the Sender to persist as an opaque `*mut c_void`; the
        // trampoline reclaims it exactly once when the op completes.
        let ctx: *mut c_void = Box::into_raw(Box::new(tx)) as *mut c_void;

        // SAFETY: `self.directory` was produced by
        // `build_persist_directory` and its `abi_version` was asserted to
        // match `DIRECTORY_ABI_VERSION` at `build_ops_directory` time, so
        // `data` ↔ `vtable` are a matched pair. `op_bytes` names readable,
        // initialized bytes that stay alive until after this call returns
        // (`build_op` reads them synchronously). `result_trampoline` +
        // `ctx` satisfy the callback contract: `ctx` is the Send-able
        // boxed Sender, valid until the callback fires exactly once from a
        // persist worker thread.
        let task: *mut TaskOpaque = unsafe {
            (self.directory.vtable.build_op)(
                self.directory.data,
                op_bytes.as_ptr(),
                op_bytes.len(),
                Self::result_trampoline,
                ctx,
            )
        };
        // `build_op` has read `op_bytes` synchronously; drop it now.
        drop(op_bytes);

        // SAFETY: `task` is the `*mut TaskOpaque` just returned by this
        // directory's `build_op` (the exact boxed-future shape
        // `executor_capsule::spawn` reconstructs), spawned exactly once.
        // `self.executor` is a matched persist executor capsule whose
        // `Arc<Runtime>` is alive for the duration of this call.
        unsafe { (self.executor.vtable.spawn)(self.executor.data, task) };

        // Await the result. A closed channel means the op-future was
        // dropped before firing the callback — surface a clean error
        // rather than hang or panic.
        let result_bytes = rx.await.map_err(|_| {
            Error::Backend(
                "directory ops proxy: directory op producer dropped without responding".into(),
            )
        })?;
        dtrace("RECV", &op_preview);

        serde_json::from_slice::<DirectoryOpResult>(&result_bytes).map_err(|e| {
            Error::Backend(format!(
                "directory ops proxy: result deserialize failure: {e}"
            ))
        })
    }
}

/// Build a consumer-side [`FederationDirectory`] proxy over a received
/// [`Directory`] capsule + an [`AsyncExecutor`] capsule (CIRISPersist#329).
///
/// The mirror of [`build_persist_directory`]: where that wraps persist's
/// backend into a capsule for export, this wraps a *received* capsule back
/// into an `Arc<dyn FederationDirectory>` the consumer calls like any
/// other. Covered methods route through the `build_op` ABI; uncovered
/// required methods return [`Error::Unsupported`].
///
/// # Errors
/// Returns [`Error::Backend`] if `directory.vtable.abi_version` does not
/// equal [`DIRECTORY_ABI_VERSION`]. (The issue floated `-> Arc<dyn ...>`,
/// but the ABI-version assertion needs a fallible return, so this yields a
/// `Result` and refuses a skewed capsule cleanly instead of risking a
/// mismatched-layout dispatch.)
pub fn build_ops_directory(
    directory: Directory,
    executor: Arc<AsyncExecutor>,
) -> Result<Arc<dyn FederationDirectory>, Error> {
    if directory.vtable.abi_version != DIRECTORY_ABI_VERSION {
        return Err(Error::Backend(format!(
            "directory ops proxy: directory capsule ABI version mismatch \
             (capsule={}, expected={DIRECTORY_ABI_VERSION}) — pin floor too low",
            directory.vtable.abi_version
        )));
    }
    Ok(Arc::new(OpsDirectory {
        directory,
        executor,
    }))
}

// `unused_variables` is allowed impl-wide: the ~53 uncovered REQUIRED
// methods are `Error::Unsupported` stubs that necessarily ignore their
// typed arguments. The covered methods DO consume their args, and a
// mistyped covered arg is a compile error (not a warning), so this allow
// cannot mask a routing bug.
#[allow(unused_variables)]
#[async_trait::async_trait]
impl FederationDirectory for OpsDirectory {
    // ── covered: routed through DirectoryOp ────────────────────────

    async fn put_public_key(&self, record: SignedKeyRecord) -> Result<(), Error> {
        match self.run_op(&DirectoryOp::PutPublicKey { record }).await? {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    // #375 — override so the capsule routes to the real upgrade-aware apply
    // (the trait default would run put_public_key DO-NOTHING here, silently
    // dropping an anchor-scrubbed record for an existing self-signed key_id).
    async fn apply_replicated_key_record(
        &self,
        record: SignedKeyRecord,
    ) -> Result<crate::federation::register::ReplicatedKeyOutcome, Error> {
        match self
            .run_op(&DirectoryOp::ApplyReplicatedKeyRecord { record })
            .await?
        {
            DirectoryOpResult::ReplicatedKeyOutcome(outcome) => Ok(outcome),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<KeyRecord>, Error> {
        match self
            .run_op(&DirectoryOp::LookupPublicKey {
                key_id: key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::PublicKey(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_keys_by_identity_type(
        &self,
        identity_type: &str,
    ) -> Result<Vec<KeyRecord>, Error> {
        // Only the ACCORD_HOLDER set has an op (the constitutional 2-of-3
        // verification set); any other identity_type is not routable.
        if identity_type != crate::federation::types::identity_type::ACCORD_HOLDER {
            return Err(Error::Unsupported {
                method: "list_keys_by_identity_type(non-accord)",
            });
        }
        match self.run_op(&DirectoryOp::ListAccordHolders {}).await? {
            DirectoryOpResult::KeyRecords(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_attestation(&self, attestation: SignedAttestation) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::PutAttestation { attestation })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_revocation(&self, revocation: SignedRevocation) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::PutRevocation { revocation })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_identity_occurrence(
        &self,
        occurrence: SignedIdentityOccurrence,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::PutIdentityOccurrence { occurrence })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_family(&self, family: SignedFamily) -> Result<(), Error> {
        match self.run_op(&DirectoryOp::PutFamily { family }).await? {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_community(&self, community: SignedCommunity) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::PutCommunity { community })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_location_proof(&self, proof: SignedLocationProof) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::PutLocationProof { proof })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_organizations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<Organization>, Error> {
        match self
            .run_op(&DirectoryOp::ListOrganizationsSince { since, limit })
            .await?
        {
            DirectoryOpResult::Organizations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_org_memberships_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<OrgMembership>, Error> {
        match self
            .run_op(&DirectoryOp::ListOrgMembershipsSince { since, limit })
            .await?
        {
            DirectoryOpResult::OrgMemberships(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn peer_metadata_for(&self, key_id: &str) -> Result<Option<PeerMetadataRow>, Error> {
        match self
            .run_op(&DirectoryOp::PeerMetadataFor {
                key_id: key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::PeerMetadata(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    // CIRISPersist#333 — the 6 peer-mutation methods override the trait
    // defaults (which return `Backend("… not implemented")`) so the proxy
    // routes them through persist's `.so` like every other covered op.
    // Edge's `federation_directory_for_edge` calls all six via UniFFI
    // `peer_*` + `reseed_canonical_bootstrap_peers` at init.
    async fn add_peer_record(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        identity_type: &str,
        transport_identity: Option<String>,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::AddPeerRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: pubkey_ed25519_base64.to_string(),
                identity_type: identity_type.to_string(),
                transport_identity,
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn remove_peer_record(&self, key_id: &str, hard: bool) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::RemovePeerRecord {
                key_id: key_id.to_string(),
                hard,
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn update_peer_alias(&self, key_id: &str, alias: Option<String>) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::UpdatePeerAlias {
                key_id: key_id.to_string(),
                alias,
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn update_peer_trust(&self, key_id: &str, trust: types::TrustClass) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::UpdatePeerTrust {
                key_id: key_id.to_string(),
                trust,
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn update_peer_notes(&self, key_id: &str, notes: Option<String>) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::UpdatePeerNotes {
                key_id: key_id.to_string(),
                notes,
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn update_peer_policy(
        &self,
        key_id: &str,
        policy: types::PeerPolicyBlob,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::UpdatePeerPolicy {
                key_id: key_id.to_string(),
                policy,
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn try_acquire_shared_instance(
        &self,
        instance_name: &str,
        owner_pid: i32,
        owner_hostname: &str,
        stale_after: Option<std::time::Duration>,
    ) -> Result<Option<shared_instance::SharedInstanceLease>, Error> {
        match self
            .run_op(&DirectoryOp::AcquireSharedInstanceLease {
                instance_name: instance_name.to_string(),
                owner_pid,
                owner_hostname: owner_hostname.to_string(),
                stale_after,
            })
            .await?
        {
            DirectoryOpResult::SharedLease(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn heartbeat_shared_instance(
        &self,
        lease: &shared_instance::SharedInstanceLease,
    ) -> Result<Option<shared_instance::SharedInstanceLease>, Error> {
        match self
            .run_op(&DirectoryOp::HeartbeatSharedInstance {
                lease: lease.clone(),
            })
            .await?
        {
            DirectoryOpResult::SharedLease(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn lookup_shared_instance_lease(
        &self,
        instance_name: &str,
    ) -> Result<Option<shared_instance::SharedInstanceLease>, Error> {
        match self
            .run_op(&DirectoryOp::LookupSharedInstanceLease {
                instance_name: instance_name.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SharedLease(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn release_shared_instance_lease(
        &self,
        lease: &shared_instance::SharedInstanceLease,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::ReleaseSharedInstanceLease {
                lease: lease.clone(),
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_transport_destination(
        &self,
        destination: &self_at_login::TransportDestination,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::PutTransportDestination {
                destination: destination.clone(),
            })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_transport_destinations_for(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        match self
            .run_op(&DirectoryOp::ListTransportDestinationsFor {
                occurrence_key_id: occurrence_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::TransportDestinations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_held_fountain_content(
        &self,
        publisher_key_id: &str,
    ) -> Result<Vec<crate::fountain::FountainHeldMeta>, Error> {
        match self
            .run_op(&DirectoryOp::ListHeldFountainContent {
                publisher_key_id: publisher_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::FountainHeld(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: crate::fountain::FountainTier,
    ) -> Result<u64, Error> {
        match self
            .run_op(&DirectoryOp::EvictFountainContentToTier {
                content_id: content_id.to_string(),
                corpus_kind: corpus_kind.to_string(),
                tier,
            })
            .await?
        {
            DirectoryOpResult::U64(n) => Ok(n),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<u64, Error> {
        match self
            .run_op(&DirectoryOp::EvictFountainContentHardDelete {
                content_id: content_id.to_string(),
                corpus_kind: corpus_kind.to_string(),
            })
            .await?
        {
            DirectoryOpResult::U64(n) => Ok(n),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    // ── uncovered REQUIRED methods: no DirectoryOp → Unsupported ────

    async fn lookup_keys_for_identity(&self, identity_ref: &str) -> Result<Vec<KeyRecord>, Error> {
        Err(Error::Unsupported {
            method: "lookup_keys_for_identity",
        })
    }
    async fn set_consent_role(
        &self,
        _key_id: &str,
        _consent_role: Option<&str>,
    ) -> Result<(), Error> {
        // v12.7.0 (CIRISPersist#365) — no DirectoryOp in the capsule
        // protocol carries consent_role mutation; not routable here.
        Err(Error::Unsupported {
            method: "set_consent_role",
        })
    }
    async fn attestation_upsert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, Error> {
        Err(Error::Unsupported {
            method: "attestation_upsert_local",
        })
    }
    async fn attestation_insert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, Error> {
        Err(Error::Unsupported {
            method: "attestation_insert_local",
        })
    }
    async fn list_attestations_for(
        &self,
        attested_key_id: &str,
    ) -> Result<Vec<Attestation>, Error> {
        Err(Error::Unsupported {
            method: "list_attestations_for",
        })
    }
    async fn list_attestations_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<Attestation>, Error> {
        Err(Error::Unsupported {
            method: "list_attestations_by",
        })
    }
    async fn attestations_binding_content(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<Attestation>, Error> {
        Err(Error::Unsupported {
            method: "attestations_binding_content",
        })
    }
    async fn revocations_for(&self, revoked_key_id: &str) -> Result<Vec<Revocation>, Error> {
        Err(Error::Unsupported {
            method: "revocations_for",
        })
    }
    async fn list_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<IdentityOccurrence>, Error> {
        Err(Error::Unsupported {
            method: "list_identity_occurrences_for",
        })
    }
    async fn lookup_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<IdentityOccurrence>, Error> {
        Err(Error::Unsupported {
            method: "lookup_identity_for_occurrence",
        })
    }
    async fn add_family_member(
        &self,
        family_key_id: &str,
        member: types::FamilyMember,
    ) -> Result<bool, Error> {
        Err(Error::Unsupported {
            method: "add_family_member",
        })
    }
    async fn lookup_family(&self, family_key_id: &str) -> Result<Option<Family>, Error> {
        Err(Error::Unsupported {
            method: "lookup_family",
        })
    }
    async fn list_families_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Family>, Error> {
        Err(Error::Unsupported {
            method: "list_families_for_member",
        })
    }
    async fn lookup_community(&self, community_key_id: &str) -> Result<Option<Community>, Error> {
        Err(Error::Unsupported {
            method: "lookup_community",
        })
    }
    async fn list_communities_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Community>, Error> {
        Err(Error::Unsupported {
            method: "list_communities_for_member",
        })
    }
    async fn put_identity_occurrence_revocation(
        &self,
        revocation: SignedIdentityOccurrenceRevocation,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_identity_occurrence_revocation",
        })
    }
    async fn put_family_membership_revocation(
        &self,
        revocation: SignedFamilyMembershipRevocation,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_family_membership_revocation",
        })
    }
    async fn put_community_membership_revocation(
        &self,
        revocation: SignedCommunityMembershipRevocation,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_community_membership_revocation",
        })
    }
    async fn list_identity_occurrence_revocations_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<IdentityOccurrenceRevocation>, Error> {
        Err(Error::Unsupported {
            method: "list_identity_occurrence_revocations_for",
        })
    }
    async fn list_family_membership_revocations_for(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<FamilyMembershipRevocation>, Error> {
        Err(Error::Unsupported {
            method: "list_family_membership_revocations_for",
        })
    }
    async fn list_community_membership_revocations_for(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<CommunityMembershipRevocation>, Error> {
        Err(Error::Unsupported {
            method: "list_community_membership_revocations_for",
        })
    }
    async fn list_location_proofs_for(
        &self,
        subject_key_id: &str,
    ) -> Result<Vec<LocationProof>, Error> {
        Err(Error::Unsupported {
            method: "list_location_proofs_for",
        })
    }
    async fn communities_containing(&self, cell_id: &str) -> Result<Vec<Community>, Error> {
        Err(Error::Unsupported {
            method: "communities_containing",
        })
    }
    async fn put_organization(
        &self,
        signed: SignedOrganization,
        key_directory: &[ciris_verify_core::threshold::ThresholdMember],
        root_stewards: &[String],
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_organization",
        })
    }
    async fn put_org_membership(
        &self,
        signed: SignedOrgMembership,
        key_directory: &[ciris_verify_core::threshold::ThresholdMember],
        root_stewards: &[String],
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_org_membership",
        })
    }
    async fn put_partner_record(
        &self,
        signed: SignedPartnerRecord,
        steward_roster: &[ciris_verify_core::threshold::ThresholdMember],
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_partner_record",
        })
    }
    async fn list_organizations_for(&self, org_id: &str) -> Result<Vec<Organization>, Error> {
        Err(Error::Unsupported {
            method: "list_organizations_for",
        })
    }
    async fn list_org_memberships_for(&self, org_id: &str) -> Result<Vec<OrgMembership>, Error> {
        Err(Error::Unsupported {
            method: "list_org_memberships_for",
        })
    }
    async fn list_partner_records_for(
        &self,
        license_id: &str,
    ) -> Result<Vec<PartnerRecord>, Error> {
        Err(Error::Unsupported {
            method: "list_partner_records_for",
        })
    }
    async fn list_partner_records_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<PartnerRecord>, Error> {
        Err(Error::Unsupported {
            method: "list_partner_records_since",
        })
    }
    async fn list_signed_partner_records_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<SignedPartnerRecord>, Error> {
        Err(Error::Unsupported {
            method: "list_signed_partner_records_since",
        })
    }
    async fn add_community_member(
        &self,
        community_key_id: &str,
        member: types::CommunityMember,
    ) -> Result<bool, Error> {
        Err(Error::Unsupported {
            method: "add_community_member",
        })
    }
    async fn supersede_group_row(
        &self,
        cohort: cohort::Cohort,
        new_snapshot: serde_json::Value,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, Error> {
        Err(Error::Unsupported {
            method: "supersede_group_row",
        })
    }
    async fn list_group_versions(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<cohort::GroupVersion>, Error> {
        Err(Error::Unsupported {
            method: "list_group_versions",
        })
    }
    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "attach_key_pqc_signature",
        })
    }
    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "attach_attestation_pqc_signature",
        })
    }
    async fn attach_revocation_pqc_signature(
        &self,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "attach_revocation_pqc_signature",
        })
    }
    async fn get_attestation(&self, attestation_id: &str) -> Result<Option<Attestation>, Error> {
        Err(Error::Unsupported {
            method: "get_attestation",
        })
    }
    async fn promote_attestation(
        &self,
        attestation_id: &str,
        scrub_signature_classical: &str,
        scrub_signature_pqc: Option<&str>,
        original_content_hash_hex: &str,
        scrub_key_id: &str,
        scrub_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Error> {
        Err(Error::Unsupported {
            method: "promote_attestation",
        })
    }
    async fn list_hybrid_pending_keys(&self, limit: i64) -> Result<Vec<HybridPendingRow>, Error> {
        Err(Error::Unsupported {
            method: "list_hybrid_pending_keys",
        })
    }
    async fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> Result<Vec<HybridPendingRow>, Error> {
        Err(Error::Unsupported {
            method: "list_hybrid_pending_attestations",
        })
    }
    async fn list_hybrid_pending_revocations(
        &self,
        limit: i64,
    ) -> Result<Vec<HybridPendingRow>, Error> {
        Err(Error::Unsupported {
            method: "list_hybrid_pending_revocations",
        })
    }
    async fn put_accord_proposal(
        &self,
        proposal: ciris_verify_core::accord_live_quorum::AccordProposal,
        authority_signature: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_accord_proposal",
        })
    }
    async fn get_accord_proposal(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<accord_quorum::StoredProposal>, Error> {
        Err(Error::Unsupported {
            method: "get_accord_proposal",
        })
    }
    async fn list_accord_proposals_by_anchor(
        &self,
        action: &str,
        prior_family_digest: &str,
    ) -> Result<Vec<accord_quorum::StoredProposal>, Error> {
        Err(Error::Unsupported {
            method: "list_accord_proposals_by_anchor",
        })
    }
    async fn put_accord_participation(
        &self,
        participation: ciris_verify_core::accord_live_quorum::AccordParticipation,
        standing_roster: &[ciris_verify_core::threshold::ThresholdMember],
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_accord_participation",
        })
    }
    async fn list_accord_participations(
        &self,
        proposal_digest: &str,
    ) -> Result<Vec<accord_quorum::StoredParticipation>, Error> {
        Err(Error::Unsupported {
            method: "list_accord_participations",
        })
    }
    async fn put_accord_decision(
        &self,
        decision: ciris_verify_core::accord_live_quorum::AccordDecision,
        steward_signatures: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "put_accord_decision",
        })
    }
    async fn get_accord_decision(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<accord_quorum::StoredDecision>, Error> {
        Err(Error::Unsupported {
            method: "get_accord_decision",
        })
    }
    async fn set_active_halt(
        &self,
        family_key_id: &str,
        active_halt_id: &str,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "set_active_halt",
        })
    }
    async fn get_active_halt(
        &self,
        family_key_id: &str,
    ) -> Result<Option<accord_quorum::ActiveHalt>, Error> {
        Err(Error::Unsupported {
            method: "get_active_halt",
        })
    }
    async fn clear_active_halt(
        &self,
        family_key_id: &str,
        active_halt_id: &str,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "clear_active_halt",
        })
    }
    async fn issue_accord_nonce(&self, family_key_id: &str, nonce: &str) -> Result<(), Error> {
        Err(Error::Unsupported {
            method: "issue_accord_nonce",
        })
    }
    async fn accord_nonce_issued(&self, family_key_id: &str, nonce: &str) -> Result<bool, Error> {
        Err(Error::Unsupported {
            method: "accord_nonce_issued",
        })
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
            consent_role: None,
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

    /// #375 — the anti-entropy-critical proof: an anchor-scrubbed record
    /// for an EXISTING self-signed key_id UPGRADES *through the C-ABI
    /// capsule* (the shape CIRISEdge's replication bridge holds). Backed by
    /// a real SqliteBackend so the upgrade plane exists — `Upgraded` is an
    /// outcome the pre-#375 default (`put_public_key` DO-NOTHING → `Unit`)
    /// could never produce, so reaching it proves the capsule now routes to
    /// the real upgrade-aware backend apply, not the insert-only fallback.
    #[cfg(feature = "sqlite")]
    #[test]
    fn apply_replicated_key_record_via_capsule_upgrades_sqlite() {
        use crate::federation::register::ReplicatedKeyOutcome as O;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type;
        use crate::store::backend::Backend;

        let rt = test_runtime();
        let backend = rt.block_on(async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .expect("open sqlite");
            b.run_migrations().await.expect("migrate");
            Arc::new(b)
        });
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let directory = build_persist_directory(dir.clone());

        // Seed the granting anchor, the node's single `user`-role owner, the
        // self-signed boot row, and the single-owner binding (owner_of).
        rt.block_on(async {
            ts::register_hybrid_key(dir.as_ref(), "cap-anchor").await;
            ts::register_identity_key(dir.as_ref(), "cap-owner", identity_type::USER).await;
            dir.apply_replicated_key_record(SignedKeyRecord {
                record: ts::replicated_key_record(
                    "cap-node",
                    identity_type::NODE,
                    "cap-node",
                    "cap-node",
                    "v1",
                ),
            })
            .await
            .expect("seed self-signed");
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(
                    &uuid::Uuid::new_v4().to_string(),
                    "cap-owner",
                    "cap-node",
                ),
            })
            .await
            .expect("owner-binding");
        });

        // The UPGRADE, driven entirely through the capsule build_op path.
        let scrubbed = ts::replicated_key_record(
            "cap-node",
            identity_type::NODE,
            "cap-anchor",
            "cap-anchor",
            "v1",
        );
        let res = run_op(
            &rt,
            &directory,
            &DirectoryOp::ApplyReplicatedKeyRecord {
                record: SignedKeyRecord { record: scrubbed },
            },
        );
        assert!(
            matches!(res, DirectoryOpResult::ReplicatedKeyOutcome(O::Upgraded)),
            "capsule apply must UPGRADE (not DO-NOTHING), got {res:?}"
        );
        // The backend row is really anchor-scrubbed now.
        let row = rt
            .block_on(dir.lookup_public_key("cap-node"))
            .expect("lookup")
            .expect("row");
        assert_eq!(row.scrub_key_id, "cap-anchor");

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn peer_mutation_ops_round_trip() {
        // CIRISPersist#333 — the 6 peer-mutation ops that edge's
        // `federation_directory_for_edge` invokes. Each must dispatch to
        // the real backend method (NOT the `Backend("… not implemented")`
        // trait default the proxy would otherwise inherit).
        let rt = test_runtime();
        let (dir, directory) = memory_directory();

        // AddPeerRecord → Unit, and the row is really there.
        let added = run_op(
            &rt,
            &directory,
            &DirectoryOp::AddPeerRecord {
                key_id: "peer-333".into(),
                pubkey_ed25519_base64: "AAAA".into(),
                identity_type: "agent".into(),
                transport_identity: Some("rns://abc".into()),
            },
        );
        assert!(
            matches!(added, DirectoryOpResult::Unit),
            "add_peer_record ⇒ Unit, got {added:?}"
        );
        let meta = rt
            .block_on(dir.peer_metadata_for("peer-333"))
            .expect("metadata query")
            .expect("peer row present");
        assert_eq!(meta.transport_identity.as_deref(), Some("rns://abc"));
        assert_eq!(meta.trust, types::TrustClass::Untrusted);

        // The four field-update ops each → Unit and mutate the row.
        for (op, label) in [
            (
                DirectoryOp::UpdatePeerAlias {
                    key_id: "peer-333".into(),
                    alias: Some("alias-1".into()),
                },
                "update_peer_alias",
            ),
            (
                DirectoryOp::UpdatePeerTrust {
                    key_id: "peer-333".into(),
                    trust: types::TrustClass::Trusted,
                },
                "update_peer_trust",
            ),
            (
                DirectoryOp::UpdatePeerNotes {
                    key_id: "peer-333".into(),
                    notes: Some("noted".into()),
                },
                "update_peer_notes",
            ),
            (
                DirectoryOp::UpdatePeerPolicy {
                    key_id: "peer-333".into(),
                    policy: types::PeerPolicyBlob(serde_json::json!({ "k": "v" })),
                },
                "update_peer_policy",
            ),
        ] {
            let r = run_op(&rt, &directory, &op);
            assert!(
                matches!(r, DirectoryOpResult::Unit),
                "{label} ⇒ Unit, got {r:?}"
            );
        }
        let meta = rt
            .block_on(dir.peer_metadata_for("peer-333"))
            .expect("metadata query")
            .expect("peer row present");
        assert_eq!(meta.trust, types::TrustClass::Trusted, "trust updated");
        assert_eq!(meta.alias.as_deref(), Some("alias-1"), "alias updated");

        // RemovePeerRecord (soft) → Unit; the row is then hidden from reads.
        let removed = run_op(
            &rt,
            &directory,
            &DirectoryOp::RemovePeerRecord {
                key_id: "peer-333".into(),
                hard: false,
            },
        );
        assert!(
            matches!(removed, DirectoryOpResult::Unit),
            "remove_peer_record ⇒ Unit, got {removed:?}"
        );
        assert!(
            rt.block_on(dir.peer_metadata_for("peer-333"))
                .expect("metadata query")
                .is_none(),
            "soft-removed peer is hidden from reads"
        );

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

    // ── #329: build_ops_directory consumer-proxy ───────────────────

    #[test]
    fn build_ops_directory_rejects_abi_skew() {
        // A capsule whose vtable advertises a newer ABI than this build
        // understands MUST be refused cleanly, never dispatched (a
        // mismatched layout could misdispatch). The proxy checks
        // `abi_version` before touching `data`/`build_op`, so a null data
        // pointer + dummy fns are safe here.
        unsafe extern "C" fn dummy_build_op(
            _: *mut c_void,
            _: *const u8,
            _: usize,
            _: ResultCallback,
            _: *mut c_void,
        ) -> *mut TaskOpaque {
            std::ptr::null_mut()
        }
        unsafe extern "C" fn dummy_drop(_: *mut c_void) {}
        static BAD_VTABLE: DirectoryVTable = DirectoryVTable {
            abi_version: DIRECTORY_ABI_VERSION + 1,
            _reserved: 0,
            build_op: dummy_build_op,
            drop: dummy_drop,
        };
        let bad = Directory {
            data: std::ptr::null_mut(),
            vtable: &BAD_VTABLE,
        };
        let rt = test_runtime();
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let res = build_ops_directory(bad, executor);
        assert!(res.is_err(), "abi skew must be refused");
    }

    #[test]
    fn ops_directory_put_then_lookup_round_trips() {
        // End-to-end proof: op → build_op → spawn → trampoline → oneshot
        // → deserialize. Drive the proxy futures on the same multi-thread
        // runtime that spawns the op-future (block_on on the caller
        // thread; the op-future runs on a worker; the oneshot bridges).
        let rt = test_runtime();
        let backend: Arc<MemoryBackend> = Arc::new(MemoryBackend::new());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory(directory, executor).expect("abi ok");

        let rec = sample_key_record("primitive-ops");
        rt.block_on(proxy.put_public_key(SignedKeyRecord {
            record: rec.clone(),
        }))
        .expect("proxy put_public_key");

        let via_proxy = rt
            .block_on(proxy.lookup_public_key("primitive-ops"))
            .expect("proxy lookup_public_key");
        let via_direct = rt
            .block_on(dir.lookup_public_key("primitive-ops"))
            .expect("direct lookup");
        assert_eq!(
            via_proxy, via_direct,
            "proxy result must equal a direct backend call"
        );
        assert_eq!(via_proxy.expect("some").key_id, "primitive-ops");
    }

    #[test]
    fn ops_directory_unsupported_method_errors() {
        // A REQUIRED method with no DirectoryOp must surface
        // `Error::Unsupported`, not route garbage.
        let rt = test_runtime();
        let backend: Arc<MemoryBackend> = Arc::new(MemoryBackend::new());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir);
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory(directory, executor).expect("abi ok");

        let err = rt
            .block_on(proxy.get_attestation("att-x"))
            .expect_err("get_attestation has no op → Unsupported");
        assert!(
            matches!(
                err,
                Error::Unsupported {
                    method: "get_attestation"
                }
            ),
            "got {err:?}"
        );
        assert_eq!(err.kind(), "federation_ops_proxy_unsupported");
    }
}
