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
//! so the structured error variant does not cross the ABI. Since v62.0.0
//! (ABI 14, CC 2.7) its READING does: a method failure is
//! [`DirectoryOpResult::TypedErr`] carrying the error's stable `kind()`
//! token, its [`crate::federation::Error::is_wait`] answer and its
//! `to_string()`, and the consumer proxy rebuilds it as
//! [`crate::federation::Error::Relayed`] (a `federation_backend` as
//! [`crate::federation::Error::Backend`]). Before v62 every failure was
//! [`DirectoryOpResult::Err`]`(String)`, rebuilt as `Backend`, so a
//! retryable ordering gap reached a capsule host as a database outage.
//! `Err(String)` remains for the failures with no federation kind.

use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::federation::admission::{reachable_under_scope_with_reasons, ReachabilityVerdict};
use crate::federation::types::{
    Attestation, Community, CommunityMembershipRevocation, Family, FamilyMembershipRevocation,
    IdentityOccurrence, IdentityOccurrenceRevocation, KeyRecord, LocationProof, PeerMetadataRow,
    Revocation, SignedCommunityMembershipRevocation, SignedFamilyMembershipRevocation,
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

/// v62.0.0 (CL-fix1) — **wire shape of a retired op; never evaluated.** The
/// `policy` member of the retired [`DirectoryOp::VerifyHybridViaDirectory`],
/// kept so the ABI-14 op stays byte-identical on the wire (append-only: a
/// retired op keeps its fields and refuses). Its serde encoding is the
/// earlier `HybridPolicy`'s: the same variant names and fields. Persist's
/// own hybrid-policy type is deleted and nothing reads this value: the op's
/// arm refuses `Unsupported` before looking at it. Re-exported at the old
/// path (`verify::hybrid::HybridPolicy`) only so the op's field text, which
/// the structural-digest pin hashes, is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetiredHybridPolicy {
    /// Wire value `"Strict"`.
    Strict,
    /// Wire value `{"SoftFreshness": {"window": …}}`.
    SoftFreshness {
        /// The earlier freshness window (never read).
        window: std::time::Duration,
    },
    /// Wire value `"Ed25519Fallback"`.
    Ed25519Fallback,
}

/// ABI version of [`DirectoryVTable`]. Bumped on any breaking change to
/// the vtable's layout or function-pointer signatures.
///
/// This is INDEPENDENT of [`DirectoryOp`]'s wire *growth*: appending a new
/// [`DirectoryOp`] variant does NOT bump this, because the vtable
/// signature (`build_op` takes opaque bytes) is unchanged — an older
/// consumer simply never emits the new variant, and a well-formed op it
/// does emit still round-trips. The version guards the *C-ABI shape*
/// (function-pointer count/order/signatures), which the serialized-op
/// design keeps stable across op growth.
///
/// **Growth is not the same as a break** (v32.0.0, CIRISPersist#682). When
/// an *existing* variant's field set or field types change, an older
/// consumer's well-formed op no longer round-trips: it emits the variant
/// by name, hits a `serde_json` type error, and gets an opaque
/// [`DirectoryOpResult::Err`] on the hot path instead of a diagnosis. The
/// `abi_version` field is the only signal a consumer can read at
/// capsule-receive time, before any op is dispatched, so a variant-shape
/// break MUST bump it — otherwise the load-time gate says "compatible"
/// about a contract the consumer was not compiled for, and the mismatch
/// surfaces later, further from its cause, as a serde error rather than
/// "pin floor too low".
///
/// v2 is that case: `ListSignedKeyRecordsSince` took a bare instant and
/// returned [`SignedKeyRecord`]s; it now takes the `(admitted_at, key_id)`
/// pair and returns [`crate::federation::ServedKeyRecord`]s. Breaking it
/// in place rather than appending a second op is deliberate — the old
/// cursor semantics are the #682 defect itself (a record replicated late
/// sorts under its producer's timestamp and is never served past it), and
/// preserving a reachable path to a known under-serving read, for
/// compatibility, would keep the vulnerability alive in exactly the
/// consumers slowest to upgrade.
///
/// v3 (v36.0.0, CIRISPersist#675) is the payload-type form of the same
/// break: [`DirectoryOpResult::AccordEvidenceAdmitted`] kept its name, but
/// its payload
/// [`AccordEvidenceAdmission`](crate::federation::accord_carriage::AccordEvidenceAdmission)
/// replaced `participations_admitted` — a differencing count that
/// mis-attributed under concurrent admissions — with the check-time-novelty
/// [`effect`](crate::federation::accord_carriage::AccordAdmissionEffect)
/// enum, which is what a consumer actually keyed the counter for
/// (Admitted-vs-Duplicate, per admission). An older consumer deserializes
/// the old struct with a non-defaulted field the new host no longer sends,
/// so its well-formed op fails on the hot path unless the load-time gate
/// says so first. The same version also carries growth that rides free:
/// [`DirectoryOpResult::AccordEvidenceCarrierRefused`] (CIRISPersist#674).
///
/// v6 (v50.0.0, CIRISPersist#928, review M3) is the payload-type form again:
/// [`crate::federation::ReachabilityVerdict`] gained `BeyondDepthCap` (CC
/// 4.1.1: a scope-bearing chain continues past the depth cap — too deep, not
/// absent), and an EXISTING op returns it inside
/// `DirectoryOpResult::Reachability`. An older consumer serde-fails on the hot
/// path (or, with a catch-all arm, misreports it as a substrate fault), so the
/// load-time gate must say so. The two enum-body digests do not move — the
/// verdict is a payload type outside their sight, exactly as v3's was.
///
/// v3 also carries the v2 break applied to the WHOLE cursor family
/// (v36.0.0, CIRISPersist#668): every remaining `List*Since` op takes the
/// `(serve position, resume id)` pair instead of a bare instant, and every
/// cursor result variant carries `Served*` wrappers (the record plus THIS
/// node's `admitted_at` beside it, never inside it). Broken in place for
/// the v2 reason verbatim: the old instant-only cursors ARE the #668/#682
/// defect (a tie larger than one page loses its remainder; a row
/// replicated late is never served past its producer's timestamp), and
/// preserving a reachable path to a known under-serving read would keep
/// the vulnerability alive in exactly the consumers slowest to upgrade.
///
/// v7 (v52.0.0, CIRISPersist#784) — a PAYLOAD break, like v6's: the
/// [`Revocation`] carried by `DirectoryOpResult::Revocations` /
/// `SignedRevocations` names its subject by `revoked_key_sha256_ed25519_raw`
/// (required) and its `revoked_key_id` became optional. An older consumer
/// serde-fails on a digest-only row. `RevocationsForSubject` is APPENDED
/// (growth). The enum-body digests move only for that growth.
///
/// v8 (v58.0.0, CIRISPersist#991) — a PAYLOAD break, like v6's and v7's:
/// [`AttestationRefusalReason`](crate::federation::attestation_apply::AttestationRefusalReason),
/// carried inside the existing `DirectoryOpResult::ReplicatedAttestationOutcome`,
/// gained `KeyPlaneRefused` (a key-plane row whose family door did not apply
/// its object). An older consumer serde-fails on it. The framed key-plane ops
/// (`ListSignedKeyRecordsSince`, `ListSignedRevocationsSince`,
/// `ListSignedIdentityOccurrencesSince`,
/// `ListSignedIdentityOccurrenceRevocationsSince`,
/// `PutIdentityOccurrenceRevocation` and their results) were removed on the
/// release branch and are restored with their v7 names and shapes (compat
/// reads, operator ruling 2026-10-18): the op set is v7's, and against the
/// branch's 8 the restoration is growth, which by the rule above does not bump.
///
/// v9 (v59.0.0, sealed-transport floor, operator ruling 2026-10-19; CC
/// 5.3.3.5 E1 option (i)) — a BREAK: the framed key-plane compat reads are
/// REMOVED (`ListSignedKeyRecordsSince`, `ListSignedRevocationsSince`,
/// `ListSignedIdentityOccurrencesSince`,
/// `ListSignedIdentityOccurrenceRevocationsSince` and their results
/// `SignedKeyRecords`, `SignedRevocations`, `SignedIdentityOccurrencesSince`,
/// `SignedIdentityOccurrenceRevocationsSince`), and
/// `PutIdentityOccurrenceRevocation`'s payload is raw JSON answered with the
/// refusal `federation_envelope_kind_retired: identity_occurrence_revocation`;
/// `ApplyReplicatedKeyRecord` answers `federation_envelope_kind_retired: key`.
/// Every RNS byte rides a per-link hybrid seal, so an unsealed pre-v58 peer
/// these ops served is unreachable; the key plane replicates as rows
/// (`ApplyReplicatedAttestation`).
///
/// v10 (v59.0.0, CIRISPersist#1064, CIRISEdge) — `AttestationRefusalReason`,
/// inside the existing `ReplicatedAttestationOutcome` result, gains
/// `SelfRosterPending` (an open self-roster proposal: retryable), split out of
/// `KeyPlaneRefused` (terminal). A consumer built against 9 fails to decode it
/// on the hot path (the v6 / v8 payload-type form).
///
/// v11 (v60.0.0, CIRISPersist#1036 item 4, CC 3.3.9) — a BREAK: the
/// operational kinds retired onto affiliation rows, so the ops
/// `ListOrgMembershipsSince` / `ListOrganizationsSince` and their results
/// `OrgMemberships` / `Organizations` are REMOVED (their tables went at
/// V205). A consumer built against 10 sends ops this host no longer decodes.
///
/// v12 (v61, CIRISPersist#991, CC 3.1.3) — a BREAK: a group's record and its
/// widening and revocation planes are rows on the attestation plane
/// (`group:roster:v1`, `membership:{widening,removal,resignation}:v1`), and
/// their six framed kinds joined `RETIRED_FRAMED`. The ops
/// `ListSignedFamiliesSince`, `ListSignedCommunitiesSince`,
/// `ListSignedFamilyMembershipRevocationsSince`,
/// `ListSignedFamilyMembershipWideningsSince`,
/// `ListSignedCommunityMembershipRevocationsSince`,
/// `ListSignedCommunityMembershipWideningsSince` and
/// `ApplyReplicatedCommunity` and their results are REMOVED: the rows ride
/// `ApplyReplicatedAttestation` and the attestation cursor. A consumer built
/// against 11 sends ops this host no longer decodes.
/// The same break retires the member listing with no successor (the
/// steward's ruling: no outward member listing): the op
/// `ListSignedCommunityMembershipListingsSince` and its result
/// `SignedCommunityMembershipListings` are REMOVED.
///
/// v13 (v61.3.0, CIRISPersist#1252, CC 3.3.4) — `ReplicatedAttestationOutcome`
/// (the payload of the existing attestation-apply result) gains
/// `HeldEquivalent` (`"held_equivalent"`): this node holds the same act under
/// another row (an assembled widening or removal with a different sufficient
/// subset of cosignatures, other randomised ML-DSA bytes, or a `cosign:*` row
/// of the same signer). A consumer built against 12 fails to decode it on the
/// hot path (the v6 / v8 / v10 payload-type form).
///
/// v14 (v62.0.0, CC 2.7) — the result wire gains
/// [`DirectoryOpResult::TypedErr`] ([`CapsuleError`]: the error's kind, its
/// [`Error::is_wait`] and its text), and every op whose method answers a
/// federation error now fails with it instead of `Err(String)`. A consumer
/// built against 13 fails to decode an existing op's failure (the v5
/// `AttestationOutcome` form).
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
pub const DIRECTORY_ABI_VERSION: u32 = 14;

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
    /// constitutional verification set (CIRISEdge#19), counted at a strict
    /// majority of the holders of the bundle in force (2·yes > N).
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
    /// `verify_hybrid_via_directory` (deleted v62.0.0)`(dir,
    /// …)` does MULTIPLE directory lookups + the Ed25519/ML-DSA-65 hybrid
    /// verification internally — a raw-`dyn` vtable misdispatch here would
    /// silently verify against the wrong method (accept a forged signature),
    /// so this MUST run inside persist's `.so`. `canonical_bytes` is the
    /// exact bytes the signatures cover.
    ///
    /// v62.0.0 (F0-cp5; RULINGS "composite signatures only") — RETIRED: the
    /// arm refuses `Unsupported { method: "verify_hybrid_via_directory" }`
    /// and reads nothing. Kept (append-only) so an old consumer's op is
    /// answered by name; use [`DirectoryOp::VerifyCompositeViaDirectory`].
    VerifyHybridViaDirectory {
        /// The canonical bytes the signatures were computed over.
        canonical_bytes: Vec<u8>,
        /// The claimed signing key id (resolved against the directory).
        signing_key_id: String,
        /// Base64 Ed25519 signature.
        ed25519_sig_b64: String,
        /// Base64 ML-DSA-65 signature (absent for classical-only rows).
        ml_dsa_65_sig_b64: Option<String>,
        /// The hybrid-verification policy. v61.1.0 (CIRISPersist#1233,
        /// CC 5.3.2.4.3.1): only [`HybridPolicy::Strict`](crate::verify::hybrid::HybridPolicy::Strict)
        /// is accepted; any other variant is refused inside `HybridVerify`
        /// with `verify_policy_violation`. The field is removed in v62.
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
        /// v38.0.0 (CIRISPersist#721) — WHY. Required non-empty: a removal
        /// is an attributed act, announced on the hard_case plane.
        /// `#[serde(default)]` so an old consumer's payload still DECODES —
        /// and then refuses with the typed reason-required error rather
        /// than a decode error.
        #[serde(default)]
        reason: String,
        /// The `delegates_to` id the actor acts under (recorded, not
        /// resolved — the admin_field discipline).
        #[serde(default)]
        acting_under_delegation_id: Option<String>,
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
    /// [`FederationDirectory::lookup_identity_for_occurrence`] (#397) — the
    /// reverse occurrence→identity lookup the agent's embedded edge needs to
    /// resolve a peer's kex pubkeys (`resolve_peer_kex_pubkeys`). Without this
    /// op the capsule proxy surfaced [`Error::Unsupported`], so an
    /// explicit-hash canonical (which cannot announce) was unrootable — the
    /// resolve path erred instead of resolving. APPEND-ONLY: added at the end.
    LookupIdentityForOccurrence {
        /// The occurrence `key_id` to reverse-resolve to its identity row.
        occurrence_key_id: String,
    },
    /// [`FederationDirectory::list_all_transport_destinations`] (#411) — every
    /// stored reachable address across ALL occurrences, for the boot reload
    /// (edge's embedded `dyn FederationDirectory` repopulates its rooted-peers
    /// map + KEX resolver on startup, incl. the transport-tier x25519). Result
    /// rides the existing `TransportDestinations` variant. APPEND-ONLY.
    ListAllTransportDestinations {},
    /// [`FederationDirectory::list_transport_destinations_by_destination`] (#413)
    /// — every claimant of one dest-hash, so the routing layer can prefer a
    /// `rooted` binding over an `advisory` one (competing-claims / AV-42-spoof
    /// resolution by preference). Result rides `TransportDestinations`.
    /// APPEND-ONLY.
    ListTransportDestinationsByDestination {
        /// The dest-hash (`TransportDestination::destination`) to list claimants of.
        destination: String,
    },
    /// [`FederationDirectory::list_signed_identity_occurrences_for`] (#418
    /// replication read) — the signed-put occurrences of an identity, each
    /// carrying its original `{attesting_key_id, signed_envelope, signature}`
    /// container. The embedded edge (CIRISEdge#305) re-wraps these verbatim to
    /// re-publish to a peer: it holds the transport signer, not the identity's
    /// federation key, so it CANNOT re-sign — the tuple must round-trip
    /// byte-exact. Result rides the new `SignedIdentityOccurrences` variant.
    /// APPEND-ONLY.
    ListSignedIdentityOccurrencesFor {
        /// The identity `key_id` whose signed occurrences to enumerate.
        identity_key_id: String,
    },
    /// [`FederationDirectory::list_signed_records`] (#425) — the uniform signed
    /// read: every replicated record of `kind` for `subject_key_id` as a
    /// byte-exact [`SignedReplicatedRecord`](crate::federation::namespace::SignedReplicatedRecord).
    /// The edge replication engine sweeps a subject across
    /// [`ReplicatedKind::all`](crate::federation::namespace::ReplicatedKind::all)
    /// through this ONE op instead of a bespoke selector per plane. Result rides
    /// the new `SignedReplicatedRecords` variant. APPEND-ONLY.
    ListSignedRecords {
        /// Which replicated CEG object kind to fetch.
        kind: crate::federation::namespace::ReplicatedKind,
        /// The subject `key_id` whose records to enumerate.
        subject_key_id: String,
    },
    /// [`FederationDirectory::put_identity_occurrence_revocation`] (#421) — the
    /// SIGNED revocation apply: the wire path edge's replication bridge drives
    /// (`apply_identity_occurrence_revocation` delegates to `put`, exactly like
    /// the occurrence). The gate (hybrid 1-of-1 over `JCS(signed_envelope)` +
    /// `signer_acts_for` + divergence check) runs INSIDE persist's `.so` at
    /// dispatch — a forged revocation is refused before any write. Result rides
    /// `Unit`. APPEND-ONLY.
    ///
    /// v59.0.0 (sealed-transport floor, operator ruling 2026-10-19) — RETIRED:
    /// the framed occurrence revocation is no longer admitted. The variant is
    /// kept, its payload read as raw JSON, so an old consumer's op is answered
    /// with the typed refusal `federation_envelope_kind_retired:
    /// identity_occurrence_revocation` instead of a decode error.
    PutIdentityOccurrenceRevocation {
        /// The retired framed object, unread.
        revocation: serde_json::Value,
    },
    /// [`FederationDirectory::put_signed_transport_destination`] (#443) — the
    /// AUTHENTICATED route-plane replication apply: the wire path edge's
    /// replication bridge drives instead of the trusted-local
    /// `PutTransportDestination` (which stays for the node's OWN routes). The
    /// gate (hybrid 1-of-1 over `JCS(signed_envelope)` against the pinned key
    /// of `attesting_key_id` + `signer_acts_for` + divergence check) runs
    /// INSIDE persist's `.so` at dispatch, then the `(epoch, asserted_at)`
    /// monotonic guard applies — a forged or stale route is refused before /
    /// without any write. Result rides the new
    /// `TransportDestinationApplyOutcome` variant. APPEND-ONLY.
    PutSignedTransportDestination {
        /// The signed route record to apply.
        signed: self_at_login::SignedTransportDestination,
    },
    /// [`FederationDirectory::list_signed_transport_destinations_for`] (#443)
    /// — the route-plane signed replication read: SIGNED-put rows (incl.
    /// retired tombstones) with their byte-exact signature container, so the
    /// edge re-publishes routes it cannot re-sign (the #418/#421 pattern).
    /// Result rides the new `SignedTransportDestinations` variant.
    /// APPEND-ONLY.
    ListSignedTransportDestinationsFor {
        /// The occurrence `key_id` whose signed routes to enumerate.
        occurrence_key_id: String,
    },
    /// [`FederationDirectory::resolve_encryption_keys`] (#329 field hit,
    /// CIRISServer#260) — the v14 REVOCATION-AWARE seal lookup as ONE
    /// composite op. The whole fold (occurrence lookup → validity window →
    /// the v16 `revokes()` re-establishment comparator over the identity's
    /// revocations) executes INSIDE persist's `.so` at dispatch: routing the
    /// composite — rather than only the raw revocations read — means a
    /// cohabiting consumer pinned to an older persist crate can never run a
    /// STALE comparator against newer data (the #320 skew class, on the
    /// seal-safety path). `None` ⇒ recipient excluded from v2 grants
    /// (fail-secure; never a plaintext fallback). Result rides the new
    /// `EncryptionKeys` variant. APPEND-ONLY.
    ResolveEncryptionKeys {
        /// The occurrence `key_id` whose CURRENT v2 KEX pubkeys to resolve.
        occurrence_key_id: String,
    },
    /// [`FederationDirectory::list_identity_occurrence_revocations_for`]
    /// (#329 field hit) — the raw revocation-plane read, routed so
    /// revocation-aware consumer logic (and the trait's default folds) can
    /// run against the ops proxy at all. Prefer the `ResolveEncryptionKeys`
    /// composite for SEALING decisions (comparator stays in the `.so`); this
    /// raw read is for enumeration/observability. Result rides the new
    /// `IdentityOccurrenceRevocations` variant. APPEND-ONLY.
    ListIdentityOccurrenceRevocationsFor {
        /// The identity `key_id` whose occurrence revocations to enumerate.
        identity_key_id: String,
    },
    /// [`FederationDirectory::list_scores`] (v17.4.0, FSD-005 Appendix C) —
    /// the durable `scores` LIST read routed as a composite op: the §4.3
    /// caller gate + the ordered subject+dimension seek run INSIDE persist's
    /// `.so` at dispatch. Result rides the new `Scores` variant. APPEND-ONLY.
    ListScores {
        /// The reading occurrence's `key_id` (empty ⇒ unauthenticated).
        caller_occurrence_key_id: String,
        /// The `ScoresQuery` filter (extended `AttestationFilter`).
        filter: crate::read::AttestationFilter,
        /// Opaque `(asserted_at, attestation_id)` page cursor.
        cursor: Option<crate::read::AttestationCursor>,
        /// Page size (1..=10_000).
        limit: i64,
    },
    /// [`FederationDirectory::resolve_scores`] (v17.4.0, FSD-005 Appendix C) —
    /// the composed-verdict fold routed as a composite op (the #329 pattern):
    /// the WHOLE gate + precedence latest-wins fold + polarity aggregation
    /// runs inside persist's `.so`, so a cohabiting consumer can never run a
    /// STALE composer against newer data. Result rides the new
    /// `ComposedVerdict` variant. APPEND-ONLY.
    ResolveScores {
        /// The reading occurrence's `key_id` (empty ⇒ unauthenticated).
        caller_occurrence_key_id: String,
        /// The `ScoresQuery` filter (extended `AttestationFilter`).
        filter: crate::read::AttestationFilter,
        /// The composition policy id (CC 4.4.3).
        policy: String,
        /// When true, populate the verdict's derivation trace.
        trace: bool,
    },
    /// [`FederationDirectory::list_attestation_log`] (v17.5.0, CIRISPersist#455)
    /// — the OWNER-scope replication log walk beside the caller-gated
    /// `ListScores` consumer read. NO caller gate, NO lifecycle folding,
    /// federation-tier, byte-faithful rows — the relay enumerates its own
    /// store to decide what to gossip (edge's advertise sweep). `None`
    /// subject = full-log anti-entropy walk. Result rides `Scores`.
    /// APPEND-ONLY.
    ListAttestationLog {
        /// Subject `key_id` to seek, or `None` for the full-log walk.
        subject_key_id: Option<String>,
        /// Opaque `(asserted_at, attestation_id)` page cursor.
        cursor: Option<crate::read::AttestationCursor>,
        /// Page size (1..=10_000).
        limit: i64,
    },
    /// [`FederationDirectory::record_announced_peer`] (v17.8.0,
    /// CIRISPersist#469) — the seeder bridge: record a self-consistent but
    /// UNROOTED LAN announce as a non-canonical, untrusted discovery
    /// bookmark. NOT an admission; never an authority. Edge calls this from
    /// `resolve_announce_cold_start`'s Advisory admit path, beside the
    /// transport-binding write. Result rides `Unit`. APPEND-ONLY.
    RecordAnnouncedPeer {
        /// The announced occurrence `key_id` (NOT in `federation_keys`).
        key_id: String,
        /// Ed25519 pubkey from the announce, base64 standard.
        pubkey_ed25519_base64: String,
        /// ML-DSA-65 pubkey when the announce carried it.
        pubkey_ml_dsa_65_base64: Option<String>,
        /// The identity_type the announce CLAIMED (advisory only).
        claimed_identity_type: Option<String>,
        /// Announce receipt time (RFC 3339 → DateTime).
        last_seen: chrono::DateTime<chrono::Utc>,
    },
    /// [`FederationDirectory::list_announced_peers`] (v17.8.0,
    /// CIRISPersist#469) — the live (not-yet-admitted) bookmarks, newest
    /// `last_seen_at` first. Result rides `AnnouncedPeers`. APPEND-ONLY.
    ListAnnouncedPeers,
    /// [`crate::federation::trust_root::trust_root_valid`] (v18.2.0,
    /// CIRISPersist#481) — the pluggable-trust-root graph predicate
    /// (edge + self-declaration + heartbeat + halt latch), served from
    /// persist so server/edge/agent share ONE implementation. Result rides
    /// `TrustRootVerdict`. APPEND-ONLY.
    TrustRootValid {
        /// The trusting user/node occurrence key.
        user_key_id: String,
        /// The candidate external root key.
        root_key_id: String,
    },
    /// [`crate::federation::trust_root::capability_roots_to_trusted_root`]
    /// (v18.3.0, CIRISPersist#483) — the composed capability walk: does
    /// `subject_key_id` hold `scope`, granted by a root `user_key_id`
    /// trusts? The `ConferralPlane::Delegation` half of CIRISEdge#386's
    /// trace serve gate. APPEND-ONLY.
    CapabilityRootsToTrustedRoot {
        /// The local node asking.
        user_key_id: String,
        /// The peer whose capability is in question.
        subject_key_id: String,
        /// The delegation scope token (e.g. `infra:serve`).
        scope: String,
    },
    /// [`FederationDirectory::list_consent_peers`] (v21.0.0,
    /// CIRISPersist#502 E7) — the revocation-folded `consent_peer_set`
    /// read: `node_key_id`'s live `consent:replication:v1` peers. Result
    /// rides `ConsentPeers`. APPEND-ONLY.
    ListConsentPeers {
        /// The granting node whose live peer set is asked for.
        node_key_id: String,
    },
    /// [`FederationDirectory::list_signed_location_proofs_since`] (v21.0.0,
    /// CIRISPersist#504 FLOOR). Structural mirror of
    /// the other signed cursors. Result rides `SignedLocationProofs`.
    /// APPEND-ONLY.
    ListSignedLocationProofsSince {
        /// Cursor: rows with `asserted_at > since` (None ⇒ from start).
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        /// Page cap.
        limit: u32,
    },
    /// [`FederationDirectory::list_signed_transport_destinations_since`]
    /// (v21.1.0, CIRISPersist#507c). Structural mirror of
    /// [`DirectoryOp::ListSignedKeyRecordsSince`]. Result rides
    /// `SignedTransportDestinationsSince`. APPEND-ONLY.
    ListSignedTransportDestinationsSince {
        /// Cursor: rows with `asserted_at > since` (None ⇒ from start).
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        /// Page cap.
        limit: u32,
    },
    /// [`FederationDirectory::list_attestations_since`] (v21.1.0,
    /// CIRISPersist#507c) — federation-tier-only bulk read (the E5
    /// invariant). Result rides `Attestations`. APPEND-ONLY.
    ListAttestationsSince {
        /// Cursor: rows with `asserted_at > since` (None ⇒ from start).
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        /// Page cap.
        limit: u32,
    },
    /// [`FederationDirectory::lookup_signed_record_by_content_hash`]
    /// (v21.1.0, CIRISPersist#507b) — the content-hash point-read. Result
    /// rides `OptionalBytes`. APPEND-ONLY.
    LookupSignedRecordByContentHash {
        /// The `EnvelopeKind::as_str()` token.
        kind: String,
        /// Lowercase-hex sha256 over the record's wire JSON bytes.
        content_hash: String,
    },
    /// [`FederationDirectory::rebuild_signed_wire_index`] (v21.1.0,
    /// CIRISPersist#507b) — full backfill/rebuild of `signed_wire_index`.
    /// Result rides `U64` (rows indexed). APPEND-ONLY.
    RebuildSignedWireIndex,
    /// [`crate::federation::trust_root::resolve_transit_eligibility`]
    /// (v24.1.0, CIRISPersist#561) — may `peer_key_id` carry our relay
    /// traffic, and for how long may the answer be cached? The substrate half
    /// of CIRISEdge#430's A/V hop-selection gate: edge resolves ONCE per
    /// candidate through this op, caches `(eligible, valid_until)`, and keeps
    /// the selection hot path crypto-free. Result rides
    /// `TransitEligibility`. APPEND-ONLY.
    ResolveTransitEligibility {
        /// "Us" — the selecting node.
        user_key_id: String,
        /// The candidate hop.
        peer_key_id: String,
    },
    /// [`FederationDirectory::revocations_for`] (v31.1.0, CIRISPersist#655) —
    /// the key-level revocation rows for a subject. Was the capsule's only
    /// hard-`Unsupported` on an EXCLUSION plane: a host running behind the
    /// capsule proxy could store a revocation and then not read it back, so
    /// the plane it needs in order to exclude anything was invisible to it.
    /// Result rides `Revocations`. APPEND-ONLY.
    RevocationsFor {
        /// The subject whose revocations to list.
        revoked_key_id: String,
    },
    /// [`FederationDirectory::list_signed_accord_quorum_evidence_since`]
    /// (v31.1.0, CIRISPersist#662) — the signed accord EVIDENCE cursor.
    /// Result rides `AccordQuorumEvidence`. APPEND-ONLY.
    ListSignedAccordQuorumEvidenceSince {
        /// Cursor: bundles with `evidence_at > since` (None ⇒ from start).
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        /// Page cap, counted in PROPOSALS.
        limit: u32,
    },
    /// [`FederationDirectory::apply_replicated_accord_evidence`] (v31.1.0,
    /// CIRISPersist#662) — the RECEIVE half of the evidence plane, as ONE op.
    ///
    /// It has to be one op rather than the five primitives the free function
    /// composes: those primitives are `Unsupported` on this proxy, so a
    /// capsule-backed consumer could otherwise serve evidence and never apply
    /// it. Routing the whole admission also keeps the re-tally inside
    /// persist's `.so`, where a consumer cannot reassemble it differently.
    /// Result rides `AccordEvidenceAdmitted`. APPEND-ONLY.
    ApplyReplicatedAccordEvidence {
        /// The bundle to re-tally and admit.
        evidence: crate::federation::accord_carriage::AccordQuorumEvidence,
    },
    /// [`FederationDirectory::list_wire_hashes_since`] (v38.7.0,
    /// CIRISPersist#780) — the complete HELD hash set for one wire kind,
    /// index-only. Result rides [`DirectoryOpResult::WireHashes`].
    ///
    /// Added in CIRISPersist#785, not #780: the trait method shipped in
    /// v38.7.0 with a DEFAULT body and no op, so a capsule consumer got
    /// `Unsupported` for the very read #780 exists to provide, while its two
    /// neighbours routed fine. APPEND-ONLY.
    ListWireHashesSince {
        /// The `EnvelopeKind::as_str()` token.
        kind: String,
        /// Exclusive cursor; `None` starts at the first hash.
        after_content_hash: Option<String>,
        /// Page size.
        limit: u32,
    },
    /// [`FederationDirectory::insert_known_wire_hash`] (CIRISPersist#785) —
    /// record that a hash EXISTS without holding its body. Result rides
    /// [`DirectoryOpResult::Unit`]. APPEND-ONLY.
    InsertKnownWireHash {
        /// The `EnvelopeKind::as_str()` token.
        kind: String,
        /// Canonical lowercase 64-hex sha256; refused otherwise.
        content_hash: String,
        /// LOCAL-ONLY observation of who advertised it — never replicated.
        advertised_by: Option<String>,
        /// The observation instant. Applied MONOTONICALLY: an older sighting
        /// arriving late does not move the stored value backwards.
        now: chrono::DateTime<chrono::Utc>,
    },
    /// [`FederationDirectory::known_wire_hash_contains`] (CIRISPersist#785).
    /// Result rides [`DirectoryOpResult::Bool`]. APPEND-ONLY.
    KnownWireHashContains {
        /// The `EnvelopeKind::as_str()` token.
        kind: String,
        /// The hash to look for.
        content_hash: String,
    },
    /// [`FederationDirectory::list_known_wire_hashes_since`]
    /// (CIRISPersist#785) — page the KNOWN set, cursored on the hash. Result
    /// rides [`DirectoryOpResult::KnownWireHashes`]. APPEND-ONLY.
    ListKnownWireHashesSince {
        /// The `EnvelopeKind::as_str()` token.
        kind: String,
        /// Exclusive cursor; `None` starts at the first hash.
        after_content_hash: Option<String>,
        /// Page size.
        limit: u32,
    },
    /// [`FederationDirectory::evict_known_wire_hashes`] (CIRISPersist#785) —
    /// evict on a CALLER-SUPPLIED cutoff. Result rides
    /// [`DirectoryOpResult::KnownHashEviction`]. APPEND-ONLY.
    EvictKnownWireHashes {
        /// Entries not advertised since this instant are evicted. The caller
        /// owns this number — persist never derives it, because the safe
        /// floor is one wrap period of the caller's own re-sweep.
        cutoff: chrono::DateTime<chrono::Utc>,
        /// Soft cap. The floor WINS: an overage is reported, not resolved by
        /// evicting below the cutoff.
        bound: u64,
    },
    /// v41.0.0 (CIRISPersist#804) — publish a row THIS NODE AUTHORED, as
    /// distinct from [`Self::PutAttestation`], which admits a row from
    /// elsewhere. APPEND-ONLY (Growth): a new variant at the end, so an older
    /// consumer's dispatch is unaffected and `DIRECTORY_ABI_VERSION` does not
    /// move.
    ///
    /// It is a separate OP rather than a flag on `PutAttestation` because the
    /// two are different acts with different budgets, and a bool on the wire
    /// is a thing a caller can get wrong silently. Answers with
    /// [`DirectoryOpResult::AttestationOutcome`], exactly as its sibling does.
    PutAttestationAuthored {
        /// The signed row this node just authored.
        attestation: SignedAttestation,
    },
    /// v41.0.0 (CIRISPersist#804) — the privileged SYNC door across the ABI:
    /// a row delivered over a session the transport authenticated as
    /// `authenticated_peer_key_id`. APPEND-ONLY (Growth).
    ///
    /// The identity travels because it is the whole basis of the privilege —
    /// a proxy that dropped it would silently demote every synced row to
    /// stranger metering, which is the defect this door exists to fix. The
    /// far side still decides whether that identity is a cohort-mate, from
    /// its own rosters.
    PutAttestationSynced {
        /// The signed row.
        attestation: SignedAttestation,
        /// The identity the TRANSPORT authenticated — never the row's claim.
        authenticated_peer_key_id: String,
    },
    /// v50.0.0 (CIRISPersist#917) —
    /// [`FederationDirectory::apply_replicated_attestation`], the typed
    /// unattributed door. The far side runs the whole plan-then-write body
    /// against its own backend, so the outcome is decided where the stored
    /// row is. Result rides `ReplicatedAttestationOutcome`. APPEND-ONLY
    /// (Growth).
    ApplyReplicatedAttestation {
        /// The signed row.
        attestation: SignedAttestation,
    },
    /// v50.0.0 (CIRISPersist#917) —
    /// [`FederationDirectory::put_attestation_synced`], the typed attributed
    /// door. [`DirectoryOp::PutAttestationSynced`] stays the untyped
    /// stored-write door for consumers built before v50. Result rides
    /// `ReplicatedAttestationOutcome`. APPEND-ONLY (Growth).
    ApplyReplicatedAttestationSynced {
        /// The signed row.
        attestation: SignedAttestation,
        /// The identity the TRANSPORT authenticated — never the row's claim.
        authenticated_peer_key_id: String,
    },
    /// v51.0.0 (CIRISPersist#938, CC 3.2 T6 rc6) —
    /// [`FederationDirectory::put_lineage_head_cosign`], the witness plane's
    /// door: a replication bridge forwards a `ciris.lineage_head_cosign.v1`
    /// object. Result rides `LineageCosignOutcome`. APPEND-ONLY (Growth).
    PutLineageHeadCosign {
        /// The cosign received from a peer or a witness.
        cosign: crate::federation::lineage_witness::LineageHeadCosign,
    },
    /// v50.0.0 (CIRISPersist#928, final check) —
    /// [`FederationDirectory::withdraws_admission_depth`]: the depth a stored
    /// `withdraws` was admitted under, so a capsule consumer re-deriving it at
    /// read time walks the ROW's depth instead of guessing. Result rides
    /// `WithdrawsAdmissionDepth`. APPEND-ONLY (Growth).
    WithdrawsAdmissionDepth {
        /// The `withdraws` row's id.
        attestation_id: String,
    },
    /// v52.0.0 (CIRISPersist#784) —
    /// [`FederationDirectory::revocations_for_subject`]: the revocations whose
    /// SUBJECT is this `sha256_ed25519_raw` digest, whether or not the key is
    /// held. Result rides `Revocations`. APPEND-ONLY (Growth).
    RevocationsForSubject {
        /// The subject key's `sha256_ed25519_raw` (64 lowercase hex).
        revoked_key_sha256_ed25519_raw: String,
    },
    /// CIRISPersist#973 (CC 3.2 T4a) —
    /// [`FederationDirectory::trust_direction_held_among`]: which of these
    /// unlabelled `delegates_to` rows the node held when the label became
    /// required, so a capsule consumer reads a held row the way the backend
    /// does instead of denying it. Result rides `WireHashes` (the
    /// `Vec<String>` shape). APPEND-ONLY (Growth).
    TrustDirectionHeldAmong {
        /// The candidate rows' ids.
        attestation_ids: Vec<String>,
    },
    /// [`FederationDirectory::list_key_plane_wire_hashes_since`] (v60.0.0,
    /// CIRISPersist#1105) — the HELD hash set of one key-plane family,
    /// routed so a capsule consumer (Edge) reaches the read the ask was for
    /// rather than the trait default. Result rides
    /// [`DirectoryOpResult::WireHashes`]. APPEND-ONLY (Growth): a new variant
    /// at the end, so `DIRECTORY_ABI_VERSION` does not move.
    ListKeyPlaneWireHashesSince {
        /// One of `key_plane::HOLDINGS_FAMILIES`.
        family: String,
        /// Exclusive cursor; `None` starts at the first hash.
        after_content_hash: Option<String>,
        /// Page size.
        limit: u32,
    },
    /// v59.1.2 (CIRISPersist#1162) —
    /// [`FederationDirectory::execute_attestation_query`]: the typed bounded
    /// read's storage half. Every `AttestationQuery` read a capsule consumer
    /// makes (the owner walk, `owner_of`, a chat reader) runs through this;
    /// the page cut, cursor and per-door count stay on the consumer's side
    /// (`AttestationReads::query_attestations`), so the host runs the
    /// statement only. Result rides `AttestationQueryRows`. APPEND-ONLY
    /// (Growth).
    ExecuteAttestationQuery {
        /// The query, as the consumer built it.
        query: crate::federation::attestation_query::AttestationQuery,
    },
    /// v59.1.2 (CIRISPersist#1162) —
    /// [`FederationDirectory::list_composers_referencing_any`]: the
    /// retraction fold's second read (`owner_of` reaches it through the
    /// live-delegation fold). Result rides `AttestationRows`. APPEND-ONLY
    /// (Growth).
    ListComposersReferencingAny {
        /// The targets the composers' `references_attestation_id` names.
        target_attestation_ids: Vec<String>,
        /// Only composers attested to this key, when given.
        attested_key_id: Option<String>,
        /// Only composers authored by this key, when given.
        attesting_key_id: Option<String>,
    },
    /// v59.1.2 (CIRISPersist#1162) —
    /// [`FederationDirectory::list_identity_occurrence_history_by_occurrence`]:
    /// `owner_of` names each granter as the self it signed as at its
    /// binding's instant (`self_of_at`), which reads this history. Result
    /// rides `OccurrenceHistory`. APPEND-ONLY (Growth).
    ListIdentityOccurrenceHistoryByOccurrence {
        /// The occurrence key.
        occurrence_key_id: String,
    },
    /// v59.1.2 (CIRISPersist#1162) —
    /// [`FederationDirectory::list_identity_occurrences_by_occurrence_key`]:
    /// `self_of_at` reads the occurrence's current rows beside its history.
    /// Result rides `IdentityOccurrences`. APPEND-ONLY (Growth).
    ListIdentityOccurrencesByOccurrenceKey {
        /// The occurrence key.
        occurrence_key_id: String,
    },
    /// v61.0.5 (CIRISPersist#1225) —
    /// [`FederationDirectory::list_attestations_naming_by_dimension`]: the
    /// rows naming a key under one dimension, so a relayed invitation reaches
    /// its invitee. Result rides `Scores`. APPEND-ONLY (Growth).
    ListAttestationsNamingByDimension {
        /// The key the rows name in `subject_key_ids`.
        subject_key_id: String,
        /// The one dimension.
        dimension: String,
        /// Opaque `(asserted_at, attestation_id)` page cursor.
        cursor: Option<crate::read::AttestationCursor>,
        /// Page size (1..=10_000).
        limit: i64,
    },
    /// v61.1.0 (CIRISPersist#1190) —
    /// [`FederationDirectory::list_attestations_since_by_prefixes`]: the
    /// serve stream narrowed by family prefix. Result rides
    /// `ServedAttestationPage`. APPEND-ONLY (Growth).
    ListAttestationsSinceByPrefixes {
        /// The serve position, exclusive.
        since: Option<crate::federation::types::ServePosition>,
        /// Family prefixes (`row_type::claim_token`'s family).
        family_prefixes: Vec<String>,
        /// Page size (1..=10_000).
        limit: i64,
    },
    /// v61.1.0 (CIRISPersist#1163) —
    /// [`FederationDirectory::list_owner_bindings_since`]: the announced
    /// roster's change feed. Result rides `OwnerBindingPage`. APPEND-ONLY
    /// (Growth).
    ListOwnerBindingsSince {
        /// The serve position, exclusive.
        since: Option<crate::federation::types::ServePosition>,
        /// Page size (1..=500).
        limit: i64,
    },
    /// v61.4.0 (CIRISPersist#1227) —
    /// [`FederationDirectory::list_keys_by_identity_type`] for ANY role.
    /// [`Self::ListAccordHolders`] answers only the accord set, so a capsule
    /// consumer could not list `canonical` conferrals. Result rides
    /// `KeyRecords`. APPEND-ONLY (Growth).
    ListKeysByIdentityType {
        /// The `federation_keys.identity_type` to list.
        identity_type: String,
    },
    /// v61.4.0 —
    /// [`FederationDirectory::list_all_transport_destinations_unfolded`]:
    /// every stored live route before the one-live-key fold, so a consumer
    /// that folds itself runs the read inside persist's `.so`. Result rides
    /// `TransportDestinations`. APPEND-ONLY (Growth).
    ListAllTransportDestinationsUnfolded {},
    /// v61.4.0 —
    /// [`FederationDirectory::list_transport_destinations_by_destination_unfolded`]:
    /// every stored live claimant of a destination before the fold. Result
    /// rides `TransportDestinations`. APPEND-ONLY (Growth).
    ListTransportDestinationsByDestinationUnfolded {
        /// The destination hash.
        destination: String,
    },
    /// v61.4.0 (CIRISPersist#1244) —
    /// [`crate::federation::BlackholeRules::blackhole_list`]. Result rides
    /// `BlackholeRecords`. APPEND-ONLY (Growth).
    BlackholeList {},
    /// v61.4.0 (CIRISPersist#1244) —
    /// [`crate::federation::BlackholeRules::blackhole_upsert`]. Result rides
    /// `Unit`. APPEND-ONLY (Growth).
    BlackholeUpsert {
        /// The 16-byte Reticulum identity hash.
        #[serde(with = "crate::federation::serde_bytes_b64")]
        identity_hash: Vec<u8>,
        /// Soft expiry; `None` is a permanent rule.
        until: Option<chrono::DateTime<chrono::Utc>>,
        /// Operator-readable reason.
        reason: Option<String>,
    },
    /// v61.4.0 (CIRISPersist#1244) —
    /// [`crate::federation::BlackholeRules::blackhole_remove`]. Result rides
    /// `Unit`. APPEND-ONLY (Growth).
    BlackholeRemove {
        /// The 16-byte Reticulum identity hash.
        #[serde(with = "crate::federation::serde_bytes_b64")]
        identity_hash: Vec<u8>,
    },
    /// v61.4.0 (CIRISPersist#1244) —
    /// [`crate::federation::BlackholeRules::blackhole_record_hit`]. Result
    /// rides `Unit`. APPEND-ONLY (Growth).
    BlackholeRecordHit {
        /// The 16-byte Reticulum identity hash.
        #[serde(with = "crate::federation::serde_bytes_b64")]
        identity_hash: Vec<u8>,
    },
    /// v61.4.0 (CIRISPersist#1244) —
    /// [`crate::federation::BlackholeRules::blackhole_prune_expired`]. Result
    /// rides `U64`. APPEND-ONLY (Growth).
    BlackholePruneExpired {
        /// Rules whose `until` is before this instant are dropped.
        now: chrono::DateTime<chrono::Utc>,
    },
    /// v61.4.0 (CIRISPersist#1244) —
    /// [`crate::derived::DerivedSchema::put_edge_detection_event`]. Result
    /// rides `Unit`. APPEND-ONLY (Growth).
    PutEdgeDetectionEvent {
        /// The detection row, as the detector signed it.
        event: crate::derived::EdgeDetectionEvent,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, the rooting view) —
    /// [`FederationDirectory::list_attestations_referencing`]: the referencing rows `trust_root::live_conferrals` walks (Edge `bundle_gate::pipeline_blessing`). Result rides
    /// `AttestationRows`. APPEND-ONLY (Growth).
    ListAttestationsReferencing {
        /// `target_attestation_id`.
        target_attestation_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, the rooting view) —
    /// [`FederationDirectory::get_attestation`]: one row by id. Result rides
    /// `Attestation`. APPEND-ONLY (Growth).
    GetAttestation {
        /// `attestation_id`.
        attestation_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, the rooting view) —
    /// [`FederationDirectory::list_settled_self_roster_proposals`]: `self_roster::genesis_evicted_since` reads it. Result rides
    /// `SelfRosterReceipts`. APPEND-ONLY (Growth).
    ListSettledSelfRosterProposals {
        /// `identity_key_id`.
        identity_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, the rooting view) —
    /// [`FederationDirectory::list_identity_occurrences_for`]: the identity's occurrences (`bridge::live_announcing_rows`). Result rides
    /// `IdentityOccurrences`. APPEND-ONLY (Growth).
    ListIdentityOccurrencesFor {
        /// `identity_key_id`.
        identity_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::get_active_halt`]: an active constitutional halt; through `Unsupported` a halt never latched. Result rides
    /// `ActiveHalt`. APPEND-ONLY (Growth).
    GetActiveHalt {
        /// `family_key_id`.
        family_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::lookup_role_withdrawal`]: the trait default answered `Ok(None)`, so a withdrawn role read as live. Result rides
    /// `RoleWithdrawal`. APPEND-ONLY (Growth).
    LookupRoleWithdrawal {
        /// `role`.
        role: String,
        /// `key_id`.
        key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::lookup_family`]: `trust_root::resolve_family_root` read `Unsupported` as no family. Result rides
    /// `Family`. APPEND-ONLY (Growth).
    LookupFamily {
        /// `family_key_id`.
        family_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::lookup_community`]: the community record. Result rides
    /// `Community`. APPEND-ONLY (Growth).
    LookupCommunity {
        /// `community_key_id`.
        community_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_families_for_member`]: `trust_root` read `Unsupported` as no families. Result rides
    /// `Families`. APPEND-ONLY (Growth).
    ListFamiliesForMember {
        /// `member_identity_key_id`.
        member_identity_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::family_roster_signers`]: the family roster's signers. Result rides
    /// `RosterSigners`. APPEND-ONLY (Growth).
    FamilyRosterSigners {
        /// `family_key_id`.
        family_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::community_roster_signers`]: `canonical_community` read `Unsupported` as no founder resignations. Result rides
    /// `RosterSigners`. APPEND-ONLY (Growth).
    CommunityRosterSigners {
        /// `community_key_id`.
        community_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_family_membership_revocations_for`]: `canonical_community` skipped them on `Unsupported`. Result rides
    /// `FamilyMembershipRevocations`. APPEND-ONLY (Growth).
    ListFamilyMembershipRevocationsFor {
        /// `family_key_id`.
        family_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_family_membership_widenings_for`]: `canonical_community` skipped them on `Unsupported`. Result rides
    /// `FamilyMembershipWidenings`. APPEND-ONLY (Growth).
    ListFamilyMembershipWideningsFor {
        /// `family_key_id`.
        family_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_lineage_head_cosigns_for`]: `canonical_community` read `Unsupported` as no cosigns. Result rides
    /// `LineageHeadCosigns`. APPEND-ONLY (Growth).
    ListLineageHeadCosignsFor {
        /// `lineage_key_id`.
        lineage_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::lookup_signed_community`]: the signed community record. Result rides
    /// `SignedCommunity`. APPEND-ONLY (Growth).
    LookupSignedCommunity {
        /// `community_key_id`.
        community_key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::lookup_canonical_withdrawal`]: the trait default answered `Ok(None)`, so `is_canonical_effective` read a withdrawn canonical as live. Result rides
    /// `CanonicalWithdrawal`. APPEND-ONLY (Growth).
    LookupCanonicalWithdrawal {
        /// `key_id`.
        key_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_canonical_withdrawals`]: the trait default answered empty. Result rides
    /// `CanonicalWithdrawals`. APPEND-ONLY (Growth).
    ListCanonicalWithdrawals {},
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::vote_window_first_held`]: the reverse-quorum deadline fell back to the actor's own instant on `Unsupported`. Result rides
    /// `OptionalInstant`. APPEND-ONLY (Growth).
    VoteWindowFirstHeld {
        /// `action_id`.
        action_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_cosign_aliases`]: `cosign::act_retracted` skipped aliases on `Unsupported`. Result rides
    /// `CosignAliases`. APPEND-ONLY (Growth).
    ListCosignAliases {
        /// `quorum_key`.
        quorum_key: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::cosign_alias`]: a withdraws naming an alias resolved to nothing on `Unsupported`. Result rides
    /// `CosignAlias`. APPEND-ONLY (Growth).
    CosignAlias {
        /// `attestation_id`.
        attestation_id: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::get_accord_decision`]: `roster_head::roster_lag` read `Unsupported` as undecided. Result rides
    /// `AccordDecision`. APPEND-ONLY (Growth).
    GetAccordDecision {
        /// `proposal_digest`.
        proposal_digest: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_accord_proposals_by_anchor`]: `roster_head::roster_lag` read `Unsupported` as none. Result rides
    /// `AccordProposals`. APPEND-ONLY (Growth).
    ListAccordProposalsByAnchor {
        /// `action`.
        action: String,
        /// `prior_family_digest`.
        prior_family_digest: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::purge_tombstoned`]: the tombstone admission gate read `Unsupported` as not tombstoned. Result rides
    /// `OptionalString`. APPEND-ONLY (Growth).
    PurgeTombstoned {
        /// `plane`.
        plane: String,
        /// `record_ref`.
        record_ref: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::purge_tombstone_notices`]: the serve-side withheld filter read `Unsupported` as not withheld. Result rides
    /// `WireHashes`. APPEND-ONLY (Growth).
    PurgeTombstoneNotices {
        /// `plane`.
        plane: String,
        /// `record_ref`.
        record_ref: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::list_targeted_by_dimension_prefix`]: `cosign::held_rows_of_act` and `community_dissolved_at` read `Unsupported` as none. Result rides
    /// `AttestationRows`. APPEND-ONLY (Growth).
    ListTargetedByDimensionPrefix {
        /// `cohort_scopes`.
        cohort_scopes: Vec<String>,
        /// `cohort_target`.
        cohort_target: String,
        /// `dimension_prefix`.
        dimension_prefix: String,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::key_grant_held_owner`]: the trait default answered `Ok(None)`, so `check_sealer` skipped the signer-is-author leg. Result rides
    /// `OptionalString`. APPEND-ONLY (Growth).
    KeyGrantHeldOwner {
        /// `axis`.
        axis: crate::federation::key_grant::KeyGrantAxis,
    },
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::node_key_id`]: the trait default answered `None`,
    /// which `replicated_row_in_audience` reads as "no audience check". Result
    /// rides `OptionalString`. APPEND-ONLY (Growth).
    NodeKeyId {},
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::withdraws_delegation_depth`]: the host's
    /// configured depth, not the trait default. Result rides `U64`.
    /// APPEND-ONLY (Growth).
    WithdrawsDelegationDepth {},
    /// v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read) —
    /// [`FederationDirectory::hardware_attestation_policy`]: the host's
    /// installed policy, not the default. Result rides
    /// `HardwareAttestationPolicy`. APPEND-ONLY (Growth).
    HardwareAttestationPolicy {},
    /// v62.0.0 (JSON-cut slice D, CC 2.6.1, 2.6.1.12) — **the edition-2
    /// statement door**, [`crate::federation::edition2::ingest::put_statement`]
    /// at tier `federation`, run inside persist's `.so` over persist's own
    /// directory: one `COSE_Sign1` statement as received. An earlier-form
    /// object is refused `earlier_form_object` by the door itself. Result
    /// rides `Edition2StatementOutcome`. APPEND-ONLY (Growth).
    PutEdition2Statement {
        /// The statement's bytes as received.
        statement: Vec<u8>,
        /// The row id the carrier names it by, if any: it must be the one
        /// this node computes (`row_id_mismatch`).
        offered_row_id: Option<[u8; 32]>,
    },
    /// v62.0.0 (JSON-cut slice D) — **the replicated statement door**,
    /// [`crate::federation::edition2::ingest::apply_replicated_statement`]:
    /// one statement a peer delivered under the id it offered. A statement
    /// whose signer's key record is not held is the retryable
    /// `federation_attester_key_unknown` error (the cursor must not advance);
    /// a lost race is `Refused`. Result rides `ReplicatedStatementOutcome`.
    /// APPEND-ONLY (Growth).
    ApplyReplicatedStatement {
        /// The statement's bytes as the peer delivered them.
        statement: Vec<u8>,
        /// The row id the peer offered it as.
        offered_row_id: [u8; 32],
    },
    /// v62.0.0 (JSON-cut slice D) —
    /// [`FederationDirectory::edition2_statements_since`]: the held
    /// statements after `cursor`, in this node's admission order, as
    /// received. Result rides `Edition2StatementPage`. APPEND-ONLY (Growth).
    Edition2StatementsSince {
        /// Resume after this position (`None`: from the first).
        cursor: Option<Edition2Cursor>,
        /// At most this many (the store clamps to its page bound).
        limit: u32,
    },
    /// v62.0.0 (JSON-cut slice D, CC 2.6.1.11, 2.7.8) —
    /// [`crate::federation::edition2::genesis::bundles_in_force`]: the tips of
    /// the held genesis lineage as CIRISVerify places them (two are a fork).
    /// Result rides `BundlesInForce`. APPEND-ONLY (Growth).
    BundlesInForce {},
    /// v61.4.2 (the community mirror of #1244 round 2's family pair) —
    /// [`FederationDirectory::list_community_membership_revocations_for`]:
    /// a room's active roster is record + widenings − revocations, and
    /// through `Unsupported` every call join on an agent install answered
    /// 503. Result rides `CommunityMembershipRevocations`. APPEND-ONLY
    /// (Growth).
    ListCommunityMembershipRevocationsFor {
        /// `community_key_id`.
        community_key_id: String,
    },
    /// v61.4.2 (the community mirror of #1244 round 2's family pair) —
    /// [`FederationDirectory::list_community_membership_widenings_for`]: the
    /// growth half of the room's active roster. Result rides
    /// `CommunityMembershipWidenings`. APPEND-ONLY (Growth).
    ListCommunityMembershipWideningsFor {
        /// `community_key_id`.
        community_key_id: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::add_community_member`]; the proxy answered
    /// `Unsupported`. Result rides `Bool`. APPEND-ONLY (Growth).
    AddCommunityMember {
        /// `community_key_id`.
        community_key_id: String,
        /// `member`.
        member: types::CommunityMember,
        /// `spec`.
        spec: cohort::AdmitSpec,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::add_family_member`]; the proxy answered
    /// `Unsupported`. Result rides `Bool`. APPEND-ONLY (Growth).
    AddFamilyMember {
        /// `family_key_id`.
        family_key_id: String,
        /// `member`.
        member: types::FamilyMember,
        /// `spec`.
        spec: cohort::AdmitSpec,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::attestation_insert_local`]; the proxy answered
    /// `Unsupported`. Result rides `AttestationId`. APPEND-ONLY (Growth).
    AttestationInsertLocal {
        /// `input`.
        input: types::LocalAttestationInput,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::attestation_type_census`]; the proxy answered
    /// `Unsupported`. Result rides `AttestationTypeCounts`. APPEND-ONLY (Growth).
    AttestationTypeCensus {},
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::attestation_upsert_local`]; the proxy answered
    /// `Unsupported`. Result rides `AttestationId`. APPEND-ONLY (Growth).
    AttestationUpsertLocal {
        /// `input`.
        input: types::LocalAttestationInput,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::attestations_binding_content`]; the proxy answered
    /// `Unsupported`. Result rides `AttestationRows`. APPEND-ONLY (Growth).
    AttestationsBindingContent {
        /// `content_sha256`.
        content_sha256: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::attestations_binding_content_with_placements`]; the proxy answered
    /// `Unsupported`. Result rides `AttestationRows`. APPEND-ONLY (Growth).
    AttestationsBindingContentWithPlacements {
        /// `content_sha256`.
        content_sha256: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::clear_active_halt`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    ClearActiveHalt {
        /// `family_key_id`.
        family_key_id: String,
        /// `active_halt_id`.
        active_halt_id: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::communities_containing`]; the proxy answered
    /// `Unsupported`. Result rides `Communities`. APPEND-ONLY (Growth).
    CommunitiesContaining {
        /// `cell_id`.
        cell_id: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::dag_manifests_of_chunk`]; the proxy answered
    /// `Unsupported`. Result rides `ChunkManifests`. APPEND-ONLY (Growth).
    DagManifestsOfChunk {
        /// `chunk_sha256`.
        chunk_sha256: [u8; 32],
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::enter_mesh`]; the proxy answered
    /// `Unsupported`. Result rides `MeshCrossing`. APPEND-ONLY (Growth).
    EnterMesh {
        /// `attestation_id`.
        attestation_id: String,
        /// `ci`.
        ci: crate::federation::ContextualIntegrity,
        /// `custody`.
        custody: crate::federation::TierPromotionCustody,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::get_accord_proposal`]; the proxy answered
    /// `Unsupported`. Result rides `AccordProposal`. APPEND-ONLY (Growth).
    GetAccordProposal {
        /// `proposal_digest`.
        proposal_digest: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::list_accord_participations`]; the proxy answered
    /// `Unsupported`. Result rides `AccordParticipations`. APPEND-ONLY (Growth).
    ListAccordParticipations {
        /// `proposal_digest`.
        proposal_digest: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::list_attestations_by_dimension_citing`]; the proxy answered
    /// `Unsupported`. Result rides `AttestationRows`. APPEND-ONLY (Growth).
    ListAttestationsByDimensionCiting {
        /// `attesting_key_id`.
        attesting_key_id: String,
        /// `dimension`.
        dimension: String,
        /// `evidence_ref`.
        evidence_ref: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::list_communities_for_member`]; the proxy answered
    /// `Unsupported`. Result rides `Communities`. APPEND-ONLY (Growth).
    ListCommunitiesForMember {
        /// `member_identity_key_id`.
        member_identity_key_id: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::list_group_versions`]; the proxy answered
    /// `Unsupported`. Result rides `GroupVersions`. APPEND-ONLY (Growth).
    ListGroupVersions {
        /// `cohort`.
        cohort: cohort::Cohort,
        /// `group_key_id`.
        group_key_id: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::list_location_proofs_for`]; the proxy answered
    /// `Unsupported`. Result rides `LocationProofs`. APPEND-ONLY (Growth).
    ListLocationProofsFor {
        /// `subject_key_id`.
        subject_key_id: String,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::lookup_keys_for_identity`]; the proxy answered
    /// `Unsupported`. Result rides `KeyRecords`. APPEND-ONLY (Growth).
    LookupKeysForIdentity {
        /// `identity_ref`.
        identity_ref: String,
    },
    /// v61.4.2 (the capsule stub sweep) — the former `FederationDirectory::put_accord_decision`.
    /// v62.0.0 (CC rc20): RETIRED with the accord live-quorum records; the
    /// arm refuses `Unsupported` and reads nothing. APPEND-ONLY (Growth).
    PutAccordDecision {
        /// `decision`.
        decision: accord_quorum::AccordDecision,
    },
    /// v61.4.2 (the capsule stub sweep) — the former `FederationDirectory::put_accord_participation`.
    /// v62.0.0 (CC rc20): RETIRED with the accord live-quorum records; the
    /// arm refuses `Unsupported` and reads nothing. APPEND-ONLY (Growth).
    PutAccordParticipation {
        /// `participation`.
        participation: accord_quorum::AccordParticipation,
        /// `standing_roster`.
        standing_roster: Vec<ciris_verify_core::threshold::ThresholdMember>,
    },
    /// v61.4.2 (the capsule stub sweep) — the former `FederationDirectory::put_accord_proposal`.
    /// v62.0.0 (CC rc20): RETIRED with the accord live-quorum records; the
    /// arm refuses `Unsupported` and reads nothing. APPEND-ONLY (Growth).
    PutAccordProposal {
        /// `proposal`.
        proposal: accord_quorum::AccordProposal,
        /// `authority_signature`.
        authority_signature: Option<serde_json::Value>,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::put_community_membership_revocation`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    PutCommunityMembershipRevocation {
        /// `revocation`.
        revocation: SignedCommunityMembershipRevocation,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::put_community_membership_widening`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    PutCommunityMembershipWidening {
        /// `widening`.
        widening: crate::federation::SignedCommunityMembershipWidening,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::put_family_membership_revocation`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    PutFamilyMembershipRevocation {
        /// `revocation`.
        revocation: SignedFamilyMembershipRevocation,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::put_family_membership_widening`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    PutFamilyMembershipWidening {
        /// `widening`.
        widening: crate::federation::SignedFamilyMembershipWidening,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::set_active_halt`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    SetActiveHalt {
        /// `family_key_id`.
        family_key_id: String,
        /// `active_halt_id`.
        active_halt_id: String,
        /// v62.0.0 (HALT-235) — the halt latch as JSON. Defaulted, so a
        /// consumer that sends the earlier two fields still decodes (the op
        /// enum has no `deny_unknown_fields`, so an older persist ignores it).
        #[serde(default)]
        latch_json: Option<String>,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::set_consent_role`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    SetConsentRole {
        /// `key_id`.
        key_id: String,
        /// `consent_role`.
        consent_role: Option<String>,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::supersede_group_row`]; the proxy answered
    /// `Unsupported`. Result rides `GroupRowVersion`. APPEND-ONLY (Growth).
    SupersedeGroupRow {
        /// `cohort`.
        cohort: cohort::Cohort,
        /// `new_snapshot`.
        new_snapshot: serde_json::Value,
        /// `authorization`.
        authorization: Option<serde_json::Value>,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::withdraw_location_proof`]; the proxy answered
    /// `Unsupported`. Result rides `Unit`. APPEND-ONLY (Growth).
    WithdrawLocationProof {
        /// `proof`.
        proof: SignedLocationProof,
    },
    /// v61.4.2 (the capsule stub sweep) — [`FederationDirectory::list_live_consent_grants_by`]; the proxy answered
    /// `Unsupported`. Result rides `AttestationRows`. APPEND-ONLY (Growth).
    ListLiveConsentGrantsBy {
        /// `node_key_id`.
        node_key_id: String,
    },
    /// v62.0.0 (round 3, L1) — [`FederationDirectory::list_settled_edition2_roster_proposals`]:
    /// the edition-2 twin of `ListSettledSelfRosterProposals` (#1244 round 2,
    /// the rooting view). A producer names the latest landed roster row as
    /// its `refs.head` from it (`current_roster_heads`), and through the
    /// inherited `Unsupported` it read "nothing landed". Result rides
    /// `SelfRosterReceipts`. APPEND-ONLY (Growth).
    ListSettledEdition2RosterProposals {
        /// `identity_key_id`.
        identity_key_id: String,
    },
    /// v62.0.0 (round 3, O1 fix 5) — [`FederationDirectory::edition2_roster_proposal`]:
    /// one receipt of the same edition-2 rooting view, by row id. The
    /// roster fold reads whether a named row LANDED from it
    /// (`self_roster::roster_at_heads`), as does `genesis_evicted_at`.
    /// Through the inherited `Unsupported` it read "not landed". Result
    /// rides `SelfRosterReceipts` (zero or one). APPEND-ONLY (Growth).
    Edition2RosterProposal {
        /// The proposal's row id, hex.
        row_id_hex: String,
    },
    /// v62.0.0 (v62 P8-fix5; CC 2.6.1.9, 2.7.3, 4.4.3.19) —
    /// [`FederationDirectory::held_rows_for`]: the held rows waiting for
    /// `key`'s voice, in any second-signer role (only `role`, when named).
    /// Result rides `HeldRows`. APPEND-ONLY (Growth).
    HeldRowsFor {
        /// The awaited key (identity-ref).
        key: String,
        /// Only this role, when named.
        role: Option<String>,
        /// The held row id to page after.
        after: Option<[u8; 32]>,
        /// At most this many.
        limit: u32,
    },
    /// v62.0.0 (v62 P8-fix5) — [`FederationDirectory::voice_status`]: the
    /// state of a row a voice concerns. Result rides `VoiceOutcome`.
    /// APPEND-ONLY (Growth).
    VoiceStatus {
        /// The row id.
        row_id: [u8; 32],
    },
    /// v62.0.0 (v62 P8-fix5) — [`FederationDirectory::submit_voice`]: a
    /// second signer's voice through the statement door, run inside
    /// persist's `.so`; the row's resulting state. Result rides
    /// `VoiceOutcome`. APPEND-ONLY (Growth).
    SubmitVoice {
        /// The voice statement's bytes.
        statement: Vec<u8>,
    },
    /// v62.0.0 (ceremony gap 4; CC 2.6.1.11, CC 5.3.4) — **the genesis
    /// bundle/2 import door**,
    /// [`crate::federation::edition2::genesis::put_genesis_bundle`], run
    /// inside persist's `.so` over persist's own directory, so every gate
    /// runs on the host's store: one statement list (bundle voices and the
    /// rows they name, each as received) read by CIRISVerify's bundle reader,
    /// and `anchor` for a first bundle not already held (`None` roots nothing
    /// new). An earlier-form object is refused `earlier_form_object` by the
    /// door itself. Result rides `GenesisAdmission`. APPEND-ONLY (Growth).
    PutGenesisBundle {
        /// The bundle voices and the rows they name, each as received.
        statements: Vec<Vec<u8>>,
        /// The anchor for a first bundle not already held.
        anchor: Option<GenesisAnchor>,
    },
    /// v62.0.0 (ceremony gap 2; CC 3.3.6.2, CC 3.4.7) —
    /// [`crate::federation::edition2::transport_rebind::rebind_held_for`]: the
    /// counted re-bind live for a seat of the genesis bundle in force (a
    /// pre-roll gate's question). Result rides `RebindHeld`. APPEND-ONLY
    /// (Growth).
    RebindHeldFor {
        /// The seat's identity-ref.
        seat_identity_ref: String,
    },
    /// v62.0.0 (F0-cp5; RULINGS "composite signatures only") — the
    /// security-critical verify, edition 2:
    /// [`verify_composite_via_directory`](crate::federation::edition2::composite_verify::verify_composite_via_directory)
    /// runs inside persist's `.so` (the reason `VerifyHybridViaDirectory`
    /// existed) over ONE composite signature under `identity_ref`'s LIVE
    /// edition-2 key at `at_ms`. Result rides `CompositeVerify`. APPEND-ONLY
    /// (Growth).
    VerifyCompositeViaDirectory {
        /// The exact bytes the composite covers.
        message: Vec<u8>,
        /// The signer's edition-2 identity-ref.
        identity_ref: String,
        /// The composite signature's raw bytes.
        composite_sig: Vec<u8>,
        /// The instant the key's liveness is read at (POSIX ms).
        at_ms: u64,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::edition2_statements_about`],
    /// the first of the edition-2 and fold store READS appended here. Each
    /// trait default answered empty / `None` / `false` through the consumer
    /// proxy, so a free fold a consumer runs over it (`genesis_in_force`,
    /// `held_keys_for_kid`, `bytes_servable`, `is_held_back`, ...) read
    /// "nothing held"; each now crosses to the HOST's store, and the defaults
    /// refuse `Unsupported`. Result rides `Edition2Statements`. APPEND-ONLY
    /// (Growth).
    Edition2StatementsAbout {
        /// The statement family (`key:record`, ...).
        family: String,
        /// The CWT `sub`.
        sub: String,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::edition2_voices`]. Result
    /// rides `Edition2Statements`. APPEND-ONLY (Growth).
    Edition2Voices {
        /// The row id.
        row_id: [u8; 32],
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::edition2_rows_naming`].
    /// Result rides `Edition2RowIds`. APPEND-ONLY (Growth).
    Edition2RowsNaming {
        /// The named row id.
        named: [u8; 32],
        /// The `refs` role.
        role: String,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::edition2_objects`]. Result
    /// rides `Edition2Statements`. APPEND-ONLY (Growth).
    Edition2Objects {
        /// The object `typ` (`ceg-genesis-bundle/2`).
        typ: String,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::edition2_statement`].
    /// Result rides `OptionalBytes`. APPEND-ONLY (Growth).
    Edition2Statement {
        /// The statement id.
        statement_id: [u8; 32],
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::edition2_statement_ids_since`].
    /// Result rides `Edition2StatementIds`. APPEND-ONLY (Growth).
    Edition2StatementIdsSince {
        /// Page after this statement id (`None`: from the first).
        after: Option<[u8; 32]>,
        /// At most this many.
        limit: u32,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::fold_held`]. Result rides
    /// `FoldHeldReason`. APPEND-ONLY (Growth).
    FoldHeld {
        /// The row id.
        row_id: [u8; 32],
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::fold_held_page`]. Result
    /// rides `FoldHeldReasons`. APPEND-ONLY (Growth).
    FoldHeldPage {
        /// Page after this row id (`None`: from the first).
        after: Option<[u8; 32]>,
        /// At most this many.
        limit: u32,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::fold_dependents`]. Result
    /// rides `Edition2RowIds`. APPEND-ONLY (Growth).
    FoldDependents {
        /// The read keys.
        read_keys: Vec<String>,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::fold_state`]. Result rides
    /// `FoldStateOf`. APPEND-ONLY (Growth).
    FoldState {
        /// The row id.
        row_id: [u8; 32],
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::fold_slot_rows`]. Result
    /// rides `Edition2RowIds`. APPEND-ONLY (Growth).
    FoldSlotRows {
        /// The projection slot.
        slot: String,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::fold_slot_held`]. Result
    /// rides `Bool`. APPEND-ONLY (Growth).
    FoldSlotHeld {
        /// The projection slot.
        slot: String,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::fold_any_refolding`].
    /// Result rides `Bool`. APPEND-ONLY (Growth).
    FoldAnyRefolding {},
    /// v62.0.0 (PR-fix1; CC 3.2 T8, CC 5.3.4) —
    /// [`peer_rooting`](crate::federation::edition2::peer_rooting::peer_rooting):
    /// is the peer Rooted for the reader node at the signer-stamped instant
    /// `at_ms`. Result rides `PeerRooting`. APPEND-ONLY (Growth).
    PeerRooting {
        /// The reader node's identity-ref (its owner's acceptance edges are
        /// read).
        reader_node: String,
        /// The peer's identity-ref.
        peer_identity_ref: String,
        /// The key the peer speaks with.
        claimed_key: crate::federation::edition2::peer_rooting::ClaimedKeyWire,
        /// The signer-stamped instant judged at (POSIX ms), never the
        /// reader's clock for a stored outcome.
        at_ms: u64,
    },
    /// v62.0.0 (AU-fix2; CC 2.7.11) —
    /// [`FederationDirectory::admission_unit_rows`]: the LIVE
    /// `admission:unit` rows about `sub` at `at_ms` (concluded, in lease, not
    /// withdrawn, signers live persons). The trait default reads the
    /// edition-2 store, which REFUSES through the proxy, so the whole read
    /// crosses. Result rides `AdmissionUnitRows`. APPEND-ONLY (Growth).
    AdmissionUnitRows {
        /// The unit's `canonical:sha256:{hex}`.
        sub: String,
        /// The instant asked (POSIX ms).
        at_ms: u64,
        /// The host owner the standing legs read; `None`: the node's own.
        owner: Option<String>,
    },
    /// v62.0.0 (AU-fix2; CC 2.7.11) —
    /// [`admission_unit_runnable`](crate::federation::edition2::admission_unit::admission_unit_runnable):
    /// may the unit row `row_id` admits run on the HOST's store at `at_ms`
    /// (every leg: concluded, lease, end, persons, standing, receipt). A free
    /// fold persist runs over its own directory. Result rides
    /// `AdmissionUnitAnswer`. APPEND-ONLY (Growth).
    AdmissionUnitRunnable {
        /// The `admission:unit` row id.
        row_id: [u8; 32],
        /// The instant asked (POSIX ms).
        at_ms: u64,
        /// The host owner the standing legs read; `None`: the node's own.
        owner: Option<String>,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::put_touch_claim_local`]:
    /// the node-local touch (RULINGS: a touch claim is node-local), the
    /// replacement for the retired signed `put_touch_claim` a host called.
    /// Result rides `TouchApplied`. APPEND-ONLY (Growth).
    PutTouchClaimLocal {
        /// The touched target.
        target_key_id: String,
        /// The target's kind.
        target_kind: String,
        /// The instant the target is fresh as of.
        fresh_as_of: chrono::DateTime<chrono::Utc>,
        /// The mandatory cohort scope.
        cohort_scope: String,
    },
    /// v62.0.0 (PX-fix1) — [`FederationDirectory::freshness_floor`]: the
    /// floor this node holds for a target. Result rides `FreshnessFloorOf`.
    /// APPEND-ONLY (Growth).
    FreshnessFloor {
        /// The target.
        target_key_id: String,
        /// The target's kind.
        target_kind: String,
    },
    /// v62.0.0 (RL-fix1, lead ruling (B)) —
    /// [`crate::federation::edition2::ingest::apply_replicated_statement_at_feed`]:
    /// the replicated statement door with the host's feed position, so an
    /// accord row this node cannot judge (no genesis bundle held) advances
    /// the cursor and leaves a watermark. Result rides
    /// `ReplicatedStatementOutcome`. APPEND-ONLY (Growth).
    ApplyReplicatedStatementAtFeed {
        /// The statement's bytes as the peer delivered them.
        statement: Vec<u8>,
        /// The row id the peer offered it as.
        offered_row_id: [u8; 32],
        /// Where the host's feed stands.
        feed: crate::federation::edition2::accord_rescan::FeedPosition,
    },
    /// v62.0.0 (RL-fix1, ruling (B)) —
    /// [`crate::federation::edition2::accord_rescan::rescan_needed`]: the
    /// feeds to re-pull once a genesis bundle is in force. Result rides
    /// `AccordRescans`. APPEND-ONLY (Growth).
    AccordRescanNeeded {},
    /// v62.0.0 (RL-fix1, ruling (B)) —
    /// [`crate::federation::edition2::accord_rescan::ack_rescan`]: the host
    /// re-pulled a feed past its watermark. Result rides `Bool`. APPEND-ONLY
    /// (Growth).
    AckAccordRescan {
        /// The plane the feed carries.
        plane: String,
        /// The peer (or feed) the host pulls from.
        peer: String,
        /// The watermark's first position.
        from_position: String,
    },
    /// v62.0.0 (RL-fix3) —
    /// [`crate::federation::edition2::contact::record_dial_hints`]: a
    /// contact's local, unsigned dial hint. Result rides `Unit`.
    /// APPEND-ONLY (Growth).
    RecordDialHints {
        /// The decoded record.
        hints: crate::federation::edition2::contact::DialHints,
    },
    /// v62.0.0 (RL-fix3) — the dial hint held for `node`. Result rides
    /// `DialHints`. APPEND-ONLY (Growth).
    DialHintsFor {
        /// The node's identity-ref.
        node: String,
    },
    /// v62.0.0 (RL-fix3) — every dial hint held. Result rides
    /// `DialHintsList`. APPEND-ONLY (Growth).
    ListDialHints {},
    /// v62.0.0 (RL-fix3) — remove `node`'s dial hint. Result rides `Bool`.
    /// APPEND-ONLY (Growth).
    RemoveDialHints {
        /// The node's identity-ref.
        node: String,
    },
    /// v62.0.0 (RL-fix3; CC 5.3.3.10 E1) —
    /// [`crate::federation::edition2::contact::admit_pre_seal_answer`].
    /// Result rides `PreSealAdmission`. APPEND-ONLY (Growth).
    AdmitPreSealAnswer {
        /// The dialled node's identity-ref.
        dialled: String,
        /// The node's own key record.
        key_record: Vec<u8>,
        /// The node's own bind, carrying its route and transit key.
        route: Vec<u8>,
    },
    /// v62.0.0 (RL-fix3) —
    /// [`crate::federation::edition2::contact::admit_contact_owner_rows`].
    /// Result rides `ContactOwner`. APPEND-ONLY (Growth).
    AdmitContactOwnerRows {
        /// The node's identity-ref.
        node: String,
        /// The code's identity-ref.
        identity: String,
        /// The owner's own key record.
        owner_key_record: Vec<u8>,
        /// The owner binding's voices.
        binding: Vec<Vec<u8>>,
    },
    /// v62.0.0 (PX-fix3) — [`FederationDirectory::list_group_tips`]: the
    /// versions held as TIPS beside a group's head. The authorized roster
    /// fold a consumer composes over the proxy (`active_family_members`, the
    /// room rosters) reads it to keep only the members common to all tips;
    /// its `Unsupported` was read as "not forked". Result rides `GroupTips`.
    /// APPEND-ONLY (Growth).
    ListGroupTips {
        /// `cohort`.
        cohort: cohort::Cohort,
        /// `group_key_id`.
        group_key_id: String,
    },
    /// v62.0.0 (K2-fix20; CC 5.4.6 as ruled for rc22, CC 3.4.13 Q5) —
    /// [`may_publish_federation_rendezvous`](crate::federation::age::may_publish_federation_rendezvous),
    /// run inside persist's `.so`: the producing node's authoring check
    /// before it publishes a federation-scope `rendezvous:route` for
    /// `key_id`. `Unit` when it may; the `scope_minor_rendezvous_at_federation`
    /// refusal rides `TypedErr`. APPEND-ONLY (Growth).
    MayPublishFederationRendezvous {
        /// The person, a key acting for them, or their node.
        key_id: String,
    },
    /// v62.0.0 (RL-fix2c) —
    /// [`crate::federation::edition2::serve::serve_standing`]: what this store
    /// will serve a third party (node key, rooted, withholds the federation
    /// tier). Result rides `ServeStanding`. APPEND-ONLY (Growth).
    ServeStanding {},
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
    /// v38.5.0 (#771) — what a `put_attestation` DID.
    ///
    /// `Unit` cannot carry it, and collapsing `AlreadyHeld` into `Unit` here
    /// would reproduce the very defect #771 filed: a classification lost at
    /// a crate boundary, leaving the caller unable to tell idempotent
    /// success from a state change. The ABI version moves with it.
    AttestationOutcome(crate::federation::AttestationOutcome),
    /// The `()` returns: `put_transport_destination`, `put_revocation`,
    /// `put_public_key`, `put_location_proof`, `put_identity_occurrence`,
    /// `put_family`, `put_community`,
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
    /// OUTCOME (`Inserted` / `Upgraded` / `Unchanged` / `Superseded` /
    /// `Refused{reason}`). A `Refused` is a *policy* outcome carried HERE,
    /// NOT flattened to the top-level [`DirectoryOpResult::Err`] (which is
    /// reserved for a real backend error that means the apply could not run).
    /// v24.2.0 (CIRISPersist#565): the refusal carries a typed
    /// [`KeyRefusalReason`](crate::federation::register::KeyRefusalReason)
    /// across this boundary — same struct-variant wire shape as the sibling
    /// [`Self::TransportDestinationApplyOutcome`]. APPEND-ONLY.
    ReplicatedKeyOutcome(crate::federation::register::ReplicatedKeyOutcome),
    /// `lookup_identity_for_occurrence` (#397) — the reverse occurrence→identity
    /// row (`None` ⇒ the key is not bound as an occurrence). APPEND-ONLY.
    IdentityOccurrence(Option<IdentityOccurrence>),
    /// `list_signed_identity_occurrences_for` (#418) — the signed-put
    /// occurrences with their signature container, for transport replication.
    /// APPEND-ONLY.
    SignedIdentityOccurrences(Vec<crate::federation::SignedIdentityOccurrence>),
    /// `list_signed_records` (#425) — the uniform per-kind signed read.
    /// APPEND-ONLY.
    SignedReplicatedRecords(Vec<crate::federation::namespace::SignedReplicatedRecord>),
    /// `put_signed_transport_destination` (#443) — the monotonic route apply
    /// OUTCOME (`Inserted` / `Superseded` / `Unchanged` / `Refused{reason}`).
    /// A `Refused` is a *policy* outcome carried HERE, NOT flattened to the
    /// top-level [`DirectoryOpResult::Err`] (which is reserved for gate
    /// failures / real backend errors). APPEND-ONLY.
    TransportDestinationApplyOutcome(self_at_login::TransportDestinationApplyOutcome),
    /// `list_signed_transport_destinations_for` (#443) — the signed-put
    /// routes with their signature container, for transport replication.
    /// APPEND-ONLY.
    SignedTransportDestinations(Vec<self_at_login::SignedTransportDestination>),
    /// `resolve_encryption_keys` (#329) — the revocation-aware current KEX
    /// pubkeys (`None` ⇒ fail-secure exclusion from v2 grants). APPEND-ONLY.
    EncryptionKeys(Option<crate::federation::EncryptionPubkeys>),
    /// `list_identity_occurrence_revocations_for` (#329) — the raw
    /// revocation-plane rows for an identity. APPEND-ONLY.
    IdentityOccurrenceRevocations(Vec<IdentityOccurrenceRevocation>),
    /// `list_scores` (v17.4.0) — one page of scored rows + next cursor.
    /// APPEND-ONLY.
    Scores(crate::read::ScoresPage),
    /// `resolve_scores` (v17.4.0) — the composed verdict (band + n's + open
    /// trace). APPEND-ONLY.
    ComposedVerdict(crate::read::ComposedVerdict),
    /// `list_announced_peers` (v17.8.0, #469) — the live advisory-peer
    /// bookmarks (non-canonical, untrusted, never an authority). APPEND-ONLY.
    AnnouncedPeers(Vec<crate::federation::types::AnnouncedPeer>),
    /// `trust_root_valid` (v18.2.0, #481) — the per-check trust-root
    /// verdict. APPEND-ONLY.
    TrustRootVerdict(crate::federation::trust_root::TrustRootVerdict),
    /// `capability_roots_to_trusted_root` (v18.3.0, #483) — the winning
    /// grant, or `None` if the subject holds the scope from no trusted
    /// root. APPEND-ONLY.
    TrustedGrant(Option<crate::federation::trust_root::TrustedGrant>),
    /// `list_consent_peers` (v21.0.0, #502 E7) — the revocation-folded
    /// `consent_peer_set` peer list, sorted + deduped. APPEND-ONLY.
    ConsentPeers(Vec<String>),
    /// `list_signed_location_proofs_since` (v21.0.0, CIRISPersist#504 FLOOR).
    /// APPEND-ONLY.
    SignedLocationProofs(Vec<crate::federation::ServedLocationProof>),
    /// `list_signed_transport_destinations_since` (v21.1.0,
    /// CIRISPersist#507c). APPEND-ONLY.
    SignedTransportDestinationsSince(Vec<crate::federation::ServedTransportDestination>),
    /// `list_attestations_since` (v21.1.0, CIRISPersist#507c) — federation-
    /// tier-only rows. APPEND-ONLY.
    Attestations(Vec<crate::federation::ServedAttestation>),
    /// `lookup_signed_record_by_content_hash` (v21.1.0, CIRISPersist#507b) —
    /// the re-serialized record bytes, or `None` on a miss/index-mismatch.
    /// APPEND-ONLY.
    OptionalBytes(Option<Vec<u8>>),
    /// `resolve_transit_eligibility` (v24.1.0, CIRISPersist#561) — the
    /// transport-hop verdict plus its authoritative cache TTL and the shared
    /// root that satisfied it. APPEND-ONLY.
    TransitEligibility(crate::federation::trust_root::TransitEligibility),
    /// `revocations_for` (v31.1.0, CIRISPersist#655). APPEND-ONLY.
    Revocations(Vec<Revocation>),
    /// `list_signed_accord_quorum_evidence_since` (v31.1.0,
    /// CIRISPersist#662). APPEND-ONLY.
    AccordQuorumEvidence(Vec<crate::federation::accord_carriage::AccordQuorumEvidence>),
    /// `apply_replicated_accord_evidence` (v31.1.0, CIRISPersist#662) — what
    /// the RECEIVER's own re-tally found. APPEND-ONLY.
    AccordEvidenceAdmitted(crate::federation::accord_carriage::AccordEvidenceAdmission),
    /// v31.1.0 (CIRISPersist#662, PR #667 round-3) — a TYPED refusal of
    /// replicated accord evidence, carried across the ABI as itself.
    ///
    /// [`DirectoryOpResult::Err`] flattens every failure to a string, which the
    /// proxy rebuilds as `Error::Backend` — so a capsule-backed caller saw
    /// `kind() == "federation_backend"` for a bundle its own node refused to
    /// authorize. That erases the whole distinction
    /// [`Error::AccordEvidenceUnverified`](crate::federation::Error::AccordEvidenceUnverified)
    /// exists to draw: "a peer offered evidence that does not verify here"
    /// (a partition, a stale roster, or a forgery) reads identically to "our
    /// storage broke". One is a carrier decision, the other is an incident, and
    /// a refusal that loses its kind crossing a door is a refusal nobody can
    /// act on. APPEND-ONLY.
    AccordEvidenceRefused {
        /// The content-derived digest of the refused proposal.
        proposal_digest: String,
        /// Why the receiver's own re-derivation failed.
        reason: String,
    },
    /// v36.0.0 (CIRISPersist#674) — the CARRIER-fault refusal of replicated
    /// accord evidence, carried across the ABI as itself for the same reason
    /// as [`DirectoryOpResult::AccordEvidenceRefused`]: the whole point of
    /// [`Error::AccordEvidenceCarrierMalformed`](crate::federation::Error::AccordEvidenceCarrierMalformed)
    /// is that an operator can tell a malformed carrier from a partition,
    /// and a kind that flattens crossing the capsule cannot draw that line.
    /// APPEND-ONLY.
    AccordEvidenceCarrierRefused {
        /// The content-derived digest of the refused proposal.
        proposal_digest: String,
        /// How many participations the bundle carried.
        participations: usize,
        /// How many seats the declared accord roster has.
        roster_seats: usize,
        /// Which structural rule the bundle broke.
        reason: String,
    },
    /// [`DirectoryOp::ListWireHashesSince`] (CIRISPersist#785) — the HELD
    /// hash set page. APPEND-ONLY.
    WireHashes(Vec<String>),
    /// [`DirectoryOp::KnownWireHashContains`] (CIRISPersist#785).
    /// APPEND-ONLY.
    Bool(bool),
    /// [`DirectoryOp::ListKnownWireHashesSince`] (CIRISPersist#785) — the
    /// KNOWN-set page. A DISTINCT variant from [`Self::WireHashes`] on
    /// purpose: the two sets must never be unioned, and giving them one wire
    /// shape would make a swapped dispatch arm type-check. APPEND-ONLY.
    KnownWireHashes(Vec<crate::federation::KnownWireHash>),
    /// [`DirectoryOp::EvictKnownWireHashes`] (CIRISPersist#785) — evicted,
    /// remaining, and how far over bound the floor left it. APPEND-ONLY.
    KnownHashEviction(crate::federation::KnownHashEviction),
    /// v50.0.0 (CIRISPersist#917) — `apply_replicated_attestation` and
    /// `put_attestation_synced`: the typed Attestation-plane outcome. A
    /// `Refused` is a policy outcome carried HERE with its reason, never
    /// flattened to [`Self::Err`]. APPEND-ONLY (Growth).
    ReplicatedAttestationOutcome(
        crate::federation::attestation_apply::ReplicatedAttestationOutcome,
    ),
    /// v50.0.0 (CIRISPersist#928) — `withdraws_admission_depth`: `None` when
    /// nothing was recorded (a pre-V157 row reads as the 16-hop walk).
    /// APPEND-ONLY (Growth).
    WithdrawsAdmissionDepth(Option<u32>),
    /// v51.0.0 (CIRISPersist#938) — `PutLineageHeadCosign`'s typed outcome.
    /// APPEND-ONLY (Growth).
    LineageCosignOutcome(crate::federation::lineage_witness::LineageCosignOutcome),
    /// v59.1.2 (CIRISPersist#1162) — `execute_attestation_query`: the rows in
    /// the query's order (at most `limit + 1`), the envelope bytes decoded and
    /// the backend that ran it. APPEND-ONLY (Growth).
    AttestationQueryRows(crate::federation::attestation_query::QueryRows),
    /// v59.1.2 (CIRISPersist#1162) — a plain `Vec<Attestation>` read
    /// (`list_composers_referencing_any`). Distinct from
    /// [`Self::Attestations`], which carries `Served*` rows. APPEND-ONLY
    /// (Growth).
    AttestationRows(Vec<Attestation>),
    /// v59.1.2 (CIRISPersist#1162) —
    /// `list_identity_occurrence_history_by_occurrence`. APPEND-ONLY (Growth).
    OccurrenceHistory(Vec<crate::federation::OccurrenceAssertion>),
    /// v59.1.2 (CIRISPersist#1162) —
    /// `list_identity_occurrences_by_occurrence_key`. APPEND-ONLY (Growth).
    IdentityOccurrences(Vec<IdentityOccurrence>),
    /// v61.1.0 (CIRISPersist#1190) — `list_attestations_since_by_prefixes`.
    /// APPEND-ONLY (Growth).
    ServedAttestationPage(
        crate::federation::types::ServePage<crate::federation::types::ServedAttestation>,
    ),
    /// v61.1.0 (CIRISPersist#1163) — `list_owner_bindings_since`.
    /// APPEND-ONLY (Growth).
    OwnerBindingPage(
        crate::federation::types::ServePage<crate::federation::types::OwnerBindingChange>,
    ),
    /// v61.4.0 (CIRISPersist#1244) — `blackhole_list`. APPEND-ONLY (Growth).
    BlackholeRecords(Vec<crate::federation::BlackholeRecord>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `get_attestation`. APPEND-ONLY (Growth).
    Attestation(Option<Attestation>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_settled_self_roster_proposals`. APPEND-ONLY (Growth).
    SelfRosterReceipts(Vec<crate::federation::self_roster::SelfRosterReceipt>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `get_active_halt`. APPEND-ONLY (Growth).
    ActiveHalt(Option<accord_quorum::ActiveHalt>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `lookup_role_withdrawal`. APPEND-ONLY (Growth).
    RoleWithdrawal(Option<crate::federation::admission::RoleWithdrawal>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `lookup_family`. APPEND-ONLY (Growth).
    Family(Option<Family>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `lookup_community`. APPEND-ONLY (Growth).
    Community(Option<Community>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_families_for_member`. APPEND-ONLY (Growth).
    Families(Vec<Family>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `family_roster_signers`, `community_roster_signers`. APPEND-ONLY (Growth).
    RosterSigners(types::CommunityRosterSigners),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_family_membership_revocations_for`. APPEND-ONLY (Growth).
    FamilyMembershipRevocations(Vec<FamilyMembershipRevocation>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_family_membership_widenings_for`. APPEND-ONLY (Growth).
    FamilyMembershipWidenings(Vec<types::FamilyMembershipWidening>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_lineage_head_cosigns_for`. APPEND-ONLY (Growth).
    LineageHeadCosigns(Vec<crate::federation::lineage_witness::LineageHeadCosign>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `lookup_signed_community`. APPEND-ONLY (Growth).
    SignedCommunity(Option<SignedCommunity>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `lookup_canonical_withdrawal`. APPEND-ONLY (Growth).
    CanonicalWithdrawal(Option<crate::federation::admission::CanonicalWithdrawal>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_canonical_withdrawals`. APPEND-ONLY (Growth).
    CanonicalWithdrawals(Vec<crate::federation::admission::CanonicalWithdrawal>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `vote_window_first_held`. APPEND-ONLY (Growth).
    OptionalInstant(Option<chrono::DateTime<chrono::Utc>>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_cosign_aliases`. APPEND-ONLY (Growth).
    CosignAliases(Vec<(String, String)>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `cosign_alias`. APPEND-ONLY (Growth).
    CosignAlias(Option<(String, String)>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `get_accord_decision`. APPEND-ONLY (Growth).
    AccordDecision(Option<accord_quorum::StoredDecision>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `list_accord_proposals_by_anchor`. APPEND-ONLY (Growth).
    AccordProposals(Vec<accord_quorum::StoredProposal>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `purge_tombstoned`, `key_grant_held_owner`, `node_key_id`. APPEND-ONLY (Growth).
    OptionalString(Option<String>),
    /// v61.4.0 (CIRISPersist#1244 round 2) — `hardware_attestation_policy`. APPEND-ONLY (Growth).
    HardwareAttestationPolicy(crate::federation::HardwareAttestationPolicy),
    /// v62.0.0 (JSON-cut slice D) — what `PutEdition2Statement` did.
    /// APPEND-ONLY (Growth).
    Edition2StatementOutcome(Edition2StatementOutcome),
    /// v62.0.0 (JSON-cut slice D) — `ApplyReplicatedStatement`'s typed
    /// outcome: a `Refused` is a policy outcome carried HERE, never flattened
    /// to [`Self::Err`]. APPEND-ONLY (Growth).
    ReplicatedStatementOutcome(Edition2ReplicatedOutcome),
    /// v62.0.0 (JSON-cut slice D) — `edition2_statements_since`.
    /// APPEND-ONLY (Growth).
    Edition2StatementPage(Vec<Edition2ServedStatement>),
    /// v62.0.0 (JSON-cut slice D) — `bundles_in_force`. APPEND-ONLY (Growth).
    BundlesInForce(Vec<Edition2BundleInForce>),
    /// v62.0.0 (CC 2.7) — **a method failure with its reading**: the
    /// error's stable `kind()` token, its [`Error::is_wait`] answer and its
    /// text ([`CapsuleError`]). Every op whose method answers a
    /// [`crate::federation::Error`] fails with this; [`Self::Err`] stays for
    /// the failures that carry no federation kind (an op that does not parse,
    /// a host that offers no blackhole or detection surface, the derived
    /// detection door). The consumer's proxy rebuilds it as
    /// [`Error::Relayed`] (a relayed `federation_backend` as
    /// [`Error::Backend`] itself), so a retryable ordering gap no longer
    /// reaches a capsule host as a database outage. APPENDED, but an existing
    /// op can now answer it, so a consumer built against 13 fails to decode
    /// it: [`DIRECTORY_ABI_VERSION`] 13 → 14.
    TypedErr(CapsuleError),
    /// v61.4.2 — `list_community_membership_revocations_for`. APPEND-ONLY (Growth).
    CommunityMembershipRevocations(Vec<CommunityMembershipRevocation>),
    /// v61.4.2 — `list_community_membership_widenings_for`. APPEND-ONLY (Growth).
    CommunityMembershipWidenings(Vec<types::CommunityMembershipWidening>),
    /// v61.4.2 (the capsule stub sweep) — `communities_containing`, `list_communities_for_member`. APPEND-ONLY (Growth).
    Communities(Vec<Community>),
    /// v61.4.2 (the capsule stub sweep) — `attestation_insert_local`, `attestation_upsert_local`: the row id. APPEND-ONLY (Growth).
    AttestationId(String),
    /// v61.4.2 (the capsule stub sweep) — `attestation_type_census`. APPEND-ONLY (Growth).
    AttestationTypeCounts(Vec<crate::federation::row_type::AttestationTypeCount>),
    /// v61.4.2 (the capsule stub sweep) — `dag_manifests_of_chunk`. APPEND-ONLY (Growth).
    ChunkManifests(Vec<[u8; 32]>),
    /// v61.4.2 (the capsule stub sweep) — `enter_mesh`. APPEND-ONLY (Growth).
    MeshCrossing(crate::federation::MeshCrossingOutcome),
    /// v61.4.2 (the capsule stub sweep) — `get_accord_proposal`. APPEND-ONLY (Growth).
    AccordProposal(Option<accord_quorum::StoredProposal>),
    /// v61.4.2 (the capsule stub sweep) — `list_accord_participations`. APPEND-ONLY (Growth).
    AccordParticipations(Vec<accord_quorum::StoredParticipation>),
    /// v61.4.2 (the capsule stub sweep) — `list_group_versions`. APPEND-ONLY (Growth).
    GroupVersions(Vec<cohort::GroupVersion>),
    /// v61.4.2 (the capsule stub sweep) — `list_location_proofs_for`. APPEND-ONLY (Growth).
    LocationProofs(Vec<LocationProof>),
    /// v61.4.2 (the capsule stub sweep) — `supersede_group_row`: the new version. APPEND-ONLY (Growth).
    GroupRowVersion(u32),
    /// v62.0.0 (v62 P8-fix5) — `held_rows_for`. APPEND-ONLY (Growth).
    HeldRows(Vec<crate::federation::edition2::second_signer_voice::HeldRow>),
    /// v62.0.0 (v62 P8-fix5) — `voice_status` / `submit_voice`. APPEND-ONLY
    /// (Growth).
    VoiceOutcome(crate::federation::edition2::second_signer_voice::VoiceOutcome),
    /// v62.0.0 (ceremony gap 4) — what `PutGenesisBundle` did. APPEND-ONLY
    /// (Growth).
    GenesisAdmission(Edition2GenesisAdmission),
    /// v62.0.0 (ceremony gap 2) — `edition2::transport_rebind::rebind_held_for`.
    /// APPEND-ONLY (Growth).
    RebindHeld(Option<Edition2HeldRebind>),
    /// v62.0.0 (F0-cp5) — `VerifyCompositeViaDirectory`: the verify VERDICT,
    /// intact. `Ok` is the signer's identity-ref; a refusal rides INSIDE this
    /// variant with its token and whether it is a wait. A failed directory
    /// read is the top-level `TypedErr` (verify could not run). APPEND-ONLY
    /// (Growth).
    CompositeVerify(Result<String, CompositeVerifyRefusal>),
    /// v62.0.0 (PX-fix1) — `edition2_statements_about`, `edition2_voices`,
    /// `edition2_objects`: statements as received. APPEND-ONLY (Growth).
    Edition2Statements(Vec<Vec<u8>>),
    /// v62.0.0 (PX-fix1) — `edition2_rows_naming`, `fold_dependents`,
    /// `fold_slot_rows`: node-computed row ids. APPEND-ONLY (Growth).
    Edition2RowIds(Vec<[u8; 32]>),
    /// v62.0.0 (PX-fix1) — `edition2_statement_ids_since` (lowercase hex).
    /// APPEND-ONLY (Growth).
    Edition2StatementIds(Vec<String>),
    /// v62.0.0 (PX-fix1) — `fold_held`. APPEND-ONLY (Growth).
    FoldHeldReason(Option<Edition2HeldReason>),
    /// v62.0.0 (PX-fix1) — `fold_held_page`. APPEND-ONLY (Growth).
    FoldHeldReasons(Vec<Edition2HeldReason>),
    /// v62.0.0 (PX-fix1) — `fold_state`. APPEND-ONLY (Growth).
    FoldStateOf(Option<Edition2FoldState>),
    /// v62.0.0 (PR-fix1) — `PeerRooting`: the peer verdict, intact (a
    /// `not_rooted` or `cannot_tell_yet` answer rides inside it). A failed
    /// directory read is the top-level `TypedErr`. APPEND-ONLY (Growth).
    PeerRooting(crate::federation::edition2::peer_rooting::PeerRooting),
    /// v62.0.0 (AU-fix2) — `admission_unit_rows`. APPEND-ONLY (Growth).
    AdmissionUnitRows(Vec<crate::federation::edition2::admission_unit::AdmissionUnitRow>),
    /// v62.0.0 (AU-fix2) — `AdmissionUnitRunnable`: the host's answer.
    /// APPEND-ONLY (Growth).
    AdmissionUnitAnswer(AdmissionUnitAnswerWire),
    /// v62.0.0 (PX-fix1) — `put_touch_claim_local`. APPEND-ONLY (Growth).
    TouchApplied(crate::federation::freshness::TouchApplyOutcome),
    /// v62.0.0 (PX-fix1) — `freshness_floor`. APPEND-ONLY (Growth).
    FreshnessFloorOf(Option<types::FreshnessFloor>),
    /// v62.0.0 (RL-fix1, ruling (B)) — `AccordRescanNeeded`. APPEND-ONLY
    /// (Growth).
    AccordRescans(Vec<crate::federation::edition2::accord_rescan::AccordRescan>),
    /// v62.0.0 (RL-fix3) — `DialHintsFor`. APPEND-ONLY (Growth).
    DialHints(Option<crate::federation::edition2::contact::DialHints>),
    /// v62.0.0 (RL-fix3) — `ListDialHints`. APPEND-ONLY (Growth).
    DialHintsList(Vec<crate::federation::edition2::contact::DialHints>),
    /// v62.0.0 (RL-fix3) — `AdmitPreSealAnswer`. APPEND-ONLY (Growth).
    PreSealAdmission(Edition2PreSealAdmission),
    /// v62.0.0 (RL-fix3) — `AdmitContactOwnerRows`. APPEND-ONLY (Growth).
    ContactOwner(Edition2ContactOwner),
    /// v62.0.0 (PX-fix3) — `list_group_tips`. APPEND-ONLY (Growth).
    GroupTips(Vec<cohort::GroupTip>),
    /// v62.0.0 (RL-fix2c) — `ServeStanding`. APPEND-ONLY (Growth).
    ServeStanding(crate::federation::edition2::serve::ServeStanding),
}

/// v62.0.0 (AU-fix2; CC 2.7.11) — the host's answer for one
/// `admission:unit` row
/// ([`AdmissionAnswer`](crate::federation::edition2::admission_unit::AdmissionAnswer))
/// as it crosses the capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionUnitAnswerWire {
    /// May the unit run?
    pub runnable: bool,
    /// The failing leg's token (`None` when runnable).
    pub token: Option<String>,
    /// The failing leg's detail (`None` when runnable).
    pub detail: Option<String>,
    /// The Transparency Service whose receipt verified (runnable only).
    pub service: Option<String>,
    /// The voice the receipt registered, hex (runnable only).
    pub statement_id: Option<String>,
    /// The row the answer read, if any.
    pub row: Option<crate::federation::edition2::admission_unit::AdmissionUnitRow>,
}

impl AdmissionUnitAnswerWire {
    /// The wire form of `a`.
    #[must_use]
    pub fn of(a: &crate::federation::edition2::admission_unit::AdmissionAnswer) -> Self {
        use crate::federation::edition2::admission_unit::AdmissionAnswer;
        let (service, statement_id) = match a {
            AdmissionAnswer::Runnable {
                service,
                statement_id,
                ..
            } => (Some(service.clone()), Some(hex::encode(statement_id))),
            AdmissionAnswer::NotRunnable { .. } => (None, None),
        };
        Self {
            runnable: a.is_runnable(),
            token: a.token().map(str::to_owned),
            detail: a.detail().map(str::to_owned),
            service,
            statement_id,
            row: a.row().cloned(),
        }
    }
}

/// v62.0.0 (F0-cp5) — a refusal of
/// [`verify_composite_via_directory`](crate::federation::edition2::composite_verify::verify_composite_via_directory)
/// across the capsule: its stable token
/// (`verify_component_signature`, `verify_unknown_key`, …), whether the same
/// call may succeed later (a record that waits, an instant not yet covered),
/// and the message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeVerifyRefusal {
    /// The refusal's stable token.
    pub token: String,
    /// A wait, not a final refusal.
    pub retryable: bool,
    /// The refusal's message (leads with the token).
    pub detail: String,
}

/// v62.0.0 (CC 2.7) — a failed op's error as it crosses the capsule: what
/// [`DirectoryOpResult::TypedErr`] carries. Built by [`op_err`] /
/// [`op_err_typed`] on the host side; [`CapsuleError::into_error`] on the
/// consumer side. Its own shape is pinned by [`DIRECTORY_ABI_VERSION`] (the
/// digest gate reads enum bodies only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleError {
    /// The host error's stable [`Error::kind`] token.
    pub kind: String,
    /// The host's [`Error::is_wait`]: `true` for an ordering gap a re-offer
    /// can turn into an admission.
    pub wait: bool,
    /// The host error's text, exactly as the pre-v62 `Err(String)` carried
    /// it (or [`typed_error_string`] on the ops that already used it).
    pub message: String,
}

/// The kinds a consumer interns, at most: the host's kind tokens are a
/// closed set (one per [`Error`] arm plus the refusal tokens some arms
/// carry), so this bound is never reached by a conformant host; a host that
/// sends more is answered `federation_backend` rather than growing the
/// consumer's memory.
const MAX_RELAYED_KINDS: usize = 1024;

/// The `&'static str` for a relayed kind token, interned once per distinct
/// token. A token that is not lowercase snake case of at most 96 bytes, or
/// past [`MAX_RELAYED_KINDS`], is `federation_backend`.
fn intern_relayed_kind(kind: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static KINDS: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    const FALLBACK: &str = "federation_backend";
    let well_formed = !kind.is_empty()
        && kind.len() <= 96
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !well_formed {
        return FALLBACK;
    }
    let set = KINDS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut held = match set.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(&k) = held.get(kind) {
        return k;
    }
    if held.len() >= MAX_RELAYED_KINDS {
        return FALLBACK;
    }
    let leaked: &'static str = Box::leak(kind.to_owned().into_boxed_str());
    held.insert(leaked);
    leaked
}

impl CapsuleError {
    /// The host side: `e` with its kind, its wait and its text.
    #[must_use]
    pub fn of(e: &Error) -> Self {
        Self {
            kind: e.kind().to_owned(),
            wait: e.is_wait(),
            message: e.to_string(),
        }
    }

    /// The consumer side: the error the proxy answers. A relayed
    /// `federation_backend` is [`Error::Backend`] with the host's text,
    /// byte-identical to the pre-v62 flattening (so [`Error::is_duplicate_key`]
    /// and every other reader of that arm read it as before); every other
    /// kind is [`Error::Relayed`], whose `kind()` and `is_wait()` are the
    /// host's.
    #[must_use]
    pub fn into_error(self) -> Error {
        if self.kind == "federation_backend" {
            return Error::Backend(self.message);
        }
        Error::Relayed {
            kind: intern_relayed_kind(&self.kind),
            wait: self.wait,
            message: self.message,
        }
    }
}

impl DirectoryOpResult {
    /// v62.0.0 — the pre-v62 reading of a failure: a
    /// [`Self::TypedErr`] becomes [`Self::Err`] with the same text, anything
    /// else is unchanged. For a consumer that branches on the text only.
    #[must_use]
    pub fn into_flattened(self) -> Self {
        match self {
            Self::TypedErr(t) => Self::Err(t.message),
            other => other,
        }
    }
}

/// v62.0.0 (CC 2.7) — a failed op's answer: [`DirectoryOpResult::TypedErr`]
/// carrying `e`'s kind, its [`Error::is_wait`] and `e.to_string()` (the text
/// the pre-v62 `Err(String)` carried).
#[must_use]
pub fn op_err(e: &Error) -> DirectoryOpResult {
    DirectoryOpResult::TypedErr(CapsuleError::of(e))
}

/// [`op_err`] with [`typed_error_string`] as the text, for the ops that
/// already answered that reading (the edition-2 ops and the earlier-form
/// refusal).
#[must_use]
pub fn op_err_typed(e: &Error) -> DirectoryOpResult {
    DirectoryOpResult::TypedErr(CapsuleError {
        message: typed_error_string(e),
        ..CapsuleError::of(e)
    })
}

// ── v62.0.0 (JSON-cut slice D) — the edition-2 payload types ────────────
//
// The edition-2 store's own types (`RowId`, `StatementCursor`,
// `ServedStatement`, `BundleInForce`, `StatementOutcome`) carry no serde
// derive; these are their wire mirrors, converted at the dispatch arm. Each is
// NEW at v62, so it is growth, and its own shape is pinned by
// `DIRECTORY_ABI_VERSION` from here on (the digest gate reads enum bodies
// only).

/// The wire mirror of [`crate::federation::edition2::store::StatementCursor`]:
/// a position in this node's admission order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edition2Cursor {
    /// The admission position, POSIX µs.
    pub admitted_us: i64,
    /// The statement id.
    pub statement_id: [u8; 32],
}

impl From<crate::federation::edition2::store::StatementCursor> for Edition2Cursor {
    fn from(c: crate::federation::edition2::store::StatementCursor) -> Self {
        Self {
            admitted_us: c.admitted_us,
            statement_id: c.statement_id,
        }
    }
}

impl From<Edition2Cursor> for crate::federation::edition2::store::StatementCursor {
    fn from(c: Edition2Cursor) -> Self {
        Self {
            admitted_us: c.admitted_us,
            statement_id: c.statement_id,
        }
    }
}

/// The wire mirror of [`crate::federation::edition2::store::ServedStatement`]:
/// one held statement as received (CC 2.6.1.2), with its position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2ServedStatement {
    /// Pass the last one served back as the cursor.
    pub cursor: Edition2Cursor,
    /// The statement's bytes as received.
    pub bytes: Vec<u8>,
}

impl From<crate::federation::edition2::store::ServedStatement> for Edition2ServedStatement {
    fn from(s: crate::federation::edition2::store::ServedStatement) -> Self {
        Self {
            cursor: s.cursor.into(),
            bytes: s.bytes,
        }
    }
}

/// The wire mirror of [`crate::federation::edition2::ingest::StatementOutcome`]:
/// where the edition-2 door kept a statement. `row_id` is the id THIS node
/// computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edition2StatementOutcome {
    /// A key-plane row (`key:record`, `key:revocation`).
    KeyPlane {
        /// The row id.
        row_id: [u8; 32],
        /// Was it new.
        new: bool,
    },
    /// A further voice of a row already held.
    Voice {
        /// The row id.
        row_id: [u8; 32],
        /// Was the statement new.
        new: bool,
    },
    /// A row admitted through the attestation gates.
    Row {
        /// The row id.
        row_id: [u8; 32],
        /// Was the statement new.
        new: bool,
    },
    /// v62.0.0 (T1) — a counted row short of its count: the statement is
    /// held, the row waits for its voices. APPENDED.
    Pending {
        /// The row id.
        row_id: [u8; 32],
        /// Was the statement new.
        new: bool,
    },
}

impl From<crate::federation::edition2::ingest::StatementOutcome> for Edition2StatementOutcome {
    fn from(o: crate::federation::edition2::ingest::StatementOutcome) -> Self {
        use crate::federation::edition2::ingest::StatementOutcome as S;
        match o {
            S::KeyPlane { row_id, new } => Self::KeyPlane {
                row_id: row_id.0,
                new,
            },
            S::Voice { row_id, new } => Self::Voice {
                row_id: row_id.0,
                new,
            },
            S::Row { row_id, new } => Self::Row {
                row_id: row_id.0,
                new,
            },
            S::Pending { row_id, new } => Self::Pending {
                row_id: row_id.0,
                new,
            },
        }
    }
}

/// The wire mirror of
/// [`crate::federation::edition2::ingest::ReplicatedStatementOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edition2ReplicatedOutcome {
    /// New here and kept.
    Admitted(Edition2StatementOutcome),
    /// Already held byte for byte: nothing changed.
    Unchanged(Edition2StatementOutcome),
    /// Not kept; the store is untouched. Advances the sender's cursor.
    Refused {
        /// Which branch refused.
        reason: crate::federation::attestation_apply::AttestationRefusalReason,
    },
}

impl From<crate::federation::edition2::ingest::ReplicatedStatementOutcome>
    for Edition2ReplicatedOutcome
{
    fn from(o: crate::federation::edition2::ingest::ReplicatedStatementOutcome) -> Self {
        use crate::federation::edition2::ingest::ReplicatedStatementOutcome as R;
        match o {
            R::Admitted(s) => Self::Admitted(s.into()),
            R::Unchanged(s) => Self::Unchanged(s.into()),
            R::Refused { reason } => Self::Refused { reason },
        }
    }
}

/// v62.0.0 (RL-fix3) — the wire mirror of
/// [`crate::federation::edition2::contact::PreSealAdmission`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2PreSealAdmission {
    /// The node's key record at the replicated door.
    pub key_record: Edition2ReplicatedOutcome,
    /// The node's bind at the replicated door.
    pub route: Edition2ReplicatedOutcome,
    /// Does `transit_kex_pair_for(node)` answer now?
    pub transit_ready: bool,
}

impl From<crate::federation::edition2::contact::PreSealAdmission> for Edition2PreSealAdmission {
    fn from(a: crate::federation::edition2::contact::PreSealAdmission) -> Self {
        Self {
            key_record: a.key_record.into(),
            route: a.route.into(),
            transit_ready: a.transit_ready,
        }
    }
}

/// v62.0.0 (RL-fix3) — the wire mirror of
/// [`crate::federation::edition2::contact::ContactOwner`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2ContactOwner {
    /// The outcomes, the owner's key record first.
    pub outcomes: Vec<Edition2ReplicatedOutcome>,
    /// Does the node's one live owner resolve to the code's identity now?
    pub owner_resolved: bool,
}

impl From<crate::federation::edition2::contact::ContactOwner> for Edition2ContactOwner {
    fn from(o: crate::federation::edition2::contact::ContactOwner) -> Self {
        Self {
            outcomes: o.outcomes.into_iter().map(Into::into).collect(),
            owner_resolved: o.owner_resolved,
        }
    }
}

/// v62.0.0 (LF-fix2, T5) — the consumer side: the proxy's
/// `replicated_statement_door` reads the op's outcome back as the door's own.
impl From<Edition2StatementOutcome> for crate::federation::edition2::ingest::StatementOutcome {
    fn from(o: Edition2StatementOutcome) -> Self {
        use crate::federation::edition2::names::RowId;
        match o {
            Edition2StatementOutcome::KeyPlane { row_id, new } => Self::KeyPlane {
                row_id: RowId(row_id),
                new,
            },
            Edition2StatementOutcome::Voice { row_id, new } => Self::Voice {
                row_id: RowId(row_id),
                new,
            },
            Edition2StatementOutcome::Row { row_id, new } => Self::Row {
                row_id: RowId(row_id),
                new,
            },
            Edition2StatementOutcome::Pending { row_id, new } => Self::Pending {
                row_id: RowId(row_id),
                new,
            },
        }
    }
}

/// v62.0.0 (LF-fix2, T5) — [`Edition2ReplicatedOutcome`] back to the door's
/// outcome (the proxy's `replicated_statement_door`).
impl From<Edition2ReplicatedOutcome>
    for crate::federation::edition2::ingest::ReplicatedStatementOutcome
{
    fn from(o: Edition2ReplicatedOutcome) -> Self {
        match o {
            Edition2ReplicatedOutcome::Admitted(s) => Self::Admitted(s.into()),
            Edition2ReplicatedOutcome::Unchanged(s) => Self::Unchanged(s.into()),
            Edition2ReplicatedOutcome::Refused { reason } => Self::Refused { reason },
        }
    }
}

/// The wire mirror of one tip of
/// [`crate::federation::edition2::genesis::bundles_in_force`] (Verify's
/// `GenesisPlacement`): the members PyO3's `bundles_in_force_json` serves,
/// with the identity-refs only (a consumer that needs a seat's keys reads its
/// key record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2BundleInForce {
    /// The bundle's object id.
    pub object_id: [u8; 32],
    /// `version`.
    pub version: u32,
    /// `refs.prev`, on a later bundle.
    pub prev: Option<[u8; 32]>,
    /// `asserted_at`, POSIX ms.
    pub asserted_at: u64,
    /// The accord's name.
    pub family_key_id: String,
    /// The roster's identity-refs, in `holders` order.
    pub holders: Vec<String>,
    /// The seats' identity-refs, in `serve_nodes` order.
    pub serve_nodes: Vec<String>,
    /// The identity-refs whose statements counted, sorted.
    pub counted: Vec<String>,
}

impl From<&crate::federation::edition2::genesis::GenesisPlacement> for Edition2BundleInForce {
    fn from(t: &crate::federation::edition2::genesis::GenesisPlacement) -> Self {
        Self {
            object_id: t.object_id,
            version: t.version,
            prev: t.prev,
            asserted_at: t.asserted_at,
            family_key_id: t.family_key_id.clone(),
            holders: t.holders.iter().map(|h| h.identity_ref.clone()).collect(),
            serve_nodes: t.seats.iter().map(|x| x.identity_ref.clone()).collect(),
            counted: t.counted.clone(),
        }
    }
}

/// v62.0.0 (ceremony gap 4) — the wire mirror of
/// [`crate::federation::edition2::genesis::Anchor`] (CC 5.3.4): the reader's
/// anchor for a first bundle, never a member of the wire bundle itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenesisAnchor {
    /// The first bundle's holders' composite-key thumbprints.
    Thumbprints(Vec<[u8; 32]>),
    /// The object id of one first bundle; any other first bundle is void.
    ObjectId([u8; 32]),
}

impl From<GenesisAnchor> for crate::federation::edition2::genesis::Anchor {
    fn from(a: GenesisAnchor) -> Self {
        match a {
            GenesisAnchor::Thumbprints(t) => Self::Thumbprints(t.into_iter().collect()),
            GenesisAnchor::ObjectId(o) => Self::ObjectId(o),
        }
    }
}

/// v62.0.0 (ceremony gap 4) — the wire mirror of
/// [`crate::federation::edition2::genesis::NotPlaced`]: an offered bundle the
/// door did not place (nothing of it stored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2NotPlaced {
    /// The object id.
    pub object_id: [u8; 32],
    /// Verify's token, or `genesis_bundle_waiting`.
    pub token: String,
    /// Verify's reason or detail; for a waiting bundle, what it waits on.
    pub detail: Option<String>,
    /// It waits on a named row or its predecessor: retryable.
    pub waiting: bool,
}

/// v62.0.0 (ceremony gap 4) — the wire mirror of
/// [`crate::federation::edition2::genesis::GenesisAdmission`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2GenesisAdmission {
    /// Each offered bundle placed, in lineage order.
    pub placed: Vec<Edition2BundleInForce>,
    /// Each offered bundle not placed.
    pub not_placed: Vec<Edition2NotPlaced>,
    /// Offered statements (by index) that are neither a bundle voice nor a
    /// row.
    pub unreadable: Vec<u64>,
    /// The tips in force after the store ([`crate::federation::edition2::genesis::GenesisInForce::tips`]):
    /// empty on a fork of the genesis.
    pub tips: Vec<Edition2BundleInForce>,
}

impl From<&crate::federation::edition2::genesis::GenesisAdmission> for Edition2GenesisAdmission {
    fn from(a: &crate::federation::edition2::genesis::GenesisAdmission) -> Self {
        Self {
            placed: a.placed.iter().map(Edition2BundleInForce::from).collect(),
            not_placed: a
                .not_placed
                .iter()
                .map(|n| Edition2NotPlaced {
                    object_id: n.object_id,
                    token: n.token.to_owned(),
                    detail: n.detail.clone(),
                    waiting: n.waiting,
                })
                .collect(),
            unreadable: a.unreadable.iter().map(|i| *i as u64).collect(),
            tips: a
                .in_force
                .tips()
                .into_iter()
                .map(Edition2BundleInForce::from)
                .collect(),
        }
    }
}

/// v62.0.0 (ceremony gap 2) — the wire mirror of
/// [`crate::federation::edition2::transport_rebind::HeldRebind`]: the counted
/// re-bind live for a seat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2HeldRebind {
    /// The re-bind row's id.
    pub row_id: [u8; 32],
    /// The X-Wing transit key it makes live (1216 bytes).
    pub transit_xwing_pubkey: Vec<u8>,
    /// The bundle it is counted over (`refs.head`).
    pub head: [u8; 32],
}

impl From<&crate::federation::edition2::transport_rebind::HeldRebind> for Edition2HeldRebind {
    fn from(r: &crate::federation::edition2::transport_rebind::HeldRebind) -> Self {
        Self {
            row_id: r.row_id.0,
            transit_xwing_pubkey: r.transit_xwing_pubkey.to_vec(),
            head: r.head.0,
        }
    }
}

/// v62.0.0 (PX-fix1) — the wire mirror of
/// [`crate::federation::edition2::fold::HeldReason`]: why a held row
/// concludes nothing. Both directions are total (the proxy rebuilds the
/// reason the host's store read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2HeldReason {
    /// The row id.
    pub row_id: [u8; 32],
    /// The row's family.
    pub family: String,
    /// The tier the row concludes at.
    pub tier: String,
    /// Did the row first arrive through the replicated door?
    pub replicated: bool,
    /// Its plane.
    pub plane: String,
    /// The reason token.
    pub reason: String,
    /// The refusal the gate would have raised, as text.
    pub detail: String,
    /// The HOST's clock (POSIX µs) when the row was first held for this
    /// reason.
    pub since_us: i64,
}

impl From<&crate::federation::edition2::fold::HeldReason> for Edition2HeldReason {
    fn from(h: &crate::federation::edition2::fold::HeldReason) -> Self {
        Self {
            row_id: h.row_id.0,
            family: h.family.clone(),
            tier: h.tier.clone(),
            replicated: h.replicated,
            plane: h.plane.clone(),
            reason: h.reason.clone(),
            detail: h.detail.clone(),
            since_us: h.since_us,
        }
    }
}

impl From<Edition2HeldReason> for crate::federation::edition2::fold::HeldReason {
    fn from(h: Edition2HeldReason) -> Self {
        Self {
            row_id: crate::federation::edition2::names::RowId(h.row_id),
            family: h.family,
            tier: h.tier,
            replicated: h.replicated,
            plane: h.plane,
            reason: h.reason,
            detail: h.detail,
            since_us: h.since_us,
        }
    }
}

/// v62.0.0 (PX-fix1) — the wire mirror of
/// [`crate::federation::edition2::fold::FoldState`]: the fold's whole record
/// of one row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2FoldState {
    /// The row id.
    pub row_id: [u8; 32],
    /// The row's family.
    pub family: String,
    /// The tier it first arrived at.
    pub tier: String,
    /// Did it first arrive through the replicated door?
    pub replicated: bool,
    /// Its plane.
    pub plane: String,
    /// Its projection slot.
    pub slot: String,
    /// `None`: concluded. `Some`: why it concludes nothing.
    pub held: Option<Edition2HeldReason>,
}

impl From<&crate::federation::edition2::fold::FoldState> for Edition2FoldState {
    fn from(f: &crate::federation::edition2::fold::FoldState) -> Self {
        Self {
            row_id: f.row_id.0,
            family: f.family.clone(),
            tier: f.tier.clone(),
            replicated: f.replicated,
            plane: f.plane.clone(),
            slot: f.slot.clone(),
            held: f.held.as_ref().map(Edition2HeldReason::from),
        }
    }
}

impl From<Edition2FoldState> for crate::federation::edition2::fold::FoldState {
    fn from(f: Edition2FoldState) -> Self {
        Self {
            row_id: crate::federation::edition2::names::RowId(f.row_id),
            family: f.family,
            tier: f.tier,
            replicated: f.replicated,
            plane: f.plane,
            slot: f.slot,
            held: f.held.map(Into::into),
        }
    }
}

/// v62.0.0 (JSON-cut slice D) — an [`Error`] flattened for the capsule WITH
/// its stable reading: `"{kind}: {plane}: {reason}: {message}"` for a
/// [`Error::MalformedRow`] (the prefix is Python's
/// `ValueError("federation_malformed_row: {plane}: {reason}")`), and
/// `"{kind}: {message}"` for every other error, so a consumer tells the
/// retryable `federation_attester_key_unknown` from a terminal refusal
/// without parsing prose. Used by the edition-2 ops and the earlier-form
/// refusal; the older ops keep their `to_string()` flattening.
#[must_use]
pub fn typed_error_string(e: &Error) -> String {
    match e {
        Error::MalformedRow {
            plane,
            reason,
            message,
        } => format!("{}: {plane}: {reason}: {message}", e.kind()),
        other => format!("{}: {other}", other.kind()),
    }
}

/// v62.0.0 (JSON-cut slice D, CC 2.6.1.12) — **the earlier-form refusal at
/// the capsule.** Each op that carries an earlier-form signed object (a JSON
/// object signed over its JCS image) answers
/// [`crate::federation::edition2::door::refuse_earlier_form`]'s refusal
/// before dispatch, under the plane the Rust door names. It is inert until
/// [`crate::federation::edition2::door::EARLIER_FORM_DOORS_SHUT`] is `true`.
/// A row that carries its edition-2 statement (`ceg_statement`) is the
/// edition-2 door's mapping and passes
/// ([`crate::federation::edition2::door::refuse_earlier_form_row`]).
///
/// # Errors
/// `federation_malformed_row` / `earlier_form_object` once the doors are shut.
pub fn refuse_earlier_form_op(op: &DirectoryOp) -> Result<(), Error> {
    use crate::federation::edition2::door::{refuse_earlier_form, refuse_earlier_form_row};
    match op {
        DirectoryOp::PutAttestation { attestation }
        | DirectoryOp::PutAttestationAuthored { attestation }
        | DirectoryOp::ApplyReplicatedAttestation { attestation }
        | DirectoryOp::PutAttestationSynced { attestation, .. }
        | DirectoryOp::ApplyReplicatedAttestationSynced { attestation, .. } => {
            refuse_earlier_form_row("attestation", &attestation.attestation)
        }
        other => match earlier_form_op_plane(other) {
            Some(plane) => refuse_earlier_form(plane),
            None => Ok(()),
        },
    }
}

/// v62.0.0 (JSON-cut slice D) — the door plane of each [`DirectoryOp`] that
/// carries an earlier-form signed object, `None` for the rest. Exhaustive, so
/// an appended op must be classified here before it compiles.
#[must_use]
pub fn earlier_form_op_plane(op: &DirectoryOp) -> Option<&'static str> {
    match op {
        // ── inbound earlier-form signed objects ──
        DirectoryOp::PutPublicKey { .. } | DirectoryOp::ApplyReplicatedKeyRecord { .. } => {
            Some("key_record")
        }
        DirectoryOp::PutRevocation { .. } => Some("revocation"),
        DirectoryOp::PutLocationProof { .. } => Some("location_proof"),
        DirectoryOp::PutIdentityOccurrence { .. } => Some("identity_occurrence"),
        DirectoryOp::PutIdentityOccurrenceRevocation { .. } => {
            Some("identity_occurrence_revocation")
        }
        DirectoryOp::PutFamily { .. } => Some("family"),
        DirectoryOp::PutCommunity { .. } => Some("community"),
        DirectoryOp::PutTransportDestination { .. }
        | DirectoryOp::PutSignedTransportDestination { .. } => Some("transport_destination"),
        DirectoryOp::ApplyReplicatedAccordEvidence { .. } => Some("accord_evidence"),
        DirectoryOp::PutLineageHeadCosign { .. } => Some("lineage_head_cosign"),
        DirectoryOp::PutAttestation { .. }
        | DirectoryOp::PutAttestationAuthored { .. }
        | DirectoryOp::PutAttestationSynced { .. }
        | DirectoryOp::ApplyReplicatedAttestation { .. }
        | DirectoryOp::ApplyReplicatedAttestationSynced { .. } => Some("attestation"),
        // v61.4.2 (the capsule stub sweep) — the group-plane, accord and
        // crossing writes carry an earlier-form signed object, on the plane
        // their store door refuses by.
        DirectoryOp::PutCommunityMembershipRevocation { .. }
        | DirectoryOp::PutCommunityMembershipWidening { .. } => Some("community"),
        DirectoryOp::PutFamilyMembershipRevocation { .. }
        | DirectoryOp::PutFamilyMembershipWidening { .. } => Some("family"),
        DirectoryOp::PutAccordProposal { .. }
        | DirectoryOp::PutAccordParticipation { .. }
        | DirectoryOp::PutAccordDecision { .. } => Some("accord_quorum"),
        DirectoryOp::EnterMesh { .. } => Some("enter_mesh"),
        // ── reads, folds and node-local writes: no signed object in ──
        DirectoryOp::LookupPublicKey { .. }
        | DirectoryOp::ListTransportDestinationsFor { .. }
        | DirectoryOp::LookupSharedInstanceLease { .. }
        | DirectoryOp::AcquireSharedInstanceLease { .. }
        | DirectoryOp::HeartbeatSharedInstance { .. }
        | DirectoryOp::ReleaseSharedInstanceLease { .. }
        | DirectoryOp::ListAccordHolders { .. }
        | DirectoryOp::PeerMetadataFor { .. }
        | DirectoryOp::ListHeldFountainContent { .. }
        | DirectoryOp::EvictFountainContentToTier { .. }
        | DirectoryOp::EvictFountainContentHardDelete { .. }
        | DirectoryOp::ReachableUnderScope { .. }
        | DirectoryOp::BuildDelegationGraph { .. }
        | DirectoryOp::AddPeerRecord { .. }
        | DirectoryOp::RemovePeerRecord { .. }
        | DirectoryOp::UpdatePeerAlias { .. }
        | DirectoryOp::UpdatePeerTrust { .. }
        | DirectoryOp::UpdatePeerNotes { .. }
        | DirectoryOp::UpdatePeerPolicy { .. }
        | DirectoryOp::LookupIdentityForOccurrence { .. }
        | DirectoryOp::ListAllTransportDestinations { .. }
        | DirectoryOp::ListTransportDestinationsByDestination { .. }
        | DirectoryOp::ListSignedIdentityOccurrencesFor { .. }
        | DirectoryOp::ListSignedRecords { .. }
        | DirectoryOp::ListSignedTransportDestinationsFor { .. }
        | DirectoryOp::ResolveEncryptionKeys { .. }
        | DirectoryOp::ListIdentityOccurrenceRevocationsFor { .. }
        | DirectoryOp::ListScores { .. }
        | DirectoryOp::ResolveScores { .. }
        | DirectoryOp::ListAttestationLog { .. }
        | DirectoryOp::RecordAnnouncedPeer { .. }
        | DirectoryOp::ListAnnouncedPeers
        | DirectoryOp::TrustRootValid { .. }
        | DirectoryOp::CapabilityRootsToTrustedRoot { .. }
        | DirectoryOp::ListConsentPeers { .. }
        | DirectoryOp::ListSignedLocationProofsSince { .. }
        | DirectoryOp::ListSignedTransportDestinationsSince { .. }
        | DirectoryOp::ListAttestationsSince { .. }
        | DirectoryOp::LookupSignedRecordByContentHash { .. }
        | DirectoryOp::RebuildSignedWireIndex
        | DirectoryOp::ResolveTransitEligibility { .. }
        | DirectoryOp::RevocationsFor { .. }
        | DirectoryOp::ListSignedAccordQuorumEvidenceSince { .. }
        | DirectoryOp::ListWireHashesSince { .. }
        | DirectoryOp::InsertKnownWireHash { .. }
        | DirectoryOp::KnownWireHashContains { .. }
        | DirectoryOp::ListKnownWireHashesSince { .. }
        | DirectoryOp::EvictKnownWireHashes { .. }
        | DirectoryOp::WithdrawsAdmissionDepth { .. }
        | DirectoryOp::RevocationsForSubject { .. }
        | DirectoryOp::TrustDirectionHeldAmong { .. }
        | DirectoryOp::ListKeyPlaneWireHashesSince { .. }
        | DirectoryOp::ExecuteAttestationQuery { .. }
        | DirectoryOp::ListComposersReferencingAny { .. }
        | DirectoryOp::ListIdentityOccurrenceHistoryByOccurrence { .. }
        | DirectoryOp::ListIdentityOccurrencesByOccurrenceKey { .. }
        | DirectoryOp::ListAttestationsNamingByDimension { .. }
        | DirectoryOp::ListAttestationsSinceByPrefixes { .. }
        | DirectoryOp::ListOwnerBindingsSince { .. }
        | DirectoryOp::ListKeysByIdentityType { .. }
        | DirectoryOp::ListAllTransportDestinationsUnfolded { .. }
        | DirectoryOp::ListTransportDestinationsByDestinationUnfolded { .. }
        | DirectoryOp::BlackholeList { .. }
        | DirectoryOp::BlackholeUpsert { .. }
        | DirectoryOp::BlackholeRemove { .. }
        | DirectoryOp::BlackholeRecordHit { .. }
        | DirectoryOp::BlackholePruneExpired { .. }
        | DirectoryOp::ListAttestationsReferencing { .. }
        | DirectoryOp::GetAttestation { .. }
        | DirectoryOp::ListSettledSelfRosterProposals { .. }
        | DirectoryOp::ListIdentityOccurrencesFor { .. }
        | DirectoryOp::GetActiveHalt { .. }
        | DirectoryOp::LookupRoleWithdrawal { .. }
        | DirectoryOp::LookupFamily { .. }
        | DirectoryOp::LookupCommunity { .. }
        | DirectoryOp::ListFamiliesForMember { .. }
        | DirectoryOp::FamilyRosterSigners { .. }
        | DirectoryOp::CommunityRosterSigners { .. }
        | DirectoryOp::ListFamilyMembershipRevocationsFor { .. }
        | DirectoryOp::ListFamilyMembershipWideningsFor { .. }
        | DirectoryOp::ListCommunityMembershipRevocationsFor { .. }
        | DirectoryOp::ListCommunityMembershipWideningsFor { .. }
        | DirectoryOp::AddCommunityMember { .. }
        | DirectoryOp::AddFamilyMember { .. }
        | DirectoryOp::AttestationInsertLocal { .. }
        | DirectoryOp::AttestationTypeCensus { .. }
        | DirectoryOp::AttestationUpsertLocal { .. }
        | DirectoryOp::AttestationsBindingContent { .. }
        | DirectoryOp::AttestationsBindingContentWithPlacements { .. }
        | DirectoryOp::ClearActiveHalt { .. }
        | DirectoryOp::CommunitiesContaining { .. }
        | DirectoryOp::DagManifestsOfChunk { .. }
        | DirectoryOp::GetAccordProposal { .. }
        | DirectoryOp::ListAccordParticipations { .. }
        | DirectoryOp::ListAttestationsByDimensionCiting { .. }
        | DirectoryOp::ListCommunitiesForMember { .. }
        | DirectoryOp::ListGroupVersions { .. }
        | DirectoryOp::ListLocationProofsFor { .. }
        | DirectoryOp::LookupKeysForIdentity { .. }
        | DirectoryOp::SetActiveHalt { .. }
        | DirectoryOp::SetConsentRole { .. }
        | DirectoryOp::SupersedeGroupRow { .. }
        | DirectoryOp::WithdrawLocationProof { .. }
        | DirectoryOp::ListLiveConsentGrantsBy { .. }
        | DirectoryOp::ListSettledEdition2RosterProposals { .. }
        | DirectoryOp::Edition2RosterProposal { .. }
        | DirectoryOp::ListLineageHeadCosignsFor { .. }
        | DirectoryOp::LookupSignedCommunity { .. }
        | DirectoryOp::LookupCanonicalWithdrawal { .. }
        | DirectoryOp::ListCanonicalWithdrawals { .. }
        | DirectoryOp::VoteWindowFirstHeld { .. }
        | DirectoryOp::ListCosignAliases { .. }
        | DirectoryOp::CosignAlias { .. }
        | DirectoryOp::GetAccordDecision { .. }
        | DirectoryOp::ListAccordProposalsByAnchor { .. }
        | DirectoryOp::PurgeTombstoned { .. }
        | DirectoryOp::PurgeTombstoneNotices { .. }
        | DirectoryOp::ListTargetedByDimensionPrefix { .. }
        | DirectoryOp::KeyGrantHeldOwner { .. }
        | DirectoryOp::NodeKeyId { .. }
        | DirectoryOp::WithdrawsDelegationDepth { .. }
        | DirectoryOp::HardwareAttestationPolicy { .. } => None,
        // ── the edition-2 doors and reads ──
        DirectoryOp::PutEdition2Statement { .. }
        | DirectoryOp::ApplyReplicatedStatement { .. }
        | DirectoryOp::Edition2StatementsSince { .. }
        | DirectoryOp::BundlesInForce { .. }
        // v62.0.0 (v62 P8-fix5) — edition-2 reads and the edition-2 door
        // (`SubmitVoice` puts through `put_statement`, which refuses an
        // earlier-form object itself): no earlier-form object.
        | DirectoryOp::HeldRowsFor { .. }
        | DirectoryOp::VoiceStatus { .. }
        | DirectoryOp::SubmitVoice { .. }
        // v62.0.0 (ceremony gap 4) — the genesis import door.
        | DirectoryOp::PutGenesisBundle { .. }
        // v62.0.0 (ceremony gap 2) — the seat re-bind read.
        | DirectoryOp::RebindHeldFor { .. }
        // v62.0.0 (PX-fix1) — the edition-2 and fold store reads: they read
        // held statements and fold records, and carry no signed object.
        | DirectoryOp::Edition2StatementsAbout { .. }
        | DirectoryOp::Edition2Voices { .. }
        | DirectoryOp::Edition2RowsNaming { .. }
        | DirectoryOp::Edition2Objects { .. }
        | DirectoryOp::Edition2Statement { .. }
        | DirectoryOp::Edition2StatementIdsSince { .. }
        | DirectoryOp::FoldHeld { .. }
        | DirectoryOp::FoldHeldPage { .. }
        | DirectoryOp::FoldDependents { .. }
        | DirectoryOp::FoldState { .. }
        | DirectoryOp::FoldSlotRows { .. }
        | DirectoryOp::FoldSlotHeld { .. }
        | DirectoryOp::FoldAnyRefolding { .. }
        // v62.0.0 (PX-fix1) — the node-local touch and its floor: unsigned,
        // this node's own state; no signed object rides them.
        | DirectoryOp::PutTouchClaimLocal { .. }
        | DirectoryOp::FreshnessFloor { .. }
        // v62.0.0 (PX-fix3) — a read of held tips; no signed object rides it.
        | DirectoryOp::ListGroupTips { .. } => None,
        // v62.0.0 (RL-fix1) — the replicated edition-2 door with a feed
        // position, and the accord-rescan watermark read and ack.
        | DirectoryOp::ApplyReplicatedStatementAtFeed { .. }
        | DirectoryOp::AccordRescanNeeded { .. }
        | DirectoryOp::AckAccordRescan { .. }
        // v62.0.0 (RL-fix3) — the contact path: a local unsigned record, and
        // two edition-2 doors that refuse an earlier-form object themselves.
        | DirectoryOp::RecordDialHints { .. }
        | DirectoryOp::DialHintsFor { .. }
        | DirectoryOp::ListDialHints { .. }
        | DirectoryOp::RemoveDialHints { .. }
        | DirectoryOp::AdmitPreSealAnswer { .. }
        | DirectoryOp::AdmitContactOwnerRows { .. }
        // v62.0.0 (RL-fix2c) — a read of this store's serve standing.
        | DirectoryOp::ServeStanding { .. } => None,
        // TODO(json-cut): detection events are MESH (RULINGS "Planes"), but
        // no edition-2 detection door exists yet and the Rust door
        // (`derived::put_edge_detection_event`) is not wired to the
        // switch; the capsule follows the Rust door rather than diverge.
        DirectoryOp::PutEdgeDetectionEvent { .. } => None,
        // v62.0.0 (F0-cp5) — signature checks, not doors: the earlier one is
        // a retired arm that reads nothing, the composite one admits nothing.
        DirectoryOp::VerifyHybridViaDirectory { .. }
        | DirectoryOp::VerifyCompositeViaDirectory { .. } => None,
        // v62.0.0 (PR-fix1) — the edition-2 peer verdict: a read.
        DirectoryOp::PeerRooting { .. } => None,
        // v62.0.0 (AU-fix2) — edition-2 reads: no earlier-form object.
        DirectoryOp::AdmissionUnitRows { .. } | DirectoryOp::AdmissionUnitRunnable { .. } => None,
        // v62.0.0 (K2-fix20) — an authoring read: carries no signed object.
        DirectoryOp::MayPublishFederationRendezvous { .. } => None,
    }
}

/// v61.4.0 (CIRISPersist#1244) — the refusal a blackhole op gets from a
/// directory whose [`FederationDirectory::blackhole_rules_surface`] is `None`
/// (a test double, or the memory backend).
pub const NO_BLACKHOLE_SURFACE: &str =
    "directory capsule: this directory carries no BlackholeRules surface";

/// v61.4.0 (CIRISPersist#1244) — the refusal `PutEdgeDetectionEvent` gets
/// from a directory whose [`FederationDirectory::edge_detection_surface`] is
/// `None`.
pub const NO_EDGE_DETECTION_SURFACE: &str =
    "directory capsule: this directory carries no edge-detection surface";

/// v61.4.0 (CIRISPersist#1244 round 2) — what the proxy's
/// [`FederationDirectory::node_key_id`] answers when it cannot fetch the
/// host's: a key id no row names, so an audience check refuses rather than
/// being skipped (`None` means "no audience check").
pub const NODE_KEY_ID_UNAVAILABLE: &str = "ciris-persist:directory-proxy:node-key-id-unavailable";

/// v61.4.0 (CIRISPersist#1244 round 2) — what the proxy's
/// [`FederationDirectory::hardware_attestation_policy`] answers when it
/// cannot fetch the host's: a policy that accepts no evidence, so holder
/// evidence is refused rather than judged against the default.
pub fn refuse_all_hardware_attestation_policy() -> crate::federation::HardwareAttestationPolicy {
    crate::federation::HardwareAttestationPolicy {
        accepted_hardware_types: std::collections::HashSet::new(),
        max_nonce_age: std::time::Duration::ZERO,
        accepted_custody_tiers: std::collections::HashSet::new(),
        yubico_root_der: std::borrow::Cow::Borrowed(&[]),
        android_root_ders: Vec::new(),
    }
}

/// How long a sync proxy read waits for the host before answering its
/// fail-closed value.
const BLOCKING_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    // v62.0.0 (JSON-cut slice D) — an op that carries an earlier-form signed
    // object is refused by name once the doors are shut, before any parse,
    // with the same reading as the Rust and Python doors.
    if let Err(e) = refuse_earlier_form_op(&op) {
        return op_err_typed(&e);
    }
    match op {
        DirectoryOp::LookupPublicKey { key_id } => match dir.lookup_public_key(&key_id).await {
            Ok(v) => DirectoryOpResult::PublicKey(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::PutTransportDestination { destination } => {
            match dir.put_transport_destination(&destination).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListTransportDestinationsFor { occurrence_key_id } => {
            match dir
                .list_transport_destinations_for(&occurrence_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::TransportDestinations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAllTransportDestinations {} => {
            match dir.list_all_transport_destinations().await {
                Ok(v) => DirectoryOpResult::TransportDestinations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListTransportDestinationsByDestination { destination } => {
            match dir
                .list_transport_destinations_by_destination(&destination)
                .await
            {
                Ok(v) => DirectoryOpResult::TransportDestinations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupSharedInstanceLease { instance_name } => {
            match dir.lookup_shared_instance_lease(&instance_name).await {
                Ok(v) => DirectoryOpResult::SharedLease(v),
                Err(e) => op_err(&e),
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
            Err(e) => op_err(&e),
        },
        DirectoryOp::HeartbeatSharedInstance { lease } => {
            match dir.heartbeat_shared_instance(&lease).await {
                Ok(v) => DirectoryOpResult::SharedLease(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ReleaseSharedInstanceLease { lease } => {
            match dir.release_shared_instance_lease(&lease).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAccordHolders {} => {
            match dir
                .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
                .await
            {
                Ok(v) => DirectoryOpResult::KeyRecords(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PutRevocation { revocation } => match dir.put_revocation(revocation).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        // v59.0.0 (CIRISPersist#1103, CC 2.6.8) — a host's registration
        // through the capsule is a door: the id names its own key.
        DirectoryOp::PutPublicKey { record } => {
            match crate::federation::register::check_key_id_fingerprint(dir, &record.record).await {
                Err(e) => op_err(&e),
                Ok(()) => match dir.put_public_key(record).await {
                    Ok(()) => DirectoryOpResult::Unit,
                    Err(e) => op_err(&e),
                },
            }
        }
        // #375 — the whole apply (plan + adopt_scrub_upgrade) runs INSIDE
        // persist's .so against persist's own vtable, so the capsule
        // consumer gets the real upgrade-aware outcome, not DO-NOTHING.
        // v59.0.0 (sealed-transport floor, operator ruling 2026-10-19) — the
        // framed key-record replication door is retired: a key replicates as
        // its `key:record:v1` row (`ApplyReplicatedAttestation`).
        DirectoryOp::ApplyReplicatedKeyRecord { record } => {
            let _ = record;
            op_err(&crate::federation::Error::EnvelopeKindRetired {
                kind: crate::federation::replication_policy::EnvelopeKind::Key,
            })
        }
        DirectoryOp::LookupIdentityForOccurrence { occurrence_key_id } => {
            match dir.lookup_identity_for_occurrence(&occurrence_key_id).await {
                Ok(v) => DirectoryOpResult::IdentityOccurrence(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSignedIdentityOccurrencesFor { identity_key_id } => {
            match dir
                .list_signed_identity_occurrences_for(&identity_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::SignedIdentityOccurrences(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSignedRecords {
            kind,
            subject_key_id,
        } => match dir.list_signed_records(kind, &subject_key_id).await {
            Ok(v) => DirectoryOpResult::SignedReplicatedRecords(v),
            Err(e) => op_err(&e),
        },
        // v59.0.0 (sealed-transport floor) — the framed inbound door is retired.
        DirectoryOp::PutIdentityOccurrenceRevocation { revocation } => {
            let _ = revocation;
            op_err(&crate::federation::Error::EnvelopeKindRetired {
                kind: crate::federation::replication_policy::EnvelopeKind::IdentityOccurrenceRevocation,
            })
        }
        // #443 — the gate + monotonic apply run INSIDE persist's .so against
        // persist's own vtable; the consumer gets the policy outcome, and a
        // gate failure flattens to the top-level Err (record inadmissible).
        DirectoryOp::PutSignedTransportDestination { signed } => {
            match dir.put_signed_transport_destination(&signed).await {
                Ok(outcome) => DirectoryOpResult::TransportDestinationApplyOutcome(outcome),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSignedTransportDestinationsFor { occurrence_key_id } => {
            match dir
                .list_signed_transport_destinations_for(&occurrence_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::SignedTransportDestinations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ResolveEncryptionKeys { occurrence_key_id } => {
            // #329 — the WHOLE revocation-aware fold runs here, inside
            // persist's `.so`, against persist's own comparator + clock.
            match dir.resolve_encryption_keys(&occurrence_key_id).await {
                Ok(v) => DirectoryOpResult::EncryptionKeys(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListIdentityOccurrenceRevocationsFor { identity_key_id } => {
            match dir
                .list_identity_occurrence_revocations_for(&identity_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::IdentityOccurrenceRevocations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListScores {
            caller_occurrence_key_id,
            filter,
            cursor,
            limit,
        } => match dir
            .list_scores(&caller_occurrence_key_id, filter, cursor, limit)
            .await
        {
            Ok(v) => DirectoryOpResult::Scores(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::ResolveScores {
            caller_occurrence_key_id,
            filter,
            policy,
            trace,
        } => {
            // v17.4.0 — the WHOLE precedence + polarity fold runs here, inside
            // persist's `.so`, against persist's own comparator + clock.
            match dir
                .resolve_scores(&caller_occurrence_key_id, filter, policy, trace)
                .await
            {
                Ok(v) => DirectoryOpResult::ComposedVerdict(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAttestationLog {
            subject_key_id,
            cursor,
            limit,
        } => match dir
            .list_attestation_log(subject_key_id.as_deref(), cursor, limit)
            .await
        {
            Ok(v) => DirectoryOpResult::Scores(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::ListAttestationsNamingByDimension {
            subject_key_id,
            dimension,
            cursor,
            limit,
        } => match dir
            .list_attestations_naming_by_dimension(&subject_key_id, &dimension, cursor, limit)
            .await
        {
            Ok(v) => DirectoryOpResult::Scores(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::ListAttestationsSinceByPrefixes {
            since,
            family_prefixes,
            limit,
        } => match dir
            .list_attestations_since_by_prefixes(since, &family_prefixes, limit)
            .await
        {
            Ok(v) => DirectoryOpResult::ServedAttestationPage(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::ListOwnerBindingsSince { since, limit } => {
            match dir.list_owner_bindings_since(since, limit).await {
                Ok(v) => DirectoryOpResult::OwnerBindingPage(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListKeysByIdentityType { identity_type } => {
            match dir.list_keys_by_identity_type(&identity_type).await {
                Ok(v) => DirectoryOpResult::KeyRecords(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAllTransportDestinationsUnfolded {} => {
            match dir.list_all_transport_destinations_unfolded().await {
                Ok(v) => DirectoryOpResult::TransportDestinations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListTransportDestinationsByDestinationUnfolded { destination } => {
            match dir
                .list_transport_destinations_by_destination_unfolded(&destination)
                .await
            {
                Ok(v) => DirectoryOpResult::TransportDestinations(v),
                Err(e) => op_err(&e),
            }
        }
        // v61.4.0 (CIRISPersist#1244) — the blackhole and edge-detection
        // surfaces are sibling traits of `FederationDirectory`, reached
        // through the backend's own accessor so they run inside this `.so`.
        DirectoryOp::BlackholeList {} => match dir.blackhole_rules_surface() {
            None => DirectoryOpResult::Err(NO_BLACKHOLE_SURFACE.into()),
            Some(r) => match r.blackhole_list().await {
                Ok(v) => DirectoryOpResult::BlackholeRecords(v),
                Err(e) => op_err(&e),
            },
        },
        DirectoryOp::BlackholeUpsert {
            identity_hash,
            until,
            reason,
        } => match dir.blackhole_rules_surface() {
            None => DirectoryOpResult::Err(NO_BLACKHOLE_SURFACE.into()),
            Some(r) => match r
                .blackhole_upsert(&identity_hash, until, reason.as_deref())
                .await
            {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            },
        },
        DirectoryOp::BlackholeRemove { identity_hash } => match dir.blackhole_rules_surface() {
            None => DirectoryOpResult::Err(NO_BLACKHOLE_SURFACE.into()),
            Some(r) => match r.blackhole_remove(&identity_hash).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            },
        },
        DirectoryOp::BlackholeRecordHit { identity_hash } => match dir.blackhole_rules_surface() {
            None => DirectoryOpResult::Err(NO_BLACKHOLE_SURFACE.into()),
            Some(r) => match r.blackhole_record_hit(&identity_hash).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            },
        },
        DirectoryOp::BlackholePruneExpired { now } => match dir.blackhole_rules_surface() {
            None => DirectoryOpResult::Err(NO_BLACKHOLE_SURFACE.into()),
            Some(r) => match r.blackhole_prune_expired(now).await {
                Ok(n) => DirectoryOpResult::U64(n),
                Err(e) => op_err(&e),
            },
        },
        DirectoryOp::ListAttestationsReferencing {
            target_attestation_id,
        } => {
            match dir
                .list_attestations_referencing(&target_attestation_id)
                .await
            {
                Ok(v) => DirectoryOpResult::AttestationRows(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::GetAttestation { attestation_id } => {
            match dir.get_attestation(&attestation_id).await {
                Ok(v) => DirectoryOpResult::Attestation(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSettledSelfRosterProposals { identity_key_id } => {
            match dir
                .list_settled_self_roster_proposals(&identity_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::SelfRosterReceipts(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListIdentityOccurrencesFor { identity_key_id } => {
            match dir.list_identity_occurrences_for(&identity_key_id).await {
                Ok(v) => DirectoryOpResult::IdentityOccurrences(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::GetActiveHalt { family_key_id } => {
            match dir.get_active_halt(&family_key_id).await {
                Ok(v) => DirectoryOpResult::ActiveHalt(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupRoleWithdrawal { role, key_id } => {
            match dir.lookup_role_withdrawal(&role, &key_id).await {
                Ok(v) => DirectoryOpResult::RoleWithdrawal(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupFamily { family_key_id } => {
            match dir.lookup_family(&family_key_id).await {
                Ok(v) => DirectoryOpResult::Family(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupCommunity { community_key_id } => {
            match dir.lookup_community(&community_key_id).await {
                Ok(v) => DirectoryOpResult::Community(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListFamiliesForMember {
            member_identity_key_id,
        } => match dir.list_families_for_member(&member_identity_key_id).await {
            Ok(v) => DirectoryOpResult::Families(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::FamilyRosterSigners { family_key_id } => {
            match dir.family_roster_signers(&family_key_id).await {
                Ok(v) => DirectoryOpResult::RosterSigners(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::CommunityRosterSigners { community_key_id } => {
            match dir.community_roster_signers(&community_key_id).await {
                Ok(v) => DirectoryOpResult::RosterSigners(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListFamilyMembershipRevocationsFor { family_key_id } => {
            match dir
                .list_family_membership_revocations_for(&family_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::FamilyMembershipRevocations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListFamilyMembershipWideningsFor { family_key_id } => {
            match dir
                .list_family_membership_widenings_for(&family_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::FamilyMembershipWidenings(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::AddCommunityMember {
            community_key_id,
            member,
            spec,
        } => {
            match dir
                .add_community_member(&community_key_id, member, &spec)
                .await
            {
                Ok(v) => DirectoryOpResult::Bool(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::AddFamilyMember {
            family_key_id,
            member,
            spec,
        } => match dir.add_family_member(&family_key_id, member, &spec).await {
            Ok(v) => DirectoryOpResult::Bool(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::AttestationInsertLocal { input } => {
            match dir.attestation_insert_local(input).await {
                Ok(v) => DirectoryOpResult::AttestationId(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::AttestationTypeCensus {} => match dir.attestation_type_census().await {
            Ok(v) => DirectoryOpResult::AttestationTypeCounts(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::AttestationUpsertLocal { input } => {
            match dir.attestation_upsert_local(input).await {
                Ok(v) => DirectoryOpResult::AttestationId(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::AttestationsBindingContent { content_sha256 } => {
            match dir.attestations_binding_content(&content_sha256).await {
                Ok(v) => DirectoryOpResult::AttestationRows(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::AttestationsBindingContentWithPlacements { content_sha256 } => {
            match dir
                .attestations_binding_content_with_placements(&content_sha256)
                .await
            {
                Ok(v) => DirectoryOpResult::AttestationRows(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ClearActiveHalt {
            family_key_id,
            active_halt_id,
        } => match dir.clear_active_halt(&family_key_id, &active_halt_id).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::CommunitiesContaining { cell_id } => {
            match dir.communities_containing(&cell_id).await {
                Ok(v) => DirectoryOpResult::Communities(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::DagManifestsOfChunk { chunk_sha256 } => {
            match dir.dag_manifests_of_chunk(&chunk_sha256).await {
                Ok(v) => DirectoryOpResult::ChunkManifests(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::EnterMesh {
            attestation_id,
            ci,
            custody,
        } => match dir.enter_mesh(&attestation_id, &ci, &custody).await {
            Ok(v) => DirectoryOpResult::MeshCrossing(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::GetAccordProposal { proposal_digest } => {
            match dir.get_accord_proposal(&proposal_digest).await {
                Ok(v) => DirectoryOpResult::AccordProposal(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAccordParticipations { proposal_digest } => {
            match dir.list_accord_participations(&proposal_digest).await {
                Ok(v) => DirectoryOpResult::AccordParticipations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAttestationsByDimensionCiting {
            attesting_key_id,
            dimension,
            evidence_ref,
        } => {
            match dir
                .list_attestations_by_dimension_citing(&attesting_key_id, &dimension, &evidence_ref)
                .await
            {
                Ok(v) => DirectoryOpResult::AttestationRows(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListCommunitiesForMember {
            member_identity_key_id,
        } => {
            match dir
                .list_communities_for_member(&member_identity_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::Communities(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListGroupVersions {
            cohort,
            group_key_id,
        } => match dir.list_group_versions(cohort, &group_key_id).await {
            Ok(v) => DirectoryOpResult::GroupVersions(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::ListLocationProofsFor { subject_key_id } => {
            match dir.list_location_proofs_for(&subject_key_id).await {
                Ok(v) => DirectoryOpResult::LocationProofs(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupKeysForIdentity { identity_ref } => {
            match dir.lookup_keys_for_identity(&identity_ref).await {
                Ok(v) => DirectoryOpResult::KeyRecords(v),
                Err(e) => op_err(&e),
            }
        }
        // v62.0.0 (JSON-cut slice F; CC rc20) — the accord proposal,
        // participation and decision records are retired (a roster change is
        // a later genesis bundle): their trait doors are deleted and these
        // append-only ops stay as refusing arms that read nothing.
        DirectoryOp::PutAccordDecision { decision } => {
            let _ = decision;
            op_err(&crate::federation::Error::Unsupported {
                method: "put_accord_decision",
            })
        }
        DirectoryOp::PutAccordParticipation {
            participation,
            standing_roster,
        } => {
            let _ = (participation, standing_roster);
            op_err(&crate::federation::Error::Unsupported {
                method: "put_accord_participation",
            })
        }
        DirectoryOp::PutAccordProposal {
            proposal,
            authority_signature,
        } => {
            let _ = (proposal, authority_signature);
            op_err(&crate::federation::Error::Unsupported {
                method: "put_accord_proposal",
            })
        }
        DirectoryOp::PutCommunityMembershipRevocation { revocation } => {
            match dir.put_community_membership_revocation(revocation).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PutCommunityMembershipWidening { widening } => {
            match dir.put_community_membership_widening(widening).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PutFamilyMembershipRevocation { revocation } => {
            match dir.put_family_membership_revocation(revocation).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PutFamilyMembershipWidening { widening } => {
            match dir.put_family_membership_widening(widening).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::SetActiveHalt {
            family_key_id,
            active_halt_id,
            latch_json,
        } => match dir
            .set_active_halt(&family_key_id, &active_halt_id, latch_json.as_deref())
            .await
        {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::SetConsentRole {
            key_id,
            consent_role,
        } => match dir.set_consent_role(&key_id, consent_role.as_deref()).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::SupersedeGroupRow {
            cohort,
            new_snapshot,
            authorization,
        } => {
            match dir
                .supersede_group_row(cohort, new_snapshot, authorization)
                .await
            {
                Ok(v) => DirectoryOpResult::GroupRowVersion(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::WithdrawLocationProof { proof } => {
            match dir.withdraw_location_proof(proof).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListLiveConsentGrantsBy { node_key_id } => {
            match dir.list_live_consent_grants_by(&node_key_id).await {
                Ok(v) => DirectoryOpResult::AttestationRows(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSettledEdition2RosterProposals { identity_key_id } => {
            match dir
                .list_settled_edition2_roster_proposals(&identity_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::SelfRosterReceipts(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::Edition2RosterProposal { row_id_hex } => {
            match dir.edition2_roster_proposal(&row_id_hex).await {
                Ok(r) => DirectoryOpResult::SelfRosterReceipts(r.into_iter().collect()),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::HeldRowsFor {
            key,
            role,
            after,
            limit,
        } => {
            let after = after.map(crate::federation::edition2::names::RowId);
            match Box::pin(dir.held_rows_for(&key, role.as_deref(), after.as_ref(), limit)).await {
                Ok(v) => DirectoryOpResult::HeldRows(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::VoiceStatus { row_id } => {
            let row_id = crate::federation::edition2::names::RowId(row_id);
            match Box::pin(dir.voice_status(&row_id)).await {
                Ok(v) => DirectoryOpResult::VoiceOutcome(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::SubmitVoice { statement } => {
            match Box::pin(dir.submit_voice(&statement)).await {
                Ok(v) => DirectoryOpResult::VoiceOutcome(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::AdmissionUnitRows { sub, at_ms, owner } => {
            let Some(at) = i64::try_from(at_ms)
                .ok()
                .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
            else {
                return op_err(&crate::federation::Error::InvalidArgument(format!(
                    "admission_unit_rows: at_ms {at_ms} is out of range"
                )));
            };
            match Box::pin(dir.admission_unit_rows(&sub, at, owner.as_deref())).await {
                Ok(v) => DirectoryOpResult::AdmissionUnitRows(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::AdmissionUnitRunnable {
            row_id,
            at_ms,
            owner,
        } => {
            let Some(at) = i64::try_from(at_ms)
                .ok()
                .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
            else {
                return op_err(&crate::federation::Error::InvalidArgument(format!(
                    "admission_unit_runnable: at_ms {at_ms} is out of range"
                )));
            };
            let row_id = crate::federation::edition2::names::RowId(row_id);
            match Box::pin(
                crate::federation::edition2::admission_unit::admission_unit_runnable(
                    dir,
                    &row_id,
                    at,
                    owner.as_deref(),
                ),
            )
            .await
            {
                Ok(a) => DirectoryOpResult::AdmissionUnitAnswer(AdmissionUnitAnswerWire::of(&a)),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::ListCommunityMembershipRevocationsFor { community_key_id } => {
            match dir
                .list_community_membership_revocations_for(&community_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::CommunityMembershipRevocations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListCommunityMembershipWideningsFor { community_key_id } => {
            match dir
                .list_community_membership_widenings_for(&community_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::CommunityMembershipWidenings(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListLineageHeadCosignsFor { lineage_key_id } => {
            match dir.list_lineage_head_cosigns_for(&lineage_key_id).await {
                Ok(v) => DirectoryOpResult::LineageHeadCosigns(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupSignedCommunity { community_key_id } => {
            match dir.lookup_signed_community(&community_key_id).await {
                Ok(v) => DirectoryOpResult::SignedCommunity(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupCanonicalWithdrawal { key_id } => {
            match dir.lookup_canonical_withdrawal(&key_id).await {
                Ok(v) => DirectoryOpResult::CanonicalWithdrawal(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListCanonicalWithdrawals {} => match dir.list_canonical_withdrawals().await {
            Ok(v) => DirectoryOpResult::CanonicalWithdrawals(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::VoteWindowFirstHeld { action_id } => {
            match dir.vote_window_first_held(&action_id).await {
                Ok(v) => DirectoryOpResult::OptionalInstant(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListCosignAliases { quorum_key } => {
            match dir.list_cosign_aliases(&quorum_key).await {
                Ok(v) => DirectoryOpResult::CosignAliases(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::CosignAlias { attestation_id } => {
            match dir.cosign_alias(&attestation_id).await {
                Ok(v) => DirectoryOpResult::CosignAlias(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::GetAccordDecision { proposal_digest } => {
            match dir.get_accord_decision(&proposal_digest).await {
                Ok(v) => DirectoryOpResult::AccordDecision(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAccordProposalsByAnchor {
            action,
            prior_family_digest,
        } => {
            match dir
                .list_accord_proposals_by_anchor(&action, &prior_family_digest)
                .await
            {
                Ok(v) => DirectoryOpResult::AccordProposals(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PurgeTombstoned { plane, record_ref } => {
            match dir.purge_tombstoned(&plane, &record_ref).await {
                Ok(v) => DirectoryOpResult::OptionalString(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PurgeTombstoneNotices { plane, record_ref } => {
            match dir.purge_tombstone_notices(&plane, &record_ref).await {
                Ok(v) => DirectoryOpResult::WireHashes(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListTargetedByDimensionPrefix {
            cohort_scopes,
            cohort_target,
            dimension_prefix,
        } => {
            let cohort_scopes_refs: Vec<&str> = cohort_scopes.iter().map(String::as_str).collect();
            match dir
                .list_targeted_by_dimension_prefix(
                    &cohort_scopes_refs,
                    &cohort_target,
                    &dimension_prefix,
                )
                .await
            {
                Ok(v) => DirectoryOpResult::AttestationRows(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::KeyGrantHeldOwner { axis } => match dir.key_grant_held_owner(&axis).await {
            Ok(v) => DirectoryOpResult::OptionalString(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::NodeKeyId {} => DirectoryOpResult::OptionalString(dir.node_key_id()),
        DirectoryOp::WithdrawsDelegationDepth {} => {
            DirectoryOpResult::U64(dir.withdraws_delegation_depth() as u64)
        }
        DirectoryOp::HardwareAttestationPolicy {} => DirectoryOpResult::HardwareAttestationPolicy(
            dir.hardware_attestation_policy().as_ref().clone(),
        ),
        DirectoryOp::PutEdgeDetectionEvent { event } => match dir.edge_detection_surface() {
            None => DirectoryOpResult::Err(NO_EDGE_DETECTION_SURFACE.into()),
            Some(s) => match s.put_edge_detection_event(event).await {
                Ok(()) => DirectoryOpResult::Unit,
                // A `crate::derived::Error`: no federation kind to carry.
                Err(e) => DirectoryOpResult::Err(e.to_string()),
            },
        },
        DirectoryOp::RecordAnnouncedPeer {
            key_id,
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64,
            claimed_identity_type,
            last_seen,
        } => match dir
            .record_announced_peer(
                &key_id,
                &pubkey_ed25519_base64,
                pubkey_ml_dsa_65_base64.as_deref(),
                claimed_identity_type.as_deref(),
                last_seen,
            )
            .await
        {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::ListAnnouncedPeers => match dir.list_announced_peers().await {
            Ok(v) => DirectoryOpResult::AnnouncedPeers(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::TrustRootValid {
            user_key_id,
            root_key_id,
        } => match crate::federation::trust_root::trust_root_valid(
            dir,
            &user_key_id,
            &root_key_id,
            crate::host::clock::now(),
        )
        .await
        {
            Ok(v) => DirectoryOpResult::TrustRootVerdict(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::CapabilityRootsToTrustedRoot {
            user_key_id,
            subject_key_id,
            scope,
        } => match crate::federation::trust_root::capability_roots_to_trusted_root(
            dir,
            &user_key_id,
            &subject_key_id,
            &scope,
            crate::host::clock::now(),
        )
        .await
        {
            Ok(g) => DirectoryOpResult::TrustedGrant(g),
            Err(e) => op_err(&e),
        },
        // v24.1.0 (CIRISPersist#561) — the transport-hop gate. Note it has no
        // `Err` arm to route: `resolve_transit_eligibility` is fail-CLOSED and
        // folds every read failure into `eligible: false` itself, so a capsule
        // caller can never receive an error it might be tempted to treat as
        // "unknown, proceed".
        DirectoryOp::ResolveTransitEligibility {
            user_key_id,
            peer_key_id,
        } => match crate::federation::trust_root::resolve_transit_eligibility(
            dir,
            &user_key_id,
            &peer_key_id,
        )
        .await
        {
            Ok(v) => DirectoryOpResult::TransitEligibility(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::RevocationsFor { revoked_key_id } => {
            match dir.revocations_for(&revoked_key_id).await {
                Ok(v) => DirectoryOpResult::Revocations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSignedAccordQuorumEvidenceSince { since, limit } => {
            match dir
                .list_signed_accord_quorum_evidence_since(since, limit)
                .await
            {
                Ok(v) => DirectoryOpResult::AccordQuorumEvidence(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ApplyReplicatedAccordEvidence { evidence } => {
            // The free function, not the trait method: `dir` here is the REAL
            // backend inside persist's `.so`, so the whole re-tally + local
            // projection runs on this side of the ABI.
            match crate::federation::accord_carriage::admit_replicated_accord_evidence(
                dir, &evidence,
            )
            .await
            {
                Ok(v) => DirectoryOpResult::AccordEvidenceAdmitted(v),
                // The typed refusals cross as themselves; everything else
                // flattens. See `AccordEvidenceRefused` /
                // `AccordEvidenceCarrierRefused`.
                Err(Error::AccordEvidenceUnverified {
                    proposal_digest,
                    reason,
                }) => DirectoryOpResult::AccordEvidenceRefused {
                    proposal_digest,
                    reason,
                },
                Err(Error::AccordEvidenceCarrierMalformed {
                    proposal_digest,
                    participations,
                    roster_seats,
                    reason,
                }) => DirectoryOpResult::AccordEvidenceCarrierRefused {
                    proposal_digest,
                    participations,
                    roster_seats,
                    reason,
                },
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PutLocationProof { proof } => match dir.put_location_proof(proof).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::PutIdentityOccurrence { occurrence } => {
            match dir.put_identity_occurrence(occurrence).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::PutFamily { family } => match dir.put_family(family).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::PutCommunity { community } => match dir.put_community(community).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::PutAttestation { attestation } => match dir.put_attestation(attestation).await
        {
            Ok(outcome) => DirectoryOpResult::AttestationOutcome(outcome),
            Err(e) => op_err(&e),
        },
        DirectoryOp::PutAttestationAuthored { attestation } => {
            match dir.put_attestation_authored(attestation).await {
                Ok(outcome) => DirectoryOpResult::AttestationOutcome(outcome),
                Err(e) => op_err(&e),
            }
        }
        // v50.0.0 (CIRISPersist#917) — the pre-v50 op keeps its contract: the
        // stored-write door under the Sync origin, answering
        // `AttestationOutcome`, for consumers built before the typed door. A
        // v50 proxy sends `ApplyReplicatedAttestationSynced` instead.
        DirectoryOp::PutAttestationSynced {
            attestation,
            authenticated_peer_key_id,
        } => match dir
            .put_attestation_with_origin(
                attestation,
                crate::federation::replication::admission::WriteOrigin::Sync {
                    peer_key_id: authenticated_peer_key_id,
                },
            )
            .await
        {
            Ok(outcome) => DirectoryOpResult::AttestationOutcome(outcome),
            Err(e) => op_err(&e),
        },
        DirectoryOp::PeerMetadataFor { key_id } => match dir.peer_metadata_for(&key_id).await {
            Ok(v) => DirectoryOpResult::PeerMetadata(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::ListHeldFountainContent { publisher_key_id } => {
            match dir.list_held_fountain_content(&publisher_key_id).await {
                Ok(v) => DirectoryOpResult::FountainHeld(v),
                Err(e) => op_err(&e),
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
            Err(e) => op_err(&e),
        },
        DirectoryOp::EvictFountainContentHardDelete {
            content_id,
            corpus_kind,
        } => match dir
            .evict_fountain_content_hard_delete(&content_id, &corpus_kind)
            .await
        {
            Ok(n) => DirectoryOpResult::U64(n),
            Err(e) => op_err(&e),
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
            Err(e) => op_err(&e),
        },
        // v62.0.0 (F0-cp5; RULINGS "composite signatures only") — retired:
        // the bound-hybrid verify reads nothing and is refused by name;
        // `VerifyCompositeViaDirectory` is its edition-2 successor.
        DirectoryOp::VerifyHybridViaDirectory {
            canonical_bytes,
            signing_key_id,
            ed25519_sig_b64,
            ml_dsa_65_sig_b64,
            policy,
            row_age,
        } => {
            let _ = (
                canonical_bytes,
                signing_key_id,
                ed25519_sig_b64,
                ml_dsa_65_sig_b64,
                policy,
                row_age,
            );
            op_err(&crate::federation::Error::Unsupported {
                method: "verify_hybrid_via_directory",
            })
        }
        DirectoryOp::VerifyCompositeViaDirectory {
            message,
            identity_ref,
            composite_sig,
            at_ms,
        } => {
            use crate::federation::edition2::composite_verify::{
                verify_composite_via_directory, CompositeVerifyError,
            };
            // The verify runs entirely here, inside persist's `.so`, against
            // persist's own vtable.
            match verify_composite_via_directory(
                dir,
                &message,
                &identity_ref,
                &composite_sig,
                at_ms,
            )
            .await
            {
                Ok(signer) => DirectoryOpResult::CompositeVerify(Ok(signer.identity_ref)),
                Err(CompositeVerifyError::Directory(e)) => op_err(&e),
                Err(e) => DirectoryOpResult::CompositeVerify(Err(CompositeVerifyRefusal {
                    token: e.token().to_owned(),
                    retryable: e.is_retryable(),
                    detail: e.to_string(),
                })),
            }
        }
        DirectoryOp::BuildDelegationGraph {
            from_key,
            max_depth,
        } => {
            match crate::federation::topology::build_delegation_graph(
                dir,
                &from_key,
                // The op always names a depth: an explicit caller choice
                // (CC 4.1.1 opt-in), clamped at the ceiling.
                Some(max_depth as usize),
            )
            .await
            {
                Ok(g) => DirectoryOpResult::DelegationGraph(g),
                Err(e) => op_err(&e),
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
            Err(e) => op_err(&e),
        },
        DirectoryOp::RemovePeerRecord {
            key_id,
            hard,
            reason,
            acting_under_delegation_id,
        } => {
            match dir
                .remove_peer_record(
                    &key_id,
                    hard,
                    &reason,
                    acting_under_delegation_id.as_deref(),
                )
                .await
            {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::UpdatePeerAlias { key_id, alias } => {
            match dir.update_peer_alias(&key_id, alias).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::UpdatePeerTrust { key_id, trust } => {
            match dir.update_peer_trust(&key_id, trust).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::UpdatePeerNotes { key_id, notes } => {
            match dir.update_peer_notes(&key_id, notes).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::UpdatePeerPolicy { key_id, policy } => {
            match dir.update_peer_policy(&key_id, policy).await {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListConsentPeers { node_key_id } => {
            match dir.list_consent_peers(&node_key_id).await {
                Ok(v) => DirectoryOpResult::ConsentPeers(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSignedLocationProofsSince { since, limit } => {
            match dir.list_signed_location_proofs_since(since, limit).await {
                Ok(v) => DirectoryOpResult::SignedLocationProofs(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListSignedTransportDestinationsSince { since, limit } => {
            match dir
                .list_signed_transport_destinations_since(since, limit)
                .await
            {
                Ok(v) => DirectoryOpResult::SignedTransportDestinationsSince(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListAttestationsSince { since, limit } => {
            match dir.list_attestations_since(since, limit).await {
                Ok(v) => DirectoryOpResult::Attestations(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::LookupSignedRecordByContentHash { kind, content_hash } => {
            match dir
                .lookup_signed_record_by_content_hash(&kind, &content_hash)
                .await
            {
                Ok(v) => DirectoryOpResult::OptionalBytes(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::RebuildSignedWireIndex => match dir.rebuild_signed_wire_index().await {
            Ok(v) => DirectoryOpResult::U64(v),
            Err(e) => op_err(&e),
        },
        // CIRISPersist#785 — the wire-hash reads and the known-but-not-held
        // set. The two `list_*` arms return DIFFERENT result variants for the
        // same underlying shape (`Vec<String>` vs `Vec<KnownWireHash>`), which
        // is deliberate: these sets must never be unioned, and a shared wire
        // shape would let a swapped arm here type-check.
        DirectoryOp::ListWireHashesSince {
            kind,
            after_content_hash,
            limit,
        } => match dir
            .list_wire_hashes_since(&kind, after_content_hash.as_deref(), limit)
            .await
        {
            Ok(v) => DirectoryOpResult::WireHashes(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::InsertKnownWireHash {
            kind,
            content_hash,
            advertised_by,
            now,
        } => match dir
            .insert_known_wire_hash(&kind, &content_hash, advertised_by.as_deref(), now)
            .await
        {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => op_err(&e),
        },
        DirectoryOp::KnownWireHashContains { kind, content_hash } => {
            match dir.known_wire_hash_contains(&kind, &content_hash).await {
                Ok(v) => DirectoryOpResult::Bool(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListKnownWireHashesSince {
            kind,
            after_content_hash,
            limit,
        } => match dir
            .list_known_wire_hashes_since(&kind, after_content_hash.as_deref(), limit)
            .await
        {
            Ok(v) => DirectoryOpResult::KnownWireHashes(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::EvictKnownWireHashes { cutoff, bound } => {
            match dir.evict_known_wire_hashes(cutoff, bound).await {
                Ok(v) => DirectoryOpResult::KnownHashEviction(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ApplyReplicatedAttestation { attestation } => {
            match dir.apply_replicated_attestation(attestation).await {
                Ok(o) => DirectoryOpResult::ReplicatedAttestationOutcome(o),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ApplyReplicatedAttestationSynced {
            attestation,
            authenticated_peer_key_id,
        } => match dir
            .put_attestation_synced(attestation, &authenticated_peer_key_id)
            .await
        {
            Ok(o) => DirectoryOpResult::ReplicatedAttestationOutcome(o),
            Err(e) => op_err(&e),
        },
        // v62.0.0 (F0-cp9) — RETIRED: the lineage-head cosign door was the
        // earlier form (a bound-hybrid witness signature) with no edition-2
        // form (CC: OPEN). The op keeps its fields (ABI 14); it refuses.
        DirectoryOp::PutLineageHeadCosign { cosign } => {
            let _ = cosign;
            op_err(&crate::federation::Error::Unsupported {
                method: "put_lineage_head_cosign",
            })
        }
        DirectoryOp::WithdrawsAdmissionDepth { attestation_id } => {
            match dir.withdraws_admission_depth(&attestation_id).await {
                Ok(d) => DirectoryOpResult::WithdrawsAdmissionDepth(
                    d.map(|d| u32::try_from(d).unwrap_or(u32::MAX)),
                ),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::RevocationsForSubject {
            revoked_key_sha256_ed25519_raw,
        } => match dir
            .revocations_for_subject(&revoked_key_sha256_ed25519_raw)
            .await
        {
            Ok(v) => DirectoryOpResult::Revocations(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::TrustDirectionHeldAmong { attestation_ids } => {
            match dir.trust_direction_held_among(&attestation_ids).await {
                Ok(v) => DirectoryOpResult::WireHashes(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListKeyPlaneWireHashesSince {
            family,
            after_content_hash,
            limit,
        } => match dir
            .list_key_plane_wire_hashes_since(&family, after_content_hash.as_deref(), limit)
            .await
        {
            Ok(v) => DirectoryOpResult::WireHashes(v),
            Err(e) => op_err(&e),
        },
        // The storage half only: the consumer's `query_attestations` wrapper
        // validates, cuts the page and records the read, so calling the
        // wrapper here would count it twice.
        DirectoryOp::ExecuteAttestationQuery { query } => {
            match dir.execute_attestation_query(&query).await {
                Ok(rows) => DirectoryOpResult::AttestationQueryRows(rows),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListComposersReferencingAny {
            target_attestation_ids,
            attested_key_id,
            attesting_key_id,
        } => match dir
            .list_composers_referencing_any(
                &target_attestation_ids,
                attested_key_id.as_deref(),
                attesting_key_id.as_deref(),
            )
            .await
        {
            Ok(v) => DirectoryOpResult::AttestationRows(v),
            Err(e) => op_err(&e),
        },
        DirectoryOp::ListIdentityOccurrenceHistoryByOccurrence { occurrence_key_id } => {
            match dir
                .list_identity_occurrence_history_by_occurrence(&occurrence_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::OccurrenceHistory(v),
                Err(e) => op_err(&e),
            }
        }
        DirectoryOp::ListIdentityOccurrencesByOccurrenceKey { occurrence_key_id } => {
            match dir
                .list_identity_occurrences_by_occurrence_key(&occurrence_key_id)
                .await
            {
                Ok(v) => DirectoryOpResult::IdentityOccurrences(v),
                Err(e) => op_err(&e),
            }
        }
        // v62.0.0 (JSON-cut slice D) — the edition-2 doors run inside
        // persist's `.so` over persist's own directory; their errors keep
        // their reading (`typed_error_string`).
        DirectoryOp::PutEdition2Statement {
            statement,
            offered_row_id,
        } => match Box::pin(crate::federation::edition2::ingest::put_statement(
            dir,
            &statement,
            offered_row_id.as_ref(),
            crate::federation::edition2::ingest::INGEST_TIER,
        ))
        .await
        {
            Ok(o) => DirectoryOpResult::Edition2StatementOutcome(o.into()),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::ApplyReplicatedStatement {
            statement,
            offered_row_id,
        } => match Box::pin(
            crate::federation::edition2::ingest::apply_replicated_statement(
                dir,
                &statement,
                &offered_row_id,
            ),
        )
        .await
        {
            Ok(o) => DirectoryOpResult::ReplicatedStatementOutcome(o.into()),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::Edition2StatementsSince { cursor, limit } => {
            let cursor = cursor.map(crate::federation::edition2::store::StatementCursor::from);
            match dir.edition2_statements_since(cursor.as_ref(), limit).await {
                Ok(v) => DirectoryOpResult::Edition2StatementPage(
                    v.into_iter().map(Edition2ServedStatement::from).collect(),
                ),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::BundlesInForce {} => {
            match Box::pin(crate::federation::edition2::genesis::bundles_in_force(dir)).await {
                Ok(v) => DirectoryOpResult::BundlesInForce(
                    v.iter().map(Edition2BundleInForce::from).collect(),
                ),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::PutGenesisBundle { statements, anchor } => {
            let anchor = anchor.map(crate::federation::edition2::genesis::Anchor::from);
            match Box::pin(crate::federation::edition2::genesis::put_genesis_bundle(
                dir,
                &statements,
                anchor.as_ref(),
            ))
            .await
            {
                Ok(a) => DirectoryOpResult::GenesisAdmission((&a).into()),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::RebindHeldFor { seat_identity_ref } => {
            match Box::pin(
                crate::federation::edition2::transport_rebind::rebind_held_for(
                    dir,
                    &seat_identity_ref,
                ),
            )
            .await
            {
                Ok(r) => DirectoryOpResult::RebindHeld(r.as_ref().map(Edition2HeldRebind::from)),
                Err(e) => op_err_typed(&e),
            }
        }
        // v62.0.0 (PX-fix1) — the edition-2 and fold store reads, answered
        // by the host's own store (the defaults refuse `Unsupported`).
        DirectoryOp::Edition2StatementsAbout { family, sub } => {
            match dir.edition2_statements_about(&family, &sub).await {
                Ok(v) => DirectoryOpResult::Edition2Statements(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::Edition2Voices { row_id } => {
            let row_id = crate::federation::edition2::names::RowId(row_id);
            match dir.edition2_voices(&row_id).await {
                Ok(v) => DirectoryOpResult::Edition2Statements(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::Edition2RowsNaming { named, role } => {
            let named = crate::federation::edition2::names::RowId(named);
            match dir.edition2_rows_naming(&named, &role).await {
                Ok(v) => DirectoryOpResult::Edition2RowIds(v.into_iter().map(|r| r.0).collect()),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::Edition2Objects { typ } => match dir.edition2_objects(&typ).await {
            Ok(v) => DirectoryOpResult::Edition2Statements(v),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::Edition2Statement { statement_id } => {
            match dir.edition2_statement(&statement_id).await {
                Ok(v) => DirectoryOpResult::OptionalBytes(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::Edition2StatementIdsSince { after, limit } => {
            match dir
                .edition2_statement_ids_since(after.as_ref(), limit)
                .await
            {
                Ok(v) => DirectoryOpResult::Edition2StatementIds(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::FoldHeld { row_id } => {
            let row_id = crate::federation::edition2::names::RowId(row_id);
            match dir.fold_held(&row_id).await {
                Ok(h) => {
                    DirectoryOpResult::FoldHeldReason(h.as_ref().map(Edition2HeldReason::from))
                }
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::FoldHeldPage { after, limit } => {
            let after = after.map(crate::federation::edition2::names::RowId);
            match dir.fold_held_page(after.as_ref(), limit).await {
                Ok(v) => DirectoryOpResult::FoldHeldReasons(
                    v.iter().map(Edition2HeldReason::from).collect(),
                ),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::FoldDependents { read_keys } => match dir.fold_dependents(&read_keys).await {
            Ok(v) => DirectoryOpResult::Edition2RowIds(v.into_iter().map(|r| r.0).collect()),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::FoldState { row_id } => {
            let row_id = crate::federation::edition2::names::RowId(row_id);
            match dir.fold_state(&row_id).await {
                Ok(f) => DirectoryOpResult::FoldStateOf(f.as_ref().map(Edition2FoldState::from)),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::FoldSlotRows { slot } => match dir.fold_slot_rows(&slot).await {
            Ok(v) => DirectoryOpResult::Edition2RowIds(v.into_iter().map(|r| r.0).collect()),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::FoldSlotHeld { slot } => match dir.fold_slot_held(&slot).await {
            Ok(b) => DirectoryOpResult::Bool(b),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::FoldAnyRefolding {} => match dir.fold_any_refolding().await {
            Ok(b) => DirectoryOpResult::Bool(b),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::PeerRooting {
            reader_node,
            peer_identity_ref,
            claimed_key,
            at_ms,
        } => {
            let parsed =
                match claimed_key.composite() {
                    Ok(p) => p,
                    Err(_) => return op_err_typed(&crate::federation::Error::InvalidArgument(
                        "peer_rooting: claimed_key's composite bytes are no composite public key"
                            .into(),
                    )),
                };
            let Some(claim) = claimed_key.as_claim(parsed.as_ref()) else {
                return op_err_typed(&crate::federation::Error::InvalidArgument(
                    "peer_rooting: no claim".into(),
                ));
            };
            match Box::pin(crate::federation::edition2::peer_rooting::peer_rooting(
                dir,
                &reader_node,
                &peer_identity_ref,
                claim,
                at_ms,
            ))
            .await
            {
                Ok(v) => DirectoryOpResult::PeerRooting(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::PutTouchClaimLocal {
            target_key_id,
            target_kind,
            fresh_as_of,
            cohort_scope,
        } => match dir
            .put_touch_claim_local(&target_key_id, &target_kind, fresh_as_of, &cohort_scope)
            .await
        {
            Ok(o) => DirectoryOpResult::TouchApplied(o),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::FreshnessFloor {
            target_key_id,
            target_kind,
        } => match dir.freshness_floor(&target_key_id, &target_kind).await {
            Ok(f) => DirectoryOpResult::FreshnessFloorOf(f),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::ApplyReplicatedStatementAtFeed {
            statement,
            offered_row_id,
            feed,
        } => match Box::pin(
            crate::federation::edition2::ingest::apply_replicated_statement_at_feed(
                dir,
                &statement,
                &offered_row_id,
                &feed,
            ),
        )
        .await
        {
            Ok(o) => DirectoryOpResult::ReplicatedStatementOutcome(o.into()),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::AccordRescanNeeded {} => {
            match Box::pin(crate::federation::edition2::accord_rescan::rescan_needed(
                dir,
            ))
            .await
            {
                Ok(v) => DirectoryOpResult::AccordRescans(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::AckAccordRescan {
            plane,
            peer,
            from_position,
        } => match Box::pin(crate::federation::edition2::accord_rescan::ack_rescan(
            dir,
            &plane,
            &peer,
            &from_position,
        ))
        .await
        {
            Ok(b) => DirectoryOpResult::Bool(b),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::RecordDialHints { hints } => {
            match Box::pin(crate::federation::edition2::contact::record_dial_hints(
                dir, hints,
            ))
            .await
            {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::DialHintsFor { node } => {
            match Box::pin(crate::federation::edition2::contact::dial_hints_for(
                dir, &node,
            ))
            .await
            {
                Ok(v) => DirectoryOpResult::DialHints(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::ListDialHints {} => {
            match Box::pin(crate::federation::edition2::contact::list_dial_hints(dir)).await {
                Ok(v) => DirectoryOpResult::DialHintsList(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::RemoveDialHints { node } => {
            match Box::pin(crate::federation::edition2::contact::remove_dial_hints(
                dir, &node,
            ))
            .await
            {
                Ok(b) => DirectoryOpResult::Bool(b),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::AdmitPreSealAnswer {
            dialled,
            key_record,
            route,
        } => match Box::pin(crate::federation::edition2::contact::admit_pre_seal_answer(
            dir,
            &dialled,
            &key_record,
            &route,
        ))
        .await
        {
            Ok(a) => DirectoryOpResult::PreSealAdmission(a.into()),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::AdmitContactOwnerRows {
            node,
            identity,
            owner_key_record,
            binding,
        } => match Box::pin(
            crate::federation::edition2::contact::admit_contact_owner_rows(
                dir,
                &node,
                &identity,
                &owner_key_record,
                &binding,
            ),
        )
        .await
        {
            Ok(o) => DirectoryOpResult::ContactOwner(o.into()),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::ServeStanding {} => {
            match Box::pin(crate::federation::edition2::serve::serve_standing(dir)).await {
                Ok(v) => DirectoryOpResult::ServeStanding(v),
                Err(e) => op_err_typed(&e),
            }
        }
        DirectoryOp::ListGroupTips {
            cohort,
            group_key_id,
        } => match dir.list_group_tips(cohort, &group_key_id).await {
            Ok(v) => DirectoryOpResult::GroupTips(v),
            Err(e) => op_err_typed(&e),
        },
        DirectoryOp::MayPublishFederationRendezvous { key_id } => {
            match Box::pin(crate::federation::age::may_publish_federation_rendezvous(
                dir, &key_id,
            ))
            .await
            {
                Ok(()) => DirectoryOpResult::Unit,
                Err(e) => op_err_typed(&e),
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

    // v61.1.0 (CIRISPersist#1235) — the op is polled on persist's worker, not
    // on the task that built it: carry the caller scope in force HERE (the
    // proxy's `run_op` calls this synchronously, inside the caller's poll) so
    // the op's door reads are credited to it.
    let fut: BoxedFut = Box::pin(crate::observe::carry_caller(async move {
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
    }));

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

/// v62.0.0 (CC 2.7) — the proxy's reading of a host answer: a
/// [`DirectoryOpResult::TypedErr`] is the host's error, rebuilt with its kind
/// and its wait ([`CapsuleError::into_error`]); every other answer is the
/// op's result for the calling method to match. Every proxy method reaches
/// the host through [`OpsDirectory::run_op`] / `run_op_blocking`, so this is
/// the one place the typed failure is read.
fn relay_typed_err(result: DirectoryOpResult) -> Result<DirectoryOpResult, Error> {
    match result {
        DirectoryOpResult::TypedErr(t) => Err(t.into_error()),
        other => Ok(other),
    }
}

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
///
/// v61.4.0 (CIRISPersist#1244) — public, and also a
/// [`crate::federation::BlackholeRules`] and a
/// [`crate::derived::DerivedSchema`] (its edge-detection admission routed,
/// the rest `NotImplemented`), so a consumer holding an
/// `Arc<OpsDirectory>` from [`build_ops_directory_proxy`] reaches all three
/// surfaces without the raw `outbound_queue_capsule`. Being a concrete
/// `Sized` type, it also satisfies a consumer's blanket impls bound on
/// `F: FederationDirectory`. Every call runs inside persist's `.so`: no
/// code compiled into the consumer locks persist's primitives.
pub struct OpsDirectory {
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

        let result = serde_json::from_slice::<DirectoryOpResult>(&result_bytes).map_err(|e| {
            Error::Backend(format!(
                "directory ops proxy: result deserialize failure: {e}"
            ))
        })?;
        relay_typed_err(result)
    }
}

impl OpsDirectory {
    /// The std-channel twin of [`Self::result_trampoline`], for
    /// [`Self::run_op_blocking`].
    ///
    /// # Safety
    /// Invoked only as the `result_cb` handed to `build_op` in
    /// [`OpsDirectory::run_op_blocking`]; MUST NOT be called directly.
    unsafe extern "C" fn blocking_trampoline(ctx: *mut c_void, ptr: *const u8, len: usize) {
        // SAFETY: `ctx` is the `Box::into_raw`'d `mpsc::Sender<Vec<u8>>` made
        // in `run_op_blocking` for THIS op; `build_op` fires the callback
        // exactly once, so the Box is reclaimed exactly once.
        let tx = unsafe { Box::from_raw(ctx as *mut std::sync::mpsc::Sender<Vec<u8>>) };
        // SAFETY: `(ptr, len)` name readable bytes valid for this call only;
        // copied out before returning.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        let _ = tx.send(bytes);
    }

    /// v61.4.0 (CIRISPersist#1244 round 2) — [`Self::run_op`] for the trait's
    /// SYNC methods. The op runs on persist's runtime (the executor capsule);
    /// this thread waits on a std channel, up to [`BLOCKING_OP_TIMEOUT`]. It
    /// touches no tokio primitive of the caller's binary, so it is safe from
    /// any thread, but it parks the calling thread for one host round trip.
    fn run_op_blocking(&self, op: &DirectoryOp) -> Result<DirectoryOpResult, Error> {
        let op_bytes = serde_json::to_vec(op).map_err(|e| {
            Error::Backend(format!("directory ops proxy: op serialize failure: {e}"))
        })?;
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let ctx: *mut c_void = Box::into_raw(Box::new(tx)) as *mut c_void;
        // SAFETY: as in `run_op` — a matched data/vtable pair (ABI asserted at
        // build), readable op bytes for the call, and a Send-able single-fire
        // ctx/callback pair.
        let task: *mut TaskOpaque = unsafe {
            (self.directory.vtable.build_op)(
                self.directory.data,
                op_bytes.as_ptr(),
                op_bytes.len(),
                Self::blocking_trampoline,
                ctx,
            )
        };
        // SAFETY: `task` is this directory's `build_op` output, spawned once
        // on a matched, live executor capsule.
        unsafe { (self.executor.vtable.spawn)(self.executor.data, task) };
        let bytes = rx.recv_timeout(BLOCKING_OP_TIMEOUT).map_err(|e| {
            Error::Backend(format!(
                "directory ops proxy: sync op did not complete: {e}"
            ))
        })?;
        let result = serde_json::from_slice::<DirectoryOpResult>(&bytes).map_err(|e| {
            Error::Backend(format!(
                "directory ops proxy: result deserialize failure: {e}"
            ))
        })?;
        relay_typed_err(result)
    }

    /// Run a blackhole op and expect `Unit`.
    async fn blackhole_unit_op(&self, op: DirectoryOp) -> Result<(), Error> {
        match self.run_op(&op).await? {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
}

/// v61.4.0 (CIRISPersist#1244) — the blackhole surface over the capsule. The
/// 16-byte length check runs here as well as on the far side, so a short
/// hash is still [`Error::InvalidArgument`], not a flattened backend error.
#[async_trait::async_trait]
impl crate::federation::BlackholeRules for OpsDirectory {
    async fn blackhole_list(&self) -> Result<Vec<crate::federation::BlackholeRecord>, Error> {
        match self.run_op(&DirectoryOp::BlackholeList {}).await? {
            DirectoryOpResult::BlackholeRecords(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<&str>,
    ) -> Result<(), Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        self.blackhole_unit_op(DirectoryOp::BlackholeUpsert {
            identity_hash: identity_hash.to_vec(),
            until,
            reason: reason.map(str::to_owned),
        })
        .await
    }

    async fn blackhole_remove(&self, identity_hash: &[u8]) -> Result<(), Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        self.blackhole_unit_op(DirectoryOp::BlackholeRemove {
            identity_hash: identity_hash.to_vec(),
        })
        .await
    }

    async fn blackhole_record_hit(&self, identity_hash: &[u8]) -> Result<(), Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        self.blackhole_unit_op(DirectoryOp::BlackholeRecordHit {
            identity_hash: identity_hash.to_vec(),
        })
        .await
    }

    async fn blackhole_prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, Error> {
        match self
            .run_op(&DirectoryOp::BlackholePruneExpired { now })
            .await?
        {
            DirectoryOpResult::U64(n) => Ok(n),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
}

/// v61.4.0 (CIRISPersist#1244) — the derived-schema surface over the capsule.
/// Only the edge-detection admission is routed (the one call a consumer
/// makes); every other method answers [`crate::derived::Error::NotImplemented`].
/// A far-side failure arrives as [`crate::derived::Error::Backend`] carrying
/// the far side's message (a `Conflict` keeps its text, not its variant).
impl crate::derived::DerivedSchema for OpsDirectory {
    async fn get_detection_events(
        &self,
        _filter: crate::derived::EventFilter,
    ) -> Result<Vec<crate::derived::DetectionEvent>, crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "get_detection_events: not routed through the directory capsule",
        ))
    }

    async fn put_edge_detection_event(
        &self,
        event: crate::derived::EdgeDetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        match self
            .run_op(&DirectoryOp::PutEdgeDetectionEvent { event })
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(crate::derived::Error::Backend(s)),
            _ => Err(crate::derived::Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn get_edge_detection_events(
        &self,
        _filter: crate::derived::EdgeEventFilter,
    ) -> Result<Vec<crate::derived::EdgeDetectionEvent>, crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "get_edge_detection_events: not routed through the directory capsule",
        ))
    }

    async fn put_calibration_bundle(
        &self,
        _bundle: crate::derived::CalibrationBundle,
    ) -> Result<(), crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "put_calibration_bundle: not routed through the directory capsule",
        ))
    }

    async fn get_current_calibration_bundle(
        &self,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "get_current_calibration_bundle: not routed through the directory capsule",
        ))
    }

    async fn get_calibration_bundle_by_version(
        &self,
        _version: i32,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "get_calibration_bundle_by_version: not routed through the directory capsule",
        ))
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
    let proxy: Arc<dyn FederationDirectory> = build_ops_directory_proxy(directory, executor)?;
    Ok(proxy)
}

/// v62.0.0 (PX-fix1) — TESTS: the consumer proxy over `dir` exactly as a host
/// builds it (`build_persist_directory` → [`build_ops_directory`]), driven by
/// an executor capsule on a runtime of its own. The runtime is never dropped:
/// a runtime may not be dropped inside an async test, and the proxy may
/// outlive the caller's scope.
///
/// # Panics
/// The runtime cannot be built, or the ABI check fails.
#[cfg(test)]
pub(crate) fn test_proxy(dir: Arc<dyn FederationDirectory>) -> Arc<dyn FederationDirectory> {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_stack_size(16 * 1024 * 1024)
            .enable_all()
            .build()
            .expect("PX-fix1: the proxy's runtime"),
    );
    std::mem::forget(rt.clone());
    let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(rt));
    build_ops_directory(build_persist_directory(dir), executor).expect("PX-fix1: abi ok")
}

/// v61.4.0 (CIRISPersist#1244) — [`build_ops_directory`], returning the
/// concrete [`OpsDirectory`] so one capsule serves as a
/// `FederationDirectory`, a [`crate::federation::BlackholeRules`] and a
/// [`crate::derived::DerivedSchema`] (`Arc<OpsDirectory>` coerces to each
/// trait object). Same ABI-version refusal.
///
/// # Errors
/// [`Error::Backend`] if `directory.vtable.abi_version` does not equal
/// [`DIRECTORY_ABI_VERSION`].
pub fn build_ops_directory_proxy(
    directory: Directory,
    executor: Arc<AsyncExecutor>,
) -> Result<Arc<OpsDirectory>, Error> {
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
    fn as_dyn_directory(&self) -> &dyn crate::federation::FederationDirectory {
        self
    }

    // v61.4.0 (CIRISPersist#1244) — the proxy is itself both surfaces (each
    // routed through the capsule), so a directory capsule built over a proxy
    // forwards them too.
    fn blackhole_rules_surface(&self) -> Option<&dyn crate::federation::BlackholeRules> {
        Some(self)
    }

    fn edge_detection_surface(&self) -> Option<&dyn crate::derived::EdgeDetectionSink> {
        Some(self)
    }

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
        // v61.4.0 (CIRISPersist#1227) — every role routes. The accord set
        // keeps its original op, so a host older than v61.4.0 still answers
        // the one read it always could; every other role rides
        // `ListKeysByIdentityType`.
        let op = if identity_type == crate::federation::types::identity_type::ACCORD_HOLDER {
            DirectoryOp::ListAccordHolders {}
        } else {
            DirectoryOp::ListKeysByIdentityType {
                identity_type: identity_type.to_string(),
            }
        };
        match self.run_op(&op).await? {
            DirectoryOpResult::KeyRecords(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_attestation_with_origin(
        &self,
        attestation: SignedAttestation,
        origin: crate::federation::replication::admission::WriteOrigin,
    ) -> Result<crate::federation::AttestationOutcome, Error> {
        // v41.0.0 (#804) — the origin must SURVIVE the capsule boundary. A
        // proxy that dropped it would meter the far side's local authorship as
        // a peer again, which is the whole defect, reappearing wherever the
        // directory is reached through the ABI rather than directly.
        use crate::federation::replication::admission::WriteOrigin;
        let op = match origin {
            WriteOrigin::Authored => DirectoryOp::PutAttestationAuthored { attestation },
            WriteOrigin::Sync { peer_key_id } => DirectoryOp::PutAttestationSynced {
                attestation,
                authenticated_peer_key_id: peer_key_id,
            },
            WriteOrigin::Wire => DirectoryOp::PutAttestation { attestation },
        };
        match self.run_op(&op).await? {
            DirectoryOpResult::AttestationOutcome(o) => Ok(o),
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

    /// v50.0.0 (CIRISPersist#928, final check) — the recorded admission depth
    /// of a stored `withdraws`, proxied: the proxy never guesses 16.
    async fn withdraws_admission_depth(
        &self,
        attestation_id: &str,
    ) -> Result<Option<usize>, Error> {
        match self
            .run_op(&DirectoryOp::WithdrawsAdmissionDepth {
                attestation_id: attestation_id.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::WithdrawsAdmissionDepth(d) => {
                Ok(d.map(|d| usize::try_from(d).unwrap_or(usize::MAX)))
            }
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// CIRISPersist#973 — the held unlabelled delegations, proxied: the proxy
    /// never answers "none held" on the backend's behalf.
    async fn trust_direction_held_among(
        &self,
        attestation_ids: &[String],
    ) -> Result<Vec<String>, Error> {
        match self
            .run_op(&DirectoryOp::TrustDirectionHeldAmong {
                attestation_ids: attestation_ids.to_vec(),
            })
            .await?
        {
            DirectoryOpResult::WireHashes(v) => Ok(v),
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

    async fn remove_peer_record(
        &self,
        key_id: &str,
        hard: bool,
        reason: &str,
        acting_under_delegation_id: Option<&str>,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::RemovePeerRecord {
                key_id: key_id.to_string(),
                hard,
                reason: reason.to_owned(),
                acting_under_delegation_id: acting_under_delegation_id.map(str::to_owned),
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

    async fn list_all_transport_destinations(
        &self,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        // #411 — the boot reload across the wheel boundary.
        match self
            .run_op(&DirectoryOp::ListAllTransportDestinations {})
            .await?
        {
            DirectoryOpResult::TransportDestinations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_transport_destinations_by_destination(
        &self,
        destination: &str,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        // #413 — competing-claims read across the wheel boundary.
        match self
            .run_op(&DirectoryOp::ListTransportDestinationsByDestination {
                destination: destination.to_string(),
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

    // v61.4.0 (CIRISPersist#1244 round 2) — the three sync config reads, each
    // fetched from the host on every call (the host may change them at run
    // time). A failed fetch answers the fail-CLOSED value, never the default.
    fn node_key_id(&self) -> Option<String> {
        match self.run_op_blocking(&DirectoryOp::NodeKeyId {}) {
            Ok(DirectoryOpResult::OptionalString(v)) => v,
            _ => Some(NODE_KEY_ID_UNAVAILABLE.to_owned()),
        }
    }

    fn withdraws_delegation_depth(&self) -> usize {
        match self.run_op_blocking(&DirectoryOp::WithdrawsDelegationDepth {}) {
            Ok(DirectoryOpResult::U64(d)) => {
                crate::federation::topology::effective_delegation_depth(Some(
                    usize::try_from(d).unwrap_or(0),
                ))
            }
            _ => 0,
        }
    }

    fn hardware_attestation_policy(&self) -> Arc<crate::federation::HardwareAttestationPolicy> {
        match self.run_op_blocking(&DirectoryOp::HardwareAttestationPolicy {}) {
            Ok(DirectoryOpResult::HardwareAttestationPolicy(p)) => Arc::new(p),
            _ => Arc::new(refuse_all_hardware_attestation_policy()),
        }
    }

    async fn list_settled_self_roster_proposals(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::self_roster::SelfRosterReceipt>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, the rooting view).
        match self
            .run_op(&DirectoryOp::ListSettledSelfRosterProposals {
                identity_key_id: identity_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SelfRosterReceipts(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn lookup_role_withdrawal(
        &self,
        role: &str,
        key_id: &str,
    ) -> Result<Option<crate::federation::admission::RoleWithdrawal>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::LookupRoleWithdrawal {
                role: role.to_string(),
                key_id: key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::RoleWithdrawal(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn family_roster_signers(
        &self,
        family_key_id: &str,
    ) -> Result<types::CommunityRosterSigners, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::FamilyRosterSigners {
                family_key_id: family_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::RosterSigners(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn community_roster_signers(
        &self,
        community_key_id: &str,
    ) -> Result<types::CommunityRosterSigners, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::CommunityRosterSigners {
                community_key_id: community_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::RosterSigners(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_lineage_head_cosigns_for(
        &self,
        lineage_key_id: &str,
    ) -> Result<Vec<crate::federation::lineage_witness::LineageHeadCosign>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListLineageHeadCosignsFor {
                lineage_key_id: lineage_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::LineageHeadCosigns(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn lookup_signed_community(
        &self,
        community_key_id: &str,
    ) -> Result<Option<SignedCommunity>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::LookupSignedCommunity {
                community_key_id: community_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SignedCommunity(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn lookup_canonical_withdrawal(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::admission::CanonicalWithdrawal>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::LookupCanonicalWithdrawal {
                key_id: key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::CanonicalWithdrawal(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_canonical_withdrawals(
        &self,
    ) -> Result<Vec<crate::federation::admission::CanonicalWithdrawal>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListCanonicalWithdrawals {})
            .await?
        {
            DirectoryOpResult::CanonicalWithdrawals(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn vote_window_first_held(
        &self,
        action_id: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::VoteWindowFirstHeld {
                action_id: action_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::OptionalInstant(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_cosign_aliases(&self, quorum_key: &str) -> Result<Vec<(String, String)>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListCosignAliases {
                quorum_key: quorum_key.to_string(),
            })
            .await?
        {
            DirectoryOpResult::CosignAliases(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn cosign_alias(&self, attestation_id: &str) -> Result<Option<(String, String)>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::CosignAlias {
                attestation_id: attestation_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::CosignAlias(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn purge_tombstoned(
        &self,
        plane: &str,
        record_ref: &str,
    ) -> Result<Option<String>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::PurgeTombstoned {
                plane: plane.to_string(),
                record_ref: record_ref.to_string(),
            })
            .await?
        {
            DirectoryOpResult::OptionalString(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn purge_tombstone_notices(
        &self,
        plane: &str,
        record_ref: &str,
    ) -> Result<Vec<String>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::PurgeTombstoneNotices {
                plane: plane.to_string(),
                record_ref: record_ref.to_string(),
            })
            .await?
        {
            DirectoryOpResult::WireHashes(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_targeted_by_dimension_prefix(
        &self,
        cohort_scopes: &[&str],
        cohort_target: &str,
        dimension_prefix: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListTargetedByDimensionPrefix {
                cohort_scopes: cohort_scopes.iter().map(|s| s.to_string()).collect(),
                cohort_target: cohort_target.to_string(),
                dimension_prefix: dimension_prefix.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AttestationRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn key_grant_held_owner(
        &self,
        axis: &crate::federation::key_grant::KeyGrantAxis,
    ) -> Result<Option<String>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::KeyGrantHeldOwner { axis: axis.clone() })
            .await?
        {
            DirectoryOpResult::OptionalString(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_all_transport_destinations_unfolded(
        &self,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        // v61.4.0 — the pre-fold read, run inside persist's `.so`.
        match self
            .run_op(&DirectoryOp::ListAllTransportDestinationsUnfolded {})
            .await?
        {
            DirectoryOpResult::TransportDestinations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_transport_destinations_by_destination_unfolded(
        &self,
        destination: &str,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        // v61.4.0 — the pre-fold claimant read, run inside persist's `.so`.
        match self
            .run_op(
                &DirectoryOp::ListTransportDestinationsByDestinationUnfolded {
                    destination: destination.to_string(),
                },
            )
            .await?
        {
            DirectoryOpResult::TransportDestinations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn put_signed_transport_destination(
        &self,
        signed: &self_at_login::SignedTransportDestination,
    ) -> Result<self_at_login::TransportDestinationApplyOutcome, Error> {
        // #443 — the authenticated route apply across the wheel boundary;
        // gate + monotonic guard run inside persist's .so.
        match self
            .run_op(&DirectoryOp::PutSignedTransportDestination {
                signed: signed.clone(),
            })
            .await?
        {
            DirectoryOpResult::TransportDestinationApplyOutcome(outcome) => Ok(outcome),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_signed_transport_destinations_for(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<self_at_login::SignedTransportDestination>, Error> {
        // #443 — the route-plane signed replication read across the wheel
        // boundary (byte-exact container round-trip).
        match self
            .run_op(&DirectoryOp::ListSignedTransportDestinationsFor {
                occurrence_key_id: occurrence_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SignedTransportDestinations(v) => Ok(v),
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

    // v53.0.0 (CIRISPersist#975) — the row-type census is a local report
    // door; no DirectoryOp carries it.
    async fn attestation_type_census(
        &self,
    ) -> Result<Vec<crate::federation::row_type::AttestationTypeCount>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self.run_op(&DirectoryOp::AttestationTypeCensus {}).await? {
            DirectoryOpResult::AttestationTypeCounts(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn lookup_keys_for_identity(&self, identity_ref: &str) -> Result<Vec<KeyRecord>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::LookupKeysForIdentity {
                identity_ref: identity_ref.to_string(),
            })
            .await?
        {
            DirectoryOpResult::KeyRecords(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn set_consent_role(
        &self,
        key_id: &str,
        consent_role: Option<&str>,
    ) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::SetConsentRole {
                key_id: key_id.to_string(),
                consent_role: consent_role.map(str::to_owned),
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
    async fn attestation_upsert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::AttestationUpsertLocal { input })
            .await?
        {
            DirectoryOpResult::AttestationId(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn attestation_insert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::AttestationInsertLocal { input })
            .await?
        {
            DirectoryOpResult::AttestationId(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    /// v59.1.2 (CIRISPersist#1162) — routed (was `Error::Unsupported`). Every
    /// `AttestationQuery` read on a capsule consumer — the owner walk,
    /// `owner_of`, edge's chat reader — reaches the host's backend here; the
    /// stub made each one a refusal on every phone and agent-embedded node.
    async fn execute_attestation_query(
        &self,
        q: &crate::federation::attestation_query::AttestationQuery,
    ) -> Result<crate::federation::attestation_query::QueryRows, Error> {
        match self
            .run_op(&DirectoryOp::ExecuteAttestationQuery { query: q.clone() })
            .await?
        {
            DirectoryOpResult::AttestationQueryRows(rows) => Ok(rows),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    // v56.0.0 (CIRISPersist#1001) — required now (its default composed over a
    // retired read): not proxied across the capsule.
    async fn list_attestations_by_dimension_citing(
        &self,
        attesting_key_id: &str,
        dimension: &str,
        evidence_ref: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::ListAttestationsByDimensionCiting {
                attesting_key_id: attesting_key_id.to_string(),
                dimension: dimension.to_string(),
                evidence_ref: evidence_ref.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AttestationRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_attestations_referencing(
        &self,
        target_attestation_id: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, the rooting view).
        match self
            .run_op(&DirectoryOp::ListAttestationsReferencing {
                target_attestation_id: target_attestation_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AttestationRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_composers_referencing_any(
        &self,
        target_attestation_ids: &[String],
        attested_key_id: Option<&str>,
        attesting_key_id: Option<&str>,
    ) -> Result<Vec<Attestation>, Error> {
        // v59.1.2 (CIRISPersist#1162) — routed: `owner_of` reaches it through
        // the live-delegation fold's retraction read.
        match self
            .run_op(&DirectoryOp::ListComposersReferencingAny {
                target_attestation_ids: target_attestation_ids.to_vec(),
                attested_key_id: attested_key_id.map(str::to_owned),
                attesting_key_id: attesting_key_id.map(str::to_owned),
            })
            .await?
        {
            DirectoryOpResult::AttestationRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn attestations_binding_content(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::AttestationsBindingContent {
                content_sha256: content_sha256.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AttestationRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    /// v61.4.0 (CIRISPersist#1260) — unsupported, as the binding query
    /// beside it is.
    async fn attestations_binding_content_with_placements(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::AttestationsBindingContentWithPlacements {
                content_sha256: content_sha256.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AttestationRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    /// v53.1.0 (#979) — a capsule host stores no blobs through this surface;
    /// unsupported, as the binding query beside it is.
    async fn dag_manifests_of_chunk(
        &self,
        chunk_sha256: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::DagManifestsOfChunk {
                chunk_sha256: *chunk_sha256,
            })
            .await?
        {
            DirectoryOpResult::ChunkManifests(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    /// v31.1.0 (CIRISPersist#655) — routed (was `Error::Unsupported`). An
    /// exclusion plane a capsule host could write and never read back is the
    /// same defect #655 found on the serve side, one surface over.
    async fn revocations_for(&self, revoked_key_id: &str) -> Result<Vec<Revocation>, Error> {
        match self
            .run_op(&DirectoryOp::RevocationsFor {
                revoked_key_id: revoked_key_id.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Revocations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    /// v52.0.0 (CIRISPersist#784) — routed, as `revocations_for` is.
    async fn revocations_for_subject(
        &self,
        revoked_key_sha256_ed25519_raw: &str,
    ) -> Result<Vec<Revocation>, Error> {
        match self
            .run_op(&DirectoryOp::RevocationsForSubject {
                revoked_key_sha256_ed25519_raw: revoked_key_sha256_ed25519_raw.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Revocations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<IdentityOccurrence>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, the rooting view).
        match self
            .run_op(&DirectoryOp::ListIdentityOccurrencesFor {
                identity_key_id: identity_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::IdentityOccurrences(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    // v59.1.2 (CIRISPersist#1162) — routed (was `Unsupported`, #851):
    // `owner_of`'s `self_of_at` reads it, so a capsule consumer's owner walk
    // needs it.
    async fn list_identity_occurrences_by_occurrence_key(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<IdentityOccurrence>, Error> {
        match self
            .run_op(&DirectoryOp::ListIdentityOccurrencesByOccurrenceKey {
                occurrence_key_id: occurrence_key_id.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::IdentityOccurrences(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    // v59.1.2 (CIRISPersist#1162) — routed (was `Unsupported`, v52.0.0
    // #930): `owner_of` folds every granter through `self_of_at`, which
    // reads this history, so a capsule consumer's owner walk needs it.
    async fn list_identity_occurrence_history_by_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<crate::federation::OccurrenceAssertion>, Error> {
        match self
            .run_op(&DirectoryOp::ListIdentityOccurrenceHistoryByOccurrence {
                occurrence_key_id: occurrence_key_id.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::OccurrenceHistory(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn lookup_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<IdentityOccurrence>, Error> {
        // #397 — routed (was Error::Unsupported). This is the reverse
        // occurrence→identity lookup the agent's embedded edge drives inside
        // `resolve_peer_kex_pubkeys`; unrouted, an explicit-hash canonical
        // (which cannot announce) was unrootable.
        match self
            .run_op(&DirectoryOp::LookupIdentityForOccurrence {
                occurrence_key_id: occurrence_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::IdentityOccurrence(v) => {
                // Ask 3 — make the resolve outcome self-evident (a swallowed
                // error here previously required an in-process resolver-map
                // snapshot to diagnose).
                if v.is_some() {
                    tracing::info!(
                        occurrence_key_id,
                        "directory: identity resolved for occurrence"
                    );
                } else {
                    tracing::warn!(
                        occurrence_key_id,
                        "directory: no identity bound for occurrence — peer cannot be \
                         rooted from this key (occurrence not registered)"
                    );
                }
                Ok(v)
            }
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_signed_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::SignedIdentityOccurrence>, Error> {
        // #418 replication read — routed so the embedded edge (CIRISEdge#305)
        // can re-publish an occurrence to a peer verbatim. Edge holds only the
        // transport signer, not the identity's federation key, so it cannot
        // re-sign; the signed tuple must round-trip byte-exact through the ABI.
        match self
            .run_op(&DirectoryOp::ListSignedIdentityOccurrencesFor {
                identity_key_id: identity_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SignedIdentityOccurrences(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_signed_records(
        &self,
        kind: crate::federation::namespace::ReplicatedKind,
        subject_key_id: &str,
    ) -> Result<Vec<crate::federation::namespace::SignedReplicatedRecord>, Error> {
        // #425 uniform signed read — routed so the embedded edge's one
        // replication engine fetches every kind byte-exact through the ABI.
        match self
            .run_op(&DirectoryOp::ListSignedRecords {
                kind,
                subject_key_id: subject_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SignedReplicatedRecords(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn add_family_member(
        &self,
        family_key_id: &str,
        member: types::FamilyMember,
        spec: &crate::federation::cohort::AdmitSpec,
    ) -> Result<bool, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::AddFamilyMember {
                family_key_id: family_key_id.to_string(),
                member,
                spec: spec.clone(),
            })
            .await?
        {
            DirectoryOpResult::Bool(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn lookup_family(&self, family_key_id: &str) -> Result<Option<Family>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::LookupFamily {
                family_key_id: family_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::Family(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_families_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Family>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListFamiliesForMember {
                member_identity_key_id: member_identity_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::Families(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn lookup_community(&self, community_key_id: &str) -> Result<Option<Community>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::LookupCommunity {
                community_key_id: community_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::Community(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_communities_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Community>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::ListCommunitiesForMember {
                member_identity_key_id: member_identity_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::Communities(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn put_family_membership_revocation(
        &self,
        revocation: SignedFamilyMembershipRevocation,
    ) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::PutFamilyMembershipRevocation { revocation })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn put_community_membership_revocation(
        &self,
        revocation: SignedCommunityMembershipRevocation,
    ) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::PutCommunityMembershipRevocation { revocation })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn put_community_membership_widening(
        &self,
        widening: crate::federation::SignedCommunityMembershipWidening,
    ) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::PutCommunityMembershipWidening { widening })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn put_family_membership_widening(
        &self,
        widening: crate::federation::SignedFamilyMembershipWidening,
    ) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::PutFamilyMembershipWidening { widening })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_identity_occurrence_revocations_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<IdentityOccurrenceRevocation>, Error> {
        // #329 — routed (was Error::Unsupported). The raw revocation-plane
        // read; SEALING decisions should go through the trait's
        // `resolve_encryption_keys` (overridden below to route the composite
        // op) so the revocation comparator runs inside persist's `.so`.
        match self
            .run_op(&DirectoryOp::ListIdentityOccurrenceRevocationsFor {
                identity_key_id: identity_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::IdentityOccurrenceRevocations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// #329 (CIRISServer#260 field hit) — OVERRIDE of the trait's default
    /// fold. The default decomposes into `lookup_identity_for_occurrence` +
    /// `list_identity_occurrence_revocations_for` and runs the validity
    /// window + the v16 `revokes()` re-establishment comparator IN THE
    /// CONSUMER'S BINARY — the #320 cross-cdylib skew class, on the
    /// seal-safety path (a cohabiting consumer pinned to an older persist
    /// crate would run a stale comparator against newer data). Routing the
    /// ONE composite op executes the whole fold inside persist's `.so`
    /// against persist's own comparator and clock.
    async fn resolve_encryption_keys(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<crate::federation::EncryptionPubkeys>, Error> {
        match self
            .run_op(&DirectoryOp::ResolveEncryptionKeys {
                occurrence_key_id: occurrence_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::EncryptionKeys(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v17.4.0 — route the `scores` LIST read through the composite op so the
    /// §4.3 gate + ordered seek run in persist's `.so`.
    async fn list_scores(
        &self,
        caller_occurrence_key_id: &str,
        filter: crate::read::AttestationFilter,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::ScoresPage, Error> {
        match self
            .run_op(&DirectoryOp::ListScores {
                caller_occurrence_key_id: caller_occurrence_key_id.to_string(),
                filter,
                cursor,
                limit,
            })
            .await?
        {
            DirectoryOpResult::Scores(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v17.4.0 — route the `scores` RESOLVE fold through the composite op (the
    /// #329 pattern): the whole gate + precedence + aggregation runs in
    /// persist's `.so`, never a stale comparator in the consumer's binary.
    async fn resolve_scores(
        &self,
        caller_occurrence_key_id: &str,
        filter: crate::read::AttestationFilter,
        policy: String,
        trace: bool,
    ) -> Result<crate::read::ComposedVerdict, Error> {
        match self
            .run_op(&DirectoryOp::ResolveScores {
                caller_occurrence_key_id: caller_occurrence_key_id.to_string(),
                filter,
                policy,
                trace,
            })
            .await?
        {
            DirectoryOpResult::ComposedVerdict(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v17.5.0 (#455) — route the owner-scope replication LOG walk through the
    /// capsule so edge's advertise sweep reaches the real (un-gated,
    /// lifecycle-blind, byte-faithful) enumeration inside persist's `.so`.
    async fn list_attestation_log(
        &self,
        subject_key_id: Option<&str>,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::ScoresPage, Error> {
        match self
            .run_op(&DirectoryOp::ListAttestationLog {
                subject_key_id: subject_key_id.map(str::to_string),
                cursor,
                limit,
            })
            .await?
        {
            DirectoryOpResult::Scores(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v61.0.5 (CIRISPersist#1225) — the subject read, proxied.
    async fn list_attestations_naming_by_dimension(
        &self,
        subject_key_id: &str,
        dimension: &str,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::ScoresPage, Error> {
        match self
            .run_op(&DirectoryOp::ListAttestationsNamingByDimension {
                subject_key_id: subject_key_id.to_owned(),
                dimension: dimension.to_owned(),
                cursor,
                limit,
            })
            .await?
        {
            DirectoryOpResult::Scores(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v61.1.0 (CIRISPersist#1190) — the narrowed serve read, proxied.
    async fn list_attestations_since_by_prefixes(
        &self,
        since: Option<crate::federation::types::ServePosition>,
        family_prefixes: &[String],
        limit: i64,
    ) -> Result<
        crate::federation::types::ServePage<crate::federation::types::ServedAttestation>,
        Error,
    > {
        match self
            .run_op(&DirectoryOp::ListAttestationsSinceByPrefixes {
                since,
                family_prefixes: family_prefixes.to_vec(),
                limit,
            })
            .await?
        {
            DirectoryOpResult::ServedAttestationPage(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (v62 P8-fix5) — the held rows waiting for a key's voice,
    /// proxied: the default reads the fold store (`fold_dependents`,
    /// `fold_state`, `edition2_voices`), which answers EMPTY through the
    /// proxy and would read "nothing waits for you" (the #1244 fail-open
    /// class), so the whole read crosses.
    async fn held_rows_for(
        &self,
        key: &str,
        role: Option<&str>,
        after: Option<&crate::federation::edition2::names::RowId>,
        limit: u32,
    ) -> Result<Vec<crate::federation::edition2::second_signer_voice::HeldRow>, Error> {
        match self
            .run_op(&DirectoryOp::HeldRowsFor {
                key: key.to_owned(),
                role: role.map(str::to_owned),
                after: after.map(|r| r.0),
                limit,
            })
            .await?
        {
            DirectoryOpResult::HeldRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (v62 P8-fix5) — a row's voice state, proxied (the default's
    /// fold read answers empty through the proxy: every row would read
    /// `Waiting` with no reason).
    async fn voice_status(
        &self,
        row_id: &crate::federation::edition2::names::RowId,
    ) -> Result<crate::federation::edition2::second_signer_voice::VoiceOutcome, Error> {
        match self
            .run_op(&DirectoryOp::VoiceStatus { row_id: row_id.0 })
            .await?
        {
            DirectoryOpResult::VoiceOutcome(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (v62 P8-fix5) — a second signer's voice, put through the
    /// statement door inside persist's `.so` and answered with the row's
    /// state in one crossing.
    async fn submit_voice(
        &self,
        statement: &[u8],
    ) -> Result<crate::federation::edition2::second_signer_voice::VoiceOutcome, Error> {
        match self
            .run_op(&DirectoryOp::SubmitVoice {
                statement: statement.to_vec(),
            })
            .await?
        {
            DirectoryOpResult::VoiceOutcome(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (LF-fix2, T5) — the replicated statement door, routed WHOLE as
    /// the `ApplyReplicatedStatement` op: its gates, its fold and its
    /// receive-side hooks (the #916 owner-binding re-wrap, which this proxy
    /// does not route as a method) run inside persist over the host's store.
    /// A wait (`federation_attester_key_unknown`) crosses typed
    /// (`TypedErr`, relayed by `run_op`); a lost race is the outcome's
    /// `Refused`, never an error.
    async fn replicated_statement_door(
        &self,
        statement: &[u8],
        offered_id: &[u8; 32],
    ) -> Result<crate::federation::edition2::ingest::ReplicatedStatementOutcome, Error> {
        match self
            .run_op(&DirectoryOp::ApplyReplicatedStatement {
                statement: statement.to_vec(),
                offered_row_id: *offered_id,
            })
            .await?
        {
            DirectoryOpResult::ReplicatedStatementOutcome(o) => Ok(o.into()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (AU-fix2; CC 2.7.11) — the live `admission:unit` rows,
    /// proxied: the default reads the edition-2 store, which refuses through
    /// the proxy, so the whole read crosses.
    async fn admission_unit_rows(
        &self,
        sub: &str,
        at: chrono::DateTime<chrono::Utc>,
        owner: Option<&str>,
    ) -> Result<Vec<crate::federation::edition2::admission_unit::AdmissionUnitRow>, Error> {
        let at_ms = u64::try_from(at.timestamp_millis()).map_err(|_| {
            Error::InvalidArgument(format!("admission_unit_rows: {at} is before the epoch"))
        })?;
        match self
            .run_op(&DirectoryOp::AdmissionUnitRows {
                sub: sub.to_owned(),
                at_ms,
                owner: owner.map(str::to_owned),
            })
            .await?
        {
            DirectoryOpResult::AdmissionUnitRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (JSON-cut slice D) — the edition-2 serve listing, proxied.
    /// The trait default answers EMPTY, which a serving consumer would read
    /// as "nothing held" (the #1244 fail-open class), so the read crosses.
    async fn edition2_statements_since(
        &self,
        cursor: Option<&crate::federation::edition2::store::StatementCursor>,
        limit: u32,
    ) -> Result<Vec<crate::federation::edition2::store::ServedStatement>, Error> {
        match self
            .run_op(&DirectoryOp::Edition2StatementsSince {
                cursor: cursor.copied().map(Edition2Cursor::from),
                limit,
            })
            .await?
        {
            DirectoryOpResult::Edition2StatementPage(v) => Ok(v
                .into_iter()
                .map(|s| crate::federation::edition2::store::ServedStatement {
                    cursor: s.cursor.into(),
                    bytes: s.bytes,
                })
                .collect()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    // ── v62.0.0 (PX-fix1) — the edition-2 and fold store reads, proxied ──
    //
    // Each trait default answered empty / `None` / `false`, so every free
    // fold a consumer composes over this proxy (`genesis_in_force`,
    // `held_keys_for_kid`, `bytes_servable`, `is_held_back`, the group serve
    // filter, ...) read "nothing held" — fail-open (the #1244 class). Each
    // read crosses to the host's store; the defaults now refuse.

    async fn edition2_statements_about(
        &self,
        family: &str,
        sub: &str,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match self
            .run_op(&DirectoryOp::Edition2StatementsAbout {
                family: family.to_owned(),
                sub: sub.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Edition2Statements(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn edition2_voices(
        &self,
        row_id: &crate::federation::edition2::names::RowId,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match self
            .run_op(&DirectoryOp::Edition2Voices { row_id: row_id.0 })
            .await?
        {
            DirectoryOpResult::Edition2Statements(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn edition2_rows_naming(
        &self,
        named: &crate::federation::edition2::names::RowId,
        role: &str,
    ) -> Result<Vec<crate::federation::edition2::names::RowId>, Error> {
        match self
            .run_op(&DirectoryOp::Edition2RowsNaming {
                named: named.0,
                role: role.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Edition2RowIds(v) => Ok(v
                .into_iter()
                .map(crate::federation::edition2::names::RowId)
                .collect()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn edition2_objects(&self, typ: &str) -> Result<Vec<Vec<u8>>, Error> {
        match self
            .run_op(&DirectoryOp::Edition2Objects {
                typ: typ.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Edition2Statements(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn edition2_statement(&self, statement_id: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        match self
            .run_op(&DirectoryOp::Edition2Statement {
                statement_id: *statement_id,
            })
            .await?
        {
            DirectoryOpResult::OptionalBytes(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn edition2_statement_ids_since(
        &self,
        after: Option<&[u8; 32]>,
        limit: u32,
    ) -> Result<Vec<String>, Error> {
        match self
            .run_op(&DirectoryOp::Edition2StatementIdsSince {
                after: after.copied(),
                limit,
            })
            .await?
        {
            DirectoryOpResult::Edition2StatementIds(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn fold_held(
        &self,
        row_id: &crate::federation::edition2::names::RowId,
    ) -> Result<Option<crate::federation::edition2::fold::HeldReason>, Error> {
        match self
            .run_op(&DirectoryOp::FoldHeld { row_id: row_id.0 })
            .await?
        {
            DirectoryOpResult::FoldHeldReason(h) => Ok(h.map(Into::into)),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn fold_held_page(
        &self,
        after: Option<&crate::federation::edition2::names::RowId>,
        limit: u32,
    ) -> Result<Vec<crate::federation::edition2::fold::HeldReason>, Error> {
        match self
            .run_op(&DirectoryOp::FoldHeldPage {
                after: after.map(|r| r.0),
                limit,
            })
            .await?
        {
            DirectoryOpResult::FoldHeldReasons(v) => Ok(v.into_iter().map(Into::into).collect()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn fold_dependents(
        &self,
        read_keys: &[String],
    ) -> Result<Vec<crate::federation::edition2::names::RowId>, Error> {
        match self
            .run_op(&DirectoryOp::FoldDependents {
                read_keys: read_keys.to_vec(),
            })
            .await?
        {
            DirectoryOpResult::Edition2RowIds(v) => Ok(v
                .into_iter()
                .map(crate::federation::edition2::names::RowId)
                .collect()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn fold_state(
        &self,
        row_id: &crate::federation::edition2::names::RowId,
    ) -> Result<Option<crate::federation::edition2::fold::FoldState>, Error> {
        match self
            .run_op(&DirectoryOp::FoldState { row_id: row_id.0 })
            .await?
        {
            DirectoryOpResult::FoldStateOf(f) => Ok(f.map(Into::into)),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn fold_slot_rows(
        &self,
        slot: &str,
    ) -> Result<Vec<crate::federation::edition2::names::RowId>, Error> {
        match self
            .run_op(&DirectoryOp::FoldSlotRows {
                slot: slot.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Edition2RowIds(v) => Ok(v
                .into_iter()
                .map(crate::federation::edition2::names::RowId)
                .collect()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn fold_slot_held(&self, slot: &str) -> Result<bool, Error> {
        match self
            .run_op(&DirectoryOp::FoldSlotHeld {
                slot: slot.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Bool(b) => Ok(b),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn fold_any_refolding(&self) -> Result<bool, Error> {
        match self.run_op(&DirectoryOp::FoldAnyRefolding {}).await? {
            DirectoryOpResult::Bool(b) => Ok(b),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (PX-fix1) — the node-local touch, proxied: the replacement for
    /// the retired signed `put_touch_claim` (RULINGS: a touch claim is
    /// node-local), answered by the host's own floor.
    async fn put_touch_claim_local(
        &self,
        target_key_id: &str,
        target_kind: &str,
        fresh_as_of: chrono::DateTime<chrono::Utc>,
        cohort_scope: &str,
    ) -> Result<crate::federation::freshness::TouchApplyOutcome, Error> {
        match self
            .run_op(&DirectoryOp::PutTouchClaimLocal {
                target_key_id: target_key_id.to_owned(),
                target_kind: target_kind.to_owned(),
                fresh_as_of,
                cohort_scope: cohort_scope.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::TouchApplied(o) => Ok(o),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v62.0.0 (PX-fix1) — the floor this node holds, proxied.
    async fn freshness_floor(
        &self,
        target_key_id: &str,
        target_kind: &str,
    ) -> Result<Option<types::FreshnessFloor>, Error> {
        match self
            .run_op(&DirectoryOp::FreshnessFloor {
                target_key_id: target_key_id.to_owned(),
                target_kind: target_kind.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::FreshnessFloorOf(f) => Ok(f),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v61.1.0 (CIRISPersist#1163) — the owner-binding feed, proxied.
    async fn list_owner_bindings_since(
        &self,
        since: Option<crate::federation::types::ServePosition>,
        limit: i64,
    ) -> Result<
        crate::federation::types::ServePage<crate::federation::types::OwnerBindingChange>,
        Error,
    > {
        match self
            .run_op(&DirectoryOp::ListOwnerBindingsSince { since, limit })
            .await?
        {
            DirectoryOpResult::OwnerBindingPage(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v17.8.0 (#469) — route the seeder-bridge bookmark write through the
    /// capsule so edge's `resolve_announce_cold_start` Advisory admit path can
    /// record LAN-announced peers without an admission.
    async fn record_announced_peer(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        claimed_identity_type: Option<&str>,
        last_seen: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::RecordAnnouncedPeer {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: pubkey_ed25519_base64.to_owned(),
                pubkey_ml_dsa_65_base64: pubkey_ml_dsa_65_base64.map(str::to_owned),
                claimed_identity_type: claimed_identity_type.map(str::to_owned),
                last_seen,
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

    /// v17.8.0 (#469) — the live advisory-peer bookmarks via the capsule.
    async fn list_announced_peers(
        &self,
    ) -> Result<Vec<crate::federation::types::AnnouncedPeer>, Error> {
        match self.run_op(&DirectoryOp::ListAnnouncedPeers).await? {
            DirectoryOpResult::AnnouncedPeers(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v21.0.0 (#502 E7) — the revocation-folded `consent_peer_set` read
    /// via the capsule.
    async fn list_consent_peers(&self, node_key_id: &str) -> Result<Vec<String>, Error> {
        match self
            .run_op(&DirectoryOp::ListConsentPeers {
                node_key_id: node_key_id.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::ConsentPeers(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v21.0.0 (CIRISPersist#504 FLOOR) — the signed location-proof bulk
    /// read via the capsule.
    async fn list_signed_location_proofs_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedLocationProof>, Error> {
        match self
            .run_op(&DirectoryOp::ListSignedLocationProofsSince { since, limit })
            .await?
        {
            DirectoryOpResult::SignedLocationProofs(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v50.0.0 (CIRISPersist#917) — the typed unattributed door crosses whole.
    /// The trait default would plan on THIS side, where `get_attestation` is
    /// `Unsupported`, and fall back to plan-free apply over the untyped
    /// `PutAttestation` op — reporting a re-offer of a held row as `Inserted`
    /// and a conflict as an untyped backend error.
    async fn apply_replicated_attestation(
        &self,
        attestation: SignedAttestation,
    ) -> Result<crate::federation::attestation_apply::ReplicatedAttestationOutcome, Error> {
        match self
            .run_op(&DirectoryOp::ApplyReplicatedAttestation { attestation })
            .await?
        {
            DirectoryOpResult::ReplicatedAttestationOutcome(o) => Ok(o),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v50.0.0 (CIRISPersist#917) — the typed attributed door crosses whole,
    /// for the reason [`Self::apply_replicated_attestation`] gives. The peer
    /// travels so the far side meters it exactly as a direct call would.
    async fn put_attestation_synced(
        &self,
        attestation: SignedAttestation,
        authenticated_peer_key_id: &str,
    ) -> Result<crate::federation::attestation_apply::ReplicatedAttestationOutcome, Error> {
        match self
            .run_op(&DirectoryOp::ApplyReplicatedAttestationSynced {
                attestation,
                authenticated_peer_key_id: authenticated_peer_key_id.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::ReplicatedAttestationOutcome(o) => Ok(o),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v31.1.0 (CIRISPersist#662) — the signed accord EVIDENCE cursor, routed.
    async fn list_signed_accord_quorum_evidence_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::accord_carriage::AccordQuorumEvidence>, Error> {
        match self
            .run_op(&DirectoryOp::ListSignedAccordQuorumEvidenceSince { since, limit })
            .await?
        {
            DirectoryOpResult::AccordQuorumEvidence(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v31.1.0 (CIRISPersist#662) — the RECEIVE half, routed as ONE op so the
    /// re-tally runs inside persist's `.so`. The five primitives the free
    /// function composes are `Unsupported` on this proxy; without this a
    /// capsule host could serve evidence and never rebuild from it.
    async fn apply_replicated_accord_evidence(
        &self,
        evidence: &crate::federation::accord_carriage::AccordQuorumEvidence,
    ) -> Result<crate::federation::accord_carriage::AccordEvidenceAdmission, Error> {
        match self
            .run_op(&DirectoryOp::ApplyReplicatedAccordEvidence {
                evidence: evidence.clone(),
            })
            .await?
        {
            DirectoryOpResult::AccordEvidenceAdmitted(v) => Ok(v),
            // Reconstructed as the SAME typed errors the far side raised, so
            // `kind()` reads `accord_evidence_unverified` /
            // `accord_evidence_carrier_malformed` on both sides of the ABI.
            // A carrier keys its retry/quarantine decision on those tokens.
            DirectoryOpResult::AccordEvidenceRefused {
                proposal_digest,
                reason,
            } => Err(Error::AccordEvidenceUnverified {
                proposal_digest,
                reason,
            }),
            DirectoryOpResult::AccordEvidenceCarrierRefused {
                proposal_digest,
                participations,
                roster_seats,
                reason,
            } => Err(Error::AccordEvidenceCarrierMalformed {
                proposal_digest,
                participations,
                roster_seats,
                reason,
            }),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v21.1.0 (CIRISPersist#507c) — structural mirror of
    /// [`Self::list_signed_key_records_since`].
    async fn list_signed_transport_destinations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedTransportDestination>, Error> {
        match self
            .run_op(&DirectoryOp::ListSignedTransportDestinationsSince { since, limit })
            .await?
        {
            DirectoryOpResult::SignedTransportDestinationsSince(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v21.1.0 (CIRISPersist#507c) — structural mirror of
    /// [`Self::list_signed_key_records_since`]; federation-tier-only rows
    /// (the E5 invariant).
    async fn list_attestations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedAttestation>, Error> {
        match self
            .run_op(&DirectoryOp::ListAttestationsSince { since, limit })
            .await?
        {
            DirectoryOpResult::Attestations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v21.1.0 (CIRISPersist#507b) — the content-hash point-read via the
    /// capsule.
    async fn lookup_signed_record_by_content_hash(
        &self,
        kind: &str,
        content_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        match self
            .run_op(&DirectoryOp::LookupSignedRecordByContentHash {
                kind: kind.to_owned(),
                content_hash: content_hash.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::OptionalBytes(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// v21.1.0 (CIRISPersist#507b) — the full-rebuild backfill via the
    /// capsule.
    /// CIRISPersist#785 — #780's held-hash read, routed. It shipped in
    /// v38.7.0 with a default body and no op, so a capsule consumer reached
    /// the default and got `Unsupported`.
    /// v60.0.0 (CIRISPersist#1105) — the family-scoped held-hash read,
    /// routed.
    async fn list_key_plane_wire_hashes_since(
        &self,
        family: &str,
        after_content_hash: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, Error> {
        match self
            .run_op(&DirectoryOp::ListKeyPlaneWireHashesSince {
                family: family.to_owned(),
                after_content_hash: after_content_hash.map(str::to_owned),
                limit,
            })
            .await?
        {
            DirectoryOpResult::WireHashes(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_wire_hashes_since(
        &self,
        kind: &str,
        after_content_hash: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, Error> {
        match self
            .run_op(&DirectoryOp::ListWireHashesSince {
                kind: kind.to_owned(),
                after_content_hash: after_content_hash.map(str::to_owned),
                limit,
            })
            .await?
        {
            DirectoryOpResult::WireHashes(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// CIRISPersist#785 — record that a hash exists, unheld.
    async fn insert_known_wire_hash(
        &self,
        kind: &str,
        content_hash: &str,
        advertised_by: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        match self
            .run_op(&DirectoryOp::InsertKnownWireHash {
                kind: kind.to_owned(),
                content_hash: content_hash.to_owned(),
                advertised_by: advertised_by.map(str::to_owned),
                now,
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

    /// CIRISPersist#785 — is this hash known to exist?
    async fn known_wire_hash_contains(
        &self,
        kind: &str,
        content_hash: &str,
    ) -> Result<bool, Error> {
        match self
            .run_op(&DirectoryOp::KnownWireHashContains {
                kind: kind.to_owned(),
                content_hash: content_hash.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::Bool(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// CIRISPersist#785 — page the KNOWN set, cursored on the hash.
    async fn list_known_wire_hashes_since(
        &self,
        kind: &str,
        after_content_hash: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::federation::KnownWireHash>, Error> {
        match self
            .run_op(&DirectoryOp::ListKnownWireHashesSince {
                kind: kind.to_owned(),
                after_content_hash: after_content_hash.map(str::to_owned),
                limit,
            })
            .await?
        {
            DirectoryOpResult::KnownWireHashes(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    /// CIRISPersist#785 — evict on a caller-supplied cutoff.
    async fn evict_known_wire_hashes(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
        bound: u64,
    ) -> Result<crate::federation::KnownHashEviction, Error> {
        match self
            .run_op(&DirectoryOp::EvictKnownWireHashes { cutoff, bound })
            .await?
        {
            DirectoryOpResult::KnownHashEviction(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn rebuild_signed_wire_index(&self) -> Result<u64, Error> {
        match self.run_op(&DirectoryOp::RebuildSignedWireIndex).await? {
            DirectoryOpResult::U64(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_family_membership_revocations_for(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<FamilyMembershipRevocation>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListFamilyMembershipRevocationsFor {
                family_key_id: family_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::FamilyMembershipRevocations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_live_consent_grants_by(
        &self,
        node_key_id: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::ListLiveConsentGrantsBy {
                node_key_id: node_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AttestationRows(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn edition2_roster_proposal(
        &self,
        row_id_hex: &str,
    ) -> Result<Option<crate::federation::self_roster::SelfRosterReceipt>, Error> {
        // v62.0.0 (round 3, O1 fix 5) — one receipt of the edition-2 rooting
        // view (the roster fold's "did this row land here").
        match self
            .run_op(&DirectoryOp::Edition2RosterProposal {
                row_id_hex: row_id_hex.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SelfRosterReceipts(v) => Ok(v.into_iter().next()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_settled_edition2_roster_proposals(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::self_roster::SelfRosterReceipt>, Error> {
        // v62.0.0 (round 3, L1) — the edition-2 rooting view, as
        // `list_settled_self_roster_proposals`.
        match self
            .run_op(&DirectoryOp::ListSettledEdition2RosterProposals {
                identity_key_id: identity_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::SelfRosterReceipts(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_community_membership_revocations_for(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<CommunityMembershipRevocation>, Error> {
        // v61.4.2 — the removal half of a room's active roster (Edge's call
        // join reads record + widenings − revocations through the capsule).
        match self
            .run_op(&DirectoryOp::ListCommunityMembershipRevocationsFor {
                community_key_id: community_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::CommunityMembershipRevocations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_community_membership_widenings_for(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<crate::federation::CommunityMembershipWidening>, Error> {
        // v61.4.2 — the growth half of a room's active roster.
        match self
            .run_op(&DirectoryOp::ListCommunityMembershipWideningsFor {
                community_key_id: community_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::CommunityMembershipWidenings(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_family_membership_widenings_for(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<types::FamilyMembershipWidening>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListFamilyMembershipWideningsFor {
                family_key_id: family_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::FamilyMembershipWidenings(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_location_proofs_for(
        &self,
        subject_key_id: &str,
    ) -> Result<Vec<LocationProof>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::ListLocationProofsFor {
                subject_key_id: subject_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::LocationProofs(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn withdraw_location_proof(&self, proof: SignedLocationProof) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::WithdrawLocationProof { proof })
            .await?
        {
            DirectoryOpResult::Unit => Ok(()),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn communities_containing(&self, cell_id: &str) -> Result<Vec<Community>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::CommunitiesContaining {
                cell_id: cell_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::Communities(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn add_community_member(
        &self,
        community_key_id: &str,
        member: types::CommunityMember,
        spec: &cohort::AdmitSpec,
    ) -> Result<bool, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::AddCommunityMember {
                community_key_id: community_key_id.to_string(),
                member,
                spec: spec.clone(),
            })
            .await?
        {
            DirectoryOpResult::Bool(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn supersede_group_row(
        &self,
        cohort: cohort::Cohort,
        new_snapshot: serde_json::Value,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::SupersedeGroupRow {
                cohort,
                new_snapshot,
                authorization,
            })
            .await?
        {
            DirectoryOpResult::GroupRowVersion(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    /// v62.0.0 (PX-fix3) — the held tips, proxied: the roster fold composed
    /// over this proxy reads them, and their `Unsupported` read as "not
    /// forked" (a forked group's roster read as its head's).
    async fn list_group_tips(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<cohort::GroupTip>, Error> {
        match self
            .run_op(&DirectoryOp::ListGroupTips {
                cohort,
                group_key_id: group_key_id.to_owned(),
            })
            .await?
        {
            DirectoryOpResult::GroupTips(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }

    async fn list_group_versions(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<cohort::GroupVersion>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::ListGroupVersions {
                cohort,
                group_key_id: group_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::GroupVersions(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn get_attestation(&self, attestation_id: &str) -> Result<Option<Attestation>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, the rooting view).
        match self
            .run_op(&DirectoryOp::GetAttestation {
                attestation_id: attestation_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::Attestation(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn enter_mesh(
        &self,
        attestation_id: &str,
        ci: &crate::federation::ContextualIntegrity,
        custody: &crate::federation::TierPromotionCustody,
    ) -> Result<crate::federation::MeshCrossingOutcome, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::EnterMesh {
                attestation_id: attestation_id.to_string(),
                ci: ci.clone(),
                custody: custody.clone(),
            })
            .await?
        {
            DirectoryOpResult::MeshCrossing(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn get_accord_proposal(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<accord_quorum::StoredProposal>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::GetAccordProposal {
                proposal_digest: proposal_digest.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AccordProposal(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_accord_proposals_by_anchor(
        &self,
        action: &str,
        prior_family_digest: &str,
    ) -> Result<Vec<accord_quorum::StoredProposal>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::ListAccordProposalsByAnchor {
                action: action.to_string(),
                prior_family_digest: prior_family_digest.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AccordProposals(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn list_accord_participations(
        &self,
        proposal_digest: &str,
    ) -> Result<Vec<accord_quorum::StoredParticipation>, Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::ListAccordParticipations {
                proposal_digest: proposal_digest.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AccordParticipations(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn get_accord_decision(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<accord_quorum::StoredDecision>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::GetAccordDecision {
                proposal_digest: proposal_digest.to_string(),
            })
            .await?
        {
            DirectoryOpResult::AccordDecision(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn set_active_halt(
        &self,
        family_key_id: &str,
        active_halt_id: &str,
        latch_json: Option<&str>,
    ) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::SetActiveHalt {
                family_key_id: family_key_id.to_string(),
                active_halt_id: active_halt_id.to_string(),
                latch_json: latch_json.map(str::to_owned),
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
    async fn get_active_halt(
        &self,
        family_key_id: &str,
    ) -> Result<Option<accord_quorum::ActiveHalt>, Error> {
        // v61.4.0 (CIRISPersist#1244 round 2, a fail-open trust read).
        match self
            .run_op(&DirectoryOp::GetActiveHalt {
                family_key_id: family_key_id.to_string(),
            })
            .await?
        {
            DirectoryOpResult::ActiveHalt(v) => Ok(v),
            DirectoryOpResult::Err(s) => Err(Error::Backend(s)),
            _ => Err(Error::Backend(
                "directory ops proxy: unexpected result variant".into(),
            )),
        }
    }
    async fn clear_active_halt(
        &self,
        family_key_id: &str,
        active_halt_id: &str,
    ) -> Result<(), Error> {
        // v61.4.2 (the capsule stub sweep).
        match self
            .run_op(&DirectoryOp::ClearActiveHalt {
                family_key_id: family_key_id.to_string(),
                active_halt_id: active_halt_id.to_string(),
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
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::mpsc;

    // ── shared helpers ─────────────────────────────────────────────

    fn test_directory() -> (Arc<dyn FederationDirectory>, Directory) {
        let backend: Arc<SqliteBackend> = Arc::new(crate::store::test_backend::test_backend());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());
        (dir, directory)
    }

    /// v50.0.0 (CIRISPersist#928, final check) — the proxy forwards the
    /// recorded admission depth of a stored `withdraws` (never guessing 16):
    /// a deferred `withdraws` admitted at the default reads back 5 through the
    /// op; an id with nothing recorded reads `None`.
    #[test]
    fn withdraws_admission_depth_op_forwards_the_recorded_depth() {
        // v62.0.0 (JSON cut, E7) — a withdraws of a HELD row (an edition-2
        // composer names a held row; the deferred arm is gone) is admitted at
        // the node's default depth, and the op reads it back.
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        let (wid, _) = seed_withdraws_e2(&rt, dir.as_ref(), "capsule-issuer", "depth");
        for (id, want) in [
            (
                wid.as_str(),
                Some(crate::federation::DEFAULT_DELEGATION_DEPTH as u32),
            ),
            ("no-such-row", None),
        ] {
            match run_op(
                &rt,
                &directory,
                &DirectoryOp::WithdrawsAdmissionDepth {
                    attestation_id: id.to_owned(),
                },
            ) {
                DirectoryOpResult::WithdrawsAdmissionDepth(d) => assert_eq!(d, want, "{id}"),
                other => panic!("{id}: {other:?}"),
            }
        }
    }

    /// CIRISPersist#973 — the op forwards the backend's held set: a marked id
    /// comes back, an unmarked one does not.
    #[test]
    fn trust_direction_held_among_op_forwards_the_held_set() {
        let rt = test_runtime();
        let backend = Arc::new(crate::store::test_backend::test_backend());
        backend.mark_trust_direction_held("held-row");
        let directory = build_persist_directory(backend as Arc<dyn FederationDirectory>);
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::TrustDirectionHeldAmong {
                attestation_ids: vec!["held-row".to_owned(), "new-row".to_owned()],
            },
        ) {
            DirectoryOpResult::WireHashes(v) => assert_eq!(v, vec!["held-row".to_owned()]),
            other => panic!("{other:?}"),
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
        // v62.0.0 (ABI 14) — these witnesses read a failure's TEXT; a
        // `TypedErr` carries the same text the pre-v62 `Err` did.
        serde_json::from_slice::<DirectoryOpResult>(&bytes)
            .expect("deserialize DirectoryOpResult")
            .into_flattened()
    }

    /// v61.0.5 (CIRISPersist#1225) — **I1548: the subject read crosses the
    /// capsule.** Rows seeded on the backend come back through the C-ABI as the
    /// same page, in the same order and with the same cursor, as the direct
    /// trait call, and a refused page size is refused through the capsule too.
    #[test]
    fn i1548_subject_read_round_trips_the_capsule() {
        use crate::federation::subject_read_1225_invariants::bodies as b;
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        let (k, ids) = rt.block_on(async {
            let (a, k) = b::keys(dir.as_ref(), "cap").await;
            let mut ids = Vec::new();
            for s in [30, 20, 10] {
                ids.push(b::put_naming(dir.as_ref(), &a, &[&k], b::DIM, b::at(s), None).await);
            }
            (k, ids)
        });
        let direct = rt
            .block_on(dir.list_attestations_naming_by_dimension(&k, b::DIM, None, 2))
            .expect("direct");
        let op = |cursor| DirectoryOp::ListAttestationsNamingByDimension {
            subject_key_id: k.clone(),
            dimension: b::DIM.into(),
            cursor,
            limit: 2,
        };
        let first = match run_op(&rt, &directory, &op(None)) {
            DirectoryOpResult::Scores(page) => page,
            other => panic!("I1548: expected Scores, got {other:?}"),
        };
        let page_ids = |p: &crate::read::ScoresPage| -> Vec<String> {
            p.items.iter().map(|a| a.attestation_id.clone()).collect()
        };
        assert_eq!(page_ids(&first), page_ids(&direct), "I1548: the same page");
        assert_eq!(
            page_ids(&first),
            vec![ids[2].clone(), ids[1].clone()],
            "I1548: newest first"
        );
        let cursor = first
            .next_cursor
            .clone()
            .expect("I1548: more past the first page");
        assert_eq!(
            Some(&cursor),
            direct.next_cursor.as_ref(),
            "I1548: the same cursor"
        );
        match run_op(&rt, &directory, &op(Some(cursor))) {
            DirectoryOpResult::Scores(page) => {
                assert_eq!(
                    page_ids(&page),
                    vec![ids[0].clone()],
                    "I1548: the last page"
                );
                assert!(page.next_cursor.is_none(), "I1548: nothing past");
            }
            other => panic!("I1548: expected Scores, got {other:?}"),
        }
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListAttestationsNamingByDimension {
                subject_key_id: k.clone(),
                dimension: b::DIM.into(),
                cursor: None,
                limit: 0,
            },
        ) {
            DirectoryOpResult::Err(_) => {}
            other => panic!("I1548: a page of 0 is refused through the capsule, got {other:?}"),
        }
    }

    /// v61.1.0 (CIRISPersist#1235) — **I1587: the caller scope crosses the
    /// capsule's worker hop.** `build_op` runs on the caller's thread and the
    /// op is polled on persist's worker, where neither the caller's task scope
    /// nor its thread scope is in force; the read must still be credited to
    /// the caller in force when `build_op` ran. The worker records into the
    /// process-wide counters, so the witness reads those under a label no other
    /// test sets.
    #[test]
    fn i1587_the_caller_scope_crosses_the_capsule() {
        use crate::observe::{self, Caller, ThreadCallerScope};
        let rt = test_runtime();
        let (_dir, directory) = test_directory();
        let label = "i1587.capsule";
        let caller = Caller::new(label).expect("a legal label");
        let at = || {
            observe::snapshot().caller(
                observe::StoreBackend::Sqlite,
                observe::Door::ListAttestationsSince,
                label,
            )
        };
        let before = at();
        let op = DirectoryOp::ListAttestationsSince {
            since: None,
            limit: 10,
        };
        {
            let _scope = ThreadCallerScope::enter(Some(caller));
            match run_op(&rt, &directory, &op) {
                DirectoryOpResult::Attestations(rows) => assert!(rows.is_empty()),
                other => panic!("I1587: expected Attestations, got {other:?}"),
            }
        }
        // Outside the scope: not credited to the label.
        match run_op(&rt, &directory, &op) {
            DirectoryOpResult::Attestations(_) => {}
            other => panic!("I1587: expected Attestations, got {other:?}"),
        }
        let after = at();
        assert_eq!(
            (after.0 - before.0, after.1 - before.1, after.2 - before.2),
            (1, 0, 0),
            "I1587: the one scoped read through the capsule is the caller's"
        );
    }

    /// v61.1.0 (CIRISPersist#1190, #1163) — **I1578: both narrowed serve
    /// reads cross the capsule.** The prefix read and the owner-binding feed
    /// come back through the C-ABI as the same page, cursor and high water as
    /// the direct trait call, the cursor resumes through the op, and a refused
    /// input is refused through the capsule too.
    #[test]
    fn i1578_serve_feeds_round_trip_the_capsule() {
        use crate::federation::serve_feeds_1163_1190_invariants::bodies as f;
        use crate::federation::types::{
            cohort_scope, AnnouncedOwnerState, ServePage, ServedAttestation,
        };
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        let (ids, owner, node) = rt.block_on(async {
            let (a, k) = f::attester(dir.as_ref(), "cap").await;
            let mut ids = Vec::new();
            for i in 0..3 {
                // v62.0.0 (E0 fix 2) — a registered family (`i1578:` is
                // open vocabulary, refused at the edition-2 door).
                // v62.0.0 (FS-sig-a) — `need:` (the serve feeds' own fixture
                // family), not `watchlist:`, whose rows now count only from
                // a group's `moderate` / `takedown` holder.
                ids.push(f::put_dim(dir.as_ref(), &a, &k, &format!("need:i1578n{i}:x:v1")).await);
            }
            let (owner, node) = f::owner_and_node(dir.as_ref(), "cap1578").await;
            f::bind(dir.as_ref(), &owner, &node, cohort_scope::FEDERATION).await;
            (ids, owner, node)
        });
        let dims = vec!["need:".to_owned()];
        let direct = rt
            .block_on(dir.list_attestations_since_by_prefixes(None, &dims, 2))
            .expect("direct");
        let op = |since| DirectoryOp::ListAttestationsSinceByPrefixes {
            since,
            family_prefixes: dims.clone(),
            limit: 2,
        };
        let first = match run_op(&rt, &directory, &op(None)) {
            DirectoryOpResult::ServedAttestationPage(p) => p,
            other => panic!("I1578: expected ServedAttestationPage, got {other:?}"),
        };
        let page_ids = |p: &ServePage<ServedAttestation>| -> Vec<String> {
            p.items
                .iter()
                .map(|r| r.attestation.attestation_id.clone())
                .collect()
        };
        assert_eq!(
            (page_ids(&first), &first.next_cursor, &first.high_water),
            (page_ids(&direct), &direct.next_cursor, &direct.high_water),
            "I1578: the same page through the capsule"
        );
        assert_eq!(page_ids(&first), ids[..2].to_vec(), "I1578: serve order");
        let cursor = first
            .next_cursor
            .clone()
            .expect("I1578: more past the page");
        match run_op(&rt, &directory, &op(Some(cursor))) {
            DirectoryOpResult::ServedAttestationPage(p) => {
                assert_eq!(page_ids(&p), ids[2..].to_vec(), "I1578: the last page");
                assert!(p.next_cursor.is_none(), "I1578: nothing past");
                assert!(!p.high_water.is_origin(), "I1578: a high water");
            }
            other => panic!("I1578: expected ServedAttestationPage, got {other:?}"),
        }
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListAttestationsSinceByPrefixes {
                since: None,
                family_prefixes: Vec::new(),
                limit: 2,
            },
        ) {
            DirectoryOpResult::Err(e) => assert!(
                e.contains(crate::federation::read_plan::SERVE_PREFIXES_REFUSED),
                "I1578: the refusal's token crosses the capsule: {e}"
            ),
            other => panic!("I1578: no prefix is refused through the capsule, got {other:?}"),
        }

        let direct = rt
            .block_on(dir.list_owner_bindings_since(None, 100))
            .expect("direct feed");
        let through = match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListOwnerBindingsSince {
                since: None,
                limit: 100,
            },
        ) {
            DirectoryOpResult::OwnerBindingPage(p) => p,
            other => panic!("I1578: expected OwnerBindingPage, got {other:?}"),
        };
        assert_eq!(
            through, direct,
            "I1578: the same feed page through the capsule"
        );
        // v62.0.0 (round 3, E7) — the feed names keys by identity-ref
        // (`owner_and_node` returns the seeds it registered).
        let (owner, node) = (
            crate::federation::edition2::fixture_switch::kid(&owner),
            crate::federation::edition2::fixture_switch::kid(&node),
        );
        assert!(
            through.items.iter().any(|c| c.node_key_id == node
                && c.state
                    == AnnouncedOwnerState::Announced {
                        owner_key_id: owner.clone()
                    }),
            "I1578: the announced node crosses with its owner: {through:?}"
        );
        // v61.1.0 (#1163 review M5, D19) — the feed's page is at most 500,
        // and the refusal's token crosses the capsule.
        for limit in [0, 501] {
            match run_op(
                &rt,
                &directory,
                &DirectoryOp::ListOwnerBindingsSince { since: None, limit },
            ) {
                DirectoryOpResult::Err(e) => assert!(
                    e.contains(crate::federation::read_plan::SERVE_LIMIT_OUT_OF_RANGE),
                    "I1578: a page of {limit} is refused with its token: {e}"
                ),
                other => {
                    panic!("I1578: a page of {limit} is refused through the capsule, got {other:?}")
                }
            }
        }
    }

    /// v17.4.0 — the `scores` read ops (ListScores + ResolveScores) round-trip
    /// through the full C-ABI: serialize op → dispatch inside the `.so` →
    /// result variant back across the seam. Proves the composite-op wiring
    /// (op variant, dispatch arm, result variant) end-to-end; the fold logic
    /// itself is covered by the backend + `federation::scores` unit tests.
    #[test]
    fn scores_ops_round_trip_through_capsule() {
        let rt = test_runtime();
        let (_dir, directory) = test_directory();
        let filter = crate::read::AttestationFilter {
            subject_key_id: Some("subj".into()),
            ..Default::default()
        };
        // ListScores → empty page (no rows seeded), correct variant.
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListScores {
                caller_occurrence_key_id: String::new(),
                filter: filter.clone(),
                cursor: None,
                limit: 100,
            },
        ) {
            DirectoryOpResult::Scores(page) => {
                assert!(page.items.is_empty());
                assert!(page.next_cursor.is_none());
            }
            other => panic!("expected Scores, got {other:?}"),
        }
        // ResolveScores → InsufficientWitnesses verdict, correct variant.
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ResolveScores {
                caller_occurrence_key_id: String::new(),
                filter,
                policy: "cc-4.4.2-signed-mean".into(),
                trace: true,
            },
        ) {
            DirectoryOpResult::ComposedVerdict(v) => {
                assert_eq!(v.contributor_count, 0);
                assert_eq!(v.band, crate::read::ConfidenceBand::InsufficientWitnesses);
                assert_eq!(v.policy_applied, "cc-4.4.2-signed-mean");
            }
            other => panic!("expected ComposedVerdict, got {other:?}"),
        }
    }

    /// v31.1.0 (CIRISPersist#655/#662, PR #667 review P1) — **both exclusion
    /// planes cross the capsule ABI.**
    ///
    /// The capsule is a real door, and #652 was found by counting doors. Before
    /// this cut the proxy could neither read a revocation back
    /// (`revocations_for` was a hard `Unsupported`) nor apply accord evidence
    /// — so a capsule-backed host could WRITE an exclusion and never read it,
    /// and could SERVE evidence and never rebuild from it. Both are round-
    /// tripped here through the real C-ABI, not through a direct trait call.
    #[test]
    fn exclusion_planes_route_through_the_capsule_655_662() {
        let rt = test_runtime();
        let (_dir, directory) = test_directory();

        // `revocations_for` — routed, and an unknown subject is an empty
        // answer, not `Unsupported`. (An `Unsupported` here read as "this host
        // has no exclusions", which is the wrong direction of failure.)
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::RevocationsFor {
                revoked_key_id: "nobody".into(),
            },
        ) {
            DirectoryOpResult::Revocations(v) => assert!(v.is_empty()),
            other => panic!("expected Revocations, got {other:?}"),
        }

        // v62.0.0 (JSON cut, E7) — the accord evidence arms (the serve
        // cursor and `ApplyReplicatedAccordEvidence`) are deleted: the
        // accord's proposal, participation and decision are gone (RULINGS,
        // genesis bundle/2); a roster change is a later bundle.
    }

    /// v32.0.0 (CIRISPersist#682) — bumped 1 → 2 because
    /// `ListSignedKeyRecordsSince` changed SHAPE in place (bare instant →
    /// `(admitted_at, key_id)` pair; `SignedKeyRecord` → `ServedKeyRecord`).
    /// v36.0.0 (CIRISPersist#675) — bumped 2 → 3 because
    /// `AccordEvidenceAdmitted`'s payload struct replaced
    /// `participations_admitted` (which an older consumer deserializes as a
    /// required field) with the `effect` enum; see the
    /// [`DIRECTORY_ABI_VERSION`] doc.
    /// v38.0.0 (CIRISPersist#721) — bumped 3 → 4: `RemovePeerRecord` gained
    /// `reason` + `acting_under_delegation_id` (serde-default, so an old
    /// consumer's payload still DECODES and then refuses with the typed
    /// reason-required error — but the contract the consumer was built
    /// against changed, and the load-time gate must say so).
    ///
    /// The pin is deliberately two assertions on two different things: the
    /// constant consumers compile against, and the value this build actually
    /// puts in the vtable a consumer reads at runtime. A single assertion
    /// comparing them to each other would hold trivially while both drifted.
    #[test]
    fn abi_version_pinned_at_14() {
        assert_eq!(
            DIRECTORY_ABI_VERSION, 14,
            "v62.0.0 (CC 2.7): the result wire gained TypedErr, and an existing op's failure \
             now answers it (the error's kind and wait cross the capsule) — a consumer built \
             against 13 fails to decode it on the hot path. Previous move: \
             v61.3.0 (CIRISPersist#1252): ReplicatedAttestationOutcome gained HeldEquivalent \
             (the same act held under another row) — a consumer built against 12 fails to \
             decode it on the hot path. Previous move: \
             v61 (CIRISPersist#991): the six group kinds retired — the signed group cursors \
             and ApplyReplicatedCommunity and their results are removed from the op and result \
             wire; the rows ride ApplyReplicatedAttestation, so a consumer built against 11 \
             sends ops this host no longer decodes; AttestationRefusalReason gains \
             GroupPlaneRefused. Previous move: \
             v60.0.0 (CIRISPersist#1036): the operational kinds retired — ListOrgMembershipsSince \
             / ListOrganizationsSince and their results are removed from the op and result \
             wire, so a consumer built against 10 sends ops this host no longer decodes. \
             Previous move: v59.0.0 (CIRISPersist#1064): AttestationRefusalReason gained SelfRosterPending \
             inside ReplicatedAttestationOutcome — a consumer built against 9 fails to decode \
             it. Previous move: v59.0.0 (sealed-transport floor, operator ruling 2026-10-19): the framed \
             key-plane listings are removed from the op and result wire and \
             PutIdentityOccurrenceRevocation's payload is retyped — a consumer built against \
             8 sends ops this host no longer decodes. Previous move: \
             v58.0.0 (CIRISPersist#991): AttestationRefusalReason, inside the existing \
             ReplicatedAttestationOutcome result, gained KeyPlaneRefused — a consumer built \
             against 7 fails to decode it on the hot path (the v6 payload-type form). The \
             framed key-plane ops the slice first removed are restored with their v7 names \
             and shapes (compat reads, operator ruling 2026-10-18), so the op SET is v7's: \
             against 8 that is growth, which does not bump. Previous move: \
             v52.0.0 (CIRISPersist#784): the Revocation carried by Revocations / \
             SignedRevocations names its subject by revoked_key_sha256_ed25519_raw and its \
             revoked_key_id became optional — a consumer built against 6 fails to decode a \
             digest-only row. Previous move: \
             v50.0.0 (CIRISPersist#928): ReachabilityVerdict, the payload of the \
             existing Reachability result, gained BeyondDepthCap — a consumer built \
             against 5 fails to decode it on the hot path. Previous move: the RESULT \
             wire gained a variant in v38.5.0 \
             (DirectoryOpResult::AttestationOutcome, CIRISPersist#771): a \
             consumer built against 4 decodes `Unit` for put_attestation and \
             would fail to decode the new variant, so the load-time gate must \
             say so. Previous move: v38.0.0, an existing DirectoryOp shape \
             change (RemovePeerRecord, #721); the load-time gate is the only \
             signal a consumer gets BEFORE it dispatches an op, so a shape \
             break must \
             move this or the gate certifies a contract the consumer was not \
             built for"
        );
        assert_eq!(
            PERSIST_DIRECTORY_VTABLE.abi_version, 14,
            "the shipped vtable must advertise what consumers pin against"
        );
    }

    /// Structural digest of one `pub enum NAME { … }` body from this file's own
    /// source: doc comments and blank lines dropped, whitespace collapsed,
    /// **attributes kept** (a `#[serde(rename)]` moves the wire name, so it is
    /// contract, not decoration).
    ///
    /// Deliberately blind to prose so that documenting a variant never costs a
    /// re-pin — a gate that cries wolf on comment edits gets its digest bumped
    /// reflexively, which is the same as not having it.
    fn structural_digest(enum_name: &str) -> String {
        let src = include_str!("directory_capsule.rs");
        let open = format!("pub enum {enum_name} {{");
        let mut lines = src.lines().skip_while(|l| !l.starts_with(&open));
        assert!(
            lines.next().is_some(),
            "`{open}` not found — the gate's own recognizer broke, which would \
             otherwise digest an EMPTY body and pass forever"
        );

        let mut body = Vec::new();
        for line in lines {
            if line == "}" {
                assert!(
                    !body.is_empty(),
                    "empty enum body for {enum_name} — recognizer failure"
                );
                return format!(
                    "{:x}",
                    <sha2::Sha256 as sha2::Digest>::digest(body.join("\n").as_bytes())
                );
            }
            let t = line.trim();
            if t.is_empty() || t.starts_with("///") {
                continue;
            }
            body.push(t.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        panic!("unterminated enum body for {enum_name}");
    }

    /// v32.0.0 (CIRISPersist#682) — **the append-only rule, enforced.**
    ///
    /// [`DirectoryOp`] and [`DirectoryOpResult`] are the wire contract between a
    /// persist wheel and consumers built against an older persist. The rule —
    /// append at the end, never change an existing variant's field set or types
    /// — lived only in a doc comment, and in v32.0.0 it was violated twice in
    /// one change (`ListSignedKeyRecordsSince.since` gained a tuple;
    /// `SignedKeyRecords` swapped its payload type) with
    /// [`DIRECTORY_ABI_VERSION`] left at 1. A consumer would have passed the
    /// load-time gate and then failed on the hot path with an opaque serde
    /// error.
    ///
    /// This pins the SHAPE so the next such edit cannot be silent. A red here
    /// is not "fix the digest" — it is a fork:
    ///
    /// * **Growth** (a new variant appended, nothing existing touched):
    ///   re-pin the digest, leave [`DIRECTORY_ABI_VERSION`] alone.
    /// * **Break** (an existing variant's fields or types changed, or a variant
    ///   renamed/removed/reordered): re-pin the digest **and** bump
    ///   [`DIRECTORY_ABI_VERSION`], or older consumers get that opaque error
    ///   instead of "pin floor too low".
    #[test]
    fn directory_op_wire_contract_is_pinned_682() {
        // v59.0.0 (sealed-transport floor) — a BREAK: the framed key-plane
        // ops are removed and `PutIdentityOccurrenceRevocation` retyped;
        // DIRECTORY_ABI_VERSION 8 → 9.
        // v60.0.0 (CIRISPersist#1105) — GROWTH: `ListKeyPlaneWireHashesSince`
        // APPENDED, nothing existing touched; DIRECTORY_ABI_VERSION stays.
        // v60.0.0 (CIRISPersist#1036) — a BREAK: `ListOrgMembershipsSince` and
        // `ListOrganizationsSince` removed; DIRECTORY_ABI_VERSION 10 → 11.
        // v59.1.2 (CIRISPersist#1162), merged forward — GROWTH:
        // `ExecuteAttestationQuery`, `ListComposersReferencingAny`,
        // `ListIdentityOccurrenceHistoryByOccurrence` and
        // `ListIdentityOccurrencesByOccurrenceKey` APPENDED; v61's ABI is 12
        // for #991's removals, not for this.
        // v61 (CIRISPersist#991) — `ListSignedCommunityMembershipListingsSince`
        // removed with the member listing (a BREAK, inside ABI 12).
        // v61.1.0 (CIRISPersist#1190, #1163) — GROWTH:
        // `ListAttestationsSinceByPrefixes` and `ListOwnerBindingsSince`
        // APPENDED.
        // v61.4.0 (CIRISPersist#1227, #1244) — GROWTH: `ListKeysByIdentityType`,
        // the two `*Unfolded` transport reads, the five `Blackhole*` ops and
        // `PutEdgeDetectionEvent` APPENDED, nothing existing touched;
        // DIRECTORY_ABI_VERSION stays 13.
        // v61.4.0 round 2 (CIRISPersist#1244) — GROWTH: the rooting reads and
        // the fail-open trust reads APPENDED (29 ops); ABI stays 13.
        // v62.0.0 (JSON-cut slice D) — GROWTH: `PutEdition2Statement`,
        // `ApplyReplicatedStatement`, `Edition2StatementsSince` and
        // `BundlesInForce` APPENDED, nothing existing touched; ABI stays 13.
        // v61.4.2 (merged forward) — GROWTH:
        // `ListCommunityMembership{Revocations,Widenings}For` APPENDED (the
        // community mirror of the family pair); ABI stays 14.
        // v61.4.2 (the capsule stub sweep, merged forward) — GROWTH: 30 ops
        // APPENDED, one per method the proxy answered `Unsupported`; ABI
        // stays 14.
        // v62.0.0 (round 3, L1) — GROWTH: `ListSettledEdition2RosterProposals`
        // APPENDED (the edition-2 rooting view); ABI stays 14.
        // v62.0.0 (round 3, O1 fix 5) — GROWTH: `Edition2RosterProposal`
        // APPENDED (one receipt of that view); ABI stays 14.
        // v62.0.0 (v62 P8-fix4 + P8-fix5, one pass) — GROWTH: `HeldRowsFor`,
        // `VoiceStatus`, `SubmitVoice` APPENDED (fix4's unshipped
        // `HeldDelegationsFor` became `HeldRowsFor` before any release); ABI
        // stays 14.
        // v62.0.0 (ceremony gap 4) — GROWTH: `PutGenesisBundle` APPENDED (the
        // genesis import door); ABI stays 14.
        // v62.0.0 (ceremony gap 2, C3) — GROWTH: `RebindHeldFor` APPENDED;
        // ABI stays 14.
        // v62.0.0 (L1-fix3) — re-pinned over the merged order: P8-fix5's
        // three, then C1's `PutGenesisBundle`, then C3's `RebindHeldFor`.
        // GROWTH; ABI stays 14.
        // v62.0.0 (X2 pass 4c) — re-pinned over the integrated order: L1's
        // `ListSettledEdition2RosterProposals`, O1 fix 5's
        // `Edition2RosterProposal`, then the five above. GROWTH; ABI stays 14.
        // v62.0.0 (F0-cp5) — GROWTH: `VerifyCompositeViaDirectory` APPENDED;
        // `VerifyHybridViaDirectory` keeps its fields (its arm now refuses);
        // ABI stays 14. (X2 pass 4d: re-pinned over the integrated order.)
        // v62.0.0 (AU-fix2) — GROWTH: `AdmissionUnitRows` and
        // `AdmissionUnitRunnable` APPENDED after PX-fix1's reads; ABI stays
        // 14 (the pin is 4g-regen's, on the merged file).
        // v62.0.0 (PX-fix1) — GROWTH: the 13 edition-2 and fold store reads
        // (`Edition2StatementsAbout` … `FoldAnyRefolding`), then the node-local
        // touch (`PutTouchClaimLocal`, `FreshnessFloor`) APPENDED after
        // `VerifyCompositeViaDirectory`; ABI stays 14.
        // v62.0.0 (PX-fix3) — GROWTH: `ListGroupTips` APPENDED; ABI stays 14. (Another wave that
        // appends ops re-pins over the MERGED order: the python port is
        // FSD/v62_wip/parallel/tools/structural_digest.py.)
        // v62.0.0 (PR-fix1) — GROWTH: `PeerRooting` APPENDED (the peer
        // verdict, CC 3.2 T8); ABI stays 14. Merged with another wave that
        // appends ops (PX-fix1, AU-fix2): recompute on the merged file.
        // v62.0.0 (RL-fix1) — GROWTH: `ApplyReplicatedStatementAtFeed`,
        // `AccordRescanNeeded`, `AckAccordRescan` APPENDED; ABI stays 14
        // (re-pinned with the python port of `structural_digest`).
        // v62.0.0 (RL-fix3) — GROWTH: the contact path's six ops APPENDED.
        // v62.0.0 (4g-regen) — re-pinned over the MERGED 4g order (PR-fix1,
        // AU-fix2, PX-fix2, RL-fix2, RL-fix3, PX-fix3, K2-fix20 after 4f's
        // PX-fix1). GROWTH; ABI stays 14.
        // v62.0.0 (4h-regen) — re-pinned over 4h: RL-fix2c's `ServeStanding`
        // appended (and TR-fix2's changes). ABI stays 14 (ruled).
        // v62.0.0 (4i-regen) — re-pinned over 4i: VA-quorum's local accord
        // types (three type-path texts; the wire is identical). ABI stays 14.
        // v62.0.0 (HALT-235) — `SetActiveHalt` gains `latch_json` under
        // `#[serde(default)]`: an existing variant's field set changed, but
        // the wire stays compatible both ways (an older consumer's two-field
        // op decodes; the op enum has no `deny_unknown_fields`, so an older
        // persist ignores the field). ABI stays 14 pending the lead's ruling
        // (HALT-235.md).
        assert_eq!(
            structural_digest("DirectoryOp"),
            "385a88dbbad9a1de7fe9af64bd286fa47c394ca9585b34b704a11b484bac13ba",
            "DirectoryOp's wire shape changed. GROWTH (appended a variant, \
             touched nothing existing) → re-pin this digest only. BREAK \
             (changed/renamed/removed/reordered an existing variant) → re-pin \
             AND bump DIRECTORY_ABI_VERSION; see its doc for why the load-time \
             gate is the only signal a consumer gets before dispatching."
        );
    }

    /// Companion to [`directory_op_wire_contract_is_pinned_682`] for the result
    /// half. Pinned separately so a red names which side of the call moved —
    /// a consumer can be forward-compatible on ops and not on results.
    ///
    /// Re-pinned again in CIRISPersist#785 — GROWTH on both halves: five ops
    /// and four result variants APPENDED, nothing existing renamed, reordered
    /// or retyped. So both digests move and [`DIRECTORY_ABI_VERSION`] stays
    /// put, which is the fork this gate's doc prescribes. A consumer built
    /// against the older shape keeps working: it never sends the new ops and
    /// never receives the new results.
    ///
    /// Re-pinned in v36.0.0 for two changes riding one release: GROWTH
    /// (`AccordEvidenceCarrierRefused` appended, CIRISPersist#674) and the
    /// serve-cursor BREAK (the `list_*_since` cursor pairs). The release
    /// ALSO breaks an existing variant's payload OUTSIDE this digest's sight
    /// — `AccordEvidenceAdmitted`'s struct replaced a field
    /// (CIRISPersist#675) — which is why [`DIRECTORY_ABI_VERSION`] moved to
    /// 3: this gate reads the enum body only, so a payload-type's own shape
    /// is the version pin's job, not the digest's. All v36 breaks share the
    /// one 2 → 3 bump.
    ///
    /// Re-pinned in v50.0.0 (CIRISPersist#917) — GROWTH on both halves: the
    /// `ApplyReplicatedAttestation` and `ApplyReplicatedAttestationSynced` ops
    /// and the `ReplicatedAttestationOutcome` result APPENDED, nothing
    /// existing touched. [`DIRECTORY_ABI_VERSION`] stays 5.
    ///
    /// Re-pinned again in v50.0.0 (CIRISPersist#931) — GROWTH on both halves:
    /// the `ApplyReplicatedCommunity` and `WithdrawsAdmissionDepth` ops and the
    /// `ReplicatedCommunityOutcome` and `WithdrawsAdmissionDepth` results
    /// APPENDED. The version is 6 for #928's payload change
    /// (`ReachabilityVerdict::BeyondDepthCap`), not for this.
    #[test]
    fn directory_op_result_wire_contract_is_pinned_682() {
        // v59.0.0 (sealed-transport floor) — the four framed key-plane
        // results removed (a BREAK, with the op gate's bump to 9).
        // v60.0.0 (CIRISPersist#1036) — `OrgMemberships` / `Organizations`
        // removed (a BREAK, with the op gate's bump to 11).
        // v61 (CIRISPersist#991) — the six signed group results and
        // `ReplicatedCommunityOutcome` removed (a BREAK, with the op gate's
        // bump to 12).
        // v59.1.2 (CIRISPersist#1162), merged forward — GROWTH:
        // `AttestationQueryRows`, `AttestationRows`, `OccurrenceHistory` and
        // `IdentityOccurrences` APPENDED.
        // v61 (CIRISPersist#991) — `SignedCommunityMembershipListings` removed
        // with the member listing (a BREAK, inside ABI 12).
        // v61.1.0 (CIRISPersist#1190, #1163) — GROWTH:
        // `ServedAttestationPage` and `OwnerBindingPage` APPENDED.
        // v61.4.0 (CIRISPersist#1244) — GROWTH: `BlackholeRecords` APPENDED.
        // v61.4.0 round 2 (CIRISPersist#1244) — GROWTH: 21 result variants
        // APPENDED for the rooting and trust reads.
        // v62.0.0 (JSON-cut slice D) — GROWTH: `Edition2StatementOutcome`,
        // `ReplicatedStatementOutcome`, `Edition2StatementPage` and
        // `BundlesInForce` APPENDED.
        // v62.0.0 (CC 2.7) — `TypedErr` APPENDED; an existing op now answers
        // it, so DIRECTORY_ABI_VERSION 13 → 14 (the AttestationOutcome form).
        // v61.4.2 (merged forward) — GROWTH:
        // `CommunityMembership{Revocations,Widenings}` APPENDED after
        // `TypedErr`; ABI stays 14.
        // v61.4.2 (the capsule stub sweep, merged forward) — GROWTH: 10
        // result variants APPENDED.
        // v62.0.0 (v62 P8-fix5) — GROWTH: `HeldRows`, `VoiceOutcome`
        // APPENDED (fix4's unshipped `HeldDelegations` became `HeldRows`).
        // v62.0.0 (ceremony gap 4) — GROWTH: `GenesisAdmission` APPENDED;
        // ABI stays 14.
        // v62.0.0 (ceremony gap 2, C3) — GROWTH: `RebindHeld` APPENDED.
        // v62.0.0 (L1-fix3) — re-pinned over the merged order: `HeldRows`,
        // `VoiceOutcome`, `GenesisAdmission`, `RebindHeld`. GROWTH.
        // v62.0.0 (PR-fix1) — GROWTH: `PeerRooting` APPENDED; ABI stays 14.
        // Recompute on a merge with another op-appending wave.
        // v62.0.0 (AU-fix2) — GROWTH: `AdmissionUnitRows` and
        // `AdmissionUnitAnswer` APPENDED; ABI stays 14 (pinned by 4g-regen).
        assert_eq!(
            // v62.0.0 (F0-cp5) — GROWTH: `CompositeVerify` APPENDED.
            // v62.0.0 (PX-fix1) — GROWTH: `Edition2Statements`,
            // `Edition2RowIds`, `Edition2StatementIds`, `FoldHeldReason`,
            // `FoldHeldReasons`, `FoldStateOf`, `TouchApplied`,
            // `FreshnessFloorOf` APPENDED; ABI stays 14.
            // v62.0.0 (PX-fix3) — GROWTH: `GroupTips` APPENDED.
            // v62.0.0 (4g-regen) — re-pinned over the merged 4g order.
            structural_digest("DirectoryOpResult"),
            "96480819e93fca49e71e71a041d8a87f012ef8f1cea199ecd85c421ce7b10ec6",
            "DirectoryOpResult's wire shape changed — same fork as the op gate: \
             growth re-pins, a break re-pins AND bumps DIRECTORY_ABI_VERSION."
        );
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

    /// CIRISPersist#785 — the known-hash surface ROUND-TRIPS ACROSS THE
    /// CAPSULE, and the two hash sets keep distinct wire shapes doing it.
    ///
    /// Without this, the ops are five appended enum variants nothing proves
    /// are wired: the dispatch arm could return the wrong result variant and
    /// only a consumer on the far side of the ABI would ever find out. That is
    /// the same gap the trait-default methods had — reachable-looking code
    /// that answers `Unsupported` in the one configuration that matters.
    ///
    /// `list_wire_hashes_since` is exercised here too. It shipped in #780
    /// (v38.7.0) with a default body and NO op, so a capsule consumer got
    /// `Unsupported` for the very read that release existed to provide, while
    /// its two neighbours routed fine.
    /// v60.0.0 (CIRISPersist#1105, I1201 across the capsule) — the
    /// family-scoped holdings read routes: the op answers exactly what the
    /// directory answers, and a non-key-plane family is refused (as text,
    /// like every op), never answered as an empty set.
    #[test]
    fn i1201_key_plane_holdings_route_through_the_capsule() {
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        // v62.0.0 (round 3, E7; rule 4) — the fixture's two key rows are
        // gone: the holdings read walks key records mirrored as ATTESTATION
        // rows (`key:record:v1` in the attestation index), the earlier-form
        // key plane. An edition-2 `key:record` is a statement and never such
        // a row (attestation_apply's I1201 was deleted for the same reason).
        // What stays is the routing: the op answers exactly what the
        // directory answers, and a non-key-plane family is refused.
        let direct = rt
            .block_on(dir.list_key_plane_wire_hashes_since("key:record:v1", None, 100))
            .expect("the direct read");
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListKeyPlaneWireHashesSince {
                family: "key:record:v1".into(),
                after_content_hash: None,
                limit: 100,
            },
        ) {
            DirectoryOpResult::WireHashes(v) => assert_eq!(v, direct, "I1201: routed as is"),
            other => panic!("I1201: {other:?}"),
        }
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListKeyPlaneWireHashesSince {
                family: "consent:replication:v1".into(),
                after_content_hash: None,
                limit: 100,
            },
        ) {
            DirectoryOpResult::Err(m) => assert!(m.contains("not a key-plane family"), "{m}"),
            other => panic!("I1201: a non-key-plane family is refused: {other:?}"),
        }
    }

    #[test]
    fn known_hash_ops_round_trip_through_the_capsule_785() {
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        let hash = crate::federation::wire_index::content_hash_of_bytes(b"capsule-785");
        let now = chrono::DateTime::parse_from_rfc3339("2027-05-06T07:08:09Z")
            .expect("literal is valid RFC-3339")
            .with_timezone(&chrono::Utc);

        // Insert → Unit.
        assert!(
            matches!(
                run_op(
                    &rt,
                    &directory,
                    &DirectoryOp::InsertKnownWireHash {
                        kind: "Attestation".into(),
                        content_hash: hash.clone(),
                        advertised_by: Some("peer-1".into()),
                        now,
                    },
                ),
                DirectoryOpResult::Unit
            ),
            "#785: InsertKnownWireHash must route across the capsule"
        );

        // Contains → Bool(true).
        assert!(
            matches!(
                run_op(
                    &rt,
                    &directory,
                    &DirectoryOp::KnownWireHashContains {
                        kind: "Attestation".into(),
                        content_hash: hash.clone(),
                    },
                ),
                DirectoryOpResult::Bool(true)
            ),
            "#785: KnownWireHashContains must route and answer for what was \
             written through the capsule"
        );

        // The KNOWN page carries the record, with its local-only advertiser.
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListKnownWireHashesSince {
                kind: "Attestation".into(),
                after_content_hash: None,
                limit: u32::MAX,
            },
        ) {
            DirectoryOpResult::KnownWireHashes(rows) => {
                let got = rows
                    .iter()
                    .find(|r| r.content_hash == hash)
                    .expect("#785: the inserted hash must page back");
                assert_eq!(got.advertised_by.as_deref(), Some("peer-1"));
                assert_eq!(got.last_advertised_at, now);
            }
            other => panic!("#785: expected KnownWireHashes, got {other:?}"),
        }

        // …and the HELD read is a DIFFERENT wire variant that does not carry
        // it. One shared shape here would let a swapped dispatch arm
        // type-check, which is the union this plane exists to prevent —
        // expressed at the ABI rather than only in the backend.
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListWireHashesSince {
                kind: "Attestation".into(),
                after_content_hash: None,
                limit: u32::MAX,
            },
        ) {
            DirectoryOpResult::WireHashes(held) => assert!(
                !held.contains(&hash),
                "#785: a KNOWN-only hash reached the HELD read across the \
                 capsule — `want = remote ∖ holdings` would drop it and the \
                 node would stop fetching, silently"
            ),
            other => panic!("#785: expected WireHashes, got {other:?}"),
        }

        // Evict with a cutoff BELOW the entry keeps it, and reports the bound.
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::EvictKnownWireHashes {
                cutoff: now - chrono::Duration::hours(1),
                bound: 0,
            },
        ) {
            DirectoryOpResult::KnownHashEviction(rep) => {
                assert_eq!(rep.evicted, 0, "#785: nothing is older than the cutoff");
                assert!(
                    rep.over_bound_by >= 1,
                    "#785: the floor wins over the bound, and the overage is \
                     REPORTED rather than resolved by evicting below it"
                );
            }
            other => panic!("#785: expected KnownHashEviction, got {other:?}"),
        }
        drop(dir);
    }

    #[test]
    fn put_then_lookup_public_key_round_trips() {
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        // v62.0.0 (JSON cut, E7) — the key is an edition-2 `key:record` put on
        // the backend (the capsule's JSON `PutPublicKey` door is shut); the
        // capsule's `LookupPublicKey` is what this round-trips.
        let key_id = rt.block_on(crate::federation::edition2::fixture_switch::put_key(
            dir.as_ref(),
            "primitive-abc",
            &[crate::federation::types::identity_type::PRIMITIVE],
        ));

        // LookupPublicKey via the capsule → PublicKey(Some(..)).
        let looked = run_op(
            &rt,
            &directory,
            &DirectoryOp::LookupPublicKey {
                key_id: key_id.clone(),
            },
        );
        let via_capsule = match looked {
            DirectoryOpResult::PublicKey(v) => v,
            other => panic!("expected PublicKey, got {other:?}"),
        };

        // Assert it matches calling the method directly on the backend.
        let via_direct = rt
            .block_on(dir.lookup_public_key(&key_id))
            .expect("direct lookup");
        assert_eq!(
            via_capsule, via_direct,
            "capsule result must equal direct call"
        );
        assert_eq!(via_capsule.expect("some").key_id, key_id);

        // Keep `directory.data` owned by us; drop it through the vtable.
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    /// v59.0.0 (sealed-transport floor, operator ruling 2026-10-19) —
    /// **I1146: the capsule's framed inbound key-plane ops are retired.**
    /// `ApplyReplicatedKeyRecord` (the #375 upgrade path a pre-v59 Edge
    /// drove) and `PutIdentityOccurrenceRevocation` answer the typed refusal
    /// naming the kind, and store nothing; a key arrives as its
    /// `key:record:v1` row through `ApplyReplicatedAttestation`.
    #[cfg(feature = "sqlite")]
    #[test]
    fn i1146_framed_inbound_ops_are_retired_sqlite() {
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
        // v62.0.0 (JSON cut, E7) — the record is the edition-2 key read model
        // (E0's flipped `replicated_key_record`); its id is the identity-ref.
        let record = ts::replicated_key_record(
            "cap-node",
            identity_type::NODE,
            "cap-node",
            "cap-node",
            "v1",
        );
        let cap_node = record.key_id.clone();
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ApplyReplicatedKeyRecord {
                record: SignedKeyRecord {
                    record: record.clone(),
                },
            },
        ) {
            // v62.0.0 (round 6, CP2) — the doors are shut, so the op is
            // refused by its form before its retired arm runs.
            DirectoryOpResult::Err(e) => assert!(
                e.starts_with("federation_malformed_row: key_record: earlier_form_object: "),
                "I1146: {e}"
            ),
            other => panic!("I1146: the framed key-record op: {other:?}"),
        }
        assert!(
            rt.block_on(dir.lookup_public_key(&cap_node))
                .unwrap()
                .is_none(),
            "I1146: nothing was stored"
        );
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::PutIdentityOccurrenceRevocation {
                revocation: serde_json::json!({ "identity_occurrence_revocation": {} }),
            },
        ) {
            DirectoryOpResult::Err(e) => assert!(
                e.starts_with(
                    "federation_malformed_row: identity_occurrence_revocation: earlier_form_object: "
                ),
                "I1146: {e}"
            ),
            other => panic!("I1146: the framed occurrence-revocation op: {other:?}"),
        }
        // v62.0.0 (JSON cut, E7) — a key arrives as its edition-2 `key:record`
        // statement (the earlier `key:record:v1` attestation row is gone).
        rt.block_on(crate::federation::edition2::fixture_switch::put_key_row(
            dir.as_ref(),
            &record,
        ));
        assert!(rt
            .block_on(dir.lookup_public_key(&cap_node))
            .unwrap()
            .is_some());
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn peer_mutation_ops_round_trip() {
        // CIRISPersist#333 — the 6 peer-mutation ops that edge's
        // `federation_directory_for_edge` invokes. Each must dispatch to
        // the real backend method (NOT the `Backend("… not implemented")`
        // trait default the proxy would otherwise inherit).
        let rt = test_runtime();
        // v57.0.0 (#988 item 2) — the removal's hard_case row needs this
        // node's key.
        let backend: Arc<SqliteBackend> = Arc::new(crate::store::test_backend::test_backend());
        rt.block_on(crate::federation::hard_case::test_support::declare_node(
            &*backend,
            "capsule-node",
        ));
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());

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
                reason: "capsule op test".into(),
                acting_under_delegation_id: None,
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

    /// v62.0.0 (round 6, CP2) — the earlier-form `PutTransportDestination`
    /// op is refused by its plane at the capsule, and stores nothing; the
    /// route listing crosses the ABI intact (every field, #397/#411/#413/
    /// #443) over a route seeded through the directory.
    #[test]
    fn put_then_list_transport_destinations_round_trips() {
        use crate::federation::edition2::fixture_switch as e2;
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        // A node key the route names (the occurrence key is an FK).
        let occ = rt.block_on(e2::put_key(dir.as_ref(), "occ-roundtrip-node", &["node"]));
        let dest = self_at_login::TransportDestination {
            occurrence_key_id: occ.clone(),
            transport_kind: "reticulum".into(),
            destination: "abcd".into(),
            // v61 (CC 2.6.2) — a signed member crosses the ABI `.sssZ`. A
            // node key's window is now-relative, so the route is too.
            asserted_at: crate::federation::admission::truncate_to_substrate_resolution(
                crate::host::clock::now(),
            ),
            last_seen_at: Some(
                crate::federation::admission::truncate_to_substrate_resolution(
                    crate::host::clock::now(),
                ),
            ),
            // #397/#411 — the transport-tier Ed25519 + X25519 (KEX) must cross
            // the ABI intact (prime + re-seal after restart).
            transport_ed25519_pubkey_base64: Some("dHJhbnNwb3J0LWVkMjU1MTk=".into()),
            transport_x25519_pubkey_base64: Some("dHJhbnNwb3J0LXgyNTUxOQ==".into()),
            // #413 — the provenance tag rides the ABI via serde.
            binding_provenance: self_at_login::BindingProvenance::Advisory,
            // #443 — the route-table epoch + tombstone ride the ABI via serde
            // (serde-default ⇒ older consumers' records read epoch 0, live).
            epoch: 7,
            retired_at: None,
        };

        match run_op(
            &rt,
            &directory,
            &DirectoryOp::PutTransportDestination {
                destination: dest.clone(),
            },
        ) {
            DirectoryOpResult::Err(e) => assert!(
                e.starts_with(
                    "federation_malformed_row: transport_destination: earlier_form_object: "
                ),
                "the earlier-form put is refused by its plane: {e}"
            ),
            other => panic!("the earlier-form put is refused, got {other:?}"),
        }
        assert!(
            rt.block_on(dir.list_transport_destinations_for(&occ))
                .expect("direct list")
                .is_empty(),
            "nothing stored behind the refusal"
        );

        rt.block_on(dir.put_transport_destination(&dest))
            .expect("seed the route through the directory");
        let via_direct = rt
            .block_on(dir.list_transport_destinations_for(&occ))
            .expect("direct list");
        assert_eq!(via_direct.len(), 1, "the seed is listed");
        match run_op(
            &rt,
            &directory,
            &DirectoryOp::ListTransportDestinationsFor {
                occurrence_key_id: occ.clone(),
            },
        ) {
            DirectoryOpResult::TransportDestinations(v) => {
                assert_eq!(v, via_direct, "the listing crosses intact")
            }
            other => panic!("capsule list: {other:?}"),
        }

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    /// #443 — the appended signed-route ops cross the ABI: an unauthenticated
    /// container is REFUSED inside the .so (fail-closed, top-level Err — the
    /// confused-deputy write can no longer ride the capsule), and the signed
    /// list round-trips its (empty) result shape.
    #[test]
    fn signed_transport_destination_ops_fail_closed_and_round_trip() {
        let rt = test_runtime();
        let (dir, directory) = test_directory();

        let signed = self_at_login::SignedTransportDestination {
            transport_destination: self_at_login::TransportDestination {
                occurrence_key_id: "occ-1".into(),
                transport_kind: "reticulum".into(),
                destination: "abcd".into(),
                asserted_at: chrono::Utc::now(),
                last_seen_at: None,
                transport_ed25519_pubkey_base64: None,
                transport_x25519_pubkey_base64: None,
                binding_provenance: self_at_login::BindingProvenance::Rooted,
                epoch: 1,
                retired_at: None,
            },
            attesting_key_id: "nobody".into(),
            // No verifiable envelope/signature — the gate must refuse.
            signed_envelope: serde_json::json!({}),
            signature: crate::federation::types::RetiredPairSignature {
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        let put = run_op(
            &rt,
            &directory,
            &DirectoryOp::PutSignedTransportDestination {
                signed: signed.clone(),
            },
        );
        assert!(
            matches!(put, DirectoryOpResult::Err(_)),
            "an unauthenticated signed-route apply must fail closed, got {put:?}"
        );
        // Direct call agrees (same gate, same vtable).
        assert!(rt
            .block_on(dir.put_signed_transport_destination(&signed))
            .is_err());
        // Nothing was written.
        assert!(rt
            .block_on(dir.list_transport_destinations_for("occ-1"))
            .unwrap()
            .is_empty());

        // The signed list op round-trips its result shape (empty here).
        let listed = run_op(
            &rt,
            &directory,
            &DirectoryOp::ListSignedTransportDestinationsFor {
                occurrence_key_id: "occ-1".into(),
            },
        );
        match listed {
            DirectoryOpResult::SignedTransportDestinations(v) => assert!(v.is_empty()),
            other => panic!("expected SignedTransportDestinations, got {other:?}"),
        }

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn reachable_under_scope_no_trust_roots() {
        let rt = test_runtime();
        let (dir, directory) = test_directory();

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

    /// v62.0.0 (F0-cp5) — **I2885 (capsule): the retired bound-hybrid verify
    /// is refused by name and reads nothing; the composite op verifies inside
    /// persist's `.so`** and carries its refusals INSIDE `CompositeVerify`,
    /// byte-identical to the direct call. (The earlier
    /// `verify_hybrid_via_directory` round trip and I1562's policy legs
    /// witnessed the bound-hybrid verify and are deleted.)
    #[test]
    fn i2885_capsule_verify_is_composite_only() {
        use crate::federation::edition2::composite_verify::{
            verify_composite_via_directory, VERIFY_COMPONENT_SIGNATURE,
        };
        use crate::federation::edition2::fixture_switch as e2;
        let rt = test_runtime();
        let (dir, directory) = test_directory();

        match run_op(
            &rt,
            &directory,
            &DirectoryOp::VerifyHybridViaDirectory {
                canonical_bytes: b"canonical".to_vec(),
                signing_key_id: "no-such-key".into(),
                ed25519_sig_b64: "AAAA".into(),
                ml_dsa_65_sig_b64: None,
                policy: crate::verify::hybrid::HybridPolicy::Strict,
                row_age: None,
            },
        ) {
            // `run_op` flattens a typed failure to its text.
            DirectoryOpResult::Err(e) => assert!(
                e.contains("verify_hybrid_via_directory"),
                "I2885: refused by name: {e}"
            ),
            other => panic!("I2885: the retired op is refused, got {other:?}"),
        }

        let seed = "i2885-capsule-signer";
        let who = rt.block_on(e2::put_key(dir.as_ref(), seed, &["user"]));
        let msg = b"F0-cp5 I2885 capsule".to_vec();
        let sig = e2::signing_key(seed).sign(&msg).expect("composite sign");
        let at = e2::ms(crate::host::clock::now());
        let op = |sig: Vec<u8>| DirectoryOp::VerifyCompositeViaDirectory {
            message: msg.clone(),
            identity_ref: who.clone(),
            composite_sig: sig,
            at_ms: at,
        };
        match run_op(&rt, &directory, &op(sig.clone())) {
            DirectoryOpResult::CompositeVerify(Ok(signer)) => {
                assert_eq!(signer, who, "I2885: the live signer");
            }
            other => panic!("I2885: a live key's composite verifies: {other:?}"),
        }
        let half = sig[..64].to_vec();
        let direct = rt
            .block_on(verify_composite_via_directory(
                dir.as_ref(),
                &msg,
                &who,
                &half,
                at,
            ))
            .expect_err("I2885: a lone half is refused directly");
        match run_op(&rt, &directory, &op(half)) {
            DirectoryOpResult::CompositeVerify(Err(r)) => {
                assert_eq!(r.token, VERIFY_COMPONENT_SIGNATURE, "I2885: {r:?}");
                assert!(!r.retryable, "I2885: final");
                assert_eq!(r.detail, direct.to_string(), "I2885: byte-identical");
            }
            other => panic!("I2885: a lone half is refused by name: {other:?}"),
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
        let (dir, directory) = test_directory();

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
                Some(3),
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

    /// PR #921 review (Codex, F4) — `max_depth: 0` through the op: a root
    /// that delegates is past a zero cap (`BeyondCapSelfVerify`, no edges); a
    /// root that delegates nothing is `WithinCap`. The op passes 0 through
    /// (the cap is the caller's explicit choice); it is not rejected.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn build_delegation_graph_op_reports_a_zero_cap() {
        use crate::federation::admission::steward_liveness_test_support::{register, signed_row};
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_type, identity_type as it};
        let rt = test_runtime();
        let (dir, directory) = test_directory();
        rt.block_on(async {
            register(dir.as_ref(), "zc-root", &[it::USER]).await;
            register(dir.as_ref(), "zc-next", &[it::PRIMITIVE]).await;
            register(dir.as_ref(), "zc-lone", &[it::USER]).await;
            let mut row = signed_row(
                "zc-root",
                "zc-next",
                attestation_type::DELEGATES_TO,
                serde_json::json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "scope": ["infra:serve"],
                    "sub_delegation": true
                }),
            );
            ts::reseal(&mut row);
            // v62.0.0 (round 3, E7) — through the one entry (a mapped row is
            // not routed to the statement store by `put_attestation`).
            // v62.0.0 (round 6, CC 2.6.1.9) — a delegation seats only with
            // its second signers' voices (the delegate's): without them it is
            // held `count_short` and the root delegates nothing. Supply them.
            use crate::federation::edition2::fixture_switch as e2;
            let (seeds, unvoiced) = e2::second_signer_voices(dir.as_ref(), &row)
                .await
                .expect("second signers");
            assert!(unvoiced.is_empty(), "zc-root: unvoiced roles {unvoiced:?}");
            let seeds: Vec<&str> = seeds.iter().map(String::as_str).collect();
            let landed = e2::land_with_voices(dir.as_ref(), &row, &seeds)
                .await
                .expect("edge");
            assert!(
                matches!(
                    landed,
                    crate::federation::edition2::ingest::StatementOutcome::Row { .. }
                ),
                "zc-root: the edge lands: {landed:?}"
            );
        });
        for (root, want) in [
            (
                "zc-root",
                crate::federation::DelegationDepthOutcome::BeyondCapSelfVerify,
            ),
            (
                "zc-lone",
                crate::federation::DelegationDepthOutcome::WithinCap,
            ),
        ] {
            match run_op(
                &rt,
                &directory,
                // v62.0.0 (round 3, E7) — the root as the directory keys it
                // (`register` puts `e2::kid(seed)`'s record); a seed names no
                // held key, so it read as a root that delegates nothing.
                &DirectoryOp::BuildDelegationGraph {
                    from_key: crate::federation::edition2::fixture_switch::kid(root),
                    max_depth: 0,
                },
            ) {
                DirectoryOpResult::DelegationGraph(g) => {
                    assert_eq!(g.max_depth, 0, "{root}");
                    assert!(g.edges.is_empty(), "{root}: a zero cap follows nothing");
                    assert_eq!(g.depth_outcome, want, "{root}");
                }
                other => panic!("{root}: expected DelegationGraph, got {other:?}"),
            }
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[test]
    fn backend_error_flattens_to_err_variant() {
        // A backend failure injected on `lookup_shared_instance_lease` (the
        // fault double over the test backend) proves the Err(String)
        // flattening path across the ABI.
        let rt = test_runtime();
        let dir: Arc<dyn FederationDirectory> = Arc::new(
            crate::federation::directory_double::FaultInjectingDirectory::new(Arc::new(
                crate::store::test_backend::test_backend(),
            ))
            .erroring("lookup_shared_instance_lease"),
        );
        let directory = build_persist_directory(dir.clone());

        let res = run_op(
            &rt,
            &directory,
            &DirectoryOp::LookupSharedInstanceLease {
                instance_name: "rns-singleton".into(),
            },
        );
        assert!(
            matches!(res, DirectoryOpResult::Err(_)),
            "a failing backend method ⇒ Err(String), got {res:?}"
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
        let (_dir, directory) = test_directory();

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
        let backend: Arc<SqliteBackend> = Arc::new(crate::store::test_backend::test_backend());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory(directory, executor).expect("abi ok");

        // v62.0.0 (JSON cut, E7) — a key becomes live only as an edition-2
        // `key:record` statement (the JSON `put_public_key` door is shut), so
        // the key is put on the backend and the PROXY's read is what crosses.
        let key_id = rt.block_on(crate::federation::edition2::fixture_switch::put_key(
            dir.as_ref(),
            "primitive-ops",
            &[crate::federation::types::identity_type::PRIMITIVE],
        ));

        let via_proxy = rt
            .block_on(proxy.lookup_public_key(&key_id))
            .expect("proxy lookup_public_key");
        let via_direct = rt
            .block_on(dir.lookup_public_key(&key_id))
            .expect("direct lookup");
        assert_eq!(
            via_proxy, via_direct,
            "proxy result must equal a direct backend call"
        );
        assert_eq!(via_proxy.expect("some").key_id, key_id);
    }

    /// CIRISPersist#785 — the known-hash surface through the **consumer-side
    /// proxy**, which is a different claim from the dispatch round-trip above.
    ///
    /// `run_op` proves the DISPATCH arm exists; the compiler already forced
    /// that, since the match must be exhaustive. It proves nothing about
    /// `OpsDirectory`'s proxy method, and that side has NO compiler backstop:
    /// omit one and the trait default answers `Unsupported`, silently, in
    /// exactly the configuration a downstream consumer runs. That is the same
    /// silent-default class as the directory double, and it is how #780's
    /// `list_wire_hashes_since` shipped unreachable in v38.7.0.
    ///
    /// So every one of the five routed methods is called HERE, through
    /// `build_ops_directory`, and compared against the same call on the bare
    /// backend.
    #[test]
    fn ops_directory_known_hash_methods_route_785() {
        let rt = test_runtime();
        let backend: Arc<SqliteBackend> = Arc::new(crate::store::test_backend::test_backend());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory(directory, executor).expect("abi ok");

        let hash = crate::federation::wire_index::content_hash_of_bytes(b"ops-proxy-785");
        let now = chrono::DateTime::parse_from_rfc3339("2027-05-06T07:08:09Z")
            .expect("literal is valid RFC-3339")
            .with_timezone(&chrono::Utc);

        rt.block_on(proxy.insert_known_wire_hash("Attestation", &hash, Some("peer-1"), now))
            .expect("#785: insert_known_wire_hash must route through the PROXY");

        assert!(
            rt.block_on(proxy.known_wire_hash_contains("Attestation", &hash))
                .expect("#785: known_wire_hash_contains must route through the PROXY"),
            "#785: the proxy must see what it wrote"
        );

        let via_proxy = rt
            .block_on(proxy.list_known_wire_hashes_since("Attestation", None, u32::MAX))
            .expect("#785: list_known_wire_hashes_since must route through the PROXY");
        let via_direct = rt
            .block_on(dir.list_known_wire_hashes_since("Attestation", None, u32::MAX))
            .expect("direct list");
        assert_eq!(
            via_proxy, via_direct,
            "#785: the proxy's known-set page must equal a direct backend call"
        );

        // #780's read, whose whole defect was being unreachable from here.
        let held = rt
            .block_on(proxy.list_wire_hashes_since("Attestation", None, u32::MAX))
            .expect("#785: list_wire_hashes_since must route through the PROXY");
        assert!(
            !held.contains(&hash),
            "#785: a KNOWN-only hash reached the HELD read through the proxy"
        );

        let report = rt
            .block_on(proxy.evict_known_wire_hashes(now - chrono::Duration::hours(1), 0))
            .expect("#785: evict_known_wire_hashes must route through the PROXY");
        assert_eq!(report.evicted, 0, "#785: nothing is older than the cutoff");
        assert!(
            report.over_bound_by >= 1,
            "#785: the floor wins and the overage is reported, across the ABI too"
        );
    }

    #[test]
    fn ops_directory_resolve_encryption_keys_is_revocation_aware() {
        // #329 (CIRISServer#260 field hit) — the exact fleet-breaking
        // scenario, through the proxy: resolve_encryption_keys previously
        // decomposed to the uncovered raw revocations read and surfaced
        // Error::Unsupported the moment the occurrence row existed, so the
        // embedded/pyo3 path could never resolve a peer's KEX pubkeys. Now
        // the composite op routes the WHOLE fold into persist's `.so`:
        // resolves Some before revocation, None after (revocation-aware
        // through the ABI), and the raw revocations read round-trips too.
        let rt = test_runtime();
        let backend: Arc<SqliteBackend> = Arc::new(crate::store::test_backend::test_backend());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory(directory, executor).expect("abi ok");

        let now = chrono::Utc::now();
        // v62.0.0 (JSON cut, E7) — edition-2 keys; the ids below are the
        // identity-refs `e2::put_key` returns.
        let identity = rt.block_on(crate::federation::edition2::fixture_switch::put_key(
            dir.as_ref(),
            "kex-identity",
            &[crate::federation::types::identity_type::USER],
        ));
        // v62.0.0 (round 3, E7) — the person's PHONE: a person's key, class
        // `phone` (P1's person/machine rule, CC 3.3.6: no machine class sits
        // under a person's identity; the earlier `agent` class did).
        let phone = rt.block_on(crate::federation::edition2::fixture_switch::put_key(
            dir.as_ref(),
            "kex-phone",
            &[crate::federation::types::identity_type::USER],
        ));
        rt.block_on(
            dir.test_seam_put_identity_occurrence(crate::federation::IdentityOccurrence {
                identity_key_id: identity.clone(),
                occurrence_key_id: phone.clone(),
                // v62.0.0 (P1-fix4; CC rc21 3.3.6) — a person's phone, not an
                // `agent`-class occurrence (an agent's occurrence binds the
                // agent's own identity).
                device_class: crate::federation::types::device_class::PHONE.into(),
                hardware_attestation: None,
                asserted_at: now - chrono::Duration::hours(1),
                valid_until: None,
                encryption_pubkeys: Some({
                    use base64::engine::general_purpose::STANDARD as B64;
                    use base64::Engine as _;
                    crate::federation::EncryptionPubkeys {
                        x25519_base64: B64.encode([0x11u8; 32]),
                        ml_kem_768_base64: B64.encode(vec![0x22u8; 1184]),
                    }
                }),
                transport_binding: None,
                persist_row_hash: String::new(),
            }),
        )
        .expect("seed occurrence");

        // Pre-revocation: the proxy resolves the KEX keys (was: hard error).
        let resolved = rt
            .block_on(proxy.resolve_encryption_keys(&phone))
            .expect("#329: proxy resolve must not be Unsupported");
        {
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine as _;
            assert_eq!(
                resolved.as_ref().map(|k| k.x25519_base64.clone()),
                Some(B64.encode([0x11u8; 32])),
                "proxy must resolve the occurrence's KEX pubkeys"
            );
        }

        // Revoke → the SAME proxy call fail-secure excludes the occurrence.
        rt.block_on(dir.put_identity_occurrence_revocation_edition2(
            crate::federation::IdentityOccurrenceRevocation {
                identity_key_id: identity.clone(),
                occurrence_key_id: phone.clone(),
                revoked_at: now,
                effective_at: now,
                reason: None,
                witness_set: vec![identity.clone()],
                persist_row_hash: String::new(),
            },
            crate::federation::DoorToken::new(),
        ))
        .expect("seed revocation");
        let resolved = rt
            .block_on(proxy.resolve_encryption_keys(&phone))
            .expect("proxy resolve after revocation");
        assert!(
            resolved.is_none(),
            "a revoked occurrence must resolve to None through the ABI"
        );

        // The raw revocation-plane read routes too, equal to a direct call.
        let via_proxy = rt
            .block_on(proxy.list_identity_occurrence_revocations_for(&identity))
            .expect("#329: raw revocations read must not be Unsupported");
        let via_direct = rt
            .block_on(dir.list_identity_occurrence_revocations_for(&identity))
            .expect("direct revocations read");
        assert_eq!(via_proxy.len(), 1);
        assert_eq!(via_proxy, via_direct, "proxy == direct backend call");
    }

    #[test]
    fn ops_directory_unsupported_method_errors() {
        // A REQUIRED method with no DirectoryOp must surface
        // `Error::Unsupported`, not route garbage.
        let rt = test_runtime();
        let backend: Arc<SqliteBackend> = Arc::new(crate::store::test_backend::test_backend());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir);
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory(directory, executor).expect("abi ok");

        // v61.4.2 — the proxy has no stub of its own left (the capsule stub
        // sweep); a node-local cosign ledger read it inherits from the trait
        // default still answers `Unsupported` (allowlisted, COSIGN_1252).
        let err = rt
            .block_on(proxy.list_open_cosign_receipts())
            .expect_err("list_open_cosign_receipts has no op → Unsupported");
        assert!(
            matches!(
                err,
                Error::Unsupported {
                    method: "list_open_cosign_receipts"
                }
            ),
            "got {err:?}"
        );
        assert_eq!(err.kind(), "federation_ops_proxy_unsupported");
    }

    #[test]
    fn ops_directory_lookup_identity_for_occurrence_routes() {
        // #397 regression — `lookup_identity_for_occurrence` was an
        // `Error::Unsupported` stub, so the agent's embedded edge could not
        // resolve a peer's kex pubkeys and an explicit-hash canonical was
        // unrootable. It must now ROUTE: an unbound key resolves to
        // `Ok(None)` (the real backend answer), NOT the Unsupported error.
        let rt = test_runtime();
        let backend: Arc<SqliteBackend> = Arc::new(crate::store::test_backend::test_backend());
        let dir: Arc<dyn FederationDirectory> = backend;
        let directory = build_persist_directory(dir.clone());
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory(directory, executor).expect("abi ok");

        let via_proxy = rt
            .block_on(proxy.lookup_identity_for_occurrence("not-bound"))
            .expect("routed, not Unsupported");
        let via_direct = rt
            .block_on(dir.lookup_identity_for_occurrence("not-bound"))
            .expect("direct lookup");
        assert_eq!(
            via_proxy, via_direct,
            "proxy result must equal a direct backend call"
        );
        assert!(via_proxy.is_none(), "unbound occurrence resolves to None");
    }

    // ── CIRISPersist#1162 — the typed bounded read crosses the capsule ──

    /// The owner walk's own query (`live_delegation_granter_instants`), run
    /// through the CONSUMER-SIDE proxy over a real backend, against the same
    /// call on the backend directly. Before #1162 the proxy answered
    /// `execute_attestation_query` with `Unsupported`, so every
    /// `AttestationQuery` read on a phone or agent-embedded node — the owner
    /// walk, `owner_of`, a chat reader — was a refusal.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn exercise_attestation_query_through_the_proxy_1162(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        suffix: &str,
    ) {
        use crate::ceg::list::federation::AttestationCursor;
        use crate::federation::attestation_query::{AttestationQuery, AttestationReads, FOLD_PAGE};
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::attestation_type;

        let owner = format!("owner-1162-{suffix}");
        let node = format!("node-1162-{suffix}");
        rt.block_on(async {
            ts::register_user_role_key(dir.as_ref(), &owner).await;
            ts::register_hybrid_key(dir.as_ref(), &node).await;
            ts::put_owner_binding(dir.as_ref(), &owner, &node).await;
        });
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy =
            build_ops_directory(build_persist_directory(dir.clone()), executor).expect("abi ok");

        let walk = AttestationQuery::to(&node, FOLD_PAGE).types(&[attestation_type::DELEGATES_TO]);
        let retractions = AttestationQuery::to(&node, FOLD_PAGE)
            .types(&[attestation_type::WITHDRAWS, attestation_type::RECANTS]);
        for q in [&walk, &retractions] {
            // The storage half: the rows, the decoded bytes AND the backend
            // that ran it survive the capsule.
            let raw_proxy = rt
                .block_on(proxy.execute_attestation_query(q))
                .unwrap_or_else(|e| panic!("#1162 {}: routed, not {e:?}", q.shape()));
            let raw_direct = rt
                .block_on(dir.execute_attestation_query(q))
                .expect("direct execute");
            assert_eq!(raw_proxy.rows, raw_direct.rows, "#1162 {}", q.shape());
            assert_eq!(raw_proxy.bytes, raw_direct.bytes, "#1162 {}", q.shape());
            assert_eq!(raw_proxy.backend, raw_direct.backend, "#1162 {}", q.shape());
            // The read every fold makes.
            let via_proxy = rt
                .block_on(proxy.query_attestations(q))
                .served()
                .unwrap_or_else(|e| panic!("#1162 {}: served, not {e:?}", q.shape()));
            let via_direct = rt
                .block_on(dir.query_attestations(q))
                .served()
                .expect("direct read");
            assert_eq!(via_proxy, via_direct, "#1162 {}", q.shape());
        }
        let page = rt
            .block_on(proxy.query_attestations(&walk))
            .served()
            .expect("served");
        assert_eq!(page.rows.len(), 1, "#1162 the one owner-binding");
        assert_eq!(page.rows[0].attesting_key_id, owner);

        // A cursor crosses too: resuming after the only row is an empty page
        // on both sides, not the same row again.
        let after = walk.clone().after(Some(AttestationCursor::from_trailing(
            page.rows[0].asserted_at,
            page.rows[0].attestation_id.clone(),
        )));
        let resumed = rt
            .block_on(proxy.query_attestations(&after))
            .served()
            .expect("served");
        assert_eq!(
            resumed,
            rt.block_on(dir.query_attestations(&after))
                .served()
                .expect("direct read")
        );
        assert!(resumed.rows.is_empty(), "#1162 the cursor was honoured");

        // And the fold the field log named resolves through the proxy.
        assert_eq!(
            rt.block_on(crate::federation::admission::owner_of(
                proxy.as_ref(),
                &node
            ))
            .expect("#1162 owner_of through the capsule"),
            Some(owner),
        );
    }

    /// CIRISPersist#1162 — sqlite arm.
    #[cfg(feature = "sqlite")]
    #[test]
    fn i1162_attestation_query_through_the_proxy_sqlite() {
        let rt = test_runtime();
        let backend = rt.block_on(async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .expect("open sqlite");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        exercise_attestation_query_through_the_proxy_1162(&rt, Arc::new(backend), "sqlite");
    }

    /// CIRISPersist#1162 — postgres arm.
    #[cfg(feature = "postgres")]
    #[test]
    #[serial_test::serial(postgres)]
    fn i1162_attestation_query_through_the_proxy_pg() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = test_runtime();
        let backend = rt.block_on(async {
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        exercise_attestation_query_through_the_proxy_1162(&rt, Arc::new(backend), &suffix);
    }

    // ── v61.4.0 — the ops Edge moves off the raw outbound_queue capsule ──
    //
    // Edge's `.so` and persist's each link their own `parking_lot`, so a
    // store method compiled into Edge that locks persist's writer mutex can
    // park where persist's unlock never wakes it. Each op below runs the
    // method inside persist's `.so`. Every witness drives the op through the
    // C-ABI vtable (`run_op`) AND through the consumer proxy, on sqlite and
    // postgres, against the direct call.

    /// A migrated sqlite backend, or a postgres one when the DSN is set.
    fn sqlite_backend_1244(
        rt: &Arc<tokio::runtime::Runtime>,
    ) -> Arc<crate::store::sqlite::SqliteBackend> {
        Arc::new(rt.block_on(async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .expect("open sqlite");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        }))
    }

    #[cfg(feature = "postgres")]
    fn pg_backend_1244(
        rt: &Arc<tokio::runtime::Runtime>,
    ) -> Option<Arc<crate::store::postgres::PostgresBackend>> {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return None;
        };
        Some(Arc::new(rt.block_on(async {
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        })))
    }

    fn proxy_1244(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
    ) -> Arc<OpsDirectory> {
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        build_ops_directory_proxy(build_persist_directory(dir), executor).expect("abi ok")
    }

    /// **I1755 (CIRISPersist#1227) — `list_keys_by_identity_type` crosses the
    /// capsule for a non-accord role.** Two `node` keys come back through the
    /// vtable and through the proxy, equal to the direct read; the proxy no
    /// longer answers `Unsupported`.
    fn exercise_i1755(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        use crate::federation::types::identity_type::NODE;
        // v62.0.0 (JSON cut, E7) — edition-2 keys: the ids are the
        // identity-refs `e2::put_key` returns.
        let mine: Vec<String> = rt.block_on(async {
            let mut v = Vec::new();
            for k in [format!("{tag}-node-a"), format!("{tag}-node-b")] {
                v.push(
                    crate::federation::edition2::fixture_switch::put_key(dir.as_ref(), &k, &[NODE])
                        .await,
                );
            }
            v
        });
        let ids = |v: &[KeyRecord]| -> Vec<String> { v.iter().map(|r| r.key_id.clone()).collect() };
        let direct = rt
            .block_on(dir.list_keys_by_identity_type(NODE))
            .expect("direct");
        for k in &mine {
            assert!(ids(&direct).contains(k), "I1755 seed {k}");
        }
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListKeysByIdentityType {
                identity_type: NODE.into(),
            },
        ) {
            DirectoryOpResult::KeyRecords(v) => assert_eq!(ids(&v), ids(&direct), "I1755 vtable"),
            other => panic!("I1755: expected KeyRecords, got {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        let via = rt
            .block_on(proxy.list_keys_by_identity_type(NODE))
            .expect("I1755: the proxy routes a non-accord role");
        assert_eq!(ids(&via), ids(&direct), "I1755 proxy");
    }

    /// Two `node` keys tied to one owner, each with a route on one
    /// destination: the fold keeps the newer, the unfolded read keeps both.
    fn seed_tied_routes_1244(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, Vec<String>) {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::{NODE, USER};
        let dest = format!("{tag}dest");
        // v62.0.0 (E0 fix 4) — THE DISTINGUISHING PART FIRST: a test key
        // seeds from its first 32 bytes, and the pg tag is a 32-char uuid, so
        // `{tag}-owner` / `{tag}-node-N` were ONE key (the binding's target
        // was the `user` owner itself: `target_age_unverified`).
        let owner = format!("owner-{tag}");
        let nodes = [format!("node-1-{tag}"), format!("node-2-{tag}")];
        rt.block_on(async {
            ts::register_identity_key(dir, &owner, USER).await;
            for (i, n) in nodes.iter().enumerate() {
                ts::register_identity_key(dir, n, NODE).await;
                ts::put_owner_binding(dir, &owner, n).await;
                // v62.0.0 (round 6) — the route names the node's KEY, its
                // identity-ref (the store keys it `kid(seed)`): the fold ties
                // two routes through the owner binding OF THAT KEY, and a
                // seed-named route was nobody's, so the fold kept both.
                let r = self_at_login::TransportDestination {
                    occurrence_key_id: crate::federation::edition2::fixture_switch::kid(n),
                    transport_kind: "reticulum".into(),
                    destination: dest.clone(),
                    asserted_at: "2026-10-22T00:00:00.000Z".parse().unwrap(),
                    last_seen_at: None,
                    transport_ed25519_pubkey_base64: None,
                    transport_x25519_pubkey_base64: None,
                    binding_provenance: self_at_login::BindingProvenance::Rooted,
                    epoch: 1 + i as u64,
                    retired_at: None,
                };
                dir.put_transport_destination(&r).await.expect("seed route");
            }
        });
        // Sorted, as `route_keys_1244` answers them.
        let mut nodes: Vec<String> = nodes
            .iter()
            .map(|n| crate::federation::edition2::fixture_switch::kid(n))
            .collect();
        nodes.sort();
        (dest, nodes)
    }

    fn route_keys_1244(v: &[self_at_login::TransportDestination], tag: &str) -> Vec<String> {
        // The two node keys `seed_tied_routes_1244` seeds under `tag`.
        let mine: Vec<String> = [format!("node-1-{tag}"), format!("node-2-{tag}")]
            .iter()
            .map(|n| crate::federation::edition2::fixture_switch::kid(n))
            .collect();
        let mut k: Vec<String> = v
            .iter()
            .filter(|r| mine.contains(&r.occurrence_key_id))
            .map(|r| r.occurrence_key_id.clone())
            .collect();
        k.sort();
        k
    }

    /// **I1756 — `list_all_transport_destinations_unfolded` crosses the
    /// capsule unfolded.** Both tied routes come back through the vtable and
    /// the proxy (the folded read keeps one), equal to the direct read.
    fn exercise_i1756(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let (_, nodes) = seed_tied_routes_1244(rt, dir.as_ref(), tag);
        let direct = rt
            .block_on(dir.list_all_transport_destinations_unfolded())
            .expect("direct");
        assert_eq!(
            route_keys_1244(&direct, tag),
            nodes,
            "I1756 seed: both routes"
        );
        let folded = rt
            .block_on(dir.list_all_transport_destinations())
            .expect("folded");
        assert_eq!(
            route_keys_1244(&folded, tag),
            // The newer epoch's: `node-2`'s key.
            vec![crate::federation::edition2::fixture_switch::kid(&format!(
                "node-2-{tag}"
            ))],
            "I1756 seed: the fold keeps one"
        );
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListAllTransportDestinationsUnfolded {},
        ) {
            DirectoryOpResult::TransportDestinations(v) => {
                assert_eq!(route_keys_1244(&v, tag), nodes, "I1756 vtable")
            }
            other => panic!("I1756: expected TransportDestinations, got {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        let via = rt
            .block_on(proxy.list_all_transport_destinations_unfolded())
            .expect("I1756: the proxy routes the unfolded read");
        assert_eq!(route_keys_1244(&via, tag), nodes, "I1756 proxy");
    }

    /// **I1757 — `list_transport_destinations_by_destination_unfolded`
    /// crosses the capsule unfolded.** Same shape as I1756, one destination.
    fn exercise_i1757(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let (dest, nodes) = seed_tied_routes_1244(rt, dir.as_ref(), tag);
        let direct = rt
            .block_on(dir.list_transport_destinations_by_destination_unfolded(&dest))
            .expect("direct");
        assert_eq!(
            route_keys_1244(&direct, tag),
            nodes,
            "I1757 seed: both routes"
        );
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListTransportDestinationsByDestinationUnfolded {
                destination: dest.clone(),
            },
        ) {
            DirectoryOpResult::TransportDestinations(v) => {
                assert_eq!(route_keys_1244(&v, tag), nodes, "I1757 vtable")
            }
            other => panic!("I1757: expected TransportDestinations, got {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        let via = rt
            .block_on(proxy.list_transport_destinations_by_destination_unfolded(&dest))
            .expect("I1757: the proxy routes the unfolded claimant read");
        assert_eq!(route_keys_1244(&via, tag), nodes, "I1757 proxy");
    }

    /// **I1758 (CIRISPersist#1244) — the five blackhole ops run inside
    /// persist's `.so`.** Through the vtable: upsert lands a rule, record_hit
    /// bumps its counter, an expired rule is pruned with its count, remove
    /// drops a rule; through the proxy (`Arc<OpsDirectory>` as
    /// `BlackholeRules`), the same, and a short hash is `InvalidArgument`.
    fn exercise_i1758<B>(rt: &Arc<tokio::runtime::Runtime>, backend: Arc<B>)
    where
        B: FederationDirectory + crate::federation::BlackholeRules + 'static,
    {
        use crate::federation::BlackholeRules;
        let fresh = || uuid::Uuid::new_v4().as_bytes().to_vec();
        let find = |v: &[crate::federation::BlackholeRecord], h: &[u8]| {
            v.iter().find(|r| r.identity_hash == h).cloned()
        };
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let directory = build_persist_directory(dir.clone());
        let list_via_vtable = || match run_op(rt, &directory, &DirectoryOp::BlackholeList {}) {
            DirectoryOpResult::BlackholeRecords(v) => v,
            other => panic!("I1758: expected BlackholeRecords, got {other:?}"),
        };
        let unit = |op: DirectoryOp| match run_op(rt, &directory, &op) {
            DirectoryOpResult::Unit => {}
            other => panic!("I1758: expected Unit for {op:?}, got {other:?}"),
        };

        // upsert + list
        let h = fresh();
        unit(DirectoryOp::BlackholeUpsert {
            identity_hash: h.clone(),
            until: None,
            reason: Some("i1758".into()),
        });
        let row = find(&list_via_vtable(), &h).expect("I1758 upsert landed");
        assert_eq!(row.reason.as_deref(), Some("i1758"));
        assert_eq!(row.hits, 0);
        assert_eq!(
            find(&rt.block_on(backend.blackhole_list()).unwrap(), &h),
            Some(row),
            "I1758 list equals the direct read"
        );
        // record_hit
        unit(DirectoryOp::BlackholeRecordHit {
            identity_hash: h.clone(),
        });
        unit(DirectoryOp::BlackholeRecordHit {
            identity_hash: h.clone(),
        });
        assert_eq!(
            find(&list_via_vtable(), &h).unwrap().hits,
            2,
            "I1758 record_hit"
        );
        // prune
        let expired = fresh();
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        unit(DirectoryOp::BlackholeUpsert {
            identity_hash: expired.clone(),
            until: Some(past),
            reason: None,
        });
        match run_op(
            rt,
            &directory,
            &DirectoryOp::BlackholePruneExpired {
                now: chrono::Utc::now(),
            },
        ) {
            DirectoryOpResult::U64(n) => assert!(n >= 1, "I1758 prune counted {n}"),
            other => panic!("I1758: expected U64, got {other:?}"),
        }
        let after = list_via_vtable();
        assert!(
            find(&after, &expired).is_none(),
            "I1758 the expired rule is pruned"
        );
        assert!(
            find(&after, &h).is_some(),
            "I1758 a permanent rule survives"
        );
        // remove
        unit(DirectoryOp::BlackholeRemove {
            identity_hash: h.clone(),
        });
        assert!(find(&list_via_vtable(), &h).is_none(), "I1758 remove");
        // a short hash is refused inside the .so too
        match run_op(
            rt,
            &directory,
            &DirectoryOp::BlackholeRecordHit {
                identity_hash: vec![1, 2, 3],
            },
        ) {
            DirectoryOpResult::Err(e) => assert!(e.contains("16 bytes"), "I1758: {e}"),
            other => panic!("I1758: a short hash must refuse, got {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };

        // the consumer's view: the proxy as `Arc<dyn BlackholeRules>`.
        let rules: Arc<dyn BlackholeRules> = proxy_1244(rt, dir.clone());
        let p = fresh();
        rt.block_on(rules.blackhole_upsert(&p, None, Some("proxy")))
            .expect("I1758 proxy upsert");
        rt.block_on(rules.blackhole_record_hit(&p))
            .expect("I1758 proxy record_hit");
        let r = find(&rt.block_on(rules.blackhole_list()).unwrap(), &p).expect("I1758 proxy list");
        assert_eq!((r.reason.as_deref(), r.hits), (Some("proxy"), 1));
        let q = fresh();
        rt.block_on(rules.blackhole_upsert(&q, Some(past), None))
            .unwrap();
        assert!(
            rt.block_on(rules.blackhole_prune_expired(chrono::Utc::now()))
                .unwrap()
                >= 1
        );
        rt.block_on(rules.blackhole_remove(&p)).unwrap();
        let left = rt.block_on(backend.blackhole_list()).unwrap();
        assert!(
            find(&left, &p).is_none() && find(&left, &q).is_none(),
            "I1758 proxy"
        );
        assert!(matches!(
            rt.block_on(rules.blackhole_record_hit(&[0u8; 3])),
            Err(Error::InvalidArgument(_))
        ));
    }

    /// **I1759 (CIRISPersist#1244) — `put_edge_detection_event` runs inside
    /// persist's `.so`.** A row put through the vtable reads back from the
    /// backend; a re-put is idempotent; the same id with another row hash is
    /// refused through the capsule; and the proxy, as a `DerivedSchema`,
    /// admits a second row.
    fn exercise_i1759<B>(rt: &Arc<tokio::runtime::Runtime>, backend: Arc<B>, tag: &str)
    where
        B: FederationDirectory + crate::derived::DerivedSchema + 'static,
    {
        use crate::derived::DerivedSchema;
        let subject = format!("{tag}-edge-sub");
        rt.block_on(backend.add_peer_record(&subject, "AAAA", "agent", None))
            .expect("peer");
        let event = |hash: &str| crate::derived::EdgeDetectionEvent {
            detection_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: "i1759".into(),
            detector_kind: "unconsented_external_probe".into(),
            subject_key_id: subject.clone(),
            observed_at: chrono::Utc::now(),
            evidence: serde_json::json!({"probe_count": 7}),
            severity: "warn".into(),
            signature: "edge-sig-base64".into(),
            signing_key_id: subject.clone(),
            signature_verified: true,
            persist_row_hash: hash.into(),
        };
        let stored = || -> Vec<String> {
            let mut v: Vec<String> = rt
                .block_on(
                    backend.get_edge_detection_events(crate::derived::EdgeEventFilter {
                        peer_key_id: Some(subject.clone()),
                        ..Default::default()
                    }),
                )
                .expect("read")
                .into_iter()
                .map(|e| e.detection_id)
                .collect();
            v.sort();
            v
        };
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let directory = build_persist_directory(dir.clone());
        let e1 = event("row-hash-A");
        for _ in 0..2 {
            match run_op(
                rt,
                &directory,
                &DirectoryOp::PutEdgeDetectionEvent { event: e1.clone() },
            ) {
                DirectoryOpResult::Unit => {}
                other => panic!("I1759: expected Unit, got {other:?}"),
            }
        }
        assert_eq!(
            stored(),
            vec![e1.detection_id.clone()],
            "I1759 vtable put landed"
        );
        let mut clash = e1.clone();
        clash.persist_row_hash = "row-hash-B".into();
        match run_op(
            rt,
            &directory,
            &DirectoryOp::PutEdgeDetectionEvent { event: clash },
        ) {
            DirectoryOpResult::Err(e) => assert!(e.contains("conflict"), "I1759: {e}"),
            other => panic!("I1759: a differing row hash must refuse, got {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };

        let proxy = proxy_1244(rt, dir);
        let e2 = event("row-hash-C");
        rt.block_on(DerivedSchema::put_edge_detection_event(
            proxy.as_ref(),
            e2.clone(),
        ))
        .expect("I1759 proxy put");
        let mut want = vec![e1.detection_id, e2.detection_id];
        want.sort();
        assert_eq!(stored(), want, "I1759 proxy put landed");
    }

    macro_rules! both_backends_1244 {
        ($sqlite:ident, $pg:ident, |$rt:ident, $b:ident, $tag:ident| $body:expr) => {
            #[test]
            fn $sqlite() {
                let $rt = test_runtime();
                let $b = sqlite_backend_1244(&$rt);
                let $tag = "sq".to_string();
                $body
            }
            #[cfg(feature = "postgres")]
            #[test]
            #[serial_test::serial(postgres)]
            fn $pg() {
                let $rt = test_runtime();
                let Some($b) = pg_backend_1244(&$rt) else {
                    return;
                };
                // v62.0.0 (round 3, E7) — 12 hex, not 32: a test signer
                // seeds from the FIRST 32 BYTES of its name, so `{tag}-alice`
                // and `{tag}-bob` under a 32-hex tag were ONE key on pg (the
                // roster then listed it twice, refused by the payload codec).
                let $tag = uuid::Uuid::new_v4().simple().to_string()[..12].to_owned();
                $body
            }
        };
    }

    both_backends_1244!(
        i1755_keys_by_any_role_cross_the_capsule_sqlite,
        i1755_keys_by_any_role_cross_the_capsule_pg,
        |rt, b, tag| exercise_i1755(&rt, b, &tag)
    );
    both_backends_1244!(
        i1756_all_routes_unfolded_cross_the_capsule_sqlite,
        i1756_all_routes_unfolded_cross_the_capsule_pg,
        |rt, b, tag| exercise_i1756(&rt, b, &tag)
    );
    both_backends_1244!(
        i1757_claimants_unfolded_cross_the_capsule_sqlite,
        i1757_claimants_unfolded_cross_the_capsule_pg,
        |rt, b, tag| exercise_i1757(&rt, b, &tag)
    );
    both_backends_1244!(
        i1758_blackhole_ops_cross_the_capsule_sqlite,
        i1758_blackhole_ops_cross_the_capsule_pg,
        |rt, b, tag| {
            let _ = tag;
            exercise_i1758(&rt, b)
        }
    );
    both_backends_1244!(
        i1759_edge_detection_put_crosses_the_capsule_sqlite,
        i1759_edge_detection_put_crosses_the_capsule_pg,
        |rt, b, tag| exercise_i1759(&rt, b, &tag)
    );

    /// **I1760 (CIRISPersist#1244) — a skewed ABI version is refused by the
    /// concrete-proxy constructor too**, so the new surfaces cannot dispatch
    /// over a capsule built for another layout.
    #[test]
    fn i1760_the_concrete_proxy_refuses_a_skewed_abi() {
        static SKEWED: DirectoryVTable = DirectoryVTable {
            abi_version: DIRECTORY_ABI_VERSION + 1,
            _reserved: 0,
            build_op: persist_directory_build_op,
            drop: persist_directory_drop,
        };
        let rt = test_runtime();
        let directory = Directory {
            data: std::ptr::null_mut(),
            vtable: &SKEWED,
        };
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        match build_ops_directory_proxy(directory, executor) {
            Err(Error::Backend(m)) => assert!(m.contains("ABI version mismatch"), "I1760: {m}"),
            Err(e) => panic!("I1760: wrong refusal {e:?}"),
            Ok(_) => panic!("I1760: a skewed capsule was accepted"),
        }
    }

    /// **I1761 (CIRISPersist#1244) — a directory with no blackhole or
    /// edge-detection surface refuses those ops by name**, never answering
    /// an empty list or a silent `Unit`.
    #[test]
    fn i1761_a_surfaceless_directory_refuses_by_name() {
        let rt = test_runtime();
        let inner: Arc<dyn FederationDirectory> = sqlite_backend_1244(&rt);
        let double: Arc<dyn FederationDirectory> =
            Arc::new(crate::federation::directory_double::FaultInjectingDirectory::new(inner));
        assert!(double.blackhole_rules_surface().is_none());
        let directory = build_persist_directory(double);
        for (op, want) in [
            (DirectoryOp::BlackholeList {}, NO_BLACKHOLE_SURFACE),
            (
                DirectoryOp::BlackholePruneExpired {
                    now: chrono::Utc::now(),
                },
                NO_BLACKHOLE_SURFACE,
            ),
            (
                DirectoryOp::PutEdgeDetectionEvent {
                    event: crate::derived::EdgeDetectionEvent {
                        detection_id: uuid::Uuid::new_v4().to_string(),
                        tenant_id: "i1761".into(),
                        detector_kind: "unconsented_external_probe".into(),
                        subject_key_id: "nobody".into(),
                        observed_at: chrono::Utc::now(),
                        evidence: serde_json::json!({}),
                        severity: "warn".into(),
                        signature: "sig".into(),
                        signing_key_id: "nobody".into(),
                        signature_verified: false,
                        persist_row_hash: "h".into(),
                    },
                },
                NO_EDGE_DETECTION_SURFACE,
            ),
        ] {
            match run_op(&rt, &directory, &op) {
                DirectoryOpResult::Err(e) => assert_eq!(e, want, "I1761 {op:?}"),
                other => panic!("I1761 {op:?}: {other:?}"),
            }
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    // ── v61.4.0 round 2 (CIRISPersist#1244) — the rooting view and the
    // fail-open trust reads cross the capsule ───────────────────────────

    type ProxyCall =
        fn(Arc<dyn FederationDirectory>) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

    fn axis() -> crate::federation::key_grant::KeyGrantAxis {
        crate::federation::key_grant::KeyGrantAxis::Content {
            at_rest_sha256: "00".repeat(32),
            cohort_scope: "self".into(),
            owner_key_id: "x".into(),
        }
    }

    /// **I1762 — every round-2 read reaches the HOST's method.** Over a
    /// directory double that fails exactly one method, that op's capsule
    /// answer (vtable) and the proxy's carry the injected failure by name:
    /// an op that answered empty, or called another method, would not. One
    /// row per routed read; the sync reads are I1766–I1768.
    fn exercise_i1762(rt: &Arc<tokio::runtime::Runtime>, inner: Arc<dyn FederationDirectory>) {
        let table: Vec<(&'static str, DirectoryOp, ProxyCall)> = vec![
            (
                "list_attestations_referencing",
                DirectoryOp::ListAttestationsReferencing {
                    target_attestation_id: "x".into(),
                },
                |p| Box::pin(async move { p.list_attestations_referencing("x").await.map(|_| ()) }),
            ),
            (
                "get_attestation",
                DirectoryOp::GetAttestation {
                    attestation_id: "x".into(),
                },
                |p| Box::pin(async move { p.get_attestation("x").await.map(|_| ()) }),
            ),
            (
                "list_settled_self_roster_proposals",
                DirectoryOp::ListSettledSelfRosterProposals {
                    identity_key_id: "x".into(),
                },
                |p| {
                    Box::pin(
                        async move { p.list_settled_self_roster_proposals("x").await.map(|_| ()) },
                    )
                },
            ),
            (
                "list_identity_occurrences_for",
                DirectoryOp::ListIdentityOccurrencesFor {
                    identity_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.list_identity_occurrences_for("x").await.map(|_| ()) }),
            ),
            (
                "get_active_halt",
                DirectoryOp::GetActiveHalt {
                    family_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.get_active_halt("x").await.map(|_| ()) }),
            ),
            (
                "lookup_family",
                DirectoryOp::LookupFamily {
                    family_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.lookup_family("x").await.map(|_| ()) }),
            ),
            (
                "lookup_community",
                DirectoryOp::LookupCommunity {
                    community_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.lookup_community("x").await.map(|_| ()) }),
            ),
            (
                "list_families_for_member",
                DirectoryOp::ListFamiliesForMember {
                    member_identity_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.list_families_for_member("x").await.map(|_| ()) }),
            ),
            (
                "family_roster_signers",
                DirectoryOp::FamilyRosterSigners {
                    family_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.family_roster_signers("x").await.map(|_| ()) }),
            ),
            (
                "community_roster_signers",
                DirectoryOp::CommunityRosterSigners {
                    community_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.community_roster_signers("x").await.map(|_| ()) }),
            ),
            (
                "list_family_membership_revocations_for",
                DirectoryOp::ListFamilyMembershipRevocationsFor {
                    family_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_family_membership_revocations_for("x")
                            .await
                            .map(|_| ())
                    })
                },
            ),
            (
                "list_family_membership_widenings_for",
                DirectoryOp::ListFamilyMembershipWideningsFor {
                    family_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_family_membership_widenings_for("x")
                            .await
                            .map(|_| ())
                    })
                },
            ),
            (
                "list_community_membership_revocations_for",
                DirectoryOp::ListCommunityMembershipRevocationsFor {
                    community_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_community_membership_revocations_for("x")
                            .await
                            .map(|_| ())
                    })
                },
            ),
            (
                "list_community_membership_widenings_for",
                DirectoryOp::ListCommunityMembershipWideningsFor {
                    community_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_community_membership_widenings_for("x")
                            .await
                            .map(|_| ())
                    })
                },
            ),
            (
                "list_lineage_head_cosigns_for",
                DirectoryOp::ListLineageHeadCosignsFor {
                    lineage_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.list_lineage_head_cosigns_for("x").await.map(|_| ()) }),
            ),
            (
                "lookup_signed_community",
                DirectoryOp::LookupSignedCommunity {
                    community_key_id: "x".into(),
                },
                |p| Box::pin(async move { p.lookup_signed_community("x").await.map(|_| ()) }),
            ),
            (
                "vote_window_first_held",
                DirectoryOp::VoteWindowFirstHeld {
                    action_id: "x".into(),
                },
                |p| Box::pin(async move { p.vote_window_first_held("x").await.map(|_| ()) }),
            ),
            (
                "list_cosign_aliases",
                DirectoryOp::ListCosignAliases {
                    quorum_key: "x".into(),
                },
                |p| Box::pin(async move { p.list_cosign_aliases("x").await.map(|_| ()) }),
            ),
            (
                "cosign_alias",
                DirectoryOp::CosignAlias {
                    attestation_id: "x".into(),
                },
                |p| Box::pin(async move { p.cosign_alias("x").await.map(|_| ()) }),
            ),
            (
                "get_accord_decision",
                DirectoryOp::GetAccordDecision {
                    proposal_digest: "x".into(),
                },
                |p| Box::pin(async move { p.get_accord_decision("x").await.map(|_| ()) }),
            ),
            (
                "list_accord_proposals_by_anchor",
                DirectoryOp::ListAccordProposalsByAnchor {
                    action: "x".into(),
                    prior_family_digest: "y".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_accord_proposals_by_anchor("x", "y")
                            .await
                            .map(|_| ())
                    })
                },
            ),
            (
                "purge_tombstoned",
                DirectoryOp::PurgeTombstoned {
                    plane: "x".into(),
                    record_ref: "y".into(),
                },
                |p| Box::pin(async move { p.purge_tombstoned("x", "y").await.map(|_| ()) }),
            ),
            (
                "purge_tombstone_notices",
                DirectoryOp::PurgeTombstoneNotices {
                    plane: "x".into(),
                    record_ref: "y".into(),
                },
                |p| Box::pin(async move { p.purge_tombstone_notices("x", "y").await.map(|_| ()) }),
            ),
            (
                "list_targeted_by_dimension_prefix",
                DirectoryOp::ListTargetedByDimensionPrefix {
                    cohort_scopes: vec!["community".into()],
                    cohort_target: "x".into(),
                    dimension_prefix: "y".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_targeted_by_dimension_prefix(&["community"], "x", "y")
                            .await
                            .map(|_| ())
                    })
                },
            ),
            (
                "key_grant_held_owner",
                DirectoryOp::KeyGrantHeldOwner { axis: axis() },
                |p| Box::pin(async move { p.key_grant_held_owner(&axis()).await.map(|_| ()) }),
            ),
        ];
        // v61.4.2: + the community membership pair (23 → 25).
        assert_eq!(table.len(), 25, "I1762: one row per routed async read");
        // Every row runs, and the red names every op that failed, not only
        // the first (so one mutated build shows each arm's witness).
        let mut red = Vec::new();
        for (method, op, call) in table {
            let row = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let want = format!("injected backend failure: {method}");
                let faulty: Arc<dyn FederationDirectory> = Arc::new(
                    crate::federation::directory_double::FaultInjectingDirectory::new(
                        inner.clone(),
                    )
                    .erroring(method),
                );
                let directory = build_persist_directory(faulty.clone());
                match run_op(rt, &directory, &op) {
                    DirectoryOpResult::Err(e) => {
                        assert!(e.contains(&want), "I1762 {method} vtable: {e}")
                    }
                    other => {
                        panic!(
                            "I1762 {method}: the vtable answered {other:?}, not the host's failure"
                        )
                    }
                }
                // SAFETY: single-drop, matched vtable.
                unsafe { (directory.vtable.drop)(directory.data) };
                let proxy = proxy_1244(rt, faulty);
                match rt.block_on(call(proxy as Arc<dyn FederationDirectory>)) {
                    Err(Error::Backend(e)) => {
                        assert!(e.contains(&want), "I1762 {method} proxy: {e}")
                    }
                    other => {
                        panic!(
                            "I1762 {method}: the proxy answered {other:?}, not the host's failure"
                        )
                    }
                }
                // And with no fault, the proxy answers what the direct call does
                // (never the old `Unsupported`): both Ok, or the same failure.
                let clean = proxy_1244(rt, inner.clone());
                match (rt.block_on(call(clean)), rt.block_on(call(inner.clone()))) {
                    (Ok(()), Ok(())) => {}
                    // v62.0.0 (ABI 14) — a host `Backend` crosses as `Backend`
                    // with the host's text; any other failure as `Relayed`,
                    // whose text and kind are the host's.
                    (Err(Error::Backend(p)), Err(d)) => {
                        assert_eq!(p, d.to_string(), "I1762 {method}: the host's own failure")
                    }
                    (Err(p @ Error::Relayed { .. }), Err(d)) => {
                        assert_eq!(p.to_string(), d.to_string(), "I1762 {method}: the text");
                        assert_eq!(p.kind(), d.kind(), "I1762 {method}: the kind crosses");
                        assert_eq!(p.is_wait(), d.is_wait(), "I1762 {method}: the wait crosses");
                    }
                    (p, d) => panic!("I1762 {method}: proxy {p:?} vs direct {d:?}"),
                }
            }));
            if row.is_err() {
                red.push(method);
            }
        }
        assert!(
            red.is_empty(),
            "I1762: these ops did not reach the host: {red:?}"
        );
    }

    /// **I1763 — an active halt is SEEN through the proxy.** Before #1244
    /// round 2 the proxy answered `Unsupported`, and `trust_root` read it as
    /// no halt.
    fn exercise_i1763(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let fam = format!("{tag}-halted-family");
        rt.block_on(dir.set_active_halt(&fam, "halt-1763", None))
            .expect("set halt");
        let direct = rt.block_on(dir.get_active_halt(&fam)).expect("direct");
        assert!(direct.is_some(), "I1763 seed");
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::GetActiveHalt {
                family_key_id: fam.clone(),
            },
        ) {
            DirectoryOpResult::ActiveHalt(v) => assert_eq!(v, direct, "I1763 vtable"),
            other => panic!("I1763: {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        let via = rt
            .block_on(proxy.get_active_halt(&fam))
            .expect("I1763 routed");
        assert_eq!(via, direct, "I1763: the proxy sees the active halt");
        assert_eq!(via.unwrap().active_halt_id, "halt-1763");
    }

    /// **I1764 — a withdrawn role is SEEN as withdrawn through the proxy.**
    /// The trait default answered `Ok(None)`, so a withdrawn role read as live.
    fn exercise_i1764(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let key = format!("{tag}-role-key");
        rt.block_on(dir.record_role_withdrawal("steward", &key, None, "digest-1764"))
            .expect("record role withdrawal");
        let direct = rt
            .block_on(dir.lookup_role_withdrawal("steward", &key))
            .expect("direct");
        assert!(direct.is_some(), "I1764 seed");
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::LookupRoleWithdrawal {
                role: "steward".into(),
                key_id: key.clone(),
            },
        ) {
            DirectoryOpResult::RoleWithdrawal(v) => assert_eq!(v, direct, "I1764 vtable"),
            other => panic!("I1764: {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        let via = rt
            .block_on(proxy.lookup_role_withdrawal("steward", &key))
            .expect("I1764 routed");
        assert_eq!(via, direct, "I1764: the proxy sees the role as withdrawn");
        assert!(rt
            .block_on(proxy.lookup_role_withdrawal("steward", "never-withdrawn"))
            .unwrap()
            .is_none());
    }

    /// **I1765** — v62.0.0 (TR-fix2; CC rc21 4.2.1): a canonical is withdrawn
    /// only by a later genesis bundle. The backend writer is gone: the
    /// concrete store refuses `record_canonical_withdrawal` by name (naming
    /// `PutGenesisBundle`), and the lookup / list answer none, alike direct,
    /// through the vtable and through the proxy.
    fn exercise_i1765(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let key = format!("{tag}-canonical");
        match rt.block_on(dir.record_canonical_withdrawal(&key, None, "digest-1765")) {
            Err(Error::Unsupported { method }) => assert!(
                method.contains("PutGenesisBundle"),
                "I1765: the refusal names the replacement: {method}"
            ),
            other => panic!("I1765: the backend writer is retired, got {other:?}"),
        }
        let direct = rt
            .block_on(dir.lookup_canonical_withdrawal(&key))
            .expect("direct");
        assert!(direct.is_none(), "I1765: nothing is held");
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::LookupCanonicalWithdrawal {
                key_id: key.clone(),
            },
        ) {
            DirectoryOpResult::CanonicalWithdrawal(v) => assert_eq!(v, direct, "I1765 vtable"),
            other => panic!("I1765: {other:?}"),
        }
        let listed = match run_op(rt, &directory, &DirectoryOp::ListCanonicalWithdrawals {}) {
            DirectoryOpResult::CanonicalWithdrawals(v) => v,
            other => panic!("I1765: {other:?}"),
        };
        assert_eq!(
            listed,
            rt.block_on(dir.list_canonical_withdrawals()).unwrap(),
            "I1765 list"
        );
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        assert_eq!(
            rt.block_on(proxy.lookup_canonical_withdrawal(&key))
                .unwrap(),
            direct,
            "I1765 proxy"
        );
        assert_eq!(
            rt.block_on(proxy.list_canonical_withdrawals()).unwrap(),
            listed,
            "I1765 proxy list"
        );
    }

    /// v62.0.0 (JSON cut, E7) — the edition-2 twin of the earlier `seed_withdraws_1244`:
    /// `issuer` (a seed) holds a row and then withdraws it (an edition-2
    /// composer must name a HELD row). Returns `(withdraws id, target id)`,
    /// both node-computed.
    fn seed_withdraws_e2(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: &dyn FederationDirectory,
        issuer: &str,
        label: &str,
    ) -> (String, String) {
        use crate::federation::edition2::fixture_switch as e2;
        rt.block_on(async {
            e2::put_key(
                dir,
                issuer,
                &[crate::federation::types::identity_type::USER],
            )
            .await;
            let now = chrono::Utc::now();
            let target = crate::federation::Attestation {
                attestation_id: String::new(),
                attesting_key_id: e2::kid(issuer),
                attested_key_id: e2::kid(issuer),
                attestation_type: crate::federation::types::attestation_type::SCORES.into(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: serde_json::json!({
                    "dimension": "coherence_standing:cab:v1",
                    "score": 1.0,
                    "confidence": 0.9,
                    "label": label,
                }),
                original_content_hash: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: e2::kid(issuer),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: "federation".into(),
                tier: crate::federation::types::attestation_tier::FEDERATION.into(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            };
            let target = e2::put_row(dir, &target, issuer).await;
            let w = e2::composer_of("withdraws", &target, issuer);
            e2::put_signed(dir, &w)
                .await
                .expect("a withdraws is admitted");
            (w.attestation_id.clone(), target.attestation_id.clone())
        })
    }

    fn exercise_i1769(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let issuer = format!("{tag}-issuer-1769");
        let (wid, target) = seed_withdraws_e2(rt, dir.as_ref(), &issuer, "target-1769");
        let refs = rt
            .block_on(dir.list_attestations_referencing(&target))
            .expect("direct");
        assert_eq!(refs.len(), 1, "I1769 seed");
        let got = rt.block_on(dir.get_attestation(&wid)).expect("direct");
        assert!(got.is_some(), "I1769 seed");
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListAttestationsReferencing {
                target_attestation_id: target.clone(),
            },
        ) {
            DirectoryOpResult::AttestationRows(v) => {
                assert_eq!(v, refs, "I1769 vtable referencing")
            }
            other => panic!("I1769: {other:?}"),
        }
        match run_op(
            rt,
            &directory,
            &DirectoryOp::GetAttestation {
                attestation_id: wid.clone(),
            },
        ) {
            DirectoryOpResult::Attestation(v) => assert_eq!(v, got, "I1769 vtable get"),
            other => panic!("I1769: {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        assert_eq!(
            rt.block_on(proxy.list_attestations_referencing(&target))
                .unwrap(),
            refs,
            "I1769 proxy"
        );
        assert_eq!(
            rt.block_on(proxy.get_attestation(&wid)).unwrap(),
            got,
            "I1769 proxy get"
        );
    }

    /// **I1770 — an identity's occurrences cross the capsule**
    /// (`list_identity_occurrences_for`), equal to the direct read.
    fn exercise_i1770(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        use crate::federation::tier_ingest::test_support as ts;
        // v62.0.0 (round 3, E7) — the occurrence is an edition-2
        // `identity:occurrence` bind (O1's self pair: identity = occurrence =
        // the user key, its one voice), named by identity-ref; the earlier
        // signed content-only occurrence door is shut.
        let seed = format!("ident-1770-{tag}");
        let id = crate::federation::edition2::fixture_switch::kid(&seed);
        rt.block_on(async {
            ts::register_identity_key(
                dir.as_ref(),
                &seed,
                crate::federation::types::identity_type::USER,
            )
            .await;
            crate::federation::edition2::fixture_occurrence::put_bind(
                dir.as_ref(),
                &seed,
                &seed,
                &seed,
                crate::federation::types::device_class::PHONE,
                &crate::federation::edition2::fixture_occurrence::BindOptions::default(),
            )
            .await
            .expect("occurrence");
        });
        let direct = rt
            .block_on(dir.list_identity_occurrences_for(&id))
            .expect("direct");
        assert_eq!(direct.len(), 1, "I1770 seed");
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListIdentityOccurrencesFor {
                identity_key_id: id.clone(),
            },
        ) {
            DirectoryOpResult::IdentityOccurrences(v) => assert_eq!(v, direct, "I1770 vtable"),
            other => panic!("I1770: {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        assert_eq!(
            rt.block_on(proxy.list_identity_occurrences_for(&id))
                .unwrap(),
            direct,
            "I1770 proxy"
        );
    }

    /// **I1771 — settled self-roster proposals cross the capsule.**
    fn exercise_i1771(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let id = format!("{tag}-ident-1771");
        // The receipt names a stored row (the ledger joins on it).
        let (prop, _) =
            seed_withdraws_e2(rt, dir.as_ref(), &format!("{tag}-issuer-1771"), "t-1771");
        rt.block_on(async {
            dir.note_self_roster_proposal(&prop, &id, chrono::Utc::now())
                .await
                .expect("note");
            dir.settle_self_roster_proposal(
                &prop,
                crate::federation::self_roster::WITHDRAWN_OUTCOME,
                chrono::Utc::now(),
            )
            .await
            .expect("settle");
        });
        let direct = rt
            .block_on(dir.list_settled_self_roster_proposals(&id))
            .expect("direct");
        assert_eq!(direct.len(), 1, "I1771 seed");
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListSettledSelfRosterProposals {
                identity_key_id: id.clone(),
            },
        ) {
            DirectoryOpResult::SelfRosterReceipts(v) => assert_eq!(v, direct, "I1771 vtable"),
            other => panic!("I1771: {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        assert_eq!(
            rt.block_on(proxy.list_settled_self_roster_proposals(&id))
                .unwrap(),
            direct,
            "I1771 proxy"
        );
    }

    /// **I1772 — cosign aliases cross the capsule**, by alias and by quorum
    /// key; through `Unsupported` a withdraws naming an alias resolved to
    /// nothing.
    fn exercise_i1772(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let (alias, qk, held) = (
            format!("{tag}-alias"),
            format!("{tag}-qk"),
            format!("{tag}-held"),
        );
        rt.block_on(dir.note_cosign_alias(&alias, &qk, &held))
            .expect("note alias");
        let one = rt.block_on(dir.cosign_alias(&alias)).expect("direct");
        let all = rt.block_on(dir.list_cosign_aliases(&qk)).expect("direct");
        assert!(one.is_some() && all.len() == 1, "I1772 seed");
        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::CosignAlias {
                attestation_id: alias.clone(),
            },
        ) {
            DirectoryOpResult::CosignAlias(v) => assert_eq!(v, one, "I1772 vtable"),
            other => panic!("I1772: {other:?}"),
        }
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListCosignAliases {
                quorum_key: qk.clone(),
            },
        ) {
            DirectoryOpResult::CosignAliases(v) => assert_eq!(v, all, "I1772 vtable list"),
            other => panic!("I1772: {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
        let proxy = proxy_1244(rt, dir.clone());
        assert_eq!(
            rt.block_on(proxy.cosign_alias(&alias)).unwrap(),
            one,
            "I1772 proxy"
        );
        assert_eq!(
            rt.block_on(proxy.list_cosign_aliases(&qk)).unwrap(),
            all,
            "I1772 proxy list"
        );
    }

    /// **I1808 — a room's membership planes cross the capsule.** Edge's
    /// call join reads a room's active roster (record + widenings −
    /// revocations) through the capsule; before v61.4.2 the proxy answered
    /// `Unsupported` for both planes and every join on an agent install
    /// answered 503. A keyless room with one widening and one revocation:
    /// the vtable and the proxy each answer the direct backend's rows, and
    /// the fold over the proxy's reads seats the widened member and drops
    /// the revoked one.
    fn exercise_i1808(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        use crate::federation::room_roster_invariants::bodies::keyless_room_dir;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type;
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().expect("rfc3339") };
        let (t_join, t_leave) = (at("2026-03-01T00:00:00Z"), at("2026-03-02T00:00:00Z"));
        let tg = format!("{tag}-1808");
        let (room, alice, bob) = rt.block_on(keyless_room_dir(dir.as_ref(), &tg));
        // v62.0.0 (round 3, E7) — carol by identity-ref, as the room's other
        // members are (`keyless_room_dir` returns kids); registered by seed.
        // Role first: a test signer seeds from the first 32 bytes (L1-fix1's
        // `carol-{tg}` form, which this rebases onto).
        let carol_seed = format!("carol-{tg}");
        let carol = crate::federation::edition2::fixture_switch::kid(&carol_seed);
        let widening = ts::sign_community_membership_widening(
            &alice,
            types::CommunityMembershipWidening {
                community_key_id: room.clone(),
                member_key_id: carol.clone(),
                joined_at: t_join,
                effective_at: t_join,
                role: None,
                persist_row_hash: String::new(),
            },
        );
        let revocation = ts::sign_community_membership_revocation(
            &alice,
            CommunityMembershipRevocation {
                community_key_id: room.clone(),
                removed_identity_key_id: bob.clone(),
                removed_at: t_leave,
                effective_at: t_leave,
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
                leaf: crate::federation::types::RevocationLeaf::Removal,
            },
        );
        // v62.0.0 (round 3, E7; T1 §3) — the widening and the revocation are
        // edition-2 voices over the room's held head. The widening follows a
        // proposal and carol's acceptance (CC 4.4.3: the member consents);
        // the earlier JSON membership doors are shut.
        rt.block_on(async {
            use crate::federation::edition2::fixture_switch as e2;
            use crate::federation::membership_acceptance_invariants::bodies::{
                proposal, put, reply,
            };
            ts::register_hybrid_key_as(dir.as_ref(), &carol_seed, &carol_seed, identity_type::USER)
                .await;
            let d: &dyn FederationDirectory = dir.as_ref();
            let p = proposal(
                &alice,
                crate::federation::types::cohort_scope::COMMUNITY,
                &room,
                &carol,
                None,
                t_join - chrono::Duration::seconds(3),
                Some(chrono::Duration::days(7)),
            );
            put(d, &p).await.expect("I1808 proposal");
            put(
                d,
                &reply(
                    &carol,
                    &carol,
                    &p,
                    true,
                    t_join - chrono::Duration::seconds(2),
                ),
            )
            .await
            .expect("I1808 carol accepts");
            let head = e2::held_head(d, &room).await.map(|(h, _)| h);
            e2::put_voices(d, &e2::community_widening_voices(&widening, head.as_ref()))
                .await
                .expect("I1808 widening");
            let head = e2::held_head(d, &room).await.map(|(h, _)| h);
            e2::put_voices(
                d,
                &e2::community_revocation_voices(&revocation, head.as_ref()),
            )
            .await
            .expect("I1808 revocation");
        });
        let ws = rt
            .block_on(dir.list_community_membership_widenings_for(&room))
            .expect("direct widenings");
        let rs = rt
            .block_on(dir.list_community_membership_revocations_for(&room))
            .expect("direct revocations");
        assert_eq!((ws.len(), rs.len()), (1, 1), "I1808 seed");

        let directory = build_persist_directory(dir.clone());
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListCommunityMembershipWideningsFor {
                community_key_id: room.clone(),
            },
        ) {
            DirectoryOpResult::CommunityMembershipWidenings(v) => {
                assert_eq!(v, ws, "I1808 vtable widenings")
            }
            other => panic!("I1808 widenings: {other:?}"),
        }
        match run_op(
            rt,
            &directory,
            &DirectoryOp::ListCommunityMembershipRevocationsFor {
                community_key_id: room.clone(),
            },
        ) {
            DirectoryOpResult::CommunityMembershipRevocations(v) => {
                assert_eq!(v, rs, "I1808 vtable revocations")
            }
            other => panic!("I1808 revocations: {other:?}"),
        }
        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };

        let proxy = proxy_1244(rt, dir.clone());
        let pw = rt
            .block_on(proxy.list_community_membership_widenings_for(&room))
            .expect("I1808: the proxy routes widenings");
        assert_eq!(pw, ws, "I1808 proxy widenings");
        let pr = rt
            .block_on(proxy.list_community_membership_revocations_for(&room))
            .expect("I1808: the proxy routes revocations");
        assert_eq!(pr, rs, "I1808 proxy revocations");
        // The fold Edge's join makes — record + widenings − revocations —
        // over the PROXY's three reads: carol is in, bob is out.
        let rec = rt
            .block_on(proxy.lookup_community(&room))
            .expect("I1808: the proxy routes the record")
            .expect("I1808: the room is held");
        let mut got: Vec<String> =
            crate::federation::active_roster_at(&rec.members, &pw, &pr, chrono::Utc::now())
                .into_iter()
                .map(|m| m.key_id)
                .collect();
        got.sort();
        let mut want = vec![alice, carol];
        want.sort();
        assert_eq!(got, want, "I1808 proxy fold: carol in, bob out");
    }

    // ── v61.4.2 (the capsule stub sweep) — every proxy stub routes ─────────

    type ProxyCallDbg = fn(
        Arc<dyn FederationDirectory>,
    ) -> Pin<Box<dyn Future<Output = Result<String, Error>> + Send>>;

    const KEY_1890: &str = "i1890-authority-key-000000000000000000";

    fn at_1890() -> chrono::DateTime<chrono::Utc> {
        "2026-03-01T00:00:00Z".parse().expect("rfc3339")
    }

    fn member_1890() -> types::CommunityMember {
        types::CommunityMember {
            key_id: "y".into(),
            joined_at: at_1890(),
            role: None,
        }
    }

    fn family_member_1890() -> types::FamilyMember {
        types::FamilyMember {
            key_id: "y".into(),
            joined_at: at_1890(),
            role: None,
        }
    }

    fn spec_1890() -> cohort::AdmitSpec {
        cohort::AdmitSpec {
            authority_key_id: KEY_1890.into(),
            scrub_signature_classical: "sig".into(),
            scrub_signature_pqc: None,
            cosignatures: Vec::new(),
        }
    }

    fn local_1890() -> types::LocalAttestationInput {
        crate::federation::tier_ingest::test_support::bound_transit_revocation_input(
            "att-1890",
            KEY_1890,
            "y",
            Vec::new(),
            "self",
            at_1890(),
            serde_json::json!({}),
        )
    }

    fn ci_1890() -> crate::federation::ContextualIntegrity {
        use crate::federation::crossing as c;
        c::ContextualIntegrity {
            sender: KEY_1890.into(),
            data_subject: c::DataSubject::Nobody,
            recipient_see: c::Audience::SelfOnly,
            recipient_revoke: c::RevocationAuthority::ProducerOnly,
            recipient_receive: c::DeliveryMode::BestEffort,
            information_type: crate::federation::namespace::AttestationFamily::Scores,
            transmission_principle: c::CrossingBasis::ProducerAuthority,
            temporal_lifecycle: c::Lifecycle {
                asserted_at: at_1890(),
                expires_at: None,
            },
            content: c::ContentRef::Sha256Hex {
                hash: "00".repeat(32),
            },
        }
    }

    fn custody_1890() -> crate::federation::TierPromotionCustody {
        crate::federation::TierPromotionCustody::NodeCoScrub(types::ScrubSig {
            scrub_key_id: KEY_1890.into(),
            scrub_signature_classical: "sig".into(),
            scrub_signature_pqc: None,
            cosigned_at: Some("2026-03-01T00:00:00Z".into()),
        })
    }

    fn community_revocation_1890() -> SignedCommunityMembershipRevocation {
        crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
            KEY_1890,
            CommunityMembershipRevocation {
                community_key_id: "x".into(),
                removed_identity_key_id: "y".into(),
                removed_at: at_1890(),
                effective_at: at_1890(),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
                leaf: crate::federation::types::RevocationLeaf::Removal,
            },
        )
    }

    fn community_widening_1890() -> crate::federation::SignedCommunityMembershipWidening {
        crate::federation::tier_ingest::test_support::sign_community_membership_widening(
            KEY_1890,
            types::CommunityMembershipWidening {
                community_key_id: "x".into(),
                member_key_id: "y".into(),
                joined_at: at_1890(),
                effective_at: at_1890(),
                role: None,
                persist_row_hash: String::new(),
            },
        )
    }

    fn family_revocation_1890() -> SignedFamilyMembershipRevocation {
        crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
            KEY_1890,
            FamilyMembershipRevocation {
                family_key_id: "x".into(),
                removed_identity_key_id: "y".into(),
                removed_at: at_1890(),
                effective_at: at_1890(),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
                leaf: crate::federation::types::RevocationLeaf::Removal,
            },
        )
    }

    fn family_widening_1890() -> crate::federation::SignedFamilyMembershipWidening {
        crate::federation::tier_ingest::test_support::sign_family_membership_widening(
            KEY_1890,
            types::FamilyMembershipWidening {
                family_key_id: "x".into(),
                member_key_id: "y".into(),
                joined_at: at_1890(),
                effective_at: at_1890(),
                role: None,
                persist_row_hash: String::new(),
            },
        )
    }

    fn location_proof_1890() -> SignedLocationProof {
        crate::federation::tier_ingest::test_support::sign_location_proof(
            KEY_1890,
            LocationProof {
                subject_key_id: KEY_1890.into(),
                cell_id: "x".into(),
                cell_resolution: 7,
                asserted_at: at_1890(),
                valid_until: None,
                attestation_evidence: None,
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
        )
    }

    /// **I1890 — every method the proxy stubbed reaches the HOST.** The
    /// capsule stub sweep: before v61.4.2 the proxy answered `Unsupported`
    /// for 29 `FederationDirectory` methods (33 at v61.4.1; the four hybrid-pending
    /// doors left the trait in v62) and inherited an `Unsupported`
    /// default for `list_live_consent_grants_by`, and persist's own folds
    /// running over the proxy (Edge's call join, after the community pair)
    /// failed on the next one (`list_group_versions`). One row per routed
    /// method, over a directory double that fails exactly one method:
    ///
    /// * the vtable and the proxy each carry the injected failure by name
    ///   (an op that answered empty, or called another method, would not —
    ///   `add_*_member` are trait defaults, so the leaf they read first is
    ///   the one failed);
    /// * with no fault, a READ answers through the proxy exactly what the
    ///   direct call answers (`Debug`-equal, or the host's own failure); a
    ///   WRITE is never `Unsupported` (its effect is I1891's and I1892's).
    fn exercise_i1890(rt: &Arc<tokio::runtime::Runtime>, inner: Arc<dyn FederationDirectory>) {
        let table: Vec<(&'static str, &'static str, bool, DirectoryOp, ProxyCallDbg)> = vec![
            (
                "add_community_member",
                "lookup_community",
                true,
                DirectoryOp::AddCommunityMember {
                    community_key_id: "x".into(),
                    member: member_1890(),
                    spec: spec_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.add_community_member("x", member_1890(), &spec_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "add_family_member",
                "lookup_family",
                true,
                DirectoryOp::AddFamilyMember {
                    family_key_id: "x".into(),
                    member: family_member_1890(),
                    spec: spec_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.add_family_member("x", family_member_1890(), &spec_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "attestation_insert_local",
                "attestation_insert_local",
                true,
                DirectoryOp::AttestationInsertLocal {
                    input: local_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.attestation_insert_local(local_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "attestation_type_census",
                "attestation_type_census",
                false,
                DirectoryOp::AttestationTypeCensus {},
                |p| {
                    Box::pin(
                        async move { p.attestation_type_census().await.map(|v| format!("{v:?}")) },
                    )
                },
            ),
            (
                "attestation_upsert_local",
                "attestation_upsert_local",
                true,
                DirectoryOp::AttestationUpsertLocal {
                    input: local_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.attestation_upsert_local(local_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "attestations_binding_content",
                "attestations_binding_content",
                false,
                DirectoryOp::AttestationsBindingContent {
                    content_sha256: "00".repeat(32),
                },
                |p| {
                    Box::pin(async move {
                        p.attestations_binding_content(&"00".repeat(32))
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "attestations_binding_content_with_placements",
                "attestations_binding_content_with_placements",
                false,
                DirectoryOp::AttestationsBindingContentWithPlacements {
                    content_sha256: "00".repeat(32),
                },
                |p| {
                    Box::pin(async move {
                        p.attestations_binding_content_with_placements(&"00".repeat(32))
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "clear_active_halt",
                "clear_active_halt",
                true,
                DirectoryOp::ClearActiveHalt {
                    family_key_id: "x".into(),
                    active_halt_id: "y".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.clear_active_halt("x", "y")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "communities_containing",
                "communities_containing",
                false,
                DirectoryOp::CommunitiesContaining {
                    cell_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.communities_containing("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "dag_manifests_of_chunk",
                "dag_manifests_of_chunk",
                false,
                DirectoryOp::DagManifestsOfChunk {
                    chunk_sha256: [7u8; 32],
                },
                |p| {
                    Box::pin(async move {
                        p.dag_manifests_of_chunk(&[7u8; 32])
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "enter_mesh",
                "enter_mesh",
                true,
                DirectoryOp::EnterMesh {
                    attestation_id: "x".into(),
                    ci: ci_1890(),
                    custody: custody_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.enter_mesh("x", &ci_1890(), &custody_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "get_accord_proposal",
                "get_accord_proposal",
                false,
                DirectoryOp::GetAccordProposal {
                    proposal_digest: "x".into(),
                },
                |p| {
                    Box::pin(
                        async move { p.get_accord_proposal("x").await.map(|v| format!("{v:?}")) },
                    )
                },
            ),
            (
                "list_accord_participations",
                "list_accord_participations",
                false,
                DirectoryOp::ListAccordParticipations {
                    proposal_digest: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_accord_participations("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "list_attestations_by_dimension_citing",
                "list_attestations_by_dimension_citing",
                false,
                DirectoryOp::ListAttestationsByDimensionCiting {
                    attesting_key_id: "x".into(),
                    dimension: "y".into(),
                    evidence_ref: "z".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_attestations_by_dimension_citing("x", "y", "z")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "list_communities_for_member",
                "list_communities_for_member",
                false,
                DirectoryOp::ListCommunitiesForMember {
                    member_identity_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_communities_for_member("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "list_group_versions",
                "list_group_versions",
                false,
                DirectoryOp::ListGroupVersions {
                    cohort: cohort::Cohort::Community,
                    group_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_group_versions(cohort::Cohort::Community, "x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "list_location_proofs_for",
                "list_location_proofs_for",
                false,
                DirectoryOp::ListLocationProofsFor {
                    subject_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_location_proofs_for("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "lookup_keys_for_identity",
                "lookup_keys_for_identity",
                false,
                DirectoryOp::LookupKeysForIdentity {
                    identity_ref: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.lookup_keys_for_identity("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "put_community_membership_revocation",
                "put_community_membership_revocation",
                true,
                DirectoryOp::PutCommunityMembershipRevocation {
                    revocation: community_revocation_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.put_community_membership_revocation(community_revocation_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "put_community_membership_widening",
                "put_community_membership_widening",
                true,
                DirectoryOp::PutCommunityMembershipWidening {
                    widening: community_widening_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.put_community_membership_widening(community_widening_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "put_family_membership_revocation",
                "put_family_membership_revocation",
                true,
                DirectoryOp::PutFamilyMembershipRevocation {
                    revocation: family_revocation_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.put_family_membership_revocation(family_revocation_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "put_family_membership_widening",
                "put_family_membership_widening",
                true,
                DirectoryOp::PutFamilyMembershipWidening {
                    widening: family_widening_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.put_family_membership_widening(family_widening_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "set_active_halt",
                "set_active_halt",
                true,
                DirectoryOp::SetActiveHalt {
                    family_key_id: "x".into(),
                    active_halt_id: "y".into(),
                    latch_json: None,
                },
                |p| {
                    Box::pin(async move {
                        p.set_active_halt("x", "y", None)
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "set_consent_role",
                "set_consent_role",
                true,
                DirectoryOp::SetConsentRole {
                    key_id: "x".into(),
                    consent_role: Some("y".into()),
                },
                |p| {
                    Box::pin(async move {
                        p.set_consent_role("x", Some("y"))
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "supersede_group_row",
                "supersede_group_row",
                true,
                DirectoryOp::SupersedeGroupRow {
                    cohort: cohort::Cohort::Community,
                    new_snapshot: serde_json::json!({}),
                    authorization: None,
                },
                |p| {
                    Box::pin(async move {
                        p.supersede_group_row(
                            cohort::Cohort::Community,
                            serde_json::json!({}),
                            None,
                        )
                        .await
                        .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "withdraw_location_proof",
                "withdraw_location_proof",
                true,
                DirectoryOp::WithdrawLocationProof {
                    proof: location_proof_1890(),
                },
                |p| {
                    Box::pin(async move {
                        p.withdraw_location_proof(location_proof_1890())
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "list_live_consent_grants_by",
                "list_live_consent_grants_by",
                false,
                DirectoryOp::ListLiveConsentGrantsBy {
                    node_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_live_consent_grants_by("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "list_settled_edition2_roster_proposals",
                "list_settled_edition2_roster_proposals",
                false,
                DirectoryOp::ListSettledEdition2RosterProposals {
                    identity_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_settled_edition2_roster_proposals("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "edition2_roster_proposal",
                "edition2_roster_proposal",
                false,
                DirectoryOp::Edition2RosterProposal {
                    row_id_hex: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.edition2_roster_proposal("x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            // v62.0.0 (L1-fix3; P8-fix5, CC 2.6.1.9) — the second-signer voice
            // reads. Both are trait DEFAULTS composing reads, so the double
            // fails the leaf each one reads first.
            (
                "held_rows_for",
                "fold_dependents",
                false,
                DirectoryOp::HeldRowsFor {
                    key: "x".into(),
                    role: None,
                    after: None,
                    limit: 10,
                },
                |p| {
                    Box::pin(async move {
                        p.held_rows_for("x", None, None, 10)
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "voice_status",
                "get_attestation",
                false,
                DirectoryOp::VoiceStatus { row_id: [9u8; 32] },
                |p| {
                    Box::pin(async move {
                        p.voice_status(&crate::federation::edition2::names::RowId([9u8; 32]))
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            // v62.0.0 (PX-fix1) — the edition-2 and fold store reads: each a
            // leaf (the double delegates it), so the double fails the method
            // itself; with no fault the proxy answers the host's store.
            (
                "edition2_statements_about",
                "edition2_statements_about",
                false,
                DirectoryOp::Edition2StatementsAbout {
                    family: "key:record".into(),
                    sub: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.edition2_statements_about("key:record", "x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "edition2_voices",
                "edition2_voices",
                false,
                DirectoryOp::Edition2Voices { row_id: [9u8; 32] },
                |p| {
                    Box::pin(async move {
                        p.edition2_voices(&crate::federation::edition2::names::RowId([9u8; 32]))
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "edition2_rows_naming",
                "edition2_rows_naming",
                false,
                DirectoryOp::Edition2RowsNaming {
                    named: [9u8; 32],
                    role: "target".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.edition2_rows_naming(
                            &crate::federation::edition2::names::RowId([9u8; 32]),
                            "target",
                        )
                        .await
                        .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "edition2_objects",
                "edition2_objects",
                false,
                DirectoryOp::Edition2Objects {
                    typ: "ceg-genesis-bundle/2".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.edition2_objects("ceg-genesis-bundle/2")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "edition2_statement",
                "edition2_statement",
                false,
                DirectoryOp::Edition2Statement {
                    statement_id: [9u8; 32],
                },
                |p| {
                    Box::pin(async move {
                        p.edition2_statement(&[9u8; 32])
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "edition2_statement_ids_since",
                "edition2_statement_ids_since",
                false,
                DirectoryOp::Edition2StatementIdsSince {
                    after: None,
                    limit: 10,
                },
                |p| {
                    Box::pin(async move {
                        p.edition2_statement_ids_since(None, 10)
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "fold_held",
                "fold_held",
                false,
                DirectoryOp::FoldHeld { row_id: [9u8; 32] },
                |p| {
                    Box::pin(async move {
                        p.fold_held(&crate::federation::edition2::names::RowId([9u8; 32]))
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "fold_held_page",
                "fold_held_page",
                false,
                DirectoryOp::FoldHeldPage {
                    after: None,
                    limit: 10,
                },
                |p| {
                    Box::pin(
                        async move { p.fold_held_page(None, 10).await.map(|v| format!("{v:?}")) },
                    )
                },
            ),
            (
                "fold_dependents",
                "fold_dependents",
                false,
                DirectoryOp::FoldDependents {
                    read_keys: vec!["x".into()],
                },
                |p| {
                    Box::pin(async move {
                        p.fold_dependents(&["x".to_owned()])
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "fold_state",
                "fold_state",
                false,
                DirectoryOp::FoldState { row_id: [9u8; 32] },
                |p| {
                    Box::pin(async move {
                        p.fold_state(&crate::federation::edition2::names::RowId([9u8; 32]))
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "fold_slot_rows",
                "fold_slot_rows",
                false,
                DirectoryOp::FoldSlotRows { slot: "x".into() },
                |p| Box::pin(async move { p.fold_slot_rows("x").await.map(|v| format!("{v:?}")) }),
            ),
            (
                "fold_slot_held",
                "fold_slot_held",
                false,
                DirectoryOp::FoldSlotHeld { slot: "x".into() },
                |p| Box::pin(async move { p.fold_slot_held("x").await.map(|v| format!("{v:?}")) }),
            ),
            (
                "fold_any_refolding",
                "fold_any_refolding",
                false,
                DirectoryOp::FoldAnyRefolding {},
                |p| Box::pin(async move { p.fold_any_refolding().await.map(|v| format!("{v:?}")) }),
            ),
            // v62.0.0 (AU-fix2) — the live admission read: a trait DEFAULT
            // whose first leaf is `edition2_statements_about`.
            (
                "admission_unit_rows",
                "edition2_statements_about",
                false,
                DirectoryOp::AdmissionUnitRows {
                    sub: "x".into(),
                    at_ms: 1_000,
                    owner: None,
                },
                |p| {
                    Box::pin(async move {
                        p.admission_unit_rows(
                            "x",
                            chrono::DateTime::<chrono::Utc>::from_timestamp_millis(1_000)
                                .expect("an instant"),
                            None,
                        )
                        .await
                        .map(|v| format!("{v:?}"))
                    })
                },
            ),
            // v62.0.0 (PX-fix1) — the node-local touch (the retired signed
            // touch's replacement) and its floor.
            (
                "put_touch_claim_local",
                "put_touch_claim_local",
                true,
                DirectoryOp::PutTouchClaimLocal {
                    target_key_id: "x".into(),
                    target_kind: "y".into(),
                    fresh_as_of: at_1890(),
                    cohort_scope: "self".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.put_touch_claim_local("x", "y", at_1890(), "self")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
            (
                "freshness_floor",
                "freshness_floor",
                false,
                DirectoryOp::FreshnessFloor {
                    target_key_id: "x".into(),
                    target_kind: "y".into(),
                },
                |p| {
                    Box::pin(
                        async move { p.freshness_floor("x", "y").await.map(|v| format!("{v:?}")) },
                    )
                },
            ),
            // v62.0.0 (PX-fix3) — the held tips the roster fold reads.
            (
                "list_group_tips",
                "list_group_tips",
                false,
                DirectoryOp::ListGroupTips {
                    cohort: cohort::Cohort::Family,
                    group_key_id: "x".into(),
                },
                |p| {
                    Box::pin(async move {
                        p.list_group_tips(cohort::Cohort::Family, "x")
                            .await
                            .map(|v| format!("{v:?}"))
                    })
                },
            ),
        ];
        // v62.0.0 (L1-fix3) — + `held_rows_for`, `voice_status`; with O1 fix 5's
        // `edition2_roster_proposal` the table is 34 rows (`submit_voice` is
        // I1894's: its first act is a parse, no leaf to fail).
        // v62.0.0 (X2 pass 4d) — 31: F0's CP2 cut deleted the three earlier-form
        // accord doors (`put_accord_proposal` / `_participation` / `_decision`).
        // v62.0.0 (AU-fix2) — + `admission_unit_rows` (45 on the merged
        // file; the count is 4g-regen's to pin).
        // v62.0.0 (PX-fix1) — 44: + the 13 edition-2 and fold store reads.
        // v62.0.0 (PX-fix1) — 46: + the 13 edition-2 and fold store reads, the
        // node-local touch and its floor.
        // v62.0.0 (PX-fix3) — 47: + `list_group_tips`.
        // v62.0.0 (4g-regen) — 48: counted on the merged table.
        assert_eq!(table.len(), 48, "I1890: one row per routed method");
        let mut red = Vec::new();
        for (method, fault, write, op, call) in table {
            let row = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // v62.0.0 (round 6, CP2) — an op that carries an earlier-form
                // signed object is refused by its plane at the capsule, before
                // any directory read, once the doors are shut: through the
                // vtable and through the proxy alike, never `Unsupported`.
                if let Some(plane) = earlier_form_op_plane(&op)
                    .filter(|_| crate::federation::edition2::door::earlier_form_doors_shut())
                {
                    let refused = format!("federation_malformed_row: {plane}: earlier_form_object");
                    let directory = build_persist_directory(inner.clone());
                    match run_op(rt, &directory, &op) {
                        DirectoryOpResult::Err(e) => {
                            assert!(e.starts_with(&refused), "I1890 {method} vtable: {e}")
                        }
                        other => panic!("I1890 {method}: the vtable answered {other:?}"),
                    }
                    // SAFETY: single-drop, matched vtable.
                    unsafe { (directory.vtable.drop)(directory.data) };
                    let proxy = proxy_1244(rt, inner.clone());
                    match rt.block_on(call(proxy as Arc<dyn FederationDirectory>)) {
                        Err(e) => assert!(
                            e.to_string().contains("earlier_form_object")
                                && e.to_string().contains(plane),
                            "I1890 {method} proxy: {e}"
                        ),
                        Ok(v) => panic!("I1890 {method}: the proxy answered Ok({v})"),
                    }
                    return;
                }
                let want = format!("injected backend failure: {fault}");
                let faulty: Arc<dyn FederationDirectory> = Arc::new(
                    crate::federation::directory_double::FaultInjectingDirectory::new(
                        inner.clone(),
                    )
                    .erroring(fault),
                );
                let directory = build_persist_directory(faulty.clone());
                match run_op(rt, &directory, &op) {
                    DirectoryOpResult::Err(e) => {
                        assert!(e.contains(&want), "I1890 {method} vtable: {e}")
                    }
                    other => panic!("I1890 {method}: the vtable answered {other:?}"),
                }
                // SAFETY: single-drop, matched vtable.
                unsafe { (directory.vtable.drop)(directory.data) };
                let proxy = proxy_1244(rt, faulty);
                match rt.block_on(call(proxy as Arc<dyn FederationDirectory>)) {
                    Err(Error::Backend(e)) => {
                        assert!(e.contains(&want), "I1890 {method} proxy: {e}")
                    }
                    other => panic!("I1890 {method}: the proxy answered {other:?}"),
                }
                let clean = proxy_1244(rt, inner.clone());
                let via = rt.block_on(call(clean));
                if let Err(Error::Unsupported { .. }) = via {
                    panic!("I1890 {method}: the proxy still answers Unsupported");
                }
                if let Err(Error::Backend(m)) = &via {
                    assert!(
                        !m.contains("has no DirectoryOp"),
                        "I1890 {method}: no op carries it: {m}"
                    );
                }
                if !write {
                    match (via, rt.block_on(call(inner.clone()))) {
                        (Ok(p), Ok(d)) => assert_eq!(p, d, "I1890 {method}: proxy == direct"),
                        (Err(Error::Backend(p)), Err(d)) => {
                            assert_eq!(p, d.to_string(), "I1890 {method}: the host's own failure")
                        }
                        // v62.0.0 (ABI 14) — a non-`Backend` failure crosses as
                        // `Relayed`, with the host's text and kind.
                        (Err(p @ Error::Relayed { .. }), Err(d)) => {
                            assert_eq!(p.to_string(), d.to_string(), "I1890 {method}: the text");
                            assert_eq!(p.kind(), d.kind(), "I1890 {method}: the kind crosses");
                        }
                        (p, d) => panic!("I1890 {method}: proxy {p:?} vs direct {d:?}"),
                    }
                }
            }));
            if row.is_err() {
                red.push(method);
            }
        }
        assert!(
            red.is_empty(),
            "I1890: these methods did not reach the host: {red:?}"
        );
    }

    /// **I1891 — group-plane writes through the capsule land as direct ones
    /// would.** A keyless room (alice founds, bob seated); THROUGH THE PROXY
    /// carol's widening and bob's revocation arrive as their edition-2
    /// statements (`submit_voice`, the statement door run in persist's
    /// `.so`). The direct backend then holds both rows, and every group read
    /// — the two planes, `list_group_versions`, `list_communities_for_member`,
    /// `lookup_keys_for_identity` — answers the same through the proxy as
    /// directly, non-empty. The earlier-form doors (`add_community_member`,
    /// `put_community_membership_revocation`) are shut (CP2): through the
    /// proxy they answer the host's own refusal, byte for byte.
    fn exercise_i1891(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        use crate::federation::room_roster_invariants::bodies::keyless_room_dir;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{cohort_scope, identity_type};
        let tg = format!("{tag}-1891");
        let (room, alice, bob) = rt.block_on(keyless_room_dir(dir.as_ref(), &tg));
        // v62 (round 3) — carol is an edition-2 key named by her identity-ref,
        // as the room's members are: the growth gate reads her replies by that
        // id (`replies_of`), so a seed-named key with JSON-door consent left
        // the acceptance unresolved. Her seed leads with her name: a test
        // signer seeds from the first 32 bytes, and pg's tag is 32 hex.
        let carol = e2::kid(&format!("carol-{tg}"));
        let joined = at_1890();
        let seat = types::CommunityMember {
            key_id: carol.clone(),
            joined_at: joined,
            role: None,
        };
        let spec = ts::widening_admit_spec(&alice, &room, &seat);
        let revocation = ts::sign_community_membership_revocation(
            &alice,
            CommunityMembershipRevocation {
                community_key_id: room.clone(),
                removed_identity_key_id: bob.clone(),
                removed_at: joined + chrono::Duration::days(1),
                effective_at: joined + chrono::Duration::days(1),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
                leaf: crate::federation::types::RevocationLeaf::Removal,
            },
        );
        let widening = ts::sign_community_membership_widening(
            &alice,
            types::CommunityMembershipWidening {
                community_key_id: room.clone(),
                member_key_id: carol.clone(),
                joined_at: joined,
                effective_at: joined,
                role: None,
                persist_row_hash: String::new(),
            },
        );
        let proxy = proxy_1244(rt, dir.clone());
        rt.block_on(async {
            let d: &dyn FederationDirectory = dir.as_ref();
            e2::put_key(d, &carol, &[identity_type::USER]).await;
            // Carol's consent, as the room-roster witnesses write it: the
            // founder's proposal and her acceptance, each a statement.
            let proposal =
                proposal_row(&alice, cohort_scope::COMMUNITY, &room, &carol, None, joined);
            e2::put_signed(d, &proposal)
                .await
                .expect("I1891: the proposal lands");
            e2::put_signed(d, &acceptance_row(&carol, &proposal, joined))
                .await
                .expect("I1891: the acceptance lands");
            // v62.0.0 (round 6, CP2) — the earlier-form doors are shut: the
            // proxy answers exactly the host's refusal, never `Unsupported`.
            let via = proxy
                .add_community_member(&room, seat.clone(), &spec)
                .await
                .expect_err("I1891: the earlier-form add is refused");
            let direct = d
                .add_community_member(&room, seat, &spec)
                .await
                .expect_err("I1891: refused directly too");
            assert_eq!(
                via.to_string(),
                direct.to_string(),
                "I1891: the host's own refusal"
            );
            assert_eq!(via.kind(), direct.kind(), "I1891: the kind crosses");
            assert!(
                via.to_string().contains("earlier form"),
                "I1891: refused by form: {via}"
            );
            // The writes as they cross now: each statement through the
            // proxy's statement door, naming the room's held head.
            let head = e2::held_head(d, &room).await.map(|(h, _)| h);
            for st in e2::community_widening_voices(&widening, head.as_ref()) {
                proxy
                    .submit_voice(&st)
                    .await
                    .expect("I1891: the widening crosses the capsule");
            }
            let head = e2::held_head(d, &room).await.map(|(h, _)| h);
            for st in e2::community_revocation_voices(&revocation, head.as_ref()) {
                proxy
                    .submit_voice(&st)
                    .await
                    .expect("I1891: the revocation crosses the capsule");
            }
        });
        let ws = rt
            .block_on(dir.list_community_membership_widenings_for(&room))
            .expect("direct widenings");
        let rs = rt
            .block_on(dir.list_community_membership_revocations_for(&room))
            .expect("direct revocations");
        assert_eq!(
            (ws.len(), rs.len()),
            (1, 1),
            "I1891: both rows landed directly"
        );
        assert_eq!(ws[0].member_key_id, carol, "I1891: the widening is carol's");
        assert_eq!(
            rs[0].removed_identity_key_id, bob,
            "I1891: the revocation is bob's"
        );
        let dbg = |r: Result<String, Error>| r.expect("I1891 read");
        // Each read has a seeded non-empty answer, so proxy == direct is never
        // two empty lists agreeing:
        // * `list_group_versions` — the room's live record is its current
        //   version (both backends append the `federation_communities` row);
        // * `list_communities_for_member(alice)` — alice is seated;
        // * `lookup_keys_for_identity(alice)` — `keyless_room_dir` makes
        //   alice's key live, and an edition-2 key row's `identity_ref` is
        //   its own identity-ref (I2000).
        let current = "is_current: true".to_owned();
        for (name, must_name, via, direct) in [
            (
                "list_group_versions",
                &current,
                rt.block_on(proxy.list_group_versions(cohort::Cohort::Community, &room))
                    .map(|v| format!("{v:?}")),
                rt.block_on(dir.list_group_versions(cohort::Cohort::Community, &room))
                    .map(|v| format!("{v:?}")),
            ),
            (
                "list_communities_for_member",
                &room,
                rt.block_on(proxy.list_communities_for_member(&alice))
                    .map(|v| format!("{v:?}")),
                rt.block_on(dir.list_communities_for_member(&alice))
                    .map(|v| format!("{v:?}")),
            ),
            (
                "lookup_keys_for_identity",
                &alice,
                rt.block_on(proxy.lookup_keys_for_identity(&alice))
                    .map(|v| format!("{v:?}")),
                rt.block_on(dir.lookup_keys_for_identity(&alice))
                    .map(|v| format!("{v:?}")),
            ),
        ] {
            let (via, direct) = (dbg(via), dbg(direct));
            assert_ne!(direct, "[]", "I1891 {name}: the seed is not empty");
            assert!(
                direct.contains(must_name.as_str()),
                "I1891 {name}: the seeded answer names {must_name}: {direct}"
            );
            assert_eq!(via, direct, "I1891 {name}: proxy == direct");
        }
    }

    /// **I1894 — a second signer's voice submitted THROUGH the capsule lands
    /// on the host** (`submit_voice`, P8-fix5, CC 2.6.1.9). Its first act is
    /// the statement door's parse, so I1890's fault leg has no leaf to fail;
    /// this witness drives it end to end instead:
    ///
    /// * a statement submitted through the proxy lands in the HOST's store
    ///   (the key it records is live there), and the proxy's `VoiceOutcome`
    ///   is the direct `voice_status` of that row;
    /// * `voice_status` of that row is proxy == direct;
    /// * a malformed statement is the host's own refusal, never
    ///   `Unsupported` or "has no DirectoryOp".
    fn exercise_i1894(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::names::RowId;
        use crate::federation::edition2::second_signer_voice::VoiceOutcome;
        let seed = format!("voice-{tag}-1894");
        let statement = e2::key_record(&seed, &["user"]);
        let proxy = proxy_1244(rt, dir.clone());
        let via = rt
            .block_on(proxy.submit_voice(&statement))
            .expect("I1894: submit_voice routes");
        assert!(
            rt.block_on(dir.lookup_public_key(&e2::kid(&seed)))
                .expect("direct lookup")
                .is_some(),
            "I1894: the statement landed in the host's store"
        );
        let hex_id = match &via {
            VoiceOutcome::Seated { row_id } | VoiceOutcome::Waiting { row_id, .. } => {
                row_id.clone()
            }
        };
        let row_id = RowId(
            <[u8; 32]>::try_from(hex::decode(&hex_id).expect("I1894: a hex row id"))
                .expect("I1894: a 32-byte row id"),
        );
        let direct = rt
            .block_on(dir.voice_status(&row_id))
            .expect("direct voice_status");
        assert_eq!(via, direct, "I1894: the proxy's outcome is the host's");
        assert_eq!(
            rt.block_on(proxy.voice_status(&row_id))
                .expect("I1894: voice_status routes"),
            direct,
            "I1894: voice_status proxy == direct"
        );
        let refused = rt
            .block_on(proxy.submit_voice(b"not a statement"))
            .expect_err("I1894: a malformed voice is refused");
        assert!(
            !matches!(refused, Error::Unsupported { .. })
                && !refused.to_string().contains("has no DirectoryOp"),
            "I1894: the host refused it, not the proxy: {refused}"
        );
        let direct_refusal = rt
            .block_on(dir.submit_voice(b"not a statement"))
            .expect_err("direct refusal");
        // ABI 14: `SubmitVoice` answers with `op_err_typed`, so the text that
        // crosses is the host error's TYPED reading
        // (`{kind}: {plane}: {reason}: {message}`), and its kind crosses too.
        let crossed = match &refused {
            Error::Backend(m) => m.clone(),
            other => other.to_string(),
        };
        assert_eq!(
            crossed,
            typed_error_string(&direct_refusal),
            "I1894: the host's own refusal"
        );
        assert_eq!(
            refused.kind(),
            direct_refusal.kind(),
            "I1894: the kind crosses"
        );
    }

    /// **I1892 — an accord halt set and cleared THROUGH the capsule is the
    /// direct backend's halt.** Before v61.4.2 both writes answered
    /// `Unsupported` on the proxy.
    fn exercise_i1892(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let fam = format!("{tag}-1892-family");
        let proxy = proxy_1244(rt, dir.clone());
        rt.block_on(proxy.set_active_halt(&fam, "halt-1892", None))
            .expect("I1892: set_active_halt routes");
        let set = rt.block_on(dir.get_active_halt(&fam)).expect("direct");
        assert_eq!(
            set.as_ref().map(|h| h.active_halt_id.as_str()),
            Some("halt-1892"),
            "I1892: the direct backend holds the halt"
        );
        rt.block_on(proxy.clear_active_halt(&fam, "halt-1892"))
            .expect("I1892: clear_active_halt routes");
        assert!(
            rt.block_on(dir.get_active_halt(&fam))
                .expect("direct")
                .is_none(),
            "I1892: the direct backend's halt is lifted"
        );
    }

    both_backends_1244!(
        i1762_every_round2_read_reaches_the_host_sqlite,
        i1762_every_round2_read_reaches_the_host_pg,
        |rt, b, tag| {
            let _ = tag;
            exercise_i1762(&rt, b)
        }
    );
    both_backends_1244!(
        i1763_an_active_halt_is_seen_through_the_proxy_sqlite,
        i1763_an_active_halt_is_seen_through_the_proxy_pg,
        |rt, b, tag| exercise_i1763(&rt, b, &tag)
    );
    both_backends_1244!(
        i1764_a_withdrawn_role_is_seen_through_the_proxy_sqlite,
        i1764_a_withdrawn_role_is_seen_through_the_proxy_pg,
        |rt, b, tag| exercise_i1764(&rt, b, &tag)
    );
    both_backends_1244!(
        i1765_a_withdrawn_canonical_is_seen_through_the_proxy_sqlite,
        i1765_a_withdrawn_canonical_is_seen_through_the_proxy_pg,
        |rt, b, tag| exercise_i1765(&rt, b, &tag)
    );
    both_backends_1244!(
        i1769_rooting_row_reads_cross_the_capsule_sqlite,
        i1769_rooting_row_reads_cross_the_capsule_pg,
        |rt, b, tag| exercise_i1769(&rt, b, &tag)
    );
    both_backends_1244!(
        i1770_occurrences_cross_the_capsule_sqlite,
        i1770_occurrences_cross_the_capsule_pg,
        |rt, b, tag| exercise_i1770(&rt, b, &tag)
    );
    both_backends_1244!(
        i1771_settled_self_roster_crosses_the_capsule_sqlite,
        i1771_settled_self_roster_crosses_the_capsule_pg,
        |rt, b, tag| exercise_i1771(&rt, b, &tag)
    );
    both_backends_1244!(
        i1772_cosign_aliases_cross_the_capsule_sqlite,
        i1772_cosign_aliases_cross_the_capsule_pg,
        |rt, b, tag| exercise_i1772(&rt, b, &tag)
    );
    both_backends_1244!(
        i1808_room_membership_planes_cross_the_capsule_sqlite,
        i1808_room_membership_planes_cross_the_capsule_pg,
        |rt, b, tag| exercise_i1808(&rt, b, &tag)
    );
    both_backends_1244!(
        i1890_every_stubbed_method_reaches_the_host_sqlite,
        i1890_every_stubbed_method_reaches_the_host_pg,
        |rt, b, tag| {
            let _ = tag;
            exercise_i1890(&rt, b)
        }
    );
    both_backends_1244!(
        i1891_group_writes_through_the_capsule_land_sqlite,
        i1891_group_writes_through_the_capsule_land_pg,
        |rt, b, tag| exercise_i1891(&rt, b, &tag)
    );
    both_backends_1244!(
        i1892_a_halt_set_through_the_capsule_is_held_sqlite,
        i1892_a_halt_set_through_the_capsule_is_held_pg,
        |rt, b, tag| exercise_i1892(&rt, b, &tag)
    );
    both_backends_1244!(
        i1894_a_voice_submitted_through_the_capsule_lands_sqlite,
        i1894_a_voice_submitted_through_the_capsule_lands_pg,
        |rt, b, tag| exercise_i1894(&rt, b, &tag)
    );

    /// **I1766 / I1767 / I1768 — the sync config reads answer the HOST's
    /// setting**, not the trait default: the node key id, a tightened hardware
    /// policy, and a non-default withdraws depth (sqlite; the setters are the
    /// concrete backend's).
    #[test]
    fn i1766_i1767_i1768_sync_reads_answer_the_hosts_setting_sqlite() {
        let rt = test_runtime();
        let b = sqlite_backend_1244(&rt);
        exercise_sync_reads(
            &rt,
            b.clone(),
            |p| b.set_node_key_id(p),
            |p| b.set_hardware_attestation_policy(Arc::new(p)),
            |d| b.set_withdraws_delegation_depth(d),
        );
    }

    /// I1766–I1768 — postgres arm.
    #[cfg(feature = "postgres")]
    #[test]
    #[serial_test::serial(postgres)]
    fn i1766_i1767_i1768_sync_reads_answer_the_hosts_setting_pg() {
        let rt = test_runtime();
        let Some(b) = pg_backend_1244(&rt) else {
            return;
        };
        exercise_sync_reads(
            &rt,
            b.clone(),
            |p| b.set_node_key_id(p),
            |p| b.set_hardware_attestation_policy(Arc::new(p)),
            |d| b.set_withdraws_delegation_depth(d),
        );
    }

    fn exercise_sync_reads(
        rt: &Arc<tokio::runtime::Runtime>,
        dir: Arc<dyn FederationDirectory>,
        set_node: impl Fn(&str),
        set_policy: impl Fn(crate::federation::HardwareAttestationPolicy),
        set_depth: impl Fn(usize),
    ) {
        let proxy = proxy_1244(rt, dir.clone());
        let mut red = Vec::new();
        let mut check = |id: &'static str, f: &dyn Fn()| {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err() {
                red.push(id);
            }
        };
        set_node("node-1766");
        set_depth(2);
        let mut tight = crate::federation::HardwareAttestationPolicy::default();
        tight.accepted_custody_tiers.clear();
        tight.max_nonce_age = std::time::Duration::from_secs(60);
        set_policy(tight.clone());
        check("I1766", &|| {
            // I1766 — the node key id.
            assert_eq!(
                dir.node_key_id().as_deref(),
                Some("node-1766"),
                "I1766 seed"
            );
            assert_eq!(
                proxy.node_key_id(),
                dir.node_key_id(),
                "I1766: the proxy answers the host's node key"
            );
        });
        check("I1767", &|| {
            // I1767 — a tightened policy (no custody tiers, a short nonce age).
            assert_ne!(
                tight,
                crate::federation::HardwareAttestationPolicy::default()
            );
            assert_eq!(
                *proxy.hardware_attestation_policy(),
                tight,
                "I1767: the host's policy, not the default"
            );
        });
        check("I1768", &|| {
            // I1768 — a non-default withdraws depth.
            assert_eq!(dir.withdraws_delegation_depth(), 2, "I1768 seed");
            assert_eq!(
                proxy.withdraws_delegation_depth(),
                2,
                "I1768: the host's depth, not the default"
            );
        });
        assert!(
            red.is_empty(),
            "sync reads answered something other than the host's setting: {red:?}"
        );
    }

    /// **I1773 — a sync read that cannot reach the host answers FAIL-CLOSED**:
    /// a node key id no row names (an audience check refuses), a policy that
    /// accepts no evidence, and depth 0 — never the trait's permissive default.
    #[test]
    fn i1773_an_unreachable_host_fails_closed() {
        unsafe extern "C" fn err_build_op(
            _data: *mut c_void,
            _op_ptr: *const u8,
            _op_len: usize,
            cb: ResultCallback,
            ctx: *mut c_void,
        ) -> *mut TaskOpaque {
            let bytes =
                serde_json::to_vec(&DirectoryOpResult::Err("host unreachable".into())).unwrap();
            // SAFETY: the callback contract — fired once with readable bytes.
            unsafe { cb(ctx, bytes.as_ptr(), bytes.len()) };
            let fut: BoxedFut = Box::pin(async {});
            Box::into_raw(Box::new(fut)) as *mut TaskOpaque
        }
        unsafe extern "C" fn noop_drop(_: *mut c_void) {}
        static ERRING: DirectoryVTable = DirectoryVTable {
            abi_version: DIRECTORY_ABI_VERSION,
            _reserved: 0,
            build_op: err_build_op,
            drop: noop_drop,
        };
        let rt = test_runtime();
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy = build_ops_directory_proxy(
            Directory {
                data: std::ptr::null_mut(),
                vtable: &ERRING,
            },
            executor,
        )
        .expect("abi ok");
        assert_eq!(
            proxy.node_key_id().as_deref(),
            Some(NODE_KEY_ID_UNAVAILABLE),
            "I1773 node key"
        );
        let p = proxy.hardware_attestation_policy();
        assert_eq!(*p, refuse_all_hardware_attestation_policy(), "I1773 policy");
        assert!(p.accepted_hardware_types.is_empty() && p.accepted_custody_tiers.is_empty());
        assert_eq!(proxy.withdraws_delegation_depth(), 0, "I1773 depth");
    }

    // ── I1774 (CIRISPersist#1268) — the trust walk, concrete vs proxy ──

    /// One answer, as the harness compares it: the `Ok` value's debug form,
    /// any error as `Err` (the proxy flattens error variants), and an
    /// `Unsupported` named, so reaching one is a red of its own.
    fn answer_1774<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
        match r {
            Ok(v) => format!("{v:?}"),
            Err(Error::Unsupported { method }) => format!("UNSUPPORTED({method})"),
            Err(e) if e.to_string().contains("ops_proxy_unsupported") => {
                format!("UNSUPPORTED({e})")
            }
            Err(_) => "Err".to_owned(),
        }
    }

    /// The policy in a canonical form (its sets sorted: two equal
    /// `HashSet`s need not iterate alike).
    fn policy_1774(p: &crate::federation::HardwareAttestationPolicy) -> String {
        let mut hw: Vec<String> = p
            .accepted_hardware_types
            .iter()
            .map(|t| format!("{t:?}"))
            .collect();
        hw.sort();
        let mut tiers: Vec<&String> = p.accepted_custody_tiers.iter().collect();
        tiers.sort();
        format!(
            "{hw:?} {:?} {tiers:?} {:?} {:?}",
            p.max_nonce_age, p.yubico_root_der, p.android_root_ders
        )
    }

    /// The trust questions the harness asks of one directory.
    /// v62.0.0 (JSON cut, E7) — the I1774 fixture's identity-refs and ids:
    /// this node (the asking party), W1b's rooted trust root and its subject,
    /// E9's chartered root and its subject, the withdraws and its target.
    struct Eq1774 {
        node: String,
        root: String,
        subject_a: String,
        root_f: String,
        subject_f: String,
        holder: String,
        wid: String,
        target: String,
    }

    async fn trust_questions_1774(
        d: &dyn FederationDirectory,
        q: &Eq1774,
    ) -> Vec<(&'static str, String)> {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, trust_root_valid, INFRA_SERVE_SCOPE,
        };
        vec![
            (
                "trust_root_valid bundle root",
                answer_1774(trust_root_valid(d, &q.node, &q.root, crate::host::clock::now()).await),
            ),
            (
                "trust_root_valid self root",
                answer_1774(trust_root_valid(d, &q.node, &q.node, crate::host::clock::now()).await),
            ),
            (
                "trust_root_valid unknown root",
                answer_1774(
                    trust_root_valid(d, &q.node, "eq-nobody", crate::host::clock::now()).await,
                ),
            ),
            (
                "capability bundle root",
                answer_1774(
                    capability_roots_to_trusted_root(
                        d,
                        &q.node,
                        &q.subject_a,
                        INFRA_SERVE_SCOPE,
                        crate::host::clock::now(),
                    )
                    .await,
                ),
            ),
            (
                "capability second subject",
                answer_1774(
                    capability_roots_to_trusted_root(
                        d,
                        &q.node,
                        &q.subject_f,
                        INFRA_SERVE_SCOPE,
                        crate::host::clock::now(),
                    )
                    .await,
                ),
            ),
            (
                "get_active_halt",
                answer_1774(d.get_active_halt(&q.root_f).await),
            ),
            (
                "lookup_role_withdrawal",
                answer_1774(d.lookup_role_withdrawal("steward", &q.subject_f).await),
            ),
            (
                "lookup_canonical_withdrawal",
                answer_1774(d.lookup_canonical_withdrawal(&q.subject_f).await),
            ),
            (
                "owner_of",
                answer_1774(crate::federation::admission::owner_of(d, &q.subject_f).await),
            ),
            (
                "list_attestations_referencing",
                answer_1774(d.list_attestations_referencing(&q.target).await),
            ),
            (
                "get_attestation",
                answer_1774(d.get_attestation(&q.wid).await),
            ),
            (
                "list_settled_self_roster_proposals",
                answer_1774(d.list_settled_self_roster_proposals(&q.node).await),
            ),
            (
                "list_identity_occurrences_for",
                answer_1774(d.list_identity_occurrences_for(&q.node).await),
            ),
            (
                "list_identity_occurrence_revocations_for",
                answer_1774(d.list_identity_occurrence_revocations_for(&q.node).await),
            ),
            (
                "lookup_family",
                answer_1774(d.lookup_family(&q.root_f).await),
            ),
            (
                "list_families_for_member",
                answer_1774(d.list_families_for_member(&q.holder).await),
            ),
            (
                "lookup_community",
                answer_1774(d.lookup_community(&q.root).await),
            ),
            (
                "lookup_signed_community",
                answer_1774(d.lookup_signed_community(&q.root).await),
            ),
            (
                "family_roster_signers",
                answer_1774(d.family_roster_signers(&q.root_f).await),
            ),
            (
                "community_roster_signers",
                answer_1774(d.community_roster_signers(&q.root).await),
            ),
            (
                "hardware_attestation_policy",
                policy_1774(&d.hardware_attestation_policy()),
            ),
            ("node_key_id", format!("{:?}", d.node_key_id())),
            (
                "withdraws_delegation_depth",
                format!("{:?}", d.withdraws_delegation_depth()),
            ),
        ]
    }

    /// Ask both, and return every difference (and every `Unsupported`).
    fn diff_1774(
        rt: &Arc<tokio::runtime::Runtime>,
        concrete: &Arc<dyn FederationDirectory>,
        proxy: &Arc<OpsDirectory>,
        q: &Eq1774,
        phase: &str,
    ) -> (Vec<String>, Vec<(&'static str, String)>) {
        let want = rt.block_on(trust_questions_1774(concrete.as_ref(), q));
        let got = rt.block_on(trust_questions_1774(proxy.as_ref(), q));
        let mut red = Vec::new();
        for ((q, w), (_, g)) in want.iter().zip(&got) {
            if g.starts_with("UNSUPPORTED") || w.starts_with("UNSUPPORTED") {
                red.push(format!(
                    "{phase} / {q}: Unsupported reached: {g} (concrete {w})"
                ));
            } else if w != g {
                red.push(format!("{phase} / {q}: concrete {w}\n    proxy    {g}"));
            }
        }
        (red, want)
    }

    /// **I1774 (CIRISPersist#1268) — the trust walk answers the same through
    /// the proxy as on the concrete backend.** One store holds a key root
    /// (`exercise_trust_root`), a family-quorum root
    /// (`seed_chartered_family_root`, `quorum:2/3`) and the `ciris-canonical` community
    /// root, plus a `withdraws` row. The same trust questions — the
    /// `trust_root_valid` and conferral walks over each root, the halt, role
    /// and canonical-withdrawal reads, and the rooting reads — run on the
    /// backend and on `build_ops_directory_proxy` over its capsule, in three
    /// phases: as seeded; with an active halt, a withdrawn role and a
    /// withdrawn canonical; and with the halt lifted. Any difference, or any
    /// `Unsupported` reached, is red. It does not list the methods the walks
    /// reach: it finds them.
    ///
    /// v62.0.0 (JSON cut, E7) — the roots are edition 2: W1b's rooted trust
    /// root (`put_conferral` to its subject); the asking party is THIS node
    /// (the runner sets its key). v62.0.0 (R2-fixture; CC 3.2 T5): E9's
    /// chartered KEYED root (`seed_chartered_e2_root`, `confer_e2`) is deleted
    /// with the keyed root; the bundle's lineage is the one root, so the
    /// "family-quorum root" questions go and the halt, role and roster reads
    /// ask about the lineage and a second conferred subject. The `ciris-canonical` community
    /// arm is gone (wave-3 rule 1: canonical = `serve_nodes` of the bundle in
    /// force). The withdraws names a HELD row (`seed_withdraws_e2`).
    fn exercise_i1774(rt: &Arc<tokio::runtime::Runtime>, concrete: Arc<dyn FederationDirectory>) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::trust_root::INFRA_SERVE_SCOPE;
        let q = rt.block_on(async {
            let node = concrete
                .node_key_id()
                .expect("the runner sets the node key first");
            let r = e2::rooted_trust_root(
                concrete.as_ref(),
                &crate::federation::edition2::fixture_genesis::HOLDER_SEEDS,
                "quorum:2/3",
            )
            .await;
            crate::federation::edition2::fixture_trust_root::put_conferral(
                concrete.as_ref(),
                &r,
                "eqa-subject",
                &[INFRA_SERVE_SCOPE],
            )
            .await
            .expect("the key root confers");
            crate::federation::edition2::fixture_trust_root::put_conferral(
                concrete.as_ref(),
                &r,
                "eqf-subject",
                &[INFRA_SERVE_SCOPE],
            )
            .await
            .expect("the root confers on a second subject");
            Eq1774 {
                node,
                root: r.lineage.clone(),
                subject_a: e2::kid("eqa-subject"),
                holder: r.founders.first().cloned().unwrap_or_default(),
                root_f: r.lineage.clone(),
                subject_f: e2::kid("eqf-subject"),
                wid: String::new(),
                target: String::new(),
            }
        });
        let (wid, target) = seed_withdraws_e2(rt, concrete.as_ref(), "eq-issuer", "eq-target");
        let q = Eq1774 { wid, target, ..q };
        let proxy = proxy_1244(rt, concrete.clone());

        let mut red = Vec::new();
        let (r, seeded) = diff_1774(rt, &concrete, &proxy, &q, "seeded");
        red.extend(r);
        // The fixture is not trivial: the root answers VALID.
        for name in ["trust_root_valid bundle root"] {
            let a = &seeded.iter().find(|(n, _)| *n == name).unwrap().1;
            assert!(
                a.contains("valid: true"),
                "I1774 fixture: {name} is not valid: {a}"
            );
        }

        rt.block_on(async {
            concrete
                .set_active_halt(&q.root_f, "eq-halt", None)
                .await
                .unwrap();
            concrete
                .record_role_withdrawal("steward", &q.subject_f, None, "eq-digest")
                .await
                .unwrap();
            // v62.0.0 (TR-fix2): no canonical tombstone can be written (a
            // later genesis bundle withdraws a canonical, CC 4.2.1).
        });
        let (r, _) = diff_1774(rt, &concrete, &proxy, &q, "halted+withdrawn");
        red.extend(r);
        // v62.0.0 — a halt is reported, not a gate on trust (CC 4.2.1.1); only
        // proxy/concrete agreement is asserted here.

        rt.block_on(concrete.clear_active_halt(&q.root_f, "eq-halt"))
            .unwrap();
        let (r, _) = diff_1774(rt, &concrete, &proxy, &q, "halt lifted");
        red.extend(r);

        assert!(
            red.is_empty(),
            "I1774: the proxy answers differently:\n{}",
            red.join("\n")
        );
    }

    #[test]
    fn i1774_the_trust_walk_answers_the_same_through_the_proxy_sqlite() {
        let rt = test_runtime();
        let b = sqlite_backend_1244(&rt);
        // v62.0.0 (W1b precondition) — this node's key, set before the fixture.
        let node = rt.block_on(crate::federation::edition2::fixture_switch::put_key(
            b.as_ref(),
            "eq-node",
            &[crate::federation::types::identity_type::NODE],
        ));
        b.set_node_key_id(node);
        exercise_i1774(&rt, b);
    }

    /// I1774 — postgres arm, in a database of its own (the community fixture
    /// uses fixed key ids).
    #[cfg(feature = "postgres")]
    #[test]
    fn i1774_the_trust_walk_answers_the_same_through_the_proxy_pg() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = test_runtime();
        let b = rt.block_on(async {
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            let node = crate::federation::edition2::fixture_switch::put_key(
                &b,
                "eq-node",
                &[crate::federation::types::identity_type::NODE],
            )
            .await;
            b.set_node_key_id(node);
            b
        });
        exercise_i1774(&rt, Arc::new(b));
    }

    /// CIRISPersist#1162 — every field of the query and of its rows crosses
    /// the capsule's JSON as itself, and an unknown field is a refusal: a
    /// newer consumer's narrowing that an older host silently dropped would
    /// run a WIDER read than the one asked for.
    #[test]
    fn i1162_attestation_query_serde_round_trips_every_field() {
        use crate::federation::attestation_query::{
            page_size, AttestationQuery, QueryOrder, QueryRows, QueryTier,
        };
        let q = AttestationQuery::to("k-to", page_size(7))
            .authored_by("k-by")
            .dimension_any_of(&["a", "b"])
            .types(&["delegates_to"])
            .type_prefix("dele")
            .excluding_dimensions(&["x"])
            .tier(QueryTier::Local)
            .oldest_first()
            .as_of("2026-10-30T00:00:00Z".parse().unwrap())
            .scope("community", Some("c-1"))
            .after(Some(
                crate::ceg::list::federation::AttestationCursor::from_trailing(
                    "2026-10-29T00:00:00Z".parse().unwrap(),
                    "row-1".into(),
                ),
            ));
        assert_eq!(
            q.order,
            QueryOrder::ByAssertedAt(crate::federation::attestation_query::Direction::Asc)
        );
        let op = DirectoryOp::ExecuteAttestationQuery { query: q.clone() };
        match serde_json::from_slice::<DirectoryOp>(&serde_json::to_vec(&op).unwrap()).unwrap() {
            DirectoryOp::ExecuteAttestationQuery { query } => assert_eq!(query, q),
            other => panic!("{other:?}"),
        }
        let mut v = serde_json::to_value(&q).unwrap();
        v["widened_by_a_newer_consumer"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<AttestationQuery>(v).is_err(),
            "an unknown query field must refuse, never drop"
        );
        let mut v = serde_json::to_value(&q).unwrap();
        v["limit"] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<AttestationQuery>(v).is_err(),
            "a zero page is not a page"
        );
        let rows = QueryRows {
            rows: Vec::new(),
            bytes: 42,
            backend: crate::observe::StoreBackend::Postgres,
        };
        let back: QueryRows = serde_json::from_slice(&serde_json::to_vec(&rows).unwrap()).unwrap();
        assert_eq!((back.bytes, back.backend), (42, rows.backend));
    }

    /// The `fn` items at the top level of the `{…}` body that opens after
    /// `anchor` in `blanked` (comments and string contents blanked): each
    /// name with its body, or `None` for a bodiless (required) declaration.
    fn top_level_fns(blanked: &str, anchor: &str) -> BTreeMap<String, Option<String>> {
        let start = blanked
            .find(anchor)
            .unwrap_or_else(|| panic!("`{anchor}` not found — the scan's recognizer broke"));
        let b = blanked.as_bytes();
        let open = start + blanked[start..].find('{').expect("body");
        // The span of the `{…}` block opening at `at`.
        let block_end = |at: usize| -> usize {
            let mut depth = 0i32;
            for (i, &c) in b.iter().enumerate().skip(at) {
                match c {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return i;
                        }
                    }
                    _ => {}
                }
            }
            panic!("unterminated block at {at}");
        };
        let end = block_end(open);
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut out = BTreeMap::new();
        let mut i = open + 1;
        while i < end {
            match b[i] {
                // A nested block that is not an fn body (an attribute's
                // tokens never hold braces): skip it whole.
                b'{' => i = block_end(i) + 1,
                b'f' if b[i..].starts_with(b"fn ") && (i == 0 || !ident(b[i - 1])) => {
                    let name_at = i + 3;
                    let name_len = b[name_at..].iter().take_while(|&&c| ident(c)).count();
                    let name = blanked[name_at..name_at + name_len].to_owned();
                    // The signature ends at the first `;` or `{` outside
                    // parens/brackets (`[u8; 32]` holds a `;`).
                    let mut depth = 0i32;
                    let mut j = name_at + name_len;
                    loop {
                        match b[j] {
                            b'(' | b'[' => depth += 1,
                            b')' | b']' => depth -= 1,
                            b';' if depth == 0 => {
                                out.insert(name, None);
                                i = j + 1;
                                break;
                            }
                            b'{' if depth == 0 => {
                                let close = block_end(j);
                                out.insert(name, Some(blanked[j..=close].to_owned()));
                                i = close + 1;
                                break;
                            }
                            _ => {}
                        }
                        j += 1;
                    }
                }
                _ => i += 1,
            }
        }
        out
    }

    /// The reasons a `FederationDirectory` method may answer `Unsupported`
    /// on the capsule proxy. A method on this list is a KNOWN gap with its
    /// reason, never a silent one.
    const COSIGN_1252: &str = "v61.3.0 (#1252): a node-local cosign ledger or projection read; \
                               a proxy holds no store of its own, and every caller treats \
                               Unsupported as nothing held";
    const INHERITED_DEFAULT: &str = "the trait DEFAULT answers Unsupported for any backend that \
                                     does not override it; the proxy inherits it (pre-existing \
                                     at v59.1.1)";
    const GROUP_ROWS_991: &str = "v61 (#991): the framed kind is retired and its op left the \
                                  capsule at ABI 12; the record replicates as its group-plane \
                                  row through ApplyReplicatedAttestation";
    const DOOR_HOOK_PX: &str = "v62.0.0 (PX-fix1): a write hook the host's own doors run \
                                (the door crosses as its op and runs in persist's .so over \
                                the host's store); its default was a silent Ok(()), so a door \
                                composed over the proxy claimed a write it never made";
    const REFUSED_DEFAULT_PX: &str = "v62.0.0 (PX-fix1): the trait default answered \
                                      Err(Backend(..)) through the proxy; an unrouted method \
                                      now fails Unsupported and nothing else (I2180); no \
                                      call in CIRISEdge's production code reaches it (I1893)";
    const RETIRED_FOR_EDGE_PX: &str = "v62.0.0 (PX-fix2): an earlier-form verb CIRISEdge v45.1.6 \
                                       calls; retired from the capsule, its Unsupported names \
                                       the edition-2 replacement (EDGE_RETIRED_VERBS, I1893)";
    const PROXY_UNSUPPORTED_ALLOWLIST: &[(&str, &str)] = &[
        // v62.0.0 (PX-fix1) — the four Edge verbs retired from the capsule.
        ("record_canonical_withdrawal", RETIRED_FOR_EDGE_PX),
        ("record_role_withdrawal", RETIRED_FOR_EDGE_PX),
        ("put_touch_claim", RETIRED_FOR_EDGE_PX),
        ("put_identity_occurrence_local", RETIRED_FOR_EDGE_PX),
        // v62.0.0 (WD-fix9; WD-fix11: `cfg(test)` only, never in a
        // `test-anchor` build) — a TEST seam: the storage the retired
        // trusted-local write had; no op carries it.
        (
            "test_seam_put_identity_occurrence",
            "v62.0.0 (WD-fix9) — test-only seeding of an occurrence row (the retired \
             trusted-local write's storage); never compiled into a production build",
        ),
        // v62.0.0 (PX-fix1) — the `Err(Backend)` defaults, now refusing.
        ("put_edition2_object", REFUSED_DEFAULT_PX),
        ("put_edition2_statement", REFUSED_DEFAULT_PX),
        ("upsert_edition2_key_projection", REFUSED_DEFAULT_PX),
        ("put_family_local", REFUSED_DEFAULT_PX),
        // v62.0.0 (WD-fix8) — the retired trusted-local revocation now refuses
        // by name on every directory (not `Unsupported`); its store is the
        // edition-2 eviction door's, which runs on the host's store.
        (
            "put_identity_occurrence_revocation_edition2",
            "v62.0.0 (WD-fix8) — the edition-2 occurrence revocation is written by the \
             node's own eviction door (`edition2::typed` / `occurrence::land_held_eviction`), \
             reached through `put_edition2_statement`; no DirectoryOp carries the typed write",
        ),
        ("grant_trust", REFUSED_DEFAULT_PX),
        ("revoke_trust", REFUSED_DEFAULT_PX),
        ("lookup_trust", REFUSED_DEFAULT_PX),
        ("list_trusted_keys", REFUSED_DEFAULT_PX),
        ("get_goal", REFUSED_DEFAULT_PX),
        ("list_goals", REFUSED_DEFAULT_PX),
        (
            "list_transport_destinations_for_unfolded",
            REFUSED_DEFAULT_PX,
        ),
        ("remove_transport_destination", REFUSED_DEFAULT_PX),
        ("lookup_freshness_floor", REFUSED_DEFAULT_PX),
        ("record_hard_case", REFUSED_DEFAULT_PX),
        ("list_hard_case_events", REFUSED_DEFAULT_PX),
        ("put_wholeness_witness", REFUSED_DEFAULT_PX),
        ("list_wholeness_witnesses_for_peer", REFUSED_DEFAULT_PX),
        ("last_witness_epoch_for_peer", REFUSED_DEFAULT_PX),
        ("list_witness_peer_ids", REFUSED_DEFAULT_PX),
        ("list_consent_revocations", REFUSED_DEFAULT_PX),
        // v62.0.0 (PX-fix1) — the silent no-op hooks, now refusing.
        ("rewrap_own_epochs_for_device", DOOR_HOOK_PX),
        ("project_key_grant_row", DOOR_HOOK_PX),
        ("purge_attestation_projections", DOOR_HOOK_PX),
        (
            "drop_group_tips",
            "v62.0.0 (wave T1): the merge's tip retirement is the edition-2 \
          roster door's own write; no DirectoryOp carries it",
        ),
        (
            "put_group_lineage_end",
            "v62.0.0 (LINEAGE-L3d): a lineage end is the edition-2 group door's own \
          write, reached through `put_edition2_statement`; no DirectoryOp carries it",
        ),
        (
            "put_group_lineage_node",
            "v62.0.0 (LINEAGE-L1): a lineage node is the edition-2 group door's own \
          write, reached through `put_edition2_statement`; no DirectoryOp carries it",
        ),
        // v61 (CIRISPersist#991): the group framed kinds retired; their ops
        // left the capsule at ABI 12 and the records replicate as rows.
        ("apply_replicated_community", GROUP_ROWS_991),
        ("list_signed_families_since", GROUP_ROWS_991),
        ("list_signed_communities_since", GROUP_ROWS_991),
        (
            "list_signed_family_membership_revocations_since",
            GROUP_ROWS_991,
        ),
        (
            "list_signed_family_membership_widenings_since",
            GROUP_ROWS_991,
        ),
        (
            "list_signed_community_membership_revocations_since",
            GROUP_ROWS_991,
        ),
        (
            "list_signed_community_membership_widenings_since",
            GROUP_ROWS_991,
        ),
        // Trait defaults the proxy does not override.
        ("store_rebound_key_record", INHERITED_DEFAULT),
        ("store_invalid_replaced_key_record", INHERITED_DEFAULT),
        ("list_key_registration_history", INHERITED_DEFAULT),
        ("list_derived_hex", INHERITED_DEFAULT),
        ("list_attestations_citing_by_dimension", INHERITED_DEFAULT),
        ("list_consent_peers_for", INHERITED_DEFAULT),
        ("list_live_consent_grants_for", INHERITED_DEFAULT),
        ("list_local_tier_attestations", INHERITED_DEFAULT),
        ("list_widening_candidates", INHERITED_DEFAULT),
        ("list_attestations_for_migration", INHERITED_DEFAULT),
        ("reseal_attestation_v31", INHERITED_DEFAULT),
        ("list_expired_attestation_ids", INHERITED_DEFAULT),
        ("purge_attestation_v31", INHERITED_DEFAULT),
        ("note_self_roster_proposal", INHERITED_DEFAULT),
        ("list_open_self_roster_proposals", INHERITED_DEFAULT),
        ("settle_self_roster_proposal", INHERITED_DEFAULT),
        // v62.0.0 (CONTENT-A4) — the room-content series index: a host drafts
        // on its own store; through the proxy a draft names no predecessor
        // (a conformant first row of a branch, CC rc22 3.1.3.2).
        ("edition2_room_series", INHERITED_DEFAULT),
        ("edition2_room_tips", INHERITED_DEFAULT),
        ("edition2_held_bound_put", INHERITED_DEFAULT),
        ("edition2_held_bound_remove", INHERITED_DEFAULT),
        ("edition2_held_bound_usage", INHERITED_DEFAULT),
        ("edition2_held_bound_expired", INHERITED_DEFAULT),
        ("edition2_content_ends", INHERITED_DEFAULT),
        ("edition2_put_content_answers", INHERITED_DEFAULT),
        ("edition2_put_content_answer", INHERITED_DEFAULT),
        ("edition2_content_answer", INHERITED_DEFAULT),
        // v61.3.0 (CIRISPersist#1252) — the cosign hold's node-local ledgers
        // and the group pointer read: a proxy has no store of its own, so no
        // hold is taken behind one (`cosign::hold` needs the receipt).
        ("cosign_receipt", COSIGN_1252),
        ("list_open_cosign_receipts", COSIGN_1252),
        ("settle_cosign_receipt", COSIGN_1252),
        ("list_cosign_signatures", COSIGN_1252),
        ("drop_cosign_rows", COSIGN_1252),
        ("note_cosign_alias", COSIGN_1252),
        ("read_group_plane_object", COSIGN_1252),
        // v62.0.0 (AU-fix1) — node-local: when THIS node first held a row,
        // read only by the host's answer, which runs host-side (the
        // `AdmissionUnitRunnable` op); a proxy holds no store.
        (
            "edition2_first_held_us",
            "v62.0.0 (AU-fix1): node-local first-held instant of a row; the host's admission \
             answer reads it on the host's own store, never through a proxy",
        ),
        ("purge_scan_attestations", INHERITED_DEFAULT),
        ("purge_trace_ids_for_llm_model", INHERITED_DEFAULT),
        ("purge_trace_ids_signed_by", INHERITED_DEFAULT),
        ("purge_trace_row_counts", INHERITED_DEFAULT),
        ("purge_put_execution", INHERITED_DEFAULT),
        ("purge_execution", INHERITED_DEFAULT),
        ("purge_tombstones_of", INHERITED_DEFAULT),
        ("list_purge_executions_since", INHERITED_DEFAULT),
        ("purge_delete_tombstoned_attestation", INHERITED_DEFAULT),
        ("purge_delete_tombstoned_trace", INHERITED_DEFAULT),
        // v62.0.0 (WD-fix1) — the withdrawn-content sweep's read and the
        // descent's statement delete: the host's own store's, never proxied.
        ("list_withdrawals_since", INHERITED_DEFAULT),
        ("purge_delete_tombstoned_statements", INHERITED_DEFAULT),
        ("purge_mark_finalized", INHERITED_DEFAULT),
        (
            "put_identity_occurrence_edition2",
            "v62.0.0 (wave O1) — the edition-2 occurrence bind is written by the \
             node's own door (`edition2::occurrence::put_occurrence_voice`), reached \
             through `put_edition2_statement`; no DirectoryOp carries the typed write",
        ),
        (
            "store_projected_trust",
            "v62.0.0 (wave T2) — the v1.3 trust plane's row re-derived from a held \
             trust:accepts edge by the node's own door (`edition2::typed`); no DirectoryOp \
             carries the projection write",
        ),
        (
            "retract_projected_trust",
            "v62.0.0 (wave T2) — the expiry of a projected trust row on the granter's \
             withdraws, by the node's own door (`edition2::typed`); no DirectoryOp carries it",
        ),
        (
            "put_delivery_receipt_edition2",
            "v62.0.0 (wave T2) — an edition-2 delivery receipt's typed write is the \
             node's own door (`edition2::typed`), reached through \
             `put_edition2_statement`; no DirectoryOp carries the typed write",
        ),
        (
            "put_edition2_genesis",
            "v62.0.0 (C1) — the genesis bundle's one-transaction write is the \
             node's own door (`edition2::genesis::put_genesis_bundle`); no DirectoryOp \
             carries a bundle's GenesisWrite",
        ),
        // v62.0.0 (PX-fix1) — `put_touch_claim_local` and `freshness_floor`
        // left this list: routed (`PutTouchClaimLocal`, `FreshnessFloor`).
        (
            "put_fold_record",
            "v62.0.0 (wave G0; CC 2.7.3) — the fold's record of a held row is written \
             by the node's own door (`edition2::fold`), reached through \
             `put_edition2_statement`; no DirectoryOp carries it",
        ),
        (
            "recheck_attestation",
            "v62.0.0 (wave G0) — the fold's re-check of a concluded row runs the plan in \
             the process that owns the store (`edition2::fold`); no DirectoryOp carries it",
        ),
        (
            "put_fold_reason",
            "v62.0.0 (wave G0 fix4) — the re-fold's marker and its restore run in the \
             process that owns the store (`edition2::fold`); no DirectoryOp carries it",
        ),
        (
            "fold_slot_all_rows",
            "v62.0.0 (GID-tips) — the roster door's read of every row under one group id \
             runs in the process that owns the store (`edition2::group`, inside the \
             statement door the proxy carries whole); no DirectoryOp carries it",
        ),
        (
            "drop_held_row",
            "v62.0.0 (KR-fix20) — the door's drop of a held row it now refuses for good \
             runs in the process that owns the store (`edition2::ingest`, \
             `edition2::fold`); no DirectoryOp carries it",
        ),
        // v62.0.0 (RL-fix1, ruling (B)) — the accord-rescan watermark store
        // is written and read by the free doors persist runs over its own
        // directory (`ApplyReplicatedStatementAtFeed`, `AccordRescanNeeded`,
        // `AckAccordRescan`); the proxy holds no store of its own.
        (
            "note_accord_skip",
            "v62.0.0 (RL-fix1) — written by `apply_replicated_statement_at_feed` in the \
             process that owns the store; the consumer sends ApplyReplicatedStatementAtFeed",
        ),
        (
            "accord_skips",
            "v62.0.0 (RL-fix1) — read by `accord_rescan::rescan_needed` in the process that \
             owns the store; the consumer sends AccordRescanNeeded",
        ),
        (
            "put_dial_hints",
            "v62.0.0 (RL-fix3) — written by `contact::record_dial_hints` in the process that \
             owns the store; the consumer sends RecordDialHints",
        ),
        (
            "dial_hints_for",
            "v62.0.0 (RL-fix3) — read in the process that owns the store; the consumer sends \
             DialHintsFor",
        ),
        (
            "list_dial_hints",
            "v62.0.0 (RL-fix3) — read in the process that owns the store; the consumer sends \
             ListDialHints",
        ),
        (
            "remove_dial_hints",
            "v62.0.0 (RL-fix3) — removed in the process that owns the store; the consumer \
             sends RemoveDialHints",
        ),
        (
            "clear_accord_skip",
            "v62.0.0 (RL-fix1) — cleared by `accord_rescan::ack_rescan` in the process that \
             owns the store; the consumer sends AckAccordRescan",
        ),
        (
            "clear_occurrence_projection",
            "v62.0.0 (wave G0 v4) — the occurrence plane's un-project hook runs in the \
             process that owns the store (`edition2::fold::Plane`); no DirectoryOp carries it",
        ),
        (
            "unconclude_attestation",
            "v62.0.0 (wave G0) — the fold takes a row it no longer concludes out of its \
             typed table in the process that owns the store; no DirectoryOp carries it",
        ),
        (
            "note_edition2_roster_proposal",
            "v62.0.0 (O1) — THIS node's receipt of an edition-2 self-roster \
             proposal (ceg_roster_proposals), written by its own occurrence door; no DirectoryOp \
             carries it",
        ),
        (
            "settle_edition2_roster_proposal",
            "v62.0.0 (O1) — settles THIS node's held self-roster proposal \
             (the two paths, CC 3.3.6.4); node-local, no DirectoryOp carries it",
        ),
        (
            "list_open_edition2_roster_proposals",
            "v62.0.0 (O1) — THIS node's open self-roster proposals, read \
             by its own sweep; node-local, no DirectoryOp carries it",
        ),
        // v62.0.0 (PX-fix3) — `list_group_tips` left this list: routed
        // (`ListGroupTips`).
    ];

    /// **I1162 — proxy parity.** Every `FederationDirectory` method the
    /// capsule proxy answers `Unsupported` — its own stub, or a trait default
    /// it inherits that answers `Unsupported` itself — is on
    /// [`PROXY_UNSUPPORTED_ALLOWLIST`] with a reason, and every entry there
    /// still answers `Unsupported` (a routed method leaves the list).
    ///
    /// From disk, so a new trait method or a new stub cannot slip past a hand
    /// list: #1162 was `execute_attestation_query`, a typed read every fold
    /// moved onto in v56.0.0, left a stub on the one surface phones run. The
    /// compiler is no backstop here — a stub type-checks.
    ///
    /// Blind spot: a trait default that COMPOSES other methods is not
    /// classified (it routes or fails through what it calls, which this gate
    /// sees at those methods).
    #[test]
    fn i1162_proxy_parity_every_unsupported_method_is_allowlisted() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let read = |p: &str| {
            crate::federation::blank_comments_and_strings(
                &std::fs::read_to_string(root.join(p)).expect("read source"),
            )
        };
        let tr = top_level_fns(
            &read("src/federation/mod.rs"),
            "pub trait FederationDirectory",
        );
        let px = top_level_fns(
            &read("src/ffi/directory_capsule.rs"),
            "impl FederationDirectory for OpsDirectory",
        );
        assert!(
            tr.len() > 200,
            "I1162 the trait scan found {} methods",
            tr.len()
        );
        assert!(
            px.len() > 100,
            "I1162 the proxy scan found {} methods",
            px.len()
        );
        for m in ["execute_attestation_query", "lookup_public_key"] {
            assert!(
                tr.contains_key(m) && px.contains_key(m),
                "I1162 recognizer: {m}"
            );
        }
        let answers_unsupported =
            |body: &Option<String>| body.as_deref().is_some_and(|b| b.contains("Unsupported"));
        let mut unsupported = BTreeSet::new();
        for (name, body) in &tr {
            let on_proxy = match px.get(name) {
                Some(own) => answers_unsupported(own),
                None => answers_unsupported(body),
            };
            if on_proxy {
                unsupported.insert(name.as_str());
            }
        }
        let extra: Vec<&String> = px.keys().filter(|n| !tr.contains_key(*n)).collect();
        assert!(
            extra.is_empty(),
            "I1162 proxy methods not on the trait: {extra:?}"
        );

        let allow: BTreeMap<&str, &str> = PROXY_UNSUPPORTED_ALLOWLIST.iter().copied().collect();
        assert_eq!(
            allow.len(),
            PROXY_UNSUPPORTED_ALLOWLIST.len(),
            "I1162 a duplicate allowlist entry"
        );
        assert!(
            allow.values().all(|r| r.trim().len() > 20),
            "I1162 every allowlisted method carries its reason"
        );
        let unlisted: Vec<&&str> = unsupported
            .iter()
            .filter(|m| !allow.contains_key(**m))
            .collect();
        assert!(
            unlisted.is_empty(),
            "I1162 the capsule proxy answers Unsupported for {unlisted:?} — every call \
             to them fails on a phone or agent-embedded node. Append a DirectoryOp and \
             route it, or allowlist it WITH a reason"
        );
        let stale: Vec<&&str> = allow
            .keys()
            .filter(|m| !unsupported.contains(**m))
            .collect();
        assert!(
            stale.is_empty(),
            "I1162 allowlisted but no longer Unsupported on the proxy (remove them): {stale:?}"
        );
    }

    /// v62.0.0 (PX-fix1) — the trait defaults that answer a benign-looking
    /// value (empty, `None`, `false`, `Ok(())`) and that the capsule proxy
    /// may inherit, each with why. Every other such default is a fail-open
    /// read through the proxy (I2180).
    const PROXY_SILENT_DEFAULT_ALLOWLIST: &[(&str, &str)] = &[
        (
            "peer_quota_observation",
            "a SYNC observability accessor of the backend's in-memory quota table; `None` is \
             'this directory keeps no table', read by node_state as zero tracked peers, never \
             as an admission or authority verdict",
        ),
        (
            "trust_root_standing_cache",
            "a SYNC accessor of the backend's verdict CACHE; `None` means no cache, so \
             canonical_community recomputes every verdict over the proxy's routed reads — \
             slower, never a different answer",
        ),
    ];

    /// How one trait default answers when nothing overrides it (I2180).
    #[derive(Debug, PartialEq, Eq)]
    enum DefaultAnswer {
        /// It refuses `Unsupported` (I1162's ground).
        Unsupported,
        /// It names `self`: a composition, answering through the methods it
        /// calls (each of which this gate classifies at its own default).
        Composes,
        /// It answers only an error (`Err(Error::Backend(..))`): loud.
        Refuses,
        /// Anything else: an empty / `None` / `false` / `Ok(())` answer —
        /// "nothing held" to every caller over the proxy.
        Silent,
    }

    /// Classify one (comments and strings already blanked) default body.
    fn default_answer(body: &str) -> DefaultAnswer {
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let names_self = body
            .match_indices("self")
            .any(|(i, m)| !body[..i].ends_with(ident) && !body[i + m.len()..].starts_with(ident));
        if body.contains("Unsupported") {
            DefaultAnswer::Unsupported
        } else if names_self {
            DefaultAnswer::Composes
        } else if body.contains("Err(") && !body.contains("Ok(") {
            DefaultAnswer::Refuses
        } else {
            DefaultAnswer::Silent
        }
    }

    /// **I2180 (v62.0.0, PX-fix1) — no trait default answers SILENTLY
    /// through the capsule proxy.** Every `FederationDirectory` method with a
    /// default body the proxy does not override answers through that default.
    /// One that answers empty / `None` / `false` / `Ok(())` without naming
    /// `self` reads "nothing held" to every free fold a consumer composes over
    /// the proxy: v62's `genesis_in_force` read no genesis,
    /// `held_keys_for_kid` read `NotHeld`, `bytes_servable` answered TRUE for
    /// held-back bytes. Such a default is routed (a proxy override), made to
    /// refuse `Unsupported` (I1162 then lists it), or named on
    /// [`PROXY_SILENT_DEFAULT_ALLOWLIST`] with why; an allowlisted name that
    /// is no longer a silent default is stale. From disk, comments and
    /// strings blanked, so a commented-out override or a `"Unsupported"` in
    /// a message cannot pass for one.
    ///
    /// A default that answers an error OTHER than `Unsupported`
    /// (`Err(Error::Backend(..))`) is red too (lead's ruling): an unrouted
    /// method fails `Unsupported` and nothing else.
    ///
    /// Blind spot (as I1162's): a COMPOSING default is not classified — it
    /// answers through the methods it calls, which this gate classifies.
    #[test]
    fn i2180_no_trait_default_answers_silently_through_the_proxy() {
        // The classifier, on the shapes it must tell apart.
        for (body, want) in [
            ("{ let _ = typ; Ok(Vec::new()) }", DefaultAnswer::Silent),
            ("{ let _ = row_id; Ok(None) }", DefaultAnswer::Silent),
            ("{ Ok(false) }", DefaultAnswer::Silent),
            ("{ let _ = row; Ok(()) }", DefaultAnswer::Silent),
            ("{ None }", DefaultAnswer::Silent),
            ("{ let _ = itself; Ok(myself) }", DefaultAnswer::Silent),
            (
                "{ let _ = x; Err(Error::Unsupported { method: \"\" }) }",
                DefaultAnswer::Unsupported,
            ),
            (
                "{ Err(Error::Backend(\"\".into())) }",
                DefaultAnswer::Refuses,
            ),
            (
                "{ Ok(self.lookup_public_key(k).await?.is_some()) }",
                DefaultAnswer::Composes,
            ),
            ("{ fold(self, k).await }", DefaultAnswer::Composes),
        ] {
            assert_eq!(default_answer(body), want, "I2180 classifier on {body}");
        }

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let read = |p: &str| {
            crate::federation::blank_comments_and_strings(
                &std::fs::read_to_string(root.join(p)).expect("read source"),
            )
        };
        let tr = top_level_fns(
            &read("src/federation/mod.rs"),
            "pub trait FederationDirectory",
        );
        let px = top_level_fns(
            &read("src/ffi/directory_capsule.rs"),
            "impl FederationDirectory for OpsDirectory",
        );
        assert!(tr.len() > 200, "I2180 the trait scan found {}", tr.len());
        assert!(px.len() > 100, "I2180 the proxy scan found {}", px.len());
        // Recognizers: a routed read, a silent sync accessor, a composition.
        for m in ["edition2_objects", "fold_slot_held", "held_rows_for"] {
            assert!(px.contains_key(m), "I2180 recognizer: the proxy routes {m}");
        }
        let inherited = |name: &str| -> Option<DefaultAnswer> {
            match (tr.get(name), px.contains_key(name)) {
                (Some(Some(body)), false) => Some(default_answer(body)),
                _ => None,
            }
        };
        assert_eq!(
            inherited("peer_quota_observation"),
            Some(DefaultAnswer::Silent),
            "I2180 recognizer: a silent default is seen"
        );
        assert_eq!(
            inherited("key_edition"),
            Some(DefaultAnswer::Composes),
            "I2180 recognizer: a composition is seen"
        );

        // v62.0.0 (PX-fix1, lead's ruling) — an unrouted method fails
        // `Unsupported` and nothing else: a default that answers another
        // error (`Err(Backend(..))`) is red too, so a host can always tell
        // "not on the capsule" from a failure of the host's store.
        let silent: BTreeSet<&str> = tr
            .keys()
            .map(String::as_str)
            .filter(|&n| {
                matches!(
                    inherited(n),
                    Some(DefaultAnswer::Silent | DefaultAnswer::Refuses)
                )
            })
            .collect();
        let allow: BTreeMap<&str, &str> = PROXY_SILENT_DEFAULT_ALLOWLIST.iter().copied().collect();
        assert_eq!(
            allow.len(),
            PROXY_SILENT_DEFAULT_ALLOWLIST.len(),
            "I2180 a duplicate allowlist entry"
        );
        assert!(
            allow.values().all(|r| r.split_whitespace().count() >= 10),
            "I2180 every allowlisted default carries its reason"
        );
        let unlisted: Vec<&&str> = silent.iter().filter(|m| !allow.contains_key(**m)).collect();
        assert!(
            unlisted.is_empty(),
            "I2180 these trait defaults answer empty / None / false / Ok(()) — or an error \
             other than Unsupported — through the capsule proxy: {unlisted:?}. Route each \
             (append a DirectoryOp, override it on OpsDirectory), make the default \
             `Err(Error::Unsupported {{ .. }})`, or allowlist it WITH a reason"
        );
        let stale: Vec<&&str> = allow.keys().filter(|m| !silent.contains(**m)).collect();
        assert!(
            stale.is_empty(),
            "I2180 allowlisted but no longer a silent default the proxy inherits \
             (remove them): {stale:?}"
        );
    }

    /// v61.4.2 — the `FederationDirectory` methods CIRISEdge v45.1.6 calls
    /// from PRODUCTION code (`git grep` over `src/` at the tag: a `.method(`
    /// call outside `#[cfg(test)] mod`, `*test*` files, comments, and the two
    /// delegating wrappers `ffi/kept_directory.rs` and
    /// `replication/counting_directory_930.rs`). Pinned, not read from disk:
    /// Edge's tree is not a persist input, and a gate that reads a sibling
    /// checkout fails toward whatever happens to be checked out. Re-derive it
    /// on an Edge re-pin (`L1.md` has the script).
    ///
    /// v62.0.0 (PX-fix2) — the list holds only the calls that SUCCEED over
    /// the v62 capsule: the four earlier-form verbs v62 retired
    /// (`record_canonical_withdrawal`, `record_role_withdrawal`,
    /// `put_touch_claim`, `put_identity_occurrence_local`) moved to
    /// [`EDGE_RETIRED_VERBS`], each with its edition-2 replacement.
    const EDGE_V45_1_6_PRODUCTION_CALLS: &[&str] = &[
        "active_community_key_ids_for",
        "active_community_members",
        "active_family_key_ids_for",
        "active_family_members",
        "active_identities_for_occurrence",
        "add_community_member",
        "add_member",
        "add_peer_record",
        "apply_replicated_accord_evidence",
        "apply_replicated_attestation",
        "attestations_binding_content",
        "evict_fountain_content_hard_delete",
        "evict_fountain_content_to_tier",
        "get_attestation",
        "list_attestations_for",
        "list_attestations_naming_by_dimension",
        "list_attestations_referencing",
        "list_attestations_since",
        "list_attestations_since_by_prefixes",
        "list_canonical_withdrawals",
        "list_communities_for_member_active",
        "list_composers_referencing_any",
        "list_families_for_member_active",
        "list_held_fountain_content",
        "list_identity_occurrences_active",
        "list_identity_occurrences_by_occurrence_key",
        "list_keys_by_identity_type",
        "list_live_consent_grants_by",
        "list_signed_accord_quorum_evidence_since",
        "list_signed_location_proofs_since",
        "list_signed_transport_destinations_for",
        "list_signed_transport_destinations_since",
        "list_targeted_by_dimension_prefix",
        "list_transport_destinations_for",
        "list_wire_hashes_since",
        "lookup_canonical_withdrawal",
        "lookup_community",
        "lookup_public_key",
        "lookup_signed_record_by_content_hash",
        "put_attestation",
        "put_attestation_authored",
        "put_attestation_synced",
        "put_community",
        "put_community_membership_revocation",
        "put_family_membership_widening",
        "put_public_key",
        "put_signed_transport_destination",
        "rebuild_signed_wire_index",
        "release_shared_instance_lease",
        "remove_peer_record",
        "resolve_scoped_consent",
        "revocations_for",
        "update_peer_alias",
        "update_peer_notes",
        "update_peer_policy",
        "update_peer_trust",
    ];

    /// **I1893 — no method Edge calls is allowlisted `Unsupported` on the
    /// proxy.** I1162 proves every `Unsupported` answer is allowlisted with a
    /// reason; this proves no such reason covers a method Edge's production
    /// code calls (v61.4.1 allowlisted five, and an agent install's call join
    /// answered 503). Every pinned name is a trait method, so a rename
    /// cannot empty the check.
    #[test]
    fn i1893_no_method_edge_calls_is_allowlisted_unsupported() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let trait_src = crate::federation::blank_comments_and_strings(
            &std::fs::read_to_string(root.join("src/federation/mod.rs")).expect("read source"),
        );
        let tr = top_level_fns(&trait_src, "pub trait FederationDirectory");
        assert!(
            EDGE_V45_1_6_PRODUCTION_CALLS.len() > 50,
            "I1893 the pinned list is not empty"
        );
        let unknown: Vec<&&str> = EDGE_V45_1_6_PRODUCTION_CALLS
            .iter()
            .filter(|m| !tr.contains_key(**m))
            .collect();
        assert!(
            unknown.is_empty(),
            "I1893 pinned names that are no trait method (renamed? re-derive): {unknown:?}"
        );
        let allowlisted: Vec<&&str> = EDGE_V45_1_6_PRODUCTION_CALLS
            .iter()
            .filter(|m| PROXY_UNSUPPORTED_ALLOWLIST.iter().any(|(n, _)| n == *m))
            .collect();
        assert!(
            allowlisted.is_empty(),
            "I1893 Edge calls these, and the proxy answers them Unsupported: {allowlisted:?}"
        );
        // v62.0.0 (PX-fix1) — a RETIRED verb Edge still calls answers
        // `Unsupported` naming its edition-2 replacement, read from the
        // default's own text (strings kept: the message is the contract).
        let raw = std::fs::read_to_string(root.join("src/federation/mod.rs")).expect("read");
        for (verb, replacement) in EDGE_RETIRED_VERBS {
            assert!(
                !EDGE_V45_1_6_PRODUCTION_CALLS.contains(verb),
                "I1893 a retired verb is no call that succeeds (drop it from the production list): {verb}"
            );
            assert!(
                matches!(tr.get(*verb), Some(Some(b)) if b.contains("Unsupported")),
                "I1893 {verb}: the trait default must answer Unsupported"
            );
            let message = format!("method: \"{verb} — retired");
            let at = raw
                .find(&message)
                .unwrap_or_else(|| panic!("I1893 {verb}: its Unsupported says it is retired"));
            let line_end = at + raw[at..].find('\n').unwrap_or(raw.len() - at);
            assert!(
                raw[at..line_end].contains(replacement),
                "I1893 {verb}: its Unsupported names the replacement `{replacement}`"
            );
            assert!(
                PROXY_UNSUPPORTED_ALLOWLIST.iter().any(|(n, _)| n == verb),
                "I1893 {verb}: listed with I1162"
            );
        }
    }

    /// v62.0.0 (PX-fix2) — the earlier-form verbs CIRISEdge v45.1.6 calls from
    /// production that v62 retired from the capsule, each with the edition-2
    /// replacement its `Unsupported` names (ADOPTION-NOTES "PX-fix2" says what
    /// Edge calls instead). Disjoint from the production-call list.
    const EDGE_RETIRED_VERBS: &[(&str, &str)] = &[
        ("record_canonical_withdrawal", "PutGenesisBundle"),
        ("record_role_withdrawal", "PutEdition2Statement"),
        ("put_touch_claim", "put_touch_claim_local"),
        ("put_identity_occurrence_local", "PutEdition2Statement"),
    ];
}

/// v60.0.0 (CIRISPersist#787) — the consumer side of every op.
#[cfg(test)]
mod proxy_gate {
    /// The ops a consumer never reaches through an [`OpsDirectory`] trait
    /// method, each with why. Every other op must be constructed by the proxy.
    ///
    /// [`OpsDirectory`]: super::OpsDirectory
    const DISPATCH_ONLY: &[(&str, &str)] = &[
        (
            "ReachableUnderScope",
            "a free fold (`reachable_under_scope_with_reasons`) persist runs over its own \
             directory; no `FederationDirectory` method exists to proxy",
        ),
        (
            "VerifyHybridViaDirectory",
            "retired at v62.0.0 (F0-cp5): kept so an old consumer's op is answered with \
             `Unsupported`, never issued by a current proxy",
        ),
        // v62.0.0 (round 6) — the accord proposal / participation / decision
        // trait doors are deleted (JSON-cut slice F; a roster change is a later
        // genesis bundle); their append-only ops stay as refusing arms.
        // v62.0.0 (PX-fix3, 4g merge) — PX-fix3's `PutLineageHeadCosign` row is
        // the one 4f-regen already carries (below); one row per op.
        (
            "PutAccordDecision",
            "retired at v62.0.0 (slice F): its trait door is deleted; the op stays so an \
             old consumer's call is refused by name, never issued by a current proxy",
        ),
        (
            "PutAccordParticipation",
            "retired at v62.0.0 (slice F): its trait door is deleted; the op stays so an \
             old consumer's call is refused by name, never issued by a current proxy",
        ),
        (
            "PutAccordProposal",
            "retired at v62.0.0 (slice F): its trait door is deleted; the op stays so an \
             old consumer's call is refused by name, never issued by a current proxy",
        ),
        (
            "VerifyCompositeViaDirectory",
            "the verify runs inside persist's .so against its own vtable, by design: a \
             consumer-side proxy would reintroduce the vtable skew the op exists to avoid",
        ),
        // v62.0.0 (AU-fix2; CC 2.7.11) — the host's whole answer is a free
        // fold over the host's store; the consumer sends the op.
        (
            "AdmissionUnitRunnable",
            "`edition2::admission_unit::admission_unit_runnable` is a free fold persist runs \
             over its own directory (every leg on the host's store); no trait method to proxy",
        ),
        (
            "BuildDelegationGraph",
            "a free walk persist runs over its own directory; no trait method to proxy",
        ),
        // v62.0.0 (4f-regen) — F0-cp9r deleted the lineage-head cosign door
        // (one verify path); the op stays as a refusing arm for the ABI.
        (
            "PutLineageHeadCosign",
            "retired at v62.0.0 (F0-cp9r): its trait door is deleted and its arm \
             refuses; the op stays for the ABI, never issued by a current proxy",
        ),
        // v62.0.0 (RL-fix1, ruling (B)) — free doors and reads persist runs
        // over its own directory.
        (
            "ApplyReplicatedStatementAtFeed",
            "`edition2::ingest::apply_replicated_statement_at_feed` is a free door persist \
             runs over its own directory; no trait method to proxy",
        ),
        (
            "AccordRescanNeeded",
            "`edition2::accord_rescan::rescan_needed` is a free read over the genesis in \
             force and the watermarks; no trait method to proxy",
        ),
        (
            "AckAccordRescan",
            "`edition2::accord_rescan::ack_rescan` is a free door over the watermark store; \
             no trait method to proxy",
        ),
        // v62.0.0 (RL-fix3) — the contact path's free doors and reads.
        (
            "RecordDialHints",
            "`edition2::contact::record_dial_hints` is a free door (bounds and the CC 2.6.8 \
             guard) persist runs over its own directory",
        ),
        (
            "DialHintsFor",
            "`edition2::contact::dial_hints_for` is a free read over the dial-hint store, not a trait method to proxy",
        ),
        (
            "ListDialHints",
            "`edition2::contact::list_dial_hints` is a free read over the dial-hint store, not a trait method to proxy",
        ),
        (
            "RemoveDialHints",
            "`edition2::contact::remove_dial_hints` is a free door over the dial-hint store, not a trait method to proxy",
        ),
        (
            "AdmitPreSealAnswer",
            "`edition2::contact::admit_pre_seal_answer` is a free door persist runs over its \
             own directory (pure checks, then the replicated door)",
        ),
        (
            "AdmitContactOwnerRows",
            "`edition2::contact::admit_contact_owner_rows` is a free door persist runs over \
             its own directory",
        ),
        (
            "ServeStanding",
            "`edition2::serve::serve_standing` is a free read over this store's node key and \
             its own standing chain, not a trait method to proxy",
        ),
        (
            "PutIdentityOccurrenceRevocation",
            "retired at v59.0.0: kept so an old consumer's op is answered with the typed \
             `federation_envelope_kind_retired` refusal, never issued by a current proxy",
        ),
        (
            "TrustRootValid",
            "`trust_root::trust_root_valid` is a free function over the directory, not a \
             trait method",
        ),
        (
            "CapabilityRootsToTrustedRoot",
            "`trust_root::capability_roots_to_trusted_root` is a free function over the \
             directory, not a trait method",
        ),
        (
            "ResolveTransitEligibility",
            "`trust_root::resolve_transit_eligibility` is a free, fail-closed function over \
             the directory, not a trait method",
        ),
        // v62.0.0 (JSON-cut slice D) — the edition-2 doors are free functions
        // over the directory; the consumer sends the op.
        (
            "PutEdition2Statement",
            "`edition2::ingest::put_statement` is a free door persist runs over its own \
             directory, so every gate runs on the host's store; no trait method to proxy",
        ),
        // v62.0.0 (LF-fix2, T5) — `ApplyReplicatedStatement` left this list:
        // the proxy's `replicated_statement_door` builds it (the whole
        // replicated door, routed).
        (
            "BundlesInForce",
            "`edition2::genesis::bundles_in_force` is a free fold over the held genesis \
             lineage, not a trait method",
        ),
        (
            "PutGenesisBundle",
            "`edition2::genesis::put_genesis_bundle` is a free door persist runs over its own \
             directory (Verify's reader, then one transaction); no trait method to proxy",
        ),
        (
            "RebindHeldFor",
            "`edition2::transport_rebind::rebind_held_for` is a free read over the held \
             genesis lineage and re-bind voices, not a trait method",
        ),
        (
            "PeerRooting",
            "`edition2::peer_rooting::peer_rooting` is a free read over the held genesis, \
             key plane and trust rows, not a trait method",
        ),
        (
            "MayPublishFederationRendezvous",
            "`age::may_publish_federation_rendezvous` is a free authoring check over the held \
             age rows, not a trait method; the host sends the op before it publishes",
        ),
    ];

    /// The body of the first `{ … }` block opening at or after `at`.
    fn block(src: &str, at: usize) -> &str {
        let open = at + src[at..].find('{').expect("a block");
        let mut depth = 0usize;
        for (k, c) in src[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &src[open..open + k];
                    }
                }
                _ => {}
            }
        }
        panic!("unterminated block");
    }

    /// **I1322 (#787)** — every `DirectoryOp` the dispatch side answers has a
    /// consumer-side proxy (a method of `impl FederationDirectory for
    /// OpsDirectory` that builds it), or is named in [`DISPATCH_ONLY`] with
    /// why. The dispatch `match` is exhaustive, so the compiler holds that
    /// side; nothing held this one, and an op with no proxy answers
    /// `Error::Unsupported` from the trait default in exactly the build a
    /// consumer runs (#780). Read from the text this binary was compiled from
    /// (`include_str!`), comments stripped, so neither a moved tree nor a
    /// commented-out construction can read as a proxy.
    #[test]
    fn i1322_every_op_has_a_consumer_proxy_or_says_why() {
        let src: String = include_str!("directory_capsule.rs")
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let ops = block(
            &src,
            src.find("pub enum DirectoryOp {").expect("the op enum"),
        );
        let variants: Vec<&str> = ops
            .lines()
            .filter_map(|l| {
                let name = l.strip_prefix("    ")?;
                let end = name.find(|c: char| !c.is_ascii_alphanumeric())?;
                let name = &name[..end];
                name.starts_with(|c: char| c.is_ascii_uppercase())
                    .then_some(name)
            })
            .collect();
        assert!(
            variants.len() >= 70,
            "I1322: the op scan found {} variants — the extractor collapsed",
            variants.len()
        );
        // v61.4.0 (CIRISPersist#1244) — the proxy is three impls: the
        // directory, and the blackhole and derived-schema surfaces the
        // capsule also carries.
        let proxy: String = [
            "impl FederationDirectory for OpsDirectory {",
            "impl crate::federation::BlackholeRules for OpsDirectory {",
            "impl crate::derived::DerivedSchema for OpsDirectory {",
        ]
        .iter()
        .map(|head| block(&src, src.find(head).expect("a consumer proxy impl")))
        .collect::<Vec<_>>()
        .join("\n");
        let built = |v: &str| {
            proxy
                .match_indices(&format!("DirectoryOp::{v}"))
                .any(|(i, m)| {
                    !proxy[i + m.len()..].starts_with(|c: char| c.is_ascii_alphanumeric())
                })
        };
        let mut missing = Vec::new();
        for v in &variants {
            let exempt = DISPATCH_ONLY.iter().any(|(n, _)| n == v);
            match (built(v), exempt) {
                (true, true) => missing.push(format!(
                    "{v}: the proxy builds it now — delete its DISPATCH_ONLY row"
                )),
                (false, false) => missing.push(format!(
                    "{v}: no OpsDirectory method builds it (a consumer gets Unsupported)"
                )),
                _ => {}
            }
        }
        for (n, why) in DISPATCH_ONLY {
            assert!(
                variants.contains(n),
                "I1322: DISPATCH_ONLY names no op `{n}`"
            );
            assert!(
                why.split_whitespace().count() >= 10,
                "I1322: `{n}` needs a reason"
            );
        }
        assert!(missing.is_empty(), "I1322 (#787):\n{}", missing.join("\n"));
    }
}

/// v62.0.0 (JSON-cut slice D) — the edition-2 ops and the earlier-form
/// refusal across the capsule, on sqlite and postgres.
///
/// - **I2480 (the statement door crosses).** `PutEdition2Statement` admits a
///   `key:record` through the C-ABI as the key plane, under the row id this
///   node computes from the bytes; the same bytes again are `new: false`.
/// - **I2481 (an earlier-form object at the edition-2 op).** JSON bytes are
///   refused by the door itself, and the flattened error carries the
///   reading `federation_malformed_row: {plane}: earlier_form_object`.
/// - **I2482 (the offered id).** An offered row id the bytes do not name is
///   `row_id_mismatch`; the store is untouched.
/// - **I2483 (the replicated door).** `ApplyReplicatedStatement` under the
///   computed id is `Admitted`, then `Unchanged`, with the plane carried.
/// - **I2484 (the serve listing crosses, and the proxy reads it).**
///   `Edition2StatementsSince` pages every held statement once, as received,
///   in strictly increasing positions; the answer equals the directory's
///   own, and the consumer proxy (`OpsDirectory`) answers the same instead
///   of the trait default's empty set.
/// - **I2485 (bundles in force cross).** `BundlesInForce` answers what
///   `edition2::genesis::bundles_in_force` answers (none held: empty).
/// - **I2486 (the earlier-form ops refuse once shut).** With the switch
///   forced on, `PutAttestation` (a JSON row with no statement) and
///   `PutIdentityOccurrenceRevocation` answer
///   `federation_malformed_row: {plane}: earlier_form_object` before any
///   parse, and nothing is stored. (v62.0.0 CP2: the switch is shut for
///   good; the switch-off leg is deleted.)
/// - **I2487 (every inbound op is classified).** Every `Put*` /
///   `ApplyReplicated*` op is classified earlier-form by
///   [`earlier_form_op_plane`], or is named here with why.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod edition2_ops {
    use super::*;
    use ciris_crypto::composite::CompositeSigningKey;
    use ciris_verify_core::cde::{self, Value};
    use ciris_verify_core::edition2::{cose_key, identity_ref, sign_row_statement, thumbprint};
    use std::sync::mpsc;

    use crate::federation::edition2::names::RowId;

    // ── fixtures (signed before any await: no signing key crosses one) ──

    fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
    }

    fn iref(k: &CompositeSigningKey) -> String {
        identity_ref(&thumbprint(k.public_key()))
    }

    fn map(mut m: Vec<(&str, Value)>) -> Value {
        let t = |s: &str| Value::Text(s.into());
        m.sort_by_key(|(k, _)| cde::encode(&t(k)));
        Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
    }

    /// A self-signed `key:record` of the key seeded `n`.
    fn key_record(n: u8, at: u64) -> Vec<u8> {
        let k = key(n);
        let roles = Value::Array(vec![Value::Text("user".into())]);
        let payload = map(vec![
            ("key", cose_key(k.public_key())),
            ("identity_type", roles),
            ("asserted_at", Value::Uint(at)),
            ("author", Value::Text(iref(&k))),
        ]);
        sign_row_statement(
            &k,
            &iref(&k),
            &iref(&k),
            "scores",
            "key:record",
            &payload,
            vec![],
        )
        .expect("sign a key:record")
    }

    fn rid(statement: &[u8]) -> [u8; 32] {
        RowId::of_statement(statement).expect("a row statement").0
    }

    fn runtime() -> Arc<tokio::runtime::Runtime> {
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build tokio runtime"),
        )
    }

    /// Drive one op through the C-ABI (the shape a consumer wheel uses).
    fn run_op(
        rt: &Arc<tokio::runtime::Runtime>,
        directory: &Directory,
        op: &DirectoryOp,
    ) -> DirectoryOpResult {
        let op_bytes = serde_json::to_vec(op).expect("serialize op");
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let ctx: *mut c_void = Box::into_raw(Box::new(tx)) as *mut c_void;

        unsafe extern "C" fn cb(ctx: *mut c_void, ptr: *const u8, len: usize) {
            // SAFETY: single-fire boxed Sender; readable (ptr,len) for the call.
            let tx: Box<mpsc::Sender<Vec<u8>>> =
                unsafe { Box::from_raw(ctx as *mut mpsc::Sender<Vec<u8>>) };
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            let _ = tx.send(bytes);
        }

        // SAFETY: matched data/vtable; readable op bytes; Send-valid ctx/cb.
        let task_ptr = unsafe {
            (directory.vtable.build_op)(directory.data, op_bytes.as_ptr(), op_bytes.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("op result must arrive");
        // SAFETY: single-drop, matched vtable.
        unsafe { (executor.vtable.drop)(executor.data) };
        // v62.0.0 (ABI 14) — these witnesses read a failure's TEXT; a
        // `TypedErr` carries the same text the pre-v62 `Err` did.
        serde_json::from_slice::<DirectoryOpResult>(&bytes)
            .expect("deserialize DirectoryOpResult")
            .into_flattened()
    }

    fn err_of(r: DirectoryOpResult, what: &str) -> String {
        match r {
            DirectoryOpResult::Err(s) => s,
            other => panic!("{what}: expected Err, got {other:?}"),
        }
    }

    /// I2480–I2487 over one migrated, EMPTY store.
    fn body(rt: &Arc<tokio::runtime::Runtime>, dir: Arc<dyn FederationDirectory>) {
        let s1 = key_record(81, 1_000);
        let s2 = key_record(82, 2_000);
        let directory = build_persist_directory(dir.clone());

        // ── I2480 ──
        for want_new in [true, false] {
            match run_op(
                rt,
                &directory,
                &DirectoryOp::PutEdition2Statement {
                    statement: s1.clone(),
                    offered_row_id: None,
                },
            ) {
                DirectoryOpResult::Edition2StatementOutcome(
                    Edition2StatementOutcome::KeyPlane { row_id, new },
                ) => {
                    assert_eq!(row_id, rid(&s1), "I2480: the node-computed row id");
                    assert_eq!(new, want_new, "I2480: new on first put only");
                }
                other => panic!("I2480: {other:?}"),
            }
        }

        // ── I2481 ──
        let json = br#"{"attestation":{"attestation_id":"a","attesting_key_id":"k"}}"#.to_vec();
        let e = err_of(
            run_op(
                rt,
                &directory,
                &DirectoryOp::PutEdition2Statement {
                    statement: json,
                    offered_row_id: None,
                },
            ),
            "I2481",
        );
        assert!(
            e.starts_with("federation_malformed_row: ") && e.contains(": earlier_form_object: "),
            "I2481: the reading crosses: {e}"
        );

        // ── I2482 ──
        let e = err_of(
            run_op(
                rt,
                &directory,
                &DirectoryOp::PutEdition2Statement {
                    statement: s2.clone(),
                    offered_row_id: Some([0x5a; 32]),
                },
            ),
            "I2482",
        );
        assert!(e.contains(": row_id_mismatch: "), "I2482: {e}");
        let held = rt
            .block_on(dir.edition2_statements_since(None, 100))
            .expect("I2482: read");
        assert!(
            held.iter().all(|s| s.bytes != s2),
            "I2482: a refused statement is not stored"
        );

        // ── I2483 ──
        let first = run_op(
            rt,
            &directory,
            &DirectoryOp::ApplyReplicatedStatement {
                statement: s2.clone(),
                offered_row_id: rid(&s2),
            },
        );
        let again = run_op(
            rt,
            &directory,
            &DirectoryOp::ApplyReplicatedStatement {
                statement: s2.clone(),
                offered_row_id: rid(&s2),
            },
        );
        let kp = Edition2StatementOutcome::KeyPlane {
            row_id: rid(&s2),
            new: true,
        };
        match first {
            DirectoryOpResult::ReplicatedStatementOutcome(Edition2ReplicatedOutcome::Admitted(
                o,
            )) => assert_eq!(o, kp, "I2483: admitted on the key plane"),
            other => panic!("I2483 first: {other:?}"),
        }
        match again {
            DirectoryOpResult::ReplicatedStatementOutcome(
                Edition2ReplicatedOutcome::Unchanged(Edition2StatementOutcome::KeyPlane {
                    row_id,
                    new,
                }),
            ) => {
                assert_eq!(row_id, rid(&s2), "I2483");
                assert!(!new, "I2483: a re-offer is not new");
            }
            other => panic!("I2483 again: {other:?}"),
        }

        // ── I2484 ──
        let mut served: Vec<Edition2ServedStatement> = Vec::new();
        let mut cursor = None;
        loop {
            let page = match run_op(
                rt,
                &directory,
                &DirectoryOp::Edition2StatementsSince { cursor, limit: 1 },
            ) {
                DirectoryOpResult::Edition2StatementPage(v) => v,
                other => panic!("I2484: {other:?}"),
            };
            assert!(page.len() <= 1, "I2484: the limit");
            let Some(last) = page.last() else { break };
            cursor = Some(last.cursor);
            served.extend(page);
        }
        assert!(
            served.windows(2).all(|w| w[0].cursor < w[1].cursor),
            "I2484: strictly increasing positions"
        );
        for s in [&s1, &s2] {
            assert_eq!(
                served.iter().filter(|x| &x.bytes == s).count(),
                1,
                "I2484: each held statement served once, as received"
            );
        }
        let direct: Vec<Edition2ServedStatement> = rt
            .block_on(dir.edition2_statements_since(None, 100))
            .expect("I2484: direct read")
            .into_iter()
            .map(Edition2ServedStatement::from)
            .collect();
        assert_eq!(
            served, direct,
            "I2484: the op answers what the directory answers"
        );
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy =
            build_ops_directory(build_persist_directory(dir.clone()), executor).expect("abi ok");
        let via_proxy: Vec<Edition2ServedStatement> = rt
            .block_on(proxy.edition2_statements_since(None, 100))
            .expect("I2484: proxy read")
            .into_iter()
            .map(Edition2ServedStatement::from)
            .collect();
        assert_eq!(
            via_proxy, direct,
            "I2484: the consumer proxy reads the host's listing, not the empty default"
        );

        // ── I2485 ──
        let direct: Vec<Edition2BundleInForce> = rt
            .block_on(crate::federation::edition2::genesis::bundles_in_force(
                dir.as_ref(),
            ))
            .expect("I2485: direct")
            .iter()
            .map(Edition2BundleInForce::from)
            .collect();
        match run_op(rt, &directory, &DirectoryOp::BundlesInForce {}) {
            DirectoryOpResult::BundlesInForce(v) => {
                assert_eq!(v, direct, "I2485: the op answers the fold");
                assert!(v.is_empty(), "I2485: no genesis bundle held");
            }
            other => panic!("I2485: {other:?}"),
        }

        // ── I2486 ── (dispatched in THIS task: the forced switch is
        // task-local, and the C-ABI spawns onto another task.)
        use crate::federation::tier_ingest::test_support as ts;
        let id = uuid::Uuid::new_v4().to_string();
        let row =
            ts::bare_attestation(&id, "i2486-signer", "i2486-subject", &serde_json::json!({}));
        let put_row = || DirectoryOp::PutAttestation {
            attestation: crate::federation::SignedAttestation {
                attestation: row.clone(),
            },
        };
        let put_occ_rev = || DirectoryOp::PutIdentityOccurrenceRevocation {
            revocation: serde_json::json!({ "identity_occurrence_revocation": {} }),
        };
        let shut = rt.block_on(async {
            (
                dispatch_directory_op(dir.as_ref(), put_row())
                    .await
                    .into_flattened(),
                dispatch_directory_op(dir.as_ref(), put_occ_rev())
                    .await
                    .into_flattened(),
            )
        });
        for (r, plane) in [
            (shut.0, "attestation"),
            (shut.1, "identity_occurrence_revocation"),
        ] {
            let e = err_of(r, "I2486 shut");
            assert!(
                e.starts_with(&format!(
                    "federation_malformed_row: {plane}: earlier_form_object: "
                )),
                "I2486: {plane} refused by name: {e}"
            );
        }
        assert!(
            rt.block_on(dir.get_attestation(&id))
                .expect("I2486: read")
                .is_none(),
            "I2486: nothing stored behind the refusal"
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn i2480_to_i2486_edition2_ops_cross_the_capsule_sqlite() {
        let rt = runtime();
        let backend = rt.block_on(async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .expect("open sqlite");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        body(&rt, Arc::new(backend));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn i2480_to_i2486_edition2_ops_cross_the_capsule_pg() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = runtime();
        let backend = rt.block_on(async {
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        body(&rt, Arc::new(backend));
    }

    /// The `Put*` / `ApplyReplicated*` ops that are NOT earlier-form doors,
    /// each with why.
    const NOT_EARLIER_FORM: &[(&str, &str)] = &[
        (
            "PutEdition2Statement",
            "the edition-2 door itself; it refuses an earlier-form object by its own form check",
        ),
        (
            "ApplyReplicatedStatement",
            "the replicated edition-2 door; the same form check runs inside put_statement",
        ),
        (
            "ApplyReplicatedStatementAtFeed",
            "the replicated edition-2 door with a feed position; the same form check runs \
             inside put_statement",
        ),
        (
            "PutGenesisBundle",
            "the edition-2 genesis door itself; it refuses an earlier-form object (a bundle/1 \
             JSON) by its own form check",
        ),
        (
            "PutEdgeDetectionEvent",
            "TODO(json-cut): MESH by ruling, but no edition-2 detection door exists and the Rust \
             door is not on the switch; the capsule follows the Rust door",
        ),
        (
            "PutTouchClaimLocal",
            "v62.0.0 (PX-fix1): the node-local touch carries no signed object at all (RULINGS: \
             a touch claim is node-local), so there is no earlier form to refuse",
        ),
    ];

    /// I2487 — from this file's own text (comments stripped): every
    /// `Put*` / `ApplyReplicated*` variant of [`DirectoryOp`] is named in
    /// [`earlier_form_op_plane`]'s earlier-form arms (the arms before its
    /// first `=> None`), or in [`NOT_EARLIER_FORM`] with why — never both.
    #[test]
    fn i2487_every_inbound_op_is_classified() {
        let src: String = include_str!("directory_capsule.rs")
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let enum_at = src.find("pub enum DirectoryOp {").expect("the op enum");
        let enum_end = enum_at + src[enum_at..].find("\n}\n").expect("enum end");
        let variants: Vec<&str> = src[enum_at..enum_end]
            .lines()
            .filter_map(|l| {
                let name = l.strip_prefix("    ")?;
                let end = name
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(name.len());
                let name = &name[..end];
                name.starts_with(|c: char| c.is_ascii_uppercase())
                    .then_some(name)
            })
            .collect();
        assert!(
            variants.len() >= 115,
            "I2487: the scan found {} variants",
            variants.len()
        );
        let fn_at = src
            .find("pub fn earlier_form_op_plane(")
            .expect("the classifier");
        let earlier = &src[fn_at..fn_at + src[fn_at..].find("=> None").expect("a None arm")];
        let classified = |v: &str| {
            earlier
                .match_indices(&format!("DirectoryOp::{v}"))
                .any(|(i, m)| {
                    !earlier[i + m.len()..].starts_with(|c: char| c.is_ascii_alphanumeric())
                })
        };
        let mut bad = Vec::new();
        for v in variants
            .iter()
            .filter(|v| v.starts_with("Put") || v.starts_with("ApplyReplicated"))
        {
            let exempt = NOT_EARLIER_FORM.iter().any(|(n, _)| n == v);
            match (classified(v), exempt) {
                (true, true) => bad.push(format!("{v}: classified AND exempt")),
                (false, false) => bad.push(format!("{v}: not classified earlier-form")),
                _ => {}
            }
        }
        for (n, why) in NOT_EARLIER_FORM {
            assert!(variants.contains(n), "I2487: no op `{n}`");
            assert!(
                why.split_whitespace().count() >= 8,
                "I2487: `{n}` needs a reason"
            );
        }
        assert!(bad.is_empty(), "I2487:\n{}", bad.join("\n"));
    }

    /// I2486 (pure) — the classifier's refusal names the plane (v62.0.0: the
    /// switch is on; the inert-while-off leg went with the earlier form).
    #[tokio::test]
    async fn i2486_the_op_refusal_follows_the_switch() {
        let op = DirectoryOp::PutIdentityOccurrenceRevocation {
            revocation: serde_json::json!({}),
        };
        let e = async { refuse_earlier_form_op(&op) }
            .await
            .expect_err("I2486: refused once shut");
        assert_eq!(
            typed_error_string(&e)
                .split(": ")
                .take(3)
                .collect::<Vec<_>>(),
            vec![
                "federation_malformed_row",
                "identity_occurrence_revocation",
                "earlier_form_object"
            ],
            "I2486: the reading"
        );
        let read = DirectoryOp::LookupPublicKey { key_id: "k".into() };
        async { refuse_earlier_form_op(&read) }
            .await
            .expect("I2486: a read is never refused");
    }
}

/// v62.0.0 (CC 2.7, wave P9) — **the kind and the wait cross the capsule.**
///
/// - **I3602 (sqlite and postgres).** A row signed by a key this node holds
///   no record of, put through the C-ABI (`build_op` + the executor capsule)
///   as `PutEdition2Statement`, answers [`DirectoryOpResult::TypedErr`] with
///   kind `federation_attester_key_unknown` and `wait: true` (before v62 a
///   failure crossed as `Err(String)` and the proxy rebuilt it as
///   `federation_backend`); the proxy's reading ([`relay_typed_err`]) is an
///   error with that kind whose `is_wait()` holds, and nothing is stored. A
///   JSON body crosses as `federation_malformed_row`, `wait: false` (a
///   terminal refusal stays terminal). A relayed `federation_backend` is
///   [`Error::Backend`] with the host's text, byte for byte (the pre-v62
///   flattening every `Backend` reader keys on), and any other kind keeps
///   its token through the interner; a kind that is not a token is
///   `federation_backend`.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod wait_relay {
    use super::*;
    use ciris_crypto::composite::CompositeSigningKey;
    use ciris_verify_core::cde::{self, Value};
    use ciris_verify_core::edition2::{identity_ref, row_ref, sign_row_statement, thumbprint};
    use std::sync::mpsc;

    use crate::federation::edition2::names::RowId;

    fn map(mut m: Vec<(&str, Value)>) -> Value {
        let t = |s: &str| Value::Text(s.into());
        m.sort_by_key(|(k, _)| cde::encode(&t(k)));
        Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
    }

    /// A score row by a key no store here holds (the shape
    /// `edition2::ingest_invariants` answers the wait for).
    fn stranger_row() -> Vec<u8> {
        let k = CompositeSigningKey::from_seeds(&[98; 32], &[198; 32]);
        let me = identity_ref(&thumbprint(k.public_key()));
        let payload = map(vec![
            ("asserted_at", Value::Uint(5_000)),
            ("author", Value::Text(me.clone())),
            ("score", Value::Uint(750_000)),
            ("confidence", Value::Uint(900_000)),
            ("dimension", Value::Text("coherence_standing:cab:v1".into())),
            (
                "refs",
                map(vec![(
                    "also",
                    map(vec![("cites", Value::Array(vec![row_ref(&[0x31; 32])]))]),
                )]),
            ),
        ]);
        sign_row_statement(
            &k,
            &me,
            &me,
            "scores",
            "coherence_standing:.cohort",
            &payload,
            vec![],
        )
        .expect("sign a score row")
    }

    fn runtime() -> Arc<tokio::runtime::Runtime> {
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build tokio runtime"),
        )
    }

    /// One op through the C-ABI, the bytes deserialized as a consumer does
    /// (NOT flattened: this witness reads the typed failure).
    fn run_op(
        rt: &Arc<tokio::runtime::Runtime>,
        directory: &Directory,
        op: &DirectoryOp,
    ) -> DirectoryOpResult {
        let op_bytes = serde_json::to_vec(op).expect("serialize op");
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let ctx: *mut c_void = Box::into_raw(Box::new(tx)) as *mut c_void;

        unsafe extern "C" fn cb(ctx: *mut c_void, ptr: *const u8, len: usize) {
            // SAFETY: single-fire boxed Sender; readable (ptr,len) for the call.
            let tx: Box<mpsc::Sender<Vec<u8>>> =
                unsafe { Box::from_raw(ctx as *mut mpsc::Sender<Vec<u8>>) };
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            let _ = tx.send(bytes);
        }

        // SAFETY: matched data/vtable; readable op bytes; Send-valid ctx/cb.
        let task_ptr = unsafe {
            (directory.vtable.build_op)(directory.data, op_bytes.as_ptr(), op_bytes.len(), cb, ctx)
        };
        let executor = crate::ffi::executor_capsule::build_persist_executor(rt.clone());
        // SAFETY: task from build_op; matched executor vtable; single spawn.
        unsafe { (executor.vtable.spawn)(executor.data, task_ptr) };
        let bytes = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("op result must arrive");
        // SAFETY: single-drop, matched vtable.
        unsafe { (executor.vtable.drop)(executor.data) };
        serde_json::from_slice(&bytes).expect("deserialize DirectoryOpResult")
    }

    fn typed(r: DirectoryOpResult, what: &str) -> CapsuleError {
        match r {
            DirectoryOpResult::TypedErr(t) => t,
            other => panic!("{what}: expected TypedErr, got {other:?}"),
        }
    }

    fn body(rt: &Arc<tokio::runtime::Runtime>, dir: Arc<dyn FederationDirectory>) {
        let row = stranger_row();
        let row_id = RowId::of_statement(&row).expect("a row statement");
        let directory = build_persist_directory(dir.clone());

        // ── I3602: the wait crosses ──
        let t = typed(
            run_op(
                rt,
                &directory,
                &DirectoryOp::PutEdition2Statement {
                    statement: row.clone(),
                    offered_row_id: None,
                },
            ),
            "I3602 wait",
        );
        assert_eq!(t.kind, "federation_attester_key_unknown", "I3602: {t:?}");
        assert!(t.wait, "I3602: the wait crosses: {t:?}");
        assert!(
            t.message.starts_with("federation_attester_key_unknown: "),
            "I3602: the edition-2 op keeps its typed reading: {t:?}"
        );
        let e = relay_typed_err(DirectoryOpResult::TypedErr(t))
            .expect_err("I3602: the proxy reads a failure");
        assert_eq!(e.kind(), "federation_attester_key_unknown", "I3602 proxy");
        assert!(e.is_wait(), "I3602 proxy: still a wait");
        assert!(
            rt.block_on(dir.get_attestation(&row_id.hex()))
                .expect("I3602: read")
                .is_none(),
            "I3602: nothing stored behind a wait"
        );

        // ── I3602: a terminal refusal stays terminal ──
        let t = typed(
            run_op(
                rt,
                &directory,
                &DirectoryOp::PutEdition2Statement {
                    statement: br#"{"attestation":{}}"#.to_vec(),
                    offered_row_id: None,
                },
            ),
            "I3602 terminal",
        );
        assert_eq!(t.kind, "federation_malformed_row", "I3602: {t:?}");
        assert!(!t.wait, "I3602: terminal: {t:?}");
        let e = relay_typed_err(DirectoryOpResult::TypedErr(t)).expect_err("I3602");
        assert_eq!(e.kind(), "federation_malformed_row", "I3602 proxy");
        assert!(!e.is_wait(), "I3602 proxy: terminal");

        // SAFETY: single-drop, matched vtable.
        unsafe { (directory.vtable.drop)(directory.data) };
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn i3602_the_kind_and_the_wait_cross_the_capsule_sqlite() {
        let rt = runtime();
        let backend = rt.block_on(async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .expect("open sqlite");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        body(&rt, Arc::new(backend));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn i3602_the_kind_and_the_wait_cross_the_capsule_pg() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = runtime();
        let backend = rt.block_on(async {
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        body(&rt, Arc::new(backend));
    }

    /// I3602 — the consumer's rebuild, without a backend: `federation_backend`
    /// is `Backend` byte for byte; another token keeps its kind and wait
    /// through the interner (twice: the same `&'static str`); a non-token is
    /// `federation_backend`.
    #[test]
    fn i3602_the_rebuild_keeps_the_backend_arm_and_interns_the_kind() {
        let host = Error::Backend("insert attestation: UNIQUE constraint failed: x".into());
        let wire = serde_json::to_vec(&op_err(&host)).expect("serialize");
        let back: DirectoryOpResult = serde_json::from_slice(&wire).expect("deserialize");
        match relay_typed_err(back) {
            Err(Error::Backend(s)) => {
                assert_eq!(s, host.to_string(), "I3602: the pre-v62 flattening");
                assert!(
                    Error::Backend(s).is_duplicate_key(),
                    "I3602: a duplicate still reads as one"
                );
            }
            other => panic!("I3602: {other:?}"),
        }
        let host = Error::link_not_held("family", "insert family: FOREIGN KEY constraint failed");
        let a = CapsuleError::of(&host).into_error();
        let b = CapsuleError::of(&host).into_error();
        assert_eq!(a.kind(), "federation_link_not_held", "I3602");
        assert!(a.is_wait() && b.is_wait(), "I3602: the wait");
        assert!(
            std::ptr::eq(a.kind(), b.kind()),
            "I3602: one interned token per kind"
        );
        assert_eq!(a.to_string(), host.to_string(), "I3602: the host's text");
        let odd = CapsuleError {
            kind: "Not A Token!".into(),
            wait: false,
            message: "m".into(),
        }
        .into_error();
        assert_eq!(odd.kind(), "federation_backend", "I3602: a non-token");
        assert!(
            matches!(odd, Error::Relayed { .. }),
            "I3602: still relayed, with its text"
        );
    }
}

/// v62.0.0 (PX-fix1) — **the free folds read the HOST's store through the
/// capsule proxy**, two-sided (backend ← capsule dispatch ← [`OpsDirectory`]),
/// on sqlite and postgres. Before PX-fix1 every edition-2 and fold store read
/// fell to a trait default that answered empty / `None` / `false` through the
/// proxy, so a fold a consumer composed over it read "nothing held".
///
/// - **I2181** — after `fixture_genesis::install_v2` on the backend,
///   `genesis_in_force` over the proxy reads the same genesis (its holders,
///   seats and served lineage) as over the backend, and it is held.
/// - **I2182** — `held_keys_for_kid` over the proxy reads every seat and
///   holder key `Live` at its record's instant, as the backend does (it read
///   `NotHeld` through the empty default).
/// - **I2183** — each of the 13 routed reads answers through the proxy what
///   the backend answers, non-empty where the bundle holds rows (the bundle
///   objects, a seat's key records, a record row's voices, the statement-id
///   index and a point read from it), and the folds over them
///   (`bytes_servable`, `is_held_back`) agree.
/// - **I2184** — a method the proxy does not route answers `Unsupported`
///   naming itself, never an empty `Ok`: the three write hooks whose
///   defaults were a silent `Ok(())`, and an inherited fold-store write; the
///   retired Edge withdrawal verbs (their default was `Err(Backend)`) answer
///   `Unsupported` naming their edition-2 replacement.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod proxy_fail_open {
    use super::*;
    use crate::federation::edition2::liveness::Liveness;
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::{fixture_genesis, fold, genesis, ingest};
    use ciris_verify_core::edition2::identity_ref;
    use ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY;

    fn runtime() -> Arc<tokio::runtime::Runtime> {
        // ML-DSA-65 verifies overflow a 2 MB stack: the body runs on these
        // workers (spawned), never on the test thread.
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build tokio runtime"),
        )
    }

    async fn body(dir: Arc<dyn FederationDirectory>, proxy: Arc<dyn FederationDirectory>) {
        let d: &dyn FederationDirectory = dir.as_ref();
        let p: &dyn FederationDirectory = proxy.as_ref();
        let c = fixture_genesis::bundle_v2();
        fixture_genesis::install_v2(d)
            .await
            .expect("I2181: the bundle installs on the backend");

        // ── I2181 ──
        let direct = genesis::genesis_in_force(d).await.expect("I2181: direct");
        let via = genesis::genesis_in_force(p).await.expect("I2181: proxy");
        assert!(direct.is_held(), "I2181: the backend holds the genesis");
        assert!(via.is_held(), "I2181: the proxy reads a genesis held");
        assert_eq!(via.held, direct.held, "I2181: held count");
        assert_eq!(
            format!("{:?}", via.holders()),
            format!("{:?}", direct.holders()),
            "I2181: the holders"
        );
        assert_eq!(
            format!("{:?}", via.seats()),
            format!("{:?}", direct.seats()),
            "I2181: the seats"
        );
        assert_eq!(via.statements, direct.statements, "I2181: the lineage");
        assert_eq!(
            via.seats().len(),
            c.seats.len(),
            "I2181: every seat of the bundle"
        );
        assert!(!via.holders().is_empty(), "I2181: holders are read");

        // ── I2182 ──
        let kids: Vec<[u8; 32]> = c
            .seats
            .iter()
            .map(|s| s.kid)
            .chain(c.holders.iter().map(|h| h.kid))
            .collect();
        for kid in &kids {
            let held_d = ingest::held_keys_for_kid(d, kid)
                .await
                .expect("I2182: direct");
            let held_p = ingest::held_keys_for_kid(p, kid)
                .await
                .expect("I2182: proxy");
            let valid = held_d
                .valid_records(kid)
                .expect("I2182: the backend holds a valid record");
            let at = valid[0].record.asserted_at;
            let (ld, lp) = (held_d.liveness(kid, at), held_p.liveness(kid, at));
            assert!(
                matches!(ld, Liveness::Live(_)),
                "I2182: Live on the backend: {ld:?}"
            );
            assert!(
                matches!(lp, Liveness::Live(_)),
                "I2182: Live through the proxy (was NotHeld): {lp:?}"
            );
            assert_eq!(
                format!("{lp:?}"),
                format!("{ld:?}"),
                "I2182: the same reading"
            );
        }

        // ── I2183 ── each routed read: the proxy answers the host's store.
        let objs = d
            .edition2_objects(genesis::GENESIS_BUNDLE_TYP)
            .await
            .expect("I2183: direct objects");
        assert!(!objs.is_empty(), "I2183: the bundle's voices are held");
        assert_eq!(
            p.edition2_objects(genesis::GENESIS_BUNDLE_TYP)
                .await
                .expect("I2183: proxy objects"),
            objs,
            "I2183: edition2_objects"
        );
        let seat = &c.seats[0];
        let sub = identity_ref(&seat.kid);
        let about = d
            .edition2_statements_about(KEY_RECORD_FAMILY, &sub)
            .await
            .expect("I2183: direct about");
        assert!(!about.is_empty(), "I2183: the seat's key record is held");
        assert_eq!(
            p.edition2_statements_about(KEY_RECORD_FAMILY, &sub)
                .await
                .expect("I2183: proxy about"),
            about,
            "I2183: edition2_statements_about"
        );
        let rec = RowId(seat.record.row_id);
        let voices = d.edition2_voices(&rec).await.expect("I2183: direct voices");
        assert!(!voices.is_empty(), "I2183: the record row has its voice");
        assert_eq!(
            p.edition2_voices(&rec).await.expect("I2183: proxy voices"),
            voices,
            "I2183: edition2_voices"
        );
        for role in ["target", "head", "subject"] {
            assert_eq!(
                p.edition2_rows_naming(&rec, role)
                    .await
                    .expect("I2183: proxy naming"),
                d.edition2_rows_naming(&rec, role)
                    .await
                    .expect("I2183: direct naming"),
                "I2183: edition2_rows_naming {role}"
            );
        }
        let ids = d
            .edition2_statement_ids_since(None, 1000)
            .await
            .expect("I2183: direct ids");
        assert!(!ids.is_empty(), "I2183: the statement-id index is held");
        assert_eq!(
            p.edition2_statement_ids_since(None, 1000)
                .await
                .expect("I2183: proxy ids"),
            ids,
            "I2183: edition2_statement_ids_since"
        );
        let first: [u8; 32] = hex::decode(&ids[0])
            .expect("I2183: hex")
            .try_into()
            .expect("I2183: 32 bytes");
        let one = d
            .edition2_statement(&first)
            .await
            .expect("I2183: direct point read");
        assert!(one.is_some(), "I2183: the indexed statement is held");
        assert_eq!(
            p.edition2_statement(&first)
                .await
                .expect("I2183: proxy point read"),
            one,
            "I2183: edition2_statement"
        );
        let read_ok = |r: Result<String, Error>| r.expect("I2183: a fold read");
        assert_eq!(
            read_ok(p.fold_held_page(None, 100).await.map(|v| format!("{v:?}"))),
            read_ok(d.fold_held_page(None, 100).await.map(|v| format!("{v:?}"))),
            "I2183: fold_held_page"
        );
        for row in [rec, RowId(c.object_id), RowId([9u8; 32])] {
            assert_eq!(
                read_ok(p.fold_held(&row).await.map(|v| format!("{v:?}"))),
                read_ok(d.fold_held(&row).await.map(|v| format!("{v:?}"))),
                "I2183: fold_held"
            );
            assert_eq!(
                read_ok(p.fold_state(&row).await.map(|v| format!("{v:?}"))),
                read_ok(d.fold_state(&row).await.map(|v| format!("{v:?}"))),
                "I2183: fold_state"
            );
        }
        let slot = fold::blob_slot(&[7u8; 32]);
        assert_eq!(
            p.fold_slot_rows(&slot)
                .await
                .expect("I2183: proxy slot rows"),
            d.fold_slot_rows(&slot)
                .await
                .expect("I2183: direct slot rows"),
            "I2183: fold_slot_rows"
        );
        assert_eq!(
            p.fold_slot_held(&slot)
                .await
                .expect("I2183: proxy slot held"),
            d.fold_slot_held(&slot)
                .await
                .expect("I2183: direct slot held"),
            "I2183: fold_slot_held"
        );
        let keys = vec![format!("key:{sub}")];
        assert_eq!(
            p.fold_dependents(&keys).await.expect("I2183: proxy deps"),
            d.fold_dependents(&keys).await.expect("I2183: direct deps"),
            "I2183: fold_dependents"
        );
        assert_eq!(
            p.fold_any_refolding()
                .await
                .expect("I2183: proxy refolding"),
            d.fold_any_refolding()
                .await
                .expect("I2183: direct refolding"),
            "I2183: fold_any_refolding"
        );
        assert_eq!(
            fold::bytes_servable(p, &[7u8; 32])
                .await
                .expect("I2183: proxy servable"),
            fold::bytes_servable(d, &[7u8; 32])
                .await
                .expect("I2183: direct servable"),
            "I2183: bytes_servable"
        );
        for v in &c.voices {
            assert_eq!(
                fold::is_held_back(p, v)
                    .await
                    .expect("I2183: proxy held back"),
                fold::is_held_back(d, v)
                    .await
                    .expect("I2183: direct held back"),
                "I2183: is_held_back"
            );
        }

        // ── I2184 ── an unrouted method refuses by name through the proxy.
        let named = |r: Result<(), Error>, want: &str| match r {
            Err(Error::Unsupported { method }) => {
                assert_eq!(method, want, "I2184: the refusal names the method")
            }
            other => panic!("I2184 {want}: through the proxy answered {other:?}, not Unsupported"),
        };
        named(
            p.rewrap_own_epochs_for_device("owner", "device").await,
            "rewrap_own_epochs_for_device",
        );
        named(
            p.purge_attestation_projections("no-such-row").await,
            "purge_attestation_projections",
        );
        named(
            p.put_fold_reason(&RowId([9u8; 32]), None).await.map(|_| ()),
            "put_fold_reason",
        );
        // The retired Edge verbs refuse by name AND name their replacement.
        let retired = |r: Result<(), Error>, verb: &str, replacement: &str| match r {
            Err(Error::Unsupported { method }) => assert!(
                method.starts_with(verb) && method.contains(replacement),
                "I2184 {verb}: the refusal names its replacement: {method}"
            ),
            other => panic!("I2184 {verb}: through the proxy answered {other:?}"),
        };
        retired(
            p.record_canonical_withdrawal("k", None, "d").await,
            "record_canonical_withdrawal",
            "PutGenesisBundle",
        );
        retired(
            p.record_role_withdrawal("steward", "k", None, "d").await,
            "record_role_withdrawal",
            "PutEdition2Statement",
        );
    }

    fn run(rt: &Arc<tokio::runtime::Runtime>, dir: Arc<dyn FederationDirectory>) {
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(
            rt.clone(),
        ));
        let proxy =
            build_ops_directory(build_persist_directory(dir.clone()), executor).expect("abi ok");
        rt.block_on(rt.spawn(body(dir, proxy)))
            .expect("the witness body");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn i2181_to_i2184_folds_read_the_host_through_the_proxy_sqlite() {
        let rt = runtime();
        let b = rt.block_on(async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .expect("open sqlite");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        run(&rt, Arc::new(b));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn i2181_to_i2184_folds_read_the_host_through_the_proxy_pg() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let rt = runtime();
        let b = rt.block_on(async {
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect");
            crate::store::backend::Backend::run_migrations(&b)
                .await
                .expect("migrate");
            b
        });
        run(&rt, Arc::new(b));
    }
}
