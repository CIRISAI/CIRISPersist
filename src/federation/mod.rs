//! Federation directory — pubkey + attestation + revocation substrate
//! (v0.2.0+, PoB §3.1).
//!
//! # Mission alignment (MISSION.md §2 — `federation/`)
//!
//! Persist holds the substrate; consumers compose policy. This module
//! defines the [`FederationDirectory`] trait — CRUD over three tables
//! (`federation_keys`, `federation_attestations`, `federation_revocations`)
//! plus serde wire types and write-authority guards. Backends (memory,
//! postgres, sqlite) implement the trait in [`crate::store`].
//!
//! **No `is_trusted()` / `trust_score()` / `trust_path()` methods.**
//! Those are policy decisions consumers compose by walking the
//! attestation graph however they want; persist exposes the edges, the
//! consumer composes the traversal. See `docs/FEDERATION_DIRECTORY.md`
//! §"Explicit non-goals" for the architectural boundary.
//!
//! ## Wire-format compatibility with CIRISRegistry
//!
//! `CIRISRegistry/rust-registry/src/federation/types.rs` vendors the
//! same shapes as this module's [`types`]. The contract:
//!
//! - Field names + types match field-for-field.
//! - Field ordering matters for `serde_json` default serialization
//!   (registry hashes the vendored shape; persist hashes its own).
//! - `persist_row_hash` is computed server-side by persist via the
//!   `PythonJsonDumpsCanonicalizer` (sorted keys, no whitespace,
//!   `ensure_ascii=True`) and shipped on read responses. Consumers
//!   store + string-compare; they don't reproduce the canonicalizer.
//!
//! See `docs/FEDERATION_DIRECTORY.md` for the architectural contract
//! and the registry-side `docs/FEDERATION_CLIENT.md` for the consumer
//! complement.

pub mod accord_carriage;
pub mod accord_quorum;
pub mod admission;
pub mod age;
pub mod at_rest_cascade;
/// v36.0.0 (CIRISPersist#624) — the typed, pre-write replicated
/// ATTESTATION-plane apply (`AttestationRefusalReason` /
/// `ReplicatedAttestationOutcome`): the Key plane's #565 twin.
pub mod attestation_apply;
/// v25.1.0 (CIRISPersist#582) — the backend-generic signed-ATTESTATION emit
/// recipe (distinct from [`emit`], the trust-grant/audit-entry API).
pub mod attestation_emit;
#[cfg(feature = "cirisaudit")]
pub mod backfill;
pub mod blackhole;
pub mod blobs;
pub mod bootstrap_admission;
pub mod canonical_at_rest;
pub mod capacity;
pub mod cohort;
pub mod community_dek;
pub mod consent;
pub mod consent_grammar;
pub mod consent_peer_set;
// (CIRISPersist#612) — the `content_class:*` flag-plane read predicate. The
// write door is open by constitutional decision (#571 / CC 3.3.12); this is
// where the discrimination lives.
pub mod content_class;
#[cfg(feature = "cirisaudit")]
pub mod emit;
// (CIRISPersist#519 / #520) — the family-rule INVENTORY: every namespace family
// persist states an emitter/composition rule about, derived from each ruling
// surface at its own source, plus the pinned gap where the vendored registry
// states no such rule. Generalizes #590's minted-only pin (3 of 17) and closes
// it with a source scan, so a new purpose-built gate cannot be invisible to the
// inventory. Pure gates + accessors; no wire surface.
pub mod family_rules;
pub mod genesis;
pub mod goal;
pub mod hardware_attestation;
pub mod identity_aggregate;
// (CIRISPersist#519 item 3) — the invariant-registry admission enforcement
// + consistency witness: the admission-enforceable subset of the vendored
// `invariant_registry` (571 invariants / 104 families) and the executed
// proof that persist's hardcoded reserved-prefix admission surface cannot
// silently drift from it. See the module doc for what's newly enforced
// (one gap: `health:liveness:*` self-emission) vs. already-covered vs.
// consumer-owned.
pub mod invariant;
pub mod location;
/// v31.0.0 (CIRISPersist#650) — the in-place v31 migration: re-stamp the FINAL
/// folded CEG state from the owner root, then purge what is provably dead.
pub mod migration;
pub mod namespace;
// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13 / §10.1.6) — operational-
// data admit + merge surface (organization / org_membership /
// partner_record). Row shapes, the four admission checks, and the two
// CEG-declared merge dispatchers; the backends do the storage I/O.
pub mod operational;

/// v18.3.0 (CIRISPersist#484) — the exported accord co-scrub test-minting
/// surface: `Identity`, `signed_canonical_record[_with_roles]`, and
/// `register_accord_holder`. Behind `test-anchor` (persist's test-only,
/// never-in-a-published-wheel fence) so a DOWNSTREAM consumer gating a real
/// plane on `has_accord_conferred_role` can mint a genuinely co-scrubbed record and
/// test the ALLOW path — not just the deny path.
#[cfg(any(test, feature = "test-anchor"))]
pub use operational::test_support as accord_test_support;
// (CIRISPersist#578, CIRISConstitution rc3 CC 3.2) — the `ownership:*`
// ownerless-lock reclaim CEREMONY: petition → CC 4.3 Wise-Authority quorum
// finding → gated `withdraws` leaving the node UNOWNED → fresh owner-binding
// co-signed by the node. Refuses every reclaim until a deployment publishes a
// WA body; the accord holder roster is explicitly NOT that body. See the
// module doc for the full ceremony and the single-act wall.
pub mod ownership_reclaim;
pub mod perceptual_hash;
pub mod precedence;
#[cfg(feature = "cirisaudit")]
pub mod read;
// v8.8.0 (CIRISPersist#234, CEG 1.0-RC28/RC29 §5.6.8.15) — the single
// canonical federation-key registration admission gate (hybrid-verify
// the registration + §7 reserved-prefix identity rules + fail-secure).
// DRYs the out-of-group peering gate that CIRISServer/CIRISStatus
// previously re-derived; `consent:replication` stays CEG-side
// governance.
pub mod envelope;
/// v31.0.0 (CIRISPersist#645) — the byte-exactness witness for the V122
/// signature-covered envelope columns.
pub mod envelope_bytes;
// v21.6.0 (CIRISPersist#519 item 2a-iii) — the signed `fresh_as_of`
// freshness floor: SignedTouchClaim's storage + monotonic-max merge
// (persist's half; the producer surface is edge/agent's, documented for
// adoption, not built here). See `namespace/namespace_supersets.json` §
// `freshness_floor`.
pub mod deletion_window;
// CIRISPersist#573 / CIRISVerify#241 / CIRISConstitution#78 — erasability is a
// MINT-time property. An object is either SEALED (payload inside the signed
// envelope, permanent by arithmetic) or ERASABLE (payload beside it as salted
// disclosures, erasable without touching a single signed byte). The module doc
// carries the containment ruling and the evidence for it.
pub mod erasable;
pub mod freshness;
// v24.2.0 (CIRISPersist#564 stage 1) — the reachability primitive: is a CEG
// object load-bearing on THIS node? Read-only, fail-secure, and gated for
// exhaustiveness against the #519 manifest. Releases nothing.
pub mod load_bearing;
// CIRISServer#356 — the OPERATOR read surface: the node-scoped state signals
// this substrate already computes, folded into one banded, three-valued
// answer. A gauge, never a gate; see the module doc.
pub mod node_state;

/// v20.1.0 (CIRISPersist#478) — the trace-attestation backfill report:
/// what minted (incl. idempotent already-present no-ops — the funnels'
/// conflict-ignore makes a re-run indistinguishable from a first run) and
/// what SKIPPED with its typed reason (honest accounting, e.g. an
/// unregistered pre-18.0 producer key).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TraceBackfillReport {
    /// Traces whose attestation now exists (minted or already present).
    pub minted: usize,
    /// `(trace_id, error kind)` for traces the funnels refused.
    pub skipped: Vec<(String, String)>,
}

/// v21.2.0 (CIRISPersist#509 FLOOR) — one
/// [`crate::Engine::promote_consented_backlog`] sweep's tally: local-tier
/// attestations promoted to federation tier (their dimension was covered
/// by a LIVE self-authored `consent:replication:v1` grant) vs. skipped
/// (an `attestation_promote` error on that ONE row — logged via
/// `tracing::warn!` and counted, never wedging the rest of the sweep;
/// the same honest-accounting posture [`TraceBackfillReport`]
/// established for the #478 backfill).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ConsentSweepReport {
    /// Local-tier attestations promoted to federation tier this sweep
    /// (the [`crate::Engine::promote_consented_backlog`] motion).
    pub promoted: u64,
    /// Federation-tier rows whose suppressed (`self`/`family`) placement
    /// was corrected to the covering grant's federation-visible audience
    /// (the [`crate::Engine::repair_stranded_scope_backlog`] motion —
    /// CIRISPersist#530). `0` for the promote sweep, which never touches
    /// federation-tier rows.
    pub rescoped: u64,
    /// Rows that matched a live grant's prefix set but failed the sweep's
    /// write (promote or re-scope) on that ONE row — logged via
    /// `tracing::warn!` and counted, never wedging the rest of the sweep;
    /// the same honest-accounting posture [`TraceBackfillReport`]
    /// established for the #478 backfill.
    pub skipped: u64,
}

pub mod register;
// CIRISPersist#571 — `regime:*` experimental-regime research artifacts:
// the CC-blocked registry finding + the replication decision.
pub mod regime;
pub mod replication;
pub mod replication_policy;
pub mod rooting;
// v25.1.0 (CIRISPersist#570 ask 5) — quarantine: withhold from serving.
// Tier 2 of the graded response set; a marker, never a command.
pub mod quarantine;
// v28.3.0 (CIRISPersist#570 ask 1) — the mesh_config plane: a trust root turns
// a knob on the nodes that subscribe to it, bounded by CC 4.2.1's
// relieve-never-expand and most-restrictive-across-roots.
pub mod mesh_config;
// v24.3.0 (CIRISPersist#574) — reverse quorum: the commons' brake.
// 1-of-N to protect, m-of-n to undo.
pub mod reverse_quorum;
pub mod schema_resolver;
pub mod scores;
pub mod scores_read_audit;
pub mod trust_root;
// CIRISPersist#210 — cross-process leader election (RNS shared-instance
// owner; CIRISEdge#100). Backend-agnostic types + staleness helper; the
// atomic acquire/heartbeat/release live in the backends.
pub mod shared_instance;
// CIRISPersist#146 Ask 3 — the substrate hard_case:* emission surface
// (consent-SLA watcher + general observability primitive; CEG §8.1.11.3).
pub mod hard_case;
// CIRISPersist#183 — the "self at login" substrate vocabulary
// (delegation/partnership envelope builders + scope tokens +
// TransportDestination type; CEG §8.1.12.7 / §5.6.8.8.1).
pub mod self_at_login;
#[cfg(feature = "sqlite")]
pub mod sqlite_open;
// CIRISPersist#507b — the shared signed-wire content-hash index
// (V111 `signed_wire_index`): content-hash + record-key helpers every
// backend's signed-record write chokepoint calls.
pub mod wire_index;
// v4.1 (CIRISPersist#142 Cut C2) — streaming-chunk AES-256-GCM + STREAM
// nonce. Gated on `secrets`: routes through that feature's
// `secrets::crypto` facade (MISSION §1.4 sole symmetric-crypto site).
#[cfg(feature = "secrets")]
pub mod stream_seal;
// v4.1 (CIRISPersist#142 Cut C4) — delivery-receipt canonical bytes +
// subscriber-signature verify. Backend-agnostic; the JOIN-against-STH
// gate + storage live in the backends.
pub mod stream_receipt;
pub mod stream_sth;
pub mod substrate_machine;
// v9.0.0 (CIRISPersist#237, CC 5.3.2.4.3.1) — the PQC-mandatory
// federation-tier ingest gate: hybrid-verify a federation-tier
// attestation's envelope signature against the attester's REGISTERED
// pubkeys at the bulk store/replicate path, BEFORE persist. Local-tier
// rows are exempt (CC 5.3.2.2 deferred signature). Sibling of
// `register::verify_key_registration`; same verify contract.
/// v31.4.0 (CIRISPersist#603/#604) — the fault-injecting `FederationDirectory`
/// double. Test-only, and `pub` because consumers need it.
#[cfg(any(test, feature = "test-anchor"))]
pub mod directory_double;
pub mod tier_ingest;
pub mod topology;
// v21.6.0 (CIRISPersist#519 item 2a-ii) — the closed, total (terminating)
// transform algebra: named opcodes, fixed arity, no loops/recursion/user-
// defined functions. `consent_grammar::strip_field` delegates here (ONE
// strip implementation); see the module doc for the live-vs-declared-only
// opcode split and the TRANSFORM_ALGEBRA_HASH pin.
pub mod transform;
pub mod trust_grant;
pub mod types;
pub mod verify_coord;

/// Base64-string serde codec for `Vec<u8>` byte fields. Mirrors the
/// private module of the same name in `crate::audit::types` — kept
/// in lockstep so federation + audit wire shapes serialize byte
/// fields identically (base64 standard alphabet). Visibility is
/// `pub(crate)` so the federation submodules use it via
/// `#[serde(with = "crate::federation::serde_bytes_b64")]` without
/// re-exporting the codec on the public surface.
pub(crate) mod serde_bytes_b64 {
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

pub use admission::{
    canonical_withdrawal_payload_sha256, check_accord_role_admission_over_roster,
    check_canonical_role_admission, check_canonical_role_admission_over_roster,
    check_co_steward_role_admission, check_co_steward_role_admission_over_roster,
    check_cohort_scope, check_consensus_protocol_form, check_device_class,
    check_encryption_pubkeys, check_infra_attest_role_admission,
    check_infra_attest_role_admission_over_roster, check_observed_region, check_row_column_binding,
    has_accord_conferred_role, has_accord_conferred_role_over_roster, is_canonical,
    is_canonical_effective, is_infra_attest, is_infra_attest_effective, op_withdraw_role,
    supersede_canonical, verify_canonical_supersede_authority, verify_canonical_withdraw_authority,
    verify_signed_identity_occurrence_revocation, verify_signed_touch_claim,
    verify_signed_transport_destination, verify_touch_claim_admission, withdraw_accord_role,
    withdraw_accord_role_over_roster, withdraw_canonical_role, withdraw_infra_attest_role,
    CanonicalWithdrawal, DimensionAdmissionPolicy, DimensionRejectionReason,
    NamespaceConformanceReason, ReachabilityVerdict, ReservedPrefixRule, RoleWithdrawal,
    ATTESTATION_LADDER_MECHANISMS, DEFAULT_MAX_TOUCH_SKEW, MINTED_NAMESPACE_FAMILIES,
    UNREGISTERED_GATED_FAMILIES,
};
pub use blackhole::{BlackholeRecord, BlackholeRules, RETICULUM_IDENTITY_HASH_LEN};
pub use blobs::{
    holds_bytes_attestation_envelope, holds_bytes_attestation_type, BlobBody, BlobError, BlobRange,
    BlobStorage, ChunkManifest, ChunkRef, EvictActorReport, ExternalRef, GroupDekRef,
    PutBlobAttestation, ScopeBlobSymbol, CHUNK_MANIFEST_VERSION, DEFAULT_INLINE_BYTES_CAP,
    HOLDS_BYTES_ATTESTATION_TYPE_PREFIX, HOLDS_BYTES_PREFIX_HEX_LEN,
};
pub use cohort::{Cohort, GroupRef, GroupVersion, RevokeSpec, RosterMember};
pub use consent::consent_role_of;
pub use freshness::{coalesce_touch_ts, TouchApplyOutcome};
pub use goal::{
    canonicalize_goal_text, DeliberationRef, Goal, GoalScope, GoalsFilter, M1Dimension,
    MetaGoalAlignment,
};
pub use hard_case::{
    check_admin_action_attribution, AdminActionRefusal, ConsentPromotionOverdueRow, ConsentState,
    ConsentWatchReport, HardCaseEvent, HardCaseFilter,
};
// v25.1.0 (CIRISPersist#570 ask 5) — the quarantine marker plane. Exported
// beside the refusal taxonomies above; downstream keys on the `as_str` tokens.
pub use quarantine::{
    fold_quarantine, is_withheld, resolve_quarantine, QuarantineFold, QuarantineOutcome,
    QuarantineRefusalReason, QuarantineState,
};
// v28.3.0 (CIRISPersist#570 ask 1) — the mesh-config plane. Same export
// discipline: downstream keys on the `as_str` tokens, which are append-only.
pub use mesh_config::{
    fold_mesh_config, record_mesh_config_row, resolve_mesh_config, FlowPolarity,
    MeshConfigBaseline, MeshConfigFold, MeshConfigForm, MeshConfigKey, MeshConfigKeySpec,
    MeshConfigOutcome, MeshConfigRefusalReason, MeshConfigSetting, MeshConfigUnit, RootValue,
};
// v25.1.0 (CIRISPersist#570 ask 4) — the time-bounded de-admission fold.
pub use hardware_attestation::{HardwareAttestationPolicy, DEFAULT_MAX_NONCE_AGE};
pub use identity_aggregate::{
    ContentKemIdentity, LocalIdentityAggregate, LOCAL_IDENTITY_AGGREGATE_VERSION,
};
pub use operational::{
    MergeIntent, OrgMembership, Organization, PartnerRecord, SignedOrgMembership,
    SignedOrganization, SignedPartnerRecord, SubjectKind,
};
pub use ownership_reclaim::{
    check_ownership_reclaim_admission, check_post_reclaim_rebinding_admission, ReclaimPolicy,
    ReclaimRefusal, ReclaimVerdict, WaFinding, WaQuorum, OWNERSHIP_FRESHNESS_TARGET_KIND,
    RECLAIM_WITHDRAWS_ADMISSION_RULE,
};
pub use perceptual_hash::{
    HashDatabaseId, HashMatchError, HashMatchResult, MatcherUnreachablePolicy,
    NullPerceptualHashMatcher, OnMatchPolicy, PerceptualHashMatcher, SharedMatcher,
};
pub use register::verify_key_registration;
pub use register::{
    check_revocation_bound, resolve_key_statement_standing, KeyStatementFold, KeyStatementStanding,
    RevocationBoundRefusal,
};
pub use replication::{
    aggregate_trust_score, classify_free_bytes, parse_human_bytes, withdraws_attestation_envelope,
    AdmissionGate, ByteParseError, CacheMode, DiskPressureConfig, DiskPressureMonitor,
    DiskPressureMonitorHandle, DiskPressureSnapshot, EvictionCandidate, EvictionDecay,
    EvictionSweeper, FamilyPredicate, FreeBytesSource, MemoryTrustScoring, PressureAction,
    PressureTier, ReplicationConfig, StatvfsFreeBytes, StubFreeBytes, SweepReport, TrustScoring,
    TrustScoringError, TrustTier, DEFAULT_SWEEP_BATCH, MIN_POLL_INTERVAL, MIN_SWEEP_INTERVAL,
};
// v24.3.0 (CIRISPersist#575) — re-exported at `federation::` because
// `Error::RateLimited` carries it: a public error variant must not force every
// consumer to name a path into `replication::admission`, and the error surface
// must not be welded to an internal module layout. Definition stays beside the
// logic that produces it (the `register::KeyRefusalReason` precedent from #565).
pub use replication::admission::{PeerQuotaRefusal, PeerQuotaRefused};
// v25.1.0 (CIRISPersist#569) — same rationale as `PeerQuotaRefusal` above:
// `Error::ConsentGateRefused` carries these, so a consumer must not have to
// name a path into `admission` to match on the error it was handed.
pub use admission::{ConsentGateRefused, ConsentGatedClaim, ConsentGatedFamily};
pub use rooting::{
    provenance_chain, root_binding, ProvenanceChain, ProvenanceLink, RootingRejection,
    RootingVerdict, MAX_PROVENANCE_DEPTH,
};
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub use schema_resolver::BlobBackedSchemaResolver;
pub use schema_resolver::{
    axis_from_dimension, AxisSchema, NoOpSchemaResolver, SchemaResolver, SchemaResolverError,
};
pub use self_at_login::{
    delegates_to_agent_envelope, delegates_to_envelope, owner_binding_delegates_to_envelope,
    partnership_accept_envelope, partnership_grant_envelope, SignedTransportDestination,
    TransportDestination, TransportDestinationApplyOutcome, SELF_AT_LOGIN_DELEGATION_SCOPE,
};
pub use shared_instance::{SharedInstanceLease, DEFAULT_STALE_AFTER};
#[cfg(feature = "sqlite")]
pub use sqlite_open::FederationDirectorySqlite;
pub use stream_sth::{
    log_id_for_stream, parse_stream_id, recompute_and_assert_root, StreamChunkLeaf,
    STREAM_LOG_ID_PREFIX,
};
pub(crate) use tier_ingest::community_reput_verdict;
pub use tier_ingest::{
    verify_community_admission, verify_community_membership_revocation_admission,
    verify_envelope_hybrid_signature, verify_family_admission,
    verify_family_membership_revocation_admission, verify_federation_tier_ingest,
    verify_location_proof_admission, verify_revocation_admission, verify_row_hybrid_signature,
};
pub use topology::{
    build_delegation_graph, build_trust_topology, AuditChainEntry, AuditChainProof, DelegationEdge,
    DelegationGraph, EdgeType, FederationDirectoryFilter, TrustEdge, TrustNode, TrustTopology,
    WithdrawalEntry, MAX_DELEGATION_DEPTH,
};
pub use types::{consent_role, device_class, identity_type};
pub use types::{
    Attestation, AttestationReseal, Community, CommunityMember, CommunityMembershipRevocation,
    EmitAttestationInput, EncryptionPubkeys, Family, FamilyMember, FamilyMembershipRevocation,
    HybridPendingRow, IdentityOccurrence, IdentityOccurrenceRevocation, KeyRecord, LocationProof,
    PeerMetadataRow, PeerPolicyBlob, Revocation, ServedAttestation, ServedCommunity,
    ServedCommunityMembershipRevocation, ServedFamily, ServedFamilyMembershipRevocation,
    ServedIdentityOccurrence, ServedIdentityOccurrenceRevocation, ServedKeyRecord,
    ServedLocationProof, ServedOrgMembership, ServedOrganization, ServedPartnerRecord,
    ServedRevocation, ServedSignedPartnerRecord, ServedTransportDestination, SignedAttestation,
    SignedCommunity, SignedCommunityMembershipRevocation, SignedFamily,
    SignedFamilyMembershipRevocation, SignedIdentityOccurrence, SignedIdentityOccurrenceRevocation,
    SignedKeyRecord, SignedLocationProof, SignedRevocation, SignedTouchClaim, SignedTrustGrant,
    SignedTrustRevocation, SignerForm, TrustClass, TrustFilter, TrustGrant, TrustRelationship,
    TrustRow, TrustType,
};

/// v9.3.0 (CIRISPersist#249 Cut B) — the **roster-minus-effective-
/// revocations** fold, shared by every "currently-active membership"
/// reader. `removed_key_ids_at` collapses a revocation list to the set of
/// member key_ids whose `effective_at <= as_of`; callers then retain only
/// the roster members NOT in that set.
///
/// This is the ONE place the "a revocation with `effective_at <= now`
/// drops its subject" rule lives. The community-DEK cascade
/// ([`community_dek::orchestrate`]'s `resolve_community_members`) and the
/// new `active_*_members` group-roster readers both compose it, so the
/// forward-secrecy subtraction is never forked. A FUTURE-dated revocation
/// (`effective_at > as_of`) is intentionally NOT in the removed set — the
/// member is still active until its effective time arrives.
///
/// `revs` yields `(removed_identity_key_id, effective_at)` pairs (the
/// shape both [`FamilyMembershipRevocation`] and
/// [`CommunityMembershipRevocation`] project to).
pub fn removed_key_ids_at<'a, I>(
    revs: I,
    as_of: chrono::DateTime<chrono::Utc>,
) -> std::collections::HashSet<&'a str>
where
    I: IntoIterator<Item = (&'a str, chrono::DateTime<chrono::Utc>)>,
{
    revs.into_iter()
        .filter(|(_, effective_at)| *effective_at <= as_of)
        .map(|(key_id, _)| key_id)
        .collect()
}

/// #249 Cut G3.5 — the verify-A-store-B guard for quorum-gated supersede: the
/// roster/protocol being persisted MUST be exactly the one the quorum
/// authorized in `change_envelope` (`group_key_id` + member `key_id` set +
/// `consensus_protocol` all match). Defends against verifying one membership
/// change and storing another.
fn assert_change_envelope_matches(
    group_key_id: &str,
    new_member_key_ids: &std::collections::BTreeSet<&str>,
    new_consensus_protocol: &str,
    change_envelope: &serde_json::Value,
) -> Result<(), Error> {
    let env_key = change_envelope
        .get("family_key_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if env_key != group_key_id {
        return Err(Error::InvalidArgument(format!(
            "supersede: change_envelope family_key_id {env_key:?} != group {group_key_id:?}"
        )));
    }
    let env_cp = change_envelope
        .get("consensus_protocol")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if env_cp != new_consensus_protocol {
        return Err(Error::InvalidArgument(format!(
            "supersede: change_envelope consensus_protocol {env_cp:?} != superseding row \
             {new_consensus_protocol:?}"
        )));
    }
    let env_members: std::collections::BTreeSet<&str> = change_envelope
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|m| m.get("key_id").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default();
    if &env_members != new_member_key_ids {
        return Err(Error::InvalidArgument(
            "supersede: change_envelope roster does not match the superseding roster".to_string(),
        ));
    }
    Ok(())
}

/// CIRISPersist#293 (CC 2.6.3 / CEG §0.6) — reject any `subject_key_ids[]`
/// element that is not in canonical (all-lowercase) form. A subject id is a
/// federation key_id — on real nodes the derived `"<label>-<fingerprint>"`
/// shape, which is all-lowercase by construction — so the rule is exactly
/// the §0.6/§0.8 lowercase-canonical rejection already enforced on adjacent
/// fields (`location.rs` `cell_id`, `media_sharing.rs` hashes): an uppercase
/// or otherwise non-canonical subject id breaks byte-identical
/// canonicalization for downstream verifiers (two encodings of the same
/// subject would both admit). We reject ASCII-uppercase rather than a strict
/// `0-9a-f` charset because a derived key_id legitimately carries a `-` and a
/// lowercase alphabetic label — the operative canonical invariant is "no
/// uppercase", matching the precedent validators.
///
/// # Why this is no longer backend-gated (a pre-existing red, fixed here)
///
/// It used to carry `#[cfg(any(feature = "postgres", feature = "sqlite"))]`,
/// on the stated grounds that its *sole* caller
/// (`Engine::emit_attestation_assemble`) carried the same gate and it would
/// otherwise be dead code. v25.1.0 (CIRISPersist#582) added a SECOND caller —
/// [`attestation_emit::assemble_and_put`] — and that one is **not** gated, so
/// from that release the crate stopped compiling with no backend feature at
/// all: `cargo check`, and CI's `cargo nextest run --test
/// wire_format_fixtures` default leg, both fail with "cannot find function
/// `validate_subject_key_ids` in module `super`".
///
/// The gate's premise is simply no longer true — an ungated caller makes this
/// live in every configuration — so the gate is removed rather than the second
/// caller being gated to match. Found while verifying CIRISServer#356 against
/// the feature matrix; unrelated to that work, and fixed rather than deferred
/// because a leg that cannot compile is a leg that proves nothing.
pub(crate) fn validate_subject_key_ids(subject_key_ids: &[String]) -> Result<(), Error> {
    for sid in subject_key_ids {
        if sid.is_empty() || sid.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(Error::InvalidArgument(format!(
                "subject_key_ids element must be a canonical lowercase key_id \
                 (CC 2.6.3 / §0.6); got {sid:?}"
            )));
        }
    }
    Ok(())
}

/// CIRISServer#356 — **the one definition of "this revocation is overdue for
/// promotion"** (CC 5.3.2.2 / §10.1.3's never-rest-local tripwire).
///
/// A subject-side `consent:state:revoked` fires iff it is still at a
/// non-federation tier, has no `promoted_at`, and has rested longer than
/// `window`. Extracted so
/// [`FederationDirectory::list_consent_revocation_promotion_overdue`] and its
/// non-emitting twin
/// [`FederationDirectory::list_consent_revocation_promotion_overdue_readonly`]
/// ask the identical question — a read-only variant that re-derived the
/// predicate would be a second definition of overdue, and this repo has a
/// recorded defect class for exactly that (one predicate, one impl).
#[must_use]
pub fn is_promotion_overdue(
    rev: &Attestation,
    now: chrono::DateTime<chrono::Utc>,
    window: chrono::Duration,
) -> bool {
    let local = rev.tier != crate::federation::types::attestation_tier::FEDERATION;
    local && rev.promoted_at.is_none() && now - rev.asserted_at > window
}

/// The projection shared by both overdue readers, for the same reason
/// [`is_promotion_overdue`] is shared: two readers of one condition must
/// produce one row shape.
#[must_use]
fn overdue_row(
    rev: &Attestation,
    now: chrono::DateTime<chrono::Utc>,
) -> hard_case::ConsentPromotionOverdueRow {
    hard_case::ConsentPromotionOverdueRow {
        attestation_id: rev.attestation_id.clone(),
        target_key_id: rev.attested_key_id.clone(),
        subject_key_id: rev.attesting_key_id.clone(),
        asserted_at: rev.asserted_at,
        age_seconds: (now - rev.asserted_at).num_seconds().max(0) as u64,
        tier: rev.tier.clone(),
    }
}

/// Federation directory trait — the registry/lens/agent's read+write
/// surface over persist's three federation tables.
///
/// # Object-safety (v2.6.0, CIRISPersist#106)
///
/// The trait is annotated with [`#[async_trait]`](async_trait::async_trait)
/// so it is **object-safe** — consumers can build
/// `Arc<dyn FederationDirectory>` (the shape
/// [`Engine::federation_directory`](crate::Engine::federation_directory)
/// returns). The macro rewrites each `async fn` to a `Pin<Box<dyn
/// Future<Output = …> + Send + '_>>` return — one heap allocation per
/// call. For the federation directory's call frequency (admission paths,
/// directory lookups, attestation enumeration) the per-call alloc is
/// not a hot-path concern.
///
/// # Wire-format note
///
/// Read methods return [`KeyRecord`] / [`Attestation`] / [`Revocation`]
/// with `persist_row_hash` populated server-side (see
/// [`types::KeyRecord::persist_row_hash`] for the canonicalization
/// contract). CIRISVerify v3.2.0+ binds the field into
/// `FederationProvenance::persist_row_hash` so a downstream consumer
/// can trace an attestation back to its underlying persist row
/// (CIRISPersist#108).
///
/// Write methods take [`SignedKeyRecord`] / [`SignedAttestation`] /
/// [`SignedRevocation`] — wrappers carrying a record the caller has
/// signed but persist has not yet stored. Persist verifies the
/// scrub-signature on receipt before writing.
#[async_trait::async_trait]
pub trait FederationDirectory: Send + Sync {
    // ── Public keys ────────────────────────────────────────────────

    /// Insert a new pubkey row. Idempotent on `key_id` collision with
    /// matching content (no-op); errors on `key_id` collision with
    /// differing content.
    async fn put_public_key(&self, record: SignedKeyRecord) -> Result<(), Error>;

    /// v23.1.0 (CIRISPersist#554) — the hardware-attestation policy THIS
    /// directory admits `accord_holder` rows under.
    ///
    /// Exists so a validator other than the put path can run the *same*
    /// predicate: `genesis::verify_bundle_quorum` checks holder-evidence
    /// admissibility through this, so **a bundle that verifies is a bundle
    /// that installs**. #554 was the two of them disagreeing about the same
    /// bytes — the verifier passed the production bundle while
    /// [`Self::put_public_key`] refused every holder it carried.
    ///
    /// Reaching the configured policy (rather than `default()`) is the point:
    /// a deployment that tightened its accepted set must have the verifier
    /// tighten with it, or the disagreement simply returns in another form.
    /// The default body is the default policy — a directory impl that has no
    /// configuration surface needs no override.
    fn hardware_attestation_policy(&self) -> std::sync::Arc<HardwareAttestationPolicy> {
        std::sync::Arc::new(HardwareAttestationPolicy::default())
    }

    /// v30.2.0 (CIRISPersist#607) — **this node's own federation key id**, when
    /// the host has told the directory who it is.
    ///
    /// Admission gates that must ask *"do **I** trust the root that conferred
    /// this?"* need an identity to ask on behalf of. Without one the question
    /// has no non-circular form: asking whether the ATTESTER trusts the root
    /// that vouches for the attester is answered by two rows the attester signs
    /// itself, which is forgery, not verification.
    ///
    /// `None` is the honest default for a directory nobody configured, and
    /// callers MUST treat it as *cannot verify* — which for an
    /// authority-bearing row means REFUSE, never admit. Injected exactly like
    /// [`hardware_attestation_policy`](Self::hardware_attestation_policy): the
    /// host sets it, the trait exposes it, and no gate reaches past the host to
    /// invent one.
    fn node_key_id(&self) -> Option<String> {
        None
    }

    /// v13.0.1 (CIRISPersist#375) — the **upgrade-aware, `owner_of`-gated
    /// Key-plane apply** for anti-entropy replication, dyn-dispatchable.
    ///
    /// This is the trait surface for the #371 apply. Edge's replication
    /// bridge holds an `Arc<dyn FederationDirectory>` and has no concrete
    /// backend type, so the inherent
    /// `apply_replicated_key_record` on `SqliteBackend`/`PostgresBackend`
    /// (dispatched by [`Engine::apply_replicated_key_record`](crate::Engine::apply_replicated_key_record))
    /// was unreachable — a receiver could only call [`Self::put_public_key`]
    /// (`ON CONFLICT DO NOTHING`), silently dropping an anchor-scrubbed
    /// record for a `key_id` it already holds self-signed. That DO-NOTHING
    /// is exactly what #371 replaces over replication.
    ///
    /// The real sqlite/postgres backends **override** this to run the
    /// monotonic, verify-before-mutation upgrade path (the
    /// [`plan_replicated_key_apply`](register::plan_replicated_key_apply)
    /// classification + `adopt_scrub_upgrade` on the Upgrade arm). The
    /// default body here preserves the memory/mock backends: they have no
    /// scrub-upgrade plane, so an incoming record is a **first-seen
    /// insert** — `put_public_key` already leaves an existing differing row
    /// untouched, so a collision resolves to `Refused` (fail-closed,
    /// re-offerable) rather than aborting the anti-entropy loop.
    async fn apply_replicated_key_record(
        &self,
        record: SignedKeyRecord,
    ) -> Result<register::ReplicatedKeyOutcome, Error> {
        match self.put_public_key(record).await {
            Ok(()) => Ok(register::ReplicatedKeyOutcome::Inserted),
            // First-seen wins on the replication plane: a differing row
            // already present ⇒ not applied, but safe to re-offer.
            // v24.2.0 (CIRISPersist#565) — named `StoreConflict`, not one of
            // the plan's policy reasons: this body has no plan, so all it can
            // honestly report is that the store step found a different row.
            // Claiming a policy branch it never evaluated would be the
            // mislabelled-refusal failure #565 exists to end.
            Err(Error::Conflict(_)) => Ok(register::ReplicatedKeyOutcome::Refused {
                reason: register::KeyRefusalReason::StoreConflict,
            }),
            Err(e) => Err(e),
        }
    }

    /// v13.4.2 (CIRISPersist#394) — the **self-signed → accord-scrubbed
    /// upgrade** primitive, dyn-dispatchable (like #375's
    /// [`apply_replicated_key_record`](Self::apply_replicated_key_record)).
    /// Unlike that method it has **no `owner_of` gate** — the accord scrub set
    /// IS the authority — so it is the correct primitive for the genesis
    /// canonical seed on a node that already holds its OWN self-signed row
    /// (`genesis::seed_canonical_servers`). Re-runs `check_canonical_role_admission`
    /// (the ≥2-distinct-anchor-scrub gate), so a `canonical` role is still only
    /// conferred on a valid 2-of-3. Requires the row to already EXIST (an absent
    /// row ⇒ `InvalidArgument` — use `put_public_key` to insert). The
    /// sqlite/postgres backends override this to delegate to their inherent
    /// method; the default here is for backends without the upgrade path.
    async fn adopt_scrub_upgrade(
        &self,
        _record: SignedKeyRecord,
    ) -> Result<register::AdoptScrubOutcome, Error> {
        Err(Error::InvalidArgument(
            "adopt_scrub_upgrade is not supported on this backend".to_owned(),
        ))
    }

    /// Fetch a single pubkey row by `key_id`. Returns `None` if absent.
    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<KeyRecord>, Error>;

    /// v19.1.0 (CIRISPersist#490) — the **authenticated re-anchor**: replace
    /// an ALREADY-ANCHORED key row with a re-blessed record carried by a
    /// quorum-verified [`genesis::GenesisBundle`]. The ONLY path that may
    /// replace an anchored canonical. Every impl MUST re-verify the bundle
    /// quorum INTERNALLY against this node's own roster + pinned keys
    /// (`genesis::verify_bundle_quorum`) before writing — authority is
    /// re-derived from own verified state, never accepted from the caller
    /// (the #377 lesson). Identity guard (pubkey-identical) + anti-rollback
    /// (`valid_from` strictly newer) are re-asserted at the write.
    async fn adopt_genesis_reanchor(
        &self,
        record: SignedKeyRecord,
        bundle: &genesis::GenesisBundle,
    ) -> Result<(), Error> {
        let _ = (record, bundle);
        Err(Error::Unsupported {
            method: "adopt_genesis_reanchor",
        })
    }

    /// Fetch all pubkey rows for a given identity. Used by the
    /// "all keys for primitive X" lookup the v0.2.x verify subsumption
    /// proxy will call.
    async fn lookup_keys_for_identity(&self, identity_ref: &str) -> Result<Vec<KeyRecord>, Error>;

    /// v2.6.0 (CIRISPersist#105) — enumerate `federation_keys` rows
    /// by `identity_type` (e.g. [`types::identity_type::ACCORD_HOLDER`],
    /// [`types::identity_type::STEWARD`]).
    ///
    /// Used by CIRISEdge for class-based directory queries:
    /// - `identity_type::ACCORD_HOLDER` → 2-of-3 constitutional
    ///   verification set (CIRISEdge#19).
    /// - `identity_type::STEWARD` → high-priority recipient class for
    ///   gossip topology (CIRISEdge#20).
    ///
    /// Rows are returned in stable lex order by `key_id` so callers
    /// can deterministically pick a subset (e.g. "first N by key_id"
    /// for rotation phasing). Empty `Vec` if no rows match.
    async fn list_keys_by_identity_type(
        &self,
        identity_type: &str,
    ) -> Result<Vec<KeyRecord>, Error>;

    /// v13.0.0 (CIRISPersist#365, CC 3.4.7.2 `consent-counter`) — assign
    /// or **overwrite** the Counter-RII [`consent_role`](types::consent_role)
    /// of `key_id`.
    ///
    /// This is the OQ-1 **non-recursive, overwrite-on-revoke** mutation
    /// on the V020 `federation_keys.consent_role` column (the
    /// CIRISAgent#760 §RC lock CC 3.4.7.2 ratifies): `Some(role)` sets
    /// one of the six ratified tokens ([`types::consent_role::RECOGNIZED`]
    /// — an unrecognized token is [`Error::InvalidArgument`] on EVERY
    /// backend, keeping PG's schema CHECK and CHECK-less SQLite
    /// symmetric); `None` revokes it back to the stored `'unregistered'`
    /// default. There is NO chain — a subsequent call simply overwrites
    /// the single flat column (chain history, if a deployment wants it,
    /// lives in a separate audit surface, never embedded in this field).
    /// `consent_role` is excluded from `persist_row_hash`, so the
    /// overwrite does not disturb the signed registration row (and
    /// `adopt_scrub_upgrade` never touches it). Returns
    /// [`Error::InvalidArgument`] if `key_id` has no `federation_keys`
    /// row.
    ///
    /// Persist's responsibility ends at STORE + EXPOSE + this overwrite.
    /// The OQ-2 (`peer` blanket suppression) and OQ-3
    /// (`authorized_review` strict post-window) *detection signals* are
    /// applied by the consumer (edge `ProbePatternObserver` / RATCHET)
    /// reading the role via [`consent::consent_role_of`] — persist houses
    /// no Counter-RII detector.
    async fn set_consent_role(&self, key_id: &str, consent_role: Option<&str>)
        -> Result<(), Error>;

    /// v13.1.0 (CIRISPersist#377) — record a canonical-role WITHDRAW/SUPERSEDE
    /// **tombstone** (V095 `canonical_role_withdrawal`). `key_id` is the
    /// withdrawn canonical node; `superseded_by` is the successor key_id for a
    /// supersede (the old→new link) or `None` for a plain withdraw;
    /// `authority_decision_digest` is the authorizing accord `AccordDecision`
    /// proposal digest (#302, the audit anchor). **Idempotent** — a re-record of
    /// the same withdrawal is a no-op (the tombstone is monotone; a conflicting
    /// re-record with a DIFFERENT `superseded_by` is a [`Error::Conflict`]).
    ///
    /// Recorded on the revocation-wins plane: because
    /// [`check_canonical_role_admission`](admission::check_canonical_role_admission)
    /// consults the tombstone, a re-add of the withdrawn canonical over
    /// anti-entropy ([`apply_replicated_key_record`](Self::apply_replicated_key_record))
    /// is Refused. Callers use the verify-before-mutation orchestration
    /// ([`admission::withdraw_canonical_role`] / [`admission::supersede_canonical`])
    /// which verifies the accord authority BEFORE this write. The default body
    /// errors (mock/test backends without the V095 table); the real
    /// sqlite/postgres/memory backends override it.
    async fn record_canonical_withdrawal(
        &self,
        key_id: &str,
        superseded_by: Option<&str>,
        authority_decision_digest: &str,
    ) -> Result<(), Error> {
        let _ = (key_id, superseded_by, authority_decision_digest);
        Err(Error::Backend(
            "record_canonical_withdrawal is not supported by this backend".to_owned(),
        ))
    }

    /// v13.1.0 (CIRISPersist#377) — consult the canonical-role withdrawal
    /// tombstone for `key_id` (V095). `Some(_)` iff the accord quorum withdrew
    /// (or superseded) it; `None` otherwise. This is the load-bearing gate
    /// consult: [`check_canonical_role_admission`](admission::check_canonical_role_admission)
    /// calls it so a withdrawn canonical cannot be re-conferred the role. The
    /// default returns `None` (backends without the V095 table — mock/test);
    /// the real sqlite/postgres/memory backends override it.
    async fn lookup_canonical_withdrawal(
        &self,
        key_id: &str,
    ) -> Result<Option<admission::CanonicalWithdrawal>, Error> {
        let _ = key_id;
        Ok(None)
    }

    /// v13.1.0 (CIRISPersist#377) — list all canonical-role withdrawal
    /// tombstones (V095), stable-sorted by `key_id`. Gives
    /// `list_canonical_servers` consumers a withdrawn-history view. The default
    /// returns empty; the real backends override it.
    async fn list_canonical_withdrawals(
        &self,
    ) -> Result<Vec<admission::CanonicalWithdrawal>, Error> {
        Ok(Vec::new())
    }

    /// v16.0.0 (CIRISPersist#424) — record a GENERIC accord-conferred-role
    /// withdrawal tombstone (V104 `federation_role_withdrawals`; the #377
    /// primitive generalized — `canonical` stays on its V095 table, every LATER
    /// role lands here, starting with
    /// [`roles::INFRA_ATTEST`](types::roles::INFRA_ATTEST)). Same semantics as
    /// [`Self::record_canonical_withdrawal`]: idempotent re-record; a
    /// conflicting `superseded_by` is [`Error::Conflict`]; callers verify the
    /// accord authority BEFORE this write
    /// ([`admission::withdraw_infra_attest_role`]). Default errors; the real
    /// backends override.
    async fn record_role_withdrawal(
        &self,
        role: &str,
        key_id: &str,
        superseded_by: Option<&str>,
        authority_decision_digest: &str,
    ) -> Result<(), Error> {
        let _ = (role, key_id, superseded_by, authority_decision_digest);
        Err(Error::Backend(
            "record_role_withdrawal is not supported by this backend".to_owned(),
        ))
    }

    /// v16.0.0 (CIRISPersist#424) — consult the generic role-withdrawal
    /// tombstone for `(role, key_id)` (V104). The load-bearing gate consult:
    /// [`check_infra_attest_role_admission`](admission::check_infra_attest_role_admission)
    /// calls it so a withdrawn `infra:attest` key cannot be re-conferred the
    /// role over anti-entropy. Default returns `None`; the real backends
    /// override.
    async fn lookup_role_withdrawal(
        &self,
        role: &str,
        key_id: &str,
    ) -> Result<Option<admission::RoleWithdrawal>, Error> {
        let _ = (role, key_id);
        Ok(None)
    }

    // ── Attestations ───────────────────────────────────────────────

    /// Insert a new attestation row.
    async fn put_attestation(&self, attestation: SignedAttestation) -> Result<(), Error>;

    /// v36.0.0 (CIRISPersist#624) — the **typed, pre-write replicated
    /// Attestation-plane apply**: the Key plane's #565 twin
    /// ([`Self::apply_replicated_key_record`]), for the plane that had none.
    ///
    /// Decides against the currently-stored row BEFORE any write
    /// ([`attestation_apply::plan_replicated_attestation_apply`], a pure
    /// function of `(existing, incoming)`), so the verdict does not depend on
    /// a storage constraint existing (#624 problem 3) and classifies
    /// identically on every backend (memory / sqlite / postgres run THIS
    /// default body — none overrides):
    ///
    /// - absent id ⇒ `put_attestation` (every admission gate intact) ⇒
    ///   [`Inserted`](attestation_apply::ReplicatedAttestationOutcome::Inserted) —
    ///   or, for a CEG §6.1 structural composer whose
    ///   `(references_attestation_id, type, attester)` triple the store
    ///   resolved as an idempotent-replay no-op,
    ///   [`Deduplicated`](attestation_apply::ReplicatedAttestationOutcome::Deduplicated)
    ///   (verified by re-reading the id: an outcome must not claim an insert
    ///   that never happened);
    /// - byte-identical re-offer (the baked-genesis case) ⇒
    ///   [`Unchanged`](attestation_apply::ReplicatedAttestationOutcome::Unchanged);
    /// - same id, same signed assertion, same producer, unsigned decoration
    ///   differs ⇒ `Refused { AlreadyPresentIdentical }`;
    /// - same id, anything else ⇒ `Refused { ConflictingAttestation }` —
    ///   first-seen wins, the CIRISEdge#459 convergence conflict, finally a
    ///   countable mesh fact;
    /// - a duplicate key the plan did not see (lost plan/act race) ⇒
    ///   `Refused { StoreConflict }` — fail-closed, safe to re-offer.
    ///
    /// A directory that CANNOT answer [`Self::get_attestation`]
    /// ([`Error::Unsupported`] — the #603 arm) falls back to plan-free apply:
    /// `put_attestation` + the duplicate-key mapping, exactly the plan-free
    /// default body of the Key twin. Any OTHER `get_attestation` failure
    /// propagates as `Err` — *could not ask* is never *absent* (#604).
    ///
    /// Refusals are outcomes, not errors, so an apply loop stays total over
    /// unsolicited rows. Admission-gate failures on a fresh insert keep their
    /// typed [`Error`]s (each already carries a stable `kind()` token — a
    /// second copy of that taxonomy here would be the two-lists-that-disagree
    /// class).
    async fn apply_replicated_attestation(
        &self,
        attestation: SignedAttestation,
    ) -> Result<attestation_apply::ReplicatedAttestationOutcome, Error> {
        use attestation_apply::{
            plan_replicated_attestation_apply, AttestationRefusalReason,
            ReplicatedAttestationOutcome as Outcome, ReplicatedAttestationPlan as Plan,
        };
        let incoming = &attestation.attestation;
        let attestation_id = incoming.attestation_id.clone();
        // The §6.1 silent-no-op door only exists for structural composers
        // that actually carry a references target — precompute the predicate
        // while `incoming` is still borrowed.
        let dedup_possible = precedence::is_structural_composer(&incoming.attestation_type)
            && precedence::references_attestation_id_from_envelope(&incoming.attestation_envelope)
                .is_some();
        let planned = match self.get_attestation(&attestation_id).await {
            Ok(existing) => Some(plan_replicated_attestation_apply(
                existing.as_ref(),
                incoming,
            )?),
            // The #603 arm: this directory cannot answer, so apply plan-free.
            Err(Error::Unsupported { .. }) => None,
            // Every other failure is *could not ask*, which is never *absent*.
            Err(e) => return Err(e),
        };
        match planned {
            Some(Plan::Unchanged) => return Ok(Outcome::Unchanged),
            Some(Plan::Refused { reason }) => return Ok(Outcome::Refused { reason }),
            Some(Plan::Insert) | None => {}
        }
        match self.put_attestation(attestation).await {
            Ok(()) => {
                // §6.1: a structural-composer replay is a silent `Ok` with NO
                // row written. Ask the store what it actually did, so
                // `Inserted` keeps meaning inserted. Skipped on the plan-free
                // fallback (this directory cannot be asked).
                if dedup_possible
                    && planned.is_some()
                    && self.get_attestation(&attestation_id).await?.is_none()
                {
                    return Ok(Outcome::Deduplicated);
                }
                Ok(Outcome::Inserted)
            }
            Err(e) if e.is_duplicate_key() => Ok(Outcome::Refused {
                reason: AttestationRefusalReason::StoreConflict,
            }),
            Err(e) => Err(e),
        }
    }

    /// v4.4.0 (CIRISPersist#171, CEG §10.1.3) — **upsert** a local-tier
    /// self-attestation (singleton current-state): replace any prior
    /// `local` row for `(attesting_key_id, dimension)`, then insert.
    /// Signature deferred (no hybrid sig; the row is `tier = local`,
    /// visible only to the producing occurrence). Runs the §4.1 local-tier
    /// gate (refuse `capacity:*` and subject-side revocations) plus the
    /// shared admission gates (trust / dimension / cohort_scope). Returns
    /// the new row's `attestation_id`.
    async fn attestation_upsert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, Error>;

    /// v4.4.0 (CIRISPersist#171) — **insert** (append) a local-tier
    /// attestation for a multi-valued / event dimension (memory, per-
    /// thought verdicts): a fresh row keyed by a server-assigned id, NOT
    /// collapsed by dimension. Same gates as
    /// [`attestation_upsert_local`](Self::attestation_upsert_local).
    /// Returns the new `attestation_id`.
    async fn attestation_insert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, Error>;

    /// v4.4.0 (CIRISPersist#171) — batched [`attestation_upsert_local`]
    /// for the boot-time `graph_nodes → attestations` backlog. Default
    /// loops; backends MAY override for single-transaction chunking.
    /// Returns the new ids in input order.
    async fn attestation_upsert_local_many(
        &self,
        inputs: Vec<crate::federation::types::LocalAttestationInput>,
    ) -> Result<Vec<String>, Error> {
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            ids.push(self.attestation_upsert_local(input).await?);
        }
        Ok(ids)
    }

    /// v4.4.0 (CIRISPersist#171) — batched [`attestation_insert_local`].
    /// Default loops; backends MAY override for chunked single-tx insert.
    async fn attestation_insert_local_many(
        &self,
        inputs: Vec<crate::federation::types::LocalAttestationInput>,
    ) -> Result<Vec<String>, Error> {
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            ids.push(self.attestation_insert_local(input).await?);
        }
        Ok(ids)
    }

    /// All attestations targeting `attested_key_id` (consumer asks
    /// "who vouches for K?"). Ordered by `asserted_at` DESC.
    async fn list_attestations_for(&self, attested_key_id: &str)
        -> Result<Vec<Attestation>, Error>;

    /// All attestations issued by `attesting_key_id` (consumer asks
    /// "which keys does K vouch for?"). Ordered by `asserted_at` DESC.
    async fn list_attestations_by(&self, attesting_key_id: &str)
        -> Result<Vec<Attestation>, Error>;

    /// v21.0.0 (CIRISPersist#502 E7) — the revocation-folded
    /// `consent_peer_set` projection (V109): `node_key_id`'s LIVE
    /// `consent:replication:v1` peers, sorted + deduped, with any
    /// `withdraws`/`recants`-revoked peer already excluded. Closes the
    /// hole where CIRISServer's `replication_peers_from_consent` read
    /// `list_attestations_by` + flat-mapped `subject_key_ids` without
    /// folding revocation — a revoked peer kept receiving replication.
    /// Maintained by [`consent_peer_set`](super::consent_peer_set) IN the
    /// same transaction as `put_attestation`'s insert. Default
    /// `Unsupported`; sqlite/postgres/memory override.
    async fn list_consent_peers(&self, node_key_id: &str) -> Result<Vec<String>, Error> {
        let _ = node_key_id;
        Err(Error::Unsupported {
            method: "list_consent_peers",
        })
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — `node_key_id`'s LIVE
    /// `consent:replication:v1` grants it authored about ITSELF
    /// (`attesting_key_id = node_key_id`): rows whose envelope dimension
    /// is [`consent_peer_set::DIMENSION`] AND that still have a
    /// `consent_peer_set` row sourced from them (`source_attestation_id
    /// = attestation_id`) — i.e. NOT folded by a subsequent
    /// `withdraws`/`recants`. The E7 revocation fold already ran at
    /// write time ([`consent_peer_set`]'s projection maintenance); this
    /// method never re-derives it, only reads the result. Feeds
    /// [`crate::Engine::promote_consented_backlog`]'s prefix union.
    /// Default `Unsupported`; sqlite/postgres/memory override.
    async fn list_live_consent_grants_by(
        &self,
        node_key_id: &str,
    ) -> Result<Vec<Attestation>, Error> {
        let _ = node_key_id;
        Err(Error::Unsupported {
            method: "list_live_consent_grants_by",
        })
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — a plain keyset cursor over
    /// `local`-tier attestations, ascending `attestation_id`:
    /// [`crate::Engine::promote_consented_backlog`]'s page source.
    /// `after_attestation_id = None` starts from the beginning;
    /// `Some(id)` resumes strictly after it (`attestation_id > after`,
    /// lexical string ordering — a stable resumption point, not a
    /// chronological one). Backends order + page: `ORDER BY
    /// attestation_id ASC LIMIT limit`. Default `Unsupported`;
    /// sqlite/postgres/memory override.
    async fn list_local_tier_attestations(
        &self,
        after_attestation_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Attestation>, Error> {
        let _ = (after_attestation_id, limit);
        Err(Error::Unsupported {
            method: "list_local_tier_attestations",
        })
    }

    /// v21.12.0 (CIRISPersist#530) — the REPAIR sweep's page source: a
    /// keyset cursor (identical shape to [`Self::list_local_tier_attestations`])
    /// over the **stranded** rows — `tier = 'federation'` yet
    /// `cohort_scope ∈ {self, family}` (the
    /// [`types::cohort_scope::suppresses_holds_bytes`] scopes that project
    /// `SelfOwn` and are structurally invisible to the offer filter).
    ///
    /// This is the second motion #530 identifies as missing.
    /// [`Self::list_local_tier_attestations`] pages `WHERE tier = 'local'`,
    /// so its self-limiting property (a promoted row leaves the `local`
    /// tier and is never revisited) — the very property that makes
    /// [`crate::Engine::promote_consented_backlog`] safe to call
    /// unconditionally — is *exactly* what makes it unable to repair a row
    /// that already reached `(federation, self)` (sealed-before-grant, or a
    /// pre-#519 tier-only promotion that flipped tier without carrying the
    /// placement). A stranded row is past the tier gate, covered by the
    /// grant, and still never offered; only a page source that selects on
    /// `tier = 'federation'` can see it.
    ///
    /// `after_attestation_id = None` starts from the beginning; `Some(id)`
    /// resumes strictly after it (`attestation_id > after`, lexical
    /// ordering). Backends order + page `ORDER BY attestation_id ASC LIMIT
    /// limit`. Default `Unsupported`; sqlite/postgres/memory override.
    async fn list_stranded_federation_attestations(
        &self,
        after_attestation_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Attestation>, Error> {
        let _ = (after_attestation_id, limit);
        Err(Error::Unsupported {
            method: "list_stranded_federation_attestations",
        })
    }

    /// v31.0.0 (CIRISPersist#650) — **the ONLY unfiltered attestation
    /// enumerator**: every row, every tier, every `cohort_scope`, keyset-paged
    /// `attestation_id > after ORDER BY attestation_id ASC LIMIT limit`.
    ///
    /// Every other list method on this trait is tier-partitioned
    /// (`list_attestations_for` / `_by` / `_since` / `list_attestation_log` all
    /// pin `tier = 'federation'`; [`Self::list_local_tier_attestations`] pins
    /// `'local'`), which is right for every CONSUMER read — a local-tier row
    /// must never reach the serve wire. The v31 migration is not a consumer
    /// read: it must FOLD, and a fold over a partition is a fold that can
    /// resurrect the half it could not see. That is why this exists, and why it
    /// is named for the one caller that may use it rather than being offered as
    /// a general `list_attestations`.
    ///
    /// The keyset shape is [`Self::list_local_tier_attestations`]'s verbatim —
    /// a stable resumption point rather than a chronological one, so a run
    /// interrupted mid-corpus resumes without skipping or repeating. Default
    /// `Unsupported`; sqlite/postgres/memory override.
    async fn list_attestations_for_migration(
        &self,
        after_attestation_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Attestation>, Error> {
        let _ = (after_attestation_id, limit);
        Err(Error::Unsupported {
            method: "list_attestations_for_migration",
        })
    }

    /// v31.0.0 (CIRISPersist#650) — **re-seal an EXISTING row in place**, under
    /// its existing `attestation_id`.
    ///
    /// `resealed` is the row **as it will be stored**: the same row, with the
    /// #598 signed instants and the #643 typed-column mirror stamped and the
    /// seal recomputed over exactly those bytes. Implementations:
    ///
    /// 1. load the stored row; `Ok(false)` if it is gone (a concurrent purge is
    ///    not an error);
    /// 2. **REFUSE any divergence in an IMMUTABLE field** —
    ///    `attesting_key_id`, `attested_key_id`, `attestation_type`,
    ///    `subject_key_ids`, `cohort_scope`, `weight`, `tier`. A "re-seal" that
    ///    could move a row between tiers or scopes would be a placement door
    ///    beside [`Self::promote_attestation`] and
    ///    [`Self::set_attestation_cohort_scope`], with none of their gates;
    /// 3. run [`admission::check_instant_binding`] and
    ///    [`admission::check_row_column_binding`] over `resealed`, so a caller
    ///    that hands over a still-legacy row is REFUSED rather than silently
    ///    writing one no peer will take (the CIRISPersist#649 rule);
    /// 4. write `attestation_envelope`, `original_content_hash`,
    ///    `scrub_signature_classical`, `scrub_signature_pqc`, `scrub_key_id`,
    ///    `scrub_timestamp`, `additional_scrubs`, `asserted_at`, `expires_at`
    ///    and the recomputed `persist_row_hash` in ONE statement.
    ///
    /// `asserted_at` / `expires_at` are mutable here precisely because #598
    /// binds them: a legacy row minted with nanosecond precision cannot satisfy
    /// the gate until the COLUMN is truncated to the substrate resolution
    /// alongside its signed twin, and doing one without the other is the
    /// divergence the gate exists to catch.
    ///
    /// **This is not a general re-sign door.** It exists for the migration and
    /// refuses everything else by refusing the legacy shape it is handed. Any
    /// other caller wanting to re-sign a row is changing its placement and
    /// belongs at one of the two doors that gate that. Default `Unsupported`;
    /// sqlite/postgres/memory override.
    ///
    /// [`admission::check_instant_binding`]: admission::check_instant_binding
    /// [`admission::check_row_column_binding`]: admission::check_row_column_binding
    async fn reseal_attestation_v31(&self, resealed: &Attestation) -> Result<bool, Error> {
        let _ = resealed;
        Err(Error::Unsupported {
            method: "reseal_attestation_v31",
        })
    }

    /// v31.0.0 (CIRISPersist#650) — **hard-delete ONE attestation row** by id.
    /// `Ok(true)` if a row was removed, `Ok(false)` if it was already gone (so
    /// a re-run of an interrupted migration is a no-op, not an error).
    ///
    /// The row's `attestation_subjects` projection goes with it (`ON DELETE
    /// CASCADE` on the SQL backends; explicitly on memory). The V111 signed
    /// wire index is NOT touched per row — the migration calls
    /// [`Self::rebuild_signed_wire_index`] once at the end, which is the
    /// sanctioned repair for exactly this and already exists on all three
    /// backends.
    ///
    /// # This deletes user data, so the door carries the invariant
    ///
    /// The disposition is decided by
    /// [`migration::classify`](migration::classify), which purges only on a
    /// proof — a live tombstone from the row's own attester — or on the
    /// operator's explicit recoverability licence. But *"the caller is careful"*
    /// is the shape CIRISPersist#652 was: a door whose safety lives entirely in
    /// its callers. So implementations re-ask the one question whose wrong
    /// answer is unrecoverable, via
    /// [`migration::check_purge_admission`](migration::check_purge_admission):
    /// **an exclusion-bearing row is refused here**, tombstones included,
    /// whatever the caller believes. Default `Unsupported`;
    /// sqlite/postgres/memory override.
    async fn purge_attestation_v31(&self, attestation_id: &str) -> Result<bool, Error> {
        let _ = attestation_id;
        Err(Error::Unsupported {
            method: "purge_attestation_v31",
        })
    }

    /// v31.1.0 (CIRISPersist#665) — **the re-bake's replacement half**: remove
    /// ONE baked genesis delegation row so
    /// [`seed_delegation_plane`](genesis::seed_delegation_plane) can install the
    /// current ceremony's version of it under the same id.
    ///
    /// # Why this is not [`purge_attestation_v31`]
    ///
    /// It cannot be. Two of the three genesis delegation rows are
    /// `delegates_to`, which
    /// [`migration::is_exclusion_bearing`](migration::is_exclusion_bearing)
    /// classifies `ExclusionClass::Delegation`, so
    /// [`migration::check_purge_admission`](migration::check_purge_admission)
    /// refuses them — correctly, and that gate must not be weakened: deleting a
    /// delegation edge on the general purge path is unrecoverable, which is the
    /// whole of CIRISPersist#650.
    ///
    /// # What authorizes it instead
    ///
    /// A far narrower rule, re-asked inside every implementation (AV-9,
    /// verify-before-mutation) via
    /// [`genesis::check_genesis_rebake_purge_admission`]:
    ///
    /// > `attestation_id` MUST be one of the ids the COMPILED-IN bundle carries.
    ///
    /// The door therefore cannot address any row that this binary is not
    /// holding a replacement for. Its worst-case misuse — deleting a genesis
    /// row and never re-inserting — leaves the delegation plane `Absent`, which
    /// BOOTS and which the next start re-seeds; it can never remove a
    /// conferral this node cannot re-create from its own artifact. That bounded
    /// blast radius is what makes bypassing the exclusion gate defensible here
    /// and nowhere else.
    ///
    /// The re-insert deliberately does NOT live in this door: the caller
    /// follows it with an ordinary [`put_attestation`](Self::put_attestation),
    /// so the replacement row pays the full admission stack — canonical-at-rest,
    /// the #660 reservation, `persist_row_hash`, the V106 subject projection —
    /// exactly as a first-boot install does. A second write path for genesis
    /// rows would be a second thing to keep in step with the first.
    ///
    /// # COMPARE-AND-DELETE, because the decision was made against an earlier read
    ///
    /// v31.1.0 (CIRISPersist#665 review) — `expected_persist_row_hash` is the
    /// `persist_row_hash` of the row the caller CLASSIFIED, and the delete only
    /// fires if the stored row still carries it. Deleting by id alone was a
    /// rolling-deployment hazard and the sharpest kind: the replacement decision
    /// is made from a `get_attestation` taken earlier, so when two engine
    /// versions initialize one postgres database — which is simply what a fleet
    /// upgrade looks like — a stale initializer could delete a NEWER ceremony
    /// row that landed in between and install its own older baked one. That is
    /// exactly the rollback
    /// [`candidate_is_strictly_newer`](genesis::candidate_is_strictly_newer)
    /// exists to refuse, performed by the one caller that had already decided it
    /// was allowed to write.
    ///
    /// The window is only dangerous on THIS door. The non-destructive paths
    /// close it for free: an `INSERT` that races a newer row fails on the
    /// primary key and is reported as
    /// [`Raced`](genesis::DelegationRowOutcome::Raced), so the newer row stands.
    /// Only the delete could destroy something, so only the delete needs the
    /// compare.
    ///
    /// **The failure direction is RECLASSIFY, NEVER REMOVE.** `Ok(false)` means
    /// the corpus moved under the caller's decision, and the honest response is
    /// to re-read and decide again rather than to force a write derived from a
    /// state that no longer exists.
    ///
    /// Returns whether a row was actually removed — `false` both when the id is
    /// absent and when it is present with a different `persist_row_hash`.
    /// Default `Unsupported`; sqlite/postgres/memory override.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if `attestation_id` is not a baked genesis
    /// delegation id; [`Error::Backend`] on a backend failure.
    async fn purge_genesis_delegation_row_v31(
        &self,
        attestation_id: &str,
        expected_persist_row_hash: &str,
        authority: &genesis::bundle::GenesisPurgeAuthority<'_>,
    ) -> Result<bool, Error> {
        let _ = (attestation_id, expected_persist_row_hash, authority);
        Err(Error::Unsupported {
            method: "purge_genesis_delegation_row_v31",
        })
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — stamp a NEW `cohort_scope` onto
    /// an EXISTING attestation row: the second placement door, driven by
    /// [`crate::Engine::repair_stranded_scope_backlog`] (CIRISPersist#530),
    /// which re-scopes an ALREADY-federation row to a covering grant's
    /// audience. `cohort_scope` MUST be one of the closed-set values
    /// ([`types::cohort_scope::is_valid`]) — implementations validate
    /// before writing and reject an out-of-set value with
    /// `InvalidArgument`. Also `InvalidArgument` if `attestation_id`
    /// does not exist. Default `Unsupported`; sqlite/postgres/memory
    /// override.
    ///
    /// # v31.0.0 (CIRISPersist#649) — a re-scope is a RE-SIGN
    ///
    /// This method's own doc used to end *"`cohort_scope` is a row attribute
    /// outside the signed envelope, so the scrub signature stays valid"*.
    /// CIRISPersist#643 made that sentence false: `cohort_scope` is one of the
    /// seven columns bound into `envelope.row`, and
    /// [`admission::check_row_column_binding`] refuses any row whose column
    /// diverges from that mirror. Rewriting the column in place therefore
    /// produced a row asserting its OLD scope — refused by every peer's
    /// `put_attestation`, and by this node's own.
    ///
    /// So the caller re-stamps the mirror
    /// ([`envelope::RowMirror::restamp_for_scope`]), re-signs the result, and
    /// hands both over as `reseal`; the envelope, its digest, its signature
    /// and the new placement land in ONE statement. Implementations re-run
    /// [`admission::check_row_column_binding`] over the row as it will be
    /// stored, so a caller that skips the re-stamp is REFUSED rather than
    /// silently minting an unreplicable row.
    async fn set_attestation_cohort_scope(
        &self,
        attestation_id: &str,
        cohort_scope: &str,
        reseal: &AttestationReseal,
    ) -> Result<(), Error> {
        let _ = (attestation_id, cohort_scope, reseal);
        Err(Error::Unsupported {
            method: "set_attestation_cohort_scope",
        })
    }

    /// v3.6.0 (CIRISPersist#134, CEG 0.3 §8.1.10 Policy J / §11.5.3)
    /// — return the chain of `content_rating:*` attestations rooted
    /// at a `trusted_publisher` identity_type that vouches for
    /// `content_sha256`. Returns an empty vector when the content is
    /// not trusted-publisher-blessed.
    ///
    /// Composition (default impl):
    ///
    ///   1. Enumerate all `trusted_publisher`-type keys via
    ///      [`Self::list_keys_by_identity_type`].
    ///   2. For each, list attestations issued by the key via
    ///      [`Self::list_attestations_by`].
    ///   3. Keep `scores` attestations whose envelope `dimension`
    ///      starts with `content_rating:` AND whose `evidence_refs`
    ///      array contains the hex `content_sha256`.
    ///
    /// CEG 0.3 §11.5.3: only `trusted_publisher`-type keys may emit
    /// publisher-curated content ratings (the
    /// [`super::admission::default_reserved_prefix_rules`]
    /// admission gate enforces this at write time). The returned set
    /// is the publisher's vouch chain — receiver-side Policy J
    /// composition consumes the chain alongside the age-assurance
    /// gate.
    ///
    /// # Default impl rationale
    ///
    /// Composes [`Self::list_keys_by_identity_type`] +
    /// [`Self::list_attestations_by`] (both already trait-required);
    /// no per-backend SQL needed. Memory / Postgres / SQLite backends
    /// inherit the same shape. Backends with a `content_rating:*`
    /// secondary index may override for O(log N) lookup instead of the
    /// default O(P · A) scan (P trusted_publishers, A attestations
    /// each).
    async fn lookup_trusted_publisher_chain(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<Attestation>, Error> {
        // Validate hex shape early — callers may pass arbitrary user input.
        if content_sha256.len() != 64 || !content_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(Vec::new());
        }
        let publishers = self
            .list_keys_by_identity_type(types::identity_type::TRUSTED_PUBLISHER)
            .await?;

        // v30.3.0 (CIRISPersist#611) — **`trusted_publisher` is a claim a key
        // makes about itself, so holding it is not enough to be in this chain.**
        //
        // `conferral_mode(TRUSTED_PUBLISHER)` is `DelegatedFromTrustRoot`, whose
        // contract is that the authority is "resolved at USE by
        // `capability_roots_to_trusted_root`". Nothing resolved it. This filter
        // is what makes the declaration true: a publisher is in the chain only
        // if a root THIS NODE trusts has conferred `infra:publish_rating` on it.
        //
        // Why the check lives here and not on the write door: CC 3.3.12 leaves
        // `content_rating:` open vocabulary, and #571 removed persist's
        // CEG-sourced write gate as stricter than the Constitution. CC puts the
        // discrimination on the read side — *"polarity carries certifier
        // confidence; not a slashing input"* — so an open write door and a
        // conferral-filtered read door is the shape CC describes.
        let node = self.node_key_id().ok_or(Error::NodeIdentityUnset {
            method: "lookup_trusted_publisher_chain",
            needed_for: "resolving each publisher's infra:publish_rating conferral against this node's own trust root",
        })?;

        let mut chain: Vec<Attestation> = Vec::new();
        for publisher in publishers {
            // Resolved per publisher, not cached: a conferral withdrawn between
            // two reads must stop vouching on the second one. The walk is the
            // same one the write doors use, so there is one predicate for
            // "conferred", not two that can drift.
            let conferred = trust_root::capability_roots_to_trusted_root(
                self,
                &node,
                &publisher.key_id,
                types::delegation_scope::INFRA_PUBLISH_RATING,
            )
            .await?;
            if conferred.is_none() {
                continue;
            }
            let attestations = self.list_attestations_by(&publisher.key_id).await?;
            for att in attestations {
                if att.attestation_type != types::attestation_type::SCORES {
                    continue;
                }
                // CEG 0.3 §5.6.8.3 reserved-prefix rule: content_rating:*
                // dimensions are emitter-restricted to trusted_publisher,
                // so a (publisher, content_rating:*) pair carries the
                // publisher's vouch by construction.
                let dimension_match = att
                    .attestation_envelope
                    .get("dimension")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.starts_with("content_rating:"));
                if !dimension_match {
                    continue;
                }
                let evidence_match = att
                    .attestation_envelope
                    .get("evidence_refs")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| arr.iter().any(|r| r.as_str() == Some(content_sha256)));
                if !evidence_match {
                    continue;
                }
                chain.push(att);
            }
        }
        Ok(chain)
    }

    /// v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10;
    /// CIRISRegistry#96) — the content-establishing `scores`
    /// attestations that bind `content_sha256`: federation-tier `scores`
    /// rows whose envelope `evidence_refs` array contains the hex
    /// `content_sha256`. These are the attestations whose producer signed
    /// the content's `subject_key_ids` INSIDE the attestation — the
    /// signed subject set behind the hash (NOT a later third party's
    /// self-declaration).
    ///
    /// Returns an empty vector when no establishing attestation is
    /// locally held (the fail-secure case: an undetermined `subject_of`
    /// means the subject-self admission clause FAILS — see
    /// [`super::admission::subject_of_content`]).
    ///
    /// # Why a separate method (not [`Self::lookup_trusted_publisher_chain`])
    ///
    /// `lookup_trusted_publisher_chain` is the publisher-vouch chain: it
    /// is scoped to `trusted_publisher`-type keys AND `content_rating:*`
    /// dimensions. Content PROVENANCE is broader — the establishing
    /// `scores` Contribution may be issued by any key on any dimension; it
    /// is identified solely by binding the hash in `evidence_refs`. So the
    /// subject resolution scans `evidence_refs` without the publisher /
    /// dimension restriction.
    ///
    /// # Default impl rationale
    ///
    /// No default — the trait has no "all attestations" enumerator, so
    /// each backend supplies the indexed / `json_extract` query directly.
    /// The hex shape is validated by the caller
    /// ([`super::admission::subject_of_content`]); backends MAY assume a
    /// well-formed lowercase hex-64 `content_sha256`.
    async fn attestations_binding_content(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<Attestation>, Error>;

    // ── Revocations ────────────────────────────────────────────────

    /// Insert a new revocation row. Append-only — revocations of an
    /// already-revoked key are accepted (the latest-effective-at one
    /// wins under most consumer policies).
    async fn put_revocation(&self, revocation: SignedRevocation) -> Result<(), Error>;

    /// All revocations targeting `revoked_key_id`. Ordered by
    /// `effective_at` DESC. Consumers walk this list and apply their
    /// policy ("is K revoked at time T?").
    async fn revocations_for(&self, revoked_key_id: &str) -> Result<Vec<Revocation>, Error>;

    // ── CEG 0.7 identity_occurrence + family (v3.12.0, #153) ───────

    /// v3.12.0 (CIRISPersist#153 Ask 1, CEG 0.7 §5.6.8.8) — admit an
    /// `identity_occurrence` binding (this `occurrence_key_id` IS
    /// also `identity_key_id`).
    ///
    /// Runs `check_device_class` admission before computing
    /// `persist_row_hash` and INSERTing. Idempotent on
    /// `(identity_key_id, occurrence_key_id)` PK collision with
    /// matching content; errors on collision with differing content.
    ///
    /// This cut admits the row on value-validation only. The full
    /// self-vouch / single-vouch admission per §5.6.8.8
    /// ("`attesting_key_id == identity_key_id` OR
    /// `attesting_key_id ∈ current occurrences of identity_key_id`")
    /// is the v3.13+ admission gate that needs the trust-graph walk.
    ///
    /// # The composite-projection class invariant (v17.0.1, CIRISPersist#446)
    ///
    /// **An embedded member of a signed composite that also has a dedicated
    /// consumer-read table MUST be materialized into that table at
    /// acceptance — as a LOCAL derived row inheriting the composite's
    /// authority and supersession clock — and de-materialized when the
    /// composite is revoked.** Otherwise the object is durably stored and
    /// verified yet invisible in the representation consumers actually query
    /// ("accepted but not projected" — the CIRISEdge#336 failure class).
    /// Instances on this struct: `encryption_pubkeys` → flattened occurrence
    /// columns ✓; `transport_binding` → projected into
    /// `transport_destinations` via
    /// [`types::OccurrenceTransportBinding::project_route`] on every accepted
    /// put (signed + trusted-local, all backends), retired on occurrence
    /// revocation ✓. Any future embedded member with a standalone table must
    /// follow the same shape.
    async fn put_identity_occurrence(
        &self,
        occurrence: SignedIdentityOccurrence,
    ) -> Result<(), Error>;

    /// v14.0.0 (CIRISPersist#418, issue ask 4) — write a **trusted-local**
    /// occurrence, bypassing the [`Self::put_identity_occurrence`] signature
    /// gate. For engine-internal writes on behalf of the local user
    /// (`Engine::self_at_login`, the HTTP self-bind) where the occurrence is
    /// **content-only** (a DEK-cascade KEX target with no reticulum transport)
    /// and locally produced — NOT peer-received, so not the content-MITM threat
    /// the gate closes. Grandfathered: the `attesting_key_id`/`signed_envelope`/
    /// `signature` columns are stored NULL. **Never reachable from the
    /// replication apply** (the bridge only calls the gated path), so a peer
    /// cannot forge a local write. Default impl errors; backends override.
    async fn put_identity_occurrence_local(
        &self,
        occurrence: types::IdentityOccurrence,
    ) -> Result<(), Error> {
        let _ = occurrence;
        Err(Error::Backend(
            "put_identity_occurrence_local not implemented for this backend".into(),
        ))
    }

    /// v3.12.0 — list every currently-stored occurrence of
    /// `identity_key_id`. The DEK-cascade fan-out path
    /// (#152 v3.13+): when a `cohort_scope: self` Contribution
    /// lands, substrate wraps the DEK to every row this returns.
    ///
    /// Filtering by `valid_until` is **caller-side** — the substrate
    /// returns every row, expired or not, and consumers walk the list
    /// applying their freshness policy. Same shape as
    /// `revocations_for`.
    async fn list_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<IdentityOccurrence>, Error>;

    /// v14.1.0 (CIRISPersist#418, completing the replication half) — list the
    /// stored occurrences of `identity_key_id` **with their original signature
    /// container** ([`SignedIdentityOccurrence`]), reconstructed byte-exact from
    /// the persisted `{attesting_key_id, signed_envelope, signature}` columns.
    ///
    /// This is the read counterpart to [`Self::put_identity_occurrence`]: the
    /// signature only ever existed on the put input, never on
    /// [`Self::list_identity_occurrences_for`]'s bare rows. A transport-layer
    /// replicator (CIRISEdge#305) that re-publishes an occurrence to a peer
    /// cannot re-sign it — it holds the transport signer, not the identity's
    /// federation key — so it MUST re-wrap the already-signed tuple verbatim.
    /// The receiver's [`Self::put_identity_occurrence`] gate then re-verifies
    /// over the same `signed_envelope`.
    ///
    /// Only rows that were **signed-put** are returned: trusted-local rows
    /// ([`Self::put_identity_occurrence_local`], signature columns NULL) are
    /// omitted — you can only signed-replicate what was signed-put. Default impl
    /// errors; backends override.
    async fn list_signed_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<SignedIdentityOccurrence>, Error> {
        let _ = identity_key_id;
        Err(Error::Backend(
            "list_signed_identity_occurrences_for not implemented for this backend".into(),
        ))
    }

    /// v3.12.0 — reverse lookup: which identity does this
    /// `occurrence_key_id` speak for? Returns `None` if the key is
    /// not bound as an occurrence.
    ///
    /// Use by consumers asking "is this signing key co-self with X?"
    /// — `lookup_identity_for_occurrence(K)?.identity_key_id == X`.
    /// Returns the full row so the caller can also see the
    /// `device_class` / `hardware_attestation` / freshness fields.
    async fn lookup_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<IdentityOccurrence>, Error>;

    /// v4.13.0 (CIRISPersist#192, CEG 0.18 §5.6.8.8 / §10.1.4) — resolve
    /// an occurrence's **current** content-encryption pubkeys (the
    /// `wrap_algorithm: v2` recipient inputs for the #152 DEK cascade).
    ///
    /// Returns the `encryption_pubkeys` of the occurrence bound to
    /// `occurrence_key_id` iff it exists, is within validity
    /// (`valid_until` unset or future), and registered the keys. `None` ⇒
    /// the recipient is **fail-secure excluded** from v2 grants — the
    /// cascade MUST NOT fall back to plaintext (§10.1.4). Revocation
    /// filtering is the enumeration's job
    /// ([`Self::list_identity_occurrences_active`]); this is the
    /// per-occurrence key lookup. Default impl over
    /// [`Self::lookup_identity_for_occurrence`]; backends need not
    /// override.
    async fn resolve_encryption_keys(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<EncryptionPubkeys>, Error> {
        let now = chrono::Utc::now();
        let Some(occ) = self
            .lookup_identity_for_occurrence(occurrence_key_id)
            .await?
        else {
            return Ok(None);
        };
        // Validity window (§10.1.4 fail-secure exclusion).
        if occ.valid_until.is_some_and(|vu| vu <= now) {
            return Ok(None);
        }
        // v14.0.0 (CIRISPersist#418) — REVOCATION-AWARE seal lookup. This is the
        // single per-occurrence lookup used for SEALING; without the revocation
        // filter it returns the KEX key of a REVOKED occurrence, and content
        // seals to a key the identity has repudiated (fail-open). An admitted
        // (signed) revocation whose `effective_at <= now` fail-closed excludes it.
        //
        // v16.0.0 (CIRISPersist#421) — RE-ESTABLISHMENT: a revocation is no
        // longer terminal-forever. The single fold comparator
        // ([`IdentityOccurrenceRevocation::revokes`]) kills occurrences
        // asserted AT OR BEFORE the revocation; a FRESH signed occurrence with
        // a strictly-newer `asserted_at` re-establishes sealability under the
        // same key_id (compromise → signed revoke → re-key → publish →
        // recovered), and a replayed OLD revocation is a no-op.
        let revoked = self
            .list_identity_occurrence_revocations_for(&occ.identity_key_id)
            .await?
            .into_iter()
            .any(|r| r.revokes(&occ, now));
        if revoked {
            return Ok(None);
        }
        Ok(occ.encryption_pubkeys)
    }

    /// v17.4.0 (FSD-005 Appendix C) — the durable `scores` LIST read: an
    /// ordered subject+dimension seek over the V106 `attestation_subjects`
    /// projection, JOINed to `federation_attestations`, honoring the full
    /// [`AttestationFilter`](crate::read::AttestationFilter) axis set
    /// (subject / dimension exact+prefix / tier / lifecycle / attester_filter
    /// / window / confidence) and the §4.3 caller-visibility gate resolved
    /// from `caller_occurrence_key_id` (empty ⇒ unauthenticated, broad tiers
    /// only). Cursor-paged `(asserted_at, attestation_id)` newest-first.
    ///
    /// Declared on `FederationDirectory` (not `ReadEngine`) so the composite
    /// substrate op can route it (the #329 capsule dispatches `dyn
    /// FederationDirectory`): the whole gate + seek runs inside persist's
    /// `.so`. Default = `Unsupported`; the sqlite/postgres/memory backends
    /// override.
    async fn list_scores(
        &self,
        caller_occurrence_key_id: &str,
        filter: crate::read::AttestationFilter,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::ScoresPage, Error> {
        let _ = (caller_occurrence_key_id, filter, cursor, limit);
        Err(Error::Unsupported {
            method: "list_scores",
        })
    }

    /// v17.4.0 (FSD-005 Appendix C) — the durable `scores` RESOLVE read: the
    /// composed verdict. Fetches the same candidate set as
    /// [`Self::list_scores`] (no pagination), runs the CEG §6.1 per-attester
    /// precedence latest-wins fold + the CC 4.4.2 polarity aggregation
    /// ([`super::scores::compose_verdict`]), and maps the result to a
    /// qualitative [`ConfidenceBand`](crate::read::ConfidenceBand). Scope-gated
    /// rows are excluded from BOTH the fold and the result (no verdict-
    /// differencing).
    ///
    /// Runs as a composite substrate op (the #329 pattern): the whole
    /// gate + fetch + fold executes inside persist's `.so`, so a cohabiting
    /// consumer can never run a STALE composer against newer data. Default =
    /// `Unsupported`; the backends override.
    async fn resolve_scores(
        &self,
        caller_occurrence_key_id: &str,
        filter: crate::read::AttestationFilter,
        policy: String,
        trace: bool,
    ) -> Result<crate::read::ComposedVerdict, Error> {
        let _ = (caller_occurrence_key_id, filter, policy, trace);
        Err(Error::Unsupported {
            method: "resolve_scores",
        })
    }

    /// v17.5.0 (CIRISPersist#455) — the **owner-scope attestation-LOG
    /// enumeration**: the replication/relay read beside the caller-gated
    /// consumer read. A caller-visibility-gated read can never serve a
    /// relay enumerating ITS OWN STORE to decide what to gossip (a Cohort
    /// hold-and-forward relay must see rows attested *between other
    /// parties*; wiring the sweep through [`Self::list_scores`] silently
    /// narrows — the CIRISEdge#336 failure shape). Three contract
    /// invariants, each load-bearing:
    ///
    /// 1. **No caller gate.** The caller is the substrate owner enumerating
    ///    its own store; gossip policy (what to actually advertise) lives at
    ///    the consumer tier (edge `projection_for`), never here.
    /// 2. **Lifecycle-blind.** Anti-entropy converges the append-only LOG,
    ///    not the live view — superseded/withdrawn/recanted rows are
    ///    returned (also skipping the correlated retraction subquery, the
    ///    most expensive predicate at sweep cardinalities).
    /// 3. **Byte-faithful.** Full rows with `persist_row_hash` intact, fit
    ///    for re-publish.
    ///
    /// The log is the **replicable set**: federation-tier rows only. Local
    /// (`tier='local'`) drafts are pre-promotion producer state, not part of
    /// the shared log by definition (AV-60: nothing crosses to federation
    /// visibility unsigned). `subject_key_id = None` walks the full log
    /// (anti-entropy); `Some` seeks one subject over V106. Ordered
    /// `(asserted_at DESC, attestation_id DESC)`, cursor-paged.
    ///
    /// Two entry points per replicated kind — the owner log walk (this) and
    /// the gated consumer view ([`Self::list_scores`]) — never one doing
    /// both jobs.
    async fn list_attestation_log(
        &self,
        subject_key_id: Option<&str>,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::ScoresPage, Error> {
        let _ = (subject_key_id, cursor, limit);
        Err(Error::Unsupported {
            method: "list_attestation_log",
        })
    }

    /// v17.8.0 (CIRISPersist#469) — the **seeder bridge**: record a peer
    /// learned from a self-consistent (but not directory-rooted) LAN announce
    /// as a **non-canonical, untrusted discovery bookmark**.
    ///
    /// This is deliberately **NOT an admission**. An advisory peer is unrooted
    /// by definition; `put_public_key`'s gate must keep rejecting it. Four
    /// invariants (the #469 contract):
    /// 1. **Non-canonical, untrusted** — rows live in the separate
    ///    `announced_peers` table and project server-side to
    ///    `canonical=false, trust="unknown"`.
    /// 2. **Never an authority** — enforced by construction: no admission /
    ///    quorum / rooting / `list_keys_by_identity_type` path reads this
    ///    table. A bookmark can never satisfy an accord seat, WA, or steward
    ///    count.
    /// 3. **Idempotent + liveness-refreshing** — repeated announces for the
    ///    same `key_id` + same pubkey refresh `last_seen_at` and bump
    ///    `announce_count`; they never duplicate. A repeat announce whose
    ///    **pubkey differs** is rejected `Error::Conflict` (fail-honest: the
    ///    caller verified announce self-consistency, so a changed pubkey for
    ///    one key_id is a genuine identity conflict, not a refresh).
    /// 4. **Promotable** — when the same `key_id` later roots for real
    ///    (admitted `put_public_key`), the real row wins:
    ///    [`Self::list_announced_peers`] anti-joins `federation_keys`, so the
    ///    bookmark is superseded on the read side with **no hook in the
    ///    admission gate**.
    ///
    /// `claimed_identity_type` is what the announce asserted — advisory
    /// display data only, never an authority input.
    async fn record_announced_peer(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        claimed_identity_type: Option<&str>,
        last_seen: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        let _ = (
            key_id,
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64,
            claimed_identity_type,
            last_seen,
        );
        Err(Error::Unsupported {
            method: "record_announced_peer",
        })
    }

    /// v17.8.0 (CIRISPersist#469) — list the live announced-peer bookmarks
    /// (see [`Self::record_announced_peer`]).
    ///
    /// **Anti-joins `federation_keys`**: a bookmark whose `key_id` has since
    /// been admitted for real is excluded — the rooted row supersedes it
    /// (invariant 4) — so the server's `collect_peers` union never shows the
    /// same peer twice at two trust levels. Ordered newest-`last_seen_at`
    /// first. This read is the server-side feed for
    /// `GET /v1/federation/peers`' `canonical=false / trust="unknown"`
    /// projection; it is NOT a key read — rows here carry no provenance and
    /// must never be fed into verification paths.
    async fn list_announced_peers(&self) -> Result<Vec<types::AnnouncedPeer>, Error> {
        Err(Error::Unsupported {
            method: "list_announced_peers",
        })
    }

    /// v3.12.0 (CIRISPersist#153 Ask 2, CEG 0.7 §5.6.8.9) — admit a
    /// `family` row.
    ///
    /// Runs `check_consensus_protocol_form` admission before computing
    /// `persist_row_hash` and INSERTing. Idempotent on `family_key_id`
    /// PK collision with matching content; errors on collision with
    /// differing content.
    ///
    /// This cut admits on value-validation (closed-set CHECK +
    /// consensus_protocol canonical-form). The full consensus-protocol
    /// enforcement (signature-counting per the protocol's rule,
    /// rejection of in-protocol amendment when entrenched, retroactive
    /// `key_grant` emission on member-add) is the v3.13+ admission
    /// gate.
    async fn put_family(&self, family: SignedFamily) -> Result<(), Error>;

    /// v21.0.0 (CIRISPersist#502 E4) — write a **trusted-local** `Family`,
    /// bypassing the [`Self::put_family`] authority-signature gate
    /// (`verify_family_admission`). For the genesis boot-seed
    /// (`crate::federation::genesis::seed_accord_family`) ONLY: the baked
    /// HUMANITY_ACCORD family is a *bake-what-exists* declaration over a
    /// compiled-in ceremony artifact — `family_key_id` is **keyless by
    /// design** (no private key for a "family" identity ever exists — see
    /// [`Self::put_family`]'s FK-only precedent and the constitutional-family
    /// invariant), so there is no key the boot process could sign with.
    /// **Never reachable from the replication apply / any wire surface** —
    /// mirrors [`Self::put_identity_occurrence_revocation_local`]'s
    /// trusted-local precedent. Default impl errors; backends override.
    async fn put_family_local(&self, family: Family) -> Result<(), Error> {
        let _ = family;
        Err(Error::Backend(
            "put_family_local not implemented for this backend".into(),
        ))
    }

    /// v6.2.0 (CIRISPersist#161 A4/A5, CEG §11.7.1) — admit one identity
    /// into an existing family roster, additively. This is the **roster-
    /// grow** primitive that makes family-member *addition* first-class
    /// and symmetric with the removal path
    /// ([`put_family_membership_revocation`](Self::put_family_membership_revocation)):
    /// addition mutates the roster in place, removal stays append-only
    /// revocation the `*_active` reads compose against.
    ///
    /// Idempotent on `member.key_id`: a member already on the roster is a
    /// no-op and returns `Ok(false)`; a genuine add returns `Ok(true)`.
    /// The family must exist ([`Error::InvalidArgument`] otherwise).
    /// Recomputes `persist_row_hash` over the grown roster.
    ///
    /// # v31.0.0 (CIRISPersist#654) — the addition carries an authority signature
    ///
    /// `spec` is the caller's hybrid signature over the **grown** record's
    /// [`Family::signing_envelope`](types::Family::signing_envelope), verified
    /// through the same [`verify_family_admission`] gate `put_family` and
    /// `supersede_family` run (see [`cohort::AdmitSpec`] and
    /// [`cohort::authorize_family_growth`]). Before this, roster growth was an
    /// UNAUTHENTICATED write door into `federation_families.members` — inside
    /// the signing preimage — that also left the row's stored
    /// `authority_key_id` / `scrub_signature_*` describing the roster that used
    /// to be there. Implementations MUST write the new signature columns in the
    /// SAME statement as `members` + `persist_row_hash` (#651's rule: the
    /// record and the signature that authorizes it travel together, because the
    /// way they go stale is by being able to move apart) and MUST re-index
    /// `signed_wire_index` afterwards (#547/#640).
    ///
    /// The idempotent no-op returns `Ok(false)` BEFORE the gate: no row is
    /// written, so there is nothing to authorize, and demanding a signature
    /// over a record that is not going to be stored would break the idempotency
    /// the membership-change drivers depend on.
    ///
    /// This is the forward-path half of a membership-change: the at-rest
    /// cascade re-key
    /// ([`rekey_family_member_add`](crate::federation::at_rest_cascade::orchestrate::rekey_family_member_add))
    /// grants an already-rostered member *past* family blobs; this call puts
    /// them on the roster so `resolve_recipients` includes them in *future*
    /// writes too. Since #654 the caller runs this FIRST and the re-key driver
    /// second — the driver holds no key material, so it can neither produce
    /// this signature nor relay one over a record it mints fields of.
    async fn add_family_member(
        &self,
        family_key_id: &str,
        member: types::FamilyMember,
        spec: &cohort::AdmitSpec,
    ) -> Result<bool, Error>;

    /// v3.12.0 — fetch a single family by `family_key_id`. Returns
    /// `None` if absent.
    async fn lookup_family(&self, family_key_id: &str) -> Result<Option<Family>, Error>;

    /// v3.12.0 — list every family that `member_identity_key_id`
    /// belongs to (the DEK-cascade fan-out path for
    /// `cohort_scope: family` content + the membership-change-
    /// ceremony propagation walker).
    ///
    /// Scans the `members` JSONB / TEXT field; postgres uses the
    /// V059 GIN index for O(log N), sqlite falls back to a full scan
    /// (acceptable for the family-count cardinality the substrate
    /// expects — a single identity in 10s of families, not 10s of
    /// thousands).
    async fn list_families_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Family>, Error>;

    /// v4.0 (CEG 0.8 §8.1.13.3) — admit a `community` row. Structural
    /// mirror of [`Self::put_family`].
    ///
    /// Runs `check_consensus_protocol_form` admission before computing
    /// `persist_row_hash` and INSERTing. Idempotent on
    /// `community_key_id` PK collision with matching content; errors on
    /// collision with differing content.
    ///
    /// Unlike `self` / `family`, community content is NOT structurally
    /// invisible ([`crate::federation::types::cohort_scope::suppresses_holds_bytes`]
    /// is false for `community`) — read paths federate community
    /// content normally.
    async fn put_community(&self, community: SignedCommunity) -> Result<(), Error>;

    /// v4.0 — fetch a single community by `community_key_id`. Returns
    /// `None` if absent. Structural mirror of [`Self::lookup_family`].
    async fn lookup_community(&self, community_key_id: &str) -> Result<Option<Community>, Error>;

    /// v4.0 — list every community that `member_identity_key_id`
    /// belongs to. Structural mirror of
    /// [`Self::list_families_for_member`]; the §4.3 community-scope
    /// predicate's fan-out path (`build_caller_admission` resolves
    /// `identity_key_id → community_key_ids` through this method).
    ///
    /// Scans the `members` JSONB / TEXT field; postgres uses the V060
    /// GIN index for O(log N), sqlite falls back to a full scan via
    /// `json_each`.
    async fn list_communities_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Community>, Error>;

    // ─── v4.8.0 (CIRISPersist#161, CEG §11.7.1) — Option-A forward-
    //     secrecy removal/revocation primitives. The `list_*_for` /
    //     `list_*_for_member` methods above are the **full-history**
    //     accessors (admit rows, no revocation filter). The
    //     `list_*_active` default methods below compose them with the
    //     revocation tables for the honest "currently-bound" view that
    //     `build_caller_admission` (Ask 6) and the deferred forward-
    //     secrecy key_grant gate (Ask 4) depend on.

    /// v4.8.0 — record an identity-occurrence revocation (an occurrence
    /// leaving a self-collective). Append-only; idempotent on the
    /// `(identity_key_id, occurrence_key_id)` PK. Computes
    /// `persist_row_hash` server-side. The V059 admission row is left
    /// intact — effective state is the composition (see
    /// [`Self::list_identity_occurrences_active`]).
    async fn put_identity_occurrence_revocation(
        &self,
        revocation: SignedIdentityOccurrenceRevocation,
    ) -> Result<(), Error>;

    /// v16.0.0 (CIRISPersist#421) — write a **trusted-local** occurrence
    /// revocation, bypassing the [`Self::put_identity_occurrence_revocation`]
    /// signature gate. For engine-internal writes on behalf of the local user
    /// where the revocation is locally produced — NOT peer-received, so not the
    /// permanent-DoS forgery the gate closes. Grandfathered: the signature
    /// columns are stored NULL, so the signed replication read omits these rows
    /// (you can only signed-replicate what was signed-put). **Never reachable
    /// from the replication apply.** Default impl errors; backends override.
    /// Mirrors [`Self::put_identity_occurrence_local`].
    async fn put_identity_occurrence_revocation_local(
        &self,
        revocation: types::IdentityOccurrenceRevocation,
    ) -> Result<(), Error> {
        let _ = revocation;
        Err(Error::Backend(
            "put_identity_occurrence_revocation_local not implemented for this backend".into(),
        ))
    }

    /// v16.0.0 (CIRISPersist#421) — list the stored occurrence revocations of
    /// `identity_key_id` **with their original signature container**,
    /// reconstructed byte-exact from the persisted `{attesting_key_id,
    /// signed_envelope, signature}` columns — the revocation twin of
    /// [`Self::list_signed_identity_occurrences_for`], so a transport
    /// replicator re-publishes a revocation it cannot re-sign. Signed-put rows
    /// only (trusted-local NULL-signature rows omitted). Default impl errors;
    /// backends override.
    async fn list_signed_identity_occurrence_revocations_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<SignedIdentityOccurrenceRevocation>, Error> {
        let _ = identity_key_id;
        Err(Error::Backend(
            "list_signed_identity_occurrence_revocations_for not implemented for this backend"
                .into(),
        ))
    }

    /// v4.8.0 — record a family-membership removal. Append-only;
    /// idempotent on the `(family_key_id, removed_identity_key_id)` PK.
    async fn put_family_membership_revocation(
        &self,
        revocation: SignedFamilyMembershipRevocation,
    ) -> Result<(), Error>;

    /// v4.8.0 — record a community-membership removal. Structural mirror
    /// of [`Self::put_family_membership_revocation`].
    async fn put_community_membership_revocation(
        &self,
        revocation: SignedCommunityMembershipRevocation,
    ) -> Result<(), Error>;

    /// v4.8.0 — all identity-occurrence revocations for `identity_key_id`
    /// (no `effective_at` filter — full history). Keyed by the table's
    /// leading PK column.
    async fn list_identity_occurrence_revocations_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<IdentityOccurrenceRevocation>, Error>;

    /// v4.8.0 — all family-membership revocations for `family_key_id`.
    async fn list_family_membership_revocations_for(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<FamilyMembershipRevocation>, Error>;

    /// v4.8.0 — all community-membership revocations for
    /// `community_key_id`.
    async fn list_community_membership_revocations_for(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<CommunityMembershipRevocation>, Error>;

    /// v4.10.0 (CIRISPersist#154, CEG 0.8 §0.8.1) — record a
    /// `location_proof`. Runs the §0.8 H3 canonicalization gate +
    /// §0.8.1 **rough-only** bound (`cell_resolution <= 7`) via
    /// [`location::validate_location_cell`](crate::federation::location::validate_location_cell)
    /// before computing `persist_row_hash` and inserting — an over-precise
    /// or malformed cell is **refused** (the substrate is the second line
    /// of defense after client UI gating). Append-only on the
    /// `(subject_key_id, asserted_at)` PK.
    async fn put_location_proof(&self, proof: SignedLocationProof) -> Result<(), Error>;

    /// v4.10.0 — every stored `location_proof` for `subject_key_id`
    /// (in-force and withdrawn — full history; callers filter on
    /// `withdrawn_at` / `valid_until` per their freshness policy, same
    /// shape as `list_identity_occurrences_for`).
    async fn list_location_proofs_for(
        &self,
        subject_key_id: &str,
    ) -> Result<Vec<LocationProof>, Error>;

    /// v4.11.0 (CIRISPersist#154 Ask 5, CEG 0.8 §0.8.2) — geographic
    /// communities whose constraint cell **contains** `cell_id` (the
    /// emergency-broadcast cascade read: "which geo-communities does this
    /// location fall within?"). Scans communities with
    /// `policy_blob.cohort_subkind == "geographic"` and returns those where
    /// [`location::h3_cell_contained`](crate::federation::location::h3_cell_contained)`(cell_id, constraint_cell)`.
    /// Non-geographic communities are never returned.
    async fn communities_containing(&self, cell_id: &str) -> Result<Vec<Community>, Error>;

    // ── CEG 1.0-RC2 §5.6.8.13 operational data (v5.1.0, #65) ───────

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13 / §10.1.6) — admit
    /// an `organization` envelope. Role-gated (`lww_skew_bounded`).
    ///
    /// Runs the four admission checks in order:
    /// 1. **Skew-bound** ([`operational::check_skew_bound`]) — reject
    ///    `asserted_at > now + §0.7 tolerance`.
    /// 2. **No payment-processor identifier**
    ///    ([`operational::reject_payment_processor_identifiers`]) over the
    ///    signed envelope.
    /// 3. **Authority** — the backend resolves the **current
    ///    `org_membership` set** for `organization.org_id` from storage,
    ///    then calls
    ///    [`ciris_verify_core::operational_admit::resolve_role_authority`]
    ///    with the caller-supplied `key_directory` + `root_stewards`,
    ///    requiring [`OrgRole::OrgAdmin`](ciris_verify_core::operational_admit::OrgRole::OrgAdmin).
    ///    **Fail-closed** — anything but a positive verdict is rejection.
    ///
    /// Append-only on `attestation_id`; idempotent re-submit of identical
    /// content is `Ok(())`. Current-state is resolved at read time by
    /// [`operational::resolve_lww`] (stable-id grouping on `org_id`).
    async fn put_organization(&self, signed: SignedOrganization) -> Result<(), Error>;

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13 / §10.1.6) — admit
    /// an `org_membership` envelope. Role-gated (`lww_skew_bounded`).
    ///
    /// Same four-check pipeline as [`Self::put_organization`]; the
    /// authority check requires the granter (the operation's
    /// `attesting_key_id`) hold a role permitting the grant — resolved by
    /// [`ciris_verify_core::operational_admit::resolve_role_authority`]
    /// against the current membership set for `org_membership.org_id`
    /// (requiring `OrgAdmin`), the caller-supplied `key_directory`, and
    /// `root_stewards`. Fail-closed.
    ///
    /// Current-state is resolved at read time by
    /// [`operational::resolve_lww`] (stable-id grouping on
    /// `(user_id, org_id)`).
    async fn put_org_membership(&self, signed: SignedOrgMembership) -> Result<(), Error>;

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13 / §10.1.6) — admit
    /// a `partner_record` envelope. M-of-N steward quorum
    /// (`monotonic_quorum`).
    ///
    /// Runs:
    /// 1. **Skew-bound** ([`operational::check_skew_bound`]).
    /// 2. **No payment-processor identifier** over the signed envelope.
    /// 3. **Set-semantics** — capability/restriction arrays sorted
    ///    ([`ciris_verify_core::operational_admit::check_set_semantics_sorted`]
    ///    over [`operational::PARTNER_RECORD_SET_FIELDS`]).
    /// 4. **Quorum** —
    ///    [`ciris_verify_core::operational_admit::verify_partner_record_quorum`]
    ///    over `JCS(signed_envelope)` against `steward_roster` at
    ///    `signed.threshold`. Fail-closed.
    /// 5. **Anti-rollback** — the `revision` MUST strictly exceed the
    ///    most-recent admitted `revision` for the same `license_id`
    ///    (queried from storage), else [`Error::PartnerRecordRollback`].
    ///    Enforced **at admission**, before the §10.1.6 merge.
    ///
    /// Current-state is resolved at read time by
    /// [`operational::resolve_monotonic_quorum`] (stable-id grouping on
    /// `license_id`).
    async fn put_partner_record(&self, signed: SignedPartnerRecord) -> Result<(), Error>;

    /// v5.1.0 (CIRISPersist#65) — all stored `organization` rows for
    /// `org_id` (in-force and withdrawn — full history). Callers resolve
    /// current state via [`operational::resolve_lww`].
    async fn list_organizations_for(&self, org_id: &str) -> Result<Vec<Organization>, Error>;

    /// v5.1.0 (CIRISPersist#65) — all stored `org_membership` rows for one
    /// `org_id` (every user; full history). This is the set the role-
    /// authority resolver groups by `(user_id, org_id)`.
    async fn list_org_memberships_for(&self, org_id: &str) -> Result<Vec<OrgMembership>, Error>;

    /// v5.1.0 (CIRISPersist#65) — all stored `partner_record` rows for
    /// `license_id` (full history). Callers resolve current state via
    /// [`operational::resolve_monotonic_quorum`].
    async fn list_partner_records_for(&self, license_id: &str)
        -> Result<Vec<PartnerRecord>, Error>;

    /// v5.1.0 (CIRISPersist#65, CIRISEdge#65 v2 bridge) — bulk-list
    /// `organization` rows since a cursor, for the anti-entropy carrier.
    ///
    /// v36.0.0 (CIRISPersist#668) — **BREAKING: resumes on THIS node's serve
    /// position, as a PAIR.** `since` is the `(admitted_at, attestation_id)`
    /// pair the last-returned row's
    /// [`ServedOrganization::resume_pair`](crate::federation::ServedOrganization::resume_pair)
    /// yields (`None` = from the start); the page is ordered by that pair and
    /// the filter is strictly greater than it, so a tie larger than one page
    /// resumes correctly instead of skipping its remainder, and a row
    /// replicated late is stamped ahead of every existing cursor instead of
    /// sorting under the producer's `asserted_at`, permanently behind it.
    /// Every remaining `list_*_since` cursor on this trait carries the same
    /// contract — learn this one, know them all.
    async fn list_organizations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedOrganization>, Error>;

    /// v5.1.0 (CIRISPersist#65, CIRISEdge#65 v2 bridge) — bulk-list
    /// `org_membership` rows since a cursor. Same ordering + pair-cursor
    /// contract as [`Self::list_organizations_since`] (#668).
    async fn list_org_memberships_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedOrgMembership>, Error>;

    /// v5.1.0 (CIRISPersist#65, CIRISEdge#65 v2 bridge) — bulk-list
    /// `partner_record` rows since a cursor. Same ordering + pair-cursor
    /// contract as [`Self::list_organizations_since`] (#668).
    async fn list_partner_records_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedPartnerRecord>, Error>;

    /// v5.2.0 (CIRISPersist#194, CIRISEdge#65 v2 bridge) — bulk-list the
    /// **full [`SignedPartnerRecord`] wrappers** (row + the M-of-N steward
    /// signature set + threshold) since a cursor, with the same ordering +
    /// cursor contract as [`Self::list_partner_records_since`]
    /// (`asserted_at ASC, attestation_id ASC`).
    ///
    /// Unlike [`Self::list_partner_records_since`] (which returns rows
    /// *without* signatures), this re-emits the wrapper the producer signed,
    /// so the Edge v2 Initiator can recompute a **byte-reproducible**
    /// `envelope_hash` from JCS bytes identical to the sender's — the
    /// property anti-entropy convergence depends on. Records admitted before
    /// v5.2.0 (admit-only era) carry an empty signature set + `threshold: 0`.
    /// Pair-cursor contract per [`Self::list_organizations_since`] (#668);
    /// `admitted_at` rides on [`ServedSignedPartnerRecord`], never inside
    /// the signed wrapper.
    async fn list_signed_partner_records_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedSignedPartnerRecord>, Error>;

    /// v21.0.0 (CIRISPersist#504 FLOOR, CIRISEdge advertise/serve bridge) —
    /// bulk-list the full [`SignedFamily`] wrappers (row + the V110 authority
    /// signature the CIRISPersist#502 E4 gate verified at admission) since a
    /// cursor. Pair-cursor contract per [`Self::list_organizations_since`]
    /// (#668): `since` is the `(admitted_at, family_key_id)` pair from
    /// [`ServedFamily::resume_pair`](crate::federation::ServedFamily::resume_pair).
    /// `limit` caps the page.
    ///
    /// **Signed rows only.** A `put_family_local` genesis-bake row is
    /// legitimately unsigned (`authority_key_id` NULL) and is never emitted
    /// here — serving it would hand the edge advertise/serve responder empty
    /// signature bytes, which fails hybrid-Strict verify downstream and
    /// reopens the exact keyless-declaration forgery class E4 closed.
    async fn list_signed_families_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedFamily>, Error>;

    /// v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full
    /// [`SignedCommunity`] wrappers since a cursor. Structural mirror of
    /// [`Self::list_signed_families_since`]: pair-cursor on
    /// `(admitted_at, community_key_id)` (#668), signed-rows-only contract
    /// identical.
    async fn list_signed_communities_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedCommunity>, Error>;

    /// v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full
    /// [`SignedLocationProof`] wrappers since a cursor. Structural mirror of
    /// [`Self::list_signed_families_since`]: pair-cursor (#668) whose resume
    /// id is the [`compound_resume_id`](crate::federation::types::compound_resume_id)
    /// of `(subject_key_id, persist_row_hash)` — the table PK is
    /// `(subject_key_id, asserted_at)`, one subject holds many proofs —
    /// signed-rows-only contract identical.
    async fn list_signed_location_proofs_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedLocationProof>, Error>;

    /// v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full
    /// [`SignedFamilyMembershipRevocation`] wrappers since a cursor.
    /// Structural mirror of [`Self::list_signed_families_since`]:
    /// pair-cursor (#668) whose resume id is the compound of
    /// `(family_key_id, removed_identity_key_id)`; signed-rows-only
    /// contract identical.
    async fn list_signed_family_membership_revocations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedFamilyMembershipRevocation>, Error>;

    /// v21.0.0 (CIRISPersist#504 FLOOR) — bulk-list the full
    /// [`SignedCommunityMembershipRevocation`] wrappers since a cursor.
    /// Structural mirror of [`Self::list_signed_families_since`]:
    /// pair-cursor (#668) whose resume id is the compound of
    /// `(community_key_id, removed_identity_key_id)`; signed-rows-only
    /// contract identical.
    async fn list_signed_community_membership_revocations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedCommunityMembershipRevocation>, Error>;

    // ─── v21.1.0 (CIRISPersist#507c) — bulk signed-since reads for the 5
    //     PRIMARY signed planes (edge advertise/serve bridge; extends the
    //     #504 pattern past the E4 keyless-declaration set). Signed-only
    //     per plane, but the concrete "signed" test differs by shape —
    //     these 5 planes carry their signature material three different
    //     ways: inline on the row (`Key`/`Attestation`, both share the
    //     `KeyRecord`-style scrub-signature fields), in a sibling nullable
    //     detached-signature container (`IdentityOccurrence`,
    //     `IdentityOccurrenceRevocation`, `TransportDestination`), or —
    //     for `federation_keys` specifically — always-required so no
    //     filter applies at all.

    /// v21.1.0 (CIRISPersist#507c) — bulk-list [`SignedKeyRecord`] wrappers
    /// (one per `federation_keys` row) since a cursor. `since` filters on
    /// `scrub_timestamp > since` (`None` = from the start — `scrub_timestamp`
    /// is the row's registration time, when its scrub-signature was issued);
    /// rows are ordered by `(scrub_timestamp ASC, key_id ASC)` so the cursor
    /// is a stable resumption point, mirroring
    /// [`Self::list_organizations_since`]. `limit` caps the page.
    ///
    /// **Every row qualifies.** Unlike the #504 keyless planes,
    /// `federation_keys.scrub_signature_classical` is `NOT NULL` — a key
    /// registration cannot be admitted unsigned, so there is no
    /// legitimately-unsigned shape to filter out here. [`KeyRecord`] already
    /// carries its own scrub-signature fields inline (it IS the signed
    /// wrapper for read purposes); [`SignedKeyRecord`] exists only so the
    /// write-input and bulk-read shapes match (`{ record: KeyRecord }`).
    /// v31.4.0 (CIRISPersist#682, #668) — **BREAKING: resumes on THIS node's
    /// admission position, as a PAIR.**
    ///
    /// `since` is `(admitted_at, key_id)` — the pair, not the instant alone.
    /// The page is ordered by that pair and the filter is strictly greater than
    /// it, so a tie larger than one page resumes correctly instead of skipping
    /// its remainder (#668).
    ///
    /// It keys on `admitted_at` (receiver-stamped, monotonic) rather than
    /// `scrub_timestamp` (the producer's clock). A record signed in January,
    /// replicated late and admitted in February, used to sort under January and
    /// was never served to a consumer past it — #655's defect on the identity
    /// plane, which every other plane's verification resolves against (#682).
    async fn list_signed_key_records_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedKeyRecord>, Error>;

    /// v21.1.0 (CIRISPersist#507c) — bulk-list the full
    /// [`SignedIdentityOccurrence`] wrappers (row + the detached
    /// `{attesting_key_id, signed_envelope, signature}` container V102
    /// added) since a cursor — the bulk-read mirror of
    /// [`Self::list_signed_identity_occurrences_for`] (which is per-subject).
    /// Pair-cursor contract per [`Self::list_organizations_since`] (#668);
    /// the resume id is the compound of
    /// `(identity_key_id, occurrence_key_id)`. `limit` caps the page.
    ///
    /// **Signed rows only**: a [`Self::put_identity_occurrence_local`]
    /// trusted-local row (NULL signature columns) is never emitted — same
    /// contract as the per-subject read.
    async fn list_signed_identity_occurrences_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedIdentityOccurrence>, Error>;

    /// v21.1.0 (CIRISPersist#507c) — bulk-list the full
    /// [`self_at_login::SignedTransportDestination`] wrappers since a
    /// cursor — the bulk-read mirror of
    /// [`Self::list_signed_transport_destinations_for`]. Pair-cursor
    /// contract per [`Self::list_organizations_since`] (#668); the resume id
    /// is the compound of `(occurrence_key_id, transport_kind)`. `limit`
    /// caps the page.
    ///
    /// **Signed rows only** (trusted-local NULL-signature rows omitted).
    /// RETIRED rows ARE included — tombstones must gossip, matching
    /// [`Self::list_signed_transport_destinations_for`] — and v36.0.0
    /// (#668) the retire doors MOVE the serve position, so a consumer whose
    /// cursor had already passed the row is served the tombstone rather than
    /// keeping the live route forever.
    async fn list_signed_transport_destinations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedTransportDestination>, Error>;

    /// v21.2.0 (CIRISPersist#507c) — bulk-list [`Attestation`] rows since a
    /// cursor, **federation tier only** (`WHERE tier = 'federation'`) — the
    /// E5 invariant: a `local`-tier row is producer-only-authority and must
    /// never reach the advertise/serve wire surface (see
    /// [`replication_policy::WireTier`]).
    ///
    /// The cursor was always half local on this plane —
    /// `COALESCE(promoted_at, asserted_at)`, because a consent-promoted row
    /// (#509) becomes federation-visible at `promoted_at`, possibly long
    /// after it was asserted. v36.0.0 (#668) completes it: the position is
    /// the V130 `admitted_at` serve position (stamped at admission,
    /// RE-stamped by the promote sweep and every other consumer-visible
    /// rewrite), and the resume is the `(admitted_at, attestation_id)` PAIR
    /// per [`Self::list_organizations_since`]. `limit` caps the page.
    ///
    /// The `Attestation` row carries its own hybrid scrub-signature fields
    /// inline (same shape as [`KeyRecord`]) — it IS the signed wrapper;
    /// [`ServedAttestation`] adds only this node's serve position beside it.
    async fn list_attestations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedAttestation>, Error>;

    /// v21.1.0 (CIRISPersist#507c) — bulk-list the full
    /// [`SignedIdentityOccurrenceRevocation`] wrappers since a cursor — the
    /// bulk-read mirror of
    /// [`Self::list_signed_identity_occurrence_revocations_for`].
    /// Pair-cursor contract per [`Self::list_organizations_since`] (#668);
    /// the resume id is the compound of
    /// `(identity_key_id, occurrence_key_id)`. `limit` caps the page.
    ///
    /// **Signed rows only** (trusted-local NULL-signature rows omitted),
    /// same contract as the per-subject read.
    async fn list_signed_identity_occurrence_revocations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedIdentityOccurrenceRevocation>, Error>;

    /// v31.1.0 (CIRISPersist#655) — bulk-list [`ServedRevocation`]s (one per
    /// `federation_revocations` row) since a cursor. v36.0.0 (#668) —
    /// `since` is the `(admitted_at, revocation_id)` PAIR from
    /// [`ServedRevocation::resume_pair`]; rows are ordered by that pair and
    /// filtered strictly greater than it. V123 gave this plane the right
    /// CLOCK; the pair gives it the right RESUME — half-fixed was worse than
    /// untouched, because a tie larger than one page silently dropped its
    /// remainder on the EXCLUSION plane. `limit` caps the page.
    ///
    /// # The cursor is THIS NODE's admission order, not the producer's clock
    ///
    /// It shipped keyed on `scrub_timestamp` and that was wrong, in the
    /// ordinary case rather than the adversarial one: a revocation signed in
    /// January and replicated late is admitted in February, and a consumer
    /// whose cursor has passed January asks for `> February` and never sees it.
    /// `check_revocation_scrub_skew` is a ceiling only, so an arbitrarily old
    /// signed instant is admissible, and `check_revocation_anti_rollback` is
    /// per-`revoked_key_id`, so it is silent about a first revocation for an
    /// unseen subject. The exclusion is stored and permanently invisible —
    /// #655's own defect, arriving through the cursor key.
    ///
    /// So the key is [`ServedRevocation::admitted_at`] (V123), which this node
    /// stamps on admission. Same correction, same reason, as
    /// [`Self::list_signed_accord_quorum_evidence_since`]'s `evidence_at`: the
    /// receiver re-derives rather than trusts, for time as well as authority.
    /// `scrub_timestamp` is unchanged and keeps every other job it had — it is
    /// envelope-bound (#659) and it is the anti-rollback latch; it is simply
    /// not this node's position in its own stream.
    ///
    /// # Why this plane needed only a cursor
    ///
    /// #655 found an exclusion plane that could be destroyed and never
    /// rebuilt — every other replicated plane had a `list_signed_*_since` and
    /// this one did not, so a DSAR erasure, an operator repair or a restored
    /// backup removed an exclusion permanently and silently.
    ///
    /// Unlike `federation_role_withdrawals` (whose remedy is the accord
    /// EVIDENCE plane — see
    /// [`accord_carriage`](crate::federation::accord_carriage)), a revocation
    /// row is **self-authenticating**: it carries `revocation_envelope` plus
    /// the hybrid `scrub_signature_classical` / `scrub_signature_pqc` /
    /// `scrub_key_id`, and the receive side already re-verifies that
    /// signature, the #659 subject binding and the #502 E1 authorship gate
    /// against its OWN registered directory inside
    /// [`Self::put_revocation`]. Serving the row therefore ships evidence, not
    /// a verdict; no re-derivation step is needed because the receiver was
    /// already re-deriving.
    ///
    /// **Every row qualifies.** `scrub_signature_classical` is `NOT NULL` —
    /// a revocation cannot be admitted unsigned — so, exactly as with
    /// [`Self::list_signed_key_records_since`], there is no legitimately-
    /// unsigned shape to filter out. [`Revocation`] carries its scrub-
    /// signature fields inline (it IS the signed wrapper for read purposes);
    /// [`SignedRevocation`] exists so the write-input and bulk-read shapes
    /// match.
    async fn list_signed_revocations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedRevocation>, Error>;

    /// v31.1.0 (CIRISPersist#662) — bulk-list the
    /// [`accord_carriage::AccordQuorumEvidence`] bundles (V091
    /// `accord_proposal` + its `accord_participation` set) since a cursor.
    /// v36.0.0 (#668) — `since` is the
    /// `(evidence_at, proposal.digest())` PAIR (`None` = from the start);
    /// bundles are ordered by `(evidence_at ASC, proposal_digest ASC)` and
    /// filtered strictly greater than the pair. `limit` caps the page
    /// (counted in PROPOSALS, not participations). **Resume from the last
    /// element's `(evidence_at, proposal.digest())`** — two proposals whose
    /// latest vote landed in one instant tie, and a resume on the instant
    /// alone dropped the tie's remainder at a page boundary.
    ///
    /// It is emphatically NOT the proposal's `created_at`: that value is not
    /// on the bundle at all, and cursoring on it would pin a bundle at the
    /// moment it had no votes, so a consumer reading pre-quorum would advance
    /// past it and never be offered the quorum-bearing version. `evidence_at`
    /// is `max(created_at, max(server_arrival_at))`, so a vote's arrival moves
    /// the bundle forward and it is re-offered exactly when it has something
    /// new to say.
    ///
    /// # This is the signed EVIDENCE plane, and it exists so a verdict plane
    /// does not have to
    ///
    /// `federation_role_withdrawals` (V104) has no signature columns at all,
    /// so a cursor on IT would hand a peer a derived verdict to trust — the
    /// forgeable-decision-bool shape CIRISPersist#377 closed. The signatures
    /// live here instead, on the participations, and a receiver admits a
    /// bundle only by **re-tallying** it against a roster resolved from its
    /// own directory
    /// ([`accord_carriage::admit_replicated_accord_evidence`]), then
    /// re-derives its own tombstones locally. See that module for the full
    /// ordering argument.
    ///
    /// Participations are sorted by `member_id` within each bundle so the
    /// serialization is deterministic across backends.
    async fn list_signed_accord_quorum_evidence_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<accord_carriage::AccordQuorumEvidence>, Error>;

    /// v31.1.0 (CIRISPersist#662) — the RECEIVE half of the evidence plane:
    /// admit a bundle by re-tallying it against this node's own accord roster,
    /// then re-derive this node's own withdrawal tombstones. Fail-closed with
    /// [`Error::AccordEvidenceUnverified`] — or, since v36.0.0
    /// (CIRISPersist#674), [`Error::AccordEvidenceCarrierMalformed`] when the
    /// bundle is refused pre-tally for what the CARRIER sent (more
    /// participations than the roster has seats / duplicate `member_id`s);
    /// idempotent on replay. See
    /// [`accord_carriage::admit_replicated_accord_evidence`], which is the
    /// shared body every backend delegates to.
    ///
    /// # Why this is on the trait and not only a free function
    ///
    /// The free function composes five directory calls
    /// (`issue_accord_nonce`, `put_accord_proposal`, `put_accord_participation`,
    /// `list_accord_participations`, plus the projection's reads), which is
    /// fine against a real backend and useless across the FFI directory
    /// capsule, where those primitives are `Unsupported`. A capsule-backed
    /// consumer could then SERVE evidence and never apply it — the plane
    /// admitted through one door and not another, which is the class
    /// CIRISPersist#652 was found by counting. As a trait method the capsule
    /// routes it as ONE op that runs the whole re-tally inside persist's own
    /// `.so`, which is also where it belongs: the re-derivation must not be
    /// something a consumer can reassemble differently.
    async fn apply_replicated_accord_evidence(
        &self,
        evidence: &accord_carriage::AccordQuorumEvidence,
    ) -> Result<accord_carriage::AccordEvidenceAdmission, Error>;

    // ─── v21.1.0 (CIRISPersist#507b) — the shared signed-wire content-hash
    //     index (V111 `signed_wire_index`). One shared table covers every
    //     kind edge serves: the 5 primary planes above, the 5 #504 E4
    //     keyless planes, the org/org_membership/partner_record trio, and —
    //     since v31.1.0 (CIRISPersist#655) — the key-level `Revocation`
    //     plane, which #507 had left out of scope. 14 of the 15
    //     `EnvelopeKind`s; `AccordQuorumEvidence` is the exception and stays
    //     out by construction (see [`super::wire_index`]). That module also
    //     holds the shared hash/record-key helpers backends call at each
    //     signed write chokepoint.

    /// v21.1.0 (CIRISPersist#507b) — **the content-hash point-read.** The
    /// content hash of a signed record is the lowercase-hex sha256 over the
    /// exact JSON bytes persist's read surface returns for that record
    /// (`sha256(serde_json::to_vec(record))` — the SAME value the
    /// `list_signed_*_since` / [`Self::list_attestations_since`] reads
    /// return). This is the lockstep fact CIRISEdge's fetch map depends on:
    /// edge keys its fetch map by `sha256(wire_bytes)` per `(kind, hash)`,
    /// which makes persist's hash equal edge's BY CONSTRUCTION (both hash
    /// the same bytes for the same record).
    ///
    /// `kind` is the [`replication_policy::EnvelopeKind::as_str`] token.
    /// Looks up `(kind, content_hash)` in the `signed_wire_index`, reloads
    /// the record by its stored `record_key`, re-serializes it, and
    /// DEFENSIVELY recomputes the hash before returning — a mismatch
    /// (index drift) logs a warning and returns `Ok(None)` rather than
    /// handing back bytes that don't actually hash to what was asked for
    /// (self-healing posture: the caller falls back to
    /// [`Self::rebuild_signed_wire_index`] or a bulk `_since` read).
    ///
    /// `Ok(None)` on unknown `(kind, content_hash)` or on a stale/mismatched
    /// index entry. Default impl errors; backends override.
    async fn lookup_signed_record_by_content_hash(
        &self,
        kind: &str,
        content_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        let _ = (kind, content_hash);
        Err(Error::Backend(
            "lookup_signed_record_by_content_hash not implemented for this backend".into(),
        ))
    }

    /// v21.1.0 (CIRISPersist#507b) — full rebuild of the `signed_wire_index`:
    /// scans every covered kind's current rows, recomputes each hash, and
    /// upserts `(kind, content_hash, record_key)`. Returns the count of rows
    /// indexed. This is the upgrade/backfill path — operators run it once
    /// post-upgrade (a fresh V111 table starts empty; every write from that
    /// point forward stays current via the per-put hook, but pre-existing
    /// rows need this to become point-readable), or CIRISEdge triggers it on
    /// adoption. Default impl errors; backends override.
    async fn rebuild_signed_wire_index(&self) -> Result<u64, Error> {
        Err(Error::Backend(
            "rebuild_signed_wire_index not implemented for this backend".into(),
        ))
    }

    /// v4.8.0 (#161 Ask 2) — occurrences of `identity_key_id` that are
    /// **currently active**: admitted AND with no revocation whose
    /// `effective_at <= now`. This is the honest view
    /// [`build_caller_admission`](crate::scope::build_caller_admission)
    /// resolves identity membership through; the deferred forward-
    /// secrecy DEK cascade (#161 Ask 4) will fan out over it.
    ///
    /// Default impl composes [`Self::list_identity_occurrences_for`]
    /// with [`Self::list_identity_occurrence_revocations_for`]; backends
    /// need not override.
    async fn list_identity_occurrences_active(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<IdentityOccurrence>, Error> {
        let revs = self
            .list_identity_occurrence_revocations_for(identity_key_id)
            .await?;
        let now = chrono::Utc::now();
        // v16.0.0 (#421): per-occurrence fold via THE comparator
        // ([`IdentityOccurrenceRevocation::revokes`]) — a re-established
        // occurrence (asserted after its revocation) is ACTIVE again; the old
        // key-id set was blind to `asserted_at` and stayed terminal.
        Ok(self
            .list_identity_occurrences_for(identity_key_id)
            .await?
            .into_iter()
            .filter(|o| !revs.iter().any(|r| r.revokes(o, now)))
            .collect())
    }

    /// v4.8.0 (#161 Ask 2) — families `member_identity_key_id` is
    /// **currently** an active member of: a member of the roster AND not
    /// removed by a revocation whose `effective_at <= now`. Default impl
    /// composes [`Self::list_families_for_member`] with a per-family
    /// [`Self::list_family_membership_revocations_for`] (family-count
    /// cardinality is small — tens, not thousands).
    async fn list_families_for_member_active(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Family>, Error> {
        let now = chrono::Utc::now();
        let families = self
            .list_families_for_member(member_identity_key_id)
            .await?;
        let mut active = Vec::with_capacity(families.len());
        for f in families {
            let revs = self
                .list_family_membership_revocations_for(&f.family_key_id)
                .await?;
            let removed = revs.iter().any(|r| {
                r.removed_identity_key_id == member_identity_key_id && r.effective_at <= now
            });
            if !removed {
                active.push(f);
            }
        }
        Ok(active)
    }

    /// v4.8.0 (#161 Ask 2) — communities `member_identity_key_id` is
    /// **currently** an active member of. Structural mirror of
    /// [`Self::list_families_for_member_active`].
    async fn list_communities_for_member_active(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<Community>, Error> {
        let now = chrono::Utc::now();
        let communities = self
            .list_communities_for_member(member_identity_key_id)
            .await?;
        let mut active = Vec::with_capacity(communities.len());
        for c in communities {
            let revs = self
                .list_community_membership_revocations_for(&c.community_key_id)
                .await?;
            let removed = revs.iter().any(|r| {
                r.removed_identity_key_id == member_identity_key_id && r.effective_at <= now
            });
            if !removed {
                active.push(c);
            }
        }
        Ok(active)
    }

    // ─── #249 Cut B — group-roster enumerators (members-of-a-group) ───
    //
    // The INVERSE of the `list_*_for_member_active` readers above (which
    // answer "which groups is this member in?"): these answer "who are the
    // currently-active members of THIS group?" — a group's roster MINUS its
    // effective membership revocations. Both share the
    // [`removed_key_ids_at`] fold so the revocation-subtraction logic is
    // never forked (the community-DEK cascade composes the same fold).

    /// #249 Cut B — the **active member roster** of `family_key_id`: the
    /// family's `members` MINUS every member removed by a revocation whose
    /// `effective_at <= now`. A future-dated revocation does NOT drop its
    /// subject (the member is active until its effective time arrives).
    ///
    /// Default impl composes [`Self::lookup_family`] with
    /// [`Self::list_family_membership_revocations_for`] through the shared
    /// [`removed_key_ids_at`] fold; backends need not override.
    /// [`Error::InvalidArgument`] if the family is unknown.
    async fn active_family_members(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<types::FamilyMember>, Error> {
        let family = self.lookup_family(family_key_id).await?.ok_or_else(|| {
            Error::InvalidArgument(format!(
                "active_family_members names unknown family_key_id {family_key_id:?}"
            ))
        })?;
        let revs = self
            .list_family_membership_revocations_for(family_key_id)
            .await?;
        let removed = removed_key_ids_at(
            revs.iter()
                .map(|r| (r.removed_identity_key_id.as_str(), r.effective_at)),
            chrono::Utc::now(),
        );
        Ok(family
            .members
            .into_iter()
            .filter(|m| !removed.contains(m.key_id.as_str()))
            .collect())
    }

    /// v38.2.0 (CIRISPersist#757 follow-on) — the family key_ids `identity`
    /// is an **ACTIVE** member of: raw roster containment minus effective
    /// revocations, projected to ids. See
    /// [`Self::active_community_key_ids_for`] for why raw containment is not
    /// an admission answer; this is the family mirror.
    async fn active_family_key_ids_for(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        for f in self
            .list_families_for_member(member_identity_key_id)
            .await?
        {
            let active = self.active_family_members(&f.family_key_id).await?;
            if active.iter().any(|m| m.key_id == member_identity_key_id) {
                out.push(f.family_key_id);
            }
        }
        Ok(out)
    }

    /// v38.2.0 (CIRISPersist#757 follow-on) — the community key_ids
    /// `identity` is an **ACTIVE** member of.
    ///
    /// # Why raw roster containment is not an admission answer
    ///
    /// The roster is append-only: membership removal is a
    /// [`CommunityMembershipRevocation`](types::CommunityMembershipRevocation)
    /// row, and effective membership is *admitted AND NOT revoked* — the
    /// fold [`Self::active_community_members`] spells once (#709; the same
    /// rule the community-DEK cascade's wrap fan-out resolves over, and the
    /// same rule the consumer's `require_member` applies on replicated
    /// state). `list_communities_for_member` answers raw containment, which
    /// counts a REVOKED member as a member.
    ///
    /// Through v38.0.0 that mismatch was vacuously unreachable at the write
    /// gate: `put_attestation` passed a hardcoded `None` target, so the
    /// family/community arms refused every placement before membership was
    /// ever consulted. v38.2.0 (#757) opened that door — and the raw fold
    /// would have let a revoked member keep WRITING into the community's
    /// plane, which is precisely the failure the removal primitive exists
    /// to prevent (forward secrecy: a removed member loses the room, not
    /// just future DEK epochs). Admission therefore filters through the
    /// active fold, spelled HERE once — a sixth hand-rolled
    /// membership-minus-revocations spelling is the #686 defect class.
    async fn active_community_key_ids_for(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        for c in self
            .list_communities_for_member(member_identity_key_id)
            .await?
        {
            let active = self.active_community_members(&c.community_key_id).await?;
            if active.iter().any(|m| m.key_id == member_identity_key_id) {
                out.push(c.community_key_id);
            }
        }
        Ok(out)
    }

    /// #249 Cut B — the **active member roster** of `community_key_id`.
    /// Structural mirror of [`Self::active_family_members`]; the forward
    /// fold the community-DEK cascade's wrap fan-out resolves over (same
    /// roster-minus-effective-revocations rule, via [`removed_key_ids_at`]).
    /// [`Error::InvalidArgument`] if the community is unknown.
    async fn active_community_members(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<types::CommunityMember>, Error> {
        let community = self
            .lookup_community(community_key_id)
            .await?
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "active_community_members names unknown community_key_id {community_key_id:?}"
                ))
            })?;
        let revs = self
            .list_community_membership_revocations_for(community_key_id)
            .await?;
        let removed = removed_key_ids_at(
            revs.iter()
                .map(|r| (r.removed_identity_key_id.as_str(), r.effective_at)),
            chrono::Utc::now(),
        );
        Ok(community
            .members
            .into_iter()
            .filter(|m| !removed.contains(m.key_id.as_str()))
            .collect())
    }

    /// #249 Cut B — incremental **community-roster grow**. The exact mirror
    /// of [`Self::add_family_member`]: admit one identity into an existing
    /// community roster additively (roster mutates in place; removal stays
    /// append-only revocation the `active_*` reads compose against).
    ///
    /// Idempotent on `member.key_id`: a member already on the roster is a
    /// no-op returning `Ok(false)`; a genuine add returns `Ok(true)`. The
    /// community must exist ([`Error::InvalidArgument`] otherwise).
    /// Recomputes `persist_row_hash` over the grown roster.
    ///
    /// v31.0.0 (CIRISPersist#654) — carries the same authority signature its
    /// family twin does, verified through [`verify_community_admission`]; see
    /// [`Self::add_family_member`] for why an addition needs one.
    async fn add_community_member(
        &self,
        community_key_id: &str,
        member: types::CommunityMember,
        spec: &cohort::AdmitSpec,
    ) -> Result<bool, Error>;

    // ── #249 Cut G1 ── the uniform rostered-group surface ──────────────
    //
    // CIRISServer #249 write+governance ask §1/§2/§6/§Q1-self. `self` /
    // `family` / `community` are the same machine (roster + append-only
    // revocations + the `roster − effective revocations` fold) at three
    // points on the visibility gradient; these methods are the single
    // `cohort`-parameterized surface over the three mirrored method sets,
    // so consumers write rostered-group ops ONCE. All are DEFAULT methods
    // composing the existing per-backend methods — backend parity (pg /
    // sqlite / memory) is inherited, no override needed. See
    // [`cohort`](crate::federation::cohort).

    /// #249 Cut G1 (§1) — the **active roster** of `group_key_id` in `cohort`,
    /// uniform across `self` / `family` / `community` (`roster − effective
    /// revocations`, `effective_at <= now`). Dispatches to
    /// [`Self::active_family_members`] / [`Self::active_community_members`] /
    /// [`Self::list_identity_occurrences_active`] and projects each to the
    /// uniform [`RosterMember`]. [`Error::InvalidArgument`] if a
    /// family/community `group_key_id` is unknown.
    async fn active_members(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<cohort::RosterMember>, Error> {
        Ok(match cohort {
            cohort::Cohort::Family => self
                .active_family_members(group_key_id)
                .await?
                .into_iter()
                .map(cohort::RosterMember::from)
                .collect(),
            // CC 4.4.3.2.8 / #308: `affiliations` shares the community roster.
            cohort::Cohort::Community | cohort::Cohort::Affiliations => self
                .active_community_members(group_key_id)
                .await?
                .into_iter()
                .map(cohort::RosterMember::from)
                .collect(),
            cohort::Cohort::SelfId => self
                .list_identity_occurrences_active(group_key_id)
                .await?
                .into_iter()
                .map(cohort::RosterMember::from)
                .collect(),
        })
    }

    /// **CIRISPersist#425 — the uniform signed read.** Fetch every replicated
    /// record of `kind` for `subject_key_id` as a byte-exact
    /// [`SignedReplicatedRecord`](namespace::SignedReplicatedRecord),
    /// generalizing #418's [`Self::list_signed_identity_occurrences_for`] so an
    /// edge replication engine sweeps a subject across ALL kinds through ONE
    /// call ([`ReplicatedKind::all`](namespace::ReplicatedKind::all)) instead of
    /// a bespoke `list_* + selector` per plane. A DEFAULT method composing the
    /// existing per-kind reads — backend parity (pg / sqlite / memory) inherited,
    /// no override. The occurrence, revocation and (since #443) transport arms
    /// use their SIGNED reads so the detached signature container survives; the
    /// embedded-signature kinds (key record, attestation) are byte-exact from
    /// their bare read. Each record
    /// is serialized to canonical JSON; the receiver's put gate re-canonicalizes
    /// via JCS, so the round-trip preserves verifiability.
    async fn list_signed_records(
        &self,
        kind: namespace::ReplicatedKind,
        subject_key_id: &str,
    ) -> Result<Vec<namespace::SignedReplicatedRecord>, Error> {
        use namespace::{ReplicatedKind as K, SignedReplicatedRecord as Rec};
        fn wrap<T: serde::Serialize>(kind: K, items: Vec<T>) -> Result<Vec<Rec>, Error> {
            items
                .into_iter()
                .map(|it| {
                    Ok(Rec {
                        kind,
                        canonical_json: serde_json::to_value(it).map_err(|e| {
                            Error::Backend(format!("serialize replicated record: {e}"))
                        })?,
                    })
                })
                .collect()
        }
        match kind {
            K::KeyRecord => wrap(
                kind,
                self.lookup_public_key(subject_key_id)
                    .await?
                    .into_iter()
                    .collect(),
            ),
            K::IdentityOccurrence => wrap(
                kind,
                self.list_signed_identity_occurrences_for(subject_key_id)
                    .await?,
            ),
            // v17.0.0 (#443): the route arm returns the SIGNED container
            // (byte-exact re-publish; signed-put rows only — a bare local
            // route is not replicable) INCLUDING retired tombstones, which
            // must gossip so the mesh converges on the retirement.
            K::TransportDestination => wrap(
                kind,
                self.list_signed_transport_destinations_for(subject_key_id)
                    .await?,
            ),
            K::Attestation => wrap(kind, self.list_attestations_for(subject_key_id).await?),
            // v16.0.0 (#421): the revocation arm returns the SIGNED container
            // (byte-exact re-publish; signed-put rows only) now that the
            // revocation plane carries the #418 signature discipline.
            K::IdentityOccurrenceRevocation => wrap(
                kind,
                self.list_signed_identity_occurrence_revocations_for(subject_key_id)
                    .await?,
            ),
        }
    }

    /// #249 Cut G1 (§2) — the active roster resolved to its **pinned hybrid
    /// public keys** ([`KeyRecord`]s), one call. The bridge from membership to
    /// threshold verification (the input to every quorum check): composes
    /// [`Self::active_members`] with [`Self::lookup_public_key`] per member.
    ///
    /// **Fail-secure:** an active roster member whose key is absent from
    /// `federation_keys` is a graph inconsistency that would silently undercount
    /// a quorum, so this returns [`Error::InvalidArgument`] rather than skip it.
    async fn active_member_keys(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<types::KeyRecord>, Error> {
        let members = self.active_members(cohort, group_key_id).await?;
        let mut out = Vec::with_capacity(members.len());
        for m in members {
            let rec = self.lookup_public_key(&m.key_id).await?.ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "active_member_keys: roster member {:?} of {} {:?} has no federation_keys \
                     row (broken roster — refusing to undercount a quorum)",
                    m.key_id,
                    cohort.as_str(),
                    group_key_id
                ))
            })?;
            out.push(rec);
        }
        Ok(out)
    }

    /// #249 Cut G1 (§1) — look up a group's identity uniformly. Dispatches to
    /// [`Self::lookup_family`] / [`Self::lookup_community`]; for `self` the
    /// identity_key IS the group, so it returns a metadata-free [`GroupRef`]
    /// when `group_key_id` is a known key ([`Self::lookup_public_key`] is
    /// `Some`). `Ok(None)` if the group/key is unknown.
    async fn lookup_group(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Option<cohort::GroupRef>, Error> {
        Ok(match cohort {
            cohort::Cohort::Family => self
                .lookup_family(group_key_id)
                .await?
                .map(cohort::GroupRef::from),
            // CC 4.4.3.2.8 / #308: `affiliations` resolves via the community row.
            cohort::Cohort::Community | cohort::Cohort::Affiliations => self
                .lookup_community(group_key_id)
                .await?
                .map(cohort::GroupRef::from),
            cohort::Cohort::SelfId => {
                self.lookup_public_key(group_key_id)
                    .await?
                    .map(|_| cohort::GroupRef {
                        cohort: cohort::Cohort::SelfId,
                        group_key_id: group_key_id.to_string(),
                        name: None,
                        consensus_protocol: None,
                        founded_at: None,
                    })
            }
        })
    }

    /// #249 Cut G1 (§1) — every group in `cohort` that `member_key_id` is
    /// **currently** a member of (the active reverse lookup). Dispatches to
    /// [`Self::list_families_for_member_active`] /
    /// [`Self::list_communities_for_member_active`]; for `self` it resolves the
    /// occurrence → its identity via [`Self::lookup_identity_for_occurrence`].
    async fn groups_of(
        &self,
        cohort: cohort::Cohort,
        member_key_id: &str,
    ) -> Result<Vec<cohort::GroupRef>, Error> {
        Ok(match cohort {
            cohort::Cohort::Family => self
                .list_families_for_member_active(member_key_id)
                .await?
                .into_iter()
                .map(cohort::GroupRef::from)
                .collect(),
            // CC 4.4.3.2.8 / #308: `affiliations` shares the community reverse lookup.
            cohort::Cohort::Community | cohort::Cohort::Affiliations => self
                .list_communities_for_member_active(member_key_id)
                .await?
                .into_iter()
                .map(cohort::GroupRef::from)
                .collect(),
            cohort::Cohort::SelfId => self
                .lookup_identity_for_occurrence(member_key_id)
                .await?
                .into_iter()
                .map(|o| cohort::GroupRef {
                    cohort: cohort::Cohort::SelfId,
                    group_key_id: o.identity_key_id,
                    name: None,
                    consensus_protocol: None,
                    founded_at: None,
                })
                .collect(),
        })
    }

    /// #249 Cut G1 (§1) — admit one [`RosterMember`] into a `family` /
    /// `community` roster uniformly (dispatches to [`Self::add_family_member`]
    /// / [`Self::add_community_member`]). Idempotent on `member.key_id`
    /// (`Ok(false)` = already present, `Ok(true)` = genuine add).
    ///
    /// The `self` cohort is **not** admissible here: an occurrence carries
    /// `device_class` / `hardware_attestation` / `encryption_pubkeys` that a
    /// [`RosterMember`] cannot, so `self` members are added via
    /// [`Self::put_identity_occurrence`]. Returns [`Error::InvalidArgument`]
    /// for `Cohort::SelfId`.
    ///
    /// v31.0.0 (CIRISPersist#654) — `spec` is the authority signature over the
    /// grown roster, the exact mirror of the [`cohort::RevokeSpec`]
    /// [`Self::revoke_member`] has taken since v21.0.0. Adding a seat and
    /// removing one are the same act in opposite directions; only one of them
    /// used to need proof.
    async fn add_member(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        member: cohort::RosterMember,
        spec: &cohort::AdmitSpec,
    ) -> Result<bool, Error> {
        let member_key_id = member.key_id.clone();
        let (added, change_kind) = match cohort {
            cohort::Cohort::Family => (
                self.add_family_member(
                    group_key_id,
                    types::FamilyMember {
                        key_id: member.key_id,
                        joined_at: member.joined_at,
                        role: member.role,
                    },
                    spec,
                )
                .await?,
                hard_case::kind::FAMILY_MEMBERSHIP_CHANGE,
            ),
            // CC 4.4.3.2.8 / #308: `affiliations` admits via the community roster.
            cohort::Cohort::Community | cohort::Cohort::Affiliations => (
                self.add_community_member(
                    group_key_id,
                    types::CommunityMember {
                        key_id: member.key_id,
                        joined_at: member.joined_at,
                        role: member.role,
                    },
                    spec,
                )
                .await?,
                hard_case::kind::COMMUNITY_MEMBERSHIP_CHANGE,
            ),
            cohort::Cohort::SelfId => {
                return Err(Error::InvalidArgument(
                    "add_member: the `self` cohort admits members via \
                     put_identity_occurrence (an occurrence carries device_class / \
                     hardware_attestation / encryption_pubkeys a RosterMember cannot)"
                        .to_string(),
                ))
            }
        };
        // #249 Cut G4 (§9) — notify on "joined" (only on a genuine add, not the
        // idempotent no-op) so consumers reconcile via `list_hard_case_events`.
        // change_kind=ADDED; idempotent on the event_id.
        if added {
            let now = chrono::Utc::now();
            self.record_hard_case(hard_case::HardCaseEvent {
                event_id: hard_case::membership_change_event_id(group_key_id, &member_key_id, now),
                kind: change_kind.to_string(),
                target_key_id: Some(group_key_id.to_string()),
                subject_key_id: Some(member_key_id.clone()),
                detail: serde_json::json!({
                    "change_kind": hard_case::change_kind::ADDED,
                    "subject_key_id": member_key_id,
                    "cohort_key_id": group_key_id,
                }),
                emitted_at: now,
            })
            .await?;
        }
        Ok(added)
    }

    /// #249 Cut G1 (§1) — remove one member from a `cohort` roster uniformly,
    /// via the append-only revocation table (the roster `members[]` is left
    /// intact; the `active_*` reads compose against the revocation). Builds the
    /// cohort's revocation row (`persist_row_hash` is backend-computed) and
    /// dispatches to the matching `put_*_revocation`. `effective_at` may be
    /// future-dated (the member stays active until it arrives).
    async fn revoke_member(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        removed_key_id: &str,
        spec: cohort::RevokeSpec,
    ) -> Result<(), Error> {
        let now = chrono::Utc::now();
        let cohort::RevokeSpec {
            effective_at,
            reason,
            witness_set,
            authority_key_id,
            scrub_signature_classical,
            scrub_signature_pqc,
        } = spec;
        // #249 Cut G4 (§9) — `kind` of the membership-change "removed" event to
        // emit after a family/community revocation (`self` uses the occurrence
        // path, which carries its own events). `None` ⇒ no membership event.
        let change_kind = match cohort {
            cohort::Cohort::Family => Some(hard_case::kind::FAMILY_MEMBERSHIP_CHANGE),
            // CC 4.4.3.2.8 / #308: `affiliations` shares the community event kind.
            cohort::Cohort::Community | cohort::Cohort::Affiliations => {
                Some(hard_case::kind::COMMUNITY_MEMBERSHIP_CHANGE)
            }
            cohort::Cohort::SelfId => None,
        };
        match cohort {
            cohort::Cohort::Family => {
                self.put_family_membership_revocation(types::SignedFamilyMembershipRevocation {
                    family_membership_revocation: types::FamilyMembershipRevocation {
                        family_key_id: group_key_id.to_string(),
                        removed_identity_key_id: removed_key_id.to_string(),
                        // v21.0.0 (#502 E4) — `removed_at` is `effective_at`, NOT
                        // a freshly-minted `now`: the caller signs the revocation
                        // BEFORE calling `revoke_member` (it has no way to
                        // predict a server-minted timestamp), so every field the
                        // gate verifies over must be caller-known in advance.
                        removed_at: effective_at,
                        effective_at,
                        reason,
                        witness_set,
                        persist_row_hash: String::new(),
                    },
                    // v21.0.0 (#502 E4) — the caller-supplied authority
                    // signature; `put_family_membership_revocation` hybrid-
                    // Strict-verifies it before any write.
                    authority_key_id,
                    scrub_signature_classical,
                    scrub_signature_pqc,
                })
                .await?;
            }
            // CC 4.4.3.2.8 / #308: `affiliations` removal rides the community
            // revocation table — which bumps the CommunityDek epoch at write
            // time (forward secrecy, CC 4.4.3.2.2), inherited for free.
            cohort::Cohort::Community | cohort::Cohort::Affiliations => {
                self.put_community_membership_revocation(
                    types::SignedCommunityMembershipRevocation {
                        community_membership_revocation: types::CommunityMembershipRevocation {
                            community_key_id: group_key_id.to_string(),
                            removed_identity_key_id: removed_key_id.to_string(),
                            // v21.0.0 (#502 E4) — see the family arm above:
                            // `removed_at` MUST be caller-predictable.
                            removed_at: effective_at,
                            effective_at,
                            reason,
                            witness_set,
                            persist_row_hash: String::new(),
                        },
                        // v21.0.0 (#502 E4) — see the family arm above.
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                    },
                )
                .await?;
            }
            cohort::Cohort::SelfId => {
                // v16.0.0 (#421): the rostered-group removal is an ENGINE-
                // INTERNAL op on behalf of the local user (never peer-received),
                // so it takes the trusted-local path — the gated
                // `put_identity_occurrence_revocation` is for the wire.
                self.put_identity_occurrence_revocation_local(
                    types::IdentityOccurrenceRevocation {
                        identity_key_id: group_key_id.to_string(),
                        occurrence_key_id: removed_key_id.to_string(),
                        revoked_at: now,
                        effective_at,
                        reason,
                        witness_set,
                        persist_row_hash: String::new(),
                    },
                )
                .await?;
            }
        }
        // #249 Cut G4 (§9) — notify on "left" so consumers reconcile via
        // `list_hard_case_events` instead of polling. Idempotent on the event_id
        // (keyed on effective_at). NOT a forward-secrecy re-key — for community
        // that is `at_rest_cascade::rekey_community_member_revoke` (epoch bump);
        // for self/family it is inherent (fresh-per-write DEK).
        if let Some(kind) = change_kind {
            self.record_hard_case(hard_case::membership_removed_event(
                kind,
                group_key_id,
                removed_key_id,
                effective_at,
            ))
            .await?;
        }
        Ok(())
    }

    /// #249 Cut G1 (§6) — atomically swap one member for another in a `family`
    /// / `community` roster: [`Self::revoke_member`] the outgoing key, then
    /// [`Self::add_member`] the incoming one. Returns the `add_member` result
    /// (`Ok(true)` = genuine add).
    ///
    /// **Consistency note:** this default composes two writes, so it is
    /// *eventually* consistent rather than single-transaction atomic — between
    /// the two calls a concurrent reader sees the outgoing member revoked but
    /// the incoming one not yet added (a transiently *smaller* roster, never a
    /// double-counted one; the `roster − revocations` fold can never report
    /// `out` as active). A backend-level single-transaction `swap` (one
    /// `persist_row_hash` recompute, no torn read) is a Cut G2 hardening.
    /// `self` is rejected ([`Error::InvalidArgument`]) — see [`Self::add_member`].
    ///
    /// v31.0.0 (CIRISPersist#654) — a swap is two authorized acts, so it needs
    /// TWO authorizations: `revoke_spec` for the removal (as before) and
    /// `admit_spec` for the addition. The addition's signature is over the
    /// roster as it will be AFTER the removal, because that is the state the
    /// add is applied to — the removal is append-only, so `members[]` still
    /// carries the outgoing key and the grown envelope contains both.
    async fn swap_member(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        out_key_id: &str,
        in_member: cohort::RosterMember,
        revoke_spec: cohort::RevokeSpec,
        admit_spec: &cohort::AdmitSpec,
    ) -> Result<bool, Error> {
        if cohort == cohort::Cohort::SelfId {
            return Err(Error::InvalidArgument(
                "swap_member: the `self` cohort manages occurrences via \
                 put_identity_occurrence / put_identity_occurrence_revocation"
                    .to_string(),
            ));
        }
        self.revoke_member(cohort, group_key_id, out_key_id, revoke_spec)
            .await?;
        self.add_member(cohort, group_key_id, in_member, admit_spec)
            .await
    }

    // ── #249 Cut G2 ── supersede + versioning (CIRISServer #249 §3/§8) ──
    //
    // THE write gap: `put_family` / `put_community` error on differing
    // content and `add`/`revoke` can't touch the `consensus_protocol`, so
    // there is no way to change an entrenched group's M/N threshold or
    // atomically re-baseline its roster — `expand 3→5` (which forces
    // `quorum:2/3 → quorum:3/5` under strict majority) is impossible.
    // `supersede` REPLACES the live row as a NEW version, snapshotting the
    // prior version into the append-only `federation_group_versions` history
    // (§8). `self` is not versioned (occurrences are managed individually).
    //
    // `supersede_group_row` + `list_group_versions` are the backend
    // primitives (the supersede is one transaction: snapshot prior → replace
    // live → bump version); the typed `supersede_family` / `supersede_community`
    // and the `group_history` / `group_at` reads are default methods.

    /// #249 Cut G2 — backend primitive: atomically supersede the live
    /// `family`/`community` row named by `new_snapshot`'s key with the new
    /// content, snapshotting the prior version into `federation_group_versions`
    /// and bumping `version`. `new_snapshot` is the full `Family`/`Community`
    /// JSON (the backend recomputes its `persist_row_hash`). `authorization`
    /// records the membership-change justification (the Cut G3 quorum envelope
    /// + cosignatures) on the superseded prior row, or `None`. Returns the new
    /// version. [`Error::InvalidArgument`] if the group does not exist or the
    /// cohort is `self`. Prefer the typed [`Self::supersede_family`] /
    /// [`Self::supersede_community`] wrappers.
    /// v31.0.0 (CIRISPersist#651) — `new_snapshot` is the **SIGNED WRAPPER**
    /// ([`types::SignedFamily`] / [`types::SignedCommunity`]), not the bare
    /// record. Implementations decode the wrapper and MUST write
    /// `authority_key_id` + `scrub_signature_{classical,pqc}` alongside the
    /// record columns they update — the signature covers `members`,
    /// `family_name`, `founded_at` and `consensus_protocol`, so a supersede
    /// that rewrites those and leaves the old signature in place stores a row
    /// that cannot verify against its own contents.
    async fn supersede_group_row(
        &self,
        cohort: cohort::Cohort,
        new_snapshot: serde_json::Value,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, Error>;

    /// #249 Cut G2 (§8) — the full version chain of a `family`/`community`:
    /// every superseded prior version (from `federation_group_versions`) plus
    /// the live current version, ascending by `version`. Empty for an unknown
    /// group; the live version always has `is_current = true` and
    /// `superseded_at = None`.
    async fn list_group_versions(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<cohort::GroupVersion>, Error>;

    /// #249 Cut G2 (§3) — supersede a family with new content (a re-baselined
    /// roster and/or a new `consensus_protocol`) as a new version. Validates
    /// the new `consensus_protocol` form, then composes
    /// [`Self::supersede_group_row`]. `authorization` is the membership-change
    /// justification recorded on the superseded prior version.
    async fn supersede_family(
        &self,
        new: types::SignedFamily,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, Error> {
        check_consensus_protocol_form(&new.family.consensus_protocol)?;
        // v31.0.0 (CIRISPersist#651) — THE AUTHORSHIP GATE. `put_family` has
        // run this since v21.0.0 (#502 E4); supersede ran NOTHING, so
        // `federation_families` had a SECOND write door that admitted a
        // re-baselined roster, a new `consensus_protocol` and a new
        // `family_name` on FK-existence alone. Superseding is not a lesser act
        // than creating — it is the act that REPLACES what creation
        // established — so it is gated identically, and before any write.
        crate::federation::verify_family_admission(self, &new).await?;
        // The snapshot is the SIGNED WRAPPER, not the bare record. Serializing
        // `.family` alone is what dropped the caller's freshly-minted
        // signature on the floor: `signing_envelope()` covers `members`,
        // `family_name`, `founded_at` and `consensus_protocol`, so a supersede
        // that carries the record without its signature leaves the stored
        // `authority_key_id` / `scrub_signature_*` describing a roster that is
        // no longer there. Same discipline as #649's `AttestationReseal`: the
        // record and the signature that authorizes it travel together, because
        // the way they go stale is by being able to move apart.
        let snapshot = serde_json::to_value(&new)
            .map_err(|e| Error::Backend(format!("supersede_family snapshot serialize: {e}")))?;
        self.supersede_group_row(cohort::Cohort::Family, snapshot, authorization)
            .await
    }

    /// #249 Cut G2 (§3) — supersede a community with new content as a new
    /// version. Mirror of [`Self::supersede_family`].
    async fn supersede_community(
        &self,
        new: types::SignedCommunity,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, Error> {
        check_consensus_protocol_form(&new.community.consensus_protocol)?;
        // v31.0.0 (CIRISPersist#651) — the authorship gate + the signed
        // wrapper as the snapshot. See [`Self::supersede_family`] for why both.
        crate::federation::verify_community_admission(self, &new).await?;
        let snapshot = serde_json::to_value(&new)
            .map_err(|e| Error::Backend(format!("supersede_community snapshot serialize: {e}")))?;
        self.supersede_group_row(cohort::Cohort::Community, snapshot, authorization)
            .await
    }

    /// CC 4.4.3.2.8 / #308 — supersede an `affiliations` group. Identical to
    /// [`Self::supersede_community`] (affiliations share the
    /// `federation_communities` storage + the `Community` row type) but records
    /// the version under the `affiliations` discriminator so the version chain
    /// stays separable per tier.
    async fn supersede_affiliations(
        &self,
        new: types::SignedCommunity,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, Error> {
        check_consensus_protocol_form(&new.community.consensus_protocol)?;
        // v31.0.0 (CIRISPersist#651) — gated and signature-carrying for the
        // same reason as its two siblings. #651 named the family and community
        // arms; this THIRD arm shares `SignedCommunity` and the
        // `federation_communities` storage with the community arm, so fixing
        // the two named doors and leaving this one open would have left the
        // identical hole reachable under a different discriminator — which is
        // exactly the by-name evadability #598 refused for the instant gate.
        crate::federation::verify_community_admission(self, &new).await?;
        let snapshot = serde_json::to_value(&new).map_err(|e| {
            Error::Backend(format!("supersede_affiliations snapshot serialize: {e}"))
        })?;
        self.supersede_group_row(cohort::Cohort::Affiliations, snapshot, authorization)
            .await
    }

    /// #249 Cut G2 (§8) — alias for [`Self::list_group_versions`]: the
    /// supersession audit trail (who superseded whom, when, authorized by
    /// which quorum).
    async fn group_history(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<cohort::GroupVersion>, Error> {
        self.list_group_versions(cohort, group_key_id).await
    }

    /// #249 Cut G2 (§8) — the `family`/`community` at a specific `version`
    /// (historical or current). Default filters [`Self::list_group_versions`];
    /// `Ok(None)` if that version does not exist.
    async fn group_at(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        version: u32,
    ) -> Result<Option<cohort::GroupVersion>, Error> {
        Ok(self
            .list_group_versions(cohort, group_key_id)
            .await?
            .into_iter()
            .find(|v| v.version == version))
    }

    // ── #249 Cut G3 ── quorum-authorized membership gate (§4/§5) ──
    //
    // The deferred v3.13+ admission gate, landable on verify v6.8.0's
    // threshold primitives. A membership change to a `quorum:M/N` group MUST
    // carry ≥M valid hybrid member cosignatures over the canonical change
    // payload — enforced HERE in the substrate, so one-seat-per-human +
    // M-of-N-to-change become invariants of the graph, not properties any one
    // server upholds. The PRIOR roster authorizes the change (the current
    // holders decide who joins/leaves; an incoming key never authorizes its
    // own admission). Default methods composing the trait + verify
    // primitives, so backend parity is inherited.

    /// #249 Cut G3 (§4/§5), robust on Cut G3.5 — verify a membership change is
    /// authorized by the group's **current** strict-majority quorum, composing
    /// CIRISVerify v6.9.0's general
    /// [`verify_membership_change`](ciris_verify_core::accord_genesis::verify_membership_change)
    /// (CIRISVerify#104). `change_envelope` is the canonical membership-change
    /// payload (build it with [`Self::build_membership_change_envelope`]); the
    /// **prior** roster cosigned its JCS bytes.
    ///
    /// Inherits verify's full fail-closed gate — strictly stronger than the
    /// v9.7.0 count-only check:
    /// - well-formed + **distinct** member `key_id`s;
    /// - **strict-majority** `quorum:M/N` (`2M>N`) over the new roster;
    /// - **one-seat key-distinctness** — the new roster resolves to **distinct
    ///   pubkeys** in the directory (no human seated under two `key_id`s);
    /// - **entrenchment preserved** — `family_key_id` unchanged, an entrenched
    ///   group cannot be de-entrenched;
    /// - **anti-replay** — `supersedes.prior_member_key_ids` MUST equal the
    ///   actual prior roster (no presenting the change against a different
    ///   prior state);
    /// - the **prior** roster's strict-majority quorum validly signed the new
    ///   envelope (role-agnostic, hybrid; classical-only does not count —
    ///   CC 5.3.2.4.3.1).
    ///
    /// The `directory` handed to verify is the authoritative `federation_keys`
    /// pin set for the prior roster ∪ the new roster (resolved via
    /// [`Self::lookup_public_key`]); authorization is exactly as strong as it.
    /// [`Error::InvalidArgument`] (wrapping the verify-side `AccordGenesisError`)
    /// on any failed check; the `self` cohort has no quorum.
    async fn verify_membership_quorum(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        change_envelope: &serde_json::Value,
        signatures: &[ciris_verify_core::threshold::ThresholdSignature],
    ) -> Result<(), Error> {
        use ciris_verify_core::threshold::ThresholdMember;
        let prior_envelope = self.group_prior_envelope(cohort, group_key_id).await?;
        // Directory = prior active roster ∪ the new envelope's members,
        // resolved to their REGISTERED pinned hybrid pubkeys. verify resolves
        // the NEW roster against this for the one-seat (distinct-pubkey) check
        // and the PRIOR roster for the quorum count, so it must cover both.
        let mut key_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for m in self.active_members(cohort, group_key_id).await? {
            key_ids.insert(m.key_id);
        }
        if let Some(arr) = change_envelope.get("members").and_then(|v| v.as_array()) {
            for m in arr {
                if let Some(k) = m.get("key_id").and_then(|v| v.as_str()) {
                    key_ids.insert(k.to_string());
                }
            }
        }
        let mut directory: Vec<ThresholdMember> = Vec::with_capacity(key_ids.len());
        for k in key_ids {
            if let Some(rec) = self.lookup_public_key(&k).await? {
                directory.push(ThresholdMember {
                    member_id: rec.key_id,
                    ed25519_public_key_base64: rec.pubkey_ed25519_base64,
                    mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
                    role: None,
                });
            }
        }
        ciris_verify_core::accord_genesis::verify_membership_change(
            &prior_envelope,
            change_envelope,
            signatures,
            &directory,
        )
        .map_err(|e| {
            Error::InvalidArgument(format!(
                "verify_membership_quorum: membership change not authorized: {e}"
            ))
        })
    }

    /// #249 Cut G3.5 — the family-shaped **prior envelope** of the live
    /// `family`/`community`: the input both
    /// [`Self::build_membership_change_envelope`] and
    /// [`Self::verify_membership_quorum`] derive from, so build-time and
    /// verify-time agree byte-for-byte (the anti-replay `supersedes` binding
    /// depends on it). verify's general helper reads `family_key_id` /
    /// `family_name` / `members[].key_id` / `consensus_protocol` /
    /// `consensus_protocol_entrenched` generically; a community maps its
    /// `community_*` fields onto those keys (`entrenched=false`). `self` has no
    /// quorum → [`Error::InvalidArgument`].
    async fn group_prior_envelope(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
    ) -> Result<serde_json::Value, Error> {
        fn members_json(members: Vec<(String, Option<String>)>) -> serde_json::Value {
            serde_json::Value::Array(
                members
                    .into_iter()
                    .map(|(key_id, role)| {
                        serde_json::json!({
                            "key_id": key_id,
                            "role": role.unwrap_or_else(|| "member".into()),
                        })
                    })
                    .collect(),
            )
        }
        match cohort {
            cohort::Cohort::Family => {
                let f = self.lookup_family(group_key_id).await?.ok_or_else(|| {
                    Error::InvalidArgument(format!("unknown family group {group_key_id:?}"))
                })?;
                Ok(serde_json::json!({
                    "family_key_id": f.family_key_id,
                    "family_name": f.family_name,
                    "members": members_json(
                        f.members.into_iter().map(|m| (m.key_id, m.role)).collect()
                    ),
                    "consensus_protocol": f.consensus_protocol,
                    "consensus_protocol_entrenched": f.consensus_protocol_entrenched,
                }))
            }
            // CC 4.4.3.2.8 / #308: `affiliations` derives its prior envelope
            // from the shared community row.
            cohort::Cohort::Community | cohort::Cohort::Affiliations => {
                let c = self.lookup_community(group_key_id).await?.ok_or_else(|| {
                    Error::InvalidArgument(format!("unknown community group {group_key_id:?}"))
                })?;
                Ok(serde_json::json!({
                    "family_key_id": c.community_key_id,
                    "family_name": c.community_name,
                    "members": members_json(
                        c.members.into_iter().map(|m| (m.key_id, m.role)).collect()
                    ),
                    "consensus_protocol": c.consensus_protocol,
                    "consensus_protocol_entrenched": false,
                }))
            }
            cohort::Cohort::SelfId => Err(Error::InvalidArgument(
                "the `self` cohort has no quorum / membership-change envelope".to_string(),
            )),
        }
    }

    /// #249 Cut G3.5 (§5) — build the canonical membership-change payload for a
    /// roster change on `group_key_id`, via CIRISVerify v6.9.0's
    /// [`build_membership_change`](ciris_verify_core::accord_genesis::build_membership_change).
    /// The prior roster cosigns this envelope's JCS bytes; submit it + the
    /// cosignatures to [`Self::supersede_family_with_quorum`] /
    /// [`Self::supersede_community_with_quorum`]. Defined once in verify so the
    /// payload is portable + re-verifiable across the federation. Role is
    /// `Founder` for a `family` (entrenched M-of-N), `Member` for a `community`
    /// (role is cosmetic — the general gate counts role-agnostically).
    async fn build_membership_change_envelope(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        new_member_key_ids: &[String],
        entrenched: bool,
        consensus_protocol: Option<&str>,
    ) -> Result<serde_json::Value, Error> {
        use ciris_verify_core::threshold::Role;
        let prior_envelope = self.group_prior_envelope(cohort, group_key_id).await?;
        let role = match cohort {
            cohort::Cohort::Family => Role::Founder,
            _ => Role::Member,
        };
        Ok(ciris_verify_core::accord_genesis::build_membership_change(
            &prior_envelope,
            new_member_key_ids,
            role,
            entrenched,
            consensus_protocol,
        ))
    }

    /// #249 Cut G3 (§3/§4/§5) — quorum-gated family supersede: verify the
    /// current roster's strict-majority quorum cosigned `change_envelope` via
    /// [`Self::verify_membership_quorum`], THEN [`Self::supersede_family`],
    /// recording `{change_envelope, quorum_signatures}` as the superseded
    /// version's authorization (the §8 audit trail). The quorum is checked
    /// against the PRIOR group — the current holders authorize the change.
    async fn supersede_family_with_quorum(
        &self,
        new: types::SignedFamily,
        change_envelope: serde_json::Value,
        signatures: Vec<ciris_verify_core::threshold::ThresholdSignature>,
    ) -> Result<u32, Error> {
        // Verify-A-store-B guard: the quorum authorized `change_envelope`, so
        // the roster/protocol being stored MUST be exactly the one it
        // describes — never verify one roster and persist another.
        let members: std::collections::BTreeSet<&str> = new
            .family
            .members
            .iter()
            .map(|m| m.key_id.as_str())
            .collect();
        assert_change_envelope_matches(
            &new.family.family_key_id,
            &members,
            &new.family.consensus_protocol,
            &change_envelope,
        )?;
        self.verify_membership_quorum(
            cohort::Cohort::Family,
            &new.family.family_key_id,
            &change_envelope,
            &signatures,
        )
        .await?;
        let authorization = serde_json::json!({
            "change_envelope": change_envelope,
            "quorum_signatures": signatures,
        });
        self.supersede_family(new, Some(authorization)).await
    }

    /// #249 Cut G3 — quorum-gated community supersede. Mirror of
    /// [`Self::supersede_family_with_quorum`].
    async fn supersede_community_with_quorum(
        &self,
        new: types::SignedCommunity,
        change_envelope: serde_json::Value,
        signatures: Vec<ciris_verify_core::threshold::ThresholdSignature>,
    ) -> Result<u32, Error> {
        let members: std::collections::BTreeSet<&str> = new
            .community
            .members
            .iter()
            .map(|m| m.key_id.as_str())
            .collect();
        assert_change_envelope_matches(
            &new.community.community_key_id,
            &members,
            &new.community.consensus_protocol,
            &change_envelope,
        )?;
        self.verify_membership_quorum(
            cohort::Cohort::Community,
            &new.community.community_key_id,
            &change_envelope,
            &signatures,
        )
        .await?;
        let authorization = serde_json::json!({
            "change_envelope": change_envelope,
            "quorum_signatures": signatures,
        });
        self.supersede_community(new, Some(authorization)).await
    }

    /// CC 4.4.3.2.8 / #308 — quorum-gated `affiliations` supersede. Mirror of
    /// [`Self::supersede_community_with_quorum`]; the quorum is verified against
    /// the shared community row and the new version is recorded under the
    /// `affiliations` discriminator via [`Self::supersede_affiliations`].
    async fn supersede_affiliations_with_quorum(
        &self,
        new: types::SignedCommunity,
        change_envelope: serde_json::Value,
        signatures: Vec<ciris_verify_core::threshold::ThresholdSignature>,
    ) -> Result<u32, Error> {
        let members: std::collections::BTreeSet<&str> = new
            .community
            .members
            .iter()
            .map(|m| m.key_id.as_str())
            .collect();
        assert_change_envelope_matches(
            &new.community.community_key_id,
            &members,
            &new.community.consensus_protocol,
            &change_envelope,
        )?;
        self.verify_membership_quorum(
            cohort::Cohort::Affiliations,
            &new.community.community_key_id,
            &change_envelope,
            &signatures,
        )
        .await?;
        let authorization = serde_json::json!({
            "change_envelope": change_envelope,
            "quorum_signatures": signatures,
        });
        self.supersede_affiliations(new, Some(authorization)).await
    }

    /// #249 Cut B — the INBOUND delegation walk: every key that holds a
    /// `delegates_to` edge naming `key_id` as the recipient ("who delegated
    /// TO me?"). The reverse of the forward-only
    /// [`topology::build_delegation_graph`](crate::federation::topology::build_delegation_graph),
    /// which walks OUTBOUND. Returns the full inbound `delegates_to`
    /// [`Attestation`] rows (deduped on `attestation_id`), so a consumer can
    /// read each edge's scope/expiry/granter.
    ///
    /// Default impl filters [`Self::list_attestations_for`] to
    /// `delegates_to`; backends need not override. Returns an empty vec when
    /// no key delegates to `key_id`.
    async fn delegations_to(&self, key_id: &str) -> Result<Vec<Attestation>, Error> {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        Ok(self
            .list_attestations_for(key_id)
            .await?
            .into_iter()
            .filter(|a| a.attestation_type == types::attestation_type::DELEGATES_TO)
            .filter(|a| seen.insert(a.attestation_id.clone()))
            .collect())
    }

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-path
    /// cohort_scope admission gate, for write paths reachable through
    /// `FederationDirectory` (`put_attestation`, and any other row
    /// carrying a `(cohort_scope, target)` claim).
    ///
    /// Resolves `writer_occurrence_key_id`'s admission (identity →
    /// families → communities, identical to
    /// [`crate::scope::build_caller_admission`] but trait-local so
    /// per-backend `put_attestation` can call it without an `Engine`)
    /// and runs [`admission::DimensionAdmissionPolicy::check_write_cohort_scope`]
    /// against the claimed `(cohort_scope, target)`. Returns
    /// [`Error::WriteScopeRefused`] on a downgrade attempt; the caller
    /// runs this BEFORE computing `persist_row_hash` / INSERT so a
    /// refused row leaves no trace (verify-then-gate-then-persist).
    ///
    /// `self` and the broad belonging-tiers are no-op passes that need
    /// no admission read; only `family` / `community` trigger the
    /// resolution fan-out. On refusal a §9.3
    /// `persist_refused_write_scope_total` event is emitted.
    ///
    /// Provided method (not per-backend SQL): composes the existing
    /// resolution methods. Both backends inherit it.
    async fn check_write_cohort_scope_for(
        &self,
        writer_occurrence_key_id: &str,
        write_path: &'static str,
        claimed_cohort_scope: &str,
        claimed_target_id: Option<&str>,
    ) -> Result<(), Error> {
        use crate::federation::types::cohort_scope as cs;
        // Fast path: `self` + the broad belonging-tiers need no
        // membership resolution. Only family/community do.
        let needs_admission =
            claimed_cohort_scope == cs::FAMILY || claimed_cohort_scope == cs::COMMUNITY;

        let admission = if needs_admission {
            // occurrence → identity (singleton fallback: unbound
            // occurrence IS its own identity, FSD §4.4).
            let identity = match self
                .lookup_identity_for_occurrence(writer_occurrence_key_id)
                .await?
            {
                Some(io) => io.identity_key_id,
                None => writer_occurrence_key_id.to_owned(),
            };
            // ACTIVE membership, not raw containment — the roster is
            // append-only, so raw `members` counts a revoked member as a
            // member. See `active_community_key_ids_for` for the full
            // argument; measured by the revoked-member arm of
            // `exercise_owner_signed_community_row`.
            let family_key_ids = self.active_family_key_ids_for(&identity).await?;
            let community_key_ids = self.active_community_key_ids_for(&identity).await?;
            crate::scope::CallerAdmission::from_resolved(
                writer_occurrence_key_id.to_owned(),
                identity,
                family_key_ids,
                community_key_ids,
            )
        } else {
            // No reads needed; an empty admission is sufficient for the
            // self / broad-tier arms (they ignore the membership sets).
            crate::scope::CallerAdmission::from_resolved(
                writer_occurrence_key_id.to_owned(),
                writer_occurrence_key_id.to_owned(),
                std::iter::empty::<crate::scope::KeyId>(),
                std::iter::empty::<crate::scope::KeyId>(),
            )
        };

        admission::DimensionAdmissionPolicy::check_write_cohort_scope(
            &admission,
            claimed_cohort_scope,
            claimed_target_id,
        )
        .map_err(|reason| {
            tracing::warn!(
                metric = "persist_refused_write_scope_total",
                write_path = %write_path,
                scope = %claimed_cohort_scope,
                reason = %reason.kind(),
                target = ?claimed_target_id,
                "ciris-persist: write-path cohort_scope refused (AV-45)"
            );
            Error::WriteScopeRefused(reason)
        })
    }

    // ── Cold-path PQC fill-in (writer contract step 4) ─────────────
    //
    // Per `docs/FEDERATION_DIRECTORY.md` §"Trust contract — eventual
    // consistency as a federation primitive" + §"PQC strategy", the
    // writer contract is:
    //   1. Sign canonical with Ed25519 (hot)
    //   2. Write the row (PQC fields None)
    //   3. IMMEDIATELY kick off ML-DSA-65 sign on cold path
    //   4. Call attach_*_pqc_signature once ML-DSA completes
    //
    // These three methods implement step 4. They:
    //   - Reject if the row is already hybrid-complete (no double-fill)
    //   - Update PQC fields atomically
    //   - Set pqc_completed_at = NOW()
    //   - Recompute persist_row_hash since row content changed
    //
    // v31.0.0 (CIRISPersist#657) — CORRECTED IN PLACE. This comment used to
    // read "Persist does NOT verify the cryptographic validity of the PQC
    // signature on attach — that's the writer's responsibility. Persist
    // verifies on read at the consumer's policy layer." It documented a defect
    // as a design: true of a SIGNATURE, false of a KEY.
    // `attach_key_pqc_signature` writes `pubkey_ml_dsa_65_base64` — the PQC
    // half of an IDENTITY — and an unverified public key is not something a
    // downstream reader can catch later, because every later verify resolves
    // that key out of the directory and succeeds against it. So the key plane
    // now gates at the door
    // ([`admission::check_key_pqc_attachment`](crate::federation::admission::check_key_pqc_attachment)):
    // the signed `registration_envelope` must bind the attached ML-DSA-65
    // pubkey (#659), and the post-attach row must verify hybrid-Strict.
    //
    // The two signature-only siblings below attach no key material, so their
    // signature really is verified at the consumer's policy layer on read.

    /// Attach the PQC components to a hybrid-pending federation_keys row.
    /// Updates pubkey_ml_dsa_65_base64 + scrub_signature_pqc + pqc_completed_at.
    /// Errors if the row is already PQC-complete.
    ///
    /// v31.0.0 (CIRISPersist#657) — REFUSES unless the row's already-signed
    /// `registration_envelope` binds the ML-DSA-65 pubkey being attached and
    /// the post-attach row hybrid-Strict-verifies. See
    /// [`admission::check_key_pqc_attachment`](crate::federation::admission::check_key_pqc_attachment)
    /// for why a row that bound `pubkey_ml_dsa_65_base64: null` may not attach
    /// one afterwards.
    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error>;

    /// Attach the PQC signature to a hybrid-pending
    /// `federation_attestations` row. Attestations don't have their
    /// own pubkey — they reference the existing
    /// `federation_keys.scrub_key_id`'s pubkey for verification.
    ///
    /// v31.0.0 (CIRISPersist#657) — implementations MUST re-index
    /// `signed_wire_index` after the UPDATE. Three serialized columns move, so
    /// the wire content hash moves with them; this is the #547/#640 stale-index
    /// class, which was fixed at [`Self::attach_key_pqc_signature`] and not
    /// here.
    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error>;

    /// Attach the PQC signature to a hybrid-pending
    /// `federation_revocations` row. Same shape as attestations.
    ///
    /// v31.0.0 (CIRISPersist#657) — deliberately does NOT re-index:
    /// `federation_revocations` (the KEY-revocation plane, as distinct from the
    /// `*MembershipRevocation` and `IdentityOccurrenceRevocation` planes, which
    /// do have index kinds) has no `signed_wire_index` kind at all — no arm in
    /// [`wire_index::reload_record_bytes`](crate::federation::wire_index::reload_record_bytes)
    /// and no entry in
    /// [`wire_index::all_kind_hash_keys`](crate::federation::wire_index::all_kind_hash_keys),
    /// because no bulk signed-since surface serves it. There is no stale index
    /// to fix here; if that plane ever gains a wire kind, this method gains the
    /// re-index its two siblings have.
    async fn attach_revocation_pqc_signature(
        &self,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error>;

    /// v4.6 (CIRISPersist#171 phase 2) — fetch a single attestation row
    /// by id (any tier). `None` if absent. Used by `Engine::attestation_
    /// promote` to load the `local` row's envelope before signing.
    async fn get_attestation(&self, attestation_id: &str) -> Result<Option<Attestation>, Error>;

    /// v4.6 (CIRISPersist#171 phase 2, CEG §10.1.3/§10.1.5) — the
    /// local→federation **promotion** write-back: stamp the hybrid scrub
    /// envelope computed by [`crate::Engine::attestation_promote`] and
    /// flip `tier` to `federation` (+ `promoted_at`), iff the row is
    /// currently `local`. Returns `Ok(true)` on promotion, `Ok(false)` if
    /// the row is already `federation` (idempotent), `Err` if absent. The
    /// signing bytes are the §0.9-canonical envelope (gated produce
    /// canonicalizer), so a promoted row is byte-identical on the wire to
    /// a natively-federation one (Registry must #1).
    ///
    /// # v26.0.0 (CIRISPersist#589 / AV-83) — the primitive carries its placement
    ///
    /// `cohort_scope` is the placement the promoted row lands at, written in
    /// the SAME statement as the tier flip. Before this it was a separate
    /// [`Self::set_attestation_cohort_scope`] call the caller made first
    /// ("placement before tier"), which was safe only while promotion could
    /// not refuse on authority grounds. Now that
    /// [`admission::check_promotion_admission`] runs here, that two-step left a
    /// REFUSED promotion having already mutated the row's `cohort_scope` and
    /// `persist_row_hash` — a verify-before-mutation (AV-9) violation, and
    /// exactly what the substrate state machine's I2a caught. Carrying the
    /// placement is #519's own "a promotion is placement-touching, so the
    /// primitive must carry it" argument applied one layer further down: an
    /// incomplete OR a partially-applied promotion is no longer expressible.
    ///
    /// # v31.0.0 (CIRISPersist#649) — the primitive carries its ENVELOPE
    ///
    /// The same argument, one layer further still. CIRISPersist#643 bound
    /// `cohort_scope` into `envelope.row`; promotion CHANGES `cohort_scope`
    /// and RE-SIGNS the row, and it was re-signing the PRE-promotion envelope
    /// — so the promoted row's signed mirror asserted its old scope while its
    /// column said otherwise, and every peer's `put_attestation` refused it.
    /// The promoting node's own output was unreplicable, and promotion
    /// returned `Ok` throughout, which is what hid it.
    ///
    /// [`AttestationReseal`] now carries the RE-STAMPED envelope
    /// ([`envelope::RowMirror::restamp_for_scope`]) alongside the digest and
    /// signature computed over exactly those bytes, and the implementation
    /// writes the envelope in the SAME statement as the placement and the tier
    /// flip. Implementations re-run [`admission::check_row_column_binding`]
    /// over the row as it will be stored (via
    /// [`admission::check_promotion_admission`]), so a caller that skips the
    /// re-stamp is REFUSED at the primitive.
    ///
    /// # This absorbed `promote_attestation_transformed`
    ///
    /// v21.3.0's #510 strip-then-promote variant existed for exactly one
    /// reason: it additionally wrote back `attestation_envelope`. Once THIS
    /// method must write the envelope back too, the two were the same method
    /// under two names with two copies of one gate stack — the "door beside
    /// the door" this repo keeps re-discovering. There is one promotion
    /// primitive; a #510 restriction pipeline is just a different `base` handed
    /// to [`envelope::RowMirror::restamp_for_scope`]
    /// (see [`crate::Engine::promote_consented_backlog`]). The row's full
    /// PRE-transform form remains queryable via the `trace_events` projection,
    /// exactly as before.
    async fn promote_attestation(
        &self,
        attestation_id: &str,
        cohort_scope: &str,
        reseal: &AttestationReseal,
    ) -> Result<bool, Error>;

    // ── Hybrid-pending sweep (CIRISPersist#11, v0.3.2) ─────────────
    //
    // Per V004's schema header §"Phase transitions":
    //   "Pre-flip rows that are still pending get walked through the
    //    upgrade pipeline."
    // These three methods feed that pipeline. Persist's PyO3
    // `Engine.run_pqc_sweep()` walks each batch and drives cold-path
    // PQC fill-in for rows authored before the writer was configured
    // with a PQC local signer (or where the per-write cold-path failed
    // transiently). Idempotent at the consumer level —
    // `attach_*_pqc_signature` already guards against double-fill via
    // `WHERE pqc_completed_at IS NULL`.

    /// Return up to `limit` `federation_keys` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `valid_from`. Returns `(key_id, registration_envelope,
    /// scrub_signature_classical)` triples sufficient to reconstruct
    /// the cold-path bound-signature input.
    async fn list_hybrid_pending_keys(&self, limit: i64) -> Result<Vec<HybridPendingRow>, Error>;

    /// Return up to `limit` `federation_attestations` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `asserted_at`.
    async fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> Result<Vec<HybridPendingRow>, Error>;

    /// Return up to `limit` `federation_revocations` rows where
    /// `pqc_completed_at IS NULL`, ordered oldest first by
    /// `revoked_at`.
    async fn list_hybrid_pending_revocations(
        &self,
        limit: i64,
    ) -> Result<Vec<HybridPendingRow>, Error>;

    // ── Trust grants (v1.3.0, CIRISPersist#46 + #47) ───────────────
    //
    // Persist absorbs NodeCore's `crate::trust` module surface at
    // the M2 cut. Raw CRUD over the trust-hierarchy columns on
    // `federation_keys` (added by V020); NodeCore composes the
    // transitive-resolution policy on top via `resolve_trust`.
    //
    // Default impls return `Error::Backend` with a stable
    // "trust_methods_not_implemented" marker so backends that
    // haven't been ported yet (memory/test shims) compile cleanly.
    // The real backends (postgres, sqlite) override every method.
    //
    // # Audit chain coupling
    //
    // CIRISAgent#756 Q4 verdict: state transitions for the trust
    // hierarchy live in the audit chain (`cirislens.audit_log`),
    // not in a separate revocation_history table. The
    // `AuditEventType::TrustGranted` / `TrustRevoked` vocabulary +
    // V020 CHECK extension carry the wire-shape; persist callers
    // compose the pair (write the trust row via this trait, then
    // write the audit entry via `AuditService::record_entry` /
    // `try_claim_event` with a caller-signed `AuditEntry`). Persist
    // does not auto-sign because the audit chain's self-signed
    // identity model (AV-49) requires the caller's Ed25519 key.

    /// Insert or update a trust row on `federation_keys`.
    /// Implementations:
    ///   1. Validate `grant.trusted_by != grant.key` (no self-trust);
    ///      reject with [`Error::InvalidArgument`].
    ///   2. Validate `Registry`-relationship grants carry a non-empty
    ///      `trust_domains`; reject with [`Error::InvalidArgument`].
    ///   3. UPSERT on `key_id` — preserves the pubkey + signature
    ///      envelope written by the prior `put_public_key`, overwrites
    ///      the trust columns. `trusted_at` is set to `NOW()`.
    /// v38.0.0 (CIRISPersist#721) — takes a [`SignedTrustGrant`]: the
    /// granter PROVES it is `trusted_by` (Strict hybrid over the pinned
    /// signing bytes, verified against the directory-pinned keys) at
    /// [`admission::check_trust_grant_authority`], asked INSIDE every
    /// implementation ahead of the shape validation.
    async fn grant_trust(&self, grant: SignedTrustGrant) -> Result<(), Error> {
        let _ = grant;
        Err(Error::Backend(
            "grant_trust not implemented for this backend".into(),
        ))
    }

    /// Soft-delete a trust row by setting `expires_at = NOW()`.
    /// Idempotent — revoking an already-expired or absent row is a no-op.
    ///
    /// v38.0.0 (CIRISPersist#721) — takes a [`SignedTrustRevocation`]: the
    /// revoker proves it is `revoked_by`
    /// ([`admission::check_trust_revocation_authority`]) and must BE the
    /// stored row's `trusted_by` — only the granter withdraws its own grant
    /// (the protective-1 side; see [`admission::TRUST_PLANE_OPS`]). The old
    /// door validated `revoked_by` non-empty and then DISCARDED it.
    async fn revoke_trust(&self, revocation: SignedTrustRevocation) -> Result<(), Error> {
        let _ = revocation;
        Err(Error::Backend(
            "revoke_trust not implemented for this backend".into(),
        ))
    }

    /// Point lookup — the raw trust row, no transitive resolution.
    /// `None` if no trust row exists for `key` (i.e., the row
    /// exists in `federation_keys` but `trusted_by` is NULL — a
    /// pre-V020 row, or a key registered without a trust grant).
    async fn lookup_trust(&self, key: &str) -> Result<Option<TrustRow>, Error> {
        let _ = key;
        Err(Error::Backend(
            "lookup_trust not implemented for this backend".into(),
        ))
    }

    /// All currently-trusted keys matching `filter`. Server-side
    /// filtering for relationship + domain; expired rows excluded
    /// unless `filter.include_expired = true`. Pre-V020 rows
    /// (`trusted_by IS NULL`) are excluded — the surface returns
    /// only rows with an explicit trust grant.
    async fn list_trusted_keys(&self, filter: TrustFilter) -> Result<Vec<TrustRow>, Error> {
        let _ = filter;
        Err(Error::Backend(
            "list_trusted_keys not implemented for this backend".into(),
        ))
    }

    // ── Goals (v2.10.0, CIRISPersist#114) ──────────────────────────
    //
    // The typed `Goal` primitive (see [`goal`]) carries M-1 alignment
    // as a structural construction-time invariant — a Goal cannot be
    // constructed without [`MetaGoalAlignment`]. The persistence
    // surface mirrors that discipline: every write goes through a
    // typed `Goal`, never a free-form JSON envelope.
    //
    // F-3 detector consumers (CIRISLensCore#23 / #24 / #26) walk
    // these rows to aggregate goals by `declared_by_key_id` + scope +
    // `m1_dimension`. The hot path skips retired goals (the
    // `(retired_at IS NULL)` partial index), so `list_goals` defaults
    // to live-only via `GoalsFilter::include_retired = false`.
    //
    // Defaults route to `Error::Backend(...)` so the memory shim and
    // any future test-only backend compile cleanly; the real backends
    // (postgres, sqlite) override every method.

    /// Insert a [`Goal`]. The row is persisted with a server-computed
    /// `persist_row_hash` over the canonical bytes (same shape as
    /// `KeyRecord` et al.). Errors:
    /// - [`Error::InvalidArgument`] when `declared_by_key_id` is not
    ///   present in `federation_keys` (FK enforcement).
    /// - [`Error::Conflict`] when `goal_id` is already in the table
    ///   with content that differs from the submitted row.
    async fn put_goal(&self, goal: Goal) -> Result<(), Error> {
        let _ = goal;
        Err(Error::Backend(
            "put_goal not implemented for this backend".into(),
        ))
    }

    /// Fetch a single [`Goal`] by `goal_id`. Returns `None` when
    /// absent.
    async fn get_goal(&self, goal_id: uuid::Uuid) -> Result<Option<Goal>, Error> {
        let _ = goal_id;
        Err(Error::Backend(
            "get_goal not implemented for this backend".into(),
        ))
    }

    /// Enumerate [`Goal`] rows matching `filter`. Fields AND-composed
    /// (see [`GoalsFilter`]); retired rows are filtered out by
    /// default. Returned in stable lex order by `(declared_at,
    /// goal_id)` so callers can deterministically paginate.
    async fn list_goals(&self, filter: GoalsFilter) -> Result<Vec<Goal>, Error> {
        let _ = filter;
        Err(Error::Backend(
            "list_goals not implemented for this backend".into(),
        ))
    }

    /// Mark a [`Goal`] retired at `retired_at`. **Idempotent.** A
    /// second call against an already-retired goal returns `Ok(())`
    /// without changing the stored `retired_at` — the chosen
    /// discipline matches [`revoke_trust`](Self::revoke_trust)'s
    /// "soft-delete, idempotent" shape so consumers driving
    /// retirement from a queue don't need to special-case the
    /// race-replay window. Callers wanting strict-once semantics
    /// MUST guard at their layer (the
    /// [`Engine::receive_and_persist`](crate::Engine::receive_and_persist)
    /// pattern uses content-hash dedup for that). When the row does
    /// not exist, [`Error::InvalidArgument`] is returned.
    async fn retire_goal(
        &self,
        goal_id: uuid::Uuid,
        retired_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        let _ = (goal_id, retired_at);
        Err(Error::Backend(
            "retire_goal not implemented for this backend".into(),
        ))
    }

    // ── Peer-mutation surface (v3.1.0, CIRISPersist#117) ───────────
    //
    // Unblocks CIRISEdge v0.13.0's `PEER_MUTATION_FOLLOWUP` stubs in
    // `src/ffi/uniffi_impl.rs`. Operator-driven writes against the
    // V051 `federation_peer_metadata` sibling table. Access control
    // for these methods is enforced OUTSIDE persist (the UniFFI layer
    // is operator-local); persist's responsibility is value-domain
    // validation — typed errors, no silent coercion.
    //
    // Defaults route to `Error::Backend(...)` so backends that
    // haven't been ported yet compile cleanly. The real backends
    // (memory, postgres, sqlite) override every method.

    /// Insert a new peer row. Atomically:
    /// 1. Inserts a minimal `federation_keys` identity row carrying
    ///    `key_id`, `pubkey_ed25519_base64`, `identity_type`.
    /// 2. Inserts the sibling `federation_peer_metadata` row with
    ///    default `trust = TrustClass::Untrusted` + the supplied
    ///    `transport_identity`.
    ///
    /// Both writes happen in a single transaction; either both land
    /// or neither does.
    ///
    /// Errors:
    /// - [`Error::Conflict`] when `key_id` already exists with
    ///   different content.
    /// - [`Error::InvalidArgument`] when `key_id` /
    ///   `pubkey_ed25519_base64` / `identity_type` are empty.
    async fn add_peer_record(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        identity_type: &str,
        transport_identity: Option<String>,
    ) -> Result<(), Error> {
        let _ = (
            key_id,
            pubkey_ed25519_base64,
            identity_type,
            transport_identity,
        );
        Err(Error::Backend(
            "add_peer_record not implemented for this backend".into(),
        ))
    }

    /// Remove a peer row. Two modes:
    /// - `hard = false` (recommended): marks
    ///   `federation_peer_metadata.removed_at = NOW()`; subsequent
    ///   reads filter the row out. The federation_keys row is
    ///   preserved — the audit trail of "this peer was once a peer"
    ///   stays intact.
    /// - `hard = true`: DELETEs the federation_keys row in the same
    ///   transaction; the FK ON DELETE CASCADE removes the
    ///   federation_peer_metadata row too. **Rejected** with
    ///   [`Error::HardRemoveWithActiveAttestations`] when the peer
    ///   still has rows in `federation_attestations` —
    ///   hard-removing would orphan the attestation_envelope. Caller
    ///   must either soft-remove (preserve the audit trail) OR
    ///   explicitly revoke the key first.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    /// - [`Error::HardRemoveWithActiveAttestations`] when `hard =
    ///   true` and the peer has active attestations.
    async fn remove_peer_record(
        &self,
        key_id: &str,
        hard: bool,
        reason: &str,
        acting_under_delegation_id: Option<&str>,
    ) -> Result<(), Error> {
        let _ = (key_id, hard, reason, acting_under_delegation_id);
        Err(Error::Backend(
            "remove_peer_record not implemented for this backend".into(),
        ))
    }

    /// Set the peer's operator-local alias. `None` clears it. Bumps
    /// `updated_at` and recomputes `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_alias(&self, key_id: &str, alias: Option<String>) -> Result<(), Error> {
        let _ = (key_id, alias);
        Err(Error::Backend(
            "update_peer_alias not implemented for this backend".into(),
        ))
    }

    /// Set the peer's operator-trust class. Typed enum (no silent
    /// coercion of unrecognized strings). Bumps `updated_at` and
    /// recomputes `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_trust(&self, key_id: &str, trust: TrustClass) -> Result<(), Error> {
        let _ = (key_id, trust);
        Err(Error::Backend(
            "update_peer_trust not implemented for this backend".into(),
        ))
    }

    /// Set the peer's operator-local notes. `None` clears the field.
    /// Bumps `updated_at` and recomputes `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_notes(&self, key_id: &str, notes: Option<String>) -> Result<(), Error> {
        let _ = (key_id, notes);
        Err(Error::Backend(
            "update_peer_notes not implemented for this backend".into(),
        ))
    }

    /// Set the peer's opaque policy blob. Persist round-trips the
    /// JSON verbatim; the shape is owned by the consumer (CIRISEdge
    /// UniFFI's `PeerPolicy`). Bumps `updated_at` and recomputes
    /// `persist_row_hash`.
    ///
    /// Errors:
    /// - [`Error::PeerNotFound`] when no peer row exists for
    ///   `key_id`.
    async fn update_peer_policy(&self, key_id: &str, policy: PeerPolicyBlob) -> Result<(), Error> {
        let _ = (key_id, policy);
        Err(Error::Backend(
            "update_peer_policy not implemented for this backend".into(),
        ))
    }

    /// v3.4.1 (CIRISPersist#127) — read accessor for
    /// `federation_peer_metadata`. Returns the full row shape for
    /// active peers; `None` for non-existent or soft-removed peers
    /// (`removed_at IS NOT NULL`).
    ///
    /// Symmetric to [`update_peer_policy`] + the four other peer
    /// update methods — the write side shipped in v3.1.0 (#117); this
    /// is the read side CIRISEdge#48 (cohort_scope consumer-side
    /// enforcement) requires for `peer.policy_blob.cohort_scope`
    /// comparison.
    ///
    /// The `policy_blob` field is opaque JSON (the same shape callers
    /// pass to [`update_peer_policy`]); consumer is responsible for
    /// the typed decode.
    async fn peer_metadata_for(&self, key_id: &str) -> Result<Option<PeerMetadataRow>, Error> {
        let _ = key_id;
        Err(Error::Backend(
            "peer_metadata_for not implemented for this backend".into(),
        ))
    }

    // ── Shared-instance leases (CIRISPersist#210; CIRISEdge#100) ────
    //
    // Cross-process leader election for a named singleton (the RNS
    // shared-instance owner). See [`shared_instance`] for the model.

    /// Try to become the owner of `instance_name`. Atomic across racing
    /// siblings — exactly one wins.
    ///
    /// - `Ok(Some(lease))` — won. The caller is now the server: hold the
    ///   lease and call [`heartbeat_shared_instance`](Self::heartbeat_shared_instance)
    ///   periodically. Won either because no row existed, or the prior
    ///   owner's heartbeat aged past `stale_after` (a dead owner is
    ///   stolen; `lease_version` increments so the demoted owner detects
    ///   the takeover on its next heartbeat).
    /// - `Ok(None)` — a *live* owner already holds it. The caller is a
    ///   client; use [`lookup_shared_instance_lease`](Self::lookup_shared_instance_lease)
    ///   to find who to dial.
    /// - `Err(_)` — transport failure (DB unreachable etc.).
    ///
    /// `stale_after` defaults to
    /// [`shared_instance::DEFAULT_STALE_AFTER`] (30s) when `None`. The
    /// staleness threshold is computed client-side so the new row's
    /// timestamps and the staleness comparison share one clock.
    async fn try_acquire_shared_instance(
        &self,
        instance_name: &str,
        owner_pid: i32,
        owner_hostname: &str,
        stale_after: Option<std::time::Duration>,
    ) -> Result<Option<shared_instance::SharedInstanceLease>, Error> {
        let _ = (instance_name, owner_pid, owner_hostname, stale_after);
        Err(Error::Backend(
            "try_acquire_shared_instance not implemented for this backend".into(),
        ))
    }

    /// Refresh the lease's `last_heartbeat_at`. The owner calls this on a
    /// timer (e.g. every 10s against a 30s `stale_after`).
    ///
    /// - `Ok(Some(lease))` — heartbeat landed; the caller is still owner
    ///   (returned lease carries the refreshed `last_heartbeat_at`).
    /// - `Ok(None)` — the lease was **stolen** (a stale window elapsed
    ///   while the owner was paused and a sibling took over; the stored
    ///   row's `lease_version`/owner no longer matches the held lease, or
    ///   the row is gone). Treat as a demotion: stop owning, become a
    ///   client, reconnect to the new owner.
    /// - `Err(_)` — transport failure.
    async fn heartbeat_shared_instance(
        &self,
        lease: &shared_instance::SharedInstanceLease,
    ) -> Result<Option<shared_instance::SharedInstanceLease>, Error> {
        let _ = lease;
        Err(Error::Backend(
            "heartbeat_shared_instance not implemented for this backend".into(),
        ))
    }

    /// Look up the current owner of `instance_name` (live or stale).
    /// `None` if no row exists. Clients use it to find who to dial;
    /// operators use it to debug. Liveness is the caller's call from
    /// `last_heartbeat_at` age.
    async fn lookup_shared_instance_lease(
        &self,
        instance_name: &str,
    ) -> Result<Option<shared_instance::SharedInstanceLease>, Error> {
        let _ = instance_name;
        Err(Error::Backend(
            "lookup_shared_instance_lease not implemented for this backend".into(),
        ))
    }

    /// Explicitly release the lease on graceful shutdown so a sibling can
    /// take over immediately without waiting out `stale_after`. Idempotent
    /// and ownership-checked: only deletes the row if the held lease is
    /// still the current owner (matching `lease_version`); a no-op if the
    /// lease was already stolen (never deletes another process's lease).
    async fn release_shared_instance_lease(
        &self,
        lease: &shared_instance::SharedInstanceLease,
    ) -> Result<(), Error> {
        let _ = lease;
        Err(Error::Backend(
            "release_shared_instance_lease not implemented for this backend".into(),
        ))
    }

    // ── transport_destination (CIRISPersist#183, CEG §5.6.8.8.1) ───

    /// v6.5.0 (CIRISPersist#183, CEG §5.6.8.8.1) — register (or refresh) the
    /// reachable network address for an occurrence. **The trusted-LOCAL
    /// put** (self-at-login, the node's own engine); the replication plane
    /// goes through [`Self::put_signed_transport_destination`] instead.
    ///
    /// v17.0.0 (CIRISPersist#443) — route-table semantics: keyed on the
    /// `(occurrence_key_id, transport_kind)` PK (`destination` is payload —
    /// one live route per peer per transport), and **guarded monotonic**: the
    /// write applies iff no row exists or the incoming `(epoch, asserted_at)`
    /// is lexicographically greater than the stored one. A stale assertion is
    /// a silent no-op (never an error — the local caller re-reads if it
    /// cares). A local put that supersedes a SIGNED row NULLs the stored
    /// signature container (it attested the old content).
    ///
    /// Default impl errors; the three backends override.
    async fn put_transport_destination(
        &self,
        destination: &self_at_login::TransportDestination,
    ) -> Result<(), Error> {
        let _ = destination;
        Err(Error::Backend(
            "put_transport_destination not implemented for this backend".into(),
        ))
    }

    /// v17.0.0 (CIRISPersist#443) — the **authenticated replication apply**
    /// for the route plane: verify the
    /// [`verify_signed_transport_destination`](admission::verify_signed_transport_destination)
    /// gate (hybrid 1-of-1 over `JCS(signed_envelope)` against the PINNED
    /// federation pubkeys of `attesting_key_id`, typed-projection ≡ envelope,
    /// `signer_acts_for`) BEFORE any write, then apply under the same
    /// `(epoch, asserted_at)` monotonic guard as the local put, storing the
    /// signature container for byte-exact re-publish.
    ///
    /// Outcomes ([`TransportDestinationApplyOutcome`](self_at_login::TransportDestinationApplyOutcome)):
    /// fresh `(occ, kind)` ⇒ `Inserted`; strictly newer ⇒ `Superseded`
    /// (retirement — `retired_at` set — rides this too); identical typed
    /// content ⇒ `Unchanged`; older, or same `(epoch, asserted_at)` with
    /// different content ⇒ `Refused` (fail-closed, re-offerable). Gate
    /// failures surface as `Err` — the record itself is inadmissible.
    ///
    /// Default impl errors; the three backends override.
    async fn put_signed_transport_destination(
        &self,
        signed: &self_at_login::SignedTransportDestination,
    ) -> Result<self_at_login::TransportDestinationApplyOutcome, Error> {
        let _ = signed;
        Err(Error::Backend(
            "put_signed_transport_destination not implemented for this backend".into(),
        ))
    }

    /// v17.0.0 (CIRISPersist#443) — the route-plane **signed replication
    /// read**: every SIGNED-put route row of `occurrence_key_id` with its
    /// original `{attesting_key_id, signed_envelope, signature}` container,
    /// byte-exact (the mirror of
    /// [`Self::list_signed_identity_occurrence_revocations_for`]). Trusted-
    /// local rows (NULL signature columns) are OMITTED — a bare local route
    /// is not replicable (the receiver could not verify it). RETIRED rows are
    /// INCLUDED: tombstones must gossip. Default impl errors; the three
    /// backends override.
    async fn list_signed_transport_destinations_for(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<self_at_login::SignedTransportDestination>, Error> {
        let _ = occurrence_key_id;
        Err(Error::Backend(
            "list_signed_transport_destinations_for not implemented for this backend".into(),
        ))
    }

    /// v6.5.0 — list every LIVE route registered for `occurrence_key_id`
    /// ("how do I reach this occurrence?"): at most one row per
    /// `transport_kind` since #443, RETIRED (tombstoned) rows excluded.
    /// Empty when none. Liveness filtering (on `last_seen_at` age) is
    /// caller-side. Default impl errors; the three backends override.
    async fn list_transport_destinations_for(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        let _ = occurrence_key_id;
        Err(Error::Backend(
            "list_transport_destinations_for not implemented for this backend".into(),
        ))
    }

    /// v13.8.0 (CIRISPersist#411) — every stored reachable address across ALL
    /// occurrences, in one call. The **boot reload**: persist is the source of
    /// truth for rooted-peer transport state, so on startup the node/edge (which
    /// holds a `dyn FederationDirectory`) reloads every binding — dest-hash +
    /// transport-tier ed25519 (#397) + x25519 KEX (#411) — to repopulate its
    /// rooted-peers map + KEX resolver, with zero re-announces. The per-key
    /// [`Self::list_transport_destinations_for`] cannot reconstruct the whole set
    /// (it needs every key_id up front). #443: RETIRED rows excluded; ordered
    /// by `(occurrence_key_id, transport_kind)` — the route key, so the
    /// restore order is deterministic and "which is current" is structural
    /// (one row per key). Default impl errors; backends override.
    async fn list_all_transport_destinations(
        &self,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        Err(Error::Backend(
            "list_all_transport_destinations not implemented for this backend".into(),
        ))
    }

    /// v13.9.0 (CIRISPersist#413, CC 3.3.6.2) — every claimant of a `destination`
    /// (dest-hash), across all `occurrence_key_id`s. The **competing-claims**
    /// read: two different keys asserting the same dest-hash are BOTH admitted
    /// (distinct rows on the composite PK) and surfaced here so the routing layer
    /// can PREFER a [`BindingProvenance::Rooted`](self_at_login::BindingProvenance::Rooted)
    /// binding over an [`Advisory`](self_at_login::BindingProvenance::Advisory)
    /// one — the AV-42 spoof is resolved by preference, never a substrate reject.
    /// #443: RETIRED rows excluded. Default impl errors; backends override.
    async fn list_transport_destinations_by_destination(
        &self,
        destination: &str,
    ) -> Result<Vec<self_at_login::TransportDestination>, Error> {
        let _ = destination;
        Err(Error::Backend(
            "list_transport_destinations_by_destination not implemented for this backend".into(),
        ))
    }

    /// v6.5.0 — drop one reachable address (e.g. a stale relay). Returns
    /// `true` if a row was removed, `false` if absent (idempotent).
    ///
    /// **LOCAL-ONLY DELETE (#443)** — this is a node-local hygiene operation
    /// that does NOT replicate: a peer that gossiped the route will offer it
    /// again, and a plain delete carries no anti-resurrection state. Route
    /// RETIREMENT on the mesh is a signed put with `retired_at` set and a
    /// higher `(epoch, asserted_at)` via
    /// [`Self::put_signed_transport_destination`] — the durable tombstone the
    /// monotonic guard defends. Default impl errors; the three backends
    /// override.
    async fn remove_transport_destination(
        &self,
        occurrence_key_id: &str,
        transport_kind: &str,
        destination: &str,
    ) -> Result<bool, Error> {
        let _ = (occurrence_key_id, transport_kind, destination);
        Err(Error::Backend(
            "remove_transport_destination not implemented for this backend".into(),
        ))
    }

    // ── freshness_floor (CIRISPersist#519 item 2a-iii) ─────────────

    /// v21.6.0 (CIRISPersist#519 item 2a-iii) — admit a SIGNED touch-claim
    /// against `(target_key_id, target_kind)`'s freshness floor
    /// ([`freshness`]). **Monotonic max**: the stored `fresh_as_of` only
    /// ever advances — an incoming claim with `fresh_as_of` less than or
    /// equal to the stored one is a no-op
    /// ([`freshness::TouchApplyOutcome::NotFresher`]), a strictly-greater
    /// one replaces ([`freshness::TouchApplyOutcome::Advanced`]).
    ///
    /// Runs, BEFORE any write: [`admission::verify_signed_touch_claim`]
    /// (hybrid signature + `cohort_scope` + signer-form relationship) AND
    /// [`admission::verify_touch_claim_admission`] (the future-skew guard,
    /// [`admission::DEFAULT_MAX_TOUCH_SKEW`]) — a lying clock cannot jump
    /// the floor forward, and the monotonic-max merge itself cannot roll it
    /// back. Default impl errors; the three backends override.
    async fn put_touch_claim(
        &self,
        claim: &types::SignedTouchClaim,
    ) -> Result<freshness::TouchApplyOutcome, Error> {
        let _ = claim;
        Err(Error::Backend(
            "put_touch_claim not implemented for this backend".into(),
        ))
    }

    /// v21.6.0 (CIRISPersist#519 item 2a-iii) — read the current freshness
    /// floor for `(target_key_id, target_kind)`; `None` if it was never
    /// touched. Default impl errors; the three backends override.
    ///
    /// **Privacy note (mandatory — see [`freshness`]'s module docs):** the
    /// returned claim carries a `cohort_scope`. A consumer MUST apply the
    /// same cohort/consent gating persist applies to any other
    /// cohort-scoped read before exposing this to a peer. This method is
    /// NOT a global read-receipt trail; composing an unrestricted "who
    /// last touched what, when" surface out of it is exactly the
    /// access-pattern surveillance the manifest's `privacy_row` flags
    /// (worst case: `trace:*`, where it would leak who is reading whose
    /// reasoning).
    async fn lookup_freshness_floor(
        &self,
        target_key_id: &str,
        target_kind: &str,
    ) -> Result<Option<types::SignedTouchClaim>, Error> {
        let _ = (target_key_id, target_kind);
        Err(Error::Backend(
            "lookup_freshness_floor not implemented for this backend".into(),
        ))
    }

    // ── hard_case:* emission surface (CIRISPersist#146 Ask 3) ──────

    /// Record a `hard_case:*` observability event (CEG §8.1.11.3 /
    /// §10.1.3). **Idempotent on `event_id`** — the emitter derives a
    /// deterministic id from `(kind, target, window)`, so re-recording
    /// the same observed condition (e.g. a re-scan by the consent-SLA
    /// watcher) is a no-op rather than a duplicate. See
    /// [`hard_case`](crate::federation::hard_case).
    async fn record_hard_case(&self, event: hard_case::HardCaseEvent) -> Result<(), Error> {
        let _ = event;
        Err(Error::Backend(
            "record_hard_case not implemented for this backend".into(),
        ))
    }

    /// CIRISServer#356 — this backend's **live peer-write-quota gauge**, or
    /// `None` when it holds no quota at all.
    ///
    /// The default is `None` and that is the honest answer for any
    /// implementation that does not run the #583 admission path: a backend
    /// which never charges a peer write has no tripwire to report, and
    /// synthesising a zero here would be indistinguishable from a healthy
    /// reading. Every consumer must render `None` as *unknown* — see
    /// [`PeerQuotaObservation`](replication::admission::PeerQuotaObservation),
    /// whose doc also explains why the numbers it carries are about a PROCESS
    /// and not about a node.
    ///
    /// Not `async` in spirit — it takes a mutex, touches no I/O, and never
    /// fails — but it lives on this trait because the quota is a private field
    /// of each backend and this is the only seam a host can reach it through.
    fn peer_quota_observation(&self) -> Option<replication::admission::PeerQuotaObservation> {
        None
    }

    /// List recorded `hard_case:*` events (LensCore consumes by kind +
    /// recency to compose `detection:consent:*`). Newest first.
    async fn list_hard_case_events(
        &self,
        filter: hard_case::HardCaseFilter,
    ) -> Result<Vec<hard_case::HardCaseEvent>, Error> {
        let _ = filter;
        Err(Error::Backend(
            "list_hard_case_events not implemented for this backend".into(),
        ))
    }

    // ── §19.1 WholenessWitness corpus (CIRISPersist#228 items 1–2) ──

    /// v8.2.0 (CEG 1.0-RC11 §19.1 / N3 / RC8) — admit a WholenessWitness
    /// to the corpus, **PQC-verified-BEFORE-persist**. Runs the full
    /// [`crate::witness::admit_witness`] gate (hybrid-PQC over the §19.1
    /// canonical preimage + the WW-2 namespace guard + the optional
    /// leaf/root recompute) BEFORE any row is durable; on any failure
    /// NOTHING is written (verify-before-mutation, AV-9). A
    /// classical-only / missing-ML-DSA-65 witness is the §19.0 hard cut
    /// ([`Error::WitnessAdmit`] with the `witness_admit_hybrid_required`
    /// token) — store-then-quarantine is non-conformant.
    ///
    /// `disclosed_leaves`, when `Some`, are re-hashed and the resulting
    /// root must equal `witness.merkle_root`. The producer keys
    /// (`ed25519_pubkey_b64` / `ml_dsa_65_pubkey_b64`) are the signing
    /// peer's verifying keys.
    ///
    /// On success the corpus is pruned to the last
    /// [`WITNESS_CORPUS_K`](crate::witness::WITNESS_CORPUS_K) witnesses
    /// for the peer (by `observed_at_unix_ms`). Idempotent on
    /// `(peer_id, epoch_id, observed_at_unix_ms)`.
    #[allow(clippy::too_many_arguments)]
    async fn put_wholeness_witness(
        &self,
        witness: &ciris_verify_core::holonomic::WholenessWitness,
        sig_ed25519_b64: &str,
        sig_ml_dsa_65_b64: Option<&str>,
        pqc_key_id: &str,
        ed25519_pubkey_b64: &str,
        ml_dsa_65_pubkey_b64: Option<&str>,
        disclosed_leaves: Option<&[Vec<u8>]>,
    ) -> Result<(), Error> {
        let _ = (
            witness,
            sig_ed25519_b64,
            sig_ml_dsa_65_b64,
            pqc_key_id,
            ed25519_pubkey_b64,
            ml_dsa_65_pubkey_b64,
            disclosed_leaves,
        );
        Err(Error::Backend(
            "put_wholeness_witness not implemented for this backend".into(),
        ))
    }

    /// v8.2.0 (§19.1) — the verified witnesses currently stored for
    /// `peer_id`, newest first (by `observed_at_unix_ms`). Capped at the
    /// last-K the corpus retains. Every row already passed the ingest
    /// gate (no in-band `verified` flag — F-5).
    async fn list_wholeness_witnesses_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<Vec<crate::witness::StoredWitness>, Error> {
        let _ = peer_id;
        Err(Error::Backend(
            "list_wholeness_witnesses_for_peer not implemented for this backend".into(),
        ))
    }

    /// v8.2.0 (§19.1 N4 anti-rollback / eclipse guard) — the highest
    /// `epoch_id` persist has accepted from `peer_id`, or `None` if it
    /// has never accepted a witness from the peer. Feeds
    /// [`crate::witness::accept_if_monotonic`] so a stale/replayed epoch
    /// is rejected before a peer's witness is acted on as newer.
    async fn last_witness_epoch_for_peer(&self, peer_id: &str) -> Result<Option<u64>, Error> {
        let _ = peer_id;
        Err(Error::Backend(
            "last_witness_epoch_for_peer not implemented for this backend".into(),
        ))
    }

    /// v8.2.0 (§19.1 N4 / WW→§10.1.6 subordination, CIRISPersist#228
    /// item 2) — classify the **verified** corpus set for `peer_id` and
    /// take the §19.1 action. Default impl composing
    /// [`list_wholeness_witnesses_for_peer`](Self::list_wholeness_witnesses_for_peer),
    /// [`crate::witness::classify_stored`], and (on equivocation)
    /// [`record_hard_case`](Self::record_hard_case):
    ///
    /// - **Equivocation** → emit a `hard_case:witness_equivocation` per
    ///   proof (idempotent) and RETAIN the pair; NEVER reconcile (N4,
    ///   non-repudiable). Returns
    ///   [`WitnessReconcileAction::Equivocation`].
    /// - **Divergent** → returns
    ///   [`WitnessReconcileAction::TriggerQuorumMerge`]. The witness is a
    ///   divergence DETECTOR: the caller fulfils the directive by
    ///   re-running the EXISTING §10.1.6 quorum-merge resolver
    ///   ([`operational::resolve_monotonic_quorum`] for `partner_record`,
    ///   the `revision` anti-rollback for `revocation`/`org_membership`)
    ///   over the stored rows. The witness root NEVER enters that
    ///   resolution — there is no "reconstitute from any fragment" path,
    ///   so a revoked key cannot be resurrected.
    /// - **Consistent** → [`WitnessReconcileAction::NoAction`].
    ///
    /// This method classifies + surfaces; it deliberately does NOT call
    /// the merge itself (the witness must not decide it). `now` stamps an
    /// emitted equivocation event.
    async fn reconcile_peer_witnesses(
        &self,
        peer_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::witness::WitnessReconcileAction, Error> {
        let stored = self.list_wholeness_witnesses_for_peer(peer_id).await?;
        let action = crate::witness::classify_stored(&stored)?;
        if let crate::witness::WitnessReconcileAction::Equivocation(proofs) = &action {
            for proof in proofs {
                // Retain + surface; NEVER reconcile (N4). Idempotent on
                // the deterministic event_id.
                self.record_hard_case(crate::witness::equivocation_hard_case(proof, now))
                    .await?;
            }
        }
        Ok(action)
    }

    /// v16 (CIRISPersist#431, CC 6.1.1) — the distinct `peer_id`s with at
    /// least one witness in the corpus. Feeds the compare-all path of
    /// [`compare_stored_witnesses`](Self::compare_stored_witnesses).
    async fn list_witness_peer_ids(&self) -> Result<Vec<String>, Error> {
        Err(Error::Backend(
            "list_witness_peer_ids not implemented for this backend".into(),
        ))
    }

    /// v16 (CIRISPersist#431, CC 6.1.1) — classify the stored, VERIFIED
    /// witnesses of `peer_ids` (`None` = every peer in the corpus) into
    /// the §19.1 verdict. Read-only: unlike
    /// [`reconcile_peer_witnesses`](Self::reconcile_peer_witnesses) it
    /// emits nothing (emission happens at put-time reconcile).
    ///
    /// Verified-inputs precondition (the `compare_witnesses` contract):
    /// every corpus row passed the ingest gate by construction — the F-5
    /// rule stores no unverified rows and no in-band `verified` flag to
    /// forge. The only way a stored row can fail to round-trip back to
    /// the verify-core shape is substrate corruption (a malformed root
    /// column), and that REFUSES with an error rather than comparing —
    /// an unverifiable row never reaches `compare_witnesses`.
    async fn compare_stored_witnesses(
        &self,
        peer_ids: Option<&[String]>,
    ) -> Result<crate::witness::WitnessReconcileAction, Error> {
        let peers: Vec<String> = match peer_ids {
            Some(ids) => ids.to_vec(),
            None => self.list_witness_peer_ids().await?,
        };
        let mut stored = Vec::new();
        for peer in &peers {
            stored.extend(self.list_wholeness_witnesses_for_peer(peer).await?);
        }
        Ok(crate::witness::classify_stored(&stored)?)
    }

    /// v16 (CIRISPersist#431, N4 read-back) — the non-repudiable
    /// equivocations visible in `peer_id`'s corpus: for each proof, BOTH
    /// conflicting [`StoredWitness`](crate::witness::StoredWitness) rows
    /// (retained, never reconciled) plus the recorded
    /// `hard_case:witness_equivocation` marker (matched by its
    /// deterministic event_id). Default impl composing
    /// [`list_wholeness_witnesses_for_peer`](Self::list_wholeness_witnesses_for_peer),
    /// [`crate::witness::classify_stored`], and
    /// [`list_hard_case_events`](Self::list_hard_case_events).
    async fn list_witness_equivocations(
        &self,
        peer_id: &str,
    ) -> Result<Vec<crate::witness::WitnessEquivocationRecord>, Error> {
        let stored = self.list_wholeness_witnesses_for_peer(peer_id).await?;
        let action = crate::witness::classify_stored(&stored)?;
        let crate::witness::WitnessReconcileAction::Equivocation(proofs) = action else {
            return Ok(Vec::new());
        };
        // The recorded markers for this kind, keyed by event_id so each
        // proof pairs with exactly its own emission (or None pre-emit).
        let cases = self
            .list_hard_case_events(hard_case::HardCaseFilter {
                kind: Some(crate::witness::WITNESS_EQUIVOCATION.to_owned()),
                since: None,
            })
            .await?;
        let mut records = Vec::with_capacity(proofs.len());
        for proof in &proofs {
            let root_a = crate::witness::encode_root_hex(&proof.roots.0);
            let root_b = crate::witness::encode_root_hex(&proof.roots.1);
            // The two conflicting corpus rows (match either root at the
            // proof's (epoch, namespace-set) identity).
            let mut ns_sorted = proof.claim_namespaces.clone();
            ns_sorted.sort_unstable();
            let witnesses: Vec<_> = stored
                .iter()
                .filter(|w| {
                    let mut w_ns = w.claim_namespaces.clone();
                    w_ns.sort_unstable();
                    w_ns.dedup();
                    w.epoch_id == proof.epoch_id
                        && w_ns == ns_sorted
                        && (w.merkle_root_hex == root_a || w.merkle_root_hex == root_b)
                })
                .cloned()
                .collect();
            // The marker's event_id is deterministic on (peer, epoch,
            // roots) — derive it through `equivocation_hard_case` itself
            // (the timestamp does not enter the id) so there is exactly
            // one derivation to keep coherent.
            let event_id =
                crate::witness::equivocation_hard_case(proof, chrono::Utc::now()).event_id;
            let hard_case = cases.iter().find(|c| c.event_id == event_id).cloned();
            records.push(crate::witness::WitnessEquivocationRecord {
                peer_id: proof.peer_id.clone(),
                epoch_id: proof.epoch_id,
                claim_namespaces: proof.claim_namespaces.clone(),
                root_a,
                root_b,
                witnesses,
                hard_case,
            });
        }
        Ok(records)
    }

    /// CEG §8.1.11.1 — effective consent stance of subject `s` over
    /// target Contribution `T` at `now`. Default impl over
    /// [`list_attestations_for`](Self::list_attestations_for): the latest
    /// non-expired `consent:state:*` attestation whose `attesting_key_id`
    /// is `s`, by `asserted_at`. `Unspecified` if `s` never declared a
    /// stance against `T`.
    ///
    /// v1 resolves the **direct** subject only; the `delegates_to` proxy
    /// chain (§8.1.11.1 `attesting_key_id ∈ delegates_to(s).proxies`) is
    /// a follow-up — a delegate-emitted stance is not yet folded in.
    ///
    /// v31.0.0 (CIRISPersist#598) — the winner is picked through
    /// [`consent::fold_ordering_key`]: still latest-wins on the `asserted_at`
    /// COLUMN (which every admitted `consent:state:*` row now proves equals
    /// its own signed envelope instant), with a deterministic
    /// RESTRICTION-WINS tie-break. Read that function's doc for why re-keying
    /// this fold to the envelope instant is the wrong fix.
    ///
    /// v36.0.0 (CIRISPersist#642) — the clock is now the FALLBACK, not the key.
    /// The body is [`consent::fold_stance`], shared with
    /// [`Self::resolve_scoped_consent`]: a `consent:state:*` row that NAMES the
    /// statement it supersedes (the signed
    /// [`consent_supersedes`](envelope::paths::CONSENT_SUPERSEDES) key) is
    /// ordered causally, and `asserted_at` decides only what causality leaves
    /// incomparable. Read [`consent::ConsentCausalEdge`] for
    /// why a 300s skew window is the wrong axis, and [`consent::fold_stance`]
    /// for the ratchet that keeps the new plane unable to loosen an answer.
    async fn resolve_consent_state(
        &self,
        target_key_id: &str,
        subject_key_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<hard_case::ConsentState, Error> {
        let rows = self.list_attestations_for(target_key_id).await?;
        Ok(consent::fold_stance(&rows, subject_key_id, now, None))
    }

    /// v16.1.0 (CIRISPersist#389, CC 4.5.13) — the **scope/class-scoped**
    /// consent resolver: the same latest-wins/expiry fold as
    /// [`Self::resolve_consent_state`], but folded ONLY over `consent:state:*`
    /// rows whose envelope names the given `scope` (bare string or array
    /// member) and — when `qualifier` is given — a matching `content_class`.
    ///
    /// This is the substrate half of the CIRISServer infohazard gate
    /// (`resolve_view_consent`, CIRISServer#161): the gate needs a grant that
    /// SPECIFICALLY names `scope:view` + the content class, and a revocation
    /// naming a DIFFERENT scope must NOT re-close it — which the
    /// all-dimensions fold above cannot express. One canonical resolver; the
    /// server deletes its parallel fold (the DRY-audit H2 finding).
    ///
    /// **Scope-matching is asymmetric on the fail direction (v16.1.1,
    /// CIRISServer#243):** a scope-less **NON-grant** (`consent:state:revoked`
    /// / `expired` / any unknown stance) is a **blanket** stance — "I withdraw
    /// my consent" with nothing qualifying it reads as wholesale withdrawal
    /// and matches EVERY scoped query (on a CC 4.5.13 child-safety gate the
    /// safe reading is the right default). A scope-less **grant** matches
    /// NOTHING — `granted` is the sole fail-open stance, so it must name its
    /// scope exactly (a broad grant never backs a gate it didn't name). A
    /// scoped row still matches only its own scope (+ `content_class`), so a
    /// revocation naming a *different* scope stays unrelated. Latest-wins
    /// composes naturally: a scoped re-grant NEWER than a blanket revoke
    /// re-opens that scope.
    ///
    /// v36.0.0 (CIRISPersist#642) — same body as
    /// [`Self::resolve_consent_state`] ([`consent::fold_stance`]), with the
    /// scope filter switched on: ONE fold, so the causal plane cannot reach one
    /// entry point and not the other. Note the universe an edge resolves
    /// against is the subject's WHOLE consent history for this target, not the
    /// scoped slice — a revocation naming a grant that answers a different
    /// scope is resolved, not read as a partial view.
    async fn resolve_scoped_consent(
        &self,
        target_key_id: &str,
        subject_key_id: &str,
        scope: &str,
        qualifier: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<hard_case::ConsentState, Error> {
        let rows = self.list_attestations_for(target_key_id).await?;
        Ok(consent::fold_stance(
            &rows,
            subject_key_id,
            now,
            Some((scope, qualifier)),
        ))
    }

    /// v31.0.0 (CIRISPersist#612, CC 4.5.13) — the **other half** of the
    /// infohazard reveal gate: fold the `content_class:{class}` flag plane for
    /// `subject_key_id`, honouring a cross-emitter CLEAR only from a key holding
    /// [`INFRA_CLASSIFY_CONTENT`](types::delegation_scope::INFRA_CLASSIFY_CONTENT)
    /// conferred by a root **this node** accepts.
    ///
    /// [`Self::resolve_scoped_consent`] above answers *"did the subject consent
    /// to this reveal?"*. This answers *"is the content flagged, by anyone whose
    /// clearing I am obliged to honour?"* — the arm CIRISServer#363 reported as
    /// a live fail-open, where an ordinary `agent`-typed key withdrew a flag it
    /// had never raised and the gate returned `Allow`.
    ///
    /// The whole design, including why RAISES are deliberately **not**
    /// conferral-filtered, lives in [`content_class`]. Default impl over
    /// [`Self::list_attestations_for`] + the capability walk — no per-backend
    /// SQL, so memory / sqlite / postgres inherit one fold.
    ///
    /// # Errors
    ///
    /// See [`content_class::resolve_content_class_flag`]: `InvalidArgument` for
    /// a dimension outside [`content_class::FAMILY_STEM`],
    /// [`Error::NodeIdentityUnset`] when the directory has no node identity to
    /// resolve conferrals against, plus any backend/walk error. A caller that
    /// cannot complete the fold must withhold.
    async fn resolve_content_class_flag(
        &self,
        subject_key_id: &str,
        dimension: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<content_class::ContentClassFlag, Error> {
        content_class::resolve_content_class_flag(self, subject_key_id, dimension, now).await
    }

    /// Subject-side revocations (consent observability scan, §8.1.11.3 /
    /// §10.1.3) — every `consent:state:revoked` attestation plus every
    /// subject-side `withdraws` (admission rule 2/3/4; rule 1 is the
    /// *producer's* self-revoke, not a consent event). Returns the full
    /// [`Attestation`] rows (`attested_key_id` = target `T`,
    /// `attesting_key_id` = subject `s`, `asserted_at` = revocation time,
    /// `tier`/`promoted_at` for the §10.1.3 local-tier check). Includes
    /// **local-tier** rows (unlike [`list_attestations_for`](Self::list_attestations_for),
    /// which is federation-only) — the promotion-overdue check needs them.
    /// `since` bounds the scan; `None` = all.
    async fn list_consent_revocations(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<Attestation>, Error> {
        let _ = since;
        Err(Error::Backend(
            "list_consent_revocations not implemented for this backend".into(),
        ))
    }

    /// CEG §8.1.11.3 + §10.1.3 — the consent observability watcher. One
    /// pass: for each subject-side revocation, (a) emit
    /// `hard_case:consent_sla_breach` if the producer committed a
    /// `consent:deletion_sla:{days}` on `T`, the deadline
    /// (`revocation_at + days`) has passed, and no `consent:deletion_complete`
    /// landed after the revocation; (b) emit
    /// `hard_case:consent_revocation_promotion_overdue` if the revocation
    /// is still local-tier (unpromoted) past `promotion_window`.
    ///
    /// Backend-agnostic default composing
    /// [`list_consent_revocations`](Self::list_consent_revocations) +
    /// [`list_attestations_for`](Self::list_attestations_for) +
    /// [`record_hard_case`](Self::record_hard_case). Emission is idempotent
    /// (deterministic `event_id`), so running every tick re-emits nothing
    /// for already-recorded conditions. NOTE: the per-revocation
    /// `list_attestations_for` is an N+1 read — fine for a periodic watcher
    /// over a bounded `since` window; revisit if the revocation set grows
    /// large.
    async fn run_consent_sla_watch(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        promotion_window: std::time::Duration,
    ) -> Result<hard_case::ConsentWatchReport, Error> {
        fn envelope_dimension(a: &Attestation) -> Option<&str> {
            a.attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str())
        }
        let promotion = chrono::Duration::from_std(promotion_window)
            .unwrap_or_else(|_| chrono::Duration::hours(24));
        let revocations = self.list_consent_revocations(None).await?;
        let mut report = hard_case::ConsentWatchReport {
            revocations_scanned: revocations.len(),
            ..Default::default()
        };
        for rev in &revocations {
            let target = &rev.attested_key_id;
            let subject = &rev.attesting_key_id;
            let revoked_at = rev.asserted_at;

            // (a) §8.1.11.3 deletion-SLA breach.
            let atts = self.list_attestations_for(target).await?;
            let sla_days = atts
                .iter()
                .filter_map(|a| {
                    envelope_dimension(a)
                        .and_then(hard_case::parse_deletion_sla_days)
                        .map(|days| (a.asserted_at, days))
                })
                .max_by_key(|(at, _)| *at)
                .map(|(_, days)| days);
            if let Some(days) = sla_days {
                let deadline = revoked_at + chrono::Duration::days(i64::from(days));
                let completed = atts.iter().any(|a| {
                    envelope_dimension(a)
                        .is_some_and(|d| d.starts_with("consent:deletion_complete"))
                        && a.asserted_at > revoked_at
                });
                if now > deadline && !completed {
                    self.record_hard_case(hard_case::HardCaseEvent {
                        event_id: hard_case::watch_event_id(
                            hard_case::kind::CONSENT_SLA_BREACH,
                            target,
                            revoked_at,
                        ),
                        kind: hard_case::kind::CONSENT_SLA_BREACH.to_string(),
                        target_key_id: Some(target.clone()),
                        subject_key_id: Some(subject.clone()),
                        detail: serde_json::json!({
                            "sla_days": days,
                            "revocation_at": revoked_at.to_rfc3339(),
                            "deadline": deadline.to_rfc3339(),
                        }),
                        emitted_at: now,
                    })
                    .await?;
                    report.sla_breaches += 1;
                }
            }

            // (b) §10.1.3 local-tier revocation unpromoted past the window.
            // AV-61 RESOLVED (CIRISPersist#238; §10.1.3 "transit-not-rest"
            // ratification): a subject-side revocation is federation-tier by
            // *classification*. It MAY *transit* the local-tier write path
            // while in flight (the producing occurrence's substrate accepts the
            // unsigned envelope before promotion) but MUST NOT *rest* there —
            // its only conformant terminal states are *promoted* (tier becomes
            // `federation`, so it drops out of this fire condition) or
            // *overdue-flagged* (this emission). This overdue emission IS the
            // SLA enforcement: the consent-promotion gate and the CC 5.3.2.4.3
            // `local ⟹ caller is the producing occurrence` read-gate read this
            // SAME overdue state, which is exactly what keeps the two gates
            // from de-syncing (the AV-61 threat). persist itself never *rests*
            // a subject revocation as a durable local row — its own admission
            // gate (`check_local_tier_eligibility` rule 2) refuses to originate
            // one; a transit-staged row here arrives via the #171 promote
            // surface and this watcher drives it out (promote or flag).
            // CIRISServer#356 — the SAME predicate the two readers use. It was
            // a third open-coded copy of the identical three conjuncts; a
            // watcher and a reader that disagreed about "overdue" would flag
            // and report different sets.
            if is_promotion_overdue(rev, now, promotion) {
                self.record_hard_case(hard_case::HardCaseEvent {
                    event_id: hard_case::watch_event_id(
                        hard_case::kind::CONSENT_REVOCATION_PROMOTION_OVERDUE,
                        target,
                        revoked_at,
                    ),
                    kind: hard_case::kind::CONSENT_REVOCATION_PROMOTION_OVERDUE.to_string(),
                    target_key_id: Some(target.clone()),
                    subject_key_id: Some(subject.clone()),
                    detail: serde_json::json!({
                        "revocation_at": revoked_at.to_rfc3339(),
                        "promotion_window_secs": promotion_window.as_secs(),
                    }),
                    emitted_at: now,
                })
                .await?;
                report.promotion_overdue += 1;
            }
        }
        Ok(report)
    }

    /// v16 (CIRISPersist#434, CC 5.3.2.2) — the 24h-SLA detector's READ
    /// surface: every subject-side `consent:state:revoked` still resting
    /// at LOCAL tier (unpromoted) with `now - asserted_at > sla`,
    /// returned as [`ConsentPromotionOverdueRow`](hard_case::ConsentPromotionOverdueRow)s.
    /// This is the never-rest-local tripwire's reader half — the
    /// `run_consent_sla_watch` (b) branch surfaces the same condition as
    /// a `hard_case`; this method returns the rows so a caller can drive
    /// the promotion (`attestation_promote`) that clears them.
    ///
    /// Each overdue row is ALSO recorded as
    /// `hard_case:consent_revocation_promotion_overdue`, idempotently:
    /// the deterministic [`hard_case::watch_event_id`] is the SAME one
    /// the watcher derives, so a reader scan and a watcher tick never
    /// double-emit for one observed condition.
    ///
    /// Backend-agnostic default composing
    /// [`list_consent_revocations`](Self::list_consent_revocations) +
    /// [`record_hard_case`](Self::record_hard_case).
    async fn list_consent_revocation_promotion_overdue(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        sla: std::time::Duration,
    ) -> Result<Vec<hard_case::ConsentPromotionOverdueRow>, Error> {
        let window =
            chrono::Duration::from_std(sla).unwrap_or_else(|_| chrono::Duration::hours(24));
        let revocations = self.list_consent_revocations(None).await?;
        let mut overdue = Vec::new();
        for rev in &revocations {
            // §10.1.3 transit-not-rest: only a LOCAL-tier, unpromoted row
            // past the window is overdue (a promoted row's terminal state
            // is `federation`, which drops it out of the fire condition).
            if !is_promotion_overdue(rev, now, window) {
                continue;
            }
            // Flag it (idempotent — the watcher's own event_id derivation,
            // so reader + watcher dedup against each other).
            self.record_hard_case(hard_case::HardCaseEvent {
                event_id: hard_case::watch_event_id(
                    hard_case::kind::CONSENT_REVOCATION_PROMOTION_OVERDUE,
                    &rev.attested_key_id,
                    rev.asserted_at,
                ),
                kind: hard_case::kind::CONSENT_REVOCATION_PROMOTION_OVERDUE.to_string(),
                target_key_id: Some(rev.attested_key_id.clone()),
                subject_key_id: Some(rev.attesting_key_id.clone()),
                detail: serde_json::json!({
                    "revocation_at": rev.asserted_at.to_rfc3339(),
                    "promotion_window_secs": sla.as_secs(),
                }),
                emitted_at: now,
            })
            .await?;
            overdue.push(overdue_row(rev, now));
        }
        Ok(overdue)
    }

    /// CIRISServer#356 — **the same question, answered without writing
    /// anything.**
    ///
    /// Byte-for-byte the same `Vec<ConsentPromotionOverdueRow>` that
    /// [`list_consent_revocation_promotion_overdue`](Self::list_consent_revocation_promotion_overdue)
    /// returns for the same `(now, sla)`, computed by the same
    /// [`is_promotion_overdue`] predicate over the same rows — and with the
    /// `record_hard_case` call removed. Nothing else differs, and the two share
    /// their predicate rather than copying it so they cannot drift into
    /// disagreeing about what "overdue" means.
    ///
    /// # Why "idempotent" was not good enough
    ///
    /// The emitting reader is idempotent, which means *no duplicate rows*. It
    /// does not mean *no writes*: every call re-executes `record_hard_case` for
    /// every currently-overdue row, so an operator dashboard polling the
    /// condition every few seconds drives a write to the audit plane on every
    /// refresh — forever, at whatever rate someone left the page open at. The
    /// row count stays flat and the write volume does not, and a substrate that
    /// makes *looking* a mutation has made observation expensive in exactly the
    /// place #356 wants it cheap.
    ///
    /// So: **poll this one.** Use the emitting sibling (or
    /// [`run_consent_sla_watch`](Self::run_consent_sla_watch)) when the point
    /// is to put the breach on the record — a scheduled watcher tick, an
    /// operator acknowledging the condition. Reading and attesting are two
    /// different acts and they now have two different methods.
    ///
    /// Backend-agnostic default over
    /// [`list_consent_revocations`](Self::list_consent_revocations); mutates
    /// nothing on any backend.
    async fn list_consent_revocation_promotion_overdue_readonly(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        sla: std::time::Duration,
    ) -> Result<Vec<hard_case::ConsentPromotionOverdueRow>, Error> {
        let window =
            chrono::Duration::from_std(sla).unwrap_or_else(|_| chrono::Duration::hours(24));
        Ok(self
            .list_consent_revocations(None)
            .await?
            .iter()
            .filter(|rev| is_promotion_overdue(rev, now, window))
            .map(|rev| overdue_row(rev, now))
            .collect())
    }

    // ─── v10.0.0 — fountain holdings/eviction surface (CIRISPersist#270) ──
    //
    // Promoted from the concrete `Backend` trait onto the PUBLIC
    // `FederationDirectory` so downstream consumers holding
    // `Arc<dyn FederationDirectory>` (CIRISEdge#143 swarm runtime) can call
    // the fountain store-and-evict half directly — collapsing the
    // `FountainHoldingsSource` / `FountainTierEvict` / `FountainEvictHardDelete`
    // adapter traits onto this one surface. Each mirrors the identically
    // named [`crate::store::Backend`] method 1:1.

    /// v10.0.0 (CIRISPersist#270) — list the fountain-coded content a
    /// **publisher** holds, as [`FountainHeldMeta`](crate::fountain::FountainHeldMeta)
    /// (manifest essentials + the current degradation state: `held_symbols`
    /// vs `min_viable_symbols` ⇒ `recoverable`). Filtered to the manifest
    /// signer (`content_manifest.pqc_key_id = publisher_key_id`); no symbol
    /// bytes are read. Ordered by `admitted_at` descending. Empty when the
    /// publisher holds nothing.
    ///
    /// Mirrors [`crate::store::Backend::list_held_fountain_content`].
    async fn list_held_fountain_content(
        &self,
        publisher_key_id: &str,
    ) -> Result<Vec<crate::fountain::FountainHeldMeta>, Error>;

    /// v10.0.0 (CIRISPersist#270) — evict a content unit's symbols down to
    /// the per-tier keep-count, dropping by `retention_priority DESC` within
    /// the `content_id`. The manifest is NEVER touched. Returns the number
    /// of symbol rows evicted. No-op (`Ok(0)`) when the content_id is unknown
    /// or already at/below the keep-count.
    ///
    /// Mirrors [`crate::store::Backend::evict_fountain_content_to_tier`].
    async fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: crate::fountain::FountainTier,
    ) -> Result<u64, Error>;

    /// v10.0.0 (CIRISPersist#270) — **HardDelete** every symbol row for
    /// `(content_id, corpus_kind)` unconditionally (the §8.1.11.3
    /// deletion-SLA / revocation-dominates-rarity path), leaving the manifest
    /// as the always-retained `EnvelopeOnly` provenance. Never consults
    /// `retention_priority`. Returns the number of symbol rows dropped.
    /// Unknown content ⇒ `Ok(0)` no-op.
    ///
    /// Mirrors [`crate::store::Backend::evict_fountain_content_hard_delete`].
    async fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<u64, Error>;

    // ── #302 (FSD-004) accord live-quorum storage ──────────────────────
    //
    // The durable substrate for the constitutional kill-switch's
    // decimation-recovery live quorum (CIRISVerify#150 stateless machinery;
    // CIRISServer#122 runtime writes through). Persist STORES the verify-core
    // objects verbatim + dedups + verifies participations + holds nonce/halt
    // state; the SERVER runs the tally. Recovery (H7) is absent (CIRISAccord#4
    // gate). See [`crate::federation::accord_quorum`].

    /// #302 — admit an `accord_proposal` (server-issued). M4 fail-closed: the
    /// proposal's `nonce` MUST already be issued for its family
    /// ([`Self::issue_accord_nonce`]) or the write is rejected. The digest is
    /// derived via verify-core ([`AccordProposal::digest`](ciris_verify_core::accord_live_quorum::AccordProposal::digest));
    /// the object is stored verbatim. Idempotent on a byte-identical re-PUT.
    async fn put_accord_proposal(
        &self,
        proposal: ciris_verify_core::accord_live_quorum::AccordProposal,
        authority_signature: Option<serde_json::Value>,
    ) -> Result<(), Error>;

    /// #302 — the stored proposal for `proposal_digest`, or `None`.
    async fn get_accord_proposal(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<accord_quorum::StoredProposal>, Error>;

    /// #302 — proposals over `(action, prior_family_digest)` — the H4
    /// coalescing index (collapse duplicate proposals over one standing
    /// roster). `prior_family_digest` is the STANDING envelope digest (C3).
    async fn list_accord_proposals_by_anchor(
        &self,
        action: &str,
        prior_family_digest: &str,
    ) -> Result<Vec<accord_quorum::StoredProposal>, Error>;

    /// v31.1.0 (CIRISPersist#662, PR review P2) — the stored proposals whose
    /// `payload_sha256` equals `payload_sha256`.
    ///
    /// The lookup [`accord_carriage::project_role_withdrawal_for_key`]
    /// resolves a withdrawal candidate with. That path runs inside the
    /// role-admission gates, so an ATTACKER chooses when it runs — by offering
    /// a key that claims `canonical` or `infra:attest`, before the co-scrub
    /// gate has had a chance to reject the row. Resolving it by scanning the
    /// evidence plane would make every such attempt read all of accord history
    /// plus one participation query per proposal: a request-amplification path
    /// on the key write chokepoint that grows with the ceremony log.
    ///
    /// # Cost, per backend, stated exactly
    ///
    /// `sqlite` and `postgres` answer from the V124
    /// `accord_proposal(payload_sha256)` index. The memory backend filters its
    /// proposal map in memory — O(proposals) but with no I/O and no
    /// per-proposal second read, which is the amplification that mattered. The
    /// default implementation filters the evidence cursor and is correct on any
    /// directory, including one whose accord primitives are not routed: it
    /// reads ONLY the cursor and never calls back into `get_accord_proposal`.
    ///
    /// That last property is the reason this returns the verify-core
    /// [`AccordProposal`](ciris_verify_core::accord_live_quorum::AccordProposal)
    /// rather than a `StoredProposal`. The caller needs the digest and nothing
    /// else, and the wider type forced the default to re-read each hit through
    /// a method the FFI capsule surfaces as `Unsupported` — a default that
    /// could not run on the one directory that would ever reach it, behind a
    /// doc comment claiming it was merely slower.
    async fn list_accord_proposals_by_payload(
        &self,
        payload_sha256: &str,
    ) -> Result<Vec<ciris_verify_core::accord_live_quorum::AccordProposal>, Error> {
        Ok(self
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await?
            .into_iter()
            .filter(|b| b.proposal.payload_sha256 == payload_sha256)
            .map(|b| b.proposal)
            .collect())
    }

    /// #302 — admit an `accord_participation`. Verify-before-mutation: the
    /// proposal MUST exist, the member MUST be in `standing_roster` (C3), and
    /// [`AccordParticipation::verify`](ciris_verify_core::accord_live_quorum::AccordParticipation::verify)
    /// MUST pass (fail-closed). M6 durable dedup by PINNED pubkey: a second
    /// participation by the same pinned key for the same proposal is an
    /// idempotent no-op if byte-identical, else [`Error::Conflict`]
    /// (one vote per holder per proposal). C2: persist stamps the
    /// authoritative `server_arrival_at`.
    async fn put_accord_participation(
        &self,
        participation: ciris_verify_core::accord_live_quorum::AccordParticipation,
        standing_roster: &[ciris_verify_core::threshold::ThresholdMember],
    ) -> Result<(), Error>;

    /// #302 — all stored participations for a proposal (the server's tally
    /// input). Deduped by pinned pubkey at write time (M6).
    async fn list_accord_participations(
        &self,
        proposal_digest: &str,
    ) -> Result<Vec<accord_quorum::StoredParticipation>, Error>;

    /// #302 — record the server's frozen-L decision (M2). IMMUTABLE: a
    /// differing re-PUT for the same proposal is [`Error::Conflict`]; an
    /// identical one is an idempotent no-op. `steward_signatures` carries the
    /// |L|<L_FLOOR backstop (H6) when present.
    async fn put_accord_decision(
        &self,
        decision: ciris_verify_core::accord_live_quorum::AccordDecision,
        steward_signatures: Option<serde_json::Value>,
    ) -> Result<(), Error>;

    /// #302 — the stored decision for `proposal_digest`, or `None`.
    async fn get_accord_decision(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<accord_quorum::StoredDecision>, Error>;

    /// #302 (H2) — set the active CONSTITUTIONAL halt for a family (upsert;
    /// at most one active halt per family).
    async fn set_active_halt(&self, family_key_id: &str, active_halt_id: &str)
        -> Result<(), Error>;

    /// #302 (H2) — the active halt for a family, or `None`.
    async fn get_active_halt(
        &self,
        family_key_id: &str,
    ) -> Result<Option<accord_quorum::ActiveHalt>, Error>;

    /// #302 (H2) — clear the active halt iff it matches `active_halt_id` (a
    /// resume un-fires the specific halt). A no-op if a different / no halt is
    /// active, so a replayed resume against a stale halt has no effect.
    async fn clear_active_halt(
        &self,
        family_key_id: &str,
        active_halt_id: &str,
    ) -> Result<(), Error>;

    /// #302 (M4) — record a server-issued proposal nonce (idempotent).
    async fn issue_accord_nonce(&self, family_key_id: &str, nonce: &str) -> Result<(), Error>;

    /// #302 (M4) — has this `(family_key_id, nonce)` been issued? The
    /// fail-closed gate `put_accord_proposal` consults.
    async fn accord_nonce_issued(&self, family_key_id: &str, nonce: &str) -> Result<bool, Error>;
}

/// Federation directory errors. Distinct from
/// [`crate::store::Error`] (which covers trace ingest / lens schema
/// concerns) — federation has its own failure surface for write
/// validation and quota enforcement.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments (empty `key_id`, malformed
    /// pubkey, scrub_key_id doesn't exist, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Scrub-signature on the incoming row did not verify against
    /// the scrub_key_id's pubkey. Indicates either tampering or a
    /// caller bug. Persist does not store the row.
    #[error("scrub-signature verification failed: {0}")]
    SignatureInvalid(String),

    /// A write quota refused this row. `reason` names WHICH budget —
    /// per-peer, per-node, reserved-family, or the untracked tail — and in
    /// which regime (burst vs sustained); see [`PeerQuotaRefusal`].
    ///
    /// v24.3.0 (CIRISPersist#575) — the reason reaches the WIRE, not just the
    /// quota's own API. A bare `federation_rate_limited` sends an operator
    /// looking for the wrong control at exactly the moment they need the right
    /// one; that is the gap #565 closed for key refusals, and this closes it
    /// for rate limits. Consumers key on [`PeerQuotaRefusal::as_str`] — a
    /// program constant, never this message text.
    #[error("rate limited ({reason}): retry after {retry_after_seconds}s")]
    RateLimited {
        /// Seconds the caller should wait before retrying.
        retry_after_seconds: u64,
        /// WHICH quota refused, and in which regime.
        reason: PeerQuotaRefusal,
    },

    /// v25.1.0 (CIRISPersist#569) — **CONSENT BEFORE SCORING** refused this
    /// row: a federation-tier trust signal about a subject who has granted the
    /// attester no live [`admission::ANALYZE_CONSENT_SCOPE`] consent.
    ///
    /// The payload names WHICH rule ([`admission::ConsentGatedFamily`]), the
    /// dimension verbatim, both parties, and the stance the fold actually
    /// resolved — so a consumer branches on a program constant and reads the
    /// rest as data, never string-matching the message. Before #569 this
    /// refusal was a bare [`Error::InvalidArgument`], indistinguishable on the
    /// wire from every other argument complaint.
    #[error("{0}")]
    ConsentGateRefused(admission::ConsentGateRefused),

    /// Row would conflict with an existing row whose content differs.
    /// Idempotent re-submission of the *same* content is OK; this
    /// fires only when the caller is overwriting.
    #[error("conflicts with existing row: {0}")]
    Conflict(String),

    /// v25.1.0 (CIRISPersist#570 ask 3) — a
    /// [`hard_case::kind::ADMIN_ACTION`] record did not carry the authority
    /// it was taken under. An admin action that does not carry its own
    /// authority is indistinguishable from an unauthorized one once the actor
    /// is gone; `reason` names WHICH half of the attribution is missing so an
    /// operator fixes the emitter rather than guessing. Consumers key on
    /// [`AdminActionRefusal::as_str`] — a program constant, never this text.
    #[error("admin_action hard_case refused ({reason}): unattributed")]
    AdminActionUnattributed {
        /// WHICH branch refused.
        reason: AdminActionRefusal,
    },

    /// v25.1.0 (CIRISPersist#570 ask 4) — a revocation's history bound
    /// ([`Revocation::revoked_after`]) failed admission: it is not mirrored in
    /// the SIGNED envelope, the two disagree, it does not parse, or it is
    /// later than `effective_at`. The bound is the one field on the revocation
    /// plane that makes part of a revoked key's corpus keep standing, so an
    /// unsigned or incoherent one is refused rather than stored. Consumers key
    /// on [`RevocationBoundRefusal::as_str`].
    #[error("revocation history bound refused ({reason})")]
    RevocationBoundInvalid {
        /// WHICH branch refused.
        reason: RevocationBoundRefusal,
    },

    /// v31.0.0 (CIRISPersist#659) — a [`Revocation`] carries a typed column
    /// that its scrub signature does not cover and that disagrees with the
    /// `revocation_envelope` it claims to project.
    ///
    /// The de-conferral plane is **producer envelope + typed projection**, the
    /// same shape as the three operational planes
    /// ([`Error::OperationalEnvelopeUnbound`]): the hybrid signature covers
    /// `revocation_envelope` and nothing else, while WHICH KEY IS REVOKED,
    /// WHO revoked it, WHICH ROW this is and WHEN it takes effect were all
    /// plain caller-supplied columns. One validly-signed revocation could
    /// therefore be re-pasted at an arbitrary `revoked_key_id` and an
    /// arbitrary `revocation_id`, unboundedly often, with the producer's own
    /// signature still verifying — an unbounded de-conferral primitive off a
    /// single conferral.
    ///
    /// Fail-closed, and no legacy regime: an unbound revocation is REFUSED,
    /// never stored-and-flagged. See
    /// [`admission::check_revocation_envelope_binding`].
    #[error(
        "revocation {revocation_id:?}: typed column `{field}` is not bound to the signed \
         `revocation_envelope` — {detail}. The scrub signature covers that envelope only, so an \
         unbound column is authored by whoever relayed the row, not by whoever signed it — and \
         `revoked_key_id` unbound means one signed revocation de-admits ANY key it is pasted \
         onto (CIRISPersist#659)"
    )]
    RevocationEnvelopeUnbound {
        /// The rejected row's `revocation_id`.
        revocation_id: String,
        /// The typed column that diverged.
        field: &'static str,
        /// How it diverged (column value vs signed value, or absence).
        detail: String,
    },

    /// v17.9.0 (CIRISConstitution#38 interim) — the attestation envelope's
    /// canonical (JCS) bytes exceed
    /// [`admission::MAX_ATTESTATION_ENVELOPE_BYTES`]. The CEG had NO size
    /// bound at any layer (the 8 MiB HTTP body cap doesn't cover capsule/FFI
    /// writes), so an unchecked write could park a multi-hundred-MB row on
    /// the replication plane. Payloads above the cap belong on the degradable
    /// plane (fountain-content, envelope-carries-manifest). The cap value is
    /// persist's conservative interim; re-pinned when CC#38 ratifies.
    #[error("attestation envelope too large: {bytes} bytes > {cap} cap")]
    EnvelopeTooLarge {
        /// Canonical-bytes size of the submitted envelope.
        bytes: usize,
        /// The admission cap it exceeded.
        cap: usize,
    },

    /// v18.1.0 (CIRISPersist#473 followup) — a `trace:*`-dimension
    /// attestation failed the Information-Type validator: the dimension is
    /// the CEG's machine-checkable type parameter, so a `trace:*` row that
    /// admits MUST be self-emitted (attester ∈ subjects — a trace records
    /// its own producer's reasoning) and MUST parse as exactly one of the
    /// ratification-tracked shapes (inline trace / `trace_manifest:v1`).
    /// Admission validates SHAPE; the in-envelope producer signature
    /// carries provenance (verified at promotion/read).
    #[error("trace:* dimension admission refused: {detail}")]
    TraceDimensionInvalid {
        /// What failed (self-emission / missing field / bad manifest …).
        detail: String,
    },

    /// v19.0.0 (CIRISPersist#488, CRITICAL — the KERI lesson) — a root
    /// charter (`delegates_to(root → root, infra:*)`) failed the recovery
    /// admission gate: missing/malformed pre-rotation commitment, or a
    /// recovery declaration that does not bind to the predecessor's
    /// pre-committed successor key set. A charter without pre-committed
    /// recovery makes root-key compromise unrecoverable by construction.
    #[error("root charter admission refused: {detail}")]
    CharterInvalid {
        /// What failed (commitment shape / membership / binding).
        detail: String,
    },

    /// v19.1.0 (CIRISPersist#490) — an assembled genesis bundle failed
    /// verification or bake admission: unparseable artifact, quorum not
    /// met against THIS node's roster, a non-seated/unresolvable holder,
    /// an authorization signature that does not verify against the
    /// directory-pinned keys, an identity-changing re-anchor, or a
    /// rollback (bundle record not newer than the anchored one).
    #[error("genesis bundle refused: {detail}")]
    GenesisBundleInvalid {
        /// What failed.
        detail: String,
    },

    /// v31.0.0 (CIRISPersist#648) — **the pre-genesis refusal.** The operation
    /// resolves authority to the constitutional trust root, and this node does
    /// not hold one: the accord-holder roster and/or the keyless
    /// `humanity-accord` family row are not installed.
    ///
    /// This is the typed answer to *"a node with no root must not become a node
    /// that checks nothing"*. 31.0.0 is the binary that RUNS the genesis
    /// ceremony, so it boots pre-genesis on purpose — and every gate in
    /// [`genesis::ROOT_REQUIRING_GATES`](crate::federation::genesis::ROOT_REQUIRING_GATES)
    /// returns this rather than tallying a quorum against an empty roster and
    /// discovering that nothing to check reads like nothing to refuse. That
    /// inversion is the #632 defect and it is the one most likely to be
    /// reintroduced here.
    ///
    /// The remedy is a ceremony, not a signature, and the message says so —
    /// `accord family m-of-n not met (1-of-0)` would send an operator hunting
    /// for a holder who was never going to answer.
    #[error(
        "no constitutional trust root yet: {operation} resolves authority to the accord root, \
         which this node does not hold ({fault_kind} {leg} leg: {detail}). Run the genesis \
         ceremony (or bake a seed) before this operation."
    )]
    NoConstitutionalRootYet {
        /// WHICH gate refused — a token from
        /// [`ROOT_REQUIRING_GATES`](crate::federation::genesis::ROOT_REQUIRING_GATES).
        operation: &'static str,
        /// Which constitutional leg is missing — roster or threshold.
        leg: genesis::GenesisLeg,
        /// `absent` / `divergent` / `unreadable` — the
        /// [`GenesisFault`](crate::federation::genesis::GenesisFault) class.
        fault_kind: &'static str,
        /// The specific finding.
        detail: String,
    },

    /// v31.0.0 (CIRISPersist#648) — **the constitutional family id is
    /// reserved.** A `federation_families` write named
    /// [`HUMANITY_ACCORD_FAMILY_KEY_ID`](ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID)
    /// through an ordinary admission door.
    ///
    /// Before #648 this was defended by an accident of ordering: the seed was
    /// unconditional, so the primary key was always already occupied by the
    /// time any peer could write, and `put_family` refuses a collision with
    /// different content. Allowing boot without a seed removes that accident
    /// and opens the sharpest hole in the whole issue — a registered peer
    /// declares a `humanity-accord` family with itself as the sole seat and
    /// `founder_only` as the protocol, `family_charter_threshold` resolves to
    /// 1, and one signature charters the constitutional root.
    ///
    /// So the reservation is now stated. The name enters this node's directory
    /// through the genesis seeder / the assemble ceremony
    /// ([`put_family_local`](FederationDirectory::put_family_local)) and
    /// through nothing else — which is also the property that keeps a second
    /// assemble from becoming a replacement.
    #[error(
        "family_key_id {family_key_id:?} is the constitutional accord family and is reserved: \
         it is established by the genesis ceremony, never by a peer declaration \
         (attesting key {attesting_key_id:?})"
    )]
    ConstitutionalFamilyReserved {
        /// The reserved id the caller tried to claim.
        family_key_id: String,
        /// Who tried.
        attesting_key_id: String,
    },

    /// v31.0.0 (CIRISPersist#660) — **a baked genesis delegation id is
    /// reserved.** An attestation write claimed `genesis-charter` /
    /// `genesis-grant:…` / `genesis-lifecycle` with content that is not the
    /// baked ceremony row.
    ///
    /// The attestation-plane twin of [`Self::ConstitutionalFamilyReserved`],
    /// and the same finding: nothing reserved these ids, so one ordinary
    /// `scores` row from any registered key could take the primary key the
    /// ceremony needs. On the family plane the consequence was a 1-of-1
    /// charter; here it was worse in one specific way — the squat also flipped
    /// [`genesis_posture`](genesis::genesis_posture) to
    /// [`Divergent`](genesis::GenesisPosture::Divergent), which
    /// [`refuses_boot`](genesis::GenesisFault::refuses_boot), so a peer could
    /// deny a node its boot AND make the denial permanent by holding the key.
    ///
    /// The rule is stated as AUTHORSHIP — federation-tier, attested by a seated
    /// accord holder — rather than as a door, because unlike the family plane
    /// the delegation plane has no second door: the ceremony, the host's boot
    /// write and a peer's replication all arrive at `put_attestation`. See
    /// [`check_genesis_attestation_reserved`](genesis::check_genesis_attestation_reserved),
    /// including why pinning the baked CONTENT instead would have refused the
    /// re-ceremony these ids exist for.
    #[error(
        "attestation_id {attestation_id:?} is a baked genesis delegation row and is reserved: \
         it is installed by the genesis ceremony, never by an ordinary write — this one's \
         {field} {detail} (attesting key {attesting_key_id:?})"
    )]
    GenesisAttestationReserved {
        /// The reserved id the caller tried to claim.
        attestation_id: String,
        /// Who tried.
        attesting_key_id: String,
        /// The first field that diverged from the baked row.
        field: String,
        /// What diverged, for an operator.
        detail: String,
    },

    /// v2.4.0 (CIRISPersist#102 Ask 3a). The submitted `scores`
    /// attestation's `dimension` begins with `accord:` but the
    /// `attesting_key_id`'s `identity_type` is not `accord_holder`.
    /// The federation's one constitutional asymmetry per FSD-002
    /// §4.1 + §7.1; the admission gate refused the write.
    #[error(
        "accord:* dimensions require identity_type=accord_holder \
         (got dimension={dimension:?}, attesting identity_type={identity_type:?})"
    )]
    AccordDimensionRequiresAccordHolder {
        /// The `dimension` from the attestation envelope that
        /// triggered the rejection.
        dimension: String,
        /// The attesting key's `identity_type` as resolved at
        /// admission time.
        identity_type: String,
    },

    /// v37.0.0 (CIRISPersist#733). The row is on the `accord:*` family but its
    /// SIGNED envelope carries no
    /// [`accord_root`](envelope::paths::ACCORD_ROOT), so nothing on it says
    /// WHICH accord it belongs to and a relaying node cannot resolve the
    /// roster it would have to judge the signer against. Stable `kind()` token
    /// `federation_accord_root_unnamed`.
    ///
    /// Raised by [`trust_root::check_accord_root_binding`] at the
    /// [`admission::check_reserved_prefix_admission`] chokepoint. The one
    /// exemption is the drill dimension
    /// [`trust_root::ACCORD_HEARTBEAT_DIMENSION`] — see that gate.
    #[error(
        "attestation {attestation_id:?} is on the accord:* family ({namespace:?}) but its \
         signed envelope carries no `{key}`: nothing on the row says WHICH accord it belongs \
         to, so a node relaying it cannot resolve the roster that would authorize the signer, \
         and refuses. `attested_key_id` is not a substitute — it names the scored agent, the \
         self-attesting holder or the accord depending on dimension. Stamp `{key}` (the \
         accord's root ref) into the envelope BEFORE signing (CIRISPersist#733)"
    )]
    AccordRootUnnamed {
        /// The row that named no accord.
        attestation_id: String,
        /// Which namespace put it on the family — the `attestation_type` or
        /// the envelope `dimension`, whichever began with `accord:`.
        namespace: String,
        /// The envelope key that was missing, spelled once
        /// ([`envelope::paths::ACCORD_ROOT`]).
        key: &'static str,
    },

    /// v37.0.0 (CIRISPersist#733). An
    /// [`ACCORD_HEARTBEAT_DIMENSION`](trust_root::ACCORD_HEARTBEAT_DIMENSION)
    /// row carries BOTH root signals — the explicit
    /// [`accord_root`](envelope::paths::ACCORD_ROOT) key AND the standing rule
    /// that `attested_key_id` is the accord on that dimension — and they name
    /// DIFFERENT accords. Stable `kind()` token
    /// `federation_accord_root_disagrees`.
    ///
    /// Refused rather than resolved either way. Preferring the key lets an
    /// emitter relabel a heartbeat's accord; preferring the column makes the
    /// key decorative on the one dimension where a rule already exists. One
    /// artifact asserting two roots is malformed whichever a reader would have
    /// picked — the same ruling
    /// [`namespace::supersets`]'s `every_pointer_read_is_discriminator_guarded`
    /// applies to the composer pointer.
    #[error(
        "attestation {attestation_id:?} names TWO accords: its signed envelope `{key}` says \
         {envelope_root:?}, while the {dimension} rule reads the accord from `attested_key_id` \
         = {attested_key_id:?}. A row asserting two roots is malformed whichever one a reader \
         would have preferred, so it is REFUSED rather than resolved silently — re-mint with \
         the two agreeing (CIRISPersist#733)"
    )]
    AccordRootDisagrees {
        /// The row that named two accords.
        attestation_id: String,
        /// The root the signed envelope key named.
        envelope_root: String,
        /// The root the drill-dimension rule reads off the row.
        attested_key_id: String,
        /// The drill dimension whose rule supplied the second signal.
        dimension: &'static str,
        /// The envelope key that supplied the first, spelled once.
        key: &'static str,
    },

    /// v37.0.0 (CIRISPersist#734). A [`SignedLocationProof`] was REFUSED
    /// because its `authority_key_id` is neither the subject itself nor a
    /// LIVE delegate of the subject. Location is self-knowledge: a third
    /// party has no source for where a subject is, so their valid signature
    /// proves only that they signed it. E4 closed "no signature at all";
    /// this closes "which identity may assert a location for this subject".
    /// The admissible set is exactly `{subject} ∪ {live delegates of subject}`.
    /// The row is not stored (verify-before-mutation, AV-9). Stable `kind()`
    /// token `federation_location_authority_unauthorized`.
    ///
    /// `rule` names WHICH clause refused, and the distinction is
    /// operationally load-bearing: `location_authority_no_delegation_edge`
    /// may be an out-of-order replication artifact (the `delegates_to` has
    /// not arrived yet) and is safe to RETRY; the retracted/expired tokens
    /// are substantive verdicts that retrying will not change. See
    /// [`tier_ingest::LOCATION_AUTHORITY_RULE_NO_DELEGATION_EDGE`].
    #[error(
        "location proof for subject {subject_key_id:?} offers authority \
         {offered_authority_key_id:?}, which is neither the subject itself nor a live \
         delegates_to delegate of it ({rule}): location is SELF-KNOWLEDGE, so a third \
         party's valid signature proves only that they signed it, never where the \
         subject is. Admissible authority is exactly the subject plus its live \
         delegates (CIRISPersist#734)"
    )]
    LocationAuthorityUnauthorized {
        /// `location_proof.subject_key_id` — whose location was asserted.
        subject_key_id: String,
        /// The `authority_key_id` offered on the wrapper, whose signature
        /// DID verify against its registered pubkeys. The refusal is about
        /// standing, never about the signature.
        offered_authority_key_id: String,
        /// Which clause refused; one of the `tier_ingest::LOCATION_AUTHORITY_RULE_*`
        /// tokens. `..._no_delegation_edge` is the retryable one.
        rule: &'static str,
    },

    /// v2.4.0 (CIRISPersist#102 Ask 3b). The submitted `scores`
    /// attestation's `dimension` failed one of the four
    /// operational-language tests (FSD-002 §1.10.1): rules/verdicts
    /// separation (T1), mechanism-descriptive-not-judgment naming
    /// (T2), version-pinning (T3), adjudication separation (T4).
    /// See [`admission::DimensionAdmissionPolicy`] for the policy
    /// shape and `docs/FEDERATION_DIRECTORY.md` for the rationale.
    #[error("dimension rejected by admission policy: {reason} (dimension={dimension:?})")]
    DimensionRejected {
        /// The `dimension` value that failed the gate.
        dimension: String,
        /// Stable machine-readable reason token (matches one of
        /// [`admission::DimensionRejectionReason`]'s `as_str()`).
        reason: &'static str,
    },

    /// v37.0.0. The submitted `scores` attestation's `dimension` is spelled in
    /// the **removed** CEG 0.1 attestation-ladder wire shape
    /// `attestation:l{N}:{mechanism}`.
    ///
    /// CEG 0.2 §13.1 deprecated that shape in favour of the mechanism-only
    /// form `attestation:{mechanism}`. Persist admitted both from v3.0.0
    /// under an `AttestationLadderTransitionPolicy::DualAccept` default whose
    /// documented flip condition ("post-CEG 0.3") passed five CEG versions
    /// ago; v37.0.0 removed the policy, the knob and the deprecated shape
    /// together.
    ///
    /// # Why its own variant rather than a `DimensionRejected` reason
    ///
    /// Without this arm the removed shape falls through to the
    /// version-segment gate and refuses as `missing_version_segment` — an
    /// instruction to add a `:v[0-9]+` that would NOT make the row
    /// admissible, because the canonical ladder form carries no version
    /// segment either. The producer's defect is the wire shape, so the
    /// refusal carries the shape it received AND the admissible set, which a
    /// bare reason token has no room for.
    #[error(
        "removed attestation-ladder wire shape {dimension:?}: the CEG 0.1 form \
         `attestation:l<N>:<mechanism>` was deprecated by CEG 0.2 §13.1 and REMOVED at \
         persist v37.0.0 — the dual-accept transition window is closed. Emit the canonical \
         mechanism form `attestation:<mechanism>` instead; admissible set: {canonical:?}"
    )]
    DeprecatedAttestationLadderForm {
        /// The `dimension` value from the attestation envelope, as received.
        dimension: String,
        /// The canonical mechanism-only vocabulary the producer must emit
        /// instead — [`admission::ATTESTATION_LADDER_MECHANISMS`].
        canonical: &'static [&'static str],
    },

    /// v3.0.0 (CIRISPersist#116, CEG 0.2 §7.0). The submitted
    /// `scores` attestation's `dimension` matches a reserved-prefix
    /// pattern (`system:*`, `audit_chain:*`, `transparency_log:cosigned:*`,
    /// `capacity:*` self-emission, …) but the `attesting_key_id`'s
    /// `identity_type` does not satisfy the emitter rule for that
    /// prefix. Rejected at admission; the row is not stored. See
    /// [`admission::ReservedPrefixRule`] for the per-prefix rule
    /// shape and [`admission::DimensionAdmissionPolicy::reserved_prefix_rules`]
    /// for the default policy contents.
    #[error(
        "reserved-prefix emitter mismatch: dimension {dimension:?} requires \
         identity_type ∈ {required:?} but got identity_type={got_identity_type:?}"
    )]
    ReservedPrefixEmitterMismatch {
        /// The `dimension` value from the attestation envelope.
        dimension: String,
        /// The reserved prefix pattern that matched.
        prefix: String,
        /// Identity-type vocabulary the prefix accepts (sorted for
        /// deterministic error output).
        required: Vec<String>,
        /// The submitting key's resolved `identity_type`.
        got_identity_type: String,
    },

    /// (CIRISPersist#590, **CC 3.1.7 R2(b)**). Emission was observed on
    /// a namespace family persist itself **governs** — one it gates
    /// ([`admission::default_reserved_prefix_rules`] and the hard-coded reserved
    /// arms) or one it **mints**
    /// ([`admission::MINTED_NAMESPACE_FAMILIES`]) — that carries **no row** in
    /// the vendored `namespace_registry.json`.
    ///
    /// R2(b): *"a substrate observing emission on a family with no registry row
    /// (provisional or ratified) MUST surface it as a conformance failure
    /// (`namespace_family_unregistered`), never admit-and-wait."* Admitting
    /// would file the row under the `ProducerSteward` fallback — an authority
    /// nobody chose for it — silently and cumulatively.
    ///
    /// The refusal is deliberately **stem-granular and scoped to governed
    /// families**: the open-vocabulary space CC leaves open (`{param}` slots
    /// inside a registered family, and families this Part never speaks to) is
    /// untouched, because refusing it is the "reject conformant traffic and
    /// blame the producer" failure CIRISPersist#590 was opened to prevent.
    #[error(
        "namespace family unregistered (CC 3.1.7 R2(b)): {namespace:?} is emitted on family \
         {family_stem:?}, which persist governs but the vendored CC namespace registry does not \
         register — admitting it would file it under the ProducerSteward fallback, an authority \
         nobody chose for it"
    )]
    NamespaceFamilyUnregistered {
        /// The `attestation_type` or envelope `dimension` that was refused.
        namespace: String,
        /// Its family stem (up to and including the first `:`) — the
        /// granularity CC 3.1.7 R2 registers at.
        family_stem: String,
        /// Stable machine-readable reason token — CC's own R2(b) spelling, via
        /// [`admission::NamespaceConformanceReason::as_str`].
        reason: &'static str,
    },

    /// (CIRISPersist#571, **CC 3.1.7 R2 Private Use**). A row on the
    /// `x_private:{anything}` range was offered at **federation tier**.
    ///
    /// CC: *"One family prefix is reserved for Private Use (`x_private:{anything}`)
    /// and carries no registry row: private-use families MUST NOT admit at
    /// federation tier under any authority and MUST NOT be promoted to a
    /// registered family without minting a fresh name — the legitimate
    /// unregistered range whose absence is what mints `X-`-convention squatting
    /// (RFC 6648's lesson)."*
    ///
    /// **This is the one refusal in the R2 family that is a TIER rule, not a
    /// registration rule.** R2(b) refuses a governed family that nobody
    /// registered; this refuses a family that is *legitimately* unregistered
    /// and always will be. Sharing R2(b)'s error would have said the opposite
    /// of what CC means about Private Use — the range is valid, its reach is
    /// not — so it names its own branch
    /// ([`admission::NamespaceConformanceReason::PrivateUseNotFederatable`]).
    ///
    /// **"Under any authority"** is why no identity, role, or co-scrub appears
    /// in this check: there is nothing a signer can be that buys a private-use
    /// row a federation tier. Local tier is untouched — refusing there would
    /// delete the legitimate range CC created, which is the squatting failure
    /// the clause exists to prevent.
    #[error(
        "namespace private use is not federatable (CC 3.1.7 R2): {namespace:?} is on the \
         reserved Private Use range {family_stem:?}, which MUST NOT admit at federation tier \
         under any authority — keep it local, or mint a fresh registered name (a private-use \
         family is never promoted into a registered one)"
    )]
    NamespacePrivateUseNotFederatable {
        /// The `attestation_type` or envelope `dimension` that was refused.
        namespace: String,
        /// The Private Use stem it sits on
        /// ([`admission::PRIVATE_USE_FAMILY_STEM`]).
        family_stem: &'static str,
        /// Stable machine-readable reason token, via
        /// [`admission::NamespaceConformanceReason::as_str`].
        reason: &'static str,
    },

    /// v10.3.0 (CIRISPersist#288, CC 3.4.5). A `capacity:*` attestation
    /// was self-emitted (`attesting_key_id == attested_key_id`). The
    /// Constitution's "Critical enforcement" rule: a `capacity:*` score
    /// MUST NOT be self-emitted — the agent's own capacity score is never
    /// fed back into the agent's own context (anti-Goodhart). Rejected at
    /// admission; the row is not stored. Unlike the identity-type prefix
    /// rules, this is an attester==attested check, not an identity check.
    #[error(
        "capacity:* self-emission rejected: attesting_key_id == attested_key_id ({key_id:?}) — \
         a capacity score must not be self-emitted (CC 3.4.5; attestation_type={attestation_type:?})"
    )]
    CapacitySelfEmissionRejected {
        /// The key that attempted to self-emit a `capacity:*` attestation.
        key_id: String,
        /// The `attestation_type` that triggered the rejection.
        attestation_type: String,
    },

    /// v13.0.0 (CIRISPersist#368, CC 3.4.11). An `age_assurance:*`
    /// attestation was self-emitted (`attesting_key_id ==
    /// attested_key_id`). The witness rung is an attestation ABOUT a
    /// subject: CC 3.4.11 — "A subject MUST NOT emit on `age_assurance:`;
    /// … a CCS MUST reject … at admission". Without this check a key that
    /// happens to carry the `witness` identity_type could graduate ITSELF
    /// to `adult` — the self-minted adulthood the witness reservation
    /// exists to prevent. Rejected at admission; the row is not stored.
    /// The exact sibling of [`Error::CapacitySelfEmissionRejected`]
    /// (CC 3.4.12's identical subject-must-not-emit rule for
    /// `capacity_assurance:*`); like it, an attester==attested check
    /// independent of `identity_type`.
    #[error(
        "age_assurance:* self-emission rejected: attesting_key_id == attested_key_id \
         ({key_id:?}) — a subject must not emit its own age assurance (CC 3.4.11; \
         attestation_type={attestation_type:?})"
    )]
    AgeAssuranceSelfEmissionRejected {
        /// The key that attempted to self-emit an `age_assurance:*` row.
        key_id: String,
        /// The `attestation_type` that triggered the rejection.
        attestation_type: String,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 4). The submitted `scores`
    /// attestation's `attestation_envelope` failed JSON Schema
    /// validation against the per-axis schema registered for the
    /// dimension's axis (FSD-002 §4.9.1 operational-definition
    /// "evidence-shape requirement"). The schema's `evidence_refs`
    /// requirement (the schema SHA must appear in the envelope's
    /// `evidence_refs[]`) is part of the schema document, not
    /// separately enforced — JSON Schema does that work.
    #[error(
        "envelope schema violation for dimension {dimension:?} (axis={axis:?}): \
         {} violation(s)", violations.len()
    )]
    EnvelopeSchemaViolation {
        /// The `dimension` value from the attestation envelope.
        dimension: String,
        /// The axis derived from `dimension` (per
        /// [`axis_from_dimension`]).
        axis: String,
        /// Human-readable violation strings, one per JSON Schema
        /// failure. Order matches `jsonschema::iter_errors`.
        violations: Vec<String>,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `federation_keys` row has `identity_type = 'accord_holder'`
    /// but no `attestation_evidence` field, or the field is null /
    /// fails to deserialize. Per FSD-002 §7.3, accord-holder keys
    /// MUST live on hardware substrate; the admission hook reads
    /// `attestation_evidence` to confirm. Defense-in-depth:
    /// V048 CHECK constraint catches the same shape if a row
    /// bypasses the admission hook (e.g., direct SQL).
    #[error(
        "accord_holder row requires non-null attestation_evidence \
         (key_id={key_id:?}): {detail}"
    )]
    AccordHolderRequiresAttestationEvidence {
        /// The `key_id` of the rejected row.
        key_id: String,
        /// Detail: "missing", "null", "malformed: <serde err>", etc.
        detail: String,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `attestation_evidence` carries a `hardware_type` that
    /// [`HardwareAttestationPolicy`] does not accept for accord-
    /// holder identity. The default policy refuses
    /// `HardwareType::SoftwareOnly` — Verify's one structural floor
    /// (`supports_professional_license() == false`); operator
    /// policies may tighten further.
    #[error(
        "accord_holder hardware_type {got:?} not accepted by policy \
         (accepted={accepted:?})"
    )]
    HardwareTypeNotAccepted {
        /// The submitted hardware_type variant name (e.g.
        /// `"SoftwareOnly"`, `"AndroidStrongbox"`).
        got: String,
        /// The policy's accepted set, serialized for the error
        /// message. Sorted for deterministic output.
        accepted: Vec<String>,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `PlatformAttestation` variant matches the
    /// [`HardwareAttestationPolicy`] but is structurally
    /// incomplete — missing one of the variant's required fields
    /// (e.g. Android without `key_attestation_chain`; TPM without
    /// `pcr_values`). Persist does NOT do active chain validation
    /// here (that's CIRISVerify#32 Ask 5); only structural
    /// field-presence checks locally.
    #[error(
        "accord_holder attestation_evidence incomplete \
         (hardware_type={hardware_type:?}, missing={missing_fields:?})"
    )]
    AttestationEvidenceIncomplete {
        /// The hardware type variant from the submitted evidence.
        hardware_type: String,
        /// The list of required-but-missing field names. Stable
        /// vocabulary; tests pin specific names.
        missing_fields: Vec<String>,
    },

    /// v2.5.0 (CIRISPersist#102 Ask 8). The submitted
    /// `attestation_evidence` carries a `nonce_captured_at`
    /// timestamp older than [`HardwareAttestationPolicy::max_nonce_age`].
    /// Defeats replay of an old attestation against a new key-
    /// binding event.
    #[error(
        "accord_holder attestation_evidence stale \
         (captured_at={captured_at}, max_age={max_age_secs}s)"
    )]
    AttestationEvidenceStale {
        /// RFC3339 timestamp of the captured nonce.
        captured_at: chrono::DateTime<chrono::Utc>,
        /// Max age in seconds (`HardwareAttestationPolicy::max_nonce_age`).
        max_age_secs: u64,
    },

    /// v3.1.0 (CIRISPersist#117). The peer-mutation surface was
    /// called with a `key_id` that has no row in
    /// `federation_peer_metadata`. Distinct from
    /// [`Error::InvalidArgument`] so consumers can deterministically
    /// pattern-match the "you addressed an unknown peer" outcome.
    #[error("peer record not found for key_id={key_id}")]
    PeerNotFound {
        /// The `key_id` the caller addressed.
        key_id: String,
    },

    /// v3.1.0 (CIRISPersist#117). [`FederationDirectory::remove_peer_record`]
    /// was called with `hard = true` against a peer that still has
    /// `federation_attestations` rows attesting to / from / scrubbed-by
    /// the key. A hard remove would orphan those attestations'
    /// `attestation_envelope` (the federation_keys row they reference
    /// would disappear). The caller MUST either soft-remove (preserve
    /// the audit trail) OR explicitly revoke the key first.
    #[error(
        "hard remove of peer with active attestations rejected — \
         use soft remove or revoke the key first; key_id={key_id}, \
         attestation_count={attestation_count}"
    )]
    HardRemoveWithActiveAttestations {
        /// The `key_id` the caller tried to hard-remove.
        key_id: String,
        /// The count of attestations that would have been orphaned.
        attestation_count: usize,
    },

    /// v3.4.0 (CIRISPersist#123) — the
    /// [`AdmissionGate`](crate::federation::AdmissionGate) rejected the
    /// write: the attesting key's aggregate trust score is below the
    /// deployment's `trust_threshold`. The row was NOT written.
    /// Distinct from [`Error::InvalidArgument`] so consumers can
    /// match the trust-rejection deterministically without parsing
    /// the error string. The trust gate runs BEFORE FK validation,
    /// envelope-schema validation, and signature verification — by
    /// design, an unauthorized writer should not learn whether the
    /// downstream checks would have succeeded.
    #[error("trust score {score} for key_id={key_id} is below threshold {threshold}")]
    TrustBelowThreshold {
        /// The attesting key the gate evaluated.
        key_id: String,
        /// The aggregate score returned by the resolver.
        score: f64,
        /// The configured threshold.
        threshold: f64,
    },

    /// v3.9.1 (CIRISPersist#150 Ask 3, CEG 0.4 §4.2.4). The submitted
    /// attestation's `cohort_scope` is outside the closed set
    /// `{self, family, community, affiliations, species, biosphere,
    /// federation}` — most commonly `global`, which is a §8.1.8
    /// feed-name (`{species, biosphere, federation}` aggregate), not a
    /// wire value. Rejected at admission by
    /// [`admission::check_cohort_scope`]; the row is not stored.
    /// Distinct from [`Error::InvalidArgument`] so consumers can
    /// pattern-match the cohort_scope rejection deterministically. The
    /// V056 `CHECK (cohort_scope IN (...))` constraint is the
    /// defense-in-depth backstop for rows that bypass this hook.
    #[error(
        "cohort_scope {cohort_scope:?} is not in the closed set \
         {{self, family, community, affiliations, species, biosphere, federation}}"
    )]
    CohortScopeRejected {
        /// The rejected `cohort_scope` value as submitted.
        cohort_scope: String,
    },

    /// v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2 R1). The submitted revocation's `observed_region` is
    /// outside the closed set `{us, eu, apac}`. Rejected at admission
    /// by [`admission::check_observed_region`]; the row is not stored.
    /// Distinct from [`Error::InvalidArgument`] so consumers can
    /// pattern-match the region-closed-set rejection deterministically.
    #[error("observed_region {observed_region:?} is not in the closed set {{us, eu, apac}}")]
    RegionRejected {
        /// The rejected `observed_region` value as submitted.
        observed_region: String,
    },

    /// v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2 Q1, F-AV-ROLLBACK closure). The submitted revocation's
    /// `signed_timestamp` is **not strictly later than** the most-
    /// recent existing revocation for the same `revoked_key_id`. The
    /// spec's anti-rollback contract is enforced **at admission**,
    /// before quorum is asked — a sufficient minority of regions
    /// cannot ratify a rollback because the rollback never enters the
    /// quorum gate.
    ///
    /// `existing_signed_timestamp` is the latest already-stored
    /// timestamp the gate compared against; `submitted_signed_timestamp`
    /// is the rejected row's. Equal timestamps reject too (strictly
    /// greater is required).
    #[error(
        "anti-rollback: revocation for {revoked_key_id:?} signed_timestamp \
         {submitted_signed_timestamp} is not strictly later than existing \
         {existing_signed_timestamp}"
    )]
    RevocationRollback {
        /// The `revoked_key_id` the new revocation targets.
        revoked_key_id: String,
        /// The latest signed_timestamp already on file for this target.
        existing_signed_timestamp: chrono::DateTime<chrono::Utc>,
        /// The submitted (rejected) signed_timestamp.
        submitted_signed_timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// v31.0.0 (CIRISPersist#659) — **the anti-rollback CEILING**: the
    /// submitted revocation's `scrub_timestamp` is further in the future than
    /// this node will accept.
    ///
    /// [`Error::RevocationRollback`] is the FLOOR, and on its own it makes
    /// `scrub_timestamp` a monotonic latch on a key's entire de-admission
    /// history with no upper bound. Self-revocation needs no conferral
    /// ([`admission::check_revocation_authority`] — a compromised key must be
    /// retirable by its holder), so one self-signed revocation dated at the
    /// year 9999 made its own subject **immune to every later de-admission**,
    /// a slash-conferred moderator's included. Binding `scrub_timestamp` into
    /// the signed envelope (#659) closes the relay variant and cannot close
    /// this one, because the attacker signs its own row. A latch needs a
    /// ceiling as well as a floor.
    ///
    /// A DISTINCT variant rather than a second meaning for the floor's: the
    /// floor's message says *"not strictly later than existing …"*, and
    /// reporting a ceiling through it would tell an operator the one thing
    /// that is not true — there is no existing revocation at that instant.
    /// See [`admission::check_revocation_scrub_skew`].
    #[error(
        "anti-rollback ceiling: revocation for {revoked_key_id:?} scrub_timestamp \
         {submitted_signed_timestamp} is {ahead_seconds}s ahead of this node's clock, beyond \
         the {tolerance_seconds}s tolerance. The scrub instant is a MONOTONIC LATCH per \
         revoked_key_id, so a future-dated one blocks every later de-admission of this key \
         (CIRISPersist#659)"
    )]
    RevocationScrubSkew {
        /// The `revoked_key_id` the new revocation targets.
        revoked_key_id: String,
        /// The submitted (rejected) `scrub_timestamp`.
        submitted_signed_timestamp: chrono::DateTime<chrono::Utc>,
        /// How far ahead of this node's clock it sits.
        ahead_seconds: i64,
        /// The tolerance it exceeded ([`admission::DEFAULT_MAX_TOUCH_SKEW`]).
        tolerance_seconds: i64,
    },

    /// v3.12.0 (CIRISPersist#153 Ask 1, CEG 0.7 §5.6.8.8). The submitted
    /// identity_occurrence's `device_class` is outside the closed set
    /// `{phone, laptop, server, embedded, agent, service}`. Rejected at
    /// admission by [`admission::check_device_class`]; the row is not
    /// stored. The V059 `CHECK` constraint is the defense-in-depth
    /// backstop for direct-SQL bypass.
    #[error(
        "device_class {device_class:?} is not in the closed set \
         {{phone, laptop, server, embedded, agent, service}}"
    )]
    DeviceClassRejected {
        /// The rejected `device_class` value as submitted.
        device_class: String,
    },

    /// v3.12.0 (CIRISPersist#153 Ask 2, CEG 0.7 §5.6.8.9). The submitted
    /// family's `consensus_protocol` does not parse into a canonical
    /// shape — `founder_only` / `unanimous` / `majority` / `quorum:m/n`
    /// / `weighted:rubric` / `custom:id`. Rejected at admission by
    /// [`admission::check_consensus_protocol_form`]; the row is not
    /// stored.
    ///
    /// **NOT** the consensus-protocol enforcement error — full
    /// signature-counting against the protocol is the v3.13+ admission
    /// gate, which surfaces a distinct error kind. This is the
    /// value-validation floor (malformed protocol-string syntax).
    #[error(
        "consensus_protocol {consensus_protocol:?} does not parse into a canonical shape \
         (founder_only / unanimous / majority / quorum:m/n / weighted:rubric / custom:id)"
    )]
    ConsensusProtocolMalformed {
        /// The malformed `consensus_protocol` value as submitted.
        consensus_protocol: String,
    },

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-path
    /// cohort_scope admission refusal. A writer (`attesting_key_id` for
    /// an attestation) claimed a `cohort_scope` whose target cohort the
    /// writer is not a member of — a visibility-downgrade attempt.
    /// Rejected at admission by
    /// [`admission::DimensionAdmissionPolicy::check_write_cohort_scope`];
    /// the row is not stored (mirrors the verify-then-gate-then-persist
    /// discipline, MISSION §1.6). Distinct from
    /// [`Error::CohortScopeRejected`] (which is closed-set *value*
    /// validation): this is *membership* refusal of a well-formed label.
    ///
    /// Carries the structured [`ScopeRefusalReason`](crate::scope::ScopeRefusalReason);
    /// `kind()` returns the stable boundary token
    /// `federation_write_scope_refused`, and the inner reason's own
    /// `kind()` distinguishes family vs community membership.
    #[error("write-path cohort_scope refused: {0}")]
    WriteScopeRefused(#[from] crate::scope::ScopeRefusalReason),

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §10.1.6 / §0.7) — an
    /// operational-data envelope merging under `lww_skew_bounded`
    /// (`organization` / `org_membership`) carried an `asserted_at` more
    /// than the §0.7 clock-skew tolerance (±5 min) in the future.
    /// Rejected at admission by
    /// [`operational::check_skew_bound`]; the row is not stored. The LWW
    /// front-running fix — unbounded LWW on `org_membership.role` is a
    /// role-escalation surface.
    #[error(
        "clock-skew violation: asserted_at {asserted_at} is more than 5 minutes \
         past now {now} (§0.7)"
    )]
    ClockSkewViolation {
        /// The rejected envelope's `asserted_at` (RFC-3339).
        asserted_at: String,
        /// The substrate's `now` the gate compared against (RFC-3339).
        now: String,
    },

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13, fail-secure) — an
    /// operational-data envelope carried a recognizable payment-processor
    /// (Stripe-shaped) identifier anywhere, including an open-vocabulary
    /// field or object key. Rejected at admission by
    /// [`operational::reject_payment_processor_identifiers`]; the row is
    /// not stored. Defense-in-depth behind the Registry's emit-side
    /// minimization — billing stays entirely Portal+Stripe, off-wire.
    #[error(
        "operational envelope carries a payment-processor identifier \
         (matched prefix {matched_prefix:?}); billing data MUST NOT federate"
    )]
    PaymentProcessorIdentifier {
        /// The matched payment-processor prefix (e.g. `"cus_"`).
        matched_prefix: &'static str,
    },

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13) — an
    /// operational-data admit failed its authority check: the
    /// `organization` / `org_membership` actor did not hold the required
    /// role via a root-anchored grant
    /// ([`ciris_verify_core::operational_admit::resolve_role_authority`]
    /// returned `authorized: false`), or the `partner_record` M-of-N
    /// steward quorum was not met
    /// ([`ciris_verify_core::operational_admit::verify_partner_record_quorum`]).
    /// Fail-closed: the absence of a positive verdict is rejection. The
    /// row is not stored.
    #[error("operational-data authority not established: {0}")]
    OperationalAuthority(String),

    /// v31.0.0 (CIRISPersist#644, CEG 1.0-RC2 §5.6.8.13) — an
    /// `organization` / `org_membership` / `partner_record` row carried a
    /// typed column that its signature does not cover and that disagrees
    /// with the signed envelope it claims to project.
    ///
    /// The three operational planes are **producer envelope + typed
    /// projection**: the signature (or the M-of-N steward quorum) covers
    /// `signed_envelope` and nothing else, while `resolve_lww` /
    /// `resolve_monotonic_quorum` / the read surface all decide on the
    /// COLUMNS beside it. Before this gate those columns — including the
    /// `withdrawn_at` tombstone, `status`, `role`, the `asserted_at` LWW
    /// key and the `partner_record` `revision` anti-rollback counter —
    /// were authored by whoever wrote the row rather than by whoever
    /// signed it, so replaying a still-validly-signed envelope with edited
    /// columns needed no forgery at all.
    ///
    /// Fail-closed, and no legacy regime: an unbound row is REFUSED, not
    /// downgraded. See
    /// [`operational::check_organization_binding`] /
    /// [`operational::check_org_membership_binding`] /
    /// [`operational::check_partner_record_binding`].
    #[error(
        "{plane} row {attestation_id:?}: typed column `{field}` is not bound to the \
         signed envelope — {detail}. The signature covers `signed_envelope` only, so an \
         unbound column is authored by whoever wrote the row, not by whoever signed it \
         (CIRISPersist#644)"
    )]
    OperationalEnvelopeUnbound {
        /// `organization` | `org_membership` | `partner_record`.
        plane: &'static str,
        /// The rejected row's `attestation_id`.
        attestation_id: String,
        /// The typed column that diverged.
        field: &'static str,
        /// How it diverged (column value vs signed value, or absence).
        detail: String,
    },

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13, F-AV-ROLLBACK) — a
    /// `partner_record` write whose `revision` does not strictly exceed
    /// the most-recent admitted `revision` for the same `license_id`. The
    /// monotonic anti-rollback is enforced **at admission**, before the
    /// §10.1.6 quorum merge — a stale `active` can never overwrite a
    /// later `revoked`. Equal revisions reject too. The row is not stored.
    #[error(
        "partner_record revision rollback for license_id {license_id:?}: \
         submitted revision {submitted} does not exceed existing {existing}"
    )]
    PartnerRecordRollback {
        /// The `license_id` whose monotonic counter was violated.
        license_id: String,
        /// The rejected row's `revision`.
        submitted: u64,
        /// The latest already-admitted `revision` for this `license_id`.
        existing: u64,
    },

    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13 / §0.9.2.1 rule 1)
    /// — a `partner_record` set-semantics array
    /// (`capabilities_granted` / `capabilities_denied` /
    /// `geographic_restrictions` / `allowed_identity_templates`) was not
    /// lexicographically sorted. Caught by
    /// [`ciris_verify_core::operational_admit::check_set_semantics_sorted`]
    /// at the producer *before* M stewards sign divergent JCS bytes —
    /// far better than a silent quorum collapse at admission. The row is
    /// not stored.
    #[error("partner_record set-semantics array not sorted: {0}")]
    SetSemanticsUnsorted(String),

    /// v6.4.0 (CIRISPersist#146 Ask 2, CEG §3.2.3). A `withdraws`
    /// attestation was refused because its `issuer` (`attesting_key_id`)
    /// satisfies NONE of the four broadened admission rules against the
    /// target `T`: (1) producer self-revocation, (2) subject
    /// self-revocation, (3) a `consent_revocation`-scoped `delegates_to`
    /// chain reaching a subject, (4) a `consent_revocation`-scoped
    /// delegation reaching the producer or a subject. The row is not
    /// stored. Distinct from [`Error::InvalidArgument`] so consumers can
    /// pattern-match the authority rejection deterministically (stable
    /// `kind()` token `federation_withdraws_not_admitted`). See
    /// [`admission::resolve_withdraws_admission_rule`].
    #[error(
        "withdraws by issuer {issuer:?} against target attestation \
         {target_attestation_id:?} is not admitted: the issuer satisfies none of the \
         four §3.2.3 admission rules (producer / subject / delegated-proxy authority)"
    )]
    WithdrawsNotAdmitted {
        /// The `attesting_key_id` of the refused `withdraws`.
        issuer: String,
        /// The `attestation_id` of the target `T` being withdrawn.
        target_attestation_id: String,
    },

    /// v8.7.1 (CIRISPersist#233, CEG RC24/RC25/RC26 §11.10 / §11.11 /
    /// §5.6.8.10; CIRISRegistry#95). A moderation / takedown / review
    /// primitive emission was refused: the `signer` is NOT a duty-holder
    /// over the target (it is neither a subject of the target content nor a
    /// named moderator of the target community) AND no steward-bound
    /// duty-holder reaches it via a live `delegates_to` chain bearing the
    /// governing `scope` (`moderate` / `takedown` / `review`, with
    /// `⊆`-parent attenuation + `sub_delegation`-gated deputization + depth
    /// ≤ 5 + no `withdraws`-revoked edge). The row is not stored. This is
    /// the §11.10 "the principal is the steward-bound chain root discovered by
    /// walking up, and only then" gate — the child-safety scope-isolation
    /// property (a `consent_revocation`-scoped delegation cannot drive a
    /// `takedown`). **Absence is never an admit condition** (the v8.7.0
    /// absent-⇒-admit bypass, closed). Distinct from
    /// [`Error::InvalidArgument`] so consumers can pattern-match the
    /// authority rejection deterministically (stable `kind()` token
    /// `federation_delegated_scope_unauthorized`). See
    /// [`admission::check_moderation_admission`].
    #[error(
        "moderation emission by signer {signer:?} over target {on_behalf_of:?} \
         is not admitted: signer is neither a {scope:?} duty-holder as-self \
         nor reached by an steward-bound duty-holder via a live {scope:?}-scoped \
         delegates_to chain (CEG §11.10)"
    )]
    DelegatedScopeUnauthorized {
        /// The signer (`attesting_key_id` / `author_id` / `accuser_id`)
        /// of the refused emission.
        signer: String,
        /// The target descriptor the emission acted over (the content
        /// dimension / `takedown_notice` / `moderation_event` audit string).
        /// v8.7.0's principal-field model is gone; this names the TARGET
        /// whose duty-holders the signer failed to be / be reached by.
        on_behalf_of: String,
        /// The governing delegated-duty scope token (`moderate` /
        /// `takedown` / `review`).
        scope: String,
    },

    /// v9.0.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5). A `delegates_to`
    /// was REFUSED because its `attested_key_id` resolves to a `node`-only
    /// [`crate::federation::types::identity_type::NODE`] identity but the
    /// delegation carries a scope that is NOT `infra:*` — i.e. an
    /// `agency:*` scope, a legacy unprefixed agency kind
    /// (`act_on_behalf` / `message_io` / `reason` / `decide` /
    /// `sub_delegation`), an empty scope set, or any other non-`infra:`
    /// token. This is the gate that makes CC 1.13.5 ("infrastructure must
    /// not have agency") cryptographically enforced: a node key can never
    /// receive agency. The row is not stored (verify-before-mutation,
    /// AV-9). Distinct from [`Error::InvalidArgument`] so consumers can
    /// pattern-match the rejection deterministically (stable `kind()`
    /// token `federation_node_agency_forbidden`). See
    /// [`admission::check_node_agency_admission`] /
    /// [`admission::scopes_are_infra_only`].
    #[error(
        "delegates_to to node-only key {attested_key_id:?} carries non-infra scope(s) \
         {offending_scopes:?}: a node-role delegate may carry ONLY infra:* scopes \
         (CC 4.4.3.4.3 / CC 1.13.5 — infrastructure must not have agency)"
    )]
    NodeAgencyForbidden {
        /// The `attested_key_id` (recipient) that resolved to `node`-only.
        attested_key_id: String,
        /// The offending non-`infra:` scope tokens carried by the
        /// delegation (sorted for a stable error string); empty vec when
        /// the delegation carried no scope at all (empty-set rejection).
        offending_scopes: Vec<String>,
    },

    /// v12.6.0 (CIRISConstitution#23, CC 1.13.3.3 / CC 3.2) — a **second,
    /// distinct-owner** node owner-binding was REJECTED: the node already
    /// carries a LIVE owner-binding from `incumbent_owner`, and a node has at
    /// most ONE responsible steward (the `self` cohort boundary is undefined
    /// otherwise). The incumbent must first `withdraws`/`recants` (or the
    /// binding must lapse) before a different owner can bind. A refresh by the
    /// SAME owner is idempotently admitted. The row is NOT stored (verify-
    /// before-mutation, AV-9). Stable `kind()` token
    /// `federation_node_already_owned`. See
    /// [`admission::check_single_node_owner_admission`] / [`admission::owner_of`].
    #[error(
        "node {node_key_id:?} is already owner-bound by {incumbent_owner:?}; a node has \
         at most one responsible steward (CC 1.13.3.3 / CC 3.2) — {attempted_owner:?} may \
         not bind until the incumbent withdraws/recants or the binding lapses"
    )]
    NodeAlreadyOwned {
        /// The node whose ownership is already claimed.
        node_key_id: String,
        /// The live incumbent owner (a different `user`-role granter).
        incumbent_owner: String,
        /// The rejected would-be owner (the incoming `attesting_key_id`).
        attempted_owner: String,
    },

    /// v12.6.0 (CIRISConstitution#23, CC 1.13.3.3 / CC 3.2) — [`admission::owner_of`]
    /// found **more than one** distinct live owner for a node (a pre-gate
    /// anomaly; [`admission::check_single_node_owner_admission`] prevents new
    /// occurrences). This is a READ-path fail-closed signal: an ambiguous owner
    /// is NOT a resolvable `self` boundary, so consumers MUST refuse rather than
    /// silently pick one. Stable `kind()` token `federation_ambiguous_node_owner`.
    #[error(
        "node {node_key_id:?} has {} distinct live owners {owners:?}; ownership is \
         single-valued (CC 1.13.3.3 / CC 3.2) — cannot resolve a `self` boundary \
         (fail closed)",
        .owners.len()
    )]
    AmbiguousNodeOwner {
        /// The node with an ambiguous (multi-owner) binding state.
        node_key_id: String,
        /// The distinct live owners (sorted).
        owners: Vec<String>,
    },

    /// v25.x (CIRISPersist#578, CIRISConstitution rc3 CC 3.2) — a step of the
    /// **ownerless-lock reclaim ceremony** was refused, naming WHICH step.
    ///
    /// This is the write-path face of
    /// [`ownership_reclaim::ReclaimVerdict::Refused`]: raised when a
    /// `withdraws` against a live owner-binding fails the CC 3.2 recovery
    /// gate, and when a post-reclaim owner-binding arrives without the node's
    /// own co-signature (ceremony step 4). A bare refusal on a node-seizure
    /// path is unacceptable — [`ownership_reclaim::ReclaimRefusal`] is the
    /// stable typed surface, `detail` is diagnostic prose. Stable `kind()`
    /// token `federation_ownership_reclaim_refused`.
    #[error(
        "ownerless-reclaim refused for node {node_key_id:?} against owner-binding \
         {owner_binding_id:?} at {reason}: {detail}"
    )]
    OwnershipReclaimRefused {
        /// The node whose ownership the ceremony concerns.
        node_key_id: String,
        /// The owner-binding `attestation_id` under adjudication (or, for a
        /// step-4 refusal, the rejected fresh binding).
        owner_binding_id: String,
        /// WHICH ceremony step refused.
        reason: ownership_reclaim::ReclaimRefusal,
        /// Human-readable diagnostic. Never parsed.
        detail: String,
    },

    /// v13.0.0 (CIRISPersist#372, CC 3.4.7.1 set-membership) — a
    /// `federation_keys` row carrying the [`types::identity_type::CANONICAL`]
    /// role was REJECTED at admission because it is **not accord-conferred**.
    /// The `canonical` (founding bootstrap server) role is accord-CONFERRED,
    /// never self-claimed: a row may carry it **iff** the record is
    /// anchor-scrub-signed (`scrub_key_id != key_id` AND `scrub_key_id`'s
    /// Ed25519 pubkey ∈ the pinned HUMANITY_ACCORD anchor —
    /// [`ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor`]).
    /// A **self-signed** record carrying `canonical`, or one scrubbed by a
    /// **non-anchor** key, is refused here (fail-closed) — the row is NOT
    /// stored (verify-before-mutation, AV-9). This closes the "a node
    /// bootstraps itself into the founding set" gap on EVERY admission path
    /// (direct registration, self-registration, replication of a self-signed
    /// row, and the `adopt_scrub_upgrade` self→anchored path). Stable
    /// `kind()` token `canonical_role_not_accord_conferred`. See
    /// [`admission::check_canonical_role_admission`].
    #[error(
        "federation_keys row {key_id:?} carries the `canonical` role but is not accord-conferred \
         (scrub_key_id={scrub_key_id:?}, reason: {reason}); the `canonical` founding-server role \
         is accord-CONFERRED, never self-claimed — a row may carry it only when anchor-scrub-signed \
         (scrub_key_id != key_id AND the scrubber's ed25519 ∈ the pinned HUMANITY_ACCORD anchor)"
    )]
    CanonicalRoleNotAccordConferred {
        /// The `key_id` of the row that attempted to carry `canonical`.
        key_id: String,
        /// The row's `scrub_key_id` (the claimed scrubber).
        scrub_key_id: String,
        /// Why the record failed the accord-conferred test (self-signed /
        /// unknown scrubber / non-anchor scrubber / undecodable scrubber key).
        reason: String,
    },

    /// v15.0.0 (CIRISPersist#422, CIRISVerify#185) — a `federation_keys` write
    /// was REFUSED because it carries the `infra:attest` role (an accord-blessed
    /// build-signing / CI pipeline key; [`types::roles::INFRA_ATTEST`]) but is
    /// **not accord-co-scrubbed to the family m-of-n**. Exactly mirrors
    /// [`Self::CanonicalRoleNotAccordConferred`] for the `roles`-vector role: the
    /// build-manifest trust root folds onto the SAME accord co-scrub as a
    /// canonical server, so `infra:attest` is accord-CONFERRED, never
    /// self-claimed — a row may carry it only when anchor-scrubbed with a scrub
    /// set meeting the live accord quorum. Fail-closed (verify-before-mutation,
    /// AV-9 — the row is NOT stored). Stable `kind()` token
    /// `infra_attest_role_not_accord_conferred`. See
    /// [`admission::check_infra_attest_role_admission`].
    #[error(
        "federation_keys row {key_id:?} carries the `infra:attest` role but is not accord-conferred \
         (scrub_key_id={scrub_key_id:?}, reason: {reason}); the `infra:attest` build-signing role is \
         accord-CONFERRED via the same m-of-n accord co-scrub as `canonical`, never self-claimed"
    )]
    InfraAttestRoleNotAccordConferred {
        /// The `key_id` of the row that attempted to carry `infra:attest`.
        key_id: String,
        /// The row's `scrub_key_id` (the claimed scrubber).
        scrub_key_id: String,
        /// Why the record failed the accord-conferred test (self-signed /
        /// sub-quorum scrub set / non-anchor scrubbers).
        reason: String,
    },

    /// v16.0.0 (CIRISPersist#424) — a `federation_keys` write was REFUSED
    /// because it would confer `infra:attest` on a `key_id` the accord quorum
    /// has WITHDRAWN (a durable V104 tombstone exists whose `superseded_by`
    /// does not name this key). The revocation-wins consult that makes
    /// withdrawal defeat a re-add over anti-entropy — the #377 canonical rule,
    /// generalized to the roles vector. Stable `kind()` token
    /// `infra_attest_role_withdrawn`. See
    /// [`admission::check_infra_attest_role_admission`] and
    /// [`admission::withdraw_infra_attest_role`].
    #[error(
        "federation_keys row {key_id:?} was refused the `infra:attest` role: the accord quorum \
         withdrew it (V104 tombstone; superseded_by={superseded_by:?}) — a withdrawn \
         build-signing key cannot be re-conferred the role, even by a valid co-scrub \
         (revocation-wins, #424)"
    )]
    InfraAttestRoleWithdrawn {
        /// The `key_id` that carries a withdrawal tombstone.
        key_id: String,
        /// The successor `key_id` the withdrawal points to (a supersede), or
        /// `None` for a plain withdraw.
        superseded_by: Option<String>,
    },

    /// v13.1.0 (CIRISPersist#377, CC 3.4.7.1 / FSD Trust Root) — a
    /// `federation_keys` write was REFUSED because it would confer the
    /// `canonical` role on a `key_id` the accord quorum has WITHDRAWN (a durable
    /// V095 `canonical_role_withdrawal` tombstone exists whose `superseded_by`
    /// does NOT name this same key). This is the **revocation-wins** gate
    /// consult that makes withdrawal defeat a re-add over anti-entropy: even a
    /// genuinely anchor-scrubbed re-offer of the old `canonical` record is
    /// refused here (verify-before-mutation, AV-9 — the row is NOT stored /
    /// upgraded), so a peer still holding the old record cannot silently
    /// re-confer the role on the next replication round. Stable `kind()` token
    /// `canonical_role_withdrawn`. See
    /// [`admission::check_canonical_role_admission`] and
    /// [`admission::withdraw_canonical_role`].
    #[error(
        "federation_keys row {key_id:?} was refused the `canonical` role: the accord quorum \
         withdrew it (V095 tombstone; superseded_by={superseded_by:?}) — a withdrawn canonical \
         key cannot be re-conferred the role, even by a valid anchor-scrub (revocation-wins, \
         #377); the withdrawal MUST be superseded to a new key to re-enter the canonical set"
    )]
    CanonicalRoleWithdrawn {
        /// The `key_id` that carries a withdrawal tombstone.
        key_id: String,
        /// The successor `key_id` the withdrawal points to (a supersede), or
        /// `None` for a plain withdraw.
        superseded_by: Option<String>,
    },

    /// v17.0.0 (CIRISPersist#440/#441) — a `federation_keys` write was REFUSED
    /// because it claims an accord-conferred `role` (on EITHER role surface —
    /// the `identity_type` set or the `roles` vector,
    /// [`types::KeyRecord::claims_role`]) without the accord family m-of-n
    /// co-scrub. The role-generic mirror of
    /// [`Self::CanonicalRoleNotAccordConferred`] /
    /// [`Self::InfraAttestRoleNotAccordConferred`], carried by the CC 3.4.9
    /// co-steward roles (`registry`/`verify`) and every future
    /// accord-conferred role. Fail-closed (verify-before-mutation, AV-9 — the
    /// row is NOT stored). Stable `kind()` token `role_not_accord_conferred`.
    /// See [`admission::check_accord_role_admission_over_roster`].
    #[error(
        "federation_keys row {key_id:?} claims the accord-conferred role {role:?} but is not \
         accord-conferred (scrub_key_id={scrub_key_id:?}, reason: {reason}); accord-conferred \
         roles are conferred by the accord family m-of-n co-scrub, never self-claimed — on \
         either role surface (identity_type set or roles vector)"
    )]
    RoleNotAccordConferred {
        /// The accord-conferred role token the row claimed.
        role: String,
        /// The `key_id` of the row that attempted to carry the role.
        key_id: String,
        /// The row's `scrub_key_id` (the claimed scrubber).
        scrub_key_id: String,
        /// Why the record failed the accord-conferred test (self-signed /
        /// sub-quorum scrub set / non-anchor scrubbers).
        reason: String,
    },

    /// v17.0.0 (CIRISPersist#440) — a `federation_keys` write was REFUSED
    /// because it would confer `role` on a `key_id` the accord quorum has
    /// WITHDRAWN (a durable V104 tombstone whose `superseded_by` does not name
    /// this key). The role-generic revocation-wins consult — the #377 rule
    /// carried by [`admission::check_accord_role_admission_over_roster`].
    /// Stable `kind()` token `role_withdrawn`. See
    /// [`admission::withdraw_accord_role`].
    #[error(
        "federation_keys row {key_id:?} was refused the accord-conferred role {role:?}: the \
         accord quorum withdrew it (V104 tombstone; superseded_by={superseded_by:?}) — a \
         withdrawn key cannot be re-conferred the role, even by a valid co-scrub \
         (revocation-wins)"
    )]
    RoleWithdrawn {
        /// The withdrawn role token.
        role: String,
        /// The `key_id` that carries a withdrawal tombstone.
        key_id: String,
        /// The successor `key_id` the withdrawal points to (a supersede), or
        /// `None` for a plain withdraw.
        superseded_by: Option<String>,
    },

    /// v13.1.0 (CIRISPersist#377, FSD Trust Root m-of-n) — a canonical
    /// withdraw/supersede was REFUSED because its accord live-quorum authority
    /// [`AccordDecision`](ciris_verify_core::accord_live_quorum::AccordDecision)
    /// did not verify: either `authorized == false` (no m-of-n family quorum
    /// verdict) or its `proposal.payload_sha256` does not commit to the
    /// persist-computed canonical payload for THIS operation + target (a replay
    /// of a decision authorizing some other payload). Fail-closed
    /// (verify-before-mutation, AV-9 — no tombstone / successor is written).
    /// Symmetric m-of-n by design (v13.2.0 / CIRISPersist#383): ADD requires a
    /// 2-of-3 accord co-scrub and WITHDRAW/SUPERSEDE the 2-of-3 quorum. Stable `kind()` token
    /// `canonical_withdrawal_authority_invalid`. See
    /// [`admission::verify_canonical_withdraw_authority`].
    #[error(
        "canonical withdraw/supersede of {key_id:?} refused — invalid accord authority: {reason}"
    )]
    CanonicalWithdrawalAuthorityInvalid {
        /// The target `key_id` the (rejected) withdraw/supersede named.
        key_id: String,
        /// Why the authority failed (unauthorized decision / payload mismatch).
        reason: String,
    },

    /// v31.1.0 (CIRISPersist#662) — a replicated **accord evidence bundle**
    /// ([`accord_carriage::AccordQuorumEvidence`]) was REFUSED because the
    /// receiver's own re-tally did not reach a strict majority of its accord
    /// roster, or the bundle was outside the HUMANITY_ACCORD family scope.
    ///
    /// The distinction from [`Error::CanonicalWithdrawalAuthorityInvalid`] is
    /// deliberate: that token means "a LOCAL destructive op named an
    /// authority that does not hold"; this one means "a PEER offered evidence
    /// and we re-derived its quorum ourselves and it did not hold". Both are
    /// fail-closed (nothing is stored), but only this one tells an operator
    /// that a carrier is supplying bundles that do not verify here — which is
    /// either a partition, a stale roster, or a forgery attempt, and they
    /// want to know which surface said so. Stable `kind()` token
    /// `accord_evidence_unverified`.
    #[error(
        "replicated accord evidence for proposal {proposal_digest:?} refused — \
         the receiver's own re-tally did not authorize it: {reason}"
    )]
    AccordEvidenceUnverified {
        /// The content-derived digest of the refused proposal.
        proposal_digest: String,
        /// Why the receiver's re-derivation failed.
        reason: String,
    },

    /// v36.0.0 (CIRISPersist#674) — a replicated **accord evidence bundle**
    /// was REFUSED for what the CARRIER sent, before any signature was
    /// verified: its participation list is structurally impossible against
    /// ANY roster of the declared size (more entries than the roster has
    /// seats, or two entries for one `member_id`).
    ///
    /// The distinction from [`Error::AccordEvidenceUnverified`] is the point
    /// of the variant (the CIRISPersist#565 typed-refusal family): that token
    /// means "we re-derived the quorum ourselves and it did not hold" — a
    /// partition, a stale roster, or a forgery attempt. This one means "no
    /// tally was attempted, because no legitimate serve side can produce this
    /// bundle" — the serve side orders participations by `member_id`, which
    /// M6 dedup makes unique within a bundle, and a bundle cannot carry more
    /// votes than there are seats. An operator hunting a partition must not
    /// be sent there by a malformed carrier, and vice versa.
    ///
    /// Decided BEFORE the re-tally, before roster resolution, and before
    /// anything lands (fail-closed, nothing stored) — so the hybrid
    /// Ed25519 + ML-DSA-65 verification work an already-authenticated carrier
    /// can demand from one bundle is bounded by the declared seat count as a
    /// structural property, not as a side effect of the tally erroring on
    /// its first anomaly. Stable `kind()` token
    /// `accord_evidence_carrier_malformed`.
    #[error(
        "replicated accord evidence for proposal {proposal_digest:?} refused BEFORE \
         verification — the carrier's bundle is malformed ({participations} participation(s) \
         against {roster_seats} declared accord seat(s)): {reason}"
    )]
    AccordEvidenceCarrierMalformed {
        /// The content-derived digest of the refused proposal.
        proposal_digest: String,
        /// How many participations the bundle carried.
        participations: usize,
        /// How many seats the declared accord roster has.
        roster_seats: usize,
        /// Which structural rule the bundle broke.
        reason: String,
    },

    /// v9.0.0 (CIRISPersist#237, CC 5.3.2.4.3.1) — a **federation-tier**
    /// attestation was REJECTED at the bulk store/replicate ingest gate
    /// because its envelope hybrid signature could not be verified
    /// against the attesting key's REGISTERED pubkeys under the
    /// always-on `HybridPolicy::Strict` (both Ed25519 over `JCS(envelope)`
    /// AND ML-DSA-65 over the bound `JCS(envelope) ‖ ed25519_sig`
    /// REQUIRED). Causes, all fail-secure (the row is NOT stored): the
    /// classical-only / hybrid-pending case (missing ML-DSA-65 half —
    /// the load-bearing CC 5.3.2.4.3.1 guard), a tampered / invalid
    /// Ed25519 or ML-DSA-65 signature, a canonicalizer mismatch
    /// (`SHA-256(JCS(envelope)) != original_content_hash`), or an
    /// **unregistered attester** (no pubkeys to verify against). The
    /// mandate is at the federation admission boundary only — **local-tier
    /// rows are EXEMPT** (CC 5.3.2.2 deferred signature) and never reach
    /// this gate. Distinct from [`Error::SignatureInvalid`] (the
    /// registration-gate token) so consumers can pattern-match the
    /// federation-tier ingest rejection deterministically (stable
    /// `kind()` token `federation_federation_tier_unverified`).
    /// Verify-before-mutation (AV-9). See
    /// [`verify_federation_tier_ingest`](crate::federation::verify_federation_tier_ingest).
    #[error(
        "federation-tier attestation {attestation_id:?} (attesting_key_id={attesting_key_id:?}) \
         rejected at the bulk ingest gate: {reason} — a federation-tier row MUST carry a \
         valid hybrid Ed25519 + ML-DSA-65 signature verified against the attester's registered \
         key (CC 5.3.2.4.3.1; classical-only / non-PQC producers are confined to local-tier)"
    )]
    FederationTierUnverified {
        /// The rejected row's `attestation_id`.
        attestation_id: String,
        /// The `attesting_key_id` whose registered key the signature was
        /// (or could not be) verified against.
        attesting_key_id: String,
        /// Human-readable cause (missing PQC half / bad signature /
        /// canonicalizer mismatch / unregistered attester).
        reason: String,
    },

    /// v9.0.0 (CC 3.4.7.1 / CC 3.2). A `community` admission was REFUSED
    /// because one of its roster members resolves to a `node`- or
    /// `agent`-role identity ([`crate::federation::types::identity_type`])
    /// that is **not steward-bound** — there is no live, unrevoked path from
    /// the member key to a `user`-role identity
    /// ([`admission::is_steward_bound`]). Per the CC 3.2 "steward-binding gate
    /// for non-infrastructure membership", non-infra community membership
    /// is an authority act that MUST root in an accountable human; a fresh,
    /// unstewarded node/agent is canonical-trust-and-serve only. The gate is a
    /// **precondition** to (not a substitute for) the community's own
    /// `consensus_protocol` vote. `cohort_subkind: infrastructure`
    /// communities are EXEMPT (trust + serve needs no owner). The row is
    /// NOT stored (verify-before-mutation, AV-9). Distinct from
    /// [`Error::InvalidArgument`] so consumers can pattern-match the
    /// rejection deterministically (stable `kind()` token
    /// `federation_unstewarded_community_member`). See
    /// [`admission::check_community_membership_steward_binding`].
    #[error(
        "community {community_key_id:?} cannot admit member {member_key_id:?}: a {member_role} \
         key MUST be steward-bound (a live delegates_to/identity_occurrence path to a user-role \
         identity) before admission to a non-infrastructure community \
         (CC 3.2 / CC 3.4.7.1 — non-infra membership is an authority act)"
    )]
    UnstewardedCommunityMember {
        /// The community's `community_key_id` whose admission was refused.
        community_key_id: String,
        /// The roster member key that resolved to node/agent without a
        /// live steward-binding.
        member_key_id: String,
        /// The offending role token (`node` or `agent`) — whichever was
        /// present in the member's `identity_type` set.
        member_role: &'static str,
    },

    /// v11.5.0 (CIRISPersist#306, CC 3.2 / CC 1.15.6) — a `delegates_to`
    /// whose TARGET (`attested_key_id`) resolves to a `user`-role identity was
    /// REFUSED by the CC 3.2 user-target steward-binding gate. "Stewarding a
    /// person" is admissible only as **minor-guardianship**; the admissible
    /// set is exactly: target is a PROVEN minor AND the granter
    /// (`attesting_key_id`) is a PROVEN adult `user`. Every other user-target
    /// binding is refused:
    ///
    /// - `target_is_self_sovereign` — the target is a proven ADULT user. An
    ///   adult is un-stewardable (CC 1.15.6, no-slavery / self-sovereignty);
    ///   rejected unconditionally.
    /// - `target_age_unverified` — the target has no usable age proof
    ///   ([`crate::federation::age::AgeBand::Unknown`]). The
    ///   presumption-of-sovereignty default: you may not acquire stewardship
    ///   over someone unless they are PROVEN a minor.
    /// - `granter_unresolved` — the granter key does not resolve.
    /// - `granter_not_adult_user` — the granter is not a `user`, or not a
    ///   proven adult (a minor cannot be a guardian; a non-user cannot be a
    ///   guardian).
    ///
    /// v11.9.0 (CIRISPersist#309, CC 3.4.12) — an ADULT target is admissible
    /// ONLY through the narrow adult-incapacity aperture
    /// ([`admission::check_adult_incapacity_binding`]). Its rejection reasons:
    ///
    /// - `scope_missing` — the binding declares no scope.
    /// - `scope_exceeds_attested_domains` — a scoped domain has no live
    ///   `capacity_assurance:*:{d}:incapacitated`.
    /// - `capacity_reversible_not_excluded` — a scoped domain lacks the
    ///   mandatory `reversible_excluded` companion (and the T1
    ///   `reversible_pending` acute path does not apply).
    /// - `scope_touches_protected_domain` — scope intersects the apophatic
    ///   [`crate::federation::capacity::PROTECTED_NON_TRANSFERABLE`] floor.
    /// - `attester_conflicted` — a capacity assessor is the steward or
    ///   petitioner (assessor-independence).
    /// - `missing_legitimacy_source` — absent/invalid
    ///   `binding_legitimacy_source` (never the steward's signature alone).
    /// - `missing_valid_until` / `valid_until_unparseable` /
    ///   `valid_until_exceeds_review_cadence` — the fail-to-liberty mandatory
    ///   bounded expiry is missing, malformed, or outruns the T2 cadence.
    ///
    /// `node`/`agent`-target bindings are governed by
    /// [`admission::check_node_agency_admission`] and are NOT affected by this
    /// rule. The row is NOT stored (verify-before-mutation, AV-9). Stable
    /// `kind()` token `federation_user_target_steward_binding_forbidden`. See
    /// [`admission::check_user_target_steward_binding_admission`].
    #[error(
        "delegates_to to user-role target {target_key_id:?} refused ({reason}): a user-target \
         steward-binding is admissible only as minor-guardianship — the target MUST be a proven \
         minor and the granter a proven adult user (CC 3.2 / CC 1.15.6 — an adult is \
         un-stewardable; presumption of sovereignty for an unverified age)"
    )]
    UserTargetStewardBindingForbidden {
        /// The `attested_key_id` (target) that resolved to a `user`-role
        /// identity and failed the minor-guardianship predicate.
        target_key_id: String,
        /// Which leg of the predicate failed (`target_is_self_sovereign` /
        /// `target_age_unverified` / `granter_unresolved` /
        /// `granter_not_adult_user`).
        reason: &'static str,
    },

    /// v12.5.0 (CIRISPersist#238, CC 4.5.4 / §11.11 — the no-moderator-no-
    /// federate existence invariant). A federation-tier apply step keyed on a
    /// `community` was REFUSED because that community has **no live holder of
    /// its `moderate` duty** — no
    /// [`is_named_moderator`](admission::is_named_moderator) resolvable member.
    /// A `community` federates only while ≥1 steward-bound authority root
    /// exists (a founder / `consensus_protocol` signer who
    /// [`is_steward_bound`](admission::is_steward_bound)); such a root is a
    /// zero-hop named moderator, and every delegated moderator chains back to
    /// one. Fail-secure per §11.11 rule 3 — "better no group than an
    /// unmoderated one": a moderator-less community MUST NOT federate at
    /// moderated capability. `cohort_subkind: infrastructure` communities are
    /// EXEMPT (trust + serve needs no moderator, mirroring the CC 3.2 steward-
    /// binding carve-out). The row/record is NOT stored (verify-before-
    /// mutation, AV-9). Stable `kind()` token
    /// `federation_community_no_moderator`. See
    /// [`admission::check_no_moderator_federate_admission`].
    ///
    /// Merit auto-promotion (§11.11 rule 2) + the CC 4.5.13 48-hour recovery
    /// are appointment *ceremonies* that emit a `delegates_to(moderate)` signed
    /// by the community authority — persist cannot forge that signature, so
    /// those live one layer up; this substrate gate is the fail-secure floor
    /// they recover the community *out of*.
    #[error(
        "community {community_key_id:?} has no live `moderate`-duty holder — a community \
         federates only while ≥1 steward-bound authority root (a named moderator) exists \
         (CC 4.5.4 / §11.11 — no unmoderated federated space; better no group than an \
         unmoderated one). Fail-secure: it MUST NOT federate at moderated capability"
    )]
    CommunityHasNoModerator {
        /// The community whose federation was refused for lack of a moderator.
        community_key_id: String,
    },

    /// CIRISPersist#592 (**AV-84**) — a promotion tried to place a row
    /// into a TARGETED cohort plane (`family` / `community`) while the row
    /// names a party other than its own producer.
    ///
    /// This is NOT [`Error::WriteScopeRefused`] wearing a new hat, and the two
    /// must never collapse into one: AV-45's refusal means *"the writer is not
    /// a member of the target it named"*, a verdict this table cannot reach
    /// because an attestation has no `cohort_target_id` to name a target with.
    /// This one means *"the row is not the promoter's own content, so the one
    /// cohort placement the promote door CAN adjudicate is unavailable"*.
    /// Reporting the first for the second would send an operator hunting for a
    /// membership record that was never the problem — the #565 lesson (a
    /// refusal names its own branch) applied to the one axis where a shared
    /// name would be actively misleading.
    ///
    /// The row is NOT promoted and NOT mutated (verify-before-mutation, AV-9).
    /// Stable `kind()` token `federation_cohort_standing_refused`; consumers
    /// branch on [`admission::CohortStandingRefusal::as_str`], never this text.
    /// See [`admission::check_promotion_cohort_standing`].
    #[error(
        "targeted-cohort placement refused ({reason}): promoting to cohort_scope \
         {cohort_scope:?} requires the row to name no party but its own producer \
         {producer_key_id:?}, but its {} names {foreign_key_id:?}. A promotion into a \
         family/community plane is a producer self-declaration about its own content's \
         visibility (CIRISPersist#592 / AV-84); a claim about a third party belongs at a \
         broad belonging-tier, where any authenticated writer may emit",
        reason.field()
    )]
    CohortStandingRefused {
        /// The targeted placement that was refused (`family` / `community`).
        cohort_scope: String,
        /// The row's producer — `attesting_key_id`.
        producer_key_id: String,
        /// The party the row names who is NOT the producer.
        foreign_key_id: String,
        /// WHICH field carried the foreign party.
        reason: admission::CohortStandingRefusal,
    },

    /// v8.2.0 (CEG 1.0-RC11 §19.1 / CIRISPersist#228 item 1 / #229 item 1)
    /// — a WholenessWitness was REJECTED at the verify-before-persist
    /// gate: the §19.0 PQC-mandatory hard cut (classical-only / missing
    /// or invalid ML-DSA-65 half), a WW-2 namespace violation
    /// (names self/anonymous), a leaf/root mismatch, or a malformed
    /// key/signature/version. Carries the
    /// [`crate::witness::WitnessAdmitError`] — its `kind()` token is
    /// preserved via [`Error::kind`]. Verify-before-mutation (AV-9):
    /// nothing was written.
    #[error("wholeness witness admission rejected: {0}")]
    WitnessAdmit(#[from] crate::witness::WitnessAdmitError),

    /// Backend-level error (DB connection, serialization, etc.).
    /// String-typed because each backend has its own error tree.
    #[error("backend: {0}")]
    Backend(String),

    /// v11.8.1 (CIRISPersist#329). The consumer-side
    /// [`crate::ffi::directory_capsule::build_ops_directory`] proxy was
    /// asked for a `FederationDirectory` method that has no corresponding
    /// [`crate::ffi::directory_capsule::DirectoryOp`] variant, so it
    /// cannot be routed across the ABI. The remedy is on the persist side:
    /// add the missing op (and its dispatch arm) so the proxy can carry
    /// the call. This is a static contract gap, never a runtime data
    /// condition.
    #[error(
        "directory ops proxy: method {method} has no DirectoryOp — \
         the consumer needs it; add the op in persist (CIRISPersist#329)"
    )]
    Unsupported {
        /// The `FederationDirectory` method name the proxy could not route.
        method: &'static str,
    },

    /// v30.3.0 (CIRISPersist#611). A door that must re-derive authority
    /// against **this node's own trust root** was asked of a directory that
    /// does not know which key it is. The answer is neither "admit" nor a
    /// silent empty result — it is this.
    ///
    /// # Why an error and not an empty result
    ///
    /// The gate this backs is a filter on a READ
    /// ([`FederationDirectory::lookup_trusted_publisher_chain`]), where the
    /// fail-secure reflex is to return nothing. That reflex is wrong here, and
    /// the reason is the whole decision in #611: a host that forgot
    /// `set_node_key_id()` would watch legitimate publisher vouches silently
    /// vanish, with no diagnostic and nothing in the result distinguishing
    /// "this content has no vouches" from "this node cannot check vouches".
    /// Those are different facts and a caller acts differently on each.
    ///
    /// `Engine` injects the identity at construction, so no ordinary host
    /// reaches this. It exists for the bare-backend case, and it names what to
    /// call.
    #[error(
        "{method} must re-derive authority against this node's own trust root, but this \
         directory has no node identity — call set_node_key_id() (needed for: {needed_for})"
    )]
    NodeIdentityUnset {
        /// The method that could not answer.
        method: &'static str,
        /// What the identity was needed for, so the message is actionable.
        needed_for: &'static str,
    },
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::NodeIdentityUnset { .. } => "federation_node_identity_unset",
            Error::InvalidArgument(_) => "federation_invalid_argument",
            Error::SignatureInvalid(_) => "federation_signature_invalid",
            Error::RateLimited { .. } => "federation_rate_limited",
            Error::ConsentGateRefused(_) => "federation_consent_gate_refused",
            Error::Conflict(_) => "federation_conflict",
            Error::AdminActionUnattributed { .. } => "federation_admin_action_unattributed",
            Error::RevocationBoundInvalid { .. } => "federation_revocation_bound_invalid",
            Error::RevocationEnvelopeUnbound { .. } => "federation_revocation_envelope_unbound",
            Error::EnvelopeTooLarge { .. } => "federation_envelope_too_large",
            Error::TraceDimensionInvalid { .. } => "federation_trace_dimension_invalid",
            Error::CharterInvalid { .. } => "federation_charter_invalid",
            Error::GenesisBundleInvalid { .. } => "federation_genesis_bundle_invalid",
            Error::NoConstitutionalRootYet { .. } => "federation_no_constitutional_root_yet",
            Error::ConstitutionalFamilyReserved { .. } => {
                "federation_constitutional_family_reserved"
            }
            Error::GenesisAttestationReserved { .. } => "federation_genesis_attestation_reserved",
            Error::AccordRootUnnamed { .. } => "federation_accord_root_unnamed",
            Error::AccordRootDisagrees { .. } => "federation_accord_root_disagrees",
            Error::LocationAuthorityUnauthorized { .. } => {
                "federation_location_authority_unauthorized"
            }
            Error::AccordDimensionRequiresAccordHolder { .. } => {
                "federation_accord_dimension_requires_accord_holder"
            }
            Error::DimensionRejected { .. } => "federation_dimension_rejected",
            Error::DeprecatedAttestationLadderForm { .. } => {
                "federation_deprecated_attestation_ladder_form"
            }
            Error::CapacitySelfEmissionRejected { .. } => {
                "federation_capacity_self_emission_rejected"
            }
            Error::AgeAssuranceSelfEmissionRejected { .. } => {
                "federation_age_assurance_self_emission_rejected"
            }
            Error::ReservedPrefixEmitterMismatch { .. } => {
                "federation_reserved_prefix_emitter_mismatch"
            }
            Error::NamespaceFamilyUnregistered { .. } => "federation_namespace_family_unregistered",
            Error::NamespacePrivateUseNotFederatable { .. } => {
                "federation_namespace_private_use_not_federatable"
            }
            Error::EnvelopeSchemaViolation { .. } => "federation_envelope_schema_violation",
            Error::AccordHolderRequiresAttestationEvidence { .. } => {
                "federation_accord_holder_requires_attestation_evidence"
            }
            Error::HardwareTypeNotAccepted { .. } => "federation_hardware_type_not_accepted",
            Error::AttestationEvidenceIncomplete { .. } => {
                "federation_attestation_evidence_incomplete"
            }
            Error::AttestationEvidenceStale { .. } => "federation_attestation_evidence_stale",
            Error::PeerNotFound { .. } => "federation_peer_not_found",
            Error::HardRemoveWithActiveAttestations { .. } => {
                "federation_hard_remove_with_active_attestations"
            }
            Error::TrustBelowThreshold { .. } => "federation_trust_below_threshold",
            Error::CohortScopeRejected { .. } => "federation_cohort_scope_rejected",
            Error::RegionRejected { .. } => "federation_region_rejected",
            Error::RevocationRollback { .. } => "federation_revocation_rollback",
            Error::RevocationScrubSkew { .. } => "federation_revocation_scrub_skew",
            Error::DeviceClassRejected { .. } => "federation_device_class_rejected",
            Error::ConsensusProtocolMalformed { .. } => "federation_consensus_protocol_malformed",
            Error::WriteScopeRefused(_) => "federation_write_scope_refused",
            Error::ClockSkewViolation { .. } => "federation_clock_skew_violation",
            Error::PaymentProcessorIdentifier { .. } => "federation_payment_processor_identifier",
            Error::OperationalAuthority(_) => "federation_operational_authority",
            Error::OperationalEnvelopeUnbound { .. } => "federation_operational_envelope_unbound",
            Error::PartnerRecordRollback { .. } => "federation_partner_record_rollback",
            Error::SetSemanticsUnsorted(_) => "federation_set_semantics_unsorted",
            Error::WithdrawsNotAdmitted { .. } => "federation_withdraws_not_admitted",
            Error::DelegatedScopeUnauthorized { .. } => "federation_delegated_scope_unauthorized",
            Error::NodeAgencyForbidden { .. } => "federation_node_agency_forbidden",
            Error::NodeAlreadyOwned { .. } => "federation_node_already_owned",
            Error::AmbiguousNodeOwner { .. } => "federation_ambiguous_node_owner",
            Error::OwnershipReclaimRefused { .. } => "federation_ownership_reclaim_refused",
            Error::CanonicalRoleNotAccordConferred { .. } => "canonical_role_not_accord_conferred",
            Error::InfraAttestRoleNotAccordConferred { .. } => {
                "infra_attest_role_not_accord_conferred"
            }
            Error::InfraAttestRoleWithdrawn { .. } => "infra_attest_role_withdrawn",
            Error::CanonicalRoleWithdrawn { .. } => "canonical_role_withdrawn",
            Error::RoleNotAccordConferred { .. } => "role_not_accord_conferred",
            Error::RoleWithdrawn { .. } => "role_withdrawn",
            Error::CanonicalWithdrawalAuthorityInvalid { .. } => {
                "canonical_withdrawal_authority_invalid"
            }
            Error::AccordEvidenceUnverified { .. } => "accord_evidence_unverified",
            Error::AccordEvidenceCarrierMalformed { .. } => "accord_evidence_carrier_malformed",
            Error::UnstewardedCommunityMember { .. } => "federation_unstewarded_community_member",
            Error::UserTargetStewardBindingForbidden { .. } => {
                "federation_user_target_steward_binding_forbidden"
            }
            Error::CommunityHasNoModerator { .. } => "federation_community_no_moderator",
            Error::CohortStandingRefused { .. } => "federation_cohort_standing_refused",
            Error::FederationTierUnverified { .. } => "federation_federation_tier_unverified",
            Error::WitnessAdmit(e) => e.kind(),
            Error::Backend(_) => "federation_backend",
            Error::Unsupported { .. } => "federation_ops_proxy_unsupported",
        }
    }

    /// v31.1.0 (CIRISPersist#665) — **did this write lose a primary-key race?**
    ///
    /// The one predicate for *"the row is already there, written by somebody
    /// else"*, so that every caller which must treat a duplicate as SUCCESS
    /// asks the same question in the same words.
    ///
    /// v36.0.0 (CIRISPersist#624) — also the store-step arm of
    /// [`FederationDirectory::apply_replicated_attestation`], which maps a
    /// duplicate the pre-write plan did not see to the typed
    /// `Refused { StoreConflict }` outcome. The semantic classification #624
    /// asked for lives THERE (decided pre-write, above the backends); this
    /// predicate stays the single spelling of the raw storage fact.
    ///
    /// # Why a string predicate and not a typed variant
    ///
    /// A duplicate `attestation_id` does **not** surface as [`Error::Conflict`]
    /// on any backend. All three funnel it into [`Error::Backend`]:
    ///
    /// - **memory** — the AV-79 uniqueness emulation returns
    ///   `Backend("insert attestation: UNIQUE constraint failed: …")`,
    ///   deliberately byte-identical to sqlite's;
    /// - **sqlite** — `map`s every non-FK `rusqlite` insert failure through
    ///   `Backend(format!("insert attestation: {msg}"))`, and `msg` for a PK
    ///   collision is `UNIQUE constraint failed: …`;
    /// - **postgres** — `map_attestation_pg_err` classifies only SQLSTATE 23503
    ///   (FK) specially; a 23505 unique violation falls through to
    ///   `Backend(pg_error_detail(..))`, which renders as
    ///   `SQLSTATE 23505: duplicate key value violates unique constraint …`.
    ///
    /// The *right* fix would be a typed `Error::Conflict` from all three, or an
    /// `INSERT … ON CONFLICT DO NOTHING` insert-if-absent primitive. Neither is
    /// available to this cut: no backend offers an atomic insert-if-absent on
    /// `put_attestation` (all three do a plain `INSERT` behind the full
    /// admission stack), and re-typing the refusal would move
    /// `error_kind` — which `assert_parity` hard-asserts equal across backends,
    /// and which the memory backend's uniqueness emulation was written
    /// specifically to match. That is a public-contract change, not a fix to
    /// this finding.
    ///
    /// So the predicate stays a string test, and the point of putting it HERE
    /// is that there is exactly one of it. It was previously transcribed inline
    /// in `exercise_genesis_seed_installs` and NOT in
    /// [`seed_delegation_plane`](super::federation::genesis::seed_delegation_plane) —
    /// a second copy would have been the two-lists-that-disagree class, which is
    /// how the seed path came to treat a lost race as "still absent" and stop
    /// seeding half-way.
    ///
    /// Both the SQLSTATE token and the human phrase are matched for postgres:
    /// the code is the machine fact, the phrase survives a locale or
    /// driver-rendering change of the other.
    #[must_use]
    pub fn is_duplicate_key(&self) -> bool {
        if matches!(self, Error::Conflict(_)) {
            return true;
        }
        let Error::Backend(msg) = self else {
            return false;
        };
        msg.contains("UNIQUE constraint")
            || msg.contains("duplicate key")
            || msg.contains("SQLSTATE 23505")
    }
}
