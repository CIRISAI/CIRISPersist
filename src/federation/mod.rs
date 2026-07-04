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

pub mod accord_quorum;
pub mod admission;
pub mod age;
pub mod at_rest_cascade;
#[cfg(feature = "cirisaudit")]
pub mod backfill;
pub mod blackhole;
pub mod blobs;
pub mod capacity;
pub mod cohort;
pub mod community_dek;
#[cfg(feature = "cirisaudit")]
pub mod emit;
pub mod genesis;
pub mod goal;
pub mod hardware_attestation;
pub mod identity_aggregate;
pub mod location;
// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13 / §10.1.6) — operational-
// data admit + merge surface (organization / org_membership /
// partner_record). Row shapes, the four admission checks, and the two
// CEG-declared merge dispatchers; the backends do the storage I/O.
pub mod operational;
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
pub mod register;
pub mod replication;
pub mod rooting;
pub mod schema_resolver;
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
// v9.0.0 (CIRISPersist#237, CC 5.3.2.4.3.1) — the PQC-mandatory
// federation-tier ingest gate: hybrid-verify a federation-tier
// attestation's envelope signature against the attester's REGISTERED
// pubkeys at the bulk store/replicate path, BEFORE persist. Local-tier
// rows are exempt (CC 5.3.2.2 deferred signature). Sibling of
// `register::verify_key_registration`; same verify contract.
pub mod tier_ingest;
pub mod topology;
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
    check_cohort_scope, check_consensus_protocol_form, check_device_class,
    check_encryption_pubkeys, check_observed_region, AttestationLadderTransitionPolicy,
    DimensionAdmissionPolicy, DimensionRejectionReason, ReachabilityVerdict, ReservedPrefixRule,
    ATTESTATION_LADDER_MECHANISMS,
};
pub use blackhole::{BlackholeRecord, BlackholeRules, RETICULUM_IDENTITY_HASH_LEN};
pub use blobs::{
    holds_bytes_attestation_envelope, holds_bytes_attestation_type, BlobBody, BlobError, BlobRange,
    BlobStorage, ChunkManifest, ChunkRef, EvictActorReport, ExternalRef, GroupDekRef,
    PutBlobAttestation, ScopeBlobSymbol, CHUNK_MANIFEST_VERSION, DEFAULT_INLINE_BYTES_CAP,
    HOLDS_BYTES_ATTESTATION_TYPE_PREFIX, HOLDS_BYTES_PREFIX_HEX_LEN,
};
pub use cohort::{Cohort, GroupRef, GroupVersion, RevokeSpec, RosterMember};
pub use goal::{
    canonicalize_goal_text, DeliberationRef, Goal, GoalScope, GoalsFilter, M1Dimension,
    MetaGoalAlignment,
};
pub use hard_case::{ConsentState, ConsentWatchReport, HardCaseEvent, HardCaseFilter};
pub use hardware_attestation::{HardwareAttestationPolicy, DEFAULT_MAX_NONCE_AGE};
pub use identity_aggregate::{
    ContentKemIdentity, LocalIdentityAggregate, LOCAL_IDENTITY_AGGREGATE_VERSION,
};
pub use operational::{
    MergeIntent, OrgMembership, Organization, PartnerRecord, SignedOrgMembership,
    SignedOrganization, SignedPartnerRecord, SubjectKind,
};
pub use perceptual_hash::{
    HashDatabaseId, HashMatchError, HashMatchResult, MatcherUnreachablePolicy,
    NullPerceptualHashMatcher, OnMatchPolicy, PerceptualHashMatcher, SharedMatcher,
};
pub use register::verify_key_registration;
pub use replication::{
    aggregate_trust_score, classify_free_bytes, parse_human_bytes, withdraws_attestation_envelope,
    AdmissionGate, ByteParseError, CacheMode, DiskPressureConfig, DiskPressureMonitor,
    DiskPressureMonitorHandle, DiskPressureSnapshot, EvictionCandidate, EvictionDecay,
    EvictionSweeper, FamilyPredicate, FreeBytesSource, MemoryTrustScoring, PressureAction,
    PressureTier, ReplicationConfig, StatvfsFreeBytes, StubFreeBytes, SweepReport, TrustScoring,
    TrustScoringError, TrustTier, DEFAULT_SWEEP_BATCH, MIN_POLL_INTERVAL, MIN_SWEEP_INTERVAL,
};
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
    delegates_to_agent_envelope, delegates_to_envelope, partnership_accept_envelope,
    partnership_grant_envelope, TransportDestination, SELF_AT_LOGIN_DELEGATION_SCOPE,
};
pub use shared_instance::{SharedInstanceLease, DEFAULT_STALE_AFTER};
#[cfg(feature = "sqlite")]
pub use sqlite_open::FederationDirectorySqlite;
pub use stream_sth::{
    log_id_for_stream, parse_stream_id, recompute_and_assert_root, StreamChunkLeaf,
    STREAM_LOG_ID_PREFIX,
};
pub use tier_ingest::verify_federation_tier_ingest;
pub use topology::{
    build_delegation_graph, build_trust_topology, AuditChainEntry, AuditChainProof, DelegationEdge,
    DelegationGraph, EdgeType, FederationDirectoryFilter, TrustEdge, TrustNode, TrustTopology,
    WithdrawalEntry, MAX_DELEGATION_DEPTH,
};
pub use types::{device_class, identity_type};
pub use types::{
    Attestation, Community, CommunityMember, CommunityMembershipRevocation, EmitAttestationInput,
    EncryptionPubkeys, Family, FamilyMember, FamilyMembershipRevocation, HybridPendingRow,
    IdentityOccurrence, IdentityOccurrenceRevocation, KeyRecord, LocationProof, PeerMetadataRow,
    PeerPolicyBlob, Revocation, SignedAttestation, SignedCommunity,
    SignedCommunityMembershipRevocation, SignedFamily, SignedFamilyMembershipRevocation,
    SignedIdentityOccurrence, SignedIdentityOccurrenceRevocation, SignedKeyRecord,
    SignedLocationProof, SignedRevocation, TrustClass, TrustFilter, TrustGrant, TrustRelationship,
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
/// Gated to the backends that have an emit path: the sole caller
/// (`Engine::emit_attestation_assemble`) is
/// `#[cfg(any(feature = "postgres", feature = "sqlite"))]`, so without a
/// backend feature this function would be dead code (the crate denies it).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
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

    /// Fetch a single pubkey row by `key_id`. Returns `None` if absent.
    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<KeyRecord>, Error>;

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

    // ── Attestations ───────────────────────────────────────────────

    /// Insert a new attestation row.
    async fn put_attestation(&self, attestation: SignedAttestation) -> Result<(), Error>;

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
        let mut chain: Vec<Attestation> = Vec::new();
        for publisher in publishers {
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
    async fn put_identity_occurrence(
        &self,
        occurrence: SignedIdentityOccurrence,
    ) -> Result<(), Error>;

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
        Ok(self
            .lookup_identity_for_occurrence(occurrence_key_id)
            .await?
            .filter(|o| o.valid_until.is_none_or(|vu| vu > now))
            .and_then(|o| o.encryption_pubkeys))
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
    /// This is the forward-path half of a membership-change re-key: the
    /// at-rest cascade re-key
    /// ([`rekey_family_member_add`](crate::federation::at_rest_cascade::orchestrate::rekey_family_member_add))
    /// grants the newcomer *past* family blobs; `add_family_member` puts
    /// them on the roster so `resolve_recipients` includes them in
    /// *future* writes too. The re-key driver calls this first.
    async fn add_family_member(
        &self,
        family_key_id: &str,
        member: types::FamilyMember,
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
    async fn put_organization(
        &self,
        signed: SignedOrganization,
        key_directory: &[ciris_verify_core::threshold::ThresholdMember],
        root_stewards: &[String],
    ) -> Result<(), Error>;

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
    async fn put_org_membership(
        &self,
        signed: SignedOrgMembership,
        key_directory: &[ciris_verify_core::threshold::ThresholdMember],
        root_stewards: &[String],
    ) -> Result<(), Error>;

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
    async fn put_partner_record(
        &self,
        signed: SignedPartnerRecord,
        steward_roster: &[ciris_verify_core::threshold::ThresholdMember],
    ) -> Result<(), Error>;

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
    /// `since` filters on `asserted_at > since` (None = from the start);
    /// rows are returned ordered by `(asserted_at ASC, attestation_id
    /// ASC)` so the cursor is a stable resumption point. `limit` caps the
    /// page.
    async fn list_organizations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<Organization>, Error>;

    /// v5.1.0 (CIRISPersist#65, CIRISEdge#65 v2 bridge) — bulk-list
    /// `org_membership` rows since a cursor. Same ordering + cursor
    /// contract as [`Self::list_organizations_since`].
    async fn list_org_memberships_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<OrgMembership>, Error>;

    /// v5.1.0 (CIRISPersist#65, CIRISEdge#65 v2 bridge) — bulk-list
    /// `partner_record` rows since a cursor. Same ordering + cursor
    /// contract as [`Self::list_organizations_since`].
    async fn list_partner_records_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<PartnerRecord>, Error>;

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
    async fn list_signed_partner_records_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<SignedPartnerRecord>, Error>;

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
        let revoked: std::collections::HashSet<&str> = revs
            .iter()
            .filter(|r| r.effective_at <= now)
            .map(|r| r.occurrence_key_id.as_str())
            .collect();
        Ok(self
            .list_identity_occurrences_for(identity_key_id)
            .await?
            .into_iter()
            .filter(|o| !revoked.contains(o.occurrence_key_id.as_str()))
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
    async fn add_community_member(
        &self,
        community_key_id: &str,
        member: types::CommunityMember,
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
    async fn add_member(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        member: cohort::RosterMember,
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
                        removed_at: now,
                        effective_at,
                        reason,
                        witness_set,
                        persist_row_hash: String::new(),
                    },
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
                            removed_at: now,
                            effective_at,
                            reason,
                            witness_set,
                            persist_row_hash: String::new(),
                        },
                    },
                )
                .await?;
            }
            cohort::Cohort::SelfId => {
                self.put_identity_occurrence_revocation(
                    types::SignedIdentityOccurrenceRevocation {
                        identity_occurrence_revocation: types::IdentityOccurrenceRevocation {
                            identity_key_id: group_key_id.to_string(),
                            occurrence_key_id: removed_key_id.to_string(),
                            revoked_at: now,
                            effective_at,
                            reason,
                            witness_set,
                            persist_row_hash: String::new(),
                        },
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
    async fn swap_member(
        &self,
        cohort: cohort::Cohort,
        group_key_id: &str,
        out_key_id: &str,
        in_member: cohort::RosterMember,
        spec: cohort::RevokeSpec,
    ) -> Result<bool, Error> {
        if cohort == cohort::Cohort::SelfId {
            return Err(Error::InvalidArgument(
                "swap_member: the `self` cohort manages occurrences via \
                 put_identity_occurrence / put_identity_occurrence_revocation"
                    .to_string(),
            ));
        }
        self.revoke_member(cohort, group_key_id, out_key_id, spec)
            .await?;
        self.add_member(cohort, group_key_id, in_member).await
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
        let snapshot = serde_json::to_value(&new.family)
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
        let snapshot = serde_json::to_value(&new.community)
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
        let snapshot = serde_json::to_value(&new.community).map_err(|e| {
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
            let family_key_ids = self
                .list_families_for_member(&identity)
                .await?
                .into_iter()
                .map(|f| f.family_key_id);
            let community_key_ids = self
                .list_communities_for_member(&identity)
                .await?
                .into_iter()
                .map(|c| c.community_key_id);
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
    // Persist does NOT verify the cryptographic validity of the PQC
    // signature on attach — that's the writer's responsibility.
    // Persist verifies on read at the consumer's policy layer.

    /// Attach the PQC components to a hybrid-pending federation_keys row.
    /// Updates pubkey_ml_dsa_65_base64 + scrub_signature_pqc + pqc_completed_at.
    /// Errors if the row is already PQC-complete.
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
    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), Error>;

    /// Attach the PQC signature to a hybrid-pending
    /// `federation_revocations` row. Same shape as attestations.
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
    #[allow(clippy::too_many_arguments)]
    async fn promote_attestation(
        &self,
        attestation_id: &str,
        scrub_signature_classical: &str,
        scrub_signature_pqc: Option<&str>,
        original_content_hash_hex: &str,
        scrub_key_id: &str,
        scrub_timestamp: chrono::DateTime<chrono::Utc>,
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
    async fn grant_trust(&self, grant: TrustGrant) -> Result<(), Error> {
        let _ = grant;
        Err(Error::Backend(
            "grant_trust not implemented for this backend".into(),
        ))
    }

    /// Soft-delete a trust row by setting `expires_at = NOW()`.
    /// Idempotent — revoking an already-expired row is a no-op.
    async fn revoke_trust(&self, key: &str, revoked_by: &str) -> Result<(), Error> {
        let _ = (key, revoked_by);
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
    async fn remove_peer_record(&self, key_id: &str, hard: bool) -> Result<(), Error> {
        let _ = (key_id, hard);
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

    /// v6.5.0 (CIRISPersist#183, CEG §5.6.8.8.1) — register (or refresh)
    /// one reachable network address for an occurrence. **Idempotent on
    /// the `(occurrence_key_id, transport_kind, destination)` PK** — a
    /// re-assert updates `asserted_at` / `last_seen_at` in place. The
    /// occurrence key must exist in `federation_keys` (FK).
    ///
    /// Reachability is mutable + disposable (drop + re-register, not
    /// revoke), so this row carries no signature / `persist_row_hash`.
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

    /// v6.5.0 — list every reachable address registered for
    /// `occurrence_key_id` ("how do I reach this occurrence?"). Empty
    /// when none. Liveness filtering (on `last_seen_at` age) is
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

    /// v6.5.0 — drop one reachable address (e.g. a stale relay). Returns
    /// `true` if a row was removed, `false` if absent (idempotent).
    /// Default impl errors; the three backends override.
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
    async fn resolve_consent_state(
        &self,
        target_key_id: &str,
        subject_key_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<hard_case::ConsentState, Error> {
        // `dimension` is the envelope's "dimension" string (the same
        // axis admission keys on); read it straight off the stored
        // `attestation_envelope`.
        fn envelope_dimension(a: &Attestation) -> Option<&str> {
            a.attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str())
        }
        let rows = self.list_attestations_for(target_key_id).await?;
        let latest = rows
            .into_iter()
            .filter(|a| a.attesting_key_id == subject_key_id)
            .filter(|a| envelope_dimension(a).is_some_and(|d| d.starts_with("consent:state:")))
            .filter(|a| a.expires_at.is_none_or(|exp| exp > now))
            .max_by_key(|a| a.asserted_at);
        Ok(match latest.as_ref().and_then(envelope_dimension) {
            Some(d) if d.starts_with("consent:state:granted") => hard_case::ConsentState::Granted,
            Some(d) if d.starts_with("consent:state:revoked") => hard_case::ConsentState::Revoked,
            Some(d) if d.starts_with("consent:state:expired") => hard_case::ConsentState::Expired,
            // A consent:state:* whose value isn't in the closed set, or
            // no candidate at all → unspecified (forward-compat: an
            // unknown stance value never silently reads as granted).
            _ => hard_case::ConsentState::Unspecified,
        })
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
            let local = rev.tier != crate::federation::types::attestation_tier::FEDERATION;
            if local && rev.promoted_at.is_none() && now - revoked_at > promotion {
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

    /// Per-source-IP rate limit exceeded (default 60 writes/min/IP)
    /// or per-primitive write quota exceeded (default 10 keys/day).
    /// Caller should retry after `retry_after_seconds`.
    #[error("rate limited: retry after {retry_after_seconds}s")]
    RateLimited {
        /// Seconds the caller should wait before retrying.
        retry_after_seconds: u64,
    },

    /// Row would conflict with an existing row whose content differs.
    /// Idempotent re-submission of the *same* content is OK; this
    /// fires only when the caller is overwriting.
    #[error("conflicts with existing row: {0}")]
    Conflict(String),

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

    /// v8.9.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5). A `delegates_to`
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
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "federation_invalid_argument",
            Error::SignatureInvalid(_) => "federation_signature_invalid",
            Error::RateLimited { .. } => "federation_rate_limited",
            Error::Conflict(_) => "federation_conflict",
            Error::AccordDimensionRequiresAccordHolder { .. } => {
                "federation_accord_dimension_requires_accord_holder"
            }
            Error::DimensionRejected { .. } => "federation_dimension_rejected",
            Error::CapacitySelfEmissionRejected { .. } => {
                "federation_capacity_self_emission_rejected"
            }
            Error::ReservedPrefixEmitterMismatch { .. } => {
                "federation_reserved_prefix_emitter_mismatch"
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
            Error::DeviceClassRejected { .. } => "federation_device_class_rejected",
            Error::ConsensusProtocolMalformed { .. } => "federation_consensus_protocol_malformed",
            Error::WriteScopeRefused(_) => "federation_write_scope_refused",
            Error::ClockSkewViolation { .. } => "federation_clock_skew_violation",
            Error::PaymentProcessorIdentifier { .. } => "federation_payment_processor_identifier",
            Error::OperationalAuthority(_) => "federation_operational_authority",
            Error::PartnerRecordRollback { .. } => "federation_partner_record_rollback",
            Error::SetSemanticsUnsorted(_) => "federation_set_semantics_unsorted",
            Error::WithdrawsNotAdmitted { .. } => "federation_withdraws_not_admitted",
            Error::DelegatedScopeUnauthorized { .. } => "federation_delegated_scope_unauthorized",
            Error::NodeAgencyForbidden { .. } => "federation_node_agency_forbidden",
            Error::NodeAlreadyOwned { .. } => "federation_node_already_owned",
            Error::AmbiguousNodeOwner { .. } => "federation_ambiguous_node_owner",
            Error::UnstewardedCommunityMember { .. } => "federation_unstewarded_community_member",
            Error::UserTargetStewardBindingForbidden { .. } => {
                "federation_user_target_steward_binding_forbidden"
            }
            Error::CommunityHasNoModerator { .. } => "federation_community_no_moderator",
            Error::FederationTierUnverified { .. } => "federation_federation_tier_unverified",
            Error::WitnessAdmit(e) => e.kind(),
            Error::Backend(_) => "federation_backend",
            Error::Unsupported { .. } => "federation_ops_proxy_unsupported",
        }
    }
}
