//! In-memory Backend impl — for fast tests + parity-check fixtures.
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same trait surface as the Postgres + SQLite backends. The
//! conformance suite defined here runs against every backend; an
//! in-memory pass that disagrees with Postgres on the same inputs is
//! a mission-level signal (FSD §10 — "no flag-day at any phase"
//! depends on backend parity).
//!
//! Phase 1 status: implements the Phase 1 surface
//! (`insert_trace_events_batch`, `insert_trace_llm_calls_batch`,
//! `lookup_public_key`, `run_migrations`). Phase 2/3 surfaces inherit
//! the trait's `NotImplemented` defaults.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use ed25519_dalek::VerifyingKey;

use super::backend::{Backend, InsertReport};
use super::types::{TraceEventRow, TraceLlmCallRow};
use super::Error;
use crate::schema::ReasoningEventType;

/// Dedup-tuple shape for the in-memory event index. Mirrors
/// `super::decompose::dedup_key`'s return type and the V001 SQL
/// UNIQUE index `trace_events_dedup`. THREAT_MODEL.md AV-9.
type DedupKey = (String, String, String, ReasoningEventType, u32);

/// v21.0.0 (CIRISPersist#502 E4 followup) — one stored authority signature:
/// `(authority_key_id, scrub_signature_classical, scrub_signature_pqc)`.
/// Mirrors the V110 `authority_key_id` / `scrub_signature_{classical,pqc}`
/// columns added to the 5 E4 keyless-declaration tables (`federation_families`
/// / `federation_communities` / `federation_family_membership_revocations` /
/// `federation_community_membership_revocations` /
/// `federation_location_proofs`) — the fields `verify_family_admission` (and
/// its 4 siblings) verify at `put_family` etc. before this cut were verified
/// then discarded; now they're stored alongside the record.
type AuthoritySig = (String, String, Option<String>);

/// In-memory backend.
///
/// Locks: a single `Mutex` guards all state. This is fine for tests
/// (no contention); a real concurrent backend uses per-table locks
/// or, more typically, the SQL DB's own MVCC.
pub struct MemoryBackend {
    state: Mutex<State>,
    /// v22.0.0 (CIRISPersist#543) — hardware-attestation policy for
    /// `accord_holder` `put_public_key` admission, backend-symmetric with
    /// [`crate::store::sqlite::SqliteBackend`] (`sqlite.rs`) and the Postgres
    /// twin. Before this the memory backend admitted an `accord_holder` claim
    /// with NO hardware evidence at all — the exact "tested on one backend,
    /// used on the other" shape #518/#534/#536/#541 keep producing. Override
    /// via [`MemoryBackend::set_hardware_attestation_policy`].
    hardware_attestation_policy:
        std::sync::RwLock<std::sync::Arc<crate::federation::HardwareAttestationPolicy>>,
    /// v30.2.0 (CIRISPersist#607) — this node's own federation key id, set by
    /// the host via `set_node_key_id`. `None` until told, and gates that need
    /// it MUST fail secure rather than invent one.
    node_key_id: std::sync::RwLock<Option<String>>,
    /// v3.4.0 (CIRISPersist#123) — trust-weighted admission gate. `None` =
    /// no gate (bootstrap-permissive). See
    /// [`MemoryBackend::set_admission_gate`].
    ///
    /// v22.0.0 (CIRISPersist#543 finding 4): the memory backend had NO gate
    /// field, no accessor and no call site — `AdmissionGate::check_federation`
    /// simply never ran here, on any write path, since v3.4.0. Same
    /// recurrence class as #541.
    admission_gate: std::sync::RwLock<Option<crate::federation::AdmissionGate>>,
    /// v2.5.0 (CIRISPersist#102 Ask 4) — per-axis envelope-schema resolver.
    /// The default is [`crate::federation::NoOpSchemaResolver`], which makes
    /// the `put_attestation` validation hook a no-op (existing callers don't
    /// break). Override via [`MemoryBackend::set_schema_resolver`].
    ///
    /// v22.0.0 (CIRISPersist#543): the memory backend had no field, no
    /// accessor and no call site, so the `scores` envelope-schema gate never
    /// ran here — latent rather than live only because the default resolver
    /// answers `None`. Any host that installed a REAL resolver got schema
    /// enforcement on sqlite + postgres and silence on memory.
    schema_resolver: std::sync::RwLock<std::sync::Arc<dyn crate::federation::SchemaResolver>>,
    /// v22.0.0 (CIRISPersist#543 / AV-77) — this node's OWN federation key_id,
    /// installed by the host at construction. It is the only thing that lets
    /// the substrate tell "a de-admission I authored" from "a de-admission
    /// someone else authored about a third party" — de-admission is scoped to
    /// the emitting node's own corpus, so without knowing which rows are ours
    /// the set is empty and the gate is vacuous (correct, not fail-open: a
    /// node that has not declared an identity has authored no de-admissions).
    ///
    /// v22.0.0 (CIRISPersist#543): absent here entirely, so AV-77 — one of the
    /// five findings the CHANGELOG claims are "closed on all three backends" —
    /// was not closed on memory at all.
    self_key_id: std::sync::RwLock<Option<String>>,
    /// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — per-peer attestation
    /// write quota. Scoped to *this* backend instance rather than a process
    /// global (the [`Self::hardware_attestation_policy`] precedent): the
    /// quota is node-local admission state, and a global would leak one
    /// engine's traffic into another's budget — and one test's into the
    /// next's, which on the memory backend (the one every unit test reaches
    /// for) would be an immediate cross-test flake. Always on; the limit is
    /// a substrate constant, not an operator knob.
    peer_write_quota: crate::federation::replication::admission::PeerWriteQuota,
    /// (CIRISPersist#593) — how many times has
    /// [`FederationDirectory::list_attestations_by`] been called on this
    /// instance? See [`MemoryBackend::attestation_read_counts`]; this exists so
    /// a walk's read cost can be **measured** rather than estimated.
    ///
    /// [`FederationDirectory::list_attestations_by`]: crate::federation::FederationDirectory::list_attestations_by
    attestation_reads_by: std::sync::atomic::AtomicU64,
    /// (CIRISPersist#593) — the [`list_attestations_for`] twin.
    ///
    /// [`list_attestations_for`]: crate::federation::FederationDirectory::list_attestations_for
    attestation_reads_for: std::sync::atomic::AtomicU64,
}

struct State {
    /// Inserted `trace_events` rows, keyed by dedup tuple
    /// (THREAT_MODEL.md AV-9). See [`DedupKey`].
    events: HashMap<DedupKey, (i64, TraceEventRow)>,
    /// Inserted `trace_llm_calls` rows.
    llm_calls: Vec<TraceLlmCallRow>,
    /// Monotonic event_id counter (mimics Postgres BIGSERIAL).
    next_event_id: i64,
    /// Public-key directory (legacy `accord_public_keys` shape; used
    /// by the trace-verify path).
    keys: HashMap<String, VerifyingKey>,
    /// v0.2.0 — Federation directory `federation_keys` rows,
    /// keyed by `key_id`.
    federation_keys: HashMap<String, crate::federation::KeyRecord>,
    /// v1.3.0 (CIRISPersist#46 + #47) — Federation trust hierarchy
    /// rows, parallel to `federation_keys`. Same key (`key_id`)
    /// because V020 adds the trust columns to the same Postgres
    /// table; on the memory backend we keep them separately so the
    /// "row exists in directory but has no trust grant" case
    /// stays unambiguous.
    federation_trust: HashMap<String, crate::federation::TrustRow>,
    /// v0.2.0 — Federation `federation_attestations` rows,
    /// append-only.
    federation_attestations: Vec<crate::federation::Attestation>,
    /// v17.4.0 (V106) — the in-memory mirror of the `attestation_subjects`
    /// projection: `subject_key_id → [attestation_id, …]`. Maintained on every
    /// attestation write (put + local upsert/insert). Advisory: reads still
    /// scan `federation_attestations` (the authoritative store) so a stale
    /// entry can never yield a wrong row — it exists to make the projection
    /// backend-symmetric and inspectable.
    subject_index: HashMap<String, Vec<String>>,
    /// v17.8.0 (CIRISPersist#469) — announced/advisory LAN-peer bookmarks,
    /// keyed by `key_id`. Deliberately SEPARATE from `federation_keys`
    /// (never an authority; see the trait docs on `record_announced_peer`).
    announced_peers: HashMap<String, crate::federation::types::AnnouncedPeer>,
    /// v0.2.0 — Federation `federation_revocations` rows,
    /// append-only.
    federation_revocations: Vec<crate::federation::Revocation>,
    /// v3.1.0 (CIRISPersist#117) — Federation peer metadata, sibling
    /// to `federation_keys`. Keyed by `key_id`. Memory backend
    /// mirrors the V051 PG/SQLite shape: same fields, same soft-
    /// remove discipline (`removed_at`) so behavioral parity tests
    /// pass against any backend.
    federation_peer_metadata: HashMap<String, crate::federation::PeerMetadataRow>,
    /// v0.4.0 — Edge outbound queue (CIRISPersist#16). Same logical
    /// surface as `cirislens.edge_outbound_queue`. Keyed by
    /// queue_id. State-machine integrity enforced by the impl,
    /// matching the postgres CHECK constraints.
    outbound_queue: HashMap<String, crate::outbound::OutboundRow>,
    /// v2.10.0 (CIRISPersist#114) — Federation goals (`goals`).
    /// Keyed by `goal_id`. M-1 alignment is structurally guaranteed
    /// by [`crate::federation::Goal`]'s constructor; the memory shim
    /// stores the typed value verbatim.
    federation_goals: HashMap<uuid::Uuid, crate::federation::Goal>,
    /// v3.2.0 (CIRISPersist#120) — Per-identity Reticulum blackhole
    /// rules, keyed by the 16-byte identity hash. Mirrors the V052
    /// PG/SQLite shape so behavioral parity tests pass against any
    /// backend.
    blackhole_rules: HashMap<Vec<u8>, crate::federation::BlackholeRecord>,
    /// v3.12.0 (CIRISPersist#153 Ask 1, CEG 0.7 §5.6.8.8) —
    /// identity_occurrence bindings keyed by
    /// `(identity_key_id, occurrence_key_id)`. Memory backend mirrors
    /// the V059 PG/SQLite composite-PK shape.
    federation_identity_occurrences:
        HashMap<(String, String), crate::federation::IdentityOccurrence>,
    /// v14.1.0 (CIRISPersist#418, replication read) — signature container for
    /// signed-put occurrences, keyed like `federation_identity_occurrences`
    /// (`(attesting_key_id, signed_envelope, signature)`). Absent for
    /// trusted-local rows, so `list_signed_identity_occurrences_for` returns
    /// only what was signed-put. Superseded in lockstep with the projection
    /// under last-signed-wins; preserved on a local overwrite (matching the
    /// sqlite/postgres `DO UPDATE` that omits the sig columns).
    federation_identity_occurrence_sigs: HashMap<
        (String, String),
        (
            String,
            serde_json::Value,
            ciris_verify_core::transport_binding::TransportBindingSignature,
        ),
    >,
    /// v3.12.0 (CIRISPersist#153 Ask 2, CEG 0.7 §5.6.8.9) — family
    /// rows keyed by `family_key_id`. Mirrors V059 PG/SQLite PK.
    federation_families: HashMap<String, crate::federation::Family>,
    /// v4.0 (CEG 0.8 §8.1.13.3) — community rows keyed by
    /// `community_key_id`. Mirrors V060 PG/SQLite PK.
    federation_communities: HashMap<String, crate::federation::Community>,
    /// #249 Cut G2 — current live version per group, keyed by
    /// `(cohort, group_key_id)` (`cohort` ∈ `family`/`community`). Mirrors
    /// the V089 `version` column; absent ⇒ 1.
    federation_group_current_version: HashMap<(String, String), u32>,
    /// #249 Cut G2 (§8) — append-only superseded version history, keyed by
    /// `(cohort, group_key_id)`. Mirrors V089 `federation_group_versions`.
    federation_group_versions:
        HashMap<(String, String), Vec<crate::federation::cohort::GroupVersion>>,
    /// v4.8.0 (CIRISPersist#161, CEG §11.7.1) — Option-A forward-secrecy
    /// removal/revocation rows. Keyed by the V067 composite PKs.
    federation_identity_occurrence_revocations:
        HashMap<(String, String), crate::federation::IdentityOccurrenceRevocation>,
    /// v16.0.0 (CIRISPersist#421, replication read) — signature container for
    /// signed-put occurrence REVOCATIONS, keyed like the revocation map
    /// (`(attesting_key_id, signed_envelope, signature)`). Absent for
    /// trusted-local rows. Mirror of `federation_identity_occurrence_sigs`.
    federation_identity_occurrence_revocation_sigs: HashMap<
        (String, String),
        (
            String,
            serde_json::Value,
            ciris_verify_core::transport_binding::TransportBindingSignature,
        ),
    >,
    federation_family_membership_revocations:
        HashMap<(String, String), crate::federation::FamilyMembershipRevocation>,
    federation_community_membership_revocations:
        HashMap<(String, String), crate::federation::CommunityMembershipRevocation>,
    /// v9.0.0 G5 (CC 4.4.3.2.2) — the community DEK rotation epoch
    /// counter, `community_key_id -> current epoch`. The DEK crypto itself
    /// (V087 grants) lives only on the at-rest BlobStorage backends
    /// (postgres/sqlite); the MemoryBackend has no blob storage, so it
    /// carries the rotation *state* (so rotation-on-removal is observably
    /// PRESENT here too — the epoch advances) but not the wrapped DEK.
    federation_community_dek_epoch: HashMap<String, u64>,
    /// v4.10.0 (CIRISPersist#154) — location_proofs keyed by the V068
    /// `(subject_key_id, asserted_at)` PK.
    federation_location_proofs:
        HashMap<(String, chrono::DateTime<chrono::Utc>), crate::federation::LocationProof>,
    /// v5.1.0 (CIRISPersist#65, CEG 1.0-RC2 §5.6.8.13) — operational-data
    /// rows keyed by `attestation_id`.
    federation_organizations: HashMap<String, crate::federation::Organization>,
    federation_org_memberships: HashMap<String, crate::federation::OrgMembership>,
    federation_partner_records: HashMap<String, crate::federation::PartnerRecord>,
    /// v5.2.0 (#194) — the M-of-N steward signature set + threshold per
    /// partner_record `attestation_id`, so `list_signed_partner_records_since`
    /// reconstructs the full wrapper (the row map above holds only the
    /// unsigned [`PartnerRecord`]).
    federation_partner_record_sigs:
        HashMap<String, (Vec<ciris_verify_core::threshold::ThresholdSignature>, usize)>,
    /// v6.5.0 (CIRISPersist#183, CEG §5.6.8.8.1) — per-occurrence
    /// reachability rows. v17.0.0 (#443): keyed by the ROUTE-TABLE PK
    /// `(occurrence_key_id, transport_kind)` (`destination` is payload — one
    /// live route per peer per transport), superseded under the
    /// `(epoch, asserted_at)` monotonic guard. Parity with the
    /// postgres/sqlite `transport_destinations` table (V105).
    transport_destinations: HashMap<(String, String), crate::federation::TransportDestination>,
    /// v17.0.0 (CIRISPersist#443, replication read) — signature container for
    /// SIGNED-put routes, keyed like `transport_destinations`
    /// (`(attesting_key_id, signed_envelope, signature)`). Absent for
    /// trusted-local rows (and REMOVED when a local put supersedes a signed
    /// row — the container attested the old content), so
    /// `list_signed_transport_destinations_for` returns only what was
    /// signed-put. Mirror of `federation_identity_occurrence_sigs`.
    transport_destination_sigs: HashMap<
        (String, String),
        (
            String,
            serde_json::Value,
            ciris_verify_core::transport_binding::TransportBindingSignature,
        ),
    >,
    /// v21.6.0 (CIRISPersist#519 item 2a-iii) — the `freshness_floor` table
    /// (V112): the signed `fresh_as_of` touch-claim currently on file for
    /// each `(target_key_id, target_kind)`, monotonic-max merged in
    /// `put_touch_claim`. Parity with the postgres/sqlite `freshness_floor`
    /// table.
    freshness_floor: HashMap<(String, String), crate::federation::types::SignedTouchClaim>,
    /// v6.7.0 (CIRISPersist#146 Ask 3 / #161 Ask 5, CEG §7.7/§8.1.11.3) —
    /// the `hard_case:*` emission surface, keyed by the deterministic
    /// `event_id` (idempotent insert = no-op on conflict). Parity with the
    /// postgres/sqlite `hard_case_events` table (V075).
    federation_hard_case_events: HashMap<String, crate::federation::hard_case::HardCaseEvent>,
    /// v8.0.0 (CIRISPersist#227) — fountain `content_manifest` rows,
    /// keyed by the `(content_id, corpus_kind)` PK. NEVER evicted.
    /// Parity with the postgres/sqlite `content_manifest` table (V084).
    fountain_manifests: HashMap<(String, String), crate::fountain::FountainManifestV1>,
    /// v8.0.0 (CIRISPersist#227) — fountain `content_symbols` rows, keyed
    /// by `content_id`, inner map keyed by `symbol_id`. The rows
    /// pressure/decay evict (by `retention_priority DESC`). Parity with
    /// the postgres/sqlite `content_symbols` table (V084).
    fountain_symbols: HashMap<String, HashMap<u32, crate::fountain::FountainSymbolV1>>,
    /// v13.0.0 (§Q / CIRISPersist#370) — installed `StorageBudgetV1` pin
    /// state, keyed by owner `node_id`. Parity with the postgres/sqlite
    /// `storage_budget_installed` table (V093). Replaced only by a
    /// strictly-higher revision (§Q B3 anti-rollback).
    installed_storage_budgets:
        HashMap<String, crate::fountain::storage_contention::InstalledStorageBudget>,
    /// #227 (residual) — the admission wall-clock per `(content_id,
    /// corpus_kind)`, the decay reference instant for the consent-decay
    /// clock. Parity with the pg/sqlite `content_manifest.admitted_at`
    /// column (which memory's `FountainHeldMeta` view stubs to empty).
    fountain_admitted_at: HashMap<(String, String), chrono::DateTime<chrono::Utc>>,
    /// v8.2.0 (CEG 1.0-RC11 §19.1 / CIRISPersist#228) — WholenessWitness
    /// corpus, keyed by `peer_id`, inner vec the last-K verified witnesses
    /// (newest last). Parity with the postgres/sqlite
    /// `wholeness_witness_corpus` table (V085). Every entry already passed
    /// the verify-before-persist gate (no in-band `verified` flag — F-5).
    wholeness_witnesses: HashMap<String, Vec<crate::witness::StoredWitness>>,
    /// v8.3.0 (CEG 1.0-RC12 §19.7 / CIRISPersist#230) — §19.7 inter-object
    /// aggregation records, keyed by the composite's `aggregate_content_id`
    /// (the PK). Parity with the postgres/sqlite `content_aggregation`
    /// table (V086). `aggregation_meta` is OPAQUE bytes persist never
    /// parses.
    content_aggregations: HashMap<String, crate::fountain::AggregationRecordV1>,
    /// v9.1.0 (CC 1.13.3 / FSD §2.4, CIRISPersist#243) — scope-blob symbol
    /// store, keyed by `(record_id, symbol_index)` (the PK), degraded-but-
    /// present parity with the pg/sqlite `federation_scope_blobs` table.
    /// `BlobStorage` itself is pg/sqlite-only (the at-rest backends), so the
    /// scope-blob surface lives as inherent methods here — mirroring how the
    /// community-DEK rotation *state* (`federation_community_dek_epoch`) is
    /// carried on memory while its crypto half is BlobStorage-only.
    federation_scope_blobs: HashMap<([u8; 32], u16), MemScopeBlob>,
    /// #302 (FSD-004) — accord live-quorum storage, parity with the
    /// pg/sqlite V091 tables. Proposals keyed by `proposal_digest`;
    /// participations a flat vec (deduped by `(proposal_digest,
    /// pinned_pubkey)` at write time, M6); decisions keyed by
    /// `proposal_digest` (immutable, M2); active halts keyed by family (H2);
    /// issued nonces a `(family_key_id, nonce)` set (M4).
    accord_proposals: HashMap<String, crate::federation::accord_quorum::StoredProposal>,
    accord_participations: Vec<crate::federation::accord_quorum::StoredParticipation>,
    accord_decisions: HashMap<String, crate::federation::accord_quorum::StoredDecision>,
    accord_active_halts: HashMap<String, crate::federation::accord_quorum::ActiveHalt>,
    accord_issued_nonces: std::collections::HashSet<(String, String)>,
    /// #377 — canonical-role WITHDRAW/SUPERSEDE tombstones (V095), keyed by the
    /// withdrawn `key_id`. The in-memory mirror of `canonical_role_withdrawal`.
    canonical_withdrawals: HashMap<String, crate::federation::CanonicalWithdrawal>,
    /// v16.0.0 (CIRISPersist#424) — generic role-withdrawal tombstones (V104
    /// mirror), keyed `(role, key_id)`.
    role_withdrawals: HashMap<(String, String), crate::federation::admission::RoleWithdrawal>,
    /// v21.0.0 (CIRISPersist#502 E7) — the in-memory mirror of the V109
    /// `consent_peer_set` projection: the node's live `consent:replication:v1`
    /// peer grants, revocation-folded. Maintained on every `put_attestation`
    /// (grant upsert / withdraws-revocation fold), same as the SQL backends'
    /// `consent_peer_set` table. See `crate::federation::consent_peer_set`.
    consent_peer_set: Vec<ConsentPeerRow>,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — the authority
    /// signature `put_family` verified at admission, keyed by
    /// `family_key_id`. Absent for `put_family_local` genesis-bake rows
    /// (legitimately unsigned — mirrors `federation_identity_occurrence_sigs`'s
    /// "absent for trusted-local rows" convention).
    federation_family_authority_sigs: HashMap<String, AuthoritySig>,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — structural
    /// mirror of `federation_family_authority_sigs`, keyed by
    /// `community_key_id`.
    federation_community_authority_sigs: HashMap<String, AuthoritySig>,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — structural
    /// mirror, keyed like `federation_family_membership_revocations`.
    federation_family_membership_revocation_authority_sigs: HashMap<(String, String), AuthoritySig>,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — structural
    /// mirror, keyed like `federation_community_membership_revocations`.
    federation_community_membership_revocation_authority_sigs:
        HashMap<(String, String), AuthoritySig>,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — structural
    /// mirror, keyed like `federation_location_proofs`.
    federation_location_proof_authority_sigs:
        HashMap<(String, chrono::DateTime<chrono::Utc>), AuthoritySig>,
    /// v21.1.0 (CIRISPersist#507b, V111 mirror) — the shared signed-wire
    /// content-hash index: `(kind, content_hash) -> record_key`. Memory
    /// mirror of the `signed_wire_index` table.
    signed_wire_index: HashMap<(String, String), String>,
}

/// v21.0.0 (CIRISPersist#502 E7) — one row of the in-memory
/// `consent_peer_set` mirror. Mirrors the V109 table shape exactly.
#[derive(Clone)]
struct ConsentPeerRow {
    node_key_id: String,
    peer_key_id: String,
    source_attestation_id: String,
    /// Kept for V109 table-shape parity with the SQL backends;
    /// `list_consent_peers` returns only the peer set (a name, not a
    /// recency), so this is written but not read back.
    #[allow(dead_code)]
    asserted_at: chrono::DateTime<chrono::Utc>,
}

/// v9.1.0 (CIRISPersist#243) — one in-memory scope-blob symbol + its LRU
/// access clock. `last_accessed_at` is bumped on read so the in-memory
/// eviction mirrors the pg/sqlite LRU discipline.
#[derive(Clone)]
struct MemScopeBlob {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
    group_dek_epoch: u64,
    admitted_at: chrono::DateTime<chrono::Utc>,
    last_accessed_at: chrono::DateTime<chrono::Utc>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                events: HashMap::new(),
                llm_calls: Vec::new(),
                next_event_id: 1,
                keys: HashMap::new(),
                federation_keys: HashMap::new(),
                federation_attestations: Vec::new(),
                subject_index: HashMap::new(),
                announced_peers: HashMap::new(),
                federation_revocations: Vec::new(),
                federation_trust: HashMap::new(),
                outbound_queue: HashMap::new(),
                federation_goals: HashMap::new(),
                federation_peer_metadata: HashMap::new(),
                federation_identity_occurrences: HashMap::new(),
                federation_identity_occurrence_sigs: HashMap::new(),
                federation_families: HashMap::new(),
                federation_communities: HashMap::new(),
                federation_group_current_version: HashMap::new(),
                federation_group_versions: HashMap::new(),
                federation_identity_occurrence_revocations: HashMap::new(),
                federation_identity_occurrence_revocation_sigs: HashMap::new(),
                federation_family_membership_revocations: HashMap::new(),
                federation_community_membership_revocations: HashMap::new(),
                federation_community_dek_epoch: HashMap::new(),
                federation_location_proofs: HashMap::new(),
                federation_organizations: HashMap::new(),
                federation_org_memberships: HashMap::new(),
                federation_partner_records: HashMap::new(),
                federation_partner_record_sigs: HashMap::new(),
                blackhole_rules: HashMap::new(),
                transport_destinations: HashMap::new(),
                transport_destination_sigs: HashMap::new(),
                freshness_floor: HashMap::new(),
                federation_hard_case_events: HashMap::new(),
                fountain_manifests: HashMap::new(),
                fountain_symbols: HashMap::new(),
                installed_storage_budgets: HashMap::new(),
                fountain_admitted_at: HashMap::new(),
                wholeness_witnesses: HashMap::new(),
                content_aggregations: HashMap::new(),
                federation_scope_blobs: HashMap::new(),
                accord_proposals: HashMap::new(),
                accord_participations: Vec::new(),
                accord_decisions: HashMap::new(),
                accord_active_halts: HashMap::new(),
                accord_issued_nonces: std::collections::HashSet::new(),
                canonical_withdrawals: HashMap::new(),
                role_withdrawals: HashMap::new(),
                consent_peer_set: Vec::new(),
                federation_family_authority_sigs: HashMap::new(),
                federation_community_authority_sigs: HashMap::new(),
                federation_family_membership_revocation_authority_sigs: HashMap::new(),
                federation_community_membership_revocation_authority_sigs: HashMap::new(),
                federation_location_proof_authority_sigs: HashMap::new(),
                signed_wire_index: HashMap::new(),
            }),
            hardware_attestation_policy: std::sync::RwLock::new(std::sync::Arc::new(
                crate::federation::HardwareAttestationPolicy::default(),
            )),
            node_key_id: std::sync::RwLock::new(None),
            admission_gate: std::sync::RwLock::new(None),
            schema_resolver: std::sync::RwLock::new(std::sync::Arc::new(
                crate::federation::NoOpSchemaResolver,
            )),
            self_key_id: std::sync::RwLock::new(None),
            peer_write_quota: crate::federation::replication::admission::PeerWriteQuota::new(),
            attestation_reads_by: std::sync::atomic::AtomicU64::new(0),
            attestation_reads_for: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl MemoryBackend {
    /// Create an empty memory backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// v31.0.0 (CIRISPersist#646) — the memory twin of
    /// `PostgresBackend`/`SqliteBackend::index_stored_record`: reload the row
    /// through the read path's own dispatcher and index the bytes it returns.
    /// See
    /// [`wire_index::entry_as_stored`](crate::federation::wire_index::entry_as_stored).
    ///
    /// Memory rounds nothing and normalizes nothing, so this backend is where
    /// the defect never bit — which is exactly why it must run the same
    /// derivation. A rule only the failing backend follows is a rule the next
    /// writer will not know about, and memory is the CONTROL every witness
    /// compares against: it has to be running the code under test.
    ///
    /// The state `Mutex` is not reentrant and the reload takes it, so every
    /// caller must have released its guard before awaiting this — which is also
    /// what keeps these futures `Send`.
    async fn index_stored_record(
        &self,
        kind: &str,
        record_key_json: &str,
    ) -> Result<(), crate::federation::Error> {
        if let Some(content_hash) =
            crate::federation::wire_index::entry_as_stored(self, kind, record_key_json).await?
        {
            self.state
                .lock()
                .expect("memory backend lock")
                .signed_wire_index
                .insert((kind.to_owned(), content_hash), record_key_json.to_owned());
        }
        Ok(())
    }

    /// v31.0.0 (CIRISPersist#646) — the Key-plane shorthand for
    /// [`index_stored_record`](Self::index_stored_record).
    async fn index_stored_key_row(&self, key_id: &str) -> Result<(), crate::federation::Error> {
        self.index_stored_record(
            "Key",
            &crate::federation::wire_index::record_key(&[("key_id", key_id)]),
        )
        .await
    }

    /// (CIRISPersist#593) — snapshot `(list_attestations_by,
    /// list_attestations_for)` call counts for this instance.
    ///
    /// A directory-read counter, not a walk-internal one: it counts what the
    /// substrate was actually asked for, so a claim like *"the moderation walk
    /// costs at most 2× the reads it used to"* is a measurement rather than an
    /// estimate. Two relaxed atomic increments inside methods that already take
    /// the state mutex — no meaningful cost, and the memory backend is the one
    /// every test reaches for.
    #[must_use]
    pub fn attestation_read_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.attestation_reads_by.load(Ordering::Relaxed),
            self.attestation_reads_for.load(Ordering::Relaxed),
        )
    }

    /// (CIRISPersist#593) — zero both counters, so a measurement can start at a
    /// known point after the fixture has finished writing.
    pub fn reset_attestation_read_counts(&self) {
        use std::sync::atomic::Ordering;
        self.attestation_reads_by.store(0, Ordering::Relaxed);
        self.attestation_reads_for.store(0, Ordering::Relaxed);
    }

    /// v22.0.0 (CIRISPersist#543) — install a custom hardware-attestation
    /// policy. Mirrors [`crate::store::sqlite::SqliteBackend::set_hardware_attestation_policy`].
    pub fn set_hardware_attestation_policy(
        &self,
        policy: std::sync::Arc<crate::federation::HardwareAttestationPolicy>,
    ) {
        *self
            .hardware_attestation_policy
            .write()
            .unwrap_or_else(|p| p.into_inner()) = policy;
    }

    /// v30.2.0 (CIRISPersist#607) — tell this backend which federation key IS
    /// this node.
    ///
    /// Required before any reserved-prefix rule carrying a
    /// `required_delegation_scope` can admit: resolving "does THIS NODE trust
    /// the root that conferred the emitter's role" needs an identity to ask on
    /// behalf of, and asking on behalf of the ATTESTER is answered by rows the
    /// attester signs itself.
    ///
    /// Set by the host (`Engine`), never inferred here. A backend that guesses
    /// its own identity is a backend that can be told the wrong one.
    pub fn set_node_key_id(&self, key_id: impl Into<String>) {
        *self.node_key_id.write().expect("node_key_id lock") = Some(key_id.into());
    }

    /// Snapshot the currently-installed hardware-attestation policy.
    pub fn hardware_attestation_policy(
        &self,
    ) -> std::sync::Arc<crate::federation::HardwareAttestationPolicy> {
        self.hardware_attestation_policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v3.4.0 (CIRISPersist#123) — install the trust-weighted
    /// [`AdmissionGate`](crate::federation::AdmissionGate). Passing `None`
    /// clears the gate (bootstrap-permissive). Mirrors
    /// [`crate::store::sqlite::SqliteBackend::set_admission_gate`].
    pub fn set_admission_gate(&self, gate: Option<crate::federation::AdmissionGate>) {
        *self
            .admission_gate
            .write()
            .unwrap_or_else(|p| p.into_inner()) = gate;
    }

    /// Snapshot of the currently-installed admission gate, if any.
    pub fn admission_gate(&self) -> Option<crate::federation::AdmissionGate> {
        self.admission_gate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v22.0.0 (CIRISPersist#543 / AV-77) — declare this node's own federation
    /// key_id, enabling the de-admission gate
    /// ([`crate::federation::admission::check_peer_deadmission`]). Mirrors
    /// [`crate::store::sqlite::SqliteBackend::set_self_key_id`].
    pub fn set_self_key_id(&self, key_id: Option<String>) {
        *self.self_key_id.write().unwrap_or_else(|p| p.into_inner()) = key_id;
    }

    /// This node's declared own key_id, if the host installed one.
    pub fn self_key_id(&self) -> Option<String> {
        self.self_key_id
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v2.5.0 (CIRISPersist#102 Ask 4) — install a per-axis envelope-schema
    /// resolver for the `put_attestation` admission hook. Mirrors
    /// [`crate::store::sqlite::SqliteBackend::set_schema_resolver`].
    pub fn set_schema_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::federation::SchemaResolver>,
    ) {
        *self
            .schema_resolver
            .write()
            .unwrap_or_else(|p| p.into_inner()) = resolver;
    }

    /// Snapshot the currently-installed schema resolver.
    pub fn schema_resolver(&self) -> std::sync::Arc<dyn crate::federation::SchemaResolver> {
        self.schema_resolver
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v22.0.0 (CIRISPersist#543) — genesis-trusted seed of the
    /// HUMANITY_ACCORD holder rooting-anchor rows, the memory twin of
    /// [`crate::store::sqlite::SqliteBackend::seed_genesis_accord_holders`].
    ///
    /// Skips ONLY the per-registration `accord_holder` fresh-nonce hardware
    /// gate that `put_public_key` enforces — the pinned #268 ceremony bake IS
    /// the trust root, so re-verifying its (stale-by-design) custody
    /// attestation at every boot is a category error. Every OTHER invariant
    /// still applies: the pubkey must decode to 32 bytes, the algorithm must
    /// be hybrid, and the consent_role token must be admissible. Idempotent
    /// on `key_id` (mirrors `ON CONFLICT (key_id) DO NOTHING`).
    pub async fn seed_genesis_accord_holders(
        &self,
        records: &[crate::federation::SignedKeyRecord],
    ) -> Result<(), crate::federation::Error> {
        for sr in records {
            let mut row = sr.record.clone();
            crate::federation::register::validate_registration_pubkey(&row)?;
            if row.algorithm != crate::federation::types::algorithm::HYBRID {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "genesis seed algorithm must be 'hybrid' (got '{}')",
                    row.algorithm
                )));
            }
            crate::federation::types::consent_role::check_admissible(row.consent_role.as_deref())?;
            row.consent_role = row
                .consent_role
                .as_deref()
                .and_then(crate::federation::types::consent_role::wire_from_stored)
                .map(str::to_owned);
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            let mut state = self.state.lock().expect("memory backend lock");
            state
                .federation_keys
                .entry(row.key_id.clone())
                .or_insert(row);
        }
        Ok(())
    }

    // ── v9.1.0 (CC 1.13.3 / FSD §2.4, CIRISPersist#243) scope-blob store ──
    //
    // Inherent methods (NOT a BlobStorage impl — that trait is pg/sqlite-
    // only). Degraded-but-present parity so the scope-native-privacy
    // surface is testable on all three backends with no pg/sqlite
    // asymmetry. Same behaviors as the pg/sqlite trait methods: opaque
    // ciphertext round-trip, first-write-wins idempotency on
    // (record_id, symbol_index), reads bump the LRU clock, LRU+capacity
    // eviction (no trust-scoring).

    /// Admit one symbol-AEAD-encrypted symbol; first-write-wins on
    /// `(record_id, symbol_index)`.
    pub fn put_scope_blob(
        &self,
        record_id: [u8; 32],
        symbol_index: u16,
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
        tag: [u8; 16],
        group_dek_ref: crate::federation::GroupDekRef,
    ) -> Result<(), crate::federation::BlobError> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        // DO NOTHING on conflict: a redundant re-put never resets the LRU
        // clock (only genuine reads bump last_accessed_at).
        state
            .federation_scope_blobs
            .entry((record_id, symbol_index))
            .or_insert(MemScopeBlob {
                nonce,
                ciphertext,
                tag,
                group_dek_epoch: group_dek_ref.epoch,
                admitted_at: now,
                last_accessed_at: now,
            });
        Ok(())
    }

    /// Read one symbol back; bumps its LRU clock. `None` if absent.
    pub fn get_scope_blob(
        &self,
        record_id: [u8; 32],
        symbol_index: u16,
    ) -> Result<Option<crate::federation::ScopeBlobSymbol>, crate::federation::BlobError> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        match state
            .federation_scope_blobs
            .get_mut(&(record_id, symbol_index))
        {
            None => Ok(None),
            Some(b) => {
                b.last_accessed_at = now;
                Ok(Some(crate::federation::ScopeBlobSymbol {
                    symbol_index,
                    nonce: b.nonce,
                    ciphertext: b.ciphertext.clone(),
                    tag: b.tag,
                    group_dek_epoch: b.group_dek_epoch,
                }))
            }
        }
    }

    /// List every symbol for `record_id`, ordered by `symbol_index` ASC;
    /// bumps the LRU clock on each.
    pub fn list_scope_blob_symbols(
        &self,
        record_id: [u8; 32],
    ) -> Result<Vec<crate::federation::ScopeBlobSymbol>, crate::federation::BlobError> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<crate::federation::ScopeBlobSymbol> = state
            .federation_scope_blobs
            .iter_mut()
            .filter(|((rid, _), _)| *rid == record_id)
            .map(|((_, sidx), b)| {
                b.last_accessed_at = now;
                crate::federation::ScopeBlobSymbol {
                    symbol_index: *sidx,
                    nonce: b.nonce,
                    ciphertext: b.ciphertext.clone(),
                    tag: b.tag,
                    group_dek_epoch: b.group_dek_epoch,
                }
            })
            .collect();
        out.sort_by_key(|s| s.symbol_index);
        Ok(out)
    }

    /// Capacity-bound LRU eviction: keep the newest `max_symbols` (by
    /// `last_accessed_at`), delete the coldest rest; returns the count
    /// deleted. Pure LRU + capacity, no trust-scoring (#243 §1).
    pub fn evict_scope_blobs(&self, max_symbols: u64) -> Result<u64, crate::federation::BlobError> {
        let mut state = self.state.lock().expect("memory backend lock");
        let total = state.federation_scope_blobs.len() as u64;
        if total <= max_symbols {
            return Ok(0);
        }
        // Rank keys by (last_accessed_at DESC, admitted_at DESC); the keys
        // past the capacity bound are the eviction set.
        let mut keys: Vec<([u8; 32], u16)> = state.federation_scope_blobs.keys().copied().collect();
        keys.sort_by(|a, b| {
            let ba = &state.federation_scope_blobs[a];
            let bb = &state.federation_scope_blobs[b];
            bb.last_accessed_at
                .cmp(&ba.last_accessed_at)
                .then(bb.admitted_at.cmp(&ba.admitted_at))
        });
        let to_evict: Vec<([u8; 32], u16)> = keys.into_iter().skip(max_symbols as usize).collect();
        let mut deleted = 0u64;
        for k in to_evict {
            if state.federation_scope_blobs.remove(&k).is_some() {
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// v9.0.0 G5 (CC 4.4.3.2.2) — the current community DEK rotation epoch
    /// for `community_key_id` (0 if it was never rotated). The MemoryBackend
    /// has no at-rest BlobStorage, so it carries only the rotation *state*
    /// (advanced on every `put_community_membership_revocation`); the actual
    /// per-epoch DEK + member grants live on the postgres/sqlite backends.
    /// This accessor makes the rotation observable for parity assertions.
    pub fn community_dek_epoch(&self, community_key_id: &str) -> u64 {
        self.state
            .lock()
            .expect("memory backend lock")
            .federation_community_dek_epoch
            .get(community_key_id)
            .copied()
            .unwrap_or(0)
    }

    /// v4.4.0 (CIRISPersist#171) — local-tier write (upsert/insert)
    /// parity with the sqlite/postgres backends. `async` since v12.6.0: a
    /// subject-side revocation transiting the local tier is hybrid-verified
    /// (resolving pubkeys via the directory) before it is written.
    async fn memory_write_local_attestation(
        &self,
        input: crate::federation::types::LocalAttestationInput,
        replace: bool,
    ) -> Result<String, crate::federation::Error> {
        use crate::federation::Error;

        // v17.9.0 (CC#38 interim) — envelope size cap FIRST, before any
        // parsing/lookups (cheapest-most-specific-rejection-first).
        // v20.0.0 (#495): the input envelope is TYPED (EnvelopeCore);
        // serialize once for the Value-based admission checks.
        let envelope_value = input.attestation_envelope.to_value();
        crate::federation::admission::check_envelope_size_admission(&envelope_value)?;
        crate::federation::admission::check_trace_dimension_admission(
            input.dimension(),
            &input.attesting_key_id,
            &input.subject_key_ids,
            &envelope_value,
        )?;
        crate::federation::trust_root::check_trust_charter_admission(
            self,
            &input.attestation_type,
            &input.attesting_key_id,
            input
                .attested_key_id
                .as_deref()
                .unwrap_or(&input.attesting_key_id),
            &envelope_value,
        )
        .await?;
        let dimension = input.dimension().map(|s| s.to_string()).ok_or_else(|| {
            Error::InvalidArgument(
                "local attestation envelope must carry a \"dimension\" string".into(),
            )
        })?;
        let disposition = crate::federation::admission::check_local_tier_eligibility(
            &input.attestation_type,
            Some(dimension.as_str()),
            &input.attesting_key_id,
            &input.subject_key_ids,
            &input.cohort_scope,
        )?;
        crate::federation::admission::check_cohort_scope(&input.cohort_scope)?;

        // v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — a subject-side
        // revocation MAY *transit* the local write path only if its bound-hybrid
        // signature verifies (accept on VALID crypto only; the operator gate).
        // Runs BEFORE the state lock (verify resolves pubkeys via the directory,
        // which locks itself). `None` for a durable producer-authority row.
        let transit = crate::federation::admission::verify_local_transit_revocation(
            self,
            disposition,
            &input,
        )
        .await?;

        // v24.0.0 (CIRISPersist#557) — the attested SUBJECT rule, shared with
        // sqlite + postgres and with the federation write path. BEFORE the state
        // lock: the predicate reads the directory, which locks itself.
        crate::federation::admission::check_attested_subject_admission(
            self,
            input
                .attested_key_id
                .as_deref()
                .unwrap_or(&input.attesting_key_id),
        )
        .await?;

        let mut state = self.state.lock().expect("memory backend lock");
        let identity_type = match state.federation_keys.get(&input.attesting_key_id) {
            Some(rec) => rec.identity_type.clone(),
            None => {
                return Err(Error::InvalidArgument(format!(
                    "attesting_key_id {} does not exist in federation_keys",
                    input.attesting_key_id
                )))
            }
        };
        let dim = input.dimension();
        crate::federation::admission::DimensionAdmissionPolicy::default().check(
            &input.attestation_type,
            dim,
            &identity_type,
        )?;
        // attested_key_id (defaults to attesting) was checked above by
        // `check_attested_subject_admission` — one predicate, one impl (v24.0.0,
        // CIRISPersist#557).

        // v18.0.0 (#473) — caller-supplied deterministic id (replay-idempotent
        // trace ingest) or the classic fresh v4.
        let attestation_id = input
            .attestation_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let attesting_key_id = input.attesting_key_id.clone();
        // v31.0.0 (CIRISPersist#598) — the row instant comes from the SIGNED
        // envelope when it carries one (see `admission::local_row_instant`), so
        // a `consent:state:*` row staged at the local tier can still satisfy
        // the instant binding at the promote door.
        let now =
            crate::federation::admission::local_row_instant(&envelope_value, chrono::Utc::now())?;
        let mut row = match transit {
            Some((hash, sig_classical, sig_pqc)) => input.into_transit_revocation_row(
                attestation_id.clone(),
                now,
                hash,
                sig_classical,
                sig_pqc,
            ),
            None => input.into_local_row(attestation_id.clone(), now),
        };
        // v31.0.0 (CIRISPersist#598) — the same binding the federation door
        // asks, asked at the local door too: a `consent:state:*` row that
        // cannot state its own signed instant is refused where it is written,
        // not where it is promoted.
        crate::federation::admission::check_consent_state_instant_binding(
            &row,
            chrono::Utc::now(),
            crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
        )?;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        // v18.0.0 (#473) — replay idempotence for caller-supplied DETERMINISTIC
        // ids (the trace-ingest mint): an existing attestation_id is a no-op
        // success, mirroring sqlite's INSERT OR IGNORE / pg's ON CONFLICT DO
        // NOTHING.
        if state
            .federation_attestations
            .iter()
            .any(|a| a.attestation_id == row.attestation_id)
        {
            return Ok(attestation_id);
        }

        if replace {
            state.federation_attestations.retain(|a| {
                !(a.attesting_key_id == attesting_key_id
                    && a.tier == crate::federation::types::attestation_tier::LOCAL
                    && a.attestation_envelope
                        .get("dimension")
                        .and_then(|v| v.as_str())
                        == Some(dimension.as_str()))
            });
        }
        // v17.4.0 (V106) — maintain the subject-index mirror at local tier.
        for subj in &row.subject_key_ids {
            state
                .subject_index
                .entry(subj.clone())
                .or_default()
                .push(row.attestation_id.clone());
        }
        state.federation_attestations.push(row);
        Ok(attestation_id)
    }

    /// Register a public key. For test fixtures. v0.4.0 — writes to
    /// federation_keys (the canonical pubkey directory post-lens#8
    /// ASK 2). Pre-v0.4.0 wrote to a separate `keys` map; the legacy
    /// fallback was retired in this release. The `keys` field stays
    /// on the State struct so existing tests that build via this
    /// helper continue to work; lookup_public_key reads only from
    /// federation_keys.
    pub fn add_public_key(&self, key_id: &str, key: VerifyingKey) {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let mut state = self.state.lock().expect("memory backend lock");
        let pubkey_b64 = BASE64.encode(key.to_bytes());
        // Write a minimal federation_keys row matching the test
        // fixture shape. The v0.2.0 federation directory schema
        // requires more fields; we fill them with stub-but-valid
        // values appropriate for test scope. Production callers go
        // through Engine.put_public_key with full SignedKeyRecord.
        let now = chrono::Utc::now();
        let rec = crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: pubkey_b64,
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: "agent".to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: hex::encode([0u8; 32]),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        state.federation_keys.insert(key_id.to_owned(), rec);
        // Keep the legacy map populated too — some tests still
        // reference it via `state.keys`. Single source of truth at
        // verify is federation_keys; this is just bookkeeping.
        state.keys.insert(key_id.to_owned(), key);
    }

    /// v1.3.0 (CIRISPersist#46) — test helper to grant a key the
    /// supplied role tags. Mutates the existing `federation_keys`
    /// row's `roles` column; called after [`add_public_key`] by tests
    /// that exercise the role-tag enforcement on pipeline / secrets
    /// routes. Panics if the key isn't already present.
    pub fn set_roles(&self, key_id: &str, roles: Vec<String>) {
        let mut state = self.state.lock().expect("memory backend lock");
        let rec = state
            .federation_keys
            .get_mut(key_id)
            .expect("set_roles: key_id must exist via add_public_key first");
        rec.capability_roles = roles;
    }

    /// v4.0 (CIRISPersist#160, FSD §4.6) — test helper: declare a
    /// community whose roster contains `member_identity_key_ids`, so the
    /// write-path cohort_scope gate sees the writer as a member. Inserts
    /// directly into the in-memory roster (skips the `put_community` FK +
    /// admission path — pure membership fixture for the AV-45 ingest
    /// tests). Used by the trace-ingest write-gate tests.
    pub fn add_community_membership(
        &self,
        community_key_id: &str,
        member_identity_key_ids: &[&str],
    ) {
        let now = chrono::Utc::now();
        let members = member_identity_key_ids
            .iter()
            .map(|k| crate::federation::types::CommunityMember {
                key_id: (*k).to_owned(),
                joined_at: now,
                role: None,
            })
            .collect();
        let community = crate::federation::Community {
            community_key_id: community_key_id.to_owned(),
            community_name: format!("test-community:{community_key_id}"),
            members,
            founded_at: now,
            consensus_protocol: "founder_only".to_owned(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        let mut state = self.state.lock().expect("memory backend lock");
        state
            .federation_communities
            .insert(community_key_id.to_owned(), community);
    }

    /// Snapshot of inserted event rows. For tests.
    pub fn snapshot_events(&self) -> Vec<TraceEventRow> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state.events.values().map(|(_, r)| r.clone()).collect();
        rows.sort_by_key(|a| a.ts);
        rows
    }

    /// Snapshot of inserted llm-call rows. For tests.
    pub fn snapshot_llm_calls(&self) -> Vec<TraceLlmCallRow> {
        let state = self.state.lock().expect("memory backend lock");
        state.llm_calls.clone()
    }
}

impl Backend for MemoryBackend {
    /// v4.0 (CIRISPersist#160, FSD §4.4) — delegate to the
    /// `FederationDirectory` occurrence→identity lookup; `None` means
    /// the singleton-identity fallback (occurrence == identity).
    async fn resolve_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<String>, Error> {
        use crate::federation::FederationDirectory;
        let io = self
            .lookup_identity_for_occurrence(occurrence_key_id)
            .await
            .map_err(|e| Error::Backend(format!("resolve_identity_for_occurrence: {e}")))?;
        Ok(io.map(|o| o.identity_key_id))
    }

    /// v4.0 (CIRISPersist#160, FSD §4.6) — family-half of the writer
    /// admission; delegates to the `FederationDirectory` fan-out.
    async fn admission_family_key_ids(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<String>, Error> {
        use crate::federation::FederationDirectory;
        let families = self
            .list_families_for_member(member_identity_key_id)
            .await
            .map_err(|e| Error::Backend(format!("admission_family_key_ids: {e}")))?;
        Ok(families.into_iter().map(|f| f.family_key_id).collect())
    }

    /// v4.0 (CIRISPersist#160, FSD §4.6) — community-half of the writer
    /// admission; delegates to the `FederationDirectory` fan-out.
    async fn admission_community_key_ids(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<String>, Error> {
        use crate::federation::FederationDirectory;
        let communities = self
            .list_communities_for_member(member_identity_key_id)
            .await
            .map_err(|e| Error::Backend(format!("admission_community_key_ids: {e}")))?;
        Ok(communities
            .into_iter()
            .map(|c| c.community_key_id)
            .collect())
    }

    async fn insert_trace_events_batch(
        &self,
        rows: &[TraceEventRow],
    ) -> Result<InsertReport, Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let mut inserted = 0usize;
        let mut conflicted = 0usize;
        // Within a batch, also enforce uniqueness by dedup tuple — a
        // batch that contains two rows with the same dedup tuple is a
        // schema bug and would be ON CONFLICT-suppressed in Postgres.
        let mut seen = HashSet::new();
        for row in rows {
            let key = (
                row.agent_id_hash.clone(),
                row.trace_id.clone(),
                row.thought_id.clone(),
                row.event_type,
                row.attempt_index,
            );
            if !seen.insert(key.clone()) {
                conflicted += 1;
                continue;
            }
            if state.events.contains_key(&key) {
                conflicted += 1;
                continue;
            }
            let event_id = state.next_event_id;
            state.next_event_id += 1;
            state.events.insert(key, (event_id, row.clone()));
            inserted += 1;
        }
        Ok(InsertReport {
            inserted,
            conflicted,
        })
    }

    async fn insert_trace_llm_calls_batch(&self, rows: &[TraceLlmCallRow]) -> Result<usize, Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let n = rows.len();
        state.llm_calls.extend(rows.iter().cloned());
        Ok(n)
    }

    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<VerifyingKey>, Error> {
        // v0.4.0 (lens#8 ASK 2) — federation_keys is the canonical
        // pubkey directory. Legacy `keys` map fallback retired this
        // release. The `keys` field stays on the State struct for
        // test fixtures (add_public_key) but lookup_public_key no
        // longer reads from it.
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let state = self.state.lock().expect("memory backend lock");
        let Some(rec) = state.federation_keys.get(key_id) else {
            return Ok(None);
        };
        let now = chrono::Utc::now();
        if rec.valid_until.is_some_and(|t| t <= now) {
            return Ok(None);
        }
        let bytes = BASE64
            .decode(&rec.pubkey_ed25519_base64)
            .map_err(|e| Error::Backend(format!("public_key_base64 decode: {e}")))?;
        if bytes.len() != 32 {
            return Err(Error::Backend(format!(
                "public_key_base64 wrong length: got {}, expected 32",
                bytes.len()
            )));
        }
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("length-checked");
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| Error::Backend(format!("public_key parse: {e}")))?;
        Ok(Some(key))
    }

    async fn run_migrations(&self) -> Result<(), Error> {
        // Memory backend has no schema to migrate.
        Ok(())
    }

    async fn delete_traces_for_agent(
        &self,
        agent_id_hash: &str,
        signature_key_id: &str,
        include_federation_key: bool,
    ) -> Result<super::types::DeleteSummary, Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // Per-key DSAR scope: both agent_id_hash AND signing_key_id
        // must match. trace_llm_calls cascade joins by trace_id
        // (V001 schema — LLM call rows don't carry either field).
        let row_matches = |row: &TraceEventRow| -> bool {
            row.agent_id_hash == agent_id_hash && row.signing_key_id == signature_key_id
        };

        let target_trace_ids: HashSet<String> = state
            .events
            .values()
            .filter(|(_, row)| row_matches(row))
            .map(|(_, row)| row.trace_id.clone())
            .collect();

        let trace_events_before = state.events.len();
        state.events.retain(|_, (_, row)| !row_matches(row));
        let trace_events_deleted = (trace_events_before - state.events.len()) as u64;

        let llm_calls_before = state.llm_calls.len();
        state
            .llm_calls
            .retain(|row| !target_trace_ids.contains(&row.trace_id));
        let trace_llm_calls_deleted = (llm_calls_before - state.llm_calls.len()) as u64;

        let mut federation_keys_deleted = 0u64;
        let mut federation_attestations_deleted = 0u64;
        let mut federation_revocations_deleted = 0u64;

        if include_federation_key {
            // Find every key_id where identity_type='agent' AND
            // identity_ref=agent_id_hash. May be multiple if the agent
            // rotated keys.
            // Per-key federation_keys cascade: the single key_id
            // matching (agent_id_hash, signature_key_id). The agent's
            // other registered keys stay alive — DSAR can only revoke
            // the key it was signed with.
            let target_key_ids: HashSet<String> = state
                .federation_keys
                .values()
                .filter(|rec| {
                    rec.identity_type == "agent"
                        && rec.identity_ref == agent_id_hash
                        && rec.key_id == signature_key_id
                })
                .map(|rec| rec.key_id.clone())
                .collect();

            // FK-cascade: revocations + attestations referencing those
            // keys (as attesting/attested/revoking/revoked/scrub_key_id)
            // must go before the federation_keys delete.
            let revs_before = state.federation_revocations.len();
            state.federation_revocations.retain(|r| {
                !(target_key_ids.contains(&r.revoked_key_id)
                    || target_key_ids.contains(&r.revoking_key_id)
                    || target_key_ids.contains(&r.scrub_key_id))
            });
            federation_revocations_deleted =
                (revs_before - state.federation_revocations.len()) as u64;

            let atts_before = state.federation_attestations.len();
            state.federation_attestations.retain(|a| {
                !(target_key_ids.contains(&a.attesting_key_id)
                    || target_key_ids.contains(&a.attested_key_id)
                    || target_key_ids.contains(&a.scrub_key_id))
            });
            federation_attestations_deleted =
                (atts_before - state.federation_attestations.len()) as u64;

            // Now safe to delete the federation_keys rows.
            let keys_before = state.federation_keys.len();
            state
                .federation_keys
                .retain(|k, _| !target_key_ids.contains(k));
            federation_keys_deleted = (keys_before - state.federation_keys.len()) as u64;
        }

        Ok(super::types::DeleteSummary {
            trace_events_deleted,
            trace_llm_calls_deleted,
            federation_keys_deleted,
            federation_attestations_deleted,
            federation_revocations_deleted,
            deleted_at: chrono::Utc::now(),
        })
    }

    async fn delete_traces_for_agent_id_hash(
        &self,
        agent_id_hash: &str,
    ) -> Result<super::types::ErasureSummary, Error> {
        let erased_at = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");

        // Full erasure: every trace_events row for this agent_id_hash,
        // across all signing keys. trace_llm_calls cascade joins by
        // trace_id (V001 — LLM call rows carry no agent_id_hash).
        let target_trace_ids: HashSet<String> = state
            .events
            .values()
            .filter(|(_, row)| row.agent_id_hash == agent_id_hash)
            .map(|(_, row)| row.trace_id.clone())
            .collect();

        let events_before = state.events.len();
        state
            .events
            .retain(|_, (_, row)| row.agent_id_hash != agent_id_hash);
        let trace_events = (events_before - state.events.len()) as u64;

        let llm_before = state.llm_calls.len();
        state
            .llm_calls
            .retain(|row| !target_trace_ids.contains(&row.trace_id));
        let trace_llm_calls = (llm_before - state.llm_calls.len()) as u64;

        // detection_events tombstone: the memory backend has no
        // cirislens_derived storage (DerivedSchema put paths return
        // NotImplemented), so there is nothing to tombstone. Always 0;
        // the postgres/sqlite backends carry the real tombstone path.
        let detection_events_tombstoned = 0u64;

        // Audit emit — record a `hard_case:trace_erasure` row, mirroring
        // the durable hard_case_events surface (atomic with the deletes
        // since the whole op holds the single state lock). Emit only when
        // something was actually erased, so an idempotent re-run stays a
        // clean no-op.
        if trace_events > 0 || trace_llm_calls > 0 {
            let event_id = uuid::Uuid::new_v4().to_string();
            let detail = serde_json::json!({
                "agent_id_hash": agent_id_hash,
                "trace_events": trace_events,
                "trace_llm_calls": trace_llm_calls,
                "detection_events_tombstoned": detection_events_tombstoned,
            });
            state.federation_hard_case_events.insert(
                event_id.clone(),
                crate::federation::hard_case::HardCaseEvent {
                    event_id,
                    kind: crate::federation::hard_case::kind::TRACE_ERASURE.to_owned(),
                    target_key_id: Some(agent_id_hash.to_owned()),
                    subject_key_id: None,
                    detail,
                    emitted_at: erased_at,
                },
            );
        }

        Ok(super::types::ErasureSummary {
            trace_events,
            trace_llm_calls,
            detection_events_tombstoned,
            erased_at,
        })
    }

    async fn fetch_trace_events_page(
        &self,
        after_event_id: i64,
        limit: i64,
        agent_id_hash: Option<&str>,
    ) -> Result<Vec<(i64, TraceEventRow)>, Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<(i64, TraceEventRow)> = state
            .events
            .values()
            .filter(|(eid, row)| {
                *eid > after_event_id && agent_id_hash.is_none_or(|h| row.agent_id_hash == h)
            })
            .map(|(eid, row)| (*eid, row.clone()))
            .collect();
        rows.sort_by_key(|(eid, _)| *eid);
        rows.truncate(limit.max(0) as usize);
        Ok(rows)
    }

    // ─── v8.0.0 — fountain content primitive (CIRISPersist#227) ─────

    async fn put_fountain_content(
        &self,
        manifest: &crate::fountain::FountainManifestV1,
        symbols: &[crate::fountain::FountainSymbolV1],
    ) -> Result<(), Error> {
        // Verify-before-mutation (AV-9): the full admission gate runs
        // first; on any failure NOTHING is written. Byte-identical gate
        // across all three backends via `check_admission_via_envelope`.
        crate::fountain::check_admission_via_envelope(
            manifest,
            symbols,
            &crate::verify::PythonJsonDumpsCanonicalizer,
        )?;

        let mut state = self.state.lock().expect("memory backend lock");
        let key = (manifest.content_id.clone(), manifest.corpus_kind.clone());
        // Manifest: insert-if-absent (idempotent re-admit = no-op on the
        // manifest, mirroring ON CONFLICT DO NOTHING).
        state
            .fountain_manifests
            .entry(key.clone())
            .or_insert_with(|| manifest.clone());
        // Record the admission instant once (the consent-decay clock's
        // reference); idempotent re-admit keeps the first.
        state
            .fountain_admitted_at
            .entry(key)
            .or_insert_with(chrono::Utc::now);
        // Symbols: upsert by symbol_id (idempotent).
        let bucket = state
            .fountain_symbols
            .entry(manifest.content_id.clone())
            .or_default();
        for sym in symbols {
            bucket.insert(sym.symbol_id, sym.clone());
        }
        Ok(())
    }

    async fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: crate::fountain::FountainTier,
    ) -> Result<u64, Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let Some(manifest) = state
            .fountain_manifests
            .get(&(content_id.to_owned(), corpus_kind.to_owned()))
            .cloned()
        else {
            return Ok(0);
        };
        let keep = tier.keep_count(&manifest) as usize;
        let Some(bucket) = state.fountain_symbols.get_mut(content_id) else {
            return Ok(0);
        };
        if bucket.len() <= keep {
            return Ok(0);
        }
        // Sort present symbols by the eviction order — keep the lowest
        // retention_priority (keep-longest); evict highest first. Tie-
        // break on symbol_id DESC so the order is deterministic.
        let mut present: Vec<(u32, u8)> = bucket
            .iter()
            .map(|(id, s)| (*id, s.retention_priority))
            .collect();
        // Ascending by (priority, symbol_id): the first `keep` are kept.
        present.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
        let evict_ids: Vec<u32> = present.iter().skip(keep).map(|(id, _)| *id).collect();
        let mut evicted = 0u64;
        for id in evict_ids {
            if bucket.remove(&id).is_some() {
                evicted += 1;
            }
        }
        Ok(evicted)
    }

    async fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<u64, Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // Manifest stays (EnvelopeOnly provenance); unknown content ⇒ no-op.
        if !state
            .fountain_manifests
            .contains_key(&(content_id.to_owned(), corpus_kind.to_owned()))
        {
            return Ok(0);
        }
        // Drop ALL symbols — never consults retention_priority (N5:
        // revocation dominates rarity; the §8.1.11.3 deletion-SLA wins).
        let dropped = state
            .fountain_symbols
            .remove(content_id)
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        Ok(dropped)
    }

    async fn get_fountain_content(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<Option<crate::fountain::FountainContent>, Error> {
        let state = self.state.lock().expect("memory backend lock");
        let Some(manifest) = state
            .fountain_manifests
            .get(&(content_id.to_owned(), corpus_kind.to_owned()))
            .cloned()
        else {
            return Ok(None);
        };
        let mut symbols: Vec<crate::fountain::FountainSymbolV1> = state
            .fountain_symbols
            .get(content_id)
            .map(|b| b.values().cloned().collect())
            .unwrap_or_default();
        symbols.sort_by_key(|s| s.symbol_id);
        drop(state);
        Ok(Some(assemble_fountain_content(manifest, symbols)?))
    }

    // #227 — publisher-facing held fountain-content enumerator. Memory parity
    // for the pg/sqlite query; `admitted_at` is empty (the in-memory manifest
    // map does not retain an admission timestamp — the Engine/FFI fountain
    // surface is pg/sqlite only).
    async fn list_held_fountain_content(
        &self,
        publisher_key_id: &str,
    ) -> Result<Vec<crate::fountain::FountainHeldMeta>, Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<crate::fountain::FountainHeldMeta> = state
            .fountain_manifests
            .iter()
            .filter(|((_, _), m)| m.pqc_key_id == publisher_key_id)
            .map(|((content_id, corpus_kind), m)| {
                let held = state
                    .fountain_symbols
                    .get(content_id)
                    .map(|b| b.len())
                    .unwrap_or(0) as u32;
                crate::fountain::FountainHeldMeta {
                    content_id: content_id.clone(),
                    corpus_kind: corpus_kind.clone(),
                    pqc_key_id: m.pqc_key_id.clone(),
                    original_content_length: m.original_content_length,
                    n_source: m.n_source,
                    k_repair: m.k_repair,
                    min_viable_symbols: m.min_viable_symbols,
                    symbol_size: m.symbol_size,
                    held_symbols: held,
                    content_bytes: u64::from(held) * u64::from(m.symbol_size),
                    cohort_scope: crate::fountain::cohort_scope_from_envelope(&m.envelope),
                    recoverable: held >= m.min_viable_symbols,
                    admitted_at: String::new(),
                }
            })
            .collect();
        out.sort_by(|a, b| b.content_id.cmp(&a.content_id));
        Ok(out)
    }

    // ─── v13.0.0 — §Q pin-INSTALL surface (CIRISPersist#370) ─────────

    async fn put_installed_storage_budget(
        &self,
        budget: &crate::fountain::storage_contention::InstalledStorageBudget,
    ) -> Result<bool, Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // §Q B3 anti-rollback under the same lock the map lives behind —
        // replace only on a STRICTLY higher revision (parity with the
        // SQL dialects' conditional upsert).
        match state.installed_storage_budgets.get(&budget.node_id) {
            Some(existing) if existing.revision >= budget.revision => Ok(false),
            _ => {
                state
                    .installed_storage_budgets
                    .insert(budget.node_id.clone(), budget.clone());
                Ok(true)
            }
        }
    }

    async fn get_installed_storage_budget(
        &self,
        node_id: &str,
    ) -> Result<Option<crate::fountain::storage_contention::InstalledStorageBudget>, Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.installed_storage_budgets.get(node_id).cloned())
    }

    async fn list_installed_storage_budgets(
        &self,
    ) -> Result<Vec<crate::fountain::storage_contention::InstalledStorageBudget>, Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<_> = state.installed_storage_budgets.values().cloned().collect();
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Ok(out)
    }

    // #227 (residual) — consent-decay clock enumerator (disk-independent).
    async fn list_fountain_decay_candidates(
        &self,
    ) -> Result<Vec<crate::fountain::FountainDecayCandidate>, Error> {
        let state = self.state.lock().expect("memory backend lock");
        let out = state
            .fountain_manifests
            .iter()
            .map(|((content_id, corpus_kind), m)| {
                let admitted_at = state
                    .fountain_admitted_at
                    .get(&(content_id.clone(), corpus_kind.clone()))
                    .copied()
                    .unwrap_or_else(chrono::Utc::now);
                crate::fountain::FountainDecayCandidate {
                    content_id: content_id.clone(),
                    corpus_kind: corpus_kind.clone(),
                    envelope: m.envelope.clone(),
                    admitted_at,
                }
            })
            .collect();
        Ok(out)
    }

    // ─── v8.3.0 — §19.7 inter-object aggregation (CIRISPersist#230) ──

    async fn put_aggregated_tier(
        &self,
        manifest: &crate::fountain::FountainManifestV1,
        symbols: &[crate::fountain::FountainSymbolV1],
        agg: &crate::fountain::AggregationMetaV1,
        aggregated_at_unix_ms: i64,
    ) -> Result<(), Error> {
        // Verify-before-mutation (AV-9): BOTH gates run BEFORE any write.
        //   (i)  the EXISTING #225 fountain admit gate — classical-only
        //        composite manifest REJECTED (hard cut).
        //   (ii) v8.4.0 §19.7.1 PQC-mandatory store-path gate (§10.1.5.1.1):
        //        verify the aggregation_meta bound-hybrid signature against the
        //        aggregator pubkeys on the composite envelope. The STORAGE
        //        column stays OPAQUE — verification inputs are admission-only.
        crate::fountain::check_admission_via_envelope(
            manifest,
            symbols,
            &crate::verify::PythonJsonDumpsCanonicalizer,
        )?;
        agg.verify_for_admission(manifest)?;

        let mut state = self.state.lock().expect("memory backend lock");
        // (a) composite manifest (idempotent) + symbols.
        let key = (manifest.content_id.clone(), manifest.corpus_kind.clone());
        state
            .fountain_manifests
            .entry(key.clone())
            .or_insert_with(|| manifest.clone());
        state
            .fountain_admitted_at
            .entry(key)
            .or_insert_with(chrono::Utc::now);
        let bucket = state
            .fountain_symbols
            .entry(manifest.content_id.clone())
            .or_default();
        for sym in symbols {
            bucket.insert(sym.symbol_id, sym.clone());
        }
        // (b) aggregation provenance row (opaque aggregation_meta;
        // idempotent on aggregate_content_id).
        state
            .content_aggregations
            .entry(agg.aggregate_content_id.clone())
            .or_insert_with(|| crate::fountain::AggregationRecordV1 {
                aggregate_content_id: agg.aggregate_content_id.clone(),
                source_corpus_kind: agg.source_corpus_kind.clone(),
                aggregation_level: agg.aggregation_level,
                fan_in: agg.fan_in,
                member_commitment: agg.member_commitment.clone(),
                aggregation_meta: agg.aggregation_meta.clone(),
                aggregated_at_unix_ms,
            });
        Ok(())
    }

    async fn get_aggregation(
        &self,
        aggregate_content_id: &str,
    ) -> Result<Option<crate::fountain::AggregationRecordV1>, Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .content_aggregations
            .get(aggregate_content_id)
            .cloned())
    }

    async fn list_aggregations_at_level(
        &self,
        level: i64,
        limit: i64,
    ) -> Result<Vec<crate::fountain::AggregationRecordV1>, Error> {
        let level_u64 = match u64::try_from(level) {
            Ok(l) => l,
            // A negative level can never match a stored (u64) level.
            Err(_) => return Ok(Vec::new()),
        };
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<crate::fountain::AggregationRecordV1> = state
            .content_aggregations
            .values()
            .filter(|r| r.aggregation_level == level_u64)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.aggregated_at_unix_ms
                .cmp(&b.aggregated_at_unix_ms)
                .then_with(|| a.aggregate_content_id.cmp(&b.aggregate_content_id))
        });
        rows.truncate(limit.max(0) as usize);
        Ok(rows)
    }
}

/// v8.0.0 (CIRISPersist#227) — shared read assembler: re-verify each
/// present symbol's SHA-256 against the signed `symbol_hashes`, then
/// classify present-count vs the manifest thresholds into the typed
/// [`FountainContent`](crate::fountain::FountainContent). Used by every
/// backend's `get_fountain_content` so the read contract (authenticated
/// partials, Full/Partial/EnvelopeOnly boundary) is byte-identical.
pub(crate) fn assemble_fountain_content(
    manifest: crate::fountain::FountainManifestV1,
    symbols: Vec<crate::fountain::FountainSymbolV1>,
) -> Result<crate::fountain::FountainContent, Error> {
    use crate::fountain::{FountainContent, FountainReadClass};
    // Per-symbol hash re-auth on read (authenticated partials).
    for sym in &symbols {
        let idx = sym.symbol_id as usize;
        let Some(expected) = manifest.symbol_hashes.get(idx) else {
            return Err(Error::FountainIntegrity(format!(
                "symbol_id {} has no signed hash (symbol_hashes len {})",
                sym.symbol_id,
                manifest.symbol_hashes.len()
            )));
        };
        let got = crate::fountain::symbol_sha256_hex(&sym.symbol_bytes);
        if &got != expected {
            return Err(Error::FountainIntegrity(format!(
                "stored symbol {} sha256 {} != signed hash {}",
                sym.symbol_id, got, expected
            )));
        }
    }
    let present = symbols.len() as u32;
    Ok(
        match FountainContent::classify(present, manifest.n_source, manifest.min_viable_symbols) {
            FountainReadClass::Full => FountainContent::Full { manifest, symbols },
            FountainReadClass::Partial => FountainContent::Partial {
                manifest,
                symbols,
                present,
            },
            FountainReadClass::EnvelopeOnly => FountainContent::EnvelopeOnly { manifest },
        },
    )
}

// ─── FederationDirectory impl (v0.2.0) ─────────────────────────────
//
// In-process maps mirror the postgres tables. No FK enforcement
// (postgres + sqlite enforce; tests against the memory backend run
// against the same logical contract via the `FederationDirectory`
// trait). `persist_row_hash` is computed on every put per the
// architectural contract — consumers see the canonical hash even
// against the in-memory backend.

/// v17.4.0 — the Rust-side twin of the sqlite/postgres `scores` WHERE
/// predicate for the memory backend: does `r` match the filter's shared axes
/// (subject / dimension exact+prefix / type / attester / pqc / confidence /
/// valid_at / window / tier / attester_filter) AND the §4.3 scope gate?
/// Lifecycle + cursor are applied by the caller.
fn mem_scores_row_matches(
    r: &crate::federation::Attestation,
    filter: &crate::read::AttestationFilter,
    scope: &crate::scope::CallerScope,
) -> bool {
    use crate::read::{AttesterSet, Tier};
    let dimension = crate::federation::admission::envelope_dimension(&r.attestation_envelope);
    if let Some(subj) = &filter.subject_key_id {
        if !r.subject_key_ids.iter().any(|s| s == subj) {
            return false;
        }
    }
    if let Some(dx) = &filter.dimension_exact {
        if dimension != Some(dx.as_str()) {
            return false;
        }
    }
    if !filter.dimension_prefixes.is_empty() {
        let d = dimension.unwrap_or("");
        if !filter.dimension_prefixes.iter().any(|p| d.starts_with(p)) {
            return false;
        }
    }
    if let Some(t) = &filter.attestation_type {
        if &r.attestation_type != t {
            return false;
        }
    }
    // v30.9.0 (CIRISPersist#627) — singular ∪ set, OR-combined.
    {
        let keys = crate::ceg::list::federation::merge_key_predicate(
            filter.attesting_key_id.as_ref(),
            &filter.attesting_key_ids,
        );
        if !keys.is_empty() && !keys.iter().any(|k| k == &r.attesting_key_id) {
            return false;
        }
    }
    // v30.9.0 (CIRISPersist#627) — singular ∪ set, OR-combined.
    {
        let keys = crate::ceg::list::federation::merge_key_predicate(
            filter.attested_key_id.as_ref(),
            &filter.attested_key_ids,
        );
        if !keys.is_empty() && !keys.iter().any(|k| k == &r.attested_key_id) {
            return false;
        }
    }
    if let Some(pqc) = filter.pqc_completed {
        if r.pqc_completed_at.is_some() != pqc {
            return false;
        }
    }
    if let Some(floor) = filter.confidence_floor {
        match r.weight {
            Some(w) if w >= floor => {}
            _ => return false,
        }
    }
    if let Some(va) = filter.valid_at {
        if !(r.asserted_at <= va && r.expires_at.is_none_or(|e| e > va)) {
            return false;
        }
    }
    if let Some((start, end)) = filter.window {
        if !(r.asserted_at >= start && r.asserted_at < end) {
            return false;
        }
    }
    match filter.tier {
        None | Some(Tier::Federation) => {
            if r.tier != crate::federation::types::attestation_tier::FEDERATION {
                return false;
            }
        }
        Some(Tier::Local) => {
            if r.tier != crate::federation::types::attestation_tier::LOCAL {
                return false;
            }
        }
        Some(Tier::Any) => {}
    }
    if let Some(AttesterSet::Explicit(keys)) = &filter.attester_filter {
        if !keys.iter().any(|k| k == &r.attesting_key_id) {
            return false;
        }
    }
    // §4.3 scope gate (target = attested_key_id, mirroring the SQL).
    scope.admits(&r.cohort_scope, &r.attested_key_id)
}

#[async_trait::async_trait]
impl crate::federation::FederationDirectory for MemoryBackend {
    fn node_key_id(&self) -> Option<String> {
        self.node_key_id.read().expect("node_key_id lock").clone()
    }
    // v23.1.0 (CIRISPersist#554) — surface THIS backend's configured policy on
    // the trait so `genesis::verify_bundle_quorum` gates holder evidence with
    // the same predicate `put_public_key` uses. Delegates to the inherent
    // method (the single source of truth); a tightened deployment tightens
    // both validators at once.
    fn hardware_attestation_policy(
        &self,
    ) -> std::sync::Arc<crate::federation::HardwareAttestationPolicy> {
        MemoryBackend::hardware_attestation_policy(self)
    }

    async fn put_public_key(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let mut row = record.record;
        // v19.0.0 (#486) — lift envelope-attested roles into the claim
        // surface BEFORE the role write-gates (lift-then-gate).
        crate::federation::admission::lift_envelope_attested_roles(&mut row);

        // v10.1.0 (CIRISPersist#275 hardening) — universal write-path
        // invariant: pubkey_ed25519_base64 MUST decode to a 32-byte Ed25519
        // key. Rejects a wrong-curve / malformed key at admission for EVERY
        // registration path. v22.0.0 (#543): the memory backend was the one
        // backend that skipped this, so a malformed key it accepted was
        // refused by sqlite/postgres — restore the parity.
        crate::federation::register::validate_registration_pubkey(&row)?;

        // v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation admission
        // gate for accord_holder rows. Runs BEFORE persist_row_hash + insert
        // so rejected rows leave no trace. #441: evaluated over
        // identity_type ∪ roles (claims_role) — an `accord_holder` claim in
        // the set form ("agent,accord_holder") or in the roles vector hits
        // the same gate as the scalar. v22.0.0 (#543): the memory backend
        // never ran this gate at all, so an evidence-less accord_holder that
        // sqlite/postgres REJECT was silently admitted here.
        if row.claims_role(crate::federation::types::identity_type::ACCORD_HOLDER) {
            self.hardware_attestation_policy().check(
                &row.key_id,
                row.attestation_evidence.as_ref(),
                chrono::Utc::now(),
            )?;
        }

        // v13.0.0 (CIRISPersist#365, CC 3.4.7.2) — same consent_role
        // admission gate + 'unregistered'⇔None normalization as the SQL
        // backends (a stored-form 'unregistered' submitted on the wire
        // reads back as None everywhere).
        crate::federation::types::consent_role::check_admissible(row.consent_role.as_deref())?;
        row.consent_role = row
            .consent_role
            .as_deref()
            .and_then(crate::federation::types::consent_role::wire_from_stored)
            .map(str::to_owned);
        // v13.0.0 (CIRISPersist#372, CC 3.4.7.1) — accord-conferred `canonical`
        // gate. Runs BEFORE the state lock (it calls lookup_public_key on self,
        // which acquires the lock itself) and BEFORE persist — a self-signed /
        // non-anchor-scrubbed `canonical` claim leaves no trace. Backend-
        // symmetric with SQLite + Postgres.
        crate::federation::admission::check_canonical_role_admission(self, &row).await?;
        // #422 — `infra:attest` in `roles` is accord-conferred, same m-of-n
        // co-scrub gate as `canonical`. Fail-closed before any write.
        crate::federation::admission::check_infra_attest_role_admission(self, &row).await?;
        // #440 — the CC 3.4.9 co-steward roles (`registry`/`verify`) are
        // accord-conferred, same ceremony. Fail-closed before any write.
        crate::federation::admission::check_co_steward_role_admission(self, &row).await?;
        // v22.0.0 (CIRISPersist#543 finding 3) — the CLOSED authority-claim
        // gate: every remaining privileged `identity_type` is accord-conferred,
        // never self-asserted. Same chokepoint, same fail-closed posture; the
        // closed set lives in `identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES`
        // and is proven to cover every reserved-prefix rule.
        crate::federation::admission::check_privileged_identity_type_admission(self, &row).await?;
        // Server-computed hash (excludes the field itself).
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        let key_id = {
            let mut state = self.state.lock().expect("memory backend lock");
            // Idempotent on key_id collision with matching content.
            if let Some(existing) = state.federation_keys.get(&row.key_id) {
                if existing.persist_row_hash == row.persist_row_hash {
                    return Ok(()); // exact duplicate — no-op
                }
                return Err(crate::federation::Error::Conflict(format!(
                    "key_id {} already exists with different content",
                    row.key_id
                )));
            }
            // v21.1.0 (CIRISPersist#507b) — the row must land in the wire index.
            // v24.1.0 (CIRISPersist#547) — through the SHARED derivation, so this
            // path and the mutators cannot compute the entry differently.
            // v31.0.0 (CIRISPersist#640/#646) — indexed from the STORED row, after
            // the insert AND after the guard is released; see
            // `MemoryBackend::index_stored_record`.
            let key_id = row.key_id.clone();
            state.federation_keys.insert(key_id.clone(), row);
            key_id
        };
        self.index_stored_key_row(&key_id).await?;
        Ok(())
    }

    // v19.1.0 (#490) — the authenticated re-anchor (memory parity; see the
    // sqlite impl for the full invariants).
    async fn adopt_genesis_reanchor(
        &self,
        record: crate::federation::SignedKeyRecord,
        bundle: &crate::federation::genesis::GenesisBundle,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::Error;
        crate::federation::genesis::verify_bundle_quorum(self, bundle).await?;
        let mut row = record.record;
        if !bundle.serve_nodes.iter().any(|sn| {
            sn.record.persist_row_hash == row.persist_row_hash
                && sn.record.key_id == row.key_id
                && sn.record.registration_envelope == row.registration_envelope
        }) {
            return Err(Error::GenesisBundleInvalid {
                detail: format!(
                    "re-anchor record {} is not carried by the verified bundle",
                    row.key_id
                ),
            });
        }
        crate::federation::admission::lift_envelope_attested_roles(&mut row);
        crate::federation::register::validate_registration_pubkey(&row)?;
        crate::federation::admission::check_canonical_role_admission(self, &row).await?;
        crate::federation::admission::check_infra_attest_role_admission(self, &row).await?;
        crate::federation::admission::check_co_steward_role_admission(self, &row).await?;
        // v22.0.0 (CIRISPersist#543 finding 3) — the CLOSED authority-claim
        // gate: every remaining privileged `identity_type` is accord-conferred,
        // never self-asserted. Same chokepoint, same fail-closed posture; the
        // closed set lives in `identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES`
        // and is proven to cover every reserved-prefix rule.
        crate::federation::admission::check_privileged_identity_type_admission(self, &row).await?;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let key_id = {
            let mut state = self.state.lock().expect("memory backend lock");
            let existing = state.federation_keys.get(&row.key_id).ok_or_else(|| {
                Error::GenesisBundleInvalid {
                    detail: format!("re-anchor target {} has no existing row", row.key_id),
                }
            })?;
            if existing.pubkey_ed25519_base64 != row.pubkey_ed25519_base64 {
                return Err(Error::GenesisBundleInvalid {
                    detail: format!("re-anchor {}: pubkey change refused", row.key_id),
                });
            }
            if row.valid_from <= existing.valid_from {
                return Err(Error::GenesisBundleInvalid {
                    detail: format!(
                        "re-anchor {}: valid_from not newer than anchored — rollback refused",
                        row.key_id
                    ),
                });
            }
            // v24.1.0 (CIRISPersist#547) — the Key-plane wire index must follow the
            // row through EVERY mutator, not only `put_public_key`.
            // v31.0.0 (CIRISPersist#640/#646) — from the STORED row; see
            // `MemoryBackend::index_stored_record`.
            let key_id = row.key_id.clone();
            state.federation_keys.insert(key_id.clone(), row);
            key_id
        };
        self.index_stored_key_row(&key_id).await?;
        Ok(())
    }

    async fn lookup_public_key(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::KeyRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_keys.get(key_id).cloned())
    }

    async fn lookup_keys_for_identity(
        &self,
        identity_ref: &str,
    ) -> Result<Vec<crate::federation::KeyRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .federation_keys
            .values()
            .filter(|k| k.identity_ref == identity_ref)
            .cloned()
            .collect())
    }

    /// v2.6.0 (CIRISPersist#105) — enumerate by `identity_type`.
    /// Stable lex-sort order by `key_id` so callers can
    /// deterministically pick subsets.
    async fn list_keys_by_identity_type(
        &self,
        identity_type: &str,
    ) -> Result<Vec<crate::federation::KeyRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_keys
            .values()
            .filter(|k| k.identity_type == identity_type)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(rows)
    }

    /// v13.0.0 (CIRISPersist#365, CC 3.4.7.2 OQ-1) — overwrite-on-revoke
    /// consent_role. `None` revokes (back to the unset/'unregistered'
    /// default). No chain; a subsequent call overwrites. `consent_role`
    /// is excluded from `persist_row_hash`, so mutating it does not
    /// change the stored row's hash. Same admission gate +
    /// 'unregistered'⇔None normalization as the SQL backends.
    async fn set_consent_role(
        &self,
        key_id: &str,
        consent_role: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::types::consent_role::check_admissible(consent_role)?;
        let normalized: Option<String> = consent_role
            .and_then(crate::federation::types::consent_role::wire_from_stored)
            .map(str::to_owned);
        {
            let mut state = self.state.lock().expect("memory backend lock");
            let Some(row) = state.federation_keys.get_mut(key_id) else {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "set_consent_role: no federation_keys row for {key_id}"
                )));
            };
            row.consent_role = normalized;
            // v24.1.0 (CIRISPersist#547) — `consent_role` is excluded from
            // `persist_row_hash` but IS in the bytes the read surface returns, so
            // the WIRE content hash moves here. Re-index.
            // v31.0.0 (CIRISPersist#640/#646) — through the shared stored-row
            // helper, after the guard is released.
        }
        self.index_stored_key_row(key_id).await?;
        Ok(())
    }

    /// v13.1.0 (CIRISPersist#377) — record a canonical-role WITHDRAW/SUPERSEDE
    /// tombstone (V095 mirror). Idempotent on `key_id`: matching
    /// `superseded_by` + `authority_decision_digest` is a no-op; a differing one
    /// is a [`Conflict`](crate::federation::Error::Conflict). Backend-symmetric
    /// with SQLite + Postgres.
    async fn record_canonical_withdrawal(
        &self,
        key_id: &str,
        superseded_by: Option<&str>,
        authority_decision_digest: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut record = crate::federation::CanonicalWithdrawal {
            key_id: key_id.to_owned(),
            withdrawn_at: chrono::Utc::now(),
            authority_decision_digest: authority_decision_digest.to_owned(),
            superseded_by: superseded_by.map(str::to_owned),
            persist_row_hash: String::new(),
        };
        record.persist_row_hash = crate::federation::types::compute_persist_row_hash(&record)?;
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(existing) = state.canonical_withdrawals.get(key_id) {
            if existing.superseded_by == record.superseded_by
                && existing.authority_decision_digest == record.authority_decision_digest
            {
                return Ok(()); // idempotent no-op
            }
            return Err(crate::federation::Error::Conflict(format!(
                "canonical_role_withdrawal for {key_id} already exists with different content"
            )));
        }
        state
            .canonical_withdrawals
            .insert(key_id.to_owned(), record);
        Ok(())
    }

    /// v13.1.0 (CIRISPersist#377) — consult the V095 withdrawal tombstone for
    /// `key_id` (the load-bearing gate consult). Backend-symmetric.
    async fn lookup_canonical_withdrawal(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::CanonicalWithdrawal>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.canonical_withdrawals.get(key_id).cloned())
    }

    /// v13.1.0 (CIRISPersist#377) — all V095 withdrawal tombstones, stable-sorted
    /// by `key_id`. Backend-symmetric.
    async fn list_canonical_withdrawals(
        &self,
    ) -> Result<Vec<crate::federation::CanonicalWithdrawal>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<crate::federation::CanonicalWithdrawal> =
            state.canonical_withdrawals.values().cloned().collect();
        out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(out)
    }

    /// v16.0.0 (CIRISPersist#424) — the GENERIC role-withdrawal tombstone
    /// (V104 mirror), same idempotency/Conflict semantics as canonical.
    async fn record_role_withdrawal(
        &self,
        role: &str,
        key_id: &str,
        superseded_by: Option<&str>,
        authority_decision_digest: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut record = crate::federation::admission::RoleWithdrawal {
            role: role.to_owned(),
            key_id: key_id.to_owned(),
            withdrawn_at: chrono::Utc::now(),
            authority_decision_digest: authority_decision_digest.to_owned(),
            superseded_by: superseded_by.map(str::to_owned),
            persist_row_hash: String::new(),
        };
        record.persist_row_hash = crate::federation::types::compute_persist_row_hash(&record)?;
        let mut state = self.state.lock().expect("memory backend lock");
        let map_key = (role.to_owned(), key_id.to_owned());
        if let Some(existing) = state.role_withdrawals.get(&map_key) {
            if existing.superseded_by == record.superseded_by
                && existing.authority_decision_digest == record.authority_decision_digest
            {
                return Ok(()); // idempotent no-op
            }
            return Err(crate::federation::Error::Conflict(format!(
                "role_withdrawal ({role}, {key_id}) already exists with different content"
            )));
        }
        state.role_withdrawals.insert(map_key, record);
        Ok(())
    }

    /// v16.0.0 (CIRISPersist#424) — consult the generic tombstone for
    /// `(role, key_id)`. Backend-symmetric.
    async fn lookup_role_withdrawal(
        &self,
        role: &str,
        key_id: &str,
    ) -> Result<Option<crate::federation::admission::RoleWithdrawal>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .role_withdrawals
            .get(&(role.to_owned(), key_id.to_owned()))
            .cloned())
    }

    async fn put_attestation(
        &self,
        attestation: crate::federation::SignedAttestation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = attestation.attestation;

        // ── AV-76 TIER 0 — the free prologue ────────────────────────
        // Neither check below reads the row's content or touches state.
        // Backend-symmetric with the sqlite + postgres prologue; before
        // v22.0.0 (CIRISPersist#543 finding 4) the memory backend ran
        // NEITHER — it had no `admission_gate` field at all, so the
        // v3.4.0 trust gate had never run on this backend, and the AV-76
        // quota would have shipped existing on two backends out of three.
        if !row.attesting_key_id.is_empty() {
            // Per-peer write quota. It LEADS because it is the only check
            // in the whole stack that consults no shared state, so it also
            // bounds the recursive directory walk the trust scorer runs at
            // any threshold > 0. It answers "you are writing too fast",
            // never "that key exists" — strictly less leaky than the gate
            // it precedes. Per-backend-instance state.
            // v24.3.0 (CIRISPersist#575) — takes the ROW now, not the key:
            // the budget a write is charged against is a pure function of
            // the row (see `PeerWriteQuota::classify`), and that predicate
            // lives in the quota so the three backends cannot hold three
            // opinions of it.
            self.peer_write_quota.check_write(&row)?;

            // v3.4.0 (CIRISPersist#123) — trust-threshold gate. The
            // cheapest reject that consults state AND the one that leaks
            // the least; an unauthorized writer shouldn't learn about FK /
            // envelope-schema state past it. Free at the default threshold
            // 0 (short-circuits without dispatching to the resolver).
            if let Some(gate) = self.admission_gate() {
                gate.check_federation(&row.attesting_key_id).await?;
            }
        }

        // ── AV-76 TIER 1 — PURE ENVELOPE GATES ──────────────────────
        // v22.0.0 (CIRISPersist#543 finding 4) — every check in this tier is
        // a pure function of `row`: no state lock, no directory read, no
        // crypto. On this backend they used to be scattered across the stack
        // BEHIND the lock-free authority walks (withdraws / delegated-duty /
        // node-agency / single-owner), so a row that could never be admitted
        // still paid for every one of them — the bootstrap amplification this
        // cut closes.
        //
        // `check_envelope_size_admission` leads deliberately: it BOUNDS the
        // JCS canonicalization that BOTH the hybrid verify (tier 3) and
        // `compute_persist_row_hash` (tier 5) pay.
        //
        // This tier is IDENTICAL to the sqlite + postgres backends', gate for
        // gate and order for order.
        crate::federation::admission::check_envelope_size_admission(&row.attestation_envelope)?;
        // v22.0.0 (CIRISEdge#428) — closed delivery_mode vocabulary; an
        // unknown value is refused HERE instead of being silently demoted
        // to may-drop BestEffort at delivery. Pure predicate, tier 1.
        crate::federation::admission::check_delivery_mode_vocabulary(&row.attestation_envelope)?;

        // v31.0.0 (CIRISPersist#598) — THE CONSENT INSTANT BINDING. A
        // `consent:state:*` row is refused unless its signed envelope carries
        // an `asserted_at` (and `expires_at`) equal to the row column the
        // consent fold orders on. `asserted_at` is stored VERBATIM from the
        // caller here and no signature covers it, so without this a replay of
        // a subject's own byte-identical, still-valid grant with a bumped
        // column flipped a revocation back to Granted — and re-opened
        // `check_capacity_consent_admission`, a gate inside persist. Pure
        // function of (row, now) ⇒ AV-76 TIER 1, and a REFUSAL, so an early
        // position is safe. Backend-symmetric across memory / sqlite /
        // postgres, and asked again at the promote door
        // (`check_promotion_admission`) so the local tier is not a way around
        // it (B8).
        crate::federation::admission::check_consent_state_instant_binding(
            &row,
            chrono::Utc::now(),
            crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
        )?;

        // v31.0.0 (CIRISPersist#643) — THE TYPED-COLUMN BINDING. The
        // signature covers `attestation_envelope` and NOTHING ELSE, so
        // `attestation_type` (the VERB), `subject_key_ids` (which grants
        // revocation authority), `attested_key_id`, `cohort_scope` and
        // `weight` were unsigned columns a relay could rewrite with the
        // producer's own signature still verifying — flip `withdraws` to
        // `scores` and a retraction becomes a claim while the thing it
        // retracted stays live. Refused on ABSENCE or DIVERGENCE, no legacy
        // regime. Pure function of the row => AV-76 TIER 1, tier-blind (a
        // tier-scoped binding would be skippable by writing `tier = "local"`
        // and promoting), and backend-symmetric across memory / sqlite /
        // postgres.
        crate::federation::admission::check_row_column_binding(&row)?;

        // v3.9.1 (CIRISPersist#150 Ask 3, CEG 0.4 §4.2.4) — cohort_scope
        // admission-gate VALUE validation. Rejects out-of-closed-set values
        // (notably `global`, a §8.1.8 feed-name, never a wire value) BEFORE
        // persist_row_hash + insert so rejected rows leave no trace.
        // v22.0.0 (CIRISPersist#543): the memory backend never ran this, and
        // — unlike sqlite/postgres — it has NO V056 CHECK-constraint backstop
        // behind it, so a `global` row the SQL backends refuse at two layers
        // was accepted unconditionally here.
        crate::federation::admission::check_cohort_scope(&row.cohort_scope)?;

        // v26.0.0 (CIRISPersist#589 / AV-83) — `capacity:*` IS NEVER LOCAL.
        // See `src/store/sqlite.rs` put_attestation for the full rationale:
        // the v4.4.0 rule lived only inside `check_local_tier_eligibility`,
        // which this door never calls, while this door accepts
        // `tier = "local"`. Pure predicate ⇒ tier 1; a refusal, never an
        // accept. Backend-symmetric with sqlite + postgres.
        if row.tier == crate::federation::types::attestation_tier::LOCAL {
            crate::federation::admission::check_capacity_never_local(
                &row.attestation_type,
                crate::federation::admission::envelope_dimension(&row.attestation_envelope),
            )?;
        }

        // v18.1.0 (CIRISPersist#473 followup) — the `trace:*`
        // Information-Type validator: self-emission polarity
        // (`attesting_key_id` ∈ `subject_key_ids`) plus the inline-trace /
        // manifest shape. No-op for every non-`trace:` dimension.
        crate::federation::admission::check_trace_dimension_admission(
            crate::federation::admission::envelope_dimension(&row.attestation_envelope),
            &row.attesting_key_id,
            &row.subject_key_ids,
            &row.attestation_envelope,
        )?;

        // v21.3.0 (CIRISPersist#510 P1) — the closed consent-transfer
        // grammar admission chokepoint (parity with sqlite + postgres). A
        // `consent:replication:v1` grant's `payload` MUST parse through
        // `consent_grammar::parse_grant_payload` (closed enums, strict
        // `deny_unknown_fields`) — an unknown restriction op, an
        // unrecognized payload field, a non-consentable `kinds` entry, a
        // bad `grants` token, a bad `audience`, or an empty-string
        // `attestation_prefixes` entry rejects the WHOLE grant. No-op for
        // every other dimension (a `withdraws`/`recants` referencing a grant
        // carries its OWN dimension, never GRANT_DIMENSION). Runs BEFORE
        // persist — a rejected grant leaves no trace.
        if crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            == Some(crate::federation::consent_grammar::GRANT_DIMENSION)
        {
            if let Err(reason) = crate::federation::consent_grammar::validate_grant_admission(
                &row.attestation_envelope,
            ) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "consent grant rejected by the closed grammar (#510): {reason}"
                )));
            }
        }

        // ── AV-76 TIER 2 — the one unavoidable directory read ───────
        // v2.4.0 (CIRISPersist#102 Ask 3) — admission gate. Look up the
        // attesting key's `identity_type`; a missing key is the memory
        // backend's stand-in for the FK violation the SQL backends surface,
        // reported here as the same clearer-typed `InvalidArgument` sqlite +
        // postgres return from THIS tier. The guard is block-scoped so it
        // drops before the awaits below (a `MutexGuard` held across an await
        // is not `Send`).
        let attesting_identity_type = {
            let state = self.state.lock().expect("memory backend lock");
            match state.federation_keys.get(&row.attesting_key_id) {
                Some(rec) => rec.identity_type.clone(),
                None => {
                    return Err(crate::federation::Error::InvalidArgument(format!(
                        "attesting_key_id {} does not exist in federation_keys",
                        row.attesting_key_id
                    )));
                }
            }
        };
        // AV-76 D2 — the lookup above is a hard DATA dependency of the
        // dimension policy here (`attesting_identity_type`); the pair moves
        // as a unit and its internal order is fixed. The default policy
        // enforces the `accord:*` × `accord_holder` rule and the four-test
        // operational-language gate on `scores` attestations; structural
        // primitives are exempt. See `src/federation/admission.rs`.
        crate::federation::admission::DimensionAdmissionPolicy::default().check(
            &row.attestation_type,
            crate::federation::admission::envelope_dimension(&row.attestation_envelope),
            &attesting_identity_type,
        )?;

        // v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — a `revoked`
        // consent_record at local tier MAY *transit* the local write path
        // only if its bound-hybrid signature verifies (accept on VALID crypto
        // only). No-op for non-consent_record rows and durable (granted /
        // federation) ones. Backend-symmetric with SQLite + Postgres.
        //
        // v22.0.0 (AV-76) — deliberately kept AHEAD of the §6.1 dedup. This
        // is the one crypto gate that must NOT move behind it: `withdraws` is
        // a structural composer, so a replayed subject-side revocation would
        // short-circuit at the dedup and never prove its bound-hybrid
        // signature.
        crate::federation::admission::verify_consent_record_transit_ingest(self, &row).await?;

        // ── AV-76 TIER 3 — CRYPTO ───────────────────────────────────
        // v9.0.0 (CIRISPersist#237, CC 5.3.2.4.3.1) — PQC-mandatory
        // hybrid-verify at the federation-tier bulk store/replicate
        // ingest gate (parity with the postgres + sqlite backends). A
        // no-op for local-tier rows (CC 5.3.2.2 deferred signature); for
        // a federation-tier row it hybrid-verifies the envelope signature
        // (Ed25519 + ML-DSA-65, Strict) against the attester's REGISTERED
        // pubkeys. Composes with — does not replace — the trust-threshold
        // check_federation + the node-agency gate. Runs BEFORE persist — a
        // rejected row leaves no trace (verify-before-mutation, AV-9;
        // store-then-quarantine is non-conformant per CC 5.3.2.4.3.1).
        //
        // v22.0.0 (CIRISPersist#543 finding 4, AV-76) — MOVED here from
        // behind the whole authority walk. The ML-DSA-65 verify is the single
        // most expensive step in the stack, but a row whose signature can
        // never verify must not buy a single directory walk with it — and no
        // authority gate may run on an unverified row. The move is
        // correctness-safe because the verdict is position-independent: the
        // gate reads only attestation_envelope / attesting_key_id /
        // scrub_signature_* / original_content_hash / tier, and NO gate in the
        // stack writes any of them (the sole field-stamping gate,
        // `check_withdraws_admission`, writes `withdraws_admission_rule`,
        // which this never reads).
        crate::federation::verify_federation_tier_ingest(self, &row).await?;

        // ── AV-76 TIER 4 — the DB-WALK authority gates ──────────────
        // Everything below walks the directory (delegation chains, family /
        // community membership, moderator sets, trust charters) — on this
        // backend by re-entering `self`, which takes the state lock itself, so
        // none of it may run under a held guard. All of it now runs only for a
        // row that has already proven its envelope is admissible in shape AND
        // that its signature verifies.

        // v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-path
        // cohort_scope admission gate. The writer (`attesting_key_id`) must be
        // a MEMBER of the target cohort they stamp. `self` + broad tiers pass
        // with no read; family/community (no `cohort_target_id` field on
        // attestations) are refused as a downgrade with no provable
        // membership. Runs AFTER the closed-set value validation in tier 1 and
        // BEFORE persist (verify-then-gate-then-persist, MISSION §1.6).
        crate::federation::FederationDirectory::check_write_cohort_scope_for(
            self,
            &row.attesting_key_id,
            "put_attestation",
            &row.cohort_scope,
            None,
        )
        .await?;

        // v2.5.0 (CIRISPersist#102 Ask 4) — envelope-schema admission hook.
        // Same shape and same tier position as the sqlite + postgres backends;
        // see `src/store/sqlite.rs` put_attestation for the architectural
        // commentary. Skipped on the default `NoOpSchemaResolver` (which
        // answers `None`), so nothing that passes today starts failing.
        // AV-76 D4 — recomputes the dimension rather than carrying a binding
        // across the reordered stack; `envelope_dimension` is pure.
        //
        // v22.0.0 (CIRISPersist#543) — the memory backend had no resolver field
        // and no call site, so this gate did not exist here. Latent, not live,
        // because the default resolver is a no-op — but a host installing a
        // REAL resolver got enforcement on two backends and silence on the
        // third.
        if row.attestation_type == crate::federation::types::attestation_type::SCORES {
            if let Some(dim_str) =
                crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            {
                let resolver = self.schema_resolver();
                let resolved = resolver.resolve(dim_str).await.map_err(|e| {
                    crate::federation::Error::Backend(format!(
                        "schema resolver: {} ({})",
                        e,
                        e.kind()
                    ))
                })?;
                if let Some(schema) = resolved {
                    if let Err(violations) =
                        crate::federation::schema_resolver::validate_envelope_against_schema(
                            &schema.document,
                            &row.attestation_envelope,
                        )
                    {
                        let axis = crate::federation::axis_from_dimension(dim_str)
                            .unwrap_or("")
                            .to_owned();
                        return Err(crate::federation::Error::EnvelopeSchemaViolation {
                            dimension: dim_str.to_string(),
                            axis,
                            violations,
                        });
                    }
                }
            }
        }

        // ── AV-76 TIER 4b — the §6.1 idempotent-replay short-circuit ──
        // v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer dedup
        // on `(references_attestation_id, attestation_type,
        // attesting_key_id)`. A duplicate composer is a typed `Ok(())` no-op;
        // the audit chain stays complete without accumulating replayed rows.
        // Non-composers (scores, delegates_to) skip this branch.
        //
        // v22.0.0 (CIRISPersist#543 / AV-76 D3) — the short-circuit sits HERE,
        // after crypto AND after the AV-45 write-scope gate, because **a dedup
        // short-circuit may return early to REFUSE, never to ACCEPT**: a
        // replay must still prove the properties of its own bytes and its
        // writer's standing before it earns an `Ok`. Ahead of them it is a
        // fail-open hole. See `src/store/sqlite.rs` put_attestation, AV-76
        // TIER 4b, for the full rationale and the shrunk counterexample.
        if crate::federation::precedence::is_structural_composer(&row.attestation_type) {
            let state = self.state.lock().expect("memory backend lock");
            for existing in &state.federation_attestations {
                if crate::federation::precedence::is_dedup_match(existing, &row) {
                    return Ok(());
                }
            }
        }

        // v6.4.0 (CIRISPersist#146 Ask 2, CEG §3.2.3) — broadened
        // `withdraws` admission gate (parity with sqlite + postgres). A
        // no-op for non-`withdraws` rows; for a `withdraws` it loads the
        // target T (by the envelope's `references_attestation_id`), resolves
        // WHICH of the 4 admission rules authorizes the issuer, and stamps
        // the rule number onto the row for the per-rule audit metadata. Runs
        // AFTER the §6.1 dedup (an idempotent replay short-circuits before
        // the walk) and BEFORE persist_row_hash, so a refused withdraws
        // leaves no trace and the recorded rule is covered by the row hash.
        if let Some(rule) =
            crate::federation::admission::check_withdraws_admission(self, &row).await?
        {
            row.withdraws_admission_rule = Some(rule);
        }

        // v8.7.1 (CIRISPersist#233, CEG §11.10) — FULL moderation gate for
        // the report→`scores` half (moderation:* / reconsideration:*).
        // A no-op for any non-matching row; for a moderation/review report
        // it admits IFF the signer IS a duty-holder over the target (the
        // row's subject_key_ids ∪ the envelope community_id's named
        // moderators) or is reached by an steward-bound duty-holder via a live
        // scoped delegates_to chain. Absence ⇒ REJECT.
        crate::federation::admission::check_delegated_duty_scores_admission(self, &row).await?;

        // v9.0.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5) — reject-agency-
        // on-node-key gate. A no-op for non-`delegates_to` rows; for a
        // `delegates_to` whose recipient (`attested_key_id`) resolves to a
        // node-ONLY identity it REJECTS any scope set that is not
        // `infra:*`-only (agency:* / legacy unprefixed agency / empty /
        // other) — "infrastructure must not have agency" made cryptographic.
        crate::federation::admission::check_node_agency_admission(self, &row).await?;

        // v11.5.0 (CIRISPersist#306, CC 3.2 / CC 1.15.6) — the user-target
        // steward-binding gate: a `delegates_to` onto a `user`-role target is
        // admissible ONLY as minor-guardianship (proven-minor target +
        // proven-adult-user granter). Backend-symmetric with SQLite +
        // Postgres; verify-before-mutation.
        crate::federation::admission::check_user_target_steward_binding_admission(self, &row)
            .await?;

        // v12.6.0 (CIRISConstitution#23, CC 1.13.3.3 / CC 3.2) — the single-owner
        // gate: a node has AT MOST ONE responsible steward, so a second,
        // distinct-owner owner-binding `delegates_to(U → node)` is rejected. This
        // is what makes the `self` cohort boundary well-defined. Backend-symmetric
        // with SQLite + Postgres; verify-before-mutation.
        crate::federation::admission::check_single_node_owner_admission(self, &row).await?;

        // v18.2.0 — trust-charter admission (the charter walk). AV-76: a
        // directory walk, so it stays in tier 4.
        crate::federation::trust_root::check_trust_charter_admission(
            self,
            &row.attestation_type,
            &row.attesting_key_id,
            &row.attested_key_id,
            &row.attestation_envelope,
        )
        .await?;
        // v24.0.0 (CIRISPersist#557) — a charter naming a constitutional family
        // must be signed by that family's QUORUM. Sits beside the key-charter
        // gate above and refuses the same class of row for the same reason: a
        // root that one seat can declare is not a threshold.
        crate::federation::trust_root::check_family_charter_admission(self, &row).await?;

        // v10.3.0 (CIRISPersist#288, CC 3.4.1/3.4.3/3.4.5) — reserved-prefix
        // admission on the attestation_TYPE namespace, keyed on the attesting
        // key's identity_type (a directory read), plus the #543 finding-2
        // dimension-keyed `capacity:*` self-emission arm. Backend-symmetric
        // with SQLite + Postgres.
        crate::federation::admission::check_reserved_prefix_admission(self, &row).await?;

        // v22.0.0 (CIRISConstitution#46) — CONSENT BEFORE SCORING. A
        // federation-tier `capacity:*` claim about subject S from attester P is
        // refused unless a live `analyze` consent from S covering P exists in
        // this node's verified corpus. AV-76 TIER 4: it reads the directory
        // (the scoped consent fold), so it must never run ahead of crypto.
        // Placed IMMEDIATELY after the reserved-prefix gate — which carries
        // AV-62/74's dimension-keyed self-emission arm — so a SELF-attested
        // capacity row is still reported as self-emission rather than shadowed
        // by "no consent". Backend-symmetric across memory / sqlite / postgres.
        crate::federation::admission::check_capacity_consent_admission(self, &row).await?;

        // v22.0.0 (CIRISPersist#543 / AV-77) — THE DE-ADMISSION GATE. A peer
        // this node has de-admitted gets its writes refused here. No-op when
        // the host installed no `self_key_id`: a node that has declared no
        // identity has authored no de-admissions, so the set is empty.
        //
        // v22.0.0 (CIRISPersist#543): absent on this backend entirely — the
        // gate, its `self_key_id` field and its accessor all shipped on sqlite
        // + postgres only, which made the CHANGELOG's "all five closed on all
        // three backends" false for AV-77. Same tier position as the SQL
        // backends so a refusal is named by the same gate everywhere.
        if let Some(me) = self.self_key_id() {
            crate::federation::admission::check_peer_deadmission(self, &row, &me).await?;
        }

        // v12.5.0 (CIRISPersist#238, CC 4.5.4 / §11.11) — no-moderator-no-
        // federate FEDERATION-APPLY re-check (point ii). A federation-tier row
        // keyed on a community is a federation apply step keyed on C; it is
        // refused if C has lost its last live `moderate`-holder (so a
        // moderator-less community cannot continue at moderated capability).
        // #369 broadened the keying: C is referenced via envelope
        // `community_id`/`community_key_id`/`cohort_key_id`, OR a row endpoint
        // / subject_key_ids entry resolving as a stored community (the
        // membership shape). No-op for local-tier rows and rows referencing no
        // locally-known community. Backend-symmetric.
        crate::federation::admission::check_no_moderator_federate_apply(self, &row).await?;
        // v24.0.0 (CIRISPersist#557) — the attested SUBJECT must resolve as a
        // key this node knows OR as a constitutional family it has stored. V114
        // lifted this rule out of the SQLite schema FK (which cannot express the
        // keyless-family exception a family trust root needs) into ONE predicate
        // every backend runs at this same point. All three DID enforce the rule
        // before (sqlite + postgres by FK, memory by emulation); what none of
        // them could express is the keyless-family exception.
        crate::federation::admission::check_attested_subject_admission(self, &row.attested_key_id)
            .await?;

        // ── AV-76 TIER 5 — hash + insert ────────────────────────────
        // D1: `check_withdraws_admission` above STAMPS
        // `row.withdraws_admission_rule`, and the row hash covers it — so that
        // gate must precede this block. It does.
        // v21.0.0 (#501) — capture the inbound trace projection while `row`
        // is still owned (before the push consumes it).
        let projected_trace =
            crate::ingest::project_trace_events_from_attestation(&row.attestation_envelope);
        // v31.0.0 (CIRISPersist#646) — carried OUT of the guard scope: the
        // reload the index derivation needs takes the same lock.
        let wire_index_key: Option<String>;

        {
            let mut state = self.state.lock().expect("memory backend lock");
            // v22.0.0 (CIRISPersist#543 / AV-79) — PRIMARY-KEY UNIQUENESS on
            // `attestation_id`, which this backend simply did not have.
            // `federation_attestations.attestation_id` is `TEXT PRIMARY KEY` on
            // both SQL backends (`migrations/sqlite/lens/V004__federation_directory.sql`,
            // `migrations/postgres/lens/V071__ceg_rc2_operational_data.sql`);
            // memory kept a `Vec` and pushed unconditionally, so two DIFFERENT
            // rows sharing one id both landed. That is worse than a missing
            // constraint, because the two read paths then disagree:
            // `get_attestation` answers with the FIRST row — so the second write
            // was accepted and then SHADOWED, and its writer believes it landed
            // when it did not — while `list_attestations_by` returns both, so
            // the same duplicate double-counts on every read that does not go
            // through `get_attestation`. Silent write loss on one path and
            // double-counting on the other, from one defect. Found by the
            // substrate state machine.
            //
            // Placement is TIER 5, at the insert point and AHEAD of the FK
            // emulation below, because that is where and in what order the SQL
            // engines enforce it: a row violating BOTH constraints reports
            // `UNIQUE constraint failed`, not `FOREIGN KEY constraint failed`
            // (SQLite inserts the PK index entry before the FK check). Hoisting
            // it above the tier-4 authority gates would change which gate names
            // a refusal and break the AV-76 cross-backend refusal-kind parity.
            //
            // The error MATCHES sqlite's byte for byte — same `Error::Backend`
            // variant (kind `federation_backend`), same message — because the
            // SQL backends map every non-FK insert failure through
            // `Backend(format!("insert attestation: {msg}"))`, and `assert_parity`
            // hard-asserts `error_kind` equality across backends. §6.1 replay is
            // unaffected: a structural composer replaying an existing triple
            // short-circuits at tier 4b and never reaches this line.
            if state
                .federation_attestations
                .iter()
                .any(|existing| existing.attestation_id == row.attestation_id)
            {
                return Err(crate::federation::Error::Backend(
                    "insert attestation: UNIQUE constraint failed: \
                     federation_attestations.attestation_id"
                        .to_string(),
                ));
            }

            // v24.0.0 (CIRISPersist#557) — the attested-subject rule moved to
            // the shared `check_attested_subject_admission` predicate (run at
            // tier 4b, above, on all three backends) so the keyless-family
            // exception a family trust root needs is expressible. What used to
            // be here was a hand-rolled emulation of the SQLite FK; the
            // emulation and the FK are now the same predicate.

            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // v17.4.0 (V106) — maintain the subject-index mirror.
            for subj in &row.subject_key_ids {
                state
                    .subject_index
                    .entry(subj.clone())
                    .or_default()
                    .push(row.attestation_id.clone());
            }
            // v21.0.0 (CIRISPersist#502 E7) — maintain the consent_peer_set
            // mirror (grant upsert / withdraws-revocation fold) BEFORE `row`
            // moves into `federation_attestations` below.
            if let Some(target_id) =
                crate::federation::consent_peer_set::revocation_fold_target(&row)
            {
                state
                    .consent_peer_set
                    .retain(|r| r.source_attestation_id != target_id);
            } else if crate::federation::consent_peer_set::is_consent_replication_grant(&row) {
                for peer in &row.subject_key_ids {
                    state.consent_peer_set.retain(|r| {
                        !(r.node_key_id == row.attesting_key_id && r.peer_key_id == *peer)
                    });
                    state.consent_peer_set.push(ConsentPeerRow {
                        node_key_id: row.attesting_key_id.clone(),
                        peer_key_id: peer.clone(),
                        source_attestation_id: row.attestation_id.clone(),
                        asserted_at: row.asserted_at,
                    });
                }
            }
            // v21.1.0 (CIRISPersist#507b) — wire-index this row (federation-
            // tier only, the E5 invariant). `Attestation` IS its own signed
            // wrapper (inline scrub signature). Computed before the push
            // moves `row`.
            // v31.0.0 (CIRISPersist#646) — indexed after the guard is
            // released, from the STORED row; see `index_stored_record`.
            wire_index_key = (row.tier == crate::federation::types::attestation_tier::FEDERATION)
                .then(|| {
                    crate::federation::wire_index::record_key(&[(
                        "attestation_id",
                        &row.attestation_id,
                    )])
                });
            state.federation_attestations.push(row);
            // v21.0.0 (CIRISPersist#501) — INBOUND trace projection: a replicated
            // `trace:complete:v1` attestation materializes its `trace_events`
            // rows (via the SAME decompose the ingest path uses), so a
            // replicated trace becomes scorer-readable through
            // `list_trace_summaries`. Idempotent (the trace_events dedup index);
            // inline form only (manifest payload is a fountain-fetch follow-up).
            // Block-scoped: the MutexGuard ends HERE, before the projection
            // awaits (drop() alone does not satisfy rustc's Send analysis).
        }
        if let Some(decomposed) = projected_trace {
            if !decomposed.events.is_empty() {
                self.insert_trace_events_batch(&decomposed.events)
                    .await
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!("trace projection: {e}"))
                    })?;
            }
            if !decomposed.llm_calls.is_empty() {
                self.insert_trace_llm_calls_batch(&decomposed.llm_calls)
                    .await
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!("trace llm projection: {e}"))
                    })?;
            }
        }
        if let Some(wire_index_key) = wire_index_key {
            self.index_stored_record("Attestation", &wire_index_key)
                .await?;
        }
        Ok(())
    }

    async fn list_scores(
        &self,
        caller_occurrence_key_id: &str,
        filter: crate::read::AttestationFilter,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::ScoresPage, crate::federation::Error> {
        use crate::federation::Error;
        use crate::read::LifecycleView;
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "AttestationCursor version {} unsupported; v1 only",
                    c.version
                )));
            }
        }
        let scope = crate::scope::caller_scope_from_directory(self, caller_occurrence_key_id)
            .await
            .map_err(|e| Error::Backend(format!("list_scores admission: {e}")))?;
        let hide: &[&str] = match filter.lifecycle {
            LifecycleView::Live => &["supersedes", "withdraws", "recants"],
            LifecycleView::IncludeSuperseded => &["withdraws", "recants"],
            LifecycleView::IncludeWithdrawn => &["supersedes", "recants"],
            LifecycleView::IncludeRecanted => &["supersedes", "withdraws"],
            LifecycleView::All => &[],
        };
        let state = self.state.lock().expect("memory backend lock");
        let all = &state.federation_attestations;
        let mut rows: Vec<crate::federation::Attestation> = all
            .iter()
            .filter(|r| mem_scores_row_matches(r, &filter, &scope))
            .filter(|r| {
                if hide.is_empty() {
                    return true;
                }
                // Exclude rows retracted by a still-hiding composer from the
                // same attester.
                !all.iter().any(|c| {
                    hide.contains(&c.attestation_type.as_str())
                        && c.attesting_key_id == r.attesting_key_id
                        && crate::federation::precedence::references_attestation_id_from_envelope(
                            &c.attestation_envelope,
                        ) == Some(r.attestation_id.as_str())
                })
            })
            .cloned()
            .collect();
        // (asserted_at DESC, attestation_id DESC).
        rows.sort_by(|a, b| {
            b.asserted_at
                .cmp(&a.asserted_at)
                .then_with(|| b.attestation_id.cmp(&a.attestation_id))
        });
        if let Some(c) = &cursor {
            rows.retain(|r| {
                (r.asserted_at, r.attestation_id.as_str())
                    < (c.last_asserted_at, c.last_attestation_id.as_str())
            });
        }
        let limit_usize = limit as usize;
        rows.truncate(limit_usize);
        let next_cursor = if rows.len() == limit_usize {
            rows.last().map(|last| {
                crate::read::AttestationCursor::from_trailing(
                    last.asserted_at,
                    last.attestation_id.clone(),
                )
            })
        } else {
            None
        };
        Ok(crate::read::ScoresPage {
            items: rows,
            next_cursor,
        })
    }

    async fn resolve_scores(
        &self,
        caller_occurrence_key_id: &str,
        filter: crate::read::AttestationFilter,
        policy: String,
        trace: bool,
    ) -> Result<crate::read::ComposedVerdict, crate::federation::Error> {
        use crate::federation::Error;
        let scope = crate::scope::caller_scope_from_directory(self, caller_occurrence_key_id)
            .await
            .map_err(|e| Error::Backend(format!("resolve_scores admission: {e}")))?;
        let (data, composers) = {
            let state = self.state.lock().expect("memory backend lock");
            let all = &state.federation_attestations;
            let mut data: Vec<crate::federation::Attestation> = all
                .iter()
                .filter(|r| {
                    r.attestation_type == crate::federation::types::attestation_type::SCORES
                        && mem_scores_row_matches(r, &filter, &scope)
                })
                .cloned()
                .collect();
            // #456 — bound the fold input at the newest RESOLVE_CANDIDATE_CAP
            // rows (parity with the sqlite/postgres LIMIT): sort DESC, truncate.
            data.sort_by(|a, b| {
                b.asserted_at
                    .cmp(&a.asserted_at)
                    .then_with(|| b.attestation_id.cmp(&a.attestation_id))
            });
            data.truncate(crate::federation::scores::RESOLVE_CANDIDATE_CAP as usize);
            let attesters: std::collections::HashSet<&str> =
                data.iter().map(|a| a.attesting_key_id.as_str()).collect();
            let composers: Vec<crate::federation::Attestation> = all
                .iter()
                .filter(|c| {
                    crate::federation::precedence::is_structural_composer(&c.attestation_type)
                        && attesters.contains(c.attesting_key_id.as_str())
                })
                .cloned()
                .collect();
            (data, composers)
        };
        Ok(crate::federation::scores::compose_verdict(
            data,
            composers,
            &policy,
            trace,
            chrono::Utc::now(),
        ))
    }

    async fn list_attestation_log(
        &self,
        subject_key_id: Option<&str>,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::ScoresPage, crate::federation::Error> {
        use crate::federation::Error;
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "AttestationCursor version {} unsupported; v1 only",
                    c.version
                )));
            }
        }
        // #455 — owner-scope LOG walk: NO caller gate, NO lifecycle folding,
        // federation-tier (the replicable set) only, byte-faithful rows.
        //
        // Scoped in a block so the state guard is DROPPED before the
        // quarantine consult below: `filter_withheld_rows` re-enters this
        // backend through `list_attestations_for`, which takes the same lock,
        // and a guard merely `drop()`ed still keeps the future non-`Send`.
        // (sqlite/postgres hold no equivalent guard at this point.)
        let limit_usize = limit as usize;
        let (rows, next_cursor) = {
            let state = self.state.lock().expect("memory backend lock");
            let mut rows: Vec<crate::federation::Attestation> = state
                .federation_attestations
                .iter()
                .filter(|r| {
                    r.tier == crate::federation::types::attestation_tier::FEDERATION
                        && subject_key_id
                            .is_none_or(|subj| r.subject_key_ids.iter().any(|s| s == subj))
                })
                .cloned()
                .collect();
            rows.sort_by(|a, b| {
                b.asserted_at
                    .cmp(&a.asserted_at)
                    .then_with(|| b.attestation_id.cmp(&a.attestation_id))
            });
            if let Some(c) = &cursor {
                rows.retain(|r| {
                    (r.asserted_at, r.attestation_id.as_str())
                        < (c.last_asserted_at, c.last_attestation_id.as_str())
                });
            }
            rows.truncate(limit_usize);
            let next_cursor = if rows.len() == limit_usize {
                rows.last().map(|last| {
                    crate::read::AttestationCursor::from_trailing(
                        last.asserted_at,
                        last.attestation_id.clone(),
                    )
                })
            } else {
                None
            };
            (rows, next_cursor)
        };

        // v25.1.0 (CIRISPersist#570 ask 5) — THE SERVE CONSULT. See the
        // sqlite twin for the full rationale, including why `next_cursor` is
        // computed BEFORE the filter (a fully-withheld page must still advance
        // the walk) and why pages may come back short.
        let items =
            crate::federation::quarantine::filter_withheld_rows(self, rows, chrono::Utc::now())
                .await?;
        Ok(crate::read::ScoresPage { items, next_cursor })
    }

    async fn record_announced_peer(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        claimed_identity_type: Option<&str>,
        last_seen: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::Error;
        if key_id.is_empty() || pubkey_ed25519_base64.is_empty() {
            return Err(Error::InvalidArgument(
                "record_announced_peer: key_id and pubkey_ed25519_base64 must be non-empty".into(),
            ));
        }
        let mut state = self.state.lock().expect("memory backend lock");
        match state.announced_peers.get_mut(key_id) {
            // #469 invariant 3 — Conflict on pubkey change (identity conflict,
            // not a refresh).
            Some(existing) if existing.pubkey_ed25519_base64 != pubkey_ed25519_base64 => {
                Err(Error::Conflict(format!(
                    "announced peer {key_id}: pubkey differs from the recorded announce \
                     (identity conflict, not a refresh)"
                )))
            }
            Some(existing) => {
                existing.last_seen_at = last_seen;
                existing.announce_count += 1;
                if let Some(pqc) = pubkey_ml_dsa_65_base64 {
                    existing.pubkey_ml_dsa_65_base64 = Some(pqc.to_owned());
                }
                if let Some(claimed) = claimed_identity_type {
                    existing.claimed_identity_type = Some(claimed.to_owned());
                }
                Ok(())
            }
            None => {
                state.announced_peers.insert(
                    key_id.to_owned(),
                    crate::federation::types::AnnouncedPeer {
                        key_id: key_id.to_owned(),
                        pubkey_ed25519_base64: pubkey_ed25519_base64.to_owned(),
                        pubkey_ml_dsa_65_base64: pubkey_ml_dsa_65_base64.map(str::to_owned),
                        claimed_identity_type: claimed_identity_type.map(str::to_owned),
                        first_seen_at: last_seen,
                        last_seen_at: last_seen,
                        announce_count: 1,
                    },
                );
                Ok(())
            }
        }
    }

    async fn list_announced_peers(
        &self,
    ) -> Result<Vec<crate::federation::types::AnnouncedPeer>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // #469 invariant 4 — anti-join federation_keys: an admitted key_id
        // supersedes its bookmark.
        let mut out: Vec<_> = state
            .announced_peers
            .values()
            .filter(|p| !state.federation_keys.contains_key(&p.key_id))
            .cloned()
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.last_seen_at));
        Ok(out)
    }

    async fn attestation_upsert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, crate::federation::Error> {
        self.memory_write_local_attestation(input, true).await
    }

    async fn attestation_insert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, crate::federation::Error> {
        self.memory_write_local_attestation(input, false).await
    }

    async fn list_attestations_for(
        &self,
        attested_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        self.attestation_reads_for
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.attested_key_id == attested_key_id
                    && a.tier == crate::federation::types::attestation_tier::FEDERATION
            })
            .cloned()
            .collect();
        // Match postgres ORDER BY asserted_at DESC.
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        Ok(rows)
    }

    async fn list_attestations_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        self.attestation_reads_by
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.attesting_key_id == attesting_key_id
                    && a.tier == crate::federation::types::attestation_tier::FEDERATION
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        Ok(rows)
    }

    /// v21.0.0 (CIRISPersist#502 E7) — the revocation-folded
    /// `consent_peer_set` read: `node_key_id`'s live peers, sorted +
    /// deduped. The fold already happened at write time (see
    /// `put_attestation`'s `consent_peer_set` mirror maintenance).
    async fn list_consent_peers(
        &self,
        node_key_id: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut peers: Vec<String> = state
            .consent_peer_set
            .iter()
            .filter(|r| r.node_key_id == node_key_id)
            .map(|r| r.peer_key_id.clone())
            .collect();
        peers.sort();
        peers.dedup();
        Ok(peers)
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — `node_key_id`'s LIVE
    /// `consent:replication:v1` self-grants: filtered by attester +
    /// dimension + presence in the `consent_peer_set` mirror (by
    /// `source_attestation_id`).
    async fn list_live_consent_grants_by(
        &self,
        node_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let live_ids: std::collections::HashSet<&str> = state
            .consent_peer_set
            .iter()
            .map(|r| r.source_attestation_id.as_str())
            .collect();
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.attesting_key_id == node_key_id
                    && crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                        == Some(crate::federation::consent_peer_set::DIMENSION)
                    && live_ids.contains(a.attestation_id.as_str())
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        Ok(rows)
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — the `promote_consented_backlog`
    /// sweep's page source: ascending-`attestation_id` keyset cursor over
    /// `local`-tier rows.
    async fn list_local_tier_attestations(
        &self,
        after_attestation_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.tier == crate::federation::types::attestation_tier::LOCAL
                    && match after_attestation_id {
                        Some(after) => a.attestation_id.as_str() > after,
                        None => true,
                    }
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        rows.truncate(limit as usize);
        Ok(rows)
    }

    /// v21.12.0 (CIRISPersist#530) — the repair sweep's page source: the
    /// stranded rows (`tier = 'federation'` with a suppressed
    /// `cohort_scope`). Twin of `list_local_tier_attestations`; the
    /// predicate uses [`crate::federation::types::cohort_scope::suppresses_holds_bytes`]
    /// (`self`/`family`) directly rather than a literal set so the memory
    /// backend can never drift from the taxonomy the SQL backends spell out.
    async fn list_stranded_federation_attestations(
        &self,
        after_attestation_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        use crate::federation::types::{attestation_tier, cohort_scope};
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.tier == attestation_tier::FEDERATION
                    && cohort_scope::suppresses_holds_bytes(&a.cohort_scope)
                    && match after_attestation_id {
                        Some(after) => a.attestation_id.as_str() > after,
                        None => true,
                    }
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        rows.truncate(limit as usize);
        Ok(rows)
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — the promote-on-consent
    /// write-back: validate against the closed cohort_scope set, stamp
    /// it, and recompute `persist_row_hash`.
    async fn set_attestation_cohort_scope(
        &self,
        attestation_id: &str,
        cohort_scope: &str,
    ) -> Result<(), crate::federation::Error> {
        if !crate::federation::types::cohort_scope::is_valid(cohort_scope) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "set_attestation_cohort_scope: invalid cohort_scope {cohort_scope:?}"
            )));
        }
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let row = state
                .federation_attestations
                .iter_mut()
                .find(|a| a.attestation_id == attestation_id)
                .ok_or_else(|| {
                    crate::federation::Error::InvalidArgument(format!(
                        "federation_attestations row {attestation_id} does not exist"
                    ))
                })?;
            // CIRISPersist#592 (AV-84) — THE SECOND PLACEMENT DOOR.
            // `repair_stranded_scope_backlog` re-scopes an already-federation row
            // to a covering grant's audience through here, which can be
            // `community` — so without this the standing gate on
            // `promote_attestation` would have a door beside it, this repo's own
            // recurring class.
            //
            // Gated on a CANDIDATE clone, before `row` is touched: this backend
            // holds `&mut` into live state, so stamping first and checking second
            // would leave a REFUSED re-scope having already mutated the row — the
            // AV-9 violation sqlite/postgres are structurally protected from by
            // working on a loaded copy. Memory tolerating what the SQL backends
            // reject is exactly the class this ordering exists to deny.
            let mut candidate = row.clone();
            candidate.cohort_scope = cohort_scope.to_owned();
            crate::federation::admission::check_promotion_cohort_standing(&candidate)?;

            row.cohort_scope = cohort_scope.to_owned();
            let mut for_hash = row.clone();
            for_hash.persist_row_hash = String::new();
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
            // v30.1.0 (CIRISPersist#610) — the wire index moves WITH the row.
            // Same defect as the two SQL backends: this mutator recomputes
            // `persist_row_hash`, so without re-indexing the row advertises a hash
            // the index does not hold and the pack path cannot serve what the offer
            // path offered. Federation-tier only, per the E5 invariant that governs
            // the put path's own indexing.
            (row.tier == crate::federation::types::attestation_tier::FEDERATION).then(|| {
                crate::federation::wire_index::record_key(&[(
                    "attestation_id",
                    &row.attestation_id,
                )])
            })
        };
        if let Some(wire_index_key) = wire_index_key {
            self.index_stored_record("Attestation", &wire_index_key)
                .await?;
        }
        Ok(())
    }

    async fn attestations_binding_content(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        // v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10) — the
        // content-establishing `scores` rows that bind `content_sha256`
        // in their envelope `evidence_refs` array. The in-memory scan
        // mirrors the SQL backends' filter exactly (federation-tier
        // `scores`, exact `evidence_refs` set-membership).
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.attestation_type == crate::federation::types::attestation_type::SCORES
                    && a.tier == crate::federation::types::attestation_tier::FEDERATION
                    && crate::federation::admission::envelope_binds_content(
                        &a.attestation_envelope,
                        content_sha256,
                    )
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        Ok(rows)
    }

    async fn put_revocation(
        &self,
        revocation: crate::federation::SignedRevocation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = revocation.revocation;
        // v3.4.0 (CIRISPersist#123) — trust gate first; the revoking key is
        // the attester. v22.0.0 (CIRISPersist#543 finding 4): backend-
        // symmetric with sqlite + postgres, which have gated this path
        // since v3.4.0 while memory silently did not.
        if !row.revoking_key_id.is_empty() {
            if let Some(gate) = self.admission_gate() {
                gate.check_federation(&row.revoking_key_id).await?;
            }
        }
        // v30.8.0 (CIRISPersist#596 item 1) — revoking SOMEONE ELSE'S key is a
        // moderation act. Self-revocation passes untouched.
        crate::federation::admission::check_revocation_authority(self, &row).await?;
        // v21.0.0 (CIRISPersist#502 E1) — mechanistic authorship BEFORE the
        // state lock (the verify resolves keys via the directory, which
        // locks itself). Hybrid-Strict vs the revoking key's registered
        // pubkeys — was FK + trust-score only, forgeable de-peer DoS.
        crate::federation::verify_revocation_admission(self, &row).await?;
        // v25.1.0 (CIRISPersist#570 ask 4) — the history bound must be the one
        // that was SIGNED, and must be coherent with `effective_at`. Runs
        // before persist_row_hash and before the push, so a refused bound
        // leaves no trace (AV-9) — and runs HERE, on memory, because the
        // backend-symmetry lesson has cost this repo seven releases.
        crate::federation::check_revocation_bound(&row)?;
        let mut state = self.state.lock().expect("memory backend lock");
        if !state.federation_keys.contains_key(&row.revoked_key_id) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "revoked_key_id {} does not exist in federation_keys",
                row.revoked_key_id
            )));
        }
        if !state.federation_keys.contains_key(&row.revoking_key_id) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "revoking_key_id {} does not exist in federation_keys",
                row.revoking_key_id
            )));
        }
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        state.federation_revocations.push(row);
        Ok(())
    }

    async fn revocations_for(
        &self,
        revoked_key_id: &str,
    ) -> Result<Vec<crate::federation::Revocation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_revocations
            .iter()
            .filter(|r| r.revoked_key_id == revoked_key_id)
            .cloned()
            .collect();
        // Match postgres ORDER BY effective_at DESC.
        rows.sort_by_key(|a| std::cmp::Reverse(a.effective_at));
        Ok(rows)
    }

    // ── CEG 0.7 identity_occurrence + family (v3.12.0, #153) ───────

    async fn put_identity_occurrence(
        &self,
        occurrence: crate::federation::SignedIdentityOccurrence,
    ) -> Result<(), crate::federation::Error> {
        // v14.0.0 (CIRISPersist#418) — verify the signature gate BEFORE any write
        // (before locking; the gate locks state internally). Backend-symmetric.
        crate::federation::admission::verify_signed_identity_occurrence(self, &occurrence).await?;
        let mut row = occurrence.identity_occurrence;
        crate::federation::check_device_class(&row.device_class)?;
        crate::federation::check_encryption_pubkeys(row.encryption_pubkeys.as_ref())?;
        // #446 — the projection is computed inside the lock scope but applied
        // after it (put_transport_destination takes the lock itself), ONLY
        // when the occurrence write applied.
        // v31.0.0 (CIRISPersist#646) — same for the wire-index derivation: it
        // reloads through the read surface, which takes this lock.
        let mut indexed: Option<String> = None;
        let projected_route = {
            let mut state = self.state.lock().expect("memory backend lock");
            if !state.federation_keys.contains_key(&row.identity_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "identity_key_id {} does not exist in federation_keys",
                    row.identity_key_id
                )));
            }
            if !state.federation_keys.contains_key(&row.occurrence_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "occurrence_key_id {} does not exist in federation_keys",
                    row.occurrence_key_id
                )));
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // Last-signed-wins: only a strictly-newer asserted_at supersedes.
            let key = (row.identity_key_id.clone(), row.occurrence_key_id.clone());
            let newer = state
                .federation_identity_occurrences
                .get(&key)
                .is_none_or(|ex| row.asserted_at > ex.asserted_at);
            let projected_route = if newer {
                row.transport_binding
                    .as_ref()
                    .map(|tb| tb.project_route(&row.occurrence_key_id, row.asserted_at))
                    .transpose()?
            } else {
                None
            };
            if newer {
                // v21.1.0 (CIRISPersist#507b) — computed before the moves
                // below consume `row` / `occurrence.*`.
                let wire_index_key = crate::federation::wire_index::record_key(&[
                    ("identity_key_id", &row.identity_key_id),
                    ("occurrence_key_id", &row.occurrence_key_id),
                ]);
                // #418 — store the signature container in lockstep so the
                // replication read reconstructs the tuple that was put.
                state.federation_identity_occurrence_sigs.insert(
                    key.clone(),
                    (
                        occurrence.attesting_key_id,
                        occurrence.signed_envelope,
                        occurrence.signature,
                    ),
                );
                state.federation_identity_occurrences.insert(key, row);
                indexed = Some(wire_index_key);
            }
            projected_route
        };
        if let Some(wire_index_key) = indexed {
            self.index_stored_record("IdentityOccurrence", &wire_index_key)
                .await?;
        }
        if let Some(route) = &projected_route {
            crate::federation::FederationDirectory::put_transport_destination(self, route).await?;
        }
        Ok(())
    }

    async fn put_identity_occurrence_local(
        &self,
        occurrence: crate::federation::IdentityOccurrence,
    ) -> Result<(), crate::federation::Error> {
        // #418 — trusted-local (grandfathered) write; NO signature gate.
        let mut row = occurrence;
        crate::federation::check_device_class(&row.device_class)?;
        crate::federation::check_encryption_pubkeys(row.encryption_pubkeys.as_ref())?;
        // #446 — the trusted-local path projects too (accepted write);
        // applied after the lock scope.
        let projected_route = {
            let mut state = self.state.lock().expect("memory backend lock");
            if !state.federation_keys.contains_key(&row.identity_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "identity_key_id {} does not exist in federation_keys",
                    row.identity_key_id
                )));
            }
            if !state.federation_keys.contains_key(&row.occurrence_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "occurrence_key_id {} does not exist in federation_keys",
                    row.occurrence_key_id
                )));
            }
            // v21.17.1 (CIRISPersist#541) — parity with sqlite/postgres' `WHERE
            // signature IS NULL`: a SIGNED occurrence (an entry in the sig map for
            // this PK) is authoritative and is NEVER overwritten by the local
            // writer, so a later content-only self-write cannot NULL its
            // envelope-covered columns while its signature survives and make the
            // replicated row diverge from its own envelope. Memory previously
            // HashMap::inserted unconditionally — the one-backend divergence this
            // whole issue is about.
            let pk = (row.identity_key_id.clone(), row.occurrence_key_id.clone());
            if state.federation_identity_occurrence_sigs.contains_key(&pk) {
                return Ok(());
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            let projected_route = row
                .transport_binding
                .as_ref()
                .map(|tb| tb.project_route(&row.occurrence_key_id, row.asserted_at))
                .transpose()?;
            state.federation_identity_occurrences.insert(
                (row.identity_key_id.clone(), row.occurrence_key_id.clone()),
                row,
            );
            projected_route
        };
        if let Some(route) = &projected_route {
            crate::federation::FederationDirectory::put_transport_destination(self, route).await?;
        }
        Ok(())
    }

    // ── transport_destination (CIRISPersist#183, CEG §5.6.8.8.1) ───

    async fn put_transport_destination(
        &self,
        destination: &crate::federation::TransportDestination,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // v13.9.1 (CIRISPersist#416) — NO federation_keys existence check. The
        // V078 FK was dropped in V101: an `Advisory` binding (CC 3.3.6.2) legit-
        // imately names a not-yet-rooted key that is NOT in federation_keys, and
        // admit-advisory MUST record it (the routing hint). Trust is composed by
        // the consumer (prefer `Rooted`; content gate CC 6 N1), never a substrate
        // reject. Kept backend-symmetric with the FK-less sqlite/postgres tables.
        //
        // v17.0.0 (#443) — route-table PK (occ, kind) + the (epoch,
        // asserted_at) monotonic guard: a stale assertion is a silent no-op.
        //
        // v21.4.0 (CIRISPersist#515) — SIGNED WINS THE SHARED KEY: an
        // unsigned writer never demotes a signed row. The signature
        // container is NEVER dropped by this path; a content-CHANGING
        // unsigned write against a signed row is a silent no-op (the
        // signed content is authoritative); a same-content refresh (or any
        // write over an unsigned row) applies the plain monotonic upsert.
        // Parity with the sqlite/postgres guards.
        let key = (
            destination.occurrence_key_id.clone(),
            destination.transport_kind.clone(),
        );
        let existing = state.transport_destinations.get(&key);
        let clock_newer = existing.is_none_or(|ex| {
            (destination.epoch, destination.asserted_at) > (ex.epoch, ex.asserted_at)
        });
        let stored_signed = state.transport_destination_sigs.contains_key(&key);
        let same_material_content = existing.is_some_and(|ex| {
            ex.destination == destination.destination
                && ex.transport_ed25519_pubkey_base64 == destination.transport_ed25519_pubkey_base64
                && ex.transport_x25519_pubkey_base64 == destination.transport_x25519_pubkey_base64
        });
        //
        // v21.17.1 (CIRISPersist#541) — THE PRESERVE SET MUST EQUAL THE
        // VERIFIED SET. `same_material_content` above compares only three
        // columns, but `verify_signed_transport_destination` checks NINE —
        // everything except `last_seen_at`. So a same-content liveness refresh
        // used to overwrite the whole typed row (advancing `asserted_at` /
        // `epoch`, and able to flip `binding_provenance` or `retired_at`)
        // while `transport_destination_sigs` kept the byte-exact envelope,
        // leaving the row divergent from its own signature and refused by
        // every peer. On a signed row an unsigned writer may now advance ONLY
        // the advisory liveness clock. Parity with the sqlite/postgres CASE
        // guards.
        if clock_newer && (!stored_signed || same_material_content) {
            if stored_signed {
                if let Some(row) = state.transport_destinations.get_mut(&key) {
                    row.last_seen_at = destination.last_seen_at;
                }
            } else {
                state
                    .transport_destinations
                    .insert(key, destination.clone());
            }
        }
        Ok(())
    }

    async fn put_signed_transport_destination(
        &self,
        signed: &crate::federation::SignedTransportDestination,
    ) -> Result<crate::federation::TransportDestinationApplyOutcome, crate::federation::Error> {
        use crate::federation::TransportDestinationApplyOutcome as Outcome;
        // #443 — the admission gate BEFORE any write (before locking; the
        // gate locks state internally). Backend-symmetric.
        crate::federation::admission::verify_signed_transport_destination(self, signed).await?;
        let d = &signed.transport_destination;
        let (wire_index_key, fresh) = {
            let mut state = self.state.lock().expect("memory backend lock");
            let key = (d.occurrence_key_id.clone(), d.transport_kind.clone());
            // v21.4.0 (CIRISPersist#515) — SIGNED WINS THE SHARED KEY: the
            // monotonic-clock refusal applies only against a stored row that is
            // itself SIGNED; a signed write always reclaims an unsigned row
            // (occurrence-projection / announce state) regardless of clocks.
            let stored_signed = state.transport_destination_sigs.contains_key(&key);
            let fresh = match state.transport_destinations.get(&key) {
                Some(ex) if *ex == *d && stored_signed => return Ok(Outcome::Unchanged),
                Some(ex)
                    if stored_signed && (d.epoch, d.asserted_at) <= (ex.epoch, ex.asserted_at) =>
                {
                    return Ok(Outcome::Refused {
                        reason: format!(
                            "incoming (epoch {}, asserted_at {}) does not supersede stored \
                         SIGNED (epoch {}, asserted_at {})",
                            d.epoch,
                            d.asserted_at.to_rfc3339(),
                            ex.epoch,
                            ex.asserted_at.to_rfc3339()
                        ),
                    })
                }
                Some(_) => false,
                None => true,
            };
            // Store the signature container in lockstep so the replication read
            // reconstructs the tuple that was put (mirror of the occurrence /
            // revocation sig maps).
            state.transport_destination_sigs.insert(
                key.clone(),
                (
                    signed.attesting_key_id.clone(),
                    signed.signed_envelope.clone(),
                    signed.signature.clone(),
                ),
            );
            state.transport_destinations.insert(key.clone(), d.clone());
            // v21.1.0 (CIRISPersist#507b) — `signed` IS the exact value
            // `list_signed_transport_destinations_since` re-serializes.
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("occurrence_key_id", &key.0),
                ("transport_kind", &key.1),
            ]);
            (wire_index_key, fresh)
        };
        self.index_stored_record("TransportDestination", &wire_index_key)
            .await?;
        Ok(if fresh {
            Outcome::Inserted
        } else {
            Outcome::Superseded
        })
    }

    async fn list_transport_destinations_for(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<crate::federation::TransportDestination>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // #443 — live routes only (retired tombstones excluded).
        let mut rows: Vec<_> = state
            .transport_destinations
            .values()
            .filter(|d| d.occurrence_key_id == occurrence_key_id && d.retired_at.is_none())
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.transport_kind.cmp(&b.transport_kind));
        Ok(rows)
    }

    async fn list_signed_transport_destinations_for(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<crate::federation::SignedTransportDestination>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // #443 replication read: join each route with its stored signature
        // container; trusted-local rows (no sig entry) are omitted. RETIRED
        // rows are INCLUDED — tombstones must gossip.
        let mut rows: Vec<crate::federation::SignedTransportDestination> = state
            .transport_destinations
            .iter()
            .filter(|((occ, _), _)| occ == occurrence_key_id)
            .filter_map(|(key, td)| {
                state.transport_destination_sigs.get(key).map(
                    |(attesting_key_id, signed_envelope, signature)| {
                        crate::federation::SignedTransportDestination {
                            transport_destination: td.clone(),
                            attesting_key_id: attesting_key_id.clone(),
                            signed_envelope: signed_envelope.clone(),
                            signature: signature.clone(),
                        }
                    },
                )
            })
            .collect();
        rows.sort_by(|a, b| {
            a.transport_destination
                .transport_kind
                .cmp(&b.transport_destination.transport_kind)
        });
        Ok(rows)
    }

    async fn list_all_transport_destinations(
        &self,
    ) -> Result<Vec<crate::federation::TransportDestination>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // #443 — live routes only, ordered by the route key (deterministic
        // restore; one row per (occ, kind) is structural).
        let mut rows: Vec<_> = state
            .transport_destinations
            .values()
            .filter(|d| d.retired_at.is_none())
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.occurrence_key_id
                .cmp(&b.occurrence_key_id)
                .then_with(|| a.transport_kind.cmp(&b.transport_kind))
        });
        Ok(rows)
    }

    async fn list_transport_destinations_by_destination(
        &self,
        destination: &str,
    ) -> Result<Vec<crate::federation::TransportDestination>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // #443 — live routes only.
        let mut rows: Vec<_> = state
            .transport_destinations
            .values()
            .filter(|d| d.destination == destination && d.retired_at.is_none())
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.occurrence_key_id
                .cmp(&b.occurrence_key_id)
                .then_with(|| a.transport_kind.cmp(&b.transport_kind))
        });
        Ok(rows)
    }

    async fn remove_transport_destination(
        &self,
        occurrence_key_id: &str,
        transport_kind: &str,
        destination: &str,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // #443 — local-only DELETE (never replicated; retirement on the mesh
        // is a signed tombstone put). `destination` still selects: only the
        // row currently carrying that address is dropped — parity with the
        // sqlite/postgres `AND destination = ?` DELETE.
        let key = (occurrence_key_id.to_owned(), transport_kind.to_owned());
        let matches = state
            .transport_destinations
            .get(&key)
            .is_some_and(|d| d.destination == destination);
        if matches {
            state.transport_destinations.remove(&key);
            state.transport_destination_sigs.remove(&key);
        }
        Ok(matches)
    }

    // ── freshness_floor (CIRISPersist#519 item 2a-iii) ─────────────

    async fn put_touch_claim(
        &self,
        claim: &crate::federation::types::SignedTouchClaim,
    ) -> Result<crate::federation::TouchApplyOutcome, crate::federation::Error> {
        use crate::federation::TouchApplyOutcome as Outcome;
        // v21.6.0 (#519 item 2a-iii) — verify-before-mutation (before
        // locking; the gate locks state internally via lookup_public_key).
        // Mirrors put_signed_transport_destination's ordering.
        crate::federation::admission::verify_signed_touch_claim(self, claim).await?;
        crate::federation::admission::verify_touch_claim_admission(
            claim,
            chrono::Utc::now(),
            crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
        )?;
        let mut state = self.state.lock().expect("memory backend lock");
        let key = (claim.target_key_id.clone(), claim.target_kind.clone());
        // Monotonic-max merge: `fresh_as_of` only ever advances.
        let advances = state
            .freshness_floor
            .get(&key)
            .is_none_or(|ex| claim.fresh_as_of > ex.fresh_as_of);
        if advances {
            state.freshness_floor.insert(key, claim.clone());
            Ok(Outcome::Advanced)
        } else {
            Ok(Outcome::NotFresher)
        }
    }

    async fn lookup_freshness_floor(
        &self,
        target_key_id: &str,
        target_kind: &str,
    ) -> Result<Option<crate::federation::types::SignedTouchClaim>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let key = (target_key_id.to_owned(), target_kind.to_owned());
        Ok(state.freshness_floor.get(&key).cloned())
    }

    async fn list_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::IdentityOccurrence>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_identity_occurrences
            .values()
            .filter(|o| o.identity_key_id == identity_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.occurrence_key_id.cmp(&b.occurrence_key_id));
        Ok(rows)
    }

    async fn list_signed_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::SignedIdentityOccurrence>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // #418 replication read: join each occurrence with its stored signature
        // container; trusted-local rows (no sig entry) are omitted.
        let mut rows: Vec<crate::federation::SignedIdentityOccurrence> = state
            .federation_identity_occurrences
            .iter()
            .filter(|((id, _), _)| id == identity_key_id)
            .filter_map(|(key, occ)| {
                state.federation_identity_occurrence_sigs.get(key).map(
                    |(attesting_key_id, signed_envelope, signature)| {
                        crate::federation::SignedIdentityOccurrence {
                            identity_occurrence: occ.clone(),
                            attesting_key_id: attesting_key_id.clone(),
                            signed_envelope: signed_envelope.clone(),
                            signature: signature.clone(),
                        }
                    },
                )
            })
            .collect();
        rows.sort_by(|a, b| {
            a.identity_occurrence
                .occurrence_key_id
                .cmp(&b.identity_occurrence.occurrence_key_id)
        });
        Ok(rows)
    }

    async fn lookup_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<crate::federation::IdentityOccurrence>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .federation_identity_occurrences
            .values()
            .find(|o| o.occurrence_key_id == occurrence_key_id)
            .cloned())
    }

    async fn put_family(
        &self,
        family: crate::federation::SignedFamily,
    ) -> Result<(), crate::federation::Error> {
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE the
        // state lock (the verify resolves keys via the directory, which
        // locks itself). Hybrid-Strict vs the authority's registered
        // pubkeys — was FK-existence only, a forgeable keyless declaration.
        crate::federation::verify_family_admission(self, &family).await?;
        let crate::federation::SignedFamily {
            family: row,
            authority_key_id,
            scrub_signature_classical,
            scrub_signature_pqc,
        } = family;
        let family_key_id = row.family_key_id.clone();
        self.put_family_local(row).await?;
        // v21.0.0 (CIRISPersist#502 E4 followup) — persist the authority
        // signature the gate above already verified (was verified-then-
        // discarded: the durable row had no home for it, so it couldn't
        // prove its own authorship later). `put_family_local` (the
        // genesis-bake bypass) is untouched — its rows are legitimately
        // unsigned; this side-map entry is written only on the signed,
        // gate-verified path.
        self.state
            .lock()
            .expect("memory backend lock")
            .federation_family_authority_sigs
            .insert(
                family_key_id.clone(),
                (
                    authority_key_id.clone(),
                    scrub_signature_classical.clone(),
                    scrub_signature_pqc.clone(),
                ),
            );
        // v21.1.0 (CIRISPersist#507b) — wire-index the FULL `SignedFamily`
        // shape `list_signed_families_since` re-serializes. Reload rather
        // than reuse the pre-write `Family` value: `put_family_local` stamps
        // `persist_row_hash` on its OWN local copy, invisible from here.
        self.index_stored_record(
            "Family",
            &crate::federation::wire_index::record_key(&[("family_key_id", &family_key_id)]),
        )
        .await?;
        Ok(())
    }

    async fn put_family_local(
        &self,
        mut row: crate::federation::types::Family,
    ) -> Result<(), crate::federation::Error> {
        // v3.12.0 — value-validation admission (consensus_protocol
        // canonical form). Full signature-counting enforcement is v3.13+.
        crate::federation::check_consensus_protocol_form(&row.consensus_protocol)?;
        // v13.3.0 (CIRISPersist#386) — the real invariant (replaces the dropped
        // family_key_id FK): every member key_id must be a registered key.
        crate::federation::admission::validate_family_members(self, &row).await?;
        // v24.0.0 (CIRISPersist#557) — the `family_key_id ∈ federation_keys`
        // check that used to sit here is GONE, four cuts after it should have
        // been. v13.3.0 (#386) dropped that FK on sqlite and postgres precisely
        // because **a constitutional family is KEYLESS** — the family_key_id is
        // an identifier, not a key — and replaced it with the member-validation
        // above; the memory backend kept enforcing the dropped constraint, with
        // the comment on the line above already describing the replacement. It
        // went unnoticed because nothing seeds genesis on memory, and it surfaced
        // here as "the one backend where a family trust root cannot exist".
        let mut state = self.state.lock().expect("memory backend lock");
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        state
            .federation_families
            .insert(row.family_key_id.clone(), row);
        Ok(())
    }

    async fn add_family_member(
        &self,
        family_key_id: &str,
        member: crate::federation::types::FamilyMember,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let family = state
            .federation_families
            .get_mut(family_key_id)
            .ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!(
                    "add_family_member names unknown family_key_id {family_key_id:?}"
                ))
            })?;
        if family.members.iter().any(|m| m.key_id == member.key_id) {
            return Ok(false); // already on the roster — no-op
        }
        family.members.push(member);
        family.persist_row_hash = crate::federation::types::compute_persist_row_hash(family)?;
        Ok(true)
    }

    async fn lookup_family(
        &self,
        family_key_id: &str,
    ) -> Result<Option<crate::federation::Family>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_families.get(family_key_id).cloned())
    }

    // ── #249 Cut B ── incremental community-roster grow (mirror of
    //    add_family_member).
    async fn add_community_member(
        &self,
        community_key_id: &str,
        member: crate::federation::types::CommunityMember,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let community = state
            .federation_communities
            .get_mut(community_key_id)
            .ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!(
                    "add_community_member names unknown community_key_id {community_key_id:?}"
                ))
            })?;
        if community.members.iter().any(|m| m.key_id == member.key_id) {
            return Ok(false); // already on the roster — no-op
        }
        community.members.push(member);
        community.persist_row_hash = crate::federation::types::compute_persist_row_hash(community)?;
        Ok(true)
    }

    // #249 Cut G2 — supersede + versioning (CIRISServer #249 §3/§8).
    async fn supersede_group_row(
        &self,
        cohort: crate::federation::cohort::Cohort,
        new_snapshot: serde_json::Value,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, crate::federation::Error> {
        use crate::federation::cohort::{Cohort, GroupVersion};
        use crate::federation::Error;
        // CC 4.4.3.2.8 / #308: `affiliations` keys its version history under its
        // own discriminator while sharing the `federation_communities` storage.
        let cohort_str = match cohort {
            Cohort::SelfId => {
                return Err(Error::InvalidArgument(
                    "supersede: the `self` cohort is not versioned".to_string(),
                ))
            }
            Cohort::Family | Cohort::Community | Cohort::Affiliations => {
                cohort.as_str().to_string()
            }
        };
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        match cohort {
            Cohort::Family => {
                let mut new_fam: crate::federation::Family = serde_json::from_value(new_snapshot)
                    .map_err(|e| {
                    Error::InvalidArgument(format!("supersede family snapshot decode: {e}"))
                })?;
                new_fam.persist_row_hash =
                    crate::federation::types::compute_persist_row_hash(&new_fam)?;
                let key = new_fam.family_key_id.clone();
                let prior = state
                    .federation_families
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| {
                        Error::InvalidArgument(format!(
                            "supersede: unknown family group {key:?} (nothing to supersede)"
                        ))
                    })?;
                let cur_ver = *state
                    .federation_group_current_version
                    .get(&(cohort_str.clone(), key.clone()))
                    .unwrap_or(&1);
                let snapshot = serde_json::to_value(&prior).unwrap_or(serde_json::Value::Null);
                state
                    .federation_group_versions
                    .entry((cohort_str.clone(), key.clone()))
                    .or_default()
                    .push(GroupVersion {
                        cohort,
                        group_key_id: key.clone(),
                        version: cur_ver,
                        snapshot,
                        authorization,
                        superseded_at: Some(now),
                        is_current: false,
                    });
                state.federation_families.insert(key.clone(), new_fam);
                let next = cur_ver + 1;
                state
                    .federation_group_current_version
                    .insert((cohort_str, key), next);
                Ok(next)
            }
            Cohort::Community | Cohort::Affiliations => {
                let mut new_comm: crate::federation::Community =
                    serde_json::from_value(new_snapshot).map_err(|e| {
                        Error::InvalidArgument(format!("supersede community snapshot decode: {e}"))
                    })?;
                new_comm.persist_row_hash =
                    crate::federation::types::compute_persist_row_hash(&new_comm)?;
                let key = new_comm.community_key_id.clone();
                let prior = state
                    .federation_communities
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| {
                        Error::InvalidArgument(format!(
                            "supersede: unknown community group {key:?} (nothing to supersede)"
                        ))
                    })?;
                let cur_ver = *state
                    .federation_group_current_version
                    .get(&(cohort_str.clone(), key.clone()))
                    .unwrap_or(&1);
                let snapshot = serde_json::to_value(&prior).unwrap_or(serde_json::Value::Null);
                state
                    .federation_group_versions
                    .entry((cohort_str.clone(), key.clone()))
                    .or_default()
                    .push(GroupVersion {
                        cohort,
                        group_key_id: key.clone(),
                        version: cur_ver,
                        snapshot,
                        authorization,
                        superseded_at: Some(now),
                        is_current: false,
                    });
                state.federation_communities.insert(key.clone(), new_comm);
                let next = cur_ver + 1;
                state
                    .federation_group_current_version
                    .insert((cohort_str, key), next);
                Ok(next)
            }
            Cohort::SelfId => unreachable!("guarded above"),
        }
    }

    // #249 Cut G2 (§8) — full version chain: history rows + the live current.
    async fn list_group_versions(
        &self,
        cohort: crate::federation::cohort::Cohort,
        group_key_id: &str,
    ) -> Result<Vec<crate::federation::cohort::GroupVersion>, crate::federation::Error> {
        use crate::federation::cohort::{Cohort, GroupVersion};
        use crate::federation::Error;
        if cohort == Cohort::SelfId {
            return Err(Error::InvalidArgument(
                "list_group_versions: the `self` cohort is not versioned".to_string(),
            ));
        }
        // CC 4.4.3.2.8 / #308: `affiliations` reads its own history chain.
        let cohort_str = cohort.as_str().to_string();
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<GroupVersion> = state
            .federation_group_versions
            .get(&(cohort_str.clone(), group_key_id.to_string()))
            .cloned()
            .unwrap_or_default();
        let cur_ver = *state
            .federation_group_current_version
            .get(&(cohort_str, group_key_id.to_string()))
            .unwrap_or(&1);
        let live = match cohort {
            Cohort::Family => state
                .federation_families
                .get(group_key_id)
                .map(|f| serde_json::to_value(f).unwrap_or(serde_json::Value::Null)),
            // CC 4.4.3.2.8 / #308: `affiliations` reads the shared community row.
            Cohort::Community | Cohort::Affiliations => state
                .federation_communities
                .get(group_key_id)
                .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null)),
            Cohort::SelfId => None,
        };
        if let Some(snapshot) = live {
            out.push(GroupVersion {
                cohort,
                group_key_id: group_key_id.to_string(),
                version: cur_ver,
                snapshot,
                authorization: None,
                superseded_at: None,
                is_current: true,
            });
        }
        out.sort_by_key(|v| v.version);
        Ok(out)
    }

    async fn list_families_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<crate::federation::Family>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_families
            .values()
            .filter(|f| f.members.iter().any(|m| m.key_id == member_identity_key_id))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.family_key_id.cmp(&b.family_key_id));
        Ok(rows)
    }

    async fn put_community(
        &self,
        community: crate::federation::SignedCommunity,
    ) -> Result<(), crate::federation::Error> {
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any
        // other admission step (mirrors put_family). Hybrid-Strict vs the
        // authority's registered pubkeys.
        crate::federation::verify_community_admission(self, &community).await?;
        let mut row = community.community;
        // v4.0 — value-validation admission (consensus_protocol
        // canonical form). Mirrors put_family.
        crate::federation::check_consensus_protocol_form(&row.consensus_protocol)?;
        // v4.11.0 (#154 Ask 4) — geographic cohort_subkind admission. Runs
        // BEFORE the state lock below: it reads via list_location_proofs_for
        // (which locks state itself), so calling it under the lock would
        // deadlock. No-op for non-geographic communities.
        crate::federation::location::check_geographic_community_admission(
            self,
            &row,
            chrono::Utc::now(),
        )
        .await?;
        // v9.0.0 (CC 3.2 / CC 3.4.7.1) — steward-binding precondition for
        // non-infrastructure community membership. Resolves member
        // identity_type + steward-binding via the directory (locks state
        // itself), so it MUST run before the state lock below to avoid a
        // re-entrant deadlock. No-op for infrastructure communities and
        // for rosters with no node/agent members.
        crate::federation::admission::check_community_membership_steward_binding(self, &row)
            .await?;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            if !state.federation_keys.contains_key(&row.community_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "community_key_id {} does not exist in federation_keys",
                    row.community_key_id
                )));
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // v21.1.0 (CIRISPersist#507b) — computed before the moves below
            // consume `row.clone()` / `community.*`.
            let wire_index_key = crate::federation::wire_index::record_key(&[(
                "community_key_id",
                &row.community_key_id,
            )]);
            // v21.0.0 (CIRISPersist#502 E4 followup) — persist the authority
            // signature the gate above already verified (was verified-then-
            // discarded).
            state.federation_community_authority_sigs.insert(
                row.community_key_id.clone(),
                (
                    community.authority_key_id,
                    community.scrub_signature_classical,
                    community.scrub_signature_pqc,
                ),
            );
            state
                .federation_communities
                .insert(row.community_key_id.clone(), row);
            wire_index_key
        };
        self.index_stored_record("Community", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn lookup_community(
        &self,
        community_key_id: &str,
    ) -> Result<Option<crate::federation::Community>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_communities.get(community_key_id).cloned())
    }

    async fn list_communities_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<crate::federation::Community>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_communities
            .values()
            .filter(|c| c.members.iter().any(|m| m.key_id == member_identity_key_id))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.community_key_id.cmp(&b.community_key_id));
        Ok(rows)
    }

    // ─── #302 (FSD-004) accord live-quorum storage ──────────────────────

    async fn put_accord_proposal(
        &self,
        proposal: ciris_verify_core::accord_live_quorum::AccordProposal,
        authority_signature: Option<serde_json::Value>,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::Error;
        // M4 fail-closed (self.accord_nonce_issued locks state — run before).
        if !self
            .accord_nonce_issued(&proposal.family_key_id, &proposal.nonce)
            .await?
        {
            return Err(Error::InvalidArgument(format!(
                "accord proposal nonce {:?} not issued for family {:?} (M4 fail-closed)",
                proposal.nonce, proposal.family_key_id
            )));
        }
        let prep = crate::federation::accord_quorum::prepare_proposal(
            &proposal,
            authority_signature,
            chrono::Utc::now(),
        )?;
        let crate::federation::accord_quorum::PreparedProposal {
            proposal_digest,
            persist_row_hash,
            created_at,
            authority_signature,
            ..
        } = prep;
        let stored = crate::federation::accord_quorum::StoredProposal {
            proposal,
            authority_signature,
            persist_row_hash,
            created_at,
        };
        let mut state = self.state.lock().expect("memory backend lock");
        // Content-derived digest ⇒ insert-if-absent is idempotent.
        state
            .accord_proposals
            .entry(proposal_digest)
            .or_insert(stored);
        Ok(())
    }

    async fn get_accord_proposal(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<crate::federation::accord_quorum::StoredProposal>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.accord_proposals.get(proposal_digest).cloned())
    }

    async fn list_accord_proposals_by_anchor(
        &self,
        action: &str,
        prior_family_digest: &str,
    ) -> Result<Vec<crate::federation::accord_quorum::StoredProposal>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .accord_proposals
            .values()
            .filter(|p| {
                p.proposal.action.as_str() == action
                    && p.proposal.prior_family_digest == prior_family_digest
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.proposal.digest().cmp(&b.proposal.digest()))
        });
        Ok(rows)
    }

    async fn put_accord_participation(
        &self,
        participation: ciris_verify_core::accord_live_quorum::AccordParticipation,
        standing_roster: &[ciris_verify_core::threshold::ThresholdMember],
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::Error;
        // Proposal must exist (get locks state — run before our lock).
        let stored_proposal = self
            .get_accord_proposal(&participation.proposal_digest)
            .await?
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "accord participation references unknown proposal {:?}",
                    participation.proposal_digest
                ))
            })?;
        let prep = crate::federation::accord_quorum::verify_and_prepare_participation(
            &stored_proposal.proposal,
            &participation,
            standing_roster,
            chrono::Utc::now(),
        )?;
        let crate::federation::accord_quorum::PreparedParticipation {
            proposal_digest,
            pinned_pubkey,
            server_arrival_at,
            persist_row_hash,
            ..
        } = prep;
        let mut state = self.state.lock().expect("memory backend lock");
        // M6 durable dedup by (proposal_digest, pinned_pubkey).
        if let Some(existing) = state.accord_participations.iter().find(|p| {
            p.participation.proposal_digest == proposal_digest && p.pinned_pubkey == pinned_pubkey
        }) {
            if existing.persist_row_hash == persist_row_hash {
                return Ok(());
            }
            return Err(Error::Conflict(format!(
                "accord participation: holder (pinned pubkey) already voted differently on proposal {proposal_digest:?} (M6 — one vote per holder)"
            )));
        }
        state
            .accord_participations
            .push(crate::federation::accord_quorum::StoredParticipation {
                participation,
                pinned_pubkey,
                server_arrival_at,
                persist_row_hash,
            });
        Ok(())
    }

    async fn list_accord_participations(
        &self,
        proposal_digest: &str,
    ) -> Result<Vec<crate::federation::accord_quorum::StoredParticipation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .accord_participations
            .iter()
            .filter(|p| p.participation.proposal_digest == proposal_digest)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.server_arrival_at
                .cmp(&b.server_arrival_at)
                .then_with(|| a.pinned_pubkey.cmp(&b.pinned_pubkey))
        });
        Ok(rows)
    }

    async fn put_accord_decision(
        &self,
        decision: ciris_verify_core::accord_live_quorum::AccordDecision,
        steward_signatures: Option<serde_json::Value>,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::Error;
        let prep = crate::federation::accord_quorum::prepare_decision(
            &decision,
            steward_signatures,
            chrono::Utc::now(),
        )?;
        let crate::federation::accord_quorum::PreparedDecision {
            proposal_digest,
            persist_row_hash,
            decided_at,
            steward_signatures,
            ..
        } = prep;
        let mut state = self.state.lock().expect("memory backend lock");
        // Immutable (M2): identical re-PUT no-ops, a differing one conflicts.
        if let Some(existing) = state.accord_decisions.get(&proposal_digest) {
            if existing.persist_row_hash == persist_row_hash {
                return Ok(());
            }
            return Err(Error::Conflict(format!(
                "accord decision for proposal {proposal_digest:?} already recorded with different content (M2 — immutable)"
            )));
        }
        state.accord_decisions.insert(
            proposal_digest,
            crate::federation::accord_quorum::StoredDecision {
                decision,
                steward_signatures,
                persist_row_hash,
                decided_at,
            },
        );
        Ok(())
    }

    async fn get_accord_decision(
        &self,
        proposal_digest: &str,
    ) -> Result<Option<crate::federation::accord_quorum::StoredDecision>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.accord_decisions.get(proposal_digest).cloned())
    }

    async fn set_active_halt(
        &self,
        family_key_id: &str,
        active_halt_id: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        state.accord_active_halts.insert(
            family_key_id.to_owned(),
            crate::federation::accord_quorum::ActiveHalt {
                family_key_id: family_key_id.to_owned(),
                active_halt_id: active_halt_id.to_owned(),
                set_at: chrono::Utc::now(),
            },
        );
        Ok(())
    }

    async fn get_active_halt(
        &self,
        family_key_id: &str,
    ) -> Result<Option<crate::federation::accord_quorum::ActiveHalt>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.accord_active_halts.get(family_key_id).cloned())
    }

    async fn clear_active_halt(
        &self,
        family_key_id: &str,
        active_halt_id: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // Only clear the matching halt (a stale-halt resume is a no-op).
        let matches = state
            .accord_active_halts
            .get(family_key_id)
            .is_some_and(|h| h.active_halt_id == active_halt_id);
        if matches {
            state.accord_active_halts.remove(family_key_id);
        }
        Ok(())
    }

    async fn issue_accord_nonce(
        &self,
        family_key_id: &str,
        nonce: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        state
            .accord_issued_nonces
            .insert((family_key_id.to_owned(), nonce.to_owned()));
        Ok(())
    }

    async fn accord_nonce_issued(
        &self,
        family_key_id: &str,
        nonce: &str,
    ) -> Result<bool, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .accord_issued_nonces
            .contains(&(family_key_id.to_owned(), nonce.to_owned())))
    }

    // ─── v4.8.0 (CIRISPersist#161, CEG §11.7.1) — membership revocations.

    async fn put_identity_occurrence_revocation(
        &self,
        revocation: crate::federation::SignedIdentityOccurrenceRevocation,
    ) -> Result<(), crate::federation::Error> {
        // v16.0.0 (CIRISPersist#421) — verify the signature gate BEFORE any
        // write (before locking; the gate locks state internally).
        crate::federation::admission::verify_signed_identity_occurrence_revocation(
            self,
            &revocation,
        )
        .await?;
        let crate::federation::SignedIdentityOccurrenceRevocation {
            identity_occurrence_revocation: mut row,
            attesting_key_id,
            signed_envelope,
            signature,
        } = revocation;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            for k in [&row.identity_key_id, &row.occurrence_key_id] {
                if !state.federation_keys.contains_key(k) {
                    return Err(crate::federation::Error::InvalidArgument(format!(
                        "{k} does not exist in federation_keys"
                    )));
                }
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            let key = (row.identity_key_id.clone(), row.occurrence_key_id.clone());
            // v21.1.0 (CIRISPersist#507b) — computed before the moves below
            // consume `row` / `attesting_key_id` / `signed_envelope` / `signature`.
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("identity_key_id", &key.0),
                ("occurrence_key_id", &key.1),
            ]);
            // #421 — store the signature container in lockstep so the replication
            // read reconstructs the tuple that was put (mirror of the occurrence
            // sig map).
            state
                .federation_identity_occurrence_revocation_sigs
                .insert(key.clone(), (attesting_key_id, signed_envelope, signature));
            let revoked_at = row.revoked_at;
            let occurrence_key_id = row.occurrence_key_id.clone();
            state
                .federation_identity_occurrence_revocations
                .insert(key, row);
            // #446 de-projection (the projection's inverse): retire the LOCAL
            // derived route materialized from this occurrence's binding. Narrow
            // on purpose: only the signature-free projected/local row; a live
            // SIGNED route retires via its own #443 signed-tombstone plane.
            let route_key = (
                occurrence_key_id,
                crate::federation::types::OccurrenceTransportBinding::TRANSPORT_KIND.to_owned(),
            );
            if !state.transport_destination_sigs.contains_key(&route_key) {
                if let Some(route) = state.transport_destinations.get_mut(&route_key) {
                    if route.retired_at.is_none() {
                        route.retired_at = Some(revoked_at);
                    }
                }
            }
            wire_index_key
        };
        self.index_stored_record("IdentityOccurrenceRevocation", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn put_identity_occurrence_revocation_local(
        &self,
        revocation: crate::federation::IdentityOccurrenceRevocation,
    ) -> Result<(), crate::federation::Error> {
        // #421 — trusted-local (grandfathered) write; NO signature gate, no sig
        // map entry (the signed read omits local rows).
        let mut row = revocation;
        let mut state = self.state.lock().expect("memory backend lock");
        for k in [&row.identity_key_id, &row.occurrence_key_id] {
            if !state.federation_keys.contains_key(k) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{k} does not exist in federation_keys"
                )));
            }
        }
        // v21.17.1 (CIRISPersist#541) — a second write to the same PK is REFUSED,
        // matching sqlite/postgres (a bare INSERT into a PK'd table errors on the
        // duplicate). Memory previously HashMap::inserted unconditionally,
        // silently overwriting `revoked_at`/`effective_at` under any stored
        // signature — a one-backend divergence on `effective_at`, flagged in-code
        // (admission.rs) as "the whole attack".
        let pk = (row.identity_key_id.clone(), row.occurrence_key_id.clone());
        if state
            .federation_identity_occurrence_revocations
            .contains_key(&pk)
        {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "identity_occurrence_revocation already recorded for ({}, {}) — a second local \
                 revocation write is refused (parity with sqlite/postgres unique-key error, #541)",
                row.identity_key_id, row.occurrence_key_id
            )));
        }
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        let revoked_at = row.revoked_at;
        let occurrence_key_id = row.occurrence_key_id.clone();
        state
            .federation_identity_occurrence_revocations
            .insert(pk, row);
        // #446 de-projection — mirrors the signed revocation path.
        let route_key = (
            occurrence_key_id,
            crate::federation::types::OccurrenceTransportBinding::TRANSPORT_KIND.to_owned(),
        );
        if !state.transport_destination_sigs.contains_key(&route_key) {
            if let Some(route) = state.transport_destinations.get_mut(&route_key) {
                if route.retired_at.is_none() {
                    route.retired_at = Some(revoked_at);
                }
            }
        }
        Ok(())
    }

    async fn put_family_membership_revocation(
        &self,
        revocation: crate::federation::SignedFamilyMembershipRevocation,
    ) -> Result<(), crate::federation::Error> {
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE the
        // state lock (the verify resolves keys via the directory, which
        // locks itself). Was FK-existence only — a forged removal was
        // indistinguishable from a real one.
        crate::federation::verify_family_membership_revocation_admission(self, &revocation).await?;
        let mut row = revocation.family_membership_revocation;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            for k in [&row.family_key_id, &row.removed_identity_key_id] {
                if !state.federation_keys.contains_key(k) {
                    return Err(crate::federation::Error::InvalidArgument(format!(
                        "{k} does not exist in federation_keys"
                    )));
                }
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // CEG §7.7 (CIRISPersist#161 Ask 5) — emit the removal-direction
            // membership-change hard_case (`change_kind: "removed"`), keyed on
            // the re-key epoch (`effective_at`). Idempotent on the event_id.
            let event = crate::federation::hard_case::membership_removed_event(
                crate::federation::hard_case::kind::FAMILY_MEMBERSHIP_CHANGE,
                &row.family_key_id,
                &row.removed_identity_key_id,
                row.effective_at,
            );
            state
                .federation_hard_case_events
                .entry(event.event_id.clone())
                .or_insert(event);
            let revocation_key = (
                row.family_key_id.clone(),
                row.removed_identity_key_id.clone(),
            );
            // v21.1.0 (CIRISPersist#507b) — computed before the moves below
            // consume `row.clone()` / `revocation.*`.
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("family_key_id", &revocation_key.0),
                ("removed_identity_key_id", &revocation_key.1),
            ]);
            // v21.0.0 (CIRISPersist#502 E4 followup) — persist the authority
            // signature the gate above already verified (was verified-then-
            // discarded).
            state
                .federation_family_membership_revocation_authority_sigs
                .insert(
                    revocation_key.clone(),
                    (
                        revocation.authority_key_id,
                        revocation.scrub_signature_classical,
                        revocation.scrub_signature_pqc,
                    ),
                );
            state
                .federation_family_membership_revocations
                .insert(revocation_key, row);
            wire_index_key
        };
        self.index_stored_record("FamilyMembershipRevocation", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn put_community_membership_revocation(
        &self,
        revocation: crate::federation::SignedCommunityMembershipRevocation,
    ) -> Result<(), crate::federation::Error> {
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any
        // other admission step. THE worst-case E4 hole: an unverified
        // removal here rotates the community DEK epoch below — an
        // unauthenticated forward-secrecy DoS.
        crate::federation::verify_community_membership_revocation_admission(self, &revocation)
            .await?;
        let mut row = revocation.community_membership_revocation;
        // SecReview F4 — community removal is immediate for forward-secrecy;
        // reject a future-dated effective_at BEFORE any state mutation
        // (3-backend parity with pg + sqlite).
        crate::federation::community_dek::reject_future_dated_community_revocation(
            row.effective_at,
        )?;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            for k in [&row.community_key_id, &row.removed_identity_key_id] {
                if !state.federation_keys.contains_key(k) {
                    return Err(crate::federation::Error::InvalidArgument(format!(
                        "{k} does not exist in federation_keys"
                    )));
                }
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // Parity with pg/sqlite: the revocation table PK is
            // (community_key_id, removed_identity_key_id) (V067), so a REPLAYED
            // revocation hits a unique-violation at the INSERT and errors BEFORE
            // the hard_case emission + epoch bump. Memory must reject the replay
            // the same way (else memory would double-bump the DEK epoch where
            // pg/sqlite leave it untouched — an observable gate-path divergence).
            // Matches map_revocation_pg_err's non-FK Backend mapping.
            let revocation_key = (
                row.community_key_id.clone(),
                row.removed_identity_key_id.clone(),
            );
            if state
                .federation_community_membership_revocations
                .contains_key(&revocation_key)
            {
                return Err(crate::federation::Error::Backend(format!(
                    "insert community_membership_revocation: duplicate key value violates unique \
                 constraint (community_key_id={}, removed_identity_key_id={})",
                    revocation_key.0, revocation_key.1
                )));
            }
            // CEG §7.8 (CIRISPersist#161 Ask 5) — community analog of the §7.7
            // removal emission (`change_kind: "removed"`). Idempotent on event_id.
            let event = crate::federation::hard_case::membership_removed_event(
                crate::federation::hard_case::kind::COMMUNITY_MEMBERSHIP_CHANGE,
                &row.community_key_id,
                &row.removed_identity_key_id,
                row.effective_at,
            );
            state
                .federation_hard_case_events
                .entry(event.event_id.clone())
                .or_insert(event);
            // CC 4.4.3.2.2 rotation-on-removal: advance the community DEK epoch
            // (the at-rest crypto half lives only on the BlobStorage backends;
            // memory carries the rotation *state* so rotation-on-removal is
            // observably present here too). Only on a genuinely new revocation
            // (replays errored out above) — parity with pg/sqlite. Bump first →
            // revocation insert moves `row`.
            *state
                .federation_community_dek_epoch
                .entry(row.community_key_id.clone())
                .or_insert(0) += 1;
            // v21.1.0 (CIRISPersist#507b) — computed before the moves below
            // consume `row.clone()` / `revocation.*`.
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("community_key_id", &revocation_key.0),
                ("removed_identity_key_id", &revocation_key.1),
            ]);
            // v21.0.0 (CIRISPersist#502 E4 followup) — persist the authority
            // signature the gate above already verified (was verified-then-
            // discarded).
            state
                .federation_community_membership_revocation_authority_sigs
                .insert(
                    revocation_key.clone(),
                    (
                        revocation.authority_key_id,
                        revocation.scrub_signature_classical,
                        revocation.scrub_signature_pqc,
                    ),
                );
            state
                .federation_community_membership_revocations
                .insert(revocation_key, row);
            wire_index_key
        };
        self.index_stored_record("CommunityMembershipRevocation", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn list_identity_occurrence_revocations_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::IdentityOccurrenceRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_identity_occurrence_revocations
            .values()
            .filter(|r| r.identity_key_id == identity_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.occurrence_key_id.cmp(&b.occurrence_key_id));
        Ok(rows)
    }

    async fn list_signed_identity_occurrence_revocations_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::SignedIdentityOccurrenceRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        // #421 replication read: join each revocation with its stored signature
        // container; trusted-local rows (no sig entry) are omitted.
        let mut rows: Vec<crate::federation::SignedIdentityOccurrenceRevocation> = state
            .federation_identity_occurrence_revocations
            .iter()
            .filter(|((id, _), _)| id == identity_key_id)
            .filter_map(|(key, rev)| {
                state
                    .federation_identity_occurrence_revocation_sigs
                    .get(key)
                    .map(|(attesting_key_id, signed_envelope, signature)| {
                        crate::federation::SignedIdentityOccurrenceRevocation {
                            identity_occurrence_revocation: rev.clone(),
                            attesting_key_id: attesting_key_id.clone(),
                            signed_envelope: signed_envelope.clone(),
                            signature: signature.clone(),
                        }
                    })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.identity_occurrence_revocation
                .occurrence_key_id
                .cmp(&b.identity_occurrence_revocation.occurrence_key_id)
        });
        Ok(rows)
    }

    async fn list_family_membership_revocations_for(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<crate::federation::FamilyMembershipRevocation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_family_membership_revocations
            .values()
            .filter(|r| r.family_key_id == family_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.removed_identity_key_id.cmp(&b.removed_identity_key_id));
        Ok(rows)
    }

    async fn list_community_membership_revocations_for(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<crate::federation::CommunityMembershipRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_community_membership_revocations
            .values()
            .filter(|r| r.community_key_id == community_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.removed_identity_key_id.cmp(&b.removed_identity_key_id));
        Ok(rows)
    }

    // ─── v6.7.0 (CIRISPersist#146 Ask 3 / #161 Ask 5) — hard_case:* surface.
    //     Memory parity with the sqlite/postgres `hard_case_events` table so
    //     the substrate's removal/SLA emissions behave identically on all
    //     three backends. Idempotent on the deterministic `event_id`.

    async fn record_hard_case(
        &self,
        event: crate::federation::hard_case::HardCaseEvent,
    ) -> Result<(), crate::federation::Error> {
        // v25.1.0 (CIRISPersist#570 ask 3) — the attribution gate.
        // Verify-before-mutation: an `admin_action` record that does not carry
        // {delegation_id, reason} is refused naming WHICH, and no row is
        // written. A no-op for every observed-condition kind.
        crate::federation::check_admin_action_attribution(&event)?;
        let mut state = self.state.lock().expect("memory backend lock");
        state
            .federation_hard_case_events
            .entry(event.event_id.clone())
            .or_insert(event);
        Ok(())
    }

    /// CIRISServer#356 — this backend DOES charge peer writes
    /// (`peer_write_quota.check_write` on the `put_attestation` path), so it
    /// answers rather than taking the `None` default.
    fn peer_quota_observation(
        &self,
    ) -> Option<crate::federation::replication::admission::PeerQuotaObservation> {
        Some(self.peer_write_quota.observe())
    }

    async fn list_hard_case_events(
        &self,
        filter: crate::federation::hard_case::HardCaseFilter,
    ) -> Result<Vec<crate::federation::hard_case::HardCaseEvent>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_hard_case_events
            .values()
            .filter(|e| filter.kind.as_ref().is_none_or(|k| &e.kind == k))
            .filter(|e| filter.since.is_none_or(|s| e.emitted_at >= s))
            .cloned()
            .collect();
        // Match the SQL backends: newest first, event_id as a stable tiebreak.
        rows.sort_by(|a, b| {
            b.emitted_at
                .cmp(&a.emitted_at)
                .then_with(|| b.event_id.cmp(&a.event_id))
        });
        Ok(rows)
    }

    // ─── v12.5.0 (CIRISPersist#238 / #146, CEG §8.1.11.3 / §10.1.3) —
    //     subject-side consent revocations for the consent-SLA watcher. Memory
    //     parity with the sqlite/postgres backends (the default trait impl
    //     errors); the promotion-overdue check
    //     ([`run_consent_sla_watch`]) needs local-tier rows too, so this is
    //     NOT tier-filtered (unlike list_attestations_for, which is
    //     federation-only).

    async fn list_consent_revocations(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        use crate::federation::types::attestation_type;
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                // Subject-side revocations only: a `withdraws` admitted under
                // rule 2/3/4 (rule 1 is the producer's own self-revoke, not a
                // consent event), OR a `consent:state:revoked` stance.
                let is_subject_withdraws = a.attestation_type == attestation_type::WITHDRAWS
                    && matches!(a.withdraws_admission_rule, Some(2..=4));
                let is_consent_revoked = a
                    .attestation_envelope
                    .get("dimension")
                    .and_then(|v| v.as_str())
                    .is_some_and(|d| {
                        d.starts_with(
                            crate::federation::consent::consent_dimension::STATE_REVOKED_PREFIX,
                        )
                    });
                is_subject_withdraws || is_consent_revoked
            })
            .filter(|a| since.is_none_or(|s| a.asserted_at >= s))
            .cloned()
            .collect();
        // Match the SQL backends: ORDER BY asserted_at DESC.
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        Ok(rows)
    }

    // ─── v8.2.0 (CEG 1.0-RC11 §19.1) — WholenessWitness corpus.

    async fn put_wholeness_witness(
        &self,
        witness: &ciris_verify_core::holonomic::WholenessWitness,
        sig_ed25519_b64: &str,
        sig_ml_dsa_65_b64: Option<&str>,
        pqc_key_id: &str,
        ed25519_pubkey_b64: &str,
        ml_dsa_65_pubkey_b64: Option<&str>,
        disclosed_leaves: Option<&[Vec<u8>]>,
    ) -> Result<(), crate::federation::Error> {
        // Verify-BEFORE-persist (N3 / RC8 / AV-9): full hybrid-PQC gate +
        // WW-2 namespace guard + optional leaf/root recompute. On any
        // failure NOTHING is written.
        let stored = crate::witness::admit_witness(
            witness,
            sig_ed25519_b64,
            sig_ml_dsa_65_b64,
            pqc_key_id,
            ed25519_pubkey_b64,
            ml_dsa_65_pubkey_b64,
            disclosed_leaves,
        )?;
        let mut state = self.state.lock().expect("memory backend lock");
        let bucket = state
            .wholeness_witnesses
            .entry(stored.peer_id.clone())
            .or_default();
        // Idempotent on (peer_id, epoch_id, observed_at_unix_ms).
        if !bucket.iter().any(|w| {
            w.epoch_id == stored.epoch_id && w.observed_at_unix_ms == stored.observed_at_unix_ms
        }) {
            bucket.push(stored);
        }
        // Prune to the last-K by observed_at (newest kept).
        bucket.sort_by_key(|w| w.observed_at_unix_ms);
        if bucket.len() > crate::witness::WITNESS_CORPUS_K {
            let drop_n = bucket.len() - crate::witness::WITNESS_CORPUS_K;
            bucket.drain(0..drop_n);
        }
        Ok(())
    }

    async fn list_wholeness_witnesses_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<Vec<crate::witness::StoredWitness>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .wholeness_witnesses
            .get(peer_id)
            .cloned()
            .unwrap_or_default();
        // Newest first (parity with the SQL backends' ORDER BY DESC).
        rows.sort_by_key(|w| std::cmp::Reverse(w.observed_at_unix_ms));
        Ok(rows)
    }

    async fn last_witness_epoch_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<Option<u64>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .wholeness_witnesses
            .get(peer_id)
            .and_then(|b| b.iter().map(|w| w.epoch_id).max()))
    }

    async fn list_witness_peer_ids(&self) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut peers: Vec<String> = state
            .wholeness_witnesses
            .iter()
            .filter(|(_, b)| !b.is_empty())
            .map(|(p, _)| p.clone())
            .collect();
        // Sorted (parity with the SQL backends' ORDER BY).
        peers.sort_unstable();
        Ok(peers)
    }

    // ─── v4.10.0 (CIRISPersist#154, CEG 0.8 §0.8.1) — location proofs.

    async fn put_location_proof(
        &self,
        proof: crate::federation::SignedLocationProof,
    ) -> Result<(), crate::federation::Error> {
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any
        // other admission step.
        crate::federation::verify_location_proof_admission(self, &proof).await?;
        let mut row = proof.location_proof;
        // §0.8 canonicalization + §0.8.1 rough-only gate before write.
        crate::federation::location::validate_location_cell(&row.cell_id, row.cell_resolution)?;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            if !state.federation_keys.contains_key(&row.subject_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "subject_key_id {} does not exist in federation_keys",
                    row.subject_key_id
                )));
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            let proof_key = (row.subject_key_id.clone(), row.asserted_at);
            // v21.1.0 (CIRISPersist#507b) — computed before the moves below
            // consume `row.clone()` / `proof.*`.
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("subject_key_id", &proof_key.0),
                (
                    "asserted_at",
                    &crate::federation::wire_index::locator_instant(&proof_key.1),
                ),
            ]);
            // v21.0.0 (CIRISPersist#502 E4 followup) — persist the authority
            // signature the gate above already verified (was verified-then-
            // discarded).
            state.federation_location_proof_authority_sigs.insert(
                proof_key.clone(),
                (
                    proof.authority_key_id,
                    proof.scrub_signature_classical,
                    proof.scrub_signature_pqc,
                ),
            );
            state.federation_location_proofs.insert(proof_key, row);
            wire_index_key
        };
        self.index_stored_record("LocationProof", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn list_location_proofs_for(
        &self,
        subject_key_id: &str,
    ) -> Result<Vec<crate::federation::LocationProof>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_location_proofs
            .values()
            .filter(|p| p.subject_key_id == subject_key_id)
            .cloned()
            .collect();
        rows.sort_by_key(|p| p.asserted_at);
        Ok(rows)
    }

    async fn communities_containing(
        &self,
        cell_id: &str,
    ) -> Result<Vec<crate::federation::Community>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_communities
            .values()
            .filter(|c| {
                crate::federation::location::geographic_constraint_cell(c.policy_blob.as_ref())
                    .is_some_and(|constraint| {
                        crate::federation::location::h3_cell_contained(cell_id, &constraint)
                    })
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.community_key_id.cmp(&b.community_key_id));
        Ok(rows)
    }

    // ── CEG 1.0-RC2 §5.6.8.13 operational data (v5.1.0, #65) ───────

    async fn put_organization(
        &self,
        signed: crate::federation::SignedOrganization,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::operational;
        let mut row = signed.organization;
        let now = chrono::Utc::now();
        operational::check_skew_and_payment(row.asserted_at, now, &row.signed_envelope)?;
        // v31.0.0 (#644) — bind the projection + hybrid-Strict verify the
        // row's OWN signature. Before the state lock: the verify resolves
        // the attester's registered pubkeys, which locks the directory.
        operational::verify_organization_admission(self, &row).await?;
        // v21.0.0 (#502 E9) — resolve the steward roster from OUR directory
        // BEFORE the state lock (the resolve locks the directory itself).
        let (__stw_dir, __stw_roots) = operational::resolve_steward_roster(self).await?;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let current: Vec<_> = state
                .federation_org_memberships
                .values()
                .filter(|m| m.org_id == row.org_id)
                .cloned()
                .collect();
            operational::check_role_authority(
                &row.attesting_key_id,
                &row.org_id,
                &current,
                &__stw_dir,
                &__stw_roots,
            )?;
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // v21.1.0 (CIRISPersist#507b) — `Organization` carries its own
            // single-signer signature fields inline — it IS the value
            // `list_organizations_since` re-serializes, no separate wrapper.
            // Computed before the insert below moves `row`.
            let wire_index_key = crate::federation::wire_index::record_key(&[(
                "attestation_id",
                &row.attestation_id,
            )]);
            memory_idempotent_insert(
                &mut state.federation_organizations,
                row.attestation_id.clone(),
                row,
                "organization",
            )?;
            wire_index_key
        };
        self.index_stored_record("Organization", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn put_org_membership(
        &self,
        signed: crate::federation::SignedOrgMembership,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::operational;
        let mut row = signed.org_membership;
        let now = chrono::Utc::now();
        operational::check_skew_and_payment(row.asserted_at, now, &row.signed_envelope)?;
        // v31.0.0 (#644) — bind the projection + hybrid-Strict verify the
        // row's OWN signature, before the lock (see `put_organization`).
        operational::verify_org_membership_admission(self, &row).await?;
        // v21.0.0 (#502 E9) — roster from OUR directory, before the lock.
        let (__stw_dir, __stw_roots) = operational::resolve_steward_roster(self).await?;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let current: Vec<_> = state
                .federation_org_memberships
                .values()
                .filter(|m| m.org_id == row.org_id)
                .cloned()
                .collect();
            operational::check_role_authority(
                &row.attesting_key_id,
                &row.org_id,
                &current,
                &__stw_dir,
                &__stw_roots,
            )?;
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // v21.1.0 (CIRISPersist#507b) — `OrgMembership` carries its own
            // single-signer signature fields inline; see `put_organization`'s
            // wire-index comment.
            let wire_index_key = crate::federation::wire_index::record_key(&[(
                "attestation_id",
                &row.attestation_id,
            )]);
            memory_idempotent_insert(
                &mut state.federation_org_memberships,
                row.attestation_id.clone(),
                row,
                "org_membership",
            )?;
            wire_index_key
        };
        self.index_stored_record("OrgMembership", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn put_partner_record(
        &self,
        signed: crate::federation::SignedPartnerRecord,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::operational;
        let now = chrono::Utc::now();
        operational::check_skew_and_payment(
            signed.partner_record.asserted_at,
            now,
            &signed.partner_record.signed_envelope,
        )?;
        // v21.0.0 (#502 E9) — steward roster from OUR directory.
        let (__stw_dir, _) = operational::resolve_steward_roster(self).await?;
        operational::check_partner_set_and_quorum(&signed, &__stw_dir)?;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let existing_max = state
                .federation_partner_records
                .values()
                .filter(|p| p.license_id == signed.partner_record.license_id)
                .map(|p| p.revision)
                .max();
            operational::check_partner_revision_monotonic(
                &signed.partner_record.license_id,
                signed.partner_record.revision,
                existing_max,
            )?;
            // v5.2.0 (#194) — keep the M-of-N steward signature set + threshold so
            // list_signed_partner_records_since reconstructs the full wrapper.
            let steward_signatures = signed.steward_signatures;
            let threshold = signed.threshold;
            let mut row = signed.partner_record;
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            let attestation_id = row.attestation_id.clone();
            // v21.1.0 (CIRISPersist#507b) — `PartnerRecord`'s M-of-N steward
            // quorum is EXTERNAL to the row, so the read surface
            // (`list_signed_partner_records_since`) returns the
            // `SignedPartnerRecord` wrapper — hash that shape, not the bare row.
            // Computed before the moves below.
            let wire_index_key =
                crate::federation::wire_index::record_key(&[("attestation_id", &attestation_id)]);
            memory_idempotent_insert(
                &mut state.federation_partner_records,
                attestation_id.clone(),
                row,
                "partner_record",
            )?;
            state
                .federation_partner_record_sigs
                .insert(attestation_id, (steward_signatures, threshold));
            wire_index_key
        };
        self.index_stored_record("PartnerRecord", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn list_organizations_for(
        &self,
        org_id: &str,
    ) -> Result<Vec<crate::federation::Organization>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_organizations
            .values()
            .filter(|o| o.org_id == org_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        Ok(rows)
    }

    async fn list_org_memberships_for(
        &self,
        org_id: &str,
    ) -> Result<Vec<crate::federation::OrgMembership>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_org_memberships
            .values()
            .filter(|m| m.org_id == org_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        Ok(rows)
    }

    async fn list_partner_records_for(
        &self,
        license_id: &str,
    ) -> Result<Vec<crate::federation::PartnerRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_partner_records
            .values()
            .filter(|p| p.license_id == license_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        Ok(rows)
    }

    async fn list_organizations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::Organization>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_organizations
            .values()
            .filter(|o| since.is_none_or(|s| o.asserted_at > s))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.asserted_at
                .cmp(&b.asserted_at)
                .then_with(|| a.attestation_id.cmp(&b.attestation_id))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_org_memberships_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::OrgMembership>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_org_memberships
            .values()
            .filter(|m| since.is_none_or(|s| m.asserted_at > s))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.asserted_at
                .cmp(&b.asserted_at)
                .then_with(|| a.attestation_id.cmp(&b.attestation_id))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_partner_records_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::PartnerRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_partner_records
            .values()
            .filter(|p| since.is_none_or(|s| p.asserted_at > s))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.asserted_at
                .cmp(&b.asserted_at)
                .then_with(|| a.attestation_id.cmp(&b.attestation_id))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_partner_records_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedPartnerRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_partner_records
            .values()
            .filter(|p| since.is_none_or(|s| p.asserted_at > s))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.asserted_at
                .cmp(&b.asserted_at)
                .then_with(|| a.attestation_id.cmp(&b.attestation_id))
        });
        rows.truncate(limit as usize);
        Ok(rows
            .into_iter()
            .map(|partner_record| {
                let (steward_signatures, threshold) = state
                    .federation_partner_record_sigs
                    .get(&partner_record.attestation_id)
                    .cloned()
                    .unwrap_or_default();
                crate::federation::SignedPartnerRecord {
                    partner_record,
                    steward_signatures,
                    threshold,
                }
            })
            .collect())
    }

    // ─── v21.0.0 (CIRISPersist#504 FLOOR) — bulk signed-since reads for the
    //     5 E4 keyless-declaration planes (edge advertise/serve bridge).
    //     Signed-only: a record is included only if its key is present in
    //     the corresponding `*_authority_sigs` side-map — the memory mirror
    //     of the sqlite/pg `authority_key_id IS NOT NULL AND <> ''` filter.
    //     `put_family_local` genesis-bake rows never populate the side-map,
    //     so they are excluded here exactly as they are on the SQL backends.

    async fn list_signed_families_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedFamily>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_families
            .values()
            .filter(|f| since.is_none_or(|s| f.founded_at > s))
            .filter_map(|f| {
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_family_authority_sigs
                    .get(&f.family_key_id)?
                    .clone();
                Some(crate::federation::SignedFamily {
                    family: f.clone(),
                    authority_key_id,
                    scrub_signature_classical,
                    scrub_signature_pqc,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.family
                .founded_at
                .cmp(&b.family.founded_at)
                .then_with(|| a.family.family_key_id.cmp(&b.family.family_key_id))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_communities_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedCommunity>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_communities
            .values()
            .filter(|c| since.is_none_or(|s| c.founded_at > s))
            .filter_map(|c| {
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_community_authority_sigs
                    .get(&c.community_key_id)?
                    .clone();
                Some(crate::federation::SignedCommunity {
                    community: c.clone(),
                    authority_key_id,
                    scrub_signature_classical,
                    scrub_signature_pqc,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.community
                .founded_at
                .cmp(&b.community.founded_at)
                .then_with(|| {
                    a.community
                        .community_key_id
                        .cmp(&b.community.community_key_id)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_location_proofs_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedLocationProof>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_location_proofs
            .values()
            .filter(|p| since.is_none_or(|s| p.asserted_at > s))
            .filter_map(|p| {
                let key = (p.subject_key_id.clone(), p.asserted_at);
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_location_proof_authority_sigs
                    .get(&key)?
                    .clone();
                Some(crate::federation::SignedLocationProof {
                    location_proof: p.clone(),
                    authority_key_id,
                    scrub_signature_classical,
                    scrub_signature_pqc,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.location_proof
                .asserted_at
                .cmp(&b.location_proof.asserted_at)
                .then_with(|| {
                    a.location_proof
                        .subject_key_id
                        .cmp(&b.location_proof.subject_key_id)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_family_membership_revocations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedFamilyMembershipRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_family_membership_revocations
            .values()
            .filter(|r| since.is_none_or(|s| r.removed_at > s))
            .filter_map(|r| {
                let key = (r.family_key_id.clone(), r.removed_identity_key_id.clone());
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_family_membership_revocation_authority_sigs
                    .get(&key)?
                    .clone();
                Some(crate::federation::SignedFamilyMembershipRevocation {
                    family_membership_revocation: r.clone(),
                    authority_key_id,
                    scrub_signature_classical,
                    scrub_signature_pqc,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.family_membership_revocation
                .removed_at
                .cmp(&b.family_membership_revocation.removed_at)
                .then_with(|| {
                    a.family_membership_revocation
                        .family_key_id
                        .cmp(&b.family_membership_revocation.family_key_id)
                })
                .then_with(|| {
                    a.family_membership_revocation
                        .removed_identity_key_id
                        .cmp(&b.family_membership_revocation.removed_identity_key_id)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_community_membership_revocations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedCommunityMembershipRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_community_membership_revocations
            .values()
            .filter(|r| since.is_none_or(|s| r.removed_at > s))
            .filter_map(|r| {
                let key = (
                    r.community_key_id.clone(),
                    r.removed_identity_key_id.clone(),
                );
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_community_membership_revocation_authority_sigs
                    .get(&key)?
                    .clone();
                Some(crate::federation::SignedCommunityMembershipRevocation {
                    community_membership_revocation: r.clone(),
                    authority_key_id,
                    scrub_signature_classical,
                    scrub_signature_pqc,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.community_membership_revocation
                .removed_at
                .cmp(&b.community_membership_revocation.removed_at)
                .then_with(|| {
                    a.community_membership_revocation
                        .community_key_id
                        .cmp(&b.community_membership_revocation.community_key_id)
                })
                .then_with(|| {
                    a.community_membership_revocation
                        .removed_identity_key_id
                        .cmp(&b.community_membership_revocation.removed_identity_key_id)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    // ─── v21.1.0 (CIRISPersist#507c) — bulk signed-since reads for the 5
    //     PRIMARY signed planes.

    async fn list_signed_key_records_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedKeyRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // Every `federation_keys` row is signed — `scrub_signature_classical`
        // is required at admission, so there is no filter to apply here.
        let mut rows: Vec<_> = state
            .federation_keys
            .values()
            .filter(|k| since.is_none_or(|s| k.scrub_timestamp > s))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.scrub_timestamp
                .cmp(&b.scrub_timestamp)
                .then_with(|| a.key_id.cmp(&b.key_id))
        });
        rows.truncate(limit as usize);
        Ok(rows
            .into_iter()
            .map(|record| crate::federation::SignedKeyRecord { record })
            .collect())
    }

    async fn list_signed_identity_occurrences_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedIdentityOccurrence>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // Signed-put rows only (join against the sig side-map); trusted-
        // local rows (no sig entry) are omitted.
        let mut rows: Vec<crate::federation::SignedIdentityOccurrence> = state
            .federation_identity_occurrences
            .iter()
            .filter(|(_, occ)| since.is_none_or(|s| occ.asserted_at > s))
            .filter_map(|(key, occ)| {
                state.federation_identity_occurrence_sigs.get(key).map(
                    |(attesting_key_id, signed_envelope, signature)| {
                        crate::federation::SignedIdentityOccurrence {
                            identity_occurrence: occ.clone(),
                            attesting_key_id: attesting_key_id.clone(),
                            signed_envelope: signed_envelope.clone(),
                            signature: signature.clone(),
                        }
                    },
                )
            })
            .collect();
        rows.sort_by(|a, b| {
            a.identity_occurrence
                .asserted_at
                .cmp(&b.identity_occurrence.asserted_at)
                .then_with(|| {
                    a.identity_occurrence
                        .identity_key_id
                        .cmp(&b.identity_occurrence.identity_key_id)
                })
                .then_with(|| {
                    a.identity_occurrence
                        .occurrence_key_id
                        .cmp(&b.identity_occurrence.occurrence_key_id)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_transport_destinations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedTransportDestination>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // Signed-put rows only; RETIRED rows ARE included — tombstones must
        // gossip, matching `list_signed_transport_destinations_for`.
        let mut rows: Vec<crate::federation::SignedTransportDestination> = state
            .transport_destinations
            .iter()
            .filter(|(_, td)| since.is_none_or(|s| td.asserted_at > s))
            .filter_map(|(key, td)| {
                state.transport_destination_sigs.get(key).map(
                    |(attesting_key_id, signed_envelope, signature)| {
                        crate::federation::SignedTransportDestination {
                            transport_destination: td.clone(),
                            attesting_key_id: attesting_key_id.clone(),
                            signed_envelope: signed_envelope.clone(),
                            signature: signature.clone(),
                        }
                    },
                )
            })
            .collect();
        rows.sort_by(|a, b| {
            a.transport_destination
                .asserted_at
                .cmp(&b.transport_destination.asserted_at)
                .then_with(|| {
                    a.transport_destination
                        .occurrence_key_id
                        .cmp(&b.transport_destination.occurrence_key_id)
                })
                .then_with(|| {
                    a.transport_destination
                        .transport_kind
                        .cmp(&b.transport_destination.transport_kind)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_attestations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // E5 invariant: federation-tier rows only — a local-tier row must
        // never reach the advertise/serve wire surface.
        //
        // v21.2.0 (#507 × #509) — the cursor is the VISIBILITY timestamp
        // `COALESCE(promoted_at, asserted_at)`: a consent-promoted row
        // (#509) becomes wire-visible at `promoted_at`, which can be long
        // after `asserted_at` — cursoring on `asserted_at` alone would make
        // late promotions invisible to pure-delta consumers forever.
        let visible_at =
            |a: &crate::federation::Attestation| a.promoted_at.unwrap_or(a.asserted_at);
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                since.is_none_or(|s| visible_at(a) > s)
                    && a.tier == crate::federation::types::attestation_tier::FEDERATION
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            visible_at(a)
                .cmp(&visible_at(b))
                .then_with(|| a.attestation_id.cmp(&b.attestation_id))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_identity_occurrence_revocations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<crate::federation::SignedIdentityOccurrenceRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        // Signed-put rows only — same contract as
        // `list_signed_identity_occurrence_revocations_for`.
        let mut rows: Vec<crate::federation::SignedIdentityOccurrenceRevocation> = state
            .federation_identity_occurrence_revocations
            .iter()
            .filter(|(_, rev)| since.is_none_or(|s| rev.revoked_at > s))
            .filter_map(|(key, rev)| {
                state
                    .federation_identity_occurrence_revocation_sigs
                    .get(key)
                    .map(|(attesting_key_id, signed_envelope, signature)| {
                        crate::federation::SignedIdentityOccurrenceRevocation {
                            identity_occurrence_revocation: rev.clone(),
                            attesting_key_id: attesting_key_id.clone(),
                            signed_envelope: signed_envelope.clone(),
                            signature: signature.clone(),
                        }
                    })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.identity_occurrence_revocation
                .revoked_at
                .cmp(&b.identity_occurrence_revocation.revoked_at)
                .then_with(|| {
                    a.identity_occurrence_revocation
                        .identity_key_id
                        .cmp(&b.identity_occurrence_revocation.identity_key_id)
                })
                .then_with(|| {
                    a.identity_occurrence_revocation
                        .occurrence_key_id
                        .cmp(&b.identity_occurrence_revocation.occurrence_key_id)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    // ─── v21.1.0 (CIRISPersist#507b) — the shared signed-wire content-hash
    //     index (V111 mirror: `signed_wire_index` HashMap).

    async fn lookup_signed_record_by_content_hash(
        &self,
        kind: &str,
        content_hash: &str,
    ) -> Result<Option<Vec<u8>>, crate::federation::Error> {
        let record_key = {
            let state = self.state.lock().expect("memory backend lock");
            state
                .signed_wire_index
                .get(&(kind.to_owned(), content_hash.to_owned()))
                .cloned()
        };
        let Some(record_key) = record_key else {
            return Ok(None);
        };
        let bytes =
            crate::federation::wire_index::reload_record_bytes(self, kind, &record_key).await?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let recomputed = crate::federation::wire_index::content_hash_of_bytes(&bytes);
        if recomputed != content_hash {
            tracing::warn!(
                kind,
                content_hash,
                recomputed = %recomputed,
                "signed_wire_index content-hash mismatch; self-healing (returning None)"
            );
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    async fn rebuild_signed_wire_index(&self) -> Result<u64, crate::federation::Error> {
        let triples = crate::federation::wire_index::all_kind_hash_keys(self).await?;
        let count = triples.len() as u64;
        let mut state = self.state.lock().expect("memory backend lock");
        for (kind, hash, record_key) in triples {
            state
                .signed_wire_index
                .insert((kind.to_owned(), hash), record_key);
        }
        Ok(count)
    }

    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        {
            let mut state = self.state.lock().expect("memory backend lock");
            let row = state.federation_keys.get_mut(key_id).ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!(
                    "federation_keys row {key_id} does not exist"
                ))
            })?;
            if row.is_pqc_complete() {
                return Err(crate::federation::Error::Conflict(format!(
                    "federation_keys row {key_id} is already PQC-complete"
                )));
            }
            row.pubkey_ml_dsa_65_base64 = Some(pubkey_ml_dsa_65_base64.to_owned());
            row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
            row.pqc_completed_at = Some(chrono::Utc::now());
            // Recompute persist_row_hash since row content changed.
            let mut for_hash = row.clone();
            for_hash.persist_row_hash = String::new();
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
            // v24.1.0 (CIRISPersist#547) — four serialized columns just moved, so
            // the wire content hash moved with them.
            // v31.0.0 (CIRISPersist#640/#646) — through the shared stored-row
            // helper, after the guard is released.
        }
        self.index_stored_key_row(key_id).await?;
        Ok(())
    }

    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let row = state
            .federation_attestations
            .iter_mut()
            .find(|a| a.attestation_id == attestation_id)
            .ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!(
                    "federation_attestations row {attestation_id} does not exist"
                ))
            })?;
        if row.is_pqc_complete() {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_attestations row {attestation_id} is already PQC-complete"
            )));
        }
        row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
        row.pqc_completed_at = Some(chrono::Utc::now());
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
        Ok(())
    }

    async fn get_attestation(
        &self,
        attestation_id: &str,
    ) -> Result<Option<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .federation_attestations
            .iter()
            .find(|a| a.attestation_id == attestation_id)
            .cloned())
    }

    async fn promote_attestation(
        &self,
        attestation_id: &str,
        cohort_scope: &str,
        scrub_signature_classical: &str,
        scrub_signature_pqc: Option<&str>,
        original_content_hash_hex: &str,
        scrub_key_id: &str,
        scrub_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::federation::Error> {
        use crate::federation::types::attestation_tier;
        // v26.0.0 (CIRISPersist#589 / AV-83) — THE PROMOTION ADMISSION GATE.
        // See `src/store/sqlite.rs` promote_attestation for the rationale.
        // It MUST run before `self.state.lock()`: every gate in the stack
        // reads the directory through that same lock, so gating inside the
        // critical section would deadlock this backend. Running it first is
        // also verify-before-mutation (AV-9) — a refused promotion never
        // touches the row.
        {
            let current = self.get_attestation(attestation_id).await?.ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!(
                    "federation_attestations row {attestation_id} does not exist"
                ))
            })?;
            if current.tier != attestation_tier::FEDERATION {
                let mut as_promoted = current;
                as_promoted.tier = attestation_tier::FEDERATION.to_string();
                as_promoted.cohort_scope = cohort_scope.to_owned();
                crate::federation::admission::check_promotion_admission(
                    self,
                    &as_promoted,
                    self.self_key_id().as_deref(),
                )
                .await?;
            }
        }
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let row = state
                .federation_attestations
                .iter_mut()
                .find(|a| a.attestation_id == attestation_id)
                .ok_or_else(|| {
                    crate::federation::Error::InvalidArgument(format!(
                        "federation_attestations row {attestation_id} does not exist"
                    ))
                })?;
            if row.tier == attestation_tier::FEDERATION {
                return Ok(false);
            }
            let now = scrub_timestamp;
            row.cohort_scope = cohort_scope.to_owned();
            row.original_content_hash = original_content_hash_hex.to_owned();
            row.scrub_signature_classical = scrub_signature_classical.to_owned();
            row.scrub_signature_pqc = scrub_signature_pqc.map(|s| s.to_owned());
            row.scrub_key_id = scrub_key_id.to_owned();
            row.scrub_timestamp = now;
            row.pqc_completed_at = scrub_signature_pqc.map(|_| now);
            row.tier = attestation_tier::FEDERATION.to_string();
            row.promoted_at = Some(now);
            // v24.0.0 (CIRISPersist#557/#556) — PROMOTION CLEARS THE CO-SIGNATURES.
            // A local-tier row defers its signature, so any `additional_scrubs` it
            // carried were STORED WITHOUT EVER BEING VERIFIED. Promotion re-signs
            // the row with this node's key and moves it into the federation plane,
            // where the ingest verifier DOES check every scrub — so carrying the
            // unverified set across would either launder it into the signed plane or
            // (once corrupt) make the promoted row unverifiable at every peer with
            // no error at the promote site. That is the #541 shape: the preserve set
            // must equal the verified set. Co-signatures are earned at the ceremony
            // that mints a federation-tier row, never inherited by a promotion.
            row.additional_scrubs.clear();
            let mut for_hash = row.clone();
            for_hash.persist_row_hash = String::new();
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
            // v21.1.0 (CIRISPersist#507b) — the promoted row is now federation-
            // tier and therefore wire-servable; index it under its final
            // post-promotion shape (matches `list_attestations_since`).
            crate::federation::wire_index::record_key(&[("attestation_id", &row.attestation_id)])
        };
        self.index_stored_record("Attestation", &wire_index_key)
            .await?;
        Ok(true)
    }

    async fn promote_attestation_transformed(
        &self,
        attestation_id: &str,
        cohort_scope: &str,
        envelope_json: &serde_json::Value,
        scrub_signature_classical: &str,
        scrub_signature_pqc: Option<&str>,
        original_content_hash_hex: &str,
        scrub_key_id: &str,
        scrub_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::federation::Error> {
        use crate::federation::types::attestation_tier;
        // v26.0.0 (CIRISPersist#589 / AV-83) — THE PROMOTION ADMISSION GATE,
        // over the TRANSFORMED envelope. Runs before the state lock for the
        // same deadlock reason as `promote_attestation`.
        {
            let current = self.get_attestation(attestation_id).await?.ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!(
                    "federation_attestations row {attestation_id} does not exist"
                ))
            })?;
            if current.tier != attestation_tier::FEDERATION {
                let mut as_promoted = current;
                as_promoted.attestation_envelope = envelope_json.clone();
                as_promoted.tier = attestation_tier::FEDERATION.to_string();
                as_promoted.cohort_scope = cohort_scope.to_owned();
                crate::federation::admission::check_promotion_admission(
                    self,
                    &as_promoted,
                    self.self_key_id().as_deref(),
                )
                .await?;
            }
        }
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let row = state
                .federation_attestations
                .iter_mut()
                .find(|a| a.attestation_id == attestation_id)
                .ok_or_else(|| {
                    crate::federation::Error::InvalidArgument(format!(
                        "federation_attestations row {attestation_id} does not exist"
                    ))
                })?;
            if row.tier == attestation_tier::FEDERATION {
                return Ok(false);
            }
            let now = scrub_timestamp;
            row.cohort_scope = cohort_scope.to_owned();
            row.attestation_envelope = envelope_json.clone();
            row.original_content_hash = original_content_hash_hex.to_owned();
            row.scrub_signature_classical = scrub_signature_classical.to_owned();
            row.scrub_signature_pqc = scrub_signature_pqc.map(|s| s.to_owned());
            row.scrub_key_id = scrub_key_id.to_owned();
            row.scrub_timestamp = now;
            row.pqc_completed_at = scrub_signature_pqc.map(|_| now);
            row.tier = attestation_tier::FEDERATION.to_string();
            row.promoted_at = Some(now);
            // v24.0.0 (CIRISPersist#557/#556) — PROMOTION CLEARS THE CO-SIGNATURES.
            // A local-tier row defers its signature, so any `additional_scrubs` it
            // carried were STORED WITHOUT EVER BEING VERIFIED. Promotion re-signs
            // the row with this node's key and moves it into the federation plane,
            // where the ingest verifier DOES check every scrub — so carrying the
            // unverified set across would either launder it into the signed plane or
            // (once corrupt) make the promoted row unverifiable at every peer with
            // no error at the promote site. That is the #541 shape: the preserve set
            // must equal the verified set. Co-signatures are earned at the ceremony
            // that mints a federation-tier row, never inherited by a promotion.
            row.additional_scrubs.clear();
            let mut for_hash = row.clone();
            for_hash.persist_row_hash = String::new();
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
            // v21.2.0 (#507 × #510) — the transformed promotion CHANGES the
            // served bytes, so the wire index must carry the NEW content hash —
            // same hook as `promote_attestation`. (Hash computed while the row
            // borrow is live; the map insert happens after it ends.)
            crate::federation::wire_index::record_key(&[("attestation_id", &row.attestation_id)])
        };
        self.index_stored_record("Attestation", &wire_index_key)
            .await?;
        Ok(true)
    }

    async fn attach_revocation_pqc_signature(
        &self,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let row = state
            .federation_revocations
            .iter_mut()
            .find(|r| r.revocation_id == revocation_id)
            .ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!(
                    "federation_revocations row {revocation_id} does not exist"
                ))
            })?;
        if row.is_pqc_complete() {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_revocations row {revocation_id} is already PQC-complete"
            )));
        }
        row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
        row.pqc_completed_at = Some(chrono::Utc::now());
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
        Ok(())
    }

    async fn list_hybrid_pending_keys(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_keys
            .values()
            .filter(|r| r.pqc_completed_at.is_none())
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.valid_from);
        Ok(rows
            .into_iter()
            .take(limit.max(0) as usize)
            .map(|r| crate::federation::HybridPendingRow {
                id: r.key_id,
                envelope: r.registration_envelope,
                classical_sig_b64: r.scrub_signature_classical,
            })
            .collect())
    }

    async fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|r| r.pqc_completed_at.is_none())
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.asserted_at);
        Ok(rows
            .into_iter()
            .take(limit.max(0) as usize)
            .map(|r| crate::federation::HybridPendingRow {
                id: r.attestation_id,
                envelope: r.attestation_envelope,
                classical_sig_b64: r.scrub_signature_classical,
            })
            .collect())
    }

    async fn list_hybrid_pending_revocations(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_revocations
            .iter()
            .filter(|r| r.pqc_completed_at.is_none())
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.revoked_at);
        Ok(rows
            .into_iter()
            .take(limit.max(0) as usize)
            .map(|r| crate::federation::HybridPendingRow {
                id: r.revocation_id,
                envelope: r.revocation_envelope,
                classical_sig_b64: r.scrub_signature_classical,
            })
            .collect())
    }

    // ── Trust grants (v1.3.0, CIRISPersist#46 + #47) ───────────────

    async fn grant_trust(
        &self,
        grant: crate::federation::TrustGrant,
    ) -> Result<(), crate::federation::Error> {
        validate_trust_grant(&grant)?;
        let mut state = self.state.lock().expect("memory backend lock");
        // V020 adds the trust columns to the existing federation_keys
        // table. On the memory backend we mirror that contract by
        // requiring `grant.key` to already exist as a federation_keys
        // row (matches the PG "UPSERT preserves pubkey + envelope"
        // shape — there's nothing to preserve if the row doesn't
        // exist yet).
        if !state.federation_keys.contains_key(&grant.key) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "federation_keys row {} does not exist — call put_public_key first",
                grant.key
            )));
        }
        let row = crate::federation::TrustRow {
            key: grant.key.clone(),
            trust_type: grant.trust_type,
            trust_relationship: grant.trust_relationship,
            trust_domains: grant.trust_domains,
            trusted_by: grant.trusted_by,
            trusted_at: chrono::Utc::now(),
            expires_at: grant.expires_at,
        };
        state.federation_trust.insert(grant.key, row);
        Ok(())
    }

    async fn revoke_trust(
        &self,
        key: &str,
        revoked_by: &str,
    ) -> Result<(), crate::federation::Error> {
        if key.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "key must be non-empty".into(),
            ));
        }
        if revoked_by.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "revoked_by must be non-empty".into(),
            ));
        }
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(row) = state.federation_trust.get_mut(key) {
            // Idempotent: only update if not already expired.
            let now = chrono::Utc::now();
            match row.expires_at {
                Some(t) if t <= now => {} // already expired — no-op
                _ => row.expires_at = Some(now),
            }
        }
        Ok(())
    }

    async fn lookup_trust(
        &self,
        key: &str,
    ) -> Result<Option<crate::federation::TrustRow>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_trust.get(key).cloned())
    }

    async fn list_trusted_keys(
        &self,
        filter: crate::federation::TrustFilter,
    ) -> Result<Vec<crate::federation::TrustRow>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let now = chrono::Utc::now();
        let rows: Vec<crate::federation::TrustRow> = state
            .federation_trust
            .values()
            .filter(|r| {
                if !filter.include_expired {
                    if let Some(t) = r.expires_at {
                        if t <= now {
                            return false;
                        }
                    }
                }
                if let Some(t) = filter.trust_type {
                    if r.trust_type != t {
                        return false;
                    }
                }
                if let Some(rel) = filter.trust_relationship {
                    if r.trust_relationship != rel {
                        return false;
                    }
                }
                if let Some(domain) = &filter.domain {
                    let in_domain = r
                        .trust_domains
                        .as_ref()
                        .map(|d| d.iter().any(|x| x == domain))
                        .unwrap_or(false);
                    if !in_domain {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        Ok(rows)
    }

    // ── Goals (v2.10.0, CIRISPersist#114) ──────────────────────────

    async fn put_goal(
        &self,
        goal: crate::federation::Goal,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // FK enforcement parity with postgres: declared_by_key_id
        // must exist in federation_keys.
        if !state.federation_keys.contains_key(&goal.declared_by_key_id) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "declared_by_key_id {} does not exist in federation_keys",
                goal.declared_by_key_id
            )));
        }
        // Idempotent on goal_id collision with matching content;
        // conflict on differing content (same shape as
        // put_public_key).
        let new_hash = crate::federation::types::compute_persist_row_hash(&goal)?;
        if let Some(existing) = state.federation_goals.get(&goal.goal_id) {
            let existing_hash = crate::federation::types::compute_persist_row_hash(existing)?;
            if existing_hash == new_hash {
                return Ok(()); // exact duplicate — no-op
            }
            return Err(crate::federation::Error::Conflict(format!(
                "goal_id {} already exists with different content",
                goal.goal_id
            )));
        }
        state.federation_goals.insert(goal.goal_id, goal);
        Ok(())
    }

    async fn get_goal(
        &self,
        goal_id: uuid::Uuid,
    ) -> Result<Option<crate::federation::Goal>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_goals.get(&goal_id).cloned())
    }

    async fn list_goals(
        &self,
        filter: crate::federation::GoalsFilter,
    ) -> Result<Vec<crate::federation::Goal>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<crate::federation::Goal> = state
            .federation_goals
            .values()
            .filter(|g| {
                if !filter.include_retired && g.retired_at.is_some() {
                    return false;
                }
                if let Some(key) = &filter.declared_by_key_id {
                    if &g.declared_by_key_id != key {
                        return false;
                    }
                }
                if let Some(dim) = filter.m1_dimension {
                    if g.meta_goal_alignment.dimension != dim {
                        return false;
                    }
                }
                if let Some(kind) = &filter.scope_kind {
                    if g.scope.scope_kind_str() != kind.as_str() {
                        return false;
                    }
                }
                if let Some(cohort) = &filter.cohort_id {
                    if g.scope.cohort_id() != Some(cohort.as_str()) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        // Stable lex order by (declared_at, goal_id) — matches the
        // SQL ORDER BY in the postgres + sqlite impls.
        rows.sort_by(|a, b| {
            a.declared_at
                .cmp(&b.declared_at)
                .then_with(|| a.goal_id.cmp(&b.goal_id))
        });
        Ok(rows)
    }

    async fn retire_goal(
        &self,
        goal_id: uuid::Uuid,
        retired_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let row = state.federation_goals.get_mut(&goal_id).ok_or_else(|| {
            crate::federation::Error::InvalidArgument(format!("goal_id {goal_id} does not exist"))
        })?;
        // Idempotent: only set retired_at when the row is still
        // live. A second call against an already-retired goal is a
        // no-op (matches the `revoke_trust` shape).
        if row.retired_at.is_none() {
            row.retired_at = Some(retired_at);
        }
        Ok(())
    }

    // ── Peer-mutation surface (v3.1.0, CIRISPersist#117) ───────────

    async fn add_peer_record(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        identity_type: &str,
        transport_identity: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        if key_id.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "key_id must be non-empty".into(),
            ));
        }
        if pubkey_ed25519_base64.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "pubkey_ed25519_base64 must be non-empty".into(),
            ));
        }
        if identity_type.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "identity_type must be non-empty".into(),
            ));
        }

        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");

        // Conflict semantics: if a federation_keys row exists with
        // matching pubkey, treat add_peer_record as upsert-of-
        // metadata; if pubkey differs, it's a genuine conflict.
        if let Some(existing_key) = state.federation_keys.get(key_id) {
            if existing_key.pubkey_ed25519_base64 != pubkey_ed25519_base64 {
                return Err(crate::federation::Error::Conflict(format!(
                    "key_id {key_id} already exists with different pubkey"
                )));
            }
            // Identical key — metadata row may or may not exist yet.
        } else {
            // Insert minimal federation_keys row. Tests-only shape,
            // mirroring `add_public_key`: zero-byte placeholders for
            // the scrub envelope (the peer was added by the operator,
            // not via a signed registration envelope from the peer
            // itself; operator's authority is enforced at the UniFFI
            // layer).
            let key = crate::federation::KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: pubkey_ed25519_base64.to_owned(),
                pubkey_ml_dsa_65_base64: None,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: identity_type.to_owned(),
                identity_ref: key_id.to_owned(),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({"peer_added_by_operator": true}),
                original_content_hash: "00".repeat(32),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            };
            // persist_row_hash filled in inline (mirrors put_public_key)
            let mut to_insert = key;
            to_insert.persist_row_hash =
                crate::federation::types::compute_persist_row_hash(&to_insert)?;
            state.federation_keys.insert(key_id.to_owned(), to_insert);
        }

        // Insert the metadata row. Conflict on existing row:
        // - if it's soft-removed (`removed_at` is some), the
        //   add re-uses it (clears removed_at) — operator re-adding
        //   a previously-removed peer.
        // - if it's live and matches content, no-op idempotent.
        // - if it's live and differs (transport_identity), Conflict.
        let mut row = crate::federation::PeerMetadataRow {
            key_id: key_id.to_owned(),
            alias: None,
            trust: crate::federation::TrustClass::Untrusted,
            notes: None,
            policy_blob: None,
            transport_identity: transport_identity.clone(),
            removed_at: None,
            inserted_at: now,
            updated_at: now,
            persist_row_hash: String::new(),
        };
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        if let Some(existing) = state.federation_peer_metadata.get(key_id) {
            if existing.removed_at.is_some() {
                // Soft-removed → re-add. Replace with the new row.
                state
                    .federation_peer_metadata
                    .insert(key_id.to_owned(), row);
                return Ok(());
            }
            // Live row already exists. If transport_identity matches
            // (or both None) it's idempotent; otherwise Conflict.
            if existing.transport_identity == transport_identity {
                return Ok(());
            }
            return Err(crate::federation::Error::Conflict(format!(
                "peer_metadata row for key_id {key_id} already exists with different transport_identity"
            )));
        }
        state
            .federation_peer_metadata
            .insert(key_id.to_owned(), row);
        Ok(())
    }

    async fn remove_peer_record(
        &self,
        key_id: &str,
        hard: bool,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // PeerNotFound when no live metadata row OR (for hard remove)
        // no key row either. Treat "metadata row already removed_at"
        // as PeerNotFound for soft remove (idempotent re-call is fine
        // — second soft remove finds the row already marked).
        let exists_metadata_live = state
            .federation_peer_metadata
            .get(key_id)
            .map(|r| r.removed_at.is_none())
            .unwrap_or(false);
        if !exists_metadata_live {
            return Err(crate::federation::Error::PeerNotFound {
                key_id: key_id.to_owned(),
            });
        }

        if hard {
            // Reject if there are any attestations referencing this
            // key. Match the PG semantics: count rows where the key
            // appears as attesting / attested / scrub_key_id.
            let attestation_count = state
                .federation_attestations
                .iter()
                .filter(|a| {
                    a.attesting_key_id == key_id
                        || a.attested_key_id == key_id
                        || a.scrub_key_id == key_id
                })
                .count();
            if attestation_count > 0 {
                return Err(crate::federation::Error::HardRemoveWithActiveAttestations {
                    key_id: key_id.to_owned(),
                    attestation_count,
                });
            }
            // Cascade: drop federation_keys row + metadata row.
            state.federation_keys.remove(key_id);
            state.federation_peer_metadata.remove(key_id);
        } else {
            // Soft-remove: mark removed_at; bump updated_at;
            // recompute persist_row_hash.
            let now = chrono::Utc::now();
            if let Some(row) = state.federation_peer_metadata.get_mut(key_id) {
                row.removed_at = Some(now);
                row.updated_at = now;
                let mut for_hash = row.clone();
                for_hash.persist_row_hash = String::new();
                row.persist_row_hash =
                    crate::federation::types::compute_persist_row_hash(&for_hash)?;
            }
        }
        Ok(())
    }

    async fn update_peer_alias(
        &self,
        key_id: &str,
        alias: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let row = state
            .federation_peer_metadata
            .get_mut(key_id)
            .filter(|r| r.removed_at.is_none())
            .ok_or_else(|| crate::federation::Error::PeerNotFound {
                key_id: key_id.to_owned(),
            })?;
        row.alias = alias;
        row.updated_at = chrono::Utc::now();
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
        Ok(())
    }

    async fn update_peer_trust(
        &self,
        key_id: &str,
        trust: crate::federation::TrustClass,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let row = state
            .federation_peer_metadata
            .get_mut(key_id)
            .filter(|r| r.removed_at.is_none())
            .ok_or_else(|| crate::federation::Error::PeerNotFound {
                key_id: key_id.to_owned(),
            })?;
        row.trust = trust;
        row.updated_at = chrono::Utc::now();
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
        Ok(())
    }

    async fn update_peer_notes(
        &self,
        key_id: &str,
        notes: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let row = state
            .federation_peer_metadata
            .get_mut(key_id)
            .filter(|r| r.removed_at.is_none())
            .ok_or_else(|| crate::federation::Error::PeerNotFound {
                key_id: key_id.to_owned(),
            })?;
        row.notes = notes;
        row.updated_at = chrono::Utc::now();
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
        Ok(())
    }

    async fn update_peer_policy(
        &self,
        key_id: &str,
        policy: crate::federation::PeerPolicyBlob,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let row = state
            .federation_peer_metadata
            .get_mut(key_id)
            .filter(|r| r.removed_at.is_none())
            .ok_or_else(|| crate::federation::Error::PeerNotFound {
                key_id: key_id.to_owned(),
            })?;
        row.policy_blob = Some(policy);
        row.updated_at = chrono::Utc::now();
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;
        Ok(())
    }

    // v3.4.1 (CIRISPersist#127) — read accessor; returns `None` for
    // non-existent or soft-removed peers.
    async fn peer_metadata_for(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::PeerMetadataRow>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .federation_peer_metadata
            .get(key_id)
            .filter(|r| r.removed_at.is_none())
            .cloned())
    }

    // ─── v10.0.0 — fountain holdings/eviction surface (CIRISPersist#270) ──
    // Delegate to the inherent `Backend` methods of the SAME NAME via
    // fully-qualified syntax (a bare `self.<name>` would re-dispatch to
    // this trait method ⇒ infinite recursion), then map `store::Error`
    // onto `federation::Error::Backend`.

    async fn list_held_fountain_content(
        &self,
        publisher_key_id: &str,
    ) -> Result<Vec<crate::fountain::FountainHeldMeta>, crate::federation::Error> {
        <Self as crate::store::Backend>::list_held_fountain_content(self, publisher_key_id)
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))
    }

    async fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: crate::fountain::FountainTier,
    ) -> Result<u64, crate::federation::Error> {
        <Self as crate::store::Backend>::evict_fountain_content_to_tier(
            self,
            content_id,
            corpus_kind,
            tier,
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(e.to_string()))
    }

    async fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<u64, crate::federation::Error> {
        <Self as crate::store::Backend>::evict_fountain_content_hard_delete(
            self,
            content_id,
            corpus_kind,
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(e.to_string()))
    }
}

// ─── BlackholeRules impl (v3.2.0, CIRISPersist#120) ────────────────
//
// In-memory mirror of the V052 blackhole_rules table. The same
// upsert / remove / hit / prune contract the PG + SQLite backends
// implement, against an in-process HashMap keyed by the 16-byte
// identity_hash. Used by fixture tests + by the in-process Engine
// when no DB backend is wired (test harness).

#[async_trait::async_trait]
impl crate::federation::BlackholeRules for MemoryBackend {
    async fn blackhole_list(
        &self,
    ) -> Result<Vec<crate::federation::BlackholeRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state.blackhole_rules.values().cloned().collect();
        rows.sort_by_key(|a| a.added_at);
        Ok(rows)
    }

    async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let mut state = self.state.lock().expect("memory backend lock");
        let now = chrono::Utc::now();
        let key = identity_hash.to_vec();
        let reason_owned = reason.map(str::to_owned);

        match state.blackhole_rules.get_mut(&key) {
            Some(row) => {
                // Re-upsert: preserve hits + added_at, overwrite
                // operator-intent fields, recompute persist_row_hash.
                row.until = until;
                row.reason = reason_owned;
                row.persist_row_hash = crate::federation::blackhole::compute_blackhole_row_hash(
                    &row.identity_hash,
                    &row.until,
                    &row.reason,
                    &row.added_at,
                )?;
            }
            None => {
                let mut record = crate::federation::BlackholeRecord {
                    identity_hash: key.clone(),
                    until,
                    reason: reason_owned,
                    added_at: now,
                    hits: 0,
                    persist_row_hash: String::new(),
                };
                record.persist_row_hash = crate::federation::blackhole::compute_blackhole_row_hash(
                    &record.identity_hash,
                    &record.until,
                    &record.reason,
                    &record.added_at,
                )?;
                state.blackhole_rules.insert(key, record);
            }
        }
        Ok(())
    }

    async fn blackhole_remove(&self, identity_hash: &[u8]) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let mut state = self.state.lock().expect("memory backend lock");
        state.blackhole_rules.remove(identity_hash);
        Ok(())
    }

    async fn blackhole_record_hit(
        &self,
        identity_hash: &[u8],
    ) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(row) = state.blackhole_rules.get_mut(identity_hash) {
            row.hits = row.hits.saturating_add(1);
        }
        // Silent no-op when absent — race-tolerant.
        Ok(())
    }

    async fn blackhole_prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let before = state.blackhole_rules.len();
        state.blackhole_rules.retain(|_, row| match row.until {
            Some(until) => until >= now,
            None => true, // permanent
        });
        let after = state.blackhole_rules.len();
        Ok((before - after) as u64)
    }
}

/// Shared validation for `TrustGrant`. Same rules as the PG CHECK
/// constraints (`federation_keys_no_self_trust` +
/// `federation_keys_registry_requires_domains`) — surfaced as typed
/// `Error::InvalidArgument` instead of an opaque backend SQL error.
/// Used by every FederationDirectory impl so SQLite (which can't
/// add CHECK via ALTER TABLE) gets the same enforcement.
pub(crate) fn validate_trust_grant(
    grant: &crate::federation::TrustGrant,
) -> Result<(), crate::federation::Error> {
    if grant.key.is_empty() {
        return Err(crate::federation::Error::InvalidArgument(
            "grant.key must be non-empty".into(),
        ));
    }
    if grant.trusted_by.is_empty() {
        return Err(crate::federation::Error::InvalidArgument(
            "grant.trusted_by must be non-empty".into(),
        ));
    }
    if grant.trusted_by == grant.key {
        return Err(crate::federation::Error::InvalidArgument(format!(
            "grant.trusted_by must differ from grant.key (no self-trust); got {}",
            grant.key
        )));
    }
    match grant.trust_relationship {
        crate::federation::TrustRelationship::Registry => {
            let n = grant.trust_domains.as_ref().map(|d| d.len()).unwrap_or(0);
            if n == 0 {
                return Err(crate::federation::Error::InvalidArgument(
                    "Registry-relationship grants require a non-empty trust_domains list".into(),
                ));
            }
        }
        crate::federation::TrustRelationship::Direct => {
            // Direct grants: trust_domains MUST be None per NodeCore's
            // shape contract. The PG schema doesn't reject Some(vec)
            // on Direct rows directly, but the resolver ignores
            // domains there — surface as InvalidArgument at the API
            // boundary so callers get a clean error instead of silent
            // misuse of the field.
            if grant.trust_domains.is_some() {
                return Err(crate::federation::Error::InvalidArgument(
                    "Direct-relationship grants must have trust_domains=None".into(),
                ));
            }
        }
    }
    Ok(())
}

// ─── OutboundQueue impl (v0.4.0, CIRISPersist#16) ──────────────────
//
// In-process map mirroring the postgres edge_outbound_queue table.
// State-machine invariants enforced by the impl (matches postgres
// CHECK constraints + transaction semantics). Single-mutex; fine
// for tests.

impl crate::outbound::OutboundQueue for MemoryBackend {
    async fn enqueue_outbound(
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
        initial_next_attempt_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::outbound::QueueId, crate::outbound::Error> {
        // Local invariant gate (matches CHECK constraints; cleaner
        // error than waiting for SQL roundtrip).
        if max_attempts <= 0 {
            return Err(crate::outbound::Error::InvalidArgument(
                "max_attempts must be > 0".into(),
            ));
        }
        if ttl_seconds <= 0 {
            return Err(crate::outbound::Error::InvalidArgument(
                "ttl_seconds must be > 0".into(),
            ));
        }
        if !(1..=8 * 1024 * 1024).contains(&body_size_bytes) {
            return Err(crate::outbound::Error::InvalidArgument(format!(
                "body_size_bytes out of range: {body_size_bytes}"
            )));
        }
        if requires_ack && ack_timeout_seconds.is_none_or_zero() {
            return Err(crate::outbound::Error::InvalidArgument(
                "ack_timeout_seconds required when requires_ack=true".into(),
            ));
        }
        let queue_id = format!(
            "{:x}-{:x}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            uuid_like_counter()
        );
        let row = crate::outbound::OutboundRow {
            queue_id: queue_id.clone(),
            sender_key_id: sender_key_id.into(),
            destination_key_id: destination_key_id.into(),
            message_type: message_type.into(),
            edge_schema_version: edge_schema_version.into(),
            envelope_bytes: envelope_bytes.to_vec(),
            body_sha256: *body_sha256,
            body_size_bytes,
            status: crate::outbound::OutboundStatus::Pending,
            enqueued_at: chrono::Utc::now(),
            next_attempt_after: initial_next_attempt_after,
            last_attempt_at: None,
            transport_delivered_at: None,
            delivered_at: None,
            abandoned_at: None,
            abandoned_reason: None,
            attempt_count: 0,
            max_attempts,
            ttl_seconds,
            last_error_class: None,
            last_error_detail: None,
            last_transport: None,
            requires_ack,
            ack_timeout_seconds,
            ack_envelope_bytes: None,
            ack_received_at: None,
            claimed_until: None,
            claimed_by: None,
        };
        let mut state = self.state.lock().expect("memory backend lock");
        state.outbound_queue.insert(queue_id.clone(), row);
        Ok(queue_id)
    }

    async fn claim_pending_outbound(
        &self,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> Result<Vec<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let now = chrono::Utc::now();
        let claim_until = now + chrono::Duration::seconds(claim_duration_seconds);
        let mut state = self.state.lock().expect("memory backend lock");
        // Pick eligible rows ordered by next_attempt_after ASC.
        let mut candidates: Vec<String> = state
            .outbound_queue
            .iter()
            .filter(|(_, r)| {
                r.status == crate::outbound::OutboundStatus::Pending && r.next_attempt_after <= now
            })
            .map(|(k, _)| k.clone())
            .collect();
        candidates.sort_by_key(|k| {
            state
                .outbound_queue
                .get(k)
                .map(|r| r.next_attempt_after)
                .unwrap_or(now)
        });
        candidates.truncate(batch_size.max(0) as usize);

        let mut claimed = Vec::with_capacity(candidates.len());
        for k in candidates {
            if let Some(r) = state.outbound_queue.get_mut(&k) {
                r.status = crate::outbound::OutboundStatus::Sending;
                r.last_attempt_at = Some(now);
                r.attempt_count += 1;
                r.claimed_until = Some(claim_until);
                r.claimed_by = Some(claimed_by.into());
                claimed.push(r.clone());
            }
        }
        Ok(claimed)
    }

    async fn mark_transport_delivered(
        &self,
        queue_id: &crate::outbound::QueueId,
        transport: &str,
    ) -> Result<(), crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let r = state
            .outbound_queue
            .get_mut(queue_id)
            .ok_or_else(|| crate::outbound::Error::NotFound(queue_id.clone()))?;
        if r.status != crate::outbound::OutboundStatus::Sending {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'sending'"
            )));
        }
        r.transport_delivered_at = Some(now);
        r.last_transport = Some(transport.into());
        r.claimed_until = None;
        r.claimed_by = None;
        if r.requires_ack {
            r.status = crate::outbound::OutboundStatus::AwaitingAck;
        } else {
            r.status = crate::outbound::OutboundStatus::Delivered;
            r.delivered_at = Some(now);
        }
        Ok(())
    }

    async fn mark_transport_failed(
        &self,
        queue_id: &crate::outbound::QueueId,
        error_class: &str,
        error_detail: &str,
        transport: &str,
        next_attempt_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::outbound::OutboundFailureOutcome, crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let r = state
            .outbound_queue
            .get_mut(queue_id)
            .ok_or_else(|| crate::outbound::Error::NotFound(queue_id.clone()))?;
        if r.status != crate::outbound::OutboundStatus::Sending {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'sending'"
            )));
        }
        r.last_error_class = Some(error_class.into());
        r.last_error_detail = Some(error_detail.into());
        r.last_transport = Some(transport.into());
        r.claimed_until = None;
        r.claimed_by = None;

        let ttl_expired = (now - r.enqueued_at) > chrono::Duration::seconds(r.ttl_seconds);
        let attempts_exhausted = r.attempt_count >= r.max_attempts;
        if ttl_expired || attempts_exhausted {
            r.status = crate::outbound::OutboundStatus::Abandoned;
            r.abandoned_at = Some(now);
            r.abandoned_reason = Some(if ttl_expired {
                crate::outbound::AbandonedReason::TtlExpired
            } else {
                crate::outbound::AbandonedReason::MaxAttempts
            });
            Ok(crate::outbound::OutboundFailureOutcome::Abandoned)
        } else {
            r.status = crate::outbound::OutboundStatus::Pending;
            r.next_attempt_after = next_attempt_after;
            Ok(crate::outbound::OutboundFailureOutcome::Retrying {
                attempt: r.attempt_count,
            })
        }
    }

    async fn mark_replay_resolved(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(r) = state.outbound_queue.get_mut(queue_id) {
            if !r.status.is_terminal() {
                r.status = crate::outbound::OutboundStatus::Delivered;
                r.delivered_at = Some(now);
                r.claimed_until = None;
                r.claimed_by = None;
            }
        }
        Ok(())
    }

    async fn match_ack_to_outbound(
        &self,
        in_reply_to_sha256: &[u8; 32],
    ) -> Result<Option<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .outbound_queue
            .values()
            .find(|r| {
                r.status == crate::outbound::OutboundStatus::AwaitingAck
                    && r.body_sha256 == *in_reply_to_sha256
            })
            .cloned())
    }

    async fn mark_ack_received(
        &self,
        queue_id: &crate::outbound::QueueId,
        ack_envelope_bytes: &[u8],
    ) -> Result<(), crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let r = state
            .outbound_queue
            .get_mut(queue_id)
            .ok_or_else(|| crate::outbound::Error::NotFound(queue_id.clone()))?;
        if r.status != crate::outbound::OutboundStatus::AwaitingAck {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'awaiting_ack'"
            )));
        }
        r.status = crate::outbound::OutboundStatus::Delivered;
        r.ack_envelope_bytes = Some(ack_envelope_bytes.to_vec());
        r.ack_received_at = Some(now);
        r.delivered_at = Some(now);
        Ok(())
    }

    async fn sweep_ack_timeouts(&self) -> Result<i64, crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let mut count = 0i64;
        let queue_ids: Vec<String> = state
            .outbound_queue
            .iter()
            .filter(|(_, r)| {
                if r.status != crate::outbound::OutboundStatus::AwaitingAck {
                    return false;
                }
                let Some(t) = r.transport_delivered_at else {
                    return false;
                };
                let Some(timeout) = r.ack_timeout_seconds else {
                    return false;
                };
                (now - t) > chrono::Duration::seconds(timeout)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in queue_ids {
            if let Some(r) = state.outbound_queue.get_mut(&k) {
                let ttl_expired = (now - r.enqueued_at) > chrono::Duration::seconds(r.ttl_seconds);
                let attempts_exhausted = r.attempt_count >= r.max_attempts;
                r.last_error_class = Some("ack_timeout".into());
                r.last_error_detail = Some("no ACK before ack_timeout_seconds expired".into());
                if ttl_expired || attempts_exhausted {
                    r.status = crate::outbound::OutboundStatus::Abandoned;
                    r.abandoned_at = Some(now);
                    r.abandoned_reason = Some(if ttl_expired {
                        crate::outbound::AbandonedReason::TtlExpired
                    } else {
                        crate::outbound::AbandonedReason::MaxAttempts
                    });
                } else {
                    r.status = crate::outbound::OutboundStatus::Pending;
                    r.next_attempt_after = now + chrono::Duration::seconds(60);
                }
                count += 1;
            }
        }
        Ok(count)
    }

    async fn sweep_ttl_expired(&self) -> Result<i64, crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let mut count = 0i64;
        for r in state.outbound_queue.values_mut() {
            if r.status.is_terminal() {
                continue;
            }
            if (now - r.enqueued_at) > chrono::Duration::seconds(r.ttl_seconds) {
                r.status = crate::outbound::OutboundStatus::Abandoned;
                r.abandoned_at = Some(now);
                r.abandoned_reason = Some(crate::outbound::AbandonedReason::TtlExpired);
                r.claimed_until = None;
                r.claimed_by = None;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn sweep_expired_claims(&self) -> Result<i64, crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let mut count = 0i64;
        for r in state.outbound_queue.values_mut() {
            if r.status == crate::outbound::OutboundStatus::Sending
                && r.claimed_until.map(|t| t < now).unwrap_or(false)
            {
                r.status = crate::outbound::OutboundStatus::Pending;
                r.claimed_until = None;
                r.claimed_by = None;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn outbound_status(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<Option<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.outbound_queue.get(queue_id).cloned())
    }

    async fn list_outbound(
        &self,
        filter: crate::outbound::OutboundFilter,
        limit: i64,
    ) -> Result<Vec<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .outbound_queue
            .values()
            .filter(|r| {
                filter.status.is_none_or(|s| r.status == s)
                    && filter
                        .destination_key_id
                        .as_ref()
                        .is_none_or(|d| r.destination_key_id == *d)
                    && filter
                        .sender_key_id
                        .as_ref()
                        .is_none_or(|s| r.sender_key_id == *s)
                    && filter
                        .message_type
                        .as_ref()
                        .is_none_or(|m| r.message_type == *m)
                    && filter.enqueued_after.is_none_or(|t| r.enqueued_at >= t)
            })
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.enqueued_at);
        rows.truncate(limit.max(0) as usize);
        Ok(rows)
    }

    async fn cancel_outbound(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(r) = state.outbound_queue.get_mut(queue_id) {
            if !r.status.is_terminal() {
                r.status = crate::outbound::OutboundStatus::Abandoned;
                r.abandoned_at = Some(now);
                r.abandoned_reason = Some(crate::outbound::AbandonedReason::OperatorCancel);
                r.claimed_until = None;
                r.claimed_by = None;
            }
        }
        Ok(())
    }

    async fn replay_abandoned(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let now = chrono::Utc::now();
        let mut state = self.state.lock().expect("memory backend lock");
        let r = state
            .outbound_queue
            .get_mut(queue_id)
            .ok_or_else(|| crate::outbound::Error::NotFound(queue_id.clone()))?;
        if r.status != crate::outbound::OutboundStatus::Abandoned {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'abandoned'"
            )));
        }
        r.status = crate::outbound::OutboundStatus::Pending;
        r.attempt_count = 0;
        r.next_attempt_after = now;
        r.abandoned_at = None;
        r.abandoned_reason = None;
        r.last_error_class = None;
        r.last_error_detail = None;
        Ok(())
    }
}

/// Helper: monotonic counter for memory-backend queue_id generation.
/// Postgres uses gen_random_uuid(); the memory backend just needs
/// uniqueness within the in-process map. Ten-digit hex is plenty.
fn uuid_like_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Append-only idempotent insert keyed by `attestation_id` (the V071
/// operational tables): a re-submit of byte-identical content is a no-op
/// `Ok(())`; a collision with differing content is an
/// [`Error::Conflict`](crate::federation::Error::Conflict). Mirrors the
/// `put_public_key` idempotent contract on the in-memory backend.
fn memory_idempotent_insert<V: PartialEq>(
    map: &mut std::collections::HashMap<String, V>,
    key: String,
    value: V,
    kind: &str,
) -> Result<(), crate::federation::Error> {
    match map.get(&key) {
        Some(existing) if *existing == value => Ok(()),
        Some(_) => Err(crate::federation::Error::Conflict(format!(
            "{kind} attestation_id {key} already exists with differing content"
        ))),
        None => {
            map.insert(key, value);
            Ok(())
        }
    }
}

/// Helper trait for None-or-zero check used by the memory backend's
/// invariant gate.
trait IsNoneOrZero {
    fn is_none_or_zero(&self) -> bool;
}

impl IsNoneOrZero for Option<i64> {
    fn is_none_or_zero(&self) -> bool {
        matches!(self, None | Some(0))
    }
}

// ─── ReadEngine impl (v0.5.0, CIRISPersist#23) ─────────────────────
//
// Memory backend — read primitives are SQL-heavy aggregates that
// don't fit the in-memory shape. Returns NotImplemented for every
// method; tests can compose against the Postgres backend directly,
// and Memory backend remains for the lighter Backend trait surfaces
// (insert / dedup / federation directory).

/// Memory-backend read surface (FSD §8).
///
/// The [`MemoryBackend`] is a non-SQL, sovereign-mode Pi-class store; it
/// holds no `trace_events` / `federation_*` relational tables, so the
/// SQL-heavy CEG read primitives have nothing to read. v4.0 removed
/// `Error::NotImplemented`, so these honestly surface
/// [`Error::Backend`](crate::read::Error::Backend) — "this backend has no
/// relational read substrate" — rather than the retired escape-hatch
/// variant. The Postgres + SQLite backends are the two that implement
/// every primitive for real (MISSION §1.5). Every method accepts the
/// v4.0 `scope: CallerScope` arg for signature parity; it is unused here
/// because there is no row substrate to gate.
impl crate::read::ReadEngine for MemoryBackend {
    async fn list_trace_summaries(
        &self,
        _filter: crate::read::TraceFilter,
        _cursor: Option<crate::read::TraceCursor>,
        _limit: i64,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::TraceListPage, crate::read::Error> {
        Err(memory_read_unsupported("list_trace_summaries"))
    }

    async fn get_trace_summary(
        &self,
        _trace_id: &str,
        _scope: crate::scope::CallerScope,
    ) -> Result<Option<crate::read::TraceSummary>, crate::read::Error> {
        Err(memory_read_unsupported("get_trace_summary"))
    }

    async fn get_trace_detail(
        &self,
        _trace_id: &str,
        _scope: crate::scope::CallerScope,
    ) -> Result<Option<crate::read::TraceDetail>, crate::read::Error> {
        Err(memory_read_unsupported("get_trace_detail"))
    }

    async fn list_tasks(
        &self,
        _filter: crate::read::TaskFilter,
        _cursor: Option<crate::read::TaskCursor>,
        _limit: i64,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::TaskListPage, crate::read::Error> {
        Err(memory_read_unsupported("list_tasks"))
    }

    async fn list_llm_calls(
        &self,
        _filter: crate::read::LlmCallFilter,
        _cursor: Option<crate::read::LlmCallCursor>,
        _limit: i64,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::LlmCallListPage, crate::read::Error> {
        Err(memory_read_unsupported("list_llm_calls"))
    }

    async fn aggregate_llm_costs(
        &self,
        _filter: crate::read::LlmCallFilter,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::LlmCostAggregate, crate::read::Error> {
        Err(memory_read_unsupported("aggregate_llm_costs"))
    }

    async fn get_repository_statistics(
        &self,
        _filter: crate::ceg::RepositoryFilter,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::ceg::RepositoryStatistics, crate::read::Error> {
        Err(memory_read_unsupported("get_repository_statistics"))
    }

    async fn corpus_shape(
        &self,
        _filter: crate::read::CorpusShapeFilter,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::CorpusShape, crate::read::Error> {
        Err(memory_read_unsupported("corpus_shape"))
    }

    async fn aggregate_scrub_stats(
        &self,
        _window: crate::read::TimeWindow,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::ScrubAggregate, crate::read::Error> {
        Err(memory_read_unsupported("aggregate_scrub_stats"))
    }

    async fn list_federation_keys(
        &self,
        _filter: crate::read::FederationKeyFilter,
        _cursor: Option<crate::read::FederationKeyCursor>,
        _limit: i64,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::FederationKeyListPage, crate::read::Error> {
        Err(memory_read_unsupported("list_federation_keys"))
    }

    async fn list_attestations(
        &self,
        _filter: crate::read::AttestationFilter,
        _cursor: Option<crate::read::AttestationCursor>,
        _limit: i64,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::AttestationListPage, crate::read::Error> {
        Err(memory_read_unsupported("list_attestations"))
    }

    async fn list_attestations_for(
        &self,
        _target: &str,
        _cursor: Option<crate::read::AttestationCursor>,
        _limit: i64,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::AttestationListPage, crate::read::Error> {
        Err(memory_read_unsupported("list_attestations_for"))
    }

    async fn list_revocations(
        &self,
        _filter: crate::read::RevocationFilter,
        _cursor: Option<crate::read::RevocationCursor>,
        _limit: i64,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::RevocationListPage, crate::read::Error> {
        Err(memory_read_unsupported("list_revocations"))
    }

    async fn cross_agent_divergence(
        &self,
        _deployment_domain: &str,
        _window: crate::read::TimeWindow,
        _metric: crate::read::DeviationMetric,
        _scope: crate::scope::CallerScope,
    ) -> Result<Vec<crate::read::DivergenceRow>, crate::read::Error> {
        Err(memory_read_unsupported("cross_agent_divergence"))
    }

    async fn temporal_drift(
        &self,
        _agent_id_hash: &str,
        _baseline: crate::read::TimeWindow,
        _comparison: crate::read::TimeWindow,
        _scope: crate::scope::CallerScope,
    ) -> Result<Vec<crate::read::TemporalDriftRow>, crate::read::Error> {
        Err(memory_read_unsupported("temporal_drift"))
    }

    async fn hash_chain_gaps(
        &self,
        _agent_id_hash: &str,
        _window: crate::read::TimeWindow,
        _scope: crate::scope::CallerScope,
    ) -> Result<Vec<crate::read::HashChainGap>, crate::read::Error> {
        Err(memory_read_unsupported("hash_chain_gaps"))
    }

    async fn conscience_override_rates(
        &self,
        _deployment_domain: &str,
        _window: crate::read::TimeWindow,
        _scope: crate::scope::CallerScope,
    ) -> Result<Vec<crate::read::OverrideRateRow>, crate::read::Error> {
        Err(memory_read_unsupported("conscience_override_rates"))
    }

    async fn aggregate_scoring_factors(
        &self,
        _agent_id_hash: &str,
        _window: crate::read::TimeWindow,
        _baseline: Option<crate::read::TimeWindow>,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::ScoringFactorAggregate, crate::read::Error> {
        Err(memory_read_unsupported("aggregate_scoring_factors"))
    }

    async fn aggregate_scoring_factors_batch(
        &self,
        _agent_id_hashes: &[String],
        _window: crate::read::TimeWindow,
        _baseline: Option<crate::read::TimeWindow>,
        _scope: crate::scope::CallerScope,
    ) -> Result<Vec<crate::read::ScoringFactorAggregate>, crate::read::Error> {
        Err(memory_read_unsupported("aggregate_scoring_factors_batch"))
    }

    async fn aggregate_scoring_factors_stream(
        &self,
        _agent_id_hashes: Vec<String>,
        _window: crate::read::TimeWindow,
        _baseline: Option<crate::read::TimeWindow>,
        _scope: crate::scope::CallerScope,
        _callback: impl FnMut(crate::read::ScoringFactorAggregate) -> bool + Send + 'static,
    ) -> Result<crate::read::StreamSummary, crate::read::Error> {
        Err(memory_read_unsupported("aggregate_scoring_factors_stream"))
    }

    async fn count_traces(
        &self,
        _filter: crate::read::TraceFilter,
        _scope: crate::scope::CallerScope,
    ) -> Result<i64, crate::read::Error> {
        Err(memory_read_unsupported("count_traces"))
    }

    async fn count_overrides(
        &self,
        _filter: crate::read::TraceFilter,
        _scope: crate::scope::CallerScope,
    ) -> Result<i64, crate::read::Error> {
        Err(memory_read_unsupported("count_overrides"))
    }

    async fn count_identity_changes(
        &self,
        _filter: crate::read::TraceFilter,
        _scope: crate::scope::CallerScope,
    ) -> Result<i64, crate::read::Error> {
        Err(memory_read_unsupported("count_identity_changes"))
    }

    async fn aggregate_audit_chain(
        &self,
        _filter: crate::read::TraceFilter,
        _scope: crate::scope::CallerScope,
    ) -> Result<crate::read::AuditChainAggregate, crate::read::Error> {
        Err(memory_read_unsupported("aggregate_audit_chain"))
    }
}

/// The memory backend has no relational read substrate; every CEG read
/// primitive surfaces this stable [`Error::Backend`](crate::read::Error::Backend)
/// (v4.0 dropped `NotImplemented`). The `read_backend` kind token crosses
/// the boundary; the per-method context goes to the message.
fn memory_read_unsupported(method: &str) -> crate::read::Error {
    crate::read::Error::Backend(format!(
        "{method}: memory backend has no relational read substrate; use postgres or sqlite for CEG reads"
    ))
}

// ─── DerivedSchema impl (v0.4.3, CIRISPersist#18) ──────────────────
//
// Memory backend stub — sovereign-mode Pi-class deployments without
// lens-core / RATCHET don't need the substrate, so the put paths
// return NotImplemented. The get paths return empty results so
// callers that probe (e.g. lens-core's startup load) get a clean
// "no current bundle" rather than an error.

impl crate::derived::DerivedSchema for MemoryBackend {
    async fn put_detection_event(
        &self,
        _event: crate::derived::DetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "put_detection_event (memory backend; use postgres for federation evidence)",
        ))
    }

    async fn get_detection_events(
        &self,
        _filter: crate::derived::EventFilter,
    ) -> Result<Vec<crate::derived::DetectionEvent>, crate::derived::Error> {
        Ok(Vec::new())
    }

    async fn put_edge_detection_event(
        &self,
        _event: crate::derived::EdgeDetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "put_edge_detection_event (memory backend; use postgres for federation evidence)",
        ))
    }

    // v2.13.0 (CIRISPersist#113) — memory backend has no
    // `edge_detection_events` substrate (sovereign-mode Pi-class
    // deployments without LensCore don't need it). Returns empty so
    // probing callers get a clean "no rows" rather than an error,
    // matching the existing `get_detection_events` shape.
    async fn get_edge_detection_events(
        &self,
        _filter: crate::derived::EdgeEventFilter,
    ) -> Result<Vec<crate::derived::EdgeDetectionEvent>, crate::derived::Error> {
        Ok(Vec::new())
    }

    async fn put_calibration_bundle(
        &self,
        _bundle: crate::derived::CalibrationBundle,
    ) -> Result<(), crate::derived::Error> {
        Err(crate::derived::Error::NotImplemented(
            "put_calibration_bundle (memory backend; use postgres for federation evidence)",
        ))
    }

    async fn get_current_calibration_bundle(
        &self,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        Ok(None)
    }

    async fn get_calibration_bundle_by_version(
        &self,
        _version: i32,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        Ok(None)
    }
}

#[cfg(test)]
mod accord_tests {
    use super::*;

    /// #302 — full accord live-quorum storage flow on the memory backend (M4
    /// nonce / verify-before-mutation / M6 dedup / M2 immutability / H2 halt).
    /// Shares the assertion body with the sqlite + pg parity tests.
    #[tokio::test]
    async fn accord_live_quorum_storage_flow() {
        let backend = MemoryBackend::new();
        crate::federation::accord_quorum::test_fixtures::exercise_accord_storage(&backend, "mem")
            .await;
    }

    /// #443 — the transport route-table (epoch, asserted_at) monotonic-guard
    /// matrix on the memory backend. Shares the assertion body with the
    /// sqlite + pg parity tests.
    #[tokio::test]
    async fn transport_route_guard_matrix_memory() {
        let backend = MemoryBackend::new();
        crate::federation::self_at_login::test_support::run_transport_route_guard_matrix(
            &backend, "mem",
        )
        .await;
    }

    /// #443 — the authenticated route apply + signed tombstone matrix (real
    /// hybrid crypto) on the memory backend. Shares the assertion body with
    /// the sqlite + pg parity tests.
    #[tokio::test]
    async fn signed_transport_route_matrix_memory() {
        let backend = MemoryBackend::new();
        crate::federation::self_at_login::test_support::run_signed_transport_route_matrix(
            &backend, "mem",
        )
        .await;
    }

    /// #598 B10-a — a REPLAYED consent grant whose `asserted_at` column
    /// diverges from its own signed envelope is refused, on the memory backend. Shares
    /// the assertion body with the other two backends: the pre-#598 fold
    /// coverage was sqlite-only and single-writer, which is the "test shape"
    /// gap the defect lived in.
    #[tokio::test]
    async fn consent_replay_refused_memory_598() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_consent_replay_refusal(
            &backend, "mem598a",
        )
        .await;
    }

    /// #644-a — an org row whose own signature does not verify is REFUSED,
    /// on the memory backend.
    #[tokio::test]
    async fn org_bogus_signature_refused_memory_644() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_org_bogus_signature_refused(
            &backend, "mem644a",
        )
        .await;
    }

    /// #644-b — a `withdrawn_at` tombstone (and a `status` / `role` flip)
    /// that the signature does not cover is REFUSED, on the memory backend.
    #[tokio::test]
    async fn unsigned_tombstone_refused_memory_644() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_unsigned_tombstone_refused(
            &backend, "mem644b",
        )
        .await;
    }

    /// #644-c — an inflated `PartnerRecord::revision` is REFUSED and a
    /// legitimate later revision still admits, on the memory backend.
    #[tokio::test]
    async fn revision_inflation_refused_memory_644() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_revision_inflation_refused(
            &backend, "mem644c",
        )
        .await;
    }

    /// #598 B10-b — two directories fed the SAME signed envelopes with the two
    /// `asserted_at` columns swapped fold to the SAME verdict, on the memory backend.
    #[tokio::test]
    async fn consent_divergent_order_agrees_memory_598() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_consent_divergent_order(
            &backend, "mem598b",
        )
        .await;
    }

    /// #598 B10-c — a sub-microsecond consent instant is refused and a true
    /// tie resolves RESTRICTIVE, in both insertion orders, on the memory backend.
    #[tokio::test]
    async fn consent_tie_resolves_restrictive_memory_598() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_consent_tie_restriction_wins(
            &backend, "mem598c"
        )
        .await;
    }
    /// #543 AV-77 — de-admission stops an abuser and is revocable, on memory.
    ///
    /// The memory arm of the `{gate} × {backend}` matrix; the SAME shared
    /// exercise body the sqlite (`bootstrap_peer_deadmission_sqlite_543`) and
    /// postgres arms run, which is what makes it a parity proof rather than
    /// three tests that happen to agree today.
    /// v31.0.0 (CIRISPersist#643) — the typed-column binding, memory arm.
    /// Same shared body as the sqlite + postgres arms: a parity proof, not
    /// three tests that happen to agree today.
    #[tokio::test]
    async fn row_column_binding_memory_643() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_row_column_binding(
            &backend, "memory",
        )
        .await;
    }

    #[tokio::test]
    async fn bootstrap_peer_deadmission_memory_543() {
        let backend = MemoryBackend::new();
        backend.set_self_key_id(Some("mem543d-self".to_string()));
        crate::federation::bootstrap_admission::test_support::exercise_peer_deadmission(
            &backend,
            "mem543d-self",
            "mem543d",
        )
        .await;
    }

    /// v22.0.0 (CIRISPersist#543) — the `scores` ENVELOPE-SCHEMA gate, which
    /// the memory backend did not have: no resolver field, no accessor, no
    /// call site. It was latent rather than live only because the default
    /// [`crate::federation::NoOpSchemaResolver`] answers `None` — a host that
    /// installed a REAL resolver got enforcement on sqlite + postgres and
    /// silence here.
    ///
    /// Written as a DIFFERENTIAL rather than two independent assertions: the
    /// same stub resolver and the same violating envelope go through both
    /// backends and the two `error_kind`s must be equal. That drives sqlite's
    /// answer instead of hard-coding a guess at it, which is what
    /// `assert_parity`'s hard `error_kind` equality now demands of every gate.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn envelope_schema_gate_matches_sqlite_memory_543() {
        use crate::federation::{
            AxisSchema, FederationDirectory as _, SchemaResolver, SchemaResolverError,
            SignedAttestation,
        };
        use crate::store::backend::Backend as _;

        /// Resolver that always yields a schema requiring `evidence_refs`.
        struct AlwaysRequiresEvidence;
        impl SchemaResolver for AlwaysRequiresEvidence {
            fn resolve<'a>(
                &'a self,
                _dimension: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<Option<AxisSchema>, SchemaResolverError>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async {
                    Ok(Some(AxisSchema {
                        sha256: [0u8; 32],
                        document: serde_json::json!({
                            "type": "object",
                            "required": ["evidence_refs"],
                        }),
                    }))
                })
            }
        }

        // A neutral dimension: `detection:*` and friends are reserved-prefix
        // gated to specific identity types, and a row that bounces off THAT
        // gate would prove nothing about this one. `trust:demo:v1` is the
        // dimension the shared AV-77 exercise already drives through every
        // other gate on all three backends.
        const DIM: &str = "trust:demo:v1";
        // `scores_row`'s envelope carries dimension/score/confidence and NO
        // `evidence_refs`, so it violates the schema above.
        let row = |id: &str| {
            crate::federation::bootstrap_admission::test_support::scores_row(
                id, "sch543", "sch543", DIM,
            )
        };

        // (a) DEFAULT resolver is still a no-op — nothing that passes today
        // starts failing. This is the half that protects every other test.
        let plain = MemoryBackend::new();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&plain, "sch543").await;
        plain
            .put_attestation(SignedAttestation {
                attestation: row(&uuid::Uuid::new_v4().to_string()),
            })
            .await
            .expect("the default NoOpSchemaResolver must leave the gate a no-op");

        // (b) THE DIFFERENTIAL — same resolver, same row, both backends.
        let mem = MemoryBackend::new();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&mem, "sch543").await;
        mem.set_schema_resolver(std::sync::Arc::new(AlwaysRequiresEvidence));
        let mem_err = mem
            .put_attestation(SignedAttestation {
                attestation: row(&uuid::Uuid::new_v4().to_string()),
            })
            .await
            .expect_err("memory must refuse an envelope that violates its axis schema");

        let sq = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .expect("open sqlite");
        sq.run_migrations().await.expect("migrations");
        crate::federation::tier_ingest::test_support::register_hybrid_key(&sq, "sch543").await;
        sq.set_schema_resolver(std::sync::Arc::new(AlwaysRequiresEvidence));
        let sq_err = sq
            .put_attestation(SignedAttestation {
                attestation: row(&uuid::Uuid::new_v4().to_string()),
            })
            .await
            .expect_err("sqlite refuses the same row");

        assert_eq!(
            mem_err.kind(),
            sq_err.kind(),
            "the two backends must refuse at the same gate KIND — a gate that refuses \
             correctly but reports differently is still a failing divergence under \
             `assert_parity` (memory {mem_err:?} vs sqlite {sq_err:?})"
        );
        // And the shared kind is the typed schema violation, not a generic backend error.
        assert!(
            matches!(
                &mem_err,
                crate::federation::Error::EnvelopeSchemaViolation { dimension, .. }
                    if dimension == DIM
            ),
            "and it names the violating dimension: {mem_err:?}"
        );
    }

    /// CIRISEdge#428 B6 — delivery_mode closed vocabulary on memory.
    #[tokio::test]
    async fn bootstrap_delivery_mode_vocabulary_memory_428() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_delivery_mode_vocabulary_gate(
            &backend, "mem428",
        )
        .await;
    }

    /// #543 B1 — capacity self-emission gate on memory (both wire shapes).
    #[tokio::test]
    async fn bootstrap_capacity_self_emission_gate_memory_543() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_capacity_self_emission_gate(
            &backend, "mem543",
        )
        .await;
    }

    /// #543 B5 / CIRISConstitution#46 — consent-before-scoring for `capacity:*`
    /// on memory. Same shared exercise body as the sqlite + postgres arms.
    #[tokio::test]
    async fn bootstrap_capacity_consent_gate_memory_46() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_capacity_consent_gate(
            &backend, "mem46",
        )
        .await;
    }

    /// #569 B7 (CC 3.4.5) — the verify-owned verification families are NOT
    /// consent-gated, on memory. Shared exercise body.
    #[tokio::test]
    async fn bootstrap_verify_families_not_consent_gated_memory_569() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_verify_families_are_not_consent_gated(
            &backend, "mem569",
        )
        .await;
    }

    /// #589 B8 / AV-83 — the promotion admission gate + "capacity is never
    /// local", on memory. Shared exercise body with sqlite + postgres.
    #[tokio::test]
    async fn promotion_admission_gate_memory_589() {
        let backend = MemoryBackend::new();
        backend.set_self_key_id(Some("mem589-self".to_string()));
        crate::federation::bootstrap_admission::test_support::exercise_promotion_admission_gate(
            &backend,
            "mem589-self",
            "mem589",
        )
        .await;
    }

    /// #592 B9 / AV-84 — a targeted-cohort placement is a producer
    /// self-declaration, on memory. Shared exercise body with sqlite +
    /// postgres.
    #[tokio::test]
    async fn promotion_cohort_standing_gate_memory_592() {
        let backend = MemoryBackend::new();
        crate::federation::bootstrap_admission::test_support::exercise_promotion_cohort_standing_gate(
            &backend, "mem592",
        )
        .await;
    }

    /// #541 — the signed-row-survives-unsigned-write invariant on memory.
    #[tokio::test]
    async fn signed_row_survives_local_write_memory_541() {
        let backend = MemoryBackend::new();
        crate::federation::self_at_login::test_support::exercise_signed_row_survives_local_write(
            &backend, "mem541",
        )
        .await;
    }

    // ── freshness_floor (CIRISPersist#519 item 2a-iii) witnesses ────

    /// The anti-rollback matrix on the memory backend. Shares the assertion
    /// body with the sqlite + pg parity tests.
    #[tokio::test]
    async fn touch_claim_monotonic_max_only_advances_memory() {
        let backend = MemoryBackend::new();
        crate::federation::freshness::test_support::run_monotonic_max_matrix(&backend, "mem").await;
    }

    /// The future-skew rejection on the memory backend.
    #[tokio::test]
    async fn touch_claim_rejects_future_beyond_skew_memory() {
        let backend = MemoryBackend::new();
        crate::federation::freshness::test_support::run_future_skew_rejection(&backend, "mem")
            .await;
    }

    /// The forged-signature rejection on the memory backend.
    #[tokio::test]
    async fn touch_claim_requires_valid_hybrid_signature_memory() {
        let backend = MemoryBackend::new();
        crate::federation::freshness::test_support::run_forged_signature_rejection(&backend, "mem")
            .await;
    }

    /// The `cohort_scope` admission-gate validation on the memory backend.
    #[tokio::test]
    async fn touch_claim_cohort_scope_validated_memory() {
        let backend = MemoryBackend::new();
        crate::federation::freshness::test_support::run_cohort_scope_validation(&backend, "mem")
            .await;
    }

    /// The byte-exact round-trip on the memory backend.
    #[tokio::test]
    async fn touch_claim_round_trip_byte_exact_memory() {
        let backend = MemoryBackend::new();
        crate::federation::freshness::test_support::run_round_trip(&backend, "mem").await;
    }

    /// `witness_touch` signer-relationship on the memory backend.
    #[tokio::test]
    async fn touch_claim_witness_touch_relationship_memory() {
        let backend = MemoryBackend::new();
        crate::federation::freshness::test_support::run_witness_touch_relationship(&backend, "mem")
            .await;
    }

    #[tokio::test]
    async fn touch_claim_nofm_cosigned_tally_memory() {
        let backend = MemoryBackend::new();
        crate::federation::freshness::test_support::run_nofm_cosigned_tally(&backend, "mem").await;
    }

    /// #446 — the occurrence→route composite-projection matrix on the memory
    /// backend. Shares the assertion body with the sqlite + pg parity tests.
    #[tokio::test]
    async fn binding_projection_matrix_memory() {
        let backend = MemoryBackend::new();
        crate::federation::self_at_login::test_support::run_binding_projection_matrix(
            &backend, "mem",
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::CompleteTrace;
    use crate::schema::{ComponentType, SchemaVersion, TraceLevel};
    use crate::store::decompose::decompose;

    fn fixture_row(attempt_index: u32, event_type: ReasoningEventType) -> TraceEventRow {
        TraceEventRow {
            trace_id: "trace-x".into(),
            thought_id: "th-1".into(),
            task_id: None,
            step_point: None,
            event_type,
            attempt_index,
            ts: "2026-04-30T00:16:00Z".parse().unwrap(),
            agent_name: None,
            agent_id_hash: "deadbeef".into(),
            cognitive_state: None,
            trace_level: TraceLevel::Generic,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "AAAA".into(),
            signing_key_id: "test-key".into(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".into(),
            pii_scrubbed: false,
            // FSD §3.7 envelope columns: tests for the in-memory
            // dedup / idempotency surface use None — pipeline tests
            // populate them.
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
            // v0.3.4 deployment_profile columns. Test fixture stays
            // 2.7.0-shape (no profile) — None across the board.
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
            cohort_scope: "federation".to_string(),
            cohort_target_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        }
    }

    #[tokio::test]
    async fn insert_returns_inserted_count() {
        let backend = MemoryBackend::new();
        let rows = vec![
            fixture_row(0, ReasoningEventType::ThoughtStart),
            fixture_row(0, ReasoningEventType::ConscienceResult),
            fixture_row(1, ReasoningEventType::ConscienceResult),
        ];
        let report = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(report.inserted, 3);
        assert_eq!(report.conflicted, 0);
    }

    /// Mission category §4 "Idempotency": adapter retries must not
    /// double-insert. Re-submitting the same batch produces zero new
    /// rows and `conflicted == batch.len()`.
    #[tokio::test]
    async fn idempotent_on_dedup_key() {
        let backend = MemoryBackend::new();
        let rows = vec![
            fixture_row(0, ReasoningEventType::ThoughtStart),
            fixture_row(0, ReasoningEventType::ActionResult),
        ];
        let r1 = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(r1.inserted, 2);
        let r2 = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(r2.inserted, 0);
        assert_eq!(r2.conflicted, 2);
        // Same total count after second insert.
        assert_eq!(backend.snapshot_events().len(), 2);
    }

    /// THREAT_MODEL.md AV-9 regression: two distinct agents with
    /// the same trace_id/thought_id/event_type/attempt_index/ts
    /// shape no longer collide. Pre-fix this would have silently
    /// dropped one agent's row.
    #[tokio::test]
    async fn dedup_keyed_by_agent_id_hash() {
        let backend = MemoryBackend::new();
        let mut row_a = fixture_row(0, ReasoningEventType::ActionResult);
        let mut row_b = fixture_row(0, ReasoningEventType::ActionResult);
        // Same trace shape; different agent.
        row_a.agent_id_hash = "agent-a".into();
        row_b.agent_id_hash = "agent-b".into();

        let r = backend
            .insert_trace_events_batch(&[row_a, row_b])
            .await
            .unwrap();
        assert_eq!(r.inserted, 2, "distinct agents must not collide");
        assert_eq!(r.conflicted, 0);
        assert_eq!(backend.snapshot_events().len(), 2);
    }

    #[tokio::test]
    async fn intra_batch_duplicates_conflict() {
        // A batch that itself contains two rows with the same dedup
        // tuple is a bug; mirror Postgres's ON CONFLICT DO NOTHING
        // behavior.
        let backend = MemoryBackend::new();
        let rows = vec![
            fixture_row(0, ReasoningEventType::ConscienceResult),
            fixture_row(0, ReasoningEventType::ConscienceResult),
        ];
        let r = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(r.inserted, 1);
        assert_eq!(r.conflicted, 1);
    }

    #[tokio::test]
    async fn lookup_public_key_round_trip() {
        let backend = MemoryBackend::new();
        // Use a fixed deterministic test keypair.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let vkey = signing.verifying_key();

        // Lookup with no entry → None (typed; not panic).
        // Disambiguate: both Backend and FederationDirectory traits
        // expose `lookup_public_key` post-v0.2.0; this test exercises
        // the legacy Backend (VerifyingKey) shape used by the trace
        // verify path.
        assert!(Backend::lookup_public_key(&backend, "missing")
            .await
            .unwrap()
            .is_none());

        backend.add_public_key("key-id-1", vkey);
        let got = Backend::lookup_public_key(&backend, "key-id-1")
            .await
            .unwrap()
            .expect("registered key returns Some");
        assert_eq!(got.to_bytes(), vkey.to_bytes());
    }

    /// v13.0.0 (CIRISPersist#365, CC 3.4.7.2) — consent_role round-trip,
    /// OQ-1 overwrite-on-revoke via set_consent_role, and the
    /// consent_role_of resolver, on the memory backend.
    #[tokio::test]
    async fn consent_role_round_trip_overwrite_and_resolver_memory() {
        use crate::federation::consent::consent_role_of;
        use crate::federation::types::consent_role;
        let backend = MemoryBackend::new();

        // Born with consent_role = peer → round-trips through put/lookup.
        let mut key = fix_key("k-cr", "primitive-cr", "k-cr");
        key.consent_role = Some(consent_role::PEER.into());
        crate::federation::FederationDirectory::put_public_key(
            &backend,
            crate::federation::SignedKeyRecord { record: key },
        )
        .await
        .unwrap();
        let got = crate::federation::FederationDirectory::lookup_public_key(&backend, "k-cr")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.consent_role.as_deref(), Some(consent_role::PEER));
        assert_eq!(
            consent_role_of(&backend, "k-cr").await.unwrap().as_deref(),
            Some(consent_role::PEER)
        );

        // OQ-1 overwrite → authorized_review (flat, non-recursive).
        crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-cr",
            Some(consent_role::AUTHORIZED_REVIEW),
        )
        .await
        .unwrap();
        assert_eq!(
            consent_role_of(&backend, "k-cr").await.unwrap().as_deref(),
            Some(consent_role::AUTHORIZED_REVIEW)
        );

        // Revoke (overwrite to None).
        crate::federation::FederationDirectory::set_consent_role(&backend, "k-cr", None)
            .await
            .unwrap();
        assert_eq!(consent_role_of(&backend, "k-cr").await.unwrap(), None);

        // Unknown key: setter errors, resolver stays total (Ok(None)).
        assert!(crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-missing",
            Some("peer")
        )
        .await
        .is_err());
        assert_eq!(consent_role_of(&backend, "k-missing").await.unwrap(), None);

        // Unrecognized token: rejected at admission (backend-symmetric).
        assert!(crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-cr",
            Some("emperor")
        )
        .await
        .is_err());

        // The literal stored default 'unregistered' normalizes to wire
        // None on set (stored/wire forms cohere).
        crate::federation::FederationDirectory::set_consent_role(
            &backend,
            "k-cr",
            Some(consent_role::UNREGISTERED),
        )
        .await
        .unwrap();
        assert_eq!(consent_role_of(&backend, "k-cr").await.unwrap(), None);

        // consent_role does NOT enter persist_row_hash (OQ-1 exclusion).
        let mut a = fix_key("k-hash", "primitive-cr", "k-hash");
        a.consent_role = None;
        let h0 = crate::federation::types::compute_persist_row_hash(&a).unwrap();
        a.consent_role = Some(consent_role::PARTNERED.into());
        let h1 = crate::federation::types::compute_persist_row_hash(&a).unwrap();
        assert_eq!(h0, h1, "consent_role must not affect persist_row_hash");
    }

    /// Mission category §4 "Backend parity" (placeholder for the
    /// Phase-1.4 conformance suite): a decomposed CompleteTrace lands
    /// on the in-memory backend with the right row counts, dedup
    /// keys preserved, and llm_calls separated.
    #[tokio::test]
    async fn end_to_end_decompose_and_store() {
        let trace = CompleteTrace {
            trace_id: "trace-x-1".into(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789Z".parse().unwrap(),
            trace_level: TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![
                crate::schema::TraceComponent {
                    component_type: ComponentType::Observation,
                    event_type: ReasoningEventType::ThoughtStart,
                    timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m
                    },
                    agent_id_hash: None,
                },
                crate::schema::TraceComponent {
                    component_type: ComponentType::LlmCall,
                    event_type: ReasoningEventType::LlmCall,
                    timestamp: "2026-04-30T00:15:54.012Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m.insert("handler_name".into(), "EthicalPDMA".into());
                        m.insert("service_name".into(), "OpenAICompatibleLLM".into());
                        m.insert("timestamp".into(), "2026-04-30T00:15:54.012Z".into());
                        m.insert("duration_ms".into(), serde_json::json!(900.0));
                        m.insert("status".into(), "ok".into());
                        m
                    },
                    agent_id_hash: None,
                },
                crate::schema::TraceComponent {
                    component_type: ComponentType::Action,
                    event_type: ReasoningEventType::ActionResult,
                    timestamp: "2026-04-30T00:16:12.789Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m.insert("llm_calls".into(), 1.into());
                        m.insert("tokens_total".into(), 8704.into());
                        m.insert("cost_cents".into(), serde_json::json!(0.5));
                        m
                    },
                    agent_id_hash: None,
                },
            ],
            deployment_profile: None,
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: "AAAA".into(),
            signature_key_id: "ciris-agent-key:dead".into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        };

        let d = decompose(&trace).expect("decompose ok");
        let backend = MemoryBackend::new();

        let event_report = backend.insert_trace_events_batch(&d.events).await.unwrap();
        assert_eq!(event_report.inserted, 3);
        let llm_count = backend
            .insert_trace_llm_calls_batch(&d.llm_calls)
            .await
            .unwrap();
        assert_eq!(llm_count, 1);

        // ACTION_RESULT row carries denormalized cost.
        let snap = backend.snapshot_events();
        let action = snap
            .iter()
            .find(|e| e.event_type == ReasoningEventType::ActionResult)
            .unwrap();
        assert_eq!(action.cost_llm_calls, Some(1));
        assert_eq!(action.cost_tokens, Some(8704));
        assert!((action.cost_usd.unwrap() - 0.005).abs() < 1e-9);
    }

    #[tokio::test]
    async fn migrations_no_op_on_memory() {
        let backend = MemoryBackend::new();
        backend.run_migrations().await.unwrap();
    }

    // (v7.0.0: the `phase_2_surfaces_return_not_implemented` test was
    // removed with the vestigial `Backend` Phase-2/3 stubs — those
    // capabilities ship via the per-capability service traits with full
    // pg/sqlite parity; see `store::backend`.)

    // ─── FederationDirectory tests ─────────────────────────────────

    use crate::federation::{
        Attestation, FederationDirectory, KeyRecord, Revocation, SignedAttestation,
        SignedKeyRecord, SignedRevocation,
    };

    fn fix_key(key_id: &str, identity_ref: &str, scrub_key_id: &str) -> KeyRecord {
        // v9.0.0 (CC 5.3.2.4.3.1) — register REAL deterministic hybrid
        // pubkeys so the federation-tier ingest gate verifies attestations
        // signed by this key (see `tier_ingest::test_support`).
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: identity_ref.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// v9.0.0 (CC 5.3.2.4.3.1) — (re-)sign a federation-tier test
    /// attestation's envelope with its `attesting_key_id`'s deterministic
    /// hybrid key so the mandatory federation-tier ingest gate verifies
    /// it. Call AFTER any post-construction mutation of
    /// `attestation_envelope` / `attesting_key_id`. Matching pubkeys are
    /// registered via [`fix_key`].
    ///
    /// v31.0.0 (CIRISPersist#643) — delegates to
    /// [`tier_ingest::test_support::reseal`](crate::federation::tier_ingest::test_support::reseal),
    /// which ALSO re-stamps the typed-column mirror from the row's own five
    /// columns before signing. A mutation to `attestation_type` /
    /// `subject_key_ids` / `attested_key_id` / `cohort_scope` / `weight` is now
    /// exactly as much a re-sign trigger as a mutation to the envelope, and
    /// keeping both in one helper is what stops a fixture from re-signing half
    /// the change.
    fn resign_fix(row: &mut Attestation) {
        crate::federation::tier_ingest::test_support::reseal(row);
    }

    fn fix_attestation(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
    ) -> Attestation {
        let mut row = Attestation {
            attestation_id: id.into(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            // v2.4.0 admission gate (CIRISPersist#102 Ask 3) — `scores`
            // attestations need a versioned mechanism-descriptive
            // dimension. Test rows use a generic identity-binding
            // shape that passes the four-test gate.
            attestation_envelope: serde_json::json!({
                "id": id,
                "dimension": "identity_binding:v1",
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        // v9.0.0 — sign the as-built envelope (CC 5.3.2.4.3.1).
        resign_fix(&mut row);
        row
    }

    /// v21.12.0 (CIRISPersist#530) — the repair page source surfaces ONLY
    /// the stranded rows: `tier = 'federation'` AND a suppressed
    /// (`self`/`family`) `cohort_scope`. Already-visible federation/community
    /// scopes and any local-tier row are excluded; results page in
    /// `attestation_id` ASC with a working keyset cursor. Rows are seeded
    /// straight into state — a stranded row exists precisely because it
    /// bypassed the placement machinery, so the read path must be provable
    /// against an arbitrary stored shape.
    #[tokio::test]
    async fn list_stranded_federation_attestations_filters_suppressed_scopes_530() {
        use crate::federation::types::{attestation_tier, cohort_scope};
        let be = MemoryBackend::new();
        for (id, tier, scope) in [
            ("s-self", attestation_tier::FEDERATION, cohort_scope::SELF),
            (
                "s-family",
                attestation_tier::FEDERATION,
                cohort_scope::FAMILY,
            ),
            (
                "v-fed",
                attestation_tier::FEDERATION,
                cohort_scope::FEDERATION,
            ),
            (
                "v-comm",
                attestation_tier::FEDERATION,
                cohort_scope::COMMUNITY,
            ),
            ("l-self", attestation_tier::LOCAL, cohort_scope::SELF),
        ] {
            let mut a = fix_attestation(id, "k530", "k530", "k530");
            a.tier = tier.to_string();
            a.cohort_scope = scope.to_string();
            resign_fix(&mut a);
            be.state
                .lock()
                .expect("memory backend lock")
                .federation_attestations
                .push(a);
        }

        let ids: Vec<String> = be
            .list_stranded_federation_attestations(None, 100)
            .await
            .expect("page")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            ids,
            vec!["s-family".to_string(), "s-self".to_string()],
            "only suppressed federation-tier rows, ASC by attestation_id"
        );

        // keyset cursor resumes strictly after the given id.
        let after: Vec<String> = be
            .list_stranded_federation_attestations(Some("s-family"), 100)
            .await
            .expect("page 2")
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(after, vec!["s-self".to_string()]);
    }

    // ── v17.4.0 (FSD-005 Appendix C) — scores read surface parity ──

    fn scores_base() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::timestamp_opt(&chrono::Utc, 1_700_000_000, 0).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn mem_put_score(
        be: &MemoryBackend,
        id: &str,
        attester: &str,
        subject: &str,
        dimension: &str,
        score: f64,
        weight: f64,
        secs: i64,
    ) {
        let _ = be
            .put_public_key(SignedKeyRecord {
                record: fix_key(attester, attester, attester),
            })
            .await;
        let mut a = fix_attestation(id, attester, attester, attester);
        a.weight = Some(weight);
        a.asserted_at = scores_base() + chrono::Duration::seconds(secs);
        a.attestation_envelope = serde_json::json!({
            "dimension": dimension, "score": score, "confidence": weight,
        });
        a.subject_key_ids = vec![subject.into()];
        resign_fix(&mut a);
        be.put_attestation(SignedAttestation { attestation: a })
            .await
            .unwrap();
    }

    async fn mem_put_composer(
        be: &MemoryBackend,
        id: &str,
        attester: &str,
        ty: &str,
        references: &str,
        secs: i64,
    ) {
        let _ = be
            .put_public_key(SignedKeyRecord {
                record: fix_key(attester, attester, attester),
            })
            .await;
        let mut a = fix_attestation(id, attester, attester, attester);
        a.attestation_type = ty.into();
        a.asserted_at = scores_base() + chrono::Duration::seconds(secs);
        a.attestation_envelope =
            serde_json::json!({ "references_attestation_id": references, "reason": "t" });
        a.subject_key_ids = vec![];
        resign_fix(&mut a);
        be.put_attestation(SignedAttestation { attestation: a })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn memory_list_attestation_log_owner_scope() {
        // #455 — backend parity for the owner LOG walk: lifecycle-blind (a
        // withdrawn score stays) + composers visible in the full walk;
        // subject seek returns subject-bearing rows only.
        use crate::federation::FederationDirectory;
        let be = MemoryBackend::new();
        mem_put_score(&be, "live", "k1", "subj", "trust:demo:v1", 0.5, 1.0, 10).await;
        mem_put_score(&be, "gone", "k2", "subj", "trust:demo:v1", 0.5, 1.0, 20).await;
        mem_put_composer(&be, "wd", "k2", "withdraws", "gone", 30).await;
        // gated Live read hides the withdrawn "gone".
        let gated: Vec<String> = be
            .list_scores(
                "",
                crate::read::AttestationFilter {
                    subject_key_id: Some("subj".into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(gated, vec!["live"]);
        // subject log: gone + live (lifecycle-blind; subjectless wd excluded).
        let mut sids: Vec<String> = be
            .list_attestation_log(Some("subj"), None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        sids.sort();
        assert_eq!(sids, vec!["gone", "live"]);
        // full log: every federation row incl. the composer.
        let mut fids: Vec<String> = be
            .list_attestation_log(None, None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        fids.sort();
        assert_eq!(fids, vec!["gone", "live", "wd"]);
    }

    #[tokio::test]
    async fn memory_scores_read_resolve_and_mirror() {
        use crate::federation::FederationDirectory;
        let be = MemoryBackend::new();
        mem_put_score(&be, "a", "k1", "subj", "trust:demo:v1", 0.5, 1.0, 10).await;
        mem_put_score(&be, "b", "k2", "subj", "trust:demo:v1", 0.5, 1.0, 20).await;
        mem_put_score(&be, "c", "k3", "subj", "trust:demo:v1", 0.5, 1.0, 30).await;
        let filter = crate::read::AttestationFilter {
            subject_key_id: Some("subj".into()),
            ..Default::default()
        };
        // newest-first
        let ids: Vec<String> = be
            .list_scores("", filter.clone(), None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(ids, vec!["c", "b", "a"]);
        // cursor pagination
        let p1 = be.list_scores("", filter.clone(), None, 2).await.unwrap();
        assert_eq!(p1.items.len(), 2);
        let cur = p1.next_cursor.expect("full page");
        let p2 = be
            .list_scores("", filter.clone(), Some(cur), 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 1);
        assert_eq!(p2.items[0].attestation_id, "a");
        // resolve: 3 contributors, mean 0.5 → Supported
        let v = be
            .resolve_scores("", filter.clone(), "cc-4.4.2-signed-mean".into(), false)
            .await
            .unwrap();
        assert_eq!(v.contributor_count, 3);
        assert_eq!(v.band, crate::read::ConfidenceBand::Supported);
        // withdraw k3 → drops from both list (default Live) and fold
        mem_put_composer(&be, "w", "k3", "withdraws", "c", 40).await;
        let ids: Vec<String> = be
            .list_scores("", filter.clone(), None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(ids, vec!["b", "a"], "withdrawn hidden by default");
        let v = be
            .resolve_scores("", filter, "cc-4.4.2-signed-mean".into(), false)
            .await
            .unwrap();
        assert_eq!(v.contributor_count, 2, "k3 withdrawn → out of fold");
        // the in-memory subject-index mirror was maintained on every write.
        let idx = be.state.lock().unwrap();
        let mut ids = idx.subject_index.get("subj").cloned().unwrap_or_default();
        ids.sort();
        assert_eq!(ids, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    /// v30.8.0 (CIRISPersist#596 item 1) — give `revoker` the `slash` authority
    /// that revoking SOMEONE ELSE'S key now requires.
    ///
    /// These fixtures test revocation MECHANICS (round-trip, region,
    /// anti-rollback, PQC attach), not who may revoke — so they get the
    /// authority they would hold in production rather than being rewritten as
    /// self-revocations, which would quietly narrow what they exercise.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn grant_slash(backend: &MemoryBackend, revoker: &str) {
        backend.set_node_key_id("rev-authority-node");
        // NOT self-registering: these fixtures register their own keys with
        // their own pubkeys, and `register_hybrid_key`'s deterministic ones
        // collide as a content conflict. Call this AFTER the fixture has
        // registered the revoker.
        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            backend,
            "rev-authority-node",
            "rev-authority-root",
            revoker,
            crate::federation::admission::DELEGATION_SCOPE_SLASH,
        )
        .await;
    }

    fn fix_revocation(id: &str, revoked: &str, revoking: &str, scrub_key_id: &str) -> Revocation {
        // v21.0.0 (#502 E1) — real hybrid sig by the revoking key.
        let __rev_env = serde_json::json!({"id": id});
        let (__rev_och, __rev_sc, __rev_sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(revoking, &__rev_env);
        Revocation {
            revocation_id: id.into(),
            revoked_key_id: revoked.into(),
            revoking_key_id: revoking.into(),
            reason: Some("test".into()),
            revoked_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            effective_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            revocation_envelope: __rev_env,
            original_content_hash: __rev_och,
            scrub_signature_classical: __rev_sc,
            scrub_signature_pqc: __rev_sp,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.into(),
            revoked_after: None,
            persist_row_hash: String::new(),
        }
    }

    // ── #236 CC 4.4.3.4.3 / CC 1.13.5 — reject-agency-on-node-key gate ───

    /// Build a `delegates_to` row from `attesting` to `attested` carrying
    /// the given scope set (array wire shape). Re-uses `fix_attestation`
    /// then overrides the type + scope envelope.
    /// v30.8.0 (CIRISConstitution#87) — a delegation carrying the CC 2.4.1.2
    /// **owner-binding marker**: an explicit claim of custody over the target.
    ///
    /// The steward-gate tests need this now. Before the ruling, an UNMARKED
    /// `delegates_to(user → user)` was itself read as a steward binding, so those
    /// tests could assert CC 3.2's refusals against a bare edge. CC 3.2 rc3 ruled
    /// that unmarked edge is a capability CONFERRAL — giving a person a job — and
    /// it is now admitted. Testing the custody rule therefore requires stating
    /// custody, which is what this helper does.
    ///
    /// The refusals those tests assert are unchanged; only the shape that
    /// triggers them is now explicit.
    fn fix_owner_binding_delegates_to(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
        scope: &[&str],
    ) -> Attestation {
        let mut att = fix_attestation(id, attesting, attested, scrub_key_id);
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            "delegation_purpose": crate::federation::types::owner_binding::CC_DELEGATION_PURPOSE,
        });
        resign_fix(&mut att); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        att
    }

    fn fix_node_delegates_to(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
        scope: &[&str],
    ) -> Attestation {
        let mut att = fix_attestation(id, attesting, attested, scrub_key_id);
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        });
        resign_fix(&mut att); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        att
    }

    /// Register `owner` (user) + `node` (node-only) + an `agent` recipient.
    async fn bootstrap_node_agency(backend: &MemoryBackend) {
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        let mut owner = fix_key("owner", "owner", "registry-steward");
        owner.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: owner })
            .await
            .unwrap();
        let mut node = fix_key("node-key", "node", "registry-steward");
        node.identity_type = crate::federation::types::identity_type::NODE.into();
        backend
            .put_public_key(SignedKeyRecord { record: node })
            .await
            .unwrap();
        let mut agent = fix_key("agent-key", "agent", "registry-steward");
        agent.identity_type = crate::federation::types::identity_type::AGENT.into();
        backend
            .put_public_key(SignedKeyRecord { record: agent })
            .await
            .unwrap();
    }

    /// (a) delegates_to → node key with ONLY infra:* scopes → ADMITTED.
    #[tokio::test]
    async fn node_delegation_infra_only_admitted() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        bootstrap_node_agency(&backend).await;
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "d-infra",
                    "owner",
                    "node-key",
                    "owner",
                    &[ds::INFRA_NETWORK_PRESENCE, ds::INFRA_SERVE],
                ),
            })
            .await
            .unwrap();
        let stored = backend.list_attestations_for("node-key").await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].attestation_id, "d-infra");
    }

    /// (b) delegates_to → node key carrying agency:* → REJECTED + not stored.
    /// THE load-bearing CC 1.13.5 guard.
    #[tokio::test]
    async fn node_delegation_agency_rejected_not_stored() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        bootstrap_node_agency(&backend).await;
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "d-agency",
                    "owner",
                    "node-key",
                    "owner",
                    &[ds::INFRA_SERVE, ds::AGENCY_ACT_ON_BEHALF],
                ),
            })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::NodeAgencyForbidden {
                ref attested_key_id,
                ref offending_scopes,
            } => {
                assert_eq!(attested_key_id, "node-key");
                assert_eq!(
                    offending_scopes,
                    &vec![ds::AGENCY_ACT_ON_BEHALF.to_string()]
                );
            }
            other => panic!("expected NodeAgencyForbidden, got {other:?}"),
        }
        assert_eq!(err.kind(), "federation_node_agency_forbidden");
        // Not stored (verify-before-mutation).
        assert!(backend
            .list_attestations_for("node-key")
            .await
            .unwrap()
            .is_empty());
    }

    /// (b') delegates_to → node key carrying a LEGACY unprefixed agency
    /// kind (`act_on_behalf`) → REJECTED.
    #[tokio::test]
    async fn node_delegation_legacy_agency_rejected() {
        use crate::federation::self_at_login::SCOPE_ACT_ON_BEHALF;
        let backend = MemoryBackend::new();
        bootstrap_node_agency(&backend).await;
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "d-legacy",
                    "owner",
                    "node-key",
                    "owner",
                    &[SCOPE_ACT_ON_BEHALF],
                ),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::NodeAgencyForbidden { .. }
        ));
        assert!(backend
            .list_attestations_for("node-key")
            .await
            .unwrap()
            .is_empty());
    }

    /// (c) delegates_to → node key with an EMPTY scope set → REJECTED.
    #[tokio::test]
    async fn node_delegation_empty_scope_rejected() {
        let backend = MemoryBackend::new();
        bootstrap_node_agency(&backend).await;
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to("d-empty", "owner", "node-key", "owner", &[]),
            })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::NodeAgencyForbidden {
                ref offending_scopes,
                ..
            } => assert!(offending_scopes.is_empty()),
            other => panic!("expected NodeAgencyForbidden, got {other:?}"),
        }
    }

    /// (d) delegates_to → NON-node (agent) key carrying agency:* → ADMITTED.
    /// The gate ONLY constrains node recipients — no over-reject.
    #[tokio::test]
    async fn agent_delegation_agency_admitted_not_over_rejected() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        bootstrap_node_agency(&backend).await;
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "d-agent",
                    "owner",
                    "agent-key",
                    "owner",
                    &[ds::AGENCY_ACT_ON_BEHALF, ds::AGENCY_DECIDE],
                ),
            })
            .await
            .unwrap();
        let stored = backend.list_attestations_for("agent-key").await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].attestation_id, "d-agent");
    }

    /// SecReview F1: a DUPLICATE `identity_type` token (`"node,node"` /
    /// `"node, node"`) must NOT bypass the node-agency gate. The gate tests
    /// the identity_type *set*, so a node-only key carrying `agency:*` is
    /// REJECTED + not stored regardless of dup/whitespace tokens — closing
    /// the `parse_set` non-dedup bypass (CC 1.13.5 / CC 4.4.3.4.3).
    #[tokio::test]
    async fn node_delegation_agency_rejected_with_duplicate_identity_type_token() {
        use crate::federation::types::delegation_scope as ds;
        use crate::federation::types::identity_type;
        for (key_id, dup_ity) in [("node-dup", "node,node"), ("node-ws", "node, node")] {
            let backend = MemoryBackend::new();
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key("registry-steward", "registry", "registry-steward"),
                })
                .await
                .unwrap();
            let mut owner = fix_key("owner", "owner", "registry-steward");
            owner.identity_type = identity_type::USER.into();
            backend
                .put_public_key(SignedKeyRecord { record: owner })
                .await
                .unwrap();
            // Node key whose identity_type set is exactly {node} but stored
            // with a duplicate / whitespace token.
            let mut node = fix_key(key_id, "node", "registry-steward");
            node.identity_type = dup_ity.into();
            backend
                .put_public_key(SignedKeyRecord { record: node })
                .await
                .unwrap();
            let err = backend
                .put_attestation(SignedAttestation {
                    attestation: fix_node_delegates_to(
                        "d-dup",
                        "owner",
                        key_id,
                        "owner",
                        &[ds::AGENCY_ACT_ON_BEHALF],
                    ),
                })
                .await
                .unwrap_err();
            assert!(
                matches!(err, crate::federation::Error::NodeAgencyForbidden { .. }),
                "{dup_ity}: a dup/whitespace node token must still hit the gate, got {err:?}"
            );
            assert_eq!(err.kind(), "federation_node_agency_forbidden");
            assert!(backend
                .list_attestations_for(key_id)
                .await
                .unwrap()
                .is_empty());
        }
    }

    /// SecReview F1 (negative control): a genuine `node,agent` HYBRID key is
    /// NOT node-only, so it legitimately carries `agency:*` — the set-based
    /// gate must still ADMIT it (no over-reject from the dedup fix).
    #[tokio::test]
    async fn node_agent_hybrid_carries_agency_admitted() {
        use crate::federation::types::delegation_scope as ds;
        use crate::federation::types::identity_type;
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        let mut owner = fix_key("owner", "owner", "registry-steward");
        owner.identity_type = identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: owner })
            .await
            .unwrap();
        let mut hybrid = fix_key("node-agent", "hybrid", "registry-steward");
        hybrid.identity_type = format!("{},{}", identity_type::NODE, identity_type::AGENT);
        backend
            .put_public_key(SignedKeyRecord { record: hybrid })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "d-hybrid",
                    "owner",
                    "node-agent",
                    "owner",
                    &[ds::AGENCY_ACT_ON_BEHALF],
                ),
            })
            .await
            .expect("a node,agent hybrid legitimately carries agency");
        let stored = backend.list_attestations_for("node-agent").await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].attestation_id, "d-hybrid");
    }

    #[tokio::test]
    async fn put_and_lookup_public_key() {
        let backend = MemoryBackend::new();
        let key = fix_key("persist-steward", "persist", "persist-steward");
        backend
            .put_public_key(SignedKeyRecord {
                record: key.clone(),
            })
            .await
            .unwrap();

        // Disambiguate: both Backend and FederationDirectory traits
        // expose `lookup_public_key`; here we want the federation
        // KeyRecord shape, not the legacy VerifyingKey.
        let got = FederationDirectory::lookup_public_key(&backend, "persist-steward")
            .await
            .unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.key_id, "persist-steward");
        assert_eq!(got.identity_ref, "persist");
        // persist_row_hash is server-computed.
        assert_eq!(got.persist_row_hash.len(), 64);
        assert_ne!(got.persist_row_hash, key.persist_row_hash);
    }

    #[tokio::test]
    async fn lookup_unknown_returns_none() {
        let backend = MemoryBackend::new();
        let got = FederationDirectory::lookup_public_key(&backend, "missing")
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn idempotent_put_same_content() {
        let backend = MemoryBackend::new();
        let key = fix_key("persist-steward", "persist", "persist-steward");
        backend
            .put_public_key(SignedKeyRecord {
                record: key.clone(),
            })
            .await
            .unwrap();
        // Same content — idempotent no-op.
        backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn put_conflict_different_content() {
        let backend = MemoryBackend::new();
        let mut key1 = fix_key("k1", "primitive-a", "k1");
        key1.identity_type = "primitive".into();
        let mut key2 = fix_key("k1", "primitive-b", "k1");
        key2.identity_type = "primitive".into();
        backend
            .put_public_key(SignedKeyRecord { record: key1 })
            .await
            .unwrap();
        let err = backend
            .put_public_key(SignedKeyRecord { record: key2 })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn lookup_keys_for_identity_filters() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-persist-1", "persist", "k-persist-1"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-persist-2", "persist", "k-persist-2"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-other", "lens", "k-other"),
            })
            .await
            .unwrap();
        let persist_keys = backend.lookup_keys_for_identity("persist").await.unwrap();
        assert_eq!(persist_keys.len(), 2);
        let lens_keys = backend.lookup_keys_for_identity("lens").await.unwrap();
        assert_eq!(lens_keys.len(), 1);
        let none = backend.lookup_keys_for_identity("missing").await.unwrap();
        assert!(none.is_empty());
    }

    /// v2.6.0 (CIRISPersist#105) — class-based enumeration via
    /// `list_keys_by_identity_type`. Two `steward` rows + one
    /// `primitive` row; the steward query returns the two in
    /// `key_id` lex order, the primitive query returns the one row,
    /// and an unknown identity_type returns the empty Vec.
    ///
    /// Mirrors the sibling `federation_list_keys_by_identity_type_round_trip`
    /// in `store::sqlite::tests` (uses non-accord identity_types so
    /// the memory + sqlite + postgres impls can run the same scenario
    /// without V048's hardware-attestation surface friction).
    #[tokio::test]
    async fn list_keys_by_identity_type_class_lookup() {
        let backend = MemoryBackend::new();
        // Insert in reverse lex order to confirm ORDER BY key_id sort.
        let mut steward_b = fix_key("steward-bravo", "steward-bravo", "steward-bravo");
        steward_b.identity_type = crate::federation::types::identity_type::STEWARD.into();
        let mut steward_a = fix_key("steward-alpha", "steward-alpha", "steward-alpha");
        steward_a.identity_type = crate::federation::types::identity_type::STEWARD.into();
        let prim = fix_key("prim-1", "prim-1", "prim-1"); // PRIMITIVE by default

        backend
            .put_public_key(SignedKeyRecord { record: steward_b })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord { record: steward_a })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord { record: prim })
            .await
            .unwrap();

        let steward_rows = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::STEWARD)
            .await
            .unwrap();
        assert_eq!(steward_rows.len(), 2);
        assert_eq!(steward_rows[0].key_id, "steward-alpha");
        assert_eq!(steward_rows[1].key_id, "steward-bravo");

        let prim_rows = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::PRIMITIVE)
            .await
            .unwrap();
        assert_eq!(prim_rows.len(), 1);
        assert_eq!(prim_rows[0].key_id, "prim-1");

        let empty = backend
            .list_keys_by_identity_type("unknown_type")
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    /// v2.6.0 (CIRISPersist#108) — confirm `persist_row_hash` is
    /// surfaced on every federation row-read path. Verify will pass
    /// the hex value into `FederationProvenance::persist_row_hash`
    /// (Option<String>) so a downstream consumer can correlate the
    /// attestation back to persist's storage. Two reads of the same
    /// row return the same hash (idempotency) and the hash is
    /// non-empty (the server computed it on the put).
    #[tokio::test]
    async fn persist_row_hash_surfaces_on_federation_reads() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("steward-1", "steward-1", "steward-1"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-target", "primitive-a", "steward-1"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-1", "steward-1", "k-target", "steward-1"),
            })
            .await
            .unwrap();
        grant_slash(&backend, "steward-1").await;
        backend
            .put_revocation(SignedRevocation {
                revocation: fix_revocation("rev-1", "k-target", "steward-1", "steward-1"),
            })
            .await
            .unwrap();

        // Keys.
        let key1 = FederationDirectory::lookup_public_key(&backend, "k-target")
            .await
            .unwrap()
            .expect("row exists");
        assert!(!key1.persist_row_hash.is_empty(), "key row_hash empty");
        let key2 = FederationDirectory::lookup_public_key(&backend, "k-target")
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(
            key1.persist_row_hash, key2.persist_row_hash,
            "key persist_row_hash differs between reads"
        );

        // Attestations.
        let att1 = backend.list_attestations_for("k-target").await.unwrap();
        assert_eq!(att1.len(), 1);
        assert!(
            !att1[0].persist_row_hash.is_empty(),
            "attestation row_hash empty"
        );
        let att2 = backend.list_attestations_for("k-target").await.unwrap();
        assert_eq!(att1[0].persist_row_hash, att2[0].persist_row_hash);

        // Revocations.
        let rev1 = backend.revocations_for("k-target").await.unwrap();
        assert_eq!(rev1.len(), 1);
        assert!(
            !rev1[0].persist_row_hash.is_empty(),
            "revocation row_hash empty"
        );
        let rev2 = backend.revocations_for("k-target").await.unwrap();
        assert_eq!(rev1[0].persist_row_hash, rev2[0].persist_row_hash);
    }

    #[tokio::test]
    async fn put_attestation_requires_both_keys_exist() {
        let backend = MemoryBackend::new();
        // Neither key exists yet — should be rejected. v22.0.0
        // (CIRISPersist#543 / AV-76): the ATTESTER lookup is tier 2, the one
        // unavoidable directory read, so an unregistered attester is refused
        // there with the clearer-typed `InvalidArgument` — ahead of the tier-3
        // hybrid verify, which would only have reported the same key as
        // unresolvable in less specific words. This is the sqlite + postgres
        // answer too (both hoist the same lookup to tier 2 rather than let the
        // FK violation surface at INSERT); before the re-tiering memory alone
        // returned `FederationTierUnverified` here. Either way, no row stored.
        let att = fix_attestation("a-1", "registry-steward", "primitive-a", "registry-steward");
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert!(
            matches!(&err, crate::federation::Error::InvalidArgument(m)
                if m.contains("attesting_key_id") && m.contains("does not exist")),
            "expected the tier-2 attester-lookup refusal, got {err:?}"
        );

        // Add the keys; retry succeeds.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("primitive-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = fix_attestation("a-1", "registry-steward", "primitive-a", "registry-steward");
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    // ─── v22.0.0 (CIRISPersist#543) memory-backend parity witnesses ──
    //
    // Two gates sqlite + postgres both enforce were missing on the memory
    // backend. Memory is the backend every unit test reaches for first, so a
    // gate absent HERE is a gate the whole test suite proves nothing about —
    // the #518/#534/#536/#541 "tested on one backend, used on the other"
    // shape, arriving from the opposite direction.

    /// Fresh, well-formed Android-Strongbox hardware evidence (the shape the
    /// sqlite witnesses use, so the two backends are proven against the SAME
    /// artifact). `captured_at` is a parameter so the stale-nonce arm can
    /// reach back past `max_nonce_age`.
    fn strongbox_evidence(captured_at: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
        serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        vec![0x30u8, 0x82, 0x01, 0x00],
                        vec![0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": captured_at.to_rfc3339(),
        })
    }

    /// v22.0.0 (CIRISPersist#543) — WITNESS for hole 1: an `accord_holder`
    /// claim on the MEMORY backend is gated by the hardware-attestation
    /// policy, identically to sqlite (`sqlite_put_public_key_rejects_accord_
    /// holder_without_evidence` + siblings) and postgres.
    ///
    /// Before the fix `MemoryBackend::put_public_key` ran ZERO of this — the
    /// `hardware_attestation_policy` field did not exist on the backend — so
    /// an evidence-less `accord_holder`, the STRONGEST claim in the identity
    /// grammar (`ConferralMode::HardwareAttested`), was admitted for free.
    /// That is not a cosmetic gap: `check_privileged_identity_type_admission`
    /// deliberately DELEGATES `accord_holder` to this policy (it skips every
    /// non-`AccordCoScrubbed` mode), so with the policy absent nothing at all
    /// stood behind the claim, and a memory-backed node would seat a forged
    /// holder into the very roster the accord quorum is tallied from.
    ///
    /// All four policy outcomes are exercised, plus the two negative controls
    /// (non-holder needs no evidence; a rejected row leaves NO trace).
    #[tokio::test]
    async fn memory_put_public_key_gates_accord_holder_on_hardware_attestation_543() {
        use crate::federation::types::identity_type::ACCORD_HOLDER;
        let backend = MemoryBackend::new();

        // (a) scalar `identity_type = accord_holder`, NO evidence → REJECT.
        let mut k = fix_key("mem-ah-no-ev", "humanity-accord-x", "mem-ah-no-ev");
        k.identity_type = ACCORD_HOLDER.into();
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_accord_holder_requires_attestation_evidence",
            "evidence-less accord_holder must be refused on memory too, got {err:?}"
        );
        // …and verify-before-mutation: the refused row left no trace.
        assert!(
            FederationDirectory::lookup_public_key(&backend, "mem-ah-no-ev")
                .await
                .unwrap()
                .is_none(),
            "a refused accord_holder must not be stored"
        );

        // (b) #441 SET form ("agent,accord_holder") hits the same gate as the
        //     scalar — `claims_role`, not string equality.
        let mut k = fix_key("mem-ah-setform", "humanity-accord-x", "mem-ah-setform");
        k.identity_type = format!("agent,{ACCORD_HOLDER}");
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_accord_holder_requires_attestation_evidence",
            "set-form accord_holder claim must hit the gate, got {err:?}"
        );

        // (c) #441 ROLES-vector form hits it too.
        let mut k = fix_key("mem-ah-roles", "humanity-accord-x", "mem-ah-roles");
        k.capability_roles = vec![ACCORD_HOLDER.to_string()];
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_accord_holder_requires_attestation_evidence",
            "roles-vector accord_holder claim must hit the gate, got {err:?}"
        );

        // (d) the gate is the POLICY, not a presence check: a stale nonce is
        //     refused even though the evidence is structurally perfect.
        let stale = chrono::Utc::now() - chrono::Duration::days(30);
        let mut k = fix_key("mem-ah-stale", "humanity-accord-x", "mem-ah-stale");
        k.identity_type = ACCORD_HOLDER.into();
        k.attestation_evidence = Some(strongbox_evidence(stale));
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_attestation_evidence_stale",
            "a months-old nonce must be refused on memory too, got {err:?}"
        );

        // (e) software-only custody is refused (the one structural floor
        //     Verify draws). Same evidence body as the sqlite twin.
        let mut k = fix_key("mem-ah-sw", "humanity-accord-x", "mem-ah-sw");
        k.identity_type = ACCORD_HOLDER.into();
        k.attestation_evidence = Some(serde_json::json!({
            "platform_attestation": {
                "Software": {
                    "key_derivation": "random",
                    "storage": "memory",
                    "security_warning": "test"
                }
            },
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        }));
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_hardware_type_not_accepted",
            "SoftwareOnly custody must not seat an accord holder, got {err:?}"
        );

        // (f) POSITIVE control — fresh Strongbox evidence ADMITS. The gate
        //     tightens, it does not close the door on a real holder.
        let mut k = fix_key("mem-ah-ok", "humanity-accord-x", "mem-ah-ok");
        k.identity_type = ACCORD_HOLDER.into();
        k.attestation_evidence = Some(strongbox_evidence(chrono::Utc::now()));
        backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .expect("a hardware-attested accord_holder must admit");
        let read = FederationDirectory::lookup_public_key(&backend, "mem-ah-ok")
            .await
            .unwrap()
            .expect("admitted holder is readable");
        assert_eq!(read.identity_type, ACCORD_HOLDER);

        // (g) NEGATIVE control — a non-holder still needs no evidence.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("mem-plain", "plain", "mem-plain"),
            })
            .await
            .expect("a non-accord_holder row must not require hardware evidence");
    }

    /// v22.0.0 (CIRISPersist#543) — WITNESS for hole 1's second half: the
    /// `validate_registration_pubkey` write-path invariant (#275) now runs on
    /// memory too. Before the fix a wrong-curve / wrong-length
    /// `pubkey_ed25519_base64` that sqlite and postgres BOTH refuse was
    /// admitted by memory, so the row a memory-backed test proved "registers
    /// fine" could not be replicated to either SQL backend.
    #[tokio::test]
    async fn memory_put_public_key_validates_registration_pubkey_543() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let backend = MemoryBackend::new();
        // A 65-byte uncompressed P-256 point — the exact wrong-curve shape
        // the #275 saga produced. Not a 32-byte Ed25519 key.
        let mut k = fix_key("mem-badcurve", "badcurve", "mem-badcurve");
        k.pubkey_ed25519_base64 = BASE64.encode([0x04u8; 65]);
        let err = backend
            .put_public_key(SignedKeyRecord { record: k })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(_)),
            "a 65-byte non-Ed25519 pubkey must be refused at admission, got {err:?}"
        );
        assert!(
            FederationDirectory::lookup_public_key(&backend, "mem-badcurve")
                .await
                .unwrap()
                .is_none(),
            "a refused malformed-pubkey row must not be stored"
        );
    }

    /// v22.0.0 (CIRISPersist#543) — WITNESS for hole 2: `put_attestation` on
    /// memory runs the closed-set `check_cohort_scope` VALUE gate, so an
    /// out-of-set `cohort_scope` fails with the SAME typed error sqlite
    /// (`sqlite.rs`) and postgres raise.
    ///
    /// Scope note, stated honestly: memory did not *store* a `global` row
    /// before this fix either — the AV-45 membership gate
    /// (`check_write_cohort_scope_for`) falls through to
    /// `ScopeRefusalReason::InvalidCohortScope` for any out-of-set value, so
    /// the ACCEPT/REJECT sets already matched. What did NOT match is the
    /// typed rejection: memory raised `WriteScopeRefused`
    /// (`federation_write_scope_refused`) where both SQL backends raise
    /// `CohortScopeRejected` (`federation_cohort_scope_rejected`) — and that
    /// kind string is the documented machine-readable contract consumers
    /// pattern-match on. A backend that refuses the right rows under the
    /// wrong error kind still breaks every caller that branches on the kind,
    /// which is why this asserts the kind and not merely `is_err()`.
    #[tokio::test]
    async fn memory_put_attestation_rejects_out_of_set_cohort_scope_543() {
        let backend = MemoryBackend::new();
        for k in ["cs-attester", "cs-attested"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, k),
                })
                .await
                .unwrap();
        }

        // `global` is a §8.1.8 FEED name aggregating {species, biosphere,
        // federation} — never a wire value.
        let mut att = fix_attestation("cs-global", "cs-attester", "cs-attested", "cs-attester");
        att.cohort_scope = "global".to_string();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_cohort_scope_rejected",
            "memory must raise the same typed cohort_scope rejection as sqlite/postgres, got {err:?}"
        );
        assert!(
            backend
                .get_attestation("cs-global")
                .await
                .unwrap()
                .is_none(),
            "a refused cohort_scope row must leave no trace"
        );

        // Empty string — same closed-set refusal, same kind.
        let mut att = fix_attestation("cs-empty", "cs-attester", "cs-attested", "cs-attester");
        att.cohort_scope = String::new();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_cohort_scope_rejected",
            "an empty cohort_scope is out-of-set too, got {err:?}"
        );

        // POSITIVE control — every closed-set value that needs no membership
        // target still admits (the gate validates the VALUE, nothing more).
        for (i, scope) in ["self", "affiliations", "species", "biosphere", "federation"]
            .into_iter()
            .enumerate()
        {
            let mut att = fix_attestation(
                &format!("cs-ok-{i}"),
                "cs-attester",
                "cs-attested",
                "cs-attester",
            );
            att.cohort_scope = scope.to_string();
            crate::federation::tier_ingest::test_support::reseal(&mut att);
            backend
                .put_attestation(SignedAttestation { attestation: att })
                .await
                .unwrap_or_else(|e| panic!("closed-set cohort_scope {scope} must admit: {e:?}"));
        }
    }

    /// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — WITNESS: the per-peer
    /// write quota is charged on the FIRST gate of `put_attestation` on the
    /// memory backend, exactly as on sqlite
    /// (`av76_per_peer_write_quota_is_wired_sqlite`) and postgres
    /// (`av76_per_peer_write_quota_is_wired_postgres`).
    ///
    /// This calls the SAME shared assertion body those two call — the whole
    /// point of `gate_order_test_support` is that the ordering claim lives
    /// once and every backend re-runs it, so a divergence is a test failure
    /// rather than a silent third-backend gap. Memory shipping without the
    /// quota would have been AV-76 existing on two backends out of three:
    /// the #541 recurrence class the shared helper exists to prevent.
    #[tokio::test]
    async fn av76_per_peer_write_quota_is_wired_memory() {
        let backend = MemoryBackend::new();
        crate::federation::replication::admission::gate_order_test_support::
            assert_per_peer_write_quota_is_wired(&backend, "mem").await;
    }

    /// v31.0.0 (CIRISPersist#612) — the `content_class:*` flag plane on the
    /// memory backend. Shares its body with the sqlite and postgres twins.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn content_class_flag_plane_memory() {
        let backend = MemoryBackend::new();
        backend.set_node_key_id("cc-node-mem");
        crate::federation::content_class::parity_test_support::assert_content_class_flag_plane(
            &backend,
            "cc-node-mem",
            "mem",
        )
        .await;
    }

    /// CIRISServer#356 — the operator read surface on the memory backend:
    /// unknown-not-green, the distinguished zeroes, and the read-only overdue
    /// query's zero-write proof. Shares its body with the sqlite and postgres
    /// twins.
    #[tokio::test]
    async fn node_state_surface_memory() {
        let backend = MemoryBackend::new();
        crate::federation::node_state::parity_test_support::assert_node_state_surface(
            &backend, "mem",
        )
        .await;
    }

    /// v25.1.0 (CIRISPersist#583): the quota's BYTE dimension is charged from
    /// the real envelope, on this backend, through the real host API. Shares
    /// the assertion body with the sqlite and postgres twins — a dimension
    /// wired on two backends out of three is the #541 recurrence class.
    #[tokio::test]
    async fn quota_byte_dimension_is_wired_memory() {
        let backend = MemoryBackend::new();
        crate::federation::replication::admission::gate_order_test_support::
            assert_byte_dimension_is_wired(&backend, "mem").await;
    }

    /// v22.0.0 (CIRISPersist#543 finding 4) — WITNESS: the v3.4.0
    /// trust-weighted [`crate::federation::AdmissionGate`] now actually RUNS
    /// on the memory backend.
    ///
    /// `MemoryBackend` had no `admission_gate` field, no accessor and no
    /// call site, so `check_federation` had never executed on this backend
    /// on ANY write path since v3.4.0 — an installed gate was silently a
    /// no-op. Both directions are asserted: a below-threshold peer is
    /// REFUSED (`federation_trust_below_threshold`), and the same write
    /// from an above-threshold peer gets past the gate (it then fails
    /// further down the stack, which is the proof it was not stopped here).
    #[tokio::test]
    async fn admission_gate_is_wired_on_memory_543() {
        struct FixedTrustScoring(std::collections::HashMap<String, f64>);
        #[async_trait::async_trait]
        impl crate::federation::TrustScoring for FixedTrustScoring {
            async fn trust_score(
                &self,
                key_id: &str,
                _recursion_depth: u8,
            ) -> Result<f64, crate::federation::TrustScoringError> {
                match self.0.get(key_id) {
                    Some(s) => Ok(*s),
                    None => Err(crate::federation::TrustScoringError::KeyNotFound(
                        key_id.into(),
                    )),
                }
            }
        }
        let gate_for = |pairs: &[(&str, f64)], threshold: f64| {
            let mut map = std::collections::HashMap::new();
            for (k, v) in pairs {
                map.insert((*k).to_owned(), *v);
            }
            crate::federation::AdmissionGate::new(
                std::sync::Arc::new(FixedTrustScoring(map)),
                threshold,
                0,
            )
        };

        // Default state: NO gate installed — bootstrap-permissive.
        let backend = MemoryBackend::new();
        assert!(
            backend.admission_gate().is_none(),
            "a fresh memory backend must be bootstrap-permissive"
        );

        // Below threshold ⇒ the gate refuses, and it refuses FIRST: the
        // attesting key is not even registered, so any later gate would
        // have produced a different (more informative) error.
        backend.set_admission_gate(Some(gate_for(&[("ag-lo", 0.1)], 0.5)));
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("ag-1", "ag-lo", "ag-lo", "ag-lo"),
            })
            .await
            .expect_err("a below-threshold peer must be refused");
        assert_eq!(
            err.kind(),
            "federation_trust_below_threshold",
            "the trust gate must run on memory and reject first — got {err:?}"
        );

        // Above threshold ⇒ NOT stopped here. The write still fails (the
        // key is unregistered), but on a LATER gate — which is what proves
        // the gate admitted rather than that it is inert.
        backend.set_admission_gate(Some(gate_for(&[("ag-hi", 0.9)], 0.5)));
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("ag-2", "ag-hi", "ag-hi", "ag-hi"),
            })
            .await
            .expect_err("unregistered attester still fails downstream");
        assert_ne!(
            err.kind(),
            "federation_trust_below_threshold",
            "an above-threshold peer must pass the trust gate — got {err:?}"
        );

        // Clearing restores bootstrap-permissive.
        backend.set_admission_gate(None);
        assert!(backend.admission_gate().is_none(), "gate cleared");
    }

    #[tokio::test]
    async fn list_attestations_for_and_by() {
        let backend = MemoryBackend::new();
        // Bootstrap: registry-steward, two primitives, three attestations.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-b", "primitive-b", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation(
                    "att-1",
                    "registry-steward",
                    "k-a",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation(
                    "att-2",
                    "registry-steward",
                    "k-b",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();

        // Two attestations from registry-steward.
        let by = backend
            .list_attestations_by("registry-steward")
            .await
            .unwrap();
        assert_eq!(by.len(), 2);

        // One attestation FOR k-a.
        let for_a = backend.list_attestations_for("k-a").await.unwrap();
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].attestation_id, "att-1");
    }

    /// v8.7.2 (#233 follow-on, CEG RC27 §11.10) — `subject_of_content`
    /// resolves the SIGNED subject set behind a content hash from the
    /// content-establishing `scores` attestation(s) binding it via
    /// `evidence_refs`. Memory-backend parity for the resolution.
    #[tokio::test]
    async fn subject_of_content_resolves_signed_subjects() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("producer", "producer", "registry-steward"),
            })
            .await
            .unwrap();
        let sha = "a".repeat(64);
        let other_sha = "b".repeat(64);

        // Establishing scores attestation binding `sha` with signed
        // subjects = [subj-1, subj-2].
        let mut est = fix_attestation("est-1", "producer", "producer", "registry-steward");
        est.attestation_envelope = serde_json::json!({
            "dimension": "content:established:v1",
            "evidence_refs": [sha],
        });
        resign_fix(&mut est); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        est.subject_key_ids = vec!["subj-1".into(), "subj-2".into()];
        resign_fix(&mut est); // #643 — a typed-column edit is a re-seal trigger
        backend
            .put_attestation(SignedAttestation { attestation: est })
            .await
            .unwrap();

        // Resolves the signed subjects for the bound hash.
        let subjects = crate::federation::admission::subject_of_content(&backend, &sha)
            .await
            .unwrap();
        assert_eq!(subjects.len(), 2);
        assert!(subjects.contains("subj-1") && subjects.contains("subj-2"));

        // A DIFFERENT (unbound) hash → empty (fail-secure).
        let none = crate::federation::admission::subject_of_content(&backend, &other_sha)
            .await
            .unwrap();
        assert!(none.is_empty());

        // A malformed (non-hex) hash → empty.
        let bad = crate::federation::admission::subject_of_content(&backend, "not-a-hash")
            .await
            .unwrap();
        assert!(bad.is_empty());
    }

    #[tokio::test]
    async fn attach_pqc_completes_hybrid_pending_key() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-pending", "primitive-a", "k-pending"),
            })
            .await
            .unwrap();
        // Initially hybrid-pending.
        let row = FederationDirectory::lookup_public_key(&backend, "k-pending")
            .await
            .unwrap()
            .unwrap();
        assert!(row.is_pqc_pending());
        assert!(!row.is_pqc_complete());

        // Attach the PQC components.
        backend
            .attach_key_pqc_signature("k-pending", "test-mldsa-pubkey", "test-mldsa-sig")
            .await
            .unwrap();

        let row = FederationDirectory::lookup_public_key(&backend, "k-pending")
            .await
            .unwrap()
            .unwrap();
        assert!(row.is_pqc_complete());
        assert_eq!(
            row.pubkey_ml_dsa_65_base64.as_deref(),
            Some("test-mldsa-pubkey")
        );
        assert_eq!(row.scrub_signature_pqc.as_deref(), Some("test-mldsa-sig"));
        assert!(row.pqc_completed_at.is_some());
        // Hash recomputed.
        assert_eq!(row.persist_row_hash.len(), 64);
    }

    #[tokio::test]
    async fn attach_pqc_rejects_double_fill() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-double", "primitive-a", "k-double"),
            })
            .await
            .unwrap();
        backend
            .attach_key_pqc_signature("k-double", "mldsa-pk-1", "mldsa-sig-1")
            .await
            .unwrap();
        // Second attach errors with Conflict.
        let err = backend
            .attach_key_pqc_signature("k-double", "mldsa-pk-2", "mldsa-sig-2")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn attach_pqc_rejects_missing_row() {
        let backend = MemoryBackend::new();
        let err = backend
            .attach_key_pqc_signature("ghost", "mldsa-pk", "mldsa-sig")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn attach_pqc_for_attestation_and_revocation() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("steward", "registry", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-target", "primitive-a", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-1", "steward", "k-target", "steward"),
            })
            .await
            .unwrap();
        backend
            .attach_attestation_pqc_signature("att-1", "att-pqc-sig")
            .await
            .unwrap();
        let atts = backend.list_attestations_for("k-target").await.unwrap();
        assert!(atts[0].is_pqc_complete());
        grant_slash(&backend, "steward").await;

        backend
            .put_revocation(SignedRevocation {
                revocation: fix_revocation("rev-1", "k-target", "steward", "steward"),
            })
            .await
            .unwrap();
        backend
            .attach_revocation_pqc_signature("rev-1", "rev-pqc-sig")
            .await
            .unwrap();
        let revs = backend.revocations_for("k-target").await.unwrap();
        assert!(revs[0].is_pqc_complete());
    }

    /// v0.3.2 (CIRISPersist#11) — list_hybrid_pending_* returns rows
    /// where pqc_completed_at IS NULL, oldest first; rows that have
    /// been hybrid-completed via attach_*_pqc_signature are excluded.
    /// This is the substrate `Engine.run_pqc_sweep` walks.
    #[tokio::test]
    async fn list_hybrid_pending_filters_completed_rows() {
        let backend = MemoryBackend::new();
        // Steward + three agent keys.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("steward", "registry", "steward"),
            })
            .await
            .unwrap();
        for id in &["k-a", "k-b", "k-c"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(id, "primitive", "steward"),
                })
                .await
                .unwrap();
        }
        // Two attestations, one revocation.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-x", "steward", "k-a", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("att-y", "steward", "k-b", "steward"),
            })
            .await
            .unwrap();
        backend
            .put_revocation(SignedRevocation {
                revocation: // v30.8.0 (#596 item 1) — SELF-revocation: this test counts rows, and the
                // trust-root scaffolding a third-party conferral needs would
                // pollute the count it measures. Self-revocation needs no
                // authority and changes nothing else here.
                fix_revocation("rev-z", "steward", "steward", "steward"),
            })
            .await
            .unwrap();

        // All hybrid-pending — 4 keys (steward + 3 agents), 2 attestations, 1 revocation.
        let pending_keys = backend.list_hybrid_pending_keys(100).await.unwrap();
        let pending_atts = backend.list_hybrid_pending_attestations(100).await.unwrap();
        let pending_revs = backend.list_hybrid_pending_revocations(100).await.unwrap();
        assert_eq!(pending_keys.len(), 4);
        assert_eq!(pending_atts.len(), 2);
        assert_eq!(pending_revs.len(), 1);

        // Attach PQC to one row in each table. Filter excludes them.
        backend
            .attach_key_pqc_signature("k-a", "mldsa-pk", "mldsa-sig")
            .await
            .unwrap();
        backend
            .attach_attestation_pqc_signature("att-x", "att-pqc-sig")
            .await
            .unwrap();
        backend
            .attach_revocation_pqc_signature("rev-z", "rev-pqc-sig")
            .await
            .unwrap();
        let pending_keys = backend.list_hybrid_pending_keys(100).await.unwrap();
        let pending_atts = backend.list_hybrid_pending_attestations(100).await.unwrap();
        let pending_revs = backend.list_hybrid_pending_revocations(100).await.unwrap();
        assert_eq!(pending_keys.len(), 3);
        assert!(!pending_keys.iter().any(|r| r.id == "k-a"));
        assert_eq!(pending_atts.len(), 1);
        assert_eq!(pending_atts[0].id, "att-y");
        assert_eq!(pending_revs.len(), 0);
    }

    /// v0.3.2 (CIRISPersist#11) — limit caps the batch; envelope +
    /// classical_sig fields are populated correctly so the sweep can
    /// recompute the bound-signature input identical to the per-write
    /// cold-path.
    #[tokio::test]
    async fn list_hybrid_pending_limit_and_payload() {
        let backend = MemoryBackend::new();
        for i in 0..5 {
            let id = format!("k-{i}");
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(&id, "primitive", &id),
                })
                .await
                .unwrap();
        }
        // Limit=2 returns 2 rows.
        let rows = backend.list_hybrid_pending_keys(2).await.unwrap();
        assert_eq!(rows.len(), 2);
        // Each row carries id, envelope, classical_sig — sufficient to
        // recompute the cold-path bound-signature input.
        for row in &rows {
            assert!(row.id.starts_with("k-"));
            assert!(!row.classical_sig_b64.is_empty());
            assert!(row.envelope.is_object());
        }
    }

    /// v0.3.6 (CIRISPersist#15) — Helper: insert a trace_events row
    /// scoped to (agent_id_hash, signing_key_id). Returns the
    /// trace_id used so the caller can pair an LLM call.
    fn dsar_fixture_row(
        agent_id_hash: &str,
        signing_key_id: &str,
        trace_suffix: &str,
    ) -> TraceEventRow {
        TraceEventRow {
            trace_id: format!("trace-{trace_suffix}"),
            thought_id: format!("th-{trace_suffix}"),
            task_id: None,
            step_point: None,
            event_type: ReasoningEventType::ThoughtStart,
            attempt_index: 0,
            ts: "2026-04-30T00:00:00Z".parse().unwrap(),
            agent_name: None,
            agent_id_hash: agent_id_hash.to_owned(),
            cognitive_state: None,
            trace_level: TraceLevel::Generic,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "AAAA".into(),
            signing_key_id: signing_key_id.to_owned(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".into(),
            pii_scrubbed: false,
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
            cohort_scope: "federation".to_string(),
            cohort_target_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        }
    }

    /// v0.3.6 (CIRISPersist#15) — Per-key DSAR scope: deletion is
    /// scoped to (agent_id_hash, signing_key_id). Traces signed under
    /// other keys for the same agent stay alive — the per-key
    /// authorization model means the DSAR can only delete what its
    /// signing key signed.
    #[tokio::test]
    async fn dsar_per_key_scopes_correctly() {
        use crate::store::Backend;
        let backend = MemoryBackend::new();
        // Same agent_id_hash, two different signing keys (key1 + key2).
        // Plus a different agent's row (other) under the same key1.
        backend
            .insert_trace_events_batch(&[
                dsar_fixture_row("agent-A", "key1", "k1-t1"),
                dsar_fixture_row("agent-A", "key1", "k1-t2"),
                dsar_fixture_row("agent-A", "key2", "k2-t1"),
                dsar_fixture_row("agent-B", "key1", "B-t1"),
            ])
            .await
            .unwrap();

        // DSAR for (agent-A, key1) — deletes only the 2 key1 rows.
        let summary = backend
            .delete_traces_for_agent("agent-A", "key1", false)
            .await
            .unwrap();
        assert_eq!(summary.trace_events_deleted, 2);
        assert_eq!(summary.federation_keys_deleted, 0);

        // Surviving rows: agent-A's key2 row + agent-B's key1 row.
        let remaining = backend.snapshot_events();
        assert_eq!(remaining.len(), 2);
        assert!(remaining
            .iter()
            .any(|r| r.agent_id_hash == "agent-A" && r.signing_key_id == "key2"));
        assert!(remaining
            .iter()
            .any(|r| r.agent_id_hash == "agent-B" && r.signing_key_id == "key1"));

        // Idempotent: re-invocation on the now-deleted scope returns 0.
        let summary2 = backend
            .delete_traces_for_agent("agent-A", "key1", false)
            .await
            .unwrap();
        assert_eq!(summary2.trace_events_deleted, 0);
    }

    /// v0.3.6 (CIRISPersist#15) — Per-key cascade through trace_llm_calls.
    /// LLM call rows joined by trace_id only cascade for the targeted
    /// key's traces. Cross-key LLM calls survive.
    #[tokio::test]
    async fn dsar_per_key_cascades_llm_calls() {
        use crate::store::Backend;
        let backend = MemoryBackend::new();
        backend
            .insert_trace_events_batch(&[
                dsar_fixture_row("agent-A", "key1", "k1-t1"),
                dsar_fixture_row("agent-A", "key2", "k2-t1"),
            ])
            .await
            .unwrap();
        // One LLM call per trace.
        for trace_id in ["trace-k1-t1", "trace-k2-t1"] {
            backend
                .insert_trace_llm_calls_batch(&[TraceLlmCallRow {
                    trace_id: trace_id.into(),
                    thought_id: "th".into(),
                    task_id: None,
                    parent_event_id: None,
                    parent_event_type: ReasoningEventType::ThoughtStart,
                    parent_attempt_index: 0,
                    attempt_index: 0,
                    ts: "2026-04-30T00:00:00Z".parse().unwrap(),
                    duration_ms: 0.0,
                    handler_name: "h".into(),
                    service_name: "s".into(),
                    model: None,
                    base_url: None,
                    response_model: None,
                    prompt_tokens: None,
                    completion_tokens: None,
                    prompt_bytes: None,
                    completion_bytes: None,
                    cost_usd: None,
                    status: crate::schema::LlmCallStatus::Ok,
                    error_class: None,
                    attempt_count: None,
                    retry_count: None,
                    prompt_hash: None,
                    prompt: None,
                    response_text: None,
                }])
                .await
                .unwrap();
        }

        // DSAR for (agent-A, key1) — cascades only the key1 LLM call.
        let summary = backend
            .delete_traces_for_agent("agent-A", "key1", false)
            .await
            .unwrap();
        assert_eq!(summary.trace_events_deleted, 1);
        assert_eq!(summary.trace_llm_calls_deleted, 1);

        // The key2 LLM call survives.
        let remaining = backend.snapshot_llm_calls();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].trace_id, "trace-k2-t1");
    }

    /// v7.0.0 (CIRISPersist#222) — full Art. 17 erasure deletes the
    /// agent's traces across ALL signing keys (contrast the per-key
    /// `delete_traces_for_agent`), cascades LLM calls by trace_id,
    /// emits a `hard_case:trace_erasure` audit row, and is idempotent.
    #[tokio::test]
    async fn erasure_deletes_all_keys_cascades_and_audits() {
        use crate::federation::{hard_case, FederationDirectory, HardCaseFilter};
        use crate::store::Backend;
        let backend = MemoryBackend::new();
        // agent-A under two keys + an unrelated agent-B.
        backend
            .insert_trace_events_batch(&[
                dsar_fixture_row("agent-A", "key1", "A-k1"),
                dsar_fixture_row("agent-A", "key2", "A-k2"),
                dsar_fixture_row("agent-B", "key1", "B-k1"),
            ])
            .await
            .unwrap();
        for trace_id in ["trace-A-k1", "trace-A-k2", "trace-B-k1"] {
            backend
                .insert_trace_llm_calls_batch(&[TraceLlmCallRow {
                    trace_id: trace_id.into(),
                    thought_id: "th".into(),
                    task_id: None,
                    parent_event_id: None,
                    parent_event_type: ReasoningEventType::ThoughtStart,
                    parent_attempt_index: 0,
                    attempt_index: 0,
                    ts: "2026-04-30T00:00:00Z".parse().unwrap(),
                    duration_ms: 0.0,
                    handler_name: "h".into(),
                    service_name: "s".into(),
                    model: None,
                    base_url: None,
                    response_model: None,
                    prompt_tokens: None,
                    completion_tokens: None,
                    prompt_bytes: None,
                    completion_bytes: None,
                    cost_usd: None,
                    status: crate::schema::LlmCallStatus::Ok,
                    error_class: None,
                    attempt_count: None,
                    retry_count: None,
                    prompt_hash: None,
                    prompt: None,
                    response_text: None,
                }])
                .await
                .unwrap();
        }

        // Erase agent-A: both keys' traces (2) + their 2 LLM calls.
        let summary = backend
            .delete_traces_for_agent_id_hash("agent-A")
            .await
            .unwrap();
        assert_eq!(summary.trace_events, 2, "both keys' traces");
        assert_eq!(summary.trace_llm_calls, 2);
        // Memory backend has no derived storage — nothing to tombstone.
        assert_eq!(summary.detection_events_tombstoned, 0);

        // agent-B survives untouched.
        let remaining = backend.snapshot_events();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].agent_id_hash, "agent-B");
        assert_eq!(backend.snapshot_llm_calls().len(), 1);

        // Audit: exactly one hard_case:trace_erasure row for agent-A.
        let events = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::TRACE_ERASURE.into()),
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target_key_id.as_deref(), Some("agent-A"));
        assert_eq!(events[0].detail["trace_events"], 2);
        assert_eq!(events[0].detail["trace_llm_calls"], 2);

        // Idempotent: a second erasure returns all-zero and emits NO
        // new audit row (clean no-op).
        let summary2 = backend
            .delete_traces_for_agent_id_hash("agent-A")
            .await
            .unwrap();
        assert_eq!(summary2.trace_events, 0);
        assert_eq!(summary2.trace_llm_calls, 0);
        let events2 = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::TRACE_ERASURE.into()),
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(events2.len(), 1, "idempotent re-run emits no new audit");
    }

    /// v0.3.5 (CIRISLens#8 ASK 3) — fetch_trace_events_page returns
    /// rows in event_id order, respects the cursor, respects the limit.
    #[tokio::test]
    async fn fetch_trace_events_page_cursors_correctly() {
        use crate::store::Backend;
        let backend = MemoryBackend::new();
        for i in 0..5 {
            let row = TraceEventRow {
                trace_id: format!("trace-{i}"),
                thought_id: format!("th-{i}"),
                task_id: None,
                step_point: None,
                event_type: ReasoningEventType::ThoughtStart,
                attempt_index: 0,
                ts: "2026-04-30T00:00:00Z".parse().unwrap(),
                agent_name: None,
                agent_id_hash: format!("agent-{}", i % 2),
                cognitive_state: None,
                trace_level: TraceLevel::Generic,
                payload: serde_json::Map::new(),
                cost_llm_calls: None,
                cost_tokens: None,
                cost_usd: None,
                signature: "AAAA".into(),
                signing_key_id: "k".into(),
                signature_verified: true,
                verification_source: crate::store::VerificationSource::Persist,
                schema_version: "2.7.0".into(),
                pii_scrubbed: false,
                original_content_hash: None,
                scrub_signature: None,
                scrub_key_id: None,
                scrub_timestamp: None,
                agent_role: None,
                agent_template: None,
                deployment_domain: None,
                deployment_type: None,
                deployment_region: None,
                deployment_trust_mode: None,
                cohort_scope: "federation".to_string(),
                cohort_target_id: None,
                signature_ml_dsa_65: None,
                pubkey_ml_dsa_65: None,
                pqc_key_id: None,
            };
            backend.insert_trace_events_batch(&[row]).await.unwrap();
        }
        // Page 1: limit=2 returns first 2 by event_id.
        let page1 = backend.fetch_trace_events_page(0, 2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        let last_eid = page1.last().unwrap().0;
        // Page 2: cursor = last from page 1.
        let page2 = backend
            .fetch_trace_events_page(last_eid, 2, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert!(page2.iter().all(|(eid, _)| *eid > last_eid));
        // Filtered by agent_id_hash.
        let filtered = backend
            .fetch_trace_events_page(0, 100, Some("agent-0"))
            .await
            .unwrap();
        assert!(filtered
            .iter()
            .all(|(_, row)| row.agent_id_hash == "agent-0"));
    }

    /// v0.2.1 — Backend::lookup_public_key dual-read. After
    /// put_public_key writes to federation_keys, the legacy
    /// Backend::lookup_public_key trait method (used by trace verify)
    /// reads back the same key via the federation table.
    #[tokio::test]
    async fn backend_lookup_public_key_dual_reads_federation() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::SigningKey;
        let backend = MemoryBackend::new();
        // Generate a real Ed25519 keypair so VerifyingKey parses.
        let signing = SigningKey::from_bytes(&[0xAB; 32]);
        let verifying = signing.verifying_key();
        let pk_b64 = B64.encode(verifying.to_bytes());

        // Write via federation surface only — no accord_public_keys insert.
        let mut rec = fix_key("agent-fed-1", "agent-1", "agent-fed-1");
        rec.pubkey_ed25519_base64 = pk_b64.clone();
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .unwrap();

        // Backend::lookup_public_key (legacy trait method, used by
        // trace verify) finds the key via federation_keys.
        let got = Backend::lookup_public_key(&backend, "agent-fed-1")
            .await
            .unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().to_bytes(), verifying.to_bytes());
    }

    /// v0.2.1 — When federation_keys has nothing, fall through to
    /// the legacy `accord_public_keys` map. This is the migration-
    /// window guarantee: trace verify keeps working against legacy
    /// rows while lens migrates.
    #[tokio::test]
    async fn backend_lookup_public_key_falls_back_to_legacy() {
        use ed25519_dalek::SigningKey;
        let backend = MemoryBackend::new();
        let signing = SigningKey::from_bytes(&[0xCD; 32]);
        let verifying = signing.verifying_key();

        // Register via legacy add_public_key (mimics
        // accord_public_keys insert).
        backend.add_public_key("agent-legacy-1", verifying);

        let got = Backend::lookup_public_key(&backend, "agent-legacy-1")
            .await
            .unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().to_bytes(), verifying.to_bytes());

        // Unknown key → None (federation empty AND legacy empty).
        let none = Backend::lookup_public_key(&backend, "ghost").await.unwrap();
        assert!(none.is_none());
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn revocation_round_trip() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("k-bad", "primitive-bad", "registry-steward"),
            })
            .await
            .unwrap();
        grant_slash(&backend, "registry-steward").await;
        backend
            .put_revocation(SignedRevocation {
                revocation: fix_revocation(
                    "rev-1",
                    "k-bad",
                    "registry-steward",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();
        let revs = backend.revocations_for("k-bad").await.unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].revocation_id, "rev-1");
        assert_eq!(revs[0].persist_row_hash.len(), 64);
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer ──
    //     dedup (memory backend parity).

    fn fix_structural_composer(
        id: &str,
        attester: &str,
        ty: &str,
        references_attestation_id: &str,
        asserted_at: &str,
    ) -> Attestation {
        let mut row = Attestation {
            attestation_id: id.into(),
            attesting_key_id: attester.into(),
            attested_key_id: attester.into(),
            attestation_type: ty.into(),
            weight: None,
            asserted_at: asserted_at.parse().unwrap(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "references_attestation_id": references_attestation_id,
                "withdrawal_reason": "test",
            }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: asserted_at.parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        resign_fix(&mut row); // v9.0.0 — sign the envelope (CC 5.3.2.4.3.1)
        row
    }

    #[tokio::test]
    async fn memory_put_attestation_structural_dedup_silent_noop() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        let w1 = fix_structural_composer(
            "w-1",
            "registry-steward",
            crate::federation::types::attestation_type::WITHDRAWS,
            "upstream-1",
            "2026-05-01T00:00:00Z",
        );
        let mut w2 = w1.clone();
        w2.attestation_id = "w-2".into();
        crate::federation::tier_ingest::test_support::reseal(&mut w2);
        w2.asserted_at = "2026-05-02T00:00:00Z".parse().unwrap();
        backend
            .put_attestation(SignedAttestation { attestation: w1 })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation { attestation: w2 })
            .await
            .unwrap();
        let rows = backend
            .list_attestations_for("registry-steward")
            .await
            .unwrap();
        let composers: Vec<_> = rows
            .iter()
            .filter(|r| r.attestation_type == crate::federation::types::attestation_type::WITHDRAWS)
            .collect();
        assert_eq!(composers.len(), 1, "second triple should be a no-op");
        assert_eq!(composers[0].attestation_id, "w-1");
    }

    // ── v6.4.0 (CIRISPersist#146 Ask 2, CEG §3.2.3 / §8.1.11.2) —
    // broadened `withdraws` admission gate on the memory backend
    // (parity with sqlite + postgres). The gate runs before the state
    // lock; this test confirms the rule numbers + the
    // independent-authority + the rule-3 delegation-chain path resolve
    // identically here.

    /// Build a memory-backend `withdraws` against `target_id`.
    fn fix_withdraws(id: &str, issuer: &str, target_id: &str) -> Attestation {
        let mut w = fix_attestation(id, issuer, issuer, issuer);
        w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        w.attestation_envelope = serde_json::json!({
            "references_attestation_id": target_id,
            "withdrawal_reason": "test",
        });
        resign_fix(&mut w); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        w
    }

    /// Build a `consent:replication:v1` grant from `node` naming `peer` as
    /// the sole `subject_key_ids` entry.
    fn fix_consent_grant(id: &str, node: &str, peer: &str) -> Attestation {
        let mut g = fix_attestation(id, node, node, node);
        // v21.3.0 (CIRISPersist#510 P1) — a `consent:replication:v1` row
        // now admits through the closed-grammar gate; this E7 fixture
        // needs a minimally-valid `payload` (its content is irrelevant to
        // this test, which exercises the peer-set fold, not grammar
        // semantics).
        g.attestation_envelope = serde_json::json!({
            "dimension": crate::federation::consent_peer_set::DIMENSION,
            "payload": {"grants": "replication", "attestation_prefixes": ["e7-fixture:"]},
        });
        g.subject_key_ids = vec![peer.to_string()];
        resign_fix(&mut g); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        g
    }

    /// v21.0.0 (CIRISPersist#502 E7) — THE witness: a `consent:replication:v1`
    /// grant to peer P1 makes `list_consent_peers` include P1; a `withdraws`
    /// referencing that grant's `attestation_id` REMOVES P1; a second,
    /// untouched grant to peer P2 is unaffected. This is the mechanical
    /// revocation fold CIRISServer's `replication_peers_from_consent` was
    /// missing (the server read `list_attestations_by` + flat-mapped
    /// `subject_key_ids` with no withdraws/recants fold at all).
    #[tokio::test]
    async fn consent_peer_set_folds_revocation_502e7() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("node-e7", "node", "node-e7"),
            })
            .await
            .unwrap();

        backend
            .put_attestation(SignedAttestation {
                attestation: fix_consent_grant("grant-e7-1", "node-e7", "peer-e7-1"),
            })
            .await
            .expect("grant 1 admits");
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_consent_grant("grant-e7-2", "node-e7", "peer-e7-2"),
            })
            .await
            .expect("grant 2 admits");

        let peers = backend.list_consent_peers("node-e7").await.unwrap();
        assert_eq!(
            peers,
            vec!["peer-e7-1".to_string(), "peer-e7-2".to_string()],
            "both live grants must be visible, sorted"
        );

        // Revoke grant 1 — self-withdrawal (rule 1: issuer ==
        // target.attesting_key_id).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("withdraw-e7-1", "node-e7", "grant-e7-1"),
            })
            .await
            .expect("withdraws admits");

        let peers_after = backend.list_consent_peers("node-e7").await.unwrap();
        assert_eq!(
            peers_after,
            vec!["peer-e7-2".to_string()],
            "peer-1's consent was withdrawn — it must disappear; peer-2 (untouched) survives"
        );
    }

    /// v21.3.0 (CIRISPersist#510 P1) — the memory-backend leg of the
    /// closed consent-grammar admission gate (see
    /// `sqlite::tests::consent_grammar_admission_rejections_sqlite_510` /
    /// `postgres::tests::consent_grammar_admission_rejections_postgres_510`):
    /// an unknown restriction op, an unrecognized top-level payload
    /// field, and a non-consentable `kinds` entry each reject the WHOLE
    /// grant at `put_attestation`. Memory duplicates its own fixture
    /// helpers (`fix_key`/`fix_attestation`/`resign_fix`) rather than
    /// sharing `consent_grammar::test_support` (that module is
    /// feature-gated on sqlite/postgres so a no-backend build compiles
    /// cleanly — the same reason `consent_peer_set_folds_revocation_502e7`
    /// above doesn't share `consent_peer_set::test_support` either).
    #[tokio::test]
    async fn consent_grant_admission_rejects_closed_grammar_violations_510() {
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("node-510m", "node", "node-510m"),
            })
            .await
            .unwrap();

        fn bad_grant(id: &str, node: &str, payload: serde_json::Value) -> Attestation {
            let mut g = fix_attestation(id, node, node, node);
            g.attestation_envelope = serde_json::json!({
                "dimension": crate::federation::consent_peer_set::DIMENSION,
                "payload": payload,
            });
            g.subject_key_ids = vec![format!("peer-of-{node}")];
            resign_fix(&mut g); // envelope changed → re-sign (CC 5.3.2.4.3.1)
            g
        }

        fn expect_510_reject(result: &Result<(), crate::federation::Error>, what: &str) {
            match result {
                Err(crate::federation::Error::InvalidArgument(msg)) => {
                    assert!(
                        msg.contains("#510"),
                        "{what} must reject with a #510-tagged reason, got: {msg}"
                    );
                }
                other => panic!("{what} must reject as InvalidArgument, got: {other:?}"),
            }
        }

        let bad1 = bad_grant(
            "510m-restr",
            "node-510m",
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "restrictions": [{"op": "quantum_redaction"}],
            }),
        );
        let err1 = backend
            .put_attestation(SignedAttestation { attestation: bad1 })
            .await;
        expect_510_reject(&err1, "an unknown restriction op");

        let bad2 = bad_grant(
            "510m-field",
            "node-510m",
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "unexpected_field_510": true,
            }),
        );
        let err2 = backend
            .put_attestation(SignedAttestation { attestation: bad2 })
            .await;
        expect_510_reject(&err2, "an unknown top-level payload field");

        let bad3 = bad_grant(
            "510m-kind",
            "node-510m",
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "kinds": ["Key"],
            }),
        );
        let err3 = backend
            .put_attestation(SignedAttestation { attestation: bad3 })
            .await;
        expect_510_reject(&err3, "a non-consentable kind");
    }

    /// Build a memory-backend `delegates_to` carrying `scope`.
    fn fix_delegates_to(
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
    ) -> Attestation {
        let mut d = fix_attestation(id, granter, grantee, granter);
        d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        d.attestation_envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": scope,
        });
        resign_fix(&mut d); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        d
    }

    /// v18.2.0 (CIRISPersist#481) — the pluggable-trust-root witnesses, all
    /// four asks through the REAL write + walk surfaces:
    /// 1. self-root `attestation(user → user)` ADMITS;
    /// 2. self-referential `delegates_to(root → root, scope:[infra:*])`
    ///    ADMITS (a root roots to itself) — and note the TWO-PLANES rule:
    ///    these are delegation SCOPE tokens in an envelope, not the
    ///    accord-conferred `infra:attest` key ROLE (which stays co-scrub
    ///    gated; see admission set-path tests);
    /// 3. `trust_root_valid` evaluates the full predicate (edge +
    ///    self-declaration + fresh heartbeat + halt latch);
    /// 4. the `withdraws` tombstone on the trust edge makes the walk treat
    ///    it as ABSENT (nuclear un-trust; base self-root untouched).
    #[tokio::test]
    async fn trust_root_walk_and_tombstone_481() {
        use crate::federation::trust_root::{trust_root_valid, TrustRootVerdict};
        let backend = MemoryBackend::new();
        for (k, it) in [
            ("tr-user", "user"),
            ("tr-root", "node"),
            ("tr-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }

        // Ask 1 — the self-root base admits (attesting == attested == self).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("tr-self", "tr-user", "tr-user", "tr-user"),
            })
            .await
            .expect("(1) self-root attestation(user→user) must admit");

        // Ask 2 — the self-referential root declaration admits.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_charter(
                    "tr-rootdecl",
                    "tr-root",
                    serde_json::json!(["infra:attest", "infra:serve"]),
                ),
            })
            .await
            .expect("(2) delegates_to(root→root, infra:*) must admit");

        // The user's trust edge.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "tr-edge",
                    "tr-user",
                    "tr-root",
                    serde_json::json!(["infra:attest", "infra:serve"]),
                ),
            })
            .await
            .expect("delegates_to(user→root) must admit");

        // Fresh heartbeat about the root (accord:* attester must be
        // an accord_holder — the constitutional asymmetry holds here too).
        let mut lc = fix_attestation("tr-lc", "tr-la", "tr-root", "tr-la");
        lc.attestation_envelope = serde_json::json!({
            "id": "tr-lc",
            "dimension": "accord:lifecycle:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        lc.asserted_at = chrono::Utc::now();
        resign_fix(&mut lc);
        backend
            .put_attestation(SignedAttestation { attestation: lc })
            .await
            .expect("the heartbeat from an accord_holder must admit");

        // Ask 3 — the walk: every leg green.
        let v: TrustRootVerdict = trust_root_valid(&backend, "tr-user", "tr-root")
            .await
            .expect("walk");
        assert!(v.edge_exists, "(3) live user→root edge");
        assert!(
            v.root_self_declares,
            "(3) root self-declares w/ infra scope"
        );
        assert_eq!(
            v.drill_freshness,
            crate::federation::trust_root::DrillFreshness::Green,
            "(3) fresh drill reads Green — reported, not gated on"
        );
        assert_ne!(v.halt_latched, Some(true), "(3) no halt latched");
        assert!(v.valid, "(3) all legs ⇒ valid");

        // A self-root is the immutable BASE, never a valid EXTERNAL root.
        let v0 = trust_root_valid(&backend, "tr-user", "tr-user")
            .await
            .expect("walk self");
        assert!(
            !v0.valid && !v0.edge_exists,
            "base self-root ≠ external root"
        );

        // Ask 4 — nuclear un-trust: withdraw the edge; the walk folds it
        // ABSENT. The base self-root is untouched (the app never bricks).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("tr-w", "tr-user", "tr-edge"),
            })
            .await
            .expect("(4) withdraws on own edge must admit");
        let v2 = trust_root_valid(&backend, "tr-user", "tr-root")
            .await
            .expect("walk post-tombstone");
        assert!(!v2.edge_exists, "(4) tombstoned edge is ABSENT to the walk");
        assert!(!v2.valid, "(4) un-trust revokes validity");
        assert!(
            v2.root_self_declares
                && v2.drill_freshness == crate::federation::trust_root::DrillFreshness::Green,
            "(4) only the EDGE died — the root's own declarations stand"
        );
    }

    /// v23.0.0 (CIRISPersist#551 item 4, the REAL half) — **the drill is a
    /// trust SIGNAL, not a functionality gate.**
    ///
    /// A genesis root is valid until revoked, halted, or un-trusted:
    /// tombstones and the halt latch ARE the revocation mechanism, so a
    /// deadman on top of them gave the artifact a shelf life nobody intended
    /// — three months after the mint every node darkens together, with no
    /// error at the point of use. What the drill actually tells you is
    /// whether the root is GOVERNED or ABANDONED, and that is a thing to
    /// report, not a thing to withhold service over.
    ///
    /// So: `valid` no longer consults the drill at all, and the freshness
    /// rides a band — the same band-not-float discipline as every other
    /// score in the system. The hard gates (edge, charter, recovery, halt
    /// latch) are untouched: the kill switch and the operator's un-trust
    /// lever still work exactly as before.
    #[tokio::test]
    async fn drill_freshness_is_a_signal_not_a_gate_551() {
        use crate::federation::trust_root::{
            trust_root_valid, DrillFreshness, TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION,
        };
        let backend = MemoryBackend::new();
        for (k, it) in [
            ("drill-user", "user"),
            ("drill-green", "node"),
            ("drill-yellow", "node"),
            ("drill-never", "node"),
            ("drill-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        let scope = || serde_json::json!(["infra:attest", "infra:serve"]);
        let stamp = |mut a: Attestation, dimension: &str| {
            a.attestation_envelope["dimension"] = serde_json::json!(dimension);
            resign_fix(&mut a);
            a
        };
        // A drill row about `root`, asserted `days_ago` days back.
        let drill = |id: &str, about: &str, days_ago: i64| {
            let mut d = fix_attestation(id, "drill-la", about, "drill-la");
            d.attestation_envelope = serde_json::json!({
                "id": id,
                "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
                "score": 1.0,
                "confidence": 0.9,
            });
            d.asserted_at = chrono::Utc::now() - chrono::Duration::days(days_ago);
            resign_fix(&mut d);
            d
        };
        // Stand up the HARD legs for each root: charter + the user's edge.
        for root in ["drill-green", "drill-yellow", "drill-never"] {
            for a in [
                stamp(
                    fix_charter(&format!("{root}-charter"), root, scope()),
                    TRUST_CHARTER_DIMENSION,
                ),
                stamp(
                    fix_delegates_to(&format!("{root}-edge"), "drill-user", root, scope()),
                    TRUST_ACCEPTS_DIMENSION,
                ),
            ] {
                backend
                    .put_attestation(SignedAttestation { attestation: a })
                    .await
                    .expect("hard legs admit");
            }
        }
        // Drills: fresh / aged into the yellow band / none at all.
        for a in [
            drill("dg-lc", "drill-green", 1),
            drill("dy-lc", "drill-yellow", 120),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("drill admits");
        }

        let green = trust_root_valid(&backend, "drill-user", "drill-green")
            .await
            .expect("walk");
        assert!(green.valid, "fresh drill + hard legs ⇒ valid: {green:?}");
        assert_eq!(green.drill_freshness, DrillFreshness::Green, "{green:?}");
        assert!(green.last_drill_at.is_some(), "the drill date is reported");

        // THE ASSERTION THIS TEST EXISTS FOR — a root drilled 120 days ago
        // still SERVES. Its trust card reads yellow; nothing is withheld.
        let yellow = trust_root_valid(&backend, "drill-user", "drill-yellow")
            .await
            .expect("walk");
        assert!(
            yellow.valid,
            "a stale-drilled root MUST still serve — the deadman is gone: {yellow:?}"
        );
        assert_eq!(yellow.drill_freshness, DrillFreshness::Yellow, "{yellow:?}");

        // Never drilled: valid, and RED. `last_drill_at: None` is what
        // distinguishes "never" from "long ago" — the band does not need a
        // fourth variant to say it.
        let never = trust_root_valid(&backend, "drill-user", "drill-never")
            .await
            .expect("walk");
        assert!(
            never.valid,
            "an undrilled root still serves — governance signal, not a gate: {never:?}"
        );
        assert_eq!(never.drill_freshness, DrillFreshness::Red, "{never:?}");
        assert_eq!(never.last_drill_at, None, "never drilled, and it says so");

        // The HARD gates are untouched: withdraw the one edge and trust
        // collapses, drill or no drill.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("dg-w", "drill-user", "drill-green-edge"),
            })
            .await
            .expect("withdraws admits");
        let unrooted = trust_root_valid(&backend, "drill-user", "drill-green")
            .await
            .expect("walk");
        assert!(
            !unrooted.valid && !unrooted.edge_exists,
            "the un-trust lever still works: {unrooted:?}"
        );
        assert_eq!(
            unrooted.drill_freshness,
            DrillFreshness::Green,
            "…and the drill signal is reported independently of the gate"
        );
    }

    /// v23.0.0 (CIRISPersist#551 item 2) — the three `delegates_to` jobs are
    /// NAMED, and a mislabeled lever is refused.
    ///
    /// One wire type, three opposite jobs, discriminated only by direction:
    /// charter (R→R), conferral (R→subject), trust edge (node→R). #551 cost a
    /// session four wrong statements about the trust root, every one a "which
    /// `delegates_to` is this?" failure made while reading the source. So the
    /// job now rides the envelope `dimension`, and each predicate reads its
    /// own name instead of doing direction-arithmetic.
    ///
    /// Three properties, in the order that makes the design legible:
    /// 1. correctly-dimensioned rows walk exactly as before (PREFERRED);
    /// 2. an UNDIMENSIONED row still walks (direction-inference retained —
    ///    additive, no wire break, every pre-v23 row keeps working);
    /// 3. a row whose dimension CONTRADICTS its direction is REFUSED by the
    ///    predicate reading it. A mislabeled lever is worse than an
    ///    unlabeled one: unlabeled, the reader must look at direction and
    ///    gets it right; mislabeled, the label invites the reader to trust it.
    #[tokio::test]
    async fn trust_job_dimensions_named_and_contradictions_refused_551() {
        use crate::federation::trust_root::{
            trust_root_valid, TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION,
        };
        let backend = MemoryBackend::new();
        for (k, it) in [
            ("d551-user", "user"),
            ("d551-root", "node"),
            ("d551-plain", "node"),
            ("d551-bad", "node"),
            ("d551-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        // A fresh liveness witness about `root`, so the other legs are green.
        let lifecycle = |id: &str, about: &str| {
            let mut lc = fix_attestation(id, "d551-la", about, "d551-la");
            lc.attestation_envelope = serde_json::json!({
                "id": id,
                "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
                "score": 1.0,
                "confidence": 0.9,
            });
            lc.asserted_at = chrono::Utc::now();
            resign_fix(&mut lc);
            lc
        };
        // Stamp a job dimension onto a row built by the shared fixtures.
        let stamp = |mut a: Attestation, dimension: &str| {
            a.attestation_envelope["dimension"] = serde_json::json!(dimension);
            resign_fix(&mut a);
            a
        };
        let scope = || serde_json::json!(["infra:attest", "infra:serve"]);

        // ── (1) CORRECTLY dimensioned: charter says charter, edge says
        //    accepts. Every leg green.
        for a in [
            stamp(
                fix_charter("d551-charter", "d551-root", scope()),
                TRUST_CHARTER_DIMENSION,
            ),
            stamp(
                fix_delegates_to("d551-edge", "d551-user", "d551-root", scope()),
                TRUST_ACCEPTS_DIMENSION,
            ),
            lifecycle("d551-lc", "d551-root"),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("(1) a job-dimensioned trust row must ADMIT — item 2 is additive");
        }
        let v = trust_root_valid(&backend, "d551-user", "d551-root")
            .await
            .expect("walk");
        assert!(
            v.edge_exists && v.root_self_declares && v.valid,
            "(1) correctly-named rows walk: {v:?}"
        );

        // ── (2) UNDIMENSIONED rows still walk. This is the additive
        //    guarantee for every row written before v23.0.0: no wire break,
        //    no migration, no re-signing. Asserted deliberately here rather
        //    than left to whichever fixture happened not to be stamped.
        for a in [
            fix_charter("d551-plaincharter", "d551-plain", scope()),
            fix_delegates_to("d551-plainedge", "d551-user", "d551-plain", scope()),
            lifecycle("d551-plainlc", "d551-plain"),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("(2) an undimensioned trust row admits as it always did");
        }
        let plain = trust_root_valid(&backend, "d551-user", "d551-plain")
            .await
            .expect("walk");
        assert!(
            plain.edge_exists && plain.root_self_declares && plain.valid,
            "(2) direction inference still decides an unlabeled row: {plain:?}"
        );

        // ── (3) CONTRADICTION: same shapes, labels swapped. The charter
        //    (R→R) claims to be a trust edge; the edge (user→R) claims to be
        //    a charter. Neither predicate may accept the row that lies to it.
        for a in [
            stamp(
                fix_charter("d551-badcharter", "d551-bad", scope()),
                TRUST_ACCEPTS_DIMENSION,
            ),
            stamp(
                fix_delegates_to("d551-badedge", "d551-user", "d551-bad", scope()),
                TRUST_CHARTER_DIMENSION,
            ),
            lifecycle("d551-badlc", "d551-bad"),
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("a mislabeled row still WRITES — refusal is the walk's job, not ingest's");
        }
        let bad = trust_root_valid(&backend, "d551-user", "d551-bad")
            .await
            .expect("walk");
        assert!(
            !bad.root_self_declares,
            "(3) a self-loop labeled `{TRUST_ACCEPTS_DIMENSION}` is NOT a charter: {bad:?}"
        );
        assert!(
            !bad.edge_exists,
            "(3) a user→root edge labeled `{TRUST_CHARTER_DIMENSION}` is NOT a trust edge: {bad:?}"
        );
        assert!(!bad.valid, "(3) a mislabeled lever confers nothing");
    }

    /// v19.1.0 (CIRISPersist#490) — THE acceptance witness: bake the REAL
    /// 2026-07-23 humanity-accord ceremony artifact (`genesis_v2.json`,
    /// byte-exact, sha256 44be2cf8…) against a node holding the REAL baked
    /// genesis state (A1/B1/C1 roster + the prior roles-less canonical
    /// anchor — the exact state that refused the adopt in the field).
    ///
    /// Proves end-to-end, with production cryptography:
    /// 1. the bundle quorum (A1+B1 hybrid YubiKey authorizations) verifies
    ///    against persist's OWN roster + directory-pinned keys;
    /// 2. the anchored-but-different canonical is RE-ANCHORED (the exact
    ///    "downgrade/replace refused" case, now authenticated);
    /// 3. the #486 lift makes the re-blessed record claim `infra:serve`
    ///    (envelope-attested, top-level `roles:[]` on the wire);
    /// 4. the delegation plane admits (the charter passes the v19.0.0
    ///    pre-rotation gate; the serve grant lands);
    /// 5. re-baking the same artifact is a no-op (idempotent).
    #[tokio::test]
    async fn bake_real_genesis_v2_artifact_490() {
        use crate::federation::genesis::{bake_assembled_genesis, BakeItemOutcome};
        let backend = MemoryBackend::new();

        // Seed the REAL baked genesis state: the A1/B1/C1 holder roster…
        // v22.0.0 (CIRISPersist#543) — through `seed_genesis_accord_holders`,
        // the same door the sqlite + postgres genesis paths use, NOT bare
        // `put_public_key`. The baked ceremony evidence is a #268 custody
        // attestation with a stale-by-design nonce; re-checking it at every
        // boot is a category error, which is exactly why the SQL backends
        // have a dedicated seed entry point. Memory reaching for
        // `put_public_key` here was the tell that it had no hardware gate to
        // need seeding around.
        backend
            .seed_genesis_accord_holders(
                &crate::federation::genesis::effective_accord_holder_records(),
            )
            .await
            .expect("seed accord holder roster");
        // …and the PRIOR canonical anchor — the PRE-CEREMONY roles-less
        // record (kept as a fixture: the live baked seed is now the
        // re-blessed one, so the field-refusal state must be seeded
        // explicitly).
        let prev: Vec<crate::federation::SignedKeyRecord> =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/canonical_seed_pre_ceremony.json"
            )))
            .expect("pre-ceremony seed fixture parses");
        for rec in prev {
            backend
                .put_public_key(rec)
                .await
                .expect("seed prior canonical anchor");
        }
        let canon = "ciris-canonical-1-d7bdeu223k";
        let before = crate::federation::FederationDirectory::lookup_public_key(&backend, canon)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !before.claims_role("infra:serve"),
            "fixture: prior anchor is dark (no infra:serve) — the #480 state"
        );

        // Bake the REAL artifact.
        let artifact = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/genesis_v2.json"
        ));
        let report = bake_assembled_genesis(&backend, artifact)
            .await
            .expect("the real ceremony artifact must verify and bake");
        assert_eq!(
            report.quorum_verified, 2,
            "A1+B1 hybrid authorizations verified"
        );
        assert_eq!(
            report.serve_nodes,
            vec![(canon.to_owned(), BakeItemOutcome::ReAnchored)],
            "the anchored-but-different canonical is re-anchored under quorum"
        );
        for (id, outcome) in &report.attestations {
            assert!(
                matches!(
                    outcome,
                    BakeItemOutcome::Anchored | BakeItemOutcome::AlreadyPresent
                ),
                "delegation-plane row {id} must land, got {outcome:?}"
            );
        }

        // The mesh is bright: the re-blessed record claims infra:serve
        // (the #486 lift over the envelope-attested set).
        let after = crate::federation::FederationDirectory::lookup_public_key(&backend, canon)
            .await
            .unwrap()
            .unwrap();
        assert!(after.claims_role("infra:serve"), "the trace plane opens");
        assert!(after.claims_role(crate::federation::types::identity_type::CANONICAL));
        assert!(
            after.valid_from > before.valid_from,
            "anti-rollback ordering"
        );

        // Idempotent: same artifact again → nothing changes, no error.
        let again = bake_assembled_genesis(&backend, artifact)
            .await
            .expect("re-bake is a no-op, not an error");
        assert_eq!(
            again.serve_nodes,
            vec![(canon.to_owned(), BakeItemOutcome::AlreadyPresent)],
            "idempotent re-bake"
        );

        // A tampered bundle (flipped byte in an authorization) refuses and
        // writes NOTHING.
        let mut tampered: serde_json::Value = serde_json::from_str(artifact).unwrap();
        tampered["authorizations"][0]["signature_classical"] = serde_json::json!("QUFBQQ==");
        let err = bake_assembled_genesis(&backend, &tampered.to_string())
            .await
            .expect_err("tampered authorization must refuse");
        assert_eq!(err.kind(), "federation_genesis_bundle_invalid");
    }

    /// v21.0.0 (CIRISPersist#502 E9) — the operational role authority
    /// resolves the steward roster from OUR OWN registered directory, not a
    /// caller-passed slice. A grant rooted at a key that is NOT a registered
    /// steward is REFUSED — a caller can no longer bless itself by handing
    /// in a roster.
    #[tokio::test]
    async fn operational_roster_resolves_from_own_directory_502e9() {
        use crate::federation::operational::test_support as op;
        let backend = MemoryBackend::new();
        let steward = op::Identity::new("e9-steward");
        let admin = op::Identity::new("e9-admin");

        // v31.0.0 (CIRISPersist#644) — the outsider is now REGISTERED (as a
        // plain agent), which sharpens this test rather than weakening it.
        // Before #644 the first leg refused a key the directory had never
        // heard of, so "not a steward" and "not registered at all" were
        // indistinguishable — and the row's own signature was never checked,
        // so the leg could not have told them apart. Now the outsider's
        // signature VERIFIES and the ONLY thing it lacks is steward status,
        // which is precisely the E9 property under test.
        let outsider = op::Identity::new("e9-outsider");
        crate::federation::tier_ingest::test_support::register_hybrid_key(&backend, "e9-outsider")
            .await;

        // Grant rooted at a registered NON-steward → the resolved roster
        // does not contain it → NoQualifyingGrant, refused.
        let grant = op::signed_membership(
            "e9-m1",
            &outsider,
            "e9-admin",
            "e9-org",
            "org_admin",
            "active",
            chrono::Utc::now(),
        );
        let err = backend
            .put_org_membership(grant)
            .await
            .expect_err("(E9) grant rooted at a non-steward is refused");
        assert!(
            err.kind().contains("operational_authority"),
            "kind {}",
            err.kind()
        );

        // Register the steward IN OUR DIRECTORY → now the same grant admits.
        backend
            .put_public_key(SignedKeyRecord {
                record: steward.steward_key_record(),
            })
            .await
            .expect("register steward");
        let grant2 = op::signed_membership(
            "e9-m2",
            &steward,
            "e9-admin",
            "e9-org",
            "org_admin",
            "active",
            chrono::Utc::now(),
        );
        backend
            .put_org_membership(grant2)
            .await
            .expect("(E9) grant rooted at a REGISTERED steward admits");
        let _ = &admin;
    }

    // v30.8.0 (CIRISPersist#596 item 1) — gated with `grant_slash`, which needs
    // the conferral builder in `r2_test_support` (itself cfg(any(sqlite,
    // postgres)) because it requires a real signing path). A cfg on the helper
    // but not its CALL SITES is the v30.4.1 `_pyffi` defect exactly, and the
    // no-feature leg is what catches it. Coverage note: this test stops running
    // on the default build; its subject (revocation mechanics on the memory
    // backend) is covered on every featured leg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    /// v21.0.0 (CIRISPersist#502 E1) — a forged revocation (scrub sig by a
    /// key OTHER than the declared revoking key) is REJECTED. The attack:
    /// any linked peer forging `{revoked: victim, revoking: any-existing}`
    /// for a targeted de-peer. Before this it admitted on FK-existence.
    #[tokio::test]
    async fn forged_revocation_wrong_signer_rejected_502e1() {
        let backend = MemoryBackend::new();
        for k in ["e1-victim", "e1-revoker", "e1-attacker"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        // Honest revocation (revoker signs) — admits.
        let good = fix_revocation("e1-good", "e1-victim", "e1-revoker", "e1-revoker");
        grant_slash(&backend, "e1-revoker").await;
        backend
            .put_revocation(crate::federation::SignedRevocation { revocation: good })
            .await
            .expect("(E1) honestly-signed revocation admits");

        // Forged: claims revoking=e1-revoker but the envelope is signed by
        // the ATTACKER's key. The registered pubkeys of e1-revoker won't
        // verify it → reject.
        let mut forged = fix_revocation("e1-forged", "e1-victim", "e1-revoker", "e1-revoker");
        let (och, sc, sp) = crate::federation::tier_ingest::test_support::sign_envelope(
            "e1-attacker",
            &forged.revocation_envelope,
        );
        forged.original_content_hash = och;
        forged.scrub_signature_classical = sc;
        forged.scrub_signature_pqc = sp;
        let err = backend
            .put_revocation(crate::federation::SignedRevocation { revocation: forged })
            .await
            .expect_err("(E1) forged revocation must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
    }

    /// v21.0.0 (CIRISPersist#502 E5) — a LOCAL-tier delegates_to/charter
    /// must NEVER count in the capability walk. Before this a local-tier
    /// `delegates_to(user→root)` + local-tier root self-charter silently
    /// satisfied `trust_root_valid` (the hole under all 95 claim families).
    #[tokio::test]
    async fn local_tier_rows_do_not_count_in_capability_walk_502e5() {
        use crate::federation::trust_root::trust_root_valid;
        let backend = MemoryBackend::new();
        for (k, it) in [
            ("e5-user", "user"),
            ("e5-root", "node"),
            ("e5-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        // Build the full valid-root fixture but flip every capability row to
        // LOCAL tier — the walk must treat them as absent.
        let mut charter = fix_charter(
            "e5-c",
            "e5-root",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        charter.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut charter);
        backend
            .put_attestation(SignedAttestation {
                attestation: charter,
            })
            .await
            .unwrap();

        let mut edge = fix_delegates_to(
            "e5-e",
            "e5-user",
            "e5-root",
            serde_json::json!(["infra:serve"]),
        );
        edge.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut edge);
        backend
            .put_attestation(SignedAttestation { attestation: edge })
            .await
            .unwrap();

        let mut lc = fix_attestation("e5-lc", "e5-la", "e5-root", "e5-la");
        lc.attestation_envelope = serde_json::json!({
            "id": "e5-lc", "dimension": "accord:lifecycle:v1", "score": 1.0, "confidence": 0.9,
        });
        lc.asserted_at = chrono::Utc::now();
        lc.tier = crate::federation::types::attestation_tier::LOCAL.to_string();
        resign_fix(&mut lc);
        backend
            .put_attestation(SignedAttestation { attestation: lc })
            .await
            .unwrap();

        let v = trust_root_valid(&backend, "e5-user", "e5-root")
            .await
            .unwrap();
        assert!(!v.edge_exists, "local-tier edge must not count");
        assert!(!v.root_self_declares, "local-tier charter must not count");
        assert_eq!(
            v.last_drill_at, None,
            "a local-tier drill row must not register as a drill"
        );
        assert!(!v.valid, "no local-tier row satisfies the capability gate");
    }

    /// v19.0.0 (CIRISPersist#488) — the RC3 charter deltas, all three:
    /// (1) CRITICAL: a charter without a pre-rotation commitment REFUSES at
    /// admission; a recovery declaration must BIND to the predecessor's
    /// pre-committed successor set; (2) serve∧attest AND-minimum — a
    /// serve-only self-loop is not a root; (3) an EXPIRED trust edge is as
    /// dead to the walk as a tombstoned one.
    #[tokio::test]
    async fn rc3_charter_deltas_488() {
        use crate::federation::trust_root::{pre_rotation_commitment, trust_root_valid};
        let backend = MemoryBackend::new();
        for (k, it) in [
            ("rc-user", "user"),
            ("rc-root", "node"),
            ("rc-root2", "node"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }

        // (1) commitment-less charter REFUSES with the typed kind.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "rc-bare",
                    "rc-root",
                    "rc-root",
                    serde_json::json!(["infra:serve", "infra:attest"]),
                ),
            })
            .await
            .expect_err("(1) charter without pre-rotation commitment must refuse");
        assert_eq!(err.kind(), "federation_charter_invalid");

        // (2) serve-only charter admits (it is a valid delegates_to) but is
        // NOT a root to the walk — the AND-minimum.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_charter(
                    "rc-serveonly",
                    "rc-root2",
                    serde_json::json!(["infra:serve"]),
                ),
            })
            .await
            .expect("serve-only self-loop admits (charter-shaped, commitment present)");
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "rc-edge2",
                    "rc-user",
                    "rc-root2",
                    serde_json::json!(["infra:serve"]),
                ),
            })
            .await
            .unwrap();
        let v = trust_root_valid(&backend, "rc-user", "rc-root2")
            .await
            .unwrap();
        assert!(v.edge_exists);
        assert!(
            !v.root_self_declares && !v.valid,
            "(2) serve-only self-loop is NOT a root (serve∧attest minimum)"
        );

        // (3) an expired edge is dead to the walk.
        let mut expired = fix_delegates_to(
            "rc-expired-edge",
            "rc-user",
            "rc-root",
            serde_json::json!(["infra:serve"]),
        );
        expired.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        resign_fix(&mut expired);
        backend
            .put_attestation(SignedAttestation {
                attestation: expired,
            })
            .await
            .unwrap();
        let v3 = trust_root_valid(&backend, "rc-user", "rc-root")
            .await
            .unwrap();
        assert!(
            !v3.edge_exists,
            "(3) expired delegates_to is ABSENT to the walk"
        );

        // (1b) recovery binding: predecessor charter pre-commits to a
        // successor set; the bound successor charter ADMITS; a non-binding
        // one REFUSES; a non-member attester REFUSES.
        let successors = vec!["rc-root2".to_owned(), "rc-user".to_owned()];
        let commitment = pre_rotation_commitment(&successors).unwrap();
        let mut pred = fix_delegates_to(
            "rc-pred",
            "rc-root",
            "rc-root",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        pred.attestation_envelope = serde_json::json!({
            "references_attestation_id": "rc-pred",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment": commitment,
        });
        resign_fix(&mut pred);
        backend
            .put_attestation(SignedAttestation { attestation: pred })
            .await
            .expect("predecessor charter admits");

        // Bound successor charter: attester rc-root2 ∈ pre-committed set.
        let mut succ = fix_charter(
            "rc-succ",
            "rc-root2",
            serde_json::json!(["infra:serve", "infra:attest"]),
        );
        let succ_env = serde_json::json!({
            "references_attestation_id": "rc-succ",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment":
                pre_rotation_commitment(&["rc-next-a".to_owned()]).unwrap(),
            "recovers": "rc-root",
            "successor_keys": successors,
        });
        succ.attestation_envelope = succ_env;
        resign_fix(&mut succ);
        backend
            .put_attestation(SignedAttestation {
                attestation: succ.clone(),
            })
            .await
            .expect("(1b) BOUND recovery charter admits");

        // Non-binding successor set → refused.
        let mut bad = succ.clone();
        bad.attestation_id = "rc-succ-bad".into();
        bad.attestation_envelope["successor_keys"] =
            serde_json::json!(["rc-root2", "not-precommitted"]);
        resign_fix(&mut bad);
        let err = backend
            .put_attestation(SignedAttestation { attestation: bad })
            .await
            .expect_err("(1b) non-binding successor set must refuse");
        assert_eq!(err.kind(), "federation_charter_invalid");
    }

    /// v19.0.0 (CIRISPersist#486) — envelope-attested roles LIFT into the
    /// claim surface (union, then gate): a scrub-signed envelope carrying
    /// `roles:["infra:serve"]` becomes visible to `claims_role` after
    /// `put_public_key`; a GATED role (`infra:attest`) lifted from an
    /// envelope with no accord co-scrub still REFUSES at its write gate —
    /// lifting creates visibility, never conferral.
    #[tokio::test]
    async fn envelope_attested_roles_lift_then_gate_486() {
        let backend = MemoryBackend::new();

        // Ungated role in the envelope, empty top-level roles (the exact
        // #480 shape): after put, the row CLAIMS infra:serve.
        let mut rec = fix_key("lift-1", "ref", "lift-1");
        rec.identity_type = "node".to_owned();
        rec.registration_envelope = serde_json::json!({
            "key_id": "lift-1",
            "roles": ["infra:serve"],
        });
        assert!(
            rec.capability_roles.is_empty(),
            "fixture: top-level roles empty"
        );
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("envelope-roled record admits");
        let row = crate::federation::FederationDirectory::lookup_public_key(&backend, "lift-1")
            .await
            .unwrap()
            .unwrap();
        assert!(
            row.claims_role("infra:serve"),
            "(486) envelope-attested infra:serve is VISIBLE to claims_role"
        );

        // Lift-then-gate: infra:attest in the envelope of a record with NO
        // accord co-scrub → the v15 write gate refuses the lifted claim.
        let mut gated = fix_key("lift-2", "ref", "lift-2");
        gated.identity_type = "node".to_owned();
        gated.registration_envelope = serde_json::json!({
            "key_id": "lift-2",
            "roles": ["infra:attest"],
        });
        let err = backend
            .put_public_key(SignedKeyRecord { record: gated })
            .await
            .expect_err("(486) lifted infra:attest with no co-scrub must refuse");
        assert!(
            err.kind().contains("infra_attest") || err.kind().contains("accord"),
            "refused by the infra:attest gate, got kind {}",
            err.kind()
        );
    }

    /// v18.3.0 (CIRISPersist#483) — the composed capability walk: a
    /// subject's `infra:serve`, granted by a root the asking user trusts,
    /// resolves to that root; when the user un-trusts the root (edge
    /// tombstone), the SAME subject grant no longer roots → `None`. This is
    /// edge#386's trace-serve gate: serve only under a COMMON valid root.
    #[tokio::test]
    async fn capability_roots_to_trusted_root_483() {
        use crate::federation::trust_root::{capability_roots_to_trusted_root, trust_root_valid};
        let backend = MemoryBackend::new();
        for (k, it) in [
            ("cr-user", "user"),
            ("cr-root", "node"),
            ("cr-peer", "node"),
            ("cr-la", "accord_holder"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        let infra = || serde_json::json!(["infra:attest", "infra:serve"]);

        // Root self-declares + user trusts it + fresh lifecycle (the full
        // valid-root fixture, mirroring the 481 witness).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_charter("cr-rootdecl", "cr-root", infra()),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to("cr-edge", "cr-user", "cr-root", infra()),
            })
            .await
            .unwrap();
        let mut lc = fix_attestation("cr-lc", "cr-la", "cr-root", "cr-la");
        lc.attestation_envelope = serde_json::json!({
            "id": "cr-lc", "dimension": "accord:lifecycle:v1", "score": 1.0, "confidence": 0.9,
        });
        lc.asserted_at = chrono::Utc::now();
        resign_fix(&mut lc);
        backend
            .put_attestation(SignedAttestation { attestation: lc })
            .await
            .unwrap();
        assert!(
            trust_root_valid(&backend, "cr-user", "cr-root")
                .await
                .unwrap()
                .valid,
            "fixture: root is valid for the user"
        );

        // The root grants the PEER infra:serve.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "cr-grant",
                    "cr-root",
                    "cr-peer",
                    serde_json::json!(["infra:serve"]),
                ),
            })
            .await
            .unwrap();

        // #483 — the peer's infra:serve roots to a root the user trusts.
        let grant = capability_roots_to_trusted_root(&backend, "cr-user", "cr-peer", "infra:serve")
            .await
            .expect("walk")
            .expect("peer serves under a root the user trusts");
        assert_eq!(grant.root_key_id, "cr-root");
        assert_eq!(grant.grant_attestation_id, "cr-grant");
        assert!(grant.verdict.valid);

        // A scope the peer was NOT granted → None.
        assert!(
            capability_roots_to_trusted_root(&backend, "cr-user", "cr-peer", "infra:store")
                .await
                .unwrap()
                .is_none(),
            "ungranted scope roots nowhere"
        );

        // Un-trust the root: the peer's grant now roots to nothing.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("cr-w", "cr-user", "cr-edge"),
            })
            .await
            .unwrap();
        assert!(
            capability_roots_to_trusted_root(&backend, "cr-user", "cr-peer", "infra:serve")
                .await
                .unwrap()
                .is_none(),
            "un-trusting the root stops the peer serving immediately (edge#386)"
        );
    }

    /// v18.3.0 (CIRISPersist#484) — the exported co-scrub minting helpers
    /// let a consumer test the `has_accord_conferred_role` ALLOW path, not just the
    /// deny path (the CIRISEdge#379 fail-closed-blindness fix). Same crate,
    /// so `#[cfg(test)]` reaches them; downstream reaches them via the
    /// `test-anchor` feature (`ciris_persist::federation::accord_test_support`).
    #[tokio::test]
    async fn exported_coscrub_helpers_prove_has_accord_conferred_role_allow_and_deny_484() {
        use crate::federation::admission::has_accord_conferred_role_over_roster;
        use crate::federation::operational::test_support::{
            register_accord_holder, signed_canonical_record, signed_canonical_record_with_roles,
            Identity,
        };
        let backend = MemoryBackend::new();

        // A 2-of-3 accord family (register the pinned pubkeys the co-scrub
        // verifies against).
        let holders = [
            Identity::new("h0-484"),
            Identity::new("h1-484"),
            Identity::new("h2-484"),
        ];
        for h in &holders {
            register_accord_holder(&backend, h)
                .await
                .expect("register holder");
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let env = serde_json::json!({ "key_id": "canon-484", "purpose": "test" });

        // ALLOW: a genuinely co-scrubbed record claiming infra:serve, signed
        // by 2 distinct holders → has_accord_conferred_role == true.
        let allow = signed_canonical_record_with_roles(
            "canon-484",
            "node",
            vec!["infra:serve".to_owned()],
            env.clone(),
            &[&holders[0], &holders[1]],
        );
        backend
            .put_public_key(SignedKeyRecord { record: allow })
            .await
            .expect("co-scrubbed record admits");
        assert!(
            has_accord_conferred_role_over_roster(&backend, "canon-484", "infra:serve", &roster)
                .await
                .unwrap(),
            "(484) genuinely co-scrubbed record → has_accord_conferred_role ALLOW"
        );

        // DENY: a record with the SAME role claim but NO co-scrub (only a
        // self-scrub) → false. This is what edge could test before; now both
        // arms are provable.
        let self_only = signed_canonical_record_with_roles(
            "canon-484-self",
            "node",
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": "canon-484-self" }),
            &[&Identity::new("self-484")], // not in the roster → does not count
        );
        backend
            .put_public_key(SignedKeyRecord { record: self_only })
            .await
            .expect("self-scrubbed record still stores");
        assert!(
            !has_accord_conferred_role_over_roster(
                &backend,
                "canon-484-self",
                "infra:serve",
                &roster
            )
            .await
            .unwrap(),
            "(484) self-asserted role with no accord co-scrub → DENY"
        );

        // And the plain (rolesless) builder is unaffected — sanity that the
        // export didn't change existing behavior.
        let _plain = signed_canonical_record("x-484", "node", env, &[&holders[0]]);
    }

    /// v21.14.0 (CIRISPersist#534) — the SAME backend-agnostic conferral body
    /// the sqlite + postgres parity tests run, on MemoryBackend. The trio
    /// closes the "tested on one backend, used on the other" gap: the pre-#534
    /// helpers only ever ran here (the `test-anchor` anchor and the unregistered
    /// self-scrubber both survived only because MemoryBackend hex-decodes
    /// nothing and enforces no FK).
    #[tokio::test]
    async fn role_conferral_helpers_work_on_memory_534() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_role_conferral(&backend, "mem534")
            .await;
    }

    /// v21.15.0 (CIRISPersist#536) — the trust-root fixture parity body on
    /// MemoryBackend (the same one sqlite + postgres run). establish_trust_root
    /// stands up all four legs (incl. the reserved heartbeat) + the
    /// scope edge, and the capability walk roots the subject's infra:serve.
    #[tokio::test]
    async fn trust_root_helper_works_on_memory_536() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_trust_root(&backend, "mem536").await;
    }

    /// **CIRISPersist#557 — the root is a THRESHOLD, not a seat.** The family
    /// trust-root parity body: a 1-of-3 charter REFUSED naming its shortfall, a
    /// 2-of-3 charter + grant + node edge rooting the subject's `infra:serve` to
    /// the ACCORD, the A1-compromise scenario (one seat cannot re-root, re-grant
    /// or buy a quorum), the family halt latch gating the family root, and the
    /// threshold re-derived from THIS node's roster rather than the carried
    /// policy string.
    #[tokio::test]
    async fn family_trust_root_works_on_memory_557() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_family_trust_root(
            &backend, "mem557",
        )
        .await
        .expect("557 family trust root exercise");
    }

    /// **CIRISPersist#561 — transport-hop eligibility.** The A/B/C/D rule, its
    /// authoritative TTL, the anti-inflation bound and the withdrawal contract,
    /// on MemoryBackend.
    #[tokio::test]
    async fn transit_eligibility_works_on_memory_561() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_transit_eligibility(
            &backend, "mem561",
        )
        .await
        .expect("561 transit eligibility exercise");
        crate::federation::operational::test_support::exercise_transit_eligibility_family_root(
            &backend, "mem561f",
        )
        .await
        .expect("561 family-root transit eligibility exercise");
    }

    /// **CIRISPersist#547 — a mutated row must be able to serve the Key ref it
    /// advertises.** Memory has no `adopt_scrub_upgrade` (that leg skips), but it
    /// DOES carry the index and it DOES have `set_consent_role` /
    /// `attach_key_pqc_signature` / `adopt_genesis_reanchor` — every one of which
    /// moved the row without moving the index before this cut.
    #[tokio::test]
    async fn key_wire_index_follows_every_mutator_memory_547() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_key_wire_index_follows_every_mutator(
            &backend, "mem547",
        )
        .await
        .expect("547 wire-index-follows-mutators exercise");
    }

    /// CIRISPersist#548 — ceremony-plane conferral (the baked-seed shape) on memory.
    #[tokio::test]
    async fn ceremony_plane_capability_walk_memory_548() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_ceremony_plane_capability_walk(
            &backend, "mem548",
        )
        .await
        .expect("548 exercise");
    }

    /// v21.16.0 (CIRISPersist#536 follow-up) — the REAL engine-backed user path
    /// on memory: synthetic user edge skipped, user's own signer completes leg 1.
    #[tokio::test]
    async fn trust_root_real_user_works_on_memory_536() {
        let backend = MemoryBackend::new();
        crate::federation::operational::test_support::exercise_trust_root_real_user(
            &backend, "memR536",
        )
        .await;
    }

    /// v18.3.0 (CIRISPersist#480, persist-side compat confirmation) — a
    /// `canonical,node` record that ALSO carries `roles:["infra:serve"]`
    /// still (a) passes the 2-of-3 `check_canonical_role_admission` core
    /// gate — the co-scrub is over `registration_envelope`, and `roles` is a
    /// separate column, so the added role does not perturb admission — and
    /// (b) preserves the `canonical` identity_type the genesis seed
    /// re-verify (`verify_canonical_seeded`) asserts. So when server hands us
    /// the re-blessed `SignedKeyRecord` for `canonical_seed.json`, the seed
    /// swap is a drop-in: both gates already accept it, and BOTH effective
    /// roles read true. (The seed JSON change itself waits on that
    /// accord-holder-signed record — this proves persist is ready for it.)
    #[tokio::test]
    async fn canonical_record_with_infra_serve_role_admits_and_reads_both_480() {
        use crate::federation::admission::{
            check_canonical_role_admission_over_roster_legacy,
            has_accord_conferred_role_over_roster,
        };
        use crate::federation::operational::test_support::{
            register_accord_holder, signed_canonical_record_with_roles, Identity,
        };
        use crate::federation::types::identity_type;
        let backend = MemoryBackend::new();
        let holders = [
            Identity::new("h0-480"),
            Identity::new("h1-480"),
            Identity::new("h2-480"),
        ];
        for h in &holders {
            register_accord_holder(&backend, h).await.unwrap();
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();

        // canonical,node + infra:serve, genuinely 2-of-3 co-scrubbed.
        let rec = signed_canonical_record_with_roles(
            "ciris-canonical-test-480",
            "canonical,node",
            vec!["infra:serve".to_owned()],
            serde_json::json!({ "key_id": "ciris-canonical-test-480" }),
            &[&holders[0], &holders[1]],
        );

        // (a) the canonical admission gate accepts the added role.
        check_canonical_role_admission_over_roster_legacy(&backend, &rec, &roster)
            .await
            .expect("(480a) canonical admission accepts a record carrying infra:serve");

        // (b) the seed re-verify invariant: canonical role preserved.
        assert!(
            identity_type::set_contains(&rec.identity_type, identity_type::CANONICAL),
            "(480b) verify_canonical_seeded's `canonical` invariant holds"
        );

        // Store + read both effective roles (put_public_key here would fire
        // the PRODUCTION-roster canonical gate, so seed the row directly via
        // the state — the read path is what #480 cares about).
        {
            let mut st = backend.state.lock().expect("lock");
            let mut stored = rec.clone();
            stored.persist_row_hash =
                crate::federation::types::compute_persist_row_hash(&stored).unwrap();
            st.federation_keys.insert(stored.key_id.clone(), stored);
        }
        assert!(
            has_accord_conferred_role_over_roster(
                &backend,
                "ciris-canonical-test-480",
                identity_type::CANONICAL,
                &roster
            )
            .await
            .unwrap(),
            "(480) canonical role reads effective"
        );
        assert!(
            has_accord_conferred_role_over_roster(
                &backend,
                "ciris-canonical-test-480",
                "infra:serve",
                &roster
            )
            .await
            .unwrap(),
            "(480) infra:serve role ALSO reads effective — the trace-serve gate opens"
        );
    }

    /// Build a root CHARTER: self-loop `delegates_to(root → root)` carrying
    /// `scope` + the v19.0.0 (#488) pre-rotation commitment (over a
    /// deterministic test successor set) the charter admission gate requires.
    fn fix_charter(id: &str, root: &str, scope: serde_json::Value) -> Attestation {
        let successors = vec![format!("{root}-succ-a"), format!("{root}-succ-b")];
        let commitment =
            crate::federation::trust_root::pre_rotation_commitment(&successors).unwrap();
        let mut d = fix_attestation(id, root, root, root);
        d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut d);
        d.attestation_envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": scope,
            "pre_rotation_commitment": commitment,
        });
        resign_fix(&mut d);
        d
    }

    #[tokio::test]
    async fn memory_withdraws_admission_rules_2_3_and_refusal() {
        let backend = MemoryBackend::new();
        for k in ["prod", "s1", "s2", "proxy", "canon", "rando"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // Target T: producer `prod`, subjects {s1, s2, canon}.
        let mut t = fix_attestation("t-1", "prod", "prod", "prod");
        t.subject_key_ids = vec!["s1".into(), "s2".into(), "canon".into()];
        crate::federation::tier_ingest::test_support::reseal(&mut t);
        backend
            .put_attestation(SignedAttestation { attestation: t })
            .await
            .unwrap();

        // Rule 2 + §8.1.11.2 — only s1 revokes; admitted under rule 2.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("w-s1", "s1", "t-1"),
            })
            .await
            .unwrap();
        let got = backend.get_attestation("w-s1").await.unwrap().unwrap();
        assert_eq!(got.withdraws_admission_rule, Some(2));

        // Rule 3 — proxy holds consent_revocation delegation to `canon`.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-1",
                    "proxy",
                    "canon",
                    serde_json::json!(["share", "consent_revocation"]),
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("w-proxy", "proxy", "t-1"),
            })
            .await
            .unwrap();
        let got = backend.get_attestation("w-proxy").await.unwrap().unwrap();
        assert_eq!(got.withdraws_admission_rule, Some(3));

        // Refusal — `rando` is neither producer, subject, nor delegate.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_withdraws("w-bad", "rando", "t-1"),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_withdraws_not_admitted");
        assert!(backend.get_attestation("w-bad").await.unwrap().is_none());
    }

    // ── v8.7.1 (CIRISPersist#233, CEG RC24/RC25/RC26 §11.10/§11.11/
    // §5.6.8.10) — FULL §11.10 moderation enforcement on the report→
    // `scores` path (review / moderation dimensions), memory-backend
    // (3-backend parity with sqlite + postgres). Replaces the v8.7.0
    // on_behalf_of model. Exercises the full matrix: (a) as-self subject,
    // (b1) subject-delegated chain, (b2) named-moderator, (c) no authority,
    // (c2) nothing → REJECT (the bypass-closed guard), (d) scope isolation,
    // (e) depth>5, (f) ⊆-parent attenuation violation, (g) deputization
    // without sub_delegation, (h) withdraws on mid-chain edge, (i)
    // non-steward-bound root.

    /// A `user`-role key (steward-bound by clause (1) of `is_steward_bound`).
    fn fix_user_key(key_id: &str) -> KeyRecord {
        let mut k = fix_key(key_id, "primitive", key_id);
        k.identity_type = crate::federation::types::identity_type::USER.into();
        k
    }

    /// Build a memory-backend `scores` report on `dimension`, signed by
    /// `signer`, declaring the target's `subject_key_ids` + `community_id`.
    fn fix_scores_report(
        id: &str,
        signer: &str,
        dimension: &str,
        subject_key_ids: &[&str],
        community_id: Option<&str>,
    ) -> Attestation {
        let mut a = fix_attestation(id, signer, signer, signer);
        // attestation_type stays SCORES (the fix_attestation default).
        let mut env = serde_json::json!({
            "id": id,
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
        });
        if let Some(c) = community_id {
            env["community_id"] = serde_json::Value::String(c.to_owned());
        }
        a.attestation_envelope = env;
        resign_fix(&mut a); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        a.subject_key_ids = subject_key_ids.iter().map(|s| (*s).to_owned()).collect();
        crate::federation::tier_ingest::test_support::reseal(&mut a);
        a
    }

    /// A `delegates_to` edge with explicit `sub_delegation` flag.
    fn fix_delegates_to_sub(
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
        sub_delegation: bool,
    ) -> Attestation {
        let mut d = fix_delegates_to(id, granter, grantee, scope);
        d.attestation_envelope["sub_delegation"] = serde_json::Value::Bool(sub_delegation);
        resign_fix(&mut d); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        d
    }

    /// Register a community keyed by `community_id` with `founder` (a
    /// `user`-role founder) in its roster under `founder_only`.
    async fn seed_community_with_founder(
        backend: &MemoryBackend,
        community_id: &str,
        founder: &str,
    ) {
        // The community's own key must exist in federation_keys.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key(community_id, "primitive", community_id),
            })
            .await
            .unwrap();
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    community_id,
                    crate::federation::types::Community {
                        community_key_id: community_id.into(),
                        community_name: "test-community".into(),
                        members: vec![crate::federation::types::CommunityMember {
                            key_id: founder.into(),
                            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            role: Some("founder".into()),
                        }],
                        founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        consensus_protocol:
                            crate::federation::types::consensus_protocol::FOUNDER_ONLY.into(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .expect("seed community");
    }

    #[tokio::test]
    async fn memory_moderation_scores_review_full_matrix() {
        let backend = MemoryBackend::new();
        // `subject` is a user (steward-bound), the content's own subject.
        // `delegate`/`deep` are agent keys; `founder` is the community's
        // steward-bound authority; `rando`/`modkey` are unauthorized.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("founder"),
            })
            .await
            .unwrap();
        for k in ["delegate", "deep", "rando", "modkey", "agentroot"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        seed_community_with_founder(&backend, "comm-1", "founder").await;

        // (a) v21.11.0 (CIRISPersist#517, CC 4.5.5) — as-self subject → REJECT.
        // A reconsideration's REVIEW authority is `is_named_moderator` ONLY;
        // the subject naming ITSELF confers no authority (integrity of the
        // signed subject ≠ authority over the action). `subject` is not a
        // moderator of comm-1, so this is refused (was the spoof: admitted).
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-self",
                    "subject",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend.get_attestation("r-self").await.unwrap().is_none());

        // (b1) subject-delegated chain (subject → delegate) → REJECT. The
        // subject never held review authority (it is not a moderator), so it
        // cannot delegate it — the delegation row is admissible, but the
        // delegate's reconsideration is not (#517).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-rev",
                    "subject",
                    "delegate",
                    serde_json::json!(["message_io", "review"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-deleg",
                    "delegate",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend.get_attestation("r-deleg").await.unwrap().is_none());

        // (b1') founder-delegated chain (founder → fdelegate, review over
        // comm-1) → ADMIT. The LEGITIMATE delegated-moderator path: authority
        // roots at a real named moderator (founder) and flows down the
        // review-scoped delegation — proving #517 cut only the subject-self
        // seed, not genuine moderator delegation.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("fdelegate", "primitive", "fdelegate"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-frev",
                    "founder",
                    "fdelegate",
                    serde_json::json!(["message_io", "review"]),
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-fdeleg",
                    "fdelegate",
                    "reconsideration:case42:v1",
                    &[],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(b1') founder-delegated review admitted");
        assert!(backend.get_attestation("r-fdeleg").await.unwrap().is_some());

        // (b2) named-moderator: community founder (steward-bound authority)
        // → ADMIT as-self (community-moderation case #95 unblocked).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-mod",
                    "founder",
                    "reconsideration:case42:v1",
                    &[],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(b2) named-moderator (founder) admitted");
        assert!(backend.get_attestation("r-mod").await.unwrap().is_some());

        // (c) no authority (rando, claims subject target) → REJECT.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-rando",
                    "rando",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend.get_attestation("r-rando").await.unwrap().is_none());

        // (c2) NOTHING — no subjects, no community → REJECT. THE
        // bypass-closed regression guard: absence is never an admit.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-nothing",
                    "rando",
                    "reconsideration:case42:v1",
                    &[],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(
            backend
                .get_attestation("r-nothing")
                .await
                .unwrap()
                .is_none(),
            "(c2) absent principal must REJECT, not admit"
        );

        // (d) scope isolation — a consent_revocation-only delegation from
        // the subject MUST NOT drive a `review`.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-wrongscope",
                    "subject",
                    "modkey",
                    serde_json::json!(["consent_revocation"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-wrongscope",
                    "modkey",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
        assert!(backend
            .get_attestation("r-wrongscope")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn memory_moderation_scores_moderation_dimension_uses_moderate_scope() {
        // A `moderation:*` scores dimension is gated by the `moderate`
        // scope; a `review`-scoped delegation does NOT satisfy it.
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("founder"),
            })
            .await
            .unwrap();
        seed_community_with_founder(&backend, "comm-1", "founder").await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("delegate", "primitive", "delegate"),
            })
            .await
            .unwrap();
        // `review`-scoped delegation → cannot drive a `moderation:*` report.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-rev2",
                    "founder",
                    "delegate",
                    serde_json::json!(["review"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "m-wrongscope",
                    "delegate",
                    "moderation:rogue_action:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");

        // `moderate`-scoped delegation → ADMIT.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "d-mod",
                    "founder",
                    "delegate",
                    serde_json::json!(["moderate"]),
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "m-ok",
                    "delegate",
                    "moderation:rogue_action:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("moderate-scoped delegate admitted");
    }

    #[tokio::test]
    async fn memory_moderation_scores_depth_cap_rejects() {
        // (e) a `review`-scoped chain deeper than the §11.10 depth cap
        // (MAX_MODERATION_DELEGATION_DEPTH = 5) is refused.
        let backend = MemoryBackend::new();
        let depth = crate::federation::admission::MAX_MODERATION_DELEGATION_DEPTH;
        // k0 (the steward-bound subject root) → k1 → ... → k(depth+1).
        let n = depth + 2;
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("k0"),
            })
            .await
            .unwrap();
        let keys: Vec<String> = (0..n).map(|i| format!("k{i}")).collect();
        for k in keys.iter().skip(1) {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // Every edge `review`-scoped + sub_delegation so only the depth
        // cap (not the deputization gate) is what rejects.
        for i in 0..(n - 1) {
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_delegates_to_sub(
                        &format!("d{i}"),
                        &keys[i],
                        &keys[i + 1],
                        serde_json::json!(["review"]),
                        true,
                    ),
                })
                .await
                .unwrap();
        }
        // The signer is the too-deep tail key; the root k0 is the subject.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "r-toodeep",
                    &keys[n - 1],
                    "reconsideration:case42:v1",
                    &["k0"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_delegated_scope_unauthorized");
    }

    #[tokio::test]
    async fn memory_moderation_scores_attenuation_and_subdelegation() {
        // (f) ⊆-parent attenuation violation → REJECT; (g) deputization
        // without sub_delegation → REJECT; (h) withdraws on a mid-chain
        // edge → downstream REJECT; (i) non-steward-bound root → REJECT (b).
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("founder"),
            })
            .await
            .unwrap();
        seed_community_with_founder(&backend, "comm-1", "founder").await;
        for k in ["mid", "leaf", "agentroot", "agdel"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }

        // (g) deputization without sub_delegation: subject → mid (review,
        // sub_delegation=false), mid → leaf (review). mid may exercise the
        // duty but MUST NOT deputize leaf → leaf REJECT.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "g-1",
                    "founder",
                    "mid",
                    serde_json::json!(["review"]),
                    false,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "g-2",
                    "mid",
                    "leaf",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "g-rep",
                    "leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(g) deputization without sub_delegation must reject downstream"
        );
        // But `mid` itself (the direct delegate) IS admitted.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "g-mid",
                    "mid",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(g) direct delegate (mid) is admitted");

        // (i) non-steward-bound root: agentroot (NOT user-role) → agdel
        // (review). agentroot reaches agdel, but is NOT steward-bound, and is
        // not in any community authority set → agdel REJECT under (b).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "i-1",
                    "agentroot",
                    "agdel",
                    serde_json::json!(["review"]),
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "i-rep",
                    "agdel",
                    "reconsideration:case42:v1",
                    &["agentroot"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(i) non-steward-bound root cannot confer a delegated duty"
        );

        // (h) withdraws on a mid-chain edge: subject → h_mid (review, sub),
        // h_mid → h_leaf (review). subject then withdraws the subject→h_mid
        // edge → h_leaf REJECT (downstream invalidated).
        for k in ["h_mid", "h_leaf"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "h-1",
                    "founder",
                    "h_mid",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "h-2",
                    "h_mid",
                    "h_leaf",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        // h_leaf admitted BEFORE the withdraws.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "h-pre",
                    "h_leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .expect("(h) chain valid before withdraws");
        // subject withdraws the subject→h_mid edge (issuer-against-recipient).
        backend
            .put_attestation(SignedAttestation {
                attestation: {
                    let mut w = fix_attestation("h-w", "founder", "h_mid", "founder");
                    w.attestation_type =
                        crate::federation::types::attestation_type::WITHDRAWS.into();
                    w.attestation_envelope =
                        serde_json::json!({"references_attestation_id": "h-1"});
                    resign_fix(&mut w); // envelope changed → re-sign (CC 5.3.2.4.3.1)
                    w
                },
            })
            .await
            .expect("founder withdraws own delegation edge");
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "h-post",
                    "h_leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    Some("comm-1"),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(h) withdraws on mid-chain edge invalidates downstream"
        );
    }

    #[tokio::test]
    async fn memory_moderation_scores_attenuation_violation_rejects() {
        // (f) focused: child edge scope-set NOT ⊆ parent → REJECT.
        let backend = MemoryBackend::new();
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_user_key("subject"),
            })
            .await
            .unwrap();
        for k in ["mid", "leaf"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // subject → mid grants {review} (sub_delegation).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "att-1",
                    "subject",
                    "mid",
                    serde_json::json!(["review"]),
                    true,
                ),
            })
            .await
            .unwrap();
        // mid → leaf grants {review, moderate} — EXPANDS beyond parent's
        // {review}; the review-scoped edge is present but the scope-set is
        // not ⊆ parent → attenuation rejects the traversal to leaf.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to_sub(
                    "att-2",
                    "mid",
                    "leaf",
                    serde_json::json!(["review", "moderate"]),
                    true,
                ),
            })
            .await
            .unwrap();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_scores_report(
                    "att-rep",
                    "leaf",
                    "reconsideration:case42:v1",
                    &["subject"],
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_delegated_scope_unauthorized",
            "(f) child scope-set must be ⊆ parent scope-set"
        );
    }

    // ── v9.0.0 (CC 3.2 / CC 3.4.7.1) — steward-binding precondition for
    // non-infrastructure community membership (memory backend; 3-backend
    // parity with sqlite + postgres). A node/agent roster member of a
    // non-infra community MUST be steward-bound; infra communities + pure
    // user/canonical participation are not over-rejected.

    /// Submit a community `community_id` (its own key seeded) with the
    /// given roster + optional `cohort_subkind` in policy_blob.
    async fn put_community_with(
        backend: &MemoryBackend,
        community_id: &str,
        members: Vec<crate::federation::types::CommunityMember>,
        cohort_subkind: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        // SecReview F2: an infra carve-out is honored only when the
        // community's own key is the `substrate_persist` authority — default
        // the comm key to authorized exactly when infra-labeled.
        let comm_authorized = cohort_subkind == Some("infrastructure");
        put_community_with_authority(
            backend,
            community_id,
            members,
            cohort_subkind,
            comm_authorized,
        )
        .await
    }

    /// As [`put_community_with`] but with explicit control over whether the
    /// community's own key carries the `substrate_persist` authority
    /// (SecReview F2 unauthorized-infra-label test).
    async fn put_community_with_authority(
        backend: &MemoryBackend,
        community_id: &str,
        members: Vec<crate::federation::types::CommunityMember>,
        cohort_subkind: Option<&str>,
        comm_authorized: bool,
    ) -> Result<(), crate::federation::Error> {
        let mut comm_key = fix_key(community_id, "primitive", community_id);
        if comm_authorized {
            comm_key.identity_type =
                crate::federation::types::identity_type::SUBSTRATE_PERSIST.into();
        }
        backend
            .put_public_key(SignedKeyRecord { record: comm_key })
            .await
            .unwrap();
        let policy_blob = cohort_subkind.map(|sk| serde_json::json!({ "cohort_subkind": sk }));
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    community_id,
                    crate::federation::types::Community {
                        community_key_id: community_id.into(),
                        community_name: "ob-test".into(),
                        members,
                        founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        consensus_protocol:
                            crate::federation::types::consensus_protocol::FOUNDER_ONLY.into(),
                        policy_blob,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
    }

    fn member(key_id: &str) -> crate::federation::types::CommunityMember {
        crate::federation::types::CommunityMember {
            key_id: key_id.into(),
            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            role: Some("member".into()),
        }
    }

    /// Register a `user`-role key, a node-only key, and an agent key.
    async fn seed_ob_keys(backend: &MemoryBackend) {
        let mut owner = fix_key("ob-owner", "owner", "ob-owner");
        owner.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: owner })
            .await
            .unwrap();
        let mut node = fix_key("ob-node", "node", "ob-node");
        node.identity_type = crate::federation::types::identity_type::NODE.into();
        backend
            .put_public_key(SignedKeyRecord { record: node })
            .await
            .unwrap();
        let mut agent = fix_key("ob-agent", "agent", "ob-agent");
        agent.identity_type = crate::federation::types::identity_type::AGENT.into();
        backend
            .put_public_key(SignedKeyRecord { record: agent })
            .await
            .unwrap();
    }

    /// An UNSTEWARDED node member of a non-infra community → REJECTED + not
    /// stored (the load-bearing CC 3.2 gate).
    #[tokio::test]
    async fn community_unstewarded_node_member_rejected() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        let err = put_community_with(&backend, "comm-ob-1", vec![member("ob-node")], None)
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::UnstewardedCommunityMember {
                ref community_key_id,
                ref member_key_id,
                member_role,
            } => {
                assert_eq!(community_key_id, "comm-ob-1");
                assert_eq!(member_key_id, "ob-node");
                assert_eq!(member_role, crate::federation::types::identity_type::NODE);
            }
            other => panic!("expected UnstewardedCommunityMember, got {other:?}"),
        }
        assert_eq!(err.kind(), "federation_unstewarded_community_member");
        // Verify-before-mutation: nothing stored.
        assert!(backend
            .lookup_community("comm-ob-1")
            .await
            .unwrap()
            .is_none());
    }

    /// An UNSTEWARDED agent member → REJECTED (role reported as `agent`).
    #[tokio::test]
    async fn community_unstewarded_agent_member_rejected() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        let err = put_community_with(&backend, "comm-ob-2", vec![member("ob-agent")], None)
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::UnstewardedCommunityMember { member_role, .. } => {
                assert_eq!(member_role, crate::federation::types::identity_type::AGENT);
            }
            other => panic!("expected UnstewardedCommunityMember, got {other:?}"),
        }
        assert!(backend
            .lookup_community("comm-ob-2")
            .await
            .unwrap()
            .is_none());
    }

    /// An STEWARD-BOUND node member (live `delegates_to(user → node, infra:*)`)
    /// → ADMITTED. The infra-only scope both stores the delegation (past
    /// the node-agency gate) and satisfies `is_steward_bound` clause (3).
    #[tokio::test]
    async fn community_steward_bound_node_member_admitted() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        // owner (user) delegates infra:* to the node → steward-binding.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "ob-d-node",
                    "ob-owner",
                    "ob-node",
                    "ob-owner",
                    &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                ),
            })
            .await
            .unwrap();
        put_community_with(&backend, "comm-ob-3", vec![member("ob-node")], None)
            .await
            .expect("steward-bound node admitted");
        assert!(backend
            .lookup_community("comm-ob-3")
            .await
            .unwrap()
            .is_some());
    }

    /// SecReview F3: a `delegates_to(user → node)` that the granter has
    /// WITHDRAWN no longer confers steward-binding. The node is admitted while
    /// the delegation is live, then a second community (same owner-withdrawn
    /// node) is REJECTED — the withdrawn edge is not "live".
    #[tokio::test]
    async fn community_steward_binding_withdrawn_delegation_not_live() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        // owner (user) delegates infra:* → node → steward-binding (live).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "ob-d-wd",
                    "ob-owner",
                    "ob-node",
                    "ob-owner",
                    &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                ),
            })
            .await
            .unwrap();
        // Live → admitted.
        put_community_with(&backend, "comm-ob-wd-live", vec![member("ob-node")], None)
            .await
            .expect("steward-bound (live delegation) node admitted");

        // owner WITHDRAWS the delegation edge (issuer-against-recipient: the
        // withdraws' attested_key_id is the recipient `ob-node`).
        backend
            .put_attestation(SignedAttestation {
                attestation: {
                    let mut w = fix_attestation("ob-d-wd-w", "ob-owner", "ob-node", "ob-owner");
                    w.attestation_type =
                        crate::federation::types::attestation_type::WITHDRAWS.into();
                    w.attestation_envelope =
                        serde_json::json!({"references_attestation_id": "ob-d-wd"});
                    resign_fix(&mut w);
                    w
                },
            })
            .await
            .expect("owner withdraws own delegation edge");

        // Withdrawn → NOT steward-bound → REJECTED.
        let err = put_community_with(&backend, "comm-ob-wd-dead", vec![member("ob-node")], None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::UnstewardedCommunityMember { .. }
        ));
        assert!(backend
            .lookup_community("comm-ob-wd-dead")
            .await
            .unwrap()
            .is_none());
    }

    /// SecReview F3: an EXPIRED `delegates_to(user → node)` (`expires_at` in
    /// the past) does NOT confer steward-binding — the unstewarded node is
    /// REJECTED.
    #[tokio::test]
    async fn community_steward_binding_expired_delegation_not_live() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        let mut d = fix_node_delegates_to(
            "ob-d-exp",
            "ob-owner",
            "ob-node",
            "ob-owner",
            &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        );
        d.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap()); // past
        backend
            .put_attestation(SignedAttestation { attestation: d })
            .await
            .unwrap();
        let err = put_community_with(&backend, "comm-ob-exp", vec![member("ob-node")], None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::UnstewardedCommunityMember { .. }
        ));
        assert!(backend
            .lookup_community("comm-ob-exp")
            .await
            .unwrap()
            .is_none());
    }

    /// An STEWARD-BOUND agent member (live `delegates_to(user → agent)`) →
    /// ADMITTED. Agent is not node-only, so the delegation needs no infra
    /// scope to store.
    #[tokio::test]
    async fn community_steward_bound_agent_member_admitted() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "ob-d-agent",
                    "ob-owner",
                    "ob-agent",
                    serde_json::json!(["share"]),
                ),
            })
            .await
            .unwrap();
        put_community_with(&backend, "comm-ob-4", vec![member("ob-agent")], None)
            .await
            .expect("steward-bound agent admitted");
        assert!(backend
            .lookup_community("comm-ob-4")
            .await
            .unwrap()
            .is_some());
    }

    /// `cohort_subkind: infrastructure` community → an UNSTEWARDED node member
    /// is ADMITTED (trust + serve needs no owner — CC 3.2 carve-out).
    #[tokio::test]
    async fn community_infrastructure_exempts_unstewarded_node() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        put_community_with(
            &backend,
            "comm-ob-infra",
            vec![member("ob-node")],
            Some("infrastructure"),
        )
        .await
        .expect("infrastructure community exempt from steward-binding");
        assert!(backend
            .lookup_community("comm-ob-infra")
            .await
            .unwrap()
            .is_some());
    }

    /// SecReview F2: an `infrastructure`-LABELED community whose own key is
    /// NOT `substrate_persist` does NOT get the carve-out — steward-binding is
    /// STILL enforced, so an UNSTEWARDED node member is REJECTED + not stored
    /// (fail-secure: a self-applied infra label can never skip the gate).
    #[tokio::test]
    async fn community_unauthorized_infra_label_still_enforces_steward_binding() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        let err = put_community_with_authority(
            &backend,
            "comm-ob-fakeinfra",
            vec![member("ob-node")],
            Some("infrastructure"),
            false, // comm key is NOT substrate_persist
        )
        .await
        .unwrap_err();
        match err {
            crate::federation::Error::UnstewardedCommunityMember {
                ref member_key_id,
                member_role,
                ..
            } => {
                assert_eq!(member_key_id, "ob-node");
                assert_eq!(member_role, crate::federation::types::identity_type::NODE);
            }
            other => panic!("expected UnstewardedCommunityMember, got {other:?}"),
        }
        assert!(backend
            .lookup_community("comm-ob-fakeinfra")
            .await
            .unwrap()
            .is_none());
    }

    /// A pure `user`-role member (and an unresolved/non-node-agent member)
    /// is NOT over-rejected — canonical/user participation is in scope only
    /// for node/agent standing.
    #[tokio::test]
    async fn community_user_member_not_over_rejected() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        put_community_with(&backend, "comm-ob-user", vec![member("ob-owner")], None)
            .await
            .expect("user member admitted (trivially steward-bound)");
        assert!(backend
            .lookup_community("comm-ob-user")
            .await
            .unwrap()
            .is_some());
    }

    /// SecReview F4: a FUTURE-DATED community membership revocation
    /// `effective_at` is REJECTED (`Error::InvalidArgument`) — community
    /// removal is immediate for forward-secrecy; a non-future `effective_at`
    /// is accepted AND bumps the DEK epoch. (memory parity.)
    #[tokio::test]
    async fn community_revocation_rejects_future_dated_effective_at() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await; // ob-owner (community key proxy) + ob-node exist
                                      // #502 E4 — sign with `ob-owner` (real deterministic hybrid keys via
                                      // `fix_key`/`seed_ob_keys`) so the new admission gate passes and the
                                      // future-dated check below is the actual thing under test.
        let rev = |effective_at: chrono::DateTime<chrono::Utc>| {
            crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                "ob-owner",
                crate::federation::CommunityMembershipRevocation {
                    community_key_id: "ob-owner".into(),
                    removed_identity_key_id: "ob-node".into(),
                    removed_at: effective_at,
                    effective_at,
                    reason: Some("left".into()),
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
        };
        // Future-dated (now + 30d) → REJECTED before any write.
        let future = chrono::Utc::now() + chrono::Duration::days(30);
        let err = backend
            .put_community_membership_revocation(rev(future))
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(_)),
            "future-dated effective_at must be rejected, got {err:?}"
        );
        // No epoch bump happened (still 0).
        assert_eq!(backend.community_dek_epoch("ob-owner"), 0);

        // effective_at == now → accepted + epoch bumps to 1.
        backend
            .put_community_membership_revocation(rev(chrono::Utc::now()))
            .await
            .expect("non-future revocation accepted");
        assert_eq!(backend.community_dek_epoch("ob-owner"), 1);
    }

    /// CC 4.4.3.2.8 / #308 — the `affiliations` cohort runs the FULL membership
    /// lifecycle (add → active-members → revoke) through the SAME community
    /// machinery as `community`, including the epoch bump (forward secrecy) on
    /// removal. Asserted via the uniform [`FederationDirectory`] cohort surface.
    #[tokio::test]
    async fn affiliations_cohort_membership_lifecycle_mirrors_community() {
        use crate::federation::cohort::{Cohort, RosterMember};
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await; // ob-owner (user), ob-node, ob-agent
                                      // A second user-role key to add to the roster.
        let mut joiner = fix_key("ob-joiner", "owner", "ob-joiner");
        joiner.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: joiner })
            .await
            .unwrap();
        // The affiliations group is a community row (shared storage), founded
        // by the user-role member ob-owner.
        let group = "aff-grp";
        put_community_with(&backend, group, vec![member("ob-owner")], None)
            .await
            .expect("affiliations group (community row) created");

        // ── add via the affiliations cohort ────────────────────────────────
        let added = backend
            .add_member(
                Cohort::Affiliations,
                group,
                RosterMember {
                    key_id: "ob-joiner".into(),
                    joined_at: chrono::Utc::now(),
                    role: Some("member".into()),
                },
            )
            .await
            .expect("affiliations add_member");
        assert!(added, "genuine add returns true");

        // active_members(affiliations) reads the shared community roster.
        let active: Vec<String> = backend
            .active_members(Cohort::Affiliations, group)
            .await
            .expect("affiliations active_members")
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(active.contains(&"ob-owner".to_string()));
        assert!(
            active.contains(&"ob-joiner".to_string()),
            "added member visible via the affiliations cohort"
        );
        // Identical to reading via the `community` cohort (shared machinery).
        let active_via_community: Vec<String> = backend
            .active_members(Cohort::Community, group)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert_eq!(
            active, active_via_community,
            "affiliations and community read the SAME roster"
        );

        // ── revoke via the affiliations cohort → epoch bump (forward secrecy) ─
        assert_eq!(backend.community_dek_epoch(group), 0, "epoch starts 0");
        backend
            .revoke_member(
                Cohort::Affiliations,
                group,
                "ob-joiner",
                crate::federation::tier_ingest::test_support::sign_revoke_spec(
                    Cohort::Affiliations,
                    group,
                    group,
                    "ob-joiner",
                    chrono::Utc::now(),
                    Some("left".into()),
                    vec![],
                ),
            )
            .await
            .expect("affiliations revoke_member");
        assert_eq!(
            backend.community_dek_epoch(group),
            1,
            "affiliations removal bumps the CommunityDek epoch (CC 4.4.3.2.2 forward secrecy)"
        );
        let active_after: Vec<String> = backend
            .active_members(Cohort::Affiliations, group)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(
            !active_after.contains(&"ob-joiner".to_string()),
            "revoked member dropped from the active affiliations roster"
        );
    }

    /// CC 4.4.3.2.8 / #308 — `affiliations` resolves to the `CommunityDek`
    /// crypto tier (the same tier as `community`), and the negative-default
    /// holds: `self`/`family` → InvisibleEncrypted, an unknown scope →
    /// Plaintext, infrastructure-subkind → Plaintext.
    #[test]
    fn affiliations_resolves_to_community_dek_tier() {
        use crate::federation::types::cohort_scope::{crypto_tier, CryptoTier, AFFILIATIONS};
        assert_eq!(
            crypto_tier(AFFILIATIONS, None),
            CryptoTier::CommunityDek,
            "affiliations → CommunityDek (CC 4.4.3.2.8)"
        );
        // Same tier as community (shared machinery).
        assert_eq!(crypto_tier("community", None), CryptoTier::CommunityDek);
        // Infrastructure carve-out → Plaintext even for affiliations.
        assert_eq!(
            crypto_tier(AFFILIATIONS, Some("infrastructure")),
            CryptoTier::Plaintext
        );
        // self/family → InvisibleEncrypted; unknown → Plaintext (negative default).
        assert_eq!(crypto_tier("self", None), CryptoTier::InvisibleEncrypted);
        assert_eq!(crypto_tier("family", None), CryptoTier::InvisibleEncrypted);
        assert_eq!(crypto_tier("federation", None), CryptoTier::Plaintext);
        assert_eq!(crypto_tier("nonsense-scope", None), CryptoTier::Plaintext);
    }

    // ── v3.1.0 (CIRISPersist#117) — peer-mutation surface ──────────

    /// Read helper for the memory backend's federation_peer_metadata.
    /// Tests only — production reads will land in a follow-up cut.
    fn peek_peer(
        backend: &MemoryBackend,
        key_id: &str,
    ) -> Option<crate::federation::PeerMetadataRow> {
        let state = backend.state.lock().expect("memory backend lock");
        state.federation_peer_metadata.get(key_id).cloned()
    }

    fn peek_key(backend: &MemoryBackend, key_id: &str) -> Option<crate::federation::KeyRecord> {
        let state = backend.state.lock().expect("memory backend lock");
        state.federation_keys.get(key_id).cloned()
    }

    #[tokio::test]
    async fn add_peer_record_creates_both_rows_atomically() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-a", "AAAA", "agent", Some("rns://abc".into()))
            .await
            .unwrap();
        let key = peek_key(&backend, "peer-a").expect("federation_keys row");
        assert_eq!(key.pubkey_ed25519_base64, "AAAA");
        assert_eq!(key.identity_type, "agent");
        let meta = peek_peer(&backend, "peer-a").expect("peer_metadata row");
        assert_eq!(meta.trust, crate::federation::TrustClass::Untrusted);
        assert_eq!(meta.transport_identity.as_deref(), Some("rns://abc"));
        assert!(meta.removed_at.is_none());
        assert!(!meta.persist_row_hash.is_empty());
    }

    #[tokio::test]
    async fn add_peer_record_duplicate_key_id_rejects() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-dup", "AAAA", "agent", None)
            .await
            .unwrap();
        let err = backend
            .add_peer_record("peer-dup", "BBBB", "agent", None)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn remove_peer_record_soft_marks_removed_at_and_hides_from_reads() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-soft", "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .remove_peer_record("peer-soft", false)
            .await
            .unwrap();
        let meta = peek_peer(&backend, "peer-soft").expect("metadata row preserved");
        assert!(meta.removed_at.is_some(), "removed_at must be set");
        // federation_keys row preserved (audit trail).
        assert!(peek_key(&backend, "peer-soft").is_some());
        // Subsequent updates against a soft-removed peer report
        // PeerNotFound (live-row gate).
        let err = backend
            .update_peer_alias("peer-soft", Some("nope".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::PeerNotFound { .. }));
    }

    #[tokio::test]
    async fn remove_peer_record_hard_with_active_attestations_rejects() {
        use crate::federation::FederationDirectory;
        use crate::federation::{SignedAttestation, SignedKeyRecord};
        let backend = MemoryBackend::new();
        // Add a peer + a counter-peer so we can build an attestation
        // between them. v9.0.0 (CC 5.3.2.4.3.1): the attestation below is
        // federation-tier, so its attester (peer-att-a) must carry REAL
        // hybrid pubkeys. Register peer-att-a via fix_key first (full
        // hybrid pubkeys), then add_peer_record with the MATCHING Ed25519
        // pubkey (the upsert-of-metadata path — pubkey matches, no
        // conflict), so the peer-metadata row exists and the key can be
        // hybrid-verified.
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("peer-att-a", "peer-att-a", "peer-att-a"),
            })
            .await
            .unwrap();
        let (peer_a_ed, _) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys("peer-att-a");
        backend
            .add_peer_record("peer-att-a", &peer_a_ed, "agent", None)
            .await
            .unwrap();
        // A second federation_keys row registered the normal way (with
        // real hybrid pubkeys so it can be an attested key).
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("peer-att-b", "peer-att-b", "peer-att-b"),
            })
            .await
            .unwrap();
        // Attestation that references peer-att-a as attesting key.
        // v9.0.0 — build via fix_attestation + resign so the mandatory
        // federation-tier ingest gate verifies it (CC 5.3.2.4.3.1).
        let att = fix_attestation(
            &uuid::Uuid::new_v4().to_string(),
            "peer-att-a",
            "peer-att-b",
            "peer-att-a",
        );
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();

        let err = backend
            .remove_peer_record("peer-att-a", true)
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::HardRemoveWithActiveAttestations {
                key_id,
                attestation_count,
            } => {
                assert_eq!(key_id, "peer-att-a");
                assert!(attestation_count >= 1);
            }
            other => panic!("expected HardRemoveWithActiveAttestations, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn remove_peer_record_hard_with_no_attestations_cascades() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-hard", "AAAA", "agent", None)
            .await
            .unwrap();
        backend.remove_peer_record("peer-hard", true).await.unwrap();
        assert!(peek_key(&backend, "peer-hard").is_none(), "key row gone");
        assert!(
            peek_peer(&backend, "peer-hard").is_none(),
            "metadata row gone via cascade"
        );
    }

    #[tokio::test]
    async fn update_peer_alias_round_trip() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-alias", "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .update_peer_alias("peer-alias", Some("home-base".into()))
            .await
            .unwrap();
        let meta = peek_peer(&backend, "peer-alias").unwrap();
        assert_eq!(meta.alias.as_deref(), Some("home-base"));
        // Clearing.
        backend.update_peer_alias("peer-alias", None).await.unwrap();
        let meta = peek_peer(&backend, "peer-alias").unwrap();
        assert!(meta.alias.is_none());
    }

    #[tokio::test]
    async fn update_peer_trust_round_trip_each_variant() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-trust", "AAAA", "agent", None)
            .await
            .unwrap();
        for variant in [
            crate::federation::TrustClass::Trusted,
            crate::federation::TrustClass::Restricted,
            crate::federation::TrustClass::Blocked,
            crate::federation::TrustClass::Untrusted,
        ] {
            backend
                .update_peer_trust("peer-trust", variant)
                .await
                .unwrap();
            let meta = peek_peer(&backend, "peer-trust").unwrap();
            assert_eq!(meta.trust, variant, "round-trip failed for {variant:?}");
        }
    }

    #[tokio::test]
    async fn update_peer_notes_round_trip() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-notes", "AAAA", "agent", None)
            .await
            .unwrap();
        // null → some → null
        let meta = peek_peer(&backend, "peer-notes").unwrap();
        assert!(meta.notes.is_none());
        backend
            .update_peer_notes("peer-notes", Some("contact ops".into()))
            .await
            .unwrap();
        let meta = peek_peer(&backend, "peer-notes").unwrap();
        assert_eq!(meta.notes.as_deref(), Some("contact ops"));
        backend.update_peer_notes("peer-notes", None).await.unwrap();
        let meta = peek_peer(&backend, "peer-notes").unwrap();
        assert!(meta.notes.is_none());
    }

    #[tokio::test]
    async fn update_peer_policy_round_trip() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        backend
            .add_peer_record("peer-policy", "AAAA", "agent", None)
            .await
            .unwrap();
        let blob = crate::federation::PeerPolicyBlob(serde_json::json!({
            "max_rate_per_min": 60,
            "tags": ["sandbox", "staging"],
        }));
        backend
            .update_peer_policy("peer-policy", blob.clone())
            .await
            .unwrap();
        let meta = peek_peer(&backend, "peer-policy").unwrap();
        assert_eq!(meta.policy_blob, Some(blob));
    }

    #[tokio::test]
    async fn update_peer_unknown_key_id_rejects() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        for outcome in [
            backend.update_peer_alias("ghost", None).await,
            backend
                .update_peer_trust("ghost", crate::federation::TrustClass::Trusted)
                .await,
            backend.update_peer_notes("ghost", None).await,
            backend
                .update_peer_policy(
                    "ghost",
                    crate::federation::PeerPolicyBlob(serde_json::json!({})),
                )
                .await,
        ] {
            match outcome.expect_err("must fail with PeerNotFound") {
                crate::federation::Error::PeerNotFound { key_id } => {
                    assert_eq!(key_id, "ghost");
                }
                other => panic!("expected PeerNotFound, got {other:?}"),
            }
        }
    }

    // ── BlackholeRules tests (v3.2.0, CIRISPersist#120) ────────────

    fn id16(byte: u8) -> Vec<u8> {
        vec![byte; 16]
    }

    #[tokio::test]
    async fn blackhole_upsert_then_list_round_trip() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        let id = id16(0xAA);
        backend
            .blackhole_upsert(&id, None, Some("noisy"))
            .await
            .unwrap();
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity_hash, id);
        assert!(rows[0].until.is_none(), "permanent rule");
        assert_eq!(rows[0].reason.as_deref(), Some("noisy"));
        assert_eq!(rows[0].hits, 0);
        assert!(
            !rows[0].persist_row_hash.is_empty(),
            "server populates row hash"
        );
    }

    #[tokio::test]
    async fn blackhole_upsert_with_until_round_trip() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        let id = id16(0xBB);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        backend
            .blackhole_upsert(&id, Some(future), Some("temp"))
            .await
            .unwrap();
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].until.is_some());
        let stored = rows[0].until.unwrap();
        // Sub-second roundtrip jitter is fine on memory; identity-cmp.
        assert_eq!(stored.timestamp_millis(), future.timestamp_millis());
    }

    #[tokio::test]
    async fn blackhole_upsert_idempotent_preserves_hits() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        let id = id16(0xCC);
        backend
            .blackhole_upsert(&id, None, Some("first"))
            .await
            .unwrap();
        for _ in 0..3 {
            backend.blackhole_record_hit(&id).await.unwrap();
        }
        let before = backend.blackhole_list().await.unwrap();
        assert_eq!(before[0].hits, 3);
        let added_at_before = before[0].added_at;

        // Re-upsert with new reason — hits + added_at preserved,
        // reason overwritten.
        backend
            .blackhole_upsert(&id, None, Some("second"))
            .await
            .unwrap();
        let after = backend.blackhole_list().await.unwrap();
        assert_eq!(after[0].hits, 3, "hits preserved across re-upsert");
        assert_eq!(after[0].reason.as_deref(), Some("second"));
        assert_eq!(
            after[0].added_at, added_at_before,
            "added_at preserved across re-upsert"
        );
    }

    #[tokio::test]
    async fn blackhole_upsert_invalid_hash_length_rejects() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        for bad in [vec![], vec![1u8; 8], vec![1u8; 15], vec![1u8; 17]] {
            let err = backend
                .blackhole_upsert(&bad, None, None)
                .await
                .expect_err("non-16 must reject");
            assert!(
                matches!(err, crate::federation::Error::InvalidArgument(_)),
                "got {err:?} for len {}",
                bad.len()
            );
        }
    }

    #[tokio::test]
    async fn blackhole_remove_unknown_silent_ok() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        backend.blackhole_remove(&id16(0xEE)).await.unwrap();
        assert!(backend.blackhole_list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn blackhole_remove_idempotent() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        let id = id16(0xFE);
        backend.blackhole_upsert(&id, None, None).await.unwrap();
        backend.blackhole_remove(&id).await.unwrap();
        backend.blackhole_remove(&id).await.unwrap(); // 2nd call also OK
        assert!(backend.blackhole_list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn blackhole_record_hit_increments() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        let id = id16(0x42);
        backend.blackhole_upsert(&id, None, None).await.unwrap();
        for _ in 0..5 {
            backend.blackhole_record_hit(&id).await.unwrap();
        }
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows[0].hits, 5);
    }

    #[tokio::test]
    async fn blackhole_record_hit_unknown_silent_ok() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        backend.blackhole_record_hit(&id16(0xAB)).await.unwrap();
        assert!(backend.blackhole_list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn blackhole_prune_expired_drops_only_expired() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        let now = chrono::Utc::now();
        let expired = id16(0x11);
        let permanent = id16(0x22);
        backend
            .blackhole_upsert(&expired, Some(now - chrono::Duration::hours(1)), None)
            .await
            .unwrap();
        backend
            .blackhole_upsert(&permanent, None, None)
            .await
            .unwrap();

        let dropped = backend.blackhole_prune_expired(now).await.unwrap();
        assert_eq!(dropped, 1);
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity_hash, permanent);
    }

    #[tokio::test]
    async fn blackhole_prune_expired_with_no_expired_returns_zero() {
        use crate::federation::BlackholeRules;
        let backend = MemoryBackend::new();
        let now = chrono::Utc::now();
        backend
            .blackhole_upsert(&id16(0x33), None, None)
            .await
            .unwrap();
        backend
            .blackhole_upsert(&id16(0x44), Some(now + chrono::Duration::hours(1)), None)
            .await
            .unwrap();
        let dropped = backend.blackhole_prune_expired(now).await.unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(backend.blackhole_list().await.unwrap().len(), 2);
    }

    // ─── v6.7.0 Lane G (CEG 1.0-RC5) — consent clauses ─────────────

    use crate::federation::hard_case::{self, HardCaseFilter};
    use crate::federation::types::{consent_record, FamilyMember};
    use crate::federation::{Family, FamilyMembershipRevocation};

    /// Bootstrap a backend with a family + the two keys, returning it.
    async fn family_backend(family_key: &str, member_key: &str) -> MemoryBackend {
        let backend = MemoryBackend::new();
        for k in [family_key, member_key] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, "registry-steward"),
                })
                .await
                .unwrap();
        }
        backend
            .put_public_key(SignedKeyRecord {
                record: fix_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_family(crate::federation::tier_ingest::test_support::sign_family(
                family_key,
                Family {
                    family_key_id: family_key.into(),
                    family_name: "Test Household".into(),
                    members: vec![FamilyMember {
                        key_id: member_key.into(),
                        joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        role: None,
                    }],
                    founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    consensus_protocol: "founder_only".into(),
                    consensus_protocol_entrenched: false,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap();
        backend
    }

    // ── Clause 1 (#161 Ask 5, CEG §7.7) — removal-path emission ────

    /// A family-membership revocation emits the §7.7
    /// `family_membership_change` hard_case with `change_kind: "removed"`,
    /// the RC5 payload (subject/cohort/effective_at), keyed on the re-key
    /// epoch, and is idempotent on a re-submit at the same effective_at.
    #[tokio::test]
    async fn family_membership_revocation_emits_removed_hard_case() {
        let backend = family_backend("fam-A", "carol").await;
        let effective: chrono::DateTime<chrono::Utc> = "2026-06-10T12:00:00Z".parse().unwrap();
        let rev = FamilyMembershipRevocation {
            family_key_id: "fam-A".into(),
            removed_identity_key_id: "carol".into(),
            removed_at: "2026-06-10T11:00:00Z".parse().unwrap(),
            effective_at: effective,
            reason: Some("left the household".into()),
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        };
        backend
            .put_family_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                    "fam-A",
                    rev.clone(),
                ),
            )
            .await
            .unwrap();

        let events = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::FAMILY_MEMBERSHIP_CHANGE.into()),
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 1, "exactly one removal event");
        let e = &events[0];
        assert_eq!(e.kind, hard_case::kind::FAMILY_MEMBERSHIP_CHANGE);
        assert_eq!(e.target_key_id.as_deref(), Some("fam-A"));
        assert_eq!(e.subject_key_id.as_deref(), Some("carol"));
        assert_eq!(e.detail["change_kind"], hard_case::change_kind::REMOVED);
        assert_eq!(e.detail["cohort_key_id"], "fam-A");
        assert_eq!(e.detail["subject_key_id"], "carol");
        assert_eq!(e.detail["effective_at"], effective.to_rfc3339());

        // Idempotent: a re-submit at the same effective_at writes no
        // duplicate (the forward-secrecy re-key keys on effective_at).
        backend
            .put_family_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                    "fam-A", rev,
                ),
            )
            .await
            .unwrap();
        let events2 = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(hard_case::kind::FAMILY_MEMBERSHIP_CHANGE.into()),
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(events2.len(), 1, "re-submit is idempotent on event_id");
    }

    // ── Clause 2 (#146 Ask 5, CEG §5.6.8.7) — consent_record ───────

    /// Build a `consent_record` `scores` attestation envelope + row.
    fn consent_record_row(
        id: &str,
        subject: &str,
        stance: &str,
        tier: &str,
        include_required: bool,
    ) -> Attestation {
        let mut env = serde_json::json!({
            "id": id,
            "subject_kind": consent_record::SUBJECT_KIND,
            "stance": stance,
            "dimension": "consent:partnership_grant:v1",
        });
        if include_required {
            env["subject_key_id"] = serde_json::json!(subject);
            env["asserted_at"] = serde_json::json!("2026-06-01T00:00:00Z");
        }
        let mut a = fix_attestation(id, subject, "registry-steward", "registry-steward");
        a.attestation_envelope = env;
        resign_fix(&mut a); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        a.tier = tier.to_string();
        // A local-tier row must be cohort_scope=self (the v4.0 read-gate);
        // federation rows keep the fixture default.
        if tier == crate::federation::types::attestation_tier::LOCAL {
            a.cohort_scope = crate::federation::types::cohort_scope::SELF.to_string();
            crate::federation::tier_ingest::test_support::reseal(&mut a);
        }
        a
    }

    async fn consent_backend() -> MemoryBackend {
        let backend = MemoryBackend::new();
        for k in ["registry-steward", "subject-key"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, "registry-steward"),
                })
                .await
                .unwrap();
        }
        backend
    }

    #[tokio::test]
    async fn consent_record_granted_federation_admits() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-1",
            "subject-key",
            consent_record::stance::GRANTED,
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("granted/federation consent_record admits");
    }

    #[tokio::test]
    async fn consent_record_missing_required_field_rejected() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-2",
            "subject-key",
            consent_record::stance::GRANTED,
            crate::federation::types::attestation_tier::FEDERATION,
            false, // omit subject_key_id / asserted_at
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(ref m) if m.contains("subject_key_id")),
            "missing required field rejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn consent_record_producer_submitted_expired_rejected() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-3",
            "subject-key",
            consent_record::stance::EXPIRED,
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(ref m) if m.contains("substrate-emitted only")),
            "producer-submitted expired rejected, got {err:?}"
        );
    }

    /// v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — a `revoked`
    /// consent_record at local tier is ACCEPTED as a **transit** write when
    /// its bound-hybrid signature verifies (the operator decision), but a
    /// crypto-INVALID one is rejected at admission (never rests unsigned).
    /// Pre-v12.6.0 this was a hard rejection of both.
    #[tokio::test]
    async fn consent_record_revoked_local_tier_transits_iff_signed() {
        let backend = consent_backend().await;
        // (1) Validly-signed revoked consent_record @ local → transit-accepted.
        let row = consent_record_row(
            "cr-4",
            "subject-key",
            consent_record::stance::REVOKED,
            crate::federation::types::attestation_tier::LOCAL,
            true,
        );
        backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("crypto-valid revoked consent_record transits the local tier (§10.1.3)");

        // (2) A crypto-INVALID one (signature corrupted) is rejected at
        // admission — accept ONLY on a valid bound-hybrid signature.
        let mut forged = consent_record_row(
            "cr-4b",
            "subject-key",
            consent_record::stance::REVOKED,
            crate::federation::types::attestation_tier::LOCAL,
            true,
        );
        forged.scrub_signature_classical = "AAAA".into(); // not a valid sig
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: forged,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::FederationTierUnverified { .. }
            ),
            "unsigned/forged revoked consent_record rejected at admission, got {err:?}"
        );
    }

    /// v12.6.0 (CIRISPersist#171, §10.1.3) — the `put_attestation(tier=local)`
    /// bypass is CLOSED for *bare* subject-side revocations too (not only the
    /// consent_record ceremony): a `consent:state:revoked` row whose writer ∈
    /// `subject_key_ids` at local tier is hybrid-verified at ingest — a valid
    /// signature transits, a forged one is rejected.
    #[tokio::test]
    async fn bare_subject_side_revocation_via_put_attestation_gated() {
        let backend = consent_backend().await;
        let mut row = fix_attestation("bare-rev", "subject-key", "registry-steward", "subject-key");
        // v31.0.0 (CIRISPersist#598) — the signed instant must equal the column.
        row.asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(row.asserted_at);
        row.attestation_envelope = serde_json::json!({
            "id": "bare-rev", "dimension": "consent:state:revoked:v1",
            "score": 1.0, "confidence": 0.9,
            crate::federation::envelope::paths::ASSERTED_AT: row.asserted_at.to_rfc3339(),
        });
        row.subject_key_ids = vec!["subject-key".into()];
        row.tier = crate::federation::types::attestation_tier::LOCAL.into();
        row.cohort_scope = crate::federation::types::cohort_scope::SELF.to_string();
        resign_fix(&mut row); // envelope changed → re-sign
        let mut forged = row.clone();
        backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("crypto-valid bare subject-side revocation transits at local tier");

        // Forged signature → rejected (no put_attestation bypass of the gate).
        forged.attestation_id = "bare-rev-forged".into();
        crate::federation::tier_ingest::test_support::reseal(&mut forged);
        forged.scrub_signature_classical = "AAAA".into();
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: forged,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::FederationTierUnverified { .. }
            ),
            "forged bare revocation rejected at put_attestation local tier, got {err:?}"
        );
    }

    #[tokio::test]
    async fn consent_record_revoked_federation_tier_admits() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-5",
            "subject-key",
            consent_record::stance::REVOKED,
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("revoked/federation consent_record admits");
    }

    #[tokio::test]
    async fn consent_record_bad_stance_rejected() {
        let backend = consent_backend().await;
        let row = consent_record_row(
            "cr-6",
            "subject-key",
            "maybe",
            crate::federation::types::attestation_tier::FEDERATION,
            true,
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(ref m) if m.contains("closed set")),
            "out-of-closed-set stance rejected, got {err:?}"
        );
    }

    // ── Clause 3 (#146 Ask 6, CEG §5.6.8.14) — canonical_binding ───

    /// A `withdraws` from K against a target whose `subject_key_ids`
    /// holds a canonical hash H is admitted under rule 2 ONLY after K has
    /// emitted an `identity:canonical_binding:{H}` self-assertion.
    #[tokio::test]
    async fn canonical_binding_widens_withdraws_rule2() {
        let backend = MemoryBackend::new();
        for k in ["registry-steward", "K", "producer"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, k, "registry-steward"),
                })
                .await
                .unwrap();
        }
        let canonical_h = "canonical:sha256:deadbeefcafe";

        // Target T: a producer `scores` naming the canonical hash H as a
        // consent subject. (subject_key_ids takes canonical-hash entries —
        // no FK.)
        let mut target = fix_attestation("T-1", "producer", "producer", "registry-steward");
        target.subject_key_ids = vec![canonical_h.to_string()];
        crate::federation::tier_ingest::test_support::reseal(&mut target);
        backend
            .put_attestation(SignedAttestation {
                attestation: target.clone(),
            })
            .await
            .unwrap();

        // Helper: a `withdraws` from K against T-1.
        let withdraws_row = |id: &str| {
            let mut w = fix_attestation(id, "K", "producer", "registry-steward");
            w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
            w.attestation_envelope = serde_json::json!({
                "id": id,
                "references_attestation_id": "T-1",
            });
            resign_fix(&mut w); // envelope changed → re-sign (CC 5.3.2.4.3.1)
            w
        };

        // Before any binding: K is neither producer nor a subject → the
        // 4-rule gate refuses (rule resolution finds nothing).
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: withdraws_row("W-pre"),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::federation::Error::WithdrawsNotAdmitted { .. }),
            "pre-binding withdraws not admitted, got {err:?}"
        );

        // K self-asserts the canonical binding K → H.
        let mut binding = fix_attestation("bind-1", "K", "K", "registry-steward");
        binding.attestation_envelope = serde_json::json!({
            "id": "bind-1",
            "dimension": format!("identity:canonical_binding:{canonical_h}"),
            "score": 1.0,
            "confidence": 1.0,
            "witness_relation": "self",
        });
        resign_fix(&mut binding); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        backend
            .put_attestation(SignedAttestation {
                attestation: binding,
            })
            .await
            .expect("canonical_binding self-assertion admits");

        // Now the same withdraws is admitted under rule 2 (binding
        // promotes H to K's direct revocation authority).
        backend
            .put_attestation(SignedAttestation {
                attestation: withdraws_row("W-post"),
            })
            .await
            .expect("post-binding withdraws admits");
        let rows = backend.list_attestations_by("K").await.unwrap();
        let w = rows
            .iter()
            .find(|r| r.attestation_id == "W-post")
            .expect("W-post stored");
        assert_eq!(
            w.withdraws_admission_rule,
            Some(2),
            "canonical_binding admits as rule 2 (direct subject authority)"
        );
    }

    // ── v9.1.0 (CC 1.13.3 / FSD §2.4, CIRISPersist#243) scope-blob store ──

    #[tokio::test]
    async fn mem_put_scope_blob_round_trip() {
        use crate::federation::GroupDekRef;
        let backend = MemoryBackend::new();
        let record_id = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let ciphertext = b"caller-pre-encrypted-symbol-bytes".to_vec();
        let tag = [0x33u8; 16];
        backend
            .put_scope_blob(
                record_id,
                0,
                nonce,
                ciphertext.clone(),
                tag,
                GroupDekRef::new("community-x".into(), 7),
            )
            .unwrap();
        let got = backend
            .get_scope_blob(record_id, 0)
            .unwrap()
            .expect("present");
        assert_eq!(got.symbol_index, 0);
        assert_eq!(got.nonce, nonce);
        assert_eq!(got.ciphertext, ciphertext);
        assert_eq!(got.tag, tag);
        assert_eq!(got.group_dek_epoch, 7);
    }

    #[tokio::test]
    async fn mem_scope_blob_n_symbols_and_idempotent_reput() {
        use crate::federation::GroupDekRef;
        let backend = MemoryBackend::new();
        let record_id = [0x44u8; 32];
        const N: u16 = 20;
        for i in 0..N {
            backend
                .put_scope_blob(
                    record_id,
                    i,
                    [i as u8; 24],
                    vec![i as u8; 8],
                    [i as u8; 16],
                    GroupDekRef::new("community-y".into(), 3),
                )
                .unwrap();
        }
        backend
            .put_scope_blob(
                record_id,
                5,
                [0xFFu8; 24],
                b"different-bytes".to_vec(),
                [0xFFu8; 16],
                GroupDekRef::new("community-y".into(), 99),
            )
            .unwrap();
        let symbols = backend.list_scope_blob_symbols(record_id).unwrap();
        assert_eq!(symbols.len(), N as usize, "PK dedup: no extra row");
        for (i, s) in symbols.iter().enumerate() {
            assert_eq!(s.symbol_index, i as u16, "ordered by symbol_index ASC");
        }
        let s5 = backend.get_scope_blob(record_id, 5).unwrap().unwrap();
        assert_eq!(s5.ciphertext, vec![5u8; 8], "first write wins on re-put");
        assert_eq!(s5.group_dek_epoch, 3);
    }

    #[tokio::test]
    async fn mem_scope_blob_read_bumps_last_accessed_at() {
        use crate::federation::GroupDekRef;
        let backend = MemoryBackend::new();
        let record_id = [0x55u8; 32];
        backend
            .put_scope_blob(
                record_id,
                0,
                [1u8; 24],
                vec![1u8; 4],
                [1u8; 16],
                GroupDekRef::new("community-z".into(), 0),
            )
            .unwrap();
        let before = {
            let state = backend.state.lock().unwrap();
            state.federation_scope_blobs[&(record_id, 0)].last_accessed_at
        };
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let _ = backend.get_scope_blob(record_id, 0).unwrap();
        let after = {
            let state = backend.state.lock().unwrap();
            state.federation_scope_blobs[&(record_id, 0)].last_accessed_at
        };
        assert!(after > before, "read must bump last_accessed_at");
    }

    #[tokio::test]
    async fn mem_scope_blob_eviction_removes_lru_first() {
        use crate::federation::GroupDekRef;
        let backend = MemoryBackend::new();
        let record_id = [0x66u8; 32];
        for i in 0..6u16 {
            backend
                .put_scope_blob(
                    record_id,
                    i,
                    [i as u8; 24],
                    vec![i as u8; 4],
                    [i as u8; 16],
                    GroupDekRef::new("community-e".into(), 1),
                )
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let _ = backend.get_scope_blob(record_id, 0).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        let _ = backend.get_scope_blob(record_id, 1).unwrap();

        let deleted = backend.evict_scope_blobs(3).unwrap();
        assert_eq!(deleted, 3);
        let survivors: Vec<u16> = backend
            .list_scope_blob_symbols(record_id)
            .unwrap()
            .into_iter()
            .map(|s| s.symbol_index)
            .collect();
        assert_eq!(survivors.len(), 3);
        assert!(survivors.contains(&0), "re-read symbol 0 survives");
        assert!(survivors.contains(&1), "re-read symbol 1 survives");
        assert!(survivors.contains(&5), "newest-admitted symbol 5 survives");
        for cold in [2u16, 3, 4] {
            assert!(
                !survivors.contains(&cold),
                "LRU symbol {cold} must be evicted"
            );
        }
    }

    #[tokio::test]
    async fn mem_scope_blob_eviction_noop_under_capacity() {
        use crate::federation::GroupDekRef;
        let backend = MemoryBackend::new();
        let record_id = [0x77u8; 32];
        for i in 0..3u16 {
            backend
                .put_scope_blob(
                    record_id,
                    i,
                    [i as u8; 24],
                    vec![i as u8; 4],
                    [i as u8; 16],
                    GroupDekRef::new("community-f".into(), 0),
                )
                .unwrap();
        }
        let deleted = backend.evict_scope_blobs(10).unwrap();
        assert_eq!(deleted, 0, "no eviction when under capacity");
        assert_eq!(backend.list_scope_blob_symbols(record_id).unwrap().len(), 3);
    }

    // ── #249 Cut B — CEG-native graph DX enumerators + add_community_member.

    /// Register `n` user-role keys `pfx-0..pfx-(n-1)` (trivially steward-bound,
    /// so a community of them passes the steward-binding gate).
    async fn seed_user_keys(backend: &MemoryBackend, pfx: &str, n: usize) -> Vec<String> {
        let mut ids = Vec::new();
        for i in 0..n {
            let id = format!("{pfx}-{i}");
            let mut k = fix_key(&id, "user", &id);
            k.identity_type = crate::federation::types::identity_type::USER.into();
            backend
                .put_public_key(SignedKeyRecord { record: k })
                .await
                .unwrap();
            ids.push(id);
        }
        ids
    }

    /// active_community_members: roster of N, revoke 1 (effective now) →
    /// N−1; the removed member is gone, the rest remain.
    #[tokio::test]
    async fn active_community_members_subtracts_effective_revocation() {
        let backend = MemoryBackend::new();
        let ids = seed_user_keys(&backend, "acm", 3).await;
        put_community_with(
            &backend,
            "acm-comm",
            ids.iter().map(|i| member(i)).collect(),
            None,
        )
        .await
        .unwrap();
        // Full roster active before any revocation.
        let all = backend.active_community_members("acm-comm").await.unwrap();
        assert_eq!(all.len(), 3);

        // Revoke acm-1 effective now → N−1.
        backend
            .put_community_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                    "acm-comm",
                    crate::federation::CommunityMembershipRevocation {
                        community_key_id: "acm-comm".into(),
                        removed_identity_key_id: "acm-1".into(),
                        removed_at: chrono::Utc::now(),
                        effective_at: chrono::Utc::now(),
                        reason: None,
                        witness_set: vec![],
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .unwrap();
        let active = backend.active_community_members("acm-comm").await.unwrap();
        let keys: std::collections::HashSet<&str> =
            active.iter().map(|m| m.key_id.as_str()).collect();
        assert_eq!(active.len(), 2, "one effective revocation drops one member");
        assert!(!keys.contains("acm-1"));
        assert!(keys.contains("acm-0") && keys.contains("acm-2"));
        // lookup_community still carries the FULL roster (revocation is the
        // composed-against append-only table, not a roster mutation).
        assert_eq!(
            backend
                .lookup_community("acm-comm")
                .await
                .unwrap()
                .unwrap()
                .members
                .len(),
            3
        );
    }

    /// active_family_members: a FUTURE-DATED revocation does NOT drop its
    /// subject (family revocations may be future-dated; the member is active
    /// until effective_at arrives). Exercises the SAME `removed_key_ids_at`
    /// fold the community reader uses (community future-dating is rejected at
    /// write time — SecReview F4 — so the future-dated path is covered here).
    #[tokio::test]
    async fn active_family_members_future_revocation_keeps_member() {
        let backend = family_backend("afm-fam", "afm-carol").await;
        // Effective revocation of a NON-member key is a no-op; here we
        // future-date a revocation of the real member and assert it stays.
        let future = chrono::Utc::now() + chrono::Duration::days(30);
        backend
            .put_family_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                    "afm-fam",
                    FamilyMembershipRevocation {
                        family_key_id: "afm-fam".into(),
                        removed_identity_key_id: "afm-carol".into(),
                        removed_at: chrono::Utc::now(),
                        effective_at: future,
                        reason: None,
                        witness_set: vec![],
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .unwrap();
        let active = backend.active_family_members("afm-fam").await.unwrap();
        assert_eq!(
            active.len(),
            1,
            "future-dated revocation leaves the member active"
        );
        assert_eq!(active[0].key_id, "afm-carol");

        // Now an effective (now) revocation DOES drop it → empty roster.
        backend
            .put_family_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                    "afm-fam",
                    FamilyMembershipRevocation {
                        family_key_id: "afm-fam".into(),
                        removed_identity_key_id: "afm-carol".into(),
                        removed_at: chrono::Utc::now(),
                        effective_at: chrono::Utc::now(),
                        reason: None,
                        witness_set: vec![],
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .unwrap();
        let active = backend.active_family_members("afm-fam").await.unwrap();
        assert!(active.is_empty(), "effective revocation drops the member");
    }

    /// add_community_member: add → appears in lookup + active reader; re-add
    /// same key → idempotent (no dup, returns false).
    #[tokio::test]
    async fn add_community_member_grows_roster_idempotent() {
        let backend = MemoryBackend::new();
        let ids = seed_user_keys(&backend, "addc", 3).await;
        put_community_with(&backend, "addc-comm", vec![member(&ids[0])], None)
            .await
            .unwrap();
        // Genuine add → true, appears in both lookup + active reader.
        assert!(backend
            .add_community_member("addc-comm", member("addc-1"))
            .await
            .unwrap());
        let active = backend.active_community_members("addc-comm").await.unwrap();
        let keys: std::collections::HashSet<&str> =
            active.iter().map(|m| m.key_id.as_str()).collect();
        assert!(keys.contains("addc-0") && keys.contains("addc-1"));
        assert!(backend
            .lookup_community("addc-comm")
            .await
            .unwrap()
            .unwrap()
            .members
            .iter()
            .any(|m| m.key_id == "addc-1"));
        // Re-add same key → idempotent no-op (false), no duplicate.
        assert!(!backend
            .add_community_member("addc-comm", member("addc-1"))
            .await
            .unwrap());
        assert_eq!(
            backend
                .lookup_community("addc-comm")
                .await
                .unwrap()
                .unwrap()
                .members
                .iter()
                .filter(|m| m.key_id == "addc-1")
                .count(),
            1,
            "no duplicate member row on re-add"
        );
        // Unknown community → InvalidArgument.
        assert!(matches!(
            backend
                .add_community_member("no-such-comm", member("addc-2"))
                .await
                .unwrap_err(),
            crate::federation::Error::UnstewardedCommunityMember { .. }
                | crate::federation::Error::InvalidArgument(_)
        ));
    }

    /// moderators_of: a community with a founder (authority root) + a
    /// `delegates_to(moderate)` chain founder → deputy → returns the full
    /// set {founder, deputy}; a non-moderator key is excluded.
    #[tokio::test]
    async fn moderators_of_enumerates_roots_and_delegates() {
        use crate::federation::admission::DELEGATION_SCOPE_MODERATE;
        let backend = MemoryBackend::new();
        // founder is a user-role key (steward-bound + authority root).
        let mut founder = fix_key("mod-founder", "user", "mod-founder");
        founder.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: founder })
            .await
            .unwrap();
        for k in ["mod-deputy", "mod-outsider", "mod-comm"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // Community whose authority root is the founder.
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    "mod-comm",
                    crate::federation::types::Community {
                        community_key_id: "mod-comm".into(),
                        community_name: "mods".into(),
                        members: vec![crate::federation::types::CommunityMember {
                            key_id: "mod-founder".into(),
                            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.into()),
                        }],
                        founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        consensus_protocol:
                            crate::federation::types::consensus_protocol::FOUNDER_ONLY.into(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .unwrap();
        // founder delegates `moderate` to deputy.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_delegates_to(
                    "mod-d",
                    "mod-founder",
                    "mod-deputy",
                    serde_json::json!([DELEGATION_SCOPE_MODERATE]),
                ),
            })
            .await
            .unwrap();
        let mods = crate::federation::admission::moderators_of(
            &backend,
            "mod-comm",
            DELEGATION_SCOPE_MODERATE,
        )
        .await
        .unwrap();
        let set: std::collections::HashSet<&str> = mods.iter().map(|s| s.as_str()).collect();
        assert!(set.contains("mod-founder"), "authority root is a moderator");
        assert!(
            set.contains("mod-deputy"),
            "duty-scoped delegate is a moderator"
        );
        assert!(!set.contains("mod-outsider"), "non-delegate excluded");
        // Consistency with the predicate: every enumerated key is a named
        // moderator; the outsider is not.
        for m in &mods {
            assert!(crate::federation::admission::is_named_moderator(
                &backend,
                m,
                "mod-comm",
                DELEGATION_SCOPE_MODERATE
            )
            .await
            .unwrap());
        }
        assert!(!crate::federation::admission::is_named_moderator(
            &backend,
            "mod-outsider",
            "mod-comm",
            DELEGATION_SCOPE_MODERATE
        )
        .await
        .unwrap());
    }

    /// #238 (CC 4.5.4 / §11.11) — the no-moderator-no-federate substrate gate,
    /// decision-table style. A `community` federates ONLY while ≥1 steward-bound
    /// authority root (a live named `moderate`-holder) exists; infrastructure
    /// communities are EXEMPT. Enforcement lives at the federation-apply
    /// chokepoint ([`check_no_moderator_federate_apply`]); the admission
    /// predicate ([`check_no_moderator_federate_admission`]) is its primitive.
    #[tokio::test]
    async fn no_moderator_federate_gate_decision_table() {
        use crate::federation::admission::{
            check_no_moderator_federate_admission, check_no_moderator_federate_admission_by_id,
            check_no_moderator_federate_apply, MEMBER_ROLE_FOUNDER,
        };
        use crate::federation::types::{consensus_protocol, identity_type};

        // Build a community `cid` founded (founder_only) by `founder` of
        // identity_type `founder_it`, optionally infra-labeled. Registers the
        // community + founder keys and STORES the record (put_community itself
        // does not gate on moderator existence — the apply path does).
        async fn seed(
            backend: &MemoryBackend,
            cid: &str,
            founder: &str,
            founder_it: &str,
            infra: bool,
        ) -> crate::federation::types::Community {
            let mut ck = fix_key(cid, "primitive", cid);
            if infra {
                // SecReview F2: the infra carve-out is honored only when the
                // community's own key is the substrate_persist authority.
                ck.identity_type = identity_type::SUBSTRATE_PERSIST.into();
            }
            backend
                .put_public_key(SignedKeyRecord { record: ck })
                .await
                .unwrap();
            let mut fk = fix_key(founder, "primitive", founder);
            fk.identity_type = founder_it.into();
            backend
                .put_public_key(SignedKeyRecord { record: fk })
                .await
                .unwrap();
            let policy_blob =
                infra.then(|| serde_json::json!({ "cohort_subkind": "infrastructure" }));
            let community = crate::federation::types::Community {
                community_key_id: cid.into(),
                community_name: "dt".into(),
                members: vec![crate::federation::types::CommunityMember {
                    key_id: founder.into(),
                    joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    role: Some(MEMBER_ROLE_FOUNDER.into()),
                }],
                founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: consensus_protocol::FOUNDER_ONLY.into(),
                policy_blob,
                persist_row_hash: String::new(),
            };
            backend
                .put_community(
                    crate::federation::tier_ingest::test_support::sign_community(
                        cid,
                        community.clone(),
                    ),
                )
                .await
                .expect("record stored (put_community is not the moderator gate)");
            community
        }

        let b = MemoryBackend::new();

        // ── admission predicate (the reusable primitive) ────────────────────
        // (1) user founder = steward-bound authority root = zero-hop named
        //     moderator → ADMIT.
        let c_ok = seed(&b, "dt-ok", "dt-user", identity_type::USER, false).await;
        check_no_moderator_federate_admission(&b, &c_ok)
            .await
            .expect("steward-bound (user) founder ⇒ has a moderator ⇒ may federate");

        // (2) primitive founder = passes the steward-binding gate (not
        //     node/agent, out of its scope) but is NOT steward-bound ⇒ NO named
        //     moderator ⇒ REJECT, fail-secure.
        let c_no = seed(&b, "dt-no", "dt-prim", identity_type::PRIMITIVE, false).await;
        let err = check_no_moderator_federate_admission(&b, &c_no)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::CommunityHasNoModerator { .. }
            ),
            "moderator-less community refused, got {err:?}"
        );
        assert_eq!(err.kind(), "federation_community_no_moderator");

        // (3) infrastructure community with a non-steward-bound founder →
        //     EXEMPT (trust + serve needs no moderator) → ADMIT.
        let c_infra = seed(&b, "dt-infra", "dt-iprim", identity_type::PRIMITIVE, true).await;
        check_no_moderator_federate_admission(&b, &c_infra)
            .await
            .expect("authorized infrastructure community is exempt from the moderator gate");

        // ── federation-apply chokepoint (points i + ii unified) ─────────────
        // A federation-tier row keyed on the moderator-less community → REJECT.
        let mut row = fix_attestation("dt-apply", "dt-prim", "dt-prim", "dt-prim");
        row.attestation_envelope = serde_json::json!({
            "id": "dt-apply", "dimension": "identity_binding:v1", "community_id": "dt-no"
        });
        let err = check_no_moderator_federate_apply(&b, &row)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::CommunityHasNoModerator { .. }
            ),
            "federation-apply step keyed on a moderator-less community is refused"
        );
        // A LOCAL-tier row keyed on it → no-op (local writes are not a
        // federation apply step).
        let mut local_row = row.clone();
        local_row.tier = crate::federation::types::attestation_tier::LOCAL.into();
        check_no_moderator_federate_apply(&b, &local_row)
            .await
            .expect("local-tier row is not a federation apply step");
        // A row keyed on the MODERATORED community → ADMIT.
        let mut live_row = row.clone();
        live_row.attestation_envelope = serde_json::json!({
            "id": "dt-apply2", "dimension": "identity_binding:v1", "community_id": "dt-ok"
        });
        check_no_moderator_federate_apply(&b, &live_row)
            .await
            .expect("moderatored community may continue to federate");
        // No community_id + unknown community_id → out of scope (Ok).
        let mut bare = row.clone();
        bare.attestation_envelope =
            serde_json::json!({ "id": "x", "dimension": "identity_binding:v1" });
        check_no_moderator_federate_apply(&b, &bare)
            .await
            .expect("no community_id ⇒ not keyed on a community ⇒ no-op");
        check_no_moderator_federate_admission_by_id(&b, "no-such")
            .await
            .expect("unknown community ⇒ out of scope ⇒ no-op");
    }

    /// #369 (CC 4.5.4 / §11.11) — BROADENED apply-gate keying: a federation
    /// apply step is keyed on `C` under ANY of the substrate's community-
    /// reference shapes, not only a literal `attestation_envelope.community_id`.
    /// Decision table over the membership-attestation shapes: row endpoints
    /// (`attested_key_id` / `attesting_key_id` resolving as a stored
    /// community — the "subject doubles as the membership target" read-gate
    /// rule), `subject_key_ids` entries, and the sibling envelope field names
    /// (`community_key_id` / `cohort_key_id`). Plus the negative half:
    /// local-tier + storage-only community ops stay untouched.
    #[tokio::test]
    async fn no_moderator_federate_gate_broadened_keying_decision_table() {
        use crate::federation::admission::{
            check_no_moderator_federate_apply, no_moderator_federate_verdict, MEMBER_ROLE_FOUNDER,
        };
        use crate::federation::types::{consensus_protocol, identity_type};

        let b = MemoryBackend::new();

        // Seed a MODERATOR-LESS community (primitive founder — passes the
        // steward-binding storage gate, but is NOT steward-bound ⇒ no
        // zero-hop moderator) and a MODERATORED one (user founder).
        async fn seed(backend: &MemoryBackend, cid: &str, founder: &str, founder_it: &str) {
            let ck = fix_key(cid, "primitive", cid);
            backend
                .put_public_key(SignedKeyRecord { record: ck })
                .await
                .unwrap();
            let mut fk = fix_key(founder, "primitive", founder);
            fk.identity_type = founder_it.into();
            backend
                .put_public_key(SignedKeyRecord { record: fk })
                .await
                .unwrap();
            backend
                .put_community(
                    crate::federation::tier_ingest::test_support::sign_community(
                        cid,
                        crate::federation::types::Community {
                            community_key_id: cid.into(),
                            community_name: "bk".into(),
                            members: vec![crate::federation::types::CommunityMember {
                                key_id: founder.into(),
                                joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                                role: Some(MEMBER_ROLE_FOUNDER.into()),
                            }],
                            founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            consensus_protocol: consensus_protocol::FOUNDER_ONLY.into(),
                            policy_blob: None,
                            persist_row_hash: String::new(),
                        },
                    ),
                )
                .await
                .expect("storage-only put_community is NOT the moderator gate");
        }
        seed(&b, "bk-no", "bk-prim", identity_type::PRIMITIVE).await;
        seed(&b, "bk-ok", "bk-user", identity_type::USER).await;

        let refused = |err: crate::federation::Error, shape: &str| {
            assert!(
                matches!(
                    err,
                    crate::federation::Error::CommunityHasNoModerator { .. }
                ),
                "{shape}: moderator-less community must refuse, got {err:?}"
            );
        };

        // (1) MEMBERSHIP shape — federation-tier row attested TO the
        //     moderator-less community (no envelope community field) → REJECT.
        let bare_env = serde_json::json!({ "id": "bk-1", "dimension": "identity_binding:v1" });
        let mut row = fix_attestation("bk-1", "bk-prim", "bk-no", "bk-prim");
        row.attestation_envelope = bare_env.clone();
        crate::federation::tier_ingest::test_support::reseal(&mut row);
        refused(
            check_no_moderator_federate_apply(&b, &row)
                .await
                .unwrap_err(),
            "attested_key_id = C",
        );
        // Same shape onto the MODERATORED community → ADMIT.
        let mut ok_row = fix_attestation("bk-2", "bk-user", "bk-ok", "bk-user");
        ok_row.attestation_envelope = bare_env.clone();
        crate::federation::tier_ingest::test_support::reseal(&mut ok_row);
        check_no_moderator_federate_apply(&b, &ok_row)
            .await
            .expect("membership-shaped row onto a moderatored community is admitted");
        // LOCAL tier onto the moderator-less community → untouched.
        let mut local = row.clone();
        local.tier = crate::federation::types::attestation_tier::LOCAL.into();
        check_no_moderator_federate_apply(&b, &local)
            .await
            .expect("local-tier membership row is not a federation apply step");

        // (2) EMITTED-BY-C shape — attesting_key_id = the community → REJECT.
        let mut by_c = fix_attestation("bk-3", "bk-no", "bk-prim", "bk-no");
        by_c.attestation_envelope = bare_env.clone();
        crate::federation::tier_ingest::test_support::reseal(&mut by_c);
        refused(
            check_no_moderator_federate_apply(&b, &by_c)
                .await
                .unwrap_err(),
            "attesting_key_id = C",
        );

        // (3) subject_key_ids shape → REJECT; non-community subjects fail-open.
        let mut subj = fix_attestation("bk-4", "bk-prim", "bk-prim", "bk-prim");
        subj.attestation_envelope = bare_env.clone();
        subj.subject_key_ids = vec!["not-a-community".into(), "bk-no".into()];
        crate::federation::tier_ingest::test_support::reseal(&mut subj);
        refused(
            check_no_moderator_federate_apply(&b, &subj)
                .await
                .unwrap_err(),
            "subject_key_ids ∋ C",
        );
        let mut subj_ok = subj.clone();
        subj_ok.subject_key_ids = vec!["not-a-community".into(), "bk-ok".into()];
        crate::federation::tier_ingest::test_support::reseal(&mut subj_ok);
        check_no_moderator_federate_apply(&b, &subj_ok)
            .await
            .expect("subject-keyed row onto a moderatored community is admitted");

        // (4) Sibling envelope field names (`community_key_id` / `cohort_key_id`)
        //     → REJECT on the moderator-less community.
        for field in ["community_key_id", "cohort_key_id"] {
            let mut env_row = fix_attestation("bk-5", "bk-prim", "bk-prim", "bk-prim");
            env_row.attestation_envelope = serde_json::json!({
                "id": "bk-5", "dimension": "identity_binding:v1", field: "bk-no"
            });
            refused(
                check_no_moderator_federate_apply(&b, &env_row)
                    .await
                    .unwrap_err(),
                field,
            );
        }

        // (5) Storage-only community ops on the moderator-less community stay
        //     untouched: the record can be re-stored (roster rewrite) and its
        //     membership revocations recorded — loss-processing + the CC
        //     4.5.13 recovery must not be blocked by the federate gate.
        seed(&b, "bk-no", "bk-prim", identity_type::PRIMITIVE).await;
        b.put_community_membership_revocation(
            crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                "bk-no",
                crate::federation::types::CommunityMembershipRevocation {
                    community_key_id: "bk-no".into(),
                    removed_identity_key_id: "bk-prim".into(),
                    removed_at: "2026-05-02T00:00:00Z".parse().unwrap(),
                    effective_at: "2026-05-02T00:00:00Z".parse().unwrap(),
                    reason: Some("storage-only membership op stays ungated".into()),
                    witness_set: Vec::new(),
                    persist_row_hash: String::new(),
                },
            ),
        )
        .await
        .expect("membership revocation on a moderator-less community is storage, not federation");

        // (6) The drivable verdict mirrors the gate decision exactly.
        let v = no_moderator_federate_verdict(&b, "bk-no").await.unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "admitted": false, "community_known": true,
                "reason": "federation_community_no_moderator"
            })
        );
        let v = no_moderator_federate_verdict(&b, "bk-ok").await.unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "admitted": true, "community_known": true })
        );
        let v = no_moderator_federate_verdict(&b, "no-such").await.unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "admitted": true, "community_known": false })
        );
    }

    /// v12.6.0 (CIRISPersist#171 / #238 / #146, §10.1.3 transit-not-rest) —
    /// the FULL consent-SLA loop through the REAL admission path (replacing the
    /// #238 test that staged the transit row artificially): a crypto-valid
    /// subject-side `consent:state:revoked` is ADMITTED as a transit local-tier
    /// write via `attestation_upsert_local`, the revocation scan sees it, the
    /// promotion-overdue `hard_case` fires at the 24 h boundary (not before), is
    /// idempotent on re-scan, and stops once promoted. Also asserts a
    /// crypto-INVALID revocation is REJECTED at admission (never transits).
    #[tokio::test]
    async fn consent_revocation_transit_admits_and_sla_fires_end_to_end() {
        use crate::federation::hard_case::{kind, HardCaseFilter};
        use crate::federation::tier_ingest::test_support::sign_envelope;
        use crate::federation::types::{attestation_tier, attestation_type, LocalAttestationInput};
        use crate::federation::FederationDirectory;
        use std::time::Duration;
        let backend = MemoryBackend::new();
        for k in ["subject-c", "target-c"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }

        // A subject-side `consent:state:revoked` envelope, hybrid-signed by the
        // subject (Ed25519 + ML-DSA-65 bound) over the CEG canonical form.
        // v31.0.0 (CIRISPersist#598) — the signed instant; the local door
        // stamps the column from it.
        let env = serde_json::json!({
            "id": "rev-c", "dimension": "consent:state:revoked:v1",
            "score": 1.0, "confidence": 0.9,
            crate::federation::envelope::paths::ASSERTED_AT:
                crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now())
                    .to_rfc3339(),
        });
        let (_hash, sig_classical, sig_pqc) = sign_envelope("subject-c", &env);

        // Admit it through the REAL local-write admission path — accepted as a
        // TRANSIT write because the bound-hybrid signature verifies (§10.1.3).
        let att_id = backend
            .attestation_upsert_local(LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: "subject-c".into(),
                attested_key_id: Some("target-c".into()),
                attestation_type: attestation_type::SCORES.into(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    env.clone(),
                )
                .unwrap(),
                subject_key_ids: vec!["subject-c".into()],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
                scrub_signature_classical: Some(sig_classical),
                scrub_signature_pqc: sig_pqc,
            })
            .await
            .expect("crypto-valid subject-side revocation transits the local tier (§10.1.3)");

        // The transit row is stored at local tier, unpromoted, carrying its
        // REAL signature (not the deferred empty sentinel) — never a durable
        // unsigned local row.
        let rows = backend.list_consent_revocations(None).await.unwrap();
        assert_eq!(rows.len(), 1, "revocation scan sees the transit row");
        let rev = &rows[0];
        assert_eq!(rev.tier, attestation_tier::LOCAL);
        assert!(rev.promoted_at.is_none());
        assert!(
            !rev.scrub_signature_classical.is_empty() && rev.scrub_signature_pqc.is_some(),
            "transit row carries a real bound-hybrid signature"
        );
        let revoked_at = rev.asserted_at;

        let window = Duration::from_secs(86_400); // 24 h

        // Just BEFORE the boundary → in flight, NOT overdue.
        let before = revoked_at + chrono::Duration::seconds(86_400 - 1);
        let r = backend.run_consent_sla_watch(before, window).await.unwrap();
        assert_eq!(r.revocations_scanned, 1);
        assert_eq!(r.promotion_overdue, 0, "within the window: not yet overdue");
        assert!(backend
            .list_hard_case_events(HardCaseFilter::default())
            .await
            .unwrap()
            .is_empty());

        // Just AFTER the boundary → overdue fires.
        let after = revoked_at + chrono::Duration::seconds(86_400 + 1);
        let r = backend.run_consent_sla_watch(after, window).await.unwrap();
        assert_eq!(r.promotion_overdue, 1, "past the window: overdue fires");
        let evs = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(kind::CONSENT_REVOCATION_PROMOTION_OVERDUE.into()),
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].target_key_id.as_deref(), Some("target-c"));
        assert_eq!(evs[0].subject_key_id.as_deref(), Some("subject-c"));

        // Re-scan is idempotent on the deterministic event_id.
        let r = backend.run_consent_sla_watch(after, window).await.unwrap();
        assert_eq!(r.promotion_overdue, 1, "condition still active");
        assert_eq!(
            backend
                .list_hard_case_events(HardCaseFilter::default())
                .await
                .unwrap()
                .len(),
            1,
            "no duplicate overdue row on re-scan"
        );

        // Once PROMOTED (tier=federation) it drops out of the fire condition —
        // its only other conformant terminal state (transit-not-rest).
        {
            let mut st = backend.state.lock().unwrap();
            for a in st.federation_attestations.iter_mut() {
                if a.attestation_id == att_id {
                    a.tier = attestation_tier::FEDERATION.into();
                    a.promoted_at = Some(after);
                }
            }
        }
        let r = backend
            .run_consent_sla_watch(after + chrono::Duration::seconds(1), window)
            .await
            .unwrap();
        assert_eq!(
            r.promotion_overdue, 0,
            "a promoted revocation is no longer overdue"
        );

        // A crypto-INVALID revocation is REJECTED at admission (never transits).
        let bad = backend
            .attestation_insert_local(LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: "subject-c".into(),
                attested_key_id: Some("target-c".into()),
                attestation_type: attestation_type::SCORES.into(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({
                        "id": "rev-bad", "dimension": "consent:state:revoked:v1",
                        "score": 1.0, "confidence": 0.9,
                    }),
                )
                .unwrap(),
                subject_key_ids: vec!["subject-c".into()],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
                scrub_signature_classical: Some("AAAA".into()), // not a valid sig
                scrub_signature_pqc: Some("AAAA".into()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                bad,
                crate::federation::Error::FederationTierUnverified { .. }
            ),
            "crypto-invalid revocation rejected at admission, got {bad:?}"
        );

        // An UNSIGNED revocation (no signature material) is likewise rejected.
        let unsigned = backend
            .attestation_insert_local(LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: "subject-c".into(),
                attested_key_id: Some("target-c".into()),
                attestation_type: attestation_type::SCORES.into(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({
                        "id": "rev-unsigned", "dimension": "consent:state:revoked:v1",
                        "score": 1.0, "confidence": 0.9,
                    }),
                )
                .unwrap(),
                subject_key_ids: vec!["subject-c".into()],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(unsigned, crate::federation::Error::InvalidArgument(ref m) if m.contains("bound-hybrid signature")),
            "unsigned revocation rejected at admission, got {unsigned:?}"
        );
    }

    /// v16 (CIRISPersist#434, CC 5.3.2.2) — the promotion-overdue READER
    /// (`list_consent_revocation_promotion_overdue`, what the PyO3
    /// `list_consent_revocation_promotion_overdue_json` dispatches onto),
    /// over the REAL local-write admission path on the memory backend: an
    /// over-SLA transit revocation is returned + flagged idempotently, a
    /// within-SLA one never appears, and promotion clears it.
    #[tokio::test]
    async fn consent_promotion_overdue_reader_memory() {
        use crate::federation::hard_case::{kind, HardCaseFilter};
        use crate::federation::tier_ingest::test_support::sign_envelope;
        use crate::federation::types::{attestation_tier, attestation_type, LocalAttestationInput};
        use crate::federation::FederationDirectory;
        use std::time::Duration;
        let backend = MemoryBackend::new();
        for k in ["subject-r", "target-r"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // A crypto-valid subject-side revocation, admitted as a TRANSIT
        // local-tier write (same real-admission fixture as the SLA loop
        // test above).
        // v31.0.0 (CIRISPersist#598) — the signed instant; the local door
        // stamps the column from it.
        let env = serde_json::json!({
            "id": "rev-r", "dimension": "consent:state:revoked:v1",
            "score": 1.0, "confidence": 0.9,
            crate::federation::envelope::paths::ASSERTED_AT:
                crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now())
                    .to_rfc3339(),
        });
        let (_hash, sig_classical, sig_pqc) = sign_envelope("subject-r", &env);
        let att_id = backend
            .attestation_upsert_local(LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: "subject-r".into(),
                attested_key_id: Some("target-r".into()),
                attestation_type: attestation_type::SCORES.into(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(env)
                    .unwrap(),
                subject_key_ids: vec!["subject-r".into()],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
                scrub_signature_classical: Some(sig_classical),
                scrub_signature_pqc: sig_pqc,
            })
            .await
            .expect("transit local-tier revocation admits");
        let revoked_at = backend.list_consent_revocations(None).await.unwrap()[0].asserted_at;
        let sla = Duration::from_secs(86_400); // 24 h

        // Within the SLA → never appears, nothing flagged.
        let before = revoked_at + chrono::Duration::seconds(86_400 - 1);
        let rows = backend
            .list_consent_revocation_promotion_overdue(before, sla)
            .await
            .unwrap();
        assert!(rows.is_empty(), "a within-SLA revocation never appears");
        assert!(backend
            .list_hard_case_events(HardCaseFilter::default())
            .await
            .unwrap()
            .is_empty());

        // Past the SLA → returned (with the promote handle + age) + flagged.
        let after = revoked_at + chrono::Duration::seconds(86_400 + 60);
        let rows = backend
            .list_consent_revocation_promotion_overdue(after, sla)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "the over-SLA revocation is overdue");
        assert_eq!(rows[0].attestation_id, att_id);
        assert_eq!(rows[0].target_key_id, "target-r");
        assert_eq!(rows[0].subject_key_id, "subject-r");
        assert_eq!(rows[0].age_seconds, 86_400 + 60);
        assert_eq!(rows[0].tier, attestation_tier::LOCAL);
        let evs = backend
            .list_hard_case_events(HardCaseFilter {
                kind: Some(kind::CONSENT_REVOCATION_PROMOTION_OVERDUE.into()),
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(evs.len(), 1, "the overdue row was flagged");

        // Re-scan: still listed, NO duplicate hard_case.
        let rows = backend
            .list_consent_revocation_promotion_overdue(after, sla)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            backend
                .list_hard_case_events(HardCaseFilter::default())
                .await
                .unwrap()
                .len(),
            1,
            "re-scan writes no duplicate hard_case"
        );

        // Promote (tier=federation) → drops out of subsequent scans.
        {
            let mut st = backend.state.lock().unwrap();
            for a in st.federation_attestations.iter_mut() {
                if a.attestation_id == att_id {
                    a.tier = attestation_tier::FEDERATION.into();
                    a.promoted_at = Some(after);
                }
            }
        }
        let rows = backend
            .list_consent_revocation_promotion_overdue(after + chrono::Duration::seconds(1), sla)
            .await
            .unwrap();
        assert!(
            rows.is_empty(),
            "a promoted revocation is no longer overdue"
        );
    }

    /// v16 (CIRISPersist#431) — the compare surface REFUSES a corpus row
    /// it cannot round-trip back to the verify-core witness shape
    /// (substrate corruption), rather than classifying over it. This is
    /// the "never compare an unverifiable witness" assertion: the F-5
    /// rule means every stored row passed the gate, so the only
    /// unverifiable row is a corrupted one — and it errors, fail-closed.
    #[tokio::test]
    async fn compare_refuses_corrupted_witness_row() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        // Simulate at-rest corruption: a row whose merkle_root column is
        // not 64 hex chars (unreachable via put_wholeness_witness — the
        // gate writes only encode_root_hex output).
        {
            let mut st = backend.state.lock().unwrap();
            st.wholeness_witnesses
                .entry("corrupt-peer".into())
                .or_default()
                .push(crate::witness::StoredWitness {
                    peer_id: "corrupt-peer".into(),
                    epoch_id: 1,
                    claim_namespaces: vec!["scores:medical".into()],
                    merkle_root_hex: "not-hex".into(), // corrupted column
                    leaf_count: 1,
                    observed_at_unix_ms: 1000,
                    witness_version: 1,
                    signature: "AA==".into(),
                    signature_ml_dsa_65: "AA==".into(),
                    pqc_key_id: "k".into(),
                });
        }
        let peers = ["corrupt-peer".to_string()];
        let err = backend
            .compare_stored_witnesses(Some(&peers))
            .await
            .expect_err("a corrupted row REFUSES comparison (never a verdict)");
        assert_eq!(err.kind(), "witness_admit_malformed_root");
        // The N4 read-back refuses identically.
        let err = backend
            .list_witness_equivocations("corrupt-peer")
            .await
            .expect_err("read-back refuses the corrupted row too");
        assert_eq!(err.kind(), "witness_admit_malformed_root");
    }

    /// steward_bindings_of: an steward-bound node (live `delegates_to(user →
    /// node, infra:*)`) → returns the binding user; an unbound node → empty.
    #[tokio::test]
    async fn steward_bindings_of_returns_user_anchors() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await; // ob-owner (user), ob-node (node), ob-agent
                                      // Unbound node → empty.
        assert!(
            crate::federation::admission::steward_bindings_of(&backend, "ob-node")
                .await
                .unwrap()
                .is_empty()
        );
        // Live delegates_to(user → node, infra:*) → steward-bound to ob-owner.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "ob-bind",
                    "ob-owner",
                    "ob-node",
                    "ob-owner",
                    &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                ),
            })
            .await
            .unwrap();
        let bindings = crate::federation::admission::steward_bindings_of(&backend, "ob-node")
            .await
            .unwrap();
        assert_eq!(bindings, vec!["ob-owner".to_string()]);
        // The user key steward-binds itself (clause 1).
        assert_eq!(
            crate::federation::admission::steward_bindings_of(&backend, "ob-owner")
                .await
                .unwrap(),
            vec!["ob-owner".to_string()]
        );
        // Consistency with the predicate.
        assert!(
            crate::federation::admission::is_steward_bound(&backend, "ob-node")
                .await
                .unwrap()
        );
    }

    /// CIRISPersist#299 — `nodes_stewarded_by` is the exact inverse of
    /// `steward_bindings_of` (memory-backend parity): pre-delegation the user
    /// owns only itself; after `delegates_to(ob-owner → ob-node)` it owns
    /// `{ob-node, ob-owner}`; a node owns nothing.
    #[tokio::test]
    async fn nodes_stewarded_by_is_inverse_of_steward_bindings() {
        use crate::federation::admission::nodes_stewarded_by;
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await; // ob-owner (user), ob-node (node), ob-agent
                                      // Pre-delegation: owner owns only itself.
        assert_eq!(
            nodes_stewarded_by(&backend, "ob-owner").await.unwrap(),
            vec!["ob-owner".to_string()]
        );
        // A node owns nothing.
        assert!(nodes_stewarded_by(&backend, "ob-node")
            .await
            .unwrap()
            .is_empty());

        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "ob-bind",
                    "ob-owner",
                    "ob-node",
                    "ob-owner",
                    &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                ),
            })
            .await
            .unwrap();

        // Post-delegation: owns ob-node + self (deduped, sorted).
        assert_eq!(
            nodes_stewarded_by(&backend, "ob-owner").await.unwrap(),
            vec!["ob-node".to_string(), "ob-owner".to_string()]
        );
    }

    // ── CIRISConstitution#23 (CC 1.13.3.3 / CC 3.2) — single-owner gate ──

    /// Build an OWNER-BINDING `delegates_to(owner → node)` carrying the CC
    /// 1.13.3.3 / CC 3.2 ownership dimension (what the single-owner gate +
    /// `owner_of` key on) with infra-only scope, re-signed for the
    /// federation-tier ingest gate. Distinct from [`fix_node_delegates_to`],
    /// which builds a plain (non-ownership) infra delegation.
    fn fix_owner_binding(id: &str, owner: &str, node: &str) -> Attestation {
        use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};
        let mut att = fix_attestation(id, owner, node, owner);
        att.attestation_type = attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "kind": "delegates_to",
            "dimension": owner_binding::DIMENSION,
            "delegation_purpose": owner_binding::PURPOSE,
            "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        });
        resign_fix(&mut att); // envelope changed → re-sign (CC 5.3.2.4.3.1)
        att
    }

    /// Register a SECOND `user`-role key — a distinct would-be owner.
    async fn seed_second_owner(backend: &MemoryBackend, key_id: &str) {
        let mut u = fix_key(key_id, key_id, key_id);
        u.identity_type = crate::federation::types::identity_type::USER.into();
        backend
            .put_public_key(SignedKeyRecord { record: u })
            .await
            .unwrap();
    }

    /// A node cannot accrue a SECOND, distinct owner: the first owner-binding
    /// admits; a second from a DIFFERENT user is rejected `NodeAlreadyOwned`
    /// and leaves no trace (verify-before-mutation). This is what keeps the
    /// `self` cohort boundary single-valued.
    #[tokio::test]
    async fn single_owner_gate_rejects_second_distinct_owner() {
        use crate::federation::admission::owner_of;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await; // ob-owner (user), ob-node (node)
        seed_second_owner(&backend, "ob-owner2").await;

        // First owner-binding admits; owner_of resolves ob-owner.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b1", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string())
        );

        // A second, DIFFERENT owner is rejected.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b2", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::NodeAlreadyOwned {
                ref node_key_id,
                ref incumbent_owner,
                ref attempted_owner,
            } => {
                assert_eq!(node_key_id, "ob-node");
                assert_eq!(incumbent_owner, "ob-owner");
                assert_eq!(attempted_owner, "ob-owner2");
            }
            other => panic!("expected NodeAlreadyOwned, got {other:?}"),
        }
        assert_eq!(err.kind(), "federation_node_already_owned");
        // The rejected binding left no trace — owner unchanged.
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string())
        );
    }

    /// v13.3.0 (CIRISPersist#378) — the owner-binding built with the **CC
    /// 2.4.1.2 canonical marker only** (`delegation_purpose: "owner_binding"`,
    /// **no `dimension`**) — the shape a raw `emit_attestation_self` `delegates_to`
    /// carries, and exactly what CIRISConformance `test_551` probes. Before the
    /// fix, the gate keyed on the internal dimension alone and this path was
    /// UNGATED (a second distinct owner was admitted — CC 3.2 violated).
    fn fix_owner_binding_cc(id: &str, owner: &str, node: &str) -> Attestation {
        use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};
        let mut att = fix_attestation(id, owner, node, owner);
        att.attestation_type = attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        // CC 2.4.1.2 marker ONLY (no `dimension`). Carries the infra scopes so
        // it clears the node-agency gate and actually reaches the single-owner
        // gate under test (the marker recognition is the thing being proven).
        att.attestation_envelope = serde_json::json!({
            "id": id,
            "kind": "delegates_to",
            "delegation_purpose": owner_binding::CC_DELEGATION_PURPOSE,
            "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        });
        resign_fix(&mut att);
        att
    }

    /// v13.3.0 (CIRISPersist#378) — the single-owner gate + `owner_of` now fire
    /// on the **CC-marker raw-emit path** (`delegation_purpose: "owner_binding"`,
    /// no dimension), not only persist's internal-dimension `steward_bind` path.
    /// A second distinct owner via the raw path is rejected; `owner_of` resolves
    /// the first. This is the exact bypass CIRISConformance `test_551` caught.
    #[tokio::test]
    async fn single_owner_gate_rejects_second_distinct_owner_via_cc_marker() {
        use crate::federation::admission::owner_of;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        seed_second_owner(&backend, "ob-owner2").await;

        // First owner-binding (CC marker, no dimension) admits; owner_of resolves.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_cc("ob-cc1", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string()),
            "owner_of must resolve the CC-marker owner-binding"
        );

        // A second, DIFFERENT owner via the same CC-marker path is REJECTED.
        let err = backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_cc("ob-cc2", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_node_already_owned",
            "second distinct owner via the CC-marker raw-emit path must be rejected, got {err:?}"
        );
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string()),
            "the rejected second binding left no trace"
        );
    }

    /// A refresh by the SAME owner (new attestation id, same granter) is
    /// idempotently admitted — re-binding your own node is not a second owner.
    #[tokio::test]
    async fn single_owner_gate_admits_same_owner_refresh() {
        use crate::federation::admission::owner_of;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b1", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b2", "ob-owner", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner".to_string())
        );
    }

    /// Ownership is transferable, not permanent: after the incumbent binding
    /// lapses (expiry → non-live), a DIFFERENT owner may bind. The gate honors
    /// the same liveness predicate as `steward_bindings_of`.
    #[tokio::test]
    async fn single_owner_gate_admits_new_owner_after_incumbent_expires() {
        use crate::federation::admission::owner_of;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        seed_second_owner(&backend, "ob-owner2").await;

        // An already-expired incumbent binding (expires_at is a row field, not
        // in the signed envelope, so the ingest signature is unaffected).
        let mut expired = fix_owner_binding("ob-b1", "ob-owner", "ob-node");
        expired.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
        backend
            .put_attestation(SignedAttestation {
                attestation: expired,
            })
            .await
            .unwrap();
        // Expired → non-live → node reads as unowned.
        assert_eq!(owner_of(&backend, "ob-node").await.unwrap(), None);

        // A different owner may now bind.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b2", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner2".to_string())
        );
    }

    /// The gate + `owner_of` key on the OWNERSHIP dimension, NOT any
    /// `delegates_to`. A plain infra delegation (act-on-behalf shape, no
    /// ownership dimension) is not an owner-binding: it neither trips the gate
    /// nor counts toward `owner_of` — even though `steward_bindings_of` (the
    /// broader relation) does count it. This is the ownership-vs-delegation
    /// distinction the single-owner invariant rests on.
    #[tokio::test]
    async fn owner_of_ignores_non_ownership_delegations() {
        use crate::federation::admission::{owner_of, steward_bindings_of};
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        seed_second_owner(&backend, "ob-owner2").await;

        // A non-ownership infra delegation (no ownership dimension).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "ob-plain",
                    "ob-owner",
                    "ob-node",
                    "ob-owner",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .unwrap();
        // Not an owner-binding → owner_of sees no owner…
        assert_eq!(owner_of(&backend, "ob-node").await.unwrap(), None);
        // …but steward_bindings_of (broader) DOES count the granter.
        assert_eq!(
            steward_bindings_of(&backend, "ob-node").await.unwrap(),
            vec!["ob-owner".to_string()]
        );
        // A real owner-binding from a DIFFERENT user still admits — the plain
        // delegation never claimed ownership, so it does not block.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding("ob-b1", "ob-owner2", "ob-node"),
            })
            .await
            .unwrap();
        assert_eq!(
            owner_of(&backend, "ob-node").await.unwrap(),
            Some("ob-owner2".to_string())
        );
    }

    /// `owner_of` on an unowned node is `None` (not an error, not a guess).
    #[tokio::test]
    async fn owner_of_unowned_node_is_none() {
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        assert_eq!(
            crate::federation::admission::owner_of(&backend, "ob-node")
                .await
                .unwrap(),
            None
        );
    }

    /// steward_binding_chain: the PATH (anchor-first), not just endpoints.
    /// clause 1 (user key) → [self]; clause 3 (delegated node) → [user, k];
    /// unbound → empty.
    #[tokio::test]
    async fn steward_binding_chain_returns_audit_path() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        seed_ob_keys(&backend).await;
        // Unbound → empty.
        assert!(
            crate::federation::admission::steward_binding_chain(&backend, "ob-node")
                .await
                .unwrap()
                .is_empty()
        );
        // Clause 1: the user key is its own anchor → [self].
        assert_eq!(
            crate::federation::admission::steward_binding_chain(&backend, "ob-owner")
                .await
                .unwrap(),
            vec!["ob-owner".to_string()]
        );
        // Clause 3: live delegates_to(user → node) → [user, node].
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_node_delegates_to(
                    "ob-bind-chain",
                    "ob-owner",
                    "ob-node",
                    "ob-owner",
                    &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            crate::federation::admission::steward_binding_chain(&backend, "ob-node")
                .await
                .unwrap(),
            vec!["ob-owner".to_string(), "ob-node".to_string()]
        );
        // Predicate consistency: a non-empty chain ⟺ steward-bound.
        let chain_nonempty =
            !crate::federation::admission::steward_binding_chain(&backend, "ob-node")
                .await
                .unwrap()
                .is_empty();
        let bound = crate::federation::admission::is_steward_bound(&backend, "ob-node")
            .await
            .unwrap();
        assert_eq!(chain_nonempty, bound);
    }

    /// reachable_under_scope: the general ⊆-attenuation, withdraws-aware,
    /// depth-capped scoped walk. A `moderate`-scoped founder → deputy →
    /// reaches under `moderate`; the same pair is NOT reachable under a
    /// DIFFERENT scope (scope-isolation); a withdrawn edge breaks the reach;
    /// zero-hop self is not a reach.
    #[tokio::test]
    async fn reachable_under_scope_scoped_attenuated_walk() {
        use crate::federation::admission::{
            reachable_under_scope, DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW,
            MAX_MODERATION_DELEGATION_DEPTH,
        };
        let backend = MemoryBackend::new();
        for k in ["rk-root", "rk-mid", "rk-leaf", "rk-other"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // root → mid (moderate, sub_delegation) → leaf (moderate). The
        // root→mid edge MUST grant `sub_delegation` for mid to further-
        // delegate past depth 1 (§11.10 deputization gate).
        let delegate = |id: &str, granter: &str, grantee: &str, sub: bool| {
            let mut d = fix_attestation(id, granter, grantee, granter);
            d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
            crate::federation::tier_ingest::test_support::reseal(&mut d);
            d.attestation_envelope = serde_json::json!({
                "references_attestation_id": id,
                "scope": [DELEGATION_SCOPE_MODERATE],
                "sub_delegation": sub,
            });
            resign_fix(&mut d);
            d
        };
        backend
            .put_attestation(SignedAttestation {
                attestation: delegate("rk-d1", "rk-root", "rk-mid", true),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: delegate("rk-d2", "rk-mid", "rk-leaf", false),
            })
            .await
            .unwrap();
        let depth = MAX_MODERATION_DELEGATION_DEPTH;
        // Reaches leaf under moderate (2 hops).
        assert!(reachable_under_scope(
            &backend,
            "rk-root",
            "rk-leaf",
            DELEGATION_SCOPE_MODERATE,
            depth
        )
        .await
        .unwrap());
        // Scope-isolation: NOT reachable under `review`.
        assert!(!reachable_under_scope(
            &backend,
            "rk-root",
            "rk-leaf",
            DELEGATION_SCOPE_REVIEW,
            depth
        )
        .await
        .unwrap());
        // Unrelated key not reachable.
        assert!(!reachable_under_scope(
            &backend,
            "rk-root",
            "rk-other",
            DELEGATION_SCOPE_MODERATE,
            depth
        )
        .await
        .unwrap());
        // Zero-hop self is not a reach (no scope-bearing edge to self).
        assert!(!reachable_under_scope(
            &backend,
            "rk-root",
            "rk-root",
            DELEGATION_SCOPE_MODERATE,
            depth
        )
        .await
        .unwrap());
        // depth=1 reaches mid but not leaf (depth cap).
        assert!(
            reachable_under_scope(&backend, "rk-root", "rk-mid", DELEGATION_SCOPE_MODERATE, 1)
                .await
                .unwrap()
        );
        assert!(!reachable_under_scope(
            &backend,
            "rk-root",
            "rk-leaf",
            DELEGATION_SCOPE_MODERATE,
            1
        )
        .await
        .unwrap());
    }

    /// v24.2.0 (CIRISPersist#564 stage 1) — the MEMORY leg of the shared
    /// `is_load_bearing` witness. The predicate composes trait methods over
    /// `&dyn FederationDirectory`, so "it works on memory too" is not a bonus
    /// — it is the claim, and the recurring lesson is that memory is the
    /// backend where an untested divergence hides (v21.11–17.1, seven times).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn load_bearing_predicate_parity_memory_564() {
        let backend = MemoryBackend::new();
        crate::federation::load_bearing::test_support::exercise_load_bearing_predicate(
            &backend,
            "memory-lb",
        )
        .await;
    }

    /// CIRISPersist#579 (CC 4.5.1.1, rc3) — the MEMORY leg of the shared
    /// "the pointer confers no subject authority" witness. rc3 removed the
    /// subject-binding reading of `references_attestation_id`; the removal is
    /// exercised through the real write path rather than asserted, and memory
    /// is the backend where an untested divergence hides.
    #[tokio::test]
    async fn pointer_confers_no_subject_authority_memory_579() {
        let backend = MemoryBackend::new();
        crate::federation::precedence::test_support::exercise_pointer_confers_no_subject_authority(
            &backend,
            "memory-579",
        )
        .await;
    }

    /// v24.3.0 (CIRISPersist#574) — the MEMORY leg of the shared reverse-quorum
    /// witness. The whole plane composes trait methods over
    /// `&dyn FederationDirectory` (no new table, no migration), so memory is
    /// not a bonus leg here — it is the backend where an untested divergence
    /// hides, seven times over v21.11–17.1.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn reverse_quorum_parity_memory_574() {
        let backend = MemoryBackend::new();
        crate::federation::reverse_quorum::test_support::exercise_reverse_quorum(
            &backend,
            "memory-rq",
        )
        .await;
    }

    /// CIRISPersist#591 — the MEMORY leg of the shared
    /// escalation-on-silence witness. Memory tolerates what sqlite and postgres
    /// reject, so this leg is where a divergence in the steward tier's
    /// duty-holder derivation would hide rather than where it would be caught —
    /// which is exactly why it runs the SAME body as the other two.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn escalation_on_silence_parity_memory_591() {
        let backend = MemoryBackend::new();
        crate::federation::reverse_quorum::test_support::exercise_escalation_on_silence(
            &backend,
            "memory-esc",
        )
        .await;
    }

    /// v25.1.0 (CIRISPersist#570 asks 2/3/5) — the MEMORY leg of the shared
    /// admin-op witness. The quarantine plane composes trait methods over
    /// `&dyn FederationDirectory` (no new table, no migration), and memory is
    /// the backend where the serve-path filter is easiest to get subtly wrong
    /// — it is the only one holding a lock across the read the filter re-enters.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn admin_ops_parity_memory_570() {
        let backend = MemoryBackend::new();
        crate::federation::quarantine::test_support::exercise_admin_ops(&backend, "memory-qa")
            .await;
    }

    /// v30.1.0 (CIRISPersist#610) — the MEMORY leg of the shared re-scope
    /// servability witness. All three backends call the SAME body.
    ///
    /// Gated like the #590 memory leg beside it: the shared body lives in
    /// `admission::r2_test_support`, which is `cfg(any(sqlite, postgres))`
    /// because its fixtures need a real signing path. The memory BACKEND needs
    /// no feature, but the shared witness does — and without this the
    /// no-feature `default` leg fails to compile.
    /// Takes the postgres serial lock even though it drives the MEMORY
    /// backend, matching the #590 memory leg beside it. The cfg mentions
    /// `feature = "postgres"` (it tracks the shared witness's own gate), and
    /// `every_postgres_test_takes_the_serial_lock` reads that as touching
    /// postgres. Opting in is a few microseconds; loosening the gate to parse
    /// `any(...)` forms would blunt it against the real case it was built for.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn rescope_keeps_row_servable_memory_610() {
        let backend = MemoryBackend::new();
        crate::federation::admission::r2_test_support::exercise_rescope_keeps_row_servable(
            &backend,
            "memory-610",
        )
        .await;
    }

    /// v30.12.0 (CIRISPersist#634) — the MEMORY leg: every wire ref a
    /// subject read returns must resolve through the content-hash fetch path.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wire_refs_for_subject_resolve_memory_634() {
        let backend = MemoryBackend::new();
        crate::federation::admission::r2_test_support::exercise_wire_refs_for_subject_resolve(
            &backend,
            "memory-634",
        )
        .await;
    }

    /// v31.0.0 (CIRISPersist#640) — the MEMORY leg (the CONTROL: memory
    /// neither rounds timestamps nor normalizes `consent_role`, so it must be
    /// green before and after the fix; a red here means the shared derivation
    /// broke, not that the skew was caught).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn nanosecond_key_wire_ref_resolves_memory_640() {
        let backend = MemoryBackend::new();
        crate::federation::admission::r2_test_support::exercise_nanosecond_key_wire_ref_resolves(
            &backend,
            "memory-640",
        )
        .await;
    }

    /// v31.0.0 (CIRISPersist#646) — the MEMORY leg of the every-kind witness.
    /// The CONTROL: memory rounds nothing, so this must be green before AND
    /// after the fix. A red here means the shared derivation broke, not that
    /// the skew was caught.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn nanosecond_wire_refs_resolve_every_kind_memory_646() {
        let backend = MemoryBackend::new();
        crate::federation::admission::r2_test_support::exercise_nanosecond_wire_refs_resolve_every_kind(
            &backend,
            "memory-646",
        )
        .await;
    }

    /// (CIRISPersist#590, CC 3.1.7 R2(b)) — the MEMORY leg of the shared
    /// namespace-registration witness. Memory tolerates what sqlite/postgres
    /// reject, which is exactly why it gets its own leg: an R2 refusal that
    /// lived in a backend-local guard rather than the shared
    /// `check_reserved_prefix_admission` chokepoint would pass on two backends
    /// and be silently absent on this one.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn namespace_family_unregistered_parity_memory_590() {
        let backend = MemoryBackend::new();
        crate::federation::admission::r2_test_support::exercise_r2b_refusal(&backend, "memory-r2")
            .await;
    }

    /// (CIRISPersist#584) — the MEMORY leg of the shared steward-binding
    /// liveness witness (the biconditional + subject-revocation liveness). All
    /// three backends drive the SAME body through the real `put_attestation`,
    /// so no backend can keep a subject-revoked `delegates_to` conferring
    /// stewardship after the others stop.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn steward_binding_liveness_parity_memory_584() {
        let backend = MemoryBackend::new();
        crate::federation::admission::steward_liveness_test_support::exercise_steward_binding_liveness(
            &backend, "mem",
        )
        .await;
    }

    /// (CIRISPersist#593) — the MEMORY leg of the shared moderation-duty walk
    /// liveness witness (the two biconditionals + subject-revocation liveness on
    /// the `moderate`/`takedown`/`review` plane).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn moderation_walk_liveness_parity_memory_593() {
        let backend = MemoryBackend::new();
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_moderation_walk_liveness(
            &backend, "mem",
        )
        .await;
    }

    /// (CIRISPersist#593) — the read cost of the new incoming-retraction
    /// clause, MEASURED against this backend's own directory-read counters, and
    /// the proof that the predicate walk still stops at the first hit.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn moderation_walk_read_cost_memory_593() {
        let backend = MemoryBackend::new();
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_moderation_walk_read_cost(
            &backend, "mem",
        )
        .await;
    }

    /// (CIRISPersist#584) — the MEMORY leg of the objection-plane blast-radius
    /// witness: the stricter fold DOES begin refusing #574 objections in a
    /// node-rostered commons whose members' bindings are subject-revoked.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn objection_plane_blast_radius_memory_584() {
        let backend = MemoryBackend::new();
        crate::federation::admission::steward_liveness_test_support::exercise_objection_plane_blast_radius(
            &backend, "mem",
        )
        .await;
    }

    /// v25.1.0 (CIRISPersist#570 ask 4) — the MEMORY leg of the shared
    /// revocation-history-bound witness. Memory has no column to round-trip
    /// through, which is exactly why it runs: the ADMISSION gate must be
    /// backend-symmetric even where the storage is not (the seven-times
    /// lesson).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn revocation_bound_parity_memory_570() {
        let backend = MemoryBackend::new();
        backend.set_node_key_id("rb-node-memory");
        crate::federation::register::bound_test_support::exercise_revocation_bound(
            &backend,
            "memory-rb",
        )
        .await;
    }

    /// v13.0.1 (#375) — the DEFAULT `FederationDirectory::apply_replicated_key_record`
    /// trait body (memory/mock backends, no scrub-upgrade plane): a new
    /// key_id is a first-seen Inserted; a differing record for an existing
    /// key_id is Refused (fail-closed, first-seen wins) and leaves the row
    /// untouched — no panic, no error propagated up the anti-entropy loop.
    #[tokio::test]
    async fn apply_replicated_key_record_default_first_seen_wins_memory() {
        use crate::federation::register::ReplicatedKeyOutcome;
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        let dir: &dyn FederationDirectory = &backend;

        // First-seen insert.
        assert_eq!(
            dir.apply_replicated_key_record(SignedKeyRecord {
                record: fix_key("node-x", "primitive", "node-x"),
            })
            .await
            .unwrap(),
            ReplicatedKeyOutcome::Inserted
        );

        // A differing record for the same key_id — Refused, original kept.
        // v22.0.0 (CIRISPersist#543): a REAL, structurally-valid 32-byte
        // Ed25519 key that merely differs. The old `"AAAA-different-pubkey"`
        // placeholder is not even base64, so with #275's
        // `validate_registration_pubkey` now running on memory it would fail
        // admission instead of reaching the first-seen-wins decision this
        // test is about — and it would never have reached it on sqlite or
        // postgres either.
        let mut differing = fix_key("node-x", "primitive", "A1");
        differing.pubkey_ed25519_base64 =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys("node-x-other").0;
        assert_eq!(
            dir.apply_replicated_key_record(SignedKeyRecord { record: differing })
                .await
                .unwrap(),
            // v24.2.0 (CIRISPersist#565) — `StoreConflict` is the only honest
            // reason this body can give: it runs no plan, so the single fact
            // it observed is that the store step found a different row. It
            // must NOT borrow one of the plan's policy names for a branch it
            // never evaluated.
            ReplicatedKeyOutcome::Refused {
                reason: crate::federation::register::KeyRefusalReason::StoreConflict
            }
        );
        let row = dir.lookup_public_key("node-x").await.unwrap().unwrap();
        assert_eq!(row.scrub_key_id, "node-x", "original self-signed row kept");
    }

    /// reachable_under_scope_with_reasons (#272): the refusal-reason
    /// companion classifies each "no" — Reachable / MissingScope /
    /// RetractedAtRoot / SignerUnreached / NoTrustRoots — and stays
    /// byte-identical to the bool walk on the Reachable case. Distinct
    /// key pairs isolate the scenarios in one backend.
    #[tokio::test]
    async fn reachable_under_scope_with_reasons_classifies_refusals() {
        use crate::federation::admission::{
            reachable_under_scope, reachable_under_scope_with_reasons, ReachabilityVerdict,
            DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW, MAX_MODERATION_DELEGATION_DEPTH,
        };
        let backend = MemoryBackend::new();
        for k in [
            "ar-root", "ar-tgt", "br-root", "br-tgt", "cr-root", "cr-mid", "cr-tgt", "dr-iso",
            "dr-tgt",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // A scope-bearing (`moderate`) delegation edge.
        let delegate = |id: &str, granter: &str, grantee: &str| {
            let mut d = fix_attestation(id, granter, grantee, granter);
            d.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
            crate::federation::tier_ingest::test_support::reseal(&mut d);
            d.attestation_envelope = serde_json::json!({
                "references_attestation_id": id,
                "scope": [DELEGATION_SCOPE_MODERATE],
                "sub_delegation": true,
            });
            resign_fix(&mut d);
            d
        };
        // A `withdraws` keyed on the recipient (the scoped walk's edge-
        // retraction model — `attested_key_id == recipient`).
        let withdraw_edge = |id: &str, granter: &str, recipient: &str| {
            let mut w = fix_attestation(id, granter, recipient, granter);
            w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
            resign_fix(&mut w);
            w
        };
        for a in [
            delegate("ar-d", "ar-root", "ar-tgt"), // Reachable / MissingScope pair
            delegate("br-d", "br-root", "br-tgt"), // RetractedAtRoot pair
            withdraw_edge("br-w", "br-root", "br-tgt"), // … retracted
            delegate("cr-d", "cr-root", "cr-mid"), // SignerUnreached: edge, but not to tgt
        ] {
            backend
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .unwrap();
        }
        let depth = MAX_MODERATION_DELEGATION_DEPTH;
        let verdict = |issuer: &'static str, tgt: &'static str, scope: &'static str| {
            let b = &backend;
            async move {
                reachable_under_scope_with_reasons(b, issuer, tgt, scope, depth)
                    .await
                    .unwrap()
            }
        };

        // Reachable — and consistent with the bool walk.
        assert_eq!(
            verdict("ar-root", "ar-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::Reachable
        );
        assert!(reachable_under_scope(
            &backend,
            "ar-root",
            "ar-tgt",
            DELEGATION_SCOPE_MODERATE,
            depth
        )
        .await
        .unwrap());
        // MissingScope — edge to target exists but does not carry `review`.
        assert_eq!(
            verdict("ar-root", "ar-tgt", DELEGATION_SCOPE_REVIEW).await,
            ReachabilityVerdict::MissingScope
        );
        // RetractedAtRoot — scope-bearing edge to target, but withdrawn.
        assert_eq!(
            verdict("br-root", "br-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::RetractedAtRoot
        );
        // SignerUnreached — issuer delegates, but no path reaches the target.
        assert_eq!(
            verdict("cr-root", "cr-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::SignerUnreached
        );
        // NoTrustRoots — issuer emitted no delegation edges at all.
        assert_eq!(
            verdict("dr-iso", "dr-tgt", DELEGATION_SCOPE_MODERATE).await,
            ReachabilityVerdict::NoTrustRoots
        );
    }

    /// delegations_to: K with 2 inbound `delegates_to` → returns both;
    /// a key with none → empty. Non-`delegates_to` inbound edges excluded.
    #[tokio::test]
    async fn delegations_to_lists_inbound_delegation_edges() {
        let backend = MemoryBackend::new();
        for k in ["dt-k", "dt-g1", "dt-g2"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "primitive", k),
                })
                .await
                .unwrap();
        }
        // No inbound delegations yet.
        assert!(backend.delegations_to("dt-k").await.unwrap().is_empty());
        // Two granters delegate to dt-k.
        for (id, g) in [("dt-d1", "dt-g1"), ("dt-d2", "dt-g2")] {
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_delegates_to(id, g, "dt-k", serde_json::json!(["share"])),
                })
                .await
                .unwrap();
        }
        // A non-delegation inbound edge (plain attestation) must NOT appear.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_attestation("dt-vouch", "dt-g1", "dt-k", "dt-g1"),
            })
            .await
            .unwrap();
        let inbound = backend.delegations_to("dt-k").await.unwrap();
        assert_eq!(inbound.len(), 2, "both delegates_to edges, vouch excluded");
        let granters: std::collections::HashSet<&str> = inbound
            .iter()
            .map(|a| a.attesting_key_id.as_str())
            .collect();
        assert!(granters.contains("dt-g1") && granters.contains("dt-g2"));
        assert!(inbound.iter().all(
            |a| a.attestation_type == crate::federation::types::attestation_type::DELEGATES_TO
        ));
    }

    /// #288 (CC 3.4.1/3.4.3/3.4.5) — reserved-prefix admission on the
    /// attestation_TYPE, keyed on the attesting key's identity_type:
    /// `accord:*`→accord_holder, `system:*`→substrate_persist,
    /// `hard_case:*`→substrate_persist, `capacity:*`→no self-emission.
    /// Reproduces the issue's three repro cases + the authorized contrast.
    #[tokio::test]
    async fn check_reserved_prefix_admission_enforces_cc_3_4_x_288() {
        use crate::federation::admission::check_reserved_prefix_admission;
        let backend = MemoryBackend::new();
        for (k, it) in [
            ("rp-agent", "agent"),
            ("rp-accord", "accord_holder"),
            ("rp-substrate", "substrate_persist"),
        ] {
            let mut rec = fix_key(k, "ref", k);
            rec.identity_type = it.to_owned();
            // v22.0.0 (CIRISPersist#543) — the memory backend now runs the
            // same `accord_holder` hardware gate sqlite/postgres do, so an
            // `accord_holder` fixture must carry real evidence. No-op for
            // every other identity_type.
            crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
                &mut rec,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
        }
        // Build a minimal row with a given type + attesting/attested keys.
        // (The gate reads only attestation_type + attesting/attested key_id.)
        let row = |attn: &str, attesting: &str, attested: &str| {
            let mut a = fix_attestation("rp-att", attesting, attested, attesting);
            a.attestation_type = attn.to_owned();
            crate::federation::tier_ingest::test_support::reseal(&mut a);
            a
        };

        // accord:* — agent REJECTED (CC 3.4.1), accord_holder OK.
        let e = check_reserved_prefix_admission(
            &backend,
            &row("accord:invoke:notify:x", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            e.kind(),
            "federation_accord_dimension_requires_accord_holder"
        );
        check_reserved_prefix_admission(
            &backend,
            &row("accord:invoke:notify:x", "rp-accord", "rp-accord"),
        )
        .await
        .expect("accord_holder may emit accord:*");

        // capacity:* — self-emission REJECTED (CC 3.4.5); non-self OK (any id).
        let e = check_reserved_prefix_admission(
            &backend,
            &row("capacity:composite", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "federation_capacity_self_emission_rejected");
        check_reserved_prefix_admission(
            &backend,
            &row("capacity:composite", "rp-agent", "rp-accord"),
        )
        .await
        .expect("non-self capacity:* is allowed");

        // system:* — agent REJECTED (CC 3.4.3), substrate_persist OK.
        let e = check_reserved_prefix_admission(
            &backend,
            &row("system:audit_chain:hash_continuity", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
        check_reserved_prefix_admission(
            &backend,
            &row(
                "system:audit_chain:hash_continuity",
                "rp-substrate",
                "rp-substrate",
            ),
        )
        .await
        .expect("substrate_persist may emit system:*");

        // hard_case:* — agent REJECTED, substrate_persist OK.
        let e = check_reserved_prefix_admission(
            &backend,
            &row("hard_case:promotion_overdue", "rp-agent", "rp-agent"),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
        check_reserved_prefix_admission(
            &backend,
            &row(
                "hard_case:promotion_overdue",
                "rp-substrate",
                "rp-substrate",
            ),
        )
        .await
        .expect("substrate_persist may emit hard_case:*");

        // Non-reserved types fast-exit OK regardless of identity_type.
        check_reserved_prefix_admission(&backend, &row("scores", "rp-agent", "rp-agent"))
            .await
            .expect("scores is not a reserved type");
        check_reserved_prefix_admission(&backend, &row("delegates_to", "rp-agent", "rp-accord"))
            .await
            .expect("delegates_to is not a reserved type");

        // #307 (CC 3.4.11) — the age_self_declared:level:* refusal lives on
        // the attestation_TYPE gate (the REAL emit path), not just the
        // dimension gate. age tokens travel as the attestation_type string.
        for at in ["age_self_declared:level:adult", "age_self_declared:level"] {
            let e = check_reserved_prefix_admission(&backend, &row(at, "rp-agent", "rp-agent"))
                .await
                .expect_err("age_self_declared:level:* must be refused on the type gate");
            assert_eq!(
                e.kind(),
                "federation_dimension_rejected",
                "{at:?} should refuse with DimensionRejected",
            );
            match e {
                crate::federation::Error::DimensionRejected { reason, .. } => assert_eq!(
                    reason,
                    crate::federation::admission::DimensionRejectionReason::SelfDeclaredLevelReserved
                        .as_str(),
                ),
                other => panic!("expected DimensionRejected, got {other:?}"),
            }
        }
        // The `{band}` self rung still admits; a witness `age_assurance:*`
        // token also fast-exits this gate (its emitter rule is identity-gated
        // and not exercised here for an unregistered attester — use a
        // registered witness-free shape that simply isn't level-reserved).
        check_reserved_prefix_admission(
            &backend,
            &row("age_self_declared:band:adult", "rp-agent", "rp-agent"),
        )
        .await
        .expect("age_self_declared:band:* is admitted (subject-signed self rung)");
    }

    /// v17.9.0 (CC#38 interim) — the envelope size cap fires FIRST at both
    /// write chokepoint families: the federation put and the local-tier
    /// funnel. One backend suffices — the check is the single-sourced
    /// `check_envelope_size_admission` at every site (unit-pinned boundary
    /// in `federation::admission::envelope_size_tests`).
    #[tokio::test]
    async fn envelope_size_cap_refuses_oversize_at_both_write_paths() {
        use crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES;
        let backend = MemoryBackend::new();
        let oversize = serde_json::json!({
            "d": "x".repeat(MAX_ATTESTATION_ENVELOPE_BYTES),
            "dimension": "test:oversize:v1",
        });

        // Federation put: refused before signature/directory work.
        let mut row = fix_attestation("cap-fed", "cap-k", "cap-k", "cap-k");
        row.attestation_envelope = oversize.clone();
        crate::federation::tier_ingest::test_support::reseal(&mut row);
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect_err("oversize federation put must refuse");
        assert_eq!(err.kind(), "federation_envelope_too_large");

        // Local-tier funnel: refused at entry (no key seeding needed —
        // the cap fires before any lookup).
        let input = crate::federation::types::LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: "cap-k".into(),
            attested_key_id: None,
            attestation_type: "scores".into(),
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(oversize)
                .unwrap(),
            subject_key_ids: Vec::new(),
            expires_at: None,
            weight: None,
            cohort_scope: "self".into(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let err = backend
            .attestation_upsert_local(input)
            .await
            .expect_err("oversize local upsert must refuse");
        assert_eq!(err.kind(), "federation_envelope_too_large");
    }

    // ── v11.5.0 (CIRISPersist#306, CC 3.2 / CC 3.3.12 / CC 1.15.6) ──────────
    //    I1 age band + user-target steward-binding gate + minor liveness.

    /// v30.10.0 (CIRISPersist#632) — the MEMORY leg of the federation
    /// duty-holder witness.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn federation_duty_holders_memory_632() {
        let backend = MemoryBackend::new();
        backend
            .seed_genesis_accord_holders(
                crate::federation::genesis::accord_holder_genesis_records(),
            )
            .await
            .expect("holders seed");
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_federation_duty_holders(
            &backend, "memory-632",
        )
        .await;
    }

    /// v30.8.0 (CIRISConstitution#87) — the MEMORY leg of the
    /// conferral-is-not-stewardship witness.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn conferral_is_not_stewardship_memory_87() {
        let backend = MemoryBackend::new();
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_conferral_is_not_stewardship(
            &backend, "memory-87",
        )
        .await;
    }

    /// v30.8.0 — the MEMORY leg of the PRE-BAKE charter rehearsal. Proves the
    /// re-genesis charter shape works before the ceremony mints it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn moderation_charter_rehearsal_memory() {
        let backend = MemoryBackend::new();
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_moderation_charter_rehearsal(
            &backend, "memory-reh",
        )
        .await;
    }

    /// v30.8.0 (CIRISPersist#628) — the MEMORY leg of the re-delegation-budget
    /// witness. All three backends drive the SAME body.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn sub_delegation_budget_parity_memory_628() {
        let backend = MemoryBackend::new();
        crate::federation::admission::moderation_walk_liveness_test_support::exercise_sub_delegation_budget(
            &backend,
            "memory-628",
        )
        .await;
    }

    /// v30.6.0 (CIRISPersist#622) — the MEMORY leg of the three-backend genesis
    /// witness. All three install the REAL baked bundle through the REAL
    /// directory; the Postgres leg is the one that was failing in production.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn genesis_seed_installs_parity_memory_622() {
        let backend = MemoryBackend::new();
        backend
            .seed_genesis_accord_holders(crate::federation::genesis::accord_holder_genesis_records())
            .await
            .expect("holders seed");
        crate::federation::genesis::exercise_genesis_seed_installs(&backend).await;
    }

    /// v30.3.0 (CIRISPersist#611) — the MEMORY leg of the shared
    /// publisher-vouch-conferral witness. All three backends call the SAME
    /// `admission::r2_test_support::exercise_publisher_vouch_conferral` body.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn publisher_vouch_conferral_parity_memory_611() {
        let backend = MemoryBackend::new();
        backend.set_node_key_id("tp-node-memory");
        crate::federation::admission::r2_test_support::exercise_publisher_vouch_conferral(
            &backend,
            "memory-611",
        )
        .await;
    }

    /// v30.3.0 (CIRISPersist#611) — **no node identity is an ERROR, not an
    /// empty chain.**
    ///
    /// The actual decision in #611. The fail-secure reflex on a read door is to
    /// return nothing, and it is wrong here: a host that forgot
    /// `set_node_key_id()` would watch legitimate vouches vanish with nothing
    /// in the result distinguishing "this content has no vouches" from "this
    /// node cannot check vouches". Those are different facts and a caller acts
    /// differently on each.
    ///
    /// One leg, not three: the code path is the shared `FederationDirectory`
    /// DEFAULT method, identical for every backend, and the conferral property
    /// itself is what carries the three-backend witness above.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    async fn publisher_vouch_without_node_identity_is_loud_611() {
        use crate::federation::FederationDirectory;
        let backend = MemoryBackend::new();
        // Deliberately NOT calling set_node_key_id.
        let err = backend
            .lookup_trusted_publisher_chain(&"a".repeat(64))
            .await
            .expect_err("a directory that cannot check vouches must say so, not return none");
        assert_eq!(
            err.kind(),
            "federation_node_identity_unset",
            "must be the typed refusal (#565: the refusal names its branch), got: {err}"
        );
        assert!(
            err.to_string().contains("set_node_key_id"),
            "the message must name what to call, or it is not actionable: {err}"
        );
    }

    /// v30.3.0 (CIRISPersist#607) — the MEMORY leg of the shared
    /// `hard_case:` third-party-conferral witness. All three backends call the
    /// SAME `admission::r2_test_support::exercise_hard_case_third_party_conferral`
    /// body through the REAL `put_attestation`; memory gets its own leg because
    /// it tolerates what sqlite and postgres reject, so a guard that drifted
    /// into a backend-local branch would pass on two backends and be silently
    /// absent here.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn hard_case_third_party_conferral_parity_memory_607() {
        let backend = MemoryBackend::new();
        backend.set_node_key_id("hc-node-memory");
        crate::federation::admission::r2_test_support::exercise_hard_case_third_party_conferral(
            &backend,
            "memory-607",
        )
        .await;
    }

    /// Register a key with a chosen `identity_type` (e.g. `user` / `witness` /
    /// `agent` / `node`).
    /// v30.2.0 (CIRISPersist#607) — seed a key AND the trust-root conferral its
    /// reserved-prefix rule now resolves.
    ///
    /// A `witness` / `lenscore_detector` claim is no longer self-sufficient: the
    /// door asks whether a root THIS NODE trusts conferred the matching scope.
    /// This helper builds the honest path — a root, this node's `trust:accepts`
    /// edge to it, and the root's `trust:confers` edge carrying `scope` — so a
    /// fixture proves the gate ADMITS a properly conferred emitter, not merely
    /// that it refuses everything.
    ///
    /// The negative case (claim present, conferral absent) is
    /// `a_self_asserted_witness_is_refused_607`.
    /// v30.2.0 (CIRISPersist#607) — **a self-asserted witness is REFUSED.**
    ///
    /// The whole of #607 in one assertion. Before this, any stranger could
    /// register with `identity_type: "witness"` and then assert an
    /// age-assurance LEVEL about a third party — the rung CC 3.4.11 reserves to
    /// a witness *precisely because a subject must not reach it*. The door
    /// membership-tested a string the stranger wrote themselves.
    ///
    /// The POSITIVE control is `put_conferred_key`, used by every other witness
    /// fixture here: same claim, same door, plus a conferral — admitted. Both
    /// halves are needed. Without the positive, "refuse everything" passes;
    /// without this, "admit everything" passes.
    #[tokio::test]
    async fn a_self_asserted_witness_is_refused_607() {
        let backend = MemoryBackend::new();
        backend.set_node_key_id("sa-node");
        // The claim, with NO conferral behind it — the #607 attack exactly.
        put_typed_key(&backend, "sa-witness", "witness").await;
        put_typed_key(&backend, "sa-subject", "user").await;

        let att = fix_age_attestation(
            "sa-1",
            "sa-witness",
            "sa-subject",
            "age_assurance:government:adult:v1",
        );
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .expect_err(
                "a self-asserted witness must NOT be able to assert an age rung about a \
                 third party — that is CIRISPersist#607",
            );
        let msg = err.to_string();
        assert!(
            msg.contains("infra:attest_assurance"),
            "the refusal must name the missing conferral so an operator knows what to obtain; \
             got: {msg}"
        );
    }

    async fn put_conferred_key(backend: &MemoryBackend, key_id: &str, it: &str, scope: &str) {
        use crate::federation::trust_root::{
            TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION, TRUST_CONFERS_DIMENSION,
        };
        let node = "n607-node";
        let root = "n607-root";
        backend.set_node_key_id(node);
        for k in [node, root] {
            put_typed_key(backend, k, "node").await;
        }
        put_typed_key(backend, key_id, it).await;
        // The root charters itself (key root), this node accepts it, and it
        // confers `scope` on the emitter.
        for (id, from, to, dim, sc) in [
            // The root charters ITSELF (key root). It must carry a
            // pre_rotation_commitment: without a pre-committed successor set,
            // root-key compromise is unrecoverable by construction.
            // The charter's job dimension is trust:CHARTER:v1 — not
            // trust:confers. A charter is a root declaring itself, which is a
            // different job from conferring on someone else.
            (
                "n607-charter",
                root,
                root,
                TRUST_CHARTER_DIMENSION,
                "infra:serve",
            ),
            (
                "n607-accept",
                node,
                root,
                TRUST_ACCEPTS_DIMENSION,
                "infra:serve",
            ),
            ("n607-confer", root, key_id, TRUST_CONFERS_DIMENSION, scope),
        ] {
            // Sign the envelope we actually ship. Building the row first and
            // overwriting the envelope afterwards invalidates the signature —
            // the row then fails hybrid verify at the door, which is the door
            // working correctly on a fixture that lied.
            // A KEY-ROOT charter must carry BOTH infra:serve AND infra:attest
            // (the RC3 AND-minimum, #488) — one alone is not a charter.
            let mut envelope = if id == "n607-charter" {
                serde_json::json!({"dimension": dim, "scope": ["infra:serve", "infra:attest"]})
            } else {
                serde_json::json!({"dimension": dim, "scope": [sc]})
            };
            if id == "n607-charter" {
                envelope["pre_rotation_commitment"] =
                    serde_json::json!(crate::federation::trust_root::pre_rotation_commitment(&[
                        "n607-root-successor".to_owned()
                    ])
                    .expect("commitment"));
            }
            let envelope = envelope;
            let (och, sc_sig, sp_sig) =
                crate::federation::tier_ingest::test_support::sign_envelope(from, &envelope);
            let mut a = fix_attestation(id, from, to, from);
            a.attestation_type =
                crate::federation::types::attestation_type::DELEGATES_TO.to_owned();
            a.attestation_envelope = envelope;
            a.original_content_hash = och;
            a.scrub_signature_classical = sc_sig;
            a.scrub_signature_pqc = sp_sig;
            a.scrub_key_id = from.to_owned();
            crate::federation::tier_ingest::test_support::reseal(&mut a);
            match backend
                .put_attestation(crate::federation::SignedAttestation { attestation: a })
                .await
            {
                Ok(()) => {}
                // Re-asserting the shared charter / accept row is expected when
                // a test confers on more than one key. A UNIQUE violation on
                // the SAME id is idempotence, not a failure — anything else
                // still fails loudly.
                Err(e) if e.to_string().contains("UNIQUE constraint failed") => {}
                Err(e) => panic!("conferral edge must admit: {e}"),
            }
        }
    }

    async fn put_typed_key(backend: &MemoryBackend, key_id: &str, it: &str) {
        let mut rec = fix_key(key_id, "ref", key_id);
        rec.identity_type = it.to_owned();
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .unwrap();
    }

    /// Build a live age attestation ABOUT `subject` (attested_key_id ==
    /// subject) from `emitter`, carrying the given age `attestation_type`
    /// token + empty envelope. Properly hybrid-signed (CC 5.3.2.4.3.1).
    fn fix_age_attestation(id: &str, emitter: &str, subject: &str, token: &str) -> Attestation {
        let mut a = fix_attestation(id, emitter, subject, emitter);
        a.attestation_type = token.to_owned();
        a.attestation_envelope = serde_json::json!({ "id": id });
        a.expires_at = None;
        resign_fix(&mut a);
        a
    }

    /// age_band resolution: witness adult OUTRANKS self minor; self minor
    /// alone → Minor; self adult alone → Unknown (ratchet ignores self-adult);
    /// witness minor → Minor; no attestation → Unknown; expired witness
    /// attestation ignored.
    #[tokio::test]
    async fn age_band_resolution_witness_outranks_self_and_ratchets() {
        use crate::federation::age::{age_band, AgeBand};
        let backend = MemoryBackend::new();
        put_conferred_key(
            &backend,
            "ab-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ab-subj", "user").await;

        // No attestation → Unknown (presumption of sovereignty).
        assert_eq!(
            age_band(&backend, "ab-subj").await.unwrap(),
            AgeBand::Unknown
        );

        // Self-declared adult alone → Unknown (the one-way ratchet ignores a
        // self-declared adult).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ab-self-adult",
                    "ab-subj",
                    "ab-subj",
                    "age_self_declared:band:adult",
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "ab-subj").await.unwrap(),
            AgeBand::Unknown,
            "a self-declared adult must NOT graduate the subject to Adult",
        );

        // Add a self-declared MINOR → Minor (a subject may ratchet DOWN).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ab-self-minor",
                    "ab-subj",
                    "ab-subj",
                    "age_self_declared:band:minor",
                ),
            })
            .await
            .unwrap();
        assert_eq!(age_band(&backend, "ab-subj").await.unwrap(), AgeBand::Minor);

        // A witness ADULT attestation OUTRANKS the self-declared minor → Adult.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ab-witness-adult",
                    "ab-witness",
                    "ab-subj",
                    "age_assurance:provider:adult:v1",
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "ab-subj").await.unwrap(),
            AgeBand::Adult,
            "the witness rung must outrank a self-declared minor",
        );
    }

    /// age_band: a witness MINOR resolves Minor; an EXPIRED witness adult is
    /// ignored (liveness = expires_at only).
    #[tokio::test]
    async fn age_band_witness_minor_and_expired_witness_ignored() {
        use crate::federation::age::{age_band, AgeBand};
        let backend = MemoryBackend::new();
        put_conferred_key(
            &backend,
            "abe-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "abe-subj", "user").await;

        // Witness minor → Minor.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "abe-w-minor",
                    "abe-witness",
                    "abe-subj",
                    "age_assurance:provider:minor:v1",
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "abe-subj").await.unwrap(),
            AgeBand::Minor
        );

        // An EXPIRED witness adult is ignored — Minor still wins (it is live).
        let mut expired = fix_age_attestation(
            "abe-w-adult-exp",
            "abe-witness",
            "abe-subj",
            "age_assurance:provider:adult:v1",
        );
        expired.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
        resign_fix(&mut expired);
        backend
            .put_attestation(SignedAttestation {
                attestation: expired,
            })
            .await
            .unwrap();
        assert_eq!(
            age_band(&backend, "abe-subj").await.unwrap(),
            AgeBand::Minor,
            "an expired witness adult must be ignored (liveness = expires_at)",
        );
    }

    /// CC 3.2 user-target gate decision table, exercised through the REAL
    /// `put_attestation` admission path on the memory backend.
    #[tokio::test]
    async fn user_target_steward_binding_gate_decision_table() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        // S = adult-user steward; the witness that attests adulthood.
        put_conferred_key(
            &backend,
            "ut-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ut-S", "user").await;
        // Adult target A (witness-attested adult), unknown-age user U,
        // minor target M (witness-attested minor), node N.
        put_typed_key(&backend, "ut-A", "user").await;
        put_typed_key(&backend, "ut-U", "user").await;
        put_typed_key(&backend, "ut-M", "user").await;
        put_typed_key(&backend, "ut-N", "node").await;

        // Witness-attest S and A as adults; M as a minor.
        for (id, subj, token) in [
            ("uw-S", "ut-S", "age_assurance:provider:adult:v1"),
            ("uw-A", "ut-A", "age_assurance:provider:adult:v1"),
            ("uw-M", "ut-M", "age_assurance:provider:minor:v1"),
        ] {
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_age_attestation(id, "ut-witness", subj, token),
                })
                .await
                .unwrap();
        }

        let deleg = |id: &str, s: &str, t: &str| {
            fix_owner_binding_delegates_to(id, s, t, s, &[ds::INFRA_SERVE])
        };

        // S(adult user) → A(adult user) : REJECTED (target_is_self_sovereign).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: deleg("utd-A", "ut-S", "ut-A"),
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), "federation_user_target_steward_binding_forbidden");
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "target_is_self_sovereign");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }

        // S(adult) → U(no age = Unknown) : REJECTED (target_age_unverified).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: deleg("utd-U", "ut-S", "ut-U"),
            })
            .await
            .unwrap_err();
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "target_age_unverified");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }

        // S(adult user) → M(witness minor) : ADMITTED (legal guardianship).
        backend
            .put_attestation(SignedAttestation {
                attestation: deleg("utd-M", "ut-S", "ut-M"),
            })
            .await
            .expect("adult-user steward → witness-minor ward is admitted");
        // (The granter-not-adult-user leg + node-target no-op are covered by
        // `user_target_gate_granter_must_be_adult_and_nodes_unaffected`.)
    }

    /// CC 3.2 user-target gate: a non-adult (Unknown-age) granter cannot
    /// steward even a proven minor (granter_not_adult_user); a node/agent
    /// target is unaffected by this gate (goes through node-agency only).
    #[tokio::test]
    async fn user_target_gate_granter_must_be_adult_and_nodes_unaffected() {
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        put_conferred_key(
            &backend,
            "ug-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ug-U", "user").await; // unknown-age user (granter)
        put_typed_key(&backend, "ug-M", "user").await; // witness-minor ward
        put_typed_key(&backend, "ug-N", "node").await; // node target

        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "ugw-M",
                    "ug-witness",
                    "ug-M",
                    "age_assurance:provider:minor:v1",
                ),
            })
            .await
            .unwrap();

        // U(unknown-age user) → M(minor) : REJECTED (granter not proven adult).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ugd-UM",
                    "ug-U",
                    "ug-M",
                    "ug-U",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .unwrap_err();
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "granter_not_adult_user");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }

        // U(unknown-age user) → N(node) : the user-target gate is a no-op for a
        // node target (infra:* scope clears the node-agency gate) → ADMITTED.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ugd-UN",
                    "ug-U",
                    "ug-N",
                    "ug-U",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .expect("a node target is governed by the node-agency gate, not the user-target gate");
    }

    // ── v13.0.0 (CIRISPersist#368, CC 3.4.11 / CC 3.4.13) ────────────────
    //    Witness-targets-subject age_assurance admission decision table.

    /// CC 3.4.11 witness-targets-subject decision table, through the REAL
    /// `put_attestation` admission path:
    ///
    /// - a witness emitting `age_assurance:*` ABOUT a DIFFERENT subject is
    ///   ADMITTED and graduates THAT subject's band (witness outranks the
    ///   subject's own self-declared rung);
    /// - a witness emitting `age_assurance:*` about ITSELF (attester ==
    ///   attested) is REJECTED — "a subject MUST NOT emit on
    ///   `age_assurance:`" — so nobody self-mints their own graduation;
    /// - a non-witness cross-subject emitter is still REJECTED by the
    ///   unchanged identity gate (reserved-prefix emitter mismatch).
    #[tokio::test]
    async fn age_assurance_witness_targets_subject_decision_table() {
        use crate::federation::age::{age_band, age_band_fine, AgeBand, AgeBandFine};
        let backend = MemoryBackend::new();
        put_conferred_key(
            &backend,
            "wts-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "wts-T", "user").await; // the subject
        put_typed_key(&backend, "wts-P", "user").await; // plain (non-witness) user

        // Baseline: T self-declares MINOR (the non-reserved self rung still
        // admits attester==attested — it is subject-signed by design).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-self-minor",
                    "wts-T",
                    "wts-T",
                    "age_self_declared:minor:v1",
                ),
            })
            .await
            .expect("subject-signed self rung admits");
        assert_eq!(age_band(&backend, "wts-T").await.unwrap(), AgeBand::Minor);

        // CROSS-SUBJECT witness graduation: W attests T adult — ADMITTED, and
        // T's band graduates (witness outranks T's own self-declared minor).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-w-adult",
                    "wts-witness",
                    "wts-T",
                    "age_assurance:government:adult:v1",
                ),
            })
            .await
            .expect("witness-targets-subject age_assurance is admitted (CC 3.4.13)");
        assert_eq!(
            age_band(&backend, "wts-T").await.unwrap(),
            AgeBand::Adult,
            "a witness row ABOUT T graduates T's band",
        );
        assert_eq!(
            age_band_fine(&backend, "wts-T").await.unwrap(),
            AgeBandFine::Adult,
            "the finer resolution graduates too",
        );

        // SELF-graduation via the witness prefix: W attests W — REJECTED
        // (attester == attested; CC 3.4.11 "a subject MUST NOT emit on
        // `age_assurance:`"). The witness identity_type does NOT bypass.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-w-self",
                    "wts-witness",
                    "wts-witness",
                    "age_assurance:provider:adult:v1",
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), "federation_age_assurance_self_emission_rejected");
        assert_eq!(
            age_band(&backend, "wts-witness").await.unwrap(),
            AgeBand::Unknown,
            "the rejected self-emission confers nothing",
        );

        // Identity gate UNCHANGED: a plain user cross-attesting T's age is
        // still refused (reserved prefix requires a witness emitter).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "wts-p-cross",
                    "wts-P",
                    "wts-T",
                    "age_assurance:provider:minor:v1",
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
    }

    /// #368 read-side defense-in-depth: a self-emitted `age_assurance:*` row
    /// that PRE-DATES the admission gate (or arrived via replication before
    /// v13.0.0) must not graduate its own emitter either. Injected directly
    /// into backend state (bypassing `put_attestation`) to simulate the
    /// legacy row; `age_band` / `age_band_fine` skip it.
    #[tokio::test]
    async fn age_band_ignores_pre_gate_self_emitted_witness_row() {
        use crate::federation::age::{age_band, age_band_fine, AgeBand, AgeBandFine};
        let backend = MemoryBackend::new();
        put_conferred_key(
            &backend,
            "pg-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "pg-T", "user").await;

        // Bypass the gate: push a self-emitted witness-adult row directly.
        let legacy = fix_age_attestation(
            "pg-self-adult",
            "pg-witness",
            "pg-witness",
            "age_assurance:government:adult:v1",
        );
        backend
            .state
            .lock()
            .expect("memory backend lock")
            .federation_attestations
            .push(legacy);

        assert_eq!(
            age_band(&backend, "pg-witness").await.unwrap(),
            AgeBand::Unknown,
            "a pre-gate self-emitted witness row is skipped at read time",
        );
        assert_eq!(
            age_band_fine(&backend, "pg-witness").await.unwrap(),
            AgeBandFine::Unknown,
        );

        // Control: the SAME token about a DIFFERENT subject resolves.
        let cross = fix_age_attestation(
            "pg-cross-adult",
            "pg-witness",
            "pg-T",
            "age_assurance:government:adult:v1",
        );
        backend
            .state
            .lock()
            .expect("memory backend lock")
            .federation_attestations
            .push(cross);
        assert_eq!(age_band(&backend, "pg-T").await.unwrap(), AgeBand::Adult);
    }

    // ── CIRISPersist#309 (CC 3.4.12) — adult-incapacity steward-binding ──

    /// Build an adult-incapacity `delegates_to(steward -> ward)` carrying the
    /// CC 3.4.12 envelope fields. `scope` = decision-domains; the optionals
    /// mirror `capacity::binding_field::*`.
    #[allow(clippy::too_many_arguments)]
    fn fix_incapacity_binding(
        id: &str,
        steward: &str,
        ward: &str,
        scope: &[&str],
        legit: Option<&str>,
        valid_until: Option<&str>,
        binding_tier: Option<&str>,
        petitioner: Option<&str>,
    ) -> Attestation {
        let mut att = fix_attestation(id, steward, ward, steward);
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        crate::federation::tier_ingest::test_support::reseal(&mut att);
        let mut env = serde_json::json!({
            "id": id,
            "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            // v30.8.0 (CIRISConstitution#87) — an incapacity binding is a CUSTODY
            // CLAIM by construction, so it declares itself as one. Since the
            // ruling, custody must be DECLARED: an undeclared `delegates_to` to a
            // person is a capability conferral. That matters most for the
            // `missing_legitimacy_source` case — a binding that omits its
            // justification is otherwise indistinguishable from a conferral, and
            // would slip past the gate that exists to punish exactly that
            // omission. Declaring custody is what makes the omission visible.
            //
            // Fail-safe either way: an undeclared edge confers no custody, so a
            // host that forgets the marker gets a grant that establishes nothing
            // rather than silent stewardship.
            "delegation_purpose": crate::federation::types::owner_binding::CC_DELEGATION_PURPOSE,
        });
        let obj = env.as_object_mut().unwrap();
        if let Some(l) = legit {
            obj.insert("binding_legitimacy_source".into(), serde_json::json!(l));
        }
        if let Some(v) = valid_until {
            obj.insert("valid_until".into(), serde_json::json!(v));
        }
        if let Some(t) = binding_tier {
            obj.insert("binding_tier".into(), serde_json::json!(t));
        }
        if let Some(p) = petitioner {
            obj.insert("petitioner_key_id".into(), serde_json::json!(p));
        }
        att.attestation_envelope = env;
        resign_fix(&mut att);
        att
    }

    fn assert_forbidden(e: &crate::federation::Error, want: &str) {
        assert_eq!(e.kind(), "federation_user_target_steward_binding_forbidden");
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(*reason, want, "wrong rejection reason");
            }
            other => panic!("expected UserTargetStewardBindingForbidden({want}), got {other:?}"),
        }
    }

    /// Register `assessor`(witness), `S`(adult user), `A`(adult user); attest
    /// S and A adults. Returns nothing; keys are `<p>-assessor/-S/-A`.
    async fn bootstrap_incapacity(backend: &MemoryBackend, p: &str) {
        // v30.2.0 (CIRISPersist#607) — the assessor is a witness, and a witness
        // now needs a trust-root conferral before `age_assurance:` admits.
        put_conferred_key(
            backend,
            &format!("{p}-assessor"),
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(backend, &format!("{p}-S"), "user").await;
        put_typed_key(backend, &format!("{p}-A"), "user").await;
        for who in ["S", "A"] {
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_age_attestation(
                        &format!("{p}w-{who}"),
                        &format!("{p}-assessor"),
                        &format!("{p}-{who}"),
                        "age_assurance:provider:adult:v1",
                    ),
                })
                .await
                .unwrap();
        }
    }

    /// Put a capacity attestation ABOUT `ward` from `attester`.
    async fn put_capacity(
        backend: &MemoryBackend,
        id: &str,
        attester: &str,
        ward: &str,
        token: &str,
    ) {
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(id, attester, ward, token),
            })
            .await
            .unwrap_or_else(|e| panic!("capacity attestation {token} rejected: {e:?}"));
    }

    /// CC 3.4.12 capacity-assurance emitter discipline: witness-RESERVED (a
    /// non-witness emitter is rejected) AND the subject MUST NOT self-emit
    /// (attester == attested rejected even for a witness).
    #[tokio::test]
    async fn capacity_assurance_witness_reserved_and_no_self_emit() {
        let backend = MemoryBackend::new();
        put_conferred_key(
            &backend,
            "cap-assessor",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "cap-user", "user").await;
        put_typed_key(&backend, "cap-subj", "user").await;

        // A witness assessor CAN attest another's capacity.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "cap-ok",
                    "cap-assessor",
                    "cap-subj",
                    "capacity_assurance:panel:financial:incapacitated:v1",
                ),
            })
            .await
            .expect("witness assessor may attest another's capacity");

        // A non-witness (plain user) may NOT emit capacity_assurance.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "cap-nonwit",
                    "cap-user",
                    "cap-subj",
                    "capacity_assurance:provider:medical:incapacitated:v1",
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");

        // The SUBJECT must not self-mint their own (in)capacity, even as a
        // witness (attester == attested).
        put_conferred_key(
            &backend,
            "cap-selfwit",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_age_attestation(
                    "cap-self",
                    "cap-selfwit",
                    "cap-selfwit",
                    "capacity_assurance:provider:financial:incapacitated:v1",
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), "federation_capacity_self_emission_rejected");
    }

    /// CC 3.4.12 adult-incapacity admission decision table (through the REAL
    /// `put_attestation` path): presumption-of-capacity, missing legitimacy /
    /// valid_until, cadence ceiling, scope containment, reversible exclusion,
    /// then a valid ADMIT that makes the steward a live anchor.
    #[tokio::test]
    async fn adult_incapacity_binding_gate_decision_table() {
        use crate::federation::admission::steward_bindings_of;
        use chrono::{Duration, Utc};
        let backend = MemoryBackend::new();
        bootstrap_incapacity(&backend, "ai").await;
        let future = (Utc::now() + Duration::days(30)).to_rfc3339();

        // (0) presumption of capacity — an adult with NO incapacity attested is
        // self-sovereign (the CC 3.2 un-stewardable default reasserts).
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-0",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "target_is_self_sovereign");

        // Attest A incapacitated for `financial` + rule out reversible mimics.
        put_capacity(
            &backend,
            "aic-fin",
            "ai-assessor",
            "ai-A",
            "capacity_assurance:panel:financial:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "aic-fin-rex",
            "ai-assessor",
            "ai-A",
            "capacity_assurance:reversible_excluded:financial",
        )
        .await;

        // (1) missing legitimacy source → naked self-appointment refused.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-1",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    None,
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "missing_legitimacy_source");

        // (2) missing valid_until → no fail-to-liberty expiry.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-2",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    None,
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "missing_valid_until");

        // (3) valid_until beyond the T2 review cadence (90d) → rejected.
        let far = (Utc::now() + Duration::days(200)).to_rfc3339();
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-3",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&far),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "valid_until_exceeds_review_cadence");

        // (4) scope exceeds the attested-incapacitated domains.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-4",
                    "ai-S",
                    "ai-A",
                    &["medical"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "scope_exceeds_attested_domains");

        // (5) attested incapacitated but reversible mimics NOT excluded.
        put_capacity(
            &backend,
            "aic-res",
            "ai-assessor",
            "ai-A",
            "capacity_assurance:provider:residence:incapacitated:v1",
        )
        .await;
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-5",
                    "ai-S",
                    "ai-A",
                    &["residence"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "capacity_reversible_not_excluded");

        // (6) ADMIT — scope ⊆ attested loss, reversible excluded, prior-will
        // legitimacy, bounded valid_until, independent assessor.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "ai-6",
                    "ai-S",
                    "ai-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .expect("valid adult-incapacity binding is admitted");

        // A live binding makes S an anchor of A; A (an adult) also self-anchors
        // (it is never demoted to a perpetual minor).
        let anchors = steward_bindings_of(&backend, "ai-A").await.unwrap();
        assert!(anchors.contains(&"ai-S".to_string()), "S is a live anchor");
        assert!(
            anchors.contains(&"ai-A".to_string()),
            "the adult retains its own self-anchor (never a perpetual minor)"
        );
    }

    /// CC 3.4.12 T1 acute path: `reversible_pending` (in lieu of `_excluded`)
    /// is admissible ONLY for `binding_tier == T1_emergency_necessity` with the
    /// `emergency_necessity_expedited` legitimacy source.
    #[tokio::test]
    async fn adult_incapacity_t1_reversible_pending_path() {
        use crate::federation::capacity::{legitimacy_source, tier};
        use chrono::{Duration, Utc};
        let backend = MemoryBackend::new();
        bootstrap_incapacity(&backend, "t1").await;
        let soon = (Utc::now() + Duration::days(2)).to_rfc3339();
        put_capacity(
            &backend,
            "t1c",
            "t1-assessor",
            "t1-A",
            "capacity_assurance:provider:medical:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "t1c-pend",
            "t1-assessor",
            "t1-A",
            "capacity_assurance:reversible_pending:medical",
        )
        .await;

        // Standard path (no T1 tier) with only `pending` → rejected.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "t1-std",
                    "t1-S",
                    "t1-A",
                    &["medical"],
                    Some(legitimacy_source::PRIOR_WILL_PROXY),
                    Some(&soon),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "capacity_reversible_not_excluded");

        // T1 acute path → admitted.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "t1-ok",
                    "t1-S",
                    "t1-A",
                    &["medical"],
                    Some(legitimacy_source::EMERGENCY_NECESSITY_EXPEDITED),
                    Some(&soon),
                    Some(tier::T1_EMERGENCY_NECESSITY),
                    None,
                ),
            })
            .await
            .expect("T1 emergency-necessity + reversible_pending is admitted");
    }

    /// CC 3.4.12 apophatic floor: a protected non-transferable domain (voting)
    /// is rejected even when incapacity + reversible exclusion are attested.
    #[tokio::test]
    async fn adult_incapacity_protected_domain_rejected() {
        use chrono::{Duration, Utc};
        let backend = MemoryBackend::new();
        bootstrap_incapacity(&backend, "pd").await;
        let future = (Utc::now() + Duration::days(10)).to_rfc3339();
        put_capacity(
            &backend,
            "pdc",
            "pd-assessor",
            "pd-A",
            "capacity_assurance:panel:voting:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "pdc-rex",
            "pd-assessor",
            "pd-A",
            "capacity_assurance:reversible_excluded:voting",
        )
        .await;
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "pd-b",
                    "pd-S",
                    "pd-A",
                    &["voting"],
                    Some("wa_due_process_quorum"),
                    Some(&future),
                    None,
                    None,
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "scope_touches_protected_domain");
    }

    /// CC 3.4.12 assessor-independence: the capacity attester may not be the
    /// petitioner (anti-capture). The steward-is-attester case rides the same
    /// `incapacity_attesters.contains(steward)` branch.
    #[tokio::test]
    async fn adult_incapacity_conflicted_attester_rejected() {
        use chrono::{Duration, Utc};
        let backend = MemoryBackend::new();
        bootstrap_incapacity(&backend, "cf").await;
        let future = (Utc::now() + Duration::days(10)).to_rfc3339();
        put_capacity(
            &backend,
            "cfc",
            "cf-assessor",
            "cf-A",
            "capacity_assurance:panel:financial:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "cfc-rex",
            "cf-assessor",
            "cf-A",
            "capacity_assurance:reversible_excluded:financial",
        )
        .await;
        // petitioner == the assessor → conflicted.
        let e = backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "cf-b",
                    "cf-S",
                    "cf-A",
                    &["financial"],
                    Some("wa_due_process_quorum"),
                    Some(&future),
                    None,
                    Some("cf-assessor"),
                ),
            })
            .await
            .unwrap_err();
        assert_forbidden(&e, "attester_conflicted");
    }

    /// CC 3.4.12 fail-to-liberty: a binding whose `valid_until` has lapsed is
    /// non-live — the steward drops out of the ward's anchors and the adult
    /// auto-re-sovereigns (self-anchor only), with NO steward assent.
    #[tokio::test]
    async fn adult_incapacity_fail_to_liberty_auto_re_sovereign() {
        use crate::federation::admission::steward_bindings_of;
        use chrono::{Duration, Utc};
        let backend = MemoryBackend::new();
        bootstrap_incapacity(&backend, "fl").await;
        put_capacity(
            &backend,
            "flc",
            "fl-assessor",
            "fl-A",
            "capacity_assurance:panel:financial:incapacitated:v1",
        )
        .await;
        put_capacity(
            &backend,
            "flc-rex",
            "fl-assessor",
            "fl-A",
            "capacity_assurance:reversible_excluded:financial",
        )
        .await;
        // Admit a binding whose valid_until is ALREADY in the past (structurally
        // admissible: present, parseable, within the cadence ceiling).
        let lapsed = (Utc::now() - Duration::days(1)).to_rfc3339();
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_incapacity_binding(
                    "fl-b",
                    "fl-S",
                    "fl-A",
                    &["financial"],
                    Some("prior_will_proxy"),
                    Some(&lapsed),
                    None,
                    None,
                ),
            })
            .await
            .expect("a lapsed-valid_until binding is structurally admitted");

        // Fail-to-liberty at READ: the lapsed edge confers no standing. S is
        // NOT an anchor; the adult self-anchors (auto-re-sovereign).
        let anchors = steward_bindings_of(&backend, "fl-A").await.unwrap();
        assert!(
            !anchors.contains(&"fl-S".to_string()),
            "a lapsed adult-incapacity binding must NOT confer steward standing"
        );
        assert_eq!(
            anchors,
            vec!["fl-A".to_string()],
            "the adult auto-re-sovereigns to its own self-anchor with no steward assent"
        );
    }

    /// Minor-stewardship liveness fail-secure (CC 3.2): a minor user bound by
    /// an adult (live edge) is steward-bound; after the granter withdraws it,
    /// is_steward_bound flips to false (the minor does NOT self-anchor). A
    /// node is unchanged; an adult user self-anchors with no edge.
    #[tokio::test]
    async fn minor_stewardship_liveness_fails_secure_nodes_and_adults_unchanged() {
        use crate::federation::admission::{is_steward_bound, steward_bindings_of};
        use crate::federation::types::delegation_scope as ds;
        let backend = MemoryBackend::new();
        put_conferred_key(
            &backend,
            "ml-witness",
            "witness",
            crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE,
        )
        .await;
        put_typed_key(&backend, "ml-S", "user").await; // adult-user steward
        put_typed_key(&backend, "ml-M", "user").await; // minor-user ward
        put_typed_key(&backend, "ml-A", "user").await; // adult-user (self-sovereign)
        put_typed_key(&backend, "ml-N", "node").await; // node control

        // Attest S and A as adults, M as a minor.
        for (id, subj, token) in [
            ("mlw-S", "ml-S", "age_assurance:provider:adult:v1"),
            ("mlw-A", "ml-A", "age_assurance:provider:adult:v1"),
            ("mlw-M", "ml-M", "age_assurance:provider:minor:v1"),
        ] {
            backend
                .put_attestation(SignedAttestation {
                    attestation: fix_age_attestation(id, "ml-witness", subj, token),
                })
                .await
                .unwrap();
        }

        // An adult user with no edge self-anchors (sovereign — its own steward).
        assert!(
            is_steward_bound(&backend, "ml-A").await.unwrap(),
            "an adult user is its own steward anchor",
        );

        // A steward-less minor does NOT self-anchor (fail-secure).
        assert!(
            !is_steward_bound(&backend, "ml-M").await.unwrap(),
            "a steward-less minor must NOT self-anchor (CC 3.2 fail-secure)",
        );

        // Bind the minor to the adult steward (live edge) → steward-bound.
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ml-bind",
                    "ml-S",
                    "ml-M",
                    "ml-S",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .expect("adult-user steward → minor ward admitted");
        assert!(is_steward_bound(&backend, "ml-M").await.unwrap());
        assert_eq!(
            steward_bindings_of(&backend, "ml-M").await.unwrap(),
            vec!["ml-S".to_string()],
            "while bound, the minor is anchored only to the adult steward (NOT self)",
        );

        // The adult withdraws the binding → the minor fails secure again.
        let mut w = fix_attestation("ml-withdraw", "ml-S", "ml-M", "ml-S");
        w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        w.attestation_envelope = serde_json::json!({ "id": "ml-withdraw" });
        resign_fix(&mut w);
        backend
            .put_attestation(SignedAttestation { attestation: w })
            .await
            .unwrap();
        assert!(
            !is_steward_bound(&backend, "ml-M").await.unwrap(),
            "a minor whose only adult steward was withdrawn must be steward-less (fail-secure)",
        );
        assert!(steward_bindings_of(&backend, "ml-M")
            .await
            .unwrap()
            .is_empty());

        // Control: a node bound then withdrawn is unchanged (bound→true,
        // withdrawn→false) — the node path never used clauses (1)/(2).
        backend
            .put_attestation(SignedAttestation {
                attestation: fix_owner_binding_delegates_to(
                    "ml-nbind",
                    "ml-S",
                    "ml-N",
                    "ml-S",
                    &[ds::INFRA_SERVE],
                ),
            })
            .await
            .unwrap();
        assert!(is_steward_bound(&backend, "ml-N").await.unwrap());
        let mut wn = fix_attestation("ml-nwithdraw", "ml-S", "ml-N", "ml-S");
        wn.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.into();
        wn.attestation_envelope = serde_json::json!({ "id": "ml-nwithdraw" });
        resign_fix(&mut wn);
        backend
            .put_attestation(SignedAttestation { attestation: wn })
            .await
            .unwrap();
        assert!(
            !is_steward_bound(&backend, "ml-N").await.unwrap(),
            "the node/agent fail-secure path is unchanged by the minor gate",
        );
    }

    // ─── v21.0.0 (CIRISPersist#502 E4) — keyless-declaration forgery
    //     witnesses. `Family` / `Community` / `FamilyMembershipRevocation` /
    //     `CommunityMembershipRevocation` / `LocationProof` carried NO
    //     per-record signature at all (admission was FK-existence only), so
    //     any linked peer could forge one wholesale — worst case, a forged
    //     community-membership removal rotates the CC 4.4.3.2.2 DEK epoch
    //     (an unauthenticated forward-secrecy DoS). Each witness below: an
    //     honestly-signed record admits; the SAME record re-signed by a
    //     DIFFERENT key (while still CLAIMING the honest authority's
    //     `authority_key_id`) is rejected fail-closed and leaves no trace.

    /// A forged `Family`: claims `authority_key_id: "e4-fam-authority"` but
    /// the envelope is actually signed by `e4-fam-attacker`'s key — the
    /// registered pubkeys of the claimed authority won't verify it.
    #[tokio::test]
    async fn forged_family_wrong_signer_rejected_502e4() {
        let backend = MemoryBackend::new();
        for k in [
            "e4-fam-authority",
            "e4-fam-attacker",
            "e4-fam-member",
            "e4-fam-good",
            "e4-fam-forged",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        let fam = |key_id: &str| crate::federation::types::Family {
            family_key_id: key_id.into(),
            family_name: "E4 Household".into(),
            members: vec![crate::federation::types::FamilyMember {
                key_id: "e4-fam-member".into(),
                joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                role: None,
            }],
            founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            consensus_protocol: "founder_only".into(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        };
        // Honest: signed by the authority it claims to be — admits.
        backend
            .put_family(crate::federation::tier_ingest::test_support::sign_family(
                "e4-fam-authority",
                fam("e4-fam-good"),
            ))
            .await
            .expect("(E4) honestly-signed family admits");

        // Forged: same shape, but the SIGNATURE comes from the attacker's
        // key while `authority_key_id` still claims the honest authority.
        let mut forged = crate::federation::tier_ingest::test_support::sign_family(
            "e4-fam-attacker",
            fam("e4-fam-forged"),
        );
        forged.authority_key_id = "e4-fam-authority".to_owned();
        let err = backend
            .put_family(forged)
            .await
            .expect_err("(E4) forged family must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert!(
            backend
                .lookup_family("e4-fam-forged")
                .await
                .unwrap()
                .is_none(),
            "(E4) rejected family must NOT be stored (fail-secure)"
        );
    }

    /// A forged `Community`: same shape as the family witness.
    #[tokio::test]
    async fn forged_community_wrong_signer_rejected_502e4() {
        let backend = MemoryBackend::new();
        for k in [
            "e4-comm-authority",
            "e4-comm-attacker",
            "e4-comm-member",
            "e4-comm-good",
            "e4-comm-forged",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        let comm = |key_id: &str| crate::federation::types::Community {
            community_key_id: key_id.into(),
            community_name: "E4 Co-op".into(),
            members: vec![crate::federation::types::CommunityMember {
                key_id: "e4-comm-member".into(),
                joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                role: None,
            }],
            founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            consensus_protocol: "founder_only".into(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    "e4-comm-authority",
                    comm("e4-comm-good"),
                ),
            )
            .await
            .expect("(E4) honestly-signed community admits");

        let mut forged = crate::federation::tier_ingest::test_support::sign_community(
            "e4-comm-attacker",
            comm("e4-comm-forged"),
        );
        forged.authority_key_id = "e4-comm-authority".to_owned();
        let err = backend
            .put_community(forged)
            .await
            .expect_err("(E4) forged community must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert!(
            backend
                .lookup_community("e4-comm-forged")
                .await
                .unwrap()
                .is_none(),
            "(E4) rejected community must NOT be stored (fail-secure)"
        );
    }

    /// A forged `FamilyMembershipRevocation`.
    #[tokio::test]
    async fn forged_family_membership_revocation_wrong_signer_rejected_502e4() {
        let backend = MemoryBackend::new();
        for k in [
            "e4-fmr-authority",
            "e4-fmr-attacker",
            "e4-fmr-fam",
            "e4-fmr-member",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        backend
            .put_family(crate::federation::tier_ingest::test_support::sign_family(
                "e4-fmr-fam",
                crate::federation::types::Family {
                    family_key_id: "e4-fmr-fam".into(),
                    family_name: "E4 FMR Household".into(),
                    members: vec![crate::federation::types::FamilyMember {
                        key_id: "e4-fmr-member".into(),
                        joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        role: None,
                    }],
                    founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    consensus_protocol: "founder_only".into(),
                    consensus_protocol_entrenched: false,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("seed family");

        let effective: chrono::DateTime<chrono::Utc> = "2026-06-10T00:00:00Z".parse().unwrap();
        let rev = crate::federation::FamilyMembershipRevocation {
            family_key_id: "e4-fmr-fam".into(),
            removed_identity_key_id: "e4-fmr-member".into(),
            removed_at: effective,
            effective_at: effective,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        // Honest: signed by e4-fmr-authority — admits.
        backend
            .put_family_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                    "e4-fmr-authority",
                    rev.clone(),
                ),
            )
            .await
            .expect("(E4) honestly-signed revocation admits");

        // Forged: a DIFFERENT removal (so it isn't a no-op re-submit),
        // signed by the attacker but claiming the honest authority.
        let forged_rev = crate::federation::FamilyMembershipRevocation {
            removed_identity_key_id: "e4-fmr-fam".into(), // different removal target
            ..rev
        };
        let mut forged =
            crate::federation::tier_ingest::test_support::sign_family_membership_revocation(
                "e4-fmr-attacker",
                forged_rev,
            );
        forged.authority_key_id = "e4-fmr-authority".to_owned();
        let err = backend
            .put_family_membership_revocation(forged)
            .await
            .expect_err("(E4) forged revocation must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert!(
            backend
                .list_family_membership_revocations_for("e4-fmr-fam")
                .await
                .unwrap()
                .iter()
                .all(|r| r.removed_identity_key_id != "e4-fmr-fam"),
            "(E4) rejected revocation must NOT be stored (fail-secure)"
        );
    }

    /// A forged `CommunityMembershipRevocation` — THE worst-case E4 hole: an
    /// unverified removal rotates the CC 4.4.3.2.2 community DEK epoch, an
    /// unauthenticated forward-secrecy DoS.
    #[tokio::test]
    async fn forged_community_membership_revocation_wrong_signer_rejected_502e4() {
        let backend = MemoryBackend::new();
        for k in [
            "e4-cmr-authority",
            "e4-cmr-attacker",
            "e4-cmr-comm",
            "e4-cmr-member",
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    "e4-cmr-comm",
                    crate::federation::types::Community {
                        community_key_id: "e4-cmr-comm".into(),
                        community_name: "E4 CMR Co-op".into(),
                        members: vec![crate::federation::types::CommunityMember {
                            key_id: "e4-cmr-member".into(),
                            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            role: None,
                        }],
                        founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        consensus_protocol: "founder_only".into(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .expect("seed community");
        assert_eq!(backend.community_dek_epoch("e4-cmr-comm"), 0);

        let effective: chrono::DateTime<chrono::Utc> = "2026-06-10T00:00:00Z".parse().unwrap();
        // Forged FIRST: signed by the attacker but claiming the honest
        // authority — must be rejected BEFORE the epoch bump.
        let forged_rev = crate::federation::CommunityMembershipRevocation {
            community_key_id: "e4-cmr-comm".into(),
            removed_identity_key_id: "e4-cmr-member".into(),
            removed_at: effective,
            effective_at: effective,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        let mut forged =
            crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                "e4-cmr-attacker",
                forged_rev,
            );
        forged.authority_key_id = "e4-cmr-authority".to_owned();
        let err = backend
            .put_community_membership_revocation(forged)
            .await
            .expect_err("(E4) forged community removal must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        assert_eq!(
            backend.community_dek_epoch("e4-cmr-comm"),
            0,
            "(E4) a forged removal must NOT rotate the DEK epoch (forward-secrecy DoS closed)"
        );
        assert!(
            backend
                .list_community_membership_revocations_for("e4-cmr-comm")
                .await
                .unwrap()
                .is_empty(),
            "(E4) rejected removal must NOT be stored (fail-secure)"
        );

        // Honest, same content, signed by the real authority — admits +
        // bumps the epoch.
        let honest_rev = crate::federation::CommunityMembershipRevocation {
            community_key_id: "e4-cmr-comm".into(),
            removed_identity_key_id: "e4-cmr-member".into(),
            removed_at: effective,
            effective_at: effective,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        backend
            .put_community_membership_revocation(
                crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
                    "e4-cmr-authority",
                    honest_rev,
                ),
            )
            .await
            .expect("(E4) honestly-signed removal admits");
        assert_eq!(backend.community_dek_epoch("e4-cmr-comm"), 1);
    }

    /// A forged `LocationProof`.
    #[tokio::test]
    async fn forged_location_proof_wrong_signer_rejected_502e4() {
        let backend = MemoryBackend::new();
        for k in ["e4-loc-authority", "e4-loc-attacker", "e4-loc-subject"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        let cell7 = h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        let proof = |asserted_at: &str| crate::federation::types::LocationProof {
            subject_key_id: "e4-loc-subject".into(),
            cell_id: cell7.clone(),
            cell_resolution: 7,
            asserted_at: asserted_at.parse().unwrap(),
            valid_until: None,
            attestation_evidence: None,
            withdrawn_at: None,
            persist_row_hash: String::new(),
        };
        // Honest: signed by e4-loc-authority — admits.
        backend
            .put_location_proof(
                crate::federation::tier_ingest::test_support::sign_location_proof(
                    "e4-loc-authority",
                    proof("2026-06-01T00:00:00Z"),
                ),
            )
            .await
            .expect("(E4) honestly-signed location proof admits");

        // Forged: a DIFFERENT proof (distinct asserted_at, so it isn't a
        // no-op re-submit), signed by the attacker, claiming the honest
        // authority.
        let mut forged = crate::federation::tier_ingest::test_support::sign_location_proof(
            "e4-loc-attacker",
            proof("2026-06-02T00:00:00Z"),
        );
        forged.authority_key_id = "e4-loc-authority".to_owned();
        let err = backend
            .put_location_proof(forged)
            .await
            .expect_err("(E4) forged location proof must be rejected");
        assert!(
            err.kind().contains("federation_tier_unverified") || err.kind().contains("unverified"),
            "rejected by hybrid verify, got kind {}",
            err.kind()
        );
        let rows = backend
            .list_location_proofs_for("e4-loc-subject")
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "(E4) rejected proof must NOT be stored (fail-secure)"
        );
        assert_eq!(
            rows[0].asserted_at,
            "2026-06-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
    }

    // ─── v21.0.0 (CIRISPersist#502 E4 followup) — the authority signature
    //     E4's admission gate verifies must be PERSISTED, not verified-then-
    //     discarded: before this cut, `Family`/`Community`/etc. had no home
    //     for `authority_key_id` / `scrub_signature_{classical,pqc}`, so the
    //     durable row could never prove its own authorship. Put an
    //     authority-signed family, then read the stored side-map entry
    //     directly (there is no public reconstruction of `SignedFamily` on
    //     the read side yet — see the V110 migration note) and assert all 3
    //     fields round-trip byte-exact.

    /// A honestly-signed `Family` round-trips its authority signature: the
    /// `federation_family_authority_sigs` side-map (V110 mirror) holds the
    /// SAME `authority_key_id` + `scrub_signature_{classical,pqc}` the
    /// caller submitted, not empty/discarded values.
    #[tokio::test]
    async fn e4_authority_signature_persists_502_followup() {
        let backend = MemoryBackend::new();
        for k in ["e4sig-authority", "e4sig-member", "e4sig-family"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fix_key(k, "ref", k),
                })
                .await
                .unwrap();
        }
        let fam = crate::federation::types::Family {
            family_key_id: "e4sig-family".into(),
            family_name: "E4 Signature Household".into(),
            members: vec![crate::federation::types::FamilyMember {
                key_id: "e4sig-member".into(),
                joined_at: "2026-07-01T00:00:00Z".parse().unwrap(),
                role: None,
            }],
            founded_at: "2026-07-01T00:00:00Z".parse().unwrap(),
            consensus_protocol: "founder_only".into(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        };
        let signed =
            crate::federation::tier_ingest::test_support::sign_family("e4sig-authority", fam);
        let expect_classical = signed.scrub_signature_classical.clone();
        let expect_pqc = signed.scrub_signature_pqc.clone();
        backend
            .put_family(signed)
            .await
            .expect("(E4 followup) honestly-signed family admits");

        let stored = backend
            .state
            .lock()
            .expect("memory backend lock")
            .federation_family_authority_sigs
            .get("e4sig-family")
            .cloned()
            .expect("(E4 followup) authority signature must be persisted, not discarded");
        assert_eq!(stored.0, "e4sig-authority");
        assert_eq!(stored.1, expect_classical);
        assert_eq!(stored.2, expect_pqc);
    }
}
