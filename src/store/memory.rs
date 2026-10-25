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
    /// v50.0.0 (CIRISPersist#928, review H2) — the delegation depth this
    /// node's `withdraws` write gate walks: the CC 4.1.1 default (5) unless
    /// the host opts in, up to the 16 ceiling (`set_withdraws_delegation_depth`).
    withdraws_delegation_depth: std::sync::atomic::AtomicUsize,
    /// v3.4.0 (CIRISPersist#123) — trust-weighted admission gate. `None` =
    /// no gate (bootstrap-permissive). See
    /// [`MemoryBackend::set_admission_gate`].
    ///
    /// v22.0.0 (CIRISPersist#543 finding 4): the memory backend had NO gate
    /// field, no accessor and no call site — `AdmissionGate::check_federation`
    /// simply never ran here, on any write path, since v3.4.0. Same
    /// recurrence class as #541.
    admission_gate: std::sync::RwLock<Option<crate::federation::AdmissionGate>>,
    /// v50.0.0 (CIRISPersist#926) — this directory's trust-root standing cache.
    trust_root_standing_cache: crate::federation::canonical_community::StandingCache,
    /// v54.0.0 (Codex on PR #1050) — the in-process half of the
    /// `delegates_to` cycle-gate serialization
    /// ([`crate::federation::admission::delegation_cycle_gated`]): held from
    /// the cycle check through the insert of every gated write.
    delegation_write_lock: tokio::sync::Mutex<()>,
    /// v54.0.0 (Codex on PR #1050) — the per-record stripe a
    /// `signed_wire_index` re-index holds from its read of the stored bytes
    /// through the replacement ([`crate::store::record_locks`]).
    wire_index_locks: crate::store::record_locks::RecordLocks,
    /// v50.0.0 (PR #921 review) — test-only hooks inside this backend's doors.
    #[cfg(test)]
    test_hooks: crate::store::test_hooks::TestHooks,
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
    /// (CIRISPersist#593) — how many attestation read statements pinned on an
    /// ATTESTER this instance has run. v56.0.0 (CIRISPersist#1001): one per
    /// executed typed query (one per page) whose `by` is set, the reads
    /// `list_attestations_by` made before it was retired. See
    /// [`MemoryBackend::attestation_read_counts`]; this exists so a walk's read
    /// cost can be **measured** rather than estimated.
    attestation_reads_by: std::sync::atomic::AtomicU64,
    /// (CIRISPersist#593) — the twin: typed queries whose `to` is set.
    attestation_reads_for: std::sync::atomic::AtomicU64,
}

struct State {
    /// v51.0.0 (#938) — the witness plane, keyed (lineage, head, witness).
    lineage_head_cosigns: std::collections::BTreeMap<
        (String, String, String, String),
        crate::federation::lineage_witness::LineageHeadCosign,
    >,
    /// Inserted `trace_events` rows, keyed by dedup tuple
    /// (THREAT_MODEL.md AV-9). See [`DedupKey`].
    events: HashMap<DedupKey, (i64, TraceEventRow)>,
    /// Inserted `trace_llm_calls` rows.
    llm_calls: Vec<TraceLlmCallRow>,
    /// v54.1.0 (CIRISPersist#1046, V187 mirror) — steward purge execution
    /// headers, keyed by notice id.
    purge_executions:
        std::collections::BTreeMap<String, crate::federation::steward_purge::PurgeExecution>,
    /// v54.1.0 (CIRISPersist#1046, V187 mirror) — steward purge tombstones,
    /// keyed `(notice_id, plane, record_ref)`.
    purge_tombstones: std::collections::BTreeMap<
        (String, String, String),
        crate::federation::steward_purge::PurgeTombstone,
    >,
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
    /// v50.0.0 (CIRISPersist#928, V157 mirror) — the delegation depth each
    /// admitted `withdraws` was admitted under.
    federation_withdraws_admission_depths: HashMap<String, usize>,
    /// #973 (V167) — unlabelled `delegates_to` ids held before the "bundle
    /// only" rule. A memory backend is born after the rule, so this is empty
    /// outside tests ([`MemoryBackend::mark_trust_direction_held`]).
    federation_trust_direction_held: std::collections::HashSet<String>,
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
    /// v31.1.0 (CIRISPersist#655) — the in-memory mirror of V123's
    /// `federation_revocations.admitted_at`: when THIS node admitted each
    /// revocation, keyed by `revocation_id`. A side map rather than a field on
    /// the row because the instant is local metadata ABOUT the record, not part
    /// of it — the same split the SQL backends make between the column and the
    /// `Revocation` struct, and the reason one revocation hashes identically on
    /// every node that holds it.
    revocation_admitted_at: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,

    /// `federation_keys.admitted_at` (V126): when THIS node admitted each key
    /// record. Keyed by `key_id`. A side map rather than a field on `KeyRecord`,
    /// because the record's bytes must hash identically on every node while each
    /// node keeps its own arrival order — the same separation `ServedRevocation`
    /// makes (#682).
    key_record_admitted_at: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// v36.0.0 (CIRISPersist#707) — `federation_keys.mutated_at` (V131): when
    /// THIS node last rewrote a key row's consumer-visible bytes through a
    /// mutating door. Keyed by `key_id`; absent = never mutated. The serve
    /// cursor keys on the GREATER of this and the admission position, so a
    /// consumer whose cursor passed the row is served the new bytes again.
    /// `admitted_at` above keeps its V126 meaning (first admission) untouched.
    key_record_mutated_at: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// v44.7.0 (CIRISPersist#864) — `federation_key_registration_history`
    /// (V148): the registration claims each key row has REPLACED through the
    /// rebind store step, oldest first. Keyed by `key_id`.
    key_registration_history:
        HashMap<String, Vec<crate::federation::types::KeyRegistrationHistoryRow>>,
    /// v36.0.0 (CIRISPersist#668) — the in-memory mirror of the V130
    /// `admitted_at` columns, for EVERY remaining serve-cursor plane: plane
    /// kind (the wire-index token) → resume id → THIS node's serve position
    /// on the row. A row with no entry falls back to its legacy producer
    /// instant, exactly as the sqlite dialect's
    /// `COALESCE(admitted_at, <legacy>)` does for a pre-V130 row. One nested
    /// map rather than twelve named fields because the planes share one
    /// contract; the key-record and revocation planes keep their own maps
    /// (they predate this one and carry extra prose).
    serve_positions:
        HashMap<&'static str, std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>>,
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
    /// v60.0.0 (CIRISPersist#988 item 4) — the `goals` projection of the
    /// goal rows held, keyed by `goal_id` (the declaration's id), refolded by
    /// the row executor ([`memory_project_goal`]).
    federation_goals:
        std::collections::BTreeMap<String, crate::federation::goal_projection::GoalProjection>,
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
    /// v52.0.0 (CIRISPersist#930) — the V161 mirror: every assertion either
    /// put door admitted, append-only, unique on
    /// `(identity, occurrence, asserted_at, attesting)`.
    federation_identity_occurrence_history: Vec<crate::federation::OccurrenceAssertion>,
    /// v59.0.0 (CIRISPersist#1099) — the V199 mirror: this node's self-roster
    /// proposal ledger, keyed by the proposal row's `attestation_id`.
    self_roster_proposals:
        std::collections::BTreeMap<String, crate::federation::self_roster::SelfRosterReceipt>,
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
    /// v49.0.0 (#910.1, V154 mirror) — keyed on the three-part PK
    /// `(family, member, effective_at)`: a re-added member can be removed again.
    federation_family_membership_revocations: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        crate::federation::FamilyMembershipRevocation,
    >,
    /// v49.0.0 (#912, V156 mirror) — the listing plane: the signed row (its
    /// `persist_row_hash` stamped), keyed on the three-part PK.
    federation_community_membership_listings: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        crate::federation::SignedCommunityMembershipListing,
    >,
    /// v49.0.0 (#910, V154 mirror) — the family widening plane, keyed on its
    /// three-part PK.
    federation_family_membership_widenings: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        crate::federation::FamilyMembershipWidening,
    >,
    /// v48.0.0 (#860) — keyed on the three-part PK `(room, member,
    /// effective_at)`: a re-added member can be removed again.
    federation_community_membership_revocations: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        crate::federation::CommunityMembershipRevocation,
    >,
    /// v48.0.0 (#860) — the widening plane, keyed on its three-part PK.
    federation_community_membership_widenings: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        crate::federation::CommunityMembershipWidening,
    >,
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
    ///
    /// v57.0.0 (CIRISPersist#988 item 2, V194 mirror) — a PROJECTION of the
    /// `hard_case:{kind}:v1` rows, each entry carrying the `attestation_id`
    /// of the row it came from; [`prune_row_projections`] drops an entry
    /// whose row left (the SQL backends' `ON DELETE CASCADE`).
    federation_hard_case_events:
        HashMap<String, (String, crate::federation::hard_case::HardCaseEvent)>,
    /// v60.0.0 (CIRISPersist#988 item 1) — the `credits_ledger` /
    /// `expertise_ledger` projections of this node's ledger rows, keyed by
    /// [`LedgerProjection::map_key`](crate::federation::ledger_projection::LedgerProjection::map_key).
    /// Memory held no ledger before v60; the row door gives it one, so the
    /// projection witness runs here too.
    cirisnode_ledgers:
        std::collections::BTreeMap<String, crate::federation::ledger_projection::LedgerProjection>,
    /// v57.0.0 (CIRISPersist#988 item 3, V195 mirror) — the
    /// `detection_events` projection of the `detection:{detector}:v1` rows,
    /// keyed by `detection_id`, each entry carrying its row's
    /// `attestation_id`. Memory held no detection substrate before v57; the
    /// row door gives it one, so the projection witness runs here too.
    derived_detection_events:
        HashMap<String, (String, crate::derived::detection_row::DetectionProjection)>,
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
    /// `proposal_digest` (immutable, M2); active halts keyed by family (H2).
    accord_proposals: HashMap<String, crate::federation::accord_quorum::StoredProposal>,
    accord_participations: Vec<crate::federation::accord_quorum::StoredParticipation>,
    accord_decisions: HashMap<String, crate::federation::accord_quorum::StoredDecision>,
    accord_active_halts: HashMap<String, crate::federation::accord_quorum::ActiveHalt>,
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
    /// v44.6.0 (#857) — the V147 `consent_peer_set_for` mirror: a grant that
    /// names the machine it is FOR, keyed `(author, for_key, peer)`.
    consent_peer_set_for: Vec<ConsentPeerForRow>,
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
    /// v49.0.0 (CIRISPersist#910.5, V155 mirror) — the `supersede_proof` a
    /// family's current version carries, keyed by `family_key_id`. Absent for
    /// a founding record or one superseded without a quorum.
    federation_family_supersede_proofs: HashMap<String, crate::federation::GroupSupersedeProof>,
    /// v52.0.0 (CIRISPersist#955, V162 mirror) — a family's founding
    /// co-signatures, keyed by `family_key_id`. Absent when single-signed.
    federation_family_cosignatures:
        HashMap<String, Vec<crate::federation::types::RosterCosignature>>,
    /// v49.0.0 (CIRISPersist#910.5, V155 mirror) — the community twin of
    /// `federation_family_supersede_proofs`, keyed by `community_key_id`.
    federation_community_supersede_proofs: HashMap<String, crate::federation::GroupSupersedeProof>,
    /// v50.0.0 (CIRISPersist#926, V158 mirror) — a community's co-signatures
    /// over its signing envelope, keyed by `community_key_id`. Absent = none.
    federation_community_cosignatures:
        HashMap<String, Vec<crate::federation::types::RosterCosignature>>,
    /// v50.0.0 (CIRISPersist#926, V158 mirror) — a trust-root community's
    /// prior signed versions (its chain), keyed by `community_key_id`.
    federation_community_lineages: HashMap<String, Vec<crate::federation::SignedCommunity>>,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — structural
    /// mirror, keyed like `federation_family_membership_revocations`.
    federation_family_membership_revocation_authority_sigs:
        HashMap<(String, String, chrono::DateTime<chrono::Utc>), AuthoritySig>,
    /// v49.0.0 (#910) — keyed like `federation_family_membership_widenings`.
    federation_family_membership_widening_authority_sigs:
        HashMap<(String, String, chrono::DateTime<chrono::Utc>), AuthoritySig>,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — structural
    /// mirror, keyed like `federation_community_membership_revocations`.
    federation_community_membership_revocation_authority_sigs:
        HashMap<(String, String, chrono::DateTime<chrono::Utc>), AuthoritySig>,
    /// v48.0.0 (#860) — keyed like `federation_community_membership_widenings`.
    federation_community_membership_widening_authority_sigs:
        HashMap<(String, String, chrono::DateTime<chrono::Utc>), AuthoritySig>,
    /// v49.0.0 (CIRISPersist#908, V153 mirror) — the co-signatures the door
    /// verified, keyed like `federation_family_membership_revocations`.
    /// Absent ⇒ none (a single-signed row).
    federation_family_membership_revocation_cosignatures: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        Vec<crate::federation::RosterCosignature>,
    >,
    /// v49.0.0 (#910) — keyed like `federation_family_membership_widenings`.
    federation_family_membership_widening_cosignatures: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        Vec<crate::federation::RosterCosignature>,
    >,
    /// v49.0.0 (CIRISPersist#908, V153 mirror) — keyed like
    /// `federation_community_membership_revocations`.
    federation_community_membership_revocation_cosignatures: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        Vec<crate::federation::RosterCosignature>,
    >,
    /// v49.0.0 (CIRISPersist#908, V153 mirror) — keyed like
    /// `federation_community_membership_widenings`.
    federation_community_membership_widening_cosignatures: HashMap<
        (String, String, chrono::DateTime<chrono::Utc>),
        Vec<crate::federation::RosterCosignature>,
    >,
    /// v21.0.0 (CIRISPersist#502 E4 followup, V110 mirror) — structural
    /// mirror, keyed like `federation_location_proofs`.
    federation_location_proof_authority_sigs:
        HashMap<(String, chrono::DateTime<chrono::Utc>), AuthoritySig>,
    /// v21.1.0 (CIRISPersist#507b, V111 mirror) — the shared signed-wire
    /// content-hash index: `(kind, content_hash) -> record_key`. Memory
    /// mirror of the `signed_wire_index` table.
    signed_wire_index: HashMap<(String, String), String>,
    /// CIRISPersist#785 — mirror of the `known_wire_hashes` table:
    /// records this node has HEARD EXIST and deliberately does not hold.
    ///
    /// A SEPARATE map from `signed_wire_index` above, for the same reason the
    /// SQL backends use a separate table: if a known-but-not-held hash ever
    /// reaches the holdings read, the node concludes it already has
    /// everything it has merely heard of and silently stops fetching. Note
    /// the value shapes differ too — the wire index stores a `record_key`
    /// pointing at a held row, which these entries have no such thing as.
    known_wire_hashes: HashMap<(String, String), (chrono::DateTime<chrono::Utc>, Option<String>)>,
    /// v45.0.0 (CIRISPersist#871, V149 mirror) — the `blob_renditions`
    /// projection: one row per admitted attestation whose `media.derived_from`
    /// is set, keyed by `rendition_sha256_hex`. Maintained by
    /// [`project_rendition_row`] in the same lock as the row insert and
    /// removed by the retraction fold that retires the source row.
    blob_renditions: Vec<crate::federation::renditions::Rendition>,
}

/// v21.0.0 (CIRISPersist#502 E7) — one row of the in-memory
/// `consent_peer_set` mirror. Mirrors the V109 table shape exactly.
#[derive(Clone)]
struct ConsentPeerForRow {
    author_key_id: String,
    for_key_id: String,
    peer_key_id: String,
    source_attestation_id: String,
}

#[derive(Clone)]
struct ConsentPeerRow {
    node_key_id: String,
    /// v48.0.0 (#905, V152) — the machine the grant is FOR (a self-grant:
    /// its author); part of the key.
    for_key_id: String,
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

/// v31.4.0 (CIRISPersist#682) — this node's position on one key row.
///
/// The memory analogue of the V126 column, and of the sqlite dialect's
/// `COALESCE(admitted_at, scrub_timestamp)`: a row that reached the map without
/// a stamp falls back to the producer's instant, which is what the V126
/// backfill writes for rows that predate the column. Defined once because the
/// serve cursor and the allocator MUST read the same expression — an allocator
/// blind to a position the cursor can see would hand out a value below it, and
/// the row stamped with that value would sort behind a cursor that had already
/// passed. That is #682 itself, re-entering through the allocator.
fn key_record_position(
    state: &State,
    record: &crate::federation::KeyRecord,
) -> chrono::DateTime<chrono::Utc> {
    let admitted = state
        .key_record_admitted_at
        .get(&record.key_id)
        .copied()
        .unwrap_or(record.scrub_timestamp);
    // v36.0.0 (CIRISPersist#707) — the serve position is the GREATER of the
    // admission position and the last consumer-visible mutation, the memory
    // analogue of the SQL `GREATEST(admitted_at, mutated_at)` / V131
    // expression. A mutated row moves FORWARD in the stream.
    match state.key_record_mutated_at.get(&record.key_id).copied() {
        Some(mutated) if mutated > admitted => mutated,
        _ => admitted,
    }
}

/// v31.4.0 (CIRISPersist#682) — allocate THIS node's next admission position on
/// `federation_keys`. Memory twin of `SqliteBackend::next_key_admission_position`.
///
/// Strictly after the last position handed out rather than read off the wall
/// clock: a backward step (NTP correction, VM restore) would stamp a later row
/// below a position a consumer already passed, and `> since` would skip it
/// permanently. Callers hold the state lock, so allocation on this backend is
/// strictly increasing.
fn next_key_admission_position(state: &State) -> chrono::DateTime<chrono::Utc> {
    let last = state
        .federation_keys
        .values()
        .map(|k| key_record_position(state, k))
        .max();
    crate::federation::types::monotonic_admission_instant(chrono::Utc::now(), last)
}

// ─── v36.0.0 (CIRISPersist#668) — the V130 serve-position machinery, memory
//     twin. Plane tokens are the wire-index kind strings, so the side map
//     reads like the shared index does.

const PLANE_ORGANIZATION: &str = "Organization";
const PLANE_ORG_MEMBERSHIP: &str = "OrgMembership";
const PLANE_PARTNER_RECORD: &str = "PartnerRecord";
const PLANE_FAMILY: &str = "Family";
const PLANE_COMMUNITY: &str = "Community";
const PLANE_LOCATION_PROOF: &str = "LocationProof";
const PLANE_FAMILY_MEMBERSHIP_REVOCATION: &str = "FamilyMembershipRevocation";
const PLANE_COMMUNITY_MEMBERSHIP_REVOCATION: &str = "CommunityMembershipRevocation";
const PLANE_COMMUNITY_MEMBERSHIP_WIDENING: &str = "CommunityMembershipWidening";
const PLANE_FAMILY_MEMBERSHIP_WIDENING: &str = "FamilyMembershipWidening";
const PLANE_COMMUNITY_MEMBERSHIP_LISTING: &str = "CommunityMembershipListing";
const PLANE_IDENTITY_OCCURRENCE: &str = "IdentityOccurrence";
const PLANE_IDENTITY_OCCURRENCE_REVOCATION: &str = "IdentityOccurrenceRevocation";
const PLANE_TRANSPORT_DESTINATION: &str = "TransportDestination";
const PLANE_ATTESTATION: &str = "Attestation";

/// One row's serve position: the stamped V130 instant, or the plane's legacy
/// producer instant when no stamp exists — the memory analogue of
/// `COALESCE(admitted_at, <legacy>)`, defined once because the cursor and
/// the allocator MUST read the same expression (#682's invariant).
fn plane_position(
    state: &State,
    plane: &'static str,
    id: &str,
    fallback: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    state
        .serve_positions
        .get(plane)
        .and_then(|m| m.get(id))
        .copied()
        .unwrap_or(fallback)
}

/// Allocate the next serve position on one plane, strictly above every
/// position already handed out. `rows` yields `(resume_id, legacy fallback)`
/// for every stored row of the plane, so the allocator sees exactly what the
/// cursor sees. Callers hold the state lock, so allocation is strictly
/// increasing on this backend.
fn next_plane_position(
    state: &State,
    plane: &'static str,
    rows: impl Iterator<Item = (String, chrono::DateTime<chrono::Utc>)>,
) -> chrono::DateTime<chrono::Utc> {
    let last = rows
        .map(|(id, fallback)| plane_position(state, plane, &id, fallback))
        .max();
    crate::federation::types::monotonic_admission_instant(chrono::Utc::now(), last)
}

/// Stamp (or RE-stamp, for a consumer-visible rewrite — #707's class) one
/// row's serve position.
fn stamp_plane_position(
    state: &mut State,
    plane: &'static str,
    id: String,
    at: chrono::DateTime<chrono::Utc>,
) {
    state
        .serve_positions
        .entry(plane)
        .or_default()
        .insert(id, at);
}

/// Allocate-and-stamp in one call, for the common door shape: compute the
/// next position over the plane's CURRENT rows (immutable pass), then stamp
/// `id` with it (mutable pass). Callers hold the state lock throughout, so
/// the two passes are one atomic step from any reader's point of view.
fn allocate_and_stamp(
    state: &mut State,
    plane: &'static str,
    id: String,
    rows: Vec<(String, chrono::DateTime<chrono::Utc>)>,
) -> chrono::DateTime<chrono::Utc> {
    let at = next_plane_position(state, plane, rows.into_iter());
    stamp_plane_position(state, plane, id, at);
    at
}

/// The `(resume id, legacy fallback)` inventory per plane — what the
/// allocator reads so it sees exactly what the cursor sees.
fn organization_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_organizations
        .values()
        .map(|o| (o.attestation_id.clone(), o.asserted_at))
        .collect()
}
fn org_membership_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_org_memberships
        .values()
        .map(|m| (m.attestation_id.clone(), m.asserted_at))
        .collect()
}
fn partner_record_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_partner_records
        .values()
        .map(|p| (p.attestation_id.clone(), p.asserted_at))
        .collect()
}
fn family_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_families
        .values()
        .map(|f| (f.family_key_id.clone(), f.founded_at))
        .collect()
}
fn community_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_communities
        .values()
        .map(|c| (c.community_key_id.clone(), c.founded_at))
        .collect()
}
fn location_proof_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_location_proofs
        .values()
        .map(|p| {
            (
                crate::federation::types::compound_resume_id(&[
                    &p.subject_key_id,
                    &p.persist_row_hash,
                ]),
                p.asserted_at,
            )
        })
        .collect()
}
fn family_membership_revocation_rows(
    state: &State,
) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_family_membership_revocations
        .values()
        .map(|r| {
            (
                crate::federation::types::compound_resume_id(&[
                    &r.family_key_id,
                    &r.removed_identity_key_id,
                    &r.effective_at.to_rfc3339(),
                ]),
                r.removed_at,
            )
        })
        .collect()
}
/// v49.0.0 (#912) — every listing row is stamped at admission; the fallback
/// (its `effective_at`) is never read.
fn community_membership_listing_rows(
    state: &State,
) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_community_membership_listings
        .values()
        .map(|l| {
            let l = &l.community_membership_listing;
            (
                crate::federation::types::compound_resume_id(&[
                    &l.community_key_id,
                    &l.member_key_id,
                    &l.effective_at.to_rfc3339(),
                ]),
                l.effective_at,
            )
        })
        .collect()
}
fn family_membership_widening_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_family_membership_widenings
        .values()
        .map(|w| {
            (
                crate::federation::types::compound_resume_id(&[
                    &w.family_key_id,
                    &w.member_key_id,
                    &w.effective_at.to_rfc3339(),
                ]),
                w.joined_at,
            )
        })
        .collect()
}
fn community_membership_revocation_rows(
    state: &State,
) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_community_membership_revocations
        .values()
        .map(|r| {
            (
                crate::federation::types::compound_resume_id(&[
                    &r.community_key_id,
                    &r.removed_identity_key_id,
                ]),
                r.removed_at,
            )
        })
        .collect()
}
fn community_membership_widening_rows(
    state: &State,
) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_community_membership_widenings
        .values()
        .map(|w| {
            (
                crate::federation::types::compound_resume_id(&[
                    &w.community_key_id,
                    &w.member_key_id,
                    &w.effective_at.to_rfc3339(),
                ]),
                w.joined_at,
            )
        })
        .collect()
}
fn identity_occurrence_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_identity_occurrences
        .values()
        .map(|o| {
            (
                crate::federation::types::compound_resume_id(&[
                    &o.identity_key_id,
                    &o.occurrence_key_id,
                ]),
                o.asserted_at,
            )
        })
        .collect()
}
fn identity_occurrence_revocation_rows(
    state: &State,
) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_identity_occurrence_revocations
        .values()
        .map(|r| {
            (
                crate::federation::types::compound_resume_id(&[
                    &r.identity_key_id,
                    &r.occurrence_key_id,
                ]),
                r.revoked_at,
            )
        })
        .collect()
}
fn transport_destination_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .transport_destinations
        .values()
        .map(|t| {
            (
                crate::federation::types::compound_resume_id(&[
                    &t.occurrence_key_id,
                    &t.transport_kind,
                ]),
                t.asserted_at,
            )
        })
        .collect()
}
/// v54.1.0 (Codex round 4 on PR #1057) — the memory twin of
/// `steward_purge::person_subject_sql`: does a held key that is a person
/// (`identity_type_is_person`) appear among `row`'s subjects
/// (`subject_key_ids`, `attested_key_id`)?
fn mem_person_subject(state: &State, row: &crate::federation::Attestation) -> bool {
    row.subject_key_ids
        .iter()
        .chain(std::iter::once(&row.attested_key_id))
        .filter(|k| !k.is_empty())
        .any(|k| {
            state.federation_keys.get(k).is_some_and(|r| {
                crate::federation::steward_purge::identity_type_is_person(&r.identity_type)
            })
        })
}

/// v45.0.0 (CIRISPersist#871, FSD §5) — maintain the V149 `blob_renditions`
/// mirror for `row` under the state lock the caller already holds: when
/// [`crate::federation::renditions::rendition_of_row`] answers `Some`, upsert
/// it keyed by `rendition_sha256_hex` (the SQL backends' `ON CONFLICT`).
/// A row that projects nothing is left alone.
///
/// **Call sites (the door bodies, in the SAME lock as the row insert):**
/// `put_attestation_with_origin` and `memory_write_local_attestation`. The
/// promotion door (`enter_mesh`) updates the row IN PLACE under its id, so the
/// projection written at the local door is already the federation row's. The
/// retraction fold that removes a row's projection lives with
/// `consent_peer_set`'s in `put_attestation_with_origin`, the local
/// upsert-replace retires the replaced row's, and
/// `purge_attestation_projections` the purged row's.
fn project_rendition_row(state: &mut State, row: &crate::federation::Attestation) {
    if let Some(r) = crate::federation::renditions::rendition_of_row(row) {
        state
            .blob_renditions
            .retain(|e| e.rendition_sha256_hex != r.rendition_sha256_hex);
        state.blob_renditions.push(r);
    }
}

fn attestation_rows(state: &State) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    state
        .federation_attestations
        .iter()
        .map(|a| {
            (
                a.attestation_id.clone(),
                a.promoted_at.unwrap_or(a.asserted_at),
            )
        })
        .collect()
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                lineage_head_cosigns: Default::default(),
                events: HashMap::new(),
                llm_calls: Vec::new(),
                purge_executions: std::collections::BTreeMap::new(),
                purge_tombstones: std::collections::BTreeMap::new(),
                next_event_id: 1,
                keys: HashMap::new(),
                federation_keys: HashMap::new(),
                federation_attestations: Vec::new(),
                federation_withdraws_admission_depths: HashMap::new(),
                federation_trust_direction_held: std::collections::HashSet::new(),
                subject_index: HashMap::new(),
                announced_peers: HashMap::new(),
                federation_revocations: Vec::new(),
                revocation_admitted_at: HashMap::new(),
                key_record_admitted_at: HashMap::new(),
                key_record_mutated_at: HashMap::new(),
                key_registration_history: HashMap::new(),
                serve_positions: HashMap::new(),
                federation_trust: HashMap::new(),
                outbound_queue: HashMap::new(),
                federation_goals: std::collections::BTreeMap::new(),
                federation_peer_metadata: HashMap::new(),
                federation_identity_occurrences: HashMap::new(),
                federation_identity_occurrence_history: Vec::new(),
                self_roster_proposals: std::collections::BTreeMap::new(),
                federation_identity_occurrence_sigs: HashMap::new(),
                federation_families: HashMap::new(),
                federation_communities: HashMap::new(),
                federation_group_current_version: HashMap::new(),
                federation_group_versions: HashMap::new(),
                federation_identity_occurrence_revocations: HashMap::new(),
                federation_family_membership_revocations: HashMap::new(),
                federation_family_membership_widenings: HashMap::new(),
                federation_community_membership_listings: HashMap::new(),
                federation_community_membership_revocations: HashMap::new(),
                federation_community_membership_widenings: HashMap::new(),
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
                cirisnode_ledgers: std::collections::BTreeMap::new(),
                derived_detection_events: HashMap::new(),
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
                canonical_withdrawals: HashMap::new(),
                role_withdrawals: HashMap::new(),
                consent_peer_set: Vec::new(),
                consent_peer_set_for: Vec::new(),
                federation_family_authority_sigs: HashMap::new(),
                federation_community_authority_sigs: HashMap::new(),
                federation_family_supersede_proofs: HashMap::new(),
                federation_family_cosignatures: HashMap::new(),
                federation_community_supersede_proofs: HashMap::new(),
                federation_community_cosignatures: HashMap::new(),
                federation_community_lineages: HashMap::new(),
                federation_family_membership_revocation_authority_sigs: HashMap::new(),
                federation_family_membership_widening_authority_sigs: HashMap::new(),
                federation_community_membership_revocation_authority_sigs: HashMap::new(),
                federation_community_membership_widening_authority_sigs: HashMap::new(),
                federation_family_membership_revocation_cosignatures: HashMap::new(),
                federation_family_membership_widening_cosignatures: HashMap::new(),
                federation_community_membership_revocation_cosignatures: HashMap::new(),
                federation_community_membership_widening_cosignatures: HashMap::new(),
                federation_location_proof_authority_sigs: HashMap::new(),
                signed_wire_index: HashMap::new(),
                known_wire_hashes: HashMap::new(),
                blob_renditions: Vec::new(),
            }),
            hardware_attestation_policy: std::sync::RwLock::new(std::sync::Arc::new(
                crate::federation::HardwareAttestationPolicy::default(),
            )),
            node_key_id: std::sync::RwLock::new(None),
            withdraws_delegation_depth: std::sync::atomic::AtomicUsize::new(
                crate::federation::topology::DEFAULT_DELEGATION_DEPTH,
            ),
            admission_gate: std::sync::RwLock::new(None),
            trust_root_standing_cache: Default::default(),
            delegation_write_lock: tokio::sync::Mutex::new(()),
            wire_index_locks: Default::default(),
            #[cfg(test)]
            test_hooks: Default::default(),
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
    /// v50.0.0 (PR #921 review) — the test-only hook table (see
    /// [`crate::store::test_hooks`]).
    #[cfg(test)]
    #[allow(dead_code)] // unarmed under the `server`-only axis
    pub(crate) fn test_hooks(&self) -> &crate::store::test_hooks::TestHooks {
        &self.test_hooks
    }

    /// v58.0.0 (CIRISPersist#1094, I967) — TEST SEAM: the key's record expired
    /// a day ago (a host that no longer holds a live producer key).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn test_expire_key(&self, key_id: &str) {
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(rec) = state.federation_keys.get_mut(key_id) {
            rec.valid_until = Some(chrono::Utc::now() - chrono::Duration::days(1));
        }
    }

    /// v57.0.0 (CIRISPersist#988, I960) — a `hard_case_events` entry no row
    /// produces: the projection witness's red on the backend with no SQL.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn test_insert_orphan_hard_case_projection(&self, event_id: &str) {
        let mut state = self.state.lock().expect("memory backend lock");
        state.federation_hard_case_events.insert(
            event_id.to_owned(),
            (
                format!("{event_id}-no-row"),
                crate::federation::hard_case::HardCaseEvent {
                    event_id: event_id.to_owned(),
                    kind: "orphan".into(),
                    target_key_id: None,
                    subject_key_id: None,
                    detail: serde_json::json!({}),
                    emitted_at: chrono::Utc::now(),
                    emitter_key_id: String::new(),
                },
            ),
        );
    }

    /// v54.1.0 (CIRISPersist#1044, I621) — hold a key row past every
    /// `put_public_key` gate, as a node that admitted it under an older rule
    /// does. Test-only: the role-gated rows a witness needs cannot clear the
    /// production-roster gate.
    #[cfg(test)]
    #[allow(dead_code)] // the witness that calls it needs postgres or sqlite
    pub(crate) fn seed_key_row_unchecked_for_test(&self, mut row: crate::federation::KeyRecord) {
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)
            .expect("seeded key row hashes");
        self.state
            .lock()
            .expect("memory backend lock")
            .federation_keys
            .insert(row.key_id.clone(), row);
    }

    /// v50.0.0 (PR #921 review) — the test-only rival write armed for `at`
    /// (see [`crate::store::test_hooks`]), applied through this backend's own
    /// replicated door. Never armed outside a test.
    #[cfg(test)]
    async fn test_rival_at(
        &self,
        at: crate::store::test_hooks::RivalPoint,
    ) -> Result<(), crate::federation::Error> {
        if let Some(rival) = self.test_hooks.take_rival_at(at) {
            Box::pin(crate::federation::community_admit::put_community_planned(
                self,
                rival,
                crate::federation::CommunityDoor::ReplicatedApply,
            ))
            .await?;
        }
        Ok(())
    }

    /// v54.1.0 (CIRISPersist#1040) — TEST SEAM: store `identity_type` on a
    /// held key row as if the role had been conferred at its door (the
    /// conferral itself is the canonical gate's, witnessed by I190 and the
    /// #372 tests). Nothing else moves.
    #[cfg(any(test, feature = "test-anchor"))]
    pub async fn test_seam_set_key_identity_type(
        &self,
        key_id: &str,
        identity_type: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(r) = state.federation_keys.get_mut(key_id) {
            r.identity_type = identity_type.to_owned();
        }
        Ok(())
    }

    /// v54.1.0 (Codex on PR #1057) — TEST SEAM: drop one stored tombstone of
    /// a notice, reproducing a header whose set is partial (the state the
    /// pre-fix, non-atomic write could leave). Nothing else moves.
    #[cfg(test)]
    pub async fn test_seam_drop_purge_tombstone(
        &self,
        notice_id: &str,
        plane: &str,
        record_ref: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        state.purge_tombstones.remove(&(
            notice_id.to_owned(),
            plane.to_owned(),
            record_ref.to_owned(),
        ));
        Ok(())
    }

    /// v54.1.0 (CIRISPersist#1043) — TEST SEAM: reproduce a legacy row the
    /// apply door refuses today (#598 "typed asserted_at diverges from the
    /// signed envelope"): move the typed `asserted_at` column off the signed
    /// instant. Nothing else moves.
    #[cfg(any(test, feature = "test-anchor"))]
    pub async fn test_seam_set_attestation_asserted_at(
        &self,
        attestation_id: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(a) = state
            .federation_attestations
            .iter_mut()
            .find(|a| a.attestation_id == attestation_id)
        {
            a.asserted_at = asserted_at;
        }
        Ok(())
    }

    /// v55.0.0 (CIRISPersist#989) — TEST SEAM: reproduce a row of a type no
    /// door admits today (a retired `holds_bytes` carrier a node still holds):
    /// rewrite the typed `attestation_type`. Nothing else moves.
    #[cfg(any(test, feature = "test-anchor"))]
    pub async fn test_seam_set_attestation_type(
        &self,
        attestation_id: &str,
        attestation_type: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(a) = state
            .federation_attestations
            .iter_mut()
            .find(|a| a.attestation_id == attestation_id)
        {
            a.attestation_type = attestation_type.to_owned();
        }
        Ok(())
    }

    /// v54.0.0 (CIRISPersist#995 row 2) — TEST SEAM: reproduce what a
    /// pre-v53.1.4 UPDATE door left behind: `additional_scrubs` emptied while
    /// `persist_row_hash` still binds the full record. Nothing else moves.
    #[cfg(any(test, feature = "test-anchor"))]
    pub async fn test_seam_drop_key_additional_scrubs(
        &self,
        key_id: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(r) = state.federation_keys.get_mut(key_id) {
            r.additional_scrubs.clear();
        }
        Ok(())
    }

    /// Create an empty memory backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// #973 — record `attestation_id` as an unlabelled `delegates_to` this
    /// backend held before the "bundle only" rule (what V167 records on the
    /// SQL backends at upgrade). A memory backend never upgrades, so this is
    /// the only way its tests reach the held-row arm.
    #[cfg(any(test, feature = "test-anchor"))]
    pub fn mark_trust_direction_held(&self, attestation_id: &str) {
        self.state
            .lock()
            .expect("memory backend lock")
            .federation_trust_direction_held
            .insert(attestation_id.to_owned());
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
    /// v36.0.0 (CIRISPersist#668) — **a failure here is LOUD, never fatal**,
    /// matching the SQL twins: the primary write is already durable, so an
    /// index error must not be reported as a write failure the caller cannot
    /// repair (the admission gates refuse an identical resubmission). Memory's
    /// own upsert is infallible; the reload through the read path is the only
    /// thing that can error, and it is logged rather than propagated so the
    /// contract is uniform across all three backends.
    pub(crate) async fn index_stored_record(
        &self,
        kind: &str,
        record_key_json: &str,
    ) -> Result<(), crate::federation::Error> {
        // v54.0.0 (Codex on PR #1050) — the read and the replacement are ONE step
        // per record (the SQL twins' reason): the state lock is released between
        // the reload and the upsert, so the record's stripe spans both.
        let _stripe = self.wire_index_locks.lock(kind, record_key_json).await;
        match crate::federation::wire_index::entry_as_stored(self, kind, record_key_json).await {
            Ok(Some(content_hash)) => {
                #[cfg(test)]
                self.test_hooks()
                    .pause_if_armed("wire_index_before_write")
                    .await;
                let mut state = self.state.lock().expect("memory backend lock");
                memory_upsert_wire_index(
                    &mut state.signed_wire_index,
                    kind,
                    content_hash,
                    record_key_json,
                );
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(
                    kind,
                    record_key = record_key_json,
                    error = %e,
                    "signed_wire_index update failed AFTER a durable primary write (#668): the \
                     row is stored but absent from incremental content-hash lookup until \
                     rebuild_signed_wire_index or the self-healing point read repairs it"
                );
            }
        }
        Ok(())
    }

    /// v31.0.0 (CIRISPersist#646) — the Key-plane shorthand for
    /// [`index_stored_record`](Self::index_stored_record).
    async fn index_stored_key_row(&self, key_id: &str) -> Result<(), crate::federation::Error> {
        // v58.0.0 (CIRISPersist#991) — the key's record rides as its
        // `key:record:v1` row: the entry is that row's (the Attestation kind).
        let row_id = {
            let state = self.state.lock().expect("memory backend lock");
            state
                .federation_attestations
                .iter()
                .find(|a| is_key_record_row_of(a, key_id))
                .map(|a| a.attestation_id.clone())
        };
        self.index_plane_row(row_id.as_deref()).await
    }

    /// v58.0.0 (CIRISPersist#991) — index a key-plane row on the Attestation
    /// kind.
    async fn index_plane_row(
        &self,
        attestation_id: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        let Some(id) = attestation_id else {
            return Ok(());
        };
        self.index_stored_record(
            "Attestation",
            &crate::federation::wire_index::record_key(&[("attestation_id", id)]),
        )
        .await
    }

    /// (CIRISPersist#593) — snapshot `(list_attestations_by,
    /// list_attestations_for)` call counts for this instance.
    ///
    /// v56.0.0 (CIRISPersist#1001) — counted in `execute_attestation_query`:
    /// one per STATEMENT (page) of a typed read pinned on `by` / `to` (a query
    /// pinning both counts in both). A slice read across `k` pages counts `k`.
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

    /// v50.0.0 (CIRISPersist#928, review H2) — the host's explicit opt-in to
    /// a deeper `withdraws` proxy walk (CC 4.1.1 "configurable"), clamped at
    /// the 16 ceiling. The depth is recorded with every `withdraws` admitted
    /// under it, and the read-time re-derivation walks at the ROW's depth.
    pub fn set_withdraws_delegation_depth(&self, depth: usize) {
        self.withdraws_delegation_depth.store(
            crate::federation::effective_delegation_depth(Some(depth)),
            std::sync::atomic::Ordering::Relaxed,
        );
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

    /// v55.0.0 (CIRISPersist#989, test only) — hold an attestation BELOW
    /// every admission gate, at the next serve position: the memory twin of
    /// a raw `INSERT`, for the witness that a row an older build admitted (a
    /// retired carrier) is never served. Never reachable outside `cfg(test)`.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn plant_attestation_below_the_door(&self, row: crate::federation::Attestation) {
        let mut state = self.state.lock().expect("memory backend lock");
        let admitted_at = next_plane_position(
            &state,
            PLANE_ATTESTATION,
            attestation_rows(&state).into_iter(),
        );
        let id = row.attestation_id.clone();
        state.federation_attestations.push(row);
        stamp_plane_position(&mut state, PLANE_ATTESTATION, id, admitted_at);
    }

    /// v50.0.0 (CIRISPersist#926, test only) — store a signed community row
    /// BELOW every admission gate: the memory twin of a raw `INSERT`, for the
    /// witness that a pre-v50 row the trust-root door never judged is not
    /// honoured. Never reachable outside `cfg(test)`.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn plant_community_below_the_door(
        &self,
        signed: crate::federation::SignedCommunity,
    ) {
        let mut state = self.state.lock().expect("memory backend lock");
        let mut row = signed.community;
        row.persist_row_hash =
            crate::federation::types::compute_persist_row_hash(&row).expect("row hash");
        let id = row.community_key_id.clone();
        if let Some(p) = signed.supersede_proof {
            state
                .federation_community_supersede_proofs
                .insert(id.clone(), p);
        }
        state.federation_community_authority_sigs.insert(
            id.clone(),
            (
                signed.authority_key_id,
                signed.scrub_signature_classical,
                signed.scrub_signature_pqc,
            ),
        );
        let admitted_at =
            next_plane_position(&state, PLANE_COMMUNITY, community_rows(&state).into_iter());
        state.federation_communities.insert(id.clone(), row);
        stamp_plane_position(&mut state, PLANE_COMMUNITY, id, admitted_at);
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
        // v60.0.0 (CIRISPersist#934 step 3) — the shared plan, one insert per record.
        crate::federation::key_plane::seed_genesis_accord_holders_planned(self, records).await
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

    /// CIRISPersist#789 — register a key WITH its ML-DSA-65 pubkey.
    ///
    /// The fleet is 100% PQC, and since #789 admission resolves a producer's
    /// PQC pubkey from `federation_keys` by `pqc_key_id` rather than trusting
    /// the copy carried on the payload. A fixture that registers only an
    /// Ed25519 half is therefore modelling a world that does not exist, and
    /// its traces are refused — correctly.
    pub fn add_pqc_public_key(&self, key_id: &str, pqc_pubkey_b64: &str) {
        let mut state = self.state.lock().expect("memory backend lock");
        let now = chrono::Utc::now();
        let rec = crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: String::new(),
            pubkey_ml_dsa_65_base64: Some(pqc_pubkey_b64.to_owned()),
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::AGENT.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "key_id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2ln".to_owned(),
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
        // v31.4.0 (CIRISPersist#682) — stamped through the same allocator as
        // the real door. A helper that writes the row but skips the position
        // would make memory the one backend where the column is optional, which
        // is the divergence class this repo keeps paying for.
        let admitted_at = next_key_admission_position(&state);
        state
            .key_record_admitted_at
            .insert(key_id.to_owned(), admitted_at);
        state.federation_keys.insert(key_id.to_owned(), rec);
        // Keep the legacy map populated too — some tests still
        // reference it via `state.keys`. Single source of truth at
        // verify is federation_keys; this is just bookkeeping.
        state.keys.insert(key_id.to_owned(), key);
    }

    /// v37.0.0 — test helper to attach an ML-DSA-65 public key to an
    /// existing `federation_keys` row, making that key hybrid-complete.
    ///
    /// [`add_public_key`](Self::add_public_key) writes
    /// `pubkey_ml_dsa_65_base64: None` — a hybrid-PENDING row. That was
    /// sufficient while the production write paths verified under
    /// `HybridPolicy::Ed25519Fallback`; the v37.0.0 flip to
    /// `HybridPolicy::Strict` means a fixture key with no PQC half can no
    /// longer sign anything those paths will accept. Tests that need an
    /// ACCEPTED write call this after `add_public_key`; tests that need
    /// the refusal simply don't.
    ///
    /// Panics if the key isn't already present, matching
    /// [`set_roles`](Self::set_roles)'s contract.
    pub fn set_pqc_pubkey(&self, key_id: &str, pubkey_ml_dsa_65_base64: &str) {
        let mut state = self.state.lock().expect("memory backend lock");
        let rec = state
            .federation_keys
            .get_mut(key_id)
            .expect("set_pqc_pubkey: key_id must exist via add_public_key first");
        rec.pubkey_ml_dsa_65_base64 = Some(pubkey_ml_dsa_65_base64.to_owned());
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
            prev_head_digest: String::new(),
            charter_digest: String::new(),
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
        // ACTIVE binding only (PR #761 review) — a revoked occurrence falls
        // back to its singleton identity, severing inherited membership.
        let identity = self
            .active_identity_for_occurrence(occurrence_key_id)
            .await
            .map_err(|e| Error::Backend(format!("resolve_identity_for_occurrence: {e}")))?;
        Ok((identity != occurrence_key_id).then_some(identity))
    }

    /// v4.0 (CIRISPersist#160, FSD §4.6) — family-half of the writer
    /// admission; delegates to the `FederationDirectory` fan-out.
    async fn admission_family_key_ids(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<String>, Error> {
        use crate::federation::FederationDirectory;
        // v38.2.0 (#757 follow-on) — the ACTIVE fold, not raw containment:
        // see `FederationDirectory::active_community_key_ids_for`.
        self.active_family_key_ids_for(member_identity_key_id)
            .await
            .map_err(|e| Error::Backend(format!("admission_family_key_ids: {e}")))
    }

    /// v4.0 (CIRISPersist#160, FSD §4.6) — community-half of the writer
    /// admission; delegates to the `FederationDirectory` fan-out.
    async fn admission_community_key_ids(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<String>, Error> {
        use crate::federation::FederationDirectory;
        // v38.2.0 (#757 follow-on) — same ONE fold as the write gate.
        self.active_community_key_ids_for(member_identity_key_id)
            .await
            .map_err(|e| Error::Backend(format!("admission_community_key_ids: {e}")))
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
        // v32.1.0 (CIRISPersist#606) — ONE admission instant for the whole
        // batch, allocated under the same lock the insert holds.
        //
        // Memory must match the SQL backends here or the witnesses that run on
        // all three stop meaning the same thing — this backend tolerates what
        // sqlite and postgres reject, which is exactly how a parity gap hides.
        // Same allocator, same reason: `MAX(admitted_at)` is the liveness
        // reading, so a backward clock step must still advance it rather than
        // freezing the max and reading dark while traces land.
        let last_admitted = state
            .events
            .values()
            .filter_map(|(_, r)| r.admitted_at)
            .max();
        let admitted_at = crate::federation::types::monotonic_admission_instant(
            chrono::Utc::now(),
            last_admitted,
        );

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
                // A re-delivery is not an arrival: the existing row keeps its
                // instant, mirroring `ON CONFLICT ... DO NOTHING`. Refreshing
                // it here would make a stuck producer replaying old batches
                // look live, which is the failure this column exists to end.
                conflicted += 1;
                continue;
            }
            let event_id = state.next_event_id;
            state.next_event_id += 1;
            let mut stored = row.clone();
            // Stamped by the backend, overwriting whatever the caller set — a
            // producer must not be able to assert when THIS node received it.
            stored.admitted_at = Some(admitted_at);
            state.events.insert(key, (event_id, stored));
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
        // v57.0.0 (CIRISPersist#988 item 2) — the audit row's attester, read
        // before the lock (the SQL backends read it before their transaction).
        // An act: refused, typed, before anything moves when this node cannot
        // attest its audit row (CIRISPersist#988 ruling: a host must hold a
        // node key before any erasure is recorded).
        let attester = crate::federation::attestation_admit::hard_case_attester(self)
            .await
            .map_err(Error::from_hard_case_attester)?;
        // v58.0.0 (CIRISPersist#1094 item 2, CC 4.5.3) — each reached row
        // erased under its producer's rule-1 `withdraws`, or refused with a
        // reason; read before the lock.
        let received_at = chrono::Utc::now();
        let crate::federation::subject_erasure::ErasurePlan {
            citations,
            new_withdraws,
            refused,
        } = crate::federation::subject_erasure::plan_store_erasure(
            self,
            agent_id_hash,
            Some(signature_key_id),
            received_at,
        )
        .await
        .map_err(|e| Error::Backend(format!("erasure plan: {e}")))?;
        let refused_count = refused.len() as u64;
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
        // v58.0.0 (CIRISPersist#1094 item 2) — the row-backed detections
        // their producers' `withdraws` cover are hard-deleted and leave no
        // projection row. Found BEFORE anything moves.
        let erased_rows = memory_held_citations(&state, &citations);
        let detection_events_tombstoned = erased_rows.len() as u64;

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
            // v52.0.0 (#784) — a revocation OF one of these keys is found by
            // its subject digest, whatever label (if any) it named.
            let target_digests: Vec<String> = target_key_ids
                .iter()
                .filter_map(|k| state.federation_keys.get(k))
                .filter_map(|rec| {
                    crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
                        &rec.pubkey_ed25519_base64,
                    )
                    .ok()
                    .map(|d| d.to_hex())
                })
                .collect();
            state.federation_revocations.retain(|r| {
                !(r.revoked_key_id
                    .as_ref()
                    .is_some_and(|k| target_key_ids.contains(k))
                    || target_digests.contains(&r.revoked_key_sha256_ed25519_raw)
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
            prune_row_projections(&mut state);

            // Now safe to delete the federation_keys rows.
            let keys_before = state.federation_keys.len();
            state
                .federation_keys
                .retain(|k, _| !target_key_ids.contains(k));
            federation_keys_deleted = (keys_before - state.federation_keys.len()) as u64;
        }

        // v38.0.0 (#721) — announced, exactly like the SQL doors and the
        // Art.-17 sibling: this face deletes strictly MORE and was silent.
        if trace_events_deleted > 0
            || trace_llm_calls_deleted > 0
            || federation_keys_deleted > 0
            || federation_attestations_deleted > 0
            || federation_revocations_deleted > 0
            || detection_events_tombstoned > 0
        {
            // v58.0.0 (#1094 item 2, CC 4.5.3) — subject-free.
            let event = crate::federation::hard_case::trace_erasure_event(
                &crate::federation::hard_case::TraceErasureCounts {
                    op: crate::federation::hard_case::trace_erasure_op::ONE_KEY,
                    trace_events: trace_events_deleted,
                    trace_llm_calls: trace_llm_calls_deleted,
                    detection_events_tombstoned,
                    detection_rows_erased: erased_rows.len() as u64,
                    detection_rows_refused: refused_count,
                    federation_keys: federation_keys_deleted,
                    federation_attestations: federation_attestations_deleted,
                    federation_revocations: federation_revocations_deleted,
                },
                received_at,
            );
            let plan = memory_plan_erasure(&attester, &event, &erased_rows, received_at)
                .map_err(|e| Error::Backend(format!("dsar: {e}")))?;
            memory_apply_erasure(&mut state, &new_withdraws, &erased_rows, plan);
        }

        Ok(super::types::DeleteSummary {
            trace_events_deleted,
            trace_llm_calls_deleted,
            federation_keys_deleted,
            federation_attestations_deleted,
            federation_revocations_deleted,
            detection_rows_refused: refused,
            deleted_at: chrono::Utc::now(),
        })
    }

    async fn delete_traces_for_agent_id_hash(
        &self,
        agent_id_hash: &str,
    ) -> Result<super::types::ErasureSummary, Error> {
        // v57.0.0 (CIRISPersist#988 item 2) — the audit row's attester, read
        // before the lock. An act: refused, typed, before anything moves when
        // this node cannot attest its audit row (lead ruling: a host must hold
        // a node key before any erasure is recorded).
        let attester = crate::federation::attestation_admit::hard_case_attester(self)
            .await
            .map_err(Error::from_hard_case_attester)?;
        // v57.0.0 (#988 item 3) — a pre-v57 detection this node can attest
        // to its detector is moved onto the plane first (memory holds none:
        // a declared no-op, kept so the three doors read alike).
        {
            use crate::federation::attestation_admit::AttestationStore as _;
            self.rehome_legacy_detection_events(chrono::Utc::now())
                .await
                .map_err(|e| Error::Backend(format!("rehome before erasure: {e}")))?;
        }
        // v58.0.0 (CIRISPersist#1094 item 2, CC 4.5.3) — each reached row
        // erased under its producer's rule-1 `withdraws`, or refused with a
        // reason; read before the lock.
        let erased_at = chrono::Utc::now();
        let crate::federation::subject_erasure::ErasurePlan {
            citations,
            new_withdraws,
            refused,
        } = crate::federation::subject_erasure::plan_store_erasure(
            self,
            agent_id_hash,
            None,
            erased_at,
        )
        .await
        .map_err(|e| Error::Backend(format!("erasure plan: {e}")))?;
        let refused_count = refused.len() as u64;
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

        // Decided under the lock BEFORE anything moves (the SQL backends'
        // transaction): the counts, the detection rows, the audit row and its
        // tombstones. A refusal of the plan leaves everything as it was.
        let trace_events = state
            .events
            .values()
            .filter(|(_, row)| row.agent_id_hash == agent_id_hash)
            .count() as u64;
        let trace_llm_calls = state
            .llm_calls
            .iter()
            .filter(|row| target_trace_ids.contains(&row.trace_id))
            .count() as u64;
        // v58.0.0 (CIRISPersist#1094 item 2, CC 4.5.3) — a ROW-BACKED
        // detection is erased by its producer's rule-1 `withdraws`: each cited row is
        // HARD-DELETED, never rewritten, under a tombstone citing the
        // withdraws. Memory holds no pre-v57 silo rows.
        let erased_rows = memory_held_citations(&state, &citations);
        let detection_events_tombstoned = erased_rows.len() as u64;
        let plan = if trace_events > 0 || trace_llm_calls > 0 || detection_events_tombstoned > 0 {
            let event = crate::federation::hard_case::trace_erasure_event(
                &crate::federation::hard_case::TraceErasureCounts {
                    op: crate::federation::hard_case::trace_erasure_op::FULL,
                    trace_events,
                    trace_llm_calls,
                    detection_events_tombstoned,
                    detection_rows_erased: erased_rows.len() as u64,
                    detection_rows_refused: refused_count,
                    ..Default::default()
                },
                erased_at,
            );
            memory_plan_erasure(&attester, &event, &erased_rows, erased_at)
                .map_err(|e| Error::Backend(format!("erasure: {e}")))?
        } else {
            MemoryErasurePlan::default()
        };

        state
            .events
            .retain(|_, (_, row)| row.agent_id_hash != agent_id_hash);
        state
            .llm_calls
            .retain(|row| !target_trace_ids.contains(&row.trace_id));
        memory_apply_erasure(&mut state, &new_withdraws, &erased_rows, plan);

        Ok(super::types::ErasureSummary {
            trace_events,
            trace_llm_calls,
            detection_events_tombstoned,
            detection_rows_refused: refused,
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
    // v46.4.0 (CIRISPersist#891) — the cohort axes, the memory twin of
    // `sqlite_cohort_axes` / `pg_cohort_axes`.
    if let Some(cs) = &filter.cohort_scope {
        if &r.cohort_scope != cs {
            return false;
        }
    }
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
    // V4.4 §3 (PR #889 review) — a local-tier row is its producer's alone.
    if !scope.admits_local_tier(&r.tier, &r.attesting_key_id) {
        return false;
    }
    if let Some(AttesterSet::Explicit(keys)) = &filter.attester_filter {
        if !keys.iter().any(|k| k == &r.attesting_key_id) {
            return false;
        }
    }
    // §4.3 scope gate (target = attested_key_id, mirroring the SQL).
    // v46.5.0 (#893) — the memory twin of the per-arm target: the ROW's room
    // comes from the signed envelope, the same value V150 generates in SQL.
    // A malformed/split-brain envelope yields None, which refuses — the write
    // gate already refuses to store one.
    let room = crate::federation::admission::envelope_cohort_target(&r.attestation_envelope)
        .ok()
        .flatten();
    scope.admits(
        &r.cohort_scope,
        &r.attested_key_id,
        room,
        crate::federation::admission::envelope_dimension(&r.attestation_envelope),
    )
}

/// v56.0.0 (CIRISPersist#934 step 1) — the attestation plane's executor on
/// memory. Storage only: the decision is
/// [`plan_put_attestation`](crate::federation::attestation_admit::plan_put_attestation).
#[async_trait::async_trait]
impl crate::federation::attestation_admit::AttestationStore for MemoryBackend {
    fn admission_cx(&self) -> crate::federation::attestation_admit::AdmissionCx<'_> {
        crate::federation::attestation_admit::AdmissionCx {
            quota: &self.peer_write_quota,
            admission_gate: self.admission_gate(),
            self_key_id: self.self_key_id(),
            schema_resolver: self.schema_resolver(),
        }
    }

    async fn attesting_identity_type(
        &self,
        key_id: &str,
    ) -> Result<Option<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .federation_keys
            .get(key_id)
            .map(|rec| rec.identity_type.clone()))
    }

    async fn composer_replay_held(
        &self,
        attestation_type: &str,
        attesting_key_id: &str,
        references_attestation_id: &str,
    ) -> Result<bool, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_attestations.iter().any(|existing| {
            existing.attestation_type == attestation_type
                && existing.attesting_key_id == attesting_key_id
                && crate::federation::precedence::references_attestation_id_from_envelope(
                    &existing.attestation_envelope,
                ) == Some(references_attestation_id)
        }))
    }

    async fn repair_withdraws_depth(
        &self,
        attestation_id: &str,
        depth: usize,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        if state
            .federation_attestations
            .iter()
            .any(|e| e.attestation_id == attestation_id)
        {
            state
                .federation_withdraws_admission_depths
                .entry(attestation_id.to_owned())
                .or_insert(depth);
        }
        Ok(())
    }

    async fn store_pqc_completion(
        &self,
        completion: crate::federation::attestation_admit::PqcCompletion,
    ) -> Result<(), crate::federation::Error> {
        {
            let mut state = self.state.lock().expect("memory backend lock");
            // v36.0.0 (#668/#707-class) — the hybrid-completion write rewrites
            // served columns; the serve position moves with them.
            let admitted_at = next_plane_position(
                &state,
                PLANE_ATTESTATION,
                attestation_rows(&state).into_iter(),
            );
            // The SQL backends' `WHERE pqc_completed_at IS NULL` guard: the row
            // was read and planned outside this lock.
            let Some(row) = state.federation_attestations.iter_mut().find(|a| {
                a.attestation_id == completion.attestation_id && a.pqc_completed_at.is_none()
            }) else {
                return Err(crate::federation::Error::Conflict(format!(
                    "federation_attestations row {} was concurrently completed",
                    completion.attestation_id
                )));
            };
            row.scrub_signature_pqc = Some(completion.scrub_signature_pqc);
            row.pqc_completed_at = Some(completion.pqc_completed_at);
            row.persist_row_hash = completion.persist_row_hash;
            stamp_plane_position(
                &mut state,
                PLANE_ATTESTATION,
                completion.attestation_id.clone(),
                admitted_at,
            );
        }
        // v31.0.0 (CIRISPersist#657) — re-index; see the sqlite twin. Done
        // AFTER the guard is released, the same shape `attach_key_pqc_signature`
        // uses on this backend (the shared helper re-reads through the
        // directory surface, which takes the same lock).
        self.index_stored_record(
            "Attestation",
            &crate::federation::wire_index::record_key(&[(
                "attestation_id",
                &completion.attestation_id,
            )]),
        )
        .await?;
        Ok(())
    }

    async fn store_planned_local_attestation(
        &self,
        planned: crate::federation::attestation_admit::PlannedLocalAttestation,
    ) -> Result<(), crate::federation::Error> {
        let crate::federation::attestation_admit::PlannedLocalAttestation {
            row,
            dimension,
            replace,
            withdraws_depth,
        } = planned;
        let mut state = self.state.lock().expect("memory backend lock");
        if replace {
            // Upsert-replace: drop every prior local row of this
            // (attester, dimension), whatever id it holds (lead ruling on I951;
            // the SQL backends' DELETE).
            let replaced: Vec<String> = state
                .federation_attestations
                .iter()
                .filter(|a| {
                    a.attesting_key_id == row.attesting_key_id
                        && a.tier == crate::federation::types::attestation_tier::LOCAL
                        && a.attestation_envelope
                            .get("dimension")
                            .and_then(|v| v.as_str())
                            == Some(dimension.as_str())
                })
                .map(|a| a.attestation_id.clone())
                .collect();
            state
                .federation_attestations
                .retain(|a| !replaced.contains(&a.attestation_id));
            prune_row_projections(&mut state);
            // v45.0.0 (#871) — a replaced row's rendition leaves the V149
            // mirror with it.
            state
                .blob_renditions
                .retain(|r| !replaced.contains(&r.source_attestation_id));
        }
        memory_insert_local_row(&mut state, row, withdraws_depth);
        Ok(())
    }

    async fn store_planned_reseal(
        &self,
        planned: crate::federation::attestation_admit::PlannedReseal,
    ) -> Result<bool, crate::federation::Error> {
        #[cfg(test)]
        self.test_hooks()
            .pause_if_armed("reseal_before_write")
            .await;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            // v36.0.0 (#668/#707-class) — a re-seal rewrites the served bytes;
            // the serve position moves with them. Allocated before the mutable
            // row borrow below, stamped after it ends.
            let admitted_at = next_plane_position(
                &state,
                PLANE_ATTESTATION,
                attestation_rows(&state).into_iter(),
            );
            let Some(row) = state
                .federation_attestations
                .iter_mut()
                .find(|a| a.attestation_id == planned.attestation_id())
            else {
                return Ok(false);
            };
            // The row this backend holds under its lock, judged and sealed by
            // the shared plan.
            *row = planned.sealed_over(row)?;
            // The wire index moves WITH the row (#610).
            let wik =
                (row.tier == crate::federation::types::attestation_tier::FEDERATION).then(|| {
                    crate::federation::wire_index::record_key(&[(
                        "attestation_id",
                        &row.attestation_id,
                    )])
                });
            let id = row.attestation_id.clone();
            stamp_plane_position(&mut state, PLANE_ATTESTATION, id, admitted_at);
            wik
        };
        if let Some(wire_index_key) = wire_index_key {
            self.index_stored_record("Attestation", &wire_index_key)
                .await?;
        }
        Ok(true)
    }

    async fn delete_attestation(
        &self,
        attestation_id: &str,
        only_if_hash: Option<&str>,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // One step under the lock: for the re-bake, the compare cannot be
        // overtaken between the compare and the removal (#665 review).
        let before = state.federation_attestations.len();
        state.federation_attestations.retain(|a| {
            a.attestation_id != attestation_id
                || only_if_hash.is_some_and(|h| a.persist_row_hash != h)
        });
        if state.federation_attestations.len() == before {
            return Ok(false);
        }
        // The V106 subject projection follows the row (the SQL backends get
        // this from `ON DELETE CASCADE`).
        for ids in state.subject_index.values_mut() {
            ids.retain(|id| id != attestation_id);
        }
        state.subject_index.retain(|_, ids| !ids.is_empty());
        // v57.0.0 (#988) — and the V194/V195 projections.
        prune_row_projections(&mut state);
        Ok(true)
    }

    async fn store_planned_hard_case(
        &self,
        planned: crate::federation::attestation_admit::PlannedHardCase,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        memory_store_hard_case(&mut state, planned);
        Ok(())
    }

    /// Memory holds no pre-v57 silo rows: nothing to rehome.
    async fn rehome_legacy_hard_case_events(
        &self,
        _attester: &crate::federation::attestation_admit::HardCaseAttester,
        _received_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        Ok(())
    }

    async fn trace_agent_id_hash(
        &self,
        trace_id: &str,
    ) -> Result<Option<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .events
            .values()
            .filter(|(_, row)| row.trace_id == trace_id)
            .min_by_key(|(eid, _)| *eid)
            .map(|(_, row)| row.agent_id_hash.clone()))
    }

    async fn detection_row_ids_for_agent(
        &self,
        agent_id_hash: &str,
        signing_key_id: Option<&str>,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let traces: HashSet<String> = state
            .events
            .values()
            .filter(|(_, row)| {
                row.agent_id_hash == agent_id_hash
                    && signing_key_id.is_none_or(|k| row.signing_key_id == k)
            })
            .map(|(_, row)| row.trace_id.clone())
            .collect();
        let mut ids = memory_find_detection_rows(&state, &traces);
        // The full erasure also reaches the rows NAMING the subject, so a row
        // an earlier run left (its trace already gone) is found again.
        if signing_key_id.is_none() {
            if let Ok(subject) = crate::federation::subject_erasure::agent_subject(agent_id_hash) {
                ids.extend(
                    state
                        .federation_attestations
                        .iter()
                        .filter(|row| {
                            row.subject_key_ids.contains(&subject)
                                && crate::federation::admission::envelope_dimension(
                                    &row.attestation_envelope,
                                )
                                .is_some_and(|d| d.starts_with("detection:"))
                        })
                        .map(|row| row.attestation_id.clone()),
                );
                ids.sort();
                ids.dedup();
            }
        }
        Ok(ids)
    }

    async fn store_planned_detection(
        &self,
        planned: crate::federation::attestation_admit::PlannedDetection,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let crate::federation::attestation_admit::PlannedDetection { row, projection } = planned;
        let attestation_id = row.attestation_id.clone();
        if !memory_insert_local_row(&mut state, row, None) {
            return Ok(false);
        }
        state.derived_detection_events.insert(
            projection.detection_id.to_string(),
            (attestation_id, projection),
        );
        Ok(true)
    }

    /// Memory held no detection substrate before v57: nothing to rehome.
    async fn rehome_legacy_detection_events(
        &self,
        _received_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        Ok(())
    }

    async fn projection_rebuild(
        &self,
        projection: crate::federation::silo_projection::SiloProjection,
    ) -> Result<crate::federation::silo_projection::ProjectionRebuild, crate::federation::Error>
    {
        use crate::federation::silo_projection::SiloProjection;
        let state = self.state.lock().expect("memory backend lock");
        // Each entry rendered as its serde form, keyed and ordered like the
        // SQL tables' primary keys; the rebuild projects every held row
        // through the same function the writers use.
        fn render<T: serde::Serialize>(
            map: std::collections::BTreeMap<String, (String, T)>,
        ) -> Result<Vec<String>, crate::federation::Error> {
            map.into_iter()
                .map(|(k, (id, v))| {
                    serde_json::to_string(&(k, id, v)).map_err(|e| {
                        crate::federation::Error::Backend(format!("projection render: {e}"))
                    })
                })
                .collect()
        }
        let (live, rebuilt) = match projection {
            SiloProjection::FederationKeys => {
                // v58.0.0 (CIRISPersist#991, V198 mirror) — the projection's
                // `attestation_id` is the key's own claim row as held.
                let live = state
                    .federation_keys
                    .values()
                    .map(|r| {
                        let row_id = state
                            .federation_attestations
                            .iter()
                            .find(|a| is_key_record_row_of(a, &r.key_id))
                            .map(|a| a.attestation_id.clone());
                        let mut r = r.clone();
                        r.consent_role = None;
                        (r, row_id)
                    })
                    .collect();
                let rows: Vec<crate::federation::Attestation> = state
                    .federation_attestations
                    .iter()
                    .filter(|a| {
                        crate::federation::key_plane::KeyPlaneFamily::of_row(a)
                            == Some(crate::federation::key_plane::KeyPlaneFamily::KeyRecord)
                    })
                    .cloned()
                    .collect();
                return Ok(crate::federation::key_plane::key_projection_rebuild(
                    live, &rows,
                ));
            }
            SiloProjection::IdentityOccurrences => {
                // v58.0.0 (CIRISPersist#991, V198 mirror) — the signed
                // occurrences; a pair's `attestation_id` is its row as held.
                let rows: Vec<crate::federation::Attestation> = state
                    .federation_attestations
                    .iter()
                    .filter(|a| {
                        crate::federation::key_plane::KeyPlaneFamily::of_row(a)
                            == Some(
                                crate::federation::key_plane::KeyPlaneFamily::IdentityOccurrence,
                            )
                    })
                    .cloned()
                    .collect();
                let live = state
                    .federation_identity_occurrence_sigs
                    .keys()
                    .filter_map(|key| {
                        let signed = memory_signed_occurrence(&state, key)?;
                        let row_id = rows
                            .iter()
                            .find(|a| is_occurrence_row_of(a, key))
                            .map(|a| a.attestation_id.clone());
                        Some((signed, row_id))
                    })
                    .collect();
                return Ok(crate::federation::key_plane::occurrence_projection_rebuild(
                    live, &rows,
                ));
            }
            SiloProjection::FederationRevocations => {
                // v58.0.0 (CIRISPersist#991, V198 mirror) — the revocation's
                // `attestation_id` is its row as held.
                let rows: Vec<crate::federation::Attestation> = state
                    .federation_attestations
                    .iter()
                    .filter(|a| crate::federation::key_plane::is_never_withdrawn(a))
                    .cloned()
                    .collect();
                let live = state
                    .federation_revocations
                    .iter()
                    .map(|r| {
                        let row_id = rows
                            .iter()
                            .find(|a| {
                                crate::federation::key_plane::revocation_of_row(a)
                                    .is_some_and(|x| x.revocation_id == r.revocation_id)
                            })
                            .map(|a| a.attestation_id.clone());
                        (r.clone(), row_id)
                    })
                    .collect();
                return Ok(crate::federation::key_plane::revocation_projection_rebuild(
                    live, &rows,
                ));
            }
            SiloProjection::CreditsLedger | SiloProjection::ExpertiseLedger => {
                use crate::federation::ledger_projection::{project_ledger_row, Ledger};
                let want = if projection == SiloProjection::CreditsLedger {
                    Ledger::Credits
                } else {
                    Ledger::Expertise
                };
                let live: Vec<String> = state
                    .cirisnode_ledgers
                    .values()
                    .filter(|p| p.ledger() == want)
                    .map(|p| p.render())
                    .collect();
                let node = crate::federation::FederationDirectory::node_key_id(self);
                let mut rebuilt = std::collections::BTreeMap::new();
                for row in &state.federation_attestations {
                    if let Some(p) = project_ledger_row(row, node.as_deref()) {
                        if p.ledger() == want {
                            memory_project_ledger(&mut rebuilt, p);
                        }
                    }
                }
                let rebuilt = rebuilt.values().map(|p| p.render()).collect();
                return Ok(crate::federation::silo_projection::ProjectionRebuild { live, rebuilt });
            }
            // v60.0.0 (CIRISPersist#988 item 4) — every goal declaration,
            // refolded.
            SiloProjection::Goals => {
                let live = state
                    .federation_goals
                    .values()
                    .map(|p| p.render())
                    .collect();
                let rebuilt = state
                    .federation_attestations
                    .iter()
                    .filter(|a| crate::federation::goal_projection::is_goal_declaration(a))
                    .filter_map(|a| {
                        memory_project_goal(&state.federation_attestations, &a.attestation_id)
                    })
                    .map(|p| (p.goal_id.clone(), p.render()))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_values()
                    .collect();
                return Ok(crate::federation::silo_projection::ProjectionRebuild { live, rebuilt });
            }
            SiloProjection::HardCaseEvents => {
                let live = state
                    .federation_hard_case_events
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let rebuilt = state
                    .federation_attestations
                    .iter()
                    .filter_map(|row| {
                        crate::federation::hard_case::project_hard_case_row(row)
                            .map(|e| (e.event_id.clone(), (row.attestation_id.clone(), e)))
                    })
                    .collect();
                (render(live)?, render(rebuilt)?)
            }
            SiloProjection::DetectionEvents => {
                let live = state
                    .derived_detection_events
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let rebuilt = state
                    .federation_attestations
                    .iter()
                    .filter_map(|row| {
                        crate::derived::detection_row::project_detection_row_under(
                            row,
                            memory_detection_tombstone_instant(&state, &row.attestation_id),
                        )
                        .map(|p| (p.detection_id.to_string(), (row.attestation_id.clone(), p)))
                    })
                    .collect();
                (render(live)?, render(rebuilt)?)
            }
        };
        Ok(crate::federation::silo_projection::ProjectionRebuild { live, rebuilt })
    }

    async fn store_planned_attestation(
        &self,
        planned: crate::federation::attestation_admit::PlannedAttestation,
    ) -> Result<crate::federation::attestation_admit::StoredAttestation, crate::federation::Error>
    {
        use crate::federation::attestation_admit::StoredAttestation;
        // v54.0.0 (Codex on PR #1050) — THE CYCLE CHECK AND THE INSERT ARE ONE
        // STEP. The plan read the graph unlocked; a concurrent writer of the
        // reverse edge could have passed the same read since. Hold the
        // delegation write lock from the re-ask through the write, so every
        // gated writer is serialized against it. One process owns this store,
        // so the in-process lock is the whole serialization.
        let _cycle_guard = if planned.cycle_gated() {
            let guard = self.delegation_write_lock.lock().await;
            planned.recheck_cycle_under_lock(self).await?;
            #[cfg(test)]
            self.test_hooks()
                .pause_if_armed("delegation_cycle_before_insert")
                .await;
            Some(guard)
        } else {
            None
        };
        let crate::federation::attestation_admit::PlannedAttestation {
            row,
            withdraws_depth,
            projected_trace,
            projected_detection,
            projected_hard_case,
            projected_ledger,
            projected_goal,
            wire_index_key,
            ..
        } = planned;
        {
            let mut state = self.state.lock().expect("memory backend lock");
            // v22.0.0 (CIRISPersist#543 / AV-79) — PRIMARY-KEY UNIQUENESS on
            // `attestation_id`, the SQL backends' `TEXT PRIMARY KEY`. v38.5.0
            // (#771): an occupied id writes nothing and reports the stored
            // hash, exactly as the SQL backends' absorb-then-re-read does; the
            // shared verdict decides. Checked BEFORE any mutation, so a
            // duplicate leaves no trace.
            if let Some(existing) = state
                .federation_attestations
                .iter()
                .find(|existing| existing.attestation_id == row.attestation_id)
            {
                return Ok(StoredAttestation::Occupied {
                    stored_persist_row_hash: Some(existing.persist_row_hash.clone()),
                });
            }

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
                state
                    .consent_peer_set_for
                    .retain(|r| r.source_attestation_id != target_id);
                // v45.0.0 (#871) — a retired row's rendition leaves the index with it.
                state
                    .blob_renditions
                    .retain(|r| r.source_attestation_id != target_id);
            } else if crate::federation::consent_peer_set::is_consent_replication_grant(&row) {
                let for_key =
                    crate::federation::consent_by_humans::for_key_id_of(&row.attestation_envelope)
                        .map(str::to_owned);
                for peer in &row.subject_key_ids {
                    if let Some(for_key) = &for_key {
                        state.consent_peer_set_for.retain(|r| {
                            !(r.author_key_id == row.attesting_key_id
                                && r.for_key_id == *for_key
                                && r.peer_key_id == *peer)
                        });
                        state.consent_peer_set_for.push(ConsentPeerForRow {
                            author_key_id: row.attesting_key_id.clone(),
                            for_key_id: for_key.clone(),
                            peer_key_id: peer.clone(),
                            source_attestation_id: row.attestation_id.clone(),
                        });
                    }
                    let keyed_for = for_key
                        .clone()
                        .unwrap_or_else(|| row.attesting_key_id.clone());
                    state.consent_peer_set.retain(|r| {
                        !(r.node_key_id == row.attesting_key_id
                            && r.for_key_id == keyed_for
                            && r.peer_key_id == *peer)
                    });
                    state.consent_peer_set.push(ConsentPeerRow {
                        node_key_id: row.attesting_key_id.clone(),
                        for_key_id: keyed_for,
                        peer_key_id: peer.clone(),
                        source_attestation_id: row.attestation_id.clone(),
                        asserted_at: row.asserted_at,
                    });
                }
            }
            // v45.0.0 (CIRISPersist#871, FSD §5) — maintain the V149
            // `blob_renditions` mirror under the same lock, before `row` moves.
            project_rendition_row(&mut state, &row);
            // v57.0.0 (CIRISPersist#988 item 3) — the V195 `detection_events`
            // mirror, under the same lock.
            if let Some(detection) = projected_detection {
                state.derived_detection_events.insert(
                    detection.detection_id.to_string(),
                    (row.attestation_id.clone(), detection),
                );
            }
            // v60.0.0 (CIRISConstitution#170 closed) — the `hard_case_events`
            // mirror of a replicated (or put) hard_case row, under the same
            // lock.
            if let Some(event) = projected_hard_case {
                state
                    .federation_hard_case_events
                    .insert(event.event_id.clone(), (row.attestation_id.clone(), event));
            }
            // v60.0.0 (CIRISPersist#988 item 1) — the ledger projection, when
            // the row supersedes the one held on its key.
            if let Some(ledger) = projected_ledger {
                memory_project_ledger(&mut state.cirisnode_ledgers, ledger);
            }
            // v36.0.0 (#668) — serve position (V130 mirror).
            let admitted_at = next_plane_position(
                &state,
                PLANE_ATTESTATION,
                attestation_rows(&state).into_iter(),
            );
            let id_for_stamp = row.attestation_id.clone();
            // v50.0.0 (review H2, V157 mirror) — record the depth this
            // `withdraws` was admitted under, beside the row.
            if let Some(depth) = withdraws_depth {
                state
                    .federation_withdraws_admission_depths
                    .insert(row.attestation_id.clone(), depth);
            }
            state.federation_attestations.push(row);
            // v60.0.0 (CIRISPersist#988 item 4) — the goal this row touches,
            // refolded from the rows now held (this one included), under the
            // same lock.
            if let Some(goal_id) = &projected_goal {
                let goals = memory_project_goal(&state.federation_attestations, goal_id);
                match goals {
                    Some(p) => state.federation_goals.insert(goal_id.clone(), p),
                    None => state.federation_goals.remove(goal_id),
                };
            }
            stamp_plane_position(&mut state, PLANE_ATTESTATION, id_for_stamp, admitted_at);
            // Block-scoped: the MutexGuard ends HERE, before the projection
            // awaits (drop() alone does not satisfy rustc's Send analysis).
        }
        // v21.0.0 (CIRISPersist#501) — INBOUND trace projection: a replicated
        // `trace:complete:v1` attestation materializes its `trace_events` rows
        // (the SAME decompose the ingest path uses). Idempotent.
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
        // v21.1.0 (CIRISPersist#507b) / v31.0.0 (#646) — indexed after the
        // guard is released, from the STORED row (`index_stored_record`).
        if let Some(wire_index_key) = wire_index_key {
            self.index_stored_record("Attestation", &wire_index_key)
                .await?;
        }
        Ok(StoredAttestation::Inserted)
    }
}

/// v45.0.0 (CIRISPersist#871, FSD §5) — the memory backend has no blob
/// storage (the trait is sqlite/postgres-only, see the scope-blob note
/// above), so it holds no original and the placement rule is always the
/// node's here. Answering `None` is the truth, not a bypass: the gate runs by
/// the same name at the same door on all three backends.
impl crate::federation::renditions::HeldBlobScope for MemoryBackend {
    async fn held_blob_cohort_scope(
        &self,
        _sha256: &[u8; 32],
    ) -> Result<Option<String>, crate::federation::Error> {
        Ok(None)
    }

    async fn held_claim_scope(
        &self,
        _sha256: &[u8; 32],
    ) -> Result<Option<crate::federation::holding_claim::ClaimScope>, crate::federation::Error>
    {
        Ok(None)
    }
}

/// v52.0.0 (CIRISPersist#930) — the V161 append, unique on the assertion's key.
fn append_occurrence_history(
    state: &mut State,
    row: &crate::federation::IdentityOccurrence,
    attesting_key_id: Option<String>,
) {
    let exists = state
        .federation_identity_occurrence_history
        .iter()
        .any(|a| {
            a.identity_key_id == row.identity_key_id
                && a.occurrence_key_id == row.occurrence_key_id
                && a.asserted_at == row.asserted_at
                && a.attesting_key_id == attesting_key_id
        });
    if !exists {
        state
            .federation_identity_occurrence_history
            .push(crate::federation::OccurrenceAssertion {
                identity_key_id: row.identity_key_id.clone(),
                occurrence_key_id: row.occurrence_key_id.clone(),
                asserted_at: row.asserted_at,
                valid_until: row.valid_until,
                attesting_key_id,
            });
    }
}

#[async_trait::async_trait]
impl crate::federation::FederationDirectory for MemoryBackend {
    fn as_dyn_directory(&self) -> &dyn crate::federation::FederationDirectory {
        self
    }

    // ── v54.1.0 (CIRISPersist#1046) — the steward purge plane (V187 mirror) ──

    async fn purge_scan_attestations(
        &self,
        after_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| after_id.is_none_or(|after| a.attestation_id.as_str() > after))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn purge_trace_ids_for_llm_model(
        &self,
        model: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let ids: std::collections::BTreeSet<String> = state
            .llm_calls
            .iter()
            .filter(|c| c.model.as_deref() == Some(model))
            .map(|c| c.trace_id.clone())
            .collect();
        Ok(ids.into_iter().collect())
    }

    async fn purge_trace_ids_signed_by(
        &self,
        key_id: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let ids: std::collections::BTreeSet<String> = state
            .events
            .values()
            .filter(|(_, e)| e.signing_key_id == key_id)
            .map(|(_, e)| e.trace_id.clone())
            .collect();
        Ok(ids.into_iter().collect())
    }

    async fn purge_trace_row_counts(
        &self,
        trace_ids: &[String],
    ) -> Result<(u64, u64), crate::federation::Error> {
        let wanted: std::collections::HashSet<&str> =
            trace_ids.iter().map(String::as_str).collect();
        let state = self.state.lock().expect("memory backend lock");
        let events = state
            .events
            .values()
            .filter(|(_, e)| wanted.contains(e.trace_id.as_str()))
            .count() as u64;
        let calls = state
            .llm_calls
            .iter()
            .filter(|c| wanted.contains(c.trace_id.as_str()))
            .count() as u64;
        Ok((events, calls))
    }

    async fn purge_put_execution(
        &self,
        execution: &crate::federation::steward_purge::PurgeExecution,
        tombstones: &[crate::federation::steward_purge::PurgeTombstone],
    ) -> Result<crate::federation::steward_purge::PurgePutOutcome, crate::federation::Error> {
        crate::federation::steward_purge::check_purge_put_set(execution, tombstones)?;
        let mut state = self.state.lock().expect("memory backend lock");
        // Codex on PR #1057 — the header and its tombstones are one write:
        // everything is decided under the lock BEFORE anything is inserted,
        // so a failure leaves neither.
        let header_inserted = !state.purge_executions.contains_key(&execution.notice_id);
        let keys: Vec<(String, String, String)> = tombstones
            .iter()
            .map(|t| {
                (
                    t.notice_id.clone(),
                    t.plane.as_str().to_owned(),
                    t.record_ref.clone(),
                )
            })
            .collect();
        let mut fresh = std::collections::BTreeSet::new();
        let tombstones_inserted: Vec<bool> = keys
            .iter()
            .map(|k| !state.purge_tombstones.contains_key(k) && fresh.insert(k.clone()))
            .collect();
        #[cfg(test)]
        self.test_hooks()
            .fail_if_armed("purge_put_execution_tombstones")?;
        if header_inserted {
            let last = state.purge_executions.values().map(|e| e.admitted_at).max();
            let mut row = execution.clone();
            row.admitted_at =
                crate::federation::types::monotonic_admission_instant(chrono::Utc::now(), last);
            row.finalized_at = None;
            state.purge_executions.insert(row.notice_id.clone(), row);
        }
        for ((key, t), inserted) in keys.into_iter().zip(tombstones).zip(&tombstones_inserted) {
            if *inserted {
                state.purge_tombstones.insert(key, t.clone());
                // Codex round 4 sweep — a newly tombstoned attestation leaves
                // the signed-wire index at once (no longer advertised).
                if t.plane == crate::federation::steward_purge::PurgePlane::Attestation {
                    let rk = crate::federation::wire_index::record_key(&[(
                        "attestation_id",
                        &t.record_ref,
                    )]);
                    state
                        .signed_wire_index
                        .retain(|(kind, _), v| !(kind == "Attestation" && *v == rk));
                    // v57.0.0 (CIRISPersist#988 item 3) — a tombstoned
                    // detection row's projection is the V080 tombstone, in
                    // the same write.
                    if let Some(at) = state
                        .purge_executions
                        .get(&t.notice_id)
                        .map(|e| e.executed_at)
                    {
                        memory_tombstone_detection_projection(&mut state, &t.record_ref, at);
                    }
                }
            }
        }
        Ok(crate::federation::steward_purge::PurgePutOutcome {
            header_inserted,
            tombstones_inserted,
        })
    }

    async fn purge_execution(
        &self,
        notice_id: &str,
    ) -> Result<Option<crate::federation::steward_purge::PurgeExecution>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.purge_executions.get(notice_id).cloned())
    }

    async fn purge_tombstones_of(
        &self,
        notice_id: &str,
    ) -> Result<Vec<crate::federation::steward_purge::PurgeTombstone>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<_> = state
            .purge_tombstones
            .values()
            .filter(|t| t.notice_id == notice_id)
            .cloned()
            .collect();
        out.sort_by_key(|t| t.ordinal);
        Ok(out)
    }

    async fn purge_tombstoned(
        &self,
        plane: &str,
        record_ref: &str,
    ) -> Result<Option<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .purge_tombstones
            .keys()
            .filter(|(_, p, r)| p == plane && r == record_ref)
            .map(|(n, _, _)| n.clone())
            .min())
    }

    async fn purge_tombstone_notices(
        &self,
        plane: &str,
        record_ref: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<String> = state
            .purge_tombstones
            .keys()
            .filter(|(_, p, r)| p == plane && r == record_ref)
            .map(|(n, _, _)| n.clone())
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn list_purge_executions_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::steward_purge::PurgeExecution>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<_> = state
            .purge_executions
            .values()
            .filter(|e| {
                since.as_ref().is_none_or(|(at, id)| {
                    (e.admitted_at, e.notice_id.as_str()) > (*at, id.as_str())
                })
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| a.notice_id.cmp(&b.notice_id))
        });
        out.truncate(limit as usize);
        Ok(out)
    }

    async fn purge_delete_tombstoned_attestation(
        &self,
        attestation_id: &str,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // The door's own gate: only a row a purge tombstone names, and never
        // the accountability record (Codex on PR #1057: a tombstone is void
        // for it).
        let tombstoned = state
            .purge_tombstones
            .keys()
            .any(|(_, p, r)| p == "attestation" && r == attestation_id);
        let accountability = state.federation_attestations.iter().any(|a| {
            a.attestation_id == attestation_id
                && (crate::federation::steward_purge::accountability_record_of(a).is_some()
                    // INTERIM (Codex round 4): nor a row a person is the
                    // subject of.
                    || mem_person_subject(&state, a))
        });
        if !tombstoned || accountability {
            return Ok(false);
        }
        let before = state.federation_attestations.len();
        state
            .federation_attestations
            .retain(|a| a.attestation_id != attestation_id);
        if state.federation_attestations.len() == before {
            return Ok(false);
        }
        for ids in state.subject_index.values_mut() {
            ids.retain(|id| id != attestation_id);
        }
        state.subject_index.retain(|_, ids| !ids.is_empty());
        // v57.0.0 (#988) — and the V194/V195 projections.
        prune_row_projections(&mut state);
        Ok(true)
    }

    async fn purge_delete_tombstoned_trace(
        &self,
        trace_id: &str,
    ) -> Result<(u64, u64), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let tombstoned = state
            .purge_tombstones
            .keys()
            .any(|(_, p, r)| p == "trace" && r == trace_id);
        if !tombstoned {
            return Ok((0, 0));
        }
        // INTERIM (Codex round 4 on PR #1057) — never a trace a person signed.
        let person_signed = state.events.values().any(|(_, e)| {
            e.trace_id == trace_id
                && state
                    .federation_keys
                    .get(&e.signing_key_id)
                    .is_some_and(|k| {
                        crate::federation::steward_purge::identity_type_is_person(&k.identity_type)
                    })
        });
        if person_signed {
            return Ok((0, 0));
        }
        let events_before = state.events.len();
        state.events.retain(|_, (_, e)| e.trace_id != trace_id);
        let calls_before = state.llm_calls.len();
        state.llm_calls.retain(|c| c.trace_id != trace_id);
        Ok((
            (events_before - state.events.len()) as u64,
            (calls_before - state.llm_calls.len()) as u64,
        ))
    }

    async fn purge_mark_finalized(
        &self,
        notice_id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        match state.purge_executions.get_mut(notice_id) {
            Some(e) if e.finalized_at.is_none() => {
                e.finalized_at = Some(at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn withdraws_delegation_depth(&self) -> usize {
        self.withdraws_delegation_depth
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn withdraws_admission_depth(
        &self,
        attestation_id: &str,
    ) -> Result<Option<usize>, crate::federation::Error> {
        Ok(self
            .state
            .lock()
            .expect("memory backend lock")
            .federation_withdraws_admission_depths
            .get(attestation_id)
            .copied())
    }

    async fn trust_direction_held_among(
        &self,
        attestation_ids: &[String],
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(attestation_ids
            .iter()
            .filter(|id| state.federation_trust_direction_held.contains(*id))
            .cloned()
            .collect())
    }

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
        // v60.0.0 (CIRISPersist#934 step 3) — the decision is the shared plan's.
        crate::federation::key_plane::key_record_write_planned(
            self,
            crate::federation::key_plane::KeyRecordWrite::Put {
                record: record.record,
                door: crate::federation::register::KeyDoor::LocalMint,
            },
        )
        .await?;
        Ok(())
    }

    /// v60.0.0 (CIRISPersist#934 step 3) — the scrub upgrade, on the shared
    /// plan like the SQL backends (this backend had no upgrade door before).
    async fn adopt_scrub_upgrade(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<crate::federation::register::AdoptScrubOutcome, crate::federation::Error> {
        use crate::federation::register::AdoptScrubOutcome;
        Ok(
            match crate::federation::key_plane::key_record_write_planned(
                self,
                crate::federation::key_plane::KeyRecordWrite::ScrubUpgrade {
                    record: record.record,
                },
            )
            .await?
            {
                crate::federation::key_plane::KeyRecordWritten::Written => {
                    AdoptScrubOutcome::Upgraded
                }
                crate::federation::key_plane::KeyRecordWritten::Settled => {
                    AdoptScrubOutcome::AlreadyAdopted
                }
            },
        )
    }

    /// v44.7.0 (CIRISPersist#864) — the replicated apply; v60.0.0
    /// (CIRISPersist#934 step 3): one shared body for every backend.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn apply_replicated_key_record(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<crate::federation::register::ReplicatedKeyOutcome, crate::federation::Error> {
        crate::federation::key_plane::apply_replicated_key_record_planned(self, record).await
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn store_rebound_key_record(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<crate::federation::register::ReplicatedKeyOutcome, crate::federation::Error> {
        use crate::federation::register::ReplicatedKeyOutcome;
        // v60.0.0 (CIRISPersist#934 step 3) — the decision is the shared plan's.
        Ok(
            match crate::federation::key_plane::key_record_write_planned(
                self,
                crate::federation::key_plane::KeyRecordWrite::Rebind {
                    record: record.record,
                },
            )
            .await?
            {
                crate::federation::key_plane::KeyRecordWritten::Written => {
                    ReplicatedKeyOutcome::Rebound
                }
                crate::federation::key_plane::KeyRecordWritten::Settled => {
                    ReplicatedKeyOutcome::Unchanged
                }
            },
        )
    }

    /// v54.1.0 (CIRISPersist#1044) — the invalid-replace store step (the
    /// sqlite/postgres shape).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn store_invalid_replaced_key_record(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<crate::federation::register::ReplicatedKeyOutcome, crate::federation::Error> {
        use crate::federation::register::ReplicatedKeyOutcome;
        // v60.0.0 (CIRISPersist#934 step 3) — the decision is the shared plan's.
        Ok(
            match crate::federation::key_plane::key_record_write_planned(
                self,
                crate::federation::key_plane::KeyRecordWrite::InvalidReplace {
                    record: record.record,
                },
            )
            .await?
            {
                crate::federation::key_plane::KeyRecordWritten::Written => {
                    ReplicatedKeyOutcome::InvalidReplaced
                }
                crate::federation::key_plane::KeyRecordWritten::Settled => {
                    ReplicatedKeyOutcome::Unchanged
                }
            },
        )
    }

    async fn list_key_registration_history(
        &self,
        key_id: &str,
    ) -> Result<Vec<crate::federation::types::KeyRegistrationHistoryRow>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .key_registration_history
            .get(key_id)
            .cloned()
            .unwrap_or_default())
    }

    /// v45.0.0 (CIRISPersist#871, FSD §5) — the rendition index read over the
    /// V149 mirror, ordered by `rendition_sha256`.
    async fn list_derived_hex(
        &self,
        original_sha256_hex: &str,
    ) -> Result<Vec<crate::federation::renditions::Rendition>, crate::federation::Error> {
        let original = hex::encode(crate::federation::renditions::decode_sha256_hex(
            original_sha256_hex,
        )?);
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<crate::federation::renditions::Rendition> = state
            .blob_renditions
            .iter()
            .filter(|r| r.original_sha256_hex == original)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.rendition_sha256_hex.cmp(&b.rendition_sha256_hex));
        Ok(out)
    }

    // v19.1.0 (#490) — the authenticated re-anchor (memory parity; see the
    // sqlite impl for the full invariants).
    async fn adopt_genesis_reanchor(
        &self,
        record: crate::federation::SignedKeyRecord,
        bundle: &crate::federation::genesis::GenesisBundle,
    ) -> Result<(), crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 3) — the decision is the shared plan's.
        crate::federation::key_plane::key_record_write_planned(
            self,
            crate::federation::key_plane::KeyRecordWrite::Reanchor {
                record: record.record,
                bundle,
            },
        )
        .await?;
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
        // v60.0.0 (CIRISPersist#934 step 4) — the decision is the shared plan's.
        crate::federation::consent_admit::set_consent_role_planned(self, key_id, consent_role)
            .await?;
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

    /// v56.0.0 (CIRISPersist#934 step 1) — the decision is
    /// [`plan_put_attestation`](crate::federation::attestation_admit::plan_put_attestation),
    /// shared by all three backends; this backend executes it through its
    /// [`AttestationStore`](crate::federation::attestation_admit::AttestationStore) impl.
    async fn put_attestation_with_origin(
        &self,
        attestation: crate::federation::SignedAttestation,
        origin: crate::federation::replication::admission::WriteOrigin,
    ) -> Result<crate::federation::AttestationOutcome, crate::federation::Error> {
        crate::federation::attestation_admit::put_attestation_planned(self, attestation, origin)
            .await
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
        // #552 (CC 3.4.5) — the scores-plane read log. FIRST statement in the
        // door, ahead of every refusal, so a read rejected for a bad limit or
        // cursor is logged exactly like one that is served.
        crate::federation::scores_read_audit::log_scores_read(
            crate::federation::scores_read_audit::ScoresReadSite::ListScores,
            caller_occurrence_key_id,
            &filter,
        );
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
                // Exclude rows retracted by a still-hiding composer: the
                // target's own author's, or one the write door admitted under
                // a resolved rule (v51.2.0, #945 — a node owner's, a subject's
                // or a delegate's withdrawal hides too; the consolidated fold
                // `precedence::retired_ids` already held so).
                !all.iter().any(|c| {
                    hide.contains(&c.attestation_type.as_str())
                        && (c.attesting_key_id == r.attesting_key_id
                            || c.withdraws_admission_rule.is_some())
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
        // #552 (CC 3.4.5) — the scores-plane read log; see `list_scores`.
        crate::federation::scores_read_audit::log_scores_read(
            crate::federation::scores_read_audit::ScoresReadSite::ResolveScores,
            caller_occurrence_key_id,
            &filter,
        );
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
                        // v53.0.0 (#975) — the replicable set excludes an
                        // unregistered type under enforcement.
                        && crate::federation::row_type::served_under_enforcement(r)
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
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListAttestationLog,
            subject_key_id.unwrap_or("*"),
            &items,
            0,
        );
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
        crate::federation::attestation_admit::write_local_attestation_planned(self, input, true)
            .await
    }

    async fn attestation_insert_local(
        &self,
        input: crate::federation::types::LocalAttestationInput,
    ) -> Result<String, crate::federation::Error> {
        crate::federation::attestation_admit::write_local_attestation_planned(self, input, false)
            .await
    }

    async fn list_attestations_referencing(
        &self,
        target_attestation_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        use crate::federation::types::attestation_type as at;
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.tier == crate::federation::types::attestation_tier::FEDERATION
                    && matches!(
                        a.attestation_type.as_str(),
                        at::WITHDRAWS | at::RECANTS | at::SUPERSEDES
                    )
                    && crate::federation::precedence::references_attestation_id_from_envelope(
                        &a.attestation_envelope,
                    ) == Some(target_attestation_id)
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListAttestationsReferencing,
            target_attestation_id,
            &rows,
            0,
        );
        Ok(rows)
    }

    /// v56.0.0 (CIRISPersist#1001) — the query's own predicate
    /// ([`AttestationQuery::admits`]) and order, one past the page.
    ///
    /// [`AttestationQuery::admits`]: crate::federation::attestation_query::AttestationQuery::admits
    async fn execute_attestation_query(
        &self,
        q: &crate::federation::attestation_query::AttestationQuery,
    ) -> Result<crate::federation::attestation_query::QueryRows, crate::federation::Error> {
        use std::sync::atomic::Ordering::Relaxed;
        if q.by.is_some() {
            self.attestation_reads_by.fetch_add(1, Relaxed);
        }
        if q.to.is_some() {
            self.attestation_reads_for.fetch_add(1, Relaxed);
        }
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| q.admits(a))
            .cloned()
            .collect();
        drop(state);
        q.sort(&mut rows);
        rows.truncate(q.fetch());
        Ok(crate::federation::attestation_query::QueryRows {
            rows,
            bytes: 0,
            backend: crate::observe::StoreBackend::Memory,
        })
    }

    async fn list_composers_referencing_any(
        &self,
        target_attestation_ids: &[String],
        attested_key_id: Option<&str>,
        attesting_key_id: Option<&str>,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        use crate::federation::types::attestation_type as at;
        if target_attestation_ids.is_empty() {
            return Ok(Vec::new());
        }
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.tier == crate::federation::types::attestation_tier::FEDERATION
                    && matches!(
                        a.attestation_type.as_str(),
                        at::WITHDRAWS | at::RECANTS | at::SUPERSEDES
                    )
                    && attested_key_id.is_none_or(|k| a.attested_key_id == k)
                    && attesting_key_id.is_none_or(|k| a.attesting_key_id == k)
                    && crate::federation::precedence::references_attestation_id_from_envelope(
                        &a.attestation_envelope,
                    )
                    .is_some_and(|r| target_attestation_ids.iter().any(|t| t == r))
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListComposersReferencingAny,
            attested_key_id.or(attesting_key_id).unwrap_or("*"),
            &rows,
            0,
        );
        Ok(rows)
    }

    /// v55.0.0 (CIRISPersist#989) — every attester's federation-tier rows on
    /// `dimension` whose `evidence_refs[0]` is `evidence_ref` (the holder
    /// directory's candidates).
    async fn list_attestations_citing_by_dimension(
        &self,
        dimension: &str,
        evidence_ref: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.tier == crate::federation::types::attestation_tier::FEDERATION
                    && crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                        == Some(dimension)
                    && crate::federation::first_evidence_ref(&a.attestation_envelope)
                        == Some(evidence_ref)
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListAttestationsByDimensionCiting,
            dimension,
            &rows,
            0,
        );
        Ok(rows)
    }

    async fn list_attestations_by_dimension_citing(
        &self,
        attesting_key_id: &str,
        dimension: &str,
        evidence_ref: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.attesting_key_id == attesting_key_id
                    && a.tier == crate::federation::types::attestation_tier::FEDERATION
                    && crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                        == Some(dimension)
                    && crate::federation::first_evidence_ref(&a.attestation_envelope)
                        == Some(evidence_ref)
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListAttestationsByDimensionCiting,
            attesting_key_id,
            &rows,
            0,
        );
        Ok(rows)
    }

    /// The V150 fold, in Rust: `cohort_target_of_envelope` is the generated
    /// column's COALESCE order verbatim.
    async fn list_targeted_by_dimension_prefix(
        &self,
        cohort_scopes: &[&str],
        cohort_target: &str,
        dimension_prefix: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                cohort_scopes.contains(&a.cohort_scope.as_str())
                    && a.tier == crate::federation::types::attestation_tier::FEDERATION
                    && crate::federation::cohort_target_of_envelope(&a.attestation_envelope)
                        == Some(cohort_target)
                    && crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                        .is_some_and(|d| d.starts_with(dimension_prefix))
            })
            .cloned()
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.asserted_at));
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListTargetedByDimensionPrefix,
            cohort_target,
            &rows,
            0,
        );
        Ok(rows)
    }

    /// v21.0.0 (CIRISPersist#502 E7) — the revocation-folded
    /// `consent_peer_set` read: `node_key_id`'s live peers, sorted +
    /// deduped. The fold already happened at write time (see
    /// `put_attestation`'s `consent_peer_set` mirror maintenance).
    async fn list_consent_peers_for(
        &self,
        for_key_id: &str,
    ) -> Result<Vec<(String, String)>, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — one fold over the typed read.
        let pairs =
            crate::federation::consent_admit::list_consent_peers_for_planned(self, for_key_id)
                .await?;
        Ok(pairs)
    }

    async fn list_consent_peers(
        &self,
        node_key_id: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — one fold over the typed read.
        let peers =
            crate::federation::consent_admit::list_consent_peers_planned(self, node_key_id).await?;
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
        // v60.0.0 (CIRISPersist#934 step 4) — one fold over the typed read.
        let rows = crate::federation::consent_admit::live_consent_grants_planned(
            self,
            crate::federation::consent_admit::ConsentRead::Node(node_key_id),
        )
        .await?;
        Ok(rows)
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — the `promote_consented_backlog`
    /// sweep's page source: ascending-`attestation_id` keyset cursor over
    /// `local`-tier rows.
    async fn list_live_consent_grants_for(
        &self,
        for_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — one fold over the typed read.
        let rows = crate::federation::consent_admit::live_consent_grants_planned(
            self,
            crate::federation::consent_admit::ConsentRead::For(for_key_id),
        )
        .await?;
        Ok(rows)
    }

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
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListLocalTierAttestations,
            after_attestation_id.unwrap_or("*"),
            &rows,
            0,
        );
        Ok(rows)
    }

    /// v21.12.0 (CIRISPersist#530) — the repair sweep's page source: the
    /// stranded rows (`tier = 'federation'` with a suppressed
    /// `cohort_scope`). Twin of `list_local_tier_attestations`; the
    /// predicate uses [`crate::federation::types::cohort_scope::is_structurally_invisible`]
    /// (`self`/`family`) directly rather than a literal set so the memory
    /// backend can never drift from the taxonomy the SQL backends spell out.
    async fn list_widening_candidates(
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
                    && cohort_scope::is_structurally_invisible(&a.cohort_scope)
                    // v50.0.0 (CIRISPersist#919) — stranded rows only: a row
                    // naming a cohort target was PLACED (the SQL backends
                    // render this same predicate).
                    && !crate::federation::admission::envelope_names_cohort_target(
                        &a.attestation_envelope,
                    )
                    && match after_attestation_id {
                        Some(after) => a.attestation_id.as_str() > after,
                        None => true,
                    }
                    // not yet widened: no `supersedes` by the same attester
                    // references it (the sqlite/postgres NOT EXISTS arm)
                    && !state.federation_attestations.iter().any(|s| {
                        s.attestation_type == crate::federation::types::attestation_type::SUPERSEDES
                            && s.attesting_key_id == a.attesting_key_id
                            && crate::federation::precedence::references_attestation_id_from_envelope(
                                &s.attestation_envelope,
                            ) == Some(a.attestation_id.as_str())
                    })
                    // v41.1.0 (CIRISPersist#807) — …and not already published
                    // WIDER by an equivalent row. A candidate exists to make an
                    // undiscoverable row discoverable; if the same attester has
                    // already put the same claim on a discoverable scope by
                    // other means, there is nothing here awaiting anybody.
                    && !state.federation_attestations.iter().any(|e| {
                        e.tier == attestation_tier::FEDERATION
                            && !cohort_scope::is_structurally_invisible(&e.cohort_scope)
                            // `delegates_to` ONLY: there `(attester, attested,
                            // dimension)` identifies the edge. Two `scores` or
                            // `chat:` rows share all four and are DIFFERENT
                            // claims, so a wider one settles nothing.
                            && e.attestation_type
                                == crate::federation::types::attestation_type::DELEGATES_TO
                            && a.attestation_type == e.attestation_type
                            && e.attesting_key_id == a.attesting_key_id
                            && e.attested_key_id == a.attested_key_id
                            && crate::federation::admission::envelope_dimension(
                                &e.attestation_envelope,
                            ) == crate::federation::admission::envelope_dimension(
                                &a.attestation_envelope,
                            )
                    })
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        rows.truncate(limit as usize);
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListWideningCandidates,
            after_attestation_id.unwrap_or("*"),
            &rows,
            0,
        );
        Ok(rows)
    }

    /// v31.0.0 (CIRISPersist#650) — the unfiltered corpus enumerator: every
    /// row, every tier. Twin of `list_local_tier_attestations` MINUS the tier
    /// predicate; see the trait doc for why a fold may not run over a
    /// partition.
    async fn list_attestations_for_migration(
        &self,
        after_attestation_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| match after_attestation_id {
                Some(after) => a.attestation_id.as_str() > after,
                None => true,
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
        rows.truncate(limit as usize);
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListAttestationsForMigration,
            after_attestation_id.unwrap_or("*"),
            &rows,
            0,
        );
        Ok(rows)
    }

    /// v31.0.0 (CIRISPersist#650) — re-seal in place. The gate stack is
    /// [`crate::federation::migration::check_reseal_admission`], shared with
    /// sqlite and postgres, run on a CANDIDATE before `row` is touched: this
    /// backend holds `&mut` into live state, so gating after stamping would
    /// leave a REFUSED re-seal having already mutated the row — the AV-9
    /// violation the SQL backends are structurally protected from by working on
    /// a loaded copy.
    /// v56.0.0 (CIRISPersist#934 step 1, door 4) — the decision is
    /// [`plan_reseal_attestation`](crate::federation::attestation_admit::plan_reseal_attestation)
    /// and its re-ask in the write step,
    /// [`PlannedReseal::sealed_over`](crate::federation::attestation_admit::PlannedReseal::sealed_over);
    /// this backend stores it.
    async fn reseal_attestation_v31(
        &self,
        resealed: &crate::federation::Attestation,
    ) -> Result<bool, crate::federation::Error> {
        crate::federation::attestation_admit::reseal_attestation_planned(self, resealed).await
    }

    /// v31.0.0 (CIRISPersist#650) — hard-delete one attestation row, and the
    /// V106 subject projection with it (the SQL backends get that from `ON
    /// DELETE CASCADE`; memory has to say it).
    /// v38.4.0 (PR #769 review round 2) — memory holds BOTH projections, so
    /// the trait's no-op default was wrong here.
    ///
    /// `MemoryState` carries `consent_peer_set` and `signed_wire_index` just
    /// as the SQL backends do, so reaping an expired replication grant left
    /// `list_consent_peers` returning a peer whose authorising attestation
    /// was gone — the same authority leak, on the backend most tests run
    /// against, which is exactly where it would have gone unnoticed.
    async fn purge_attestation_projections(
        &self,
        attestation_id: &str,
    ) -> Result<(), crate::federation::Error> {
        let record_key =
            crate::federation::wire_index::record_key(&[("attestation_id", attestation_id)]);
        let mut state = self.state.lock().expect("memory backend lock");
        state
            .consent_peer_set
            .retain(|r| r.source_attestation_id != attestation_id);
        // v45.0.0 (#871) — a retired row's rendition leaves the index with it.
        state
            .blob_renditions
            .retain(|r| r.source_attestation_id != attestation_id);
        state
            .signed_wire_index
            .retain(|(kind, _), rk| !(kind == "Attestation" && *rk == record_key));
        // v54.1.0 (Codex round 4 on PR #1057) — every other mirror of a
        // `steward_purge::ATTESTATION_PROJECTIONS` table: the steward-scoped
        // `consent_peer_set_for` (a hard-deleted grant kept authorising its
        // peer through `consent_peers_by_principals`), the withdraws depth and
        // the trust-direction grandfather. Memory holds no pending-KeyGrant
        // set and no canonical-binding table.
        state
            .consent_peer_set_for
            .retain(|r| r.source_attestation_id != attestation_id);
        state
            .federation_withdraws_admission_depths
            .remove(attestation_id);
        state.federation_trust_direction_held.remove(attestation_id);
        // v57.0.0 (#988) — the V194/V195 projections of the row.
        state
            .federation_hard_case_events
            .retain(|_, (id, _)| id != attestation_id);
        state
            .derived_detection_events
            .retain(|_, (id, _)| id != attestation_id);
        // v59.0.0 (#1099) — the V199 receipt (ON DELETE CASCADE).
        state.self_roster_proposals.remove(attestation_id);
        // v60.0.0 (#988 items 1, 4) — the V203 ledger and V204 goal
        // projections, CASCADE with the row they project (the SQL backends'
        // foreign keys).
        state
            .cirisnode_ledgers
            .retain(|_, p| p.attestation_id != attestation_id);
        state
            .federation_goals
            .retain(|_, p| p.attestation_id != attestation_id);
        Ok(())
    }

    /// v38.7.0 (CIRISPersist#780) — index-only hash page for one kind.
    async fn list_key_plane_wire_hashes_since(
        &self,
        family: &str,
        after_content_hash: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#1105) — one shared read plan.
        let hashes = crate::federation::key_plane::list_key_plane_wire_hashes_planned(
            self,
            family,
            after_content_hash,
            limit,
        )
        .await?;
        Ok(hashes)
    }

    async fn list_wire_hashes_since(
        &self,
        kind: &str,
        after_content_hash: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let after = after_content_hash.unwrap_or("");
        let state = self.state.lock().expect("memory backend lock");
        let mut hashes: Vec<String> = state
            .signed_wire_index
            .keys()
            .filter(|(k, h)| k == kind && h.as_str() > after)
            .map(|(_, h)| h.clone())
            .collect();
        // The SQL backends page over the PRIMARY KEY, so this must order the
        // same way or a caller's cursor would skip entries on one backend.
        hashes.sort();
        hashes.truncate(limit as usize);
        Ok(hashes)
    }

    /// CIRISPersist#785 — record that a hash EXISTS, unheld.
    async fn insert_known_wire_hash(
        &self,
        kind: &str,
        content_hash: &str,
        advertised_by: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::wire_index::validate_content_hash(
            "insert_known_wire_hash",
            content_hash,
        )?;
        // v59.0.0 — a peer's advertisement of a framed key-plane hash is
        // refused: that carriage is retired.
        crate::federation::replication_policy::refuse_retired_framed(kind)?;
        let mut state = self.state.lock().expect("memory backend lock");
        // Matches the SQL backends' upsert: the same hash arrives on every
        // wrap of edge's re-sweep, and `last_advertised_at` must MOVE on each
        // sighting or the eviction floor is measured against a frozen value
        // (#776) — but it must move FORWARDS ONLY. Execution order is not
        // observation order, so a delayed write carrying an older sighting
        // would otherwise drag the column backwards and let the next sweep
        // evict a hash that was recently advertised.
        let entry = state
            .known_wire_hashes
            .entry((kind.to_owned(), content_hash.to_owned()))
            .or_insert((now, advertised_by.map(str::to_owned)));
        if now > entry.0 {
            *entry = (now, advertised_by.map(str::to_owned));
        }
        Ok(())
    }

    /// CIRISPersist#785 — is this hash known to exist?
    async fn known_wire_hash_contains(
        &self,
        kind: &str,
        content_hash: &str,
    ) -> Result<bool, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .known_wire_hashes
            .contains_key(&(kind.to_owned(), content_hash.to_owned())))
    }

    /// CIRISPersist#785 — page the known set, cursored on the HASH.
    async fn list_known_wire_hashes_since(
        &self,
        kind: &str,
        after_content_hash: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::federation::KnownWireHash>, crate::federation::Error> {
        let after = after_content_hash.unwrap_or("");
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<crate::federation::KnownWireHash> = state
            .known_wire_hashes
            .iter()
            .filter(|((k, h), _)| k == kind && h.as_str() > after)
            .map(|((k, h), (ts, by))| crate::federation::KnownWireHash {
                kind: k.clone(),
                content_hash: h.clone(),
                last_advertised_at: *ts,
                advertised_by: by.clone(),
            })
            .collect();
        // Ordered by HASH, like the SQL backends page over the primary key —
        // a caller's cursor must not skip entries on one backend and not
        // another. Deliberately NOT by `last_advertised_at`: that column moves
        // on every re-advertisement, so a row bumped mid-iteration would jump
        // the cursor and be skipped permanently.
        out.sort_by(|a, b| a.content_hash.cmp(&b.content_hash));
        out.truncate(limit as usize);
        Ok(out)
    }

    /// CIRISPersist#785 — evict on a CALLER-SUPPLIED cutoff; the
    /// floor wins over the bound.
    async fn evict_known_wire_hashes(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
        bound: u64,
    ) -> Result<crate::federation::KnownHashEviction, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — the report is shared; the cutoff is
        // the caller's (edge owns the wrap period), never derived here.
        let report =
            crate::federation::sweep_plan::evict_known_wire_hashes_planned(self, cutoff, bound)
                .await?;
        Ok(report)
    }

    /// v38.4.0 (CIRISPersist#768) — expired ids, oldest first, bounded.
    async fn list_expired_attestation_ids(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — the reaper's selection is shared.
        let ids = crate::federation::sweep_plan::list_expired_attestation_ids_planned(
            self, now, limit, offset,
        )
        .await?;
        Ok(ids)
    }

    /// v56.0.0 (CIRISPersist#934 step 1, door 5) — decided by
    /// [`purge_attestation_planned`](crate::federation::attestation_admit::purge_attestation_planned).
    async fn purge_attestation_v31(
        &self,
        attestation_id: &str,
    ) -> Result<bool, crate::federation::Error> {
        crate::federation::attestation_admit::purge_attestation_planned(self, attestation_id).await
    }

    /// v56.0.0 (CIRISPersist#934 step 1, door 6) — decided by
    /// [`purge_genesis_delegation_row_planned`](crate::federation::attestation_admit::purge_genesis_delegation_row_planned).
    async fn purge_genesis_delegation_row_v31(
        &self,
        attestation_id: &str,
        expected_persist_row_hash: &str,
        authority: &crate::federation::genesis::bundle::GenesisPurgeAuthority<'_>,
    ) -> Result<bool, crate::federation::Error> {
        crate::federation::attestation_admit::purge_genesis_delegation_row_planned(
            self,
            attestation_id,
            expected_persist_row_hash,
            authority,
        )
        .await
    }

    async fn dag_manifests_of_chunk(
        &self,
        _chunk_sha256: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, crate::federation::Error> {
        // v53.1.0 (#979) — the memory backend stores no blobs, so no chunk
        // belongs to any DAG here.
        Ok(Vec::new())
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
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::AttestationsBindingContent,
            content_sha256,
            &rows,
            0,
        );
        Ok(rows)
    }

    async fn put_revocation(
        &self,
        revocation: crate::federation::SignedRevocation,
    ) -> Result<(), crate::federation::Error> {
        // v58.0.0 (CIRISPersist#991) — one plan for every backend
        // (`key_plane::plan_put_revocation`); this backend stores.
        crate::federation::key_plane::put_revocation_planned(self, revocation).await
    }

    async fn revocations_for_subject(
        &self,
        revoked_key_sha256_ed25519_raw: &str,
    ) -> Result<Vec<crate::federation::Revocation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_revocations
            .iter()
            .filter(|r| r.revoked_key_sha256_ed25519_raw == revoked_key_sha256_ed25519_raw)
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
        // v59.0.0 (CIRISPersist#1099, CC 3.3.6.3) — a roster change lands by
        // the two-path door or is held as a proposal.
        crate::federation::self_roster::gate_occurrence(self, &occurrence).await?;
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
            // v52.0.0 (#930) — history whether or not the upsert takes it.
            append_occurrence_history(&mut state, &row, Some(occurrence.attesting_key_id.clone()));
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
                // v36.0.0 (#668) — serve position (V130 mirror): stamped on
                // admission, RE-stamped on a last-signed-wins supersede.
                let admitted_at = next_plane_position(
                    &state,
                    PLANE_IDENTITY_OCCURRENCE,
                    identity_occurrence_rows(&state).into_iter(),
                );
                let resume = crate::federation::types::compound_resume_id(&[
                    &row.identity_key_id,
                    &row.occurrence_key_id,
                ]);
                state
                    .federation_identity_occurrences
                    .insert(key.clone(), row);
                stamp_plane_position(&mut state, PLANE_IDENTITY_OCCURRENCE, resume, admitted_at);
                // v58.0.0 (CIRISPersist#991) — and its `identity:occurrence:v1` row.
                memory_sync_occurrence_row(&mut state, &key);
                indexed = state
                    .federation_attestations
                    .iter()
                    .find(|a| is_occurrence_row_of(a, &key))
                    .map(|a| a.attestation_id.clone());
            }
            projected_route
        };
        // v58.0.0 (CIRISPersist#991) — the pair's `identity:occurrence:v1` row
        // is a wire-index entry (the Attestation kind); the framed
        // `IdentityOccurrence` entry stays beside it for pre-v58 peers.
        self.index_plane_row(indexed.as_deref()).await?;
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
            // v52.0.0 (#930) — a trusted-local assertion is history too, even
            // when the signed row below stays authoritative.
            append_occurrence_history(&mut state, &row, None);
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
            // v36.0.0 (#668) — serve position (V130 mirror), the local twin.
            let admitted_at = next_plane_position(
                &state,
                PLANE_IDENTITY_OCCURRENCE,
                identity_occurrence_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[
                &row.identity_key_id,
                &row.occurrence_key_id,
            ]);
            state.federation_identity_occurrences.insert(
                (row.identity_key_id.clone(), row.occurrence_key_id.clone()),
                row,
            );
            stamp_plane_position(&mut state, PLANE_IDENTITY_OCCURRENCE, resume, admitted_at);
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
                // v36.0.0 (#668) — `last_seen_at` alone (advisory liveness,
                // outside the verifier's nine fields): the serve position
                // deliberately does NOT move, matching the SQL twins.
                if let Some(row) = state.transport_destinations.get_mut(&key) {
                    row.last_seen_at = destination.last_seen_at;
                }
            } else {
                // v36.0.0 (#668) — serve position (V130 mirror): stamped on
                // insert and re-stamped on an unsigned-row rewrite.
                let admitted_at = next_plane_position(
                    &state,
                    PLANE_TRANSPORT_DESTINATION,
                    transport_destination_rows(&state).into_iter(),
                );
                let resume = crate::federation::types::compound_resume_id(&[&key.0, &key.1]);
                state
                    .transport_destinations
                    .insert(key, destination.clone());
                stamp_plane_position(&mut state, PLANE_TRANSPORT_DESTINATION, resume, admitted_at);
            }
        }
        Ok(())
    }

    async fn put_signed_transport_destination(
        &self,
        signed: &crate::federation::SignedTransportDestination,
    ) -> Result<crate::federation::TransportDestinationApplyOutcome, crate::federation::Error> {
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::TransportDestination,
            signed,
        )
        .await?
        {
            return Ok(
                crate::federation::self_at_login::TransportDestinationApplyOutcome::Unchanged,
            );
        }
        use crate::federation::TransportDestinationApplyOutcome as Outcome;
        // #443 — the admission gate BEFORE any write (before locking; the
        // gate locks state internally). Backend-symmetric.
        crate::federation::admission::verify_signed_transport_destination(self, signed).await?;
        // v59.0.0 (CIRISPersist#1106, CC 5.3.4) — a seated serve node's
        // bundle-pinned transit pair rotates by holder quorum, not alone.
        crate::federation::transport_rebind::check_serve_rotation(self, signed).await?;
        let d = &signed.transport_destination;
        let (wire_index_key, fresh) = {
            let mut state = self.state.lock().expect("memory backend lock");
            let key = (d.occurrence_key_id.clone(), d.transport_kind.clone());
            // v21.4.0 (CIRISPersist#515) — SIGNED WINS THE SHARED KEY: the
            // monotonic-clock refusal applies only against a stored row that is
            // itself SIGNED; a signed write always reclaims an unsigned row
            // (occurrence-projection / announce state) regardless of clocks.
            let stored_signed = state.transport_destination_sigs.contains_key(&key);
            // v56.0.0 (#1077) — the transit KEX pair is envelope-only, so an
            // equal typed projection is `Unchanged` only when the stored
            // envelope carries the same pair; a same-clock re-sign that changes
            // the pair falls through to the monotonic refusal below.
            let same_pair =
                state
                    .transport_destination_sigs
                    .get(&key)
                    .is_some_and(|(_, env, _)| {
                        crate::federation::self_at_login::same_transit_kex_member(
                            env,
                            &signed.signed_envelope,
                        )
                    });
            let fresh = match state.transport_destinations.get(&key) {
                Some(ex) if *ex == *d && stored_signed && same_pair => {
                    return Ok(Outcome::Unchanged)
                }
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
            // v36.0.0 (#668) — serve position (V130 mirror): a signed apply
            // always stamps/re-stamps.
            let admitted_at = next_plane_position(
                &state,
                PLANE_TRANSPORT_DESTINATION,
                transport_destination_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[&key.0, &key.1]);
            state.transport_destinations.insert(key.clone(), d.clone());
            stamp_plane_position(&mut state, PLANE_TRANSPORT_DESTINATION, resume, admitted_at);
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

    async fn list_identity_occurrences_by_occurrence_key(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<crate::federation::IdentityOccurrence>, crate::federation::Error> {
        #[cfg(test)]
        self.test_hooks
            .fail_if_armed("list_identity_occurrences_by_occurrence_key")?;
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_identity_occurrences
            .values()
            .filter(|o| o.occurrence_key_id == occurrence_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.identity_key_id.cmp(&b.identity_key_id));
        Ok(rows)
    }

    async fn list_identity_occurrence_history_by_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<crate::federation::OccurrenceAssertion>, crate::federation::Error> {
        #[cfg(test)]
        self.test_hooks
            .fail_if_armed("list_identity_occurrence_history_by_occurrence")?;
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_identity_occurrence_history
            .iter()
            .filter(|a| a.occurrence_key_id == occurrence_key_id)
            .cloned()
            .collect();
        crate::federation::sort_occurrence_history(&mut rows);
        Ok(rows)
    }

    async fn lookup_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<crate::federation::IdentityOccurrence>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // v45.0.1 (#873) — the SQL backends' order, not the map's: the
        // non-singleton binding first, newest `asserted_at`, then key.
        Ok(state
            .federation_identity_occurrences
            .values()
            .filter(|o| o.occurrence_key_id == occurrence_key_id)
            .min_by(|a, b| {
                (a.identity_key_id == a.occurrence_key_id)
                    .cmp(&(b.identity_key_id == b.occurrence_key_id))
                    .then_with(|| b.asserted_at.cmp(&a.asserted_at))
                    .then_with(|| a.identity_key_id.cmp(&b.identity_key_id))
            })
            .cloned())
    }

    async fn put_family(
        &self,
        family: crate::federation::SignedFamily,
    ) -> Result<(), crate::federation::Error> {
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::Family,
            &family,
        )
        .await?
        {
            return Ok(());
        }
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE the
        // state lock (the verify resolves keys via the directory, which
        // locks itself). Hybrid-Strict vs the authority's registered
        // pubkeys — was FK-existence only, a forgeable keyless declaration.
        crate::federation::verify_family_admission(self, &family).await?;
        // v49.0.0 (CIRISPersist#910.5) — an occupied id: an identical re-put
        // is a no-op, a proof-carrying amendment this node's own state
        // authorizes is applied as a supersede, anything else is refused.
        // (Memory used to OVERWRITE here — `put_family_local` is a map insert.)
        if let crate::federation::group_amendment::OccupiedRoute::Settled(_) =
            crate::federation::group_amendment::route_occupied_family(self, &family).await?
        {
            return Ok(());
        }
        let crate::federation::SignedFamily {
            family: row,
            authority_key_id,
            scrub_signature_classical,
            scrub_signature_pqc,
            supersede_proof,
            cosignatures,
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
        {
            let mut state = self.state.lock().expect("memory backend lock");
            state.federation_family_authority_sigs.insert(
                family_key_id.clone(),
                (
                    authority_key_id.clone(),
                    scrub_signature_classical.clone(),
                    scrub_signature_pqc.clone(),
                ),
            );
            // v49.0.0 (#910.5) — a first copy of an amended version keeps its
            // proof, so the next peer can apply it.
            match supersede_proof {
                Some(p) => {
                    state
                        .federation_family_supersede_proofs
                        .insert(family_key_id.clone(), p);
                }
                None => {
                    state
                        .federation_family_supersede_proofs
                        .remove(&family_key_id);
                }
            }
            // v52.0.0 (#955, V162 mirror) — the founding members' consent.
            state
                .federation_family_cosignatures
                .insert(family_key_id.clone(), cosignatures);
            // v36.0.0 (#668) — attaching the authority signature is what makes
            // the row visible to the signed serve cursor; re-stamp the serve
            // position here (V130 mirror).
            let rows = family_rows(&state);
            allocate_and_stamp(&mut state, PLANE_FAMILY, family_key_id.clone(), rows);
        }
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
        // v36.0.0 (#668) — serve position (V130 mirror), allocated over the
        // pre-existing rows and stamped after the insert lands.
        let admitted_at =
            next_plane_position(&state, PLANE_FAMILY, family_rows(&state).into_iter());
        let id_for_stamp = row.family_key_id.clone();
        state
            .federation_families
            .insert(row.family_key_id.clone(), row);
        stamp_plane_position(&mut state, PLANE_FAMILY, id_for_stamp, admitted_at);
        Ok(())
    }

    async fn lookup_family(
        &self,
        family_key_id: &str,
    ) -> Result<Option<crate::federation::Family>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_families.get(family_key_id).cloned())
    }

    // #249 Cut G2 — supersede + versioning (CIRISServer #249 §3/§8).
    async fn supersede_group_row(
        &self,
        cohort: crate::federation::cohort::Cohort,
        new_snapshot: serde_json::Value,
        authorization: Option<serde_json::Value>,
    ) -> Result<u32, crate::federation::Error> {
        // Test-only (PR #921 review, F3): a rival supersede of the same
        // community lands here, before this one re-checks its prior.
        #[cfg(test)]
        if matches!(cohort, crate::federation::cohort::Cohort::Community) {
            self.test_rival_at(crate::store::test_hooks::RivalPoint::BeforeSupersede)
                .await?;
        }
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
        let group_key_id =
            crate::federation::group_amendment::snapshot_group_key_id(cohort, &new_snapshot);
        // The lock is scoped to this block so it is released before the
        // re-index below awaits.
        let next = {
            let mut state = self.state.lock().expect("memory backend lock");
            match cohort {
                Cohort::Family => {
                    // v31.0.0 (CIRISPersist#651) — the snapshot is the SIGNED
                    // wrapper. Decoding the bare record here is what silently
                    // stranded the caller's signature while every field
                    // `signing_envelope()` covers was replaced below.
                    let crate::federation::SignedFamily {
                        family: mut new_fam,
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        supersede_proof,
                        cosignatures,
                    } = serde_json::from_value(new_snapshot).map_err(|e| {
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
                    // v49.0.0 (#910.5) — a proof names the version it replaces;
                    // checked under the same lock that replaces it.
                    if let Some(p) = &supersede_proof {
                        crate::federation::group_amendment::check_proof_names_prior(
                            &cohort_str,
                            &key,
                            p,
                            &prior.persist_row_hash,
                        )?;
                    }
                    // v53.0.0 (CC 3.2 T6) — the version names the head it
                    // succeeds; checked under the same lock that replaces it.
                    crate::federation::group_amendment::check_prev_head_names_held(
                        &cohort_str,
                        &key,
                        &new_fam.prev_head_digest,
                        &prior.persist_row_hash,
                        authorization.as_ref(),
                    )?;
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
                    // v31.0.0 (CIRISPersist#651) — the signature moves with the
                    // record it authorizes, in the same critical section.
                    state.federation_family_authority_sigs.insert(
                        key.clone(),
                        (
                            authority_key_id,
                            scrub_signature_classical,
                            scrub_signature_pqc,
                        ),
                    );
                    // v49.0.0 (#910.5) — the proof moves with the version it
                    // authorized; a supersede without one clears the last one.
                    match supersede_proof {
                        Some(p) => {
                            state
                                .federation_family_supersede_proofs
                                .insert(key.clone(), p);
                        }
                        None => {
                            state.federation_family_supersede_proofs.remove(&key);
                        }
                    }
                    state
                        .federation_family_cosignatures
                        .insert(key.clone(), cosignatures);
                    // v36.0.0 (#668/#707-class) — a supersede rewrites the served
                    // bytes; the serve position moves with them.
                    let rows = family_rows(&state);
                    allocate_and_stamp(&mut state, PLANE_FAMILY, key.clone(), rows);
                    let next = cur_ver + 1;
                    state
                        .federation_group_current_version
                        .insert((cohort_str, key), next);
                    next
                }
                Cohort::Community | Cohort::Affiliations => {
                    // v31.0.0 (CIRISPersist#651) — the SIGNED wrapper; see the
                    // family arm above.
                    let crate::federation::SignedCommunity {
                        community: mut new_comm,
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        supersede_proof,
                        cosignatures,
                        lineage,
                    } = serde_json::from_value(new_snapshot).map_err(|e| {
                        Error::InvalidArgument(format!("supersede community snapshot decode: {e}"))
                    })?;
                    new_comm.persist_row_hash =
                        crate::federation::types::compute_persist_row_hash(&new_comm)?;
                    let key = new_comm.community_key_id.clone();
                    let prior =
                        state
                            .federation_communities
                            .get(&key)
                            .cloned()
                            .ok_or_else(|| {
                                Error::InvalidArgument(format!(
                            "supersede: unknown community group {key:?} (nothing to supersede)"
                        ))
                            })?;
                    // v49.0.0 (#910.5) — see the family arm.
                    if let Some(p) = &supersede_proof {
                        crate::federation::group_amendment::check_proof_names_prior(
                            &cohort_str,
                            &key,
                            p,
                            &prior.persist_row_hash,
                        )?;
                    }
                    // v53.0.0 (CC 3.2 T6) — the version names the head it
                    // succeeds; checked under the same lock that replaces it.
                    crate::federation::group_amendment::check_prev_head_names_held(
                        &cohort_str,
                        &key,
                        &new_comm.prev_head_digest,
                        &prior.persist_row_hash,
                        authorization.as_ref(),
                    )?;
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
                    // v31.0.0 (CIRISPersist#651) — see the family arm.
                    state.federation_community_authority_sigs.insert(
                        key.clone(),
                        (
                            authority_key_id,
                            scrub_signature_classical,
                            scrub_signature_pqc,
                        ),
                    );
                    // v49.0.0 (#910.5) — see the family arm.
                    match supersede_proof {
                        Some(p) => {
                            state
                                .federation_community_supersede_proofs
                                .insert(key.clone(), p);
                        }
                        None => {
                            state.federation_community_supersede_proofs.remove(&key);
                        }
                    }
                    // v50.0.0 (#926) — the co-signatures travel with the
                    // authority signature they sit beside.
                    if cosignatures.is_empty() {
                        state.federation_community_cosignatures.remove(&key);
                    } else {
                        state
                            .federation_community_cosignatures
                            .insert(key.clone(), cosignatures);
                    }
                    if lineage.is_empty() {
                        state.federation_community_lineages.remove(&key);
                    } else {
                        state
                            .federation_community_lineages
                            .insert(key.clone(), lineage);
                    }
                    // v36.0.0 (#668/#707-class) — see the family arm.
                    let rows = community_rows(&state);
                    allocate_and_stamp(&mut state, PLANE_COMMUNITY, key.clone(), rows);
                    let next = cur_ver + 1;
                    state
                        .federation_group_current_version
                        .insert((cohort_str, key), next);
                    next
                }
                Cohort::SelfId => unreachable!("guarded above"),
            }
        };
        // v49.0.0 (#910.5) — a supersede changes the served record; re-index
        // it, or a peer's content-hash lookup never sees the new version.
        let (kind, key_field) = match cohort {
            Cohort::Family => ("Family", "family_key_id"),
            _ => ("Community", "community_key_id"),
        };
        self.index_stored_record(
            kind,
            &crate::federation::wire_index::record_key(&[(key_field, &group_key_id)]),
        )
        .await?;
        Ok(next)
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
            // v49.0.0 (CIRISPersist#910) — containment in the family's
            // HISTORY: on the record, or named by a widening. Still raw.
            .filter(|f| {
                f.members.iter().any(|m| m.key_id == member_identity_key_id)
                    || state
                        .federation_family_membership_widenings
                        .values()
                        .any(|w| {
                            w.family_key_id == f.family_key_id
                                && w.member_key_id == member_identity_key_id
                        })
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.family_key_id.cmp(&b.family_key_id));
        Ok(rows)
    }

    async fn put_community(
        &self,
        community: crate::federation::SignedCommunity,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::community_admit::put_community_planned(
            self,
            community,
            crate::federation::CommunityDoor::Local,
        )
        .await?;
        Ok(())
    }

    /// v50.0.0 (CIRISPersist#925/#931, review) — the REPLICATED community
    /// entry: a record received from a peer. An identical re-put settles; a
    /// legacy non-conformant infrastructure record is admitted as data (the
    /// fold's gates apply to it); an occupied id routes through the amendment
    /// checks exactly as on the local door.
    async fn apply_replicated_community(
        &self,
        community: crate::federation::SignedCommunity,
    ) -> Result<crate::federation::ReplicatedCommunityOutcome, crate::federation::Error> {
        crate::federation::community_admit::apply_replicated_community_planned(self, community)
            .await
    }

    fn trust_root_standing_cache(
        &self,
    ) -> Option<&crate::federation::canonical_community::StandingCache> {
        Some(&self.trust_root_standing_cache)
    }

    async fn store_lineage_head_cosign(
        &self,
        cosign: &crate::federation::lineage_witness::LineageHeadCosign,
    ) -> Result<bool, crate::federation::Error> {
        // v51.0.0 (#938) — insert-or-hold, never delete (evidence).
        let mut state = self.state.lock().expect("memory backend lock");
        let key = (
            cosign.lineage_key_id.clone(),
            cosign.head_digest_sha256_hex.clone(),
            cosign.witness_key_id.clone(),
            cosign.signed_at.clone(),
        );
        if state.lineage_head_cosigns.contains_key(&key) {
            return Ok(false);
        }
        state.lineage_head_cosigns.insert(key, cosign.clone());
        Ok(true)
    }

    async fn list_lineage_head_cosigns_for(
        &self,
        lineage_key_id: &str,
    ) -> Result<Vec<crate::federation::lineage_witness::LineageHeadCosign>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut out: Vec<_> = state
            .lineage_head_cosigns
            .values()
            .filter(|c| c.lineage_key_id == lineage_key_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.signed_at
                .cmp(&b.signed_at)
                .then_with(|| a.witness_key_id.cmp(&b.witness_key_id))
        });
        Ok(out)
    }

    async fn lookup_signed_community(
        &self,
        community_key_id: &str,
    ) -> Result<Option<crate::federation::SignedCommunity>, crate::federation::Error> {
        // v50.0.0 (CIRISPersist#926) — the point twin of the signed since-read.
        let state = self.state.lock().expect("memory backend lock");
        let Some(c) = state.federation_communities.get(community_key_id) else {
            return Ok(None);
        };
        let Some((authority_key_id, scrub_signature_classical, scrub_signature_pqc)) = state
            .federation_community_authority_sigs
            .get(community_key_id)
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(crate::federation::SignedCommunity {
            community: c.clone(),
            authority_key_id,
            scrub_signature_classical,
            scrub_signature_pqc,
            supersede_proof: state
                .federation_community_supersede_proofs
                .get(community_key_id)
                .cloned(),
            cosignatures: state
                .federation_community_cosignatures
                .get(community_key_id)
                .cloned()
                .unwrap_or_default(),
            lineage: state
                .federation_community_lineages
                .get(community_key_id)
                .cloned()
                .unwrap_or_default(),
        }))
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
            // v49.0.0 (CIRISPersist#907) — containment in the room's
            // HISTORY: on the record, or named by a widening. Still raw.
            .filter(|c| {
                c.members.iter().any(|m| m.key_id == member_identity_key_id)
                    || state
                        .federation_community_membership_widenings
                        .values()
                        .any(|w| {
                            w.community_key_id == c.community_key_id
                                && w.member_key_id == member_identity_key_id
                        })
            })
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
        // v31.1.0 (CIRISPersist#662, PR #667 round-4) — `created_at` is half the
        // evidence cursor, so it is an allocated position, not a wall-clock read.
        let created_at = {
            let state = self.state.lock().expect("memory backend lock");
            let last = state.accord_proposals.values().map(|p| p.created_at).max();
            crate::federation::types::monotonic_admission_instant(chrono::Utc::now(), last)
        };
        let prep = crate::federation::accord_quorum::prepare_proposal(
            &proposal,
            authority_signature,
            created_at,
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
        // Codex round 4 on PR #1057 — a held digest is an idempotent replay,
        // asked BEFORE single use (the SQL backends' legacy pairs need it).
        if state.accord_proposals.contains_key(&proposal_digest) {
            return Ok(());
        }
        // v54.1.0 (#1047) — single use, under the same lock as the insert: a
        // proposer-minted nonce names one proposal per family.
        if let Some(other) = state.accord_proposals.iter().find_map(|(d, p)| {
            (*d != proposal_digest
                && p.proposal.family_key_id == stored.proposal.family_key_id
                && p.proposal.nonce == stored.proposal.nonce)
                .then(|| d.clone())
        }) {
            return Err(crate::federation::accord_quorum::nonce_reused(
                &stored.proposal,
                &other,
            ));
        }
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

    /// v31.1.0 (CIRISPersist#662) — the payload-digest lookup the withdrawal
    /// projection resolves with, so a role-claiming key offer costs one pass
    /// instead of assembling every proposal's participation set.
    async fn list_accord_proposals_by_payload(
        &self,
        payload_sha256: &str,
    ) -> Result<Vec<ciris_verify_core::accord_live_quorum::AccordProposal>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        // O(proposals) with no I/O and no per-proposal second read — this
        // backend has no index to answer from, and the amplification that
        // mattered was the per-hit round trip, not the filter.
        let mut rows: Vec<_> = state
            .accord_proposals
            .values()
            .filter(|p| p.proposal.payload_sha256 == payload_sha256)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.proposal.digest().cmp(&b.proposal.digest()))
        });
        Ok(rows.into_iter().map(|s| s.proposal).collect())
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
        // `server_arrival_at` is the other half of the evidence cursor; same rule.
        let arrival = {
            let state = self.state.lock().expect("memory backend lock");
            let last = state
                .accord_participations
                .iter()
                .map(|r| r.server_arrival_at)
                .max();
            crate::federation::types::monotonic_admission_instant(chrono::Utc::now(), last)
        };
        let prep = crate::federation::accord_quorum::verify_and_prepare_participation(
            &stored_proposal.proposal,
            &participation,
            standing_roster,
            arrival,
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
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::Error;
        let prep =
            crate::federation::accord_quorum::prepare_decision(&decision, chrono::Utc::now())?;
        let crate::federation::accord_quorum::PreparedDecision {
            proposal_digest,
            persist_row_hash,
            decided_at,
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

    // ─── v4.8.0 (CIRISPersist#161, CEG §11.7.1) — membership revocations.

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
        // v36.0.0 (#668) — serve position (V130 mirror), the local twin.
        let admitted_at = next_plane_position(
            &state,
            PLANE_IDENTITY_OCCURRENCE_REVOCATION,
            identity_occurrence_revocation_rows(&state).into_iter(),
        );
        let resume = crate::federation::types::compound_resume_id(&[&pk.0, &pk.1]);
        state
            .federation_identity_occurrence_revocations
            .insert(pk, row);
        stamp_plane_position(
            &mut state,
            PLANE_IDENTITY_OCCURRENCE_REVOCATION,
            resume,
            admitted_at,
        );
        // #446 de-projection — mirrors the signed revocation path.
        let route_key = (
            occurrence_key_id,
            crate::federation::types::OccurrenceTransportBinding::TRANSPORT_KIND.to_owned(),
        );
        if !state.transport_destination_sigs.contains_key(&route_key) {
            // v36.0.0 (#668/#707-class) — the retirement moves the route's
            // serve position; see the signed twin.
            let route_admitted_at = next_plane_position(
                &state,
                PLANE_TRANSPORT_DESTINATION,
                transport_destination_rows(&state).into_iter(),
            );
            let route_resume =
                crate::federation::types::compound_resume_id(&[&route_key.0, &route_key.1]);
            if let Some(route) = state.transport_destinations.get_mut(&route_key) {
                if route.retired_at.is_none() {
                    route.retired_at = Some(revoked_at);
                    stamp_plane_position(
                        &mut state,
                        PLANE_TRANSPORT_DESTINATION,
                        route_resume,
                        route_admitted_at,
                    );
                }
            }
        }
        Ok(())
    }

    async fn note_self_roster_proposal(
        &self,
        proposal_id: &str,
        identity_key_id: &str,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::federation::self_roster::SelfRosterReceipt, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // V199's FK: a receipt names a held row.
        if !state
            .federation_attestations
            .iter()
            .any(|a| a.attestation_id == proposal_id)
        {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "self-roster proposal {proposal_id} is not a held attestation"
            )));
        }
        Ok(state
            .self_roster_proposals
            .entry(proposal_id.to_owned())
            .or_insert_with(|| crate::federation::self_roster::SelfRosterReceipt {
                proposal_id: proposal_id.to_owned(),
                identity_key_id: identity_key_id.to_owned(),
                received_at,
                settled_at: None,
                outcome: None,
            })
            .clone())
    }

    async fn list_open_self_roster_proposals(
        &self,
        identity_key_id: Option<&str>,
    ) -> Result<Vec<crate::federation::self_roster::SelfRosterReceipt>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let held: std::collections::HashSet<&str> = state
            .federation_attestations
            .iter()
            .map(|a| a.attestation_id.as_str())
            .collect();
        let mut out: Vec<_> = state
            .self_roster_proposals
            .values()
            .filter(|r| r.settled_at.is_none())
            .filter(|r| identity_key_id.is_none_or(|i| r.identity_key_id == i))
            // V199's ON DELETE CASCADE: a receipt whose row is gone is gone.
            .filter(|r| held.contains(r.proposal_id.as_str()))
            .cloned()
            .collect();
        out.sort_by(|a, b| (a.received_at, &a.proposal_id).cmp(&(b.received_at, &b.proposal_id)));
        Ok(out)
    }

    async fn list_settled_self_roster_proposals(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::self_roster::SelfRosterReceipt>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let held: std::collections::HashSet<&str> = state
            .federation_attestations
            .iter()
            .map(|a| a.attestation_id.as_str())
            .collect();
        let mut out: Vec<_> = state
            .self_roster_proposals
            .values()
            .filter(|r| r.settled_at.is_some() && r.identity_key_id == identity_key_id)
            // V199's ON DELETE CASCADE: a receipt whose row is gone is gone.
            .filter(|r| held.contains(r.proposal_id.as_str()))
            .cloned()
            .collect();
        out.sort_by(|a, b| (a.settled_at, &a.proposal_id).cmp(&(b.settled_at, &b.proposal_id)));
        Ok(out)
    }

    async fn settle_self_roster_proposal(
        &self,
        proposal_id: &str,
        outcome: &str,
        settled_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(r) = state.self_roster_proposals.get_mut(proposal_id) {
            if r.settled_at.is_none() {
                r.settled_at = Some(settled_at);
                r.outcome = Some(outcome.to_owned());
            }
        }
        Ok(())
    }

    async fn put_family_membership_revocation(
        &self,
        revocation: crate::federation::SignedFamilyMembershipRevocation,
    ) -> Result<(), crate::federation::Error> {
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::FamilyMembershipRevocation,
            &revocation,
        )
        .await?
        {
            return Ok(());
        }
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE the
        // state lock (the verify resolves keys via the directory, which
        // locks itself). Was FK-existence only — a forged removal was
        // indistinguishable from a real one.
        crate::federation::verify_family_membership_revocation_admission(self, &revocation).await?;
        let mut row = revocation.family_membership_revocation;
        // v49.0.0 (CIRISPersist#910.3) — standing, by the family's own
        // `consensus_protocol` at the row's instant (the #908 family half).
        crate::federation::check_family_roster_authority(
            self,
            &row.family_key_id,
            &revocation.authority_key_id,
            &crate::federation::roster_row_signer_set(
                &revocation.authority_key_id,
                &revocation.cosignatures,
            ),
            crate::federation::types::FamilyMember {
                key_id: row.removed_identity_key_id.clone(),
                joined_at: row.effective_at,
                role: None,
            },
            true,
            row.effective_at,
        )
        .await?;
        // CEG §7.7 (CIRISPersist#161 Ask 5) — the removal-direction
        // membership-change hard_case (`change_kind: "removed"`), keyed on the
        // re-key epoch (`effective_at`). Built before the lock; RECORDED after
        // it, through `record_hard_case`.
        let removal_event = crate::federation::hard_case::membership_removed_event(
            crate::federation::hard_case::kind::FAMILY_MEMBERSHIP_CHANGE,
            &row.family_key_id,
            &row.removed_identity_key_id,
            row.effective_at,
        );
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            // v48.0.0 (CIRISPersist#860, V151) — the group FK points at the
            // GROUP table: a family / a room is a keyless identifier. The
            // member is a key.
            if !state.federation_families.contains_key(&row.family_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_families",
                    row.family_key_id
                )));
            }
            if !state
                .federation_keys
                .contains_key(&row.removed_identity_key_id)
            {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_keys",
                    row.removed_identity_key_id
                )));
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            let revocation_key = (
                row.family_key_id.clone(),
                row.removed_identity_key_id.clone(),
                row.effective_at,
            );
            // v47.1.0 (CIRISPersist#861) — IDEMPOTENT on the PK. v49.0.0
            // (#910.1, V154): the PK carries `effective_at`, so an exact retry
            // is the no-op and a removal at another instant is another event
            // (a re-removal after a re-add, or an earlier removal the fold
            // honours first).
            if state
                .federation_family_membership_revocations
                .contains_key(&revocation_key)
            {
                return Ok(());
            }
            // v21.1.0 (CIRISPersist#507b) — computed before the moves below
            // consume `row.clone()` / `revocation.*`.
            let effective_at_rfc3339 = revocation_key.2.to_rfc3339();
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("family_key_id", &revocation_key.0),
                ("removed_identity_key_id", &revocation_key.1),
                ("effective_at", &effective_at_rfc3339),
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
            // v49.0.0 (CIRISPersist#908, V153 mirror).
            state
                .federation_family_membership_revocation_cosignatures
                .insert(revocation_key.clone(), revocation.cosignatures);
            // v36.0.0 (#668) — serve position (V130 mirror).
            let admitted_at = next_plane_position(
                &state,
                PLANE_FAMILY_MEMBERSHIP_REVOCATION,
                family_membership_revocation_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[
                &revocation_key.0,
                &revocation_key.1,
                &effective_at_rfc3339,
            ]);
            state
                .federation_family_membership_revocations
                .insert(revocation_key, row);
            stamp_plane_position(
                &mut state,
                PLANE_FAMILY_MEMBERSHIP_REVOCATION,
                resume,
                admitted_at,
            );
            wire_index_key
        };
        self.index_stored_record("FamilyMembershipRevocation", &wire_index_key)
            .await?;
        // v31.2.0 (CIRISPersist#670) — through `record_hard_case`, which is
        // where `check_admin_action_attribution` lives, and NOT by reaching
        // into `federation_hard_case_events` directly. The direct insert this
        // replaces was behaviourally identical *today* — the attribution gate
        // short-circuits for a kind that is not `admin_action:*`, and the
        // `.entry().or_insert()` matched the SQL backends' idempotent upsert —
        // which is exactly what made it invisible. It was one gate away from a
        // hole, permanently, on the arm nobody watches.
        // v57.0.0 (CIRISPersist#988 item 2) — an observation: a node with no
        // attester records nothing; the removal already landed.
        crate::federation::hard_case::record_observation(self, removal_event).await?;
        Ok(())
    }

    async fn put_community_membership_revocation(
        &self,
        revocation: crate::federation::SignedCommunityMembershipRevocation,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::community_admit::put_community_membership_revocation_planned(
            self, revocation,
        )
        .await
    }

    async fn put_community_membership_widening(
        &self,
        widening: crate::federation::SignedCommunityMembershipWidening,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::community_admit::put_community_membership_widening_planned(
            self, widening,
        )
        .await
    }

    async fn put_family_membership_widening(
        &self,
        widening: crate::federation::SignedFamilyMembershipWidening,
    ) -> Result<(), crate::federation::Error> {
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::FamilyMembershipWidening,
            &widening,
        )
        .await?
        {
            return Ok(());
        }
        // v49.0.0 (CIRISPersist#910, FSD `ROOM_ROSTER_AUTHORITY.md` §10.1) —
        // the family twin of the room's widening door; see the sqlite twin.
        crate::federation::verify_family_membership_widening_admission(self, &widening).await?;
        let mut row = widening.family_membership_widening;
        crate::federation::reject_future_dated_family_widening(row.effective_at)?;
        crate::federation::check_family_roster_authority(
            self,
            &row.family_key_id,
            &widening.authority_key_id,
            &crate::federation::roster_row_signer_set(
                &widening.authority_key_id,
                &widening.cosignatures,
            ),
            row.member(),
            false,
            row.effective_at,
        )
        .await?;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            // The V154 FKs: the family (a keyless group) and the member (a key).
            if !state.federation_families.contains_key(&row.family_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_families",
                    row.family_key_id
                )));
            }
            if !state.federation_keys.contains_key(&row.member_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_keys",
                    row.member_key_id
                )));
            }
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            let key = (
                row.family_key_id.clone(),
                row.member_key_id.clone(),
                row.effective_at,
            );
            if state
                .federation_family_membership_widenings
                .contains_key(&key)
            {
                return Ok(());
            }
            let effective_at_rfc3339 = key.2.to_rfc3339();
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("family_key_id", &key.0),
                ("member_key_id", &key.1),
                ("effective_at", &effective_at_rfc3339),
            ]);
            state
                .federation_family_membership_widening_authority_sigs
                .insert(
                    key.clone(),
                    (
                        widening.authority_key_id,
                        widening.scrub_signature_classical,
                        widening.scrub_signature_pqc,
                    ),
                );
            state
                .federation_family_membership_widening_cosignatures
                .insert(key.clone(), widening.cosignatures);
            let admitted_at = next_plane_position(
                &state,
                PLANE_FAMILY_MEMBERSHIP_WIDENING,
                family_membership_widening_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[
                &key.0,
                &key.1,
                &effective_at_rfc3339,
            ]);
            state
                .federation_family_membership_widenings
                .insert(key, row);
            stamp_plane_position(
                &mut state,
                PLANE_FAMILY_MEMBERSHIP_WIDENING,
                resume,
                admitted_at,
            );
            wire_index_key
        };
        self.index_stored_record("FamilyMembershipWidening", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn put_community_membership_listing(
        &self,
        listing: crate::federation::SignedCommunityMembershipListing,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::community_admit::put_community_membership_listing_planned(self, listing)
            .await
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
        rows.sort_by(|a, b| {
            a.removed_identity_key_id
                .cmp(&b.removed_identity_key_id)
                .then_with(|| a.effective_at.cmp(&b.effective_at))
        });
        Ok(rows)
    }

    async fn list_community_membership_widenings_for(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<crate::federation::CommunityMembershipWidening>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_community_membership_widenings
            .values()
            .filter(|w| w.community_key_id == community_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.member_key_id
                .cmp(&b.member_key_id)
                .then_with(|| a.effective_at.cmp(&b.effective_at))
        });
        Ok(rows)
    }

    async fn list_community_membership_listings_for(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<crate::federation::CommunityMembershipListing>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_community_membership_listings
            .values()
            .map(|l| &l.community_membership_listing)
            .filter(|l| l.community_key_id == community_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.member_key_id
                .cmp(&b.member_key_id)
                .then_with(|| a.effective_at.cmp(&b.effective_at))
        });
        Ok(rows)
    }

    async fn community_roster_signers(
        &self,
        community_key_id: &str,
    ) -> Result<crate::federation::CommunityRosterSigners, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        if !state.federation_communities.contains_key(community_key_id) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "community_roster_signers names unknown community_key_id {community_key_id:?}"
            )));
        }
        let record_authority_key_id = state
            .federation_community_authority_sigs
            .get(community_key_id)
            .map(|s| s.0.clone());
        type EventKey = (String, String, chrono::DateTime<chrono::Utc>);
        let signer =
            |key: &EventKey,
             sigs: &HashMap<EventKey, AuthoritySig>,
             cosigs: &HashMap<EventKey, Vec<crate::federation::RosterCosignature>>| {
                crate::federation::RosterEventSigner {
                    member_key_id: key.1.clone(),
                    effective_at: key.2,
                    authority_key_id: sigs.get(key).map(|s| s.0.clone()),
                    cosigner_key_ids: cosigs
                        .get(key)
                        .map(|c| c.iter().map(|c| c.authority_key_id.clone()).collect())
                        .unwrap_or_default(),
                }
            };
        let widening_signers = state
            .federation_community_membership_widenings
            .keys()
            .filter(|k| k.0 == community_key_id)
            .map(|k| {
                signer(
                    k,
                    &state.federation_community_membership_widening_authority_sigs,
                    &state.federation_community_membership_widening_cosignatures,
                )
            })
            .collect();
        let revocation_signers = state
            .federation_community_membership_revocations
            .keys()
            .filter(|k| k.0 == community_key_id)
            .map(|k| {
                signer(
                    k,
                    &state.federation_community_membership_revocation_authority_sigs,
                    &state.federation_community_membership_revocation_cosignatures,
                )
            })
            .collect();
        Ok(crate::federation::CommunityRosterSigners {
            record_authority_key_id,
            widening_signers,
            revocation_signers,
        })
    }

    async fn list_family_membership_widenings_for(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<crate::federation::FamilyMembershipWidening>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_family_membership_widenings
            .values()
            .filter(|w| w.family_key_id == family_key_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.member_key_id
                .cmp(&b.member_key_id)
                .then_with(|| a.effective_at.cmp(&b.effective_at))
        });
        Ok(rows)
    }

    async fn family_roster_signers(
        &self,
        family_key_id: &str,
    ) -> Result<crate::federation::CommunityRosterSigners, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        if !state.federation_families.contains_key(family_key_id) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "family_roster_signers names unknown family_key_id {family_key_id:?}"
            )));
        }
        let record_authority_key_id = state
            .federation_family_authority_sigs
            .get(family_key_id)
            .map(|s| s.0.clone());
        type EventKey = (String, String, chrono::DateTime<chrono::Utc>);
        let signer =
            |key: &EventKey,
             sigs: &HashMap<EventKey, AuthoritySig>,
             cosigs: &HashMap<EventKey, Vec<crate::federation::RosterCosignature>>| {
                crate::federation::RosterEventSigner {
                    member_key_id: key.1.clone(),
                    effective_at: key.2,
                    authority_key_id: sigs.get(key).map(|s| s.0.clone()),
                    cosigner_key_ids: cosigs
                        .get(key)
                        .map(|c| c.iter().map(|c| c.authority_key_id.clone()).collect())
                        .unwrap_or_default(),
                }
            };
        let widening_signers = state
            .federation_family_membership_widenings
            .keys()
            .filter(|k| k.0 == family_key_id)
            .map(|k| {
                signer(
                    k,
                    &state.federation_family_membership_widening_authority_sigs,
                    &state.federation_family_membership_widening_cosignatures,
                )
            })
            .collect();
        let revocation_signers = state
            .federation_family_membership_revocations
            .keys()
            .filter(|k| k.0 == family_key_id)
            .map(|k| {
                signer(
                    k,
                    &state.federation_family_membership_revocation_authority_sigs,
                    &state.federation_family_membership_revocation_cosignatures,
                )
            })
            .collect();
        Ok(crate::federation::CommunityRosterSigners {
            record_authority_key_id,
            widening_signers,
            revocation_signers,
        })
    }

    // ─── v6.7.0 (CIRISPersist#146 Ask 3 / #161 Ask 5) — hard_case:* surface.
    //     Memory parity with the sqlite/postgres `hard_case_events` table so
    //     the substrate's removal/SLA emissions behave identically on all
    //     three backends. Idempotent on the deterministic `event_id`.

    async fn record_hard_case(
        &self,
        event: crate::federation::hard_case::HardCaseEvent,
    ) -> Result<(), crate::federation::Error> {
        // v57.0.0 (CIRISPersist#988 item 2) — a `hard_case:{kind}:v1` row on
        // the plane, decided once (`plan_hard_case_row`); the map is its
        // projection, written under the same lock.
        crate::federation::attestation_admit::record_hard_case_planned(self, event).await
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
            .map(|(_, e)| e)
            .filter(|e| filter.kind.as_ref().is_none_or(|k| &e.kind == k))
            .filter(|e| filter.since.is_none_or(|s| e.emitted_at >= s))
            .filter(|e| {
                filter
                    .emitter_key_id
                    .as_ref()
                    .is_none_or(|k| &e.emitter_key_id == k)
            })
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
        // v60.0.0 (CIRISPersist#934 step 4) — one fold over the typed read.
        let rows =
            crate::federation::consent_admit::consent_revocations_planned(self, since).await?;
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
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::LocationProof,
            &proof,
        )
        .await?
        {
            return Ok(());
        }
        // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any
        // other admission step.
        crate::federation::verify_location_proof_admission(self, &proof).await?;
        // v53.1.2 (CIRISPersist#984 row 19) — a held PK re-offered as a
        // WITHDRAWAL (the attester's re-signed row, as a peer serves it) is the
        // withdraw door's case: the local and the replicated path run the one
        // predicate. Any other re-offer keeps its path.
        if proof.location_proof.withdrawn_at.is_some() {
            let held = self
                .state
                .lock()
                .expect("memory backend lock")
                .federation_location_proofs
                .contains_key(&(
                    proof.location_proof.subject_key_id.clone(),
                    proof.location_proof.asserted_at,
                ));
            if held {
                return crate::federation::FederationDirectory::withdraw_location_proof(
                    self, proof,
                )
                .await;
            }
        }
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
            // v36.0.0 (#668) — serve position (V130 mirror). Resume id is
            // (subject_key_id, persist_row_hash), matching the SQL twins.
            let admitted_at = next_plane_position(
                &state,
                PLANE_LOCATION_PROOF,
                location_proof_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[
                &row.subject_key_id,
                &row.persist_row_hash,
            ]);
            state.federation_location_proofs.insert(proof_key, row);
            stamp_plane_position(&mut state, PLANE_LOCATION_PROOF, resume, admitted_at);
            wire_index_key
        };
        self.index_stored_record("LocationProof", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn withdraw_location_proof(
        &self,
        proof: crate::federation::SignedLocationProof,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::location::{
            check_location_proof_withdrawal, LocationProofWithdrawal,
        };
        // #984 row 16 — the signature and standing legs, exactly as a put.
        crate::federation::verify_location_proof_admission(self, &proof).await?;
        // The lock is scoped to this block: the guard is not `Send`, and the
        // re-index below awaits after the write is durable.
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let key = (
                proof.location_proof.subject_key_id.clone(),
                proof.location_proof.asserted_at,
            );
            let Some(held_row) = state.federation_location_proofs.get(&key).cloned() else {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "location_proof_withdraw_not_held: no proof by {} at {} is held here",
                    key.0, key.1
                )));
            };
            let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                .federation_location_proof_authority_sigs
                .get(&key)
                .cloned()
                .unwrap_or_default();
            let held = crate::federation::SignedLocationProof {
                location_proof: held_row,
                authority_key_id,
                scrub_signature_classical,
                scrub_signature_pqc,
            };
            match check_location_proof_withdrawal(&held, &proof)? {
                LocationProofWithdrawal::AlreadyWithdrawn => return Ok(()),
                LocationProofWithdrawal::Apply => {}
            }
            let mut row = proof.location_proof;
            row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
            // The row moves to a fresh serve position so a peer past its cursor
            // is served the withdrawal.
            let admitted_at = next_plane_position(
                &state,
                PLANE_LOCATION_PROOF,
                location_proof_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[
                &row.subject_key_id,
                &row.persist_row_hash,
            ]);
            state.federation_location_proof_authority_sigs.insert(
                key.clone(),
                (
                    proof.authority_key_id,
                    proof.scrub_signature_classical,
                    proof.scrub_signature_pqc,
                ),
            );
            let wire_index_key = crate::federation::wire_index::record_key(&[
                ("subject_key_id", &row.subject_key_id),
                (
                    "asserted_at",
                    &crate::federation::wire_index::locator_instant(&row.asserted_at),
                ),
            ]);
            state.federation_location_proofs.insert(key, row);
            stamp_plane_position(&mut state, PLANE_LOCATION_PROOF, resume, admitted_at);
            wire_index_key
        };
        // v53.1.3 (Codex on #985 P1, #986) — the row's bytes changed, so the
        // signed wire index must learn the new content hash exactly as the
        // put path teaches it.
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
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::Organization,
            &signed.organization,
        )
        .await?
        {
            return Ok(());
        }
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
            // v36.0.0 (#668) — THIS node's serve position (V130 mirror),
            // allocated before the insert so the allocator reads only
            // pre-existing rows, stamped after it lands.
            let admitted_at = next_plane_position(
                &state,
                PLANE_ORGANIZATION,
                organization_rows(&state).into_iter(),
            );
            let id_for_stamp = row.attestation_id.clone();
            memory_idempotent_insert(
                &mut state.federation_organizations,
                row.attestation_id.clone(),
                row,
                "organization",
            )?;
            stamp_plane_position(&mut state, PLANE_ORGANIZATION, id_for_stamp, admitted_at);
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
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::OrgMembership,
            &signed.org_membership,
        )
        .await?
        {
            return Ok(());
        }
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
            // v36.0.0 (#668) — serve position (V130 mirror).
            let admitted_at = next_plane_position(
                &state,
                PLANE_ORG_MEMBERSHIP,
                org_membership_rows(&state).into_iter(),
            );
            let id_for_stamp = row.attestation_id.clone();
            memory_idempotent_insert(
                &mut state.federation_org_memberships,
                row.attestation_id.clone(),
                row,
                "org_membership",
            )?;
            stamp_plane_position(&mut state, PLANE_ORG_MEMBERSHIP, id_for_stamp, admitted_at);
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
        // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
        // before any verification (`replication_policy::settle_if_held`).
        if crate::federation::replication_policy::settle_if_held(
            self,
            crate::federation::replication_policy::EnvelopeKind::PartnerRecord,
            &signed,
        )
        .await?
        {
            return Ok(());
        }
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
            // v36.0.0 (#668) — serve position (V130 mirror).
            let admitted_at = next_plane_position(
                &state,
                PLANE_PARTNER_RECORD,
                partner_record_rows(&state).into_iter(),
            );
            memory_idempotent_insert(
                &mut state.federation_partner_records,
                attestation_id.clone(),
                row,
                "partner_record",
            )?;
            stamp_plane_position(
                &mut state,
                PLANE_PARTNER_RECORD,
                attestation_id.clone(),
                admitted_at,
            );
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

    // v36.0.0 (CIRISPersist#668) — every cursor below reads THIS node's
    // serve position (the `serve_positions` side map, falling back to the
    // plane's legacy producer instant exactly as the sqlite COALESCE does)
    // and resumes on the `(position, id)` PAIR.

    async fn list_organizations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedOrganization>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let position = |o: &crate::federation::operational::Organization| {
            plane_position(&state, PLANE_ORGANIZATION, &o.attestation_id, o.asserted_at)
        };
        let mut rows: Vec<_> = state
            .federation_organizations
            .values()
            .filter(|o| {
                since.as_ref().is_none_or(|(s_at, s_id)| {
                    (position(o), o.attestation_id.as_str()) > (*s_at, s_id.as_str())
                })
            })
            .map(|o| crate::federation::ServedOrganization {
                admitted_at: position(o),
                organization: o.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            a.admitted_at.cmp(&b.admitted_at).then_with(|| {
                a.organization
                    .attestation_id
                    .cmp(&b.organization.attestation_id)
            })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_org_memberships_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedOrgMembership>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let position = |m: &crate::federation::operational::OrgMembership| {
            plane_position(
                &state,
                PLANE_ORG_MEMBERSHIP,
                &m.attestation_id,
                m.asserted_at,
            )
        };
        let mut rows: Vec<_> = state
            .federation_org_memberships
            .values()
            .filter(|m| {
                since.as_ref().is_none_or(|(s_at, s_id)| {
                    (position(m), m.attestation_id.as_str()) > (*s_at, s_id.as_str())
                })
            })
            .map(|m| crate::federation::ServedOrgMembership {
                admitted_at: position(m),
                org_membership: m.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            a.admitted_at.cmp(&b.admitted_at).then_with(|| {
                a.org_membership
                    .attestation_id
                    .cmp(&b.org_membership.attestation_id)
            })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_partner_records_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedPartnerRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let position = |p: &crate::federation::operational::PartnerRecord| {
            plane_position(
                &state,
                PLANE_PARTNER_RECORD,
                &p.attestation_id,
                p.asserted_at,
            )
        };
        let mut rows: Vec<_> = state
            .federation_partner_records
            .values()
            .filter(|p| {
                since.as_ref().is_none_or(|(s_at, s_id)| {
                    (position(p), p.attestation_id.as_str()) > (*s_at, s_id.as_str())
                })
            })
            .map(|p| crate::federation::ServedPartnerRecord {
                admitted_at: position(p),
                partner_record: p.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            a.admitted_at.cmp(&b.admitted_at).then_with(|| {
                a.partner_record
                    .attestation_id
                    .cmp(&b.partner_record.attestation_id)
            })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_partner_records_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedSignedPartnerRecord>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let position = |p: &crate::federation::operational::PartnerRecord| {
            plane_position(
                &state,
                PLANE_PARTNER_RECORD,
                &p.attestation_id,
                p.asserted_at,
            )
        };
        let mut rows: Vec<_> = state
            .federation_partner_records
            .values()
            .filter(|p| {
                since.as_ref().is_none_or(|(s_at, s_id)| {
                    (position(p), p.attestation_id.as_str()) > (*s_at, s_id.as_str())
                })
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            position(a)
                .cmp(&position(b))
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
                crate::federation::ServedSignedPartnerRecord {
                    admitted_at: position(&partner_record),
                    record: crate::federation::SignedPartnerRecord {
                        partner_record,
                        steward_signatures,
                        threshold,
                    },
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
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedFamily>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let position = |f: &crate::federation::types::Family| {
            plane_position(&state, PLANE_FAMILY, &f.family_key_id, f.founded_at)
        };
        let mut rows: Vec<_> = state
            .federation_families
            .values()
            .filter(|f| {
                since.as_ref().is_none_or(|(s_at, s_id)| {
                    (position(f), f.family_key_id.as_str()) > (*s_at, s_id.as_str())
                })
            })
            .filter_map(|f| {
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_family_authority_sigs
                    .get(&f.family_key_id)?
                    .clone();
                Some(crate::federation::ServedFamily {
                    admitted_at: position(f),
                    family: crate::federation::SignedFamily {
                        family: f.clone(),
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        supersede_proof: state
                            .federation_family_supersede_proofs
                            .get(&f.family_key_id)
                            .cloned(),
                        cosignatures: state
                            .federation_family_cosignatures
                            .get(&f.family_key_id)
                            .cloned()
                            .unwrap_or_default(),
                    },
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.admitted_at.cmp(&b.admitted_at).then_with(|| {
                a.family
                    .family
                    .family_key_id
                    .cmp(&b.family.family.family_key_id)
            })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_communities_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedCommunity>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let position = |c: &crate::federation::types::Community| {
            plane_position(&state, PLANE_COMMUNITY, &c.community_key_id, c.founded_at)
        };
        let mut rows: Vec<_> = state
            .federation_communities
            .values()
            .filter(|c| {
                since.as_ref().is_none_or(|(s_at, s_id)| {
                    (position(c), c.community_key_id.as_str()) > (*s_at, s_id.as_str())
                })
            })
            .filter_map(|c| {
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_community_authority_sigs
                    .get(&c.community_key_id)?
                    .clone();
                Some(crate::federation::ServedCommunity {
                    admitted_at: position(c),
                    community: crate::federation::SignedCommunity {
                        community: c.clone(),
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        supersede_proof: state
                            .federation_community_supersede_proofs
                            .get(&c.community_key_id)
                            .cloned(),
                        cosignatures: state
                            .federation_community_cosignatures
                            .get(&c.community_key_id)
                            .cloned()
                            .unwrap_or_default(),
                        lineage: state
                            .federation_community_lineages
                            .get(&c.community_key_id)
                            .cloned()
                            .unwrap_or_default(),
                    },
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.admitted_at.cmp(&b.admitted_at).then_with(|| {
                a.community
                    .community
                    .community_key_id
                    .cmp(&b.community.community.community_key_id)
            })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_location_proofs_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedLocationProof>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // The row-unique resume id is (subject_key_id, persist_row_hash) —
        // the PK carries an instant, which stays out of the token.
        let resume_id = |p: &crate::federation::types::LocationProof| {
            crate::federation::types::compound_resume_id(&[&p.subject_key_id, &p.persist_row_hash])
        };
        let position = |p: &crate::federation::types::LocationProof| {
            plane_position(&state, PLANE_LOCATION_PROOF, &resume_id(p), p.asserted_at)
        };
        let since_parts = since.as_ref().map(|(s_at, s_id)| {
            let [a, b] = crate::federation::types::split_resume_id::<2>(s_id);
            (*s_at, a.to_owned(), b.to_owned())
        });
        let mut rows: Vec<_> = state
            .federation_location_proofs
            .values()
            .filter(|p| {
                since_parts.as_ref().is_none_or(|(s_at, s_a, s_b)| {
                    (
                        position(p),
                        p.subject_key_id.as_str(),
                        p.persist_row_hash.as_str(),
                    ) > (*s_at, s_a.as_str(), s_b.as_str())
                })
            })
            .filter_map(|p| {
                let key = (p.subject_key_id.clone(), p.asserted_at);
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_location_proof_authority_sigs
                    .get(&key)?
                    .clone();
                Some(crate::federation::ServedLocationProof {
                    admitted_at: position(p),
                    proof: crate::federation::SignedLocationProof {
                        location_proof: p.clone(),
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                    },
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| {
                    a.proof
                        .location_proof
                        .subject_key_id
                        .cmp(&b.proof.location_proof.subject_key_id)
                })
                .then_with(|| {
                    a.proof
                        .location_proof
                        .persist_row_hash
                        .cmp(&b.proof.location_proof.persist_row_hash)
                })
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_family_membership_revocations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedFamilyMembershipRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let resume_id = |r: &crate::federation::types::FamilyMembershipRevocation| {
            crate::federation::types::compound_resume_id(&[
                &r.family_key_id,
                &r.removed_identity_key_id,
                &r.effective_at.to_rfc3339(),
            ])
        };
        let position = |r: &crate::federation::types::FamilyMembershipRevocation| {
            plane_position(
                &state,
                PLANE_FAMILY_MEMBERSHIP_REVOCATION,
                &resume_id(r),
                r.removed_at,
            )
        };
        let since_parts = since.as_ref().map(|(s_at, s_id)| {
            let [a, b, c] = crate::federation::types::split_resume_id::<3>(s_id);
            (*s_at, a.to_owned(), b.to_owned(), c.to_owned())
        });
        let mut rows: Vec<_> = state
            .federation_family_membership_revocations
            .values()
            .filter(|r| {
                since_parts.as_ref().is_none_or(|(s_at, s_a, s_b, s_c)| {
                    (
                        position(r),
                        r.family_key_id.as_str(),
                        r.removed_identity_key_id.as_str(),
                        r.effective_at.to_rfc3339().as_str(),
                    ) > (*s_at, s_a.as_str(), s_b.as_str(), s_c.as_str())
                })
            })
            .filter_map(|r| {
                let key = (
                    r.family_key_id.clone(),
                    r.removed_identity_key_id.clone(),
                    r.effective_at,
                );
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_family_membership_revocation_authority_sigs
                    .get(&key)?
                    .clone();
                let cosignatures = state
                    .federation_family_membership_revocation_cosignatures
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                Some(crate::federation::ServedFamilyMembershipRevocation {
                    admitted_at: position(r),
                    revocation: crate::federation::SignedFamilyMembershipRevocation {
                        family_membership_revocation: r.clone(),
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        cosignatures,
                    },
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            let ar = &a.revocation.family_membership_revocation;
            let br = &b.revocation.family_membership_revocation;
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| ar.family_key_id.cmp(&br.family_key_id))
                .then_with(|| ar.removed_identity_key_id.cmp(&br.removed_identity_key_id))
                .then_with(|| ar.effective_at.cmp(&br.effective_at))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_community_membership_revocations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedCommunityMembershipRevocation>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let resume_id = |r: &crate::federation::types::CommunityMembershipRevocation| {
            crate::federation::types::compound_resume_id(&[
                &r.community_key_id,
                &r.removed_identity_key_id,
                &r.effective_at.to_rfc3339(),
            ])
        };
        let position = |r: &crate::federation::types::CommunityMembershipRevocation| {
            plane_position(
                &state,
                PLANE_COMMUNITY_MEMBERSHIP_REVOCATION,
                &resume_id(r),
                r.removed_at,
            )
        };
        let since_parts = since.as_ref().map(|(s_at, s_id)| {
            let [a, b, c] = crate::federation::types::split_resume_id::<3>(s_id);
            (*s_at, a.to_owned(), b.to_owned(), c.to_owned())
        });
        let mut rows: Vec<_> = state
            .federation_community_membership_revocations
            .values()
            .filter(|r| {
                since_parts.as_ref().is_none_or(|(s_at, s_a, s_b, s_c)| {
                    (
                        position(r),
                        r.community_key_id.as_str(),
                        r.removed_identity_key_id.as_str(),
                        r.effective_at.to_rfc3339().as_str(),
                    ) > (*s_at, s_a.as_str(), s_b.as_str(), s_c.as_str())
                })
            })
            .filter_map(|r| {
                let key = (
                    r.community_key_id.clone(),
                    r.removed_identity_key_id.clone(),
                    r.effective_at,
                );
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_community_membership_revocation_authority_sigs
                    .get(&key)?
                    .clone();
                let cosignatures = state
                    .federation_community_membership_revocation_cosignatures
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                Some(crate::federation::ServedCommunityMembershipRevocation {
                    admitted_at: position(r),
                    revocation: crate::federation::SignedCommunityMembershipRevocation {
                        community_membership_revocation: r.clone(),
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        cosignatures,
                    },
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            let ar = &a.revocation.community_membership_revocation;
            let br = &b.revocation.community_membership_revocation;
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| ar.community_key_id.cmp(&br.community_key_id))
                .then_with(|| ar.removed_identity_key_id.cmp(&br.removed_identity_key_id))
                .then_with(|| ar.effective_at.cmp(&br.effective_at))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_community_membership_widenings_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedCommunityMembershipWidening>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let resume_id = |w: &crate::federation::types::CommunityMembershipWidening| {
            crate::federation::types::compound_resume_id(&[
                &w.community_key_id,
                &w.member_key_id,
                &w.effective_at.to_rfc3339(),
            ])
        };
        let position = |w: &crate::federation::types::CommunityMembershipWidening| {
            plane_position(
                &state,
                PLANE_COMMUNITY_MEMBERSHIP_WIDENING,
                &resume_id(w),
                w.joined_at,
            )
        };
        let since_parts = since.as_ref().map(|(s_at, s_id)| {
            let [a, b, c] = crate::federation::types::split_resume_id::<3>(s_id);
            (*s_at, a.to_owned(), b.to_owned(), c.to_owned())
        });
        let mut rows: Vec<_> = state
            .federation_community_membership_widenings
            .values()
            .filter(|w| {
                since_parts.as_ref().is_none_or(|(s_at, s_a, s_b, s_c)| {
                    (
                        position(w),
                        w.community_key_id.as_str(),
                        w.member_key_id.as_str(),
                        w.effective_at.to_rfc3339().as_str(),
                    ) > (*s_at, s_a.as_str(), s_b.as_str(), s_c.as_str())
                })
            })
            .filter_map(|w| {
                let key = (
                    w.community_key_id.clone(),
                    w.member_key_id.clone(),
                    w.effective_at,
                );
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_community_membership_widening_authority_sigs
                    .get(&key)?
                    .clone();
                let cosignatures = state
                    .federation_community_membership_widening_cosignatures
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                Some(crate::federation::ServedCommunityMembershipWidening {
                    admitted_at: position(w),
                    widening: crate::federation::SignedCommunityMembershipWidening {
                        community_membership_widening: w.clone(),
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        cosignatures,
                    },
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            let aw = &a.widening.community_membership_widening;
            let bw = &b.widening.community_membership_widening;
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| aw.community_key_id.cmp(&bw.community_key_id))
                .then_with(|| aw.member_key_id.cmp(&bw.member_key_id))
                .then_with(|| aw.effective_at.cmp(&bw.effective_at))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_community_membership_listings_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedCommunityMembershipListing>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let position = |l: &crate::federation::types::CommunityMembershipListing| {
            plane_position(
                &state,
                PLANE_COMMUNITY_MEMBERSHIP_LISTING,
                &crate::federation::types::compound_resume_id(&[
                    &l.community_key_id,
                    &l.member_key_id,
                    &l.effective_at.to_rfc3339(),
                ]),
                l.effective_at,
            )
        };
        let since_parts = since.as_ref().map(|(s_at, s_id)| {
            let [a, b, c] = crate::federation::types::split_resume_id::<3>(s_id);
            (*s_at, a.to_owned(), b.to_owned(), c.to_owned())
        });
        let mut rows: Vec<_> = state
            .federation_community_membership_listings
            .values()
            .filter(|s| !s.authority_key_id.is_empty())
            .filter(|s| {
                let l = &s.community_membership_listing;
                since_parts.as_ref().is_none_or(|(s_at, s_a, s_b, s_c)| {
                    (
                        position(l),
                        l.community_key_id.as_str(),
                        l.member_key_id.as_str(),
                        l.effective_at.to_rfc3339().as_str(),
                    ) > (*s_at, s_a.as_str(), s_b.as_str(), s_c.as_str())
                })
            })
            .map(|s| crate::federation::ServedCommunityMembershipListing {
                admitted_at: position(&s.community_membership_listing),
                listing: s.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            let al = &a.listing.community_membership_listing;
            let bl = &b.listing.community_membership_listing;
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| al.community_key_id.cmp(&bl.community_key_id))
                .then_with(|| al.member_key_id.cmp(&bl.member_key_id))
                .then_with(|| al.effective_at.cmp(&bl.effective_at))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_signed_family_membership_widenings_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedFamilyMembershipWidening>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let resume_id = |w: &crate::federation::types::FamilyMembershipWidening| {
            crate::federation::types::compound_resume_id(&[
                &w.family_key_id,
                &w.member_key_id,
                &w.effective_at.to_rfc3339(),
            ])
        };
        let position = |w: &crate::federation::types::FamilyMembershipWidening| {
            plane_position(
                &state,
                PLANE_FAMILY_MEMBERSHIP_WIDENING,
                &resume_id(w),
                w.joined_at,
            )
        };
        let since_parts = since.as_ref().map(|(s_at, s_id)| {
            let [a, b, c] = crate::federation::types::split_resume_id::<3>(s_id);
            (*s_at, a.to_owned(), b.to_owned(), c.to_owned())
        });
        let mut rows: Vec<_> = state
            .federation_family_membership_widenings
            .values()
            .filter(|w| {
                since_parts.as_ref().is_none_or(|(s_at, s_a, s_b, s_c)| {
                    (
                        position(w),
                        w.family_key_id.as_str(),
                        w.member_key_id.as_str(),
                        w.effective_at.to_rfc3339().as_str(),
                    ) > (*s_at, s_a.as_str(), s_b.as_str(), s_c.as_str())
                })
            })
            .filter_map(|w| {
                let key = (
                    w.family_key_id.clone(),
                    w.member_key_id.clone(),
                    w.effective_at,
                );
                let (authority_key_id, scrub_signature_classical, scrub_signature_pqc) = state
                    .federation_family_membership_widening_authority_sigs
                    .get(&key)?
                    .clone();
                let cosignatures = state
                    .federation_family_membership_widening_cosignatures
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                Some(crate::federation::ServedFamilyMembershipWidening {
                    admitted_at: position(w),
                    widening: crate::federation::SignedFamilyMembershipWidening {
                        family_membership_widening: w.clone(),
                        authority_key_id,
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        cosignatures,
                    },
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            let aw = &a.widening.family_membership_widening;
            let bw = &b.widening.family_membership_widening;
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| aw.family_key_id.cmp(&bw.family_key_id))
                .then_with(|| aw.member_key_id.cmp(&bw.member_key_id))
                .then_with(|| aw.effective_at.cmp(&bw.effective_at))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    // ─── v21.1.0 (CIRISPersist#507c) — bulk signed-since reads for the 5
    //     PRIMARY signed planes.

    /// v31.1.0 (CIRISPersist#662) — the signed accord EVIDENCE cursor. Page
    /// selection is over PROPOSALS; the participation set for each is
    /// assembled by the shared
    /// [`accord_carriage::assemble_evidence_page`](crate::federation::accord_carriage::assemble_evidence_page)
    /// so the `member_id` sort order is identical on all three backends.
    async fn list_signed_accord_quorum_evidence_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<
        Vec<crate::federation::accord_carriage::AccordQuorumEvidence>,
        crate::federation::Error,
    > {
        let page = {
            let state = self.state.lock().expect("memory backend lock");
            // v31.1.0 (CIRISPersist#662, PR review P1) — the cursor is the
            // bundle's VISIBILITY instant: `max(created_at, latest
            // server_arrival_at)`. The SQL backends spell the same expression
            // in their `WHERE`/`ORDER BY`; `assemble_evidence_page` recomputes
            // it for the returned struct, so all three agree by construction.
            let evidence_at = |p: &crate::federation::accord_quorum::StoredProposal| {
                let digest = p.proposal.digest();
                state
                    .accord_participations
                    .iter()
                    .filter(|r| r.participation.proposal_digest == digest)
                    .map(|r| r.server_arrival_at)
                    .max()
                    .map_or(p.created_at, |latest| latest.max(p.created_at))
            };
            // v31.1.0 (PR review P1) — the SELECTED instant is carried out
            // with each row, never recomputed at assembly time; see
            // `assemble_evidence_page` for the torn read that would otherwise
            // let a consumer's cursor skip a page-limited proposal.
            // v36.0.0 (#668) — the PAIR: two proposals whose latest vote
            // landed in one instant tie, and the digest is the tie-break.
            let mut rows: Vec<_> = state
                .accord_proposals
                .values()
                .map(|p| (p.clone(), evidence_at(p)))
                .filter(|(p, at)| {
                    since.as_ref().is_none_or(|(s_at, s_id)| {
                        (*at, p.proposal.digest()) > (*s_at, s_id.clone())
                    })
                })
                .collect();
            rows.sort_by(|(a, a_at), (b, b_at)| {
                a_at.cmp(b_at)
                    .then_with(|| a.proposal.digest().cmp(&b.proposal.digest()))
            });
            rows.truncate(limit as usize);
            rows
        };
        crate::federation::accord_carriage::assemble_evidence_page(self, page).await
    }

    /// v31.1.0 (CIRISPersist#662) — delegates to the shared re-tally body.
    async fn apply_replicated_accord_evidence(
        &self,
        evidence: &crate::federation::accord_carriage::AccordQuorumEvidence,
    ) -> Result<crate::federation::accord_carriage::AccordEvidenceAdmission, crate::federation::Error>
    {
        crate::federation::accord_carriage::admit_replicated_accord_evidence(self, evidence).await
    }

    async fn list_signed_transport_destinations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedTransportDestination>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let resume_id = |t: &crate::federation::TransportDestination| {
            crate::federation::types::compound_resume_id(&[&t.occurrence_key_id, &t.transport_kind])
        };
        let position = |t: &crate::federation::TransportDestination| {
            plane_position(
                &state,
                PLANE_TRANSPORT_DESTINATION,
                &resume_id(t),
                t.asserted_at,
            )
        };
        let since_parts = since.as_ref().map(|(s_at, s_id)| {
            let [a, b] = crate::federation::types::split_resume_id::<2>(s_id);
            (*s_at, a.to_owned(), b.to_owned())
        });
        // Signed-put rows only; RETIRED rows ARE included — tombstones must
        // gossip, matching `list_signed_transport_destinations_for` — and
        // v36.0.0 (#668) the retire doors MOVE the serve position.
        let mut rows: Vec<crate::federation::ServedTransportDestination> = state
            .transport_destinations
            .iter()
            .filter(|(_, td)| {
                since_parts.as_ref().is_none_or(|(s_at, s_a, s_b)| {
                    (
                        position(td),
                        td.occurrence_key_id.as_str(),
                        td.transport_kind.as_str(),
                    ) > (*s_at, s_a.as_str(), s_b.as_str())
                })
            })
            .filter_map(|(key, td)| {
                state.transport_destination_sigs.get(key).map(
                    |(attesting_key_id, signed_envelope, signature)| {
                        crate::federation::ServedTransportDestination {
                            admitted_at: position(td),
                            destination: crate::federation::SignedTransportDestination {
                                transport_destination: td.clone(),
                                attesting_key_id: attesting_key_id.clone(),
                                signed_envelope: signed_envelope.clone(),
                                signature: signature.clone(),
                            },
                        }
                    },
                )
            })
            .collect();
        rows.sort_by(|a, b| {
            let ad = &a.destination.transport_destination;
            let bd = &b.destination.transport_destination;
            a.admitted_at
                .cmp(&b.admitted_at)
                .then_with(|| ad.occurrence_key_id.cmp(&bd.occurrence_key_id))
                .then_with(|| ad.transport_kind.cmp(&bd.transport_kind))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn attestation_type_census(
        &self,
    ) -> Result<Vec<crate::federation::row_type::AttestationTypeCount>, crate::federation::Error>
    {
        let state = self.state.lock().expect("memory backend lock");
        let mut by: std::collections::BTreeMap<
            String,
            crate::federation::row_type::AttestationTypeCount,
        > = std::collections::BTreeMap::new();
        for a in &state.federation_attestations {
            let e = by.entry(a.attestation_type.clone()).or_insert_with(|| {
                crate::federation::row_type::AttestationTypeCount {
                    attestation_type: a.attestation_type.clone(),
                    count: 0,
                    oldest: a.asserted_at,
                    newest: a.asserted_at,
                }
            });
            e.count += 1;
            e.oldest = e.oldest.min(a.asserted_at);
            e.newest = e.newest.max(a.asserted_at);
        }
        Ok(by.into_values().collect())
    }

    async fn list_attestations_since(
        &self,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<crate::federation::ServedAttestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        // E5 invariant: federation-tier rows only — a local-tier row must
        // never reach the advertise/serve wire surface.
        //
        // v36.0.0 (#668) — the position falls back to the legacy visibility
        // timestamp `COALESCE(promoted_at, asserted_at)` for an unstamped
        // row, and every writer (including the promote sweep) stamps the
        // serve position going forward.
        let position = |a: &crate::federation::Attestation| {
            plane_position(
                &state,
                PLANE_ATTESTATION,
                &a.attestation_id,
                a.promoted_at.unwrap_or(a.asserted_at),
            )
        };
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.tier == crate::federation::types::attestation_tier::FEDERATION
                    // v53.0.0 (#975, CC 2.4) — under enforcement a held row of
                    // an unregistered type is neither served nor replicated.
                    && crate::federation::row_type::served_under_enforcement(a)
                    // v54.1.0 (CIRISPersist#1046) — a tombstoned row is never
                    // served; filtered BEFORE the page is cut.
                    && (!state.purge_tombstones.keys().any(|(_, p, r)| {
                        p == "attestation" && *r == a.attestation_id
                    })
                        // Codex on PR #1057 — a tombstone is void for the
                        // accountability record: it is served.
                        || crate::federation::admission::envelope_dimension(
                            &a.attestation_envelope,
                        )
                        .and_then(crate::federation::migration::accountability_record_family)
                        .is_some()
                        // Codex round 4 — and (interim) a row a person is the
                        // subject of.
                        || mem_person_subject(&state, a))
                    && since.as_ref().is_none_or(|(s_at, s_id)| {
                        (position(a), a.attestation_id.as_str()) > (*s_at, s_id.as_str())
                    })
            })
            .map(|a| crate::federation::ServedAttestation {
                admitted_at: position(a),
                attestation: a.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            a.admitted_at.cmp(&b.admitted_at).then_with(|| {
                a.attestation
                    .attestation_id
                    .cmp(&b.attestation.attestation_id)
            })
        });
        rows.truncate(limit as usize);
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::ListAttestationsSince,
            "*",
            &rows,
            0,
        );
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
            memory_upsert_wire_index(&mut state.signed_wire_index, kind, hash, &record_key);
        }
        Ok(count)
    }

    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 3) — the decision is the shared plan's.
        crate::federation::key_plane::key_record_write_planned(
            self,
            crate::federation::key_plane::KeyRecordWrite::AttachPqc {
                key_id,
                pubkey_ml_dsa_65_base64,
                scrub_signature_pqc,
            },
        )
        .await?;
        Ok(())
    }

    /// v56.0.0 (CIRISPersist#934 step 1) — the decision is
    /// [`plan_attach_attestation_pqc_signature`](crate::federation::attestation_admit::plan_attach_attestation_pqc_signature),
    /// shared by all three backends; this backend stores it.
    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::attestation_admit::attach_attestation_pqc_planned(
            self,
            attestation_id,
            scrub_signature_pqc,
        )
        .await
    }

    async fn get_attestation(
        &self,
        attestation_id: &str,
    ) -> Result<Option<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let row = state
            .federation_attestations
            .iter()
            .find(|a| a.attestation_id == attestation_id)
            .cloned();
        crate::observe::record_read(
            crate::observe::StoreBackend::Memory,
            crate::observe::Door::GetAttestation,
            attestation_id,
            row.as_slice(),
            0,
        );
        Ok(row)
    }

    /// v39.0.0 — the tier crossing. Everything that decides lives in
    /// `crossing::plan_enter_mesh` (read that module's doc). It runs
    /// BEFORE `self.state.lock()` — every gate in it reads the directory through
    /// that same lock — and writes nothing, so a refused crossing never touches
    /// the row (verify-before-mutation, AV-9). The critical section then swaps
    /// the planned row in, re-stamps the plane position (v36.0.0 #668) and
    /// re-indexes it under its stored bytes.
    async fn enter_mesh(
        &self,
        attestation_id: &str,
        ci: &crate::federation::ContextualIntegrity,
        custody: &crate::federation::TierPromotionCustody,
    ) -> Result<crate::federation::MeshCrossingOutcome, crate::federation::Error> {
        use crate::federation::types::attestation_tier;
        use crate::federation::{crossing, Error, MeshCrossingOutcome};
        let current = self.get_attestation(attestation_id).await?.ok_or_else(|| {
            Error::InvalidArgument(format!(
                "federation_attestations row {attestation_id} does not exist"
            ))
        })?;
        // v54.0.0 (Codex on PR #1050) — a crossing `delegates_to` adds an edge to
        // the federation-tier graph the cycle gate reads: the plan's cycle check
        // and the write below are one step under the delegation write lock.
        let _cycle_guard = if crate::federation::admission::delegation_cycle_gated(&current) {
            Some(self.delegation_write_lock.lock().await)
        } else {
            None
        };
        let Some(crossing::EnterPlan { row, crossing }) =
            crossing::plan_enter_mesh(self, &current, ci, custody, self.self_key_id().as_deref())
                .await?
        else {
            return Ok(MeshCrossingOutcome::AlreadyInMesh {
                attestation_id: attestation_id.to_owned(),
            });
        };
        #[cfg(test)]
        if _cycle_guard.is_some() {
            self.test_hooks()
                .pause_if_armed("delegation_cycle_before_crossing")
                .await;
        }
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            let admitted_at = next_plane_position(
                &state,
                PLANE_ATTESTATION,
                attestation_rows(&state).into_iter(),
            );
            let slot = state
                .federation_attestations
                .iter_mut()
                .find(|a| a.attestation_id == attestation_id)
                .ok_or_else(|| {
                    Error::InvalidArgument(format!(
                        "federation_attestations row {attestation_id} does not exist"
                    ))
                })?;
            if slot.tier == attestation_tier::FEDERATION {
                return Err(Error::Conflict(format!(
                    "federation_attestations row {attestation_id} was concurrently promoted"
                )));
            }
            *slot = row;
            let wik = crate::federation::wire_index::record_key(&[(
                "attestation_id",
                &slot.attestation_id,
            )]);
            stamp_plane_position(
                &mut state,
                PLANE_ATTESTATION,
                attestation_id.to_owned(),
                admitted_at,
            );
            wik
        };
        self.index_stored_record("Attestation", &wire_index_key)
            .await?;
        Ok(MeshCrossingOutcome::Crossed(crossing))
    }

    async fn list_hybrid_pending_keys(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — the PQC sweep's selection is shared.
        let rows = crate::federation::sweep_plan::list_hybrid_pending_planned(
            self,
            crate::federation::sweep_plan::HybridPlane::Keys,
            limit,
        )
        .await?;
        Ok(rows)
    }

    async fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — the PQC sweep's selection is shared.
        let rows = crate::federation::sweep_plan::list_hybrid_pending_planned(
            self,
            crate::federation::sweep_plan::HybridPlane::Attestations,
            limit,
        )
        .await?;
        Ok(rows)
    }

    // ── Trust grants (v1.3.0, CIRISPersist#46 + #47) ───────────────

    async fn grant_trust(
        &self,
        signed: crate::federation::SignedTrustGrant,
    ) -> Result<(), crate::federation::Error> {
        // v60.0.0 (CIRISPersist#934 step 4) — the decision is the shared plan's
        // (the #721 authority gate first, then the shape).
        crate::federation::consent_admit::grant_trust_planned(self, signed).await?;
        Ok(())
    }

    async fn revoke_trust(
        &self,
        revocation: crate::federation::SignedTrustRevocation,
    ) -> Result<(), crate::federation::Error> {
        if revocation.key.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "key must be non-empty".into(),
            ));
        }
        // v38.0.0 (#721) — signature proof first; then ownership against the
        // STORED granter (only the granter withdraws its own grant).
        crate::federation::admission::check_trust_revocation_authority(self, &revocation).await?;
        let mut state = self.state.lock().expect("memory backend lock");
        if let Some(row) = state.federation_trust.get_mut(&revocation.key) {
            if row.trusted_by != revocation.revoked_by {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "trust on {} was granted by {:?}; {:?} may not revoke it — only the \
                     granter withdraws its own grant (CIRISPersist#721)",
                    revocation.key, row.trusted_by, revocation.revoked_by
                )));
            }
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

    // ── Goals: the projection's reads (v60.0.0, CIRISPersist#988 item 4) ──

    async fn get_goal(
        &self,
        goal_id: &str,
    ) -> Result<Option<crate::federation::Goal>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.federation_goals.get(goal_id).map(|p| p.to_goal()))
    }

    async fn list_goals(
        &self,
        filter: crate::federation::GoalsFilter,
    ) -> Result<Vec<crate::federation::Goal>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<crate::federation::Goal> = state
            .federation_goals
            .values()
            .map(|p| p.to_goal())
            .filter(|g| {
                (filter.include_retired || g.retired_at.is_none())
                    && filter
                        .declared_by_key_id
                        .as_ref()
                        .is_none_or(|k| &g.declared_by_key_id == k)
                    && filter
                        .m1_dimension
                        .is_none_or(|d| g.meta_goal_alignment.dimension == d)
                    && filter.scale.as_deref().is_none_or(|s| g.scope.scale() == s)
                    && filter
                        .cohort_id
                        .as_deref()
                        .is_none_or(|c| g.scope.cohort_id() == Some(c))
            })
            .collect();
        rows.sort_by(|a, b| {
            a.declared_at
                .cmp(&b.declared_at)
                .then_with(|| a.goal_id.cmp(&b.goal_id))
        });
        Ok(rows)
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

        // v31.0.0 (CIRISPersist#656) — THE FIFTH `federation_keys` ADMISSION
        // PATH. This door writes a caller-supplied `identity_type` and ran no
        // role gate at all, so `add_peer_record(k, pk, "canonical", None)` made
        // `is_canonical_effective` answer true for an attacker-named key.
        // BEFORE any lock or DB work: the gates read the directory, which locks
        // itself. One gate, three backends.
        crate::federation::admission::check_peer_record_admission(self, key_id, identity_type)
            .await?;

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
            // v31.4.0 (CIRISPersist#682) — THIS node's admission position. An
            // operator-added peer is a `federation_keys` row like any other and
            // is served by the same cursor, so it is stamped by the same
            // allocator as `put_public_key`.
            let admitted_at = next_key_admission_position(&state);
            state
                .key_record_admitted_at
                .insert(key_id.to_owned(), admitted_at);
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
        reason: &str,
        acting_under_delegation_id: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        // v38.0.0 (#721) — an unrecorded removal is the defect: persist does
        // not adjudicate an admin's reasons, it refuses to let them go
        // unrecorded (the check_admin_action_attribution discipline, applied
        // to the one table verb that removed served rows unannounced).
        if reason.trim().is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "remove_peer_record: a removal is an attributed act — `reason` is required \
                 (CIRISPersist#721)"
                    .into(),
            ));
        }
        // v57.0.0 (CIRISPersist#988 item 2) — the record's attester, read
        // before the lock; asked for only once the removal's own refusals
        // have had their say.
        let attester = crate::federation::attestation_admit::hard_case_attester(self).await;
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
                    (a.attesting_key_id == key_id
                        || a.attested_key_id == key_id
                        || a.scrub_key_id == key_id)
                        // v58.0.0 (CIRISPersist#991) — the key's own claim is
                        // the key, not an attestation that depends on it.
                        && !is_key_record_row_of(a, key_id)
                })
                .count();
            if attestation_count > 0 {
                return Err(crate::federation::Error::HardRemoveWithActiveAttestations {
                    key_id: key_id.to_owned(),
                    attestation_count,
                });
            }
        }
        // v57.0.0 (CIRISPersist#988 item 2) — an act: no attester, no removal.
        // The record is planned before anything moves.
        let removal =
            plan_peer_removal_event(&attester?, key_id, hard, reason, acting_under_delegation_id)?;
        if hard {
            // Cascade: drop federation_keys row + metadata row.
            state.federation_keys.remove(key_id);
            state.federation_peer_metadata.remove(key_id);
            memory_sync_key_record_row(&mut state, key_id);
            memory_store_hard_case(&mut state, removal);
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
            // v38.0.0 (#721, the #707-class third face): the soft removal
            // CHANGES THE SERVED SET (the cohort-scoped listing filters on
            // removed_at) while the sibling key row's serve position stood
            // still — a synced peer never re-reads the key and keeps serving
            // to a removed peer's audience. Stamp mutated_at so the cursor
            // planes re-serve the sibling row.
            state.key_record_mutated_at.insert(key_id.to_owned(), now);
            memory_store_hard_case(&mut state, removal);
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

/// v38.0.0 (CIRISPersist#721) — the peer-removal announcement, memory arm:
/// the same in-transaction `hard_case:admin_action:peer_removal:v1` row the
/// SQL doors write (v57.0.0, CIRISPersist#988 item 2). Planned BEFORE the
/// removal mutates anything, so a refusal leaves the peer in place; stored
/// after it, under the same lock. Emission is unconditional on the removal
/// succeeding — an announced act, never a courtesy.
fn plan_peer_removal_event(
    attester: &crate::federation::attestation_admit::HardCaseAttester,
    key_id: &str,
    hard: bool,
    reason: &str,
    delegation_id: Option<&str>,
) -> Result<crate::federation::attestation_admit::PlannedHardCase, crate::federation::Error> {
    let now = chrono::Utc::now();
    let event = crate::federation::hard_case::HardCaseEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        kind: crate::federation::hard_case::admin_action_kind(
            crate::federation::hard_case::admin_op::PEER_REMOVAL,
        ),
        target_key_id: Some(key_id.to_owned()),
        subject_key_id: None,
        detail: serde_json::json!({
            crate::federation::hard_case::admin_field::DELEGATION_ID: delegation_id,
            crate::federation::hard_case::admin_field::REASON: reason,
            "hard": hard,
        }),
        emitted_at: now,
        emitter_key_id: String::new(),
    };
    crate::federation::attestation_admit::plan_hard_case_row(
        &event,
        attester,
        crate::federation::attestation_admit::PlanInstants {
            fold_at: now,
            received_at: now,
        },
    )
}

/// v56.0.0 (CIRISPersist#934 door 2), lifted in v57.0.0 so the hard_case
/// writer stores its row through the same step — push one local-tier row:
/// the rendition and subject mirrors, its `withdraws` depth, its serve
/// position. `false` (nothing written) when the id is already held (the
/// `INSERT OR IGNORE` twin).
fn memory_insert_local_row(
    state: &mut State,
    row: crate::federation::Attestation,
    withdraws_depth: Option<usize>,
) -> bool {
    // v18.0.0 (#473) — the INSERT OR IGNORE twin: an id still held here (a
    // concurrent writer took it after the plan read it free) is a no-op.
    if state
        .federation_attestations
        .iter()
        .any(|a| a.attestation_id == row.attestation_id)
    {
        return false;
    }
    // v45.0.0 (CIRISPersist#871, FSD §5) — the V149 `blob_renditions`
    // mirror at the local door, under the same lock as the push below.
    project_rendition_row(state, &row);
    // v17.4.0 (V106) — maintain the subject-index mirror at local tier.
    for subj in &row.subject_key_ids {
        state
            .subject_index
            .entry(subj.clone())
            .or_default()
            .push(row.attestation_id.clone());
    }
    // v36.0.0 (#668) — serve position (V130 mirror).
    let admitted_at = next_plane_position(
        state,
        PLANE_ATTESTATION,
        attestation_rows(state).into_iter(),
    );
    let id_for_stamp = row.attestation_id.clone();
    // v50.0.0 (review H2, final check, 3d) — a local `withdraws`'s depth.
    if let Some(depth) = withdraws_depth {
        state
            .federation_withdraws_admission_depths
            .insert(row.attestation_id.clone(), depth);
    }
    state.federation_attestations.push(row);
    stamp_plane_position(state, PLANE_ATTESTATION, id_for_stamp, admitted_at);
    true
}

/// v58.0.0 (CIRISPersist#991, V198 mirror) — is `row` a `key:record:v1`
/// claim of `key_id` (its own: attester = attested = the key)?
fn is_key_record_row_of(row: &crate::federation::Attestation, key_id: &str) -> bool {
    row.attesting_key_id == key_id
        && row.attested_key_id == key_id
        && crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            == Some(crate::federation::key_plane::KEY_RECORD_DIMENSION)
}

/// v58.0.0 (CIRISPersist#991, CC 3.1.3; the SQL backends'
/// `*_sync_key_record_row`) — **the key's `key:record:v1` row follows its
/// record**, under the caller's lock: the held record, the key's current row
/// and the base signer's held keys go to the shared step (v60.0.0:
/// `key_plane::key_record_row_step`), and its verdict is applied: keep, or
/// remove the key's rows and insert the planned one.
fn memory_sync_key_record_row(state: &mut State, key_id: &str) {
    use crate::federation::key_plane::KeyRecordRowStep;
    let record = state.federation_keys.get(key_id);
    // The base signer's held keys (for a self-scrubbed record the key
    // itself, which proof of possession never consults).
    let held_signer = record
        .and_then(|r| state.federation_keys.get(&r.scrub_key_id))
        .map(|k| {
            (
                k.pubkey_ed25519_base64.clone(),
                k.pubkey_ml_dsa_65_base64.clone(),
            )
        });
    let current = state
        .federation_attestations
        .iter()
        .find(|a| is_key_record_row_of(a, key_id))
        .map(|a| a.attestation_id.clone());
    let step =
        crate::federation::key_plane::key_record_row_step(record, current.as_deref(), &held_signer);
    let KeyRecordRowStep::Replace(planned) = step else {
        return;
    };
    state
        .federation_attestations
        .retain(|a| !is_key_record_row_of(a, key_id));
    if let Some(row) = planned {
        memory_insert_local_row(state, *row, None);
    }
}

/// v58.0.0 (CIRISPersist#991, V198 mirror) — the signed occurrence of a pair
/// as held (the occurrence and its signature container), `None` for an
/// unsigned (trusted-local) one.
fn memory_signed_occurrence(
    state: &State,
    key: &(String, String),
) -> Option<crate::federation::SignedIdentityOccurrence> {
    let occurrence = state.federation_identity_occurrences.get(key)?;
    let (attesting_key_id, signed_envelope, signature) =
        state.federation_identity_occurrence_sigs.get(key)?;
    Some(crate::federation::SignedIdentityOccurrence {
        identity_occurrence: occurrence.clone(),
        attesting_key_id: attesting_key_id.clone(),
        signed_envelope: signed_envelope.clone(),
        signature: signature.clone(),
    })
}

/// v58.0.0 (CIRISPersist#991) — is `row` the `identity:occurrence:v1` row of
/// the pair `key`?
fn is_occurrence_row_of(row: &crate::federation::Attestation, key: &(String, String)) -> bool {
    crate::federation::key_plane::occurrence_of_row(row).is_some_and(|s| {
        s.identity_occurrence.identity_key_id == key.0
            && s.identity_occurrence.occurrence_key_id == key.1
    })
}

/// v58.0.0 (CIRISPersist#991, CC 3.3.6; the SQL backends'
/// `*_sync_occurrence_row`) — the pair's `identity:occurrence:v1` row follows
/// its current SIGNED occurrence, under the caller's lock.
fn memory_sync_occurrence_row(state: &mut State, key: &(String, String)) {
    let planned = memory_signed_occurrence(state, key)
        .filter(|s| state.federation_keys.contains_key(&s.attesting_key_id))
        .and_then(|s| crate::federation::key_plane::occurrence_row_if_hybrid(&s));
    if let Some(p) = &planned {
        if state
            .federation_attestations
            .iter()
            .any(|a| a.attestation_id == p.attestation_id)
        {
            return;
        }
    }
    state
        .federation_attestations
        .retain(|a| !is_occurrence_row_of(a, key));
    if let Some(row) = planned {
        memory_insert_local_row(state, row, None);
    }
}

/// v57.0.0 (CIRISPersist#988 item 2) — **the hard_case writer**, memory arm:
/// the planned row (insert-if-absent) and, when it landed, its projection.
fn memory_store_hard_case(
    state: &mut State,
    planned: crate::federation::attestation_admit::PlannedHardCase,
) {
    let crate::federation::attestation_admit::PlannedHardCase { row, projection } = planned;
    let attestation_id = row.attestation_id.clone();
    if memory_insert_local_row(state, row, None) {
        state
            .federation_hard_case_events
            .insert(projection.event_id.clone(), (attestation_id, projection));
    }
}

/// v57.0.0 (CIRISPersist#988 item 2) — an in-lock emitter's record (the SQL
/// backends' `*_record_hard_case_in_tx`): plan with the attester resolved
/// before the lock, store under it. Without an attester an act refuses and an
/// observation records nothing
/// ([`crate::federation::attestation_admit::HardCaseEmitter`]).
fn memory_record_hard_case_in_state(
    state: &mut State,
    attester: &Result<crate::federation::attestation_admit::HardCaseAttester, String>,
    emitter: crate::federation::attestation_admit::HardCaseEmitter,
    event: &crate::federation::hard_case::HardCaseEvent,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let attester = match attester {
        Ok(a) => a,
        Err(e) => return emitter.without_attester(&event.event_id, e),
    };
    let planned = crate::federation::attestation_admit::plan_hard_case_row(
        event,
        attester,
        crate::federation::attestation_admit::PlanInstants {
            fold_at: received_at,
            received_at,
        },
    )
    .map_err(|e| format!("{}: {e}", e.kind()))?;
    memory_store_hard_case(state, planned);
    Ok(())
}

/// v57.0.0 (CIRISPersist#988 item 3; lead ruling 5) — the purge door's
/// tombstone of a detection row, on its projection: the entry for
/// `attestation_id`, if live, becomes the V080 tombstone at `executed_at`
/// (the SQL backends' UPDATE in `purge_put_execution`).
fn memory_tombstone_detection_projection(
    state: &mut State,
    attestation_id: &str,
    executed_at: chrono::DateTime<chrono::Utc>,
) {
    for (id, p) in state.derived_detection_events.values_mut() {
        if id == attestation_id && p.erased_at.is_none() {
            *p = p.tombstoned(executed_at);
        }
    }
}

/// The instant the earliest-admitted purge execution naming
/// `attestation_id` executed, if one does: what the detection projection's
/// tombstone stamps (the rebuild's half of
/// [`memory_tombstone_detection_projection`]).
fn memory_detection_tombstone_instant(
    state: &State,
    attestation_id: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    state
        .purge_tombstones
        .iter()
        .filter(|((_, plane, r), _)| plane == "attestation" && r == attestation_id)
        .filter_map(|((notice, _, _), _)| state.purge_executions.get(notice))
        .min_by(|a, b| (a.admitted_at, &a.notice_id).cmp(&(b.admitted_at, &b.notice_id)))
        .map(|e| e.executed_at)
}

/// v57.0.0 (CIRISPersist#988 item 3; lead ruling on the DSAR path) — the
/// row-backed detections of `trace_ids`, found by the ROW's own body
/// (`detection.trace_id`, as the SQL doors read it). Nothing moves.
fn memory_find_detection_rows(state: &State, trace_ids: &HashSet<String>) -> Vec<String> {
    let mut found: Vec<String> = state
        .federation_attestations
        .iter()
        .filter(|row| {
            let env = &row.attestation_envelope;
            env.get("dimension")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|d| d.starts_with("detection:"))
                && env
                    .pointer("/detection/trace_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|t| trace_ids.contains(t))
        })
        .map(|row| row.attestation_id.clone())
        .collect();
    found.sort();
    found
}

/// What a memory erasure writes, decided before anything moves.
#[derive(Default)]
struct MemoryErasurePlan {
    row: Option<crate::federation::attestation_admit::PlannedHardCase>,
    tombstones: Vec<(
        crate::federation::steward_purge::PurgeExecution,
        crate::federation::steward_purge::PurgeTombstone,
    )>,
}

/// v58.0.0 (CIRISPersist#1094 item 2) — plan an erasure's subject-free
/// `hard_case:trace_erasure:v1` row and, per erased row, the tombstone header
/// citing the producer's `withdraws`. Nothing moves.
fn memory_plan_erasure(
    attester: &crate::federation::attestation_admit::HardCaseAttester,
    event: &crate::federation::hard_case::HardCaseEvent,
    erased: &[crate::federation::subject_erasure::ErasureCitation],
    at: chrono::DateTime<chrono::Utc>,
) -> Result<MemoryErasurePlan, String> {
    let planned = crate::federation::attestation_admit::plan_hard_case_row(
        event,
        attester,
        crate::federation::attestation_admit::PlanInstants {
            fold_at: at,
            received_at: at,
        },
    )
    .map_err(|e| format!("{}: {e}", e.kind()))?;
    let tombstones = erased
        .iter()
        .map(|c| {
            crate::federation::subject_erasure::erasure_execution(
                c,
                &attester.key_id,
                crate::federation::steward_purge::origin::LOCAL,
                at,
                Some(at),
            )
            .map_err(|e| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    Ok(MemoryErasurePlan {
        row: Some(planned),
        tombstones,
    })
}

/// v58.0.0 — the cited rows still held (the SQL doors' `DELETE … WHERE id`
/// counts the same set).
fn memory_held_citations(
    state: &State,
    citations: &[crate::federation::subject_erasure::ErasureCitation],
) -> Vec<crate::federation::subject_erasure::ErasureCitation> {
    citations
        .iter()
        .filter(|c| {
            state
                .federation_attestations
                .iter()
                .any(|a| a.attestation_id == c.target)
        })
        .cloned()
        .collect()
}

/// Apply a planned erasure under the lock: hard-delete the erased detection
/// rows (their projection entries follow), store the erasure row, write the
/// tombstones.
fn memory_apply_erasure(
    state: &mut State,
    new_withdraws: &[crate::federation::subject_erasure::PlannedErasureWithdraws],
    erased: &[crate::federation::subject_erasure::ErasureCitation],
    plan: MemoryErasurePlan,
) {
    // v58.0.0 (#1094 item 2) — the producers' withdraws first, through the
    // local-row writer every local door uses.
    for w in new_withdraws {
        memory_insert_local_row(state, w.row.clone(), Some(w.depth));
    }
    for c in erased {
        let record_key =
            crate::federation::wire_index::record_key(&[("attestation_id", &c.target)]);
        state
            .signed_wire_index
            .retain(|(kind, _), rk| !(kind == "Attestation" && *rk == record_key));
        state
            .federation_attestations
            .retain(|a| a.attestation_id != c.target);
    }
    prune_row_projections(state);
    if let Some(planned) = plan.row {
        memory_store_hard_case(state, planned);
    }
    for (mut execution, t) in plan.tombstones {
        let last = state.purge_executions.values().map(|e| e.admitted_at).max();
        execution.admitted_at =
            crate::federation::types::monotonic_admission_instant(chrono::Utc::now(), last);
        state
            .purge_executions
            .entry(execution.notice_id.clone())
            .or_insert(execution);
        state.purge_tombstones.insert(
            (
                t.notice_id.clone(),
                t.plane.as_str().to_owned(),
                t.record_ref.clone(),
            ),
            t,
        );
    }
}

/// v57.0.0 (CIRISPersist#988, V194/V195 mirror) — the SQL backends' `ON
/// DELETE CASCADE` from a projection row to its row: drop every projection
/// entry whose row is no longer held. Called by every memory door that
/// removes attestation rows.
fn prune_row_projections(state: &mut State) {
    let held: HashSet<String> = state
        .federation_attestations
        .iter()
        .map(|a| a.attestation_id.clone())
        .collect();
    state
        .federation_hard_case_events
        .retain(|_, (attestation_id, _)| held.contains(attestation_id));
    state
        .derived_detection_events
        .retain(|_, (attestation_id, _)| held.contains(attestation_id));
    state
        .cirisnode_ledgers
        .retain(|_, p| held.contains(&p.attestation_id));
}

/// v60.0.0 (CIRISPersist#988 item 1) — the ledger writer: replace the held
/// entry on the projection's key when the projection supersedes it
/// ([`supersedes`](crate::federation::ledger_projection::supersedes)).
fn memory_project_ledger(
    ledgers: &mut std::collections::BTreeMap<
        String,
        crate::federation::ledger_projection::LedgerProjection,
    >,
    ledger: crate::federation::ledger_projection::LedgerProjection,
) {
    let key = ledger.map_key();
    let held = ledgers
        .get(&key)
        .map(|h| (Some(h.attestation_id.as_str()), h.asserted_at));
    if crate::federation::ledger_projection::supersedes(held, &ledger) {
        ledgers.insert(key, ledger);
    }
}

/// v60.0.0 (CIRISPersist#988 item 4) — the goal writer's fold over the held
/// rows (the SQL executors' reads: a row by id; the federation-tier
/// structural rows naming an id).
fn memory_project_goal(
    rows: &[crate::federation::Attestation],
    goal_id: &str,
) -> Option<crate::federation::goal_projection::GoalProjection> {
    use crate::federation::types::attestation_tier::FEDERATION;
    let get = |id: &str| -> Result<_, std::convert::Infallible> {
        Ok(rows.iter().find(|r| r.attestation_id == id).cloned())
    };
    let naming = |id: &str| -> Result<Vec<_>, std::convert::Infallible> {
        Ok(rows
            .iter()
            .filter(|r| {
                r.tier == FEDERATION
                    && crate::federation::precedence::is_structural_composer(&r.attestation_type)
                    && crate::federation::precedence::references_attestation_id_from_envelope(
                        &r.attestation_envelope,
                    ) == Some(id)
            })
            .cloned()
            .collect())
    };
    match crate::federation::goal_projection::refold_goal(goal_id, get, naming) {
        Ok(p) => p,
        Err(never) => match never {},
    }
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

    async fn outbound_counts(
        &self,
    ) -> Result<
        std::collections::HashMap<crate::outbound::OutboundStatus, u64>,
        crate::outbound::Error,
    > {
        let state = self.state.lock().expect("memory backend lock");
        let mut out = std::collections::HashMap::new();
        for r in state.outbound_queue.values() {
            *out.entry(r.status).or_insert(0u64) += 1;
        }
        Ok(out)
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
    /// v57.0.0 (CIRISPersist#988 item 3) — the row door: memory stores the
    /// `detection:{detector}:v1` row and its projection like the SQL
    /// backends (it returned `NotImplemented` before the row existed).
    async fn put_detection_event(
        &self,
        event: crate::derived::DetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        crate::federation::steward_purge::refuse_if_tombstoned_trace(self, &event.trace_id)
            .await
            .map_err(|e| match e {
                crate::federation::Error::PurgeRefused { .. } => {
                    crate::derived::Error::InvalidArgument(format!("{}: {e}", e.kind()))
                }
                other => crate::derived::Error::Backend(other.to_string()),
            })?;
        crate::federation::attestation_admit::put_detection_planned(self, &event)
            .await
            .map_err(crate::derived::detection_row::derived_error)
    }

    /// The projection read, as the SQL backends: live (untombstoned)
    /// detections only, newest first, at most 1000.
    async fn get_detection_events(
        &self,
        filter: crate::derived::EventFilter,
    ) -> Result<Vec<crate::derived::DetectionEvent>, crate::derived::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<crate::derived::DetectionEvent> = state
            .derived_detection_events
            .values()
            .filter_map(|(_, p)| p.to_event())
            .filter(|e| filter.trace_id.as_ref().is_none_or(|t| &e.trace_id == t))
            .filter(|e| filter.detector.as_ref().is_none_or(|d| &e.detector == d))
            .filter(|e| filter.since.is_none_or(|s| e.ts >= s))
            .collect();
        rows.sort_by_key(|e| std::cmp::Reverse(e.ts));
        rows.truncate(1000);
        Ok(rows)
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

/// v50.0.0 (CIRISPersist#925 review M5) — the key-record store step, with the
/// door it was reached through: `put_public_key` is the local mint
/// ([`KeyDoor::LocalMint`](crate::federation::register::KeyDoor::LocalMint));
/// the replicated `Insert` arm stores a key minted elsewhere
/// ([`KeyDoor::ReplicatedInsert`](crate::federation::register::KeyDoor::ReplicatedInsert)).
/// Every gate is the same on both except CC 3.4.7.3 Clause A, which gates
/// minting only.
impl MemoryBackend {}

/// v60.0.0 (CIRISPersist#934 step 4) — the sweeps' executor on memory.
/// Storage only: the selections are `federation::sweep_plan`'s, evaluated
/// over the rows held here.
#[async_trait::async_trait]
impl crate::federation::sweep_plan::SweepStore for MemoryBackend {
    async fn read_hybrid_pending(
        &self,
        selection: crate::federation::sweep_plan::HybridPendingSelection,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        use crate::federation::sweep_plan::HybridPlane;
        let state = self.state.lock().expect("memory backend lock");
        let rows: Vec<_> = match selection.plane {
            HybridPlane::Keys => state
                .federation_keys
                .values()
                .map(|r| {
                    (
                        r.key_id.clone(),
                        r.valid_from,
                        r.pqc_completed_at.is_none(),
                        (
                            r.registration_envelope.clone(),
                            r.scrub_signature_classical.clone(),
                        ),
                    )
                })
                .collect(),
            HybridPlane::Attestations => state
                .federation_attestations
                .iter()
                .map(|r| {
                    (
                        r.attestation_id.clone(),
                        r.asserted_at,
                        r.pqc_completed_at.is_none(),
                        (
                            r.attestation_envelope.clone(),
                            r.scrub_signature_classical.clone(),
                        ),
                    )
                })
                .collect(),
        };
        Ok(selection
            .cut(rows)
            .into_iter()
            .map(
                |(id, (envelope, classical_sig_b64))| crate::federation::HybridPendingRow {
                    id,
                    envelope,
                    classical_sig_b64,
                },
            )
            .collect())
    }

    async fn read_expired_attestation_ids(
        &self,
        selection: crate::federation::sweep_plan::ExpiredSelection,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(selection.cut(
            state
                .federation_attestations
                .iter()
                .map(|a| {
                    (
                        a.attestation_id.clone(),
                        a.attestation_type.clone(),
                        a.expires_at,
                    )
                })
                .collect(),
        ))
    }

    async fn evict_known_wire_hashes_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<(u64, u64), crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        let before = state.known_wire_hashes.len() as u64;
        state.known_wire_hashes.retain(|_, (ts, _)| *ts >= cutoff);
        let remaining = state.known_wire_hashes.len() as u64;
        Ok((before.saturating_sub(remaining), remaining))
    }
}

/// v60.0.0 (CIRISPersist#934 step 4) — the consent plane's executor on
/// memory. Storage only: the decisions are `federation::consent_admit`'s.
#[async_trait::async_trait]
impl crate::federation::consent_admit::ConsentStore for MemoryBackend {
    async fn store_planned_consent_role(
        &self,
        planned: crate::federation::consent_admit::PlannedConsentRole,
    ) -> Result<bool, crate::federation::Error> {
        {
            let mut state = self.state.lock().expect("memory backend lock");
            if !state.federation_keys.contains_key(&planned.key_id) {
                return Ok(false);
            }
            // v36.0.0 (CIRISPersist#707) — `consent_role` IS in the served
            // bytes, so this rewrite moves the serve position, allocated
            // BEFORE the row mutation so it sorts above every served one.
            let mutated_at = next_key_admission_position(&state);
            state
                .key_record_mutated_at
                .insert(planned.key_id.clone(), mutated_at);
            if let Some(row) = state.federation_keys.get_mut(&planned.key_id) {
                row.consent_role = planned.role.clone();
            }
        }
        // v31.0.0 (CIRISPersist#640/#646) — the WIRE content hash moves (the
        // role is in the served bytes): re-index after the guard is released.
        self.index_stored_key_row(&planned.key_id).await?;
        Ok(true)
    }

    async fn store_planned_trust_grant(
        &self,
        row: crate::federation::TrustRow,
    ) -> Result<bool, crate::federation::Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // V020 puts the trust columns on the `federation_keys` row: a grant
        // rides an existing key, as on the SQL backends.
        if !state.federation_keys.contains_key(&row.key) {
            return Ok(false);
        }
        state.federation_trust.insert(row.key.clone(), row);
        Ok(true)
    }

    async fn read_consent_peer_rows(
        &self,
        read: crate::federation::consent_admit::ConsentRead<'_>,
    ) -> Result<Vec<crate::federation::consent_admit::ConsentPeerRow>, crate::federation::Error>
    {
        use crate::federation::consent_admit::{ConsentPeerRow, ConsentRead};
        let state = self.state.lock().expect("memory backend lock");
        Ok(match read {
            ConsentRead::Node(node) => state
                .consent_peer_set
                .iter()
                .filter(|r| r.node_key_id == node)
                .map(|r| ConsentPeerRow {
                    author_key_id: r.node_key_id.clone(),
                    peer_key_id: r.peer_key_id.clone(),
                })
                .collect(),
            ConsentRead::For(for_key) => state
                .consent_peer_set_for
                .iter()
                .filter(|r| r.for_key_id == for_key)
                .map(|r| ConsentPeerRow {
                    author_key_id: r.author_key_id.clone(),
                    peer_key_id: r.peer_key_id.clone(),
                })
                .collect(),
        })
    }

    async fn read_live_consent_grant_candidates(
        &self,
        read: crate::federation::consent_admit::ConsentRead<'_>,
    ) -> Result<crate::federation::attestation_query::QueryRows, crate::federation::Error> {
        use crate::federation::consent_admit::ConsentRead;
        let state = self.state.lock().expect("memory backend lock");
        let live: std::collections::HashSet<&str> = match read {
            ConsentRead::Node(_) => state
                .consent_peer_set
                .iter()
                .map(|r| r.source_attestation_id.as_str())
                .collect(),
            ConsentRead::For(for_key) => state
                .consent_peer_set_for
                .iter()
                .filter(|r| r.for_key_id == for_key)
                .map(|r| r.source_attestation_id.as_str())
                .collect(),
        };
        let rows = state
            .federation_attestations
            .iter()
            .filter(|a| match read {
                ConsentRead::Node(node) => a.attesting_key_id == node,
                ConsentRead::For(_) => true,
            })
            .filter(|a| live.contains(a.attestation_id.as_str()))
            .cloned()
            .collect();
        Ok(crate::federation::attestation_query::QueryRows {
            rows,
            bytes: 0,
            backend: crate::observe::StoreBackend::Memory,
        })
    }

    async fn read_consent_revocation_candidates(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        Ok(state
            .federation_attestations
            .iter()
            .filter(|a| {
                a.attestation_type == crate::federation::types::attestation_type::WITHDRAWS
                    || crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                        .is_some_and(|d| {
                            d.starts_with(
                                crate::federation::consent::consent_dimension::STATE_REVOKED_PREFIX,
                            )
                        })
            })
            .filter(|a| since.is_none_or(|s| a.asserted_at >= s))
            .cloned()
            .collect())
    }
}

/// v58.0.0 (CIRISPersist#991) — the key plane's executor on memory. Storage
/// only: the decisions are `federation::key_plane`'s plans.
#[async_trait::async_trait]
impl crate::federation::key_plane::KeyPlaneStore for MemoryBackend {
    async fn store_planned_revocation(
        &self,
        planned: crate::federation::key_plane::PlannedRevocation,
    ) -> Result<(), crate::federation::Error> {
        let crate::federation::key_plane::PlannedRevocation {
            revocation: row,
            row: plane,
        } = planned;
        let wire_index_key = {
            let mut state = self.state.lock().expect("memory backend lock");
            // The FK emulation: the revoker is a held key (V004's FK). No FK
            // on the subject (#784, V163): a digest-only revocation may
            // precede the key record.
            if !state.federation_keys.contains_key(&row.revoking_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "revoking_key_id {} does not exist in federation_keys",
                    row.revoking_key_id
                )));
            }
            let key = (
                plane.attestation_id.clone(),
                crate::federation::wire_index::record_key(&[
                    (
                        "revoked_key_sha256_ed25519_raw",
                        row.revoked_key_sha256_ed25519_raw.as_str(),
                    ),
                    ("revocation_id", row.revocation_id.as_str()),
                ]),
            );
            // THIS node's admission position, strictly after the last one
            // handed out (`monotonic_admission_instant`), under the same lock.
            let last_admitted = state.revocation_admitted_at.values().copied().max();
            let admitted_at = crate::federation::types::monotonic_admission_instant(
                chrono::Utc::now(),
                last_admitted,
            );
            state
                .revocation_admitted_at
                .insert(row.revocation_id.clone(), admitted_at);
            state.federation_revocations.push(row);
            // v58.0.0 (CIRISPersist#991) — and its `key:revocation:v1` row.
            memory_insert_local_row(&mut state, plane, None);
            key
        };
        // v58.0.0 (CIRISPersist#991) — the revocation's row is a wire-index
        // entry (the Attestation kind); v59.0.0 retired the framed entry.
        self.index_plane_row(Some(&wire_index_key.0)).await?;
        Ok(())
    }

    /// v60.0.0 (CIRISPersist#934 step 3) — the key-record executor, the
    /// memory mirror of the SQL backends' statements: under one lock, the
    /// write's atomic re-assertion (their `WHERE`), the write, the serve
    /// position, and the key's `key:record:v1` row; a write that matched
    /// nothing reports the plan's wording
    /// ([`PlannedKeyRecord::raced`](crate::federation::key_plane::PlannedKeyRecord::raced)).
    async fn read_key_plane_wire_hashes(
        &self,
        read: crate::federation::key_plane::KeyPlaneHoldingsRead,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let rows: std::collections::HashMap<&str, &crate::federation::Attestation> = state
            .federation_attestations
            .iter()
            .map(|a| (a.attestation_id.as_str(), a))
            .collect();
        let mut hashes: Vec<String> = state
            .signed_wire_index
            .iter()
            .filter(|((kind, hash), record_key)| {
                kind == crate::federation::key_plane::HOLDINGS_WIRE_KIND
                    && crate::federation::wire_index::record_key_field(record_key, "attestation_id")
                        .ok()
                        .and_then(|id| rows.get(id.as_str()).copied())
                        .is_some_and(|row| read.admits(row, hash))
            })
            .map(|((_, hash), _)| hash.clone())
            .collect();
        // The SQL backends page over the index's hash order.
        hashes.sort();
        hashes.truncate(read.limit as usize);
        Ok(hashes)
    }

    async fn store_planned_key_record(
        &self,
        planned: crate::federation::key_plane::PlannedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::key_plane::{PlannedKeyRecord as P, RewriteGuard};
        let key_id = planned.key_id().to_owned();
        {
            let mut state = self.state.lock().expect("memory backend lock");
            let position = next_key_admission_position(&state);
            let held = state.federation_keys.get(&key_id).cloned();
            let rows: u64 = match (&planned, held) {
                (P::Insert { record, .. }, None) => {
                    state
                        .key_record_admitted_at
                        .insert(key_id.clone(), position);
                    state.federation_keys.insert(key_id.clone(), record.clone());
                    1
                }
                (P::Insert { .. }, Some(h)) => {
                    planned.insert_held(Some(&h.persist_row_hash))?;
                    1
                }
                (P::Rewrite { record, guard }, Some(h))
                    if h.pubkey_ed25519_base64 == record.pubkey_ed25519_base64
                        && match guard {
                            RewriteGuard::SelfSigned => h.scrub_key_id == h.key_id,
                            RewriteGuard::Anchored { prior_hash } => {
                                h.scrub_key_id != h.key_id && h.persist_row_hash == *prior_hash
                            }
                            RewriteGuard::SamePubkey => true,
                        } =>
                {
                    // `consent_role` is never rewritten (CC 3.4.7.2): the
                    // SQL SET lists leave the column out.
                    let mut stored = record.clone();
                    stored.consent_role = h.consent_role;
                    state.key_record_mutated_at.insert(key_id.clone(), position);
                    state.federation_keys.insert(key_id.clone(), stored);
                    1
                }
                (
                    P::Replace {
                        record,
                        existing_hash,
                        kind,
                    },
                    Some(h),
                ) if h.persist_row_hash == *existing_hash
                    && h.pubkey_ed25519_base64 == record.pubkey_ed25519_base64
                    && (*kind != crate::federation::types::KeyReplacementKind::Rebind
                        || h.scrub_key_id == h.key_id) =>
                {
                    state
                        .key_registration_history
                        .entry(key_id.clone())
                        .or_default()
                        .push(crate::federation::types::KeyRegistrationHistoryRow {
                            key_id: key_id.clone(),
                            registration_envelope: h.registration_envelope,
                            original_content_hash: h.original_content_hash,
                            scrub_signature_classical: h.scrub_signature_classical,
                            scrub_signature_pqc: h.scrub_signature_pqc,
                            scrub_key_id: h.scrub_key_id,
                            scrub_timestamp: h.scrub_timestamp,
                            replaced_at: position,
                            replaced_by_hash: record.persist_row_hash.clone(),
                            replaced_row_hash: Some(h.persist_row_hash),
                            replacement: *kind,
                        });
                    state.key_record_mutated_at.insert(key_id.clone(), position);
                    state.federation_keys.insert(key_id.clone(), record.clone());
                    1
                }
                (
                    P::CompletePqc {
                        pubkey_ml_dsa_65_base64,
                        scrub_signature_pqc,
                        completed_at,
                        persist_row_hash,
                        ..
                    },
                    Some(h),
                ) if h.pqc_completed_at.is_none() => {
                    let mut stored = h;
                    stored.pubkey_ml_dsa_65_base64 = Some(pubkey_ml_dsa_65_base64.clone());
                    stored.scrub_signature_pqc = Some(scrub_signature_pqc.clone());
                    stored.pqc_completed_at = Some(*completed_at);
                    stored.persist_row_hash = persist_row_hash.clone();
                    state.key_record_mutated_at.insert(key_id.clone(), position);
                    state.federation_keys.insert(key_id.clone(), stored);
                    1
                }
                (P::RehydrateScrubs { record }, Some(h))
                    if h.persist_row_hash == record.persist_row_hash
                        && h.additional_scrubs.is_empty() =>
                {
                    let mut stored = h;
                    stored.additional_scrubs = record.additional_scrubs.clone();
                    state.key_record_mutated_at.insert(key_id.clone(), position);
                    state.federation_keys.insert(key_id.clone(), stored);
                    1
                }
                _ => 0,
            };
            if let Some(e) = planned.raced(rows) {
                return Err(e);
            }
            // v58.0.0 (CIRISPersist#991) — and its `key:record:v1` row.
            memory_sync_key_record_row(&mut state, &key_id);
        }
        self.index_stored_key_row(&key_id).await
    }
}

/// v57.0.0 (CIRISPersist#934 step 2) — the community plane's executor on
/// memory. Storage only: the decisions are
/// [`plan_put_community`](crate::federation::community_admit::plan_put_community)
/// and the three roster plans in `federation::community_admit`.
#[async_trait::async_trait]
impl crate::federation::community_admit::CommunityStore for MemoryBackend {
    async fn store_planned_community(
        &self,
        planned: crate::federation::community_admit::CommunityInsert,
    ) -> Result<crate::federation::community_admit::StoredCommunity, crate::federation::Error> {
        let crate::federation::community_admit::CommunityInsert {
            community,
            wire_index_key,
        } = planned;
        let row = community.community;
        {
            let mut state = self.state.lock().expect("memory backend lock");
            // v38.2.0 (CIRISPersist#758) — **memory used to silently
            // OVERWRITE.** `HashMap::insert` replaced the stored row AND its
            // authority signature. An occupied id now writes nothing and
            // reports the stored hash; the shared door's #758 verdict decides.
            if let Some(existing) = state.federation_communities.get(&row.community_key_id) {
                return Ok(
                    crate::federation::community_admit::StoredCommunity::Occupied {
                        stored_persist_row_hash: existing.persist_row_hash.clone(),
                    },
                );
            }
            // v21.0.0 (CIRISPersist#502 E4 followup) — persist the verified
            // authority signature.
            state.federation_community_authority_sigs.insert(
                row.community_key_id.clone(),
                (
                    community.authority_key_id,
                    community.scrub_signature_classical,
                    community.scrub_signature_pqc,
                ),
            );
            // v49.0.0 (#910.5) — a first copy of an amended version keeps its
            // proof, so the next peer can apply it.
            if let Some(p) = community.supersede_proof {
                state
                    .federation_community_supersede_proofs
                    .insert(row.community_key_id.clone(), p);
            }
            // v50.0.0 (#926) — persisted beside the authority signature.
            if !community.cosignatures.is_empty() {
                state
                    .federation_community_cosignatures
                    .insert(row.community_key_id.clone(), community.cosignatures);
            }
            if !community.lineage.is_empty() {
                state
                    .federation_community_lineages
                    .insert(row.community_key_id.clone(), community.lineage);
            }
            // v36.0.0 (#668) — serve position (V130 mirror).
            let admitted_at =
                next_plane_position(&state, PLANE_COMMUNITY, community_rows(&state).into_iter());
            let id_for_stamp = row.community_key_id.clone();
            state
                .federation_communities
                .insert(row.community_key_id.clone(), row);
            stamp_plane_position(&mut state, PLANE_COMMUNITY, id_for_stamp, admitted_at);
        }
        self.index_stored_record("Community", &wire_index_key)
            .await?;
        Ok(crate::federation::community_admit::StoredCommunity::Inserted)
    }

    async fn store_planned_community_revocation(
        &self,
        planned: crate::federation::community_admit::PlannedCommunityRevocation,
    ) -> Result<(), crate::federation::Error> {
        let crate::federation::community_admit::PlannedCommunityRevocation {
            revocation,
            removal_event,
            wire_index_key,
        } = planned;
        let row = revocation.community_membership_revocation;
        // v57.0.0 (CIRISPersist#988 item 2) — the removal's hard_case row is
        // planned inside the write; its attester is read here, before it. An
        // observation: a node with no attester records nothing and the
        // removal (and its rotation) still lands.
        let hard_case_attester = crate::federation::attestation_admit::hard_case_attester(self)
            .await
            .map_err(|e| format!("{}: {e}", e.kind()));
        let hard_case_received_at = chrono::Utc::now();
        {
            let mut state = self.state.lock().expect("memory backend lock");
            // v48.0.0 (CIRISPersist#860, V151) — the group FK points at the
            // GROUP table: a family / a room is a keyless identifier. The
            // member is a key.
            if !state
                .federation_communities
                .contains_key(&row.community_key_id)
            {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_communities",
                    row.community_key_id
                )));
            }
            if !state
                .federation_keys
                .contains_key(&row.removed_identity_key_id)
            {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_keys",
                    row.removed_identity_key_id
                )));
            }
            // v47.1.0 (CIRISPersist#861) / v48.0.0 (#860) — idempotent on
            // `(community, removed, effective_at)`: an exact repeat is `Ok`
            // and writes no second hard_case and no second epoch bump; a
            // removal at another instant is another event.
            let revocation_key = (
                row.community_key_id.clone(),
                row.removed_identity_key_id.clone(),
                row.effective_at,
            );
            if state
                .federation_community_membership_revocations
                .contains_key(&revocation_key)
            {
                return Ok(());
            }
            // CEG §7.8 (CIRISPersist#161 Ask 5) — idempotent on event_id (the
            // row id derives from it).
            memory_record_hard_case_in_state(
                &mut state,
                &hard_case_attester,
                crate::federation::attestation_admit::HardCaseEmitter::Observation,
                &removal_event,
                hard_case_received_at,
            )
            .map_err(crate::federation::Error::Backend)?;
            // CC 4.4.3.2.2 rotation-on-removal: advance the community DEK epoch
            // (memory carries the rotation *state*), only on a new revocation.
            *state
                .federation_community_dek_epoch
                .entry(row.community_key_id.clone())
                .or_insert(0) += 1;
            // v21.0.0 (CIRISPersist#502 E4 followup) — persist the verified
            // authority signature.
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
            // v49.0.0 (CIRISPersist#908, V153 mirror).
            state
                .federation_community_membership_revocation_cosignatures
                .insert(revocation_key.clone(), revocation.cosignatures);
            // v36.0.0 (#668) — serve position (V130 mirror).
            let admitted_at = next_plane_position(
                &state,
                PLANE_COMMUNITY_MEMBERSHIP_REVOCATION,
                community_membership_revocation_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[
                &revocation_key.0,
                &revocation_key.1,
                &revocation_key.2.to_rfc3339(),
            ]);
            state
                .federation_community_membership_revocations
                .insert(revocation_key, row);
            stamp_plane_position(
                &mut state,
                PLANE_COMMUNITY_MEMBERSHIP_REVOCATION,
                resume,
                admitted_at,
            );
        }
        self.index_stored_record("CommunityMembershipRevocation", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn store_planned_community_widening(
        &self,
        planned: crate::federation::community_admit::PlannedCommunityWidening,
    ) -> Result<(), crate::federation::Error> {
        let crate::federation::community_admit::PlannedCommunityWidening {
            widening,
            wire_index_key,
        } = planned;
        let row = widening.community_membership_widening;
        {
            let mut state = self.state.lock().expect("memory backend lock");
            if !state.federation_keys.contains_key(&row.member_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_keys",
                    row.member_key_id
                )));
            }
            let key = (
                row.community_key_id.clone(),
                row.member_key_id.clone(),
                row.effective_at,
            );
            if state
                .federation_community_membership_widenings
                .contains_key(&key)
            {
                return Ok(());
            }
            state
                .federation_community_membership_widening_authority_sigs
                .insert(
                    key.clone(),
                    (
                        widening.authority_key_id,
                        widening.scrub_signature_classical,
                        widening.scrub_signature_pqc,
                    ),
                );
            // v49.0.0 (CIRISPersist#908, V153 mirror).
            state
                .federation_community_membership_widening_cosignatures
                .insert(key.clone(), widening.cosignatures);
            let admitted_at = next_plane_position(
                &state,
                PLANE_COMMUNITY_MEMBERSHIP_WIDENING,
                community_membership_widening_rows(&state).into_iter(),
            );
            let resume = crate::federation::types::compound_resume_id(&[
                &key.0,
                &key.1,
                &key.2.to_rfc3339(),
            ]);
            state
                .federation_community_membership_widenings
                .insert(key, row);
            stamp_plane_position(
                &mut state,
                PLANE_COMMUNITY_MEMBERSHIP_WIDENING,
                resume,
                admitted_at,
            );
        }
        self.index_stored_record("CommunityMembershipWidening", &wire_index_key)
            .await?;
        Ok(())
    }

    async fn store_planned_community_listing(
        &self,
        planned: crate::federation::community_admit::PlannedCommunityListing,
    ) -> Result<(), crate::federation::Error> {
        let crate::federation::community_admit::PlannedCommunityListing {
            listing,
            wire_index_key,
        } = planned;
        {
            let mut state = self.state.lock().expect("memory backend lock");
            let row = &listing.community_membership_listing;
            // The V156 FKs: the room (the plan checked it) and the member.
            if !state
                .federation_communities
                .contains_key(&row.community_key_id)
            {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_communities",
                    row.community_key_id
                )));
            }
            if !state.federation_keys.contains_key(&row.member_key_id) {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "{} does not exist in federation_keys",
                    row.member_key_id
                )));
            }
            let key = (
                row.community_key_id.clone(),
                row.member_key_id.clone(),
                row.effective_at,
            );
            if state
                .federation_community_membership_listings
                .contains_key(&key)
            {
                return Ok(());
            }
            let resume = crate::federation::types::compound_resume_id(&[
                &key.0,
                &key.1,
                &key.2.to_rfc3339(),
            ]);
            let rows = community_membership_listing_rows(&state);
            allocate_and_stamp(&mut state, PLANE_COMMUNITY_MEMBERSHIP_LISTING, resume, rows);
            state
                .federation_community_membership_listings
                .insert(key, listing);
        }
        self.index_stored_record("CommunityMembershipListing", &wire_index_key)
            .await?;
        Ok(())
    }

    #[cfg(test)]
    async fn rival_community_write_at(
        &self,
        at: crate::store::test_hooks::RivalPoint,
    ) -> Result<(), crate::federation::Error> {
        self.test_rival_at(at).await
    }
}

/// v54.0.0 (CIRISPersist#995 row 5) — the memory twin of the SQL upserts: a
/// record has ONE current content hash, so its earlier mappings are dropped
/// before the new one is written.
fn memory_upsert_wire_index(
    index: &mut HashMap<(String, String), String>,
    kind: &str,
    content_hash: String,
    record_key: &str,
) {
    index.retain(|(k, h), rk| !(k == kind && rk == record_key && *h != content_hash));
    index.insert((kind.to_owned(), content_hash), record_key.to_owned());
}
