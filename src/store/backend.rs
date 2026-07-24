//! Backend trait — sealed Phase 1, surfaces Phase 2 + 3 (stubbed
//! `unimplemented!()` until those phases land).
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same persistence trait surface, regardless of substrate. Phase 1's
//! Postgres impl satisfies the Phase-1 methods; Phase 2's expanded
//! impl fills in audit + correlation; Phase 3 finishes runtime state.
//! The trait surface itself is Phase 1 work — the lock-in that
//! prevents bifurcation between "Phase 1+2 ciris-persist" vs "Phase 3
//! ciris-persist" the FSD §5.2 calls out.
//!
//! Mission constraint (MISSION.md §3 anti-pattern #4): typed errors;
//! every fallible operation returns `Result<T, Error>` with a defined
//! `Error` variant, never panics in non-test code paths.

use std::future::Future;

use ed25519_dalek::VerifyingKey;

use super::types::{DeleteSummary, ErasureSummary, TraceEventRow, TraceLlmCallRow};
use super::Error;

/// Persistence Backend trait — the load-bearing abstraction.
///
/// Async surface uses Rust 1.75+ `async fn in trait` directly; futures
/// are constrained `Send` so backends can be used from
/// `tokio::spawn`-style multi-threaded contexts.
///
/// Phase 1 methods are ready to implement. Phase 2 / 3 methods are
/// part of the Phase 1 trait shape but their default impl returns an
/// `Error::NotImplemented` — a backend that doesn't yet support a
/// surface returns that variant rather than panicking, so callers
/// can handle "this backend can't do that" as a typed error.
pub trait Backend: Send + Sync {
    // ─── Phase 1 — lens trace ingest ───────────────────────────────

    /// Insert a batch of `trace_events` rows. Returns the count of
    /// rows actually inserted (i.e. excluding ON CONFLICT skips).
    ///
    /// Mission constraint (MISSION.md §4 "Idempotency"): adapter
    /// retries are safe; conflict on
    /// `(trace_id, thought_id, event_type, attempt_index)` is a
    /// no-op.
    fn insert_trace_events_batch(
        &self,
        rows: &[TraceEventRow],
    ) -> impl Future<Output = Result<InsertReport, Error>> + Send;

    /// Insert a batch of `trace_llm_calls` rows. Returns the count of
    /// rows actually inserted.
    fn insert_trace_llm_calls_batch(
        &self,
        rows: &[TraceLlmCallRow],
    ) -> impl Future<Output = Result<usize, Error>> + Send;

    /// ## Projection-pinned (v20.1.0, CIRISPersist#477 — recorded decision)
    ///
    /// This surface reads the `trace_events` PROJECTION by design, not the
    /// envelope-native attestation (the canonical home since v18.0.0). The
    /// #477 disposition: the projection is a SUPERSET projection (all
    /// per-event scalars + payload + enrichment columns), maintained at
    /// ingest in the same flow as the attestation mint — physical-row
    /// reads stay HERE permanently; corpus unification would force
    /// envelope reassembly on every hot read for no consumer benefit.
    /// Mutable enrichment (`extracted_features`/`classifications`) is
    /// projection-LOCAL by design: a projection column, not envelope
    /// content — the signed envelope is never retro-mutated.
    /// v0.7.4 (CIRISPersist#19) — batch-UPDATE the V009
    /// `extracted_features` column for `(trace_id, thought_id)` pairs.
    /// Called from `IngestPipeline::receive_and_persist` post-insert
    /// when the `extract` pipeline stage runs.
    ///
    /// Default impl returns 0 (no-op) — memory + sqlite backends
    /// don't have the V009 column. Postgres backend overrides with
    /// the real UNNEST'd UPDATE.
    #[cfg(feature = "extract")]
    fn update_features_batch(
        &self,
        updates: &[(String, String, crate::pipeline::extract::Features)],
    ) -> impl Future<Output = Result<u64, Error>> + Send {
        let _ = updates;
        async { Ok(0) }
    }

    /// Look up a verifying key by `signature_key_id`
    /// (`accord_public_keys` table).
    fn lookup_public_key(
        &self,
        key_id: &str,
    ) -> impl Future<Output = Result<Option<VerifyingKey>, Error>> + Send;

    /// v0.1.17 — backend-side diagnostic for the verify-unknown-key
    /// breadcrumb (CIRISPersist#6). Returns total count of valid
    /// (unrevoked, unexpired) public-key rows + a sample of up to
    /// `limit` `key_id` values.
    ///
    /// Used ONLY by the `IngestPipeline` warn-log emitted when
    /// `lookup_public_key` returns `Ok(None)` — surfaces "what does
    /// the backend actually see at lookup time" so a verify miss can
    /// be triaged without source-level instrumentation. Default impl
    /// returns an empty sample (the Memory backend doesn't run a real
    /// query); the Postgres impl runs `SELECT COUNT(*) ... + LIMIT N`
    /// against `cirislens.accord_public_keys` with the same filter
    /// the runtime lookup applies.
    ///
    /// **Not part of the public ingest contract.** Don't make
    /// production decisions on this method's output; it's a
    /// diagnostic-only escape hatch.
    fn sample_public_keys(
        &self,
        limit: usize,
    ) -> impl Future<Output = Result<PublicKeySample, Error>> + Send {
        let _ = limit;
        async {
            Ok(PublicKeySample {
                size: 0,
                sample: Vec::new(),
            })
        }
    }

    /// Run pending migrations against the backend's schema. Phase 1
    /// migrations live in `migrations/postgres/lens/` and
    /// `migrations/sqlite/lens/`; the runner is `refinery`.
    fn run_migrations(&self) -> impl Future<Output = Result<(), Error>> + Send;

    /// v0.3.6 (CIRISPersist#15, CIRISLens#8 ASK 1) — GDPR Article 17
    /// / DSAR primitive. Per-key scope: deletion is scoped to
    /// `(agent_id_hash, signing_key_id)` — both required.
    ///
    /// `signature_key_id` is the **authorization scope** of the DSAR,
    /// not just an identity filter. A request signed by key A is
    /// only authorized to delete traces signed by key A. Without
    /// per-key scope, any one valid key could file a DSAR deleting
    /// traces from other agent instances claiming the same logical
    /// identity (e.g., separate deployments of the same template
    /// with different signing keys).
    ///
    /// **Breaking change vs v0.3.5**: v0.3.5 took only
    /// `agent_id_hash` and broadened scope to all keys for that
    /// agent. v0.3.6 requires `signature_key_id` — the per-key
    /// contract is load-bearing for the federation's authorization
    /// model. Admin / forensic deletions (operator with explicit
    /// out-of-band authorization, no DSAR signature) belong in
    /// standard privileged CRUD, not this primitive.
    ///
    /// Deletes:
    /// - `trace_events` rows where `agent_id_hash` AND
    ///   `signing_key_id` both match
    /// - `trace_llm_calls` rows joined by `trace_id` from the deleted
    ///   trace_events set (LLM call rows don't carry agent_id_hash
    ///   or signing_key_id per V001 schema; the trace_id bridge
    ///   ensures cross-key cascade safety)
    ///
    /// When `include_federation_key=true`, additionally:
    /// - the single `federation_keys` row where `key_id =
    ///   signature_key_id` AND `identity_type='agent'` AND
    ///   `identity_ref=agent_id_hash`
    /// - FK-cascade: `federation_attestations` rows referencing that
    ///   key (attesting / attested / scrub_key_id) deleted first
    /// - FK-cascade: `federation_revocations` rows referencing that
    ///   key, deleted before the federation_keys delete
    ///
    /// The agent's other registered keys stay alive — the per-key
    /// authorization model means the DSAR can only revoke the key it
    /// was signed with.
    ///
    /// All deletes happen in a single transaction. The caller's
    /// `agent_id_hash` and `signature_key_id` are not validated
    /// against any signing-key proof — that's the lens's
    /// DSAR-orchestration responsibility. Persist owns the substrate
    /// row delete; lens owns the audit + signature verification of
    /// the request envelope.
    ///
    /// Idempotent: re-invocation returns a `DeleteSummary` with all
    /// counts zero.
    fn delete_traces_for_agent(
        &self,
        agent_id_hash: &str,
        signature_key_id: &str,
        include_federation_key: bool,
    ) -> impl Future<Output = Result<DeleteSummary, Error>> + Send;

    /// v6.9.0 (CIRISPersist#222) — GDPR Art. 17 / DSAR **full erasure** of
    /// an agent's trace corpus, keyed on `agent_id_hash` ALONE (across all
    /// signing keys — contrast [`delete_traces_for_agent`](Self::delete_traces_for_agent),
    /// which scopes to one signing key for the per-key DSAR).
    ///
    /// In a single transaction:
    /// - HARD-delete every `trace_events` row where `agent_id_hash`
    ///   matches.
    /// - HARD-delete every `trace_llm_calls` row joined by `trace_id`
    ///   from that erased set (LLM call rows carry no `agent_id_hash` per
    ///   the V001 schema; the `trace_id` bridge is the only linkage).
    /// - TOMBSTONE — not delete — every `detection_events` row derived
    ///   from those traces (matched by `trace_id`): NULL the PII-linkage
    ///   columns (`trace_id`, `body_sha256`, `canonical_bytes`) and stamp
    ///   `erased_at` (V080). The derived analytics survive; the subject
    ///   linkage is severed. Operator decision per CIRISPersist#222:
    ///   detections are substrate-derived, not the subject's personal
    ///   data.
    /// - EMIT a `hard_case:trace_erasure` audit row (V075
    ///   `hard_case_events`) inside the SAME transaction, so the audit
    ///   record commits atomically with the erasure — persist's
    ///   self-emission audit surface for destructive ops.
    ///
    /// **Idempotent**: a second call finds no matching rows and returns a
    /// [`ErasureSummary`] with all counts zero. A not-found is NEVER an
    /// error here.
    ///
    /// Authority is NOT validated against any signing-key proof — that is
    /// the caller's (CIRISServer's absorbed-lens slice) DSAR-orchestration
    /// responsibility. Persist owns the atomic substrate erasure.
    fn delete_traces_for_agent_id_hash(
        &self,
        agent_id_hash: &str,
    ) -> impl Future<Output = Result<ErasureSummary, Error>> + Send;

    /// ## Projection-pinned (v20.1.0, CIRISPersist#477 — recorded decision)
    ///
    /// This surface reads the `trace_events` PROJECTION by design, not the
    /// envelope-native attestation (the canonical home since v18.0.0). The
    /// #477 disposition: the projection is a SUPERSET projection (all
    /// per-event scalars + payload + enrichment columns), maintained at
    /// ingest in the same flow as the attestation mint — physical-row
    /// reads stay HERE permanently; corpus unification would force
    /// envelope reassembly on every hot read for no consumer benefit.
    /// Mutable enrichment (`extracted_features`/`classifications`) is
    /// projection-LOCAL by design: a projection column, not envelope
    /// content — the signed envelope is never retro-mutated.
    /// v0.3.5 (CIRISLens#8 ASK 3) — Page-cursor read primitive for
    /// analytical streaming. Returns up to `limit` `trace_events` rows
    /// where `event_id > after_event_id`, ordered ascending by
    /// `event_id` (the BIGSERIAL primary key). Optional
    /// `agent_id_hash` filter.
    ///
    /// Caller orchestrates the cursor — track the max returned
    /// `event_id` between calls, pass it as `after_event_id` for the
    /// next page, stop when the result set is empty.
    ///
    /// Cleaner than a callback-style `iterate_trace_events(filter, cb)`
    /// across PyO3: callers pull pages on their own pace, no FFI
    /// re-entry per row, no shared-state synchronization. Same shape
    /// `Engine.run_pqc_sweep` uses (cursor at the trait boundary,
    /// caller drives).
    ///
    /// `event_id` is internal to the row but is returned in the
    /// `TraceEventRow` indirectly via the row's serialized form;
    /// the PyO3 surface (`Engine.fetch_trace_events_page`) returns
    /// dicts that include `event_id` so callers can extract the
    /// cursor without parsing further.
    fn fetch_trace_events_page(
        &self,
        after_event_id: i64,
        limit: i64,
        agent_id_hash: Option<&str>,
    ) -> impl Future<Output = Result<Vec<(i64, TraceEventRow)>, Error>> + Send;

    // ─── Phase 2 / 3 surfaces (audit, correlations, tasks, graph) ──
    //
    // v7.0.0 (CEWP-ready): the former `append_audit_entry` /
    // `record_correlation` / `upsert_task` / `try_claim_shared_task` /
    // `add_graph_node` default-`NotImplemented` stubs are REMOVED. They
    // were vestigial scaffolding from the original monolithic-`Backend`
    // design; the capabilities ship on both backends via the dedicated
    // per-capability service traits — `audit::AuditService`,
    // `correlations::CorrelationsService`, `tasks::TasksService`, and the
    // `cirisgraph` surface — each with full PostgreSQL + SQLite parity. No
    // backend ever overrode the `Backend`-trait versions; nothing called
    // them through `Backend`. Removing them ends the naming collision that
    // forced UFCS at the call sites and stops the trait advertising
    // "NotImplemented" for capabilities that are, in fact, implemented.

    /// v4.0 (CIRISPersist#160, FSD §4.4) — resolve the IDENTITY a
    /// signing/occurrence key speaks for, for the trace-ingest
    /// `self`-target stamping path (FSD §12.0 item 1).
    ///
    /// Returns the `identity_key_id` bound to `occurrence_key_id` via
    /// `federation_identity_occurrences` (V059), or `None` when the
    /// key is not (yet) bound as an occurrence of any identity — the
    /// **singleton-identity fallback** (FSD §4.4): a fresh sovereign
    /// deployment IS its own identity, so the caller treats `None` as
    /// "identity == occurrence" and stamps the occurrence key itself.
    ///
    /// Default impl returns `Ok(None)` (always singleton) so backends
    /// without a federation directory degrade to the sovereign posture.
    /// The Postgres / SQLite / Memory backends override to consult
    /// their [`crate::federation::FederationDirectory`] impl.
    ///
    /// This is a *resolution* method (MISSION §1.7): it reports what
    /// the federation chain has admitted about the key, never arbitrates
    /// it.
    fn resolve_identity_for_occurrence(
        &self,
        _occurrence_key_id: &str,
    ) -> impl Future<Output = Result<Option<String>, Error>> + Send {
        async { Ok(None) }
    }

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — every family
    /// `family_key_id` the given IDENTITY is a member of. The
    /// family-half of the writer's [`CallerAdmission`](crate::scope::CallerAdmission)
    /// for the write-path cohort_scope gate
    /// ([`DimensionAdmissionPolicy::check_write_cohort_scope`](crate::federation::admission::DimensionAdmissionPolicy::check_write_cohort_scope)).
    ///
    /// Mirrors the read-side admission builder
    /// ([`build_caller_admission`](crate::scope::build_caller_admission))
    /// step 2 but reachable from the `Backend`-only ingest pipeline,
    /// which holds no `Engine`. `member_identity_key_id` is the writer's
    /// identity (resolved via [`Self::resolve_identity_for_occurrence`]).
    ///
    /// Default impl returns `Ok(vec![])` — the sovereign/singleton
    /// posture (no family memberships). The Postgres / SQLite / Memory
    /// backends override to consult their
    /// [`crate::federation::FederationDirectory`] impl.
    fn admission_family_key_ids(
        &self,
        _member_identity_key_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, Error>> + Send {
        async { Ok(Vec::new()) }
    }

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — every community
    /// `community_key_id` the given IDENTITY is a member of. The
    /// community-half of the writer's admission for the write-path
    /// cohort_scope gate. Symmetric to [`Self::admission_family_key_ids`];
    /// see that method for the full rationale.
    ///
    /// Default impl returns `Ok(vec![])` — sovereign/singleton posture.
    fn admission_community_key_ids(
        &self,
        _member_identity_key_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, Error>> + Send {
        async { Ok(Vec::new()) }
    }

    // ─── v8.0.0 — fountain content primitive (CIRISPersist#227) ─────
    //
    // The store-and-evict half of the `FountainContentV1` contract.
    // persist is store-and-evict-ONLY: opaque symbol bytes, zero codec
    // crates. Three methods, full PG/SQLite/memory parity:
    //   * put_fountain_content — verify-before-mutation admit (the #225
    //     hybrid verify on the manifest + per-symbol SHA-256 auth), then
    //     transactional insert of manifest + symbols.
    //   * evict_fountain_content_to_tier — tier × priority eviction; the
    //     mechanism both the DiskPressure (#149) and the consent-decay
    //     triggers call.
    //   * get_fountain_content — typed degraded read with per-symbol
    //     hash re-auth.
    // See `crate::fountain` for the structs + the admission/eviction
    // logic the three backends share.

    /// v8.0.0 (CIRISPersist#227) — admit a fountain-coded content unit:
    /// verify the manifest's hybrid signature (`HybridPolicy::Strict` —
    /// classical-only REJECTED, the #225 hard cut) over the LOCKED
    /// canonical bytes, verify every provided symbol's SHA-256 against
    /// the signed `symbol_hashes`, validate structure
    /// (`symbol_hashes.len() == n_source + k_repair`, in-range, no dups),
    /// and ONLY THEN insert the manifest + symbols in one transaction
    /// (AV-9 verify-before-mutation).
    ///
    /// On any admission failure NOTHING is written; the error carries the
    /// stable [`crate::fountain::FountainAdmitError`] token. The producer
    /// Ed25519 + ML-DSA-65 pubkeys are asserted on the manifest envelope
    /// (`pubkey_ed25519` / `pubkey_ml_dsa_65`), bound into the hybrid
    /// verify (a forged pubkey fails the signature — it cannot grant
    /// trust by itself).
    ///
    /// Idempotent on `(content_id, corpus_kind)`: re-admitting the same
    /// content (manifest ON CONFLICT DO NOTHING; symbols upserted) is
    /// safe.
    fn put_fountain_content(
        &self,
        manifest: &crate::fountain::FountainManifestV1,
        symbols: &[crate::fountain::FountainSymbolV1],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// v8.0.0 (CIRISPersist#227) — evict a content unit's symbols down to
    /// the per-tier keep-count, dropping by `retention_priority DESC`
    /// (highest-priority-value first) within the `content_id`. The
    /// manifest is NEVER touched. Returns the number of symbol rows
    /// evicted.
    ///
    /// This is the persist-owned eviction MECHANISM both orthogonal
    /// triggers call: the DiskPressure (#149) sweeper maps a
    /// [`crate::federation::DiskPressureSnapshot`] tier to a
    /// [`crate::fountain::FountainTier`] via
    /// [`FountainTier::from_pressure`](crate::fountain::FountainTier::from_pressure);
    /// the consent-decay trigger (full Consensual-Evolution scheduling is
    /// a documented follow-on) calls it directly.
    ///
    /// A no-op (returns `Ok(0)`) when the content_id is unknown or
    /// already at/below the keep-count.
    fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: crate::fountain::FountainTier,
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    /// v8.1.0 (CEG 1.0-RC11 §19 / CIRISPersist#228 N5 — revocation
    /// overrides rarity) — **HardDelete** every symbol row for
    /// `(content_id, corpus_kind)` unconditionally, leaving the manifest
    /// as the always-retained `EnvelopeOnly` provenance ("existed with
    /// signature X"). Returns the number of symbol rows dropped.
    ///
    /// This is the §8.1.11.3 deletion-SLA path for a withdrawn /
    /// `consent:state:revoked` content_id, and it is DELIBERATELY a
    /// separate path from
    /// [`evict_fountain_content_to_tier`](Self::evict_fountain_content_to_tier):
    /// it never consults `retention_priority` (nor any future swarm
    /// rarity reweight packed into that byte). Revocation is a
    /// content-level dominating signal, NOT a value that competes inside
    /// the priority ordering — so a high rarity score can never resurrect
    /// a revoked content. The trigger that calls this on revoke rides
    /// with the consent-decay scheduling follow-on; the dominating
    /// mechanism + the precedence invariant live here now. Unknown
    /// content ⇒ `Ok(0)` no-op.
    fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    /// v8.0.0 (CIRISPersist#227) — typed degraded read. Counts present
    /// symbols and classifies vs the manifest thresholds:
    /// `present >= n_source` ⇒ `Full`; `[min_viable, n_source)` ⇒
    /// `Partial { present }`; `< min_viable` (incl. 0) ⇒ `EnvelopeOnly`
    /// (the manifest always survives). Each present symbol's SHA-256 is
    /// re-verified against the signed `symbol_hashes` on read
    /// (authenticated partials — memory fades but can't be falsified);
    /// a mismatch is a substrate-integrity error, not a degraded read.
    ///
    /// Returns `Ok(None)` when there is no manifest for
    /// `(content_id, corpus_kind)`.
    fn get_fountain_content(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> impl Future<Output = Result<Option<crate::fountain::FountainContent>, Error>> + Send;

    /// #227 — list the fountain-coded content a **publisher** holds, as
    /// [`FountainHeldMeta`](crate::fountain::FountainHeldMeta) (manifest
    /// essentials + the current degradation state: `held_symbols` vs
    /// `min_viable_symbols` ⇒ `recoverable`). Filtered to
    /// `content_manifest.pqc_key_id = publisher_key_id` (the manifest signer);
    /// no symbol bytes are read. Ordered by `admitted_at` descending. Empty
    /// when the publisher holds nothing.
    fn list_held_fountain_content(
        &self,
        publisher_key_id: &str,
    ) -> impl Future<Output = Result<Vec<crate::fountain::FountainHeldMeta>, Error>> + Send;

    // ─── v12.7.0 — §Q pin-INSTALL surface (CC 6.1.5.2 / CIRISPersist#370) ──
    //
    // The durable half of the storage-contention shapes (#356 shipped
    // build/verify as wire-negotiation only). One row per owner node_id in
    // `storage_budget_installed` (V093). The B5 capacity sweep
    // (`Engine::sweep_evictions_once`) reads this state back; the
    // revocation path (`evict_fountain_content_hard_delete`, above) NEVER
    // does — §Q B6: pinning never defeats revocation.

    /// #370 (§Q B3) — conditionally upsert an installed `StorageBudgetV1`.
    ///
    /// The caller (`Engine::install_storage_budget_v1`) MUST have
    /// bound-hybrid-verified the wire first (PQC-mandatory, CC 5.3.2.4.3.1
    /// store-path); this method enforces the **anti-rollback** half
    /// ATOMICALLY at the row: insert if the `node_id` is new, replace iff
    /// `budget.revision` is STRICTLY higher than the installed revision.
    /// Returns `Ok(true)` when the row was written, `Ok(false)` when refused
    /// (lower/equal revision — the caller surfaces
    /// `StorageContentionError::RevisionRollback`). Doing the check in the
    /// upsert itself (`... WHERE installed.revision < excluded.revision`)
    /// means two racing installs cannot roll the revision back.
    fn put_installed_storage_budget(
        &self,
        budget: &crate::fountain::storage_contention::InstalledStorageBudget,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// #370 — read back the installed budget for `node_id` (the signed wire
    /// verbatim + denormalized fields). `Ok(None)` when none installed.
    fn get_installed_storage_budget(
        &self,
        node_id: &str,
    ) -> impl Future<
        Output = Result<Option<crate::fountain::storage_contention::InstalledStorageBudget>, Error>,
    > + Send;

    /// #370 (§Q B5) — every installed budget (typically exactly one: this
    /// node's own). The capacity sweep folds these into the effective
    /// `pinned_class` set + `pin_reserve_bytes` floor once per cycle.
    fn list_installed_storage_budgets(
        &self,
    ) -> impl Future<
        Output = Result<Vec<crate::fountain::storage_contention::InstalledStorageBudget>, Error>,
    > + Send;
    /// #227 (residual) — enumerate EVERY fountain content unit's decay
    /// coordinates for the consent-decay clock: `(content_id, corpus_kind,
    /// envelope, admitted_at)`. The signed `envelope` carries the decay
    /// class ([`crate::fountain::consent_decay_class_from_envelope`]) and
    /// `admitted_at` is the decay reference instant. No symbol bytes are
    /// read; the sweep asks
    /// [`consent_decay_target_tier`](crate::fountain::consent_decay_target_tier)
    /// for a target tier and reuses the shared eviction mechanism
    /// ([`Self::evict_fountain_content_to_tier`]). Unordered; empty when
    /// nothing is stored. Disk-INDEPENDENT (never consults free bytes).
    fn list_fountain_decay_candidates(
        &self,
    ) -> impl Future<Output = Result<Vec<crate::fountain::FountainDecayCandidate>, Error>> + Send;

    // ─── v8.3.0 — §19.7 inter-object aggregation (CIRISPersist#230) ──
    //
    // The forever-memory storage half of operator 2. persist is
    // codec-free: the N→1 resampling is edge-side; persist stores the
    // composite (a FountainContentV1, via the EXISTING #225 admit gate) +
    // records the aggregation provenance. The §19.7 wire payload is OPAQUE
    // bytes (`aggregation_meta`) persist never parses — the wire-churn
    // firewall (the §19.7 contract is not yet frozen).

    /// v8.3.0 (CEG 1.0-RC12 §19.7 / CIRISPersist#230) — admit an aggregate
    /// composite + record its aggregation provenance, in ONE transaction:
    ///
    /// 1. Admit the composite via the EXISTING fountain admit path
    ///    ([`Self::put_fountain_content`] / `check_admission_via_envelope`
    ///    — the #225 hybrid-manifest verify + per-symbol SHA-256; a
    ///    classical-only composite manifest is REJECTED, the same hard
    ///    cut). Verify-before-mutation (AV-9): nothing is written if the
    ///    composite admit fails.
    /// 2. Insert the `content_aggregation` row.
    ///
    /// `manifest.content_id` MUST equal `agg.aggregate_content_id` and
    /// `manifest.corpus_kind` MUST be
    /// `"aggregate:<agg.source_corpus_kind>"`. The composite is PQC-verified
    /// (it's a FountainContentV1). `agg.member_commitment` +
    /// `agg.aggregation_meta` are STORED (opaque); persist does NOT verify
    /// them this cut (§19.7-freeze-gated, CIRISVerify v5.10.0).
    ///
    /// Idempotent on `aggregate_content_id` (the row is `ON CONFLICT DO
    /// NOTHING`; the composite reuses the fountain idempotency).
    fn put_aggregated_tier(
        &self,
        manifest: &crate::fountain::FountainManifestV1,
        symbols: &[crate::fountain::FountainSymbolV1],
        agg: &crate::fountain::AggregationMetaV1,
        aggregated_at_unix_ms: i64,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// v8.3.0 (CIRISPersist#230) — read the aggregation record for a
    /// composite content_id (the opaque `aggregation_meta` comes back as
    /// raw bytes). `Ok(None)` when there is no aggregation record. The
    /// O(log T) pyramid-walk point read.
    fn get_aggregation(
        &self,
        aggregate_content_id: &str,
    ) -> impl Future<Output = Result<Option<crate::fountain::AggregationRecordV1>, Error>> + Send;

    /// v8.3.0 (CIRISPersist#230) — list the aggregation records at a
    /// pyramid level, ordered by `aggregated_at_unix_ms ASC` then
    /// `aggregate_content_id ASC` (deterministic), capped at `limit`. The
    /// level-walk for the O(log T) forever-memory navigation.
    fn list_aggregations_at_level(
        &self,
        level: i64,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<crate::fountain::AggregationRecordV1>, Error>> + Send;
}

/// Report of a batch insert.
///
/// Mission category §4 "Idempotency": separates inserted from
/// conflicted so callers can tell whether retries actually wrote new
/// rows or merely confirmed existing ones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InsertReport {
    /// Number of rows that were newly inserted.
    pub inserted: usize,
    /// Number of rows that hit `ON CONFLICT DO NOTHING` (idempotent
    /// re-submission).
    pub conflicted: usize,
}

impl InsertReport {
    /// Total rows considered by the backend (inserted + conflicted).
    pub fn total_seen(&self) -> usize {
        self.inserted + self.conflicted
    }
}

/// v0.1.17 — diagnostic snapshot of `accord_public_keys` for the
/// verify-unknown-key breadcrumb. See [`Backend::sample_public_keys`].
///
/// Mission constraint: this is observability scaffolding, not a
/// production data path. The `sample` is bounded by the caller's
/// `limit` and is whatever the backend orders the rows by (no
/// stability guarantee across calls).
#[derive(Debug, Clone, Default)]
pub struct PublicKeySample {
    /// Total count of valid (unrevoked, unexpired) public-key rows
    /// the backend can see at the time of the call.
    pub size: usize,
    /// First N `key_id` values per the backend's natural ordering
    /// (typically primary-key order on Postgres).
    pub sample: Vec<String>,
}
