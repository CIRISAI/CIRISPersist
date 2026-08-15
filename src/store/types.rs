//! Row-shaped types — what the Backend trait reads and writes.
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same row shape across backends (Postgres, SQLite, in-memory test).
//! Naming and column types here mirror
//! `context/lens_027_trace_events.sql` so the SQL writer is a
//! straightforward field-by-field map. Drift between this struct and
//! the SQL schema is the failure mode that breaks corpus
//! reconstruction; reviewers MUST cross-check against the migration
//! file when updating either.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::schema::{LlmCallStatus, ReasoningEventType, TraceLevel};

/// v2.0 (CIRISPersist#91) — who established a trace's authenticity,
/// stored in the `trace_events.verification_source` TEXT column.
///
/// Closed set, typed the same way as the other discriminators on
/// [`TraceEventRow`] (e.g. [`TraceLevel`]) — a Rust enum mapped to a
/// constant-set TEXT column via [`as_wire_str`](Self::as_wire_str) /
/// [`from_wire_str`](Self::from_wire_str). The DB CHECK constraint
/// `verification_source IN ('persist','edge')` mirrors this set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationSource {
    /// Persist ran [`crate::verify::verify_trace`] itself during
    /// ingest — [`VerifyMode::Full`](crate::ingest::VerifyMode::Full).
    /// The default: every pre-V044 row, and every direct-ingest row.
    #[default]
    Persist,
    /// Verification was delegated upstream to an Edge verifier; the
    /// relay carried the `verify_outcome` and persist skipped its own
    /// `verify_trace` — the
    /// [`VerifyMode::TrustPreVerified`](crate::ingest::VerifyMode::TrustPreVerified)
    /// relay skip-verify path (CIRISPersist#91).
    Edge,
}

impl VerificationSource {
    /// The TEXT-column wire form (`'persist'` / `'edge'`). Matches
    /// the V044 CHECK-constraint value set.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            VerificationSource::Persist => "persist",
            VerificationSource::Edge => "edge",
        }
    }

    /// Parse the TEXT-column wire form. `None` for any value outside
    /// the closed set — the caller surfaces it as a backend decode
    /// error (the DB CHECK constraint should make this unreachable).
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "persist" => Some(VerificationSource::Persist),
            "edge" => Some(VerificationSource::Edge),
            _ => None,
        }
    }
}

/// A row landing on `cirislens.trace_events`
/// (`context/lens_027_trace_events.sql` lines 13-38).
///
/// Mission constraint: `payload` IS the agent's testimony kept
/// verbatim (the JSONB column). Typed accessors live on the wire
/// type [`crate::schema::TraceComponent`]; once decomposed to a row,
/// the typed extracts have already been pulled into the denormalized
/// columns (`cost_*`, `attempt_index`, etc.) and the `payload` blob
/// is the on-disk archive of the original `data` dict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEventRow {
    /// Stable trace identifier (CompleteTrace.trace_id).
    pub trace_id: String,
    /// Thought-iteration identifier within the trace.
    pub thought_id: String,
    /// Optional originating task identifier; absent for traces that
    /// originate outside a task (passive observations, etc.).
    pub task_id: Option<String>,

    /// Derived from `event_type` per the H3ERE step sequence; phase 1
    /// approximation pulls it from `data["step_point"]` if present,
    /// else infers a default from `event_type`.
    pub step_point: Option<String>,

    /// Typed event kind (THOUGHT_START / CONSCIENCE_RESULT / etc.).
    pub event_type: ReasoningEventType,
    /// Per-`(thought_id, event_type)` attempt counter. Bounded by
    /// `schema::MAX_ATTEMPT_INDEX` (THREAT_MODEL.md AV-17).
    pub attempt_index: u32,
    /// Wall-clock at which the event happened.
    pub ts: DateTime<Utc>,

    /// Optional human-readable agent name (debug / display only).
    pub agent_name: Option<String>,
    /// SHA-256 digest of the agent's identity tuple (the dedup-key
    /// prefix; THREAT_MODEL.md AV-9).
    pub agent_id_hash: String,
    /// Cognitive-state tag for the agent at the moment of the event.
    pub cognitive_state: Option<String>,

    /// Trace verbosity level (generic / detailed / full_traces).
    pub trace_level: TraceLevel,
    /// Verbatim component data dict (post-scrub if the scrubber
    /// modified it; pre-scrub bytes are NOT retained).
    pub payload: serde_json::Map<String, serde_json::Value>,

    /// Denormalized cost columns — populated only on the
    /// `ACTION_RESULT` row (TRACE_WIRE_FORMAT.md §5.9). Other rows
    /// leave these `None`.
    pub cost_llm_calls: Option<i32>,
    /// LLM token cost summed over the trace's LLM calls.
    pub cost_tokens: Option<i32>,
    /// USD cost summed over the trace's LLM calls.
    pub cost_usd: Option<f64>,

    /// Per-trace agent signature (carried verbatim from the
    /// CompleteTrace; identical across all rows of the same trace).
    pub signature: String,
    /// Identifier for the agent's signing key (looked up against
    /// `accord_public_keys`).
    pub signing_key_id: String,
    /// True iff this row's parent CompleteTrace signature is valid —
    /// the authenticity gate passed. Never persisted as `false` for
    /// unverified bytes (MISSION.md §3 anti-pattern #2 — "store
    /// first, verify later" is rejected).
    ///
    /// Who established that the signature is valid is recorded
    /// separately in [`verification_source`](Self::verification_source):
    /// persist's own `verify_trace`, or an upstream Edge verifier
    /// (CIRISPersist#91 relay skip-verify). `signature_verified` is
    /// `true` in both cases — the signature is valid either way.
    pub signature_verified: bool,

    /// v2.0 (CIRISPersist#91) — who established this trace's
    /// authenticity.
    ///
    /// [`VerificationSource::Persist`] — persist ran
    /// [`crate::verify::verify_trace`] itself during ingest
    /// ([`VerifyMode::Full`](crate::ingest::VerifyMode::Full), the
    /// default and the only mode for untrusted direct-ingest input).
    ///
    /// [`VerificationSource::Edge`] — verification was delegated
    /// upstream: an Edge verifier attested the batch and the relay
    /// carried the `verify_outcome`, so persist skipped its own
    /// `verify_trace` (and the redundant federation-directory lookup)
    /// — the [`VerifyMode::TrustPreVerified`](crate::ingest::VerifyMode::TrustPreVerified)
    /// relay skip-verify path. The trace is still authentic
    /// (`signature_verified = true`); Edge attested it.
    ///
    /// A consumer that needs persist-attested verification
    /// specifically filters `verification_source = 'persist'`. The
    /// TEXT column defaults to `'persist'` — every pre-V044 row was
    /// ingested through persist's own `verify_trace`.
    pub verification_source: VerificationSource,

    /// Wire-format schema version the trace was emitted under.
    pub schema_version: String,
    /// True after the scrubber pass ran.
    pub pii_scrubbed: bool,

    // ─── v0.3.4 deployment_profile denormalization (CIRISPersist#13).
    // Per-trace constants copied onto every event row of the trace,
    // same shape as `agent_name` / `agent_id_hash` / `cognitive_state`
    // already do. Lens-side analytical paths group/filter on these
    // for cohort routing without needing JSONB extracts.
    //
    // Populated when `CompleteTrace.deployment_profile` is `Some` —
    // i.e., 2.7.9 traces (where the block is required-on-wire) and
    // any future 2.7.0 trace that opts in (the cross-shape rule
    // ignores the block from the *canonical*, not from the column
    // copy — copying it lets lens query 2.7.0+block traffic uniformly
    // even though canonical bytes don't include it). All `None` for
    // 2.7.0 traces with no block.
    /// Agent persona role declared by the trace's deployment_profile.
    pub agent_role: Option<String>,
    /// Agent code template ID declared by the trace's deployment_profile.
    pub agent_template: Option<String>,
    /// Deployment domain (`healthcare` / `legal` / ...) declared by
    /// the trace's deployment_profile.
    pub deployment_domain: Option<String>,
    /// Deployment lifecycle stage (`production` / `staging` / ...)
    /// declared by the trace's deployment_profile.
    pub deployment_type: Option<String>,
    /// ISO-3166-1 alpha-2, `global`, or null (not disclosed) declared
    /// by the trace's deployment_profile.
    pub deployment_region: Option<String>,
    /// Federation participation intent (`sovereign` / `limited_trust` /
    /// `federated_peer`) declared by the trace's deployment_profile.
    pub deployment_trust_mode: Option<String>,

    // ─── v0.1.3 scrub envelope columns (FSD §3.7; THREAT_MODEL.md
    // AV-24/25). Always populated on rows produced by the v0.1.3+
    // pipeline; pre-v0.1.3 rows have these as None.
    /// sha256 of canonical(component.data_pre_scrub) — proves what
    /// the scrubber input was without retaining the original bytes.
    pub original_content_hash: Option<String>,
    /// base64(ed25519_sign(canonical(component.data_post_scrub))) —
    /// cryptographic proof that *this deployment* processed *this
    /// payload* at *this time*, verifiable by any peer with the
    /// deployment's published public key.
    pub scrub_signature: Option<String>,
    /// The deployment's signing-key id (lens-scrub-v1, etc.). Same
    /// key as the agent's wire-format §8 key on Phase 2+
    /// deployments — single-key principle.
    pub scrub_key_id: Option<String>,
    /// When the scrub+sign happened. Bounds the window between the
    /// trace's `completed_at` and lens handling.
    pub scrub_timestamp: Option<chrono::DateTime<chrono::Utc>>,

    // ─── v32.0.0 (CIRISPersist#690) scrub TREATMENT columns.
    //
    // These are not decoration beside the envelope — they are INSIDE its
    // signature preimage, so a verifier that cannot read them cannot rebuild
    // the preimage and cannot check `scrub_signature` at all.
    //
    // That is not hypothetical. #690 widened the preimage from
    // `canonical(post_scrub)` to the whole envelope, and shipped without these
    // columns: the signature was covering three values that were stored
    // NOWHERE. It verified at signing time and was unverifiable by anyone,
    // forever after, which is strictly worse than the ambiguity it set out to
    // fix. Caught by the AV-24 round-trip witness, which is the only test that
    // rebuilds the preimage from a STORED row rather than from the in-memory
    // envelope it was just handed.
    //
    // Rule this encodes: **every field in a signature preimage must be
    // recoverable from what is persisted.** The preserve set must equal the
    // verified set.
    /// **Did a named-entity pass actually run?** `None` on pre-v32.0.0 rows,
    /// whose signatures cover the older, narrower preimage.
    pub scrub_ner_ran: Option<bool>,
    /// The trace level the content was actually TREATED at, which may be a
    /// downgrade from the level the trace is labelled with.
    pub scrub_applied_trace_level: Option<String>,
    /// Digest of the NER model that ran; `None` when no pass happened.
    ///
    /// Nullable for two DIFFERENT reasons that a verifier must not conflate: a
    /// pre-v32.0.0 row (no claim was ever made) and a v32.0.0 row that honestly
    /// ran no model. `scrub_ner_ran` is what separates them — it is `None` only
    /// in the first case.
    pub scrub_model_digest: Option<String>,

    // ─── v4.0 cohort_scope columns (CIRISPersist#160, V060, FSD §4.3
    // / §12.0 item 1). The CEG visibility/routing axis the producer's
    // policy formed for the trace; persist RECORDS it (MISSION §1.7)
    // and the §4.3 read-gate filters on (cohort_scope, cohort_target_id).
    /// The producer-declared cohort_scope. Closed-set values `self |
    /// family | community | affiliations | species | biosphere |
    /// federation`. Defaults to `'federation'` when the producer omits
    /// it on the wire (today: every producer) — matching the V060
    /// column DEFAULT and the pre-v4.0 federation-visible behavior.
    pub cohort_scope: String,
    /// The scope **target** (FSD §4.3): the `family_id` / `community_id`
    /// the producer policy routed this trace to, or — for `self` — the
    /// owner identity the substrate resolved from the verified signer
    /// at ingest (`scrub_key_id` → identity, FSD §4.4). `None` for the
    /// broad belonging-tiers (`affiliations` / `species` / `biosphere`
    /// / `federation`).
    pub cohort_target_id: Option<String>,

    // ─── v7.2.0 per-trace ML-DSA-65 hybrid columns (CIRISPersist#225,
    // V083). The producer's post-quantum half of the per-trace envelope
    // signature — the trace-tier hybrid hard cut against HNDL
    // forge-later. Mirrors the federation key split
    // (`scrub_signature_classical` + `scrub_signature_pqc`,
    // KeyRecord/V004). All NULLABLE: classical pre-#225 rows + the
    // `2.7.legacy` pre-verified carve-out write `None`; presence for
    // new Full-mode writes is enforced by the ingest gate, not a column
    // constraint.
    /// Base64 (standard) ML-DSA-65 producer signature over the SAME
    /// canonical bytes the Ed25519 [`signature`](Self::signature)
    /// covers. `verify_hybrid` binds it to the classical sig (it signs
    /// `canonical || classical`). `None` = classical-only row (legacy /
    /// pre-#225 / pre-verified carve-out).
    pub signature_ml_dsa_65: Option<String>,
    /// Base64 (standard) producer ML-DSA-65 public key (1952 raw
    /// bytes), asserted on the trace envelope. The Ed25519 pubkey is
    /// resolved from `accord_public_keys` by `signing_key_id`; that
    /// directory is Ed25519-only, so the PQC pubkey rides the envelope
    /// and is bound into the hybrid verify.
    pub pubkey_ml_dsa_65: Option<String>,
    /// The producer's ML-DSA-65 key identifier (provenance; may differ
    /// from the Ed25519 `signing_key_id`).
    pub pqc_key_id: Option<String>,
}

/// A row landing on `cirislens.trace_llm_calls`
/// (`context/lens_027_trace_events.sql` lines 58-103).
///
/// Phase 1: produced for every `LLM_CALL` component
/// (TRACE_WIRE_FORMAT.md §5.10). Linked to its parent `trace_events`
/// row via `parent_event_id` once the parent insert returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceLlmCallRow {
    /// Trace this LLM call belongs to.
    pub trace_id: String,
    /// Thought-iteration this call happened inside.
    pub thought_id: String,
    /// Originating task, if any.
    pub task_id: Option<String>,

    /// FK to `trace_events.event_id` once the parent insert returns
    /// the row's PK. `None` until the parent is persisted.
    pub parent_event_id: Option<i64>,
    /// Event type of the parent reasoning event that triggered this
    /// LLM call.
    pub parent_event_type: ReasoningEventType,
    /// `attempt_index` of the parent event (used for FK uniqueness).
    pub parent_attempt_index: u32,

    /// Monotonic per `(thought_id, parent_event_id)`; for our purposes
    /// the same as `LlmCallSummary.attempt_index`.
    pub attempt_index: u32,

    /// Wall-clock when the LLM call started.
    pub ts: DateTime<Utc>,

    /// Round-trip duration in milliseconds.
    pub duration_ms: f64,
    /// Agent handler that issued the call (debug / aggregation).
    pub handler_name: String,
    /// Logical service name (e.g. "openai", "anthropic").
    pub service_name: String,

    /// Model identifier reported by the provider.
    pub model: Option<String>,
    /// Provider base URL, if non-default.
    pub base_url: Option<String>,
    /// Provider's response_model identifier when present.
    pub response_model: Option<String>,

    /// Prompt-side token count.
    pub prompt_tokens: Option<i32>,
    /// Completion-side token count.
    pub completion_tokens: Option<i32>,
    /// Prompt byte length (UTF-8).
    pub prompt_bytes: Option<i32>,
    /// Completion byte length (UTF-8).
    pub completion_bytes: Option<i32>,
    /// USD cost of the call as reported by the provider.
    pub cost_usd: Option<f64>,

    /// Outcome of the call (ok / timeout / rate_limited / etc.).
    pub status: LlmCallStatus,
    /// Provider-specific error class on failure.
    pub error_class: Option<String>,
    /// Total attempt count across retries.
    pub attempt_count: Option<i32>,
    /// Number of retries that fired.
    pub retry_count: Option<i32>,

    /// SHA-256 of the prompt content (de-dup / aggregation key).
    pub prompt_hash: Option<String>,
    /// FULL trace-level only.
    pub prompt: Option<String>,
    /// FULL trace-level only.
    pub response_text: Option<String>,
}

/// v0.3.5 (CIRISLens#8 ASK 1) — Result of `Engine.delete_traces_for_agent`.
/// Counts every row removed by the GDPR Article 17 / DSAR primitive
/// across persist's substrate tables. Lens consumes this for its own
/// DSAR audit ledger; persist returns the row counts, lens records
/// the request envelope + signature.
///
/// Federation-key counts are zero unless `include_federation_key=true`
/// was passed. When set, the agent's federation_keys row(s) are
/// removed AND FK-cascade rows in federation_attestations +
/// federation_revocations are removed too — required for FK integrity
/// since persist's federation FKs are not ON DELETE CASCADE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeleteSummary {
    /// Rows removed from `cirislens.trace_events`.
    pub trace_events_deleted: u64,
    /// Rows removed from `cirislens.trace_llm_calls` (joined by
    /// trace_id from the deleted trace_events set).
    pub trace_llm_calls_deleted: u64,
    /// Rows removed from `cirislens.federation_keys`. Always 0 unless
    /// `include_federation_key=true`. May be >1 if the agent rotated
    /// keys (multiple federation_keys rows with
    /// `identity_type='agent'` + `identity_ref=<agent_id_hash>`).
    pub federation_keys_deleted: u64,
    /// FK-cascade: rows removed from `cirislens.federation_attestations`
    /// where the agent's key was attesting_key_id, attested_key_id,
    /// or scrub_key_id. Always 0 unless `include_federation_key=true`.
    pub federation_attestations_deleted: u64,
    /// FK-cascade: rows removed from `cirislens.federation_revocations`
    /// referencing the agent's key. Always 0 unless
    /// `include_federation_key=true`.
    pub federation_revocations_deleted: u64,
    /// Wall-clock when the delete transaction committed.
    pub deleted_at: chrono::DateTime<chrono::Utc>,
}

/// v7.0.0 (CIRISPersist#222) — Result of
/// [`Engine::delete_traces_for_agent_id_hash`](crate::Engine::delete_traces_for_agent_id_hash)
/// — the GDPR Art. 17 / DSAR full-erasure primitive.
///
/// Unlike [`DeleteSummary`] (the per-signing-key DSAR primitive), this
/// erases the agent's ENTIRE trace corpus across ALL signing keys, and
/// cascades to the derived `detection_events` by **tombstoning** (not
/// deleting): the detection analytics are substrate-derived, not the
/// subject's personal data, so the PII linkage (`trace_id`,
/// `body_sha256`, `canonical_bytes`) is NULLed and an `erased_at` marker
/// stamped, while the detector/severity/cohort_cell rows survive.
///
/// All three operations — the two hard deletes, the tombstone update, and
/// the `hard_case:trace_erasure` audit emit — happen in a single
/// transaction. **Idempotent**: a second call finds no rows and returns
/// all-zero counts (`Ok`, never an error — a not-found is not an error
/// for erasure).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ErasureSummary {
    /// Rows hard-deleted from `cirislens.trace_events` (every row where
    /// `agent_id_hash` matches, across all signing keys).
    pub trace_events: u64,
    /// Rows hard-deleted from `cirislens.trace_llm_calls` (joined by
    /// `trace_id` from the erased trace_events set — V001 LLM call rows
    /// carry no `agent_id_hash`).
    pub trace_llm_calls: u64,
    /// Rows TOMBSTONED in `cirislens_derived.detection_events` — derived
    /// from the erased agent's traces (matched by `trace_id`), with the
    /// PII linkage NULLed and `erased_at` stamped. NOT hard-deleted.
    /// Always 0 on the memory backend (no derived-schema storage) and on
    /// backends with no detection rows for the agent.
    pub detection_events_tombstoned: u64,
    /// Wall-clock when the erasure transaction committed.
    pub erased_at: chrono::DateTime<chrono::Utc>,
}

/// Phase 2 stub — agent audit-log entry shape (FSD §4.1).
///
/// Carried as a placeholder type so the Backend trait surface can
/// reference it from Phase 1; full impl + DAO migration in Phase 2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic per-agent audit sequence number.
    pub sequence_number: i64,
    /// Hash chain link — sha256 of the previous entry.
    pub previous_hash: String,
    /// sha256 of this entry's canonical payload.
    pub entry_hash: String,
    /// Ed25519 signature over `entry_hash`.
    pub signature: String,
    /// Signing-key id (looked up via `accord_public_keys`).
    pub signing_key_id: String,
    /// Wall-clock when the entry was minted.
    pub timestamp: DateTime<Utc>,
    /// Audit event type (string-keyed for forward compatibility).
    pub event_type: String,
    /// Operator-readable summary of the event.
    pub event_summary: String,
    /// Agent identifier emitting the entry.
    pub agent_id: String,
    /// JSONB payload — the audit event's full data dict.
    pub payload: serde_json::Value,
}

/// Phase 2 stub — service correlation shape (FSD §4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceCorrelation {
    /// Correlation identifier (UUID-shaped).
    pub correlation_id: String,
    /// Service type the correlation belongs to.
    pub service_type: String,
    /// Correlation kind — RPC, queue handoff, etc.
    pub correlation_type: String,
    /// Wall-clock of the correlation.
    pub timestamp: DateTime<Utc>,
    /// Agent identifier.
    pub agent_id: String,
    /// JSONB payload with the correlation's full data dict.
    pub payload: serde_json::Value,
}

/// Phase 3 stub — task shape (FSD §5.1).
///
/// Mission constraint: multi-occurrence semantics preserved verbatim
/// (FSD §5.6) — `agent_occurrence_id` namespace and `try_claim_shared_task`
/// race-claim are first-class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// Task identifier (stable across occurrences).
    pub task_id: String,
    /// Agent occurrence identifier; namespaces tasks per-agent.
    pub agent_occurrence_id: String,
    /// Channel the task was created on.
    pub channel_id: String,
    /// Operator-readable task description.
    pub description: String,
    /// Task status (pending / claimed / completed / failed / etc.).
    pub status: String,
    /// Numeric priority (lower = higher priority).
    pub priority: u8,
    /// When the task was created.
    pub created_at: DateTime<Utc>,
    /// When the task was last updated.
    pub updated_at: DateTime<Utc>,
    /// Task-type tag for routing / filtering.
    pub task_type: Option<String>,
    /// Identifier of the agent that signed this task (FSD §5.1
    /// signed-task primitive).
    pub signed_by: Option<String>,
    /// Ed25519 signature over the canonical task payload.
    pub signature: Option<String>,
    /// When the signature was issued.
    pub signed_at: Option<DateTime<Utc>>,
}

/// Phase 3 stub — graph node shape (FSD §5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    /// Node identifier.
    pub node_id: String,
    /// Node type tag.
    pub node_type: String,
    /// Scope namespace (per-agent, per-deployment, etc.).
    pub scope: String,
    /// Agent occurrence identifier.
    pub agent_occurrence_id: String,
    /// JSONB attributes blob.
    pub attributes_json: serde_json::Value,
    /// When the node was created.
    pub created_at: DateTime<Utc>,
    /// When the node was last updated.
    pub updated_at: DateTime<Utc>,
    /// Optimistic-concurrency version counter.
    pub version: i32,
}

/// Phase 3 stub — `try_claim_shared_task` parameter group
/// (FSD §5.6 — multi-occurrence atomicity primitive).
#[derive(Debug, Clone)]
pub struct ClaimParams<'a> {
    /// Task-type to claim.
    pub task_type: &'a str,
    /// Occurrence identifier requesting the claim.
    pub occurrence_id: &'a str,
    /// Channel scope of the claim.
    pub channel_id: &'a str,
    /// Description of the claimed task (used when creating).
    pub description: &'a str,
    /// Numeric priority of the claim.
    pub priority: u8,
    /// Wall-clock at the moment of claim.
    pub now: DateTime<Utc>,
}

/// v4.7.0 (CIRISPersist#177) — typed outcome of registering an
/// `accord_public_keys` pubkey (the agent's boot-time signing-key
/// registration). Replaces the string-matchable exception consumers
/// reverse-engineered (`str(exc).lower()` for "already"/"exists"/
/// "conflict"). A rotation collision is a **normal return value, not an
/// error**, so the idempotent boot path stays non-throwing; per CEG §0.0
/// the substrate authors the trust-relevant signal and the consumer
/// surfaces it without parsing exception strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRegistrationOutcome {
    /// Newly inserted — no prior row for this `key_id`.
    Registered,
    /// Idempotent match — the `key_id` already maps to the **same**
    /// pubkey. The expected steady-state on every reboot.
    AlreadyRegistered,
    /// The `key_id` already maps to a **different** pubkey — a key
    /// rotation / potential-compromise signal the consumer MUST surface
    /// (CIRISAgent#809). Carries a stable fingerprint of the *existing*
    /// (stored) key so the consumer can log/compare without handling raw
    /// key material.
    RotationCollision {
        /// SHA-256 (hex) of the stored `public_key_base64`.
        existing_key_fingerprint: String,
    },
}

impl KeyRegistrationOutcome {
    /// Stable discriminator token for the PyO3 dict / logs / metrics.
    pub fn status(&self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::AlreadyRegistered => "already_registered",
            Self::RotationCollision { .. } => "rotation_collision",
        }
    }
}

/// SHA-256 (hex) of a stored pubkey base64 — the stable fingerprint
/// carried on [`KeyRegistrationOutcome::RotationCollision`].
pub fn accord_key_fingerprint(public_key_base64: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(public_key_base64.as_bytes()))
}

/// Classify a registration attempt from the `INSERT … ON CONFLICT DO
/// NOTHING` result plus any pre-existing row, read back on the same
/// connection. Pure (no IO) so backends share one definition and it is
/// exhaustively unit-testable.
///
/// - `inserted` — the insert affected a row (no prior `key_id`).
/// - `existing_public_key_base64` — the stored pubkey when the insert
///   was a no-op (conflict), else `None`.
///
/// The `inserted == false && existing == None` case is a benign TOCTOU
/// (the conflicting row was deleted between insert and read on an
/// otherwise append-only table); we report [`AlreadyRegistered`] rather
/// than fabricate a [`RotationCollision`] — never raise a false rotation
/// alarm.
///
/// [`AlreadyRegistered`]: KeyRegistrationOutcome::AlreadyRegistered
/// [`RotationCollision`]: KeyRegistrationOutcome::RotationCollision
pub fn classify_key_registration(
    inserted: bool,
    existing_public_key_base64: Option<&str>,
    new_public_key_base64: &str,
) -> KeyRegistrationOutcome {
    if inserted {
        return KeyRegistrationOutcome::Registered;
    }
    match existing_public_key_base64 {
        Some(existing) if existing == new_public_key_base64 => {
            KeyRegistrationOutcome::AlreadyRegistered
        }
        Some(existing) => KeyRegistrationOutcome::RotationCollision {
            existing_key_fingerprint: accord_key_fingerprint(existing),
        },
        None => KeyRegistrationOutcome::AlreadyRegistered,
    }
}

#[cfg(test)]
mod keyreg_tests {
    use super::*;

    #[test]
    fn classify_new_insert_is_registered() {
        assert_eq!(
            classify_key_registration(true, None, "pubA"),
            KeyRegistrationOutcome::Registered
        );
    }

    #[test]
    fn classify_conflict_same_pubkey_is_already_registered() {
        assert_eq!(
            classify_key_registration(false, Some("pubA"), "pubA"),
            KeyRegistrationOutcome::AlreadyRegistered
        );
    }

    #[test]
    fn classify_conflict_different_pubkey_is_rotation_collision() {
        let out = classify_key_registration(false, Some("pubOLD"), "pubNEW");
        match out {
            KeyRegistrationOutcome::RotationCollision {
                existing_key_fingerprint,
            } => {
                assert_eq!(existing_key_fingerprint, accord_key_fingerprint("pubOLD"));
                assert_eq!(existing_key_fingerprint.len(), 64, "sha256 hex");
            }
            other => panic!("expected RotationCollision, got {other:?}"),
        }
    }

    #[test]
    fn classify_conflict_vanished_row_is_benign_not_false_collision() {
        // TOCTOU: never fabricate a rotation alarm.
        assert_eq!(
            classify_key_registration(false, None, "pubA"),
            KeyRegistrationOutcome::AlreadyRegistered
        );
    }

    #[test]
    fn status_tokens_are_stable() {
        assert_eq!(KeyRegistrationOutcome::Registered.status(), "registered");
        assert_eq!(
            KeyRegistrationOutcome::AlreadyRegistered.status(),
            "already_registered"
        );
        assert_eq!(
            KeyRegistrationOutcome::RotationCollision {
                existing_key_fingerprint: "x".into()
            }
            .status(),
            "rotation_collision"
        );
    }
}
