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

/// In-memory backend.
///
/// Locks: a single `Mutex` guards all state. This is fine for tests
/// (no contention); a real concurrent backend uses per-table locks
/// or, more typically, the SQL DB's own MVCC.
pub struct MemoryBackend {
    state: Mutex<State>,
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
    /// v0.2.0 — Federation `federation_attestations` rows,
    /// append-only.
    federation_attestations: Vec<crate::federation::Attestation>,
    /// v0.2.0 — Federation `federation_revocations` rows,
    /// append-only.
    federation_revocations: Vec<crate::federation::Revocation>,
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
                federation_revocations: Vec::new(),
            }),
        }
    }
}

impl MemoryBackend {
    /// Create an empty memory backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a public key. For test fixtures.
    pub fn add_public_key(&self, key_id: &str, key: VerifyingKey) {
        let mut state = self.state.lock().expect("memory backend lock");
        state.keys.insert(key_id.to_owned(), key);
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
        let state = self.state.lock().expect("memory backend lock");
        Ok(state.keys.get(key_id).copied())
    }

    async fn run_migrations(&self) -> Result<(), Error> {
        // Memory backend has no schema to migrate.
        Ok(())
    }
}

// ─── FederationDirectory impl (v0.2.0) ─────────────────────────────
//
// In-process maps mirror the postgres tables. No FK enforcement
// (postgres + sqlite enforce; tests against the memory backend run
// against the same logical contract via the `FederationDirectory`
// trait). `persist_row_hash` is computed on every put per the
// architectural contract — consumers see the canonical hash even
// against the in-memory backend.

impl crate::federation::FederationDirectory for MemoryBackend {
    async fn put_public_key(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let mut row = record.record;
        // Server-computed hash (excludes the field itself).
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
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
        state.federation_keys.insert(row.key_id.clone(), row);
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

    async fn put_attestation(
        &self,
        attestation: crate::federation::SignedAttestation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = attestation.attestation;
        let mut state = self.state.lock().expect("memory backend lock");
        // FK enforcement parity with postgres: both attesting_key_id
        // and attested_key_id must exist in federation_keys.
        if !state.federation_keys.contains_key(&row.attesting_key_id) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "attesting_key_id {} does not exist in federation_keys",
                row.attesting_key_id
            )));
        }
        if !state.federation_keys.contains_key(&row.attested_key_id) {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "attested_key_id {} does not exist in federation_keys",
                row.attested_key_id
            )));
        }
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        state.federation_attestations.push(row);
        Ok(())
    }

    async fn list_attestations_for(
        &self,
        attested_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| a.attested_key_id == attested_key_id)
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
        let state = self.state.lock().expect("memory backend lock");
        let mut rows: Vec<_> = state
            .federation_attestations
            .iter()
            .filter(|a| a.attesting_key_id == attesting_key_id)
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
            schema_version: "2.7.0".into(),
            pii_scrubbed: false,
            // FSD §3.7 envelope columns: tests for the in-memory
            // dedup / idempotency surface use None — pipeline tests
            // populate them.
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
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
                },
            ],
            signature: "AAAA".into(),
            signature_key_id: "ciris-agent-key:dead".into(),
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

    /// Phase 2/3 surfaces return `NotImplemented`, not panic
    /// (MISSION.md §3 anti-pattern #4).
    #[tokio::test]
    async fn phase_2_surfaces_return_not_implemented() {
        let backend = MemoryBackend::new();
        let entry = super::super::types::AuditEntry {
            sequence_number: 1,
            previous_hash: "00".into(),
            entry_hash: "01".into(),
            signature: "AAAA".into(),
            signing_key_id: "k".into(),
            timestamp: "2026-04-30T00:00:00Z".parse().unwrap(),
            event_type: "test".into(),
            event_summary: "test".into(),
            agent_id: "agent".into(),
            payload: serde_json::Value::Null,
        };
        let err = backend.append_audit_entry(&entry).await.unwrap_err();
        assert!(matches!(err, Error::NotImplemented(_)));
    }

    // ─── FederationDirectory tests ─────────────────────────────────

    use crate::federation::{
        Attestation, FederationDirectory, KeyRecord, Revocation, SignedAttestation,
        SignedKeyRecord, SignedRevocation,
    };

    fn fix_key(key_id: &str, identity_ref: &str, scrub_key_id: &str) -> KeyRecord {
        KeyRecord {
            key_id: key_id.into(),
            pubkey_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            algorithm: crate::federation::types::algorithm::ED25519.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: identity_ref.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature: "c2lnbmF0dXJl".into(),
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            persist_row_hash: String::new(),
        }
    }

    fn fix_attestation(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
    ) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: crate::federation::types::attestation_type::VOUCHES_FOR.into(),
            weight: Some(1.0),
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            attestation_envelope: serde_json::json!({"id": id}),
            original_content_hash: "abc123".into(),
            scrub_signature: "c2ln".into(),
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            persist_row_hash: String::new(),
        }
    }

    fn fix_revocation(id: &str, revoked: &str, revoking: &str, scrub_key_id: &str) -> Revocation {
        Revocation {
            revocation_id: id.into(),
            revoked_key_id: revoked.into(),
            revoking_key_id: revoking.into(),
            reason: Some("test".into()),
            revoked_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            effective_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            revocation_envelope: serde_json::json!({"id": id}),
            original_content_hash: "abc123".into(),
            scrub_signature: "c2ln".into(),
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            persist_row_hash: String::new(),
        }
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

    #[tokio::test]
    async fn put_attestation_requires_both_keys_exist() {
        let backend = MemoryBackend::new();
        // Neither key exists yet — should fail with InvalidArgument.
        let att = fix_attestation("a-1", "registry-steward", "primitive-a", "registry-steward");
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));

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
}
