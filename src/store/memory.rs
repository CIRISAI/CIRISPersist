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
        // v0.2.1 — dual-read migration matching postgres + sqlite.
        // federation_keys first; fall back to legacy `keys` map.
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let state = self.state.lock().expect("memory backend lock");
        if let Some(rec) = state.federation_keys.get(key_id) {
            // valid_until check (None means no expiry).
            let now = chrono::Utc::now();
            if rec.valid_until.map_or(true, |t| t > now) {
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
                return Ok(Some(key));
            }
        }
        // Fall back to legacy keys map.
        Ok(state.keys.get(key_id).copied())
    }

    async fn run_migrations(&self) -> Result<(), Error> {
        // Memory backend has no schema to migrate.
        Ok(())
    }

    async fn delete_traces_for_agent(
        &self,
        agent_id_hash: &str,
        include_federation_key: bool,
    ) -> Result<super::types::DeleteSummary, Error> {
        let mut state = self.state.lock().expect("memory backend lock");
        // Step 1: collect trace_ids of the agent's events.
        let target_trace_ids: HashSet<String> = state
            .events
            .values()
            .filter(|(_, row)| row.agent_id_hash == agent_id_hash)
            .map(|(_, row)| row.trace_id.clone())
            .collect();

        let trace_events_before = state.events.len();
        state
            .events
            .retain(|_, (_, row)| row.agent_id_hash != agent_id_hash);
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
            let target_key_ids: HashSet<String> = state
                .federation_keys
                .values()
                .filter(|rec| rec.identity_type == "agent" && rec.identity_ref == agent_id_hash)
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
                *eid > after_event_id && agent_id_hash.map_or(true, |h| row.agent_id_hash == h)
            })
            .map(|(eid, row)| (*eid, row.clone()))
            .collect();
        rows.sort_by_key(|(eid, _)| *eid);
        rows.truncate(limit.max(0) as usize);
        Ok(rows)
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

    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
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
            // v0.3.4 deployment_profile columns. Test fixture stays
            // 2.7.0-shape (no profile) — None across the board.
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
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
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
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
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
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
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
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
                revocation: fix_revocation("rev-z", "k-c", "steward", "steward"),
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

    /// v0.3.5 (CIRISLens#8 ASK 1) — DSAR primitive deletes the agent's
    /// trace_events + trace_llm_calls atomically. Returns the row
    /// counts for the lens-side audit ledger. Idempotent.
    #[tokio::test]
    async fn dsar_deletes_trace_data_for_agent() {
        use crate::store::Backend;
        let backend = MemoryBackend::new();
        // Insert traces for two agents; only one is the DSAR target.
        let target_aih = "agent-target-hash";
        let other_aih = "agent-other-hash";
        for (aih, trace_suffix) in &[(target_aih, "t1"), (target_aih, "t2"), (other_aih, "o1")] {
            let row = TraceEventRow {
                trace_id: format!("trace-{trace_suffix}"),
                thought_id: format!("th-{trace_suffix}"),
                task_id: None,
                step_point: None,
                event_type: ReasoningEventType::ThoughtStart,
                attempt_index: 0,
                ts: "2026-04-30T00:00:00Z".parse().unwrap(),
                agent_name: None,
                agent_id_hash: (*aih).to_owned(),
                cognitive_state: None,
                trace_level: TraceLevel::Generic,
                payload: serde_json::Map::new(),
                cost_llm_calls: None,
                cost_tokens: None,
                cost_usd: None,
                signature: "AAAA".into(),
                signing_key_id: "k".into(),
                signature_verified: true,
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
            };
            backend.insert_trace_events_batch(&[row]).await.unwrap();
        }
        // Add an LLM call for the target's trace t1.
        let llm = TraceLlmCallRow {
            trace_id: "trace-t1".into(),
            thought_id: "th-t1".into(),
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
        };
        backend.insert_trace_llm_calls_batch(&[llm]).await.unwrap();

        // First DSAR: deletes the target's 2 events + 1 llm call.
        let summary = backend
            .delete_traces_for_agent(target_aih, false)
            .await
            .unwrap();
        assert_eq!(summary.trace_events_deleted, 2);
        assert_eq!(summary.trace_llm_calls_deleted, 1);
        assert_eq!(summary.federation_keys_deleted, 0);

        // Other agent's row is untouched.
        let remaining = backend.snapshot_events();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].agent_id_hash, other_aih);

        // Idempotent: re-invocation returns all-zero.
        let summary2 = backend
            .delete_traces_for_agent(target_aih, false)
            .await
            .unwrap();
        assert_eq!(summary2.trace_events_deleted, 0);
        assert_eq!(summary2.trace_llm_calls_deleted, 0);
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
