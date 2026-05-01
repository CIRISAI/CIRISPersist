//! Ingest pipeline — the public entry point the lens (and Phase 2 the
//! agent) call.
//!
//! # Mission alignment
//!
//! This module composes every layer of the FSD §3.3 pipeline:
//!
//! ```text
//! bytes → schema parse → verify → scrub → decompose → backend insert → BatchSummary
//! ```
//!
//! Each step is a typed boundary. Failure at any step short-circuits
//! with a typed [`IngestError`] variant; the lens turns that into the
//! structured 422 / 401 / 429 / 500 response the wire-format spec
//! (TRACE_WIRE_FORMAT.md §1) requires.
//!
//! Mission constraint (MISSION.md §3 anti-pattern #2): verify-before-
//! persist. Mission constraint (anti-pattern #7): every test asserts
//! a *mission-aligned outcome*, not just absence of error.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::HardwareSigner;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::{BatchEnvelope, BatchEvent, CompleteTrace, Error as SchemaError};
use crate::scrub::{ScrubError, Scrubber};
use crate::store::{Backend, Error as StoreError, InsertReport};
use crate::verify::{canonical::Canonicalizer, ed25519::verify_trace, Error as VerifyError};

/// What the ingest pipeline did with one `events[]` body.
///
/// Mission constraint (MISSION.md §3 anti-pattern #7): a successful
/// ingest reports concrete numbers, not a bare `Ok(())`. The lens
/// surfaces these to its operations dashboard so a deployment-time
/// regression (e.g. a per-event drop) is visible immediately.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Count of `events[]` envelope items processed (each may be a
    /// CompleteTrace with N components).
    pub envelopes_processed: usize,
    /// Count of `trace_events` rows that landed (excluding ON
    /// CONFLICT skips).
    pub trace_events_inserted: usize,
    /// Count of `trace_events` ON CONFLICT skips.
    pub trace_events_conflicted: usize,
    /// Count of `trace_llm_calls` rows that landed.
    pub trace_llm_calls_inserted: usize,
    /// Number of fields the scrubber modified (for telemetry).
    pub scrubbed_fields: usize,
    /// Number of CompleteTrace envelopes whose signature verified.
    pub signatures_verified: usize,
}

/// Errors the ingest pipeline can return.
///
/// Mission constraint (MISSION.md §3 anti-pattern #4): typed errors
/// per layer. Each variant maps to a specific lens HTTP response shape.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// Schema-layer failure (malformed JSON, schema-version mismatch,
    /// unknown trace_level, missing required field). Lens → HTTP 422.
    #[error("schema: {0}")]
    Schema(#[from] SchemaError),

    /// Verify-layer failure (signature mismatch, unknown key,
    /// malformed signature). Lens → HTTP 401 (signature) or 422
    /// (malformed).
    #[error("verify: {0}")]
    Verify(#[from] VerifyError),

    /// Scrubber failure. Lens → HTTP 500 (scrubber bug) or 422
    /// (scrubber rejected schema-altering result).
    #[error("scrub: {0}")]
    Scrub(#[from] ScrubError),

    /// Backend write failure (DB unreachable, IO, etc.). Lens → HTTP
    /// 503 + Retry-After (the lens's bounded-queue layer also kicks
    /// in here for the journal-replay path; FSD §3.4 #2).
    #[error("store: {0}")]
    Store(#[from] StoreError),

    /// THREAT_MODEL.md AV-24/25: ciris-keyring sign failure during
    /// step 3.5. Hardware-backed signers can fail (TPM unavailable,
    /// keyring locked, etc.); software fallback can fail (key file
    /// IO error, etc.). Either way, refuse to persist — the FSD
    /// §3.4 #7 contract is "every row signed."
    #[error("sign: {0}")]
    Sign(String),
}

impl IngestError {
    /// Stable string-token identifying the error variant.
    /// THREAT_MODEL.md AV-15: HTTP / PyO3 sanitization. The verbose
    /// `Display` form goes to tracing logs only; the kind is what
    /// the lens surfaces in HTTP error bodies.
    pub fn kind(&self) -> &'static str {
        match self {
            IngestError::Schema(e) => e.kind(),
            IngestError::Verify(e) => e.kind(),
            IngestError::Scrub(e) => e.kind(),
            IngestError::Store(e) => e.kind(),
            IngestError::Sign(_) => "sign_keyring",
        }
    }
}

/// Per-component scrub envelope produced by step 3.5.
///
/// THREAT_MODEL.md AV-24: cryptographic proof that *this deployment*
/// processed *this payload* at *this time*. Same shape as the four
/// columns on `trace_events` (FSD §3.7). Carried alongside the
/// component during decompose so the row writer doesn't need to
/// re-sign.
#[derive(Debug, Clone)]
pub struct ScrubEnvelope {
    pub original_content_hash: String,
    pub scrub_signature: String,
    pub scrub_key_id: String,
    pub scrub_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Composition of dependencies for one ingest call.
///
/// Mission constraint (MISSION.md §2 — `store/`, `verify/`, `scrub/`):
/// each is a trait, each is injected here. Different deployment
/// shapes (lens server, agent in-process, iOS bundled) compose the
/// same pipeline with different impls.
///
/// The Backend doubles as the public-key directory (its
/// `lookup_public_key` async method is the only path) — mission
/// constraint (MISSION.md §3 anti-pattern #3): one path for key
/// lookup; the lens has no side-channel that bypasses the
/// persistence-layer key directory.
pub struct IngestPipeline<'a, B, C, S>
where
    B: Backend + ?Sized,
    C: Canonicalizer + ?Sized,
    S: Scrubber + ?Sized,
{
    pub backend: &'a B,
    pub canonicalizer: &'a C,
    pub scrubber: &'a S,
    /// v0.1.3: scrub-signing key. UNCONDITIONAL — always present,
    /// every row signed (FSD §3.4 robustness primitive #7;
    /// THREAT_MODEL.md AV-24). Use ciris-keyring's
    /// `get_platform_signer(alias)` for production (hardware-backed
    /// where available); `Ed25519SoftwareSigner` for tests.
    pub signer: &'a dyn HardwareSigner,
    /// Stable identifier for the signer (matches what the deployment
    /// publishes to the registry). Carried into the scrub_key_id
    /// column on every row.
    pub signer_key_id: &'a str,
}

impl<'a, B, C, S> IngestPipeline<'a, B, C, S>
where
    B: Backend + ?Sized,
    C: Canonicalizer + ?Sized,
    S: Scrubber + ?Sized,
{
    /// Run the FSD §3.3 pipeline over a raw HTTP body.
    ///
    /// Step ordering is load-bearing — schema first (fail fast on
    /// malformed input), verify second (no mutation before
    /// authenticity gate), scrub third (verify is over the
    /// agent-shipped bytes; scrub mutates after), decompose fourth,
    /// store last.
    pub async fn receive_and_persist(&self, bytes: &[u8]) -> Result<BatchSummary, IngestError> {
        // 1. Schema parse — typed envelope. Schema-version gate fires
        //    here.
        let mut env = BatchEnvelope::from_json(bytes)?;

        // 2. Verify each CompleteTrace signature. Mission constraint
        //    (MISSION.md §3 anti-pattern #2): verify before any
        //    mutation; verification is over the agent-shipped bytes.
        let mut signatures_verified = 0usize;
        for event in &env.events {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    self.verify_complete_trace(trace).await?;
                    signatures_verified += 1;
                }
            }
        }

        // 3. Capture pre-scrub canonical bytes for every component.
        //    FSD §3.3 step 3.5: original_content_hash is sha256 of
        //    canonical(component.data_pre_scrub) — must be computed
        //    BEFORE scrub mutates `data`. One Vec<u8>-per-component
        //    held briefly; dropped after step 3.5.
        let pre_scrub_hashes = self.compute_pre_scrub_hashes(&env)?;

        // 4. Scrub. By the time we get here every signature has been
        //    accepted, so we know the bytes are real agent testimony.
        let scrubbed_fields = self.scrubber.scrub_batch(&mut env)?;

        // 5. Step 3.5 — sign per-component scrub envelope. UNCONDITIONAL
        //    (FSD §3.3 step 3.5; §3.4 robustness primitive #7).
        //    Same key signs every component on every trace level.
        let envelopes = self.sign_scrub_envelopes(&env, &pre_scrub_hashes).await?;

        // 6. Decompose each CompleteTrace into row-shaped writes.
        //    Envelope columns get attached to each row by index.
        let mut events_to_insert = Vec::new();
        let mut llm_calls_to_insert = Vec::new();
        let mut env_idx = 0usize;
        for event in &env.events {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    let mut d = crate::store::decompose(trace).map_err(IngestError::Store)?;
                    for row in &mut d.events {
                        let env_for_row = &envelopes[env_idx];
                        row.original_content_hash = Some(env_for_row.original_content_hash.clone());
                        row.scrub_signature = Some(env_for_row.scrub_signature.clone());
                        row.scrub_key_id = Some(env_for_row.scrub_key_id.clone());
                        row.scrub_timestamp = Some(env_for_row.scrub_timestamp);
                        env_idx += 1;
                    }
                    events_to_insert.extend(d.events);
                    llm_calls_to_insert.extend(d.llm_calls);
                }
            }
        }
        debug_assert_eq!(env_idx, envelopes.len(), "envelope index drift");

        // 5. Insert. Postgres ON CONFLICT DO NOTHING handles
        //    idempotency at the dedup index (FSD §3.4 #4).
        let event_report: InsertReport = self
            .backend
            .insert_trace_events_batch(&events_to_insert)
            .await
            .map_err(IngestError::Store)?;

        let llm_inserted = self
            .backend
            .insert_trace_llm_calls_batch(&llm_calls_to_insert)
            .await
            .map_err(IngestError::Store)?;

        Ok(BatchSummary {
            envelopes_processed: env.events.len(),
            trace_events_inserted: event_report.inserted,
            trace_events_conflicted: event_report.conflicted,
            trace_llm_calls_inserted: llm_inserted,
            scrubbed_fields,
            signatures_verified,
        })
    }

    /// Compute pre-scrub `original_content_hash` for every component
    /// across every CompleteTrace in the batch. Order is flat:
    /// envelopes[i] corresponds to the i-th component in document
    /// order across all events.
    ///
    /// Mission alignment (MISSION.md §2 — `verify/`): the hash is
    /// the bridge between the unscrubbed bytes (which we never
    /// retain) and the scrubbed payload that lands in storage. An
    /// auditor with the original content can verify it was the
    /// scrubbing input.
    fn compute_pre_scrub_hashes(&self, env: &BatchEnvelope) -> Result<Vec<String>, IngestError> {
        let mut hashes = Vec::new();
        for event in &env.events {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    for component in &trace.components {
                        let value = serde_json::Value::Object(component.data.clone());
                        let bytes = self
                            .canonicalizer
                            .canonicalize_value(&value)
                            .map_err(IngestError::Verify)?;
                        let mut h = Sha256::new();
                        h.update(&bytes);
                        hashes.push(format!("sha256:{}", hex::encode(h.finalize())));
                    }
                }
            }
        }
        Ok(hashes)
    }

    /// Sign post-scrub canonical bytes per component. Returns one
    /// `ScrubEnvelope` per component, in the same flat order as
    /// `compute_pre_scrub_hashes`. THREAT_MODEL.md AV-24.
    async fn sign_scrub_envelopes(
        &self,
        env: &BatchEnvelope,
        pre_hashes: &[String],
    ) -> Result<Vec<ScrubEnvelope>, IngestError> {
        let now = chrono::Utc::now();
        let key_id = self.signer_key_id.to_owned();
        let mut envelopes = Vec::with_capacity(pre_hashes.len());
        let mut idx = 0usize;
        for event in &env.events {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    for component in &trace.components {
                        let value = serde_json::Value::Object(component.data.clone());
                        let post_bytes = self
                            .canonicalizer
                            .canonicalize_value(&value)
                            .map_err(IngestError::Verify)?;
                        let sig_bytes = self
                            .signer
                            .sign(&post_bytes)
                            .await
                            .map_err(|e| IngestError::Sign(format!("{e}")))?;
                        envelopes.push(ScrubEnvelope {
                            original_content_hash: pre_hashes[idx].clone(),
                            scrub_signature: BASE64.encode(&sig_bytes),
                            scrub_key_id: key_id.clone(),
                            scrub_timestamp: now,
                        });
                        idx += 1;
                    }
                }
            }
        }
        Ok(envelopes)
    }

    async fn verify_complete_trace(&self, trace: &CompleteTrace) -> Result<(), IngestError> {
        let key = self
            .backend
            .lookup_public_key(&trace.signature_key_id)
            .await
            .map_err(IngestError::Store)?
            .ok_or_else(|| {
                IngestError::Verify(VerifyError::UnknownKey(trace.signature_key_id.clone()))
            })?;
        verify_trace(trace, self.canonicalizer, &key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SchemaVersion;
    use crate::scrub::NullScrubber;
    use crate::store::{decompose, MemoryBackend};
    use crate::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a deterministic Ed25519 software signer for tests.
    /// Per the user's "use the direct trait" call: returns
    /// `Box<dyn HardwareSigner>` directly, no wrapper. The seed is
    /// fixed so test runs are reproducible.
    async fn make_test_signer() -> (Box<dyn HardwareSigner>, String) {
        use ciris_keyring::Ed25519SoftwareSigner;
        let key_id = "test-scrub-key-v1".to_owned();
        let mut signer = Ed25519SoftwareSigner::new(&key_id);
        // Deterministic 32-byte seed for reproducibility.
        let seed = [0xA5u8; 32];
        signer
            .import_key(&seed)
            .expect("import_key on Ed25519SoftwareSigner");
        (Box::new(signer) as Box<dyn HardwareSigner>, key_id)
    }

    fn make_signed_batch_bytes() -> (Vec<u8>, String, ed25519_dalek::VerifyingKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let key_id = "ciris-agent-key:test";

        let mut trace = CompleteTrace {
            trace_id: "trace-pipeline-1".into(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![
                crate::schema::TraceComponent {
                    component_type: crate::schema::ComponentType::Observation,
                    event_type: crate::schema::ReasoningEventType::ThoughtStart,
                    timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m
                    },
                },
                crate::schema::TraceComponent {
                    component_type: crate::schema::ComponentType::Action,
                    event_type: crate::schema::ReasoningEventType::ActionResult,
                    timestamp: "2026-04-30T00:16:12.789Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m.insert("audit_sequence_number".into(), 42.into());
                        m.insert("audit_entry_hash".into(), "abcd".into());
                        m.insert("audit_signature".into(), "BBBB".into());
                        m.insert("llm_calls".into(), 0.into());
                        m.insert("tokens_total".into(), 100.into());
                        m.insert("cost_cents".into(), serde_json::json!(0.1));
                        m
                    },
                },
            ],
            signature: String::new(),
            signature_key_id: key_id.into(),
        };
        let payload = canonical_payload_value(&trace);
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let sig = sk.sign(&bytes);
        trace.signature = BASE64.encode(sig.to_bytes());

        let trace_json = serde_json::to_value(&trace).unwrap();
        let envelope = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": trace_json,
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
        });
        (
            envelope.to_string().into_bytes(),
            key_id.to_owned(),
            sk.verifying_key(),
        )
    }

    #[tokio::test]
    async fn happy_path_full_pipeline() {
        // Mission category §4: end-to-end across schema + verify +
        // scrub (null) + decompose + backend (memory). Every layer
        // must succeed with mission-aligned outcome counts.
        let (bytes, key_id, vkey) = make_signed_batch_bytes();
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let summary = pipeline
            .receive_and_persist(&bytes)
            .await
            .expect("happy path must succeed");

        assert_eq!(summary.envelopes_processed, 1);
        assert_eq!(summary.signatures_verified, 1);
        assert_eq!(
            summary.trace_events_inserted, 2,
            "two components → two rows"
        );
        assert_eq!(summary.trace_events_conflicted, 0);
        assert_eq!(summary.trace_llm_calls_inserted, 0);
        assert_eq!(summary.scrubbed_fields, 0);

        // Snapshot: ACTION_RESULT row carries the audit anchor (FSD §3.2).
        let snap = backend.snapshot_events();
        let action = snap
            .iter()
            .find(|e| e.event_type == crate::schema::ReasoningEventType::ActionResult)
            .unwrap();
        assert_eq!(action.cost_llm_calls, Some(0));
        assert_eq!(action.cost_tokens, Some(100));

        // THREAT_MODEL.md AV-24 regression: every row carries a
        // populated scrub envelope. Always present; key never null.
        for row in &snap {
            assert!(
                row.original_content_hash.is_some(),
                "every v0.1.3+ row populates original_content_hash"
            );
            assert!(row.scrub_signature.is_some(), "scrub_signature populated");
            assert_eq!(
                row.scrub_key_id.as_deref(),
                Some(signer_key_id.as_str()),
                "scrub_key_id matches the signer's id"
            );
            assert!(row.scrub_timestamp.is_some(), "scrub_timestamp populated");
        }

        // THREAT_MODEL.md AV-24 verification: ed25519_verify the
        // first row's scrub_signature against signer's public key
        // and the canonical(post-scrub) bytes — proves a peer with
        // the published public key can verify the deployment's
        // attestation.
        let pubkey_bytes = signer.public_key().await.expect("signer.public_key");
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .expect("ed25519 public key is 32 bytes");
        let pubkey =
            ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).expect("verifying key parse");

        let row0 = &snap[0];
        let payload_value = serde_json::Value::Object(row0.payload.clone());
        let canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload_value)
            .unwrap();
        let sig_b64 = row0.scrub_signature.as_ref().unwrap();
        let sig_bytes = BASE64.decode(sig_b64).expect("base64 decode");
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .expect("ed25519 signature is 64 bytes");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        pubkey
            .verify_strict(&canonical, &sig)
            .expect("scrub_signature verifies against canonical(post-scrub)");
    }

    #[tokio::test]
    async fn idempotent_replay() {
        // Mission category §4 "Idempotency": replaying the same batch
        // bytes results in 0 inserts + N conflicts the second time.
        let (bytes, key_id, vkey) = make_signed_batch_bytes();
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let s1 = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(s1.trace_events_inserted, 2);
        let s2 = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(s2.trace_events_inserted, 0);
        assert_eq!(s2.trace_events_conflicted, 2);
    }

    #[tokio::test]
    async fn malformed_json_is_typed_error() {
        let backend = MemoryBackend::new();
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline
            .receive_and_persist(b"{not valid json")
            .await
            .unwrap_err();
        assert!(matches!(err, IngestError::Schema(_)));
    }

    #[tokio::test]
    async fn schema_version_mismatch_rejected() {
        // FSD §3.4 robustness primitive #3.
        let body = serde_json::json!({
            "events": [],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "9.9.9"
        });
        let backend = MemoryBackend::new();
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline
            .receive_and_persist(body.to_string().as_bytes())
            .await
            .unwrap_err();
        match err {
            IngestError::Schema(SchemaError::UnsupportedSchemaVersion { got, .. }) => {
                assert_eq!(got, "9.9.9");
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_signing_key_rejected() {
        let (bytes, key_id, _vkey) = make_signed_batch_bytes();
        let backend = MemoryBackend::new();
        // No key registered → verify must reject with UnknownKey.
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
        match err {
            IngestError::Verify(VerifyError::UnknownKey(id)) => assert_eq!(id, key_id),
            other => panic!("expected UnknownKey, got {other:?}"),
        }
        // Backend received zero rows.
        assert!(backend.snapshot_events().is_empty());
    }

    #[tokio::test]
    async fn signature_mismatch_rejected_no_writes() {
        // Mission constraint (MISSION.md §3 anti-pattern #2): unverified
        // bytes never touch persistence.
        let (bytes, key_id, _vkey) = make_signed_batch_bytes();
        // Wire a *different* key for the same key_id.
        let other_sk = SigningKey::from_bytes(&[0x99; 32]);
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, other_sk.verifying_key());

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
        assert!(matches!(
            err,
            IngestError::Verify(VerifyError::SignatureMismatch)
        ));
        assert!(
            backend.snapshot_events().is_empty(),
            "rejected traces must produce zero rows"
        );
    }

    #[tokio::test]
    async fn empty_events_array_rejected() {
        // FSD §3.3 step 1; MISSION.md §3 anti-pattern #7.
        let body = serde_json::json!({
            "events": [],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0"
        });
        let backend = MemoryBackend::new();
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline
            .receive_and_persist(body.to_string().as_bytes())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            IngestError::Schema(SchemaError::MissingField("events"))
        ));
    }

    /// Sanity: pure-function decompose remains the path inside the
    /// pipeline; nothing in ingest mutates the decomposition results.
    #[test]
    fn pipeline_decompose_is_pure() {
        let trace = CompleteTrace {
            trace_id: "t-1".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:00:00Z".parse().unwrap(),
            completed_at: "2026-04-30T00:01:00Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![],
            signature: "AAAA".into(),
            signature_key_id: "k".into(),
        };
        let d1 = decompose(&trace).unwrap();
        let d2 = decompose(&trace).unwrap();
        assert_eq!(d1, d2);
    }
}
