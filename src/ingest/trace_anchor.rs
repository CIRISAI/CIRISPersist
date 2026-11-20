//! v62.0.0 (P7-fix8; the adopters' ask — Server / lens-core's ports off the
//! removed `verify_trace`) — **test-anchor helpers for a trace's edition-2
//! row**, so an adopter's test signs and admits a trace through the SAME door
//! production uses. Behind `test-anchor` (never in a production build);
//! re-exported from [`crate::prelude`].
//!
//! The production shape (CC 3.1.5, ruling (a)): a trace is a BLOB (its JCS
//! bytes, no signature members) named by its `trace:complete:v1` ROW, ONE
//! composite statement under the agent's **agent-kind** edition-2 key; the
//! door refuses any other signer kind (`trace_signer_not_agent`).
//!
//! ```ignore
//! use ciris_persist::prelude::*;
//!
//! // The agent's key, live on this node (an `agent` key:record).
//! let iss = put_agent_trace_key(&backend, "lens-test-agent").await;
//! // A trace dated inside that key's window.
//! let mut trace = my_trace_json();
//! date_trace(&mut trace, agent_trace_instant_ms("lens-test-agent"));
//! // The signed row + its blob.
//! let row = sign_agent_trace("lens-test-agent", &trace)?;
//! // Through the real statement door: the blob plane, then `put_statement`
//! // (Verify's reader, the key-of-issuer check, liveness, every attestation
//! // gate, the signer kind, the trace projection).
//! let held = admit_trace_row(&backend, &row).await?;
//! // Or the batch door itself (`IngestPipeline::receive_and_persist`):
//! let event = trace_row_event(&row, "generic");
//! ```

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::edition2::{identity_ref, sign_row_statement, thumbprint};

use super::{
    admit_trace_statement, canonical_trace_blob, check_trace_statement_binding,
    is_sealed_trace_blob, parse_trace_blob, trace_row_payload, IngestError, SealedTrace,
    TRACE_FAMILY_ID, TRACE_ROW_TYPE,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::FederationDirectory;
use crate::schema::CompleteTrace;
use crate::store::Backend;

const DAY_MS: u64 = 86_400_000;

/// Put the seed-named fixture key `seed` on `dir` as an **agent** key (its
/// self-signed edition-2 `key:record`, the default agent window), returning
/// its identity-ref: the `iss` every trace row it signs carries.
pub async fn put_agent_trace_key<D: FederationDirectory + ?Sized>(dir: &D, seed: &str) -> String {
    e2::put_key(dir, seed, &[crate::federation::types::identity_type::AGENT]).await
}

/// The instant (ms) a trace signed by `seed` is dated at: the agent key's own
/// window start ([`e2::key_window_start_ms`]) plus the fixed
/// `OWNER_BINDING_OFFSET_DAYS` (K2's rule). Never the wall clock, never a
/// fixed calendar date an agent record (at most 365 days) would outlive.
#[must_use]
pub fn agent_trace_instant_ms(seed: &str) -> u64 {
    let offset =
        u64::try_from(crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS)
            .expect("a positive day count");
    e2::key_window_start_ms(seed) + offset * DAY_MS
}

/// Re-date `trace` (a `CompleteTrace` JSON object) to END at `completed_ms`:
/// `completed_at` = that instant, `started_at` one second per component (plus
/// one) before it, each component's `timestamp` one second apart from
/// `started_at`. Non-object values are left alone.
pub fn date_trace(trace: &mut serde_json::Value, completed_ms: u64) {
    let stamp = |ms: i64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null)
    };
    let completed = i64::try_from(completed_ms).unwrap_or(i64::MAX);
    let n = trace
        .get("components")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let n = i64::try_from(n).unwrap_or(0);
    let started = completed - (n + 1) * 1000;
    let Some(obj) = trace.as_object_mut() else {
        return;
    };
    obj.insert("started_at".into(), stamp(started));
    obj.insert("completed_at".into(), stamp(completed));
    if let Some(components) = obj
        .get_mut("components")
        .and_then(serde_json::Value::as_array_mut)
    {
        for (i, c) in (0_i64..).zip(components.iter_mut()) {
            if let Some(c) = c.as_object_mut() {
                c.insert("timestamp".into(), stamp(started + i * 1000));
            }
        }
    }
}

/// [`sign_agent_trace_with`] under the seed-named fixture key `seed` (the key
/// [`put_agent_trace_key`] puts).
///
/// # Errors
/// As [`sign_agent_trace_with`].
pub fn sign_agent_trace(seed: &str, trace: &serde_json::Value) -> Result<SealedTrace, IngestError> {
    sign_agent_trace_with(&e2::signing_key(seed), trace)
}

/// **The signed edition-2 trace statement**, as production builds it
/// (`ingest::seal_trace_row` without its scrub): the trace's blob
/// ([`canonical_trace_blob`]: JCS, the signature members stripped) and its
/// `trace:complete:v1` row ([`trace_row_payload`]) signed ONCE by `key`'s
/// composite, `iss` = `sub` = `key`'s identity-ref.
///
/// The key must be an AGENT's for the door to admit the row.
///
/// # Errors
/// `trace_statement_invalid` (not a trace object / not a `CompleteTrace`),
/// the payload's refusals, `IngestError::Sign` when the composite fails.
pub fn sign_agent_trace_with(
    key: &CompositeSigningKey,
    trace: &serde_json::Value,
) -> Result<SealedTrace, IngestError> {
    let iss = identity_ref(&thumbprint(key.public_key()));
    let trace_blob = canonical_trace_blob(trace)?;
    let parsed: CompleteTrace =
        serde_json::from_slice(&trace_blob).map_err(|e| IngestError::Schema(e.into()))?;
    let payload = trace_row_payload(&parsed, &trace_blob, &iss)?;
    let statement = sign_row_statement(
        key,
        &iss,
        &iss,
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        &payload,
        vec![],
    )
    .map_err(|e| IngestError::Sign(format!("trace row: {e}")))?;
    Ok(SealedTrace {
        statement,
        trace_blob,
    })
}

/// `row` as one batch-envelope event on the v62 trace wire (`statement` +
/// `trace_blob`, base64; no inline `trace`), for the batch door
/// (`IngestPipeline::receive_and_persist`) or the Lens pipeline route.
#[must_use]
pub fn trace_row_event(row: &SealedTrace, trace_level: &str) -> serde_json::Value {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    serde_json::json!({
        "event_type": "complete_trace",
        "trace_level": trace_level,
        "statement": b64.encode(&row.statement),
        "trace_blob": b64.encode(&row.trace_blob),
    })
}

/// **Admit `row` through the real door**, exactly as the batch door does for
/// one row-form event: for a plaintext blob, the content binding
/// ([`check_trace_statement_binding`]) and the decompose pre-check; then
/// `admit_trace_statement` — the signer kind, the blob onto the blob plane,
/// and the edition-2 statement door (`put_statement`: Verify's reader, the
/// key-of-issuer check, the key's liveness at the row's instant, every
/// attestation gate, the trace projection in the row's own write).
///
/// Returns `true` when the door HELD the row (G0's fold: a sealed blob this
/// node cannot open yet), `false` when it is admitted.
///
/// # Errors
/// The door's refusals by name (`trace_signer_not_agent`,
/// `kid_not_of_iss`, `trace_statement_content_mismatch`, …), as
/// [`IngestError`].
pub async fn admit_trace_row<B>(backend: &B, row: &SealedTrace) -> Result<bool, IngestError>
where
    B: Backend + FederationDirectory + ?Sized,
{
    let trace = if is_sealed_trace_blob(&row.trace_blob) {
        None
    } else {
        let raw = parse_trace_blob(&row.trace_blob)?;
        let trace: CompleteTrace =
            serde_json::from_value(raw).map_err(|e| IngestError::Schema(e.into()))?;
        check_trace_statement_binding(&row.statement, &trace, &row.trace_blob)?;
        crate::store::decompose(&trace).map_err(|e| match e {
            crate::store::Error::Schema(s) => IngestError::Schema(s),
            other => IngestError::Store(other),
        })?;
        Some(trace)
    };
    let (_, held) =
        admit_trace_statement(backend, trace.as_ref(), &row.statement, &row.trace_blob).await?;
    Ok(held)
}

/// **I3489-bis** — the adopters' helper lands (sqlite, postgres): an agent's
/// row signed by [`sign_agent_trace`], dated by [`agent_trace_instant_ms`],
/// is admitted by [`admit_trace_row`] and its `trace_events` are projected;
/// the same trace signed by a `node` key is refused `trace_signer_not_agent`.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::*;

    fn unique(tag: &str) -> String {
        format!(
            "p7-anchor-{tag}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )
    }

    fn a_trace(trace_id: &str) -> serde_json::Value {
        serde_json::json!({
            "trace_id": trace_id,
            "thought_id": format!("{trace_id}-th"),
            "agent_id_hash": "anchor-agent-hash",
            "started_at": "2000-01-01T00:00:00Z",
            "completed_at": "2000-01-01T00:00:01Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
            "cohort_scope": "federation",
            "components": [{
                "component_type": "observation",
                "event_type": "THOUGHT_START",
                "timestamp": "2000-01-01T00:00:00Z",
                "data": {"attempt_index": 0},
            }],
        })
    }

    async fn events_of<B: Backend>(b: &B, trace_id: &str) -> usize {
        b.fetch_trace_events_page(-1, i64::MAX, None)
            .await
            .expect("fetch_trace_events_page")
            .into_iter()
            .filter(|(_, r)| r.trace_id == trace_id)
            .count()
    }

    async fn body<B>(b: &B)
    where
        B: Backend + FederationDirectory,
    {
        let agent = unique("agent");
        let iss = put_agent_trace_key(b, &agent).await;
        let trace_id = unique("trace");
        let mut trace = a_trace(&trace_id);
        date_trace(&mut trace, agent_trace_instant_ms(&agent));
        let row = sign_agent_trace(&agent, &trace).expect("the helper signs");
        let (signed_as, _) = super::super::check_trace_row_shape(&row.statement, &row.trace_blob)
            .expect("the row names its blob");
        assert_eq!(signed_as, iss, "I3489-bis: signed as the agent key");
        let held = admit_trace_row(b, &row)
            .await
            .unwrap_or_else(|e| panic!("I3489-bis: the helper's row lands: {} ({e})", e.kind()));
        assert!(!held, "I3489-bis: admitted, not held");
        assert!(
            events_of(b, &trace_id).await > 0,
            "I3489-bis: projected in the row's own write"
        );

        let node = unique("node");
        e2::put_key(b, &node, &["node"]).await;
        let trace_id = unique("trace-node");
        let mut trace = a_trace(&trace_id);
        date_trace(&mut trace, agent_trace_instant_ms(&node));
        let row = sign_agent_trace(&node, &trace).expect("signs");
        let refused = admit_trace_row(b, &row).await.expect_err("a node key");
        assert_eq!(
            refused.kind(),
            super::super::TRACE_SIGNER_NOT_AGENT,
            "I3489-bis: refused by name"
        );
        assert_eq!(events_of(b, &trace_id).await, 0, "I3489-bis: nothing lands");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3489_bis_trace_anchor_helper_lands_sqlite() {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(&b)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3489_bis_trace_anchor_helper_lands_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(&b)).await;
    }
}
