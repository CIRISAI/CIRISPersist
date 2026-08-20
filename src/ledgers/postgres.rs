//! PostgreSQL impl of [`LedgerService`] (CIRISPersist#754, CC 3.3.10.1
//! rc4.3).
//!
//! Timestamps cross as `chrono::DateTime<Utc>` (TIMESTAMPTZ); JSON columns
//! (`witness_refs`, `evidence_json`) ride as `serde_json::Value` (JSONB);
//! sequence numbers as `i64` (BIGINT, validated non-negative on the way
//! in).
//!
//! Unlike the SQLite arm there is no connection mutex serializing writers,
//! so the #719 discipline is load-bearing here, not belt-and-braces: every
//! door is `INSERT ... ON CONFLICT DO NOTHING` (or a guarded `UPDATE`)
//! with a zero-row re-read to decide identical-no-op vs differing-refusal.
//! `DO NOTHING` alone would silently accept a differing concurrent claim —
//! which is exactly what these doors exist to refuse.

use super::service::LedgerService;
use super::standard::{derive_ledger_id, fork_evidence_id, ForkEvidence};
use super::types::{
    AdvanceOutcome, ForkEvidenceRow, LedgerCheckpointRow, LedgerEntryRangeRow, LedgerHeadRow,
    RegisterOutcome,
};
use super::validate;
use super::Error;
use crate::store::postgres::PostgresBackend;

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
    let code = e.as_db_error().map(|d| d.code().clone());
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    match code {
        Some(c) if c == SqlState::CHECK_VIOLATION => {
            Error::InvalidArgument(format!("{op} CHECK: {detail}"))
        }
        Some(c) if c == SqlState::UNIQUE_VIOLATION => {
            Error::Conflict(format!("{op} UNIQUE: {detail}"))
        }
        Some(c) if c == SqlState::NOT_NULL_VIOLATION => {
            Error::InvalidArgument(format!("{op} NOT NULL: {detail}"))
        }
        Some(c) if c == SqlState::FOREIGN_KEY_VIOLATION => {
            Error::Conflict(format!("{op} FK: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

fn decode_head_row(row: &tokio_postgres::Row) -> Result<LedgerHeadRow, Error> {
    let seq: Option<i64> = row
        .try_get("seq")
        .map_err(|e| Error::Backend(format!("decode seq: {e}")))?;
    let get = |k: &str| -> Result<String, Error> {
        row.try_get(k)
            .map_err(|e| Error::Backend(format!("decode {k}: {e}")))
    };
    let get_opt = |k: &str| -> Result<Option<String>, Error> {
        row.try_get(k)
            .map_err(|e| Error::Backend(format!("decode {k}: {e}")))
    };
    Ok(LedgerHeadRow {
        ledger_id: get("ledger_id")?,
        owner_key_id: get("owner_key_id")?,
        unit: get("unit")?,
        standard_version: get("standard_version")?,
        seq: seq.map(|s| s as u64),
        head_hash: get_opt("head_hash")?,
        witness_anchor_ref: get_opt("witness_anchor_ref")?,
        source_envelope_ref: get_opt("source_envelope_ref")?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?,
    })
}

const HEAD_COLUMNS: &str = "ledger_id, owner_key_id, unit, standard_version, seq, head_hash, \
                            witness_anchor_ref, source_envelope_ref, created_at, updated_at";

impl LedgerService for PostgresBackend {
    async fn register_ledger(
        &self,
        owner_key_id: &str,
        unit: &str,
        standard_version: &str,
    ) -> Result<(String, RegisterOutcome), Error> {
        validate::non_empty(owner_key_id, "owner_key_id")?;
        validate::non_empty(unit, "unit")?;
        validate::non_empty(standard_version, "standard_version")?;
        let ledger_id = derive_ledger_id(owner_key_id, unit, standard_version)
            .map_err(|e| Error::Internal(e.to_string()))?;
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let inserted = client
            .execute(
                "INSERT INTO cirislens.ledger_heads (\
                    ledger_id, owner_key_id, unit, standard_version, \
                    seq, head_hash, witness_anchor_ref, source_envelope_ref, \
                    created_at, updated_at\
                 ) VALUES ($1, $2, $3, $4, NULL, NULL, NULL, NULL, $5, $5) \
                 ON CONFLICT DO NOTHING",
                &[&ledger_id, &owner_key_id, &unit, &standard_version, &now],
            )
            .await
            .map_err(|e| map_pg_error(e, "register_ledger insert"))?;
        if inserted == 1 {
            return Ok((ledger_id, RegisterOutcome::Registered));
        }
        // Zero rows: a key is occupied. Re-read to decide — identical
        // triple is the idempotent no-op, anything else is the L1 refusal.
        let incumbent = client
            .query_opt(
                "SELECT owner_key_id, unit, standard_version \
                 FROM cirislens.ledger_heads WHERE ledger_id = $1",
                &[&ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "register_ledger re-read"))?;
        match incumbent {
            Some(row) => {
                let (i_owner, i_unit, i_sv): (String, String, String) = (
                    row.try_get(0).map_err(|e| Error::Backend(e.to_string()))?,
                    row.try_get(1).map_err(|e| Error::Backend(e.to_string()))?,
                    row.try_get(2).map_err(|e| Error::Backend(e.to_string()))?,
                );
                if i_owner == owner_key_id && i_unit == unit && i_sv == standard_version {
                    Ok((ledger_id, RegisterOutcome::AlreadyRegistered))
                } else {
                    Err(Error::Conflict(format!(
                        "ledger_id {ledger_id} is occupied by triple ({i_owner}, {i_unit}, \
                         {i_sv}) — derivation drift or forged row"
                    )))
                }
            }
            None => {
                let squatter = client
                    .query_opt(
                        "SELECT ledger_id FROM cirislens.ledger_heads \
                         WHERE owner_key_id = $1 AND unit = $2 AND standard_version = $3",
                        &[&owner_key_id, &unit, &standard_version],
                    )
                    .await
                    .map_err(|e| map_pg_error(e, "register_ledger triple re-read"))?;
                let squatter: String = squatter
                    .map(|r| r.try_get(0))
                    .transpose()
                    .map_err(|e| Error::Backend(e.to_string()))?
                    .unwrap_or_else(|| "<gone>".into());
                Err(Error::Conflict(format!(
                    "L1 triple ({owner_key_id}, {unit}, {standard_version}) is occupied by \
                     ledger {squatter} — no parallel books within the claim's scope"
                )))
            }
        }
    }

    async fn advance_head(
        &self,
        ledger_id: &str,
        seq: u64,
        head_hash: &str,
        witness_anchor_ref: Option<&str>,
        source_envelope_ref: Option<&str>,
    ) -> Result<AdvanceOutcome, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        validate::non_empty(head_hash, "head_hash")?;
        let seq_i = validate::seq_as_i64(seq, "seq")?;
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Guarded forward move: only a strictly-later head (or the first)
        // lands. A zero-row result is then classified by re-read.
        let moved = client
            .execute(
                "UPDATE cirislens.ledger_heads SET \
                    seq = $2, head_hash = $3, witness_anchor_ref = $4, \
                    source_envelope_ref = $5, updated_at = $6 \
                 WHERE ledger_id = $1 AND (seq IS NULL OR seq < $2)",
                &[
                    &ledger_id,
                    &seq_i,
                    &head_hash,
                    &witness_anchor_ref,
                    &source_envelope_ref,
                    &now,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "advance_head update"))?;
        if moved == 1 {
            return Ok(AdvanceOutcome::Advanced);
        }
        let current = client
            .query_opt(
                "SELECT seq, head_hash, witness_anchor_ref \
                 FROM cirislens.ledger_heads WHERE ledger_id = $1",
                &[&ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "advance_head re-read"))?;
        let Some(row) = current else {
            return Err(Error::NotFound(format!(
                "ledger {ledger_id} is not registered"
            )));
        };
        let cur_seq: Option<i64> = row.try_get(0).map_err(|e| Error::Backend(e.to_string()))?;
        let cur_hash: Option<String> = row.try_get(1).map_err(|e| Error::Backend(e.to_string()))?;
        let cur_anchor: Option<String> =
            row.try_get(2).map_err(|e| Error::Backend(e.to_string()))?;
        match (cur_seq, cur_hash) {
            (Some(c), Some(h)) if seq_i == c && h == head_hash => {
                // Anchor fill-in for the head we already hold — guarded so
                // it only ever fills a NULL (an anchored fact pins, never
                // flips), and re-keyed on the head so a racing advance
                // cannot be anchored with a stale ref.
                if cur_anchor.is_none() && witness_anchor_ref.is_some() {
                    client
                        .execute(
                            "UPDATE cirislens.ledger_heads SET \
                                witness_anchor_ref = $2, updated_at = $3 \
                             WHERE ledger_id = $1 AND seq = $4 AND head_hash = $5 \
                               AND witness_anchor_ref IS NULL",
                            &[&ledger_id, &witness_anchor_ref, &now, &seq_i, &head_hash],
                        )
                        .await
                        .map_err(|e| map_pg_error(e, "advance_head anchor fill"))?;
                }
                Ok(AdvanceOutcome::Unchanged)
            }
            (Some(c), Some(h)) if seq_i == c => Err(Error::Conflict(format!(
                "fork-shaped head for {ledger_id} at seq {seq}: stored {h}, offered {head_hash}"
            ))),
            (Some(c), _) if seq_i < c => Ok(AdvanceOutcome::Stale),
            // seq > current or current NULL, yet the guarded UPDATE moved
            // nothing: a concurrent writer advanced past us between the two
            // statements — that is a stale arrival by the time we looked.
            _ => Ok(AdvanceOutcome::Stale),
        }
    }

    async fn get_ledger(&self, ledger_id: &str) -> Result<Option<LedgerHeadRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row = client
            .query_opt(
                &format!("SELECT {HEAD_COLUMNS} FROM cirislens.ledger_heads WHERE ledger_id = $1"),
                &[&ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_ledger"))?;
        row.map(|r| decode_head_row(&r)).transpose()
    }

    async fn find_ledger_by_triple(
        &self,
        owner_key_id: &str,
        unit: &str,
        standard_version: &str,
    ) -> Result<Option<LedgerHeadRow>, Error> {
        validate::non_empty(owner_key_id, "owner_key_id")?;
        validate::non_empty(unit, "unit")?;
        validate::non_empty(standard_version, "standard_version")?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row = client
            .query_opt(
                &format!(
                    "SELECT {HEAD_COLUMNS} FROM cirislens.ledger_heads \
                     WHERE owner_key_id = $1 AND unit = $2 AND standard_version = $3"
                ),
                &[&owner_key_id, &unit, &standard_version],
            )
            .await
            .map_err(|e| map_pg_error(e, "find_ledger_by_triple"))?;
        row.map(|r| decode_head_row(&r)).transpose()
    }

    async fn list_ledgers_for_owner(
        &self,
        owner_key_id: &str,
    ) -> Result<Vec<LedgerHeadRow>, Error> {
        validate::non_empty(owner_key_id, "owner_key_id")?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {HEAD_COLUMNS} FROM cirislens.ledger_heads \
                     WHERE owner_key_id = $1 ORDER BY ledger_id"
                ),
                &[&owner_key_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_ledgers_for_owner"))?;
        rows.iter().map(decode_head_row).collect()
    }

    async fn put_checkpoint(&self, checkpoint: &LedgerCheckpointRow) -> Result<bool, Error> {
        validate::non_empty(&checkpoint.ledger_id, "ledger_id")?;
        validate::balance_minor(&checkpoint.balance_minor)?;
        validate::witness_refs(&checkpoint.witness_refs)?;
        let seq_i = validate::seq_as_i64(checkpoint.seq, "seq")?;
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let registered = client
            .query_opt(
                "SELECT 1 FROM cirislens.ledger_heads WHERE ledger_id = $1",
                &[&checkpoint.ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_checkpoint precheck"))?;
        if registered.is_none() {
            return Err(Error::NotFound(format!(
                "ledger {} is not registered",
                checkpoint.ledger_id
            )));
        }
        let inserted = client
            .execute(
                "INSERT INTO cirislens.ledger_checkpoints (\
                    ledger_id, seq, balance_minor, witness_refs, \
                    supersedes_ref, source_envelope_ref, created_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT DO NOTHING",
                &[
                    &checkpoint.ledger_id,
                    &seq_i,
                    &checkpoint.balance_minor,
                    &checkpoint.witness_refs,
                    &checkpoint.supersedes_ref,
                    &checkpoint.source_envelope_ref,
                    &now,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_checkpoint insert"))?;
        if inserted == 1 {
            return Ok(true);
        }
        let stored = client
            .query_one(
                "SELECT balance_minor, witness_refs, supersedes_ref \
                 FROM cirislens.ledger_checkpoints WHERE ledger_id = $1 AND seq = $2",
                &[&checkpoint.ledger_id, &seq_i],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_checkpoint re-read"))?;
        let (s_balance, s_witness, s_supersedes): (String, serde_json::Value, Option<String>) = (
            stored
                .try_get(0)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(1)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(2)
                .map_err(|e| Error::Backend(e.to_string()))?,
        );
        if s_balance == checkpoint.balance_minor
            && s_witness == checkpoint.witness_refs
            && s_supersedes == checkpoint.supersedes_ref
        {
            return Ok(false);
        }
        Err(Error::Conflict(format!(
            "checkpoint ({}, {}) exists with different content — checkpoints are immutable",
            checkpoint.ledger_id, checkpoint.seq
        )))
    }

    async fn latest_checkpoint(
        &self,
        ledger_id: &str,
    ) -> Result<Option<LedgerCheckpointRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row = client
            .query_opt(
                "SELECT ledger_id, seq, balance_minor, witness_refs, supersedes_ref, \
                        source_envelope_ref, created_at \
                 FROM cirislens.ledger_checkpoints WHERE ledger_id = $1 \
                 ORDER BY seq DESC LIMIT 1",
                &[&ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "latest_checkpoint"))?;
        match row {
            None => Ok(None),
            Some(r) => {
                let seq: i64 = r.try_get(1).map_err(|e| Error::Backend(e.to_string()))?;
                Ok(Some(LedgerCheckpointRow {
                    ledger_id: r.try_get(0).map_err(|e| Error::Backend(e.to_string()))?,
                    seq: seq as u64,
                    balance_minor: r.try_get(2).map_err(|e| Error::Backend(e.to_string()))?,
                    witness_refs: r.try_get(3).map_err(|e| Error::Backend(e.to_string()))?,
                    supersedes_ref: r.try_get(4).map_err(|e| Error::Backend(e.to_string()))?,
                    source_envelope_ref: r.try_get(5).map_err(|e| Error::Backend(e.to_string()))?,
                    created_at: r.try_get(6).map_err(|e| Error::Backend(e.to_string()))?,
                }))
            }
        }
    }

    async fn put_entry_range(&self, range: &LedgerEntryRangeRow) -> Result<bool, Error> {
        validate::non_empty(&range.ledger_id, "ledger_id")?;
        validate::non_empty(&range.blob_ref, "blob_ref")?;
        validate::non_empty(&range.head_hash_at_to, "head_hash_at_to")?;
        if range.to_seq < range.from_seq {
            return Err(Error::InvalidArgument(format!(
                "inverted range [{}, {}]",
                range.from_seq, range.to_seq
            )));
        }
        let from_i = validate::seq_as_i64(range.from_seq, "from_seq")?;
        let to_i = validate::seq_as_i64(range.to_seq, "to_seq")?;
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let registered = client
            .query_opt(
                "SELECT 1 FROM cirislens.ledger_heads WHERE ledger_id = $1",
                &[&range.ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_entry_range precheck"))?;
        if registered.is_none() {
            return Err(Error::NotFound(format!(
                "ledger {} is not registered",
                range.ledger_id
            )));
        }
        let inserted = client
            .execute(
                "INSERT INTO cirislens.ledger_entry_ranges (\
                    ledger_id, from_seq, to_seq, blob_ref, head_hash_at_to, created_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT DO NOTHING",
                &[
                    &range.ledger_id,
                    &from_i,
                    &to_i,
                    &range.blob_ref,
                    &range.head_hash_at_to,
                    &now,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_entry_range insert"))?;
        if inserted == 1 {
            return Ok(true);
        }
        let stored = client
            .query_one(
                "SELECT to_seq, blob_ref, head_hash_at_to \
                 FROM cirislens.ledger_entry_ranges \
                 WHERE ledger_id = $1 AND from_seq = $2",
                &[&range.ledger_id, &from_i],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_entry_range re-read"))?;
        let (s_to, s_blob, s_hash): (i64, String, String) = (
            stored
                .try_get(0)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(1)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(2)
                .map_err(|e| Error::Backend(e.to_string()))?,
        );
        if s_to == to_i && s_blob == range.blob_ref && s_hash == range.head_hash_at_to {
            return Ok(false);
        }
        Err(Error::Conflict(format!(
            "entry range ({}, {}) exists with different content",
            range.ledger_id, range.from_seq
        )))
    }

    async fn list_entry_ranges(&self, ledger_id: &str) -> Result<Vec<LedgerEntryRangeRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT ledger_id, from_seq, to_seq, blob_ref, head_hash_at_to, created_at \
                 FROM cirislens.ledger_entry_ranges WHERE ledger_id = $1 ORDER BY from_seq",
                &[&ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_entry_ranges"))?;
        rows.iter()
            .map(|r| {
                let from: i64 = r.try_get(1).map_err(|e| Error::Backend(e.to_string()))?;
                let to: i64 = r.try_get(2).map_err(|e| Error::Backend(e.to_string()))?;
                Ok(LedgerEntryRangeRow {
                    ledger_id: r.try_get(0).map_err(|e| Error::Backend(e.to_string()))?,
                    from_seq: from as u64,
                    to_seq: to as u64,
                    blob_ref: r.try_get(3).map_err(|e| Error::Backend(e.to_string()))?,
                    head_hash_at_to: r.try_get(4).map_err(|e| Error::Backend(e.to_string()))?,
                    created_at: r.try_get(5).map_err(|e| Error::Backend(e.to_string()))?,
                })
            })
            .collect()
    }

    async fn record_fork_evidence(&self, evidence: &ForkEvidence) -> Result<String, Error> {
        let evidence_id = fork_evidence_id(evidence).map_err(|e| Error::Internal(e.to_string()))?;
        let seq_i = validate::seq_as_i64(evidence.seq(), "seq")?;
        let evidence_json = serde_json::to_value(evidence)
            .map_err(|e| Error::Internal(format!("evidence encode: {e}")))?;
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // The id is a content hash: ON CONFLICT DO NOTHING alone is the
        // whole idempotence story here (differing content under one id is
        // a hash collision, not a reachable state).
        client
            .execute(
                "INSERT INTO cirislens.ledger_fork_evidence (\
                    evidence_id, ledger_id, seq, fork_kind, evidence_json, detected_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT DO NOTHING",
                &[
                    &evidence_id,
                    &evidence.ledger_id(),
                    &seq_i,
                    &evidence.fork_kind_str(),
                    &evidence_json,
                    &now,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_fork_evidence insert"))?;
        Ok(evidence_id)
    }

    async fn list_fork_evidence(&self, ledger_id: &str) -> Result<Vec<ForkEvidenceRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT evidence_id, ledger_id, seq, fork_kind, evidence_json, detected_at \
                 FROM cirislens.ledger_fork_evidence WHERE ledger_id = $1 ORDER BY evidence_id",
                &[&ledger_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_fork_evidence"))?;
        rows.iter()
            .map(|r| {
                let seq: i64 = r.try_get(2).map_err(|e| Error::Backend(e.to_string()))?;
                Ok(ForkEvidenceRow {
                    evidence_id: r.try_get(0).map_err(|e| Error::Backend(e.to_string()))?,
                    ledger_id: r.try_get(1).map_err(|e| Error::Backend(e.to_string()))?,
                    seq: seq as u64,
                    fork_kind: r.try_get(3).map_err(|e| Error::Backend(e.to_string()))?,
                    evidence_json: r.try_get(4).map_err(|e| Error::Backend(e.to_string()))?,
                    detected_at: r.try_get(5).map_err(|e| Error::Backend(e.to_string()))?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::standard::{detect_double_head, SignedHead};
    use super::*;
    use crate::store::postgres::PostgresBackend;

    fn unique(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4())
    }

    async fn svc() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::dsn()?;
        let backend = PostgresBackend::connect(&dsn).await.expect("pg connect");
        crate::store::backend::Backend::run_migrations(&backend)
            .await
            .expect("pg migrations");
        Some(backend)
    }

    #[tokio::test]
    async fn pg_register_advance_and_the_fork_refusal() {
        let Some(svc) = svc().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let owner = unique("owner");
        let (id, o1) = svc.register_ledger(&owner, "usd", "1").await.unwrap();
        assert_eq!(o1, RegisterOutcome::Registered);
        assert_eq!(id, derive_ledger_id(&owner, "usd", "1").unwrap());
        let (_, o2) = svc.register_ledger(&owner, "usd", "1").await.unwrap();
        assert_eq!(o2, RegisterOutcome::AlreadyRegistered);

        assert_eq!(
            svc.advance_head(&id, 4, "h4", None, None).await.unwrap(),
            AdvanceOutcome::Advanced
        );
        assert_eq!(
            svc.advance_head(&id, 7, "h7", Some("anchor-7"), None)
                .await
                .unwrap(),
            AdvanceOutcome::Advanced
        );
        assert_eq!(
            svc.advance_head(&id, 7, "h7", None, None).await.unwrap(),
            AdvanceOutcome::Unchanged
        );
        assert_eq!(
            svc.advance_head(&id, 5, "h5", None, None).await.unwrap(),
            AdvanceOutcome::Stale
        );
        let err = svc
            .advance_head(&id, 7, "h7-other", None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "ledgers_conflict");
        assert!(err.to_string().contains("fork-shaped"), "{err}");
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row.head_hash.as_deref(), Some("h7"));
        assert_eq!(row.witness_anchor_ref.as_deref(), Some("anchor-7"));

        let err = svc
            .advance_head(&unique("ledger-nope"), 0, "h", None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "ledgers_not_found");
    }

    #[tokio::test]
    async fn pg_second_book_on_an_occupied_triple_is_refused() {
        let Some(svc) = svc().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let owner = unique("owner");
        // Forge a row occupying the triple under a different ledger_id.
        let forged = unique("ledger-forged");
        let client = svc.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO cirislens.ledger_heads (\
                    ledger_id, owner_key_id, unit, standard_version, created_at, updated_at\
                 ) VALUES ($1, $2, 'usd', '1', NOW(), NOW())",
                &[&forged, &owner],
            )
            .await
            .unwrap();
        let err = svc.register_ledger(&owner, "usd", "1").await.unwrap_err();
        assert_eq!(err.kind(), "ledgers_conflict");
        assert!(err.to_string().contains(&forged), "{err}");
    }

    /// **The ACID witnesses, on the backend where they are load-bearing.**
    /// The SQLite arm serializes writers behind one mutex; here the pool
    /// hands every racer its own connection, so Isolation is exactly what
    /// the #719 absorb-then-re-read discipline claims to buy. Sixteen true
    /// concurrent claims on one L1 triple: one registration, fifteen
    /// idempotent no-ops, zero errors, one row. Then the fork race at one
    /// seq: the stored head is ONE of the offered hashes, never a blend.
    /// Then conflicting checkpoints at one seq: exactly one lands, the rest
    /// refuse, and the stored bytes are exactly one contender's. Durability:
    /// a SECOND pool over the same DSN reads everything back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn acid_pg_isolation_atomicity_durability() {
        let Some(svc) = svc().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let svc = std::sync::Arc::new(svc);
        let owner = unique("owner-acid");

        // ISOLATION 1 — the L1 door under true concurrency.
        let mut regs = Vec::new();
        for _ in 0..16 {
            let svc = svc.clone();
            let owner = owner.clone();
            regs.push(tokio::spawn(async move {
                svc.register_ledger(&owner, "usd", "1").await
            }));
        }
        let (mut registered, mut already, mut id) = (0, 0, String::new());
        for r in regs {
            let (lid, outcome) = r.await.unwrap().expect("no racer may error");
            id = lid;
            match outcome {
                RegisterOutcome::Registered => registered += 1,
                RegisterOutcome::AlreadyRegistered => already += 1,
            }
        }
        assert_eq!(
            (registered, already),
            (1, 15),
            "one registration, 15 no-ops"
        );

        // ISOLATION 2 — the fork race: two camps at one seq.
        let mut advances = Vec::new();
        for i in 0..8 {
            let svc = svc.clone();
            let id = id.clone();
            let hash = if i % 2 == 0 { "hash-a" } else { "hash-b" };
            advances.push(tokio::spawn(async move {
                svc.advance_head(&id, 3, hash, None, None).await
            }));
        }
        for a in advances {
            match a.await.unwrap() {
                Ok(_) => {}
                Err(e) => assert_eq!(e.kind(), "ledgers_conflict", "{e}"),
            }
        }
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row.seq, Some(3));
        assert!(
            row.head_hash.as_deref() == Some("hash-a")
                || row.head_hash.as_deref() == Some("hash-b"),
            "one of the offered hashes, never a blend: {:?}",
            row.head_hash
        );
        assert_eq!(row.seq.is_some(), row.head_hash.is_some());

        // ATOMICITY under contention — eight DIFFERENT checkpoints at one
        // seq: exactly one lands (Ok(true)), the rest refuse Conflict, and
        // the stored bytes are exactly one contender's.
        let mut cps = Vec::new();
        for i in 0..8u32 {
            let svc = svc.clone();
            let id = id.clone();
            cps.push(tokio::spawn(async move {
                let cp = LedgerCheckpointRow {
                    ledger_id: id,
                    seq: 3,
                    balance_minor: i.to_string(),
                    witness_refs: serde_json::json!([format!("w{i}")]),
                    supersedes_ref: None,
                    source_envelope_ref: None,
                    created_at: chrono::Utc::now(),
                };
                svc.put_checkpoint(&cp).await
            }));
        }
        let mut landed = 0;
        for c in cps {
            match c.await.unwrap() {
                Ok(true) => landed += 1,
                Ok(false) => panic!("no two contenders were identical"),
                Err(e) => assert_eq!(e.kind(), "ledgers_conflict", "{e}"),
            }
        }
        assert_eq!(landed, 1, "exactly one checkpoint lands at a seq");
        let cp = svc.latest_checkpoint(&id).await.unwrap().unwrap();
        let winner: u32 = cp.balance_minor.parse().unwrap();
        assert_eq!(
            cp.witness_refs,
            serde_json::json!([format!("w{winner}")]),
            "the stored checkpoint is one contender's bytes, never a blend"
        );

        // DURABILITY — a second pool over the same DSN sees it all.
        let dsn = crate::test_pg::dsn().unwrap();
        let second = PostgresBackend::connect(&dsn).await.unwrap();
        let row2 = second.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row2, row);
        assert_eq!(second.latest_checkpoint(&id).await.unwrap().unwrap(), cp);
    }

    #[tokio::test]
    async fn pg_checkpoints_ranges_and_fork_evidence() {
        let Some(svc) = svc().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let owner = unique("owner");
        let (id, _) = svc.register_ledger(&owner, "usd", "1").await.unwrap();

        let cp = |balance: &str| LedgerCheckpointRow {
            ledger_id: id.clone(),
            seq: 10,
            balance_minor: balance.into(),
            witness_refs: serde_json::json!(["w1"]),
            supersedes_ref: None,
            source_envelope_ref: None,
            created_at: chrono::Utc::now(),
        };
        assert_eq!(
            svc.put_checkpoint(&cp("007")).await.unwrap_err().kind(),
            "ledgers_invalid_argument"
        );
        assert!(svc.put_checkpoint(&cp("-42")).await.unwrap());
        assert!(!svc.put_checkpoint(&cp("-42")).await.unwrap());
        assert_eq!(
            svc.put_checkpoint(&cp("-41")).await.unwrap_err().kind(),
            "ledgers_conflict"
        );
        let latest = svc.latest_checkpoint(&id).await.unwrap().unwrap();
        assert_eq!(latest.balance_minor, "-42");

        let rg = LedgerEntryRangeRow {
            ledger_id: id.clone(),
            from_seq: 0,
            to_seq: 9,
            blob_ref: "blob-0-9".into(),
            head_hash_at_to: "h9".into(),
            created_at: chrono::Utc::now(),
        };
        assert!(svc.put_entry_range(&rg).await.unwrap());
        assert!(!svc.put_entry_range(&rg).await.unwrap());
        let mut differing = rg.clone();
        differing.blob_ref = "blob-other".into();
        assert_eq!(
            svc.put_entry_range(&differing).await.unwrap_err().kind(),
            "ledgers_conflict"
        );

        // Fork evidence: idempotent, content-derived id, no FK precondition.
        let foreign = unique("ledger-elsewhere");
        let mk = |hash: &str| SignedHead {
            ledger_id: foreign.clone(),
            seq: 7,
            head_hash: hash.into(),
            signature_key_id: "owner".into(),
            signature_classical_base64: "c2ln".into(),
            signature_pqc_base64: None,
        };
        let ev = detect_double_head(&mk("hash-a"), &mk("hash-b")).unwrap();
        let id1 = svc.record_fork_evidence(&ev).await.unwrap();
        let id2 = svc.record_fork_evidence(&ev).await.unwrap();
        assert_eq!(id1, id2);
        let rows = svc.list_fork_evidence(&foreign).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fork_kind, "double_head");
    }
}
