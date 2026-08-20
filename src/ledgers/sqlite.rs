//! SQLite impl of [`LedgerService`] (CIRISPersist#754, CC 3.3.10.1 rc4.3).
//!
//! Mirrors the Postgres impl. Dialect translations (the V034 conventions):
//!
//!   TIMESTAMPTZ → TEXT (RFC 3339)
//!   JSONB       → TEXT (raw JSON string)
//!   BIGINT      → INTEGER
//!
//! Threading: inline-sync closures over `conn.lock()` per the existing
//! family pattern. Every write door is idempotent for byte-identical
//! re-puts and `Conflict` for differing claims on occupied keys — the
//! #719 discipline: absorb the race at the INSERT, then a zero-row result
//! re-reads to decide identical-no-op vs differing-refusal.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};

use super::service::LedgerService;
use super::standard::{derive_ledger_id, fork_evidence_id, ForkEvidence};
use super::types::{
    AdvanceOutcome, ForkEvidenceRow, LedgerCheckpointRow, LedgerEntryRangeRow, LedgerHeadRow,
    RegisterOutcome,
};
use super::validate;
use super::Error;

/// SQLite-backed [`LedgerService`] impl.
pub struct SqliteLedgerBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteLedgerBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            // SQLite collapses CHECK / NOT NULL / FK / UNIQUE under one
            // ErrorCode; distinguish by extended code so FK + UNIQUE
            // violations surface as Conflict (parity with PG) and
            // CHECK / NOT NULL as InvalidArgument.
            let extended = err.extended_code;
            // 787  = SQLITE_CONSTRAINT_FOREIGNKEY
            // 1555 = SQLITE_CONSTRAINT_PRIMARYKEY
            // 2067 = SQLITE_CONSTRAINT_UNIQUE
            if extended == 787 {
                return Error::Conflict(format!("{op} FK: {e}"));
            }
            if extended == 1555 || extended == 2067 {
                return Error::Conflict(format!("{op} UNIQUE: {e}"));
            }
            return Error::InvalidArgument(format!("{op}: {e}"));
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn decode_json(s: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str(s).map_err(|e| Error::Backend(format!("json decode: {e} (raw={s})")))
}

fn decode_head_row(row: &rusqlite::Row<'_>) -> Result<LedgerHeadRow, Error> {
    let seq: Option<i64> = row
        .get("seq")
        .map_err(|e| Error::Backend(format!("decode seq: {e}")))?;
    let created_at: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    let updated_at: String = row
        .get("updated_at")
        .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?;
    let get = |k: &str| -> Result<String, Error> {
        row.get(k)
            .map_err(|e| Error::Backend(format!("decode {k}: {e}")))
    };
    let get_opt = |k: &str| -> Result<Option<String>, Error> {
        row.get(k)
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
        created_at: parse_datetime(&created_at)?,
        updated_at: parse_datetime(&updated_at)?,
    })
}

const HEAD_COLUMNS: &str = "ledger_id, owner_key_id, unit, standard_version, seq, head_hash, \
                            witness_anchor_ref, source_envelope_ref, created_at, updated_at";

impl LedgerService for SqliteLedgerBackend {
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
        let now = fmt_datetime(Utc::now());
        let (owner, unit, sv) = (
            owner_key_id.to_owned(),
            unit.to_owned(),
            standard_version.to_owned(),
        );
        let conn = self.conn.clone();
        (move || -> Result<(String, RegisterOutcome), Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "register_ledger begin"))?;
            // INSERT OR IGNORE absorbs the race; a zero-row result re-reads
            // to decide (identical ⇒ idempotent no-op, differing ⇒ refusal)
            // — `DO NOTHING` alone would silently accept a differing claim,
            // which is what L1 exists to refuse (the #719 lesson).
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO cirislens_ledger_heads (\
                        ledger_id, owner_key_id, unit, standard_version, \
                        seq, head_hash, witness_anchor_ref, source_envelope_ref, \
                        created_at, updated_at\
                     ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL, ?5, ?5)",
                    params![ledger_id, owner, unit, sv, now],
                )
                .map_err(|e| map_sqlite_error(e, "register_ledger insert"))?;
            if inserted == 1 {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "register_ledger commit"))?;
                return Ok((ledger_id, RegisterOutcome::Registered));
            }
            // Zero rows: something occupies a key. Re-read to decide.
            let incumbent: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT owner_key_id, unit, standard_version \
                     FROM cirislens_ledger_heads WHERE ledger_id = ?1",
                    params![ledger_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "register_ledger re-read"))?;
            match incumbent {
                Some((i_owner, i_unit, i_sv))
                    if i_owner == owner && i_unit == unit && i_sv == sv =>
                {
                    tx.commit()
                        .map_err(|e| map_sqlite_error(e, "register_ledger commit"))?;
                    Ok((ledger_id, RegisterOutcome::AlreadyRegistered))
                }
                Some((i_owner, i_unit, i_sv)) => Err(Error::Conflict(format!(
                    "ledger_id {ledger_id} is occupied by triple ({i_owner}, {i_unit}, {i_sv}) — \
                     derivation drift or forged row"
                ))),
                None => {
                    // Not the id — then the L1 triple index is occupied by
                    // a row with a DIFFERENT ledger_id: a second book.
                    let squatter: Option<String> = tx
                        .query_row(
                            "SELECT ledger_id FROM cirislens_ledger_heads \
                             WHERE owner_key_id = ?1 AND unit = ?2 AND standard_version = ?3",
                            params![owner, unit, sv],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(|e| map_sqlite_error(e, "register_ledger triple re-read"))?;
                    Err(Error::Conflict(format!(
                        "L1 triple ({owner}, {unit}, {sv}) is occupied by ledger {} — \
                         no parallel books within the claim's scope",
                        squatter.unwrap_or_else(|| "<gone>".into())
                    )))
                }
            }
        })()
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
        let now = fmt_datetime(Utc::now());
        let (lid, hash) = (ledger_id.to_owned(), head_hash.to_owned());
        let anchor = witness_anchor_ref.map(str::to_owned);
        let envelope_ref = source_envelope_ref.map(str::to_owned);
        let conn = self.conn.clone();
        (move || -> Result<AdvanceOutcome, Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "advance_head begin"))?;
            let current: Option<(Option<i64>, Option<String>, Option<String>)> = tx
                .query_row(
                    "SELECT seq, head_hash, witness_anchor_ref \
                     FROM cirislens_ledger_heads WHERE ledger_id = ?1",
                    params![lid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "advance_head read"))?;
            let Some((cur_seq, cur_hash, cur_anchor)) = current else {
                return Err(Error::NotFound(format!("ledger {lid} is not registered")));
            };
            let outcome = match (cur_seq, cur_hash) {
                (None, _) => AdvanceOutcome::Advanced,
                (Some(c), _) if seq_i > c => AdvanceOutcome::Advanced,
                (Some(c), Some(h)) if seq_i == c && h == hash => AdvanceOutcome::Unchanged,
                (Some(c), Some(h)) if seq_i == c => {
                    // Fork-shaped: same seq, different hash. The door
                    // refuses and never overwrites — the caller assembles
                    // ForkEvidence from both heads (L8).
                    return Err(Error::Conflict(format!(
                        "fork-shaped head for {lid} at seq {seq}: stored {h}, offered {hash}"
                    )));
                }
                (Some(_), _) => AdvanceOutcome::Stale,
            };
            match outcome {
                AdvanceOutcome::Advanced => {
                    tx.execute(
                        "UPDATE cirislens_ledger_heads SET \
                            seq = ?2, head_hash = ?3, witness_anchor_ref = ?4, \
                            source_envelope_ref = ?5, updated_at = ?6 \
                         WHERE ledger_id = ?1",
                        params![lid, seq_i, hash, anchor, envelope_ref, now],
                    )
                    .map_err(|e| map_sqlite_error(e, "advance_head update"))?;
                }
                AdvanceOutcome::Unchanged => {
                    // Anchor fill-in: a witness anchor arriving for the head
                    // we already hold is real information (L4 anchors after
                    // the head lands). Fill only when currently NULL — an
                    // anchored fact pins, it never flips.
                    if cur_anchor.is_none() && anchor.is_some() {
                        tx.execute(
                            "UPDATE cirislens_ledger_heads SET \
                                witness_anchor_ref = ?2, updated_at = ?3 \
                             WHERE ledger_id = ?1",
                            params![lid, anchor, now],
                        )
                        .map_err(|e| map_sqlite_error(e, "advance_head anchor fill"))?;
                    }
                }
                AdvanceOutcome::Stale => {}
            }
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "advance_head commit"))?;
            Ok(outcome)
        })()
    }

    async fn get_ledger(&self, ledger_id: &str) -> Result<Option<LedgerHeadRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let lid = ledger_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<LedgerHeadRow>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    &format!(
                        "SELECT {HEAD_COLUMNS} FROM cirislens_ledger_heads WHERE ledger_id = ?1"
                    ),
                    params![lid],
                    |row| Ok(decode_head_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_ledger"))?;
            row_opt.transpose()
        })()
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
        let (owner, unit, sv) = (
            owner_key_id.to_owned(),
            unit.to_owned(),
            standard_version.to_owned(),
        );
        let conn = self.conn.clone();
        (move || -> Result<Option<LedgerHeadRow>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    &format!(
                        "SELECT {HEAD_COLUMNS} FROM cirislens_ledger_heads \
                         WHERE owner_key_id = ?1 AND unit = ?2 AND standard_version = ?3"
                    ),
                    params![owner, unit, sv],
                    |row| Ok(decode_head_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "find_ledger_by_triple"))?;
            row_opt.transpose()
        })()
    }

    async fn list_ledgers_for_owner(
        &self,
        owner_key_id: &str,
    ) -> Result<Vec<LedgerHeadRow>, Error> {
        validate::non_empty(owner_key_id, "owner_key_id")?;
        let owner = owner_key_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Vec<LedgerHeadRow>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&format!(
                    "SELECT {HEAD_COLUMNS} FROM cirislens_ledger_heads \
                     WHERE owner_key_id = ?1 ORDER BY ledger_id"
                ))
                .map_err(|e| map_sqlite_error(e, "list_ledgers_for_owner prepare"))?;
            let rows = stmt
                .query_map(params![owner], |row| Ok(decode_head_row(row)))
                .map_err(|e| map_sqlite_error(e, "list_ledgers_for_owner query"))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(|e| map_sqlite_error(e, "list_ledgers_for_owner row"))??);
            }
            Ok(out)
        })()
    }

    async fn put_checkpoint(&self, checkpoint: &LedgerCheckpointRow) -> Result<bool, Error> {
        validate::non_empty(&checkpoint.ledger_id, "ledger_id")?;
        validate::balance_minor(&checkpoint.balance_minor)?;
        validate::witness_refs(&checkpoint.witness_refs)?;
        let seq_i = validate::seq_as_i64(checkpoint.seq, "seq")?;
        let witness_str = serde_json::to_string(&checkpoint.witness_refs)
            .map_err(|e| Error::Internal(format!("witness_refs encode: {e}")))?;
        let now = fmt_datetime(Utc::now());
        let cp = checkpoint.clone();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "put_checkpoint begin"))?;
            let registered: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM cirislens_ledger_heads WHERE ledger_id = ?1",
                    params![cp.ledger_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "put_checkpoint precheck"))?;
            if registered.is_none() {
                return Err(Error::NotFound(format!(
                    "ledger {} is not registered",
                    cp.ledger_id
                )));
            }
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO cirislens_ledger_checkpoints (\
                        ledger_id, seq, balance_minor, witness_refs, \
                        supersedes_ref, source_envelope_ref, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        cp.ledger_id,
                        seq_i,
                        cp.balance_minor,
                        witness_str,
                        cp.supersedes_ref,
                        cp.source_envelope_ref,
                        now
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_checkpoint insert"))?;
            if inserted == 1 {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "put_checkpoint commit"))?;
                return Ok(true);
            }
            // Occupied: identical content ⇒ idempotent no-op; differing ⇒
            // refusal — a witnessed checkpoint pins, it never flips.
            let stored: (String, String, Option<String>) = tx
                .query_row(
                    "SELECT balance_minor, witness_refs, supersedes_ref \
                     FROM cirislens_ledger_checkpoints WHERE ledger_id = ?1 AND seq = ?2",
                    params![cp.ledger_id, seq_i],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(|e| map_sqlite_error(e, "put_checkpoint re-read"))?;
            if stored.0 == cp.balance_minor
                && stored.1 == witness_str
                && stored.2 == cp.supersedes_ref
            {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "put_checkpoint commit"))?;
                return Ok(false);
            }
            Err(Error::Conflict(format!(
                "checkpoint ({}, {}) exists with different content — checkpoints are immutable",
                cp.ledger_id, cp.seq
            )))
        })()
    }

    async fn latest_checkpoint(
        &self,
        ledger_id: &str,
    ) -> Result<Option<LedgerCheckpointRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let lid = ledger_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<LedgerCheckpointRow>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    "SELECT ledger_id, seq, balance_minor, witness_refs, supersedes_ref, \
                            source_envelope_ref, created_at \
                     FROM cirislens_ledger_checkpoints WHERE ledger_id = ?1 \
                     ORDER BY seq DESC LIMIT 1",
                    params![lid],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, String>(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "latest_checkpoint"))?;
            match row_opt {
                None => Ok(None),
                Some((
                    ledger_id,
                    seq,
                    balance_minor,
                    witness_raw,
                    supersedes_ref,
                    env,
                    created,
                )) => Ok(Some(LedgerCheckpointRow {
                    ledger_id,
                    seq: seq as u64,
                    balance_minor,
                    witness_refs: decode_json(&witness_raw)?,
                    supersedes_ref,
                    source_envelope_ref: env,
                    created_at: parse_datetime(&created)?,
                })),
            }
        })()
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
        let now = fmt_datetime(Utc::now());
        let rg = range.clone();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "put_entry_range begin"))?;
            let registered: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM cirislens_ledger_heads WHERE ledger_id = ?1",
                    params![rg.ledger_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "put_entry_range precheck"))?;
            if registered.is_none() {
                return Err(Error::NotFound(format!(
                    "ledger {} is not registered",
                    rg.ledger_id
                )));
            }
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO cirislens_ledger_entry_ranges (\
                        ledger_id, from_seq, to_seq, blob_ref, head_hash_at_to, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        rg.ledger_id,
                        from_i,
                        to_i,
                        rg.blob_ref,
                        rg.head_hash_at_to,
                        now
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_entry_range insert"))?;
            if inserted == 1 {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "put_entry_range commit"))?;
                return Ok(true);
            }
            let stored: (i64, String, String) = tx
                .query_row(
                    "SELECT to_seq, blob_ref, head_hash_at_to \
                     FROM cirislens_ledger_entry_ranges \
                     WHERE ledger_id = ?1 AND from_seq = ?2",
                    params![rg.ledger_id, from_i],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(|e| map_sqlite_error(e, "put_entry_range re-read"))?;
            if stored.0 == to_i && stored.1 == rg.blob_ref && stored.2 == rg.head_hash_at_to {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "put_entry_range commit"))?;
                return Ok(false);
            }
            Err(Error::Conflict(format!(
                "entry range ({}, {}) exists with different content",
                rg.ledger_id, rg.from_seq
            )))
        })()
    }

    async fn list_entry_ranges(&self, ledger_id: &str) -> Result<Vec<LedgerEntryRangeRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let lid = ledger_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Vec<LedgerEntryRangeRow>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT ledger_id, from_seq, to_seq, blob_ref, head_hash_at_to, created_at \
                     FROM cirislens_ledger_entry_ranges WHERE ledger_id = ?1 ORDER BY from_seq",
                )
                .map_err(|e| map_sqlite_error(e, "list_entry_ranges prepare"))?;
            let rows = stmt
                .query_map(params![lid], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })
                .map_err(|e| map_sqlite_error(e, "list_entry_ranges query"))?;
            let mut out = Vec::new();
            for r in rows {
                let (ledger_id, from_seq, to_seq, blob_ref, head_hash_at_to, created) =
                    r.map_err(|e| map_sqlite_error(e, "list_entry_ranges row"))?;
                out.push(LedgerEntryRangeRow {
                    ledger_id,
                    from_seq: from_seq as u64,
                    to_seq: to_seq as u64,
                    blob_ref,
                    head_hash_at_to,
                    created_at: parse_datetime(&created)?,
                });
            }
            Ok(out)
        })()
    }

    async fn record_fork_evidence(&self, evidence: &ForkEvidence) -> Result<String, Error> {
        let evidence_id = fork_evidence_id(evidence).map_err(|e| Error::Internal(e.to_string()))?;
        let seq_i = validate::seq_as_i64(evidence.seq(), "seq")?;
        let evidence_str = serde_json::to_string(evidence)
            .map_err(|e| Error::Internal(format!("evidence encode: {e}")))?;
        let (lid, kind) = (evidence.ledger_id().to_owned(), evidence.fork_kind_str());
        let now = fmt_datetime(Utc::now());
        let eid = evidence_id.clone();
        let conn = self.conn.clone();
        (move || -> Result<String, Error> {
            let guard = conn.lock();
            // The id is a content hash, so INSERT OR IGNORE alone is the
            // whole idempotence story: same evidence ⇒ same id ⇒ one row,
            // and differing content under one id is a hash collision, not
            // a reachable state.
            guard
                .execute(
                    "INSERT OR IGNORE INTO cirislens_ledger_fork_evidence (\
                        evidence_id, ledger_id, seq, fork_kind, evidence_json, detected_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![eid, lid, seq_i, kind, evidence_str, now],
                )
                .map_err(|e| map_sqlite_error(e, "record_fork_evidence insert"))?;
            Ok(eid)
        })()
    }

    async fn list_fork_evidence(&self, ledger_id: &str) -> Result<Vec<ForkEvidenceRow>, Error> {
        validate::non_empty(ledger_id, "ledger_id")?;
        let lid = ledger_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Vec<ForkEvidenceRow>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT evidence_id, ledger_id, seq, fork_kind, evidence_json, detected_at \
                     FROM cirislens_ledger_fork_evidence WHERE ledger_id = ?1 \
                     ORDER BY evidence_id",
                )
                .map_err(|e| map_sqlite_error(e, "list_fork_evidence prepare"))?;
            let rows = stmt
                .query_map(params![lid], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })
                .map_err(|e| map_sqlite_error(e, "list_fork_evidence query"))?;
            let mut out = Vec::new();
            for r in rows {
                let (evidence_id, ledger_id, seq, fork_kind, evidence_raw, detected) =
                    r.map_err(|e| map_sqlite_error(e, "list_fork_evidence row"))?;
                out.push(ForkEvidenceRow {
                    evidence_id,
                    ledger_id,
                    seq: seq as u64,
                    fork_kind,
                    evidence_json: decode_json(&evidence_raw)?,
                    detected_at: parse_datetime(&detected)?,
                });
            }
            Ok(out)
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::super::standard::SignedHead;
    use super::*;
    use crate::store::backend::Backend as _;
    use crate::store::sqlite::SqliteBackend;

    async fn fresh() -> (SqliteBackend, SqliteLedgerBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteLedgerBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn head(ledger_id: &str, seq: u64, hash: &str) -> SignedHead {
        SignedHead {
            ledger_id: ledger_id.into(),
            seq,
            head_hash: hash.into(),
            signature_key_id: "owner-1".into(),
            signature_classical_base64: "c2ln".into(),
            signature_pqc_base64: None,
        }
    }

    #[tokio::test]
    async fn register_is_idempotent_and_the_id_is_derived() {
        let (_b, svc) = fresh().await;
        let (id1, o1) = svc.register_ledger("owner-1", "usd", "1").await.unwrap();
        assert_eq!(o1, RegisterOutcome::Registered);
        assert_eq!(
            id1,
            derive_ledger_id("owner-1", "usd", "1").unwrap(),
            "the service must use THE derivation, not its own spelling"
        );
        let (id2, o2) = svc.register_ledger("owner-1", "usd", "1").await.unwrap();
        assert_eq!(id2, id1);
        assert_eq!(o2, RegisterOutcome::AlreadyRegistered);
        // A different unit is a different ledger, not a conflict (L1 binds
        // the TRIPLE, not the owner).
        let (id3, o3) = svc.register_ledger("owner-1", "eur", "1").await.unwrap();
        assert_ne!(id3, id1);
        assert_eq!(o3, RegisterOutcome::Registered);
    }

    #[tokio::test]
    async fn a_second_book_on_an_occupied_triple_is_refused() {
        let (b, svc) = fresh().await;
        // Forge a row occupying the triple under a DIFFERENT ledger_id —
        // the state a derivation drift or a hostile writer would create.
        {
            let conn = b.conn_handle();
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirislens_ledger_heads (\
                        ledger_id, owner_key_id, unit, standard_version, \
                        created_at, updated_at\
                     ) VALUES ('ledger-forged', 'owner-2', 'usd', '1', \
                               '2026-08-19T00:00:00Z', '2026-08-19T00:00:00Z')",
                    [],
                )
                .unwrap();
        }
        let err = svc
            .register_ledger("owner-2", "usd", "1")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "ledgers_conflict");
        assert!(err.to_string().contains("ledger-forged"), "{err}");
    }

    #[tokio::test]
    async fn advance_head_walks_the_full_outcome_lattice() {
        let (_b, svc) = fresh().await;
        let (id, _) = svc.register_ledger("owner-1", "usd", "1").await.unwrap();

        // Unregistered ledger refuses.
        let err = svc
            .advance_head("ledger-nope", 0, "h0", None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "ledgers_not_found");

        // No head yet: any seq lands (a promotion may first arrive mid-chain).
        assert_eq!(
            svc.advance_head(&id, 4, "h4", None, None).await.unwrap(),
            AdvanceOutcome::Advanced
        );
        // Forward moves.
        assert_eq!(
            svc.advance_head(&id, 7, "h7", Some("anchor-7"), None)
                .await
                .unwrap(),
            AdvanceOutcome::Advanced
        );
        // Identical re-assertion is a no-op.
        assert_eq!(
            svc.advance_head(&id, 7, "h7", Some("anchor-7"), None)
                .await
                .unwrap(),
            AdvanceOutcome::Unchanged
        );
        // A LOWER head is stale, not an error — normal under replication.
        assert_eq!(
            svc.advance_head(&id, 5, "h5", None, None).await.unwrap(),
            AdvanceOutcome::Stale
        );
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row.seq, Some(7));
        assert_eq!(row.head_hash.as_deref(), Some("h7"));

        // Same seq, DIFFERENT hash: the fork shape. Refused, never chosen.
        let err = svc
            .advance_head(&id, 7, "h7-other", None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "ledgers_conflict");
        assert!(err.to_string().contains("fork-shaped"), "{err}");
        // And the stored head did not move — the refusal is the protection.
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row.head_hash.as_deref(), Some("h7"));
    }

    #[tokio::test]
    async fn an_anchor_fills_in_but_never_flips() {
        let (_b, svc) = fresh().await;
        let (id, _) = svc.register_ledger("owner-1", "usd", "1").await.unwrap();
        svc.advance_head(&id, 3, "h3", None, None).await.unwrap();
        // Anchor arrives later for the SAME head: fills in.
        svc.advance_head(&id, 3, "h3", Some("anchor-a"), None)
            .await
            .unwrap();
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row.witness_anchor_ref.as_deref(), Some("anchor-a"));
        // A different anchor for the same head does NOT overwrite.
        svc.advance_head(&id, 3, "h3", Some("anchor-b"), None)
            .await
            .unwrap();
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row.witness_anchor_ref.as_deref(), Some("anchor-a"));
    }

    #[tokio::test]
    async fn checkpoints_are_immutable_and_balance_must_be_canonical() {
        let (_b, svc) = fresh().await;
        let (id, _) = svc.register_ledger("owner-1", "usd", "1").await.unwrap();
        let cp = |balance: &str| LedgerCheckpointRow {
            ledger_id: id.clone(),
            seq: 10,
            balance_minor: balance.into(),
            witness_refs: serde_json::json!(["w1", "w2"]),
            supersedes_ref: None,
            source_envelope_ref: None,
            created_at: Utc::now(),
        };

        // Unregistered ledger refuses before the FK gets a say.
        let mut orphan = cp("5");
        orphan.ledger_id = "ledger-nope".into();
        assert_eq!(
            svc.put_checkpoint(&orphan).await.unwrap_err().kind(),
            "ledgers_not_found"
        );

        // Non-canonical decimals are refused — each a distinct spelling of
        // the same byte-equality failure.
        for bad in ["+5", "007", "-0", " 5", "5 ", "0x5", ""] {
            let err = svc.put_checkpoint(&cp(bad)).await.unwrap_err();
            assert_eq!(err.kind(), "ledgers_invalid_argument", "balance {bad:?}");
        }
        // Canonical negatives are fine — a net position may owe.
        assert!(svc.put_checkpoint(&cp("-42")).await.unwrap());
        // Identical re-put: idempotent no-op.
        assert!(!svc.put_checkpoint(&cp("-42")).await.unwrap());
        // Differing content at the same (ledger, seq): pinned, never flips.
        let err = svc.put_checkpoint(&cp("-41")).await.unwrap_err();
        assert_eq!(err.kind(), "ledgers_conflict");

        let latest = svc.latest_checkpoint(&id).await.unwrap().unwrap();
        assert_eq!(latest.seq, 10);
        assert_eq!(latest.balance_minor, "-42");
        assert_eq!(latest.witness_refs, serde_json::json!(["w1", "w2"]));
    }

    #[tokio::test]
    async fn entry_ranges_index_the_chain_blobs() {
        let (_b, svc) = fresh().await;
        let (id, _) = svc.register_ledger("owner-1", "usd", "1").await.unwrap();
        let rg = LedgerEntryRangeRow {
            ledger_id: id.clone(),
            from_seq: 0,
            to_seq: 9,
            blob_ref: "blob-0-9".into(),
            head_hash_at_to: "h9".into(),
            created_at: Utc::now(),
        };
        assert!(svc.put_entry_range(&rg).await.unwrap());
        assert!(!svc.put_entry_range(&rg).await.unwrap());
        let mut differing = rg.clone();
        differing.blob_ref = "blob-other".into();
        assert_eq!(
            svc.put_entry_range(&differing).await.unwrap_err().kind(),
            "ledgers_conflict"
        );
        let mut inverted = rg.clone();
        inverted.from_seq = 10;
        inverted.to_seq = 9;
        assert_eq!(
            svc.put_entry_range(&inverted).await.unwrap_err().kind(),
            "ledgers_invalid_argument"
        );
        let ranges = svc.list_entry_ranges(&id).await.unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].blob_ref, "blob-0-9");
    }

    #[tokio::test]
    async fn fork_evidence_is_idempotent_and_needs_no_registration() {
        let (_b, svc) = fresh().await;
        // Deliberately about a ledger this node never registered — a fork
        // report must not be droppable for lack of a local head row.
        let ev = crate::ledgers::standard::detect_double_head(
            &head("ledger-elsewhere", 7, "hash-a"),
            &head("ledger-elsewhere", 7, "hash-b"),
        )
        .expect("two different hashes at one seq are a fork");
        let id1 = svc.record_fork_evidence(&ev).await.unwrap();
        let id2 = svc.record_fork_evidence(&ev).await.unwrap();
        assert_eq!(id1, id2, "content-derived id: one fork, one row");
        assert_eq!(id1, fork_evidence_id(&ev).unwrap());
        let rows = svc.list_fork_evidence("ledger-elsewhere").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fork_kind, "double_head");
        assert_eq!(rows[0].seq, 7);
        // The stored evidence round-trips to the typed record.
        let back: ForkEvidence = serde_json::from_value(rows[0].evidence_json.clone()).unwrap();
        assert_eq!(back, ev);
    }

    /// **The ACID witnesses** (CIRISPersist#754) — Atomicity, Consistency,
    /// Isolation, Durability, exercised through the exposed `LedgerService`
    /// surface and nothing else. A ledger substrate whose ACID story is
    /// asserted in prose is a ledger substrate with no ACID story; CC
    /// 3.3.10.1's whole design leans on "ACID within the ledger is trivial"
    /// (single writer), so the doors that MAKE it trivial are what these
    /// witness.
    ///
    /// DURABILITY: the working index survives a full close-and-reopen from
    /// disk — not `open_in_memory`, an actual file, a dropped backend, a
    /// second open.
    #[tokio::test]
    async fn acid_durability_rows_survive_reopen_from_disk() {
        let dir = std::env::temp_dir().join(format!("ciris-ledgers-acid-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledgers.db").to_string_lossy().into_owned();

        let (id, before_cp, before_rg) = {
            let backend = SqliteBackend::open(&path).await.unwrap();
            backend.run_migrations().await.unwrap();
            let svc = SqliteLedgerBackend::new(backend.conn_handle());
            let (id, _) = svc.register_ledger("owner-d", "usd", "1").await.unwrap();
            svc.advance_head(&id, 9, "h9", Some("anchor-9"), None)
                .await
                .unwrap();
            let cp = LedgerCheckpointRow {
                ledger_id: id.clone(),
                seq: 5,
                balance_minor: "12".into(),
                witness_refs: serde_json::json!(["w"]),
                supersedes_ref: None,
                source_envelope_ref: None,
                created_at: Utc::now(),
            };
            svc.put_checkpoint(&cp).await.unwrap();
            let rg = LedgerEntryRangeRow {
                ledger_id: id.clone(),
                from_seq: 0,
                to_seq: 9,
                blob_ref: "blob".into(),
                head_hash_at_to: "h9".into(),
                created_at: Utc::now(),
            };
            svc.put_entry_range(&rg).await.unwrap();
            let cp_read = svc.latest_checkpoint(&id).await.unwrap().unwrap();
            let rg_read = svc.list_entry_ranges(&id).await.unwrap();
            (id, cp_read, rg_read)
            // backend dropped HERE — the connection closes.
        };

        let backend = SqliteBackend::open(&path).await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteLedgerBackend::new(backend.conn_handle());
        let row = svc.get_ledger(&id).await.unwrap().expect("survived reopen");
        assert_eq!(row.seq, Some(9));
        assert_eq!(row.head_hash.as_deref(), Some("h9"));
        assert_eq!(row.witness_anchor_ref.as_deref(), Some("anchor-9"));
        assert_eq!(
            svc.latest_checkpoint(&id).await.unwrap().unwrap(),
            before_cp
        );
        assert_eq!(svc.list_entry_ranges(&id).await.unwrap(), before_rg);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ISOLATION: sixteen tasks race the SAME L1 triple through the real
    /// door. Exactly one registration happens; every loser sees the
    /// idempotent no-op; nobody errors; one row exists. Then eight tasks
    /// race one sequence number with TWO different hashes — the fork shape
    /// under contention: the stored head is exactly ONE of the offered
    /// hashes (never a blend, never a flip-flop), and every task got
    /// Advanced, Unchanged, or the fork Conflict — no fourth outcome.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn acid_isolation_concurrent_doors_never_blend() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = std::sync::Arc::new(SqliteLedgerBackend::new(backend.conn_handle()));

        let mut regs = Vec::new();
        for _ in 0..16 {
            let svc = svc.clone();
            regs.push(tokio::spawn(async move {
                svc.register_ledger("owner-i", "usd", "1").await
            }));
        }
        let mut registered = 0;
        let mut already = 0;
        let mut id = String::new();
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

        // The fork race: same seq, two camps of hashes.
        let mut advances = Vec::new();
        for i in 0..8 {
            let svc = svc.clone();
            let id = id.clone();
            let hash = if i % 2 == 0 { "hash-a" } else { "hash-b" };
            advances.push(tokio::spawn(async move {
                svc.advance_head(&id, 3, hash, None, None).await
            }));
        }
        let mut conflicts = 0;
        for a in advances {
            match a.await.unwrap() {
                Ok(AdvanceOutcome::Advanced | AdvanceOutcome::Unchanged) => {}
                Ok(AdvanceOutcome::Stale) => panic!("nothing here is stale"),
                Err(e) => {
                    assert_eq!(e.kind(), "ledgers_conflict", "{e}");
                    conflicts += 1;
                }
            }
        }
        assert!(conflicts >= 1, "the two camps must have collided");
        let row = svc.get_ledger(&id).await.unwrap().unwrap();
        assert_eq!(row.seq, Some(3));
        assert!(
            row.head_hash.as_deref() == Some("hash-a")
                || row.head_hash.as_deref() == Some("hash-b"),
            "the stored head is one of the offered hashes, never a blend: {:?}",
            row.head_hash
        );
        // CONSISTENCY under the storm: the schema's pairing invariant holds
        // on what the surface returns.
        assert_eq!(row.seq.is_some(), row.head_hash.is_some());
    }

    /// ATOMICITY: a refused door leaves NO partial state. The checkpoint
    /// conflict leaves the original checkpoint byte-identical; the L1
    /// conflict writes nothing under the derived id and leaves the squatter
    /// untouched.
    #[tokio::test]
    async fn acid_atomicity_a_refusal_writes_nothing() {
        let (b, svc) = fresh().await;
        let (id, _) = svc.register_ledger("owner-a", "usd", "1").await.unwrap();
        let cp = LedgerCheckpointRow {
            ledger_id: id.clone(),
            seq: 4,
            balance_minor: "10".into(),
            witness_refs: serde_json::json!(["w1"]),
            supersedes_ref: None,
            source_envelope_ref: None,
            created_at: Utc::now(),
        };
        svc.put_checkpoint(&cp).await.unwrap();
        let stored = svc.latest_checkpoint(&id).await.unwrap().unwrap();
        let mut differing = cp.clone();
        differing.balance_minor = "11".into();
        differing.witness_refs = serde_json::json!(["w2"]);
        assert_eq!(
            svc.put_checkpoint(&differing).await.unwrap_err().kind(),
            "ledgers_conflict"
        );
        assert_eq!(
            svc.latest_checkpoint(&id).await.unwrap().unwrap(),
            stored,
            "a refused checkpoint must not half-land"
        );

        // L1 refusal writes nothing: forge a squatter on a fresh triple,
        // refuse the registration, then verify NEITHER row moved.
        {
            let conn = b.conn_handle();
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirislens_ledger_heads (                        ledger_id, owner_key_id, unit, standard_version,                         created_at, updated_at                     ) VALUES ('ledger-squat', 'owner-b', 'usd', '1',                                '2026-08-19T00:00:00Z', '2026-08-19T00:00:00Z')",
                    [],
                )
                .unwrap();
        }
        assert_eq!(
            svc.register_ledger("owner-b", "usd", "1")
                .await
                .unwrap_err()
                .kind(),
            "ledgers_conflict"
        );
        let derived = derive_ledger_id("owner-b", "usd", "1").unwrap();
        assert!(
            svc.get_ledger(&derived).await.unwrap().is_none(),
            "the refused registration must not have landed a row"
        );
        assert!(svc.get_ledger("ledger-squat").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn seqs_beyond_i64_are_refused_not_wrapped() {
        let (_b, svc) = fresh().await;
        let (id, _) = svc.register_ledger("owner-1", "usd", "1").await.unwrap();
        let err = svc
            .advance_head(&id, u64::MAX, "h", None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "ledgers_invalid_argument");
    }
}
