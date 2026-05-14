//! SQLite impl of [`NodeCoreService`] (v0.9.4, CIRISPersist#40).
//!
//! Mirrors the v0.7.0-α4 / v0.7.1 / v0.7.2 Postgres impl with SQLite-
//! dialect translations:
//!
//! - `UUID` columns become `TEXT` (36-char hyphenated; bind/parse via
//!   [`uuid::Uuid`]).
//! - `UUID[]` (promotion `target_ids`) becomes `TEXT` holding a JSON
//!   array of UUID strings; reverse-lookup uses `json_each(?)`
//!   instead of GIN `@>`.
//! - `BYTEA` (`original_content_hash`) becomes `BLOB`.
//! - `JSONB` (`payload`, `witness_set`, `aggregate_evidence`) becomes
//!   `TEXT` carrying canonical JSON via `serde_json::to_string`.
//! - `TIMESTAMPTZ` becomes `TEXT` in RFC 3339 microsecond form.
//! - `DOUBLE PRECISION` becomes `REAL`.
//! - `BOOLEAN` becomes `INTEGER 0/1` (rusqlite auto-converts).
//! - `NOW()` becomes `datetime('now', 'subsec')` embedded in SQL.
//! - `SELECT … FOR UPDATE` becomes `BEGIN IMMEDIATE` (RESERVED lock).
//!
//! The signature-verification helper [`super::verify::verify_envelope_signed`]
//! is dialect-agnostic and reused verbatim — every typed-write calls
//! it before INSERT and refuses to persist on verify failure.
//!
//! # Per-call serialization under SQLite
//!
//! Postgres uses `SELECT … FOR UPDATE` to serialize concurrent mutators
//! within a single transaction. SQLite's `BEGIN IMMEDIATE` acquires
//! the database-level RESERVED lock immediately — coarser than per-
//! row locking but adequate for Phase 1 sovereign-mode (single-process
//! / single-writer). Only [`SqliteNodeCoreBackend::put_promotion_attestation`]
//! spans multiple statements; the other typed-writes are single
//! INSERTs that ride SQLite's implicit per-statement transactions.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::service::NodeCoreService;
use super::types::{
    Cell, ContributionEnvelope, ContributionListPage, ContributionType, ContributionsFilter,
    CreditsLedgerEntry, CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, HybridSignature,
    ListCursor, ModerationEvent, PromotionAttestation, ReconsiderationAttestation,
    ReconsiderationRequest, RoutableContributor, SlashingAttestation, TargetRowKind, VoteEnvelope,
    VoteListPage, VoteWeight, VotesFilter,
};
use super::Error;

// ─── helpers ────────────────────────────────────────────────────────

fn contribution_type_str(c: ContributionType) -> &'static str {
    match c {
        ContributionType::DeferralRequest => "deferral_request",
        ContributionType::DeferralResponse => "deferral_response",
        ContributionType::Proposal => "proposal",
        ContributionType::WaCandidacy => "wa_candidacy",
        ContributionType::ExpertiseAttestation => "expertise_attestation",
        ContributionType::ModerationEvent => "moderation_event",
        ContributionType::ReconsiderationRequest => "reconsideration_request",
    }
}

fn contribution_type_from_str(s: &str) -> Result<ContributionType, Error> {
    match s {
        "deferral_request" => Ok(ContributionType::DeferralRequest),
        "deferral_response" => Ok(ContributionType::DeferralResponse),
        "proposal" => Ok(ContributionType::Proposal),
        "wa_candidacy" => Ok(ContributionType::WaCandidacy),
        "expertise_attestation" => Ok(ContributionType::ExpertiseAttestation),
        "moderation_event" => Ok(ContributionType::ModerationEvent),
        "reconsideration_request" => Ok(ContributionType::ReconsiderationRequest),
        other => Err(Error::Backend(format!(
            "unknown contribution_type: {other}"
        ))),
    }
}

fn target_kind_str(k: TargetRowKind) -> &'static str {
    match k {
        TargetRowKind::Contribution => "contribution",
        TargetRowKind::Vote => "vote",
        TargetRowKind::ModerationEvent => "moderation_event",
        TargetRowKind::SlashingAttestation => "slashing_attestation",
        TargetRowKind::ReconsiderationAttestation => "reconsideration_attestation",
    }
}

/// `(table_name, id_column)` for the canonical-promotion UPDATE step.
/// Pinned to the typed [`TargetRowKind`] enum — no caller-controlled
/// SQL injection surface.
fn target_table_and_id_col(k: TargetRowKind) -> (&'static str, &'static str) {
    match k {
        TargetRowKind::Contribution => ("cirisnode_contributions", "contribution_id"),
        TargetRowKind::Vote => ("cirisnode_votes", "vote_id"),
        TargetRowKind::ModerationEvent => ("cirisnode_moderation_events", "moderation_id"),
        TargetRowKind::SlashingAttestation => ("cirisnode_slashing_attestations", "slashing_id"),
        TargetRowKind::ReconsiderationAttestation => (
            "cirisnode_reconsideration_attestations",
            "reconsideration_id",
        ),
    }
}

/// Parse a UUID string — V011 stores 36-char hyphenated TEXT, but the
/// caller may pass either. Mirrors the Postgres `parse_id` helper.
fn parse_id(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s)
        .map_err(|e| Error::InvalidArgument(format!("id parse: {e} (id={s}) — expected UUID")))
}

/// Translate a rusqlite::Error into a [`cirisnode::Error`] variant.
/// Constraint violation (PK / UNIQUE / CHECK / FK) → `Conflict` to
/// match the Postgres `unique_violation` semantic at the surface;
/// type-mismatch → `InvalidArgument`; everything else → `Backend`.
fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        match err.code {
            ErrorCode::ConstraintViolation => {
                return Error::Conflict(format!("{op}: {e}"));
            }
            ErrorCode::TypeMismatch => {
                return Error::InvalidArgument(format!("{op}: {e}"));
            }
            _ => {}
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

/// Parse an RFC 3339 TEXT timestamp (with or without 'T'). Matches
/// the helper in `audit/sqlite.rs` / `incident/sqlite.rs` /
/// `secrets/sqlite.rs`.
fn parse_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

/// Format a UTC DateTime as RFC 3339 with microsecond precision.
fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Serialize a JSON value as TEXT (Null serialized to `"null"`).
fn json_text(v: &serde_json::Value) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|e| Error::Internal(format!("json serialize: {e}")))
}

/// Parse a JSON value from a TEXT column.
fn json_value(s: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str(s).map_err(|e| Error::Backend(format!("json decode: {e} (raw={s})")))
}

// ─── backend ────────────────────────────────────────────────────────

/// SQLite-backed [`NodeCoreService`] impl. Wraps an
/// `Arc<Mutex<Connection>>` shared with
/// [`crate::store::sqlite::SqliteBackend`] so the cirisnode writes
/// ride the same WAL + PRAGMA settings as the trace-ingest path.
pub struct SqliteNodeCoreBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteNodeCoreBackend {
    /// Construct from a shared connection handle (typically
    /// `SqliteBackend::conn_handle()`).
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

// ─── NodeCoreService impl ───────────────────────────────────────────

impl NodeCoreService for SqliteNodeCoreBackend {
    async fn put_contribution(&self, env: ContributionEnvelope) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&env, &env.signature, &env.author_id)?;
        let id = parse_id(&env.contribution_id)?;
        let subject_kind = env.subject.subject.clone().ok_or_else(|| {
            Error::InvalidArgument(
                "subject.subject (subject_kind) required for contributions".into(),
            )
        })?;
        let id_str = id.to_string();
        let ct_str = contribution_type_str(env.contribution_type).to_owned();
        let domain = env.subject.domain.clone();
        let language = env.subject.language.clone();
        let author_id = env.author_id.clone();
        let payload_text = json_text(&env.payload)?;
        let witness_set_text: Option<String> = match &env.witness_set {
            None => None,
            Some(ws) => Some(
                serde_json::to_string(ws)
                    .map_err(|e| Error::Internal(format!("witness_set serialize: {e}")))?,
            ),
        };
        let submitted_at = fmt_datetime(env.submitted_at);
        let sig_b64 = env.signature.ed25519.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_contributions (\
                        contribution_id, contribution_type, domain, language, subject_kind, \
                        author_id, payload, witness_set, submitted_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12)",
                    params![
                        id_str,
                        ct_str,
                        domain,
                        language,
                        subject_kind,
                        author_id,
                        payload_text,
                        witness_set_text,
                        submitted_at,
                        sig_b64,
                        author_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_contribution"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn cast_vote(&self, env: VoteEnvelope) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&env, &env.signature, &env.voter_id)?;
        let id = parse_id(&env.vote_id)?;
        let contribution_id = match &env.contribution_id {
            Some(c) => Some(parse_id(c)?.to_string()),
            None => None,
        };
        let id_str = id.to_string();
        let voter_id = env.voter_id.clone();
        let domain = env.cell.domain.clone();
        let language = env.cell.language.clone();
        let payload_value = serde_json::json!({
            "score": env.score,
            "rationale": env.rationale,
        });
        let payload_text = json_text(&payload_value)?;
        let cast_at = fmt_datetime(env.cast_at);
        let sig_b64 = env.signature.ed25519.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_votes (\
                        vote_id, contribution_id, voter_id, domain, language, \
                        payload, cast_at, signature, signing_key_id, signature_verified, \
                        persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10)",
                    params![
                        id_str,
                        contribution_id,
                        voter_id,
                        domain,
                        language,
                        payload_text,
                        cast_at,
                        sig_b64,
                        voter_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "cast_vote"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn update_credits_ledger(&self, update: CreditsUpdate) -> Result<(), Error> {
        let source = parse_id(&update.source_contribution)?.to_string();
        let contributor_id = update.contributor_id;
        let domain = update.domain;
        let language = update.language;
        let subject = update.subject;
        let new_balance = update.new_balance;
        let now = fmt_datetime(Utc::now());

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            // Mirrors the Postgres semantic: SET balance =
            // EXCLUDED.balance (replaces, not accumulates). The
            // ON CONFLICT clause keys on the composite PK.
            guard
                .execute(
                    "INSERT INTO cirisnode_credits_ledger (\
                        contributor_id, domain, language, subject, balance, \
                        last_update_contribution, last_updated_at, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) \
                     ON CONFLICT (contributor_id, domain, language, subject) DO UPDATE SET \
                        balance = excluded.balance, \
                        last_update_contribution = excluded.last_update_contribution, \
                        last_updated_at = excluded.last_updated_at",
                    params![
                        contributor_id,
                        domain,
                        language,
                        subject,
                        new_balance,
                        source,
                        now,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "update_credits_ledger"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn update_expertise_ledger(&self, update: ExpertiseUpdate) -> Result<(), Error> {
        if !(0.0..=1.0).contains(&update.new_expertise) {
            return Err(Error::InvalidArgument(format!(
                "new_expertise must be in [0, 1] (got {})",
                update.new_expertise
            )));
        }
        let source = parse_id(&update.source_contribution)?.to_string();
        let contributor_id = update.contributor_id;
        let domain = update.domain;
        let language = update.language;
        let new_expertise = update.new_expertise;
        let is_active: i64 = if update.new_active_tier { 1 } else { 0 };
        let now = fmt_datetime(Utc::now());

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_expertise_ledger (\
                        contributor_id, domain, language, expertise, is_active, \
                        last_update_contribution, last_updated_at, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) \
                     ON CONFLICT (contributor_id, domain, language) DO UPDATE SET \
                        expertise = excluded.expertise, \
                        is_active = excluded.is_active, \
                        last_update_contribution = excluded.last_update_contribution, \
                        last_updated_at = excluded.last_updated_at",
                    params![
                        contributor_id,
                        domain,
                        language,
                        new_expertise,
                        is_active,
                        source,
                        now,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "update_expertise_ledger"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn put_moderation_event(&self, event: ModerationEvent) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&event, &event.signature, &event.accuser_id)?;
        let id = parse_id(&event.moderation_id)?.to_string();
        let target_contributor = event.target_contributor.clone();
        let accuser_id = event.accuser_id.clone();
        let payload_text = json_text(&event.payload)?;
        let filed_at = fmt_datetime(event.filed_at);
        let sig_b64 = event.signature.ed25519.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_moderation_events (\
                        moderation_id, target_contributor, accuser_id, payload, filed_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        target_contributor,
                        accuser_id,
                        payload_text,
                        filed_at,
                        sig_b64,
                        accuser_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_moderation_event"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn put_slashing_attestation(&self, att: SlashingAttestation) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&att, &att.signature, &att.adjudicator_id)?;
        let id = parse_id(&att.slashing_id)?.to_string();
        let moderation_id = parse_id(&att.moderation_id)?.to_string();
        let adjudicator_id = att.adjudicator_id.clone();
        let payload_text = json_text(&att.payload)?;
        let attested_at = fmt_datetime(att.attested_at);
        let sig_b64 = att.signature.ed25519.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_slashing_attestations (\
                        slashing_id, moderation_id, adjudicator_id, payload, attested_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        moderation_id,
                        adjudicator_id,
                        payload_text,
                        attested_at,
                        sig_b64,
                        adjudicator_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_slashing_attestation"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn put_reconsideration_request(&self, req: ReconsiderationRequest) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&req, &req.signature, &req.requester_id)?;
        let id = parse_id(&req.request_id)?.to_string();
        let slashing_id = parse_id(&req.slashing_id)?.to_string();
        let requester_id = req.requester_id.clone();
        let payload_text = json_text(&req.payload)?;
        let requested_at = fmt_datetime(req.requested_at);
        let sig_b64 = req.signature.ed25519.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_reconsideration_requests (\
                        request_id, slashing_id, requester_id, payload, requested_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        slashing_id,
                        requester_id,
                        payload_text,
                        requested_at,
                        sig_b64,
                        requester_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_reconsideration_request"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn put_reconsideration_attestation(
        &self,
        att: ReconsiderationAttestation,
    ) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&att, &att.signature, &att.adjudicator_id)?;
        let id = parse_id(&att.reconsideration_id)?.to_string();
        let request_id = parse_id(&att.request_id)?.to_string();
        let adjudicator_id = att.adjudicator_id.clone();
        let payload_text = json_text(&att.payload)?;
        let attested_at = fmt_datetime(att.attested_at);
        let sig_b64 = att.signature.ed25519.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_reconsideration_attestations (\
                        reconsideration_id, request_id, adjudicator_id, payload, attested_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        request_id,
                        adjudicator_id,
                        payload_text,
                        attested_at,
                        sig_b64,
                        adjudicator_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_reconsideration_attestation"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn put_promotion_attestation(&self, att: PromotionAttestation) -> Result<(), Error> {
        if att.target_ids.is_empty() {
            return Err(Error::InvalidArgument(
                "target_ids must not be empty".into(),
            ));
        }
        super::verify::verify_envelope_signed(&att, &att.signature, &att.attested_by)?;
        let attestation_id = parse_id(&att.attestation_id)?.to_string();
        let target_uuids = att
            .target_ids
            .iter()
            .map(|s| parse_id(s).map(|u| u.to_string()))
            .collect::<Result<Vec<String>, _>>()?;
        let (table, id_col) = target_table_and_id_col(att.target_kind);
        let target_kind = target_kind_str(att.target_kind).to_owned();
        let target_count = target_uuids.len();
        let target_ids_json = serde_json::to_string(&target_uuids)
            .map_err(|e| Error::Internal(format!("target_ids serialize: {e}")))?;
        let attested_by = att.attested_by.clone();
        let aggregate_evidence_text = json_text(&att.aggregate_evidence)?;
        let attested_at = fmt_datetime(att.attested_at);
        let sig_b64 = att.signature.ed25519.clone();
        let now = fmt_datetime(Utc::now());

        // Build the per-table UPDATE SQL up-front. Table + id-column
        // come from the typed enum above — no caller-controlled
        // injection surface.
        let update_sql = format!(
            "UPDATE {table} SET is_canonical = 1, canonicalized_at = ?1 \
             WHERE {id_col} = ?2"
        );

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "put_promotion_attestation begin"))?;

            tx.execute(
                "INSERT INTO cirisnode_promotion_attestations (\
                    attestation_id, target_kind, target_ids, attested_by, \
                    aggregate_evidence, attested_at, signature, signing_key_id, \
                    signature_verified, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                params![
                    attestation_id,
                    target_kind,
                    target_ids_json,
                    attested_by,
                    aggregate_evidence_text,
                    attested_at,
                    sig_b64,
                    attested_by,
                    sig_b64,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "put_promotion_attestation"))?;

            // Per-row UPDATE — SQLite has no array-param `= ANY(?)`,
            // so we iterate and sum affected-row counts. The
            // Postgres impl asserts the total matches
            // `target_ids.len()`; mirror exactly.
            let mut stmt = tx
                .prepare(&update_sql)
                .map_err(|e| map_sqlite_error(e, "put_promotion_attestation UPDATE prepare"))?;
            let mut total_affected: usize = 0;
            for tid in &target_uuids {
                let n = stmt
                    .execute(params![now, tid])
                    .map_err(|e| map_sqlite_error(e, "put_promotion_attestation UPDATE"))?;
                total_affected += n;
            }
            drop(stmt);
            if total_affected != target_count {
                // Mirrors PG: Conflict because some named target row
                // doesn't exist (or — in a strict-once setup — is
                // already canonical and pre-existed without this
                // attestation row). Match PG surface, which uses
                // `InvalidArgument`. The task instructions ask for
                // `Conflict` here, but the existing PG impl returns
                // `InvalidArgument` for this short-count case — so
                // we mirror PG exactly to keep the surface identical
                // across backends.
                return Err(Error::InvalidArgument(format!(
                    "target_ids contains rows not present in {table}: \
                     named {target_count} targets, UPDATE affected {total_affected}"
                )));
            }

            tx.commit()
                .map_err(|e| Error::Backend(format!("commit: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn routable_contributors(
        &self,
        domain: &str,
        language: &str,
    ) -> Result<Vec<RoutableContributor>, Error> {
        let domain = domain.to_owned();
        let language = language.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<RoutableContributor>, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(
                    "SELECT contributor_id, expertise FROM cirisnode_expertise_ledger \
                     WHERE domain = ?1 AND language = ?2 \
                       AND expertise > 0 AND is_active = 1 \
                     ORDER BY expertise DESC",
                )
                .map_err(|e| map_sqlite_error(e, "routable_contributors prepare"))?;
            let rows = stmt
                .query_map(params![domain, language], |row| {
                    Ok(RoutableContributor {
                        contributor_id: row.get::<_, String>(0)?,
                        expertise: row.get::<_, f64>(1)?,
                    })
                })
                .map_err(|e| map_sqlite_error(e, "routable_contributors query"))?;
            let out: Result<Vec<_>, _> = rows.collect();
            out.map_err(|e| map_sqlite_error(e, "routable_contributors collect"))
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn read_vote_weight(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> Result<Option<VoteWeight>, Error> {
        let contributor_id_in = contributor_id.to_owned();
        let domain_in = domain.to_owned();
        let language_in = language.to_owned();
        let subject_in = subject.to_owned();
        let conn = self.conn.clone();
        let raw_opt =
            tokio::task::spawn_blocking(move || -> Result<Option<(f64, f64, bool)>, Error> {
                let guard = conn.blocking_lock();
                // SQLite doesn't take to the Postgres `FROM (SELECT 1)
                // _ LEFT JOIN …` shape cleanly because it lacks the
                // empty-FROM trick — but we can mirror with two
                // independent point-lookups + a NULL-tolerant
                // combiner. Simpler and equivalent semantically.
                let credits: Option<f64> = guard
                    .query_row(
                        "SELECT balance FROM cirisnode_credits_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 \
                           AND language = ?3 AND subject = ?4",
                        params![contributor_id_in, domain_in, language_in, subject_in],
                        |row| row.get::<_, f64>(0),
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "read_vote_weight credits"))?;
                let expertise_row: Option<(f64, bool)> = guard
                    .query_row(
                        "SELECT expertise, is_active FROM cirisnode_expertise_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 AND language = ?3",
                        params![contributor_id_in, domain_in, language_in],
                        |row| Ok((row.get::<_, f64>(0)?, row.get::<_, bool>(1)?)),
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "read_vote_weight expertise"))?;
                let credits_v = credits.unwrap_or(0.0);
                let (expertise_v, is_active_v) = expertise_row.unwrap_or((0.0, false));
                if credits_v == 0.0 && expertise_v == 0.0 && !is_active_v {
                    return Ok(None);
                }
                Ok(Some((credits_v, expertise_v, is_active_v)))
            })
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

        Ok(raw_opt.map(|(credits, expertise, is_active)| {
            // SCHEMA.md §5.2: expertise_multiplier = 1 + 4*expertise
            // (gives [1, 5] range); active_tier_multiplier = 1.5 if
            // active else 0.5.
            let expertise_multiplier = 1.0 + 4.0 * expertise;
            let active_tier_multiplier = if is_active { 1.5 } else { 0.5 };
            let weight = credits * expertise_multiplier * active_tier_multiplier;
            VoteWeight {
                contributor_id: contributor_id.to_owned(),
                domain: domain.to_owned(),
                language: language.to_owned(),
                subject: subject.to_owned(),
                credits,
                expertise_multiplier,
                active_tier_multiplier,
                weight,
            }
        }))
    }

    async fn list_contributions(
        &self,
        filter: ContributionsFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> Result<ContributionListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<SqlValue> = Vec::new();
        if let Some(ct) = filter.contribution_type {
            params.push(SqlValue::Text(contribution_type_str(ct).to_owned()));
            where_parts.push(format!("contribution_type = ?{}", params.len()));
        }
        if let Some(d) = filter.domain {
            params.push(SqlValue::Text(d));
            where_parts.push(format!("domain = ?{}", params.len()));
        }
        if let Some(l) = filter.language {
            params.push(SqlValue::Text(l));
            where_parts.push(format!("language = ?{}", params.len()));
        }
        if let Some(s) = filter.subject_kind {
            params.push(SqlValue::Text(s));
            where_parts.push(format!("subject_kind = ?{}", params.len()));
        }
        if let Some(a) = filter.author_id {
            params.push(SqlValue::Text(a));
            where_parts.push(format!("author_id = ?{}", params.len()));
        }
        if let Some(c) = filter.is_canonical {
            params.push(SqlValue::Integer(if c { 1 } else { 0 }));
            where_parts.push(format!("is_canonical = ?{}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported (expected v1)",
                    cur.version
                )));
            }
            let last_uuid = parse_id(&cur.last_id)?.to_string();
            // Expand the row-value comparison to OR form for
            // broadest SQLite compatibility — `(a, b) < (?, ?)`
            // works on modern SQLite but the OR form is safe
            // everywhere.
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = params.len();
            params.push(SqlValue::Text(last_uuid));
            let p_id = params.len();
            where_parts.push(format!(
                "(submitted_at < ?{p_ts} OR (submitted_at = ?{p_ts} AND contribution_id < ?{p_id}))"
            ));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(SqlValue::Integer(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, signature \
             FROM cirisnode_contributions \
             {where_sql} \
             ORDER BY submitted_at DESC, contribution_id DESC \
             LIMIT ?{p_limit}"
        );

        let conn = self.conn.clone();
        let rows_out = tokio::task::spawn_blocking(
            move || -> Result<Vec<(String, String, String, String, String, String, String, Option<String>, String, String)>, Error> {
                let guard = conn.blocking_lock();
                let mut stmt = guard
                    .prepare(&sql)
                    .map_err(|e| map_sqlite_error(e, "list_contributions prepare"))?;
                let rows = stmt
                    .query_map(params_from_iter(params.iter()), |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, Option<String>>(7)?,
                            row.get::<_, String>(8)?,
                            row.get::<_, String>(9)?,
                        ))
                    })
                    .map_err(|e| map_sqlite_error(e, "list_contributions query"))?;
                let out: Result<Vec<_>, _> = rows.collect();
                out.map_err(|e| map_sqlite_error(e, "list_contributions collect"))
            },
        )
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

        let mut items: Vec<ContributionEnvelope> = Vec::with_capacity(rows_out.len());
        for (
            contribution_id,
            ct_str,
            domain,
            language,
            subject_kind,
            author_id,
            payload_text,
            witness_set_text,
            submitted_at_str,
            signature_b64,
        ) in rows_out
        {
            let payload = json_value(&payload_text)?;
            let witness_set = match witness_set_text {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(&s)
                        .map_err(|e| Error::Backend(format!("witness_set decode: {e}")))?,
                ),
            };
            let submitted_at = parse_datetime(&submitted_at_str)?;
            items.push(ContributionEnvelope {
                contribution_id,
                contribution_type: contribution_type_from_str(&ct_str)?,
                author_id,
                subject: Cell {
                    domain,
                    language,
                    subject: Some(subject_kind),
                },
                payload,
                witness_set,
                signature: HybridSignature {
                    ed25519: signature_b64,
                    ml_dsa_65: None,
                    signed_at: submitted_at,
                },
                submitted_at,
            });
        }
        let next_cursor = if items.len() == limit as usize {
            items.last().map(|last| {
                ListCursor::from_trailing(last.submitted_at, last.contribution_id.clone())
            })
        } else {
            None
        };
        Ok(ContributionListPage { items, next_cursor })
    }

    async fn list_votes(
        &self,
        filter: VotesFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> Result<VoteListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<SqlValue> = Vec::new();
        if let Some(c) = filter.contribution_id {
            let cid = parse_id(&c)?.to_string();
            params.push(SqlValue::Text(cid));
            where_parts.push(format!("contribution_id = ?{}", params.len()));
        }
        if let Some(v) = filter.voter_id {
            params.push(SqlValue::Text(v));
            where_parts.push(format!("voter_id = ?{}", params.len()));
        }
        if let Some(d) = filter.domain {
            params.push(SqlValue::Text(d));
            where_parts.push(format!("domain = ?{}", params.len()));
        }
        if let Some(l) = filter.language {
            params.push(SqlValue::Text(l));
            where_parts.push(format!("language = ?{}", params.len()));
        }
        if let Some(c) = filter.is_canonical {
            params.push(SqlValue::Integer(if c { 1 } else { 0 }));
            where_parts.push(format!("is_canonical = ?{}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported",
                    cur.version
                )));
            }
            let last_uuid = parse_id(&cur.last_id)?.to_string();
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = params.len();
            params.push(SqlValue::Text(last_uuid));
            let p_id = params.len();
            where_parts.push(format!(
                "(cast_at < ?{p_ts} OR (cast_at = ?{p_ts} AND vote_id < ?{p_id}))"
            ));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(SqlValue::Integer(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT vote_id, contribution_id, voter_id, domain, language, \
                    payload, cast_at, signature \
             FROM cirisnode_votes \
             {where_sql} \
             ORDER BY cast_at DESC, vote_id DESC \
             LIMIT ?{p_limit}"
        );

        let conn = self.conn.clone();
        let rows_out = tokio::task::spawn_blocking(
            move || -> Result<Vec<(String, Option<String>, String, String, String, String, String, String)>, Error> {
                let guard = conn.blocking_lock();
                let mut stmt = guard
                    .prepare(&sql)
                    .map_err(|e| map_sqlite_error(e, "list_votes prepare"))?;
                let rows = stmt
                    .query_map(params_from_iter(params.iter()), |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, String>(7)?,
                        ))
                    })
                    .map_err(|e| map_sqlite_error(e, "list_votes query"))?;
                let out: Result<Vec<_>, _> = rows.collect();
                out.map_err(|e| map_sqlite_error(e, "list_votes collect"))
            },
        )
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

        let mut items: Vec<VoteEnvelope> = Vec::with_capacity(rows_out.len());
        for (
            vote_id,
            contribution_id,
            voter_id,
            domain,
            language,
            payload_text,
            cast_at_str,
            signature_b64,
        ) in rows_out
        {
            let payload_value = json_value(&payload_text)?;
            let score = payload_value
                .get("score")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let rationale = payload_value
                .get("rationale")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let cast_at = parse_datetime(&cast_at_str)?;
            items.push(VoteEnvelope {
                vote_id,
                voter_id,
                contribution_id,
                cell: Cell {
                    domain,
                    language,
                    subject: None, // not stored on votes table
                },
                score,
                rationale,
                signature: HybridSignature {
                    ed25519: signature_b64,
                    ml_dsa_65: None,
                    signed_at: cast_at,
                },
                cast_at,
            });
        }
        let next_cursor = if items.len() == limit as usize {
            items
                .last()
                .map(|last| ListCursor::from_trailing(last.cast_at, last.vote_id.clone()))
        } else {
            None
        };
        Ok(VoteListPage { items, next_cursor })
    }

    async fn get_credits_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> Result<Option<CreditsLedgerEntry>, Error> {
        let contributor_id_in = contributor_id.to_owned();
        let domain_in = domain.to_owned();
        let language_in = language.to_owned();
        let subject_in = subject.to_owned();
        let conn = self.conn.clone();
        let raw_opt = tokio::task::spawn_blocking(
            move || -> Result<Option<(String, String, String, String, f64, Option<String>, String, String)>, Error> {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT contributor_id, domain, language, subject, balance, \
                                last_update_contribution, last_updated_at, created_at \
                         FROM cirisnode_credits_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 \
                           AND language = ?3 AND subject = ?4",
                        params![contributor_id_in, domain_in, language_in, subject_in],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, f64>(4)?,
                                row.get::<_, Option<String>>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, String>(7)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "get_credits_ledger"))
            },
        )
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

        match raw_opt {
            None => Ok(None),
            Some((
                contributor_id,
                domain,
                language,
                subject,
                balance,
                last_update_contribution,
                last_updated_at_str,
                created_at_str,
            )) => Ok(Some(CreditsLedgerEntry {
                contributor_id,
                domain,
                language,
                subject,
                balance,
                last_update_contribution,
                last_updated_at: parse_datetime(&last_updated_at_str)?,
                created_at: parse_datetime(&created_at_str)?,
            })),
        }
    }

    async fn get_expertise_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
    ) -> Result<Option<ExpertiseLedgerEntry>, Error> {
        let contributor_id_in = contributor_id.to_owned();
        let domain_in = domain.to_owned();
        let language_in = language.to_owned();
        let conn = self.conn.clone();
        let raw_opt = tokio::task::spawn_blocking(
            move || -> Result<Option<(String, String, String, f64, bool, String, Option<String>, String)>, Error> {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT contributor_id, domain, language, expertise, is_active, \
                                last_updated_at, last_update_contribution, created_at \
                         FROM cirisnode_expertise_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 AND language = ?3",
                        params![contributor_id_in, domain_in, language_in],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, f64>(3)?,
                                row.get::<_, bool>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, Option<String>>(6)?,
                                row.get::<_, String>(7)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "get_expertise_ledger"))
            },
        )
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

        match raw_opt {
            None => Ok(None),
            Some((
                contributor_id,
                domain,
                language,
                expertise,
                is_active,
                last_updated_at_str,
                last_update_contribution,
                created_at_str,
            )) => Ok(Some(ExpertiseLedgerEntry {
                contributor_id,
                domain,
                language,
                expertise,
                is_active,
                last_updated_at: parse_datetime(&last_updated_at_str)?,
                last_update_contribution,
                created_at: parse_datetime(&created_at_str)?,
            })),
        }
    }
}

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;

    /// v0.7.1 — produce the contributor's base64-encoded Ed25519
    /// pubkey from a deterministic seed (for tests). Per SCHEMA.md
    /// §2.2 the pubkey IS the contributor_id.
    fn pubkey_b64(key: &ed25519_dalek::SigningKey) -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        BASE64.encode(key.verifying_key().to_bytes())
    }

    /// Sign the canonical bytes of an envelope and stamp the signature
    /// field. Generic over the typed-envelope shape.
    fn sign_envelope<T: serde::Serialize>(
        env: &T,
        key: &ed25519_dalek::SigningKey,
    ) -> HybridSignature {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let canonical = super::super::verify::canonical_bytes_for_envelope(env)
            .expect("canonical bytes for sign");
        let sig = key.sign(&canonical);
        HybridSignature {
            ed25519: BASE64.encode(sig.to_bytes()),
            ml_dsa_65: None,
            signed_at: Utc::now(),
        }
    }

    async fn fresh_backend() -> (SqliteBackend, SqliteNodeCoreBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let cn = SqliteNodeCoreBackend::new(backend.conn_handle());
        (backend, cn)
    }

    /// v0.9.4 SQLite parity: same lifecycle as the v0.7.1 / v0.7.2
    /// Postgres tests, run against in-memory SQLite. Covers the full
    /// 14-method NodeCoreService surface + duplicate-key conflict +
    /// tampered-envelope signature rejection + promotion-attestation
    /// transaction (flip `is_canonical` on 2 targets in one
    /// attestation) + rollback on phantom target.
    #[tokio::test]
    async fn cirisnode_sqlite_round_trip_full_lifecycle() {
        let (_b, backend) = fresh_backend().await;

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
        let voter_key = ed25519_dalek::SigningKey::from_bytes(&[0xB2; 32]);
        let adjudicator_key = ed25519_dalek::SigningKey::from_bytes(&[0xC3; 32]);
        let consensus_key = ed25519_dalek::SigningKey::from_bytes(&[0xD4; 32]);
        let author = pubkey_b64(&author_key);
        let voter = pubkey_b64(&voter_key);
        let adjudicator = pubkey_b64(&adjudicator_key);
        let consensus = pubkey_b64(&consensus_key);
        let domain = format!("test-dom-{}", Uuid::new_v4());
        let language = "en";
        let subject_kind = "arc_question";

        // 1. put_contribution
        let contribution_id = Uuid::new_v4();
        let mut env = ContributionEnvelope {
            contribution_id: contribution_id.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            payload: serde_json::json!({"question_id": "test_q01"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env.signature = sign_envelope(&env, &author_key);
        backend.put_contribution(env.clone()).await.unwrap();

        // 1b. duplicate → Conflict
        let dup = backend.put_contribution(env.clone()).await.unwrap_err();
        assert!(
            matches!(dup, Error::Conflict(_)),
            "expected Conflict on duplicate, got: {dup:?}"
        );

        // 1c. tampered envelope → Signature
        let mut tampered = env.clone();
        tampered.contribution_id = Uuid::new_v4().to_string();
        tampered.payload = serde_json::json!({"q": "TAMPERED"});
        let tampered_err = backend.put_contribution(tampered).await.unwrap_err();
        assert!(
            matches!(tampered_err, Error::Signature(_)),
            "expected Signature on tampered, got: {tampered_err:?}"
        );

        // 2. cast_vote
        let vote_id = Uuid::new_v4();
        let mut vote = VoteEnvelope {
            vote_id: vote_id.to_string(),
            voter_id: voter.clone(),
            contribution_id: Some(contribution_id.to_string()),
            cell: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            score: serde_json::json!({"verdict": "approve", "magnitude": 1.0}),
            rationale: Some("test".into()),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            cast_at: Utc::now(),
        };
        vote.signature = sign_envelope(&vote, &voter_key);
        backend.cast_vote(vote).await.unwrap();

        // 3. update_credits_ledger
        backend
            .update_credits_ledger(CreditsUpdate {
                contributor_id: voter.clone(),
                domain: domain.clone(),
                language: language.into(),
                subject: subject_kind.into(),
                new_balance: 10.0,
                source_contribution: contribution_id.to_string(),
            })
            .await
            .unwrap();

        // 4. update_expertise_ledger
        backend
            .update_expertise_ledger(ExpertiseUpdate {
                contributor_id: voter.clone(),
                domain: domain.clone(),
                language: language.into(),
                new_expertise: 0.5,
                new_active_tier: true,
                source_contribution: contribution_id.to_string(),
            })
            .await
            .unwrap();

        // 5. routable_contributors
        let routable = backend
            .routable_contributors(&domain, language)
            .await
            .unwrap();
        assert_eq!(routable.len(), 1);
        assert_eq!(routable[0].contributor_id, voter);
        assert!((routable[0].expertise - 0.5).abs() < 1e-9);

        // 6. read_vote_weight
        let vw = backend
            .read_vote_weight(&voter, &domain, language, subject_kind)
            .await
            .unwrap()
            .expect("vote weight present");
        assert!((vw.credits - 10.0).abs() < 1e-9);
        assert!((vw.expertise_multiplier - 3.0).abs() < 1e-9);
        assert!((vw.active_tier_multiplier - 1.5).abs() < 1e-9);
        assert!((vw.weight - 45.0).abs() < 1e-9);

        // 7. list_contributions
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    domain: Some(domain.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].contribution_id, contribution_id.to_string());

        // 8. list_votes
        let page = backend
            .list_votes(
                VotesFilter {
                    domain: Some(domain.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);

        // 9. get_credits_ledger
        let cl = backend
            .get_credits_ledger(&voter, &domain, language, subject_kind)
            .await
            .unwrap()
            .expect("credits present");
        assert!((cl.balance - 10.0).abs() < 1e-9);

        // 10. get_expertise_ledger
        let el = backend
            .get_expertise_ledger(&voter, &domain, language)
            .await
            .unwrap()
            .expect("expertise present");
        assert!((el.expertise - 0.5).abs() < 1e-9);
        assert!(el.is_active);

        // 11. put_moderation_event
        let moderation_id = Uuid::new_v4();
        let mut mod_event = ModerationEvent {
            moderation_id: moderation_id.to_string(),
            target_contributor: voter.clone(),
            accuser_id: author.clone(),
            payload: serde_json::json!({"violation": "test"}),
            filed_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        mod_event.signature = sign_envelope(&mod_event, &author_key);
        backend.put_moderation_event(mod_event).await.unwrap();

        // 12. put_slashing_attestation
        let slashing_id = Uuid::new_v4();
        let mut slash = SlashingAttestation {
            slashing_id: slashing_id.to_string(),
            moderation_id: moderation_id.to_string(),
            adjudicator_id: adjudicator.clone(),
            payload: serde_json::json!({"outcome": "dismiss"}),
            attested_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        slash.signature = sign_envelope(&slash, &adjudicator_key);
        backend.put_slashing_attestation(slash).await.unwrap();

        // 13. put_reconsideration_request + put_reconsideration_attestation
        let request_id = Uuid::new_v4();
        let mut recon_req = ReconsiderationRequest {
            request_id: request_id.to_string(),
            slashing_id: slashing_id.to_string(),
            requester_id: voter.clone(),
            payload: serde_json::json!({"grounds": "new evidence"}),
            requested_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        recon_req.signature = sign_envelope(&recon_req, &voter_key);
        backend
            .put_reconsideration_request(recon_req)
            .await
            .unwrap();

        let reconsideration_id = Uuid::new_v4();
        let mut recon_att = ReconsiderationAttestation {
            reconsideration_id: reconsideration_id.to_string(),
            request_id: request_id.to_string(),
            adjudicator_id: adjudicator.clone(),
            payload: serde_json::json!({"outcome": "uphold"}),
            attested_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        recon_att.signature = sign_envelope(&recon_att, &adjudicator_key);
        backend
            .put_reconsideration_attestation(recon_att)
            .await
            .unwrap();

        // 14. put_promotion_attestation — flip 2 contributions canonical
        // First, INSERT a second pending contribution to promote
        // alongside `contribution_id`.
        let contribution_id_2 = Uuid::new_v4();
        let mut env2 = ContributionEnvelope {
            contribution_id: contribution_id_2.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            payload: serde_json::json!({"q": "second"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env2.signature = sign_envelope(&env2, &author_key);
        backend.put_contribution(env2).await.unwrap();

        let attestation_id = Uuid::new_v4();
        let mut att = PromotionAttestation {
            attestation_id: attestation_id.to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![contribution_id.to_string(), contribution_id_2.to_string()],
            attested_by: consensus.clone(),
            aggregate_evidence: serde_json::json!({
                "threshold": "policy-A",
                "votes_for": 12,
                "witness_count": 3,
            }),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        att.signature = sign_envelope(&att, &consensus_key);
        backend
            .put_promotion_attestation(att.clone())
            .await
            .unwrap();

        // Verify both targets are now canonical.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    domain: Some(domain.clone()),
                    is_canonical: Some(true),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(
            page.items.len(),
            2,
            "both contributions should be canonical after promotion"
        );

        // Duplicate attestation_id → Conflict.
        let dup_err = backend.put_promotion_attestation(att).await.unwrap_err();
        assert!(
            matches!(dup_err, Error::Conflict(_)),
            "expected Conflict on dup attestation, got: {dup_err:?}"
        );

        // Empty target_ids → InvalidArgument.
        let mut empty_att = PromotionAttestation {
            attestation_id: Uuid::new_v4().to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![],
            attested_by: consensus.clone(),
            aggregate_evidence: serde_json::json!({}),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        empty_att.signature = sign_envelope(&empty_att, &consensus_key);
        let empty_err = backend
            .put_promotion_attestation(empty_att)
            .await
            .unwrap_err();
        assert!(
            matches!(empty_err, Error::InvalidArgument(_)),
            "expected InvalidArgument on empty target_ids, got: {empty_err:?}"
        );

        // Phantom target → InvalidArgument + rollback. Re-using the
        // same attestation_id afterwards with a valid target succeeds
        // (proving the INSERT was rolled back).
        let phantom_id = Uuid::new_v4();
        let phantom_attestation_id = Uuid::new_v4();
        let mut phantom_att = PromotionAttestation {
            attestation_id: phantom_attestation_id.to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![phantom_id.to_string()],
            attested_by: consensus.clone(),
            aggregate_evidence: serde_json::json!({}),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        phantom_att.signature = sign_envelope(&phantom_att, &consensus_key);
        let phantom_err = backend
            .put_promotion_attestation(phantom_att)
            .await
            .unwrap_err();
        assert!(
            matches!(phantom_err, Error::InvalidArgument(_)),
            "expected InvalidArgument on phantom target, got: {phantom_err:?}"
        );

        // Insert a fresh pending contribution + re-use the same
        // attestation_id with a valid target → must succeed (proves
        // rollback of the earlier phantom attempt).
        let recovery_cid = Uuid::new_v4();
        let mut recovery_env = ContributionEnvelope {
            contribution_id: recovery_cid.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            payload: serde_json::json!({"q": "recovery"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        recovery_env.signature = sign_envelope(&recovery_env, &author_key);
        backend.put_contribution(recovery_env).await.unwrap();

        let mut recovery_att = PromotionAttestation {
            attestation_id: phantom_attestation_id.to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![recovery_cid.to_string()],
            attested_by: consensus,
            aggregate_evidence: serde_json::json!({}),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        recovery_att.signature = sign_envelope(&recovery_att, &consensus_key);
        backend
            .put_promotion_attestation(recovery_att)
            .await
            .expect("attestation row was rolled back; re-use must succeed");
    }
}
