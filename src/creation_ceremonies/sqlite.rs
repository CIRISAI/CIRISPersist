//! SQLite impl of [`CreationCeremonyService`] (v1.5.16,
//! CIRISPersist#59 #8).
//!
//! Mirrors the v1.5.16 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                            → TEXT (RFC 3339)
//!   ON CONFLICT (ceremony_id) DO NOTHING   → INSERT OR IGNORE
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.lock()`
//! per the existing pattern.
//!
//! `record_ceremony` uses the same ClaimResult shape as the v1.5.14
//! deferral_reports SQLite path: `INSERT OR IGNORE` followed by an
//! in-transaction `SELECT` so the race-loser reads back the existing
//! row.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, types::Value as SqlValue, Connection, OptionalExtension};

use super::service::CreationCeremonyService;
use super::types::{CeremonyFilter, CeremonyStatus, CreationCeremony};
use super::Error;
use crate::ClaimResult;

/// SQLite-backed [`CreationCeremonyService`] impl.
pub struct SqliteCreationCeremonyBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteCreationCeremonyBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
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

fn validate_ceremony(c: &CreationCeremony) -> Result<(), Error> {
    if c.ceremony_id.is_empty() {
        return Err(Error::InvalidArgument("ceremony_id required".into()));
    }
    if c.creator_agent_id.is_empty() {
        return Err(Error::InvalidArgument("creator_agent_id required".into()));
    }
    if c.creator_human_id.is_empty() {
        return Err(Error::InvalidArgument("creator_human_id required".into()));
    }
    if c.wise_authority_id.is_empty() {
        return Err(Error::InvalidArgument("wise_authority_id required".into()));
    }
    if c.new_agent_id.is_empty() {
        return Err(Error::InvalidArgument("new_agent_id required".into()));
    }
    if c.new_agent_name.is_empty() {
        return Err(Error::InvalidArgument("new_agent_name required".into()));
    }
    if c.new_agent_purpose.is_empty() {
        return Err(Error::InvalidArgument("new_agent_purpose required".into()));
    }
    if c.creation_justification.is_empty() {
        return Err(Error::InvalidArgument(
            "creation_justification required".into(),
        ));
    }
    if c.ethical_considerations.is_empty() {
        return Err(Error::InvalidArgument(
            "ethical_considerations required".into(),
        ));
    }
    Ok(())
}

fn decode_ceremony_row(row: &rusqlite::Row<'_>) -> Result<CreationCeremony, Error> {
    let ceremony_id: String = row
        .get("ceremony_id")
        .map_err(|e| Error::Backend(format!("decode ceremony_id: {e}")))?;
    let timestamp_str: String = row
        .get("timestamp")
        .map_err(|e| Error::Backend(format!("decode timestamp: {e}")))?;
    let creator_agent_id: String = row
        .get("creator_agent_id")
        .map_err(|e| Error::Backend(format!("decode creator_agent_id: {e}")))?;
    let creator_human_id: String = row
        .get("creator_human_id")
        .map_err(|e| Error::Backend(format!("decode creator_human_id: {e}")))?;
    let wise_authority_id: String = row
        .get("wise_authority_id")
        .map_err(|e| Error::Backend(format!("decode wise_authority_id: {e}")))?;
    let new_agent_id: String = row
        .get("new_agent_id")
        .map_err(|e| Error::Backend(format!("decode new_agent_id: {e}")))?;
    let new_agent_name: String = row
        .get("new_agent_name")
        .map_err(|e| Error::Backend(format!("decode new_agent_name: {e}")))?;
    let new_agent_purpose: String = row
        .get("new_agent_purpose")
        .map_err(|e| Error::Backend(format!("decode new_agent_purpose: {e}")))?;
    let new_agent_description: Option<String> = row
        .get("new_agent_description")
        .map_err(|e| Error::Backend(format!("decode new_agent_description: {e}")))?;
    let creation_justification: String = row
        .get("creation_justification")
        .map_err(|e| Error::Backend(format!("decode creation_justification: {e}")))?;
    let expected_capabilities: Option<String> = row
        .get("expected_capabilities")
        .map_err(|e| Error::Backend(format!("decode expected_capabilities: {e}")))?;
    let ethical_considerations: String = row
        .get("ethical_considerations")
        .map_err(|e| Error::Backend(format!("decode ethical_considerations: {e}")))?;
    let template_profile_hash: Option<String> = row
        .get("template_profile_hash")
        .map_err(|e| Error::Backend(format!("decode template_profile_hash: {e}")))?;
    let status_str: String = row
        .get("ceremony_status")
        .map_err(|e| Error::Backend(format!("decode ceremony_status: {e}")))?;
    let ceremony_status = CeremonyStatus::parse_str(&status_str).ok_or_else(|| {
        Error::Backend(format!(
            "decode ceremony_status: unknown vocabulary `{status_str}`"
        ))
    })?;
    Ok(CreationCeremony {
        ceremony_id,
        timestamp: parse_datetime(&timestamp_str)?,
        creator_agent_id,
        creator_human_id,
        wise_authority_id,
        new_agent_id,
        new_agent_name,
        new_agent_purpose,
        new_agent_description,
        creation_justification,
        expected_capabilities,
        ethical_considerations,
        template_profile_hash,
        ceremony_status,
    })
}

const SELECT_COLUMNS: &str = "ceremony_id, timestamp, creator_agent_id, creator_human_id, \
     wise_authority_id, new_agent_id, new_agent_name, new_agent_purpose, \
     new_agent_description, creation_justification, expected_capabilities, \
     ethical_considerations, template_profile_hash, ceremony_status";

impl CreationCeremonyService for SqliteCreationCeremonyBackend {
    async fn record_ceremony(
        &self,
        ceremony: CreationCeremony,
    ) -> Result<ClaimResult<CreationCeremony>, Error> {
        validate_ceremony(&ceremony)?;
        let timestamp_str = fmt_datetime(ceremony.timestamp);
        let status_str = ceremony.ceremony_status.as_sql_str().to_owned();
        let ceremony_id_for_lookup = ceremony.ceremony_id.clone();

        let conn = self.conn.clone();
        let (won, row): (bool, CreationCeremony) =
            (move || -> Result<(bool, CreationCeremony), Error> {
                let mut guard = conn.lock();
                let tx = guard
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|e| map_sqlite_error(e, "record_ceremony begin"))?;
                let changed = tx
                    .execute(
                        "INSERT OR IGNORE INTO cirislens_creation_ceremonies (\
                            ceremony_id, timestamp, creator_agent_id, creator_human_id, \
                            wise_authority_id, new_agent_id, new_agent_name, new_agent_purpose, \
                            new_agent_description, creation_justification, expected_capabilities, \
                            ethical_considerations, template_profile_hash, ceremony_status\
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                        params![
                            ceremony.ceremony_id,
                            timestamp_str,
                            ceremony.creator_agent_id,
                            ceremony.creator_human_id,
                            ceremony.wise_authority_id,
                            ceremony.new_agent_id,
                            ceremony.new_agent_name,
                            ceremony.new_agent_purpose,
                            ceremony.new_agent_description,
                            ceremony.creation_justification,
                            ceremony.expected_capabilities,
                            ceremony.ethical_considerations,
                            ceremony.template_profile_hash,
                            status_str,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "record_ceremony insert"))?;
                let won = changed > 0;
                let row = tx
                    .query_row(
                        &format!(
                            "SELECT {SELECT_COLUMNS} FROM cirislens_creation_ceremonies \
                             WHERE ceremony_id = ?1"
                        ),
                        params![ceremony_id_for_lookup],
                        |row| Ok(decode_ceremony_row(row)),
                    )
                    .map_err(|e| map_sqlite_error(e, "record_ceremony readback"))??;
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "record_ceremony commit"))?;
                Ok((won, row))
            })()?;

        if won {
            Ok(ClaimResult::Stored(row))
        } else {
            Ok(ClaimResult::AlreadyClaimed(row))
        }
    }

    async fn get_ceremony(&self, ceremony_id: &str) -> Result<Option<CreationCeremony>, Error> {
        if ceremony_id.is_empty() {
            return Err(Error::InvalidArgument("ceremony_id required".into()));
        }
        let ceremony_id_owned = ceremony_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<CreationCeremony>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    &format!(
                        "SELECT {SELECT_COLUMNS} FROM cirislens_creation_ceremonies \
                         WHERE ceremony_id = ?1"
                    ),
                    params![ceremony_id_owned],
                    |row| Ok(decode_ceremony_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_ceremony query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })()
    }

    async fn list_ceremonies(
        &self,
        filter: CeremonyFilter,
        limit: i64,
    ) -> Result<Vec<CreationCeremony>, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut where_parts: Vec<String> = Vec::new();
        let mut sql_params: Vec<SqlValue> = Vec::new();
        if let Some(creator_agent_id) = filter.creator_agent_id {
            sql_params.push(SqlValue::Text(creator_agent_id));
            where_parts.push(format!("creator_agent_id = ?{}", sql_params.len()));
        }
        if let Some(creator_human_id) = filter.creator_human_id {
            sql_params.push(SqlValue::Text(creator_human_id));
            where_parts.push(format!("creator_human_id = ?{}", sql_params.len()));
        }
        if let Some(wise_authority_id) = filter.wise_authority_id {
            sql_params.push(SqlValue::Text(wise_authority_id));
            where_parts.push(format!("wise_authority_id = ?{}", sql_params.len()));
        }
        if let Some(new_agent_id) = filter.new_agent_id {
            sql_params.push(SqlValue::Text(new_agent_id));
            where_parts.push(format!("new_agent_id = ?{}", sql_params.len()));
        }
        if let Some(status) = filter.ceremony_status {
            sql_params.push(SqlValue::Text(status.as_sql_str().to_owned()));
            where_parts.push(format!("ceremony_status = ?{}", sql_params.len()));
        }
        if let Some(after) = filter.timestamp_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("timestamp >= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.timestamp_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("timestamp <= ?{}", sql_params.len()));
        }
        sql_params.push(SqlValue::Integer(limit));
        let p_limit = sql_params.len();
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {} ", where_parts.join(" AND "))
        };
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM cirislens_creation_ceremonies \
             {where_sql}\
             ORDER BY timestamp DESC, ceremony_id DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        (move || -> Result<Vec<CreationCeremony>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_ceremonies prepare"))?;
            let rows_iter = stmt
                .query_map(rusqlite::params_from_iter(sql_params.iter()), |row| {
                    Ok(decode_ceremony_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_ceremonies query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_ceremonies row"))??);
            }
            Ok(items)
        })()
    }

    async fn update_ceremony_status(
        &self,
        ceremony_id: &str,
        new_status: CeremonyStatus,
    ) -> Result<bool, Error> {
        if ceremony_id.is_empty() {
            return Err(Error::InvalidArgument("ceremony_id required".into()));
        }
        let ceremony_id_owned = ceremony_id.to_owned();
        let status_str = new_status.as_sql_str().to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            let changed = guard
                .execute(
                    "UPDATE cirislens_creation_ceremonies SET \
                        ceremony_status = ?1 \
                     WHERE ceremony_id = ?2",
                    params![status_str, ceremony_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "update_ceremony_status exec"))?;
            Ok(changed > 0)
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteCreationCeremonyBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteCreationCeremonyBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn mk_ceremony(suffix: &str) -> CreationCeremony {
        let unique = Uuid::new_v4().simple().to_string();
        CreationCeremony {
            ceremony_id: format!("ceremony-{suffix}-{unique}"),
            timestamp: Utc::now(),
            creator_agent_id: format!("creator-{unique}"),
            creator_human_id: format!("human-{unique}"),
            wise_authority_id: format!("wa-{unique}"),
            new_agent_id: format!("new-{unique}"),
            new_agent_name: "Newton".into(),
            new_agent_purpose: "scientific reasoning".into(),
            new_agent_description: Some("thoughtful agent".into()),
            creation_justification: "operator demand".into(),
            expected_capabilities: Some(r#"["compute", "reason"]"#.into()),
            ethical_considerations: "alignment confirmed".into(),
            template_profile_hash: Some("sha256:deadbeef".into()),
            ceremony_status: CeremonyStatus::Pending,
        }
    }

    #[tokio::test]
    async fn record_get_round_trip_all_14_columns() {
        let (_b, svc) = fresh_backend().await;
        let now = Utc::now();
        let mut c = mk_ceremony("rt");
        c.timestamp = now;
        let outcome = svc.record_ceremony(c.clone()).await.unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = svc
            .get_ceremony(&c.ceremony_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.ceremony_id, c.ceremony_id);
        assert_eq!(got.creator_agent_id, c.creator_agent_id);
        assert_eq!(got.creator_human_id, c.creator_human_id);
        assert_eq!(got.wise_authority_id, c.wise_authority_id);
        assert_eq!(got.new_agent_id, c.new_agent_id);
        assert_eq!(got.new_agent_name, c.new_agent_name);
        assert_eq!(got.new_agent_purpose, c.new_agent_purpose);
        assert_eq!(got.new_agent_description, c.new_agent_description);
        assert_eq!(got.creation_justification, c.creation_justification);
        assert_eq!(got.expected_capabilities, c.expected_capabilities);
        assert_eq!(got.ethical_considerations, c.ethical_considerations);
        assert_eq!(got.template_profile_hash, c.template_profile_hash);
        assert_eq!(got.ceremony_status, c.ceremony_status);
        let drift = (got.timestamp - now).num_seconds().abs();
        assert!(drift <= 1, "timestamp preserved: {drift}s drift");
    }

    #[tokio::test]
    async fn record_already_claimed_returns_existing_row() {
        let (_b, svc) = fresh_backend().await;
        let c1 = mk_ceremony("dup");
        let out1 = svc.record_ceremony(c1.clone()).await.unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        let mut c2 = c1.clone();
        c2.creation_justification = "overwritten?".into();
        c2.ceremony_status = CeremonyStatus::Completed;
        let out2 = svc.record_ceremony(c2).await.unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(
            existing.creation_justification, c1.creation_justification,
            "loser sees original row"
        );
        assert_eq!(existing.ceremony_status, CeremonyStatus::Pending);
    }

    #[tokio::test]
    async fn list_filters_by_creator_and_new_agent() {
        let (_b, svc) = fresh_backend().await;
        let mut c1 = mk_ceremony("a");
        let mut c2 = mk_ceremony("b");
        let c3 = mk_ceremony("c");
        c2.creator_agent_id = c1.creator_agent_id.clone();
        c1.timestamp = Utc::now();
        c2.timestamp = Utc::now() + chrono::Duration::milliseconds(10);
        for c in [&c1, &c2, &c3] {
            svc.record_ceremony(c.clone()).await.unwrap();
        }

        let by_creator = svc
            .list_ceremonies(
                CeremonyFilter {
                    creator_agent_id: Some(c1.creator_agent_id.clone()),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(by_creator.len(), 2);
        // ORDER BY timestamp DESC — c2 newer than c1.
        assert_eq!(by_creator[0].ceremony_id, c2.ceremony_id);
        assert_eq!(by_creator[1].ceremony_id, c1.ceremony_id);

        let by_new_agent = svc
            .list_ceremonies(
                CeremonyFilter {
                    new_agent_id: Some(c3.new_agent_id.clone()),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(by_new_agent.len(), 1);
        assert_eq!(by_new_agent[0].ceremony_id, c3.ceremony_id);
    }

    #[tokio::test]
    async fn list_filters_by_wa_status_and_window() {
        let (_b, svc) = fresh_backend().await;
        let wa = format!("wa-{}", Uuid::new_v4().simple());
        let mut c1 = mk_ceremony("wa1");
        let mut c2 = mk_ceremony("wa2");
        c1.wise_authority_id = wa.clone();
        c2.wise_authority_id = wa.clone();
        c1.timestamp = Utc::now() - chrono::Duration::hours(2);
        c2.timestamp = Utc::now();
        c2.ceremony_status = CeremonyStatus::Completed;
        svc.record_ceremony(c1.clone()).await.unwrap();
        svc.record_ceremony(c2.clone()).await.unwrap();

        let by_wa_status = svc
            .list_ceremonies(
                CeremonyFilter {
                    wise_authority_id: Some(wa.clone()),
                    ceremony_status: Some(CeremonyStatus::Completed),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(by_wa_status.len(), 1);
        assert_eq!(by_wa_status[0].ceremony_id, c2.ceremony_id);

        let by_window = svc
            .list_ceremonies(
                CeremonyFilter {
                    wise_authority_id: Some(wa.clone()),
                    timestamp_after: Some(Utc::now() - chrono::Duration::minutes(30)),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(by_window.len(), 1);
        assert_eq!(by_window[0].ceremony_id, c2.ceremony_id);
    }

    #[tokio::test]
    async fn status_check_rejects_unknown_value() {
        let (b, _svc) = fresh_backend().await;
        // Bypass the typed enum to write an arbitrary status string
        // directly — verify the CHECK constraint fires.
        let conn = b.conn_handle();
        let now = fmt_datetime(Utc::now());
        let cid = format!("ceremony-bad-{}", Uuid::new_v4().simple());
        let res = (move || {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_creation_ceremonies (\
                    ceremony_id, timestamp, creator_agent_id, creator_human_id, \
                    wise_authority_id, new_agent_id, new_agent_name, new_agent_purpose, \
                    creation_justification, ethical_considerations, ceremony_status\
                 ) VALUES (?1, ?2, 'a', 'h', 'w', 'n', 'name', 'purpose', \
                           'just', 'ethics', ?3)",
                params![cid, now, "WEIRD_STATUS"],
            )
        })();
        assert!(
            res.is_err(),
            "CHECK on ceremony_status should reject unknown values"
        );
    }

    #[tokio::test]
    async fn update_status_success_and_missing() {
        let (_b, svc) = fresh_backend().await;
        let c = mk_ceremony("upd");
        svc.record_ceremony(c.clone()).await.unwrap();

        let ok = svc
            .update_ceremony_status(&c.ceremony_id, CeremonyStatus::InProgress)
            .await
            .unwrap();
        assert!(ok);
        let got = svc
            .get_ceremony(&c.ceremony_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.ceremony_status, CeremonyStatus::InProgress);

        let ok = svc
            .update_ceremony_status(&c.ceremony_id, CeremonyStatus::Completed)
            .await
            .unwrap();
        assert!(ok);

        let bogus = format!("ceremony-bogus-{}", Uuid::new_v4().simple());
        let ok = svc
            .update_ceremony_status(&bogus, CeremonyStatus::Failed)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn validate_required_columns() {
        let (_b, svc) = fresh_backend().await;
        let mut c = mk_ceremony("val");
        c.ceremony_id = String::new();
        let res = svc.record_ceremony(c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut c = mk_ceremony("val");
        c.ethical_considerations = String::new();
        let res = svc.record_ceremony(c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
