//! PostgreSQL impl of [`CreationCeremonyService`] (v1.5.16,
//! CIRISPersist#59 #8).
//!
//! 14 columns. `timestamp` rides as `chrono::DateTime<Utc>`
//! (TIMESTAMPTZ); `ceremony_status` rides as a SQL string from
//! [`CeremonyStatus::as_sql_str`] with a CHECK over the 5-value
//! vocabulary. `expected_capabilities` rides as `Option<String>`
//! — agent stores it as a JSON-array-shaped TEXT and we preserve
//! that shape literally.
//!
//! `record_ceremony` uses `INSERT ... ON CONFLICT (ceremony_id) DO
//! NOTHING RETURNING ceremony_id` followed by an in-tx `SELECT` so
//! the race-loser reads back the existing row. Mirrors the
//! v1.5.14 deferral_reports + v1.5.9 tasks claim shape.

use super::service::CreationCeremonyService;
use super::types::{CeremonyFilter, CeremonyStatus, CreationCeremony};
use super::Error;
use crate::store::postgres::PostgresBackend;
use crate::ClaimResult;

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
        _ => Error::Backend(format!("{op}: {detail}")),
    }
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

fn decode_ceremony_row(row: &tokio_postgres::Row) -> Result<CreationCeremony, Error> {
    let status_str: String = row
        .try_get("ceremony_status")
        .map_err(|e| Error::Backend(format!("decode ceremony_status: {e}")))?;
    let status = CeremonyStatus::parse_str(&status_str).ok_or_else(|| {
        Error::Backend(format!(
            "decode ceremony_status: unknown vocabulary `{status_str}`"
        ))
    })?;
    Ok(CreationCeremony {
        ceremony_id: row
            .try_get("ceremony_id")
            .map_err(|e| Error::Backend(format!("decode ceremony_id: {e}")))?,
        timestamp: row
            .try_get("timestamp")
            .map_err(|e| Error::Backend(format!("decode timestamp: {e}")))?,
        creator_agent_id: row
            .try_get("creator_agent_id")
            .map_err(|e| Error::Backend(format!("decode creator_agent_id: {e}")))?,
        creator_human_id: row
            .try_get("creator_human_id")
            .map_err(|e| Error::Backend(format!("decode creator_human_id: {e}")))?,
        wise_authority_id: row
            .try_get("wise_authority_id")
            .map_err(|e| Error::Backend(format!("decode wise_authority_id: {e}")))?,
        new_agent_id: row
            .try_get("new_agent_id")
            .map_err(|e| Error::Backend(format!("decode new_agent_id: {e}")))?,
        new_agent_name: row
            .try_get("new_agent_name")
            .map_err(|e| Error::Backend(format!("decode new_agent_name: {e}")))?,
        new_agent_purpose: row
            .try_get("new_agent_purpose")
            .map_err(|e| Error::Backend(format!("decode new_agent_purpose: {e}")))?,
        new_agent_description: row
            .try_get("new_agent_description")
            .map_err(|e| Error::Backend(format!("decode new_agent_description: {e}")))?,
        creation_justification: row
            .try_get("creation_justification")
            .map_err(|e| Error::Backend(format!("decode creation_justification: {e}")))?,
        expected_capabilities: row
            .try_get("expected_capabilities")
            .map_err(|e| Error::Backend(format!("decode expected_capabilities: {e}")))?,
        ethical_considerations: row
            .try_get("ethical_considerations")
            .map_err(|e| Error::Backend(format!("decode ethical_considerations: {e}")))?,
        template_profile_hash: row
            .try_get("template_profile_hash")
            .map_err(|e| Error::Backend(format!("decode template_profile_hash: {e}")))?,
        ceremony_status: status,
    })
}

const SELECT_COLUMNS: &str = "ceremony_id, timestamp, creator_agent_id, creator_human_id, \
     wise_authority_id, new_agent_id, new_agent_name, new_agent_purpose, \
     new_agent_description, creation_justification, expected_capabilities, \
     ethical_considerations, template_profile_hash, ceremony_status";

impl CreationCeremonyService for PostgresBackend {
    async fn record_ceremony(
        &self,
        ceremony: CreationCeremony,
    ) -> Result<ClaimResult<CreationCeremony>, Error> {
        validate_ceremony(&ceremony)?;
        let status_str = ceremony.ceremony_status.as_sql_str();
        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;
        let inserted = tx
            .query_opt(
                "INSERT INTO cirislens.creation_ceremonies (\
                    ceremony_id, timestamp, creator_agent_id, creator_human_id, \
                    wise_authority_id, new_agent_id, new_agent_name, new_agent_purpose, \
                    new_agent_description, creation_justification, expected_capabilities, \
                    ethical_considerations, template_profile_hash, ceremony_status\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
                 ON CONFLICT (ceremony_id) DO NOTHING \
                 RETURNING ceremony_id",
                &[
                    &ceremony.ceremony_id,
                    &ceremony.timestamp,
                    &ceremony.creator_agent_id,
                    &ceremony.creator_human_id,
                    &ceremony.wise_authority_id,
                    &ceremony.new_agent_id,
                    &ceremony.new_agent_name,
                    &ceremony.new_agent_purpose,
                    &ceremony.new_agent_description,
                    &ceremony.creation_justification,
                    &ceremony.expected_capabilities,
                    &ceremony.ethical_considerations,
                    &ceremony.template_profile_hash,
                    &status_str,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_ceremony insert"))?;
        let won = inserted.is_some();
        let row = tx
            .query_one(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.creation_ceremonies \
                     WHERE ceremony_id = $1"
                ),
                &[&ceremony.ceremony_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_ceremony readback"))?;
        let row = decode_ceremony_row(&row)?;
        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.creation_ceremonies \
                     WHERE ceremony_id = $1"
                ),
                &[&ceremony_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_ceremony"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_ceremony_row(&row)?)),
        }
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
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(creator_agent_id) = filter.creator_agent_id {
            params.push(Box::new(creator_agent_id));
            where_parts.push(format!("creator_agent_id = ${}", params.len()));
        }
        if let Some(creator_human_id) = filter.creator_human_id {
            params.push(Box::new(creator_human_id));
            where_parts.push(format!("creator_human_id = ${}", params.len()));
        }
        if let Some(wise_authority_id) = filter.wise_authority_id {
            params.push(Box::new(wise_authority_id));
            where_parts.push(format!("wise_authority_id = ${}", params.len()));
        }
        if let Some(new_agent_id) = filter.new_agent_id {
            params.push(Box::new(new_agent_id));
            where_parts.push(format!("new_agent_id = ${}", params.len()));
        }
        if let Some(status) = filter.ceremony_status {
            params.push(Box::new(status.as_sql_str().to_owned()));
            where_parts.push(format!("ceremony_status = ${}", params.len()));
        }
        if let Some(after) = filter.timestamp_after {
            params.push(Box::new(after));
            where_parts.push(format!("timestamp >= ${}", params.len()));
        }
        if let Some(before) = filter.timestamp_before {
            params.push(Box::new(before));
            where_parts.push(format!("timestamp <= ${}", params.len()));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {} ", where_parts.join(" AND "))
        };
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM cirislens.creation_ceremonies \
             {where_sql}\
             ORDER BY timestamp DESC, ceremony_id DESC \
             LIMIT ${p_limit}"
        );
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "list_ceremonies"))?;
        let mut items: Vec<CreationCeremony> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_ceremony_row(row)?);
        }
        Ok(items)
    }

    async fn update_ceremony_status(
        &self,
        ceremony_id: &str,
        new_status: CeremonyStatus,
    ) -> Result<bool, Error> {
        if ceremony_id.is_empty() {
            return Err(Error::InvalidArgument("ceremony_id required".into()));
        }
        let status_str = new_status.as_sql_str();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.creation_ceremonies SET \
                    ceremony_status = $1 \
                 WHERE ceremony_id = $2",
                &[&status_str, &ceremony_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "update_ceremony_status"))?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
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
    #[serial_test::serial(postgres)]
    async fn ceremony_pg_record_get_round_trip_all_14_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let c = mk_ceremony("rt");
        let outcome = CreationCeremonyService::record_ceremony(&backend, c.clone())
            .await
            .unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = backend
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
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn ceremony_pg_record_already_claimed_returns_existing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let c1 = mk_ceremony("dup");
        let out1 = CreationCeremonyService::record_ceremony(&backend, c1.clone())
            .await
            .unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        // Second record with same ceremony_id but different
        // justification — should NOT overwrite.
        let mut c2 = c1.clone();
        c2.creation_justification = "overwritten?".into();
        c2.ceremony_status = CeremonyStatus::Completed;
        let out2 = CreationCeremonyService::record_ceremony(&backend, c2)
            .await
            .unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(
            existing.creation_justification, c1.creation_justification,
            "loser sees original row"
        );
        assert_eq!(existing.ceremony_status, CeremonyStatus::Pending);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn ceremony_pg_list_filters_by_creator_and_new_agent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // Create 3 ceremonies — share creator on 2 of them.
        let mut c1 = mk_ceremony("a");
        let mut c2 = mk_ceremony("b");
        let mut c3 = mk_ceremony("c");
        c2.creator_agent_id = c1.creator_agent_id.clone();
        c1.timestamp = Utc::now();
        c2.timestamp = Utc::now() + chrono::Duration::milliseconds(10);
        c3.timestamp = Utc::now() + chrono::Duration::milliseconds(20);
        for c in [&c1, &c2, &c3] {
            CreationCeremonyService::record_ceremony(&backend, c.clone())
                .await
                .unwrap();
        }

        // Filter by creator_agent_id — should get c1 + c2.
        let by_creator = backend
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

        // Filter by new_agent_id — c3 only.
        let by_new_agent = backend
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
    #[serial_test::serial(postgres)]
    async fn ceremony_pg_list_filters_by_wa_status_and_window() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let wa = format!("wa-{}", Uuid::new_v4().simple());
        let mut c1 = mk_ceremony("wa1");
        let mut c2 = mk_ceremony("wa2");
        c1.wise_authority_id = wa.clone();
        c2.wise_authority_id = wa.clone();
        c1.timestamp = Utc::now() - chrono::Duration::hours(2);
        c2.timestamp = Utc::now();
        c2.ceremony_status = CeremonyStatus::Completed;
        CreationCeremonyService::record_ceremony(&backend, c1.clone())
            .await
            .unwrap();
        CreationCeremonyService::record_ceremony(&backend, c2.clone())
            .await
            .unwrap();

        let by_wa_status = backend
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

        // timestamp window — should miss c1, hit c2.
        let by_window = backend
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
    #[serial_test::serial(postgres)]
    async fn ceremony_pg_status_check_rejects_unknown_value() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // Bypass the typed enum to write an arbitrary status string
        // directly — verify the CHECK constraint kicks in at the
        // database layer.
        let client = backend.pool().get().await.unwrap();
        let now = Utc::now();
        let cid = format!("ceremony-bad-{}", Uuid::new_v4().simple());
        let res = client
            .execute(
                "INSERT INTO cirislens.creation_ceremonies (\
                    ceremony_id, timestamp, creator_agent_id, creator_human_id, \
                    wise_authority_id, new_agent_id, new_agent_name, new_agent_purpose, \
                    creation_justification, ethical_considerations, ceremony_status\
                 ) VALUES ($1, $2, $3, $3, $3, $3, 'n', 'p', 'j', 'e', $4)",
                &[&cid, &now, &"a", &"WEIRD_STATUS"],
            )
            .await;
        assert!(
            res.is_err(),
            "CHECK on ceremony_status should reject unknown values"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn ceremony_pg_update_status_success_and_missing() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let c = mk_ceremony("upd");
        CreationCeremonyService::record_ceremony(&backend, c.clone())
            .await
            .unwrap();

        // pending → in_progress.
        let ok = backend
            .update_ceremony_status(&c.ceremony_id, CeremonyStatus::InProgress)
            .await
            .unwrap();
        assert!(ok);
        let got = backend
            .get_ceremony(&c.ceremony_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.ceremony_status, CeremonyStatus::InProgress);

        // → completed.
        let ok = backend
            .update_ceremony_status(&c.ceremony_id, CeremonyStatus::Completed)
            .await
            .unwrap();
        assert!(ok);

        // Missing row.
        let bogus = format!("ceremony-bogus-{}", Uuid::new_v4().simple());
        let ok = backend
            .update_ceremony_status(&bogus, CeremonyStatus::Failed)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn ceremony_pg_validate_required_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mut c = mk_ceremony("val");
        c.ceremony_id = String::new();
        let res = CreationCeremonyService::record_ceremony(&backend, c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut c = mk_ceremony("val");
        c.ethical_considerations = String::new();
        let res = CreationCeremonyService::record_ceremony(&backend, c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
