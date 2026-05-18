//! SQLite impl of [`WaCertService`] (v1.5.19, CIRISPersist#59 #11,
//! FINAL).
//!
//! Mirrors the v1.5.19 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                  → TEXT (RFC 3339)
//!   JSONB                        → TEXT (raw JSON string)
//!   BOOLEAN                      → INTEGER (0 / 1)
//!   ON CONFLICT (wa_id) DO UPDATE   → identical
//!   DEFERRABLE INITIALLY DEFERRED   → omitted (SQLite has only
//!                                     immediate-mode FK enforcement
//!                                     with PRAGMA foreign_keys=ON)
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.blocking_lock()`
//! per the existing pattern.
//!
//! `upsert_wa_cert` overwrites every column except `wa_id` + `created`
//! on conflict; `created` is preserved.
//!
//! # Self-FK semantics
//!
//! On SQLite the parent_wa_id FK is immediate — the parent must
//! already exist when the child INSERT runs. The `cirislens_wa_cert`
//! table is the self-FK target; both the table and the foreign-key
//! constraint share the same name with the persist-side rename
//! convention (`cirislens_` prefix instead of the agent's bare
//! `wa_cert`).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::service::WaCertService;
use super::types::{TokenType, WaCert, WaRole};
use super::Error;

/// SQLite-backed [`WaCertService`] impl.
pub struct SqliteWaCertBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteWaCertBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            // SQLite collapses CHECK / NOT NULL / FK / UNIQUE under
            // one ErrorCode; distinguish by extended code so FK +
            // UNIQUE violations surface as Conflict (parity with PG)
            // and CHECK / NOT NULL as InvalidArgument.
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

fn parse_datetime_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>, Error> {
    match s {
        None => Ok(None),
        Some(raw) => parse_datetime(&raw).map(Some),
    }
}

fn encode_json(v: &serde_json::Value) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|e| Error::Internal(format!("json encode: {e}")))
}

fn encode_json_opt(v: Option<&serde_json::Value>) -> Result<Option<String>, Error> {
    match v {
        None => Ok(None),
        Some(value) => serde_json::to_string(value)
            .map(Some)
            .map_err(|e| Error::Internal(format!("json encode: {e}"))),
    }
}

fn decode_json(s: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str(s).map_err(|e| Error::Backend(format!("json decode: {e} (raw={s})")))
}

fn decode_json_opt(s: Option<String>) -> Result<Option<serde_json::Value>, Error> {
    match s {
        None => Ok(None),
        Some(raw) => decode_json(&raw).map(Some),
    }
}

fn validate_cert(c: &WaCert) -> Result<(), Error> {
    if c.wa_id.is_empty() {
        return Err(Error::InvalidArgument("wa_id required".into()));
    }
    if c.name.is_empty() {
        return Err(Error::InvalidArgument("name required".into()));
    }
    if c.pubkey.is_empty() {
        return Err(Error::InvalidArgument("pubkey required".into()));
    }
    if c.jwt_kid.is_empty() {
        return Err(Error::InvalidArgument("jwt_kid required".into()));
    }
    Ok(())
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<WaCert, Error> {
    let role_str: String = row
        .get("role")
        .map_err(|e| Error::Backend(format!("decode role: {e}")))?;
    let role = WaRole::parse_str(&role_str)
        .ok_or_else(|| Error::Backend(format!("decode role: unknown vocabulary `{role_str}`")))?;
    let token_type_str: String = row
        .get("token_type")
        .map_err(|e| Error::Backend(format!("decode token_type: {e}")))?;
    let token_type = TokenType::parse_str(&token_type_str).ok_or_else(|| {
        Error::Backend(format!(
            "decode token_type: unknown vocabulary `{token_type_str}`"
        ))
    })?;
    let auto_minted_int: i64 = row
        .get("auto_minted")
        .map_err(|e| Error::Backend(format!("decode auto_minted: {e}")))?;
    let active_int: i64 = row
        .get("active")
        .map_err(|e| Error::Backend(format!("decode active: {e}")))?;
    let oauth_links_raw: Option<String> = row
        .get("oauth_links")
        .map_err(|e| Error::Backend(format!("decode oauth_links: {e}")))?;
    let scopes_raw: String = row
        .get("scopes")
        .map_err(|e| Error::Backend(format!("decode scopes: {e}")))?;
    let custom_permissions_raw: Option<String> = row
        .get("custom_permissions")
        .map_err(|e| Error::Backend(format!("decode custom_permissions: {e}")))?;
    let adapter_metadata_raw: Option<String> = row
        .get("adapter_metadata")
        .map_err(|e| Error::Backend(format!("decode adapter_metadata: {e}")))?;
    let created_str: String = row
        .get("created")
        .map_err(|e| Error::Backend(format!("decode created: {e}")))?;
    let last_login_str: Option<String> = row
        .get("last_login")
        .map_err(|e| Error::Backend(format!("decode last_login: {e}")))?;

    Ok(WaCert {
        wa_id: row
            .get("wa_id")
            .map_err(|e| Error::Backend(format!("decode wa_id: {e}")))?,
        name: row
            .get("name")
            .map_err(|e| Error::Backend(format!("decode name: {e}")))?,
        role,
        pubkey: row
            .get("pubkey")
            .map_err(|e| Error::Backend(format!("decode pubkey: {e}")))?,
        jwt_kid: row
            .get("jwt_kid")
            .map_err(|e| Error::Backend(format!("decode jwt_kid: {e}")))?,
        password_hash: row
            .get("password_hash")
            .map_err(|e| Error::Backend(format!("decode password_hash: {e}")))?,
        api_key_hash: row
            .get("api_key_hash")
            .map_err(|e| Error::Backend(format!("decode api_key_hash: {e}")))?,
        oauth_provider: row
            .get("oauth_provider")
            .map_err(|e| Error::Backend(format!("decode oauth_provider: {e}")))?,
        oauth_external_id: row
            .get("oauth_external_id")
            .map_err(|e| Error::Backend(format!("decode oauth_external_id: {e}")))?,
        oauth_links: decode_json_opt(oauth_links_raw)?,
        veilid_id: row
            .get("veilid_id")
            .map_err(|e| Error::Backend(format!("decode veilid_id: {e}")))?,
        auto_minted: auto_minted_int != 0,
        parent_wa_id: row
            .get("parent_wa_id")
            .map_err(|e| Error::Backend(format!("decode parent_wa_id: {e}")))?,
        parent_signature: row
            .get("parent_signature")
            .map_err(|e| Error::Backend(format!("decode parent_signature: {e}")))?,
        scopes: decode_json(&scopes_raw)?,
        custom_permissions: decode_json_opt(custom_permissions_raw)?,
        adapter_id: row
            .get("adapter_id")
            .map_err(|e| Error::Backend(format!("decode adapter_id: {e}")))?,
        adapter_name: row
            .get("adapter_name")
            .map_err(|e| Error::Backend(format!("decode adapter_name: {e}")))?,
        adapter_metadata: decode_json_opt(adapter_metadata_raw)?,
        token_type,
        created: parse_datetime(&created_str)?,
        last_login: parse_datetime_opt(last_login_str)?,
        active: active_int != 0,
    })
}

const SELECT_COLUMNS: &str = "wa_id, name, role, pubkey, jwt_kid, \
     password_hash, api_key_hash, oauth_provider, oauth_external_id, \
     oauth_links, veilid_id, auto_minted, parent_wa_id, parent_signature, \
     scopes, custom_permissions, adapter_id, adapter_name, adapter_metadata, \
     token_type, created, last_login, active";

impl WaCertService for SqliteWaCertBackend {
    async fn upsert_wa_cert(&self, cert: WaCert) -> Result<(), Error> {
        validate_cert(&cert)?;
        let role_str = cert.role.as_sql_str().to_owned();
        let token_type_str = cert.token_type.as_sql_str().to_owned();
        let oauth_links_str = encode_json_opt(cert.oauth_links.as_ref())?;
        let scopes_str = encode_json(&cert.scopes)?;
        let custom_permissions_str = encode_json_opt(cert.custom_permissions.as_ref())?;
        let adapter_metadata_str = encode_json_opt(cert.adapter_metadata.as_ref())?;
        let created_str = fmt_datetime(cert.created);
        let last_login_str = cert.last_login.map(fmt_datetime);
        let auto_minted_int: i64 = if cert.auto_minted { 1 } else { 0 };
        let active_int: i64 = if cert.active { 1 } else { 0 };

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "upsert_wa_cert begin"))?;
            tx.execute(
                "INSERT INTO cirislens_wa_cert (\
                    wa_id, name, role, pubkey, jwt_kid, \
                    password_hash, api_key_hash, oauth_provider, oauth_external_id, \
                    oauth_links, veilid_id, auto_minted, parent_wa_id, parent_signature, \
                    scopes, custom_permissions, adapter_id, adapter_name, adapter_metadata, \
                    token_type, created, last_login, active\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                           ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23) \
                 ON CONFLICT(wa_id) DO UPDATE SET \
                    name = excluded.name, \
                    role = excluded.role, \
                    pubkey = excluded.pubkey, \
                    jwt_kid = excluded.jwt_kid, \
                    password_hash = excluded.password_hash, \
                    api_key_hash = excluded.api_key_hash, \
                    oauth_provider = excluded.oauth_provider, \
                    oauth_external_id = excluded.oauth_external_id, \
                    oauth_links = excluded.oauth_links, \
                    veilid_id = excluded.veilid_id, \
                    auto_minted = excluded.auto_minted, \
                    parent_wa_id = excluded.parent_wa_id, \
                    parent_signature = excluded.parent_signature, \
                    scopes = excluded.scopes, \
                    custom_permissions = excluded.custom_permissions, \
                    adapter_id = excluded.adapter_id, \
                    adapter_name = excluded.adapter_name, \
                    adapter_metadata = excluded.adapter_metadata, \
                    token_type = excluded.token_type, \
                    last_login = excluded.last_login, \
                    active = excluded.active",
                params![
                    cert.wa_id,
                    cert.name,
                    role_str,
                    cert.pubkey,
                    cert.jwt_kid,
                    cert.password_hash,
                    cert.api_key_hash,
                    cert.oauth_provider,
                    cert.oauth_external_id,
                    oauth_links_str,
                    cert.veilid_id,
                    auto_minted_int,
                    cert.parent_wa_id,
                    cert.parent_signature,
                    scopes_str,
                    custom_permissions_str,
                    cert.adapter_id,
                    cert.adapter_name,
                    adapter_metadata_str,
                    token_type_str,
                    created_str,
                    last_login_str,
                    active_int,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "upsert_wa_cert insert"))?;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "upsert_wa_cert commit"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_wa_cert(&self, wa_id: &str) -> Result<Option<WaCert>, Error> {
        if wa_id.is_empty() {
            return Err(Error::InvalidArgument("wa_id required".into()));
        }
        let wa_id_owned = wa_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<WaCert>, Error> {
            let guard = conn.blocking_lock();
            let row_opt = guard
                .query_row(
                    &format!("SELECT {SELECT_COLUMNS} FROM cirislens_wa_cert WHERE wa_id = ?1"),
                    params![wa_id_owned],
                    |row| Ok(decode_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_wa_cert"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_by_kid(&self, jwt_kid: &str) -> Result<Option<WaCert>, Error> {
        if jwt_kid.is_empty() {
            return Err(Error::InvalidArgument("jwt_kid required".into()));
        }
        let kid_owned = jwt_kid.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<WaCert>, Error> {
            let guard = conn.blocking_lock();
            let row_opt = guard
                .query_row(
                    &format!("SELECT {SELECT_COLUMNS} FROM cirislens_wa_cert WHERE jwt_kid = ?1"),
                    params![kid_owned],
                    |row| Ok(decode_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_by_kid"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_by_oauth(
        &self,
        oauth_provider: &str,
        oauth_external_id: &str,
    ) -> Result<Option<WaCert>, Error> {
        if oauth_provider.is_empty() {
            return Err(Error::InvalidArgument("oauth_provider required".into()));
        }
        if oauth_external_id.is_empty() {
            return Err(Error::InvalidArgument("oauth_external_id required".into()));
        }
        let provider_owned = oauth_provider.to_owned();
        let ext_owned = oauth_external_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<WaCert>, Error> {
            let guard = conn.blocking_lock();
            let row_opt = guard
                .query_row(
                    &format!(
                        "SELECT {SELECT_COLUMNS} FROM cirislens_wa_cert \
                         WHERE oauth_provider = ?1 AND oauth_external_id = ?2"
                    ),
                    params![provider_owned, ext_owned],
                    |row| Ok(decode_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_by_oauth"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_by_role(&self, role: WaRole, limit: i64) -> Result<Vec<WaCert>, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let role_str = role.as_sql_str().to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<WaCert>, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens_wa_cert \
                     WHERE role = ?1 AND active = 1 \
                     ORDER BY created DESC, wa_id DESC \
                     LIMIT ?2"
                ))
                .map_err(|e| map_sqlite_error(e, "list_by_role prepare"))?;
            let rows_iter = stmt
                .query_map(params![role_str, limit], |row| Ok(decode_row(row)))
                .map_err(|e| map_sqlite_error(e, "list_by_role query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_by_role row"))??);
            }
            Ok(items)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn set_active(&self, wa_id: &str, active: bool) -> Result<bool, Error> {
        if wa_id.is_empty() {
            return Err(Error::InvalidArgument("wa_id required".into()));
        }
        let wa_id_owned = wa_id.to_owned();
        let active_int: i64 = if active { 1 } else { 0 };
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let guard = conn.blocking_lock();
            let changed = guard
                .execute(
                    "UPDATE cirislens_wa_cert SET active = ?1 WHERE wa_id = ?2",
                    params![active_int, wa_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "set_active"))?;
            Ok(changed > 0)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn update_last_login(
        &self,
        wa_id: &str,
        login_time: DateTime<Utc>,
    ) -> Result<bool, Error> {
        if wa_id.is_empty() {
            return Err(Error::InvalidArgument("wa_id required".into()));
        }
        let wa_id_owned = wa_id.to_owned();
        let login_str = fmt_datetime(login_time);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let guard = conn.blocking_lock();
            let changed = guard
                .execute(
                    "UPDATE cirislens_wa_cert SET last_login = ?1 WHERE wa_id = ?2",
                    params![login_str, wa_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "update_last_login"))?;
            Ok(changed > 0)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteWaCertBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteWaCertBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn unique_id(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }

    fn mk_minimal(wa_id: &str, kid: &str) -> WaCert {
        WaCert {
            wa_id: wa_id.into(),
            name: format!("WA {wa_id}"),
            role: WaRole::Authority,
            pubkey: "pk-base64".into(),
            jwt_kid: kid.into(),
            password_hash: None,
            api_key_hash: None,
            oauth_provider: None,
            oauth_external_id: None,
            oauth_links: None,
            veilid_id: None,
            auto_minted: false,
            parent_wa_id: None,
            parent_signature: None,
            scopes: serde_json::json!(["sign"]),
            custom_permissions: None,
            adapter_id: None,
            adapter_name: None,
            adapter_metadata: None,
            token_type: TokenType::Standard,
            created: Utc::now(),
            last_login: None,
            active: true,
        }
    }

    async fn fk_pragma_on(b: &SqliteBackend) -> bool {
        let conn = b.conn_handle();
        tokio::task::spawn_blocking(move || -> bool {
            let guard = conn.blocking_lock();
            guard
                .query_row("PRAGMA foreign_keys", params![], |row| row.get::<_, i64>(0))
                .map(|v| v == 1)
                .unwrap_or(false)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn upsert_round_trip_all_24_columns() {
        let (_b, svc) = fresh_backend().await;
        let wa_id = unique_id("wa");
        let kid = unique_id("kid");
        let now = Utc::now();
        let cert = WaCert {
            wa_id: wa_id.clone(),
            name: "Alice".into(),
            role: WaRole::Authority,
            pubkey: "pk-base64".into(),
            jwt_kid: kid,
            password_hash: Some("argon2:abc".into()),
            api_key_hash: Some("hash-1".into()),
            oauth_provider: Some("google".into()),
            oauth_external_id: Some("ext-123".into()),
            oauth_links: Some(serde_json::json!({"profile": "https://example/u/alice"})),
            veilid_id: Some("veilid-1".into()),
            auto_minted: true,
            parent_wa_id: None,
            parent_signature: Some("sig-base64".into()),
            scopes: serde_json::json!(["sign", "approve"]),
            custom_permissions: Some(serde_json::json!({"can_revoke": true})),
            adapter_id: Some("adapter-discord-1".into()),
            adapter_name: Some("discord".into()),
            adapter_metadata: Some(serde_json::json!({"guild_id": "g-1"})),
            token_type: TokenType::ApiKey,
            created: now,
            last_login: Some(now),
            active: true,
        };
        svc.upsert_wa_cert(cert.clone()).await.unwrap();
        let got = svc.get_wa_cert(&wa_id).await.unwrap().unwrap();
        // Round-trip checks: all 24 columns. Timestamps go through
        // RFC 3339 with `Micros` precision so sub-microsecond detail
        // is dropped — compare with a 1s drift tolerance.
        assert_eq!(got.wa_id, cert.wa_id);
        assert_eq!(got.name, cert.name);
        assert_eq!(got.role, cert.role);
        assert_eq!(got.pubkey, cert.pubkey);
        assert_eq!(got.jwt_kid, cert.jwt_kid);
        assert_eq!(got.password_hash, cert.password_hash);
        assert_eq!(got.api_key_hash, cert.api_key_hash);
        assert_eq!(got.oauth_provider, cert.oauth_provider);
        assert_eq!(got.oauth_external_id, cert.oauth_external_id);
        assert_eq!(got.oauth_links, cert.oauth_links);
        assert_eq!(got.veilid_id, cert.veilid_id);
        assert_eq!(got.auto_minted, cert.auto_minted);
        assert_eq!(got.parent_wa_id, cert.parent_wa_id);
        assert_eq!(got.parent_signature, cert.parent_signature);
        assert_eq!(got.scopes, cert.scopes);
        assert_eq!(got.custom_permissions, cert.custom_permissions);
        assert_eq!(got.adapter_id, cert.adapter_id);
        assert_eq!(got.adapter_name, cert.adapter_name);
        assert_eq!(got.adapter_metadata, cert.adapter_metadata);
        assert_eq!(got.token_type, cert.token_type);
        let drift = (got.created - cert.created).num_seconds().abs();
        assert!(drift <= 1, "created preserved: {drift}s drift");
        let drift = (got.last_login.unwrap() - cert.last_login.unwrap())
            .num_seconds()
            .abs();
        assert!(drift <= 1, "last_login preserved: {drift}s drift");
        assert_eq!(got.active, cert.active);
    }

    #[tokio::test]
    async fn upsert_idempotent_preserves_created() {
        let (_b, svc) = fresh_backend().await;
        let wa_id = unique_id("wa");
        let cert1 = mk_minimal(&wa_id, &unique_id("kid"));
        let original_created = cert1.created;
        svc.upsert_wa_cert(cert1.clone()).await.unwrap();
        svc.upsert_wa_cert(cert1.clone()).await.unwrap();

        let mut cert2 = cert1.clone();
        cert2.name = "Renamed".into();
        cert2.active = false;
        cert2.created = Utc::now() + chrono::Duration::hours(1);
        svc.upsert_wa_cert(cert2).await.unwrap();

        let got = svc.get_wa_cert(&wa_id).await.unwrap().unwrap();
        assert_eq!(got.name, "Renamed");
        assert!(!got.active);
        let drift = (got.created - original_created).num_seconds().abs();
        assert!(
            drift <= 1,
            "created preserved across upsert: {drift}s drift"
        );
    }

    #[tokio::test]
    async fn jwt_kid_unique_conflict() {
        let (_b, svc) = fresh_backend().await;
        let shared_kid = unique_id("shared-kid");
        let cert1 = mk_minimal(&unique_id("wa1"), &shared_kid);
        let cert2 = mk_minimal(&unique_id("wa2"), &shared_kid);
        svc.upsert_wa_cert(cert1).await.unwrap();
        let res = svc.upsert_wa_cert(cert2).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected UNIQUE jwt_kid conflict, got {res:?}"
        );
    }

    #[tokio::test]
    async fn self_fk_rejects_nonexistent_parent() {
        let (b, svc) = fresh_backend().await;
        if !fk_pragma_on(&b).await {
            eprintln!("SQLite foreign_keys pragma off — skipping FK rejection check.");
            return;
        }
        let mut cert = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        cert.parent_wa_id = Some(unique_id("nonexistent-parent"));
        let res = svc.upsert_wa_cert(cert).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling parent_wa_id, got {res:?}"
        );
    }

    #[tokio::test]
    async fn null_parent_passes_fk() {
        let (_b, svc) = fresh_backend().await;
        let cert = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        assert!(cert.parent_wa_id.is_none());
        svc.upsert_wa_cert(cert).await.unwrap();
    }

    #[tokio::test]
    async fn get_by_kid_finds_via_unique_index() {
        let (_b, svc) = fresh_backend().await;
        let kid = unique_id("kid");
        let cert = mk_minimal(&unique_id("wa"), &kid);
        svc.upsert_wa_cert(cert.clone()).await.unwrap();
        let got = svc.get_by_kid(&kid).await.unwrap().unwrap();
        assert_eq!(got.wa_id, cert.wa_id);

        let missing = svc.get_by_kid(&unique_id("missing-kid")).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn get_by_oauth_finds_via_partial_index() {
        let (_b, svc) = fresh_backend().await;
        let external_id = unique_id("oauth-ext");
        let mut cert = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        cert.oauth_provider = Some("google".into());
        cert.oauth_external_id = Some(external_id.clone());
        svc.upsert_wa_cert(cert.clone()).await.unwrap();

        let got = svc
            .get_by_oauth("google", &external_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.wa_id, cert.wa_id);

        // Wrong provider → None.
        let missing = svc.get_by_oauth("github", &external_id).await.unwrap();
        assert!(missing.is_none());

        // Missing oauth fields filter rejects via InvalidArgument.
        let res = svc.get_by_oauth("", &external_id).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }

    #[tokio::test]
    async fn list_by_role_filters_active_true() {
        let (_b, svc) = fresh_backend().await;
        let mk = |role: WaRole, active: bool, suffix: &str| -> WaCert {
            let mut c = mk_minimal(
                &unique_id(&format!("wa-{suffix}")),
                &unique_id(&format!("kid-{suffix}")),
            );
            c.role = role;
            c.active = active;
            c
        };
        svc.upsert_wa_cert(mk(WaRole::Root, true, "root"))
            .await
            .unwrap();
        svc.upsert_wa_cert(mk(WaRole::Authority, true, "auth-a"))
            .await
            .unwrap();
        svc.upsert_wa_cert(mk(WaRole::Authority, false, "auth-inactive"))
            .await
            .unwrap();
        svc.upsert_wa_cert(mk(WaRole::Observer, true, "obs"))
            .await
            .unwrap();

        let authorities = svc.list_by_role(WaRole::Authority, 100).await.unwrap();
        assert_eq!(
            authorities.len(),
            1,
            "active=TRUE filter drops the inactive authority"
        );
        assert!(authorities[0].active);
        assert_eq!(authorities[0].role, WaRole::Authority);

        let observers = svc.list_by_role(WaRole::Observer, 100).await.unwrap();
        assert_eq!(observers.len(), 1);
        let roots = svc.list_by_role(WaRole::Root, 100).await.unwrap();
        assert_eq!(roots.len(), 1);
    }

    #[tokio::test]
    async fn set_active_toggle_and_missing_row() {
        let (_b, svc) = fresh_backend().await;
        let wa_id = unique_id("wa");
        let cert = mk_minimal(&wa_id, &unique_id("kid"));
        svc.upsert_wa_cert(cert).await.unwrap();

        let ok = svc.set_active(&wa_id, false).await.unwrap();
        assert!(ok);
        let got = svc.get_wa_cert(&wa_id).await.unwrap().unwrap();
        assert!(!got.active);

        let ok = svc.set_active(&wa_id, true).await.unwrap();
        assert!(ok);
        let got = svc.get_wa_cert(&wa_id).await.unwrap().unwrap();
        assert!(got.active);

        let missing = svc
            .set_active(&unique_id("missing-wa"), false)
            .await
            .unwrap();
        assert!(!missing);
    }

    #[tokio::test]
    async fn update_last_login_success_and_missing() {
        let (_b, svc) = fresh_backend().await;
        let wa_id = unique_id("wa");
        let cert = mk_minimal(&wa_id, &unique_id("kid"));
        svc.upsert_wa_cert(cert).await.unwrap();
        let now = Utc::now();
        let ok = svc.update_last_login(&wa_id, now).await.unwrap();
        assert!(ok);
        let got = svc.get_wa_cert(&wa_id).await.unwrap().unwrap();
        let drift = (got.last_login.unwrap() - now).num_seconds().abs();
        assert!(drift <= 1);

        let missing = svc
            .update_last_login(&unique_id("missing-wa"), now)
            .await
            .unwrap();
        assert!(!missing);
    }

    #[tokio::test]
    async fn role_check_rejects_unknown_value() {
        let (b, _svc) = fresh_backend().await;
        let conn = b.conn_handle();
        let res = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let guard = conn.blocking_lock();
            guard.execute(
                "INSERT INTO cirislens_wa_cert (\
                    wa_id, name, role, pubkey, jwt_kid, scopes, token_type, \
                    created, auto_minted, active\
                 ) VALUES ('wa-bad', 'n', 'admin', 'pk', 'kid-bad', '[]', 'standard', \
                           '2026-01-01T00:00:00Z', 0, 1)",
                params![],
            )
        })
        .await
        .unwrap();
        assert!(res.is_err(), "CHECK should reject 'admin'");
    }

    #[tokio::test]
    async fn token_type_check_rejects_unknown_value() {
        let (b, _svc) = fresh_backend().await;
        let conn = b.conn_handle();
        let res = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let guard = conn.blocking_lock();
            guard.execute(
                "INSERT INTO cirislens_wa_cert (\
                    wa_id, name, role, pubkey, jwt_kid, scopes, token_type, \
                    created, auto_minted, active\
                 ) VALUES ('wa-bad-tt', 'n', 'observer', 'pk', 'kid-bad-tt', '[]', 'jwt', \
                           '2026-01-01T00:00:00Z', 0, 1)",
                params![],
            )
        })
        .await
        .unwrap();
        assert!(res.is_err(), "CHECK should reject 'jwt' token_type");
    }

    #[tokio::test]
    async fn parent_tree_root_children_grandchild() {
        let (_b, svc) = fresh_backend().await;
        let root_id = unique_id("wa-root");
        let mut root = mk_minimal(&root_id, &unique_id("kid-root"));
        root.role = WaRole::Root;
        svc.upsert_wa_cert(root).await.unwrap();

        let child_a_id = unique_id("wa-child-a");
        let mut child_a = mk_minimal(&child_a_id, &unique_id("kid-child-a"));
        child_a.parent_wa_id = Some(root_id.clone());
        svc.upsert_wa_cert(child_a).await.unwrap();

        let child_b_id = unique_id("wa-child-b");
        let mut child_b = mk_minimal(&child_b_id, &unique_id("kid-child-b"));
        child_b.parent_wa_id = Some(root_id.clone());
        svc.upsert_wa_cert(child_b).await.unwrap();

        let gc_id = unique_id("wa-gc");
        let mut gc = mk_minimal(&gc_id, &unique_id("kid-gc"));
        gc.parent_wa_id = Some(child_a_id.clone());
        svc.upsert_wa_cert(gc).await.unwrap();

        let got_a = svc.get_wa_cert(&child_a_id).await.unwrap().unwrap();
        assert_eq!(got_a.parent_wa_id.as_deref(), Some(root_id.as_str()));
        let got_gc = svc.get_wa_cert(&gc_id).await.unwrap().unwrap();
        assert_eq!(got_gc.parent_wa_id.as_deref(), Some(child_a_id.as_str()));
    }

    #[tokio::test]
    async fn validate_required_columns() {
        let (_b, svc) = fresh_backend().await;
        let mut c = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        c.wa_id = String::new();
        let res = svc.upsert_wa_cert(c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut c = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        c.jwt_kid = String::new();
        let res = svc.upsert_wa_cert(c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut c = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        c.pubkey = String::new();
        let res = svc.upsert_wa_cert(c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
