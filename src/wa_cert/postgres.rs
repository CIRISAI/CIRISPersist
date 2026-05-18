//! PostgreSQL impl of [`WaCertService`] (v1.5.19, CIRISPersist#59 #11,
//! FINAL).
//!
//! 24 columns. Booleans (`auto_minted`, `active`) ride as `bool`
//! (BOOLEAN); JSON columns (`oauth_links`, `scopes`,
//! `custom_permissions`, `adapter_metadata`) ride as
//! `serde_json::Value` (JSONB); timestamps cross as
//! `chrono::DateTime<Utc>` (TIMESTAMPTZ); `role` + `token_type` ride
//! as SQL strings via `WaRole::as_sql_str` / `TokenType::as_sql_str`.
//!
//! Self-FK on `parent_wa_id` is `DEFERRABLE INITIALLY DEFERRED` (V034)
//! so a bulk INSERT of parent + child in the same tx passes the
//! constraint check at COMMIT.
//!
//! `upsert_wa_cert` uses `INSERT ... ON CONFLICT (wa_id) DO UPDATE
//! SET ...` — every column except `wa_id` + `created` overwrites on
//! conflict. `created` is preserved per the spec.

use chrono::{DateTime, Utc};

use super::service::WaCertService;
use super::types::{TokenType, WaCert, WaRole};
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

fn decode_row(row: &tokio_postgres::Row) -> Result<WaCert, Error> {
    let role_str: String = row
        .try_get("role")
        .map_err(|e| Error::Backend(format!("decode role: {e}")))?;
    let role = WaRole::parse_str(&role_str)
        .ok_or_else(|| Error::Backend(format!("decode role: unknown vocabulary `{role_str}`")))?;
    let token_type_str: String = row
        .try_get("token_type")
        .map_err(|e| Error::Backend(format!("decode token_type: {e}")))?;
    let token_type = TokenType::parse_str(&token_type_str).ok_or_else(|| {
        Error::Backend(format!(
            "decode token_type: unknown vocabulary `{token_type_str}`"
        ))
    })?;
    Ok(WaCert {
        wa_id: row
            .try_get("wa_id")
            .map_err(|e| Error::Backend(format!("decode wa_id: {e}")))?,
        name: row
            .try_get("name")
            .map_err(|e| Error::Backend(format!("decode name: {e}")))?,
        role,
        pubkey: row
            .try_get("pubkey")
            .map_err(|e| Error::Backend(format!("decode pubkey: {e}")))?,
        jwt_kid: row
            .try_get("jwt_kid")
            .map_err(|e| Error::Backend(format!("decode jwt_kid: {e}")))?,
        password_hash: row
            .try_get("password_hash")
            .map_err(|e| Error::Backend(format!("decode password_hash: {e}")))?,
        api_key_hash: row
            .try_get("api_key_hash")
            .map_err(|e| Error::Backend(format!("decode api_key_hash: {e}")))?,
        oauth_provider: row
            .try_get("oauth_provider")
            .map_err(|e| Error::Backend(format!("decode oauth_provider: {e}")))?,
        oauth_external_id: row
            .try_get("oauth_external_id")
            .map_err(|e| Error::Backend(format!("decode oauth_external_id: {e}")))?,
        oauth_links: row
            .try_get("oauth_links")
            .map_err(|e| Error::Backend(format!("decode oauth_links: {e}")))?,
        veilid_id: row
            .try_get("veilid_id")
            .map_err(|e| Error::Backend(format!("decode veilid_id: {e}")))?,
        auto_minted: row
            .try_get("auto_minted")
            .map_err(|e| Error::Backend(format!("decode auto_minted: {e}")))?,
        parent_wa_id: row
            .try_get("parent_wa_id")
            .map_err(|e| Error::Backend(format!("decode parent_wa_id: {e}")))?,
        parent_signature: row
            .try_get("parent_signature")
            .map_err(|e| Error::Backend(format!("decode parent_signature: {e}")))?,
        scopes: row
            .try_get("scopes")
            .map_err(|e| Error::Backend(format!("decode scopes: {e}")))?,
        custom_permissions: row
            .try_get("custom_permissions")
            .map_err(|e| Error::Backend(format!("decode custom_permissions: {e}")))?,
        adapter_id: row
            .try_get("adapter_id")
            .map_err(|e| Error::Backend(format!("decode adapter_id: {e}")))?,
        adapter_name: row
            .try_get("adapter_name")
            .map_err(|e| Error::Backend(format!("decode adapter_name: {e}")))?,
        adapter_metadata: row
            .try_get("adapter_metadata")
            .map_err(|e| Error::Backend(format!("decode adapter_metadata: {e}")))?,
        token_type,
        created: row
            .try_get("created")
            .map_err(|e| Error::Backend(format!("decode created: {e}")))?,
        last_login: row
            .try_get("last_login")
            .map_err(|e| Error::Backend(format!("decode last_login: {e}")))?,
        active: row
            .try_get("active")
            .map_err(|e| Error::Backend(format!("decode active: {e}")))?,
    })
}

const SELECT_COLUMNS: &str = "wa_id, name, role, pubkey, jwt_kid, \
     password_hash, api_key_hash, oauth_provider, oauth_external_id, \
     oauth_links, veilid_id, auto_minted, parent_wa_id, parent_signature, \
     scopes, custom_permissions, adapter_id, adapter_name, adapter_metadata, \
     token_type, created, last_login, active";

impl WaCertService for PostgresBackend {
    async fn upsert_wa_cert(&self, cert: WaCert) -> Result<(), Error> {
        validate_cert(&cert)?;
        let role_str = cert.role.as_sql_str();
        let token_type_str = cert.token_type.as_sql_str();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirislens.wa_cert (\
                    wa_id, name, role, pubkey, jwt_kid, \
                    password_hash, api_key_hash, oauth_provider, oauth_external_id, \
                    oauth_links, veilid_id, auto_minted, parent_wa_id, parent_signature, \
                    scopes, custom_permissions, adapter_id, adapter_name, adapter_metadata, \
                    token_type, created, last_login, active\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                           $15, $16, $17, $18, $19, $20, $21, $22, $23) \
                 ON CONFLICT (wa_id) DO UPDATE SET \
                    name = EXCLUDED.name, \
                    role = EXCLUDED.role, \
                    pubkey = EXCLUDED.pubkey, \
                    jwt_kid = EXCLUDED.jwt_kid, \
                    password_hash = EXCLUDED.password_hash, \
                    api_key_hash = EXCLUDED.api_key_hash, \
                    oauth_provider = EXCLUDED.oauth_provider, \
                    oauth_external_id = EXCLUDED.oauth_external_id, \
                    oauth_links = EXCLUDED.oauth_links, \
                    veilid_id = EXCLUDED.veilid_id, \
                    auto_minted = EXCLUDED.auto_minted, \
                    parent_wa_id = EXCLUDED.parent_wa_id, \
                    parent_signature = EXCLUDED.parent_signature, \
                    scopes = EXCLUDED.scopes, \
                    custom_permissions = EXCLUDED.custom_permissions, \
                    adapter_id = EXCLUDED.adapter_id, \
                    adapter_name = EXCLUDED.adapter_name, \
                    adapter_metadata = EXCLUDED.adapter_metadata, \
                    token_type = EXCLUDED.token_type, \
                    last_login = EXCLUDED.last_login, \
                    active = EXCLUDED.active",
                &[
                    &cert.wa_id,
                    &cert.name,
                    &role_str,
                    &cert.pubkey,
                    &cert.jwt_kid,
                    &cert.password_hash,
                    &cert.api_key_hash,
                    &cert.oauth_provider,
                    &cert.oauth_external_id,
                    &cert.oauth_links,
                    &cert.veilid_id,
                    &cert.auto_minted,
                    &cert.parent_wa_id,
                    &cert.parent_signature,
                    &cert.scopes,
                    &cert.custom_permissions,
                    &cert.adapter_id,
                    &cert.adapter_name,
                    &cert.adapter_metadata,
                    &token_type_str,
                    &cert.created,
                    &cert.last_login,
                    &cert.active,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "upsert_wa_cert"))?;
        Ok(())
    }

    async fn get_wa_cert(&self, wa_id: &str) -> Result<Option<WaCert>, Error> {
        if wa_id.is_empty() {
            return Err(Error::InvalidArgument("wa_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                &format!("SELECT {SELECT_COLUMNS} FROM cirislens.wa_cert WHERE wa_id = $1"),
                &[&wa_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_wa_cert"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_row(&row)?)),
        }
    }

    async fn get_by_kid(&self, jwt_kid: &str) -> Result<Option<WaCert>, Error> {
        if jwt_kid.is_empty() {
            return Err(Error::InvalidArgument("jwt_kid required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                &format!("SELECT {SELECT_COLUMNS} FROM cirislens.wa_cert WHERE jwt_kid = $1"),
                &[&jwt_kid],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_by_kid"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_row(&row)?)),
        }
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.wa_cert \
                     WHERE oauth_provider = $1 AND oauth_external_id = $2"
                ),
                &[&oauth_provider, &oauth_external_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_by_oauth"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_row(&row)?)),
        }
    }

    async fn list_by_role(&self, role: WaRole, limit: i64) -> Result<Vec<WaCert>, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let role_str = role.as_sql_str().to_owned();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.wa_cert \
                     WHERE role = $1 AND active = TRUE \
                     ORDER BY created DESC, wa_id DESC \
                     LIMIT $2"
                ),
                &[&role_str, &limit],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_by_role"))?;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_row(row)?);
        }
        Ok(items)
    }

    async fn set_active(&self, wa_id: &str, active: bool) -> Result<bool, Error> {
        if wa_id.is_empty() {
            return Err(Error::InvalidArgument("wa_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.wa_cert SET active = $1 WHERE wa_id = $2",
                &[&active, &wa_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "set_active"))?;
        Ok(changed > 0)
    }

    async fn update_last_login(
        &self,
        wa_id: &str,
        login_time: DateTime<Utc>,
    ) -> Result<bool, Error> {
        if wa_id.is_empty() {
            return Err(Error::InvalidArgument("wa_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.wa_cert SET last_login = $1 WHERE wa_id = $2",
                &[&login_time, &wa_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "update_last_login"))?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
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

    fn unique_id(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_upsert_round_trip_all_24_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let wa_id = unique_id("wa");
        let kid = unique_id("kid");
        let cert = WaCert {
            wa_id: wa_id.clone(),
            name: "Alice".into(),
            role: WaRole::Authority,
            pubkey: "pk-base64".into(),
            jwt_kid: kid,
            password_hash: Some("argon2:abc".into()),
            api_key_hash: Some("hash-1".into()),
            oauth_provider: Some("google".into()),
            oauth_external_id: Some(unique_id("ext")),
            oauth_links: Some(serde_json::json!({"profile": "https://example/u/alice"})),
            veilid_id: Some("veilid-1".into()),
            auto_minted: true,
            parent_wa_id: None,
            parent_signature: Some("sig-base64".into()),
            scopes: serde_json::json!(["sign", "approve"]),
            custom_permissions: Some(serde_json::json!({"can_revoke": true})),
            adapter_id: Some(unique_id("adapter")),
            adapter_name: Some("discord".into()),
            adapter_metadata: Some(serde_json::json!({"guild_id": "g-1"})),
            token_type: TokenType::ApiKey,
            created: Utc::now(),
            last_login: Some(Utc::now()),
            active: true,
        };
        WaCertService::upsert_wa_cert(&backend, cert.clone())
            .await
            .unwrap();

        let got = WaCertService::get_wa_cert(&backend, &wa_id)
            .await
            .unwrap()
            .unwrap();
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
        assert!(got.last_login.is_some());
        assert_eq!(got.active, cert.active);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_upsert_idempotent_preserves_created() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let wa_id = unique_id("wa");
        let kid = unique_id("kid");
        let cert1 = mk_minimal(&wa_id, &kid);
        let original_created = cert1.created;
        WaCertService::upsert_wa_cert(&backend, cert1.clone())
            .await
            .unwrap();

        // Re-upsert with same data — should be a no-op (no observable
        // change).
        WaCertService::upsert_wa_cert(&backend, cert1.clone())
            .await
            .unwrap();

        // Now upsert with different data — should overwrite mutables
        // but preserve `created`.
        let mut cert2 = cert1.clone();
        cert2.name = "Renamed".into();
        cert2.active = false;
        cert2.created = Utc::now() + chrono::Duration::hours(1);
        WaCertService::upsert_wa_cert(&backend, cert2.clone())
            .await
            .unwrap();

        let got = WaCertService::get_wa_cert(&backend, &wa_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name, "Renamed");
        assert!(!got.active);
        let drift = (got.created - original_created).num_seconds().abs();
        assert!(
            drift <= 1,
            "created preserved across upsert: {drift}s drift (got vs original)"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_jwt_kid_unique_conflict() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let shared_kid = unique_id("shared-kid");
        let cert1 = mk_minimal(&unique_id("wa1"), &shared_kid);
        let cert2 = mk_minimal(&unique_id("wa2"), &shared_kid);
        WaCertService::upsert_wa_cert(&backend, cert1)
            .await
            .unwrap();
        let res = WaCertService::upsert_wa_cert(&backend, cert2).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected UNIQUE jwt_kid conflict, got {res:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_self_fk_rejects_nonexistent_parent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mut cert = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        cert.parent_wa_id = Some(unique_id("nonexistent-parent"));
        let res = WaCertService::upsert_wa_cert(&backend, cert).await;
        // PG: DEFERRABLE FK fires at COMMIT. Same observable error
        // kind (Conflict) either way.
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling parent_wa_id, got {res:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_null_parent_passes_fk() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let cert = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        assert!(cert.parent_wa_id.is_none());
        WaCertService::upsert_wa_cert(&backend, cert).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_get_by_kid_finds_via_unique_index() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let kid = unique_id("kid");
        let cert = mk_minimal(&unique_id("wa"), &kid);
        WaCertService::upsert_wa_cert(&backend, cert.clone())
            .await
            .unwrap();
        let got = WaCertService::get_by_kid(&backend, &kid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.wa_id, cert.wa_id);
        assert_eq!(got.jwt_kid, kid);

        // Missing kid → None.
        let missing = WaCertService::get_by_kid(&backend, &unique_id("missing-kid"))
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_get_by_oauth_finds_via_partial_index() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let external_id = unique_id("oauth-ext");
        let mut cert = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        cert.oauth_provider = Some("google".into());
        cert.oauth_external_id = Some(external_id.clone());
        WaCertService::upsert_wa_cert(&backend, cert.clone())
            .await
            .unwrap();

        let got = WaCertService::get_by_oauth(&backend, "google", &external_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.wa_id, cert.wa_id);

        // Wrong provider → None.
        let missing = WaCertService::get_by_oauth(&backend, "github", &external_id)
            .await
            .unwrap();
        assert!(missing.is_none());

        // A cert with NULL oauth_* fields must not be findable by
        // oauth lookup even when the supplied strings are "" (those
        // are rejected as InvalidArgument).
        let res = WaCertService::get_by_oauth(&backend, "", &external_id).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_list_by_role_filters_active_true() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // Tag each WA with a unique scope so list_by_role can be
        // filtered down to this test's rows even when the table is
        // shared across serial(postgres) tests.
        let test_tag = unique_id("test");
        let mk = |role: WaRole, active: bool, suffix: &str| -> WaCert {
            let mut c = mk_minimal(
                &unique_id(&format!("wa-{suffix}")),
                &unique_id(&format!("kid-{suffix}")),
            );
            c.role = role;
            c.active = active;
            c.scopes = serde_json::json!([test_tag]);
            c
        };
        WaCertService::upsert_wa_cert(&backend, mk(WaRole::Root, true, "root"))
            .await
            .unwrap();
        WaCertService::upsert_wa_cert(&backend, mk(WaRole::Authority, true, "auth-a"))
            .await
            .unwrap();
        WaCertService::upsert_wa_cert(&backend, mk(WaRole::Authority, false, "auth-inactive"))
            .await
            .unwrap();
        WaCertService::upsert_wa_cert(&backend, mk(WaRole::Observer, true, "obs"))
            .await
            .unwrap();

        let authorities = WaCertService::list_by_role(&backend, WaRole::Authority, 1000)
            .await
            .unwrap();
        // Filter to our test_tag in case other concurrent test data
        // exists.
        let mine: Vec<&WaCert> = authorities
            .iter()
            .filter(|c| c.scopes == serde_json::json!([test_tag]))
            .collect();
        assert_eq!(mine.len(), 1, "active=TRUE filter drops the inactive WA");
        assert!(mine[0].active);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_set_active_toggle_and_missing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let wa_id = unique_id("wa");
        let cert = mk_minimal(&wa_id, &unique_id("kid"));
        WaCertService::upsert_wa_cert(&backend, cert).await.unwrap();
        // active = TRUE initially.
        let ok = WaCertService::set_active(&backend, &wa_id, false)
            .await
            .unwrap();
        assert!(ok);
        let got = WaCertService::get_wa_cert(&backend, &wa_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!got.active);

        let ok = WaCertService::set_active(&backend, &wa_id, true)
            .await
            .unwrap();
        assert!(ok);
        let got = WaCertService::get_wa_cert(&backend, &wa_id)
            .await
            .unwrap()
            .unwrap();
        assert!(got.active);

        let missing = WaCertService::set_active(&backend, &unique_id("missing-wa"), false)
            .await
            .unwrap();
        assert!(!missing, "missing-row returns false");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_update_last_login_success_and_missing() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let wa_id = unique_id("wa");
        let cert = mk_minimal(&wa_id, &unique_id("kid"));
        WaCertService::upsert_wa_cert(&backend, cert).await.unwrap();
        let now = Utc::now();
        let ok = WaCertService::update_last_login(&backend, &wa_id, now)
            .await
            .unwrap();
        assert!(ok);
        let got = WaCertService::get_wa_cert(&backend, &wa_id)
            .await
            .unwrap()
            .unwrap();
        let drift = (got.last_login.unwrap() - now).num_seconds().abs();
        assert!(drift <= 1);

        let missing = WaCertService::update_last_login(&backend, &unique_id("missing-wa"), now)
            .await
            .unwrap();
        assert!(!missing);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_role_check_rejects_unknown_value() {
        // Direct raw-SQL insert of an out-of-vocabulary role; the
        // typed enum can't produce one. Mirrors the tickets/status
        // CHECK test pattern.
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend.pool().get().await.unwrap();
        let res = client
            .execute(
                "INSERT INTO cirislens.wa_cert (\
                    wa_id, name, role, pubkey, jwt_kid, scopes, token_type, \
                    created, auto_minted, active\
                 ) VALUES ($1, 'n', 'admin', 'pk', $2, '[]'::jsonb, 'standard', \
                           NOW(), FALSE, TRUE)",
                &[&unique_id("wa-bad-role"), &unique_id("kid-bad-role")],
            )
            .await;
        assert!(res.is_err(), "CHECK should reject 'admin'");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_token_type_check_rejects_unknown_value() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend.pool().get().await.unwrap();
        let res = client
            .execute(
                "INSERT INTO cirislens.wa_cert (\
                    wa_id, name, role, pubkey, jwt_kid, scopes, token_type, \
                    created, auto_minted, active\
                 ) VALUES ($1, 'n', 'observer', 'pk', $2, '[]'::jsonb, 'jwt', \
                           NOW(), FALSE, TRUE)",
                &[&unique_id("wa-bad-tt"), &unique_id("kid-bad-tt")],
            )
            .await;
        assert!(res.is_err(), "CHECK should reject 'jwt' token_type");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_parent_tree_root_children_grandchild() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let root_id = unique_id("wa-root");
        let mut root = mk_minimal(&root_id, &unique_id("kid-root"));
        root.role = WaRole::Root;
        WaCertService::upsert_wa_cert(&backend, root).await.unwrap();

        let child_a_id = unique_id("wa-child-a");
        let mut child_a = mk_minimal(&child_a_id, &unique_id("kid-child-a"));
        child_a.parent_wa_id = Some(root_id.clone());
        WaCertService::upsert_wa_cert(&backend, child_a)
            .await
            .unwrap();

        let child_b_id = unique_id("wa-child-b");
        let mut child_b = mk_minimal(&child_b_id, &unique_id("kid-child-b"));
        child_b.parent_wa_id = Some(root_id.clone());
        WaCertService::upsert_wa_cert(&backend, child_b)
            .await
            .unwrap();

        let gc_id = unique_id("wa-gc");
        let mut gc = mk_minimal(&gc_id, &unique_id("kid-gc"));
        gc.parent_wa_id = Some(child_a_id.clone());
        WaCertService::upsert_wa_cert(&backend, gc).await.unwrap();

        // Verify the chain holds.
        let got_a = WaCertService::get_wa_cert(&backend, &child_a_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_a.parent_wa_id.as_deref(), Some(root_id.as_str()));
        let got_gc = WaCertService::get_wa_cert(&backend, &gc_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_gc.parent_wa_id.as_deref(), Some(child_a_id.as_str()));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn wa_cert_pg_validate_required_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mut c = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        c.wa_id = String::new();
        let res = WaCertService::upsert_wa_cert(&backend, c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut c = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        c.jwt_kid = String::new();
        let res = WaCertService::upsert_wa_cert(&backend, c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut c = mk_minimal(&unique_id("wa"), &unique_id("kid"));
        c.pubkey = String::new();
        let res = WaCertService::upsert_wa_cert(&backend, c).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
