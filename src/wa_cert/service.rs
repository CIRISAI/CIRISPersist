//! `WaCertService` trait surface (v1.5.19, CIRISPersist#59 #11, FINAL).
//!
//! 7 methods. Same `impl Future<...> + Send` GAT pattern as the rest
//! of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use chrono::{DateTime, Utc};

use super::types::{WaCert, WaRole};
use super::Error;

/// Wa_cert substrate trait — absorbs CIRISAgent's `wa_cert` table.
/// The Wise-Authority cert directory; per-WA identity + auth columns
/// keyed on `wa_id`, with a self-FK on `parent_wa_id`.
pub trait WaCertService: Send + Sync {
    /// Idempotent upsert keyed on `wa_id`. Same shape as tasks /
    /// thoughts: same data is a no-op; differing data overwrites
    /// mutable columns (`name`, `role`, `pubkey`, `jwt_kid`,
    /// `*_hash`, `oauth_*`, `veilid_id`, `auto_minted`, `parent_*`,
    /// `scopes`, `custom_permissions`, `adapter_*`, `token_type`,
    /// `last_login`, `active`); preserves `created`.
    ///
    /// Constraint surfaces:
    /// - Duplicate `jwt_kid` across different `wa_id`s →
    ///   [`Error::Conflict`] (UNIQUE violation).
    /// - Non-NULL `parent_wa_id` referencing a missing parent →
    ///   [`Error::Conflict`] (FK violation; on PG the FK is
    ///   `DEFERRABLE INITIALLY DEFERRED` so the check fires at COMMIT
    ///   — same observable error kind).
    /// - Unknown role / token_type SQL string → [`Error::InvalidArgument`]
    ///   (CHECK violation; can't happen for callers using the typed
    ///   enums but does happen if a raw SQL caller sneaks a value in).
    fn upsert_wa_cert(&self, cert: WaCert) -> impl Future<Output = Result<(), Error>> + Send;

    /// Point lookup by `wa_id`. Returns `None` if no row matches.
    fn get_wa_cert(
        &self,
        wa_id: &str,
    ) -> impl Future<Output = Result<Option<WaCert>, Error>> + Send;

    /// JWT verification hot path — lookup by `jwt_kid`. Hits the
    /// unique `wa_cert_jwt_kid` index. Returns `None` if no row
    /// matches.
    fn get_by_kid(
        &self,
        jwt_kid: &str,
    ) -> impl Future<Output = Result<Option<WaCert>, Error>> + Send;

    /// OAuth login path — lookup by `(oauth_provider,
    /// oauth_external_id)`. Hits the partial `wa_cert_oauth` index.
    /// Returns the row iff a WA exists with BOTH fields matching the
    /// supplied values.
    fn get_by_oauth(
        &self,
        oauth_provider: &str,
        oauth_external_id: &str,
    ) -> impl Future<Output = Result<Option<WaCert>, Error>> + Send;

    /// Role-based listing — all certs with `active = TRUE` filtered by
    /// `role`. Used by `list_observers` / `list_authorities`. Hits the
    /// partial `wa_cert_role_active` index. Ordered `created DESC,
    /// wa_id DESC`.
    fn list_by_role(
        &self,
        role: WaRole,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<WaCert>, Error>> + Send;

    /// Activity toggle. Sets `active` to the supplied value. Returns
    /// `true` if any row was updated; `false` if `wa_id` doesn't
    /// exist. Idempotent — toggling to the same value still returns
    /// `true` when the row exists.
    fn set_active(
        &self,
        wa_id: &str,
        active: bool,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Last-login bookkeeping. Sets `last_login` to the supplied
    /// timestamp. Returns `true` if any row was updated; `false` if
    /// `wa_id` doesn't exist.
    fn update_last_login(
        &self,
        wa_id: &str,
        login_time: DateTime<Utc>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}
