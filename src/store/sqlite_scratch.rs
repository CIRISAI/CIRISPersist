//! v60.0.0 (CIRISPersist#1002) — **a fresh, migrated, in-memory SQLite
//! database, cloned from one migrated template per process.**
//!
//! `SqliteBackend::open_in_memory()` + `run_migrations()` costs 248 ms on the
//! dev box (the replay dominates); a clone of the migrated template costs
//! 7.1 ms. Each clone copies the template with the SQLite backup API and then
//! runs the real open path ([`Backend::run_migrations`]), which finds every
//! migration applied and runs the open-time passes over an empty store, so a
//! clone is a backend in exactly the state a fresh migrated one is.
//!
//! One caller: the test constructor (`store::test_backend`). v62.0.0
//! (json-cut C5): the genesis scratch that also used it is deleted with the
//! bundle/1 ceremony.

use std::sync::Arc;

use crate::store::sqlite::SqliteBackend;
use crate::store::{Backend as _, Error};

type Conn = Arc<parking_lot::Mutex<rusqlite::Connection>>;

static TEMPLATE: tokio::sync::OnceCell<Conn> = tokio::sync::OnceCell::const_new();

async fn template() -> Result<&'static Conn, Error> {
    TEMPLATE
        .get_or_try_init(|| async {
            let b = SqliteBackend::open_in_memory().await?;
            b.run_migrations().await?;
            Ok::<_, Error>(b.conn_handle())
        })
        .await
}

/// A fresh, empty, fully migrated in-memory [`SqliteBackend`]: one per call,
/// sharing nothing with any other.
///
/// # Errors
///
/// The template could not be built, the copy did not finish, or the open path
/// over the clone failed.
pub(crate) async fn migrated_in_memory() -> Result<SqliteBackend, Error> {
    let src = template().await?;
    let mut dst = rusqlite::Connection::open_in_memory()
        .map_err(|e| Error::Backend(format!("scratch: open the clone: {e}")))?;
    {
        let src = src.lock();
        let backup = rusqlite::backup::Backup::new(&src, &mut dst)
            .map_err(|e| Error::Backend(format!("scratch: backup handle: {e}")))?;
        // The whole template in one step, or the clone is a partial copy the
        // open path would silently re-migrate from scratch.
        let step = backup
            .step(-1)
            .map_err(|e| Error::Backend(format!("scratch: copy the template: {e}")))?;
        if step != rusqlite::backup::StepResult::Done {
            return Err(Error::Backend(format!(
                "scratch: the template copy stopped at {step:?}"
            )));
        }
    }
    let dst = SqliteBackend::apply_connection_settings(dst)?;
    let backend = SqliteBackend::from_handles(
        Arc::new(parking_lot::Mutex::new(dst)),
        crate::store::sqlite_conn_model::ReadPool::empty(),
    );
    backend.run_migrations().await?;
    Ok(backend)
}
