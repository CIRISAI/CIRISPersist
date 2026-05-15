//! v1.1.0 (CIRISPersist#43) — direct SQLite-backed OutboundQueue
//! constructor, without an `Engine` or `PyEngine`.
//!
//! Sovereign-mode CIRISEdge instances running over Reticulum on
//! Pi-class hardware use this to construct an
//! [`OutboundQueue`](crate::outbound::OutboundQueue) handle from a
//! SQLite file without going through the full substrate composition
//! surface.
//!
//! # Trait-object note
//!
//! The `OutboundQueue` trait is NOT object-safe — its methods return
//! RPITIT-style `impl Future + Send`, which precludes
//! `Arc<dyn OutboundQueue>`. Instead, this helper returns
//! `Arc<SqliteBackend>` directly; consumers call the trait methods
//! through the concrete handle.

use std::path::Path;
use std::sync::Arc;

use crate::store::{Backend, Error, SqliteBackend};

/// v1.1.0 (CIRISPersist#43) — direct SQLite-backed OutboundQueue
/// constructor. See the module-level doc for usage rationale.
pub struct EdgeOutboundQueueSqlite;

impl EdgeOutboundQueueSqlite {
    /// Open (or create) the file-backed SQLite database at `db_path`,
    /// run migrations, and return the constructed
    /// `Arc<SqliteBackend>`. The returned `Arc` implements
    /// [`OutboundQueue`](crate::outbound::OutboundQueue) (in addition
    /// to [`FederationDirectory`](crate::federation::FederationDirectory)
    /// and [`Backend`](crate::store::Backend) — same SQLite file
    /// holds every substrate primitive).
    ///
    /// Use the special path `":memory:"` for an ephemeral in-memory
    /// database (test fixture only — data does not survive process
    /// exit).
    pub async fn open(db_path: impl AsRef<Path>) -> Result<Arc<SqliteBackend>, Error> {
        let path = db_path.as_ref();
        let backend = if path == Path::new(":memory:") {
            SqliteBackend::open_in_memory().await?
        } else {
            SqliteBackend::open(path.to_string_lossy().into_owned()).await?
        };
        backend.run_migrations().await?;
        Ok(Arc::new(backend))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::{OutboundFilter, OutboundQueue};

    #[tokio::test]
    async fn open_in_memory_yields_usable_outbound_queue() {
        let backend = EdgeOutboundQueueSqlite::open(":memory:")
            .await
            .expect("open in-memory");
        // Trait method dispatch works through the concrete handle.
        let rows = backend
            .list_outbound(OutboundFilter::default(), 10)
            .await
            .expect("list");
        assert!(rows.is_empty());
    }
}
