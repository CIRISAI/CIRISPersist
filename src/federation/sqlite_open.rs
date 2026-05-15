//! v1.1.0 (CIRISPersist#43) — direct SQLite-backed FederationDirectory
//! constructor, without an `Engine` or `PyEngine`.
//!
//! Sovereign-mode agents adopting CIRISEdge over Reticulum use this to
//! construct a [`FederationDirectory`](crate::federation::FederationDirectory)
//! handle from a SQLite file (or `:memory:`) without dragging in the
//! rest of the substrate composition surface.
//!
//! # Trait-object note
//!
//! The `FederationDirectory` trait is NOT object-safe — its methods
//! return RPITIT-style `impl Future + Send`, which precludes
//! `Arc<dyn FederationDirectory>`. Instead, this helper returns
//! `Arc<SqliteBackend>` directly; consumers call the trait methods
//! through the concrete handle.

use std::path::Path;
use std::sync::Arc;

use crate::store::{Backend, Error, SqliteBackend};

/// v1.1.0 (CIRISPersist#43) — direct SQLite-backed FederationDirectory
/// constructor. See the module-level doc for usage rationale.
pub struct FederationDirectorySqlite;

impl FederationDirectorySqlite {
    /// Open (or create) the file-backed SQLite database at `db_path`,
    /// run migrations, and return the constructed
    /// `Arc<SqliteBackend>`. The returned `Arc` implements
    /// [`FederationDirectory`](crate::federation::FederationDirectory)
    /// (in addition to [`OutboundQueue`](crate::outbound::OutboundQueue)
    /// and [`Backend`](crate::store::Backend) — same SQLite file holds
    /// every substrate primitive).
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
    use crate::federation::FederationDirectory;

    #[tokio::test]
    async fn open_in_memory_yields_usable_federation_directory() {
        let backend = FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open in-memory");
        // Trait method dispatch works through the concrete handle.
        // Disambiguate from `Backend::lookup_public_key` (different
        // return type — VerifyingKey vs KeyRecord — but same name).
        let row = FederationDirectory::lookup_public_key(&*backend, "does-not-exist")
            .await
            .expect("lookup");
        assert!(row.is_none());
    }
}
