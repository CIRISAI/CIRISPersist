//! v60.0.0 (CIRISPersist#1002, steward ruling 2026-10-25: "parity even for
//! genesis") — **where a genesis door replays a bundle.**
//!
//! [`verify_ceremony_outputs`](super::verify_ceremony_outputs) — and through it
//! the import door, the ceremony's `finish` and the amend's `plan` / `finish` —
//! applies a candidate bundle through the ordinary doors on a directory that
//! holds only what a fresh node holds. That directory used to be the in-process
//! memory backend, which every build carried. It is now provisioned by the
//! backend the caller runs, one shared replay over a per-backend scratch:
//!
//! - SQLite: a migrated in-memory database (a clone of the per-process
//!   template, `store::sqlite_scratch`);
//! - PostgreSQL: a throwaway database in the live cluster, created from the
//!   configured DSN, migrated, and dropped when the replay ends — on success,
//!   on a refusal, and (through [`Drop`]) on a panic.
//!
//! A transaction rolled back on the live database was the alternative for
//! postgres and is not used: the replay runs a dozen doors, each on its own
//! pooled connection and its own transaction, so it does not fit one.

use crate::federation::{Error, FederationDirectory, SignedKeyRecord};

/// The scratch's release step: run once, after the replay.
type Release = Box<
    dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>
        + Send,
>;

/// A provisioned scratch directory, owned for one replay. Call
/// [`Self::release`] when done; dropping it unreleased releases it too
/// (blocking, on a thread of its own), so an early return or a panic leaves
/// nothing behind.
pub struct ScratchDirectory {
    dir: Option<Box<dyn FederationDirectory>>,
    release: Option<Release>,
}

impl ScratchDirectory {
    /// A scratch whose release is `release` (run after `dir` is dropped).
    #[must_use]
    pub fn new(
        dir: Box<dyn FederationDirectory>,
        release: impl FnOnce()
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>
            + Send
            + 'static,
    ) -> Self {
        Self {
            dir: Some(dir),
            release: Some(Box::new(release)),
        }
    }

    /// A scratch with nothing to release (an in-memory database).
    #[must_use]
    pub fn owned(dir: Box<dyn FederationDirectory>) -> Self {
        Self {
            dir: Some(dir),
            release: None,
        }
    }

    /// The directory the replay runs on.
    ///
    /// # Panics
    ///
    /// Never: the directory is held until [`Self::release`] consumes `self`.
    #[must_use]
    pub fn directory(&self) -> &dyn FederationDirectory {
        self.dir.as_deref().expect("held until release")
    }

    /// Drop the directory, then run the release step.
    ///
    /// # Errors
    ///
    /// The release step's failure (the scratch could not be removed).
    pub async fn release(mut self) -> Result<(), Error> {
        drop(self.dir.take());
        match self.release.take() {
            Some(r) => r().await,
            None => Ok(()),
        }
    }
}

/// Run a release step to completion on a thread of its own with its own
/// runtime, so it neither needs nor blocks on the caller's runtime.
fn release_blocking(r: Release) -> Result<(), Error> {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Backend(format!("genesis scratch: release runtime: {e}")))?
            .block_on(r())
    })
    .join()
    .map_err(|_| Error::Backend("genesis scratch: the release thread panicked".into()))?
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        drop(self.dir.take());
        // Unreleased: an early return or a panic.
        if let Some(r) = self.release.take() {
            if let Err(e) = release_blocking(r) {
                tracing::error!(error = %e, "genesis scratch: release on drop failed; the scratch may remain");
            }
        }
    }
}

/// A backend that can provision a genesis scratch (CIRISPersist#1002).
#[async_trait::async_trait]
pub trait GenesisScratch: Send + Sync {
    /// A fresh, migrated, empty directory holding exactly `holders` (this
    /// build's accord roster, seeded through the genesis seed door).
    ///
    /// # Errors
    ///
    /// The scratch could not be created, migrated or seeded; anything already
    /// created is released before the error returns.
    async fn provision_genesis_scratch(
        &self,
        holders: &[SignedKeyRecord],
    ) -> Result<ScratchDirectory, Error>;
}
