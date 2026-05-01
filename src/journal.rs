//! Local outage-tolerance journal — `redb`-backed.
//!
//! # Mission alignment (FSD §3.4 robustness primitive #2)
//!
//! When Postgres is unreachable, batches go to a local append-only
//! journal at a configurable path (default
//! `/var/lib/cirislens/journal.redb`). On startup, the persister
//! replays journaled batches before accepting new traffic.
//! Append-only event semantics make this trivially safe: if the
//! agent's signature is preserved, the journal entry's bytes are
//! the agent's testimony exactly as shipped.
//!
//! Mission constraint (MISSION.md §2 — `store/`): the journal is
//! part of "robustly supporting every CIRIS deployment target." A
//! Pi-class sovereign agent that loses its database connection for
//! a few hours must not lose evidence; PoB §2.4's N_eff is computed
//! over a corpus that's missing nothing.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

const QUEUED_BATCHES: TableDefinition<u64, &[u8]> = TableDefinition::new("queued_batches");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const META_NEXT_SEQ: &str = "next_seq";

/// Append-only outage journal.
pub struct Journal {
    db: Arc<Database>,
    next_seq: AtomicU64,
}

impl Journal {
    /// Open or create a journal at `path`. Recovers `next_seq` from
    /// disk if the file existed.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, JournalError> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| JournalError::Io(format!("create_dir_all: {e}")))?;
            }
        }
        let db = Database::create(path.as_ref()).map_err(|e| JournalError::Open(e.to_string()))?;

        // Bootstrap tables (idempotent on existing files) and read
        // any persisted next_seq.
        {
            let txn = db
                .begin_write()
                .map_err(|e| JournalError::Backend(e.to_string()))?;
            {
                let _ = txn
                    .open_table(QUEUED_BATCHES)
                    .map_err(|e| JournalError::Backend(e.to_string()))?;
                let _ = txn
                    .open_table(META)
                    .map_err(|e| JournalError::Backend(e.to_string()))?;
            }
            txn.commit()
                .map_err(|e| JournalError::Backend(e.to_string()))?;
        }

        let next_seq = {
            let read = db
                .begin_read()
                .map_err(|e| JournalError::Backend(e.to_string()))?;
            let meta = read
                .open_table(META)
                .map_err(|e| JournalError::Backend(e.to_string()))?;
            meta.get(META_NEXT_SEQ)
                .map_err(|e| JournalError::Backend(e.to_string()))?
                .map(|g| g.value())
                .unwrap_or(1)
        };

        Ok(Self {
            db: Arc::new(db),
            next_seq: AtomicU64::new(next_seq),
        })
    }

    /// Append a raw batch payload. Returns the assigned sequence.
    pub fn append(&self, bytes: &[u8]) -> Result<u64, JournalError> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| JournalError::Backend(e.to_string()))?;
        {
            let mut table = txn
                .open_table(QUEUED_BATCHES)
                .map_err(|e| JournalError::Backend(e.to_string()))?;
            table
                .insert(seq, bytes)
                .map_err(|e| JournalError::Backend(e.to_string()))?;
            let mut meta = txn
                .open_table(META)
                .map_err(|e| JournalError::Backend(e.to_string()))?;
            meta.insert(META_NEXT_SEQ, seq + 1)
                .map_err(|e| JournalError::Backend(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| JournalError::Backend(e.to_string()))?;
        Ok(seq)
    }

    /// Drain all pending batches in sequence order, calling `handler`
    /// for each. If `handler` returns `Ok(())`, the entry is purged;
    /// if `Err`, replay halts and the remaining entries stay
    /// journaled. Returns the number of entries successfully
    /// replayed.
    ///
    /// Mission category §4 "Power-cycle resilience": this is the
    /// startup gate FSD §3.4 #2 names. We replay BEFORE accepting
    /// new traffic so journaled bytes go through the same pipeline
    /// in the same order they were originally received.
    pub fn replay<F>(&self, mut handler: F) -> Result<usize, JournalError>
    where
        F: FnMut(u64, &[u8]) -> Result<(), String>,
    {
        let mut replayed = 0usize;
        loop {
            let entry: Option<(u64, Vec<u8>)> = {
                let read = self
                    .db
                    .begin_read()
                    .map_err(|e| JournalError::Backend(e.to_string()))?;
                let table = read
                    .open_table(QUEUED_BATCHES)
                    .map_err(|e| JournalError::Backend(e.to_string()))?;
                let first = table
                    .first()
                    .map_err(|e| JournalError::Backend(e.to_string()))?;
                first.map(|(k, v)| (k.value(), v.value().to_vec()))
            };
            let Some((seq, bytes)) = entry else {
                break;
            };
            handler(seq, &bytes).map_err(JournalError::Replay)?;
            self.purge(seq)?;
            replayed += 1;
        }
        Ok(replayed)
    }

    /// Remove a single entry by sequence number.
    pub fn purge(&self, seq: u64) -> Result<(), JournalError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| JournalError::Backend(e.to_string()))?;
        {
            let mut table = txn
                .open_table(QUEUED_BATCHES)
                .map_err(|e| JournalError::Backend(e.to_string()))?;
            table
                .remove(seq)
                .map_err(|e| JournalError::Backend(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| JournalError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Number of entries currently pending replay.
    pub fn pending_count(&self) -> Result<u64, JournalError> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| JournalError::Backend(e.to_string()))?;
        let table = read
            .open_table(QUEUED_BATCHES)
            .map_err(|e| JournalError::Backend(e.to_string()))?;
        table
            .len()
            .map_err(|e| JournalError::Backend(e.to_string()))
    }
}

/// Journal-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// Filesystem IO failure (path not writable, ENOSPC, etc.).
    #[error("io: {0}")]
    Io(String),
    /// `redb` failed to open or initialize the journal file.
    #[error("redb open: {0}")]
    Open(String),
    /// `redb` runtime error during read/write.
    #[error("redb backend: {0}")]
    Backend(String),
    /// Handler-supplied replay failure.
    #[error("replay handler: {0}")]
    Replay(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Mission category §4 "Power-cycle resilience": journaled bytes
    /// survive process exit and replay in order.
    #[test]
    fn append_replay_round_trip() {
        let dir = temp_dir();
        let path = dir.path().join("j.redb");
        {
            let j = Journal::open(&path).unwrap();
            j.append(b"batch-1").unwrap();
            j.append(b"batch-2").unwrap();
            j.append(b"batch-3").unwrap();
            assert_eq!(j.pending_count().unwrap(), 3);
        }

        let j = Journal::open(&path).unwrap();
        let count = AtomicUsize::new(0);
        let collected: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());
        let n = j
            .replay(|_seq, bytes| {
                count.fetch_add(1, Ordering::SeqCst);
                collected.lock().unwrap().push(bytes.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(j.pending_count().unwrap(), 0);
        let collected = collected.into_inner().unwrap();
        assert_eq!(
            collected,
            vec![
                b"batch-1".to_vec(),
                b"batch-2".to_vec(),
                b"batch-3".to_vec()
            ],
            "replayed in append order"
        );
    }

    /// Mission constraint: replay halts on handler error so a downstream
    /// outage doesn't drop pending journal entries.
    #[test]
    fn replay_halts_on_handler_error() {
        let dir = temp_dir();
        let path = dir.path().join("j.redb");
        let j = Journal::open(&path).unwrap();
        j.append(b"a").unwrap();
        j.append(b"b").unwrap();
        j.append(b"c").unwrap();

        let calls = AtomicUsize::new(0);
        let _ = j.replay(|_seq, bytes| {
            calls.fetch_add(1, Ordering::SeqCst);
            if bytes == b"b" {
                Err("backend offline".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 2, "stopped after failure");
        assert_eq!(j.pending_count().unwrap(), 2, "b + c still pending");
    }

    /// Sequence numbers stay monotonic across reopens — never reused.
    #[test]
    fn next_seq_persists_across_reopen() {
        let dir = temp_dir();
        let path = dir.path().join("j.redb");
        let s1 = {
            let j = Journal::open(&path).unwrap();
            j.append(b"x").unwrap()
        };
        let j = Journal::open(&path).unwrap();
        let _ = j.replay(|_, _| Ok(())).unwrap();
        let s2 = j.append(b"y").unwrap();
        assert!(s2 > s1, "seq monotonic across reopen");
    }
}
