//! v62.0.0 (slice A, P3 + P8) — I1794–I1795: the audit Merkle stores run
//! inside a current-thread runtime with no `block_on`, and the signed tree
//! head carries the installed clock's instant.
//!
//! Up to v61 both stores wrapped every SQL call in `runtime.block_on`. On a
//! current-thread runtime, or on a single-thread host where blocking work
//! runs inline, that panics ("Cannot start a runtime from within a
//! runtime"). These witnesses drive the real audit ingest path (chain
//! commit, Merkle append, STH sign, STH store) on exactly that shape.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use uuid::Uuid;

use super::service::AuditService;
use super::types::AuditEntry;
use super::verify::compute_entry_hash;
use super::GENESIS_PREV_HASH;
use crate::host::clock::{self, FixedClock};

/// Whole microseconds, far from any wall clock: the stores keep a stamp at
/// µs, so a stored head equals this exactly or the stamp came from
/// somewhere else.
fn fixed_instant() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2032, 7, 8, 9, 10, 11).unwrap() + chrono::Duration::microseconds(654_321)
}

fn merkle_signer(seed: u8) -> Arc<crate::signing::LocalSigner> {
    use ciris_keyring::MlDsa65SoftwareSigner;
    let pqc = MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], "i1794-pqc")
        .expect("seed bytes");
    let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
    Arc::new(crate::signing::LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        "i1794-steward".to_string(),
        Some(pqc),
        Some("i1794-pqc".to_string()),
    ))
}

fn signed_entry(key: &SigningKey, tenant: &str) -> AuditEntry {
    let mut entry = AuditEntry {
        entry_id: Uuid::new_v4().to_string(),
        sequence_number: 1,
        tenant_id: tenant.to_owned(),
        actor_id: B64.encode(key.verifying_key().to_bytes()),
        action_type: "handler_action_task_complete".to_owned(),
        subject_kind: "task".into(),
        subject_id: "subj-1".into(),
        payload: serde_json::json!({"seq": 1}),
        prev_hash: GENESIS_PREV_HASH.to_vec(),
        entry_hash: vec![],
        recorded_at: super::verify::truncate_to_micros(chrono::Utc::now()),
        signature: String::new(),
    };
    entry.entry_hash = compute_entry_hash(&entry).unwrap().to_vec();
    let canonical = super::verify::canonical_bytes_for_entry(&entry).unwrap();
    entry.signature = B64.encode(key.sign(&canonical).to_bytes());
    entry
}

/// The shared body: record one entry with the Merkle hook on, then read the
/// head back. The head must exist, cover the one leaf, and carry the
/// installed clock's instant.
async fn record_and_read_head<A: AuditService>(audit: &A, seed: u8, backend: &str) {
    let at = fixed_instant();
    let tenant = format!("i1794-{backend}-{}", Uuid::new_v4().simple());
    let key = SigningKey::from_bytes(&[seed; 32]);
    clock::install(Arc::new(FixedClock::new(at)));
    let recorded = audit.record_entry(signed_entry(&key, &tenant)).await;
    let head = audit.current_sth(&tenant).await;
    clock::uninstall();
    recorded.unwrap_or_else(|e| panic!("{backend}: record_entry: {e}"));
    let head = head
        .unwrap_or_else(|e| panic!("{backend}: current_sth: {e}"))
        .unwrap_or_else(|| panic!("{backend}: the Merkle hook stored no head"));
    assert_eq!(head.tree_size, 1, "{backend}: the head covers the one leaf");
    assert_eq!(
        head.timestamp, at,
        "{backend}: the signed head must carry the installed clock's instant"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::store::Backend as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// **I1794.** On a current-thread runtime in the single-thread profile
    /// (blocking work inline), the SQLite audit ingest path appends a Merkle
    /// leaf, signs and stores the head, and serves it back, without starting
    /// a thread; the head's instant is the installed clock's. v61's
    /// `SqliteMerkleStore` called `runtime.block_on` inside that inline
    /// closure and panicked.
    #[test]
    fn i1794_sqlite_merkle_hook_on_one_thread_stamps_the_clock() {
        crate::host::HostSeams::single_thread().install();
        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .on_thread_start(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .build()
            .unwrap();
        rt.block_on(async {
            let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            backend.run_migrations().await.unwrap();
            let audit = crate::audit::sqlite::SqliteAuditBackend::new(backend.conn_handle());
            audit.set_merkle_signer(Some(merkle_signer(0x94)));
            record_and_read_head(&audit, 0x94, "sqlite").await;
        });
        crate::host::rt::uninstall();
        assert_eq!(
            started.load(Ordering::SeqCst),
            0,
            "I1794: the single-thread audit path started a runtime thread"
        );
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::audit::merkle_leaf::AuditLeaf;
    use crate::audit::merkle_store::PgMerkleStore;
    use crate::store::Backend as _;

    fn leaf(entry_id: &str, chain_event_id: i64) -> AuditLeaf {
        let key = SigningKey::from_bytes(&[0x95; 32]);
        let mut e = signed_entry(&key, "i1795-leaf");
        e.entry_id = entry_id.to_owned();
        AuditLeaf::with_chain_event_id(e, chain_event_id)
    }

    /// **I1795.** `PgMerkleStore` is async end to end: inside a
    /// current-thread runtime (`#[tokio::test]`'s default flavour) it
    /// appends, sizes, roots, stores and reads a head and proves inclusion,
    /// with no `block_on`; v61's `self.runtime.block_on` on that runtime's
    /// own thread panicked. The audit ingest path over it stamps the head
    /// with the installed clock's instant.
    #[tokio::test]
    async fn i1795_pg_merkle_store_on_a_current_thread_runtime() {
        use ciris_verify_core::transparency::{verify_inclusion, SignedTreeHead};
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("I1795 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        assert_eq!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::CurrentThread,
            "I1795 must run on a current-thread runtime, or a block_on would not panic"
        );
        let backend = Arc::new(
            crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap(),
        );
        backend.run_migrations().await.unwrap();

        let tenant = format!("i1795-{}", Uuid::new_v4().simple());
        let store = PgMerkleStore::new(backend.clone(), tenant.clone());
        assert_eq!(store.tree_size().await.unwrap(), 0);
        for i in 0..3i64 {
            assert_eq!(
                store
                    .append(leaf(&format!("i1795-{i}"), 100 + i))
                    .await
                    .unwrap(),
                u64::try_from(i).unwrap()
            );
        }
        let root = store.root().await.unwrap();
        let signer = merkle_signer(0x95);
        let log_id = crate::audit::merkle_store::log_id_for_tenant(&tenant);
        let at = fixed_instant();
        let bytes = SignedTreeHead::signing_bytes(&log_id, 3, &root, at);
        let sth = SignedTreeHead {
            log_id,
            tree_size: 3,
            root_hash: root,
            timestamp: at,
            signature: signer.sign_hybrid(&bytes).await.unwrap(),
            witness_signatures: Vec::new(),
        };
        store.store_sth(&sth).await.unwrap();
        let back = store.latest_sth().await.unwrap().expect("stored head");
        assert_eq!(back.tree_size, 3);
        assert_eq!(back.root_hash, root);
        assert_eq!(back.timestamp, at);
        let proof = store.inclusion_proof(1).await.unwrap();
        assert!(
            verify_inclusion(&proof),
            "I1795: the inclusion proof verifies"
        );
        assert_eq!(proof.root, root);

        // The ingest path over the async store, stamped by the clock.
        backend.set_merkle_signer(Some(merkle_signer(0x96)));
        record_and_read_head(backend.as_ref(), 0x96, "postgres").await;
        backend.set_merkle_signer(None);
        eprintln!("I1795 postgres: RAN");
    }
}
