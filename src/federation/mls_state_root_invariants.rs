//! v50.0.0 (CIRISPersist#920, `FSD/SECOND_DEVICE.md` §2) — **I187: the
//! MLS-state root follows the content master**, through the door a host
//! holds: `Engine::open_mls_state(path)`.
//!
//! The row-level arms (hardware over the storage double, the row wins,
//! domain separation) are witnessed beside the opener in `encrypted_kv`;
//! these legs prove the Engine reads the SAME persisted
//! `federation_content_master` row the blob doors resolve, on each backend
//! that has it (sqlite, postgres — the memory backend has no content
//! master), and initialises it when absent.

use crate::encrypted_kv::{EncryptedKVStore as _, KVError, MlsStateCustodyKind, XChaChaKvStore};
use crate::engine::BackendDispatch;
use crate::federation::BlobStorage as _;
use crate::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

const SOFTWARE_MASTER: [u8; 32] = [0x3c; 32];

fn signer() -> std::sync::Arc<crate::signing::LocalSigner> {
    crate::federation::tier_ingest::test_support::local_signer("i187-mls-state-root")
}

async fn seed_row(engine: &Engine, kind: &str, b64: Option<String>) {
    let descriptor = format!("I187 seeded {kind} row");
    match engine.backend() {
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(b) => {
            b.get_client()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO cirislens.federation_content_master \
                        (id, key_kind, master_key_b64, descriptor) VALUES (0, $1, $2, $3)",
                    &[&kind, &b64, &descriptor],
                )
                .await
                .unwrap();
        }
        BackendDispatch::Sqlite(b) => {
            b.conn_handle()
                .lock()
                .execute(
                    "INSERT INTO federation_content_master \
                        (id, key_kind, master_key_b64, descriptor) VALUES (0, ?1, ?2, ?3)",
                    rusqlite::params![kind, b64, descriptor],
                )
                .unwrap();
        }
    }
}

async fn content_master(engine: &Engine) -> [u8; 32] {
    match engine.backend() {
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(b) => b.load_or_init_content_master().await.unwrap(),
        BackendDispatch::Sqlite(b) => b.load_or_init_content_master().await.unwrap(),
    }
}

/// The persisted row's kind, read with a plain SELECT that initialises
/// nothing (#920 review, finding 5): `None` means there is no row.
async fn row_kind_if_present(engine: &Engine) -> Option<String> {
    match engine.backend() {
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(b) => b
            .get_client()
            .await
            .unwrap()
            .query_opt(
                "SELECT key_kind FROM cirislens.federation_content_master WHERE id = 0",
                &[],
            )
            .await
            .unwrap()
            .map(|r| r.get::<_, String>(0)),
        BackendDispatch::Sqlite(b) => {
            use rusqlite::OptionalExtension as _;
            b.conn_handle()
                .lock()
                .query_row(
                    "SELECT key_kind FROM federation_content_master WHERE id = 0",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .unwrap()
        }
    }
}

fn has_kv_table(path: &std::path::Path) -> bool {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'encrypted_kv'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        > 0
}

/// I187(a)+(b) at the door — a software row opens as `Software`, survives a
/// reopen through the Engine, leaves the row unchanged, and the store's key
/// is not the content master.
async fn software_row_opens_as_software(engine: &Engine) {
    seed_row(engine, "software", Some(B64.encode(SOFTWARE_MASTER))).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mls.db");

    let (s, custody) = engine
        .open_mls_state(&path)
        .await
        .expect("a software host opens its MLS store");
    assert_eq!(custody.kind, MlsStateCustodyKind::Software);
    assert!(
        custody.descriptor.contains("software") && custody.descriptor.contains("I187 seeded"),
        "the descriptor names the class and the row, got: {}",
        custody.descriptor
    );
    s.put("mls", b"group", b"epoch-state").await.unwrap();
    drop(s);

    let (s, custody) = engine.open_mls_state(&path).await.expect("reopen");
    assert_eq!(custody.kind, MlsStateCustodyKind::Software);
    assert_eq!(
        s.get("mls", b"group").await.unwrap().as_deref(),
        Some(&b"epoch-state"[..]),
        "the state survives the restart"
    );
    drop(s);

    assert_eq!(
        content_master(engine).await,
        SOFTWARE_MASTER,
        "the opener must not have replaced the content master row"
    );
    let err = XChaChaKvStore::open(&path, &SOFTWARE_MASTER)
        .err()
        .expect("the content master itself must not open the MLS store");
    assert!(matches!(err, KVError::WrongPassphrase), "got {err}");
}

/// I187 — a node with no row yet gets one (as its first blob write would),
/// and the custody reported IS the row's kind.
async fn no_row_initialises_it_and_reports_its_kind(engine: &Engine) {
    assert_eq!(
        row_kind_if_present(engine).await,
        None,
        "precondition: a fresh node has no content-master row"
    );
    let dir = tempfile::tempdir().unwrap();
    let (_s, custody) = engine
        .open_mls_state(dir.path().join("mls.db"))
        .await
        .expect("a fresh node opens (its row is initialised on the way)");
    let kind = row_kind_if_present(engine)
        .await
        .expect("open_mls_state must have initialised the content-master row");
    assert_eq!(
        custody.kind.as_str(),
        kind,
        "the custody must be the persisted row's kind"
    );
}

/// I187(f) at the door (#920 review, finding 1) — a store v49 keyed from
/// the hardware seed under a SOFTWARE row (CIRISEdge v32.1.0 on a TPM host)
/// opens through the Engine as `Hardware` with the legacy descriptor; a
/// fresh store on the same node still opens as `Software`.
#[cfg(feature = "secrets")]
async fn a_v49_store_under_a_software_row_opens_as_legacy_hardware(engine: &Engine) {
    use crate::secrets::hardware::{derive_with_storage, test_doubles::FakeHardwareStorage};
    use std::sync::Arc;
    seed_row(engine, "software", Some(B64.encode(SOFTWARE_MASTER))).await;
    let storage = Arc::new(FakeHardwareStorage::empty());
    let over_double = |storage: Arc<FakeHardwareStorage>| {
        move |c: bool| {
            crate::secrets::hardware::derive_with_storage_typed(
                storage.as_ref(),
                crate::encrypted_kv::MLS_STATE_CONTEXT,
                c,
            )
            .map(|(k, d)| (zeroize::Zeroizing::new(k), d))
            .map_err(crate::encrypted_kv::HardwareRootError::from)
        }
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mls.db");
    // v49's opener: the hardware seed under MLS_STATE_CONTEXT, whatever the row.
    let (v49_key, _) = derive_with_storage(
        storage.as_ref(),
        crate::encrypted_kv::MLS_STATE_CONTEXT,
        true,
    )
    .unwrap();
    let s = XChaChaKvStore::open(&path, &v49_key).unwrap();
    s.put("mls", b"group", b"v49-state").await.unwrap();
    drop(s);

    let (s, custody) = engine
        .open_mls_state_with(&path, over_double(storage.clone()))
        .await
        .expect("the v49 store must still open");
    assert_eq!(custody.kind, MlsStateCustodyKind::Hardware);
    assert!(
        custody
            .descriptor
            .contains("legacy-v49-hardware-keyed-under-software-row"),
        "got: {}",
        custody.descriptor
    );
    assert_eq!(
        s.get("mls", b"group").await.unwrap().as_deref(),
        Some(&b"v49-state"[..])
    );

    let (_s, custody) = engine
        .open_mls_state_with(dir.path().join("fresh.db"), over_double(storage.clone()))
        .await
        .unwrap();
    assert_eq!(
        custody.kind,
        MlsStateCustodyKind::Software,
        "the compat arm is a fallback, never a preference"
    );
}

/// I187(c) at the door — a hardware row on a host whose seed is unreachable
/// refuses by name and writes nothing. On a host where the hardware root IS
/// reachable this leg has nothing to measure and says so.
async fn hardware_row_without_a_seed_refuses(engine: &Engine) {
    use crate::federation::at_rest_cascade::{content_master_key, ContentMasterSource};
    if matches!(
        content_master_key(false),
        ContentMasterSource::Hardware { .. }
    ) {
        eprintln!("I187(c) door leg skipped: this host reaches a hardware seed");
        return;
    }
    seed_row(engine, "hardware", None).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mls.db");
    let err = engine
        .open_mls_state(&path)
        .await
        .err()
        .expect("a hardware row with no reachable seed must not open");
    assert!(
        matches!(err, KVError::HardwareCustodyUnavailable(_)),
        "got {err}"
    );
    assert!(
        !has_kv_table(&path),
        "a refused open must leave nothing behind"
    );
}

async fn sqlite_engine() -> Engine {
    Engine::with_signer(signer(), "sqlite::memory:")
        .await
        .expect("sqlite engine")
}

#[tokio::test]
async fn i187_sqlite_software_row_opens_as_software() {
    software_row_opens_as_software(&sqlite_engine().await).await;
}

#[tokio::test]
async fn i187_sqlite_no_row_initialises_it_and_reports_its_kind() {
    no_row_initialises_it_and_reports_its_kind(&sqlite_engine().await).await;
}

#[tokio::test]
async fn i187_sqlite_hardware_row_without_a_seed_refuses() {
    hardware_row_without_a_seed_refuses(&sqlite_engine().await).await;
}

#[cfg(feature = "secrets")]
#[tokio::test]
async fn i187_sqlite_a_v49_store_under_a_software_row_opens_as_legacy_hardware() {
    a_v49_store_under_a_software_row_opens_as_legacy_hardware(&sqlite_engine().await).await;
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;

    /// The content-master row is one per database: each leg takes a
    /// database of its own.
    async fn pg_engine() -> Option<Engine> {
        let dsn = crate::test_pg::isolated_dsn()?;
        Some(
            Engine::with_signer(signer(), &dsn)
                .await
                .expect("pg engine"),
        )
    }

    #[tokio::test]
    async fn i187_postgres_software_row_opens_as_software() {
        let Some(e) = pg_engine().await else { return };
        software_row_opens_as_software(&e).await;
    }

    #[tokio::test]
    async fn i187_postgres_no_row_initialises_it_and_reports_its_kind() {
        let Some(e) = pg_engine().await else { return };
        no_row_initialises_it_and_reports_its_kind(&e).await;
    }

    #[tokio::test]
    async fn i187_postgres_hardware_row_without_a_seed_refuses() {
        let Some(e) = pg_engine().await else { return };
        hardware_row_without_a_seed_refuses(&e).await;
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn i187_postgres_a_v49_store_under_a_software_row_opens_as_legacy_hardware() {
        let Some(e) = pg_engine().await else { return };
        a_v49_store_under_a_software_row_opens_as_legacy_hardware(&e).await;
    }
}
