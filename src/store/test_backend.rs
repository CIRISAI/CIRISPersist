//! v60.0.0 (CIRISPersist#1002) — **the one backend constructor for tests.**
//!
//! The memory backend is retired. Every test that ran on it runs on
//! [`SqliteBackend`] in memory with every migration applied: real SQL, a real
//! schema and real transaction semantics, which is where the reds the memory
//! backend could not produce come from.
//!
//! Measured on this box (#1002 step 1, `measure` below): the memory backend's
//! constructor took 81-90 µs and `SqliteBackend::open_in_memory()` + `run_migrations()` took
//! 248 ms, so replay dominates. One migrated database per process is the
//! TEMPLATE; each [`test_backend`] clones it with the SQLite backup API and then
//! runs the real open path ([`Backend::run_migrations`]), which finds every
//! migration applied and runs the open-time passes over an empty store, so a
//! clone is a backend in exactly the state a fresh migrated one is.
//!
//! Synchronous on purpose: it replaces a synchronous constructor at every call
//! site, inside async tests and outside them. The open path runs on a scoped
//! thread with its own current-thread runtime, so it never blocks on, or
//! needs, the caller's runtime.

use std::sync::{Arc, OnceLock};

use crate::store::sqlite::SqliteBackend;
use crate::store::Backend as _;

type Conn = Arc<parking_lot::Mutex<rusqlite::Connection>>;

static TEMPLATE: OnceLock<Conn> = OnceLock::new();

/// Run `f`'s future to completion on a fresh current-thread runtime on its own
/// thread (no runtime context there, so the sqlite dispatcher runs inline).
fn on_own_runtime<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|s| {
        s.spawn(f)
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e))
    })
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test_backend: a current-thread runtime")
        .block_on(fut)
}

fn template() -> &'static Conn {
    TEMPLATE.get_or_init(|| {
        on_own_runtime(|| {
            block_on(async {
                let b = SqliteBackend::open_in_memory()
                    .await
                    .expect("test_backend template: open");
                b.run_migrations()
                    .await
                    .expect("test_backend template: migrate");
                b.conn_handle()
            })
        })
    })
}

/// A fresh, empty, fully migrated in-memory [`SqliteBackend`]: one per call,
/// sharing nothing with any other. The test constructor (#1002).
pub fn test_backend() -> SqliteBackend {
    let mut dst = rusqlite::Connection::open_in_memory().expect("test_backend: open the clone");
    {
        let src = template().lock();
        let backup =
            rusqlite::backup::Backup::new(&src, &mut dst).expect("test_backend: backup handle");
        // The whole template in one step, or the clone is a partial copy the
        // open path would silently re-migrate from scratch.
        assert_eq!(
            backup
                .step(-1)
                .expect("test_backend: copy the migrated template"),
            rusqlite::backup::StepResult::Done,
            "test_backend: the template copied in full"
        );
    }
    let dst = SqliteBackend::apply_connection_settings(dst).expect("test_backend: pragmas");
    let backend = SqliteBackend::from_handles(
        Arc::new(parking_lot::Mutex::new(dst)),
        crate::store::sqlite_conn_model::ReadPool::empty(),
    );
    on_own_runtime(|| {
        block_on(backend.run_migrations()).expect("test_backend: the open path over the clone");
    });
    backend
}

/// The fixture seams the retired memory backend carried, on the backend the
/// tests now run on. **Each writes BELOW every door** (no admission gate, no
/// signature check), exactly as the memory helpers did: a fixture that needs
/// a row to exist, not a witness of the door that would write it. A witness
/// of a door calls the door.
impl SqliteBackend {
    fn fixture_key_row(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
    ) {
        let admitted_at = on_own_runtime(|| block_on(self.next_key_admission_position()))
            .expect("fixture: key admission position")
            .to_rfc3339();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn_handle()
            .lock()
            .execute(
                "INSERT INTO federation_keys (key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, \
                    algorithm, identity_type, identity_ref, valid_from, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_key_id, scrub_timestamp, \
                    persist_row_hash, admitted_at) \
                 VALUES (?1, ?2, ?3, 'hybrid', 'agent', ?1, ?4, ?5, ?6, '', ?1, ?4, '', ?7) \
                 ON CONFLICT(key_id) DO UPDATE SET \
                    pubkey_ed25519_base64 = excluded.pubkey_ed25519_base64, \
                    pubkey_ml_dsa_65_base64 = excluded.pubkey_ml_dsa_65_base64",
                rusqlite::params![
                    key_id,
                    pubkey_ed25519_base64,
                    pubkey_ml_dsa_65_base64,
                    now,
                    serde_json::json!({ "id": key_id }).to_string(),
                    vec![0u8; 32],
                    admitted_at,
                ],
            )
            .expect("fixture: federation_keys row");
    }

    /// Fixture: register `key`'s Ed25519 half as `key_id` (a hybrid-PENDING
    /// row: no ML-DSA-65 half until one is attached).
    #[doc(hidden)]
    pub fn add_public_key(&self, key_id: &str, key: ed25519_dalek::VerifyingKey) {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
        self.fixture_key_row(key_id, &b64, None);
    }

    /// Fixture: a key row carrying only an ML-DSA-65 half (an Ed25519 half
    /// already present is kept).
    #[doc(hidden)]
    pub fn add_pqc_public_key(&self, key_id: &str, pqc_pubkey_b64: &str) {
        let held: Option<String> = self
            .conn_handle()
            .lock()
            .query_row(
                "SELECT pubkey_ed25519_base64 FROM federation_keys WHERE key_id = ?1",
                [key_id],
                |r| r.get(0),
            )
            .ok();
        self.fixture_key_row(key_id, held.as_deref().unwrap_or(""), Some(pqc_pubkey_b64));
    }

    /// Fixture read: every stored trace event row, in insertion order,
    /// through the backend's own page read.
    #[doc(hidden)]
    pub fn snapshot_events(&self) -> Vec<crate::store::types::TraceEventRow> {
        use crate::store::Backend as _;
        on_own_runtime(|| block_on(self.fetch_trace_events_page(-1, i64::MAX, None)))
            .expect("snapshot_events: fetch_trace_events_page")
            .into_iter()
            .map(|(_, row)| row)
            .collect()
    }
}

/// The fixtures only this crate's own tests use: `cfg(test)`, so no build a
/// consumer links carries a below-the-door writer it did not ask for.
#[cfg(test)]
impl SqliteBackend {
    /// Fixture: attach an ML-DSA-65 half to a row [`Self::add_public_key`]
    /// wrote. Panics when the row is absent.
    #[cfg(feature = "server")]
    pub(crate) fn set_pqc_pubkey(&self, key_id: &str, pubkey_ml_dsa_65_base64: &str) {
        let n = self
            .conn_handle()
            .lock()
            .execute(
                "UPDATE federation_keys SET pubkey_ml_dsa_65_base64 = ?2 WHERE key_id = ?1",
                rusqlite::params![key_id, pubkey_ml_dsa_65_base64],
            )
            .expect("fixture: set_pqc_pubkey");
        assert_eq!(
            n, 1,
            "set_pqc_pubkey: key_id must exist via add_public_key first"
        );
    }

    /// Fixture: grant `key_id` the role tags. Panics when the row is absent.
    #[cfg(feature = "server")]
    pub(crate) fn set_roles(&self, key_id: &str, roles: Vec<String>) {
        let n = self
            .conn_handle()
            .lock()
            .execute(
                "UPDATE federation_keys SET roles = ?2 WHERE key_id = ?1",
                rusqlite::params![key_id, serde_json::to_string(&roles).expect("roles json")],
            )
            .expect("fixture: set_roles");
        assert_eq!(
            n, 1,
            "set_roles: key_id must exist via add_public_key first"
        );
    }

    /// Fixture: a `founder_only` community whose roster is
    /// `member_identity_key_ids` (replacing one already held).
    pub(crate) fn add_community_membership(
        &self,
        community_key_id: &str,
        member_identity_key_ids: &[&str],
    ) {
        let now = chrono::Utc::now();
        let members: Vec<crate::federation::types::CommunityMember> = member_identity_key_ids
            .iter()
            .map(|k| crate::federation::types::CommunityMember {
                key_id: (*k).to_owned(),
                joined_at: now,
                role: None,
            })
            .collect();
        self.conn_handle()
            .lock()
            .execute(
                "INSERT INTO federation_communities (community_key_id, community_name, members, \
                    founded_at, consensus_protocol, persist_row_hash, admitted_at) \
                 VALUES (?1, ?2, ?3, ?4, 'founder_only', '', ?4) \
                 ON CONFLICT(community_key_id) DO UPDATE SET members = excluded.members",
                rusqlite::params![
                    community_key_id,
                    format!("test-community:{community_key_id}"),
                    serde_json::to_string(&members).expect("members json"),
                    now.to_rfc3339(),
                ],
            )
            .expect("fixture: federation_communities row");
    }

    /// Fixture: hold `attestation_id` in the trust-direction held set, as a
    /// node that stored the row before V167 does (CIRISPersist#973).
    pub(crate) fn mark_trust_direction_held(&self, attestation_id: &str) {
        self.conn_handle()
            .lock()
            .execute(
                "INSERT OR IGNORE INTO federation_trust_direction_held (attestation_id) VALUES (?1)",
                [attestation_id],
            )
            .expect("fixture: federation_trust_direction_held row");
    }

    /// Fixture: hold an attestation BELOW every admission gate, at the next
    /// serve position (a row an older build admitted).
    pub(crate) fn plant_attestation_below_the_door(&self, row: crate::federation::Attestation) {
        // Below the door means below its foreign keys too: a row an older
        // build stored can name a key this node no longer holds.
        let conn = self.conn_handle();
        let conn = conn.lock();
        conn.execute_batch("PRAGMA foreign_keys = OFF")
            .expect("fixture: foreign keys off");
        let planted = crate::store::sqlite::sqlite_insert_plane_row(&conn, &row);
        conn.execute_batch("PRAGMA foreign_keys = ON")
            .expect("fixture: foreign keys on");
        planted.expect("fixture: plant an attestation row");
    }

    /// Fixture: hold a key row past every `put_public_key` gate, as a node
    /// that admitted it under an older rule does (CIRISPersist#1044, I621).
    pub(crate) fn seed_key_row_unchecked_for_test(&self, mut row: crate::federation::KeyRecord) {
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)
            .expect("seeded key row hashes");
        let admitted_at = on_own_runtime(|| block_on(self.next_key_admission_position()))
            .expect("fixture: key admission position")
            .to_rfc3339();
        let json = |v: &serde_json::Value| v.to_string();
        self.conn_handle()
            .lock()
            .execute(
                "INSERT OR REPLACE INTO federation_keys (key_id, pubkey_ed25519_base64, \
                    pubkey_ml_dsa_65_base64, algorithm, identity_type, identity_ref, valid_from, \
                    valid_until, registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_signature_pqc, scrub_key_id, scrub_timestamp, \
                    pqc_completed_at, persist_row_hash, roles, attestation_evidence, consent_role, \
                    additional_scrubs, admitted_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
                    ?17, ?18, ?19, ?20, ?21)",
                rusqlite::params![
                    row.key_id,
                    row.pubkey_ed25519_base64,
                    row.pubkey_ml_dsa_65_base64,
                    row.algorithm,
                    row.identity_type,
                    row.identity_ref,
                    row.valid_from.to_rfc3339(),
                    row.valid_until.map(|t| t.to_rfc3339()),
                    json(&row.registration_envelope),
                    hex::decode(&row.original_content_hash).unwrap_or_default(),
                    row.scrub_signature_classical,
                    row.scrub_signature_pqc,
                    row.scrub_key_id,
                    row.scrub_timestamp.to_rfc3339(),
                    row.pqc_completed_at.map(|t| t.to_rfc3339()),
                    row.persist_row_hash,
                    (!row.capability_roles.is_empty())
                        .then(|| serde_json::to_string(&row.capability_roles).expect("roles")),
                    row.attestation_evidence.as_ref().map(json),
                    row.consent_role.clone().unwrap_or_else(|| {
                        crate::federation::types::consent_role::UNREGISTERED.to_owned()
                    }),
                    serde_json::to_string(&row.additional_scrubs).expect("additional_scrubs"),
                    admitted_at,
                ],
            )
            .expect("fixture: seed a key row");
    }

    /// Fixture read: the single integer `sql` selects (a count, usually).
    pub(crate) fn test_query_i64(&self, sql: &str) -> i64 {
        self.conn_handle()
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .expect("fixture: test_query_i64")
    }

    /// Fixture read: the highest community DEK epoch any minter holds for
    /// `community_key_id` (0 when none was ever minted).
    pub(crate) fn community_dek_epoch(&self, community_key_id: &str) -> u64 {
        let e: i64 = self
            .conn_handle()
            .lock()
            .query_row(
                "SELECT COALESCE(MAX(epoch), 0) FROM federation_community_dek_epoch \
                  WHERE community_key_id = ?1",
                [community_key_id],
                |r| r.get(0),
            )
            .expect("fixture: community_dek_epoch");
        u64::try_from(e).unwrap_or(0)
    }

    /// Fixture read: every stored LLM-call row, in insertion order.
    pub(crate) fn snapshot_llm_calls(&self) -> Vec<crate::store::types::TraceLlmCallRow> {
        let conn = self.conn_handle();
        let conn = conn.lock();
        let mut stmt = conn
            .prepare("SELECT * FROM trace_llm_calls ORDER BY rowid")
            .expect("snapshot_llm_calls: prepare");
        let rows = stmt
            .query_map([], crate::store::sqlite::sqlite_row_to_llm_call_row)
            .expect("snapshot_llm_calls: query")
            .map(|r| r.expect("snapshot_llm_calls: row"))
            .collect();
        rows
    }
}

#[cfg(test)]
mod measure {
    use crate::store::Backend as _;
    use std::time::Instant;

    /// #1002 step 1 — `open_in_memory()`, `open_in_memory()` + every
    /// migration, and the template clone. Run with
    /// `--run-ignored only --no-capture`. (The retired memory backend's
    /// constructor measured 81-90 µs on this box, CIRISPersist#1002.)
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn measure_open_in_memory_against_the_clone() {
        let n = 30u32;
        let t = Instant::now();
        for _ in 0..n {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            std::hint::black_box(&b);
        }
        let open = t.elapsed() / n;

        let t = Instant::now();
        for _ in 0..n {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
        }
        let migrated = t.elapsed() / n;

        let _ = super::test_backend(); // the template, built once
        let n_t = 200u32;
        let t = Instant::now();
        for _ in 0..n_t {
            std::hint::black_box(super::test_backend());
        }
        let cloned = t.elapsed() / n_t;
        println!(
            "#1002 MEASURE open_in_memory {open:?} | \
             open_in_memory+run_migrations {migrated:?} | test_backend (template clone + open path) {cloned:?}"
        );
    }

    /// The clone is a migrated, empty backend that serves a door.
    #[tokio::test]
    async fn the_clone_is_migrated_and_independent() {
        let a = super::test_backend();
        let b = super::test_backend();
        a.conn_handle()
            .lock()
            .execute_batch("CREATE TABLE s5_probe(x INTEGER)")
            .unwrap();
        let has = |be: &crate::store::sqlite::SqliteBackend| -> bool {
            be.conn_handle()
                .lock()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 's5_probe'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                == 1
        };
        assert!(has(&a) && !has(&b), "clones share nothing");
        assert!(
            crate::federation::FederationDirectory::lookup_public_key(&a, "nobody")
                .await
                .unwrap()
                .is_none()
        );
    }
}
