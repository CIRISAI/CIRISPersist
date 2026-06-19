//! `EncryptedKVStore` — app-layer XChaCha20-Poly1305 encrypted key/value
//! store over the bundled rusqlite (v9.2.0, CIRISPersist#243 part 3).
//!
//! # What this is
//!
//! A small, sovereign/edge-local encrypted key/value box. CIRISEdge layers
//! the openmls [`StorageProvider`] cold-state (MLS group state, ratchet
//! trees, secrets) on top of this surface so that the at-rest database file
//! is **opaque** to anyone who reads the bytes off disk without the boot
//! passphrase — the "cold-state opacity" property (CEWP
//! [`FSD/SCOPE_PRIVACY.md`](https://github.com/CIRISAI/CEWP/blob/main/FSD/SCOPE_PRIVACY.md)
//! §7.8 phone-class degraded posture).
//!
//! # Why NOT SQLCipher
//!
//! Operator-ratified: SQLCipher (or rusqlite's `bundled-sqlcipher`) would
//! change the shared `libsqlite3-sys` across all 7 wheel platforms — a
//! cross-platform C-build risk we explicitly reject. Instead the values
//! **and** keys are sealed at the **application layer** with the CIRISVerify
//! v6.3.0 scope-privacy crypto (pure-Rust `chacha20poly1305` / `hmac` /
//! `hkdf`): NO new C dependency, NO change to the shared bundled rusqlite,
//! NO wheel risk. The store uses the same bundled rusqlite every other
//! sqlite-backed surface in persist uses; only the *contents* of the rows
//! are sealed.
//!
//! # On-disk shape (`encrypted_kv` table)
//!
//! | column      | contents                                              |
//! |-------------|-------------------------------------------------------|
//! | `ns_blind`  | `HMAC-SHA3-256(K_blind, ns_bytes)` — namespace blind  |
//! | `key_blind` | `HMAC-SHA3-256(K_blind, ns_bytes ‖ key)` — key blind  |
//! | `nonce`     | 24-byte CSPRNG XChaCha nonce for `value_ct`           |
//! | `value_ct`  | `xchacha::seal(K_value(ns), nonce, value)`            |
//! | `key_nonce` | 24-byte CSPRNG XChaCha nonce for `key_ct`             |
//! | `key_ct`    | `xchacha::seal(K_value(ns), key_nonce, key)`          |
//!
//! `PRIMARY KEY (ns_blind, key_blind)`. **No plaintext namespace, key, or
//! value byte ever touches the file** — the blinds are keyed HMACs (not
//! reversible) and the value/key are AEAD-sealed. The sealed *plaintext
//! key* (`key_ct`) is stored so [`scan`](EncryptedKVStore::scan) can
//! recover plaintext keys for prefix filtering (blinded keys aren't
//! prefix-queryable, by construction).
//!
//! # Key hierarchy (derived from the boot passphrase)
//!
//! All derivations are HKDF-SHA3-256 / HMAC-SHA3-256 — the CIRISVerify
//! v6.3.0 scope-privacy primitives ([`ciris_crypto::kdf::hkdf_sha3_256`],
//! [`ciris_crypto::hmac::sha3_256`]).
//!
//! ```text
//! root      = HKDF-SHA3-256(salt = FIXED_APP_SALT, ikm = passphrase,
//!                           info = "ciris-persist/encrypted-kv/root/v1",  32)
//! K_blind   = HKDF-SHA3-256(salt = root,           ikm = [],
//!                           info = "ciris-persist/encrypted-kv/blind/v1", 32)
//! K_value(ns) = HKDF-SHA3-256(salt = root,         ikm = ns_bytes,
//!                           info = "ciris-persist/encrypted-kv/value/v1", 32)
//! ```
//!
//! `K_value` is namespace-bound (the namespace is the HKDF `ikm`), so a
//! ciphertext sealed under namespace `a` can never be opened under
//! namespace `b` even if an attacker mislabels the row — namespace
//! isolation is cryptographic, not just a `WHERE` clause.
//!
//! # Boot UX — refuse-to-open-without + wrong-passphrase fail-fast
//!
//! On open the store write-once seals a known constant under the
//! `__verifier__` namespace. On every subsequent open it re-opens that
//! sealed constant; a wrong passphrase derives a different `root` →
//! different `K_value("__verifier__")` → the AEAD open fails its Poly1305
//! tag → [`KVError::WrongPassphrase`]. The store **refuses to operate**
//! rather than silently starting with a bad key.
//!
//! # Hardware-key custodian boundary
//!
//! persist takes the **passphrase** in (`&[u8]`). The hardware-key
//! custodian — TPM / Secure Enclave keychain / DPAPI / libsecret that
//! *releases* the passphrase at boot — is the **caller/operator's**
//! responsibility, out of scope for this surface (FSD §7.8: the
//! phone-class degraded posture is passphrase-only; hardware sealing of
//! the passphrase is a higher tier the operator opts into). Derived keys
//! and the passphrase copy are zeroized on drop where practical.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension};
use zeroize::{Zeroize, Zeroizing};

/// XChaCha20-Poly1305 key length (bytes).
const KEY_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length (bytes). The 24-byte nonce is what
/// makes random per-seal nonces safe (collision probability negligible).
const NONCE_LEN: usize = ciris_crypto::xchacha::NONCE_LEN;

/// Fixed application salt for the root HKDF. This is a *domain separator*,
/// not a secret: it binds the root derivation to this exact store
/// (`ciris-persist/encrypted-kv`) so the same passphrase used elsewhere
/// derives unrelated keys. Hard-coded (no env override) so a deployment
/// can't accidentally desync the salt and lock itself out.
const FIXED_APP_SALT: &[u8] = b"ciris-persist/encrypted-kv/app-salt/v1";

/// HKDF `info` for the root key.
const INFO_ROOT: &[u8] = b"ciris-persist/encrypted-kv/root/v1";
/// HKDF `info` for the blinding key.
const INFO_BLIND: &[u8] = b"ciris-persist/encrypted-kv/blind/v1";
/// HKDF `info` for the per-namespace value key.
const INFO_VALUE: &[u8] = b"ciris-persist/encrypted-kv/value/v1";

/// Reserved namespace holding the passphrase verifier row. Callers must
/// not use it (rejected with [`KVError::InvalidArgument`]).
const VERIFIER_NS: &str = "__verifier__";
/// The known plaintext sealed under [`VERIFIER_NS`] at first open and
/// re-opened on every subsequent open to detect a wrong passphrase.
const VERIFIER_PLAINTEXT: &[u8] = b"ciris-persist/encrypted-kv/verifier/v1";
/// The fixed key (within [`VERIFIER_NS`]) the verifier row is stored under.
const VERIFIER_KEY: &[u8] = b"verifier";

/// Passphrase-INDEPENDENT `ns_blind` for the verifier row. The verifier
/// must live at a fixed, key-independent location so that on reopen **any**
/// passphrase addresses the *same* row — otherwise a wrong passphrase would
/// derive a different blind, find no row, and silently re-seal a fresh
/// verifier instead of failing. These are fixed SHA3-domain constants
/// (32 bytes each, the HMAC-SHA3-256 output width), not secrets. The
/// `__verifier__` namespace is reserved (callers are rejected), so there is
/// no collision with real `(ns_blind, key_blind)` rows. The AEAD open under
/// the passphrase-derived `K_value(__verifier__)` is the sole discriminator.
const VERIFIER_NS_BLIND: [u8; 32] = *b"ciris-persist/enc-kv/verif/ns/v1";
const VERIFIER_KEY_BLIND: [u8; 32] = *b"ciris-persist/enc-kv/verif/key/1";

/// Typed error for the [`EncryptedKVStore`] surface. Stable shape:
/// callers (CIRISEdge's openmls `StorageProvider` adapter) match on the
/// variant, not the message.
#[derive(Debug)]
pub enum KVError {
    /// The boot passphrase failed the `__verifier__` AEAD check (or a
    /// stored row failed to open). The store refuses to operate.
    WrongPassphrase,
    /// An AEAD open failed for a row that is not the verifier — a tampered
    /// / corrupt ciphertext, or a key/value sealed under a mismatched
    /// namespace. Opaque by design (we don't branch on the AEAD reason).
    AuthFailure(String),
    /// A crypto primitive (HKDF / HMAC / seal / RNG) faulted. Rare.
    Crypto(String),
    /// The underlying rusqlite backend errored.
    Backend(String),
    /// Caller passed an invalid argument (empty namespace, reserved
    /// namespace, etc.).
    InvalidArgument(String),
}

impl std::fmt::Display for KVError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KVError::WrongPassphrase => write!(
                f,
                "encrypted-kv: wrong passphrase (verifier AEAD open failed) — refusing to operate"
            ),
            KVError::AuthFailure(m) => write!(f, "encrypted-kv: AEAD open failed: {m}"),
            KVError::Crypto(m) => write!(f, "encrypted-kv: crypto fault: {m}"),
            KVError::Backend(m) => write!(f, "encrypted-kv: backend error: {m}"),
            KVError::InvalidArgument(m) => write!(f, "encrypted-kv: invalid argument: {m}"),
        }
    }
}

impl std::error::Error for KVError {}

/// A recovered `(plaintext_key, plaintext_value)` pair — the
/// [`EncryptedKVStore::scan`] element type.
pub type KvPair = (Vec<u8>, Vec<u8>);

impl From<rusqlite::Error> for KVError {
    fn from(e: rusqlite::Error) -> Self {
        KVError::Backend(e.to_string())
    }
}

/// App-layer encrypted key/value store.
///
/// Async surface mirrors the [`crate::federation::BlobStorage`] trait
/// style — `impl Future<Output = …> + Send` (Rust 1.75+ async-fn-in-trait
/// via the desugared form; not object-safe). `ns` is a UTF-8 namespace;
/// `key` / `value` are arbitrary bytes.
pub trait EncryptedKVStore: Send + Sync {
    /// Fetch the value stored at `(ns, key)`, or `None` if absent.
    fn get(
        &self,
        ns: &str,
        key: &[u8],
    ) -> impl Future<Output = Result<Option<Vec<u8>>, KVError>> + Send;

    /// Store `value` at `(ns, key)`, overwriting any existing value.
    fn put(
        &self,
        ns: &str,
        key: &[u8],
        value: &[u8],
    ) -> impl Future<Output = Result<(), KVError>> + Send;

    /// Delete `(ns, key)`. A no-op (Ok) if the key is absent.
    fn delete(&self, ns: &str, key: &[u8]) -> impl Future<Output = Result<(), KVError>> + Send;

    /// Return every `(plaintext_key, plaintext_value)` in `ns` whose key
    /// starts with `prefix`. O(namespace size) — adequate for MLS group
    /// state. Blinded keys aren't prefix-queryable, so this opens each
    /// row's sealed plaintext key, filters, then opens the value.
    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
    ) -> impl Future<Output = Result<Vec<KvPair>, KVError>> + Send;
}

/// XChaCha20-Poly1305-backed [`EncryptedKVStore`].
///
/// Backed by a **dedicated** rusqlite [`Connection`] (its own DB file,
/// separate from the federation-directory DB) wrapped in
/// `Arc<Mutex<…>>`, mirroring [`crate::store::sqlite::SqliteBackend`]'s
/// sync-`Connection`-in-async pattern. The table is self-created on open
/// (no refinery migration — this is a standalone local store, not part of
/// the versioned federation schema).
pub struct XChaChaKvStore {
    conn: Arc<Mutex<Connection>>,
    /// Derived key material. Zeroized on drop.
    keys: Keys,
}

/// Derived key hierarchy. Held only in memory; zeroized on drop.
struct Keys {
    /// Root key (HKDF over the passphrase). Retained so per-namespace
    /// `K_value` can be derived lazily on each op.
    root: [u8; KEY_LEN],
    /// Blinding key for namespace/key HMACs.
    k_blind: [u8; KEY_LEN],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.root.zeroize();
        self.k_blind.zeroize();
    }
}

impl Keys {
    /// Derive the root + blinding keys from the boot passphrase.
    fn derive(passphrase: &[u8]) -> Result<Keys, KVError> {
        let mut root_v =
            ciris_crypto::kdf::hkdf_sha3_256(passphrase, FIXED_APP_SALT, INFO_ROOT, KEY_LEN)
                .map_err(|e| KVError::Crypto(format!("hkdf root: {e}")))?;
        let mut root = [0u8; KEY_LEN];
        root.copy_from_slice(&root_v);
        root_v.zeroize();

        // K_blind = HKDF(salt = root, ikm = [], info = blind). Empty ikm is
        // valid — the root provides all the entropy as the HKDF salt.
        let mut blind_v = ciris_crypto::kdf::hkdf_sha3_256(&[], &root, INFO_BLIND, KEY_LEN)
            .map_err(|e| KVError::Crypto(format!("hkdf blind: {e}")))?;
        let mut k_blind = [0u8; KEY_LEN];
        k_blind.copy_from_slice(&blind_v);
        blind_v.zeroize();

        Ok(Keys { root, k_blind })
    }

    /// Derive the per-namespace value key. The namespace is the HKDF
    /// `ikm`, binding the AEAD key to the namespace cryptographically.
    /// Returned in a [`Zeroizing`] wrapper so the per-op key is scrubbed
    /// when the caller's frame drops; deref to `&[u8; 32]` for the AEAD.
    fn k_value(&self, ns_bytes: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, KVError> {
        let mut v = ciris_crypto::kdf::hkdf_sha3_256(ns_bytes, &self.root, INFO_VALUE, KEY_LEN)
            .map_err(|e| KVError::Crypto(format!("hkdf value: {e}")))?;
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&v);
        v.zeroize();
        Ok(Zeroizing::new(k))
    }

    /// `ns_blind = HMAC-SHA3-256(K_blind, ns_bytes)`.
    fn ns_blind(&self, ns_bytes: &[u8]) -> [u8; 32] {
        ciris_crypto::hmac::sha3_256(&self.k_blind, ns_bytes)
    }

    /// `key_blind = HMAC-SHA3-256(K_blind, ns_bytes ‖ key)`. The namespace
    /// prefix means the same key in two namespaces blinds differently.
    fn key_blind(&self, ns_bytes: &[u8], key: &[u8]) -> [u8; 32] {
        let mut msg = Vec::with_capacity(ns_bytes.len() + key.len());
        msg.extend_from_slice(ns_bytes);
        msg.extend_from_slice(key);
        let h = ciris_crypto::hmac::sha3_256(&self.k_blind, &msg);
        msg.zeroize();
        h
    }
}

/// Generate a fresh 24-byte XChaCha nonce from the OS CSPRNG.
fn random_nonce() -> Result<[u8; NONCE_LEN], KVError> {
    let v = ciris_crypto::random::bytes(NONCE_LEN)
        .map_err(|e| KVError::Crypto(format!("random nonce: {e}")))?;
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&v);
    Ok(n)
}

/// Seal `plaintext` under `key` with a fresh CSPRNG nonce. Returns
/// `(nonce, ciphertext‖tag)`.
fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), KVError> {
    let nonce = random_nonce()?;
    let ct = ciris_crypto::xchacha::seal(key, &nonce, plaintext)
        .map_err(|e| KVError::Crypto(format!("seal: {e}")))?;
    Ok((nonce, ct))
}

impl XChaChaKvStore {
    /// Open (or create) the store at `path` with the boot `passphrase`.
    ///
    /// Self-creates the `encrypted_kv` table, derives the key hierarchy,
    /// and runs the passphrase verifier:
    /// - first open ever → write-once seals the [`VERIFIER_PLAINTEXT`]
    ///   constant under [`VERIFIER_NS`];
    /// - subsequent opens → re-open the verifier row. A wrong passphrase
    ///   ⇒ [`KVError::WrongPassphrase`] and the store is NOT returned.
    ///
    /// `passphrase` is taken by `&[u8]`; the hardware-key custodian that
    /// released it is the caller's responsibility (see module docs).
    pub fn open(path: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, KVError> {
        let conn = Connection::open(path).map_err(|e| KVError::Backend(e.to_string()))?;
        Self::from_connection(conn, passphrase)
    }

    /// Open an in-memory store (tests). Same key derivation + verifier
    /// path as [`open`](Self::open); the DB lives only for the process.
    pub fn open_in_memory(passphrase: &[u8]) -> Result<Self, KVError> {
        let conn = Connection::open_in_memory().map_err(|e| KVError::Backend(e.to_string()))?;
        Self::from_connection(conn, passphrase)
    }

    fn from_connection(conn: Connection, passphrase: &[u8]) -> Result<Self, KVError> {
        // Copy the passphrase into a zeroizing buffer for the derivation
        // so the caller's slice isn't the only lifetime we depend on, and
        // our working copy is scrubbed when this scope ends.
        let pass = Zeroizing::new(passphrase.to_vec());
        let keys = Keys::derive(&pass)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS encrypted_kv (\
                 ns_blind  BLOB NOT NULL, \
                 key_blind BLOB NOT NULL, \
                 nonce     BLOB NOT NULL, \
                 value_ct  BLOB NOT NULL, \
                 key_nonce BLOB NOT NULL, \
                 key_ct    BLOB NOT NULL, \
                 PRIMARY KEY (ns_blind, key_blind)\
             )",
            [],
        )
        .map_err(|e| KVError::Backend(format!("create table: {e}")))?;

        let store = XChaChaKvStore {
            conn: Arc::new(Mutex::new(conn)),
            keys,
        };

        store.verify_passphrase()?;
        Ok(store)
    }

    /// Write-once-then-check the `__verifier__` row. Returns
    /// [`KVError::WrongPassphrase`] if the verifier exists but does not
    /// open to the expected constant under the derived key.
    fn verify_passphrase(&self) -> Result<(), KVError> {
        let ns_bytes = VERIFIER_NS.as_bytes();
        // Fixed, passphrase-independent blinds so every passphrase addresses
        // the same row — the AEAD open under the derived key is what detects
        // a wrong passphrase. (See VERIFIER_NS_BLIND docs.)
        let ns_blind = VERIFIER_NS_BLIND.to_vec();
        let key_blind = VERIFIER_KEY_BLIND.to_vec();
        let k_value = self.keys.k_value(ns_bytes)?;

        let existing: Option<(Vec<u8>, Vec<u8>)> = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT nonce, value_ct FROM encrypted_kv \
                     WHERE ns_blind = ?1 AND key_blind = ?2",
                rusqlite::params![ns_blind, key_blind],
                |row| {
                    let nonce: Vec<u8> = row.get("nonce")?;
                    let value_ct: Vec<u8> = row.get("value_ct")?;
                    Ok((nonce, value_ct))
                },
            )
            .optional()?
        };

        match existing {
            None => {
                // First open ever — write-once seal the verifier constant.
                let (nonce, value_ct) = seal(&k_value, VERIFIER_PLAINTEXT)?;
                let (key_nonce, key_ct) = seal(&k_value, VERIFIER_KEY)?;
                let conn = self.conn.lock();
                conn.execute(
                    "INSERT INTO encrypted_kv \
                         (ns_blind, key_blind, nonce, value_ct, key_nonce, key_ct) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        ns_blind,
                        key_blind,
                        nonce.to_vec(),
                        value_ct,
                        key_nonce.to_vec(),
                        key_ct
                    ],
                )?;
                Ok(())
            }
            Some((nonce, value_ct)) => {
                let nonce_arr = to_nonce(&nonce)?;
                let opened = ciris_crypto::xchacha::open(&k_value, &nonce_arr, &value_ct)
                    // A verifier open failure means the derived key is
                    // wrong ⇒ wrong passphrase. Fail-fast, refuse to start.
                    .map_err(|_| KVError::WrongPassphrase)?;
                if opened.as_slice() == VERIFIER_PLAINTEXT {
                    Ok(())
                } else {
                    Err(KVError::WrongPassphrase)
                }
            }
        }
    }

    /// Run a blocking rusqlite closure on the tokio blocking pool, keeping
    /// the synchronous `Connection` off the async runtime threads. Mirrors
    /// [`crate::store::sqlite::SqliteBackend`]'s spawn-blocking adapter.
    async fn blocking<T, F>(&self, f: F) -> Result<T, KVError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, KVError> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            f(&guard)
        })
        .await
        .map_err(|e| KVError::Backend(format!("join: {e}")))?
    }

    /// Reject empty / reserved namespaces before any crypto runs.
    fn check_ns(ns: &str) -> Result<(), KVError> {
        if ns.is_empty() {
            return Err(KVError::InvalidArgument(
                "namespace must be non-empty".into(),
            ));
        }
        if ns == VERIFIER_NS {
            return Err(KVError::InvalidArgument(format!(
                "namespace {VERIFIER_NS:?} is reserved"
            )));
        }
        Ok(())
    }
}

/// Coerce a stored nonce blob to the fixed 24-byte array, rejecting a
/// wrong length (corrupt row) as an auth failure.
fn to_nonce(b: &[u8]) -> Result<[u8; NONCE_LEN], KVError> {
    if b.len() != NONCE_LEN {
        return Err(KVError::AuthFailure(format!(
            "nonce length {} != {NONCE_LEN}",
            b.len()
        )));
    }
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(b);
    Ok(n)
}

impl EncryptedKVStore for XChaChaKvStore {
    fn get(
        &self,
        ns: &str,
        key: &[u8],
    ) -> impl Future<Output = Result<Option<Vec<u8>>, KVError>> + Send {
        let res = (|| {
            Self::check_ns(ns)?;
            let ns_bytes = ns.as_bytes().to_vec();
            let ns_blind = self.keys.ns_blind(&ns_bytes).to_vec();
            let key_blind = self.keys.key_blind(&ns_bytes, key).to_vec();
            let k_value = self.keys.k_value(&ns_bytes)?;
            Ok::<_, KVError>((ns_blind, key_blind, k_value))
        })();
        async move {
            let (ns_blind, key_blind, k_value) = res?;
            let row: Option<(Vec<u8>, Vec<u8>)> = self
                .blocking(move |conn| {
                    conn.query_row(
                        "SELECT nonce, value_ct FROM encrypted_kv \
                             WHERE ns_blind = ?1 AND key_blind = ?2",
                        rusqlite::params![ns_blind, key_blind],
                        |row| {
                            let nonce: Vec<u8> = row.get("nonce")?;
                            let value_ct: Vec<u8> = row.get("value_ct")?;
                            Ok((nonce, value_ct))
                        },
                    )
                    .optional()
                    .map_err(KVError::from)
                })
                .await?;
            match row {
                None => Ok(None),
                Some((nonce, value_ct)) => {
                    let nonce_arr = to_nonce(&nonce)?;
                    let pt = ciris_crypto::xchacha::open(&k_value, &nonce_arr, &value_ct)
                        .map_err(|e| KVError::AuthFailure(e.to_string()))?;
                    Ok(Some(pt))
                }
            }
        }
    }

    fn put(
        &self,
        ns: &str,
        key: &[u8],
        value: &[u8],
    ) -> impl Future<Output = Result<(), KVError>> + Send {
        let res = (|| {
            Self::check_ns(ns)?;
            let ns_bytes = ns.as_bytes().to_vec();
            let ns_blind = self.keys.ns_blind(&ns_bytes).to_vec();
            let key_blind = self.keys.key_blind(&ns_bytes, key).to_vec();
            let k_value = self.keys.k_value(&ns_bytes)?;
            let (nonce, value_ct) = seal(&k_value, value)?;
            let (key_nonce, key_ct) = seal(&k_value, key)?;
            Ok::<_, KVError>((
                ns_blind,
                key_blind,
                nonce.to_vec(),
                value_ct,
                key_nonce.to_vec(),
                key_ct,
            ))
        })();
        async move {
            let (ns_blind, key_blind, nonce, value_ct, key_nonce, key_ct) = res?;
            self.blocking(move |conn| {
                // First-write-wins is NOT the policy here (unlike scope
                // blobs) — a KV store overwrites. UPSERT on the PK.
                conn.execute(
                    "INSERT INTO encrypted_kv \
                         (ns_blind, key_blind, nonce, value_ct, key_nonce, key_ct) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                         ON CONFLICT(ns_blind, key_blind) DO UPDATE SET \
                             nonce = excluded.nonce, \
                             value_ct = excluded.value_ct, \
                             key_nonce = excluded.key_nonce, \
                             key_ct = excluded.key_ct",
                    rusqlite::params![ns_blind, key_blind, nonce, value_ct, key_nonce, key_ct],
                )
                .map(|_| ())
                .map_err(KVError::from)
            })
            .await
        }
    }

    fn delete(&self, ns: &str, key: &[u8]) -> impl Future<Output = Result<(), KVError>> + Send {
        let res = (|| {
            Self::check_ns(ns)?;
            let ns_bytes = ns.as_bytes().to_vec();
            let ns_blind = self.keys.ns_blind(&ns_bytes).to_vec();
            let key_blind = self.keys.key_blind(&ns_bytes, key).to_vec();
            Ok::<_, KVError>((ns_blind, key_blind))
        })();
        async move {
            let (ns_blind, key_blind) = res?;
            self.blocking(move |conn| {
                conn.execute(
                    "DELETE FROM encrypted_kv WHERE ns_blind = ?1 AND key_blind = ?2",
                    rusqlite::params![ns_blind, key_blind],
                )
                .map(|_| ())
                .map_err(KVError::from)
            })
            .await
        }
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
    ) -> impl Future<Output = Result<Vec<KvPair>, KVError>> + Send {
        // Sealed-row tuple fetched for each namespace member:
        // `(nonce, value_ct, key_nonce, key_ct)`.
        type ScanRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
        let res = (|| {
            Self::check_ns(ns)?;
            let ns_bytes = ns.as_bytes().to_vec();
            let ns_blind = self.keys.ns_blind(&ns_bytes).to_vec();
            let k_value = self.keys.k_value(&ns_bytes)?;
            Ok::<_, KVError>((ns_blind, k_value))
        })();
        let prefix = prefix.to_vec();
        async move {
            let (ns_blind, k_value) = res?;
            // Pull every row in the namespace (exact ns_blind match), then
            // open + filter in this task. O(namespace size).
            let rows: Vec<ScanRow> = self
                .blocking(move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT nonce, value_ct, key_nonce, key_ct FROM encrypted_kv \
                             WHERE ns_blind = ?1",
                    )?;
                    let mapped = stmt.query_map(rusqlite::params![ns_blind], |row| {
                        let nonce: Vec<u8> = row.get("nonce")?;
                        let value_ct: Vec<u8> = row.get("value_ct")?;
                        let key_nonce: Vec<u8> = row.get("key_nonce")?;
                        let key_ct: Vec<u8> = row.get("key_ct")?;
                        Ok((nonce, value_ct, key_nonce, key_ct))
                    })?;
                    let mut out = Vec::new();
                    for r in mapped {
                        out.push(r?);
                    }
                    Ok(out)
                })
                .await?;

            let mut result = Vec::new();
            for (nonce, value_ct, key_nonce, key_ct) in rows {
                let key_nonce_arr = to_nonce(&key_nonce)?;
                let plain_key = ciris_crypto::xchacha::open(&k_value, &key_nonce_arr, &key_ct)
                    .map_err(|e| KVError::AuthFailure(e.to_string()))?;
                if !plain_key.starts_with(&prefix) {
                    continue;
                }
                let nonce_arr = to_nonce(&nonce)?;
                let plain_value = ciris_crypto::xchacha::open(&k_value, &nonce_arr, &value_ct)
                    .map_err(|e| KVError::AuthFailure(e.to_string()))?;
                result.push((plain_key, plain_value));
            }
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct horse battery staple";

    fn store() -> XChaChaKvStore {
        XChaChaKvStore::open_in_memory(PASS).expect("open in-memory store")
    }

    #[tokio::test]
    async fn get_put_delete_roundtrip() {
        let s = store();
        assert_eq!(s.get("ns", b"k").await.unwrap(), None);
        s.put("ns", b"k", b"value-bytes").await.unwrap();
        assert_eq!(
            s.get("ns", b"k").await.unwrap().as_deref(),
            Some(&b"value-bytes"[..])
        );
        s.delete("ns", b"k").await.unwrap();
        assert_eq!(s.get("ns", b"k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn put_overwrites() {
        let s = store();
        s.put("ns", b"k", b"first").await.unwrap();
        s.put("ns", b"k", b"second").await.unwrap();
        assert_eq!(
            s.get("ns", b"k").await.unwrap().as_deref(),
            Some(&b"second"[..])
        );
    }

    #[tokio::test]
    async fn delete_absent_is_ok() {
        let s = store();
        s.delete("ns", b"missing").await.unwrap();
    }

    #[tokio::test]
    async fn exact_byte_roundtrip_including_empty_and_binary() {
        let s = store();
        let val: Vec<u8> = (0u8..=255).collect();
        s.put("ns", b"\x00\x01\x02", &val).await.unwrap();
        assert_eq!(s.get("ns", b"\x00\x01\x02").await.unwrap().unwrap(), val);
        // Empty value is valid (AEAD over empty plaintext = 16-byte tag).
        s.put("ns", b"empty", b"").await.unwrap();
        assert_eq!(s.get("ns", b"empty").await.unwrap().unwrap(), b"");
    }

    #[tokio::test]
    async fn scan_prefix_filtered_plaintext() {
        let s = store();
        s.put("ns", b"user:1", b"alice").await.unwrap();
        s.put("ns", b"user:2", b"bob").await.unwrap();
        s.put("ns", b"group:1", b"x").await.unwrap();
        let mut got = s.scan("ns", b"user:").await.unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                (b"user:1".to_vec(), b"alice".to_vec()),
                (b"user:2".to_vec(), b"bob".to_vec()),
            ]
        );
        // Empty prefix returns every key in the namespace.
        assert_eq!(s.scan("ns", b"").await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn namespace_isolation() {
        let s = store();
        s.put("a", b"k", b"in-a").await.unwrap();
        // Same key in ns "b" is invisible / distinct.
        assert_eq!(s.get("b", b"k").await.unwrap(), None);
        s.put("b", b"k", b"in-b").await.unwrap();
        assert_eq!(
            s.get("a", b"k").await.unwrap().as_deref(),
            Some(&b"in-a"[..])
        );
        assert_eq!(
            s.get("b", b"k").await.unwrap().as_deref(),
            Some(&b"in-b"[..])
        );
        // scan in "a" never sees "b"'s rows.
        let a = s.scan("a", b"").await.unwrap();
        assert_eq!(a, vec![(b"k".to_vec(), b"in-a".to_vec())]);
    }

    #[tokio::test]
    async fn reserved_and_empty_namespace_rejected() {
        let s = store();
        assert!(matches!(
            s.get(VERIFIER_NS, b"x").await,
            Err(KVError::InvalidArgument(_))
        ));
        assert!(matches!(
            s.put("", b"x", b"v").await,
            Err(KVError::InvalidArgument(_))
        ));
    }

    #[test]
    fn wrong_passphrase_refuses_to_open() {
        // Seal with the right passphrase against a temp file, close, then
        // reopen with the wrong one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kv.sqlite");
        {
            let s = XChaChaKvStore::open(&path, PASS).unwrap();
            // (drop closes the connection)
            drop(s);
        }
        match XChaChaKvStore::open(&path, b"WRONG passphrase") {
            Err(KVError::WrongPassphrase) => {}
            Err(other) => panic!("expected WrongPassphrase, got {other:?}"),
            Ok(_) => panic!("expected WrongPassphrase, store opened with wrong passphrase"),
        }
        // The correct passphrase still opens.
        XChaChaKvStore::open(&path, PASS).expect("right passphrase reopens");
    }

    #[tokio::test]
    async fn wrong_passphrase_persisted_data_inaccessible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kv.sqlite");
        {
            let s = XChaChaKvStore::open(&path, PASS).unwrap();
            s.put("ns", b"secret-key", b"secret-value").await.unwrap();
        }
        // Wrong passphrase can't even open.
        assert!(matches!(
            XChaChaKvStore::open(&path, b"nope"),
            Err(KVError::WrongPassphrase)
        ));
        // Right passphrase recovers the value.
        let s = XChaChaKvStore::open(&path, PASS).unwrap();
        assert_eq!(
            s.get("ns", b"secret-key").await.unwrap().as_deref(),
            Some(&b"secret-value"[..])
        );
    }

    // --- COLD-STATE OPACITY (load-bearing — the whole point of part 3) ---

    #[tokio::test]
    async fn cold_state_opacity_no_plaintext_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kv.sqlite");
        let plain_key = b"openmls/group/ABCDEF/secret-tree";
        let plain_value = b"RATCHET-SECRET-MUST-NOT-LEAK-0123456789";
        let plain_ns = "openmls-storage";
        {
            let s = XChaChaKvStore::open(&path, PASS).unwrap();
            s.put(plain_ns, plain_key, plain_value).await.unwrap();
            // flush + close: drop the store so rusqlite finalizes the file.
            drop(s);
        }
        let bytes = std::fs::read(&path).expect("read raw db file");
        assert!(
            !contains(&bytes, plain_value),
            "PLAINTEXT VALUE leaked into the on-disk DB file"
        );
        assert!(
            !contains(&bytes, plain_key),
            "PLAINTEXT KEY leaked into the on-disk DB file"
        );
        assert!(
            !contains(&bytes, plain_ns.as_bytes()),
            "PLAINTEXT NAMESPACE leaked into the on-disk DB file"
        );
        // Sanity: a sealed store with data is non-empty (we actually wrote).
        assert!(
            bytes.len() > 1024,
            "db file unexpectedly tiny: {}",
            bytes.len()
        );
    }

    // --- helpers ---

    /// Naive substring search over the raw file bytes.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
