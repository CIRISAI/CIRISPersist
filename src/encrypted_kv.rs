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

/// v49.0.0 (CIRISPersist#911) — HKDF `context` under which the durable MLS
/// state store's key derives from the content master's root, beside
/// `secrets-store-master-v1` and
/// [`crate::federation::at_rest_cascade::CONTENT_MASTER_CONTEXT`]
/// (`Engine::open_mls_state`). v50.0.0 (#920): the root is whatever the
/// persisted `federation_content_master` row resolves to on this host — the
/// hardware-sealed seed or the software content master. **Stable wire
/// constant** — changing it derives a different key, and every store opened
/// under the old one then refuses with [`KVError::WrongPassphrase`].
pub const MLS_STATE_CONTEXT: &str = "mls-state-at-rest-v1";

/// v50.0.0 (CIRISPersist#920) — which root keys a durable MLS-state store.
/// It is the content master's `key_kind`, measured from the persisted row,
/// never a preference: a software store is a class, not a failure
/// (CC 4.2.2.1), and it is reported by name so a host logs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsStateCustodyKind {
    /// Derived from the hardware-sealed seed (TPM / Keystore / Secure
    /// Enclave) — the row says `key_kind='hardware'`.
    Hardware,
    /// Derived from the persisted software content master — the row says
    /// `key_kind='software'`. Honest about being software
    /// (`BLOB_ENCRYPTION_AT_REST.md` §4.3).
    Software,
}

impl MlsStateCustodyKind {
    /// `"hardware"` | `"software"` — the row's own vocabulary.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MlsStateCustodyKind::Hardware => "hardware",
            MlsStateCustodyKind::Software => "software",
        }
    }
}

/// v50.0.0 (CIRISPersist#920) — the custody a durable MLS-state store was
/// opened under, returned beside the store by `Engine::open_mls_state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsStateCustody {
    /// Hardware or software, from the persisted content-master row.
    pub kind: MlsStateCustodyKind,
    /// Provenance: the root, the HKDF context, and the row's own
    /// descriptor. Carries no key material.
    pub descriptor: String,
}

/// Key id under which the software content master is presented to
/// CIRISVerify's `derive_symmetric_key` (see [`SoftwareRootAsSeed`]).
const SOFTWARE_ROOT_KEY_ID: &str = "federation-content-master-software";

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
    /// v49.0.0 (CIRISPersist#911); narrowed in v50.0.0 (#920) —
    /// **`BLOB_ENCRYPTION_AT_REST.md` §11.7 and nothing else:** the
    /// persisted content-master row says `key_kind='hardware'` and the
    /// hardware-sealed seed it was derived from cannot be reached on this
    /// host (the keyring directory is gone, `CIRIS_DATA_DIR` is unset, the
    /// TPM is absent, or the build lacks `secrets`). The store is not
    /// opened and nothing is written; no seed is minted, because a new seed
    /// would be a different root and the content corpus sealed under the
    /// old one would become unreadable. A host WITHOUT hardware is not this
    /// case: its row says software and the store opens under
    /// [`MlsStateCustodyKind::Software`]. A room id is not a passphrase.
    HardwareCustodyUnavailable(String),
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
            KVError::HardwareCustodyUnavailable(m) => write!(
                f,
                "encrypted-kv: the content master is recorded hardware-rooted but its \
                 hardware-sealed seed is unreachable — not opened, nothing minted \
                 (BLOB_ENCRYPTION_AT_REST.md §11.7): {m}"
            ),
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

    /// v50.0.0 (CIRISPersist#920) — **open the durable MLS-state store at
    /// `path` under the root the persisted content-master row names.** The
    /// public door is `Engine::open_mls_state(path)`, which loads (or, on a
    /// host that has sealed nothing yet, initialises) the
    /// `federation_content_master` row and hands its fields here; this
    /// module takes no backend import.
    ///
    /// **Clean break:** v49's bare `XChaChaKvStore::open_mls_state(path)` is
    /// REMOVED. It asked the hardware seed only, so on every software host
    /// (CI, dev, a server without a TPM) it could only refuse.
    ///
    /// The key is HKDF(root, [`MLS_STATE_CONTEXT`]) through CIRISVerify's
    /// `derive_symmetric_key` in both arms — the same function, salt and
    /// `info`; only the root differs:
    ///
    /// - `key_kind = "hardware"` → the hardware-sealed seed, via
    ///   `hardware(create_seed_if_absent = false)`. The row exists, so a seed
    ///   was sealed when it was written; an absent seed is §11.7's lost
    ///   keyring and is refused ([`KVError::HardwareCustodyUnavailable`]),
    ///   never re-minted — not even on the first open of an empty store,
    ///   since a new seed would also move the content master.
    /// - `key_kind = "software"` → the persisted software content master
    ///   (`master_key_b64`), presented to verify as the seed.
    ///
    /// **The row wins** (§10.2): a store created on a software host keeps
    /// opening as software after a TPM appears.
    ///
    /// **v49 compatibility arm** (review of #920, finding 1). v49's opener
    /// keyed every store from the hardware seed regardless of the row, and
    /// CIRISEdge v32.1.0 shipped on it, so a TPM host with a `software` row
    /// can hold a store keyed HKDF(hardware seed, [`MLS_STATE_CONTEXT`]).
    /// Under a software row, and ONLY when the store is already in use and
    /// its verifier refuses the software-derived key, the opener asks
    /// `hardware(false)` (never mint) and tries the v49 key. On success the
    /// custody is reported as [`MlsStateCustodyKind::Hardware`] — the store
    /// IS hardware-keyed — with a `legacy-v49-hardware-keyed-under-software-row`
    /// descriptor. Nothing is re-keyed. The software key is always tried
    /// first, so this is a fallback, never a preference; if both keys fail
    /// the answer is [`KVError::WrongPassphrase`].
    ///
    /// **Synchronous / blocking** (TPM + filesystem I/O) — call from
    /// `spawn_blocking`.
    pub(crate) fn open_mls_state_from_row(
        path: impl AsRef<Path>,
        key_kind: &str,
        master_key_b64: Option<&str>,
        row_descriptor: &str,
        hardware: impl FnOnce(bool) -> Result<(Zeroizing<Vec<u8>>, String), KVError>,
    ) -> Result<(Self, MlsStateCustody), KVError> {
        let path = path.as_ref();
        let connect = || Connection::open(path).map_err(|e| KVError::Backend(e.to_string()));
        // Every arm resolves its root BEFORE touching the file, so a refusal
        // leaves nothing behind.
        match key_kind {
            "hardware" => {
                let (key, seed_descriptor) = hardware(false)?;
                let store = Self::open_rooted(connect()?, move |_first_open| Ok(key))?;
                Ok((
                    store,
                    MlsStateCustody {
                        kind: MlsStateCustodyKind::Hardware,
                        descriptor: format!(
                            "hardware root ({seed_descriptor}); content master row: {row_descriptor}"
                        ),
                    },
                ))
            }
            "software" => {
                let key = software_mls_state_key(master_key_b64)?;
                match Self::open_rooted(connect()?, move |_first_open| Ok(key)) {
                    Ok(store) => Ok((
                        store,
                        MlsStateCustody {
                            kind: MlsStateCustodyKind::Software,
                            descriptor: format!(
                                "software root: the persisted software content master, \
                                 HKDF context={MLS_STATE_CONTEXT}; content master row: \
                                 {row_descriptor}"
                            ),
                        },
                    )),
                    // The verifier refused: a store in use under another key.
                    // The one other key it may legitimately hold is v49's.
                    Err(KVError::WrongPassphrase) => {
                        let Ok((legacy, seed_descriptor)) = hardware(false) else {
                            return Err(KVError::WrongPassphrase);
                        };
                        let store = Self::open_rooted(connect()?, move |_first_open| Ok(legacy))?;
                        Ok((
                            store,
                            MlsStateCustody {
                                kind: MlsStateCustodyKind::Hardware,
                                descriptor: format!(
                                    "legacy-v49-hardware-keyed-under-software-row: hardware root \
                                     ({seed_descriptor}), not re-keyed; content master row: \
                                     {row_descriptor}"
                                ),
                            },
                        ))
                    }
                    Err(other) => Err(other),
                }
            }
            other => Err(KVError::InvalidArgument(format!(
                "content master row has unknown key_kind {other:?}"
            ))),
        }
    }

    /// The store half of the MLS-state opener over a supplied derivation,
    /// so it is testable without a TPM (every CI runner):
    /// `derive(first_open)` is told whether the store holds no verifier row
    /// yet. (v49 let the first open seal a seed; since v50 the seed belongs
    /// to the content master's row, and
    /// [`open_mls_state_from_row`](Self::open_mls_state_from_row) never
    /// grants that.)
    fn open_rooted(
        conn: Connection,
        derive: impl FnOnce(bool) -> Result<Zeroizing<Vec<u8>>, KVError>,
    ) -> Result<Self, KVError> {
        let in_use = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'encrypted_kv'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
            && conn
                .query_row(
                    "SELECT 1 FROM encrypted_kv WHERE ns_blind = ?1 AND key_blind = ?2",
                    rusqlite::params![VERIFIER_NS_BLIND.to_vec(), VERIFIER_KEY_BLIND.to_vec()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
        let key = derive(!in_use)?;
        Self::from_connection(conn, &key)
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

/// The production hardware derivation behind `Engine::open_mls_state`: the
/// hardware-sealed seed under [`MLS_STATE_CONTEXT`], with its descriptor.
pub(crate) fn hardware_mls_state_key(
    create_seed_if_absent: bool,
) -> Result<(Zeroizing<Vec<u8>>, String), KVError> {
    #[cfg(feature = "secrets")]
    {
        // The §11.7 meaning, stated here: the SecretsError text is written
        // for the secrets store's caller, which stays on its software master.
        crate::secrets::hardware::derive_hardware_mls_state_key(create_seed_if_absent)
            .map(|(key, descriptor)| (Zeroizing::new(key), descriptor))
            .map_err(|e| {
                KVError::HardwareCustodyUnavailable(format!(
                    "the hardware-sealed seed (context={MLS_STATE_CONTEXT}) cannot be reached on \
                     this host, and none is minted in its place: {e}"
                ))
            })
    }
    #[cfg(not(feature = "secrets"))]
    {
        let _ = create_seed_if_absent;
        Err(KVError::HardwareCustodyUnavailable(
            "built without the `secrets` feature — no hardware-sealed seed is reachable".into(),
        ))
    }
}

/// v50.0.0 (#920) — the software arm: HKDF(software content master,
/// [`MLS_STATE_CONTEXT`]), through the SAME CIRISVerify
/// `derive_symmetric_key` the hardware arm uses (HKDF-SHA-256, verify's
/// fixed salt, `info` = the context). Verify's KDF reads its input keying
/// material from a `SecureBlobStorage`, so the persisted master is presented
/// to it through [`SoftwareRootAsSeed`], an in-process, read-only, one-entry
/// storage that says it is NOT hardware-backed. Persist implements no KDF of
/// its own (MISSION §1.4), and the two arms differ in the root alone.
fn software_mls_state_key(master_key_b64: Option<&str>) -> Result<Zeroizing<Vec<u8>>, KVError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let b64 = master_key_b64.ok_or_else(|| {
        KVError::InvalidArgument("content master row says software but carries no key bytes".into())
    })?;
    let raw = Zeroizing::new(
        B64.decode(b64)
            .map_err(|e| KVError::InvalidArgument(format!("content-master b64: {e}")))?,
    );
    if raw.len() != KEY_LEN {
        return Err(KVError::InvalidArgument(format!(
            "content master is {} bytes, expected {KEY_LEN}",
            raw.len()
        )));
    }
    let key = Zeroizing::new(
        ciris_verify_core::derive_symmetric_key(
            &SoftwareRootAsSeed(raw),
            SOFTWARE_ROOT_KEY_ID,
            MLS_STATE_CONTEXT,
        )
        .map_err(|e| KVError::Crypto(format!("verify derive_symmetric_key failed: {e}")))?,
    );
    if key.len() != KEY_LEN {
        return Err(KVError::Crypto(format!(
            "verify derived a {}-byte key; expected {KEY_LEN}",
            key.len()
        )));
    }
    Ok(key)
}

/// The persisted software content master, presented to CIRISVerify's
/// `derive_symmetric_key` as the seed under [`SOFTWARE_ROOT_KEY_ID`].
/// Read-only and in-process; reports `is_hardware_backed() == false`,
/// because it is not.
struct SoftwareRootAsSeed(Zeroizing<Vec<u8>>);

impl ciris_keyring::SecureBlobStorage for SoftwareRootAsSeed {
    fn store(&self, key_id: &str, _data: &[u8]) -> Result<(), ciris_keyring::KeyringError> {
        Err(ciris_keyring::KeyringError::StorageFailed {
            reason: format!("read-only software root: refusing to store {key_id:?}"),
        })
    }
    fn load(&self, key_id: &str) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
        if key_id == SOFTWARE_ROOT_KEY_ID {
            Ok(self.0.to_vec())
        } else {
            Err(ciris_keyring::KeyringError::KeyNotFound {
                alias: key_id.to_owned(),
            })
        }
    }
    fn exists(&self, key_id: &str) -> bool {
        key_id == SOFTWARE_ROOT_KEY_ID
    }
    fn delete(&self, key_id: &str) -> Result<(), ciris_keyring::KeyringError> {
        Err(ciris_keyring::KeyringError::StorageFailed {
            reason: format!("read-only software root: refusing to delete {key_id:?}"),
        })
    }
    fn list_keys(&self) -> Result<Vec<String>, ciris_keyring::KeyringError> {
        Ok(vec![SOFTWARE_ROOT_KEY_ID.to_owned()])
    }
    fn is_hardware_backed(&self) -> bool {
        false
    }
    fn diagnostics(&self) -> String {
        "persisted software content master (in-process, read-only)".into()
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

    // ── v49.0.0 (CIRISPersist#911) — the hardware-rooted MLS-state opener.
    // The TPM branch is unreachable on CI, so the seed policy is driven
    // through `open_rooted` with a stand-in derivation; the derivation
    // itself is witnessed in `secrets::hardware`'s seed-policy tests.

    fn derive_recording(
        key: [u8; 32],
        asked: &std::cell::Cell<Option<bool>>,
    ) -> impl FnOnce(bool) -> Result<Zeroizing<Vec<u8>>, KVError> + '_ {
        move |create| {
            asked.set(Some(create));
            Ok(Zeroizing::new(key.to_vec()))
        }
    }

    /// I184 — only the FIRST open of an empty store may seal a seed; a
    /// store in use re-derives (never mints), and its state survives the
    /// reopen, which is the restart CIRISServer#630 needs.
    #[tokio::test]
    async fn i184_the_first_open_may_seal_a_reopen_never_mints() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let asked = std::cell::Cell::new(None);
        let s = XChaChaKvStore::open_rooted(
            Connection::open(&path).unwrap(),
            derive_recording([7; 32], &asked),
        )
        .unwrap();
        assert_eq!(asked.get(), Some(true), "an empty store may seal the seed");
        s.put("mls", b"group", b"epoch-state").await.unwrap();
        drop(s);

        let asked = std::cell::Cell::new(None);
        let s = XChaChaKvStore::open_rooted(
            Connection::open(&path).unwrap(),
            derive_recording([7; 32], &asked),
        )
        .unwrap();
        assert_eq!(
            asked.get(),
            Some(false),
            "a store in use must never mint a seed"
        );
        assert_eq!(
            s.get("mls", b"group").await.unwrap().as_deref(),
            Some(&b"epoch-state"[..]),
            "the state survives the restart"
        );
    }

    /// I184 — a different key (another context, or a re-minted seed) is
    /// refused by the verifier: the store never opens over state it cannot
    /// read.
    #[test]
    fn i184_a_different_key_is_refused_not_reinitialised() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let asked = std::cell::Cell::new(None);
        drop(
            XChaChaKvStore::open_rooted(
                Connection::open(&path).unwrap(),
                derive_recording([7; 32], &asked),
            )
            .unwrap(),
        );
        let err = XChaChaKvStore::open_rooted(
            Connection::open(&path).unwrap(),
            derive_recording([8; 32], &asked),
        )
        .err()
        .expect("a different key must not open the store");
        assert!(matches!(err, KVError::WrongPassphrase), "got {err}");
    }

    /// I184 — a derivation that refuses (since v50: the §11.7 case, a
    /// hardware row whose seed is unreachable) opens nothing and writes
    /// nothing. The public-id passphrase every host used
    /// (`open_in_memory(room_id)`) is not a fallback.
    #[test]
    fn i184_no_hardware_seed_is_named_and_opens_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let err = XChaChaKvStore::open_rooted(Connection::open(&path).unwrap(), |_| {
            Err(KVError::HardwareCustodyUnavailable("no TPM".into()))
        })
        .err()
        .expect("no seed must not open");
        assert!(
            matches!(err, KVError::HardwareCustodyUnavailable(_)),
            "got {err}"
        );
        assert!(err.to_string().contains("§11.7"));
        let conn = Connection::open(&path).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'encrypted_kv'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "a refused open must leave nothing behind");
    }

    // ── v50.0.0 (CIRISPersist#920) — I187: the MLS-state root follows the
    // content master's persisted row. The hardware arm is driven over
    // `secrets::hardware`'s storage double through `derive_with_storage`, as
    // v49's seed-policy tests are; the Engine door is witnessed in
    // `federation::mls_state_root_invariants`.

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    const SOFTWARE_MASTER: [u8; 32] = [0x5a; 32];
    const SOFTWARE_ROW: &str = "software content-at-rest master (no TPM)";
    const HARDWARE_ROW: &str = "hardware-blob-storage seed=… context=content-at-rest-master-v1";

    /// HKDF(`root`, `context`) through CIRISVerify's `derive_symmetric_key`,
    /// over a one-seed storage of the test's own (independent of the
    /// opener's adapter).
    fn verify_hkdf(root: &[u8; 32], context: &str) -> Vec<u8> {
        struct OneSeed(Vec<u8>);
        impl ciris_keyring::SecureBlobStorage for OneSeed {
            fn store(&self, _: &str, _: &[u8]) -> Result<(), ciris_keyring::KeyringError> {
                unreachable!()
            }
            fn load(&self, _: &str) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
                Ok(self.0.clone())
            }
            fn exists(&self, _: &str) -> bool {
                true
            }
            fn delete(&self, _: &str) -> Result<(), ciris_keyring::KeyringError> {
                unreachable!()
            }
            fn list_keys(&self) -> Result<Vec<String>, ciris_keyring::KeyringError> {
                Ok(vec!["seed".into()])
            }
            fn is_hardware_backed(&self) -> bool {
                false
            }
            fn diagnostics(&self) -> String {
                "test one-seed".into()
            }
        }
        ciris_verify_core::derive_symmetric_key(&OneSeed(root.to_vec()), "seed", context).unwrap()
    }

    fn no_hardware_consulted(_: bool) -> Result<(Zeroizing<Vec<u8>>, String), KVError> {
        panic!("the hardware root must not be consulted under a software row (the row wins)")
    }

    fn open_software(path: &Path) -> Result<(XChaChaKvStore, MlsStateCustody), KVError> {
        XChaChaKvStore::open_mls_state_from_row(
            path,
            "software",
            Some(&B64.encode(SOFTWARE_MASTER)),
            SOFTWARE_ROW,
            no_hardware_consulted,
        )
    }

    fn has_kv_table(path: &Path) -> bool {
        let conn = Connection::open(path).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'encrypted_kv'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    /// I187(a) — a software row opens the store, reports `Software` by
    /// name, and the state survives a reopen.
    #[tokio::test]
    async fn i187_a_software_row_opens_reports_software_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let (s, custody) = open_software(&path).expect("a software host opens its store");
        assert_eq!(custody.kind, MlsStateCustodyKind::Software);
        assert_eq!(custody.kind.as_str(), "software");
        assert!(
            custody.descriptor.contains("software")
                && custody.descriptor.contains(MLS_STATE_CONTEXT),
            "the descriptor must name the class and the context, got: {}",
            custody.descriptor
        );
        assert!(
            !custody.descriptor.contains(&B64.encode(SOFTWARE_MASTER)),
            "the descriptor must carry no key material"
        );
        s.put("mls", b"group", b"epoch-state").await.unwrap();
        drop(s);
        let (s, custody) = open_software(&path).expect("reopen");
        assert_eq!(custody.kind, MlsStateCustodyKind::Software);
        assert_eq!(
            s.get("mls", b"group").await.unwrap().as_deref(),
            Some(&b"epoch-state"[..]),
            "the state survives the restart"
        );
    }

    /// I187(b) — domain separation by context: the store's key is
    /// HKDF(master, MLS_STATE_CONTEXT), which is neither the content master
    /// itself nor HKDF(master, CONTENT_MASTER_CONTEXT). Measured through the
    /// store's own verifier: only the MLS-context key opens it.
    #[test]
    fn i187_b_the_mls_key_is_domain_separated_from_the_content_master() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        drop(open_software(&path).unwrap());
        let content = verify_hkdf(
            &SOFTWARE_MASTER,
            crate::federation::at_rest_cascade::CONTENT_MASTER_CONTEXT,
        );
        for (what, key) in [
            ("the content master itself", SOFTWARE_MASTER.to_vec()),
            ("HKDF(master, CONTENT_MASTER_CONTEXT)", content),
        ] {
            let err = XChaChaKvStore::open(&path, &key)
                .err()
                .unwrap_or_else(|| panic!("the store opened under {what}: no domain separation"));
            assert!(matches!(err, KVError::WrongPassphrase), "{what}: got {err}");
        }
        XChaChaKvStore::open(&path, &verify_hkdf(&SOFTWARE_MASTER, MLS_STATE_CONTEXT))
            .expect("the key is HKDF(master, MLS_STATE_CONTEXT) through verify's KDF");
    }

    /// I187(c) — a hardware row whose seed is unreachable refuses
    /// `HardwareCustodyUnavailable`, writes nothing, and never asks to mint.
    #[test]
    fn i187_c_a_hardware_row_with_no_reachable_seed_refuses_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let asked = std::cell::Cell::new(None);
        let err =
            XChaChaKvStore::open_mls_state_from_row(&path, "hardware", None, HARDWARE_ROW, |c| {
                asked.set(Some(c));
                Err(KVError::HardwareCustodyUnavailable(
                    "no TPM on this host".into(),
                ))
            })
            .err()
            .expect("a hardware row with no seed must not open");
        assert!(
            matches!(err, KVError::HardwareCustodyUnavailable(_)),
            "got {err}"
        );
        assert_eq!(
            asked.get(),
            Some(false),
            "under a hardware row the opener never asks to mint"
        );
        assert!(
            !has_kv_table(&path),
            "a refused open must leave nothing behind"
        );
    }

    /// I187(c) over the storage double — the TPM is present but the seed is
    /// gone (a lost keyring, §11.7). Even on the FIRST open of an empty
    /// store nothing is minted: a new seed would move the content master too.
    #[cfg(feature = "secrets")]
    #[test]
    fn i187_c_a_present_tpm_with_an_absent_seed_never_mints() {
        use crate::secrets::hardware::{derive_with_storage, test_doubles::FakeHardwareStorage};
        use ciris_keyring::SecureBlobStorage as _;
        let storage = FakeHardwareStorage::empty();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let err =
            XChaChaKvStore::open_mls_state_from_row(&path, "hardware", None, HARDWARE_ROW, |c| {
                derive_with_storage(&storage, MLS_STATE_CONTEXT, c)
                    .map(|(k, d)| (Zeroizing::new(k), d))
                    .map_err(|e| KVError::HardwareCustodyUnavailable(e.to_string()))
            })
            .err()
            .expect("an absent seed under a hardware row must refuse");
        assert!(
            matches!(err, KVError::HardwareCustodyUnavailable(_)),
            "got {err}"
        );
        assert!(
            storage.list_keys().unwrap().is_empty(),
            "refusing must not have minted a seed"
        );
        assert!(
            !has_kv_table(&path),
            "a refused open must leave nothing behind"
        );
    }

    /// I187(d) — the hardware branch over the storage double: the row says
    /// hardware, the seed was sealed when the row was written, the store
    /// opens as `Hardware`, and neither the open nor the reopen mints.
    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn i187_d_the_hardware_branch_reports_hardware_and_reopen_never_mints() {
        use crate::secrets::hardware::{derive_with_storage, test_doubles::FakeHardwareStorage};
        use ciris_keyring::SecureBlobStorage as _;
        let storage = FakeHardwareStorage::empty();
        // The content master's row init sealed the seed (create=true).
        derive_with_storage(
            &storage,
            crate::federation::at_rest_cascade::CONTENT_MASTER_CONTEXT,
            true,
        )
        .unwrap();
        let sealed = storage.list_keys().unwrap();
        let seed = storage.load(&sealed[0]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let open = || {
            let asked = std::cell::Cell::new(None);
            let r = XChaChaKvStore::open_mls_state_from_row(
                &path,
                "hardware",
                None,
                HARDWARE_ROW,
                |c| {
                    asked.set(Some(c));
                    derive_with_storage(&storage, MLS_STATE_CONTEXT, c)
                        .map(|(k, d)| (Zeroizing::new(k), d))
                        .map_err(|e| KVError::HardwareCustodyUnavailable(e.to_string()))
                },
            );
            assert_eq!(
                asked.get(),
                Some(false),
                "a hardware row never asks to mint"
            );
            r
        };
        let (s, custody) = open().expect("hardware row + present seed opens");
        assert_eq!(custody.kind, MlsStateCustodyKind::Hardware);
        assert_eq!(custody.kind.as_str(), "hardware");
        assert!(
            custody.descriptor.contains("hardware")
                && custody.descriptor.contains(MLS_STATE_CONTEXT),
            "got: {}",
            custody.descriptor
        );
        s.put("mls", b"group", b"epoch-state").await.unwrap();
        drop(s);
        let (s, custody) = open().expect("reopen");
        assert_eq!(custody.kind, MlsStateCustodyKind::Hardware);
        assert_eq!(
            s.get("mls", b"group").await.unwrap().as_deref(),
            Some(&b"epoch-state"[..])
        );
        assert_eq!(storage.list_keys().unwrap(), sealed, "no second seed");
        assert_eq!(
            storage.load(&sealed[0]).unwrap(),
            seed,
            "the seed never re-minted"
        );
    }

    /// I187(e) — the row wins (§10.2): a store created under a software row
    /// still opens as `Software` once a hardware seed is available, because
    /// the row still says software. The hardware root is never consulted.
    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn i187_e_the_row_wins_a_software_store_ignores_new_hardware() {
        use crate::secrets::hardware::{derive_with_storage, test_doubles::FakeHardwareStorage};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let (s, _) = open_software(&path).unwrap();
        s.put("mls", b"group", b"epoch-state").await.unwrap();
        drop(s);

        // A TPM appears, with a sealed seed.
        let storage = FakeHardwareStorage::empty();
        derive_with_storage(&storage, MLS_STATE_CONTEXT, true).unwrap();
        let consulted = std::cell::Cell::new(false);
        let (s, custody) = XChaChaKvStore::open_mls_state_from_row(
            &path,
            "software",
            Some(&B64.encode(SOFTWARE_MASTER)),
            SOFTWARE_ROW,
            |c| {
                consulted.set(true);
                derive_with_storage(&storage, MLS_STATE_CONTEXT, c)
                    .map(|(k, d)| (Zeroizing::new(k), d))
                    .map_err(|e| KVError::HardwareCustodyUnavailable(e.to_string()))
            },
        )
        .expect("the software-created store keeps opening");
        assert!(
            !consulted.get(),
            "the hardware root was consulted under a software row"
        );
        assert_eq!(custody.kind, MlsStateCustodyKind::Software);
        assert_eq!(
            s.get("mls", b"group").await.unwrap().as_deref(),
            Some(&b"epoch-state"[..])
        );
    }

    /// I187 — a malformed row is a refusal, never a fallback.
    #[test]
    fn i187_a_malformed_row_refuses() {
        let dir = tempfile::tempdir().unwrap();
        for (i, (kind, b64)) in [
            ("software", None),
            ("software", Some("!!!not b64!!!".to_owned())),
            ("software", Some(B64.encode([1u8; 16]))),
            ("nonsense", None),
        ]
        .into_iter()
        .enumerate()
        {
            let path = dir.path().join(format!("{i}.db"));
            let r = XChaChaKvStore::open_mls_state_from_row(
                &path,
                kind,
                b64.as_deref(),
                SOFTWARE_ROW,
                no_hardware_consulted,
            );
            assert!(r.is_err(), "{kind}/{b64:?} opened");
            assert!(!has_kv_table(&path), "{kind}/{b64:?} left a table behind");
        }
    }

    /// The hardware derivation over the storage double, as production wires
    /// `derive_hardware_mls_state_key`, recording the create flag it was asked.
    #[cfg(feature = "secrets")]
    fn over_double<'a>(
        storage: &'a crate::secrets::hardware::test_doubles::FakeHardwareStorage,
        asked: &'a std::cell::Cell<Option<bool>>,
    ) -> impl FnOnce(bool) -> Result<(Zeroizing<Vec<u8>>, String), KVError> + 'a {
        move |c| {
            asked.set(Some(c));
            crate::secrets::hardware::derive_with_storage(storage, MLS_STATE_CONTEXT, c)
                .map(|(k, d)| (Zeroizing::new(k), d))
                .map_err(|e| KVError::HardwareCustodyUnavailable(e.to_string()))
        }
    }

    /// I187(f) — the v49 compatibility arm (#920 review, finding 1): a store
    /// v49 keyed from the hardware seed on a host whose row says SOFTWARE
    /// (CIRISEdge v32.1.0 on a TPM host) still opens. It reports `Hardware`
    /// — the store IS hardware-keyed — with the legacy descriptor, is not
    /// re-keyed, and nothing is minted.
    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn i187_f_a_v49_store_under_a_software_row_opens_as_legacy_hardware() {
        use crate::secrets::hardware::{derive_with_storage, test_doubles::FakeHardwareStorage};
        use std::sync::atomic::Ordering;
        let storage = FakeHardwareStorage::empty();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        // The v49 way: `open_rooted` over the hardware seed, first open seals.
        let s = XChaChaKvStore::open_rooted(Connection::open(&path).unwrap(), |c| {
            derive_with_storage(&storage, MLS_STATE_CONTEXT, c)
                .map(|(k, _)| Zeroizing::new(k))
                .map_err(|e| KVError::HardwareCustodyUnavailable(e.to_string()))
        })
        .unwrap();
        s.put("mls", b"group", b"v49-state").await.unwrap();
        drop(s);
        let seals = storage.stores.load(Ordering::SeqCst);

        let asked = std::cell::Cell::new(None);
        let (s, custody) = XChaChaKvStore::open_mls_state_from_row(
            &path,
            "software",
            Some(&B64.encode(SOFTWARE_MASTER)),
            SOFTWARE_ROW,
            over_double(&storage, &asked),
        )
        .expect("a v49 hardware-keyed store under a software row must still open");
        assert_eq!(custody.kind, MlsStateCustodyKind::Hardware);
        assert!(
            custody
                .descriptor
                .contains("legacy-v49-hardware-keyed-under-software-row"),
            "got: {}",
            custody.descriptor
        );
        assert_eq!(
            asked.get(),
            Some(false),
            "the compat arm never asks to mint"
        );
        assert_eq!(
            s.get("mls", b"group").await.unwrap().as_deref(),
            Some(&b"v49-state"[..])
        );
        assert_eq!(
            storage.stores.load(Ordering::SeqCst),
            seals,
            "nothing minted"
        );
        drop(s);
        // Not re-keyed: the v49 key still opens it.
        let (legacy, _) = derive_with_storage(&storage, MLS_STATE_CONTEXT, false).unwrap();
        XChaChaKvStore::open(&path, &legacy).expect("the store was not re-keyed");
    }

    /// I187(f) — the compat arm is a fallback, not a preference: a FRESH
    /// store under a software row with hardware available is `Software`,
    /// and the hardware root is not consulted.
    #[cfg(feature = "secrets")]
    #[test]
    fn i187_f_a_fresh_store_under_a_software_row_stays_software() {
        use crate::secrets::hardware::{derive_with_storage, test_doubles::FakeHardwareStorage};
        let storage = FakeHardwareStorage::empty();
        derive_with_storage(&storage, MLS_STATE_CONTEXT, true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let asked = std::cell::Cell::new(None);
        let (_s, custody) = XChaChaKvStore::open_mls_state_from_row(
            dir.path().join("mls.db"),
            "software",
            Some(&B64.encode(SOFTWARE_MASTER)),
            SOFTWARE_ROW,
            over_double(&storage, &asked),
        )
        .unwrap();
        assert_eq!(custody.kind, MlsStateCustodyKind::Software);
        assert_eq!(
            asked.get(),
            None,
            "the hardware root was consulted for a fresh store"
        );
    }

    /// I187(f) — the compat arm never mints: a v49 store whose seed is gone
    /// (TPM present, keyring lost) under a software row is `WrongPassphrase`,
    /// and no seed is sealed in the attempt.
    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn i187_f_the_compat_arm_never_mints() {
        use crate::secrets::hardware::{derive_with_storage, test_doubles::FakeHardwareStorage};
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db");
        let lost = FakeHardwareStorage::empty();
        let (k, _) = derive_with_storage(&lost, MLS_STATE_CONTEXT, true).unwrap();
        drop(XChaChaKvStore::open(&path, &k).unwrap());

        let present_tpm_no_seed = FakeHardwareStorage::empty();
        let asked = std::cell::Cell::new(None);
        let err = XChaChaKvStore::open_mls_state_from_row(
            &path,
            "software",
            Some(&B64.encode(SOFTWARE_MASTER)),
            SOFTWARE_ROW,
            over_double(&present_tpm_no_seed, &asked),
        )
        .err()
        .expect("neither key opens this store");
        assert!(matches!(err, KVError::WrongPassphrase), "got {err}");
        assert_eq!(asked.get(), Some(false));
        assert_eq!(
            present_tpm_no_seed.stores.load(Ordering::SeqCst),
            0,
            "the compat arm minted a seed"
        );
    }
}
