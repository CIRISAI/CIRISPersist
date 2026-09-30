//! v52.0.0 (CIRISPersist#784) — **a key named without its label.**
//!
//! A `key_id` is `<label>-<fingerprint>` (`ciris_verify_core::fedcode::derive_key_id`):
//! the label is the keystore alias IN CLEARTEXT. A revocation or moderation
//! row that names a `key_id` publishes that label to everyone the row reaches.
//! [`Sha256Ed25519Raw`] names the same key by the SHA-256 of its RAW 32-byte
//! Ed25519 public key — the primitive `derive_key_id` truncates into its
//! suffix — which carries no label and is stable for the life of the key.
//!
//! One preimage, spelled in the type: the RAW bytes. Nothing in this module
//! hashes base64 text; `store::sha256_of_pubkey_base64_text` is the other
//! digest, kept for its one diagnostic caller, and the two never meet.
//!
//! The on-wire and column spelling is 64 lowercase hex, and only that: an
//! exact-match identifier has exactly one spelling.

use sha2::{Digest, Sha256};

/// The SHA-256 of a key's RAW 32-byte Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Ed25519Raw([u8; 32]);

impl Sha256Ed25519Raw {
    /// Digest of the raw public key bytes.
    #[must_use]
    pub fn from_pubkey_bytes(pubkey: &[u8; 32]) -> Self {
        Self(Sha256::digest(pubkey).into())
    }

    /// Decode a base64 Ed25519 public key (as `federation_keys` stores it)
    /// and digest its RAW bytes.
    ///
    /// # Errors
    /// The text is not standard base64, or does not decode to 32 bytes.
    pub fn from_pubkey_base64(pubkey_base64: &str) -> Result<Self, String> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(pubkey_base64.trim())
            .map_err(|e| format!("ed25519 pubkey is not base64: {e}"))?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|v: Vec<u8>| format!("ed25519 pubkey is {} bytes, not 32", v.len()))?;
        Ok(Self::from_pubkey_bytes(&raw))
    }

    /// Parse the wire spelling: exactly 64 LOWERCASE hex digits.
    ///
    /// # Errors
    /// Any other length, an uppercase digit, or a non-hex character.
    pub fn parse(hex_text: &str) -> Result<Self, String> {
        if hex_text.len() != 64
            || !hex_text
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(format!(
                "{hex_text:?} is not a sha256_ed25519_raw digest (64 lowercase hex digits)"
            ));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_text, &mut out).map_err(|e| e.to_string())?;
        Ok(Self(out))
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The wire spelling (64 lowercase hex).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Sha256Ed25519Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The SQL function name the sqlite backend registers on every connection it
/// opens: `ciris_sha256_ed25519_raw(pubkey_ed25519_base64)` → 64 lowercase
/// hex, or NULL when the text does not decode to a 32-byte key. Used in
/// QUERIES only — never in a migration file, which must run on a bare
/// connection.
pub const SQLITE_FN: &str = "ciris_sha256_ed25519_raw";

/// Register [`SQLITE_FN`] on a sqlite connection.
///
/// # Errors
/// sqlite refused the registration.
#[cfg(feature = "sqlite")]
pub fn register_sqlite_fn(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        SQLITE_FN,
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let text: Option<String> = ctx.get(0)?;
            Ok(text.and_then(|t| {
                Sha256Ed25519Raw::from_pubkey_base64(&t)
                    .ok()
                    .map(|d| d.to_hex())
            }))
        },
    )
}

/// The postgres expression for the digest of a base64 pubkey column
/// (`sha256`/`decode`/`encode` are built in and immutable).
#[must_use]
pub fn postgres_sql_expr(pubkey_base64_col: &str) -> String {
    format!("encode(sha256(decode({pubkey_base64_col}, 'base64')), 'hex')")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **I220** — the digest is over the RAW key bytes: its leading bits are
    /// `derive_key_id`'s fingerprint suffix, and it differs from the digest
    /// of the base64 TEXT (the other helper's preimage).
    #[test]
    fn i220_the_digest_is_the_raw_key_primitive_derive_key_id_truncates() {
        use base64::Engine as _;
        let pk = [7u8; 32];
        let d = Sha256Ed25519Raw::from_pubkey_bytes(&pk);
        let b64 = base64::engine::general_purpose::STANDARD.encode(pk);
        assert_eq!(Sha256Ed25519Raw::from_pubkey_base64(&b64).unwrap(), d);
        let key_id = ciris_verify_core::fedcode::derive_key_id("frank-laptop", &pk);
        let suffix = key_id.rsplit('-').next().unwrap().to_ascii_uppercase();
        let b32 = data_encoding_base32(d.as_bytes());
        assert!(
            b32.starts_with(&suffix),
            "derive_key_id suffix {suffix} is a prefix of base32(sha256(raw)) {b32}"
        );
        assert_ne!(
            d.to_hex(),
            crate::store::sha256_of_pubkey_base64_text(&b64),
            "the raw digest is not the digest of the base64 text"
        );
        assert!(!d.to_hex().contains("frank"));
        assert_eq!(Sha256Ed25519Raw::parse(&d.to_hex()).unwrap(), d);
        assert!(Sha256Ed25519Raw::parse(&d.to_hex().to_uppercase()).is_err());
        assert!(Sha256Ed25519Raw::from_pubkey_base64("AAAA").is_err());
    }

    fn data_encoding_base32(bytes: &[u8]) -> String {
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        let (mut buf, mut bits) = (0u32, 0u32);
        for &b in bytes {
            buf = (buf << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((buf >> bits) & 31) as usize] as char);
            }
        }
        out
    }
}
