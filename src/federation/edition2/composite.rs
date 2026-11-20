//! v62.0.0 (C5-fix3) — **the ONE place persist splits a composite
//! ML-DSA-65 + Ed25519 key or signature into its halves.**
//!
//! ciris-crypto v23.3.1 (`b0933ba`) gives `CompositePublicKey` no half
//! accessor (only `from_bytes`, `from_halves`, `as_bytes` and `verify`; its
//! `mldsa` / `ed25519` fields are private), and a composite signature is a bare
//! byte string. So the halves are read here by Verify's NAMED layout constants
//! (`ciris_crypto::composite`), never a literal offset:
//!
//! - **key**: `mldsaPK || ed25519PK` — the struct's doc,
//!   `PUBLIC_KEY_LEN = MLDSA65_PK_LEN + 32`, and `CompositePublicKey::from_bytes`,
//!   which splits at `MLDSA65_PK_LEN` and decodes the tail as the Ed25519
//!   point (the same split Verify's genesis custody gate reads,
//!   `edition2::genesis::custody_gate`);
//! - **signature**: `mldsaSig || ed25519Sig` — `SIGNATURE_LEN = MLDSA65_SIG_LEN + 64`
//!   and `CompositePublicKey::verify`, which splits at `MLDSA65_SIG_LEN`.
//!
//! A byte string of any other length yields `None`, never a guessed slice. When
//! Verify ships named half accessors (asked for 23.3.2), the key helpers
//! become one-line delegates and nothing else in persist changes.

use ciris_crypto::composite::{
    CompositePublicKey, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

/// The Ed25519 half of a composite public key (32 bytes).
#[must_use]
pub fn ed25519_public(key: &CompositePublicKey) -> Option<[u8; 32]> {
    let (_mldsa, ed25519) = key_halves(key)?;
    <[u8; 32]>::try_from(ed25519).ok()
}

/// The ML-DSA-65 half of a composite public key (`MLDSA65_PK_LEN` bytes).
#[must_use]
pub fn mldsa65_public(key: &CompositePublicKey) -> Option<&[u8]> {
    key_halves(key).map(|(mldsa, _)| mldsa)
}

/// A composite public key's two halves, `(ML-DSA-65, Ed25519)`, in the
/// composite's order.
#[must_use]
pub fn key_halves(key: &CompositePublicKey) -> Option<(&[u8], &[u8])> {
    let bytes: &[u8] = key.as_bytes();
    if bytes.len() != PUBLIC_KEY_LEN {
        return None;
    }
    Some(bytes.split_at(MLDSA65_PK_LEN))
}

/// A composite signature's two halves, `(ML-DSA-65, Ed25519)`, in the
/// composite's order; `None` unless `sig` is exactly `SIGNATURE_LEN` bytes.
#[must_use]
pub fn signature_halves(sig: &[u8]) -> Option<(&[u8], &[u8])> {
    if sig.len() != SIGNATURE_LEN {
        return None;
    }
    Some(sig.split_at(MLDSA65_SIG_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::composite::CompositeSigningKey;

    /// I2423 (v62.0.0, C5-fix3) — **the shared split reads Verify's layout**,
    /// checked against independent derivations, never against itself:
    /// - the key's Ed25519 half equals the Ed25519 key its seed derives
    ///   (ed25519-dalek), and `CompositePublicKey::from_halves` (Verify's
    ///   constructor) rebuilds the encoding from the two halves;
    /// - a composite signature's halves are `MLDSA65_SIG_LEN` and 64 bytes,
    ///   and the Ed25519 half verifies under the seed's Ed25519 key over the
    ///   message representative Verify signs (ed25519-dalek, strict);
    /// - a wrong length is `None`.
    #[test]
    fn i2423_the_one_split_reads_verifys_layout() {
        use ed25519_dalek::Verifier as _;
        let signer = CompositeSigningKey::from_seeds(&[0x51; 32], &[0x52; 32]);
        let key = signer.public_key();
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]).verifying_key();
        assert_eq!(
            ed25519_public(key),
            Some(ed.to_bytes()),
            "I2423: Ed25519 half"
        );
        let (mldsa, ed_half) = key_halves(key).expect("I2423: a composite key splits");
        assert_eq!(mldsa.len(), MLDSA65_PK_LEN, "I2423: ML-DSA-65 half length");
        assert_eq!(mldsa65_public(key), Some(mldsa));
        let rebuilt = CompositePublicKey::from_halves(mldsa, ed_half).expect("I2423: rebuild");
        assert_eq!(
            rebuilt.as_bytes(),
            key.as_bytes(),
            "I2423: Verify's layout round-trips"
        );

        let msg = b"i2423";
        let sig = signer.sign(msg).expect("I2423: sign");
        let (ml_sig, ed_sig) = signature_halves(&sig).expect("I2423: a composite signature splits");
        assert_eq!(ml_sig.len(), MLDSA65_SIG_LEN);
        let ed_sig =
            ed25519_dalek::Signature::from_slice(ed_sig).expect("I2423: 64-byte Ed25519 half");
        let mp = ciris_crypto::composite::message_representative(msg);
        assert!(
            ed.verify(&mp, &ed_sig).is_ok(),
            "I2423: the signature's Ed25519 half is the Ed25519 signature"
        );

        assert!(signature_halves(&sig[1..]).is_none(), "I2423: wrong length");
    }
}
