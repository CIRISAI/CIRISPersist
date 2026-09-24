//! v47.4.0 (CIRISPersist#805, `FSD/TEST_ANCHOR_BLOCK_MINTER.md`) — the
//! minter of the `CIRIS_TEST_TRUST_ROOT*` block lives HERE, next to the
//! envelope it signs and the seeder that consumes it.
//!
//! Three consumers each rolled a minter; one signed a two-key literal that
//! had never rooted, and nothing at boot could tell. There is exactly one
//! correct block per persist+verify pair — the envelope shape and the
//! canonicalization are persist's, the primitives are the pinned verify's —
//! and persist is the only party that knows it.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};

use crate::federation::Error;

/// The domain string both consumers already derive the ML-DSA-65 seed
/// with: `SHA-256(domain ‖ ed_seed)`. Persist owns it now, so the PQC half
/// of a re-mint cannot drift from the blocks the harnesses carry.
pub const TEST_ANCHOR_MLDSA_SEED_DOMAIN: &[u8] = b"ciris-test-trust-root/mldsa/v1";

/// The seed every harness shares (bytes `01..=20`), so a re-mint with no
/// argument prints the block they already carry — with the scrubs for the
/// pair that compiled the minter.
pub const TEST_ANCHOR_SHARED_SEED_B64: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

/// The tracing target the seeder reports on (a witness captures by it).
pub const TEST_ANCHOR_LOG_TARGET: &str = "ciris_persist::test_anchor";

/// The seven variables of the block, in the order the compose lines print.
pub const TEST_ANCHOR_ENV_VARS: [&str; 7] = [
    "CIRIS_TESTING_MODE",
    "CIRIS_TEST_TRUST_ROOT",
    "CIRIS_TEST_TRUST_ROOT_PQC",
    "CIRIS_TEST_TRUST_ROOT_SCRUB",
    "CIRIS_TEST_TRUST_ROOT_SCRUB_PQC",
    "CIRIS_TEST_TRUST_ROOT_SEED",
    "CIRIS_TEST_TRUST_ROOT_MINTED_BY",
];

/// The ML-DSA-65 seed for a test-anchor holder, derived from its Ed25519
/// seed the way every existing block was.
#[must_use]
pub fn test_anchor_mldsa_seed(ed_seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(TEST_ANCHOR_MLDSA_SEED_DOMAIN);
    h.update(ed_seed);
    h.finalize().into()
}

/// One holder of a minted block — every value base64, exactly as the env
/// carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestAnchorHolder {
    /// `test-accord-holder-{i}` — the seeder's naming.
    pub key_id: String,
    /// `CIRIS_TEST_TRUST_ROOT` slot: the Ed25519 pubkey.
    pub root: String,
    /// `CIRIS_TEST_TRUST_ROOT_PQC` slot: the ML-DSA-65 pubkey.
    pub pqc: String,
    /// `CIRIS_TEST_TRUST_ROOT_SCRUB` slot: Ed25519 over the canonical envelope.
    pub scrub: String,
    /// `CIRIS_TEST_TRUST_ROOT_SCRUB_PQC` slot: ML-DSA-65 over canonical ‖ ed_sig.
    pub scrub_pqc: String,
    /// `CIRIS_TEST_TRUST_ROOT_SEED` slot: the Ed25519 seed the holder was
    /// derived from.
    pub seed: String,
}

/// A minted block: the holders (slot `i` is `test-accord-holder-{i}`) and the
/// pair that minted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestAnchorBlock {
    /// One per seed, in seed order.
    pub holders: Vec<TestAnchorHolder>,
    /// `persist vX.Y.Z / verify vA.B.C` — [`test_anchor_minted_by`] at
    /// mint time.
    pub minted_by: String,
}

impl TestAnchorBlock {
    /// The seven `(VAR, value)` pairs; multi-holder slots comma-joined, the
    /// grammar `test_anchor_genesis_records` splits.
    #[must_use]
    pub fn env_pairs(&self) -> Vec<(&'static str, String)> {
        let join = |f: fn(&TestAnchorHolder) -> &str| -> String {
            self.holders.iter().map(f).collect::<Vec<_>>().join(",")
        };
        vec![
            (TEST_ANCHOR_ENV_VARS[0], "true".to_owned()),
            (TEST_ANCHOR_ENV_VARS[1], join(|h| &h.root)),
            (TEST_ANCHOR_ENV_VARS[2], join(|h| &h.pqc)),
            (TEST_ANCHOR_ENV_VARS[3], join(|h| &h.scrub)),
            (TEST_ANCHOR_ENV_VARS[4], join(|h| &h.scrub_pqc)),
            (TEST_ANCHOR_ENV_VARS[5], join(|h| &h.seed)),
            (TEST_ANCHOR_ENV_VARS[6], self.minted_by.clone()),
        ]
    }

    /// The block as compose `environment:` lines (two-space indent,
    /// `KEY: "value"`), one per variable, in [`TEST_ANCHOR_ENV_VARS`] order.
    #[must_use]
    pub fn compose_lines(&self) -> String {
        self.env_pairs()
            .into_iter()
            .map(|(k, v)| format!("  {k}: \"{v}\"\n"))
            .collect()
    }
}

/// `persist v<CARGO_PKG_VERSION> / verify <tag>` — the verify tag is parsed
/// at first use from persist's OWN `Cargo.toml` (the `ciris-verify-core`
/// pin), so the pair a block claims is the pair that compiled the minter,
/// never a hand-typed string.
#[must_use]
pub fn test_anchor_minted_by() -> &'static str {
    static PAIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PAIR.get_or_init(|| {
        let manifest = include_str!("../../../Cargo.toml");
        let tag = manifest
            .lines()
            .find(|l| l.trim_start().starts_with("ciris-verify-core"))
            .and_then(|l| l.split("tag = \"").nth(1))
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("unpinned");
        format!("persist v{} / verify {tag}", env!("CARGO_PKG_VERSION"))
    })
}

/// Mint the block for `ed_seeds` (holder `i` = `test-accord-holder-{i}`):
/// Ed25519 from the seed, ML-DSA-65 from [`test_anchor_mldsa_seed`], the
/// envelope from [`super::test_anchor_registration_envelope`], canonicalized
/// by `ceg_produce_canonicalize`, `ed.sign(canonical)` and
/// `mldsa.sign(canonical ‖ ed_sig)` — the hybrid scrub shape every
/// federation-tier row carries. Pure: no directory, no clock.
pub fn mint_test_anchor_block(ed_seeds: &[[u8; 32]]) -> Result<TestAnchorBlock, Error> {
    if ed_seeds.is_empty() {
        return Err(Error::InvalidArgument(
            "mint_test_anchor_block: at least one seed".into(),
        ));
    }
    let bad = |what: &str, e: String| {
        Error::InvalidArgument(format!("mint_test_anchor_block: {what}: {e}"))
    };
    let mut holders = Vec::with_capacity(ed_seeds.len());
    for (i, seed) in ed_seeds.iter().enumerate() {
        let key_id = format!("test-accord-holder-{i}");
        let ed = Ed25519Signer::from_seed(seed).map_err(|e| bad("ed25519 seed", e.to_string()))?;
        let mldsa = MlDsa65Signer::from_seed(&test_anchor_mldsa_seed(seed))
            .map_err(|e| bad("ml-dsa-65 seed", e.to_string()))?;
        let root = B64.encode(
            ed.public_key()
                .map_err(|e| bad("ed25519 pubkey", e.to_string()))?,
        );
        let pqc = B64.encode(
            mldsa
                .public_key()
                .map_err(|e| bad("ml-dsa-65 pubkey", e.to_string()))?,
        );
        let envelope = super::test_anchor_registration_envelope(&key_id, &root, Some(&pqc));
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
            .map_err(|e| bad("canonicalize", e.to_string()))?;
        let ed_sig = ed
            .sign(&canonical)
            .map_err(|e| bad("ed25519 sign", e.to_string()))?;
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let ml_sig = mldsa
            .sign(&bound)
            .map_err(|e| bad("ml-dsa-65 sign", e.to_string()))?;
        holders.push(TestAnchorHolder {
            key_id,
            root,
            pqc,
            scrub: B64.encode(&ed_sig),
            scrub_pqc: B64.encode(&ml_sig),
            seed: B64.encode(seed),
        });
    }
    Ok(TestAnchorBlock {
        holders,
        minted_by: test_anchor_minted_by().to_owned(),
    })
}

/// Decode a base64 seed into the 32 bytes a holder is derived from.
pub fn decode_seed_b64(seed_b64: &str) -> Result<[u8; 32], Error> {
    let bytes = B64
        .decode(seed_b64.trim())
        .map_err(|e| Error::InvalidArgument(format!("seed is not base64: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        Error::InvalidArgument(format!("seed must decode to 32 bytes, got {}", v.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The consumers' block (CIRISServer `harness/mesh-repro/docker-compose.yml`,
    /// minted by CIRISEdge's generator) for the shared seed — the Ed25519
    /// side byte-for-byte, the long PQC values by SHA-256.
    const COMPOSE_ROOT: &str = "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=";
    const COMPOSE_SCRUB: &str =
        "ZOkeMQA9qWCJTjzCn9osJLwedBxvg0y+dusOp9bErJZKbZDouYSq3DWwGyXH3BpquFtBwRAeIb6502i+Ffi8Bg==";
    const COMPOSE_PQC_SHA256: &str =
        "7729242d8f30ef6d9e0bb159e113fd9d2bcbb53a944a727a0452a9b8a2a6bbd3";

    fn sha256_hex(s: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(s.as_bytes()))
    }

    /// **I159 — one block per pair, and it is the consumers' block.**
    #[test]
    fn i159_the_minter_reproduces_the_consumers_block() {
        let seed = decode_seed_b64(TEST_ANCHOR_SHARED_SEED_B64).unwrap();
        assert_eq!(seed, core::array::from_fn(|i| (i + 1) as u8));
        let block = mint_test_anchor_block(&[seed]).unwrap();
        assert_eq!(block.holders.len(), 1);
        let h = &block.holders[0];
        assert_eq!(h.key_id, "test-accord-holder-0");
        assert_eq!(
            h.root, COMPOSE_ROOT,
            "I159: the Ed25519 pubkey is the harnesses'"
        );
        assert_eq!(
            sha256_hex(&h.pqc),
            COMPOSE_PQC_SHA256,
            "I159: the ML-DSA-65 pubkey is the harnesses' (the seed domain is persist's now)"
        );
        assert_eq!(
            h.scrub, COMPOSE_SCRUB,
            "I159: Ed25519 is deterministic — the scrub IS the proof of one block per pair"
        );
        assert_eq!(h.seed, TEST_ANCHOR_SHARED_SEED_B64);
        // The PQC scrub is randomized: pinned by verification, over the
        // SAME preimage the seeder and the rooting walk use.
        let envelope = crate::federation::genesis::test_anchor_registration_envelope(
            &h.key_id,
            &h.root,
            Some(&h.pqc),
        );
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope).unwrap();
        crate::verify::hybrid::verify_hybrid(
            &canonical,
            &h.scrub,
            Some(&h.scrub_pqc),
            &h.root,
            Some(&h.pqc),
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .expect("I159: both halves verify over persist's canonical envelope");
        // Seven keys, in order, compose-ready.
        let text = block.compose_lines();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 7);
        for (line, var) in lines.iter().zip(TEST_ANCHOR_ENV_VARS) {
            assert!(
                line.starts_with(&format!("  {var}: \"")) && line.ends_with('"'),
                "I159: compose line shape: {line}"
            );
        }
        assert_eq!(
            lines[6],
            format!(
                "  CIRIS_TEST_TRUST_ROOT_MINTED_BY: \"{}\"",
                test_anchor_minted_by()
            )
        );
        // Two holders: comma-joined slots, distinct keys.
        let two = mint_test_anchor_block(&[seed, [0x42u8; 32]]).unwrap();
        let pairs = two.env_pairs();
        assert_eq!(pairs[1].1.split(',').count(), 2);
        assert_ne!(two.holders[0].root, two.holders[1].root);
        assert_eq!(two.holders[1].key_id, "test-accord-holder-1");
        assert!(mint_test_anchor_block(&[]).is_err());
    }

    /// **I162 (pure half) — the minted-by pair is derived, not typed.**
    #[test]
    fn i162_minted_by_is_the_compiled_pair() {
        let pair = test_anchor_minted_by();
        assert_eq!(
            pair,
            format!("persist v{} / verify v16.1.0", env!("CARGO_PKG_VERSION")),
            "I162: the verify half is the Cargo.toml tag; bump it there, never here"
        );
        let seed = decode_seed_b64(TEST_ANCHOR_SHARED_SEED_B64).unwrap();
        assert_eq!(mint_test_anchor_block(&[seed]).unwrap().minted_by, pair);
    }
}
