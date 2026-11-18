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

    // v62.0.0 (JSON cut, E7) — I159 (the block's hybrid scrub over the JCS
    // registration envelope, pinned to the consumers' compose block) is
    // deleted: it pins earlier-form signing.

    /// **I162 (pure half) — the minted-by pair is derived, not typed.**
    ///
    /// v54.0.0 — the expected verify half is read from `Cargo.toml` HERE too,
    /// independently of the minter's parse: every `CIRISVerify` git pin, all
    /// of which must name one tag. It was a typed `v19.0.0`, so the #992 pin
    /// flip to v20.1.0 left this witness red while the minter was right.
    #[test]
    fn i162_minted_by_is_the_compiled_pair() {
        let pair = test_anchor_minted_by();
        let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .expect("I162: read Cargo.toml");
        let tags: std::collections::BTreeSet<&str> = manifest
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter(|l| l.contains("github.com/CIRISAI/CIRISVerify"))
            .filter_map(|l| l.split("tag = \"").nth(1))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        assert_eq!(
            tags.len(),
            1,
            "I162: every CIRISVerify pin in Cargo.toml names ONE tag: {tags:?}"
        );
        let tag = tags.into_iter().next().expect("one tag");
        assert_eq!(
            pair,
            format!("persist v{} / verify {tag}", env!("CARGO_PKG_VERSION")),
            "I162: the verify half is the Cargo.toml tag; bump it there, never here"
        );
        let seed = decode_seed_b64(TEST_ANCHOR_SHARED_SEED_B64).unwrap();
        assert_eq!(mint_test_anchor_block(&[seed]).unwrap().minted_by, pair);
    }
}
