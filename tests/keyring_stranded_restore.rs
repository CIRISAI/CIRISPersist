//! I1477 (CIRISVerify#311) — **a node identity stranded by the pre-#311
//! keyring reopens with the same key.**
//!
//! A booting node opens its own classical identity with
//! `ciris_keyring::SealedEd25519Signer::open_existing` (the PyEngine
//! `identity_dir` + `keystore_alias` branch in `src/ffi/pyo3.rs`). Before
//! CIRISVerify 20.3.0, a re-open under a newly visible higher tier minted that
//! tier's master and renamed the live software key to `*.superseded-pre-v8`
//! without writing anything into the new tier. Every later open then answered
//! `KeyNotFound`, and the node could not boot. CIRISVerify 22 restores such a
//! home on open (`restore_stranded_software_key`, inside
//! `create_platform_storage`).
//!
//! This builds that home without hardware: seal a known seed in the software
//! tier, then rename every artifact of the alias to `*.superseded-pre-v8`,
//! exactly as the pre-#311 supersession left it. `open_existing` must answer
//! with the SAME public key and the files must be back under their own names.
//!
//! The software tier is the only tier this can strand (a hardware tier's key
//! never leaves the device). On a host where the TPM plugin is installed the
//! first seal lands in the plugin tier instead; the test then says so and
//! stops, because the stranded-software home cannot be built there.

use ciris_keyring::{HardwareSigner as _, SealedEd25519Signer};

const ALIAS: &str = "node-identity";
const SUPERSEDED_SUFFIX: &str = "superseded-pre-v8";

fn alias_files(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read the keyring dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&format!("{ALIAS}.")))
        .collect();
    names.sort();
    names
}

fn public_key(signer: &SealedEd25519Signer) -> Vec<u8> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(signer.public_key())
        .expect("public key")
}

#[test]
fn i1477_a_stranded_software_identity_reopens_with_the_same_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seed = [0x5au8; 32];

    let sealed = SealedEd25519Signer::open_or_create(ALIAS, dir.path(), Some(&seed))
        .expect("seal the identity");
    let original = public_key(&sealed);
    drop(sealed);

    let live = alias_files(dir.path());
    if !live.iter().any(|n| n == &format!("{ALIAS}.master.key")) {
        eprintln!(
            "I1477: the first seal did not land in the software tier ({live:?}); \
             a hardware tier is present on this host, so the stranded-software \
             home cannot be built here"
        );
        return;
    }
    assert!(
        live.iter().any(|n| n.ends_with(".blob")),
        "the software tier holds the sealed seed as a blob: {live:?}"
    );

    // The pre-#311 supersession: every artifact of the alias archived, nothing
    // live in any tier.
    for name in &live {
        std::fs::rename(
            dir.path().join(name),
            dir.path().join(format!("{name}.{SUPERSEDED_SUFFIX}")),
        )
        .expect("archive");
    }
    assert!(
        alias_files(dir.path())
            .iter()
            .all(|n| n.ends_with(SUPERSEDED_SUFFIX)),
        "the home is stranded: no live artifact"
    );

    let reopened = SealedEd25519Signer::open_existing(ALIAS, dir.path())
        .expect("a stranded software identity must reopen, not answer KeyNotFound");
    assert_eq!(
        public_key(&reopened),
        original,
        "the reopened identity is the one that was sealed, not a new key"
    );
    assert_eq!(
        alias_files(dir.path()),
        live,
        "every archived artifact is back under its own name"
    );
}
