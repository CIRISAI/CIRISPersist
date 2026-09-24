//! v47.4.0 (CIRISPersist#805, `FSD/TEST_ANCHOR_BLOCK_MINTER.md` §4) — the
//! env-armed half of the witnesses: a MINTED block roots; a STALE block is
//! named at boot and the rooting rejection carries its detail; the
//! minted-by tag is checked. Its own process (the #738 rule: env-mutating
//! tests never share a binary with the suite), `#[serial]` within.
#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::genesis::{
    decode_seed_b64, mint_test_anchor_block, test_anchor_genesis_records, test_anchor_minted_by,
    TestAnchorBlock, TEST_ANCHOR_ENV_VARS, TEST_ANCHOR_LOG_TARGET, TEST_ANCHOR_SHARED_SEED_B64,
};
use ciris_persist::federation::rooting::{
    root_binding, RootingRejection, RootingVerdict, ROOTING_LOG_TARGET,
};

/// Arms the seven variables from `pairs`; restores the previous environment
/// on drop (the other tests in this binary, and this one's control legs).
struct ArmedBlock {
    saved: Vec<(&'static str, Option<String>)>,
}

impl ArmedBlock {
    fn arm(pairs: &[(&'static str, String)]) -> Self {
        let saved = TEST_ANCHOR_ENV_VARS
            .iter()
            .map(|v| (*v, std::env::var(v).ok()))
            .collect();
        for v in TEST_ANCHOR_ENV_VARS {
            std::env::remove_var(v);
        }
        for (k, v) in pairs {
            std::env::set_var(k, v);
        }
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("CIRIS_ENV");
        std::env::remove_var("CIRIS_ENVIRONMENT");
        Self { saved }
    }
}

impl Drop for ArmedBlock {
    fn drop(&mut self) {
        for (k, v) in self.saved.drain(..) {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// Captures every event on `target` as `field=value` strings.
struct Capture {
    target: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

struct Visitor(String);
impl tracing::field::Visit for Visitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{}={:?} ", field.name(), value));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!("{}={value} ", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
        m.target() == self.target
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() != self.target {
            return;
        }
        let mut v = Visitor(format!("[{}] ", event.metadata().level()));
        event.record(&mut v);
        self.events.lock().unwrap().push(v.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn captured<T>(target: &'static str, f: impl FnOnce() -> T) -> (T, Vec<String>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sub = Capture {
        target,
        events: Arc::clone(&events),
    };
    let out = tracing::subscriber::with_default(sub, f);
    let got = events.lock().unwrap().clone();
    (out, got)
}

fn shared_block() -> TestAnchorBlock {
    mint_test_anchor_block(&[decode_seed_b64(TEST_ANCHOR_SHARED_SEED_B64).unwrap()]).unwrap()
}

/// The shape CIRISServer's generator signed for months: the SAME keys over
/// a two-key literal that is not persist's envelope. Ed25519 is
/// deterministic, so this is exactly the stale block, not a caricature.
fn stale_block() -> Vec<(&'static str, String)> {
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    let seed = decode_seed_b64(TEST_ANCHOR_SHARED_SEED_B64).unwrap();
    let ed = Ed25519Signer::from_seed(&seed).unwrap();
    let mldsa = MlDsa65Signer::from_seed(
        &ciris_persist::federation::genesis::test_anchor_mldsa_seed(&seed),
    )
    .unwrap();
    let literal = serde_json::json!({ "key_id": "test-accord-holder-0", "test_anchor": true });
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&literal).unwrap();
    let ed_sig = ed.sign(&canonical).unwrap();
    let mut bound = canonical.clone();
    bound.extend_from_slice(&ed_sig);
    let ml_sig = mldsa.sign(&bound).unwrap();
    let good = shared_block();
    let mut pairs = good.env_pairs();
    pairs[3].1 = B64.encode(&ed_sig);
    pairs[4].1 = B64.encode(&ml_sig);
    pairs.retain(|(k, _)| *k != "CIRIS_TEST_TRUST_ROOT_MINTED_BY");
    pairs
}

async fn engine_with_block() -> ciris_persist::prelude::Engine {
    let pqc = Arc::new(
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[0x51; 32],
            "pin-node-pqc".to_string(),
        )
        .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(ciris_persist::prelude::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[0x50; 32]),
        "pin-node".to_string(),
        Some(pqc),
        Some("pin-node-pqc".to_string()),
    ));
    ciris_persist::prelude::Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("in-memory engine")
}

/// **I160 — a minted block roots.**
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i160_a_minted_block_roots() {
    let block = shared_block();
    let _armed = ArmedBlock::arm(&block.env_pairs());

    let (records, warns) = captured(TEST_ANCHOR_LOG_TARGET, test_anchor_genesis_records);
    let records = records.expect("I160: the armed block seeds the anchor");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record.key_id, "test-accord-holder-0");
    assert_eq!(
        records[0].record.scrub_signature_classical,
        block.holders[0].scrub
    );
    assert!(
        warns.is_empty(),
        "I160: a block minted by this pair says nothing at boot: {warns:?}"
    );

    let engine = engine_with_block().await;
    let dir = engine.federation_directory();
    let terminus = dir
        .lookup_public_key("test-accord-holder-0")
        .await
        .unwrap()
        .expect("I160: the engine seeds the terminus while the block is armed");
    let (verdict, rooting_warns) = {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sub = Capture {
            target: ROOTING_LOG_TARGET,
            events: Arc::clone(&events),
        };
        let _g = tracing::subscriber::set_default(sub);
        let v = root_binding(&*dir, &terminus.key_id, &terminus.pubkey_ed25519_base64).await;
        drop(_g);
        let got = events.lock().unwrap().clone();
        (v, got)
    };
    assert!(
        matches!(verdict, RootingVerdict::Confirmed { .. }),
        "I160: the minted block roots under the pair that minted it: {verdict:?}"
    );
    assert!(
        rooting_warns.is_empty(),
        "I160: no rejection, no line: {rooting_warns:?}"
    );
}

/// **I161 — a stale block is named at boot, and the rejection carries its detail.**
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i161_a_stale_block_is_named_at_boot_and_the_rejection_carries_detail() {
    let _armed = ArmedBlock::arm(&stale_block());

    let (records, warns) = captured(TEST_ANCHOR_LOG_TARGET, test_anchor_genesis_records);
    assert_eq!(
        records.map(|r| r.len()),
        Some(1),
        "I161: the record is still seeded — the rooting walk is the gate, the seeder reports"
    );
    assert_eq!(
        warns.len(),
        1,
        "I161: exactly one boot-time line: {warns:?}"
    );
    let w = &warns[0];
    assert!(w.starts_with("[WARN]"), "{w}");
    assert!(
        w.contains("key_id=test-accord-holder-0"),
        "I161: names the slot: {w}"
    );
    assert!(w.contains("detail="), "I161: carries verify's detail: {w}");
    assert!(
        w.contains("mint_test_anchor") && w.contains("--features test-anchor"),
        "I161: names the fix: {w}"
    );

    let engine = engine_with_block().await;
    let dir = engine.federation_directory();
    let terminus = dir
        .lookup_public_key("test-accord-holder-0")
        .await
        .unwrap()
        .expect("terminus seeded");
    let events = Arc::new(Mutex::new(Vec::new()));
    let sub = Capture {
        target: ROOTING_LOG_TARGET,
        events: Arc::clone(&events),
    };
    let g = tracing::subscriber::set_default(sub);
    let verdict = root_binding(&*dir, &terminus.key_id, &terminus.pubkey_ed25519_base64).await;
    drop(g);
    let rooting_warns = events.lock().unwrap().clone();
    let RootingVerdict::Rejected { rejection } = verdict else {
        panic!("I161: the stale block must NOT root: {verdict:?}");
    };
    let RootingRejection::UnsignedProvenanceLink { key_id, detail, .. } = &rejection else {
        panic!("I161: the rejection is the unsigned link: {rejection:?}");
    };
    assert_eq!(key_id, "test-accord-holder-0");
    assert!(
        detail.contains("did not verify"),
        "I161: verify's text: {detail}"
    );
    assert_eq!(
        rooting_warns.len(),
        1,
        "I161: one line where the verdict is produced: {rooting_warns:?}"
    );
    let rw = &rooting_warns[0];
    assert!(
        rw.contains("kind=rooting_unsigned_provenance_link") && rw.contains("did not verify"),
        "I161: the line carries the kind AND the detail: {rw}"
    );
}

/// **I162 (env half) — the minted-by tag is checked.**
#[serial_test::serial(test_anchor_env)]
#[test]
fn i162_the_minted_by_tag_is_checked_at_boot() {
    let block = shared_block();
    // Equal: silent.
    {
        let _armed = ArmedBlock::arm(&block.env_pairs());
        let (_, warns) = captured(TEST_ANCHOR_LOG_TARGET, test_anchor_genesis_records);
        assert!(
            warns.is_empty(),
            "I162: the tag matches the running pair: {warns:?}"
        );
    }
    // Absent: silent (every block that predates the tag).
    {
        let mut pairs = block.env_pairs();
        pairs.retain(|(k, _)| *k != "CIRIS_TEST_TRUST_ROOT_MINTED_BY");
        let _armed = ArmedBlock::arm(&pairs);
        let (_, warns) = captured(TEST_ANCHOR_LOG_TARGET, test_anchor_genesis_records);
        assert!(
            warns.is_empty(),
            "I162: an untagged block is not scolded: {warns:?}"
        );
    }
    // Different: one line naming both.
    {
        let mut pairs = block.env_pairs();
        pairs[6].1 = "persist v40.0.0 / verify v14.1.0".to_owned();
        let _armed = ArmedBlock::arm(&pairs);
        let (_, warns) = captured(TEST_ANCHOR_LOG_TARGET, test_anchor_genesis_records);
        assert_eq!(warns.len(), 1, "I162: {warns:?}");
        let w = &warns[0];
        assert!(
            w.contains("persist v40.0.0 / verify v14.1.0") && w.contains(test_anchor_minted_by()),
            "I162: names the block's pair and the running pair: {w}"
        );
    }
}
