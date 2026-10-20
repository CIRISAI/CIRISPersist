//! v59.1.0 (CIRISPersist#1106, CC 5.3.4) — **the production genesis bundle,
//! re-minted as v4 by the 2-of-3 amend**, is baked and boots.
//!
//! Eric's ceremony of 2026-10-20 (holders A1 and B1, on hardware) amended the
//! v59 baked v3 bundle through `genesis::amend::AmendState`, adding the sole
//! serve node's signed transport destination with its live transit pair. This
//! file proves, on the REAL baked bytes and with no test anchor armed, that:
//! the ceremony verifier accepts it; its authorizations meet the quorum door;
//! and a fresh node opened through the production `Engine` boot holds a
//! Rooted transit pair for `ciris-canonical-1-d7bdeu223k` with no network —
//! the pair the canonical node's keystore holds.
#![cfg(feature = "sqlite")]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::self_at_login::transit_kex_pair_for;

const CANONICAL_NODE: &str = "ciris-canonical-1-d7bdeu223k";
const BAKED: &str = include_str!("../src/federation/genesis/canonical_seed.json");

/// **I1160** — the production v4 bake verifies and seeds the canonical's
/// Rooted transit pair on a fresh, offline node.
#[tokio::test]
async fn i1160_the_production_v4_bake_seeds_the_canonical_pair() {
    let bundle = canonical_genesis_bundle();
    assert_eq!(bundle.version, 4, "I1160: the bake is the v4 amend");
    assert_eq!(bundle.serve_transport_destinations.len(), 1);
    let row = &bundle.serve_transport_destinations[0];
    assert_eq!(row.attesting_key_id, CANONICAL_NODE);

    verify_ceremony_outputs(BAKED)
        .await
        .expect("I1160: the ceremony verifier accepts the baked v4 bundle");

    let signer = std::sync::Arc::new(ciris_persist::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]),
        "i1160-fresh-node".to_string(),
        None,
        None,
    ));
    let engine = ciris_persist::engine::Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("I1160: a fresh production node opens on the baked v4 bundle");
    let dir = engine.federation_directory();

    let verified = verify_bundle_quorum(dir.as_ref(), bundle)
        .await
        .expect("I1160: the v4 authorizations meet the quorum door");
    assert_eq!(
        verified.distinct_holders(),
        2,
        "I1160: the amend carries A1 and B1 (2 over the charter's 2/3)"
    );

    let pair = transit_kex_pair_for(dir.as_ref(), CANONICAL_NODE)
        .await
        .expect("I1160: the resolver reads")
        .expect("I1160: a Rooted pair for the canonical, offline");
    let carried = &row.signed_envelope["transit_kex_pubkeys"];
    let x = B64
        .decode(carried["x25519_base64"].as_str().expect("x25519_base64"))
        .unwrap();
    let m = B64
        .decode(
            carried["ml_kem_768_base64"]
                .as_str()
                .expect("ml_kem_768_base64"),
        )
        .unwrap();
    assert_eq!(&pair.x25519[..], &x[..], "I1160: the bundle's X25519");
    assert_eq!(
        &pair.ml_kem_768[..],
        &m[..],
        "I1160: the bundle's ML-KEM-768"
    );
}
