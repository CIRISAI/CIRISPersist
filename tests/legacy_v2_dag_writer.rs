//! v53.0.0 (CIRISPersist#969) — **a consumer crate can write a legacy (manifest
//! v2, per-chunk-keyed) sealed DAG and pull it end to end.**
//!
//! v53 seals every new self/family stream under one key per (stream, epoch)
//! (manifest v4); v52's files stay readable, but no public door writes one any
//! more. `chunk_dag_cascade::test_support::write_legacy_v2_dag` (test-anchor
//! only) is the one v2 writer. This test drives it from OUTSIDE the crate, the
//! way CIRISEdge's tests do: node A writes and seals a v2 file and emits its
//! key-grant sets; node B learns of it only through the doors a puller uses
//! (the replicated key-grant sets, the sealed manifest, each sealed chunk, the
//! promote), then reads it back.
#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::chunk_dag_cascade::test_support::write_legacy_v2_dag;
use ciris_persist::federation::key_grant::SignedKeyGrantSet;
use ciris_persist::federation::key_grant_invariants::two_node::{introduce_as, Node};
use ciris_persist::federation::tier_ingest::test_support as ts;
use ciris_persist::federation::types::cohort_scope::{CryptoTier, SELF};
use ciris_persist::federation::types::device_class::LAPTOP;
use ciris_persist::federation::types::identity_type::{NODE, USER};
use ciris_persist::federation::types::IdentityOccurrence;
use ciris_persist::federation::{
    AdoptDisposition, BlobBody, BlobProvenance, BlobStorage, EncryptionPubkeys, FederationDirectory,
};
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::Engine;
use std::sync::Arc;

fn run_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
}

async fn engine(alias: &str) -> (Engine, Arc<SqliteBackend>) {
    let e = Engine::with_signer_pre_genesis(ts::local_signer(alias), "sqlite::memory:")
        .await
        .expect("engine");
    e.register_self_federation_key(NODE, alias, None, serde_json::json!({}), vec![])
        .await
        .expect("own key");
    let b = e.sqlite_backend().expect("sqlite").clone();
    (e, b)
}

async fn kem(b: &SqliteBackend) -> EncryptionPubkeys {
    let id = b.load_or_init_content_kem_identity().await.expect("kem");
    EncryptionPubkeys {
        x25519_base64: id.x25519_pubkey_b64,
        ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
    }
}

async fn inline(b: &SqliteBackend, sha: &[u8; 32]) -> Vec<u8> {
    match b.get_blob(sha).await.expect("get_blob") {
        Some(BlobBody::Inline(v)) => v,
        other => panic!("{} is not inline: {other:?}", hex::encode(sha)),
    }
}

fn segment(i: usize) -> Vec<u8> {
    (0..60 + (i % 4) * 17).map(|j| (i * 29 + j) as u8).collect()
}

/// The caller AAD a v52 CIRISEdge node bound every sealed file to: its
/// `group_content::content_aad(author, asserted_at, field)`, byte for byte
/// (`ciris.edge.blob.aad.v1\0` then each part as a u32-BE length prefix and
/// its bytes; the instant rendered by persist's `render_signed_instant`).
fn edge_content_aad(
    author: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    field: &str,
) -> Vec<u8> {
    fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let instant = ciris_persist::federation::admission::render_signed_instant(asserted_at);
    let mut out = b"ciris.edge.blob.aad.v1\x00".to_vec();
    push_lp(&mut out, author.as_bytes());
    push_lp(&mut out, instant.as_bytes());
    push_lp(&mut out, field.as_bytes());
    out
}

#[tokio::test]
async fn a_legacy_v2_dag_written_on_a_is_pulled_and_read_on_b() {
    pull_a_legacy_v2_dag(None).await;
}

/// The v52 Edge shape: the file sealed under Edge's `content_aad`. B opens it
/// with the same AAD at every door, and a different AAD opens nothing.
#[tokio::test]
async fn a_legacy_v2_dag_sealed_under_edges_content_aad_needs_that_aad() {
    let aad = edge_content_aad(
        "v2w-author",
        chrono::DateTime::parse_from_rfc3339("2026-09-30T12:34:56.789Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        "body",
    );
    pull_a_legacy_v2_dag(Some(aad)).await;
}

async fn pull_a_legacy_v2_dag(aad: Option<Vec<u8>>) {
    let aad = aad.as_deref();
    let run = run_id();
    let (alias_a, alias_b) = (format!("v2w-a-{run}"), format!("v2w-b-{run}"));
    let (a, sa) = engine(&alias_a).await;
    let (b, sb) = engine(&alias_b).await;
    let na = Node {
        backend: sa.as_ref(),
        signer: ts::local_signer(&alias_a),
        key: a.local_derived_key_id().await.unwrap(),
        kem: kem(&sa).await,
    };
    let nb = Node {
        backend: sb.as_ref(),
        signer: ts::local_signer(&alias_b),
        key: b.local_derived_key_id().await.unwrap(),
        kem: kem(&sb).await,
    };
    introduce_as(&[&na, &nb], &[&alias_a, &alias_b], NODE).await;
    // One person owning both nodes, both bound on both nodes as personal
    // devices (a server-class occurrence gets none of its owner's self keys).
    let owner = format!("v2w-owner-{run}");
    for n in [&na, &nb] {
        ts::register_hybrid_key_as(n.backend, &owner, &owner, USER).await;
        for dev in [&na, &nb] {
            n.backend
                .put_identity_occurrence_local(IdentityOccurrence {
                    identity_key_id: owner.clone(),
                    occurrence_key_id: dev.key.clone(),
                    device_class: LAPTOP.to_owned(),
                    hardware_attestation: None,
                    asserted_at: chrono::Utc::now(),
                    valid_until: None,
                    encryption_pubkeys: Some(dev.kem.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                })
                .await
                .expect("bind");
            ts::put_owner_binding(n.backend, &owner, &dev.key).await;
        }
    }

    // ── A writes a v2 file, exactly as a v52 node did. ──
    let stream = format!("v2w-{run}");
    let segs: Vec<Vec<u8>> = (0..5).map(segment).collect();
    let dag = write_legacy_v2_dag(&a, sa.as_ref(), SELF, &owner, &stream, &segs, aad)
        .await
        .expect("write v2");
    let root = dag.manifest_sha256;
    let on_a = a
        .open_sealed_manifest_as(&root, &na.key, aad)
        .await
        .unwrap();
    assert_eq!(on_a.version, 2, "the writer wrote a legacy (v2) manifest");
    assert!(on_a.chunks.iter().all(|c| c.epoch.is_none()));
    assert_eq!(on_a.chunks.len(), segs.len(), "no terminator on a v2 DAG");
    a.emit_pending_key_grants().await.unwrap();
    let sets: Vec<_> = sa
        .list_attestations_by(&na.key)
        .await
        .unwrap()
        .into_iter()
        .filter(|x| x.attestation_type.starts_with("key_grant:"))
        .collect();
    assert!(!sets.is_empty(), "A emitted the v2 file's key-grant sets");

    // ── B pulls: the sets, the sealed manifest, each sealed chunk, promote. ──
    for set in sets {
        b.apply_replicated_key_grant(SignedKeyGrantSet { attestation: set })
            .await
            .expect("B applies a key-grant set");
    }
    let prov = BlobProvenance {
        author_key_id: owner.clone(),
        cohort_scope: SELF.to_owned(),
        community_key_id: None,
        epoch: None,
        tier: CryptoTier::InvisibleEncrypted,
        minter_key_id: Some(na.key.clone()),
    };
    b.adopt_sealed_blob(
        &inline(&sa, &root).await,
        prov.clone(),
        aad,
        AdoptDisposition::LocalOnly,
    )
    .await
    .expect("B adopts the manifest");
    let view = b
        .open_sealed_manifest_as(&root, &nb.key, aad)
        .await
        .expect("B opens the manifest");
    assert_eq!(view.version, 2, "B sees a legacy (v2) manifest");
    for (c, sha) in view.chunks.iter().zip(&dag.chunk_sha256) {
        assert_eq!(c.sha256_hex, hex::encode(sha), "chunk {} address", c.seq);
        b.adopt_sealed_chunk(
            &stream,
            c.seq,
            &inline(&sa, sha).await,
            0,
            u64::from(c.size),
            prov.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("B adopts chunk {}: {e}", c.seq));
    }
    b.promote_adopted_manifest_to_dag(&root, &nb.key, aad)
        .await
        .expect("B promotes the v2 DAG");
    let r = b.sealed_dag_readiness(&root, &nb.key, aad).await.unwrap();
    assert_eq!(r.chunk_keys, "content", "{r:?}");
    assert!(r.held && r.readable && r.missing.is_empty(), "{r:?}");
    assert_eq!(
        b.read_blob_as(&root, &nb.key, aad).await.unwrap(),
        dag.plaintext,
        "B reads the v2 file"
    );
    assert_eq!(
        b.read_blob_range_as(&root, &nb.key, 70, 200, aad)
            .await
            .unwrap(),
        dag.plaintext[70..=200].to_vec()
    );
    // A different AAD opens nothing: not the manifest, not the file.
    let wrong: &[u8] = match aad {
        Some(_) => b"another pointer's aad",
        None => b"an aad the file was never bound to",
    };
    assert!(
        b.open_sealed_manifest_as(&root, &nb.key, Some(wrong))
            .await
            .is_err(),
        "B must not open the manifest under a different AAD"
    );
    assert!(
        b.read_blob_as(&root, &nb.key, Some(wrong)).await.is_err(),
        "B must not read the file under a different AAD"
    );
    assert!(
        b.sealed_dag_readiness(&root, &nb.key, Some(wrong))
            .await
            .is_err(),
        "the readiness door opens the manifest with the same AAD"
    );
}
