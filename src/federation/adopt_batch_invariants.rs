//! v52.0.0 (CIRISPersist#957; `FSD/BLOB_REPLICATION.md` §6.7) — **a chunk
//! adopt costs the same at the ten-thousandth chunk as at the tenth.**
//!
//! - **I286** (sqlite) — the chunk floor's SQLite VM steps per append, read
//!   back from its cached statements, are flat in the number of chunks the
//!   stream already holds. Before #957 the nonce-cap `COUNT(*)` scanned the
//!   stream's index range on every append, so a stream was quadratic.

pub(crate) mod bodies {
    use crate::federation::at_rest_cascade::{fresh_dek, seal};
    use crate::federation::types::cohort_scope::CryptoTier;
    use crate::federation::{BlobStorage, StorageFloor};

    /// A sealed self-tier chunk envelope over `plaintext`.
    pub(crate) fn sealed(plaintext: &[u8]) -> Vec<u8> {
        let dek = fresh_dek().expect("dek");
        seal(&dek, plaintext, None).expect("seal").to_bytes()
    }

    /// Adopt chunk `seq` of `stream` at the self tier, owned by `author`.
    pub(crate) async fn adopt_one<B>(b: &B, stream: &str, author: &str, seq: u64, plaintext: &[u8])
    where
        B: BlobStorage + Sync,
    {
        b.adopt_sealed_chunk_at(
            stream,
            seq,
            sealed(plaintext),
            0,
            plaintext.len() as u64,
            "self",
            author,
            StorageFloor::resolved(CryptoTier::InvisibleEncrypted),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("adopt {stream} seq {seq}: {e}"));
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite {
    use super::bodies::adopt_one;
    use crate::store::backend::Backend as _;
    use crate::store::sqlite::{chunk_floor_cost, SqliteBackend};

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    /// **I286** — the floor's VM steps at the 1024th chunk are those at the
    /// 16th, give or take b-tree depth.
    #[tokio::test]
    async fn i286_chunk_adopt_cost_is_flat_in_stream_length() {
        let b = fresh().await;
        let stream = format!("i286-{}", uuid::Uuid::new_v4().simple());
        let author = "i286-author";
        let mut early = 0;
        for seq in 0..1024u64 {
            adopt_one(&b, &stream, author, seq, format!("chunk {seq}").as_bytes()).await;
            if seq == 16 {
                early = chunk_floor_cost::last(&stream).expect("the floor recorded its cost");
            }
        }
        let late = chunk_floor_cost::last(&stream).expect("recorded");
        assert!(early > 0);
        assert!(
            late <= early + early / 2,
            "I286: the floor's cost grows with the stream: {early} VM steps at chunk 16, \
             {late} at chunk 1023 — a per-append scan of the stream's chunks (#957)"
        );
    }

    /// Not a witness: the MEASURED before/after for #957's report. Run with
    /// `--run-ignored only`. File-backed, production pragmas, 4096 × 4 KiB.
    #[tokio::test]
    #[ignore = "timing, run by hand"]
    async fn timing_957_adopt_4096_chunks_of_4k() {
        timing(4096, 4096, 256).await;
    }

    /// As above at Edge's chunk size: 2048 × 256 KiB (a 512 MiB stream).
    #[tokio::test]
    #[ignore = "timing, run by hand"]
    async fn timing_957_adopt_2048_chunks_of_256k() {
        timing(2048, 256 * 1024, 128).await;
    }

    /// Edge's scale: 8192 × 256 KiB (a 2 GiB stream).
    #[tokio::test]
    #[ignore = "timing, run by hand"]
    async fn timing_957_adopt_8192_chunks_of_256k() {
        timing(8192, 256 * 1024, 256).await;
    }

    async fn timing(n: u64, size: usize, window: u64) {
        let dir = std::env::temp_dir().join(format!("b957-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        let b = SqliteBackend::open(path.to_string_lossy().to_string())
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let stream = "timing-957";
        let body = vec![7u8; size];
        let t0 = std::time::Instant::now();
        let mut first = std::time::Duration::ZERO;
        let mut last = std::time::Instant::now();
        for seq in 0..n {
            if seq == n - window {
                last = std::time::Instant::now();
            }
            let mut p = body.clone();
            p[..8].copy_from_slice(&seq.to_le_bytes());
            adopt_one(&b, stream, "timing-author", seq, &p).await;
            if seq == window - 1 {
                first = t0.elapsed();
            }
        }
        let total = t0.elapsed();
        let tail = last.elapsed();
        eprintln!(
            "MEASURED #957 single-door {n} x {size} B: total {total:?}; first {window} chunks \
             {first:?} ({:.3} ms/chunk); last {window} chunks {tail:?} ({:.3} ms/chunk)",
            first.as_secs_f64() * 1000.0 / window as f64,
            tail.as_secs_f64() * 1000.0 / window as f64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
