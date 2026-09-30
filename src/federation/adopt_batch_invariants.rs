//! v52.0.0 (CIRISPersist#957; `FSD/BLOB_REPLICATION.md` §6.7) — **a chunk
//! adopt costs the same at the ten-thousandth chunk as at the tenth.**
//!
//! - **I286** (sqlite) — the chunk floor's SQLite VM steps per append, read
//!   back from its cached statements, are flat in the number of chunks the
//!   stream already holds. Before #957 the nonce-cap `COUNT(*)` scanned the
//!   stream's index range on every append, so a stream was quadratic.
//! - **I287** (sqlite, postgres) — the cap still bites exactly: with the
//!   counter at `MAX_CHUNKS_PER_EPOCH − 1` one append lands and the next is
//!   refused by name (`InvalidArgument`, both backends) without stepping the
//!   counter; the next epoch takes chunks; a seq conflict does not count.
//! - **I288** (sqlite, postgres; and from disk in `blob_surface_gates`) — the
//!   counter is the truth: after appends over two epochs, a conflict, a batch
//!   with a refused item and `abandon_stream`, every counter row equals
//!   `COUNT(*) GROUP BY (stream_id, epoch)`; the abandoned stream has none;
//!   rewriting the abandoned id is refused and counts nothing; the same bytes
//!   under a fresh stream count from one. V165's backfill (sqlite, migrated
//!   from V164 over existing rows) equals the GROUP BY.
//! - **I289** (sqlite, postgres) — a batch is N singles: the same run adopted
//!   as one batch on one backend and one chunk at a time on another leaves the
//!   same index rows and counters; a duplicate seq mid-batch refuses only that
//!   item; through the cascade a non-envelope item is refused by shape and the
//!   rest land.
//! - **I290** (sqlite, postgres) — a stream-level refusal is total: a batch
//!   against another author's stream, an abandoned stream or a reserved id
//!   writes nothing — no blob row, no index row, no counter step.
//! - **I291** (from disk, `blob_surface_gates::i45`) — the batch doors are
//!   held to I45: no adopt body decrypts.

pub(crate) mod bodies {
    use crate::federation::at_rest_cascade::{fresh_dek, seal};
    use crate::federation::blobs::MAX_CHUNKS_PER_EPOCH;
    use crate::federation::types::cohort_scope::CryptoTier;
    use crate::federation::{BlobError, BlobStorage, FederationDirectory, StorageFloor};

    /// Test-only reads and writes of the V165 counter, per backend.
    pub(crate) trait CounterProbe {
        /// `(epoch, chunk_count)` from the counter, ordered by epoch.
        async fn counters(&self, stream: &str) -> Vec<(i64, i64)>;
        /// `(epoch, COUNT(*))` from the index rows, ordered by epoch.
        async fn truth(&self, stream: &str) -> Vec<(i64, i64)>;
        /// Set the counter for `(stream, epoch)`.
        async fn set_counter(&self, stream: &str, epoch: i64, n: i64);
    }

    fn sealed_of(tag: &str, seq: u64) -> (Vec<u8>, u64) {
        let p = format!("{tag} chunk {seq}");
        (sealed(p.as_bytes()), p.len() as u64)
    }

    fn floor() -> StorageFloor {
        StorageFloor::resolved(CryptoTier::InvisibleEncrypted)
    }

    async fn adopt_at<B: BlobStorage + Sync>(
        b: &B,
        stream: &str,
        author: &str,
        seq: u64,
        epoch: u64,
    ) -> Result<[u8; 32], BlobError> {
        let (env, n) = sealed_of(stream, seq);
        b.adopt_sealed_chunk_at(stream, seq, env, epoch, n, "self", author, floor(), None)
            .await
    }

    async fn batch<B: BlobStorage + Sync>(
        b: &B,
        stream: &str,
        author: &str,
        seqs: &[u64],
        epoch: u64,
    ) -> Result<Vec<Result<[u8; 32], BlobError>>, BlobError> {
        let items = seqs
            .iter()
            .map(|s| {
                let (env, n) = sealed_of(stream, *s);
                (*s, env, n)
            })
            .collect();
        b.adopt_sealed_chunks_at(stream, items, epoch, "self", author, floor(), None)
            .await
    }

    /// **I287** — the nonce cap still bites exactly.
    pub(crate) async fn i287_the_cap_bites_exactly<B>(b: &B, tag: &str)
    where
        B: BlobStorage + CounterProbe + Sync,
    {
        let stream = format!("i287-{tag}-{}", uuid::Uuid::new_v4().simple());
        let author = "i287-author";
        let max = i64::try_from(MAX_CHUNKS_PER_EPOCH).unwrap();
        b.set_counter(&stream, 0, max - 1).await;
        adopt_at(b, &stream, author, 0, 0)
            .await
            .expect("I287: the last chunk under the cap lands");
        assert_eq!(b.counters(&stream).await, vec![(0, max)]);
        let e = adopt_at(b, &stream, author, 1, 0)
            .await
            .expect_err("I287: an append past MAX_CHUNKS_PER_EPOCH");
        assert!(
            matches!(&e, BlobError::InvalidArgument(m) if m.contains("MAX_CHUNKS_PER_EPOCH")),
            "{tag} I287: the cap refuses by name as InvalidArgument: {e:?}"
        );
        assert_eq!(
            b.counters(&stream).await,
            vec![(0, max)],
            "{tag} I287: a refused append does not step the counter"
        );
        assert!(
            b.stream_chunks(&stream)
                .await
                .unwrap()
                .chunks
                .iter()
                .all(|c| c.seq == 0),
            "{tag} I287: the refused chunk left no index row"
        );
        adopt_at(b, &stream, author, 1, 1)
            .await
            .expect("I287: the next epoch takes chunks");
        let e = adopt_at(b, &stream, author, 1, 1)
            .await
            .expect_err("I287: a seq conflict");
        assert!(matches!(&e, BlobError::InvalidArgument(m) if m.contains("already exists")));
        assert_eq!(
            b.counters(&stream).await,
            vec![(0, max), (1, 1)],
            "{tag} I287: a seq conflict does not count"
        );
    }

    /// **I288** — the counter equals the index rows through every writer.
    pub(crate) async fn i288_the_counter_is_the_truth<B>(b: &B, tag: &str)
    where
        B: BlobStorage + CounterProbe + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let live = format!("i288-live-{tag}-{run}");
        let gone = format!("i288-gone-{tag}-{run}");
        let author = "i288-author";
        for seq in 0..5 {
            adopt_at(b, &live, author, seq, 0).await.unwrap();
        }
        for seq in 5..8 {
            adopt_at(b, &live, author, seq, 1).await.unwrap();
        }
        adopt_at(b, &live, author, 3, 1)
            .await
            .expect_err("a conflict");
        let got = batch(b, &live, author, &[8, 4, 9], 1).await.unwrap();
        assert!(
            got[0].is_ok() && got[1].is_err() && got[2].is_ok(),
            "{got:?}"
        );
        assert_eq!(b.counters(&live).await, vec![(0, 5), (1, 5)]);
        assert_eq!(b.counters(&live).await, b.truth(&live).await);

        for seq in 0..4 {
            adopt_at(b, &gone, author, seq, 0).await.unwrap();
        }
        assert_eq!(b.counters(&gone).await, vec![(0, 4)]);
        let report = b.abandon_stream_floor(&gone, author).await.unwrap();
        assert_eq!(report.chunks_dropped, 4);
        assert!(
            b.counters(&gone).await.is_empty(),
            "{tag} I288: an abandoned stream keeps no counter rows"
        );
        assert_eq!(b.truth(&gone).await, Vec::<(i64, i64)>::new());
        // Rewriting the abandoned id is refused, and counts nothing.
        let e = adopt_at(b, &gone, author, 0, 0)
            .await
            .expect_err("I288: an abandoned stream takes no chunks");
        assert!(matches!(&e, BlobError::InvalidArgument(m) if m.contains("stream_abandoned")));
        assert!(batch(b, &gone, author, &[0, 1], 0).await.is_err());
        assert!(b.counters(&gone).await.is_empty());
        // The same bytes under a fresh stream count from one.
        let again = format!("i288-again-{tag}-{run}");
        for seq in 0..4 {
            let (env, n) = sealed_of(&gone, seq);
            b.adopt_sealed_chunk_at(&again, seq, env, 0, n, "self", author, floor(), None)
                .await
                .unwrap();
        }
        assert_eq!(b.counters(&again).await, vec![(0, 4)]);
        assert_eq!(b.counters(&again).await, b.truth(&again).await);
        assert_eq!(b.counters(&live).await, b.truth(&live).await);
    }

    /// **I289** — a batch is N singles; a mid-batch conflict refuses one item.
    pub(crate) async fn i289_a_batch_is_n_singles<B>(one: &B, other: &B, tag: &str)
    where
        B: BlobStorage + CounterProbe + FederationDirectory + Sync,
    {
        let stream = format!("i289-{tag}-{}", uuid::Uuid::new_v4().simple());
        let author = "i289-author";
        // One seal per chunk, handed to both backends: the same bytes.
        let run: Vec<(u64, Vec<u8>, u64)> = (0u64..6)
            .map(|s| {
                let (env, n) = sealed_of(&stream, s);
                (s, env, n)
            })
            .collect();
        let batched = one
            .adopt_sealed_chunks_at(&stream, run.clone(), 0, "self", author, floor(), None)
            .await
            .unwrap();
        let mut singles = Vec::new();
        for (s, env, n) in run {
            singles.push(
                other
                    .adopt_sealed_chunk_at(&stream, s, env, 0, n, "self", author, floor(), None)
                    .await
                    .unwrap(),
            );
        }
        let batched: Vec<[u8; 32]> = batched.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            batched, singles,
            "{tag} I289: the same chunks at the same addresses"
        );
        let rows = |l: crate::federation::StreamChunks| {
            l.chunks
                .into_iter()
                .map(|c| (c.seq, c.chunk_sha, c.size_bytes))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            rows(one.stream_chunks(&stream).await.unwrap()),
            rows(other.stream_chunks(&stream).await.unwrap())
        );
        assert_eq!(one.counters(&stream).await, other.counters(&stream).await);
        // A duplicate seq mid-batch refuses only that item.
        let got = batch(one, &stream, author, &[6, 2, 7], 0).await.unwrap();
        assert!(got[0].is_ok(), "{got:?}");
        assert!(
            matches!(&got[1], Err(BlobError::InvalidArgument(m)) if m.contains("seq 2 already exists")),
            "{tag} I289: {got:?}"
        );
        assert!(got[2].is_ok(), "{got:?}");
        assert_eq!(one.counters(&stream).await, vec![(0, 8)]);
        assert_eq!(one.counters(&stream).await, one.truth(&stream).await);

        // Through the cascade: a non-envelope item is refused by its shape
        // (never opened, I45) and the rest land.
        use crate::federation::adopt_cascade::{adopt_sealed_chunks, AdoptChunkItem};
        use crate::federation::at_rest_cascade::blob_invariants::hold_ctx;
        let owner = format!("i289-owner-{tag}");
        let family: Vec<String> = Vec::new();
        let ctx = hold_ctx(false, &owner, &family);
        let prov = crate::federation::BlobProvenance {
            author_key_id: owner.clone(),
            cohort_scope: "self".into(),
            community_key_id: Some(owner.clone()),
            epoch: None,
            tier: CryptoTier::InvisibleEncrypted,
            minter_key_id: None,
        };
        let cstream = format!("i289-cascade-{tag}-{}", uuid::Uuid::new_v4().simple());
        let (e0, n0) = sealed_of(&cstream, 0);
        let (e2, n2) = sealed_of(&cstream, 2);
        let items = [
            AdoptChunkItem {
                seq: 0,
                envelope: &e0,
                plaintext_size: n0,
            },
            AdoptChunkItem {
                seq: 1,
                envelope: b"not an at-rest envelope",
                plaintext_size: 3,
            },
            AdoptChunkItem {
                seq: 2,
                envelope: &e2,
                plaintext_size: n2,
            },
        ];
        let got = adopt_sealed_chunks(one, &ctx, &cstream, &items, 0, &prov)
            .await
            .unwrap();
        assert!(got[0].is_ok() && got[2].is_ok(), "{got:?}");
        assert!(
            matches!(&got[1], Err(BlobError::InvalidArgument(m)) if m.contains("envelope shape")),
            "{tag} I289: {got:?}"
        );
        assert_eq!(one.counters(&cstream).await, vec![(0, 2)]);
    }

    /// **I290** — a stream-level refusal writes nothing at all.
    pub(crate) async fn i290_a_stream_refusal_is_total<B>(b: &B, tag: &str)
    where
        B: BlobStorage + CounterProbe + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let stream = format!("i290-{tag}-{run}");
        adopt_at(b, &stream, "i290-author-x", 0, 0).await.unwrap();
        let e = batch(b, &stream, "i290-author-y", &[1, 2, 3], 0)
            .await
            .expect_err("I290: another author's stream");
        assert!(matches!(&e, BlobError::InvalidArgument(_)), "{e:?}");
        assert_eq!(b.counters(&stream).await, vec![(0, 1)]);
        assert_eq!(b.stream_chunks(&stream).await.unwrap().chunks.len(), 1);

        // Blob rows: one sealed envelope whose address is known.
        let (env, n) = sealed_of(&stream, 9);
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&env).into()
        };
        let e = b
            .adopt_sealed_chunks_at(
                &stream,
                vec![(9, env.clone(), n)],
                0,
                "self",
                "i290-author-y",
                floor(),
                None,
            )
            .await
            .expect_err("I290: another author's stream");
        assert!(matches!(&e, BlobError::InvalidArgument(_)));
        assert!(
            !b.has_blob(&sha).await.unwrap(),
            "{tag} I290: a refused batch wrote a blob row"
        );

        // An abandoned stream.
        b.abandon_stream_floor(&stream, "i290-author-x")
            .await
            .unwrap();
        let e = b
            .adopt_sealed_chunks_at(
                &stream,
                vec![(9, env.clone(), n)],
                0,
                "self",
                "i290-author-x",
                floor(),
                None,
            )
            .await
            .expect_err("I290: an abandoned stream");
        assert!(matches!(&e, BlobError::InvalidArgument(m) if m.contains("stream_abandoned")));
        assert!(!b.has_blob(&sha).await.unwrap());
        assert!(b.counters(&stream).await.is_empty());

        // A first batch whose every item is refused claims nothing: the
        // stream row is not written (a later author can still take the id).
        let fresh_id = format!("i290-fresh-{tag}-{run}");
        let got = b
            .adopt_sealed_chunks_at(
                &fresh_id,
                vec![(0, b"not sealed".to_vec(), 10)],
                0,
                "self",
                "i290-author-x",
                floor(),
                None,
            )
            .await
            .unwrap();
        assert!(got[0].is_err());
        assert!(
            b.stream_chunks(&fresh_id).await.unwrap().stream.is_none(),
            "{tag} I290: a batch that stored nothing claimed the stream"
        );
        adopt_at(b, &fresh_id, "i290-author-y", 0, 0)
            .await
            .expect("I290: the unclaimed id is still anyone's first append");

        // A reserved (SHA-shaped) id.
        let reserved = hex::encode(sha);
        let e = b
            .adopt_sealed_chunks_at(&reserved, vec![(0, env, n)], 0, "self", "x", floor(), None)
            .await
            .expect_err("I290: a reserved id");
        assert!(matches!(&e, BlobError::InvalidArgument(m) if m.contains("reserved")));
        assert!(!b.has_blob(&sha).await.unwrap());
        assert!(b.counters(&reserved).await.is_empty());
    }

    /// A sealed self-tier chunk envelope over `plaintext`.
    pub(crate) fn sealed(plaintext: &[u8]) -> Vec<u8> {
        let dek = fresh_dek().expect("dek");
        seal(&dek, plaintext, None).expect("seal").to_bytes()
    }

    /// Adopt chunk `seq` of `stream` at the self tier, owned by `author`.
    #[cfg(feature = "sqlite")]
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
    use super::bodies::{self, adopt_one, CounterProbe};
    use crate::store::backend::Backend as _;
    use crate::store::sqlite::{chunk_floor_cost, SqliteBackend};

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    impl CounterProbe for SqliteBackend {
        async fn counters(&self, stream: &str) -> Vec<(i64, i64)> {
            let s = stream.to_owned();
            self.read(move |c| {
                let mut st = c
                    .prepare(
                        "SELECT epoch, chunk_count FROM federation_stream_epoch_counts \
                          WHERE stream_id = ?1 ORDER BY epoch",
                    )
                    .unwrap();
                st.query_map([s], |r| Ok((r.get(0)?, r.get(1)?)))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            })
            .await
        }
        async fn truth(&self, stream: &str) -> Vec<(i64, i64)> {
            let s = stream.to_owned();
            self.read(move |c| {
                let mut st = c
                    .prepare(
                        "SELECT epoch, COUNT(*) FROM federation_stream_chunks \
                          WHERE stream_id = ?1 GROUP BY epoch ORDER BY epoch",
                    )
                    .unwrap();
                st.query_map([s], |r| Ok((r.get(0)?, r.get(1)?)))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            })
            .await
        }
        async fn set_counter(&self, stream: &str, epoch: i64, n: i64) {
            let s = stream.to_owned();
            self.write(move |c| {
                c.execute(
                    "INSERT INTO federation_stream_epoch_counts (stream_id, epoch, chunk_count) \
                     VALUES (?1, ?2, ?3) \
                     ON CONFLICT (stream_id, epoch) DO UPDATE SET chunk_count = excluded.chunk_count",
                    rusqlite::params![s, epoch, n],
                )
                .unwrap();
            })
            .await;
        }
    }

    #[tokio::test]
    async fn i287_the_cap_bites_exactly_sqlite() {
        bodies::i287_the_cap_bites_exactly(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i288_the_counter_is_the_truth_sqlite() {
        bodies::i288_the_counter_is_the_truth(&fresh().await, "sqlite").await;
    }

    /// **I288 (backfill)** — V165 over a store that already holds chunk rows
    /// sets every counter to the GROUP BY.
    #[tokio::test]
    async fn i288_v165_backfill_equals_the_group_by_sqlite() {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations_through(164).await.unwrap();
        b.write(|c| {
            for (stream, seq, epoch) in [
                ("bf-a", 0i64, 0i64),
                ("bf-a", 1, 0),
                ("bf-a", 2, 3),
                ("bf-b", 0, 0),
            ] {
                c.execute(
                    "INSERT INTO federation_stream_chunks \
                        (stream_id, seq, chunk_sha, epoch, size_bytes, plaintext_size_bytes) \
                     VALUES (?1, ?2, ?3, ?4, 1, 1)",
                    rusqlite::params![stream, seq, vec![seq as u8; 32], epoch],
                )
                .unwrap();
            }
        })
        .await;
        b.run_migrations().await.unwrap();
        for s in ["bf-a", "bf-b"] {
            assert_eq!(b.counters(s).await, b.truth(s).await, "I288 backfill: {s}");
        }
        assert_eq!(b.counters("bf-a").await, vec![(0, 2), (3, 1)]);
    }

    #[tokio::test]
    async fn i289_a_batch_is_n_singles_sqlite() {
        bodies::i289_a_batch_is_n_singles(&fresh().await, &fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i290_a_stream_refusal_is_total_sqlite() {
        bodies::i290_a_stream_refusal_is_total(&fresh().await, "sqlite").await;
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

    /// The batch door at Edge's in-flight run of 8, same scale.
    #[tokio::test]
    #[ignore = "timing, run by hand"]
    async fn timing_957_batch8_8192_chunks_of_256k() {
        let dir = std::env::temp_dir().join(format!("b957-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let b = SqliteBackend::open(dir.join("t.db").to_string_lossy().to_string())
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let (n, size, run) = (8192u64, 256 * 1024usize, 8u64);
        let t0 = std::time::Instant::now();
        let mut seq = 0;
        while seq < n {
            let items = (seq..seq + run)
                .map(|s| {
                    let mut p = vec![7u8; size];
                    p[..8].copy_from_slice(&s.to_le_bytes());
                    (s, super::bodies::sealed(&p), size as u64)
                })
                .collect();
            let got = crate::federation::BlobStorage::adopt_sealed_chunks_at(
                &b,
                "timing-957-batch",
                items,
                0,
                "self",
                "timing-author",
                crate::federation::StorageFloor::resolved(
                    crate::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted,
                ),
                None,
            )
            .await
            .unwrap();
            assert!(got.iter().all(Result::is_ok));
            seq += run;
        }
        let total = t0.elapsed();
        eprintln!(
            "MEASURED #957 batch-of-8 {n} x {size} B: total {total:?} ({:.3} ms/chunk)",
            total.as_secs_f64() * 1000.0 / n as f64
        );
        let _ = std::fs::remove_dir_all(&dir);
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

#[cfg(all(test, feature = "postgres"))]
mod postgres {
    use super::bodies::{self, CounterProbe};
    use crate::store::backend::Backend as _;
    use crate::store::postgres::PostgresBackend;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    impl CounterProbe for PostgresBackend {
        async fn counters(&self, stream: &str) -> Vec<(i64, i64)> {
            let c = self.get_client().await.unwrap();
            c.query(
                "SELECT epoch, chunk_count FROM cirislens.federation_stream_epoch_counts \
                  WHERE stream_id = $1 ORDER BY epoch",
                &[&stream],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect()
        }
        async fn truth(&self, stream: &str) -> Vec<(i64, i64)> {
            let c = self.get_client().await.unwrap();
            c.query(
                "SELECT epoch, COUNT(*) FROM cirislens.federation_stream_chunks \
                  WHERE stream_id = $1 GROUP BY epoch ORDER BY epoch",
                &[&stream],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect()
        }
        async fn set_counter(&self, stream: &str, epoch: i64, n: i64) {
            let c = self.get_client().await.unwrap();
            c.execute(
                "INSERT INTO cirislens.federation_stream_epoch_counts (stream_id, epoch, chunk_count) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (stream_id, epoch) DO UPDATE SET chunk_count = EXCLUDED.chunk_count",
                &[&stream, &epoch, &n],
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn i287_the_cap_bites_exactly_postgres() {
        let Some(b) = fresh().await else { return };
        bodies::i287_the_cap_bites_exactly(&b, "postgres").await;
    }

    #[tokio::test]
    async fn i288_the_counter_is_the_truth_postgres() {
        let Some(b) = fresh().await else { return };
        bodies::i288_the_counter_is_the_truth(&b, "postgres").await;
    }

    #[tokio::test]
    async fn i289_a_batch_is_n_singles_postgres() {
        let (Some(a), Some(b)) = (fresh().await, fresh().await) else {
            return;
        };
        bodies::i289_a_batch_is_n_singles(&a, &b, "postgres").await;
    }

    #[tokio::test]
    async fn i290_a_stream_refusal_is_total_postgres() {
        let Some(b) = fresh().await else { return };
        bodies::i290_a_stream_refusal_is_total(&b, "postgres").await;
    }
}
