//! v62.0.0 (KR-fix31c; CC 5.2 "a write its own author cannot open is
//! refused") — **I4335–I4339**: every other at-rest seal under a cohort's
//! content key refuses `write_author_has_no_wrap_target` before it seals,
//! when no GRANTED wrap among the write's recipients reaches its author (the
//! community whole blob is KR-fix31's I4331–I4334). Through the verbs the
//! host doors call, on sqlite and postgres.
//!
//! - **I4335** — family whole blob (`encrypt_and_cascade`): a node no member
//!   owns is refused; a member's owned, keyed node seals and is granted.
//! - **I4336** — self whole blob: another owner's keyed device is no wrap
//!   target of alice's self content (refused); alice's own device seals.
//! - **I4337** — family chunk (`put_blob_chunk_scoped`): refused, nothing
//!   stored on the stream; seated, the chunk lands.
//! - **I4338** — community chunk: the same at the room's tier.
//! - **I4339** — stream manifest (`seal_stream_scoped`): a writer whose
//!   chunks landed, then whose owner's allow list drops the family, is
//!   refused at the seal (its terminators and manifest are not written).

#[cfg(any(feature = "postgres", feature = "sqlite"))]
mod exercises {
    use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
    use crate::federation::blobs::WRITE_AUTHOR_HAS_NO_WRAP_TARGET;
    use crate::federation::chunk_dag_cascade::orchestrate::{
        put_blob_chunk_scoped, seal_stream_scoped,
    };
    use crate::federation::community_dek::lifecycle_support::{id_of, seed_family_shaped};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::key_grant_invariants::two_node::{
        node_as, place_device, seed_community_everywhere,
    };
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY, SELF};
    use crate::federation::types::device_class::LAPTOP;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    fn refused_by_name<T: std::fmt::Debug>(r: Result<T, BlobError>, what: &str) {
        match r {
            Err(BlobError::InvalidArgument(m)) => assert!(
                m.starts_with(WRITE_AUTHOR_HAS_NO_WRAP_TARGET),
                "{what}: refused by name, got {m}"
            ),
            other => panic!("{what}: expected write_author_has_no_wrap_target, got {other:?}"),
        }
    }

    /// A family `{tag}-fam` with one member (`{tag}-alice`, a USER key with no
    /// device of its own); returns `(family id, alice seed)`.
    async fn family<B>(b: &B, tag: &str, run: &str) -> (String, String)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (fam, alice) = (format!("{tag}-fam-{run}"), format!("{tag}-alice-{run}"));
        seed_family_shaped(b, &fam, &[(&alice, &[])]).await;
        (id_of(&fam), alice)
    }

    /// I4335 — family whole blob.
    pub async fn exercise_i4335<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let (fam, alice) = family(b, tag, &run).await;
        let stray = node_as(b, &format!("i4335-s-{run}"), NODE).await;
        refused_by_name(
            encrypt_and_cascade(b, FAMILY, &fam, b"list", None, None, Some(&stray.key)).await,
            "I4335 (a node no member owns)",
        );
        let n = node_as(b, &format!("i4335-n-{run}"), NODE).await;
        place_device(b, &alice, &n.key, &n.key, LAPTOP, Some(n.kem.clone())).await;
        let r = encrypt_and_cascade(b, FAMILY, &fam, b"list", None, None, Some(&n.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I4335: a member's owned node seals: {e}"));
        assert!(r.granted.contains(&n.key), "{tag} I4335: {:?}", r.granted);
    }

    /// I4336 — self whole blob: the wrap targets are the OWNER's devices.
    pub async fn exercise_i4336<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let (alice, bob) = (format!("{tag}-a-{run}"), format!("{tag}-b-{run}"));
        for k in [&alice, &bob] {
            crate::federation::tier_ingest::test_support::register_hybrid_key_as(b, k, k, USER)
                .await;
        }
        let na = node_as(b, &format!("i4336-a-{run}"), NODE).await;
        let nb = node_as(b, &format!("i4336-b-{run}"), NODE).await;
        place_device(b, &alice, &na.key, &na.key, LAPTOP, Some(na.kem.clone())).await;
        place_device(b, &bob, &nb.key, &nb.key, LAPTOP, Some(nb.kem.clone())).await;
        let owner = id_of(&alice);
        refused_by_name(
            encrypt_and_cascade(b, SELF, &owner, b"note", None, None, Some(&nb.key)).await,
            "I4336 (bob's keyed device writes alice's self content)",
        );
        let r = encrypt_and_cascade(b, SELF, &owner, b"note", None, None, Some(&na.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I4336: alice's own device seals: {e}"));
        assert!(r.granted.contains(&na.key), "{tag} I4336: {:?}", r.granted);
        assert!(!r.granted.contains(&nb.key), "{tag} I4336: {:?}", r.granted);
    }

    /// I4337 — family chunk: refused, nothing on the stream; seated, lands.
    pub async fn exercise_i4337<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let (fam, alice) = family(b, tag, &run).await;
        let stray = node_as(b, &format!("i4337-s-{run}"), NODE).await;
        let stream = format!("{tag}-i4337-stream-{run}");
        refused_by_name(
            put_blob_chunk_scoped(
                b,
                stray.signer.as_ref(),
                FAMILY,
                Some(&fam),
                &stream,
                0,
                b"segment",
                0,
                None,
            )
            .await,
            "I4337 (a node no member owns appends)",
        );
        assert!(
            b.stream_chunks(&stream).await.unwrap().chunks.is_empty(),
            "{tag} I4337: a refused append stores nothing"
        );
        let n = node_as(b, &format!("i4337-n-{run}"), NODE).await;
        place_device(b, &alice, &n.key, &n.key, LAPTOP, Some(n.kem.clone())).await;
        let stream2 = format!("{tag}-i4337-stream2-{run}");
        put_blob_chunk_scoped(
            b,
            n.signer.as_ref(),
            FAMILY,
            Some(&fam),
            &stream2,
            0,
            b"segment",
            0,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I4337: the seated writer appends: {e}"));
        assert_eq!(
            b.stream_chunks(&stream2).await.unwrap().chunks.len(),
            1,
            "{tag} I4337"
        );
    }

    /// I4338 — community chunk.
    pub async fn exercise_i4338<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let n = node_as(b, &format!("i4338-n-{run}"), NODE).await;
        let comm = e2::kid(&format!("{tag}-i4338-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-i4338-alice-{run}"));
        seed_community_everywhere(&[&n], &comm, &[(&alice, Some(&n))]).await;
        // LEAD-fix1 — the room's DERIVED id, once founded (pass 10).
        let comm = e2::room_id(&comm);
        let stray = node_as(b, &format!("i4338-s-{run}"), NODE).await;
        let stream = format!("{tag}-i4338-stream-{run}");
        refused_by_name(
            put_blob_chunk_scoped(
                b,
                stray.signer.as_ref(),
                COMMUNITY,
                Some(&comm),
                &stream,
                0,
                b"segment",
                0,
                None,
            )
            .await,
            "I4338 (a node no member owns appends to the room)",
        );
        assert!(
            b.stream_chunks(&stream).await.unwrap().chunks.is_empty(),
            "{tag} I4338: a refused append stores nothing"
        );
        let stream2 = format!("{tag}-i4338-stream2-{run}");
        put_blob_chunk_scoped(
            b,
            n.signer.as_ref(),
            COMMUNITY,
            Some(&comm),
            &stream2,
            0,
            b"segment",
            0,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I4338: the member's node appends: {e}"));
    }

    /// I4339 — stream manifest after the writer's family key is withdrawn by
    /// its owner's allow list.
    pub async fn exercise_i4339<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::replication_audience_invariants::bodies::{grant, put};
        let run = uuid::Uuid::new_v4().simple().to_string();
        let (fam, alice) = family(b, tag, &run).await;
        let alias = format!("i4339-n-{run}");
        let n = node_as(b, &alias, NODE).await;
        place_device(b, &alice, &n.key, &n.key, LAPTOP, Some(n.kem.clone())).await;
        let stream = format!("{tag}-i4339-stream-{run}");
        put_blob_chunk_scoped(
            b,
            n.signer.as_ref(),
            FAMILY,
            Some(&fam),
            &stream,
            0,
            b"segment",
            0,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I4339: the seated writer appends: {e}"));
        // alice's allow list now names nothing for her node: no family key.
        put(
            b as &dyn FederationDirectory,
            &grant(&alice, Some(&alias), Some(serde_json::json!([]))),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I4339: alice's allow list lands: {e}"));
        refused_by_name(
            seal_stream_scoped(
                b,
                n.signer.as_ref(),
                FAMILY,
                Some(&fam),
                &stream,
                None,
                None,
            )
            .await,
            "I4339 (the writer is no longer a family recipient)",
        );
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite {
    use super::exercises::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i4335_family_blob_author_check_sqlite() {
        exercise_i4335(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4336_self_blob_author_check_sqlite() {
        exercise_i4336(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4337_family_chunk_author_check_sqlite() {
        exercise_i4337(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4338_community_chunk_author_check_sqlite() {
        exercise_i4338(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4339_stream_manifest_author_check_sqlite() {
        exercise_i4339(&fresh().await, "sqlite").await;
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres {
    use super::exercises::*;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    macro_rules! pg {
        ($name:ident, $body:ident) => {
            #[tokio::test]
            async fn $name() {
                let Some(b) = fresh().await else {
                    eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                    return;
                };
                $body(&b, "postgres").await;
            }
        };
    }

    pg!(i4335_family_blob_author_check_postgres, exercise_i4335);
    pg!(i4336_self_blob_author_check_postgres, exercise_i4336);
    pg!(i4337_family_chunk_author_check_postgres, exercise_i4337);
    pg!(i4338_community_chunk_author_check_postgres, exercise_i4338);
    pg!(i4339_stream_manifest_author_check_postgres, exercise_i4339);
}
