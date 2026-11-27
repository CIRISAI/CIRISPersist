//! v62.0.0 (KR-fix31; CC 5.2 "a write its own author cannot open is
//! refused") — **I4331–I4334**: the community sealer refuses, before anything
//! is written, a write whose AUTHOR holds no wrap target in the fan-out it
//! seals for (no current occurrence of the author, and no node the author
//! owns by a live two-voice binding, carries usable content-KEM keys and a
//! grant). Through the seal verb every host door calls
//! ([`encrypt_and_cascade_community`]), on sqlite and postgres.
//!
//! - **I4331** — an author with no keyed occurrence and no owned node is
//!   refused `write_author_has_no_wrap_target`, although another member could
//!   read; nothing is stored: no epoch, no self-retention, no grant, no
//!   object, no dirty key-grant set. The same author, once a member's owned
//!   device, seals.
//! - **I4332** — an author whose own occurrence is keyed seals, and that
//!   occurrence opens the write.
//! - **I4333** — an author with no occurrence of its own but OWNED (a
//!   two-voice owner binding + the node's self pair with keys) seals, and the
//!   node opens the write.
//! - **I4334** — the author has a target and another member has none: the
//!   write seals; that member is excluded with its recorded reason (its bare
//!   device in `excluded`, the member in `roster.excluded`), and holds no
//!   grant.

#[cfg(any(feature = "postgres", feature = "sqlite"))]
mod exercises {
    use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
    use crate::federation::blobs::WRITE_AUTHOR_HAS_NO_WRAP_TARGET;
    use crate::federation::community_dek::lifecycle_support::{id_of, seed_community};
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::key_grant_invariants::two_node::{
        node_as, place_device, seed_community_everywhere,
    };
    use crate::federation::types::device_class::LAPTOP;
    use crate::federation::types::identity_type::NODE;
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    /// Nothing of `(comm, minter)` exists on `b`: no epoch, no
    /// self-retention, no member grant, no object, nothing dirty to emit.
    async fn nothing_stored<B>(b: &B, comm: &str, minter: &str, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        assert!(
            b.community_dek_epochs(comm, minter)
                .await
                .unwrap()
                .is_empty(),
            "{tag}: a refused write mints no epoch"
        );
        assert!(
            b.community_dek_get_self_retention(comm, minter, 0)
                .await
                .unwrap()
                .is_none(),
            "{tag}: a refused write leaves no self-retention"
        );
        assert!(
            b.community_dek_member_grant_recipients(comm, minter, 0)
                .await
                .unwrap()
                .is_empty(),
            "{tag}: a refused write leaves no member grant"
        );
        assert_eq!(
            b.community_dek_epoch_object_count(comm, minter, 0)
                .await
                .unwrap(),
            0,
            "{tag}: a refused write stores no object"
        );
        assert!(
            !b.community_dek_communities()
                .await
                .unwrap()
                .iter()
                .any(|c| c == comm),
            "{tag}: a refused write leaves no epoch pointer for the room"
        );
    }

    /// I4331 — refused by name, nothing stored; then owned, it seals.
    pub async fn exercise_i4331<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let n = node_as(b, &format!("i4331-n-{run}"), NODE).await;
        let other = node_as(b, &format!("i4331-o-{run}"), NODE).await;
        let comm = e2::kid(&format!("{tag}-i4331-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-i4331-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-i4331-bob-{run}"));
        // bob's device `other` is keyed and owned: the room IS readable by
        // someone, so the refusal is about the author, not readable_by_nobody.
        seed_community_everywhere(&[&other], &comm, &[(&alice, None), (&bob, Some(&other))]).await;
        // LEAD-fix1 — the room's DERIVED id, once founded (pass 10).
        let comm = e2::room_id(&comm);

        let err = encrypt_and_cascade_community(b, &comm, b"unopenable", None, Some(&n.key))
            .await
            .expect_err("I4331: an author with no wrap target is refused");
        match &err {
            BlobError::InvalidArgument(m) => assert!(
                m.starts_with(WRITE_AUTHOR_HAS_NO_WRAP_TARGET),
                "{tag} I4331: refused by name, got {m}"
            ),
            e => panic!("{tag} I4331: the InvalidArgument arm, got {e:?}"),
        }
        assert_eq!(
            err.kind(),
            "blob_invalid_argument",
            "{tag} I4331: the arm's kind"
        );
        nothing_stored(b, &comm, &n.key, &format!("{tag} I4331")).await;

        // The same author as alice's owned, keyed device: it seals.
        place_device(b, &alice, &n.key, &n.key, LAPTOP, Some(n.kem.clone())).await;
        let sealed = encrypt_and_cascade_community(b, &comm, b"openable", None, Some(&n.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I4331: the owned author seals: {e}"));
        assert!(
            sealed.granted.contains(&n.key),
            "{tag} I4331: the author is granted"
        );
        assert_eq!(
            b.community_dek_epoch_object_count(&comm, &n.key, sealed.epoch)
                .await
                .unwrap(),
            1,
            "{tag} I4331: exactly the one object the accepted write stored"
        );
    }

    /// I4332 — an author with a keyed occurrence seals and opens it.
    pub async fn exercise_i4332<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-i4332-comm-{run}");
        let alice = format!("{tag}-i4332-alice-{run}");
        let alice_occ = format!("{tag}-i4332-alice-occ-{run}");
        seed_community(b, &comm, &[(&alice, &alice_occ)]).await;
        let (comm, alice, alice_occ) = (id_of(&comm), id_of(&alice), id_of(&alice_occ));
        let sealed = encrypt_and_cascade_community(b, &comm, b"mine", None, Some(&alice))
            .await
            .unwrap_or_else(|e| panic!("{tag} I4332: a keyed author seals: {e}"));
        assert_eq!(sealed.granted, vec![alice_occ.clone()], "{tag} I4332");
        assert_eq!(
            read_any_for_viewer(b, &sealed.at_rest_sha256, &alice_occ, None)
                .await
                .unwrap_or_else(|e| panic!("{tag} I4332: the author's occurrence opens it: {e}")),
            b"mine".to_vec(),
            "{tag} I4332"
        );
    }

    /// I4333 — an owned node (two-voice binding + keyed self pair) seals and
    /// reads.
    pub async fn exercise_i4333<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let n = node_as(b, &format!("i4333-n-{run}"), NODE).await;
        let comm = e2::kid(&format!("{tag}-i4333-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-i4333-alice-{run}"));
        seed_community_everywhere(&[&n], &comm, &[(&alice, Some(&n))]).await;
        // LEAD-fix1 — the room's DERIVED id, once founded (pass 10).
        let comm = e2::room_id(&comm);
        let sealed = encrypt_and_cascade_community(b, &comm, b"the node's", None, Some(&n.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I4333: the owned node seals: {e}"));
        assert_eq!(sealed.granted, vec![n.key.clone()], "{tag} I4333");
        assert_eq!(
            read_any_for_viewer(b, &sealed.at_rest_sha256, &n.key, None)
                .await
                .unwrap_or_else(|e| panic!("{tag} I4333: the node opens it: {e}")),
            b"the node's".to_vec(),
            "{tag} I4333"
        );
    }

    /// I4334 — the author has a target, another member none: sealed, that
    /// member excluded with its reason.
    pub async fn exercise_i4334<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let n = node_as(b, &format!("i4334-n-{run}"), NODE).await;
        let bare = node_as(b, &format!("i4334-d-{run}"), NODE).await;
        let comm = e2::kid(&format!("{tag}-i4334-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-i4334-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-i4334-bob-{run}"));
        seed_community_everywhere(&[&n], &comm, &[(&alice, Some(&n)), (&bob, None)]).await;
        // LEAD-fix1 — the room's DERIVED id, once founded (pass 10).
        let comm = e2::room_id(&comm);
        // bob's one device carries no content-KEM keys.
        place_device(b, &bob, &bare.key, &bare.key, LAPTOP, None).await;
        let sealed = encrypt_and_cascade_community(b, &comm, b"for alice", None, Some(&n.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I4334: the author has a target: sealed: {e}"));
        assert_eq!(sealed.granted, vec![n.key.clone()], "{tag} I4334");
        assert_eq!(
            sealed.excluded,
            vec![bare.key.clone()],
            "{tag} I4334: the bare device"
        );
        assert_eq!(
            sealed.roster.excluded,
            vec![bob.clone()],
            "{tag} I4334: the member"
        );
        assert!(!sealed.readable_by_nobody(), "{tag} I4334");
        assert!(
            !b.community_dek_has_member_grant(&comm, &n.key, sealed.epoch, &bare.key)
                .await
                .unwrap(),
            "{tag} I4334: the excluded device holds no grant"
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
    async fn i4331_an_author_with_no_wrap_target_is_refused_sqlite() {
        exercise_i4331(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4332_a_keyed_author_seals_sqlite() {
        exercise_i4332(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4333_an_owned_node_author_seals_and_reads_sqlite() {
        exercise_i4333(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4334_a_keyless_member_is_excluded_not_refused_sqlite() {
        exercise_i4334(&fresh().await, "sqlite").await;
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

    #[tokio::test]
    async fn i4331_an_author_with_no_wrap_target_is_refused_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        exercise_i4331(&b, "postgres").await;
    }

    #[tokio::test]
    async fn i4332_a_keyed_author_seals_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        exercise_i4332(&b, "postgres").await;
    }

    #[tokio::test]
    async fn i4333_an_owned_node_author_seals_and_reads_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        exercise_i4333(&b, "postgres").await;
    }

    #[tokio::test]
    async fn i4334_a_keyless_member_is_excluded_not_refused_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        exercise_i4334(&b, "postgres").await;
    }
}
