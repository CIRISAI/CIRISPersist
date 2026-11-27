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
//! - **I4350** (v62.0.0, KR-fix42; Constitution 11-24: THE ALLOW LIST IS PER
//!   KEY) — a device's list is stated for EACH key it holds, by key match:
//!   alice's owned node N (the BYTES) and her roster key K on that device
//!   (the WRAP). With no list: N holds the room's bytes and both keys are
//!   wrapped. A list for N alone: N holds no bytes, and the wrap still goes
//!   to K. Lists for both: neither. Every device of alice kept off: alice is
//!   `absent` from the room's fan-out (bob still wrapped), and alice's own
//!   write is refused `write_author_has_no_wrap_target`.

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

    /// I4350 — the allow list is per key: the node key withholds the bytes,
    /// the roster key the wrap; every device kept off is `absent`, and the
    /// author is refused.
    pub async fn exercise_i4350<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::lifecycle_support::seat_minter;
        use crate::federation::community_dek::orchestrate::room_targets;
        use crate::federation::replication_audience_invariants::bodies::{entries, grant, put};
        use crate::federation::types::cohort_scope::COMMUNITY;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm_s = format!("{tag}-i4350-comm-{run}");
        let elsewhere = format!("{tag}-i4350-elsewhere-{run}");
        let alice_s = format!("{tag}-i4350-alice-{run}");
        let alice_occ_s = format!("{tag}-i4350-alice-occ-{run}");
        let bob_s = format!("{tag}-i4350-bob-{run}");
        let bob_occ_s = format!("{tag}-i4350-bob-occ-{run}");
        seed_community(
            b,
            &comm_s,
            &[(&alice_s, &alice_occ_s), (&bob_s, &bob_occ_s)],
        )
        .await;
        // alice's owned, keyed node on the same device (a two-voice owner
        // binding and the node's own keyed self pair).
        let (_signer, node) = seat_minter(b, &alice_s, &format!("i4350-n-{run}")).await;
        let (comm, alice, alice_occ, bob_occ) = (
            id_of(&comm_s),
            id_of(&alice_s),
            id_of(&alice_occ_s),
            id_of(&bob_occ_s),
        );
        let dir: &dyn FederationDirectory = b;
        let (comm_r, alice_r, node_r) = (comm.as_str(), alice.as_str(), node.as_str());
        let bytes_to_node = move || async move {
            crate::federation::replication::hold::is_audience(
                dir,
                COMMUNITY,
                Some(comm_r),
                alice_r,
                |_| false,
                node_r,
            )
            .await
            .expect("the hold door's audience read")
        };
        let wrap = move || async move {
            room_targets(b, comm_r)
                .await
                .unwrap_or_else(|e| panic!("{tag} I4350: the room's wrap targets: {e}"))
                .1
        };
        // A list that keeps THIS room off: it names another room only.
        let kept_off = entries(&[(COMMUNITY, elsewhere.as_str())]);

        // Control: no list.
        let r = wrap().await;
        assert!(
            bytes_to_node().await,
            "{tag} I4350 control: with no list the node holds the room's bytes"
        );
        assert!(
            r.granted.contains(&alice_occ) && r.granted.contains(&node),
            "{tag} I4350 control: both keys are wrapped: {r:?}"
        );

        // (1) The node key's list alone.
        put(
            dir,
            &grant(&alice_s, Some(node.as_str()), Some(kept_off.clone())),
        )
        .await
        .expect("I4350: the owner's list for the node key is admitted");
        assert!(
            !bytes_to_node().await,
            "{tag} I4350 (1): the node key's list withholds the bytes"
        );
        let r = wrap().await;
        assert!(
            r.granted.contains(&alice_occ),
            "{tag} I4350 (1): the wrap still goes to the roster key: {r:?}"
        );
        assert!(
            !r.granted.contains(&node),
            "{tag} I4350 (1): the node key is no wrap target either: {r:?}"
        );

        // (2) Both keys' lists.
        put(
            dir,
            &grant(&alice_s, Some(alice_occ.as_str()), Some(kept_off)),
        )
        .await
        .expect("I4350: the owner's list for the roster key is admitted");
        assert!(
            !bytes_to_node().await,
            "{tag} I4350 (2): no bytes to the node"
        );
        let r = wrap().await;
        assert!(
            !r.granted.contains(&alice_occ) && !r.granted.contains(&node),
            "{tag} I4350 (2): neither key is wrapped: {r:?}"
        );

        // (3) Every device of alice kept off: absent, not excluded; bob is
        // still wrapped; alice's own write is refused.
        assert!(
            r.roster.absent.contains(&alice) && !r.roster.excluded.contains(&alice),
            "{tag} I4350 (3): a member every device of whom is kept off is absent: {r:?}"
        );
        assert!(
            r.granted.contains(&bob_occ),
            "{tag} I4350 (3): another member is still wrapped: {r:?}"
        );
        let err = encrypt_and_cascade_community(b, &comm, b"kept off", None, Some(&alice))
            .await
            .expect_err("I4350 (3): an author whose every device is kept off is refused");
        match &err {
            BlobError::InvalidArgument(m) => assert!(
                m.starts_with(WRITE_AUTHOR_HAS_NO_WRAP_TARGET),
                "{tag} I4350 (3): refused by name, got {m}"
            ),
            e => panic!("{tag} I4350 (3): the InvalidArgument arm, got {e:?}"),
        }
        nothing_stored(b, &comm, &alice, &format!("{tag} I4350 (3)")).await;
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

    #[tokio::test]
    async fn i4350_the_allow_list_is_per_key_sqlite() {
        exercise_i4350(&fresh().await, "sqlite").await;
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

    #[tokio::test]
    async fn i4350_the_allow_list_is_per_key_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        exercise_i4350(&b, "postgres").await;
    }
}
