//! v61.1.0 (CIRISPersist#1233, CC 5.3.1 / CC 5.3.2.4.3.1) — **I1564–I1566:
//! the audit gate is the composite-signed head.**
//!
//! An `AuditEntry` is a leaf and its Ed25519 is an inner signature; what
//! authenticates it across a node boundary is inclusion under a signed tree
//! head, so the head must carry its ML-DSA-65 half (CC's reading on
//! CIRISPersist#1233, item 2).
//!
//! v62.0.0 (slice D, CIRISVerify 23, CC rc20 "nothing carries"): the head's
//! signature is the CC 2.6.1.7 composite, which carries its ML-DSA-65 half by
//! construction; a v62 node reads ONLY composites. These witnesses offer the
//! heads that are not one and expect a refusal:
//!
//! - **I1564** `store_sth` refuses every head that is not a composite (the
//!   earlier, bound-hybrid form of v61; a composite one byte short; the
//!   ML-DSA-65 half alone; no bytes) and writes nothing; a genuine composite
//!   head stores and round-trips (the control).
//! - **I1565** a STORED earlier-form head (the row a v61 node left) is
//!   REFUSED by name on read (`sth_signature_earlier_form`), by
//!   `latest_sth` and by `AuditService::current_sth` above it: never served,
//!   and not skipped in favour of the genuine head below it
//!   (`TODO(archive-ruling)`: the pre-v62 store's fate is an open operator
//!   ruling). A stored blob in no form is refused too: refusal, not absence.
//! - **I1566** `verify_audit_sth` verifies a genuine head against its pinned
//!   signer, and refuses every non-composite head as not composite, a
//!   corrupted composite, and the genuine head against a different pinned
//!   signer (the gate asks about the signer the verifier pinned).
//!
//! I1564 and I1565 run on sqlite and postgres; I1566 is backend-free.
//! `audit_chain_proof`'s own leg is `ffi::pyo3`'s I1567.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::audit::merkle_leaf::AuditLeaf;
    use crate::audit::merkle_store::{
        verify_audit_sth, AUDIT_STH_NOT_HYBRID, AUDIT_STH_SIGNATURE_INVALID,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_verify_core::transparency::{SignedTreeHead, TransparencyStore};

    /// The pinned signer every genuine head here is signed by.
    pub(crate) const SIGNER: &str = "i1566-audit-sth-signer";

    /// A genuine audit head for `log_id` at `tree_size`, composite-signed by
    /// [`SIGNER`] through `sth_form::sign_sth` (the production signer the
    /// Merkle hook uses), with the signer's (Ed25519, ML-DSA-65) pubkeys as
    /// base64 — the pins a verifier holds.
    pub(crate) async fn genuine_head(
        log_id: &str,
        tree_size: u64,
    ) -> (SignedTreeHead, String, String) {
        let signer = crate::federation::tier_ingest::test_support::local_signer(SIGNER);
        let timestamp = crate::audit::verify::truncate_to_micros(chrono::Utc::now());
        let root_hash = [0x5Au8; 32];
        let bytes = SignedTreeHead::signing_bytes(log_id, tree_size, &root_hash, timestamp);
        let signature = crate::federation::sth_form::sign_sth(&signer, &bytes)
            .await
            .expect("sign_sth (composite)");
        let ed_pk = B64.encode(signer.ed25519_public_key_bytes());
        let pqc_pk = signer
            .pqc_public_key_b64()
            .await
            .expect("pqc pubkey")
            .expect("the fixture signer carries a PQC key");
        let sth = SignedTreeHead {
            log_id: log_id.to_owned(),
            tree_size,
            root_hash,
            timestamp,
            signature,
            witness_signatures: Vec::new(),
        };
        (sth, ed_pk, pqc_pk)
    }

    /// A v61 (earlier-form, bound-hybrid) signature over `h`'s bytes, from
    /// fixed test seeds: the bytes a pre-v62 `signature_blob` holds.
    pub(crate) fn earlier_form_signature(h: &SignedTreeHead) -> Vec<u8> {
        crate::federation::sth_form::test_support::earlier_bytes(
            [0x62; 32],
            [0x61; 32],
            &h.signing_bytes_of(),
        )
    }

    /// Every head that is not a CC 2.6.1.7 composite.
    pub(crate) fn without_the_pqc_half(h: &SignedTreeHead) -> Vec<(&'static str, SignedTreeHead)> {
        let with = |sig: Vec<u8>| {
            let mut v = h.clone();
            v.signature = sig;
            v
        };
        let mut short = h.signature.clone();
        short.pop();
        vec![
            (
                "the earlier (v61 bound-hybrid) form",
                with(earlier_form_signature(h)),
            ),
            ("a composite one byte short", with(short)),
            (
                "the ML-DSA-65 half alone",
                with(h.signature[..3309].to_vec()),
            ),
            ("no signature bytes", with(Vec::new())),
            (
                "a JSON object that is no signature",
                with(b"{\"pqc\":null}".to_vec()),
            ),
        ]
    }

    /// A stored blob in no form (a composite truncated) — malformed.
    pub(crate) fn blob_with_the_pqc_half_removed(h: &SignedTreeHead) -> Vec<u8> {
        h.signature[..h.signature.len() - 1].to_vec()
    }

    /// The row a v61 node left: an earlier-form (bound-hybrid) blob.
    pub(crate) fn blob_with_the_pqc_half_emptied(h: &SignedTreeHead) -> Vec<u8> {
        earlier_form_signature(h)
    }

    /// Insert a `merkle_sth_log` row on sqlite, bypassing `store_sth` (the
    /// row a node upgraded from an older build, or a tampered file, holds).
    #[cfg(feature = "sqlite")]
    pub(crate) fn inject_sth_row_sqlite(
        conn: &std::sync::Arc<parking_lot::Mutex<rusqlite::Connection>>,
        tenant: &str,
        tree_size: i64,
        blob: &[u8],
    ) {
        conn.lock()
            .execute(
                "INSERT INTO merkle_sth_log \
                 (tenant_id, tree_size, root_hash, signer_key_id, signature_blob) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![tenant, tree_size, vec![0x5Au8; 32], "i1565", blob],
            )
            .expect("inject sth row (sqlite)");
    }

    /// Insert a `merkle_sth_log` row on postgres, bypassing `store_sth`.
    #[cfg(feature = "postgres")]
    pub(crate) async fn inject_sth_row_pg(
        backend: &crate::store::postgres::PostgresBackend,
        tenant: &str,
        tree_size: i64,
        blob: &[u8],
    ) {
        let client = backend.checkout().await.expect("checkout");
        client
            .execute(
                "INSERT INTO cirislens.merkle_sth_log \
                 (tenant_id, tree_size, root_hash, signer_key_id, signature_blob) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &tenant,
                    &tree_size,
                    &vec![0x5Au8; 32],
                    &"i1565",
                    &blob.to_vec(),
                ],
            )
            .await
            .expect("inject sth row (postgres)");
    }

    /// I1564 — `store_sth` refuses a head without its ML-DSA-65 half and
    /// writes nothing; the genuine head stores. Sync: the store bridges with
    /// `block_on`, so the caller runs this off the runtime's workers.
    pub(crate) fn i1564_store_refuses_a_head_without_its_pqc_half(
        store: &dyn TransparencyStore<AuditLeaf>,
        genuine: &SignedTreeHead,
        who: &str,
    ) {
        for (what, bad) in without_the_pqc_half(genuine) {
            let Err(err) = store.store_sth(&bad) else {
                panic!("I1564 {who}: a head with {what} must be refused");
            };
            assert!(
                err.to_string().contains(AUDIT_STH_NOT_HYBRID),
                "I1564 {who}: {what} is refused as not composite: {err}"
            );
            assert!(
                store.latest_sth().expect("latest_sth").is_none(),
                "I1564 {who}: the refused head ({what}) wrote nothing"
            );
        }
        store
            .store_sth(genuine)
            .unwrap_or_else(|e| panic!("I1564 {who}: the genuine composite head stores: {e}"));
        let served = store
            .latest_sth()
            .expect("I1564: the genuine head is served")
            .expect("I1564: a head is present");
        assert_eq!(served.tree_size, genuine.tree_size, "I1564 {who}");
        assert_eq!(
            served.signature, genuine.signature,
            "I1564 {who}: the composite round-trips"
        );
    }

    /// I1565 — a STORED head without its half is served as itself and
    /// refused by `verify_audit_sth`. `genuine` (tree_size 1) is stored
    /// through the door first and verifies against its pins (the control);
    /// `inject` then writes a row at tree size 2 around the door, with the
    /// ML-DSA-65 half emptied. The newest row is the one served, and it is
    /// served AS ITSELF: not refused, and not skipped in favour of the
    /// genuine head below it.
    pub(crate) fn i1565_a_stored_head_without_its_pqc_half_is_served_and_refused_by_verify(
        store: &dyn TransparencyStore<AuditLeaf>,
        inject: &dyn Fn(i64, Vec<u8>),
        genuine: &SignedTreeHead,
        ed_pk: &str,
        pqc_pk: &str,
        who: &str,
    ) {
        assert_eq!(
            genuine.tree_size, 1,
            "I1565 fixture: the genuine head is at size 1"
        );
        store
            .store_sth(genuine)
            .expect("I1565: the genuine head stores");
        let served = store
            .latest_sth()
            .expect("I1565: control")
            .expect("I1565: the genuine head is present");
        verify_audit_sth(&served, ed_pk, pqc_pk).unwrap_or_else(|e| {
            panic!("I1565 {who}: the served genuine head verifies against its pins: {e}")
        });

        inject(2, blob_with_the_pqc_half_emptied(genuine));
        let Err(err) = store.latest_sth() else {
            panic!("I1565 {who}: a stored earlier-form head must be refused, never served");
        };
        assert_refused_as_earlier(&err.to_string(), who);
    }

    /// The refusal names the earlier form.
    fn assert_refused_as_earlier(err: &str, who: &str) {
        assert!(
            err.contains(crate::federation::sth_form::STH_SIGNATURE_EARLIER_FORM),
            "I1565 {who}: the stored earlier-form head is refused by name: {err}"
        );
    }

    /// I1565, the service leg — `AuditService::current_sth` (what
    /// `trust_grant_inclusion_proof` and `audit_chain_proof` serve) refuses
    /// the same stored earlier-form head by name.
    pub(crate) fn assert_current_sth_serves_the_stored_head(
        got: Result<Option<SignedTreeHead>, crate::audit::Error>,
        who: &str,
    ) {
        match got {
            Err(e) => assert_refused_as_earlier(&e.to_string(), who),
            other => {
                panic!("I1565 {who}: current_sth must refuse the earlier-form head: {other:?}")
            }
        }
    }

    /// I1565, the malformed leg — a stored blob in no form (a truncated
    /// composite) is refused by `latest_sth` (malformed is a refusal, not
    /// absence; and not the older head below it). Injected at tree size 3.
    pub(crate) fn i1565_a_stored_head_that_does_not_decode_is_refused(
        store: &dyn TransparencyStore<AuditLeaf>,
        inject: &dyn Fn(i64, Vec<u8>),
        genuine: &SignedTreeHead,
        who: &str,
    ) {
        inject(3, blob_with_the_pqc_half_removed(genuine));
        let Err(err) = store.latest_sth() else {
            panic!("I1565 {who}: a stored head with its pqc half REMOVED is refused");
        };
        assert!(
            err.to_string().contains("sth signature deserialize")
                && err
                    .to_string()
                    .contains(crate::federation::sth_form::STH_SIGNATURE_UNRECOGNIZED),
            "I1565 {who}: the malformed blob is refused: {err}"
        );
    }

    /// I1566 — `verify_audit_sth`, hybrid-Strict against the pinned signer.
    pub(crate) async fn i1566_verify_refuses_a_head_without_its_pqc_half() {
        let (genuine, ed_pk, pqc_pk) = genuine_head("tenant:i1566", 7).await;
        verify_audit_sth(&genuine, &ed_pk, &pqc_pk)
            .expect("I1566: the genuine head verifies against its pinned signer");

        for (what, bad) in without_the_pqc_half(&genuine) {
            let Err(err) = verify_audit_sth(&bad, &ed_pk, &pqc_pk) else {
                panic!("I1566: a head with {what} must not verify");
            };
            assert!(
                err.to_string().contains(AUDIT_STH_NOT_HYBRID),
                "I1566: {what} is refused as not composite, before crypto: {err}"
            );
        }

        let mut forged = genuine.clone();
        forged.signature[0] ^= 0xFF;
        let err = verify_audit_sth(&forged, &ed_pk, &pqc_pk)
            .expect_err("I1566: a corrupted composite must not verify");
        assert!(
            err.to_string().contains(AUDIT_STH_SIGNATURE_INVALID),
            "I1566: the corrupted half fails the crypto: {err}"
        );

        let other = crate::federation::tier_ingest::test_support::local_signer("i1566-other");
        let other_ed = B64.encode(other.ed25519_public_key_bytes());
        let other_pqc = other
            .pqc_public_key_b64()
            .await
            .expect("pqc pubkey")
            .expect("pqc configured");
        let err = verify_audit_sth(&genuine, &other_ed, &other_pqc)
            .expect_err("I1566: a head verifies only against ITS pinned signer");
        assert!(
            err.to_string().contains(AUDIT_STH_SIGNATURE_INVALID),
            "I1566: the wrong pinned signer is refused: {err}"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies as b;
    use crate::audit::merkle_leaf::AuditLeaf;
    use ciris_verify_core::transparency::TransparencyStore;
    use std::sync::Arc;

    fn tenant(n: &str) -> String {
        format!("i{n}-{}", uuid::Uuid::new_v4().simple())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1566_verify_audit_sth() {
        b::i1566_verify_refuses_a_head_without_its_pqc_half().await;
    }

    #[cfg(feature = "sqlite")]
    mod sqlite {
        use super::*;
        use crate::audit::merkle_store::{log_id_for_tenant, SqliteMerkleStore};
        use crate::store::Backend as _;

        async fn open() -> crate::store::sqlite::SqliteBackend {
            let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            backend.run_migrations().await.unwrap();
            backend
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i1564() {
            let backend = open().await;
            let t = tenant("1564s");
            let (genuine, _, _) = b::genuine_head(&log_id_for_tenant(&t), 1).await;
            let store: Arc<dyn TransparencyStore<AuditLeaf>> =
                Arc::new(SqliteMerkleStore::new(backend.conn_handle(), t));
            tokio::task::spawn_blocking(move || {
                b::i1564_store_refuses_a_head_without_its_pqc_half(
                    store.as_ref(),
                    &genuine,
                    "sqlite",
                );
            })
            .await
            .expect("I1564 sqlite");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i1565() {
            use crate::audit::AuditService as _;
            let backend = open().await;
            let t = tenant("1565s");
            let (genuine, ed_pk, pqc_pk) = b::genuine_head(&log_id_for_tenant(&t), 1).await;
            let conn = backend.conn_handle();
            let store: Arc<dyn TransparencyStore<AuditLeaf>> =
                Arc::new(SqliteMerkleStore::new(conn.clone(), t.clone()));
            let inject: Arc<dyn Fn(i64, Vec<u8>) + Send + Sync> = {
                let t_inject = t.clone();
                Arc::new(move |size: i64, blob: Vec<u8>| {
                    b::inject_sth_row_sqlite(&conn, &t_inject, size, &blob);
                })
            };
            {
                let (store, inject, genuine) = (store.clone(), inject.clone(), genuine.clone());
                tokio::task::spawn_blocking(move || {
                    b::i1565_a_stored_head_without_its_pqc_half_is_served_and_refused_by_verify(
                        store.as_ref(),
                        inject.as_ref(),
                        &genuine,
                        &ed_pk,
                        &pqc_pk,
                        "sqlite",
                    );
                })
                .await
                .expect("I1565 sqlite");
            }
            let audit = crate::audit::sqlite::SqliteAuditBackend::new(backend.conn_handle());
            b::assert_current_sth_serves_the_stored_head(audit.current_sth(&t).await, "sqlite");
            tokio::task::spawn_blocking(move || {
                b::i1565_a_stored_head_that_does_not_decode_is_refused(
                    store.as_ref(),
                    inject.as_ref(),
                    &genuine,
                    "sqlite",
                );
            })
            .await
            .expect("I1565 sqlite (malformed)");
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::*;
        use crate::audit::merkle_store::{log_id_for_tenant, PgMerkleStore};
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;

        /// v62.0.0 (P8) — `PgMerkleStore` is async end to end and no longer
        /// a `TransparencyStore`. The shared `b::` witnesses take the sync
        /// trait, so the TEST bridges back: each call blocks a blocking-pool
        /// thread on the store's own future. Test-only; production awaits.
        struct PgSync {
            store: PgMerkleStore,
            rt: tokio::runtime::Handle,
        }

        impl TransparencyStore<AuditLeaf> for PgSync {
            fn append(
                &self,
                e: AuditLeaf,
            ) -> Result<u64, ciris_verify_core::transparency::TransparencyError> {
                self.rt.block_on(self.store.append(e))
            }
            fn get(
                &self,
                i: u64,
            ) -> Result<Option<AuditLeaf>, ciris_verify_core::transparency::TransparencyError>
            {
                self.rt.block_on(self.store.get(i))
            }
            fn leaf_hash(
                &self,
                i: u64,
            ) -> Result<Option<[u8; 32]>, ciris_verify_core::transparency::TransparencyError>
            {
                self.rt.block_on(self.store.leaf_hash(i))
            }
            fn tree_size(&self) -> Result<u64, ciris_verify_core::transparency::TransparencyError> {
                self.rt.block_on(self.store.tree_size())
            }
            fn latest_sth(
                &self,
            ) -> Result<
                Option<ciris_verify_core::transparency::SignedTreeHead>,
                ciris_verify_core::transparency::TransparencyError,
            > {
                self.rt.block_on(self.store.latest_sth())
            }
            fn store_sth(
                &self,
                sth: &ciris_verify_core::transparency::SignedTreeHead,
            ) -> Result<(), ciris_verify_core::transparency::TransparencyError> {
                self.rt.block_on(self.store.store_sth(sth))
            }
            fn all_leaf_hashes(
                &self,
            ) -> Result<Vec<[u8; 32]>, ciris_verify_core::transparency::TransparencyError>
            {
                self.rt.block_on(self.store.all_leaf_hashes())
            }
        }

        fn pg_sync(
            backend: &Arc<PostgresBackend>,
            t: String,
        ) -> Arc<dyn TransparencyStore<AuditLeaf>> {
            Arc::new(PgSync {
                store: PgMerkleStore::new(backend.clone(), t),
                rt: tokio::runtime::Handle::current(),
            })
        }

        async fn open() -> Option<Arc<PostgresBackend>> {
            let Some(dsn) = crate::test_pg::dsn() else {
                eprintln!("1233 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                return None;
            };
            let backend = Arc::new(PostgresBackend::connect(&dsn).await.unwrap());
            backend.run_migrations().await.unwrap();
            Some(backend)
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i1564() {
            let Some(backend) = open().await else { return };
            let t = tenant("1564p");
            let (genuine, _, _) = b::genuine_head(&log_id_for_tenant(&t), 1).await;
            let store = pg_sync(&backend, t);
            tokio::task::spawn_blocking(move || {
                b::i1564_store_refuses_a_head_without_its_pqc_half(
                    store.as_ref(),
                    &genuine,
                    "postgres",
                );
            })
            .await
            .expect("I1564 postgres");
            eprintln!("i1564 postgres: RAN");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i1565() {
            use crate::audit::AuditService as _;
            let Some(backend) = open().await else { return };
            let t = tenant("1565p");
            let (genuine, ed_pk, pqc_pk) = b::genuine_head(&log_id_for_tenant(&t), 1).await;
            let store = pg_sync(&backend, t.clone());
            // Called from a blocking thread, so it may block on the runtime.
            let inject: Arc<dyn Fn(i64, Vec<u8>) + Send + Sync> = {
                let handle = tokio::runtime::Handle::current();
                let backend_inject = backend.clone();
                let t_inject = t.clone();
                Arc::new(move |size: i64, blob: Vec<u8>| {
                    handle.block_on(b::inject_sth_row_pg(
                        &backend_inject,
                        &t_inject,
                        size,
                        &blob,
                    ));
                })
            };
            {
                let (store, inject, genuine) = (store.clone(), inject.clone(), genuine.clone());
                tokio::task::spawn_blocking(move || {
                    b::i1565_a_stored_head_without_its_pqc_half_is_served_and_refused_by_verify(
                        store.as_ref(),
                        inject.as_ref(),
                        &genuine,
                        &ed_pk,
                        &pqc_pk,
                        "postgres",
                    );
                })
                .await
                .expect("I1565 postgres");
            }
            b::assert_current_sth_serves_the_stored_head(backend.current_sth(&t).await, "postgres");
            tokio::task::spawn_blocking(move || {
                b::i1565_a_stored_head_that_does_not_decode_is_refused(
                    store.as_ref(),
                    inject.as_ref(),
                    &genuine,
                    "postgres",
                );
            })
            .await
            .expect("I1565 postgres (malformed)");
            eprintln!("i1565 postgres: RAN");
        }
    }
}
