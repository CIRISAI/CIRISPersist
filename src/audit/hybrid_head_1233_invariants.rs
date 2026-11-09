//! v61.1.0 (CIRISPersist#1233, CC 5.3.1 / CC 5.3.2.4.3.1) — **I1564–I1566:
//! the audit gate is the hybrid-signed head.**
//!
//! An `AuditEntry` is a leaf and its Ed25519 is an inner signature; what
//! authenticates it across a node boundary is inclusion under a signed tree
//! head, so the head must carry its ML-DSA-65 half (CC's reading on
//! CIRISPersist#1233, item 2).
//!
//! `HybridSignature` makes the half structurally required — a blob with the
//! `pqc` member REMOVED does not decode — but an EMPTY or wrong-shaped half,
//! another PQC algorithm, or `mode: ClassicalOnly` all decode. These
//! witnesses offer each of those and expect a refusal:
//!
//! - **I1564** `store_sth` refuses every head without its ML-DSA-65 half and
//!   writes nothing; a genuine hybrid head stores (the control).
//! - **I1565** a STORED head without its half is refused where it is served:
//!   `latest_sth` (the half removed from the blob, and the half emptied), and
//!   `AuditService::current_sth` above it, the read the trust-grant inclusion
//!   proof and `audit_chain_proof` serve from. The refusal does not fall back
//!   to the older genuine head: refusal, not absence.
//! - **I1566** `verify_audit_sth` verifies a genuine head against its pinned
//!   signer, and refuses the same head with its half emptied, with
//!   `mode: ClassicalOnly`, with a corrupted (right-length) ML-DSA-65
//!   signature, and against a different pinned signer (the gate asks about
//!   the signer the verifier pinned, not the key the head names).
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
    use ciris_crypto::{PqcAlgorithm, SignatureMode};
    use ciris_verify_core::transparency::{SignedTreeHead, TransparencyStore};

    /// The pinned signer every genuine head here is signed by.
    pub(crate) const SIGNER: &str = "i1566-audit-sth-signer";

    /// A genuine audit head for `log_id` at `tree_size`, hybrid-signed by
    /// [`SIGNER`] through `LocalSigner::sign_hybrid` (the production signer
    /// the Merkle hook uses), with the signer's (Ed25519, ML-DSA-65) pubkeys
    /// as base64 — the pins a verifier holds.
    pub(crate) async fn genuine_head(
        log_id: &str,
        tree_size: u64,
    ) -> (SignedTreeHead, String, String) {
        let signer = crate::federation::tier_ingest::test_support::local_signer(SIGNER);
        let timestamp = crate::audit::verify::truncate_to_micros(chrono::Utc::now());
        let root_hash = [0x5Au8; 32];
        let bytes = SignedTreeHead::signing_bytes(log_id, tree_size, &root_hash, timestamp);
        let signature = signer.sign_hybrid(&bytes).await.expect("sign_hybrid");
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

    /// Every way a head can decode yet lack its ML-DSA-65 half.
    pub(crate) fn without_the_pqc_half(h: &SignedTreeHead) -> Vec<(&'static str, SignedTreeHead)> {
        let mut out = Vec::new();
        let mut v = h.clone();
        v.signature.pqc.signature = Vec::new();
        out.push(("ML-DSA-65 signature emptied", v));
        let mut v = h.clone();
        v.signature.pqc.public_key = Vec::new();
        out.push(("ML-DSA-65 public key emptied", v));
        let mut v = h.clone();
        v.signature.pqc.signature = Vec::new();
        v.signature.pqc.public_key = Vec::new();
        out.push(("both ML-DSA-65 fields emptied", v));
        let mut v = h.clone();
        v.signature.pqc.signature.pop();
        out.push(("ML-DSA-65 signature one byte short", v));
        let mut v = h.clone();
        v.signature.mode = SignatureMode::ClassicalOnly;
        out.push(("mode ClassicalOnly", v));
        let mut v = h.clone();
        v.signature.pqc.algorithm = PqcAlgorithm::MlDsa44;
        out.push(("PQC algorithm ML-DSA-44", v));
        out
    }

    /// The JSON `signature_blob` of `h` with the `pqc` member REMOVED — the
    /// shape `HybridSignature` cannot represent, reachable only as stored
    /// bytes.
    pub(crate) fn blob_with_the_pqc_half_removed(h: &SignedTreeHead) -> Vec<u8> {
        let mut v = serde_json::to_value(&h.signature).expect("signature serializes");
        let removed = v
            .as_object_mut()
            .expect("HybridSignature serializes as an object")
            .remove("pqc");
        assert!(removed.is_some(), "the blob carried a pqc member to remove");
        assert!(
            serde_json::from_value::<ciris_crypto::HybridSignature>(v.clone()).is_err(),
            "HybridSignature cannot represent a missing PQC half"
        );
        serde_json::to_vec(&v).expect("blob")
    }

    /// The JSON `signature_blob` of `h` with the ML-DSA-65 half EMPTIED.
    pub(crate) fn blob_with_the_pqc_half_emptied(h: &SignedTreeHead) -> Vec<u8> {
        let mut sig = h.signature.clone();
        sig.pqc.signature = Vec::new();
        sig.pqc.public_key = Vec::new();
        serde_json::to_vec(&sig).expect("blob")
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
                "I1564 {who}: {what} is refused as not hybrid: {err}"
            );
            assert!(
                store.latest_sth().expect("latest_sth").is_none(),
                "I1564 {who}: the refused head ({what}) wrote nothing"
            );
        }
        store
            .store_sth(genuine)
            .unwrap_or_else(|e| panic!("I1564 {who}: the genuine hybrid head stores: {e}"));
        let served = store
            .latest_sth()
            .expect("I1564: the genuine head is served")
            .expect("I1564: a head is present");
        assert_eq!(served.tree_size, genuine.tree_size, "I1564 {who}");
        assert_eq!(
            served.signature.pqc.signature, genuine.signature.pqc.signature,
            "I1564 {who}: the ML-DSA-65 half round-trips"
        );
    }

    /// I1565 — a STORED head without its half is refused at `latest_sth`.
    /// `genuine` (tree_size 1) is stored through the door first; `inject`
    /// then writes a row at the given tree size around the door. The newest
    /// row is the one served, so each malformed row must be REFUSED, not
    /// skipped in favour of the genuine head below it.
    pub(crate) fn i1565_serve_refuses_a_stored_head_without_its_pqc_half(
        store: &dyn TransparencyStore<AuditLeaf>,
        inject: &dyn Fn(i64, Vec<u8>),
        genuine: &SignedTreeHead,
        who: &str,
    ) {
        assert_eq!(
            genuine.tree_size, 1,
            "I1565 fixture: the genuine head is at size 1"
        );
        store
            .store_sth(genuine)
            .expect("I1565: the genuine head stores");
        assert!(
            store.latest_sth().expect("I1565: control").is_some(),
            "I1565 {who}: the genuine head is served"
        );

        inject(2, blob_with_the_pqc_half_removed(genuine));
        let Err(err) = store.latest_sth() else {
            panic!("I1565 {who}: a stored head with its pqc half REMOVED is refused");
        };
        assert!(
            err.to_string().contains("sth signature deserialize"),
            "I1565 {who}: the removed half fails to decode: {err}"
        );

        inject(3, blob_with_the_pqc_half_emptied(genuine));
        let Err(err) = store.latest_sth() else {
            panic!("I1565 {who}: a stored head with its pqc half EMPTIED is refused");
        };
        assert!(
            err.to_string().contains(AUDIT_STH_NOT_HYBRID),
            "I1565 {who}: the emptied half is refused as not hybrid: {err}"
        );
    }

    /// I1565, the service leg — `AuditService::current_sth` (what
    /// `trust_grant_inclusion_proof` and `audit_chain_proof` serve) carries
    /// the refusal up as an error, never `Ok(None)` and never the head.
    pub(crate) fn assert_current_sth_refused(
        got: Result<Option<SignedTreeHead>, crate::audit::Error>,
        who: &str,
    ) {
        match got {
            Err(e) => assert!(
                e.to_string().contains(AUDIT_STH_NOT_HYBRID),
                "I1565 {who}: current_sth refuses with the token: {e}"
            ),
            Ok(other) => panic!("I1565 {who}: current_sth must refuse, served {other:?}"),
        }
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
                "I1566: {what} is refused as not hybrid, before crypto: {err}"
            );
        }

        let mut forged = genuine.clone();
        forged.signature.pqc.signature[0] ^= 0xFF;
        let err = verify_audit_sth(&forged, &ed_pk, &pqc_pk)
            .expect_err("I1566: a corrupted ML-DSA-65 half must not verify");
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
            let store: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(SqliteMerkleStore::new(
                backend.conn_handle(),
                tokio::runtime::Handle::current(),
                t,
            ));
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
            let (genuine, _, _) = b::genuine_head(&log_id_for_tenant(&t), 1).await;
            let conn = backend.conn_handle();
            let store: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(SqliteMerkleStore::new(
                conn.clone(),
                tokio::runtime::Handle::current(),
                t.clone(),
            ));
            let t_inject = t.clone();
            tokio::task::spawn_blocking(move || {
                let inject = move |size: i64, blob: Vec<u8>| {
                    b::inject_sth_row_sqlite(&conn, &t_inject, size, &blob);
                };
                b::i1565_serve_refuses_a_stored_head_without_its_pqc_half(
                    store.as_ref(),
                    &inject,
                    &genuine,
                    "sqlite",
                );
            })
            .await
            .expect("I1565 sqlite");
            let audit = crate::audit::sqlite::SqliteAuditBackend::new(backend.conn_handle());
            b::assert_current_sth_refused(audit.current_sth(&t).await, "sqlite");
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::*;
        use crate::audit::merkle_store::{log_id_for_tenant, PgMerkleStore};
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;

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
            let store: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(PgMerkleStore::new(
                backend.clone(),
                tokio::runtime::Handle::current(),
                t,
            ));
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
            let (genuine, _, _) = b::genuine_head(&log_id_for_tenant(&t), 1).await;
            let store: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(PgMerkleStore::new(
                backend.clone(),
                tokio::runtime::Handle::current(),
                t.clone(),
            ));
            let handle = tokio::runtime::Handle::current();
            let backend_inject = backend.clone();
            let t_inject = t.clone();
            tokio::task::spawn_blocking(move || {
                let inject = move |size: i64, blob: Vec<u8>| {
                    handle.block_on(b::inject_sth_row_pg(
                        &backend_inject,
                        &t_inject,
                        size,
                        &blob,
                    ));
                };
                b::i1565_serve_refuses_a_stored_head_without_its_pqc_half(
                    store.as_ref(),
                    &inject,
                    &genuine,
                    "postgres",
                );
            })
            .await
            .expect("I1565 postgres");
            b::assert_current_sth_refused(backend.current_sth(&t).await, "postgres");
            eprintln!("i1565 postgres: RAN");
        }
    }
}
