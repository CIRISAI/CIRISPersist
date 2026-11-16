//! v59.0.0 (sealed-transport floor, operator ruling 2026-10-19; CC 5.3.3.5 E1
//! option (i)) — **I1144–I1147: the framed key plane is retired.**
//!
//! v58 restored the framed outbound key-plane listings for pre-v58 peers
//! (compat reads). Every RNS byte now rides a per-link hybrid seal with no
//! classical fallback, so an unsealed old peer is unreachable, and v59 drops
//! the compat reads: the key plane replicates only as rows.
//!
//! - **I1144 (one-way migration at first open, sqlite + postgres)** — a store
//!   migrated only through V195 (the v57 schema) holding a key record, a key
//!   revocation, two signed occurrences, a route and a FRAMED occurrence
//!   revocation is migrated forward: with no write in between, every key, key
//!   revocation and occurrence has its key-plane row (the v58 lazy rehome,
//!   eager), no identity loses a key or a route, the framed revocation is kept
//!   as a legacy projection row (V200) and the occurrence it names stays
//!   revoked, and the rehome reports what it counted. Memory holds no v57
//!   store, so this leg is SQL only.
//! - **I1145 (inbound framed objects are refused, every backend)** — the
//!   framed occurrence-revocation record read and every framed wire-index
//!   reload refuse or resolve nothing, typed `federation_envelope_kind_retired`
//!   where a door answers.
//! - **I1146 (the capsule's framed inbound ops are refused)** —
//!   `ApplyReplicatedKeyRecord` and `PutIdentityOccurrenceRevocation` answer
//!   `federation_envelope_kind_retired: key` /
//!   `…: identity_occurrence_revocation` (in `ffi::directory_capsule`'s tests,
//!   which own the capsule fixture).
//! - **I1148 (a pre-door revocation evicts no genesis key, sqlite +
//!   postgres)** — a V195 store holding another key's framed revocation of
//!   the self pair `(F, F)` migrates forward with `F` still on the roster and
//!   acting as the self; the same act through the two-path door evicts it.
//! - **I1150 (the replication path takes in no framed object, every
//!   backend)** — a peer's advertisement of a hash of each retired kind is
//!   refused at the wire-index ingest (`insert_known_wire_hash`); the
//!   authoring doors `put_identity_occurrence` / `put_revocation` still land
//!   rows. (The capsule's `ApplyReplicatedKeyRecord` and
//!   `PutIdentityOccurrenceRevocation` are I1146's.)
//! - **I1147 (the compat reads stay gone, from disk)** — no trait method,
//!   backend impl, capsule op, Python method or stub carries a retired listing
//!   or the framed revocation door (comments stripped); the v58 I1123 gate
//!   (no hybrid-pending revocation path) rides along.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::types::IdentityOccurrenceRevocation;
    use crate::federation::types::Revocation;
    use crate::federation::{Error, FederationDirectory};

    fn ms(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t.timestamp_millis()).unwrap()
    }

    /// A self-revocation of `subject`, hybrid-sealed by it.
    pub(crate) fn revocation(subject: &str, at: chrono::DateTime<chrono::Utc>) -> Revocation {
        ts::seal_revocation(Revocation {
            revocation_id: uuid::Uuid::new_v4().to_string(),
            revoked_key_id: Some(subject.to_owned()),
            revoked_key_sha256_ed25519_raw: ts::subject_digest_of(subject),
            revoking_key_id: subject.to_owned(),
            reason: Some("v57 seed".to_owned()),
            revoked_at: at,
            effective_at: at,
            revocation_envelope: serde_json::json!({ "revokes": subject }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: subject.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            revoked_after: None,
            persist_row_hash: String::new(),
        })
    }

    /// What a v57 node held, by name.
    pub(crate) struct Seed {
        pub identity: String,
        pub kept: String,
        pub revoked: String,
        pub subject: String,
        /// v61 (CIRISPersist#1122) — the node key the route rides: an
        /// agent key announces no route.
        pub route_node: String,
    }

    /// The doors a V195 store still has: keys, two signed occurrences of a
    /// user-role identity (agent keys: not roster changes), a route on the
    /// kept one.
    pub(crate) async fn seed_doors<D: FederationDirectory + ?Sized>(d: &D, tag: &str) -> Seed {
        let s = Seed {
            identity: format!("v57-id-{tag}"),
            kept: format!("v57-kept-{tag}"),
            revoked: format!("v57-gone-{tag}"),
            subject: format!("v57-k-{tag}"),
            route_node: format!("v57-node-{tag}"),
        };
        ts::register_identity_key(d, &s.route_node, identity_type::NODE).await;
        ts::register_identity_key(d, &s.identity, identity_type::USER).await;
        ts::register_identity_key(d, &s.subject, identity_type::USER).await;
        for k in [&s.kept, &s.revoked] {
            ts::register_identity_key(d, k, identity_type::AGENT).await;
        }
        let at = ms(chrono::Utc::now() - chrono::Duration::seconds(300));
        for occ in [&s.kept, &s.revoked] {
            d.put_identity_occurrence(
                ts::signed_content_only_occurrence(&s.identity, &s.identity, occ, at).await,
            )
            .await
            .expect("I1144: a v57 occurrence");
        }
        d.put_transport_destination(&crate::federation::self_at_login::test_support::route(
            &s.route_node,
            "reticulum",
            &format!("dest-{tag}"),
            1,
            &at.to_rfc3339(),
        ))
        .await
        .expect("I1144: a v57 route");
        s
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn q(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }

    /// The framed occurrence revocation alone, raw, on sqlite.
    #[cfg(feature = "sqlite")]
    pub(crate) async fn seed_raw_framed_sqlite(
        b: &crate::store::sqlite::SqliteBackend,
        framed: &(IdentityOccurrenceRevocation, serde_json::Value, String),
    ) {
        let ts = |t: chrono::DateTime<chrono::Utc>| q(&t.to_rfc3339());
        let (row, env, sig) = framed;
        b.test_execute(&format!(
            "INSERT INTO federation_identity_occurrence_revocations (\
                identity_key_id, occurrence_key_id, revoked_at, effective_at, reason, \
                witness_set, persist_row_hash, attesting_key_id, signed_envelope, signature, \
                admitted_at\
             ) VALUES ({}, {}, {}, {}, NULL, {}, {}, {}, {}, {}, {})",
            q(&row.identity_key_id),
            q(&row.occurrence_key_id),
            ts(row.revoked_at),
            ts(row.effective_at),
            q(&serde_json::to_string(&row.witness_set).unwrap()),
            q(&row.persist_row_hash),
            q(&row.witness_set[0]),
            q(&serde_json::to_string(env).unwrap()),
            q(sig),
            ts(chrono::Utc::now()),
        ))
        .await;
    }

    /// The framed occurrence revocation alone, raw, on postgres.
    #[cfg(feature = "postgres")]
    pub(crate) async fn seed_raw_framed_postgres(
        b: &crate::store::postgres::PostgresBackend,
        framed: &(IdentityOccurrenceRevocation, serde_json::Value, String),
    ) {
        let ts = |t: chrono::DateTime<chrono::Utc>| format!("{}::timestamptz", q(&t.to_rfc3339()));
        let (row, env, sig) = framed;
        b.test_execute(&format!(
            "INSERT INTO cirislens.federation_identity_occurrence_revocations (\
                identity_key_id, occurrence_key_id, revoked_at, effective_at, reason, \
                witness_set, persist_row_hash, attesting_key_id, signed_envelope, signature, \
                admitted_at\
             ) VALUES ({}, {}, {}, {}, NULL, {}::jsonb, {}, {}, {}, {}, {})",
            q(&row.identity_key_id),
            q(&row.occurrence_key_id),
            ts(row.revoked_at),
            ts(row.effective_at),
            q(&serde_json::to_string(&row.witness_set).unwrap()),
            q(&row.persist_row_hash),
            q(&row.witness_set[0]),
            q(&serde_json::to_string(env).unwrap()),
            q(sig),
            ts(chrono::Utc::now()),
        ))
        .await;
    }

    /// **I1150** — the replication path takes in no framed key-plane object:
    /// a peer's advertisement of a hash of each of the four retired kinds is
    /// refused `federation_envelope_kind_retired: <detail>` at the wire-index
    /// ingest (a live kind's still records); and the AUTHORING doors still
    /// land their objects as rows (`put_identity_occurrence` →
    /// `identity:occurrence:v1`, `put_revocation` → `key:revocation:v1`).
    pub(crate) async fn i1150_replication_takes_no_framed_object(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::key_plane as kp;
        use crate::federation::replication_policy as rp;
        let hash = "ab".repeat(32);
        let now = chrono::Utc::now();
        for kind in rp::RETIRED_FRAMED {
            match d
                .insert_known_wire_hash(kind.as_str(), &hash, Some("a-peer"), now)
                .await
            {
                Err(e @ Error::EnvelopeKindRetired { .. }) => {
                    assert_eq!(e.kind(), "federation_envelope_kind_retired");
                    assert!(
                        e.to_string().starts_with(&format!(
                            "federation_envelope_kind_retired: {}",
                            rp::retired_detail(kind)
                        )),
                        "[{tag}] I1150: {e}"
                    );
                }
                other => panic!(
                    "[{tag}] I1150: a peer's framed {} advertisement was taken in: {other:?}",
                    kind.as_str()
                ),
            }
        }
        d.insert_known_wire_hash("Attestation", &hash, Some("a-peer"), now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I1150: a live kind's advertisement: {e}"));

        // The authoring doors land rows.
        let s = seed_doors(d, tag).await;
        let held = d
            .list_signed_identity_occurrences_for(&s.identity)
            .await
            .unwrap()
            .into_iter()
            .find(|o| o.identity_occurrence.occurrence_key_id == s.kept)
            .expect("I1150: the authored occurrence is held");
        let row_id = kp::occurrence_row(&held).unwrap().attestation_id;
        assert!(
            d.get_attestation(&row_id).await.unwrap().is_some(),
            "[{tag}] I1150: the authored occurrence is not its identity:occurrence:v1 row"
        );
        let r = revocation(&s.subject, ms(now - chrono::Duration::seconds(30)));
        d.put_revocation(crate::federation::SignedRevocation {
            revocation: r.clone(),
        })
        .await
        .expect("I1150: the authored key revocation");
        let stored = d
            .revocations_for(&s.subject)
            .await
            .unwrap()
            .into_iter()
            .find(|x| x.revocation_id == r.revocation_id)
            .expect("I1150: the key revocation is held");
        let row_id = kp::revocation_row(&stored).unwrap().attestation_id;
        assert!(
            d.get_attestation(&row_id).await.unwrap().is_some(),
            "[{tag}] I1150: the authored key revocation is not its key:revocation:v1 row"
        );
    }

    /// **I1145** — the framed reads of a retired kind refuse or resolve nothing.
    pub(crate) async fn i1145_framed_reads_are_retired(d: &dyn FederationDirectory, tag: &str) {
        let s = seed_doors(d, tag).await;
        match d
            .list_signed_records(
                crate::federation::namespace::ReplicatedKind::IdentityOccurrenceRevocation,
                &s.identity,
            )
            .await
        {
            Err(e @ Error::EnvelopeKindRetired { .. }) => {
                assert_eq!(e.kind(), "federation_envelope_kind_retired");
                assert!(
                    e.to_string().starts_with(
                        "federation_envelope_kind_retired: identity_occurrence_revocation"
                    ),
                    "{e}"
                );
            }
            other => panic!("[{tag}] I1145: the framed revocation read: {other:?}"),
        }
        for (kind, key) in [
            ("Key", serde_json::json!({ "key_id": s.identity })),
            (
                "IdentityOccurrence",
                serde_json::json!({ "identity_key_id": s.identity, "occurrence_key_id": s.kept }),
            ),
            (
                "Revocation",
                serde_json::json!({ "revoked_key_sha256_ed25519_raw": "x", "revocation_id": "y" }),
            ),
            (
                "IdentityOccurrenceRevocation",
                serde_json::json!({ "identity_key_id": s.identity, "occurrence_key_id": s.revoked }),
            ),
        ] {
            assert_eq!(
                crate::federation::wire_index::reload_record_bytes(d, kind, &key.to_string())
                    .await
                    .unwrap(),
                None,
                "[{tag}] I1145: the framed {kind} wire-index reload serves bytes"
            );
        }
        let refs = crate::federation::wire_index::wire_refs_for_subject(d, &s.identity)
            .await
            .unwrap();
        assert!(
            refs.iter().all(|(k, _, _)| !matches!(
                *k,
                "Key" | "Revocation" | "IdentityOccurrence" | "IdentityOccurrenceRevocation"
            )),
            "[{tag}] I1145: a framed key-plane ref is advertised: {refs:?}"
        );
        for kind in crate::federation::replication_policy::EnvelopeKind::ALL {
            let _ = crate::federation::replication_policy::retired_detail(kind);
        }
        assert_eq!(
            crate::federation::replication_policy::retired_detail(
                crate::federation::replication_policy::EnvelopeKind::IdentityOccurrenceRevocation
            ),
            "identity_occurrence_revocation"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use super::bodies;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::store::Backend as _;

    fn tag(n: &str) -> String {
        format!("{n}-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1150_sqlite() {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1150_replication_takes_no_framed_object(&b, &tag("i1150s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1150_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1150_replication_takes_no_framed_object(&b, &tag("i1150p")).await;
        eprintln!("i1150_postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1145_sqlite() {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1145_framed_reads_are_retired(&b, &tag("i1145s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1145_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i1145 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i1145_framed_reads_are_retired(&b, &tag("i1145p")).await;
        eprintln!("i1145_postgres: RAN");
    }

    /// **I1147** — the compat reads and the framed revocation door stay gone
    /// (from disk, comments stripped); and (v58 I1123) no hybrid-pending
    /// revocation path came back.
    #[test]
    fn i1147_the_compat_reads_stay_gone() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for file in [
            "src/federation/mod.rs",
            "src/store/sqlite.rs",
            "src/store/postgres.rs",
            "src/ffi/directory_capsule.rs",
            "src/ffi/pyo3.rs",
            "src/federation/directory_double.rs",
            "python/ciris_persist/ciris_persist.pyi",
        ] {
            let code: String = std::fs::read_to_string(root.join(file))
                .unwrap()
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !t.starts_with("//") && !t.starts_with('#') && !t.starts_with("\"\"\"")
                })
                .collect::<Vec<_>>()
                .join("\n");
            for gone in [
                "fn list_signed_key_records_since",
                "fn list_signed_revocations_since",
                "fn list_signed_identity_occurrences_since",
                "fn list_signed_identity_occurrence_revocations_since",
                "fn list_signed_identity_occurrence_revocations_for",
                "fn put_identity_occurrence_revocation(",
                "def list_signed_key_records_since",
                "def list_signed_revocations_since",
                "def list_signed_identity_occurrences_since",
                "def list_signed_identity_occurrence_revocations_since",
                "ListSignedKeyRecordsSince",
                "ListSignedRevocationsSince",
                "ListSignedIdentityOccurrencesSince",
                "ListSignedIdentityOccurrenceRevocationsSince",
                "SignedIdentityOccurrenceRevocation {",
                "ServedIdentityOccurrenceRevocation",
                // v58 I1123
                "fn attach_revocation_pqc_signature",
                "def attach_revocation_pqc_signature",
                "fn list_hybrid_pending_revocations",
                "fn sweep_revocations",
                "AttachRevocationPqcSignature",
            ] {
                assert!(
                    !code.contains(gone),
                    "I1147: {file} carries `{gone}` — a retired framed key-plane path is back"
                );
            }
        }
    }
}
