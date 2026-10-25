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
        };
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
            &s.kept,
            "reticulum",
            &format!("dest-{tag}"),
            1,
            &at.to_rfc3339(),
        ))
        .await
        .expect("I1144: a v57 route");
        s
    }

    /// The framed occurrence revocation a v57 node stored: typed columns and
    /// the V103 signature trio, as produced by the retired door's producer.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn framed_revocation(
        s: &Seed,
    ) -> (IdentityOccurrenceRevocation, serde_json::Value, String) {
        framed_revocation_of(&s.identity, &s.identity, &s.revoked).await
    }

    /// [`framed_revocation`] of the pair `(identity, occurrence)` signed by
    /// `signer` (its one witness, stored as the attesting key).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn framed_revocation_of(
        signer: &str,
        identity: &str,
        occurrence: &str,
    ) -> (IdentityOccurrenceRevocation, serde_json::Value, String) {
        let at = ms(chrono::Utc::now() - chrono::Duration::seconds(60));
        let envelope = serde_json::json!({
            "attesting_key_id": signer,
            "identity_key_id": identity,
            "occurrence_key_id": occurrence,
            "revoked_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "effective_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        let id = ts::hybrid_identity(signer);
        let (signed_envelope, signature) =
            ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
                id.as_ref(),
                envelope,
            )
            .await
            .expect("sign the v57 revocation envelope");
        let mut row = IdentityOccurrenceRevocation {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            revoked_at: at,
            effective_at: at,
            reason: None,
            witness_set: vec![signer.to_owned()],
            persist_row_hash: String::new(),
        };
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row).unwrap();
        (
            row,
            signed_envelope,
            serde_json::to_string(&signature).unwrap(),
        )
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn q(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn opt(s: Option<String>) -> String {
        s.map_or_else(|| "NULL".to_owned(), |s| q(&s))
    }

    /// The v57 rows the retired doors wrote, raw, on sqlite.
    #[cfg(feature = "sqlite")]
    pub(crate) async fn seed_raw_sqlite(
        b: &crate::store::sqlite::SqliteBackend,
        r: &Revocation,
        framed: &(IdentityOccurrenceRevocation, serde_json::Value, String),
    ) {
        let ts = |t: chrono::DateTime<chrono::Utc>| q(&t.to_rfc3339());
        b.test_execute(&format!(
            "INSERT INTO federation_revocations (\
                revocation_id, revoked_key_id, revoking_key_id, reason, \
                revoked_at, effective_at, revocation_envelope, \
                original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                scrub_key_id, scrub_timestamp, pqc_completed_at, observed_region, \
                revoked_after, persist_row_hash, admitted_at, revoked_key_sha256_ed25519_raw\
             ) VALUES ({}, {}, {}, {}, {}, {}, {}, X'{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            q(&r.revocation_id),
            opt(r.revoked_key_id.clone()),
            q(&r.revoking_key_id),
            opt(r.reason.clone()),
            ts(r.revoked_at),
            ts(r.effective_at),
            q(&serde_json::to_string(&r.revocation_envelope).unwrap()),
            r.original_content_hash,
            q(&r.scrub_signature_classical),
            opt(r.scrub_signature_pqc.clone()),
            q(&r.scrub_key_id),
            ts(r.scrub_timestamp),
            opt(r.pqc_completed_at.map(|t| t.to_rfc3339())),
            q(&r.observed_region),
            opt(r.revoked_after.map(|t| t.to_rfc3339())),
            q(&r.persist_row_hash),
            ts(chrono::Utc::now()),
            q(&r.revoked_key_sha256_ed25519_raw),
        ))
        .await;
        seed_raw_framed_sqlite(b, framed).await;
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

    /// The postgres twin of [`seed_raw_sqlite`].
    #[cfg(feature = "postgres")]
    pub(crate) async fn seed_raw_postgres(
        b: &crate::store::postgres::PostgresBackend,
        r: &Revocation,
        framed: &(IdentityOccurrenceRevocation, serde_json::Value, String),
    ) {
        let ts = |t: chrono::DateTime<chrono::Utc>| format!("{}::timestamptz", q(&t.to_rfc3339()));
        let ots =
            |t: Option<chrono::DateTime<chrono::Utc>>| t.map_or_else(|| "NULL".to_owned(), ts);
        b.test_execute(&format!(
            "INSERT INTO cirislens.federation_revocations (\
                revocation_id, revoked_key_id, revoking_key_id, reason, \
                revoked_at, effective_at, revocation_envelope, \
                original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                scrub_key_id, scrub_timestamp, pqc_completed_at, observed_region, \
                revoked_after, persist_row_hash, admitted_at, revoked_key_sha256_ed25519_raw\
             ) VALUES ({}, {}, {}, {}, {}, {}, {}, '\\x{}'::bytea, {}, {}, {}, {}, {}, {}, {}, \
                {}, {}, {})",
            q(&r.revocation_id),
            opt(r.revoked_key_id.clone()),
            q(&r.revoking_key_id),
            opt(r.reason.clone()),
            ts(r.revoked_at),
            ts(r.effective_at),
            q(&serde_json::to_string(&r.revocation_envelope).unwrap()),
            r.original_content_hash,
            q(&r.scrub_signature_classical),
            opt(r.scrub_signature_pqc.clone()),
            q(&r.scrub_key_id),
            ts(r.scrub_timestamp),
            ots(r.pqc_completed_at),
            q(&r.observed_region),
            ots(r.revoked_after),
            q(&r.persist_row_hash),
            ts(chrono::Utc::now()),
            q(&r.revoked_key_sha256_ed25519_raw),
        ))
        .await;
        seed_raw_framed_postgres(b, framed).await;
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

    /// I1144's checks on a store migrated forward from V195, with no write
    /// in between.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i1144_after_migration<D: FederationDirectory + ?Sized>(
        d: &D,
        tag: &str,
        s: &Seed,
        r: &Revocation,
    ) {
        use crate::federation::key_plane as kp;
        let rows = |dim: &'static str| async move {
            let mut out = Vec::new();
            let mut since = None;
            loop {
                let page = d
                    .list_attestations_since(since.clone(), 1_000)
                    .await
                    .unwrap();
                let Some(last) = page.last() else { break };
                since = Some(last.resume_pair());
                let n = page.len();
                out.extend(page.into_iter().map(|s| s.attestation).filter(|a| {
                    crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                        == Some(dim)
                }));
                if n < 1_000 {
                    break;
                }
            }
            out
        };
        // Every key has its key:record:v1 row; none was lost.
        let key_rows = rows(kp::KEY_RECORD_DIMENSION).await;
        for k in [&s.identity, &s.subject, &s.kept, &s.revoked] {
            assert!(
                d.lookup_public_key(k).await.unwrap().is_some(),
                "[{tag}] I1144: {k} lost its key"
            );
            assert!(
                key_rows
                    .iter()
                    .any(|a| kp::key_record_of_row(a).is_some_and(|rec| &rec.key_id == k)),
                "[{tag}] I1144: {k} has no key:record:v1 row after the eager rehome"
            );
        }
        // The key revocation is its row.
        assert!(
            rows(kp::KEY_REVOCATION_DIMENSION)
                .await
                .iter()
                .any(|a| kp::revocation_of_row(a)
                    .is_some_and(|v| v.revocation_id == r.revocation_id)),
            "[{tag}] I1144: the v57 key revocation has no key:revocation:v1 row"
        );
        // Both occurrences are rows; the framed-revoked one stays revoked.
        let occ_rows = rows(kp::IDENTITY_OCCURRENCE_DIMENSION).await;
        for o in [&s.kept, &s.revoked] {
            assert!(
                occ_rows.iter().any(|a| kp::occurrence_of_row(a)
                    .is_some_and(|x| &x.identity_occurrence.occurrence_key_id == o)),
                "[{tag}] I1144: {o}'s occurrence has no identity:occurrence:v1 row"
            );
        }
        let active: Vec<String> = d
            .list_identity_occurrences_active(&s.identity)
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.occurrence_key_id)
            .collect();
        assert!(
            active.contains(&s.kept),
            "[{tag}] I1144: the kept occurrence: {active:?}"
        );
        assert!(
            !active.contains(&s.revoked),
            "[{tag}] I1144: a legacy-revoked occurrence came back: {active:?}"
        );
        // The route survives.
        assert!(
            !d.list_transport_destinations_for(&s.kept)
                .await
                .unwrap()
                .is_empty(),
            "[{tag}] I1144: the route was lost"
        );
    }

    /// I1144's count, read back from the open's rehome (idempotent: the
    /// same report the open logged).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) fn i1144_report(
        tag: &str,
        report: crate::federation::key_plane::KeyPlaneRehomeReport,
    ) {
        // The rehome's count: one legacy framed occurrence revocation, kept.
        assert_eq!(
            report.legacy_framed_occurrence_revocations, 1,
            "[{tag}] I1144: {report:?}"
        );
        assert_eq!(
            (
                report.keys_without_row,
                report.revocations_without_row,
                report.occurrences_without_row
            ),
            (0, 0, 0),
            "[{tag}] I1144: every v57 record here verifies: {report:?}"
        );
        // v59.0.0 (CIRISPersist#1104) — the legacy revocation (a self whose
        // roster is its genesis key alone: a strict majority of one) is
        // carried as an `identity:occurrence_revocation:v1` row.
        assert_eq!(
            (report.carriers.minted, report.carriers.without_quorum.len()),
            (1, 0),
            "[{tag}] I1144: the legacy revocation's carrier: {report:?}"
        );
    }

    /// I1148's v57 self: a user-role genesis key `f` (verifiable) and its
    /// transport self-occurrence `(f, f)`; `d1`, `d2` registered. (`d1`'s
    /// occurrence, asserted at the same past instant, is added after the
    /// migration: the v59 door this test drives reads V199.)
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn seed_legacy_genesis<D: FederationDirectory + ?Sized>(
        d: &D,
        tag: &str,
    ) -> (String, String, String) {
        let (f, d1, d2) = (
            format!("g57-f-{tag}"),
            format!("g57-d1-{tag}"),
            format!("g57-d2-{tag}"),
        );
        for k in [&f, &d1, &d2] {
            ts::register_identity_key(d, k, identity_type::USER).await;
        }
        let at = ms(chrono::Utc::now() - chrono::Duration::seconds(300));
        d.put_identity_occurrence(ts::signed_content_only_occurrence(&f, &f, &f, at).await)
            .await
            .expect("I1148: the v57 transport self-occurrence");
        (f, d1, d2)
    }

    /// **I1148** — a pre-door revocation of the self pair does not evict the
    /// genesis key (CC 3.3.6.3, rc9 69fd22e): after the migration, `d1`'s
    /// legacy framed revocation of `(f, f)` has retired the transport
    /// self-occurrence and nothing more — `f` is on the roster and acts as
    /// the self. The same act through the door (a `withdraws` of the pair's
    /// row by `d1`, landed by quorum) evicts it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i1148_after_migration(
        d: &dyn FederationDirectory,
        f: &str,
        d1: &str,
        d2: &str,
    ) {
        use crate::federation::self_roster as sr;
        use crate::federation::self_roster_invariants::bodies as srb;
        let at = ms(chrono::Utc::now() - chrono::Duration::seconds(300));
        srb::add(d, f, f, d1, at).await.expect("I1148: one key");
        assert_eq!(
            d.list_identity_occurrence_revocations_for(f)
                .await
                .unwrap()
                .iter()
                .filter(|r| r.occurrence_key_id == f)
                .count(),
            1,
            "I1148: the legacy (f, f) revocation is held"
        );
        assert!(!srb::active(d, f, f).await, "I1148: the pair stays retired");
        assert!(
            sr::roster_now(d, f).await.unwrap().contains(f),
            "I1148: a legacy revocation of the self pair evicted the genesis key"
        );
        assert!(sr::acts_as_steward_at(d, f, f, chrono::Utc::now())
            .await
            .unwrap());
        // f adds d2 (two keys: d1 assents).
        let p2 = srb::pending(
            srb::add(d, f, f, d2, srb::ms_now()).await,
            "I1148: f adds d2",
        );
        srb::vote(d, d1, f, &p2, true).await;
        // The same act, through the door.
        let w = srb::genesis_withdrawal(d, d1, f).await;
        let p = srb::pending(
            d.put_attestation(crate::federation::SignedAttestation { attestation: w })
                .await
                .map(|_| ()),
            "I1148: d1 proposes the genesis key's eviction",
        );
        srb::vote(d, d2, f, &p, true).await;
        assert!(
            !sr::roster_now(d, f).await.unwrap().contains(f),
            "I1148: the landed eviction did not evict"
        );
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

    /// The key revocation as a full-schema node's door stores it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn stored_revocation<D: crate::federation::FederationDirectory + ?Sized>(
        d: &D,
        subject: &str,
    ) -> crate::federation::types::Revocation {
        use crate::federation::SignedRevocation;
        let r = bodies::revocation(subject, chrono::Utc::now() - chrono::Duration::seconds(30));
        d.put_revocation(SignedRevocation {
            revocation: r.clone(),
        })
        .await
        .expect("a full-schema revocation");
        d.revocations_for_subject(&r.revoked_key_sha256_ed25519_raw)
            .await
            .unwrap()
            .into_iter()
            .find(|x| x.revocation_id == r.revocation_id)
            .unwrap()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1144_sqlite() {
        let t = tag("i1144s");
        let full = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        full.run_migrations().await.unwrap();
        let s_full = bodies::seed_doors(&full, &t).await;
        let r = stored_revocation(&full, &s_full.subject).await;
        let old = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        old.run_migrations_through(195).await.unwrap();
        let s = bodies::seed_doors(&old, &t).await;
        let framed = bodies::framed_revocation(&s).await;
        bodies::seed_raw_sqlite(&old, &r, &framed).await;
        old.run_migrations().await.unwrap();
        bodies::i1144_after_migration(&old, &t, &s, &r).await;
        bodies::i1144_report(&t, old.rehome_key_plane_at_open().await.unwrap());
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1144_postgres() {
        let Some(dsn_full) = crate::test_pg::empty_dsn() else {
            return;
        };
        let Some(dsn_old) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag("i1144p");
        let full = crate::store::postgres::PostgresBackend::connect(&dsn_full)
            .await
            .unwrap();
        full.run_migrations().await.unwrap();
        let s_full = bodies::seed_doors(&full, &t).await;
        let r = stored_revocation(&full, &s_full.subject).await;
        let old = crate::store::postgres::PostgresBackend::connect(&dsn_old)
            .await
            .unwrap();
        old.run_migrations_through(195).await.unwrap();
        let s = bodies::seed_doors(&old, &t).await;
        let framed = bodies::framed_revocation(&s).await;
        bodies::seed_raw_postgres(&old, &r, &framed).await;
        old.run_migrations().await.unwrap();
        bodies::i1144_after_migration(&old, &t, &s, &r).await;
        bodies::i1144_report(&t, old.rehome_key_plane_at_open().await.unwrap());
        eprintln!("i1144_postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1148_sqlite() {
        let t = tag("i1148s");
        let old = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        old.run_migrations_through(195).await.unwrap();
        let (f, d1, d2) = bodies::seed_legacy_genesis(&old, &t).await;
        bodies::seed_raw_framed_sqlite(&old, &bodies::framed_revocation_of(&d1, &f, &f).await)
            .await;
        old.run_migrations().await.unwrap();
        bodies::i1148_after_migration(&old, &f, &d1, &d2).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1148_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag("i1148p");
        let old = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        old.run_migrations_through(195).await.unwrap();
        let (f, d1, d2) = bodies::seed_legacy_genesis(&old, &t).await;
        bodies::seed_raw_framed_postgres(&old, &bodies::framed_revocation_of(&d1, &f, &f).await)
            .await;
        old.run_migrations().await.unwrap();
        bodies::i1148_after_migration(&old, &f, &d1, &d2).await;
        eprintln!("i1148_postgres: RAN");
    }

    /// **I1147** — the compat reads and the framed revocation door stay gone
    /// (from disk, comments stripped); and (v58 I1123) no hybrid-pending
    /// revocation path came back.
    #[test]
    fn i1147_the_compat_reads_stay_gone() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for file in [
            "src/federation/mod.rs",
            "src/store/memory.rs",
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
