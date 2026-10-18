//! v58.0.0 (compat reads, operator ruling 2026-10-18; CIRISPersist#991) —
//! **I1120–I1123: a v58 node still serves the framed key plane.**
//!
//! Slice K moved key records, key revocations and identity occurrences onto
//! attestation rows and retired the framed outbound listings, so a v58
//! canonical stopped serving keys to every pre-v58 peer (the #876 /
//! CIRISServer#788 KEX failure). The listings are restored over the tables v57
//! served from — v58's projections, which still hold the signed objects — and
//! these witnesses hold them to v57's bytes.
//!
//! - **I1120 (byte identity)** — a key record, a key revocation, an identity
//!   occurrence and a framed occurrence revocation, put through their doors,
//!   are served by the restored listings as `serde_json::to_vec(object)`
//!   byte-equal to the object as submitted (its server-computed
//!   `persist_row_hash` filled in), and byte-equal to the framed wire-index
//!   entry a pre-v58 peer fetches. On sqlite and postgres the SAME objects are
//!   seeded into a store migrated only through V195 (the v57 schema), read
//!   with the restored listings, migrated forward, and read again: the bytes
//!   do not move.
//! - **I1121 (cursor paging)** — two-row pages resumed through `since` return
//!   every row of each restored listing exactly once, in v57's order.
//! - **I1122 (mixed fleet)** — a framed occurrence revocation put on node A is
//!   served framed and applies on node B through the inbound door; a
//!   `withdraws`-only revocation is not served framed (the documented gap);
//!   both routes leave the occurrence revoked, and neither rewrites or
//!   un-revokes the other.
//! - **I1123 (no hybrid-pending path)** — an Ed25519-only key revocation is
//!   still refused at the door, and the PQC-completion path for revocations
//!   (`attach_revocation_pqc_signature`, `list_hybrid_pending_revocations`,
//!   the revocation sweep) stays gone.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        compute_persist_row_hash, identity_type, KeyRecord, Revocation, SignedIdentityOccurrence,
        SignedIdentityOccurrenceRevocation,
    };
    use crate::federation::{FederationDirectory, SignedKeyRecord, SignedRevocation};

    /// The four framed objects of one fixture, built ONCE so every store is
    /// seeded with the same bytes.
    #[derive(Clone)]
    pub(crate) struct Framed {
        pub identity: String,
        pub occurrence: String,
        pub subject: String,
        pub key: KeyRecord,
        pub revocation: Revocation,
        pub occurrence_record: SignedIdentityOccurrence,
        pub occurrence_revocation: SignedIdentityOccurrenceRevocation,
    }

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
            reason: Some("compat58".to_owned()),
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

    pub(crate) async fn framed(tag: &str) -> Framed {
        let identity = format!("c58-id-{tag}");
        let occurrence = format!("c58-occ-{tag}");
        let subject = format!("c58-k-{tag}");
        let at = ms(chrono::Utc::now() - chrono::Duration::seconds(120));
        let (ed, mldsa) = ts::hybrid_pubkeys(&subject);
        Framed {
            key: crate::federation::register::test_support::authority_signed_record(
                &subject,
                identity_type::USER,
                &ed,
                mldsa.as_deref(),
                &subject,
            ),
            revocation: revocation(
                &subject,
                ms(chrono::Utc::now() - chrono::Duration::seconds(60)),
            ),
            occurrence_record: ts::signed_content_only_occurrence(
                &identity,
                &identity,
                &occurrence,
                at,
            )
            .await,
            occurrence_revocation: ts::signed_occurrence_revocation(
                &identity,
                &identity,
                &occurrence,
                at + chrono::Duration::seconds(30),
            )
            .await,
            identity,
            occurrence,
            subject,
        }
    }

    /// Put the four objects through their doors (the revocation's door only
    /// when `with_revocation`: a V195 store has no V198 pointer for it, and is
    /// seeded through [`seed_v57_revocation_sqlite`] /
    /// [`seed_v57_revocation_postgres`] instead).
    pub(crate) async fn put_framed<D: FederationDirectory + ?Sized>(
        d: &D,
        f: &Framed,
        with_revocation: bool,
    ) {
        for k in [&f.identity, &f.occurrence] {
            ts::register_identity_key(d, k, identity_type::USER).await;
        }
        d.put_public_key(SignedKeyRecord {
            record: f.key.clone(),
        })
        .await
        .expect("compat58: the key record is admitted");
        if with_revocation {
            d.put_revocation(SignedRevocation {
                revocation: f.revocation.clone(),
            })
            .await
            .expect("compat58: the key revocation is admitted");
        }
        d.put_identity_occurrence(f.occurrence_record.clone())
            .await
            .expect("compat58: the signed occurrence is admitted");
        d.put_identity_occurrence_revocation(f.occurrence_revocation.clone())
            .await
            .expect("compat58: the framed occurrence revocation is admitted");
    }

    /// The four objects as the restored listings serve them, serialized.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct Served {
        pub key: Vec<u8>,
        pub revocation: Vec<u8>,
        pub occurrence: Vec<u8>,
        pub occurrence_revocation: Vec<u8>,
    }

    pub(crate) async fn served<D: FederationDirectory + ?Sized>(d: &D, f: &Framed) -> Served {
        let key = d
            .list_signed_key_records_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.record.key_id == f.subject)
            .expect("I1120: the key record is served");
        let revocation = d
            .list_signed_revocations_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.revocation.revocation_id == f.revocation.revocation_id)
            .expect("I1120: the key revocation is served");
        let occurrence = d
            .list_signed_identity_occurrences_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.occurrence.identity_occurrence.occurrence_key_id == f.occurrence)
            .expect("I1120: the identity occurrence is served");
        let occurrence_revocation = d
            .list_signed_identity_occurrence_revocations_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|s| {
                s.revocation
                    .identity_occurrence_revocation
                    .occurrence_key_id
                    == f.occurrence
            })
            .expect("I1120: the framed occurrence revocation is served");
        Served {
            key: serde_json::to_vec(&key.record).unwrap(),
            revocation: serde_json::to_vec(&revocation.revocation).unwrap(),
            occurrence: serde_json::to_vec(&occurrence.occurrence).unwrap(),
            occurrence_revocation: serde_json::to_vec(&occurrence_revocation.revocation).unwrap(),
        }
    }

    /// The objects as submitted, with what the door fills in server-side:
    /// `persist_row_hash` (over the submitted row) everywhere, and on the key
    /// revocation `pqc_completed_at` = its `scrub_timestamp` when it carries
    /// both halves (`key_plane::plan_put_revocation`: hybrid from its signing;
    /// v57 stamped it at the cold-path PQC attach instead).
    pub(crate) fn as_submitted(f: &Framed) -> Served {
        let mut key = f.key.clone();
        key.persist_row_hash = String::new();
        key.persist_row_hash = compute_persist_row_hash(&key).unwrap();
        let mut revocation = f.revocation.clone();
        if revocation.scrub_signature_pqc.is_some() && revocation.pqc_completed_at.is_none() {
            revocation.pqc_completed_at = Some(revocation.scrub_timestamp);
        }
        revocation.persist_row_hash = String::new();
        revocation.persist_row_hash = compute_persist_row_hash(&revocation).unwrap();
        let mut occurrence = f.occurrence_record.clone();
        occurrence.identity_occurrence.persist_row_hash = String::new();
        occurrence.identity_occurrence.persist_row_hash =
            compute_persist_row_hash(&occurrence.identity_occurrence).unwrap();
        let mut occurrence_revocation = f.occurrence_revocation.clone();
        let r = &mut occurrence_revocation.identity_occurrence_revocation;
        r.persist_row_hash = String::new();
        r.persist_row_hash = compute_persist_row_hash(&*r).unwrap();
        Served {
            key: serde_json::to_vec(&key).unwrap(),
            revocation: serde_json::to_vec(&revocation).unwrap(),
            occurrence: serde_json::to_vec(&occurrence).unwrap(),
            occurrence_revocation: serde_json::to_vec(&occurrence_revocation).unwrap(),
        }
    }

    fn diff(what: &str, got: &[u8], want: &[u8]) -> String {
        let g: serde_json::Value = serde_json::from_slice(got).unwrap();
        let w: serde_json::Value = serde_json::from_slice(want).unwrap();
        let mut out = format!("{what}: served bytes differ;");
        if let (Some(g), Some(w)) = (g.as_object(), w.as_object()) {
            for k in g.keys().chain(w.keys()) {
                if g.get(k) != w.get(k) {
                    out.push_str(&format!(" {k}: served {:?} vs {:?};", g.get(k), w.get(k)));
                }
            }
        }
        if g == w {
            out.push_str(" (equal as JSON: member order or number spelling moved)");
        }
        out
    }

    pub(crate) fn assert_bytes_eq(tag: &str, got: &Served, want: &Served) {
        for (what, g, w) in [
            ("key record", &got.key, &want.key),
            ("key revocation", &got.revocation, &want.revocation),
            ("identity occurrence", &got.occurrence, &want.occurrence),
            (
                "occurrence revocation",
                &got.occurrence_revocation,
                &want.occurrence_revocation,
            ),
        ] {
            assert!(g == w, "[{tag}] {}", diff(what, g, w));
        }
    }

    /// The framed wire-index entry of each object resolves to the listing's
    /// bytes: what a pre-v58 peer fetches by content hash is what it would have
    /// paged.
    pub(crate) async fn assert_wire_index_serves<D: FederationDirectory + ?Sized>(
        d: &D,
        tag: &str,
        s: &Served,
    ) {
        // `SignedKeyRecord { record }` / `SignedRevocation { revocation }`: a
        // one-member object around the listing's own bytes.
        let wrap = |member: &str, inner: &[u8]| -> Vec<u8> {
            [format!("{{\"{member}\":").as_bytes(), inner, b"}"].concat()
        };
        for (kind, bytes) in [
            ("Key", wrap("record", &s.key)),
            ("Revocation", wrap("revocation", &s.revocation)),
            ("IdentityOccurrence", s.occurrence.clone()),
            (
                "IdentityOccurrenceRevocation",
                s.occurrence_revocation.clone(),
            ),
        ] {
            let hash = crate::federation::wire_index::content_hash_of_bytes(&bytes);
            let fetched = d
                .lookup_signed_record_by_content_hash(kind, &hash)
                .await
                .unwrap();
            assert_eq!(
                fetched.as_deref(),
                Some(bytes.as_slice()),
                "[{tag}] I1120: the framed {kind} entry serves the listing's bytes"
            );
        }
    }

    /// I1120 — byte identity on one store (memory, or a fully migrated SQL
    /// store).
    pub(crate) async fn i1120_byte_identity<B: AttestationStore>(b: &B, tag: &str) {
        let f = framed(tag).await;
        put_framed(b, &f, true).await;
        let got = served(b, &f).await;
        assert_bytes_eq(tag, &got, &as_submitted(&f));
        assert_wire_index_serves(b, tag, &got).await;
        // And the subject-scoped advertisement carries the framed refs.
        let refs =
            crate::federation::wire_index::wire_refs_for_subject(b.as_dyn_directory(), &f.identity)
                .await
                .unwrap();
        for kind in ["IdentityOccurrence", "IdentityOccurrenceRevocation"] {
            assert!(
                refs.iter().any(|(k, _, _)| *k == kind),
                "[{tag}] I1120: the identity advertises its framed {kind} ref; got {refs:?}"
            );
        }
        let refs =
            crate::federation::wire_index::wire_refs_for_subject(b.as_dyn_directory(), &f.subject)
                .await
                .unwrap();
        for kind in ["Key", "Revocation", "Attestation"] {
            assert!(
                refs.iter().any(|(k, _, _)| *k == kind),
                "[{tag}] I1120: the key advertises its {kind} ref; got {refs:?}"
            );
        }
    }

    /// I1121 — two-row pages resumed through `since` return every row once,
    /// in v57's order.
    pub(crate) async fn i1121_cursor_paging<B: AttestationStore>(b: &B, tag: &str) {
        for i in 0..3 {
            let f = framed(&format!("{tag}-{i}")).await;
            put_framed(b, &f, true).await;
        }
        macro_rules! pages {
            ($method:ident, $key:expr) => {{
                let all = b.$method(None, u32::MAX).await.unwrap();
                assert!(
                    all.len() >= 3,
                    "[{tag}] I1121 {}: seeded",
                    stringify!($method)
                );
                let keys: Vec<_> = all.iter().map($key).collect();
                let mut sorted = keys.clone();
                sorted.sort();
                assert_eq!(
                    keys,
                    sorted,
                    "[{tag}] I1121 {}: v57's order",
                    stringify!($method)
                );
                let mut paged = Vec::new();
                let mut since = None;
                loop {
                    // A cursor that re-serves its last row never ends: bound it.
                    assert!(
                        paged.len() <= all.len(),
                        "[{tag}] I1121 {}: paging re-serves rows ({} paged of {})",
                        stringify!($method),
                        paged.len(),
                        all.len()
                    );
                    let page = b.$method(since.clone(), 2).await.unwrap();
                    assert!(page.len() <= 2);
                    let Some(last) = page.last() else { break };
                    since = Some(last.resume_pair());
                    paged.extend(page);
                }
                assert_eq!(
                    paged,
                    all,
                    "[{tag}] I1121 {}: every row once, in order",
                    stringify!($method)
                );
            }};
        }
        pages!(list_signed_key_records_since, |s| (
            s.admitted_at,
            s.record.key_id.clone()
        ));
        pages!(list_signed_revocations_since, |s| (
            s.admitted_at,
            s.revocation.revocation_id.clone()
        ));
        pages!(list_signed_identity_occurrences_since, |s| (
            s.admitted_at,
            s.occurrence.identity_occurrence.identity_key_id.clone(),
            s.occurrence.identity_occurrence.occurrence_key_id.clone()
        ));
        pages!(list_signed_identity_occurrence_revocations_since, |s| (
            s.admitted_at,
            s.revocation
                .identity_occurrence_revocation
                .identity_key_id
                .clone(),
            s.revocation
                .identity_occurrence_revocation
                .occurrence_key_id
                .clone()
        ));
    }

    async fn framed_revocations<D: FederationDirectory + ?Sized>(
        d: &D,
        identity: &str,
    ) -> Vec<SignedIdentityOccurrenceRevocation> {
        d.list_signed_identity_occurrence_revocations_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.revocation)
            .filter(|r| r.identity_occurrence_revocation.identity_key_id == identity)
            .collect()
    }

    async fn revoked<D: FederationDirectory + ?Sized>(
        d: &D,
        identity: &str,
        occurrence: &str,
    ) -> Vec<crate::federation::IdentityOccurrenceRevocation> {
        d.list_identity_occurrence_revocations_for(identity)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.occurrence_key_id == occurrence)
            .collect()
    }

    async fn active<D: FederationDirectory + ?Sized>(d: &D, identity: &str) -> Vec<String> {
        d.list_identity_occurrences_active(identity)
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.occurrence_key_id)
            .collect()
    }

    /// I1122 — the mixed fleet: the framed route replicates, the `withdraws`
    /// route does not (framed), and the two never disagree.
    pub(crate) async fn i1122_mixed_fleet<B: AttestationStore>(a: &B, b: &B, tag: &str) {
        let id = format!("i1122-id-{tag}");
        let framed_occ = format!("i1122-framed-{tag}");
        let withdrawn_occ = format!("i1122-withdrawn-{tag}");
        let at = ms(chrono::Utc::now() - chrono::Duration::seconds(300));
        for node in [a, b] {
            for k in [&id, &framed_occ, &withdrawn_occ] {
                ts::register_identity_key(node, k, identity_type::USER).await;
            }
        }
        for occ in [&framed_occ, &withdrawn_occ] {
            let o = ts::signed_content_only_occurrence(&id, &id, occ, at).await;
            a.put_identity_occurrence(o.clone()).await.unwrap();
            b.put_identity_occurrence(o).await.unwrap();
        }
        assert_eq!(active(a, &id).await.len(), 2, "[{tag}] I1122: both live");

        // (1) The framed route: authored on A, served framed, applied on B.
        let f = ts::signed_occurrence_revocation(
            &id,
            &id,
            &framed_occ,
            at + chrono::Duration::seconds(10),
        )
        .await;
        a.put_identity_occurrence_revocation(f.clone())
            .await
            .expect("I1122: the framed revocation is admitted on A");
        let served_a = framed_revocations(a, &id).await;
        assert_eq!(served_a.len(), 1, "[{tag}] I1122: A serves it framed");
        b.put_identity_occurrence_revocation(served_a[0].clone())
            .await
            .expect("I1122: B applies what A served, through the inbound door");
        assert_eq!(
            framed_revocations(b, &id).await,
            served_a,
            "[{tag}] I1122: B serves the same framed object onward"
        );
        assert_eq!(revoked(b, &id, &framed_occ).await.len(), 1);
        assert!(!active(b, &id).await.contains(&framed_occ));
        // The re-offer settles (the #672 rule, restored on this door).
        b.put_identity_occurrence_revocation(served_a[0].clone())
            .await
            .expect("I1122: a byte-identical re-offer settles");

        // (2) The `withdraws` route: revoked locally, NOT served framed.
        a.put_attestation(
            ts::occurrence_withdrawal(a, &id, &id, &withdrawn_occ, chrono::Utc::now()).await,
        )
        .await
        .expect("I1122: the identity withdraws its occurrence row");
        let w = revoked(a, &id, &withdrawn_occ).await;
        assert_eq!(
            w.len(),
            1,
            "[{tag}] I1122: the withdrawal revoked it locally"
        );
        assert!(
            framed_revocations(a, &id)
                .await
                .iter()
                .all(|r| r.identity_occurrence_revocation.occurrence_key_id != withdrawn_occ),
            "[{tag}] I1122: a withdraws-only revocation is not served framed (the documented gap)"
        );
        assert!(
            active(a, &id).await.is_empty(),
            "[{tag}] I1122: both revoked"
        );

        // (3) The two routes on one pair never disagree.
        // A `withdraws` after the framed revocation: admitted, and the framed
        // object stays exactly as it was (not rewritten, still served).
        a.put_attestation(
            ts::occurrence_withdrawal(a, &id, &id, &framed_occ, chrono::Utc::now()).await,
        )
        .await
        .expect("I1122: a withdraws on an already-revoked occurrence is admitted");
        assert_eq!(
            framed_revocations(a, &id).await,
            served_a,
            "[{tag}] I1122: the withdraws neither rewrote nor hid the framed revocation"
        );
        let held = revoked(a, &id, &framed_occ).await;
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].effective_at, f.identity_occurrence_revocation.effective_at,
            "[{tag}] I1122: the framed instants stand"
        );
        // A framed revocation after the `withdraws`: settles without a write;
        // the withdrawal's instants stand and the pair stays revoked.
        let late = ts::signed_occurrence_revocation(
            &id,
            &id,
            &withdrawn_occ,
            chrono::Utc::now() + chrono::Duration::days(1),
        )
        .await;
        a.put_identity_occurrence_revocation(late)
            .await
            .expect("I1122: a framed revocation of a withdrawn pair settles");
        assert_eq!(
            revoked(a, &id, &withdrawn_occ).await,
            w,
            "[{tag}] I1122: the later framed revocation did not move the withdrawal's instants"
        );
        assert!(
            active(a, &id).await.is_empty(),
            "[{tag}] I1122: neither route un-revoked the other"
        );
    }

    /// I1123 — an Ed25519-only key revocation is refused at the door.
    pub(crate) async fn i1123_ed25519_only_refused<B: AttestationStore>(b: &B, tag: &str) {
        let k = format!("i1123-k-{tag}");
        ts::register_hybrid_key(b, &k).await;
        let mut r = revocation(&k, ms(chrono::Utc::now()));
        r.scrub_signature_pqc = None;
        r.pqc_completed_at = None;
        let e = b
            .put_revocation(SignedRevocation { revocation: r })
            .await
            .expect_err("I1123: an Ed25519-only revocation is refused");
        assert_eq!(
            e.kind(),
            "federation_signature_invalid",
            "[{tag}] I1123: {e}"
        );
        assert!(
            b.list_signed_revocations_since(None, u32::MAX)
                .await
                .unwrap()
                .iter()
                .all(|s| s.revocation.revoking_key_id != k),
            "[{tag}] I1123: nothing landed to serve"
        );
    }

    /// SQL string literal.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn q(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn opt(s: Option<String>) -> String {
        s.map_or_else(|| "NULL".to_owned(), |s| q(&s))
    }

    /// The revocation as a v57 node stored it (V195: no `attestation_id`), on
    /// sqlite. `stored` is the object as a full-schema node's door stored it.
    #[cfg(feature = "sqlite")]
    pub(crate) async fn seed_v57_revocation_sqlite(
        b: &crate::store::sqlite::SqliteBackend,
        stored: &Revocation,
    ) {
        let r = stored;
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
    }

    /// The postgres twin of [`seed_v57_revocation_sqlite`].
    #[cfg(feature = "postgres")]
    pub(crate) async fn seed_v57_revocation_postgres(
        b: &crate::store::postgres::PostgresBackend,
        stored: &Revocation,
    ) {
        let r = stored;
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
    }

    /// The revocation as a full-schema node's door stored it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn stored_revocation<D: FederationDirectory + ?Sized>(
        d: &D,
        f: &Framed,
    ) -> Revocation {
        d.list_signed_revocations_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.revocation.revocation_id == f.revocation.revocation_id)
            .unwrap()
            .revocation
    }
}

#[cfg(test)]
mod run {
    use super::bodies;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::store::Backend as _;

    fn tag(n: &str) -> String {
        format!("{n}-{}", uuid::Uuid::new_v4().simple())
    }

    // ── memory ─────────────────────────────────────────────────────────
    #[tokio::test(flavor = "multi_thread")]
    async fn i1120_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i1120_byte_identity(&b, &tag("i1120m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1121_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i1121_cursor_paging(&b, &tag("i1121m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1122_memory() {
        let (a, b) = (
            crate::store::memory::MemoryBackend::new(),
            crate::store::memory::MemoryBackend::new(),
        );
        bodies::i1122_mixed_fleet(&a, &b, &tag("i1122m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1123_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i1123_ed25519_only_refused(&b, &tag("i1123m")).await;
    }

    /// I1123 — the revocation PQC-completion path stays gone (from disk,
    /// comments stripped): no trait method, no backend impl, no capsule op, no
    /// Python method, no sweep leg.
    #[test]
    fn i1123_no_hybrid_pending_revocation_path() {
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
                "fn attach_revocation_pqc_signature",
                "def attach_revocation_pqc_signature",
                "fn list_hybrid_pending_revocations",
                "fn sweep_revocations",
                "AttachRevocationPqcSignature",
            ] {
                assert!(
                    !code.contains(gone),
                    "I1123: {file} carries `{gone}` — the hybrid-pending revocation path is back"
                );
            }
        }
    }

    // ── sqlite ─────────────────────────────────────────────────────────
    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1120_sqlite() {
        let b = sqlite().await;
        bodies::i1120_byte_identity(&b, &tag("i1120s")).await;
    }

    /// I1120 — the v57 schema leg: the same objects on a V195 store, read,
    /// migrated forward, read again.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1120_sqlite_v195() {
        let t = tag("i1120s195");
        let f = bodies::framed(&t).await;
        let full = sqlite().await;
        bodies::put_framed(&full, &f, true).await;
        let want = bodies::served(&full, &f).await;
        bodies::assert_bytes_eq(&t, &want, &bodies::as_submitted(&f));

        let old = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        old.run_migrations_through(195).await.unwrap();
        bodies::put_framed(&old, &f, false).await;
        bodies::seed_v57_revocation_sqlite(&old, &bodies::stored_revocation(&full, &f).await).await;
        let before = bodies::served(&old, &f).await;
        bodies::assert_bytes_eq(&format!("{t} V195"), &before, &want);
        old.run_migrations().await.unwrap();
        let after = bodies::served(&old, &f).await;
        bodies::assert_bytes_eq(&format!("{t} V195→head"), &after, &before);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1121_sqlite() {
        let b = sqlite().await;
        bodies::i1121_cursor_paging(&b, &tag("i1121s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1122_sqlite() {
        let (a, b) = (sqlite().await, sqlite().await);
        bodies::i1122_mixed_fleet(&a, &b, &tag("i1122s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1123_sqlite() {
        let b = sqlite().await;
        bodies::i1123_ed25519_only_refused(&b, &tag("i1123s")).await;
    }

    // ── postgres ───────────────────────────────────────────────────────
    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("compat58 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1120_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1120_byte_identity(&b, &tag("i1120p")).await;
        eprintln!("i1120_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1120_postgres_v195() {
        let Some(full) = postgres().await else { return };
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag("i1120p195");
        let f = bodies::framed(&t).await;
        bodies::put_framed(&full, &f, true).await;
        let want = bodies::served(&full, &f).await;
        bodies::assert_bytes_eq(&t, &want, &bodies::as_submitted(&f));

        let old = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        old.run_migrations_through(195).await.unwrap();
        bodies::put_framed(&old, &f, false).await;
        bodies::seed_v57_revocation_postgres(&old, &bodies::stored_revocation(&full, &f).await)
            .await;
        let before = bodies::served(&old, &f).await;
        bodies::assert_bytes_eq(&format!("{t} V195"), &before, &want);
        old.run_migrations().await.unwrap();
        let after = bodies::served(&old, &f).await;
        bodies::assert_bytes_eq(&format!("{t} V195→head"), &after, &before);
        eprintln!("i1120_postgres_v195: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1121_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1121_cursor_paging(&b, &tag("i1121p")).await;
        eprintln!("i1121_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1122_postgres() {
        let Some(a) = postgres().await else { return };
        let Some(b) = postgres().await else { return };
        bodies::i1122_mixed_fleet(&a, &b, &tag("i1122p")).await;
        eprintln!("i1122_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1123_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1123_ed25519_only_refused(&b, &tag("i1123p")).await;
        eprintln!("i1123_postgres: RAN");
    }
}
