//! v61.0.5 (CIRISPersist#1225, Edge agent 2.20) — **I1544–I1547: the read
//! of rows naming a key, one dimension**, on every backend, through
//! [`FederationDirectory::list_attestations_naming_by_dimension`].
//!
//! - **I1544** the rows whose `subject_key_ids` name K under exactly the
//!   dimension come back newest-first by `(asserted_at, attestation_id)`
//!   (a tie broken by id, descending); a row naming another key, or K under
//!   another dimension, does not. A row naming K among other subjects does.
//! - **I1545** pages join without a gap or a repeat, and `next_cursor` is
//!   `Some` exactly when another row exists: a page that ends on the last
//!   row says so even when it is full. The page bound and the cursor
//!   version are refused.
//! - **I1546** the order is the signer's: a row that arrives later dated
//!   behind a walk's cursor is found by a read from the head, and a row
//!   dated between the head and the cursor is found ONLY from the head —
//!   the limit Edge designed around (it reads from the head each wake).
//! - **I1547** it serves what `list_attestations_since` serves: never a
//!   local-tier row, never a purge-tombstoned row, except one the tombstone
//!   is void for (a person-subject row).
//!
//! The capsule round trip is `ffi::directory_capsule`'s I1548.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::ceg::list::federation::AttestationCursor;
    use crate::federation::steward_purge::{self as sp, PurgePlane};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, Attestation};
    use crate::federation::{FederationDirectory, SignedAttestation};
    use chrono::{DateTime, Duration, Utc};

    /// The read under test's dimension, and a second one beside it.
    pub(crate) const DIM: &str = "i1544:invite:v1";
    const OTHER_DIM: &str = "i1544:other:v1";

    /// A whole-second instant `secs` before a fixed base well in the past.
    pub(crate) fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(Utc::now().timestamp() - 3_600, 0).expect("base")
            - Duration::seconds(secs)
    }

    /// The attester (an agent, so its own key is not a person subject) and
    /// the key K the read names, both tagged.
    pub(crate) async fn keys(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let a = format!("i1544-attester-{tag}");
        ts::register_hybrid_key(d, &a).await;
        (a, format!("i1544-subject-{tag}"))
    }

    /// A federation-tier self-report by `a` naming `subjects` under `dim`,
    /// asserted at `when`, sealed and put through the door. Returns its id.
    pub(crate) async fn put_naming(
        d: &dyn FederationDirectory,
        a: &str,
        subjects: &[&str],
        dim: &str,
        when: DateTime<Utc>,
        id: Option<&str>,
    ) -> String {
        let id = id.map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned);
        let env = serde_json::json!({ "dimension": dim, "n": id });
        let mut r = ts::bare_attestation(&id, a, a, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = when;
        r.scrub_timestamp = when;
        r.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        ts::seal_row_in_place(a, &mut r);
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .unwrap_or_else(|e| panic!("I1544 fixture {id} admits: {e}"));
        id
    }

    /// Every page of the read from the head, `limit` per page: the ids in
    /// order, and each page's (row count, next cursor present).
    pub(crate) async fn walk(
        d: &dyn FederationDirectory,
        k: &str,
        dim: &str,
        limit: i64,
    ) -> (Vec<String>, Vec<(usize, bool)>) {
        let mut ids = Vec::new();
        let mut shape = Vec::new();
        let mut cursor: Option<AttestationCursor> = None;
        loop {
            let page = d
                .list_attestations_naming_by_dimension(k, dim, cursor.clone(), limit)
                .await
                .expect("served");
            shape.push((page.items.len(), page.next_cursor.is_some()));
            ids.extend(page.items.iter().map(|a| a.attestation_id.clone()));
            match page.next_cursor {
                Some(c) => {
                    assert!(shape.len() < 100, "the walk does not end");
                    cursor = Some(c);
                }
                None => return (ids, shape),
            }
        }
    }

    fn ids(rows: &[Attestation]) -> Vec<String> {
        rows.iter().map(|a| a.attestation_id.clone()).collect()
    }

    /// **I1544** — the selection and the order.
    pub(crate) async fn i1544_rows_naming_k_newest_first(d: &dyn FederationDirectory, tag: &str) {
        let (a, k) = keys(d, tag).await;
        let other = format!("i1544-other-{tag}");
        let oldest = put_naming(d, &a, &[&k], DIM, at(30), None).await;
        // A tie on the signed instant: the id breaks it, descending.
        // Real UUIDs: postgres stores the id as `uuid`, and lowercase-hex
        // UUIDs order alike as text and as bytes.
        let mut tie = [
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        ];
        tie.sort();
        let tie_lo = put_naming(d, &a, &[&k], DIM, at(20), Some(&tie[0])).await;
        let tie_hi = put_naming(d, &a, &[&k], DIM, at(20), Some(&tie[1])).await;
        let among = put_naming(d, &a, &[&other, &k], DIM, at(15), None).await;
        let newest = put_naming(d, &a, &[&k], DIM, at(10), None).await;
        // Neither of these is K's under DIM.
        put_naming(d, &a, &[&other], DIM, at(5), None).await;
        put_naming(d, &a, &[&k], OTHER_DIM, at(5), None).await;

        let page = d
            .list_attestations_naming_by_dimension(&k, DIM, None, 100)
            .await
            .expect("I1544 served");
        assert_eq!(
            ids(&page.items),
            vec![newest, among, tie_hi, tie_lo, oldest],
            "I1544 {tag}: K's rows under DIM, newest first, the tie by id descending"
        );
        assert!(page.next_cursor.is_none(), "I1544 {tag}: nothing past");
        assert!(
            page.items.iter().all(|r| r.subject_key_ids.contains(&k)),
            "I1544 {tag}: every row names K"
        );
        // The other key's read sees its own two, and K under the other
        // dimension sees its one.
        let theirs = d
            .list_attestations_naming_by_dimension(&other, DIM, None, 100)
            .await
            .expect("I1544 served");
        assert_eq!(theirs.items.len(), 2, "I1544 {tag}: the other key's rows");
        let elsewhere = d
            .list_attestations_naming_by_dimension(&k, OTHER_DIM, None, 100)
            .await
            .expect("I1544 served");
        assert_eq!(elsewhere.items.len(), 1, "I1544 {tag}: K's other dimension");
        let nobody = d
            .list_attestations_naming_by_dimension(&format!("i1544-nobody-{tag}"), DIM, None, 100)
            .await
            .expect("I1544 served");
        assert!(nobody.items.is_empty() && nobody.next_cursor.is_none());
    }

    /// **I1545** — the cursor, and `next_cursor` as the "more" answer.
    pub(crate) async fn i1545_cursor_continuity_and_more(d: &dyn FederationDirectory, tag: &str) {
        let (a, k) = keys(d, tag).await;
        let mut want = Vec::new();
        for s in [50, 40, 40, 30] {
            want.push(put_naming(d, &a, &[&k], DIM, at(s), None).await);
        }
        let (all, _) = walk(d, &k, DIM, 100).await;
        // Four rows at two per page: the second page is FULL and the last.
        let (got, shape) = walk(d, &k, DIM, 2).await;
        assert_eq!(
            got, all,
            "I1545 {tag}: pages join without a gap or a repeat"
        );
        assert_eq!(
            shape,
            vec![(2, true), (2, false)],
            "I1545 {tag}: more is true exactly when another row exists"
        );
        let (got, shape) = walk(d, &k, DIM, 3).await;
        assert_eq!(got, all, "I1545 {tag}");
        assert_eq!(shape, vec![(3, true), (1, false)], "I1545 {tag}");
        let (got, shape) = walk(d, &k, DIM, 1).await;
        assert_eq!(got, all, "I1545 {tag}");
        assert_eq!(shape.len(), 4, "I1545 {tag}");
        assert_eq!(all.len(), want.len(), "I1545 {tag}: every row");
        let (got, shape) = walk(d, &k, DIM, 4).await;
        assert_eq!((got, shape), (all, vec![(4, false)]), "I1545 {tag}");

        for bad in [0, -1, 10_001] {
            d.list_attestations_naming_by_dimension(&k, DIM, None, bad)
                .await
                .expect_err("I1545: a page outside [1, 10000] is refused");
        }
        let mut v2 = AttestationCursor::from_trailing(at(40), uuid::Uuid::new_v4().to_string());
        v2.version = "v2".into();
        d.list_attestations_naming_by_dimension(&k, DIM, Some(v2), 2)
            .await
            .expect_err("I1545: an unknown cursor version is refused");
    }

    /// **I1546** — late rows, and why the caller reads from the head.
    pub(crate) async fn i1546_late_rows_found_from_the_head(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (a, k) = keys(d, tag).await;
        let b = put_naming(d, &a, &[&k], DIM, at(10), None).await;
        let old = put_naming(d, &a, &[&k], DIM, at(20), None).await;
        let (seen, _) = walk(d, &k, DIM, 1).await;
        assert_eq!(seen, vec![b.clone(), old.clone()], "I1546 {tag}");
        // The walk ended at `old`; a resume would start after it.
        let tail = d
            .list_attestations_naming_by_dimension(&k, DIM, None, 2)
            .await
            .expect("served")
            .items
            .pop()
            .expect("row");
        let past = AttestationCursor::from_trailing(tail.asserted_at, tail.attestation_id);

        // Arrives late, dated behind everything seen (behind the head AND
        // the cursor).
        let behind = put_naming(d, &a, &[&k], DIM, at(30), None).await;
        // Arrives late, dated between the head and the walk's cursor.
        let between = put_naming(d, &a, &[&k], DIM, at(15), None).await;

        let (head, _) = walk(d, &k, DIM, 2).await;
        assert_eq!(
            head,
            vec![b.clone(), between.clone(), old, behind.clone()],
            "I1546 {tag}: a read from the head finds both late rows, in signed order"
        );
        // Neither sorts above the head seen before: a high-water mark at the
        // old head would skip both.
        assert_eq!(head.first(), Some(&b), "I1546 {tag}: the head did not move");
        // A resume from the finished walk's cursor finds the row dated
        // behind it, never the one dated between.
        let resumed = d
            .list_attestations_naming_by_dimension(&k, DIM, Some(past), 100)
            .await
            .expect("served");
        assert_eq!(
            ids(&resumed.items),
            vec![behind],
            "I1546 {tag}: a resumed cursor misses {between}; only the head finds it"
        );
    }

    /// **I1547** — local tier and tombstones, as `list_attestations_since`.
    pub(crate) async fn i1547_local_and_tombstoned_rows_excluded(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (a, k) = keys(d, tag).await;
        let person = format!("i1547-person-{tag}");
        ts::register_hybrid_key_as(d, &person, &person, it::USER).await;
        let kept = put_naming(d, &a, &[&k], DIM, at(40), None).await;
        let doomed = put_naming(d, &a, &[&k], DIM, at(30), None).await;
        // Names a PERSON too: a tombstone is void for it, so it stays served
        // (Codex round 4 on PR #1057, the same rule as the cursor read).
        let void = put_naming(d, &a, &[&k, &person], DIM, at(20), None).await;
        let local = d
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: a.clone(),
                attested_key_id: None,
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({ "dimension": DIM, "n": "local" }),
                )
                .expect("object"),
                subject_key_ids: vec![k.clone()],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("I1547 the local row is written");
        assert!(
            d.get_attestation(&local).await.expect("read").is_some(),
            "I1547 {tag}: the local row is held"
        );

        let (before, _) = walk(d, &k, DIM, 100).await;
        assert_eq!(
            before,
            vec![void.clone(), doomed.clone(), kept.clone()],
            "I1547 {tag}: the local-tier row is never served"
        );

        let t = Utc::now();
        let notice_id = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(format!("i1547-{tag}").as_bytes()))
        };
        let exec = sp::PurgeExecution {
            notice_id: notice_id.clone(),
            selection_digest: "ab".repeat(32),
            claimant_key_id: "moderator-1".to_owned(),
            legal_basis: "ncmec_csam".to_owned(),
            record_count: 2,
            notice_jcs: "{}".to_owned(),
            cosignatures_json: "[]".to_owned(),
            executed_by: "node-i1547".to_owned(),
            origin: sp::origin::LOCAL.to_owned(),
            executed_at: t,
            admitted_at: t,
            finalized_at: None,
        };
        let stones: Vec<sp::PurgeTombstone> = [&doomed, &void]
            .iter()
            .enumerate()
            .map(|(i, id)| sp::PurgeTombstone {
                notice_id: notice_id.clone(),
                ordinal: i as u64,
                plane: PurgePlane::Attestation,
                record_ref: (*id).clone(),
                derived_from: None,
            })
            .collect();
        d.purge_put_execution(&exec, &stones)
            .await
            .expect("I1547 tombstones recorded");
        assert!(
            d.get_attestation(&doomed).await.expect("read").is_some(),
            "I1547 {tag}: the tombstoned row is still held"
        );
        let (after, _) = walk(d, &k, DIM, 100).await;
        assert_eq!(
            after,
            vec![void, kept],
            "I1547 {tag}: a tombstoned row is not served; the person-subject row is"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("1225 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i1544, bodies::i1544_rows_naming_k_newest_first);
    on_every_backend!(i1545, bodies::i1545_cursor_continuity_and_more);
    on_every_backend!(i1546, bodies::i1546_late_rows_found_from_the_head);
    on_every_backend!(i1547, bodies::i1547_local_and_tombstoned_rows_excluded);
}
