//! v59.0.0 (CIRISPersist#1104; CC 3.1.5 rc9 `c901645`,
//! `CLM-occurrence-revocation-carrier`) — **I1155: the legacy occurrence
//! revocation's carrier**, on every backend.
//!
//! - a node's legacy revocation becomes a carrier, revokes, replicates to a
//!   fresh node that has no consent relationship with anyone (the audience
//!   says `Public`) and revokes there;
//! - a user self's carrier without a strict majority of its live roster is
//!   refused `carrier_without_roster_quorum`; cosigned by a strict majority it
//!   admits and revokes;
//! - a BACKDATED framed object freshly signed by one user key (the
//!   `unilateral3_stolen` attack) is refused, whatever its instant;
//! - a carrier one byte off its own derivation is refused;
//! - the open's migration mints the admissible legacy carriers and NAMES the
//!   user-self ones without a quorum (sqlite, postgres).

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::occurrence_revocation_carrier as orc;
    use crate::federation::self_roster_invariants::bodies as srb;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{identity_type as it, Attestation, ScrubSig};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    /// `signer`'s framed revocation of `(identity, occurrence)` at `at`.
    pub(crate) async fn framed(
        signer: &str,
        identity: &str,
        occurrence: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> orc::FramedOccurrenceRevocation {
        let at = at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let envelope = serde_json::json!({
            "attesting_key_id": signer,
            "identity_key_id": identity,
            "occurrence_key_id": occurrence,
            "revoked_at": at,
            "effective_at": at,
        });
        let (signed_envelope, signature) =
            ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
                ts::hybrid_identity(signer).as_ref(),
                envelope,
            )
            .await
            .expect("sign the framed revocation");
        orc::FramedOccurrenceRevocation {
            attesting_key_id: signer.to_owned(),
            signed_envelope,
            signature,
        }
    }

    /// `cosigner`'s hybrid cosignature over `row`'s envelope.
    pub(crate) fn cosign(row: &mut Attestation, cosigner: &str) {
        let (_, classical, pqc) = ts::sign_envelope(cosigner, &row.attestation_envelope);
        row.additional_scrubs.push(ScrubSig {
            scrub_key_id: cosigner.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            cosigned_at: None,
        });
    }

    async fn put(d: &dyn FederationDirectory, row: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    fn refused(r: Result<(), Error>, reason: &str, what: &str) {
        match r {
            Err(Error::MalformedRow { reason: got, .. }) if got == reason => {}
            other => panic!("I1155: {what}: expected {reason}, got {other:?}"),
        }
    }

    /// A node `n` with an agent occurrence `o`, registered on `d`.
    pub(crate) async fn node_with_occurrence(d: &dyn FederationDirectory, n: &str, o: &str) {
        ts::register_identity_key(d, n, it::NODE).await;
        ts::register_identity_key(d, o, it::AGENT).await;
        d.put_identity_occurrence(ts::signed_content_only_occurrence(n, n, o, srb::ms_now()).await)
            .await
            .expect("I1155: the node's occurrence");
    }

    /// **I1155** (a): a node's carrier admits, revokes, and reaches a stranger.
    pub(crate) async fn i1155_a_node_carrier_reaches_a_stranger(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        // Ids that name their own keys: B meets them at first contact
        // (CIRISPersist#1103).
        let (n, o) = (
            ts::fp_key_id(&format!("n-{tag}")),
            ts::fp_key_id(&format!("o-{tag}")),
        );
        node_with_occurrence(a, &n, &o).await;
        let row = orc::carrier_row(&framed(&n, &n, &o, srb::ms_now()).await).unwrap();
        assert_eq!(
            crate::federation::key_plane::occurrence_revoked_by(a, &row)
                .await
                .unwrap(),
            Some((n.clone(), o.clone())),
            "I1155: the one predicate names the carrier's pair"
        );
        put(a, row.clone())
            .await
            .expect("I1155: a node's carrier admits");
        assert!(!srb::active(a, &n, &o).await, "I1155: it revokes on A");
        // Global reach: a stranger is in the carrier's audience.
        let stranger = format!("stranger-{tag}");
        assert!(
            matches!(
                crate::federation::replication_audience::may_receive(a, &stranger, &row)
                    .await
                    .unwrap(),
                crate::federation::replication_audience::Verdict::Yes(_)
            ),
            "I1155: the carrier reaches a node with no relationship to the self"
        );
        // B: a fresh node, no consent relationship; A's stream applied.
        let mut since = None;
        loop {
            let page = a
                .list_attestations_since(since.clone(), 1_000)
                .await
                .unwrap();
            let Some(last) = page.last() else { break };
            since = Some(last.resume_pair());
            for s in &page {
                let _ = b
                    .apply_replicated_attestation(SignedAttestation {
                        attestation: s.attestation.clone(),
                    })
                    .await;
            }
            if page.len() < 1_000 {
                break;
            }
        }
        assert!(
            b.get_attestation(&row.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I1155: B holds the carrier"
        );
        assert!(
            !b.list_identity_occurrences_by_occurrence_key(&o)
                .await
                .unwrap()
                .is_empty(),
            "I1155: B holds the occurrence (non-vacuity)"
        );
        assert!(
            !srb::active(b, &n, &o).await,
            "I1155: the carrier revokes on B"
        );
        assert!(
            !b.list_identity_occurrence_revocations_for(&n)
                .await
                .unwrap()
                .is_empty(),
            "I1155: B projected the revocation"
        );
    }

    /// **I1155** (b, c, d): a user self's carrier needs its roster's quorum;
    /// a backdated one-key object is refused; a byte-different row is refused.
    pub(crate) async fn i1155_a_user_carrier_needs_the_quorum(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        srb::three(d, &f, &d1, &d2).await;

        // The thief: d1 alone, backdated to before the door.
        let ancient: chrono::DateTime<chrono::Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let stolen = orc::carrier_row(&framed(&d1, &f, &d2, ancient).await).unwrap();
        refused(
            put(d, stolen).await,
            "carrier_without_roster_quorum",
            "a backdated one-key carrier",
        );
        assert!(srb::active(d, &f, &d2).await);

        // Now, one key: refused; with f's cosignature (2 of 3): admitted.
        let mut row = orc::carrier_row(&framed(&d1, &f, &d2, srb::ms_now()).await).unwrap();
        refused(
            put(d, row.clone()).await,
            "carrier_without_roster_quorum",
            "one key of three",
        );
        // A cosignature by a key off the roster does not count.
        let outsider = format!("x-{tag}");
        srb::keys(d, &[&outsider]).await;
        let mut off = row.clone();
        cosign(&mut off, &outsider);
        refused(
            put(d, off).await,
            "carrier_without_roster_quorum",
            "a cosigner off the roster",
        );

        // Byte-different: the cosigned row with one member changed.
        cosign(&mut row, &f);
        let mut tampered = row.clone();
        tampered
            .attestation_envelope
            .as_object_mut()
            .unwrap()
            .insert("score".to_owned(), (-2).into());
        refused(
            put(d, tampered).await,
            "typed_diverges_from_envelope",
            "a byte-different carrier",
        );

        put(d, row).await.expect("I1155: a strict majority admits");
        assert!(
            !srb::active(d, &f, &d2).await,
            "I1155: the quorum carrier revokes"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_node_memory() {
        let (a, b) = (
            crate::store::memory::MemoryBackend::new(),
            crate::store::memory::MemoryBackend::new(),
        );
        bodies::i1155_a_node_carrier_reaches_a_stranger(&a, &b, &tag("m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_user_memory() {
        let d = crate::store::memory::MemoryBackend::new();
        bodies::i1155_a_user_carrier_needs_the_quorum(&d, &tag("m")).await;
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_node_sqlite() {
        let (a, b) = (sqlite().await, sqlite().await);
        bodies::i1155_a_node_carrier_reaches_a_stranger(&a, &b, &tag("s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_user_sqlite() {
        bodies::i1155_a_user_carrier_needs_the_quorum(&sqlite().await, &tag("s")).await;
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_node_postgres() {
        let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
            return;
        };
        bodies::i1155_a_node_carrier_reaches_a_stranger(&a, &b, &tag("p")).await;
        eprintln!("i1155_node_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_user_postgres() {
        let Some(d) = postgres().await else { return };
        bodies::i1155_a_user_carrier_needs_the_quorum(&d, &tag("p")).await;
        eprintln!("i1155_user_postgres: RAN");
    }

    /// **I1155** (e): the open's migration mints the admissible carriers and
    /// NAMES a user self's legacy revocation that has no roster quorum. The
    /// two legacy framed rows are written raw (as a v58 node held them), then
    /// the open's rehome runs.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn migration_seed(
        d: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> (
        Vec<(
            crate::federation::types::IdentityOccurrenceRevocation,
            serde_json::Value,
            String,
        )>,
        String,
        (String, String),
    ) {
        use crate::federation::occurrence_revocation_carrier as orc;
        use crate::federation::self_roster_invariants::bodies as srb;
        use crate::federation::tier_ingest::test_support as ts;
        let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
        srb::three(d, &f, &d1, &d2).await;
        let (n, o) = (
            ts::fp_key_id(&format!("n-{tag}")),
            ts::fp_key_id(&format!("o-{tag}")),
        );
        bodies::node_with_occurrence(d, &n, &o).await;
        let mut rows = Vec::new();
        let mut node_id = String::new();
        for (framed, is_node) in [
            (bodies::framed(&d1, &f, &d2, srb::ms_now()).await, false),
            (bodies::framed(&n, &n, &o, srb::ms_now()).await, true),
        ] {
            if is_node {
                node_id = orc::carrier_row(&framed).unwrap().attestation_id;
            }
            let mut rev = framed.revocation().unwrap();
            rev.persist_row_hash =
                crate::federation::types::compute_persist_row_hash(&rev).unwrap();
            rows.push((
                rev,
                framed.signed_envelope.clone(),
                serde_json::to_string(&framed.signature).unwrap(),
            ));
        }
        (rows, node_id, (f, d2))
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn migration_check(
        d: &dyn crate::federation::FederationDirectory,
        report: crate::federation::key_plane::KeyPlaneRehomeReport,
        node_id: &str,
        user_pair: (String, String),
    ) {
        assert!(
            d.get_attestation(node_id).await.unwrap().is_some(),
            "I1155: the node's legacy revocation now has its carrier: {report:?}"
        );
        assert!(
            report.carriers.without_quorum.contains(&user_pair),
            "I1155: the user self's legacy revocation without a quorum is NAMED: {report:?}"
        );
        assert_eq!(report.legacy_framed_occurrence_revocations, 2, "{report:?}");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_migration_sqlite() {
        let b = sqlite().await;
        let (rows, node_id, user_pair) = migration_seed(&b, &tag("ms")).await;
        for r in &rows {
            crate::federation::key_plane_retired_invariants::bodies::seed_raw_framed_sqlite(&b, r)
                .await;
        }
        b.test_execute(
            "UPDATE federation_identity_occurrence_revocations SET legacy_framed = 1 \
              WHERE signed_envelope IS NOT NULL",
        )
        .await;
        let report = b.rehome_key_plane_at_open().await.unwrap();
        migration_check(&b, report, &node_id, user_pair).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1155_migration_postgres() {
        let Some(b) = postgres().await else { return };
        let (rows, node_id, user_pair) = migration_seed(&b, &tag("mp")).await;
        for r in &rows {
            crate::federation::key_plane_retired_invariants::bodies::seed_raw_framed_postgres(
                &b, r,
            )
            .await;
        }
        b.test_execute(
            "UPDATE cirislens.federation_identity_occurrence_revocations SET legacy_framed = true \
              WHERE signed_envelope IS NOT NULL",
        )
        .await;
        let report = b.rehome_key_plane_at_open().await.unwrap();
        migration_check(&b, report, &node_id, user_pair).await;
        eprintln!("i1155_migration_postgres: RAN");
    }
}
