//! v51.0.0 invariants that need a real backend door (the parser-level and
//! engine-level ones live beside their code):
//!
//! - **I122 (CIRISPersist#923)** — the sealed-descriptor doors: "may open the
//!   descriptor" ⇔ "may open the bytes" — member opens, stranger is
//!   `NotGranted`, a plaintext row is `InvalidArgument`, a descriptor sealed for
//!   another blob (or the blob's own ciphertext) fails after authorization, the
//!   plaintext cap holds. On sqlite and postgres over the two-node community
//!   ladder (#876's fixture).
//! - **I126 (CIRISPersist#941)** — the live owner of a NODE may withdraw a
//!   row that node attested (rule 1 lifted to the producer's principal, CC
//!   3.4.7.3) — but only a row produced while the issuer already owned the
//!   node; a stranger is refused. On memory, sqlite and postgres.
//! - **I125 (CIRISPersist#933)** — on postgres, `put_attestation`'s three
//!   projections run INSIDE the row's transaction: a projection that fails
//!   rolls the row back (no committed, unprojected `withdraws`), and the
//!   retry — with the projection answering — inserts and projects.
//!
//! The fault is a `cfg(test)` one-shot inside the postgres door
//! (`store::test_hooks`, the PR #921 review shape): a wrapping double cannot
//! reach a backend's own transaction.

#[cfg(all(test, feature = "postgres"))]
mod postgres {
    use crate::federation::admission::steward_liveness_test_support::{register, signed_row};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, SignedAttestation};
    use crate::federation::{AttestationOutcome, Error, FederationDirectory};
    use crate::store::Backend as _;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// I125 — a failed `consent_peer_set` projection leaves NO row; the retry
    /// inserts. The same statement sequence that committed the row and then
    /// projected it as autocommit (v17.4.0 … v50.0.0) would have left the row
    /// with its revocation never folded, and the retry would have dedupped to
    /// `AlreadyHeld` without re-projecting.
    #[tokio::test]
    async fn i125_a_failed_projection_rolls_the_row_back_on_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let d: &dyn FederationDirectory = &b;
        let s = suffix();
        let granter = format!("g933-{s}");
        let recipient = format!("r933-{s}");
        register(d, &granter, &[it::USER]).await;
        register(d, &recipient, &[it::PRIMITIVE]).await;
        let mut row = signed_row(
            &granter,
            &recipient,
            attestation_type::DELEGATES_TO,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "scope": ["infra:serve"] }),
        );
        ts::reseal(&mut row);
        let id = row.attestation_id.clone();

        b.test_hooks().fail_next("pg_project_consent_peer_set", 1);
        let got = d
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await;
        assert!(
            matches!(&got, Err(Error::Backend(m)) if m.contains("injected transient")),
            "the projection's failure is the door's failure: {got:?}"
        );
        assert!(
            d.get_attestation(&id).await.unwrap().is_none(),
            "I125: a failed projection leaves no committed row (it ran inside the transaction)"
        );

        b.test_hooks().fail_next("pg_project_consent_peer_set", 0);
        let again = d
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap();
        assert_eq!(
            again,
            AttestationOutcome::Inserted,
            "the retry INSERTS (never `AlreadyHeld` over an unprojected row)"
        );
        assert!(d.get_attestation(&id).await.unwrap().is_some());
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod descriptor {
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY, FEDERATION};
    use crate::federation::{BlobBody, BlobError, BlobStorage, FederationDirectory};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// I122 — see the module doc.
    pub(crate) async fn i122_the_descriptor_opens_for_whoever_opens_the_bytes<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        let r = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"the room's bytes", None, None)
            .await
            .expect("A seals a community blob");
        assert_eq!(r.tier, CryptoTier::CommunityDek);
        let sha = r.at_rest_sha256;
        let plaintext = br#"{"format":"image/jpeg","name":"cat.jpg"}"#;

        // the minter's node seals and opens
        let sealed = e
            .seal_descriptor_for_blob(&sha, &l.node_a, plaintext)
            .await
            .expect("the sealer of the bytes seals the descriptor");
        assert_eq!(
            e.open_descriptor_for_blob(&sha, &l.node_a, &sealed)
                .await
                .unwrap(),
            plaintext,
            "round trip"
        );
        // the producer's own shape check admits what the door produced
        {
            use base64::Engine as _;
            crate::federation::media_source::check_sealed_descriptor_shape(
                &base64::engine::general_purpose::STANDARD.encode(&sealed),
            )
            .expect("the struct member's shape");
        }
        // a member's node (bob's, granted A's epoch on A — I188's precondition) opens it too
        assert_eq!(
            e.open_descriptor_for_blob(&sha, &l.node_b, &sealed)
                .await
                .unwrap(),
            plaintext,
            "a member who may open the bytes may open the descriptor"
        );
        // a stranger is NotGranted on both doors and learns nothing
        let stranger = format!("em-stranger-{run}");
        assert!(
            matches!(
                e.open_descriptor_for_blob(&sha, &stranger, &sealed).await,
                Err(BlobError::NotGranted { .. })
            ),
            "a stranger cannot open the descriptor"
        );
        assert!(
            matches!(
                e.seal_descriptor_for_blob(&sha, &stranger, plaintext).await,
                Err(BlobError::NotGranted { .. })
            ),
            "a stranger cannot seal one either"
        );
        // a plaintext row has nothing to seal under
        let p = e
            .put_blob_scoped(FEDERATION, None, b"public bytes", None, None)
            .await
            .expect("a plaintext blob");
        assert_eq!(p.tier, CryptoTier::Plaintext);
        assert!(
            matches!(
                e.seal_descriptor_for_blob(&p.at_rest_sha256, &l.node_a, plaintext)
                    .await,
                Err(BlobError::InvalidArgument(_))
            ),
            "a plaintext row is InvalidArgument at the seal door"
        );
        assert!(
            matches!(
                e.open_descriptor_for_blob(&p.at_rest_sha256, &l.node_a, &sealed)
                    .await,
                Err(BlobError::InvalidArgument(_))
            ),
            "and at the open door"
        );
        // a descriptor sealed for blob 1 does not open against blob 2 (AAD), and the
        // refusal is AFTER authorization — never NotGranted
        let r2 = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"other bytes", None, None)
            .await
            .unwrap();
        let cross = e
            .open_descriptor_for_blob(&r2.at_rest_sha256, &l.node_a, &sealed)
            .await;
        assert!(
            !matches!(cross, Ok(_) | Err(BlobError::NotGranted { .. })),
            "lifted onto another blob: refused after authorization, got {cross:?}"
        );
        // the blob's own ciphertext presented as a descriptor does not open (domain separation)
        let Some(BlobBody::Inline(body)) = l.ba.get_blob(&sha).await.unwrap() else {
            panic!("inline body")
        };
        let as_descriptor = e.open_descriptor_for_blob(&sha, &l.node_a, &body).await;
        assert!(
            !matches!(as_descriptor, Ok(_) | Err(BlobError::NotGranted { .. })),
            "the bytes' ciphertext is not a descriptor: {as_descriptor:?}"
        );
        // the plaintext cap
        let big = vec![
            b'x';
            crate::federation::at_rest_cascade::orchestrate::SEALED_DESCRIPTOR_PLAINTEXT_MAX
                + 1
        ];
        assert!(
            matches!(
                e.seal_descriptor_for_blob(&sha, &l.node_a, &big).await,
                Err(BlobError::InvalidArgument(_))
            ),
            "over the descriptor cap"
        );
    }

    macro_rules! runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::*;
                #[tokio::test]
                async fn i122() {
                    let Some((a, b)) = $dsns else { return };
                    i122_the_descriptor_opens_for_whoever_opens_the_bytes(&a, &b, &suffix(), $pick)
                        .await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as Pick<crate::store::sqlite::SqliteBackend>
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as Pick<crate::store::postgres::PostgresBackend>
    );
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod owner_withdraw {
    use crate::federation::admission::resolve_withdraws_admission_rule;
    use crate::federation::admission::steward_liveness_test_support::{
        register, signed_row, withdraws_of,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, SignedAttestation};
    use crate::federation::{Error, FederationDirectory};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// I126 — see the module doc.
    pub(crate) async fn i126_the_owner_withdraws_its_nodes_row(d: &dyn FederationDirectory) {
        let s = suffix();
        let (owner, node, stranger, subject) = (
            format!("ow-owner-{s}"),
            format!("ow-node-{s}"),
            format!("ow-stranger-{s}"),
            format!("ow-subject-{s}"),
        );
        register(d, &owner, &[it::USER]).await;
        register(d, &node, &[it::NODE]).await;
        register(d, &stranger, &[it::USER]).await;
        register(d, &subject, &[it::USER]).await;
        d.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&format!("ob-{s}"), &owner, &node),
        })
        .await
        .expect("the owner binds the node");
        // a row the node produced AFTER the binding (signed_row stamps now)
        let after = signed_row(
            &node,
            &subject,
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": "x:y" }),
        );
        assert_eq!(
            resolve_withdraws_admission_rule(d, &owner, &after)
                .await
                .unwrap(),
            1,
            "the node's live owner withdraws the node's row (rule 1, the producer's principal)"
        );
        assert!(
            matches!(
                resolve_withdraws_admission_rule(d, &stranger, &after).await,
                Err(Error::WithdrawsNotAdmitted { .. })
            ),
            "a stranger is refused"
        );
        // a row the node produced BEFORE the owner's binding (2026-05-01)
        let mut before = signed_row(
            &node,
            &subject,
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": "x:y" }),
        );
        before.asserted_at = "2026-04-01T00:00:00Z".parse().unwrap();
        ts::reseal(&mut before);
        assert!(
            matches!(
                resolve_withdraws_admission_rule(d, &owner, &before).await,
                Err(Error::WithdrawsNotAdmitted { .. })
            ),
            "the owner did not own the node when that row was produced"
        );
        // the node itself still withdraws its own rows (rule 1 unchanged)
        assert_eq!(
            resolve_withdraws_admission_rule(d, &node, &before)
                .await
                .unwrap(),
            1
        );
        // PR #943 review — A→B→A: the node moves to another owner, produces a
        // row, and moves back. The first owner's old binding (withdrawn at the
        // hand-off) predates the row but proves nothing about who owned the
        // node when it was produced — refused. The owner at that instant is
        // admitted while they own it.
        let other = format!("ow-other-{s}");
        register(d, &other, &[it::USER]).await;
        let put = |a: crate::federation::Attestation| async move {
            d.put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("stored")
        };
        put(withdraws_of(&owner, &node, &format!("ob-{s}"))).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        put(ts::owner_binding_attestation(
            &format!("ob2-{s}"),
            &other,
            &node,
        ))
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let under_other = signed_row(
            &node,
            &subject,
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": "x:y" }),
        );
        assert_eq!(
            resolve_withdraws_admission_rule(d, &other, &under_other)
                .await
                .unwrap(),
            1,
            "the owner at the row's instant withdraws it"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        put(withdraws_of(&other, &node, &format!("ob2-{s}"))).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        put(ts::owner_binding_attestation(
            &format!("ob3-{s}"),
            &owner,
            &node,
        ))
        .await;
        assert!(
            matches!(
                resolve_withdraws_admission_rule(d, &owner, &under_other).await,
                Err(Error::WithdrawsNotAdmitted { .. })
            ),
            "A→B→A: the returning owner did not own the node when B's row was produced"
        );
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i126() {
                    let Some(d) = $fresh.await else { return };
                    super::i126_the_owner_withdraws_its_nodes_row(
                        &d as &dyn crate::federation::FederationDirectory,
                    )
                    .await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
