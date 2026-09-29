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

    /// I125b (PR #943 review) — a DIFFERENT row under an occupied id is
    /// refused, and its projections are not committed: a consent grant's
    /// peer (the `consent_peer_set` projection, which gates replication)
    /// never enters the peer set from a row that was not stored.
    #[tokio::test]
    async fn i125b_a_refused_duplicate_projects_nothing_on_postgres() {
        use crate::federation::consent_peer_set::test_support::grant;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let d: &dyn FederationDirectory = &b;
        let s = suffix();
        let node = format!("n943-{s}");
        let (first, second) = (format!("p943a-{s}"), format!("p943b-{s}"));
        ts::register_hybrid_key(d, &node).await;
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            d.put_attestation(SignedAttestation {
                attestation: grant(&id, &node, &first),
            })
            .await
            .unwrap(),
            AttestationOutcome::Inserted
        );
        let got = d
            .put_attestation(SignedAttestation {
                attestation: grant(&id, &node, &second),
            })
            .await;
        assert!(
            !matches!(got, Ok(AttestationOutcome::Inserted)),
            "a different row under an occupied id is not stored: {got:?}"
        );
        assert_eq!(
            d.list_consent_peers(&node).await.unwrap(),
            vec![first],
            "the refused row's peer never entered the replication peer set"
        );
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
            e.open_descriptor_for_blob(&sha, &l.node_a, &sealed, None)
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
            e.open_descriptor_for_blob(&sha, &l.node_b, &sealed, None)
                .await
                .unwrap(),
            plaintext,
            "a member who may open the bytes may open the descriptor"
        );
        // #923 amendment 1 (CIRISEdge#710 D8) — a blob sealed under its ROW's
        // associated data: the descriptor opens only under that row's data; a
        // pointer transplanted onto another row (or presented with none)
        // reveals nothing, refused AFTER authorization
        let row1: &[u8] = b"row-1|author|2026-09-28T00:00:00Z|media";
        let bound = e
            .put_blob_scoped(
                COMMUNITY,
                Some(&l.comm),
                b"row-bound bytes",
                None,
                Some(row1),
            )
            .await
            .expect("a row-bound community blob");
        let sealed_bound = e
            .seal_descriptor_for_blob(&bound.at_rest_sha256, &l.node_a, plaintext)
            .await
            .unwrap();
        assert_eq!(
            e.open_descriptor_for_blob(&bound.at_rest_sha256, &l.node_a, &sealed_bound, Some(row1))
                .await
                .unwrap(),
            plaintext,
            "the referencing row opens its descriptor"
        );
        for other in [Some(&b"row-2|author|2026-09-28T00:00:01Z|media"[..]), None] {
            let t = e
                .open_descriptor_for_blob(&bound.at_rest_sha256, &l.node_a, &sealed_bound, other)
                .await;
            assert!(
                !matches!(t, Ok(_) | Err(BlobError::NotGranted { .. })),
                "a transplanted pointer ({other:?}) must reveal nothing: {t:?}"
            );
        }
        // a stranger is NotGranted on both doors and learns nothing
        let stranger = format!("em-stranger-{run}");
        assert!(
            matches!(
                e.open_descriptor_for_blob(&sha, &stranger, &sealed, None)
                    .await,
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
                e.open_descriptor_for_blob(&p.at_rest_sha256, &l.node_a, &sealed, None)
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
            .open_descriptor_for_blob(&r2.at_rest_sha256, &l.node_a, &sealed, None)
            .await;
        assert!(
            !matches!(cross, Ok(_) | Err(BlobError::NotGranted { .. })),
            "lifted onto another blob: refused after authorization, got {cross:?}"
        );
        // the blob's own ciphertext presented as a descriptor does not open (domain separation)
        let Some(BlobBody::Inline(body)) = l.ba.get_blob(&sha).await.unwrap() else {
            panic!("inline body")
        };
        let as_descriptor = e
            .open_descriptor_for_blob(&sha, &l.node_a, &body, None)
            .await;
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
    use crate::federation::admission::steward_liveness_test_support::{
        register, signed_row, withdraws_of,
    };
    use crate::federation::admission::{owner_of, resolve_withdraws_admission_rule};
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
        // PR #943 review — A→B→A. The first owner's binding LAPSES (its
        // expiry), the node is bound to another owner and produces a row, that
        // owner withdraws, and the first owner binds the node again. The old
        // binding predates the row but was not in force when it was produced —
        // refused. (A withdrawal by the granter itself retires every later edge
        // from it too, so A→B→A through a self-withdrawal cannot return to A;
        // the reachable paths are a lapse and a CC 4.3 reclaim.)
        let node2 = format!("ow-node2-{s}");
        let other = format!("ow-other-{s}");
        register(d, &node2, &[it::NODE]).await;
        register(d, &other, &[it::USER]).await;
        let put = |a: crate::federation::Attestation| async move {
            d.put_attestation(SignedAttestation { attestation: a })
                .await
                .expect("stored")
        };
        let mut lapsing = ts::owner_binding_attestation(&format!("ob1-{s}"), &owner, &node2);
        lapsing.expires_at = Some(chrono::Utc::now() + chrono::Duration::milliseconds(300));
        ts::reseal(&mut lapsing);
        put(lapsing).await;
        assert_eq!(owner_of(d, &node2).await.unwrap(), Some(owner.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(
            owner_of(d, &node2).await.unwrap(),
            None,
            "precondition: the first binding lapsed"
        );
        put(ts::owner_binding_attestation(
            &format!("ob2-{s}"),
            &other,
            &node2,
        ))
        .await;
        assert_eq!(owner_of(d, &node2).await.unwrap(), Some(other.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let under_other = signed_row(
            &node2,
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
        put(withdraws_of(&other, &node2, &format!("ob2-{s}"))).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        put(ts::owner_binding_attestation(
            &format!("ob3-{s}"),
            &owner,
            &node2,
        ))
        .await;
        assert_eq!(
            owner_of(d, &node2).await.unwrap(),
            Some(owner.clone()),
            "precondition: the first owner owns the node again, alone"
        );
        assert!(
            matches!(
                resolve_withdraws_admission_rule(d, &owner, &under_other).await,
                Err(Error::WithdrawsNotAdmitted { .. })
            ),
            "A→B→A: the returning owner did not own the node when B's row was produced"
        );
        // the hand-off: C owns node3 and withdraws its binding; A binds node3
        // and the node produces a row. C's era ended (its withdrawal) before
        // the row, so A — the only owner in force then — retracts it.
        let node3 = format!("ow-node3-{s}");
        let prior = format!("ow-prior-{s}");
        register(d, &node3, &[it::NODE]).await;
        register(d, &prior, &[it::USER]).await;
        put(ts::owner_binding_attestation(
            &format!("obc-{s}"),
            &prior,
            &node3,
        ))
        .await;
        put(withdraws_of(&prior, &node3, &format!("obc-{s}"))).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        put(ts::owner_binding_attestation(
            &format!("oba-{s}"),
            &owner,
            &node3,
        ))
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let under_a = signed_row(
            &node3,
            &subject,
            attestation_type::SCORES,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "dimension": "x:y" }),
        );
        assert_eq!(
            resolve_withdraws_admission_rule(d, &owner, &under_a)
                .await
                .unwrap(),
            1,
            "a hand-off: the previous owner's era ended before the row"
        );
        // the fixture stamps every owner binding 2026-05-01 — i.e. A's ob3 is
        // already BACKDATED into B's era; the refusal above is the backdating
        // witness too (B's binding was in force at the row's instant)
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

/// **I127 (CIRISPersist#942)** — the custody view, on sqlite and postgres over
/// the two-node community ladder (#876's fixture): a community blob lists the
/// members of its sealing epoch and counts this node's copy; a self blob lists
/// the owner's grant recipients and says its copies elsewhere are NOT
/// observable (never "1 copy"); a commons blob lists no access and is
/// observable; a stranger is `NotGranted` and learns nothing.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod custody {
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::types::cohort_scope::{COMMUNITY, FEDERATION, SELF};
    use crate::federation::{BlobError, BlobStorage, FederationDirectory};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    pub(crate) async fn i127_the_custody_view<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let e = &l.engine_a;
        // community
        let c = e
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"room bytes", None, None)
            .await
            .unwrap();
        let v = e.blob_custody(&c.at_rest_sha256, &l.node_a).await.unwrap();
        assert_eq!(v.tier, "community_dek");
        assert!(
            v.held_here && v.copies_observable && v.copies_known >= 1,
            "{v:?}"
        );
        let devices: Vec<&String> = v.access.iter().flat_map(|a| &a.devices).collect();
        assert!(
            devices.contains(&&l.node_a) && devices.contains(&&l.node_b),
            "both members' devices: {v:?}"
        );
        assert!(v.access.iter().all(|a| a.via == "community_epoch_grant"));
        // self
        let s = e
            .put_blob_scoped(SELF, Some(&l.alice), b"my bytes", None, None)
            .await
            .unwrap();
        let v = e.blob_custody(&s.at_rest_sha256, &l.node_a).await.unwrap();
        assert_eq!(v.tier, "invisible_encrypted");
        assert!(v.held_here);
        assert!(
            !v.copies_observable,
            "self/family copies are never countable today: {v:?}"
        );
        assert!(
            v.why
                .as_deref()
                .is_some_and(|w| w.contains("never announced")),
            "{v:?}"
        );
        assert!(
            v.access
                .iter()
                .flat_map(|a| &a.devices)
                .all(|d| d != crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT),
            "persist's self-retention row never appears as a device"
        );
        assert!(
            !v.access.is_empty(),
            "the owner's device holds a key: {v:?}"
        );
        // commons
        let p = e
            .put_blob_scoped(FEDERATION, None, b"public bytes", None, None)
            .await
            .unwrap();
        let v = e.blob_custody(&p.at_rest_sha256, &l.node_a).await.unwrap();
        assert_eq!(v.tier, "plaintext");
        assert!(v.access.is_empty() && v.copies_observable, "{v:?}");
        // a stranger learns nothing
        let stranger = format!("cu-stranger-{run}");
        assert!(
            matches!(
                e.blob_custody(&c.at_rest_sha256, &stranger).await,
                Err(BlobError::NotGranted { .. })
            ),
            "a stranger is refused the community blob's custody view"
        );
        assert!(
            matches!(
                e.blob_custody(&s.at_rest_sha256, &stranger).await,
                Err(BlobError::NotGranted { .. })
            ),
            "and the self blob's"
        );
    }

    macro_rules! runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::*;
                #[tokio::test]
                async fn i127() {
                    let Some((a, b)) = $dsns else { return };
                    i127_the_custody_view(&a, &b, &suffix(), $pick).await
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
