//! v46.4.0 (CIRISPersist#891, `FSD/DRIVE_QUERY_AND_CHUNK_ADOPT.md`) — **the
//! drive query**: the cohort axes on [`AttestationFilter`], witnessed through
//! the door that already carries the §4.3 gate.
//!
//! Edge's drive listing ("my files in this room, resumable") was a client-side
//! filter over `list_attestations_since` — the REPLICATION cursor, which
//! composes no visibility gate — because `AttestationFilter` had no
//! `cohort_scope` axis. The door was never missing (`list_attestations` has
//! been filtered, cursor-paged and scope-gated since v4.0); the axis was.
//!
//! I142 measures the axis AND the order it composes in: the gate refuses a
//! room the caller is not in even when the filter names it, so a filter can
//! never widen an audience.

#[cfg(any(test, feature = "test-anchor"))]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::read::AttestationFilter;
    use crate::scope::{CallerAdmission, CallerScope};

    /// Seed one scoped attestation row through the local put door.
    async fn seed<B>(b: &B, id: &str, attester: &str, scope: &str, target: Option<&str>, dim: &str)
    where
        B: crate::federation::FederationDirectory + Sync,
    {
        // The cohort TARGET rides `attested_key_id` on this plane (V114 admits
        // a keyless family there) — it is the column the §4.3 gate compares.
        let mut row = ts::bare_attestation(
            id,
            attester,
            attester,
            &serde_json::json!({ "id": id, "dimension": dim, "cohort_scope": scope }),
        );
        // A real cohort row names its target TWICE, and the two gates read
        // different places: the WRITE gate (AV-45) reads the signed
        // envelope's cohort-target member, the READ gate (§4.3) compares the
        // `attested_key_id` column. The filter axis follows the read gate.
        if let Some(tk) = target {
            let member = match scope {
                "community" | "affiliations" => "community_key_id",
                "family" => "family_key_id",
                _ => "",
            };
            if !member.is_empty() {
                row.attestation_envelope[member] = serde_json::json!(tk);
            }
        }
        row.attestation_type = "scores".into();
        row.cohort_scope = scope.to_owned();
        row.subject_key_ids = vec![attester.to_owned()];
        ts::seal_row_in_place(attester, &mut row);
        b.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("I142 seed {id}: {e}"));
    }

    /// **I142 — the drive query.** The cohort axes select, AND with the other
    /// axes, survive paging, and never widen past the §4.3 gate.
    pub(crate) async fn i142_the_drive_query<B>(b: &B, s: &str)
    where
        B: crate::federation::FederationDirectory + crate::ceg::ReadEngine + Sync,
    {
        // `list_attestations` is a relational CEG read: the memory backend has
        // no substrate for it and says so. Its leg is `i142_mem`, which
        // measures the same axis through the scores door memory DOES serve.
        if let Err(crate::ceg::Error::Backend(msg)) = crate::ceg::ReadEngine::list_attestations(
            b,
            AttestationFilter::default(),
            None,
            1,
            CallerScope::Unauthenticated,
        )
        .await
        {
            if msg.contains("no relational read substrate") {
                return;
            }
        }
        let owner = format!("i142-owner-{s}");
        ts::register_identity_key(b, &owner, crate::federation::types::identity_type::USER).await;
        seed(
            b,
            &format!("i142-f1-{s}"),
            &owner,
            "self",
            None,
            "file:photo:v1",
        )
        .await;
        seed(
            b,
            &format!("i142-f2-{s}"),
            &owner,
            "self",
            None,
            "file:video:v1",
        )
        .await;
        seed(
            b,
            &format!("i142-note-{s}"),
            &owner,
            "self",
            None,
            "note:draft:v1",
        )
        .await;
        seed(
            b,
            &format!("i142-fed-{s}"),
            &owner,
            "federation",
            None,
            "file:public:v1",
        )
        .await;

        let me = || CallerScope::Authenticated {
            admission: CallerAdmission::for_test(owner.clone(), owner.clone(), [], []),
        };
        let ids = |f: AttestationFilter, sc: CallerScope| async move {
            let mut v: Vec<String> = crate::ceg::ReadEngine::list_attestations(b, f, None, 100, sc)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|a| a.attestation_id)
                .collect();
            v.sort();
            v
        };

        // The axis selects.
        assert_eq!(
            ids(
                AttestationFilter {
                    cohort_scope: Some("self".into()),
                    ..Default::default()
                },
                me()
            )
            .await,
            vec![
                format!("i142-f1-{s}"),
                format!("i142-f2-{s}"),
                format!("i142-note-{s}")
            ],
            "I142: `cohort_scope` selects the self rows and excludes the federation one"
        );
        // …and ANDs with the dimension axis: that IS the drive listing.
        assert_eq!(
            ids(
                AttestationFilter {
                    cohort_scope: Some("self".into()),
                    dimension_prefixes: vec!["file:".into()],
                    ..Default::default()
                },
                me()
            )
            .await,
            vec![format!("i142-f1-{s}"), format!("i142-f2-{s}")],
            "I142: the drive listing — cohort AND dimension, not OR"
        );
        // A stranger sees none of it: the GATE refuses, not the filter.
        let stranger = format!("i142-stranger-{s}");
        ts::register_identity_key(b, &stranger, crate::federation::types::identity_type::USER)
            .await;
        assert!(
            ids(
                AttestationFilter {
                    cohort_scope: Some("self".into()),
                    ..Default::default()
                },
                CallerScope::Authenticated {
                    admission: CallerAdmission::for_test(
                        stranger.clone(),
                        stranger.clone(),
                        [],
                        []
                    ),
                },
            )
            .await
            .is_empty(),
            "I142: naming a cohort in the filter never widens the audience past §4.3"
        );
        // The TARGETED cohorts (community / family) are NOT witnessed here and
        // are not claimed by this cut: AV-84 makes a targeted row name its own
        // PRODUCER in `attested_key_id`, and the §4.3 gate compares that column
        // against the caller's room set — an empty intersection by
        // construction, so no member can read their own room's rows through
        // this plane. Found by this fixture, filed as CIRISPersist#893 with the
        // reproduction. `cohort_scope` is a SELECTION and ships regardless: it
        // narrows what the gate already admitted and can never widen it, which
        // the stranger leg above measures.

        // Resumable: one row at a time, no repeat.
        let page1 = crate::ceg::ReadEngine::list_attestations(
            b,
            AttestationFilter {
                cohort_scope: Some("self".into()),
                dimension_prefixes: vec!["file:".into()],
                ..Default::default()
            },
            None,
            1,
            me(),
        )
        .await
        .unwrap();
        assert_eq!(page1.items.len(), 1, "I142: limit binds");
        let cur = page1
            .next_cursor
            .expect("I142: a full page hands back a cursor");
        let page2 = crate::ceg::ReadEngine::list_attestations(
            b,
            AttestationFilter {
                cohort_scope: Some("self".into()),
                dimension_prefixes: vec!["file:".into()],
                ..Default::default()
            },
            Some(cur),
            1,
            me(),
        )
        .await
        .unwrap();
        assert_eq!(
            page2.items.len(),
            1,
            "I142: the second page is the second row"
        );
        assert_ne!(
            page1.items[0].attestation_id, page2.items[0].attestation_id,
            "I142: paging does not repeat a row"
        );
    }

    /// **I142-mem — the axis on the scores plane, where the memory backend
    /// lives.** `list_attestations` has no memory substrate, so the memory
    /// twin of the cohort axis (`mem_scores_row_matches`) is measured through
    /// `list_scores` — the other door `sqlite_cohort_axes` / `pg_cohort_axes`
    /// are called from. Without this leg nothing would fail if the memory
    /// twin ignored the axis.
    pub(crate) async fn i142_mem_the_axis_on_the_scores_plane<B>(b: &B, s: &str)
    where
        B: crate::federation::FederationDirectory + crate::ceg::ReadEngine + Sync,
    {
        let owner = format!("i142m-owner-{s}");
        ts::register_identity_key(b, &owner, crate::federation::types::identity_type::USER).await;
        seed(
            b,
            &format!("i142m-self-{s}"),
            &owner,
            "self",
            None,
            "file:photo:v1",
        )
        .await;
        seed(
            b,
            &format!("i142m-fed-{s}"),
            &owner,
            "federation",
            None,
            "file:public:v1",
        )
        .await;
        let page = |f: AttestationFilter| {
            let owner = owner.clone();
            async move {
                let mut v: Vec<String> =
                    <B as crate::federation::FederationDirectory>::list_scores(
                        b, &owner, f, None, 100,
                    )
                    .await
                    .unwrap()
                    .items
                    .into_iter()
                    .map(|a| a.attestation_id)
                    .collect();
                v.sort();
                v
            }
        };
        let all = page(AttestationFilter {
            dimension_prefixes: vec!["file:".into()],
            ..Default::default()
        })
        .await;
        assert!(
            all.contains(&format!("i142m-fed-{s}")),
            "I142-mem: the federation row is on the scores plane to begin with: {all:?}"
        );
        assert_eq!(
            page(AttestationFilter {
                cohort_scope: Some("self".into()),
                dimension_prefixes: vec!["file:".into()],
                ..Default::default()
            })
            .await,
            vec![format!("i142m-self-{s}")],
            "I142-mem: the cohort axis selects on the scores plane too — the memory twin of \
             sqlite_cohort_axes / pg_cohort_axes"
        );
    }

    /// **I143 (from disk)** — the chunk adopt reaches Python: the receiving
    /// half of the scoped chunk DAG (#821) is bound, and classified.
    pub(crate) fn i143_the_chunk_adopt_reaches_python() {
        let pyo3 = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ffi/pyo3.rs"))
            .expect("read pyo3.rs");
        assert!(
            pyo3.contains("fn adopt_sealed_chunk_json("),
            "I143: the chunk twin of adopt_sealed_blob_json is not bound — a sibling device \
             can be SENT a chunk DAG and cannot adopt it (CIRISPersist#821)"
        );
        let tax = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/ffi_taxonomy.tsv"
        ))
        .expect("read ffi_taxonomy.tsv");
        assert!(
            tax.contains("adopt_sealed_chunk_json"),
            "I143: the door exists and is unclassified"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn i143() {
        super::bodies::i143_the_chunk_adopt_reaches_python();
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i142() {
                    let Some(b) = $fresh.await else { return };
                    super::super::bodies::i142_the_drive_query(&b, &super::suffix()).await
                }

                #[tokio::test]
                async fn i142_mem() {
                    let Some(b) = $fresh.await else { return };
                    super::super::bodies::i142_mem_the_axis_on_the_scores_plane(
                        &b,
                        &super::suffix(),
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
