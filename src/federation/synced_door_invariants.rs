//! v50.0.0 (CIRISPersist#917; `FSD/SECOND_DEVICE.md` §4) — **I189: the
//! attributed sync door has the typed pre-write outcome.**
//!
//! `put_attestation_synced(record, peer)` and `apply_replicated_attestation`
//! classify the same bytes to the same [`ReplicatedAttestationOutcome`]
//! variant; a decoration-only re-delivery is a duplicate
//! (`Refused { AlreadyPresentIdentical }`, which CIRISEdge books as
//! `Duplicate`), never `Error::Conflict`; a different signed row under the id
//! is `Refused { ConflictingAttestation }`; and the door still meters by
//! `shares_cohort_with(peer)` — a stranger over budget is refused with the
//! same `Error::RateLimited` the wire door gives, and nothing is stored.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::attestation_apply::{
        AttestationRefusalReason as Reason, ReplicatedAttestationOutcome as Outcome,
    };
    use crate::federation::bootstrap_admission::test_support::scores_row;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{identity_type, Attestation, Community, CommunityMember};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    /// The parties. `us` is the node's own key (the caller installed it with
    /// `set_self_key_id`); `mate` shares a community with it; `stranger` does
    /// not; `author` signs the rows a sync carries.
    pub struct Parties {
        pub us: String,
        pub mate: String,
        pub stranger: String,
        pub author: String,
    }

    impl Parties {
        pub fn new(us: &str, tag: &str) -> Self {
            Self {
                us: us.to_owned(),
                mate: format!("{tag}-mate"),
                stranger: format!("{tag}-stranger"),
                author: format!("{tag}-author"),
            }
        }
    }

    /// Register every party and the community `us` and `mate` share. Run on
    /// each directory a body touches, so both see the same cohort.
    async fn seat(d: &dyn FederationDirectory, p: &Parties, tag: &str) {
        let comm = format!("{tag}-comm");
        for k in [&p.us, &p.mate, &p.stranger, &p.author, &comm] {
            ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
        }
        let now = chrono::Utc::now();
        d.put_community(ts::sign_community(
            &p.us,
            Community {
                community_key_id: comm.clone(),
                community_name: format!("{tag}-c"),
                members: vec![
                    CommunityMember {
                        key_id: p.us.clone(),
                        joined_at: now,
                        role: Some("founder".to_owned()),
                    },
                    CommunityMember {
                        key_id: p.mate.clone(),
                        joined_at: now,
                        role: None,
                    },
                ],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("({tag}) I189: the community admits: {e}"));
        let shares = |peer: String| async move {
            crate::federation::replication::admission::shares_cohort_with(d, &p.us, &peer)
                .await
                .unwrap_or_else(|e| panic!("({tag}) I189: cohort resolution failed: {e}"))
        };
        assert!(
            shares(p.mate.clone()).await,
            "({tag}) I189 fixture: `{}` must share `{comm}` with `{}`",
            p.mate,
            p.us
        );
        assert!(
            !shares(p.stranger.clone()).await,
            "({tag}) I189 fixture: `{}` must share no cohort with `{}`",
            p.stranger,
            p.us
        );
    }

    /// The same signed assertion with different UNSIGNED decoration: the
    /// envelope re-signed and a later `scrub_timestamp` (the column, not the
    /// envelope's signed instants). `original_content_hash`, the producer
    /// pair and every signed byte are unchanged; `persist_row_hash` moves.
    fn decorated(row: &Attestation) -> Attestation {
        let mut deco = row.clone();
        let (och, classical, pqc) =
            ts::sign_envelope(&row.scrub_key_id, &deco.attestation_envelope);
        assert_eq!(
            och, row.original_content_hash,
            "same signed bytes, same hash"
        );
        deco.scrub_signature_classical = classical;
        deco.scrub_signature_pqc = pqc;
        deco.scrub_timestamp += chrono::Duration::seconds(11);
        assert_ne!(
            crate::federation::types::compute_persist_row_hash(&deco).expect("hash"),
            crate::federation::types::compute_persist_row_hash(row).expect("hash"),
            "the fixture must actually differ in decoration"
        );
        deco
    }

    /// A genuinely different signed row under the same id.
    fn rival(row: &Attestation) -> Attestation {
        let mut rival = row.clone();
        rival.attestation_envelope["note"] = serde_json::json!("a different mint of the same id");
        ts::reseal(&mut rival);
        assert_ne!(rival.original_content_hash, row.original_content_hash);
        rival
    }

    fn signed(a: &Attestation) -> SignedAttestation {
        SignedAttestation {
            attestation: a.clone(),
        }
    }

    async fn stored(d: &dyn FederationDirectory, id: &str) -> Option<Attestation> {
        d.get_attestation(id).await.expect("get_attestation")
    }

    /// Arms (a)–(e). `a` is driven through the synced door, `b` (a fresh
    /// directory) through the unattributed door, with the SAME bytes in the
    /// same order.
    pub async fn i189_one_outcome_on_both_doors(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        p: &Parties,
        tag: &str,
    ) {
        seat(a, p, tag).await;
        seat(b, p, tag).await;
        let id = format!("{tag}-row");
        let row = scores_row(&id, &p.author, &p.author, "trust:demo:v1");
        let deco = decorated(&row);
        let rival = rival(&row);

        // (a) first delivery.
        let got = a
            .put_attestation_synced(signed(&row), &p.mate)
            .await
            .unwrap_or_else(|e| panic!("({tag}) I189(a): {e}"));
        assert_eq!(
            got,
            Outcome::Inserted,
            "({tag}) I189(a): a new row is Inserted"
        );
        let held = stored(a, &id)
            .await
            .unwrap_or_else(|| panic!("({tag}) I189(a): Inserted must mean stored"));

        // (b) byte-identical re-delivery — the mint, and the stored row as the
        // wire re-offers it.
        for (what, offer) in [("mint", &row), ("stored row", &held)] {
            let got = a
                .put_attestation_synced(signed(offer), &p.mate)
                .await
                .unwrap_or_else(|e| panic!("({tag}) I189(b) {what}: {e}"));
            assert_eq!(
                got,
                Outcome::Unchanged,
                "({tag}) I189(b): a byte-identical re-delivery ({what}) is Unchanged"
            );
        }

        // (c) decoration-only re-delivery — a duplicate, never a Conflict.
        let got = a.put_attestation_synced(signed(&deco), &p.mate).await;
        assert!(
            matches!(
                got,
                Ok(Outcome::Refused {
                    reason: Reason::AlreadyPresentIdentical
                })
            ),
            "({tag}) I189(c): the same signed assertion with different unsigned decoration \
             is `already_present_identical` on the attributed door — got {got:?}. \
             `Err(Conflict)` is the pre-#917 binary verdict CIRISEdge booked as a refusal"
        );
        let after = stored(a, &id).await.expect("still held");
        assert_eq!(
            (
                &after.persist_row_hash,
                &after.scrub_signature_pqc,
                after.scrub_timestamp
            ),
            (
                &held.persist_row_hash,
                &held.scrub_signature_pqc,
                held.scrub_timestamp
            ),
            "({tag}) I189(c): a duplicate must leave the stored row untouched"
        );

        // (d) a different signed row under the same id.
        let got = a.put_attestation_synced(signed(&rival), &p.mate).await;
        assert!(
            matches!(
                got,
                Ok(Outcome::Refused {
                    reason: Reason::ConflictingAttestation
                })
            ),
            "({tag}) I189(d): a different signed row under an occupied id is \
             `conflicting_attestation` — got {got:?}"
        );
        let after = stored(a, &id).await.expect("still held");
        assert_eq!(
            after.persist_row_hash, held.persist_row_hash,
            "({tag}) I189(d): first-seen wins; the stored row is untouched"
        );

        // (e) the same bytes, same order, through the unattributed door.
        let synced = [
            Outcome::Inserted,
            Outcome::Unchanged,
            Outcome::Refused {
                reason: Reason::AlreadyPresentIdentical,
            },
            Outcome::Refused {
                reason: Reason::ConflictingAttestation,
            },
        ];
        for (offer, want) in [&row, &row, &deco, &rival].into_iter().zip(synced) {
            let got = b
                .apply_replicated_attestation(signed(offer))
                .await
                .unwrap_or_else(|e| panic!("({tag}) I189(e): {e}"));
            assert_eq!(
                got, want,
                "({tag}) I189(e): the unattributed door must classify these bytes as the \
                 attributed door did"
            );
        }
    }

    /// Arm (f): the peer is still metered. A stranger's rows are charged to
    /// the author's own bucket (the wire door's budget), so once that bucket
    /// is spent the synced door refuses a fresh row from the stranger with the
    /// wire door's `RateLimited` and stores nothing — while the SAME row from
    /// a cohort mate spends the sync budget and lands.
    pub async fn i189_the_peer_is_still_metered(
        d: &dyn FederationDirectory,
        p: &Parties,
        tag: &str,
    ) {
        seat(d, p, tag).await;
        // Signed and ready BEFORE the drain: the window refills in real time
        // (~150 KB/s on the byte dimension), so nothing slow may sit between
        // the drain and the charge this row must fail.
        let id = format!("{tag}-metered");
        let mut row = scores_row(&id, &p.author, &p.author, "trust:demo:v1");
        row.attestation_envelope["pad"] = serde_json::json!("p".repeat(600 * 1024));
        ts::reseal(&mut row);

        // Drain the author's per-peer byte budget THROUGH THE SYNCED DOOR under
        // the stranger — unsigned junk the gates after the quota refuse, so
        // nothing is stored and each call costs its envelope size. Step the
        // size down each time the quota says no, until less than 64 KiB is
        // left — about one iteration's refill, and a tenth of the row below.
        let mut size = 1_100 * 1024;
        let mut n = 0u32;
        let mut limited = 0u32;
        while size >= 64 * 1024 {
            n += 1;
            assert!(n < 400, "({tag}) I189(f): the drain did not converge");
            let mut junk = scores_row(
                &format!("{tag}-junk-{n}"),
                &p.author,
                &p.author,
                "trust:demo:v1",
            );
            junk.attestation_envelope["pad"] = serde_json::json!("j".repeat(size));
            match d.put_attestation_synced(signed(&junk), &p.stranger).await {
                Err(Error::RateLimited { .. }) => {
                    limited += 1;
                    size /= 2;
                }
                Err(_) => {}
                Ok(o) => panic!("({tag}) I189(f): an unsigned junk row was admitted: {o:?}"),
            }
        }
        assert!(
            limited > 0,
            "({tag}) I189(f): the stranger's budget was never reached"
        );

        let got = d.put_attestation_synced(signed(&row), &p.stranger).await;
        assert!(
            matches!(got, Err(Error::RateLimited { .. })),
            "({tag}) I189(f): a stranger routed through the synced door is metered as a \
             stranger — over budget it is refused with RateLimited, as before #917. Got {got:?}"
        );
        assert!(
            stored(d, &id).await.is_none(),
            "({tag}) I189(f): a metered refusal stores nothing"
        );
        let wire = d.put_attestation(signed(&row)).await;
        assert!(
            matches!(wire, Err(Error::RateLimited { .. })),
            "({tag}) I189(f): the wire door charges the same bucket — got {wire:?}"
        );
        let got = d
            .put_attestation_synced(signed(&row), &p.mate)
            .await
            .unwrap_or_else(|e| panic!("({tag}) I189(f): a cohort mate's sync admits: {e}"));
        assert_eq!(
            got,
            Outcome::Inserted,
            "({tag}) I189(f): the same row from a cohort mate spends the sync budget and lands"
        );
    }
}

#[cfg(test)]
mod run {
    fn tag(arm: &str) -> String {
        format!("i189-{arm}-{}", uuid::Uuid::new_v4().simple())
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i189_one_outcome_on_both_doors() {
                    let tag = super::tag("doors");
                    let us = format!("{tag}-us");
                    let (Some(a), Some(b)) = ($fresh(&us).await, $fresh(&us).await) else {
                        return;
                    };
                    let p = super::super::bodies::Parties::new(&us, &tag);
                    super::super::bodies::i189_one_outcome_on_both_doors(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &p,
                        &tag,
                    )
                    .await
                }
                #[tokio::test]
                async fn i189_the_peer_is_still_metered() {
                    let tag = super::tag("meter");
                    let us = format!("{tag}-us");
                    let Some(d) = $fresh(&us).await else { return };
                    let p = super::super::bodies::Parties::new(&us, &tag);
                    super::super::bodies::i189_the_peer_is_still_metered(
                        &d as &dyn FederationDirectory,
                        &p,
                        &tag,
                    )
                    .await
                }
            }
        };
    }

    async fn memory(us: &str) -> Option<crate::store::memory::MemoryBackend> {
        let b = crate::store::memory::MemoryBackend::new();
        b.set_self_key_id(Some(us.to_owned()));
        Some(b)
    }
    runners!(memory_backend, super::memory);

    #[cfg(feature = "sqlite")]
    async fn sqlite(us: &str) -> Option<crate::store::sqlite::SqliteBackend> {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.set_self_key_id(Some(us.to_owned()));
        Some(b)
    }
    #[cfg(feature = "sqlite")]
    runners!(sqlite_backend, super::sqlite);

    #[cfg(feature = "postgres")]
    async fn postgres(us: &str) -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.set_self_key_id(Some(us.to_owned()));
        Some(b)
    }
    #[cfg(feature = "postgres")]
    runners!(postgres_backend, super::postgres);
}
