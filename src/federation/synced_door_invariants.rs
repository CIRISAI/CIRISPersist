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
                prev_head_digest: String::new(),
                charter_digest: String::new(),
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

    /// The stored row still carries the held row's bytes.
    async fn untouched(seat: &dyn FederationDirectory, held: &Attestation, tag: &str, what: &str) {
        let after = stored(seat, &held.attestation_id)
            .await
            .expect("still held");
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
            "({tag}) I189{what}: the stored row must be untouched"
        );
    }

    /// Where a body seats its fixture and reads the stored row (`seat`, a
    /// backend) and which directory it drives the door through (`door`: the
    /// same backend, or an `OpsDirectory` over it — the capsule arm).
    #[derive(Clone, Copy)]
    pub struct Node<'a> {
        pub seat: &'a dyn FederationDirectory,
        pub door: &'a dyn FederationDirectory,
    }

    impl<'a> Node<'a> {
        pub fn direct(d: &'a dyn FederationDirectory) -> Self {
            Self { seat: d, door: d }
        }
    }

    /// A row that COPIES the held row's `original_content_hash`, producer pair
    /// and signatures onto a different envelope — a claim of "same assertion"
    /// its own bytes do not support.
    fn forged(row: &Attestation, other: &Attestation) -> Attestation {
        let mut forged = row.clone();
        forged.attestation_envelope = other.attestation_envelope.clone();
        forged
    }

    /// A replay of the held id whose envelope is over the size cap. The claim
    /// fields are the held row's, so only the size gate can stop the plan from
    /// canonicalizing it for free.
    fn oversize(row: &Attestation) -> Attestation {
        let mut big = row.clone();
        big.attestation_envelope["pad"] = serde_json::json!("o".repeat(1_100 * 1024));
        big
    }

    /// Arms (a)–(e), (h), (i). `a` is driven through the synced door, `b` (a
    /// fresh node) through the unattributed door, with the SAME bytes in the
    /// same order.
    pub async fn i189_one_outcome_on_both_doors(a: Node<'_>, b: Node<'_>, p: &Parties, tag: &str) {
        seat(a.seat, p, tag).await;
        seat(b.seat, p, tag).await;
        let id = format!("{tag}-row");
        let mut row = scores_row(&id, &p.author, &p.author, "trust:demo:v1");
        // #964 — an instant whose microseconds end in 000 with a sub-µs tail:
        // postgres stores .123000, and the read-back row serializes it as
        // .123. The stored-row re-offer must still hash to the stored hash.
        row.scrub_timestamp =
            chrono::DateTime::from_timestamp(row.scrub_timestamp.timestamp(), 123_000_789)
                .expect("instant");
        let deco = decorated(&row);
        let rival = rival(&row);
        let forged = forged(&row, &rival);
        let synced = |offer: &Attestation| a.door.put_attestation_synced(signed(offer), &p.mate);

        // (a) first delivery.
        let got = synced(&row)
            .await
            .unwrap_or_else(|e| panic!("({tag}) I189(a): {e}"));
        assert_eq!(
            got,
            Outcome::Inserted,
            "({tag}) I189(a): a new row is Inserted"
        );
        let held = stored(a.seat, &id)
            .await
            .unwrap_or_else(|| panic!("({tag}) I189(a): Inserted must mean stored"));

        // (b) byte-identical re-delivery — the mint, and the stored row as the
        // wire re-offers it.
        for (what, offer) in [("mint", &row), ("stored row", &held)] {
            let got = synced(offer)
                .await
                .unwrap_or_else(|e| panic!("({tag}) I189(b) {what}: {e}"));
            assert_eq!(
                got,
                Outcome::Unchanged,
                "({tag}) I189(b): a byte-identical re-delivery ({what}) is Unchanged"
            );
        }

        // (c) decoration-only re-delivery — a duplicate, never a Conflict.
        let got = synced(&deco).await;
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
        untouched(a.seat, &held, tag, "(c) a duplicate").await;

        // (d) a different signed row under the same id.
        let got = synced(&rival).await;
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
        untouched(a.seat, &held, tag, "(d) first-seen wins").await;

        // (h) the held row's hash and producer copied onto another envelope.
        let got = synced(&forged).await;
        assert!(
            matches!(
                got,
                Ok(Outcome::Refused {
                    reason: Reason::ConflictingAttestation
                })
            ),
            "({tag}) I189(h): a row whose envelope does not hash to the \
             `original_content_hash` it claims is a conflict, not a quiet duplicate — \
             got {got:?}"
        );
        untouched(a.seat, &held, tag, "(h) a forged claim").await;

        // (i) a replay of the held id over the size cap is refused by the size
        // gate before the plan pays for it — not classified.
        let got = synced(&oversize(&held)).await;
        assert!(
            matches!(&got, Err(e) if e.to_string().contains("envelope too large")),
            "({tag}) I189(i): an over-cap replay of a held id must meet the size gate, \
             not the plan — got {got:?}"
        );
        untouched(a.seat, &held, tag, "(i) an over-cap replay").await;

        // (e) the same bytes, same order, through the unattributed door.
        let want = [
            Outcome::Inserted,
            Outcome::Unchanged,
            Outcome::Refused {
                reason: Reason::AlreadyPresentIdentical,
            },
            Outcome::Refused {
                reason: Reason::ConflictingAttestation,
            },
            Outcome::Refused {
                reason: Reason::ConflictingAttestation,
            },
        ];
        for (offer, want) in [&row, &row, &deco, &rival, &forged].into_iter().zip(want) {
            let got = b
                .door
                .apply_replicated_attestation(signed(offer))
                .await
                .unwrap_or_else(|e| panic!("({tag}) I189(e): {e}"));
            assert_eq!(
                got, want,
                "({tag}) I189(e): the unattributed door must classify these bytes as the \
                 attributed door did"
            );
        }
        let got = b
            .door
            .apply_replicated_attestation(signed(&oversize(&held)))
            .await;
        assert!(
            matches!(&got, Err(e) if e.to_string().contains("envelope too large")),
            "({tag}) I189(e/i): the unattributed door meets the same size gate — got {got:?}"
        );
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
            assert!(
                n < 400,
                "({tag}) I189(f): 400 rows from a non-cohort peer never met the author's \
                 per-peer limit — the synced door is not metering a stranger as a stranger"
            );
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
                        super::super::bodies::Node::direct(&a as &dyn FederationDirectory),
                        super::super::bodies::Node::direct(&b as &dyn FederationDirectory),
                        &p,
                        &tag,
                    )
                    .await
                }
                /// The capsule arm: the same bytes through an `OpsDirectory`
                /// over this backend — CIRISEdge's shape — classify the same.
                #[test]
                fn i189_the_capsule_carries_the_outcome() {
                    use std::sync::Arc;
                    let rt = Arc::new(
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(2)
                            .enable_all()
                            .build()
                            .expect("runtime"),
                    );
                    let tag = super::tag("capsule");
                    let us = format!("{tag}-us");
                    let (Some(a), Some(b)) =
                        rt.block_on(async { ($fresh(&us).await, $fresh(&us).await) })
                    else {
                        return;
                    };
                    let a: Arc<dyn FederationDirectory> = Arc::new(a);
                    let b: Arc<dyn FederationDirectory> = Arc::new(b);
                    let proxy = |d: &Arc<dyn FederationDirectory>| {
                        crate::ffi::directory_capsule::build_ops_directory(
                            crate::ffi::directory_capsule::build_persist_directory(d.clone()),
                            Arc::new(crate::ffi::executor_capsule::build_persist_executor(
                                rt.clone(),
                            )),
                        )
                        .expect("abi ok")
                    };
                    let (pa, pb) = (proxy(&a), proxy(&b));
                    let p = super::super::bodies::Parties::new(&us, &tag);
                    rt.block_on(super::super::bodies::i189_one_outcome_on_both_doors(
                        super::super::bodies::Node {
                            seat: a.as_ref(),
                            door: pa.as_ref(),
                        },
                        super::super::bodies::Node {
                            seat: b.as_ref(),
                            door: pb.as_ref(),
                        },
                        &p,
                        &tag,
                    ));
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
