//! v61 (CIRISPersist#991 planes 2 and 3; CC 3.1.3, 3.1.3.2;
//! `CLM-planes-as-rows`, `CLM-cosigned-rows`) — **a group's record and its
//! roster planes are rows, and the tables are their projections.**
//!
//! I1484 — the family plane: the record is a `group:roster:v1` row placed at
//! the family; a co-signed widening is a `membership:widening:v1` row whose
//! co-signature rides as `additional_scrubs`; a widening short of the
//! protocol's quorum is refused and leaves no row; a co-signed removal is a
//! `membership:removal:v1` row, a member's own leaving a
//! `membership:resignation:v1` row; the roster lists what the rows say; and
//! every family projection is byte-equal to its from-rows rebuild.
//!
//! I1485 — the same, on the room plane.
//!
//! I1486 — the rows replicate: a second node that receives nothing but the
//! first node's attestation rows (through `apply_replicated_attestation`)
//! folds the same record and roster, and its projections rebuild byte-equal;
//! a row one byte off its carried object, or stripped of a co-signature, is
//! refused and leaves nothing.
//!
//! I1487 — the retraction of a cosigned row is a cosigned `withdraws` under
//! the same protocol: one signature under `quorum:2/3` is refused, two are
//! admitted and the roster event leaves the projection (the rebuild still
//! byte-equal); a resignation is withdrawn only by its signer; a group's
//! record is never withdrawn.
//!
//! I1620 (v61.1.0, CIRISPersist#1188) — a retraction names the member its
//! row names, and a record's names no one: under `unanimous` every OTHER
//! member retracts a widening without the member it seated; under
//! `open:self_admit` two founders dissolve a public room by withdrawing its
//! record, and one does not.
//!
//! I1488 — the rows are served to the group's membership-plane audience: a
//! private family's rows reach a member and the member a row names, never a
//! stranger.
//!
//! I1490 — the rebuild gate can fail: a roster event whose row is gone, or a
//! projection column that no row says, is a red naming the table.
//!
//! I1491 — the row carries the bytes its signer signed: a nanosecond-signed
//! record replicates to a node that admits it (on a backend that keeps
//! microseconds, a row minted from the read-back would not verify); the
//! receiver's signature rule takes the row and refuses it one byte off; a
//! re-offer of a held row settles; and a roster event re-put under the same key
//! with other co-signers leaves the row that matches what the store kept.
//!
//! I1489 — an upgraded node: a v60 schema (through V205) holds signed typed
//! records and roster events with no rows; V206/V207 and the rehome at open
//! give every one its row, checked by a from-disk count (no signed projection
//! row names no row; the plane holds one row per signed object), every
//! projection rebuilds byte-equal, and a second rehome links nothing.
//!
//! I1497 — the member listing retires with no successor (the steward's ruling:
//! no outward member listing). A v60 node (through V208) holds a private
//! room's listing rows (two members listed `public`) and a peer's
//! advertisement of a listing hash. After V209, by a from-disk count, the
//! table is gone and so is the advertisement. A non-member's node receives
//! none of the room's planes, whichever member a row names (the listed ones
//! included), while a member's still does. The envelope vocabulary no longer
//! names `listed`.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
///
/// v62.0.0 (JSON-cut slice E4, flip wave 3): I1484, I1485 (the family and
/// room planes as JSON rows), I1486 (the rows replicate) and I1487, I1492,
/// I1532, I1620 (a cosigned `withdraws` of a group row) are DELETED. Their
/// properties are owned by the edition-2 group door's witnesses (T1):
/// - a counted founding, a version, a fork, an unheld head: I2993–I2997;
/// - a removal short of the protocol is kept and absent, the meeting voice
///   lands through `apply_replicated_statement`: I2998;
/// - a widening's growth gate and its landing: I2999, I3004;
/// - a community founding and removal: I3000;
/// - a dissolution: I3003;
/// - a composer of a roster is not the roster's plane (so there is no
///   cosigned retraction of a group row: a removal or a dissolution
///   replaces it): I2992;
/// - the same statements converging on two nodes:
///   `family_dissolution_invariants` I280/I283, `room_roster_invariants`
///   I164.
///
/// I1490 (the rebuild gate over JSON plane rows) is DELETED too: group rows
/// are now `ceg_statements` voices with T1's typed projection, so there is no
/// JSON plane row to rebuild a table from. I1488 is rewritten against cut B's
/// serve filter.
#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        identity_type, Family, FamilyMember, FamilyMembershipRevocation,
    };
    use crate::federation::FederationDirectory;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// I1488 — a group's statements are served to its membership-plane
    /// audience only. v62 (E4, wave 5): the family's roster and its counted
    /// removal are `group:roster` / `membership:removal` voices (T1); cut B's
    /// serve filter (`edition2::serve::servable_to`) is asked of each: a
    /// member receives them, a stranger never does, and the removed member
    /// receives the removal that names them.
    pub(crate) async fn i1488_rows_reach_the_group_audience<D>(d: &D, tag: &str)
    where
        D: FederationDirectory,
    {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::serve::servable_to;
        let [ann, ben, cat, eve] =
            ["ann", "ben", "cat", "eve"].map(|n| e2::kid(&format!("{n}-{tag}")));
        for k in [&ann, &ben, &cat, &eve] {
            e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let fam = e2::kid(&format!("fam-{tag}"));
        let founded = at("2026-01-01T00:00:00Z");
        let ms =
            |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp_millis()).expect("ms");
        let record = e2::family_voices(
            &ts::sign_family(
                &ann,
                Family {
                    prev_head_digest: String::new(),
                    charter_digest: String::new(),
                    family_key_id: fam.clone(),
                    family_name: "household".into(),
                    members: [&ann, &ben, &cat]
                        .iter()
                        .enumerate()
                        .map(|(i, k)| FamilyMember {
                            key_id: (*k).clone(),
                            joined_at: founded,
                            role: (i == 0).then(|| "founder".to_owned()),
                        })
                        .collect(),
                    founded_at: founded,
                    consensus_protocol: "quorum:2/3".to_owned(),
                    consensus_protocol_entrenched: false,
                    dissolved_at: None,
                    persist_row_hash: String::new(),
                },
            ),
            1,
            None,
            ms(founded),
        );
        e2::put_voices(d, &record).await.expect("the family lands");
        let (head, _) = e2::held_head(d, &fam).await.expect("the roster's head");
        let mut r = ts::sign_family_membership_revocation(
            &ann,
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: cat.clone(),
                removed_at: at("2026-03-01T00:00:00Z"),
                effective_at: at("2026-03-01T00:00:00Z"),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_family_membership_revocation(&mut r, &ben);
        let removal = e2::family_revocation_voices(&r, Some(&head));
        e2::put_voices(d, &removal).await.expect("2 of 3 remove");
        for st in record.iter().chain(removal.iter()) {
            assert!(
                servable_to(d, st, Some(&ann)).await.unwrap(),
                "{tag}: a member receives the group's statements"
            );
            assert!(
                !servable_to(d, st, Some(&eve)).await.unwrap(),
                "{tag}: a stranger never receives a private group's statements"
            );
        }
        for st in &removal {
            assert!(
                servable_to(d, st, Some(&cat)).await.unwrap(),
                "{tag}: the removed member receives the removal that names them"
            );
        }
    }

    // v62 (E4, flip wave 2): I1491 ("the row carries the bytes its signer
    // signed": a nanosecond-signed JSON record replicated as a row, refused
    // one byte off, and a roster event re-put with other co-signers) is
    // DELETED: it witnesses the earlier form's JSON row bytes and
    // `RosterCosignature` re-put (T1.api.md §3, "delete"). An edition-2
    // voice is a statement the door verifies; its instants are POSIX ms.
}

#[cfg(test)]
mod run {
    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    // Invoked only under a backend feature; a no-backend axis build would
    // otherwise read it as an unused macro (a `-D warnings` red).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i1488() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1488_rows_reach_the_group_audience(&d, &super::tag())
                        .await;
                }
            }
        };
    }

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
