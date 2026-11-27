//! v62.0.0 (RESIGN-8; the Constitution's rulings of 2026-11-24 "resignation:
//! two readings side by side" and the general form of dissolution, with the
//! Constitution + Kernel resignation run) — **a resignation's two readings
//! on the lineage, and dissolution as every member's held end.**
//!
//! - **I6840** (sqlite + postgres) — TWO STORES, BOTH ARRIVAL ORDERS: a room
//!   of a and b; a and b resign concurrently, each acting from h0. Store 1
//!   holds a's end first, store 2 b's. After ONE end, each store reads the
//!   resigner ended at once (`no_held_end_of_seat` false, out of
//!   `wrap_audience_at`), the other still seated; the COUNT still seats both
//!   (`count_base` citing nothing); not dissolved. After BOTH, both stores
//!   read the room DISSOLVED (`lineage::dissolution`, and
//!   `group_plane::refuse_if_community_dissolved` refuses `GroupDissolved`);
//!   the count still seats both (no counted row cited either end).
//! - **I6841** (sqlite + postgres) — a cited resignation, then a
//!   re-admission: c's end held ⇒ c ended at once, still counted; a counted
//!   widening (drafted through `state_head`) cites it ⇒ c is out of
//!   `members_at` and no longer reads "ended" (the end is in the lineage
//!   past); c re-admitted by a later counted widening ⇒ seated and NOT ended
//!   (the old seat's end ends no current seat).
//! - **I6843** (sqlite + postgres; RESIGN-5) — a resignation's seat is read
//!   AT THE HEAD IT NAMES, never at the signer's own `effective_at`: m,
//!   seated by a counted widening w over h0, resigning at h0 (where m holds
//!   no seat) is HELD `resignation_not_a_member_at_head` though stamped
//!   after the widening; m resigning at w LANDS though stamped before the
//!   widening's instant. Red on 2c6e7e28 by construction (the instant fold
//!   reads both the other way).
//! - **I6844** (sqlite + postgres; RESIGN-8b) — at TWO tips the WRAP set is
//!   the UNION of the members seated at each tip, never the common members:
//!   with m1 widened on one tip and m2 on the other, both are wrapped to
//!   (`wrap_audience_at`) while `members_at` of both tips (the COUNT base on
//!   0.2.2) holds neither and a count naming only one tip lacks the other
//!   tip's newcomer; when a, b and c (the earlier members) resign, each is
//!   out of the wrap set on BOTH tips at once while a count still seats
//!   them; the room is then NOT dissolved (NotJudged at several tips; m1
//!   and m2 are still wrapped to). A join naming both tips is not witnessed:
//!   on 0.2.2 its count base is the common members less the cited ends,
//!   which is empty here (the judged-after-join case is kernel-v0.3.0's).
//! - **I6842** (sqlite + postgres) — SEVERAL heads: two counted widenings
//!   extending h0 make two tips; `lineage::dissolution` answers `NotJudged`
//!   (never dissolved) until kernel-v0.3.0.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::{
        membership_payload, MembershipRecord, MEMBERSHIP_PREFIX,
    };
    use crate::federation::edition2::head_rule::{roster_heads, state_head};
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::lineage::{
        count_base, dissolution, members_at, no_held_end_of_seat, wrap_audience_at, Dissolution,
    };
    use crate::federation::edition2::names::RowId;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, id_of, proposal, put, reg, reply,
    };
    use crate::federation::resign_invariants::bodies::{ms, room_end_voices, room_of_three};
    use crate::federation::types::{CommunityMembershipWidening, RevocationLeaf};
    use crate::federation::{Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};
    use std::collections::BTreeSet;

    fn at_ago(mins: i64) -> DateTime<Utc> {
        crate::federation::admission::truncate_to_substrate_resolution(
            Utc::now() - Duration::minutes(mins),
        )
    }

    fn landed(r: &Result<StatementOutcome, Error>) -> bool {
        matches!(r, Ok(StatementOutcome::Row { .. }))
    }

    fn set(xs: &[&String]) -> BTreeSet<String> {
        xs.iter().map(|x| (*x).clone()).collect()
    }

    /// The room of two `a`, `b` (`majority`) founded on store `d` under the
    /// fixture alias `tag`: the derived id and the row ids are the alias's,
    /// so two stores founding it hold the same room.
    async fn room_of_two(d: &dyn FederationDirectory, tag: &str) -> (String, String, String) {
        let k = |n: &str| format!("{tag}-{n}");
        let (a, b, room) = (k("a"), k("b"), k("room"));
        reg(d, &[&a, &b, &room]).await;
        let (a, b, room) = (id_of(&a), id_of(&b), id_of(&room));
        let room = found_community(d, &room, "majority", &[&a, &b], &[])
            .await
            .unwrap_or_else(|e| panic!("{tag}: the room is founded: {e}"));
        (room, a, b)
    }

    async fn the_head(d: &dyn FederationDirectory, room: &str, what: &str) -> RowId {
        let hs = roster_heads(d, room).await.expect("the heads read");
        let [h] = hs.as_slice() else {
            panic!("{what}: one head, got {hs:?}");
        };
        *h
    }

    /// The store's readings of `room` at its one head `h0`: the WRAP set,
    /// the COUNT base (citing nothing), and whether `who` has a held end.
    async fn readings(
        d: &dyn FederationDirectory,
        h0: RowId,
        who: &str,
    ) -> (BTreeSet<String>, BTreeSet<String>, bool) {
        (
            wrap_audience_at(d, &[h0])
                .await
                .expect("the wrap set reads"),
            count_base(d, &[h0], &[])
                .await
                .expect("the count reads")
                .members,
            no_held_end_of_seat(d, who, &[h0])
                .await
                .expect("the predicate reads"),
        )
    }

    /// **I6840** — two concurrent resignations on two stores, both orders.
    pub(crate) async fn i6840_two_concurrent_resignations_two_stores(
        s1: &dyn FederationDirectory,
        s2: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (room, a, b) = room_of_two(s1, tag).await;
        let (room2, a2, b2) = room_of_two(s2, tag).await;
        assert_eq!(
            (&room, &a, &b),
            (&room2, &a2, &b2),
            "{tag} I6840 premise: both stores hold the same room"
        );
        let h0 = the_head(s1, &room, "I6840 store 1").await;
        assert_eq!(
            the_head(s2, &room, "I6840 store 2").await,
            h0,
            "{tag} I6840 premise: one founding head on both stores"
        );
        // Both resign concurrently, each acting from h0 (store 1 drafts both:
        // they name the same head).
        let ea = room_end_voices(
            s1,
            &room,
            &a,
            &[&a],
            at_ago(30),
            RevocationLeaf::Resignation,
        )
        .await;
        let eb = room_end_voices(
            s1,
            &room,
            &b,
            &[&b],
            at_ago(29),
            RevocationLeaf::Resignation,
        )
        .await;
        let both = set(&[&a, &b]);
        for (d, first, second, (gone, stays), store) in [
            (s1, &ea, &eb, (&a, &b), "store 1 (a first)"),
            (s2, &eb, &ea, (&b, &a), "store 2 (b first)"),
        ] {
            let r = e2::put_voices(d, first).await;
            assert!(
                landed(&r),
                "{tag} I6840 {store}: the first end lands: {r:?}"
            );
            let (wrap, count, unended) = readings(d, h0, gone).await;
            assert_eq!(
                wrap,
                set(&[stays]),
                "{tag} I6840 {store}: one member left: the resigner is wrapped and served no more"
            );
            assert!(
                !unended,
                "{tag} I6840 {store}: the resigner's seat has a held end, at once"
            );
            assert_eq!(
                count, both,
                "{tag} I6840 {store}: the COUNT still seats the resigner (no row cites the end)"
            );
            assert_eq!(
                dissolution(d, &room).await.expect("dissolution reads"),
                Dissolution::NotDissolved,
                "{tag} I6840 {store}: one end held: not dissolved"
            );
            assert!(
                crate::federation::group_plane::refuse_if_community_dissolved(d, &room)
                    .await
                    .is_ok(),
                "{tag} I6840 {store}: a change to the room is not refused"
            );
            let r = e2::put_voices(d, second).await;
            assert!(
                landed(&r),
                "{tag} I6840 {store}: the second end lands: {r:?}"
            );
            let (wrap, count, _) = readings(d, h0, stays).await;
            assert!(wrap.is_empty(), "{tag} I6840 {store}: nobody is wrapped");
            assert_eq!(
                count, both,
                "{tag} I6840 {store}: the count still seats both: no counted row cites either end"
            );
            assert!(
                dissolution(d, &room)
                    .await
                    .expect("dissolution reads")
                    .is_dissolved(),
                "{tag} I6840 {store}: both ends held: DISSOLVED"
            );
            assert!(
                matches!(
                    crate::federation::group_plane::refuse_if_community_dissolved(d, &room).await,
                    Err(Error::GroupDissolved { .. })
                ),
                "{tag} I6840 {store}: a change to the dissolved room is refused (held \
                 group_dissolved under a fold attempt)"
            );
        }
    }

    /// A counted widening of the registered key `seed` into `room`: proposal
    /// by `a`, the invitee's acceptance, then the widening (through
    /// `state_head` when `naming` is `None`, else naming those heads),
    /// voiced by `a` and `b`. Its row id and the put's outcome.
    #[allow(clippy::too_many_arguments)]
    async fn widen(
        d: &dyn FederationDirectory,
        room: &str,
        a: &str,
        b: &str,
        member: &str,
        at: DateTime<Utc>,
        naming: Option<&RowId>,
    ) -> (RowId, Result<StatementOutcome, Error>) {
        let p = proposal(
            a,
            crate::federation::types::cohort_scope::COMMUNITY,
            room,
            member,
            None,
            at,
            Some(Duration::days(7)),
        );
        put(d, &p).await.expect("the proposal");
        put(
            d,
            &reply(member, member, &p, true, at + Duration::seconds(1)),
        )
        .await
        .expect("the acceptance");
        let record = MembershipRecord::CommunityWidening(CommunityMembershipWidening {
            community_key_id: room.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: ms(at + Duration::seconds(2)),
            effective_at: ms(at + Duration::seconds(2)),
            role: None,
            persist_row_hash: String::new(),
        });
        let family = ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX);
        let payload = match naming {
            Some(h) => membership_payload(&record, Some(h)).expect("the payload"),
            None => state_head(
                d,
                "scores",
                &family,
                a,
                membership_payload(&record, None).expect("the payload"),
            )
            .await
            .expect("the producer states the head"),
        };
        let voices: Vec<Vec<u8>> = [a, b]
            .iter()
            .map(|s| {
                e2::sign_group_payload(&e2::signing_key(s), member, MEMBERSHIP_PREFIX, &payload)
            })
            .collect();
        let w = e2::row_id_of(&voices[0]);
        (w, e2::put_voices(d, &voices).await)
    }

    /// **I6841** — a cited resignation, then a re-admission.
    pub(crate) async fn i6841_cited_then_readmitted(d: &dyn FederationDirectory, tag: &str) {
        let (room, a, b, c) = room_of_three(d, &format!("i6841-{tag}"), "majority").await;
        let h0 = the_head(d, &room, "I6841").await;
        let ec =
            room_end_voices(d, &room, &c, &[&c], at_ago(60), RevocationLeaf::Resignation).await;
        assert!(
            landed(&e2::put_voices(d, &ec).await),
            "{tag} I6841: c's end lands"
        );
        let (wrap, count, unended) = readings(d, h0, &c).await;
        assert!(
            !unended && !wrap.contains(&c),
            "{tag} I6841: c ended at once"
        );
        assert!(count.contains(&c), "{tag} I6841: still counted until cited");
        // A counted change cites the end (state_head, LINEAGE-L5).
        let m = format!("i6841-{tag}-m");
        reg(d, &[&m]).await;
        let m = id_of(&m);
        let (w1, r) = widen(d, &room, &a, &b, &m, at_ago(50), None).await;
        assert!(landed(&r), "{tag} I6841: the citing widening lands: {r:?}");
        assert!(
            !members_at(d, &[w1]).await.unwrap().members.contains(&c),
            "{tag} I6841: from the citing row c is out of the members"
        );
        assert!(
            no_held_end_of_seat(d, &c, &[w1]).await.unwrap(),
            "{tag} I6841: the cited end is in the lineage past: it ends no current seat"
        );
        // c re-admitted.
        let (w2, r) = widen(d, &room, &a, &b, &c, at_ago(40), None).await;
        assert!(landed(&r), "{tag} I6841: c's re-admission lands: {r:?}");
        assert!(
            wrap_audience_at(d, &[w2]).await.unwrap().contains(&c),
            "{tag} I6841: re-admitted, c is wrapped and served again"
        );
        assert!(
            no_held_end_of_seat(d, &c, &[w2]).await.unwrap(),
            "{tag} I6841: the old seat's end ends no current seat"
        );
        assert_eq!(
            dissolution(d, &room).await.unwrap(),
            Dissolution::NotDissolved,
            "{tag} I6841"
        );
    }

    /// The voices of `member`'s own resignation from `room`, acting from
    /// `head`, stamped at `at`.
    fn resignation_at(room: &str, member: &str, head: &RowId, at: DateTime<Utc>) -> Vec<Vec<u8>> {
        let r = crate::federation::tier_ingest::test_support::sign_community_membership_revocation(
            member,
            crate::federation::resign_invariants::bodies::room_end(
                room,
                member,
                at,
                RevocationLeaf::Resignation,
            ),
        );
        e2::community_revocation_voices(&r, Some(head))
    }

    /// **I6843** — a resignation's seat is read at the head it names.
    pub(crate) async fn i6843_seat_read_at_the_named_head(d: &dyn FederationDirectory, tag: &str) {
        let (room, a, b, _c) = room_of_three(d, &format!("i6843-{tag}"), "majority").await;
        let h0 = the_head(d, &room, "I6843").await;
        let m = format!("i6843-{tag}-m");
        reg(d, &[&m]).await;
        let m = id_of(&m);
        let widened_at = at_ago(30);
        let (w, r) = widen(d, &room, &a, &b, &m, widened_at, None).await;
        assert!(landed(&r), "{tag} I6843 premise: m is widened in: {r:?}");
        // At h0, where m holds no seat, stamped AFTER the widening.
        let early = resignation_at(&room, &m, &h0, at_ago(10));
        let held = e2::row_id_of(&early[0]);
        let r = e2::put_voices(d, &early).await;
        assert!(
            matches!(r, Ok(StatementOutcome::Pending { .. })),
            "{tag} I6843: a resignation at a head where m is not seated waits: {r:?}"
        );
        assert_eq!(
            crate::federation::edition2::fold::why_held(d, &held)
                .await
                .unwrap()
                .map(|h| h.reason)
                .as_deref(),
            Some(crate::federation::malformed_row::RESIGNATION_NOT_A_MEMBER_AT_HEAD),
            "{tag} I6843: held resignation_not_a_member_at_head (the head decides, not the stamp)"
        );
        // At w, where m IS seated, stamped BEFORE the widening's instant.
        let r = e2::put_voices(
            d,
            &resignation_at(&room, &m, &w, widened_at - Duration::minutes(5)),
        )
        .await;
        assert!(
            landed(&r),
            "{tag} I6843: a resignation at the head that seats m lands whatever its stamp: {r:?}"
        );
    }

    /// **I6844** — the wrap set at two tips is the union.
    pub(crate) async fn i6844_the_wrap_set_at_two_tips_is_the_union(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (room, a, b, c) = room_of_three(d, &format!("i6844-{tag}"), "majority").await;
        let h0 = the_head(d, &room, "I6844").await;
        let mut news = Vec::new();
        let mut tips = Vec::new();
        for (i, n) in ["m1", "m2"].iter().enumerate() {
            let k = format!("i6844-{tag}-{n}");
            reg(d, &[&k]).await;
            let m = id_of(&k);
            let (w, r) = widen(d, &room, &a, &b, &m, at_ago(50 - 5 * i as i64), Some(&h0)).await;
            assert!(landed(&r), "{tag} I6844: the widening of {n} lands: {r:?}");
            news.push(m);
            tips.push(w);
        }
        let heads = roster_heads(d, &room).await.unwrap();
        assert_eq!(heads.len(), 2, "{tag} I6844 premise: two tips");
        let (m1, m2) = (&news[0], &news[1]);
        let wrap = wrap_audience_at(d, &heads).await.unwrap();
        assert_eq!(
            wrap,
            set(&[&a, &b, &c, m1, m2]),
            "{tag} I6844: the UNION: each tip's newcomer is wrapped to and served"
        );
        let common = members_at(d, &heads).await.unwrap().members;
        assert!(
            !common.contains(m1) && !common.contains(m2),
            "{tag} I6844 premise: the members common to the tips hold neither newcomer"
        );
        let at_t2 = count_base(d, &[tips[1]], &[]).await.unwrap().members;
        assert!(
            !at_t2.contains(m1),
            "{tag} I6844: a count naming only the other tip lacks m1"
        );
        // The earlier members resign, each acting from the first tip.
        for (i, x) in [&a, &b, &c].into_iter().enumerate() {
            let r = e2::put_voices(
                d,
                &resignation_at(&room, x, &tips[0], at_ago(20 - i as i64)),
            )
            .await;
            assert!(landed(&r), "{tag} I6844: {x}'s resignation lands: {r:?}");
        }
        assert_eq!(
            wrap_audience_at(d, &heads).await.unwrap(),
            set(&[m1, m2]),
            "{tag} I6844: a resigner with a held end is out of the wrap set on EITHER tip"
        );
        for x in [&a, &b, &c] {
            assert!(
                !no_held_end_of_seat(d, x, &heads).await.unwrap(),
                "{tag} I6844: {x}'s seat has a held end"
            );
        }
        assert!(
            count_base(d, &[tips[1]], &[])
                .await
                .unwrap()
                .members
                .contains(&c),
            "{tag} I6844: a count still seats a resigner no counted row cites"
        );
        assert_eq!(
            dissolution(d, &room).await.unwrap(),
            Dissolution::NotJudged,
            "{tag} I6844: every earlier member resigned, newcomers seated on the tips: NOT \
             dissolved (not judged at several tips until kernel-v0.3.0)"
        );
    }

    /// **I6842** — several heads: not judged.
    pub(crate) async fn i6842_several_heads_not_judged(d: &dyn FederationDirectory, tag: &str) {
        let (room, a, b, _c) = room_of_three(d, &format!("i6842-{tag}"), "majority").await;
        let h0 = the_head(d, &room, "I6842").await;
        for (i, n) in ["m1", "m2"].iter().enumerate() {
            let k = format!("i6842-{tag}-{n}");
            reg(d, &[&k]).await;
            let (_, r) = widen(
                d,
                &room,
                &a,
                &b,
                &id_of(&k),
                at_ago(50 - 5 * i as i64),
                Some(&h0),
            )
            .await;
            assert!(landed(&r), "{tag} I6842: the widening of {n} lands: {r:?}");
        }
        assert_eq!(
            roster_heads(d, &room).await.unwrap().len(),
            2,
            "{tag} I6842 premise: two tips"
        );
        assert_eq!(
            dissolution(d, &room).await.unwrap(),
            Dissolution::NotJudged,
            "{tag} I6842: several heads are not judged until kernel-v0.3.0"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i6840_two_concurrent_resignations_two_stores() {
                    let Some(s1) = $fresh.await else { return };
                    let Some(s2) = $fresh.await else { return };
                    super::super::bodies::i6840_two_concurrent_resignations_two_stores(
                        &s1 as &dyn FederationDirectory,
                        &s2 as &dyn FederationDirectory,
                        &format!("i6840-{}", suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6841_cited_then_readmitted() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6841_cited_then_readmitted(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6843_seat_read_at_the_named_head() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6843_seat_read_at_the_named_head(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6844_the_wrap_set_at_two_tips_is_the_union() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6844_the_wrap_set_at_two_tips_is_the_union(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6842_several_heads_not_judged() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6842_several_heads_not_judged(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
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
