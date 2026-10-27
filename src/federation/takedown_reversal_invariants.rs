//! v60.1.0 (CIRISPersist#1113; CC 4.5.3, rc10 `99bf187` / `62776bc`) —
//! **a reversed reconsideration reverses a takedown; withheld is computed at
//! read.**
//!
//! - **I1366** (sqlite, postgres) — the ruling and the fold. Against a held
//!   takedown notice the content's communities judge (CC 4.5.5): a stranger's
//!   ruling is refused, a ruling naming another community is
//!   `reconsideration_community_mismatch`, the review-holder's `upheld` admits
//!   and withholds nothing back, and the review-holder's `reversed` admits and
//!   lifts the withholding (`purge_withheld` reads `None`,
//!   `takedown_reversal` names the ruling). The fold is re-derived at every
//!   read: the ruling's author withdrawing it withholds the bytes again; a
//!   reversal naming another notice, or one that has expired, reverses
//!   nothing.
//! - **I1367** (two nodes, sqlite and postgres) — the holders. A counter-notice
//!   takedown withholds the bytes on A and, delivered as a purge bundle, on B;
//!   the review-holder's reversal admitted at A serves the bytes again there,
//!   and A's re-ack claims them `here` again (`restored`); the same signed
//!   ruling delivered to B does the same on B's own state. After A's window
//!   the hard delete skips the reversed bytes (`voided`). An immediate-removal
//!   basis destroys the bytes on receipt, and its reversal restores standing,
//!   never bytes: the same content re-published is admitted again.
//! - **I1369** (sqlite, postgres; #1113 × #1070) — the write floor's
//!   in-transaction look asks the read doors' decision
//!   (`steward_purge::standing_notice`): a re-publication after a reversal
//!   lands, while a takedown that is NOT reversed, committed between the
//!   door's pre-read and its write, still refuses the write inside its
//!   transaction, naming that notice. A reversal landing after the pre-read is
//!   not credited to the write in flight: the write is refused on its own
//!   pre-read and a retry lands. On postgres a write admitted over reversed
//!   takedowns still holds a new takedown off under the shared advisory lock
//!   until it commits, and that takedown then destroys the bytes it landed.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::doors_takedown_invariants::bodies::{claimant, community_of, notice};
    use crate::federation::steward_purge::{self as sp, test_clock};
    use crate::federation::takedown_tombstone as td;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, cohort_scope, Attestation, SignedAttestation,
    };
    use crate::federation::{Error, FederationDirectory};

    pub(crate) const NODE: &str = "c-node-1";

    pub(crate) fn sha_hex(seed: &str) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(seed.as_bytes()))
    }

    pub(crate) fn sha_bytes(hex_sha: &str) -> [u8; 32] {
        <[u8; 32]>::try_from(hex::decode(hex_sha).unwrap()).unwrap()
    }

    /// Bind `sha` into `comm` by a row its member `member` signs at community
    /// scope (the content's community is the held binding's, CC 4.5.5).
    pub(crate) async fn bind_into(
        dir: &dyn FederationDirectory,
        member: &str,
        comm: &str,
        sha: &str,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = ts::bare_attestation(
            &id,
            member,
            member,
            &serde_json::json!({
                "id": id,
                "dimension": "content:established:v1",
                "evidence_refs": [sha],
                "community_id": comm,
            }),
        );
        row.attestation_type = attestation_type::SCORES.into();
        row.weight = None;
        row.cohort_scope = cohort_scope::COMMUNITY.into();
        dir.put_attestation(SignedAttestation {
            attestation: ts::seal_row(member, row),
        })
        .await
        .expect("the community binding row");
    }

    /// A `reconsideration:new_evidence:v1` ruling by `by` naming
    /// `notice_row_id`, at `scope` naming `community`.
    pub(crate) fn ruling(
        by: &str,
        notice_row_id: &str,
        outcome: &str,
        scope: &str,
        community: &str,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({
            "id": id,
            "dimension": "reconsideration:new_evidence:v1",
            "score": 1.0,
            "confidence": 1.0,
            "references_attestation_id": notice_row_id,
        });
        // An empty `outcome` is a FILING; an empty `community` names none.
        if !outcome.is_empty() {
            env["outcome"] = serde_json::json!(outcome);
        }
        if !community.is_empty() {
            env["community_id"] = serde_json::json!(community);
        }
        let mut row = ts::bare_attestation(&id, by, by, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.weight = None;
        row.cohort_scope = scope.into();
        ts::seal_row(by, row)
    }

    pub(crate) async fn put(dir: &dyn FederationDirectory, row: Attestation) -> Result<(), Error> {
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    // ── I1366 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1366_a_reversal_lifts_the_withholding_at_read<D>(d: &D, tag: &str)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let moderator = claimant(0x91);
        let stranger = claimant(0x92);
        ts::register_hybrid_key(dir, &stranger.id).await;
        let comm = format!("i1366-comm-{tag}");
        community_of(dir, &comm, &moderator.id).await;
        let sha = sha_hex(&format!("i1366-{tag}"));
        bind_into(dir, &moderator.id, &comm, &sha).await;

        let r = td::takedown_tombstone(dir, &notice(&moderator, &sha, "dmca512"), NODE)
            .await
            .expect("I1366: the moderator's counter-notice takedown");
        let notice_row = r.notice_attestation_id.clone().expect("a notice row");
        let withheld = || async { sp::purge_withheld(dir, &sha_bytes(&sha)).await.unwrap() };
        assert_eq!(
            withheld().await,
            Some(r.notice_id.clone()),
            "I1366: withheld"
        );
        assert_eq!(
            td::takedown_reversal(dir, &r.notice_id).await.unwrap(),
            None
        );

        // A stranger rules: no review duty over the content here.
        let e = put(
            dir,
            ruling(
                &stranger.id,
                &notice_row,
                "reversed",
                cohort_scope::FEDERATION,
                &comm,
            ),
        )
        .await
        .expect_err("I1366: a stranger cannot rule");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I1366: {e}"
        );
        // A ruling naming a community the content is not bound into.
        let e = put(
            dir,
            ruling(
                &moderator.id,
                &notice_row,
                "reversed",
                cohort_scope::FEDERATION,
                &format!("{comm}-other"),
            ),
        )
        .await
        .expect_err("I1366: another community");
        assert!(
            e.to_string()
                .contains(crate::federation::admission::RECONSIDERATION_COMMUNITY_MISMATCH),
            "I1366: {e}"
        );
        // The content's signed subject FILES (no outcome, naming no
        // community): admitted. The subject cannot RULE: refused.
        let author = format!("i1366-author-{tag}");
        crate::federation::doors_takedown_invariants::bodies::establish(
            dir, &author, &author, &sha,
        )
        .await;
        put(
            dir,
            ruling(&author, &notice_row, "", cohort_scope::FEDERATION, ""),
        )
        .await
        .expect("I1366: the content's subject files");
        let e = put(
            dir,
            ruling(
                &author,
                &notice_row,
                "reversed",
                cohort_scope::FEDERATION,
                "",
            ),
        )
        .await
        .expect_err("I1366: the subject cannot rule");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "I1366: {e}"
        );
        assert_eq!(withheld().await, Some(r.notice_id.clone()), "I1366: filed");
        // Upheld: admitted, and the bytes stay withheld.
        put(
            dir,
            ruling(
                &moderator.id,
                &notice_row,
                "upheld",
                cohort_scope::COMMUNITY,
                &comm,
            ),
        )
        .await
        .expect("I1366: the review-holder upholds");
        assert_eq!(withheld().await, Some(r.notice_id.clone()), "I1366: upheld");
        // A reversal naming ANOTHER notice reverses nothing here.
        put(
            dir,
            ruling(
                &moderator.id,
                &uuid::Uuid::new_v4().to_string(),
                "reversed",
                cohort_scope::COMMUNITY,
                &comm,
            ),
        )
        .await
        .expect("I1366: a ruling on an unheld target files");
        assert_eq!(
            withheld().await,
            Some(r.notice_id.clone()),
            "I1366: elsewhere"
        );

        // Reversed: admitted, and withheld is computed away at read.
        let reversal = ruling(
            &moderator.id,
            &notice_row,
            "reversed",
            cohort_scope::COMMUNITY,
            &comm,
        );
        let reversal_id = reversal.attestation_id.clone();
        put(dir, reversal.clone())
            .await
            .expect("I1366: the review-holder reverses");
        assert_eq!(
            td::takedown_reversal(dir, &r.notice_id).await.unwrap(),
            Some(reversal_id.clone()),
            "I1366: the reversal is found"
        );
        assert_eq!(withheld().await, None, "I1366: no longer withheld");
        // The tombstone row itself stays (the notice is void, not erased).
        assert!(dir.purge_tombstoned("blob", &sha).await.unwrap().is_some());

        // Re-derived at read: the author withdraws the ruling.
        ts::put_retraction(dir, &moderator.id, &moderator.id, &reversal_id, "withdraws")
            .await
            .expect("I1366: the ruling's author withdraws it");
        assert_eq!(
            withheld().await,
            Some(r.notice_id.clone()),
            "I1366: a withdrawn reversal withholds again"
        );

        // An expiring reversal: counted until its expiry, not after.
        let mut expiring = ruling(
            &moderator.id,
            &notice_row,
            "reversed",
            cohort_scope::COMMUNITY,
            &comm,
        );
        expiring.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(1));
        let expiring = ts::seal_row(&moderator.id, expiring);
        put(dir, expiring)
            .await
            .expect("I1366: an expiring reversal");
        assert_eq!(withheld().await, None, "I1366: before its expiry");
        test_clock::set(Some(chrono::Utc::now() + chrono::Duration::days(2)));
        let after = sp::purge_withheld(dir, &sha_bytes(&sha)).await.unwrap();
        test_clock::set(None);
        assert_eq!(
            after,
            Some(r.notice_id.clone()),
            "I1366: an expired reversal reverses nothing"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod engine_bodies {
    use super::bodies::{bind_into, put, ruling};
    use crate::federation::doors_takedown_invariants::bodies::{claimant, community_of, notice};
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::steward_purge::{self as sp, test_clock};
    use crate::federation::takedown_tombstone::TakedownDisposition;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope;
    use crate::federation::types::identity_type::USER;
    use crate::federation::{BlobBody, BlobError, BlobStorage, FederationDirectory};
    use sha2::Digest as _;

    async fn read(e: &crate::Engine, sha: &[u8; 32]) -> Result<Vec<u8>, BlobError> {
        e.read_blob_as(sha, "", None).await
    }

    async fn hold(engine: &crate::Engine, author: &str, bytes: &[u8]) -> [u8; 32] {
        let sha: [u8; 32] = sha2::Sha256::digest(bytes).into();
        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes.to_vec()),
                None,
                author,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
        sha
    }

    // ── I1367 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1367_the_holders_follow_the_reversal<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i1367-author-{run}");
        let moderator = claimant(0x93);
        let comm = format!("i1367-comm-{run}");
        let bytes = format!("i1367-dmca-{run}");
        let csam_bytes = format!("i1367-csam-{run}");
        let mut sha = [0u8; 32];
        for (e, b) in [(&l.engine_a, l.ba.as_ref()), (&l.engine_b, l.bb.as_ref())] {
            let dir = b.as_dyn_directory();
            ts::register_hybrid_key_as(b, &author, &author, USER).await;
            community_of(dir, &comm, &moderator.id).await;
            sha = hold(e, &author, bytes.as_bytes()).await;
            bind_into(dir, &moderator.id, &comm, &hex::encode(sha)).await;
        }
        let csam = hold(&l.engine_a, &author, csam_bytes.as_bytes()).await;
        bind_into(
            l.ba.as_dyn_directory(),
            &moderator.id,
            &comm,
            &hex::encode(csam),
        )
        .await;
        // Whole seconds: the window's boundary is then exact on every backend.
        let t = {
            use chrono::SubsecRound as _;
            chrono::Utc::now().trunc_subsecs(0)
        };
        // A blob A holds whose claim A retracted for another reason (an
        // eviction that aborted after its retraction): no tombstone names it,
        // so no re-ack ever re-advertises it.
        let other = hold(
            &l.engine_a,
            &author,
            format!("i1367-other-{run}").as_bytes(),
        )
        .await;
        let signer_a = ts::local_signer(&format!("em-a-{run}"));
        assert_eq!(signer_a.derived_key_id(), l.node_a, "the ladder's signer");
        let n = crate::federation::holding_claim::retract_own_claims(
            l.ba.as_dyn_directory(),
            &l.node_a,
            &signer_a,
            &other,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(n, 1, "I1367: A's claim on the other blob retracted");

        // A counter-notice takedown at A: withheld, A's claim retracted.
        test_clock::set(Some(t));
        let r = l
            .engine_a
            .takedown_tombstone(&notice(&moderator, &hex::encode(sha), "dmca512"))
            .await
            .expect("I1367: the moderator's takedown");
        assert_eq!(
            r.disposition,
            TakedownDisposition::WithholdThenDelete { window_days: 10 }
        );
        assert_eq!(r.claims_retracted, 1, "I1367: {r:?}");
        let notice_row = r.notice_attestation_id.clone().unwrap();
        assert!(
            matches!(read(&l.engine_a, &sha).await, Err(BlobError::Purged { .. })),
            "I1367: withheld on A"
        );
        // Delivered to B as a purge bundle: B withholds on its own state.
        let bundles = l.engine_a.list_purge_bundles_since(None, 10).await.unwrap();
        let wire: Vec<sp::PurgeBundle> =
            serde_json::from_str(&serde_json::to_string(&bundles).unwrap()).unwrap();
        l.engine_b
            .apply_replicated_purge(&wire[0])
            .await
            .expect("I1367: B applies the takedown");
        assert!(
            matches!(read(&l.engine_b, &sha).await, Err(BlobError::Purged { .. })),
            "I1367: withheld on B"
        );

        // Before any reversal the re-ack restores nothing: the bytes are
        // withheld, and the other blob carries no tombstone.
        let before = l
            .engine_a
            .reack_holding_claims_once(chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(before.restored, 0, "I1367: withheld: {before:?}");

        // The review-holder reverses at A: A serves again and re-acks.
        let reversal = ruling(
            &moderator.id,
            &notice_row,
            "reversed",
            cohort_scope::COMMUNITY,
            &comm,
        );
        put(l.ba.as_dyn_directory(), reversal.clone())
            .await
            .expect("I1367: the reversal admits at A");
        assert_eq!(
            read(&l.engine_a, &sha)
                .await
                .expect("I1367: A serves again"),
            bytes.as_bytes()
        );
        assert!(!l.ba.list_holders(&sha).await.unwrap().contains(&l.node_a));
        let reack = l
            .engine_a
            .reack_holding_claims_once(chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(reack.restored, 1, "I1367: A re-acks `here`: {reack:?}");
        assert_eq!(reack.failed, 0, "I1367: {reack:?}");
        assert!(
            !l.ba.list_holders(&other).await.unwrap().contains(&l.node_a),
            "I1367: a claim retracted for another reason is never re-advertised"
        );
        assert!(
            l.ba.list_holders(&sha).await.unwrap().contains(&l.node_a),
            "I1367: A is a holder again"
        );
        let again = l
            .engine_a
            .reack_holding_claims_once(chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(again.restored, 0, "I1367: restored once: {again:?}");

        // The same signed ruling delivered to B: B's own fold flips.
        put(l.bb.as_dyn_directory(), reversal)
            .await
            .expect("I1367: the reversal admits at B on B's own state");
        assert_eq!(
            read(&l.engine_b, &sha)
                .await
                .expect("I1367: B serves again"),
            bytes.as_bytes()
        );

        // At A's window, exactly (`executed_at` + 10 days): the hard delete
        // runs and skips the reversed bytes.
        test_clock::set(Some(t + chrono::Duration::days(10)));
        let done = l.engine_a.purge_finalize(&r.notice_id).await;
        test_clock::set(None);
        let done = done.expect("I1367: finalize at the window");
        assert_eq!(done.notice_id, r.notice_id, "I1367: {done:?}");
        assert_eq!(done.blobs_evicted, 0, "I1367: nothing evicted: {done:?}");
        assert!(
            done.voided.contains(&format!("blob:{}", hex::encode(sha))),
            "I1367: the reversed takedown's bytes are void: {done:?}"
        );
        assert!(l.ba.has_blob(&sha).await.unwrap(), "I1367: still held");

        // Immediate removal: destroyed on receipt; the reversal restores
        // standing, never bytes.
        let r = l
            .engine_a
            .takedown_tombstone(&notice(&moderator, &hex::encode(csam), "ncmec_csam"))
            .await
            .expect("I1367: an immediate-removal takedown");
        assert!(r.bytes_destroyed);
        assert!(!l.ba.has_blob(&csam).await.unwrap());
        let republish = || {
            l.engine_a.put_blob_signing(
                &csam,
                BlobBody::Inline(csam_bytes.as_bytes().to_vec()),
                None,
                &author,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
        };
        assert!(
            matches!(republish().await, Err(BlobError::Purged { .. })),
            "I1367: re-publication refused while the notice stands"
        );
        put(
            l.ba.as_dyn_directory(),
            ruling(
                &moderator.id,
                r.notice_attestation_id.as_deref().unwrap(),
                "reversed",
                cohort_scope::COMMUNITY,
                &comm,
            ),
        )
        .await
        .expect("I1367: the immediate takedown's reversal");
        assert!(
            !l.ba.has_blob(&csam).await.unwrap(),
            "I1367: no bytes come back"
        );
        let after = l
            .engine_a
            .reack_holding_claims_once(chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            (after.restored, after.failed),
            (0, 0),
            "I1367: destroyed bytes are not re-acknowledged: {after:?}"
        );
        republish()
            .await
            .expect("I1367: the same content re-published is admitted again");
        assert!(l.ba.has_blob(&csam).await.unwrap());
    }
    // ── I1369 ─────────────────────────────────────────────────────────────
    /// v60.1.0 (CIRISPersist#1113 × #1070) — **a tombstone not reversed still
    /// refuses the write inside its transaction.** `arm_inside` (postgres)
    /// pauses `store_plaintext_local` inside its write transaction, under the
    /// shared advisory lock.
    pub(crate) async fn i1369_a_standing_tombstone_refuses_in_the_write<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        arm_inside: Option<fn(&B) -> std::sync::Arc<crate::store::test_hooks::Pause>>,
    ) where
        B: BlobStorage
            + FederationDirectory
            + crate::store::test_hooks::ArmBytesPause
            + Sync
            + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i1369-author-{run}");
        let moderator = claimant(0x94);
        let comm = format!("i1369-comm-{run}");
        let bytes = format!("i1369-{run}");
        let dir = l.ba.as_dyn_directory();
        let e = &l.engine_a;
        ts::register_hybrid_key_as(l.ba.as_ref(), &author, &author, USER).await;
        community_of(dir, &comm, &moderator.id).await;
        let sha = hold(e, &author, bytes.as_bytes()).await;
        bind_into(dir, &moderator.id, &comm, &hex::encode(sha)).await;
        let take = |sha: [u8; 32]| {
            let n = notice(&moderator, &hex::encode(sha), "ncmec_csam");
            async move { e.takedown_tombstone(&n).await }
        };
        let reverse = |r: &crate::federation::takedown_tombstone::TakedownReport| {
            put(
                dir,
                ruling(
                    &moderator.id,
                    r.notice_attestation_id.as_deref().unwrap(),
                    "reversed",
                    cohort_scope::COMMUNITY,
                    &comm,
                ),
            )
        };
        let republish = || {
            e.put_blob_signing(
                &sha,
                BlobBody::Inline(bytes.as_bytes().to_vec()),
                None,
                &author,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
        };
        let refused_by = |got: Result<(), BlobError>, notice_id: &str, what: &str| match got {
            Err(BlobError::Purged { notice_id: n, .. }) => {
                assert_eq!(
                    n, notice_id,
                    "I1369 {what}: refused naming the standing notice"
                );
            }
            other => panic!("I1369 {what}: refused in the transaction: {other:?}"),
        };

        // N1, destroyed on receipt, then reversed: lifted at read.
        let n1 = take(sha).await.expect("I1369: the first takedown");
        assert!(n1.bytes_destroyed, "I1369: {n1:?}");
        reverse(&n1).await.expect("I1369: N1 reversed");
        assert_eq!(
            sp::purge_withheld(l.ba.as_ref(), &sha).await.unwrap(),
            None,
            "I1369: N1 lifted at read"
        );

        // A takedown NOT reversed commits between the pre-read (which found
        // only N1, reversed) and the write: the write's own look refuses it.
        let p = l.ba.arm_bytes_pause();
        let (got, n2) = tokio::join!(republish(), async {
            tokio::time::timeout(std::time::Duration::from_secs(20), p.reached())
                .await
                .expect("the write reaches its pre-read");
            let r = take(sha).await.expect("I1369: N2 after the pre-read");
            p.resume();
            r
        });
        assert_ne!(n2.notice_id, n1.notice_id, "I1369: two notices");
        refused_by(got, &n2.notice_id, "N2 not reversed");
        assert!(!l.ba.has_blob(&sha).await.unwrap(), "I1369: nothing landed");

        // A reversal landing after the pre-read is not credited to the write
        // in flight: N2 reversed, then N3 AND its reversal land at the pause;
        // the write is refused on its own pre-read, a retry lands.
        reverse(&n2).await.expect("I1369: N2 reversed");
        let p = l.ba.arm_bytes_pause();
        let (got, n3) = tokio::join!(republish(), async {
            tokio::time::timeout(std::time::Duration::from_secs(20), p.reached())
                .await
                .expect("the write reaches its pre-read");
            let r = take(sha).await.expect("I1369: N3 after the pre-read");
            reverse(&r)
                .await
                .expect("I1369: N3 reversed after the pre-read");
            p.resume();
            r
        });
        refused_by(got, &n3.notice_id, "N3 reversed after the pre-read");
        assert!(!l.ba.has_blob(&sha).await.unwrap(), "I1369: nothing landed");
        republish()
            .await
            .expect("I1369: every takedown reversed: the re-publication lands");
        assert!(l.ba.has_blob(&sha).await.unwrap(), "I1369: it landed");

        // postgres: a write admitted over a reversed takedown, paused under
        // the shared lock, holds a new takedown off until it commits.
        let Some(arm_inside) = arm_inside else {
            return;
        };
        let other = format!("i1369-locked-{run}").into_bytes();
        let osha = hold(e, &author, &other).await;
        bind_into(dir, &moderator.id, &comm, &hex::encode(osha)).await;
        let m1 = take(osha)
            .await
            .expect("I1369: the locked address's takedown");
        assert!(m1.bytes_destroyed, "I1369: {m1:?}");
        reverse(&m1).await.expect("I1369: reversed");
        let p = arm_inside(l.ba.as_ref());
        let door = e.store_plaintext_local(&osha, other.clone(), None);
        let rest = async {
            tokio::time::timeout(std::time::Duration::from_secs(20), p.reached())
                .await
                .expect("the write reaches its insert");
            let mut next = Box::pin(take(osha));
            let early =
                tokio::time::timeout(std::time::Duration::from_millis(750), &mut next).await;
            assert!(
                early.is_err(),
                "I1369: a takedown completed while a write admitted over a reversal was \
                 uncommitted: {early:?}"
            );
            p.resume();
            next.await.expect("I1369: the takedown, after the write")
        };
        let (got, m2) = Box::pin(async { tokio::join!(door, rest) }).await;
        got.expect("I1369: the write over a reversed takedown committed first");
        assert!(
            m2.bytes_destroyed,
            "I1369: the takedown found the bytes: {m2:?}"
        );
        assert!(
            !l.ba.has_blob(&osha).await.unwrap(),
            "I1369: nothing is left on disk"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1366_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, super::bodies::NODE).await;
        super::bodies::i1366_a_reversal_lifts_the_withholding_at_read(&b, &suffix()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1366_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, super::bodies::NODE).await;
        super::bodies::i1366_a_reversal_lifts_the_withholding_at_read(&b, &suffix()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1367_sqlite() {
        use crate::federation::epoch_minter_invariants::bodies::Pick;
        super::engine_bodies::i1367_the_holders_follow_the_reversal(
            "sqlite::memory:",
            "sqlite::memory:",
            &suffix(),
            (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                as Pick<crate::store::sqlite::SqliteBackend>,
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1367_postgres() {
        use crate::federation::epoch_minter_invariants::bodies::Pick;
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        super::engine_bodies::i1367_the_holders_follow_the_reversal(
            &a,
            &b,
            &suffix(),
            (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                as Pick<crate::store::postgres::PostgresBackend>,
        )
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1369_sqlite() {
        use crate::federation::epoch_minter_invariants::bodies::Pick;
        Box::pin(
            super::engine_bodies::i1369_a_standing_tombstone_refuses_in_the_write(
                "sqlite::memory:",
                "sqlite::memory:",
                &suffix(),
                (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                    as Pick<crate::store::sqlite::SqliteBackend>,
                None,
            ),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1369_postgres() {
        use crate::federation::epoch_minter_invariants::bodies::Pick;
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        Box::pin(
            super::engine_bodies::i1369_a_standing_tombstone_refuses_in_the_write(
                &a,
                &b,
                &suffix(),
                (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                    as Pick<crate::store::postgres::PostgresBackend>,
                Some(|b: &crate::store::postgres::PostgresBackend| {
                    b.test_hooks()
                        .arm_pause(crate::store::test_hooks::BYTES_INSIDE_THE_WRITE)
                }),
            ),
        )
        .await;
    }
}
