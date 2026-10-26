//! v55.0.0 slice C (CIRISPersist#952, #1007, #1059) — **the incremental
//! plaintext DAG write, and the takedown on the CC 2.3 tombstone.**
//!
//! The incremental plaintext chunk DAG (#952; sqlite, postgres — the bytes
//! plane):
//!
//! - **I780** — chunks stored one at a time through `put_plaintext_dag_chunk`
//!   leave no manifest row and no holding claim: the DAG's address is absent
//!   to `blob_head` and `list_holders` until `finalize_blob_chunks_signing`,
//!   which writes the `chunk_dag` row, announces it, and reads whole.
//! - **I781** — a finalize over a chunk not held is `blob_not_held` naming
//!   that chunk, and a manifest entry whose size is not the held row's is
//!   refused naming its index; nothing is written either way, and the same
//!   finalize succeeds once the DAG is whole.
//! - **I782** — the chunk door admits only the manifest entry's bytes (a
//!   wrong hash is `blob_hash_mismatch`, a wrong length refused), and the
//!   finalize refuses a manifest that is not a plaintext v1 DAG (a sealed
//!   version, a `chunk_tier`, no chunks) before reading a row.
//! - **I783** — the incremental write and the one-shot `put_blob_chunks_signing`
//!   produce the same manifest address and the same row.
//!
//! The takedown on the tombstone (#1007; CC 4.5.3 step 2, CC 4.5.5, CC 2.3,
//! CC 3.1.3.3 rule 4):
//!
//! - **I786** (memory, sqlite, postgres) — the takedown is admitted by CC
//!   4.5.5 asked of THIS node's state: a signed subject of the content
//!   executes; a signer with no duty over it, a notice edited after signing,
//!   an expired notice, a basis outside the closed set and `steward_purge`
//!   itself are each `takedown_unauthorised` with nothing written.
//! - **I787** (memory, sqlite, postgres) — one tombstone row for takedown and
//!   purge: the takedown's header is the purge plane's (its `legal_basis`,
//!   `record_count` 1, the digest of `["blob:{sha}"]`, the notice's JCS, no
//!   cosignatures), its one tombstone is on the bytes plane, `purge_status`
//!   and the ledger read it, and a re-run is idempotent.
//! - **I788** (memory, sqlite, postgres) — the bytes plane only: a replicated
//!   takedown naming a claim row, another blob, or one record too many is
//!   `takedown_not_bytes_plane` with nothing written; the age-gate basis
//!   writes no tombstone.
//! - **I789** (memory, sqlite, postgres) — a replicated takedown is
//!   re-verified on the RECEIVER's state: a receiver on which the signer
//!   holds no duty refuses it and records nothing; one on which it does
//!   records it as `replicated`.
//! - **I790** (sqlite, postgres) — this node as a holder: an immediate-removal
//!   basis destroys the bytes on receipt; a counter-notice basis withholds
//!   them at once (`blob_purged`), retracts this node's own claim, and
//!   `purge_finalize` refuses until the window has passed, then deletes.
//! - **I791** (sqlite, postgres) — only the holder retracts a holding claim:
//!   another key's unstamped `withdraws` of this node's holding claim
//!   (`custody:ack:v1` `here`) is `custody_ack_withdraws_not_the_holder` at the door and the claim stands;
//!   the holder's own is admitted. (I791b, the `custody:ack:v1` report, runs
//!   in `dag_link_invariants` where a node holds a custody-scoped blob.)
//! - **I792** (memory, sqlite, postgres) — CLM-derived-rows-follow-reason's
//!   takedown half: the score over content later taken down on a legal basis
//!   STANDS (still held and untombstoned), and its evidence ref resolves to
//!   the takedown's tombstone (`purge_withheld` names the notice).
//! - **I796** (memory, sqlite, postgres) — the content's community is the
//!   HELD binding's: with no row binding the content held here the takedown
//!   is `takedown_content_unbound` (retryable); bound under community Y, a
//!   moderator of X naming X in the notice is refused, and Y's moderator
//!   naming X is judged under Y and admitted.
//! - **I797** (two nodes, sqlite and postgres; and from disk) — bytes a
//!   tombstone took down never come back: after the takedown, the same bytes
//!   re-pushed at either node through `put_blob_signing`,
//!   `store_plaintext_local` and `put_plaintext_dag_chunk` are `blob_purged`
//!   naming the notice and nothing is stored; from disk, every production
//!   function that inserts into `federation_blobs` asks
//!   `refuse_tombstoned_bytes` first, or is named exempt with its reason.
//! - **I798** (memory, sqlite, postgres) — CC 4.5.5 item by item: (b) a live
//!   `takedown`-scoped chain from a steward-bound subject admits its
//!   delegate; a chain without the scope, a chain from a root that is not
//!   steward-bound, a signer with neither, and content whose binding names no
//!   principal at all (no subject, no community) are each refused with
//!   nothing written. (a) is I786 (subject) and I796 (named moderator).
//! - **I799** (memory, sqlite, postgres) — an immediate-removal takedown
//!   records ONE `hard_case:fast_path_takedown` for its notice (CC 4.5.3
//!   step 4), naming the basis, the content and the origin, and a re-run
//!   records no second; a counter-notice takedown records none.
//! - **I772** (memory, sqlite, postgres; Codex r2 on #1065) — only LIVE
//!   bindings confer takedown authority, read as the purge plane reads a
//!   row's subjects: a binding withdrawn by its attester, or expired, names
//!   no subject (its former subject is `takedown_unauthorised` while the live
//!   binding's subject is admitted); a binding's non-empty `attested_key_id`
//!   is a subject; an `affiliations` binding's `community_id` is a bound
//!   community, so that room's moderator is admitted.
//! - **I773** (sqlite, postgres; Codex r2 on #1065) — a plaintext DAG's
//!   chunks belong to it: the incremental finalize and the one-shot door each
//!   write the manifest → chunk relation with the `chunk_dag` row, so after an
//!   immediate-removal takedown of the DAG every chunk is withheld
//!   (`purge_withheld` finds it through `dag_manifests_of_chunk`) and evicted.
//! - **I774** (sqlite, postgres; Codex r2 on #1065) — the plaintext DAG doors
//!   ask the WILL decision of the author: at the stop tier a non-local proxy
//!   author's one-shot DAG (`put_blob_chunks_signing`) and finalize are
//!   `DiskPressureProxyRefused` (`accept`) with nothing stored and nothing
//!   announced; this node's own DAG is still admitted.
//! - **I793** — the settle is the basis's: a steward purge after W = 72 h,
//!   an immediate-removal takedown at once, a counter-notice takedown after
//!   its window, the age gate and an unknown basis never earlier than W.
//! - **I794** — from disk: the takedown handler emits no `withdraws` and runs
//!   no `evict_actor`; both backends' `evict_actor` delegate to
//!   `holding_claim::evict_actor_of` (which retracts only the evicting
//!   signer's claims); the withdraws door asks `check_custody_withdraws_signer`.
//! - **I1170** (memory, sqlite, postgres; v60.0.0, CIRISPersist#803) — a
//!   takedown notice ROW never binds its content: a named moderator's admitted
//!   notice row, its `evidence_refs` naming the digest, adds no subject to the
//!   content's binding. (The notice row's admission and its execution through
//!   the Engine are `cirisnode::rows_invariants`' I1170.) Every takedown
//!   witness here builds its notice as a signed `takedown_notice:{basis}:v1`
//!   row.
//! - **I1171** (memory, sqlite, postgres; v60.x compat) — a v59 peer's
//!   replicated takedown, its notice the retired Contribution in the old
//!   spelling, is still applied (re-verified, re-asked, recorded in CC's
//!   spelling); the local door refuses it as retired.
//! - **I795** (two nodes, sqlite and postgres) — the takedown delivered
//!   through the planes: A takes content down, serves the tombstone as a
//!   purge bundle over JSON, and B applies it, re-verified on B's state, and
//!   destroys B's own copy on receipt.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::steward_purge::{self as sp, PurgePlane};
    use crate::federation::takedown_tombstone::{
        self as td, token, TakedownDisposition, TakedownNotice,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, Attestation, SignedAttestation};
    use crate::federation::FederationDirectory;

    /// A takedown claimant: a federation key id (lowercase, CC 2.3.2.1), whose
    /// deterministic hybrid key the test signer derives from the id.
    /// v60.0.0 (CIRISPersist#803, #854) — the notice is a row the claimant
    /// signs, so the claimant is a federation key, not a raw base64 pubkey.
    pub(crate) struct Claimant {
        pub(crate) id: String,
    }

    pub(crate) fn claimant(seed: u8) -> Claimant {
        Claimant {
            id: format!("td-claimant-{seed:02x}"),
        }
    }

    /// A `takedown_notice:{basis}:v1` ROW (CC 3.1.1 / CC 3.3.2), signed by
    /// the claimant: the CC 3.3.2 members at the envelope's top level,
    /// score `-1`, `claimant_key_id` = the signer, the notice's `expires_at`
    /// the row's. v60.0.0 (CIRISPersist#803).
    pub(crate) fn notice_at(
        c: &Claimant,
        sha_hex: &str,
        basis: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> TakedownNotice {
        notice_row_with(c, sha_hex, basis, asserted_at, expires_at, |_| {})
    }

    /// [`notice_at`] with `edit` applied to the envelope BEFORE the seal.
    pub(crate) fn notice_row_with(
        c: &Claimant,
        sha_hex: &str,
        basis: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> TakedownNotice {
        let mut env = serde_json::json!({
            "dimension": td::notice_dimension(basis),
            "score": -1.0,
            "confidence": 1.0,
            "subject_kind": "takedown_notice",
            "content_sha256": sha_hex,
            "claimant_key_id": c.id,
            "legal_basis": basis,
            "jurisdiction": "US",
            "good_faith_statement": "good faith",
            "claim_text": "claim",
        });
        edit(&mut env);
        let mut row = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), &c.id, &c.id, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.weight = None;
        row.asserted_at = asserted_at;
        row.scrub_timestamp = asserted_at;
        row.expires_at = Some(expires_at);
        let row = ts::seal_row(&c.id, row);
        TakedownNotice::of_row(&row).expect("a notice row serializes")
    }

    pub(crate) fn notice(c: &Claimant, sha_hex: &str, basis: &str) -> TakedownNotice {
        let t = chrono::Utc::now();
        notice_at(c, sha_hex, basis, t, t + chrono::Duration::days(30))
    }

    /// [`notice`] whose envelope NAMES `community` (a claim the door never
    /// reads), sealed with it.
    pub(crate) fn notice_naming(
        c: &Claimant,
        sha_hex: &str,
        basis: &str,
        community: &str,
    ) -> TakedownNotice {
        let t = chrono::Utc::now();
        notice_row_with(c, sha_hex, basis, t, t + chrono::Duration::days(30), |e| {
            e["community_id"] = serde_json::json!(community);
        })
    }

    /// v60.x COMPAT fixture — a v59 peer's `takedown_notice` CONTRIBUTION,
    /// shaped as `ContributionEnvelope` serialized and self-signed Ed25519 by
    /// the raw key whose base64 pubkey is `author_id`, in the pre-v60 basis
    /// spelling. Returns `(notice, author_id)`.
    pub(crate) fn legacy_contribution_notice(
        seed: u8,
        sha_hex: &str,
        legacy_basis: &str,
    ) -> (TakedownNotice, String) {
        legacy_contribution_notice_with(seed, sha_hex, legacy_basis, |_| {})
    }

    /// [`legacy_contribution_notice`] with `edit` applied to the payload
    /// BEFORE the self-signature.
    pub(crate) fn legacy_contribution_notice_with(
        seed: u8,
        sha_hex: &str,
        legacy_basis: &str,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> (TakedownNotice, String) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let author = B64.encode(key.verifying_key().to_bytes());
        let t = chrono::Utc::now();
        let ts_of = |t: chrono::DateTime<chrono::Utc>| serde_json::to_value(t).unwrap();
        let mut env = serde_json::json!({
            "contribution_id": uuid::Uuid::new_v4().to_string(),
            "contribution_type": "proposal",
            "author_id": author,
            "subject": {"domain": "media", "language": "en", "subject": "takedown_notice"},
            "payload": {
                "content_sha256": sha_hex,
                "claimant_key_id": author,
                "legal_basis": legacy_basis,
                "jurisdiction": "US",
                "good_faith_statement": "good faith",
                "claim_text": "claim",
                "asserted_at": ts_of(t),
                "expires_at": ts_of(t + chrono::Duration::days(30)),
            },
            "witness_set": null,
            "signature": {"ed25519": "", "ml_dsa_65": null, "signed_at": ts_of(t)},
            "submitted_at": ts_of(t),
        });
        edit(&mut env["payload"]);
        let canonical = crate::verify::canonical::canonicalize_envelope_for_signing(&env).unwrap();
        env["signature"]["ed25519"] =
            serde_json::json!(B64.encode(key.sign(&canonical).to_bytes()));
        (TakedownNotice { envelope: env }, author)
    }

    // ── I1170 (binding) ───────────────────────────────────────────────────
    /// v60.0.0 (#803) — a takedown notice ROW is about the content, never a
    /// binding of it: a named moderator's admitted notice row, whose
    /// `evidence_refs` name the digest and whose attested key is its signer,
    /// adds no subject to the content's binding (`content_binding` skips the
    /// `takedown_notice:` family).
    pub(crate) async fn i1170_a_notice_row_never_binds_its_content<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let sha = sha_of("i1170b");
        let moderator = claimant(0x6d);
        let comm = "i1170b-comm";
        let binder = claimant(0x6e);
        // Two members: the binder writes the room's binding row, the
        // moderator files the notice.
        group_of(dir, comm, &[&moderator.id, &binder.id], None).await;
        bind_row(
            dir,
            &binder.id,
            &binder.id,
            &[],
            &sha,
            crate::federation::types::cohort_scope::COMMUNITY,
            Some(comm),
            None,
        )
        .await
        .expect("I1170: the binding row");
        let t = chrono::Utc::now();
        let n = notice_row_with(
            &moderator,
            &sha,
            "dmca512",
            t,
            t + chrono::Duration::days(1),
            |e| {
                e["evidence_refs"] = serde_json::json!([sha.clone()]);
            },
        );
        let row: Attestation = serde_json::from_value(n.envelope.clone()).unwrap();
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("I1170: the named moderator's notice row is admitted");
        let binding = td::content_binding(dir, &sha).await.unwrap().unwrap();
        assert!(
            !binding.subjects.contains(&moderator.id),
            "I1170: the notice row is not a binding: {binding:?}"
        );
    }

    // ── I1171 ─────────────────────────────────────────────────────────────
    /// v60.x compat (one release): a v59 peer's replicated takedown, its
    /// notice the retired Contribution in the old spelling, is still applied
    /// — re-verified (Ed25519, as v59 did) and re-asked under CC 4.5.5 here,
    /// recorded under CC 3.3.2's spelling. The LOCAL door refuses the same
    /// Contribution: a notice filed here is a row.
    pub(crate) async fn i1171_a_v59_peers_contribution_notice_still_applies<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let sha = sha_of("i1171");
        let (n, author) = legacy_contribution_notice(0x6b, &sha, "dmca_512");
        // The legacy author moderates the room the content is bound into.
        let comm = "i1171-comm";
        let binder = claimant(0x6c);
        group_of(dir, comm, &[&author, &binder.id], None).await;
        bind_row(
            dir,
            &binder.id,
            &binder.id,
            &[],
            &sha,
            crate::federation::types::cohort_scope::COMMUNITY,
            Some(comm),
            None,
        )
        .await
        .expect("I1171: the binding row");
        let e = td::takedown_tombstone(dir, &n, NODE)
            .await
            .expect_err("I1171: the local door takes a notice row only");
        assert_eq!(e.kind(), token::UNAUTHORISED, "I1171: {e}");
        assert!(
            e.to_string().contains("retired"),
            "I1171: named as retired: {e}"
        );
        let record = format!("blob:{sha}");
        // A whitespace member is empty (the compat read keeps v59's rule),
        // even signed.
        let (blank, _) = legacy_contribution_notice_with(0x6b, &sha, "dmca_512", |p| {
            p["claimant_key_id"] = serde_json::json!("  ");
        });
        let e =
            td::apply_replicated_takedown(dir, &blank, std::slice::from_ref(&record), "receiver")
                .await
                .expect_err("I1171: a blank claim_text");
        assert_eq!(e.kind(), token::UNAUTHORISED, "I1171: {e}");
        let r = td::apply_replicated_takedown(dir, &n, &[record], "receiver")
            .await
            .expect("I1171: the v59 peer's replicated notice is applied (compat)");
        assert_eq!(r.legal_basis, "dmca512", "I1171: recorded in CC's spelling");
        assert_eq!(
            r.notice_attestation_id, None,
            "I1171: a Contribution has no row"
        );
        let e = dir.purge_execution(&r.notice_id).await.unwrap().unwrap();
        assert_eq!(e.legal_basis, "dmca512");
        assert_eq!(e.origin, sp::origin::REPLICATED);
    }

    /// A community whose only member is `member` (a person, so a
    /// steward-bound authority root: a named moderator).
    pub(crate) async fn community_of(dir: &dyn FederationDirectory, comm: &str, member: &str) {
        group_of(dir, comm, &[member], None).await
    }

    /// [`community_of`] with a `policy_blob` (an `affiliations` group).
    async fn group_of(
        dir: &dyn FederationDirectory,
        comm: &str,
        members: &[&str],
        policy_blob: Option<serde_json::Value>,
    ) {
        for k in std::iter::once(&comm).chain(members) {
            if dir.lookup_public_key(k).await.unwrap().is_none() {
                ts::register_hybrid_key_as(
                    dir,
                    k,
                    k,
                    crate::federation::types::identity_type::USER,
                )
                .await;
            }
        }
        dir.put_community(ts::sign_community(
            comm,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: comm.to_owned(),
                community_name: comm.to_owned(),
                members: members
                    .iter()
                    .map(|m| crate::federation::types::CommunityMember {
                        key_id: (*m).to_owned(),
                        joined_at: chrono::Utc::now(),
                        role: None,
                    })
                    .collect(),
                founded_at: chrono::Utc::now(),
                consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                    .to_owned(),
                policy_blob,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("community {comm}: {e}"));
    }

    // ── I796 ──────────────────────────────────────────────────────────────
    /// The content's community is the HELD binding's, never the notice's.
    pub(crate) async fn i796_the_contents_own_community_judges<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let (mod_y, mod_x) = (claimant(0x79), claimant(0x7a));
        let (comm_y, comm_x) = ("i796-comm-y", "i796-comm-x");
        community_of(dir, comm_y, &mod_y.id).await;
        community_of(dir, comm_x, &mod_x.id).await;
        let sha = sha_of("i796");

        // Not bound here yet: retryable, nothing written.
        let e = td::takedown_tombstone(dir, &notice_naming(&mod_y, &sha, "dmca512", comm_y), NODE)
            .await
            .expect_err("I796: no binding row held");
        assert_eq!(e.kind(), token::CONTENT_UNBOUND, "I796: {e}");

        // Bound under Y, by a row at community scope.
        let now = chrono::Utc::now();
        let row = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: mod_y.id.clone(),
            attested_key_id: mod_y.id.clone(),
            attestation_type: attestation_type::SCORES.into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": "content:established:v1",
                "evidence_refs": [sha],
                "community_id": comm_y,
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: mod_y.id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::COMMUNITY.to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_attestation(SignedAttestation {
            attestation: ts::seal_row(&mod_y.id, row),
        })
        .await
        .expect("I796: the binding row under Y");

        // X's moderator names X: judged under Y, refused.
        let e = td::takedown_tombstone(dir, &notice_naming(&mod_x, &sha, "dmca512", comm_x), NODE)
            .await
            .expect_err("I796: X's moderator over Y's content");
        assert_eq!(e.kind(), token::UNAUTHORISED, "I796: {e}");
        assert_eq!(dir.purge_tombstoned("blob", &sha).await.unwrap(), None);
        // Y's moderator, whatever community the notice names, is Y's.
        let ok = td::takedown_tombstone(dir, &notice_naming(&mod_y, &sha, "dmca512", comm_x), NODE)
            .await
            .expect("I796: Y's named moderator over Y's content");
        assert!(ok.tombstoned);
    }

    /// Register `subject` and make it the SIGNED subject of `sha_hex`: the
    /// content's establishing `scores` row (CC 4.5.5 subject_of), produced by
    /// `producer`. Returns the row's id — a score over the content.
    pub(crate) async fn establish(
        dir: &dyn FederationDirectory,
        producer: &str,
        subject: &str,
        sha_hex: &str,
    ) -> String {
        for k in [producer, subject] {
            if dir.lookup_public_key(k).await.unwrap().is_none() {
                ts::register_hybrid_key(dir, k).await;
            }
        }
        let now = chrono::Utc::now();
        let id = uuid::Uuid::new_v4().to_string();
        let row = Attestation {
            attestation_id: id.clone(),
            attesting_key_id: producer.into(),
            attested_key_id: producer.into(),
            attestation_type: attestation_type::SCORES.into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": "content:established:v1",
                "evidence_refs": [sha_hex],
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: producer.into(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_owned()],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        let row = ts::seal_row(producer, row);
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("the establishing row");
        id
    }

    /// A content-binding `scores` row over `sha_hex` by `producer`, attested
    /// to `attested`, with `subjects`, at `scope` naming `community`.
    #[allow(clippy::too_many_arguments)]
    async fn bind_row(
        dir: &dyn FederationDirectory,
        producer: &str,
        attested: &str,
        subjects: &[&str],
        sha_hex: &str,
        scope: &str,
        community: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<String, crate::federation::Error> {
        for k in [producer, attested].iter().chain(subjects) {
            if dir.lookup_public_key(k).await.unwrap().is_none() {
                ts::register_hybrid_key(dir, k).await;
            }
        }
        let now = chrono::Utc::now();
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({
            "dimension": "content:established:v1",
            "evidence_refs": [sha_hex],
        });
        if let Some(c) = community {
            env["community_id"] = serde_json::json!(c);
        }
        let row = Attestation {
            attestation_id: id.clone(),
            attesting_key_id: producer.into(),
            attested_key_id: attested.into(),
            attestation_type: attestation_type::SCORES.into(),
            weight: None,
            asserted_at: now,
            expires_at,
            attestation_envelope: env,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: producer.into(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: subjects.iter().map(|s| (*s).to_owned()).collect(),
            withdraws_admission_rule: None,
            cohort_scope: scope.to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_attestation(SignedAttestation {
            attestation: ts::seal_row(producer, row),
        })
        .await
        .map(|_| id)
    }

    // ── I772 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i772_only_live_bindings_confer_takedown_authority<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        use crate::federation::types::cohort_scope as cs;
        let dir = d.as_dyn_directory();
        let producer = "i772-producer";
        let auth = |signer: String, sha: String| async move {
            td::takedown_authority(dir, &signer, &sha, "dmca512").await
        };
        let unauthorised = |r: Result<(), crate::federation::Error>| matches!(&r, Err(e) if e.kind() == token::UNAUTHORISED);

        // (1) Retired vs live: two bindings of one digest; the first is
        // withdrawn by its attester.
        let (old, new) = (claimant(0x91), claimant(0x92));
        let sha = sha_of("i772-retired");
        let r_old = bind_row(
            dir,
            producer,
            producer,
            &[&old.id],
            &sha,
            cs::FEDERATION,
            None,
            None,
        )
        .await
        .expect("I772: the first binding");
        bind_row(
            dir,
            producer,
            producer,
            &[&new.id],
            &sha,
            cs::FEDERATION,
            None,
            None,
        )
        .await
        .expect("I772: the live binding");
        assert!(
            auth(old.id.clone(), sha.clone()).await.is_ok(),
            "I772 precondition"
        );
        let env = serde_json::json!({
            "references_attestation_id": r_old,
            "withdrawal_reason": "I772",
        });
        let mut w =
            ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), producer, producer, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.cohort_scope = "federation".into();
        ts::seal_row_in_place(producer, &mut w);
        dir.put_attestation(SignedAttestation { attestation: w })
            .await
            .expect("I772: the attester withdraws its binding");
        assert!(
            unauthorised(auth(old.id.clone(), sha.clone()).await),
            "I772 (1): the withdrawn binding's former subject is refused"
        );
        assert!(
            auth(new.id.clone(), sha.clone()).await.is_ok(),
            "I772 (1): the live binding's subject is admitted"
        );

        // (2) An expired binding names no subject.
        let gone = claimant(0x93);
        let sha2 = sha_of("i772-expired");
        bind_row(
            dir,
            producer,
            producer,
            &[&new.id],
            &sha2,
            cs::FEDERATION,
            None,
            None,
        )
        .await
        .expect("I772: a live binding");
        let past = chrono::Utc::now() + chrono::Duration::milliseconds(300);
        bind_row(
            dir,
            producer,
            producer,
            &[&gone.id],
            &sha2,
            cs::FEDERATION,
            None,
            Some(past),
        )
        .await
        .expect("I772: a binding that expires");
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        assert!(
            unauthorised(auth(gone.id.clone(), sha2.clone()).await),
            "I772 (2): an expired binding's subject is refused"
        );

        // (3) The attested key is a subject.
        let attested = claimant(0x94);
        let sha3 = sha_of("i772-attested");
        bind_row(
            dir,
            producer,
            &attested.id,
            &[],
            &sha3,
            cs::FEDERATION,
            None,
            None,
        )
        .await
        .expect("I772: a binding attested to its subject");
        assert!(
            auth(attested.id.clone(), sha3.clone()).await.is_ok(),
            "I772 (3): the attested key is a signed subject"
        );

        // (4) An affiliations binding's room is a bound community.
        let (moderator, writer) = (claimant(0x95), claimant(0x96));
        let room = "i772-room";
        group_of(
            dir,
            room,
            &[&moderator.id, &writer.id],
            Some(crate::federation::affiliation_invariants::bodies::affiliation_blob(None)),
        )
        .await;
        let sha4 = sha_of("i772-affiliations");
        // Written by another member, attested to itself: the moderator is
        // neither a subject nor the attested key, so only the room makes it a
        // duty-holder.
        bind_row(
            dir,
            &writer.id,
            &writer.id,
            &[],
            &sha4,
            cs::AFFILIATIONS,
            Some(room),
            None,
        )
        .await
        .expect("I772: an affiliations binding");
        assert!(
            auth(moderator.id.clone(), sha4.clone()).await.is_ok(),
            "I772 (4): the affiliations room's moderator is admitted"
        );
    }

    fn sha_of(seed: &str) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(seed.as_bytes()))
    }

    const NODE: &str = "c-node-1";

    // ── I786 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i786_a_takedown_is_admitted_by_cc_4_5_5_here<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let owner = claimant(0x71);
        let stranger = claimant(0x72);
        // A keyed stranger: its notice row verifies, and it holds no duty.
        ts::register_hybrid_key(dir, &stranger.id).await;
        let sha = sha_of("i786");
        establish(dir, "i786-producer", &owner.id, &sha).await;
        let unauth = |r: Result<td::TakedownReport, crate::federation::Error>, why: &str| {
            let e = r.expect_err(why);
            assert_eq!(e.kind(), token::UNAUTHORISED, "I786 {why}: {e}");
        };

        unauth(
            td::takedown_tombstone(dir, &notice(&stranger, &sha, "dmca512"), NODE).await,
            "a signer with no duty over the content",
        );
        let mut edited = notice(&owner, &sha, "dmca512");
        edited.envelope["attestation_envelope"]["claim_text"] =
            serde_json::json!("edited after signing");
        unauth(
            td::takedown_tombstone(dir, &edited, NODE).await,
            "a notice edited after signing",
        );
        let t = chrono::Utc::now();
        unauth(
            td::takedown_tombstone(
                dir,
                &notice_at(
                    &owner,
                    &sha,
                    "dmca512",
                    t - chrono::Duration::days(40),
                    t - chrono::Duration::days(10),
                ),
                NODE,
            )
            .await,
            "an expired notice",
        );
        unauth(
            td::takedown_tombstone(dir, &notice(&owner, &sha, "not_a_basis"), NODE).await,
            "a basis outside the closed set",
        );
        unauth(
            td::takedown_tombstone(dir, &notice(&owner, &sha, sp::STEWARD_PURGE_BASIS), NODE).await,
            "steward_purge is the trust root's cosigned purge, not a takedown",
        );
        assert_eq!(
            dir.purge_tombstoned("blob", &sha).await.unwrap(),
            None,
            "I786: no refused notice wrote a tombstone"
        );

        let ok = td::takedown_tombstone(dir, &notice(&owner, &sha, "dmca512"), NODE)
            .await
            .expect("I786: a signed subject of the content takes it down");
        assert!(ok.tombstoned);
        assert_eq!(ok.signer, owner.id);
        assert_eq!(
            dir.purge_tombstoned("blob", &sha).await.unwrap(),
            Some(ok.notice_id)
        );
    }

    // ── I787 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i787_one_tombstone_row_for_takedown_and_purge<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let owner = claimant(0x73);
        let sha = sha_of("i787");
        establish(dir, "i787-producer", &owner.id, &sha).await;
        let n = notice(&owner, &sha, "ncmec_csam");
        let r = td::takedown_tombstone(dir, &n, NODE).await.unwrap();
        assert!(r.tombstoned);
        assert_eq!(r.disposition, TakedownDisposition::DestroyOnReceipt);

        let e = dir
            .purge_execution(&r.notice_id)
            .await
            .unwrap()
            .expect("I787: the header is the purge plane's");
        assert_eq!(e.legal_basis, "ncmec_csam");
        assert_eq!(e.record_count, 1);
        assert_eq!(e.claimant_key_id, owner.id);
        assert_eq!(e.cosignatures_json, "[]");
        assert_eq!(e.origin, sp::origin::LOCAL);
        let record = format!("blob:{sha}");
        assert_eq!(
            e.selection_digest,
            sp::selection_digest(&[record.as_str()]),
            "I787: the digest is the one-record selection's"
        );
        use sha2::Digest as _;
        assert_eq!(
            hex::encode(sha2::Sha256::digest(e.notice_jcs.as_bytes())),
            r.notice_id,
            "I787: the notice id is the hash of the stored notice"
        );
        // v60.0.0 (#803, CC 3.3.2) — the stored notice IS the notice row: the
        // tombstone cites its `attestation_id`, and the row is held.
        let row_id = n.envelope["attestation_id"].as_str().unwrap().to_owned();
        assert_eq!(r.notice_attestation_id.as_deref(), Some(row_id.as_str()));
        assert!(
            e.notice_jcs.contains(&row_id),
            "I787: the header carries the notice row"
        );
        assert!(
            dir.get_attestation(&row_id).await.unwrap().is_some(),
            "I787: the notice row the tombstone cites is held"
        );
        assert!(
            !e.notice_jcs.contains("\"bytes\""),
            "I787: the notice carries the digest, never content"
        );
        let stones = dir.purge_tombstones_of(&r.notice_id).await.unwrap();
        assert_eq!(stones.len(), 1);
        assert_eq!(
            (stones[0].plane, stones[0].record_ref.as_str()),
            (PurgePlane::Blob, sha.as_str()),
            "I787: one row per record, keyed by its digest, on the bytes plane"
        );
        let status = sp::purge_status(dir, &r.notice_id).await.unwrap();
        assert_eq!(status.tombstones.get("blob"), Some(&1));
        assert_eq!(
            status.settles_at, e.executed_at,
            "I787: an immediate-removal basis settles on receipt"
        );
        let ledger = sp::purge_ledger_tsv(dir, &r.notice_id).await.unwrap();
        assert!(
            ledger.contains("# legal_basis\tncmec_csam\n"),
            "I787: the ledger names the basis:\n{ledger}"
        );
        let again = td::takedown_tombstone(dir, &n, NODE).await.unwrap();
        assert!(!again.tombstoned, "I787: a re-run writes nothing new");
        assert_eq!(again.notice_id, r.notice_id);
        assert_eq!(
            dir.purge_tombstones_of(&r.notice_id).await.unwrap().len(),
            1
        );
        // I799 — the fast path enters the audit trail (CC 4.5.3 step 4),
        // once per notice.
        let cases = fast_path_cases(dir).await;
        assert_eq!(
            cases
                .iter()
                .filter(|c| c.target_key_id.as_deref() == Some(r.notice_id.as_str()))
                .count(),
            1,
            "I799: one hard_case:fast_path_takedown for the notice: {cases:?}"
        );
        let c = cases
            .iter()
            .find(|c| c.target_key_id.as_deref() == Some(r.notice_id.as_str()))
            .unwrap();
        assert_eq!(c.detail["legal_basis"], "ncmec_csam");
        assert_eq!(c.detail["content_sha256"], sha.as_str());
        assert_eq!(c.detail["origin"], sp::origin::LOCAL);
    }

    async fn fast_path_cases(
        dir: &dyn FederationDirectory,
    ) -> Vec<crate::federation::hard_case::HardCaseEvent> {
        dir.list_hard_case_events(crate::federation::hard_case::HardCaseFilter {
            kind: Some(crate::federation::hard_case::kind::FAST_PATH_TAKEDOWN.to_owned()),
            since: None,
            emitter_key_id: None,
        })
        .await
        .unwrap()
    }

    /// A `delegates_to(granter → grantee)` bearing `scope`, really signed.
    async fn delegate(dir: &dyn FederationDirectory, granter: &str, grantee: &str, scope: &[&str]) {
        let id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({"references_attestation_id": id, "scope": scope});
        // v60.0.0 (#1048) — a duty edge carries a term (CC 2.4).
        crate::federation::admission::with_test_term(&mut envelope, chrono::Utc::now());
        let mut row = ts::bare_attestation(&id, granter, grantee, &envelope);
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        ts::seal_row_in_place(granter, &mut row);
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("the delegation");
    }

    // ── I798 ──────────────────────────────────────────────────────────────
    /// CC 4.5.5, item by item: (a) the signer itself holds the duty (I786
    /// subject-self, I796 named moderator); (b) a live `takedown`-scoped
    /// chain to the signer from a STEWARD-BOUND root that holds the duty;
    /// otherwise reject, and a missing principal never admits.
    pub(crate) async fn i798_cc_4_5_5_item_by_item<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        use crate::federation::types::identity_type::{AGENT, USER};
        let dir = d.as_dyn_directory();
        let (owner, delegate_ok, delegate_cr, machine, machine_delegate, nobody) = (
            claimant(0x81),
            claimant(0x82),
            claimant(0x83),
            claimant(0x84),
            claimant(0x85),
            claimant(0x86),
        );
        for (c, kind) in [
            (&owner, USER),
            (&delegate_ok, AGENT),
            (&delegate_cr, AGENT),
            (&machine, AGENT),
            (&machine_delegate, AGENT),
            (&nobody, AGENT),
        ] {
            ts::register_hybrid_key_as(dir, &c.id, &c.id, kind).await;
        }
        let sha = sha_of("i798");
        establish(dir, "i798-producer", &owner.id, &sha).await;
        let refused = |r: Result<td::TakedownReport, crate::federation::Error>, why: &str| {
            let e = r.expect_err(why);
            assert_eq!(e.kind(), token::UNAUTHORISED, "I798 {why}: {e}");
        };

        // (b) a takedown-scoped chain from the steward-bound subject.
        delegate(dir, &owner.id, &delegate_ok.id, &["takedown"]).await;
        // A chain that does not bear the duty's scope.
        delegate(dir, &owner.id, &delegate_cr.id, &["consent_revocation"]).await;
        refused(
            td::takedown_tombstone(dir, &notice(&delegate_cr, &sha, "court_order"), NODE).await,
            "(b) a chain without the takedown scope",
        );
        refused(
            td::takedown_tombstone(dir, &notice(&nobody, &sha, "court_order"), NODE).await,
            "neither (a) nor (b)",
        );
        assert_eq!(dir.purge_tombstoned("blob", &sha).await.unwrap(), None);
        let ok = td::takedown_tombstone(dir, &notice(&delegate_ok, &sha, "court_order"), NODE)
            .await
            .expect("I798 (b): delegated from a steward-bound duty-holder");
        assert!(ok.tombstoned);

        // (b) the root must be steward-bound: a machine subject's delegate is
        // refused (the machine itself holds the duty as subject, (a)).
        let sha2 = sha_of("i798-machine");
        establish(dir, "i798-producer", &machine.id, &sha2).await;
        delegate(dir, &machine.id, &machine_delegate.id, &["takedown"]).await;
        refused(
            td::takedown_tombstone(dir, &notice(&machine_delegate, &sha2, "court_order"), NODE)
                .await,
            "(b) a chain from a root that is not steward-bound",
        );
        assert_eq!(dir.purge_tombstoned("blob", &sha2).await.unwrap(), None);

        // A missing principal never admits: content bound with no subject and
        // no community has no duty-holder at all, not even its producer.
        let sha3 = sha_of("i798-orphan");
        let now = chrono::Utc::now();
        let mut row = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            "i798-producer",
            "i798-producer",
            &serde_json::json!({"dimension": "content:established:v1", "evidence_refs": [sha3]}),
        );
        row.attestation_type = attestation_type::SCORES.to_owned();
        row.asserted_at = now;
        ts::seal_row_in_place("i798-producer", &mut row);
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("a binding row with no subject");
        let producer = claimant(0x87);
        ts::register_hybrid_key_as(dir, &producer.id, &producer.id, USER).await;
        refused(
            td::takedown_tombstone(dir, &notice(&producer, &sha3, "court_order"), NODE).await,
            "no principal: no subject, no community",
        );
        assert_eq!(dir.purge_tombstoned("blob", &sha3).await.unwrap(), None);
    }

    // ── I788 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i788_a_takedown_reaches_the_bytes_plane_only<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let owner = claimant(0x74);
        let sha = sha_of("i788");
        let score = establish(dir, "i788-producer", &owner.id, &sha).await;
        let n = notice(&owner, &sha, "court_order");
        let other = sha_of("i788-other");
        for ids in [
            vec![format!("attestation:{score}")],
            vec![format!("blob:{other}")],
            vec![format!("attestation:{score}"), format!("blob:{sha}")],
            vec![],
        ] {
            let e = td::apply_replicated_takedown(dir, &n, &ids, NODE)
                .await
                .expect_err("I788: a takedown names exactly its content's bytes");
            assert_eq!(e.kind(), token::NOT_BYTES_PLANE, "I788 {ids:?}: {e}");
        }
        assert_eq!(dir.purge_tombstoned("blob", &sha).await.unwrap(), None);
        assert_eq!(
            dir.purge_tombstoned("attestation", &score).await.unwrap(),
            None,
            "I788: a duty-holder tombstone never reaches a claim row"
        );

        let age = td::takedown_tombstone(dir, &notice(&owner, &sha, td::AGE_GATE_BASIS), NODE)
            .await
            .expect("I788: an age-gate notice is admitted");
        assert_eq!(age.disposition, TakedownDisposition::AgeGate);
        assert!(!age.tombstoned);
        assert_eq!(age.settles_at, None);
        assert!(
            dir.purge_execution(&age.notice_id).await.unwrap().is_none(),
            "I788: the age gate writes no tombstone"
        );
    }

    // ── I789 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i789_a_replicated_takedown_is_reverified_here<D>(sender: &D, receiver: &D)
    where
        D: FederationDirectory + Sync,
    {
        let (a, b) = (sender.as_dyn_directory(), receiver.as_dyn_directory());
        let owner = claimant(0x75);
        let sha = sha_of("i789");
        establish(a, "i789-producer", &owner.id, &sha).await;
        let r = td::takedown_tombstone(a, &notice(&owner, &sha, "gifct_cip"), NODE)
            .await
            .unwrap();
        let bundle = sp::list_purge_bundles_since(a, None, 10)
            .await
            .unwrap()
            .into_iter()
            .find(|x| td::is_takedown_notice_envelope(&x.notice.envelope))
            .expect("I789: the takedown is served on the tombstone plane");
        // Over the wire.
        let bundle: sp::PurgeBundle =
            serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
        let n = TakedownNotice {
            envelope: bundle.notice.envelope.clone(),
        };
        // v60.0.0 (#803) — the notice is a row: on a receiver that does not
        // hold its signer's key yet the refusal is that ordering gap,
        // retryable, never a verdict on the notice.
        let e = td::apply_replicated_takedown(b, &n, &bundle.record_ids, "receiver")
            .await
            .expect_err("I789: the receiver does not hold the signer's key yet");
        assert_eq!(
            e.kind(),
            "federation_attester_key_unknown",
            "I789: retryable: {e}"
        );
        ts::register_hybrid_key(b, &owner.id).await;
        let e = td::apply_replicated_takedown(b, &n, &bundle.record_ids, "receiver")
            .await
            .expect_err("I789: the receiver holds no row binding the content");
        assert_eq!(e.kind(), token::CONTENT_UNBOUND, "I789: retryable: {e}");
        assert!(b.purge_execution(&r.notice_id).await.unwrap().is_none());
        // Bound on the receiver, but to another subject: no duty here.
        let other = claimant(0x7b);
        establish(b, "i789-producer", &other.id, &sha).await;
        let e = td::apply_replicated_takedown(b, &n, &bundle.record_ids, "receiver")
            .await
            .expect_err("I789: the signer holds no duty on the receiver");
        assert_eq!(e.kind(), token::UNAUTHORISED, "I789: {e}");
        assert!(b.purge_execution(&r.notice_id).await.unwrap().is_none());

        establish(b, "i789-producer", &owner.id, &sha).await;
        let applied = td::apply_replicated_takedown(b, &n, &bundle.record_ids, "receiver")
            .await
            .expect("I789: re-verified on the receiver's own state");
        assert_eq!(applied.notice_id, r.notice_id);
        let e = b.purge_execution(&r.notice_id).await.unwrap().unwrap();
        assert_eq!(e.origin, sp::origin::REPLICATED);
        assert_eq!(e.legal_basis, "gifct_cip");
        assert_eq!(
            b.purge_tombstoned("blob", &sha).await.unwrap(),
            Some(r.notice_id)
        );
    }

    // ── I792 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i792_a_score_over_taken_down_content_stands<D>(d: &D)
    where
        D: FederationDirectory + Sync,
    {
        let dir = d.as_dyn_directory();
        let owner = claimant(0x76);
        let sha = sha_of("i792");
        let score = establish(dir, "i792-producer", &owner.id, &sha).await;
        let r = td::takedown_tombstone(dir, &notice(&owner, &sha, "dsa_article16"), NODE)
            .await
            .unwrap();
        assert!(
            dir.get_attestation(&score).await.unwrap().is_some(),
            "I792: the score over the taken-down content stands"
        );
        assert_eq!(
            dir.purge_tombstoned("attestation", &score).await.unwrap(),
            None,
            "I792: the takedown tombstones no claim row"
        );
        let mut raw = [0u8; 32];
        hex::decode_to_slice(&sha, &mut raw).unwrap();
        assert_eq!(
            sp::purge_withheld(dir, &raw).await.unwrap(),
            Some(r.notice_id.clone()),
            "I792: its evidence ref resolves to the takedown's tombstone"
        );
        assert!(
            !fast_path_cases(dir)
                .await
                .iter()
                .any(|c| c.target_key_id.as_deref() == Some(r.notice_id.as_str())),
            "I799: a counter-notice takedown is not the fast path"
        );
    }

    // ── I793 ──────────────────────────────────────────────────────────────
    pub(crate) fn i793_the_settle_is_the_basis() {
        let t = chrono::Utc::now();
        let e = |basis: &str| sp::PurgeExecution {
            notice_id: "ab".repeat(32),
            selection_digest: "cd".repeat(32),
            claimant_key_id: "k".into(),
            legal_basis: basis.into(),
            record_count: 1,
            notice_jcs: "{}".into(),
            cosignatures_json: "[]".into(),
            executed_by: NODE.into(),
            origin: sp::origin::LOCAL.into(),
            executed_at: t,
            admitted_at: t,
            finalized_at: None,
        };
        let w = t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS);
        assert_eq!(td::settles_at(&e(sp::STEWARD_PURGE_BASIS)), w);
        for b in td::IMMEDIATE_REMOVAL_BASES {
            assert_eq!(td::settles_at(&e(b)), t, "I793 {b}: destroy on receipt");
        }
        for (b, days) in td::COUNTER_NOTICE_BASES {
            assert_eq!(
                td::settles_at(&e(b)),
                t + chrono::Duration::days(*days),
                "I793 {b}: after its counter-notice window"
            );
        }
        assert_eq!(td::settles_at(&e(td::AGE_GATE_BASIS)), w);
        assert_eq!(
            td::settles_at(&e("unknown_basis")),
            w,
            "I793: never earlier"
        );
        assert_eq!(
            td::IMMEDIATE_REMOVAL_BASES,
            &[
                "tvec_terrorist",
                "ncmec_csam",
                "gifct_cip",
                "perceptual_hash_csam",
                "court_order"
            ],
            "I793: CC 4.5.3's immediate-removal set"
        );
        assert_eq!(
            token::ALL,
            &[
                "takedown_unauthorised",
                "takedown_not_bytes_plane",
                "takedown_content_unbound"
            ]
        );
    }
}

/// The Engine-level witnesses: the bytes plane (sqlite, postgres).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod engine_bodies {
    use super::bodies::{claimant, establish, notice};
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::steward_purge::{self as sp, test_clock};
    use crate::federation::takedown_tombstone::TakedownDisposition;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::FederationDirectory;
    use crate::federation::{BlobBody, BlobError, BlobStorage, ChunkManifest, ChunkRef};
    use sha2::Digest as _;

    fn plaintext_manifest(segs: &[Vec<u8>]) -> ChunkManifest {
        ChunkManifest {
            v: crate::federation::blobs::CHUNK_MANIFEST_VERSION,
            total_size: segs.iter().map(|s| s.len() as u64).sum(),
            chunks: segs
                .iter()
                .map(|s| ChunkRef {
                    sha: sha2::Sha256::digest(s).into(),
                    size: s.len() as u32,
                    seq: None,
                    epoch: None,
                })
                .collect(),
            chunk_tier: None,
            stream_id: None,
        }
    }

    // ── I780 / I781 / I782 / I783 ─────────────────────────────────────────
    pub(crate) async fn i780_i783_the_incremental_plaintext_dag<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i780-author-{run}");
        for b in [l.ba.as_ref(), l.bb.as_ref()] {
            ts::register_hybrid_key_as(b, &author, &author, USER).await;
        }
        let segs: Vec<Vec<u8>> = vec![vec![1u8; 700], vec![2u8; 900], vec![3u8; 400]];
        let manifest = plaintext_manifest(&segs);
        let msha: [u8; 32] = sha2::Sha256::digest(manifest.to_jcs_bytes()).into();
        let e = &l.engine_a;

        // I782 — the chunk door admits only the entry's bytes.
        let wrong = e
            .put_plaintext_dag_chunk(
                &manifest.chunks[0],
                BlobBody::Inline(segs[1].clone()),
                &author,
            )
            .await;
        assert!(
            matches!(wrong, Err(BlobError::HashMismatch { .. })),
            "I782: another chunk's bytes: {wrong:?}"
        );
        let mut short = manifest.chunks[0].clone();
        short.size -= 1;
        let wrong = e
            .put_plaintext_dag_chunk(&short, BlobBody::Inline(segs[0].clone()), &author)
            .await;
        assert!(
            matches!(wrong, Err(BlobError::InvalidArgument(_))),
            "I782: a length that is not the entry's: {wrong:?}"
        );

        // I780 — out of order, one chunk missing: nothing is visible.
        for i in [2usize, 0] {
            let got = e
                .put_plaintext_dag_chunk(
                    &manifest.chunks[i],
                    BlobBody::Inline(segs[i].clone()),
                    &author,
                )
                .await
                .expect("a chunk of the manifest");
            assert_eq!(got, manifest.chunks[i].sha);
        }
        assert!(l.ba.blob_head(&msha).await.unwrap().is_none());
        assert!(l.ba.list_holders(&msha).await.unwrap().is_empty());

        // I781 — the finalize over a missing chunk names it, writes nothing.
        let missing = e
            .finalize_blob_chunks_signing(manifest.clone(), &author)
            .await;
        match missing {
            Err(BlobError::NotHeld { sha256_hex }) => {
                assert_eq!(sha256_hex, hex::encode(manifest.chunks[1].sha), "I781");
            }
            other => panic!("I781: a missing chunk is NotHeld, got {other:?}"),
        }
        assert!(
            l.ba.blob_head(&msha).await.unwrap().is_none(),
            "I781: no manifest row over a partial DAG"
        );
        // I781 — an entry whose size is not the held row's.
        let mut lying = manifest.clone();
        lying.chunks[0].size += 5;
        lying.chunks[2].size -= 5;
        let lie = e.finalize_blob_chunks_signing(lying, &author).await;
        assert!(
            matches!(&lie, Err(BlobError::InvalidArgument(m)) if m.contains("chunk[0]")),
            "I781: the size the manifest names is the row's: {lie:?}"
        );

        // I782 — not a plaintext v1 manifest: refused before any row is read.
        for (why, m) in [
            ("a sealed version", {
                let mut m = manifest.clone();
                m.v = crate::federation::blobs::CHUNK_MANIFEST_VERSION_SEALED;
                m
            }),
            ("a chunk_tier", {
                let mut m = manifest.clone();
                m.chunk_tier =
                    Some(crate::federation::types::cohort_scope::CryptoTier::CommunityDek);
                m
            }),
            (
                "no chunks",
                ChunkManifest {
                    total_size: 0,
                    chunks: vec![],
                    ..manifest.clone()
                },
            ),
        ] {
            let r = e.finalize_blob_chunks_signing(m, &author).await;
            assert!(
                matches!(r, Err(BlobError::InvalidArgument(_))),
                "I782 {why}: {r:?}"
            );
        }

        // I780 — whole: the row, the claim, the file.
        e.put_plaintext_dag_chunk(
            &manifest.chunks[1],
            BlobBody::Inline(segs[1].clone()),
            &author,
        )
        .await
        .unwrap();
        let got = e
            .finalize_blob_chunks_signing(manifest.clone(), &author)
            .await
            .expect("I780: the DAG is whole");
        assert_eq!(got, msha);
        assert_eq!(
            e.read_blob_as(&msha, "", None).await.unwrap(),
            segs.concat(),
            "I780: the DAG reads whole"
        );
        assert!(
            l.ba.list_holders(&msha).await.unwrap().contains(&l.node_a),
            "I780: announced at finalize"
        );
        assert_eq!(
            e.finalize_blob_chunks_signing(manifest.clone(), &author)
                .await
                .unwrap(),
            msha,
            "I780: idempotent"
        );

        // I783 — the one-shot door on B yields the same address and row.
        let chunks: Vec<([u8; 32], BlobBody)> = segs
            .iter()
            .map(|s| (sha2::Sha256::digest(s).into(), BlobBody::Inline(s.clone())))
            .collect();
        let one_shot = l
            .engine_b
            .put_blob_chunks_signing(manifest.clone(), chunks, &author)
            .await
            .unwrap();
        assert_eq!(one_shot, msha, "I783: one address");
        assert_eq!(
            l.ba.blob_head(&msha).await.unwrap(),
            l.bb.blob_head(&msha).await.unwrap(),
            "I783: one row"
        );
    }

    /// Hold `bytes` on `engine` under this node's own claim.
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

    // ── I773 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i773_a_plaintext_dags_chunks_follow_its_takedown<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i773-author-{run}");
        ts::register_hybrid_key_as(l.ba.as_ref(), &author, &author, USER).await;
        let owner = claimant(0x97);
        let dir = l.ba.as_dyn_directory();
        for (door, tag) in [(true, "incremental"), (false, "one-shot")] {
            let segs: Vec<Vec<u8>> = (0..3u8)
                .map(|i| {
                    format!("i773 {tag} {run} chunk {i} ")
                        .repeat(40)
                        .into_bytes()
                })
                .collect();
            let manifest = plaintext_manifest(&segs);
            let msha = if door {
                for (c, s) in manifest.chunks.iter().zip(&segs) {
                    l.engine_a
                        .put_plaintext_dag_chunk(c, BlobBody::Inline(s.clone()), &author)
                        .await
                        .unwrap();
                }
                l.engine_a
                    .finalize_blob_chunks_signing(manifest.clone(), &author)
                    .await
                    .expect("I773: the incremental DAG")
            } else {
                let chunks = segs
                    .iter()
                    .map(|s| (sha2::Sha256::digest(s).into(), BlobBody::Inline(s.clone())))
                    .collect();
                l.engine_a
                    .put_blob_chunks_signing(manifest.clone(), chunks, &author)
                    .await
                    .expect("I773: the one-shot DAG")
            };
            for c in &manifest.chunks {
                assert!(
                    l.ba.dag_manifests_of_chunk(&c.sha)
                        .await
                        .unwrap()
                        .contains(&msha),
                    "I773 {tag}: the chunk is related to its manifest"
                );
            }
            establish(dir, &author, &owner.id, &hex::encode(msha)).await;
            let r = l
                .engine_a
                .takedown_tombstone(&notice(&owner, &hex::encode(msha), "ncmec_csam"))
                .await
                .expect("I773: an immediate-removal takedown of the DAG");
            assert!(r.bytes_destroyed, "I773 {tag}: {r:?}");
            for c in &manifest.chunks {
                assert_eq!(
                    sp::purge_withheld(dir, &c.sha).await.unwrap(),
                    Some(r.notice_id.clone()),
                    "I773 {tag}: the chunk is withheld with its DAG"
                );
                assert!(
                    l.ba.blob_head(&c.sha).await.unwrap().is_none(),
                    "I773 {tag}: the chunk is evicted with its DAG"
                );
            }
        }
    }

    // ── I774 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i774_the_plaintext_dag_doors_ask_the_will_decision<B>(
        dsn_a: &str,
        _dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::{DiskPressureConfig, DiskPressureMonitor, StubFreeBytes};
        let alias = format!("i774-node-{run}");
        let engine = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), dsn_a)
            .await
            .unwrap();
        engine
            .register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                &alias,
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .unwrap();
        let b = pick(&engine);
        let stranger = format!("i774-stranger-{run}");
        ts::register_hybrid_key_as(b.as_ref(), &stranger, &stranger, USER).await;
        let cfg = std::sync::Arc::new(DiskPressureConfig {
            monitor_path: std::path::PathBuf::from("/x"),
            ..Default::default()
        });
        let stub = std::sync::Arc::new(StubFreeBytes::new(2 * 1024 * 1024 * 1024));
        let monitor = std::sync::Arc::new(DiskPressureMonitor::with_source(
            (*cfg).clone(),
            stub.clone(),
        ));
        monitor.poll_once();
        let engine = engine
            .with_disk_pressure_config_shared(cfg)
            .with_disk_pressure_state_shared(monitor.subscribe());
        let segs = |tag: &str| -> Vec<Vec<u8>> {
            (0..2u8)
                .map(|i| format!("i774 {tag} {run} {i} ").repeat(30).into_bytes())
                .collect()
        };
        let chunks_of = |segs: &[Vec<u8>]| -> Vec<([u8; 32], BlobBody)> {
            segs.iter()
                .map(|s| (sha2::Sha256::digest(s).into(), BlobBody::Inline(s.clone())))
                .collect()
        };
        let absent = |sha: [u8; 32]| {
            let b = b.clone();
            async move { b.blob_head(&sha).await.unwrap().is_none() }
        };
        // The incremental chunks are stored BELOW stop (admitted then).
        let late = segs("finalize");
        let late_m = plaintext_manifest(&late);
        for (c, s) in late_m.chunks.iter().zip(&late) {
            engine
                .put_plaintext_dag_chunk(c, BlobBody::Inline(s.clone()), &stranger)
                .await
                .expect("I774: a proxy chunk below stop");
        }
        // STOP.
        stub.set(400 * 1024 * 1024);
        monitor.poll_once();
        let refused = |r: Result<[u8; 32], BlobError>| {
            matches!(
                r,
                Err(BlobError::DiskPressureProxyRefused {
                    operation: "accept",
                    ..
                })
            )
        };
        let one = segs("one-shot");
        let one_m = plaintext_manifest(&one);
        let one_sha: [u8; 32] = sha2::Sha256::digest(one_m.to_jcs_bytes()).into();
        assert!(
            refused(
                engine
                    .put_blob_chunks_signing(one_m.clone(), chunks_of(&one), &stranger)
                    .await
            ),
            "I774: the one-shot door refuses a proxy author at stop"
        );
        assert!(absent(one_sha).await, "I774: no manifest row");
        for c in &one_m.chunks {
            assert!(absent(c.sha).await, "I774: no chunk row");
        }
        assert!(
            b.list_holders(&one_sha).await.unwrap().is_empty(),
            "I774: no claim"
        );
        let late_sha: [u8; 32] = sha2::Sha256::digest(late_m.to_jcs_bytes()).into();
        assert!(
            refused(
                engine
                    .finalize_blob_chunks_signing(late_m.clone(), &stranger)
                    .await
            ),
            "I774: the finalize refuses a proxy author at stop"
        );
        assert!(
            absent(late_sha).await,
            "I774: no manifest row at the finalize"
        );
        assert!(b.list_holders(&late_sha).await.unwrap().is_empty());
        // This node's own DAG is not a proxy write.
        let me = engine.local_derived_key_id().await.unwrap();
        let own = segs("own");
        engine
            .put_blob_chunks_signing(plaintext_manifest(&own), chunks_of(&own), &me)
            .await
            .expect("I774: this node's own DAG at stop");
    }

    // ── I790 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i790_this_node_acts_as_a_holder<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i790-author-{run}");
        ts::register_hybrid_key_as(l.ba.as_ref(), &author, &author, USER).await;
        let owner = claimant(0x77);
        let dir = l.ba.as_dyn_directory();

        // Immediate removal: destroyed on receipt.
        let csam = hold(&l.engine_a, &author, format!("i790-csam-{run}").as_bytes()).await;
        establish(dir, &author, &owner.id, &hex::encode(csam)).await;
        let r = l
            .engine_a
            .takedown_tombstone(&notice(&owner, &hex::encode(csam), "ncmec_csam"))
            .await
            .expect("I790: an immediate-removal takedown");
        assert_eq!(r.disposition, TakedownDisposition::DestroyOnReceipt);
        assert!(r.bytes_destroyed, "I790: destroyed on receipt: {r:?}");
        assert!(!l.ba.has_blob(&csam).await.unwrap());
        assert!(
            !l.ba.list_holders(&csam).await.unwrap().contains(&l.node_a),
            "I790: this node's claim is retracted with its copy"
        );
        assert_eq!(
            l.engine_a.purge_status(&r.notice_id).await.unwrap().state,
            sp::PurgeState::Finalized
        );

        // Counter notice: withheld at once, own claim retracted, deleted
        // after the window.
        let t = chrono::Utc::now();
        test_clock::set(Some(t));
        let dmca = hold(&l.engine_a, &author, format!("i790-dmca-{run}").as_bytes()).await;
        establish(dir, &author, &owner.id, &hex::encode(dmca)).await;
        let r = l
            .engine_a
            .takedown_tombstone(&notice(&owner, &hex::encode(dmca), "dmca512"))
            .await
            .expect("I790: a counter-notice takedown");
        assert_eq!(
            r.disposition,
            TakedownDisposition::WithholdThenDelete { window_days: 10 }
        );
        assert_eq!(r.claims_retracted, 1, "I790: this node's own claim: {r:?}");
        assert!(!r.bytes_destroyed);
        assert!(l.ba.has_blob(&dmca).await.unwrap(), "I790: held, withheld");
        match l.engine_a.read_blob_as(&dmca, "", None).await {
            Err(BlobError::Purged { notice_id, .. }) => assert_eq!(notice_id, r.notice_id),
            other => panic!("I790: withheld at once, got {other:?}"),
        }
        assert!(!l.ba.list_holders(&dmca).await.unwrap().contains(&l.node_a));
        test_clock::set(Some(t + chrono::Duration::days(9)));
        let early = l.engine_a.purge_finalize(&r.notice_id).await;
        assert_eq!(
            early.map(|_| ()).unwrap_err().kind(),
            sp::token::NOT_SETTLED,
            "I790: not before the counter-notice window"
        );
        assert!(l.ba.has_blob(&dmca).await.unwrap());
        test_clock::set(Some(
            t + chrono::Duration::days(10) + chrono::Duration::seconds(1),
        ));
        let done = l.engine_a.purge_finalize(&r.notice_id).await.unwrap();
        test_clock::set(None);
        assert_eq!(done.blobs_evicted, 1, "I790: deleted after the window");
        assert!(!l.ba.has_blob(&dmca).await.unwrap());
    }

    // ── I791 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i791_only_the_holder_retracts_a_holding_claim<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i791-author-{run}");
        ts::register_hybrid_key_as(l.ba.as_ref(), &author, &author, USER).await;
        let dir = l.ba.as_dyn_directory();
        let stranger_alias = format!("i791-stranger-{run}");
        let stranger = ts::local_signer(&stranger_alias);
        ts::register_hybrid_key_aliased(dir, &stranger.derived_key_id(), &stranger_alias).await;
        let me = ts::local_signer(&format!("em-a-{run}"));

        let sha = hold(&l.engine_a, &author, format!("i791-{run}").as_bytes()).await;
        let claim = dir
            .all_attestations_by(&l.node_a)
            .await
            .unwrap()
            .into_iter()
            .find(|a| {
                crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                    == Some(crate::federation::custody_ack::CUSTODY_ACK_DIMENSION)
                    && a.attestation_envelope["evidence_refs"][0].as_str()
                        == Some(hex::encode(sha).as_str())
            })
            .expect("this node's holding claim (custody:ack:v1 here)");
        let refused = crate::federation::blobs::emit_withdraws_attestation_helper(
            &claim,
            "",
            &stranger,
            dir,
            chrono::Utc::now(),
        )
        .await
        .expect_err("I791: another key withdraws this node's claim");
        assert!(
            refused
                .to_string()
                .contains("custody_ack_withdraws_not_the_holder"),
            "I791: {refused}"
        );
        assert!(
            l.ba.list_holders(&sha).await.unwrap().contains(&l.node_a),
            "I791: the claim stands"
        );

        crate::federation::blobs::emit_withdraws_attestation_helper(
            &claim,
            "",
            &me,
            dir,
            chrono::Utc::now(),
        )
        .await
        .expect("I791: the holder retracts its own claim");
        assert!(!l.ba.list_holders(&sha).await.unwrap().contains(&l.node_a));
    }

    // ── I795 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i795_a_takedown_delivered_through_the_planes<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let author = format!("i795-author-{run}");
        let owner = claimant(0x78);
        let bytes = format!("i795-{run}");
        let mut sha = [0u8; 32];
        for (e, b) in [(&l.engine_a, l.ba.as_ref()), (&l.engine_b, l.bb.as_ref())] {
            ts::register_hybrid_key_as(b, &author, &author, USER).await;
            sha = hold(e, &author, bytes.as_bytes()).await;
            establish(b.as_dyn_directory(), &author, &owner.id, &hex::encode(sha)).await;
        }
        let r = l
            .engine_a
            .takedown_tombstone(&notice(&owner, &hex::encode(sha), "tvec_terrorist"))
            .await
            .unwrap();
        assert!(r.bytes_destroyed);
        let served = l.engine_a.list_purge_bundles_since(None, 10).await.unwrap();
        let wire = serde_json::to_string(&served).unwrap();
        let received: Vec<sp::PurgeBundle> = serde_json::from_str(&wire).unwrap();
        assert_eq!(received.len(), 1);
        assert!(l.bb.has_blob(&sha).await.unwrap(), "B holds a copy");
        let applied = l
            .engine_b
            .apply_replicated_purge(&received[0])
            .await
            .expect("I795: B re-verifies the takedown on its own state");
        assert_eq!(applied.notice_id, r.notice_id);
        assert!(
            !l.bb.has_blob(&sha).await.unwrap(),
            "I795: B destroys its own copy on receipt"
        );
        let e = l.bb.purge_execution(&r.notice_id).await.unwrap().unwrap();
        assert_eq!(e.origin, sp::origin::REPLICATED);
        assert!(e.finalized_at.is_some());

        // I797 — the bytes re-pushed at either node, through every byte
        // door a peer's delivery reaches, are refused naming the notice.
        let purged = |r: Result<(), BlobError>, why: &str| match r {
            Err(BlobError::Purged { notice_id, .. }) => assert_eq!(notice_id, applied.notice_id),
            other => panic!("I797 {why}: taken-down bytes are refused, got {other:?}"),
        };
        for (node, e, b) in [
            ("A", &l.engine_a, l.ba.as_ref()),
            ("B", &l.engine_b, l.bb.as_ref()),
        ] {
            purged(
                e.put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes.as_bytes().to_vec()),
                    None,
                    &author,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await,
                &format!("{node} put_blob_signing"),
            );
            purged(
                b.store_plaintext_local(&sha, bytes.as_bytes().to_vec(), None)
                    .await,
                &format!("{node} store_plaintext_local"),
            );
            purged(
                e.put_plaintext_dag_chunk(
                    &ChunkRef {
                        sha,
                        size: bytes.len() as u32,
                        seq: None,
                        epoch: None,
                    },
                    BlobBody::Inline(bytes.as_bytes().to_vec()),
                    &author,
                )
                .await
                .map(|_| ()),
                &format!("{node} put_plaintext_dag_chunk"),
            );
            assert!(
                !b.has_blob(&sha).await.unwrap(),
                "I797 {node}: nothing stored"
            );
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies as b;
                #[tokio::test]
                async fn i786() {
                    let Some(d) = $fresh.await else { return };
                    b::i786_a_takedown_is_admitted_by_cc_4_5_5_here(&d).await
                }
                #[tokio::test]
                async fn i787() {
                    let Some(d) = $fresh.await else { return };
                    b::i787_one_tombstone_row_for_takedown_and_purge(&d).await
                }
                #[tokio::test]
                async fn i788() {
                    let Some(d) = $fresh.await else { return };
                    b::i788_a_takedown_reaches_the_bytes_plane_only(&d).await
                }
                #[tokio::test]
                async fn i789() {
                    let Some(a) = $fresh.await else { return };
                    let Some(bb) = $fresh.await else { return };
                    b::i789_a_replicated_takedown_is_reverified_here(&a, &bb).await
                }
                #[tokio::test]
                async fn i798() {
                    let Some(d) = $fresh.await else { return };
                    b::i798_cc_4_5_5_item_by_item(&d).await
                }
                #[tokio::test]
                async fn i796() {
                    let Some(d) = $fresh.await else { return };
                    b::i796_the_contents_own_community_judges(&d).await
                }
                #[tokio::test]
                async fn i772() {
                    let Some(d) = $fresh.await else { return };
                    b::i772_only_live_bindings_confer_takedown_authority(&d).await
                }
                #[tokio::test]
                async fn i792() {
                    let Some(d) = $fresh.await else { return };
                    b::i792_a_score_over_taken_down_content_stands(&d).await
                }
                #[tokio::test]
                async fn i1170_binding() {
                    let Some(d) = $fresh.await else { return };
                    b::i1170_a_notice_row_never_binds_its_content(&d).await
                }
                #[tokio::test]
                async fn i1171() {
                    let Some(d) = $fresh.await else { return };
                    b::i1171_a_v59_peers_contribution_notice_still_applies(&d).await
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
        crate::federation::hard_case::test_support::declare_node(&b, "dt-node").await;
        Some(b)
    });

    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::isolated_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        crate::federation::hard_case::test_support::declare_node(&b, "dt-node").await;
        Some(b)
    });

    #[test]
    fn i793() {
        super::bodies::i793_the_settle_is_the_basis()
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    macro_rules! engine_runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use crate::federation::doors_takedown_invariants::engine_bodies as e;
                use crate::federation::epoch_minter_invariants::bodies::Pick;
                #[tokio::test]
                async fn i780_i783() {
                    let Some((a, b)) = $dsns else { return };
                    e::i780_i783_the_incremental_plaintext_dag(&a, &b, &super::suffix(), $pick)
                        .await
                }
                #[tokio::test]
                async fn i774() {
                    let Some((a, b)) = $dsns else { return };
                    e::i774_the_plaintext_dag_doors_ask_the_will_decision(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i773() {
                    let Some((a, b)) = $dsns else { return };
                    e::i773_a_plaintext_dags_chunks_follow_its_takedown(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i790() {
                    let Some((a, b)) = $dsns else { return };
                    e::i790_this_node_acts_as_a_holder(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i791() {
                    let Some((a, b)) = $dsns else { return };
                    e::i791_only_the_holder_retracts_a_holding_claim(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i795() {
                    let Some((a, b)) = $dsns else { return };
                    e::i795_a_takedown_delivered_through_the_planes(&a, &b, &super::suffix(), $pick)
                        .await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    engine_runners!(
        sqlite_engine,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as Pick<crate::store::sqlite::SqliteBackend>
    );
    #[cfg(feature = "postgres")]
    engine_runners!(
        postgres_engine,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as Pick<crate::store::postgres::PostgresBackend>
    );

    // ── I794 — from disk ─────────────────────────────────────────────────
    /// Comments and every test-gated item stripped: what remains is
    /// production. A gate is any `#[cfg(…)]` naming `test` as a word
    /// (`cfg(test)`, `cfg(all(test, …))`, `cfg(any(…, test))`), never the
    /// `test-anchor` feature; a gated item without a body (`mod x;`) ends the
    /// gate at its `;`.
    fn production(src: &str) -> String {
        fn gates_test(attr: &str) -> bool {
            let b = attr.as_bytes();
            attr.match_indices("test").any(|(i, _)| {
                let before = i.checked_sub(1).map(|j| b[j]);
                let after = b.get(i + 4).copied();
                matches!(before, Some(b'(' | b' ' | b','))
                    && matches!(after, Some(b')' | b',' | b' '))
            })
        }
        let mut out = String::new();
        let mut skip_depth: Option<usize> = None;
        let mut depth = 0usize;
        let mut pending = false;
        for line in src.lines() {
            let code = line.split("//").next().unwrap_or("");
            let t = code.trim();
            if skip_depth.is_none() && t.starts_with("#[cfg(") && gates_test(t) {
                pending = true;
            }
            let opens = code.matches('{').count();
            let closes = code.matches('}').count();
            if pending && skip_depth.is_none() {
                if opens > 0 {
                    skip_depth = Some(depth);
                    pending = false;
                } else if t.ends_with(';') {
                    pending = false;
                    depth = depth.saturating_sub(closes);
                    continue;
                }
            }
            depth += opens;
            depth = depth.saturating_sub(closes);
            if skip_depth.is_some() {
                if Some(depth) == skip_depth {
                    skip_depth = None;
                }
                continue;
            }
            if pending {
                continue;
            }
            out.push_str(code);
            out.push('\n');
        }
        out
    }

    /// I797 — from disk: every production function that inserts a row into
    /// `federation_blobs` asks the tombstone first, or is named here with the
    /// reason it need not.
    #[test]
    fn i797_every_byte_write_floor_asks_the_tombstone() {
        // (function, why it is exempt)
        const EXEMPT: &[(&str, &str)] = &[
            (
                "sqlite_append_chunk_item",
                "the chunk floor's per-item writer; put_blob_chunks_floor asks before it",
            ),
            (
                "pg_append_chunk_item",
                "the chunk floor's per-item writer; put_blob_chunks_floor asks before it",
            ),
            (
                "seal_stream",
                "writes a manifest this node computes over chunks the chunk floor admitted",
            ),
            (
                "seal_stream_with_scope",
                "writes a manifest this node computes over chunks the chunk floor admitted",
            ),
        ];
        let root = env!("CARGO_MANIFEST_DIR");
        for backend in ["sqlite", "postgres"] {
            let src = production(
                &std::fs::read_to_string(format!("{root}/src/store/{backend}.rs")).unwrap(),
            );
            let lines: Vec<&str> = src.lines().collect();
            let mut checked = std::collections::BTreeSet::new();
            for (i, l) in lines.iter().enumerate() {
                let compact = l.replace("cirislens.", "");
                if !compact.contains("INSERT INTO federation_blobs ")
                    && !compact.contains("INSERT INTO federation_blobs(")
                    && !compact.contains("\"INSERT INTO federation_blobs")
                {
                    continue;
                }
                // The enclosing fn: the nearest `fn name(` above.
                let (start, name) = (0..=i)
                    .rev()
                    .find_map(|j| {
                        let t = lines[j].trim_start();
                        let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
                        let t = t.strip_prefix("async ").unwrap_or(t);
                        t.strip_prefix("fn ")
                            .and_then(|r| r.split('(').next())
                            .map(|n| (j, n.trim().to_owned()))
                    })
                    .expect("an enclosing fn");
                if EXEMPT.iter().any(|(f, _)| *f == name) {
                    checked.insert(name);
                    continue;
                }
                let body = lines[start..=i].join("\n");
                assert!(
                    body.contains("steward_purge::refuse_tombstoned_bytes("),
                    "I797 {backend}: {name} stores bytes without asking the tombstone first"
                );
                checked.insert(name);
            }
            for door in [
                "put_blob_with_scope",
                "store_blob_local",
                "put_blob_chunks",
                "put_dag_manifest_over_held",
                "adopt_sealed_blob_at",
            ] {
                assert!(
                    checked.contains(door),
                    "I797 {backend}: the scan reached {door} ({checked:?})"
                );
            }
            let floor = &src[src
                .find("async fn put_blob_chunks_floor(")
                .expect("the chunk floor")..];
            let floor = &floor[..floor.find("\n    }\n").expect("its end")];
            assert!(
                floor.contains("steward_purge::refuse_tombstoned_bytes("),
                "I797 {backend}: the chunk floor asks the tombstone for every item"
            );
        }
    }

    #[test]
    fn i794_no_takedown_path_withdraws_another_devices_claim() {
        let root = env!("CARGO_MANIFEST_DIR");
        let read = |p: &str| production(&std::fs::read_to_string(format!("{root}/{p}")).unwrap());
        let handler = read("src/cirisnode/takedown_handler.rs");
        for banned in ["emit_withdraws", "evict_actor(", "list_holders("] {
            assert!(
                !handler.contains(banned),
                "I794: the takedown handler calls {banned}"
            );
        }
        assert!(
            handler.contains(".takedown_tombstone("),
            "I794: the takedown handler runs the tombstone door"
        );
        for backend in ["sqlite", "postgres"] {
            let src = read(&format!("src/store/{backend}.rs"));
            let i = src
                .find("async fn evict_actor(")
                .expect("evict_actor is implemented");
            let body = &src[i..i + src[i..].find("\n    }\n").expect("its end")];
            assert!(
                body.contains("holding_claim::evict_actor_of(self,"),
                "I794 {backend}: evict_actor delegates to the one body that retracts only the \
                 evicting signer's claims"
            );
        }
        let admission = read("src/federation/admission.rs");
        assert!(
            admission.contains("custody_ack::check_custody_withdraws_signer(row, &target)?"),
            "I794: the withdraws door asks the holder rule (CC 3.1.3.3 rule 4)"
        );
    }
}
