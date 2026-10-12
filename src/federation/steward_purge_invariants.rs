//! v54.1.0 (CIRISPersist#1046, #1040, #1043; CIRISConstitution#165; CSD-108)
//! — **the generic steward purge door's witnesses**, on every backend the door
//! runs on (memory, sqlite, postgres).
//!
//! - **I650** — authorisation is the trust root's own `consensus_protocol`
//!   over a cosigned `takedown_notice` of basis `steward_purge`: no
//!   cosignature, one founder of a `quorum:2/3`, one founder plus a seat the
//!   protocol does not count, an accord holder who holds no seat, a forged
//!   signature, another basis, an expired notice and a claimant that is not a
//!   rooted trust root are each `purge_unauthorised`, and nothing is written;
//!   a founder quorum plus a non-founder SEAT executes, the seat among the
//!   cosigners (CC 2.4 rule 0: the signer set is the roster's, the count the
//!   protocol's).
//! - **I651** — a notice whose counts match but whose digest names another
//!   id list is `purge_selection_digest_mismatch`.
//! - **I652** — a live selection that grew after the dry run is
//!   `purge_selection_count_mismatch {table, expected, found}`; there is no
//!   override. A notice without the OPTIONAL `selection_counts` is
//!   well-formed, and the same drift is then the digest's to refuse.
//! - **I653** — an inadmissible retraction (a `withdraws` whose target is not
//!   purged with it) ABORTS the purge: `purge_retraction_inadmissible
//!   {record_id, plane, index, total}`, with nothing written, on every attempt
//!   — whole or not at all (CC 4.5.3, CIRISConstitution rc8@8c8f536).
//! - **I654** — #1040's class end to end: the mock-model traces, their own
//!   trace attestations and the score derived from them are ONE selection; the
//!   dry run is read-only, its sample is the first ids in JCS order, the
//!   ledger re-derives the digest and carries the notice id, count, actor and
//!   instant; execution tombstones and stops serving; a re-run is idempotent.
//! - **I655** — `purge_finalize` refuses before settle (`purge_not_settled`),
//!   then hard-deletes exactly the tombstoned rows; afterwards the tombstone
//!   refuses the row's return (`purge_tombstoned`); a second finalize is a no-op.
//! - **I656** — the tombstone replicates: a second node applies the served
//!   bundle after re-verifying it against its OWN root; a node rooted at no
//!   trust root refuses it and records nothing; a bundle with an id
//!   dropped, a forged cosignature, or unsorted ids is refused.
//! - **I657** — RETIRED, not reused: it witnessed a #1043 serve filter the
//!   operator ruled out (2026-10-09: both classes are PURGED through this
//!   door, never withheld in place). Its selection half is I662.
//! - **I658** — RETIRED, not reused: it witnessed a purged key that could
//!   not return. The operator ruled (2026-10-09) that a purge never deletes
//!   or tombstones a key; see I665, I666.
//! - **I659** — #1040's admission refusal `trace_run_kind_mock` (CC 3.1.5,
//!   CIRISConstitution#166), keyed on the signed `run_kind`: a federation-tier
//!   `run_kind: mock` trace attestation is refused at the put and the
//!   promotion door (a local one is kept; a production run on the mock model's
//!   id, or a trace with no `run_kind`, passes); ingest on a node holding
//!   `canonical` refuses a mock run, a node without it keeps it; a tombstoned
//!   trace is refused at ingest everywhere.
//! - **I660** — the delete doors re-ask the tombstone: an untombstoned row is
//!   never deleted through them.
//! - **I661** — from disk: every backend's attestation put, both key doors,
//!   the serve read and the promotion door carry the purge gates, no key door
//!   consults the purge plane, and no
//!   serve read classifies a row by `refused_today` (#1043's ruling).
//! - **I662** — #1043 class 1 is a SELECTION: a row the apply door refuses
//!   today is still served until it is purged; `RefusedToday` selects it and
//!   every score derived from it (nothing else), the dry run counts per table
//!   and writes nothing, and once executed the purged rows stop being served.
//! - **I663** — RETIRED, not reused: it witnessed a #1043 class-2
//!   harness-prefix builder the operator dropped (harness rows on production
//!   stay; Server selects by actor or by ids when it needs a purge).
//! - **I664** — one tombstone row for takedown and purge (CC 4.5.3,
//!   CIRISConstitution rc8@8c8f536): a header with ANOTHER basis (a
//!   duty-holder `ncmec_csam` takedown, the v55 #1007 door's row) and its
//!   bytes-plane tombstone round-trip through the store with their basis
//!   intact, and the ledger names the basis.
//! - **I665** — a purge never touches a key (operator ruling 2026-10-09):
//!   `ByActor` selects only what the actor AUTHORED, never its key and never a
//!   row another key signed about it; after a by-ids and a by-actor purge are
//!   executed and finalized the key is still registered, its door still admits
//!   it, its unselected row still verifies, and a row it signs afterwards
//!   verifies.
//! - **I667** — CLM-accountability-record-unpurgeable (CIRISConstitution
//!   rc8@8c8f536): a row of each of `revocation:*`, `key:revocation`,
//!   `moderation:*`, `moderation_track_record:*` and `slashing:*` is
//!   inadmissible by that clause — refused by id, withheld by a class.
//! - **I694** (CIRISPersist#1054) — the RESET purge door refuses the same
//!   five families, through the one list both doors read
//!   (`migration::ACCOUNTABILITY_RECORD_PREFIXES`), and the reset's planning
//!   (`is_exclusion_bearing`) keeps them.
//! - **I668** — the receiver of a replicated bundle re-asks the rules no
//!   notice can lift (the accountability record; a composer without its
//!   target): a quorum-cosigned bundle naming a held `moderation_track_record`
//!   row is `purge_retraction_inadmissible` with nothing written.
//! - **I669** — a trace at an UNSUPPORTED `trace_schema_version` (2.8.0,
//!   should CIRISAgent#1249 bump the wire version) carrying `run_kind` is
//!   refused whole at the schema-version gate, `schema_unsupported_version`,
//!   nothing written — never stripped, never admitted unverifiable.
//! - **I670** — `run_kind` is a SIGNED trace member (CC 3.1.5): a 2.7.0
//!   trace signed with `production`, `qa` or `battery` admits under full
//!   verification and keeps the value on its stored attestation; one whose
//!   `run_kind` was edited after signing is refused by the signature check;
//!   a value outside the vocabulary is `schema_unknown_run_kind`; a signed
//!   `mock` run is `trace_run_kind_mock` on the canonical.
//! - **I672** — INTERIM (CIRISConstitution rc8@8c8f536): until the notice
//!   is an admitted row, a purge touches no record with a human subject. The
//!   mock-trace class passes; a by-ids selection holding one row about a
//!   `user` key is `purge_human_subject_pending_notice_row` at the dry run
//!   (naming exactly that record and subject), at execution and at the
//!   replicated apply, with nothing written; a person's by-actor purge is
//!   refused; a subject key that does not resolve fails closed.
//! - **I695** (Codex on PR #1057) — the purge header and its tombstones are
//!   ONE transaction: a fault armed between them leaves neither header nor
//!   tombstone (and the selection is still served), and a retry executes the
//!   whole set. A header whose stored set is partial (the pre-fix state) is
//!   `Incomplete` at `purge_status`, and `purge_finalize` and the bundle serve
//!   refuse it `purge_execution_incomplete` with nothing deleted, until a
//!   re-run of the same notice completes it. The store door refuses a set that
//!   is not exactly `record_count` rows of its notice.
//! - **I696** (Codex on PR #1057) — purging a trace invalidates the rollup
//!   it was folded into (sqlite, postgres; memory has no rollup and
//!   aggregates directly): after finalize, a bucket the trace shared keeps
//!   only the survivor, a bucket it alone filled is GONE (not left at its old
//!   count), and the fleet read no longer counts it — including a bucket older
//!   than the lazy refresh's watermark tail, which no refresh revisits.
//! - **I697** (Codex on PR #1057) — replication order cannot purge the
//!   accountability record: a quorum-cosigned bundle naming ids this node does
//!   not hold yet applies (a bundle legitimately names unheld rows); when
//!   those ids then arrive as a `key:revocation` row and a
//!   `moderation_track_record:*` row they are ADMITTED and served, the
//!   tombstone is void for them (`purge_status.voided`), and `purge_finalize`
//!   (and the delete door itself) never deletes them. An ordinary row at a
//!   tombstoned id is still `purge_tombstoned`.
//! - **I698** (Codex on PR #1057) — `run_kind` survives the manifest form:
//!   an OVERSIZE mock trace kept on a non-canonical node is stored as a
//!   manifest-form attestation whose manifest carries `run_kind: mock`, and
//!   that row is `trace_run_kind_mock` at the promotion door and at the
//!   federation-tier put; manifest rows declaring `production` or `qa` are
//!   admitted; a LEGACY manifest row with no `run_kind` is admitted and
//!   stored byte for byte as signed; a `run_kind` outside the vocabulary, in
//!   either shape, is `federation_trace_dimension_invalid`.
//! - **I820** (Codex round 2 on PR #1057) — derivatives leave with a
//!   withheld parent: under `RefusedToday`, a refused-today
//!   `moderation_track_record` row is withheld (inadmissible), and so are the
//!   score citing it and the score citing THAT score; a refused-today plain
//!   row and the score over it are selected; the dry run's digest is the
//!   reduced set's, and execution under it succeeds.
//! - **I821** (Codex round 2 on PR #1057) — a blob's subject is resolved
//!   from what THIS node holds, never from a bundle's `derived_from`: a
//!   quorum-cosigned bundle that points a person's blob at a harmless row is
//!   `purge_human_subject_pending_notice_row` naming the blob and the person,
//!   with nothing written; a blob nothing held here binds is refused (fail
//!   closed); a blob bound only by rows about non-persons applies; the local
//!   dry run refuses the person's blob the same way.
//! - **I822** (Codex round 2 on PR #1057) — the dwell is this node's clock:
//!   with the test clock unset, a purge executed now and finalized at once is
//!   `purge_not_settled`, its `executed_at` is the system clock's and its
//!   settle 72 h later; and from disk, no public purge surface (the
//!   `steward_purge` module's `pub fn`s, `Engine::purge_*` /
//!   `apply_replicated_purge`, the pyo3 `purge_*_json` /
//!   `apply_replicated_purge_json`) takes a `now`, so no caller can advance
//!   or backdate it.
//! - **I825** (Codex round 3 on PR #1057; sqlite, postgres) — a finalized
//!   trace purge takes the Art. 17 tombstone onto the trace's derived
//!   detection events (the DSAR door's own function, same transaction): no
//!   event names the trace or returns its body hash or canonical bytes; an
//!   unrelated trace's event is untouched.
//!   (Round-4 sweep) a detection arriving AFTER the purge is refused
//!   `purge_tombstoned` and not stored.
//! - **I826** (Codex round 3 on PR #1057; memory, sqlite, postgres) — a
//!   finalized trace purge removes the thought-signature row no remaining
//!   event cites: a later trace reusing the thought_id reads ITS OWN
//!   signature, not the purged one's; a thought another live trace shares
//!   keeps its row.
//! - **I828** (Codex round 4 on PR #1057) — replication order cannot purge a
//!   record a PERSON is the subject of (interim): a bundle naming an unheld
//!   attestation id and an unheld trace id applies (`skip_unheld`); a row
//!   about a `user` key then arriving at the attestation id is admitted,
//!   served, listed void, and survives finalize and the delete door; a trace
//!   a person signed arriving at the trace id is ingested and survives
//!   finalize and the trace delete door. An ordinary row, and a row whose
//!   subject key does not resolve here (no person PROVEN), at a tombstoned id
//!   are still `purge_tombstoned` (an unresolvable subject: the retryable
//!   `federation_attester_key_unknown`, I832); and the serve-by-hash reload
//!   withholds a tombstoned row during the dwell.
//! - **I832** (Codex round 4 follow-up; memory, sqlite, postgres) — a row (or
//!   trace) arriving at a tombstoned id BEFORE its subject's (signer's) key
//!   record is refused RETRYABLY (`federation_attester_key_unknown`, plane
//!   `purge_tombstone_subject`; for a trace, `verify_unknown_key`), not
//!   stored; once the key lands as a person the re-offer is admitted and
//!   voided; once it lands as a non-person the re-offer is `purge_tombstoned`.
//! - **I831** (Codex round 4 sweep on PR #1057; memory, sqlite, postgres) —
//!   the DSAR erasure drops the orphaned thought signature too (the purge's
//!   helper): a later trace reusing the thought_id reads its own signature.
//! - **I666** — a `key:` (or `federation_keys:`) id is not a purge record:
//!   `purge_selection_malformed`, naming `key:revocation` as key retirement's
//!   own act.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID as CANON;
    use crate::federation::canonical_community_invariants::bodies as cc;
    use crate::federation::steward_purge::unauthorised_reason as why;
    use crate::federation::steward_purge::{
        self as sp, token, PurgePlane, PurgeSelection, StewardPurgeNotice,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, Attestation, SignedAttestation};
    use crate::federation::{Error, FederationDirectory};
    use crate::store::{Backend, TraceEventRow, TraceLlmCallRow};

    /// What a witness needs from a backend beyond the two public traits.
    pub(crate) trait Seams: FederationDirectory + Backend + Sync {
        /// The #1043 legacy-row seam.
        fn shift_asserted_at<'a>(
            &'a self,
            id: &'a str,
            at: chrono::DateTime<chrono::Utc>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
        /// This node's identity, as `Engine` injects it.
        fn set_node(&self, key_id: &str);
        /// The stored role seam (CIRISPersist#1040).
        fn set_identity_type<'a>(
            &'a self,
            key_id: &'a str,
            identity_type: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
        /// The backend's own test hooks (Codex on PR #1057: the fault armed
        /// between the purge header and its tombstones).
        fn hooks(&self) -> &crate::store::test_hooks::TestHooks;
        /// Drop one stored tombstone: a header whose set is partial.
        fn drop_tombstone<'a>(
            &'a self,
            notice_id: &'a str,
            plane: &'a str,
            record_ref: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
    }

    macro_rules! seams_for {
        ($t:ty) => {
            impl Seams for $t {
                fn shift_asserted_at<'a>(
                    &'a self,
                    id: &'a str,
                    at: chrono::DateTime<chrono::Utc>,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
                    Box::pin(async move {
                        self.test_seam_set_attestation_asserted_at(id, at)
                            .await
                            .expect("seam");
                    })
                }
                fn set_node(&self, key_id: &str) {
                    self.set_node_key_id(key_id);
                }
                fn set_identity_type<'a>(
                    &'a self,
                    key_id: &'a str,
                    identity_type: &'a str,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
                    Box::pin(async move {
                        self.test_seam_set_key_identity_type(key_id, identity_type)
                            .await
                            .expect("seam");
                    })
                }
                fn hooks(&self) -> &crate::store::test_hooks::TestHooks {
                    self.test_hooks()
                }
                fn drop_tombstone<'a>(
                    &'a self,
                    notice_id: &'a str,
                    plane: &'a str,
                    record_ref: &'a str,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
                    Box::pin(async move {
                        self.test_seam_drop_purge_tombstone(notice_id, plane, record_ref)
                            .await
                            .expect("seam");
                    })
                }
            }
        };
    }
    /// The rollup witness's seams (the plain `trace_events_factor_rollup_1h`
    /// rollup exists on sqlite and postgres; memory aggregates directly).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) trait RollupSeams: Seams + crate::read::ReadEngine {
        /// Run the lazy refresh from the stored watermark.
        fn refresh_rollup(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
        /// `trace_count` per rollup bucket of `agent`.
        fn rollup_trace_counts<'a>(
            &'a self,
            agent: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<i64>> + Send + 'a>>;
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    macro_rules! rollup_seams_for {
        ($t:ty) => {
            impl RollupSeams for $t {
                fn refresh_rollup(
                    &self,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
                    Box::pin(async move {
                        self.test_seam_refresh_factor_rollup()
                            .await
                            .expect("refresh");
                    })
                }
                fn rollup_trace_counts<'a>(
                    &'a self,
                    agent: &'a str,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<i64>> + Send + 'a>>
                {
                    Box::pin(async move {
                        self.test_seam_factor_rollup_trace_counts(agent)
                            .await
                            .expect("seam")
                    })
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    rollup_seams_for!(crate::store::sqlite::SqliteBackend);
    #[cfg(feature = "postgres")]
    rollup_seams_for!(crate::store::postgres::PostgresBackend);

    seams_for!(crate::store::memory::MemoryBackend);
    #[cfg(feature = "sqlite")]
    seams_for!(crate::store::sqlite::SqliteBackend);
    #[cfg(feature = "postgres")]
    seams_for!(crate::store::postgres::PostgresBackend);

    // The purge doors read this node's clock (Codex round 2 on PR #1057); a
    // witness pins it through the `cfg(test)` seam, never an argument.
    /// `sp::purge_rows` with the purge clock pinned at `at`.
    pub(crate) async fn rows_at<F: FederationDirectory + ?Sized>(
        dir: &F,
        selection: &PurgeSelection,
        notice: &StewardPurgeNotice,
        by: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<sp::PurgeReport, Error> {
        sp::test_clock::set(Some(at));
        sp::purge_rows(dir, selection, notice, by).await
    }
    /// `sp::purge_status` with the purge clock pinned at `at`.
    pub(crate) async fn status_at<F: FederationDirectory + ?Sized>(
        dir: &F,
        notice_id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<sp::PurgeStatus, Error> {
        sp::test_clock::set(Some(at));
        sp::purge_status(dir, notice_id).await
    }
    /// `sp::purge_finalize` with the purge clock pinned at `at`.
    pub(crate) async fn finalize_at<F: FederationDirectory + ?Sized>(
        dir: &F,
        notice_id: &str,
        at: chrono::DateTime<chrono::Utc>,
        bytes: Option<&dyn sp::BytesEvictor>,
    ) -> Result<sp::FinalizeReport, Error> {
        sp::test_clock::set(Some(at));
        sp::purge_finalize(dir, notice_id, bytes).await
    }
    /// `sp::apply_replicated_purge` with the purge clock pinned at `at`.
    pub(crate) async fn apply_at<F: FederationDirectory + ?Sized>(
        dir: &F,
        bundle: &sp::PurgeBundle,
        receiver: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<sp::ApplyPurgeOutcome, Error> {
        sp::test_clock::set(Some(at));
        sp::apply_replicated_purge(dir, bundle, receiver).await
    }
    pub(crate) const AGENT: &str = "mock-agent-a";
    pub(crate) const SCORER: &str = "lens-scorer";
    pub(crate) const BYSTANDER: &str = "bystander-b";
    pub(crate) const HARNESS: &str = "qa-node-7";
    pub(crate) const NODE: &str = "canon-node-1";

    pub(crate) fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    /// The token and body of a purge refusal, or a panic naming what came back.
    pub(crate) fn refusal(e: &Error) -> (&'static str, serde_json::Value) {
        match e {
            Error::PurgeRefused { token, body } => (token, body.clone()),
            other => panic!("expected a typed purge refusal, got {other:?}"),
        }
    }

    /// The trust root rooted on `d`: the genesis accord holders, the three
    /// human founders the accord conferred, and `ciris-canonical` admitted
    /// under a 2-of-3 accord co-scrub with `quorum:2/3` among its founders.
    pub(crate) async fn root<D: Seams>(
        d: &D,
    ) -> Vec<crate::federation::accord_test_support::Identity> {
        let dir = d.as_dyn_directory();
        let holders = cc::stand_up(dir).await;
        dir.put_community(cc::signed(cc::canonical_row(&cc::FOUNDERS), &["A1", "B1"]))
            .await
            .expect("the trust root admits");
        for k in [AGENT, SCORER, BYSTANDER, HARNESS] {
            ts::register_hybrid_key(dir, k).await;
        }
        holders
    }

    /// A notice completing the dry run's template, cosigned by `signers`.
    pub(crate) fn notice_for(
        template: &serde_json::Value,
        signers: &[&str],
        now: chrono::DateTime<chrono::Utc>,
    ) -> StewardPurgeNotice {
        let mut env = template.clone();
        let digest = env["content_sha256"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        env["claimant_key_id"] = serde_json::json!(CANON);
        env["claim_text"] = serde_json::json!("test-harness input in the canonical corpus");
        env["good_faith_statement"] = serde_json::json!("the selection never belonged");
        env["jurisdiction"] = serde_json::json!("ZZ");
        env["evidence_refs"] =
            serde_json::json!([format!("evidence/purges/2026-10-09-{digest}.tsv")]);
        env["asserted_at"] = serde_json::json!((now - chrono::Duration::seconds(60)).to_rfc3339());
        env["expires_at"] = serde_json::json!((now + chrono::Duration::days(1)).to_rfc3339());
        sign(env, signers)
    }

    /// Cosign `env` by `signers` (their deterministic hybrid keys).
    pub(crate) fn sign(env: serde_json::Value, signers: &[&str]) -> StewardPurgeNotice {
        let bytes = sp::notice_signing_bytes(&env).expect("canonicalizes");
        StewardPurgeNotice {
            cosignatures: signers
                .iter()
                .map(|s| ts::threshold_sign(s, &bytes))
                .collect(),
            envelope: env,
        }
    }

    fn event_row(trace_id: &str, signer: &str, attempt: u32) -> TraceEventRow {
        TraceEventRow {
            trace_id: trace_id.to_owned(),
            thought_id: "th-1".to_owned(),
            task_id: Some("task-1".to_owned()),
            step_point: None,
            event_type: crate::schema::ReasoningEventType::ThoughtStart,
            attempt_index: attempt,
            ts: chrono::Utc::now(),
            agent_name: Some("agent-test".to_owned()),
            agent_id_hash: "deadbeef".to_owned(),
            cognitive_state: None,
            trace_level: crate::schema::TraceLevel::Detailed,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "sig-test".to_owned(),
            signing_key_id: signer.to_owned(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".to_owned(),
            pii_scrubbed: true,
            original_content_hash: Some("aabbcc".to_owned()),
            scrub_signature: Some("sig-scrub".to_owned()),
            scrub_key_id: Some("scrub-key-1".to_owned()),
            scrub_timestamp: Some(chrono::Utc::now()),
            admitted_at: None,
            scrub_ner_ran: None,
            scrub_applied_trace_level: None,
            scrub_model_digest: None,
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
            cohort_scope: "federation".to_string(),
            cohort_target_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        }
    }

    fn llm_row(trace_id: &str, model: &str) -> TraceLlmCallRow {
        TraceLlmCallRow {
            trace_id: trace_id.to_owned(),
            thought_id: "th-1".to_owned(),
            task_id: Some("task-1".to_owned()),
            parent_event_id: None,
            parent_event_type: crate::schema::ReasoningEventType::ThoughtStart,
            parent_attempt_index: 0,
            attempt_index: 0,
            ts: chrono::Utc::now(),
            duration_ms: 1.0,
            handler_name: "h".to_owned(),
            service_name: "s".to_owned(),
            model: Some(model.to_owned()),
            base_url: None,
            response_model: None,
            prompt_tokens: None,
            completion_tokens: None,
            prompt_bytes: None,
            completion_bytes: None,
            cost_usd: None,
            status: crate::schema::LlmCallStatus::Ok,
            error_class: None,
            attempt_count: None,
            retry_count: None,
            prompt_hash: None,
            prompt: None,
            response_text: None,
        }
    }

    /// One trace: two `trace_events` rows signed by `signer`, one LLM call on
    /// `model`, and its own local-tier `trace:complete:v1` attestation at the
    /// deterministic id. Returns the attestation id.
    pub(crate) async fn seed_trace<D: Seams>(
        d: &D,
        trace_id: &str,
        signer: &str,
        model: &str,
    ) -> String {
        d.insert_trace_events_batch(&[
            event_row(trace_id, signer, 0),
            event_row(trace_id, signer, 1),
        ])
        .await
        .expect("trace rows");
        d.insert_trace_llm_calls_batch(&[llm_row(trace_id, model)])
            .await
            .expect("llm row");
        let id = crate::ingest::trace_attestation_id(trace_id);
        let local = crate::federation::types::LocalAttestationInput {
            attestation_id: Some(id.clone()),
            attesting_key_id: signer.to_owned(),
            attested_key_id: None,
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({
                    "dimension": crate::ingest::TRACE_ATTESTATION_DIMENSION,
                    "trace_id": trace_id,
                    "agent_id_hash": "deadbeef",
                    "trace": {},
                }),
            )
            .expect("object"),
            subject_key_ids: vec![signer.to_owned()],
            cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let got = d
            .attestation_insert_local(local)
            .await
            .expect("trace attestation");
        assert_eq!(
            got, id,
            "the trace attestation lands at its deterministic id"
        );
        id
    }

    /// A federation-tier `scores` row by `attester` about `attested`, whose
    /// `evidence_refs` cite `refs`, really signed and put through the door.
    pub(crate) async fn put_score<D: Seams>(
        d: &D,
        attester: &str,
        attested: &str,
        refs: &[&str],
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "dimension": "chat:message:v1",
            "score": 1.0,
            "confidence": 0.9,
            "evidence_refs": refs,
        });
        let mut row = ts::bare_attestation(&id, attester, attested, &env);
        row.attestation_type = attestation_type::SCORES.to_owned();
        ts::reseal(&mut row);
        d.as_dyn_directory()
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("score {id} admits: {e}"));
        d.as_dyn_directory()
            .get_attestation(&id)
            .await
            .unwrap()
            .expect("stored")
    }

    async fn served_ids<D: Seams>(d: &D) -> Vec<String> {
        let mut out = Vec::new();
        let mut since = None;
        loop {
            let page = d
                .as_dyn_directory()
                .list_attestations_since(since.clone(), 3)
                .await
                .unwrap();
            if page.is_empty() {
                return out;
            }
            since = page
                .last()
                .map(|s| (s.admitted_at, s.attestation.attestation_id.clone()));
            out.extend(page.into_iter().map(|s| s.attestation.attestation_id));
        }
    }

    async fn assert_nothing_written<D: Seams>(d: &D, notice: &StewardPurgeNotice) {
        use sha2::Digest as _;
        let id = hex::encode(sha2::Sha256::digest(
            sp::notice_signing_bytes(&notice.envelope).expect("canonicalizes"),
        ));
        assert!(
            d.as_dyn_directory()
                .purge_execution(&id)
                .await
                .unwrap()
                .is_none(),
            "a refused notice writes no header"
        );
        assert!(
            d.as_dyn_directory()
                .purge_tombstones_of(&id)
                .await
                .unwrap()
                .is_empty(),
            "a refused notice writes no tombstone"
        );
    }

    /// The #1040 world: two mock traces by AGENT, one real trace by BYSTANDER,
    /// a score over a mock trace, a score over the real one. Returns
    /// `(mock_trace_ids, derived_score_id, unrelated_score_id)`.
    pub(crate) async fn mock_world<D: Seams>(d: &D, tag: &str) -> (Vec<String>, String, String) {
        let t1 = format!("trace-mock-1-{tag}");
        let t2 = format!("trace-mock-2-{tag}");
        let real = format!("trace-real-{tag}");
        seed_trace(d, &t1, AGENT, sp::MOCK_LLM_MODEL).await;
        seed_trace(d, &t2, AGENT, sp::MOCK_LLM_MODEL).await;
        seed_trace(d, &real, BYSTANDER, "gpt-real").await;
        let derived = put_score(d, SCORER, AGENT, &[&t1]).await;
        let unrelated = put_score(d, SCORER, BYSTANDER, &[&real]).await;
        (
            vec![t1, t2],
            derived.attestation_id,
            unrelated.attestation_id,
        )
    }

    fn mock_selection() -> PurgeSelection {
        PurgeSelection::mock_llm_traces()
    }

    // ── I650 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i650_authorisation_is_the_roots_own_protocol<D: Seams>(d: &D) {
        root(d).await;
        mock_world(d, "i650").await;
        let dir = d.as_dyn_directory();
        let t = now();
        let dry = sp::purge_dry_run(dir, &mock_selection()).await.unwrap();
        let sel = mock_selection();
        let ok = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);

        let mut cases: Vec<(&str, StewardPurgeNotice)> = vec![
            ("no cosignature", notice_for(&dry.notice_template, &[], t)),
            (
                "one of quorum:2/3",
                notice_for(&dry.notice_template, &[cc::FOUNDERS[0]], t),
            ),
            (
                "an accord holder who holds no seat",
                notice_for(&dry.notice_template, &[cc::FOUNDERS[0], "A1"], t),
            ),
            // A seat the protocol does not count is no refusal, but it is no
            // vote either: under `infrastructure` only founders are eligible.
            (
                "one founder and a non-founder seat",
                notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::SERVE_NODE], t),
            ),
            // A quorum does not launder a stranger's cosignature into the set
            // the bundle carries, nor does a seat count twice.
            (
                "a founder quorum carrying a non-seat's cosignature",
                notice_for(
                    &dry.notice_template,
                    &[cc::FOUNDERS[0], cc::FOUNDERS[1], "A1"],
                    t,
                ),
            ),
            (
                "a founder quorum with one founder signing twice",
                notice_for(
                    &dry.notice_template,
                    &[cc::FOUNDERS[0], cc::FOUNDERS[1], cc::FOUNDERS[1]],
                    t,
                ),
            ),
        ];
        let mut forged = ok.clone();
        forged.cosignatures[1] = ts::threshold_sign(cc::FOUNDERS[1], b"other bytes");
        cases.push(("a forged cosignature", forged));
        let mut other_basis = dry.notice_template.clone();
        other_basis["legal_basis"] = serde_json::json!("dmca_512");
        cases.push((
            "another basis",
            notice_for(&other_basis, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t),
        ));
        cases.push((
            "an expired notice",
            notice_for(
                &dry.notice_template,
                &[cc::FOUNDERS[0], cc::FOUNDERS[1]],
                t - chrono::Duration::days(3),
            ),
        ));
        let mut no_holders = ok.envelope.clone();
        no_holders
            .as_object_mut()
            .unwrap()
            .remove("content_holder_key_ids");
        cases.push((
            "a notice without the CC 3.3.2 holder list",
            sign(no_holders, &[cc::FOUNDERS[0], cc::FOUNDERS[1]]),
        ));
        let mut not_root = ok.envelope.clone();
        not_root["claimant_key_id"] = serde_json::json!("some-room");
        cases.push((
            "a claimant that is not a rooted trust root",
            sign(not_root, &[cc::FOUNDERS[0], cc::FOUNDERS[1]]),
        ));
        // Each case is refused BY its own clause: the reason names it, so a
        // case that an earlier clause happens to refuse cannot stand in.
        let clause = |what: &str| match what {
            "no cosignature" => "carries no cosignature",
            "one of quorum:2/3" | "one founder and a non-founder seat" => "consensus_protocol",
            "a founder quorum with one founder signing twice" => "signed twice",
            "a forged cosignature" => "does not verify",
            "another basis" => "does not authorise a steward purge",
            "an expired notice" => "expired",
            "a claimant that is not a rooted trust root" => "no community row",
            "a notice without the CC 3.3.2 holder list" => "content_holder_key_ids",
            _ => "holds no seat",
        };
        // v55.0.0 (CIRISPersist#1055) — and its typed reason, with the
        // retryable bit the reason implies: only the claimant this node does
        // not hold is an ordering gap here.
        let reason = |what: &str| match what {
            "no cosignature" => why::NO_COSIGNATURE,
            "one of quorum:2/3" | "one founder and a non-founder seat" => why::QUORUM_NOT_MET,
            "a founder quorum with one founder signing twice" => why::DUPLICATE_COSIGNER,
            "a forged cosignature" => why::SIGNATURE_INVALID,
            "another basis" => why::WRONG_BASIS,
            "an expired notice" => why::EXPIRED,
            "a claimant that is not a rooted trust root" => why::ROOT_NOT_HELD,
            "a notice without the CC 3.3.2 holder list" => why::NOTICE_MALFORMED,
            _ => why::NOT_A_SEAT,
        };
        for (what, notice) in cases {
            let e = rows_at(dir, &sel, &notice, NODE, t).await.expect_err(what);
            let (tok, body) = refusal(&e);
            assert_eq!(tok, token::UNAUTHORISED, "I650 {what}: {body}");
            assert!(
                body["detail"]
                    .as_str()
                    .is_some_and(|r| r.contains(clause(what))),
                "I650 {what}: refused by another clause: {body}"
            );
            assert_eq!(
                body["reason"].as_str(),
                Some(reason(what)),
                "I650 {what}: the typed reason: {body}"
            );
            assert_eq!(
                body["retryable"].as_bool(),
                Some(reason(what) == why::ROOT_NOT_HELD),
                "I650 {what}: retryable is the gap alone: {body}"
            );
            assert_eq!(e.kind(), "purge_unauthorised", "I650 the kind IS the token");
            assert_nothing_written(d, &notice).await;
        }
        // The quorum executes, and a non-founder SEAT's verifying cosignature
        // rides along (CC 2.4 rule 0: the signer set is the roster's, the
        // count is the protocol's).
        let with_seat = notice_for(
            &dry.notice_template,
            &[cc::FOUNDERS[0], cc::FOUNDERS[1], cc::SERVE_NODE],
            t,
        );
        let report = rows_at(dir, &sel, &with_seat, NODE, t)
            .await
            .expect("2-of-3 founders, plus a seat");
        let mut expect = vec![
            cc::FOUNDERS[0].to_owned(),
            cc::FOUNDERS[1].to_owned(),
            cc::SERVE_NODE.to_owned(),
        ];
        expect.sort();
        assert_eq!(report.cosigners, expect, "I650");
        let _ = ok;
    }

    // ── I651 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i651_a_digest_naming_other_ids_is_refused<D: Seams>(d: &D) {
        root(d).await;
        mock_world(d, "i651").await;
        let dir = d.as_dyn_directory();
        let t = now();
        let dry = sp::purge_dry_run(dir, &mock_selection()).await.unwrap();
        let mut ids: Vec<String> = sp::resolve_selection(dir, &mock_selection())
            .await
            .unwrap()
            .record_ids();
        // Same counts per table, one id swapped for another on the same plane.
        let last = ids.pop().expect("non-empty");
        let (plane, _) = last.split_once(':').unwrap();
        ids.push(format!("{plane}:00000000-0000-4000-8000-000000000000"));
        let mut tpl = dry.notice_template.clone();
        tpl["content_sha256"] = serde_json::json!(sp::selection_digest(&ids));
        let notice = notice_for(&tpl, &[cc::FOUNDERS[0], cc::FOUNDERS[2]], t);
        let e = rows_at(dir, &mock_selection(), &notice, NODE, t)
            .await
            .expect_err("digest mismatch");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::SELECTION_DIGEST_MISMATCH, "I651: {body}");
        assert_eq!(body["expected"], tpl["content_sha256"]);
        assert_eq!(body["found"], serde_json::json!(dry.selection_digest));
        assert_nothing_written(d, &notice).await;
    }

    // ── I652 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i652_a_grown_selection_is_a_count_mismatch<D: Seams>(d: &D) {
        root(d).await;
        mock_world(d, "i652").await;
        let dir = d.as_dyn_directory();
        let t = now();
        let dry = sp::purge_dry_run(dir, &mock_selection()).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        // `selection_counts` is OPTIONAL (CC 3.3.2, CIRISConstitution
        // rc8@8c8f536): without it the digest alone binds.
        let mut bare = notice.envelope.clone();
        bare.as_object_mut().unwrap().remove("selection_counts");
        let bare = sign(bare, &[cc::FOUNDERS[0], cc::FOUNDERS[1]]);
        assert!(sp::notice_terms(&bare.envelope)
            .expect("a notice without selection_counts is well-formed")
            .selection_counts
            .is_none());
        // A third mock trace lands after the dry run.
        seed_trace(d, "trace-mock-3-i652", AGENT, sp::MOCK_LLM_MODEL).await;
        let e = rows_at(dir, &mock_selection(), &notice, NODE, t)
            .await
            .expect_err("count mismatch");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::SELECTION_COUNT_MISMATCH, "I652: {body}");
        assert_eq!(body["table"], "federation_attestations", "I652: {body}");
        assert_eq!(body["expected"], 3, "I652: {body}");
        assert_eq!(body["found"], 4, "I652: {body}");
        assert_nothing_written(d, &notice).await;
        // The count-less notice: the same drift is the digest's to refuse.
        let e = rows_at(dir, &mock_selection(), &bare, NODE, t)
            .await
            .expect_err("digest mismatch");
        assert_eq!(refusal(&e).0, token::SELECTION_DIGEST_MISMATCH, "I652");
        assert_nothing_written(d, &bare).await;
    }

    // ── I653 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i653_an_inadmissible_retraction_stops_the_door<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        let target = put_score(d, BYSTANDER, AGENT, &[]).await;
        ts::put_retraction(
            dir,
            BYSTANDER,
            AGENT,
            &target.attestation_id,
            attestation_type::WITHDRAWS,
        )
        .await
        .expect("withdraws admits");
        let withdraws = dir
            .list_attestations_referencing(&target.attestation_id)
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("the withdraws");
        // Two more held records beside the withdraws (held, so the interim
        // no-human-subject gate can read their subjects).
        let before = format!(
            "attestation:{}",
            put_score(d, SCORER, AGENT, &[]).await.attestation_id
        );
        seed_trace(d, "zzz-i653", AGENT, "gpt-real").await;
        let trace = "trace:zzz-i653".to_owned();
        let wid = format!("attestation:{}", withdraws.attestation_id);
        let ids = vec![before.clone(), wid.clone(), trace.clone()];
        let sel = PurgeSelection::ByIds { ids: ids.clone() };
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        assert_eq!(
            dry.inadmissible
                .iter()
                .map(|w| w.record_id.clone())
                .collect::<Vec<_>>(),
            vec![wid.clone()],
            "I653: the dry run warns, it does not filter an explicit list"
        );
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let notice_id = sp::notice_terms(&notice.envelope).unwrap().notice_id;
        let mut sorted = ids.clone();
        sorted.sort();
        let index = sorted.iter().position(|i| *i == wid).unwrap();
        for attempt in 0..2 {
            let e = rows_at(dir, &sel, &notice, NODE, t)
                .await
                .expect_err("inadmissible");
            let (tok, body) = refusal(&e);
            assert_eq!(tok, token::RETRACTION_INADMISSIBLE, "I653: {body}");
            assert_eq!(body["record_id"], wid.as_str());
            assert_eq!(body["plane"], "attestation");
            assert_eq!(body["index"], index);
            assert_eq!(body["total"], 3);
            assert!(
                dir.purge_tombstones_of(&notice_id)
                    .await
                    .unwrap()
                    .is_empty(),
                "I653 attempt {attempt}: whole or not at all — nothing is tombstoned"
            );
            assert_nothing_written(d, &notice).await;
        }
        // Purging the target WITH its retraction is admissible.
        let with_target = PurgeSelection::ByIds {
            ids: vec![
                wid.clone(),
                format!("attestation:{}", target.attestation_id),
            ],
        };
        let dry2 = sp::purge_dry_run(dir, &with_target).await.unwrap();
        assert!(dry2.inadmissible.is_empty(), "{:?}", dry2.inadmissible);
        let n2 = notice_for(
            &dry2.notice_template,
            &[cc::FOUNDERS[1], cc::FOUNDERS[2]],
            t,
        );
        let r = rows_at(dir, &with_target, &n2, NODE, t)
            .await
            .expect("admissible");
        assert_eq!(r.tombstoned.get("attestation"), Some(&2));
        // A delegates_to between two keys neither of which is purged is a
        // third party's standing grant: inadmissible.
        let grant = ts::put_delegates_to(dir, SCORER, BYSTANDER, None)
            .await
            .unwrap();
        let gid = format!("attestation:{grant}");
        let gsel = PurgeSelection::ByIds {
            ids: vec![gid.clone()],
        };
        let gdry = sp::purge_dry_run(dir, &gsel).await.unwrap();
        assert_eq!(
            gdry.inadmissible
                .iter()
                .map(|w| w.record_id.clone())
                .collect::<Vec<_>>(),
            vec![gid.clone()],
            "I653: a third party's delegates_to is not the purge's to remove"
        );
        assert!(gdry.inadmissible[0].reason.contains("delegates_to"));
        let gn = notice_for(
            &gdry.notice_template,
            &[cc::FOUNDERS[0], cc::FOUNDERS[2]],
            t,
        );
        let e = rows_at(dir, &gsel, &gn, NODE, t)
            .await
            .expect_err("a third party's grant");
        assert_eq!(refusal(&e).0, token::RETRACTION_INADMISSIBLE, "I653");
    }

    // ── I654 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i654_the_mock_class_end_to_end<D: Seams>(d: &D) {
        root(d).await;
        let (mocks, derived, unrelated) = mock_world(d, "i654").await;
        let dir = d.as_dyn_directory();
        let t = now();
        let sel = mock_selection();
        // The wire shape the operator passes to `purge_dry_run_json`.
        assert_eq!(
            serde_json::to_value(&sel).unwrap(),
            serde_json::json!({"kind": "mock_model_traces", "model": "mock-model"})
        );
        let served_before = served_ids(d).await;
        assert!(served_before.contains(&derived) && served_before.contains(&unrelated));
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        // The selection: both mock traces, their own attestations, the score
        // derived from one of them — and nothing about the real trace.
        let mut expect: Vec<String> = mocks.iter().map(|m| format!("trace:{m}")).collect();
        expect.extend(
            mocks
                .iter()
                .map(|m| format!("attestation:{}", crate::ingest::trace_attestation_id(m))),
        );
        expect.push(format!("attestation:{derived}"));
        expect.sort();
        assert_eq!(
            dry.sample, expect,
            "I654: the sample is the ids in JCS order"
        );
        assert_eq!(dry.record_count, 5);
        assert_eq!(dry.counts.get("trace_events"), Some(&2));
        assert_eq!(dry.counts.get("federation_attestations"), Some(&3));
        assert_eq!(dry.table_rows.get("trace_events"), Some(&4));
        assert_eq!(dry.table_rows.get("trace_llm_calls"), Some(&2));
        assert_eq!(dry.selection_digest, sp::selection_digest(&expect));
        assert!(dry
            .ledger_tsv
            .contains(&format!("attestation:{derived}\ttrace:{}", mocks[0])));
        // Read-only.
        assert_eq!(
            served_ids(d).await,
            served_before,
            "I654: the dry run writes nothing"
        );

        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[2]], t);
        let report = rows_at(dir, &sel, &notice, NODE, t)
            .await
            .expect("executes");
        assert_eq!(report.record_count, 5);
        assert_eq!(report.tombstoned.get("trace"), Some(&2));
        assert_eq!(report.tombstoned.get("attestation"), Some(&3));
        assert_eq!(report.selection_digest, dry.selection_digest);
        // Nothing deleted yet; the purged score is no longer served.
        let held = dir.get_attestation(&derived).await.unwrap();
        assert!(held.is_some());
        // Nor can a held copy be re-published through the tier crossing.
        let e = crate::federation::admission::check_promotion_admission(
            dir,
            held.as_ref().unwrap(),
            None,
        )
        .await
        .expect_err("a tombstoned row cannot cross");
        assert_eq!(refusal(&e).0, token::TOMBSTONED, "I654: the promotion door");
        let served = served_ids(d).await;
        assert!(
            !served.contains(&derived),
            "I654: a tombstoned row is not served"
        );
        assert!(
            served.contains(&unrelated),
            "I654: an unrelated row still is"
        );
        // The ledger: header preimages, every row, the digest re-derives.
        let ledger = sp::purge_ledger_tsv(dir, &report.notice_id).await.unwrap();
        for header in [
            format!("# selection_digest\t{}", dry.selection_digest),
            format!("# notice_id\t{}", report.notice_id),
            "# record_count\t5".to_owned(),
            format!("# executed_by\t{NODE}"),
            format!("# claimant_key_id\t{CANON}"),
            format!("# executed_at\t{}", report.executed_at.to_rfc3339()),
        ] {
            assert!(
                ledger.contains(&header),
                "I654: the ledger carries {header:?}:\n{ledger}"
            );
        }
        // The notice id re-derives from the ledger's own `notice_jcs`, and the
        // ledger carries the whole cosignature set.
        let header = |k: &str| {
            ledger
                .lines()
                .find_map(|l| l.strip_prefix(&format!("# {k}\t")))
                .unwrap_or_else(|| panic!("I654: the ledger has no {k}"))
                .to_owned()
        };
        {
            use sha2::Digest as _;
            assert_eq!(
                hex::encode(sha2::Sha256::digest(header("notice_jcs").as_bytes())),
                report.notice_id,
                "I654: the notice id re-derives from the ledger"
            );
        }
        let cosigs: Vec<serde_json::Value> =
            serde_json::from_str(&header("cosignatures_json")).unwrap();
        assert_eq!(cosigs.len(), 2, "I654: the whole cosignature set");
        let ids: Vec<String> = ledger
            .lines()
            .filter(|l| !l.starts_with('#') && !l.starts_with("selection_digest\t"))
            .map(|l| {
                let cols: Vec<&str> = l.split('\t').collect();
                assert_eq!(cols[0], dry.selection_digest);
                assert_eq!(cols[1], report.notice_id);
                cols[4].to_owned()
            })
            .collect();
        assert_eq!(
            sp::selection_digest(&ids),
            dry.selection_digest,
            "I654: the ledger re-derives"
        );
        // The stored header carries the whole cosignature set and the notice bytes.
        let exec = dir
            .purge_execution(&report.notice_id)
            .await
            .unwrap()
            .unwrap();
        let cos: Vec<ciris_verify_core::threshold::ThresholdSignature> =
            serde_json::from_str(&exec.cosignatures_json).unwrap();
        assert_eq!(
            cos, notice.cosignatures,
            "I654: the whole signature set is carried"
        );
        assert_eq!(
            exec.notice_jcs.as_bytes(),
            sp::notice_signing_bytes(&notice.envelope)
                .unwrap()
                .as_slice()
        );
        // Idempotent re-run.
        let again = rows_at(dir, &sel, &notice, NODE, t).await.expect("re-run");
        assert!(again.tombstoned.is_empty());
        assert_eq!(again.already_tombstoned, 5);
        let status = status_at(dir, &report.notice_id, t).await.unwrap();
        assert_eq!(status.state, sp::PurgeState::Executed);
    }

    // ── I655 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i655_finalize_after_settle_and_the_tombstone_outlives<D: Seams>(d: &D) {
        root(d).await;
        let (mocks, derived, unrelated) = mock_world(d, "i655").await;
        let dir = d.as_dyn_directory();
        let t = now();
        let derived_row = dir.get_attestation(&derived).await.unwrap().unwrap();
        let dry = sp::purge_dry_run(dir, &mock_selection()).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let report = rows_at(dir, &mock_selection(), &notice, NODE, t)
            .await
            .unwrap();
        // Settle is W = 72 h after the tombstone (CC 2.6.7, CIRISConstitution
        // rc8@8c8f536): still unsettled after an hour, and after the 24 h
        // lone-holder fuse (a different constant).
        for early in [
            chrono::Duration::hours(1),
            chrono::Duration::hours(24) + chrono::Duration::seconds(1),
        ] {
            let e = finalize_at(dir, &report.notice_id, t + early, None)
                .await
                .expect_err("not settled");
            let (tok, body) = refusal(&e);
            assert_eq!(tok, token::NOT_SETTLED, "I655 at +{early}: {body}");
        }
        assert!(
            dir.get_attestation(&derived).await.unwrap().is_some(),
            "nothing deleted"
        );
        let later = t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1);
        assert_eq!(
            status_at(dir, &report.notice_id, later)
                .await
                .unwrap()
                .state,
            sp::PurgeState::Settled
        );
        let fin = finalize_at(dir, &report.notice_id, later, None)
            .await
            .expect("finalizes");
        assert_eq!(fin.attestations_deleted, 3, "{fin:?}");
        assert_eq!(fin.trace_events_deleted, 4, "{fin:?}");
        assert_eq!(fin.trace_llm_calls_deleted, 2, "{fin:?}");
        for m in &mocks {
            assert!(dir
                .get_attestation(&crate::ingest::trace_attestation_id(m))
                .await
                .unwrap()
                .is_none());
        }
        assert_eq!(dir.purge_trace_row_counts(&mocks).await.unwrap(), (0, 0));
        assert!(dir.get_attestation(&derived).await.unwrap().is_none());
        assert!(
            dir.get_attestation(&unrelated).await.unwrap().is_some(),
            "only the selection"
        );
        assert_eq!(
            dir.purge_trace_row_counts(&["trace-real-i655".to_owned()])
                .await
                .unwrap(),
            (2, 1),
            "the real trace is untouched"
        );
        // The tombstone outlives the row: its return is refused.
        let e = dir
            .put_attestation(SignedAttestation {
                attestation: derived_row,
            })
            .await
            .expect_err("a purged row does not come back");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::TOMBSTONED, "I655: {body}");
        let st = status_at(dir, &report.notice_id, later).await.unwrap();
        assert_eq!(st.state, sp::PurgeState::Finalized);
        assert_eq!(st.tombstones.values().sum::<u64>(), 5, "tombstones remain");
        let again = finalize_at(dir, &report.notice_id, later, None)
            .await
            .unwrap();
        assert!(again.already_finalized);
        let e = finalize_at(dir, "f".repeat(64).as_str(), later, None)
            .await
            .expect_err("unknown");
        assert_eq!(refusal(&e).0, token::NOTICE_UNKNOWN);
    }

    // ── I656 ──────────────────────────────────────────────────────────────
    /// **I833 (v55.0.0, CIRISPersist#1055, CIRISEdge's ask) — a retryable
    /// `purge_unauthorised` is one a later row or instant turns into an
    /// authorisation.** A receiver that does not hold the claimant trust root
    /// refuses the bundle `root_not_held`, `retryable: true`; once the root
    /// lands, the SAME bundle is no longer refused as unauthorised. A notice
    /// asserted in this node's future is `not_yet_valid`, retryable, and
    /// authorises once the clock reaches it. A forged cosignature on a node
    /// that holds the root is `signature_invalid`, `retryable: false`.
    pub(crate) async fn i833_unauthorised_reason_splits_the_gap_from_the_verdict<D: Seams>(
        a: &D,
        c: &D,
    ) {
        root(a).await;
        mock_world(a, "i833").await;
        let t = now();
        let da = a.as_dyn_directory();
        let dry = sp::purge_dry_run(da, &mock_selection()).await.unwrap();

        // A notice from this node's future: the gap is the clock.
        let ahead = t + chrono::Duration::hours(1);
        let future = notice_for(
            &dry.notice_template,
            &[cc::FOUNDERS[0], cc::FOUNDERS[1]],
            ahead,
        );
        sp::test_clock::set(Some(t));
        let e = sp::verify_purge_authorisation(da, &future)
            .await
            .expect_err("I833: a notice from the future authorises nothing yet");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::UNAUTHORISED, "I833 future: {body}");
        assert_eq!(
            body["reason"].as_str(),
            Some(why::NOT_YET_VALID),
            "I833: {body}"
        );
        assert_eq!(body["retryable"].as_bool(), Some(true), "I833: {body}");
        sp::test_clock::set(Some(ahead + chrono::Duration::minutes(1)));
        sp::verify_purge_authorisation(da, &future)
            .await
            .expect("I833: the same notice authorises once the clock reaches it");

        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        rows_at(da, &mock_selection(), &notice, NODE, t)
            .await
            .unwrap();
        let bundle = sp::list_purge_bundles_since(da, None, 10)
            .await
            .unwrap()
            .remove(0);

        // The receiver does not hold the root YET.
        let dc = c.as_dyn_directory();
        let e = apply_at(dc, &bundle, "node-c", t)
            .await
            .expect_err("I833: a rootless receiver refuses");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::UNAUTHORISED, "I833 rootless: {body}");
        assert_eq!(
            body["reason"].as_str(),
            Some(why::ROOT_NOT_HELD),
            "I833: {body}"
        );
        assert_eq!(body["retryable"].as_bool(), Some(true), "I833: {body}");
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|d| d.contains("no community row")),
            "I833: the prose rides in `detail`: {body}"
        );

        // A forged cosignature is a verdict, on a node that holds the root.
        let mut forged = bundle.clone();
        forged.notice.cosignatures[0] = ts::threshold_sign(cc::FOUNDERS[0], b"not the notice");
        root(c).await;
        let (tok, body) = refusal(&apply_at(dc, &forged, "node-c", t).await.unwrap_err());
        assert_eq!(tok, token::UNAUTHORISED, "I833 forged: {body}");
        assert_eq!(
            body["reason"].as_str(),
            Some(why::SIGNATURE_INVALID),
            "I833: {body}"
        );
        assert_eq!(body["retryable"].as_bool(), Some(false), "I833: {body}");

        // The root landed: the SAME bundle is no longer an unauthorised one.
        match apply_at(dc, &bundle, "node-c", t).await {
            Ok(_) => {}
            Err(e) => {
                let (tok, body) = refusal(&e);
                assert_ne!(
                    tok,
                    token::UNAUTHORISED,
                    "I833: once the root is held the gap is closed: {body}"
                );
            }
        }
        for r in why::RETRYABLE {
            assert!(why::ALL.contains(r) && why::is_retryable(r));
        }
        assert!(!why::is_retryable(why::NOT_A_SEAT));
    }

    pub(crate) async fn i656_the_tombstone_replicates_re_verified<D: Seams>(a: &D, b: &D, c: &D) {
        root(a).await;
        root(b).await;
        let (_, derived, _) = mock_world(a, "i656").await;
        let derived_row = a
            .as_dyn_directory()
            .get_attestation(&derived)
            .await
            .unwrap()
            .unwrap();
        b.as_dyn_directory()
            .put_attestation(SignedAttestation {
                attestation: derived_row,
            })
            .await
            .expect("b holds a replica of the score");
        let t = now();
        let (da, db) = (a.as_dyn_directory(), b.as_dyn_directory());
        let dry = sp::purge_dry_run(da, &mock_selection()).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[1], cc::FOUNDERS[2]], t);
        let report = rows_at(da, &mock_selection(), &notice, NODE, t)
            .await
            .unwrap();
        let bundles = sp::list_purge_bundles_since(da, None, 10).await.unwrap();
        assert_eq!(bundles.len(), 1);
        let bundle = bundles[0].clone();
        assert_eq!(
            bundle.notice, notice,
            "the WHOLE notice and signature set is served"
        );
        assert_eq!(
            sp::selection_digest(&bundle.record_ids),
            dry.selection_digest
        );
        // A node not rooted at the same trust root (here: none) refuses the
        // bundle and records nothing: a purge is not global erasure (CC 3.2
        // T3, 4.2.1).
        let e = apply_at(c.as_dyn_directory(), &bundle, "node-c", t)
            .await
            .unwrap_err();
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::UNAUTHORISED, "I656 rootless: {body}");
        assert!(c
            .as_dyn_directory()
            .purge_execution(&report.notice_id)
            .await
            .unwrap()
            .is_none());
        // Tampered bundles.
        let mut dropped = bundle.clone();
        dropped.record_ids.pop();
        dropped.derived_from.pop();
        let (tok, _) = refusal(&apply_at(db, &dropped, "node-b", t).await.unwrap_err());
        assert!(
            tok == token::SELECTION_DIGEST_MISMATCH,
            "I656: a dropped id re-derives another digest ({tok})"
        );
        let mut forged = bundle.clone();
        forged.notice.cosignatures[0] = ts::threshold_sign(cc::FOUNDERS[1], b"not the notice");
        let (tok, _) = refusal(&apply_at(db, &forged, "node-b", t).await.unwrap_err());
        assert_eq!(
            tok,
            token::UNAUTHORISED,
            "I656: B re-verifies the cosignatures"
        );
        let mut unsorted = bundle.clone();
        unsorted.record_ids.swap(0, 1);
        let (tok, _) = refusal(&apply_at(db, &unsorted, "node-b", t).await.unwrap_err());
        assert_eq!(tok, token::SELECTION_MALFORMED);
        assert!(db
            .purge_execution(&report.notice_id)
            .await
            .unwrap()
            .is_none());
        // The genuine bundle.
        let out = apply_at(db, &bundle, "node-b", t).await.expect("applies");
        assert_eq!(out.tombstoned, 5);
        let exec = db
            .purge_execution(&report.notice_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exec.origin, sp::origin::REPLICATED);
        assert!(
            !served_ids(b).await.contains(&derived),
            "B stops serving its replica"
        );
        let again = apply_at(db, &bundle, "node-b", t).await.unwrap();
        assert_eq!((again.tombstoned, again.already_tombstoned), (0, 5));
    }

    // ── I662 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i662_refused_today_is_a_selection_not_a_filter<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        let mut legacy = Vec::new();
        for _ in 0..4 {
            let row = put_score(d, BYSTANDER, AGENT, &[]).await;
            d.shift_asserted_at(
                &row.attestation_id,
                row.asserted_at + chrono::Duration::seconds(1),
            )
            .await;
            legacy.push(row.attestation_id);
        }
        let good = put_score(d, SCORER, AGENT, &[]).await.attestation_id;
        let derived = put_score(d, SCORER, AGENT, &[&legacy[0]])
            .await
            .attestation_id;
        for id in &legacy {
            let row = dir.get_attestation(id).await.unwrap().unwrap();
            assert!(
                sp::refused_today(&row).is_some(),
                "the seam makes a #598 legacy row"
            );
        }
        // A local-tier row the apply door would also refuse is this node's
        // own business: never served, never in the class.
        let local = seed_trace(d, "trace-local-i662", AGENT, "gpt-real").await;
        let local_row = dir.get_attestation(&local).await.unwrap().unwrap();
        d.shift_asserted_at(&local, local_row.asserted_at + chrono::Duration::seconds(1))
            .await;
        let local_row = dir.get_attestation(&local).await.unwrap().unwrap();
        assert!(
            sp::refused_today(&local_row).is_some(),
            "precondition: the class's tier clause is what keeps it out"
        );
        // The class scan reads every row, every tier, to the end.
        let mut by_one = Vec::new();
        sp::scan_attestations_paged(dir, 1, |r| by_one.push(r.attestation_id))
            .await
            .unwrap();
        let mut whole = Vec::new();
        sp::scan_attestations(dir, |r| whole.push(r.attestation_id))
            .await
            .unwrap();
        assert_eq!(by_one, whole, "I662: the scan pages to the end");
        assert!(legacy.iter().chain([&local]).all(|id| whole.contains(id)));
        // Ruled (#1043, 2026-10-09): not a serve filter. Until purged, the
        // rows are served like any other.
        let served_before = served_ids(d).await;
        for id in legacy.iter().chain([&good, &derived]) {
            assert!(
                served_before.contains(id),
                "I662: {id} is served until it is purged"
            );
        }
        // The class selects them, and the score derived from one follows.
        let sel = PurgeSelection::RefusedToday;
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let mut expect: Vec<String> = legacy.iter().map(|l| format!("attestation:{l}")).collect();
        expect.push(format!("attestation:{derived}"));
        expect.sort();
        assert_eq!(dry.sample, expect, "I662: withheld {:?}", dry.withheld);
        assert_eq!(dry.record_count, 5);
        assert_eq!(dry.counts.get("federation_attestations"), Some(&5));
        assert_eq!(dry.counts.len(), 1, "I662: {:?}", dry.counts);
        assert!(dry.withheld.is_empty(), "{:?}", dry.withheld);
        assert_eq!(dry.selection_digest, sp::selection_digest(&expect));
        assert_eq!(
            served_ids(d).await,
            served_before,
            "I662: the dry run writes nothing"
        );
        // Executed on the quorum's notice, they stop being served; the row
        // the class did not select still is.
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[1], cc::FOUNDERS[2]], t);
        let report = rows_at(dir, &sel, &notice, NODE, t)
            .await
            .expect("executes");
        assert_eq!(report.tombstoned.get("attestation"), Some(&5));
        let served = served_ids(d).await;
        for id in legacy.iter().chain([&derived]) {
            assert!(!served.contains(id), "I662: purged {id} is not served");
        }
        assert!(served.contains(&good), "I662: an unselected row still is");
    }

    // ── I664 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i664_the_tombstone_row_holds_another_basis<D: Seams>(d: &D) {
        let dir = d.as_dyn_directory();
        let t = now();
        let sha = "ab".repeat(32);
        let exec = sp::PurgeExecution {
            notice_id: "cd".repeat(32),
            selection_digest: sha.clone(),
            claimant_key_id: "moderator-1".to_owned(),
            legal_basis: "ncmec_csam".to_owned(),
            record_count: 1,
            notice_jcs: "{}".to_owned(),
            cosignatures_json: "[]".to_owned(),
            executed_by: NODE.to_owned(),
            origin: sp::origin::LOCAL.to_owned(),
            executed_at: t,
            admitted_at: t,
            finalized_at: None,
        };
        let put = dir
            .purge_put_execution(
                &exec,
                &[sp::PurgeTombstone {
                    notice_id: exec.notice_id.clone(),
                    ordinal: 0,
                    plane: PurgePlane::Blob,
                    record_ref: sha.clone(),
                    derived_from: None,
                }],
            )
            .await
            .unwrap();
        assert!(put.header_inserted);
        assert_eq!(put.tombstones_inserted, vec![true]);
        let got = dir
            .purge_execution(&exec.notice_id)
            .await
            .unwrap()
            .expect("held");
        assert_eq!(got.legal_basis, "ncmec_csam", "I664: the basis round-trips");
        assert_eq!(
            (got.claimant_key_id.as_str(), got.selection_digest.as_str()),
            (exec.claimant_key_id.as_str(), sha.as_str())
        );
        assert_eq!(
            dir.purge_tombstoned("blob", &sha).await.unwrap(),
            Some(exec.notice_id.clone()),
            "I664: the bytes-plane tombstone names its notice"
        );
        let ledger = sp::purge_ledger_tsv(dir, &exec.notice_id).await.unwrap();
        assert!(
            ledger.contains("# legal_basis\tncmec_csam\n"),
            "I664: the ledger names the basis:\n{ledger}"
        );
    }

    // ── I665 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i665_a_purge_never_touches_a_key<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        let key = dir.lookup_public_key(HARNESS).await.unwrap().unwrap();
        let by = put_score(d, HARNESS, BYSTANDER, &[]).await.attestation_id;
        let kept = put_score(d, HARNESS, SCORER, &[]).await;
        let about = put_score(d, BYSTANDER, HARNESS, &[]).await.attestation_id;
        let grant = ts::put_delegates_to(dir, HARNESS, BYSTANDER, None)
            .await
            .unwrap();
        let incoming = ts::put_delegates_to(dir, SCORER, HARNESS, None)
            .await
            .unwrap();
        let tid = "trace-harness-i665";
        let tatt = seed_trace(d, tid, HARNESS, "gpt-real").await;
        let later = t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1);

        // (a) ByIds: one of the actor's rows goes; its key and its OTHER row
        // stay, and that row still verifies against the key.
        let one = PurgeSelection::ByIds {
            ids: vec![format!("attestation:{by}")],
        };
        let dry = sp::purge_dry_run(dir, &one).await.unwrap();
        let n = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let r = rows_at(dir, &one, &n, NODE, t).await.unwrap();
        finalize_at(dir, &r.notice_id, later, None).await.unwrap();
        assert!(dir.get_attestation(&by).await.unwrap().is_none());
        crate::federation::verify_row_hybrid_signature(dir, &kept)
            .await
            .expect("I665: the actor's unselected row still verifies");

        // (b) ByActor: exactly what the actor AUTHORED — never its key, never
        // a row another key signed about it.
        let sel = PurgeSelection::ByActor {
            key_id: HARNESS.to_owned(),
        };
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let mut expect = vec![
            format!("attestation:{}", kept.attestation_id),
            format!("attestation:{grant}"),
            format!("attestation:{tatt}"),
            format!("trace:{tid}"),
        ];
        expect.sort();
        assert_eq!(dry.sample, expect, "I665: withheld {:?}", dry.withheld);
        assert!(
            !dry.counts.contains_key("federation_keys"),
            "I665: {:?}",
            dry.counts
        );
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[2]], t);
        let report = rows_at(dir, &sel, &notice, NODE, t)
            .await
            .expect("executes");
        finalize_at(dir, &report.notice_id, later, None)
            .await
            .expect("finalizes");
        // The key is untouched: still registered, byte-identical, and still
        // the key the rows others signed about the actor resolve against.
        let after = dir.lookup_public_key(HARNESS).await.unwrap();
        assert_eq!(
            after.as_ref().map(|k| &k.pubkey_ed25519_base64),
            Some(&key.pubkey_ed25519_base64),
            "I665: the actor's key stays registered"
        );
        for id in [&about, &incoming] {
            assert!(
                dir.get_attestation(id).await.unwrap().is_some(),
                "I665: {id}"
            );
        }
        dir.put_public_key(crate::federation::SignedKeyRecord {
            record: key.clone(),
        })
        .await
        .expect("I665: the key's door never refuses it on a purge's account");
        let fresh = put_score(d, HARNESS, BYSTANDER, &[]).await;
        crate::federation::verify_row_hybrid_signature(dir, &fresh)
            .await
            .expect("I665: a row the actor signs afterwards still verifies");
    }

    // ── I666 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i666_a_key_id_is_not_a_purge_record<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let key = dir.lookup_public_key(HARNESS).await.unwrap().unwrap();
        let digest = crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
            &key.pubkey_ed25519_base64,
        )
        .unwrap()
        .to_hex();
        let sel = PurgeSelection::ByIds {
            ids: vec![format!("key:{digest}")],
        };
        let e = sp::purge_dry_run(dir, &sel)
            .await
            .expect_err("a key is never a purge record");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::SELECTION_MALFORMED, "I666: {body}");
        assert!(
            body["reason"]
                .as_str()
                .is_some_and(|r| r.contains("key:revocation")),
            "I666: the refusal names key retirement's own act: {body}"
        );
        let e = sp::parse_record_id(&format!("federation_keys:{digest}"))
            .expect_err("nor by its table name");
        assert_eq!(refusal(&e).0, token::SELECTION_MALFORMED);
    }

    // ── I667 ──────────────────────────────────────────────────────────────
    /// A local-tier row by `attester` whose dimension is `dimension`.
    async fn put_local_dimension<D: Seams>(d: &D, attester: &str, dimension: &str) -> String {
        let local = crate::federation::types::LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: attester.to_owned(),
            attested_key_id: Some(BYSTANDER.to_owned()),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({"dimension": dimension, "score": 0.0}),
            )
            .expect("object"),
            subject_key_ids: vec![BYSTANDER.to_owned()],
            cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        d.attestation_insert_local(local).await.expect("local row")
    }

    /// **I694** (CIRISPersist#1054) — the RESET purge door
    /// (`migration::check_purge_admission`, every backend's
    /// `purge_attestation_v31`) refuses the accountability record too, and the
    /// reset's planning keeps it: `is_exclusion_bearing` names each of the five
    /// families. Before #1054 the door knew `revocation:`, `moderation:` and
    /// `slashing:` by prefix and deleted a `key:revocation` or a
    /// `moderation_track_record:*` row.
    pub(crate) async fn i694_the_reset_door_refuses_the_accountability_record<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let mut problems = Vec::new();
        // The CC's five families, hardcoded: built from the shared list, the
        // witness followed the list wherever it moved (dropping a family from
        // it left I694 green).
        for dimension in [
            "revocation:i694:v1",
            "key:revocation:i694:v1",
            "moderation:i694:v1",
            "moderation_track_record:i694:v1",
            "slashing:i694:v1",
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            let env = serde_json::json!({"dimension": dimension, "score": 0.0});
            let mut row = ts::bare_attestation(&id, HARNESS, BYSTANDER, &env);
            row.attestation_type = attestation_type::SCORES.to_owned();
            ts::reseal(&mut row);
            if let Err(e) = dir
                .put_attestation(SignedAttestation {
                    attestation: row.clone(),
                })
                .await
            {
                // A family the write doors refuse cannot reach the reset door
                // that way; the door's own gate is still asked below.
                problems.push(format!(
                    "{dimension}: not admitted ({e}); door asked on the row"
                ));
            }
            if crate::federation::migration::is_exclusion_bearing(&row).is_none() {
                problems.push(format!("{dimension}: the reset would PLAN its purge"));
            }
            if crate::federation::migration::check_purge_admission(&row).is_ok() {
                problems.push(format!("{dimension}: the reset door ADMITS its purge"));
            }
            if dir.get_attestation(&id).await.unwrap().is_some() {
                match dir.purge_attestation_v31(&id).await {
                    Ok(gone) => problems.push(format!(
                        "{dimension}: purge_attestation_v31 DELETED it (returned {gone})"
                    )),
                    Err(_) => assert!(
                        dir.get_attestation(&id).await.unwrap().is_some(),
                        "I694 {dimension}: refused, and the row is still held"
                    ),
                }
            }
        }
        let deleted: Vec<&String> = problems
            .iter()
            .filter(|p| !p.contains("not admitted"))
            .collect();
        assert!(deleted.is_empty(), "I694:\n{}", problems.join("\n"));
    }

    pub(crate) async fn i667_the_accountability_record_is_unpurgeable<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        let mut ids = Vec::new();
        for dimension in [
            "revocation:peer:fraud:v1",
            "key:revocation:v1",
            "moderation:spam:v1",
            "moderation_track_record:ciris-canonical:v1",
            "slashing:upheld:v1",
        ] {
            let id = put_local_dimension(d, HARNESS, dimension).await;
            ids.push((dimension, format!("attestation:{id}")));
        }
        // By ids: every one is inadmissible, by the accountability clause.
        let sel = PurgeSelection::ByIds {
            ids: ids.iter().map(|(_, id)| id.clone()).collect(),
        };
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let mut problems = Vec::new();
        for (dimension, id) in &ids {
            match dry.inadmissible.iter().find(|w| w.record_id == *id) {
                None => problems.push(format!("{dimension}: SLIPPED THROUGH")),
                Some(w) if !w.reason.contains("CLM-accountability-record-unpurgeable") => {
                    problems.push(format!(
                        "{dimension}: refused by another clause ({})",
                        w.reason
                    ));
                }
                Some(_) => {}
            }
        }
        assert!(problems.is_empty(), "I667:\n{}", problems.join("\n"));
        let n = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let e = rows_at(dir, &sel, &n, NODE, t)
            .await
            .expect_err("the accountability record is unpurgeable");
        assert_eq!(refusal(&e).0, token::RETRACTION_INADMISSIBLE, "I667");
        // By actor: the class withholds them all, and the dry run surfaces
        // them. Whole or not at all (CC 4.5.3) holds for what the notice
        // NAMES: the digest is over the admissible rows only, so executing it
        // tombstones exactly those, and the withheld rows stay untouched.
        let plain = put_score(d, HARNESS, BYSTANDER, &[]).await.attestation_id;
        let by = PurgeSelection::ByActor {
            key_id: HARNESS.to_owned(),
        };
        let dry = sp::purge_dry_run(dir, &by).await.unwrap();
        for (dimension, id) in &ids {
            assert!(
                dry.withheld.iter().any(|w| w.record_id == *id),
                "I667: by-actor did not withhold the {dimension} row"
            );
            assert!(!dry.sample.contains(id));
        }
        assert_eq!(dry.sample, vec![format!("attestation:{plain}")], "I667");
        let n = notice_for(&dry.notice_template, &[cc::FOUNDERS[1], cc::FOUNDERS[2]], t);
        let r = rows_at(dir, &by, &n, NODE, t).await.expect("executes");
        let held: Vec<String> = dir
            .purge_tombstones_of(&r.notice_id)
            .await
            .unwrap()
            .iter()
            .map(sp::PurgeTombstone::record_id)
            .collect();
        assert_eq!(held, dry.sample, "I667: exactly what the notice names");
        for (_, id) in &ids {
            let raw = id.trim_start_matches("attestation:");
            assert!(dir.get_attestation(raw).await.unwrap().is_some());
            assert_eq!(
                dir.purge_tombstoned("attestation", raw).await.unwrap(),
                None
            );
        }
    }

    // ── I670 ──────────────────────────────────────────────────────────────
    /// A 2.7.0 trace by `signer` carrying `wire_kind`, hybrid-signed over the
    /// canonical bytes with `signed_kind` as the top-level `"run_kind"` key —
    /// built INDEPENDENTLY of persist's reconstruction (the pre-run_kind
    /// payload plus the key), so the witness is not persist checking itself.
    fn signed_run_kind_trace(
        trace_id: &str,
        signer: &str,
        signed_kind: &str,
        wire_kind: &str,
    ) -> serde_json::Value {
        use crate::verify::canonical::Canonicalizer as _;
        let mut json = trace_json(trace_id, signer, "gpt-real", None);
        let typed: crate::schema::CompleteTrace = serde_json::from_value(json.clone()).unwrap();
        let mut canonical = crate::verify::ed25519::canonical_payload_value(&typed);
        canonical["run_kind"] = serde_json::json!(signed_kind);
        let bytes = crate::verify::PythonJsonDumpsCanonicalizer
            .canonicalize_value(&canonical)
            .unwrap();
        let sig = ts::threshold_sign(signer, &bytes);
        json["run_kind"] = serde_json::json!(wire_kind);
        json["signature"] = serde_json::json!(sig.ed25519_signature_base64);
        json["signature_ml_dsa_65"] = serde_json::json!(sig.mldsa65_signature_base64);
        json["pubkey_ml_dsa_65"] = serde_json::json!(ts::hybrid_pubkeys(signer).1);
        json["pqc_key_id"] = serde_json::json!(signer);
        json
    }

    async fn ingest_full<D: Seams>(
        d: &D,
        bytes: &[u8],
    ) -> Result<crate::ingest::BatchSummary, crate::ingest::IngestError> {
        use ciris_keyring::Ed25519SoftwareSigner;
        let mut signer = Ed25519SoftwareSigner::new("scrub-key-i670");
        signer.import_key(&[0xA6u8; 32]).expect("seed");
        let pipeline = crate::ingest::IngestPipeline {
            backend: d,
            canonicalizer: &crate::verify::PythonJsonDumpsCanonicalizer,
            scrubber: &crate::scrub::NullScrubber,
            signer: &signer,
            signer_key_id: "scrub-key-i670",
        };
        pipeline
            .receive_and_persist_with(bytes, crate::ingest::VerifyMode::Full)
            .await
    }

    pub(crate) async fn i670_run_kind_is_a_signed_member<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        // (a) production / qa / battery: admitted and verified, and the
        // stored trace attestation carries the signed run_kind.
        for kind in ["production", "qa", "battery"] {
            let tid = format!("trace-i670-{kind}");
            let trace = signed_run_kind_trace(&tid, AGENT, kind, kind);
            let summary = ingest_full(d, &batch(&trace))
                .await
                .unwrap_or_else(|e| panic!("I670: a signed run_kind {kind} trace admits: {e}"));
            assert_eq!(summary.signatures_verified, 1, "I670 {kind}");
            let att = dir
                .get_attestation(&crate::ingest::trace_attestation_id(&tid))
                .await
                .unwrap()
                .expect("the trace attestation");
            assert_eq!(
                att.attestation_envelope["trace"]["run_kind"], kind,
                "I670: the stored trace keeps its signed run_kind"
            );
        }
        // (b) signed one way, sent another: the signature check refuses it.
        let tampered = signed_run_kind_trace("trace-i670-tampered", AGENT, "mock", "production");
        let e = ingest_full(d, &batch(&tampered))
            .await
            .expect_err("a run_kind edited after signing");
        assert!(
            !matches!(e, crate::ingest::IngestError::TraceRefused { .. }),
            "I670: refused by the signature, not a gate: {e}"
        );
        assert_eq!(
            dir.purge_trace_row_counts(&["trace-i670-tampered".to_owned()])
                .await
                .unwrap(),
            (0, 0)
        );
        // (c) outside the closed vocabulary: a schema refusal.
        let odd = signed_run_kind_trace("trace-i670-odd", AGENT, "staging", "staging");
        let e = ingest_full(d, &batch(&odd))
            .await
            .expect_err("closed vocabulary");
        assert_eq!(e.kind(), "schema_unknown_run_kind", "I670: {e}");
        // (d) a signed mock run on the canonical: `trace_run_kind_mock`.
        ts::register_hybrid_key(dir, NODE).await;
        d.set_node(NODE);
        d.set_identity_type(NODE, "node,canonical").await;
        let mock = signed_run_kind_trace("trace-i670-mock", AGENT, "mock", "mock");
        let e = ingest_full(d, &batch(&mock)).await.expect_err("a mock run");
        assert_eq!(e.kind(), sp::TRACE_RUN_KIND_MOCK, "I670: {e}");
    }

    // ── I669 ──────────────────────────────────────────────────────────────
    /// What a v54.1 node does with the first CIRISAgent#1249 trace
    /// (`trace_format` v2.8.0, `run_kind` in the signed envelope): it REFUSES
    /// the whole batch at the schema-version gate, `schema_unsupported_version`,
    /// before any write — it never strips the field and never admits a trace
    /// whose signed bytes it cannot reconstruct.
    pub(crate) async fn i669_a_run_kind_trace_format_is_refused_whole<D: Seams>(d: &D) {
        let mut trace = trace_json("trace-i669", AGENT, "gpt-real", Some("production"));
        trace["trace_schema_version"] = serde_json::json!("2.8.0");
        let mut body: serde_json::Value = serde_json::from_slice(&batch(&trace)).unwrap();
        body["trace_schema_version"] = serde_json::json!("2.8.0");
        let e = ingest(d, body.to_string().as_bytes())
            .await
            .expect_err("a v2.8.0 trace is refused, not stripped");
        assert_eq!(e.kind(), "schema_unsupported_version", "I669: {e}");
        assert_eq!(
            d.as_dyn_directory()
                .purge_trace_row_counts(&["trace-i669".to_owned()])
                .await
                .unwrap(),
            (0, 0),
            "I669: nothing written"
        );
    }

    // ── I668 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i668_the_receiver_re_asks_admissibility<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        // A quorum-cosigned bundle that no origin door would have produced:
        // it names an accountability record this receiver holds.
        let held =
            put_local_dimension(d, HARNESS, "moderation_track_record:ciris-canonical:v1").await;
        let plain = put_score(d, SCORER, AGENT, &[]).await.attestation_id;
        let mut ids = vec![
            format!("attestation:{held}"),
            format!("attestation:{plain}"),
        ];
        ids.sort();
        let template = serde_json::json!({
            "legal_basis": sp::STEWARD_PURGE_BASIS,
            "content_sha256": sp::selection_digest(&ids),
            "content_holder_key_ids": [],
        });
        let bundle = sp::PurgeBundle {
            notice: notice_for(&template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t),
            record_ids: ids.clone(),
            derived_from: vec![String::new(); ids.len()],
            admitted_at: t,
        };
        let e = apply_at(dir, &bundle, "node-b", t)
            .await
            .expect_err("the receiver re-asks the unconditional rules");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::RETRACTION_INADMISSIBLE, "I668: {body}");
        assert_eq!(body["record_id"], format!("attestation:{held}"));
        // Whole or not at all: the plain row is not tombstoned either.
        let notice_id = sp::notice_terms(&bundle.notice.envelope).unwrap().notice_id;
        assert!(dir.purge_execution(&notice_id).await.unwrap().is_none());
        assert!(dir
            .purge_tombstones_of(&notice_id)
            .await
            .unwrap()
            .is_empty());
    }

    // ── I672 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i672_no_human_subject_until_the_notice_is_a_row<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        const ALICE: &str = "alice-human-i672";
        ts::register_hybrid_key_as(
            dir,
            ALICE,
            ALICE,
            crate::federation::types::identity_type::USER,
        )
        .await;
        // (a) The mock-trace class has no human subject: it passes.
        mock_world(d, "i672").await;
        sp::purge_dry_run(dir, &mock_selection())
            .await
            .expect("I672: the mock traces pass the interim gate");
        // (b) One row about a person, beside one that is not: refused, at the
        // dry run (naming the record and the subject) and at execution.
        let about_alice = put_score(d, SCORER, ALICE, &[]).await.attestation_id;
        let plain = put_score(d, SCORER, AGENT, &[]).await.attestation_id;
        let mut ids = vec![
            format!("attestation:{about_alice}"),
            format!("attestation:{plain}"),
        ];
        ids.sort();
        let sel = PurgeSelection::ByIds { ids: ids.clone() };
        let e = sp::purge_dry_run(dir, &sel)
            .await
            .expect_err("a human subject is refused at the dry run");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::HUMAN_SUBJECT_PENDING_NOTICE_ROW, "I672: {body}");
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 1, "I672: only the human-subject row: {body}");
        assert_eq!(
            records[0]["record_id"],
            format!("attestation:{about_alice}")
        );
        assert_eq!(records[0]["subject"], ALICE);
        let template = serde_json::json!({
            "legal_basis": sp::STEWARD_PURGE_BASIS,
            "content_sha256": sp::selection_digest(&ids),
            "content_holder_key_ids": [],
        });
        let notice = notice_for(&template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let e = rows_at(dir, &sel, &notice, NODE, t)
            .await
            .expect_err("and at execution");
        assert_eq!(
            refusal(&e).0,
            token::HUMAN_SUBJECT_PENDING_NOTICE_ROW,
            "I672"
        );
        assert_nothing_written(d, &notice).await;
        // ... and at the replicated apply, on what the receiver holds.
        let bundle = sp::PurgeBundle {
            notice: notice.clone(),
            record_ids: ids.clone(),
            derived_from: vec![String::new(); ids.len()],
            admitted_at: t,
        };
        let e = apply_at(dir, &bundle, "node-b", t)
            .await
            .expect_err("and at the receiver");
        assert_eq!(
            refusal(&e).0,
            token::HUMAN_SUBJECT_PENDING_NOTICE_ROW,
            "I672"
        );
        assert_nothing_written(d, &notice).await;
        // (c) A by-actor purge of a person is refused: the actor is the
        // subject of every record it selects.
        put_score(d, ALICE, AGENT, &[]).await;
        let e = sp::purge_dry_run(
            dir,
            &PurgeSelection::ByActor {
                key_id: ALICE.to_owned(),
            },
        )
        .await
        .expect_err("a person's by-actor purge");
        assert_eq!(
            refusal(&e).0,
            token::HUMAN_SUBJECT_PENDING_NOTICE_ROW,
            "I672"
        );
        // (d) Fail closed: a subject key this node cannot resolve.
        // (A held local row whose subject list names a key this node has no
        // record of; the federation door would not admit such an attested key.)
        let ghost = d
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: SCORER.to_owned(),
                attested_key_id: Some(AGENT.to_owned()),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({"dimension": "chat:message:v1", "score": 1.0}),
                )
                .unwrap(),
                subject_key_ids: vec!["ghost-unregistered-i672".to_owned()],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("local row");
        let e = sp::purge_dry_run(
            dir,
            &PurgeSelection::ByIds {
                ids: vec![format!("attestation:{ghost}")],
            },
        )
        .await
        .expect_err("an unresolvable subject is not proven non-human");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::HUMAN_SUBJECT_PENDING_NOTICE_ROW, "I672");
        assert!(body["records"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("does not resolve"));
    }

    // ── I659 ──────────────────────────────────────────────────────────────
    /// A trace whose LLM call reports `model` and which declares `run_kind`
    /// (absent when `None`, as every pre-CIRISAgent#1249 trace is).
    fn trace_json(
        trace_id: &str,
        signer: &str,
        model: &str,
        run_kind: Option<&str>,
    ) -> serde_json::Value {
        let mut t = serde_json::json!({
            "trace_id": trace_id,
            "thought_id": "th-1",
            "task_id": "task-1",
            "agent_id_hash": "deadbeef",
            "started_at": "2026-04-30T00:15:53.123456Z",
            "completed_at": "2026-04-30T00:16:12.789012Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
            "components": [
                {
                    "component_type": "observation",
                    "event_type": "THOUGHT_START",
                    "timestamp": "2026-04-30T00:15:53.123Z",
                    "data": {"attempt_index": 0},
                },
                {
                    "component_type": "llm_call",
                    "event_type": "LLM_CALL",
                    "timestamp": "2026-04-30T00:15:59.000Z",
                    "data": {
                        "attempt_index": 0,
                        "handler_name": "dsdma",
                        "service_name": "llm",
                        "duration_ms": 12.0,
                        "status": "ok",
                        "model": model,
                    },
                },
            ],
            "signature": "",
            "signature_key_id": signer,
        });
        if let Some(k) = run_kind {
            t["run_kind"] = serde_json::json!(k);
        }
        t
    }

    fn batch(trace: &serde_json::Value) -> Vec<u8> {
        serde_json::json!({
            "events": [{"event_type": "complete_trace", "trace_level": "generic", "trace": trace}],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
        })
        .to_string()
        .into_bytes()
    }

    async fn ingest<D: Seams>(
        d: &D,
        bytes: &[u8],
    ) -> Result<crate::ingest::BatchSummary, crate::ingest::IngestError> {
        use ciris_keyring::Ed25519SoftwareSigner;
        let mut signer = Ed25519SoftwareSigner::new("scrub-key-i659");
        signer.import_key(&[0xA5u8; 32]).expect("seed");
        let pipeline = crate::ingest::IngestPipeline {
            backend: d,
            canonicalizer: &crate::verify::PythonJsonDumpsCanonicalizer,
            scrubber: &crate::scrub::NullScrubber,
            signer: &signer,
            signer_key_id: "scrub-key-i659",
        };
        pipeline
            .receive_and_persist_with(bytes, crate::ingest::VerifyMode::TrustPreVerified)
            .await
    }

    pub(crate) async fn i659_mock_traces_are_refused_at_the_federation_doors<D: Seams>(
        canonical: &D,
        plain: &D,
    ) {
        // (a) the attestation door, federation tier.
        root(canonical).await;
        let dir = canonical.as_dyn_directory();
        let mut row = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            AGENT,
            AGENT,
            &serde_json::json!({
                "dimension": crate::ingest::TRACE_ATTESTATION_DIMENSION,
                "trace_id": "trace-i659-att",
                "trace": trace_json("trace-i659-att", AGENT, "gpt-real", Some(sp::RUN_KIND_MOCK)),
            }),
        );
        row.attestation_type = attestation_type::SCORES.to_owned();
        ts::reseal(&mut row);
        let e = dir
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .expect_err("a federation-tier mock trace is refused");
        assert_eq!(e.kind(), sp::TRACE_RUN_KIND_MOCK, "I659(a): {e}");
        assert!(sp::refuse_mock_trace_attestation(&row).is_err());
        // The tier crossing mints a federation-tier row: a local QA trace
        // cannot cross either.
        let e = crate::federation::admission::check_promotion_admission(dir, &row, None)
            .await
            .expect_err("a mock trace cannot cross");
        assert_eq!(e.kind(), sp::TRACE_RUN_KIND_MOCK, "I659(a) promotion: {e}");
        let mut local = row.clone();
        local.tier = crate::federation::types::attestation_tier::LOCAL.to_owned();
        assert!(
            sp::refuse_mock_trace_attestation(&local).is_ok(),
            "the local tier keeps QA traces"
        );
        // Keyed on the signed `run_kind`, never on a model-name heuristic: a
        // production run on the mock model's id, and a trace that predates
        // `run_kind`, pass.
        for (what, trace) in [
            (
                "run_kind production",
                trace_json(
                    "trace-i659-att",
                    AGENT,
                    sp::MOCK_LLM_MODEL,
                    Some("production"),
                ),
            ),
            (
                "no run_kind",
                trace_json("trace-i659-att", AGENT, sp::MOCK_LLM_MODEL, None),
            ),
        ] {
            let mut other = row.clone();
            other.attestation_envelope["trace"] = trace;
            assert!(
                sp::refuse_mock_trace_attestation(&other).is_ok(),
                "I659(a): {what} passes"
            );
        }

        // (b) ingest: a node holding `canonical` refuses, a plain node keeps.
        ts::register_hybrid_key(dir, NODE).await;
        assert!(!crate::federation::is_canonical_effective(dir, NODE)
            .await
            .unwrap());
        canonical.set_node(NODE);
        // Before the role: this node is not the federation corpus, so it keeps
        // a mock trace like any other node would.
        let early = batch(&trace_json(
            "trace-i659-early",
            AGENT,
            "gpt-real",
            Some(sp::RUN_KIND_MOCK),
        ));
        ingest(canonical, &early)
            .await
            .expect("a node without `canonical` keeps it");
        canonical.set_identity_type(NODE, "node,canonical").await;
        assert!(crate::federation::is_canonical_effective(dir, NODE)
            .await
            .unwrap());
        let mock = batch(&trace_json(
            "trace-i659-ingest",
            AGENT,
            "gpt-real",
            Some(sp::RUN_KIND_MOCK),
        ));
        let e = ingest(canonical, &mock)
            .await
            .expect_err("refused on the canonical");
        assert_eq!(e.kind(), sp::TRACE_RUN_KIND_MOCK, "I659(b): {e}");
        assert_eq!(
            dir.purge_trace_row_counts(&["trace-i659-ingest".to_owned()])
                .await
                .unwrap(),
            (0, 0),
            "I659(b): zero rows for the refused batch"
        );
        let real = batch(&trace_json(
            "trace-i659-real",
            AGENT,
            sp::MOCK_LLM_MODEL,
            Some("production"),
        ));
        ingest(canonical, &real)
            .await
            .expect("a real trace is admitted on the canonical");
        ingest(plain, &mock)
            .await
            .expect("a plain node keeps its QA trace");
        assert_eq!(
            plain
                .as_dyn_directory()
                .purge_trace_row_counts(&["trace-i659-ingest".to_owned()])
                .await
                .unwrap()
                .1,
            1
        );

        // (c) a tombstoned trace is refused at ingest on every node.
        let t = now();
        let sel = PurgeSelection::ByIds {
            ids: vec!["trace:trace-i659-real".to_owned()],
        };
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let rep = rows_at(dir, &sel, &notice, NODE, t).await.unwrap();
        finalize_at(
            dir,
            &rep.notice_id,
            t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1),
            None,
        )
        .await
        .unwrap();
        let e = ingest(canonical, &real)
            .await
            .expect_err("the purged trace cannot return");
        assert_eq!(e.kind(), token::TOMBSTONED, "I659(c): {e}");
    }

    // ── I695 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i695_the_header_and_its_tombstones_are_one_write<D: Seams>(d: &D) {
        root(d).await;
        let (_, derived, _) = mock_world(d, "i695").await;
        let dir = d.as_dyn_directory();
        let t = now();
        let dry = sp::purge_dry_run(dir, &mock_selection()).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);

        // A failure between the header and the tombstones leaves NEITHER.
        d.hooks().fail_next("purge_put_execution_tombstones", 1);
        let e = rows_at(dir, &mock_selection(), &notice, NODE, t)
            .await
            .expect_err("I695: the armed fault fails the write");
        assert!(
            e.to_string().contains("injected"),
            "I695: refused by the armed fault, not a gate: {e}"
        );
        assert_nothing_written(d, &notice).await;
        assert!(
            served_ids(d).await.contains(&derived),
            "I695: nothing tombstoned, so the selection is still served"
        );

        // The retry executes the whole set.
        let report = rows_at(dir, &mock_selection(), &notice, NODE, t)
            .await
            .expect("I695: the retry executes");
        assert_eq!(report.record_count, dry.record_count);
        assert_eq!(
            report.tombstoned.values().sum::<u64>(),
            dry.record_count,
            "I695: every tombstone is written by the retry: {report:?}"
        );
        assert_eq!(report.already_tombstoned, 0);
        let later = t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1);
        assert_eq!(
            status_at(dir, &report.notice_id, later)
                .await
                .unwrap()
                .state,
            sp::PurgeState::Settled
        );

        // The store door refuses a set that is not the header's whole count.
        let header = dir
            .purge_execution(&report.notice_id)
            .await
            .unwrap()
            .expect("held");
        let mut short = header.clone();
        short.notice_id = "ee".repeat(32);
        let e = dir
            .purge_put_execution(&short, &[])
            .await
            .expect_err("I695: a header without its set is refused");
        assert!(
            matches!(e, Error::InvalidArgument(_)),
            "I695: the store door's own refusal: {e:?}"
        );
        assert!(dir
            .purge_execution(&short.notice_id)
            .await
            .unwrap()
            .is_none());

        // Defence in depth: a partial set (the pre-fix state) is neither
        // finalized nor served.
        let tombs = dir.purge_tombstones_of(&report.notice_id).await.unwrap();
        let dropped = tombs.last().expect("a tombstone").clone();
        d.drop_tombstone(
            &report.notice_id,
            dropped.plane.as_str(),
            &dropped.record_ref,
        )
        .await;
        assert_eq!(
            status_at(dir, &report.notice_id, later)
                .await
                .unwrap()
                .state,
            sp::PurgeState::Incomplete
        );
        let e = finalize_at(dir, &report.notice_id, later, None)
            .await
            .expect_err("I695: a partial execution is not finalized");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::EXECUTION_INCOMPLETE, "I695 finalize: {body}");
        assert_eq!(body["record_count"], dry.record_count, "I695: {body}");
        assert_eq!(body["tombstones"], dry.record_count - 1, "I695: {body}");
        assert!(
            dir.get_attestation(&derived).await.unwrap().is_some(),
            "I695: nothing deleted"
        );
        let e = sp::list_purge_bundles_since(dir, None, 10)
            .await
            .expect_err("I695: a partial execution is not served");
        assert_eq!(refusal(&e).0, token::EXECUTION_INCOMPLETE, "I695 serve");

        // A re-run of the same notice completes it.
        let healed = rows_at(dir, &mock_selection(), &notice, NODE, t)
            .await
            .expect("I695: the re-run completes the set");
        assert_eq!(healed.tombstoned.values().sum::<u64>(), 1, "{healed:?}");
        assert_eq!(healed.already_tombstoned, dry.record_count - 1);
        let fin = finalize_at(dir, &report.notice_id, later, None)
            .await
            .expect("I695: the complete execution finalizes");
        assert_eq!(fin.attestations_deleted, 3, "{fin:?}");
        assert_eq!(
            sp::list_purge_bundles_since(dir, None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    // ── I696 ──────────────────────────────────────────────────────────────
    /// One trace at `ts` for agent `agent_hash`: two `trace_events` rows signed
    /// by `signer`, one LLM call, and its own trace attestation.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn seed_trace_at<D: Seams>(
        d: &D,
        trace_id: &str,
        signer: &str,
        agent_hash: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        seed_trace(d, trace_id, signer, "gpt-real").await;
        // Re-home the projection rows: the rollup groups by hour and agent.
        let rows: Vec<TraceEventRow> = (0..2)
            .map(|attempt| {
                let mut r = event_row(trace_id, signer, attempt);
                r.ts = ts;
                r.agent_id_hash = agent_hash.to_owned();
                r.thought_id = "th-at".to_owned();
                r
            })
            .collect();
        d.insert_trace_events_batch(&rows)
            .await
            .expect("trace rows");
    }

    /// The fleet read's `trace_count` per agent (the rollup fast path: more
    /// than one agent, no baseline, an unauthenticated caller).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn fleet_trace_counts<D: RollupSeams>(
        d: &D,
        agents: &[String],
        window: crate::read::TimeWindow,
    ) -> Vec<i64> {
        d.aggregate_scoring_factors_batch(
            agents,
            window,
            None,
            crate::scope::CallerScope::Unauthenticated,
        )
        .await
        .expect("fleet read")
        .into_iter()
        .map(|a| a.trace_count)
        .collect()
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i696_a_purged_trace_leaves_no_rollup<D: RollupSeams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        // Five hours back: older than the refresh's watermark tail (the
        // newest event, at `t`, sets the watermark; the tail is 1 h).
        let old = t - chrono::Duration::hours(5);
        let (x, y, z) = ("i696-agent-x", "i696-agent-y", "i696-agent-z");
        seed_trace_at(d, "trace-i696-a", AGENT, x, old).await;
        seed_trace_at(d, "trace-i696-b", AGENT, x, old).await;
        seed_trace_at(d, "trace-i696-c", AGENT, y, old).await;
        seed_trace_at(d, "trace-i696-d", AGENT, z, t).await;
        d.refresh_rollup().await;
        assert_eq!(d.rollup_trace_counts(x).await, vec![2], "I696: folded");
        assert_eq!(d.rollup_trace_counts(y).await, vec![1], "I696: folded");
        let window = crate::read::TimeWindow {
            since: t - chrono::Duration::days(1),
            until: t + chrono::Duration::hours(1),
        };
        let agents = [x.to_owned(), y.to_owned()];
        assert_eq!(
            fleet_trace_counts(d, &agents, window).await,
            vec![2, 1],
            "I696: the fleet read counts them"
        );

        let sel = PurgeSelection::ByIds {
            ids: vec![
                "trace:trace-i696-a".to_owned(),
                "trace:trace-i696-c".to_owned(),
            ],
        };
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let rep = rows_at(dir, &sel, &notice, NODE, t).await.unwrap();
        let fin = finalize_at(
            dir,
            &rep.notice_id,
            t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1),
            None,
        )
        .await
        .unwrap();
        assert_eq!(fin.trace_events_deleted, 8, "{fin:?}");

        // The rollup no longer counts the purged traces, with no refresh in
        // between (the lazy one would not revisit a 5 h old bucket anyway).
        assert_eq!(
            d.rollup_trace_counts(x).await,
            vec![1],
            "I696: the shared bucket keeps only the survivor"
        );
        assert_eq!(
            d.rollup_trace_counts(y).await,
            Vec::<i64>::new(),
            "I696: a bucket the purge emptied is gone"
        );
        d.refresh_rollup().await;
        assert_eq!(d.rollup_trace_counts(x).await, vec![1]);
        assert_eq!(d.rollup_trace_counts(y).await, Vec::<i64>::new());
        assert_eq!(
            fleet_trace_counts(d, &agents, window).await,
            vec![1, 0],
            "I696: the fleet read no longer counts a purged trace"
        );
        assert_eq!(d.rollup_trace_counts(z).await, vec![1], "I696: untouched");
    }

    // ── I697 ──────────────────────────────────────────────────────────────
    /// A federation-tier `scores` row at `id` on `dimension`, really signed.
    fn fed_row(id: &str, attester: &str, attested: &str, dimension: &str) -> Attestation {
        let env = serde_json::json!({
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
        });
        let mut row = ts::bare_attestation(id, attester, attested, &env);
        row.attestation_type = attestation_type::SCORES.to_owned();
        ts::reseal(&mut row);
        row
    }

    pub(crate) async fn i697_a_tombstone_never_reaches_the_accountability_record<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        let revocation = uuid::Uuid::new_v4().to_string();
        let track = uuid::Uuid::new_v4().to_string();
        let plain = uuid::Uuid::new_v4().to_string();
        // A bundle naming three ids this node does not hold yet.
        let mut ids: Vec<String> = [&revocation, &track, &plain]
            .iter()
            .map(|id| format!("attestation:{id}"))
            .collect();
        ids.sort();
        let template = serde_json::json!({
            "legal_basis": sp::STEWARD_PURGE_BASIS,
            "content_sha256": sp::selection_digest(&ids),
            "content_holder_key_ids": [],
        });
        let bundle = sp::PurgeBundle {
            notice: notice_for(&template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t),
            record_ids: ids.clone(),
            derived_from: vec![String::new(); ids.len()],
            admitted_at: t,
        };
        let applied = apply_at(dir, &bundle, NODE, t)
            .await
            .expect("I697: a bundle may name rows this node does not hold yet");
        assert_eq!(applied.tombstoned, 3);

        // The named rows ARRIVE: the accountability record is admitted.
        for (id, attester, attested, dimension) in [
            (&revocation, AGENT, AGENT, "key:revocation:v1"),
            (
                &track,
                HARNESS,
                BYSTANDER,
                "moderation_track_record:ciris-canonical:v1",
            ),
        ] {
            dir.put_attestation(SignedAttestation {
                attestation: fed_row(id, attester, attested, dimension),
            })
            .await
            .unwrap_or_else(|e| {
                panic!("I697: a {dimension} row is admitted over a tombstone: {e:?}")
            });
        }
        // An ordinary row at a tombstoned id is still refused.
        let e = dir
            .put_attestation(SignedAttestation {
                attestation: fed_row(&plain, SCORER, AGENT, "chat:message:v1"),
            })
            .await
            .expect_err("I697: an ordinary tombstoned row is refused");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::TOMBSTONED, "I697: {body}");

        let served = served_ids(d).await;
        for id in [&revocation, &track] {
            assert!(served.contains(id), "I697: {id} is served");
        }
        assert!(!served.contains(&plain));
        let notice_id = applied.notice_id;
        let later = t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1);
        let mut voided = vec![
            format!("attestation:{revocation}"),
            format!("attestation:{track}"),
        ];
        voided.sort();
        let mut st = status_at(dir, &notice_id, later).await.unwrap();
        st.voided.sort();
        assert_eq!(
            st.voided, voided,
            "I697: the ledger names the void tombstones"
        );

        // The delete door itself never deletes them, and neither does finalize.
        assert!(!dir
            .purge_delete_tombstoned_attestation(&revocation)
            .await
            .unwrap());
        let mut fin = finalize_at(dir, &notice_id, later, None)
            .await
            .expect("finalizes");
        fin.voided.sort();
        assert_eq!(fin.voided, voided, "I697: {fin:?}");
        assert_eq!(fin.attestations_deleted, 0, "I697: {fin:?}");
        for id in [&revocation, &track] {
            assert!(
                dir.get_attestation(id).await.unwrap().is_some(),
                "I697: {id} survives finalize"
            );
        }
        let served = served_ids(d).await;
        for id in [&revocation, &track] {
            assert!(served.contains(id), "I697: {id} is served after finalize");
        }
    }

    // ── I698 ──────────────────────────────────────────────────────────────
    /// A federation-tier `trace:complete:v1` row in the MANIFEST form, by
    /// AGENT about itself, really signed; `run_kind` in the manifest when given.
    fn manifest_row(id: &str, trace_id: &str, run_kind: Option<&str>) -> Attestation {
        let mut manifest = serde_json::json!({
            "schema": "trace_manifest:v1",
            "content_hash": format!("sha256:{}", "ab".repeat(32)),
            "byte_len": 2_000_000,
            "component_count": 3,
        });
        if let Some(k) = run_kind {
            manifest["run_kind"] = serde_json::json!(k);
        }
        let env = serde_json::json!({
            "dimension": crate::ingest::TRACE_ATTESTATION_DIMENSION,
            "trace_id": trace_id,
            "agent_id_hash": "deadbeef",
            "manifest": manifest,
        });
        let mut row = ts::bare_attestation(id, AGENT, AGENT, &env);
        row.attestation_type = attestation_type::SCORES.to_owned();
        // A trace is self-emitted: its producer is among its subjects.
        row.subject_key_ids = vec![AGENT.to_owned()];
        ts::reseal(&mut row);
        row
    }

    pub(crate) async fn i698_run_kind_survives_the_manifest_form<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        // An oversize mock trace, kept by a node that is not the canonical.
        let tid = "trace-i698-big";
        let mut trace = trace_json(tid, AGENT, "gpt-real", Some(sp::RUN_KIND_MOCK));
        trace["components"][0]["data"]["padding"] = serde_json::json!(
            "x".repeat(crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES + 1024)
        );
        ingest(d, &batch(&trace))
            .await
            .expect("I698: a non-canonical node keeps its QA trace");
        let local = dir
            .get_attestation(&crate::ingest::trace_attestation_id(tid))
            .await
            .unwrap()
            .expect("I698: the trace's own attestation");
        let env = &local.attestation_envelope;
        assert!(env.get("trace").is_none(), "I698: the oversize form: {env}");
        assert_eq!(
            env["manifest"]["run_kind"],
            sp::RUN_KIND_MOCK,
            "I698: the manifest carries the signed run_kind: {env}"
        );
        // The tier crossing mints a federation-tier row: refused.
        let mut crossing = local.clone();
        crossing.tier = crate::federation::types::attestation_tier::FEDERATION.to_owned();
        let e = crate::federation::admission::check_promotion_admission(dir, &crossing, None)
            .await
            .expect_err("I698: a manifest-form mock trace cannot cross");
        assert_eq!(e.kind(), sp::TRACE_RUN_KIND_MOCK, "I698 promotion: {e}");
        // A federation-tier put of the manifest form.
        let e = dir
            .put_attestation(SignedAttestation {
                attestation: manifest_row(
                    &uuid::Uuid::new_v4().to_string(),
                    "trace-i698-mock",
                    Some(sp::RUN_KIND_MOCK),
                ),
            })
            .await
            .expect_err("I698: a manifest-form mock trace is refused at the put");
        assert_eq!(e.kind(), sp::TRACE_RUN_KIND_MOCK, "I698 put: {e}");
        for kind in ["production", "qa"] {
            dir.put_attestation(SignedAttestation {
                attestation: manifest_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &format!("trace-i698-{kind}"),
                    Some(kind),
                ),
            })
            .await
            .unwrap_or_else(|e| panic!("I698: a {kind} manifest row is admitted: {e:?}"));
        }
        // The legacy manifest (no run_kind) is admitted and stored as signed.
        let legacy_id = uuid::Uuid::new_v4().to_string();
        let legacy = manifest_row(&legacy_id, "trace-i698-legacy", None);
        dir.put_attestation(SignedAttestation {
            attestation: legacy.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("I698: a legacy manifest row is admitted: {e:?}"));
        let stored = dir.get_attestation(&legacy_id).await.unwrap().unwrap();
        let jcs = |v: &serde_json::Value| ciris_verify_core::jcs::canonicalize(v).expect("jcs");
        assert_eq!(
            jcs(&stored.attestation_envelope),
            jcs(&legacy.attestation_envelope),
            "I698: the legacy manifest row's signed bytes are stored unchanged"
        );
        assert!(stored.attestation_envelope["manifest"]
            .get("run_kind")
            .is_none());
        // Outside the vocabulary, in either shape.
        let bad = manifest_row(
            &uuid::Uuid::new_v4().to_string(),
            "trace-i698-bad",
            Some("simulation"),
        );
        let e = dir
            .put_attestation(SignedAttestation { attestation: bad })
            .await
            .expect_err("I698: an unknown manifest run_kind is refused");
        assert_eq!(e.kind(), "federation_trace_dimension_invalid", "I698: {e}");
        let mut inline = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            AGENT,
            AGENT,
            &serde_json::json!({
                "dimension": crate::ingest::TRACE_ATTESTATION_DIMENSION,
                "trace_id": "trace-i698-inline",
                "agent_id_hash": "deadbeef",
                "trace": {"trace_id": "trace-i698-inline", "run_kind": 7},
            }),
        );
        inline.attestation_type = attestation_type::SCORES.to_owned();
        inline.subject_key_ids = vec![AGENT.to_owned()];
        ts::reseal(&mut inline);
        let e = dir
            .put_attestation(SignedAttestation {
                attestation: inline,
            })
            .await
            .expect_err("I698: a non-string inline run_kind is refused");
        assert_eq!(e.kind(), "federation_trace_dimension_invalid", "I698: {e}");
    }

    // ── I820 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i820_derivatives_leave_with_a_withheld_parent<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        // A refused-today accountability row (inadmissible) and a refused-
        // today plain row (admissible).
        let parent = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: fed_row(
                &parent,
                HARNESS,
                BYSTANDER,
                "moderation_track_record:ciris-canonical:v1",
            ),
        })
        .await
        .expect("the accountability row admits");
        let plain = put_score(d, BYSTANDER, AGENT, &[]).await.attestation_id;
        for id in [&parent, &plain] {
            let row = dir.get_attestation(id).await.unwrap().unwrap();
            d.shift_asserted_at(id, row.asserted_at + chrono::Duration::seconds(1))
                .await;
            let row = dir.get_attestation(id).await.unwrap().unwrap();
            assert!(sp::refused_today(&row).is_some(), "precondition: {id}");
        }
        // A chain off each: score over the row, score over that score.
        let s1 = put_score(d, SCORER, AGENT, &[&parent]).await.attestation_id;
        let s2 = put_score(d, SCORER, AGENT, &[&s1]).await.attestation_id;
        let p1 = put_score(d, SCORER, AGENT, &[&plain]).await.attestation_id;
        let p2 = put_score(d, SCORER, AGENT, &[&p1]).await.attestation_id;

        let sel = PurgeSelection::RefusedToday;
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let mut expect: Vec<String> = [&plain, &p1, &p2]
            .iter()
            .map(|id| format!("attestation:{id}"))
            .collect();
        expect.sort();
        assert_eq!(
            dry.sample, expect,
            "I820: the chain off the withheld row leaves with it; withheld {:?}",
            dry.withheld
        );
        let mut withheld: Vec<String> = dry.withheld.iter().map(|w| w.record_id.clone()).collect();
        withheld.sort();
        let mut expect_withheld: Vec<String> = [&parent, &s1, &s2]
            .iter()
            .map(|id| format!("attestation:{id}"))
            .collect();
        expect_withheld.sort();
        assert_eq!(withheld, expect_withheld, "I820: {:?}", dry.withheld);
        assert_eq!(dry.record_count, 3);
        assert_eq!(
            dry.selection_digest,
            sp::selection_digest(&expect),
            "I820: the digest is the reduced set's"
        );
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let rep = rows_at(dir, &sel, &notice, NODE, t)
            .await
            .expect("I820: the reduced selection executes");
        assert_eq!(rep.record_count, 3);
        let served = served_ids(d).await;
        for id in [&parent, &s1, &s2] {
            assert!(served.contains(id), "I820: withheld {id} is still served");
        }
    }

    // ── I821 ──────────────────────────────────────────────────────────────
    /// A quorum-cosigned bundle over `ids` (sorted here), with `derived_from`
    /// as given per id.
    fn bundle_over(
        mut pairs: Vec<(String, String)>,
        t: chrono::DateTime<chrono::Utc>,
    ) -> sp::PurgeBundle {
        pairs.sort();
        let ids: Vec<String> = pairs.iter().map(|(id, _)| id.clone()).collect();
        let template = serde_json::json!({
            "legal_basis": sp::STEWARD_PURGE_BASIS,
            "content_sha256": sp::selection_digest(&ids),
            "content_holder_key_ids": [],
        });
        sp::PurgeBundle {
            notice: notice_for(&template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t),
            record_ids: ids,
            derived_from: pairs.into_iter().map(|(_, d)| d).collect(),
            admitted_at: t,
        }
    }

    pub(crate) async fn i821_a_blobs_subject_is_resolved_locally<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        const ALICE: &str = "alice-human-i821";
        ts::register_hybrid_key_as(
            dir,
            ALICE,
            ALICE,
            crate::federation::types::identity_type::USER,
        )
        .await;
        let (personal, unbound, plain) = ("a1".repeat(32), "b2".repeat(32), "c3".repeat(32));
        // Alice's blob: a row about her binds it. A harmless row elsewhere.
        put_score(d, SCORER, ALICE, &[&personal]).await;
        put_score(d, SCORER, AGENT, &[&plain]).await;
        let harmless = put_score(d, SCORER, AGENT, &[]).await.attestation_id;

        // The peer points Alice's blob at the harmless row.
        let forged = bundle_over(
            vec![
                (format!("attestation:{harmless}"), String::new()),
                (
                    format!("blob:{personal}"),
                    format!("attestation:{harmless}"),
                ),
            ],
            t,
        );
        let e = apply_at(dir, &forged, NODE, t)
            .await
            .expect_err("I821: the bundle's provenance is not trusted");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::HUMAN_SUBJECT_PENDING_NOTICE_ROW, "I821: {body}");
        let named: Vec<(&str, &str)> = body["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["record_id"].as_str().unwrap(),
                    r["subject"].as_str().unwrap(),
                )
            })
            .collect();
        let blob_id = format!("blob:{personal}");
        assert!(
            named.contains(&(blob_id.as_str(), ALICE)),
            "I821: names Alice's blob and Alice: {body}"
        );
        assert_nothing_written(d, &forged.notice).await;

        // A person's device holds bytes: its holding claim (v55.0.0:
        // `custody:ack:v1` `here`; the holder attests itself) is a local
        // holding row too.
        const BOB: &str = "bob-human-holder-i821";
        ts::register_hybrid_key_as(dir, BOB, BOB, crate::federation::types::identity_type::USER)
            .await;
        let held = [0xd4u8; 32];
        let mut claim = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            BOB,
            BOB,
            &serde_json::json!({
                "dimension": crate::federation::custody_ack::CUSTODY_ACK_DIMENSION,
                "custody_state": "here",
                "evidence_refs": [hex::encode(held)],
                "size": 12,
                "score": 1.0,
                "confidence": 1.0,
            }),
        );
        claim.attestation_type = "scores".into();
        claim.weight = None;
        ts::reseal(&mut claim);
        dir.put_attestation(SignedAttestation { attestation: claim })
            .await
            .expect("the holder claim admits");
        let device = bundle_over(
            vec![(
                format!("blob:{}", hex::encode(held)),
                format!("attestation:{harmless}"),
            )],
            t,
        );
        let (tok, body) = refusal(
            &apply_at(dir, &device, NODE, t)
                .await
                .expect_err("I821: a person's holding claim is read locally"),
        );
        assert_eq!(tok, token::HUMAN_SUBJECT_PENDING_NOTICE_ROW, "I821: {body}");
        assert!(body.to_string().contains(BOB), "I821 holder: {body}");

        // A blob nothing here holds or binds: not proven non-human.
        let blind = bundle_over(vec![(format!("blob:{unbound}"), String::new())], t);
        let (tok, body) = refusal(
            &apply_at(dir, &blind, NODE, t)
                .await
                .expect_err("I821: an unknown holding fails closed"),
        );
        assert_eq!(tok, token::HUMAN_SUBJECT_PENDING_NOTICE_ROW, "I821: {body}");
        assert_nothing_written(d, &blind.notice).await;

        // A blob bound only by a row about a non-person applies.
        let fine = bundle_over(vec![(format!("blob:{plain}"), String::new())], t);
        apply_at(dir, &fine, NODE, t)
            .await
            .expect("I821: a non-person's blob applies");

        // The local door reads the same local state.
        let sel = PurgeSelection::ByIds {
            ids: vec![format!("blob:{personal}")],
        };
        let (tok, body) = refusal(
            &sp::purge_dry_run(dir, &sel)
                .await
                .expect_err("I821: the local dry run refuses Alice's blob"),
        );
        assert_eq!(tok, token::HUMAN_SUBJECT_PENDING_NOTICE_ROW, "I821: {body}");
        assert!(body.to_string().contains(ALICE), "I821 local: {body}");
    }

    // ── I822 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i822_the_dwell_is_this_nodes_clock<D: Seams>(d: &D) {
        root(d).await;
        mock_world(d, "i822").await;
        let dir = d.as_dyn_directory();
        let t = now();
        let dry = sp::purge_dry_run(dir, &mock_selection()).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        // The system clock: no seam, no argument.
        sp::test_clock::set(None);
        let before = chrono::Utc::now();
        let rep = sp::purge_rows(dir, &mock_selection(), &notice, NODE)
            .await
            .expect("executes");
        let after = chrono::Utc::now();
        assert!(
            rep.executed_at >= before && rep.executed_at <= after,
            "I822: executed_at is this node's clock: {} not in [{before}, {after}]",
            rep.executed_at
        );
        let e = sp::purge_finalize(dir, &rep.notice_id, None)
            .await
            .expect_err("I822: finalize right after execute is refused");
        let (tok, body) = refusal(&e);
        assert_eq!(tok, token::NOT_SETTLED, "I822: {body}");
        let st = sp::purge_status(dir, &rep.notice_id).await.unwrap();
        assert_eq!(st.state, sp::PurgeState::Executed, "I822");
        assert_eq!(
            st.settles_at,
            rep.executed_at + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS),
            "I822: the settle is 72 h after this node's execution"
        );
    }

    // ── I825 / I826 ───────────────────────────────────────────────────────
    /// Execute and finalize a by-ids purge of one trace.
    async fn purge_trace<D: Seams>(d: &D, trace_id: &str) {
        let dir = d.as_dyn_directory();
        let t = now();
        let sel = PurgeSelection::ByIds {
            ids: vec![format!("trace:{trace_id}")],
        };
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        let rep = rows_at(dir, &sel, &notice, NODE, t).await.unwrap();
        finalize_at(
            dir,
            &rep.notice_id,
            t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1),
            None,
        )
        .await
        .unwrap();
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn detection(trace_id: &str, canonical: &[u8]) -> crate::derived::DetectionEvent {
        crate::derived::DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: trace_id.to_owned(),
            body_sha256: vec![7u8; 32],
            detector: "manifold_conformity_outlier".to_owned(),
            severity: crate::derived::DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({"deployment_domain": "legal"}),
            conformity_variant: crate::derived::ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 3.1}),
            lens_core_version: "lc-1.0.0".to_owned(),
            ratchet_calibration_version: 4,
            canonical_bytes: canonical.to_vec(),
            ed25519_sig: vec![1u8; 64],
            ml_dsa_65_sig: vec![2u8; 3309],
            signing_key_id: "key-lens".to_owned(),
            ts: chrono::Utc::now(),
        }
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i825_a_purged_traces_detections_are_tombstoned<
        D: Seams + crate::derived::DerivedSchema,
    >(
        d: &D,
    ) {
        root(d).await;
        seed_trace(d, "trace-i825", AGENT, "gpt-real").await;
        seed_trace(d, "trace-i825-other", BYSTANDER, "gpt-real").await;
        d.put_detection_event(detection("trace-i825", b"purged-body"))
            .await
            .unwrap();
        d.put_detection_event(detection("trace-i825-other", b"kept-body"))
            .await
            .unwrap();
        purge_trace(d, "trace-i825").await;
        let all = d
            .get_detection_events(crate::derived::EventFilter {
                trace_id: None,
                detector: None,
                since: None,
            })
            .await
            .expect("I825: the detection read still decodes every row");
        assert!(
            all.iter()
                .all(|e| e.trace_id != "trace-i825" && e.canonical_bytes != b"purged-body"),
            "I825: no event names the purged trace or returns its content: {:?}",
            all.iter()
                .map(|e| (&e.trace_id, String::from_utf8_lossy(&e.canonical_bytes)))
                .collect::<Vec<_>>()
        );
        let kept = d
            .get_detection_events(crate::derived::EventFilter {
                trace_id: Some("trace-i825-other".to_owned()),
                detector: None,
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(kept.len(), 1, "I825: the unrelated event is untouched");
        assert_eq!(kept[0].canonical_bytes, b"kept-body");
        // The round-4 sweep: a detection ARRIVING after the purge cannot
        // re-attach the purged trace's linkage and content.
        let e = d
            .put_detection_event(detection("trace-i825", b"late-body"))
            .await
            .expect_err("I825: a detection naming a purged trace is refused");
        assert!(
            matches!(&e, crate::derived::Error::InvalidArgument(m) if m.starts_with(token::TOMBSTONED)),
            "I825: {e:?}"
        );
        assert!(d
            .get_detection_events(crate::derived::EventFilter {
                trace_id: Some("trace-i825".to_owned()),
                detector: None,
                since: None,
            })
            .await
            .unwrap()
            .is_empty());
    }

    pub(crate) async fn i826_a_reused_thought_reads_its_own_signature<D: Seams>(d: &D) {
        root(d).await;
        let signed = |trace: &str, attempt: u32, sig: &str| {
            let mut r = event_row(trace, AGENT, attempt);
            r.thought_id = "th-i826".to_owned();
            r.agent_id_hash = "agent-i826".to_owned();
            r.pqc_key_id = Some(AGENT.to_owned());
            r.signature_ml_dsa_65 = Some(sig.to_owned());
            r
        };
        let sig_of = |rows: &[(i64, TraceEventRow)], trace: &str| -> Vec<Option<String>> {
            rows.iter()
                .filter(|(_, r)| r.trace_id == trace)
                .map(|(_, r)| r.signature_ml_dsa_65.clone())
                .collect()
        };
        seed_trace(d, "trace-i826-old", AGENT, "gpt-real").await;
        d.insert_trace_events_batch(&[signed("trace-i826-old", 0, "sig-old")])
            .await
            .unwrap();
        // A thought another live trace shares keeps its row.
        seed_trace(d, "trace-i826-live", AGENT, "gpt-real").await;
        let mut shared = event_row("trace-i826-live", AGENT, 5);
        shared.thought_id = "th-i826-shared".to_owned();
        shared.agent_id_hash = "agent-i826".to_owned();
        shared.pqc_key_id = Some(AGENT.to_owned());
        shared.signature_ml_dsa_65 = Some("sig-shared".to_owned());
        let mut shared_purged = shared.clone();
        shared_purged.trace_id = "trace-i826-old".to_owned();
        shared_purged.attempt_index = 6;
        d.insert_trace_events_batch(&[shared, shared_purged])
            .await
            .unwrap();

        purge_trace(d, "trace-i826-old").await;
        d.insert_trace_events_batch(&[signed("trace-i826-new", 0, "sig-new")])
            .await
            .unwrap();
        let rows = d
            .fetch_trace_events_page(0, 1_000, Some("agent-i826"))
            .await
            .unwrap();
        assert_eq!(
            sig_of(&rows, "trace-i826-new"),
            vec![Some("sig-new".to_owned())],
            "I826: the reused thought reads its own signature"
        );
        assert!(sig_of(&rows, "trace-i826-old").is_empty(), "I826: purged");
        let live: Vec<Option<String>> = rows
            .iter()
            .filter(|(_, r)| r.thought_id == "th-i826-shared")
            .map(|(_, r)| r.signature_ml_dsa_65.clone())
            .collect();
        assert_eq!(
            live,
            vec![Some("sig-shared".to_owned())],
            "I826: a thought a live trace shares keeps its signature"
        );
    }

    // ── I828 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i828_a_person_subject_arrival_voids_the_tombstone<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        const ALICE: &str = "alice-human-i828";
        ts::register_hybrid_key_as(
            dir,
            ALICE,
            ALICE,
            crate::federation::types::identity_type::USER,
        )
        .await;
        let about_alice = uuid::Uuid::new_v4().to_string();
        let ordinary = uuid::Uuid::new_v4().to_string();
        let unknown = uuid::Uuid::new_v4().to_string();
        let trace_id = "trace-i828-alice";
        let mut ids: Vec<String> = [&about_alice, &ordinary, &unknown]
            .iter()
            .map(|id| format!("attestation:{id}"))
            .collect();
        ids.push(format!("trace:{trace_id}"));
        ids.sort();
        let template = serde_json::json!({
            "legal_basis": sp::STEWARD_PURGE_BASIS,
            "content_sha256": sp::selection_digest(&ids),
            "content_holder_key_ids": [],
        });
        let bundle = sp::PurgeBundle {
            notice: notice_for(&template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t),
            record_ids: ids.clone(),
            derived_from: vec![String::new(); ids.len()],
            admitted_at: t,
        };
        let applied = apply_at(dir, &bundle, NODE, t)
            .await
            .expect("I828: a bundle may name rows this node does not hold yet");
        assert_eq!(applied.tombstoned, 4);

        // A row about a person arrives at a tombstoned id: admitted.
        dir.put_attestation(SignedAttestation {
            attestation: fed_row(&about_alice, SCORER, ALICE, "chat:message:v1"),
        })
        .await
        .unwrap_or_else(|e| panic!("I828: a row about a person is admitted: {e:?}"));
        // An ordinary row stays refused; one whose subject key does not
        // resolve here is refused RETRYABLY (I832 walks the key landing).
        let e = dir
            .put_attestation(SignedAttestation {
                attestation: fed_row(&ordinary, SCORER, AGENT, "chat:message:v1"),
            })
            .await
            .expect_err("I828: a non-person row at a tombstoned id is refused");
        assert_eq!(refusal(&e).0, token::TOMBSTONED, "I828: {e:?}");
        let e = dir
            .put_attestation(SignedAttestation {
                attestation: fed_row(&unknown, SCORER, "nobody-knows-me-i828", "chat:message:v1"),
            })
            .await
            .expect_err("I828: an unresolved subject is not admitted");
        assert_eq!(e.kind(), "federation_attester_key_unknown", "I828: {e:?}");
        // A trace a person signed arrives at the tombstoned trace id.
        ingest(d, &batch(&trace_json(trace_id, ALICE, "gpt-real", None)))
            .await
            .expect("I828: a trace a person signed is ingested over the tombstone");

        assert!(
            served_ids(d).await.contains(&about_alice),
            "I828: the person's row is served"
        );
        let later = t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1);
        let mut st = status_at(dir, &applied.notice_id, later).await.unwrap();
        st.voided.sort();
        let mut want = vec![
            format!("attestation:{about_alice}"),
            format!("trace:{trace_id}"),
        ];
        want.sort();
        assert_eq!(
            st.voided, want,
            "I828: the ledger names the void tombstones"
        );
        assert!(!dir
            .purge_delete_tombstoned_attestation(&about_alice)
            .await
            .unwrap());
        assert_eq!(
            dir.purge_delete_tombstoned_trace(trace_id).await.unwrap(),
            (0, 0),
            "I828: the trace delete door leaves a person's trace"
        );
        let mut fin = finalize_at(dir, &applied.notice_id, later, None)
            .await
            .expect("finalizes");
        fin.voided.sort();
        assert_eq!(fin.voided, want, "I828: {fin:?}");
        assert!(dir.get_attestation(&about_alice).await.unwrap().is_some());
        assert!(
            dir.purge_trace_row_counts(&[trace_id.to_owned()])
                .await
                .unwrap()
                .0
                > 0,
            "I828: the person's trace survives finalize"
        );
        assert!(served_ids(d).await.contains(&about_alice));
    }

    /// **I832** — the subject's key arrives AFTER the row.
    pub(crate) async fn i832_an_unresolved_subject_is_retryable<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let t = now();
        const BOB: &str = "bob-late-key-i832";
        const CAROL: &str = "carol-late-agent-i832";
        let (about_bob, about_carol) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        let trace_id = "trace-i832-bob";
        let mut ids: Vec<String> = [&about_bob, &about_carol]
            .iter()
            .map(|id| format!("attestation:{id}"))
            .collect();
        ids.push(format!("trace:{trace_id}"));
        ids.sort();
        let template = serde_json::json!({
            "legal_basis": sp::STEWARD_PURGE_BASIS,
            "content_sha256": sp::selection_digest(&ids),
            "content_holder_key_ids": [],
        });
        let bundle = sp::PurgeBundle {
            notice: notice_for(&template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t),
            record_ids: ids.clone(),
            derived_from: vec![String::new(); ids.len()],
            admitted_at: t,
        };
        let applied = apply_at(dir, &bundle, NODE, t).await.unwrap();
        let offer = |id: &str, subject: &str| {
            dir.put_attestation(SignedAttestation {
                attestation: fed_row(id, SCORER, subject, "chat:message:v1"),
            })
        };
        // Row first, key later: retryable, nothing stored.
        for (id, subject) in [(&about_bob, BOB), (&about_carol, CAROL)] {
            let e = offer(id, subject)
                .await
                .expect_err("I832: an unresolved subject is not admitted");
            assert_eq!(
                e.kind(),
                "federation_attester_key_unknown",
                "I832 {subject}: {e:?}"
            );
            assert!(
                matches!(&e, Error::AttesterKeyUnknown { attesting_key_id, plane }
                    if attesting_key_id == subject && *plane == sp::PURGE_TOMBSTONE_SUBJECT_PLANE),
                "I832: names the subject and the plane: {e:?}"
            );
            assert!(dir.get_attestation(id).await.unwrap().is_none());
        }
        let e = ingest(d, &batch(&trace_json(trace_id, BOB, "gpt-real", None)))
            .await
            .expect_err("I832: a trace whose signer is not held yet is not admitted");
        assert_eq!(e.kind(), "verify_unknown_key", "I832 trace: {e}");
        // The keys land.
        ts::register_hybrid_key_as(dir, BOB, BOB, crate::federation::types::identity_type::USER)
            .await;
        ts::register_hybrid_key_as(
            dir,
            CAROL,
            CAROL,
            crate::federation::types::identity_type::AGENT,
        )
        .await;
        offer(&about_bob, BOB)
            .await
            .expect("I832: once the key lands as a person, the re-offer is admitted");
        let e = offer(&about_carol, CAROL)
            .await
            .expect_err("I832: once the key lands as a non-person, the tombstone stands");
        assert_eq!(refusal(&e).0, token::TOMBSTONED, "I832: {e:?}");
        ingest(d, &batch(&trace_json(trace_id, BOB, "gpt-real", None)))
            .await
            .expect("I832: the person's trace is admitted once the key lands");
        let later = t + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS + 1);
        let mut st = status_at(dir, &applied.notice_id, later).await.unwrap();
        st.voided.sort();
        let mut want = vec![
            format!("attestation:{about_bob}"),
            format!("trace:{trace_id}"),
        ];
        want.sort();
        assert_eq!(st.voided, want, "I832: voided once admitted");
    }

    /// **I828b** — the serve-by-hash reload withholds a tombstoned row during
    /// the dwell, exactly as the cursor serve does (the round-4 sweep).
    pub(crate) async fn i828b_serve_by_hash_withholds_during_the_dwell<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let row = put_score(d, SCORER, AGENT, &[]).await;
        let hash = crate::federation::wire_index::content_hash_of(&row).unwrap();
        let rk =
            crate::federation::wire_index::record_key(&[("attestation_id", &row.attestation_id)]);
        assert!(
            crate::federation::wire_index::reload_record_bytes(dir, "Attestation", &rk)
                .await
                .unwrap()
                .is_some(),
            "I828b control: reloads while live"
        );
        assert!(
            dir.list_wire_hashes_since("Attestation", None, 10_000)
                .await
                .unwrap()
                .contains(&hash),
            "I828b control: advertised"
        );
        let t = now();
        let sel = PurgeSelection::ByIds {
            ids: vec![format!("attestation:{}", row.attestation_id)],
        };
        let dry = sp::purge_dry_run(dir, &sel).await.unwrap();
        let notice = notice_for(&dry.notice_template, &[cc::FOUNDERS[0], cc::FOUNDERS[1]], t);
        rows_at(dir, &sel, &notice, NODE, t).await.unwrap();
        assert!(
            crate::federation::wire_index::reload_record_bytes(dir, "Attestation", &rk)
                .await
                .unwrap()
                .is_none(),
            "I828b: a tombstoned row is not served by hash during the dwell"
        );
        assert!(
            dir.lookup_signed_record_by_content_hash("Attestation", &hash)
                .await
                .unwrap()
                .is_none(),
            "I828b: nor through the content-hash door"
        );
        assert!(
            !dir.list_wire_hashes_since("Attestation", None, 10_000)
                .await
                .unwrap()
                .contains(&hash),
            "I828b: nor advertised"
        );
    }

    /// **I831** (Codex round 4 sweep on PR #1057) — the DSAR erasure
    /// (`delete_traces_for_agent_id_hash`) removes the orphaned thought
    /// signature too (one helper with the purge): a later trace reusing the
    /// thought_id reads its own signature.
    pub(crate) async fn i831_dsar_erasure_drops_orphaned_signatures<D: Seams>(d: &D) {
        let signed = |trace: &str, agent: &str, sig: &str| {
            let mut r = event_row(trace, AGENT, 0);
            r.thought_id = "th-i831".to_owned();
            r.agent_id_hash = agent.to_owned();
            r.pqc_key_id = Some(AGENT.to_owned());
            r.signature_ml_dsa_65 = Some(sig.to_owned());
            r
        };
        d.insert_trace_events_batch(&[signed("trace-i831-old", "agent-i831-erased", "sig-old")])
            .await
            .unwrap();
        d.delete_traces_for_agent_id_hash("agent-i831-erased")
            .await
            .unwrap();
        d.insert_trace_events_batch(&[signed("trace-i831-new", "agent-i831-new", "sig-new")])
            .await
            .unwrap();
        let rows = d
            .fetch_trace_events_page(0, 1_000, Some("agent-i831-new"))
            .await
            .unwrap();
        let sigs: Vec<Option<String>> = rows
            .iter()
            .map(|(_, r)| r.signature_ml_dsa_65.clone())
            .collect();
        assert_eq!(
            sigs,
            vec![Some("sig-new".to_owned())],
            "I831: after a DSAR erasure the reused thought reads its own signature"
        );
    }

    // ── I660 ──────────────────────────────────────────────────────────────
    pub(crate) async fn i660_the_delete_doors_re_ask_the_tombstone<D: Seams>(d: &D) {
        root(d).await;
        let dir = d.as_dyn_directory();
        let row = put_score(d, SCORER, AGENT, &[]).await;
        let tatt = seed_trace(d, "trace-i660", AGENT, "gpt-real").await;
        assert!(!dir
            .purge_delete_tombstoned_attestation(&row.attestation_id)
            .await
            .unwrap());
        assert!(!dir
            .purge_delete_tombstoned_attestation(&tatt)
            .await
            .unwrap());
        assert_eq!(
            dir.purge_delete_tombstoned_trace("trace-i660")
                .await
                .unwrap(),
            (0, 0)
        );
        assert!(dir
            .get_attestation(&row.attestation_id)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            dir.purge_trace_row_counts(&["trace-i660".to_owned()])
                .await
                .unwrap(),
            (2, 1)
        );
        assert!(dir.lookup_public_key(BYSTANDER).await.unwrap().is_some());
        // The plane gates the attestation and trace refusal at the door too.
        assert!(
            sp::refuse_if_tombstoned(dir, PurgePlane::Trace, "trace-i660")
                .await
                .is_ok()
        );
    }
}

#[cfg(test)]
mod run {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies as b;
                #[tokio::test]
                async fn i650() {
                    let Some(d) = $fresh.await else { return };
                    b::i650_authorisation_is_the_roots_own_protocol(&d).await
                }
                #[tokio::test]
                async fn i651() {
                    let Some(d) = $fresh.await else { return };
                    b::i651_a_digest_naming_other_ids_is_refused(&d).await
                }
                #[tokio::test]
                async fn i652() {
                    let Some(d) = $fresh.await else { return };
                    b::i652_a_grown_selection_is_a_count_mismatch(&d).await
                }
                #[tokio::test]
                async fn i653() {
                    let Some(d) = $fresh.await else { return };
                    b::i653_an_inadmissible_retraction_stops_the_door(&d).await
                }
                #[tokio::test]
                async fn i654() {
                    let Some(d) = $fresh.await else { return };
                    b::i654_the_mock_class_end_to_end(&d).await
                }
                #[tokio::test]
                async fn i655() {
                    let Some(d) = $fresh.await else { return };
                    b::i655_finalize_after_settle_and_the_tombstone_outlives(&d).await
                }
                #[tokio::test]
                async fn i656() {
                    let (Some(a), Some(c), Some(e)) = ($fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    b::i656_the_tombstone_replicates_re_verified(&a, &c, &e).await
                }
                #[tokio::test]
                async fn i833() {
                    let (Some(a), Some(c)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    b::i833_unauthorised_reason_splits_the_gap_from_the_verdict(&a, &c).await
                }
                #[tokio::test]
                async fn i670() {
                    let Some(d) = $fresh.await else { return };
                    b::i670_run_kind_is_a_signed_member(&d).await
                }
                #[tokio::test]
                async fn i672() {
                    let Some(d) = $fresh.await else { return };
                    b::i672_no_human_subject_until_the_notice_is_a_row(&d).await
                }
                #[tokio::test]
                async fn i669() {
                    let Some(d) = $fresh.await else { return };
                    b::i669_a_run_kind_trace_format_is_refused_whole(&d).await
                }
                #[tokio::test]
                async fn i668() {
                    let Some(d) = $fresh.await else { return };
                    b::i668_the_receiver_re_asks_admissibility(&d).await
                }
                #[tokio::test]
                async fn i667() {
                    let Some(d) = $fresh.await else { return };
                    b::i667_the_accountability_record_is_unpurgeable(&d).await
                }
                #[tokio::test]
                async fn i694() {
                    let Some(d) = $fresh.await else { return };
                    b::i694_the_reset_door_refuses_the_accountability_record(&d).await
                }
                #[tokio::test]
                async fn i665() {
                    let Some(d) = $fresh.await else { return };
                    b::i665_a_purge_never_touches_a_key(&d).await
                }
                #[tokio::test]
                async fn i666() {
                    let Some(d) = $fresh.await else { return };
                    b::i666_a_key_id_is_not_a_purge_record(&d).await
                }
                #[tokio::test]
                async fn i659() {
                    let (Some(a), Some(c)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    b::i659_mock_traces_are_refused_at_the_federation_doors(&a, &c).await
                }
                #[tokio::test]
                async fn i660() {
                    let Some(d) = $fresh.await else { return };
                    b::i660_the_delete_doors_re_ask_the_tombstone(&d).await
                }
                #[tokio::test]
                async fn i662() {
                    let Some(d) = $fresh.await else { return };
                    b::i662_refused_today_is_a_selection_not_a_filter(&d).await
                }
                #[tokio::test]
                async fn i695() {
                    let Some(d) = $fresh.await else { return };
                    b::i695_the_header_and_its_tombstones_are_one_write(&d).await
                }
                #[tokio::test]
                async fn i697() {
                    let Some(d) = $fresh.await else { return };
                    b::i697_a_tombstone_never_reaches_the_accountability_record(&d).await
                }
                #[tokio::test]
                async fn i698() {
                    let Some(d) = $fresh.await else { return };
                    b::i698_run_kind_survives_the_manifest_form(&d).await
                }
                #[tokio::test]
                async fn i820() {
                    let Some(d) = $fresh.await else { return };
                    b::i820_derivatives_leave_with_a_withheld_parent(&d).await
                }
                #[tokio::test]
                async fn i821() {
                    let Some(d) = $fresh.await else { return };
                    b::i821_a_blobs_subject_is_resolved_locally(&d).await
                }
                #[tokio::test]
                async fn i822() {
                    let Some(d) = $fresh.await else { return };
                    b::i822_the_dwell_is_this_nodes_clock(&d).await
                }
                #[tokio::test]
                async fn i826() {
                    let Some(d) = $fresh.await else { return };
                    b::i826_a_reused_thought_reads_its_own_signature(&d).await
                }
                #[tokio::test]
                async fn i828() {
                    let Some(d) = $fresh.await else { return };
                    b::i828_a_person_subject_arrival_voids_the_tombstone(&d).await
                }
                #[tokio::test]
                async fn i832() {
                    let Some(d) = $fresh.await else { return };
                    b::i832_an_unresolved_subject_is_retryable(&d).await
                }
                #[tokio::test]
                async fn i828b() {
                    let Some(d) = $fresh.await else { return };
                    b::i828b_serve_by_hash_withholds_during_the_dwell(&d).await
                }
                #[tokio::test]
                async fn i831() {
                    let Some(d) = $fresh.await else { return };
                    b::i831_dsar_erasure_drops_orphaned_signatures(&d).await
                }
                #[tokio::test]
                async fn i664() {
                    let Some(d) = $fresh.await else { return };
                    b::i664_the_tombstone_row_holds_another_basis(&d).await
                }
            }
        };
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    macro_rules! rollup_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies as b;
                #[tokio::test]
                async fn i825() {
                    let Some(d) = $fresh.await else { return };
                    b::i825_a_purged_traces_detections_are_tombstoned(&d).await
                }
                #[tokio::test]
                async fn i696() {
                    let Some(d) = $fresh.await else { return };
                    b::i696_a_purged_trace_leaves_no_rollup(&d).await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    rollup_runners!(sqlite_rollup, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    rollup_runners!(postgres_rollup, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::isolated_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

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
        let dsn = crate::test_pg::isolated_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    // ── I661 — from disk ─────────────────────────────────────────────────
    fn strip(src: &str) -> String {
        src.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn body<'a>(src: &'a str, open: &str) -> &'a str {
        let i = src.find(open).unwrap_or_else(|| panic!("{open} not found"));
        let rest = &src[i..];
        let end = rest[1..]
            .find("\n    async fn ")
            .map_or(rest.len(), |j| j + 1);
        &rest[..end]
    }

    #[test]
    fn i661_every_backend_door_carries_the_purge_gates() {
        let root = env!("CARGO_MANIFEST_DIR");
        for backend in ["memory", "sqlite", "postgres"] {
            let src =
                strip(&std::fs::read_to_string(format!("{root}/src/store/{backend}.rs")).unwrap());
            let put = body(&src, "async fn put_attestation_with_origin(");
            for gate in [
                "steward_purge::refuse_if_tombstoned_attestation(self, &row).await?",
                "steward_purge::refuse_mock_trace_attestation(&row)?",
            ] {
                assert!(
                    put.contains(gate),
                    "I661 {backend}: the attestation put carries {gate}"
                );
            }
            for door in [
                "async fn put_public_key(",
                "async fn apply_replicated_key_record(",
            ] {
                // A purge never touches a key (operator ruling 2026-10-09): no
                // key door consults the purge plane.
                let gated = src
                    .match_indices(door)
                    .map(|(i, _)| body(&src[i..], door))
                    .any(|b| b.contains("steward_purge::refuse_if_tombstoned"));
                assert!(!gated, "I661 {backend}: {door} consults no purge gate");
            }
            let serve = body(&src, "async fn list_attestations_since(");
            assert!(
                serve.contains("purge_tombstones"),
                "I661 {backend}: the serve read withholds tombstoned rows"
            );
            // Codex on PR #1057 (I697): except the accountability record, by
            // the one shared list.
            assert!(
                serve.contains("migration::accountability_record_"),
                "I661 {backend}: the serve read never withholds the accountability record"
            );
            // #1043 ruled: a row refused today is purged, never filtered at
            // the serve read.
            // The serve read may render the void predicates (round 4:
            // `person_subject_sql`), never classify by a purge class.
            let without_void = serve.replace("steward_purge::person_subject_sql", "");
            assert!(
                !serve.contains("refused_today") && !without_void.contains("steward_purge::"),
                "I661 {backend}: the serve read classifies no row by refused_today"
            );
        }
        let adm = strip(include_str!("admission.rs"));
        let promo = body(&adm, "pub async fn check_promotion_admission(");
        assert!(promo.contains("steward_purge::refuse_mock_trace_attestation(row)?"));
        assert!(promo.contains("steward_purge::refuse_if_tombstoned_attestation(directory, row)"));
        let ingest = strip(include_str!("../ingest.rs"));
        assert!(ingest.contains("self.refuse_named_traces(&env).await?;"));
    }

    /// The signature text of the `fn` at byte `at` of `src`, up to its body.
    fn signature_of(src: &str, at: usize) -> &str {
        let rest = &src[at..];
        &rest[..rest.find('{').unwrap_or(rest.len())]
    }

    /// **I822** (Codex round 2 on PR #1057) — from disk: no public purge
    /// surface takes a caller's instant.
    #[test]
    fn i822_no_purge_surface_takes_a_callers_now() {
        let root = env!("CARGO_MANIFEST_DIR");
        let read = |f: &str| strip(&std::fs::read_to_string(format!("{root}/{f}")).unwrap());
        let mut problems = Vec::new();
        let module = read("src/federation/steward_purge.rs");
        let mut seen = 0;
        for open in ["pub fn ", "pub async fn "] {
            for (i, _) in module.match_indices(open) {
                let sig = signature_of(&module, i);
                seen += 1;
                if sig.contains("now") {
                    problems.push(format!("steward_purge: {}", sig.trim()));
                }
            }
        }
        assert!(
            seen > 15,
            "I822: the scan read the module's pub fns ({seen})"
        );
        let engine = read("src/engine.rs");
        for name in [
            "purge_dry_run",
            "purge_rows",
            "purge_status",
            "purge_finalize",
            "purge_ledger_tsv",
            "list_purge_bundles_since",
            "apply_replicated_purge",
        ] {
            let open = format!("pub async fn {name}(");
            let i = engine
                .find(&open)
                .unwrap_or_else(|| panic!("I822: Engine::{name} not found"));
            let sig = signature_of(&engine, i);
            if sig.contains("now") {
                problems.push(format!("Engine::{name}: {}", sig.trim()));
            }
        }
        let pyo3 = read("src/ffi/pyo3.rs");
        for name in [
            "purge_rows_json",
            "purge_status_json",
            "purge_finalize_json",
            "apply_replicated_purge_json",
        ] {
            let open = format!("fn {name}(");
            let i = pyo3
                .find(&open)
                .unwrap_or_else(|| panic!("I822: pyo3 {name} not found"));
            let sig = signature_of(&pyo3, i);
            if sig.contains("now") {
                problems.push(format!("pyo3 {name}: {}", sig.trim()));
            }
        }
        assert!(
            problems.is_empty(),
            "I822: a purge surface takes a caller's instant:\n{}",
            problems.join("\n")
        );
    }

    /// **I829b** (Codex round 4 on PR #1057) — from the MIGRATED schema:
    /// every table with an `*attestation_id` column is either a classified
    /// projection (`steward_purge::ATTESTATION_PROJECTIONS`) or a declared
    /// independent plane, every foreign key to `federation_attestations`
    /// matches its classified removal, every classified entry exists, and the
    /// memory backend's projection purge names every helper-removed mirror it
    /// holds. A new projection is a red here until the purge removes it.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i829b_every_attestation_keyed_table_is_a_classified_projection() {
        use crate::federation::steward_purge::{
            ProjectionRemoval, ATTESTATION_PROJECTIONS, INDEPENDENT_ATTESTATION_ID_TABLES,
        };
        use crate::store::Backend as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i829b.db");
        let b = crate::store::sqlite::SqliteBackend::open(path.to_string_lossy().to_string())
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        drop(b);
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut columns: Vec<(String, String)> = conn
            .prepare(
                "SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p \
                 WHERE m.type = 'table' AND p.name LIKE '%attestation_id' ORDER BY 1, 2",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        columns.dedup();
        let mut problems = Vec::new();
        for (table, column) in &columns {
            let projection = ATTESTATION_PROJECTIONS
                .iter()
                .any(|(t, c, _)| t == table && c == column);
            let independent = INDEPENDENT_ATTESTATION_ID_TABLES
                .iter()
                .any(|(t, _)| t == table);
            if !projection && !independent {
                problems.push(format!(
                    "{table}.{column} is keyed by an attestation id and is neither a classified \
                     projection nor a declared independent plane"
                ));
            }
        }
        let fks: Vec<(String, String, String)> = conn
            .prepare(
                "SELECT m.name, f.\"from\", f.on_delete FROM sqlite_master m, \
                    pragma_foreign_key_list(m.name) f \
                 WHERE m.type = 'table' AND f.\"table\" = 'federation_attestations'",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for (table, column, on_delete) in &fks {
            let want = match on_delete.as_str() {
                "CASCADE" => ProjectionRemoval::ForeignKeyCascade,
                "SET NULL" => ProjectionRemoval::ForeignKeySetNull,
                other => {
                    problems.push(format!(
                        "{table}.{column}: FK ON DELETE {other} keeps the row"
                    ));
                    continue;
                }
            };
            if !ATTESTATION_PROJECTIONS.contains(&(table.as_str(), column.as_str(), want)) {
                problems.push(format!(
                    "{table}.{column}: FK {on_delete} is not classified so"
                ));
            }
        }
        for (table, column, _) in ATTESTATION_PROJECTIONS {
            if !columns.iter().any(|(t, c)| t == table && c == column) {
                problems.push(format!(
                    "stale classification: {table}.{column} is not in the schema"
                ));
            }
        }
        // The memory backend mirrors the helper-removed tables by hand.
        let root = env!("CARGO_MANIFEST_DIR");
        let memory =
            strip(&std::fs::read_to_string(format!("{root}/src/store/memory.rs")).unwrap());
        let helper = body(&memory, "async fn purge_attestation_projections(");
        for (table, _, removal) in ATTESTATION_PROJECTIONS {
            if *removal != ProjectionRemoval::Helper {
                continue;
            }
            let held = memory.contains(&format!("    {table}:"));
            if held && !helper.contains(&format!(".{table}")) {
                problems.push(format!(
                    "memory holds {table} and its projection purge omits it"
                ));
            }
        }
        assert!(problems.is_empty(), "I829b:\n{}", problems.join("\n"));
        assert!(
            columns.len() >= 10,
            "I829b: the schema scan ran ({columns:?})"
        );
    }

    /// The refusal tokens are a closed set of stable strings (CIRISServer#756
    /// maps each to a reason id).
    #[test]
    fn i661_the_tokens_are_stable() {
        use crate::federation::steward_purge::token;
        assert_eq!(
            token::ALL,
            &[
                "purge_unauthorised",
                "purge_selection_digest_mismatch",
                "purge_selection_count_mismatch",
                "purge_retraction_inadmissible",
                "purge_not_settled",
                "purge_notice_unknown",
                "purge_tombstoned",
                "purge_selection_malformed",
                "purge_human_subject_pending_notice_row",
                "purge_execution_incomplete",
            ]
        );
        assert_eq!(
            crate::federation::steward_purge::TRACE_RUN_KIND_MOCK,
            "trace_run_kind_mock"
        );
        assert_eq!(
            crate::federation::steward_purge::STEWARD_PURGE_BASIS,
            "steward_purge"
        );
        // The digest is SHA-256 over the JCS array of sorted, unique ids.
        let d =
            crate::federation::steward_purge::selection_digest(&["trace:b", "trace:a", "trace:a"]);
        use sha2::Digest as _;
        assert_eq!(
            d,
            hex::encode(sha2::Sha256::digest(br#"["trace:a","trace:b"]"#)),
            "I661: the digest preimage is the JCS array"
        );
    }
}
