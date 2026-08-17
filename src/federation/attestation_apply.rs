//! v36.0.0 (CIRISPersist#624) — the **typed, pre-write replicated
//! ATTESTATION-plane apply**: the Key plane's #565 twin.
//!
//! # The asymmetry this closes
//!
//! The Key plane returns a typed, semantic outcome:
//! [`apply_replicated_key_record`](super::FederationDirectory::apply_replicated_key_record)
//! → [`ReplicatedKeyOutcome`](super::register::ReplicatedKeyOutcome) /
//! [`KeyRefusalReason`](super::register::KeyRefusalReason), decided BEFORE the
//! write. The Attestation plane had none:
//! [`put_attestation`](super::FederationDirectory::put_attestation) is
//! `Result<(), Error>`, so a same-id / different-bytes convergence conflict
//! was only discovered when the backend's UNIQUE index rejected the insert —
//! surfacing as `Error::Backend("insert attestation: UNIQUE constraint
//! failed: …")`, a **storage** classification for a **semantic** outcome.
//! CIRISEdge#459 measured the bill: 94 refusals in ~6 minutes on a production
//! canonical, all in one `federation_backend` bucket, indistinguishable from a
//! disk error.
//!
//! Three problems, named by #624:
//!
//! 1. **Cannot be counted** — one bucket for every storage failure.
//! 2. **Reads as a fault when it is a decision** — two producers minting the
//!    same id is the mesh working, not a node bug.
//! 3. **Reaches the DB to find out** — the verdict depended on the UNIQUE
//!    index EXISTING; a backend without it would silently accept the
//!    conflicting row.
//!
//! # Shape
//!
//! [`plan_replicated_attestation_apply`] is the **pure classification core**:
//! a function of `(existing row, incoming row)` only — no directory handle, no
//! backend, testable without either. The trait-level entry point
//! [`apply_replicated_attestation`](super::FederationDirectory::apply_replicated_attestation)
//! fetches the existing row, runs the plan, and only an incoming row the plan
//! ADMITS ever reaches `put_attestation` (whose full admission-gate stack
//! still binds — nothing is bypassed; this module adds a decision layer, not a
//! side door).
//!
//! The refusal-cause inventory below comes from the code, not from #624's
//! guess — the same discipline as #565, which expected six variants and
//! shipped nine. #624 named two causes (`ConflictingAttestation`, an
//! `AlreadyPresentIdentical` duplicate); the code yields **three refusal
//! reasons and four outcome states**, because the same-id-same-bytes re-offer
//! (#624's genesis case) is [`ReplicatedAttestationOutcome::Unchanged`] — an
//! outcome, not a refusal, exactly like the Key plane's `Unchanged` — and two
//! more states exist that no issue guessed: the store-step race
//! ([`AttestationRefusalReason::StoreConflict`], the twin of the Key plane's)
//! and the CEG §6.1 structural-composer replay
//! ([`ReplicatedAttestationOutcome::Deduplicated`]), which `put_attestation`
//! resolves as a **silent no-op `Ok`** — indistinguishable from an insert to
//! every caller until now.

use super::types::Attestation;
use super::Error;

/// v36.0.0 (CIRISPersist#624) — **WHICH policy branch refused** a replicated
/// Attestation-plane apply.
///
/// **Closed**, and every variant corresponds to exactly ONE condition in the
/// code — deliberately no `Other`/`Unspecified` catch-all (a catch-all
/// reintroduces the disjunction one name deeper — the
/// [`KeyRefusalReason`](super::register::KeyRefusalReason) discipline). Serde
/// tokens are snake_case and [`Self::as_str`] returns the SAME token, so a
/// consumer keys on a program constant and never on a message string.
///
/// **The token set is the downstream contract, and this mapping is
/// APPEND-ONLY.** CIRISEdge keys its receive-plane apply ledger on these
/// constants (the #565 adoption pattern: `attestation_outcome_to_apply` + an
/// `attestation_apply_refusals_by_reason` ledger). Add variants; never
/// re-spell one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRefusalReason {
    /// The `attestation_id` is already held by a row asserting **different
    /// signed content** (a different `original_content_hash`) or the same
    /// content under a **different producer** (`attesting_key_id` /
    /// `scrub_key_id`). Two producers minted the same id — the CIRISEdge#459
    /// live case (88 distinct content hashes colliding on the fixed genesis
    /// ids). First-seen wins; a re-offer of this row can never succeed.
    ConflictingAttestation,
    /// The `attestation_id` is held by a row asserting **exactly what was
    /// offered** — same `original_content_hash` (the SHA-256 of the signed
    /// canonical envelope, which since #643 binds all seven typed columns via
    /// the row mirror) under the same producer pair — differing only in
    /// unsigned decoration (signature bytes from a re-sign — ML-DSA-65
    /// signing is randomized — `scrub_timestamp`, `tier` / `promoted_at`,
    /// `withdraws_admission_rule`, `additional_scrubs`).
    ///
    /// This is a *duplicate*, not a rejection: the receiver already holds
    /// exactly what was offered, and reporting it as a conflict sends the
    /// reader hunting for a convergence collision that is not there. A
    /// BYTE-identical re-offer never reaches here — it resolves
    /// [`ReplicatedAttestationOutcome::Unchanged`] at the `persist_row_hash`
    /// comparison. The exact twin of the Key plane's
    /// `AlreadyAnchoredIdentical` near-miss split.
    AlreadyPresentIdentical,
    /// The store step refused a duplicate `attestation_id` the plan did not
    /// see: a lost race between plan and act, or a directory that cannot
    /// answer [`get_attestation`](super::FederationDirectory::get_attestation)
    /// ([`Error::Unsupported`] — the plan-free fallback, mirroring the Key
    /// plane's plan-free default body). Fail-closed: the existing row is
    /// untouched, and the record is safe to re-offer — the next round's plan
    /// names the conflict precisely.
    StoreConflict,
}

impl AttestationRefusalReason {
    /// The **stable program token** for this reason — identical to the serde
    /// token, so a consumer that reads the wire and a consumer that holds the
    /// typed value key on the same constant.
    /// [`tests::refusal_reason_tokens_match_serde`] binds the two spellings
    /// together so they cannot drift. APPEND-ONLY (see the type doc).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ConflictingAttestation => "conflicting_attestation",
            Self::AlreadyPresentIdentical => "already_present_identical",
            Self::StoreConflict => "store_conflict",
        }
    }

    /// Every variant, in declaration order — the closed set, for exhaustive
    /// gates and for a consumer enumerating the taxonomy it must handle.
    pub const ALL: &'static [Self] = &[
        Self::ConflictingAttestation,
        Self::AlreadyPresentIdentical,
        Self::StoreConflict,
    ];
}

impl std::fmt::Display for AttestationRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v36.0.0 (CIRISPersist#624) — outcome of an
/// [`apply_replicated_attestation`](super::FederationDirectory::apply_replicated_attestation).
///
/// Serde tokens are snake_case strings (`"inserted"` / `"unchanged"` /
/// `"deduplicated"`); `Refused` carries its reason as
/// `{"refused":{"reason":"<token>"}}` — the same wire shape as
/// [`ReplicatedKeyOutcome`](super::register::ReplicatedKeyOutcome).
///
/// A `Refused` is a *policy* outcome, not an error: the anti-entropy
/// Attestation plane receives unsolicited rows, so a row that is not admitted
/// against the current corpus resolves to `Refused` (fail-closed,
/// deterministic) rather than aborting the apply loop. Admission-gate
/// failures on a FRESH insert (bad signature, quota, trust, dimension policy,
/// …) still surface as their typed [`Error`]s — each already carries its own
/// stable `kind()` token, and re-wrapping them here would be a second copy of
/// that taxonomy (the two-lists-that-disagree class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicatedAttestationOutcome {
    /// New `attestation_id` — stored via `put_attestation` (exactly the
    /// direct write path, including its whole admission-gate stack).
    Inserted,
    /// The corpus already carries this exact row (`persist_row_hash`-equal
    /// re-offer) — idempotent no-op. **The genesis re-offer case**: every
    /// node ships the baked bundle, so a canonical re-offering
    /// `genesis-charter` / `genesis-grant:*` / `genesis-lifecycle` to a node
    /// that already holds them lands HERE, not in a refusal bucket.
    Unchanged,
    /// The CEG §6.1 structural-composer dedup: an equivalent
    /// `withdraws`/`recants`/`supersedes` — same `(references_attestation_id,
    /// attestation_type, attesting_key_id)` triple under a DIFFERENT id —
    /// already exists, so `put_attestation` resolved the replay as an
    /// idempotent no-op. No row was written. Before #624 this was
    /// indistinguishable from [`Self::Inserted`] (the backend returns a
    /// silent `Ok`), so an apply loop reported an insert that never
    /// happened.
    Deduplicated,
    /// The row was NOT applied and the existing corpus is untouched.
    /// `reason` names the branch that fired — a closed enum, not a message
    /// string.
    Refused {
        /// WHICH policy branch refused.
        reason: AttestationRefusalReason,
    },
}

/// The classification half of the #624 apply — which action
/// [`apply_replicated_attestation`](super::FederationDirectory::apply_replicated_attestation)
/// takes for an incoming row given the currently-stored row.
///
/// `pub(crate)` like
/// [`ReplicatedKeyPlan`](super::register::ReplicatedKeyPlan): the plan is
/// where the policy branches actually are, so this is where each
/// [`AttestationRefusalReason`] is *produced*; the entry point carries it
/// through rather than re-deriving it (one predicate, one implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicatedAttestationPlan {
    /// No row for `attestation_id` — insert via `put_attestation` (every
    /// admission gate still binds; nothing is bypassed for fresh rows).
    Insert,
    /// Byte-identical re-offer — no-op.
    Unchanged,
    /// Not admitted; leave the corpus untouched (fail-closed).
    Refused {
        /// WHICH policy branch refused.
        reason: AttestationRefusalReason,
    },
}

/// v36.0.0 (CIRISPersist#624) — the one constructor for a refused plan, so a
/// site cannot forget the reason (there is no reason-less way to build one).
const fn refused(reason: AttestationRefusalReason) -> ReplicatedAttestationPlan {
    ReplicatedAttestationPlan::Refused { reason }
}

/// v36.0.0 (CIRISPersist#624) — decide what a replicated Attestation-plane
/// apply does with `incoming`, **WITHOUT mutating anything and WITHOUT a
/// directory** — a pure function of `(existing, incoming)`, so the verdict
/// cannot depend on a storage constraint existing (problem 3 of #624) and the
/// three backends cannot hold three opinions of it.
///
/// Decision table:
///
/// - **no existing row** ⇒ [`ReplicatedAttestationPlan::Insert`] — the store
///   step is `put_attestation` itself, so every admission gate (genesis
///   reservation, quota, trust, envelope bindings, hybrid verify, the
///   directory-walk authority gates) still binds.
/// - **byte-identical re-offer** ⇒ [`ReplicatedAttestationPlan::Unchanged`].
///   Compared over [`compute_persist_row_hash`](super::types::compute_persist_row_hash)
///   of the incoming row with its envelope first canonicalized exactly as the
///   put door canonicalizes it (#647 canonical-at-rest; idempotent), so a
///   locally re-minted row and a wire re-offer of the stored row both compare
///   stably against the stored hash.
/// - **same signed assertion, same producer** (equal `original_content_hash`
///   — which covers the envelope and, via the #643 row mirror, all seven
///   typed columns — under equal `attesting_key_id` AND `scrub_key_id`),
///   differing only in unsigned decoration ⇒
///   [`AttestationRefusalReason::AlreadyPresentIdentical`].
/// - **anything else holding the id** ⇒
///   [`AttestationRefusalReason::ConflictingAttestation`] — different signed
///   content, or the same content under a different producer. First-seen
///   wins.
///
/// Malformed input that no policy can classify (an un-canonicalizable
/// envelope, a row that cannot serialize for hashing) surfaces as `Err` —
/// `Refused` is reserved for "well-formed but not admitted", exactly like the
/// Key plane's plan.
pub(crate) fn plan_replicated_attestation_apply(
    existing: Option<&Attestation>,
    incoming: &Attestation,
) -> Result<ReplicatedAttestationPlan, Error> {
    let Some(existing) = existing else {
        return Ok(ReplicatedAttestationPlan::Insert);
    };

    // Idempotent re-offer: byte-identical row. The envelope is canonicalized
    // first — the SAME normalization the put door applies before it computes
    // the stored hash (#647), and idempotent — so the comparison is between
    // like and like. `compute_persist_row_hash` drops the `persist_row_hash`
    // field itself, so a record arriving with the origin row's hash (or with
    // none) still compares stably.
    let incoming_hash = {
        let mut normalized = incoming.clone();
        super::canonical_at_rest::canonicalize_in_place(&mut normalized.attestation_envelope)?;
        super::types::compute_persist_row_hash(&normalized)?
    };
    if existing.persist_row_hash == incoming_hash {
        return Ok(ReplicatedAttestationPlan::Unchanged);
    }

    // The near-miss: the SAME signed assertion by the SAME producer, differing
    // only in unsigned decoration. `original_content_hash` is the SHA-256 of
    // the signed canonical envelope — the bytes both scrub signatures cover —
    // so equal hashes mean the CLAIM is identical; the producer pair pins WHO
    // made it. Split from the conflict because the remedies differ: a
    // duplicate needs nothing, a conflict needs a duplicity/convergence look.
    if existing.original_content_hash == incoming.original_content_hash
        && existing.attesting_key_id == incoming.attesting_key_id
        && existing.scrub_key_id == incoming.scrub_key_id
    {
        return Ok(refused(AttestationRefusalReason::AlreadyPresentIdentical));
    }

    Ok(refused(AttestationRefusalReason::ConflictingAttestation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{FederationDirectory, SignedAttestation};

    // ── Pure plan + token tests (no backend, no directory) ────────────

    /// The serde token and [`AttestationRefusalReason::as_str`] must be the
    /// SAME spelling — a consumer that reads the wire and a consumer that
    /// holds the typed value key on one constant. Asserted over `ALL`, so a
    /// NEW variant is covered the moment it is added.
    #[test]
    fn refusal_reason_tokens_match_serde() {
        for reason in AttestationRefusalReason::ALL {
            let json = serde_json::to_string(reason).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", reason.as_str()),
                "serde token and as_str() diverged for {reason:?}"
            );
            let back: AttestationRefusalReason = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *reason);
            assert_eq!(reason.to_string(), reason.as_str(), "Display = token");
        }
        // The tokens are pairwise distinct (a duplicate token would make two
        // verdicts indistinguishable on the wire).
        let tokens: std::collections::BTreeSet<&str> = AttestationRefusalReason::ALL
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert_eq!(tokens.len(), AttestationRefusalReason::ALL.len());
    }

    /// The outcome wire shapes CIRISEdge keys on: bare snake_case strings for
    /// the applied states, `{"refused":{"reason":"<token>"}}` for refusals —
    /// the [`ReplicatedKeyOutcome`](crate::federation::register::ReplicatedKeyOutcome)
    /// shape. Round-trips, so a consumer can also parse them back.
    #[test]
    fn outcome_wire_shape_is_stable() {
        assert_eq!(
            serde_json::to_string(&ReplicatedAttestationOutcome::Inserted).expect("inserted"),
            "\"inserted\""
        );
        assert_eq!(
            serde_json::to_string(&ReplicatedAttestationOutcome::Unchanged).expect("unchanged"),
            "\"unchanged\""
        );
        assert_eq!(
            serde_json::to_string(&ReplicatedAttestationOutcome::Deduplicated)
                .expect("deduplicated"),
            "\"deduplicated\""
        );
        for reason in AttestationRefusalReason::ALL {
            let outcome = ReplicatedAttestationOutcome::Refused { reason: *reason };
            let json = serde_json::to_string(&outcome).expect("refused");
            assert_eq!(
                json,
                format!("{{\"refused\":{{\"reason\":\"{}\"}}}}", reason.as_str())
            );
            assert_eq!(
                serde_json::from_str::<ReplicatedAttestationOutcome>(&json).expect("round-trip"),
                outcome
            );
        }
    }

    /// A minimal well-formed row for the PURE plan tests. These rows never
    /// touch a directory, so they carry no signatures — the plan classifies
    /// identity, not admissibility (admissibility stays `put_attestation`'s).
    fn bare_row(id: &str, author: &str, dimension: &str) -> Attestation {
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixture instant")
            .with_timezone(&chrono::Utc);
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: author.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": dimension,
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: {
                use sha2::Digest as _;
                let canonical =
                    crate::verify::canonical::ceg_produce_canonicalize(&serde_json::json!({
                        "dimension": dimension,
                        "score": 1.0,
                        "confidence": 0.9,
                    }))
                    .expect("canonicalize");
                hex::encode(sha2::Sha256::digest(&canonical))
            },
            scrub_signature_classical: "sig-classical".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// The stored form of `row`: envelope canonicalized and
    /// `persist_row_hash` computed, exactly as the put door stores it.
    fn stored(mut row: Attestation) -> Attestation {
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut row.attestation_envelope)
            .expect("canonicalize");
        row.persist_row_hash =
            crate::federation::types::compute_persist_row_hash(&row).expect("hash");
        row
    }

    #[test]
    fn plan_absent_row_is_insert() {
        let incoming = bare_row("att-1", "author-a", "identity_binding:v1");
        assert_eq!(
            plan_replicated_attestation_apply(None, &incoming).expect("plan"),
            ReplicatedAttestationPlan::Insert
        );
    }

    /// The genesis re-offer case, decided WITHOUT any storage constraint: the
    /// same row re-offered — including a NON-canonical envelope re-offer of a
    /// canonically-stored row, and a re-offer carrying the origin's
    /// `persist_row_hash` — is `Unchanged`.
    #[test]
    fn plan_identical_reoffer_is_unchanged() {
        let minted = bare_row("att-1", "author-a", "identity_binding:v1");
        let held = stored(minted.clone());
        // The wire re-offer of the stored row (carries the origin hash).
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &held.clone()).expect("plan"),
            ReplicatedAttestationPlan::Unchanged
        );
        // The re-mint (pre-canonical envelope, empty hash) of the same row.
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &minted).expect("plan"),
            ReplicatedAttestationPlan::Unchanged
        );
    }

    /// Same id, different signed content ⇒ `ConflictingAttestation` — the
    /// CIRISEdge#459 live case, decided pre-write.
    #[test]
    fn plan_different_content_is_conflicting() {
        let held = stored(bare_row("att-1", "author-a", "identity_binding:v1"));
        let rival = bare_row("att-1", "author-a", "capability_binding:v1");
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &rival).expect("plan"),
            ReplicatedAttestationPlan::Refused {
                reason: AttestationRefusalReason::ConflictingAttestation
            }
        );
    }

    /// Same id, same signed content, DIFFERENT producer ⇒ still
    /// `ConflictingAttestation` — an identical claim under another identity
    /// is a duplicity question, never a duplicate.
    #[test]
    fn plan_same_content_different_producer_is_conflicting() {
        let held = stored(bare_row("att-1", "author-a", "identity_binding:v1"));
        let mut rival = bare_row("att-1", "author-a", "identity_binding:v1");
        rival.attesting_key_id = "author-b".to_owned();
        rival.scrub_key_id = "author-b".to_owned();
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &rival).expect("plan"),
            ReplicatedAttestationPlan::Refused {
                reason: AttestationRefusalReason::ConflictingAttestation
            }
        );
    }

    /// Same id, same assertion, same producer, differing only in unsigned
    /// decoration (a re-sign's randomized ML-DSA bytes / a fresh
    /// `scrub_timestamp`) ⇒ `AlreadyPresentIdentical` — the near-miss that
    /// reads as a conflict until it is named.
    #[test]
    fn plan_decoration_only_difference_is_already_present() {
        let held = stored(bare_row("att-1", "author-a", "identity_binding:v1"));
        let mut reoffer = bare_row("att-1", "author-a", "identity_binding:v1");
        reoffer.scrub_signature_classical = "sig-classical-resigned".to_owned();
        reoffer.scrub_timestamp += chrono::Duration::seconds(7);
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &reoffer).expect("plan"),
            ReplicatedAttestationPlan::Refused {
                reason: AttestationRefusalReason::AlreadyPresentIdentical
            }
        );
    }

    // ── Entry-point witnesses (memory backend — the PUBLIC door) ──────
    //
    // One witness per outcome/reason variant through
    // `FederationDirectory::apply_replicated_attestation`. The fixture
    // recipe (deterministic hybrid keys + `seal_row_in_place`) is the
    // corpus-standard one, so every row here clears the REAL admission
    // stack — each witness measures the apply classification, not a gate
    // upstream of it.

    /// A fully-admissible federation-tier row: registered author, sealed
    /// envelope (instants + #643 mirror + hybrid signatures).
    fn sealed_row(id: &str, author: &str, envelope: serde_json::Value) -> Attestation {
        let mut row = bare_row(id, author, "identity_binding:v1");
        row.attestation_envelope = envelope;
        crate::federation::tier_ingest::test_support::seal_row_in_place(author, &mut row);
        row
    }

    fn envelope(dimension: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut env = serde_json::json!({
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
        });
        if let (Some(obj), Some(more)) = (env.as_object_mut(), extra.as_object()) {
            for (k, v) in more {
                obj.insert(k.clone(), v.clone());
            }
        }
        env
    }

    async fn memory_with_author(author: &str) -> crate::store::MemoryBackend {
        let dir = crate::store::MemoryBackend::new();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&dir, author).await;
        dir
    }

    /// `Inserted` — a fresh row applies through the whole admission stack and
    /// is readable afterwards.
    #[tokio::test]
    async fn apply_fresh_row_is_inserted() {
        let author = "att-apply-ins-author";
        let dir = memory_with_author(author).await;
        let row = sealed_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        let id = row.attestation_id.clone();
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await
            .expect("apply");
        assert_eq!(outcome, ReplicatedAttestationOutcome::Inserted);
        assert!(
            dir.get_attestation(&id).await.expect("get").is_some(),
            "an Inserted outcome must mean the row is actually readable"
        );
    }

    /// `Unchanged` — re-offering the STORED row (the wire re-offer every
    /// baked-genesis node produces) is an idempotent no-op, not a refusal and
    /// not an error.
    #[tokio::test]
    async fn apply_identical_reoffer_is_unchanged() {
        let author = "att-apply-unch-author";
        let dir = memory_with_author(author).await;
        let row = sealed_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        let id = row.attestation_id.clone();
        dir.apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("first apply");
        // Re-offer what the STORE now holds — the replication wire shape.
        let held = dir
            .get_attestation(&id)
            .await
            .expect("get")
            .expect("stored");
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation { attestation: held })
            .await
            .expect("re-apply");
        assert_eq!(outcome, ReplicatedAttestationOutcome::Unchanged);
        // And the original (pre-canonicalization) mint re-offers as Unchanged
        // too — the hash comparison is canonicalization-stable.
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await
            .expect("re-apply mint");
        assert_eq!(outcome, ReplicatedAttestationOutcome::Unchanged);
    }

    /// `Refused { ConflictingAttestation }` — same id, different signed
    /// content: refused as a DECISION, pre-write, with the stored row
    /// untouched. The pre-write half is proven by faulting
    /// `put_attestation` itself: the verdict must not change, because the
    /// write step is never consulted for a row the plan refuses.
    #[tokio::test]
    async fn apply_conflicting_row_is_refused_pre_write() {
        let author = "att-apply-conf-author";
        let dir = std::sync::Arc::new(memory_with_author(author).await);
        let id = uuid::Uuid::new_v4().to_string();
        let first = sealed_row(
            &id,
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        dir.apply_replicated_attestation(SignedAttestation { attestation: first })
            .await
            .expect("first apply");
        let stored_before = dir.get_attestation(&id).await.expect("get").expect("held");

        // A rival mint of the SAME id with DIFFERENT signed content.
        let rival = sealed_row(
            &id,
            author,
            envelope(
                "identity_binding:v1",
                serde_json::json!({"note": "a different mint of the same id"}),
            ),
        );

        // Through a directory whose put_attestation is FAULTED: if the
        // decision reached the write step at all, the apply would error.
        let no_writes = crate::federation::directory_double::FaultInjectingDirectory::new(
            dir.clone() as std::sync::Arc<dyn FederationDirectory>,
        )
        .unsupported("put_attestation");
        let outcome = no_writes
            .apply_replicated_attestation(SignedAttestation {
                attestation: rival.clone(),
            })
            .await
            .expect("a refusal is an outcome, not an error — and pre-write");
        assert_eq!(
            outcome,
            ReplicatedAttestationOutcome::Refused {
                reason: AttestationRefusalReason::ConflictingAttestation
            }
        );
        // Same verdict through the un-faulted door, and the row is untouched.
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation { attestation: rival })
            .await
            .expect("apply");
        assert_eq!(
            outcome,
            ReplicatedAttestationOutcome::Refused {
                reason: AttestationRefusalReason::ConflictingAttestation
            }
        );
        let stored_after = dir.get_attestation(&id).await.expect("get").expect("held");
        assert_eq!(
            crate::federation::types::compute_persist_row_hash(&stored_before).expect("hash"),
            crate::federation::types::compute_persist_row_hash(&stored_after).expect("hash"),
            "a refused apply must leave the stored row untouched"
        );
    }

    /// `Refused { AlreadyPresentIdentical }` — the same assertion re-signed
    /// (fresh ML-DSA bytes, fresh scrub_timestamp) is a duplicate, not a
    /// conflict. This is the witness that distinguishes the two variants:
    /// collapsing them makes it red.
    #[tokio::test]
    async fn apply_resigned_same_assertion_is_already_present() {
        let author = "att-apply-dup-author";
        let dir = memory_with_author(author).await;
        let row = sealed_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        dir.apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("first apply");

        // Re-sign the SAME sealed envelope: same signed bytes, new signature
        // decoration. `sign_envelope` re-derives och from the same envelope,
        // and ML-DSA-65 signing is randomized, so the pqc half differs.
        let mut reoffer = row.clone();
        let (och, classical, pqc) = crate::federation::tier_ingest::test_support::sign_envelope(
            author,
            &reoffer.attestation_envelope,
        );
        assert_eq!(och, reoffer.original_content_hash, "same bytes, same hash");
        reoffer.scrub_signature_classical = classical;
        reoffer.scrub_signature_pqc = pqc;
        reoffer.scrub_timestamp += chrono::Duration::seconds(11);
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation {
                attestation: reoffer,
            })
            .await
            .expect("apply");
        assert_eq!(
            outcome,
            ReplicatedAttestationOutcome::Refused {
                reason: AttestationRefusalReason::AlreadyPresentIdentical
            }
        );
    }

    /// `Refused { StoreConflict }` — the plan-free fallback: a directory that
    /// cannot answer `get_attestation` (the #603 `Unsupported` arm) still
    /// applies, and a duplicate id surfaces as the store-step conflict, not
    /// as a `federation_backend` error. This is the Key plane's plan-free
    /// default-body shape, reached through the double built for exactly this
    /// arm.
    #[tokio::test]
    async fn apply_without_a_plan_maps_duplicate_key_to_store_conflict() {
        let author = "att-apply-race-author";
        let dir = std::sync::Arc::new(memory_with_author(author).await);
        let id = uuid::Uuid::new_v4().to_string();
        let first = sealed_row(
            &id,
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        dir.apply_replicated_attestation(SignedAttestation { attestation: first })
            .await
            .expect("first apply");

        let planless = crate::federation::directory_double::FaultInjectingDirectory::new(
            dir.clone() as std::sync::Arc<dyn FederationDirectory>,
        )
        .unsupported("get_attestation");
        // A rival mint of the same id: the plan cannot run, the store's
        // uniqueness fires, and the outcome is the typed store conflict.
        let rival = sealed_row(
            &id,
            author,
            envelope(
                "identity_binding:v1",
                serde_json::json!({"note": "rival mint, plan-free"}),
            ),
        );
        let outcome = planless
            .apply_replicated_attestation(SignedAttestation { attestation: rival })
            .await
            .expect("a store conflict is an outcome, not an error");
        assert_eq!(
            outcome,
            ReplicatedAttestationOutcome::Refused {
                reason: AttestationRefusalReason::StoreConflict
            }
        );
        // And a FRESH row through the plan-free door still inserts — the
        // fallback degrades the plan, not the write.
        let fresh = sealed_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        assert_eq!(
            planless
                .apply_replicated_attestation(SignedAttestation { attestation: fresh })
                .await
                .expect("fresh apply"),
            ReplicatedAttestationOutcome::Inserted
        );
        // The UNSANCTIONED side is witnessed separately — see
        // `a_generic_get_failure_propagates_and_does_not_degrade_624`.
    }

    /// v36.0.0 (CIRISPersist#624 M6) — **a generic `get_attestation` failure
    /// must PROPAGATE, never degrade to the plan-free path.**
    ///
    /// This is the witness the #624 stream reported as inexpressible and
    /// named the remediation for: the fault double could inject exactly one
    /// error kind (`Unsupported`), which is the SANCTIONED degrade signal, so
    /// the mutation collapsing `Err(Unsupported) => plan-free` into
    /// `Err(_) => plan-free` survived every test. A surviving mutation is a
    /// claim about the instrument, and the instrument was the gap.
    ///
    /// `FaultInjectingDirectory::erroring` (added with this witness) injects
    /// `Error::Backend`. The distinction is load-bearing: `Unsupported` means
    /// *this directory cannot answer*, and proceeding plan-free is correct;
    /// `Backend` means *the answer was attempted and failed*, and proceeding
    /// would decide a convergence conflict on evidence the node never read.
    #[tokio::test]
    async fn a_generic_get_failure_propagates_and_does_not_degrade_624() {
        let author = "att-apply-geterr-author";
        let dir = std::sync::Arc::new(memory_with_author(author).await);
        let failing = crate::federation::directory_double::FaultInjectingDirectory::new(
            dir.clone() as std::sync::Arc<dyn FederationDirectory>,
        )
        .erroring("get_attestation");
        assert!(
            failing.error_faults().contains("get_attestation"),
            "fixture must actually declare the fault it is testing"
        );

        let row = sealed_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        let result = failing
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await;
        assert!(
            result.is_err(),
            "a failed read must not become an outcome — got {result:?}"
        );
    }

    /// `Deduplicated` — the CEG §6.1 structural-composer replay: a second
    /// `withdraws` naming the same `(references_attestation_id, type,
    /// attester)` triple under a DIFFERENT id is resolved by the backend as a
    /// silent no-op; the apply names it rather than reporting an insert that
    /// never happened.
    #[tokio::test]
    async fn apply_composer_replay_is_deduplicated() {
        let author = "att-apply-dedup-author";
        let dir = memory_with_author(author).await;

        // The target the withdraws retracts — the author's own row (rule 1:
        // the producer's own retraction).
        let target = sealed_row(
            &uuid::Uuid::new_v4().to_string(),
            author,
            envelope("identity_binding:v1", serde_json::json!({})),
        );
        let target_id = target.attestation_id.clone();
        dir.apply_replicated_attestation(SignedAttestation {
            attestation: target,
        })
        .await
        .expect("target applies");

        let withdraws = |id: &str| {
            let mut row = bare_row(id, author, "identity_binding:v1");
            row.attestation_type = attestation_type::WITHDRAWS.to_owned();
            row.attestation_envelope = envelope(
                "identity_binding:v1",
                serde_json::json!({
                    crate::federation::envelope::paths::REFERENCES_ATTESTATION_ID: target_id,
                }),
            );
            crate::federation::tier_ingest::test_support::seal_row_in_place(author, &mut row);
            row
        };
        let first = withdraws(&uuid::Uuid::new_v4().to_string());
        assert_eq!(
            dir.apply_replicated_attestation(SignedAttestation { attestation: first })
                .await
                .expect("first withdraws"),
            ReplicatedAttestationOutcome::Inserted
        );

        // The replay: same triple, DIFFERENT id — §6.1 says idempotent no-op.
        let replay_id = uuid::Uuid::new_v4().to_string();
        let replay = withdraws(&replay_id);
        assert_eq!(
            dir.apply_replicated_attestation(SignedAttestation {
                attestation: replay
            })
            .await
            .expect("replay"),
            ReplicatedAttestationOutcome::Deduplicated
        );
        assert!(
            dir.get_attestation(&replay_id)
                .await
                .expect("get")
                .is_none(),
            "Deduplicated must mean no row was written under the replay id"
        );
    }
}
