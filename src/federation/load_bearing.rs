//! v24.2.0 (CIRISPersist#564 stage 1) — **`is_load_bearing(X)`**: the
//! reachability primitive, read-only and fail-secure.
//!
//! # The question
//!
//! > **Is this CEG object load-bearing on THIS node?**
//!
//! An object is load-bearing iff removing our copy would change an answer this
//! node can give or an action it may take. A `consent:replication` grant
//! authorizes *our holding of something*; hold nothing that needs it and it
//! does no work here — independent of its age or its author's fate.
//!
//! #563 found 234 inert `consent:replication` grants that nothing reduces and
//! proposed decay. The operator's reframe replaced the mechanism: **not decay,
//! not liveness — reference counting with a rigorous definition of
//! reachability.** Three of this project's paid lessons argue against the
//! decay design and are recorded so it is not re-proposed: clock-based
//! validity was removed on purpose (#551/#557 — `valid until revoked`);
//! a principal-liveness band is a score about a principal (#552, CC#49-A1) and
//! punishes the quiet-but-honest; and two decay mechanisms with different
//! schedules is the two-lists-that-disagree class. Load-bearing is
//! **structural** — about the graph, about no one.
//!
//! # What this stage does, and what it deliberately does not
//!
//! Stage 1 is the predicate + the manifest axis + the gate. It **releases,
//! evicts and mutates NOTHING**: every function here is a read. It makes the
//! 234 legible as `No` and every gap legible as `Unknown`.
//!
//! `may_release_copy` (with its `anti_entropy_satisfied` conjunct) is stage 2
//! and is deliberately absent — a `No` from this module is NOT a licence to
//! drop anything, because dropping a copy that has nowhere else to live is
//! data loss wearing a GC costume. Compaction is stage 4 and may prove
//! unnecessary entirely.
//!
//! # Never a bare bool
//!
//! [`LoadBearing`] carries a derivation trace: `Yes` names WHICH dependency,
//! `Unknown` names WHICH family and WHY. That is the `TrustRootVerdict` /
//! `TrustedGrant` discipline — a verdict whose evidence the consumer can read
//! without coming back to this layer to ask.
//!
//! # Fail-secure
//!
//! [`LoadBearing::Unknown`] is **treated as load-bearing**. It is the DEFAULT
//! for any family without a declared predicate — never `No` by omission. An
//! undeclared family is a manifest gap, never a licence to collect; the
//! coverage gate in [`super::namespace::supersets`] is what turns that gap
//! from silent into loud.

use crate::federation::{Attestation, Error, FederationDirectory};
use serde::{Deserialize, Serialize};

/// The persist-owned pseudo-family for a `federation_keys` row.
///
/// Key records are directory rows, not CC claim families, so they have no
/// prefix in the namespace manifest. They still need a family NAME to report
/// in an [`LoadBearing::Unknown`], and inventing one silently would be worse
/// than naming it here.
pub const FEDERATION_KEY_FAMILY: &str = "federation_key";

/// What the object under test is. Extended APPEND-ONLY as later stages teach
/// the predicate about routes, blobs and fountain units — the existing eviction
/// plane already answers holdings for content it stores, so those arms will
/// reuse it rather than duplicate it (#564).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectRef {
    /// A CEG attestation, by `attestation_id`. Its family is resolved from the
    /// envelope `dimension`.
    Attestation {
        /// The row's `attestation_id`.
        attestation_id: String,
    },
    /// A `federation_keys` row, by `key_id`.
    KeyRecord {
        /// The row's `key_id`.
        key_id: String,
    },
}

impl ObjectRef {
    /// The identifier, whichever arm this is — for logging and for the
    /// `object_id` a consumer echoes back.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Attestation { attestation_id } => attestation_id,
            Self::KeyRecord { key_id } => key_id,
        }
    }
}

/// The KIND of dependency a [`Dependency`] records — closed, so a consumer can
/// branch on the shape of the thing that would break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// A row this node RETAINS that exists here because of the object under
    /// test — the object authorizes our holding of it.
    RetainedAttestation,
    /// A held row that NAMES the object under test (as attester, subject,
    /// scrub or co-scrub), so removing the object would leave that row
    /// dangling.
    NamingRow,
    /// The manifest DECLARES this family always load-bearing. Not an inference
    /// from the corpus — a declaration, which is the point: `trust:accepts:v1`
    /// must be load-bearing on a node that holds nothing else at all.
    DeclaredAlways,
}

impl DependencyKind {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RetainedAttestation => "retained_attestation",
            Self::NamingRow => "naming_row",
            Self::DeclaredAlways => "declared_always",
        }
    }
}

/// ONE reason an object is load-bearing: which row depends on it, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// The shape of the dependency.
    pub kind: DependencyKind,
    /// The identifier of the depending row (an `attestation_id`, a `key_id`,
    /// or — for [`DependencyKind::DeclaredAlways`] — the declaring family).
    pub object_id: String,
    /// Human-readable derivation: what would stop working.
    pub detail: String,
}

/// The verdict. **Never a bare bool** — the consumer sees WHICH dependency and
/// WHY (the `TrustRootVerdict` / `TrustedGrant` discipline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBearing {
    /// Something here depends on this object. `because` is the enumerated
    /// derivation, capped at [`MAX_DEPENDENCIES_REPORTED`] — the verdict is
    /// the same at one dependent or a thousand, and an unbounded list would
    /// make a cheap read expensive.
    Yes {
        /// The enumerated dependents.
        because: Vec<Dependency>,
    },
    /// Provably nothing on this node depends on it. Still not a licence to
    /// release: that needs stage 2's `anti_entropy_satisfied` conjunct too.
    No,
    /// **FAIL-SECURE: treated as load-bearing.** The family declares no
    /// predicate persist can evaluate, so the honest answer is "we do not
    /// know" — and not knowing means not collecting.
    Unknown {
        /// The manifest family (or [`FEDERATION_KEY_FAMILY`]) the object
        /// resolved to, or `"<unresolved>"` when the dimension matched none.
        family: String,
        /// Why the predicate could not answer — which read persist would need.
        reason: String,
    },
}

impl LoadBearing {
    /// The fail-secure reading: `Yes` AND `Unknown` are both treated as load
    /// bearing. Only a proven `No` is not.
    ///
    /// Named for what it MEANS rather than what it returns, so a caller cannot
    /// read it as "may release" — it is not. Release needs stage 2's
    /// anti-entropy conjunct as well.
    #[must_use]
    pub const fn treated_as_load_bearing(&self) -> bool {
        !matches!(self, Self::No)
    }
}

/// The cap on enumerated dependents in a [`LoadBearing::Yes`]. One dependent
/// already settles the verdict; the rest are evidence, and evidence is worth
/// bounding.
pub const MAX_DEPENDENCIES_REPORTED: usize = 16;

/// The manifest family prefix a claim `dimension` belongs to, or `None` if it
/// matches no declared family.
///
/// Matching mirrors the manifest's own prefix grammar: a literal segment must
/// match exactly, a `{placeholder}` segment matches any ONE segment, and a
/// trailing `*` matches the remaining segments. The MOST SPECIFIC match wins
/// (most literal segments, then longest), the same longest-prefix discipline
/// [`crate::federation::namespace::registry::lookup`] uses — so
/// `dma:pdma:principled_evaluation` resolves to `dma:pdma:*` rather than to a
/// broader `dma:*` if both were declared.
#[must_use]
pub fn family_for_dimension(dimension: &str) -> Option<&'static str> {
    let mut best: Option<(usize, usize, &'static str)> = None;
    for family in super::namespace::supersets::family_prefixes() {
        let Some(literals) = prefix_match_score(family, dimension) else {
            continue;
        };
        let key = (literals, family.len(), family);
        if best.is_none_or(|b| key > b) {
            best = Some(key);
        }
    }
    best.map(|(_, _, f)| f)
}

/// `Some(number_of_literal_segments_matched)` iff `family` matches
/// `dimension`; `None` otherwise. The literal count is the specificity score.
fn prefix_match_score(family: &str, dimension: &str) -> Option<usize> {
    let fam: Vec<&str> = family.split(':').collect();
    let dim: Vec<&str> = dimension.split(':').collect();
    let mut literals = 0usize;
    for (i, seg) in fam.iter().enumerate() {
        if *seg == "*" {
            // A trailing `*` consumes the remainder — but only if there IS a
            // remainder (`consent:*` describes `consent:replication:v1`, not a
            // bare `consent`).
            return if dim.len() > i { Some(literals) } else { None };
        }
        let d = dim.get(i)?;
        if seg.starts_with('{') && seg.ends_with('}') {
            continue; // a placeholder matches exactly one segment
        }
        if seg != d {
            return None;
        }
        literals += 1;
    }
    // No wildcard consumed the tail: the arities must match exactly.
    (fam.len() == dim.len()).then_some(literals)
}

/// v24.2.0 (CIRISPersist#564 stage 1) — **is `object` load-bearing on this
/// node?**
///
/// Resolves the object's family, looks up the family's declared predicate in
/// the Registry-of-Record ([`super::namespace::supersets::load_bearing_predicate`]),
/// and evaluates it against reads that exist today. A family with no declared
/// predicate — or one declared `undeclared` — resolves
/// [`LoadBearing::Unknown`], which is fail-secure.
///
/// `Err` is reserved for a real backend failure: an object that cannot be
/// found is not an error, it is [`LoadBearing::No`] with nothing to depend on
/// it. (An absent object is trivially not load-bearing; the caller asked about
/// a copy this node does not hold.)
///
/// Backend-agnostic by construction — it composes trait methods over
/// `&dyn FederationDirectory`, so memory / sqlite / postgres get identical
/// behaviour with no per-backend code.
pub async fn is_load_bearing(
    directory: &dyn FederationDirectory,
    object: ObjectRef,
) -> Result<LoadBearing, Error> {
    match object {
        ObjectRef::Attestation { attestation_id } => {
            let Some(row) = directory.get_attestation(&attestation_id).await? else {
                // Nothing here to be load-bearing. Not an error and not
                // Unknown: the absence is itself the complete answer.
                return Ok(LoadBearing::No);
            };
            attestation_load_bearing(directory, &row).await
        }
        ObjectRef::KeyRecord { key_id } => key_record_load_bearing(directory, &key_id).await,
    }
}

/// The attestation arm: resolve family → declared predicate → evaluate.
async fn attestation_load_bearing(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<LoadBearing, Error> {
    let Some(dimension) = super::admission::envelope_dimension(&row.attestation_envelope) else {
        return Ok(LoadBearing::Unknown {
            family: "<unresolved>".to_string(),
            reason: "the envelope carries no `dimension`, so no family — and therefore no \
                     declared predicate — can be resolved for it"
                .to_string(),
        });
    };
    let Some(family) = family_for_dimension(dimension) else {
        return Ok(LoadBearing::Unknown {
            family: "<unresolved>".to_string(),
            reason: format!(
                "dimension {dimension:?} matches no family in the vendored namespace manifest, so \
                 it has no declared load-bearing predicate"
            ),
        });
    };
    let Some((kind, rationale)) = super::namespace::supersets::load_bearing_predicate(family)
    else {
        return Ok(LoadBearing::Unknown {
            family: family.to_string(),
            reason: format!(
                "family {family} declares no load-bearing predicate — a manifest gap, never a \
                 licence to collect"
            ),
        });
    };
    match kind {
        "always" => Ok(LoadBearing::Yes {
            because: vec![Dependency {
                kind: DependencyKind::DeclaredAlways,
                object_id: family.to_string(),
                detail: format!(
                    "{family} is DECLARED always load-bearing (dimension {dimension}): {rationale}"
                ),
            }],
        }),
        "retained_replication" => retained_replication(directory, row, family, dimension).await,
        // `undeclared`, and any kind a future manifest cut adds that this
        // resolver has no arm for. Both are the same fact — persist cannot
        // evaluate it — and both are fail-secure.
        _ => Ok(LoadBearing::Unknown {
            family: family.to_string(),
            reason: rationale.to_string(),
        }),
    }
}

/// The `retained_replication` predicate: a `consent:replication:v1` grant is
/// load-bearing iff this node still holds at least one row authored by a peer
/// the grant names.
///
/// The grant's peers ride `subject_key_ids` (the shape
/// [`super::consent_peer_set`] projects), and what the grant authorizes is our
/// holding of what those peers replicate to us — so `list_attestations_by(peer)`
/// is exactly the dependent set. Hold nothing from any named peer and the
/// grant does no work here.
///
/// A `consent:*` row that is NOT the replication dimension resolves
/// `Unknown`: its subject binding is not the peer-set shape, and guessing that
/// it is would be a wrong `No` on a live authorization.
async fn retained_replication(
    directory: &dyn FederationDirectory,
    row: &Attestation,
    family: &'static str,
    dimension: &str,
) -> Result<LoadBearing, Error> {
    if dimension != super::consent_peer_set::DIMENSION {
        return Ok(LoadBearing::Unknown {
            family: family.to_string(),
            reason: format!(
                "the `retained_replication` predicate is defined for {} only; dimension \
                 {dimension:?} binds its subjects differently and has no evaluable predicate yet",
                super::consent_peer_set::DIMENSION
            ),
        });
    }
    let mut because: Vec<Dependency> = Vec::new();
    for peer in &row.subject_key_ids {
        for held in directory.list_attestations_by(peer).await? {
            // The grant itself is not evidence of its own necessity.
            if held.attestation_id == row.attestation_id {
                continue;
            }
            because.push(Dependency {
                kind: DependencyKind::RetainedAttestation,
                object_id: held.attestation_id.clone(),
                detail: format!(
                    "retained under this grant: a row authored by consented peer {peer}"
                ),
            });
            if because.len() >= MAX_DEPENDENCIES_REPORTED {
                return Ok(LoadBearing::Yes { because });
            }
        }
    }
    if because.is_empty() {
        // The #563 case: a grant that reduces to nothing here.
        Ok(LoadBearing::No)
    } else {
        Ok(LoadBearing::Yes { because })
    }
}

/// The key-record arm: a `federation_keys` row is load-bearing while any held
/// row names it.
///
/// Persist can prove YES from targeted reads — `list_attestations_by` (the key
/// as attester) and `list_attestations_for` (the key as subject). It cannot yet
/// prove NO: "which rows name this key as `scrub_key_id` or co-scrub" has no
/// index, and answering it would need a full corpus scan whose cost is not
/// stage 1's to spend. So a key with no attestation dependency resolves
/// `Unknown`, not `No` — the fail-secure direction, and the honest one.
async fn key_record_load_bearing(
    directory: &dyn FederationDirectory,
    key_id: &str,
) -> Result<LoadBearing, Error> {
    let mut because: Vec<Dependency> = Vec::new();
    for (rows, role) in [
        (directory.list_attestations_by(key_id).await?, "attester"),
        (directory.list_attestations_for(key_id).await?, "subject"),
    ] {
        for held in rows {
            because.push(Dependency {
                kind: DependencyKind::NamingRow,
                object_id: held.attestation_id.clone(),
                detail: format!("a held attestation names {key_id} as its {role}"),
            });
            if because.len() >= MAX_DEPENDENCIES_REPORTED {
                return Ok(LoadBearing::Yes { because });
            }
        }
    }
    if because.is_empty() {
        Ok(LoadBearing::Unknown {
            family: FEDERATION_KEY_FAMILY.to_string(),
            reason: format!(
                "no held attestation names {key_id} as attester or subject, but persist has no \
                 index answering \"which rows name it as scrub or co-scrub\" — so NOT-load-bearing \
                 is unproven, and unproven is treated as load-bearing"
            ),
        })
    } else {
        Ok(LoadBearing::Yes { because })
    }
}

/// v24.2.0 (CIRISPersist#564 stage 1) — the shared, backend-agnostic
/// behavioural witness, run by the sqlite / postgres / memory suites against
/// `&dyn FederationDirectory` so the three backends cannot silently diverge on
/// the predicate (the same discipline
/// [`super::consent_peer_set::test_support::exercise_consent_peer_set_fold`]
/// runs for the E7 projection). `suffix` scopes every fixture key so a run
/// against a shared postgres test DB does not collide with a prior one.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::{is_load_bearing, DependencyKind, LoadBearing, ObjectRef};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// A federation-tier row carrying `dimension`, authored by `author` about
    /// `subject`. One fixture for every family the witness exercises: the
    /// thing under test is which FAMILY a dimension resolves to and what its
    /// declared predicate then does, so varying anything else would only make
    /// the witness harder to read.
    fn row(
        id: &str,
        author: &str,
        subject: &str,
        att_type: &str,
        dimension: &str,
        subject_key_ids: Vec<String>,
        extra: serde_json::Value,
    ) -> Attestation {
        let mut envelope = serde_json::json!({
            "dimension": dimension,
            "payload": {"grants": "replication", "attestation_prefixes": ["lb-fixture:"]},
        });
        // Family-specific envelope requirements (e.g. `trace:*` demands a
        // `trace_id`) ride here rather than forcing a second fixture builder.
        if let (Some(obj), Some(add)) = (envelope.as_object_mut(), extra.as_object()) {
            for (k, v) in add {
                obj.insert(k.clone(), v.clone());
            }
        }
        let (och, ed_sig, pqc_sig) =
            crate::federation::tier_ingest::test_support::sign_envelope(author, &envelope);
        let now = chrono::Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: subject.to_owned(),
            attestation_type: att_type.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    async fn verdict(dir: &dyn FederationDirectory, attestation_id: &str) -> LoadBearing {
        is_load_bearing(
            dir,
            ObjectRef::Attestation {
                attestation_id: attestation_id.to_owned(),
            },
        )
        .await
        .expect("is_load_bearing")
    }

    /// How many inert grants the witness plants. #563 counted 234 of them in
    /// production; the property under test is that the verdict does not depend
    /// on HOW MANY there are — an inert grant is inert one at a time.
    const INERT_GRANTS: usize = 5;

    /// The #564 stage-1 witness:
    ///
    /// - N inert `consent:replication` grants with no dependent data read `No`
    ///   (the 234-row case, made legible);
    /// - a grant naming a peer whose trace we DO retain reads `Yes` and NAMES
    ///   that trace;
    /// - `trust:accepts:v1` reads `Yes` with nothing else present at all — the
    ///   un-trust lever, declared, never inferred;
    /// - a declared-`undeclared` family reads `Unknown` naming the family;
    /// - a dimension outside the manifest reads `Unknown` too — fail-secure,
    ///   never `No` by omission.
    pub(crate) async fn exercise_load_bearing_predicate(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::consent_peer_set::DIMENSION as CONSENT_REPLICATION;
        use crate::federation::tier_ingest::test_support::register_hybrid_key;

        let node = format!("lb-node-{suffix}");
        let inert_peer = format!("lb-inert-{suffix}");
        let live_peer = format!("lb-live-{suffix}");
        let root = format!("lb-root-{suffix}");
        register_hybrid_key(dir, &node).await;
        register_hybrid_key(dir, &live_peer).await;
        register_hybrid_key(dir, &root).await;

        // ── (1) THE 234-ROW CASE. Grants naming a peer this node holds
        //    nothing from: they authorize a holding that does not exist here,
        //    so they do no work here — regardless of age or author.
        let mut inert = Vec::new();
        for _ in 0..INERT_GRANTS {
            let id = uuid::Uuid::new_v4().to_string();
            dir.put_attestation(SignedAttestation {
                attestation: row(
                    &id,
                    &node,
                    &node,
                    attestation_type::SCORES,
                    CONSENT_REPLICATION,
                    vec![inert_peer.clone()],
                    serde_json::Value::Null,
                ),
            })
            .await
            .expect("inert grant admits");
            inert.push(id);
        }
        for id in &inert {
            assert_eq!(
                verdict(dir, id).await,
                LoadBearing::No,
                "an inert consent:replication grant ({id}) reduces to nothing here"
            );
        }

        // ── (2) The SAME grant shape, naming a peer whose trace we retain.
        let live_grant = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &live_grant,
                &node,
                &node,
                attestation_type::SCORES,
                CONSENT_REPLICATION,
                vec![live_peer.clone()],
                serde_json::Value::Null,
            ),
        })
        .await
        .expect("live grant admits");
        assert_eq!(
            verdict(dir, &live_grant).await,
            LoadBearing::No,
            "no data retained under it yet — inert until something depends on it"
        );

        let retained_trace = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &retained_trace,
                &live_peer,
                &live_peer,
                attestation_type::SCORES,
                "trace:complete:v1",
                // `trace:*` is self-emitted: the producer must appear in its
                // own `subject_key_ids` (a trace records its own reasoning).
                vec![live_peer.clone()],
                // The `trace:*` admission gate's required shape (self-emitted
                // above, identity fields + exactly one of inline/manifest
                // here) — a REAL trace, so the witness proves the predicate
                // over the row a producer actually writes.
                serde_json::json!({
                    "trace_id": format!("lb-trace-{suffix}"),
                    "agent_id_hash": "sha256:lb-fixture-agent",
                    "trace": {"step": "load-bearing witness"},
                }),
            ),
        })
        .await
        .expect("retained trace admits");

        match verdict(dir, &live_grant).await {
            LoadBearing::Yes { because } => {
                assert!(
                    because.iter().any(|d| d.object_id == retained_trace
                        && d.kind == DependencyKind::RetainedAttestation),
                    "the verdict must NAME the retained trace, not merely say yes: {because:?}"
                );
            }
            other => panic!("a grant with a retained trace under it must be Yes, got {other:?}"),
        }

        // The live data must not have changed the inert grants' verdicts —
        // load-bearing is per-object and structural, never a corpus-wide mood.
        for id in &inert {
            assert_eq!(
                verdict(dir, id).await,
                LoadBearing::No,
                "an unrelated peer's data must not make grant {id} load-bearing"
            );
        }

        // ── (3) `trust:accepts:v1` — the un-trust lever. Yes with NOTHING
        //    else present, because it is DECLARED, never inferred.
        let accepts = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &accepts,
                &node,
                &root,
                attestation_type::DELEGATES_TO,
                "trust:accepts:v1",
                Vec::new(),
                serde_json::Value::Null,
            ),
        })
        .await
        .expect("trust:accepts:v1 admits");
        match verdict(dir, &accepts).await {
            LoadBearing::Yes { because } => assert!(
                because
                    .iter()
                    .any(|d| d.kind == DependencyKind::DeclaredAlways),
                "trust:accepts:v1 must be load-bearing BY DECLARATION: {because:?}"
            ),
            other => panic!("the un-trust lever must never read collectable, got {other:?}"),
        }

        // ── (4) A declared-`undeclared` family: Unknown, naming the family.
        match verdict(dir, &retained_trace).await {
            LoadBearing::Unknown { family, reason } => {
                assert_eq!(family, "trace:*");
                assert!(!reason.is_empty(), "an Unknown must carry its reason");
            }
            other => panic!("a declared-`undeclared` family must read Unknown, got {other:?}"),
        }

        // ── (5) A dimension outside the manifest: still Unknown, never `No`.
        //    `No` by omission is the one answer this primitive may not give.
        let alien = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &alien,
                &node,
                &node,
                attestation_type::SCORES,
                "definitely_not_a_ciris_family:xyzzy:v1",
                Vec::new(),
                serde_json::Value::Null,
            ),
        })
        .await
        .expect("alien-dimension row admits");
        assert!(
            matches!(verdict(dir, &alien).await, LoadBearing::Unknown { .. }),
            "an unresolvable family is fail-secure Unknown, never No"
        );

        // ── (6) The key-record arm: a key NAMED by held rows is load-bearing.
        match is_load_bearing(
            dir,
            ObjectRef::KeyRecord {
                key_id: live_peer.clone(),
            },
        )
        .await
        .expect("key record verdict")
        {
            LoadBearing::Yes { because } => assert!(
                because
                    .iter()
                    .any(|d| d.kind == DependencyKind::NamingRow && d.object_id == retained_trace),
                "the key that authored a held row is load-bearing, and the row is named: \
                 {because:?}"
            ),
            other => panic!("a key naming held rows must be Yes, got {other:?}"),
        }

        // ── (7) An object this node does not hold: nothing here can depend on
        //    a copy that is not here.
        assert_eq!(
            verdict(dir, &uuid::Uuid::new_v4().to_string()).await,
            LoadBearing::No,
            "an absent object is trivially not load-bearing HERE"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The family resolver honours the manifest's prefix grammar: literal,
    /// `{placeholder}`, and trailing `*`.
    #[test]
    fn dimension_resolves_to_its_manifest_family() {
        assert_eq!(
            family_for_dimension(super::super::consent_peer_set::DIMENSION),
            Some("consent:*")
        );
        assert_eq!(family_for_dimension("trust:accepts:v1"), Some("trust:*"));
        assert_eq!(family_for_dimension("trace:complete:v1"), Some("trace:*"));
        assert_eq!(
            family_for_dimension("capacity:composite"),
            Some("capacity:composite"),
            "an exact literal family matches with no wildcard"
        );
        // A `{placeholder}` consumes exactly one segment.
        assert_eq!(
            family_for_dimension("bond_posted:usd"),
            Some("bond_posted:{currency}")
        );
        // A bare prefix with nothing after it is NOT the wildcard family.
        assert_eq!(family_for_dimension("consent"), None);
        assert_eq!(
            family_for_dimension("definitely:not:a:real:family:xyzzy"),
            None
        );
    }

    /// The tokens are program constants, not prose.
    #[test]
    fn dependency_kind_tokens_match_serde() {
        for kind in [
            DependencyKind::RetainedAttestation,
            DependencyKind::NamingRow,
            DependencyKind::DeclaredAlways,
        ] {
            assert_eq!(
                serde_json::to_string(&kind).expect("serialize"),
                format!("\"{}\"", kind.as_str())
            );
        }
    }

    /// **Fail-secure**: `Unknown` is treated as load-bearing. Only a proven
    /// `No` is not. If this ever inverted, an undeclared family would become a
    /// licence to collect — the exact failure the whole axis exists to prevent.
    #[test]
    fn unknown_is_treated_as_load_bearing() {
        assert!(LoadBearing::Yes { because: vec![] }.treated_as_load_bearing());
        assert!(LoadBearing::Unknown {
            family: "whatever".into(),
            reason: "no predicate".into(),
        }
        .treated_as_load_bearing());
        assert!(!LoadBearing::No.treated_as_load_bearing());
    }
}
