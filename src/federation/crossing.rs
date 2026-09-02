//! # The federation crossing — `enter_mesh` and `widen_audience`
//!
//! v39.0.0 (`FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md`). **This module
//! is the map.** Everything that decides whether a row may cross into the
//! federation tier, who signs it when it does, and what the caller must state
//! about it lives here; the backends execute a [`EnterPlan`] this module
//! computed and nothing else. If you are changing how promotion works, you are
//! changing this file.
//!
//! ## What was wrong with `promote_attestation`, in one sentence
//!
//! It re-signed the row with the *node's* key, replaced the actor's base scrub,
//! cleared every co-scrub, and changed `cohort_scope` inside the signed bytes —
//! so the fabric became the author of an actor's claim, and (because the wire
//! verifier resolves the base signature against `attesting_key_id`, never
//! `scrub_key_id` — [`super::tier_ingest::verify_row_hybrid_signature`]) every
//! peer refused the result whenever the attester was not the node.
//!
//! ## The two operations the constitution actually names
//!
//! | verb | CC | signed bytes | `cohort_scope` | who signs |
//! |---|---|---|---|---|
//! | [`FederationDirectory::enter_mesh`](super::FederationDirectory::enter_mesh) | 5.3.2.4.2 | **byte-identical** (JCS) | unchanged | the actor (base scrub); the node may **co-scrub** into `additional_scrubs` |
//! | [`FederationDirectory::widen_audience`](super::FederationDirectory::widen_audience) | 4.4.3.3.1 / 8.1.5 | a **new** `supersedes` row | strictly wider on the new row; the prior row is untouched | the actor |
//!
//! A row authored at `(local, self)` therefore crosses to `(federation, self)`
//! — the CC 5.2 shape: replicated to the owner's own nodes by consent fan-out,
//! **not discoverable** (no `holds_bytes`). Widening it to a community is a
//! second row. This is what the constitution's worked example (CC 8.1.5) shows,
//! and it is what edge's `share` composes from these two verbs.
//!
//! ## Custody — the three-key model made mechanical
//!
//! [`TierPromotionCustody`] is the caller's answer to "who signs the crossing":
//!
//! * [`TierPromotionCustody::ActorSigned`] — the actor's own hybrid signature
//!   over `JCS(envelope)`, minted now or at local write. Becomes the base
//!   scrub. Refused unless `scrub_key_id == attesting_key_id`
//!   ([`Error::CustodyIsNotTheActor`]) and unless the signed bytes canonicalize
//!   to the stored envelope ([`Error::PromotionMovedThePreimage`]).
//! * [`TierPromotionCustody::NodeCoScrub`] — the node's hybrid signature over
//!   the *same* bytes, **appended** to `additional_scrubs` with
//!   [`ScrubSig::cosigned_at`] stamped (CC 2.6.7). Refused when the row carries
//!   no actor signature to co-scrub ([`Error::NoActorSignature`]): the fabric
//!   is never the only signer of an actor's claim.
//!
//! Every signature the plan admits — the actor's, the node's, and each
//! pre-existing co-scrub — is **verified here, before the flip**, against the
//! signer's registered pubkeys under `HybridPolicy::Strict`. That is the
//! answer to #556/#557's reason for clearing co-scrubs (they were stored
//! unverified): the preserve set equals the verified set because this door
//! verifies it.
//!
//! ## `created` / `modified`
//!
//! `asserted_at` is already a signed member of the envelope (#598) — it is
//! `created`, and the actor bound it. `cosigned_at` is `modified`: it rides on
//! the [`ScrubSig`], **outside** the preimage, so a co-scrub never changes the
//! bytes the actor signed. [`MeshCrossing::age_at_crossing`] reports
//! `now − asserted_at` so the CC 2.6.7 window is observable; the *engine*
//! chooses the custody path, this module admits either.
//!
//! ## The nine axes (CC 4.5.1.1)
//!
//! Both verbs take a [`ContextualIntegrity`]. Every axis is required, every
//! axis is **cross-checked against the row**, and every mismatch is a typed
//! refusal naming the axis ([`Error::ContextualIntegrityMismatch`]). The type is
//! the checklist; the crossing is the moment the answers become irrevocable
//! because edge replicates the row on its next round.
//!
//! ## Where the pieces are
//!
//! * [`plan_enter_mesh`] — verify custody + co-scrubs, canonicalize,
//!   run [`super::admission::check_promotion_admission`], cross-check the
//!   axes, hash. Returns the row **as it will be stored**. Backends write it.
//! * [`check_widening`] — the pure shape rule for a `supersedes` widening.
//! * [`check_contextual_integrity`] — the nine cross-checks (shared by both).
//! * [`report`] — the [`MeshCrossing`] a caller gets back.
//! * [`canonical_bytes`] — the ONE spelling of "the bytes a signer signs".
//! * [`build_widening`] — the supersedes envelope for a widening, built from
//!   the prior so the payload is reused (CC 8.1.5: no body re-upload).
//!
//! Sign-at-write for local rows (so a deferred row has something to co-scrub)
//! is the local door's job: [`super::types::LocalAttestationInput::bind_for_signing`]
//! and [`super::admission::verify_caller_signed_local_row`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::admission::{self, check_promotion_admission};
use super::envelope::{paths, row_paths};
use super::namespace::{attestation_family, AttestationFamily};
use super::precedence::references_attestation_id_from_envelope;
use super::types::{attestation_tier, attestation_type, cohort_scope, ScrubSig};
use super::{Attestation, AttestationReseal, Error, FederationDirectory};

// ─────────────────────────────────────────────────────────────────────────
// The nine axes.
// ─────────────────────────────────────────────────────────────────────────

/// The nine CC 4.5.1.1 axes, answered explicitly at the federation crossing.
///
/// Every field is required and every field is cross-checked against the row by
/// [`check_contextual_integrity`]. A crossing that cannot name one of these is
/// a crossing whose consequences nobody stated. Edge re-exports this type; its
/// `With` audience vocabulary maps onto [`Audience`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextualIntegrity {
    /// `sender` — who is speaking. MUST equal the row's `attesting_key_id`;
    /// the fabric is never the sender of an actor's claim.
    pub sender: String,
    /// `data_subject` — who the claim is ABOUT. Mirrors `subject_key_ids`;
    /// [`DataSubject::Nobody`] is an explicit answer, not an omission.
    pub data_subject: DataSubject,
    /// `recipient_see` — who may learn the row exists: the `cohort_scope`.
    /// For `enter_mesh` it must equal the row's bound scope (the bytes
    /// do not change); for `widen_audience` it is the NEW row's scope.
    pub recipient_see: Audience,
    /// `recipient_revoke` — who may withdraw it (CC 2.4.1.1). Derived from
    /// `subject_key_ids` and stated back so the caller SEES the authority the
    /// crossing confers.
    pub recipient_revoke: RevocationAuthority,
    /// `recipient_receive` — how the bytes reach the recipient. Mirrors the
    /// envelope's `delivery_mode` (absent ⇔ best-effort).
    pub recipient_receive: DeliveryMode,
    /// `information_type` — the dimension family
    /// ([`attestation_family`] of the envelope `dimension`), so the per-family
    /// norm is the one applied.
    pub information_type: AttestationFamily,
    /// `transmission_principle` — what the crossing rides on: producer
    /// authority, or a named live consent grant that covers this dimension at
    /// this audience.
    pub transmission_principle: CrossingBasis,
    /// `temporal_lifecycle` — the signed instants, stated back.
    pub temporal_lifecycle: Lifecycle,
    /// `content` — the content hash the crossing commits to: the hex SHA-256
    /// of `JCS(envelope)` for `enter_mesh`; the PRIOR row's for
    /// `widen_audience` (reused, CC 8.1.5).
    pub content: ContentRef,
}

/// `data_subject`: nobody, or exactly the row's `subject_key_ids`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DataSubject {
    /// The row names no subject (`subject_key_ids` is empty).
    Nobody,
    /// The row's subjects — order-insensitive, compared as a set.
    Keys {
        /// The subjects, as `subject_key_ids`.
        key_ids: Vec<String>,
    },
}

/// `recipient_revoke`: the producer alone, or the named subjects as well
/// (CC 2.4.1.1 — a subject may withdraw a claim about itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevocationAuthority {
    /// No subject is named; only the producer may withdraw.
    ProducerOnly,
    /// The named subjects may withdraw as well as the producer.
    Subjects {
        /// The subjects, as `subject_key_ids`.
        key_ids: Vec<String>,
    },
}

/// `recipient_see`: the closed `cohort_scope` vocabulary as a type, in
/// widening order — and, for the two TARGETED placements, WHICH family or
/// community. A cohort placement is a membership claim the put door proves
/// (AV-45, [`admission::DimensionAdmissionPolicy::check_write_cohort_scope`])
/// against the cohort the row names, so a family/community audience without
/// its id is not an audience. Edge's `With::MyFamily` / `With::Community(id)`
/// map onto these. [`Audience::discoverable`] is CC 5.2: `self`/`family`
/// replicate by consent fan-out but never emit `holds_bytes`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// `self` — the owner's own nodes (CC 5.2: not discoverable).
    SelfOnly,
    /// `family` — that family's nodes (CC 5.2: not discoverable).
    Family {
        /// The family the row is placed in (`family_key_id`).
        family_key_id: String,
    },
    /// `community` — that community's members.
    Community {
        /// The community the row is placed in (`community_key_id`).
        community_key_id: String,
    },
    /// `affiliations`.
    Affiliations,
    /// `species`.
    Species,
    /// `biosphere`.
    Biosphere,
    /// `federation` — the widest audience.
    Federation,
}

impl Audience {
    /// The wire `cohort_scope` value.
    #[must_use]
    pub fn cohort_scope(&self) -> &'static str {
        match self {
            Self::SelfOnly => cohort_scope::SELF,
            Self::Family { .. } => cohort_scope::FAMILY,
            Self::Community { .. } => cohort_scope::COMMUNITY,
            Self::Affiliations => cohort_scope::AFFILIATIONS,
            Self::Species => cohort_scope::SPECIES,
            Self::Biosphere => cohort_scope::BIOSPHERE,
            Self::Federation => cohort_scope::FEDERATION,
        }
    }

    /// The cohort the placement names, for `family` / `community`.
    #[must_use]
    pub fn cohort_target(&self) -> Option<&str> {
        match self {
            Self::Family { family_key_id } => Some(family_key_id),
            Self::Community { community_key_id } => Some(community_key_id),
            _ => None,
        }
    }

    /// The envelope member a placement's target rides in (the canonical alias
    /// among [`admission::COHORT_TARGET_ENVELOPE_FIELDS`] for that scope).
    #[must_use]
    pub fn cohort_target_member(&self) -> Option<&'static str> {
        match self {
            Self::Family { .. } => Some("family_key_id"),
            Self::Community { .. } => Some("community_key_id"),
            _ => None,
        }
    }

    /// Build from a wire `cohort_scope` and the cohort target the row names
    /// (`admission::envelope_cohort_target`). A `family`/`community` scope
    /// without a target is refused: a cohort placement names its cohort.
    pub fn from_cohort_scope(scope: &str, target: Option<&str>) -> Result<Self, Error> {
        let need = |what: &str| {
            Error::InvalidArgument(format!(
                "audience {scope:?} names no {what} — a cohort placement is a membership claim \
                 about ONE cohort (AV-45), so the row must carry its `{what}`"
            ))
        };
        Ok(match scope {
            cohort_scope::SELF => Self::SelfOnly,
            cohort_scope::FAMILY => Self::Family {
                family_key_id: target.ok_or_else(|| need("family_key_id"))?.to_owned(),
            },
            cohort_scope::COMMUNITY => Self::Community {
                community_key_id: target.ok_or_else(|| need("community_key_id"))?.to_owned(),
            },
            cohort_scope::AFFILIATIONS => Self::Affiliations,
            cohort_scope::SPECIES => Self::Species,
            cohort_scope::BIOSPHERE => Self::Biosphere,
            cohort_scope::FEDERATION => Self::Federation,
            other => {
                return Err(Error::InvalidArgument(format!(
                    "{other:?} is not a cohort_scope"
                )))
            }
        })
    }

    /// The audience a stored row HAS: its `cohort_scope` plus the cohort
    /// target its envelope names.
    pub fn of_row(row: &Attestation) -> Result<Self, Error> {
        let target = admission::envelope_cohort_target(&row.attestation_envelope)?;
        Self::from_cohort_scope(&row.cohort_scope, target)
    }

    /// CC 5.2 — whether the row emits `holds_bytes`. `self`/`family` do NOT:
    /// they still replicate (to the owner's / the family's nodes, by consent
    /// fan-out) but are structurally undiscoverable.
    #[must_use]
    pub fn discoverable(&self) -> bool {
        !cohort_scope::suppresses_holds_bytes(self.cohort_scope())
    }
}

/// `recipient_receive`: the envelope's `delivery_mode` vocabulary
/// ([`admission::DELIVERY_MODE_VOCABULARY`]) as a type. Absent on the wire ⇔
/// [`DeliveryMode::BestEffort`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// `delivery_mode` absent: may-drop delivery.
    BestEffort,
    /// `delivery_mode = "mandatory"`.
    Mandatory,
}

impl DeliveryMode {
    /// The wire value; `None` is the absent member.
    #[must_use]
    pub fn wire(self) -> Option<&'static str> {
        match self {
            Self::BestEffort => None,
            Self::Mandatory => Some("mandatory"),
        }
    }
}

/// `transmission_principle`: what the crossing rides on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CrossingBasis {
    /// A producer-authority row: the actor publishes its own claim on its own
    /// authority (CC 5.3.2.2). The admission stack decides whether that is
    /// enough for this family (consent-gated families refuse it there).
    ProducerAuthority,
    /// A live, self-authored, egress `consent:replication:v1` grant that
    /// covers this row's dimension at this audience. Verified by
    /// [`check_contextual_integrity`] against the stored grant.
    ConsentGrant {
        /// The grant row's `attestation_id`.
        attestation_id: String,
    },
}

/// `temporal_lifecycle`: the row's signed instants, stated back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    /// `created` — the signed `asserted_at`.
    pub asserted_at: DateTime<Utc>,
    /// The signed `expires_at`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// `content`: the content hash the crossing commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentRef {
    /// Hex SHA-256 of `JCS(envelope)` — `original_content_hash`.
    Sha256Hex {
        /// Lowercase hex, 64 characters.
        hash: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────
// Custody and outcome.
// ─────────────────────────────────────────────────────────────────────────

/// Who signs a tier crossing. See the module doc, "Custody".
#[derive(Debug, Clone)]
pub enum TierPromotionCustody {
    /// The actor's own hybrid signature over `JCS(envelope)`. Becomes the
    /// base scrub. `reseal.attestation_envelope` must canonicalize to the
    /// stored bytes and `reseal.scrub_key_id` must be the attester.
    ActorSigned(AttestationReseal),
    /// The node's hybrid signature over the same bytes, appended to
    /// `additional_scrubs`. Requires an existing actor signature, and
    /// [`ScrubSig::cosigned_at`] MUST be set: the co-signer stamps when it
    /// signed — the crossing does not stamp on its behalf.
    NodeCoScrub(ScrubSig),
}

impl TierPromotionCustody {
    /// **The instant the crossing happened**, taken from the party that
    /// signed: the actor's `scrub_timestamp`, or the node's `cosigned_at`.
    ///
    /// Every instant the crossing writes — `promoted_at`, `scrub_timestamp`,
    /// `pqc_completed_at`, and the age it reports — is this one value, so the
    /// same op sequence produces byte-identical rows on every backend. It used
    /// to be `Utc::now()` sampled inside each backend, which made the SAME
    /// promotion diverge between memory and sqlite (the substrate state
    /// machine's I5, caught by `substrate_state_machine_holds_on_every_backend`)
    /// and, worse, made a crossing unreplayable: `persist_row_hash` covers
    /// `promoted_at`, so the row a peer verifies depended on which clock the
    /// storage layer happened to read.
    pub fn crossing_at(&self) -> Result<DateTime<Utc>, Error> {
        match self {
            Self::ActorSigned(reseal) => Ok(reseal.scrub_timestamp),
            Self::NodeCoScrub(scrub) => {
                let raw = scrub.cosigned_at.as_deref().ok_or_else(|| {
                    Error::InvalidArgument(
                        "TierPromotionCustody::NodeCoScrub carries no `cosigned_at` — the \
                         co-signer stamps the moment it signed (CC 2.6.7); the crossing does not \
                         stamp on its behalf, because that instant is written into the row and \
                         must be the same on every backend"
                            .to_owned(),
                    )
                })?;
                DateTime::parse_from_rfc3339(raw)
                    .map(|t| t.with_timezone(&Utc))
                    .map_err(|e| {
                        Error::InvalidArgument(format!(
                            "`cosigned_at` {raw:?} is not RFC-3339: {e}"
                        ))
                    })
            }
        }
    }
}

/// How the crossed row is signed, as applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Custody {
    /// The base scrub is the actor's; no node co-scrub was added by this
    /// crossing.
    ActorSigned,
    /// The base scrub is the actor's and this crossing appended the node's
    /// co-scrub, stamped `cosigned_at`.
    ActorSignedNodeCoScrubbed {
        /// The co-scrub's `cosigned_at`, as stamped (CC 2.6.2 `.sssZ`).
        cosigned_at: String,
    },
}

/// What persist can state about replication after the crossing — and no
/// more. WHERE the bytes go (`routes_to`) is edge's to state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replicates {
    /// The wire kinds this row is served under.
    pub kinds: Vec<String>,
    /// CC 5.2 — `false` for `self`/`family`: replicated by consent fan-out,
    /// never advertised via `holds_bytes`.
    pub discoverable: bool,
}

/// The row that is now on the wire, and what edge will do with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshCrossing {
    /// The row on the wire — the same id for `enter_mesh`, the NEW
    /// `supersedes` row's id for `widen_audience`.
    pub attestation_id: String,
    /// `recipient_see`, as applied.
    pub audience: Audience,
    /// Who signed, as applied.
    pub custody: Custody,
    /// `now − asserted_at` — the CC 2.6.7 window, observable.
    pub age_at_crossing_ms: i64,
    /// What persist can state about replication.
    pub replicates: Replicates,
}

/// Every way a crossing call ends without an error. Typed, so "it did not
/// cross" is something a caller reads rather than infers from silence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MeshCrossingOutcome {
    /// The row crossed (or, for `widen_audience`, the new row was written).
    Crossed(MeshCrossing),
    /// Idempotent: the row was already federation-tier. Nothing was touched
    /// (CC 5.3.2.4.2).
    AlreadyInMesh {
        /// The row that was already in the mesh.
        attestation_id: String,
    },
    /// Idempotent: a `supersedes` by this attester already references the
    /// prior row, so the put door deduplicated the widening (CEG §6.1) and no
    /// row was written. Widen the LATEST row in the chain instead.
    AlreadyWidened {
        /// The prior that already has a widening by its attester.
        prior_attestation_id: String,
    },
    /// The row is unsigned and the caller handed over no actor signer. It
    /// WAITS — there is nothing to co-scrub. Produced by the engine, never by
    /// the directory primitive (which is always given a custody).
    AwaitingActor {
        /// The row that waits.
        attestation_id: String,
        /// `now − asserted_at`, so the CC 2.6.7 window is observable.
        age_ms: i64,
    },
}

// ─────────────────────────────────────────────────────────────────────────
// The one spelling of "the bytes a signer signs".
// ─────────────────────────────────────────────────────────────────────────

/// Canonicalize `envelope` in place (canonical at rest, #647) and return the
/// JCS bytes plus their hex SHA-256. Every signer and every verifier in this
/// module goes through here, so "same bytes" has exactly one meaning.
pub fn canonical_bytes(envelope: &mut serde_json::Value) -> Result<(Vec<u8>, String), Error> {
    use sha2::{Digest, Sha256};
    super::canonical_at_rest::canonicalize_in_place(envelope)
        .map_err(|e| Error::Backend(format!("crossing canonicalize at rest: {e}")))?;
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| Error::Backend(format!("crossing canonicalize: {e}")))?;
    let hash = hex::encode(Sha256::digest(&bytes));
    Ok((bytes, hash))
}

// ─────────────────────────────────────────────────────────────────────────
// enter_mesh — the plan.
// ─────────────────────────────────────────────────────────────────────────

/// The row as it will be stored, plus the report. Backends write `row` in one
/// statement (`tier`, `promoted_at`, the scrub columns, `additional_scrubs`,
/// the canonical envelope, `original_content_hash`, `pqc_completed_at`,
/// `persist_row_hash`) guarded by `WHERE tier = 'local'`, then return
/// `crossing`.
#[derive(Debug, Clone)]
pub struct EnterPlan {
    /// The row as it will be stored: canonical envelope, custody applied,
    /// `tier = federation`, `promoted_at`, `persist_row_hash`.
    pub row: Attestation,
    /// What the caller gets back once the write lands.
    pub crossing: MeshCrossing,
}

/// Compute the [`EnterPlan`] for a tier crossing, or `Ok(None)` when the row is
/// already federation-tier (idempotent). Verify-before-mutation: this reads and
/// verifies; it writes nothing. The backend's only job afterwards is the
/// single UPDATE.
///
/// Order, cheapest refusal first: tier check → custody shape (pure) →
/// canonical bytes + preimage identity (pure) → signature verification
/// (directory reads + crypto) → the promotion admission stack → the nine-axis
/// cross-check → hash.
pub async fn plan_enter_mesh(
    dir: &dyn FederationDirectory,
    current: &Attestation,
    ci: &ContextualIntegrity,
    custody: &TierPromotionCustody,
    self_key_id: Option<&str>,
) -> Result<Option<EnterPlan>, Error> {
    if current.tier == attestation_tier::FEDERATION {
        return Ok(None);
    }
    // Deterministic on every backend: the signer's own instant, never a clock
    // read inside the storage layer. See `TierPromotionCustody::crossing_at`.
    let now = custody.crossing_at()?;
    let mut row = current.clone();
    // Canonical at rest: the local door stores the producer's tokens verbatim
    // (`1.0` vs `1`); JCS(x) == JCS(canonical(x)), so this is not a preimage
    // move — it makes the stored column sha256 to `original_content_hash`.
    let (_bytes, computed_hash) = canonical_bytes(&mut row.attestation_envelope)?;

    let applied = match custody {
        TierPromotionCustody::ActorSigned(reseal) => {
            if reseal.scrub_key_id != row.attesting_key_id {
                return Err(Error::CustodyIsNotTheActor {
                    attestation_id: row.attestation_id.clone(),
                    attesting_key_id: row.attesting_key_id.clone(),
                    scrub_key_id: reseal.scrub_key_id.clone(),
                });
            }
            let mut offered = reseal.attestation_envelope.clone();
            let (_offered_bytes, offered_hash) = canonical_bytes(&mut offered)?;
            if offered_hash != computed_hash {
                return Err(Error::PromotionMovedThePreimage {
                    attestation_id: row.attestation_id.clone(),
                    stored_hash: computed_hash,
                    offered_hash,
                });
            }
            // The actor's signature verifies against the actor's REGISTERED
            // pubkeys, Strict — exactly what every peer's ingest will ask.
            super::verify_envelope_hybrid_signature(
                dir,
                &row.attesting_key_id,
                &row.attestation_envelope,
                &reseal.scrub_signature_classical,
                reseal.scrub_signature_pqc.as_deref(),
            )
            .await?;
            row.original_content_hash = computed_hash.clone();
            row.scrub_signature_classical = reseal.scrub_signature_classical.clone();
            row.scrub_signature_pqc = reseal.scrub_signature_pqc.clone();
            row.scrub_key_id = reseal.scrub_key_id.clone();
            row.scrub_timestamp = reseal.scrub_timestamp;
            Custody::ActorSigned
        }
        TierPromotionCustody::NodeCoScrub(scrub) => {
            if row.scrub_signature_classical.is_empty() {
                return Err(Error::NoActorSignature {
                    attestation_id: row.attestation_id.clone(),
                    attesting_key_id: row.attesting_key_id.clone(),
                });
            }
            if scrub.scrub_key_id == row.attesting_key_id {
                return Err(Error::InvalidArgument(format!(
                    "attestation {}: a co-scrub by the attester {} is a re-sign, not custody — \
                     pass TierPromotionCustody::ActorSigned",
                    row.attestation_id, row.attesting_key_id
                )));
            }
            if row.original_content_hash != computed_hash {
                return Err(Error::PromotionMovedThePreimage {
                    attestation_id: row.attestation_id.clone(),
                    stored_hash: row.original_content_hash.clone(),
                    offered_hash: computed_hash,
                });
            }
            // The base scrub the row already carries is the actor's; it is
            // verified here because a signed local row was stored on the
            // producer's word and this is the door where that word is checked.
            super::verify_envelope_hybrid_signature(
                dir,
                &row.attesting_key_id,
                &row.attestation_envelope,
                &row.scrub_signature_classical,
                row.scrub_signature_pqc.as_deref(),
            )
            .await?;
            super::verify_envelope_hybrid_signature(
                dir,
                &scrub.scrub_key_id,
                &row.attestation_envelope,
                &scrub.scrub_signature_classical,
                scrub.scrub_signature_pqc.as_deref(),
            )
            .await?;
            // `cosigned_at` is the co-signer's own stamp, already verified
            // parseable by `crossing_at` above; it rides OUTSIDE the preimage,
            // so appending it cannot disturb the bytes the actor signed.
            let cosigned_at = admission::render_signed_instant(now);
            row.additional_scrubs.push(ScrubSig {
                cosigned_at: Some(cosigned_at.clone()),
                ..scrub.clone()
            });
            Custody::ActorSignedNodeCoScrubbed { cosigned_at }
        }
    };
    // Pre-existing co-scrubs: the preserve set must equal the verified set
    // (#541/#556). Verified at THIS door, over the same bytes; refused if
    // unverifiable — never cleared.
    let inherited = match &applied {
        Custody::ActorSigned => row.additional_scrubs.len(),
        Custody::ActorSignedNodeCoScrubbed { .. } => row.additional_scrubs.len() - 1,
    };
    for (i, scrub) in row.additional_scrubs.iter().take(inherited).enumerate() {
        super::verify_envelope_hybrid_signature(
            dir,
            &scrub.scrub_key_id,
            &row.attestation_envelope,
            &scrub.scrub_signature_classical,
            scrub.scrub_signature_pqc.as_deref(),
        )
        .await
        .map_err(|e| match e {
            Error::FederationTierUnverified {
                attestation_id: _,
                attesting_key_id,
                reason,
            } => Error::FederationTierUnverified {
                attestation_id: row.attestation_id.clone(),
                attesting_key_id,
                reason: format!("additional_scrubs[{i}] at the crossing: {reason}"),
            },
            other => other,
        })?;
    }

    row.tier = attestation_tier::FEDERATION.to_owned();
    row.promoted_at = Some(now);
    // Strict verification above guarantees the PQC half is present.
    row.pqc_completed_at = Some(now);

    check_promotion_admission(dir, &row, self_key_id).await?;
    check_contextual_integrity(dir, &row, &row, ci, &row.cohort_scope.clone(), false, now).await?;

    let mut for_hash = row.clone();
    for_hash.persist_row_hash = String::new();
    row.persist_row_hash = super::types::compute_persist_row_hash(&for_hash)?;

    let crossing = report(&row, applied, now);
    Ok(Some(EnterPlan { row, crossing }))
}

/// The [`MeshCrossing`] for a row now on the wire.
#[must_use]
pub fn report(row: &Attestation, custody: Custody, now: DateTime<Utc>) -> MeshCrossing {
    // Every write door proves the row's placement before it is stored; a row
    // whose audience cannot be read back is corrupt and reported as the
    // narrowest audience rather than a wider one.
    let audience = Audience::of_row(row).unwrap_or(Audience::SelfOnly);
    let discoverable = audience.discoverable();
    MeshCrossing {
        attestation_id: row.attestation_id.clone(),
        audience,
        custody,
        age_at_crossing_ms: (now - row.asserted_at).num_milliseconds(),
        replicates: Replicates {
            kinds: vec!["Attestation".to_owned()],
            discoverable,
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The nine cross-checks.
// ─────────────────────────────────────────────────────────────────────────

fn mismatch(row: &Attestation, axis: &'static str, stated: String, actual: String) -> Error {
    Error::ContextualIntegrityMismatch {
        attestation_id: row.attestation_id.clone(),
        axis,
        stated,
        row: actual,
    }
}

fn sorted(ids: &[String]) -> Vec<&str> {
    let mut v: Vec<&str> = ids.iter().map(String::as_str).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Cross-check every axis of `ci`. Seven axes are checked against `row` —
/// the row AS IT WILL BE STORED — and `expected_scope`, the scope the crossing
/// lands at (the row's own for `enter_mesh`, the new row's for
/// `widen_audience`), so a caller cannot describe one audience and land
/// another. `temporal_lifecycle` and `content` are checked against `claim`:
/// the row itself for `enter_mesh`; for `widen_audience` the PRIOR, because a
/// widening describes the claim being widened (whose instants and content the
/// actor already signed) — the new row's own instant and hash do not exist
/// until it is stamped and signed. Refuses with
/// [`Error::ContextualIntegrityMismatch`] naming the axis.
pub async fn check_contextual_integrity<D>(
    dir: &D,
    row: &Attestation,
    claim: &Attestation,
    ci: &ContextualIntegrity,
    expected_scope: &str,
    widening: bool,
    now: DateTime<Utc>,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    if ci.sender != row.attesting_key_id {
        return Err(mismatch(
            row,
            "sender",
            ci.sender.clone(),
            row.attesting_key_id.clone(),
        ));
    }
    let subjects = sorted(&row.subject_key_ids);
    match &ci.data_subject {
        DataSubject::Nobody if subjects.is_empty() => {}
        DataSubject::Keys { key_ids } if sorted(key_ids) == subjects => {}
        other => {
            return Err(mismatch(
                row,
                "data_subject",
                format!("{other:?}"),
                format!("subject_key_ids {subjects:?}"),
            ))
        }
    }
    let expected_audience = Audience::from_cohort_scope(
        expected_scope,
        admission::envelope_cohort_target(&row.attestation_envelope)?,
    )?;
    if ci.recipient_see != expected_audience {
        return Err(mismatch(
            row,
            "recipient_see",
            format!("{:?}", ci.recipient_see),
            format!("{expected_audience:?}"),
        ));
    }
    match &ci.recipient_revoke {
        RevocationAuthority::ProducerOnly if subjects.is_empty() => {}
        RevocationAuthority::Subjects { key_ids } if sorted(key_ids) == subjects => {}
        other => {
            return Err(mismatch(
                row,
                "recipient_revoke",
                format!("{other:?}"),
                format!("subject_key_ids {subjects:?}"),
            ))
        }
    }
    let wire_delivery = row
        .attestation_envelope
        .get(paths::DELIVERY_MODE)
        .and_then(serde_json::Value::as_str);
    if wire_delivery != ci.recipient_receive.wire() {
        return Err(mismatch(
            row,
            "recipient_receive",
            format!("{:?}", ci.recipient_receive),
            format!("delivery_mode {wire_delivery:?}"),
        ));
    }
    let dimension = admission::envelope_dimension(&row.attestation_envelope).ok_or_else(|| {
        mismatch(
            row,
            "information_type",
            format!("{:?}", ci.information_type),
            "the envelope carries no `dimension`".to_owned(),
        )
    })?;
    let family = attestation_family(dimension);
    if family != ci.information_type {
        return Err(mismatch(
            row,
            "information_type",
            format!("{:?}", ci.information_type),
            format!("{family:?} ({dimension})"),
        ));
    }
    match &ci.transmission_principle {
        CrossingBasis::ProducerAuthority => {}
        CrossingBasis::ConsentGrant { attestation_id } => {
            // At `enter_mesh` the grant must COVER the dimension; the audience
            // it names is where a widening goes. At `widen_audience` it must
            // also name exactly the audience being widened to.
            let audience = widening.then_some(expected_scope);
            check_grant_covers(dir, row, attestation_id, dimension, audience, now).await?;
        }
    }
    if ci.temporal_lifecycle.asserted_at != claim.asserted_at
        || ci.temporal_lifecycle.expires_at != claim.expires_at
    {
        return Err(mismatch(
            row,
            "temporal_lifecycle",
            format!("{:?}", ci.temporal_lifecycle),
            format!(
                "asserted_at {} expires_at {:?}",
                admission::render_signed_instant(claim.asserted_at),
                claim.expires_at.map(admission::render_signed_instant)
            ),
        ));
    }
    let ContentRef::Sha256Hex { hash } = &ci.content;
    if hash != &claim.original_content_hash {
        return Err(mismatch(
            row,
            "content",
            hash.clone(),
            claim.original_content_hash.clone(),
        ));
    }
    Ok(())
}

/// `transmission_principle = ConsentGrant`: the named grant must exist at the
/// federation tier, be authored by the sender, parse under the closed #510
/// grammar as a live egress grant over `Attestation`, cover `dimension`, and —
/// when `audience` is given (a widening) — name exactly that audience. Same
/// predicate the consent sweep applies — spelled once, here.
async fn check_grant_covers<D>(
    dir: &D,
    row: &Attestation,
    grant_id: &str,
    dimension: &str,
    audience: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    use super::consent_grammar::{self, Direction};
    let refuse = |why: String| {
        mismatch(
            row,
            "transmission_principle",
            format!("consent grant {grant_id}"),
            why,
        )
    };
    let grant = dir
        .get_attestation(grant_id)
        .await?
        .ok_or_else(|| refuse("the grant does not exist".to_owned()))?;
    if grant.tier != attestation_tier::FEDERATION {
        return Err(refuse("the grant is not federation-tier".to_owned()));
    }
    if grant.attesting_key_id != row.attesting_key_id {
        return Err(refuse(format!(
            "the grant is authored by {}, not the sender",
            grant.attesting_key_id
        )));
    }
    if grant.expires_at.is_some_and(|t| t <= now) {
        return Err(refuse("the grant has expired".to_owned()));
    }
    let policy = consent_grammar::parse_grant_payload(&grant.attestation_envelope)
        .map_err(|e| refuse(format!("the grant fails the closed grammar: {e}")))?;
    if policy.direction != Direction::Egress {
        return Err(refuse("the grant is not an egress grant".to_owned()));
    }
    if !policy.kinds.iter().any(|k| k == "Attestation") {
        return Err(refuse("the grant does not cover Attestation".to_owned()));
    }
    if policy.valid_until.is_some_and(|t| t <= now) {
        return Err(refuse("the grant's valid_until has passed".to_owned()));
    }
    if !consent_grammar::covers(&policy.attestation_prefixes, dimension) {
        return Err(refuse(format!(
            "the grant does not cover dimension {dimension}"
        )));
    }
    if let Some(audience) = audience {
        if policy.audience != audience {
            return Err(refuse(format!(
                "the grant's audience is {}, not {audience}",
                policy.audience
            )));
        }
    }
    Ok(())
}

/// Derive the nine axes FROM a row — the description a truthful caller would
/// state — with `recipient_see` and the basis given ([`Audience::of_row`] for
/// a tier crossing; the target audience for a widening). This is how the
/// substrate's own sweep describes a row it is acting on under its own grant,
/// and how a consumer starts from the truth and overrides what it means to
/// change. It is not a bypass: [`check_contextual_integrity`] still runs on
/// whatever is passed, so a caller that edits an axis to a lie is refused.
///
/// `content` is the stored `original_content_hash` when the row is signed,
/// else the hash the crossing WILL compute (`JCS` of the canonical envelope) —
/// the same value either way.
pub fn describe(
    row: &Attestation,
    recipient_see: Audience,
    basis: CrossingBasis,
) -> Result<ContextualIntegrity, Error> {
    let dimension = admission::envelope_dimension(&row.attestation_envelope).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "crossing::describe: attestation {} carries no `dimension`",
            row.attestation_id
        ))
    })?;
    let content = if row.original_content_hash.is_empty() {
        let mut envelope = row.attestation_envelope.clone();
        canonical_bytes(&mut envelope)?.1
    } else {
        row.original_content_hash.clone()
    };
    let subjects = if row.subject_key_ids.is_empty() {
        None
    } else {
        Some(row.subject_key_ids.clone())
    };
    Ok(ContextualIntegrity {
        sender: row.attesting_key_id.clone(),
        data_subject: match &subjects {
            None => DataSubject::Nobody,
            Some(ids) => DataSubject::Keys {
                key_ids: ids.clone(),
            },
        },
        recipient_see,
        recipient_revoke: match subjects {
            None => RevocationAuthority::ProducerOnly,
            Some(key_ids) => RevocationAuthority::Subjects { key_ids },
        },
        recipient_receive: match row
            .attestation_envelope
            .get(paths::DELIVERY_MODE)
            .and_then(serde_json::Value::as_str)
        {
            Some("mandatory") => DeliveryMode::Mandatory,
            _ => DeliveryMode::BestEffort,
        },
        information_type: attestation_family(dimension),
        transmission_principle: basis,
        temporal_lifecycle: Lifecycle {
            asserted_at: row.asserted_at,
            expires_at: row.expires_at,
        },
        content: ContentRef::Sha256Hex { hash: content },
    })
}

// ─────────────────────────────────────────────────────────────────────────
// widen_audience — the shape rule.
// ─────────────────────────────────────────────────────────────────────────

/// The envelope members a widening legitimately changes because they ARE the
/// placement: the typed-column mirror, the signed instants, the widening's own
/// reference and `differs_in`, and the cohort-target aliases that name WHICH
/// family or community. Everything else is the prior's body, reused.
fn is_placement_member(member: &str) -> bool {
    matches!(
        member,
        paths::ROW | paths::ASSERTED_AT | paths::EXPIRES_AT | paths::REFERENCES_ATTESTATION_ID
    ) || member == paths::DIFFERS_IN
        || admission::COHORT_TARGET_ENVELOPE_FIELDS.contains(&member)
}

/// Does a `differs_in` entry account for a difference in top-level `member`?
/// Entries are JSON-pointer paths (`/agent_id_hash`, `/trace/step`) or bare
/// member names; a nested pointer accounts for a CHANGE to the member it
/// descends into, a top-level one for its absence.
fn differs_in_covers(entry: &str, member: &str) -> bool {
    let e = entry.strip_prefix('/').unwrap_or(entry);
    e == member
        || e.strip_prefix(member)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Envelope members a widening never touches and never lists in
/// `differs_in`: the identity of the claim, the signed instants, the mirror,
/// and the widening's own bookkeeping.
pub const WIDENING_PROTECTED_MEMBERS: [&str; 7] = [
    paths::DIMENSION,
    "trace_id",
    paths::ROW,
    paths::ASSERTED_AT,
    paths::EXPIRES_AT,
    paths::REFERENCES_ATTESTATION_ID,
    paths::DIFFERS_IN,
];

fn scope_rank(s: &str) -> Option<usize> {
    cohort_scope::ALL.iter().position(|v| *v == s)
}

/// `requested` must be strictly wider than the prior's `cohort_scope` in the
/// closed widening order ([`cohort_scope::ALL`]); else
/// [`Error::AudienceNotWider`]. Pure and free, so callers ask it before they
/// sign anything.
pub fn check_strictly_wider(prior: &Attestation, requested: &str) -> Result<(), Error> {
    match (scope_rank(&prior.cohort_scope), scope_rank(requested)) {
        (Some(from), Some(to)) if to > from => Ok(()),
        _ => Err(Error::AudienceNotWider {
            prior_attestation_id: prior.attestation_id.clone(),
            prior: prior.cohort_scope.clone(),
            requested: requested.to_owned(),
        }),
    }
}

/// The pure shape rule for a `supersedes` widening — CC 4.4.3.3.1 / 8.1.5.
///
/// `signed` must be: `attestation_type = supersedes`, federation-tier, by the
/// prior's attester, `references_attestation_id = prior`, `differs_in`
/// listing `cohort_scope` (and only otherwise members it STRIPS), at a
/// strictly wider `cohort_scope`, with the prior's `attested_key_id`,
/// `subject_key_ids` and `weight`, and — member by member — the prior's
/// payload: a widening reuses the body (no re-upload) and may narrow it by a
/// consent restriction, but it never re-authors it. Any other difference is
/// [`Error::WideningReAuthors`].
pub fn check_widening(prior: &Attestation, signed: &Attestation) -> Result<(), Error> {
    let malformed = |reason: String| Error::WideningMalformed {
        prior_attestation_id: prior.attestation_id.clone(),
        reason,
    };
    if prior.tier != attestation_tier::FEDERATION {
        return Err(malformed(
            "the prior row is local-tier; call enter_mesh first (CC 5.3.2.4.2), then widen"
                .to_owned(),
        ));
    }
    if signed.attestation_type != attestation_type::SUPERSEDES {
        return Err(malformed(format!(
            "attestation_type must be {:?}, got {:?}",
            attestation_type::SUPERSEDES,
            signed.attestation_type
        )));
    }
    if signed.tier != attestation_tier::FEDERATION {
        return Err(malformed(
            "the widening row must be federation-tier".to_owned(),
        ));
    }
    if signed.attesting_key_id != prior.attesting_key_id {
        return Err(Error::CustodyIsNotTheActor {
            attestation_id: signed.attestation_id.clone(),
            attesting_key_id: prior.attesting_key_id.clone(),
            scrub_key_id: signed.attesting_key_id.clone(),
        });
    }
    if references_attestation_id_from_envelope(&signed.attestation_envelope)
        != Some(prior.attestation_id.as_str())
    {
        return Err(malformed(format!(
            "`{}` must name the prior row {}",
            paths::REFERENCES_ATTESTATION_ID,
            prior.attestation_id
        )));
    }
    let differs_in: Vec<&str> = match signed.attestation_envelope.get(paths::DIFFERS_IN) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str().ok_or_else(|| {
                    malformed(format!(
                        "`{}` must be an array of strings",
                        paths::DIFFERS_IN
                    ))
                })
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(malformed(format!(
                "`{}` must be an array listing {:?}",
                paths::DIFFERS_IN,
                row_paths::COHORT_SCOPE
            )))
        }
    };
    if !differs_in.contains(&row_paths::COHORT_SCOPE) {
        return Err(malformed(format!(
            "`{}` must list {:?} — that is the member a widening changes",
            paths::DIFFERS_IN,
            row_paths::COHORT_SCOPE
        )));
    }
    if let Some(p) = differs_in.iter().find(|m| {
        WIDENING_PROTECTED_MEMBERS
            .iter()
            .any(|protected| differs_in_covers(m, protected))
    }) {
        return Err(malformed(format!(
            "`{}` lists protected member {p:?}; a widening never strips it",
            paths::DIFFERS_IN
        )));
    }
    check_strictly_wider(prior, &signed.cohort_scope)?;
    let reauthors = |member: &str| Error::WideningReAuthors {
        prior_attestation_id: prior.attestation_id.clone(),
        member: member.to_owned(),
    };
    if signed.attested_key_id != prior.attested_key_id {
        return Err(reauthors(row_paths::ATTESTED_KEY_ID));
    }
    if sorted(&signed.subject_key_ids) != sorted(&prior.subject_key_ids) {
        return Err(reauthors(row_paths::SUBJECT_KEY_IDS));
    }
    if signed.weight != prior.weight {
        return Err(reauthors(row_paths::WEIGHT));
    }
    let (Some(prior_obj), Some(new_obj)) = (
        prior.attestation_envelope.as_object(),
        signed.attestation_envelope.as_object(),
    ) else {
        return Err(malformed("both envelopes must be JSON objects".to_owned()));
    };
    let declared = |member: &str| differs_in.iter().any(|e| differs_in_covers(e, member));
    for (k, v) in prior_obj {
        if is_placement_member(k) {
            continue;
        }
        match new_obj.get(k) {
            // Unchanged, and not claimed to differ.
            Some(nv) if nv == v && !declared(k) => {}
            // Absent or changed — admissible only as a DECLARED strip.
            None | Some(_) if declared(k) => {}
            _ => return Err(reauthors(k)),
        }
    }
    for k in new_obj.keys() {
        if !is_placement_member(k) && !prior_obj.contains_key(k) {
            return Err(reauthors(k));
        }
    }
    Ok(())
}

/// Build the widening's `supersedes` input from the prior: the prior's payload
/// with `strip` applied, plus `references_attestation_id`, `differs_in`, and
/// the new placement's cohort target. The instants and the row mirror are
/// stamped by [`super::attestation_emit::stamp_and_canonicalize`] on the way to
/// the signer, exactly like any other emit.
///
/// `strip` entries are **JSON-pointer paths** — the shape
/// [`super::consent_grammar::RestrictionOp::StripField`] carries — and they are
/// applied through [`super::transform::apply`], the same total algebra every
/// other consumer of a restriction uses. String-comparing them against
/// top-level keys (an earlier draft) silently dropped every pointer-form and
/// nested path, which is a restriction the operator asked for and the substrate
/// did not apply: the #510 grammar's own tests use `/agent_id_hash`.
///
/// The prior's body is otherwise reused verbatim (CC 8.1.5: no body
/// re-upload); [`check_widening`] refuses anything else.
pub fn build_widening(
    prior: &Attestation,
    new_scope: &Audience,
    strip: &[String],
) -> Result<super::EmitAttestationInput, Error> {
    let pipeline = super::transform::TransformPipeline(
        strip
            .iter()
            .map(|path| super::transform::TransformOp::StripField { path: path.clone() })
            .collect(),
    );
    let stripped = pipeline
        .apply_all(&prior.attestation_envelope)
        .map_err(|e| Error::Backend(format!("widening strip: {e}")))?;

    let mut envelope = super::envelope::EnvelopeCore::default();
    if let Some(obj) = stripped.as_object() {
        for (k, v) in obj {
            if is_placement_member(k) {
                continue;
            }
            if k == paths::DIMENSION {
                envelope.dimension = v.as_str().map(str::to_owned);
            } else {
                envelope.extra.insert(k.clone(), v.clone());
            }
        }
    }
    if let (Some(member), Some(target)) =
        (new_scope.cohort_target_member(), new_scope.cohort_target())
    {
        envelope
            .extra
            .insert(member.to_owned(), serde_json::json!(target));
    }
    envelope.references_attestation_id = Some(prior.attestation_id.clone());
    let mut differs_in: Vec<String> = vec![row_paths::COHORT_SCOPE.to_owned()];
    differs_in.extend(strip.iter().cloned());
    envelope
        .extra
        .insert(paths::DIFFERS_IN.to_owned(), serde_json::json!(differs_in));
    Ok(super::EmitAttestationInput {
        attestation_type: attestation_type::SUPERSEDES.to_owned(),
        attested_key_id: Some(prior.attested_key_id.clone()),
        attestation_envelope: envelope,
        subject_key_ids: prior.subject_key_ids.clone(),
        cohort_scope: new_scope.cohort_scope().to_owned(),
        expires_at: prior.expires_at,
        weight: prior.weight,
    })
}
