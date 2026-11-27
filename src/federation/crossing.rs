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
//! **not discoverable** (its holding claims stay in the cohort). Widening it
//! to a community is a second row. This is what the constitution's worked example (CC 8.1.5) shows,
//! and it is what edge's `share` composes from these two verbs.
//!
//! ## Custody — the three-key model made mechanical
//!
//! [`TierPromotionCustody`] is the caller's answer to "who signs the crossing".
//! v62.0.0 (F0-cp9): only [`TierPromotionCustody::Statement`] crosses; the
//! two JCS custodies below are the earlier form, refused by name
//! (`earlier_form_object`, plane `enter_mesh`).
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
//! * [`TierPromotionCustody::Statement`] — v62.0.0 (v62 P8): an edition-2
//!   row's custody is its own statement (CC 2.6.1): the actor's composite
//!   signature over the row's payload, admitted when the row was put. The
//!   crossing re-admits that statement through the edition-2 door against
//!   the keys held NOW ([`super::attestation_emit::mapped_row`]) and flips
//!   the tier; nothing is re-signed and nothing is JCS-signed. A row id is a
//!   function of the payload and never of the tier, so restating the same
//!   payload at the same scope IS this statement (the same row id, and the
//!   same bytes from a deterministic signer).
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
//! * v62.0.0 (v62 P8) — on the clean mesh: [`plan_enter_mesh`] crosses an
//!   edition-2 row on its own statement ([`TierPromotionCustody::Statement`]);
//!   a widening is a RESTATEMENT ([`restate_at_audience`], held to
//!   [`check_restated_widening`]), not a `supersedes` (an edition-2 composer
//!   needs its target held, which a peer outside the prior's audience never
//!   is); an earlier-form local row is restated from [`restatement_input`]
//!   once the earlier-form doors are shut.
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
/// map onto these. [`Audience::discoverable`] is CC 5.2 / 3.1.3.3: only a
/// Commons placement's holding claims are at `federation`.
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
    /// `affiliations` — that affiliation's members. v47.0.0 (CIRISPersist#897,
    /// BREAKING: was a unit variant): an affiliation IS a community record
    /// (CC 4.4.3.2.8, "membership ⊆ roster"), so a placement names ONE, as
    /// [`Self::Community`] does.
    Affiliations {
        /// The affiliation the row is placed in (`community_key_id`).
        community_key_id: String,
    },
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
            Self::Affiliations { .. } => cohort_scope::AFFILIATIONS,
            Self::Species => cohort_scope::SPECIES,
            Self::Biosphere => cohort_scope::BIOSPHERE,
            Self::Federation => cohort_scope::FEDERATION,
        }
    }

    /// The cohort the placement names, for `family` / `community` /
    /// `affiliations`.
    #[must_use]
    pub fn cohort_target(&self) -> Option<&str> {
        match self {
            Self::Family { family_key_id } => Some(family_key_id),
            Self::Community { community_key_id } | Self::Affiliations { community_key_id } => {
                Some(community_key_id)
            }
            Self::SelfOnly | Self::Species | Self::Biosphere | Self::Federation => None,
        }
    }

    /// The envelope member a placement's target rides in (the canonical alias
    /// among [`admission::COHORT_TARGET_ENVELOPE_FIELDS`] for that scope).
    #[must_use]
    pub fn cohort_target_member(&self) -> Option<&'static str> {
        match self {
            Self::Family { .. } => Some("family_key_id"),
            Self::Community { .. } | Self::Affiliations { .. } => Some("community_key_id"),
            Self::SelfOnly | Self::Species | Self::Biosphere | Self::Federation => None,
        }
    }

    /// Build from a wire `cohort_scope` and the cohort target the row names
    /// (`admission::envelope_cohort_target`). A targeted scope (`family` /
    /// `community` / `affiliations`) without a target is refused: a cohort
    /// placement names its cohort.
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
            cohort_scope::AFFILIATIONS => Self::Affiliations {
                community_key_id: target.ok_or_else(|| need("community_key_id"))?.to_owned(),
            },
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

    /// CC 5.2 / 3.1.3.3 — whether content placed here is discoverable by
    /// anyone: its holding claims are at `federation`. v55.0.0
    /// (CIRISPersist#989, CIRISConstitution#141) — only a Commons placement:
    /// `self`/`family` and the rooms replicate to their cohort, and their
    /// holding claims are placed at the cohort's scope and reach its members
    /// only. (A `public` room is Commons-TIER, a property of the community
    /// record, not of this placement.)
    #[must_use]
    pub fn discoverable(&self) -> bool {
        cohort_scope::Scope::parse(self.cohort_scope())
            .is_some_and(|s| s.placement() == cohort_scope::Placement::Commons)
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
///
/// v61.4.2 — serde: the custody crosses the directory capsule (`DirectoryOp::EnterMesh`).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// v62.0.0 (v62 P8) — an edition-2 row crosses on its own statement:
    /// [`StatementCustody::statement`] must be the statement the row carries,
    /// and it is re-admitted through the edition-2 door before the flip.
    Statement(StatementCustody),
}

/// v62.0.0 (v62 P8) — the custody of an edition-2 row's crossing: the row's
/// own statement, offered back, and the instant the crossing happens.
///
/// v61.4.2 — serde: crosses the directory capsule inside
/// [`TierPromotionCustody::Statement`] (`DirectoryOp::EnterMesh`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementCustody {
    /// The row's carried statement (`ceg_statement`), as held.
    pub statement: Vec<u8>,
    /// The crossing's instant (`promoted_at`), at the substrate resolution;
    /// taken from the caller so every backend writes the same one.
    pub crossed_at: DateTime<Utc>,
}

impl TierPromotionCustody {
    /// v62.0.0 (v62 P8) — the custody an edition-2 row crosses on: its own
    /// carried statement, at `now` (substrate resolution). `None` for a row
    /// that carries no statement (an earlier-form row).
    #[must_use]
    pub fn of_statement(row: &Attestation, now: DateTime<Utc>) -> Option<Self> {
        super::edition2::emit::carried_statement(row).map(|statement| {
            Self::Statement(StatementCustody {
                statement,
                crossed_at: admission::truncate_to_substrate_resolution(now),
            })
        })
    }

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
            Self::Statement(c) => Ok(c.crossed_at),
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
    /// CC 5.2 / 3.1.3.3 — `true` only for a Commons placement, whose holding
    /// claims are the federation's holder directory.
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
    /// v62.0.0 (v62 P8-fix5; E7's finding) — the widening restatement was
    /// admitted but is HELD by the statement door (`Pending`): its family
    /// names second signers who have not voiced it yet (K2's gate), or
    /// another fold condition is unmet. Nothing crossed yet; it is not an
    /// error. The second signers find it with `held_rows_for` and voice it;
    /// `voice_status` reads when it seats.
    Held {
        /// The restatement's row id (hex).
        attestation_id: String,
        /// The prior the restatement widens.
        prior_attestation_id: String,
        /// The held reason token (`count_short` while a voice is missing).
        reason: String,
        /// The held detail, as the gate words it.
        detail: String,
    },
    /// v62.0.0 (D2; the HEAD-4.rev2 pattern, `holding_claim::node_is_unowned`)
    /// — the row is this node's own local `hard_case:*` record and this node
    /// is UNOWNED: an unowned node states no report (CC 3.2), so nothing was
    /// stated or written. The local row stays local; it crosses once an owner
    /// binding lands. Not an error. APPENDED.
    Unowned {
        /// The local row that waits.
        attestation_id: String,
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
    // v62.0.0 (wave P7; CC ruling) — an unsigned trace stays local: a
    // `trace:*` row with no edition-2 statement never crosses.
    crate::ingest::refuse_unsigned_trace_crossing(current)?;
    // Deterministic on every backend: the signer's own instant, never a clock
    // read inside the storage layer. See `TierPromotionCustody::crossing_at`.
    let now = custody.crossing_at()?;
    // v62.0.0 (v62 P8) — an edition-2 row crosses on its own statement, never
    // through the JCS arms below; a JCS custody offered for one is refused.
    if super::edition2::emit::carried_statement(current).is_some()
        != matches!(custody, TierPromotionCustody::Statement(_))
    {
        return Err(Error::InvalidArgument(format!(
            "attestation {}: an edition-2 row crosses on its own statement \
             (TierPromotionCustody::Statement), and only an edition-2 row does",
            current.attestation_id
        )));
    }
    if let TierPromotionCustody::Statement(c) = custody {
        return plan_statement_crossing(dir, current, ci, c, self_key_id, now).await;
    }
    // v62.0.0 (v62 P8-fix13; CC 2.6.1.12, E3's round-6 finding) — the JCS
    // arms below (an actor's reseal, the node's co-scrub over a JCS image) are
    // the earlier form: once its doors are shut they would mint a
    // federation-tier row no edition-2 peer can verify (the bound-hybrid
    // verify is gone, F0-cp7). The Engine never reaches them (it restates an
    // earlier-form local row, `Engine::restate_local_row`); a directory
    // caller offering a JCS custody is refused here, by name, on every
    // backend.
    super::edition2::door::refuse_earlier_form("enter_mesh")?;
    // v62.0.0 (F0-cp9) — the JCS arms themselves are deleted with their
    // bound-hybrid verify: every JCS custody is refused by name.
    let _ = ci;
    Err(super::edition2::door::earlier_form_signature("enter_mesh"))
}

/// v62.0.0 (v62 P8) — **the [`EnterPlan`] of an edition-2 row**: the row's
/// own statement, re-admitted now through the edition-2 door against the keys
/// this node holds ([`super::attestation_emit::mapped_row`]: the key-of-issuer
/// check, liveness at the signed instant, the payload rules), must name THIS
/// row (its row id and attester); then the promotion admission stack and the
/// nine axes run as for any crossing. The signed bytes, the envelope (the
/// mapping's), `original_content_hash` and `persist_row_hash` (the row id)
/// are the row's as admitted: only `tier`, `promoted_at` and
/// `pqc_completed_at` move. Nothing is signed here.
async fn plan_statement_crossing(
    dir: &dyn FederationDirectory,
    current: &Attestation,
    ci: &ContextualIntegrity,
    custody: &StatementCustody,
    self_key_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<EnterPlan>, Error> {
    use sha2::{Digest, Sha256};
    let held = super::edition2::emit::carried_statement(current).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "attestation {}: no edition-2 statement to cross on",
            current.attestation_id
        ))
    })?;
    if held != custody.statement {
        return Err(Error::PromotionMovedThePreimage {
            attestation_id: current.attestation_id.clone(),
            stored_hash: hex::encode(Sha256::digest(&held)),
            offered_hash: hex::encode(Sha256::digest(&custody.statement)),
        });
    }
    let readmitted = super::attestation_emit::mapped_row(dir, &custody.statement).await?;
    if readmitted.attestation_id != current.attestation_id
        || readmitted.attesting_key_id != current.attesting_key_id
    {
        return Err(Error::CustodyIsNotTheActor {
            attestation_id: current.attestation_id.clone(),
            attesting_key_id: current.attesting_key_id.clone(),
            scrub_key_id: readmitted.attesting_key_id,
        });
    }
    let mut row = current.clone();
    row.tier = attestation_tier::FEDERATION.to_owned();
    row.promoted_at = Some(now);
    row.pqc_completed_at = Some(now);
    check_promotion_admission(dir, &row, self_key_id).await?;
    check_contextual_integrity(dir, &row, &row, ci, &row.cohort_scope.clone(), false, now).await?;
    let crossing = report(&row, Custody::ActorSigned, now);
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
/// v48.0.0 (#905) — `pub(crate)` so a witness can drive the negative arm
/// (a steward's grant for a SIBLING machine) directly.
pub(crate) async fn check_grant_covers<D>(
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
    // v48.0.0 (CIRISPersist#905) — by principals: the sender's own grant, or
    // a grant its steward authored naming it (consent by humans, #857). The
    // same predicate the promotion sweep loads by.
    if !super::consent_by_humans::grant_is_authored_for(
        dir.as_dyn_directory(),
        &grant,
        &row.attesting_key_id,
    )
    .await?
    {
        return Err(refuse(format!(
            "the grant is authored by {}, who is neither the sender nor a steward of the \
             sender naming it",
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
        paths::ROW | paths::EXPIRES_AT | paths::REFERENCES_ATTESTATION_ID
    ) || member == paths::DIFFERS_IN
        || member == paths::WIDENED_AT
        || admission::COHORT_TARGET_ENVELOPE_FIELDS.contains(&member)
}

/// v61 (CIRISPersist#1155 / #1157) — is the held composer `held` the SAME
/// placement as `offered`: a `supersedes` by the same attester, at the same
/// cohort scope and cohort target (the same audience)? A placement is
/// idempotent per audience; one into another room is a new one.
///
/// # Errors
///
/// A split-brain cohort target on either row.
pub fn same_placement(held: &Attestation, offered: &Attestation) -> Result<bool, Error> {
    Ok(
        held.attestation_type == super::types::attestation_type::SUPERSEDES
            && held.attesting_key_id == offered.attesting_key_id
            && held.cohort_scope == offered.cohort_scope
            && super::admission::envelope_cohort_target(&held.attestation_envelope)?
                == super::admission::envelope_cohort_target(&offered.attestation_envelope)?,
    )
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
pub const WIDENING_PROTECTED_MEMBERS: [&str; 8] = [
    paths::DIMENSION,
    "trace_id",
    paths::ROW,
    paths::ASSERTED_AT,
    paths::EXPIRES_AT,
    paths::REFERENCES_ATTESTATION_ID,
    paths::DIFFERS_IN,
    // v51.0.0 (CIRISPersist#929, CC 5.4.6) — the CC 2.4.1.2 purpose marker
    // (`delegation_purpose: owner_binding`) is what a receiving peer that does
    // not hold the prior reads to know a widening announces an owner-binding;
    // a widening that strips it would announce a minor's binding at
    // federation scope past the minors gate on every peer lacking the prior.
    "delegation_purpose",
];

/// Position in the closed widening order [`cohort_scope::ALL`] — THE ordering
/// over cohort scopes, ratified by CC 4.4.3.3.1 and used by
/// [`check_strictly_wider`].
///
/// `pub(crate)` since v42.0.0 so `admission::check_duty_admission` compares
/// reach against the SAME ladder rather than deriving a second one. Two
/// orderings over one vocabulary is the two-lists class.
pub(crate) fn scope_rank(s: &str) -> Option<usize> {
    cohort_scope::ALL.iter().position(|v| *v == s)
}

/// `requested` must be strictly wider than the prior's `cohort_scope` in the
/// closed widening order ([`cohort_scope::ALL`]); else
/// [`Error::AudienceNotWider`]. Pure and free, so callers ask it before they
/// sign anything. "Wider" here is a LINEAR ladder, not containment: the Live
/// read hides a restated prior by audience CONTAINMENT
/// (`attestation_query::lifecycle_predicate`, P8-fix14), so e.g. a family row
/// restated into a community leaves both live, each served to its own audience.
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

    // v40.0.0 (CIRISPersist#801) — THE CLAIM'S INSTANT IS PART OF THE CLAIM.
    //
    // `differs_in` says `cohort_scope` is the only difference; a re-dated
    // widening makes that false, and because the prior is `self`-scoped and
    // never replicates, the re-dated instant is the ONLY one any peer can
    // read. So this is enforced rather than merely produced correctly:
    // v39.0.0 dropped the instant in `build_widening` and no gate could see
    // it, because `asserted_at` was exempted from the member comparison
    // below — the exemption hid exactly the field that then changed.
    fn instant_of(row: &Attestation) -> Option<&str> {
        row.attestation_envelope
            .get(paths::ASSERTED_AT)
            .and_then(serde_json::Value::as_str)
    }
    if instant_of(signed) != instant_of(prior) {
        return Err(malformed(format!(
            "`{}` was re-dated: the prior asserts {:?} and the widening {:?}. A widening \
             republishes the SAME claim at a wider audience — its body, subjects, weight and \
             expiry are all reused and `differs_in` names only `{}` — so the claim's instant \
             crosses with it. The act of widening has its own instant in `{}`",
            paths::ASSERTED_AT,
            instant_of(prior),
            instant_of(signed),
            row_paths::COHORT_SCOPE,
            paths::WIDENED_AT,
        )));
    }
    // …and the act must say when it happened, or the two instants are
    // indistinguishable to a reader.
    let Some(widened_at) = signed
        .attestation_envelope
        .get(paths::WIDENED_AT)
        .and_then(serde_json::Value::as_str)
    else {
        return Err(malformed(format!(
            "no `{}`: a widening carries the claim's instant in `{}` and its OWN in `{}`, so a \
             reader can tell when the claim was made from when it was placed",
            paths::WIDENED_AT,
            paths::ASSERTED_AT,
            paths::WIDENED_AT,
        )));
    };
    let widened_at = DateTime::parse_from_rfc3339(widened_at)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| malformed(format!("`{}` is not RFC-3339: {e}", paths::WIDENED_AT)))?;
    if widened_at < prior.asserted_at {
        return Err(malformed(format!(
            "`{}` {} precedes the claim it widens ({}) — a placement cannot happen before the \
             claim it places",
            paths::WIDENED_AT,
            admission::render_signed_instant(widened_at),
            admission::render_signed_instant(prior.asserted_at),
        )));
    }
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
    now: DateTime<Utc>,
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
            // `asserted_at` is NOT a placement member — `check_widening`
            // compares it like any other body member, which is what makes the
            // "carry the claim's instant" rule enforceable rather than merely
            // implemented. But it is set EXPLICITLY below, so the copy loop
            // must skip it or the typed field and `extra` both carry it and
            // the envelope grows two spellings of one member.
            if is_placement_member(k) || k == paths::ASSERTED_AT {
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
    // v40.0.0 (CIRISPersist#801) — THE CLAIM'S INSTANT CROSSES WITH THE CLAIM.
    //
    // Carried VERBATIM from the prior's signed envelope, not re-rendered: a
    // pre-v39 prior carries microseconds, and re-minting it at the substrate
    // resolution would move the instant this row exists to preserve.
    //
    // It is carried at all because a widening is not a new claim — the body,
    // the subjects, the weight and the expiry are all reused, and `differs_in`
    // says `cohort_scope` is the ONLY difference. Letting
    // `stamp_and_canonicalize` mint a fresh `asserted_at` (v39.0.0 did) made
    // that statement false and, worse, made the claim's instant UNRECOVERABLE
    // off-node: a local row must be `self`-scoped, `self` is undiscoverable
    // (CC 5.2), so the widening is the only row a peer ever sees. Every
    // cross-node reader — CIRISServer's equivocation detector among them — was
    // then comparing placement times while believing it compared claim times,
    // and two contradictory claims widened a moment apart became
    // indistinguishable from an honest revision. Nothing errored; the
    // detection just went to zero (CIRISPersist#801).
    envelope.asserted_at = prior
        .attestation_envelope
        .get(paths::ASSERTED_AT)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    // …and the ACT gets its own instant, so nothing is lost in the other
    // direction: `widened_at` is when this placement happened, and
    // `attestation_emit::assemble` reads `scrub_timestamp` from it.
    envelope.widened_at = Some(admission::render_signed_instant(now));
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

// ─────────────────────────────────────────────────────────────────────────
// v62.0.0 (v62 P8) — widen_audience on the clean mesh: a restatement.
// ─────────────────────────────────────────────────────────────────────────

/// v62.0.0 (v62 P8) — **an edition-2 widening, before it is signed**: the
/// prior's row type, family and payload restated at the wider audience.
#[derive(Debug, Clone)]
pub struct Restatement {
    /// The prior's family (header -70002).
    pub family: String,
    /// The prior's row type (header -70001).
    pub row_type: String,
    /// The prior's payload at the new placement.
    pub payload: ciris_verify_core::cde::Value,
}

/// v62.0.0 (v62 P8-fix14; lead ruling (a), CC 4.4.3.3.1 / 8.1.5) — **the
/// restatement key**: the identity of a claim across its placements. SHA-256
/// (lowercase hex) over the deterministic encoding of `[iss, sub, row type,
/// family, payload]`, the payload with its placement members
/// ([`is_restatement_placement_member`]: `cohort_scope` and the cohort
/// target) removed. Everything else the statement signs is in it,
/// `asserted_at`, `author` and every claim member included, so two distinct
/// acts never share a key; a prior and every [`restate_at_audience`] of it
/// share one. Computed from the statement alone, so every node derives the
/// same key; each backend's row writer stores it in V300's plain
/// `restatement_key` column ([`restatement_key_of_row`]), never in the
/// envelope, so no content hash sees it. The Live read hides a
/// row a live, same-`iss` row with its key and a strictly containing
/// audience restates (`attestation_query::lifecycle_predicate`).
#[must_use]
pub fn restatement_key(
    iss: &str,
    sub: &str,
    row_type: &str,
    family: &str,
    payload: &ciris_verify_core::cde::Value,
) -> Option<String> {
    use ciris_verify_core::cde::Value;
    use sha2::Digest as _;
    let members = payload.as_map()?;
    let claim: Vec<(Value, Value)> = members
        .iter()
        .filter(|(k, _)| !k.as_text().is_some_and(is_restatement_placement_member))
        .cloned()
        .collect();
    let preimage = Value::Array(vec![
        Value::Text(iss.to_owned()),
        Value::Text(sub.to_owned()),
        Value::Text(row_type.to_owned()),
        Value::Text(family.to_owned()),
        Value::Map(claim),
    ]);
    Some(hex::encode(sha2::Sha256::digest(
        ciris_verify_core::cde::encode(&preimage),
    )))
}

/// v62.0.0 (v62 P8-fix14) — [`restatement_key`] of a stored row, from the
/// statement it carries (its `iss`, `sub`, row type, family and payload): the
/// value each backend's row writer stores in V300's plain `restatement_key`
/// column beside the row. It is NEVER an envelope member, so no content hash
/// (`original_content_hash`, `persist_row_hash`) sees it. `None` for a row
/// that carries no edition-2 statement.
#[must_use]
pub fn restatement_key_of_row(row: &Attestation) -> Option<String> {
    use ciris_verify_core::cde::Value;
    let statement = super::edition2::emit::carried_statement(row)?;
    let (family, row_type) = super::edition2::emit::family_of_statement(&statement)?;
    let (protected, payload) = super::edition2::liveness::statement_parts(&statement)?;
    let claims = protected.get_int(15)?;
    let iss = claims.get_int(1).and_then(Value::as_text)?;
    let sub = claims.get_int(2).and_then(Value::as_text)?;
    restatement_key(iss, sub, &row_type, &family, &payload)
}

/// The payload members a restatement replaces because they ARE the
/// placement: the scope and the cohort-target aliases.
fn is_restatement_placement_member(member: &str) -> bool {
    member == row_paths::COHORT_SCOPE || admission::COHORT_TARGET_ENVELOPE_FIELDS.contains(&member)
}

/// v62.0.0 (HEAD-fix1; CC 2.4.1.1) — `refs` without its heads (`head`, and
/// `further_heads`, the other tips of that same head): the head an act names
/// is its PLACEMENT's (a room's roster version at a room; none for a
/// person's own row), so a restatement at a new placement names the new
/// placement's head ([`widen_by_restatement`] states it) and the widening
/// check compares the rest of `refs`. `None` when nothing else is named.
fn refs_without_head(
    refs: Option<&ciris_verify_core::cde::Value>,
) -> Option<ciris_verify_core::cde::Value> {
    use ciris_verify_core::cde::Value;
    let m = refs?.as_map()?;
    let rest: Vec<(Value, Value)> = m
        .iter()
        .filter(|(k, _)| !matches!(k.as_text(), Some("head" | "further_heads")))
        .cloned()
        .collect();
    (!rest.is_empty()).then_some(Value::Map(rest))
}

/// The payload member a placement's cohort target rides in on an edition-2
/// row: `community_id` for a room (a common member, CC 2.6.1.4) and
/// `family_key_id` for a family (the alias the cohort-target read takes).
fn restatement_target_member(audience: &Audience) -> Option<&'static str> {
    match audience {
        Audience::Family { .. } => Some("family_key_id"),
        Audience::Community { .. } | Audience::Affiliations { .. } => Some("community_id"),
        Audience::SelfOnly | Audience::Species | Audience::Biosphere | Audience::Federation => None,
    }
}

/// A JSON-pointer path's segments (`/a/b` or a bare `a`), unescaped.
fn pointer_segments(path: &str) -> Vec<String> {
    path.strip_prefix('/')
        .unwrap_or(path)
        .split('/')
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Remove the member `segments` names from a CBOR map, descending through
/// nested maps; a path that names nothing removes nothing.
fn strip_cbor(value: &mut ciris_verify_core::cde::Value, segments: &[String]) {
    use ciris_verify_core::cde::Value;
    let (Some(first), Value::Map(m)) = (segments.first(), value) else {
        return;
    };
    if segments.len() == 1 {
        m.retain(|(k, _)| k.as_text() != Some(first.as_str()));
        return;
    }
    if let Some((_, inner)) = m
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(first.as_str()))
    {
        strip_cbor(inner, &segments[1..]);
    }
}

/// v62.0.0 (v62 P8; CC 4.4.3.3.1 / 8.1.5 on the clean mesh) — **restate an
/// edition-2 row at a wider audience**: the prior's own statement's row
/// type, family and payload, with `cohort_scope` (and the cohort target) the
/// new placement's and the members `strip` names removed (a consent
/// `StripField` restriction, JSON-pointer paths). Everything else is the
/// prior's payload verbatim, `asserted_at` included: the claim's instant
/// crosses with the claim (CIRISPersist#801).
///
/// A restatement and not a `supersedes`: an edition-2 composer must find its
/// target held (`WithdrawsTargetUnheld`), and a peer outside the prior's
/// audience never holds it, so a `supersedes` over a `self` row could never
/// reach the audience it widens to. The restatement is a row of its own (the
/// row id moves with `cohort_scope`), signed by the actor, and the earlier
/// form's `widened_at` / `differs_in` / `references_attestation_id` are not
/// members of a closed family payload (`edition2::payloads`).
///
/// # Errors
/// [`Error::WideningMalformed`] for a prior that carries no edition-2
/// statement, or a `strip` naming a member a widening never strips
/// ([`WIDENING_PROTECTED_MEMBERS`], `author`, the placement).
pub fn restate_at_audience(
    prior: &Attestation,
    new_scope: &Audience,
    strip: &[String],
) -> Result<Restatement, Error> {
    use ciris_verify_core::cde::Value;
    let malformed = |reason: String| Error::WideningMalformed {
        prior_attestation_id: prior.attestation_id.clone(),
        reason,
    };
    let statement = super::edition2::emit::carried_statement(prior).ok_or_else(|| {
        malformed("the prior carries no edition-2 statement to restate".to_owned())
    })?;
    let (family, row_type) = super::edition2::emit::family_of_statement(&statement)
        .ok_or_else(|| malformed("the prior's statement names no family".to_owned()))?;
    let (_, mut payload) = super::edition2::liveness::statement_parts(&statement)
        .ok_or_else(|| malformed("the prior's statement does not decode".to_owned()))?;
    for path in strip {
        let segments = pointer_segments(path);
        let top = segments.first().map(String::as_str).unwrap_or("");
        if WIDENING_PROTECTED_MEMBERS.contains(&top)
            || top == "author"
            || is_restatement_placement_member(top)
        {
            return Err(malformed(format!(
                "`strip` names {path:?}: a widening never strips the claim's identity, its \
                 instants, its author or its placement"
            )));
        }
        strip_cbor(&mut payload, &segments);
    }
    let Value::Map(members) = payload else {
        return Err(malformed("the prior's payload is not a map".to_owned()));
    };
    let mut m: Vec<(Value, Value)> = members
        .into_iter()
        .filter(|(k, _)| !k.as_text().is_some_and(is_restatement_placement_member))
        .filter_map(|(k, v)| {
            // v62.0.0 (HEAD-fix1) — the prior placement's head is not carried:
            // the restatement names its own placement's head.
            if k.as_text() == Some("refs") {
                refs_without_head(Some(&v)).map(|r| (k, r))
            } else {
                Some((k, v))
            }
        })
        .collect();
    m.push((
        Value::Text(row_paths::COHORT_SCOPE.to_owned()),
        Value::Text(new_scope.cohort_scope().to_owned()),
    ));
    if let (Some(member), Some(target)) = (
        restatement_target_member(new_scope),
        new_scope.cohort_target(),
    ) {
        m.push((
            Value::Text(member.to_owned()),
            Value::Text(target.to_owned()),
        ));
    }
    Ok(Restatement {
        family,
        row_type,
        payload: super::edition2::emit::sorted_map(m),
    })
}

/// v62.0.0 (v62 P8) — **the shape rule of an edition-2 widening**
/// ([`restate_at_audience`]'s, read back off the signed statement): by the
/// prior's attester, federation-tier, the prior's row type, family, subject,
/// subjects and weight, a strictly wider `cohort_scope`, the claim's instant
/// unchanged, and — member by member — the prior's payload, except the
/// placement and the members `strip` removed. Any other difference is
/// [`Error::WideningReAuthors`].
///
/// # Errors
/// [`Error::WideningMalformed`], [`Error::CustodyIsNotTheActor`],
/// [`Error::AudienceNotWider`], [`Error::WideningReAuthors`].
pub fn check_restated_widening(
    prior: &Attestation,
    signed: &Attestation,
    strip: &[String],
) -> Result<(), Error> {
    let malformed = |reason: String| Error::WideningMalformed {
        prior_attestation_id: prior.attestation_id.clone(),
        reason,
    };
    let reauthors = |member: &str| Error::WideningReAuthors {
        prior_attestation_id: prior.attestation_id.clone(),
        member: member.to_owned(),
    };
    if prior.tier != attestation_tier::FEDERATION {
        return Err(malformed(
            "the prior row is local-tier; call enter_mesh first (CC 5.3.2.4.2), then widen"
                .to_owned(),
        ));
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
    if signed.attestation_type != prior.attestation_type {
        return Err(reauthors("attestation_type"));
    }
    let (Some(prior_st), Some(signed_st)) = (
        super::edition2::emit::carried_statement(prior),
        super::edition2::emit::carried_statement(signed),
    ) else {
        return Err(malformed(
            "both rows carry their edition-2 statements".to_owned(),
        ));
    };
    if super::edition2::emit::family_of_statement(&prior_st)
        != super::edition2::emit::family_of_statement(&signed_st)
    {
        return Err(reauthors("family"));
    }
    check_strictly_wider(prior, &signed.cohort_scope)?;
    if signed.asserted_at != prior.asserted_at {
        return Err(reauthors(paths::ASSERTED_AT));
    }
    if signed.attested_key_id != prior.attested_key_id {
        return Err(reauthors(row_paths::ATTESTED_KEY_ID));
    }
    if sorted(&signed.subject_key_ids) != sorted(&prior.subject_key_ids) {
        return Err(reauthors(row_paths::SUBJECT_KEY_IDS));
    }
    if signed.weight != prior.weight {
        return Err(reauthors(row_paths::WEIGHT));
    }
    let (Some((_, prior_p)), Some((_, signed_p))) = (
        super::edition2::liveness::statement_parts(&prior_st),
        super::edition2::liveness::statement_parts(&signed_st),
    ) else {
        return Err(malformed("a statement does not decode".to_owned()));
    };
    let (Some(prior_m), Some(signed_m)) = (prior_p.as_map(), signed_p.as_map()) else {
        return Err(malformed("both payloads must be maps".to_owned()));
    };
    let stripped = |member: &str| strip.iter().any(|p| differs_in_covers(p, member));
    for (k, v) in prior_m {
        let Some(name) = k.as_text() else {
            return Err(malformed("a payload member key is not text".to_owned()));
        };
        if is_restatement_placement_member(name) {
            continue;
        }
        if name == "refs" {
            if refs_without_head(Some(v)) != refs_without_head(signed_p.get_text(name)) {
                return Err(reauthors(name));
            }
            continue;
        }
        match signed_p.get_text(name) {
            Some(nv) if nv == v => {}
            None | Some(_) if stripped(name) => {}
            _ => return Err(reauthors(name)),
        }
    }
    for (k, v) in signed_m {
        let name = k.as_text().unwrap_or("");
        if name == "refs" {
            // Only its head is new: compared above when the prior has refs.
            if prior_p.get_text(name).is_none() && refs_without_head(Some(v)).is_some() {
                return Err(reauthors(name));
            }
            continue;
        }
        if !is_restatement_placement_member(name) && prior_p.get_text(name).is_none() {
            return Err(reauthors(name));
        }
    }
    Ok(())
}

/// v62.0.0 (v62 P8) — **an earlier-form local row as the input its
/// edition-2 restatement is produced from**, once the earlier-form doors are
/// shut: the row's type, subject, subjects, scope, expiry, weight and
/// envelope members (its `row` mirror dropped: a statement binds its row
/// itself), stated at `asserted_at` ([`super::hard_case::statement_instant`]:
/// the row's own instant, or the signing key's current record's start when
/// the row is older than the key, so the key covers it). The producer
/// ([`super::attestation_emit::produce_row`]) maps the members onto the
/// payload, as for any emit. A self-attested row (`attested == attesting`)
/// is stated about its signer.
///
/// # Errors
/// An envelope that is not an object.
pub fn restatement_input(
    row: &Attestation,
    asserted_at: DateTime<Utc>,
) -> Result<super::EmitAttestationInput, Error> {
    let mut envelope = row.attestation_envelope.clone();
    if let Some(o) = envelope.as_object_mut() {
        o.remove(paths::ROW);
        o.insert(
            paths::ASSERTED_AT.to_owned(),
            serde_json::Value::String(admission::render_signed_instant(asserted_at)),
        );
    }
    let core = super::envelope::EnvelopeCore::from_value(envelope)?;
    let mut input = super::EmitAttestationInput::with_envelope(
        row.attestation_type.clone(),
        core,
        row.cohort_scope.clone(),
    );
    input.attested_key_id =
        (row.attested_key_id != row.attesting_key_id).then(|| row.attested_key_id.clone());
    input.subject_key_ids = row.subject_key_ids.clone();
    input.expires_at = row.expires_at;
    input.weight = row.weight;
    Ok(input)
}

/// v62.0.0 (v62 P8) — **widen an edition-2 row by restating it, signed by
/// `signer`** (the prior's actor; the caller decides who that is): the
/// restatement ([`restate_at_audience`]) signed through
/// `edition2::produce::sign_row`, read back through the edition-2 door
/// (`attestation_emit::mapped_row`), held to [`check_restated_widening`]
/// and the nine axes ([`check_contextual_integrity`], the prior as the
/// claim), then admitted through the statement door (`put_statement`,
/// `Authored`, federation tier). The same restatement again is
/// `AlreadyWidened` (the same row id). The prior is untouched. Usable with a
/// directory and a signer alone (no Engine).
///
/// # Errors
/// [`restate_at_audience`]'s and [`check_restated_widening`]'s refusals;
/// `composite_signing_unavailable`; the door's and the gates' refusals.
pub async fn widen_by_restatement<D>(
    dir: &D,
    prior: &Attestation,
    ci: &ContextualIntegrity,
    signer: &crate::signing::LocalSigner,
    strip: &[String],
) -> Result<MeshCrossingOutcome, Error>
where
    D: FederationDirectory + Sync + ?Sized,
{
    let restated = restate_at_audience(prior, &ci.recipient_see, strip)?;
    // v62.0.0 (HEAD-fix1; CC 2.4.1.1) — the restatement is the actor's act at
    // its NEW placement: `restate_at_audience` dropped the prior's head, and
    // the head of the new placement is stated here, as every producer does
    // (a room's roster version at a room; an owner binding for a machine).
    let (_, signer_iss) = super::edition2::produce::signer_identity(signer)
        .await
        .map_err(|e| Error::InvalidArgument(format!("widen_audience: the signer: {e}")))?;
    let payload = super::edition2::head_rule::state_head(
        dir,
        &restated.row_type,
        &restated.family,
        &signer_iss,
        restated.payload.clone(),
    )
    .await?;
    let statement = super::edition2::produce::sign_row(
        signer,
        &prior.attested_key_id,
        &restated.row_type,
        &restated.family,
        &payload,
    )
    .await
    .map_err(|e| super::edition2::emit::produce_error("widen_audience", e))?;
    let signed = super::attestation_emit::mapped_row(dir, &statement).await?;
    check_restated_widening(prior, &signed, strip)?;
    let now = crate::host::clock::now();
    check_contextual_integrity(dir, &signed, prior, ci, &signed.cohort_scope, true, now).await?;
    // Idempotent per audience: the same restatement is the same row id.
    if dir.get_attestation(&signed.attestation_id).await?.is_some() {
        return Ok(MeshCrossingOutcome::AlreadyWidened {
            prior_attestation_id: prior.attestation_id.clone(),
        });
    }
    let outcome = super::edition2::ingest::put_statement_with_origin(
        dir,
        &statement,
        None,
        attestation_tier::FEDERATION,
        super::replication::admission::WriteOrigin::Authored,
    )
    .await?;
    // v62.0.0 (v62 P8-fix5; E7's finding) — a HELD restatement did not
    // cross: report it held, never `Crossed`.
    if let super::edition2::ingest::StatementOutcome::Pending { row_id, .. } = outcome {
        let held = super::edition2::fold::why_held(dir, &row_id).await?;
        return Ok(MeshCrossingOutcome::Held {
            attestation_id: row_id.hex(),
            prior_attestation_id: prior.attestation_id.clone(),
            reason: held.as_ref().map(|h| h.reason.clone()).unwrap_or_default(),
            detail: held.map(|h| h.detail).unwrap_or_default(),
        });
    }
    Ok(MeshCrossingOutcome::Crossed(report(
        &signed,
        Custody::ActorSigned,
        now,
    )))
}
