//! v62.0.0 (wave G0; CC 2.7.3) — **the held/concluded fold.**
//!
//! CC 2.7.3: "A row waits for what it names. It is never refused for what
//! another row says: a check that reads another row concludes nothing." The
//! edition-2 door refuses a statement only on its own bytes and on its
//! signer's own key plane. Everything else is decided HERE, by the fold:
//!
//! - **held**: every door-valid row's statement is kept in `ceg_statements`;
//! - **concluded**: its typed projection (`federation_attestations`, a group
//!   table, ...) exists only while every fold condition it reads holds.
//!   Readers read the typed tables, so they see exactly the concluded set;
//! - **held, concluding nothing**: no typed row, and its `ceg_fold_state`
//!   row names the REASON (a [`reason`] token) and the refusal the gate
//!   would have raised.
//!
//! v4: every folded row (held or concluded) has a `ceg_fold_state` row
//! carrying its ORIGINAL arrival (replicated or local, tier), its plane and
//! its projection slot. A re-fold replays that arrival ([`Arrival`]); a
//! concluded row un-concludes through its plane's hook ([`Plane`]).
//!
//! **The dependency index.** Each evaluation of a row's gates (an
//! [`attempt`]) records every input it read, as a [`Dep`] read key, in
//! `ceg_fold_reads`. When a statement lands, concludes, un-concludes or adds
//! a voice, the read keys it [`touches`] select the rows whose folds read it,
//! and [`refold_touched`] re-runs exactly those, in row-id order, cascading
//! until nothing changes. Write-time re-folding keeps readers simple (the
//! typed tables are the concluded set; no reader re-derives a verdict), at
//! the cost of a dependency lookup per stored statement, which is one indexed
//! read when nothing depends on it.
//!
//! **Arrival order.** A fold's answer is a function of the held set: the
//! worklist re-folds every row an input change can reach, so whichever order
//! a row and its inputs arrive in, the row is re-evaluated after the last of
//! them, against all of them. For monotone conditions (a count, a binding
//! present, an owner seated) the fixpoint is unique; a withdrawal is itself a
//! held row whose conclusion un-concludes what read its target.
//!
//! **Gates** convert by declaring their reads ([`reads`]) and wrapping the
//! refusal they already return in [`hold`]. Outside an attempt both are
//! no-ops / plain refusals, so the earlier-form door and read-time folds keep
//! their behaviour. See `FSD/v62_wip/parallel/G0.api.md` for the recipe.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::door::AdmittedRow;
use super::ingest::StatementOutcome;
use super::names::RowId;
use super::voices::Voice;
use crate::federation::types::Attestation;
use crate::federation::{Error, FederationDirectory};

/// The reason tokens a held row may carry.
///
/// **The registry (v4).** Adopters key on the TEXT. The tokens live in:
/// - **the core**: this module's own constants, listed in [`reason::ALL`]
///   in pinned order (I3550). It also holds every reason more than one
///   wave needs, so that no two waves spell one reason twice;
/// - **one submodule per conversion wave** (`gc1` … `gc8`). Each wave
///   owns its submodule outright: its constants, and its own `ALL` slice.
///   Waves never edit each other's, so merges do not conflict.
///
/// Every submodule is glob re-exported here (`reason::LINK_UNHELD` works).
/// A core constant SHADOWS a same-named one in a wave module, so a reason
/// promoted to the core silences duplicates.
///
/// [`reason::registry`] is the union of [`reason::SLICES`]. I3550 checks:
/// - the core order;
/// - that no token text is registered under two different meanings;
/// - that every token is a snake_case ASCII word.
pub mod reason {
    /// The row's voices are short of its count (a group's
    /// `consensus_protocol`, an owner binding's node voice, a charter's
    /// quorum): T1's, V1b's, O1's and W1's `Pending`.
    pub const COUNT_SHORT: &str = "count_short";
    /// The row is a third party's word about a subject whose live owner the
    /// signer is not (yet): `owner_of(subject)` does not name the signer.
    pub const OWNER_UNSEATED: &str = "owner_unseated";
    /// A steward binding of a person whose minority (or whose granter's
    /// adulthood) no held witness proves.
    pub const STEWARD_UNPROVEN: &str = "steward_unproven";
    /// An amendment whose approvals name another digest (reserved for the
    /// identity-amendment conversion).
    pub const AMENDMENT_DIGEST_MISMATCH: &str = "amendment_digest_mismatch";
    /// A re-fold met a refusal no gate marked as a fold condition: the row
    /// stays held, and the refusal is its detail.
    pub const REFOLD_REFUSED: &str = "refold_refused";
    /// Transient: a concluded row is being taken out of its typed table. A
    /// row left in this state (a crash mid-refold) is repaired by
    /// [`super::refold_all`].
    pub const REFOLDING: &str = "refolding";
    /// v2 — the subject node has more than one counted owner
    /// (`AmbiguousNodeOwner`): whatever read its owner concludes nothing
    /// until one binding is withdrawn. Raised by `admission::owner_of`
    /// itself, so no gate that calls it with `?` refuses on it.
    pub const OWNER_AMBIGUOUS: &str = "owner_ambiguous";
    /// v4 (promoted: GC3, GC4, GC7 each spelled it) — a row names a link (a
    /// key, a group, a parent row, a foreign-key parent) this node does not
    /// hold yet: it WAITS for it.
    pub const LINK_UNHELD: &str = "link_unheld";
    /// v4 (promoted: GC4, GC7) — the group the row changes is dissolved.
    pub const GROUP_DISSOLVED: &str = "group_dissolved";
    /// v4 (promoted: GC2, GC3) — a self-roster eviction that has not landed
    /// under the self's two-path rule.
    pub const SELF_ROSTER_NOT_LANDED: &str = "self_roster_not_landed";
    /// v4 (promoted: GC4, GC7) — the signer does not (yet) act for the
    /// identity the row names.
    pub const SIGNER_NOT_ACTING_FOR: &str = "signer_not_acting_for";
    /// v4 — bytes this node keeps but does not serve or replicate: the row
    /// that carries them concludes nothing yet ([`super::hold_bytes`]).
    pub const BYTES_HELD_BACK: &str = "bytes_held_back";
    /// v5.1 (promoted: GC1, GC4) — a `withdraws` not admitted for its
    /// signer, read from the target's rows.
    pub const WITHDRAWS_NOT_ADMITTED: &str = "withdraws_not_admitted";
    /// v5.1 (promoted: GC1, GC8) — a row's signed instant is outside the
    /// freshness window of a standing read from other rows.
    pub const ASSERTED_AT_STALE: &str = "asserted_at_stale";
    /// v5.1 (GC1's door gap) — a composer whose held target is of another
    /// family (read from the target's statement).
    pub const COMPOSER_FAMILY_MISMATCH: &str = "composer_family_mismatch";
    /// The core tokens, in append order (pinned by I3550).
    pub const ALL: &[&str] = &[
        COUNT_SHORT,
        OWNER_UNSEATED,
        STEWARD_UNPROVEN,
        AMENDMENT_DIGEST_MISMATCH,
        REFOLD_REFUSED,
        REFOLDING,
        OWNER_AMBIGUOUS,
        LINK_UNHELD,
        GROUP_DISSOLVED,
        SELF_ROSTER_NOT_LANDED,
        SIGNER_NOT_ACTING_FOR,
        BYTES_HELD_BACK,
        WITHDRAWS_NOT_ADMITTED,
        ASSERTED_AT_STALE,
        COMPOSER_FAMILY_MISMATCH,
    ];

    /// Wave GC1's reasons (GC1 owns this module): the `admission.rs` gates'
    /// folds (v62.0.0, CC 2.7.3). Each token is the refusal token the gate
    /// raised before (its `Error::kind` without `federation_`, or the gate's
    /// own message token). A link not held is the core `link_unheld`.
    pub mod gc1 {
        /// AV-84: a party of a targeted-cohort row resolves outside its producer
        /// or the audience (`check_cohort_standing_resolved`).
        pub const COHORT_STANDING_REFUSED: &str = "cohort_standing_refused";
        /// A duty whose held permission is another issuer's, or out-reaches it
        /// (`check_duty_admission`; a permission not held is `link_unheld`).
        pub const DUTY_PERMISSION_UNRESOLVED: &str = "duty_permission_unresolved";
        /// A `config:*` renewal whose held target is not its own, or that leaves
        /// a live row beside it (`check_config_renewal_supersedes`).
        pub const CONFIG_RENEWAL_UNRESOLVED: &str = "config_renewal_unresolved";
        /// A licence emitter holds no live `license` chain from the authority.
        pub const LICENSURE_DELEGATOR_NOT_AUTHORITY: &str = "licensure_delegator_not_authority";
        /// A licence revision below one the authority already issued.
        pub const PARTNER_RECORD_ROLLBACK: &str = "partner_record_rollback";
        /// A licence's audience against its original or its affiliation charter.
        pub const LICENCE_AUDIENCE_REFUSED: &str = "licence_audience_refused";
        /// No consent from the subject for a consent-gated claim.
        pub const CONSENT_GATE_REFUSED: &str = "consent_gate_refused";
        /// A key revocation older than one already held for the subject.
        pub const REVOCATION_ROLLBACK: &str = "revocation_rollback";
        /// A delegation's term against its affiliation's `role_term_seconds`.
        pub const DELEGATION_TERM_REQUIRED: &str = "delegation_term_required";
        /// A revocation whose held `revoked_key_id` record is not the digest it
        /// names (not held at all is `link_unheld`).
        pub const REVOCATION_SUBJECT_REFUSED: &str = "revocation_subject_refused";
        /// A duty (moderate / review / slash) the signer holds no chain for.
        pub const DELEGATED_SCOPE_UNAUTHORIZED: &str = "delegated_scope_unauthorized";
        /// An owner binding over an affiliation that is not one, or not
        /// cosigned under its protocol (not held at all is `link_unheld`).
        pub const OWNER_BINDING_AFFILIATION_REFUSED: &str = "owner_binding_affiliation_refused";
        /// A role (canonical, infra_attest, privileged type) withdrawn.
        pub const ROLE_WITHDRAWN: &str = "role_withdrawn";
        /// The signer is de-admitted from this node's corpus (AV-77).
        pub const PEER_DEADMITTED: &str = "peer_deadmitted";
        /// A community record against its stored version or its founders' keys.
        pub const COMMUNITY_CONSENSUS_PROTOCOL_VIOLATION: &str =
            "community_consensus_protocol_violation";
        /// A community member with no live steward binding.
        pub const UNSTEWARDED_COMMUNITY_MEMBER: &str = "unstewarded_community_member";
        /// A community with no steward-bound moderator.
        pub const COMMUNITY_NO_MODERATOR: &str = "community_no_moderator";
        /// A consent row naming another key's `for_key_id` with no `grant` chain.
        pub const CONSENT_FOR_KEY_NOT_DELEGATED: &str = "consent_for_key_not_delegated";
        /// An agency scope delegated to a node-role recipient.
        pub const NODE_AGENCY_FORBIDDEN: &str = "node_agency_forbidden";
        /// A minor's owner binding announced at federation scope.
        pub const MINOR_OWNER_BINDING_AT_FEDERATION: &str = "minor_owner_binding_at_federation";
        /// A reserved family whose emitter holds no conferral from a trusted root.
        pub const RESERVED_PREFIX_EMITTER_MISMATCH: &str = "reserved_prefix_emitter_mismatch";
        /// An edition-2 `accord:*` row whose emitter holds no accord standing.
        pub const ACCORD_DIMENSION_REQUIRES_ACCORD_HOLDER: &str =
            "accord_dimension_requires_accord_holder";
        /// A reconsideration naming another community than its held target's.
        pub const RECONSIDERATION_COMMUNITY_MISMATCH: &str = "reconsideration_community_mismatch";
        /// v62.0.0 (K2-fix11; Eric's ruling) — a duty edge onto a person,
        /// void because a minor band is held about them and the edge does not
        /// post-date their earliest assured-adult proof
        /// (`age::duty_edge_void_for_minor`). Never seats on its own: the
        /// appointment is made again after the adult proof.
        pub const MINOR_APPOINTMENT_VOID: &str = "minor_appointment_void";
        /// GC1's tokens, in append order.
        pub const ALL: &[&str] = &[
            COHORT_STANDING_REFUSED,
            DUTY_PERMISSION_UNRESOLVED,
            CONFIG_RENEWAL_UNRESOLVED,
            LICENSURE_DELEGATOR_NOT_AUTHORITY,
            PARTNER_RECORD_ROLLBACK,
            LICENCE_AUDIENCE_REFUSED,
            CONSENT_GATE_REFUSED,
            REVOCATION_ROLLBACK,
            DELEGATION_TERM_REQUIRED,
            REVOCATION_SUBJECT_REFUSED,
            DELEGATED_SCOPE_UNAUTHORIZED,
            OWNER_BINDING_AFFILIATION_REFUSED,
            ROLE_WITHDRAWN,
            PEER_DEADMITTED,
            COMMUNITY_CONSENSUS_PROTOCOL_VIOLATION,
            UNSTEWARDED_COMMUNITY_MEMBER,
            COMMUNITY_NO_MODERATOR,
            CONSENT_FOR_KEY_NOT_DELEGATED,
            NODE_AGENCY_FORBIDDEN,
            MINOR_OWNER_BINDING_AT_FEDERATION,
            RESERVED_PREFIX_EMITTER_MISMATCH,
            ACCORD_DIMENSION_REQUIRES_ACCORD_HOLDER,
            RECONSIDERATION_COMMUNITY_MISMATCH,
            MINOR_APPOINTMENT_VOID,
        ];
    }
    /// Wave GC2's reasons (GC2 owns this module).
    pub mod gc2 {
        // GC2 — v62.0.0 (CC 2.7.3). Each is the refusal token the gate raised
        // before it held. (The self-roster eviction uses the core
        // `SELF_ROSTER_NOT_LANDED`.)
        /// A `withdraws` naming a held `cosign:signature:v1` row: a
        /// cosignature already sent is irrevocable
        /// (`cosign::COSIGN_SIGNATURE_IRREVOCABLE`).
        pub const COSIGN_SIGNATURE_IRREVOCABLE: &str = "cosign_signature_irrevocable";
        /// The signer's trust score, read from this node's trust grants, is
        /// below the configured threshold (`Error::TrustBelowThreshold`'s
        /// kind).
        pub const TRUST_BELOW_THRESHOLD: &str = "federation_trust_below_threshold";
        /// A takedown notice whose content no held row binds
        /// (`takedown_tombstone::token::CONTENT_UNBOUND`).
        pub const TAKEDOWN_CONTENT_UNBOUND: &str = "takedown_content_unbound";
        /// A takedown notice whose signer holds no takedown duty over the
        /// content as this node holds it
        /// (`takedown_tombstone::token::UNAUTHORISED`).
        pub const TAKEDOWN_UNAUTHORISED: &str = "takedown_unauthorised";
        /// A holding claim placed at a scope other than the held content's
        /// (`holding_claim::CUSTODY_ACK_SCOPE_MISMATCH`).
        pub const CUSTODY_ACK_SCOPE_MISMATCH: &str = "custody_ack_scope_mismatch";
        /// An occurrence-revocation carrier short of its self's roster
        /// majority (`malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM`).
        pub const CARRIER_WITHOUT_ROSTER_QUORUM: &str = "carrier_without_roster_quorum";
        /// An identity whose identity-ref names two or more held,
        /// self-recorded genesis `key:record`s: rivals, so its type is not
        /// read (no tie-break) and the row concludes nothing.
        pub const GENESIS_RECORD_RIVALS: &str = "genesis_record_rivals";
        /// GC2's tokens, in append order.
        pub const ALL: &[&str] = &[
            COSIGN_SIGNATURE_IRREVOCABLE,
            TRUST_BELOW_THRESHOLD,
            TAKEDOWN_CONTENT_UNBOUND,
            TAKEDOWN_UNAUTHORISED,
            CUSTODY_ACK_SCOPE_MISMATCH,
            CARRIER_WITHOUT_ROSTER_QUORUM,
            GENESIS_RECORD_RIVALS,
        ];
    }
    /// Wave GC3's reasons (GC3 owns this module).
    pub mod gc3 {
        // v62.0.0 (wave GC3; CC 2.7.3) — the conversion of the store's FK and
        //    rival-content arms, the ownership reclaim ceremony, the key plane's
        //    other-row reads, the accord recovery, custody, lineage-cosign and
        //    rendition gates. Each reuses the refusal token it replaces. The FK
        //    and self-roster waits use the CORE `LINK_UNHELD` /
        //    `SELF_ROSTER_NOT_LANDED`; `ROSTER_UNHELD` is shared with GC4's pg.
        /// The community or family whose roster a fold reads is not held.
        pub const ROSTER_UNHELD: &str = "roster_unheld";
        /// CC 3.2 reclaim, step 2: the `wa_adjudication_ref` names no held row.
        pub const WA_ADJUDICATION_REF_UNRESOLVABLE: &str = "wa_adjudication_ref_unresolvable";
        /// CC 3.2 reclaim: the named finding is not a WA quorum finding.
        pub const NOT_A_WA_FINDING: &str = "not_a_wa_finding";
        /// CC 3.2 reclaim: the finding adjudicates another binding.
        pub const FINDING_NOT_AGAINST_THIS_BINDING: &str = "finding_not_against_this_binding";
        /// CC 3.2 reclaim, step 1: the held finding names no petition.
        pub const PETITION_MISSING: &str = "petition_missing";
        /// CC 3.2 reclaim, step 1: the petition is not held, or is not one
        /// against this binding.
        pub const PETITION_UNRESOLVABLE: &str = "petition_unresolvable";
        /// CC 3.2 reclaim: the published WA body is not a held family.
        pub const WA_BODY_UNKNOWN: &str = "wa_body_unknown";
        /// CC 3.2 reclaim: the WA body's held roster is empty.
        pub const WA_ROSTER_EMPTY: &str = "wa_roster_empty";
        /// CC 3.2 reclaim, step 3: no held delegation gives the issuer standing.
        pub const ISSUER_LACKS_RECOVERY_STANDING: &str = "issuer_lacks_recovery_standing";
        /// CC 3.2 reclaim: the held freshness floor is inside the window.
        pub const NOT_ABANDONED: &str = "not_abandoned";
        /// #405 supersede: the incoming canonical record's quorum is not proven
        /// by the held roster (or a held withdrawal wins).
        pub const RE_SCRUB: &str = "re_scrub";
        /// #405 supersede, equal instant: the held row already carries the quorum.
        pub const ALREADY_ANCHORED_IDENTICAL: &str = "already_anchored_identical";
        /// The key id is not its fingerprint and no held family vouches for it.
        pub const KEY_ID_FINGERPRINT_MISMATCH: &str = "key_id_fingerprint_mismatch";
        /// A revocation's bound is later than the bound the held revocations of
        /// its subject set.
        pub const BOUND_RAISED: &str = "bound_raised";
        /// CC 4.2.6 recovery: no accord version is held.
        pub const ACCORD_RECOVERY_NO_HELD_ACCORD: &str = "accord_recovery_no_held_accord";
        /// CC 4.2.6 recovery: the statement names another held head.
        pub const ACCORD_RECOVERY_STATEMENT_UNBOUND: &str = "accord_recovery_statement_unbound";
        /// CC 4.2.6 recovery: the old key holds no held seat.
        pub const ACCORD_RECOVERY_NOT_A_HOLDER: &str = "accord_recovery_not_a_holder";
        /// CC 4.2.6 recovery: the new key already holds a held seat.
        pub const ACCORD_RECOVERY_SEAT_TAKEN: &str = "accord_recovery_seat_taken";
        /// CC 4.2.6 recovery: the new key's held record is not an accord holder's.
        pub const ACCORD_RECOVERY_NOT_A_HOLDER_KEY: &str = "accord_recovery_not_a_holder_key";
        /// CC 4.2.6 recovery: the version changes more than the held seat.
        pub const ACCORD_RECOVERY_CHANGES_MORE_THAN_ITS_SEAT: &str =
            "accord_recovery_changes_more_than_its_seat";
        /// CC 4.2.6 recovery: no held commitment is in force for the old key.
        pub const ACCORD_RECOVERY_COMMITMENT_MISSING: &str = "accord_recovery_commitment_missing";
        /// CC 4.2.6 recovery: the recovery key's record is not held.
        pub const ACCORD_RECOVERY_KEY_UNREGISTERED: &str = "accord_recovery_key_unregistered";
        /// CC 4.2.6 recovery: the held lineage already spent the recovery key.
        pub const ACCORD_RECOVERY_KEY_SPENT: &str = "accord_recovery_key_spent";
        /// CC 4.2.6 recovery: the held key material does not reproduce the
        /// commitment in force.
        pub const ACCORD_RECOVERY_KEY_MISMATCH: &str = "accord_recovery_key_mismatch";
        /// CC 4.2.6 recovery: the next commitment repeats one the held lineage
        /// holds.
        pub const ACCORD_RECOVERY_NEXT_COMMITMENT_NOT_FRESH: &str =
            "accord_recovery_next_commitment_not_fresh";
        /// CC 4.2.6 recovery: the new key carries a held recovery key's material.
        pub const ACCORD_RECOVERY_KEY_AS_SIGNING_KEY: &str = "accord_recovery_key_as_signing_key";
        /// CC 3.1.3.3: the device is not (yet) in the held cohort its custody
        /// report is placed at.
        pub const CUSTODY_ACK_OUTSIDE_COHORT: &str = "custody_ack_outside_cohort";
        /// CC 3.1.3.3 rule 4: the held custody report a retraction names is
        /// another device's.
        pub const CUSTODY_ACK_WITHDRAWS_NOT_THE_HOLDER: &str =
            "custody_ack_withdraws_not_the_holder";
        /// rc6 lineage cosign: the witness's principal founds the held lineage.
        pub const WITNESS_IS_FOUNDER: &str = "witness_is_founder";
        /// rc6 lineage cosign: the head's instant differs from the held head's.
        pub const HEAD_INSTANT_MISMATCH: &str = "head_instant_mismatch";
        /// rc6 lineage cosign: a held prior is not an ancestor of the head.
        pub const PRIOR_NOT_ANCESTOR: &str = "prior_not_ancestor";
        /// CC 3.2 T6(ii): the held head lags the held roster.
        pub const LINEAGE_HEAD_LAGS_ROSTER: &str = "lineage_head_lags_roster";
        /// CC 3.3.13: a rendition placed outside the held original's crossing.
        pub const RENDITION_PLACEMENT_MISMATCH: &str = "rendition_placement_mismatch";

        /// GC3's tokens, in append order.
        pub const ALL: &[&str] = &[
            ROSTER_UNHELD,
            WA_ADJUDICATION_REF_UNRESOLVABLE,
            NOT_A_WA_FINDING,
            FINDING_NOT_AGAINST_THIS_BINDING,
            PETITION_MISSING,
            PETITION_UNRESOLVABLE,
            WA_BODY_UNKNOWN,
            WA_ROSTER_EMPTY,
            ISSUER_LACKS_RECOVERY_STANDING,
            NOT_ABANDONED,
            RE_SCRUB,
            ALREADY_ANCHORED_IDENTICAL,
            KEY_ID_FINGERPRINT_MISMATCH,
            BOUND_RAISED,
            ACCORD_RECOVERY_NO_HELD_ACCORD,
            ACCORD_RECOVERY_STATEMENT_UNBOUND,
            ACCORD_RECOVERY_NOT_A_HOLDER,
            ACCORD_RECOVERY_SEAT_TAKEN,
            ACCORD_RECOVERY_NOT_A_HOLDER_KEY,
            ACCORD_RECOVERY_CHANGES_MORE_THAN_ITS_SEAT,
            ACCORD_RECOVERY_COMMITMENT_MISSING,
            ACCORD_RECOVERY_KEY_UNREGISTERED,
            ACCORD_RECOVERY_KEY_SPENT,
            ACCORD_RECOVERY_KEY_MISMATCH,
            ACCORD_RECOVERY_NEXT_COMMITMENT_NOT_FRESH,
            ACCORD_RECOVERY_KEY_AS_SIGNING_KEY,
            CUSTODY_ACK_OUTSIDE_COHORT,
            CUSTODY_ACK_WITHDRAWS_NOT_THE_HOLDER,
            WITNESS_IS_FOUNDER,
            HEAD_INSTANT_MISMATCH,
            PRIOR_NOT_ANCESTOR,
            LINEAGE_HEAD_LAGS_ROSTER,
            RENDITION_PLACEMENT_MISMATCH,
        ];
    }
    // Wave GC4's reasons (GC4 owns this module).
    pub mod gc4 {
        //! v62.0.0 (wave GC4; CC 2.7) — the group-plane, consent, amendment,
        //! re-bind, halt and replication-hold folds. The store's FK, roster
        //! and self-roster waits use the core `LINK_UNHELD` and
        //! `SELF_ROSTER_NOT_LANDED`; `GROUP_DISSOLVED` and
        //! `SIGNER_NOT_ACTING_FOR` are core too; `WITHDRAWS_NOT_ADMITTED` is
        //! GC1's (`gc1`).

        /// A `withdraws` names a family's record row
        /// (`group_plane::GROUP_RECORD_WITHDRAWS_REFUSED`).
        pub const GROUP_RECORD_WITHDRAWS_REFUSED: &str = "group_record_withdraws_refused";
        /// A replicated community record the typed door found conflicting
        /// with the held record (`ReplicatedCommunityRefusal::ConflictingRecord`).
        pub const CONFLICTING_RECORD: &str = "conflicting_record";
        /// A replicated community record that lowers the held conformance
        /// (`ReplicatedCommunityRefusal::DegradesConformance`).
        pub const DEGRADES_CONFORMANCE: &str = "degrades_conformance";
        /// This node is not (yet) in the row's audience: a LOCAL decline,
        /// never Invalid (CC 2.7.5, rc21 item 11).
        pub const NOT_IN_AUDIENCE: &str = "not_in_audience";
        /// The typed store kept a different object under the row's key.
        pub const HELD_OBJECT_DIFFERS: &str = "held_object_differs";
        /// A `consent:community_trust` grant over a node no owner binding
        /// is in force over at the grant's instant.
        pub const COMMUNITY_TRUST_OWNER_UNBOUND: &str = "community_trust_owner_unbound";
        /// `community_trust_consent::ATTESTER_NOT_OWNER`.
        pub const COMMUNITY_TRUST_ATTESTER_NOT_OWNER: &str = "community_trust_attester_not_owner";
        /// A grant whose `subject_key_ids` does not list the node's owner at
        /// the grant's instant.
        pub const COMMUNITY_TRUST_OWNER_UNLISTED: &str = "community_trust_owner_unlisted";
        /// `community_trust_consent::SUBJECTS_INCOMPLETE`.
        pub const COMMUNITY_TRUST_SUBJECTS_INCOMPLETE: &str = "community_trust_subjects_incomplete";
        /// The response an identity amendment names does not approve it, or
        /// its signer is not a seated WA (rc21 item 20).
        pub const IDENTITY_AMENDMENT_UNAUTHORIZED: &str = "identity_amendment_unauthorized";
        /// A seat's transit-pair rotation no held re-bind carries: kept, not
        /// counted at a receiver (rc21 items 12, 13).
        pub const SERVE_ROTATION_BEFORE_REBIND: &str = "serve_transit_pair_rotation_before_rebind";
        /// An accord invocation that repeats the `invocation_id` or `nonce`
        /// of an earlier-ranked invocation of its accord: kept, changes
        /// nothing (rc21 item 1).
        pub const ACCORD_INVOCATION_REPLAYED: &str = "accord_invocation_replayed";

        /// GC4's tokens, in append order.
        pub const ALL: &[&str] = &[
            GROUP_RECORD_WITHDRAWS_REFUSED,
            CONFLICTING_RECORD,
            DEGRADES_CONFORMANCE,
            NOT_IN_AUDIENCE,
            HELD_OBJECT_DIFFERS,
            COMMUNITY_TRUST_OWNER_UNBOUND,
            COMMUNITY_TRUST_ATTESTER_NOT_OWNER,
            COMMUNITY_TRUST_OWNER_UNLISTED,
            COMMUNITY_TRUST_SUBJECTS_INCOMPLETE,
            IDENTITY_AMENDMENT_UNAUTHORIZED,
            SERVE_ROTATION_BEFORE_REBIND,
            ACCORD_INVOCATION_REPLAYED,
        ];
    }
    // Wave GC5's reasons (GC5 owns this module).
    // GC5
    pub mod gc5 {
        //! v62.0.0 (wave GC5; CC 2.7.3) — the group planes', genesis', re-bind,
        //! cosign, affiliation, location and roster-head fold reasons. A row
        //! waiting on a named row it does not hold uses the core
        //! [`super::LINK_UNHELD`].
        /// X2 pass 2: one definition per token (E0659 through the globs);
        /// this slice re-exports the owner's.
        pub use super::gc2::COSIGN_SIGNATURE_IRREVOCABLE;
        /// A held row the statement names is of another group or kind than the
        /// statement says (a roster version's chain, a membership change's
        /// `refs.head`): fixed once the named row is held, so the row concludes
        /// nothing.
        pub const NAMES_ANOTHER_GROUP: &str = "group_names_another_group";
        /// A group version under an occupied id with no supersede proof, or one
        /// that lost the occupied-id race to a differing version (#758, #910).
        pub const GROUP_OCCUPIED: &str = "group_occupied_by_another_version";
        /// A supersede proof that names a prior this node does not hold as the
        /// head (`stale supersede_proof`, #910): the intermediate version may not
        /// have arrived.
        pub const STALE_SUPERSEDE_PROOF: &str = "stale_supersede_proof";
        /// A version whose `prev_head_digest` names neither the held head nor a
        /// tip the kernel reads (CC 3.2 T6).
        pub const LINEAGE_PREV_HEAD_MISMATCH: &str = "lineage_prev_head_mismatch";
        /// An amendment that lifts a held family's `consensus_protocol_entrenched`.
        pub const FAMILY_ENTRENCHED: &str = "family_entrenched";
        /// A witnessed lineage's version that does not reflect the roster
        /// events answered since its prior head (CC 3.2 T6 (i)).
        pub const LINEAGE_VERSION_DISAGREES_WITH_FOLD: &str = "lineage_version_disagrees_with_fold";
        /// The held record of the addressed group is not the cohort the row
        /// addresses (CC 4.4.3.2.8).
        pub const AFFILIATION_COHORT_MISMATCH: &str = "federation_affiliation_cohort_mismatch";
        /// An act against a member that no key outside the deciding seat has
        /// countersigned yet (CC 4.4.3.12).
        pub const AFFILIATION_COUNTERSIGN_MISSING: &str = "affiliation_countersign_missing";
        /// A cosign signer who is not an active member of the group at the
        /// event's instant (or, evicted, signed outside W).
        pub const COSIGN_SIGNER_NOT_MEMBER: &str = "cosign_signer_not_member";
        /// The proposer already holds another open cosign hold in the group.
        pub const COSIGN_OPEN_PENDING_EXISTS: &str = "cosign_open_pending_exists";
        /// A location-proof withdrawal that is not the held proof with
        /// `withdrawn_at` set (other fields differ).
        pub const LOCATION_PROOF_WITHDRAW_MISMATCH: &str = "location_proof_withdraw_mismatch";
        /// A location-proof withdrawal signed by a key that did not attest the
        /// held proof.
        pub const LOCATION_PROOF_WITHDRAW_NOT_THE_ATTESTER: &str =
            "location_proof_withdraw_not_the_attester";
        /// A geographic community member with no in-force location proof inside
        /// the constraint cell.
        pub const GEOGRAPHIC_MEMBER_UNLOCATED: &str = "geographic_member_unlocated";
        /// A genesis bundle whose holders' voices are short of its count (or
        /// whose recovery statement does not count): held, concluding nothing
        /// (CC 2.6.1.11); Verify's `genesis_bundle_count_unmet`.
        pub const GENESIS_BUNDLE_COUNT_UNMET: &str = "genesis_bundle_count_unmet";
        /// A genesis bundle whose held predecessor is not Valid.
        pub const GENESIS_BUNDLE_PREV_NOT_VALID: &str = "genesis_bundle_prev_not_valid";
        /// A genesis bundle naming a row with no place (or a party with no row).
        pub const GENESIS_BUNDLE_ROW_UNPLACED: &str = "genesis_bundle_row_unplaced";
        /// A genesis bundle naming an Invalid row, or one that breaks its place.
        pub const GENESIS_BUNDLE_ROW_INVALID: &str = "genesis_bundle_row_invalid";
        /// A seat re-bind counted at a genesis head that a later held bundle
        /// superseded.
        pub const REBIND_HEAD_NOT_IN_FORCE: &str = "rebind_head_not_in_force";
        /// A roster version whose number is not one past the greatest version
        /// it names (the named versions' content).
        pub const VERSION_DOES_NOT_FOLLOW: &str = "group_version_does_not_follow";
        /// GC5's tokens.
        pub const ALL: &[&str] = &[
            NAMES_ANOTHER_GROUP,
            GROUP_OCCUPIED,
            STALE_SUPERSEDE_PROOF,
            LINEAGE_PREV_HEAD_MISMATCH,
            FAMILY_ENTRENCHED,
            LINEAGE_VERSION_DISAGREES_WITH_FOLD,
            AFFILIATION_COHORT_MISMATCH,
            AFFILIATION_COUNTERSIGN_MISSING,
            COSIGN_SIGNER_NOT_MEMBER,
            COSIGN_OPEN_PENDING_EXISTS,
            COSIGN_SIGNATURE_IRREVOCABLE,
            LOCATION_PROOF_WITHDRAW_MISMATCH,
            LOCATION_PROOF_WITHDRAW_NOT_THE_ATTESTER,
            GEOGRAPHIC_MEMBER_UNLOCATED,
            GENESIS_BUNDLE_COUNT_UNMET,
            GENESIS_BUNDLE_PREV_NOT_VALID,
            GENESIS_BUNDLE_ROW_UNPLACED,
            GENESIS_BUNDLE_ROW_INVALID,
            REBIND_HEAD_NOT_IN_FORCE,
            VERSION_DOES_NOT_FOLLOW,
        ];
    }
    /// Wave GC6's reasons (GC6 owns this module).
    pub mod gc6 {
        // GC6
        // ── v62.0.0 (wave GC6; CC 2.7) — each reuses the refusal token its
        // gate raised before the conversion (the detail is that refusal). ──

        /// A membership reply names a proposal this node does not hold.
        pub const MEMBERSHIP_PROPOSAL_UNRESOLVED: &str = "membership_proposal_unresolved";
        /// A growth names a member no admitted acceptance seats yet.
        pub const MEMBERSHIP_ACCEPTANCE_UNRESOLVED: &str = "membership_acceptance_unresolved";
        /// A reply's signer is not the invitee (by person), or the reply does not
        /// bind the proposal it names.
        pub const MEMBERSHIP_ACCEPTANCE_MISMATCH: &str = "membership_acceptance_mismatch";
        /// The member signed an opposite reply to the same proposal EARLIER.
        pub const MEMBERSHIP_REPLY_CONFLICT: &str = "membership_reply_conflict";
        /// The member declined the invitation the growth needs.
        pub const MEMBERSHIP_DECLINED: &str = "membership_declined";
        /// The proposal a growth rests on expired or was withdrawn.
        pub const MEMBERSHIP_PROPOSAL_EXPIRED: &str = "membership_proposal_expired";
        /// A standing proposal for a room that is not an open public room, or
        /// from a signer who is not one of its founders.
        pub const MEMBERSHIP_OPEN_PROPOSAL_NOT_OPEN: &str = "membership_open_proposal_not_open";
        /// Under `founder_only` / `open:self_admit`, a proposal from a signer
        /// who is not a founder of the held group.
        pub const MEMBERSHIP_PROPOSER_NOT_FOUNDER: &str = "membership_proposer_not_founder";
        /// A proposal whose signer the held group's write scope does not admit.
        pub const MEMBERSHIP_PROPOSER_OUT_OF_SCOPE: &str = "membership_proposer_out_of_scope";
        /// A supersede lists a member neither the held record nor the roster has.
        pub const MEMBERSHIP_SUPERSEDE_CANNOT_ADD: &str = "membership_supersede_cannot_add";
        /// A charter about the accord family, which this node does not hold yet.
        pub const NO_CONSTITUTIONAL_ROOT_YET: &str = "federation_no_constitutional_root_yet";
        /// A charter about a held family carrying no well-formed pre-rotation
        /// commitment (judged only once the family is held).
        pub const FAMILY_CHARTER_COMMITMENT_MALFORMED: &str = "family_charter_commitment_malformed";
        /// An accord charter's recovery commitment is a named holder's held
        /// signing key.
        pub const ACCORD_RECOVERY_KEY_NOT_APART: &str = "accord_recovery_key_not_apart";
        /// A recovery charter names a successor whose key record is not held.
        pub const CHARTER_SUCCESSOR_UNHELD: &str = "charter_successor_unheld";
        /// A recovery charter no live charter of its predecessor pre-commits.
        pub const CHARTER_RECOVERY_UNBOUND: &str = "charter_recovery_unbound";
        /// A listing whose room record is not held yet.
        pub const SCOPE_MEMBERSHIP_UNRESOLVED: &str = "scope_membership_unresolved";
        /// A listing whose held room is not `public`.
        pub const COMMUNITY_LISTING_ROOM_NOT_PUBLIC: &str = "community_listing_room_not_public";
        /// A listing whose subkind / admission members disagree with the held room.
        pub const COMMUNITY_LISTING_MALFORMED: &str = "community_listing_malformed";
        /// A listing signed by neither a founder nor a named moderate-holder.
        pub const COMMUNITY_LISTING_SIGNER_NOT_AUTHORIZED: &str =
            "community_listing_signer_not_authorized";
        /// A community version crossing the `public` boundary of the held head.
        pub const PUBLIC_SUBKIND_CHANGED: &str = "public_subkind_changed";
        /// An accord roster change while this node holds no accord head.
        pub const ACCORD_ROSTER_CHANGE_NO_HELD_ACCORD: &str = "accord_roster_change_no_held_accord";
        /// An accord roster change not bound to the held head.
        pub const ACCORD_ROSTER_CHANGE_UNBOUND: &str = "accord_roster_change_unbound";
        /// An accord roster change that changes more than the held head's seats.
        pub const ACCORD_ROSTER_CHANGE_NOT_SEATS: &str = "accord_roster_change_not_seats";
        /// An accord roster change no held, authorized, closed decision covers.
        pub const ACCORD_ROSTER_CHANGE_UNCOVERED: &str = "accord_roster_change_uncovered";
        /// An accord roster change short of the standing roster's majority.
        pub const ACCORD_ROSTER_CHANGE_SHORT: &str = "accord_roster_change_short";
        /// An accord roster change adding a key whose held record is not an
        /// accord holder's.
        pub const ACCORD_ROSTER_CHANGE_NOT_A_HOLDER_KEY: &str =
            "accord_roster_change_not_a_holder_key";
        /// An accord roster change seating a holder who did not sign it.
        pub const ACCORD_ROSTER_CHANGE_UNCONSENTED: &str = "accord_roster_change_unconsented";
        /// A purge tombstone whose notice's authority (root, seats, voices,
        /// protocol) the held rows do not show yet: it waits (CC 2.4.1.1).
        pub const PURGE_UNAUTHORISED: &str = "purge_unauthorised";
        /// A purge whose selection digest differs from its notice's.
        pub const PURGE_SELECTION_DIGEST_MISMATCH: &str = "purge_selection_digest_mismatch";
        /// A public room joiner's acceptance from a key with no live
        /// federation-scope owner binding (CC 4.4.3.17 rc21): it does not count.
        pub const JOINER_OWNER_UNBOUND: &str = "joiner_owner_unbound";
        /// Two ledgers claim one `(..)` triple: contested, neither counts while
        /// both stand (CC 3.3.10.1 rc21).
        pub const LEDGER_TRIPLE_CONTESTED: &str = "ledger_triple_contested";
        /// An accord version whose charter's recovery commitments do not cover
        /// exactly its roster, or whose named charter is not held.
        pub const ACCORD_CHARTER_COVERAGE: &str = "accord_charter_coverage";
        /// A replicated purge naming a held row no notice may retract.
        pub const PURGE_RETRACTION_INADMISSIBLE: &str = "purge_retraction_inadmissible";
        /// A replicated purge naming a held row a proven person is the subject of
        /// (INTERIM, until the notice is a row).
        pub const PURGE_HUMAN_SUBJECT: &str = "purge_human_subject_pending_notice_row";
        /// v62.0.0 (K2-fix18; CC 3.4.13 Q5, CC 5.4.6) — a growth that would
        /// list, on a `public` room's roster, a person a held age row places
        /// in a minor band (`age::age_band_held`): held while the row stands,
        /// restored when it is withdrawn or outranked. A standing protection
        /// (class 2): it re-folds on `key:<person>`.
        pub const MINOR_PUBLIC_ROSTER_ENTRY: &str = "minor_public_roster_entry";

        /// GC6's tokens.
        pub const ALL: &[&str] = &[
            MEMBERSHIP_PROPOSAL_UNRESOLVED,
            MEMBERSHIP_ACCEPTANCE_UNRESOLVED,
            MEMBERSHIP_ACCEPTANCE_MISMATCH,
            MEMBERSHIP_REPLY_CONFLICT,
            MEMBERSHIP_DECLINED,
            MEMBERSHIP_PROPOSAL_EXPIRED,
            MEMBERSHIP_OPEN_PROPOSAL_NOT_OPEN,
            MEMBERSHIP_PROPOSER_NOT_FOUNDER,
            MEMBERSHIP_PROPOSER_OUT_OF_SCOPE,
            MEMBERSHIP_SUPERSEDE_CANNOT_ADD,
            NO_CONSTITUTIONAL_ROOT_YET,
            FAMILY_CHARTER_COMMITMENT_MALFORMED,
            ACCORD_RECOVERY_KEY_NOT_APART,
            CHARTER_SUCCESSOR_UNHELD,
            CHARTER_RECOVERY_UNBOUND,
            SCOPE_MEMBERSHIP_UNRESOLVED,
            COMMUNITY_LISTING_ROOM_NOT_PUBLIC,
            COMMUNITY_LISTING_MALFORMED,
            COMMUNITY_LISTING_SIGNER_NOT_AUTHORIZED,
            PUBLIC_SUBKIND_CHANGED,
            ACCORD_ROSTER_CHANGE_NO_HELD_ACCORD,
            ACCORD_ROSTER_CHANGE_UNBOUND,
            ACCORD_ROSTER_CHANGE_NOT_SEATS,
            ACCORD_ROSTER_CHANGE_UNCOVERED,
            ACCORD_ROSTER_CHANGE_SHORT,
            ACCORD_ROSTER_CHANGE_NOT_A_HOLDER_KEY,
            ACCORD_ROSTER_CHANGE_UNCONSENTED,
            PURGE_UNAUTHORISED,
            PURGE_SELECTION_DIGEST_MISMATCH,
            JOINER_OWNER_UNBOUND,
            LEDGER_TRIPLE_CONTESTED,
            ACCORD_CHARTER_COVERAGE,
            PURGE_RETRACTION_INADMISSIBLE,
            PURGE_HUMAN_SUBJECT,
            MINOR_PUBLIC_ROSTER_ENTRY,
        ];
    }
    /// Wave GC7's reasons (GC7 owns this module).
    pub mod gc7 {
        // GC7 (v62.0.0 wave GC7; CC 2.7.3 + CC rc21 items 14, 17/18, X6).
        /// A stream's held state (abandoned) takes no append (`blob_admit`).
        pub const STREAM_ABANDONED: &str = "stream_abandoned";
        /// A stream held in another cohort / community (`blob_admit`).
        pub const STREAM_ELSEWHERE: &str = "stream_elsewhere";
        /// A stream whose first append was another key's (`blob_admit`).
        pub const STREAM_FOREIGN: &str = "stream_foreign";
        /// A chunk at a `(stream, seq)` another chunk holds, or a stream that moved under its seal.
        pub const STREAM_SEQ_HELD: &str = "stream_seq_held";
        /// A chunk under a community epoch no longer current, or a stream-key counter / epoch that moved.
        pub const STREAM_EPOCH_MOVED: &str = "stream_epoch_moved";
        /// Bytes a held tombstone purged (every byte floor).
        pub const BLOB_PURGED: &str = "blob_purged";
        /// An STH whose root disagrees with this node's own chunks, or with a held STH at the same tree size.
        pub const STH_ROOT_DISAGREES: &str = "sth_root_disagrees";
        /// A delivery receipt naming a root no published STH carries yet (it waits).
        pub const RECEIPT_ROOT_UNPUBLISHED: &str = "receipt_root_unpublished";
        /// A delivery receipt disagreeing with a held one at the same slot.
        pub const RECEIPT_EQUIVOCATION: &str = "receipt_equivocation";
        /// An announcement or claim of bytes this node does not hold (it waits).
        pub const BLOB_NOT_HELD: &str = "blob_not_held";
        /// A stream-keyed chunk named under a community epoch.
        pub const STREAM_KEYED_CHUNK_COMMUNITY_EPOCH: &str = "stream_keyed_chunk_community_epoch";
        /// Roster standing: the protocol cannot be evaluated over the held roster.
        pub const ROSTER_CONSENSUS_UNEVALUABLE: &str = "roster_consensus_unevaluable";
        /// Roster standing: the signer's own membership event is not held yet.
        pub const ROSTER_AUTHORITY_NOT_ESTABLISHED: &str = "roster_authority_not_established";
        /// Roster standing: the change would leave no founder.
        pub const ROSTER_LAST_FOUNDER: &str = "roster_last_founder";
        /// Roster standing: a signer is not an active member.
        pub const ROSTER_CONSENSUS_INSUFFICIENT: &str = "roster_consensus_insufficient";
        /// Roster standing: a removal outside its window.
        pub const ROSTER_REMOVAL_OUTSIDE_WINDOW: &str = "roster_removal_outside_window";
        /// A dissolution that changes more than `dissolved_at` of the head it names.
        pub const DISSOLUTION_NOT_TERMINAL_ONLY: &str = "dissolution_not_terminal_only";
        /// A supersede whose `prior_member_key_ids` is not the held roster.
        pub const PRIOR_ROSTER_MISMATCH: &str = "prior_roster_mismatch";
        /// A supersede's structure or one-seat check is not met over the held roster and key records.
        pub const MEMBERSHIP_CHANGE_UNAUTHORIZED: &str = "membership_change_unauthorized";
        /// A write outside the cohort the writer holds a seat in.
        pub const WRITE_SCOPE_REFUSED: &str = "write_scope_refused";
        /// mesh_config: the root is not one this node's trust edges subscribe.
        pub const ROOT_NOT_TRUSTED: &str = "root_not_trusted";
        /// mesh_config: no live conferral from the root to the author.
        pub const AUTHOR_NOT_ROOT_AUTHORIZED: &str = "author_not_root_authorized";
        /// mesh_config: the declared delegation is not the live conferral.
        pub const DELEGATION_ID_NOT_CONFERRING: &str = "delegation_id_not_conferring";
        /// mesh_config: an emergency the holder's own earlier concluding relief was in force at (kept, concludes nothing; CC rc21 item 14).
        pub const BACK_TO_BACK_RENEWAL: &str = "back_to_back_renewal";
        /// mesh_config: a durable conversion whose named emergency is not held, or disagrees.
        pub const DURABLE_UNRATIFIED: &str = "durable_unratified";
        /// mesh_config: a cold durable act short of the root's own quorum.
        pub const DURABLE_WITHOUT_ROOT_QUORUM: &str = "durable_without_root_quorum";
        /// A revocation of another's key without the moderation authority.
        pub const REVOCATION_UNAUTHORIZED: &str = "revocation_unauthorized";
        /// A canonical record supersede the held accord roster does not carry.
        pub const SUPERSEDE_POLICY_REFUSED: &str = "supersede_policy_refused";
        /// An agent's occurrence with no live owner binding at its instant.
        pub const AGENT_OCCURRENCE_UNOWNED: &str = "agent_occurrence_unowned";
        /// An agent's occurrence authored by someone other than its owner.
        pub const AGENT_OCCURRENCE_NOT_OWNER_AUTHORED: &str = "agent_occurrence_not_owner_authored";
        /// reverse quorum: the named cohort is not held here.
        pub const COHORT_UNKNOWN: &str = "cohort_unknown";
        /// reverse quorum: the cohort's protocol does not govern by objection.
        pub const NOT_GOVERNED: &str = "not_governed";
        /// reverse quorum: the cohort has not adopted the steward tier.
        pub const STEWARD_TIER_NOT_ADOPTED: &str = "steward_tier_not_adopted";
        /// reverse quorum: the vote is not filed against the named action's actor.
        pub const NOT_FILED_AGAINST_ACTOR: &str = "not_filed_against_actor";
        /// reverse quorum: the voter is the actor.
        pub const ACTOR_RECUSED: &str = "actor_recused";
        /// reverse quorum: the ballot is signed before the action.
        pub const BALLOT_PREDATES_ACTION: &str = "ballot_predates_action";
        /// A goal `supersedes` that is not its declarer's amendment.
        pub const GOAL_AMENDMENT_NOT_DECLARERS: &str = "goal_amendment_not_declarers";
        /// A replicated erasure the producer's own withdraws do not authorise.
        pub const SUBJECT_ERASURE_UNAUTHORISED: &str = "subject_erasure_unauthorised";
        /// A widening that does not widen the prior it names.
        pub const WIDENING_NOT_OF_PRIOR: &str = "widening_not_of_prior";
        /// A second, different `key:record` for a held `key_id`: both kept, the rival held and never read as the key's (CC rc21 items 17/18).
        pub const KEY_RECORD_RIVAL: &str = "key_record_rival";
        /// An amendment to an entrenched family, or one weakening its `consensus_protocol` (CC rc21 X6).
        pub const AMENDMENT_ENTRENCHED: &str = "amendment_entrenched";
        /// GC7's tokens, in append order.
        pub const ALL: &[&str] = &[
            STREAM_ABANDONED,
            STREAM_ELSEWHERE,
            STREAM_FOREIGN,
            STREAM_SEQ_HELD,
            STREAM_EPOCH_MOVED,
            BLOB_PURGED,
            STH_ROOT_DISAGREES,
            RECEIPT_ROOT_UNPUBLISHED,
            RECEIPT_EQUIVOCATION,
            BLOB_NOT_HELD,
            STREAM_KEYED_CHUNK_COMMUNITY_EPOCH,
            ROSTER_CONSENSUS_UNEVALUABLE,
            ROSTER_AUTHORITY_NOT_ESTABLISHED,
            ROSTER_LAST_FOUNDER,
            ROSTER_CONSENSUS_INSUFFICIENT,
            ROSTER_REMOVAL_OUTSIDE_WINDOW,
            DISSOLUTION_NOT_TERMINAL_ONLY,
            PRIOR_ROSTER_MISMATCH,
            MEMBERSHIP_CHANGE_UNAUTHORIZED,
            WRITE_SCOPE_REFUSED,
            ROOT_NOT_TRUSTED,
            AUTHOR_NOT_ROOT_AUTHORIZED,
            DELEGATION_ID_NOT_CONFERRING,
            BACK_TO_BACK_RENEWAL,
            DURABLE_UNRATIFIED,
            DURABLE_WITHOUT_ROOT_QUORUM,
            REVOCATION_UNAUTHORIZED,
            SUPERSEDE_POLICY_REFUSED,
            AGENT_OCCURRENCE_UNOWNED,
            AGENT_OCCURRENCE_NOT_OWNER_AUTHORED,
            COHORT_UNKNOWN,
            NOT_GOVERNED,
            STEWARD_TIER_NOT_ADOPTED,
            NOT_FILED_AGAINST_ACTOR,
            ACTOR_RECUSED,
            BALLOT_PREDATES_ACTION,
            GOAL_AMENDMENT_NOT_DECLARERS,
            SUBJECT_ERASURE_UNAUTHORISED,
            WIDENING_NOT_OF_PRIOR,
            KEY_RECORD_RIVAL,
            AMENDMENT_ENTRENCHED,
        ];
    }
    // GC8 — wave GC8's reason tokens (the whole block below is GC8's).
    /// Wave GC8's reasons (GC8 owns this module).
    pub mod gc8 {
        /// X2 pass 2: one definition per token (E0659 through the globs);
        /// this slice re-exports the owner's.
        pub use super::gc6::NO_CONSTITUTIONAL_ROOT_YET;
        /// X2 pass 2: one definition per token (E0659 through the globs);
        /// this slice re-exports the owner's.
        pub use super::gc7::PRIOR_ROSTER_MISMATCH;
        // ── v62.0.0 (wave GC8; CC 2.7.3) — each reuses the refusal token the
        //    gate raised before it was a fold condition. ──────────────────────
        /// A trust-root founder the accord did not confer (or no key record of
        /// it is held): `check_founder_eligible`.
        pub const FOUNDER_NOT_CONFERRED: &str = "founder_not_conferred";
        /// A trust-root founder that is node-bearing and not an accord seat.
        pub const NODE_BEARING_FOUNDER: &str = "node_bearing_founder";
        /// A human founder whose `steward` conferral by the accord is not held.
        pub const ROLE_NOT_ACCORD_CONFERRED: &str = "role_not_accord_conferred";
        /// An acceptance edge whose named head is not the fresh witnessed head
        /// this node holds (CC 3.2 T4a).
        pub const TRUST_ROOT_HEAD_STALE: &str = "trust_root_head_stale";
        /// A trust-root version that changes the grade or the entrenched
        /// protocol against the version held.
        pub const GRADE_CHANGED: &str = "grade_changed";
        /// A trust-root chain that does not extend the version held (CC 2.7.8:
        /// two versions of one head wait as tips).
        pub const TRUST_ROOT_CHAIN: &str = "trust_root_chain";
        /// The witness plane holds a head this node does not.
        pub const LINEAGE_HEAD_BEHIND_WITNESS: &str = "lineage_head_behind_witness";
        /// A founder's resignation dated at or before the held head's instant.
        pub const RESIGNATION_BACKDATED: &str = "resignation_backdated";
        /// A trust root whose held head is stalled admits nothing new.
        pub const LIVENESS_STALLED_NON_ADMITTING: &str = "liveness_stalled_non_admitting";
        /// A roster-plane change of a founder seat the held record or fold
        /// names.
        pub const FOUNDER_SEAT_ON_PLANE: &str = "founder_seat_on_plane";
        /// The trust root a count is asked over is not held, not rooted, or
        /// stalled here (`steward_purge::unauthorised_reason`'s tokens).
        pub const ROOT_NOT_HELD: &str = "root_not_held";
        /// See [`ROOT_NOT_HELD`].
        pub const ROOT_NOT_ROOTED: &str = "root_not_rooted";
        /// See [`ROOT_NOT_HELD`].
        pub const STALLED: &str = "stalled";
        /// A voice or cosigner that holds no seat at the held head.
        pub const NOT_A_SEAT: &str = "not_a_seat";
        /// A cosigner whose key record is not held here.
        pub const COSIGNER_KEY_NOT_HELD: &str = "cosigner_key_not_held";
        /// The held head's protocol cannot be evaluated over its held roster.
        pub const PROTOCOL_UNEVALUABLE: &str = "protocol_unevaluable";
        /// Key grant: the signer is not the minter and no held `grant`
        /// delegation from the minter names it.
        pub const SIGNER_NOT_MINTER: &str = "signer_not_minter";
        /// Key grant: the signer is not an active member occurrence by the held
        /// roster fold.
        pub const SIGNER_NOT_ACTIVE_MEMBER: &str = "signer_not_active_member";
        /// Key grant: the signer does not speak for the held blob's author.
        pub const SIGNER_NOT_AUTHOR: &str = "signer_not_author";
        /// Key grant: the signer does not speak for the held stream's owner.
        pub const SIGNER_NOT_STREAM_OWNER: &str = "signer_not_stream_owner";
        /// A row signed outside W whose signer no longer meets the rule at
        /// receipt.
        pub const ASSERTED_AT_STALE: &str = "asserted_at_stale";
        /// Key grant: the recipient is not (yet) in the held audience.
        pub const RECIPIENT_NOT_IN_AUDIENCE: &str = "recipient_not_in_audience";
        /// The constitutional family's version is not the held accord's head,
        /// or its standing majority is not met over the held roster.
        pub const CONSTITUTIONAL_FAMILY_RESERVED: &str =
            "federation_constitutional_family_reserved";
        /// A quarantine marker about a subject whose key record is not held.
        pub const SUBJECT_KEY_UNKNOWN: &str = "subject_key_unknown";
        /// A quarantine release naming a marker not held (or of another
        /// subject / dimension).
        pub const MARKER_UNKNOWN: &str = "marker_unknown";
        /// A slash by a signer whose duty the held seats and chains do not
        /// prove.
        pub const SLASH_UNAUTHORIZED: &str = "slash_unauthorized";
        /// A member a membership change names has no held key record.
        pub const MEMBER_NOT_IN_DIRECTORY: &str = "member_not_in_directory";
        /// A transport binding that does not supersede the held signed binding
        /// of its slot.
        pub const DESTINATION_SUPERSEDED: &str = "destination_superseded";
        /// Two members a membership change names resolve, by their held key
        /// records, to one key.
        pub const DUPLICATE_FOUNDER_KEY: &str = "duplicate_founder_key";
        /// GC8's tokens.
        pub const ALL: &[&str] = &[
            FOUNDER_NOT_CONFERRED,
            NODE_BEARING_FOUNDER,
            ROLE_NOT_ACCORD_CONFERRED,
            TRUST_ROOT_HEAD_STALE,
            GRADE_CHANGED,
            TRUST_ROOT_CHAIN,
            LINEAGE_HEAD_BEHIND_WITNESS,
            RESIGNATION_BACKDATED,
            LIVENESS_STALLED_NON_ADMITTING,
            FOUNDER_SEAT_ON_PLANE,
            ROOT_NOT_HELD,
            ROOT_NOT_ROOTED,
            STALLED,
            NOT_A_SEAT,
            COSIGNER_KEY_NOT_HELD,
            PROTOCOL_UNEVALUABLE,
            SIGNER_NOT_MINTER,
            SIGNER_NOT_ACTIVE_MEMBER,
            SIGNER_NOT_AUTHOR,
            SIGNER_NOT_STREAM_OWNER,
            ASSERTED_AT_STALE,
            RECIPIENT_NOT_IN_AUDIENCE,
            CONSTITUTIONAL_FAMILY_RESERVED,
            SUBJECT_KEY_UNKNOWN,
            MARKER_UNKNOWN,
            SLASH_UNAUTHORIZED,
            NO_CONSTITUTIONAL_ROOT_YET,
            MEMBER_NOT_IN_DIRECTORY,
            DESTINATION_SUPERSEDED,
            DUPLICATE_FOUNDER_KEY,
            PRIOR_ROSTER_MISMATCH,
        ];
    }
    #[allow(unused_imports)]
    pub use gc1::*;
    #[allow(unused_imports)]
    pub use gc2::*;
    #[allow(unused_imports)]
    pub use gc3::*;
    #[allow(unused_imports)]
    pub use gc4::*;
    #[allow(unused_imports)]
    pub use gc5::*;
    #[allow(unused_imports)]
    pub use gc6::*;
    #[allow(unused_imports)]
    pub use gc7::*;
    #[allow(unused_imports)]
    pub use gc8::*;

    /// Every slice of the registry: the core first, then each wave's.
    pub const SLICES: &[&[&str]] = &[
        ALL,
        gc1::ALL,
        gc2::ALL,
        gc3::ALL,
        gc4::ALL,
        gc5::ALL,
        gc6::ALL,
        gc7::ALL,
        gc8::ALL,
    ];

    /// The registered tokens: the union of [`SLICES`], sorted, each once.
    #[must_use]
    pub fn registry() -> std::collections::BTreeSet<&'static str> {
        SLICES.iter().flat_map(|s| s.iter().copied()).collect()
    }

    /// Is `token` a registered reason?
    #[must_use]
    pub fn is_registered(token: &str) -> bool {
        SLICES.iter().any(|s| s.contains(&token))
    }
}

/// The most rows one re-fold pass evaluates. A pass that reaches it logs and
/// stops; the remainder re-folds on the next touch or [`refold_all`].
pub const MAX_REFOLD_STEPS: usize = 4096;

/// The most held reasons one page returns.
pub const MAX_HELD_PAGE: u32 = 1000;

/// One input a fold read, by the key `ceg_fold_reads.read_key` stores.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dep {
    /// A row by id: its voices, a withdrawal or approval naming it.
    Row(RowId),
    /// Any row about or by this key id / identity-ref: a binding, a seat, an
    /// age witness, an owner binding.
    Key(String),
    /// The coarse fallback: any row of this family.
    Family(String),
}

impl Dep {
    /// `Dep::Key` of `id`.
    #[must_use]
    pub fn key(id: &str) -> Self {
        Self::Key(id.to_owned())
    }

    /// v4 (GC4's helper, adopted) — `Dep::Row` of a 64-hex row id; `None`
    /// for any other id (an earlier-form id: declare `Dep::key` of it).
    #[must_use]
    pub fn row_hex(id: &str) -> Option<Self> {
        let b = hex::decode(id).ok()?;
        <[u8; 32]>::try_from(b.as_slice())
            .ok()
            .map(|d| Self::Row(RowId(d)))
    }

    /// The stored text: `row:<hex>`, `key:<id>` or `family:<family>`.
    #[must_use]
    pub fn read_key(&self) -> String {
        match self {
            Self::Row(r) => format!("row:{}", r.hex()),
            Self::Key(k) => format!("key:{k}"),
            Self::Family(f) => format!("family:{f}"),
        }
    }
}

/// The planes a folded row projects into ([`Plane`]); stored as text in
/// `ceg_fold_state.plane`.
pub mod plane {
    /// A row through the attestation gates (`voices::put_counted_row`).
    pub const ATTESTATION: &str = "attestation";
    /// T2's families stored as attestation rows (takedown, custody, key grant).
    pub const TYPED_ATTESTATION: &str = "typed_attestation";
    /// T2's trust edges (an attestation row plus the v1.3 trust projection).
    pub const TRUST: &str = "trust";
    /// The key plane (`key:record`, `key:revocation`): a read model re-derived
    /// from the held, not-held-back key statements.
    pub const KEY: &str = "key";
    /// O1's occurrence binds (one projection per (identity, occurrence)).
    /// FINAL (G0-fix6): a version of a person's key roster.
    pub const OCCURRENCE: &str = "occurrence";
    /// T1's group planes (roster versions, counted membership changes).
    pub const GROUP: &str = "group";
    /// W1's counted re-bind.
    pub const REBIND: &str = "rebind";
    /// T2's own-store families (revocation, occurrence revocation, delivery
    /// receipt, cosign state, the steward purge notice).
    pub const TYPED_FINAL: &str = "typed_final";
    /// v4 — a byte executor's row (a chunk, an STH, a receipt) with no
    /// edition-2 statement of its own ([`super::hold_bytes`]). Its door
    /// re-checks itself; the fold never re-runs it.
    pub const BYTES: &str = "bytes";
}

/// Why a held row concludes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldReason {
    /// The row id.
    pub row_id: RowId,
    /// The row's family.
    pub family: String,
    /// The tier the row concludes at.
    pub tier: String,
    /// v4 — did the row first arrive through the replicated door?
    pub replicated: bool,
    /// v4 — its [`plane`].
    pub plane: String,
    /// A [`reason`] token.
    pub reason: String,
    /// The refusal the gate would have raised, as text.
    pub detail: String,
    /// THIS node's clock (POSIX µs) when the row was first held for this
    /// reason. Node-local; never replicated, never read by a rule.
    pub since_us: i64,
}

impl HeldReason {
    /// The JSON the adopter surfaces return.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "row_id": self.row_id.hex(),
            "family": self.family,
            "tier": self.tier,
            "replicated": self.replicated,
            "plane": self.plane,
            "reason": self.reason,
            "detail": self.detail,
            "since_us": self.since_us,
        })
    }
}

/// v4 — the fold's whole record of one row, held or concluded
/// (`ceg_fold_state`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldState {
    /// The row id.
    pub row_id: RowId,
    /// The row's family.
    pub family: String,
    /// The tier it first arrived at.
    pub tier: String,
    /// Did it first arrive through the replicated door?
    pub replicated: bool,
    /// Its [`plane`].
    pub plane: String,
    /// Its projection slot: rows sharing one slot project into one typed
    /// record (an occurrence pair); a row alone in its slot names itself.
    pub slot: String,
    /// `None`: concluded. `Some`: why it concludes nothing.
    pub held: Option<HeldReason>,
}

/// What one fold evaluation recorded for a row: the storage unit
/// ([`FederationDirectory::put_fold_record`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldRecord {
    /// The row id.
    pub row_id: RowId,
    /// The row's family.
    pub family: String,
    /// The tier the row concludes at (its first arrival's).
    pub tier: String,
    /// v4 — did it first arrive through the replicated door?
    pub replicated: bool,
    /// v4 — its [`plane`].
    pub plane: String,
    /// v4 — its projection slot ([`FoldState::slot`]).
    pub slot: String,
    /// `None`: concluded. `Some((reason, detail))`: held, concluding nothing.
    pub held: Option<(String, String)>,
    /// Every input the evaluation read ([`Dep::read_key`]), always including
    /// the row's own `row:<id>`.
    pub reads: BTreeSet<String>,
}

/// v4 — **the arrival a row is folded under**: how it FIRST arrived. The
/// door (`ingest::put_admitted_row`) runs under it, every record written
/// inside reads it, and a re-fold replays it exactly (T1: a replicated
/// membership change re-folds under the replicated door's gates).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// The row.
    pub row_id: RowId,
    /// The replicated door (a peer offered it under an id) or the local one.
    pub replicated: bool,
    /// The tier.
    pub tier: String,
    /// Its [`plane`].
    pub plane: &'static str,
    /// Its projection slot.
    pub slot: String,
}

tokio::task_local! {
    static ARRIVAL: Arrival;
}

/// Run `fut` under `arrival` (the door's own use).
pub(crate) async fn arriving<T, Fut>(arrival: Arrival, fut: Fut) -> T
where
    Fut: std::future::Future<Output = T>,
{
    ARRIVAL.scope(arrival, fut).await
}

fn current_arrival(row_id: &RowId) -> Option<Arrival> {
    ARRIVAL
        .try_with(|a| (a.row_id == *row_id).then(|| a.clone()))
        .ok()
        .flatten()
}

/// What one re-fold pass changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefoldReport {
    /// Held, now concluded.
    pub concluded: Vec<RowId>,
    /// Concluded, now held.
    pub unconcluded: Vec<RowId>,
    /// Re-folded and still held (the reason may have changed).
    pub still_held: Vec<RowId>,
    /// Rows evaluated.
    pub steps: usize,
}

// ─────────────────────────────────────────────────────────────────────────
//  The attempt (task-local): what gates mark
// ─────────────────────────────────────────────────────────────────────────

/// One evaluation of a row's gates.
struct Attempt {
    row_id: RowId,
    /// The voice the door is offering now (counted with the held ones while
    /// the gates run; kept only if the row concludes or is held).
    offered: Option<Voice>,
    /// The first fold condition a gate found unmet: `(reason, detail)`.
    held: Mutex<Option<(String, String)>>,
    /// Every input declared.
    reads: Mutex<BTreeSet<String>>,
}

tokio::task_local! {
    static ATTEMPT: Arc<Attempt>;
}

/// **Declare an input** the running fold read. A no-op outside an attempt.
pub fn reads(dep: Dep) {
    let _ = ATTEMPT.try_with(|a| {
        if let Ok(mut r) = a.reads.lock() {
            r.insert(dep.read_key());
        }
    });
}

/// Is a fold attempt running on this task?
#[must_use]
pub fn in_attempt() -> bool {
    ATTEMPT.try_with(|_| ()).is_ok()
}

fn mark(reason: &'static str, detail: String) {
    let _ = ATTEMPT.try_with(|a| {
        if let Ok(mut h) = a.held.lock() {
            if h.is_none() {
                *h = Some((reason.to_owned(), detail));
            }
        }
    });
}

/// **A fold condition is unmet**: mark the running attempt held with
/// `reason` (the error's text is the detail) and return `err` unchanged. The
/// door then keeps the voice and concludes nothing. Outside an attempt this
/// is the plain refusal it wraps.
#[must_use]
pub fn hold(reason: &'static str, err: Error) -> Error {
    mark(reason, err.to_string());
    err
}

/// v4 (GC4's helper, adopted) — [`hold`] for a refusal whose kind MAY be a
/// substrate failure: a storage fault (`Backend`), an exhausted pool or an
/// unrouted proxy method is never a fold condition and is returned
/// unmarked; anything else is held.
#[must_use]
pub fn hold_refusal(reason: &'static str, err: Error) -> Error {
    match err {
        Error::Backend(_) | Error::PoolExhausted { .. } | Error::Unsupported { .. } => err,
        other => hold(reason, other),
    }
}

/// v4 (GC4's helper, adopted) — mark the running attempt held with `reason`
/// and `detail`, for a gate whose refusal is not a federation [`Error`]
/// (a `BlobError`, an `Ok(Refused { .. })` answer). The caller then returns
/// its own refusal.
pub fn hold_detail(reason: &'static str, detail: impl Into<String>) {
    mark(reason, detail.into());
}

/// v4 — **run `fut` outside the running attempt**: a NESTED write a door
/// makes for another row (GC2: `self_roster::gate`'s proposal row) must not
/// mark the outer row. The marks and reads made inside are discarded; the
/// nested row's own door records its own.
pub async fn isolated<T, Fut>(fut: Fut) -> T
where
    Fut: std::future::Future<Output = T>,
{
    let a = Arc::new(Attempt {
        row_id: RowId([0; 32]),
        offered: None,
        held: Mutex::new(None),
        reads: Mutex::new(BTreeSet::new()),
    });
    ATTEMPT.scope(a, fut).await
}

/// Mark the running attempt held with `reason`, without an error in hand
/// (V1b's `note_short`). The door fills the detail from the refusal the gate
/// returns.
pub(crate) fn note(reason: &'static str) {
    mark(reason, String::new());
}

/// The offered voice of the running attempt, when it is an attempt for
/// `row_id` (`voices::voices_of_row` counts it with the held ones).
pub(crate) fn offered_voice(row_id: &RowId) -> Option<Voice> {
    ATTEMPT
        .try_with(|a| {
            if a.row_id == *row_id {
                a.offered.clone()
            } else {
                None
            }
        })
        .ok()
        .flatten()
}

/// v62.0.0 (wave GC8; G0 v3 §4 "never hold an error you then swallow") —
/// **run `fut` with its marks DISCARDED and its reads KEPT.** For a caller
/// that turns a gate's refusal into an answer (`Ok(false)`, "not rooted", an
/// `is_err()` probe): the gate's `hold` / `note` inside `fut` mark a private
/// attempt that is dropped, so they cannot leak onto an unrelated refusal of
/// the running row; every read it declared is still declared on the running
/// attempt (the answer it produced depends on those rows). Outside an
/// attempt it is `fut.await`.
pub(crate) async fn unmarked<T, Fut>(fut: Fut) -> T
where
    Fut: std::future::Future<Output = T>,
{
    let Ok((row_id, offered)) = ATTEMPT.try_with(|a| (a.row_id, a.offered.clone())) else {
        return fut.await;
    };
    let inner = Arc::new(Attempt {
        row_id,
        offered,
        held: Mutex::new(None),
        reads: Mutex::new(BTreeSet::new()),
    });
    let out = ATTEMPT.scope(inner.clone(), fut).await;
    let inner_reads = inner.reads.lock().map(|g| g.clone()).unwrap_or_default();
    let _ = ATTEMPT.try_with(|a| {
        if let Ok(mut r) = a.reads.lock() {
            r.extend(inner_reads);
        }
    });
    out
}

/// What an attempt recorded: the first unmet condition and every read.
pub(crate) struct Attempted {
    /// `(reason, detail)` of the first unmet condition, if any.
    pub(crate) held: Option<(String, String)>,
    /// Every read, including `row:<row id>`.
    pub(crate) reads: BTreeSet<String>,
}

/// Run `fut` (the row's gates) as a fold attempt for `row_id`, with
/// `offered` counted as one of its voices.
pub(crate) async fn attempt<T, Fut>(
    row_id: RowId,
    offered: Option<Voice>,
    fut: Fut,
) -> (T, Attempted)
where
    Fut: std::future::Future<Output = T>,
{
    let a = Arc::new(Attempt {
        row_id,
        offered,
        held: Mutex::new(None),
        reads: Mutex::new(BTreeSet::new()),
    });
    let out = ATTEMPT.scope(a.clone(), fut).await;
    let held = a.held.lock().ok().and_then(|g| g.clone());
    let mut reads = a.reads.lock().map(|g| g.clone()).unwrap_or_default();
    reads.insert(Dep::Row(row_id).read_key());
    (out, Attempted { held, reads })
}

// ─────────────────────────────────────────────────────────────────────────
//  Recording
// ─────────────────────────────────────────────────────────────────────────

/// Store what an evaluation found for `row_id`. The arrival context (the
/// replicated flag, the tier, the plane, the slot) is the running door's
/// ([`Arrival`]); outside one, the row's stored state's; for a row never
/// folded, the local attestation plane at `tier`. A directory with no fold
/// store (the capsule proxy, whose owner runs the fold) answers
/// `Unsupported`, which is logged and skipped.
///
/// # Errors
/// Storage failures.
pub(crate) async fn record<F>(
    dir: &F,
    row_id: RowId,
    family: &str,
    tier: &str,
    held: Option<(String, String)>,
    reads: BTreeSet<String>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let (tier, replicated, plane_name, slot) = match current_arrival(&row_id) {
        Some(a) => (a.tier, a.replicated, a.plane.to_owned(), a.slot),
        None => match dir.fold_state(&row_id).await {
            Ok(Some(s)) => (s.tier, s.replicated, s.plane, s.slot),
            Ok(None) => (
                tier.to_owned(),
                false,
                plane::ATTESTATION.to_owned(),
                Dep::Row(row_id).read_key(),
            ),
            Err(e) => return Err(e),
        },
    };
    let rec = FoldRecord {
        row_id,
        family: family.to_owned(),
        tier,
        replicated,
        plane: plane_name,
        slot,
        held,
        reads,
    };
    dir.put_fold_record(&rec).await
}

/// fix2 (triage round 2) — **record a door's `Pending`**, on EVERY hold:
/// the reason is the attempt's own mark when a gate set one, else
/// [`reason::COUNT_SHORT`]; the reads REPLACE the row's earlier ones with
/// this attempt's (plus the row's own), so the dependency index follows what
/// the row waits on NOW. Before fix2 only the first hold was recorded: a row
/// first held on A and later on B never re-folded when B arrived, and its
/// reason stayed A's.
///
/// # Errors
/// Storage failures.
pub(crate) async fn record_pending<F>(
    dir: &F,
    row_id: RowId,
    family: &str,
    tier: &str,
    mark: Option<(String, String)>,
    mut reads: BTreeSet<String>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    reads.insert(Dep::Row(row_id).read_key());
    let held = mark.unwrap_or_else(|| {
        (
            reason::COUNT_SHORT.to_owned(),
            "the row's voices are short of its count".to_owned(),
        )
    });
    record(dir, row_id, family, tier, Some(held), reads).await
}

/// v4 — **is this held statement held BACK** (its row concludes nothing)?
/// The key plane's reader (`ingest::held_keys_for_kid`) skips such a
/// statement, so a held `key:revocation` or `key:record` is not read as
/// key plane until it concludes.
///
/// # Errors
/// Storage failures.
pub async fn is_held_back<F>(dir: &F, statement: &[u8]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    match RowId::of_statement(statement) {
        Some(id) => Ok(dir.fold_held(&id).await?.is_some()),
        None => Ok(false),
    }
}

/// v5 — the row's NAMED past (the row itself and the rows its `refs` name:
/// heads, `further_heads`, cited rows, all immutable) against its declared
/// reads: every read outside it. v5.1: on a FINAL plane such reads are
/// allowed as MONOTONE triggers ([`enforce_final_plane`]); this stays the
/// diagnostic of which reads are not named past.
#[must_use]
pub fn named_past_violations(admitted: &AdmittedRow, reads: &BTreeSet<String>) -> Vec<String> {
    let mut allowed: BTreeSet<String> = admitted
        .names
        .iter()
        .map(|n| Dep::Row(n.row).read_key())
        .collect();
    allowed.insert(Dep::Row(admitted.row_id).read_key());
    reads
        .iter()
        .filter(|r| !allowed.contains(*r))
        .cloned()
        .collect()
}

/// v5.1 — **the FINAL-plane rule, as ruled** (refining v5):
///
/// - A gate on a FINAL plane reads the row's named past, and it MAY also
///   make DECLARED reads of other state (the shared steward-binding and
///   owner readers declare theirs). Such a read is **monotone**: it can only
///   move a held row TO concluded, when the input arrives (re-fold on
///   arrival). Once the row concludes, a later change to that input never
///   un-concludes it ([`Plane::is_final`]; CC 2.7.5: it acts forward,
///   through a later counted version). Arrival order can therefore change
///   WHEN the row concludes, never WHETHER.
/// - **What is enforced.** A read nobody declared is invisible to the fold,
///   so it cannot be caught at the read. What the fold CAN catch is its
///   symptom: a FINAL-plane row HELD on a marked condition that declared no
///   input beyond the row itself. Nothing could ever re-fold it, so it waits
///   on something undeclared. A test build panics, naming the reason; a
///   production build logs at `error`. (A count is exempt: `count_short`
///   waits on the row's own voices.)
pub(crate) fn enforce_final_plane(
    plane_name: &str,
    admitted: &AdmittedRow,
    held: Option<&(String, String)>,
    reads: &BTreeSet<String>,
) {
    if !plane_for(plane_name).is_final() {
        return;
    }
    let Some((why, _)) = held else {
        return;
    };
    if !final_hold_untriggered(admitted, why, reads) {
        return;
    }
    #[cfg(test)]
    panic!(
        "fold: row {} on the FINAL plane {plane_name} is held ({why}) on no declared input: \
         declare what it waits for (`fold::reads`)",
        admitted.row_id.hex()
    );
    #[cfg(not(test))]
    tracing::error!(
        plane = plane_name,
        row_id = %admitted.row_id.hex(),
        reason = %why,
        "fold: a FINAL-plane row is held on no declared input"
    );
}

/// v5.1 — is a FINAL-plane hold with `reason` waiting on nothing it
/// declared? True when every declared read is the row's own (`row:<id>`)
/// and the reason is not a count (`count_short`, which the row's own voices
/// re-fold).
#[must_use]
pub fn final_hold_untriggered(
    admitted: &AdmittedRow,
    reason_token: &str,
    reads: &BTreeSet<String>,
) -> bool {
    if reason_token == reason::COUNT_SHORT {
        return false;
    }
    let own = Dep::Row(admitted.row_id).read_key();
    reads.iter().all(|r| *r == own)
}

/// v4 — the projection slot of a blob's bytes: every row that carries or
/// claims them (a holding claim, a chunk, an STH) folds into it.
#[must_use]
pub fn blob_slot(sha256: &[u8; 32]) -> String {
    format!("blob:{}", hex::encode(sha256))
}

/// v4 — **are a blob's bytes servable?** Kept-but-not-served: bytes whose
/// every carrying row the fold holds back (held rows in [`blob_slot`], none
/// concluded) are neither served nor replicated. Bytes no folded row names
/// (an earlier-form blob) are servable as before.
///
/// # Errors
/// Storage failures.
pub async fn bytes_servable<F>(dir: &F, sha256: &[u8; 32]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let slot = blob_slot(sha256);
    if !dir.fold_slot_rows(&slot).await?.is_empty() {
        return Ok(true);
    }
    Ok(!dir.fold_slot_held(&slot).await?)
}

/// v4 — a byte executor's own row (`row_id`: its row's id, or the bytes'
/// digest when the row has none) is HELD: its bytes are kept and not served
/// ([`bytes_servable`]) until [`release_bytes`].
///
/// # Errors
/// Storage failures.
pub async fn hold_bytes<F>(
    dir: &F,
    row_id: RowId,
    sha256: &[u8; 32],
    reason_token: &str,
    detail: &str,
    reads: BTreeSet<String>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    bytes_record(
        dir,
        row_id,
        sha256,
        Some((reason_token.to_owned(), detail.to_owned())),
        reads,
    )
    .await
}

/// v4 — the byte executor's row concludes: its bytes are served again.
///
/// # Errors
/// Storage failures.
pub async fn release_bytes<F>(
    dir: &F,
    row_id: RowId,
    sha256: &[u8; 32],
    reads: BTreeSet<String>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    bytes_record(dir, row_id, sha256, None, reads).await
}

async fn bytes_record<F>(
    dir: &F,
    row_id: RowId,
    sha256: &[u8; 32],
    held: Option<(String, String)>,
    mut reads: BTreeSet<String>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    reads.insert(Dep::Row(row_id).read_key());
    let rec = FoldRecord {
        row_id,
        family: plane::BYTES.to_owned(),
        tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
        replicated: false,
        plane: plane::BYTES.to_owned(),
        slot: blob_slot(sha256),
        held,
        reads,
    };
    dir.put_fold_record(&rec).await
}

/// v4 — the boot hook: a re-fold interrupted between taking a row out of
/// its typed table and recording why (`refolding`) is repaired by
/// [`refold_all`]. One indexed probe when none is.
///
/// # Errors
/// Storage failures; the re-fold's.
pub async fn repair_at_open<F>(dir: &F) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if dir.fold_any_refolding().await? {
        // v62.0.0 (BF22, pass 4m4) — the re-fold's future TYPE ends here.
        // Every host awaits this through a store open (`run_migrations` on
        // both backends), and an `async fn` future carries its whole callee
        // tree in its type: once the fold's admission walks grew past the
        // default recursion depth (the slashing countersign paths, pass
        // 4m4), proving an open `Send` overflowed (E0275) in persist AND in
        // any host crate that `tokio::spawn`s it. A `dyn Future + Send` is
        // proved once, here, and the open path's type stops at the box, so
        // deeper folds behind it do not reach a host's Send proof.
        let refold: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<RefoldReport, Error>> + Send + '_>,
        > = Box::pin(refold_all(dir));
        let report = refold.await?;
        tracing::info!(
            steps = report.steps,
            concluded = report.concluded.len(),
            unconcluded = report.unconcluded.len(),
            "fold: repaired an interrupted re-fold at open"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
//  The reason API
// ─────────────────────────────────────────────────────────────────────────

/// **Why `row_id` concludes nothing.** `None` when it is concluded, or not
/// held here.
///
/// # Errors
/// Storage failures.
pub async fn why_held<F>(dir: &F, row_id: &RowId) -> Result<Option<HeldReason>, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.fold_held(row_id).await
}

/// The held rows that conclude nothing, in row-id order after `after`, at
/// most `limit` (clamped to [`MAX_HELD_PAGE`]).
///
/// # Errors
/// Storage failures.
pub async fn held_rows<F>(
    dir: &F,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldReason>, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.fold_held_page(after, limit.min(MAX_HELD_PAGE)).await
}

/// v62.0.0 (KR-fix2 rev 5; CC rc22 7b4a55e) — **[`why_held`] as a host
/// reads it.** The same answer for every row but a seat re-bind
/// (`transport:canonical_rebind`), whose answer is RECOMPUTED from the held
/// lineage and the voices' signed instants
/// ([`transport_rebind::rebind_counted`](super::transport_rebind::rebind_counted),
/// the count the verdict readers use): `None` when it reaches its count now,
/// a [`reason::COUNT_SHORT`] reason when it does not.
///
/// The re-bind plane is FINAL, so its stored state is the door's answer at
/// the last arrival and differs between two nodes that received the voices
/// and a later bundle in opposite orders. No verdict reads that stored state;
/// this keeps the host listings from reading it either. The fold's own
/// callers keep [`why_held`] (the stored state is what a re-fold acts on).
///
/// # Errors
/// Storage failures.
pub async fn why_held_listed<F>(dir: &F, row_id: &RowId) -> Result<Option<HeldReason>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let stored = dir.fold_held(row_id).await?;
    if stored.as_ref().is_some_and(|h| h.plane != plane::REBIND) {
        return Ok(stored);
    }
    match super::transport_rebind::rebind_counted(dir, row_id).await? {
        None => Ok(stored),
        Some(true) => Ok(None),
        Some(false) => {
            if stored.is_some() {
                return Ok(stored);
            }
            // Stored as concluded (its voices arrived before the bundle that
            // now dates them out); the same reason a node that held the
            // bundle first stores.
            Ok(dir.fold_state(row_id).await?.map(|st| HeldReason {
                row_id: st.row_id,
                family: st.family,
                tier: st.tier,
                replicated: st.replicated,
                plane: st.plane,
                reason: reason::COUNT_SHORT.to_owned(),
                detail: "the row's voices are short of its count".to_owned(),
                since_us: 0,
            }))
        }
    }
}

/// v62.0.0 (KR-fix2 rev 5) — **[`held_rows`] as a host reads it**: the same
/// page without the seat re-binds. A re-bind's stored state is arrival-order
/// dependent (see [`why_held_listed`]), and a page of STORED held rows cannot
/// list the re-binds a node stores as concluded and no longer counts, so the
/// page lists none of them on any node. A re-bind's state is read per row
/// ([`why_held_listed`], `voice_status`) or per seat
/// (`transport_rebind::rebind_held_for`). The page is refilled past the rows
/// it leaves out, so a short page still means the listing is done.
///
/// # Errors
/// Storage failures.
pub async fn held_rows_listed<F>(
    dir: &F,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldReason>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let limit = limit.min(MAX_HELD_PAGE);
    let mut out: Vec<HeldReason> = Vec::new();
    let mut after = after.copied();
    loop {
        let page = dir.fold_held_page(after.as_ref(), limit).await?;
        let full = page.len() >= limit as usize;
        let Some(last) = page.last().map(|h| h.row_id) else {
            break;
        };
        for h in page {
            if h.plane != plane::REBIND && out.len() < limit as usize {
                out.push(h);
            }
        }
        if !full || out.len() >= limit as usize {
            break;
        }
        after = Some(last);
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────
//  What a statement touches
// ─────────────────────────────────────────────────────────────────────────

/// The read keys a statement touches: its own row, every row it names, its
/// signer (`iss`, the kid), its subject, its author, and its family.
#[must_use]
pub fn touches(admitted: &AdmittedRow) -> BTreeSet<String> {
    let mut t = BTreeSet::new();
    t.insert(Dep::Row(admitted.row_id).read_key());
    for n in &admitted.names {
        t.insert(Dep::Row(n.row).read_key());
    }
    t.insert(Dep::key(&admitted.iss).read_key());
    t.insert(Dep::key(&admitted.sub).read_key());
    t.insert(Dep::key(&hex::encode(admitted.kid)).read_key());
    if let Some(a) = &admitted.author {
        t.insert(Dep::key(a).read_key());
    }
    t.insert(Dep::Family(admitted.family.clone()).read_key());
    t
}

/// The read keys a typed attestation row touches: its id (when it is an
/// edition-2 row id), its attester, its attested key and its subjects.
#[must_use]
pub fn touches_of_attestation(row: &Attestation) -> BTreeSet<String> {
    let mut t = BTreeSet::new();
    if let Some(id) = super::voices::carried_row_id(row) {
        t.insert(Dep::Row(id).read_key());
    }
    t.insert(Dep::key(&row.attesting_key_id).read_key());
    t.insert(Dep::key(&row.attested_key_id).read_key());
    for s in &row.subject_key_ids {
        t.insert(Dep::key(s).read_key());
    }
    if let Some(f) = family_of_row(row) {
        t.insert(Dep::Family(f).read_key());
    }
    // v62.0.0 (wave GC2) — a row that binds content (its `evidence_refs`
    // name a digest, in either spelling) touches `key:content:<digest>`,
    // which the takedown notice gate reads (`takedown_tombstone::content_dep`).
    if let Some(refs) = row
        .attestation_envelope
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
    {
        for r in refs
            .iter()
            .filter_map(crate::federation::admission::evidence_ref_hex)
        {
            t.insert(Dep::key(&format!("content:{r}")).read_key());
        }
    }
    t
}

/// The family of the statement a typed row carries.
fn family_of_row(row: &Attestation) -> Option<String> {
    let h = row
        .attestation_envelope
        .get(super::ingest::STATEMENT_MEMBER)?
        .as_str()?;
    let bytes = hex::decode(h).ok()?;
    let (protected, _) = super::liveness::statement_parts(&bytes)?;
    protected.get_int(-70002)?.as_text().map(str::to_owned)
}

/// Every read key of `admitted`, widened by one hop: the touches of every
/// typed row it names (a withdrawal's target's attester and subject), and of
/// its own typed projection.
async fn touched_by<F>(dir: &F, admitted: &AdmittedRow) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut t = touches(admitted);
    for n in &admitted.names {
        if let Some(a) = dir.get_attestation(&n.row.hex()).await? {
            t.extend(touches_of_attestation(&a));
        }
    }
    if let Some(a) = dir.get_attestation(&admitted.row_id.hex()).await? {
        t.extend(touches_of_attestation(&a));
    }
    Ok(t)
}

// ─────────────────────────────────────────────────────────────────────────
//  The door's tail
// ─────────────────────────────────────────────────────────────────────────

/// **After `put_statement` stored a statement**: every held or concluded
/// row whose fold read what it touches is re-folded ([`refold_touched`]).
/// (v4: the hold/conclusion bookkeeping moved into the door,
/// `ingest::put_admitted_row`, where the arrival is known.) This runs on a
/// re-offer too, so a caller that retries after a failed re-fold heals it.
///
/// # Errors
/// Storage failures (the statement itself is already kept).
pub(crate) async fn after_statement<F>(
    dir: &F,
    admitted: &AdmittedRow,
    tier: &str,
    outcome: &StatementOutcome,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let _ = tier;
    match outcome {
        StatementOutcome::Pending { .. } => Ok(()),
        StatementOutcome::Row { .. }
        | StatementOutcome::Voice { .. }
        | StatementOutcome::KeyPlane { .. } => {
            let touched = touched_by(dir, admitted).await?;
            // fix4 — a row is never its own fold dependent: the door just
            // judged it, so re-folding it here could only strand it.
            let me: BTreeSet<RowId> = [admitted.row_id].into_iter().collect();
            refold_touched_excluding(dir, touched, &me)
                .await
                .map(|_| ())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The planes: how a concluded row leaves its typed table
// ─────────────────────────────────────────────────────────────────────────

/// v4 — **one plane's un-project hook.** The fold concludes a row on every
/// plane the same way (it re-runs the door, `ingest::put_admitted_row`,
/// under the row's [`Arrival`]); un-concluding differs per plane:
///
/// - a plane with a dry re-check ([`Plane::recheck`]: the attestation plan)
///   re-asks its gates without writing, and takes the row out only when a
///   gate marks a fold condition;
/// - otherwise the fold takes the row's whole SLOT out
///   ([`Plane::unconclude`]) and re-concludes every concluded row of the
///   slot, the row itself included, under each one's own arrival: the
///   slot's typed record is rebuilt from the rows that still conclude (an
///   occurrence pair's newest-signed concluded bind wins again);
/// - a FINAL plane ([`Plane::is_final`]) never un-concludes: its rows are
///   counted acts final once the count is met, or acts read only from their
///   own signer (CC 2.7.5: "A count once met is final"; "a revocation never
///   lapses"). Its gates must read only the row's named past
///   (`Dep::Row(named)`), which no later row changes.
#[async_trait::async_trait]
pub trait Plane: Send + Sync {
    /// The [`plane`] name.
    fn name(&self) -> &'static str;

    /// A FINAL plane: nothing un-concludes its rows.
    fn is_final(&self) -> bool {
        false
    }

    /// Re-ask the plane's gates about a concluded row WITHOUT writing.
    /// `None`: this plane has no dry re-check (the fold un-projects the
    /// slot and re-concludes it instead).
    async fn recheck(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Option<Result<(), Error>> {
        let _ = (dir, row);
        None
    }

    /// Take the projection of `row`'s slot out of the plane's typed tables.
    /// Its statements stay held.
    ///
    /// # Errors
    /// Storage failures.
    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error>;
}

/// The attestation plane (and T2's attestation-backed families).
struct AttestationPlane(&'static str);

#[async_trait::async_trait]
impl Plane for AttestationPlane {
    fn name(&self) -> &'static str {
        self.0
    }

    async fn recheck(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Option<Result<(), Error>> {
        match dir.get_attestation(&row.row_id.hex()).await {
            Ok(Some(a)) => Some(dir.recheck_attestation(&a).await),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        dir.unconclude_attestation(&row.row_id.hex())
            .await
            .map(|_| ())
    }
}

/// T2's trust edges: the attestation row, then the v1.3 trust rows of the
/// edge's two ends re-derived (`typed::project_trust_for`).
struct TrustPlane;

#[async_trait::async_trait]
impl Plane for TrustPlane {
    fn name(&self) -> &'static str {
        plane::TRUST
    }

    async fn recheck(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Option<Result<(), Error>> {
        AttestationPlane(plane::TRUST).recheck(dir, row).await
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        let ends = dir
            .get_attestation(&row.row_id.hex())
            .await?
            .map(|a| (a.attesting_key_id, a.attested_key_id));
        dir.unconclude_attestation(&row.row_id.hex()).await?;
        if let Some((from, to)) = ends {
            Box::pin(super::typed::project_trust_for(dir, &from)).await?;
            Box::pin(super::typed::project_trust_for(dir, &to)).await?;
        }
        Ok(())
    }
}

/// The key plane: its read model is re-derived from the key statements not
/// held back (`ingest::put_admitted_row` re-projects after a change), so
/// there is nothing to delete.
struct KeyPlane;

#[async_trait::async_trait]
impl Plane for KeyPlane {
    fn name(&self) -> &'static str {
        plane::KEY
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        let _ = (dir, row);
        Ok(())
    }
}

/// A plane whose concluded rows are final (CC 2.7.5).
struct FinalPlane(&'static str);

#[async_trait::async_trait]
impl Plane for FinalPlane {
    fn name(&self) -> &'static str {
        self.0
    }

    fn is_final(&self) -> bool {
        true
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        let _ = (dir, row);
        Ok(())
    }
}

static ATTESTATION_PLANE: AttestationPlane = AttestationPlane(plane::ATTESTATION);
static TYPED_ATTESTATION_PLANE: AttestationPlane = AttestationPlane(plane::TYPED_ATTESTATION);
static TRUST_PLANE: TrustPlane = TrustPlane;
static KEY_PLANE: KeyPlane = KeyPlane;
// G0-fix6 — an occurrence bind is a version of a person's key roster (CC
// 2.7.8: "A person's keys ... are this one roster"): counted at the head it
// names and FINAL once concluded. A later eviction or owner change acts
// forward through a later version and never un-binds it (CC 2.7.5, 2.7.8:
// "A removal ... changes the members there, not at the old head"; CC 2.7.7:
// "A row of a removed key counts when the removal has it among its
// ancestors").
static OCCURRENCE_PLANE: FinalPlane = FinalPlane(plane::OCCURRENCE);
static GROUP_PLANE: FinalPlane = FinalPlane(plane::GROUP);
static REBIND_PLANE: FinalPlane = FinalPlane(plane::REBIND);
static TYPED_FINAL_PLANE: FinalPlane = FinalPlane(plane::TYPED_FINAL);
static BYTES_PLANE: FinalPlane = FinalPlane(plane::BYTES);

/// The [`Plane`] stored under `name` (an unknown name reads as the
/// attestation plane, the earliest records' default).
#[must_use]
pub fn plane_for(name: &str) -> &'static dyn Plane {
    match name {
        plane::TYPED_ATTESTATION => &TYPED_ATTESTATION_PLANE,
        plane::TRUST => &TRUST_PLANE,
        plane::KEY => &KEY_PLANE,
        plane::OCCURRENCE => &OCCURRENCE_PLANE,
        plane::GROUP => &GROUP_PLANE,
        plane::REBIND => &REBIND_PLANE,
        plane::TYPED_FINAL => &TYPED_FINAL_PLANE,
        plane::BYTES => &BYTES_PLANE,
        _ => &ATTESTATION_PLANE,
    }
}

/// An occurrence bind's `(identity_key_id, occurrence_key_id)`, from its
/// payload.
#[must_use]
pub fn occurrence_pair(row: &AdmittedRow) -> Option<(String, String)> {
    let text = |k: &str| {
        row.payload
            .get_text(k)
            .and_then(ciris_verify_core::cde::Value::as_text)
            .map(str::to_owned)
    };
    Some((text("identity_key_id")?, text("occurrence_key_id")?))
}

// ─────────────────────────────────────────────────────────────────────────
//  Re-folding
// ─────────────────────────────────────────────────────────────────────────

/// What re-folding one row did.
enum Change {
    /// Held, now concluded: these keys are touched.
    Concluded(BTreeSet<String>),
    /// Concluded, now held: these keys are touched.
    Unconcluded(BTreeSet<String>),
    /// Held before and after.
    StillHeld,
    /// Nothing to do (concluded and still concluding, or not held here).
    Unchanged,
}

/// The voice that projects a held row: the author's own voice for an
/// authored row, else the first held voice (statement-id order) still
/// admitted under the key plane as it stands. `None` when no held voice
/// admits.
async fn held_primary<F>(dir: &F, row_id: &RowId) -> Result<Option<AdmittedRow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut first = None;
    for st in dir.edition2_voices(row_id).await? {
        if RowId::of_statement(&st) != Some(*row_id) {
            continue;
        }
        let mut keys = super::ingest::held_keys_for(dir, &st).await?;
        // P4 fix1 (adopted) — a `key:record` is its own key source, as at
        // `ingest::put_statement` (CC 2.4.1.1: "Each key's own holder signs
        // its record"). A no-op for any other statement.
        // P4 fix1 — a `key:record` is its own key source, as at
        // `ingest::put_statement_with_origin` (CC 2.4.1.1: "Each key's own
        // holder signs its record"). The key plane's reader skips a held-back
        // statement (`ingest::held_keys_for_kid`), and `refold_row` marks the
        // row `refolding` BEFORE it re-concludes it, so without this a key
        // record re-folded by its own statement's `after_statement` (it reads
        // the key it records) cannot verify against itself, is skipped here,
        // and stays held back for good: every row its key signs then waits
        // as `federation_attester_key_unknown`. A no-op for any other
        // statement (`insert_record` reads only a `key:record`'s `key`).
        if super::ingest::is_key_record(&st) {
            keys.insert_record(st.clone());
        }
        // v62.0.0 (PIN-fix2; CIRISVerify 23.4.1) — a composer is re-admitted
        // with its held target (`SelectContext.target`), as the put door
        // admits it; without it Verify waits on the target and the row could
        // never re-fold.
        let ctx = ciris_verify_core::edition2::family::SelectContext {
            target: super::typed::held_target_row(dir, &st).await?,
            ..Default::default()
        };
        let Ok(a) = super::door::admit_row(&st, &keys, Some(&row_id.0), ctx) else {
            continue;
        };
        if a.author.as_deref() == Some(a.iss.as_str()) {
            return Ok(Some(a));
        }
        if first.is_none() {
            first = Some(a);
        }
    }
    Ok(first)
}

/// Re-run the door for a held or concluded row under its own stored
/// arrival (v4).
async fn reconclude<F>(
    dir: &F,
    primary: &AdmittedRow,
    state: &FoldState,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // X2 build fix: a re-conclusion re-judges a row this node already holds
    // (metered at its first receipt), so it writes as the node's own act.
    Box::pin(super::ingest::put_admitted_row(
        dir,
        primary,
        &state.tier,
        state.replicated,
        crate::federation::replication::admission::WriteOrigin::Authored,
    ))
    .await
}

/// Re-fold one row.
async fn refold_row<F>(dir: &F, row_id: &RowId) -> Result<Change, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(state) = dir.fold_state(row_id).await? else {
        return Ok(Change::Unchanged);
    };
    // fix3 — a `key:record` is the signer's own key plane, a DOOR input: the
    // fold never re-folds it. Re-folding it once marked it `refolding`,
    // which the key-plane reader then skipped, so it could not re-verify
    // against itself (P4's root cause).
    if state.family == ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY {
        return Ok(Change::Unchanged);
    }
    // v4 — a byte executor's row has no statement to re-run: its own door
    // re-checks it (`release_bytes`).
    if state.plane == plane::BYTES {
        return Ok(if state.held.is_some() {
            Change::StillHeld
        } else {
            Change::Unchanged
        });
    }
    // v4 (GC4) — an accord invocation is judged by the halt door
    // (`put_statement`'s intercept), never by `put_admitted_row`: a held
    // invocation (a replay) is not re-run here.
    if dir
        .edition2_voices(row_id)
        .await?
        .iter()
        .any(|st| super::halt::is_invocation(st))
    {
        return Ok(if state.held.is_some() {
            Change::StillHeld
        } else {
            Change::Unchanged
        });
    }
    let Some(primary) = held_primary(dir, row_id).await? else {
        return Ok(if state.held.is_some() {
            Change::StillHeld
        } else {
            Change::Unchanged
        });
    };
    // Held: re-run the door under the row's own arrival.
    if state.held.is_some() {
        return match reconclude(dir, &primary, &state).await {
            Ok(StatementOutcome::Pending { .. }) => Ok(Change::StillHeld),
            Ok(_) => Ok(Change::Concluded(touched_by(dir, &primary).await?)),
            Err(e) => {
                let mut reads = BTreeSet::new();
                reads.insert(Dep::Row(*row_id).read_key());
                record(
                    dir,
                    *row_id,
                    &state.family,
                    &state.tier,
                    Some((reason::REFOLD_REFUSED.to_owned(), e.to_string())),
                    reads,
                )
                .await?;
                Ok(Change::StillHeld)
            }
        };
    }
    // Concluded.
    let pl = plane_for(&state.plane);
    if pl.is_final() {
        return Ok(Change::Unchanged);
    }
    let ddir = dir.as_dyn_directory();
    let (checked, att) = attempt(*row_id, None, pl.recheck(ddir, &primary)).await;
    if let Some(out) = checked {
        return match (out, att.held) {
            (Ok(()), _) => {
                record(dir, *row_id, &state.family, &state.tier, None, att.reads).await?;
                Ok(Change::Unchanged)
            }
            (Err(e), Some((r, d))) => {
                let d = if d.is_empty() { e.to_string() } else { d };
                // The marker first (fix4: the reason alone; the row's reads,
                // plane and slot stay): a crash between it and the final
                // record leaves a row `refolding`, which the boot hook
                // repairs.
                dir.put_fold_reason(row_id, Some((reason::REFOLDING.to_owned(), d.clone())))
                    .await?;
                // What the projection touched, read before it leaves.
                let touched = touched_by(dir, &primary).await?;
                if let Err(e) = pl.unconclude(ddir, &primary).await {
                    // fix4 — never strand: the prior state comes back.
                    dir.put_fold_reason(row_id, prior_held(&state)).await?;
                    return Err(e);
                }
                record(
                    dir,
                    *row_id,
                    &state.family,
                    &state.tier,
                    Some((r, d)),
                    att.reads,
                )
                .await?;
                Ok(Change::Unconcluded(touched))
            }
            (Err(e), None) => {
                // A refusal no gate marked: not a fold condition. The row
                // keeps its conclusion (CC: never refused retroactively).
                tracing::warn!(
                    row_id = %row_id.hex(),
                    error = %e,
                    "fold re-check met an unmarked refusal; the row stays concluded"
                );
                Ok(Change::Unchanged)
            }
        };
    }
    // No dry re-check: take the slot out, then re-conclude every concluded
    // row of it, this one included, each under its own arrival.
    //
    // fix4 — DECIDE FIRST. Every row of the slot must be re-admissible
    // (its primary voice verifies under the key plane as it stands) before
    // anything is taken out. A row that cannot be re-admitted now (its
    // signer's key waits) leaves the whole slot exactly as it was.
    let mut slot: BTreeSet<RowId> = dir.fold_slot_rows(&state.slot).await?.into_iter().collect();
    slot.insert(*row_id);
    let mut plan = Vec::new();
    for id in &slot {
        let (Some(st), Some(p)) = (dir.fold_state(id).await?, held_primary(dir, id).await?) else {
            tracing::debug!(
                row_id = %id.hex(),
                "fold: a slot row cannot be re-admitted now; the slot is left as it was"
            );
            return Ok(Change::Unchanged);
        };
        plan.push((*id, st, p));
    }
    dir.put_fold_reason(row_id, Some((reason::REFOLDING.to_owned(), String::new())))
        .await?;
    let touched = touched_by(dir, &primary).await?;
    if let Err(e) = pl.unconclude(ddir, &primary).await {
        dir.put_fold_reason(row_id, prior_held(&state)).await?;
        return Err(e);
    }
    for (id, st, p) in &plan {
        match reconclude(dir, p, st).await {
            Ok(_) => {}
            Err(e) if id == row_id => {
                record(
                    dir,
                    *id,
                    &st.family,
                    &st.tier,
                    Some((reason::REFOLD_REFUSED.to_owned(), e.to_string())),
                    [Dep::Row(*id).read_key()].into_iter().collect(),
                )
                .await?;
            }
            Err(e) => {
                tracing::warn!(
                    row_id = %id.hex(),
                    error = %e,
                    "fold: a slot sibling did not re-conclude"
                );
            }
        }
    }
    // fix4 — never strand: a door that answered without recording (a
    // `Voice`, say) leaves the marker; the prior state comes back.
    let now = dir.fold_state(row_id).await?;
    if now
        .as_ref()
        .and_then(|s| s.held.as_ref())
        .is_some_and(|h| h.reason == reason::REFOLDING)
    {
        dir.put_fold_reason(row_id, prior_held(&state)).await?;
    }
    let held_now = dir.fold_held(row_id).await?.is_some();
    Ok(if held_now && state.held.is_none() {
        Change::Unconcluded(touched)
    } else {
        Change::Unchanged
    })
}

/// The `(reason, detail)` a state had, to restore it.
fn prior_held(state: &FoldState) -> Option<(String, String)> {
    state
        .held
        .as_ref()
        .map(|h| (h.reason.clone(), h.detail.clone()))
}

/// The rows whose folds read any of `touched`.
async fn dependents<F>(dir: &F, touched: &BTreeSet<String>) -> Result<BTreeSet<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if touched.is_empty() {
        return Ok(BTreeSet::new());
    }
    let keys: Vec<String> = touched.iter().cloned().collect();
    Ok(dir.fold_dependents(&keys).await?.into_iter().collect())
}

/// The worklist: re-fold in row-id order, cascading each change.
async fn run<F>(dir: &F, mut queue: BTreeSet<RowId>) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut report = RefoldReport::default();
    while let Some(id) = queue.pop_first() {
        if report.steps >= MAX_REFOLD_STEPS {
            tracing::warn!(
                remaining = queue.len() + 1,
                "fold re-fold pass reached MAX_REFOLD_STEPS; the rest re-folds on the next touch"
            );
            break;
        }
        report.steps += 1;
        match Box::pin(refold_row(dir, &id)).await? {
            Change::Concluded(t) => {
                report.concluded.push(id);
                let mut next = dependents(dir, &t).await?;
                next.remove(&id);
                queue.extend(next);
            }
            Change::Unconcluded(t) => {
                report.unconcluded.push(id);
                let mut next = dependents(dir, &t).await?;
                next.remove(&id);
                queue.extend(next);
            }
            Change::StillHeld => report.still_held.push(id),
            Change::Unchanged => {}
        }
    }
    Ok(report)
}

/// **The re-fold hook.** Re-fold every row whose fold read any of
/// `touched`, then every row those changes touch, until nothing changes.
///
/// # Errors
/// Storage failures.
pub async fn refold_touched<F>(dir: &F, touched: BTreeSet<String>) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    refold_touched_excluding(dir, touched, &BTreeSet::new()).await
}

/// fix4 — [`refold_touched`], never re-folding the rows in `except` (the
/// rows whose own arrival touched these keys: a row is never its own fold
/// dependent).
///
/// # Errors
/// Storage failures.
pub async fn refold_touched_excluding<F>(
    dir: &F,
    touched: BTreeSet<String>,
    except: &BTreeSet<RowId>,
) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut queue = dependents(dir, &touched).await?;
    queue.retain(|r| !except.contains(r));
    if queue.is_empty() {
        return Ok(RefoldReport::default());
    }
    run(dir, queue).await
}

/// Re-fold exactly `rows`, and cascade.
///
/// # Errors
/// Storage failures.
pub async fn refold_rows<F>(dir: &F, rows: BTreeSet<RowId>) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    run(dir, rows).await
}

/// Re-fold every held row: the repair sweep (a crash mid-refold, a rule
/// change).
///
/// # Errors
/// Storage failures.
pub async fn refold_all<F>(dir: &F) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut rows = BTreeSet::new();
    let mut after: Option<RowId> = None;
    loop {
        let page = dir.fold_held_page(after.as_ref(), MAX_HELD_PAGE).await?;
        let Some(last) = page.last().map(|h| h.row_id) else {
            break;
        };
        rows.extend(page.iter().map(|h| h.row_id));
        if page.len() < MAX_HELD_PAGE as usize {
            break;
        }
        after = Some(last);
    }
    run(dir, rows).await
}

// ─────────────────────────────────────────────────────────────────────────
//  Storage (both dialects; the backends call these)
// ─────────────────────────────────────────────────────────────────────────

/// The `ceg_fold_state` columns, in the baseline's order (v4; it replaces
/// v1's `ceg_fold_held`).
pub const STATE_COLUMNS: [&str; 9] = [
    "row_id",
    "family",
    "tier",
    "replicated",
    "plane",
    "slot",
    "reason",
    "detail",
    "since_us",
];

/// The `ceg_fold_reads` columns.
pub const READS_COLUMNS: [&str; 2] = ["read_key", "row_id"];

#[cfg(any(feature = "sqlite", feature = "postgres"))]
const STATE_SELECT: &str =
    "row_id, family, tier, replicated, plane, slot, reason, detail, since_us";

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn row_id_of(b: &[u8], table: &str) -> Result<RowId, Error> {
    <[u8; 32]>::try_from(b)
        .map(RowId)
        .map_err(|_| Error::Backend(format!("{table}: row_id length")))
}

/// One `ceg_fold_state` row as read.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
struct StateCols {
    row_id: Vec<u8>,
    family: String,
    tier: String,
    replicated: bool,
    plane: String,
    slot: String,
    reason: Option<String>,
    detail: Option<String>,
    since_us: Option<i64>,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl StateCols {
    fn into_state(self) -> Result<FoldState, Error> {
        let row_id = row_id_of(&self.row_id, "ceg_fold_state")?;
        let held = self.reason.map(|reason| HeldReason {
            row_id,
            family: self.family.clone(),
            tier: self.tier.clone(),
            replicated: self.replicated,
            plane: self.plane.clone(),
            reason,
            detail: self.detail.unwrap_or_default(),
            since_us: self.since_us.unwrap_or_default(),
        });
        Ok(FoldState {
            row_id,
            family: self.family,
            tier: self.tier,
            replicated: self.replicated,
            plane: self.plane,
            slot: self.slot,
            held,
        })
    }
}

/// sqlite: store a fold record in one transaction.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_record_sqlite(conn: &mut rusqlite::Connection, rec: &FoldRecord) -> Result<(), Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold: {e}"));
    let tx = crate::store::sqlite_conn_model::write_tx(conn).map_err(be)?;
    let id = &rec.row_id.0[..];
    tx.execute(
        "DELETE FROM ceg_fold_reads WHERE row_id = ?1",
        rusqlite::params![id],
    )
    .map_err(be)?;
    for k in &rec.reads {
        tx.execute(
            "INSERT OR IGNORE INTO ceg_fold_reads (read_key, row_id) VALUES (?1, ?2)",
            rusqlite::params![k, id],
        )
        .map_err(be)?;
    }
    let (reason, detail) = match &rec.held {
        Some((r, d)) => (Some(r.as_str()), Some(d.as_str())),
        None => (None, None),
    };
    let now = crate::host::clock::now().timestamp_micros();
    tx.execute(
        "INSERT INTO ceg_fold_state (row_id, family, tier, replicated, plane, slot, reason, \
         detail, since_us) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
         CASE WHEN ?7 IS NULL THEN NULL ELSE ?9 END) \
         ON CONFLICT (row_id) DO UPDATE SET family = excluded.family, tier = excluded.tier, \
         replicated = excluded.replicated, plane = excluded.plane, slot = excluded.slot, \
         since_us = CASE WHEN excluded.reason IS NULL THEN NULL \
         WHEN ceg_fold_state.reason = excluded.reason THEN ceg_fold_state.since_us \
         ELSE excluded.since_us END, \
         reason = excluded.reason, detail = excluded.detail",
        rusqlite::params![
            id,
            rec.family,
            rec.tier,
            i64::from(rec.replicated),
            rec.plane,
            rec.slot,
            reason,
            detail,
            now
        ],
    )
    .map_err(be)?;
    tx.commit().map_err(be)
}

#[cfg(feature = "sqlite")]
fn state_of_sqlite(r: &rusqlite::Row<'_>) -> rusqlite::Result<StateCols> {
    Ok(StateCols {
        row_id: r.get(0)?,
        family: r.get(1)?,
        tier: r.get(2)?,
        replicated: r.get::<_, i64>(3)? != 0,
        plane: r.get(4)?,
        slot: r.get(5)?,
        reason: r.get(6)?,
        detail: r.get(7)?,
        since_us: r.get(8)?,
    })
}

/// sqlite: the fold state of one row.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn state_sqlite(
    conn: &rusqlite::Connection,
    row_id: &RowId,
) -> Result<Option<FoldState>, Error> {
    use rusqlite::OptionalExtension as _;
    let got = conn
        .query_row(
            &format!("SELECT {STATE_SELECT} FROM ceg_fold_state WHERE row_id = ?1"),
            rusqlite::params![&row_id.0[..]],
            state_of_sqlite,
        )
        .optional()
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    got.map(StateCols::into_state).transpose()
}

/// sqlite: the held reason of one row (`None` when concluded or unknown).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn held_sqlite(
    conn: &rusqlite::Connection,
    row_id: &RowId,
) -> Result<Option<HeldReason>, Error> {
    Ok(state_sqlite(conn, row_id)?.and_then(|s| s.held))
}

/// sqlite: a page of held reasons in row-id order after `after`.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn held_page_sqlite(
    conn: &rusqlite::Connection,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldReason>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold_state: {e}"));
    let after: Vec<u8> = after.map_or_else(Vec::new, |a| a.0.to_vec());
    let mut st = conn
        .prepare(&format!(
            "SELECT {STATE_SELECT} FROM ceg_fold_state WHERE reason IS NOT NULL AND row_id > ?1 \
             ORDER BY row_id LIMIT ?2"
        ))
        .map_err(be)?;
    let rows = st
        .query_map(
            rusqlite::params![after, i64::from(limit.min(MAX_HELD_PAGE))],
            state_of_sqlite,
        )
        .map_err(be)?;
    let mut out = Vec::new();
    for r in rows {
        if let Some(h) = r.map_err(be)?.into_state()?.held {
            out.push(h);
        }
    }
    Ok(out)
}

/// sqlite: set only the reason of a row's fold state (fix4).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_reason_sqlite(
    conn: &mut rusqlite::Connection,
    row_id: &RowId,
    held: Option<&(String, String)>,
) -> Result<bool, Error> {
    let (reason, detail) = match held {
        Some((r, d)) => (Some(r.as_str()), Some(d.as_str())),
        None => (None, None),
    };
    let now = crate::host::clock::now().timestamp_micros();
    conn.execute(
        "UPDATE ceg_fold_state SET \
         since_us = CASE WHEN ?2 IS NULL THEN NULL WHEN reason = ?2 THEN since_us ELSE ?4 END, \
         reason = ?2, detail = ?3 WHERE row_id = ?1",
        rusqlite::params![&row_id.0[..], reason, detail, now],
    )
    .map(|n| n > 0)
    .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))
}

/// sqlite: the CONCLUDED rows of one projection slot, in row-id order.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn slot_rows_sqlite(conn: &rusqlite::Connection, slot: &str) -> Result<Vec<RowId>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold_state: {e}"));
    let mut st = conn
        .prepare(
            "SELECT row_id FROM ceg_fold_state WHERE slot = ?1 AND reason IS NULL ORDER BY row_id",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![slot], |r| r.get::<_, Vec<u8>>(0))
        .map_err(be)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(row_id_of(&r.map_err(be)?, "ceg_fold_state")?);
    }
    Ok(out)
}

/// sqlite: does any held row sit in `slot`?
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn slot_held_sqlite(conn: &rusqlite::Connection, slot: &str) -> Result<bool, Error> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM ceg_fold_state WHERE slot = ?1 AND reason IS NOT NULL)",
        rusqlite::params![slot],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n != 0)
    .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))
}

/// sqlite: is any row left `refolding` (an interrupted re-fold)?
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn any_refolding_sqlite(conn: &rusqlite::Connection) -> Result<bool, Error> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM ceg_fold_state WHERE reason = ?1)",
        rusqlite::params![reason::REFOLDING],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n != 0)
    .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))
}

/// sqlite: the rows whose folds read any of `read_keys`, distinct, in
/// row-id order.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn dependents_sqlite(
    conn: &rusqlite::Connection,
    read_keys: &[String],
) -> Result<Vec<RowId>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold_reads: {e}"));
    let mut st = conn
        .prepare("SELECT row_id FROM ceg_fold_reads WHERE read_key = ?1")
        .map_err(be)?;
    let mut out = BTreeSet::new();
    for k in read_keys {
        let rows = st
            .query_map(rusqlite::params![k], |r| r.get::<_, Vec<u8>>(0))
            .map_err(be)?;
        for r in rows {
            out.insert(row_id_of(&r.map_err(be)?, "ceg_fold_reads")?);
        }
    }
    Ok(out.into_iter().collect())
}

/// sqlite: take one occurrence pair's current-state row out
/// (`federation_identity_occurrences`); its history rows stay.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn clear_occurrence_sqlite(
    conn: &mut rusqlite::Connection,
    identity: &str,
    occurrence: &str,
) -> Result<bool, Error> {
    conn.execute(
        "DELETE FROM federation_identity_occurrences \
         WHERE identity_key_id = ?1 AND occurrence_key_id = ?2",
        rusqlite::params![identity, occurrence],
    )
    .map(|n| n > 0)
    .map_err(|e| Error::Backend(format!("federation_identity_occurrences: {e}")))
}

/// postgres: store a fold record in one transaction.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_record_postgres(
    client: &mut deadpool_postgres::Object,
    rec: &FoldRecord,
) -> Result<(), Error> {
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_fold: {e}"));
    let tx = client.transaction().await.map_err(be)?;
    let id: &[u8] = &rec.row_id.0[..];
    tx.execute(
        "DELETE FROM cirislens.ceg_fold_reads WHERE row_id = $1",
        &[&id],
    )
    .await
    .map_err(be)?;
    for k in &rec.reads {
        tx.execute(
            "INSERT INTO cirislens.ceg_fold_reads (read_key, row_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
            &[k, &id],
        )
        .await
        .map_err(be)?;
    }
    let (reason, detail): (Option<&str>, Option<&str>) = match &rec.held {
        Some((r, d)) => (Some(r.as_str()), Some(d.as_str())),
        None => (None, None),
    };
    let since: Option<i64> = reason.map(|_| crate::host::clock::now().timestamp_micros());
    tx.execute(
        "INSERT INTO cirislens.ceg_fold_state AS s (row_id, family, tier, replicated, plane, \
         slot, reason, detail, since_us) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (row_id) DO UPDATE SET family = EXCLUDED.family, tier = EXCLUDED.tier, \
         replicated = EXCLUDED.replicated, plane = EXCLUDED.plane, slot = EXCLUDED.slot, \
         since_us = CASE WHEN EXCLUDED.reason IS NULL THEN NULL \
         WHEN s.reason = EXCLUDED.reason THEN s.since_us ELSE EXCLUDED.since_us END, \
         reason = EXCLUDED.reason, detail = EXCLUDED.detail",
        &[
            &id,
            &rec.family,
            &rec.tier,
            &rec.replicated,
            &rec.plane,
            &rec.slot,
            &reason,
            &detail,
            &since,
        ],
    )
    .await
    .map_err(be)?;
    tx.commit().await.map_err(be)
}

#[cfg(feature = "postgres")]
fn state_of_postgres(r: &tokio_postgres::Row) -> Result<FoldState, Error> {
    StateCols {
        row_id: r.get(0),
        family: r.get(1),
        tier: r.get(2),
        replicated: r.get(3),
        plane: r.get(4),
        slot: r.get(5),
        reason: r.get(6),
        detail: r.get(7),
        since_us: r.get(8),
    }
    .into_state()
}

/// postgres: the fold state of one row.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn state_postgres<C>(client: &C, row_id: &RowId) -> Result<Option<FoldState>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let sql = format!("SELECT {STATE_SELECT} FROM cirislens.ceg_fold_state WHERE row_id = $1");
    let row = client
        .query_opt(sql.as_str(), &[&&row_id.0[..]])
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    row.as_ref().map(state_of_postgres).transpose()
}

/// postgres: the held reason of one row.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn held_postgres<C>(client: &C, row_id: &RowId) -> Result<Option<HeldReason>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    Ok(state_postgres(client, row_id).await?.and_then(|s| s.held))
}

/// postgres: a page of held reasons in row-id order after `after`.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn held_page_postgres<C>(
    client: &C,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldReason>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let after: Vec<u8> = after.map_or_else(Vec::new, |a| a.0.to_vec());
    let limit = i64::from(limit.min(MAX_HELD_PAGE));
    let sql = format!(
        "SELECT {STATE_SELECT} FROM cirislens.ceg_fold_state WHERE reason IS NOT NULL \
         AND row_id > $1 ORDER BY row_id LIMIT $2"
    );
    let rows = client
        .query(sql.as_str(), &[&after, &limit])
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    let mut out = Vec::new();
    for r in &rows {
        if let Some(h) = state_of_postgres(r)?.held {
            out.push(h);
        }
    }
    Ok(out)
}

/// postgres: set only the reason of a row's fold state (fix4).
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_reason_postgres<C>(
    client: &C,
    row_id: &RowId,
    held: Option<&(String, String)>,
) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let (reason, detail): (Option<&str>, Option<&str>) = match held {
        Some((r, d)) => (Some(r.as_str()), Some(d.as_str())),
        None => (None, None),
    };
    let now: i64 = crate::host::clock::now().timestamp_micros();
    client
        .execute(
            "UPDATE cirislens.ceg_fold_state SET \
             since_us = CASE WHEN $2::text IS NULL THEN NULL WHEN reason = $2::text \
             THEN since_us ELSE $4 END, reason = $2, detail = $3 WHERE row_id = $1",
            &[&&row_id.0[..], &reason, &detail, &now],
        )
        .await
        .map(|n| n > 0)
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))
}

/// postgres: the CONCLUDED rows of one projection slot, in row-id order.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn slot_rows_postgres<C>(client: &C, slot: &str) -> Result<Vec<RowId>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT row_id FROM cirislens.ceg_fold_state WHERE slot = $1 AND reason IS NULL \
             ORDER BY row_id",
            &[&slot],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    rows.iter()
        .map(|r| {
            let b: Vec<u8> = r.get(0);
            row_id_of(&b, "ceg_fold_state")
        })
        .collect()
}

/// postgres: does any held row sit in `slot`?
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn slot_held_postgres<C>(client: &C, slot: &str) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM cirislens.ceg_fold_state WHERE slot = $1 \
             AND reason IS NOT NULL)",
            &[&slot],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    Ok(row.get::<_, bool>(0))
}

/// postgres: is any row left `refolding`?
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn any_refolding_postgres<C>(client: &C) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM cirislens.ceg_fold_state WHERE reason = $1)",
            &[&reason::REFOLDING],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    Ok(row.get::<_, bool>(0))
}

/// postgres: the rows whose folds read any of `read_keys`, distinct, in
/// row-id order.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn dependents_postgres<C>(client: &C, read_keys: &[String]) -> Result<Vec<RowId>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let keys: Vec<String> = read_keys.to_vec();
    let rows = client
        .query(
            "SELECT DISTINCT row_id FROM cirislens.ceg_fold_reads WHERE read_key = ANY($1) \
             ORDER BY row_id",
            &[&keys],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_reads: {e}")))?;
    rows.iter()
        .map(|r| {
            let b: Vec<u8> = r.get(0);
            row_id_of(&b, "ceg_fold_reads")
        })
        .collect()
}

/// postgres: take one occurrence pair's current-state row out; its history
/// rows stay.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn clear_occurrence_postgres<C>(
    client: &C,
    identity: &str,
    occurrence: &str,
) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    client
        .execute(
            "DELETE FROM cirislens.federation_identity_occurrences \
             WHERE identity_key_id = $1 AND occurrence_key_id = $2",
            &[&identity, &occurrence],
        )
        .await
        .map(|n| n > 0)
        .map_err(|e| Error::Backend(format!("federation_identity_occurrences: {e}")))
}
