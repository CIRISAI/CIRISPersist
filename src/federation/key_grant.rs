//! CIRISPersist#848 (`FSD/BLOB_REPLICATION.md` Part II) — **key
//! transport: the key follows the bytes.** v55.0.0 (CIRISPersist#989, CC
//! 3.3.2 rc7, CIRISConstitution#143) — **one `scores` row per recipient.**
//!
//! v44.2.0 got a sealed blob's BYTES to a member's node (`adopt_sealed_blob`,
//! #846) and not the KEY: the per-epoch wraps and the per-blob grants were
//! written only by the author node's cascade into local tables, and nothing
//! carried them. On every non-author member `read_blob_as` was `NotGranted`,
//! correctly, because the wrap addressed to that occurrence existed only on
//! the author's node.
//!
//! # The row (CC 3.3.2 rc7)
//!
//! A wrap of one data-encryption key to one recipient is one `scores` row on
//! `key_grant:{axis}:v1` ([`KeyGrantRow`]). v44.3 through v54 carried the
//! wraps of one identity as a SET in one carrier row (`attestation_type =
//! key_grant:{axis}:v1`); CC rc7 retires the carrier class (CC 2.4), and the
//! set is gone: a node refuses a new set ([`KeyGrantRefusalReason::SetRetired`])
//! and serves none it holds. Its wire shape (persist's, cited by CC):
//!
//! | column / member | value |
//! |---|---|
//! | `attestation_type` | `scores` |
//! | `dimension` | `key_grant:content:v1` / `key_grant:epoch:v1` / `key_grant:stream:v1` |
//! | `attesting_key_id` | the sealer: the minter (epoch), a key that speaks for the owner (content, stream) |
//! | `attested_key_id` | the RECIPIENT occurrence, whose content-KEM keys the DEK is wrapped to |
//! | `score` | `1.0` (positive-only) |
//! | `cohort_scope` | the content's own scope; `community` on the epoch axis |
//! | `subject_key_ids` | empty: the recipient gains no retraction authority |
//! | `expires_at` | absent: never withdrawn, forward secrecy is by rotation |
//! | `axis` | `content` / `epoch` / `stream`, agreeing with the dimension |
//! | `at_rest_sha256` | content: the sealed blob's at-rest digest (never in `evidence_refs`) |
//! | `owner_key_id` | content, stream: the self identity, family or community the content is sealed for |
//! | `community_key_id`, `minter_key_id` | epoch |
//! | `epoch` | epoch, stream |
//! | `stream_id` | stream |
//! | `wrap_algorithm` | `x25519_mlkem768_aes256_gcm_hkdf_sha256` (v2 only) |
//! | `wrapped_dek` | the hybrid wrap |
//!
//! plus the CC 2 cohort target: `family_key_id` on a family row,
//! `community_id` on a community row and on every epoch row.
//!
//! # Identity, union, never withdrawn
//!
//! A wrap's identity is `(dimension, attesting_key_id, attested_key_id, axis
//! identity)` ([`KeyGrantRow::identity`]). CC 2's latest-wins / dedup triple
//! `(attester, dimension, attested)` does NOT apply to the family: one
//! recipient holds wraps for many blobs and epochs from one sealer. The
//! projection is a union into this node's grant tables (`ON CONFLICT DO
//! NOTHING`); a row once admitted is never removed by a later one, and a
//! `withdraws` / `recants` naming one is refused.
//!
//! # An epoch belongs to its minter (§11)
//!
//! Key state, self-retention and grants are keyed `(community, minter,
//! epoch)`; a blob's key identity is `(community, author, epoch)`; the signer
//! rule falls out (M signs M's counter); and every minter rotates its own
//! counter after admitting a removal (§15,
//! [`community_dek::orchestrate::ensure_epoch_dek`](crate::federation::community_dek::orchestrate::ensure_epoch_dek)).
//!
//! # Admission — one rule, every door ([`check_key_grant_row_admission`])
//!
//! Every federation-tier row passes `check_reserved_prefix_admission`, which
//! asks this module's rule: the shape ([`KeyGrantRow::from_attestation`]);
//! `wrap_algorithm` v2; signed by the party it speaks for; the SEALER rule
//! (epoch: the minter or its `grant` delegate, an active member occurrence at
//! `asserted_at`; content / stream at `self`: a key that speaks for the
//! owner; at a group scope the write gate's membership check; and, where this
//! node holds the blob or stream, a key that speaks for its author / owner);
//! and the RECIPIENT rule (the recipient is an occurrence the one audience
//! rule lets hold the cohort's key, #963). The delegation chain is judged at
//! [`crate::federation::admission::grant_chain_instant`] — the seam
//! CIRISPersist#1049 moves to the row's signed instant.
//!
//! # Projection ([`project_key_grant_row`])
//!
//! A row admitted through either typed attestation door (wire, sync) is
//! projected into this node's grant tables by the backend hook
//! [`FederationDirectory::project_key_grant_row`]. A content-axis row whose
//! bytes have not arrived is held in the pending index and projected by the
//! adopt ([`project_pending_content_grants`]).
//!
//! # Delivery (CC 6.1.5.3)
//!
//! A row reaches its recipient's node because it refers to it, and only
//! when the cohort's audience contains that node
//! ([`crate::federation::replication_audience::may_receive`]); being named in
//! a wrap delivers nothing else.
//!
//! # Emission ([`plan_key_grant_emission`])
//!
//! The local grant tables stay the record (operator ruling Q3). After a
//! cascade minted or granted anew, the sealer emits one row per wrap it holds
//! for the axis that it has not emitted as a row yet, to every recipient the
//! audience rule still admits, while the sealer itself may still sign as
//! sealer (CC conditions on #989). The full enumeration, never the delta, so
//! a node that dies mid-emission re-emits on its next write, and re-emission
//! is idempotent: a wrap already held as a row is skipped.
//!
//! # The legacy re-emit (operator ruling Q3)
//!
//! V192 marks every emission axis dirty. On its first boot after it, a node's
//! pending sweep re-emits the wraps it holds as sealer or minter as
//! per-recipient rows, each at a fresh signed instant (so each recipient is
//! re-checked against the audience at that instant), and drops the pending
//! index entries the retired sets left. The legacy set rows stay where they
//! are, unserved.

use crate::federation::attestation_apply::ReplicatedAttestationOutcome;
use crate::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
use crate::federation::self_collective::speaks_for;
use crate::federation::types::cohort_scope;
use crate::federation::{
    Attestation, BlobError, BlobStorage, EmitAttestationInput, Error, FederationDirectory,
    GrantWrap, SignedAttestation,
};
use serde::{Deserialize, Serialize};

/// The V145 backfill sentinel: the minter SQL cannot know. Resolved to the
/// node's own derived key at boot; a survivor aborts the boot (§16, I66).
pub const MINTER_SENTINEL: &str = "__this_node__";

/// The dimension stem every key-grant row carries (CC 3.1.3 `key_grant:{axis}`).
pub const KEY_GRANT_DIMENSION_PREFIX: &str = "key_grant:";
/// The epoch-axis dimension: `(community, minter, epoch)`.
pub const KEY_GRANT_EPOCH_DIMENSION: &str = "key_grant:epoch:v1";
/// The content-axis dimension: `(at_rest_sha256, cohort_scope, owner)`.
pub const KEY_GRANT_CONTENT_DIMENSION: &str = "key_grant:content:v1";
/// v53.0.0 (CIRISPersist#969, #975 ruling) — the stream-axis dimension:
/// `(stream_id, epoch, cohort_scope, owner)`, signed by the stream's owner.
/// CC 5.1's epoch-addressed `(stream_id, epoch[, recipient])` axis, for the
/// streams CC 5.3.3.1 seals under one DEK per epoch.
pub const KEY_GRANT_STREAM_DIMENSION: &str = "key_grant:stream:v1";

/// v55.0.0 (#989) — the `score` (and `confidence`) every key-grant row
/// carries: the family is positive-only, and a wrap is a fact, not a degree.
pub const KEY_GRANT_SCORE: f64 = 1.0;

/// CC 5.1's addressing axes for a `key_grant` (§12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "axis", rename_all = "snake_case")]
pub enum KeyGrantAxis {
    /// Epoch-addressed: community / affiliations. Signed by the minter.
    Epoch {
        /// The community whose epoch this is.
        community_key_id: String,
        /// The occurrence whose cascade minted the epoch — the signer.
        minter_key_id: String,
        /// The minter's own counter value.
        epoch: u64,
    },
    /// Content-addressed: self / family. Signed by the blob's sealer.
    Content {
        /// Hex of the at-rest content address (SHA-256 of the ciphertext).
        at_rest_sha256: String,
        /// `self` or `family` — the cohort the write named.
        cohort_scope: String,
        /// The owner (self) or family key the blob was sealed for.
        owner_key_id: String,
    },
    /// v53.0.0 (CIRISPersist#969) — stream-epoch-addressed: one chunk
    /// stream's `(stream_id, epoch)` DEK. Signed by the stream's owner (the
    /// single sender, CC 5.3.3.1); one row per recipient per epoch, where the
    /// content axis carried one per CHUNK. v55.0.0 (#977) — community streams
    /// ride this axis too.
    Stream {
        /// The stream.
        stream_id: String,
        /// The stream epoch the DEK seals.
        epoch: u64,
        /// `self`, `family`, `community` or `affiliations`.
        cohort_scope: String,
        /// The owner (self), family or community key the stream is sealed for.
        owner_key_id: String,
    },
}

impl KeyGrantAxis {
    /// The `key_grant:{axis}:v1` dimension a row on this axis carries.
    #[must_use]
    pub fn dimension(&self) -> &'static str {
        match self {
            KeyGrantAxis::Epoch { .. } => KEY_GRANT_EPOCH_DIMENSION,
            KeyGrantAxis::Content { .. } => KEY_GRANT_CONTENT_DIMENSION,
            KeyGrantAxis::Stream { .. } => KEY_GRANT_STREAM_DIMENSION,
        }
    }

    /// The `cohort_scope` a row is emitted at: the community scope on the
    /// epoch axis, the content's own scope on the content and stream axes.
    #[must_use]
    pub fn emission_cohort_scope(&self) -> &str {
        match self {
            KeyGrantAxis::Epoch { .. } => cohort_scope::COMMUNITY,
            KeyGrantAxis::Content { cohort_scope, .. }
            | KeyGrantAxis::Stream { cohort_scope, .. } => cohort_scope.as_str(),
        }
    }

    /// The group the content is placed in: the community (epoch), else the
    /// owner, family or community key (content, stream).
    #[must_use]
    pub fn group_key_id(&self) -> &str {
        match self {
            KeyGrantAxis::Epoch {
                community_key_id, ..
            } => community_key_id,
            KeyGrantAxis::Content { owner_key_id, .. }
            | KeyGrantAxis::Stream { owner_key_id, .. } => owner_key_id,
        }
    }

    /// The stable axis token (`epoch` / `content` / `stream`) the envelope's
    /// `axis` member carries.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            KeyGrantAxis::Epoch { .. } => "epoch",
            KeyGrantAxis::Content { .. } => "content",
            KeyGrantAxis::Stream { .. } => "stream",
        }
    }
}

/// The wraps one node holds for one axis — what the emitter reads out of its
/// grant tables ([`build_set_for_axis`]) before emitting one row per wrap.
/// A builder, never a wire object (v55.0.0, #989: the set row is retired).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyGrantSet {
    /// Which identity the wraps belong to.
    pub axis: KeyGrantAxis,
    /// Every recipient's wrap this node holds.
    pub wraps: Vec<GrantWrap>,
}

impl KeyGrantSet {
    /// One [`KeyGrantRow`] per wrap.
    #[must_use]
    pub fn rows(&self) -> Vec<KeyGrantRow> {
        self.wraps
            .iter()
            .map(|w| KeyGrantRow {
                axis: self.axis.clone(),
                wrap: w.clone(),
            })
            .collect()
    }
}

/// v55.0.0 (CIRISPersist#989, CC 3.3.2 rc7) — **one wrap of one DEK to one
/// recipient**: the `scores` row on `key_grant:{axis}:v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyGrantRow {
    /// The key's identity on its axis.
    pub axis: KeyGrantAxis,
    /// The wrap: `recipient_key_id` is the row's `attested_key_id`.
    pub wrap: GrantWrap,
}

/// The wire form of one key-grant row: the signed attestation, routed to
/// [`admit_replicated_key_grant`]. The same JSON shape a `SignedAttestation`
/// has (`{"attestation": {…}}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedKeyGrantRow {
    /// The `scores` row on `key_grant:{axis}:v1`.
    pub attestation: Attestation,
}

/// Why a key-grant row was refused at admission. Stable tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyGrantRefusalReason {
    /// The row does not parse as a key-grant row: a member missing, present
    /// on an axis that does not use it, or disagreeing with its column; the
    /// `axis` disagreeing with the dimension; a score other than `1.0`; a
    /// subject, an expiry, or the digest cited in `evidence_refs`.
    Malformed,
    /// The wrap carries a `wrap_algorithm` other than v2.
    WrapAlgorithmNotV2,
    /// The row's attester and scrub key differ: a key-grant row is signed by
    /// the party it speaks for, never scrubbed on their behalf.
    SignerNotSelf,
    /// Epoch axis: the signer is neither the row's `minter_key_id` nor a
    /// holder of a live `grant`-scoped delegation from it.
    SignerNotMinter,
    /// Epoch axis: the signer is not an active member occurrence of the
    /// community at `asserted_at` per this node's roster fold.
    SignerNotActiveMember,
    /// Content axis: this node holds the blob and the signer does not speak
    /// for its author.
    SignerNotAuthor,
    /// The attestation plane refused the row (a conflicting row under the
    /// same id, or a lost store race); nothing was projected.
    AttestationRefused,
    /// v53.0.0 (#969) — stream axis: this node holds the stream under an
    /// owner the signer does not speak for.
    SignerNotStreamOwner,
    /// v55.0.0 (#989) — the recipient is not an occurrence the one audience
    /// rule (#963) lets hold the cohort's key on this node. Retryable: the
    /// occurrence, the roster or the allow list may not have landed yet.
    RecipientNotInAudience,
    /// v55.0.0 (#989, CC 2.4 rc7) — a key-grant SET (`attestation_type =
    /// key_grant:{axis}:v1`, the retired rc6 carrier). Terminal: re-emit the
    /// wraps as per-recipient rows.
    SetRetired,
}

impl KeyGrantRefusalReason {
    /// The stable token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            KeyGrantRefusalReason::Malformed => "malformed",
            KeyGrantRefusalReason::WrapAlgorithmNotV2 => "wrap_algorithm_not_v2",
            KeyGrantRefusalReason::SignerNotSelf => "signer_not_self",
            KeyGrantRefusalReason::SignerNotMinter => "signer_not_minter",
            KeyGrantRefusalReason::SignerNotActiveMember => "signer_not_active_member",
            KeyGrantRefusalReason::SignerNotAuthor => "signer_not_author",
            KeyGrantRefusalReason::AttestationRefused => "attestation_refused",
            KeyGrantRefusalReason::SignerNotStreamOwner => "signer_not_stream_owner",
            KeyGrantRefusalReason::RecipientNotInAudience => "recipient_not_in_audience",
            KeyGrantRefusalReason::SetRetired => "set_retired",
        }
    }

    /// Every reason, for the token census.
    pub const ALL: [KeyGrantRefusalReason; 10] = [
        KeyGrantRefusalReason::Malformed,
        KeyGrantRefusalReason::WrapAlgorithmNotV2,
        KeyGrantRefusalReason::SignerNotSelf,
        KeyGrantRefusalReason::SignerNotMinter,
        KeyGrantRefusalReason::SignerNotActiveMember,
        KeyGrantRefusalReason::SignerNotAuthor,
        KeyGrantRefusalReason::AttestationRefused,
        KeyGrantRefusalReason::SignerNotStreamOwner,
        KeyGrantRefusalReason::RecipientNotInAudience,
        KeyGrantRefusalReason::SetRetired,
    ];
}

/// What [`admit_replicated_key_grant`] did with one row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyGrantAdmission {
    /// The key's identity.
    pub axis: KeyGrantAxis,
    /// The recipient the wrap is for (the row's `attested_key_id`).
    pub recipient_key_id: String,
    /// The attestation plane's outcome for the row.
    pub attestation: ReplicatedAttestationOutcome,
    /// The wrap is in this node's grant tables after the call (a union: a
    /// re-applied row reports `true` and wrote nothing new).
    pub projected: bool,
    /// Content axis only: the bytes have not arrived, so the author is not
    /// yet known and the wrap is NOT projected — the row is stored and
    /// [`project_pending_content_grants`] projects it (if its signer speaks
    /// for the author) when the adopt names the author.
    pub pending: bool,
}

fn refuse(reason: KeyGrantRefusalReason, detail: impl Into<String>) -> Error {
    Error::KeyGrantRefused {
        reason: reason.as_str(),
        detail: detail.into(),
    }
}

fn malformed(detail: impl Into<String>) -> Error {
    refuse(KeyGrantRefusalReason::Malformed, detail)
}

/// Is `row` a key-grant row (`scores` on a `key_grant:` dimension)?
#[must_use]
pub fn is_key_grant_row(row: &Attestation) -> bool {
    row.attestation_type == crate::federation::types::attestation_type::SCORES
        && crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            .is_some_and(|d| d.starts_with(KEY_GRANT_DIMENSION_PREFIX))
}

/// The `key_grant:{axis}:v1` dimension `row` carries when it is a key-grant
/// row, else `None`.
#[must_use]
pub fn key_grant_dimension_of(row: &Attestation) -> Option<&'static str> {
    if !is_key_grant_row(row) {
        return None;
    }
    let d = crate::federation::admission::envelope_dimension(&row.attestation_envelope)?;
    [
        KEY_GRANT_CONTENT_DIMENSION,
        KEY_GRANT_EPOCH_DIMENSION,
        KEY_GRANT_STREAM_DIMENSION,
    ]
    .into_iter()
    .find(|k| *k == d)
}

/// v55.0.0 (#989) — is `attestation_type` one of the three retired
/// key-grant SET carriers? A whole-string match against
/// [`RETIRED_CARRIER_STEMS`](crate::federation::namespace::registry::RETIRED_CARRIER_STEMS)'
/// key-grant entries (Codex r2 on #1065): another type that only shares the
/// prefix (`key_grant:content:v10`) is not a retired SET.
#[must_use]
pub fn is_retired_key_grant_set_type(attestation_type: &str) -> bool {
    attestation_type.starts_with(KEY_GRANT_DIMENSION_PREFIX)
        && crate::federation::row_type::retired_carrier(attestation_type).is_some()
}

/// v54.0.0 (CIRISPersist#1033, CC 2.4.1.2.1 / CC 4.4.3.4.3) — **may `signer`
/// issue a `key_grant` over an asset `owner` holds?**
///
/// CC 2.4.1.2.1: an onward grant is *"a new grant issued by the asset's owner
/// or steward, or by a holder of a `grant`-scoped delegation from them"*, and a
/// substrate MUST refuse one whose issuer is neither. The first arm is
/// [`speaks_for`] (the owner, or one of the owner's active occurrences —
/// #884); the second is a live `grant`-scoped chain to `signer` rooted at
/// `owner` or at one of its principals, via
/// [`holds_grant_delegation`](crate::federation::admission::holds_grant_delegation),
/// judged at `chain_instant` ([`crate::federation::admission::grant_chain_instant`]).
///
/// The ONE predicate every signer check on the content and stream axes asks —
/// at admission, at the pending projection, and on the stream read path's
/// sealer filter — so a row admitted under the delegate arm is never then
/// refused by a sibling that asks only the first.
pub async fn may_issue_grant_for<D>(
    dir: &D,
    signer: &str,
    owner: &str,
    chain_instant: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if speaks_for(dir, signer, owner).await? {
        return Ok(true);
    }
    // The chain may be rooted at the owner key or at one of its principals —
    // the same reading `speaks_for` gives the first arm: what a node seals is
    // its human's (#884), so the human's `grant` delegate speaks for it too.
    let mut roots = crate::federation::self_collective::principals_of(dir, owner).await?;
    if !roots.iter().any(|r| r == owner) {
        roots.insert(0, owner.to_owned());
    }
    for root in &roots {
        if crate::federation::admission::holds_grant_delegation(
            dir.as_dyn_directory(),
            root,
            signer,
            chain_instant,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn member_str<'a>(env: &'a serde_json::Value, name: &str) -> Result<&'a str, Error> {
    env.get(name)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| malformed(format!("key_grant row lacks a non-empty string `{name}`")))
}

fn member_u64(env: &serde_json::Value, name: &str) -> Result<u64, Error> {
    env.get(name)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| malformed(format!("key_grant row lacks an unsigned `{name}`")))
}

/// The axis members, each present only on the axis that uses it (persist's
/// wire shape, CIRISPersist#989 → CC 3.3.2).
const AXIS_MEMBERS: [(&str, [bool; 3]); 6] = [
    // (member, [content, epoch, stream])
    ("at_rest_sha256", [true, false, false]),
    ("owner_key_id", [true, false, true]),
    ("community_key_id", [false, true, false]),
    ("minter_key_id", [false, true, false]),
    ("epoch", [false, true, true]),
    ("stream_id", [false, false, true]),
];

impl KeyGrantRow {
    /// The recipient (the row's `attested_key_id`).
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.wrap.recipient_key_id
    }

    /// The wrap's identity beside the signer: `(dimension, recipient, axis
    /// identity)` — the union key the projection and the emitter's
    /// already-held check read. The signer completes it.
    #[must_use]
    pub fn identity(&self) -> (&'static str, &str, &KeyGrantAxis) {
        (self.axis.dimension(), self.recipient(), &self.axis)
    }

    /// The signed envelope's members (the CEG mirror and the signed instants
    /// are added by `stamp_and_canonicalize`).
    #[must_use]
    pub fn envelope(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("dimension".into(), self.axis.dimension().into());
        m.insert("score".into(), KEY_GRANT_SCORE.into());
        m.insert("confidence".into(), KEY_GRANT_SCORE.into());
        m.insert("axis".into(), self.axis.token().into());
        match &self.axis {
            KeyGrantAxis::Epoch {
                community_key_id,
                minter_key_id,
                epoch,
            } => {
                m.insert("community_key_id".into(), community_key_id.as_str().into());
                // CC 2 — a community row names its community as the target.
                m.insert("community_id".into(), community_key_id.as_str().into());
                m.insert("minter_key_id".into(), minter_key_id.as_str().into());
                m.insert("epoch".into(), (*epoch).into());
            }
            KeyGrantAxis::Content {
                at_rest_sha256,
                cohort_scope,
                owner_key_id,
            } => {
                m.insert("at_rest_sha256".into(), at_rest_sha256.as_str().into());
                m.insert("owner_key_id".into(), owner_key_id.as_str().into());
                insert_target(&mut m, cohort_scope, owner_key_id);
            }
            KeyGrantAxis::Stream {
                stream_id,
                epoch,
                cohort_scope,
                owner_key_id,
            } => {
                m.insert("stream_id".into(), stream_id.as_str().into());
                m.insert("epoch".into(), (*epoch).into());
                m.insert("owner_key_id".into(), owner_key_id.as_str().into());
                insert_target(&mut m, cohort_scope, owner_key_id);
            }
        }
        m.insert(
            "wrap_algorithm".into(),
            self.wrap.wrap_algorithm.as_str().into(),
        );
        m.insert("wrapped_dek".into(), self.wrap.wrapped_dek.as_str().into());
        serde_json::Value::Object(m)
    }

    /// The emit input: `scores`, the envelope, the recipient as
    /// `attested_key_id`, the content's scope.
    ///
    /// # Errors
    ///
    /// Never in practice: the envelope is built here and always parses.
    pub fn emit_input(&self) -> Result<EmitAttestationInput, Error> {
        let core: crate::federation::envelope::EnvelopeCore =
            serde_json::from_value(self.envelope())
                .map_err(|e| Error::Backend(format!("key_grant row envelope: {e}")))?;
        let mut input = EmitAttestationInput::with_envelope(
            crate::federation::types::attestation_type::SCORES,
            core,
            self.axis.emission_cohort_scope(),
        );
        input.attested_key_id = Some(self.wrap.recipient_key_id.clone());
        Ok(input)
    }

    /// Read a key-grant row back out of a stored / replicated attestation.
    ///
    /// # Errors
    ///
    /// [`Error::KeyGrantRefused`] with `malformed` for any departure from the
    /// shape in the module doc (`set_retired` for a retired set row).
    pub fn from_attestation(row: &Attestation) -> Result<Self, Error> {
        if is_retired_key_grant_set_type(&row.attestation_type) {
            return Err(refuse(
                KeyGrantRefusalReason::SetRetired,
                format!(
                    "attestation_type {:?} is the retired rc6 key-grant SET (CC 2.4 rc7, \
                     CIRISConstitution#143): a wrap is one `scores` row per recipient on \
                     `key_grant:{{axis}}:v1`",
                    row.attestation_type
                ),
            ));
        }
        if row.attestation_type != crate::federation::types::attestation_type::SCORES {
            return Err(malformed(format!(
                "a key_grant row is a `scores` row, not {:?}",
                row.attestation_type
            )));
        }
        let env = &row.attestation_envelope;
        let dimension = member_str(env, "dimension")?;
        let axis_token = member_str(env, "axis")?;
        let index = match (dimension, axis_token) {
            (KEY_GRANT_CONTENT_DIMENSION, "content") => 0,
            (KEY_GRANT_EPOCH_DIMENSION, "epoch") => 1,
            (KEY_GRANT_STREAM_DIMENSION, "stream") => 2,
            (d, a) => {
                return Err(malformed(format!(
                    "dimension {d:?} and axis {a:?} do not name one key_grant axis"
                )))
            }
        };
        for (member, on) in AXIS_MEMBERS {
            if !on[index] && env.get(member).is_some() {
                return Err(malformed(format!(
                    "`{member}` is not a member of the {axis_token} axis"
                )));
            }
        }
        // Positive-only, a fact: score (and confidence when present) is 1.0.
        if env.get("score").and_then(serde_json::Value::as_f64) != Some(KEY_GRANT_SCORE) {
            return Err(malformed("a key_grant row carries `score` 1.0"));
        }
        if env
            .get("confidence")
            .is_some_and(|c| c.as_f64() != Some(KEY_GRANT_SCORE))
        {
            return Err(malformed(
                "a key_grant row carries `confidence` 1.0 when present",
            ));
        }
        if row.weight.is_some_and(|w| w != KEY_GRANT_SCORE) {
            return Err(malformed("a key_grant row's weight is 1.0"));
        }
        if !row.subject_key_ids.is_empty() {
            return Err(malformed(
                "a key_grant row names no subject: the recipient gains no retraction authority",
            ));
        }
        if row.expires_at.is_some() {
            return Err(malformed(
                "a key_grant row carries no expiry: it is never withdrawn, forward secrecy is \
                 by rotation",
            ));
        }
        let scope = row.cohort_scope.as_str();
        let axis = match index {
            0 => {
                let at_rest_sha256 = member_str(env, "at_rest_sha256")?;
                if !(at_rest_sha256.len() == 64
                    && at_rest_sha256
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                {
                    return Err(malformed(
                        "`at_rest_sha256` is not 64 lowercase hex characters",
                    ));
                }
                if scope != cohort_scope::SELF && scope != cohort_scope::FAMILY {
                    return Err(malformed(format!(
                        "a content-axis key_grant row sits at self / family, not {scope:?}"
                    )));
                }
                // CC 3.3.2 — the digest is a member, never a citation.
                if env
                    .get("evidence_refs")
                    .and_then(|v| v.as_array())
                    .is_some_and(|refs| {
                        refs.iter()
                            .any(|r| r.as_str().is_some_and(|s| s.contains(at_rest_sha256)))
                    })
                {
                    return Err(malformed(
                        "`at_rest_sha256` is cited in `evidence_refs`; a key wrap is not a \
                         content binding (CC 3.3.2)",
                    ));
                }
                let owner_key_id = member_str(env, "owner_key_id")?;
                check_target(env, scope, owner_key_id)?;
                KeyGrantAxis::Content {
                    at_rest_sha256: at_rest_sha256.to_owned(),
                    cohort_scope: scope.to_owned(),
                    owner_key_id: owner_key_id.to_owned(),
                }
            }
            1 => {
                if scope != cohort_scope::COMMUNITY {
                    return Err(malformed(format!(
                        "an epoch-axis key_grant row sits at community, not {scope:?}"
                    )));
                }
                let community_key_id = member_str(env, "community_key_id")?;
                check_target(env, scope, community_key_id)?;
                KeyGrantAxis::Epoch {
                    community_key_id: community_key_id.to_owned(),
                    minter_key_id: member_str(env, "minter_key_id")?.to_owned(),
                    epoch: member_u64(env, "epoch")?,
                }
            }
            _ => {
                let scope_ok = matches!(
                    scope,
                    cohort_scope::SELF
                        | cohort_scope::FAMILY
                        | cohort_scope::COMMUNITY
                        | cohort_scope::AFFILIATIONS
                );
                if !scope_ok {
                    return Err(malformed(format!(
                        "a stream-axis key_grant row sits at a private scope, not {scope:?}"
                    )));
                }
                let owner_key_id = member_str(env, "owner_key_id")?;
                check_target(env, scope, owner_key_id)?;
                let stream_id = member_str(env, "stream_id")?;
                // v55.0.0 — a stream id reserved for an inline blob's log
                // (#953) names no stream any node can hold.
                if crate::federation::stream_sth::refuse_reserved_stream_id(stream_id).is_err() {
                    return Err(malformed(format!(
                        "a stream-axis key_grant row names stream {stream_id:?}, shaped like a \
                         SHA-256 and reserved for an inline blob's log (CIRISPersist#953)"
                    )));
                }
                KeyGrantAxis::Stream {
                    stream_id: stream_id.to_owned(),
                    epoch: member_u64(env, "epoch")?,
                    cohort_scope: scope.to_owned(),
                    owner_key_id: owner_key_id.to_owned(),
                }
            }
        };
        if row.attested_key_id.is_empty() {
            return Err(malformed("a key_grant row names its recipient"));
        }
        Ok(KeyGrantRow {
            axis,
            wrap: GrantWrap {
                recipient_key_id: row.attested_key_id.clone(),
                wrap_algorithm: member_str(env, "wrap_algorithm")?.to_owned(),
                wrapped_dek: member_str(env, "wrapped_dek")?.to_owned(),
            },
        })
    }
}

/// The CC 2 cohort target a content / stream row names: `family_key_id` at
/// family, `community_id` at a room scope, none at self.
fn insert_target(m: &mut serde_json::Map<String, serde_json::Value>, scope: &str, group: &str) {
    match scope {
        cohort_scope::FAMILY => {
            m.insert("family_key_id".into(), group.into());
        }
        cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => {
            m.insert("community_id".into(), group.into());
        }
        _ => {}
    }
}

/// The target agreement [`insert_target`] writes, read back: the group is
/// named exactly once, by the alias its scope uses, and nothing else names a
/// target (the write gate refuses a split-brain row on its own).
fn check_target(env: &serde_json::Value, scope: &str, group: &str) -> Result<(), Error> {
    let want: Option<&str> = match scope {
        cohort_scope::FAMILY => Some("family_key_id"),
        cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Some("community_id"),
        _ => None,
    };
    for field in ["family_key_id", "community_id", "cohort_key_id"] {
        let named = env.get(field);
        let ok = if Some(field) == want {
            named.and_then(|v| v.as_str()) == Some(group)
        } else {
            named.is_none()
        };
        if !ok {
            return Err(malformed(format!(
                "a {scope} key_grant row names its group {group:?} as `{}` and no other target; \
                 `{field}` is {named:?}",
                want.unwrap_or("no target")
            )));
        }
    }
    Ok(())
}

/// v55.0.0 (#989, CC 3.3.2 / #963) — **may `recipient` hold the key of
/// content placed at `scope` in `group`?** The fan-out's own rule, asked of
/// one recipient: an ACTIVE occurrence of the owner (`self`), of an active
/// family member (`family`), or of a member on the community's authorized
/// roster now (`community` / `affiliations`) that
/// [`occurrence_may_hold_key`](crate::federation::replication_audience::occurrence_may_hold_key)
/// (the room variant for a room) admits. A member whose own key is its
/// occurrence keeps its wrap.
pub async fn recipient_may_hold_key<D>(
    dir: &D,
    scope: &str,
    group: &str,
    recipient: &str,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    use crate::federation::replication_audience::{
        occurrence_may_hold_key, occurrence_may_hold_room_key, OwnerCohort,
    };
    let room = matches!(scope, cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS);
    let members: Vec<String> = match scope {
        cohort_scope::SELF => vec![group.to_owned()],
        cohort_scope::FAMILY => match dir.active_family_members(group).await {
            Ok(m) => m.into_iter().map(|m| m.key_id).collect(),
            Err(Error::InvalidArgument(_)) => Vec::new(),
            Err(e) => return Err(e),
        },
        _ if room => match dir.lookup_community(group).await? {
            Some(c) => {
                crate::federation::authorized_community_roster_at(dir, &c, chrono::Utc::now())
                    .await?
                    .into_iter()
                    .map(|m| m.key_id)
                    .collect()
            }
            None => Vec::new(),
        },
        _ => Vec::new(),
    };
    for member in &members {
        for o in dir.list_identity_occurrences_active(member).await? {
            if o.occurrence_key_id != recipient {
                continue;
            }
            let may = if room {
                occurrence_may_hold_room_key(dir, member, &o, group).await?
            } else {
                let cohort = if scope == cohort_scope::SELF {
                    OwnerCohort::SelfContent
                } else {
                    OwnerCohort::Group {
                        scope,
                        target: group,
                    }
                };
                occurrence_may_hold_key(dir, member, &o, cohort).await?
            };
            if may {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// §12 / §20.1 — is `signer` an ACTIVE member of `community_key_id` at
/// `as_of`, per this node's replicated roster fold — asked about the
/// PRINCIPAL, not the instrument (CIRISPersist#851, the #765 lift):
/// `signer` is first resolved through
/// [`admission_identity_for_writer`](crate::federation::admission::admission_identity_for_writer)
/// — an occurrence lifts to its identity, an owned node to its single live
/// owner, anything else stays itself — and the principal must be on the
/// roster minus effective removals
/// ([`removed_key_ids_at`](crate::federation::removed_key_ids_at) — the same
/// fold the cascade wraps by). The occurrence walk remains for a signer that
/// is a member's occurrence on this node. An unknown community admits nobody.
pub async fn is_active_member_at<D>(
    directory: &D,
    community_key_id: &str,
    signer: &str,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(community) = directory.lookup_community(community_key_id).await? else {
        return Ok(false);
    };
    // The principals (§20.1, PR #852 review rounds two–four):
    // - every row bound under the signer's key is read (the table's key is
    //   (identity, occurrence), so one key may be bound under several
    //   identities); a revocation counts ONLY on the row of the identity the
    //   lift resolves to — an identity may bind any key as its occurrence and
    //   revoke it, which must not disable that key for everyone else;
    // - a NODE-role key (the role on the Key-plane record) lifts only through
    //   its live owner binding, refused if the owner's own row for the key is
    //   revoked, never through a row a prior admission left;
    // - a device key lifts to each identity whose row for it is unrevoked.
    let rows = directory
        .list_identity_occurrences_by_occurrence_key(signer)
        .await?;
    let mut revoked_under: std::collections::BTreeSet<String> = Default::default();
    for o in &rows {
        let revs = directory
            .list_identity_occurrence_revocations_for(&o.identity_key_id)
            .await?;
        if revs.iter().any(|r| r.revokes(o, as_of)) {
            revoked_under.insert(o.identity_key_id.clone());
        }
    }
    let is_node = directory.lookup_public_key(signer).await?.is_some_and(|k| {
        k.identity_type == crate::federation::types::identity_type::NODE
            || k.claims_role(crate::federation::types::identity_type::NODE)
    });
    // v48.0.0 (CIRISPersist#860) — the roster AS OF `as_of` is the one fold
    // (record + widenings − revocations), never the record alone.
    // v49.0.0 (#908): only events whose signer has standing count.
    let roster =
        crate::federation::authorized_community_roster_at(directory, &community, as_of).await?;
    // A NODE minter has exactly ONE principal — its live owner — and no
    // fallback: not the key itself, not a stale row under a former owner,
    // not the member-occurrence walk below (PR #852 review, round five: an
    // ownership transfer must end the old community's minting authority).
    if is_node {
        return Ok(
            match crate::federation::admission::owner_of(directory, signer).await? {
                Some(owner) if !revoked_under.contains(&owner) => {
                    roster.iter().any(|m| m.key_id == owner)
                }
                _ => false,
            },
        );
    }
    let mut principals: Vec<String> = vec![signer.to_owned()];
    for o in &rows {
        if !revoked_under.contains(&o.identity_key_id) {
            principals.push(o.identity_key_id.clone());
        }
    }
    for member in &roster {
        if principals.contains(&member.key_id) {
            return Ok(true);
        }
        // Folded at `as_of`, not at the wall clock: a row emitted while its
        // minter occurrence was active, delivered after that occurrence was
        // revoked, is a valid historical row (CIRISPersist#850 review).
        let revs = directory
            .list_identity_occurrence_revocations_for(&member.key_id)
            .await?;
        let occurrences = directory
            .list_identity_occurrences_for(&member.key_id)
            .await?;
        if occurrences
            .iter()
            .filter(|o| !revs.iter().any(|r| r.revokes(o, as_of)))
            .any(|o| o.occurrence_key_id == signer)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v55.0.0 (#989) — **the sealer rule, asked of `signer` for `axis` at
/// `asserted_at`** (CC 3.1.3 `key_grant:{axis}`, "Reserved — sealer-only").
///
/// - epoch: the minter, or a holder of a live `grant` delegation from it
///   (`signer_not_minter`), and an active member occurrence of the community
///   at `asserted_at` (`signer_not_active_member`);
/// - content / stream: where THIS node holds the blob or the stream
///   ([`FederationDirectory::key_grant_held_owner`]), a key that speaks for
///   its author / owner, or its `grant` delegate (`signer_not_author` /
///   `signer_not_stream_owner`, terminal); then at `self` a key that speaks
///   for the owner, or its `grant` delegate (`SignerDoesNotActFor`, plane
///   `key_grant`, retryable: the occurrence may not have landed). At a group
///   scope the write gate's membership check is the owner rule.
///
/// Asked by the admission gate and by the emitter (which withholds rows it
/// could no longer sign as sealer).
pub async fn check_sealer(
    dir: &dyn FederationDirectory,
    signer: &str,
    axis: &KeyGrantAxis,
    asserted_at: chrono::DateTime<chrono::Utc>,
    chain_instant: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error> {
    match axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            ..
        } => {
            // v54.0.0 (#1033, CC 2.4.1.2.1) — the minter, or a holder of a
            // live `grant`-scoped chain from the minter.
            if signer != minter_key_id
                && !crate::federation::admission::holds_grant_delegation(
                    dir,
                    minter_key_id,
                    signer,
                    chain_instant,
                )
                .await?
            {
                return Err(refuse(
                    KeyGrantRefusalReason::SignerNotMinter,
                    format!(
                        "signer {signer:?} is not the row's minter {minter_key_id:?} and holds no \
                         live `grant`-scoped delegation from it; only M, or M's `grant` delegate, \
                         issues a grant over M's counter (BLOB_REPLICATION.md §11; CC 2.4.1.2.1)"
                    ),
                ));
            }
            if !is_active_member_at(dir, community_key_id, signer, asserted_at).await? {
                return Err(refuse(
                    KeyGrantRefusalReason::SignerNotActiveMember,
                    format!(
                        "signer {signer:?} is not an active member occurrence of community \
                         {community_key_id:?} at {} per this node's roster fold",
                        asserted_at.to_rfc3339()
                    ),
                ));
            }
            Ok(())
        }
        KeyGrantAxis::Content {
            cohort_scope: scope,
            owner_key_id,
            at_rest_sha256: id,
        }
        | KeyGrantAxis::Stream {
            cohort_scope: scope,
            owner_key_id,
            stream_id: id,
            ..
        } => {
            let content = matches!(axis, KeyGrantAxis::Content { .. });
            // The held-state leg first: where this node holds the content its
            // verdict is definitive (terminal), where the owner leg below may
            // only be an ordering gap (retryable).
            if let Some(held) = dir.key_grant_held_owner(axis).await? {
                if !may_issue_grant_for(dir, signer, &held, chain_instant).await? {
                    return Err(if content {
                        refuse(
                            KeyGrantRefusalReason::SignerNotAuthor,
                            format!(
                                "signer {signer:?} is neither the author {held:?} of blob {id} \
                                 nor an active occurrence of them"
                            ),
                        )
                    } else {
                        refuse(
                            KeyGrantRefusalReason::SignerNotStreamOwner,
                            format!(
                                "signer {signer:?} does not speak for the owner {held:?} of \
                                 stream {id:?} on this node; a stream's keys are \
                                 granted by its single sender (CC 5.3.3.1)"
                            ),
                        )
                    });
                }
            }
            if scope == cohort_scope::SELF
                && !may_issue_grant_for(dir, signer, owner_key_id, chain_instant).await?
            {
                return Err(Error::SignerDoesNotActFor {
                    attesting_key_id: signer.to_owned(),
                    identity_key_id: owner_key_id.clone(),
                    plane: KEY_GRANT_PLANE,
                    reason: super::SignerNotActingReason::NotBound,
                });
            }
            Ok(())
        }
    }
}

/// The `plane` a key-grant `SignerDoesNotActFor` refusal names.
pub const KEY_GRANT_PLANE: &str = "key_grant";

/// v60.0.0 (CIRISPersist#1049) — **the signed instants of the stream-axis
/// grant rows `sealer` holds for `(stream_id, epoch, viewer_key_id)`**, read
/// from the stored `key_grant:stream:v1` rows (no projection column carries
/// them, and none is added). The read path judges a sealer's `grant` chain at
/// these instants, the instants admission judged it at
/// ([`crate::federation::admission::grant_chain_instant`]), so a read never
/// refuses a grant admission accepted.
pub(crate) async fn stream_grant_row_instants(
    dir: &dyn FederationDirectory,
    sealer: &str,
    stream_id: &str,
    epoch: u64,
    viewer_key_id: &str,
) -> Result<Vec<chrono::DateTime<chrono::Utc>>, Error> {
    let mut out = Vec::new();
    let mut pages = crate::federation::attestation_query::AttestationQuery::by(
        sealer,
        crate::federation::attestation_query::FOLD_PAGE,
    )
    .dimension(KEY_GRANT_STREAM_DIMENSION)
    .pages();
    while let Some(page) = pages.next(dir).await? {
        for row in page {
            let Ok(parsed) = KeyGrantRow::from_attestation(&row) else {
                continue;
            };
            if parsed.recipient() == viewer_key_id
                && matches!(&parsed.axis, KeyGrantAxis::Stream { stream_id: s, epoch: e, .. }
                    if s == stream_id && *e == epoch)
            {
                out.push(row.asserted_at);
            }
        }
    }
    Ok(out)
}

/// v55.0.0 (CIRISPersist#989, CC 3.3.2 rc7) — **the key-grant admission
/// rule**, asked of every federation-tier row by
/// `check_reserved_prefix_admission` on every backend:
///
/// - (a retired key-grant SET never reaches it: the row-type gate refuses a
///   retired carrier first, and [`KeyGrantRow::from_attestation`] answers
///   `set_retired` at the key-grant door);
/// - a `scores` row on `key_grant:` must parse ([`KeyGrantRow::from_attestation`]),
///   carry a v2 wrap, be self-signed (`attesting_key_id == scrub_key_id`),
///   meet the sealer rule ([`check_sealer`], at the row's `asserted_at`, its
///   delegation chain at [`grant_chain_instant`](crate::federation::admission::grant_chain_instant);
///   v60.0.0, #1049: a row signed more than W ago must also meet it at
///   receipt, else `asserted_at_stale`),
///   and name a recipient [`recipient_may_hold_key`] admits
///   (`recipient_not_in_audience`).
///
/// Every other row passes untouched.
pub async fn check_key_grant_row_admission(
    dir: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    let Some(dimension) =
        crate::federation::admission::envelope_dimension(&row.attestation_envelope)
    else {
        return Ok(());
    };
    if !dimension.starts_with(KEY_GRANT_DIMENSION_PREFIX) {
        return Ok(());
    }
    // A `key_grant:` dimension rides `scores` only: a composer naming one
    // states nothing CC 3.3.2 defines.
    let parsed = KeyGrantRow::from_attestation(row)?;
    check_wrap_algorithm(&parsed.wrap)?;
    let signer = row.scrub_key_id.as_str();
    if signer.is_empty() || signer != row.attesting_key_id {
        return Err(refuse(
            KeyGrantRefusalReason::SignerNotSelf,
            format!(
                "attesting_key_id {:?} != scrub_key_id {:?}; a key_grant row is signed by the \
                 party it speaks for",
                row.attesting_key_id, row.scrub_key_id
            ),
        ));
    }
    check_sealer(
        dir,
        signer,
        &parsed.axis,
        row.asserted_at,
        crate::federation::admission::grant_chain_instant(row),
    )
    .await?;
    // v60.0.0 (CIRISPersist#1049, CC 2.6.7 W) — the sealer rule (its `grant`
    // chain and the epoch axis's membership) is judged at the row's signed
    // `asserted_at`; that instant stands alone only inside W. Older, the
    // signer must ALSO be a sealer at receipt, or the row is
    // `asserted_at_stale`: a withdrawn delegate cannot backdate a grant into
    // its old window.
    let now = chrono::Utc::now();
    if crate::federation::self_roster::outside_past_freshness_window(row.asserted_at, now)
        && check_sealer(dir, signer, &parsed.axis, now, now)
            .await
            .is_err()
    {
        return Err(Error::AssertedAtStale {
            author: signer.to_owned(),
            standing_for: parsed.axis.group_key_id().to_owned(),
            plane: KEY_GRANT_PLANE,
            asserted_at: row.asserted_at,
            w_secs: crate::federation::self_roster::PAST_FRESHNESS_W_SECS,
        });
    }
    if !recipient_may_hold_key(
        dir,
        parsed.axis.emission_cohort_scope(),
        parsed.axis.group_key_id(),
        parsed.recipient(),
    )
    .await?
    {
        return Err(refuse(
            KeyGrantRefusalReason::RecipientNotInAudience,
            format!(
                "recipient {:?} is not an occurrence that may hold the key of {} content in \
                 {:?} on this node (the one audience rule, #963); re-offer once its occurrence, \
                 the roster and its owner's allow list have landed",
                parsed.recipient(),
                parsed.axis.emission_cohort_scope(),
                parsed.axis.group_key_id()
            ),
        ));
    }
    Ok(())
}

fn check_wrap_algorithm(wrap: &GrantWrap) -> Result<(), Error> {
    use crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2;
    if wrap.wrap_algorithm != WRAP_ALGORITHM_V2 {
        return Err(refuse(
            KeyGrantRefusalReason::WrapAlgorithmNotV2,
            format!(
                "wrap for {:?} carries wrap_algorithm {:?}; only {WRAP_ALGORITHM_V2:?} is \
                 admissible (CC 4.4.3.4.1 / CC 5.2)",
                wrap.recipient_key_id, wrap.wrap_algorithm
            ),
        ));
    }
    Ok(())
}

fn map_blob_err(e: BlobError) -> Error {
    Error::Backend(format!("key_grant: {e}"))
}

fn sha_of(at_rest_sha256: &str) -> Result<[u8; 32], Error> {
    hex::decode(at_rest_sha256)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| malformed("at_rest_sha256"))
}

/// §14 — what an emission attempt means for the caller. A community that
/// has lost (or never had) a live steward-bound moderator MAY NOT federate
/// at moderated capability (CC 4.5.4 / §11.11), and the attestation plane
/// refuses every federation-tier row keyed on it — on this node and on every
/// peer. A key-grant row for such a community therefore has nowhere to go:
/// no peer could be party to its bytes, and the local write is still whole
/// (the minter reads through its own self-retention). That ONE verdict is
/// reported as `Ok(None)` with a warning rather than failing the write;
/// every other failure — a signer that cannot sign, a row the plane refuses
/// for what THIS node did — propagates, because then the bytes are stored
/// and the key cannot follow them.
pub fn emission_outcome<T>(r: Result<T, Error>) -> Result<Option<T>, Error> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(Error::CommunityHasNoModerator { community_key_id }) => {
            tracing::warn!(
                community = %community_key_id,
                "key_grant row not emitted: the community has no live moderator and may not \
                 federate at moderated capability (CC 4.5.4); nothing outside this node can be \
                 party to its content until one is appointed"
            );
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// §14 — every epoch-axis wrap this node holds for `(community, minter,
/// epoch)`, or `None` if it holds none.
pub async fn build_epoch_set<B>(
    backend: &B,
    community_key_id: &str,
    minter_key_id: &str,
    epoch: u64,
) -> Result<Option<KeyGrantSet>, BlobError>
where
    B: BlobStorage + Sync,
{
    let wraps = backend
        .community_dek_member_grants_for_epoch(community_key_id, minter_key_id, epoch)
        .await?;
    if wraps.is_empty() {
        return Ok(None);
    }
    Ok(Some(KeyGrantSet {
        axis: KeyGrantAxis::Epoch {
            community_key_id: community_key_id.to_owned(),
            minter_key_id: minter_key_id.to_owned(),
            epoch,
        },
        wraps,
    }))
}

/// §14 — every content-axis wrap this node holds for one self/family blob
/// except persist's own self-retention row, or `None`.
pub async fn build_content_set<B>(
    backend: &B,
    at_rest_sha256: &[u8; 32],
    scope: &str,
    owner_key_id: &str,
) -> Result<Option<KeyGrantSet>, BlobError>
where
    B: BlobStorage + Sync,
{
    let wraps = backend.list_at_rest_grants(at_rest_sha256).await?;
    if wraps.is_empty() {
        return Ok(None);
    }
    Ok(Some(KeyGrantSet {
        axis: KeyGrantAxis::Content {
            at_rest_sha256: hex::encode(at_rest_sha256),
            cohort_scope: scope.to_owned(),
            owner_key_id: owner_key_id.to_owned(),
        },
        wraps,
    }))
}

/// v53.0.0 (CIRISPersist#969) — every stream-axis wrap this node holds for
/// one `(stream_id, epoch)` it sealed, under the stream's owner, or `None`.
pub async fn build_stream_set<B>(
    backend: &B,
    stream_id: &str,
    epoch: u64,
    scope: &str,
    owner_key_id: &str,
) -> Result<Option<KeyGrantSet>, BlobError>
where
    B: BlobStorage + Sync,
{
    // The epoch's sealer is its DEK row's writer (v55.0.0, #981: a supplied
    // epoch is wrapped before the stream holds its first chunk, so the
    // stream's own row may not exist yet).
    let Some(sealer) = backend
        .stream_dek_list(stream_id)
        .await?
        .into_iter()
        .find(|r| r.epoch == epoch)
        .map(|r| r.owner_key_id)
    else {
        return Ok(None);
    };
    let wraps = backend.stream_dek_grants(stream_id, epoch, &sealer).await?;
    if wraps.is_empty() {
        return Ok(None);
    }
    Ok(Some(KeyGrantSet {
        axis: KeyGrantAxis::Stream {
            stream_id: stream_id.to_owned(),
            epoch,
            cohort_scope: scope.to_owned(),
            owner_key_id: owner_key_id.to_owned(),
        },
        wraps,
    }))
}

/// §14 — the wraps this node holds for an emission axis a write door
/// reported (`PutBlobScopedResult::key_grant_emission` and its chunk twins),
/// or `None`.
pub async fn build_set_for_axis<B>(
    backend: &B,
    axis: &KeyGrantAxis,
) -> Result<Option<KeyGrantSet>, BlobError>
where
    B: BlobStorage + Sync,
{
    match axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => build_epoch_set(backend, community_key_id, minter_key_id, *epoch).await,
        KeyGrantAxis::Content {
            at_rest_sha256,
            cohort_scope,
            owner_key_id,
        } => {
            let sha: [u8; 32] = hex::decode(at_rest_sha256)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    BlobError::InvalidArgument(format!(
                        "key_grant axis names a non-hex at_rest_sha256 {at_rest_sha256:?}"
                    ))
                })?;
            build_content_set(backend, &sha, cohort_scope, owner_key_id).await
        }
        KeyGrantAxis::Stream {
            stream_id,
            epoch,
            cohort_scope,
            owner_key_id,
        } => build_stream_set(backend, stream_id, *epoch, cohort_scope, owner_key_id).await,
    }
}

/// v55.0.0 (#989) — what one emission planned: the rows to sign, and why the
/// others were not.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyGrantEmissionPlan {
    /// The axis.
    pub axis: KeyGrantAxis,
    /// One row per wrap not yet held as a row, to a recipient the audience
    /// rule still admits.
    pub rows: Vec<KeyGrantRow>,
    /// Recipients whose wrap is already held as a row by this signer (the
    /// re-emission's idempotence).
    pub already_emitted: Vec<String>,
    /// Recipients the audience rule no longer admits (CC 4.4.3.2.2: a party
    /// removed since the wrap was written is not re-wrapped).
    pub withheld: Vec<String>,
    /// Recipients with no key record on this node yet (a row may only name a
    /// registered key, `check_attested_subject_admission`): their rows wait,
    /// and the axis stays dirty so the next pass emits them.
    pub deferred: Vec<String>,
    /// The signer can no longer sign as the axis's sealer: nothing is
    /// emitted, and the axis is marked clean (a node re-emits only wraps it
    /// can sign as sealer or minter).
    pub sealer_refused: Option<String>,
    /// The ledger watermark, read BEFORE the wraps (§14, V146).
    pub watermark: Option<chrono::DateTime<chrono::Utc>>,
    /// v55.0.0 (CIRISEdge v55 adopt) — the axis is MIS-BUILT: every
    /// recipient was withheld, the signer's own wrap among them. The signer
    /// passed [`check_sealer`], so it still speaks for the axis's owner, and
    /// the audience rule refusing its own occurrence means the axis names the
    /// wrong group (a self/family content axis owned by the node key, the
    /// pre-fix [`dirty_axes`]). Nothing is emitted and the axis stays dirty.
    pub misbuilt: Option<String>,
}

/// v55.0.0 (#989) — what one emission did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyGrantEmission {
    /// The axis.
    pub axis: KeyGrantAxis,
    /// The `attestation_id` of each row emitted, one per recipient.
    pub attestation_ids: Vec<String>,
    /// Recipients whose wrap this signer had already emitted as a row.
    pub already_emitted: Vec<String>,
    /// Recipients withheld: the audience rule no longer admits them.
    pub withheld: Vec<String>,
    /// Recipients whose key record has not reached this node: not emitted
    /// yet, the axis left dirty for the next pass.
    pub deferred: Vec<String>,
    /// The signer could no longer sign as sealer; nothing was emitted.
    pub sealer_refused: Option<String>,
    /// v55.0.0 (CIRISEdge v55 adopt) — the axis was mis-built (see
    /// [`KeyGrantEmissionPlan::misbuilt`]): nothing was emitted and the axis
    /// was left dirty, never cleared.
    #[serde(default)]
    pub misbuilt: Option<String>,
}

/// v55.0.0 (#989) — **plan the rows `signer` owes for `axis`**: the
/// watermark first (§14), then the wraps; per wrap, skip one this signer
/// already holds as a row with the same identity, and withhold one whose
/// recipient [`recipient_may_hold_key`] no longer admits. When `signer` can
/// no longer sign as the axis's sealer ([`check_sealer`] at now), nothing is
/// planned and `sealer_refused` says why. `None` when no wrap is held.
pub async fn plan_key_grant_emission<B>(
    backend: &B,
    signer: &str,
    axis: &KeyGrantAxis,
) -> Result<Option<KeyGrantEmissionPlan>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let watermark = watermark_for_axis(backend, axis).await?;
    let Some(set) = build_set_for_axis(backend, axis)
        .await
        .map_err(map_blob_err)?
    else {
        return Ok(None);
    };
    let now = chrono::Utc::now();
    let mut plan = KeyGrantEmissionPlan {
        axis: axis.clone(),
        rows: Vec::new(),
        already_emitted: Vec::new(),
        withheld: Vec::new(),
        deferred: Vec::new(),
        sealer_refused: None,
        watermark,
        misbuilt: None,
    };
    match check_sealer(backend.as_dyn_directory(), signer, axis, now, now).await {
        Ok(()) => {}
        Err(e @ (Error::KeyGrantRefused { .. } | Error::SignerDoesNotActFor { .. })) => {
            plan.sealer_refused = Some(e.to_string());
            return Ok(Some(plan));
        }
        Err(e) => return Err(e),
    }
    for row in set.rows() {
        if key_grant_row_held(backend, signer, &row).await? {
            plan.already_emitted.push(row.recipient().to_owned());
            continue;
        }
        if !recipient_may_hold_key(
            backend,
            axis.emission_cohort_scope(),
            axis.group_key_id(),
            row.recipient(),
        )
        .await?
        {
            plan.withheld.push(row.recipient().to_owned());
            continue;
        }
        if backend.lookup_public_key(row.recipient()).await?.is_none() {
            plan.deferred.push(row.recipient().to_owned());
            continue;
        }
        plan.rows.push(row);
    }
    // A plan that withholds EVERY recipient, this signer's own wrap among
    // them, is a construction error, not an audience change: a signer that
    // passed the sealer rule speaks for the owner, so the audience rule
    // refusing the signer itself means the axis names the wrong group. A
    // plan that withholds SOME recipients (a removed device or member) is
    // the audience rule working, and clears as before; so does one where
    // the signer holds no wrap of its own (nothing proves the group wrong).
    if plan.rows.is_empty()
        && plan.already_emitted.is_empty()
        && plan.deferred.is_empty()
        && plan.withheld.iter().any(|r| r == signer)
    {
        plan.misbuilt = Some(format!(
            "every recipient of {axis:?} was withheld, this signer's own wrap among them: the \
             axis names the wrong group ({})",
            axis.group_key_id()
        ));
    }
    Ok(Some(plan))
}

/// Does this node hold a key-grant row signed by `signer` with `row`'s
/// identity? (The emitter's idempotence check: the identity is the union key,
/// so a second row with it is a re-wrap the projection would ignore.)
pub async fn key_grant_row_held<D>(dir: &D, signer: &str, row: &KeyGrantRow) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut pages = AttestationQuery::to(row.recipient(), FOLD_PAGE)
        .authored_by(signer)
        .dimension_prefix(row.axis.dimension())
        .pages();
    while let Some(page) = pages.next(dir).await? {
        if page
            .iter()
            .filter(|a| is_key_grant_row(a))
            .filter_map(|a| KeyGrantRow::from_attestation(a).ok())
            .any(|held| held.axis == row.axis && held.recipient() == row.recipient())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// §14 — the full emission through `emit_one`: plan, sign and store each row,
/// then mark the axis clean when every planned row was stored and none waits
/// on a recipient's key record (or nothing was owed). A community with no
/// live moderator stores nothing and leaves the axis dirty
/// ([`emission_outcome`]).
async fn emit_planned<B, F, Fut>(
    backend: &B,
    signer: &str,
    axis: &KeyGrantAxis,
    mut emit_one: F,
) -> Result<Option<KeyGrantEmission>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
    F: FnMut(EmitAttestationInput) -> Fut,
    Fut: std::future::Future<Output = Result<String, Error>>,
{
    let Some(plan) = plan_key_grant_emission(backend, signer, axis).await? else {
        return Ok(None);
    };
    let mut ids = Vec::with_capacity(plan.rows.len());
    let mut skipped = false;
    for row in &plan.rows {
        match emission_outcome(emit_one(row.emit_input()?).await)? {
            Some(id) => ids.push(id),
            None => skipped = true,
        }
    }
    if !skipped && plan.deferred.is_empty() && plan.misbuilt.is_none() {
        if let Some(watermark) = plan.watermark {
            mark_emitted(backend, &plan.axis, watermark).await?;
        }
    }
    Ok(Some(KeyGrantEmission {
        axis: plan.axis,
        attestation_ids: ids,
        already_emitted: plan.already_emitted,
        withheld: plan.withheld,
        deferred: plan.deferred,
        sealer_refused: plan.sealer_refused,
        misbuilt: plan.misbuilt,
    }))
}

/// §14 — emit the rows for `axis` signed by `signer` through the attestation
/// store. The PyO3 doors' and the witnesses' emitter (its hybrid signer is the
/// `LocalSigner`); the Engine's is
/// [`Engine::emit_key_grant`](crate::engine::Engine::emit_key_grant).
pub async fn emit_key_grant_axis_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    axis: &KeyGrantAxis,
) -> Result<Option<KeyGrantEmission>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let me = signer.derived_key_id();
    emit_planned(backend, &me, axis, |input| async move {
        crate::federation::attestation_emit::emit_with_local_signer(backend, signer, input)
            .await
            .map(|e| e.attestation_id)
    })
    .await
}

/// §14 (V146) — **every dirty axis `signer` owes, emitted** ([`dirty_axes`]
/// under the signer's derived key): the PyO3 init sweep's and
/// `emit_pending_key_grants`' loop, and after V192 the legacy re-emit. One
/// axis that cannot be emitted is logged and left dirty; it does not hold
/// back the others. Returns the rows emitted.
pub async fn emit_dirty_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
) -> Result<usize, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let me = signer.derived_key_id();
    let axes = dirty_axes(backend, &me).await?;
    Ok(emit_dirty_axes(&me, axes, |axis| async move {
        emit_key_grant_axis_with_local_signer(backend, signer, &axis).await
    })
    .await
    .emitted)
}

/// v55.0.0 (CIRISEdge v55 adopt) — how long a MIS-BUILT axis
/// ([`KeyGrantEmissionPlan::misbuilt`]) waits before the dirty loop plans it
/// again, and the interval its log is throttled to. A mis-built axis stays
/// dirty, so without this every pass would re-plan and re-log it.
pub const MISBUILT_AXIS_RETRY: std::time::Duration = std::time::Duration::from_secs(300);

/// One mis-built axis's state in this process: when it may be planned
/// again, and how often it has been planned and skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MisbuiltAxisState {
    /// The earliest instant the dirty loop plans it again.
    pub next_retry: std::time::Instant,
    /// Passes that planned it and found it mis-built (one log line each).
    pub planned: u64,
    /// Passes that skipped it inside the retry interval.
    pub skipped: u64,
}

fn misbuilt_axes() -> &'static std::sync::Mutex<std::collections::HashMap<String, MisbuiltAxisState>>
{
    static AXES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, MisbuiltAxisState>>,
    > = std::sync::OnceLock::new();
    AXES.get_or_init(Default::default)
}

fn misbuilt_axis_key(signer: &str, axis: &KeyGrantAxis) -> String {
    format!("{signer}\u{0}{axis:?}")
}

/// v55.0.0 — the state the dirty loop keeps for `signer`'s mis-built
/// `axis` in this process, or `None` when it is not (or no longer) mis-built.
#[must_use]
pub fn misbuilt_axis_state(signer: &str, axis: &KeyGrantAxis) -> Option<MisbuiltAxisState> {
    misbuilt_axes()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&misbuilt_axis_key(signer, axis))
        .copied()
}

/// One throttled event under `key`: `true` (log it, count it planned) when
/// the key's interval has passed or it was never seen, else `false` (count
/// it skipped).
fn throttle_tick(key: &str) -> bool {
    let now = std::time::Instant::now();
    let mut map = misbuilt_axes()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let st = map.entry(key.to_owned()).or_insert(MisbuiltAxisState {
        next_retry: now,
        planned: 0,
        skipped: 0,
    });
    if now < st.next_retry {
        st.skipped += 1;
        return false;
    }
    st.planned += 1;
    st.next_retry = now + MISBUILT_AXIS_RETRY;
    true
}

/// What one pass of the dirty loop did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirtyEmissionReport {
    /// Rows emitted.
    pub emitted: usize,
    /// Axes planned this pass and found mis-built (left dirty, logged).
    pub misbuilt: usize,
    /// Mis-built axes skipped inside their retry interval.
    pub backed_off: usize,
}

/// v55.0.0 (CIRISEdge v55 adopt) — **one pass of the dirty loop over
/// `axes`**, emitted by `emit` (the LocalSigner door or the Engine's). One
/// axis that cannot be emitted is logged and left dirty; it does not hold
/// back the others (#989). A MIS-BUILT axis is left dirty and logged at
/// error level once per [`MISBUILT_AXIS_RETRY`], and is not planned again
/// until the interval has passed; the log carries how many passes planned
/// and skipped it. An axis that emits normally forgets its state.
pub async fn emit_dirty_axes<F, Fut, E>(
    signer: &str,
    axes: Vec<KeyGrantAxis>,
    mut emit: F,
) -> DirtyEmissionReport
where
    F: FnMut(KeyGrantAxis) -> Fut,
    Fut: std::future::Future<Output = Result<Option<KeyGrantEmission>, E>>,
    E: std::fmt::Display,
{
    let mut report = DirtyEmissionReport::default();
    for axis in axes {
        let key = misbuilt_axis_key(signer, &axis);
        let now = std::time::Instant::now();
        {
            let mut map = misbuilt_axes()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(st) = map.get_mut(&key) {
                if now < st.next_retry {
                    st.skipped += 1;
                    report.backed_off += 1;
                    continue;
                }
            }
        }
        match emit(axis.clone()).await {
            Ok(Some(e)) => {
                report.emitted += e.attestation_ids.len();
                let mut map = misbuilt_axes()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(reason) = &e.misbuilt {
                    report.misbuilt += 1;
                    let st = map.entry(key).or_insert(MisbuiltAxisState {
                        next_retry: now,
                        planned: 0,
                        skipped: 0,
                    });
                    st.planned += 1;
                    st.next_retry = now + MISBUILT_AXIS_RETRY;
                    tracing::error!(
                        axis = ?axis,
                        withheld = ?e.withheld,
                        planned = st.planned,
                        skipped = st.skipped,
                        retry_secs = MISBUILT_AXIS_RETRY.as_secs(),
                        "key-grant axis is mis-built and was NOT cleared: {reason}"
                    );
                } else {
                    map.remove(&key);
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                axis = ?axis,
                error = %e,
                "key-grant rows for this axis could not be emitted; it stays dirty (#989)"
            ),
        }
    }
    report
}

/// §14 — the epoch-axis rows for `(community, M, epoch)` where M is
/// `signer`'s derived key. `Ok(None)` when this node holds no wrap for it.
pub async fn emit_epoch_key_grant_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    community_key_id: &str,
    epoch: u64,
) -> Result<Option<KeyGrantEmission>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let axis = KeyGrantAxis::Epoch {
        community_key_id: community_key_id.to_owned(),
        minter_key_id: signer.derived_key_id(),
        epoch,
    };
    emit_key_grant_axis_with_local_signer(backend, signer, &axis).await
}

/// §14 — the content-axis rows for one self/family blob sealed by `signer`.
/// `Ok(None)` when the blob has no recipient grant.
pub async fn emit_content_key_grant_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    at_rest_sha256: &[u8; 32],
    scope: &str,
    owner_key_id: &str,
) -> Result<Option<KeyGrantEmission>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let axis = KeyGrantAxis::Content {
        at_rest_sha256: hex::encode(at_rest_sha256),
        cohort_scope: scope.to_owned(),
        owner_key_id: owner_key_id.to_owned(),
    };
    emit_key_grant_axis_with_local_signer(backend, signer, &axis).await
}

/// §14 — the Engine's emitter: the same plan, each row through
/// `emit_attestation_self`-shaped `emit_one`.
pub async fn emit_key_grant_axis_with<B, F, Fut>(
    backend: &B,
    signer_key_id: &str,
    axis: &KeyGrantAxis,
    emit_one: F,
) -> Result<Option<KeyGrantEmission>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
    F: FnMut(EmitAttestationInput) -> Fut,
    Fut: std::future::Future<Output = Result<String, Error>>,
{
    emit_planned(backend, signer_key_id, axis, emit_one).await
}

/// #851 (§20.3) — **publish this node's own content-only occurrence under
/// `identity_key_id`**: the envelope names the node as `attesting_key_id` and
/// `occurrence_key_id`, carries this node's content-KEM pubkeys and NO
/// transport destination (the node's transport identity lives on its own
/// plane), is signed by `signer` (the node's LocalSigner), and is admitted
/// through the gated door — so the stored row is signed-put and the plane
/// advertises it. Admission's `signer_acts_for` lifts the node to
/// `identity_key_id` through its live owner binding (§20.2); a node with no
/// such binding on this backend is refused here, exactly as a peer would
/// refuse it.
pub async fn publish_self_occurrence_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    identity_key_id: &str,
    device_class: &str,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<crate::federation::SignedIdentityOccurrence, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let me = signer.derived_key_id();
    let kem = backend
        .load_or_init_content_kem_identity()
        .await
        .map_err(map_blob_err)?;
    let enc = crate::federation::EncryptionPubkeys {
        x25519_base64: kem.x25519_pubkey_b64,
        ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
    };
    publish_signed_content_only_occurrence(
        backend,
        signer,
        identity_key_id,
        &me,
        device_class,
        None,
        enc,
        valid_until,
    )
    .await
}

/// v44.5.0 (§21.3, CIRISPersist#856) — **the one producer of the content-only
/// signed occurrence** (§20.2's second form). Two doors call it: a node
/// publishing its OWN occurrence (`occurrence_key_id == signer`, the owner
/// binding lifts it) and `self_at_login` publishing a DEVICE occurrence under
/// the identity that signs it (`attesting_key_id == identity_key_id`, no lift
/// needed). One envelope builder, so the two cannot drift by a field — the
/// gate binds every persisted field to the envelope (PR #852 round one), and
/// a second builder that carried one field differently would produce rows
/// the gate refuses.
#[allow(clippy::too_many_arguments)]
pub async fn publish_signed_content_only_occurrence<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    identity_key_id: &str,
    occurrence_key_id: &str,
    device_class: &str,
    hardware_attestation: Option<&str>,
    enc: crate::federation::EncryptionPubkeys,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<crate::federation::SignedIdentityOccurrence, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let me = signer.derived_key_id();
    // Millisecond-exact: the envelope carries the millisecond rendering and
    // the gate requires the typed instant to carry nothing below it.
    let asserted_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap_or_else(chrono::Utc::now);
    // v44.5.0 (#855, §21.2) — `valid_until` is one more bound member, carried
    // exactly as `asserted_at` is: truncated to the millisecond BEFORE
    // signing, because the gate compares the typed instant to the envelope's
    // millisecond rendering and a caller-supplied instant with finer
    // precision would sign one thing and store another.
    let valid_until = valid_until.map(|t| {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t.timestamp_millis()).unwrap_or(t)
    });
    let valid_until_json = valid_until.map_or(serde_json::Value::Null, |t| {
        serde_json::Value::String(t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    });
    let envelope = serde_json::json!({
        "attesting_key_id": me,
        "identity_key_id": identity_key_id,
        "occurrence_key_id": occurrence_key_id,
        "device_class": device_class,
        "encryption_pubkeys": {
            "x25519_base64": enc.x25519_base64,
            "ml_kem_768_base64": enc.ml_kem_768_base64,
        },
        "asserted_at": asserted_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "valid_until": valid_until_json,
        "hardware_attestation": hardware_attestation
            .map_or(serde_json::Value::Null, |h| serde_json::Value::String(h.to_owned())),
    });
    let (signed_envelope, signature) =
        ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
            &crate::signing::LocalSelfSigner::new(signer),
            envelope,
        )
        .await
        .map_err(|e| Error::Backend(format!("publish_self_occurrence: sign: {e}")))?;
    let signed = crate::federation::SignedIdentityOccurrence {
        identity_occurrence: crate::federation::IdentityOccurrence {
            identity_key_id: identity_key_id.to_owned(),
            occurrence_key_id: occurrence_key_id.to_owned(),
            device_class: device_class.to_owned(),
            hardware_attestation: hardware_attestation.map(str::to_owned),
            asserted_at,
            valid_until,
            encryption_pubkeys: Some(enc),
            transport_binding: None,
            persist_row_hash: String::new(),
        },
        attesting_key_id: me,
        signed_envelope,
        signature,
    };
    backend.put_identity_occurrence(signed.clone()).await?;
    Ok(signed)
}

/// §14 (V146, PR #850 review) — **the emission ledger: stamp the axis as
/// emitted** with the database's own clock. Called by every emitter once
/// every planned row of the axis is stored, so the ledger never depends on
/// which door carried the rows.
pub async fn mark_emitted<B>(
    backend: &B,
    axis: &KeyGrantAxis,
    watermark: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    B: BlobStorage + Sync,
{
    match axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => backend
            .community_dek_mark_key_grant_emitted(
                community_key_id,
                minter_key_id,
                *epoch,
                watermark,
            )
            .await
            .map_err(map_blob_err),
        KeyGrantAxis::Content { at_rest_sha256, .. } => {
            let sha = sha_of(at_rest_sha256)?;
            backend
                .blob_mark_key_grant_emitted(&sha, watermark)
                .await
                .map_err(map_blob_err)
        }
        KeyGrantAxis::Stream {
            stream_id, epoch, ..
        } => backend
            .stream_dek_mark_key_grant_emitted(stream_id, *epoch, watermark)
            .await
            .map_err(map_blob_err),
    }
}

/// §14 (V146) — **the grant watermark for an axis, read BEFORE the wraps**:
/// the newest grant's `created_at` under it. The rows built next carry every
/// grant at or before it; a grant that lands after it — a concurrent rekey,
/// say — is newer than the mark and keeps the axis dirty (PR #850 review,
/// round three). `None` when no grant exists yet.
pub async fn watermark_for_axis<B>(
    backend: &B,
    axis: &KeyGrantAxis,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, Error>
where
    B: BlobStorage + Sync,
{
    match axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => backend
            .community_dek_key_grant_watermark(community_key_id, minter_key_id, *epoch)
            .await
            .map_err(map_blob_err),
        KeyGrantAxis::Content { at_rest_sha256, .. } => {
            let sha = sha_of(at_rest_sha256)?;
            backend
                .blob_key_grant_watermark(&sha)
                .await
                .map_err(map_blob_err)
        }
        KeyGrantAxis::Stream {
            stream_id, epoch, ..
        } => backend
            .stream_dek_key_grant_watermark(stream_id, *epoch)
            .await
            .map_err(map_blob_err),
    }
}

/// §14 (V146) — **every axis this node owes an emission on**: each epoch
/// `me` minted whose rows are dirty, then each `invisible_encrypted` blob
/// `me` sealed whose rows are dirty (its owner is the blob row's
/// `community_key_id` — the self identity or the family — or `me` when the
/// row carries none), then each stream epoch `me` sealed. What the boot sweep
/// and `emit_pending_key_grants` iterate — and, after V192, the legacy
/// re-emit.
pub async fn dirty_axes<B>(backend: &B, me: &str) -> Result<Vec<KeyGrantAxis>, Error>
where
    B: BlobStorage + Sync,
{
    let mut out = Vec::new();
    for (community_key_id, epoch) in backend
        .community_dek_list_key_grant_dirty(me)
        .await
        .map_err(map_blob_err)?
    {
        out.push(KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id: me.to_owned(),
            epoch,
        });
    }
    for sha in backend
        .blob_list_key_grant_dirty(me)
        .await
        .map_err(map_blob_err)?
    {
        let Some(prov) = backend.blob_provenance(&sha).await.map_err(map_blob_err)? else {
            continue;
        };
        // v55.0.0 (CIRISEdge v55 adopt) — the axis's owner is the group the
        // row names: the owner (self) or the family the write recorded
        // (V177), the community for a room. A self/family row has no epoch
        // binding, so `community_key_id` is `None` there and the owner fell
        // back to THIS NODE's key: the audience rule withheld every
        // recipient and the ledger cleared with nothing emitted. A row that
        // names no group has no owner this node can name: never the node's
        // own key. It is not planned (nothing could be emitted), stays dirty,
        // and is logged once per `MISBUILT_AXIS_RETRY`.
        let owner = match prov.cohort_scope.as_str() {
            cohort_scope::SELF | cohort_scope::FAMILY => {
                prov.group_key_id.or(prov.community_key_id)
            }
            _ => prov.community_key_id.or(prov.group_key_id),
        };
        let Some(owner) = owner else {
            if throttle_tick(&format!("{me}\u{0}ownerless\u{0}{}", hex::encode(sha))) {
                tracing::error!(
                    at_rest_sha256 = %hex::encode(sha),
                    cohort_scope = %prov.cohort_scope,
                    "a dirty blob names no owner group (no group_key_id, no binding): its \
                     content rows cannot be planned and it stays dirty"
                );
            }
            continue;
        };
        out.push(KeyGrantAxis::Content {
            at_rest_sha256: hex::encode(sha),
            cohort_scope: prov.cohort_scope,
            owner_key_id: owner,
        });
    }
    // v53.0.0 (#969) — each stream epoch `me` sealed whose rows are dirty.
    for d in backend
        .stream_dek_list_key_grant_dirty(me)
        .await
        .map_err(map_blob_err)?
    {
        out.push(KeyGrantAxis::Stream {
            stream_id: d.stream_id,
            epoch: d.epoch,
            cohort_scope: d.cohort_scope,
            owner_key_id: d.group_key_id,
        });
    }
    Ok(out)
}

/// What [`project_key_grant_row`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyGrantProjection {
    /// The wrap is in the grant tables (`written` new rows: 0 on a re-apply).
    Projected {
        /// New grant rows written (a union).
        written: usize,
    },
    /// Content axis: the bytes have not arrived; the row waits in the pending
    /// index for the adopt.
    Pending,
    /// v55.0.0 (Codex r3 on #1065) — content axis: the bytes are held now and
    /// the row's signer does not speak for their author (it was admitted
    /// while the bytes were absent, then the blob arrived before this
    /// projection). Nothing is written: the stored row grants nothing and
    /// occupies no `(at_rest_sha256, recipient)` grant row.
    NotAuthor,
}

/// §13 — **project one admitted key-grant row into this node's grant
/// tables**: the union write for its axis. A content-axis row whose bytes
/// this node does not hold is put in the pending index (V146) and projected
/// by the adopt, and the race with an adopt that lands meanwhile is closed by
/// re-reading the author after the index row is written (PR #850 review).
///
/// Called by the sqlite / postgres hook
/// ([`FederationDirectory::project_key_grant_row`]) after either typed
/// attestation door admitted the row, and by [`admit_replicated_key_grant`].
/// Idempotent.
pub async fn project_key_grant_row<B>(
    backend: &B,
    row: &Attestation,
) -> Result<KeyGrantProjection, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let parsed = KeyGrantRow::from_attestation(row)?;
    let signer = row.attesting_key_id.as_str();
    let wraps = std::slice::from_ref(&parsed.wrap);
    let written = match &parsed.axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => {
            let n = backend
                .community_dek_put_member_grants(community_key_id, minter_key_id, *epoch, wraps)
                .await
                .map_err(map_blob_err)?;
            // v46.0.0 (CIRISPersist#876, `FSD/EPOCH_MINTER.md` §3) — THE
            // REPAIR. This row is proof of who minted `(community, epoch)`.
            // Any blob binding at that community and epoch whose recorded
            // minter holds neither DEK state nor a grant is stranded —
            // written before the key arrived, or under the pre-v46 premise
            // that the row's AUTHOR minted it — and can never authorize
            // anyone. Rebind it here, because nobody re-sends bytes to fix a
            // key column. A binding whose minter does hold state is left
            // exactly as it is.
            let rebound = backend
                .rebind_stranded_blob_epochs(community_key_id, minter_key_id, *epoch)
                .await
                .map_err(map_blob_err)?;
            if rebound > 0 {
                tracing::info!(
                    community = %community_key_id,
                    minter = %minter_key_id,
                    epoch = *epoch,
                    rebound,
                    "key_grant admission rebound stranded blob epoch bindings (#876)"
                );
            }
            n
        }
        KeyGrantAxis::Content {
            at_rest_sha256,
            cohort_scope,
            ..
        } => {
            let sha = sha_of(at_rest_sha256)?;
            let author = backend
                .blob_provenance(&sha)
                .await
                .map_err(map_blob_err)?
                .and_then(|p| p.author_key_id);
            if author.is_none() {
                // V146 — the pending index the adopt takes by (sha, scope).
                backend
                    .key_grant_pending_put(&sha, cohort_scope, &row.attestation_id, signer)
                    .await
                    .map_err(map_blob_err)?;
                // The race double-check (PR #850 review): an adopt that stored
                // the row and took the pending index between the first look
                // and the index write would leave this row unprojected
                // forever. Re-read now that the index row is written.
                let author = backend
                    .blob_provenance(&sha)
                    .await
                    .map_err(map_blob_err)?
                    .and_then(|p| p.author_key_id);
                if author.is_none() {
                    return Ok(KeyGrantProjection::Pending);
                }
                // The bytes arrived meanwhile: hand the row to the adopt's
                // own projection (one body decides the author verdict).
                let n = project_pending_content_grants(
                    backend,
                    &sha,
                    cohort_scope,
                    author.as_deref().unwrap_or_default(),
                )
                .await?;
                return Ok(KeyGrantProjection::Projected { written: n });
            }
            // Codex r3 on #1065 — the blob-arrival race: a row admitted while
            // the bytes were absent passed the admission rule without an
            // author to judge it by. The author is known NOW, so the signer is
            // re-judged against it before any wrap is written, as the pending
            // projection judges it: an unrelated signer must not take the
            // first-write-wins `(at_rest_sha256, recipient)` row ahead of the
            // author's own wrap.
            let author = author.unwrap_or_default();
            if !may_issue_grant_for(
                backend,
                signer,
                &author,
                crate::federation::admission::grant_chain_instant(row),
            )
            .await?
            {
                tracing::warn!(
                    signer,
                    author = %author,
                    at_rest_sha256 = %at_rest_sha256,
                    "content key_grant row projects nothing: its signer does not speak for the \
                     author of the bytes now held (CIRISPersist#1065 r3)"
                );
                return Ok(KeyGrantProjection::NotAuthor);
            }
            backend
                .put_at_rest_grants(&sha, cohort_scope, wraps)
                .await
                .map_err(map_blob_err)?
        }
        KeyGrantAxis::Stream {
            stream_id,
            epoch,
            cohort_scope,
            ..
        } => backend
            .stream_dek_put_grants(stream_id, *epoch, signer, cohort_scope, wraps)
            .await
            .map_err(map_blob_err)?,
    };
    Ok(KeyGrantProjection::Projected { written })
}

/// The sqlite / postgres body of
/// [`FederationDirectory::key_grant_held_owner`]: the held blob's author
/// (content), the recorded owner of the held stream (stream), else `None`.
pub async fn held_owner<B>(backend: &B, axis: &KeyGrantAxis) -> Result<Option<String>, Error>
where
    B: BlobStorage + Sync,
{
    match axis {
        KeyGrantAxis::Epoch { .. } => Ok(None),
        KeyGrantAxis::Content { at_rest_sha256, .. } => Ok(backend
            .blob_provenance(&sha_of(at_rest_sha256)?)
            .await
            .map_err(map_blob_err)?
            .and_then(|p| p.author_key_id)),
        KeyGrantAxis::Stream { stream_id, .. } => Ok(backend
            .stream_key_state(stream_id)
            .await
            .map_err(map_blob_err)?
            .owner_key_id),
    }
}

/// The sqlite / postgres body of [`FederationDirectory::project_key_grant_row`]:
/// [`project_key_grant_row`] for a key-grant row, nothing for any other.
pub async fn project_if_key_grant_row<B>(backend: &B, row: &Attestation) -> Result<(), Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    if is_key_grant_row(row) {
        project_key_grant_row(backend, row).await?;
    }
    Ok(())
}

/// Is `row`'s wrap in this node's grant tables?
async fn wrap_is_projected<B>(backend: &B, row: &KeyGrantRow, signer: &str) -> Result<bool, Error>
where
    B: BlobStorage + Sync,
{
    let r = row.recipient();
    Ok(match &row.axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => backend
            .community_dek_has_member_grant(community_key_id, minter_key_id, *epoch, r)
            .await
            .map_err(map_blob_err)?,
        KeyGrantAxis::Content { at_rest_sha256, .. } => backend
            .get_at_rest_grant(&sha_of(at_rest_sha256)?, r)
            .await
            .map_err(map_blob_err)?
            .is_some(),
        KeyGrantAxis::Stream {
            stream_id, epoch, ..
        } => backend
            .stream_dek_grants(stream_id, *epoch, signer)
            .await
            .map_err(map_blob_err)?
            .iter()
            .any(|g| g.recipient_key_id == r),
    })
}

/// §12–§13 — **admit one replicated key-grant row and project its wrap.**
///
/// 1. The key-grant rule ([`check_key_grant_row_admission`]) answers first,
///    in its own tokens; then the row goes through the attestation plane's
///    own admission
///    ([`apply_replicated_attestation`](FederationDirectory::apply_replicated_attestation)),
///    which runs the hybrid-Strict federation-tier ingest gate against THIS
///    node's directory and asks the same rule again.
///    `Inserted` / `Unchanged` / `Deduplicated` /
///    `Refused { AlreadyPresentIdentical }` proceed; any other refusal is
///    `attestation_refused`.
/// 2. The projection ([`project_key_grant_row`]) — the plane's own hook ran
///    it on insert; it runs again here so a row stored earlier without its
///    wrap (a crash between the two transactions) is repaired by a re-offer.
///    A union, so the second run writes nothing.
pub async fn admit_replicated_key_grant<B>(
    backend: &B,
    signed: SignedKeyGrantRow,
) -> Result<KeyGrantAdmission, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    use crate::federation::attestation_apply::AttestationRefusalReason;

    let row = signed.attestation;
    // The typed refusals first, before the plane: a row that is not a
    // key-grant row is never handed to this door's projection, and the
    // key-grant rule answers in its own tokens whichever plane gate the
    // backend asks first. The plane asks the same rule again (one function).
    let parsed = KeyGrantRow::from_attestation(&row)?;
    check_key_grant_row_admission(backend.as_dyn_directory(), &row).await?;
    let outcome = backend
        .apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await?;
    match &outcome {
        ReplicatedAttestationOutcome::Inserted
        | ReplicatedAttestationOutcome::Unchanged
        | ReplicatedAttestationOutcome::Deduplicated
        | ReplicatedAttestationOutcome::Refused {
            reason: AttestationRefusalReason::AlreadyPresentIdentical,
        } => {}
        ReplicatedAttestationOutcome::Refused { reason } => {
            return Err(refuse(
                KeyGrantRefusalReason::AttestationRefused,
                format!("the attestation plane refused the row: {reason:?}"),
            ));
        }
    }
    let projection = project_key_grant_row(backend, &row).await?;
    let pending = projection == KeyGrantProjection::Pending;
    let projected = !pending && wrap_is_projected(backend, &parsed, &row.attesting_key_id).await?;
    Ok(KeyGrantAdmission {
        recipient_key_id: parsed.wrap.recipient_key_id.clone(),
        axis: parsed.axis,
        attestation: outcome,
        projected,
        pending,
    })
}

/// §13 — **project the content-axis rows that were admitted before their
/// bytes.** Called by the adopt path the moment a blob row exists with its
/// author known: the pending index rows for `(sha, scope)` are listed (V146 —
/// an adopt reads its own rows, never an author's attestations), each is
/// retired only once its verdict is final, and each stored
/// `key_grant:content:v1` row among them *whose signer speaks for
/// `author_key_id`* is projected as a union; a row signed by anyone else
/// grants nothing (the same `signer_not_author` verdict admission gives when
/// the blob is held). Idempotent — `ON CONFLICT DO NOTHING` under it.
/// Returns the wraps written.
pub async fn project_pending_content_grants<B>(
    backend: &B,
    sha256: &[u8; 32],
    cohort_scope: &str,
    author_key_id: &str,
) -> Result<usize, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let want = hex::encode(sha256);
    let mut written = 0usize;
    for (attestation_id, signer) in backend
        .key_grant_pending_list(sha256, cohort_scope)
        .await
        .map_err(map_blob_err)?
    {
        // A definitive non-author verdict retires the row; anything that
        // fails or is not yet resolvable leaves it pending for the next
        // adopt (PR #850 review, round three). v46.3.0 (#884, §4.1): the
        // author's own active occurrence — the node that sealed the bytes —
        // speaks for the author.
        let Some(row) = backend.get_attestation(&attestation_id).await? else {
            continue;
        };
        if !may_issue_grant_for(
            backend,
            &signer,
            author_key_id,
            crate::federation::admission::grant_chain_instant(&row),
        )
        .await?
        {
            backend
                .key_grant_pending_delete(sha256, cohort_scope, &attestation_id)
                .await
                .map_err(map_blob_err)?;
            continue;
        }
        let projectable = KeyGrantRow::from_attestation(&row).ok().filter(|parsed| {
            row.attesting_key_id == signer
                && matches!(&parsed.axis, KeyGrantAxis::Content { at_rest_sha256, cohort_scope: s, .. }
                    if *at_rest_sha256 == want && s == cohort_scope)
                && check_wrap_algorithm(&parsed.wrap).is_ok()
        });
        if let Some(parsed) = projectable {
            written += backend
                .put_at_rest_grants(sha256, cohort_scope, std::slice::from_ref(&parsed.wrap))
                .await
                .map_err(map_blob_err)?;
        }
        // Projected, or a row that can never project (malformed / wrong
        // axis / non-v2): either way the verdict is final.
        backend
            .key_grant_pending_delete(sha256, cohort_scope, &attestation_id)
            .await
            .map_err(map_blob_err)?;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(recipient: &str, cohort_scope: &str, envelope: serde_json::Value) -> Attestation {
        Attestation {
            attestation_id: "id".into(),
            attesting_key_id: "m".into(),
            attested_key_id: recipient.into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "m".into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![],
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope.into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: vec![],
        }
    }

    fn wrap(r: &str) -> GrantWrap {
        GrantWrap {
            recipient_key_id: r.into(),
            wrap_algorithm: "x25519_mlkem768_aes256_gcm_hkdf_sha256".into(),
            wrapped_dek: "{}".into(),
        }
    }

    fn row_of(r: &KeyGrantRow) -> Attestation {
        row(r.recipient(), r.axis.emission_cohort_scope(), r.envelope())
    }

    fn malformed_of(a: &Attestation) -> bool {
        matches!(
            KeyGrantRow::from_attestation(a),
            Err(Error::KeyGrantRefused {
                reason: "malformed",
                ..
            })
        )
    }

    fn axes() -> Vec<KeyGrantAxis> {
        vec![
            KeyGrantAxis::Epoch {
                community_key_id: "c".into(),
                minter_key_id: "m".into(),
                epoch: 3,
            },
            KeyGrantAxis::Content {
                at_rest_sha256: "ab".repeat(32),
                cohort_scope: "self".into(),
                owner_key_id: "m".into(),
            },
            KeyGrantAxis::Content {
                at_rest_sha256: "cd".repeat(32),
                cohort_scope: "family".into(),
                owner_key_id: "fam".into(),
            },
            KeyGrantAxis::Stream {
                stream_id: "s".into(),
                epoch: 2,
                cohort_scope: "community".into(),
                owner_key_id: "c".into(),
            },
        ]
    }

    /// I740 (#989) — a row round-trips through its envelope on every axis,
    /// with persist's member names (CC 3.3.2 cites them), the recipient as
    /// `attested_key_id`, and the CC 2 target on group scopes.
    #[test]
    fn i740_key_grant_row_round_trips_through_its_envelope() {
        for axis in axes() {
            let r = KeyGrantRow {
                axis,
                wrap: wrap("r1"),
            };
            let env = r.envelope();
            assert_eq!(env["dimension"], r.axis.dimension());
            assert_eq!(env["score"], 1.0);
            assert_eq!(env["axis"], r.axis.token());
            assert!(env.get("wraps").is_none() && env.get("kind").is_none());
            let back = KeyGrantRow::from_attestation(&row_of(&r)).unwrap();
            assert_eq!(back, r);
        }
        let fam = KeyGrantRow {
            axis: axes()[2].clone(),
            wrap: wrap("r"),
        };
        assert_eq!(fam.envelope()["family_key_id"], "fam");
        let ep = KeyGrantRow {
            axis: axes()[0].clone(),
            wrap: wrap("r"),
        };
        assert_eq!(ep.envelope()["community_id"], "c");
    }

    /// I741 (#989) — every departure from the shape is `malformed`: a member
    /// on an axis that does not use it, dimension/axis disagreement, a score
    /// other than 1.0, a subject, an expiry, the digest in `evidence_refs`, a
    /// wrong scope, a wrong or missing target. A retired SET type is
    /// `set_retired`.
    #[test]
    fn i741_every_departure_from_the_row_shape_is_refused() {
        let content = KeyGrantRow {
            axis: axes()[1].clone(),
            wrap: wrap("r"),
        };
        // v55.0.0 (#953) — a stream row naming a reserved (SHA-shaped) id.
        let reserved = KeyGrantRow {
            axis: KeyGrantAxis::Stream {
                stream_id: "ab".repeat(32),
                epoch: 0,
                cohort_scope: "community".into(),
                owner_key_id: "c".into(),
            },
            wrap: wrap("r"),
        };
        assert!(malformed_of(&row_of(&reserved)), "a reserved stream id");
        let base = row_of(&content);
        let mut a = base.clone();
        a.attestation_envelope["epoch"] = 1.into();
        assert!(malformed_of(&a), "a foreign axis member");
        let mut a = base.clone();
        a.attestation_envelope["dimension"] = KEY_GRANT_EPOCH_DIMENSION.into();
        assert!(malformed_of(&a), "dimension and axis disagree");
        let mut a = base.clone();
        a.attestation_envelope["score"] = 0.5.into();
        assert!(malformed_of(&a), "score 0.5");
        let mut a = base.clone();
        a.subject_key_ids = vec!["s".into()];
        assert!(malformed_of(&a), "a subject");
        let mut a = base.clone();
        a.expires_at = Some(chrono::Utc::now());
        assert!(malformed_of(&a), "an expiry");
        let mut a = base.clone();
        a.attestation_envelope["evidence_refs"] = serde_json::json!(["ab".repeat(32)]);
        assert!(malformed_of(&a), "the digest cited");
        let mut a = base.clone();
        a.cohort_scope = "community".into();
        assert!(malformed_of(&a), "a content row at community");
        let mut a = base.clone();
        a.attestation_envelope["family_key_id"] = "f".into();
        assert!(malformed_of(&a), "a self row naming a family");
        let fam = row_of(&KeyGrantRow {
            axis: axes()[2].clone(),
            wrap: wrap("r"),
        });
        let mut a = fam.clone();
        a.attestation_envelope["family_key_id"] = "other".into();
        assert!(malformed_of(&a), "a family row naming another family");
        let mut a = fam;
        a.attestation_envelope
            .as_object_mut()
            .unwrap()
            .remove("family_key_id");
        assert!(malformed_of(&a), "a family row naming no family");
        let mut a = base.clone();
        a.attestation_type = KEY_GRANT_CONTENT_DIMENSION.into();
        assert!(matches!(
            KeyGrantRow::from_attestation(&a),
            Err(Error::KeyGrantRefused {
                reason: "set_retired",
                ..
            })
        ));
        let mut a = base;
        a.attested_key_id = String::new();
        assert!(malformed_of(&a), "no recipient");
    }

    /// The refusal tokens are distinct and stable.
    #[test]
    fn refusal_tokens_are_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for r in KeyGrantRefusalReason::ALL {
            assert!(seen.insert(r.as_str()), "{r:?}");
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::Value::String(r.as_str().into())
            );
        }
    }
}
