//! CIRISPersist#848 (`FSD/BLOB_REPLICATION.md` Part II) — **key
//! transport: the key follows the bytes.**
//!
//! v44.2.0 got a sealed blob's BYTES to a member's node (`adopt_sealed_blob`,
//! #846) and not the KEY: the per-epoch wraps and the per-blob grants were
//! written only by the author node's cascade into local tables, and nothing
//! carried them. On every non-author member `read_blob_as` was `NotGranted`,
//! correctly, because the wrap addressed to that occurrence existed only on
//! the author's node.
//!
//! # The carrier is the Constitution's own object
//!
//! CC 3 defines **`key_grant`** — `wrapped_dek` under the recipient's
//! encryption pubkeys, `wrap_algorithm` (v2, mandatory), a supersession
//! lineage — and CC 5.1 names its two addressing axes: **content-addressed**
//! `(content_sha256, recipient)` and **epoch-addressed** `(stream_id, epoch[,
//! recipient])`. Persist invents no dimension; it gives that object a
//! replicated kind, [`EnvelopeKind::KeyGrant`](crate::federation::replication_policy::EnvelopeKind::KeyGrant)
//! — the sixteenth, appended — carrying one **set** per identity:
//!
//! | axis | identity | `wraps[]` | who signs |
//! |---|---|---|---|
//! | epoch (community / affiliations) | `(community_key_id, minter_key_id, epoch)` | every recipient occurrence the minter could wrap to at emission | the MINTER's occurrence key |
//! | content (self / family) | `(at_rest_sha256, cohort_scope, owner_key_id)` | every recipient occurrence of the self-collective / family | the blob's AUTHOR |
//!
//! The set rides the attestation plane as a row whose `attestation_type` is
//! [`KEY_GRANT_EPOCH_ATTESTATION_TYPE`] / [`KEY_GRANT_CONTENT_ATTESTATION_TYPE`]
//! and whose envelope carries the vocabulary ([`KeyGrantSet::envelope_extra`]).
//! It is stored through the normal attestation store, so it is served by the
//! same cursor peers already pull (`list_attestations_since`) and replicates
//! by the plane's projection ([`Plane::KeyGrant`](crate::federation::namespace::Plane::KeyGrant):
//! `SelfOwn` on the content axis, `Cohort` on the epoch axis, never `Global`).
//!
//! # An epoch belongs to its minter (§11)
//!
//! Two members writing at the same epoch number used to mint two random DEKs
//! both labelled E, and the grant table could hold one. The Constitution
//! rules `(community, epoch)` with no lease and no per-delegate fold a FORK
//! (ledger clause 3; CC 5.3.3). So key state, self-retention and grants are
//! keyed `(community, minter, epoch)`; a blob's key identity is
//! `(community, author, epoch)`; the signer rule falls out (M signs M's
//! counter); and every minter rotates its own counter after admitting a
//! removal (§15, [`community_dek::orchestrate::ensure_epoch_dek`](crate::federation::community_dek::orchestrate::ensure_epoch_dek)).
//!
//! # Admission (§12) — the E-edges, CC §0
//!
//! [`admit_replicated_key_grant`]: the signer is resolved from the admitting
//! node's OWN directory (the attestation plane's hybrid-Strict ingest gate,
//! never the sender); on the epoch axis the signer must equal the envelope's
//! `minter_key_id` and be an ACTIVE member occurrence of the community at
//! `asserted_at` per the replicated roster fold; on the content axis the
//! signer must equal the blob row's `author_key_id` when the row is present,
//! and the set is accepted before the row arrives (order independence). A
//! wrap whose algorithm is not v2 is refused. Any other signer is refused.
//!
//! # The projection is a UNION (§13)
//!
//! `Projection::KeyGrants` writes every wrap of the set — `ON CONFLICT DO
//! NOTHING` — so a grant once admitted is never removed by a later set, a
//! re-applied set is a no-op, and a set admitted before its bytes is stored
//! and read when they arrive. CC 3: a publisher "retains existing key_grants
//! (cannot retroactively un-share)". Forward secrecy is by rotation only
//! (I67). The projection consults no keyring: every recipient's wrap is
//! stored, and the read door finds the viewer's row and unwraps it with the
//! private half this node keeps for its own occurrence.
//!
//! # Emission (§14)
//!
//! The minter emits the FULL set for `(C, M, E)` after every mint and every
//! fan-out that granted a new recipient — the full enumeration, never the
//! delta — so a node that dies mid-fan-out re-emits on its next write and
//! every receiver converges by union. The author emits one content-axis set
//! per self/family blob after its cascade.

use crate::federation::attestation_apply::ReplicatedAttestationOutcome;
use crate::federation::envelope::EnvelopeCore;
use crate::federation::types::cohort_scope;
use crate::federation::{
    Attestation, BlobError, BlobStorage, EmitAttestationInput, Error, FederationDirectory,
    GrantWrap, SignedAttestation,
};
use serde::{Deserialize, Serialize};

/// The V145 backfill sentinel: the minter SQL cannot know. Resolved to the
/// node's own derived key at boot; a survivor aborts the boot (§16, I66).
pub const MINTER_SENTINEL: &str = "__this_node__";

/// `attestation_type` prefix every `KeyGrant` row carries — the kind's
/// structural primitive, a sibling of `holds_bytes:`.
pub const KEY_GRANT_ATTESTATION_TYPE_PREFIX: &str = "key_grant:";
/// The epoch-axis row type: `(community, minter, epoch)`.
pub const KEY_GRANT_EPOCH_ATTESTATION_TYPE: &str = "key_grant:epoch:v1";
/// The content-axis row type: `(at_rest_sha256, cohort_scope, owner)`.
pub const KEY_GRANT_CONTENT_ATTESTATION_TYPE: &str = "key_grant:content:v1";
/// The envelope `kind` token.
pub const KEY_GRANT_ENVELOPE_KIND: &str = "key_grant";

/// CC 5.1's two addressing axes for a `key_grant` (§12).
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
    /// Content-addressed: self / family. Signed by the blob's author.
    Content {
        /// Hex of the at-rest content address (SHA-256 of the ciphertext).
        at_rest_sha256: String,
        /// `self` or `family` — the cohort the write named.
        cohort_scope: String,
        /// The owner (self) or family key the blob was sealed for.
        owner_key_id: String,
    },
}

impl KeyGrantAxis {
    /// The attestation type a set on this axis rides under.
    #[must_use]
    pub fn attestation_type(&self) -> &'static str {
        match self {
            KeyGrantAxis::Epoch { .. } => KEY_GRANT_EPOCH_ATTESTATION_TYPE,
            KeyGrantAxis::Content { .. } => KEY_GRANT_CONTENT_ATTESTATION_TYPE,
        }
    }

    /// The `cohort_scope` the row is emitted at: the community scope on the
    /// epoch axis (the plane projects it `Cohort`), the blob's own scope on
    /// the content axis (`SelfOwn`).
    #[must_use]
    pub fn emission_cohort_scope(&self) -> &str {
        match self {
            KeyGrantAxis::Epoch { .. } => cohort_scope::COMMUNITY,
            KeyGrantAxis::Content { cohort_scope, .. } => cohort_scope.as_str(),
        }
    }

    /// The stable axis token (`epoch` / `content`) for the plane registry.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            KeyGrantAxis::Epoch { .. } => "epoch",
            KeyGrantAxis::Content { .. } => "content",
        }
    }
}

/// One `KeyGrant` set: an identity on one axis and every wrap the emitter
/// held for it at emission (§12, §14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGrantSet {
    /// Which identity the wraps belong to.
    #[serde(flatten)]
    pub axis: KeyGrantAxis,
    /// Every recipient's wrap. Never reduced by a later set (§13).
    pub wraps: Vec<GrantWrap>,
}

/// The wire form of one `KeyGrant`: the signed attestation row that carries a
/// [`KeyGrantSet`] in its envelope. Named in the style of
/// [`SignedAttestation`] because on the wire it IS one — the same bytes a
/// peer pulls from `list_attestations_since` — routed to
/// [`admit_replicated_key_grant`] by its `attestation_type`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedKeyGrantSet {
    /// The row: `attestation_type` is one of the two `key_grant:*` types,
    /// the envelope carries the set, `attesting_key_id` / `scrub_key_id` is
    /// the minter (epoch) or the author (content).
    pub attestation: Attestation,
}

/// Why a `KeyGrant` was refused at admission (§12). Stable tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyGrantRefusalReason {
    /// The envelope does not parse as a `key_grant` set, or its
    /// `attestation_type` and `axis` disagree.
    Malformed,
    /// A wrap carries a `wrap_algorithm` other than v2.
    WrapAlgorithmNotV2,
    /// The row's attester and scrub key differ: a set is signed by the party
    /// it speaks for, never scrubbed on their behalf.
    SignerNotSelf,
    /// Epoch axis: the signer is not the envelope's `minter_key_id`.
    SignerNotMinter,
    /// Epoch axis: the signer is not an active member occurrence of the
    /// community at `asserted_at` per this node's roster fold.
    SignerNotActiveMember,
    /// Content axis: the blob row is present and its `author_key_id` is not
    /// the signer.
    SignerNotAuthor,
    /// The attestation plane refused the row (a conflicting row under the
    /// same id, or a lost store race); nothing was projected.
    AttestationRefused,
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
        }
    }
}

/// What [`admit_replicated_key_grant`] did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyGrantAdmission {
    /// The identity the set was for.
    pub axis: KeyGrantAxis,
    /// The attestation plane's outcome for the carrier row.
    pub attestation: ReplicatedAttestationOutcome,
    /// How many wraps the set carried.
    pub wraps_offered: usize,
    /// How many grant rows this admit INSERTED (a union: already-held rows
    /// count zero, so a re-applied set reports 0 here and is still `Ok`).
    pub wraps_written: usize,
    /// Content axis only: the bytes have not arrived, so the author is not
    /// yet known and the set was NOT projected — the carrier row is stored
    /// and [`project_pending_content_grants`] projects it (if the author
    /// signed it) when the adopt names the author (§13).
    pub pending: bool,
}

fn refuse(reason: KeyGrantRefusalReason, detail: impl Into<String>) -> Error {
    Error::KeyGrantRefused {
        reason: reason.as_str(),
        detail: detail.into(),
    }
}

impl KeyGrantSet {
    /// The set's identity as the envelope carries it, beside the CEG
    /// envelope members `stamp_and_canonicalize` adds. `wraps[]` entries are
    /// `{ recipient_occurrence_key_id, wrap_algorithm, wrapped_dek }` — CC 3's
    /// vocabulary, not this crate's column names.
    #[must_use]
    pub fn envelope_extra(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert(
            "kind".into(),
            serde_json::Value::String(KEY_GRANT_ENVELOPE_KIND.into()),
        );
        match &self.axis {
            KeyGrantAxis::Epoch {
                community_key_id,
                minter_key_id,
                epoch,
            } => {
                m.insert("axis".into(), "epoch".into());
                m.insert("community_key_id".into(), community_key_id.as_str().into());
                m.insert("minter_key_id".into(), minter_key_id.as_str().into());
                m.insert("epoch".into(), (*epoch).into());
            }
            KeyGrantAxis::Content {
                at_rest_sha256,
                cohort_scope,
                owner_key_id,
            } => {
                m.insert("axis".into(), "content".into());
                m.insert("at_rest_sha256".into(), at_rest_sha256.as_str().into());
                m.insert("cohort_scope".into(), cohort_scope.as_str().into());
                m.insert("owner_key_id".into(), owner_key_id.as_str().into());
            }
        }
        m.insert(
            "wraps".into(),
            serde_json::Value::Array(
                self.wraps
                    .iter()
                    .map(|w| {
                        serde_json::json!({
                            "recipient_occurrence_key_id": w.recipient_key_id,
                            "wrap_algorithm": w.wrap_algorithm,
                            "wrapped_dek": w.wrapped_dek,
                        })
                    })
                    .collect(),
            ),
        );
        m
    }

    /// Read the set back out of a stored / replicated row. Refuses a row
    /// whose `attestation_type` is not a `key_grant:*` type, whose envelope
    /// is not the `key_grant` kind, or whose `axis` disagrees with the type.
    pub fn from_attestation(row: &Attestation) -> Result<Self, Error> {
        let env = &row.attestation_envelope;
        let field = |name: &str| -> Result<String, Error> {
            env.get(name)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or_else(|| {
                    refuse(
                        KeyGrantRefusalReason::Malformed,
                        format!("key_grant envelope lacks `{name}`"),
                    )
                })
        };
        if field("kind")? != KEY_GRANT_ENVELOPE_KIND {
            return Err(refuse(
                KeyGrantRefusalReason::Malformed,
                "envelope `kind` is not `key_grant`",
            ));
        }
        let axis_token = field("axis")?;
        let axis = match (row.attestation_type.as_str(), axis_token.as_str()) {
            (KEY_GRANT_EPOCH_ATTESTATION_TYPE, "epoch") => KeyGrantAxis::Epoch {
                community_key_id: field("community_key_id")?,
                minter_key_id: field("minter_key_id")?,
                epoch: env.get("epoch").and_then(|v| v.as_u64()).ok_or_else(|| {
                    refuse(
                        KeyGrantRefusalReason::Malformed,
                        "key_grant envelope lacks an unsigned `epoch`",
                    )
                })?,
            },
            (KEY_GRANT_CONTENT_ATTESTATION_TYPE, "content") => {
                let at_rest_sha256 = field("at_rest_sha256")?;
                if hex::decode(&at_rest_sha256).map(|v| v.len()).ok() != Some(32) {
                    return Err(refuse(
                        KeyGrantRefusalReason::Malformed,
                        "key_grant `at_rest_sha256` is not 32 hex bytes",
                    ));
                }
                let scope = field("cohort_scope")?;
                if scope != cohort_scope::SELF && scope != cohort_scope::FAMILY {
                    return Err(refuse(
                        KeyGrantRefusalReason::Malformed,
                        format!("content-axis key_grant at cohort_scope {scope:?}; only self / family carry per-blob grants"),
                    ));
                }
                KeyGrantAxis::Content {
                    at_rest_sha256,
                    cohort_scope: scope,
                    owner_key_id: field("owner_key_id")?,
                }
            }
            (t, a) => {
                return Err(refuse(
                    KeyGrantRefusalReason::Malformed,
                    format!(
                    "attestation_type {t:?} and envelope axis {a:?} do not name one key_grant axis"
                ),
                ))
            }
        };
        let wraps = env
            .get("wraps")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                refuse(
                    KeyGrantRefusalReason::Malformed,
                    "key_grant envelope lacks `wraps[]`",
                )
            })?
            .iter()
            .map(|w| {
                let s = |name: &str| -> Result<String, Error> {
                    w.get(name)
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            refuse(
                                KeyGrantRefusalReason::Malformed,
                                format!("key_grant wrap lacks `{name}`"),
                            )
                        })
                };
                Ok(GrantWrap {
                    recipient_key_id: s("recipient_occurrence_key_id")?,
                    wrap_algorithm: s("wrap_algorithm")?,
                    wrapped_dek: s("wrapped_dek")?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(KeyGrantSet { axis, wraps })
    }

    /// The emit input for this set: the row type, the envelope, the scope.
    /// `stamp_and_canonicalize` adds the signed instants and the row mirror.
    #[must_use]
    pub fn emit_input(&self) -> EmitAttestationInput {
        let envelope = EnvelopeCore {
            extra: self.envelope_extra(),
            ..EnvelopeCore::default()
        };
        EmitAttestationInput::with_envelope(
            self.axis.attestation_type(),
            envelope,
            self.axis.emission_cohort_scope(),
        )
    }
}

fn map_blob_err(e: BlobError) -> Error {
    Error::Backend(format!("key_grant: {e}"))
}

/// §14 — what an emission attempt means for the caller. A community that
/// has lost (or never had) a live steward-bound moderator MAY NOT federate
/// at moderated capability (CC 4.5.4 / §11.11), and the attestation plane
/// refuses every federation-tier row keyed on it — on this node and on every
/// peer. A `KeyGrant` for such a community therefore has nowhere to go: no
/// peer could be party to its bytes, and the local write is still whole
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
                "key_grant set not emitted: the community has no live moderator and may not \
                 federate at moderated capability (CC 4.5.4); nothing outside this node can be \
                 party to its content until one is appointed"
            );
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// §14 — the FULL epoch-axis set for `(community, minter, epoch)` as this
/// node holds it, or `None` if it holds no wrap for it (nothing to emit).
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

/// §14 — the FULL content-axis set for one self/family blob: every at-rest
/// grant except persist's own self-retention row, or `None` if there is
/// nothing a peer could use.
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

/// §14 — emit the full epoch-axis set for `(community, M, epoch)` where M
/// is `signer`'s derived key, through the normal attestation store (so it
/// replicates). `Ok(None)` when this node holds no wrap for the epoch.
///
/// The backend-generic emitter, for the cascade paths and the two-node
/// witnesses; the Engine's composed-signer form is
/// [`Engine::emit_epoch_key_grant`](crate::engine::Engine::emit_epoch_key_grant).
pub async fn emit_epoch_key_grant_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    community_key_id: &str,
    epoch: u64,
) -> Result<Option<crate::federation::attestation_emit::EmittedAttestation>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let minter = signer.derived_key_id();
    let wm_axis = KeyGrantAxis::Epoch {
        community_key_id: community_key_id.to_owned(),
        minter_key_id: minter.clone(),
        epoch,
    };
    let watermark = watermark_for_axis(backend, &wm_axis).await?;
    let Some(set) = build_epoch_set(backend, community_key_id, &minter, epoch)
        .await
        .map_err(map_blob_err)?
    else {
        return Ok(None);
    };
    let emitted = emission_outcome(
        crate::federation::attestation_emit::emit_with_local_signer(
            backend,
            signer,
            set.emit_input(),
        )
        .await,
    )?;
    if let (Some(_), Some(watermark)) = (&emitted, watermark) {
        mark_emitted(backend, &set.axis, watermark).await?;
    }
    Ok(emitted)
}

/// §14 — emit the full content-axis set for one self/family blob authored
/// by `signer`. `Ok(None)` when the blob has no recipient grant.
pub async fn emit_content_key_grant_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    at_rest_sha256: &[u8; 32],
    scope: &str,
    owner_key_id: &str,
) -> Result<Option<crate::federation::attestation_emit::EmittedAttestation>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let wm_axis = KeyGrantAxis::Content {
        at_rest_sha256: hex::encode(at_rest_sha256),
        cohort_scope: scope.to_owned(),
        owner_key_id: owner_key_id.to_owned(),
    };
    let watermark = watermark_for_axis(backend, &wm_axis).await?;
    let Some(set) = build_content_set(backend, at_rest_sha256, scope, owner_key_id)
        .await
        .map_err(map_blob_err)?
    else {
        return Ok(None);
    };
    let emitted = emission_outcome(
        crate::federation::attestation_emit::emit_with_local_signer(
            backend,
            signer,
            set.emit_input(),
        )
        .await,
    )?;
    if let (Some(_), Some(watermark)) = (&emitted, watermark) {
        mark_emitted(backend, &set.axis, watermark).await?;
    }
    Ok(emitted)
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
    let asserted_at = chrono::Utc::now();
    let envelope = serde_json::json!({
        "attesting_key_id": me,
        "identity_key_id": identity_key_id,
        "occurrence_key_id": me,
        "device_class": device_class,
        "encryption_pubkeys": {
            "x25519_base64": enc.x25519_base64,
            "ml_kem_768_base64": enc.ml_kem_768_base64,
        },
        "asserted_at": asserted_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "valid_until": serde_json::Value::Null,
        "hardware_attestation": serde_json::Value::Null,
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
            occurrence_key_id: me.clone(),
            device_class: device_class.to_owned(),
            hardware_attestation: None,
            asserted_at,
            valid_until: None,
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
/// emitted** with the database's own clock. Called by every emitter on a
/// successful (`Some`) emission — the Engine's composed-signer door and the
/// local-signer emitters alike — so the ledger never depends on which door
/// carried the set.
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
            let sha: [u8; 32] = hex::decode(at_rest_sha256)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| refuse(KeyGrantRefusalReason::Malformed, "at_rest_sha256"))?;
            backend
                .blob_mark_key_grant_emitted(&sha, watermark)
                .await
                .map_err(map_blob_err)
        }
    }
}

/// §14 (V146) — **the grant watermark for an axis, read BEFORE the set is
/// built**: the newest grant's `created_at` under it. The set built next
/// carries every grant at or before it; a grant that lands after it — a
/// concurrent rekey, say — is newer than the mark and keeps the axis dirty
/// (PR #850 review, round three). `None` when no grant exists yet.
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
            let sha: [u8; 32] = hex::decode(at_rest_sha256)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| refuse(KeyGrantRefusalReason::Malformed, "at_rest_sha256"))?;
            backend
                .blob_key_grant_watermark(&sha)
                .await
                .map_err(map_blob_err)
        }
    }
}

/// §14 (V146) — **every axis this node owes an emission on**: each epoch
/// `me` minted whose set is dirty, then each `invisible_encrypted` blob `me`
/// authored whose set is dirty (its owner is the blob row's
/// `community_key_id` — the self identity or the family — or `me` when the
/// row carries none). What the boot sweep and `emit_pending_key_grants`
/// iterate.
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
        out.push(KeyGrantAxis::Content {
            at_rest_sha256: hex::encode(sha),
            cohort_scope: prov.cohort_scope,
            owner_key_id: prov.community_key_id.unwrap_or_else(|| me.to_owned()),
        });
    }
    Ok(out)
}

/// §14 — the full set for an emission axis a write door reported
/// (`PutBlobScopedResult::key_grant_emission` and its chunk twins), or
/// `None` if this node holds nothing to emit for it.
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
    }
}

/// §14 — emit the set a write door reported, signed by `signer` through the
/// attestation store. The PyO3 door's emitter (its hybrid signer is the
/// `LocalSigner`); the Engine's is
/// [`Engine::emit_key_grant`](crate::engine::Engine::emit_key_grant).
pub async fn emit_key_grant_axis_with_local_signer<B>(
    backend: &B,
    signer: &crate::signing::LocalSigner,
    axis: &KeyGrantAxis,
) -> Result<Option<crate::federation::attestation_emit::EmittedAttestation>, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let wm_axis = axis.clone();
    let watermark = watermark_for_axis(backend, &wm_axis).await?;
    let Some(set) = build_set_for_axis(backend, axis)
        .await
        .map_err(map_blob_err)?
    else {
        return Ok(None);
    };
    let emitted = emission_outcome(
        crate::federation::attestation_emit::emit_with_local_signer(
            backend,
            signer,
            set.emit_input(),
        )
        .await,
    )?;
    if let (Some(_), Some(watermark)) = (&emitted, watermark) {
        mark_emitted(backend, &set.axis, watermark).await?;
    }
    Ok(emitted)
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
async fn is_active_member_at<D>(
    directory: &D,
    community_key_id: &str,
    signer: &str,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + Sync,
{
    let Some(community) = directory.lookup_community(community_key_id).await? else {
        return Ok(false);
    };
    // The principal (§20.1, PR #852 review round two):
    // - a signer with a KNOWN-BUT-REVOKED occurrence at `as_of` is dead,
    //   whatever its owner binding says — the revocation gate strips a lost
    //   or compromised device's inherited authority;
    // - a NODE-role key (the role is on the Key-plane record the mesh already
    //   carries) lifts ONLY through its live owner binding, never through the
    //   occurrence row a prior admission left — withdrawing the binding
    //   removes the node's authority the moment it dies;
    // - a device occurrence lifts to its identity as before.
    // EVERY row bound under the signer's key, whatever identity each names
    // (the table's key is (identity, occurrence); a moved ownership leaves a
    // stale row): a revocation effective at `as_of` on ANY of them is final
    // (PR #852 review, round three).
    for o in directory
        .list_identity_occurrences_by_occurrence_key(signer)
        .await?
    {
        let revs = directory
            .list_identity_occurrence_revocations_for(&o.identity_key_id)
            .await?;
        if revs.iter().any(|r| r.revokes(&o, as_of)) {
            return Ok(false);
        }
    }
    let is_node = directory.lookup_public_key(signer).await?.is_some_and(|k| {
        k.identity_type == crate::federation::types::identity_type::NODE
            || k.claims_role(crate::federation::types::identity_type::NODE)
    });
    let principal = if is_node {
        match crate::federation::admission::owner_of(directory, signer).await? {
            Some(owner) => owner,
            None => return Ok(false),
        }
    } else {
        crate::federation::admission::admission_identity_for_writer(directory, signer).await?
    };
    let revs = directory
        .list_community_membership_revocations_for(community_key_id)
        .await?;
    let removed = crate::federation::removed_key_ids_at(
        revs.iter()
            .map(|r| (r.removed_identity_key_id.as_str(), r.effective_at)),
        as_of,
    );
    for member in &community.members {
        if removed.contains(member.key_id.as_str()) {
            continue;
        }
        if member.key_id == signer || member.key_id == principal {
            return Ok(true);
        }
        // Folded at `as_of`, not at the wall clock: a set emitted while its
        // minter occurrence was active, delivered after that occurrence was
        // revoked, is a valid historical set (CIRISPersist#850 review).
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

/// §12–§13 — **admit a replicated `KeyGrant` set and project every wrap.**
///
/// 1. Parse the set off the row ([`KeyGrantSet::from_attestation`]); refuse
///    any wrap not at v2.
/// 2. The signer of record is the row's `scrub_key_id`, and it must equal
///    `attesting_key_id`: a set speaks for exactly the party that signed it.
/// 3. Epoch axis: signer == `minter_key_id`, and an active member occurrence
///    of the community at `asserted_at` per the roster fold (occurrence
///    revocations folded at `asserted_at` too; the attestation plane's
///    cohort gate is the backstop at now — `asserted_at` is signer-chosen).
///    Content axis: signer == the blob row's `author_key_id` when the row is
///    present; when it is absent the set is **pending** — the carrier row is
///    admitted and nothing is projected until the adopt names the author
///    ([`project_pending_content_grants`]; PR #850 review).
/// 4. The attestation plane admits the carrier row —
///    [`apply_replicated_attestation`](FederationDirectory::apply_replicated_attestation),
///    which runs the hybrid-Strict federation-tier ingest gate against THIS
///    node's directory (`SignerSource::RegisteredSigner`) and every other
///    `put_attestation` gate. `Inserted` / `Unchanged` /
///    `Refused { AlreadyPresentIdentical }` proceed — the last two are a
///    re-emission, which must still project (a row stored earlier through
///    the generic attestation door carries grants nobody wrote yet).
///    `ConflictingAttestation` / `StoreConflict` refuse.
/// 5. The projection: every wrap, one transaction, a union.
///
/// Steps 4 and 5 are two transactions. A crash between them leaves a stored
/// row and no grants, which the next re-emission repairs (the same set,
/// re-applied, projects on `Unchanged`). That is the shape the FSD's "in the
/// admit transaction" is satisfied by here: the row's admission and the
/// grants' projection are ordered, idempotent, and never leave a grant
/// without its admitted row.
pub async fn admit_replicated_key_grant<B>(
    backend: &B,
    set: SignedKeyGrantSet,
) -> Result<KeyGrantAdmission, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    use crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2;
    use crate::federation::attestation_apply::AttestationRefusalReason;

    let row = &set.attestation;
    let parsed = KeyGrantSet::from_attestation(row)?;
    if let Some(bad) = parsed
        .wraps
        .iter()
        .find(|w| w.wrap_algorithm != WRAP_ALGORITHM_V2)
    {
        return Err(refuse(
            KeyGrantRefusalReason::WrapAlgorithmNotV2,
            format!(
                "wrap for {:?} carries wrap_algorithm {:?}; only {WRAP_ALGORITHM_V2:?} is admissible \
                 (CC 4.4.3.4.1 / CC 5.2)",
                bad.recipient_key_id, bad.wrap_algorithm
            ),
        ));
    }
    // The signer of record is the scrub key — the one the plane's ingest
    // gate verifies against OUR directory. A set is self-spoken.
    let signer = row.scrub_key_id.as_str();
    let mut pending = false;
    let mut retire_after_projection: Option<([u8; 32], String)> = None;
    if signer.is_empty() || signer != row.attesting_key_id {
        return Err(refuse(
            KeyGrantRefusalReason::SignerNotSelf,
            format!(
                "attesting_key_id {:?} != scrub_key_id {:?}; a key_grant set is signed by the party \
                 it speaks for",
                row.attesting_key_id, row.scrub_key_id
            ),
        ));
    }
    match &parsed.axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            ..
        } => {
            if signer != minter_key_id {
                return Err(refuse(
                    KeyGrantRefusalReason::SignerNotMinter,
                    format!(
                        "signer {signer:?} is not the set's minter {minter_key_id:?}; only M signs \
                         M's counter (BLOB_REPLICATION.md §11)"
                    ),
                ));
            }
            if !is_active_member_at(backend, community_key_id, signer, row.asserted_at).await? {
                return Err(refuse(
                    KeyGrantRefusalReason::SignerNotActiveMember,
                    format!(
                        "signer {signer:?} is not an active member occurrence of community \
                         {community_key_id:?} at {} per this node's roster fold",
                        row.asserted_at.to_rfc3339()
                    ),
                ));
            }
        }
        KeyGrantAxis::Content { at_rest_sha256, .. } => {
            let sha: [u8; 32] = hex::decode(at_rest_sha256)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| refuse(KeyGrantRefusalReason::Malformed, "at_rest_sha256"))?;
            match backend
                .blob_provenance(&sha)
                .await
                .map_err(map_blob_err)?
                .and_then(|p| p.author_key_id)
            {
                Some(author) if author != signer => {
                    return Err(refuse(
                        KeyGrantRefusalReason::SignerNotAuthor,
                        format!(
                            "signer {signer:?} is not the author {author:?} of blob \
                             {at_rest_sha256}"
                        ),
                    ));
                }
                Some(_) => {}
                // The bytes have not arrived: the author is not yet known
                // to this node, so the signer cannot be checked against it.
                // The carrier row is admitted (it is a signed attestation
                // like any other) and NOTHING is projected — a recipient who
                // knows the DEK must not be able to grant an outsider by
                // speaking first. `project_pending_content_grants` projects
                // the sets the AUTHOR signed once the adopt names the author
                // (order independence, kept; CIRISPersist#850 review).
                None => pending = true,
            }
        }
    }

    // The carrier row, through the attestation plane's own admission.
    let row_id = set.attestation.attestation_id.clone();
    let signer = signer.to_owned();
    let signer = signer.as_str();
    let outcome = backend
        .apply_replicated_attestation(SignedAttestation {
            attestation: set.attestation,
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
                format!("the attestation plane refused the carrier row: {reason:?}"),
            ));
        }
    }

    if pending {
        let KeyGrantAxis::Content {
            at_rest_sha256,
            cohort_scope,
            ..
        } = &parsed.axis
        else {
            unreachable!("pending is a content-axis verdict");
        };
        let sha: [u8; 32] = hex::decode(at_rest_sha256)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| refuse(KeyGrantRefusalReason::Malformed, "at_rest_sha256"))?;
        // V146 — the pending index the adopt takes by (sha, scope).
        backend
            .key_grant_pending_put(&sha, cohort_scope, &row_id, signer)
            .await
            .map_err(map_blob_err)?;
        // The race double-check (PR #850 review): an adopt that stored the
        // row and took the pending index between our first look and the
        // carrier's insert would otherwise leave this set unprojected
        // forever. Re-read now that the carrier is stored — every
        // interleaving is covered: if the adopt's row landed before this
        // read we project here; if after, the adopt's take sees our index
        // row (written before this read).
        match backend
            .blob_provenance(&sha)
            .await
            .map_err(map_blob_err)?
            .and_then(|p| p.author_key_id)
        {
            None => {
                return Ok(KeyGrantAdmission {
                    wraps_offered: parsed.wraps.len(),
                    axis: parsed.axis,
                    attestation: outcome,
                    wraps_written: 0,
                    pending: true,
                });
            }
            Some(author) if author != signer => {
                // The author is known now and it is not the signer: the
                // carrier stays a stored attestation, its index row is
                // dropped, nothing projects.
                backend
                    .key_grant_pending_delete(&sha, cohort_scope, &row_id)
                    .await
                    .map_err(map_blob_err)?;
                return Err(refuse(
                    KeyGrantRefusalReason::SignerNotAuthor,
                    format!(
                        "signer {signer:?} is not the author {author:?} of blob {at_rest_sha256}"
                    ),
                ));
            }
            Some(_) => {
                // The bytes arrived meanwhile: project directly (below) and
                // retire this set's index row only AFTER the union write
                // succeeds (PR #850, round four) — the adopt may also project
                // it; both paths are unions.
                retire_after_projection = Some((sha, cohort_scope.clone()));
            }
        }
    }
    // The projection: every wrap, a union.
    let wraps_written = match &parsed.axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => backend
            .community_dek_put_member_grants(community_key_id, minter_key_id, *epoch, &parsed.wraps)
            .await
            .map_err(map_blob_err)?,
        KeyGrantAxis::Content {
            at_rest_sha256,
            cohort_scope,
            ..
        } => {
            let sha: [u8; 32] = hex::decode(at_rest_sha256)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| refuse(KeyGrantRefusalReason::Malformed, "at_rest_sha256"))?;
            backend
                .put_at_rest_grants(&sha, cohort_scope, &parsed.wraps)
                .await
                .map_err(map_blob_err)?
        }
    };
    if let Some((sha, scope)) = retire_after_projection {
        backend
            .key_grant_pending_delete(&sha, &scope, &row_id)
            .await
            .map_err(map_blob_err)?;
    }
    Ok(KeyGrantAdmission {
        wraps_offered: parsed.wraps.len(),
        axis: parsed.axis,
        attestation: outcome,
        wraps_written,
        pending: false,
    })
}

/// §13 — **project the content-axis sets that were admitted before their
/// bytes.** Called by the adopt path the moment a blob row exists with its
/// author known: the pending index rows for `(sha, scope)` are listed (V146
/// — an adopt reads its own rows, never an author's attestations), each is
/// retired only once its verdict is final, and each stored `key_grant:content:v1` row among them
/// *signed by `author_key_id`* is projected as a union; a row signed by
/// anyone else grants nothing (the same `SignerNotAuthor` verdict
/// [`admit_replicated_key_grant`] gives when the row is present).
/// Idempotent — `ON CONFLICT DO NOTHING` under it. Returns the wraps
/// written.
pub async fn project_pending_content_grants<B>(
    backend: &B,
    sha256: &[u8; 32],
    cohort_scope: &str,
    author_key_id: &str,
) -> Result<usize, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    use crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2;
    let want = hex::encode(sha256);
    let mut written = 0usize;
    for (attestation_id, signer) in backend
        .key_grant_pending_list(sha256, cohort_scope)
        .await
        .map_err(map_blob_err)?
    {
        // A definitive non-author verdict retires the row; anything that
        // fails or is not yet resolvable leaves it pending for the next
        // adopt (PR #850 review, round three).
        if signer != author_key_id {
            backend
                .key_grant_pending_delete(sha256, cohort_scope, &attestation_id)
                .await
                .map_err(map_blob_err)?;
            continue;
        }
        let Some(row) = backend.get_attestation(&attestation_id).await? else {
            continue;
        };
        let projectable = row.attestation_type == KEY_GRANT_CONTENT_ATTESTATION_TYPE
            && row.scrub_key_id == author_key_id
            && KeyGrantSet::from_attestation(&row).ok().is_some_and(|parsed| {
                matches!(&parsed.axis, KeyGrantAxis::Content { at_rest_sha256, cohort_scope: set_scope, .. }
                    if *at_rest_sha256 == want && set_scope == cohort_scope)
                    && parsed.wraps.iter().all(|w| w.wrap_algorithm == WRAP_ALGORITHM_V2)
            });
        if projectable {
            let parsed = KeyGrantSet::from_attestation(&row)?;
            written += backend
                .put_at_rest_grants(sha256, cohort_scope, &parsed.wraps)
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

    fn row(attestation_type: &str, envelope: serde_json::Value) -> Attestation {
        Attestation {
            attestation_id: "id".into(),
            attesting_key_id: "m".into(),
            attested_key_id: "m".into(),
            attestation_type: attestation_type.into(),
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
            cohort_scope: "community".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: vec![],
        }
    }

    /// The envelope round-trips on both axes, byte for byte through the
    /// CC 3 vocabulary (`recipient_occurrence_key_id`, not a column name).
    #[test]
    fn key_grant_set_round_trips_through_its_envelope() {
        for set in [
            KeyGrantSet {
                axis: KeyGrantAxis::Epoch {
                    community_key_id: "c".into(),
                    minter_key_id: "m".into(),
                    epoch: 3,
                },
                wraps: vec![GrantWrap {
                    recipient_key_id: "r1".into(),
                    wrap_algorithm: "x25519_mlkem768_aes256_gcm_hkdf_sha256".into(),
                    wrapped_dek: "{}".into(),
                }],
            },
            KeyGrantSet {
                axis: KeyGrantAxis::Content {
                    at_rest_sha256: "ab".repeat(32),
                    cohort_scope: "self".into(),
                    owner_key_id: "m".into(),
                },
                wraps: vec![],
            },
        ] {
            let env = serde_json::Value::Object(set.envelope_extra());
            assert_eq!(env["wraps"].as_array().map(Vec::len), Some(set.wraps.len()));
            if let Some(w) = env["wraps"].as_array().and_then(|a| a.first()) {
                assert!(w.get("recipient_occurrence_key_id").is_some());
            }
            let back =
                KeyGrantSet::from_attestation(&row(set.axis.attestation_type(), env)).unwrap();
            assert_eq!(back, set);
        }
    }

    /// A type/axis disagreement is `malformed`, not a parse of whichever
    /// half looked right.
    #[test]
    fn key_grant_type_and_axis_must_agree() {
        let set = KeyGrantSet {
            axis: KeyGrantAxis::Epoch {
                community_key_id: "c".into(),
                minter_key_id: "m".into(),
                epoch: 1,
            },
            wraps: vec![],
        };
        let err = KeyGrantSet::from_attestation(&row(
            KEY_GRANT_CONTENT_ATTESTATION_TYPE,
            serde_json::Value::Object(set.envelope_extra()),
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            Error::KeyGrantRefused {
                reason: "malformed",
                ..
            }
        ));
    }
}
