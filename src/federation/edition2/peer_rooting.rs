//! v62.0.0 (PR-fix1; CC 3.2 T8, CC 5.3.4) — **is this peer Rooted for this
//! reader?** The edition-2 replacement for v61's `root_binding`, whose
//! scrub-pair walk could never confirm an edition-2 key (removed in BH-fix1
//! with `RootingVerdict` and `ProvenanceChain`).
//!
//! # The rule (CC rc21 3.2 T1–T8)
//!
//! T8 states the standing verdict once, as `V(rows, t)`: "a live conferral
//! chain runs from the self-root the evaluating node inherits (T1) through
//! its owner's `trust:accepts:v1` edge (T3) to a root", whose charter carries
//! a pre-rotation commitment and the `infra:serve` + `infra:attest` scopes,
//! whose lineage has a current head (T6), and whose active founder set is
//! live (T7). For a PEER that is read as: the peer's key is Rooted FOR THIS
//! READER iff
//!
//! 1. the peer holds a live conferral under some root `R` on one of T2's two
//!    planes — the **ceremony** plane (a holder or a serve seat of the
//!    genesis bundle in force: the accord's count, CC 4.2.1) or the
//!    **delegation** plane (a live `trust:confers:v1` grant `delegates_to(R →
//!    peer)` bearing `infra:serve`); and
//! 2. `R` passes the READER's own chain (T3): the reader's owner's live
//!    `trust:accepts:v1` edge to `R` (the reader's own edge while its owner
//!    has signed none), `R`'s live labelled self-charter, and `R`'s chain
//!    verdict (the stored chain from an accord birth, its witnessed head).
//!    For the ceremony plane `R` is a root the reader accepts whose chain is
//!    accord-born (the shipped default is `ciris-canonical`, whose founders
//!    are the accord holders, CC 4.4.3.34).
//!
//! Then T7's margin over `R`'s founders splits `Rooted` from `Stalled`
//! ("every leg of Rooted holds except the margin: valid and non-admitting").
//!
//! What is NEVER a leg (T4, T8): drill staleness, the 90-day heartbeat, the
//! halt latch, holder custody (an admission gate at the seating row). `V`
//! takes rows only and is evaluated at a signer-stamped instant — `at_ms`
//! here — never the reader's clock. A row not held WAITS (CC 2.7.3):
//! [`PeerRooting::CannotTellYet`], never `NotRooted`.
//!
//! # What crosses before Rooted (CC 5.3.4)
//!
//! A `NotRooted` peer is not dropped: the bootstrap kinds, the allegiance
//! facts, the pairing plane, rows addressed to the peer and a bounded
//! cohort's deliveries to it as a member all still cross. Only what the node
//! serves to a third party — a federation-tier row, a self-authored row about
//! someone other than the peer — waits for `Rooted`.
//!
//! # One machine
//!
//! Nothing here re-derives a leg. It composes:
//! - the genesis in force ([`super::genesis::genesis_in_force`]: `is_holder`,
//!   `is_canonical`);
//! - key liveness ([`super::ingest::held_keys_for_kid`] →
//!   [`HeldKeys::liveness`](super::liveness::HeldKeys::liveness));
//! - the live conferral rows (`trust_root::live_conferral_rows`, the body
//!   the capability walk reads): the root's counted grants (the ceremony
//!   plane, R2-planes) and any other grant (the delegation plane);
//! - the reader's accepted roots and T3 legs (`trust_root::accepted_roots_of`,
//!   `trust_root::chain_legs_of`, the body `own_chain_to` reads);
//! - the trust root's read verdict for that reader
//!   (`canonical_community::reader_standing`, the body `stored_standing_at`
//!   reads);
//! - T7's margin, inside that read verdict (`compute_standing`: Rooted iff
//!   the active founders reach M + 1, TR-fix1).
//!
//! v62.0.0 (R2-rooms; CC 3.2 T5) — the room-chain pieces above (the T3 legs,
//! `reader_standing`, `compute_standing`'s margin) are no longer read: the
//! one root is the bundle's lineage (`trust_root::bundle_root_accepted`, T7's
//! margin over the holders in force); with a bundle in force any other id is
//! `root_chain_not_rooted`, and with none it waits.

use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::edition2::{identity_ref, Digest32, MissingKey};
use serde::{Deserialize, Serialize};

use super::liveness::Liveness;
use crate::federation::canonical_community;
use crate::federation::trust_root::{self, ChainLegs, CharterLeg};
use crate::federation::{Error, FederationDirectory};

/// The key a peer claims to speak with: what the reader holds for it. Every
/// form is compared against the peer's LIVE `key:record` at `at_ms` (agreed
/// with Edge, 2026-11-20). A comparison is an identity MATCH, never a
/// signature verify.
#[derive(Debug, Clone, Copy)]
pub enum ClaimedKey<'a> {
    /// The composite ML-DSA-65 + Ed25519 public key: compared byte for byte
    /// with the record's key.
    Composite(&'a CompositePublicKey),
    /// The key's thumbprint (its COSE `kid`): compared with the record's kid.
    Kid(Digest32),
    /// **Transitional** (Edge on v62.0 holds only the key id and the Ed25519
    /// half at announce time, and carries the composite from v62.1): the
    /// Ed25519 half, compared with the record key's Ed25519 half
    /// (`edition2::composite::ed25519_public`). An identity match, not a lone
    /// verify (no signature is checked against it). Retire it once Edge
    /// carries the composite.
    Ed25519Half([u8; 32]),
}

// Verify 23.3.2's `CompositePublicKey` is not `PartialEq`: a claimed key is
// equal when its form and its bytes are (the composite by `as_bytes`).
impl PartialEq for ClaimedKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Composite(a), Self::Composite(b)) => a.as_bytes() == b.as_bytes(),
            (Self::Kid(a), Self::Kid(b)) => a == b,
            (Self::Ed25519Half(a), Self::Ed25519Half(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for ClaimedKey<'_> {}

/// [`ClaimedKey`] as it crosses a wire (the capsule op, the Python verb): the
/// composite's bytes owned. [`Self::as_claim`] parses them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "form", content = "bytes", rename_all = "snake_case")]
pub enum ClaimedKeyWire {
    /// [`ClaimedKey::Composite`]: `CompositePublicKey::as_bytes`.
    Composite(Vec<u8>),
    /// [`ClaimedKey::Kid`].
    Kid(Digest32),
    /// [`ClaimedKey::Ed25519Half`] (transitional).
    Ed25519Half([u8; 32]),
}

/// A wire claim whose composite bytes are no composite public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotACompositeKey;

impl ClaimedKeyWire {
    /// The parsed composite, when this is one.
    ///
    /// # Errors
    /// The bytes are no composite public key.
    pub fn composite(&self) -> Result<Option<CompositePublicKey>, NotACompositeKey> {
        match self {
            Self::Composite(b) => CompositePublicKey::from_bytes(b)
                .map(Some)
                .map_err(|_| NotACompositeKey),
            Self::Kid(_) | Self::Ed25519Half(_) => Ok(None),
        }
    }

    /// The claim, borrowing `parsed` ([`Self::composite`]'s answer) for the
    /// composite form.
    #[must_use]
    pub fn as_claim<'a>(&self, parsed: Option<&'a CompositePublicKey>) -> Option<ClaimedKey<'a>> {
        match self {
            Self::Composite(_) => parsed.map(ClaimedKey::Composite),
            Self::Kid(k) => Some(ClaimedKey::Kid(*k)),
            Self::Ed25519Half(h) => Some(ClaimedKey::Ed25519Half(*h)),
        }
    }
}

/// Which of CC 3.2 T2's two planes carried the peer's conferral.
///
/// v62.0.0 (R2-planes; Constitution 11-24 "CONSTITUTION RULED THE DELEGATION
/// ARM": peer rooting "has them backwards and is aligned") — named by the
/// count, never by a granter-declared field, as `trust_root::ConferralPlane`
/// is: a seat the BUNDLE gives (a holder, a serve seat) and the ROOT's
/// counted grant are both `Ceremony` (rows counted over the holders, naming
/// the bundle); `Delegation` is a grant whose legitimacy is NOT a count over
/// the holders. Before, a counted root grant read as `Delegation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plane {
    /// A row counted over the holders of the bundle in force, naming it: the
    /// bundle itself (its holders, its serve seats) or the root's counted
    /// grant (`admission::root_grant_of`).
    Ceremony,
    /// A live chain of `delegates_to` edges bearing the scope from a
    /// grantee of a counted grant, resolved at use (CC 3.2 T2;
    /// `trust_root::delegation_conferral`, R2-delegation-b): rooted as a
    /// counted seat is.
    Delegation,
}

/// What seats the peer under the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootedVia {
    /// A holder of the genesis bundle in force (the accord, CC 4.2.1).
    AccordHolder,
    /// A serve seat (`serve_nodes`) of the genesis bundle in force.
    ServeSeat,
    /// A live `trust:confers:v1` grant of `infra:serve` from the root.
    ConferredSeat,
}

/// The peer's live `key:record` at `at_ms`, as a wire-safe summary of
/// Verify's `edition2::keys::KeyRecord`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKeyRecord {
    /// The identity-ref of the recorded key (its kid).
    pub key_identity_ref: String,
    /// The composite public key, lowercase hex.
    pub key_hex: String,
    /// The record's `identity_type` (the key's statement about itself).
    pub identity_type: Vec<String>,
    /// The record's `asserted_at` (POSIX ms).
    pub asserted_at_ms: u64,
    /// The record's `valid_until` (POSIX ms), if it ends.
    pub valid_until_ms: Option<u64>,
}

impl PeerKeyRecord {
    fn of(r: &ciris_verify_core::edition2::keys::KeyRecord) -> Self {
        PeerKeyRecord {
            key_identity_ref: identity_ref(&r.kid),
            key_hex: hex::encode(r.key.as_bytes()),
            identity_type: r.identity_type.clone(),
            asserted_at_ms: r.asserted_at,
            valid_until_ms: r.valid_until,
        }
    }
}

/// Why a peer is not Rooted for this reader. Each variant serializes with its
/// [`Self::as_str`] token under `"token"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "token")]
pub enum NotRootedReason {
    /// The peer's key is live, but it is neither a holder nor a serve seat of
    /// the bundle in force and holds no live `infra:serve` conferral. An
    /// ordinary node — not a fault. `owned`: an owner-binding names its owner.
    #[serde(rename = "peer_no_conferral")]
    NoConferral {
        /// An owner-binding counts for the peer's key.
        owned: bool,
    },
    /// The reader's governing acceptor holds no `trust:accepts:v1` edge to
    /// the root (`root`: the root the conferral needs; `None` for a ceremony
    /// seat when the reader accepts no root at all).
    #[serde(rename = "no_acceptance_edge")]
    NoAcceptanceEdge {
        /// The root, when one is named.
        root: Option<String>,
    },
    /// The reader's acceptance edge to `root`, or `root`'s charter, is
    /// withdrawn, recanted, tombstoned or expired.
    #[serde(rename = "edge_or_charter_withdrawn")]
    EdgeOrCharterWithdrawn {
        /// The root.
        root: String,
    },
    /// `root`'s live charter misses its pre-rotation commitment or a scope of
    /// `infra:serve` / `infra:attest` (or no labelled charter is held).
    #[serde(rename = "charter_missing_commitment_or_scope")]
    CharterMissingCommitmentOrScope {
        /// The root.
        root: String,
    },
    /// Persist-local: `root`'s stored chain does not root (not accord-born,
    /// non-conformant, an earlier-form chain while those doors are shut).
    #[serde(rename = "root_chain_not_rooted")]
    RootChainNotRooted {
        /// The root.
        root: String,
        /// The chain verdict's reason, in words.
        detail: String,
    },
    /// The peer's id names no key (it is not an identity-ref).
    #[serde(rename = "unknown_key")]
    UnknownKey,
    /// The claimed key is not the peer's live key.
    #[serde(rename = "pubkey_mismatch")]
    PubkeyMismatch,
    /// A revocation of the peer's key is in effect at `at_ms` (final).
    #[serde(rename = "key_revoked")]
    Revoked,
    /// Every held record of the peer's key is invalid.
    #[serde(rename = "key_invalid")]
    Invalid,
    /// Attach time only ([`attach_reading`], never [`peer_rooting`]): the
    /// root's head carries fewer than its witness quorum of counted
    /// cosignatures (CC 3.2 T4a `trust_root_head_unwitnessed`).
    #[serde(rename = "trust_root_head_unwitnessed")]
    HeadDewitnessed {
        /// The root.
        root: String,
    },
    /// Attach time only: the newest counted cosignature is older than the
    /// root's `attach_window_secs` (CC 3.2 T4a `trust_root_head_stale`).
    #[serde(rename = "trust_root_head_stale")]
    HeadStale {
        /// The root.
        root: String,
    },
    /// Attach time only: the lineage is frozen as equivocation (CC 3.2 T6,
    /// `hard_case:lineage_equivocation`).
    #[serde(rename = "lineage_equivocation")]
    LineageFrozen {
        /// The root.
        root: String,
    },
}

impl NotRootedReason {
    /// The reason's stable token, for logs (the serialized `"token"`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoConferral { .. } => "peer_no_conferral",
            Self::NoAcceptanceEdge { .. } => "no_acceptance_edge",
            Self::EdgeOrCharterWithdrawn { .. } => "edge_or_charter_withdrawn",
            Self::CharterMissingCommitmentOrScope { .. } => "charter_missing_commitment_or_scope",
            Self::RootChainNotRooted { .. } => "root_chain_not_rooted",
            Self::UnknownKey => "unknown_key",
            Self::PubkeyMismatch => "pubkey_mismatch",
            Self::Revoked => "key_revoked",
            Self::Invalid => "key_invalid",
            Self::HeadDewitnessed { .. } => "trust_root_head_unwitnessed",
            Self::HeadStale { .. } => "trust_root_head_stale",
            Self::LineageFrozen { .. } => "lineage_equivocation",
        }
    }
}

/// What the reader does not hold yet (CC 2.7.3: a row not held waits). Each
/// variant serializes with its [`Self::as_str`] token under `"token"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "token")]
pub enum CannotTellYet {
    /// No genesis bundle is in force here (none held, or a fork of the
    /// genesis), or the root the reader accepts is not held.
    #[serde(rename = "no_genesis_or_root_lineage_held")]
    NoGenesisOrRootLineageHeld,
    /// The peer's key record (or a record, bundle or voice its chain needs)
    /// is not held. Kids are identity-refs; other ids are `record:<hex>`,
    /// `bundle:<hex>`.
    #[serde(rename = "key_record_not_held")]
    KeyRecordNotHeld {
        /// What is missing.
        missing: Vec<String>,
    },
    /// The reader node's own key record is not held, so its owner-binding
    /// (which the node's key cosigns, CC 3.2) cannot be read.
    #[serde(rename = "reader_owner_binding_not_held")]
    ReaderOwnerBindingNotHeld,
    /// The peer's records are held but none covers `at_ms` (retryable).
    #[serde(rename = "key_not_covered")]
    NotCovered,
}

impl CannotTellYet {
    /// The stable token, for logs (the serialized `"token"`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoGenesisOrRootLineageHeld => "no_genesis_or_root_lineage_held",
            Self::KeyRecordNotHeld { .. } => "key_record_not_held",
            Self::ReaderOwnerBindingNotHeld => "reader_owner_binding_not_held",
            Self::NotCovered => "key_not_covered",
        }
    }
}

/// **The peer verdict** (CC 3.2 T8's states, for a peer). JSON:
/// `{"state": "rooted" | "stalled" | "not_rooted" | "cannot_tell_yet", …}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PeerRooting {
    /// Every leg holds: serve the federation tier to this peer.
    Rooted {
        /// The root the reader's chain reaches.
        root: String,
        /// The plane of the peer's conferral.
        plane: Plane,
        /// What seats the peer.
        via: RootedVia,
        /// The peer's live key record at `at_ms`.
        record: PeerKeyRecord,
    },
    /// Every leg of `Rooted` holds except T7's margin over the root's
    /// founders: valid and non-admitting (CC 3.2 T7). Serving is unchanged
    /// (T7: "serve, vouch, manifest validity … unchanged"); the root admits
    /// no new roster change or ceremony conferral.
    Stalled {
        /// The root.
        root: String,
        /// The plane of the peer's conferral.
        plane: Plane,
        /// What seats the peer.
        via: RootedVia,
        /// The peer's live key record at `at_ms`.
        record: PeerKeyRecord,
    },
    /// A leg fails; see the reason. Not a fault for an ordinary node.
    NotRooted {
        /// Why.
        reason: NotRootedReason,
    },
    /// A row the verdict needs is not held: it waits (CC 2.7.3).
    CannotTellYet {
        /// What is missing.
        missing: CannotTellYet,
    },
}

impl PeerRooting {
    /// The verdict's token, for logs: `rooted`, `community_liveness_stalled`
    /// (the CC 3.4.2 hard case's name), or the reason's / the wait's token.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rooted { .. } => "rooted",
            Self::Stalled { .. } => "community_liveness_stalled",
            Self::NotRooted { reason } => reason.as_str(),
            Self::CannotTellYet { missing } => missing.as_str(),
        }
    }

    /// **May the federation tier cross to this peer** — what the node
    /// serves to a third party: a federation-tier row, a self-authored row
    /// about someone other than the peer (CC rc21 5.3.4 "What waits for
    /// Rooted")? True for `Rooted` and for `Stalled`: a stalled root is
    /// valid, and "serve, vouch, manifest validity … unchanged" (CC 3.2 T7
    /// l.1240; "a node whose acceptance edge is written into `Stalled` is
    /// federated").
    ///
    /// ```
    /// use ciris_persist::federation::edition2::peer_rooting::{
    ///     CannotTellYet, NotRootedReason, PeerRooting,
    /// };
    /// let ordinary = PeerRooting::NotRooted {
    ///     reason: NotRootedReason::NoConferral { owned: true },
    /// };
    /// assert!(!ordinary.federation_tier_may_cross());
    /// assert!(ordinary.mesh_planes_may_cross());
    /// let pre_genesis = PeerRooting::CannotTellYet {
    ///     missing: CannotTellYet::NoGenesisOrRootLineageHeld,
    /// };
    /// assert!(!pre_genesis.federation_tier_may_cross());
    /// assert!(pre_genesis.mesh_planes_may_cross());
    /// let forged = PeerRooting::NotRooted {
    ///     reason: NotRootedReason::PubkeyMismatch,
    /// };
    /// assert!(!forged.mesh_planes_may_cross());
    /// ```
    #[must_use]
    pub fn federation_tier_may_cross(&self) -> bool {
        matches!(self, Self::Rooted { .. } | Self::Stalled { .. })
    }

    /// **May the mesh planes cross to this peer** (CC rc21 5.3.4 "What
    /// crosses before Rooted"): the bootstrap kinds and the allegiance facts,
    /// the pairing plane, rows addressed to the peer, and a bounded cohort's
    /// deliveries to it as a member. True for every verdict except a key
    /// that is not the peer's live key: `unknown_key`, `pubkey_mismatch`,
    /// `key_revoked`, `key_invalid`. Rootless is a supported state (the
    /// agent does not run, the P2P mesh does): a host MUST NOT drop a peer,
    /// refuse pairing, refuse a cohort-delivered row or refuse a dial
    /// because the peer is not Rooted.
    #[must_use]
    pub fn mesh_planes_may_cross(&self) -> bool {
        !matches!(
            self,
            Self::NotRooted {
                reason: NotRootedReason::UnknownKey
                    | NotRootedReason::PubkeyMismatch
                    | NotRootedReason::Revoked
                    | NotRootedReason::Invalid
            }
        )
    }
}

/// The arm one root's reading gives (pure; the table test ports
/// `formal/trust_root/TrustRootVerdict.tla`'s `V`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Arm {
    Rooted,
    Stalled,
    NotRooted(NotRootedReason),
}

/// The T8 arm from one root's legs. `chain_holds`: the root's chain verdict
/// holds (its current head, T6 — the model's `HasCurrentHead`); `legs`: the
/// reader's T3 legs (`None` for a chain read without them, an earlier-form
/// chain the doors still read: its standing is the door's); `live`: T7's
/// margin. The model's `V`: no edge ⇒ NotRooted; no current head ⇒
/// NotRooted; live ⇒ Rooted; else Stalled. The charter legs are the model's
/// constants, read here.
pub(crate) fn arm(
    root: &str,
    chain_holds: bool,
    chain_detail: &str,
    legs: Option<ChainLegs>,
    live: bool,
) -> Arm {
    if let Some(l) = legs {
        if !l.accepted {
            return Arm::NotRooted(if l.edge_held {
                NotRootedReason::EdgeOrCharterWithdrawn {
                    root: root.to_owned(),
                }
            } else {
                NotRootedReason::NoAcceptanceEdge {
                    root: Some(root.to_owned()),
                }
            });
        }
        match l.charter {
            CharterLeg::Complete => {}
            CharterLeg::NotLive => {
                return Arm::NotRooted(NotRootedReason::EdgeOrCharterWithdrawn {
                    root: root.to_owned(),
                })
            }
            CharterLeg::MissingCommitmentOrScope | CharterLeg::Absent => {
                return Arm::NotRooted(NotRootedReason::CharterMissingCommitmentOrScope {
                    root: root.to_owned(),
                })
            }
        }
    }
    if !chain_holds {
        return Arm::NotRooted(NotRootedReason::RootChainNotRooted {
            root: root.to_owned(),
            detail: chain_detail.to_owned(),
        });
    }
    if live {
        Arm::Rooted
    } else {
        Arm::Stalled
    }
}

/// `at_ms` as an instant.
fn instant(at_ms: u64) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    i64::try_from(at_ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .ok_or_else(|| Error::InvalidArgument(format!("peer_rooting: at_ms {at_ms} is no instant")))
}

/// What a `Waiting` reading waits on, as ids.
fn missing_ids(missing: &[MissingKey]) -> Vec<String> {
    missing
        .iter()
        .map(|m| match m {
            MissingKey::Kid(k) | MissingKey::CoveringRecord { kid: k, .. } => identity_ref(k),
            MissingKey::Voice { kid, .. } => identity_ref(kid),
            MissingKey::Record(r) => format!("record:{}", hex::encode(r)),
            MissingKey::Bundle(b) => format!("bundle:{}", hex::encode(b)),
            // v62.0.0 (PIN-fix5b; CIRISVerify 23.4.1) — a composer's target row
            // (a key-chain reading never yields it; named if one does).
            MissingKey::Row(r) => format!("row:{}", hex::encode(r)),
            // `MissingKey` is non_exhaustive.
            other => format!("{other:?}"),
        })
        .collect()
}

/// Does `claimed` name the key `record` records?
fn claim_matches(
    claimed: &ClaimedKey<'_>,
    record: &ciris_verify_core::edition2::keys::KeyRecord,
) -> bool {
    match claimed {
        ClaimedKey::Composite(key) => record.key.as_bytes() == key.as_bytes(),
        ClaimedKey::Kid(kid) => record.kid == *kid,
        // An identity MATCH of the Ed25519 half (transitional), never a
        // signature verify: no LONE_VERIFY pattern is reached here.
        ClaimedKey::Ed25519Half(half) => {
            super::composite::ed25519_public(&record.key).is_some_and(|h| h == *half)
        }
    }
}

/// One root's reading for the reader, through the trust root's own read
/// verdict and T7's margin. v62.0.0 (R2-rooms): the bundle's lineage only
/// (`trust_root::bundle_root_accepted`); the room-chain reading is deleted.
/// It is asked only once the genesis in force is held (`peer_rooting`'s
/// step 1), so it never waits.
async fn root_arm<F>(
    dir: &F,
    reader: &str,
    root: &str,
    t: chrono::DateTime<chrono::Utc>,
) -> Result<Arm, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (KB-fix2; CC 3.2 at rc22 `87abd2d`) — the BUNDLE root: the
    // lineage of the bundle in force, named by its `family_key_id`. Its leg
    // is the reader's own chain accepting it (`bundle_root_accepted`: the
    // owner's, else the reader's, live labelled edge; the bundle's charter
    // and recovery commitments, Verify-placed). T7's margin is over the
    // holders in force: `Stalled` when losing one holder would leave the
    // rest short of the strict majority. No room chain is read for it.
    if let Some(holders) = trust_root::bundle_root_holders(dir, root).await? {
        // v62.0.0 (R2-rooms) — through the model's `V` (`arm`): the chain
        // holds (the bundle in force is its current head); the reader's T3
        // legs are its acceptance, live or not (`root_arm` is asked only for a
        // root the reader's acceptor names by a held acceptance row,
        // `trust_root::accepted_roots_of`, so the edge is HELD: one that is
        // not live reads `edge_or_charter_withdrawn`, I2223), and the charter
        // is the bundle's (complete by its placement); T7's margin is over the
        // holders in force.
        let accepted = Box::pin(trust_root::bundle_root_accepted(dir, reader, root, t)).await?;
        let n = holders.len();
        return Ok(arm(
            root,
            true,
            "",
            Some(ChainLegs {
                accepted,
                edge_held: true,
                charter: CharterLeg::Complete,
            }),
            n > crate::federation::admission::strict_majority(n),
        ));
    }
    // v62.0.0 (R2-rooms; CC 3.2 T5, "There is no other kind of root") — the
    // KEYED branch (a room chain judged as a root's,
    // `canonical_community::reader_standing`) is deleted: the genesis in
    // force is held here, and an id that is not its lineage is no root.
    Ok(Arm::NotRooted(NotRootedReason::RootChainNotRooted {
        root: root.to_owned(),
        detail: "not the lineage of the genesis bundle in force: the root is the bundle's \
                 lineage, and there is no other kind of root (CC 3.2 T5)"
            .to_owned(),
    }))
}

/// v62.0.0 (PR-fix1; CC 3.2 T8, CC 5.3.4) — **is the peer `peer_identity_ref`
/// Rooted for the reader node `reader_node` at `at_ms`?** See the module doc
/// for the rule.
///
/// - `reader_node`: THIS node's identity-ref (the node whose owner's
///   acceptance edges are read, CC 3.2 T3).
/// - `claimed_key`: the key the peer speaks with, in any [`ClaimedKey`] form;
///   a key that is not the peer's live key is
///   [`NotRootedReason::PubkeyMismatch`].
/// - `at_ms`: the **signer-stamped instant** of the thing being judged (a
///   row's `asserted_at`, a link's handshake instant the peer signed). For an
///   outcome that is stored or replicated it MUST NOT be the reader's wall
///   clock: T8's `V` is evaluated at a signer-stamped `t`, so two nodes
///   holding the same rows give the same verdict (T8 vii).
///
/// **Rootless is a supported state** (the agent does not run, the P2P mesh
/// does): `NotRooted` and `CannotTellYet` are ordinary, healthy answers,
/// returned `Ok`. The verdict gates ONLY what the node serves to a third
/// party (CC 5.3.4): the federation tier and self-authored rows about someone
/// other than the peer ([`PeerRooting::federation_tier_may_cross`]). A caller
/// MUST NOT drop a peer, refuse pairing, refuse a cohort-delivered row or
/// refuse a dial because of it ([`PeerRooting::mesh_planes_may_cross`]).
///
/// Order: the genesis in force (none: every peer waits); the reader's own key
/// record (not held: waits); the peer's key (not an identity-ref:
/// `UnknownKey`; its liveness; the claim); the peer's conferrals; each
/// conferral's root through the reader's chain. `Rooted` wins over
/// `Stalled`, that over a named `NotRooted` (v62.0.0 R2-rooms: an accepted
/// root is the lineage or no root, so nothing past step 1 waits on a root).
///
/// # Errors
///
/// `reader_node` is not an identity-ref, `at_ms` is no instant, or a
/// directory read failed.
pub async fn peer_rooting<F: FederationDirectory + ?Sized>(
    dir: &F,
    reader_node: &str,
    peer_identity_ref: &str,
    claimed_key: ClaimedKey<'_>,
    at_ms: u64,
) -> Result<PeerRooting, Error> {
    let not = |reason| Ok(PeerRooting::NotRooted { reason });
    let wait = |missing| Ok(PeerRooting::CannotTellYet { missing });
    let t = instant(at_ms)?;
    let Some(reader_kid) = super::ingest::kid_of_identity_ref(reader_node) else {
        return Err(Error::InvalidArgument(format!(
            "peer_rooting: reader_node {reader_node:?} is not an identity-ref"
        )));
    };

    // 1. The genesis in force: every edition-2 root is accord-born over it.
    let in_force = super::genesis::genesis_in_force(dir).await?;
    if !in_force.is_held() || in_force.common.is_none() {
        return wait(CannotTellYet::NoGenesisOrRootLineageHeld);
    }

    // 2. The reader's own key record: its owner-binding is read over it.
    match super::ingest::held_keys_for_kid(dir, &reader_kid)
        .await?
        .liveness(&reader_kid, at_ms)
    {
        Liveness::NotHeld | Liveness::Waiting(_) => {
            return wait(CannotTellYet::ReaderOwnerBindingNotHeld)
        }
        Liveness::Live(_) | Liveness::NotCovered | Liveness::Revoked | Liveness::Invalid => {}
    }

    // 3. The peer's key at `at_ms`, and the claim.
    let Some(peer_kid) = super::ingest::kid_of_identity_ref(peer_identity_ref) else {
        return not(NotRootedReason::UnknownKey);
    };
    let record = match super::ingest::held_keys_for_kid(dir, &peer_kid)
        .await?
        .liveness(&peer_kid, at_ms)
    {
        Liveness::Live(r) => r,
        Liveness::NotHeld => {
            return wait(CannotTellYet::KeyRecordNotHeld {
                missing: vec![identity_ref(&peer_kid)],
            })
        }
        Liveness::Waiting(m) => {
            return wait(CannotTellYet::KeyRecordNotHeld {
                missing: missing_ids(&m),
            })
        }
        Liveness::NotCovered => return wait(CannotTellYet::NotCovered),
        Liveness::Revoked => return not(NotRootedReason::Revoked),
        Liveness::Invalid => return not(NotRootedReason::Invalid),
    };
    if !claim_matches(&claimed_key, &record) {
        return not(NotRootedReason::PubkeyMismatch);
    }
    let record = PeerKeyRecord::of(&record);

    // 4. The peer's conferrals, each with the roots it may reach through.
    let accepted = trust_root::accepted_roots_of(dir, reader_node).await?;
    let mut seats: Vec<(Plane, RootedVia, Vec<String>)> = Vec::new();
    if in_force.is_holder(peer_identity_ref) {
        seats.push((Plane::Ceremony, RootedVia::AccordHolder, accepted.clone()));
    } else if in_force.is_canonical(peer_identity_ref) {
        seats.push((Plane::Ceremony, RootedVia::ServeSeat, accepted.clone()));
    }
    // v62.0.0 (KB-fix2; CC 3.2 at rc22 `87abd2d`) — a delegation seat under
    // the BUNDLE root stands on the root's grant: a row counted over the
    // holders of the bundle it names (KR-fix2's `root_grant_of`: the named
    // bundle held Valid, the count met before its successor, the charter
    // covering the scope) and accepted by the grantee (or a machine
    // grantee's owner). Its root is that bundle's `family_key_id`, never the
    // holder who authored it (the walk's arm, KR-fix3a, reads it the same
    // way). Every other grant names its root by its granter's key.
    let grants =
        trust_root::live_conferral_rows(dir, peer_identity_ref, trust_root::INFRA_SERVE_SCOPE, t)
            .await?;
    // v62.0.0 (R2-planes) — the counted grant's seat is on the CEREMONY plane
    // (a row counted over the holders, naming the bundle), when the grant's
    // bundle's charter covers `infra:serve` (R2-delegation-b, per element).
    let mut counted: Vec<String> = Vec::new();
    for g in grants {
        if !crate::federation::admission::is_counted_root_grant_row(&g) {
            continue;
        }
        if let Some(rg) =
            crate::federation::admission::root_grant_of(dir.as_dyn_directory(), &g, t).await?
        {
            let covers_serve = rg.covered.iter().any(|c| {
                crate::federation::admission::scope_covers(c, trust_root::INFRA_SERVE_SCOPE)
            });
            if rg.accepted && covers_serve && !counted.contains(&rg.family_key_id) {
                counted.push(rg.family_key_id);
            }
        }
    }
    if !counted.is_empty() {
        seats.push((Plane::Ceremony, RootedVia::ConferredSeat, counted));
    } else {
        // v62.0.0 (R2-delegation-b; Constitution 11-24, CC 3.2 T2 "neither
        // plane is privileged") — a seat standing through a live chain from a
        // counted grant (`trust_root::delegation_conferral`: each hop
        // accepted, within the reader's depth, sub_delegation on each incoming
        // offer, terms in force, every edge bearing `infra:serve`) is a seat
        // on the DELEGATION plane, rooted as a counted one is. A single
        // signer's grant read as its own root (the keyed seat) is gone.
        if let Some(g) = Box::pin(trust_root::delegation_conferral(
            dir,
            reader_node,
            peer_identity_ref,
            trust_root::INFRA_SERVE_SCOPE,
            t,
        ))
        .await?
        {
            seats.push((
                Plane::Delegation,
                RootedVia::ConferredSeat,
                vec![g.root_key_id],
            ));
        }
    }
    if seats.is_empty() {
        let owned =
            match crate::federation::admission::owner_of_unmarked(dir, peer_identity_ref).await {
                Ok(o) => o.is_some(),
                // Two counted owners read as unowned (CC 3.2, C557).
                Err(Error::AmbiguousNodeOwner { .. }) => false,
                Err(e) => return Err(e),
            };
        return not(NotRootedReason::NoConferral { owned });
    }

    // 5. Each root through the reader's chain (T3) and T7's margin.
    let mut stalled: Option<PeerRooting> = None;
    let mut named: Option<NotRootedReason> = None;
    let mut no_edge: Option<NotRootedReason> = None;
    for (plane, via, roots) in seats {
        if roots.is_empty() {
            no_edge.get_or_insert(NotRootedReason::NoAcceptanceEdge { root: None });
        }
        for root in roots {
            if !accepted.contains(&root) {
                no_edge.get_or_insert(NotRootedReason::NoAcceptanceEdge {
                    root: Some(root.clone()),
                });
                continue;
            }
            match root_arm(dir, reader_node, &root, t).await? {
                Arm::Rooted => {
                    return Ok(PeerRooting::Rooted {
                        root,
                        plane,
                        via,
                        record,
                    })
                }
                Arm::Stalled => {
                    stalled.get_or_insert(PeerRooting::Stalled {
                        root,
                        plane,
                        via,
                        record: record.clone(),
                    });
                }
                Arm::NotRooted(r @ NotRootedReason::NoAcceptanceEdge { .. }) => {
                    no_edge.get_or_insert(r);
                }
                Arm::NotRooted(r) => {
                    named.get_or_insert(r);
                }
            }
        }
    }
    if let Some(s) = stalled {
        return Ok(s);
    }
    match named.or(no_edge) {
        Some(r) => not(r),
        // Unreachable: every seat pushed a reason or a verdict above.
        None => not(NotRootedReason::NoAcceptanceEdge { root: None }),
    }
}

/// v62.0.0 (PR-fix1; CC 3.2 T4a, T6, T8 "at attach time only") — **may the
/// reader attach to `root` now, at `at_ms`?** The attach-time clauses of T8's
/// `NotRooted`, which are "never a leg of V for a node already attached"
/// (T4), so [`peer_rooting`] never reads them. `None`: attachable (or no
/// lineage of `root` is held: a key root, judged by its own read).
///
/// The freshness rule is the acceptance edge's own write gate
/// ([`canonical_community::check_attach_freshness`], the head the edge would
/// name: the witnessed head, or the held head in witnessed mode off); the
/// freeze is the witness fold's equivocation.
///
/// # Errors
///
/// `at_ms` is no instant, or a directory read failed.
pub async fn attach_reading<F: FederationDirectory + ?Sized>(
    dir: &F,
    reader_node: &str,
    root: &str,
    at_ms: u64,
) -> Result<Option<NotRootedReason>, Error> {
    let t = instant(at_ms)?;
    let Some(view) = canonical_community::root_witness_view(dir, root, t).await? else {
        return Ok(None);
    };
    if view
        .community
        .as_ref()
        .is_some_and(|c| c.equivocation.is_some())
    {
        return Ok(Some(NotRootedReason::LineageFrozen {
            root: root.to_owned(),
        }));
    }
    let witnessed_mode_on = crate::federation::lineage_witness::witnessed_mode_on(view.quorum);
    let head = if witnessed_mode_on {
        view.witnessed_head.as_ref()
    } else {
        view.held_head.as_ref()
    };
    let Some((head, _)) = head else {
        return Ok(Some(NotRootedReason::HeadDewitnessed {
            root: root.to_owned(),
        }));
    };
    let mut members = serde_json::Map::new();
    members.insert(
        "dimension".to_owned(),
        serde_json::Value::String(trust_root::TRUST_ACCEPTS_DIMENSION.to_owned()),
    );
    members.insert(
        crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST.to_owned(),
        serde_json::Value::String(head.clone()),
    );
    let envelope = serde_json::Value::Object(members);
    match canonical_community::check_attach_freshness(
        dir,
        canonical_community::AttachDoor::Author,
        None,
        reader_node,
        crate::federation::types::attestation_type::DELEGATES_TO,
        root,
        &envelope,
        t,
    )
    .await
    {
        Ok(()) => Ok(None),
        Err(Error::TrustRootHeadStale { .. } | Error::TrustRootHeadUnnamed { .. }) => {
            Ok(Some(NotRootedReason::HeadStale {
                root: root.to_owned(),
            }))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legs(accepted: bool, edge_held: bool, charter: CharterLeg) -> ChainLegs {
        ChainLegs {
            accepted,
            edge_held,
            charter,
        }
    }

    /// The model's `V` (`formal/trust_root/TrustRootVerdict.tla`, CC rc21):
    /// `IF edgeHead = 0 THEN NotRooted ELSE IF ~HasCurrentHead THEN NotRooted
    /// ELSE IF Live THEN Rooted ELSE Stalled`.
    fn model_v(edge: bool, current_head: bool, live: bool) -> &'static str {
        if !edge || !current_head {
            "NotRooted"
        } else if live {
            "Rooted"
        } else {
            "Stalled"
        }
    }

    fn state(a: &Arm) -> &'static str {
        match a {
            Arm::Rooted => "Rooted",
            Arm::Stalled => "Stalled",
            Arm::NotRooted(_) => "NotRooted",
        }
    }

    /// **I2213** (pure) — [`arm`] is the model's `V` case for case over every
    /// (edge, current head, live) instant-free state, with the model's
    /// constant charter (complete); and its invariants: `Inv_vi` (no edge ⇒
    /// NotRooted), `Inv_T7` (Stalled ⇒ edge ∧ head ∧ ¬live). A charter short
    /// of a leg is NotRooted whatever the rest (T8 `NotRooted`). `Prop_ii`
    /// ("V does not read the clock") is structural: `arm` takes no instant.
    #[test]
    fn i2213_arm_is_the_models_v() {
        for edge in [false, true] {
            for head in [false, true] {
                for live in [false, true] {
                    for held in [false, true] {
                        let l = legs(edge, held || edge, CharterLeg::Complete);
                        let a = arm("r", head, "chain", Some(l), live);
                        assert_eq!(
                            state(&a),
                            model_v(edge, head, live),
                            "I2213: edge {edge} head {head} live {live}"
                        );
                        if !edge {
                            assert_eq!(state(&a), "NotRooted", "I2213 Inv_vi");
                        }
                        if state(&a) == "Stalled" {
                            assert!(edge && head && !live, "I2213 Inv_T7");
                        }
                        for c in [
                            CharterLeg::MissingCommitmentOrScope,
                            CharterLeg::NotLive,
                            CharterLeg::Absent,
                        ] {
                            let a = arm("r", head, "chain", Some(legs(edge, held, c)), live);
                            assert_eq!(state(&a), "NotRooted", "I2213: charter {c:?}");
                        }
                    }
                }
            }
        }
    }

    /// **I2214** (pure) — the reason [`arm`] names: no edge row toward the
    /// root is `no_acceptance_edge`; an edge row held but not live is
    /// `edge_or_charter_withdrawn`; a charter withdrawn is the same token; a
    /// charter short of its commitment or scope is
    /// `charter_missing_commitment_or_scope`; a chain that does not hold is
    /// `root_chain_not_rooted`. A Stalled arm's verdict token is the CC 3.4.2
    /// hard case's name.
    #[test]
    fn i2214_the_arm_names_its_reason() {
        let why = |a: Arm| match a {
            Arm::NotRooted(r) => r.as_str(),
            other => panic!("I2214: {other:?}"),
        };
        assert_eq!(
            why(arm(
                "r",
                true,
                "",
                Some(legs(false, false, CharterLeg::Complete)),
                true
            )),
            "no_acceptance_edge"
        );
        assert_eq!(
            why(arm(
                "r",
                true,
                "",
                Some(legs(false, true, CharterLeg::Complete)),
                true
            )),
            "edge_or_charter_withdrawn"
        );
        assert_eq!(
            why(arm(
                "r",
                true,
                "",
                Some(legs(true, true, CharterLeg::NotLive)),
                true
            )),
            "edge_or_charter_withdrawn"
        );
        assert_eq!(
            why(arm(
                "r",
                true,
                "",
                Some(legs(true, true, CharterLeg::MissingCommitmentOrScope)),
                true
            )),
            "charter_missing_commitment_or_scope"
        );
        assert_eq!(
            why(arm("r", false, "not accord-born", None, true)),
            "root_chain_not_rooted"
        );
        assert_eq!(arm("r", true, "", None, false), Arm::Stalled);
        let stalled = PeerRooting::Stalled {
            root: "r".into(),
            plane: Plane::Ceremony,
            via: RootedVia::AccordHolder,
            record: PeerKeyRecord {
                key_identity_ref: "k".into(),
                key_hex: String::new(),
                identity_type: vec!["accord_holder".into()],
                asserted_at_ms: 0,
                valid_until_ms: None,
            },
        };
        assert_eq!(stalled.as_str(), "community_liveness_stalled");
        assert!(
            stalled.federation_tier_may_cross(),
            "I2214: Stalled is valid (T7)"
        );
    }

    /// **I2215** (pure) — the JSON shape: `state`, then the arm's fields; a
    /// reason or a wait carries its `token`, equal to `as_str()`; every form
    /// round-trips.
    #[test]
    fn i2215_json_shape() {
        let cases = vec![
            PeerRooting::NotRooted {
                reason: NotRootedReason::NoConferral { owned: true },
            },
            PeerRooting::NotRooted {
                reason: NotRootedReason::PubkeyMismatch,
            },
            PeerRooting::NotRooted {
                reason: NotRootedReason::NoAcceptanceEdge { root: None },
            },
            PeerRooting::CannotTellYet {
                missing: CannotTellYet::KeyRecordNotHeld {
                    missing: vec!["k".into()],
                },
            },
            PeerRooting::CannotTellYet {
                missing: CannotTellYet::NoGenesisOrRootLineageHeld,
            },
        ];
        for c in cases {
            let j = serde_json::to_value(&c).expect("I2215: serialize");
            match &c {
                PeerRooting::NotRooted { reason } => {
                    assert_eq!(j["state"], "not_rooted");
                    assert_eq!(j["reason"]["token"], reason.as_str(), "I2215");
                }
                PeerRooting::CannotTellYet { missing } => {
                    assert_eq!(j["state"], "cannot_tell_yet");
                    assert_eq!(j["missing"]["token"], missing.as_str(), "I2215");
                }
                PeerRooting::Rooted { .. } | PeerRooting::Stalled { .. } => unreachable!(),
            }
            let back: PeerRooting = serde_json::from_value(j).expect("I2215: deserialize");
            assert_eq!(back, c, "I2215: round trip");
        }
        let claim = ClaimedKeyWire::Kid([7; 32]);
        let j = serde_json::to_value(&claim).unwrap();
        assert_eq!(j["form"], "kid", "I2215: the claim's form");
        assert_eq!(serde_json::from_value::<ClaimedKeyWire>(j).unwrap(), claim);
        assert_eq!(
            claim.as_claim(None),
            Some(ClaimedKey::Kid([7; 32])),
            "I2215: a kid needs no parse"
        );
        assert_eq!(
            ClaimedKeyWire::Composite(vec![1, 2, 3])
                .composite()
                .map(|k| k.map(|k| k.as_bytes().to_vec())),
            Err(NotACompositeKey),
            "I2215: three bytes are no composite key"
        );
    }
}
