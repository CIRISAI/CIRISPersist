//! **Erasability is decided at MINT, never at erasure** (CIRISPersist#573,
//! CIRISVerify#241, CIRISConstitution#78 / CC 2.6 redaction clause).
//!
//! This module answers the one question CC and CIRISVerify both deliberately
//! left open — *"does a redacted object keep its kind, or become a distinct
//! one?"* — and it answers it by refusing the premise.
//!
//! # The ruling
//!
//! **There is no redacted object.** Persist never produces one, so neither
//! answer to CC constraint (d) as phrased is the one we take. What exists is a
//! **mint-time distinction between two shapes**:
//!
//! - **SEALED** — the payload is inside the signed envelope. Its bytes are
//!   inside `sha256(canonical(envelope)) == original_content_hash` and inside
//!   the hybrid signature over those same bytes. **It can never be erased.**
//!   That is arithmetic, not policy: any rewrite of those bytes is
//!   indistinguishable from tampering to every reader, which is exactly what
//!   CC ruled the signed-discriminator shape out for.
//! - **ERASABLE** — the payload rides **outside** the envelope as
//!   [`Disclosure`]s, bound to it only by a per-member salted digest carried
//!   *in* the envelope ([`SD_MEMBER`]). Erasure drops a disclosure. **Nothing
//!   signed is ever altered**, so the envelope canonicalizes, hashes and
//!   hybrid-verifies after erasure exactly as it did before — byte for byte.
//!
//! The distinction is therefore made **before** any erasure happens and does
//! not change when one does. An erased object carries the same kind it was
//! minted with; what tells a reader it is erasable is the presence of the
//! commitment, and that presence is inside the signature.
//!
//! # Why this is the containment answer, and not merely a convenient one
//!
//! CIRISVerify#241 proposed scoping the wire break to *"one redactable kind"*
//! and asked for **"which objects actually need erasure?"** to decide it,
//! reasoning that *"a bounded set makes the distinct-kind answer obviously
//! right."* The set is **not** bounded — of the 38 payload carriers on hashed
//! rows (`docs/design/PAYLOAD_ENUMERATION.md` §1.1), the large majority carry
//! content a remote party influences. But the converse of verify's heuristic
//! does not hold, and this is the load-bearing step:
//!
//! > An **unbounded** erasure need makes the same-kind answer *worse*, not the
//! > distinct-kind answer wrong. "Every object is redactable" is a universal,
//! > **fail-open** partiality property: every consumer of every object must
//! > then remember to ask whether members were withheld, and the one that
//! > forgets silently accepts a partial object. Under the mint-time
//! > distinction nobody has to remember anything — an object either carries
//! > a commitment or it does not, and that is signed.
//!
//! Fail direction is how `docs/design/PAYLOAD_ENUMERATION.md` §4 already tells
//! these issues apart. It decides this one too.
//!
//! # What this costs, stated rather than discovered later
//!
//! **Erasability is not retrofittable.** #573 argues *"the mesh cannot know in
//! advance which object will need nuking, so erasure has to be addressable the
//! way objects are addressed."* The first clause is true; the conclusion does
//! not follow. Erasure **is** addressable by object here — any erasable object
//! can be erased by name at any time, no foresight about *which* one. What
//! cannot be retrofitted is **erasABILITY**: a payload already inside a
//! signature cannot leave it. So the mesh does not have to predict which
//! object will need erasing, but it does have to decide, per object, whether
//! its payload goes inside the signature or beside it. That decision is
//! permanent and it is made at mint. Today every one of the 88 payload
//! carriers is sealed.
//!
//! # What this does NOT require — the inertness test
//!
//! CIRISPersist#573 was opened, and `PAYLOAD_ENUMERATION.md` §7.3 established,
//! that *a persist-only redaction change is inert*: the gate that bites is
//! `sha256(canonical) == original_content_hash` receiver-side, so the
//! redacting node tolerates its own rows and the first peer refuses them.
//!
//! That failure does not apply here, and the claim is **proved rather than
//! asserted** — `tests::erasable_envelope_survives_total_erasure_at_the_real_ingest_gate`
//! runs the *real* [`verify_federation_tier_ingest`](super::tier_ingest::verify_federation_tier_ingest)
//! over a real hybrid-signed row before and after erasing every member, on
//! every backend. It passes both times because the row is byte-identical.
//! The control in the same module erases one field of a **sealed** envelope
//! and shows the same gate refusing it.
//!
//! Consequences worth naming:
//!
//! - **No CIRISVerify change is needed on the envelope plane.** The
//!   redacted-vs-tampered ambiguity CIRISVerify#241 exists to resolve does not
//!   arise, because no signed bytes are ever rewritten.
//!   [`ciris_verify_core::redactable`] is still the primitive — it is used
//!   *above* the envelope by whoever reads the payload, not *inside* the
//!   envelope verifier.
//! - **No second `consent_role`-shaped exclusion from
//!   [`compute_persist_row_hash`](super::types::compute_persist_row_hash).**
//!   `PAYLOAD_ENUMERATION.md` §7.5 item 1 and CIRISVerify#241 both expected a
//!   row-level marker outside the row hash. None is needed: the disclosures
//!   are not row members, so the row hash is untouched by erasure.
//! - **No wire break.** An erasable envelope is an ordinary envelope with one
//!   more object-valued member. 248 of 265 wire fields are already
//!   `untyped_extra`; this is one more.
//!
//! # The tension inside #573 that salting forces
//!
//! #573 asks for two properties that are **not jointly satisfiable in
//! general**, and the reason is CC's own:
//!
//! - *Payload-only erasure* requires the surviving commitment to reveal
//!   nothing. CC and CIRISVerify#241 both ruled that this needs a **salt** —
//!   an unsalted digest of a low-entropy member is recoverable by dictionary
//!   search, and erased content is exactly what an adversary searches for.
//! - *Recognition without retention* — *"publishing the content hash of erased
//!   material lets other nodes refuse the same payload on arrival"* — requires
//!   a hash **another node can recompute over the same bytes**, i.e. an
//!   **unsalted** one. Publishing it re-opens the dictionary attack the salt
//!   exists to close.
//!
//! So recognition is available only for content with enough entropy that
//! publishing its hash does not disclose it, and persist **cannot measure
//! that**. It is therefore an explicit, per-erasure operator assertion
//! ([`RecognitionPolicy`]), never a default, with one mechanical floor persist
//! *can* check ([`RECOGNITION_MIN_BYTES`]) — declared depth, in the discipline
//! of the v23.1.0 custody note: the floor is a minimum, not a measurement, and
//! the assertion stays the operator's.
//!
//! # What is deliberately not here
//!
//! Storage for disclosures, and `erase_object` itself. Those need a migration
//! and are named in the issue thread rather than half-built here; this module
//! is the shape they store and the proof that storing it is not inert.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use ciris_verify_core::redactable::{
    Disclosure, MemberState, RedactableCommitment, RedactionError, SALT_LEN,
};

/// The envelope member carrying an object's redactable commitment.
///
/// Its **presence is the mint-time declaration** that this object is erasable,
/// and because it sits inside the canonical bytes, that declaration is signed:
/// a tamperer cannot add it to a sealed object, and cannot remove it from an
/// erasable one, without breaking `original_content_hash` and the hybrid
/// signature over the same bytes.
///
/// Underscore-prefixed after the SD-JWT `_sd` convention CC's clause names,
/// namespaced so it cannot collide with a wire field: the `field_processor_matrix`
/// types 248 of 265 fields `untyped_extra`, so an unprefixed name is a real
/// collision risk.
pub const SD_MEMBER: &str = "_ciris_sd";

/// Scheme token inside [`SD_MEMBER`]. Pinned; a change is a wire break, which
/// is why it is a value a reader checks rather than an assumption it makes.
pub const SD_SCHEME: &str = "ciris.redactable.v1";

/// Domain prefix for the **unsalted** recognition hash ([`recognition_hash`]).
/// Distinct from [`ciris_verify_core::redactable::MEMBER_DOMAIN`] so a
/// recognition hash can never be mistaken for — or replayed as — a member
/// commitment.
pub const RECOGNITION_DOMAIN: &[u8] = b"ciris.erasure.recognition.v1\n";

/// The mechanical floor below which persist refuses to publish a recognition
/// hash at all.
///
/// **It is a minimum, not a measurement.** 64 bytes of English prose is as
/// guessable as 4; length does not bound entropy. What the floor does is
/// foreclose the cases where the value space is *obviously* enumerable — a
/// boolean, an enum token, a date, a key id — so that the operator assertion
/// in [`RecognitionPolicy::OperatorAssertsHighEntropy`] is never the *only*
/// thing standing between a published hash and a dictionary attack. The
/// assertion remains the operator's and is recorded as theirs.
pub const RECOGNITION_MIN_BYTES: usize = 64;

// ─────────────────────────────────────────────────────────────────────────
//  The commitment, as it rides inside a signed envelope
// ─────────────────────────────────────────────────────────────────────────

/// [`SD_MEMBER`]'s value: the signed half of an erasable object.
///
/// `digests` is carried in full — not just `root` — deliberately. It is what
/// lets a reader holding **only the envelope** see how many members existed
/// and, against a disclosure set, exactly which are gone. #573's operator
/// requirement is *which* members were erased, not merely that some were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedCommitment {
    /// [`SD_SCHEME`].
    pub scheme: String,
    /// Hex `sha256(ROOT_DOMAIN ‖ u32_be(count) ‖ digests…)` — what the
    /// producer's hybrid signature covers, transitively, by being inside the
    /// canonical envelope bytes.
    pub root: String,
    /// Hex per-member salted digests, in index order. Length is the committed
    /// member count.
    pub digests: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────
//  Typed refusals — the #565 / #570 discipline
// ─────────────────────────────────────────────────────────────────────────

/// **WHICH branch refused** a [`seal`] call.
///
/// Closed, snake_case serde tokens, [`Self::as_str`] returning the same token,
/// and deliberately no catch-all — the
/// [`AdminActionRefusal`](super::hard_case::AdminActionRefusal) discipline.
/// The token set is APPEND-ONLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealRefusal {
    /// The header is not a JSON object, so there is nowhere to put the
    /// commitment.
    HeaderNotAnObject,
    /// The header already carries [`SD_MEMBER`]. Overwriting it would silently
    /// discard a prior commitment — and a caller that reached this is
    /// double-sealing, which is a bug rather than a shape to tolerate.
    CommitmentSlotOccupied,
    /// Zero erasable members. An "erasable" object with nothing erasable is a
    /// sealed object wearing the wrong label; refusing it keeps the presence
    /// of [`SD_MEMBER`] a truthful signal.
    NoErasableMembers,
    /// The RNG refused a salt draw (SP 800-90B fail-secure latch). A
    /// predictable salt defeats the only thing the salt is for, so this is a
    /// refusal and never a fallback.
    SaltDrawRefused,
}

impl SealRefusal {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HeaderNotAnObject => "header_not_an_object",
            Self::CommitmentSlotOccupied => "commitment_slot_occupied",
            Self::NoErasableMembers => "no_erasable_members",
            Self::SaltDrawRefused => "salt_draw_refused",
        }
    }
}

impl std::fmt::Display for SealRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// **WHICH branch refused** to read a commitment out of an envelope.
///
/// [`Self::CommitmentAbsent`] is the load-bearing one: it is not an error
/// condition, it is the answer *"this object is SEALED"*. Callers must treat
/// it as a verdict, not a failure — an unerasable object is the normal case
/// and today it is every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentRefusal {
    /// The envelope is not a JSON object.
    EnvelopeNotAnObject,
    /// No [`SD_MEMBER`]. **The object is sealed** — permanent by construction.
    CommitmentAbsent,
    /// [`SD_MEMBER`] is present but does not parse as a [`SealedCommitment`].
    CommitmentMalformed,
    /// The `scheme` token is not [`SD_SCHEME`]. A reader that does not know a
    /// scheme must refuse, never guess — guessing is how a future scheme's
    /// weaker commitment gets accepted under this one's name.
    SchemeUnknown,
    /// `root` or a `digests` entry is not 32 lowercase-hex-encoded bytes.
    DigestMalformed,
    /// Zero digests — the shape [`SealRefusal::NoErasableMembers`] refuses to
    /// mint, arriving from the wire.
    NoErasableMembers,
}

impl CommitmentRefusal {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EnvelopeNotAnObject => "envelope_not_an_object",
            Self::CommitmentAbsent => "commitment_absent",
            Self::CommitmentMalformed => "commitment_malformed",
            Self::SchemeUnknown => "scheme_unknown",
            Self::DigestMalformed => "digest_malformed",
            Self::NoErasableMembers => "no_erasable_members",
        }
    }
}

impl std::fmt::Display for CommitmentRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why [`verify_members`] did not produce a per-member verdict.
///
/// Two nested causes kept apart on purpose: the envelope's commitment being
/// unreadable is a *different operator problem* from the disclosures failing
/// against a readable one, and only the second means tampering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMembersError {
    /// The envelope's commitment could not be read.
    Commitment(CommitmentRefusal),
    /// The disclosures did not check out against it. A
    /// [`RedactionError::DigestMismatch`] here is **tampering**; a missing
    /// disclosure is not an error at all and reports as
    /// [`MemberState::Redacted`].
    Redaction(RedactionError),
}

impl std::fmt::Display for VerifyMembersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Commitment(r) => write!(f, "commitment unreadable: {r}"),
            Self::Redaction(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VerifyMembersError {}

// ─────────────────────────────────────────────────────────────────────────
//  The side-carried half
// ─────────────────────────────────────────────────────────────────────────

/// The payload that rides **beside** an erasable envelope, never inside it.
///
/// Withholding a [`Disclosure`] is what erasure is. Because this set is not a
/// member of the envelope and not a member of any hashed row, dropping one
/// changes **no** hash and **no** signature — which is the entire point and is
/// what makes a persist-side erasure non-inert on the wire.
///
/// **Fail direction, stated:** an absent disclosure set is indistinguishable
/// from a fully-erased one, and that is the correct direction for an erasure
/// feature. A peer that never received the disclosures sees an object whose
/// members are all gone — content unavailable, never content leaked and never
/// object rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureSet {
    /// Surviving disclosures, ascending by [`Disclosure::index`]. Absent index
    /// = erased.
    pub disclosures: Vec<Disclosure>,
}

impl DisclosureSet {
    /// Erase member `index`. Returns whether anything was there.
    ///
    /// **Idempotent** — a second call returns `false`, never an error. #573
    /// requirement 4, and the shape
    /// [`delete_traces_for_agent_id_hash`](crate::Engine::delete_traces_for_agent_id_hash)
    /// already demonstrates: a not-found is not an error for erasure.
    pub fn erase(&mut self, index: u32) -> bool {
        let before = self.disclosures.len();
        self.disclosures.retain(|d| d.index != index);
        self.disclosures.len() != before
    }

    /// Erase every member. The envelope survives as a proof that N members
    /// existed and are gone — which is what an erasure receipt should be.
    pub fn erase_all(&mut self) {
        self.disclosures.clear();
    }

    /// The surviving bytes of member `index`, or `None` if erased.
    #[must_use]
    pub fn member(&self, index: u32) -> Option<&[u8]> {
        self.disclosures
            .iter()
            .find(|d| d.index == index)
            .map(|d| d.bytes.as_slice())
    }

    /// Indices still disclosed, ascending.
    #[must_use]
    pub fn present_indices(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.disclosures.iter().map(|d| d.index).collect();
        v.sort_unstable();
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Mint
// ─────────────────────────────────────────────────────────────────────────

/// Mint an **erasable** object: `header` plus a commitment to `members`,
/// returning the envelope to sign and the disclosures to carry beside it.
///
/// The returned envelope is what gets hybrid-signed and stored in
/// `attestation_envelope` / `registration_envelope` / any other Axis-B
/// container. It contains the members' *digests* and never their bytes, so no
/// erasable payload is ever inside `original_content_hash`,
/// `compute_persist_row_hash`, or any signature.
///
/// # Errors
/// [`SealRefusal`] naming which branch refused.
pub fn seal(
    header: &serde_json::Value,
    members: &[Vec<u8>],
) -> Result<(serde_json::Value, DisclosureSet), SealRefusal> {
    let obj = header
        .as_object()
        .ok_or(SealRefusal::HeaderNotAnObject)?
        .clone();
    if obj.contains_key(SD_MEMBER) {
        return Err(SealRefusal::CommitmentSlotOccupied);
    }
    if members.is_empty() {
        return Err(SealRefusal::NoErasableMembers);
    }

    let commitment =
        RedactableCommitment::commit(members).map_err(|_| SealRefusal::SaltDrawRefused)?;

    let sealed = SealedCommitment {
        scheme: SD_SCHEME.to_owned(),
        root: hex::encode(commitment.root()),
        digests: commitment.digests.iter().map(hex::encode).collect(),
    };

    let mut envelope = serde_json::Value::Object(obj);
    // `SealedCommitment` is a plain struct of String/Vec<String>; the only way
    // to_value fails is an allocation failure, which serde_json does not model
    // as a recoverable error here.
    let value = serde_json::to_value(&sealed).map_err(|_| SealRefusal::HeaderNotAnObject)?;
    if let Some(m) = envelope.as_object_mut() {
        m.insert(SD_MEMBER.to_owned(), value);
    }

    Ok((
        envelope,
        DisclosureSet {
            disclosures: commitment.disclosures,
        },
    ))
}

// ─────────────────────────────────────────────────────────────────────────
//  Read + verify
// ─────────────────────────────────────────────────────────────────────────

/// Read an envelope's commitment.
///
/// [`CommitmentRefusal::CommitmentAbsent`] means **sealed**, which is a
/// verdict about the object and not a malfunction.
///
/// # Errors
/// [`CommitmentRefusal`] naming which branch refused.
pub fn read_commitment(
    envelope: &serde_json::Value,
) -> Result<SealedCommitment, CommitmentRefusal> {
    let obj = envelope
        .as_object()
        .ok_or(CommitmentRefusal::EnvelopeNotAnObject)?;
    let raw = obj
        .get(SD_MEMBER)
        .ok_or(CommitmentRefusal::CommitmentAbsent)?;
    let sealed: SealedCommitment =
        serde_json::from_value(raw.clone()).map_err(|_| CommitmentRefusal::CommitmentMalformed)?;
    if sealed.scheme != SD_SCHEME {
        return Err(CommitmentRefusal::SchemeUnknown);
    }
    if sealed.digests.is_empty() {
        return Err(CommitmentRefusal::NoErasableMembers);
    }
    if decode_digest(&sealed.root).is_none()
        || sealed.digests.iter().any(|d| decode_digest(d).is_none())
    {
        return Err(CommitmentRefusal::DigestMalformed);
    }
    Ok(sealed)
}

/// Whether this envelope was minted erasable.
///
/// Cheap and total — the question every read surface should be able to ask
/// without handling an error type.
#[must_use]
pub fn is_erasable(envelope: &serde_json::Value) -> bool {
    read_commitment(envelope).is_ok()
}

/// Verify `set` against the commitment carried in `envelope`, reporting each
/// member's state.
///
/// This is where *redacted* and *tampered* become different observables: a
/// slot with no disclosure is [`MemberState::Redacted`]; a slot whose
/// disclosure does not reproduce its digest is
/// [`RedactionError::DigestMismatch`]. Neither requires trusting anyone's
/// assertion — which is what CC ruled the signed-discriminator shape out for.
///
/// # Errors
/// [`VerifyMembersError`] — either the commitment was unreadable, or the
/// disclosures failed against it.
pub fn verify_members(
    envelope: &serde_json::Value,
    set: &DisclosureSet,
) -> Result<Vec<MemberState>, VerifyMembersError> {
    let sealed = read_commitment(envelope).map_err(VerifyMembersError::Commitment)?;
    // Every entry decoded during `read_commitment`, so `expect` is unreachable
    // rather than optimistic.
    let digests: Vec<[u8; 32]> = sealed
        .digests
        .iter()
        .map(|d| decode_digest(d).expect("read_commitment validated every digest"))
        .collect();
    let root = decode_digest(&sealed.root).expect("read_commitment validated the root");

    let commitment = RedactableCommitment {
        digests,
        disclosures: set.disclosures.clone(),
    };
    commitment
        .verify(&root)
        .map_err(VerifyMembersError::Redaction)
}

/// Which member indices have no surviving disclosure — what an operator needs
/// to see *which* members were erased, not merely that some were.
///
/// Answerable from the envelope plus whatever disclosures survive, so a peer
/// that holds the envelope alone reports every member erased. That is honest:
/// from its position they are.
///
/// # Errors
/// [`CommitmentRefusal`] if the envelope carries no readable commitment.
pub fn erased_indices(
    envelope: &serde_json::Value,
    set: &DisclosureSet,
) -> Result<Vec<u32>, CommitmentRefusal> {
    let sealed = read_commitment(envelope)?;
    let count = u32::try_from(sealed.digests.len()).unwrap_or(u32::MAX);
    Ok((0..count)
        .filter(|i| !set.disclosures.iter().any(|d| d.index == *i))
        .collect())
}

fn decode_digest(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 || !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

// ─────────────────────────────────────────────────────────────────────────
//  Recognition without retention — the opt-in, never the default
// ─────────────────────────────────────────────────────────────────────────

/// Whether an erasure also publishes an **unsalted** hash of the erased bytes,
/// so other nodes can decline the same payload sight-unseen (#573's
/// recognition-without-retention).
///
/// [`Self::Withheld`] is the default and is what every erasure gets unless an
/// operator says otherwise, because publishing an unsalted hash of
/// low-entropy content **discloses it** — the exact attack the per-member salt
/// exists to close. The two properties #573 asks for are not jointly
/// satisfiable in general; this type is where the trade-off is made
/// deliberately instead of by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionPolicy {
    /// Publish nothing. The salted member digest still survives in the signed
    /// envelope as the tombstone; it reveals nothing about the value.
    Withheld,
    /// The operator asserts the erased bytes carry enough entropy that
    /// publishing `sha256` of them does not disclose them.
    ///
    /// **Persist cannot check this** and does not pretend to — it checks
    /// [`RECOGNITION_MIN_BYTES`] and nothing more. The assertion is the
    /// operator's, and it should be recorded as theirs on the
    /// `hard_case:admin_action` row that attributes the erasure.
    OperatorAssertsHighEntropy,
}

/// **WHICH branch refused** to publish a recognition hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionRefusal {
    /// [`RecognitionPolicy::Withheld`] — the default, and not a malfunction.
    Withheld,
    /// Below [`RECOGNITION_MIN_BYTES`]. The operator asserted high entropy over
    /// content short enough that the assertion is not credible on its face.
    BelowLengthFloor,
}

impl RecognitionRefusal {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Withheld => "withheld",
            Self::BelowLengthFloor => "below_length_floor",
        }
    }
}

impl std::fmt::Display for RecognitionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The publishable, **unsalted** `sha256(`[`RECOGNITION_DOMAIN`]` ‖ bytes)` of
/// erased content — computable by any node holding the same bytes, which is
/// what makes recognition possible and what makes it dangerous.
///
/// # Errors
/// [`RecognitionRefusal`] — withheld by policy, or below the length floor.
pub fn recognition_hash(
    bytes: &[u8],
    policy: RecognitionPolicy,
) -> Result<String, RecognitionRefusal> {
    if policy == RecognitionPolicy::Withheld {
        return Err(RecognitionRefusal::Withheld);
    }
    if bytes.len() < RECOGNITION_MIN_BYTES {
        return Err(RecognitionRefusal::BelowLengthFloor);
    }
    let mut h = Sha256::new();
    h.update(RECOGNITION_DOMAIN);
    h.update(bytes);
    Ok(hex::encode(h.finalize()))
}

impl ciris_verify_core::classification::Classification for RecognitionRefusal {
    /// **MEASUREMENT.** [`Self::BelowLengthFloor`] is the one thing persist can
    /// actually check, and it is a length, not an entropy estimate.
    ///
    /// Tagged so the inverse is not read as a ruling: `Ok(hash)` means *"the
    /// operator asserted high entropy and the bytes cleared a mechanical
    /// floor"*, **never** *"publishing this hash is safe"*. Whether it is safe
    /// is a policy the deployment owns, over this measurement — the CC
    /// composition-context discipline, and the reason
    /// [`RecognitionPolicy::Withheld`] is the default.
    fn gating() -> ciris_verify_core::classification::Gating {
        ciris_verify_core::classification::Gating::Measurement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> serde_json::Value {
        serde_json::json!({
            "id": "att-erasable-1",
            "kind": "scores",
            "dimension": "moderation:report",
        })
    }

    fn members() -> Vec<Vec<u8>> {
        vec![
            b"the reported account".to_vec(),
            // Low entropy — the case an UNSALTED digest would leak, and the
            // case a takedown's own `reason` field usually is.
            b"true".to_vec(),
            b"2026-08-03".to_vec(),
        ]
    }

    #[test]
    fn a_sealed_envelope_reports_sealed_rather_than_broken() {
        let env = header();
        assert_eq!(
            read_commitment(&env).unwrap_err(),
            CommitmentRefusal::CommitmentAbsent,
            "an object minted without a commitment is SEALED — a verdict, not a fault"
        );
        assert!(!is_erasable(&env));
    }

    #[test]
    fn sealing_puts_digests_in_the_envelope_and_bytes_nowhere_near_it() {
        let (env, set) = seal(&header(), &members()).unwrap();
        assert!(is_erasable(&env));

        let canonical = serde_json::to_string(&env).unwrap();
        for m in members() {
            let plain = String::from_utf8(m).unwrap();
            assert!(
                !canonical.contains(&plain),
                "member {plain:?} leaked into the signed envelope"
            );
        }
        assert_eq!(set.present_indices(), vec![0, 1, 2]);
        assert_eq!(set.member(1), Some(&b"true"[..]));
    }

    #[test]
    fn seal_refuses_the_four_branches_it_names() {
        assert_eq!(
            seal(&serde_json::json!("not an object"), &members()).unwrap_err(),
            SealRefusal::HeaderNotAnObject
        );
        assert_eq!(
            seal(&header(), &[]).unwrap_err(),
            SealRefusal::NoErasableMembers
        );
        let (once, _) = seal(&header(), &members()).unwrap();
        assert_eq!(
            seal(&once, &members()).unwrap_err(),
            SealRefusal::CommitmentSlotOccupied,
            "double-sealing would silently discard the first commitment"
        );
    }

    /// The property the module exists for, at the member level: after erasure
    /// the envelope is **unchanged** and the erased member reports as redacted
    /// rather than as tampering.
    #[test]
    fn erasure_leaves_the_envelope_byte_identical() {
        let (env, mut set) = seal(&header(), &members()).unwrap();
        let before = crate::verify::canonical::ceg_produce_canonicalize(&env).unwrap();

        assert!(set.erase(1));
        let after = crate::verify::canonical::ceg_produce_canonicalize(&env).unwrap();
        assert_eq!(before, after, "erasure must not move the signed bytes");

        let state = verify_members(&env, &set).unwrap();
        assert_eq!(state[0], MemberState::Disclosed);
        assert_eq!(state[1], MemberState::Redacted);
        assert_eq!(state[2], MemberState::Disclosed);
        assert_eq!(erased_indices(&env, &set).unwrap(), vec![1]);
        assert_eq!(set.member(1), None);
    }

    #[test]
    fn erasure_is_idempotent_and_tolerates_unknown_indices() {
        let (env, mut set) = seal(&header(), &members()).unwrap();
        assert!(set.erase(1));
        assert!(!set.erase(1), "a second erase is a no-op, never an error");
        assert!(!set.erase(99));
        assert!(verify_members(&env, &set).is_ok());
    }

    /// Redaction and tampering are DIFFERENT observables — verify's property,
    /// re-asserted through persist's envelope-shaped surface because that is
    /// the surface persist's callers use.
    #[test]
    fn tampering_is_distinguishable_from_erasure() {
        let (env, mut set) = seal(&header(), &members()).unwrap();
        set.disclosures[0].bytes = b"a different account".to_vec();
        assert_eq!(
            verify_members(&env, &set).unwrap_err(),
            VerifyMembersError::Redaction(RedactionError::DigestMismatch { index: 0 })
        );
    }

    /// CC's count commitment, reached through the envelope: a member cannot be
    /// dropped from the *commitment*, only from the disclosures.
    #[test]
    fn shrinking_the_committed_member_set_is_a_root_mismatch() {
        let (mut env, set) = seal(&header(), &members()).unwrap();
        env.as_object_mut()
            .unwrap()
            .get_mut(SD_MEMBER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("digests")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(
            verify_members(&env, &set).unwrap_err(),
            VerifyMembersError::Redaction(RedactionError::RootMismatch)
        );
    }

    /// A fully-erased object still verifies — it becomes a proof that N
    /// members existed and are gone.
    #[test]
    fn a_fully_erased_object_still_verifies() {
        let (env, mut set) = seal(&header(), &members()).unwrap();
        set.erase_all();
        assert_eq!(
            verify_members(&env, &set).unwrap(),
            vec![MemberState::Redacted; 3]
        );
        assert_eq!(erased_indices(&env, &set).unwrap(), vec![0, 1, 2]);
    }

    /// **Why salts, restated at persist's boundary.** After total erasure the
    /// envelope is all that survives — and it must not yield a low-entropy
    /// member to a dictionary.
    #[test]
    fn a_low_entropy_member_is_not_recoverable_from_the_surviving_envelope() {
        let (env, mut set) = seal(&header(), &[b"true".to_vec()]).unwrap();
        set.erase_all();
        let committed = read_commitment(&env).unwrap();

        for guess in [&b"true"[..], b"false", b"1", b"0", b"yes", b"no"] {
            let unsalted = {
                let mut h = Sha256::new();
                h.update(ciris_verify_core::redactable::MEMBER_DOMAIN);
                h.update(0u32.to_be_bytes());
                h.update(0u32.to_be_bytes());
                h.update(guess);
                hex::encode(h.finalize())
            };
            assert_ne!(
                unsalted, committed.digests[0],
                "the salt is what stops the surviving digest from BEING the value"
            );
        }
    }

    #[test]
    fn commitment_reader_refuses_rather_than_guesses() {
        let (env, _) = seal(&header(), &members()).unwrap();
        let with = |slot: serde_json::Value| {
            let mut e = env.clone();
            e.as_object_mut()
                .unwrap()
                .insert(SD_MEMBER.to_owned(), slot);
            e
        };

        let mut wrong_scheme = env.get(SD_MEMBER).unwrap().clone();
        wrong_scheme.as_object_mut().unwrap().insert(
            "scheme".to_owned(),
            serde_json::json!("ciris.redactable.v2"),
        );
        assert_eq!(
            read_commitment(&with(wrong_scheme)).unwrap_err(),
            CommitmentRefusal::SchemeUnknown,
            "an unknown scheme is refused, never interpreted under this one"
        );

        assert_eq!(
            read_commitment(&with(serde_json::json!({"nope": 1}))).unwrap_err(),
            CommitmentRefusal::CommitmentMalformed
        );

        assert_eq!(
            read_commitment(&with(
                serde_json::json!({"scheme": SD_SCHEME, "root": "zz", "digests": ["aa"]})
            ))
            .unwrap_err(),
            CommitmentRefusal::DigestMalformed
        );

        assert_eq!(
            read_commitment(&with(
                serde_json::json!({"scheme": SD_SCHEME, "root": "0".repeat(64), "digests": []})
            ))
            .unwrap_err(),
            CommitmentRefusal::NoErasableMembers
        );
    }

    // ── recognition without retention ────────────────────────────────────

    #[test]
    fn recognition_is_withheld_by_default() {
        assert_eq!(
            recognition_hash(&[0u8; 128], RecognitionPolicy::Withheld).unwrap_err(),
            RecognitionRefusal::Withheld,
            "publishing an unsalted hash is never the default"
        );
    }

    #[test]
    fn recognition_refuses_content_short_enough_to_be_enumerable() {
        assert_eq!(
            recognition_hash(b"true", RecognitionPolicy::OperatorAssertsHighEntropy).unwrap_err(),
            RecognitionRefusal::BelowLengthFloor
        );
        let long = vec![7u8; RECOGNITION_MIN_BYTES];
        assert!(recognition_hash(&long, RecognitionPolicy::OperatorAssertsHighEntropy).is_ok());
    }

    /// The recognition hash must be reproducible by **another** node from the
    /// same bytes — that is the whole capability — and must not collide with a
    /// member commitment.
    #[test]
    fn recognition_is_reproducible_and_domain_separated() {
        let bytes = vec![3u8; 200];
        let a = recognition_hash(&bytes, RecognitionPolicy::OperatorAssertsHighEntropy).unwrap();
        let b = recognition_hash(&bytes, RecognitionPolicy::OperatorAssertsHighEntropy).unwrap();
        assert_eq!(a, b, "no salt — that is the point, and the danger");

        let (_, set) = seal(&header(), std::slice::from_ref(&bytes)).unwrap();
        assert_ne!(a, hex::encode(set.disclosures[0].digest()));
    }

    /// Two seals over identical members differ — fresh salts, so a digest
    /// cannot be correlated across objects to re-identify erased content.
    #[test]
    fn identical_members_seal_differently() {
        let (a, _) = seal(&header(), &members()).unwrap();
        let (b, _) = seal(&header(), &members()).unwrap();
        assert_ne!(
            read_commitment(&a).unwrap().root,
            read_commitment(&b).unwrap().root
        );
    }

    #[test]
    fn refusal_tokens_round_trip_through_serde() {
        for (r, tok) in [
            (SealRefusal::HeaderNotAnObject, "header_not_an_object"),
            (
                SealRefusal::CommitmentSlotOccupied,
                "commitment_slot_occupied",
            ),
            (SealRefusal::NoErasableMembers, "no_erasable_members"),
            (SealRefusal::SaltDrawRefused, "salt_draw_refused"),
        ] {
            assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(tok));
            assert_eq!(r.as_str(), tok);
        }
        for (r, tok) in [
            (
                CommitmentRefusal::EnvelopeNotAnObject,
                "envelope_not_an_object",
            ),
            (CommitmentRefusal::CommitmentAbsent, "commitment_absent"),
            (
                CommitmentRefusal::CommitmentMalformed,
                "commitment_malformed",
            ),
            (CommitmentRefusal::SchemeUnknown, "scheme_unknown"),
            (CommitmentRefusal::DigestMalformed, "digest_malformed"),
            (CommitmentRefusal::NoErasableMembers, "no_erasable_members"),
        ] {
            assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(tok));
            assert_eq!(r.as_str(), tok);
        }
        for (r, tok) in [
            (RecognitionRefusal::Withheld, "withheld"),
            (RecognitionRefusal::BelowLengthFloor, "below_length_floor"),
        ] {
            assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(tok));
            assert_eq!(r.as_str(), tok);
        }
    }
}
