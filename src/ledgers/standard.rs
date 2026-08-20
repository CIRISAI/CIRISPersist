//! CC 3.3.10.1 (1.0-rc4.3) — in-grammar ledgers: the pure half.
//!
//! CIRISConstitution#92 designates ledgers as owner-serialized *content*:
//! total order lives in the ledger's own hash chain, never in the grammar,
//! and conservation is a deterministic fold the cohort verifies byte-equal.
//! This module is CIRISPersist#754's items 2, 3 and 4 — every function here
//! is pure, so that a fold result or a fork proof is **transferable
//! evidence**: any member recomputes it from the same bytes without trusting
//! the accuser (L7's stated rationale).
//!
//! What lives here:
//!
//! * **L1** — [`derive_ledger_id`]: the deterministic `(steward-bound
//!   identity, unit, standard_version)` → `ledger_id` derivation. The
//!   admission door refuses a second ledger on an occupied triple
//!   (fail-secure, settled by the rc4.3 text); the derivation lives here so
//!   the refusal and the claimant compute the same id.
//! * **L2/L6** — [`entry_content_hash`], [`verify_chain_from_genesis`],
//!   [`verify_chain_from_checkpoint`]: dense-sequence prev-hash chain
//!   validity, the promotion compliance proof's substance.
//! * **L7** — [`conservation_fold`] + [`fold_canonical_bytes`]: pure,
//!   integer-only, byte-equal across members. Matched `transfer` pairs sum
//!   to zero; an unmatched or mismatched pair is FLAGGED, never merged away.
//! * **L8** — [`detect_double_head`], [`contradicts_witnessed_ancestor`]:
//!   proven-fork detection. Detection **records**; it never fires
//!   `slashing:*` — adjudication distinguishes equivocation from honest
//!   stale-state recovery (the same admission-of-ignorance vs accusation
//!   line CIRISPersist#713 protects on the withhold plane).
//!
//! # The canonicalization pin
//!
//! Every preimage in this module routes through
//! [`CanonVersion::V2Jcs`] **explicitly** — never through
//! `produce_canon_version()`. That dispatch exists so the *envelope produce
//! path* can migrate canonicalizers; a ledger hash is a stored contract, and
//! riding a version switch would move every entry hash in the field on the
//! day the switch flips. Same reasoning as `compute_persist_row_hash`'s pin:
//! a deliberate flip is an in-place rewrite decision, taken loudly, never a
//! side effect.
//!
//! # What is deliberately NOT here
//!
//! Signature verification (the door verifies owner/delegate signatures
//! against the directory — async, not pure), the witness chain itself
//! (edge's CC 5.4.5 plane; persist stores opaque `witness_anchor_ref`
//! pointers), and any substrate enforcement of conservation — L7 is a
//! computation members verify, not a primitive the substrate enforces.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::verify::canonical::{canonicalizer_for, CanonVersion};

/// The ledger standard version this module implements (the third member of
/// the L1 binding triple). rc4.3's nine clauses are version `"1"`.
pub const LEDGER_STANDARD_VERSION: &str = "1";

/// Errors from the pure ledger surface.
///
/// Canonicalization of the `serde_json::Value`s this module constructs
/// cannot fail on well-formed input, but the canonicalizer's contract says
/// `Result` and an `unwrap` in library code converts a future canonicalizer
/// change into a panic in the field — so it is surfaced, not swallowed.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The pinned canonicalizer refused a value — unreachable for
    /// well-formed input, surfaced rather than unwrapped.
    #[error("ledger canonicalization: {0}")]
    Canonical(String),
}

// ─────────────────────────────────────────────────────────────────────────
// L1 — binding
// ─────────────────────────────────────────────────────────────────────────

/// Derive the `ledger_id` for a `(steward-bound identity, unit,
/// standard_version)` triple — L1's "derives deterministically".
///
/// The preimage is the pinned-JCS serialization of a domain-tagged object,
/// so no concatenation ambiguity exists between the three members (JSON
/// string escaping is injective). The result is stable forever: it is the
/// admission key that refuses parallel books, and it is what a genesis
/// entry's `prev_hash` must equal ([`verify_chain_from_genesis`]), binding
/// the chain to the triple it claims.
pub fn derive_ledger_id(
    steward_identity_key_id: &str,
    unit: &str,
    standard_version: &str,
) -> Result<String, LedgerError> {
    let preimage = serde_json::json!({
        "domain": "ciris.ledger.id.v1",
        "identity": steward_identity_key_id,
        "standard_version": standard_version,
        "unit": unit,
    });
    Ok(format!("ledger-{}", sha256_hex(&pinned_jcs(&preimage)?)))
}

// ─────────────────────────────────────────────────────────────────────────
// L2 — entries
// ─────────────────────────────────────────────────────────────────────────

/// Which side of a `transfer` this entry records, on its own ledger.
///
/// L2's `transfer` kind carries the counterparty and a matching reference;
/// the pair sums to zero because each side records its own half — the
/// outgoing half debits its ledger, the incoming half credits its ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    /// This ledger sends: the amount debits it.
    Outgoing,
    /// This ledger receives: the amount credits it.
    Incoming,
}

#[allow(missing_docs)] // field names are the documentation on plain data shapes
/// L2's three entry kinds. `credit` and `debit` are unilateral facts;
/// `transfer` names its counterparty ledger and the matching reference that
/// pairs the two halves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerEntryKind {
    Credit,
    Debit,
    Transfer {
        counterparty_ledger_id: String,
        matching_ref: String,
        direction: TransferDirection,
    },
}

/// One ledger entry — the hash-chained content, WITHOUT its signature.
///
/// The owner-or-delegate signature covers [`entry_content_hash`] and rides
/// alongside ([`SignedLedgerEntry`]); it is excluded from the preimage
/// because a signature cannot cover itself, and excluded from the chain
/// links so that re-signing identical content is not a fork.
///
/// An entry is a monotonic fact — forward-only, never reversed. A dispute
/// or refund is a NEW entry naming the old one in `refs` (L2: leaving
/// doesn't un-pay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// The ledger this entry extends — a [`derive_ledger_id`] output.
    pub ledger_id: String,
    /// Dense `u64` sequence: genesis is 0, every successor is +1.
    pub seq: u64,
    /// [`entry_content_hash`] of the predecessor; for seq 0 this is the
    /// `ledger_id` itself, binding the chain to its L1 triple.
    pub prev_hash: String,
    /// The entry kind, flattened into the content projection (`kind` +
    /// the transfer fields when present).
    #[serde(flatten)]
    pub kind: LedgerEntryKind,
    /// Integer minor units — L7 is integer-only by clause.
    pub amount_minor: u64,
    /// The ledger's unit; L1 binds one unit per ledger, so a divergent unit
    /// mid-chain is a violation, not a feature.
    pub unit: String,
    /// References to prior entries or external evidence (the dispute/refund
    /// mechanism). ALWAYS serialized, even when empty — an omitted-iff-empty
    /// field read back by JSON key collapses "absent" and "default", the
    /// exact CIRISPersist#727 shape, and this is a hash preimage where that
    /// ambiguity would be permanent.
    pub refs: Vec<String>,
}

#[allow(missing_docs)] // field names are the documentation on plain data shapes
/// An entry together with its owner-or-delegate signature material.
///
/// This module does NOT verify these signatures — the admission door does,
/// against the directory (hybrid, per the federation-tier rule). They are
/// carried so fork evidence is complete: L8's proof is two owner-SIGNED
/// heads, and evidence that drops the signatures stops being transferable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLedgerEntry {
    pub entry: LedgerEntry,
    pub signature_key_id: String,
    pub signature_classical_base64: String,
    pub signature_pqc_base64: Option<String>,
}

/// The pinned content projection an entry is hashed over.
///
/// Built by hand rather than via serde so the field SET is a literal in this
/// function and in the gate test below — the v37.0.0 field-set discipline:
/// one future serializing field silently moving every stored hash is the
/// class this prevents, and a derive would hide the set in attribute soup.
fn entry_content_value(e: &LedgerEntry) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("amount_minor".into(), e.amount_minor.into());
    match &e.kind {
        LedgerEntryKind::Credit => {
            m.insert("kind".into(), "credit".into());
        }
        LedgerEntryKind::Debit => {
            m.insert("kind".into(), "debit".into());
        }
        LedgerEntryKind::Transfer {
            counterparty_ledger_id,
            matching_ref,
            direction,
        } => {
            m.insert("kind".into(), "transfer".into());
            m.insert(
                "counterparty_ledger_id".into(),
                counterparty_ledger_id.as_str().into(),
            );
            m.insert("matching_ref".into(), matching_ref.as_str().into());
            m.insert(
                "direction".into(),
                match direction {
                    TransferDirection::Outgoing => "outgoing".into(),
                    TransferDirection::Incoming => "incoming".into(),
                },
            );
        }
    }
    m.insert("ledger_id".into(), e.ledger_id.as_str().into());
    m.insert("prev_hash".into(), e.prev_hash.as_str().into());
    m.insert(
        "refs".into(),
        serde_json::Value::Array(e.refs.iter().map(|r| r.as_str().into()).collect()),
    );
    m.insert("seq".into(), e.seq.into());
    m.insert("unit".into(), e.unit.as_str().into());
    serde_json::Value::Object(m)
}

/// SHA-256 over the pinned-JCS bytes of the entry's content projection,
/// lowercase hex. This is the chain link ([`LedgerEntry::prev_hash`]) and
/// the thing a witness anchor pins.
pub fn entry_content_hash(e: &LedgerEntry) -> Result<String, LedgerError> {
    Ok(sha256_hex(&pinned_jcs(&entry_content_value(e))?))
}

// ─────────────────────────────────────────────────────────────────────────
// L2/L6 — chain validity (the promotion proof's substance)
// ─────────────────────────────────────────────────────────────────────────

#[allow(missing_docs)] // field names are the documentation on plain data shapes
/// A validated chain's head — what L4 commits to the witness chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    pub ledger_id: String,
    pub seq: u64,
    pub head_hash: String,
    pub unit: String,
}

#[allow(missing_docs)] // field names are the documentation on plain data shapes
/// Why a chain failed validation. Typed, one variant per distinct fact —
/// collapsing them is how four defects once looked like one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainViolation {
    #[error("chain is empty — nothing to validate")]
    Empty,
    #[error("entry at index {index} carries ledger_id {found}, chain is {expected}")]
    LedgerIdMismatch {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("entry at seq {seq} carries unit {found}, ledger is bound to {expected}")]
    UnitMismatch {
        seq: u64,
        expected: String,
        found: String,
    },
    #[error("sequence gap: expected seq {expected}, found {found}")]
    SeqGap { expected: u64, found: u64 },
    #[error("prev_hash mismatch at seq {seq}: chain says {expected}, entry says {found}")]
    PrevHashMismatch {
        seq: u64,
        expected: String,
        found: String,
    },
    #[error("ledger canonicalization failed during replay: {0}")]
    Canonical(String),
}

/// Validate a chain from its genesis: seq 0, `prev_hash == ledger_id`
/// (binding the chain to its L1 triple), then dense seq + hash links.
pub fn verify_chain_from_genesis(entries: &[LedgerEntry]) -> Result<ChainHead, ChainViolation> {
    let first = entries.first().ok_or(ChainViolation::Empty)?;
    verify_chain(entries, 0, &first.ledger_id)
}

/// Validate a chain from the latest witnessed checkpoint forward — L6's
/// compliance proof: the first entry must be `checkpoint_seq + 1` and link
/// to the checkpointed head hash. Conservation is provable from here.
pub fn verify_chain_from_checkpoint(
    checkpoint_seq: u64,
    checkpointed_head_hash: &str,
    entries: &[LedgerEntry],
) -> Result<ChainHead, ChainViolation> {
    verify_chain(entries, checkpoint_seq + 1, checkpointed_head_hash)
}

fn verify_chain(
    entries: &[LedgerEntry],
    expected_first_seq: u64,
    expected_first_prev: &str,
) -> Result<ChainHead, ChainViolation> {
    let first = entries.first().ok_or(ChainViolation::Empty)?;
    let ledger_id = first.ledger_id.clone();
    let unit = first.unit.clone();

    let mut expected_seq = expected_first_seq;
    let mut expected_prev = expected_first_prev.to_string();
    let mut head_hash = String::new();

    for (index, e) in entries.iter().enumerate() {
        if e.ledger_id != ledger_id {
            return Err(ChainViolation::LedgerIdMismatch {
                index,
                expected: ledger_id,
                found: e.ledger_id.clone(),
            });
        }
        if e.unit != unit {
            return Err(ChainViolation::UnitMismatch {
                seq: e.seq,
                expected: unit,
                found: e.unit.clone(),
            });
        }
        if e.seq != expected_seq {
            return Err(ChainViolation::SeqGap {
                expected: expected_seq,
                found: e.seq,
            });
        }
        if e.prev_hash != expected_prev {
            return Err(ChainViolation::PrevHashMismatch {
                seq: e.seq,
                expected: expected_prev,
                found: e.prev_hash.clone(),
            });
        }
        head_hash =
            entry_content_hash(e).map_err(|err| ChainViolation::Canonical(err.to_string()))?;
        expected_prev = head_hash.clone();
        expected_seq += 1;
    }

    Ok(ChainHead {
        ledger_id,
        seq: expected_seq - 1,
        head_hash,
        unit,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// L7 — the conservation fold
// ─────────────────────────────────────────────────────────────────────────

#[allow(missing_docs)] // variant docs above each arm; payload field names are the documentation
/// A violation the fold FLAGS and never merges away. Ordered so the flag
/// list itself is canonical (byte-equal output requires a total order).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "flag", rename_all = "snake_case")]
pub enum FoldFlag {
    /// Two entries at one `(ledger_id, seq)` with DIFFERENT content — the
    /// fork shape. Neither can be trusted, so both are excluded from the
    /// net and the fact is reported. Evidence assembly is L8's job.
    ForkShapedSequence { ledger_id: String, seq: u64 },
    /// Byte-identical duplicate in the input set: counted once, reported.
    DuplicateEntry { ledger_id: String, seq: u64 },
    /// Entry's unit differs from its ledger's binding unit (lowest
    /// surviving seq defines it). Excluded from the net.
    UnitMismatch { ledger_id: String, seq: u64 },
    /// A `matching_ref` carried by exactly one transfer half.
    UnmatchedTransfer {
        ledger_id: String,
        seq: u64,
        matching_ref: String,
    },
    /// A `matching_ref` carried by more than two entries.
    OverloadedMatchingRef { matching_ref: String, count: u64 },
    /// Both halves of a pair record the same direction.
    DirectionCollision { matching_ref: String },
    /// The halves do not name each other's ledgers.
    CounterpartyMismatch { matching_ref: String },
    /// The halves disagree on amount — the pair does NOT sum to zero.
    AmountMismatch { matching_ref: String },
    /// The halves disagree on unit.
    UnitMismatchPair { matching_ref: String },
}

/// One ledger's net position in the fold result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPosition {
    /// The ledger's bound unit.
    pub unit: String,
    /// Decimal string, not a JSON number: i128 does not survive every JSON
    /// number path byte-identically, and the entire point of this struct is
    /// byte equality across independent implementations.
    pub net_minor: String,
}

/// The fold result — [`fold_canonical_bytes`] is the byte-equal contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConservationFold {
    /// Net per ledger, keyed by `ledger_id` (BTreeMap: canonical order).
    pub nets: BTreeMap<String, NetPosition>,
    /// Every violation observed, in canonical order. FLAGGED, never merged.
    pub flags: Vec<FoldFlag>,
    /// Entries that survived dedup/fork exclusion and contributed to nets
    /// (unit-mismatched entries are excluded and NOT counted here).
    pub entry_count: u64,
}

/// L7 — the deterministic, integer-only conservation fold.
///
/// Input order is irrelevant: entries are canonicalized internally, so two
/// members folding the same set in different arrival orders produce
/// byte-equal results. The fold reports; it never repairs:
///
/// * fork-shaped `(ledger_id, seq)` groups are excluded and flagged;
/// * byte-identical duplicates are counted once and flagged;
/// * unit-divergent entries are excluded and flagged;
/// * transfer halves are paired by `matching_ref` — a valid pair is exactly
///   two halves, opposite directions, cross-naming each other's ledgers,
///   equal amount and unit. Every deviation is a typed flag, and the
///   deviant entries still contribute to their OWN ledger's net (the ledger
///   says what it says; the flag says it is in violation).
pub fn conservation_fold(entries: &[LedgerEntry]) -> Result<ConservationFold, LedgerError> {
    let mut flags: Vec<FoldFlag> = Vec::new();

    // Canonical internal order + hash every entry once.
    let mut hashed: Vec<(String, &LedgerEntry)> = entries
        .iter()
        .map(|e| Ok((entry_content_hash(e)?, e)))
        .collect::<Result<_, LedgerError>>()?;
    hashed.sort_by(|a, b| (&a.1.ledger_id, a.1.seq, &a.0).cmp(&(&b.1.ledger_id, b.1.seq, &b.0)));

    // Dedup + fork exclusion per (ledger_id, seq).
    let mut surviving: Vec<&LedgerEntry> = Vec::new();
    let mut i = 0;
    while i < hashed.len() {
        let (_, first) = &hashed[i];
        let mut j = i;
        while j < hashed.len()
            && hashed[j].1.ledger_id == first.ledger_id
            && hashed[j].1.seq == first.seq
        {
            j += 1;
        }
        let group = &hashed[i..j];
        let distinct: std::collections::BTreeSet<&str> =
            group.iter().map(|(h, _)| h.as_str()).collect();
        if distinct.len() > 1 {
            flags.push(FoldFlag::ForkShapedSequence {
                ledger_id: first.ledger_id.clone(),
                seq: first.seq,
            });
        } else {
            if group.len() > 1 {
                flags.push(FoldFlag::DuplicateEntry {
                    ledger_id: first.ledger_id.clone(),
                    seq: first.seq,
                });
            }
            surviving.push(group[0].1);
        }
        i = j;
    }

    // Unit binding per ledger: the lowest surviving seq defines the unit.
    let mut ledger_unit: BTreeMap<&str, &str> = BTreeMap::new();
    for e in &surviving {
        ledger_unit.entry(&e.ledger_id).or_insert(&e.unit);
    }
    let mut counted: Vec<&LedgerEntry> = Vec::new();
    for e in surviving {
        if ledger_unit[e.ledger_id.as_str()] != e.unit {
            flags.push(FoldFlag::UnitMismatch {
                ledger_id: e.ledger_id.clone(),
                seq: e.seq,
            });
        } else {
            counted.push(e);
        }
    }

    // Transfer pairing by matching_ref, over counted entries.
    let mut by_ref: BTreeMap<&str, Vec<&LedgerEntry>> = BTreeMap::new();
    for e in &counted {
        if let LedgerEntryKind::Transfer { matching_ref, .. } = &e.kind {
            by_ref.entry(matching_ref).or_default().push(e);
        }
    }
    for (mref, halves) in &by_ref {
        match halves.as_slice() {
            [one] => {
                flags.push(FoldFlag::UnmatchedTransfer {
                    ledger_id: one.ledger_id.clone(),
                    seq: one.seq,
                    matching_ref: (*mref).to_string(),
                });
            }
            [a, b] => {
                let (
                    LedgerEntryKind::Transfer {
                        counterparty_ledger_id: a_cp,
                        direction: a_dir,
                        ..
                    },
                    LedgerEntryKind::Transfer {
                        counterparty_ledger_id: b_cp,
                        direction: b_dir,
                        ..
                    },
                ) = (&a.kind, &b.kind)
                else {
                    unreachable!("by_ref only holds Transfer entries");
                };
                if a_dir == b_dir {
                    flags.push(FoldFlag::DirectionCollision {
                        matching_ref: (*mref).to_string(),
                    });
                }
                if !(a_cp == &b.ledger_id && b_cp == &a.ledger_id) {
                    flags.push(FoldFlag::CounterpartyMismatch {
                        matching_ref: (*mref).to_string(),
                    });
                }
                if a.amount_minor != b.amount_minor {
                    flags.push(FoldFlag::AmountMismatch {
                        matching_ref: (*mref).to_string(),
                    });
                }
                if a.unit != b.unit {
                    flags.push(FoldFlag::UnitMismatchPair {
                        matching_ref: (*mref).to_string(),
                    });
                }
            }
            many => {
                flags.push(FoldFlag::OverloadedMatchingRef {
                    matching_ref: (*mref).to_string(),
                    count: many.len() as u64,
                });
            }
        }
    }

    // Nets. Integer-only: u64 amounts accumulated in i128 — no overflow is
    // reachable (each |delta| ≤ u64::MAX and i128 holds ±2^64 · 2^63 sums).
    let mut nets: BTreeMap<String, NetPosition> = BTreeMap::new();
    for e in &counted {
        let delta: i128 = match &e.kind {
            LedgerEntryKind::Credit => i128::from(e.amount_minor),
            LedgerEntryKind::Debit => -i128::from(e.amount_minor),
            LedgerEntryKind::Transfer { direction, .. } => match direction {
                TransferDirection::Incoming => i128::from(e.amount_minor),
                TransferDirection::Outgoing => -i128::from(e.amount_minor),
            },
        };
        let pos = nets
            .entry(e.ledger_id.clone())
            .or_insert_with(|| NetPosition {
                unit: e.unit.clone(),
                net_minor: "0".to_string(),
            });
        let current: i128 = pos
            .net_minor
            .parse()
            .expect("net_minor is only ever written by this fold");
        pos.net_minor = (current + delta).to_string();
    }

    flags.sort();
    Ok(ConservationFold {
        nets,
        flags,
        entry_count: counted.len() as u64,
    })
}

/// The byte-equal contract: pinned-JCS bytes of the fold result. Two
/// members' results are compared on THESE bytes — "the results are
/// byte-equal or someone has proof of a violation."
pub fn fold_canonical_bytes(fold: &ConservationFold) -> Result<Vec<u8>, LedgerError> {
    let value = serde_json::to_value(fold).map_err(|e| LedgerError::Canonical(e.to_string()))?;
    pinned_jcs(&value)
}

// ─────────────────────────────────────────────────────────────────────────
// L8 — equivocation: detection records, adjudication judges
// ─────────────────────────────────────────────────────────────────────────

#[allow(missing_docs)] // field names are the documentation on plain data shapes
/// An owner-signed head as committed to the witness chain (L4) or presented
/// by a peer. Signatures are carried opaquely — verified at the door, kept
/// here so the evidence is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    pub ledger_id: String,
    pub seq: u64,
    pub head_hash: String,
    pub signature_key_id: String,
    pub signature_classical_base64: String,
    pub signature_pqc_base64: Option<String>,
}

#[allow(missing_docs)] // field names are the documentation on plain data shapes
/// A proven fork — L8's two shapes. This is a RECORD for the adjudication
/// plane (`slashing:*` against the posted stake); nothing in persist fires
/// slashing from it, because a fork alone cannot distinguish equivocation
/// from an honest writer restoring from a stale backup. The writer-side
/// obligation that makes that distinction cheap (re-sync from the witness
/// chain after any restore, BEFORE writing) is a client discipline; persist
/// records what it can prove and no more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fork", rename_all = "snake_case")]
pub enum ForkEvidence {
    /// Two owner-signed heads at one sequence number. Boxed: the two full
    /// heads dominate the enum's size, and this record travels through
    /// fold/list paths where the small variant is the common one.
    DoubleHead {
        ledger_id: String,
        seq: u64,
        head_a: Box<SignedHead>,
        head_b: Box<SignedHead>,
    },
    /// A presented chain whose replayed hash at a witness-anchored ancestor
    /// contradicts what the witness chain pinned.
    WitnessContradiction {
        ledger_id: String,
        witnessed_seq: u64,
        witnessed_hash: String,
        replayed_hash: String,
    },
}

impl ForkEvidence {
    /// The ledger this evidence concerns.
    pub fn ledger_id(&self) -> &str {
        match self {
            ForkEvidence::DoubleHead { ledger_id, .. }
            | ForkEvidence::WitnessContradiction { ledger_id, .. } => ledger_id,
        }
    }

    /// The sequence number the fork is proven at.
    pub fn seq(&self) -> u64 {
        match self {
            ForkEvidence::DoubleHead { seq, .. } => *seq,
            ForkEvidence::WitnessContradiction { witnessed_seq, .. } => *witnessed_seq,
        }
    }

    /// The stored `fork_kind` vocabulary — pinned by a schema CHECK in
    /// both dialects, so this and the migration must move together.
    pub fn fork_kind_str(&self) -> &'static str {
        match self {
            ForkEvidence::DoubleHead { .. } => "double_head",
            ForkEvidence::WitnessContradiction { .. } => "witness_contradiction",
        }
    }
}

/// Deterministic id for a fork-evidence record: `lfork-` + SHA-256 over the
/// pinned-JCS bytes of the evidence. Content-derived so recording is
/// idempotent — the same fork observed by two paths lands as one row, and
/// two members recording the same proof mint the same id.
pub fn fork_evidence_id(evidence: &ForkEvidence) -> Result<String, LedgerError> {
    let value =
        serde_json::to_value(evidence).map_err(|e| LedgerError::Canonical(e.to_string()))?;
    Ok(format!("lfork-{}", sha256_hex(&pinned_jcs(&value)?)))
}

/// Detect L8's first shape: two signed heads at one `(ledger_id, seq)` with
/// different hashes. Returns evidence with the halves in canonical order
/// (by `head_hash`) so two members assembling the same fork produce the
/// same record — transferable evidence must not depend on arrival order.
pub fn detect_double_head(a: &SignedHead, b: &SignedHead) -> Option<ForkEvidence> {
    if a.ledger_id != b.ledger_id || a.seq != b.seq || a.head_hash == b.head_hash {
        return None;
    }
    let (first, second) = if a.head_hash <= b.head_hash {
        (a, b)
    } else {
        (b, a)
    };
    Some(ForkEvidence::DoubleHead {
        ledger_id: a.ledger_id.clone(),
        seq: a.seq,
        head_a: Box::new(first.clone()),
        head_b: Box::new(second.clone()),
    })
}

/// Detect L8's second shape: replay a presented chain and compare its hash
/// at `witnessed_seq` against the witness-anchored hash. The chain must
/// itself be valid from its stated start (a broken chain is a
/// [`ChainViolation`], a different fact than a fork).
///
/// `chain` runs from some start whose expectations the caller states — the
/// same signature as [`verify_chain_from_checkpoint`].
pub fn contradicts_witnessed_ancestor(
    witnessed_seq: u64,
    witnessed_hash: &str,
    chain_first_seq: u64,
    chain_first_prev: &str,
    chain: &[LedgerEntry],
) -> Result<Option<ForkEvidence>, ChainViolation> {
    verify_chain(chain, chain_first_seq, chain_first_prev)?;
    let Some(at) = chain.iter().find(|e| e.seq == witnessed_seq) else {
        return Ok(None); // the witnessed seq is not in this span — no claim either way
    };
    let replayed = entry_content_hash(at).map_err(|e| ChainViolation::Canonical(e.to_string()))?;
    if replayed == witnessed_hash {
        return Ok(None);
    }
    Ok(Some(ForkEvidence::WitnessContradiction {
        ledger_id: at.ledger_id.clone(),
        witnessed_seq,
        witnessed_hash: witnessed_hash.to_string(),
        replayed_hash: replayed,
    }))
}

// ─────────────────────────────────────────────────────────────────────────
// shared plumbing
// ─────────────────────────────────────────────────────────────────────────

/// JCS, pinned. NEVER `produce_canon_version()` — see the module doc.
fn pinned_jcs(value: &serde_json::Value) -> Result<Vec<u8>, LedgerError> {
    canonicalizer_for(CanonVersion::V2Jcs)
        .canonicalize_value(value)
        .map_err(|e| LedgerError::Canonical(e.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credit(ledger: &str, seq: u64, prev: &str, amount: u64) -> LedgerEntry {
        LedgerEntry {
            ledger_id: ledger.into(),
            seq,
            prev_hash: prev.into(),
            kind: LedgerEntryKind::Credit,
            amount_minor: amount,
            unit: "usd".into(),
            refs: Vec::new(),
        }
    }

    fn transfer(
        ledger: &str,
        seq: u64,
        prev: &str,
        amount: u64,
        counterparty: &str,
        mref: &str,
        direction: TransferDirection,
    ) -> LedgerEntry {
        LedgerEntry {
            ledger_id: ledger.into(),
            seq,
            prev_hash: prev.into(),
            kind: LedgerEntryKind::Transfer {
                counterparty_ledger_id: counterparty.into(),
                matching_ref: mref.into(),
                direction,
            },
            amount_minor: amount,
            unit: "usd".into(),
            refs: Vec::new(),
        }
    }

    /// Chain-building helper: links each entry to the previous one's
    /// content hash, starting from the ledger_id (the genesis binding).
    fn chain(ledger: &str, amounts: &[u64]) -> Vec<LedgerEntry> {
        let mut prev = ledger.to_string();
        let mut out = Vec::new();
        for (i, amt) in amounts.iter().enumerate() {
            let e = credit(ledger, i as u64, &prev, *amt);
            prev = entry_content_hash(&e).unwrap();
            out.push(e);
        }
        out
    }

    // ── the pinned contracts ────────────────────────────────────────────
    // Spelled as LITERALS, not recomputed through the same helpers — a
    // witness that derives its expectation from the code under test can
    // only ever agree with it.

    #[test]
    fn derive_ledger_id_is_pinned() {
        assert_eq!(
            derive_ledger_id("owner-1", "usd", "1").unwrap(),
            "ledger-104c42eb35f4723b2c1630b192bf08a2776eaa17ab1c6c8d5e4a4b4901821f03"
        );
        // Injective across the triple: every member moves the id.
        let base = derive_ledger_id("owner-1", "usd", "1").unwrap();
        assert_ne!(derive_ledger_id("owner-2", "usd", "1").unwrap(), base);
        assert_ne!(derive_ledger_id("owner-1", "eur", "1").unwrap(), base);
        assert_ne!(derive_ledger_id("owner-1", "usd", "2").unwrap(), base);
        // No concatenation ambiguity: shifting a boundary changes the id.
        assert_ne!(
            derive_ledger_id("owner-1u", "sd", "1").unwrap(),
            base,
            "JSON escaping must keep the three members separate"
        );
    }

    #[test]
    fn entry_content_hash_is_pinned() {
        let e = credit("ledger-x", 0, "ledger-x", 5);
        assert_eq!(
            entry_content_hash(&e).unwrap(),
            "1107ec8954a1c8f2c11e6ec927b4caf3fbf13316c0d3c9cbb3d2f7d59cfb3066"
        );
    }

    /// The v37.0.0 field-set discipline, applied to this preimage: the key
    /// SET is asserted against hand-written literals in BOTH shapes, so one
    /// future serializing field cannot silently move every stored hash.
    #[test]
    fn entry_content_field_sets_are_pinned() {
        let minimal = entry_content_value(&credit("l", 0, "l", 1));
        let minimal_keys: Vec<&str> = minimal
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            minimal_keys,
            [
                "amount_minor",
                "kind",
                "ledger_id",
                "prev_hash",
                "refs",
                "seq",
                "unit"
            ]
        );
        let full = entry_content_value(&transfer(
            "l",
            1,
            "p",
            2,
            "l2",
            "m1",
            TransferDirection::Outgoing,
        ));
        let full_keys: Vec<&str> = full
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            full_keys,
            [
                "amount_minor",
                "counterparty_ledger_id",
                "direction",
                "kind",
                "ledger_id",
                "matching_ref",
                "prev_hash",
                "refs",
                "seq",
                "unit"
            ]
        );
        // refs is ALWAYS serialized — empty is a value, not an omission
        // (the #727 collapse, kept out of a hash preimage forever).
        assert_eq!(minimal["refs"], serde_json::json!([]));
    }

    // ── chain validity ──────────────────────────────────────────────────

    #[test]
    fn a_valid_genesis_chain_verifies_and_reports_its_head() {
        let c = chain("ledger-x", &[5, 3, 2]);
        let head = verify_chain_from_genesis(&c).unwrap();
        assert_eq!(head.seq, 2);
        assert_eq!(head.ledger_id, "ledger-x");
        assert_eq!(head.head_hash, entry_content_hash(&c[2]).unwrap());
    }

    #[test]
    fn every_chain_violation_is_reachable() {
        assert_eq!(verify_chain_from_genesis(&[]), Err(ChainViolation::Empty));

        let mut c = chain("ledger-x", &[5, 3, 2]);
        c[1].ledger_id = "ledger-other".into();
        assert!(matches!(
            verify_chain_from_genesis(&c),
            Err(ChainViolation::LedgerIdMismatch { index: 1, .. })
        ));

        let mut c = chain("ledger-x", &[5, 3, 2]);
        c[2].unit = "eur".into();
        assert!(matches!(
            verify_chain_from_genesis(&c),
            Err(ChainViolation::UnitMismatch { seq: 2, .. })
        ));

        let mut c = chain("ledger-x", &[5, 3, 2]);
        c[2].seq = 5;
        assert!(matches!(
            verify_chain_from_genesis(&c),
            Err(ChainViolation::SeqGap {
                expected: 2,
                found: 5
            })
        ));

        let mut c = chain("ledger-x", &[5, 3, 2]);
        c[2].prev_hash = "0".repeat(64);
        assert!(matches!(
            verify_chain_from_genesis(&c),
            Err(ChainViolation::PrevHashMismatch { seq: 2, .. })
        ));

        // Tampering with CONTENT (not links) breaks the chain at the NEXT
        // link — the property that makes a witnessed ancestor binding.
        let mut c = chain("ledger-x", &[5, 3, 2]);
        c[1].amount_minor = 4;
        assert!(matches!(
            verify_chain_from_genesis(&c),
            Err(ChainViolation::PrevHashMismatch { seq: 2, .. })
        ));
    }

    #[test]
    fn a_checkpoint_chain_verifies_from_the_checkpointed_head() {
        let c = chain("ledger-x", &[5, 3, 2, 8]);
        let checkpoint_hash = entry_content_hash(&c[1]).unwrap();
        let head = verify_chain_from_checkpoint(1, &checkpoint_hash, &c[2..]).unwrap();
        assert_eq!(head.seq, 3);
    }

    // ── the conservation fold ───────────────────────────────────────────

    #[test]
    fn the_fold_is_input_order_invariant() {
        let a = chain("ledger-a", &[10, 7]);
        let b = chain("ledger-b", &[3]);
        let mut entries: Vec<LedgerEntry> = a.into_iter().chain(b).collect();
        let forward = fold_canonical_bytes(&conservation_fold(&entries).unwrap()).unwrap();
        entries.reverse();
        let reversed = fold_canonical_bytes(&conservation_fold(&entries).unwrap()).unwrap();
        assert_eq!(forward, reversed, "byte-equal regardless of arrival order");
    }

    #[test]
    fn a_matched_transfer_pair_sums_to_zero_and_the_bytes_are_pinned() {
        // A pays B 7: A's chain = credit 10 then transfer-out 7;
        // B's chain = transfer-in 7.
        let a0 = credit("ledger-a", 0, "ledger-a", 10);
        let a0h = entry_content_hash(&a0).unwrap();
        let a1 = transfer(
            "ledger-a",
            1,
            &a0h,
            7,
            "ledger-b",
            "pay-1",
            TransferDirection::Outgoing,
        );
        let b0 = transfer(
            "ledger-b",
            0,
            "ledger-b",
            7,
            "ledger-a",
            "pay-1",
            TransferDirection::Incoming,
        );

        let fold = conservation_fold(&[a0, a1, b0]).unwrap();
        assert!(fold.flags.is_empty(), "{:?}", fold.flags);
        assert_eq!(fold.nets["ledger-a"].net_minor, "3");
        assert_eq!(fold.nets["ledger-b"].net_minor, "7");
        assert_eq!(fold.entry_count, 3);
        // The transfer legs alone sum to zero: -7 + 7.
        let bytes = fold_canonical_bytes(&fold).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), "{\"entry_count\":3,\"flags\":[],\"nets\":{\"ledger-a\":{\"net_minor\":\"3\",\"unit\":\"usd\"},\"ledger-b\":{\"net_minor\":\"7\",\"unit\":\"usd\"}}}");
    }

    #[test]
    fn every_fold_flag_is_reachable_and_flagged_never_merged() {
        // ForkShapedSequence: two DIFFERENT entries at one (ledger, seq) —
        // both excluded from the net.
        let f1 = credit("ledger-f", 0, "ledger-f", 5);
        let f2 = credit("ledger-f", 0, "ledger-f", 9);
        let fold = conservation_fold(&[f1.clone(), f2]).unwrap();
        assert!(matches!(
            fold.flags[0],
            FoldFlag::ForkShapedSequence { seq: 0, .. }
        ));
        assert!(
            fold.nets.is_empty(),
            "a fork-shaped seq must not contribute"
        );
        assert_eq!(fold.entry_count, 0);

        // DuplicateEntry: byte-identical twice — counted ONCE.
        let fold = conservation_fold(&[f1.clone(), f1.clone()]).unwrap();
        assert!(matches!(
            fold.flags[0],
            FoldFlag::DuplicateEntry { seq: 0, .. }
        ));
        assert_eq!(fold.nets["ledger-f"].net_minor, "5");
        assert_eq!(fold.entry_count, 1);

        // UnitMismatch: a divergent unit mid-ledger is excluded + flagged.
        let mut wrong_unit = credit("ledger-f", 1, "x", 100);
        wrong_unit.unit = "eur".into();
        let fold = conservation_fold(&[f1.clone(), wrong_unit]).unwrap();
        assert!(matches!(
            fold.flags[0],
            FoldFlag::UnitMismatch { seq: 1, .. }
        ));
        assert_eq!(fold.nets["ledger-f"].net_minor, "5");

        // UnmatchedTransfer: one half, no partner — still nets on its own
        // ledger (the ledger says what it says; the flag says it violates).
        let lone = transfer(
            "ledger-a",
            0,
            "ledger-a",
            7,
            "ledger-b",
            "m-lone",
            TransferDirection::Outgoing,
        );
        let fold = conservation_fold(&[lone]).unwrap();
        assert!(
            matches!(fold.flags[0], FoldFlag::UnmatchedTransfer { ref matching_ref, .. } if matching_ref == "m-lone")
        );
        assert_eq!(fold.nets["ledger-a"].net_minor, "-7");

        // OverloadedMatchingRef: three halves under one ref.
        let t1 = transfer(
            "ledger-a",
            0,
            "ledger-a",
            1,
            "ledger-b",
            "m-3",
            TransferDirection::Outgoing,
        );
        let t2 = transfer(
            "ledger-b",
            0,
            "ledger-b",
            1,
            "ledger-a",
            "m-3",
            TransferDirection::Incoming,
        );
        let t3 = transfer(
            "ledger-c",
            0,
            "ledger-c",
            1,
            "ledger-a",
            "m-3",
            TransferDirection::Incoming,
        );
        let fold = conservation_fold(&[t1, t2, t3]).unwrap();
        assert!(matches!(
            fold.flags[0],
            FoldFlag::OverloadedMatchingRef { count: 3, .. }
        ));

        // DirectionCollision: both halves outgoing.
        let t1 = transfer(
            "ledger-a",
            0,
            "ledger-a",
            1,
            "ledger-b",
            "m-dc",
            TransferDirection::Outgoing,
        );
        let t2 = transfer(
            "ledger-b",
            0,
            "ledger-b",
            1,
            "ledger-a",
            "m-dc",
            TransferDirection::Outgoing,
        );
        let fold = conservation_fold(&[t1, t2]).unwrap();
        assert!(fold
            .flags
            .iter()
            .any(|f| matches!(f, FoldFlag::DirectionCollision { .. })));

        // CounterpartyMismatch: the halves do not cross-name each other.
        let t1 = transfer(
            "ledger-a",
            0,
            "ledger-a",
            1,
            "ledger-b",
            "m-cp",
            TransferDirection::Outgoing,
        );
        let t2 = transfer(
            "ledger-c",
            0,
            "ledger-c",
            1,
            "ledger-a",
            "m-cp",
            TransferDirection::Incoming,
        );
        let fold = conservation_fold(&[t1, t2]).unwrap();
        assert!(fold
            .flags
            .iter()
            .any(|f| matches!(f, FoldFlag::CounterpartyMismatch { .. })));

        // AmountMismatch: the pair does NOT sum to zero — flagged, and BOTH
        // sides still net what their own ledger recorded.
        let t1 = transfer(
            "ledger-a",
            0,
            "ledger-a",
            5,
            "ledger-b",
            "m-am",
            TransferDirection::Outgoing,
        );
        let t2 = transfer(
            "ledger-b",
            0,
            "ledger-b",
            4,
            "ledger-a",
            "m-am",
            TransferDirection::Incoming,
        );
        let fold = conservation_fold(&[t1, t2]).unwrap();
        assert!(fold
            .flags
            .iter()
            .any(|f| matches!(f, FoldFlag::AmountMismatch { .. })));
        assert_eq!(fold.nets["ledger-a"].net_minor, "-5");
        assert_eq!(fold.nets["ledger-b"].net_minor, "4");

        // UnitMismatchPair: same amounts, different units.
        let t1 = transfer(
            "ledger-a",
            0,
            "ledger-a",
            5,
            "ledger-b",
            "m-up",
            TransferDirection::Outgoing,
        );
        let mut t2 = transfer(
            "ledger-b",
            0,
            "ledger-b",
            5,
            "ledger-a",
            "m-up",
            TransferDirection::Incoming,
        );
        t2.unit = "eur".into();
        let fold = conservation_fold(&[t1, t2]).unwrap();
        assert!(fold
            .flags
            .iter()
            .any(|f| matches!(f, FoldFlag::UnitMismatchPair { .. })));
    }

    #[test]
    fn net_minor_serializes_as_a_decimal_string_never_a_number() {
        let fold = conservation_fold(&chain("ledger-a", &[5])).unwrap();
        let bytes = fold_canonical_bytes(&fold).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("\"net_minor\":\"5\""),
            "i128 does not survive every JSON number path byte-identically: {text}"
        );
    }

    // ── fork detection ──────────────────────────────────────────────────

    fn signed_head(ledger: &str, seq: u64, hash: &str) -> SignedHead {
        SignedHead {
            ledger_id: ledger.into(),
            seq,
            head_hash: hash.into(),
            signature_key_id: "owner".into(),
            signature_classical_base64: "c2ln".into(),
            signature_pqc_base64: None,
        }
    }

    #[test]
    fn double_head_detection_is_order_invariant_evidence() {
        let a = signed_head("ledger-x", 7, "hash-a");
        let b = signed_head("ledger-x", 7, "hash-b");
        let ab = detect_double_head(&a, &b).unwrap();
        let ba = detect_double_head(&b, &a).unwrap();
        assert_eq!(
            ab, ba,
            "transferable evidence must not depend on arrival order"
        );
        assert_eq!(
            fork_evidence_id(&ab).unwrap(),
            fork_evidence_id(&ba).unwrap()
        );

        assert!(detect_double_head(&a, &a).is_none(), "same hash is no fork");
        let other_seq = signed_head("ledger-x", 8, "hash-b");
        assert!(detect_double_head(&a, &other_seq).is_none());
        let other_ledger = signed_head("ledger-y", 7, "hash-b");
        assert!(detect_double_head(&a, &other_ledger).is_none());
    }

    #[test]
    fn a_witness_anchored_ancestor_binds_the_chain() {
        let c = chain("ledger-x", &[5, 3, 2]);
        let witnessed = entry_content_hash(&c[1]).unwrap();

        // The honest chain matches its own witness: no claim.
        let ok = contradicts_witnessed_ancestor(1, &witnessed, 0, "ledger-x", &c).unwrap();
        assert!(ok.is_none());

        // A rewritten history replays a DIFFERENT hash at the witnessed
        // seq: that is the L8 second shape. The rewrite must re-link its
        // own chain (a hostile writer would), so rebuild from scratch.
        let mut rewritten = Vec::new();
        let mut prev = "ledger-x".to_string();
        for (i, amt) in [5u64, 4, 2].iter().enumerate() {
            let e = credit("ledger-x", i as u64, &prev, *amt);
            prev = entry_content_hash(&e).unwrap();
            rewritten.push(e);
        }
        let hit = contradicts_witnessed_ancestor(1, &witnessed, 0, "ledger-x", &rewritten)
            .unwrap()
            .expect("a rewritten witnessed ancestor must be caught");
        assert!(matches!(
            hit,
            ForkEvidence::WitnessContradiction {
                witnessed_seq: 1,
                ..
            }
        ));

        // A witnessed seq outside the presented span makes no claim.
        let none = contradicts_witnessed_ancestor(9, &witnessed, 0, "ledger-x", &c).unwrap();
        assert!(none.is_none());

        // A structurally broken chain is a ChainViolation, not a fork.
        let mut broken = chain("ledger-x", &[5, 3, 2]);
        broken[2].prev_hash = "0".repeat(64);
        assert!(contradicts_witnessed_ancestor(1, &witnessed, 0, "ledger-x", &broken).is_err());
    }
}
