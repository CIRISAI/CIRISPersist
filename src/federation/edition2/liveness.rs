//! Key liveness under edition 2 (CC 2.4.1.1, CC 2.6.1.7).
//!
//! A statement of this form is signed by a composite key, and that key is
//! live only through a `key:record` of this form. A key record of the earlier
//! form gives standing to nothing (CC 2.6.1.12), so this directory holds only
//! edition-2 statements. It never holds an earlier-form record, or a key held
//! in part by an earlier-form commitment (Verify's `insert_partial`).
//!
//! **The reading** ([`HeldKeys::liveness`]):
//! - A key is **live** at an instant when one of its valid records covers that
//!   instant, and no revocation by one of the three revokers has taken effect
//!   by then. A record covers `[asserted_at, valid_until)` (half-open, CC ruling; [`crate::kernel::key_end::within_record`]), or
//!   `[asserted_at, ∞)` where it states no end.
//! - Renewals that do not name each other all count, so the key lives to the
//!   greatest end they state.
//! - A key is **revoked** at an instant when a valid `key:revocation` row by
//!   one of the three revokers names it as `sub`, and either states no
//!   `revoked_after` or states one at or before the instant. This answer is
//!   final.
//! - The three revokers are the key itself, its owner under the
//!   owner-binding, and the roster that seats it. [`RevokerStanding`] answers
//!   for the owner and the roster. The default, [`SelfOnly`], admits only the
//!   key itself. A revocation by any other key revokes nothing.
//! - A signed instant that no held record covers is **not covered**. The
//!   statement is retryable, the same as one signed by a key not yet held
//!   (CC 2.4.1.1). This deliberately differs from Verify's
//!   `KeyRecordDirectory`, which reads an instant after `valid_until` as
//!   Invalid. CC lets a renewal signed after the end revive the key, so the
//!   reading cannot be final.
//! - Each record is checked against the end rule (Verify's `check_key_record`):
//!   - a set mixing a person's role with a machine's is refused;
//!   - `user` / `accord_holder` carries no `valid_until`;
//!   - `node` / `agent` carries one, at most `key_record_max_secs` after
//!     `asserted_at`.
//!
//!   A record that breaks the rule gives no liveness.
//!
//! **Whose key it is** (v62.0.0, JSON-cut slice A, I2101; CC 2.6.1.7, CC
//! 2.4.1.1; the key-chain rule, CC-READING(next-edition)). A statement's
//! `iss` is the identity-ref of the signer's genesis key. When `kid` is not
//! that genesis key, [`HeldKeys::key_of`] answers whether it is a key OF
//! that identity: `Yes` only when ALL of these hold for some held record
//! row of `kid`:
//! 1. the key's OWN statement over its `key:record` carries that `iss`;
//! 2. its `refs.target` names the predecessor's record;
//! 3. a valid statement by the predecessor key over the SAME row id carries
//!    the same `iss`, and the predecessor is itself a key of `iss`
//!    (recursively, to the genesis key);
//! 4. the named record is held, is a record of the predecessor, and covers
//!    the rotation's instant;
//! 5. no rival rotation of the predecessor is held (another key's record
//!    naming the same predecessor record, carrying the predecessor's
//!    statement under the same `iss`, and that record covering the rival's
//!    instant, the same test as the rotation path): two rotations that do
//!    not name each other hand on nothing (CC 2.4.1.1, CC 2.7.7).
//!
//!
//! **The seat arm** (CC 3.1.3, CC-READING(next-edition)): a key the
//! accord's genesis bundle in force seats for `iss` is a key of `iss` (a
//! recovery replaces a holder's key with no rotation record). With no
//! bundle held, a key signing as an accord holder's identity that the chain
//! does not reach waits on the bundle ([`ChainMissing::Bundle`]).
//!
//! A missing link waits ([`KeyOf::Waiting`]): the predecessor's statement
//! (its key), or the named record ([`ChainMissing::Record`]). A record of a
//! key signed only by other keys never makes it a key of another identity.
//! v62.0.0 (K1, triage round 3): nor does a record stating an end make the
//! key live unless the key's own voice is on it (CC 2.4.1.1: "Each key's own
//! holder signs its record of this form"; the kernel's
//! `key_end::well_formed`).
//!
//! **One check, two callers** (v62.0.0, slice C3: CIRISVerify 23.3.0).
//! Verify's row reader asks `KeyDirectory::key_of` itself, after the
//! signature verifies and only when `kid` is not `iss`, and refuses
//! `kid_not_of_iss`. `HeldKeys` (and the scoped views its own records are
//! verified through) answer that question with [`HeldKeys::key_of`], so
//! Verify's reader and persist's door give one verdict. [`KeyOf`] and
//! [`ChainMissing`] stay persist's richer reading (the seat arm's
//! [`ChainMissing::Bundle`] has no Verify counterpart); [`KeyOf::to_verify`]
//! is the one mapping onto Verify's `KeyOf` / `MissingKey`.
//!
//! Where this reading and Verify's `KeyRecordDirectory` agree and differ
//! (`edition2/key_of_iss_v1.json`, replayed in `verify_vectors_replay`):
//! - as Verify: a co-statement over the rotation held and not valid under
//!   `iss` (none waiting) hands on nothing; a named record held as some
//!   other row hands on nothing; a named record not held is waited on;
//! - a rotation whose predecessor statement is not held at all WAITS on the
//!   predecessor key here (a door receives a row's voices one at a time,
//!   CC 2.6.1.8; I2101), where Verify 23.3.0's directory answered `No` (the
//!   v1 file's answer). Verify 23.3.1 (CC rc21) waits too, naming the
//!   missing voice (`MissingKey::Voice`): the verdict now agrees, the link
//!   named differs;
//! - a rotation whose NEW key's own statement is not held, the
//!   predecessor's voice over a sound rotation being held, waits on that
//!   voice ([`ChainMissing::Voice`]; R1 round 3, CC 2.6.1.9), as Verify
//!   23.3.1 does (`rotation_lacks_possession`); v1 says `kid_not_of_iss`;
//! - a rotation whose predecessor statement waits names the link I2101
//!   names (the predecessor key when its record is held, else the record
//!   `target` names), where Verify names the key that statement waits on.
//!   Both wait: the verdict is the same, the link named differs.
//!
//! **Through the kernel** (v62.0.0, kernel pass 2, K1, I2814–I2817): whether
//! a held, verified record covers the instant is the kernel's `key_end`
//! conclusion ([`crate::kernel::key_end`]: `well_formed` under the end rule
//! and the `key_record_max_secs` ceiling, `conclude_rule`, `live`) over the
//! key's records and its own revocations, never a sweep. The kernel reads a
//! record as covering `[asserted_at, valid_until)` (CC 2.6.2: "has not yet
//! reached its `valid_until`"), so a statement signed AT `valid_until` is
//! not covered (retryable); the earlier inclusive reading is the
//! differential's reference, the named class `key_end_half_open`. What stays
//! persist's: verifying each record (Verify's `verify_row_statement`), and
//! the owner / roster revokers ([`RevokerStanding`]), which the kernel's
//! key-end reading does not count (CC 2.4.1.1: "No other row enters that
//! reading") and persist keeps until a ruling.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::names::{names_of, single};
use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::keys::{check_key_record, KeyRecord, KEY_RECORD_FAMILY};
use ciris_verify_core::edition2::{
    identity_ref, verify_row_statement, Digest32, KeyDirectory, KeyLookup, KeyOf as VerifyKeyOf,
    MissingKey, Verdict,
};

/// The family of a key revocation (CC 3.1.3, `key:revocation:v1`'s family id).
pub const KEY_REVOCATION_FAMILY: &str = "key:revocation";

/// How deep a chain of signer records is followed (Verify's bound).
const MAX_DEPTH: usize = ciris_verify_core::edition2::keys::MAX_RECORD_DEPTH;

/// Who besides the key itself may revoke it (CC 2.4.1.1, "Who may revoke a
/// key"): its owner under the owner-binding, and the roster that seats it.
///
/// v62.0.0 (kernel pass 2, K1): the kernel's key-end reading counts the
/// key's own revocation only (CC 2.4.1.1); these two revokers are persist's,
/// kept on top of it until a ruling. A host that holds the edition-2
/// owner-binding and roster rows answers here.
pub trait RevokerStanding: Send + Sync {
    /// Does `revoker` (an identity-ref) hold standing to revoke `subject` (an
    /// identity-ref), other than as the key itself?
    fn may_revoke(&self, revoker: &str, subject: &str) -> bool;
}

/// Only the key itself revokes (no owner or roster is held).
#[derive(Clone, Copy, Debug, Default)]
pub struct SelfOnly;

impl RevokerStanding for SelfOnly {
    fn may_revoke(&self, _revoker: &str, _subject: &str) -> bool {
        false
    }
}

/// What the held records say of a key at an instant.
#[derive(Clone, Debug)]
pub enum Liveness {
    /// A valid record covers the instant, and no revocation has taken effect.
    Live(Box<KeyRecord>),
    /// Valid records are held, but none covers the instant. Retryable.
    NotCovered,
    /// A revocation by one of the three revokers has taken effect. Final.
    Revoked,
    /// No record of this key is held.
    NotHeld,
    /// Every held record is invalid (the end rule, the family, a bad
    /// signature) or the chain is too deep.
    Invalid,
    /// A record waits on a deeper key.
    Waiting(Vec<MissingKey>),
}

/// The held edition-2 key records and key revocations of a reader.
#[derive(Clone)]
pub struct HeldKeys {
    records: BTreeMap<Digest32, Vec<Vec<u8>>>,
    revocations: Vec<Vec<u8>>,
    standing: Arc<dyn RevokerStanding>,
    seats: BundleSeats,
    /// v62.0.0 (wave O1, I3020) — the key-of-issuer check's occurrence arm
    /// ([`super::occurrence::OccurrenceSeats`]).
    occurrences: super::occurrence::OccurrenceSeats,
}

impl Default for HeldKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HeldKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldKeys")
            .field("keys", &self.records.len())
            .field("revocations", &self.revocations.len())
            .finish()
    }
}

/// The protected header and payload of a `COSE_Sign1`, decoded, without any
/// check: for filing a statement. Judging it is the reader's.
pub(crate) fn statement_parts(bytes: &[u8]) -> Option<(Value, Value)> {
    let Value::Tag(18, inner) = cde::decode(bytes).ok()? else {
        return None;
    };
    let parts = inner.as_array()?;
    if parts.len() != 4 {
        return None;
    }
    let protected = cde::decode(parts[0].as_bytes()?).ok()?;
    let payload = cde::decode(parts[2].as_bytes()?).ok()?;
    Some((protected, payload))
}

/// The kid of the key a key-record statement records (its payload `key`).
#[must_use]
pub fn recorded_kid(statement: &[u8]) -> Option<Digest32> {
    let (_, payload) = statement_parts(statement)?;
    check_key_record(&payload).ok().map(|r| r.kid).or_else(|| {
        // A record that breaks the end rule is still filed under its key, so
        // a lookup reaches it and answers Invalid rather than NotHeld.
        let k = payload.get_text("key")?.get_int(-1)?.as_bytes()?;
        CompositePublicKey::from_bytes(k)
            .ok()
            .map(|pk| ciris_verify_core::edition2::thumbprint(&pk))
    })
}

impl HeldKeys {
    /// An empty directory where only a key revokes itself.
    #[must_use]
    pub fn new() -> Self {
        HeldKeys {
            records: BTreeMap::new(),
            revocations: Vec::new(),
            standing: Arc::new(SelfOnly),
            seats: BundleSeats::default(),
            occurrences: super::occurrence::OccurrenceSeats::none(),
        }
    }

    /// With the seats of the accord's genesis bundle in force
    /// ([`BundleSeats`]), for the key-of-iss check's seat arm.
    #[must_use]
    pub fn with_seats(mut self, seats: BundleSeats) -> Self {
        self.seats = seats;
        self
    }

    /// v62.0.0 (wave O1, I3020; CC 3.3.6, the rc21 rule) — with the live,
    /// unevicted occurrences the key-of-issuer check admits as keys of their
    /// identity ([`super::occurrence::occurrence_seats_for`]).
    #[must_use]
    pub fn with_occurrences(mut self, occurrences: super::occurrence::OccurrenceSeats) -> Self {
        self.occurrences = occurrences;
        self
    }

    /// With an owner / roster answer for revocations.
    #[must_use]
    pub fn with_standing(mut self, standing: Arc<dyn RevokerStanding>) -> Self {
        self.standing = standing;
        self
    }

    /// Hold a `key:record` statement under the key it records. Returns that
    /// key's kid, or `None` if the bytes carry no readable payload `key`. The
    /// statement is judged when a lookup reaches it.
    pub fn insert_record(&mut self, statement: Vec<u8>) -> Option<Digest32> {
        let kid = recorded_kid(&statement)?;
        let v = self.records.entry(kid).or_default();
        if !v.contains(&statement) {
            v.push(statement);
        }
        Some(kid)
    }

    /// Hold a `key:revocation` statement. It is judged at reading.
    pub fn insert_revocation(&mut self, statement: Vec<u8>) {
        if !self.revocations.contains(&statement) {
            self.revocations.push(statement);
        }
    }

    /// The same records with no revocation held: the reading of whether a
    /// statement was signed by a key with a valid record, apart from
    /// whether that key was revoked since. The projection
    /// ([`super::projection`]) maps a held record or revocation through it,
    /// and an already-held key-plane statement is re-read through it
    /// ([`super::ingest::put_statement`]): a revoke-all revocation does not
    /// make its own bytes, or the record it ends, unreadable.
    #[must_use]
    pub fn without_revocations(&self) -> HeldKeys {
        HeldKeys {
            records: self.records.clone(),
            revocations: Vec::new(),
            standing: Arc::clone(&self.standing),
            seats: self.seats.clone(),
            occurrences: self.occurrences.clone(),
        }
    }

    /// Is this exact statement held, as a record or a revocation?
    #[must_use]
    pub fn holds(&self, statement: &[u8]) -> bool {
        self.records
            .values()
            .any(|v| v.iter().any(|s| s.as_slice() == statement))
            || self.revocations.iter().any(|s| s.as_slice() == statement)
    }

    /// The kids of the keys a statement's records are held for.
    pub fn kids(&self) -> impl Iterator<Item = &Digest32> {
        self.records.keys()
    }

    /// The reading of `kid` at `at` (POSIX ms).
    #[must_use]
    pub fn liveness(&self, kid: &Digest32, at: u64) -> Liveness {
        self.resolve(kid, at, 0, true)
    }

    fn resolve(&self, kid: &Digest32, at: u64, depth: usize, with_revocations: bool) -> Liveness {
        let valid = match self.judged(kid, depth) {
            Ok(valid) => valid,
            Err(other) => return other,
        };
        let honoured = if with_revocations {
            self.honoured_at(kid, depth)
        } else {
            Vec::new()
        };
        // The three revokers (persist's; the kernel counts the key's own,
        // presented below too): final.
        if in_effect(&honoured, at) {
            return Liveness::Revoked;
        }
        // v62.0.0 (kernel pass 2, K1, I2817) — whether a record covers the
        // instant is the kernel's key-end conclusion over the key's records
        // and its own revocations. Renewals all count: the instant is
        // covered by any one of them.
        let key = hex::encode(kid);
        let views = key_end_views(&key, kid, &valid, &honoured);
        let answer = crate::kernel::key_end::key_live(&views, &key, at);
        #[cfg(test)]
        crate::kernel::differential::key_end(
            &key,
            at,
            // persist's former reading, inclusive of `valid_until` (the
            // differential's reference)
            valid
                .iter()
                .any(|v| inclusive((v.record.asserted_at, v.record.valid_until), at)),
            answer.value,
            // every record that covered `at` inclusively ends exactly there
            valid
                .iter()
                .filter(|v| inclusive((v.record.asserted_at, v.record.valid_until), at))
                .all(|v| v.record.valid_until == Some(at)),
            // v62.0.0 (K1, triage round 3) — or carries no voice of the key
            // it records (CC 2.4.1.1: "Each key's own holder signs its
            // record"; the kernel's `key_end::well_formed`)
            valid
                .iter()
                .filter(|v| inclusive((v.record.asserted_at, v.record.valid_until), at))
                .all(|v| {
                    v.record.valid_until == Some(at)
                        || !valid
                            .iter()
                            .any(|w| w.row_id == v.row_id && w.signer == *kid)
                }),
        );
        if !answer.value {
            return Liveness::NotCovered;
        }
        let kept: Vec<crate::kernel::view::RowId> = answer.rows;
        valid
            .into_iter()
            .filter(|v| kept.contains(&crate::kernel::view::RowId(v.row_id)))
            .map(|v| v.record)
            .filter(|r| covers((r.asserted_at, r.valid_until), at))
            .max_by_key(|r| r.valid_until.unwrap_or(u64::MAX))
            .map_or(Liveness::NotCovered, |r| Liveness::Live(Box::new(r)))
    }

    /// The held records of `kid` that verify and keep the end rule, each with
    /// its statement, at any instant: the input [`Self::liveness`] reads.
    /// `Err` carries the reading when none does ([`Liveness::NotHeld`],
    /// [`Liveness::Invalid`], [`Liveness::Waiting`]).
    ///
    /// v62.0.0 (slice J0) — the edition-2 key projection
    /// ([`super::projection`]) reads THIS, so the read model and the gates
    /// share one fold.
    ///
    /// # Errors
    /// The reading when no held record of `kid` is valid.
    pub fn valid_records(&self, kid: &Digest32) -> Result<Vec<ValidRecord>, Liveness> {
        self.judged(kid, 0)
    }

    fn judged(&self, kid: &Digest32, depth: usize) -> Result<Vec<ValidRecord>, Liveness> {
        if depth > MAX_DEPTH {
            return Err(Liveness::Invalid);
        }
        let Some(statements) = self.records.get(kid) else {
            return Err(Liveness::NotHeld);
        };
        let mut valid: Vec<ValidRecord> = Vec::new();
        let mut waiting: Vec<MissingKey> = Vec::new();
        for st in statements {
            let own_key = statement_parts(st)
                .and_then(|(_, p)| check_key_record(&p).ok())
                .map(|r| r.key);
            let scoped = Scoped {
                held: self,
                depth: depth + 1,
                own: *kid,
                own_key,
            };
            match verify_row_statement(st, &scoped) {
                Verdict::Valid(row) => {
                    if row.family != KEY_RECORD_FAMILY {
                        continue;
                    }
                    // v62.0.0 (slice A) — a set breaking the identity-set
                    // exclusion gives no liveness.
                    if super::door::check_identity_set_exclusive(&row.sub, &row.payload).is_err() {
                        continue;
                    }
                    match check_key_record(&row.payload) {
                        Ok(rec) if rec.kid == *kid => valid.push(ValidRecord {
                            record: rec,
                            row_id: row.row_id,
                            signer: row.kid,
                            statement: st.clone(),
                        }),
                        _ => {}
                    }
                }
                Verdict::Waiting { missing } => waiting.extend(missing),
                Verdict::Invalid(_) => {}
            }
        }
        if valid.is_empty() {
            return Err(if waiting.is_empty() {
                Liveness::Invalid
            } else {
                Liveness::Waiting(waiting)
            });
        }
        Ok(valid)
    }

    /// **Is `kid` a key of the identity whose genesis key is `iss`?**
    /// (v62.0.0, JSON-cut slice A, I2101; module docs, "Whose key it is".)
    /// `iss` is the thumbprint inside the statement's `iss`. A key is its
    /// own genesis key's (`kid == iss`). Verify's reader reaches this
    /// through `KeyDirectory::key_of` ([`KeyOf::to_verify`]).
    #[must_use]
    pub fn key_of(&self, kid: &Digest32, iss: &Digest32) -> KeyOf {
        self.key_of_at_depth(kid, iss, 0)
    }

    fn key_of_at_depth(&self, kid: &Digest32, iss: &Digest32, depth: usize) -> KeyOf {
        if kid == iss {
            return KeyOf::Yes;
        }
        if depth > MAX_DEPTH {
            return KeyOf::No;
        }
        let statements = self.records.get(kid).map_or(&[][..], Vec::as_slice);
        let iss_ref = identity_ref(iss);
        // v62.0.0 (wave O1, I3020; CC 3.3.6, CC 3.1.3, the rc21 rule) — the
        // occurrence arm: a key admitted as a live, unevicted
        // `identity:occurrence` of `iss` at the statement's instant is a key
        // of `iss` ([`super::occurrence::occurrence_seats_for`]).
        if self.occurrences.admits(&iss_ref, kid) {
            return KeyOf::Yes;
        }
        let rows = self.record_voices(kid, statements, depth);
        let mut missing: Vec<ChainMissing> = Vec::new();
        for (row_id, voices) in &rows {
            // (1) the key's own statement, under `iss`. v62.0.0 (R1 round 3;
            // CC 2.6.1.9, CIRISVerify 23.3.1): when it is not held but the
            // predecessor's voice over a sound rotation is, the row waits on
            // the new key's voice (proof of possession); it is never refused
            // for a voice not yet held ([`Self::possession_missing`]).
            let Some(own) = voices
                .iter()
                .find(|v| v.row.kid == *kid && v.row.iss == iss_ref)
            else {
                if let Some(m) = self.possession_missing(kid, &iss_ref, row_id, voices, depth) {
                    missing.push(m);
                }
                continue;
            };
            // (2) it names the predecessor's record.
            let Some(target) = names_of(&own.row.payload)
                .ok()
                .and_then(|n| single(&n, "target"))
                .map(|r| r.0)
            else {
                continue;
            };
            // (3) a predecessor's statement over this row, under `iss`.
            let preds: Vec<&Voice> = voices
                .iter()
                .filter(|v| v.row.kid != *kid && v.row.iss == iss_ref)
                .collect();
            if preds.is_empty() {
                // v62.0.0 (slice C3) — another key's statement over this
                // row is held, and none waits: none is a predecessor's under
                // `iss`, and it hands on nothing (Verify's
                // `KeyRecordDirectory`, `key_of_iss_v1.json`).
                if self.co_statements_refused(kid, statements, row_id, depth) {
                    continue;
                }
                // None held, or one waits: wait on the key whose record
                // `target` names, when held; else on the record itself.
                missing.push(match self.record_owner(&target, depth) {
                    Some(p) => ChainMissing::Kid(p),
                    None => ChainMissing::Record(target),
                });
                continue;
            }
            for pred in preds {
                let p = pred.row.kid;
                // (4) the named record is a held record of the predecessor
                // covering the rotation's instant.
                let window = self.records.get(&p).map(|sts| {
                    self.record_voices(&p, sts, depth + 1)
                        .get(&target)
                        .and_then(|vs| vs.first())
                        .map(|v| (v.record.asserted_at, v.record.valid_until))
                });
                let window = match window {
                    Some(Some(w)) => w,
                    _ => {
                        // v62.0.0 (slice C3) — a named row held as something
                        // other than the predecessor's record breaks the
                        // chain; one not held at all is the link it waits on
                        // (Verify's `KeyRecordDirectory`).
                        if !self.holds_row(&target) {
                            missing.push(ChainMissing::Record(target));
                        }
                        continue;
                    }
                };
                if !covers(window, own.row.asserted_at) {
                    continue;
                }
                // (5) no rival rotation of the predecessor.
                if self.rival_rotation(kid, &p, &iss_ref, &target, window, row_id, depth) {
                    continue;
                }
                // (3) recursively: the predecessor is a key of `iss`.
                match self.key_of_at_depth(&p, iss, depth + 1) {
                    KeyOf::Yes => return KeyOf::Yes,
                    KeyOf::Waiting(m) => missing.extend(m),
                    KeyOf::No => {}
                }
            }
        }
        // The seat arm: a key the accord's bundle in force seats for `iss`.
        match self.seats.seat(&iss_ref, kid) {
            Seat::Seated => return KeyOf::Yes,
            Seat::NotSeated => {}
            Seat::BundleNotHeld => {
                if missing.is_empty() && self.is_accord_holder(iss, depth) {
                    missing.push(ChainMissing::Bundle);
                }
            }
        }
        if missing.is_empty() {
            KeyOf::No
        } else {
            missing.sort();
            missing.dedup();
            KeyOf::Waiting(missing)
        }
    }

    /// v62.0.0 (R1 round 3; CC 2.6.1.9, CC 2.4.1.1; CIRISVerify 23.3.1's
    /// `KeyRecordDirectory`, `key_of_iss_v2.json` `rotation_lacks_possession`)
    /// — **a rotation of `kid` whose own statement is not held.** The row
    /// `row_id` (a record of `kid`) carries a predecessor's voice under `iss`
    /// naming the predecessor's record by `refs.target`:
    ///
    /// - that record held as the predecessor's own, under `iss`, covering the
    ///   rotation's instant: the row waits on `kid`'s own statement over it
    ///   ([`ChainMissing::Voice`]), since a row gains voices without changing
    ///   its id, and a voice not held is waited on, never refused;
    /// - that record not held at all: it waits on the record
    ///   ([`ChainMissing::Record`]);
    /// - otherwise (held as something else, of another issuer, or not
    ///   covering the instant): `None`, the row hands on nothing.
    ///
    /// No voice of a predecessor under `iss` (a record of `kid` that only an
    /// unrelated key signed, naming no target) is `None` as before: the
    /// record attaches nothing.
    fn possession_missing(
        &self,
        kid: &Digest32,
        iss_ref: &str,
        row_id: &Digest32,
        voices: &[Voice],
        depth: usize,
    ) -> Option<ChainMissing> {
        for pred in voices
            .iter()
            .filter(|v| v.row.kid != *kid && v.row.iss == iss_ref)
        {
            let Some(target) = names_of(&pred.row.payload)
                .ok()
                .and_then(|n| single(&n, "target"))
                .map(|r| r.0)
            else {
                continue;
            };
            let p = pred.row.kid;
            let window = self.records.get(&p).and_then(|sts| {
                self.record_voices(&p, sts, depth + 1)
                    .get(&target)
                    .and_then(|vs| vs.iter().find(|v| v.row.kid == p && v.row.iss == iss_ref))
                    .map(|v| (v.record.asserted_at, v.record.valid_until))
            });
            match window {
                Some(w) if covers(w, pred.row.asserted_at) => {
                    return Some(ChainMissing::Voice {
                        kid: *kid,
                        row: *row_id,
                    });
                }
                Some(_) => {}
                None if !self.holds_row(&target) => return Some(ChainMissing::Record(target)),
                None => {}
            }
        }
        None
    }

    /// Does a valid record of the genesis key `iss` name the role
    /// `accord_holder`? Only an accord holder's seat moves by a bundle.
    fn is_accord_holder(&self, iss: &Digest32, depth: usize) -> bool {
        self.judged(iss, depth + 1).is_ok_and(|v| {
            v.iter()
                .any(|r| r.record.identity_type.iter().any(|t| t == "accord_holder"))
        })
    }

    /// The valid voices over records of `kid` (payload `key` is `kid`),
    /// by row id, verified through this directory one level deeper.
    fn record_voices(
        &self,
        kid: &Digest32,
        statements: &[Vec<u8>],
        depth: usize,
    ) -> BTreeMap<Digest32, Vec<Voice>> {
        let mut rows: BTreeMap<Digest32, Vec<Voice>> = BTreeMap::new();
        for st in statements {
            let own_key = statement_parts(st)
                .and_then(|(_, p)| check_key_record(&p).ok())
                .map(|r| r.key);
            let scoped = Scoped {
                held: self,
                depth: depth + 1,
                own: *kid,
                own_key,
            };
            if let Verdict::Valid(row) = verify_row_statement(st, &scoped) {
                if row.family != KEY_RECORD_FAMILY {
                    continue;
                }
                if super::door::check_identity_set_exclusive(&row.sub, &row.payload).is_err() {
                    continue;
                }
                if let Ok(rec) = check_key_record(&row.payload) {
                    if rec.kid == *kid {
                        rows.entry(row.row_id).or_default().push(Voice {
                            record: rec,
                            row: *row,
                        });
                    }
                }
            }
        }
        rows
    }

    /// Is a statement over the row `row` held among the records?
    fn holds_row(&self, row: &Digest32) -> bool {
        self.records
            .values()
            .flatten()
            .any(|st| super::names::RowId::of_statement(st).is_some_and(|r| r.0 == *row))
    }

    /// Is a statement over the record row `row`, filed under `kid` and
    /// signed by another key, held, with none of them waiting on a key? The
    /// caller found no predecessor voice under `iss`, so such statements are
    /// held and refused: the rotation hands on nothing.
    fn co_statements_refused(
        &self,
        kid: &Digest32,
        statements: &[Vec<u8>],
        row: &Digest32,
        depth: usize,
    ) -> bool {
        let mut held = false;
        for st in statements {
            let Some((protected, payload)) = statement_parts(st) else {
                continue;
            };
            let signer = protected
                .get_int(4)
                .and_then(Value::as_bytes)
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            if signer.is_none_or(|s| s == *kid)
                || !super::names::RowId::of_statement(st).is_some_and(|r| r.0 == *row)
            {
                continue;
            }
            held = true;
            let scoped = Scoped {
                held: self,
                depth: depth + 1,
                own: *kid,
                own_key: check_key_record(&payload).ok().map(|r| r.key),
            };
            if matches!(verify_row_statement(st, &scoped), Verdict::Waiting { .. }) {
                return false;
            }
        }
        held
    }

    /// The key whose held record has row id `row`, if any.
    fn record_owner(&self, row: &Digest32, depth: usize) -> Option<Digest32> {
        self.records.iter().find_map(|(k, sts)| {
            sts.iter()
                .any(|st| super::names::RowId::of_statement(st).is_some_and(|r| r.0 == *row))
                .then_some(*k)
                .filter(|_| depth <= MAX_DEPTH)
        })
    }

    /// Is another key's record, other than `row`, a rotation from the same
    /// predecessor record `target` under `iss`: its own statement and the
    /// predecessor `pred`'s, both under `iss`, naming `target`, with
    /// `target`'s `window` covering its instant?
    #[allow(clippy::too_many_arguments)]
    fn rival_rotation(
        &self,
        kid: &Digest32,
        pred: &Digest32,
        iss: &str,
        target: &Digest32,
        window: (u64, Option<u64>),
        row: &Digest32,
        depth: usize,
    ) -> bool {
        self.records
            .iter()
            .filter(|(k, _)| *k != kid && *k != pred)
            .any(|(k, sts)| {
                self.record_voices(k, sts, depth + 1)
                    .iter()
                    .filter(|(r, _)| *r != row)
                    .any(|(_, voices)| {
                        let named = |v: &Voice| {
                            names_of(&v.row.payload)
                                .ok()
                                .and_then(|n| single(&n, "target"))
                                .is_some_and(|t| t.0 == *target)
                        };
                        // A rival counts only as the rotation path would:
                        // it names the predecessor's valid record, and
                        // that record covers the rival's instant.
                        voices.iter().any(|v| {
                            v.row.kid == *k
                                && v.row.iss == iss
                                && named(v)
                                && covers(window, v.row.asserted_at)
                        }) && voices
                            .iter()
                            .any(|v| v.row.kid == *pred && v.row.iss == iss)
                    })
            })
    }

    /// The held `key:revocation`s of `kid` this reading honours: valid, about
    /// `kid`, and by one of the three revokers (the key itself, or a revoker
    /// [`RevokerStanding`] admits). Whether one has taken effect at an
    /// instant is its `revoked_after`.
    ///
    /// v62.0.0 (slice J0) — the revocation read model
    /// ([`super::projection`]) projects exactly these, and
    /// [`Self::liveness`] reads exactly these: one fold.
    #[must_use]
    pub fn honoured_revocations(&self, kid: &Digest32) -> Vec<HonouredRevocation> {
        self.honoured_at(kid, 0)
    }

    fn honoured_at(&self, kid: &Digest32, depth: usize) -> Vec<HonouredRevocation> {
        let subject = identity_ref(kid);
        self.revocations
            .iter()
            .filter_map(|st| {
                // A revocation's signer is resolved over records only, so a key
                // revoking itself does not recurse into its own revocation.
                let records_only = RecordsOnly {
                    held: self,
                    depth: depth + 1,
                };
                let Verdict::Valid(row) = verify_row_statement(st, &records_only) else {
                    return None;
                };
                if row.family != KEY_REVOCATION_FAMILY || row.sub != subject {
                    return None;
                }
                // The revoker's key must be a key of the `iss` whose standing
                // is asked (I2101).
                let of_iss = super::ingest::kid_of_identity_ref(&row.iss).is_some_and(|i| {
                    matches!(self.key_of_at_depth(&row.kid, &i, depth + 1), KeyOf::Yes)
                });
                if !of_iss {
                    return None;
                }
                let by_itself = row.kid == *kid;
                if !by_itself && !self.standing.may_revoke(&row.iss, &subject) {
                    return None;
                }
                let revoked_after = row
                    .payload
                    .get_text("revoked_after")
                    .and_then(Value::as_u64);
                Some(HonouredRevocation {
                    statement: st.clone(),
                    row: *row,
                    revoked_after,
                })
            })
            .collect()
    }
}

/// A held key record that verifies and keeps the end rule
/// ([`HeldKeys::valid_records`]).
#[derive(Clone, Debug)]
pub struct ValidRecord {
    /// The record's reading.
    pub record: KeyRecord,
    /// The record row's id.
    pub row_id: Digest32,
    /// v62.0.0 (kernel pass 2, K1) — the kid whose voice over the row is
    /// this statement (the key itself, or a predecessor's over a rotation).
    pub signer: Digest32,
    /// The statement as held.
    pub statement: Vec<u8>,
}

/// Does a record's window cover `at`? v62.0.0 (CC ruling, kernel pass 2,
/// K1): half-open, `[asserted_at, valid_until)`, through the one boundary
/// function ([`crate::kernel::key_end::within_record`]) — the key-of-iss
/// chain's predecessor record covering a rotation's instant, and a key's own
/// liveness, read the same window.
fn covers((from, until): (u64, Option<u64>), at: u64) -> bool {
    crate::kernel::key_end::within_record(at, from, until)
}

/// The former, inclusive window `[asserted_at, valid_until]`: the
/// differential's reference only (test builds).
#[cfg(test)]
fn inclusive((from, until): (u64, Option<u64>), at: u64) -> bool {
    from <= at && until.is_none_or(|u| at <= u)
}

/// Has one of the honoured revocations taken effect at `at`?
fn in_effect(honoured: &[HonouredRevocation], at: u64) -> bool {
    honoured.iter().any(|r| match r.revoked_after {
        // Absent: revoke-all.
        None => true,
        // Statements signed before the bound still stand.
        Some(bound) => at >= bound,
    })
}

/// v62.0.0 (kernel pass 2, K1) — the key's verified records, one view per
/// record row with the keys whose voices over it verified, and its OWN
/// honoured revocations, as the kernel's key-end rows
/// ([`crate::kernel::key_end::KeyEndView`]).
fn key_end_views(
    key: &str,
    kid: &Digest32,
    valid: &[ValidRecord],
    honoured: &[HonouredRevocation],
) -> Vec<crate::kernel::key_end::KeyEndView> {
    use crate::kernel::key_end::{end_rule, KeyEndKind, KeyEndView};
    use crate::kernel::view::RowId;
    let mut by_row: BTreeMap<Digest32, (&KeyRecord, Vec<String>)> = BTreeMap::new();
    for v in valid {
        let e = by_row
            .entry(v.row_id)
            .or_insert_with(|| (&v.record, Vec::new()));
        let signer = hex::encode(v.signer);
        if !e.1.contains(&signer) {
            e.1.push(signer);
        }
    }
    let mut out: Vec<KeyEndView> = by_row
        .into_iter()
        .map(|(row_id, (rec, sigs))| {
            KeyEndView::of_record(
                RowId(row_id),
                key,
                KeyEndKind::Record {
                    from: rec.asserted_at,
                    until: rec.valid_until,
                    sigs,
                    end: end_rule(&rec.identity_type),
                },
            )
        })
        .collect();
    out.extend(
        honoured
            .iter()
            .filter(|r| r.row.kid == *kid)
            .map(|r| KeyEndView::self_revocation(RowId(r.row.row_id), key, r.revoked_after)),
    );
    out
}

/// One verified voice over a record row of a key.
struct Voice {
    record: KeyRecord,
    row: ciris_verify_core::edition2::VerifiedRow,
}

/// What a key-chain link waits on ([`KeyOf::Waiting`]). Verify's
/// `MissingKey` carries `Kid`, `Record` and `Voice` ([`KeyOf::to_verify`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainMissing {
    /// A key, by its thumbprint: its statement over the rotation, or its
    /// own records.
    Kid(Digest32),
    /// The predecessor's record the rotation names, by row id: not held.
    Record(Digest32),
    /// The accord's genesis bundle in force, which seats holders' keys:
    /// none held. Persist's own; Verify's bundle reader answers seats.
    Bundle,
    /// v62.0.0 (R1 round 3; CC 2.6.1.9) — a voice of a held rotation row
    /// that is not held: `kid`'s own statement over `row` (proof of
    /// possession). Verify 23.3.1's `MissingKey::Voice`.
    Voice {
        /// The key whose statement is missing.
        kid: Digest32,
        /// The row it would be over.
        row: Digest32,
    },
}

/// The keys the accord's genesis bundle in force seats, by holder
/// identity-ref (v62.0.0, JSON-cut slice A, I2101's seat arm).
///
/// The seats are the keys the bundle IN FORCE places for each seat, never
/// an earlier bundle's: a holder or serve node re-seated at a new key by a
/// later bundle is read at that key only.
///
/// `edition2::genesis::bundle_seats_in_force` yields it from Verify's
/// bundle placement. TODO(bundle-seats): the store door does not read it
/// yet and holds [`BundleSeats::not_held`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleSeats(Option<BTreeMap<String, std::collections::BTreeSet<Digest32>>>);

/// What [`BundleSeats`] says of one key for one identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seat {
    /// The bundle in force seats the key for the identity.
    Seated,
    /// A bundle is held, and does not.
    NotSeated,
    /// No bundle is held.
    BundleNotHeld,
}

impl BundleSeats {
    /// No bundle held (pre-genesis, or not yet read).
    #[must_use]
    pub fn not_held() -> Self {
        BundleSeats(None)
    }

    /// The seats of a held bundle: each holder identity-ref and the key(s)
    /// it seats for it.
    #[must_use]
    pub fn held(seats: impl IntoIterator<Item = (String, Digest32)>) -> Self {
        let mut m: BTreeMap<String, std::collections::BTreeSet<Digest32>> = BTreeMap::new();
        for (holder, kid) in seats {
            m.entry(holder).or_default().insert(kid);
        }
        BundleSeats(Some(m))
    }

    /// Is `kid` seated for `holder`?
    #[must_use]
    pub fn seat(&self, holder: &str, kid: &Digest32) -> Seat {
        match &self.0 {
            None => Seat::BundleNotHeld,
            Some(m) if m.get(holder).is_some_and(|ks| ks.contains(kid)) => Seat::Seated,
            Some(_) => Seat::NotSeated,
        }
    }
}

/// Whether a key is a key of an identity ([`HeldKeys::key_of`]):
/// persist's reading, mapped onto Verify's `KeyOf` by [`KeyOf::to_verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyOf {
    /// It is: the chain reaches the identity's genesis key.
    Yes,
    /// It is not.
    No,
    /// A link of the chain is not held.
    Waiting(Vec<ChainMissing>),
}

impl KeyOf {
    /// **The one mapping onto CIRISVerify's `KeyDirectory::key_of`
    /// answer** (v62.0.0, slice C3). A key or a record maps to Verify's
    /// `MissingKey::Kid` / `MissingKey::Record`. [`ChainMissing::Bundle`]
    /// (no genesis bundle in force held) maps to `MissingKey::Kid(kid)`, the
    /// signing key the bundle would seat, so the reading stays retryable.
    /// R1 (Verify 23.3.1): Verify now has `MissingKey::Bundle(object_id)`,
    /// but persist's seat arm does not know the object id of a bundle it
    /// does not hold ([`BundleSeats`]), so the mapping is unchanged.
    #[must_use]
    pub fn to_verify(&self, kid: &Digest32) -> VerifyKeyOf {
        match self {
            KeyOf::Yes => VerifyKeyOf::Yes,
            KeyOf::No => VerifyKeyOf::No,
            KeyOf::Waiting(m) => VerifyKeyOf::Waiting(
                m.iter()
                    .map(|c| match c {
                        ChainMissing::Kid(k) => MissingKey::Kid(*k),
                        ChainMissing::Record(r) => MissingKey::Record(*r),
                        ChainMissing::Bundle => MissingKey::Kid(*kid),
                        ChainMissing::Voice { kid: k, row } => {
                            MissingKey::Voice { kid: *k, row: *row }
                        }
                    })
                    .collect(),
            ),
        }
    }
}

/// A `key:revocation` the reading honours ([`HeldKeys::honoured_revocations`]).
#[derive(Clone, Debug)]
pub struct HonouredRevocation {
    /// The statement as held.
    pub statement: Vec<u8>,
    /// Verify's reading of it.
    pub row: ciris_verify_core::edition2::VerifiedRow,
    /// Its `revoked_after` bound, POSIX ms; `None` revokes the key outright.
    pub revoked_after: Option<u64>,
}

/// The view a key record's own statement is verified through: its own key
/// (a self-signed record) is taken from its payload, every other key from
/// the directory one level deeper (Verify's `Scoped`, over persist's reading).
struct Scoped<'a> {
    held: &'a HeldKeys,
    depth: usize,
    own: Digest32,
    own_key: Option<CompositePublicKey>,
}

impl KeyDirectory for Scoped<'_> {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        if *kid == self.own {
            return self
                .own_key
                .clone()
                .map_or(KeyLookup::Invalid, |k| KeyLookup::Held(Box::new(k)));
        }
        lookup_of(
            self.held.resolve(kid, asserted_at, self.depth, true),
            kid,
            asserted_at,
        )
    }

    /// A record's own statement names the issuer it claims; here that claim
    /// only lets the record read as a record of its key. Whether the key is
    /// the issuer's is [`HeldKeys::key_of`]'s chain (Verify's `Scoped`).
    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> VerifyKeyOf {
        if *kid == self.own {
            return VerifyKeyOf::Yes;
        }
        self.held
            .key_of_at_depth(kid, iss, self.depth)
            .to_verify(kid)
    }
}

struct RecordsOnly<'a> {
    held: &'a HeldKeys,
    depth: usize,
}

impl KeyDirectory for RecordsOnly<'_> {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        lookup_of(
            self.held.resolve(kid, asserted_at, self.depth, false),
            kid,
            asserted_at,
        )
    }

    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> VerifyKeyOf {
        self.held
            .key_of_at_depth(kid, iss, self.depth)
            .to_verify(kid)
    }
}

fn lookup_of(l: Liveness, kid: &Digest32, at: u64) -> KeyLookup {
    match l {
        Liveness::Live(r) => KeyLookup::Held(Box::new(r.key)),
        // Retryable: the key itself may still arrive (CC 2.4.1.1).
        Liveness::NotHeld => KeyLookup::Waiting(vec![MissingKey::Kid(*kid)]),
        // Retryable: a record of the key covering the instant may still
        // arrive (CC 2.4.1.1; Verify 23.3.0's `MissingKey::CoveringRecord`).
        Liveness::NotCovered => KeyLookup::Waiting(vec![MissingKey::CoveringRecord {
            kid: *kid,
            at_ms: at,
        }]),
        Liveness::Waiting(m) => KeyLookup::Waiting(m),
        Liveness::Revoked | Liveness::Invalid => KeyLookup::Invalid,
    }
}

/// The directory Verify's reader reads a statement through: `lookup` is
/// [`HeldKeys::liveness`], and `key_of` (the key-of-issuer check,
/// `kid_not_of_iss`) is [`HeldKeys::key_of`], the one check the door also
/// runs (v62.0.0, slice C3).
impl KeyDirectory for HeldKeys {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        lookup_of(self.liveness(kid, asserted_at), kid, asserted_at)
    }

    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> VerifyKeyOf {
        HeldKeys::key_of(self, kid, iss).to_verify(kid)
    }
}
