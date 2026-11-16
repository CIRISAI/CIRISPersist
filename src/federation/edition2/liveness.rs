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
//!   by then. A record covers `[asserted_at, valid_until]`, or
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
//! TODO(key_end): when slice C's kernel adapter is merged, this reading is
//! the kernel's `key_end` conclusion (`well_formed`, `conclude_rule`, `live`,
//! `ended`, `retained`) over `KeyEndRow`s built from these records. Until
//! then it is a persist read with the same inputs. No row but a record of
//! the key and a revocation by one of the three enters it.

use std::collections::BTreeMap;
use std::sync::Arc;

use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::keys::{check_key_record, KeyRecord, KEY_RECORD_FAMILY};
use ciris_verify_core::edition2::{
    identity_ref, verify_row_statement, Digest32, KeyDirectory, KeyLookup, MissingKey, Verdict,
};

/// The family of a key revocation (CC 3.1.3, `key:revocation:v1`'s family id).
pub const KEY_REVOCATION_FAMILY: &str = "key:revocation";

/// How deep a chain of signer records is followed (Verify's bound).
const MAX_DEPTH: usize = ciris_verify_core::edition2::keys::MAX_RECORD_DEPTH;

/// Who besides the key itself may revoke it (CC 2.4.1.1, "Who may revoke a
/// key"): its owner under the owner-binding, and the roster that seats it.
///
/// TODO(key_end): the edition-2 owner-binding and roster rows are read by the
/// kernel adapter (slice C). Until it lands, a host that holds them answers
/// here.
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
        }
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
        if with_revocations && self.revoked(kid, at, depth) {
            return Liveness::Revoked;
        }
        // Renewals all count: the instant is covered by any one of them.
        valid
            .into_iter()
            .map(|v| v.record)
            .filter(|r| r.asserted_at <= at && r.valid_until.is_none_or(|u| at <= u))
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
                    match check_key_record(&row.payload) {
                        Ok(rec) if rec.kid == *kid => valid.push(ValidRecord {
                            record: rec,
                            row_id: row.row_id,
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

    /// Has a revocation by one of the three revokers taken effect for `kid`
    /// by `at`?
    fn revoked(&self, kid: &Digest32, at: u64, depth: usize) -> bool {
        self.honoured_at(kid, depth)
            .iter()
            .any(|r| match r.revoked_after {
                // Absent: revoke-all.
                None => true,
                // Statements signed before the bound still stand.
                Some(bound) => at >= bound,
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
    /// The statement as held.
    pub statement: Vec<u8>,
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
        lookup_of(self.held.resolve(kid, asserted_at, self.depth, true), kid)
    }
}

struct RecordsOnly<'a> {
    held: &'a HeldKeys,
    depth: usize,
}

impl KeyDirectory for RecordsOnly<'_> {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        lookup_of(self.held.resolve(kid, asserted_at, self.depth, false), kid)
    }
}

fn lookup_of(l: Liveness, kid: &Digest32) -> KeyLookup {
    match l {
        Liveness::Live(r) => KeyLookup::Held(Box::new(r.key)),
        // Retryable: a record covering the instant, or the key itself, may
        // still arrive (CC 2.4.1.1). Reported as a key to wait on.
        Liveness::NotCovered | Liveness::NotHeld => KeyLookup::Waiting(vec![MissingKey::Kid(*kid)]),
        Liveness::Waiting(m) => KeyLookup::Waiting(m),
        Liveness::Revoked | Liveness::Invalid => KeyLookup::Invalid,
    }
}

impl KeyDirectory for HeldKeys {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        lookup_of(self.liveness(kid, asserted_at), kid)
    }
}
