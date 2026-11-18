//! v62.0.0 (kernel pass 2, K1) — **a key's own end**, as the kernel reads it
//! (`ciris_kernel::key_end`; CC 2.4.1.1 "A key's own end (normative)", CC
//! 2.7.5).
//!
//! CC 2.4.1.1: "A key is live at an instant when one of its records covers
//! that instant and its own revocation has not taken effect by then. It has
//! ended when every one of its records has ended." The edition-2 key plane
//! ([`crate::federation::edition2::liveness::HeldKeys`]) presents each held
//! `key:record` of the key that verified, and each of the key's OWN
//! `key:revocation`s, as a [`KeyEndView`]; the kernel decides which records
//! are well formed under the end rule (`key_end::well_formed`, ceiling
//! [`KEY_RECORD_CEIL_MS`]), which conclude (`key_end::conclude_rule`), and
//! whether the key is [`live`](key_live) or [`ended`](key_ended) at an
//! instant. No sweep reads a clock; the instant is the caller's argument.
//!
//! | presented | kernel field | persist source |
//! |---|---|---|
//! | a record row | `Record { key, from, until, sigs, end }` | Verify's `KeyRecord` (`asserted_at`, `valid_until`, `identity_type`), the verified voices over the row |
//! | a self-revocation | `revocation() = (key, revoked_after)` | an honoured `key:revocation` the key signed itself; no `revoked_after` revokes from 0 |
//!
//! What stays persist's: signature verification and the record's chain to
//! its predecessor (Verify's `verify_row_statement`; a record reaches the
//! kernel only once a voice over it verified, so each record is presented
//! as concluding on its own: `names` is empty, never a renewal or a
//! rotation the kernel re-walks); and the owner / roster revokers of
//! `RevokerStanding`, which the kernel's key-end reading does not count (CC
//! 2.4.1.1: "No other row enters that reading") — persist keeps them on top
//! of this answer until a ruling (K1 notes).
//!
//! **The boundary** (CC ruling, v62.0.0: half-open everywhere). A record
//! covers `t` when `asserted_at <= t < valid_until` ([`within_record`], the
//! one function every coverage reading calls). Persist read it inclusive of
//! `valid_until` before, as Verify 23.1.3's `KeyRecordDirectory` still does
//! (Verify follows in 23.3.1): the one instant where the readings differ is
//! the named differential class `key_end_half_open`.

use super::view::RowId;
use super::{Answer, DepKey};
use ciris_kernel::key_end::{self as ke, EndRule, KeyEndRow, Record};
use ciris_kernel::layers;
use ciris_kernel::Row;

/// `key_record_max_secs` (CC 2.4.1.1; Verify's `KEY_RECORD_MAX_SECS`,
/// 31,536,000 s) in the milliseconds every instant here is read in: a
/// `node` / `agent` record's `valid_until` is at most this after its
/// `asserted_at`.
pub const KEY_RECORD_CEIL_MS: u64 = 31_536_000 * 1000;

/// **The one boundary of a record's window** (CC ruling, v62.0.0: half-open
/// everywhere): a record stating `[from, until)` covers `at` when
/// `from <= at < until`; no `until` covers every instant from `from`. Every
/// coverage reading in persist calls this — a key's liveness (the kernel's
/// `key_end::live` reads the same window), the key-of-issuer chain's
/// predecessor record covering a rotation, an occurrence's window — so the
/// boundary is one line. Instants are POSIX ms.
#[must_use]
pub fn within_record(at: u64, from: u64, until: Option<u64>) -> bool {
    from <= at && until.is_none_or(|u| at < u)
}

/// The end rule of a record, read from its `identity_type` set alone (CC
/// 2.4.1.1): a `node` or `agent` key MUST state an end, a `user` or
/// `accord_holder` key MUST NOT, any other role may. A set mixing the two
/// groups is refused before this (Verify's `check_key_record`); read here,
/// the machine rule wins, so such a set states an end or concludes nothing.
#[must_use]
pub fn end_rule(identity_type: &[String]) -> EndRule {
    let has = |r: &str| identity_type.iter().any(|t| t == r);
    if has("node") || has("agent") {
        EndRule::Required
    } else if has("user") || has("accord_holder") {
        EndRule::Forbidden
    } else {
        EndRule::Optional
    }
}

/// What a [`KeyEndView`] presents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyEndKind {
    /// A `key:record` of `key`.
    Record {
        /// Its signed `asserted_at`, ms.
        from: u64,
        /// Its signed `valid_until`, ms.
        until: Option<u64>,
        /// The keys whose voices over the row verified.
        sigs: Vec<String>,
        /// Its end rule ([`end_rule`]).
        end: EndRule,
    },
    /// The key's own `key:revocation`, in effect from `after` (ms).
    Revocation {
        /// Its `revoked_after`; `0` for a revocation that states none.
        after: u64,
    },
}

/// One row of a key's end, as the kernel's `key_end::KeyEndRow` reads it.
#[derive(Clone, Debug)]
pub struct KeyEndView {
    id: RowId,
    names: Vec<RowId>,
    key: String,
    signer: String,
    kind: KeyEndKind,
}

impl KeyEndView {
    /// A record row `id` of `key` (its voices are `kind`'s `sigs`).
    #[must_use]
    pub fn of_record(id: RowId, key: &str, kind: KeyEndKind) -> Self {
        KeyEndView {
            id,
            names: Vec::new(),
            key: key.to_owned(),
            signer: key.to_owned(),
            kind,
        }
    }

    /// The key's own revocation `id`, in effect from `revoked_after` (`None`:
    /// from the first instant).
    #[must_use]
    pub fn self_revocation(id: RowId, key: &str, revoked_after: Option<u64>) -> Self {
        KeyEndView {
            id,
            names: Vec::new(),
            key: key.to_owned(),
            signer: key.to_owned(),
            kind: KeyEndKind::Revocation {
                after: revoked_after.unwrap_or(0),
            },
        }
    }
}

impl Row for KeyEndView {
    type Id = RowId;
    type Key = String;
    fn id(&self) -> &RowId {
        &self.id
    }
    fn names(&self) -> &[RowId] {
        &self.names
    }
    fn signer(&self) -> &String {
        &self.signer
    }
}

impl KeyEndRow for KeyEndView {
    type T = u64;
    fn record(&self) -> Option<Record<'_, String, u64>> {
        match &self.kind {
            KeyEndKind::Record {
                from,
                until,
                sigs,
                end,
            } => Some(Record {
                key: &self.key,
                from: *from,
                until: *until,
                succ_of: None,
                at_old: None,
                sigs: sigs.as_slice(),
                end: *end,
            }),
            KeyEndKind::Revocation { .. } => None,
        }
    }
    fn revocation(&self) -> Option<(&String, u64)> {
        match &self.kind {
            KeyEndKind::Revocation { after } => Some((&self.key, *after)),
            KeyEndKind::Record { .. } => None,
        }
    }
}

/// The kernel's two layers over `rows`: kept under the end rule's door,
/// then concluded.
#[allow(clippy::redundant_closure)] // the rule's lifetimes are higher-ranked
fn concluded(rows: &[KeyEndView]) -> layers::Concluded<'_, KeyEndView> {
    let kept = layers::kept(rows, |r| ke::well_formed(r, KEY_RECORD_CEIL_MS));
    layers::conclude(kept, |p| ke::conclude_rule(p), None)
}

/// The concluded record rows of `key` (the rows the answer rests on).
fn concluded_records(c: &layers::Concluded<'_, KeyEndView>, key: &str) -> Vec<RowId> {
    c.cs()
        .iter()
        .map(|&i| c.g.row(i))
        .filter(|r| r.key == key && r.record().is_some())
        .map(|r| r.id)
        .collect()
}

/// **Is `key` live at `at`** (ms): one of its concluded records covers
/// `at` and its own revocation has not taken effect (`key_end::live`). The
/// read set is the key plane of `key` alone (CC 2.4.1.1: "No other row
/// enters that reading").
#[must_use]
pub fn key_live(rows: &[KeyEndView], key: &str, at: u64) -> Answer<bool> {
    let c = concluded(rows);
    let value = ke::live(&c, &key.to_owned(), at);
    Answer::reading(
        value,
        concluded_records(&c, key),
        vec![DepKey::Keys(key.to_owned())],
        "key_end::live",
    )
}

/// **Has `key` ended at `at`** (ms): every record of it ends by `at`, or it
/// revoked itself by then (`key_end::ended`). A record not yet begun has not
/// ended.
#[must_use]
pub fn key_ended(rows: &[KeyEndView], key: &str, at: u64) -> Answer<bool> {
    let c = concluded(rows);
    let value = ke::ended(&c, &key.to_owned(), at);
    Answer::reading(
        value,
        concluded_records(&c, key),
        vec![DepKey::Keys(key.to_owned())],
        "key_end::ended",
    )
}

/// The records of `key` the kernel's door keeps and concludes (well formed
/// under the end rule): the records [`key_live`] reads.
#[must_use]
pub fn kept_records(rows: &[KeyEndView], key: &str) -> Vec<RowId> {
    concluded_records(&concluded(rows), key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "k";

    fn rec(i: u8, from: u64, until: Option<u64>, end: EndRule) -> KeyEndView {
        KeyEndView::of_record(
            RowId([i; 32]),
            K,
            KeyEndKind::Record {
                from,
                until,
                sigs: vec![K.to_owned()],
                end,
            },
        )
    }

    /// **I2814** — a machine key is live over `[asserted_at, valid_until)`
    /// of a record that keeps the end rule; renewals all count; a record
    /// over the ceiling, one with no end, and a person's record with one
    /// make the key live nowhere.
    #[test]
    fn i2814_a_key_is_live_over_its_records_under_the_end_rule() {
        let rows = vec![rec(1, 1_000, Some(10_000), EndRule::Required)];
        assert!(!key_live(&rows, K, 999).value, "I2814: before");
        assert!(key_live(&rows, K, 1_000).value, "I2814: at start");
        assert!(key_live(&rows, K, 9_999).value, "I2814: inside");
        assert!(
            !key_live(&rows, K, 10_000).value,
            "I2814: at valid_until the record has ended (half-open)"
        );
        assert_eq!(key_live(&rows, K, 5_000).rows, vec![RowId([1; 32])]);
        assert_eq!(
            key_live(&rows, K, 5_000).reads,
            vec![DepKey::Keys(K.into())],
            "I2810: the key plane of the key alone"
        );
        // a renewal signed after the end revives it
        let mut renewed = rows.clone();
        renewed.push(rec(2, 20_000, Some(40_000), EndRule::Required));
        assert!(!key_live(&renewed, K, 15_000).value, "I2814: the gap");
        assert!(key_live(&renewed, K, 30_000).value, "I2814: renewed");
        // the door
        let over = vec![rec(3, 0, Some(KEY_RECORD_CEIL_MS + 1), EndRule::Required)];
        assert!(!key_live(&over, K, 1).value, "I2814: over the ceiling");
        assert!(kept_records(&over, K).is_empty(), "I2814");
        let at_ceiling = vec![rec(3, 0, Some(KEY_RECORD_CEIL_MS), EndRule::Required)];
        assert!(key_live(&at_ceiling, K, 1).value, "I2814: at the ceiling");
        let no_end = vec![rec(4, 0, None, EndRule::Required)];
        assert!(
            !key_live(&no_end, K, 1).value,
            "I2814: a machine key states an end"
        );
        let person = vec![rec(5, 0, None, EndRule::Forbidden)];
        assert!(
            key_live(&person, K, u64::MAX).value,
            "I2814: a person's key has no end"
        );
        let person_end = vec![rec(6, 0, Some(10), EndRule::Forbidden)];
        assert!(
            !key_live(&person_end, K, 1).value,
            "I2814: a person's key states none"
        );
        let backwards = vec![rec(7, 10, Some(5), EndRule::Required)];
        assert!(
            !key_live(&backwards, K, 7).value,
            "I2814: until before from"
        );
    }

    /// **I2819** — the boundary: `within_record` agrees with the kernel's
    /// `live` at `valid_until - 1`, `valid_until` and `valid_until + 1`, and
    /// at `asserted_at`.
    #[test]
    fn i2819_within_record_is_the_kernels_window() {
        let rows = vec![rec(1, 1_000, Some(10_000), EndRule::Required)];
        for (at, want) in [
            (999, false),
            (1_000, true),
            (9_999, true),
            (10_000, false),
            (10_001, false),
        ] {
            assert_eq!(
                within_record(at, 1_000, Some(10_000)),
                want,
                "I2819 at {at}"
            );
            assert_eq!(
                key_live(&rows, K, at).value,
                want,
                "I2819: the kernel at {at}"
            );
        }
        assert!(within_record(u64::MAX, 5, None), "I2819: no end");
        assert!(
            !within_record(5, 5, Some(5)),
            "I2819: an empty window covers nothing"
        );
    }

    /// **I2815** — the end rule from the role set (CC 2.4.1.1).
    #[test]
    fn i2815_the_end_rule_reads_the_role_set() {
        let set = |r: &[&str]| r.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(end_rule(&set(&["node"])), EndRule::Required);
        assert_eq!(end_rule(&set(&["agent", "steward"])), EndRule::Required);
        assert_eq!(end_rule(&set(&["user"])), EndRule::Forbidden);
        assert_eq!(end_rule(&set(&["accord_holder"])), EndRule::Forbidden);
        assert_eq!(end_rule(&set(&["steward"])), EndRule::Optional);
    }

    /// **I2816** — the key's own revocation ends it from `revoked_after`;
    /// with none it ends it outright; a key has ended when every record has.
    #[test]
    fn i2816_its_own_revocation_ends_a_key() {
        let base = vec![rec(1, 0, Some(10_000), EndRule::Required)];
        let mut bounded = base.clone();
        bounded.push(KeyEndView::self_revocation(RowId([9; 32]), K, Some(5_000)));
        assert!(
            key_live(&bounded, K, 4_999).value,
            "I2816: before the bound"
        );
        assert!(!key_live(&bounded, K, 5_000).value, "I2816: from the bound");
        assert!(key_ended(&bounded, K, 5_000).value, "I2816");
        let mut outright = base.clone();
        outright.push(KeyEndView::self_revocation(RowId([9; 32]), K, None));
        assert!(!key_live(&outright, K, 1).value, "I2816: revoked outright");
        assert!(!key_ended(&base, K, 9_999).value, "I2816: a record covers");
        assert!(
            key_ended(&base, K, 10_000).value,
            "I2816: every record ended"
        );
    }
}
