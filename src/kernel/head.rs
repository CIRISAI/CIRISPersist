//! v62.0.0 (slice C) — **a group's head, as entries**: the held version and
//! an offered one, as the kernel's `head::Entry` rows (kind `Seat`: a roster
//! version names the versions it extends).
//!
//! CC 2.7.8: "Two versions of one head wait as tips. The roster is then the
//! members common to all tips, until a version naming the tips makes one head
//! again." The kernel holds an offered version that does not name the held
//! head, as a tip beside the held head (it names a version this node holds)
//! or as a row waiting for the head it names.
//!
//! v62.0.0 (kernel pass 2, I2811) — **switched.** Persist's
//! `held_head_verdict` answers through [`head_answer`]: a [`HeadReading::Tip`]
//! is held (`federation_group_tips`), never refused, and the head stays
//! where it is. The differential still records the former refusal as the
//! named `fork_as_tip` departure ([`super::differential`]), so a run shows
//! every call that the switch changed.
//!
//! What stays persist's: a `supersede_proof` that names another prior than
//! the version it rides on is a contradiction inside one row, refused for
//! its shape before the kernel.
//!
//! Not presented (named in the K1 notes): the roster read as "the members
//! common to all tips" and the version naming the tips that "makes one head
//! again" — a `group:roster` version names one `prev` today, so no version
//! can name two tips.

use super::view::{Micros, RowId};
use super::{Answer, DepKey};
use ciris_kernel::head::{Entry, Kind};
use ciris_kernel::Row;

/// A head entry with the [`Row`] view the kernel's graph reads.
#[derive(Clone, Debug)]
pub struct HeadRow(pub Entry<RowId, String, Micros>);

impl Row for HeadRow {
    type Id = RowId;
    type Key = String;
    fn id(&self) -> &RowId {
        &self.0.id
    }
    fn names(&self) -> &[RowId] {
        &self.0.names
    }
    fn signer(&self) -> &String {
        &self.0.signer
    }
}

/// What the kernel reads of an offered version against the held head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadReading {
    /// No head is held: nothing for the version to extend in place.
    NothingHeld,
    /// The version names the held head: one head again, the version.
    Extends,
    /// The version names another version: two tips (or a row waiting for
    /// the head it names). Held, never refused (CC 2.7.8).
    Tip,
}

/// The entries of the held head and the offered version. An empty
/// `prev_head_digest` (a lineage's first version) names nothing.
#[must_use]
pub fn head_entries(
    group: &str,
    held: &str,
    offered_prev: &str,
    offered_signer: &str,
) -> [HeadRow; 2] {
    let h = Entry::new(
        RowId::of_hash(held),
        Kind::Seat,
        group.to_owned(),
        Vec::new(),
    );
    let names = if offered_prev.is_empty() {
        Vec::new()
    } else {
        vec![RowId::of_hash(offered_prev)]
    };
    let v = Entry::new(
        RowId::of_label(&["offered-version", group, offered_prev]),
        Kind::Seat,
        offered_signer.to_owned(),
        names,
    );
    [HeadRow(h), HeadRow(v)]
}

/// **The kernel's reading of a supersede**: the frontier of the two
/// versions is one head (the version extends the held head) or two tips.
#[must_use]
pub fn head_reading(
    group: &str,
    held: Option<&str>,
    offered_prev: &str,
    offered_signer: &str,
) -> HeadReading {
    let Some(held) = held else {
        return HeadReading::NothingHeld;
    };
    let rows = head_entries(group, held, offered_prev, offered_signer);
    let g = ciris_kernel::graph::Graph::new(rows.iter());
    match g.frontier(&[0, 1]).as_slice() {
        [one] if *one == 1 => HeadReading::Extends,
        _ => HeadReading::Tip,
    }
}

/// v62.0.0 (kernel pass 2, I2811, I2810) — [`head_reading`] as an
/// [`Answer`]: the rows it read (the held head and the version the offer
/// names, when it names one) and its read set, the group's roster (a new
/// version of the group can change the reading; nothing else can).
#[must_use]
pub fn head_answer(group: &str, held: Option<&str>, offered_prev: &str) -> Answer<HeadReading> {
    let value = head_reading(group, held, offered_prev, "");
    let rows: Vec<RowId> = held
        .map(RowId::of_hash)
        .into_iter()
        .chain(
            (!offered_prev.is_empty() && held != Some(offered_prev))
                .then(|| RowId::of_hash(offered_prev)),
        )
        .collect();
    Answer::reading(
        value,
        rows,
        vec![DepKey::Roster(group.to_owned())],
        "graph::Graph::frontier",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I2811 / I2810 — the answer is the reading, rests on the two versions
    /// it read, and reads the group's roster only.
    #[test]
    fn i2811_the_head_answer_is_the_reading_over_the_versions_it_read() {
        let h = "aa".repeat(32);
        let other = "bb".repeat(32);
        let a = head_answer("g", Some(&h), &other);
        assert_eq!(a.value, HeadReading::Tip, "I2811: a sibling is a tip");
        assert_eq!(
            a.rows,
            vec![RowId::of_hash(&h), RowId::of_hash(&other)],
            "I2810: the rows read are the held head and the version named"
        );
        assert_eq!(a.reads, vec![DepKey::Roster("g".into())], "I2810");
        assert!(a.read_any(&[DepKey::Roster("g".into())]), "I2810");
        assert!(
            !a.read_any(&[DepKey::Roster("another".into())]),
            "I2810: another group's version cannot change the reading"
        );
        let e = head_answer("g", Some(&h), &h);
        assert_eq!(e.value, HeadReading::Extends, "I2811");
        assert_eq!(e.rows, vec![RowId::of_hash(&h)], "I2810: one version read");
        let f = head_answer("g", Some(&h), "");
        assert_eq!(
            f.value,
            HeadReading::Tip,
            "I2811: a second founding version"
        );
        assert_eq!(f.rows, vec![RowId::of_hash(&h)], "I2810");
        assert_eq!(head_answer("g", None, &h).value, HeadReading::NothingHeld);
    }

    #[test]
    fn i1837_a_version_naming_the_held_head_extends_it_and_any_other_is_a_tip() {
        let h = "aa".repeat(32);
        let other = "bb".repeat(32);
        assert_eq!(head_reading("g", Some(&h), &h, "k"), HeadReading::Extends);
        assert_eq!(head_reading("g", Some(&h), &other, "k"), HeadReading::Tip);
        assert_eq!(head_reading("g", Some(&h), "", "k"), HeadReading::Tip);
        assert_eq!(head_reading("g", None, &h, "k"), HeadReading::NothingHeld);
    }
}
