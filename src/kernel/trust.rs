//! v62.0.0 (slice C) — **the edge leg of a trust root**: does the user hold a
//! live acceptance edge to the root (`trust_root_valid`'s leg 1), as the
//! kernel's trust walk (`ciris_kernel::trust::reaches`) over the user's own
//! acceptance edges.
//!
//! The rows are the user's: its `delegates_to` / `supersedes` toward the root
//! that persist's row-alone and present-instant reads admit (federation
//! tier, not expired, labelled `trust:accepts:v1` or held as acceptance from
//! before the label — CC 3.2 T4a, the directory's report), and every
//! composer of the user's naming one. The kernel concludes and folds them:
//!
//! - a `supersedes` is an edge only when it rotates the signer's OWN grant:
//!   it concludes iff the row it names is a concluded `delegates_to` or
//!   `supersedes` of the same signer (CC 3.2 T2; recursion on ancestry, so a
//!   chain of rotations concludes link by link);
//! - an edge whose own signer's composer wins its chain is ended (CC 3.5.1,
//!   `derived::fold_default`: one signer's chain at a time, `recants` over
//!   `withdraws` over `supersedes`, then the signer's own latest instant);
//! - the walk is one hop from the user: an edge from the user to the root.
//!   A cycle is visited once (`reaches_mono_budget`), so no edge is ever
//!   refused for closing one (I1836).

use super::view::{micros, KRow, RowId};
use super::Answer;
use crate::federation::types::{attestation_type, Attestation};
use ciris_kernel::derived::fold_default;
use ciris_kernel::layers;
use ciris_kernel::seat::Obj;
use ciris_kernel::trust::{reaches, Accepts};
use std::collections::{BTreeMap, BTreeSet};

fn rank(k: &str) -> u8 {
    match k {
        attestation_type::RECANTS => 3,
        attestation_type::WITHDRAWS => 2,
        attestation_type::SUPERSEDES => 1,
        _ => 0,
    }
}

/// The rows of the edge leg: every row of `rows` (the user's slice with its
/// composers) as a view; `edge` marks the candidates persist's own reads
/// admit as an acceptance edge toward the root.
#[must_use]
pub fn edge_rows(rows: &[&Attestation], edge: &dyn Fn(&Attestation) -> bool) -> Vec<KRow> {
    let id_of: BTreeMap<&str, RowId> = rows
        .iter()
        .map(|r| {
            (
                r.attestation_id.as_str(),
                RowId::of_hash(&r.persist_row_hash),
            )
        })
        .collect();
    rows.iter()
        .filter(|r| {
            r.attestation_type == attestation_type::DELEGATES_TO || rank(&r.attestation_type) > 0
        })
        .map(|r| {
            // only a structural composer's pointer names a row (CC 4.5.1.1)
            let composer =
                crate::federation::precedence::is_structural_composer(&r.attestation_type);
            let pointer = composer
                .then(|| {
                    crate::federation::precedence::references_attestation_id_from_envelope(
                        &r.attestation_envelope,
                    )
                })
                .flatten();
            let target = pointer.map(|t| {
                id_of
                    .get(t)
                    .copied()
                    .unwrap_or_else(|| RowId::of_label(&["unheld", t]))
            });
            let mut k = KRow::new(
                RowId::of_hash(&r.persist_row_hash),
                target.into_iter().collect(),
                r.attesting_key_id.clone(),
            )
            .at(micros(r.asserted_at));
            k.seat.target = target;
            k.seat.policy = Some(r.attestation_type.clone());
            if edge(r) {
                k.seat.obj = Some(Obj::Key(r.attested_key_id.clone()));
            }
            k
        })
        .collect()
}

/// The composer kind a view carries (`seat.policy` holds the row's type).
fn kind(r: &KRow) -> &str {
    r.seat.policy.as_deref().unwrap_or("")
}

/// **The kernel's edge leg**: the live acceptance edges, and whether the
/// user's one-hop walk reaches the root over them.
#[must_use]
pub fn edge_leg(rows: &[KRow], user: &str, root: &str) -> Answer<bool> {
    // the door first (`layers::kept`): a row is read only once every row it
    // names is held. On today's wire a reference is a peer-chosen
    // attestation id, so two rows may name each other; such a pair is never
    // kept, concludes nothing, and never reaches the graph (I1846)
    let kept = layers::kept(rows, |_| true);
    let c = layers::conclude(
        kept,
        |p| {
            let r = p.row();
            if kind(r) != attestation_type::SUPERSEDES {
                return true;
            }
            // a rotation of the signer's own grant
            r.seat.target.and_then(|t| p.get(&t)).is_some_and(|t| {
                t.signer == r.signer
                    && (kind(t) == attestation_type::DELEGATES_TO
                        || kind(t) == attestation_type::SUPERSEDES)
            })
        },
        None,
    );
    let composers: Vec<usize> = c
        .cs()
        .iter()
        .copied()
        .filter(|&i| rank(kind(c.g.row(i))) > 0)
        .collect();
    let winners = fold_default(
        &c,
        &composers,
        |r: &KRow| r.seat.target,
        |r: &KRow| rank(kind(r)),
        |r: &KRow| r.at,
    );
    let ended: BTreeSet<(String, RowId)> = winners.keys().cloned().collect();
    let mut live = Vec::new();
    let mut edges: Vec<Accepts<String, ()>> = Vec::new();
    for &i in c.cs() {
        let r = c.g.row(i);
        let Some(Obj::Key(dst)) = &r.seat.obj else {
            continue;
        };
        if ended.contains(&(r.signer.clone(), r.id)) {
            continue; // its own signer's composer wins its chain
        }
        live.push(r.id);
        edges.push(Accepts {
            src: r.signer.clone(),
            dst: dst.clone(),
            classes: Vec::new(),
            depth: 0,
        });
    }
    Answer {
        value: reaches(&edges, &user.to_owned(), &(), 1, &root.to_owned()),
        rows: live,
        rule: "trust::reaches/1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u8, kind: &str, signer: &str, names: Option<u8>, edge_to: Option<&str>) -> KRow {
        let rid = RowId([id; 32]);
        let mut k = KRow::new(
            rid,
            names.map(|n| RowId([n; 32])).into_iter().collect(),
            signer,
        );
        k.seat.target = names.map(|n| RowId([n; 32]));
        k.seat.policy = Some(kind.to_owned());
        k.seat.obj = edge_to.map(|d| Obj::Key(d.to_owned()));
        k
    }

    /// I1846 — two rows whose references name each other (on today's wire a
    /// reference is a peer-chosen id, so the pair is constructible) are never
    /// kept: the leg returns within a bound, and the pair concludes nothing.
    #[test]
    fn i1846_a_name_cycle_waits_and_never_hangs_the_leg() {
        let rows = vec![
            row(1, attestation_type::SUPERSEDES, "u", Some(2), Some("root")),
            row(2, attestation_type::SUPERSEDES, "u", Some(1), Some("root")),
        ];
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(edge_leg(&rows, "u", "root"));
        });
        let a = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("I1846: the edge leg returns within a bound over a name cycle");
        assert!(!a.value, "I1846: a cycle concludes nothing");
        assert!(a.rows.is_empty(), "I1846: no edge of the cycle is live");
        // beside it, an ordinary edge is still read
        let rows = vec![
            row(1, attestation_type::SUPERSEDES, "u", Some(2), Some("root")),
            row(2, attestation_type::SUPERSEDES, "u", Some(1), Some("root")),
            row(3, attestation_type::DELEGATES_TO, "u", None, Some("root")),
        ];
        assert!(
            edge_leg(&rows, "u", "root").value,
            "I1846: the live edge stands"
        );
    }

    /// I1847 — a `supersedes` is an edge only when it rotates the signer's
    /// OWN grant (CC 3.2 T2): one naming another signer's delegation, or the
    /// signer's own row that is no grant, concludes nothing; one naming the
    /// signer's own delegation replaces it (the rotation is the live edge).
    #[test]
    fn i1847_a_rotation_concludes_only_over_the_signers_own_grant() {
        let rows = vec![
            row(1, attestation_type::DELEGATES_TO, "x", None, None),
            row(2, attestation_type::SUPERSEDES, "u", Some(1), Some("root")),
        ];
        assert!(
            !edge_leg(&rows, "u", "root").value,
            "I1847: a rotation of another's grant is no edge"
        );
        let rows = vec![
            row(1, "scores", "u", None, None),
            row(2, attestation_type::SUPERSEDES, "u", Some(1), Some("root")),
        ];
        assert!(
            !edge_leg(&rows, "u", "root").value,
            "I1847: a rotation of a row that is no grant is no edge"
        );
        let rows = vec![
            row(1, attestation_type::DELEGATES_TO, "u", None, Some("root")),
            row(2, attestation_type::SUPERSEDES, "u", Some(1), Some("root")),
        ];
        let a = edge_leg(&rows, "u", "root");
        assert!(a.value, "I1847: the rotation stands");
        assert_eq!(
            a.rows,
            vec![RowId([2; 32])],
            "I1847: only the rotation is live"
        );
    }
}
