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
            let target = crate::federation::precedence::references_attestation_id_from_envelope(
                &r.attestation_envelope,
            )
            .map(|t| {
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

/// **The kernel's edge leg**: the live acceptance edges, and whether the
/// user's one-hop walk reaches the root over them.
#[must_use]
pub fn edge_leg(rows: &[KRow], user: &str, root: &str) -> Answer<bool> {
    let kind = |r: &KRow| r.seat.policy.clone().unwrap_or_default();
    let c = layers::conclude(
        rows.iter(),
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
        .filter(|&i| rank(&kind(c.g.row(i))) > 0)
        .collect();
    let winners = fold_default(
        &c,
        &composers,
        |r: &KRow| r.seat.target,
        |r: &KRow| rank(&kind(r)),
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
