//! v62.0.0 (slice C) — **the differential witness** (test builds only): every
//! call of a mapped decision, on every backend and every fixture the lib
//! suite runs, is answered twice — by persist's own function and by the
//! kernel over the same held rows — and every disagreement must be exactly
//! one of the named departures of `ciris-kernel`'s `DIFFERENCES.md`, each
//! backed by a CC sentence. Any other disagreement PANICS in the test that
//! reached it (I1838).
//!
//! | class | CC | function |
//! |---|---|---|
//! | [`Class::ReverseQuorum`] | CC 3.2 "Not a membership rule: reverse quorum … It admits no one" | `consensus::evaluate` |
//! | [`Class::Custom`] | CC 4.4.3.6's protocol table has six arms, no `custom:` | `consensus::evaluate` |
//! | [`Class::WeightedWhole`] | CC 3.3.4 "Each weight and the threshold is a whole number" | `consensus::evaluate` |
//! | [`Class::NodeCosign`] | CC 3.2 *The first binding (MUST)*: counts "only when the node's own key cosigned it" | `owner_of` |
//! | [`Class::ForkAsTip`] | CC 2.7.8 "Two versions of one head wait as tips" | `held_head_verdict` |
//! | [`Class::CycleVisitedOnce`] | CC 4.4.3.34 / KERNEL.md 5: the walk visits a cycle once; nothing is refused for closing one | the delegation cycle gate |
//!
//! **Counting.** With `CIRIS_KERNEL_DIFF_LOG=<file>` set, each call appends
//! one tab-separated line `function  class  key  persist  kernel  test` (the key
//! digests the call's inputs, so a run's DISTINCT calls are the distinct
//! keys). `scripts/kernel_diff_counts.py` folds a run's file into the table
//! `DIFFERENCES.md` reports.

use std::io::Write as _;

/// How a call's two answers relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The same answer.
    Agree,
    /// `reverse_quorum:*` refused as a membership protocol; persist admitted.
    ReverseQuorum,
    /// `custom:*` refused; persist admitted.
    Custom,
    /// A `weighted:` rubric that is not whole numbers refused; persist admitted.
    WeightedWhole,
    /// An owner binding the node's key never cosigned names no owner.
    NodeCosign,
    /// A version that does not name the held head is held as a tip.
    ForkAsTip,
    /// A cycle-closing delegation is not refused.
    CycleVisitedOnce,
    /// None of the above: a disagreement no CC sentence explains.
    Unexplained,
}

impl Class {
    fn as_str(self) -> &'static str {
        match self {
            Class::Agree => "agree",
            Class::ReverseQuorum => "reverse_quorum",
            Class::Custom => "custom",
            Class::WeightedWhole => "weighted_whole",
            Class::NodeCosign => "node_cosign",
            Class::ForkAsTip => "fork_as_tip",
            Class::CycleVisitedOnce => "cycle_visited_once",
            Class::Unexplained => "UNEXPLAINED",
        }
    }
}

/// Record one call; panic on an [`Class::Unexplained`] disagreement.
pub fn record(function: &str, class: Class, key: &str, persist: &str, kernel: &str) {
    if let Ok(path) = std::env::var("CIRIS_KERNEL_DIFF_LOG") {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            // nextest runs one test per process, named on the command line
            let test = std::env::args()
                .skip(1)
                .find(|a| !a.starts_with('-'))
                .unwrap_or_default();
            let line = format!(
                "{function}\t{}\t{key}\t{}\t{}\t{test}\n",
                class.as_str(),
                persist.replace(['\t', '\n'], " "),
                kernel.replace(['\t', '\n'], " ")
            );
            let _ = f.write_all(line.as_bytes());
        }
    }
    assert!(
        class != Class::Unexplained,
        "I1838: {function} — persist and the kernel disagree outside every named departure \
         (key {key}): persist {persist}, kernel {kernel}"
    );
}

/// A short digest of a call's inputs.
pub fn key_of(parts: &[&str]) -> String {
    let id = super::view::RowId::of_label(parts);
    hex::encode(&id.0[..8])
}

/// `consensus::evaluate`: the reference verdict against the kernel's.
pub fn consensus(
    b: &crate::federation::consensus::Ballot<'_>,
    persist: &crate::federation::consensus::Verdict,
) {
    use super::consensus::{admits, NoCell};
    let kernel = admits(b);
    let k_admits = kernel.as_ref().is_ok_and(|a| a.value);
    let p_admits = persist.admits();
    let class = if p_admits == k_admits {
        Class::Agree
    } else {
        match &kernel {
            Err(NoCell::ReverseQuorum) if p_admits => Class::ReverseQuorum,
            Err(NoCell::Custom) if p_admits => Class::Custom,
            Err(NoCell::NotWhole(_)) if p_admits => Class::WeightedWhole,
            _ => Class::Unexplained,
        }
    };
    let signers: Vec<&str> = b.signers.iter().map(String::as_str).collect();
    let roster: Vec<String> = b
        .roster
        .iter()
        .map(|s| {
            format!(
                "{}:{}:{}:{}",
                s.key_id,
                s.role.as_deref().unwrap_or(""),
                s.node_bearing,
                b.persons.seat_person(&s.key_id)
            )
        })
        .collect();
    let blob = b.policy_blob.map(ToString::to_string).unwrap_or_default();
    let dir = format!("{:?}", b.direction);
    let hw = format!("{:?}", b.high_water);
    let mut parts = vec![
        b.protocol,
        b.subkind.unwrap_or(""),
        &blob,
        &dir,
        b.subject.unwrap_or(""),
        &hw,
    ];
    parts.extend(roster.iter().map(String::as_str));
    parts.push("|");
    parts.extend(signers.iter().copied());
    record(
        "consensus::evaluate",
        class,
        &key_of(&parts),
        &format!("{persist:?}"),
        &format!("{:?}", kernel.map(|a| a.value)),
    );
}

/// `owner_of`: persist's owners (selves) against the kernel's holders
/// (selves of the kernel's seated keys).
pub fn owner_of(
    node: &str,
    persist: &std::collections::BTreeSet<String>,
    kernel: &std::collections::BTreeSet<String>,
    persist_without_cosign_rule: &std::collections::BTreeSet<String>,
) {
    let class = if persist == kernel {
        Class::Agree
    } else if kernel.is_subset(persist) && persist == persist_without_cosign_rule {
        // every owner the kernel drops is one whose bindings the node never
        // cosigned: the kernel, given the cosignature, names them
        Class::NodeCosign
    } else {
        Class::Unexplained
    };
    let p: Vec<&str> = persist.iter().map(String::as_str).collect();
    let k: Vec<&str> = kernel.iter().map(String::as_str).collect();
    let mut parts = vec![node, "|"];
    parts.extend(p.iter().copied());
    parts.push("|");
    parts.extend(k.iter().copied());
    record(
        "owner_of",
        class,
        &key_of(&parts),
        &format!("{p:?}"),
        &format!("{k:?}"),
    );
}

/// `trust_root_valid`'s edge leg.
pub fn trust_edge(user: &str, root: &str, persist: bool, kernel: bool, rows: usize) {
    let class = if persist == kernel {
        Class::Agree
    } else {
        Class::Unexplained
    };
    let n = rows.to_string();
    record(
        "trust_root_valid/edge",
        class,
        &key_of(&[user, root, &n, if persist { "1" } else { "0" }]),
        &persist.to_string(),
        &kernel.to_string(),
    );
}

/// The delegation cycle gate: persist refused (`Some(hops)`) or admitted.
pub fn cycle_gate(row: &crate::federation::types::Attestation, persist_refused: Option<usize>) {
    let class = if persist_refused.is_some() {
        Class::CycleVisitedOnce
    } else {
        Class::Agree
    };
    record(
        "check_delegation_cycle_admission",
        class,
        &key_of(&[
            &row.attesting_key_id,
            &row.attested_key_id,
            &row.attestation_id,
        ]),
        &format!("{persist_refused:?}"),
        "admit",
    );
}

/// `held_head_verdict`: persist's verdict against the kernel's head reading.
pub fn held_head(
    group: &str,
    held: Option<&str>,
    offered_prev: &str,
    proof_ok: bool,
    birth: bool,
    persist_ok: bool,
) {
    use super::head::{head_reading, HeadReading};
    let reading = head_reading(group, held, offered_prev, "");
    let kernel_ok = reading == HeadReading::Extends;
    let class = if !proof_ok || birth {
        // a proof naming another prior is a contradiction inside one row,
        // refused for its shape before the kernel; an accord birth over a
        // squat is a NEW lineage's first version the trust-root door stores
        // in place of the held row — neither is a version of this head
        Class::Agree
    } else if persist_ok == kernel_ok {
        Class::Agree
    } else if !persist_ok && reading == HeadReading::Tip {
        Class::ForkAsTip
    } else {
        Class::Unexplained
    };
    record(
        "held_head_verdict",
        class,
        &key_of(&[
            group,
            held.unwrap_or(""),
            offered_prev,
            if proof_ok { "p" } else { "-" },
        ]),
        &persist_ok.to_string(),
        &format!("{reading:?}"),
    );
}
