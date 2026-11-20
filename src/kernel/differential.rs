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
//! | [`Class::ForkAsTip`] | CC 2.7.8 "Two versions of one head wait as tips" | `held_head_verdict` (switched in kernel pass 2: persist's side is its former refusal, the reference) |
//! | [`Class::KeyEndHalfOpen`] | CC 2.6.2's freshness row: "the attestation has not yet reached its `valid_until`" | `HeldKeys::liveness` (kernel pass 2) |
//! | [`Class::KeyRecordOwnVoice`] | CC 2.4.1.1: "Each key's own holder signs its record of this form" | `HeldKeys::liveness` (K1, triage round 3) |
//!
//! v62.0.0 (kernel pass 2): `CycleVisitedOnce` (the delegation cycle gate,
//! CC 4.4.3.34) is no longer a class: the gate is deleted, so there is no
//! persist answer left to disagree with the kernel's walk.
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
    /// v62.0.0 (kernel pass 2, K1) — at exactly a record's `valid_until`
    /// the record has ended (the kernel's `[from, until)`); persist's
    /// former reading covered it.
    KeyEndHalfOpen,
    /// v62.0.0 (K1, triage round 3) — a key record no voice of its own key
    /// signed makes the key live nowhere (CC 2.4.1.1: "Each key's own holder
    /// signs its record of this form, so the genesis ends no key and gives no
    /// key a power over another"; the kernel's `key_end::well_formed`);
    /// persist's former reading counted any verified voice.
    KeyRecordOwnVoice,
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
            Class::KeyEndHalfOpen => "key_end_half_open",
            Class::KeyRecordOwnVoice => "key_record_own_voice",
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
    use super::consensus::{admits, admits_by_rows, NoCell};
    let kernel = admits(b);
    // I1844 — the count over the resolved head is the kernel's seat rule
    // walked over the ballot's row graph, on every call
    let by_rows = admits_by_rows(b);
    assert_eq!(
        kernel.as_ref().map(|a| a.value),
        by_rows.as_ref().map(|a| a.value),
        "I1844: the adapter's count and the kernel's seat rule over the ballot's rows disagree \
         for {:?} ({:?}, subject {:?}, {} signers, {} seats)",
        b.protocol,
        b.direction,
        b.subject,
        b.signers.len(),
        b.roster.len()
    );
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
    // the kernel HOLDS a version that extends the head and one that names
    // another (a tip, or a row waiting for the head it names); it holds
    // nothing in place of an unheld group
    let kernel_ok = reading != HeadReading::NothingHeld;
    let class = if !proof_ok || birth {
        // a proof naming another prior is a contradiction inside one row,
        // refused for its shape before the kernel; an accord birth over a
        // squat is a NEW lineage's first version the trust-root door stores
        // in place of the held row — neither is a version of this head
        Class::Agree
    } else if persist_ok == kernel_ok {
        Class::Agree
    } else if !persist_ok && reading == HeadReading::Tip {
        // CC 2.7.8: "Two versions of one head wait as tips"
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

/// v62.0.0 (kernel pass 2, K1) — `HeldKeys::liveness`: persist's former
/// coverage reading (inclusive of `valid_until`) against the kernel's
/// key-end conclusion, after the revocations (which are persist's, and
/// read before either). `at_an_end`: some valid record states exactly `at`
/// as its `valid_until`.
///
/// v62.0.0 (K1, triage round 3) — `at_an_end_or_unvoiced`: every such record
/// ends exactly at `at`, or carries no voice of the key it records.
pub fn key_end(
    key: &str,
    at: u64,
    persist_covers: bool,
    kernel_live: bool,
    at_an_end: bool,
    at_an_end_or_unvoiced: bool,
) {
    let class = if persist_covers == kernel_live {
        Class::Agree
    } else if persist_covers && !kernel_live && at_an_end {
        Class::KeyEndHalfOpen
    } else if persist_covers && !kernel_live && at_an_end_or_unvoiced {
        Class::KeyRecordOwnVoice
    } else {
        Class::Unexplained
    };
    let at_s = at.to_string();
    record(
        "HeldKeys::liveness",
        class,
        &key_of(&[key, &at_s]),
        &persist_covers.to_string(),
        &kernel_live.to_string(),
    );
}
