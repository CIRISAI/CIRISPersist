//! The test-fixture codec switch (slice E2a, the coordinator's Q1 ruling).
//!
//! The existing fixture builders emit earlier-form JSON rows, and this slice
//! does not flip the suite. This module is the switch the JSON cut flips:
//! a builder asks [`emit_edition2`] and, when set, signs an edition-2
//! statement and maps it through `edition2::ingest::attestation_of`. A
//! witness runs a body under [`with_edition2`].
//!
//! [`FLIP`] lists every builder entry point that flips: each `test_support`
//! function returning a typed row (`Attestation`, `SignedAttestation`,
//! `KeyRecord`, `SignedKeyRecord`, `SignedFamily`, `SignedCommunity`).
//! There are 37 of them. I1912 re-derives the list from disk,
//! so a new builder that is not listed is red, and the cut stays mechanical.

use std::cell::Cell;

thread_local! {
    static EDITION2: Cell<bool> = const { Cell::new(false) };
}

/// Should a fixture builder emit an edition-2 statement on this thread?
#[must_use]
pub fn emit_edition2() -> bool {
    EDITION2.with(Cell::get)
}

/// Run `f` with the fixture builders emitting edition 2 on this thread.
pub fn with_edition2<R>(f: impl FnOnce() -> R) -> R {
    let before = EDITION2.with(|c| c.replace(true));
    let out = f();
    EDITION2.with(|c| c.set(before));
    out
}

/// The builder entry points the JSON cut flips, as `file::function`.
pub const FLIP: &[&str] = &[
    "src/federation/bootstrap_admission.rs::consent_scope_row",
    "src/federation/bootstrap_admission.rs::consent_scope_row_superseding",
    "src/federation/bootstrap_admission.rs::consent_withdraws_row",
    "src/federation/bootstrap_admission.rs::scores_row",
    "src/federation/bootstrap_admission.rs::typed_family_row",
    "src/federation/consent_peer_set.rs::grant",
    "src/federation/membership_acceptance.rs::acceptance_row",
    "src/federation/membership_acceptance.rs::proposal_row",
    "src/federation/operational.rs::accord_conferred",
    "src/federation/operational.rs::co_signed_trust_attestation",
    "src/federation/operational.rs::signed_canonical_record",
    "src/federation/operational.rs::signed_canonical_record_with_roles",
    "src/federation/operational.rs::signed_trust_attestation",
    "src/federation/operational.rs::steward_key_record",
    "src/federation/register.rs::authority_signed_record",
    "src/federation/register.rs::self_scrubbed_record_signed_at",
    "src/federation/reverse_quorum.rs::signed_row",
    "src/federation/tier_ingest.rs::bare_attestation",
    "src/federation/tier_ingest.rs::community_naming_held",
    "src/federation/tier_ingest.rs::expired_key_record",
    "src/federation/tier_ingest.rs::family_naming_held",
    "src/federation/tier_ingest.rs::moderate_delegation_attestation",
    "src/federation/tier_ingest.rs::occurrence_withdrawal",
    "src/federation/tier_ingest.rs::owner_binding_attestation",
    "src/federation/tier_ingest.rs::replicated_key_record",
    "src/federation/tier_ingest.rs::replicated_key_record_with_expiry",
    "src/federation/tier_ingest.rs::seal_row",
    "src/federation/tier_ingest.rs::sign_community",
    "src/federation/tier_ingest.rs::sign_community_membership_revocation",
    "src/federation/tier_ingest.rs::sign_community_membership_widening",
    "src/federation/tier_ingest.rs::sign_family",
    "src/federation/tier_ingest.rs::sign_family_membership_revocation",
    "src/federation/tier_ingest.rs::sign_family_membership_widening",
    "src/federation/tier_ingest.rs::sign_family_revocation_by_consensus",
    "src/federation/tier_ingest.rs::sign_family_widening_by_consensus",
    "src/federation/tier_ingest.rs::sign_revocation_by_consensus",
    "src/federation/tier_ingest.rs::sign_widening_by_consensus",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The typed-row builders of every `mod test_support` under `src/`,
    /// re-derived from disk.
    fn builders_on_disk() -> Vec<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut out = Vec::new();
        let mut stack = vec![root.join("src")];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                let s = std::fs::read_to_string(&p).unwrap();
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                let mut from = 0;
                while let Some(i) = s[from..].find("mod test_support") {
                    let start = from + i;
                    let after = s[start + "mod test_support".len()..].trim_start();
                    if !after.starts_with('{') {
                        from = start + 1;
                        continue;
                    }
                    let Some(open) = s[start..].find('{') else {
                        break;
                    };
                    let (mut depth, mut j) = (1usize, start + open + 1);
                    let bytes = s.as_bytes();
                    while depth > 0 && j < bytes.len() {
                        match bytes[j] {
                            b'{' => depth += 1,
                            b'}' => depth -= 1,
                            _ => {}
                        }
                        j += 1;
                    }
                    let body = &s[start + open + 1..j.saturating_sub(1)];
                    for (k, _) in body.match_indices("fn ") {
                        let head = &body[..k];
                        let line_start = head.rfind('\n').map_or(0, |n| n + 1);
                        let prefix = head[line_start..].trim();
                        let public = ["pub", "pub(crate)"]
                            .iter()
                            .any(|v| prefix == *v || prefix.starts_with(&format!("{v} ")));
                        if !public {
                            continue;
                        }
                        let rest = &body[k + 3..];
                        let name: String = rest
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        let sig_end = rest.find(['{', ';']).unwrap_or(rest.len());
                        let sig = &rest[..sig_end];
                        let Some(arrow) = sig.find("->") else {
                            continue;
                        };
                        let ret = &sig[arrow..];
                        let typed = [
                            "SignedAttestation",
                            "SignedKeyRecord",
                            "SignedFamily",
                            "SignedCommunity",
                        ]
                        .iter()
                        .any(|t| ret.contains(t))
                            || ret
                                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                                .any(|w| w == "Attestation" || w == "KeyRecord");
                        if typed {
                            out.push(format!("{rel}::{name}"));
                        }
                    }
                    from = j;
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// **I1912**: the flip list is every typed-row builder on disk.
    #[test]
    fn i1912_the_flip_list_is_complete() {
        let mut listed: Vec<String> = FLIP.iter().map(|s| (*s).to_owned()).collect();
        listed.sort();
        assert_eq!(builders_on_disk(), listed, "I1912: FLIP is stale");
        assert_eq!(FLIP.len(), 37, "I1912: the count");
    }

    #[test]
    fn i1912_the_switch_is_per_thread_and_restores() {
        assert!(!emit_edition2());
        assert!(with_edition2(emit_edition2));
        assert!(!emit_edition2(), "I1912: restored");
    }
}
