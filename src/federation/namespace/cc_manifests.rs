//! v60.0.0 (S6v) — **the CC manifests persist vendors beside the namespace
//! registry, pinned at the CIRISConstitution `v1.0-rc9` tag.**
//!
//! [`registry`](super::registry) carries the namespace registry and its match
//! vectors; this module carries the other four CC `manifests/` files persist
//! reads, copied byte for byte with `git show v1.0-rc9:manifests/<file>` at
//! [`VENDORED_CC_COMMIT`](super::registry::VENDORED_CC_COMMIT) (`5d50c6bb`):
//!
//! | file | CC | read by |
//! |---|---|---|
//! | `governance_policy.json` | 4.5.13, the two-path policy table | [`crate::federation::governance_policy`] at runtime ([`GOVERNANCE_POLICY_JSON`]) |
//! | `governance_policy_vectors.json` | 4.5.13, 732 decision vectors | the `two_path` replay (test) |
//! | `csd4_chain.json` | the CSD/4 chain as data | `scripts/csd4_coverage.py` (report) |
//! | `topology_vocabulary.json` | the CSD/4 atom vocabulary | `scripts/csd4_coverage.py`, the chain's own vocabulary pin |
//!
//! Until v60 the four were test fixtures under `tests/fixtures/` (v59 / v60
//! S0), copied from the untagged `rc9` branch; their bytes are the tag's. Only
//! the policy table is compiled in: the other three have no runtime reader,
//! so they live here as data with their pins and are read from disk by the
//! report script and the witnesses.
//!
//! JSON carries no comments, so this doc is the four files' header. Do not
//! hand-edit them: re-copy from the tag CC names, move each pin below and
//! [`VENDORED_CC_COMMIT`](super::registry::VENDORED_CC_COMMIT) in the same
//! commit, and run `scripts/check_vendored_cc.sh <tag>`.
//!
//! The six `formal/self_roster` traces the two-path replay runs stay test
//! fixtures (`tests/fixtures/self_roster/`): they are model output, not
//! manifests. Their pins are [`SELF_ROSTER_TRACE_FILE_SHA256`], at the same tag.

/// The CC governance policy table (CC 4.5.13), compiled in: the two-path
/// doors read their policy from it ([`crate::federation::governance_policy`]).
pub(crate) const GOVERNANCE_POLICY_JSON: &str = include_str!("governance_policy.json");

/// SHA-256 of the vendored `governance_policy.json` FILE bytes.
pub const VENDORED_GOVERNANCE_POLICY_FILE_SHA256: &str =
    "12df61a92b398fac99f4cfc64f34548c43cca60944b9f90addd845f90c9f33f8";

/// The table's own `_meta.policy_sha256` (CC's hash over the rows; the
/// vectors carry the same value, so a vector set is tied to its table).
pub const VENDORED_GOVERNANCE_POLICY_SHA256: &str =
    "b7d2370da9d9a91193f5a5b904fdec3c0a629c3873429f3e1a0439a5e0502264";

/// SHA-256 of the vendored `governance_policy_vectors.json` FILE bytes.
pub const VENDORED_GOVERNANCE_POLICY_VECTORS_FILE_SHA256: &str =
    "e010d44719a9de5116c9f7cd9dd1972827bf7b51ce6acd175f55fa869fb60faa";

/// SHA-256 of the vendored `csd4_chain.json` FILE bytes.
pub const VENDORED_CSD4_CHAIN_FILE_SHA256: &str =
    "b759e4886432bc73bc3b94a41c43f168c911cf7fd85af4b201bf40b87b99a08f";

/// SHA-256 of the vendored `topology_vocabulary.json` FILE bytes. The chain's
/// `_meta.pins.vocabulary_sha256` and CIRISServer's catalogue pin
/// (`tests/fixtures/csd4/topology_vocabulary.pin`) name the same value.
pub const VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256: &str =
    "b0b220507d08424a8ced6f5390fc2a01a9987123530b0cf620be2d34bfc69afc";

/// The four files, `(file under src/federation/namespace/, pinned sha256)`,
/// in the order `scripts/check_vendored_cc.sh` compares them.
pub const VENDORED_CC_MANIFEST_FILES: &[(&str, &str)] = &[
    (
        "governance_policy.json",
        VENDORED_GOVERNANCE_POLICY_FILE_SHA256,
    ),
    (
        "governance_policy_vectors.json",
        VENDORED_GOVERNANCE_POLICY_VECTORS_FILE_SHA256,
    ),
    ("csd4_chain.json", VENDORED_CSD4_CHAIN_FILE_SHA256),
    (
        "topology_vocabulary.json",
        VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256,
    ),
];

/// The six CC `formal/self_roster/traces/*.json` files the two-path replay
/// runs (`tests/fixtures/self_roster/`), `(file, sha256)`, at the tag.
pub const SELF_ROSTER_TRACE_FILE_SHA256: &[(&str, &str)] = &[
    (
        "combined1_stolen.json",
        "4c01328021fbca54bf14fe67d02d48ee33bb8c6756df83463fa06054113e28d4",
    ),
    (
        "combined2_stolen.json",
        "edb2181bdc36dcbddd59436c9815566cedef29e607e0ea621db97f4e44a788ec",
    ),
    (
        "combined3_lost.json",
        "94bf12cf48a5266d6b123cc5b946954e5a30d94fb58e5f8c73019c24442c81d9",
    ),
    (
        "combined3_stolen.json",
        "db9563a3d3641ff3cb2b570f6bde4d99a65cc341d5c0bbbff5341a135273d66b",
    ),
    (
        "combined4_mixed.json",
        "0ea2719bb096c1f55943b7d5b11f29dfe6791a16886819c9afdbb5fae0024b91",
    ),
    (
        "unilateral3_stolen.json",
        "7220d91e1592d5b5e077160a61e34bf9a2b782a2289c7e378646f59f4d87f89d",
    ),
];

#[cfg(test)]
mod tests {
    //! **I1300–I1302, I1308** — every vendored CC byte is the pinned byte,
    //! the pin is the tag's, and the refusal tokens at the pin.
    use super::super::registry::{
        VENDORED_CC_COMMIT, VENDORED_CC_VERSION, VENDORED_REGISTRY_FILE_SHA256,
        VENDORED_VECTORS_FILE_SHA256,
    };
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    fn hex_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn namespace_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/federation/namespace")
    }

    fn trace_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/self_roster")
    }

    /// Every pinned file, `(path in CC at the tag, local path, pin)`.
    fn every_pinned_file() -> Vec<(String, PathBuf, &'static str)> {
        let ns = namespace_dir();
        let mut all = vec![
            (
                "manifests/namespace_registry.json".to_owned(),
                ns.join("namespace_registry.json"),
                VENDORED_REGISTRY_FILE_SHA256,
            ),
            (
                "manifests/namespace_match_vectors.json".to_owned(),
                ns.join("namespace_match_vectors.json"),
                VENDORED_VECTORS_FILE_SHA256,
            ),
        ];
        for (f, pin) in VENDORED_CC_MANIFEST_FILES {
            all.push((format!("manifests/{f}"), ns.join(f), *pin));
        }
        for (f, pin) in SELF_ROSTER_TRACE_FILE_SHA256 {
            all.push((
                format!("formal/self_roster/traces/{f}"),
                trace_dir().join(f),
                *pin,
            ));
        }
        all
    }

    /// **I1300** — the vendored bytes are the pinned bytes: every CC file
    /// persist vendors (the registry, its vectors, the four manifests here and
    /// the six self-roster traces) hashes to its constant, and the compiled-in
    /// policy table is the file on disk.
    #[test]
    fn i1300_every_vendored_cc_file_hashes_to_its_pin() {
        let all = every_pinned_file();
        assert_eq!(
            all.len(),
            12,
            "two registry files, four manifests, six traces"
        );
        for (_, local, pin) in &all {
            let bytes = std::fs::read(local).unwrap_or_else(|e| panic!("{local:?}: {e}"));
            assert_eq!(
                hex_sha256(&bytes),
                *pin,
                "{local:?} moved without its pin (re-vendor from the tag and move the pin together)"
            );
        }
        assert_eq!(
            hex_sha256(GOVERNANCE_POLICY_JSON.as_bytes()),
            VENDORED_GOVERNANCE_POLICY_FILE_SHA256,
            "the compiled-in policy table is the pinned file"
        );
        // Each in-file pin agrees with the pinned files.
        let table: serde_json::Value = serde_json::from_str(GOVERNANCE_POLICY_JSON).expect("table");
        let vectors: serde_json::Value = serde_json::from_slice(
            &std::fs::read(namespace_dir().join("governance_policy_vectors.json")).unwrap(),
        )
        .expect("vectors");
        assert_eq!(
            table["_meta"]["policy_sha256"],
            VENDORED_GOVERNANCE_POLICY_SHA256
        );
        assert_eq!(
            vectors["_meta"]["policy_sha256"], VENDORED_GOVERNANCE_POLICY_SHA256,
            "the vectors are the table's"
        );
        let chain: serde_json::Value = serde_json::from_slice(
            &std::fs::read(namespace_dir().join("csd4_chain.json")).unwrap(),
        )
        .expect("chain");
        assert_eq!(
            chain["_meta"]["pins"]["vocabulary_sha256"], VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256,
            "the chain pins the vendored vocabulary"
        );
    }

    /// **I1301** — CIRISServer's catalogue pin (a CIRISClient byte copy that
    /// stays a test fixture) names the vocabulary persist vendors from CC.
    #[test]
    fn i1301_the_catalogue_pin_names_the_vendored_vocabulary() {
        let pin = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/csd4/topology_vocabulary.pin"),
        )
        .expect("catalogue pin");
        let named = pin
            .lines()
            .find_map(|l| l.strip_prefix("sha256="))
            .expect("a sha256= line");
        assert_eq!(named.trim(), VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256);
    }

    /// **I1308** — the refusal tokens at the pin. CC rc9's chain
    /// (`refusal_tokens`, the tokens its text names) names
    /// `federation_set_semantics_unsorted`, `federation_malformed_row` and the
    /// reasons `aggregate_source_duplicate`, `envelope_member_missing`,
    /// `typed_diverges_from_envelope` and `envelope_member_null`; persist emits
    /// each spelling but `envelope_member_null` (CC 2.6.1.1.1 finding F4,
    /// CIRISPersist#1098, which docs/V60_TASK_PLAN.md §2 keeps out of v60).
    /// Two reasons persist emits are named by NO CC text at the pin
    /// (`key_id_fingerprint_mismatch`, CIRISPersist#1103;
    /// `carrier_without_roster_quorum`, CIRISPersist#1104). Both lists are
    /// latches: a re-vendor that names one, or a persist cut that emits
    /// `envelope_member_null`, reds this test until the line moves.
    #[test]
    fn i1308_the_refusal_tokens_at_the_pin() {
        use crate::federation::malformed_row;
        let chain: serde_json::Value = serde_json::from_slice(
            &std::fs::read(namespace_dir().join("csd4_chain.json")).unwrap(),
        )
        .unwrap();
        let named = chain["refusal_tokens"].as_object().expect("refusal_tokens");
        assert!(named.len() > 50, "the chain's token list collapsed");
        let unsorted = crate::federation::Error::SetSemanticsUnsorted(String::new()).kind();
        let malformed = crate::federation::Error::malformed_row("p", "r", "m").kind();
        for kind in [unsorted, malformed] {
            assert!(named.contains_key(kind), "rc9 names {kind}");
        }
        for reason in [
            malformed_row::AGGREGATE_SOURCE_DUPLICATE,
            malformed_row::ENVELOPE_MEMBER_MISSING,
            malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        ] {
            assert!(named.contains_key(reason), "rc9 names {reason}");
            assert!(malformed_row::ALL.contains(&reason));
        }
        // Named at rc9, not emitted (#1098 F4; out of v60).
        assert!(named.contains_key("envelope_member_null"));
        assert!(!malformed_row::ALL.contains(&"envelope_member_null"));
        // Emitted, named by no CC text at the pin.
        for reason in [
            malformed_row::KEY_ID_FINGERPRINT_MISMATCH,
            malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM,
        ] {
            assert!(
                !named.contains_key(reason),
                "CC now names {reason}: move it to the named list above"
            );
        }
    }

    /// The CIRISConstitution checkout the tag witness reads: `$CIRIS_CC_REPO`,
    /// else a sibling `CIRISConstitution` beside this checkout.
    fn cc_repo() -> Option<PathBuf> {
        let candidate = std::env::var_os("CIRIS_CC_REPO")
            .map(PathBuf::from)
            .or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .map(|p| p.join("CIRISConstitution"))
            })?;
        candidate.join(".git").exists().then_some(candidate)
    }

    fn git(repo: &Path, args: &[&str]) -> Option<Vec<u8>> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .ok()?;
        out.status.success().then_some(out.stdout)
    }

    /// **I1302** — the pins are the tag's bytes: when a CIRISConstitution
    /// checkout carrying `v<VENDORED_CC_VERSION>` is present, the tag names
    /// [`VENDORED_CC_COMMIT`] and every pinned file equals `git show
    /// <tag>:<path>` byte for byte. Without the checkout (or the tag) it skips,
    /// saying so: CI has no CC checkout, and `scripts/check_vendored_cc.sh`
    /// is the networked ship gate for the same property.
    #[test]
    fn i1302_the_pins_are_the_tags_bytes_when_cc_is_present() {
        let tag = format!("v{VENDORED_CC_VERSION}");
        let Some(repo) = cc_repo() else {
            eprintln!(
                "I1302: no CIRISConstitution checkout (CIRIS_CC_REPO or a sibling) — SKIPPED"
            );
            return;
        };
        let Some(commit) = git(&repo, &["rev-parse", &format!("{tag}^{{commit}}")]) else {
            eprintln!("I1302: {repo:?} carries no tag {tag} — SKIPPED (fetch the tags to run it)");
            return;
        };
        assert_eq!(
            String::from_utf8_lossy(&commit).trim(),
            VENDORED_CC_COMMIT,
            "{tag} is not the commit VENDORED_CC_COMMIT names"
        );
        for (cc_path, local, pin) in every_pinned_file() {
            let upstream = git(&repo, &["show", &format!("{tag}:{cc_path}")])
                .unwrap_or_else(|| panic!("{tag} carries no {cc_path}"));
            assert_eq!(
                hex_sha256(&upstream),
                pin,
                "{cc_path} at {tag} is not the pinned byte string"
            );
            assert_eq!(
                upstream,
                std::fs::read(&local).unwrap(),
                "{local:?} is not {tag}:{cc_path}"
            );
        }
        eprintln!("I1302: 12 files equal {tag} ({VENDORED_CC_COMMIT}): RAN");
    }
}
