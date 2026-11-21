//! **The CC manifests persist vendors beside the namespace registry, pinned
//! at the CIRISConstitution tag `v1.0-rc22-pre2` (commit `bab36531`;
//! [`VENDORED_CC_TAG`](super::registry::VENDORED_CC_TAG)).**
//!
//! v62.0.0 (4r): re-copied at rc22 commit `8c436b8b` (then untagged). Of these
//! five only `csd4_chain.json` moved from rc21 (108 refusal tokens: the six
//! `fedcode_*` and `code_node_key_mismatch` added); the rest and the six
//! traces are byte-identical. `WIRE_VOCABULARY.md` moved in its header line
//! only (`1.0-rc21` → `1.0-rc22`), so its file pin moves and
//! [`crate::wire_vocabulary::WIRE_VOCABULARY_HASH`] does not. v62.0.0
//! (CC-tag): the tag's commit `0774639b` carries every one of these files
//! byte-identical to `8c436b8b`. v62.0.0 (PIN-fix1): at `v1.0-rc22-pre2`
//! (`bab36531`) only `csd4_chain.json` moves, in `_meta.pins.claims_sha256`
//! (the claims table carries the SCITT charter rename). The rc21 history
//! follows.
//!
//! [`registry`](super::registry) carries the namespace registry and its match
//! vectors; this module carries the other five CC `manifests/` files persist
//! reads, copied byte for byte with `git show v1.0-rc21:manifests/<file>` at
//! [`VENDORED_CC_COMMIT`](super::registry::VENDORED_CC_COMMIT) (`b016df47`; v62.0.0 CC-pin,
//! from the rc21 wire cut `e6fd7c60`, which came from rc20 `d4bd2a6b`, which
//! came from rc18 `646df978`). At the release tag three of these five moved:
//! `governance_policy.json` and its vectors (the `moderator_election` FLOOR
//! became "2 voices, or the roster's size if smaller", `floor_rule.kind`
//! `voices_or_roster`; a `ranked` row persist reads as not two-path) and
//! `csd4_chain.json` (614 claims, 101 text tokens, the CIRISServer v0.5.245
//! catalogue). `WIRE_VOCABULARY.md` did not move:
//!
//! | file | CC | read by |
//! |---|---|---|
//! | `governance_policy.json` | 4.5.13, the two-path policy table | [`crate::federation::governance_policy`] at runtime ([`GOVERNANCE_POLICY_JSON`]) |
//! | `governance_policy_vectors.json` | 4.5.13, 819 decision vectors (rc20) | the `two_path` replay (test) |
//! | `csd4_chain.json` | the CSD/4 chain as data | `scripts/csd4_coverage.py` (report) |
//! | `topology_vocabulary.json` | the CSD/4 atom vocabulary | `scripts/csd4_coverage.py`, the chain's own vocabulary pin |
//! | `signed_object_vectors.json` | 2.6.1.8 at rc20 (2.6.1.7 at rc18; the earlier form's register row is 8.11.9), the 13 signed-object vectors | the signed-object replay (test) |
//!
//! Only the policy table is compiled in: the other four have no runtime
//! reader, so they live here as data with their pins and are read from disk
//! by the report script and the witnesses.
//!
//! JSON carries no comments, so this doc is the five files' header. Do not
//! hand-edit them: re-copy from the commit (or tag) CC names, move each pin
//! below and [`VENDORED_CC_COMMIT`](super::registry::VENDORED_CC_COMMIT) in
//! the same commit, and run `scripts/check_vendored_cc.sh`.
//!
//! The six `formal/self_roster` traces the two-path replay runs stay test
//! fixtures (`tests/fixtures/self_roster/`): they are model output, not
//! manifests. Their pins are [`SELF_ROSTER_TRACE_FILE_SHA256`], at the same tag.

/// The CC governance policy table (CC 4.5.13), compiled in: the two-path
/// doors read their policy from it ([`crate::federation::governance_policy`]).
pub(crate) const GOVERNANCE_POLICY_JSON: &str = include_str!("governance_policy.json");

/// SHA-256 of the vendored `governance_policy.json` FILE bytes.
pub const VENDORED_GOVERNANCE_POLICY_FILE_SHA256: &str =
    "72c1cc376461433e7abf78de9b921f7e43fabf5129a4c1c53c7fc46f2bcd5119";

/// The table's own `_meta.policy_sha256` (CC's hash over the rows; the
/// vectors carry the same value, so a vector set is tied to its table).
pub const VENDORED_GOVERNANCE_POLICY_SHA256: &str =
    "96edc650156b080724037c9ac7b6cf42a8386a577fd935713b02b77bd8554eaf";

/// SHA-256 of the vendored `governance_policy_vectors.json` FILE bytes.
pub const VENDORED_GOVERNANCE_POLICY_VECTORS_FILE_SHA256: &str =
    "0ea7e2313becd3a7456d667738432eaea966028a3a4b5e82594deb018908c801";

/// SHA-256 of the vendored `csd4_chain.json` FILE bytes.
pub const VENDORED_CSD4_CHAIN_FILE_SHA256: &str =
    "a83070c81779945b878650f5460490519c4f627c45de4bed0859d92e53b4f592";

/// SHA-256 of the vendored `topology_vocabulary.json` FILE bytes. The chain's
/// `_meta.pins.vocabulary_sha256` and CIRISServer's catalogue pin
/// (`tests/fixtures/csd4/topology_vocabulary.pin`) name the same value.
pub const VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256: &str =
    "bfe9d48524a103eb0d91a30fd8335fe499831957c0306808d2b5a484b54c3a7a";

/// SHA-256 of the vendored `signed_object_vectors.json` FILE bytes (CC 2.6.1.7:
/// the 13 signed-object vectors the replay runs through the attestation door,
/// CIRISPersist#1098).
pub const VENDORED_SIGNED_OBJECT_VECTORS_FILE_SHA256: &str =
    "2e2cc9d937a0417a072a4390326b710acf568246196aecdc91a72df7b367dab0";

/// SHA-256 of CC's `manifests/WIRE_VOCABULARY.md` FILE bytes at the tag.
/// Persist does not vendor the file: it pins the document's hash as
/// [`crate::wire_vocabulary::WIRE_VOCABULARY_HASH`], a cross-repo value
/// (`c6bd6aa4…`, CC 2.6.4 §4) shared with CIRISEdge and CIRISRegistry, which
/// stays where it is. This is the tag's file hash, so a re-vendor sees the
/// document move; I1302 checks it against the CC checkout.
pub const VENDORED_WIRE_VOCABULARY_FILE_SHA256: &str =
    "279b282e5d565d3d4378820770f71179dddbe1c8d397ab8f7fbe0e8f51299e77";

/// The five files, `(file under src/federation/namespace/, pinned sha256)`,
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
    (
        "signed_object_vectors.json",
        VENDORED_SIGNED_OBJECT_VECTORS_FILE_SHA256,
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
        "e0ca6f5dfd3e5d1e63787f77f9c9446569b37823625ce83162d212ce3bef1c0c",
    ),
    (
        "combined3_stolen.json",
        "1ca56beebf06179805406765a5dda807ec37840ae2a718ae6ed63b92dec3d624",
    ),
    (
        "combined4_mixed.json",
        "417f8baadd44a457d88c89f6b8ccd621797d742e2fa172823b242a660eba16a3",
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
        CcTag, VENDORED_CC_COMMIT, VENDORED_CC_TAG, VENDORED_CC_VERSION,
        VENDORED_REGISTRY_FILE_SHA256, VENDORED_VECTORS_FILE_SHA256,
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
    /// persist vendors (the registry, its vectors, the five manifests here and
    /// the six self-roster traces) hashes to its constant, and the compiled-in
    /// policy table is the file on disk.
    #[test]
    fn i1300_every_vendored_cc_file_hashes_to_its_pin() {
        let all = every_pinned_file();
        assert_eq!(
            all.len(),
            13,
            "two registry files, five manifests, six traces"
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

    /// The vocabulary CIRISServer's catalogue pin names while the CSD/4
    /// fixtures stay at the CIRISServer v0.5.234 release: CC's `v1.0-rc12`
    /// `topology_vocabulary.json` (catalogue v5). rc14 and rc15 carry vocabulary v6
    /// ([`VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256`]), and no tagged Server
    /// release carries a catalogue built on it yet.
    const SERVER_CATALOGUE_PREVIOUS_VOCABULARY_SHA256: &str =
        "871c5dfa1c20892db214c1a0bf60a04dfd1e117e7f5b82bc483d0cf3ce376587";

    /// **I1301** — CIRISServer's catalogue pin (the tagged release's
    /// `csd4-topology_vocabulary.pin` asset, a test fixture) names the
    /// PREVIOUS vocabulary, pending a tagged Server release carrying CSD/4 v6.
    ///
    /// A latch, both ways: the pin must name the rc12 vocabulary and must NOT
    /// name the one persist vendors now. When the fixtures are re-pinned from
    /// a Server release built on v6, this test goes red; the fix is to assert
    /// equality with [`VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256`] again and
    /// drop the previous-vocabulary constant.
    #[test]
    fn i1301_the_catalogue_pin_names_the_previous_vocabulary_pending_csd4_v6() {
        let pin = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/csd4/topology_vocabulary.pin"),
        )
        .expect("catalogue pin");
        let named = pin
            .lines()
            .find_map(|l| l.strip_prefix("sha256="))
            .expect("a sha256= line")
            .trim();
        assert_ne!(
            named, VENDORED_TOPOLOGY_VOCABULARY_FILE_SHA256,
            "the CSD/4 fixtures now carry the vendored vocabulary (v6): the latch is spent — \
             assert equality with the vendored vocabulary again"
        );
        assert_eq!(
            named, SERVER_CATALOGUE_PREVIOUS_VOCABULARY_SHA256,
            "pending a tagged Server release carrying CSD/4 v6, the catalogue pin names the \
             previous (rc12) vocabulary"
        );
    }

    /// **I1308** — the refusal tokens at the pin. CC rc15's chain
    /// (`refusal_tokens`, the tokens its text names) names
    /// `federation_set_semantics_unsorted`, `federation_malformed_row` and the
    /// reasons `aggregate_source_duplicate`, `envelope_member_missing`,
    /// `typed_diverges_from_envelope` and `envelope_member_null`; persist emits
    /// each (`envelope_member_null` since CIRISPersist#1098 F4). Two reasons
    /// persist emits are named by NO chain token at the pin
    /// (`key_id_fingerprint_mismatch`, CIRISPersist#1103;
    /// `carrier_without_roster_quorum`, CIRISPersist#1104), nor the three CC
    /// 2.6.1.7 lists in its text but the chain does not carry as tokens
    /// (`content_hash_mismatch`, `envelope_row_member_unknown`,
    /// `subject_key_id_malformed`, CIRISPersist#1114). The second list is a
    /// latch: a re-vendor whose chain names one reds this test until the line
    /// moves.
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
            assert!(named.contains_key(kind), "rc15 names {kind}");
        }
        for reason in [
            malformed_row::AGGREGATE_SOURCE_DUPLICATE,
            malformed_row::ENVELOPE_MEMBER_MISSING,
            malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        ] {
            assert!(named.contains_key(reason), "rc15 names {reason}");
            assert!(malformed_row::ALL.contains(&reason));
        }
        // Named at rc9, emitted since #1098 F4 (rc12).
        assert!(named.contains_key(malformed_row::ENVELOPE_MEMBER_NULL));
        assert!(malformed_row::ALL.contains(&malformed_row::ENVELOPE_MEMBER_NULL));
        // Emitted, named by no chain token at the pin. The last three are in
        // CC 2.6.1.7's text (CIRISPersist#1114) but not in the chain.
        for reason in [
            malformed_row::KEY_ID_FINGERPRINT_MISMATCH,
            malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM,
            malformed_row::CONTENT_HASH_MISMATCH,
            malformed_row::ENVELOPE_ROW_MEMBER_UNKNOWN,
            malformed_row::SUBJECT_KEY_ID_MALFORMED,
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

    /// **I1302** — the pins are the vendored cut's bytes: when a
    /// CIRISConstitution checkout is present, every pinned file equals `git
    /// show <rev>:<path>` byte for byte, where `<rev>` is
    /// [`VENDORED_CC_TAG`]'s tag once recorded (which must name
    /// [`VENDORED_CC_COMMIT`]) and the commit while the tag is pending.
    ///
    /// v62.0.0 (4r) — the pending form is a real check, not a skip: a checkout
    /// that lacks the commit FAILS ("fetch it"), and **I2431** reds the moment
    /// any tag names the commit, so the tag CC cuts is recorded in
    /// [`VENDORED_CC_TAG`] rather than silently ignored. Without a checkout at
    /// all it skips, saying so (CI has none); I2430 is the check that always
    /// runs, and `scripts/check_vendored_cc.sh` + `scripts/release_ship.sh`
    /// fail the release closed while the tag is pending.
    #[test]
    fn i1302_the_pins_are_the_tags_bytes_when_cc_is_present() {
        let Some(repo) = cc_repo() else {
            eprintln!(
                "I1302: no CIRISConstitution checkout (CIRIS_CC_REPO or a sibling) — SKIPPED"
            );
            return;
        };
        let rev = VENDORED_CC_TAG.rev();
        let commit =
            git(&repo, &["rev-parse", &format!("{rev}^{{commit}}")]).unwrap_or_else(|| {
                panic!(
                    "I1302: {repo:?} carries no {rev} ({VENDORED_CC_TAG:?}): fetch it; a \
                     checkout that cannot show the vendored cut fails, it does not skip"
                )
            });
        assert_eq!(
            String::from_utf8_lossy(&commit).trim(),
            VENDORED_CC_COMMIT,
            "{rev} is not the commit VENDORED_CC_COMMIT names"
        );
        // I2431 — the pending latch: a tag CC cut at the commit is recorded.
        if VENDORED_CC_TAG == CcTag::Pending {
            let tags = git(&repo, &["tag", "--points-at", VENDORED_CC_COMMIT])
                .expect("git tag --points-at runs");
            let tags = String::from_utf8_lossy(&tags);
            assert!(
                tags.trim().is_empty(),
                "I2431: CC tag(s) {:?} now name the vendored commit {VENDORED_CC_COMMIT}: \
                 record it (`VENDORED_CC_TAG = CcTag::Recorded(\"<tag>\")`), so the tag \
                 checks and the release read the tag",
                tags.split_whitespace().collect::<Vec<_>>()
            );
        }
        for (cc_path, local, pin) in every_pinned_file() {
            let upstream = git(&repo, &["show", &format!("{rev}:{cc_path}")])
                .unwrap_or_else(|| panic!("{rev} carries no {cc_path}"));
            assert_eq!(
                hex_sha256(&upstream),
                pin,
                "{cc_path} at {rev} is not the pinned byte string"
            );
            assert_eq!(
                upstream,
                std::fs::read(&local).unwrap(),
                "{local:?} is not {rev}:{cc_path}"
            );
        }
        let wire = git(
            &repo,
            &["show", &format!("{rev}:manifests/WIRE_VOCABULARY.md")],
        )
        .unwrap_or_else(|| panic!("{rev} carries no manifests/WIRE_VOCABULARY.md"));
        assert_eq!(
            hex_sha256(&wire),
            VENDORED_WIRE_VOCABULARY_FILE_SHA256,
            "manifests/WIRE_VOCABULARY.md at {rev} is not the pinned byte string"
        );
        eprintln!(
            "I1302: 13 files equal {rev} ({VENDORED_CC_COMMIT}, {VENDORED_CC_TAG:?}), and \
             WIRE_VOCABULARY.md hashes to its pin: RAN"
        );
    }

    /// **I2430** (v62.0.0 4r) — the pending state's own shape, checked with no
    /// CC checkout, so it runs in CI: the vendored cut is named by a full
    /// lowercase commit id, the registry's `_meta.cc_version` is
    /// [`VENDORED_CC_VERSION`], and a recorded tag is a non-empty spelling.
    /// The release half (`scripts/release_ship.sh` exit 17 while pending) is
    /// the script's, witnessed by its self-test.
    #[test]
    fn i2430_the_cc_pin_is_a_full_commit_and_the_tag_state_is_well_formed() {
        assert_eq!(VENDORED_CC_COMMIT.len(), 40, "a full commit id");
        assert!(
            VENDORED_CC_COMMIT
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "VENDORED_CC_COMMIT is lowercase hex"
        );
        let registry: serde_json::Value = serde_json::from_slice(
            &std::fs::read(namespace_dir().join("namespace_registry.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(registry["_meta"]["cc_version"], VENDORED_CC_VERSION);
        match VENDORED_CC_TAG {
            CcTag::Pending => assert_eq!(VENDORED_CC_TAG.rev(), VENDORED_CC_COMMIT),
            CcTag::Recorded(tag) => {
                assert!(!tag.trim().is_empty(), "a recorded tag has a spelling");
                assert_eq!(VENDORED_CC_TAG.rev(), tag);
            }
        }
        // The two scripts read the const's line by its text; hold its shape.
        let text = std::fs::read_to_string(namespace_dir().join("registry.rs")).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with("pub const VENDORED_CC_TAG: CcTag = "))
            .expect("VENDORED_CC_TAG is one line the scripts can read");
        assert!(
            line == "pub const VENDORED_CC_TAG: CcTag = CcTag::Pending;"
                || (line.starts_with("pub const VENDORED_CC_TAG: CcTag = CcTag::Recorded(\"")
                    && line.ends_with("\");")),
            "the scripts cannot read {line:?}"
        );
    }
}
