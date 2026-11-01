//! v61 S1 (step 5) — **I1499: the CC v1.0-rc14 text persist does not
//! build in this slice**, each named with its ticket.
//!
//! The rc14 re-vendor (`b4da527`, which contains rc13) brings text whose
//! doors are later work: v61 S2/S3, or v62. Persist vendors the bytes and
//! builds none of it here. A divergence that only lives in prose rots, so
//! every one is a row of [`NOT_BUILT`], and I1499 holds it as a latch both
//! ways:
//!
//! - **CC side.** Each row's anchor is a phrase of CC's
//!   `constitution/part_3_the_namespace.md` at the tag. When a
//!   CIRISConstitution checkout is present, the tag's file must hash to
//!   [`VENDORED_SOURCE_SHA256`] and carry every anchor. Without the checkout
//!   it skips, saying so, like I1302.
//! - **Persist side.** A row that names a CC claim id: `evidence/cc_impl.tsv`
//!   carries no row for it. The cut that builds the door adds its evidence
//!   row and reds this test until the line leaves the table. A row that names
//!   a refusal token: no non-test persist source spells it yet.
//!
//! The rc12 census families and the ballot tally (CIRISPersist#1121) are also
//! in `admission::tests::RESERVED_AND_NOT_YET_GATED`, which latches their
//! missing emitter gate. The CLM-census-rows row here latches the claim.
//!
//! [`VENDORED_SOURCE_SHA256`]: super::namespace::registry::VENDORED_SOURCE_SHA256

/// What a row's persist-side half checks.
#[derive(Debug, Clone, Copy)]
enum NotYet {
    /// `evidence/cc_impl.tsv` names no row for this CC claim id.
    NoEvidenceRow(&'static str),
    /// No non-test persist source under `src/` spells this token.
    TokenUnspelled(&'static str),
    /// CC text only: no claim id and no token to check. The anchor alone
    /// holds the line.
    TextOnly,
}

/// `(CC section, anchor in part 3 at the tag, ticket, when, persist-side check)`.
const NOT_BUILT: &[(&str, &str, &str, &str, NotYet)] = &[
    (
        "3.2",
        "the owner re-signs the binding at that group's scope",
        "CIRISPersist#1140",
        "v61 S2/S3",
        NotYet::TextOnly,
    ),
    (
        "3.1.3",
        "census_share_pair_incomplete",
        "CIRISPersist#1121",
        "v62",
        NotYet::NoEvidenceRow("CLM-census-rows"),
    ),
    (
        "3.1.5.5",
        "evidence_reference_unresolved",
        "CIRISPersist#1152",
        "v62",
        NotYet::TokenUnspelled("evidence_reference_unresolved"),
    ),
    (
        "3.1.5.5",
        "evidence:{suite}:{kind}:{cell}:{prefix}",
        "CIRISPersist#1152",
        "v62",
        NotYet::NoEvidenceRow("CLM-safety-battery-evidence-family"),
    ),
    (
        "3.1.9.7",
        "A community declares a Goal as it issues a licence",
        "CIRISPersist#1154",
        "v62",
        NotYet::TextOnly,
    ),
];

#[cfg(test)]
mod tests {
    use super::{NotYet, NOT_BUILT};
    use crate::federation::namespace::registry::{VENDORED_CC_VERSION, VENDORED_SOURCE_SHA256};
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    fn root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    /// Strip `#[cfg(test)] mod … { … }` tails and `//` comments, so a token a
    /// test or a doc spells is not read as production code.
    fn production_text(src: &str) -> String {
        let cut = src
            .find("#[cfg(test)]\nmod ")
            .or_else(|| src.find("#[cfg(test)]\npub(crate) mod "))
            .unwrap_or(src.len());
        src[..cut]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{dir:?}: {e}")) {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                rust_sources(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && !p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("_invariants.rs") || n.ends_with("_tests.rs"))
            {
                out.push(p);
            }
        }
    }

    /// **I1499 (persist side)** — nothing in [`NOT_BUILT`] has been built: no
    /// evidence row names its claim, and no production source spells its
    /// token. Red when a cut builds one; move the line out of the table in
    /// that cut.
    #[test]
    fn i1499_the_rc14_text_not_built_here_is_not_built() {
        assert_eq!(VENDORED_CC_VERSION, "1.0-rc14", "the table is rc14's");
        let tsv = std::fs::read_to_string(root().join("evidence/cc_impl.tsv")).expect("cc_impl");
        let claims: Vec<&str> = tsv
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split('\t').nth(1))
            .collect();
        assert!(
            claims.len() > 300,
            "the evidence table collapsed ({} rows)",
            claims.len()
        );
        let mut files = Vec::new();
        rust_sources(&root().join("src"), &mut files);
        assert!(
            files.len() > 100,
            "the source walk found {} files",
            files.len()
        );
        let production: Vec<(PathBuf, String)> = files
            .into_iter()
            .map(|p| {
                let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}"));
                (p, production_text(&s))
            })
            .collect();
        let mut built = Vec::new();
        for (section, _, ticket, when, check) in NOT_BUILT {
            match check {
                NotYet::NoEvidenceRow(claim) => {
                    if claims.contains(claim) {
                        built.push(format!(
                            "{claim} (CC {section}, {ticket}, {when}) has an evidence row"
                        ));
                    }
                }
                NotYet::TokenUnspelled(token) => {
                    for (p, text) in &production {
                        if text.contains(token) {
                            built.push(format!(
                                "{token} (CC {section}, {ticket}, {when}) is spelled in {p:?}"
                            ));
                        }
                    }
                }
                NotYet::TextOnly => {}
            }
        }
        assert!(
            built.is_empty(),
            "I1499: a latched rc14 divergence was built; move its line out of NOT_BUILT: {built:#?}"
        );
    }

    /// The CIRISConstitution checkout: `$CIRIS_CC_REPO`, else a sibling.
    fn cc_repo() -> Option<PathBuf> {
        let candidate = std::env::var_os("CIRIS_CC_REPO")
            .map(PathBuf::from)
            .or_else(|| root().parent().map(|p| p.join("CIRISConstitution")))?;
        candidate.join(".git").exists().then_some(candidate)
    }

    /// **I1499 (CC side)** — every anchor is the tag's text: with a
    /// CIRISConstitution checkout carrying `v<VENDORED_CC_VERSION>`, its part 3
    /// hashes to [`VENDORED_SOURCE_SHA256`] and carries every anchor. Skips,
    /// saying so, without the checkout or the tag.
    #[test]
    fn i1499_every_anchor_is_the_tags_text_when_cc_is_present() {
        let tag = format!("v{VENDORED_CC_VERSION}");
        let Some(repo) = cc_repo() else {
            eprintln!(
                "I1499: no CIRISConstitution checkout (CIRIS_CC_REPO or a sibling) — SKIPPED"
            );
            return;
        };
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args([
                "show",
                &format!("{tag}:constitution/part_3_the_namespace.md"),
            ])
            .output()
            .expect("git runs");
        if !out.status.success() {
            eprintln!("I1499: {repo:?} carries no {tag} part 3 — SKIPPED (fetch the tags)");
            return;
        }
        assert_eq!(
            hex::encode(Sha256::digest(&out.stdout)),
            VENDORED_SOURCE_SHA256,
            "part 3 at {tag} is not the source the registry was generated from"
        );
        let text = String::from_utf8(out.stdout).expect("utf-8");
        for (section, anchor, ticket, _, _) in NOT_BUILT {
            assert!(
                text.contains(anchor),
                "I1499: CC {section} at {tag} no longer says {anchor:?} ({ticket}): the \
                 divergence moved; re-read the text and the line"
            );
        }
        eprintln!("I1499: {} anchors in {tag} part 3: RAN", NOT_BUILT.len());
    }
}
