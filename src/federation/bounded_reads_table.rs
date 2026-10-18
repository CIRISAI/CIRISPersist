//! v56.0.0 (CIRISPersist#1001) — **I914–I915: what bounds every production
//! list read, and that the retired wide reads have no production caller.**
//!
//! - **I914** [`LIST_READ_BOUNDS`] classifies every production `list_*` method
//!   on [`FederationDirectory`](super::FederationDirectory): it takes a
//!   limit/cursor ([`Bound::Paged`]), it is bounded by the schema
//!   ([`Bound::Schema`], with the reason), or it is NOT bounded today
//!   ([`Bound::Open`], with what it grows with). The gate parses the trait
//!   from disk (comments stripped, test-only and `test-anchor` items
//!   skipped) and holds its `list_*` set equal to the table in both
//!   directions; a `Paged` entry's signature must carry a `limit` or a
//!   cursor parameter, and no other entry's may. A new `list_*` method fails
//!   until someone classifies it here.
//! - **I915** no production source calls the demoted wide reads
//!   (`list_attestations_by` / `list_attestations_for`, one key, every row;
//!   `#[cfg(any(test, feature = "test-anchor"))]` since v56.0.0, deleted in
//!   v57). Production is everything under `src/` except comments, string
//!   literals, items gated `#[cfg(test)]` / `#[cfg(all(test, …))]` /
//!   `#[test]` / `#[tokio::test]` / any `test-anchor` cfg, modules declared
//!   under those, and the test files (`*_invariants.rs`,
//!   `directory_double.rs`, `load_bearing.rs`). The scanner's own witness
//!   runs it over crafted text first, so a stripper that cut too much is red
//!   rather than vacuously green. The compiler is the first witness (the
//!   methods do not exist in a build without `test-anchor`); this is the
//!   second, for code compiled with the feature on.

/// What bounds one `list_*` read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    /// The read takes a page size (and resumes on a cursor).
    Paged,
    /// The schema bounds the result; the reason says how.
    Schema(&'static str),
    /// Nothing bounds the result today; the text says what it grows with.
    /// Each is a candidate for the `AttestationQuery` treatment.
    Open(&'static str),
}

/// Every production `list_*` method on `FederationDirectory`, classified.
/// Sorted by name.
pub(crate) const LIST_READ_BOUNDS: &[(&str, Bound)] = &[
    (
        "list_accord_participations",
        Bound::Schema("one proposal's participations, deduped by pinned pubkey at write time: at most the accord holder set"),
    ),
    (
        "list_accord_proposals_by_anchor",
        Bound::Open("every proposal ever made over one standing roster digest"),
    ),
    (
        "list_accord_proposals_by_payload",
        Bound::Open("every stored proposal sharing one payload digest; the proposer chooses the payload"),
    ),
    (
        "list_all_transport_destinations",
        Bound::Open("every route of every occurrence: the boot reload, grows with the federation"),
    ),
    (
        "list_announced_peers",
        Bound::Open("every live announced-peer bookmark: grows with the federation"),
    ),
    ("list_attestation_log", Bound::Paged),
    (
        "list_attestations_by_dimension_citing",
        Bound::Schema("one attester's reports under one exact dimension citing one blob"),
    ),
    ("list_attestations_for_migration", Bound::Paged),
    (
        "list_attestations_referencing",
        Bound::Schema("the structural composers (withdraws/recants/supersedes) of ONE attestation id"),
    ),
    (
        "list_attestations_citing_by_dimension",
        Bound::Schema("every holder's claims under one exact dimension about ONE blob: one fold row per holder"),
    ),
    ("list_attestations_since", Bound::Paged),
    (
        "list_canonical_withdrawals",
        Bound::Schema("one tombstone per withdrawn canonical-role key; the canonical roster is a constitutional set"),
    ),
    (
        "list_communities_for_member",
        Bound::Schema("the communities one member belongs to"),
    ),
    (
        "list_communities_for_member_active",
        Bound::Schema("the communities one member is active in now"),
    ),
    (
        "list_community_membership_listings_for",
        Bound::Open("one community's full listing history: grows with membership churn"),
    ),
    (
        "list_community_membership_revocations_for",
        Bound::Open("one community's full revocation history: grows with membership churn"),
    ),
    (
        "list_community_membership_widenings_for",
        Bound::Open("one community's full widening history: grows with membership churn"),
    ),
    (
        "list_composers_referencing_any",
        Bound::Schema("the structural composers of the caller's own id set"),
    ),
    (
        "list_consent_peers",
        Bound::Schema("the V109 projection: one node's LIVE replication peers, revocations folded, deduped"),
    ),
    (
        "list_consent_peers_for",
        Bound::Schema("the V147 projection: LIVE (author, peer) pairs for one machine, deduped"),
    ),
    (
        "list_consent_revocation_promotion_overdue",
        Bound::Open("every unpromoted local-tier revocation past the SLA; promotion drains it, nothing caps it"),
    ),
    (
        "list_consent_revocation_promotion_overdue_readonly",
        Bound::Open("the same set as list_consent_revocation_promotion_overdue, read only"),
    ),
    (
        "list_consent_revocations",
        Bound::Open("every subject-side revocation since an instant (None = all): grows with history"),
    ),
    (
        "list_derived_hex",
        Bound::Schema("the V149 renditions of ONE original blob"),
    ),
    ("list_expired_attestation_ids", Bound::Paged),
    (
        "list_families_for_member",
        Bound::Schema("the families one member belongs to"),
    ),
    (
        "list_families_for_member_active",
        Bound::Schema("the families one member is active in now"),
    ),
    (
        "list_family_membership_revocations_for",
        Bound::Open("one family's full revocation history: grows with membership churn"),
    ),
    (
        "list_family_membership_widenings_for",
        Bound::Open("one family's full widening history: grows with membership churn"),
    ),
    (
        "list_goals",
        Bound::Open("every goal matching a filter with no page size"),
    ),
    (
        "list_group_versions",
        Bound::Open("one group's full version chain: grows with every supersede"),
    ),
    (
        "list_hard_case_events",
        Bound::Open("every hard-case event of a kind since an instant, no page size"),
    ),
    (
        "list_held_fountain_content",
        Bound::Open("every fountain manifest one publisher holds"),
    ),
    (
        "list_holders_sized",
        Bound::Schema("one row per holder of ONE blob (the holding claim folded per holder)"),
    ),
    ("list_hybrid_pending_attestations", Bound::Paged),
    ("list_hybrid_pending_keys", Bound::Paged),
    (
        "list_identity_occurrence_history_by_occurrence",
        Bound::Open("one occurrence key's append-only assertion history (V161): grows with every renewal"),
    ),
    (
        "list_identity_occurrence_revocations_for",
        Bound::Schema("the revocations of one identity's occurrences: at most one per occurrence and effective instant"),
    ),
    (
        "list_identity_occurrences_active",
        Bound::Schema("one identity's active occurrences (its devices)"),
    ),
    (
        "list_identity_occurrences_by_occurrence_key",
        Bound::Schema("the rows bound under one occurrence key: one per identity it is bound under"),
    ),
    (
        "list_identity_occurrences_for",
        Bound::Schema("one identity's stored occurrences: PK (identity_key_id, occurrence_key_id), one per device"),
    ),
    (
        "list_keys_by_identity_type",
        Bound::Open("every key of one identity type: grows with the federation for the common types"),
    ),
    ("list_known_wire_hashes_since", Bound::Paged),
    (
        "list_key_registration_history",
        Bound::Schema("one key's replaced registrations: one per same-key rebind ceremony"),
    ),
    (
        "list_lineage_head_cosigns_for",
        Bound::Open("every cosign held for one lineage, across its heads"),
    ),
    (
        "list_live_consent_grants_by",
        Bound::Schema("one node's LIVE replication grants about itself (rows with a V109 projection row)"),
    ),
    (
        "list_live_consent_grants_for",
        Bound::Schema("the LIVE replication grants FOR one machine (rows with a V147 projection row)"),
    ),
    ("list_local_tier_attestations", Bound::Paged),
    (
        "list_location_proofs_for",
        Bound::Open("one subject's full location-proof history"),
    ),
    (
        "list_org_memberships_for",
        Bound::Open("one org's memberships, every user, full history"),
    ),
    ("list_org_memberships_since", Bound::Paged),
    (
        "list_organizations_for",
        Bound::Open("one org's full record history"),
    ),
    ("list_organizations_since", Bound::Paged),
    (
        "list_partner_records_for",
        Bound::Open("one licence's full partner-record history"),
    ),
    ("list_partner_records_since", Bound::Paged),
    ("list_purge_executions_since", Bound::Paged),
    ("list_scores", Bound::Paged),
    ("list_signed_accord_quorum_evidence_since", Bound::Paged),
    ("list_signed_communities_since", Bound::Paged),
    ("list_signed_community_membership_listings_since", Bound::Paged),
    ("list_signed_community_membership_revocations_since", Bound::Paged),
    ("list_signed_community_membership_widenings_since", Bound::Paged),
    ("list_signed_families_since", Bound::Paged),
    ("list_signed_family_membership_revocations_since", Bound::Paged),
    ("list_signed_family_membership_widenings_since", Bound::Paged),
    (
        "list_signed_identity_occurrence_revocations_for",
        Bound::Schema("the signed twin of list_identity_occurrence_revocations_for"),
    ),
    ("list_signed_identity_occurrence_revocations_since", Bound::Paged),
    (
        "list_signed_identity_occurrences_for",
        Bound::Schema("the signed twin of list_identity_occurrences_for: one per device"),
    ),
    ("list_signed_identity_occurrences_since", Bound::Paged),
    ("list_signed_key_records_since", Bound::Paged),
    ("list_signed_location_proofs_since", Bound::Paged),
    ("list_signed_partner_records_since", Bound::Paged),
    (
        "list_signed_records",
        Bound::Open("every replicated record of one kind for one subject; the history-bearing kinds grow"),
    ),
    ("list_signed_revocations_since", Bound::Paged),
    (
        "list_signed_transport_destinations_for",
        Bound::Schema("the signed twin of list_transport_destinations_for: one row per transport kind"),
    ),
    ("list_signed_transport_destinations_since", Bound::Paged),
    (
        "list_targeted_by_dimension_prefix",
        Bound::Open("one group's rows under a dimension prefix: grows with the group's history"),
    ),
    (
        "list_transport_destinations_by_destination",
        Bound::Schema("the claimants of ONE destination hash (competing claims, one per claimant)"),
    ),
    (
        "list_transport_destinations_for",
        Bound::Schema("one occurrence's LIVE routes: at most one per transport kind (#443)"),
    ),
    (
        "list_trusted_keys",
        Bound::Open("every trusted key matching a filter with no page size"),
    ),
    (
        "list_wholeness_witnesses_for_peer",
        Bound::Schema("one peer's witnesses: the corpus retains the last K"),
    ),
    ("list_widening_candidates", Bound::Paged),
    ("list_wire_hashes_since", Bound::Paged),
    (
        "list_witness_equivocations",
        Bound::Open("every equivocation proof recorded about one peer"),
    ),
    (
        "list_witness_peer_ids",
        Bound::Open("every distinct peer with a witness: grows with the federation"),
    ),
];

#[cfg(test)]
mod gates {
    use super::{Bound, LIST_READ_BOUNDS};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// `src` with comments and string-literal contents blanked (newlines
    /// kept, so line structure survives). Char literals are left alone; a
    /// lifetime's `'` is not a quote.
    pub(super) fn blank_comments_and_strings(src: &str) -> String {
        let b: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            let n = b.get(i + 1).copied();
            if c == '/' && n == Some('/') {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if c == '/' && n == Some('*') {
                let mut depth = 0;
                while i < b.len() {
                    if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                        continue;
                    }
                    if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                        continue;
                    }
                    if b[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
                continue;
            }
            // Raw strings: r"…", r#"…"#, br"…".
            if (c == 'r' || (c == 'b' && n == Some('r')))
                && (i == 0 || !(b[i - 1].is_alphanumeric() || b[i - 1] == '_'))
            {
                let mut j = i + if c == 'b' { 2 } else { 1 };
                let mut hashes = 0;
                while b.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&'"') {
                    out.push('"');
                    j += 1;
                    loop {
                        if j >= b.len() {
                            break;
                        }
                        if b[j] == '"' && (0..hashes).all(|h| b.get(j + 1 + h) == Some(&'#')) {
                            j += 1 + hashes;
                            break;
                        }
                        if b[j] == '\n' {
                            out.push('\n');
                        }
                        j += 1;
                    }
                    out.push('"');
                    i = j;
                    continue;
                }
            }
            // A char literal ('x', '\'', '\u{..}') is copied whole, so its
            // quote never opens a string; a lifetime ('a) is not one.
            if c == '\'' {
                if n == Some('\\') {
                    let mut j = i + 2;
                    while j < b.len() && b[j] != '\'' {
                        j += 1;
                    }
                    if j < b.len() && j <= i + 12 {
                        out.extend(&b[i..=j]);
                        i = j + 1;
                        continue;
                    }
                } else if b.get(i + 2) == Some(&'\'') {
                    out.extend(&b[i..i + 3]);
                    i += 3;
                    continue;
                }
            }
            if c == '"' {
                // An attribute's strings are kept: `feature = "test-anchor"`
                // is what gates the item.
                let line_start = out.rfind('\n').map_or(0, |n| n + 1);
                let keep = out[line_start..].trim_start().starts_with("#[");
                out.push('"');
                i += 1;
                while i < b.len() && b[i] != '"' {
                    if b[i] == '\\' {
                        if keep {
                            out.push('\\');
                            if let Some(&e) = b.get(i + 1) {
                                out.push(e);
                            }
                        }
                        i += 1;
                    } else if b[i] == '\n' {
                        out.push('\n');
                    } else if keep {
                        out.push(b[i]);
                    }
                    i += 1;
                }
                out.push('"');
                i += 1;
                continue;
            }
            out.push(c);
            i += 1;
        }
        out
    }

    /// Whether an attribute line gates its item out of a production build
    /// (test-only), or into a `test-anchor` build only.
    fn is_test_gate(line: &str) -> bool {
        let t: String = line
            .trim_start()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        crate::test_cfg::is_test_only_cfg(line)
            || t.starts_with("#[test]")
            || t.starts_with("#[tokio::test")
            || (t.starts_with("#[cfg(") && t.contains("test-anchor") && !t.contains("not("))
    }

    /// The production text of one (already blanked) file: test-gated items
    /// removed. Returns the text and the names of `mod x;` declarations that
    /// were gated (their files are test-only too).
    pub(super) fn production(blanked: &str) -> (String, Vec<String>) {
        let mut out = Vec::new();
        let mut gated_mods = Vec::new();
        let mut skip_depth: Option<i32> = None;
        let mut depth = 0i32;
        let mut pending = false;
        for line in blanked.lines() {
            let opens = line.matches('{').count() as i32;
            let closes = line.matches('}').count() as i32;
            if skip_depth.is_none() && !pending && is_test_gate(line) {
                pending = true;
                // An attribute and its item on one line.
                let after = line.trim_start();
                let item = after.find(']').map_or("", |e| after[e + 1..].trim());
                if item.is_empty() {
                    continue;
                }
            }
            if pending {
                let t = line.trim();
                if t.starts_with("#[") && opens == 0 {
                    // Further attributes on the same item.
                    continue;
                }
                if opens > 0 {
                    skip_depth = Some(depth);
                    pending = false;
                } else if closes > 0 {
                    // The enclosing block closed first: the gated item was
                    // bodiless; this line is the parent's.
                    pending = false;
                } else if t.ends_with(',') {
                    // A gated field, variant or argument.
                    pending = false;
                    continue;
                } else if t.ends_with(';') {
                    // A bodiless item: `mod x;`, `use …;`, a declaration.
                    let w: Vec<&str> = t.trim_end_matches(';').split_whitespace().collect();
                    if let Some(p) = w.iter().position(|x| *x == "mod") {
                        if let Some(name) = w.get(p + 1) {
                            gated_mods.push((*name).to_owned());
                        }
                    }
                    pending = false;
                    continue;
                } else {
                    continue;
                }
            }
            depth += opens - closes;
            if let Some(d) = skip_depth {
                if depth <= d {
                    skip_depth = None;
                }
                continue;
            }
            out.push(line);
        }
        (out.join("\n"), gated_mods)
    }

    /// The wide-read calls in `text`: `.list_attestations_by(x)` /
    /// `.list_attestations_for(x)` with ONE argument, or the path form with
    /// one or two (`FederationDirectory::list_attestations_for(self, k)`).
    /// The CEG list surface's four-argument `list_attestations_for(target,
    /// cursor, limit, scope)` is paged and does not count.
    pub(super) fn wide_calls(text: &str) -> Vec<String> {
        let mut found = Vec::new();
        for name in ["list_attestations_by", "list_attestations_for"] {
            let needle = format!("{name}(");
            let mut from = 0;
            while let Some(off) = text[from..].find(&needle) {
                let at = from + off;
                from = at + needle.len();
                let before = text[..at].trim_end();
                let path = before.ends_with("::");
                let method = before.ends_with('.');
                if !path && !method {
                    continue;
                }
                // Argument count at depth 1.
                let mut depth = 0i32;
                let mut commas = 0;
                let mut nonempty = false;
                let mut last_comma = false;
                for ch in text[at + name.len()..].chars() {
                    match ch {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        ',' if depth == 1 => {
                            commas += 1;
                            last_comma = true;
                            continue;
                        }
                        c if !c.is_whitespace() && depth >= 1 => nonempty = true,
                        _ => {}
                    }
                    if !ch.is_whitespace() {
                        last_comma = false;
                    }
                }
                let args = if nonempty {
                    commas + 1 - usize::from(last_comma)
                } else {
                    0
                };
                if (method && args == 1) || (path && (args == 1 || args == 2)) {
                    let line = text[..at].matches('\n').count() + 1;
                    found.push(format!("{line}: {name}"));
                }
            }
        }
        found
    }

    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// The test files by name, whatever their cfg says.
    fn is_test_file(p: &Path) -> bool {
        let f = p.file_name().and_then(|f| f.to_str()).unwrap_or("");
        f.ends_with("_invariants.rs") || f == "directory_double.rs" || f == "load_bearing.rs"
    }

    /// The scanner's own witness: crafted text it must count, and the
    /// near-misses it must not.
    #[test]
    fn i915_the_scanner_sees_a_production_call_and_nothing_else() {
        let scan = |src: &str| wide_calls(&production(&blank_comments_and_strings(src)).0);
        // Counted.
        for yes in [
            "fn f() { let r = d.list_attestations_by(&k).await?; }",
            "fn f() {\n    d\n        .list_attestations_for(\n            &k,\n        )\n        .await }",
            "fn f() { FederationDirectory::list_attestations_for(self, k).await }",
            "#[cfg(any(feature = \"sqlite\"))]\nfn f() { d.list_attestations_by(k); }",
            "#[cfg(test)]\nuse x;\nfn f() { d.list_attestations_by(k); }",
            "fn f() { if c == '\"' { d.list_attestations_by(k); } }",
            "enum E {\n    #[cfg(test)]\n    A,\n    B,\n}\nfn f() { d.list_attestations_by(k); }",
            "#[cfg(not(feature = \"test-anchor\"))]\nfn f() { d.list_attestations_by(k); }",
        ] {
            assert_eq!(scan(yes).len(), 1, "I915 counts {yes:?}");
        }
        // Not counted.
        for no in [
            "fn f() { // d.list_attestations_by(&k)\n }",
            "fn f() { /* d.list_attestations_by(&k) */ }",
            "fn f() { let s = \"d.list_attestations_by(k)\"; }",
            "fn f() { if c == '\"' { x(); } let s = \"d.list_attestations_by(k)\"; }",
            "#[cfg(test)]\nmod t;\nstruct S {\n    #[cfg(test)]\n    a: u8,\n}",
            "#[cfg(test)]\nmod t {\n    fn f() { d.list_attestations_by(k); }\n}",
            "#[cfg(all(test, feature = \"sqlite\"))]\nmod t {\n fn f() { d.list_attestations_for(k); }\n}",
            "#[tokio::test]\nasync fn t() {\n d.list_attestations_by(k).await;\n}",
            "#[cfg(any(test, feature = \"test-anchor\"))]\nasync fn list_attestations_by(&self, k: &str) {\n self.list_attestations_for(k)\n}",
            "fn f() { e.list_attestations_for(&t, cursor, limit, scope); }",
            "fn list_attestations_by(k: &str) {}",
        ] {
            assert!(scan(no).is_empty(), "I915 does not count {no:?}: {:?}", scan(no));
        }
        // A gated `mod x;` names a test-only file.
        let (_, mods) = production("#[cfg(test)]\nmod gate_x;\nfn f() {}");
        assert_eq!(mods, vec!["gate_x".to_owned()]);
    }

    /// **I915** — no production source calls a demoted wide read.
    #[test]
    fn i915_no_production_source_calls_a_wide_attestation_read() {
        let mut files = Vec::new();
        walk(&root().join("src"), &mut files);
        assert!(
            files.len() > 100,
            "I915 the walk found {} files",
            files.len()
        );
        let mut gated: BTreeSet<PathBuf> = BTreeSet::new();
        let mut texts = BTreeMap::new();
        for p in &files {
            let src = std::fs::read_to_string(p).unwrap();
            let (prod, mods) = production(&blank_comments_and_strings(&src));
            let dir = if p
                .file_name()
                .is_some_and(|f| f == "mod.rs" || f == "lib.rs")
            {
                p.parent().unwrap().to_path_buf()
            } else {
                p.with_extension("")
            };
            for m in mods {
                gated.insert(dir.join(format!("{m}.rs")));
                gated.insert(dir.join(m).join("mod.rs"));
            }
            texts.insert(p.clone(), prod);
        }
        let mut hits = Vec::new();
        let mut scanned = 0;
        for (p, prod) in &texts {
            if is_test_file(p)
                || gated.iter().any(|g| p.starts_with(g.with_extension("")))
                || gated.contains(p)
            {
                continue;
            }
            scanned += 1;
            for h in wide_calls(prod) {
                hits.push(format!("{}:{h}", p.strip_prefix(root()).unwrap().display()));
            }
        }
        assert!(scanned > 100, "I915 scanned {scanned} production files");
        assert!(
            hits.is_empty(),
            "I915 production calls of a demoted wide read (CIRISPersist#1001: page an \
             AttestationQuery instead): {hits:#?}"
        );
    }

    /// The production `list_*` methods of the trait, with their signatures.
    fn trait_list_methods() -> BTreeMap<String, String> {
        let src = std::fs::read_to_string(root().join("src/federation/mod.rs")).unwrap();
        let blanked = blank_comments_and_strings(&src);
        let start = blanked
            .find("pub trait FederationDirectory")
            .expect("I914 the trait");
        let open = start + blanked[start..].find('{').unwrap();
        let mut depth = 0i32;
        let mut end = open;
        for (i, c) in blanked[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let (body, _) = production(&blanked[open + 1..end]);
        let mut out = BTreeMap::new();
        let lines: Vec<&str> = body.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            let t = l.trim_start();
            let t = t.strip_prefix("async ").unwrap_or(t);
            let Some(rest) = t.strip_prefix("fn list_") else {
                continue;
            };
            // Only the trait's own items (four-space indent), not a default
            // body's nested fns.
            if l.len() - l.trim_start().len() != 4 {
                continue;
            }
            let name: String = format!(
                "list_{}",
                rest.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect::<String>()
            );
            let mut sig = String::new();
            for s in &lines[i..] {
                sig.push_str(s.trim());
                sig.push(' ');
                if s.trim_end().ends_with('{') || s.trim_end().ends_with(';') {
                    break;
                }
            }
            out.insert(name, sig);
        }
        out
    }

    fn takes_a_page(sig: &str) -> bool {
        let params = sig.split("->").next().unwrap_or(sig);
        [
            "limit:",
            "cursor:",
            "after_attestation_id:",
            "after_content_hash:",
        ]
        .iter()
        .any(|p| params.contains(p))
    }

    /// **I914** — every production `list_*` read on the trait is classified,
    /// and the classification matches its signature.
    #[test]
    fn i914_every_production_list_read_is_classified() {
        let methods = trait_list_methods();
        assert!(
            methods.len() > 60,
            "I914 the parser found {} list_* methods",
            methods.len()
        );
        // The demoted reads are not production methods.
        assert!(
            !methods.contains_key("list_attestations_by"),
            "I914 demoted"
        );
        assert!(
            !methods.contains_key("list_attestations_for"),
            "I914 demoted"
        );
        let table: BTreeMap<&str, Bound> = LIST_READ_BOUNDS.iter().copied().collect();
        assert_eq!(table.len(), LIST_READ_BOUNDS.len(), "I914 a duplicate row");
        let unclassified: Vec<&String> = methods
            .keys()
            .filter(|m| !table.contains_key(m.as_str()))
            .collect();
        assert!(
            unclassified.is_empty(),
            "I914 classify these in LIST_READ_BOUNDS (Paged / Schema(why) / Open(what it grows with)): \
             {unclassified:?}"
        );
        let stale: Vec<&&str> = table
            .keys()
            .filter(|m| !methods.contains_key(**m))
            .collect();
        assert!(
            stale.is_empty(),
            "I914 rows naming no trait method: {stale:?}"
        );
        for (name, bound) in &table {
            let sig = &methods[*name];
            match bound {
                Bound::Paged => assert!(
                    takes_a_page(sig),
                    "I914 {name} is classified Paged but takes no limit/cursor: {sig}"
                ),
                Bound::Schema(why) | Bound::Open(why) => {
                    assert!(
                        !takes_a_page(sig),
                        "I914 {name} takes a limit/cursor; classify it Paged: {sig}"
                    );
                    assert!(why.len() > 10, "I914 {name} needs a reason");
                }
            }
        }
    }
}
