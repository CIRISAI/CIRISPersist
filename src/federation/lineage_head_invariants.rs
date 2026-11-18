//! v53.0.0 (CC 3.2 T6, operator ruling B-1 on CIRISConstitution#136) —
//! **the head moves with the record.** I440–I449.
//!
//! The lineage head is the family or community record at a version. Its
//! signed `prev_head_digest` names the version it succeeds and its
//! `charter_digest` names the charter in force at that version. A charter row
//! no version names is not in force, so a charter re-scrub takes effect only
//! through a new version, and the head moves with it.
//!
//! - **I440** both members are signed, persisted and served: the row hash
//!   covers them, and every backend returns what was written.
//! - **I441** a supersede whose `prev_head_digest` is not the held head (empty,
//!   or another digest) does not move the head, on the family and the
//!   community arm; the one naming the held head is admitted. v62.0.0 (kernel
//!   pass 2, K1; CC 2.7.8): such a version is held as a tip (I2811), no
//!   longer refused `lineage_prev_head_mismatch`.
//! - **I442** a quorate charter of a family whose head names no charter
//!   confers nothing; a version naming it makes the root valid, and that
//!   version's `prev_head_digest` is the head it replaced.
//! - **I443** a charter re-scrub with no new version confers nothing: the
//!   named charter withdrawn and a fresh quorate one admitted leaves the root
//!   chartered by nothing until a version names the fresh one.
//! - **I444** the charter members (attach window) are the named charter's,
//!   never another charter row's, and follow the head when it moves.
//! - **I445** the attach head moves with the version: an acceptance edge naming
//!   the replaced head is stale at the author's door; the new head attaches.
//! - **I446** (deleted v62.0.0) witnessed the bundle/1 genesis-seeded accord
//!   family and its `genesis-charter` row; bundle/2 seeds neither.
//! - **I447** a community's charter is its conferring family's in force.
//! - **I448** from disk: every backend's `supersede_group_row` runs the prev
//!   check on both arms.
//! - **I449** a key root (no lineage record) keeps its self-charter.

//!
//! v62.0.0 (wave 3, slice E6; lead ruling 4) — **I440–I445, I447, I449 (9
//! store tests) are deleted**: the lineage head they witness is the earlier
//! form's signed `prev_head_digest` / `charter_digest` on a superseding
//! family or community record, moved through `supersede_family` /
//! `supersede_community` and charter re-scrubs. It has no forward form: an
//! edition-2 later version is the roster's own `group:roster` row with
//! `refs.head` (T1), whose quorum is its voices. I448 (from disk: every
//! backend's supersede runs the prev check on both arms) stays while the
//! earlier supersede code exists.
#[cfg(test)]
mod pure {
    /// **I448** — from disk: every backend's supersede runs the prev check on
    /// BOTH arms (family, community). v61 (CIRISPersist#934, S4b): the check
    /// lives once, in `group_supersede_admit::held_head_verdict`, which judges
    /// both head kinds' `prev_head_digest`; each backend's executor asks that
    /// verdict on both arms. Comments stripped, so a commented-out call
    /// cannot pass.
    #[test]
    fn i448_every_backend_runs_the_prev_check_on_both_arms() {
        fn fn_body(file: &str, head: &str) -> String {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
            let text = std::fs::read_to_string(&path).unwrap();
            let start = text.find(head).unwrap_or_else(|| panic!("{file}: {head}"));
            let body = &text[start..];
            let end = body[1..]
                .find("\n    async fn ")
                .or_else(|| body[1..].find("\n}\n"))
                .map_or(body.len(), |i| i + 1);
            body[..end]
                .lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n")
        }
        let plan = "src/federation/group_supersede_admit.rs";
        let verdict = fn_body(plan, "pub(crate) fn held_head_verdict(");
        assert_eq!(
            verdict.matches("check_prev_head_names_held(").count(),
            1,
            "{plan}: the verdict runs the prev check"
        );
        assert!(
            verdict.contains("planned.head.prev_head_digest()"),
            "{plan}: the verdict judges the offered head's prev_head_digest"
        );
        let accessor = fn_body(plan, "fn prev_head_digest(&self)");
        for field in ["f.family.prev_head_digest", "c.community.prev_head_digest"] {
            assert!(accessor.contains(field), "{plan}: judges {field}");
        }
        for file in ["src/store/sqlite.rs", "src/store/postgres.rs"] {
            let code = fn_body(file, "async fn store_planned_supersede(");
            assert_eq!(
                code.matches("held_head_verdict(").count(),
                2,
                "{file}: the verdict on the family AND community arm"
            );
        }
    }
}
