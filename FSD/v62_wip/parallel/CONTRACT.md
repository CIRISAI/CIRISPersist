# v62 parallel write wave: the contract every agent follows

Up to 20 agents write code at the same time and **nobody builds**. Builds happen only in the two **synthesis lanes**, which apply the patches, compile, fix and test (see "Synthesis points" below). Read this whole file first, then `FSD/V62_STATUS.md`, `FSD/v62_docs/RULINGS.md` and `FSD/v62_docs/JSON_CUT_PLAN.md` (the part for your slice).

## Base

- Base branch: **`v62-syn0` @ 8f33957f**. It is an UNBUILT merge of cut A (166b5d53) and cut B (64bd70f4), so treat it as code that probably compiles but has not been proven to.
- Your worktree: `git worktree add -b v62-p-<ID> /home/emoore/CIRISPersist-wp-<ID> v62-syn0`. Work only there.

## The no-build rule (hard)

- **NO cargo of any kind:** build, check, test, clippy, nextest, mutants, bench, doc, metadata, update, tree, and no `maturin`/`pip install`. Do not run `scripts/cargo_guard.sh`, `certify.sh`, or any script that invokes cargo. **Read a script before you run it.**
- **Allowed:**
  - `rustfmt --edition 2021 <file>...` on files you edited;
  - grep/rg, git log/show/diff/blame;
  - python scripts that do not call cargo (for example `scripts/pyi_surface.py check`, `scripts/gen_directory_double.py`);
  - reading `~/.cargo/git/checkouts/` for dependency sources. Verify 23.3.0 is tag `v23.3.0` (ffd7af1). If it isn't checked out, `git clone --depth 1 --branch v23.3.0 https://github.com/CIRISAI/CIRISVerify /home/emoore/verify-v23.3.0-src` (one agent creates it; the others reuse it).
- **Write as if the compiler were watching:**
  - open the definition of every type and function you call, and match its exact signature, visibility and cfg;
  - make every `match` exhaustive;
  - import every name;
  - no guessed APIs. If you must depend on something not written yet, take it from the owning agent's `<ID>.api.md` (below) and list it in your notes under "assumed APIs".
- **NEVER `git commit` a `.rs` file:** the pre-commit hook builds. Never use `--no-verify`, `--amend`, `reset`, `stash`, force or `pkill`.

## Deliverables (in `/home/emoore/CIRISPersist-w62int/FSD/v62_wip/parallel/`)

1. **`<ID>.patch`.** In your worktree run `git add -A && git diff --cached --binary v62-syn0 > <that dir>/<ID>.patch`. Regenerate it whenever you reach a coherent point, so partial work survives.
2. **`<ID>.md`, your notes for the synthesis builder:**
   - what you changed, file by file;
   - the tests you added, with their invariant numbers;
   - the refusal tokens you introduced;
   - the assumed APIs;
   - the compile risks you know of (anything you could not confirm by reading);
   - what is NOT done.
   Every claim is BELIEVED (nothing is built); mark the claims you checked by reading as "read-checked".
3. **`<ID>.api.md`, if other agents depend on you** (E0, C2): publish the exact signatures FIRST, within your first stretch of work, then implement to them. If you change one later, update the file and say so at the top.

Do not commit in the `w62int` worktree. The coordinator commits the patch and notes files.

## Shared rules

- **Ownership.**
  - Edit only the files your brief gives you.
  - If you must touch another file, keep the hunk small and self-contained, and list it in your notes under "foreign hunks".
  - For files several agents share, the `.files` lists and briefs say who owns production code and who owns the `#[cfg(test)]` modules.
- **Invariant numbers.**
  - Use only your block (table below), in the form `I<n>`.
  - Persist's rules: each new test names the invariant it witnesses in its doc comment, in the existing style.
- **Backends.** Every store-facing test exists for sqlite AND postgres (`backend_suite.rs` / the `pg` test modules pattern). There are no backend-only doors.
- **Code rules.**
  - `#![deny(unsafe_code)]`.
  - Shipped migrations are immutable, but V300 is unshipped, so you may edit it, with a note.
  - `src/federation/directory_double.rs` is generated: edit `FederationDirectory` in `mod.rs`, then run `python3 scripts/gen_directory_double.py`.
  - Python surface: `python/ciris_persist/ciris_persist.pyi` must match (`scripts/pyi_surface.py check`).
- **Tests that assert earlier-form behaviour are deleted, not rewritten.** These are hybrid-pending, `attach_*_pqc`, scrub upgrade, fingerprints, JCS hash checks and `*_v1_pinned`. List every deleted test in your notes, with one line of why.
- **EMBARGO: LIFTED 2026-11-18 (Eric).** Neutral wording is no longer required.
  - In every code comment, test name, doc or note, name the key-of-issuer check neutrally: "the key-of-issuer check", "kid_not_of_iss".
  - This holds until the coordinator lifts it.
- **Report back.** Your final message is at most 120 words: done or not done, the paths to your patch and notes, and your top 3 compile risks. Everything else goes in `<ID>.md`.

## Invariant blocks

| ID | block | ID | block |
|---|---|---|---|
| C1 | I2300–I2329 | E1 | I2600–I2629 |
| C2 | I2330–I2359 | E2 | I2630–I2659 |
| C3 | I2360–I2389 | E3 | I2660–I2689 |
| C4 | I2390–I2419 | E4 | I2690–I2719 |
| C5 | I2420–I2449 | E5 | I2720–I2749 |
| D1 | I2450–I2479 | E6 | I2750–I2779 |
| D2 | I2480–I2509 | E7 | I2780–I2809 |
| D3 | I2510–I2539 | K1 | I2810–I2839 |
| E0 | I2540–I2599 | K2 | I2840–I2869 |
| F0 | I2870–I2899 | R0 | (docs only) |

## Synthesis points (the build lanes; at most 2 builds at once)

- **S0:** cut A and cut B finish on their own branches (both are building now). Then `v62-syn1` = the final A + B.
- **S1 lane, "boot":** v62-syn1 + C1–C5. Build, fix and test (sqlite+pg). The C exit criteria in `V62_STATUS.md`.
- **S2 lane, "surfaces + kernel":** v62-syn1 + D1–D3 + E0 + K1–K2. Build, fix and test.
- **CP1:** S1 ∪ S2 merged into `release/62`, all lanes green.
- **S3 / S4 lanes, "fixtures":** CP1 + E1–E3 (S3) and E4–E7 (S4). Build, fix and test, by file, so the two lanes never touch the same file.
- **CP2:** S3 ∪ S4 + F0, with `EARLIER_FORM_DOORS_SHUT = true` and the full suite green.
- **R lane:** R0's notes + the evidence + certify, then CP3, the tag.
