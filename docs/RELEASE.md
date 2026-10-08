# Releasing CIRISPersist

Three checked-in scripts take a release from a written CHANGELOG section to a published GitHub release. No agent or person has to act between their stages.

```
scripts/release.sh <version> [--pr-body FILE] [--merge-body FILE]   # stages 1-8, ends at the tag push
scripts/release_finish.sh <version> <tag-run-id>                    # tag CI → release → release body
```

`release.sh` calls `scripts/release_ship.sh` for the merge and the tag. You can also run `release_ship.sh` alone; see its header. `scripts/release_selftest.sh` tests the shared functions (`scripts/release_lib.sh`) offline in a few seconds.

## Before you start

- Work in the release worktree, on a branch that is **not** named `v<version>`. A branch named like the tag makes the tag push ambiguous (v52.0.1). Use `release-<version>` or a topic name.
- `Cargo.toml` is still at the previous release. The bump is stage 3.
- `CHANGELOG.md` has the header `## [<version>] - UNRELEASED` with the full section under it. That section becomes the PR body, the merge body, the tag annotation and the release body, so write it before you start.
- For a release that names a CC version, run `scripts/check_vendored_cc.sh <cc-tag>` first.
- `scripts/release.sh --dry-run <version>` runs preflight and prints the plan, the cheap-leg commands and the commit subject. It writes nothing.

## Stages

| # | stage | what it does | done marker |
|---|---|---|---|
| 1 | preflight | Clean tree. Branch is not `v<version>`, `main` or detached. Cargo.toml is at the previous numbered section's version. The UNRELEASED header is present. The tag does not exist on origin. | `preflight.done` |
| 2 | cheap | `cargo check --all-targets --no-default-features --features <axis>` for each of `ci_feature_matrix.AXIS_LEGS`, the pyo3 lane (`nextest --features pyo3,sqlite -E 'test(/pyo3/)'`), clippy on the lint set and on `--all-features`, and `pyi_surface.py check`. RUSTFLAGS is read from ci.yml, as certify reads it. | `cheap.done` + one per leg, **at a sha** |
| 3 | bump | Cargo version, `evidence/cc_impl.tsv` re-stamp (`ciris-persist@<prev>` → `@<version>`, count asserted), CHANGELOG date, `cargo check --features sqlite`, the evidence pin test, and the commit `release(v<version>): version, evidence re-stamp — <### headings>`. The hooks run. | `bump.done` |
| 4 | pr | Pushes the branch if origin differs from HEAD, then opens the PR or reuses the open one, through REST. The body is `--pr-body` or the section. | runs every time (idempotent) |
| 5 | certify | `LANES=${LANES:-1} scripts/certify.sh full` > `.release/<v>/certify.log`. Green means exit 0 **and** the line `EVERY CI LEG GREEN BY EXIT CODE.` | `certify.done`, **at a sha** |
| 6 | prci | Waits for the PR's CI run on HEAD (`PRCI_TIMEOUT_MIN`, default 180). Auto-retry reruns are respected (see below). | `prci.done`, **at a sha** |
| 7 | ship | `release_ship.sh <pr> <version> <head7> "<subject>" <merge-body>`: merge, tag at the merge commit, push the tag once main's run is visible, and print `TAG_RUN_ID`. | `ship.done` + `tag_run` |
| 8 | stop | Prints `scripts/release_finish.sh <version> <tag-run-id>`. | — |

Then run `release_finish.sh`. It checks that the run id is this tag's CI push run, waits for it (`FINISH_TIMEOUT_MIN`, default 180) and re-runs it if the same-SHA dedup cancelled it. It then waits for the release to exist, sets the body from the tag's annotation, asserts the body is at least the tag body's bytes minus 64, and prints `RELEASE_SHIP_DONE`.

### Why the tag is pushed once main's run EXISTS (#1008)

The tag run and main's push run on the merge commit share one concurrency group (#397, keyed on the SHA, `cancel-in-progress`), so whichever run is queued later cancels the other. In v50.0.0 the two were queued in the same second, main's came second, and it cancelled the tag run, which is the one that publishes. v51 then waited for main's run to complete, which cost 64–65 min per release. Waiting only until main's run is visible makes the tag run the newer one, so it cancels main's run. `release_finish.sh` re-runs a cancelled tag run as a backstop.

### Why there are two commands

v53.1.8's ship script was killed at the harness's 2-hour background cap while tag CI queued on macOS. `release.sh` ends at the tag push. `release_finish.sh` is a separate, re-runnable command, so each half fits under the cap. If either one is killed, run the same command again.

## The resume rule

State lives in `.release/<version>/`, which is git-ignored, so it never dirties the tree. Each completed stage writes `<stage>.done`, and a re-run skips any stage that has one.

Stages 2, 5 and 6 certify a **commit**. Their markers record the sha and count as done only while HEAD is still that sha. After a fix:

1. commit the fix (never `--amend`; never `--no-verify`);
2. re-run `scripts/release.sh <version>`.

The re-run re-checks the cheap legs at the new HEAD, pushes it, re-certifies and waits for the new PR run. Bump and ship are not repeated. To redo a stage on purpose, delete its marker. To start over, delete `.release/<version>/`.

`--pr-body` and `--merge-body` are copied into the state dir on first use, so a re-run does not need them again. Pass them as absolute paths.

PR CI after a failure: `auto-retry.yml` re-runs a first-attempt failure that has an infra signature. The script treats `completed/failure` as final only when one of these holds: the run is on attempt 2 or later; an `auto-retry` run that started after the failure has completed without re-running it; or 15 minutes have passed.

## Exit codes

| code | script | meaning | what to do |
|---|---|---|---|
| 2 | all | usage: bad version, unknown flag, missing body file, or a run id that is not this tag's CI run | fix the arguments |
| 20 | release.sh | preflight refused (the line says which check) | fix it and re-run. A branch named `v<version>`: rename the branch |
| 21 | release.sh | a cheap leg is red; the log is `.release/<v>/cheap-<leg>.log` | fix, commit, re-run |
| 22 | release.sh | bump: version not rewritten, re-stamp count mismatch, `cargo check` or the evidence test red, or a hook refused the commit | read the log. If the tree is left dirty, `git checkout -- Cargo.toml Cargo.lock CHANGELOG.md evidence/cc_impl.tsv` and re-run |
| 23 | release.sh | the push (pre-push hook) or PR creation failed | read the hook output, fix, commit, re-run |
| 24 | release.sh | certify not green; the log is `.release/<v>/certify.log` | an `INFRA` (SIGKILL) leg is the machine, not the tree: re-run with fewer lanes. A `RED` leg: fix, commit, re-run |
| 25 | release.sh | PR CI red after any auto-retry | read the run. For a real red, fix, commit and re-run. For a flake, root-cause it (no nextest retries) |
| 26 | release.sh | PR CI did not finish within `PRCI_TIMEOUT_MIN` | re-run to keep waiting |
| 27 | release.sh | `release_ship.sh` failed; its own code is printed and logged in `.release/<v>/ship.log` | see the ship codes below, then re-run `release.sh`. Ship accepts an already-merged PR and an already-cut or pushed tag |
| 28 | release.sh | the tree is dirty mid-release | commit or stash, re-run |
| 3 | release_ship.sh | the PR head moved, or PR CI is not green | the head moved: let `release.sh` re-certify it |
| 4 | release_ship.sh | the merge failed after 5 attempts | check the PR's mergeability |
| 5, 6 | release_ship.sh | main CI red, or it timed out (only when the merge tree differs from the PR head tree) | something landed on main in between. Investigate before tagging |
| 7, 8, 9 | release_ship.sh | no CHANGELOG section, the tag cut failed, or the tag sha or body did not match | inspect `git tag -l --format='%(contents)' v<version>` |
| 10, 16 | release_ship.sh | the tag push failed, or no tag CI run appeared within 5 min | check `gh run list --branch v<version>` |
| 11 | release_finish.sh | tag CI red, other than a cancellation | read the run. Fix forward with a patch release |
| 12 | release_finish.sh | tag CI did not finish within `FINISH_TIMEOUT_MIN` | re-run the same command |
| 13, 14, 15 | release_finish.sh | the release never appeared, the edit failed, or the body is too short | re-run. If it repeats, `gh release edit v<version> --notes-file` with the tag annotation by hand |
