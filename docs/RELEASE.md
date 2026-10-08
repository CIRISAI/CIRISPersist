# Releasing CIRISPersist

Three checked-in scripts take a release from a written CHANGELOG section to a published GitHub release. No agent or person has to act between their stages.

```
scripts/release.sh <version> [--pr-body FILE] [--merge-body FILE] [--skip-codex]   # stages 1-9, ends at the tag push
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
| 7 | codex | Waits for `chatgpt-codex-connector[bot]`'s review of HEAD (`CODEX_TIMEOUT_SECS`, default 1800; polled every `CODEX_POLL_SECS`, default 60). Reviewed means a bot review whose `commit_id` is HEAD, or the bot's summary comment showing a Completed row for HEAD's short sha (a clean pass posts no review, only a 👍). A review of an older head does not count. Any bot inline comment made on HEAD (its `original_commit_id`, or it belongs to a bot review of HEAD) stops the release with exit 30 and prints each finding's `path:line` and title. If no review arrives in time, the stage fails OPEN with `::warning::Codex review did not arrive; shipping without it`. `--skip-codex` skips the stage (an operator override, printed loudly). | `codex.done`, **at a sha** |
| 8 | ship | `release_ship.sh <pr> <version> <head7> "<subject>" <merge-body>`: merge, tag at the merge commit, push the tag once main's run is visible, and print `TAG_RUN_ID`. | `ship.done` + `tag_run` |
| 9 | stop | Prints `scripts/release_finish.sh <version> <tag-run-id>`. | — |

Then run `release_finish.sh`. It checks that the run id is this tag's CI push run, waits for it (`FINISH_TIMEOUT_MIN`, default 180) and re-runs it if the same-SHA dedup cancelled it. It then waits for the release to exist, sets the body from the annotation of origin's tag (never a local copy; a different local tag is refused), asserts the body is at least the tag body's bytes minus 64, runs `scripts/verify_release.sh` (below), and prints `RELEASE_SHIP_DONE`.

### Why the tag is pushed once main's run EXISTS (#1008)

The tag run and main's push run on the merge commit share one concurrency group (#397, keyed on the SHA, `cancel-in-progress`), so whichever run is queued later cancels the other. In v50.0.0 the two were queued in the same second, main's came second, and it cancelled the tag run, which is the one that publishes. v51 then waited for main's run to complete, which cost 64–65 min per release. Waiting only until main's run is visible makes the tag run the newer one, so it cancels main's run. `release_finish.sh` re-runs a cancelled tag run as a backstop.

### Main's run after a tree-equal merge

On a push to main, CI's `tree equality (main merges only)` job skips the whole run when the merge tree equals a PR head whose CI passed. Tag runs are never skipped. `release_ship.sh` treats any visible main run as the signal to push the tag, including one that already completed with most jobs skipped. When the trees differ, the full main run happens and ship waits for it to succeed.

`scripts/certify.sh prebuild` compiles every certify leg (`nextest --no-run`), both clippy invocations and the dev wheel, under the same RUSTFLAGS, and runs no tests. It exits 0, 1 or 3 like `full`. It can be run by hand before `release.sh` to warm the cache. `release.sh` does not call it.

### Why there are two commands

v53.1.8's ship script was killed at the harness's 2-hour background cap while tag CI queued on macOS. `release.sh` ends at the tag push. `release_finish.sh` is a separate, re-runnable command, so each half fits under the cap. If either one is killed, run the same command again.

### Why release.sh waits for Codex (CIRISPersist#1039)

On PR #1039 the chain would have merged and tagged v53.2.0 about ten minutes after Codex posted six findings, one of them a P1 that emptied the CHANGELOG cut under gawk. Certify and PR CI were green, and nothing in the chain read the review. It was stopped by hand. The `codex` stage reads it. Findings are keyed to the commit Codex reviewed, not to a comment's current `commit_id`: GitHub moves that forward to the newest head while the line is unchanged, so an old finding that was already fixed would otherwise block every later push. The stage fails open after its timeout because Codex is an external service, and its absence must not hold a release indefinitely. The warning line makes that visible.

## The resume rule

State lives in `.release/<version>/`, which is git-ignored, so it never dirties the tree. Each completed stage writes `<stage>.done`, and a re-run skips any stage that has one.

Stages 2, 5, 6 and 7 judge a **commit**. Their markers record the sha and count as done only while HEAD is still that sha. After a fix:

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
| 24 | release.sh | certify has a RED leg (exit 1); the log is `.release/<v>/certify.log` | fix, commit, re-run |
| 25 | release.sh | PR CI red after any auto-retry | read the run. For a real red, fix, commit and re-run. For a flake, root-cause it (no nextest retries) |
| 26 | release.sh | PR CI did not finish within `PRCI_TIMEOUT_MIN` | re-run to keep waiting |
| 27 | release.sh | `release_ship.sh` failed; its own code is printed and logged in `.release/<v>/ship.log` | see the ship codes below, then re-run `release.sh`. Ship accepts an already-merged PR and an already-cut or pushed tag |
| 28 | release.sh | the tree is dirty mid-release | commit or stash, re-run |
| 29 | release.sh | certify exited 3 (INFRA): no leg is RED, but a leg was lost to the machine (disk floor `CERTIFY_MIN_FREE_GB`, a signal, an empty `.rc`, or a leg that never ran). The tree is unjudged | free disk or RAM (or lower `LANES`) and re-run. `scripts/certify.sh verdict` re-prints the table from the existing logs |
| 30 | release.sh | Codex left inline findings on HEAD. Each is printed as `path:line  title` | fix, commit, re-run the same command. The new push is reviewed again; the stage passes once Codex has reviewed the new HEAD without findings. A finding you decide not to fix needs `--skip-codex`, stated in the PR |
| 3 | release_ship.sh | the PR head moved, or PR CI is not green | the head moved: let `release.sh` re-certify it |
| 4 | release_ship.sh | the merge failed after 5 attempts | check the PR's mergeability |
| 5, 6 | release_ship.sh | main CI red, or it timed out (only when the merge tree differs from the PR head tree) | something landed on main in between. Investigate before tagging |
| 7, 8, 9 | release_ship.sh | no CHANGELOG section, the tag cut failed, or the tag sha or body did not match | inspect `git tag -l --format='%(contents)' v<version>` |
| 10, 16 | release_ship.sh | the tag push failed, or no tag CI run appeared within 5 min | check `gh run list --branch v<version>` |
| 11 | release_finish.sh | tag CI red, other than a cancellation | read the run. Fix forward with a patch release |
| 12 | release_finish.sh | tag CI did not finish within `FINISH_TIMEOUT_MIN` | re-run the same command |
| 13, 14, 15 | release_finish.sh | the release never appeared, the edit failed, or the body is too short | re-run. If it repeats, `gh release edit v<version> --notes-file` with the tag annotation by hand |
| 17 | release_finish.sh | `verify_release.sh` failed: an attestation did not verify, a wheel's bits check failed, a download failed, or `gh` has no `attestation` command | read its per-subject lines. `gh` older than 2.49: `GH=/path/to/newer/gh` and re-run. A FAIL on a provenance subject means the tag run's `attest` job did not sign those bytes: read that job before anything else. A FAIL on `bits (registered)` means the registry's row for that target is not this release's wheel: see "Remediating a registered manifest" |
| 18 | release_finish.sh | a local `refs/tags/v<version>` is a different tag object than origin's (an abandoned tagging attempt). The annotation is read only from origin's tag, fetched into `refs/release-finish/v<version>` | `git tag -d v<version>` and re-run |
| 19 | release_finish.sh | origin's tag could not be fetched; no local copy is used instead | check `git ls-remote origin refs/tags/v<version>` and the network, then re-run |

## Verifying a release

Tag CI's `attest` job (CIRISPersist#1028) signs two kinds of GitHub artifact attestation: an in-toto Statement in a DSSE envelope, signed through Sigstore's public-good instance (the repo is public) and stored against the subject's sha256.

| predicate type | subjects | predicate |
|---|---|---|
| `https://slsa.dev/provenance/v1` (SLSA Build L2) | the four abi3 desktop wheels `ciris_persist-<v>-cp310-abi3-*.whl` (tag-run artifacts, not release assets) and the three release tarballs `ciris-persist-v<v>-{ios,android,android-wheels}.tar.gz`, as downloaded from the release | GitHub's build provenance: repo, workflow, ref, commit, run |
| `https://ciris.ai/attestation/cc-conformance/v1` | `evidence/cc_impl.tsv` at the tag | `{"cc_tag", "registry_sha256", "crate_version", "merge_sha"}`: the vendored CC tag (`"v" + VENDORED_CC_VERSION`), `VENDORED_REGISTRY_SHA256` (CC's grammar hash), the Cargo version, and the tagged commit |

There is no sdist: consumers build from the git tag and nothing builds one.

```
scripts/verify_release.sh v<version> [<tag-run-id>]   # GH=/path/to/gh if the default gh is older than 2.49
```

It downloads each subject, runs `gh attestation verify` bound to `CIRISAI/CIRISPersist`, to `.github/workflows/ci.yml` as the signer workflow and to `refs/tags/v<version>` as the source ref (an attestation from a branch or PR run does not count), prints the conformance predicate, and checks its `crate_version` and `merge_sha` against the tag. Exit 0 means every subject verified; 1 lists each failure; 2 is usage or a `gh` without `attestation`; 3 is a failed download (nothing judged). Wheel artifacts expire after 90 days; for an older release `VERIFY_SKIP_WHEELS=1` skips them and says so.

An adopter verifies one file without the script:

```
gh attestation verify evidence/cc_impl.tsv -R CIRISAI/CIRISPersist \
  --predicate-type https://ciris.ai/attestation/cc-conformance/v1 \
  --source-ref refs/tags/v<version> --format json \
  --jq '.[0].verificationResult.statement.predicate'
```

`verify_release.sh` also runs `scripts/bits_changed.sh` on each desktop wheel (below), against the registry. Its `ok    bits` and `ok    bits (registered)` lines are per target.

Releases before v53.2.0 carry no attestations. Through v53.1.8 the wheel artifacts also held stale wheels restored from the build cache, and build-manifest registered a v29.0.0 wheel's hash for linux-aarch64 and windows-x86_64. v53.2.0 clears `target/wheels/` before the build and selects only `ciris_persist-<v>-*.whl`.

## The bits-changed gate

`scripts/bits_changed.sh <version> <target> <wheel-dir-or-file>` (CIRISPersist#1029) asks whether the bits changed, before a wheel's manifest is signed and after it is registered.

| check | refuses when | exit |
|---|---|---|
| 1 | the directory holds zero, or two or more, `ciris_persist-<version>-*.whl` for the target's platform tag | 10 |
| 2 | the wheel's own `*.dist-info/METADATA` `Version:` is not `<version>` | 11 |
| 2 | a `WHEEL` `Tag:` does not fit the target | 12 |
| 3 | its sha256 is the hash the registry holds for the PREVIOUS release on this target. A 404 there means the first release on the target, and it passes | 13 |
| 4 | its sha256 is in `evidence/manifest_remediation/known_stale_hashes.txt`, unless that line names `<version>` as the hash's true version | 14 |
| 5 | `--after-publish`: the registered row for (`<version>`, target) does not carry exactly its sha256, or there is no row | 15 |
| — | `--attestation-digest <hex>` differs from its sha256 | 16 |
| — | a registry read failed: not 200, and not a 404 where one is allowed | 17 |
| — | no previous version could be found | 18 |

`python-source-tree` is the fifth target. It is not a wheel: pass its tree hash as `--sha256 <hex>`. Checks 1 and 2 are skipped for it. Check 3 lets its hash equal the previous release's only when `git diff --quiet v<prev> v<version> -- python/ciris_persist` is empty, and the gate prints that it allowed it on that basis. That tree is three files, which were unchanged from v13.0.0 through v17.6.0, so an equal hash is often genuine. A wheel never gets this exemption, because it embeds its version. The tag job's `build-manifest` checkout fetches full history so the tags are there.

The target map is `aarch64-unknown-linux-gnu` to `manylinux*_aarch64`, `x86_64-unknown-linux-gnu` to `manylinux*_x86_64`, `x86_64-pc-windows-msvc` to `win_amd64`, and `aarch64-apple-darwin` to `macosx*_arm64`. The previous version is the newest `v` tag below `<version>`, from `git tag`, or `git ls-remote` in a shallow checkout. `--prev` or `BITS_CHANGED_PREV` overrides it. The registry is `BITS_CHANGED_REGISTRY_BASE`; the tag job points it at the registry it writes to. A 429 or 5xx is retried, honouring `Retry-After`.

Where it runs: the tag job runs checks 1 to 4 before each sign and check 5 after the round-trip, both through `scripts/build_manifest.sh`. `verify_release.sh` runs all five on each published wheel. `scripts/bits_changed_test.sh` is its offline witness set, a certify fast gate (`bitschanged`) and a CI lint step.

## Remediating a registered manifest

CIRISRegistry keys manifest rows by (project, version, target) and upserts them in place. It keeps no history until CIRISRegistry#144 lands. Each version has five targets: `python-source-tree`, a hash over `python/ciris_persist`, and one row per wheel.

The wheels exist only as each tag run's `ciris_persist-wheel-<label>` artifacts. PyPI publishing stopped at 22.0.1 (#615), and the GitHub release carries only the iOS and Android tarballs.

The rule is check first. A dispatch with the defaults (`mode: check`, `dry_run: true`, all five targets) writes nothing.

1. **The first dispatch is always the check pass,** over every affected version and all five targets:
   ```
   gh workflow run reregister-manifests.yml \
     -f versions="53.0.1 53.1.0 53.1.1 53.1.2 53.1.3 53.1.4 53.1.5 53.1.6 53.1.7 53.1.8"
   ```
   Per (version, target), the run prints the registered `binary_hash` beside the local hash, with `MATCH`, `MISMATCH` or `NOROW`.
   - A wheel's local hash is the sha256 of that version's wheel. It is selected by version from the tag run's artifact. The tag run is the newest CI push run of `v<version>` with unexpired wheel artifacts.
   - `python-source-tree`'s local hash is recomputed from the version's tag exactly as the tag job signs it, with `ciris-build-sign sign --tree python/ --tree-include ciris_persist` and the same exemptions, using a throwaway keypair. The tree hash does not depend on the key. It is compared with the registered `binary_hash` like any other row.
   - The table is in the step summary and in each version's `manifests-check-<v>` artifact.
2. **Snapshot all five targets of every version you will repost, and commit them.** The snapshot is the only record of what is overwritten. `register` rewrites all five targets of a version, not only the MISMATCH ones, so the repost refuses a version unless all five are committed. The 11 MISMATCH pairs known from #1029 are already committed. The other targets of those versions are not yet.
   ```
   scripts/snapshot_manifests.sh <version> python-source-tree x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc
   git add evidence/manifest_remediation/<version>/ && git commit
   ```
   The script refuses to overwrite an existing snapshot (exit 4). It writes nothing for a pair whose reads are not all 200 (exit 5).
3. **Repost** only the versions and targets that showed MISMATCH, with `mode: repost` and `dry_run: false`, from a ref that has the snapshots. A repost left at `dry_run: true` stops at `ciris-build-sign register --dry-run`. For #1029 the expected command is:
   ```
   gh workflow run reregister-manifests.yml -f mode=repost -f dry_run=false \
     -f versions="53.0.1 53.1.0 53.1.1 53.1.2 53.1.3 53.1.4 53.1.5 53.1.6 53.1.7" -f targets="x86_64-pc-windows-msvc"
   gh workflow run reregister-manifests.yml -f mode=repost -f dry_run=false \
     -f versions="53.1.8" -f targets="aarch64-unknown-linux-gnu x86_64-pc-windows-msvc"
   ```
   Use the check pass's table, not this list, if they differ. Within the targets given, a repost re-signs only the rows its own check step finds MISMATCH. Any target, `python-source-tree` included, is re-signed only on MISMATCH. It refuses a version unless all five targets have committed snapshots and every live row, compared whole as canonical JSON, still equals its snapshot.
   - The MISMATCH targets are re-signed after `bits_changed.sh` checks 1 to 4.
   - Every other target is re-posted unchanged, from the registry's live build-manifest read, never from the tag run's artifact. That fetched body must equal the committed snapshot, and its manifest is checked against its wheel or against the tag's tree. `register` writes one `binary_manifests` map per version, so a partial re-post would drop the rest.
   - `register` also rewrites every target's `builds` row. The run therefore saves its own copy of all five live rows first, in the `manifests-repost-<v>` artifact.
   - Rows go through `POST /v1/builds` and `POST /v1/verify/build-manifest`, never the legacy function-manifest path. Then come the round-trip and `bits_changed.sh --after-publish` on all five targets.
4. Run `scripts/verify_release.sh <v> <tag-run-id>`. Every `bits (registered)` line should read `ok`.

**Where the bytes come from.** Each run prints which path it took.
- **Wheels:** the tag run's artifact. When that artifact has expired after 90 days, the `rebuild` job builds the wheel from the tag in `pyo3-wheel`'s shape, under the tag's `rust-toolchain.toml`. The registration notes then say SAME-VERSION REBUILD, which CC 3.1.2.1 treats as a `supersedes`. Rebuilt bytes are not the released bytes, and they live only in that run's artifacts.
- **PersistExtras and the unchanged manifests:** the registry itself, always. `GET /v1/verify/build-manifest` serves the posted manifest byte for byte, and its `extras` re-signs to the same `manifest_hash`. The tag run's `ciris-persist-build-manifest-<v>` artifact is not used: it can be older than the live row, and re-posting it would overwrite a newer one.

The workflow uses the tag job's secrets for `repost` only, and adds none.
