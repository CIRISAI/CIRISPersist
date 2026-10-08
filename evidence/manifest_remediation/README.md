# Manifest remediation record (CIRISPersist#1029)

Through v53.1.8, the tag job's `build-manifest` signed `ls *.whl | head -1`, and the
CIRISCache restore left earlier releases' wheels in `target/wheels/`. It signed and registered a
v29.0.0 wheel's hash under later versions' names on 11 (version, target) pairs:

| target | versions | registered hash |
|---|---|---|
| `x86_64-pc-windows-msvc` | 53.0.1, 53.1.0 through 53.1.8 (ten) | `8a1e5a8f…`, the 29.0.0 windows wheel |
| `aarch64-unknown-linux-gnu` | 53.1.8 | `51193a5a…`, the 29.0.0 aarch64 wheel | Before CIRISVerify 20.1.0, a verifier checked the
signature and never related `binary_hash` to `binary_version`. So the real v53.1.8 wheel
failed integrity on those targets, and the v29.0.0 wheel passed as v53.1.8.

CIRISRegistry keys manifest rows by (project, version, target) and upserts them in place
with no history (CIRISRegistry#144 adds history and a `superseded` member). Re-posting a
corrected manifest erases the wrong one. This directory is the record of the rows that were
superseded.

## Layout

| file | what it is |
|---|---|
| `<version>/<target>.function.json` | `GET /v1/verify/function-manifest/{version}/{target}?project=ciris-persist`, verbatim |
| `<version>/<target>.build.json` | `GET /v1/verify/build-manifest/ciris-persist/{version}/{target}`, verbatim (the signed body as posted) |
| `<version>/<target>.builds.json` | `GET /v1/builds/{version}?project=ciris-persist&target={target}`, verbatim |
| `known_stale_hashes.txt` | wheel hashes once registered under the wrong version. `scripts/bits_changed.sh` check 4 refuses them |

`scripts/snapshot_manifests.sh <version> <target>...` writes the three files of a pair only when
all three reads return 200, and never over an existing snapshot. The first snapshot of a row is
the record; one taken after a re-post would record the corrected row as the old one.

`.github/workflows/reregister-manifests.yml` with `mode: check` compares every row with the
release's own bytes and writes nothing. With `mode: repost`, it re-posts only the MISMATCH rows. It
refuses one unless `<version>/<target>.function.json` is committed at the ref it runs from, and
unless the live row still carries the snapshot's `binary_hash`. Commit the snapshot first, then
dispatch. The runbook is in docs/RELEASE.md, "Remediating a registered manifest".

All 11 pairs above are snapshotted here, read from the us registry on 2026-10-08.

The files are never edited. A later correction to a pair adds a new snapshot directory only if
the registry keeps the history itself; until CIRISRegistry#144 lands, it does not.
