#!/usr/bin/env bash
# bump_version.sh — bump Cargo.toml + seed a CHANGELOG entry.
#
# Usage:
#   ./scripts/bump_version.sh <new_version>
#
# What it does:
#   1. Edit [package].version in Cargo.toml from current → new.
#   2. Prepend a CHANGELOG.md entry with today's date and a TODO
#      placeholder body (so you remember to write the changelog).
#   3. Run `cargo check` so Cargo.lock updates with the new version.
#
# Idempotent: re-running with the same version is a no-op on
# Cargo.toml, but will add a CHANGELOG entry if one doesn't yet
# exist for that version.
#
# After running:
#   - Edit CHANGELOG.md to fill in the new entry's body.
#   - Stage + commit (the pre-commit hook will run fmt+clippy).
#   - `git tag -a vX.Y.Z -m "..."`
#   - `git push origin main && git push origin vX.Y.Z`

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <new_version>"
    echo "  e.g. $0 0.4.4"
    exit 64
fi

NEW_VERSION="$1"

# Validate semver-ish shape — major.minor.patch with optional -prerelease.
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
    echo "error: '$NEW_VERSION' doesn't look like semver (X.Y.Z)" >&2
    exit 64
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

CARGO_TOML="$REPO_ROOT/Cargo.toml"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"
TODAY="$(date -u +%Y-%m-%d)"

# ── Cargo.toml ────────────────────────────────────────────────
# Match the [package] version line specifically — there are other
# `version = "..."` keys in the file (refinery features, etc.) and
# we don't want to touch those.
CURRENT_VERSION="$(grep -m1 '^version = "' "$CARGO_TOML" | sed -E 's/version = "([^"]+)"/\1/')"

if [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
    echo "Cargo.toml already at $NEW_VERSION (idempotent run)"
else
    echo "Cargo.toml: $CURRENT_VERSION → $NEW_VERSION"
    # In-place edit, portable across GNU + BSD sed.
    sed -i.bak -E "0,/^version = \"$CURRENT_VERSION\"/s//version = \"$NEW_VERSION\"/" "$CARGO_TOML"
    rm -f "$CARGO_TOML.bak"
fi

# ── CHANGELOG.md ──────────────────────────────────────────────
# Prepend a new section under the front-matter block. Keep-a-Changelog
# convention is reverse-chronological so newest entry goes nearest the
# top, right after the front matter.
#
# Detect whether an entry already exists for this version. Match
# `## [X.Y.Z]` at column 0.
if grep -q "^## \[$NEW_VERSION\]" "$CHANGELOG"; then
    echo "CHANGELOG.md already has a section for $NEW_VERSION (idempotent)"
else
    echo "CHANGELOG.md: prepending [$NEW_VERSION] entry"
    # Find the line number of the first `## [` header (= prior version).
    INSERT_BEFORE="$(grep -n '^## \[' "$CHANGELOG" | head -1 | cut -d: -f1)"
    if [ -z "$INSERT_BEFORE" ]; then
        echo "error: couldn't find any prior '## [...]' header in CHANGELOG.md" >&2
        exit 1
    fi
    NEW_ENTRY="$(cat <<EOF
## [$NEW_VERSION] — $TODAY

<!-- TODO: fill in body — what changed, why, and any threat-model
     / mission citations. Delete this comment before committing. -->

EOF
)"
    # head -n N gives the front matter; tail -n +N gives the rest.
    {
        head -n "$((INSERT_BEFORE - 1))" "$CHANGELOG"
        printf '%s\n' "$NEW_ENTRY"
        tail -n "+$INSERT_BEFORE" "$CHANGELOG"
    } > "$CHANGELOG.tmp"
    mv "$CHANGELOG.tmp" "$CHANGELOG"
fi

# ── Cargo.lock ────────────────────────────────────────────────
# `cargo check` writes the new version into Cargo.lock without
# rebuilding from scratch. Quiet so we don't drown the script
# output in compile noise.
echo "Refreshing Cargo.lock via cargo check..."
cargo check --quiet --features postgres,pyo3 2>&1 | tail -3

# ── Next steps ────────────────────────────────────────────────
cat <<EOF

✓ Bumped to $NEW_VERSION.

Next:
  1. Edit CHANGELOG.md to fill in the [$NEW_VERSION] entry body.
  2. Stage your release changes:
       git add CHANGELOG.md Cargo.toml <other release files>
  3. Commit (pre-commit hook will run cargo fmt --check + clippy):
       git commit -m "$NEW_VERSION — <one-line summary>"
  4. Tag + push:
       git tag -a v$NEW_VERSION -m "v$NEW_VERSION — <summary>"
       git push origin main
       git push origin v$NEW_VERSION
EOF
