#!/usr/bin/env bash
# install-hooks.sh — install scripts/hooks/* into .git/hooks/.
#
# Symlinks (not copies) so that updates to scripts/hooks/ take effect
# immediately without rerunning this. .git/hooks is .gitignore'd by
# default; the source-of-truth lives in scripts/hooks/ and is
# version-controlled.
#
# Run after a fresh clone:
#   ./scripts/install-hooks.sh
#
# Idempotent: safe to re-run.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_SRC="$REPO_ROOT/scripts/hooks"
HOOKS_DST="$REPO_ROOT/.git/hooks"

if [ ! -d "$HOOKS_SRC" ]; then
    echo "error: $HOOKS_SRC not found" >&2
    exit 1
fi

mkdir -p "$HOOKS_DST"

for hook in "$HOOKS_SRC"/*; do
    name="$(basename "$hook")"
    target="$HOOKS_DST/$name"

    # If target exists and is already our symlink, leave alone.
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$hook" ]; then
        echo "✓ $name already installed (symlink up-to-date)"
        continue
    fi

    # If target exists as a regular file (e.g. user-customized hook),
    # back it up before overwriting.
    if [ -e "$target" ] && [ ! -L "$target" ]; then
        backup="$target.backup.$(date +%s)"
        echo "→ backing up existing $name to $backup"
        mv "$target" "$backup"
    fi

    ln -sf "$hook" "$target"
    chmod +x "$hook"
    echo "✓ installed $name → $hook"
done

echo
echo "Hooks installed. Test with:"
echo "  ./scripts/hooks/pre-commit   # runs without committing"
echo "  ./scripts/hooks/pre-push     # runs without pushing"
