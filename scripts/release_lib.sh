# release_lib.sh — functions shared by release.sh, release_ship.sh,
# release_finish.sh and release_selftest.sh. Sourced, never executed.
#
# Kept in one place so the CHANGELOG section that becomes the PR body, the
# tag annotation and the release body is cut by ONE function, and so the
# self-test exercises the code the release runs rather than a copy of it.

# rl_prev_version <changelog> <version> — the numbered section after
# [<version>], i.e. where <version>'s section ends. Prints nothing if absent.
# The awk reads to EOF rather than exiting on the first hit: under `pipefail`
# an early-exiting reader SIGPIPEs its writer and fails the pipeline.
rl_prev_version() {
    grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$1" | sed 's/^## \[//; s/\]//' \
        | awk -v v="$2" '$0==v {f=1; next} f && !p {print; p=1}'
}

# rl_changelog_section <changelog> <version> — the section for <version>,
# from its `## [<version>]` heading up to (not including) the next numbered
# section's heading. Returns 1 if the section is missing or empty.
rl_changelog_section() {
    local file="$1" ver="$2" prev esc_v esc_p
    prev="$(rl_prev_version "$file" "$ver")"
    [ -n "$prev" ] || return 1
    esc_v="$(printf '%s' "$ver" | sed 's/\./\\./g')"
    esc_p="$(printf '%s' "$prev" | sed 's/\./\\./g')"
    awk -v s="^## \\[${esc_v}\\]" -v e="^## \\[${esc_p}\\]" '$0 ~ s {f=1} f && $0 ~ e {exit} f' "$file"
}

# rl_section_headings <changelog> <version> — the `### ` heading lines of the
# section, joined with "; " and stripped of their `### ` prefix and their
# "Added — " / "Fixed — " kind. The commit and merge subjects are built from it.
rl_section_headings() {
    rl_changelog_section "$1" "$2" | grep -E '^### ' \
        | sed -E 's/^### +//; s/^[A-Za-z]+ — //' | paste -sd ';' - | sed 's/;/; /g'
}

# rl_restamp_evidence <tsv> <prev> <version> — rewrite every
# `ciris-persist@<prev>` pointer to `@<version>` (a version bump re-stamps the
# evidence pin; supersets.rs::evidence_cc_impl_rows_pin_the_current_crate_version
# is the gate). `@<prev>` must not match a longer version (53.1.8 vs
# 53.1.80). Prints the count; returns 1 if there was nothing to re-stamp or
# the count after differs from the count before.
rl_restamp_evidence() {
    local tsv="$1" p v n_before n_after n_left
    p="$(printf '%s' "$2" | sed 's/\./\\./g')"; v="$(printf '%s' "$3" | sed 's/\./\\./g')"
    n_before="$(grep -oE "ciris-persist@${p}([^0-9.]|\$)" "$tsv" | wc -l)"
    n_after="$(grep -oE "ciris-persist@${v}([^0-9.]|\$)" "$tsv" | wc -l)"
    [ "$n_before" -gt 0 ] || { echo "no ciris-persist@$2 pointers in $tsv"; return 1; }
    sed -i -E "s/ciris-persist@${p}([^0-9.]|\$)/ciris-persist@$3\\1/g" "$tsv"
    n_left="$(grep -oE "ciris-persist@${p}([^0-9.]|\$)" "$tsv" | wc -l)"
    n_after=$(( $(grep -oE "ciris-persist@${v}([^0-9.]|\$)" "$tsv" | wc -l) - n_after ))
    [ "$n_after" -eq "$n_before" ] && [ "$n_left" -eq 0 ] \
        || { echo "re-stamped $n_after of $n_before ciris-persist@$2 pointers ($n_left left)"; return 1; }
    echo "$n_before"
}

# ── stage state ─────────────────────────────────────────────────────────
# One marker file per completed stage under <state-dir>. A stage that has a
# marker is skipped on a re-run; a stage is marked only after its body
# returned 0. Values a later stage needs (the PR number, the head sha) are
# kept as files beside the markers.

rl_done() { [ -f "$1/$2.done" ]; }
rl_mark() { date -u +%Y-%m-%dT%H:%M:%SZ > "$1/$2.done"; }
rl_put() { printf '%s\n' "$3" > "$1/$2"; }
rl_get() { [ -f "$1/$2" ] && cat "$1/$2"; }

# A stage that certifies a COMMIT (cheap legs, certify, PR CI) records the
# sha it passed on, and is done only while that sha is still HEAD.
rl_mark_at() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$3" > "$1/$2.done"; }
rl_done_at() { [ -f "$1/$2.done" ] && [ "$(cut -d' ' -f2 "$1/$2.done")" = "$3" ]; }

# rl_ci_rustflags — the workflow-level RUSTFLAGS in ci.yml, read the way
# certify.sh reads it, so these builds share certify's cache and CI's terms.
rl_ci_rustflags() {
    python3 - <<'PYEOF'
import re, pathlib, sys
text = pathlib.Path('.github/workflows/ci.yml').read_text()
head = text.split('\njobs:')[0]
m = re.search(r'^\s*RUSTFLAGS:\s*(.+?)\s*$', head, re.MULTILINE)
if not m or not m.group(1).strip().strip('"').strip("'"):
    sys.exit('could not find a workflow-level RUSTFLAGS in ci.yml')
print(m.group(1).strip().strip('"').strip("'"))
PYEOF
}

# rl_stage <state-dir> <name> <function> — run <function> unless <name> is
# already marked; mark it on success. Returns the function's exit code.
rl_stage() {
    local dir="$1" name="$2" fn="$3" rc
    if rl_done "$dir" "$name"; then
        echo "--- stage $name: already done ($(cat "$dir/$name.done")) — skipped"
        return 0
    fi
    echo "--- stage $name"
    "$fn"; rc=$?
    [ "$rc" -eq 0 ] && rl_mark "$dir" "$name"
    return "$rc"
}
