# ci_env.sh — the build environment every LOCAL gate shares with CI. Sourced,
# never executed: `certify.sh`, `hooks/pre-push`, `hooks/pre-commit` and
# `fingerprint_check.sh` all ask these functions instead of restating them.
#
# ── WHY ONE FILE (CIRISPersist#1010) ─────────────────────────────────────
# RUSTFLAGS, the feature set and the cargo profile are all part of every
# compiled unit's fingerprint. Before this file the pre-push hook ran
# `cargo test --features postgres,pyo3,server --lib` with NO RUSTFLAGS, the
# release pipeline's pre-certify lanes ran two more feature sets, and certify
# ran nine sets under `-D warnings`. Three fingerprints for one suite: every
# dependency compiled three times on one machine before CI saw a byte, and
# nothing the hook built was ever reused by certify.
#
# The hook now builds exactly certify's `core` leg (same RUSTFLAGS, same
# features, same profile), so the dependency graph and the lib-test unit it
# compiles are the ones certify's first leg finds warm.
# `scripts/fingerprint_check.sh` reads what each consumer WOULD run and fails
# if the triples differ.

# RUSTFLAGS, derived from the workflow-level `env:` block of ci.yml (never
# restated: v30.3.1 shipped because a hand-copied set was weaker than CI's).
# Prints the value; returns non-zero if it cannot be derived or is empty.
ci_rustflags() {
    local root="${1:-.}" out
    out="$(python3 - "$root" <<'PYEOF'
import re, pathlib, sys
text = (pathlib.Path(sys.argv[1]) / '.github/workflows/ci.yml').read_text()
head = text.split('\njobs:')[0]          # workflow-level env, before any job
m = re.search(r'^\s*RUSTFLAGS:\s*(.+?)\s*$', head, re.MULTILINE)
if not m:
    sys.exit('could not find a workflow-level RUSTFLAGS in ci.yml')
print(m.group(1).strip().strip('"').strip("'"))
PYEOF
)" || return 1
    [ -n "$out" ] || return 1
    printf '%s\n' "$out"
}

# A leg's feature set as cargo's comma list, derived from Cargo.toml by
# `ci_feature_matrix.py`. Returns non-zero on an empty or unknown leg — a leg
# that tests nothing cannot pass.
ci_feature_csv() {
    local leg="$1" root="${2:-.}" feats
    feats="$(python3 "$root/scripts/ci_feature_matrix.py" set "$leg")" || return 1
    [ -n "$feats" ] || return 1
    printf '%s\n' "$feats" | tr ' ' ','
}

# Test threads for ONE leg running alone (certify's quick/focus tiers and the
# pre-push hook). Threads are not in the fingerprint; they are shared so the
# hook's timings are comparable with a focus run's.
ci_single_leg_threads() {
    echo $(( $(nproc) / 2 ))
}
