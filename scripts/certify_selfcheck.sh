#!/usr/bin/env bash
# certify_selfcheck.sh — witnesses for certify.sh's verdict table and
# prune_target.py (CIRISPersist#1012). Builds nothing; runs in seconds.
#
# Each case writes a SYNTHETIC log directory (every key green, then one
# perturbation), runs `certify.sh verdict` on it, and asserts the row and the
# exit code. The perturbations are the failures #1012 measured: a leg killed
# by SIGKILL (137), an `.rc` written empty by ENOSPC, a red leg whose log says
# `No space left on device`, a leg the per-leg disk floor skipped, a leg that
# never ran — plus a genuine RED, which must still win over all of them.
#
# Before #1012 an empty `.rc` fell through every integer test into the GREEN
# branch (`green rest exit= s`). Case `empty-rc` is that bug; it fails against
# the old table.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

WORK="$(mktemp -d "${TMPDIR:-/tmp}/certify-selfcheck.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
KEYS="$(scripts/certify.sh keys)" || { echo "✗ certify.sh keys failed" >&2; exit 1; }
fails=0

green_dir() {  # $1 = dir
    rm -rf "$1"; mkdir -p "$1"
    for k in $KEYS; do
        echo 0 >"$1/$k.rc"; echo 10 >"$1/$k.secs"
        echo "     Summary [  10.000s] 5 tests run: 5 passed, 0 skipped" >"$1/$k.log"
    done
}

# expect <case> <dir> <exit> <grep -E pattern that must match> [pattern that must NOT match]
expect() {
    local name="$1" dir="$2" want="$3" must="$4" mustnot="${5:-}" out rc
    out="$(CERTIFY_LOG_DIR="$dir" scripts/certify.sh verdict 2>&1)"; rc=$?
    local ok=1
    [ "$rc" -eq "$want" ] || ok=0
    grep -qE "$must" <<<"$out" || ok=0
    if [ -n "$mustnot" ] && grep -qE "$mustnot" <<<"$out"; then ok=0; fi
    if [ "$ok" -eq 1 ]; then
        printf '  ok    %-16s exit=%s  %s\n' "$name" "$rc" "$(grep -E "$must" <<<"$out" | head -1 | sed 's/^ *//')"
    else
        printf '  FAIL  %-16s exit=%s (want %s); must match /%s/%s\n' "$name" "$rc" "$want" "$must" \
            "${mustnot:+, must not match /$mustnot/}"
        sed 's/^/        | /' <<<"$out" | head -60
        fails=$(( fails + 1 ))
    fi
}

echo "=== certify.sh verdict table ==="
D="$WORK/logs"

green_dir "$D"
expect all-green "$D" 0 '^EVERY CI LEG GREEN BY EXIT CODE'

green_dir "$D"; echo 137 >"$D/core.rc"; echo 412 >"$D/core.secs"
expect sigkill-137 "$D" 3 'KILLED\(KILL\) +core +exit=137 +412s' 'green +core '
expect sigkill-infra "$D" 3 'INFRA: 0 legs skipped for disk, 1 killed by a signal'

green_dir "$D"; echo 143 >"$D/secrets.rc"
expect sigterm-143 "$D" 3 'KILLED\(TERM\) +secrets +exit=143'

green_dir "$D"; : >"$D/rest.rc"; : >"$D/rest.secs"
expect empty-rc "$D" 3 'UNKNOWN +rest +exit=\? ' 'green +rest '

green_dir "$D"; : >"$D/rest.rc"; echo "error: No space left on device (os error 28)" >>"$D/rest.log"
expect empty-rc-enospc "$D" 3 'DISK +rest .*ENOSPC' 'green +rest '
expect enospc-infra "$D" 3 'INFRA: 1 legs skipped for disk'

green_dir "$D"; echo 101 >"$D/cirisgraph.rc"; echo "No space left on device" >>"$D/cirisgraph.log"
expect red-enospc "$D" 3 'DISK +cirisgraph +exit=101 .*ENOSPC' 'RED +cirisgraph'

green_dir "$D"; rm -f "$D/telemetry.rc"; echo 19 >"$D/telemetry.disk"
expect disk-floor "$D" 3 'DISK +telemetry +skipped: 19G free after prune'

green_dir "$D"; rm -f "$D/cirisnode.rc"
expect notrun "$D" 3 'NOTRUN +cirisnode'

green_dir "$D"; echo 100 >"$D/cirisaudit.rc"; echo 137 >"$D/core.rc"
expect red-beats-infra "$D" 1 'RED +cirisaudit +exit=100' '^EVERY'
expect red-verdict "$D" 1 'NOT CERTIFIED — 1 leg\(s\) RED'

green_dir "$D"; printf ' \n' >"$D/fmt.rc"
expect blank-rc "$D" 3 'UNKNOWN +fmt' 'green +fmt '

echo
echo "=== prune_target.py ==="
T="$WORK/target"; DEPS="$T/debug/deps"; INC="$T/debug/incremental"
mkdir -p "$DEPS" "$INC"; : >"$T/CACHEDIR.TAG"
mk() { head -c "$2" /dev/zero >"$DEPS/$1"; touch -d "@$3" "$DEPS/$1"; }
mk libfoo-aaaaaaaaaaaaaaaa.rlib 1000 1000; mk foo-aaaaaaaaaaaaaaaa.d 10 1000      # old foo lib
mk libfoo-bbbbbbbbbbbbbbbb.rlib 1000 2000; mk foo-bbbbbbbbbbbbbbbb.d 10 2000      # new foo lib
mk foo-cccccccccccccccc 5000 1500                                                  # foo TEST BINARY: own kind, kept
mk liblibc-dddddddddddddddd.rlib 100 1000; mk libc-dddddddddddddddd.d 10 1000      # crate `libc`, only gen
mkdir -p "$INC/foo-1111111111111111" "$INC/foo-2222222222222222"
touch -d @1000 "$INC/foo-1111111111111111"; touch -d @2000 "$INC/foo-2222222222222222"

out="$(python3 scripts/prune_target.py --target "$T" --dry-run)"
[ -f "$DEPS/libfoo-aaaaaaaaaaaaaaaa.rlib" ] && ok=1 || ok=0
[ "$ok" -eq 1 ] && echo "  ok    dry-run          deleted nothing" || { echo "  FAIL  dry-run deleted files"; fails=$(( fails + 1 )); }

out="$(python3 scripts/prune_target.py --target "$T")"
survivors="$(cd "$DEPS" && ls | sort | tr '\n' ' ')"; inc="$(ls "$INC" | tr '\n' ' ')"
want_s="foo-bbbbbbbbbbbbbbbb.d foo-cccccccccccccccc libc-dddddddddddddddd.d libfoo-bbbbbbbbbbbbbbbb.rlib liblibc-dddddddddddddddd.rlib "
if [ "$survivors" = "$want_s" ] && [ "$inc" = "foo-2222222222222222 " ] && grep -q '^prune_target: 3 superseded artifacts' <<<"$out"; then
    echo "  ok    newest-per-name  $(tail -1 <<<"$out")"
else
    echo "  FAIL  newest-per-name: survivors [$survivors] incremental [$inc]"; echo "        $out"
    fails=$(( fails + 1 ))
fi
python3 scripts/prune_target.py --target "$WORK" >/dev/null 2>&1
[ $? -eq 2 ] && echo "  ok    not-a-target     refused (no CACHEDIR.TAG)" \
    || { echo "  FAIL  pruned a directory with no CACHEDIR.TAG"; fails=$(( fails + 1 )); }

echo
if [ "$fails" -ne 0 ]; then echo "✗ $fails selfcheck case(s) failed"; exit 1; fi
echo "✓ certify selfcheck green"
