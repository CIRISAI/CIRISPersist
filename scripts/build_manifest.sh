#!/usr/bin/env bash
# build_manifest.sh — sign, check and register persist's CanonicalBuild v2
# manifests. The one copy of that logic: ci.yml's tag-gated `build-manifest`
# job and .github/workflows/reregister-manifests.yml (CIRISPersist#1029) both
# call it.
#
# Five targets per version: `python-source-tree` (a hash over
# python/ciris_persist) and one wheel per platform. The wheels come from
# directories named like ci.yml's artifacts, `<wheels>/ciris_persist-wheel-<label>/`.
#
#   build_manifest.sh install
#       ciris-build-sign v2.1.5 (prebuilt, CIRISVerify release) into /usr/local/bin.
#   build_manifest.sh check --version V --wheels DIR --out DIR [--targets "T..."] [--tree-root DIR]
#       Writes nothing to the registry. Per target, prints the registered
#       binary_hash beside the local one and MATCH / MISMATCH / NOROW / ERROR:
#       a wheel's sha256 (selected by version, identity checked), or the tree
#       hash recomputed from --tree-root exactly as `sign` computes it (with a
#       throwaway keypair; the hash does not depend on the key). Writes
#       DIR/check.tsv and DIR/mismatch.txt. Exit 1 when any target is ERROR.
#   build_manifest.sh fetch-reuse --version V --out DIR [--targets "T..."]
#       Fills a --reuse directory from the registry when the tag run's
#       build-manifest artifact has expired: each target's signed manifest
#       verbatim (GET /v1/verify/build-manifest serves the posted bytes), and
#       the PersistExtras out of a binary manifest's `extras` (re-signing with
#       it reproduces the registered manifest_hash).
#   build_manifest.sh sign --version V --wheels DIR --out DIR [--extras FILE]
#                          [--source-tree] [--tree-root DIR] [--targets "T..."] [--reuse DIR]
#       --source-tree  sign `python-source-tree` (also: name it in --targets).
#       --tree-root    the `python/` directory to hash (default: python/ here).
#       --targets      re-sign only these targets (default: the four wheels,
#                      plus the tree with --source-tree). A named wheel target
#                      with no wheel is an error; unnamed, a warning and a
#                      skip (the tag job's posture).
#       --reuse DIR    targets NOT named are taken from DIR's signed manifests
#                      and re-posted unchanged, after asserting each one's
#                      binary_hash: a wheel's sha256, or the tree hash of
#                      --tree-root when given. Needed because `register`
#                      writes ONE binary_manifests map per (project, version):
#                      re-registering some targets alone would drop the rest.
#       Everything signed passes scripts/bits_changed.sh checks 1-4 first.
#   build_manifest.sh preflight --out DIR
#       the registry trust-root gate (scripts/preflight_trust_root.py).
#   build_manifest.sh register --version V --commit SHA --out DIR [--notes TEXT] [--dry-run]
#       `ciris-build-sign register` over every manifest in DIR: per target a
#       `builds` row (POST /v1/builds) and a build-manifest row
#       (POST /v1/verify/build-manifest), plus the binary_manifests map.
#       Never the legacy POST /v1/verify/function-manifest.
#   build_manifest.sh roundtrip --version V --out DIR
#       GET /v1/builds/<v>, and per target, must answer 200.
#   build_manifest.sh after-publish --version V --wheels DIR --out DIR
#       scripts/bits_changed.sh --after-publish for every registered target.
#
# Env: CIRIS_BUILD_ED25519_SECRET, CIRIS_BUILD_MLDSA_SECRET (base64 key files;
# sign, register), REGISTRY_ADMIN_TOKEN (register), REGISTRY_URL (default
# https://api.registry.ciris-services-1.ai; bits_changed reads the same host),
# GH_TOKEN (install).
set -euo pipefail
cd "$(dirname "$0")/.."

TOOL_VERSION=v2.1.5
KEY_ID=ciris-persist-build-v1
REGISTRY_URL="${REGISTRY_URL:-https://api.registry.ciris-services-1.ai}"
REGISTRY_URL="${REGISTRY_URL%/}"
export BITS_CHANGED_REGISTRY_BASE="${BITS_CHANGED_REGISTRY_BASE:-$REGISTRY_URL}"
TREE=python-source-tree
# artifact dir (ci.yml's pyo3-wheel matrix label) -> target triple
ARTDIRS=(ciris_persist-wheel-linux-x86_64 ciris_persist-wheel-linux-aarch64
         ciris_persist-wheel-darwin-aarch64 ciris_persist-wheel-windows-x86_64)
declare -A WHEEL_TARGET=(
  [ciris_persist-wheel-linux-x86_64]=x86_64-unknown-linux-gnu
  [ciris_persist-wheel-linux-aarch64]=aarch64-unknown-linux-gnu
  [ciris_persist-wheel-darwin-aarch64]=aarch64-apple-darwin
  # windows signs under the standard windows triple (win7 support dropped)
  [ciris_persist-wheel-windows-x86_64]=x86_64-pc-windows-msvc
)
ALL_TARGETS="$TREE x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc"
# The python-source-tree walk. `sign` and `check` both use THIS array, so the
# check recomputes exactly what the tag job signed. Compiled libs are the
# per-arch manifests' business.
TREE_ARGS=(--tree-include ciris_persist --tree-exempt-dir __pycache__ --tree-exempt-ext pyc pyo so dylib dll)

err() { echo "::error::$*"; exit 1; }
cmd="${1:-}"; shift || true
VERSION=""; WHEELS=""; OUT=""; EXTRAS=""; SOURCE_TREE=0; TARGETS=""; REUSE=""; COMMIT=""; NOTES=""; DRY=0
TREE_ROOT=python/; TREE_ROOT_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --wheels) WHEELS="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --extras) EXTRAS="$2"; shift 2;;
    --source-tree) SOURCE_TREE=1; shift;;
    --tree-root) TREE_ROOT="${2%/}/"; TREE_ROOT_SET=1; shift 2;;
    --targets) TARGETS="$2"; shift 2;;
    --reuse) REUSE="$2"; shift 2;;
    --commit) COMMIT="$2"; shift 2;;
    --notes) NOTES="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
need() { local v; for v in "$@"; do [ -n "${!v}" ] || { echo "$cmd needs --$(echo "$v" | tr '[:upper:]' '[:lower:]')" >&2; exit 2; }; done; }
valid_targets() {
  local t; for t in $1; do
    [[ " $ALL_TARGETS " == *" $t "* ]] || { echo "unknown target: $t (one of: $ALL_TARGETS)" >&2; exit 2; }
  done
}

keys_in() {  # materialise the hybrid keypair; key_wipe removes it
  if [ -z "${CIRIS_BUILD_ED25519_SECRET:-}" ] || [ -z "${CIRIS_BUILD_MLDSA_SECRET:-}" ]; then
    err "Hybrid signing secrets not configured (CIRIS_BUILD_ED25519_SECRET, CIRIS_BUILD_MLDSA_SECRET); see docs/BUILD_SIGNING.md"
  fi
  umask 077
  ED_KEY_PATH=$(mktemp); MLDSA_KEY_PATH=$(mktemp)
  trap key_wipe EXIT
  printf '%s' "$CIRIS_BUILD_ED25519_SECRET" | base64 -d >"$ED_KEY_PATH"
  printf '%s' "$CIRIS_BUILD_MLDSA_SECRET" | base64 -d >"$MLDSA_KEY_PATH"
}
key_wipe() { shred -uz "${ED_KEY_PATH:-}" "${MLDSA_KEY_PATH:-}" 2>/dev/null || rm -f "${ED_KEY_PATH:-}" "${MLDSA_KEY_PATH:-}"; }
named() { [ -z "$TARGETS" ] || [[ " $TARGETS " == *" $1 "* ]]; }
manifest_hash_of() { python3 -I -c 'import json,sys; h=json.load(open(sys.argv[1])).get("binary_hash",""); print(h[7:] if h.startswith("sha256:") else h)' "$1"; }
artdir_of() { local a; for a in "${ARTDIRS[@]}"; do [ "${WHEEL_TARGET[$a]}" = "$1" ] && { echo "$a"; return; }; done; }

# The tree hash of $1, signed with a throwaway keypair: binary_hash for a
# file-tree manifest IS the tree hash, independent of the key.
tree_hash() {
  local k o
  k=$(mktemp -d); o="$k/m.json"
  ciris-build-sign generate-keys --output-dir "$k/keys" >/dev/null 2>&1
  ciris-build-sign sign --primitive persist --build-id "$VERSION" --target "$TREE" \
    --tree "$1" "${TREE_ARGS[@]}" --binary-version "$VERSION" \
    --ed25519-seed "$k/keys/ed25519.seed" --mldsa-secret "$k/keys/mldsa65.secret" \
    --key-id check-only --output "$o" >/dev/null 2>&1 || { rm -rf "$k"; return 1; }
  manifest_hash_of "$o"; rm -rf "$k"
}

# GET with bounded retries on 429 / 5xx / no connection; prints the HTTP code.
reg_get() {
  local i=0 code wait hdr; hdr=$(mktemp)
  while :; do
    code="$(curl -sS -o "$2" -D "$hdr" -w '%{http_code}' --max-time 30 "$1" 2>/dev/null)" || code="${code:-000}"
    case "$code" in 429|5??|000) ;; *) rm -f "$hdr"; echo "$code"; return;; esac
    [ "$i" -lt "${BUILD_MANIFEST_RETRIES:-4}" ] || { rm -f "$hdr"; echo "$code"; return; }
    i=$((i + 1))
    wait="$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' "$hdr" | head -1)"
    [ -n "$wait" ] || wait=$((i * 5)); [ "$wait" -le 60 ] || wait=60
    echo "  registry $code on $1; retry $i in ${wait}s" >&2
    sleep "$wait"
  done
}

case "$cmd" in
install)
  cd "${RUNNER_TEMP:-$(mktemp -d)}"
  # retry the download: GitHub API 5xx / network blips (CIRISVerify v2.1.1 pattern)
  for attempt in 1 2 3; do
    gh release download "$TOOL_VERSION" --repo CIRISAI/CIRISVerify --clobber \
      --pattern "ciris-verify-$TOOL_VERSION-build-tool-linux-x86_64.tar.gz" && break
    [ "$attempt" = 3 ] && err "gh release download failed 3 times"
    echo "::warning::gh release download attempt $attempt failed; retrying in $((attempt * 5))s"
    sleep $((attempt * 5))
  done
  tar -xzf "ciris-verify-$TOOL_VERSION-build-tool-linux-x86_64.tar.gz"
  sudo install -m755 build-tool/ciris-build-sign /usr/local/bin/ciris-build-sign
  sudo install -m755 build-tool/ciris-build-verify /usr/local/bin/ciris-build-verify
  ciris-build-sign --version
  ldd "$(command -v ciris-build-sign)" || true
  ;;

check)
  need VERSION WHEELS OUT
  [ -n "$TARGETS" ] || TARGETS="$ALL_TARGETS"
  valid_targets "$TARGETS"
  mkdir -p "$OUT"; : >"$OUT/mismatch.txt"
  printf 'verdict\tversion\ttarget\tregistry\tlocal\tsource\n' >"$OUT/check.tsv"
  errors=0; o=$(mktemp)
  for T in $TARGETS; do
    if [ "$T" = "$TREE" ]; then
      src="tag tree ${TREE_ROOT}"
      if ! h="$(tree_hash "$TREE_ROOT")" || [ -z "$h" ]; then
        verdict=ERROR; reg='?'; loc='?'; echo "could not hash $TREE_ROOT" >"$o"
      else
        loc="$h"
        scripts/bits_changed.sh --after-publish "$VERSION" "$TREE" --sha256 "$h" >"$o" 2>&1 && rc=0 || rc=$?
      fi
    else
      A="$(artdir_of "$T")"
      src="$(cat "$WHEELS/$A/SOURCE" 2>/dev/null || echo "$WHEELS/$A")"
      scripts/bits_changed.sh --after-publish "$VERSION" "$T" "$WHEELS/$A" >"$o" 2>&1 && rc=0 || rc=$?
      loc="$(sed -n 's/^ *sha256 \([0-9a-f]\{64\}\)$/\1/p' "$o" | head -1)"; loc="${loc:-?}"
    fi
    if [ "${verdict:-}" != ERROR ]; then
      case "$rc" in
        0) verdict=MATCH; reg="$loc";;
        15) if grep -q 'no registered row' "$o"; then verdict=NOROW; reg=-
            else verdict=MISMATCH; reg="$(sed -n "s/.*registered binary_hash for [^ ]* is '\([0-9a-f]*\)'.*/\1/p" "$o" | head -1)"; fi;;
        *) verdict=ERROR; reg='?';;
      esac
    fi
    printf '%-8s %s %-26s registry %s  local %s  (%s)\n' "$verdict" "$VERSION" "$T" "${reg:0:16}" "${loc:0:16}" "$src"
    [ "$verdict" = ERROR ] && { sed 's/^/           | /' "$o"; errors=$((errors + 1)); }
    [ "$verdict" = MISMATCH ] && echo "$T" >>"$OUT/mismatch.txt"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$verdict" "$VERSION" "$T" "$reg" "$loc" "$src" >>"$OUT/check.tsv"
    unset verdict
  done
  rm -f "$o"
  {
    echo "### $VERSION"; echo; echo "| verdict | target | registry | local | source |"; echo "|---|---|---|---|---|"
    tail -n +2 "$OUT/check.tsv" | while IFS=$'\t' read -r v _ t r l s; do echo "| $v | \`$t\` | \`${r:0:16}\` | \`${l:0:16}\` | $s |"; done
  } >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
  [ "$errors" -eq 0 ] || err "$errors target(s) could not be checked for $VERSION"
  ;;

fetch-reuse)
  need VERSION OUT
  [ -n "$TARGETS" ] || TARGETS="$ALL_TARGETS"
  valid_targets "$TARGETS"
  mkdir -p "$OUT"
  for T in $TARGETS; do
    code="$(reg_get "$REGISTRY_URL/v1/verify/build-manifest/ciris-persist/$VERSION/$T" "$OUT/manifest-$T.json")"
    [ "$code" = 200 ] || err "GET build-manifest $VERSION/$T returned HTTP $code"
    echo "fetched $T (registry verbatim body, binary_hash $(manifest_hash_of "$OUT/manifest-$T.json" | cut -c1-16)…)"
  done
  for T in $TARGETS; do
    [ "$T" = "$TREE" ] && continue
    python3 -I -c 'import json,sys; e=json.load(open(sys.argv[1])).get("extras"); assert isinstance(e, dict) and e, "no extras"; json.dump(e, open(sys.argv[2], "w"))' \
      "$OUT/manifest-$T.json" "$OUT/persist-extras-$VERSION.json" && { echo "PersistExtras taken from $T's registered manifest"; break; }
  done
  [ -s "$OUT/persist-extras-$VERSION.json" ] || err "no registered binary manifest of $VERSION carries extras"
  echo registry >"$OUT/SOURCE"
  ;;

sign)
  need VERSION WHEELS OUT
  [ -n "$EXTRAS" ] || [ -n "$REUSE" ] || { echo "sign needs --extras or --reuse" >&2; exit 2; }
  valid_targets "$TARGETS"
  resign_tree=$SOURCE_TREE
  [[ " $TARGETS " == *" $TREE "* ]] && resign_tree=1
  if [ -z "$EXTRAS" ]; then EXTRAS="$REUSE/persist-extras-$VERSION.json"; fi
  [ -s "$EXTRAS" ] || err "PersistExtras $EXTRAS missing or empty"
  mkdir -p "$OUT"
  keys_in
  if [ "$resign_tree" = 1 ]; then
    # python/ciris_persist's .py + .pyi: what iOS / Android agent rebuilds verify against.
    ciris-build-sign sign \
      --primitive persist --build-id "$VERSION" --target "$TREE" \
      --tree "$TREE_ROOT" "${TREE_ARGS[@]}" --binary-version "$VERSION" \
      --ed25519-seed "$ED_KEY_PATH" --mldsa-secret "$MLDSA_KEY_PATH" --key-id "$KEY_ID" \
      --output "$OUT/manifest-$TREE.json"
    # #1029 — checks 3-4 for the tree: an unchanged hash is allowed only when
    # git shows python/ciris_persist did not change since the previous tag.
    scripts/bits_changed.sh "$VERSION" "$TREE" --sha256 "$(manifest_hash_of "$OUT/manifest-$TREE.json")" \
      || err "bits_changed.sh refused $TREE (exit $?); not registering"
    echo "✓ signed $TREE from $TREE_ROOT"
  else
    [ -s "$REUSE/manifest-$TREE.json" ] || err "$TREE not re-signed and no $REUSE/manifest-$TREE.json to reuse"
    if [ "$TREE_ROOT_SET" = 1 ]; then
      have="$(manifest_hash_of "$REUSE/manifest-$TREE.json")"; want="$(tree_hash "$TREE_ROOT")"
      [ "$have" = "$want" ] || err "reused manifest for $TREE signs $have, the tree at $TREE_ROOT hashes to $want: that row is wrong too; add $TREE to --targets"
    fi
    cp "$REUSE/manifest-$TREE.json" "$OUT/"
    echo "✓ reused $TREE (unchanged)"
  fi
  # TARGETS naming only the tree re-signs no wheel.
  WHEELS_NAMED="$(for t in $TARGETS; do [ "$t" = "$TREE" ] || echo "$t"; done | tr '\n' ' ')"
  [ -n "$TARGETS" ] && [ -z "${WHEELS_NAMED// /}" ] && WHEELS_NAMED=NONE
  : >"$OUT/signed-binary-targets.txt"
  for ARTDIR in "${ARTDIRS[@]}"; do
    TARGET="${WHEEL_TARGET[$ARTDIR]}"
    is_named=1
    if [ -n "$TARGETS" ] && [[ " $WHEELS_NAMED " != *" $TARGET "* ]]; then is_named=0; fi
    # THIS version's wheel, exactly one (#1028: `*.whl | head -1` signed a
    # stale 29.0.0 wheel for v53.1.8).
    shopt -s nullglob
    CANDIDATES=("$WHEELS/$ARTDIR/ciris_persist-$VERSION-"*.whl)
    shopt -u nullglob
    if [ "${#CANDIDATES[@]}" -eq 0 ]; then
      if [ -n "$TARGETS" ] && [ "$is_named" = 1 ]; then err "no $VERSION wheel for named target $TARGET in $WHEELS/$ARTDIR"; fi
      if [ -n "$REUSE" ] && [ -s "$REUSE/manifest-$TARGET.json" ]; then err "no $VERSION wheel for $TARGET to check the reused manifest against"; fi
      echo "::warning::No $VERSION wheel found for $TARGET (artifact $ARTDIR); skipping"
      continue
    fi
    [ "${#CANDIDATES[@]}" -eq 1 ] || err "${#CANDIDATES[@]} $VERSION wheels in $ARTDIR: ${CANDIDATES[*]}"
    WHEEL="${CANDIDATES[0]}"
    if [ "$is_named" = 0 ]; then
      [ -n "$REUSE" ] || continue
      [ -s "$REUSE/manifest-$TARGET.json" ] || { echo "::warning::$TARGET not named and not in $REUSE; not registered"; continue; }
      have="$(manifest_hash_of "$REUSE/manifest-$TARGET.json")"; want="$(sha256sum "$WHEEL" | cut -d' ' -f1)"
      [ "$have" = "$want" ] || err "reused manifest for $TARGET signs $have, its $VERSION wheel is $want: that row is wrong too; add $TARGET to --targets"
      cp "$REUSE/manifest-$TARGET.json" "$OUT/"
      echo "$TARGET" >>"$OUT/signed-binary-targets.txt"
      echo "✓ reused $TARGET (binary_hash == sha256 of $(basename "$WHEEL"))"
      continue
    fi
    # #1029 — did the bits change? One wheel for the target, its own METADATA
    # Version and WHEEL Tag, not the previous release's registered hash, not a
    # known stale hash. Refuse to sign otherwise.
    scripts/bits_changed.sh "$VERSION" "$TARGET" "$WHEELS/$ARTDIR" \
      || err "bits_changed.sh refused $TARGET (exit $?); not signing"
    ciris-build-sign sign \
      --primitive persist --build-id "$VERSION" --target "$TARGET" \
      --binary "$WHEEL" --binary-version "$VERSION" --extras "$EXTRAS" \
      --ed25519-seed "$ED_KEY_PATH" --mldsa-secret "$MLDSA_KEY_PATH" --key-id "$KEY_ID" \
      --output "$OUT/manifest-$TARGET.json"
    echo "$TARGET" >>"$OUT/signed-binary-targets.txt"
    echo "✓ signed $TARGET: $(basename "$WHEEL")"
  done
  for t in $TARGETS; do
    [ "$t" = "$TREE" ] && continue
    grep -qx "$t" "$OUT/signed-binary-targets.txt" || err "named target $t was not signed"
  done
  echo "Manifests:"; ls -la "$OUT"/manifest-*.json
  ;;

preflight)
  need OUT
  # CIRISPersist#809 / #926 — a GATE. The self-test runs first, every time,
  # so a guard that quietly stopped refusing reds instead of passing.
  python3 scripts/preflight_trust_root.py --self-test
  echo "Registry trust-root snapshot for $REGISTRY_URL:"
  curl -sf "$REGISTRY_URL/v1/steward-key" | tee "$OUT/steward-key.json" | python3 -m json.tool
  python3 scripts/preflight_trust_root.py "$OUT/steward-key.json" >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
  ;;

register)
  need VERSION COMMIT OUT
  if [ "$DRY" != 1 ]; then
    [ -n "${REGISTRY_ADMIN_TOKEN:-}" ] || err "REGISTRY_ADMIN_TOKEN repo secret not configured"
  fi
  keys_in
  TARGET_ARGS=(--target "$TREE:$OUT/manifest-$TREE.json")
  while IFS= read -r T; do
    [ -z "$T" ] && continue
    TARGET_ARGS+=(--target "$T:$OUT/manifest-$T.json")
  done <"$OUT/signed-binary-targets.txt"
  [ -n "$NOTES" ] || NOTES="CIRIS federation persist substrate; CanonicalBuild v2 multi-target via ciris-build-sign $TOOL_VERSION (CIRISPersist#42). Targets: python-source-tree + per-wheel binary manifests."
  echo "Targets to register:"; printf '  %s\n' "${TARGET_ARGS[@]}"
  DRY_ARGS=(); [ "$DRY" = 1 ] && DRY_ARGS=(--dry-run)
  ciris-build-sign register "${DRY_ARGS[@]}" \
    --registry-url "$REGISTRY_URL" --project ciris-persist \
    --binary-version "$VERSION" --build-id "$COMMIT" \
    --source-repo "https://github.com/CIRISAI/CIRISPersist" --source-commit "$COMMIT" \
    --notes "$NOTES" \
    --ed25519-seed "$ED_KEY_PATH" --mldsa-secret "$MLDSA_KEY_PATH" --key-id "$KEY_ID" \
    "${TARGET_ARGS[@]}"
  if [ "$DRY" = 1 ]; then echo "register --dry-run: nothing posted"; else echo "✓ Multi-target build registered with CIRISRegistry"; fi
  ;;

roundtrip)
  need VERSION OUT
  echo "GET $REGISTRY_URL/v1/builds/$VERSION?project=ciris-persist"
  code=$(reg_get "$REGISTRY_URL/v1/builds/$VERSION?project=ciris-persist" "$OUT/round-trip-build.json")
  [ "$code" = 200 ] || { cat "$OUT/round-trip-build.json"; err "GET /v1/builds returned $code: registration did not land"; }
  python3 -m json.tool <"$OUT/round-trip-build.json"
  TARGETS_RT=("$TREE")
  while IFS= read -r T; do [ -n "$T" ] && TARGETS_RT+=("$T"); done <"$OUT/signed-binary-targets.txt"
  ALL_OK=1
  for T in "${TARGETS_RT[@]}"; do
    code=$(reg_get "$REGISTRY_URL/v1/builds/$VERSION?project=ciris-persist&target=$T" "$OUT/round-trip-$T.json")
    echo "  $T: HTTP $code; local manifest sha256 $(sha256sum "$OUT/manifest-$T.json" | cut -d' ' -f1)"
    [ "$code" = 200 ] || { echo "::error::Per-target GET for $T returned $code"; ALL_OK=0; }
  done
  [ "$ALL_OK" = 1 ] || err "One or more per-target round-trip GETs failed"
  {
    echo "## Registry round-trip"; echo
    echo "- registry: \`$REGISTRY_URL\`"; echo "- version: \`$VERSION\`"
    echo "- targets verified:"; for T in "${TARGETS_RT[@]}"; do echo "  - \`$T\`"; done
  } >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
  ;;

after-publish)
  need VERSION WHEELS OUT
  scripts/bits_changed.sh --after-publish "$VERSION" "$TREE" --sha256 "$(manifest_hash_of "$OUT/manifest-$TREE.json")" \
    || err "registered row for $VERSION/$TREE does not carry the signed tree hash (bits_changed.sh exit $?)"
  while IFS= read -r T; do
    [ -z "$T" ] && continue
    scripts/bits_changed.sh --after-publish "$VERSION" "$T" "$WHEELS/$(artdir_of "$T")" \
      || err "registered row for $VERSION/$T does not carry its wheel (bits_changed.sh exit $?)"
  done <"$OUT/signed-binary-targets.txt"
  ;;

*) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^set -euo/d' >&2; exit 2;;
esac
