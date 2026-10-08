#!/usr/bin/env bash
# build_manifest.sh — sign and register persist's CanonicalBuild v2 manifests.
# The one copy of that logic: ci.yml's tag-gated `build-manifest` job and
# .github/workflows/reregister-manifests.yml (CIRISPersist#1029) both call it.
#
#   build_manifest.sh install
#       ciris-build-sign v2.1.5 (prebuilt, CIRISVerify release) into /usr/local/bin.
#   build_manifest.sh sign --version V --wheels DIR --out DIR [--extras FILE]
#                          [--source-tree] [--targets "T..."] [--reuse DIR]
#       --source-tree  sign `python-source-tree` from python/ciris_persist.
#       --targets      re-sign only these binary targets (default: all four).
#                      A named target with no wheel is an error; unnamed, a
#                      warning and a skip (the tag job's posture).
#       --reuse DIR    targets NOT named are taken from DIR's already-signed
#                      manifests (the tag run's build-manifest artifact) and
#                      re-posted unchanged, after asserting each one's
#                      binary_hash is sha256 of that target's wheel. Needed
#                      because `register` writes ONE binary_manifests row per
#                      (project, version) mapping every target: re-registering
#                      two targets alone would drop the other two.
#       Every wheel signed passes scripts/bits_changed.sh checks 1-4 first.
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
#       scripts/bits_changed.sh --after-publish for every signed binary target.
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
export BITS_CHANGED_REGISTRY_BASE="${BITS_CHANGED_REGISTRY_BASE:-$REGISTRY_URL}"
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

err() { echo "::error::$*"; exit 1; }
cmd="${1:-}"; shift || true
VERSION=""; WHEELS=""; OUT=""; EXTRAS=""; SOURCE_TREE=0; TARGETS=""; REUSE=""; COMMIT=""; NOTES=""; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --wheels) WHEELS="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --extras) EXTRAS="$2"; shift 2;;
    --source-tree) SOURCE_TREE=1; shift;;
    --targets) TARGETS="$2"; shift 2;;
    --reuse) REUSE="$2"; shift 2;;
    --commit) COMMIT="$2"; shift 2;;
    --notes) NOTES="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
need() { local v; for v in "$@"; do [ -n "${!v}" ] || { echo "$cmd needs --$(echo "$v" | tr '[:upper:]' '[:lower:]')" >&2; exit 2; }; done; }

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

sign)
  need VERSION WHEELS OUT
  [ -n "$EXTRAS" ] || [ -n "$REUSE" ] || { echo "sign needs --extras or --reuse" >&2; exit 2; }
  if [ -n "$TARGETS" ]; then
    for t in $TARGETS; do
      ok=0; for a in "${ARTDIRS[@]}"; do [ "${WHEEL_TARGET[$a]}" = "$t" ] && ok=1; done
      [ "$ok" = 1 ] || { echo "unknown target in --targets: $t" >&2; exit 2; }
    done
  fi
  if [ -z "$EXTRAS" ]; then EXTRAS="$REUSE/persist-extras-$VERSION.json"; fi
  [ -s "$EXTRAS" ] || err "PersistExtras $EXTRAS missing or empty"
  mkdir -p "$OUT"
  keys_in
  if [ "$SOURCE_TREE" = 1 ]; then
    # python/ciris_persist's .py + .pyi: what iOS / Android agent rebuilds
    # verify against. Compiled libs are the per-arch manifests' business.
    ciris-build-sign sign \
      --primitive persist --build-id "$VERSION" --target python-source-tree \
      --tree python/ --tree-include ciris_persist \
      --tree-exempt-dir __pycache__ --tree-exempt-ext pyc pyo so dylib dll \
      --binary-version "$VERSION" \
      --ed25519-seed "$ED_KEY_PATH" --mldsa-secret "$MLDSA_KEY_PATH" --key-id "$KEY_ID" \
      --output "$OUT/manifest-python-source-tree.json"
  else
    [ -s "$REUSE/manifest-python-source-tree.json" ] || err "no --source-tree and no $REUSE/manifest-python-source-tree.json to reuse"
    cp "$REUSE/manifest-python-source-tree.json" "$OUT/"
    echo "reused python-source-tree (unchanged)"
  fi
  : >"$OUT/signed-binary-targets.txt"
  for ARTDIR in "${ARTDIRS[@]}"; do
    TARGET="${WHEEL_TARGET[$ARTDIR]}"
    # THIS version's wheel, exactly one (#1028: `*.whl | head -1` signed a
    # stale 29.0.0 wheel for v53.1.8).
    shopt -s nullglob
    CANDIDATES=("$WHEELS/$ARTDIR/ciris_persist-$VERSION-"*.whl)
    shopt -u nullglob
    if [ "${#CANDIDATES[@]}" -eq 0 ]; then
      if [ -n "$TARGETS" ] && named "$TARGET"; then err "no $VERSION wheel for named target $TARGET in $WHEELS/$ARTDIR"; fi
      if [ -n "$REUSE" ] && [ -s "$REUSE/manifest-$TARGET.json" ]; then err "no $VERSION wheel for $TARGET to check the reused manifest against"; fi
      echo "::warning::No $VERSION wheel found for $TARGET (artifact $ARTDIR); skipping"
      continue
    fi
    [ "${#CANDIDATES[@]}" -eq 1 ] || err "${#CANDIDATES[@]} $VERSION wheels in $ARTDIR: ${CANDIDATES[*]}"
    WHEEL="${CANDIDATES[0]}"
    if ! named "$TARGET"; then
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
  if [ -n "$TARGETS" ]; then
    for t in $TARGETS; do grep -qx "$t" "$OUT/signed-binary-targets.txt" || err "named target $t was not signed"; done
  fi
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
  TARGET_ARGS=(--target "python-source-tree:$OUT/manifest-python-source-tree.json")
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
  code=$(curl -sS -o "$OUT/round-trip-build.json" -w '%{http_code}' "$REGISTRY_URL/v1/builds/$VERSION?project=ciris-persist")
  [ "$code" = 200 ] || { cat "$OUT/round-trip-build.json"; err "GET /v1/builds returned $code: registration did not land"; }
  python3 -m json.tool <"$OUT/round-trip-build.json"
  TARGETS_RT=(python-source-tree)
  while IFS= read -r T; do [ -n "$T" ] && TARGETS_RT+=("$T"); done <"$OUT/signed-binary-targets.txt"
  ALL_OK=1
  for T in "${TARGETS_RT[@]}"; do
    code=$(curl -sS -o "$OUT/round-trip-$T.json" -w '%{http_code}' "$REGISTRY_URL/v1/builds/$VERSION?project=ciris-persist&target=$T")
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
  while IFS= read -r T; do
    [ -z "$T" ] && continue
    for a in "${ARTDIRS[@]}"; do [ "${WHEEL_TARGET[$a]}" = "$T" ] && ARTDIR="$a"; done
    scripts/bits_changed.sh --after-publish "$VERSION" "$T" "$WHEELS/$ARTDIR" \
      || err "registered row for $VERSION/$T does not carry its wheel (bits_changed.sh exit $?)"
  done <"$OUT/signed-binary-targets.txt"
  ;;

*) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^set -euo/d' >&2; exit 2;;
esac
