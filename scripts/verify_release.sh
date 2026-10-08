#!/usr/bin/env bash
# verify_release.sh — check a release's GitHub artifact attestations
# (CIRISPersist#1028). What tag CI's `attest` job signs, this reads back:
#
#   scripts/verify_release.sh v<version>          # or <version>
#
# 1. downloads the three release tarballs (`ciris-persist-v<ver>-*.tar.gz`);
# 2. downloads the four abi3 desktop wheels from the tag's CI run (they are run
#    artifacts, not release assets; GitHub expires artifacts after 90 days, so
#    VERIFY_SKIP_WHEELS=1 skips them for an older release, and says so);
# 3. fetches `evidence/cc_impl.tsv` at the tag;
# 4. runs `gh attestation verify` on each, bound to this repo, to ci.yml as the
#    signing workflow and to `refs/tags/v<ver>` as the source ref, so an
#    attestation from a branch or PR run does not count;
# 5. prints the cc-conformance predicate and checks its crate_version and
#    merge_sha against the tag.
#
# Needs a gh with `gh attestation` (2.49+). GH=/path/to/gh selects one.
#
# Exit codes: 0 every subject verified · 1 a verification or predicate check
# failed (each is listed) · 2 usage, or gh lacks `gh attestation` · 3 a
# download failed (nothing was judged).
set -uo pipefail
v="${1:?usage: verify_release.sh v<version>}"; v="${v#v}"
case "$v" in *[!0-9.]*|"") echo "not a version: $1"; exit 2;; esac
tag="v$v"
GH="${GH:-gh}"
repo="${VERIFY_REPO:-CIRISAI/CIRISPersist}"
workflow="$repo/.github/workflows/ci.yml"
cc_type="https://ciris.ai/attestation/cc-conformance/v1"

if ! "$GH" attestation verify --help >/dev/null 2>&1; then
  echo "gh at '$(command -v "$GH" || echo "$GH")' has no 'attestation' command ($("$GH" --version 2>/dev/null | head -1)); need gh 2.49+ — set GH=/path/to/newer/gh"
  exit 2
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

"$GH" release download "$tag" -R "$repo" -p "ciris-persist-$tag-*.tar.gz" -D "$tmp/release" \
  || { echo "DOWNLOAD FAILED: release assets of $tag"; exit 3; }
n=$(find "$tmp/release" -name '*.tar.gz' | wc -l)
[ "$n" -eq 3 ] || { echo "DOWNLOAD FAILED: expected 3 release tarballs for $tag, found $n"; exit 3; }

if [ "${VERIFY_SKIP_WHEELS:-0}" = 1 ]; then
  echo "SKIP  desktop wheels (VERIFY_SKIP_WHEELS=1) — their provenance is NOT checked"
else
  rid=$("$GH" run list -R "$repo" --branch "$tag" --event push --workflow CI \
          --json databaseId,conclusion --jq '[.[] | select(.conclusion == "success")][0].databaseId // empty')
  [ -n "$rid" ] || { echo "DOWNLOAD FAILED: no successful CI push run for $tag"; exit 3; }
  "$GH" run download "$rid" -R "$repo" -p 'ciris_persist-wheel-*' -D "$tmp/wheels" \
    || { echo "DOWNLOAD FAILED: wheel artifacts of run $rid (expired after 90 days? VERIFY_SKIP_WHEELS=1)"; exit 3; }
  # Only this version's wheels: through v53.1.8 the artifacts also carried
  # stale wheels restored from the build cache.
  find "$tmp/wheels" -name '*.whl' ! -name "ciris_persist-$v-*.whl" -delete
  n=$(find "$tmp/wheels" -name '*.whl' | wc -l)
  [ "$n" -eq 4 ] || { echo "DOWNLOAD FAILED: expected 4 ciris_persist-$v wheels in run $rid, found $n"; exit 3; }
fi

"$GH" api -H 'Accept: application/vnd.github.raw' "repos/$repo/contents/evidence/cc_impl.tsv?ref=$tag" \
  > "$tmp/cc_impl.tsv" || { echo "DOWNLOAD FAILED: evidence/cc_impl.tsv at $tag"; exit 3; }
[ -s "$tmp/cc_impl.tsv" ] || { echo "DOWNLOAD FAILED: evidence/cc_impl.tsv at $tag is empty"; exit 3; }

bind=(-R "$repo" --signer-workflow "$workflow" --source-ref "refs/tags/$tag")
fails=0
while IFS= read -r f; do
  if "$GH" attestation verify "$f" "${bind[@]}" >/dev/null 2>"$tmp/err"; then
    echo "ok    provenance  $(basename "$f")"
  else
    echo "FAIL  provenance  $(basename "$f"): $(tail -1 "$tmp/err")"; fails=$((fails + 1))
  fi
done < <(find "$tmp/release" "$tmp/wheels" -type f \( -name '*.tar.gz' -o -name '*.whl' \) 2>/dev/null | sort)

if pred=$("$GH" attestation verify "$tmp/cc_impl.tsv" "${bind[@]}" --predicate-type "$cc_type" \
            --format json --jq '.[0].verificationResult.statement.predicate' 2>"$tmp/err"); then
  echo "ok    cc-conformance  evidence/cc_impl.tsv sha256 $(sha256sum "$tmp/cc_impl.tsv" | cut -d' ' -f1)"
  echo "      predicate $pred"
  got_ver=$(printf '%s' "$pred" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("crate_version",""))')
  [ "$got_ver" = "$v" ] || { echo "FAIL  predicate crate_version '$got_ver' != $v"; fails=$((fails + 1)); }
  tag_sha=$("$GH" api "repos/$repo/commits/$tag" --jq .sha 2>/dev/null || true)
  got_sha=$(printf '%s' "$pred" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("merge_sha",""))')
  [ -n "$tag_sha" ] && [ "$got_sha" = "$tag_sha" ] \
    || { echo "FAIL  predicate merge_sha '$got_sha' != $tag's commit '$tag_sha'"; fails=$((fails + 1)); }
else
  echo "FAIL  cc-conformance  evidence/cc_impl.tsv: $(tail -1 "$tmp/err")"; fails=$((fails + 1))
fi

if [ "$fails" -ne 0 ]; then echo "VERIFY RELEASE $tag: $fails FAILED"; exit 1; fi
echo "VERIFY RELEASE $tag: every attestation verified"
