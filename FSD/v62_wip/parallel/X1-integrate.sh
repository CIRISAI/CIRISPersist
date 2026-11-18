#!/usr/bin/env bash
# X1 dry integration: apply C3 C1 C2 C5 D1 D2 D3 [C4] onto v62-syn0 in a NEW detached worktree.
# No cargo. Usage: integrate.sh <new-worktree-dir>
set -u
D=$1
P=/home/emoore/CIRISPersist-w62int/FSD/v62_wip/parallel
git -C /home/emoore/CIRISPersist worktree add --detach "$D" v62-syn0 >/dev/null 2>&1 || exit 1
cd "$D" || exit 1
ORDER="C3 C1 C2 C5 D1 D2 D3"
[ -f $P/C4.patch ] && ORDER="C3 C1 C2 C5 D1 D2 D3 C4"
for x in $ORDER; do
  ex=()
  # C5 already deletes this file; D3 deletes it too.
  [ $x = D3 ] && ex=(--exclude=tests/python/test_genesis_import_surface.py)
  echo "== $x"
  git apply --3way --index "${ex[@]}" $P/$x.patch 2>&1 | grep -v -e '^Applied patch' -e 'Falling back' -e 'trailing whitespace' -e 'whitespace errors' -e '^Engine\s' -e '^MODULE\s' -e "^$P"
  if [ $x = C1 ]; then
        # halt.rs: C3's rewrite + C1's roster_in_force doc (C1's body merges cleanly).
    python3 - src/federation/edition2/halt.rs <<'EOF'
import sys
p=sys.argv[1]; L=open(p).read().split('\n')
if '<<<<<<< ours' in L:
    s=L.index('<<<<<<< ours'); m=L.index('======='); e=L.index('>>>>>>> theirs')
    # C3 first: ours = C3 (Verify's reader; stub doc), theirs = C1's base view
    # (persist's old reader + C1's roster_in_force doc). Keep C3, take C1's doc.
    theirs=L[m+1:e]
    k=[i for i,l in enumerate(theirs) if l.startswith('/// The roster of the genesis bundle in force')][0]
    L=L[:s]+theirs[k:]+L[e+1:]
    open(p,'w').write('\n'.join(L))
EOF
    git add src/federation/edition2/halt.rs
  fi
done
git add -A
echo "unmerged:"; git diff --name-only --diff-filter=U
grep -rln '^<<<<<<< \|^>>>>>>> ' -- src tests python scripts docs 2>/dev/null
