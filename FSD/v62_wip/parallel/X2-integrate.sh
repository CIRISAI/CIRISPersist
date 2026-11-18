#!/usr/bin/env bash
# X2 dry integration, from scratch on the CURRENT patches:
#   X1 (X1-integrate.sh + X1-fixes.sh: C1 C3 C2 C5 D1 D2 D3 C4), then
#   E0 T1(fixture hunk) K1 K2(+kernel) P1e|P1d P2 P2b P3 T1 O1 P4 P5 P5b P6 T2 W1 [F0 only with X2_WITH_F0=1]
# in a NEW detached worktree (X1-integrate.sh creates it). No cargo. Skips every *-cutb* patch.
# Usage: X2-integrate.sh <new-worktree-dir>     (X2_STOP_AFTER=<ID> stops after that step)
set -u
D=$1
P=/home/emoore/CIRISPersist-w62int/FSD/v62_wip/parallel
quiet() { grep -v -e '^Applied patch' -e 'Falling back' -e 'whitespace' -e 'lacks the necessary blob' -e '^deontic' ; }
conflicts() { git diff --name-only --diff-filter=U; }
# The double is generated: any conflict in it is resolved by regenerating it over the merged trait.
regen() { if git diff --name-only --diff-filter=U | grep -q '^src/federation/directory_double.rs$' || [ "${1:-}" = force ]; then
  python3 scripts/gen_directory_double.py >/dev/null && git add src/federation/directory_double.rs; fi; }
stop() { [ "${X2_STOP_AFTER:-}" = "$1" ] && { echo "stopped after $1"; exit 0; }; return 0; }

# 0. X1's combined tree, re-run from its own scripts over the CURRENT C/D patches.
bash $P/X1-integrate.sh "$D" 2>&1 | grep -v -P '^\S+\t\S+\t\d+\t' | sed 's/^/X1: /'
[ -d "$D" ] || { echo "X1-integrate.sh made no tree"; exit 1; }
bash $P/X1-fixes.sh "$D" 2>&1 | grep -v -P '^\S+\t\S+\t\d+\t' | sed 's/^/X1-fixes: /'
cd "$D" || exit 1
# X1's scripts leave the double conflicted/stale with C1 update 5 (`put_edition2_genesis`): regenerate.
python3 scripts/gen_directory_double.py >/dev/null
git add -A
echo "X1 unmerged:"; conflicts
stop X1

# 1. E0, then T1's one-line hunk on E0's file.
git apply --3way --index $P/E0.patch 2>&1 | quiet
git apply --3way --index $P/T1.fixture_switch-on-E0.patch 2>&1 | quiet

# 2. K1. Conflicts: door.rs (C3 deleted chain_waiting; keep K1's new fn only),
#    genesis.rs (C1's read_lineage is pure: K1's object-voice check moves to put_genesis_bundle),
#    directory_double.rs (regenerated).
git apply --3way --index $P/K1.patch 2>&1 | quiet
python3 - <<'EOF'
import re
p='src/federation/edition2/door.rs'; s=open(p).read()
m=re.search(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', s, re.S)
if m:
    assert m.group(1)==''; th=m.group(2); k=th.index('/// v62.0.0 (kernel pass 2, K1;')
    s=s[:m.start()]+th[k:]+s[m.end():]; open(p,'w').write(s); print('K1 door.rs resolved')
p='src/federation/edition2/genesis.rs'; s=open(p).read()
m=re.search(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', s, re.S)
if m:
    s=s[:m.start()]+m.group(1)+s[m.end():]
    old='''        super::door::require_statement_form(s)?;
        if cose_parts(s).as_ref().and_then(voice_of).is_some() {
            offered.push(s.clone());'''
    new='''        super::door::require_statement_form(s)?;
        let parts = cose_parts(s);
        if parts.as_ref().and_then(voice_of).is_some() {
            // v62.0.0 (kernel pass 2, K1) — a stated window covers some
            // instant (bundle object voices too).
            if let Some(p) = parts.as_ref() {
                super::door::check_valid_until_after_asserted_at(&p.payload)?;
            }
            offered.push(s.clone());'''
    assert s.count(old)==1; s=s.replace(old,new); open(p,'w').write(s); print('K1 genesis.rs resolved')
EOF
python3 scripts/gen_directory_double.py >/dev/null
git add src/federation/directory_double.rs src/federation/edition2/door.rs src/federation/edition2/genesis.rs

# 3. K2 (+ K2.kernel by hand: K1 moved its context). Conflicts: admission.rs (K2 deletes the cycle
#    gate K1 re-documented), mod.rs (K2 deletes NodeAlreadyOwned's kind) -> K2's side; cc_impl.tsv
#    regenerated in X2-fixes.sh.
git apply --3way --index $P/K2.patch 2>&1 | quiet
python3 - <<'EOF'
for p in ['src/federation/admission.rs','src/federation/mod.rs','evidence/cc_impl.tsv']:
    s=open(p).read().split('\n'); out=[]; i=0
    while i<len(s):
        if s[i].startswith('<<<<<<< '):
            m=next(j for j in range(i,len(s)) if s[j]=='='*7); e=next(j for j in range(m,len(s)) if s[j].startswith('>>>>>>> '))
            out+=s[m+1:e]; i=e+1; continue
        out.append(s[i]); i+=1
    open(p,'w').write('\n'.join(out))
p='src/kernel/differential.rs'; s=open(p).read()
if 'CycleVisitedOnce,' in s:
    R=[('''//! | [`Class::CycleVisitedOnce`] | CC 4.4.3.34 / KERNEL.md 5: the walk visits a cycle once; nothing is refused for closing one | the delegation cycle gate |
//! | [`Class::KeyEndHalfOpen`] | CC 2.6.2's freshness row: "the attestation has not yet reached its `valid_until`" | `HeldKeys::liveness` (kernel pass 2) |
''','''//! | [`Class::KeyEndHalfOpen`] | CC 2.6.2's freshness row: "the attestation has not yet reached its `valid_until`" | `HeldKeys::liveness` (kernel pass 2) |
//!
//! v62.0.0 (kernel pass 2): `CycleVisitedOnce` (the delegation cycle gate,
//! CC 4.4.3.34) is no longer a class: the gate is deleted, so there is no
//! persist answer left to disagree with the kernel's walk.
'''),('''    /// A cycle-closing delegation is not refused.
    CycleVisitedOnce,
''',''),('''            Class::CycleVisitedOnce => "cycle_visited_once",
''','')]
    for a,b in R:
        assert s.count(a)==1,a; s=s.replace(a,b)
    i=s.index('/// The delegation cycle gate: persist refused'); j=s.index('/// `held_head_verdict`: persist')
    s=s[:i]+s[j:]; open(p,'w').write(s); print('K2.kernel applied by hand')
EOF
git add evidence/cc_impl.tsv src/federation/admission.rs src/federation/mod.rs src/kernel/differential.rs

# 4. P1d (cumulative P1+P1c+P1d). Conflict: door.rs. Merge = P1c's pure_statement_gates over C3's
#    `&dyn KeyDirectory` (KeyOwnership is deleted by C3), K1's window check inside the pure gates
#    ahead of P1d's payload check; admit_row re-reads `protected` for C3's kid_not_of_iss arm.
# P1e (cumulative P1+P1c+P1d+P1e) supersedes P1d when published.
P1X=P1d; [ -f $P/P1e.patch ] && P1X=P1e
echo "== $P1X"
git apply --3way --index $P/$P1X.patch 2>&1 | quiet
python3 - <<'EOF'
import re
p='src/federation/edition2/door.rs'; s=open(p).read()
b=list(re.finditer(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', s, re.S))
if b:
    assert len(b)==2
    new1='''/// The refusals above.
pub fn pure_statement_gates(bytes: &[u8], keys: &dyn KeyDirectory) -> Result<(), Error> {
'''
    new2='''    // v62.0.0 (kernel pass 2, K1; CC ruling) — a stated window must cover
    // some instant: read from the statement alone, before any key is asked.
    check_valid_until_after_asserted_at(&payload)?;
    // v62.0.0 (wave P1d) — the family's closed payload map
    // (`edition2::payloads`), for a family that has one: an unknown member, a
    // missing required one, a wrong type, a closed value or leaf broken is
    // `edition2_payload_invalid`. A family with no list passes as before.
    match protected.get_int(-70002).and_then(Value::as_text) {
        Some(family) => super::payloads::check_by_id(family, &payload),
        // No family in the header: Verify's verdict names that fault.
        None => Ok(()),
    }
}

/// Judge one edition-2 row statement at a door (steps 1 to 5).
///
/// `offered_id` is an id the carrier names the row by, if any. It is
/// compared with the computed one, and never used.
///
/// # Errors
/// The door's named refusals (module docs). A statement that waits on a key
/// is `Error::AttesterKeyUnknown` (retryable).
pub fn admit_row(
    bytes: &[u8],
    keys: &dyn KeyDirectory,
    offered_id: Option<&Digest32>,
    ctx: SelectContext,
) -> Result<AdmittedRow, Error> {
    // Steps 1 and 2: the pure gates. A door that reads the directory runs
    // them first itself; repeated here, they cost a decode, and keep this
    // function whole for every caller.
    pure_statement_gates(bytes, keys)?;
    // The header, for the key-of-issuer refusal's names (the pure gates have
    // decoded it already, so this cannot fail; it is not unwrapped).
    let Some((protected, _)) = statement_parts(bytes) else {
        return Err(refuse(token::STATEMENT_INVALID, "not_cose_sign1"));
    };
'''
    s=s[:b[1].start()]+new2+s[b[1].end():]; s=s[:b[0].start()]+new1+s[b[0].end():]
    open(p,'w').write(s); print('P1d door.rs resolved')
EOF
# P1e: ingest.rs — P1e's person check on the admitted row goes ahead of C1's store tail
# (`put_admitted_row`); mod.rs malformed_row consts and ALL — both, K1's first.
python3 - <<'PYEOF'
import re
def blocks(s): return list(re.finditer(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', s, re.S))
p='src/federation/edition2/ingest.rs'; s=open(p).read()
for m in reversed(blocks(s)):
    o,t=m.group(1),m.group(2)
    if 'require_admission_signer_is_person' not in t: raise SystemExit('unexpected P1e ingest.rs conflict')
    s=s[:m.start()]+t+o+s[m.end():]
open(p,'w').write(s)
p='src/federation/mod.rs'; s=open(p).read()
for m in reversed(blocks(s)): s=s[:m.start()]+m.group(1)+m.group(2)+s[m.end():]
open(p,'w').write(s)
PYEOF
git add src/federation/edition2/door.rs src/federation/edition2/ingest.rs src/federation/mod.rs
regen force

# 5-6. P2, P2b, P3, T1 (clean).
for x in P2 P2b P3 T1; do echo "== $x"; git apply --3way --index $P/$x.patch 2>&1 | quiet; [ $x = T1 ] || regen; conflicts; [ "${X2_STOP_AFTER:-}" = $x ] && exit 0; done

# T1 (12:17) adds the trait method `drop_group_tips` beside K1's `list_group_tips`: keep both
# (K1's body closes first); the double is regenerated.
python3 - <<'PYEOF'
import re
p='src/federation/mod.rs'; s=open(p).read()
for m in reversed(list(re.finditer(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', s, re.S))):
    o,t=m.group(1),m.group(2)
    if not ('list_group_tips' in o and 'drop_group_tips' in t): raise SystemExit('unexpected T1 mod.rs conflict')
    s=s[:m.start()]+o+'        })\n    }\n\n'+t+s[m.end():]
open(p,'w').write(s)
PYEOF
python3 scripts/gen_directory_double.py >/dev/null
git add src/federation/mod.rs src/federation/directory_double.rs

# 7. O1 without its payloads.rs / EDITION2_PAYLOADS.md hunks (P1d carries them).
#    Conflicts: ingest.rs (pure gates THEN the recovery-signer read; T1's group intercept THEN
#    O1's occurrence intercept), edition2/mod.rs doc table + malformed_row tokens (both, K1 first).
git apply --3way --index --exclude=src/federation/edition2/payloads.rs \
  --exclude=docs/EDITION2_PAYLOADS.md $P/O1.patch 2>&1 | quiet
python3 - <<'EOF'
import re
def blocks(s): return list(re.finditer(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', s, re.S))
p='src/federation/edition2/ingest.rs'; s=open(p).read()
for m in reversed(blocks(s)):
    o,t=m.group(1),m.group(2)
    if 'recovery_signer' in t:
        # P1c's pure gates first (they include the form check), then O1's recovery read.
        t=t.replace('    super::door::require_statement_form(bytes)?;\n','',1)
        r=o+t
    elif 'OCCURRENCE_FAMILY' in t and 'group_plane_of' in o:
        r=o+'    }\n'+t   # T1's group intercept closes; O1's occurrence intercept follows
    else:
        raise SystemExit('unexpected ingest.rs conflict:\n'+o+'=====\n'+t)
    s=s[:m.start()]+r+s[m.end():]
open(p,'w').write(s); print('O1 ingest.rs resolved')
for p in ['src/federation/edition2/mod.rs','src/federation/mod.rs']:
    s=open(p).read()
    for m in reversed(blocks(s)): s=s[:m.start()]+m.group(1)+m.group(2)+s[m.end():]
    open(p,'w').write(s)
# fixture_switch.rs tail: E0's store tests + T1's re-export, then O1's re-export (both).
p='src/federation/edition2/fixture_switch.rs'; s=open(p).read()
for m in reversed(blocks(s)):
    if 'fixture_occurrence' not in m.group(2): raise SystemExit('unexpected O1 fixture_switch conflict')
    s=s[:m.start()]+m.group(1)+'\n'+m.group(2)+s[m.end():]
open(p,'w').write(s)
EOF
python3 scripts/gen_directory_double.py >/dev/null
git add -A

stop O1

# 8. After O1, in order (each when published): P4 P5 P5b P6 T2 W1.
#    P6 brings E7's replacement test module (`P6.e7_secrets_tests.rs`), swapped in by X2-fixes.sh G9.
#    T2 and W1 were cut as deltas on an earlier X2.patch: 3-way.
for x in P4 P5 P5b P6 T2 W1; do
  [ -f $P/$x.patch ] || { echo "== $x (absent)"; continue; }
  echo "== $x"
  git apply --3way --index $P/$x.patch 2>&1 | quiet
  # T2 was cut on X2.patch @12:27, whose C1 (update 3) split `put_statement` at
  # `put_admitted_row`; C1 update 5 writes a bundle's rows in ONE transaction
  # (`put_edition2_genesis`) instead. Resolution: keep T2's split (it carries the
  # `replicated: bool` E0425 fix), P1e's person check stays in `put_statement` ahead of the
  # call; DROP T2's genesis.rs call (it would store each named row a second time, outside the
  # transaction); fixture_switch tail: both re-exports; the capsule allowlist: T2's (it
  # already holds X2's G2 entry).
  if [ $x = T2 ]; then python3 - <<'PYEOF'
import re
B=re.compile(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', re.S)
def fix(p, f, need):
    s=open(p).read(); ms=list(B.finditer(s))
    for m in reversed(ms):
        if need not in m.group(1)+m.group(2): raise SystemExit('unexpected T2 conflict in '+p)
        s=s[:m.start()]+f(m.group(1),m.group(2))+s[m.end():]
    open(p,'w').write(s)
fix('src/federation/edition2/ingest.rs', lambda o,t: o+t, 'put_admitted_row')
fix('src/federation/edition2/genesis.rs', lambda o,t: o, 'put_admitted_row')
fix('src/federation/edition2/fixture_switch.rs', lambda o,t: o+'\n'+t, 'typed_fixtures')
fix('src/ffi/directory_capsule.rs', lambda o,t: t, 'put_delivery_receipt_edition2')
PYEOF
  git add src/federation/edition2/ingest.rs src/federation/edition2/genesis.rs \
    src/federation/edition2/fixture_switch.rs src/ffi/directory_capsule.rs
  fi
  # W1 (cut on X2.patch @12:27) appends beside P1e and T2: ingest.rs — T2's typed intercept
  # closes, then W1's re-bind intercept; payloads.rs FAMILIES — P1e's entry closes, then W1's
  # `transport:canonical_rebind`; the doc — both sections (re-bless I2102 at build).
  if [ $x = W1 ]; then python3 - <<'PYEOF'
import re
B=re.compile(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', re.S)
def fix(p, f, need):
    s=open(p).read()
    for m in reversed(list(B.finditer(s))):
        if need not in m.group(2): raise SystemExit('unexpected W1 conflict in '+p)
        s=s[:m.start()]+f(m.group(1),m.group(2))+s[m.end():]
    open(p,'w').write(s)
fix('src/federation/edition2/ingest.rs', lambda o,t: o+'    }\n'+t, 'REBIND_FAMILY')
fix('src/federation/edition2/payloads.rs', lambda o,t: o+'    },\n    FamilyPayload {\n'+t, 'transport:canonical_rebind')
fix('docs/EDITION2_PAYLOADS.md', lambda o,t: o+t, 'transport:canonical_rebind')
PYEOF
  git add src/federation/edition2/ingest.rs src/federation/edition2/payloads.rs docs/EDITION2_PAYLOADS.md
  fi
  # Generic shapes (module declarations, appended tokens, parity lengths): X2-resolve.py.
  for f in $(conflicts | grep -v '^src/federation/directory_double.rs$'); do
    python3 $P/X2-resolve.py "$f" && git add "$f"
  done
  regen
  conflicts
  stop $x
done

# 9. F0 is CP2's (team-lead): only with X2_WITH_F0=1. F0-onX1.patch, conflicts in parity.rs
#    (lengths: take F0's, X2-fixes.sh G3 re-sums) and the double (regenerated).
if [ "${X2_WITH_F0:-0}" = 1 ]; then
  git apply --3way --index $P/F0-onX1.patch 2>&1 | quiet
  python3 - <<'PYEOF'
p='src/store/parity.rs'; s=open(p).read().split('\n'); out=[]; i=0
while i<len(s):
    if s[i].startswith('<<<<<<< '):
        m=next(j for j in range(i,len(s)) if s[j]=='='*7); e=next(j for j in range(m,len(s)) if s[j].startswith('>>>>>>> '))
        out+=s[m+1:e]; i=e+1; continue
    out.append(s[i]); i+=1
open(p,'w').write('\n'.join(out))
PYEOF
fi
python3 scripts/gen_directory_double.py >/dev/null
git add -A
echo "unmerged:"; conflicts
grep -rln '^<<<<<<< \|^>>>>>>> ' -- src tests python scripts docs evidence benches migrations 2>/dev/null
exit 0
