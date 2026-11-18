#!/usr/bin/env bash
# X-all: the ONE integration lane (team-lead). From v62-syn0, in a NEW detached worktree:
#   syn1  = syn0 + cut A's commits after 166b5d53 (to 23c0d30a) + cut B's after 64bd70f4 (to
#           4deb020f), applied as deltas (no merge state, no commit)
#   then  C3 C1 C2 C5 D1 D2 D3 C4 | E0 T1F K1 K2 P1(e) P2 P2b P3 T1 O1 | P4 P5 P5b T2 W1 W1b P6 V1
#         | F0 (F0-onX1, never F0-switch; X_NO_F0=1 leaves it out)
#         | the *-cutb patches: P1-cutb-ingest P1-cutb-custody P3-cutb V1-cutb
#   then  the fixes: X1's F1-F3 (F4 dropped: T1 is in), X2's G1-G13.
# Step-specific conflict rules: X-steps.py <STEP>; generic shapes: X2-resolve.py; the directory
# double is regenerated whenever it conflicts. A conflict no rule knows is LEFT and named.
# No cargo, no commit. Usage: X-all.sh <new-worktree-dir>   (X2_STOP_AFTER=<STEP> stops after it)
set -u
D=$1
P=/home/emoore/CIRISPersist-w62int/FSD/v62_wip/parallel
CUT_A=23c0d30a; CUT_A_BASE=166b5d53; CUT_B=4deb020f; CUT_B_BASE=64bd70f4
quiet() { grep -v -E -e '^Applied patch' -e 'Falling back' -e 'whitespace' -e 'lacks the necessary blob' -e $'^[^\t ]+\t[^\t ]+\t[0-9]+\t' -e '^(Engine|MODULE)[[:space:]]' ; }
conflicts() { git diff --name-only --diff-filter=U; }
regen() { if conflicts | grep -q '^src/federation/directory_double.rs$' || [ "${1:-}" = force ]; then
  python3 scripts/gen_directory_double.py >/dev/null && git add src/federation/directory_double.rs; fi; }
stop() { [ "${X2_STOP_AFTER:-}" = "$1" ] && { echo "stopped after $1"; exit 0; }; return 0; }
settle() {  # $1 = step
  python3 $P/X-steps.py "$1"
  for f in $(conflicts | grep -v '^src/federation/directory_double.rs$'); do
    python3 $P/X2-resolve.py "$f" && git add "$f"
  done
  regen
  local u; u=$(conflicts); [ -n "$u" ] && { echo "LEFT after $1 (stopping: a rule is missing): $u"; exit 1; }
  git add -A   # a rule's by-hand edit (X-steps.py POST) must be in the index for the next 3-way apply
  stop "$1"
}
# X_FROM=<STEP>: resume in an existing tree at that step (development aid; the steps before it
# must already be in the tree). Unset: the full run from a new worktree.
STARTED=1; [ -n "${X_FROM:-}" ] && STARTED=0
apply() {  # $1 = step, $2 = patch file, rest = extra git-apply args
  local s=$1 f=$2; shift 2
  [ $STARTED = 1 ] || { [ "$s" = "$X_FROM" ] && STARTED=1 || return 0; }
  [ -f "$f" ] || { echo "== $s (absent: $(basename $f))"; return 0; }
  echo "== $s ($(basename $f))"
  git apply --3way --index "$@" "$f" 2>&1 | quiet
  settle "$s"
}

if [ -n "${X_FROM:-}" ]; then cd "$D" || exit 1; else
git -C /home/emoore/CIRISPersist worktree add --detach "$D" v62-syn0 >/dev/null 2>&1 || { echo "worktree add failed"; exit 1; }
cd "$D" || exit 1

# syn1. The only A/B conflict is CHANGELOG.md: both sections (A's, then B's).
echo "== syn1: cut A $CUT_A_BASE..$CUT_A, cut B $CUT_B_BASE..$CUT_B"
git diff --binary $CUT_A_BASE $CUT_A | git apply --3way --index 2>&1 | quiet
git diff --binary $CUT_B_BASE $CUT_B | git apply --3way --index 2>&1 | quiet
python3 - <<'PYEOF'
import re
p='CHANGELOG.md'; s=open(p).read()
s=re.sub(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', lambda m: m.group(1)+'\n'+m.group(2), s, flags=re.S)
open(p,'w').write(s)
PYEOF
git add -A
settle syn1
fi

# The C/D lane (X1's order and resolutions).
apply C3 $P/C3.patch
apply C1 $P/C1.patch
apply C2 $P/C2.patch
apply C5 $P/C5.patch
apply D1 $P/D1.patch
apply D2 $P/D2.patch
# D3 deletes three Python surfaces that cut B (d5b39133) touched since syn0: excluded from the
# apply (it is atomic) and deleted here, as D3 intends.
D3_DEL="tests/python/test_hybrid_policy_1233_surface.py tests/python/test_key_grant_rows_surface.py tests/python/test_key_id_fingerprint_surface.py"
apply D3 $P/D3.patch --exclude=tests/python/test_genesis_import_surface.py $(for f in $D3_DEL; do echo --exclude=$f; done)  # C5 deletes the first too
for f in $D3_DEL; do [ -f $f ] && rm -- "$f" && git add -- "$f"; done
apply C4 $P/C4.patch
regen force

# The core.
apply E0 $P/E0.patch
apply T1F $P/T1.fixture_switch-on-E0.patch
apply K1 $P/K1.patch
apply K2 $P/K2.patch          # + K2.kernel.patch by hand (X-steps.py POST K2): K1 moved its context
P1X=P1d; [ -f $P/P1e.patch ] && P1X=P1e  # cumulative: P1+P1c+P1d(+P1e)
apply P1 $P/$P1X.patch
regen force
apply P2 $P/P2.patch
apply P2b $P/P2b.patch
apply P3 $P/P3.patch
apply T1 $P/T1.patch
apply O1 $P/O1.patch --exclude=src/federation/edition2/payloads.rs --exclude=docs/EDITION2_PAYLOADS.md  # P1 carries them

# After O1 (the authors' order: T2, then W1, then W1b).
apply P4 $P/P4.patch
apply P5 $P/P5.patch
apply P5b $P/P5b.patch
apply T2 $P/T2.patch
apply W1 $P/W1.patch
apply W1b $P/W1b.patch
apply P6 $P/P6.patch          # + P6.e7_secrets_tests.rs (fix G9)
apply V1 $P/V1-onX2.patch     # V1 + V1b

# F0-onX1 (the gate, door table, CI/certify hooks, wired doors, I2870-I2873, its deletions).
[ "${X_NO_F0:-0}" = 1 ] || apply F0 $P/F0-onX1.patch

# The *-cutb patches (cut against cut B's tip; syn1 carries B at 4deb020f).
apply P1-cutb-ingest $P/P1-cutb-ingest.patch
apply P1-cutb-custody $P/P1-cutb-custody.patch
apply P3-cutb $P/P3-cutb.patch
apply V1-cutb $P/V1-cutb.patch

python3 scripts/gen_directory_double.py >/dev/null
git add -A
echo "unmerged after the stack:"; conflicts
grep -rln '^<<<<<<< \|^>>>>>>> ' -- src tests python scripts docs evidence benches migrations CHANGELOG.md Cargo.toml 2>/dev/null
stop stack

# ── the fixes ──
# F1: examples/mint_test_ceremony.rs imports the deleted genesis::mint_test_ceremony (C5).
if [ -f examples/mint_test_ceremony.rs ]; then
  git rm -q examples/mint_test_ceremony.rs
  python3 - <<'EOF'
p='Cargo.toml'; s=open(p).read()
blk='''# CIRISPersist#973 — the software ceremony minter (dry run), test-anchor-gated:
# `cargo run --example mint_test_ceremony --features test-anchor -- <out_dir> <seed>×3 <node_seed>`.
[[example]]
name = "mint_test_ceremony"
required-features = ["test-anchor"]

'''
assert s.count(blk)==1; open(p,'w').write(s.replace(blk,''))
EOF
fi
# F2: C4's evidence rows citing symbols C1/C3 deleted.
python3 - src/federation/namespace/namespace_supersets.json <<'EOF'
import sys
p=sys.argv[1]; s=open(p).read()
R=[('src/federation/edition2/halt.rs#read_invocation','src/federation/edition2/halt.rs#refusal_error'),
('src/federation/edition2/genesis.rs#verify_bundle','src/federation/edition2/genesis.rs#read_lineage'),
('src/federation/edition2/genesis.rs#BundleInForce::is_canonical','src/federation/edition2/genesis.rs#GenesisInForce::is_canonical'),
('src/federation/edition2/genesis.rs#seat_xwing_from_binding','src/federation/edition2/genesis.rs#GenesisInForce::seat')]
for a,b in R:
    if '"'+a+'"' in s: s=s.replace('"'+a+'"','"'+b+'"'); print('repointed',a,'->',b)
open(p,'w').write(s)
EOF
python3 - <<'EOF'
def edit(p, a, b, n=1):
    s = open(p).read()
    if b and b in s:
        print('already', p); return
    assert s.count(a) == n, (p, a[:80], s.count(a))
    open(p, 'w').write(s.replace(a, b)); print('fixed', p)

# G1: T1's StatementOutcome::Pending reaches D1's and D2's exhaustive matches.
# X1's F4 stripped these arms because T1 was absent from lane 1; X2 carries T1, so they return.
edit('src/ffi/directory_capsule.rs', '''            S::Row { row_id, new } => Self::Row {
                row_id: row_id.0,
                new,
            },
        }''', '''            S::Row { row_id, new } => Self::Row {
                row_id: row_id.0,
                new,
            },
            S::Pending { row_id, new } => Self::Pending {
                row_id: row_id.0,
                new,
            },
        }''')
edit('src/server/edition2.rs', '''        StatementOutcome::Row { row_id, .. } => ("row", row_id),
    };''', '''        StatementOutcome::Row { row_id, .. } => ("row", row_id),
        StatementOutcome::Pending { row_id, .. } => ("pending", row_id),
    };''')
edit('src/server/edition2.rs', '''        | StatementOutcome::Row { new, .. } => *new,
    }''', '''        | StatementOutcome::Row { new, .. }
        | StatementOutcome::Pending { new, .. } => *new,
    }''')
edit('src/ffi/pyo3.rs', '''        StatementOutcome::Row { row_id, new } => ("row", row_id, *new),
    };''', '''        StatementOutcome::Row { row_id, new } => ("row", row_id, *new),
        StatementOutcome::Pending { row_id, new } => ("pending", row_id, *new),
    };''')

# G2: O1's new trait method defaults to Unsupported and the capsule proxy does not route it:
# I1162 (from disk) requires an allowlist entry with a reason.
if '"put_identity_occurrence_edition2",' not in open('src/ffi/directory_capsule.rs').read(): edit('src/ffi/directory_capsule.rs', '''            "list_group_tips",''', '''            "put_identity_occurrence_edition2",
            "v62.0.0 (wave O1) — the edition-2 occurrence bind is written by the \\
             node's own door (`edition2::occurrence::put_occurrence_voice`), reached \\
             through `put_edition2_statement`; no DirectoryOp carries the typed write",
        ),
        (
            "list_group_tips",''')

# G3: parity.rs's fixed-length arrays must equal their tuple counts (E0308 otherwise). C5 removed
# 2 SHARED_DOORS without re-counting; K2 and F0 each re-counted against their own base only.
# Recount every `const NAME: [T; N] = [` in the file and set N to the tuples present.
import re
p = 'src/store/parity.rs'; s = open(p).read()
def tuples(body):
    body = re.sub(r'//[^\n]*', '', body); k = 0; d = 1; n = 0; strs = 0
    while d:
        c = body[k]
        if c in '[(':
            if d == 1 and c == '(': n += 1
            d += 1
        elif c in '])': d -= 1
        elif c == '"':
            if d == 1: strs += 1
            k = body.index('"', k + 1)
        k += 1
    return n, strs
out = s
for m in reversed(list(re.finditer(r'const (\w+): \[(\(?[^;\]]*?\)?); (\d+)\] = \[', s))):
    n, strs = tuples(s[m.end():])
    have = n if m.group(2).startswith('(') else strs
    if have != int(m.group(3)):
        out = out[:m.start(3)] + str(have) + out[m.end(3):]
        print('G3', m.group(1), m.group(3), '->', have)
open(p, 'w').write(out)

# G8: the 3-way merge of O1's `mod.rs` hunk next to C2's fixture modules left
# `pub mod fixture_occurrence;` WITHOUT O1's `#[cfg(any(test, feature = "test-anchor"))]`
# (it imports `fixture_switch`, which is test/test-anchor only: E0432 in a plain build).
p = 'src/federation/edition2/mod.rs'; s = open(p).read()
cfg = '#[cfg(any(test, feature = "test-anchor"))]\n'
if 'pub mod fixture_occurrence;' in s and cfg + 'pub mod fixture_occurrence;' not in s:
    s = s.replace('pub mod fixture_occurrence;', cfg + 'pub mod fixture_occurrence;', 1)
    open(p, 'w').write(s); print('G8 cfg on fixture_occurrence')
# G9: P6 rewrote secrets.rs's production auth; its old `tests` module (E7's) no longer compiles
# (HEADER_ED25519, ROLE_SECRETS_*, capability_roles). Swap in P6.e7_secrets_tests.rs, from the
# `// ── Tests` header to the end of the `mod tests` block.
import os
src = '/home/emoore/CIRISPersist-w62int/FSD/v62_wip/parallel/P6.e7_secrets_tests.rs'
p = 'src/server/secrets.rs'
if os.path.exists(src) and 'authenticate_request' in open(p).read():
    s = open(p).read(); new = open(src).read()
    if new.strip() not in s:
        i = s.index('// ── Tests ──'); j = s.index('mod tests {', i); k = s.index('{', j); d = 0
        for e in range(k, len(s)):
            d += {'{': 1, '}': -1}.get(s[e], 0)
            if d == 0: break
        s = s[:i] + new.rstrip('\n') + s[e + 1:]
        if not s.endswith('\n'): s += '\n'
        open(p, 'w').write(s); print('G9 secrets tests module swapped')

# G10 (team-lead/T2, E0425): `put_admitted_row` (the store tail split out of put_statement)
# takes `replicated: bool`; T1's group intercept reads it, put_statement passes
# `offered_id.is_some()`. T2.patch already carries this shape; applied here only if absent.
# Also: inside put_admitted_row `admitted` is already `&AdmittedRow`, so `&admitted` is a
# needless borrow (clippy -D warnings); and its doc no longer has a genesis caller (C1 update 5
# writes a bundle's rows in one transaction, `put_edition2_genesis`).
p = 'src/federation/edition2/ingest.rs'; s = open(p).read()
if 'pub async fn put_admitted_row' in s:
    if 'replicated: bool' not in s:
        s = s.replace('    tier: &str,\n) -> Result<StatementOutcome, Error>\nwhere\n    F: FederationDirectory + ?Sized,\n{\n    let bytes: &[u8] = &admitted.bytes;',
                      '    tier: &str,\n    replicated: bool,\n) -> Result<StatementOutcome, Error>\nwhere\n    F: FederationDirectory + ?Sized,\n{\n    let bytes: &[u8] = &admitted.bytes;', 1)
        s = s.replace('put_admitted_row(dir, &admitted, tier).await', 'put_admitted_row(dir, &admitted, tier, offered_id.is_some()).await', 1)
        print('G10 replicated param added')
    i = s.index('pub async fn put_admitted_row'); j = s.index('\n}\n', i)
    body = s[i:j]
    body2 = body.replace('offered_id.is_some()', 'replicated')
    import re as _re
    body2 = _re.sub(r'&admitted\b(?!\.)', 'admitted', body2)
    if body2 != body:
        s = s[:i] + body2 + s[j:]; print('G10 put_admitted_row body: replicated / needless borrows')
    old_doc = """/// [`put_statement`] admits under the held key plane. The genesis door
/// (`edition2::genesis::put_genesis_bundle`) admits a bundle's named rows
/// under the keys the bundle places, then stores each through this, so a
/// named row passes every gate it would pass alone.
"""
    if old_doc in s:
        s = s.replace(old_doc, """/// [`put_statement`] admits under the held key plane, then stores through
/// this. (The genesis door no longer calls it: C1 writes a bundle's named
/// rows in one transaction, `FederationDirectory::put_edition2_genesis`.)
""", 1); print('G10 doc')
    open(p, 'w').write(s)
g = 'src/federation/edition2/genesis.rs'; gs = open(g).read()
assert 'put_admitted_row(' not in gs or 'INGEST_TIER, false)' in gs, 'G10: a genesis caller without `replicated`'

# G11: SQLITE_CONN_CLASSES rows the from-disk gate will name: K1's `list_group_tips` (a read,
# per T1 v4's note) and C1's sqlite `put_edition2_genesis` (one write transaction).
p = 'src/store/sqlite_conn_model.rs'; s = open(p).read()
for name, cls, after in [('list_group_tips', 'Read', '    ("list_group_versions", ConnClass::Read),\n'),
                         ('put_edition2_genesis', 'Write', '    ("drop_group_tips", ConnClass::Write),\n')]:
    row = f'    ("{name}", ConnClass::{cls}),\n'
    if f'("{name}",' not in s and name in open('src/store/sqlite.rs').read():
        assert s.count(after) == 1, after
        s = s.replace(after, after + row); print('G11 conn row', name)
open(p, 'w').write(s)

# G12: I1162 (proxy parity, from disk) names three new trait methods whose default is
# `Unsupported` and that the capsule proxy does not route: C1's `put_edition2_genesis` and P5b's
# `put_touch_claim_local` / `freshness_floor`. Allowlisted with a reason (the owners may route
# them instead: a DirectoryOp each).
p = 'src/ffi/directory_capsule.rs'; s = open(p).read()
anchor = '            "list_group_tips",'
for name, why in [
    ('put_edition2_genesis', "v62.0.0 (C1) — the genesis bundle's one-transaction write is the \\\n             node's own door (`edition2::genesis::put_genesis_bundle`); no DirectoryOp \\\n             carries a bundle's GenesisWrite"),
    ('put_touch_claim_local', "v62.0.0 (P5b) — the node-local touch claim is this node's own derived \\\n             state (RULINGS: a touch claim is node-local); no DirectoryOp carries it yet"),
    ('freshness_floor', "v62.0.0 (P5b) — the node-local freshness floor read; no DirectoryOp \\\n             carries it yet"),
]:
    if f'"{name}",' not in s:
        assert s.count(anchor) == 1
        s = s.replace(anchor, f'            "{name}",\n            "{why}",\n        ),\n        (\n' + anchor, 1)
        print('G12 allowlisted', name)
open(p, 'w').write(s)

# G14 (compile, syn1): cut B split `put_statement` into `put_statement_with_origin(.., origin)` and
# its tail writes with `put_attestation_with_origin(.., origin)`; T2's split moved that tail into
# `put_admitted_row`, where `origin` is not in scope (E0425), and V1b's `put_counted_row` writes
# with plain `put_attestation`. The origin rides through both: Authored stays Authored (#804).
WO = 'crate::federation::replication::admission::WriteOrigin'
p = 'src/federation/edition2/ingest.rs'; s = open(p).read()
i = s.find('pub async fn put_admitted_row')
if i >= 0 and 'origin: ' + WO not in s[i:i + 400]:
    old = '    replicated: bool,\n) -> Result<StatementOutcome, Error>'
    j = s.index(old, i)
    s = s[:j] + '    replicated: bool,\n    origin: ' + WO + ',\n) -> Result<StatementOutcome, Error>' + s[j + len(old):]
    c = 'put_admitted_row(dir, &admitted, tier, offered_id.is_some())'
    assert s.count(c) == 1, 'G14: put_admitted_row caller'
    s = s.replace(c, 'put_admitted_row(dir, &admitted, tier, offered_id.is_some(), origin)')
    s = s.replace("/// `replicated` is whether a peer offered the statement under an id (the\n/// replicated door): the group planes' membership door reads it.\n",
                  "/// `replicated` is whether a peer offered the statement under an id (the\n/// replicated door): the group planes' membership door reads it. `origin`\n/// is the mapped row's write origin ([`put_statement_with_origin`]).\n", 1)
    open(p, 'w').write(s); print('G14 put_admitted_row(.., origin)')
p = 'src/federation/edition2/voices.rs'
import os
if os.path.exists(p):
    s = open(p).read()
    i = s.find('pub async fn put_counted_row')
    if i >= 0 and 'origin: ' + WO not in s[i:i + 300]:
        old = '    tier: &str,\n) -> Result<super::ingest::StatementOutcome, Error>'
        j = s.index(old, i)
        s = s[:j] + '    tier: &str,\n    origin: ' + WO + ',\n) -> Result<super::ingest::StatementOutcome, Error>' + s[j + len(old):]
        w = '            dir.put_attestation(crate::federation::SignedAttestation { attestation: row }),'
        assert s.count(w) == 1, 'G14: put_counted_row write'
        s = s.replace(w, '            dir.put_attestation_with_origin(\n                crate::federation::SignedAttestation { attestation: row },\n                origin,\n            ),')
        open(p, 'w').write(s); print('G14 put_counted_row(.., origin)')

# G4 (retired): E0 v1.12+ keeps a deliberate catch-all over P1's Ty::Any and Ty::Tstrs.

# G7: C4's v62-c4-rc20 row CLM-anti-pattern-delegation cites the cycle gate K2 deleted
# (evidence_tsv.py write refuses: 0 declarations). Repointed to the walk that now carries
# CC 4.1.1's cycle reading (visited once, nothing refused): scoped_delegation_reach_at.
p = 'src/federation/namespace/namespace_supersets.json'; s = open(p).read()
a = """    "claim_id": "CLM-anti-pattern-delegation",
    "repo": "CIRISPersist",
    "path#symbol": "src/federation/admission.rs#check_delegation_cycle_admission","""
b = """    "claim_id": "CLM-anti-pattern-delegation",
    "repo": "CIRISPersist",
    "path#symbol": "src/federation/admission.rs#scoped_delegation_reach_at","""
if a in s:
    open(p, 'w').write(s.replace(a, b)); print('G7 repointed CLM-anti-pattern-delegation')
EOF
# G5: rustfmt the hand-merged files (allowed: rustfmt on files edited).
rustfmt --edition 2021 src/federation/edition2/door.rs src/federation/edition2/genesis.rs \
  src/federation/edition2/ingest.rs src/kernel/differential.rs src/store/parity.rs \
  src/server/edition2.rs src/federation/edition2/fixture_switch.rs 2>&1 | head -5
# G6: regenerate the generated projections over the combined tree.
python3 scripts/gen_directory_double.py >/dev/null && python3 scripts/gen_directory_double.py --check
python3 scripts/evidence_tsv.py write && python3 scripts/evidence_tsv.py check
python3 scripts/evidence_pointers.py check | tail -1
python3 scripts/evidence_tsv_test.py 2>&1 | tail -1
python3 scripts/pyi_surface.py surface | head -1 && python3 scripts/pyi_surface.py check >/dev/null && echo "pyi check OK"
python3 scripts/mutants_scopes_check.py 2>&1 | tail -1
git add -A
