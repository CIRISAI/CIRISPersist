#!/usr/bin/env bash
# X2's fixes on top of X2-integrate.sh's tree. No cargo. Usage: X2-fixes.sh <worktree>
set -u
cd "$1" || exit 1
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
