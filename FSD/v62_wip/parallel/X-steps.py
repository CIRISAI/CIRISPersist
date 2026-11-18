#!/usr/bin/env python3
"""X-all's step-specific conflict resolutions (no cargo). Run in the worktree after a step's
`git apply --3way --index`:   python3 X-steps.py <STEP>

Each step's rules name the conflict they expect by a marker in it; a conflict no rule (and no
generic shape in X2-resolve.py, run after this) knows is LEFT and reported, so a changed patch
fails loudly instead of being merged blind. Resolved files are `git add`ed.
"""
import re
import subprocess
import sys

B = re.compile(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', re.S)


def unmerged():
    r = subprocess.run(['git', 'diff', '--name-only', '--diff-filter=U'], capture_output=True, text=True)
    return [l for l in r.stdout.split('\n') if l]


def drop_fn(text, name):
    """`text` without the item `fn name` (its doc comment block and body)."""
    i = text.find(f'fn {name}(')
    if i < 0:
        return text
    start = text.rfind('\n\n', 0, i)
    start = 0 if start < 0 else start + 2
    k = text.index('{', i); d = 0
    for e in range(k, len(text)):
        d += {'{': 1, '}': -1}.get(text[e], 0)
        if d == 0:
            break
    end = e + 1
    while end < len(text) and text[end] == '\n':
        end += 1
    return text[:start] + text[end:]


def resolve(path, rule):
    """Apply `rule(ours, theirs, before) -> str | None` to every conflict in `path`."""
    s = open(path).read()
    left = 0
    for m in reversed(list(B.finditer(s))):
        r = rule(m.group(1), m.group(2), s[:m.start()])
        if r is None:
            left += 1
            continue
        s = s[:m.start()] + r + s[m.end():]
    open(path, 'w').write(s)
    if not left:
        subprocess.run(['git', 'add', path])
    return left


def both(o, t, _b):
    return o + t


def ours(o, _t, _b):
    return o


def theirs(_o, t, _b):
    return t


def need(marker, f):
    """Use `f` only on a conflict that carries `marker` (in either side)."""
    return lambda o, t, b: f(o, t, b) if marker in o + t else None


# ── the rules, by step ────────────────────────────────────────────────────

def k1_genesis(o, t, b):
    # C1's read_lineage is pure: K1's object-voice window check moves to put_genesis_bundle
    # (done in post_k1). Keep C1's side.
    return o if 'check_valid_until_after_asserted_at' in t else None


def post_k1():
    p = 'src/federation/edition2/genesis.rs'; s = open(p).read()
    old = '''        super::door::require_statement_form(s)?;
        if cose_parts(s).as_ref().and_then(voice_of).is_some() {
            offered.push(s.clone());'''
    new = '''        super::door::require_statement_form(s)?;
        let parts = cose_parts(s);
        if parts.as_ref().and_then(voice_of).is_some() {
            // v62.0.0 (kernel pass 2, K1) — a stated window covers some
            // instant (bundle object voices too).
            if let Some(p) = parts.as_ref() {
                super::door::check_valid_until_after_asserted_at(&p.payload)?;
            }
            offered.push(s.clone());'''
    if 'check_valid_until_after_asserted_at(&p.payload)' not in s:
        assert s.count(old) == 1, 'K1: put_genesis_bundle anchor moved'
        open(p, 'w').write(s.replace(old, new)); print('K1: window check moved into put_genesis_bundle')


def k2_kernel():
    p = 'src/kernel/differential.rs'; s = open(p).read()
    if 'CycleVisitedOnce,' not in s:
        return
    R = [('''//! | [`Class::CycleVisitedOnce`] | CC 4.4.3.34 / KERNEL.md 5: the walk visits a cycle once; nothing is refused for closing one | the delegation cycle gate |
//! | [`Class::KeyEndHalfOpen`] | CC 2.6.2's freshness row: "the attestation has not yet reached its `valid_until`" | `HeldKeys::liveness` (kernel pass 2) |
''', '''//! | [`Class::KeyEndHalfOpen`] | CC 2.6.2's freshness row: "the attestation has not yet reached its `valid_until`" | `HeldKeys::liveness` (kernel pass 2) |
//!
//! v62.0.0 (kernel pass 2): `CycleVisitedOnce` (the delegation cycle gate,
//! CC 4.4.3.34) is no longer a class: the gate is deleted, so there is no
//! persist answer left to disagree with the kernel's walk.
'''), ('''    /// A cycle-closing delegation is not refused.
    CycleVisitedOnce,
''', ''), ('''            Class::CycleVisitedOnce => "cycle_visited_once",
''', '')]
    for a, b in R:
        assert s.count(a) == 1, a
        s = s.replace(a, b)
    i = s.index('/// The delegation cycle gate: persist refused'); j = s.index('/// `held_head_verdict`: persist')
    open(p, 'w').write(s[:i] + s[j:]); print('K2.kernel applied by hand')
    subprocess.run(['git', 'add', p])


P1_GATES_HEAD = '''/// The refusals above.
pub fn pure_statement_gates(bytes: &[u8], keys: &dyn KeyDirectory) -> Result<(), Error> {
'''
P1_GATES_TAIL = '''    // v62.0.0 (kernel pass 2, K1; CC ruling) — a stated window must cover
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


def p1_door(o, t, b):
    if 'pub fn pure_statement_gates' in t and 'pub fn admit_row' in o:
        return P1_GATES_HEAD
    if 'check_by_id' in t and 'check_valid_until_after_asserted_at' in o:
        return P1_GATES_TAIL
    return None


def p1_ingest(o, t, b):
    # P1e's person check ahead of a store tail (the T2-era shape; kept for safety).
    if 'require_admission_signer_is_person' in t:
        return t + o
    # syn1: cut B's verify_carried compares envelopes by `same_envelope` (JCS images); P1c moved
    # the comparison into `require_projection` and added `check_carried_projection`. P1c's
    # structure, with B's envelope equality.
    if 'fn check_carried_projection' in t and 'same_envelope' in o:
        old = '        && expected.attestation_envelope == row.attestation_envelope;'
        assert t.count(old) == 1
        return t.replace(old, '        && same_envelope(&expected.attestation_envelope, &row.attestation_envelope);')
    # syn1: cut B split put_statement into put_statement_with_origin(.., origin); P1c's pure
    # gates replace the form check at the head of the split body.
    if 'pure_statement_gates' in t and 'put_statement_with_origin' in o:
        last = '    super::door::require_statement_form(bytes)?;\n'
        assert o.endswith(last)
        return o[:-len(last)] + t
    return None


def o1_ingest(o, t, b):
    if 'recovery_signer' in t:
        return o + t.replace('    super::door::require_statement_form(bytes)?;\n', '', 1)
    if 'OCCURRENCE_FAMILY' in t and 'group_plane_of' in o:
        return o + '    }\n' + t
    return None


def t2_ingest(o, t, b):
    # T2 (cut on C1 update 3's split) keeps `put_admitted_row(.., replicated)`; P1e's person
    # check stays in put_statement ahead of the call.
    return o + t if 'put_admitted_row' in t else None


def w1_ingest(o, t, b):
    # W1's re-bind intercept, then T2's typed intercept (W1b's base has this order).
    return t + '    }\n' + o if 'REBIND_FAMILY' in t else None


RULES = {
    # D3 rewrote / deleted these Python witnesses for v62; cut B (d5b39133) touched a few lines
    # of the earlier form they replace: D3's side.
    'D3': {'tests/python/test_affiliation_surface.py': theirs, 'tests/python/test_sqlite_engine.py': theirs},
    'C3': {'src/federation/edition2/door.rs': lambda o, t, b: drop_fn(o, 'chain_waiting') if 'fn chain_waiting' in o and not t.strip() else None},
    'C1': {'src/federation/edition2/halt.rs': lambda o, t, b: t[t.index('/// The roster of the genesis bundle in force'):] if '/// The roster of the genesis bundle in force' in t else None},
    'K1': {'src/federation/edition2/door.rs': lambda o, t, b: o + drop_fn(t, 'chain_waiting') if 'check_valid_until_after_asserted_at' in t else None,
           'src/federation/edition2/genesis.rs': k1_genesis},
    'K2': {'src/federation/admission.rs': theirs, 'src/federation/mod.rs': theirs, 'evidence/cc_impl.tsv': theirs},
    'P1': {'src/federation/edition2/door.rs': p1_door,
           'src/federation/edition2/ingest.rs': p1_ingest,
           'src/federation/mod.rs': both},
    'T1': {'src/federation/mod.rs': lambda o, t, b: o + '        })\n    }\n\n' + t if 'list_group_tips' in o and 'drop_group_tips' in t else None},
    'O1': {'src/federation/edition2/ingest.rs': o1_ingest,
           'src/federation/edition2/mod.rs': both, 'src/federation/mod.rs': both,
           'src/federation/edition2/fixture_switch.rs': lambda o, t, b: o + '\n' + t if 'fixture_occurrence' in t else None},
    'T2': {'src/federation/edition2/ingest.rs': t2_ingest,
           'src/federation/edition2/genesis.rs': lambda o, t, b: o if 'put_admitted_row' in t else None,
           'src/federation/edition2/fixture_switch.rs': lambda o, t, b: o + '\n' + t if 'typed_fixtures' in t else None,
           'src/ffi/directory_capsule.rs': lambda o, t, b: t if 'put_delivery_receipt_edition2' in t else None},
    'W1': {'src/federation/edition2/ingest.rs': w1_ingest,
           'src/federation/edition2/payloads.rs': lambda o, t, b: o + '    },\n    FamilyPayload {\n' + t if 'transport:canonical_rebind' in t else None,
           'docs/EDITION2_PAYLOADS.md': lambda o, t, b: o + t if 'transport:canonical_rebind' in t else None},
}
def v1_ingest(o, t, b):
    # V1b's counted tail replaces the direct put; cut B's write origin rides into it (G14).
    if 'put_counted_row' in t:
        return t.replace('put_counted_row(dir, admitted, tier)', 'put_counted_row(dir, admitted, tier, origin)')
    return None


RULES['V1'] = {
    'src/federation/edition2/ingest.rs': v1_ingest,
    # C1 update 5 writes a bundle's rows in ONE transaction (put_edition2_genesis), with no
    # gates and so no Pending: V1b's hunk targets C1 update 3's per-row put loop. C1's side.
    'src/federation/edition2/genesis.rs': lambda o, t, b: o if 'wave V1b' in t else None,
}

# P3 (syn0) added the edition-2 projection fence at the end of hard_case.rs; P3-cutb (cut B) added
# the producer there too: both (P3's body closes first).
RULES['P3-cutb'] = {'src/federation/hard_case.rs':
    lambda o, t, b: o + '}\n\n' + t if 'fn edition2_body_instants' in o and 'fn hard_case_emit_input' in t else None}

POST = {'K1': post_k1, 'K2': k2_kernel}


# Generated files: any side, regenerated by the fixes (evidence_tsv.py write, pyi_surface.py surface).
GENERATED = {'evidence/ffi_classification.tsv': theirs, 'evidence/cc_impl.tsv': theirs}


def main(step):
    rules = dict(GENERATED)
    rules.update(RULES.get(step, {}))
    for path in unmerged():
        if path in rules:
            left = resolve(path, rules[path])
            print(f'{step}: {path}: ' + ('resolved' if not left else f'{left} conflict(s) left'))
    if step in POST:
        POST[step]()


if __name__ == '__main__':
    main(sys.argv[1])
