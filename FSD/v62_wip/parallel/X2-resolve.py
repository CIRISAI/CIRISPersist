#!/usr/bin/env python3
"""X2's generic conflict resolver for the shapes that recur across the wave (no cargo).

Usage: python3 X2-resolve.py <file>...   (run in the worktree; resolves in place, prints what it did)

Shapes resolved:
  * src/store/parity.rs: a conflict whose sides are only `const NAME: [..; N] = [` length lines
    -> theirs (X2-fixes.sh G3 re-sums every array over the final tree).
  * a conflict whose sides are only module declarations (`[pub[(crate)]] mod x;`, their
    attributes and doc/line comments) -> ours, then theirs. When theirs does not open with its
    own attribute and the line just above the conflict is an attribute (git took the shared
    `#[cfg(..)]` into the common prefix), that attribute is repeated before theirs, so the
    second module does not lose its cfg ("scripted inserts steal the next item's attributes").
  * a conflict whose sides are only `pub const NAME: &str = ".."` tokens (with docs) or
    `NAME,` list entries -> ours, then theirs (both appended).
Anything else is left in place and named on stderr; exit 1.
"""
import re
import sys

BLOCK = re.compile(r'<<<<<<< ours\n(.*?)=======\n(.*?)>>>>>>> theirs\n', re.S)
MOD = re.compile(r'^\s*(#\[.*\]|//.*|(pub(\(crate\))? )?mod \w+;|)$')
TOKEN = re.compile(r'^\s*(///.*|//.*|pub const [A-Z0-9_]+: &str = "[^"]*";|[A-Z0-9_]+,|)$')
LENGTH = re.compile(r'^\s*const \w+: \[.*; \d+\] = \[$')


def only(rx, text):
    return all(rx.match(l) for l in text.rstrip('\n').split('\n'))


def resolve(path):
    s = open(path).read()
    bad = 0
    for m in reversed(list(BLOCK.finditer(s))):
        o, t = m.group(1), m.group(2)
        if path.endswith('store/parity.rs') and only(LENGTH, o) and only(LENGTH, t):
            r = t
        elif only(MOD, o) and only(MOD, t) and ('mod ' in o or 'mod ' in t):
            above = s[:m.start()].rstrip('\n').split('\n')[-1]
            attr = above + '\n' if above.strip().startswith('#[') and not t.lstrip().startswith('#[') else ''
            r = o + attr + t
        elif only(TOKEN, o) and only(TOKEN, t):
            r = o + t
        else:
            bad += 1
            continue
        s = s[:m.start()] + r + s[m.end():]
    open(path, 'w').write(s)
    if bad:
        print(f'X2-resolve: {path}: {bad} conflict(s) of an unknown shape left', file=sys.stderr)
    return bad


if __name__ == '__main__':
    sys.exit(1 if sum(resolve(p) for p in sys.argv[1:]) else 0)
