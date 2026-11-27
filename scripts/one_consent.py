#!/usr/bin/env python3
"""one_consent.py: a node is its owner's writer, never its consent (no cargo).

    scripts/one_consent.py check        exit 1 on a new lifting caller
    scripts/one_consent.py --self-test  the gate's own witnesses
    scripts/one_consent.py list         the current sites, as entries

v62.0.0 (KR-fix10; CC 3.1.3.2 "A node gives no acceptance", CC 3.3.6): the
owner binding carries the right to WRITE for the owner and nothing else.
`admission::writer_principal` follows it (device -> person, else node ->
owner); a consent or standing comparison never may. Those call
`admission::consenting_person` / `consenting_identity`, which read no owner
binding and answer nobody for a node key.

Red: a call of `writer_principal(` in src/**/*.rs (line comments blanked)
outside WRITERS, or more calls in a listed file than its entry allows. An
entry whose count is higher than what the file holds is red too: the list
only shrinks, and it cannot outlive its sites.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CALL = re.compile(r"\bwriter_principal\s*\(")
DEF = re.compile(r"\bfn\s+writer_principal\s*\(")

# (file): (calls, why it is a WRITER / attribution / person-grouping site)
WRITERS = {
    "src/federation/admission.rs": (2, "cohort standing of a WRITER (party_identity_read, cohort_standing_resolved_verdict)"),
    "src/federation/mod.rs": (1, "check_write_cohort_scope_for: may this writer write to the room"),
    "src/ingest.rs": (1, "writer_admission: whose memberships a signed trace exercises"),
    "src/engine.rs": (1, "seal_trace_as: whose trace it is (attribution)"),
    "src/federation/blob_custody.rs": (1, "grouping devices by person: the lift only collapses"),
}


def strip(text):
    out = []
    for line in text.splitlines():
        i = line.find("//")
        out.append(line if i < 0 else line[:i])
    return "\n".join(out)


def count(text):
    text = strip(text)
    return len(CALL.findall(text)) - len(DEF.findall(text))


def scan(root):
    found = {}
    for p in sorted((root / "src").rglob("*.rs")):
        n = count(p.read_text(encoding="utf-8"))
        if n:
            found[p.relative_to(root).as_posix()] = n
    return found


def problems(found, writers):
    out = []
    for f, n in sorted(found.items()):
        if f not in writers:
            out.append(f"{f}: {n} call(s) of writer_principal outside WRITERS: a consent or standing check calls consenting_person / consenting_identity")
        elif n > writers[f][0]:
            out.append(f"{f}: {n} calls of writer_principal, WRITERS allows {writers[f][0]}")
    for f, (n, _) in sorted(writers.items()):
        if found.get(f, 0) < n:
            out.append(f"{f}: WRITERS allows {n}, the file holds {found.get(f, 0)}: lower the entry (the list only shrinks)")
    return out


def self_test():
    cases = [
        ("a comment is not a call", "// writer_principal(x)\n/// writer_principal(y)", 0),
        ("the definition is not a call", "pub async fn writer_principal(d: &D) {}", 0),
        ("a call", "let p = writer_principal(dir, k).await?;", 1),
        ("a qualified call", "admission::writer_principal (dir, k)", 1),
        ("another name", "let p = my_writer_principal_x(dir);", 0),
    ]
    bad = [name for name, text, want in cases if count(text) != want]
    w = {"a.rs": (1, "")}
    checks = [
        ("clean", problems({"a.rs": 1}, w) == []),
        ("a new file is red", len(problems({"a.rs": 1, "b.rs": 1}, w)) == 1),
        ("a grown count is red", len(problems({"a.rs": 2}, w)) == 1),
        ("a stale entry is red", len(problems({}, w)) == 1),
    ]
    bad += [name for name, ok in checks if not ok]
    if bad:
        print("one_consent self-test RED:", "; ".join(bad))
        return 1
    print(f"one_consent self-test: {len(cases) + len(checks)}/{len(cases) + len(checks)}")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    found = scan(ROOT)
    if argv[1:] == ["list"]:
        for f, n in sorted(found.items()):
            print(f'    "{f}": ({n}, "..."),')
        return 0
    if argv[1:] != ["check"]:
        print(__doc__)
        return 2
    bad = problems(found, WRITERS)
    for b in bad:
        print("RED", b)
    if bad:
        return 1
    print("GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
