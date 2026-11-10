#!/usr/bin/env python3
"""The tag run's test receipt (CIRISPersist v61.2.1): which `linux-x86_64-test`
rows a tag run skips when its PR run already passed the same tree.

    ci_tag_receipt.py linux-exclude <ci.yml>   # JSON for strategy.matrix.exclude
    ci_tag_receipt.py self-test                 # the parser against fixtures

`linux-exclude` prints `[{"substrate": <row>}, ...]` for every row of the
`linux-x86_64-test` job's `matrix.substrate` list EXCEPT `core-1`, which runs on
every tag because it carries the only Linux CIRISCache save (#895). Each entry
is the row itself, parsed from the workflow, so it equals the matrix object it
excludes; nothing here is a second list of the legs.

Exits non-zero (and the `tree` job then runs every leg) when the job, the
list, or `core-1` cannot be found, or a row does not parse. No PyYAML: the
runner's python3 has no guaranteed yaml module, and the rows are one-line
flow mappings of scalars, which is all this reads.
"""
import json
import re
import sys

KEEP = "core-1"
JOB = "linux-x86_64-test"
ROW = re.compile(r"^\s*-\s*\{(?P<body>[^{}]*)\}\s*(#.*)?$")


def scalar(text):
    text = text.strip()
    if text in ("true", "false"):
        return text == "true"
    if re.fullmatch(r"-?[0-9]+", text):
        return int(text)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    if not text or any(c in text for c in "[]{}&*!|>%@`"):
        raise ValueError(f"unsupported matrix scalar {text!r}")
    return text


def rows(workflow_text):
    lines = workflow_text.splitlines()
    try:
        start = lines.index(f"  {JOB}:")
    except ValueError:
        raise SystemExit(f"no job {JOB!r} in the workflow")
    out, in_list = [], False
    for line in lines[start + 1:]:
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            break  # the next job
        if re.match(r"^\s+substrate:\s*$", line):
            in_list = True
            continue
        if not in_list:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = ROW.match(line)
        if not m:
            break  # the list ended
        row = {}
        for part in m.group("body").split(","):
            key, sep, value = part.partition(":")
            if not sep or not key.strip():
                raise ValueError(f"unparsed matrix row {line.strip()!r}")
            row[key.strip()] = scalar(value)
        out.append(row)
    if not out:
        raise SystemExit(f"no matrix.substrate rows under {JOB!r}")
    names = [r.get("name") for r in out]
    if KEEP not in names or len(set(names)) != len(names):
        raise SystemExit(f"rows {names!r}: {KEEP!r} missing or a name repeats")
    return out


def linux_exclude(workflow_text):
    return [{"substrate": r} for r in rows(workflow_text) if r["name"] != KEEP]


def self_test():
    fixture = """jobs:
  tree:
    runs-on: ubuntu-latest
  linux-x86_64-test:
    strategy:
      matrix:
        substrate:
          # a comment between rows
          - { name: core-1,     leg: core,       gauntlet: true,  part: 1, parts: 2 }
          - { name: core-2,     leg: core,       gauntlet: true,  part: 2, parts: 2 }

          - { name: secrets,    leg: secrets,    gauntlet: false }
    steps: []
  next-job:
    substrate:
      - { name: elsewhere, leg: x }
"""
    got = linux_exclude(fixture)
    want = [
        {"substrate": {"name": "core-2", "leg": "core", "gauntlet": True, "part": 2, "parts": 2}},
        {"substrate": {"name": "secrets", "leg": "secrets", "gauntlet": False}},
    ]
    assert got == want, got
    for broken in (fixture.replace("core-1", "core-9"), fixture.replace("linux-x86_64-test", "x")):
        try:
            linux_exclude(broken)
        except SystemExit:
            pass
        else:
            raise AssertionError("a broken workflow must refuse")
    try:
        linux_exclude(fixture.replace("leg: secrets,", "leg: [secrets],"))
    except ValueError:
        pass
    else:
        raise AssertionError("an unsupported scalar must refuse")
    print("ci_tag_receipt self-test ok")


def main(argv):
    if argv[1:2] == ["self-test"]:
        self_test()
        return 0
    if len(argv) == 3 and argv[1] == "linux-exclude":
        with open(argv[2], encoding="utf-8") as fh:
            print(json.dumps(linux_exclude(fh.read()), separators=(",", ":")))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
