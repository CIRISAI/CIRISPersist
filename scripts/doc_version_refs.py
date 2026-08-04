#!/usr/bin/env python3
"""Every `vX.Y.Z` a doc comment names must be a version that actually shipped.

WHY THIS EXISTS. v28.3.0 found **30 references across 12 files to `v25.2.0`, a
version that was never released.** They were written by agents during the cut
that became **26.0.0**, each anticipating a minor bump that went out as a major.
Nothing noticed for three majors.

A doc comment saying "v25.2.0 changed X" is worse than no comment. A reader
correlating behaviour with a release cannot find that release, cannot find its
CHANGELOG entry, and cannot `git checkout` its tag. And the failure is silent
and self-propagating: the next agent greps for the convention, copies the
phantom string, and adds to it.

WHAT THIS CHECKS. Every `vX.Y.Z` in a Rust comment inside `src/` must appear as
a released `## [X.Y.Z]` header in CHANGELOG.md. The version being cut right now
counts, because its CHANGELOG entry is written in the same commit that bumps
Cargo.toml -- which is exactly when the forward references get written.

WHAT THIS DELIBERATELY DOES NOT CHECK. Versions of OTHER crates: `ciris-verify
v12.5.0`, `CEG 0.3`, `pyo3 0.29`. Only bare `vX.Y.Z` tokens, which is this
repo's own convention for its own releases. A reference to another project's
version is qualified by that project's name and is skipped by the NAMED_CRATE
guard below.

Exit 0 = every referenced version shipped. Exit 1 = at least one did not, and
the message names the file, the line, and the phantom version.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# `v` + semver, not preceded by a word char (so `rc3-v1` / `CEG-0.3` are out)
VERSION_RE = re.compile(r"(?<![\w.])v(\d+)\.(\d+)\.(\d+)\b")
# A comment line -- doc (`///`, `//!`) or plain (`//`). Version strings inside
# string literals are code, not documentation, and are not this gate's business.
COMMENT_RE = re.compile(r"^\s*(///|//!|//)")
# Another project's version, qualified by its name somewhere earlier on the line.
NAMED_CRATE = re.compile(
    r"(ciris[-_](verify|crypto|keyring)|CIRISVerify|pyo3|CEG|agent|verify)\s*[@ ]?\s*v?$",
    re.IGNORECASE,
)


def released_versions() -> set[str]:
    """Versions that shipped: a CHANGELOG entry OR a git tag.

    Both, because they disagree at the edges -- the CHANGELOG does not reach
    back to the earliest tags, and the cut in flight has an entry before it has
    a tag. A version in either is real.
    """
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    out = set(re.findall(r"^##\s*\[(\d+\.\d+\.\d+)\]", text, re.MULTILINE))
    try:
        tags = subprocess.run(
            ["git", "tag"], capture_output=True, text=True, cwd=ROOT, check=True
        ).stdout.split()
        out |= {t[1:] for t in tags if re.fullmatch(r"v\d+\.\d+\.\d+", t)}
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass  # CHANGELOG alone still gates; a tagless checkout is not a failure
    return out


def baseline() -> set[str]:
    """The RATCHET.

    223 references to 26 never-shipped versions already existed when this gate
    was written -- `v12.7.0` alone has 93. Fixing them correctly means deciding,
    per reference, which release the work actually landed in, and that is a
    burndown (CIRISPersist#599), not a release-day edit.

    So they are grandfathered BY VERSION and anything new fails. The bleeding
    stops today; the backlog drains on its own schedule. A baseline that is
    never allowed to grow is a ratchet; one that gets appended to is a
    suppression file, which is why the gate refuses to write this itself.
    """
    path = ROOT / "evidence" / "doc_version_baseline.tsv"
    if not path.exists():
        sys.exit(f"missing ratchet baseline: {path}")
    out = set()
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.startswith("#") or not line.strip():
            continue
        out.add(line.split("\t")[0])
    return out


def current_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        sys.exit("could not read version from Cargo.toml")
    return m.group(1)


def main() -> int:
    known = released_versions()
    cur = current_version()
    known.add(cur)  # the cut in flight; its CHANGELOG entry lands in this commit
    grandfathered = baseline()

    if len(known) < 5:
        # Non-vacuity. A CHANGELOG parse change would otherwise empty this gate
        # and turn every reference into a phantom -- or, worse, if the regex
        # stopped matching, turn the gate green forever.
        print(
            f"✗ only {len(known)} released versions parsed from CHANGELOG.md — "
            "the parse is broken, not the references.",
            file=sys.stderr,
        )
        return 1

    bad: list[tuple[str, int, str, str]] = []
    scanned = 0
    for path in sorted((ROOT / "src").rglob("*.rs")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if not COMMENT_RE.match(line):
                continue
            for m in VERSION_RE.finditer(line):
                scanned += 1
                ver = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
                prefix = line[: m.start()]
                if NAMED_CRATE.search(prefix):
                    continue
                if ver not in known and ver not in grandfathered:
                    bad.append(
                        (str(path.relative_to(ROOT)), lineno, ver, line.strip()[:100])
                    )

    if bad:
        print(
            f"✗ {len(bad)} doc reference(s) name a version that never shipped:\n",
            file=sys.stderr,
        )
        for f, ln, ver, text in bad:
            print(f"  {f}:{ln}  v{ver}\n      {text}", file=sys.stderr)
        print(
            "\n  A version with no tag and no CHANGELOG entry never shipped. Usually the\n"
            "  reference means the cut the work actually landed in — which may have been a\n"
            "  BIGGER bump than anticipated when the comment was written. That is exactly\n"
            "  how v25.2.0 came to be cited 30 times: written during the cut that shipped\n"
            "  as 26.0.0.\n\n"
            "  Do NOT add it to evidence/doc_version_baseline.tsv. That file is a ratchet\n"
            "  being burned down (CIRISPersist#599); appending to it makes it a suppression\n"
            "  file and this gate decorative.",
            file=sys.stderr,
        )
        return 1

    stale = sorted(grandfathered & known)
    if stale:
        print(
            f"✗ {len(stale)} baseline entr(ies) now name a SHIPPED version: "
            f"{', '.join('v' + s for s in stale)}\n"
            "  Remove them from evidence/doc_version_baseline.tsv — a ratchet that keeps "
            "grandfathering\n  versions which have since become real only hides the next "
            "phantom behind them.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK {scanned} version reference(s) in src/ doc comments name released versions "
        f"({len(known)} known, current {cur}); {len(grandfathered)} grandfathered "
        f"version(s) pending burndown (CIRISPersist#599)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
