#!/usr/bin/env python3
"""
ciris_manifest — generate / sign / register build manifests for any CIRIS project.

VENDORED COPY. The canonical source belongs in a shared location
(planned: refactor of `~/CIRISAgent/tools/ops/register_agent_build.py`
into `tools/ops/ciris_manifest.py`; see this repo's
`docs/TODO_REGISTRY.md` and the tracking issue at
github.com/CIRISAI/CIRISAgent/issues/<TBD>). Until that refactor
lands, every CIRIS Rust project vendors a copy of this script,
keeping the schema in sync via the SCHEMA_VERSION constant.

Three independent stages:

    generate   — walk the project tree, hash files, emit unsigned manifest JSON.
                 Deterministic. No secrets. Runnable from any CI job.
    sign       — read manifest, Ed25519-sign the canonical bytes, write
                 manifest with signature populated. Uses CIRIS_BUILD_SIGN_KEY
                 env var (32-byte seed in standard base64 — same shape
                 ciris-keyring uses, so swap to a real keyring CLI is a
                 drop-in when CIRISVerify ships one).
    register   — push signed manifest to CIRISRegistry's gRPC. NOT YET
                 IMPLEMENTED for ciris-persist; the registry needs
                 persist-side support first. See `docs/TODO_REGISTRY.md`.

Manifest schema matches `CIRISVerify/src/ciris-manifest-tool` for the
signature shape (Ed25519 today; ML-DSA-65 hybrid is Phase 2+ per
PoB §6).

Usage:

    ciris_manifest.py generate \\
        --project ciris-persist \\
        --root . \\
        --version 0.1.3 \\
        --modules core \\
        --source-repo https://github.com/CIRISAI/CIRISPersist \\
        --source-commit "$(git rev-parse HEAD)" \\
        --output dist/ciris-persist-0.1.3.manifest.json

    ciris_manifest.py sign \\
        --manifest dist/ciris-persist-0.1.3.manifest.json \\
        --key-id ciris-persist-build-v1 \\
        --output dist/ciris-persist-0.1.3.manifest.signed.json

    ciris_manifest.py register \\
        --signed-manifest dist/ciris-persist-0.1.3.manifest.signed.json
    # → exits 99 with a structured TODO message until registry support lands.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

# Project-agnostic exempts. Add project-specific extras via --extra-exempt-dir
# or --extra-exempt-ext on the command line.
DEFAULT_EXEMPT_DIRS: set[str] = {
    "__pycache__",
    ".git",
    ".github",
    ".venv",
    "venv",
    "node_modules",
    "logs",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".ruff_cache",
    ".coverage",
    ".tox",
    ".nox",
    "target",  # Rust build dir
    ".cargo",
    "vendor",
}

DEFAULT_EXEMPT_EXTENSIONS: set[str] = {
    ".env",
    ".log",
    ".audit",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pyc",
    ".pyo",
    ".rmeta",
    ".rlib",
    ".o",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
}

DEFAULT_EXEMPT_NAMES: set[str] = {
    ".DS_Store",
    "Thumbs.db",
    ".coverage",
}


def is_exempt(
    relative_path: str,
    exempt_dirs: set[str],
    exempt_exts: set[str],
    exempt_names: set[str],
) -> bool:
    path = Path(relative_path)

    if path.suffix in exempt_exts or path.name in exempt_exts:
        return True
    if path.name in exempt_names:
        return True
    for part in path.parts:
        if part in exempt_dirs:
            return True
        if part.endswith(".egg-info"):
            return True
    return False


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def walk_files(
    root: Path,
    subdirs: list[str] | None,
    exempt_dirs: set[str],
    exempt_exts: set[str],
    exempt_names: set[str],
) -> dict[str, str]:
    """Walk root (or root/<subdirs>) and hash every non-exempt file.

    Returns dict[relative_path → "sha256:hex"] sorted by path.
    """
    files: dict[str, str] = {}
    scan_dirs = (
        [root / s for s in subdirs if (root / s).exists()]
        if subdirs
        else [root]
    )
    for scan_dir in scan_dirs:
        for cur, dirs, filenames in os.walk(scan_dir):
            dirs[:] = [
                d for d in dirs
                if d not in exempt_dirs and not d.endswith(".egg-info")
            ]
            for filename in filenames:
                file_path = Path(cur) / filename
                rel = str(file_path.relative_to(root)).replace("\\", "/")
                if is_exempt(rel, exempt_dirs, exempt_exts, exempt_names):
                    continue
                try:
                    files[rel] = hash_file(file_path)
                except (PermissionError, OSError) as e:
                    print(f"WARN skip {rel}: {e}", file=sys.stderr)
    return dict(sorted(files.items()))


def manifest_hash(files: dict[str, str]) -> str:
    """sha256(concat(file_hash for file_hash in sorted-by-path values))."""
    h = hashlib.sha256()
    for fh in files.values():
        h.update(fh.encode("ascii"))
    return f"sha256:{h.hexdigest()}"


def canonical_for_signing(manifest: dict[str, Any]) -> bytes:
    """Canonical bytes for signing — same shape as the wire-format
    canonicalization (json.dumps with sort_keys + tight separators).

    The `signature` field is excluded — we sign everything *except*
    the signature itself, the signature lands in that field after.
    """
    sub = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(sub, sort_keys=True, separators=(",", ":")).encode("utf-8")


def cmd_generate(args: argparse.Namespace) -> int:
    extra_dirs = set(args.extra_exempt_dir or [])
    extra_exts = set(args.extra_exempt_ext or [])
    exempt_dirs = DEFAULT_EXEMPT_DIRS | extra_dirs
    exempt_exts = DEFAULT_EXEMPT_EXTENSIONS | extra_exts
    exempt_names = DEFAULT_EXEMPT_NAMES

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"ERROR: root {root} is not a directory", file=sys.stderr)
        return 2

    files = walk_files(root, args.include_dir, exempt_dirs, exempt_exts, exempt_names)
    if not files:
        print(f"ERROR: no files matched under {root}", file=sys.stderr)
        return 2

    mh = manifest_hash(files)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "project": args.project,
        "version": args.version,
        "build_hash": mh,  # alias for manifest_hash for now
        "manifest_hash": mh,
        "files": files,
        "modules": args.modules or ["core"],
        "source_repo": args.source_repo or "",
        "source_commit": args.source_commit or "",
        "registered_at": int(datetime.now(timezone.utc).timestamp()),
        # Empty signature — populated by `sign` stage.
        "signature": {
            "classical": "",
            "classical_algorithm": "Ed25519",
            "key_id": "",
        },
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    print(
        f"OK generated manifest: {out}\n"
        f"  project: {args.project}\n"
        f"  version: {args.version}\n"
        f"  files: {len(files)}\n"
        f"  manifest_hash: {mh[:24]}…"
    )
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    seed_b64 = os.environ.get("CIRIS_BUILD_SIGN_KEY")
    if not seed_b64:
        print(
            "ERROR: CIRIS_BUILD_SIGN_KEY env var unset (Ed25519 32-byte seed in base64)\n"
            "       set the secret on this CI workflow, or use --allow-unsigned\n"
            "       to emit an unsigned manifest (NOT recommended for production).",
            file=sys.stderr,
        )
        if not args.allow_unsigned:
            return 3

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError:
        print(
            "ERROR: 'cryptography' package required for signing\n"
            "       pip install cryptography>=42",
            file=sys.stderr,
        )
        return 4

    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text())

    if args.allow_unsigned and not seed_b64:
        manifest["signature"]["classical"] = ""
        manifest["signature"]["key_id"] = "UNSIGNED"
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")
        print(f"WARN emitted unsigned manifest (CI secret unset): {out}")
        return 0

    try:
        seed = base64.b64decode(seed_b64, validate=True)
    except Exception as e:
        print(f"ERROR: CIRIS_BUILD_SIGN_KEY is not valid base64: {e}", file=sys.stderr)
        return 5
    if len(seed) != 32:
        print(
            f"ERROR: CIRIS_BUILD_SIGN_KEY must decode to 32 bytes (got {len(seed)})",
            file=sys.stderr,
        )
        return 5

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    payload = canonical_for_signing(manifest)
    sig = sk.sign(payload)
    manifest["signature"]["classical"] = base64.b64encode(sig).decode("ascii")
    manifest["signature"]["classical_algorithm"] = "Ed25519"
    manifest["signature"]["key_id"] = args.key_id

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    print(
        f"OK signed manifest: {out}\n"
        f"  key_id: {args.key_id}\n"
        f"  signed_bytes: {len(payload)}\n"
        f"  signature: {manifest['signature']['classical'][:32]}…"
    )
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    print(
        "TODO(persist→registry): registry support for project='ciris-persist'\n"
        "  is not yet implemented. The CIRISRegistry gRPC service needs a\n"
        "  RegisterProjectBuild (or RegisterCirisPersistBuild) endpoint that\n"
        "  accepts the v0.1.3 signed-manifest schema. Track in\n"
        "  docs/TODO_REGISTRY.md + the CIRISAgent tracking issue for the\n"
        "  cross-repo refactor.",
        file=sys.stderr,
    )
    return 99


def main() -> int:
    p = argparse.ArgumentParser(prog="ciris_manifest")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="walk + hash + write unsigned manifest JSON")
    g.add_argument("--project", required=True, help="project slug, e.g. ciris-persist")
    g.add_argument("--root", required=True, help="project root path to scan")
    g.add_argument("--version", required=True, help="release version")
    g.add_argument(
        "--modules",
        nargs="+",
        help="modules included (default: ['core'])",
    )
    g.add_argument("--source-repo", default="", help="git remote URL")
    g.add_argument("--source-commit", default="", help="git rev-parse HEAD")
    g.add_argument(
        "--include-dir",
        nargs="+",
        help="restrict scan to these subdirs (default: all of root)",
    )
    g.add_argument(
        "--extra-exempt-dir",
        nargs="+",
        help="additional dir names to exclude",
    )
    g.add_argument(
        "--extra-exempt-ext",
        nargs="+",
        help="additional file extensions to exclude (e.g., .swp)",
    )
    g.add_argument("--output", required=True, help="output JSON path")
    g.set_defaults(func=cmd_generate)

    s = sub.add_parser("sign", help="Ed25519-sign a manifest from CIRIS_BUILD_SIGN_KEY")
    s.add_argument("--manifest", required=True, help="path to unsigned manifest JSON")
    s.add_argument(
        "--key-id",
        required=True,
        help="key id stamped into the signature (e.g. ciris-persist-build-v1)",
    )
    s.add_argument("--output", required=True, help="output path for signed manifest")
    s.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="emit manifest with empty signature when CIRIS_BUILD_SIGN_KEY "
             "is unset (use only during initial CI bootstrap)",
    )
    s.set_defaults(func=cmd_sign)

    r = sub.add_parser("register", help="(NOT YET IMPLEMENTED) push to Registry")
    r.add_argument("--signed-manifest", required=True)
    r.add_argument("--registry-addr", default="")
    r.set_defaults(func=cmd_register)

    args = p.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
