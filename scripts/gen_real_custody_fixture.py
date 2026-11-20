#!/usr/bin/env python3
"""gen_real_custody_fixture.py — the REAL accord-holder custody fixture.

    python3 scripts/gen_real_custody_fixture.py <genesis_2.json> [--check]

Writes `src/federation/edition2/fixture_genesis_real_custody.rs` from the
July 2026 holder records (A1, B1, C1) in the trust-root genesis file
`genesis_2.json` (2026-07-30, version 2). Only PUBLIC material is lifted:
each holder's YubiKey PIV slot-9c attestation leaf, the shared attestation
chain above it (`[f9, Yubico PIV Attestation B 1, Yubico Attestation
Intermediate B 1]`), and the two public-key halves. No signature, no
envelope, nothing secret.

Refuses (exit 1) unless:
- the input's SHA-256 is GENESIS_2_SHA256 (the hash CIRISServer pins);
- each leaf and chain cert hashes to what the holder's own signed custody
  envelope commits to (`yubikey_piv_attestation_9c_sha256`,
  `yubikey_attestation_chain_sha256`);
- the public-key halves have the composite's lengths (1952 + 32).

`--check` compares instead of writing (exit 1 on a difference). No cargo.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

GENESIS_2_SHA256 = "5c474b7993d0c148336da47fd7958baa0a0840521faaf0c2d534a2df9e766972"
OUT = Path(__file__).resolve().parent.parent / "src/federation/edition2/fixture_genesis_real_custody.rs"
OID_SERIAL = bytes.fromhex("2b0601040182c40a0307")  # 1.3.6.1.4.1.41482.3.7
WIDTH = 96


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def tlv(b: bytes):
    """One DER TLV: (tag, contents, rest). Single-byte tags, definite lengths."""
    tag, l0 = b[0], b[1]
    if l0 < 0x80:
        n, i = l0, 2
    else:
        k = l0 & 0x7F
        n, i = int.from_bytes(b[2:2 + k], "big"), 2 + k
    return tag, b[i:i + n], b[i + n:]


def serial_of(leaf: bytes) -> int:
    """The leaf's `1.3.6.1.4.1.41482.3.7` token serial (the DER INTEGER its
    OCTET STRING wraps). Read from the bytes, never typed in by hand."""
    _, cert, _ = tlv(leaf)
    _, tbs, _ = tlv(cert)
    while tbs:
        tag, body, tbs = tlv(tbs)
        if tag != 0xA3:
            continue
        _, exts, _ = tlv(body)
        while exts:
            _, ext, exts = tlv(exts)
            _, oid, rest = tlv(ext)
            if oid != OID_SERIAL:
                continue
            tag, val, rest2 = tlv(rest)
            if tag == 0x01:
                tag, val, _ = tlv(rest2)
            assert tag == 0x04
            itag, num, _ = tlv(val)
            assert itag == 0x02
            return int.from_bytes(num, "big")
    raise SystemExit("a leaf carries no 1.3.6.1.4.1.41482.3.7 serial")


def lit(hex_text: str, indent: str) -> str:
    parts = [hex_text[i:i + WIDTH] for i in range(0, len(hex_text), WIDTH)]
    inner = "".join(f'{indent}    "{p}",\n' for p in parts)
    return f"concat!(\n{inner}{indent})"


def b64lit(text: str, indent: str) -> str:
    parts = [text[i:i + WIDTH] for i in range(0, len(text), WIDTH)]
    inner = "".join(f'{indent}    "{p}",\n' for p in parts)
    return f"concat!(\n{inner}{indent})"


def generate(raw: bytes) -> str:
    if sha(raw) != GENESIS_2_SHA256:
        raise SystemExit(f"genesis_2.json is {sha(raw)}, not the pinned {GENESIS_2_SHA256}")
    g = json.loads(raw)
    holders, chain = [], None
    for h in g["holders"]:
        r = h["record"]
        name = r["key_id"]
        body = r["attestation_evidence"]["body"]
        env = body["signed_envelope"]
        leaf = bytes.fromhex(body["yubikey_piv_attestation_9c_hex"])
        c = [bytes.fromhex(x) for x in body["yubikey_attestation_chain_hex"]]
        if sha(leaf) != env["yubikey_piv_attestation_9c_sha256"]:
            raise SystemExit(f"{name}: the 9c leaf is not the one its envelope commits to")
        if [sha(x) for x in c] != env["yubikey_attestation_chain_sha256"]:
            raise SystemExit(f"{name}: the chain is not the one its envelope commits to")
        if len(c) != 3:
            raise SystemExit(f"{name}: the chain above the leaf is {len(c)} certs, not 3")
        if chain is None:
            chain = c
        elif chain != c:
            # The fixture carries ONE shared chain; a holder whose chain
            # differs needs the fixture reshaped, not silently merged.
            raise SystemExit(f"{name}: its chain differs from the first holder's")
        ed = base64.b64decode(r["pubkey_ed25519_base64"])
        mldsa = base64.b64decode(r["pubkey_ml_dsa_65_base64"])
        if len(ed) != 32 or len(mldsa) != 1952:
            raise SystemExit(f"{name}: public-key halves are {len(mldsa)} + {len(ed)} bytes")
        if env["ed25519_public_key_base64"] != r["pubkey_ed25519_base64"]:
            raise SystemExit(f"{name}: the envelope attests another Ed25519 key")
        holders.append((name, leaf, r["pubkey_ed25519_base64"], r["pubkey_ml_dsa_65_base64"]))
    serials = [serial_of(leaf) for _, leaf, _, _ in holders]
    if len(set(serials)) != len(serials):
        # CC 4.2.3 "One device per holder": the July holders must name three
        # devices. A capture that repeats one needs a decision, not a fixture.
        raise SystemExit(f"two holders' leaves name one serial: {serials}")
    out = [
        "//! GENERATED by `scripts/gen_real_custody_fixture.py`: do not edit.",
        "//!",
        "//! v62.0.0 (C4-fix, ceremony gap 3; CC 4.2.2.1) — the REAL accord-holder",
        "//! custody evidence: the YubiKey PIV slot-9c attestation leaves of the July",
        "//! 2026 holders A1, B1 and C1, the 4-cert path above them",
        "//! (`[f9, Yubico PIV Attestation B 1, Yubico Attestation Intermediate B 1]`,",
        "//! to Verify's baked `Yubico Attestation Root 1`), and each holder's public",
        "//! key halves. Lifted verbatim from `genesis_2.json` (SHA-256",
        "//! [`GENESIS_2_SHA256`]); every certificate is the one its holder's signed",
        "//! custody envelope commits to. Public certificates and public keys only.",
        "//!",
        "//! The edition-2 fixtures before this one ([`super::fixture_genesis_custody`])",
        "//! are MOCK 2-cert chains: this file is what keeps the custody path from",
        "//! being proven only against evidence written to satisfy it (#554).",
        "//!",
        "//! All three holders' `f9` certificate is byte-identical, and the three",
        "//! leaves name three token serials (`1.3.6.1.4.1.41482.3.7`). CC 4.2.3",
        "//! \"One device per holder\" (rc21 ad52eb6) judges the device by the",
        "//! leaf's serial; a shared `f9` or intermediate is not a shared device.",
        "",
        "/// SHA-256 of the `genesis_2.json` the bytes were lifted from.",
        "pub const GENESIS_2_SHA256: &str =",
        f'    "{GENESIS_2_SHA256}";',
        "",
        "/// One July holder's public custody material.",
        "#[derive(Clone, Copy, Debug)]",
        "pub struct RealHolder {",
        "    /// The July key id (`A1`, `B1`, `C1`).",
        "    pub name: &'static str,",
        "    /// The slot-9c attestation leaf (DER, hex).",
        "    pub leaf_9c_hex: &'static str,",
        "    /// SHA-256 of the leaf's DER, as the holder's envelope commits to it.",
        "    pub leaf_9c_sha256: &'static str,",
        "    /// The leaf's `1.3.6.1.4.1.41482.3.7` token serial (read from the DER).",
        "    pub serial: u32,",
        "    /// The Ed25519 public key (base64), the key the leaf attests.",
        "    pub ed25519_b64: &'static str,",
        "    /// The ML-DSA-65 public key (base64, 1952 bytes).",
        "    pub mldsa65_b64: &'static str,",
        "}",
        "",
        "/// The chain above every leaf, leaf-first: `[f9, Yubico PIV Attestation B 1,",
        "/// Yubico Attestation Intermediate B 1]` (DER, hex). Shared by all three.",
        "pub const REAL_CHAIN_HEX: [&str; 3] = [",
    ]
    for c in chain:
        out.append(f"    {lit(c.hex(), '    ')},")
    out += [
        "];",
        "",
        "/// SHA-256 of each [`REAL_CHAIN_HEX`] certificate's DER.",
        "pub const REAL_CHAIN_SHA256: [&str; 3] = [",
    ]
    out += [f'    "{sha(c)}",' for c in chain]
    out += ["];", "", "/// The three July holders, in genesis order.", "pub const REAL_HOLDERS: [RealHolder; 3] = ["]
    for name, leaf, ed, mldsa in holders:
        out += [
            "    RealHolder {",
            f'        name: "{name}",',
            f"        leaf_9c_hex: {lit(leaf.hex(), '        ')},",
            f'        leaf_9c_sha256: "{sha(leaf)}",',
            f"        serial: {serial_of(leaf)},",
            f'        ed25519_b64: "{ed}",',
            f"        mldsa65_b64: {b64lit(mldsa, '        ')},",
            "    },",
        ]
    out += ["];", ""]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    text = generate(Path(argv[1]).read_bytes())
    if argv[2:3] == ["--check"]:
        if OUT.read_text() != text:
            print(f"{OUT.name} is stale against {argv[1]}", file=sys.stderr)
            return 1
        print(f"{OUT.name} is current")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
