#!/usr/bin/env python3
"""v62 (slice C2) -- the test ceremony's holder custody evidence.

Writes `src/federation/edition2/fixture_genesis_custody.rs`: the mock YubiKey
PIV attestation root and, for each test holder seed n in HOLDERS, the chain
[9c leaf, f9] attesting the Ed25519 half of the composite test key n
(ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32).

The PKI is CIRISVerify v23.3.0's vector PKI, reproduced exactly
(`tests/vectors/edition2/genesis/gen_genesis_bundles_v2.py`, `CA`, `cert`,
`yubikey_chain`). Ed25519 signing is deterministic, so the bytes are a pure
function of the seeds. With `--check-verify <pool dir>` the chains of the
holders Verify's vectors also carry (1, 2, 3, 4, and holder 1's recovered
key 41 and recovery key 51) must appear byte for byte in
Verify's pool, and the root must equal the case file's
`attestation_root_der`.

Test-only evidence: the root says "MOCK" in its name and is trusted only by a
reader handed it as its attestation store.

Needs pyca/cryptography. Calls no cargo.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID

HOLDERS = [1, 2, 3, 4, 5, 6, 7]
# After a recovery, holder n signs with key n + 40 (Verify's A_NEW = 41 for A = 1);
# its chain carries the holder's own f9 (labelled n).
RECOVERED_OFFSET = 40
# Holder n's first recovery key is key n + 50 (Verify's REC). Its chain exists
# only so a witness can offer a recovery that seats the recovery key itself
# as the signing key (Verify's `recA_rk`), which the reader refuses.
RECOVERY_KEY_OFFSET = 50
# After a SECOND recovery, holder n signs with key n + 80 (not in Verify's
# vectors, which use 42 for holder 1; 80 keeps every holder's keys disjoint).
SECOND_RECOVERED_OFFSET = 80
NB = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NA = datetime.datetime(2099, 12, 31, tzinfo=datetime.timezone.utc)
OID_FW, OID_TOUCH, OID_FIPS = (
    "1.3.6.1.4.1.41482.3.3",
    "1.3.6.1.4.1.41482.3.8",
    "1.3.6.1.4.1.41482.3.10",
)
# v62.0.0 (C4-fix2; CC 4.2.3 "One device per holder") — the token serial, a
# bare DER INTEGER as a real YubiKey leaf carries it. The tables above carry
# none (Verify's vector PKI); SERIAL_CHAINS carries one per holder.
OID_SERIAL = "1.3.6.1.4.1.41482.3.7"
# Holder n's serial in SERIAL_CHAINS; SHARED_SERIAL gives holder 2 holder 1's.
SERIAL_HOLDERS = [1, 2, 3]
SERIAL_BASE = 1000


def der_uint(n):
    body = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return bytes([0x02, len(body)]) + body


def sha(b):
    return hashlib.sha256(b).digest()


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, issuer, pub, signer, serial, exts=()):
    b = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(pub)
        .serial_number(serial)
        .not_valid_before(NB)
        .not_valid_after(NA)
    )
    for oid, val in exts:
        b = b.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), val), critical=False
        )
    return b.sign(signer, None).public_bytes(ser.Encoding.DER)


class CA:
    def __init__(self, label):
        self.key = Ed25519PrivateKey.from_private_bytes(sha(label.encode()))
        self.cn = label
        self.der = cert(label, label, self.key.public_key(), self.key, 1)


ROOT = CA("Yubico PIV Attestation (MOCK root, test only)")


def ed_pub(n):
    k = Ed25519PrivateKey.from_private_bytes(bytes([(n + 100) % 256]) * 32)
    return k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def yubikey_chain(ed_pub_bytes, n, ca=ROOT, fips=True, touch=2, serial=None):
    f9k = Ed25519PrivateKey.from_private_bytes(sha(b"f9" + bytes([n]) + ca.cn.encode()))
    f9cn = "YubiKey PIV Attestation f9 (MOCK %d)" % n
    f9 = cert(f9cn, ca.cn, f9k.public_key(), ca.key, 100 + n, [(OID_FIPS, b"")] if fips else [])
    leaf = cert(
        "YubiKey PIV Attestation 9c (MOCK %d)" % n,
        f9cn,
        Ed25519PublicKey.from_public_bytes(ed_pub_bytes),
        f9k,
        200 + n,
        [(OID_FW, b"\x04\x03\x05\x07\x04"), (OID_TOUCH, b"\x04\x02\x01" + bytes([touch]))]
        + ([] if serial is None else [(OID_SERIAL, der_uint(serial))]),
    )
    return [leaf, f9]


def rust_bytes(b, indent="    "):
    """concat! arguments: one comma-terminated literal per 96 hex digits."""
    h = b.hex()
    return "\n".join('%s"%s",' % (indent, h[i : i + 96]) for i in range(0, len(h), 96))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="src/federation/edition2/fixture_genesis_custody.rs")
    ap.add_argument("--check-verify", help="Verify's tests/vectors/edition2/genesis directory")
    a = ap.parse_args()
    chains = {n: yubikey_chain(ed_pub(n), n) for n in HOLDERS}
    recovered = {n: yubikey_chain(ed_pub(n + RECOVERED_OFFSET), n) for n in HOLDERS}
    recovery = {n: yubikey_chain(ed_pub(n + RECOVERY_KEY_OFFSET), n) for n in HOLDERS}
    second = {n: yubikey_chain(ed_pub(n + SECOND_RECOVERED_OFFSET), n) for n in HOLDERS}
    serials = {n: yubikey_chain(ed_pub(n), n, serial=SERIAL_BASE + n) for n in SERIAL_HOLDERS}
    shared = yubikey_chain(ed_pub(2), 2, serial=SERIAL_BASE + 1)
    if a.check_verify:
        d = pathlib.Path(a.check_verify)
        case = json.loads((d / "genesis_bundles_v2.json").read_text())
        assert case["attestation_root_der"] == ROOT.der.hex(), "root differs from Verify's"
        pool = "".join(p.read_text() for p in sorted(d.glob("pool_v2_*.json")))
        for n in (1, 2, 3, 4):
            for c in chains[n]:
                assert c.hex() in pool, "chain %d differs from Verify's pool" % n
        for c in recovered[1]:
            assert c.hex() in pool, "the recovered chain of holder 1 (key 41) differs from Verify's pool"
        for c in recovery[1]:
            assert c.hex() in pool, "the recovery-key chain of holder 1 (key 51) differs from Verify's pool"
        print("checked: root, chains 1..4 and holder 1's recovered and recovery-key chains are byte-identical to Verify's vectors", file=sys.stderr)
    out = [
        "//! GENERATED by `scripts/gen_test_ceremony_v2_custody.py`: do not edit.",
        "//!",
        "//! The test ceremony's holder custody evidence (CC 4.2.2.1): the MOCK",
        "//! YubiKey PIV attestation root of CIRISVerify v23.3.0's genesis vectors,",
        "//! and for each test holder seed `n` the chain `[9c leaf, f9]` (hex, DER)",
        "//! attesting the Ed25519 half of the composite test key `n`. Trusted only",
        "//! by a reader handed [`MOCK_ATTESTATION_ROOT_HEX`] as its store.",
        "",
        "/// The MOCK attestation root (DER, hex).",
        "pub const MOCK_ATTESTATION_ROOT_HEX: &str = concat!(",
        rust_bytes(ROOT.der),
        ");",
        "",
        "/// The holder seeds a chain is carried for.",
        "pub const CHAIN_SEEDS: [u8; %d] = %s;" % (len(HOLDERS), str(HOLDERS)),
        "",
        "/// `(seed, [leaf hex, f9 hex])` per holder seed.",
        "pub const HOLDER_CHAINS_HEX: [(u8, [&str; 2]); %d] = [" % len(HOLDERS),
    ]
    for n in HOLDERS:
        leaf, f9 = chains[n]
        out += [
            "    (",
            "        %d," % n,
            "        [",
            "            concat!(",
            rust_bytes(leaf, " " * 16),
            "            ),",
            "            concat!(",
            rust_bytes(f9, " " * 16),
            "            ),",
            "        ],",
            "    ),",
        ]
    out += [
        "];",
        "",
        "/// The signing-key seed offset after a recovery: holder `n` re-seats key `n + %d`." % RECOVERED_OFFSET,
        "pub const RECOVERED_KEY_OFFSET: u8 = %d;" % RECOVERED_OFFSET,
        "",
        "/// `(holder seed, [leaf hex, f9 hex])`: the chain attesting the key holder `n`",
        "/// re-seats after a recovery (key `n + RECOVERED_KEY_OFFSET`).",
        "pub const RECOVERED_CHAINS_HEX: [(u8, [&str; 2]); %d] = [" % len(HOLDERS),
    ]
    for n in HOLDERS:
        leaf, f9 = recovered[n]
        out += chain_entry(n, leaf, f9)
    out += [
        "];",
        "",
        "/// `(holder seed, [leaf hex, f9 hex])`: a chain attesting holder `n`'s first",
        "/// recovery key (key `n + %d`), for the witness that a recovery seating the" % RECOVERY_KEY_OFFSET,
        "/// recovery key itself as the signing key is refused.",
        "pub const RECOVERY_KEY_CHAINS_HEX: [(u8, [&str; 2]); %d] = [" % len(HOLDERS),
    ]
    for n in HOLDERS:
        leaf, f9 = recovery[n]
        out += chain_entry(n, leaf, f9)
    out += [
        "];",
        "",
        "/// The signing-key seed offset after a SECOND recovery: key `n + %d`." % SECOND_RECOVERED_OFFSET,
        "pub const SECOND_RECOVERED_KEY_OFFSET: u8 = %d;" % SECOND_RECOVERED_OFFSET,
        "",
        "/// `(holder seed, [leaf hex, f9 hex])`: the chain attesting the key holder `n`",
        "/// re-seats after a second recovery (key `n + SECOND_RECOVERED_KEY_OFFSET`).",
        "pub const SECOND_RECOVERED_CHAINS_HEX: [(u8, [&str; 2]); %d] = [" % len(HOLDERS),
    ]
    for n in HOLDERS:
        leaf, f9 = second[n]
        out += chain_entry(n, leaf, f9)
    out += [
        "];",
        "",
        "/// v62.0.0 (C4-fix2; CC 4.2.3) — holder `n`'s serial in",
        "/// [`SERIAL_CHAINS_HEX`]: `%d + n`." % SERIAL_BASE,
        "pub const SERIAL_BASE: u64 = %d;" % SERIAL_BASE,
        "",
        "/// v62.0.0 (C4-fix2; CC 4.2.3 \"One device per holder\") — `(holder seed,",
        "/// [leaf hex, f9 hex])`: holder `n`'s chain whose leaf also names the token",
        "/// serial `SERIAL_BASE + n` (`1.3.6.1.4.1.41482.3.7`, a bare DER INTEGER as",
        "/// a real YubiKey leaf carries it). Same f9 as [`HOLDER_CHAINS_HEX`].",
        "pub const SERIAL_CHAINS_HEX: [(u8, [&str; 2]); %d] = [" % len(SERIAL_HOLDERS),
    ]
    for n in SERIAL_HOLDERS:
        leaf, f9 = serials[n]
        out += chain_entry(n, leaf, f9)
    leaf, f9 = shared
    out += [
        "];",
        "",
        "/// v62.0.0 (C4-fix2; CC 4.2.3) — holder 2's chain whose leaf names holder",
        "/// 1's serial (`SERIAL_BASE + 1`): a distinct leaf, the same device.",
        "pub const SHARED_SERIAL_CHAIN_HEX: [&str; 2] = [",
        "    concat!(",
        rust_bytes(leaf, " " * 8),
        "    ),",
        "    concat!(",
        rust_bytes(f9, " " * 8),
        "    ),",
        "];",
        "",
    ]
    pathlib.Path(a.out).write_text("\n".join(out))


def chain_entry(n, leaf, f9):
    return [
        "    (",
        "        %d," % n,
        "        [",
        "            concat!(",
        rust_bytes(leaf, " " * 16),
        "            ),",
        "            concat!(",
        rust_bytes(f9, " " * 16),
        "            ),",
        "        ],",
        "    ),",
    ]


if __name__ == "__main__":
    main()
