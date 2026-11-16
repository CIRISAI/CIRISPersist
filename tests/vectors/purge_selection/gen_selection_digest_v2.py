#!/usr/bin/env python3
"""Known answers for the forward purge selection digest (CC 2.4.1.1, CC 3.3.2;
the store's open encoding of CC 2.6.1.12, CIRISPersist#1274).

digest = SHA-256(CDE(array of text "plane:id")), the array a set sorted by the
bytewise order of each element's deterministic encoding (shorter first),
duplicates dropped. Independent of persist: a hand CBOR encoder, stdlib only.
Run: python3 -I gen_selection_digest_v2.py > selection_digest_v2.json
"""
import hashlib, json

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 0x100: return bytes([major << 5 | 24, n])
    if n < 0x10000: return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000: return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")

def text(s):
    b = s.encode("utf-8")
    return head(3, len(b)) + b

def preimage(ids):
    elems = sorted(set(text(i) for i in ids))
    return head(4, len(elems)) + b"".join(elems)

H = "ab" * 32
CASES = [
    ("empty", []),
    ("one", ["attestation:a1"]),
    ("length_first", ["attestation:zz", "trace:t", "blob:" + H]),
    ("duplicates_dropped", ["trace:t", "trace:t", "attestation:a"]),
    ("utf8_order_differs", ["trace:bb", "attestation:a", "trace:a"]),
    ("long_23_24_boundary", ["attestation:" + "x" * 11, "attestation:" + "x" * 12, "attestation:" + "x" * 244]),
    ("non_ascii", ["attestation:é", "attestation:z", "attestation:守"]),
]
out = {
    "vector": "ciris.purge_selection_digest.v2",
    "rule": "SHA-256 over CDE(array of tstr 'plane:id'); set sorted by each element's deterministic encoding (length first), unique; carried as bstr .size 32, hex in persist's columns",
    "cases": [],
}
for name, ids in CASES:
    p = preimage(ids)
    out["cases"].append({"id": name, "record_ids": ids, "preimage_hex": p.hex(),
                         "digest_hex": hashlib.sha256(p).hexdigest()})
print(json.dumps(out, indent=2, ensure_ascii=False))
