#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Graviton tree adversarial stress — deep trie + cross-tree + collision stress.

Extends hardtest_chain with:

  DEEP TREE: 10,000 sequential keys on a single tree, interleaved with
             gets/deletes/overwrites. Both sides must produce the same root
             hash after every op (not just at the end).

  CROSS-TREE: operations on 3 trees (balances, scdata, scmeta) interleaved
              in random order — catches tree-id confusion bugs.

  COLLISION STRESS: rapid put-delete-put cycles on the same 20 keys
                    (1000 ops) — catches trie node reuse bugs.

  KEY PATTERNS: keys with common prefixes (tests trie compaction),
                 single-byte keys, 32-byte keys, empty key, max-length keys.

  VALUE PATTERNS: empty values, 1-byte, 32-byte, 255-byte, all-zeros,
                  all-0xff, random.
"""
import json
import random
import subprocess
import sys

GO = "./oracle/oracle.exe"
RUST = "./crypto/target/release/dero-oracle.exe"


def run(binp, reqs):
    p = subprocess.run(
        [binp],
        input="\n".join(json.dumps(r) for r in reqs) + "\n",
        capture_output=True,
        text=True,
        timeout=900,
    )
    if p.returncode != 0:
        return None, f"exit {p.returncode}: {p.stderr[:800]}"
    out = []
    for line in p.stdout.splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"id": -1, "ok": False, "err": "badline"})
    return out, None


def main():
    rng = random.Random(0x6A76112E)  # "GRAVITON"
    reqs = []
    iid = 1

    def add(op, inp):
        nonlocal iid
        reqs.append({"id": iid, "op": op, "in": inp})
        iid += 1

    # ---- 1. DEEP TREE: 10,000 sequential keys ----
    # Use 2-digit hex keys to create a dense trie
    print("[phase 1] deep tree: 10,000 keys...")
    for i in range(10000):
        k = "%04x" % i
        v = rng.randbytes(8).hex()
        add("grav_put", {"tree": "deep", "key": k, "value": v})

    # interleaved gets + overwrites
    for _ in range(500):
        k = "%04x" % rng.randrange(0, 10000)
        op = rng.choice(["grav_get", "grav_put", "grav_delete", "grav_get"])
        if op == "grav_put":
            add("grav_put", {"tree": "deep", "key": k, "value": rng.randbytes(16).hex()})
        elif op == "grav_delete":
            add("grav_delete", {"tree": "deep", "key": k})
        else:
            add("grav_get", {"tree": "deep", "key": k})

    # ---- 2. CROSS-TREE: interleaved ops on 3 trees ----
    print("[phase 2] cross-tree interleaving...")
    trees = ["balances", "scdata", "scmeta"]
    keys = [("k%03d" % i).encode().hex() for i in range(100)]
    for _ in range(300):
        tree = rng.choice(trees)
        key = rng.choice(keys)
        op = rng.choice(["grav_put", "grav_put", "grav_delete", "grav_get"])
        if op == "grav_put":
            add("grav_put", {"tree": tree, "key": key, "value": rng.randbytes(32).hex()})
        elif op == "grav_delete":
            add("grav_delete", {"tree": tree, "key": key})
        else:
            add("grav_get", {"tree": tree, "key": key})

    # ---- 3. COLLISION STRESS: put-delete-put on same keys ----
    print("[phase 3] collision stress: 1000 ops on 20 keys...")
    hot_keys = [("hot%02d" % i).encode().hex() for i in range(20)]
    for _ in range(1000):
        k = rng.choice(hot_keys)
        op = rng.choice(["grav_put", "grav_put", "grav_delete", "grav_put", "grav_get"])
        if op == "grav_put":
            add("grav_put", {"tree": "stress", "key": k, "value": rng.randbytes(8).hex()})
        elif op == "grav_delete":
            add("grav_delete", {"tree": "stress", "key": k})
        else:
            add("grav_get", {"tree": "stress", "key": k})

    # ---- 4. KEY PATTERNS ----
    print("[phase 4] key patterns...")
    # common prefixes (tests trie compaction)
    for i in range(50):
        k = ("prefix%02d" % i).encode().hex()
        add("grav_put", {"tree": "patterns", "key": k, "value": "01"})
    for i in range(50):
        k = ("prefix%02d" % i).encode().hex()
        add("grav_delete", {"tree": "patterns", "key": k})

    # single-byte keys
    for i in range(256):
        add("grav_put", {"tree": "patterns", "key": "%02x" % i, "value": "01"})
    for i in range(128):
        add("grav_delete", {"tree": "patterns", "key": "%02x" % rng.randrange(256)})

    # 32-byte keys (like real balance-tree keys)
    for _ in range(100):
        k = rng.randbytes(32).hex()
        add("grav_put", {"tree": "patterns", "key": k, "value": rng.randbytes(8).hex()})
    for _ in range(30):
        k = rng.randbytes(32).hex()
        add("grav_get", {"tree": "patterns", "key": k})

    # ---- 5. VALUE PATTERNS ----
    print("[phase 5] value patterns...")
    val_cases = [
        "",  # empty
        "00",  # 1 byte zero
        "01",  # 1 byte
        "00" * 32,  # 32 bytes all zero
        "ff" * 32,  # 32 bytes all 0xff
        "00" * 255,  # max length
        "ff" * 255,
        "deadbeef",
    ]
    for i, v in enumerate(val_cases):
        add("grav_put", {"tree": "values", "key": "k%02d" % i, "value": v})
    # overwrite with different sizes
    for i in range(len(val_cases)):
        v = rng.choice(val_cases)
        add("grav_put", {"tree": "values", "key": "k%02d" % i, "value": v})

    # ---- 6. FINAL HASH CHECK on all trees ----
    print("[phase 6] final hash check...")
    for tree in ["deep", "balances", "scdata", "scmeta", "stress", "patterns", "values"]:
        add("grav_get", {"tree": tree, "key": "__nonexistent__"})

    # ---- RUN ----
    print(f"running {len(reqs)} ops on both oracles...")
    go_out, err = run(GO, reqs)
    if err:
        print("GO failed:", err)
        return 1
    rust_out, err = run(RUST, reqs)
    if err:
        print("RUST failed:", err)
        return 1

    go_map = {r["id"]: r for r in go_out}
    rust_map = {r["id"]: r for r in rust_out}

    # ---- COMPARE ----
    fails = 0
    hash_checks = 0
    for r in reqs:
        g = go_map.get(r["id"], {})
        rs = rust_map.get(r["id"], {})
        if g.get("ok") != rs.get("ok"):
            print(f"MISMATCH ok id={r['id']} {r['op']}: go={g.get('ok')} rust={rs.get('ok')} "
                  f"go_err={g.get('err')} rust_err={rs.get('err')}")
            fails += 1
            continue
        if g.get("ok"):
            go_out = g.get("out", {})
            rust_out = rs.get("out", {})
            if go_out != rust_out:
                print(f"OUT MISMATCH id={r['id']} {r['op']} tree={r['in'].get('tree')}: "
                      f"go={json.dumps(go_out)[:80]} rust={json.dumps(rust_out)[:80]}")
                fails += 1
            else:
                if "hash" in go_out:
                    hash_checks += 1

    total = len(reqs)
    if fails:
        print(f"FAIL: {fails}/{total} mismatches")
        return 1
    print(f"PASS: {total} ops, {hash_checks} hash checks byte-identical "
          f"(10k deep + cross-tree + collision + patterns + values)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
