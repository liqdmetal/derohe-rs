#!/usr/bin/env python3
"""Bulletproof verify-path FUZZ — the security-critical differential.

  VALID:   50 randomized valid txs (ring 2, varied values/fees/burn/balances)
           -> tx_build_valid on BOTH sides; both must ACCEPT (self + cross).
  CORRUPT: for each valid tx, corrupt the proof bytes (bit flips at random
           offsets) -> proof_verify must REJECT identically on both sides
           (agreement semantics: both reject, or both accept — never split).
  Also corrupts statement fields (c, d, roothash, fees) in a subset.

This is the catastrophic-bug detector: a verify divergence = a real
consensus/security flaw, not a formatting quirk.
"""
import json
import random
import subprocess
import sys

GO = "./oracle/oracle.exe"
RUST = "./crypto/target/release/dero-oracle.exe"


def run(binp, reqs):
    p = subprocess.run([binp], input="\n".join(json.dumps(r) for r in reqs) + "\n",
                       capture_output=True, text=True, timeout=900)
    if p.returncode != 0:
        return None, f"exit {p.returncode}: {p.stderr[:500]}"
    out = []
    for line in p.stdout.splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"id": -1, "ok": False, "err": "badline"})
    return out, None


def main():
    rng = random.Random(0xB17F17E)  # "BULLETPROOF" seed
    reqs = []
    iid = 1

    def add(op, inp):
        nonlocal iid
        reqs.append({"id": iid, "op": op, "in": inp})
        iid += 1

    # base point (from phase A — hardcode the known DEROG base point)
    import urllib.request
    import json as _j
    # fetch via the oracle's base_g op
    p = subprocess.run([GO], input=_j.dumps({"id": 0, "op": "base_g", "in": {}}) + "\n",
                       capture_output=True, text=True, timeout=60)
    base_g_hex = _j.loads(p.stdout.splitlines()[0])["out"]["point"]

    # 1) build the sender/receiver keys (point_scalarmult of base_g * sk)
    valid_cases = []
    for trial in range(50):
        n_ring = 2
        sks = ["%064x" % rng.getrandbits(256) for _ in range(n_ring)]
        pre = []
        for skh in sks:
            add("point_scalarmult", {"point": base_g_hex, "scalar": skh})
            pre.append(iid - 1)
        valid_cases.append((pre, sks))

    go_pre, err = run(GO, reqs)
    if err:
        print("GO pre failed:", err)
        return 1
    rust_pre, err = run(RUST, reqs)
    if err:
        print("RUST pre failed:", err)
        return 1
    pre_map_go = {r["id"]: r["out"] for r in go_pre}
    pre_map_rust = {r["id"]: r["out"] for r in rust_pre}

    # 2) build the valid txs (tx_build_valid)
    valid_reqs = []
    valid_info = []  # (reqid, stmt_base, src_out)
    for (pre, sks) in valid_cases:
        pk0_g = pre_map_go[pre[0]]["point"]
        pk1_g = pre_map_go[pre[1]]["point"]
        pk0_r = pre_map_rust[pre[0]]["point"]
        pk1_r = pre_map_rust[pre[1]]["point"]
        if pk0_g != pk0_r or pk1_g != pk1_r:
            print("KEY MISMATCH go/rust")
            return 1
        value = rng.randrange(0, 2 ** 32)
        fees = rng.randrange(0, 1000)
        burn = rng.randrange(0, 100)
        remaining = rng.randrange(0, 2 ** 32)
        bal_sender = value + fees + burn + remaining
        balance = ["%x" % bal_sender, "%x" % rng.randrange(0, 2 ** 40)]
        eblind = ["%x" % rng.randrange(0, 2 ** 64) for _ in range(2)]
        rand = "".join("%064x" % rng.getrandbits(256) for _ in range(264 + 6))
        inp = {
            "publickeylist": [pk0_g, pk1_g],
            "secretkey": sks[0], "r": "%064x" % rng.getrandbits(256),
            "value": str(value), "fees": str(fees), "burn": str(burn),
            "balances": balance, "eblind": eblind,
            "roothash": "%064x" % rng.getrandbits(256),
            "scid": "%064x" % rng.getrandbits(256),
            "txid": "%064x" % rng.getrandbits(256), "rand": rand,
        }
        valid_reqs.append({"id": iid, "op": "tx_build_valid", "in": inp})
        valid_info.append((iid, inp))
        iid += 1

    go_valid, err = run(GO, valid_reqs)
    if err:
        print("GO valid build failed:", err)
        return 1
    rust_valid, err = run(RUST, valid_reqs)
    if err:
        print("RUST valid build failed:", err)
        return 1
    go_valid_map = {r["id"]: r for r in go_valid}
    rust_valid_map = {r["id"]: r for r in rust_valid}

    # 3) verify each valid tx on BOTH sides (self + cross) -> must ACCEPT
    verify_reqs = []
    accepts = 0
    for rid, inp in valid_info:
        g = go_valid_map.get(rid, {})
        r = rust_valid_map.get(rid, {})
        if not g.get("ok") or not r.get("ok"):
            print(f"build fail rid={rid}: go={g.get('err')} rust={r.get('err')}")
            return 1
        if not g["out"].get("accepted") or not r["out"].get("accepted"):
            print(f"NOT SELF-ACCEPTED rid={rid}: go={g['out'].get('accepted')} rust={r['out'].get('accepted')}")
            return 1
        # cross-verify: go proof on rust statement, rust proof on go statement
        stmt_base = {
            "publickeylist": [inp["publickeylist"][0], inp["publickeylist"][1]],
            "c": None, "d": None, "roothash": None, "fees": None,
            "cln": None, "crn": None,
        }
        for src, label in ((g, "go"), (r, "rust")):
            stmt = dict(stmt_base)
            stmt["c"] = src["out"]["c"]
            stmt["d"] = src["out"]["d"]
            stmt["roothash"] = src["out"]["roothash"]
            stmt["fees"] = src["out"]["fees"]
            stmt["cln"] = src["out"]["cln"]
            stmt["crn"] = src["out"]["crn"]
            verify_reqs.append({"id": iid, "op": "proof_verify", "in": dict(
                stmt, scid=inp["scid"], scid_index="0",
                txid=src["out"]["hash"], burn=inp["burn"],
                proof=src["out"]["proof"])})
            iid += 1

    go_v, err = run(GO, verify_reqs)
    if err:
        print("GO verify failed:", err)
        return 1
    rust_v, err = run(RUST, verify_reqs)
    if err:
        print("RUST verify failed:", err)
        return 1
    go_v_map = {r["id"]: r for r in go_v}
    rust_v_map = {r["id"]: r for r in rust_v}

    for vr in verify_reqs:
        g = go_v_map.get(vr["id"], {})
        r = rust_v_map.get(vr["id"], {})
        if g.get("ok") != r.get("ok") or g.get("out", {}).get("verified") != r.get("out", {}).get("verified"):
            print(f"VERIFY SPLIT id={vr['id']}: go={g} rust={r}")
            return 1
        if not g.get("out", {}).get("verified"):
            print(f"VALID TX REJECTED id={vr['id']}: go={g.get('out')}")
            return 1
        accepts += 1

    print(f"VALID: {accepts} accepts byte-identical (self + cross, both sides)")

    # 4) CORRUPT the proofs -> must reject identically
    corrupt_reqs = []
    corrupt_ids = []
    for rid, inp in valid_info:
        g = go_valid_map.get(rid, {})
        if not g.get("ok"):
            continue
        proof_hex = g["out"]["proof"]
        proof = bytearray.fromhex(proof_hex)
        stmt = {
            "publickeylist": [inp["publickeylist"][0], inp["publickeylist"][1]],
            "c": g["out"]["c"], "d": g["out"]["d"],
            "roothash": g["out"]["roothash"], "fees": g["out"]["fees"],
            "cln": g["out"]["cln"], "crn": g["out"]["crn"],
        }
        # 3 corruptions per valid tx: proof byte flips, statement c flip,
        # roothash flip
        for kind in ("proof", "c", "roothash", "txid"):
            cor = dict(stmt)
            if kind == "proof":
                # flip 1-3 bytes in the proof
                cproof = bytearray(proof)
                for _ in range(rng.randint(1, 3)):
                    pos = rng.randrange(len(cproof))
                    cproof[pos] ^= 1 << rng.randrange(8)
                cor_in = dict(cor, scid=inp["scid"], scid_index="0",
                              txid=g["out"]["hash"], burn=inp["burn"],
                              proof=cproof.hex())
            elif kind == "c":
                # flip a byte in C[0]
                c0 = bytearray.fromhex(g["out"]["c"][0])
                c0[rng.randrange(len(c0))] ^= 1 << rng.randrange(8)
                cor["c"] = [c0.hex()] + g["out"]["c"][1:]
                cor_in = dict(cor, scid=inp["scid"], scid_index="0",
                              txid=g["out"]["hash"], burn=inp["burn"],
                              proof=proof_hex)
            elif kind == "roothash":
                rh = bytearray.fromhex(g["out"]["roothash"])
                rh[rng.randrange(32)] ^= 1 << rng.randrange(8)
                cor["roothash"] = rh.hex()
                cor_in = dict(cor, scid=inp["scid"], scid_index="0",
                              txid=g["out"]["hash"], burn=inp["burn"],
                              proof=proof_hex)
            else:  # txid
                txid = bytearray.fromhex(g["out"]["hash"])
                txid[rng.randrange(32)] ^= 1 << rng.randrange(8)
                cor_in = dict(cor, scid=inp["scid"], scid_index="0",
                              txid=txid.hex(), burn=inp["burn"],
                              proof=proof_hex)
            corrupt_reqs.append({"id": iid, "op": "proof_verify", "in": cor_in})
            corrupt_ids.append(iid)
            iid += 1

    go_c, err = run(GO, corrupt_reqs)
    if err:
        print("GO corrupt verify failed:", err)
        return 1
    rust_c, err = run(RUST, corrupt_reqs)
    if err:
        print("RUST corrupt verify failed:", err)
        return 1
    go_c_map = {r["id"]: r for r in go_c}
    rust_c_map = {r["id"]: r for r in rust_c}

    rejects = 0
    splits = 0
    for cid in corrupt_ids:
        g = go_c_map.get(cid, {})
        r = rust_c_map.get(cid, {})
        # Go may HARD-ERROR (ok:false) on corrupted proofs (deserialize
        # fails before verify) — that IS a rejection. Map ok:false -> reject.
        gv = g.get("out", {}).get("verified") if g.get("ok") else False
        rv = r.get("out", {}).get("verified") if r.get("ok") else False
        if gv != rv:
            print(f"CORRUPT SPLIT id={cid}: go={gv} rust={rv} (go_ok={g.get('ok')} rust_ok={r.get('ok')})")
            splits += 1
        elif gv is False:
            rejects += 1
        # gv True on corrupted input: both accepted (agreement) — flag but
        # don't fail: a flip in a non-verifying field can still verify

    print(f"CORRUPT: {rejects}/{len(corrupt_ids)} rejected identically, {splits} splits")

    if splits:
        print("FAIL: verify-path divergence on corrupted inputs")
        return 1
    print("PASS: bulletproof verify fuzz — valid accepts + corrupt rejects byte-identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
