#!/usr/bin/env python3
"""HARD TEST: multi-block accumulation + random mixed-op property test.

Applies 20 sequential blocks (miner_tx + 2 txs each, hash-aligned
miniblocks, fees) to the SHARED persistent "B" tree on both oracles, then
checks the final root + every intermediate root is byte-identical.
Also runs a 150-op random mix (grav_put/grav_delete/grav_register/
chain_tx) on the same tree and compares roots after each op.
"""
import json, subprocess, random, hashlib, sys

GO = "./oracle/oracle.exe"
RUST = "./crypto/target/release/dero-oracle.exe"

P256 = 21888242871839275222246405745257275088696311157297823662689037894645226208583

def gen_addr(x):
    while True:
        xx = x % P256
        y2 = (pow(xx, 3, P256) + 3) % P256
        if pow(y2, (P256 - 1) // 2, P256) == 1:
            y = pow(y2, (P256 + 1) // 4, P256)
            return ("%064x" % xx) + ("%02x" % (1 if y & 1 else 0))
        x += 1

def blake2s16(b):
    return hashlib.blake2s(b, digest_size=32).digest()[:16]

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
    rng = random.Random(0xBEEF00D)
    reqs = []
    iid = 1

    def add(op, inp):
        nonlocal iid
        reqs.append({"id": iid, "op": op, "in": inp})
        iid += 1

    # ---- 20 sequential blocks, each: register miners, miner_tx + 2 txs ----
    # (no proofs needed — chain_block builds txs from payloads with proofs;
    #  we reuse the phase_q-style proof-less approach: chain_block needs
    #  proofs for parity, so we generate them inline via proof_generate first)
    # Simpler: build the payload statements and proofs up front.
    points_pool = None
    # Use small on-curve points derived from seeds (we only need parity, and
    # realisticStatement needs valid points)
    import sys
    sys.path.insert(0, "harness")
    # reuse the difftest helpers is fragile; instead generate points here.
    # Valid points: x where y2 has sqrt. We'll generate a pool.
    pool = []
    seed = 0x1234
    while len(pool) < 40:
        a = gen_addr(seed)
        seed += 1
        pool.append(a)

    # proof_generate requests for 40 statements (ring 2)
    stmts = []
    for i in range(40):
        pks = rng.sample(pool, 2)
        d = rng.choice(pool)
        stmt = {
            "publickeylist": pks, "c": pks, "d": d,
            "roothash": ("%064x" % rng.getrandbits(256)),
            "fees": str(rng.randrange(0, 1000)),
            "secretkey": ("%064x" % rng.getrandbits(256)),
            "r": ("%064x" % rng.getrandbits(256)),
            "transfer": str(rng.randrange(0, 2 ** 32)),
            "balance": str(rng.randrange(0, 2 ** 32)),
            "index": [0, 1],
        }
        stmts.append(stmt)
        add("proof_generate", {
            "publickeylist": pks, "c": pks, "d": d,
            "roothash": stmt["roothash"], "fees": stmt["fees"],
            "secretkey": stmt["secretkey"], "r": stmt["r"],
            "transfer": stmt["transfer"], "balance": stmt["balance"],
            "index": [0, 1], "scid": ("%064x" % rng.getrandbits(256)),
            "scid_index": "0", "txid": ("%064x" % rng.getrandbits(256)),
            "burn": str(rng.randrange(0, 100)),
            "u": rng.choice(pool), "rand": "00" * 32,
        })
    # run proofs
    go_out, err = run(GO, reqs)
    if err:
        print("GO proof run failed:", err); return 1
    proof_by_id = {r["id"]: r["out"]["proof"] for r in go_out if r.get("ok")}
    reqs = []

    # build payloads with the Go proofs
    payloads = []
    for i, stmt in enumerate(stmts):
        rid = i + 1
        if rid not in proof_by_id:
            print(f"missing proof for stmt {i}"); return 1
        rpc_payload = "".join(rng.choice("0123456789abcdef") for _ in range(290))
        payloads.append({
            "scid": "00" * 32, "burn": "0", "rpctype": "0",
            "rpcpayload": rpc_payload, "statement": stmt,
            "proof": proof_by_id[rid],
        })

    # 20 blocks: register miners, chain_block with miner + 2 txs
    used_pay = 0
    for blk in range(20):
        n_mbl = 2 + (blk % 3)
        addrs = [gen_addr(rng.randrange(0, 2 ** 254)) for _ in range(n_mbl)]
        for a in addrs:
            add("grav_register", {"tree": "B", "address": a})
        mbls = []
        for i, a in enumerate(addrs):
            kh16 = blake2s16(bytes.fromhex(a))
            kh32 = kh16 + b"\x00" * 16
            mbls.append({"Version": 1, "Final": (i == 0), "PastCount": 1,
                         "Timestamp": 0, "Height": 0, "Past": [0, 0],
                         "KeyHash": kh32.hex(), "Flags": 0})
        blk_pays = payloads[used_pay:used_pay + 2]
        used_pay += 2
        add("chain_block", {
            "miner_address": addrs[0], "miniblocks": mbls,
            "payloads": blk_pays, "height": str(2000 + blk * 17),
            "fees": str(100 + blk),
        })

    # ---- random mixed-op property test (150 ops on the same tree) ---------
    keys = [("%04x" % i).encode().hex() for i in range(50)]
    for _ in range(150):
        op = rng.choice(["grav_put", "grav_put", "grav_delete", "grav_register",
                         "chain_tx", "grav_get"])
        if op == "grav_put":
            add("grav_put", {"tree": "B", "key": rng.choice(keys),
                             "value": ("%016x" % rng.getrandbits(64))})
        elif op == "grav_delete":
            add("grav_delete", {"tree": "B", "key": rng.choice(keys)})
        elif op == "grav_register":
            add("grav_register", {"tree": "B", "address": gen_addr(rng.randrange(0, 2 ** 254))})
        elif op == "chain_tx":
            pay = rng.choice(payloads)
            tx_in = {"version": "1", "source_network": "0", "dest_network": "0",
                     "txtype": "3", "height": str(rng.randrange(0, 2 ** 32)),
                     "blid": ("%064x" % rng.getrandbits(256)),
                     "payloads": [pay]}
            add("chain_tx", dict(tx_in, height=str(1000 + rng.randrange(0, 500))))
        else:  # grav_get
            add("grav_get", {"tree": "B", "key": rng.choice(keys)})

    # ---- run both sides ----
    go_out, err = run(GO, reqs)
    if err:
        print("GO failed:", err); return 1
    rust_out, err = run(RUST, reqs)
    if err:
        print("RUST failed:", err); return 1
    go_map = {r["id"]: r for r in go_out}
    rust_map = {r["id"]: r for r in rust_out}

    fails = 0
    for r in reqs:
        g = go_map.get(r["id"], {})
        rs = rust_map.get(r["id"], {})
        if g.get("ok") != rs.get("ok"):
            print(f"MISMATCH ok {r['id']} {r['op']}: go={g.get('ok')} rust={rs.get('ok')} "
                  f"go_err={g.get('err')} rust_err={rs.get('err')}")
            fails += 1
            continue
        if g.get("ok") and g.get("out") != rs.get("out"):
            print(f"MISMATCH out {r['id']} {r['op']}:")
            print(f"  go:   {json.dumps(g['out'])[:200]}")
            print(f"  rust: {json.dumps(rs['out'])[:200]}")
            fails += 1
    if fails:
        print(f"FAIL: {fails} mismatches across {len(reqs)} ops")
        return 1
    print(f"PASS: {len(reqs)} ops byte-identical (20-block accumulation + 150-op mix)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
