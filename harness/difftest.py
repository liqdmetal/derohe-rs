#!/usr/bin/env python3
"""Differential test harness: derohe Go reference vs clean-room Rust.

Generates deterministic random vectors, feeds the SAME JSONL request stream to
both oracles (oracle/oracle.exe and crypto/target/release/dero-oracle.exe), and
compares every response. Any divergence is a porting bug (or a genuine
reference quirk we must document).

Usage:
    python harness/difftest.py            # build + run full suite
    python harness/difftest.py --no-build # skip rebuild
"""

import argparse
import json
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GO_ORACLE = ROOT / "oracle" / "oracle.exe"
RUST_ORACLE = ROOT / "crypto" / "target" / "release" / "dero-oracle.exe"

N_HEX = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
P_HEX = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"


def build():
    print("[build] go oracle ...")
    subprocess.run(["go", "build", "-o", "oracle.exe", "."], cwd=ROOT / "oracle", check=True)
    print("[build] rust oracle ...")
    subprocess.run(["cargo", "build", "--release"], cwd=ROOT / "crypto", check=True)


def run_oracle(binpath, requests):
    payload = "\n".join(json.dumps(r) for r in requests) + "\n"
    p = subprocess.run(
        [str(binpath)], input=payload, capture_output=True, text=True, timeout=900
    )
    if p.returncode != 0:
        raise RuntimeError(f"{binpath.name} exited {p.returncode}: {p.stderr[:3000]}")
    out = {}
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        out[r["id"]] = r
    return out


def scalar_edges():
    """Deterministic edge-case scalars: 0, 1, n-1, n, n+1, p-1, p, 2^255."""
    z = "00" * 32
    one = "00" * 31 + "01"
    n = int(N_HEX, 16)
    p = int(P_HEX, 16)
    edges = {
        "zero": z,
        "one": one,
        "n_minus_1": format(n - 1, "064x"),
        "n": format(n, "064x"),
        "n_plus_1": format(n + 1, "064x"),
        "p_minus_1": format(p - 1, "064x"),
        "p": format(p, "064x"),
        "top_bit": "80" + "00" * 31,
    }
    return edges


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--vectors", type=int, default=100, help="random vectors per op")
    args = ap.parse_args()

    if not args.no_build:
        build()
    if not GO_ORACLE.exists():
        sys.exit("go oracle missing; run without --no-build")
    if not RUST_ORACLE.exists():
        sys.exit("rust oracle missing; run without --no-build")

    rng = random.Random(0xD3F0C0DE)
    n = args.vectors
    edges = scalar_edges()
    edge_names = list(edges.keys())

    def rand32():
        return rng.randbytes(32).hex()

    # ---- Phase A: hash + point derivation (point pool) -------------------
    phase_a = []
    req_id = 0

    def add(op, inp):
        nonlocal req_id
        phase_a.append({"id": req_id, "op": op, "in": inp})
        req_id += 1

    # base generator (protocol constant, must match)
    add("base_g", {})
    # keccak vectors
    for _ in range(30):
        ln = rng.randrange(0, 129)
        add("keccak256", {"data": rng.randbytes(ln).hex()})
    for _ in range(30):
        ln = rng.randrange(0, 129)
        add("keccak512", {"data": rng.randbytes(ln).hex()})
    # hashtopoint: random seeds + edge seeds
    seeds = [rand32() for _ in range(n)]
    seeds += [edges[k] for k in edge_names]
    for s in seeds:
        add("hashtopoint", {"seed": s})

    go_a = run_oracle(GO_ORACLE, phase_a)
    if len(go_a) != len(phase_a):
        sys.exit(f"go oracle phase A: expected {len(phase_a)} responses, got {len(go_a)}")

    # point pool: hashtopoint outputs + base_g + generator(1,2) known encoding
    points = []
    for r in phase_a:
        if r["op"] == "hashtopoint":
            points.append(go_a[r["id"]]["out"]["point"])
    points.append(go_a[0]["out"]["point"])  # base_g (id 0)
    # standard generator (1,2) in DERO encoding: x=1, flag 0x00
    points.append("00" * 31 + "01" + "00")

    # ---- Phase B: group + elgamal ops ------------------------------------
    phase_b = []
    req_id = 100000  # unique id base to avoid collisions across phases
    phase_b_ids = []

    def add_b(op, inp):
        nonlocal req_id
        phase_b.append({"id": req_id, "op": op, "in": inp})
        phase_b_ids.append(req_id)
        req_id += 1

    def rpoint():
        return rng.choice(points)

    # point_scalarmult
    for _ in range(n):
        add_b("point_scalarmult", {"point": rpoint(), "scalar": rand32()})
    for k in edge_names:
        add_b("point_scalarmult", {"point": points[0], "scalar": edges[k]})
    # point_add (incl. p + (-p) = identity via neg)
    for _ in range(n):
        add_b("point_add", {"a": rpoint(), "b": rpoint()})
    for _ in range(20):
        p = rpoint()
        add_b("point_neg", {"point": p})
        add_b("point_add", {"a": p, "b": p})  # 2p
    # point_neg
    for _ in range(30):
        add_b("point_neg", {"point": rpoint()})
    # point_marshal_uncompressed
    for _ in range(30):
        add_b("point_marshal_uncompressed", {"point": rpoint()})
    # elgamal_commit (deterministic r)
    for _ in range(n):
        add_b("elgamal_commit", {"key": rpoint(), "value": rand32(), "randomness": rand32()})
    for k in edge_names:
        add_b("elgamal_commit", {"key": points[0], "value": edges[k], "randomness": edges[k]})
    # elgamal_add / plus / mul / neg
    for _ in range(n):
        add_b("elgamal_add", {
            "a_left": rpoint(), "a_right": rpoint(),
            "b_left": rpoint(), "b_right": rpoint(),
        })
    for _ in range(50):
        add_b("elgamal_plus", {"left": rpoint(), "right": rpoint(), "value": rand32()})
        add_b("elgamal_mul", {"left": rpoint(), "right": rpoint(), "scalar": rand32()})
        add_b("elgamal_neg", {"left": rpoint(), "right": rpoint()})
    # elgamal_serialize + deserialize round trips
    for _ in range(50):
        l, r = rpoint(), rpoint()
        add_b("elgamal_serialize", {"left": l, "right": r})
    # deserialize malformed inputs (must agree on error semantics):
    # short, long, x=0 (non-QR, both reject), x=0 + invalid flag
    for bad in ["00" * 65, "00" * 67, "00" * 66, "00" * 32 + "02"]:
        add_b("elgamal_deserialize", {"bytes": bad})
    # KNOWN REFERENCE DIVERGENCE (documented, not a bug):
    # x >= p is undefined behavior in Go: Decompress -> marshal() discards the
    # Unmarshal on-curve error (bn256/changes.go:59) and any flag != 0x01 falls
    # through to "return y1". Go 'succeeds' with an invalid point; Rust rejects
    # (clean-room correctness). Consensus impact: none for valid txs; verified
    # at chain-replay phase. Expected: go ok=True, rust ok=False.
    div_ff_id = req_id
    add_b("elgamal_deserialize", {"bytes": "ff" * 66})

    # ---- Phase C: pedersen params + fieldvector ops -----------------------
    phase_c = []
    req_id = 200000  # unique id base to avoid collisions across phases
    phase_c_ids = []

    def add_c(op, inp):
        nonlocal req_id
        phase_c.append({"id": req_id, "op": op, "in": inp})
        phase_c_ids.append(req_id)
        req_id += 1

    add_c("pedersen_gparams", {})  # pins G, H, GSUM, all 128 Gs/Hs (hashed)
    lens = [2, 4, 8, 16]
    for ln in lens:
        for _ in range(10):
            a = [rand32() for _ in range(ln)]
            b = [rand32() for _ in range(ln)]
            add_c("fieldvector_add", {"a": a, "b": b})
            add_c("fieldvector_hadamard", {"a": a, "b": b})
            add_c("fieldvector_innerproduct", {"a": a, "b": b})
            add_c("fieldvector_times", {"a": a, "scalar": rand32()})
            add_c("fieldvector_negate", {"a": a})
            add_c("fieldvector_flip", {"a": a})
            add_c("fieldvector_extract", {"a": a, "parity": str(rng.randrange(2))})
            add_c("fieldvector_sum", {"a": a})
        add_c("fieldvector_concat", {
            "a": [rand32() for _ in range(ln)],
            "b": [rand32() for _ in range(ln)],
        })
    # pedersen commitments (vector + scalar)
    for ln in [1, 2, 8, 16]:
        for _ in range(10):
            add_c("pedersen_commit", {
                "gvalues": [rand32() for _ in range(ln)],
                "hvalues": [rand32() for _ in range(ln)],
                "randomness": rand32(),
            })
    for _ in range(20):
        add_c("pedersen_commit_scalar", {"value": rand32(), "randomness": rand32()})
    # pointvector multi-exponentiation over the hash-to-point pool
    for ln in [1, 2, 8]:
        for _ in range(10):
            add_c("pointvector_multexp", {
                "points": [rng.choice(points) for _ in range(ln)],
                "exps": [rand32() for _ in range(ln)],
            })

    go_c = run_oracle(GO_ORACLE, phase_c)
    rust_c = run_oracle(RUST_ORACLE, phase_c)

    # ---- Phase D: FFT / polynomials / inner-product argument --------------
    phase_d = []
    req_id = 300000
    phase_d_ids = []

    def add_d(op, inp):
        nonlocal req_id
        phase_d.append({"id": req_id, "op": op, "in": inp})
        phase_d_ids.append(req_id)
        req_id += 1

    def bit_hex(v):
        return "00" * 32 if v == 0 else "00" * 31 + "01"

    # fft_fieldvector: forward + inverse
    for ln in [2, 4, 8, 16]:
        for _ in range(10):
            add_d("fft_fieldvector", {"a": [rand32() for _ in range(ln)], "inverse": "0"})
            add_d("fft_fieldvector", {"a": [rand32() for _ in range(ln)], "inverse": "1"})
    # fft_generatorvector over the point pool
    for ln in [2, 4, 8, 16]:
        for _ in range(6):
            add_d("fft_generatorvector", {"points": [rng.choice(points) for _ in range(ln)], "inverse": "0"})
            add_d("fft_generatorvector", {"points": [rng.choice(points) for _ in range(ln)], "inverse": "1"})
    # convolution
    for ln in [2, 4, 8]:
        for _ in range(6):
            add_d("convolution", {"exps": [rand32() for _ in range(ln)], "points": [rng.choice(points) for _ in range(ln)]})
    # polynomial_mul: b = binomial [c0, 1]
    for _ in range(20):
        alen = rng.randrange(1, 6)
        add_d("polynomial_mul", {"a": [rand32() for _ in range(alen)], "b": [rand32(), "00" * 31 + "01"]})
    # recursive_polynomials: a arbitrary, b bits
    for ln in [2, 3, 4]:
        for _ in range(6):
            add_d("recursive_polynomials", {
                "a": [rand32() for _ in range(ln)],
                "b": [bit_hex(rng.randrange(2)) for _ in range(ln)],
            })
    # reducedhash
    for _ in range(20):
        add_d("reducedhash", {"data": rng.randbytes(rng.randrange(0, 80)).hex()})
    # ip_generate: lengths 2, 8, 128 (128 = full 7 rounds)
    ip_ids = []
    for ln in [2, 8, 128]:
        for _ in range(8):
            rid = req_id
            add_d("ip_generate", {"as": [rand32() for _ in range(ln)], "bs": [rand32() for _ in range(ln)], "salt": rand32()})
            ip_ids.append(rid)

    go_d = run_oracle(GO_ORACLE, phase_d)
    rust_d = run_oracle(RUST_ORACLE, phase_d)

    # cross-verification: Go verifies Rust proofs, Rust verifies Go proofs
    cross_requests = []
    cross_expect = []
    cid = 400000
    for rid in ip_ids:
        go = go_d[rid]
        ru = rust_d[rid]
        if not go.get("ok") or not ru.get("ok"):
            continue
        for src, label in ((go, "go"), (ru, "rust")):
            # other side verifies this proof
            cross_requests.append({
                "id": cid,
                "op": "ip_verify",
                "in": {
                    "a": src["out"]["a"],
                    "b": src["out"]["b"],
                    "ls": src["out"]["ls"],
                    "rs": src["out"]["rs"],
                    "salt": [r for r in phase_d if r["id"] == rid][0]["in"]["salt"],
                    "p": src["out"]["p"],
                    "hs": src["out"]["hs"],
                },
            })
            cross_expect.append((cid, label, "rust" if label == "go" else "go"))
            cid += 1

    go_d2 = {}
    rust_d2 = {}
    if cross_requests:
        go_d2 = run_oracle(GO_ORACLE, cross_requests)
        rust_d2 = run_oracle(RUST_ORACLE, cross_requests)

    # ---- Phase E: aggregate bulletproof (proof_generate / proof_verify) ----
    phase_e = []
    req_id = 500000
    phase_e_ids = []

    def add_e(op, inp):
        nonlocal req_id
        phase_e.append({"id": req_id, "op": op, "in": inp})
        phase_e_ids.append(req_id)
        req_id += 1

    def bit_hex(v):
        return "00" * 32 if v == 0 else "00" * 31 + "01"

    # deterministic randomness stream: 264 + 6m draws of 32 bytes
    # (BA, sL(128), sR(128), BS, aa(2m-2), A, B, phi(m), chi(m), psi(m),
    #  C_XG(m), T1, T2, k_sk, k_r, k_b, k_tau)
    def rand_stream(m):
        return "".join(rand32() for _ in range(264 + 6 * m))

    proof_gen_ids = []
    for n_ring in [2, 4]:
        m = n_ring.bit_length() - 1
        for trial in range(4):
            # statement: distinct publickeys from the pool (plus G if needed)
            pks = [rng.choice(points) for _ in range(n_ring)]
            # ensure distinctness cheaply: fine for differential (both sides see same)
            d = rng.choice(points)
            roothash = rand32()
            fees = rng.randrange(0, 1000)
            # witness
            secretkey = rand32()
            r_scalar = rand32()
            transfer = rng.randrange(0, 2**32)
            balance = rng.randrange(0, 2**32)
            # index: distinct, and at least one LSB=1 so the parity check passes
            if n_ring == 2:
                i0, i1 = 0, 1
            else:
                i0, i1 = 1, 2
            scid = rand32()
            scid_index = trial
            txid = rand32()
            burn = rng.randrange(0, 100)
            u = rng.choice(points)
            rid = req_id
            add_e("proof_generate", {
                "publickeylist": pks,
                "c": pks,
                "d": d,
                "roothash": roothash,
                "fees": str(fees),
                "secretkey": secretkey,
                "r": r_scalar,
                "transfer": str(transfer),
                "balance": str(balance),
                "index": [i0, i1],
                "scid": scid,
                "scid_index": str(scid_index),
                "txid": txid,
                "burn": str(burn),
                "u": u,
                "rand": rand_stream(m),
            })
            proof_gen_ids.append((rid, {
                "publickeylist": pks, "c": pks, "d": d, "roothash": roothash,
                "fees": str(fees), "scid": scid, "scid_index": str(scid_index),
                "txid": txid, "burn": str(burn),
            }))

    go_e = run_oracle(GO_ORACLE, phase_e)
    rust_e = run_oracle(RUST_ORACLE, phase_e)

    # debug: dump phase_e requests for field-level analysis
    with open(ROOT / "harness" / "phase_e_requests.json", "w") as f:
        for r in phase_e:
            f.write(json.dumps(r) + "\n")

    # cross-verify: each side verifies the other's serialized proof
    cross_e_requests = []
    cross_e_expect = []
    cid = 600000
    for rid, stmt in proof_gen_ids:
        go = go_e[rid]
        ru = rust_e[rid]
        if not go.get("ok") or not ru.get("ok"):
            continue
        for src, label in ((go, "go"), (ru, "rust")):
            cross_e_requests.append({
                "id": cid,
                "op": "proof_verify",
                "in": dict(stmt, proof=src["out"]["proof"]),
            })
            cross_e_expect.append((cid, label, "rust" if label == "go" else "go"))
            cid += 1
    go_e2 = {}
    rust_e2 = {}
    if cross_e_requests:
        go_e2 = run_oracle(GO_ORACLE, cross_e_requests)
        rust_e2 = run_oracle(RUST_ORACLE, cross_e_requests)

    go_b = run_oracle(GO_ORACLE, phase_b)
    rust_a = run_oracle(RUST_ORACLE, phase_a)
    rust_b = run_oracle(RUST_ORACLE, phase_b)

    # ---- compare -----------------------------------------------------------
    failures = []
    per_op = {}

    def check(resp_go, resp_rust):
        op = None
        for r in (phase_a + phase_b + phase_c + phase_d + phase_e):
            if r["id"] == resp_go["id"]:
                op = r["op"]
                break
        per_op[op] = per_op.get(op, 0) + 1
        g_ok, r_ok = resp_go.get("ok"), resp_rust.get("ok")
        if resp_go["id"] == div_ff_id:
            # documented divergence: Go UB on x >= p, Rust rejects
            if g_ok and not r_ok:
                print(f"  [note] id={div_ff_id} x>=p divergence confirmed (Go UB, Rust strict) — expected")
                return
            failures.append((op, resp_go["id"], f"expected x>=p divergence, got go={g_ok} rust={r_ok}"))
            return
        if g_ok != r_ok:
            req = next((r for r in (phase_a + phase_b + phase_c + phase_d + phase_e) if r["id"] == resp_go["id"]), None)
            failures.append(
                (op, resp_go["id"], f"ok mismatch: go={g_ok} rust={r_ok} "
                 f"go_err={resp_go.get('err')} rust_err={resp_rust.get('err')} req={json.dumps(req)}")
            )
            return
        if g_ok:
            if resp_go["out"] != resp_rust["out"]:
                req = next((r for r in (phase_a + phase_b + phase_c + phase_d + phase_e) if r["id"] == resp_go["id"]), None)
                failures.append(
                    (op, resp_go["id"], f"out mismatch:\n  go:   {json.dumps(resp_go['out'])}\n  rust: {json.dumps(resp_rust['out'])}\n  req:  {json.dumps(req)}")
                )
        # both errored: agree (checked ok==False above)

    for r in phase_a:
        check(go_a[r["id"]], rust_a[r["id"]])
    for r in phase_b:
        check(go_b[r["id"]], rust_b[r["id"]])
    for r in phase_c:
        check(go_c[r["id"]], rust_c[r["id"]])
    for r in phase_d:
        check(go_d[r["id"]], rust_d[r["id"]])
    for r in phase_e:
        check(go_e[r["id"]], rust_e[r["id"]])

    # cross-verification results: both sides must accept the other's proofs
    for cid, from_label, to_label in cross_expect:
        g = go_d2.get(cid, {}).get("out", {}).get("verified")
        r = rust_d2.get(cid, {}).get("out", {}).get("verified")
        if g is not None and r is not None:
            if g != r:
                failures.append(("ip_cross_verify", cid, f"verify disagreement: go={g} rust={r} ({from_label}->{to_label})"))
            elif not g:
                failures.append(("ip_cross_verify", cid, f"both rejected a valid proof ({from_label}->{to_label})"))
        else:
            failures.append(("ip_cross_verify", cid, f"missing cross-verify response go={g} rust={r}"))

    # bulletproof cross-verification: each side accepts the other's proofs
    for cid, from_label, to_label in cross_e_expect:
        g = go_e2.get(cid, {}).get("out", {}).get("verified")
        r = rust_e2.get(cid, {}).get("out", {}).get("verified")
        if g is not None and r is not None:
            if g != r:
                failures.append(("proof_cross_verify", cid, f"verify disagreement: go={g} rust={r} ({from_label}->{to_label})"))
            elif not g:
                failures.append(("proof_cross_verify", cid, f"both rejected a valid proof ({from_label}->{to_label})"))
        else:
            failures.append(("proof_cross_verify", cid, f"missing cross-verify response go={g} rust={r}"))

    total = len(phase_a) + len(phase_b) + len(phase_c) + len(phase_d) + len(phase_e)
    print(f"\n=== differential results: {total} vectors ===")
    for op, cnt in sorted(per_op.items()):
        print(f"  {op:32s} {cnt:4d}")
    if failures:
        print(f"\nFAIL: {len(failures)} mismatches")
        for op, rid, msg in failures[:10]:
            print(f"\n  [{op} id={rid}] {msg}")
        sys.exit(1)
    print(f"\nPASS: all {total} vectors match the Go reference")


if __name__ == "__main__":
    main()
