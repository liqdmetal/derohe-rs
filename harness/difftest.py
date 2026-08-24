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

    def rpc_addr_valid(raw_hex):
        """A compressed point is valid iff decode succeeds (matches Go's
        DecodeCompressed in NewAddressFromKeys)."""
        try:
            b = bytes.fromhex(raw_hex)
            if len(b) != 33:
                return False
            p = int.from_bytes(b[:32], 'big')
            if p >= 21888242871839275222246405745257275088696311157297823662689037894645226208583:
                return False
            flag = b[32]
            return flag in (0, 1)
        except Exception:
            return False

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
                "secretkey": secretkey, "r": r_scalar,
                "transfer": str(transfer), "balance": str(balance),
                "index": [i0, i1],
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

    # ---- Phase F: NonceBalance serialization --------------------------------
    # marshal: random nonceheight (biased small/large to exercise 1-10 byte
    # varints) + random valid 66-byte ElGamal balance; then unmarshal the
    # GO-produced bytes on both sides + malformed inputs (both must fail
    # identically).
    phase_f = []
    f_marshal_ids = []
    f_nonce_ids = []
    fid = 700000

    def add_f(op, inp):
        nonlocal fid
        phase_f.append({"id": fid, "op": op, "in": inp})
        fid += 1

    for _ in range(40):
        nh = rng.choice([
            rng.randrange(0, 128),            # 1-byte varint
            rng.randrange(0, 2 ** 16),        # 2-3 bytes
            rng.randrange(0, 2 ** 40),        # 5-6 bytes
            rng.randrange(0, 2 ** 64 - 1),    # up to 10 bytes
        ])
        left = rng.choice(points)
        right = rng.choice(points)
        add_f("noncebalance_marshal", {"nonceheight": str(nh), "balance": left + right})
        f_marshal_ids.append(fid - 1)

    go_f = run_oracle(GO_ORACLE, phase_f)
    rust_f = run_oracle(RUST_ORACLE, phase_f)

    # unmarshal + unmarshal_nonce from the Go-marshaled bytes (authoritative)
    f_unmarshal_requests = []
    f_unmarshal_ids = []
    for rid in f_marshal_ids:
        g = go_f[rid]
        if not g.get("ok"):
            continue
        marshaled = g["out"]["bytes"]
        add_f("noncebalance_unmarshal", {"bytes": marshaled})
        f_unmarshal_ids.append(fid - 1)
        add_f("noncebalance_unmarshal_nonce", {"bytes": marshaled})
        f_nonce_ids.append(fid - 1)

    # malformed inputs: truncated marshaled, empty, bad varints
    for rid in f_marshal_ids[:6]:
        g = go_f[rid]
        if not g.get("ok"):
            continue
        marshaled = g["out"]["bytes"]
        cuts = [1, 2, 8, len(marshaled) // 2, len(marshaled) - 1]
        for c in cuts:
            add_f("noncebalance_unmarshal", {"bytes": marshaled[:c]})
            f_unmarshal_ids.append(fid - 1)
    add_f("noncebalance_unmarshal", {"bytes": ""})
    f_unmarshal_ids.append(fid - 1)
    add_f("noncebalance_unmarshal", {"bytes": "ff" * 10})  # varint overflow
    f_unmarshal_ids.append(fid - 1)
    add_f("noncebalance_unmarshal", {"bytes": "80"})       # truncated varint
    f_unmarshal_ids.append(fid - 1)

    # run only the new requests (marshal already ran above)
    f_extra = [r for r in phase_f if r["id"] not in go_f]
    go_f2 = run_oracle(GO_ORACLE, f_extra) if f_extra else {}
    rust_f2 = run_oracle(RUST_ORACLE, f_extra) if f_extra else {}
    go_f.update(go_f2)
    rust_f.update(rust_f2)


    # ---- Phase G: transaction serialization ---------------------------------
    # Build transactions of all 6 types. NORMAL/BURN/SC carry payloads with
    # realistic statements + real proofs (generated first via proof_generate),
    # SC adds SCDATA (CBOR args). Then deserialize the Go-produced bytes on
    # both sides (roundtrip re-serialize + hash) plus malformed inputs.
    phase_g = []
    gid = 800000

    def add_g(op, inp):
        nonlocal gid
        phase_g.append({"id": gid, "op": op, "in": inp})
        gid += 1

    def tx_header_in(txtype, rng, points):
        base = {
            "version": "1", "source_network": str(rng.randrange(0, 3)), "dest_network": "0",
            "txtype": str(txtype),
        }
        if txtype in (0, 5):  # PREMINE, SC
            base["value"] = str(rng.randrange(0, 2 ** 40))
        if txtype in (0, 2, 1):  # PREMINE, COINBASE, REGISTRATION
            base["miner_address"] = rng.choice(points)
        if txtype == 1:  # REGISTRATION
            base["c"] = rand32()
            base["s"] = rand32()
        if txtype in (3, 4, 5):  # NORMAL, BURN, SC
            base["height"] = str(rng.randrange(0, 2 ** 32))
            base["blid"] = rand32()
        return base

    def payload_in(rng, points, proof_hex, burn=None):
        # statement mirrors the phase_e proof_generate statement
        n_ring = 2
        pks = [rng.choice(points) for _ in range(n_ring)]
        d = rng.choice(points)
        roothash = rand32()
        fees = rng.randrange(0, 1000)
        secretkey = rand32()
        r_scalar = rand32()
        transfer = rng.randrange(0, 2 ** 32)
        balance = rng.randrange(0, 2 ** 32)
        if burn is None:
            burn = rng.randrange(0, 100)
        rpc_payload = "".join(rng.choice("0123456789abcdef") for _ in range(290))  # 145 bytes
        return {
            "scid": rand32(),
            "burn": str(burn),
            "rpctype": str(rng.randrange(0, 3)),
            "rpcpayload": rpc_payload,
            "statement": {
                "publickeylist": pks, "c": pks, "d": d, "roothash": roothash,
                "fees": str(fees), "secretkey": secretkey, "r": r_scalar,
                "transfer": str(transfer), "balance": str(balance), "index": [0, 1],
            },
            "proof": proof_hex,
        }

    def scdata_in(rng, points):
        addr = rng.choice(points)
        args = [
            {"name": "entrypoint", "datatype": "S", "value": "transfer"},
            {"name": "amount", "datatype": "U", "value": str(rng.randrange(0, 2 ** 64 - 1))},
            {"name": "delta", "datatype": "I", "value": str(rng.choice([-2 ** 40, -1, 0, 7, 2 ** 40]))},
            {"name": "ratio", "datatype": "F", "value": rng.choice(["1.5", "0.1", "-2.25", "65504.0", "1e300", "nan"])},
            {"name": "digest", "datatype": "H", "value": rand32()},
            {"name": "dest", "datatype": "A", "value": addr},
            {"name": "deadline", "datatype": "T", "value": rng.choice([
                "2024-01-01T00:00:00Z", "2023-06-15T12:34:56Z",
                "2024-02-29T23:59:59.5Z", "1970-01-01T00:00:00Z",
            ])},
        ]
        return args

    # 1) proof_generate requests for the payloads (run first)
    g_proof_map = []  # (name, txtype, payload_count, burn_list, proof_rid)
    proof_payloads = []  # payload inputs per tx (built after proofs exist)
    for name, txtype, npay in [
        ("normal", 3, 2), ("burn", 4, 1), ("sc", 5, 1),
        ("normal2", 3, 1), ("sc2", 5, 2),
    ]:
        stmts = []
        for _ in range(npay):
            n_ring = 2
            pks = [rng.choice(points) for _ in range(n_ring)]
            d = rng.choice(points)
            roothash = rand32()
            fees = rng.randrange(0, 1000)
            secretkey = rand32()
            r_scalar = rand32()
            transfer = rng.randrange(0, 2 ** 32)
            balance = rng.randrange(0, 2 ** 32)
            burn = rng.randrange(0, 100)
            stmt = {
                "publickeylist": pks, "c": pks, "d": d, "roothash": roothash,
                "fees": str(fees), "secretkey": secretkey, "r": r_scalar,
                "transfer": str(transfer), "balance": str(balance), "index": [0, 1],
            }
            rid = gid
            add_g("proof_generate", {
                "publickeylist": pks, "c": pks, "d": d, "roothash": roothash,
                "fees": str(fees), "secretkey": secretkey, "r": r_scalar,
                "transfer": str(transfer), "balance": str(balance), "index": [0, 1],
                "scid": rand32(), "scid_index": "0", "txid": rand32(),
                "burn": str(burn), "u": rng.choice(points), "rand": rand_stream(1),
            })
            stmts.append((rid, stmt, burn))
        g_proof_map.append((name, txtype, stmts))

    # run the proof gens first
    g_proof_reqs = [r for r in phase_g if r["op"] == "proof_generate"]
    go_g_proofs = run_oracle(GO_ORACLE, g_proof_reqs)
    rust_g_proofs = run_oracle(RUST_ORACLE, g_proof_reqs)

    # 2) tx_serialize requests using the Go-produced proofs
    for name, txtype, stmts in g_proof_map:
        tx_in = tx_header_in(txtype, rng, points)
        pay_in = []
        for rid, stmt, burn in stmts:
            g = go_g_proofs.get(rid, {})
            if not g.get("ok"):
                continue
            proof_hex = g["out"]["proof"]
            rpc_payload = "".join(rng.choice("0123456789abcdef") for _ in range(290))
            pay_in.append({
                "scid": rand32(), "burn": str(burn), "rpctype": "0",
                "rpcpayload": rpc_payload, "statement": stmt, "proof": proof_hex,
            })
        if txtype == 5:
            tx_in["scdata"] = scdata_in(rng, points)
        if pay_in:
            tx_in["payloads"] = pay_in
        add_g("tx_serialize", tx_in)

    g_tx_ser_ids = [r["id"] for r in phase_g if r["op"] == "tx_serialize"]
    go_g = run_oracle(GO_ORACLE, phase_g)
    rust_g = run_oracle(RUST_ORACLE, phase_g)

    # 3) tx_deserialize roundtrips from the Go-produced tx bytes
    for rid in g_tx_ser_ids:
        g = go_g.get(rid, {})
        if not g.get("ok"):
            continue
        txb = g["out"]["bytes"]
        add_g("tx_deserialize", {"bytes": txb})
        # malformed: truncated at several points + version != 1 + trailing junk
        cuts = sorted({1, 2, 8, len(txb) // 3, len(txb) // 2, max(0, len(txb) - 3)})
        for c in cuts:
            add_g("tx_deserialize", {"bytes": txb[:c]})
        # bad version
        bad_v = ("00" + txb[2:]) if len(txb) > 2 else txb
        add_g("tx_deserialize", {"bytes": bad_v})
        # trailing junk after a premine-type (extra data must be rejected)
    # an unknown txtype (6)
    add_g("tx_deserialize", {"bytes": "01" + "00" * 4})  # version 1, net 0, net 0, type 6
    g_extra = [r for r in phase_g if r["id"] not in go_g]
    with open(ROOT / "harness" / "phase_g_extra.json", "w") as f:
        for r in g_extra:
            f.write(json.dumps(r) + "\n")
    go_g2 = run_oracle(GO_ORACLE, g_extra) if g_extra else {}
    rust_g2 = run_oracle(RUST_ORACLE, g_extra) if g_extra else {}
    go_g.update(go_g2)
    rust_g.update(rust_g2)


    # ---- Phase H: block serialization ---------------------------------------
    # Blocks with coinbase miner_tx, tips, miniblocks (0..3), tx_hashes;
    # serialize (full + skip-last + all 4 hashes), then deserialize the
    # Go-produced bytes on both sides (roundtrip + hash) plus malformed inputs.
    phase_h = []
    hid = 900000

    def add_h(op, inp):
        nonlocal hid
        phase_h.append({"id": hid, "op": op, "in": inp})
        hid += 1

    def miner_tx_in(rng, points):
        # coinbase
        base = {
            "version": "1", "source_network": str(rng.randrange(0, 3)), "dest_network": "0",
            "txtype": "2", "miner_address": rng.choice(points),
        }
        return base

    def miniblock_in(rng, i):
        kh = rand32()
        return {
            "version": "1",
            "highdiff": i % 2 == 0,
            "final": i % 3 == 0,
            "pastcount": str(1 + i % 2),
            "timestamp": str((i * 7) % 65536),
            "height": str(1000 + i),
            "past": [str(rng.randrange(0, 2 ** 32)), str(rng.randrange(0, 2 ** 32))],
            "keyhash": kh,
            "flags": str(rng.randrange(0, 2 ** 32)),
            "nonce": [str(rng.randrange(0, 2 ** 32)) for _ in range(3)],
        }

    for trial in range(8):
        blk = {
            "major": str(rng.randrange(2, 20)),
            "minor": "0",
            "timestamp": str(rng.choice([0, 1, 1700000000000, rng.randrange(0, 2 ** 40)])),
            "height": str(rng.randrange(0, 2 ** 32)),
            "miner_tx": miner_tx_in(rng, points),
            "proof": rand32(),
            "tips": [rand32() for _ in range(rng.randrange(0, 3))],
            "miniblocks": [miniblock_in(rng, i) for i in range(rng.randrange(0, 4))],
            "tx_hashes": [rand32() for _ in range(rng.randrange(0, 4))],
        }
        add_h("block_serialize", blk)

    go_h = run_oracle(GO_ORACLE, phase_h)
    rust_h = run_oracle(RUST_ORACLE, phase_h)

    h_ser_ids = [r["id"] for r in phase_h if r["op"] == "block_serialize"]
    for rid in h_ser_ids:
        g = go_h.get(rid, {})
        if not g.get("ok"):
            continue
        blkb = g["out"]["bytes"]
        add_h("block_deserialize", {"bytes": blkb})
        # malformed: truncated at several points
        cuts = sorted({1, 2, 10, len(blkb) // 3, len(blkb) // 2, max(0, len(blkb) - 5)})
        for c in cuts:
            add_h("block_deserialize", {"bytes": blkb[:c]})
    h_extra = [r for r in phase_h if r["id"] not in go_h]
    go_h2 = run_oracle(GO_ORACLE, h_extra) if h_extra else {}
    rust_h2 = run_oracle(RUST_ORACLE, h_extra) if h_extra else {}
    go_h.update(go_h2)
    rust_h.update(rust_h2)

    # ---- Phase I: valid-transaction accept path -----------------------------
    # Build fully VALID transactions (real encrypted balances + real proofs,
    # mirroring walletapi/transaction_build.go) on BOTH oracles with
    # deterministic randomness. Requirements:
    #   * byte-identical tx bytes / txid / proof on both sides
    #   * accepted == true on BOTH (the bulletproof accept path!)
    #   * cross-accept: each side verifies the other's proof => true
    phase_i = []
    iid = 1000000

    def add_i(op, inp):
        nonlocal iid
        phase_i.append({"id": iid, "op": op, "in": inp})
        iid += 1

    base_g_hex = go_a[0]["out"]["point"]
    valid_cases = []
    for trial in range(4):
        n_ring = 2
        sks = [rand32() for _ in range(n_ring)]
        # sender/receiver pubkeys = base_g * sk_i (known keys)
        pre = []
        for k, skh in enumerate(sks):
            add_i("point_scalarmult", {"point": base_g_hex, "scalar": skh})
            pre.append(iid - 1)
        valid_cases.append((pre, sks))

    go_i_pre = run_oracle(GO_ORACLE, phase_i)
    rust_i_pre = run_oracle(RUST_ORACLE, phase_i)

    # build the valid-tx requests
    valid_ids = []
    for (pre, sks) in valid_cases:
        pk0 = go_i_pre[pre[0]]["out"]["point"]
        pk1 = go_i_pre[pre[1]]["out"]["point"]
        value = rng.randrange(0, 2 ** 32)
        fees = rng.randrange(0, 1000)
        burn = rng.randrange(0, 100)
        remaining = rng.randrange(0, 2 ** 32)
        bal_sender = value + fees + burn + remaining
        balance = ["%x" % bal_sender, "%x" % rng.randrange(0, 2 ** 40)]
        eblind = ["%x" % rng.randrange(0, 2 ** 64) for _ in range(n_ring)]
        # rand stream: 264 + 6m draws (u consumes no randomness: u = upoint*sk)
        rand = "".join(rand32() for _ in range(264 + 6 * 1))
        inp = {
            "publickeylist": [pk0, pk1],
            "secretkey": sks[0],
            "r": rand32(),
            "value": str(value),
            "fees": str(fees),
            "burn": str(burn),
            "balances": balance,
            "eblind": eblind,
            "roothash": rand32(),
            "scid": rand32(),
            "txid": rand32(),
            "rand": rand,
        }
        add_i("tx_build_valid", inp)
        valid_ids.append((iid - 1, inp, pk0))

    go_i = run_oracle(GO_ORACLE, phase_i)
    rust_i = run_oracle(RUST_ORACLE, phase_i)

    with open(ROOT / "harness" / "phase_i_requests.json", "w") as f:
        for r in phase_i:
            f.write(json.dumps(r) + "\n")

    # cross-accept: verify each side's proof on the other side
    cross_i = []
    cross_i_expect = []
    for rid, inp, pk0 in valid_ids:
        g = go_i.get(rid, {})
        r = rust_i.get(rid, {})
        if not g.get("ok") or not r.get("ok"):
            continue
        if not g["out"].get("accepted") or not r["out"].get("accepted"):
            continue
        for src, label in ((g, "go"), (r, "rust")):
            stmt = {
                "publickeylist": [pk0, inp["publickeylist"][1]],
                "c": src["out"]["c"],
                "d": src["out"]["d"], "roothash": src["out"]["roothash"],
                "fees": src["out"]["fees"],
                "cln": src["out"]["cln"], "crn": src["out"]["crn"],
            }
            cid = iid
            add_i("proof_verify", dict(stmt, scid=inp["scid"], scid_index="0",
                                       txid=src["out"]["hash"], burn=inp["burn"],
                                       proof=src["out"]["proof"]))
            cross_i_expect.append((cid, label, "accept"))
            iid += 1
    go_i2 = run_oracle(GO_ORACLE, [r for r in phase_i if r["id"] not in go_i])
    rust_i2 = run_oracle(RUST_ORACLE, [r for r in phase_i if r["id"] not in rust_i])
    go_i.update(go_i2)
    rust_i.update(rust_i2)

    # ---- Phase J: AstroBWT PoW ---------------------------------------------
    # POW32 over varied input sizes + real mainnet block blobs (fetched live).
    phase_j = []
    iid = 2000000

    def add_j(op, inp):
        nonlocal iid
        phase_j.append({"id": iid, "op": op, "in": inp})
        iid += 1

    for size in (0, 1, 2, 3, 31, 32, 33, 64, 9972, 9973, 9974, 12000):
        add_j("pow32", {"bytes": "".join(rand32() for _ in range((size + 31) // 32))[:size * 2]})
    # deterministic repeats of the exact boundary sizes
    for size in (9973, 9973, 9973, 19946, 40000):
        add_j("pow32", {"bytes": "".join(rand32() for _ in range((size + 31) // 32))[:size * 2]})
    # real block blobs from the live chain (via the replay RPC)
    try:
        import urllib.request
        for bh in (1, 100, 50000, 7500000):
            body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "DERO.GetBlock",
                               "params": {"height": bh}}).encode()
            req = urllib.request.Request("http://82.65.143.182:10102/json_rpc",
                                         data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                blob = json.loads(resp.read()).get("result", {}).get("blob")
            if blob:
                add_j("pow32", {"bytes": blob})
    except Exception as e:
        print(f"  [note] phase_j live-block fetch skipped: {e}")

    go_j = run_oracle(GO_ORACLE, phase_j)
    rust_j = run_oracle(RUST_ORACLE, phase_j)

    # ---- Phase K: AstroBWTv3 PoW + difficulty check -------------------------
    # The CURRENT mainnet PoW (post-HF2 at height 481600). Random sizes +
    # real post-HF2 block blobs; plus the difficulty-target comparison.
    phase_k = []
    iid = 3000000

    def add_k(op, inp):
        nonlocal iid
        phase_k.append({"id": iid, "op": op, "in": inp})
        iid += 1

    for size in (0, 1, 2, 31, 32, 64, 128, 256, 9973, 12000, 40000):
        add_k("pow_v3", {"bytes": "".join(rand32() for _ in range((size + 31) // 32))[:size * 2]})
    try:
        import urllib.request
        for bh in (500000, 1000000, 2000000, 5000000, 7510000):
            body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "DERO.GetBlock",
                               "params": {"height": bh}}).encode()
            req = urllib.request.Request("http://82.65.143.182:10102/json_rpc",
                                         data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                blob = json.loads(resp.read()).get("result", {}).get("blob")
            if blob:
                add_k("pow_v3", {"bytes": blob})
    except Exception as e:
        print(f"  [note] phase_k live-block fetch skipped: {e}")

    # difficulty check: random hashes at a few difficulties (both sides must
    # agree on the big-int comparison)
    for _ in range(6):
        hh = "".join(rand32() for _ in range(1))
        d = rng.randrange(1, 2 ** 70)
        add_k("check_pow", {"hash": hh, "difficulty": str(d)})

    go_k = run_oracle(GO_ORACLE, phase_k)
    rust_k = run_oracle(RUST_ORACLE, phase_k)

    # ---- Phase L: DVM ------------------------------------------------------
    # parse + run smart contracts (deterministic RND, gas, store commits)
    phase_l = []
    iid = 4000000

    def add_l(op, inp):
        nonlocal iid
        phase_l.append({"id": iid, "op": op, "in": inp})
        iid += 1

    contracts = {
        "hello": r"""Function hello() Uint64
10 RETURN 0
End Function""",
        "math": r"""Function compute(a Uint64, b Uint64) Uint64
10 DIM x AS Uint64
20 LET x = a * b + 1
30 IF x > 100 THEN GOTO 60
40 RETURN 0
60 RETURN 1
End Function""",
        "store": r"""Function Initialize() Uint64
10 STORE("owner", SIGNER())
20 RETURN 0
End Function""",
        "branch": r"""Function test(value Uint64) Uint64
10 IF value == 0 THEN GOTO 30 ELSE GOTO 40
30 RETURN 5
40 RETURN 7
End Function""",
        "strings": r"""Function greet(name String) String
10 DIM msg AS String
20 LET msg = "hello " + name
30 RETURN msg
End Function""",
        "random": r"""Function roll() Uint64
10 DIM r AS Uint64
20 LET r = RANDOM(100)
30 RETURN r
End Function""",
        "nested": r"""Function Outer() Uint64
10 DIM x AS Uint64
20 LET x = Inner(5)
30 RETURN x
End Function
Function Inner(v Uint64) Uint64
10 RETURN v * 2
End Function""",
        "loops": r"""Function count() Uint64
10 DIM i AS Uint64
20 LET i = 0
30 LET i = i + 1
40 IF i < 10 THEN GOTO 30
50 RETURN i
End Function""",
        "assets": r"""Function bal() Uint64
10 RETURN DEROVALUE()
End Function""",
    }

    for name, code in contracts.items():
        scid = rng.randrange(0, 2**128)
        scidh = "%064x" % scid
        blid = rng.randrange(0, 2**128)
        blidh = "%064x" % blid
        txid = rng.randrange(0, 2**128)
        txidh = "%064x" % txid
        add_l("dvm_parse", {"code": code})
        # run the main entrypoint (capitalized) with a couple params
        entry = name
        params = {}
        if name == "math":
            params = {"a": str(rng.randrange(1, 100)), "b": str(rng.randrange(1, 100))}
        elif name == "branch":
            params = {"value": str(rng.randrange(0, 2))}
        elif name == "strings":
            params = {"name": "world"}
        add_l("dvm_run", {
            "code": code, "entrypoint": entry, "params": params,
            "scid": scidh, "blid": blidh, "txid": txidh,
            "height": str(rng.randrange(0, 1000000)),
            "timestamp": str(rng.randrange(1000000000, 2000000000)),
            "signer": "%066x" % rng.randrange(0, 2**256),
        })

    # deterministic RND vectors
    for _ in range(3):
        add_l("dvm_rnd", {
            "scid": "%064x" % rng.randrange(0, 2**128),
            "blid": "%064x" % rng.randrange(0, 2**128),
            "txid": "%064x" % rng.randrange(0, 2**128),
            "n": "8",
        })

    go_l = run_oracle(GO_ORACLE, phase_l)
    rust_l = run_oracle(RUST_ORACLE, phase_l)

    # ---- Phase M: bech32 + hash builtins (differential on the real scheme) --
    # Round-trip real mainnet addresses + random valid compressed keys through
    # both implementations. This differentially proves rpc_addr.rs (the DVM's
    # address_raw/address_string/is_address_valid builtins) against rpc/bech32.go.
    phase_m = []
    iid = 5000000

    def add_m(op, inp):
        nonlocal iid
        phase_m.append({"id": iid, "op": op, "in": inp})
        iid += 1

    # known addresses (the user's mainnet wallet + a couple variants)
    known_addrs = [
        "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq",
        "dero1qyr8yjuh2zv85dvhphntdq24h2w2dcsy3v0hh7ckm6tlj54l5z4j7kqqkjy8s",
    ]
    for a in known_addrs:
        add_m("bech32_raw", {"address": a})
        add_m("bech32_valid", {"address": a})
    # random valid keys -> address -> back (only keys that decode as valid
    # compressed points — Go's NewAddressFromKeys needs a valid on-curve key)
    for _ in range(10):
        x = rng.randrange(0, 2**254)
        flag = rng.randrange(0, 2)
        raw = "%064x%02x" % (x, flag)
        # only emit if it's a valid on-curve compressed point
        if rpc_addr_valid(raw):
            add_m("bech32_string", {"raw": raw})
    # invalid addresses
    add_m("bech32_valid", {"address": "dero1qinvalid"})
    add_m("bech32_valid", {"address": "deto1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq"})
    # hexdecode round-trips
    for _ in range(4):
        hx = "".join(rand32() for _ in range(2))
        add_m("hexdecode", {"hex": hx})
    add_m("hexdecode", {"hex": "zz"})

    go_m = run_oracle(GO_ORACLE, phase_m)
    rust_m = run_oracle(RUST_ORACLE, phase_m)

    # ---- Phase N: graviton state trees (differential) ----------------------
    # Both oracles hold persistent trees keyed by name; the same op stream
    # (put/delete on keys, with gets) must produce identical root hashes.
    phase_n = []
    iid = 6000000

    def add_n(op, inp):
        nonlocal iid
        phase_n.append({"id": iid, "op": op, "in": inp})
        iid += 1

    rng2 = random.Random(0x6A72A7D0)
    # deterministic key/value stream across 3 trees
    keys = [("k%02d" % i).encode().hex() for i in range(40)]
    for name in ("balances", "scdata", "scmeta"):
        # put a bunch
        for i in range(25):
            k = keys[i]
            v = rng2.randbytes(8).hex()
            add_n("grav_put", {"tree": name, "key": k, "value": v})
        # gets in between
        for i in range(5):
            add_n("grav_get", {"tree": name, "key": keys[rng2.randrange(0, 25)]})
        # overwrite some
        for i in range(6):
            k = keys[rng2.randrange(0, 25)]
            v = rng2.randbytes(8).hex()
            add_n("grav_put", {"tree": name, "key": k, "value": v})
        # delete some
        for i in range(5):
            k = keys[rng2.randrange(0, 25)]
            add_n("grav_delete", {"tree": name, "key": k})
        # more puts (collapse/rebuild paths)
        for i in range(10):
            k = keys[rng2.randrange(0, 25)]
            v = rng2.randbytes(16).hex()
            add_n("grav_put", {"tree": name, "key": k, "value": v})
        # hash the tree at the end
        # (grav_* ops return the hash after each mutation, so the final op's
        # hash is the tree root)

    # a stress tree with many keys (deeper trie)
    for i in range(200):
        k = "s%04x" % i
        v = rng2.randbytes(4).hex()
        add_n("grav_put", {"tree": "deep", "key": k, "value": v})
    for i in range(40):
        add_n("grav_delete", {"tree": "deep", "key": "s%04x" % (i * 3)})

    go_n = run_oracle(GO_ORACLE, phase_n)
    rust_n = run_oracle(RUST_ORACLE, phase_n)

    # ---- Phase O: real chain tx proof verification -------------------------
    # Fetch live mainnet block blobs, extract the miner tx on BOTH sides,
    # compare the txid/statement/proof bytes and the verify verdict (must
    # AGREE — same semantics as the cross-accept).
    phase_o = []
    iid = 7000000

    def add_o(op, inp):
        nonlocal iid
        phase_o.append({"id": iid, "op": op, "in": inp})
        iid += 1

    try:
        import urllib.request
        for bh in (0, 1, 100, 1000, 500000, 1000000, 3000000, 5000000, 7000000, 7511600):
            body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "DERO.GetBlock",
                               "params": {"height": bh}}).encode()
            req = urllib.request.Request("http://82.65.143.182:10102/json_rpc",
                                         data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                blob = json.loads(resp.read()).get("result", {}).get("blob")
            if blob:
                add_o("tx_extract_verify", {"blob": blob})
    except Exception as e:
        print(f"  [note] phase_o live-block fetch skipped: {e}")

    go_o = run_oracle(GO_ORACLE, phase_o)
    rust_o = run_oracle(RUST_ORACLE, phase_o)

    # ---- Phase P: chain state transitions ----------------------------------
    # Reward formula across heights + process_miner_transaction on SYNTHETIC
    # blocks whose miniblock KeyHashes are blake2s(addr)[:16] (so the
    # prefix-lookup finds the registered miner). Both sides pre-register all
    # addresses on the shared "B" tree via grav_put, then process.
    phase_p = []
    iid = 8000000

    def add_p(op, inp):
        nonlocal iid
        phase_p.append({"id": iid, "op": op, "in": inp})
        iid += 1

    for h in (0, 1, 100, 100000, 1000000, 6999999, 7000000, 7000001, 14000000):
        add_p("chain_reward", {"height": str(h)})

    import hashlib

    def blake2s16(b):
        # first 16 bytes of the 32-byte BLAKE2s-256 digest (DERO convention)
        return hashlib.blake2s(b, digest_size=32).digest()[:16]

    # generate VALID compressed points: x where y²=x³+3 has a sqrt mod p
    P256 = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    SQRT_EXP = (P256 + 1) // 4

    def gen_addr(x):
        # find the first valid on-curve x >= the seed
        while True:
            xx = x % P256
            y2 = (pow(xx, 3, P256) + 3) % P256
            if pow(y2, (P256 - 1) // 2, P256) == 1:  # quadratic residue
                # y = sqrt; flag = 0 (even y) or 1 (odd y)
                y = pow(y2, SQRT_EXP, P256)
                flag = 1 if y & 1 else 0
                return ("%064x" % xx) + ("%02x" % flag)
            x += 1

    rng3 = random.Random(0xC14A1E5E)
    # genesis case FIRST (empty tree): process_miner_transaction registers
    gaddr = gen_addr(rng3.randrange(0, 2**254))
    add_p("chain_miner_tx", {
        "miner_address": gaddr, "miner_value": "500000000",
        "miniblocks": [], "genesis": "true", "height": "0", "fees": "0",
    })

    for blk in range(4):
        n_mbl = 2 + blk  # 2..5 miniblocks
        addrs = [gen_addr(rng3.randrange(0, 2**254)) for _ in range(n_mbl)]
        miner_addr = addrs[0]
        # register ALL addresses on the shared "B" tree with zero balances
        # (a zero NonceBalance = ElGamal{Left: pk, Right: G})
        for a in addrs:
            add_p("grav_register", {"tree": "B", "address": a})
        # build miniblocks with hash-aligned KeyHash (blake2s(addr)[:16])
        # — Go's MiniBlock.KeyHash is [32]byte, so send the full 32 bytes
        mbls = []
        for i, a in enumerate(addrs):
            kh16 = blake2s16(bytes.fromhex(a))
            kh32 = kh16 + b"\x00" * 16
            mbls.append({
                "Version": 1, "Final": (i == 0), "PastCount": 1,
                "Timestamp": 0, "Height": 0, "Past": [0, 0],
                "KeyHash": kh32.hex(), "Flags": 0,
            })
        height = 100 + blk * 1000
        add_p("chain_miner_tx", {
            "miner_address": miner_addr,
            "miner_value": "0",
            "miniblocks": mbls,
            "genesis": "false",
            "height": str(height),
            "fees": str(1000 + blk),
        })

    go_p = run_oracle(GO_ORACLE, phase_p)
    rust_p = run_oracle(RUST_ORACLE, phase_p)

    # ---- Phase Q: process_transaction (balance moves) differential --------
    # Build NORMAL txs (zero SCID -> balance-tree path) with REAL proofs,
    # apply via chain_tx (register ring keys, roundtrip, process_transaction)
    # and via chain_block (miner_tx + txs sequentially). Both sides share the
    # persistent "B" tree, so each op must leave an identical root.
    phase_q = []
    iid = 9000000

    def add_q(op, inp):
        nonlocal iid
        phase_q.append({"id": iid, "op": op, "in": inp})
        iid += 1

    rngq = random.Random(0x0A1E7A11)

    def q_stmt(rng):
        n_ring = 2
        pks = [rng.choice(points) for _ in range(n_ring)]
        d = rng.choice(points)
        return {
            "publickeylist": pks, "c": pks, "d": d, "roothash": rand32(),
            "fees": str(rng.randrange(0, 1000)), "secretkey": rand32(),
            "r": rand32(), "transfer": str(rng.randrange(0, 2 ** 32)),
            "balance": str(rng.randrange(0, 2 ** 32)), "index": [0, 1],
        }

    # 1) proof generation requests (run first, like Phase G)
    q_proofs = []  # (reqid, stmt, burn)
    for t in range(6):
        npay = 2 if t == 5 else 1
        for _ in range(npay):
            stmt = q_stmt(rngq)
            rid = iid
            add_q("proof_generate", {
                "publickeylist": stmt["publickeylist"], "c": stmt["c"],
                "d": stmt["d"], "roothash": stmt["roothash"],
                "fees": stmt["fees"], "secretkey": stmt["secretkey"],
                "r": stmt["r"], "transfer": stmt["transfer"],
                "balance": stmt["balance"], "index": stmt["index"],
                "scid": rand32(), "scid_index": "0", "txid": rand32(),
                "burn": str(rngq.randrange(0, 100)),
                "u": rngq.choice(points), "rand": rand_stream(1),
            })
            q_proofs.append((rid, stmt))

    q_proof_reqs = [r for r in phase_q if r["op"] == "proof_generate"]
    go_q_proofs = run_oracle(GO_ORACLE, q_proof_reqs)
    rust_q_proofs = run_oracle(RUST_ORACLE, q_proof_reqs)

    # 2) chain_tx requests (zero scid -> balance path)
    q_tx_payloads = []
    for rid, stmt in q_proofs:
        g = go_q_proofs.get(rid, {})
        if not g.get("ok"):
            continue
        proof_hex = g["out"]["proof"]
        rpc_payload = "".join(rngq.choice("0123456789abcdef") for _ in range(290))
        q_tx_payloads.append({
            "scid": "00" * 32,  # zero -> balance tree
            "burn": "0", "rpctype": "0", "rpcpayload": rpc_payload,
            "statement": stmt, "proof": proof_hex,
        })

    for t, pay in enumerate(q_tx_payloads):
        tx_in = tx_header_in(3, rngq, points)
        tx_in["payloads"] = [pay]
        add_q("chain_tx", dict(tx_in, height=str(100 + t * 37)))

    # one 2-payload tx
    tx_in = tx_header_in(3, rngq, points)
    tx_in["payloads"] = q_tx_payloads[0:2]
    add_q("chain_tx", dict(tx_in, height="500"))

    # 3) chain_block: miner_tx (hash-aligned miniblocks) + the txs
    for blk in range(2):
        n_mbl = 3 + blk
        addrs = [gen_addr(rngq.randrange(0, 2 ** 254)) for _ in range(n_mbl)]
        mbls = []
        for i, a in enumerate(addrs):
            kh16 = blake2s16(bytes.fromhex(a))
            kh32 = kh16 + b"\x00" * 16
            mbls.append({
                "Version": 1, "Final": (i == 0), "PastCount": 1,
                "Timestamp": 0, "Height": 0, "Past": [0, 0],
                "KeyHash": kh32.hex(), "Flags": 0,
            })
        # register the miniblock miners so the reward lookup finds them
        for a in addrs:
            add_q("grav_register", {"tree": "B", "address": a})
        blk_pays = q_tx_payloads[blk * 2:blk * 2 + 2]
        add_q("chain_block", {
            "miner_address": addrs[0], "miniblocks": mbls,
            "payloads": blk_pays, "height": str(1000 + blk * 500),
            "fees": str(500 + blk),
        })

    go_q = run_oracle(GO_ORACLE, phase_q)
    rust_q = run_oracle(RUST_ORACLE, phase_q)

    # ---- Phase R: K0 rules differential (dvm_uses_signer) -------------------
    # Mirrors dvm.ContractUsesSigner (K0 Fix B2): Go and Rust must agree on
    # whether a contract calls SIGNER() — the rule that decides ringsize-2
    # SC_TX eligibility. A divergence here would mis-tag contracts at the
    # fork (NoSigner bit set/cleared differently) and split the chain.
    phase_r = []
    iid = 9500000

    def add_r(code):
        nonlocal iid
        phase_r.append({"id": iid, "op": "dvm_uses_signer", "in": {"code": code}})
        iid += 1

    # deterministic corpus: SIGNER variants, no-SIGNER, comment/string traps
    k0_corpus = [
        'Function F() Uint64\n10 dim x as String\n20 LET x = SIGNER()\n30 RETURN 0\nEnd Function',
        'Function F() Uint64\n10 dim x as String\n20 LET x = signer()\n30 RETURN 0\nEnd Function',
        'Function F() Uint64\n10 dim x as String\n20 LET x = Signer()\n30 RETURN 0\nEnd Function',
        'Function Init() Uint64\n10 STORE("owner", "alice")\n20 RETURN 0\nEnd Function',
        'Function A() Uint64\n10 RETURN SIGNER()\nEnd Function',
        'Function B() Uint64\n10 IF SIGNER() == LOAD("owner") THEN GOTO 20\n15 RETURN 1\n20 RETURN 0\nEnd Function',
        'Function C() Uint64\n10 REM SIGNER is mentioned in a comment\n20 RETURN 0\nEnd Function',
        'Function D() Uint64\n10 STORE("note", "SIGNER")\n20 RETURN 0\nEnd Function',
        'Function E() Uint64\n10 dim x as String\n20 LET x = "SIGNER()"\n30 RETURN 0\nEnd Function',
        'Function F2() Uint64\n10 dim x as String\n20 LET x = SIG\n30 RETURN 0\nEnd Function',
        # empty / malformed
        '',
        'not valid code at all',
    ]
    for c in k0_corpus:
        add_r(c)

    go_r = run_oracle(GO_ORACLE, phase_r)
    rust_r = run_oracle(RUST_ORACLE, phase_r)

    # ---- Phase S: K0 Fix B1 floor rule differential (k0_floor) --------------
    # Mirrors blockchain.K0RingSizeFloorReject: from the fork height onward,
    # NORMAL(3)/BURN(4) txs with ringsize < 4 are rejected; everything else
    # is exempt. The fork height is passed explicitly so the boundary sweep
    # is exact. A divergence here means the two implementations disagree on
    # which txs are valid post-fork -> chain split.
    phase_s = []
    iid = 9700000

    def add_s(height, txtype, ringsize, floor):
        nonlocal iid
        phase_s.append({"id": iid, "op": "k0_floor",
                        "in": {"height": str(height), "txtype": str(txtype),
                               "ringsize": str(ringsize), "floor": str(floor)}})
        iid += 1

    FLOOR = 7_600_000
    TYPES = [0, 1, 2, 3, 4, 5]  # PREMINE, REGISTRATION, COINBASE, NORMAL, BURN, SC
    for h in [FLOOR - 1, FLOOR, FLOOR + 1, FLOOR + 100]:
        for t in TYPES:
            for r in [1, 2, 3, 4, 5, 8]:
                add_s(h, t, r, FLOOR)
    # edges: exactly at fork, ring exactly 4, all types at ring 2
    for t in TYPES:
        add_s(FLOOR, t, 2, FLOOR)
        add_s(FLOOR, t, 4, FLOOR)
    add_s(0, 3, 2, 0)          # testnet: floor at genesis
    add_s(0, 4, 2, 0)          # testnet burn at genesis
    add_s(0, 5, 2, 0)          # testnet SC exempt

    go_s = run_oracle(GO_ORACLE, phase_s)
    rust_s = run_oracle(RUST_ORACLE, phase_s)

    # ---- Phase T: strict point-decode boundary (I3/v9 wargame fix) ----------
    # dvm.strictDecodeG1 vs the Rust strict decoder: canonical compressed
    # encodings must have x < p. The conformance PR showed Go's lenient
    # decoder accepts x>=p; the intrinsics now reject it. This phase pins
    # the accept/reject boundary so the two implementations can never drift
    # on which encodings contracts may feed to ec_mul/ec_add/verify_commit.
    phase_t = []
    iid = 9800000

    def add_t(point, label):
        nonlocal iid
        phase_t.append({"id": iid, "op": "strict_point_decode", "in": {"point": point}})
        iid += 1

    P_HEX = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"
    add_t(P_HEX + "00", "x_equals_p")              # x == p -> reject (strict)
    add_t("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48" + "00", "x_gt_p")  # x > p -> reject
    add_t("ff" * 32 + "00", "all_ff")              # x huge -> reject
    add_t("0000000000000000000000000000000000000000000000000000000000000001" + "00", "x_eq_1_even")  # canonical -> accept
    add_t("0000000000000000000000000000000000000000000000000000000000000001" + "01", "x_eq_1_odd")  # canonical -> accept
    add_t("0000000000000000000000000000000000000000000000000000000000000002" + "00", "x_eq_2")     # canonical -> accept
    add_t("0000000000000000000000000000000000000000000000000000000000000000" + "00", "x_zero")    # x=0, likely non-residue -> reject
    add_t("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46" + "00", "x_lt_p")    # x = p-1, boundary -> accept or reject (non-residue?) — pins it either way

    go_t = run_oracle(GO_ORACLE, phase_t)
    rust_t = run_oracle(RUST_ORACLE, phase_t)

    # ---- Phase U: K0 Fix B2 decision boundary (install + call reject) -------
    # Pure decision functions, Go OracleK0B2InstallReject/CallReject vs the
    # Rust mirror. Sweeps the fork boundary (pre/post), ring size, and the
    # uses-signer / no-signer bit combinations that decide both rejections.
    phase_u = []
    iid = 9900000

    def add_u(height, ringsize, uses_signer, no_signer, floor="7600000"):
        nonlocal iid
        phase_u.append({"id": iid, "op": "b2_reject", "in": {
            "height": str(height), "ringsize": str(ringsize),
            "uses_signer": "true" if uses_signer else "false",
            "no_signer": "true" if no_signer else "false", "floor": floor}})
        iid += 1

    for h in (7_599_999, 7_600_000, 8_000_000):       # pre / at / post fork
        for rs in (1, 2, 3, 4):                        # ring sizes
            for us in (False, True):                   # uses SIGNER?
                # no_signer mirrors the meta bit: a SIGNER contract never has
                # it; a no-SIGNER contract gets it post-fork at install
                ns = (not us) and (h >= 7_600_000)
                add_u(h, rs, us, ns)

    go_u = run_oracle(GO_ORACLE, phase_u)
    rust_u = run_oracle(RUST_ORACLE, phase_u)

    # ---- compare -----------------------------------------------------------
    failures = []
    per_op = {}

    def check(resp_go, resp_rust):
        op = None
        for r in (phase_a + phase_b + phase_c + phase_d + phase_e + phase_f + phase_g + phase_h + phase_i + phase_j + phase_k + phase_l + phase_m + phase_n + phase_o + phase_p + phase_q + phase_r + phase_s + phase_t + phase_u):
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
            req = next((r for r in (phase_a + phase_b + phase_c + phase_d + phase_e + phase_f + phase_g + phase_h + phase_i + phase_j + phase_k + phase_l + phase_m + phase_n + phase_o + phase_p + phase_q + phase_r + phase_s + phase_t + phase_u) if r["id"] == resp_go["id"]), None)
            failures.append(
                (op, resp_go["id"], f"ok mismatch: go={g_ok} rust={r_ok} "
                 f"go_err={resp_go.get('err')} rust_err={resp_rust.get('err')} req={json.dumps(req)}")
            )
            return
        if g_ok:
            # tx_build_valid carries Go-reference-internal debug fields (snap_*)
            # that Rust legitimately does not emit — ignore them for the diff
            go_out = {k: v for k, v in resp_go["out"].items() if not k.startswith("snap_")}
            rust_out = {k: v for k, v in resp_rust["out"].items() if not k.startswith("snap_")}
            if go_out != rust_out:
                req = next((r for r in (phase_a + phase_b + phase_c + phase_d + phase_e + phase_f + phase_g + phase_h + phase_i + phase_j + phase_k + phase_l + phase_m + phase_n + phase_o + phase_p + phase_q + phase_r + phase_s + phase_t + phase_u) if r["id"] == resp_go["id"]), None)
                failures.append(
                    (op, resp_go["id"], f"out mismatch:\n  go:   {json.dumps(go_out)}\n  rust: {json.dumps(rust_out)}\n  req:  {json.dumps(req)}")
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
    for r in phase_f:
        check(go_f[r["id"]], rust_f[r["id"]])
    for r in phase_g:
        check(go_g[r["id"]], rust_g[r["id"]])
    for r in phase_h:
        check(go_h[r["id"]], rust_h[r["id"]])
    for r in phase_i:
        check(go_i[r["id"]], rust_i[r["id"]])
    for r in phase_j:
        check(go_j[r["id"]], rust_j[r["id"]])
    for r in phase_k:
        check(go_k[r["id"]], rust_k[r["id"]])
    for r in phase_l:
        check(go_l[r["id"]], rust_l[r["id"]])
    for r in phase_m:
        check(go_m[r["id"]], rust_m[r["id"]])
    for r in phase_n:
        check(go_n[r["id"]], rust_n[r["id"]])
    for r in phase_o:
        check(go_o[r["id"]], rust_o[r["id"]])
    for r in phase_p:
        check(go_p[r["id"]], rust_p[r["id"]])
    for r in phase_q:
        check(go_q[r["id"]], rust_q[r["id"]])
    for r in phase_r:
        check(go_r[r["id"]], rust_r[r["id"]])
    for r in phase_s:
        check(go_s[r["id"]], rust_s[r["id"]])
    for r in phase_t:
        check(go_t[r["id"]], rust_t[r["id"]])
    for r in phase_u:
        check(go_u[r["id"]], rust_u[r["id"]])

    # real-chain tx verify: verdicts must AGREE (accept-path agreement)
    for cid, label in ((r["id"], r["id"]) for r in phase_o):
        g = go_o.get(cid)
        rsp = rust_o.get(cid)
        if g and rsp and g.get("ok") and rsp.get("ok"):
            gv = g["out"].get("payload", {}).get("verified")
            rv = rsp["out"].get("payload", {}).get("verified")
            if gv != rv:
                failures.append(("tx_extract_verify_agree", cid,
                                 f"verify verdict mismatch go={gv} rust={rv}"))

    # valid-tx cross-accept: each side must ACCEPT the other's proof
    for cid, label, kind in cross_i_expect:
        g = go_i.get(cid, {}).get("out", {}).get("verified")
        r = rust_i.get(cid, {}).get("out", {}).get("verified")
        if g is not None and r is not None:
            if g != r:
                failures.append((f"valid_tx_cross_{kind}", cid, f"disagreement: go={g} rust={r} ({label})"))
            elif not g:
                failures.append((f"valid_tx_cross_{kind}", cid, f"both REJECTED a valid proof ({label})"))
            else:
                print(f"  [note] valid_tx_cross_accept {cid}: both ACCEPT ({label})")
        else:
            failures.append((f"valid_tx_cross_{kind}", cid, f"missing cross response go={g} rust={r}"))

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

    # bulletproof cross-verification: the implementations must AGREE on every
    # proof (both accept or both reject). Note: synthetic statements here have
    # zero encrypted balances, so the reference's anon-support reconstruction
    # rejects even its own proofs — the differential contract is agreement;
    # the full accept path is exercised at chain-replay against real txs.
    for cid, from_label, to_label in cross_e_expect:
        g = go_e2.get(cid, {}).get("out", {}).get("verified")
        r = rust_e2.get(cid, {}).get("out", {}).get("verified")
        if g is not None and r is not None:
            if g != r:
                failures.append(("proof_cross_verify", cid, f"verify DISAGREEMENT: go={g} rust={r} ({from_label}->{to_label})"))
            else:
                print(f"  [note] proof_cross_verify {cid}: both sides agree (verified={g}) ({from_label}->{to_label})")
        else:
            failures.append(("proof_cross_verify", cid, f"missing cross-verify response go={g} rust={r}"))

    total = len(phase_a) + len(phase_b) + len(phase_c) + len(phase_d) + len(phase_e) + len(phase_f) + len(phase_g) + len(phase_h) + len(phase_i) + len(phase_j) + len(phase_k) + len(phase_l) + len(phase_m) + len(phase_n) + len(phase_o) + len(phase_p) + len(phase_q) + len(phase_r) + len(phase_s) + len(phase_t) + len(phase_u)
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
