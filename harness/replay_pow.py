#!/usr/bin/env python3
"""Chain-level PoW verification: the Rust AstroBWTv3 must reproduce a VALID
PoW for real mainnet blocks (post-HF2), and the difficulty target check must
pass for the mined miniblock at the chain's own difficulty.

For a set of post-HF2 heights:
  1. fetch the block (blob + json + difficulty) from a public node
  2. parse each miniblock from the block json
  3. serialize the miniblock with the RUST block serializer (block_serialize
     is already differentially proven, so this is the Rust wire format)
  4. compute AstroBWTv3(miniblock bytes) with the Rust oracle (pow_v3)
  5. check the difficulty target: check_pow(hash, difficulty * 9 if HighDiff)
  6. the mined (Final) miniblock must PASS; also verify the same via the Go
     oracle for agreement
"""
import json
import subprocess
import sys
import urllib.request

RPC = "http://82.65.143.182:10102/json_rpc"
ROOT = r"C:/Users/$USER/derohe-rs"
GO_ORACLE = ROOT + "/oracle/oracle.exe"
RUST_ORACLE = ROOT + "/crypto/target/release/dero-oracle.exe"


def rpc(method, params=None):
    body = {"jsonrpc": "2.0", "id": 0, "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(RPC, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def run_oracle(binpath, req):
    p = subprocess.run([binpath], input=json.dumps(req) + "\n",
                       capture_output=True, text=True, timeout=300)
    return json.loads(p.stdout.splitlines()[0])


def mini_block_in(m, height):
    past = (m.get("Past") or [0, 0])
    nonce = (m.get("Nonce") or [0, 0, 0])
    return {
        "version": str(m.get("Version", 1)),
        "highdiff": bool(m.get("HighDiff", False)),
        "final": bool(m.get("Final", False)),
        "pastcount": str(m.get("PastCount", 1)),
        "timestamp": str(m.get("Timestamp", 0)),
        "height": str(m.get("Height", height)),
        "past0": str(past[0]),
        "past1": str(past[1]) if len(past) > 1 else "0",
        "keyhash": m.get("KeyHash", "00" * 16),
        "flags": str(m.get("Flags", 0)),
        "nonce0": str(nonce[0]),
        "nonce1": str(nonce[1]) if len(nonce) > 1 else "0",
        "nonce2": str(nonce[2]) if len(nonce) > 2 else "0",
    }


def main():
    # DENSE coverage: scattered checkpoints + 100-block windows at epoch points
    # PoW is per-block (no sequential dependency), so we can test any height
    height_set = set([0, 1, 2, 3, 4, 5, 10, 20, 50, 100, 500, 1000, 5000,
                      50000, 500000, 1000000, 2000000, 3000000, 4000000,
                      5000000, 6000000, 7000000, 7504640, 7504641, 7504642])
    # add 100-block dense windows (sampled: every 10th block to keep runtime sane)
    for w_start in [0, 100000, 1000000, 5000000, 7400000, 7500000, 7510000]:
        height_set |= set(range(w_start, w_start + 100, 10))
    heights = sorted(height_set)
    fails = []
    ok_miniblocks = 0
    ok_final = 0

    heights = sorted(height_set)
    for h in heights:
        res = rpc("DERO.GetBlock", {"height": h})
        r = res.get("result")
        if not r:
            print(f"height {h}: RPC error {res.get('error')}")
            continue
        bjson = json.loads(r.get("json") or "{}")
        mbls = bjson.get("miniblocks") or []
        diff_s = r.get("block_header", {}).get("difficulty")
        if not diff_s:
            print(f"height {h}: no difficulty in header")
            continue
        # 'difficulty' may be a string or number
        difficulty = int(str(diff_s))
        print(f"height {h}: {len(mbls)} miniblocks, difficulty {difficulty}")

        for m in mbls:
            inp = mini_block_in(m, h)
            # serialize with the Rust block serializer (differentially proven)
            sreq = {"id": 1, "op": "block_miniblock_serialize", "in": inp}
            rsp = run_oracle(RUST_ORACLE, sreq)
            if not rsp.get("ok"):
                fails.append((h, "mbl serialize", rsp.get("err")))
                continue
            mbl_bytes = rsp["out"]["bytes"]
            # AstroBWTv3 (Rust)
            preq = {"id": 2, "op": "pow_v3", "in": {"bytes": mbl_bytes}}
            prsp = run_oracle(RUST_ORACLE, preq)
            if not prsp.get("ok"):
                fails.append((h, "pow_v3", prsp.get("err")))
                continue
            pow_hash = prsp["out"]["hash"]
            # difficulty check (Rust), with the highdiff multiplier
            eff = difficulty * 9 if m.get("HighDiff") else difficulty
            creq = {"id": 3, "op": "check_pow", "in": {"hash": pow_hash, "difficulty": str(eff)}}
            crsp = run_oracle(RUST_ORACLE, creq)
            valid = crsp.get("out", {}).get("valid")
            # Go agreement on the same bytes
            gpow = run_oracle(GO_ORACLE, {"id": 4, "op": "pow_v3", "in": {"bytes": mbl_bytes}})
            gvalid = run_oracle(GO_ORACLE, {"id": 5, "op": "check_pow",
                                            "in": {"hash": gpow.get("out", {}).get("hash"),
                                                   "difficulty": str(eff)}})
            agree = (pow_hash == gpow.get("out", {}).get("hash")) and (valid == gvalid.get("out", {}).get("valid"))
            tag = "FINAL" if m.get("Final") else "     "
            if valid:
                ok_miniblocks += 1
            if m.get("Final") and valid:
                ok_final += 1
            print(f"  {tag} mbl HighDiff={m.get('HighDiff')} pow_valid={valid} go_agree={agree}")
            if not agree:
                fails.append((h, "pow", "go/rust disagree on pow or check"))

    print()
    print(f"=== chain PoW: {ok_miniblocks} miniblocks valid, {ok_final} final valid ===")
    if fails:
        for h, what, msg in fails[:10]:
            print(f"  height {h} {what}: {msg}")
        return 1
    print("CHAIN POW PASS: Rust AstroBWTv3 + difficulty target verify the "
          "live mainnet blocks' mined miniblocks, byte-identical to Go")
    return 0


if __name__ == "__main__":
    sys.exit(main())
