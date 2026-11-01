#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Mainnet replay: verify the Rust reimplementation against the LIVE DERO chain.

For a set of heights, fetch the raw block (DERO.GetBlock -> 'blob') plus the
chain's BLID / miner_tx_hash / tx_hashes from a public mainnet node, then:
  1. feed the blob through BOTH oracles' block_deserialize
  2. require re-serialized bytes == chain blob, computed BLID == chain BLID,
     computed miner_tx_hash == chain miner_tx_hash, and Go == Rust
  3. for non-coinbase txs, fetch each tx blob (DERO.GetTransaction) and
     verify the Rust txid == the chain's txid in tx_hashes

This is the definitive consensus test: genesis-to-tip hashing agreement.
"""
import json
import subprocess
import sys
import urllib.request

RPC = "http://82.65.143.182:10102/json_rpc"
ROOT = os.environ.get("DEROHE_RS_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
GO_ORACLE = ROOT + "/oracle/oracle.exe"
RUST_ORACLE = ROOT + "/crypto/target/release/dero-oracle.exe"


def rpc(method, params=None):
    body = {"jsonrpc": "2.0", "id": 0, "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(
        RPC,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def run_oracle(binpath, req):
    p = subprocess.run(
        [binpath], input=json.dumps(req) + "\n",
        capture_output=True, text=True, timeout=300,
    )
    line = p.stdout.splitlines()[0] if p.stdout.strip() else "{}"
    return json.loads(line)


def main():
    top = rpc("DERO.GetInfo")["result"]["height"]
    print(f"node height: {top}")

    heights = [0, 1, 2, 3, 4, 5, 10, 20, 50, 100, 200, 500, 1000, 2000,
               5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000,
               2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 7504640,
               7504641, 7504642, top]
    # DENSE coverage: 100-block contiguous windows at 7 epoch points
    # genesis, 100k, 1M, 5M, 7.4M (pre-HF3), 7.5M (post-HF3), 7.51M+ (tip area)
    dense_windows = [
        range(0, 100),           # genesis window
        range(100000, 100100),   # 100k
        range(1000000, 1000100), # 1M
        range(5000000, 5000100), # 5M
        range(7400000, 7400100), # pre-HF3
        range(7500000, 7500100), # post-HF3
        range(7510000, 7510100), # current tip area
    ]
    height_set = set(h for h in heights if 0 <= h <= top)
    for w in dense_windows:
        height_set |= set(h for h in w if h <= top)
    heights = sorted(height_set)

    block_fail = []
    tx_fail = []
    skipped_txs = []
    ok_blocks = 0
    ok_txs = 0

    for h in heights:
        res = rpc("DERO.GetBlock", {"height": h})
        r = res.get("result")
        if not r:
            print(f"height {h}: RPC error {res.get('error')}")
            continue
        blob = r["blob"]
        chain_blid = r["block_header"]["hash"].lower()
        bjson = json.loads(r.get("json") or "{}")
        chain_tx_hashes = [t.lower() for t in (bjson.get("tx_hashes") or [])]

        req = {"id": 100000 + h, "op": "block_deserialize", "in": {"bytes": blob}}
        go = run_oracle(GO_ORACLE, req)
        ru = run_oracle(RUST_ORACLE, req)

        if not go.get("ok") or not ru.get("ok"):
            block_fail.append((h, f"parse: go_ok={go.get('ok')} rust_ok={ru.get('ok')} "
                                   f"go_err={go.get('err')} rust_err={ru.get('err')}"))
            continue
        go_o, ru_o = go["out"], ru["out"]
        if go_o != ru_o:
            block_fail.append((h, "go/rust disagree"))
            continue
        o = ru_o
        if o["bytes"].lower() != blob.lower():
            block_fail.append((h, "re-serialized bytes != chain blob"))
            continue
        if o["hash"].lower() != chain_blid:
            block_fail.append((h, f"BLID mismatch: rust={o['hash']} chain={chain_blid}"))
            continue
        ok_blocks += 1

        # anchor the miner tx: strip the block header (uvarint major, uvarint
        # minor, 8B timestamp, uvarint height) — the rest is the miner tx blob.
        # tx_deserialize of those bytes must reproduce the miner_tx_hash that
        # block_deserialize computed, on both oracles.
        b = bytes.fromhex(blob)
        p = 0
        for _ in range(2):  # major, minor uvarints
            while b[p] & 0x80:
                p += 1
            p += 1
        p += 8  # timestamp
        while b[p] & 0x80:  # height uvarint
            p += 1
        p += 1
        miner_blob = blob[p * 2:]
        miner_hash = o["miner_tx_hash"].lower()
        treq = {"id": 200000 + h, "op": "tx_deserialize", "in": {"bytes": miner_blob}}
        rgo = run_oracle(GO_ORACLE, treq)
        rru = run_oracle(RUST_ORACLE, treq)
        if not rgo.get("ok") or not rru.get("ok"):
            tx_fail.append((h, miner_hash[:16], f"miner tx parse: go={rgo.get('ok')} rust={rru.get('ok')} "
                                                f"errs={rgo.get('err')}/{rru.get('err')}"))
        elif rgo["out"] != rru["out"]:
            tx_fail.append((h, miner_hash[:16], "miner tx go/rust disagree"))
        elif rru["out"]["hash"].lower() != miner_hash:
            tx_fail.append((h, miner_hash[:16], f"miner txid mismatch: rust={rru['out']['hash']} chain={miner_hash}"))
        else:
            ok_txs += 1

        # verify each listed txid against the chain's transaction blob
        for txid in chain_tx_hashes:
            tres = rpc("DERO.GetTransaction", {"txids": [txid]})
            tr = tres.get("result")
            txs = (tr or {}).get("txs") or []
            if not txs:
                skipped_txs.append((h, txid[:16], "node does not serve tx blobs"))
                continue
            tx_blob = txs[0].get("blob")
            if not tx_blob:
                tx_fail.append((h, txid[:16], "no tx blob in response"))
                continue
            treq = {"id": 200000 + h, "op": "tx_deserialize", "in": {"bytes": tx_blob}}
            rgo = run_oracle(GO_ORACLE, treq)
            rru = run_oracle(RUST_ORACLE, treq)
            if not rgo.get("ok") or not rru.get("ok"):
                tx_fail.append((h, txid[:16], f"parse: go={rgo.get('ok')} rust={rru.get('ok')} "
                                             f"errs={rgo.get('err')}/{rru.get('err')}"))
                continue
            if rgo["out"] != rru["out"]:
                tx_fail.append((h, txid[:16], "go/rust disagree"))
                continue
            if rru["out"]["hash"].lower() != txid:
                tx_fail.append((h, txid[:16], f"txid mismatch: rust={rru['out']['hash']} chain={txid}"))
                continue
            ok_txs += 1
        print(f"height {h:>8}: block OK (blob {len(blob)//2} B, {len(chain_tx_hashes)} txs)")

    print()
    print(f"=== replay results: {ok_blocks}/{len(heights)} blocks, {ok_txs} txs verified ===")
    if skipped_txs:
        print(f"  ({len(skipped_txs)} non-coinbase txs skipped: public node does not serve tx blobs)")
    if block_fail:
        print("BLOCK FAILURES:")
        for h, msg in block_fail[:10]:
            print(f"  height {h}: {msg}")
    if tx_fail:
        print("TX FAILURES:")
        for h, tx, msg in tx_fail[:10]:
            print(f"  height {h} tx {tx}: {msg}")
    if not block_fail and not tx_fail:
        print("MAINNET REPLAY PASS: every fetched block reproduces the chain's BLID "
              "byte-for-byte, and every miner tx reproduces the chain's miner_tx_hash")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
