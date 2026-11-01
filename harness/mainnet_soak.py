#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Mainnet state-transition soak: run the Rust node against a live mainnet
peer over a bounded window and verify every applied block's state roothash
matches the chain's merkle_hash. This exercises the REAL sync engine
(block fetch, verify, graviton state apply) — the same path a full sync
uses.
"""
import json
import subprocess
import sys
import time
import urllib.request

RPC = "http://82.65.143.182:10102/json_rpc"
ROOT = os.environ.get("DEROHE_RS_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
NODE = ROOT + "/crypto/target/release/node.exe"
PORT = 26100
START = int(sys.argv[1]) if len(sys.argv) > 1 else 7500000
COUNT = int(sys.argv[2]) if len(sys.argv) > 2 else 30


def rpc(method, params=None, port=None):
    base = f"http://127.0.0.1:{port}/json_rpc" if port else RPC
    body = {"jsonrpc": "2.0", "id": 0, "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(base, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read())


def main():
    # launch the Rust node with the mainnet public node as peer (bounded)
    import os
    log = os.path.join(os.environ["LOCALAPPDATA"], "Temp", "rnode_soak.log")
    proc = subprocess.Popen(
        [NODE, "--peer", RPC, "--port", str(PORT), "--mainnet", "--max-sync", str(COUNT + 2)],
        stdout=open(log, "w"), stderr=subprocess.STDOUT,
    )
    try:
        # wait for the bounded sync to finish (the peer serves ~1 block/1-3s)
        time.sleep(20)
        for _ in range(120):
            try:
                info = rpc("DERO.GetInfo", port=PORT)["result"]
                break
            except Exception:
                time.sleep(3)
        h0 = info.get("height", 0)
        print(f"node synced to h{h0}")
        # now verify the LAST COUNT blocks' state roothashes against the chain
        verified = 0
        mismatches = 0
        for h in range(max(1, h0 - COUNT + 1), h0 + 1):
            blk = rpc("DERO.GetBlock", {"height": h}, port=PORT).get("result", {})
            node_rh = blk.get("merkle_hash", "")
            chain = rpc("DERO.GetBlock", {"height": h}).get("result", {})
            chain_rh = chain.get("merkle_hash", "")
            if node_rh == chain_rh and node_rh:
                verified += 1
            else:
                mismatches += 1
                print(f"h{h}: NODE {node_rh[:16]} != CHAIN {chain_rh[:16]}")
        print(f"\n{verified}/{verified+mismatches} blocks: state roothash byte-identical")
        return 0 if mismatches == 0 else 2
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
