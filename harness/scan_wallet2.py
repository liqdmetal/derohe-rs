#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Full wallet scan against the Rust node (blob + ring serving)."""
import json
import subprocess
import sys
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 26000
RPC = f"http://127.0.0.1:{PORT}/json_rpc"
RUST = r"C:/Users/$USER/derohe-rs/crypto/target/release/dero-oracle.exe"
WORDS = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly"
START = int(sys.argv[2]) if len(sys.argv) > 2 else 21


def rpc(method, params=None):
    body = {"jsonrpc": "2.0", "id": 0, "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(RPC, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def run(req):
    p = subprocess.run([RUST], input=json.dumps(req) + "\n",
                       capture_output=True, text=True, timeout=300)
    line = p.stdout.splitlines()[0] if p.stdout.strip() else "{}"
    return json.loads(line)


def main():
    tip = rpc("DERO.GetInfo")["result"]["height"]
    print(f"scanning {START}..{tip}")
    found = 0
    for h in range(START, tip + 1):
        blk = rpc("DERO.GetBlock", {"height": h}).get("result", {})
        bjson = blk.get("json", "")
        try:
            txh = json.loads(bjson).get("tx_hashes", []) if isinstance(bjson, str) else bjson.get("tx_hashes", [])
        except Exception:
            txh = []
        for txid in txh:
            r = rpc("DERO.GetTransaction", {"txs_hashes": [txid]})
            txs = r.get("result", {}).get("txs", [])
            if not txs or not txs[0]:
                continue
            t = txs[0]
            blob = t.get("blob", "")
            if not blob:
                continue
            ring = json.dumps(t.get("ring", []))
            c = run({"op": "wallet_scan_tx", "in": {
                "blob": blob, "ring": ring, "words": WORDS,
                "height": str(h), "topoheight": str(h)}})
            if c.get("ok") and c["out"].get("entries"):
                for e in c["out"]["entries"]:
                    kind = "IN " if e["incoming"] else ("OUT" if e["status"] == 1 else "RNG")
                    print(f"  h{h} {kind} amt={e['amount']} fees={e['fees']} prev={e['prev']}->{e['changed']} txid={e['txid'][:14]}")
                    found += 1
        if h % 100 == 0:
            print(f"  ... scanned to {h} (found {found})")
    print(f"done: {found} entries")


if __name__ == "__main__":
    main()
