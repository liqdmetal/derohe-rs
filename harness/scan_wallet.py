#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Wallet scan: pull blocks from the daemon and print OUR transfer history
using the Rust wallet_state classification (in/out/ring-member).

Read-only. Walks every block from `start` to the tip, fetches each tx's
expanded ring, finds our key, classifies the change, prints entries.
"""
import json
import subprocess
import sys
import urllib.request

RPC = "http://82.65.143.182:10102/json_rpc"
ROOT = os.environ.get("DEROHE_RS_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
RUST = ROOT + "/crypto/target/release/dero-oracle.exe"
WORDS = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly"
START = int(sys.argv[1]) if len(sys.argv) > 1 else 7500000


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
    # our compressed key
    r = run({"op": "mnemonic_to_key", "in": {"words": WORDS}})
    seed = r["out"]["seed"]
    r = run({"op": "pubkey_from_seed", "in": {"seed": seed}})
    pub = r["out"]["public"]
    our_key = bytes.fromhex(pub)
    print(f"scanning for {pub[:16]}...")

    tip = rpc("DERO.GetInfo")["result"]["height"]
    print(f"tip: {tip}")
    found = 0
    for h in range(START, tip + 1):
        blk = rpc("DERO.GetBlock", {"height": h}).get("result", {})
        blob = blk.get("blob", "")
        if not blob:
            continue
        # parse the block's tx_hashes from the json view
        bjson = blk.get("json", "")
        txh = []
        try:
            j = json.loads(bjson) if isinstance(bjson, str) else bjson
            txh = j.get("tx_hashes", [])
        except Exception:
            pass
        for txid in txh:
            r = rpc("DERO.GetTransaction", {"txs_hashes": [txid]})
            txs = r.get("result", {}).get("txs", [])
            if not txs or not txs[0]:
                continue
            blob2 = txs[0].get("as_hex", "")
            ring = txs[0].get("ring", []) if isinstance(txs[0], dict) else None
            if not blob2:
                continue
            # classify via the Rust oracle
            c = run({"op": "wallet_scan_tx", "in": {
                "blob": blob2, "words": WORDS, "height": str(h),
                "topoheight": str(h), "ring": json.dumps(ring) if ring else "",
            }})
            if c.get("ok") and c["out"].get("entries"):
                for e in c["out"]["entries"]:
                    kind = "IN " if e["incoming"] else ("OUT" if e["status"] == 1 else "RNG")
                    print(f"  h{h} {kind} amt={e['amount']} fees={e['fees']} txid={e['txid'][:16]}")
                    found += 1
        if h % 200 == 0:
            print(f"  ... scanned to {h} (found {found})")
    print(f"done: {found} entries for our wallet")


if __name__ == "__main__":
    main()
