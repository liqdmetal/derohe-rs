#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""MAINNET SUBMIT: build a real transfer against live mainnet state and
broadcast it via the node's DERO.SendRawTransaction.

The tx references the CURRENT tip (blid + roothash), so build and
broadcast happen back-to-back to avoid the reference going stale.

Amount is 100 atomic units (0.000001 DERO) — dust, to minimize risk.
The source is the deterministic test wallet (wsrc words) which has a
real mainnet balance (~2.4 DERO at last check).
"""
import json
import subprocess
import urllib.request
import time

RPC = "http://82.65.143.182:10102/json_rpc"
ROOT = r"C:/Users/$USER/derohe-rs"
RUST = ROOT + "/crypto/target/release/dero-oracle.exe"
GO = ROOT + "/oracle/oracle.exe"

WORDS = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly"
AMOUNT = 100  # 100 atomic = 0.000001 DERO


def rpc(method, params=None):
    body = {"jsonrpc": "2.0", "id": 0, "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(
        RPC, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def run_oracle(binpath, req):
    p = subprocess.run(
        [binpath], input=json.dumps(req) + "\n",
        capture_output=True, text=True, timeout=300,
    )
    line = p.stdout.splitlines()[0] if p.stdout.strip() else "{}"
    return json.loads(line)


def main():
    print("=== DERO mainnet submit (real tx, dust amount) ===")
    info = rpc("DERO.GetInfo")["result"]
    height = info["height"]
    tip = info.get("top_block_hash", "")
    print(f"node height: {height}  tip: {tip[:16]}")

    r = run_oracle(RUST, {"op": "mnemonic_to_key", "in": {"words": WORDS}})
    seed = r["out"]["seed"]
    r = run_oracle(RUST, {"op": "pubkey_from_seed", "in": {"seed": seed}})
    pub = r["out"]["public"]
    r = run_oracle(RUST, {"op": "bech32_string", "in": {"raw": pub}})
    self_addr = r["out"]["addr"]
    print(f"source wallet: {self_addr[:30]}...")

    addrs = rpc("DERO.GetRandomAddress")["result"]["address"]
    # reference a state INSIDE the tx validity window: the real wallet uses
    # topoheight = daemon - 3. TX_VALIDITY_HEIGHT = 11 blocks, so -50 was
    # too old (the tx expired in the mempool before a miner included it).
    stable_height = max(0, height - 3)
    print(f"referencing stable state at height {stable_height}")
    # pick ring members that RESOLVE at the referenced state (registered
    # before it) — freshly-registered accounts aren't in the state tree
    candidates = [a for a in addrs if a != self_addr]
    ring_members = [self_addr]
    for a in candidates:
        eb = rpc("DERO.GetEncryptedBalance",
                 {"address": a, "scid": "0" * 64, "topoheight": stable_height})["result"]
        if eb.get("status") == "OK" and eb.get("data"):
            ring_members.append(a)
        if len(ring_members) >= 4:
            break
    if len(ring_members) < 4:
        print("not enough ring members resolve at the stable state")
        return 2
    print(f"ring: {len(ring_members)} members (all resolve at {stable_height})")
    balances = []
    roothash = None
    blid = None
    for addr in ring_members:
        eb = rpc("DERO.GetEncryptedBalance",
                 {"address": addr, "scid": "0" * 64, "topoheight": stable_height})["result"]
        raw = bytes.fromhex(eb.get("data", "")) if eb.get("data") else b""
        pos = 0
        while pos < len(raw) and raw[pos] & 0x80:
            pos += 1
        pos += 1
        balances.append(raw[pos:pos + 66].hex() if len(raw) >= pos + 66 else "")
        # roothash + blid from the FIRST fetch — one consistent state
        if roothash is None:
            roothash = eb.get("treehash", "")
            blid = eb.get("blockhash", tip)
            print(f"state: treehash {roothash[:16]} blid {blid[:16]}")

    dec = run_oracle(RUST, {"op": "balance_decode",
                            "in": {"balance": balances[0], "words": WORDS}})
    self_balance = dec["out"]["balance"]
    print(f"source balance: {self_balance} atomic ({self_balance/1e6:.6f} DERO)")
    if self_balance < AMOUNT + 200:
        print("INSUFFICIENT BALANCE for the dust amount + fee")
        return 2

    dest = ring_members[1]
    r = run_oracle(RUST, {"op": "bech32_raw", "in": {"address": dest}})
    dest_key = r["out"]["raw"]
    req = {"op": "wallet_build_tx", "in": {
        "words": WORDS, "dest": dest, "amount": str(AMOUNT),
        "ring": ",".join(ring_members[2:]),
        "ring_balances": ",".join(balances),
        "balance": str(self_balance), "dest_key": dest_key,
        "height": str(stable_height), "blid": blid,
        "roothash": roothash, "max_bits": "24", "wi0": "0", "wi1": "1"}}
    res = run_oracle(RUST, req)
    if not res.get("ok"):
        print("BUILD FAILED:", res.get("err"))
        return 1
    tx_hex = res["out"]["tx"]
    print(f"built tx: {len(tx_hex)//2} bytes, amount {AMOUNT}, dest {dest[:22]}...")

    # verify our own proof self-checks before broadcasting
    selfcheck = run_oracle(RUST, {"op": "proof_verify_tx", "in": {"blob": tx_hex}})
    print(f"proof self-check: {selfcheck.get('out', {}).get('ok', selfcheck)}")

    # broadcast IMMEDIATELY (the tx references the just-fetched tip)
    print("broadcasting...")
    resp = rpc("DERO.SendRawTransaction", {"tx_as_hex": tx_hex})
    print("SendRawTransaction:", json.dumps(resp)[:300])

    txid = run_oracle(RUST, {"op": "tx_deserialize", "in": {"bytes": tx_hex}})["out"]["hash"]
    print(f"txid: {txid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
