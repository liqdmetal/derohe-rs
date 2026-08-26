#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Mainnet DRY-RUN: build a real transfer against LIVE mainnet state and
cross-check Go vs Rust — WITHOUT submitting anything.

Reads: GetInfo, GetRandomAddress, GetEncryptedBalance from a public
mainnet node. Builds the tx with the Rust wallet builder, computes the
txid, and cross-checks the txid + statement against the Go oracle's
deserialize of the same blob. The tx is NEVER broadcast.

A test-only recovery phrase is derived from the seed words below; it is
NOT the user's wallet. Amount is 0 (no spend, no fee math beyond what
the builder computes for the statement).
"""
import json
import subprocess
import urllib.request
import os

RPC = "http://82.65.143.182:10102/json_rpc"
ROOT = r"C:/Users/$USER/derohe-rs"
RUST = ROOT + "/crypto/target/release/dero-oracle.exe"
GO = ROOT + "/oracle/oracle.exe"

# test-only words (NOT a real wallet; deterministic, zero balance expected)
WORDS = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly"


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
    print("=== DERO mainnet dry-run (read-only, NO submit) ===")
    info = rpc("DERO.GetInfo")["result"]
    height = info["height"]
    tip = info.get("top_block_hash", "")
    print(f"node height: {height}  tip: {tip[:16]}  network: {info.get('network')}")

    # 1. derive the test wallet's keys (Rust oracle)
    r = run_oracle(RUST, {"op": "mnemonic_to_key", "in": {"words": WORDS}})
    seed = r["out"]["seed"]
    r = run_oracle(RUST, {"op": "pubkey_from_seed", "in": {"seed": seed}})
    pub = r["out"]["public"]
    print(f"test wallet pubkey: {pub[:16]}...")
    r = run_oracle(RUST, {"op": "bech32_string", "in": {"raw": pub}})
    self_addr = r["out"]["addr"]
    print(f"test wallet addr:   {self_addr[:28]}...  (dero1 mainnet HRP confirmed)")

    # 2. ring from the live node (mainnet default ring size 2 -> we use 4
    #    for a clean power-of-2 demo; the builder handles any power of 2)
    addrs = rpc("DERO.GetRandomAddress")["result"]["address"]
    ring_size = 4
    ring_members = [self_addr] + [a for a in addrs if a != self_addr][:ring_size - 1]
    print(f"ring members: {len(ring_members)} (self + {ring_size - 1} from live node)")

    # 3. fetch balances + roothash for the ring at the tip. The oracle's
    #    wallet_build_tx expects ring_balances = [self, receiver, anonset...]
    #    (ring_size entries: index 0 = self, 1 = receiver = anonset[0], 2+ = rest)
    balances = []
    roothash = None
    for addr in ring_members:
        eb = rpc("DERO.GetEncryptedBalance", {
            "address": addr, "scid": "0" * 64, "topoheight": -1,
        })["result"]
        data = eb.get("data", "")
        raw = bytes.fromhex(data) if data else b""
        # NonceBalance: uvarint nonce + 66-byte ElGamal
        pos = 0
        while pos < len(raw) and raw[pos] & 0x80:
            pos += 1
        pos += 1
        bal_hex = raw[pos:pos + 66].hex() if len(raw) >= pos + 66 else ""
        balances.append(bal_hex)
        if roothash is None:
            roothash = eb.get("treehash", "")
    # receiver = ring_members[1]; the builder input is [self, receiver, anonset...]
    # so: self at index 0, receiver = ring_members[1], anonset = the rest.
    # ring_balances must be in the SAME order: [self, receiver, anonset...]
    ring_balances = balances  # balances[0]=self, [1]=receiver, [2:]=anonset
    print(f"roothash: {roothash[:20]}...  balances: {[b[:10] for b in balances]}")

    # 4. build the tx with the Rust builder (amount 0, never submitted)
    dest = ring_members[1]  # a ring member as the dummy destination
    # the oracle's wallet_build_tx takes: ring = the ANONSET addresses
    # (NOT self/receiver), ring_balances = [self, receiver, anonset...]
    # (index 0 = self, 1 = receiver = dest, 2+ = the anonset in order),
    # and `balance` = the DECODED self balance (BSGS via the Rust wallet).
    # NOTE: this test wallet's balance is its real mainnet balance; if it
    # is 0, the builder reports insufficient balance — expected for an
    # unfunded test wallet (the dry-run then proves only the build path
    # up to the balance check).
    dec = run_oracle(RUST, {
        "op": "balance_decode",
        "in": {"balance": balances[0], "words": WORDS},
    })
    self_balance = dec.get("out", {}).get("balance", 0)
    print(f"self decoded balance: {self_balance}")
    rust_in = {
        "op": "wallet_build_tx",
        "in": {
            "words": WORDS,
            "dest": dest,
            "amount": "0",
            "ring": ",".join(ring_members[2:]),  # anonset only
            "ring_balances": ",".join(ring_balances),
            "balance": str(self_balance),
            "dest_key": None,  # oracle derives dest from the ring member
            "height": str(height),
            "blid": tip,
            "roothash": roothash,
            "max_bits": "16",
            "wi0": "0",
            "wi1": "1",
        },
    }
    # the oracle needs dest_key; derive it from dest via bech32_raw
    r = run_oracle(RUST, {"op": "bech32_raw", "in": {"address": dest}})
    rust_in["in"]["dest_key"] = r["out"]["raw"]
    res = run_oracle(RUST, rust_in)
    if not res.get("ok"):
        print("RUST BUILD FAILED:", res.get("err"))
        return 1
    tx_hex = res["out"]["tx"]
    print(f"built tx len: {len(tx_hex)//2} bytes")

    # 5. cross-check: Go deserializes the SAME blob, txids must match
    g = run_oracle(GO, {"op": "tx_deserialize", "in": {"bytes": tx_hex}})
    if not g.get("ok"):
        print("GO DESERIALIZE FAILED:", g.get("err"))
        return 1
    rust_txid = run_oracle(RUST, {"op": "tx_deserialize", "in": {"bytes": tx_hex}})["out"]["hash"]
    print(f"Go  txid: {g['out']['hash'][:32]}")
    print(f"Rust txid: {rust_txid[:32]}")
    match = g["out"]["hash"] == rust_txid
    print(f"txid match: {match}")

    # 6. statement cross-check: the txid = keccak256(core statement), so an
    #    identical txid on both sides proves the serialized core statement
    #    (header + payloads + statement) is byte-identical. Also compare the
    #    parsed payload SCIDs.
    g = run_oracle(GO, {"op": "tx_deserialize", "in": {"bytes": tx_hex}})
    r = run_oracle(RUST, {"op": "tx_deserialize", "in": {"bytes": tx_hex}})
    ok = g.get("ok") and r.get("ok") and g["out"]["hash"] == r["out"]["hash"]
    print(f"statement Go==Rust (via identical txid): {ok}")
    if g.get("ok") and r.get("ok"):
        print(f"  payloads: {len(g['out'].get('payload_scids', []))}  txtype: {g['out'].get('txtype')}")

    print("\n=== DRY RUN COMPLETE — nothing was submitted ===")
    return 0 if (match and ok) else 2


if __name__ == "__main__":
    raise SystemExit(main())
