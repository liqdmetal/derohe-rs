#!/usr/bin/env python3
"""SC install/call differential test.

Builds a full SC_INSTALL tx (real proof + canonical-CBOR SCDATA with the SC
code), serializes it on both sides (byte-identical), then runs
chain_sc_install (process_transaction_sc) on both — the SC data tree root +
balance tree root + gas must be byte-identical.
"""
import json, subprocess, random, sys

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

def run(binp, reqs):
    p = subprocess.run([binp], input="\n".join(json.dumps(r) for r in reqs) + "\n",
                       capture_output=True, text=True, timeout=900)
    if p.returncode != 0:
        return None, f"exit {p.returncode}: {p.stderr[:800]}"
    return [json.loads(l) for l in p.stdout.splitlines()], None

def main():
    p1, p2 = gen_addr(1), gen_addr(2)

    contracts = [
        ("Function Initialize() Uint64\n10 RETURN 0\nEnd Function", "0"),
        # a contract with a proper DIM + LET (exercises store)
        ("Function Initialize() Uint64\n10 DIM k As Uint64\n20 LET k = 7\n30 RETURN 0\nEnd Function", "0"),
        # private SC (InitializePrivate entrypoint)
        ("Function InitializePrivate() Uint64\n10 RETURN 0\nEnd Function", "0"),
        # no-SIGNER contract — exercises the K0 Fix B2 NoSigner bit post-fork
        ("Function Init() Uint64\n10 STORE(\"owner\", \"alice\")\n20 RETURN 0\nEnd Function", "0"),
        # SIGNER-using contract — must NOT get the NoSigner bit post-fork
        ("Function F() Uint64\n10 dim x as String\n20 LET x = SIGNER()\n30 RETURN 0\nEnd Function", "0"),
    ]

    fails = 0
    for ci, (code, _) in enumerate(contracts):
        scdata = [{"name": "SC_ACTION", "datatype": "U", "value": "0"},
                  {"name": "SC_CODE", "datatype": "S", "value": code}]
        stmt = {
            "publickeylist": [p1, p2], "c": [p1, p2], "d": p1,
            "roothash": ("%02x" % ci) * 32, "fees": "100",
            "secretkey": "22" * 32, "r": "33" * 32,
            "transfer": "1000", "balance": "5000", "index": [0, 1],
        }
        reqs = []
        reqs.append({"id": 1, "op": "proof_generate", "in": {
            "publickeylist": [p1, p2], "c": [p1, p2], "d": p1,
            "roothash": stmt["roothash"], "fees": "100",
            "secretkey": "22" * 32, "r": "33" * 32,
            "transfer": "1000", "balance": "5000", "index": [0, 1],
            "scid": "00" * 32, "scid_index": "0", "txid": ("%02x" % ci) * 32,
            "burn": "0", "u": p1, "rand": "55" * 32}})

        go_out, err = run(GO, reqs)
        if err:
            print(f"[contract {ci}] GO proof failed: {err}"); fails += 1; continue
        proof = go_out[0]["out"]["proof"]

        # tx_serialize with scdata (both sides serialize the same JSON)
        txin = {
            "version": "1", "source_network": "0", "dest_network": "0",
            "txtype": "5", "value": "0", "height": "1", "blid": "66" * 32,
            "scdata": scdata,
            "payloads": [{"scid": "00" * 32, "burn": "0", "rpctype": "0",
                          "rpcpayload": "ab" * 145, "statement": stmt,
                          "proof": proof}],
        }
        reqs2 = [{"id": 2, "op": "tx_serialize", "in": txin}]
        go2, err = run(GO, reqs2)
        if err:
            print(f"[contract {ci}] GO serialize failed: {err}"); fails += 1; continue
        rust2, err = run(RUST, reqs2)
        if err:
            print(f"[contract {ci}] RUST serialize failed: {err}"); fails += 1; continue
        blob_go = go2[0]["out"]["bytes"]
        blob_rust = rust2[0]["out"]["bytes"]
        if blob_go != blob_rust:
            print(f"[contract {ci}] TX BLOB MISMATCH go={blob_go[:60]} rust={blob_rust[:60]}")
            fails += 1; continue

        # chain_sc_install on both (fresh state, same blob)
        # register the ring keys on the shared "B" tree so the pointer
        # lookups resolve (grav_register puts key=address, so blake2s(address)
        # [:3] = the statement pointers; GetKeyValueFromHash walks those bits)
        # Run at BOTH pre-fork (no k0_floor -> NoSigner never set) and
        # post-fork (k0_floor=7600000 -> no-SIGNER contracts get the 0x80 bit,
        # SIGNER contracts don't) so the meta_root (with the B2 bit) is
        # compared byte-for-byte against Go.
        for fork in (False, True):
            floor = {"k0_floor": "7600000"} if fork else {}
            reqs3 = [
                {"id": 30, "op": "grav_register", "in": {"tree": "B", "address": p1}},
                {"id": 31, "op": "grav_register", "in": {"tree": "B", "address": p2}},
                {"id": 3, "op": "chain_sc_install",
                 "in": {"blob": blob_go, "height": "100" if not fork else "8000000",
                        "signer": p1, **floor}},
            ]
            go3, err = run(GO, reqs3)
            if err:
                print(f"[contract {ci} {'post' if fork else 'pre'}] GO install failed: {err}"); fails += 1; continue
            rust3, err = run(RUST, reqs3)
            if err:
                print(f"[contract {ci} {'post' if fork else 'pre'}] RUST install failed: {err}"); fails += 1; continue
            g, r = go3[0]["out"], rust3[0]["out"]
            if g != r:
                print(f"[contract {ci} {'post' if fork else 'pre'}] INSTALL MISMATCH:")
                print(f"  go:   {json.dumps(g)}")
                print(f"  rust: {json.dumps(r)}")
                fails += 1
            else:
                # Go oracle read-back quirk: the Go side may report an empty
                # data_root/meta_root (it hashes a snapshot-view tree that
                # doesn't see the writes; the real chain commits via the block
                # loop). The RUST side reflects the actual tree. Compare
                # meaningfully: if Go's roots are empty, skip root comparison
                # but still compare gas; if both are populated, require
                # equality.
                if g.get("data_root") and r.get("data_root"):
                    if g["data_root"] != r["data_root"]:
                        print(f"[contract {ci} {'post' if fork else 'pre'}] DATA ROOT MISMATCH")
                        fails += 1
                if g.get("meta_root") and r.get("meta_root") and g["meta_root"] != r["meta_root"]:
                    print(f"[contract {ci} {'post' if fork else 'pre'}] META ROOT MISMATCH go={g['meta_root'][:16]} rust={r['meta_root'][:16]}")
                    fails += 1
                if g.get("gas") != r.get("gas"):
                    print(f"[contract {ci} {'post' if fork else 'pre'}] GAS MISMATCH go={g.get('gas')} rust={r.get('gas')}")
                    fails += 1
                print(f"[contract {ci} {'post' if fork else 'pre'}] OK: go_root={g.get('data_root','(empty)')[:16]} rust_root={r.get('data_root','')[:16]} "
                      f"rust_meta={r.get('meta_root','')[:16]} gas={r.get('gas')}")

    if fails:
        print(f"FAIL: {fails} mismatches"); return 1
    print("PASS: all SC installs byte-identical (blob + data/balance roots + gas)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
