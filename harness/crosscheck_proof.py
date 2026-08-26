#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Cross-check: Go's proof vs Rust's verifier and vice versa."""
import json, subprocess, urllib.request

def rpc(method, params=None, port=25000):
    body = {'jsonrpc': '2.0', 'id': 0, 'method': method}
    if params:
        body['params'] = params
    req = urllib.request.Request(f'http://127.0.0.1:{port}/json_rpc',
                                 data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())

RUST = './crypto/target/release/dero-oracle.exe'
GO = './oracle/oracle.exe'

def call(binpath, op, inp):
    p = subprocess.run([binpath], input=json.dumps({'id': 1, 'op': op, 'in': inp}) + '\n',
                       capture_output=True, text=True, timeout=120)
    return json.loads(p.stdout)

# 1. Go builds a tx (with its own proof)
ra = rpc('DERO.GetRandomAddress')['result']['address']
ring = ra[:8]
go = rpc('DERO.BuildTxEmap', {'dest': ring[1], 'amount': 100, 'ring': ring})
res = go['result']
go_tx = bytes.fromhex(res['tx'])
print('GO tx len:', len(go_tx), 'txid:', res['txid'][:16])

# 2. extract the proof region (starts at 565) and the statement
stmt = go_tx[:565]
proof_hex = go_tx[565:].hex()
# Rust: verify the GO proof against the GO statement+txid
r = call(RUST, 'proof_verify', {'stmt': stmt.hex(), 'proof': proof_hex, 'txid': res['txid'], 'scid': '0'*64, 'index': 0, 'burn': 0})
print('Rust verifies Go proof:', json.dumps(r)[:150])

# 3. Rust builds the same tx (fresh proof) — verify with Rust AND Go
words = 'sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly'
p3 = subprocess.run([RUST], input=json.dumps({'op': 'bech32_raw', 'in': {'address': ring[1]}})+'\n',
                    capture_output=True, text=True, timeout=60)
dest_key = json.loads(p3.stdout)['out']['raw']
gt = res.get('gt_emap', [])
wi0, wi1 = res['witness_index']
ring_order = res['ring_order']
anonset = [ring_order[k] for k in range(8) if k != wi0 and k != wi1]
rh = go_tx[533:565].hex()
rust_in = {'op': 'wallet_build_tx', 'in': {
    'words': words, 'dest': ring[1], 'amount': '100',
    'ring': ','.join(anonset), 'ring_balances': ','.join(gt[:8]),
    'dest_key': dest_key,
    'height': str(res['height']), 'blid': res['blid'],
    'roothash': rh, 'max_bits': '9', 'wi0': str(wi0), 'wi1': str(wi1),
}}
p = subprocess.run([RUST], input=json.dumps(rust_in)+'\n', capture_output=True, text=True, timeout=120)
rust_tx = bytes.fromhex(json.loads(p.stdout)['out']['tx'])
print('RUST tx len:', len(rust_tx))
rust_stmt = rust_tx[:565]
rust_proof = rust_tx[565:].hex()
# Rust verifies its own proof
r = call(RUST, 'proof_verify', {'stmt': rust_stmt.hex(), 'proof': rust_proof, 'txid': res['txid'], 'scid': '0'*64, 'index': 0, 'burn': 0})
print('Rust verifies Rust proof:', json.dumps(r)[:150])
# Go verifies the Rust proof
r = call(GO, 'proof_verify', {'stmt': rust_stmt.hex(), 'proof': rust_proof, 'txid': res['txid'], 'scid': '0'*64, 'index': 0, 'burn': 0})
print('Go verifies Rust proof:', json.dumps(r)[:150])
