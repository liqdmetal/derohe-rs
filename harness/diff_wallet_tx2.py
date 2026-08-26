#!/usr/bin/env python3
"""Differential: Go wallet BuildTxEmap vs Rust tx_builder — byte comparison.

Uses the simnode's BuildTxEmap RPC which returns the EXACT balances the
wallet used (emap = [self, receiver, anonset...]) plus the statement ring
order + witness indices. The Rust builder is fed the ring in
[self, receiver, anonset] order and must reproduce Go's tx byte-for-byte
up to the randomized proof.
"""
import json, subprocess, urllib.request, sys

def rpc(method, params=None, port=25000):
    body = {'jsonrpc': '2.0', 'id': 0, 'method': method}
    if params:
        body['params'] = params
    req = urllib.request.Request(
        f'http://127.0.0.1:{port}/json_rpc',
        data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())

RUST = './crypto/target/release/dero-oracle.exe'
SCID = '0000000000000000000000000000000000000000000000000000000000000000'
words = 'sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly'

def call(op, inp):
    p = subprocess.run([RUST], input=json.dumps({'op': op, 'in': inp})+'\n',
                       capture_output=True, text=True, timeout=60)
    return json.loads(p.stdout).get('out', {})

# 1. Go builds the tx with the wallet + returns emap
ra = rpc('DERO.GetRandomAddress')['result']['address']
ring = ra[:8]
go = rpc('DERO.BuildTxEmap', {'dest': ring[1], 'amount': 100, 'ring': ring})
res = go.get('result', go.get('error'))
if 'tx' not in res:
    print('GO FAILED:', json.dumps(res)[:300])
    sys.exit(1)
go_tx = bytes.fromhex(res['tx'])
go_ring_order = res['ring_order']
wi0, wi1 = res['witness_index']
print('GO tx len:', len(go_tx), 'wi:', [wi0, wi1])
print('emap len:', len(res.get('emap', [])), 'ring_order len:', len(go_ring_order))

# 2. the GROUND-TRUTH emap from the wallet's own BuildTransaction call,
#    returned ATOMICALLY with the tx in the RPC response (no file race).
ring_order = res.get('ring_order', [])
gt_emap = res.get('gt_emap', [])
anonset = [ring_order[k] for k in range(len(ring_order)) if k != wi0 and k != wi1]
if len(gt_emap) >= 8:
    emap = gt_emap[:8]  # the wallet's exact [self, receiver, anonset...] order
    print('GT emap[0] (self):', emap[0][:12])
    print('GT emap[1] (recv):', emap[1][:12])
else:
    print('WARN: no gt_emap — falling back to emap')
    emap = res.get('emap', [])
print('anonset:', [a[:10] for a in anonset], 'emap len:', len(emap))
# GROUND TRUTH: the roothash is IN the tx statement at byte 533..565 —
# use that instead of any fetch. max_bits = 9 (wallet bits+6 per the dump).
roothash = go_tx[533:565].hex()
go_max_bits = 9
print('anonset len:', len(anonset), 'emap len:', len(emap))
print('roothash from tx statement:', roothash[:16], 'max_bits:', go_max_bits)

# 3. Rust rebuild: ring = [self(receiver injected), receiver, anonset], balances = emap
dest_comp = call('bech32_raw', {'address': ring[1]})['raw']
rust_in = {
    'op': 'wallet_build_tx',
    'in': {
        'words': words,
        'dest': ring[1],
        'amount': '100',
        'ring': ','.join(anonset),
        'ring_balances': ','.join(emap),
        'dest_key': dest_comp,
        'height': str(res['height']),
        'blid': res['blid'],
        'roothash': roothash,
        'max_bits': str(go_max_bits),
        'wi0': str(wi0),
        'wi1': str(wi1),
        # the sender's decrypted balance (the witness needs it) — from the
        # simnode's wallet (holds wsrc's secret)
        'balance': str(rpc('DERO.GetBalance', {'address': ring_order[wi0]})['result'].get('balance', 0)),
    },
}
p = subprocess.run([RUST], input=json.dumps(rust_in)+'\n',
                   capture_output=True, text=True, timeout=120)
out = json.loads(p.stdout)
if not out.get('ok'):
    print('RUST ERR:', out.get('err'))
    sys.exit(1)
rust_tx = bytes.fromhex(out['out']['tx'])

# 4. compare: the STATEMENT ends at byte 565 (power+bpp+fees+D+pointers+
#    C+roothash); everything after is the RANDOMIZED proof.
diffs = [i for i in range(min(len(go_tx), len(rust_tx))) if go_tx[i] != rust_tx[i]]
stmt = [i for i in diffs if i < 565]
proof = [i for i in diffs if i >= 565]
print('len:', len(go_tx), len(rust_tx))
print('STATEMENT (0-565) diffs:', len(stmt), stmt[:8])
print('PROOF diffs (randomized, OK):', len(proof))
if not stmt:
    print('*** STATEMENT BYTE-IDENTICAL — BUILDER IS CORRECT ***')
else:
    d = stmt[0]
    print(f'first stmt diff at byte {d}: GO={go_tx[d]:02x} RST={rust_tx[d]:02x}')
    print('GO  around:', go_tx[d-4:d+8].hex())
    print('RST around:', rust_tx[d-4:d+8].hex())

# 5. CROSS-CHECK against the instrumented ground truth: roothash + emap
gt = res.get('gt', {})
if gt:
    gt_rh = gt.get('roothash', '')
    gt_emap = gt.get('emap', [])
    print('GT roothash:', gt_rh[:16], '== passed?', gt_rh == roothash)
    print('GT emap[0]:', gt_emap[0][:16] if gt_emap else '?', '== passed?', gt_emap and gt_emap[0] == emap[0])
