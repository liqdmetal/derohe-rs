#!/usr/bin/env python3
"""Differential: Go wallet BuildTx vs Rust tx_builder — byte comparison.

The simnode's DERO.BuildTx builds a real transfer with the Go wallet
using a fixed ring. We feed the same ring + destination + amount + the
wallet's chosen ring_order + per-member encrypted balances into the
Rust builder and compare the serialized txs byte-for-byte.
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

# 1. registered ring members (bech32)
ra = rpc('DERO.GetRandomAddress')['result']['address']
ring = ra[:8]

# 2. Go builds the tx (dest = ring[1])
go = rpc('DERO.BuildTx', {'dest': ring[1], 'amount': 100, 'ring': ring})
res = go.get('result', go.get('error'))
if 'tx' not in res:
    print('GO BUILD FAILED:', json.dumps(res)[:300])
    sys.exit(1)
go_tx = res['tx']
go_ring_order = res['ring_order']
go_height = res['height']
go_blid = res['blid']
# the statement's Bytes_per_publickey (bpp) — from Go's tx serialization:
# decode the payload statement to get max_bits. bpp = max_bits/8.
# Go's wallet sets Bytes_per_publickey = max_bits/8 where max_bits was
# derived from the balances + 6, rounded to bytes. Recover it from the tx.
raw_go = bytes.fromhex(go_tx)
# find the statement's bpp: after the payload header (burn uvarint + scid 32
# + rpctype 1 + rpcpayload 145), the statement: ringsize power byte, then bpp
pos = 0
# tx header: version, src, dst, type, height, blid, asset_count
# crude: scan for the ring size byte 0x03 (ring 8 -> power 3) + bpp
# bpp candidates 2..4
go_bpp = 3
for cand in (2, 3, 4):
    marker = bytes([3, cand])
    idx = raw_go.find(marker)
    if idx > 0:
        go_bpp = cand
        break
print('GO bpp (recovered):', go_bpp)
go_max_bits = go_bpp * 8
# witness indices: find the sender (wsrc pubkey) and receiver (dest) in ring_order
words = 'sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly'
p = subprocess.run([RUST], input=json.dumps({'op': 'mnemonic_to_key', 'in': {'words': words}})+'\n',
                   capture_output=True, text=True, timeout=60)
seed = json.loads(p.stdout)['out']['seed']
p2 = subprocess.run([RUST], input=json.dumps({'op': 'pubkey_from_seed', 'in': {'seed': seed}})+'\n',
                    capture_output=True, text=True, timeout=60)
sender_pub = json.loads(p2.stdout)['out']['public']
# get each ring member's compressed key via the oracle (address -> compressed)
def addr_compressed(addr):
    p3 = subprocess.run([RUST], input=json.dumps({'op': 'bech32_raw', 'in': {'address': addr}})+'\n',
                        capture_output=True, text=True, timeout=60)
    try:
        return json.loads(p3.stdout)['out']['raw']
    except Exception:
        return None
print('GO tx len:', len(go_tx)//2, 'txid:', res['txid'][:16])
print('GO ring order:', [a[:12] for a in go_ring_order])
# use the simnode's exposed witness_index (ground truth)
wi = res.get('witness_index', [])
if len(wi) == 2:
    wi0, wi1 = wi[0], wi[1]
else:
    # fallback: re-derive by pubkey match
    wi0 = wi1 = None
    for i, addr in enumerate(go_ring_order):
        comp = addr_compressed(addr)
        if comp == sender_pub:
            wi0 = i
        if addr == ring[1]:
            wi1 = i
print('witness_index (from simnode):', wi0, wi1)

# 3. fetch each ring member's encrypted balance (at the tx's height/blid)
#    NonceBalance = uvarint nonce_height + 66-byte ElGamal.
#    The RECEIVER at wi1 uses the DESTINATION's key (Go replaces the member
#    there with the receiver's key) — inject the dest's compressed key.
ring_balances = []
roothash = None
dest_comp = None
for i, addr in enumerate(go_ring_order):
    eb = rpc('DERO.GetEncryptedBalance', {'address': addr, 'scid': SCID})
    res_eb = eb.get('result', eb.get('error'))
    if 'data' not in res_eb:
        print('NO BALANCE for', addr[:16], ':', json.dumps(res_eb)[:120])
        ring_balances.append('00' * 66)
    else:
        data = res_eb['data']
        if roothash is None and res_eb.get('treehash'):
            roothash = res_eb['treehash']
        raw = bytes.fromhex(data)
        pos = 0
        while pos < len(raw) and raw[pos] & 0x80:
            pos += 1
        pos += 1
        elgamal = raw[pos:pos+66]
        ring_balances.append(elgamal.hex())
# the receiver's key = the dest's key (inject at wi1)
if wi1 is not None:
    pc = subprocess.run([RUST], input=json.dumps({'op': 'bech32_raw', 'in': {'address': ring[1]}})+'\n',
                        capture_output=True, text=True, timeout=60)
    dest_comp = json.loads(pc.stdout)['out']['raw']
print('dest key injected at wi1:', (dest_comp or '')[:16])

# 4. Rust rebuilds
rust_in = {
    'op': 'wallet_build_tx',
    'in': {
        'words': 'sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly',
        'dest': ring[1],
        'amount': '100',
        'ring': ','.join(go_ring_order),
        'ring_balances': ','.join(ring_balances),
        'dest_key': dest_comp or '',
        'height': str(go_height),
        'blid': go_blid,
        'roothash': roothash or ('00' * 32),
        'max_bits': str(go_max_bits),
        'wi0': str(wi0),
        'wi1': str(wi1),
    },
}
p = subprocess.run([RUST], input=json.dumps(rust_in)+'\n',
                   capture_output=True, text=True, timeout=120)
print('RUST:', p.stdout[:300] or p.stderr[:300])
if p.stdout:
    try:
        ro = json.loads(p.stdout)
        if ro.get('ok'):
            rust_tx = ro['out']['tx']
            print('RUST tx len:', len(rust_tx)//2)
            print('MATCH:', go_tx == rust_tx)
            if go_tx != rust_tx:
                for i in range(0, min(len(go_tx), len(rust_tx)), 2):
                    if go_tx[i] != rust_tx[i]:
                        print('first diff at byte', i//2)
                        print('GO  :', go_tx[i:i+64])
                        print('RUST:', rust_tx[i:i+64])
                        break
        else:
            print('RUST ERR:', ro.get('err'))
    except Exception as e:
        print('parse err:', e)
