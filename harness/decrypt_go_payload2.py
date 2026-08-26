#!/usr/bin/env python3
"""Clean decrypt of Go's RPCPayload using the verified r."""
import json, subprocess, urllib.request

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

def call(op, inp):
    p = subprocess.run([RUST], input=json.dumps({'op': op, 'in': inp})+'\n',
                       capture_output=True, text=True, timeout=60)
    return json.loads(p.stdout).get('out', {})

words = 'sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly'

# 1. build Go tx
ra = rpc('DERO.GetRandomAddress')['result']['address']
ring = ra[:8]
go = rpc('DERO.BuildTx', {'dest': ring[1], 'amount': 100, 'ring': ring})
res = go['result']
go_tx = bytes.fromhex(res['tx'])
wi = res['witness_index']
rh = rpc('DERO.GetEncryptedBalance', {'address': ring[0], 'scid': '0'*64})['result']['treehash']
seed = call('mnemonic_to_key', {'words': words})['seed']

# 2. r from ring_order pubkeys
pubs = []
for addr in res['ring_order']:
    comp = call('bech32_raw', {'address': addr})['raw']
    pubs.append(comp)
r = call('calc_r_debug', {'roothash': rh, 'pubkeys': ','.join(pubs), 'secret': seed})['r']
print('wi:', wi)
print('r:', r[:24])

# 3. find D = G*r in the tx (confirms r + gives the statement offset)
computed_d = call('point_mul_debug', {'scalar': r})['point']
d_idx = go_tx.find(bytes.fromhex(computed_d))
print('computed D:', computed_d[:20])
print('D found in tx at byte:', d_idx)
if d_idx < 0:
    print('D NOT FOUND — r wrong or encoding mismatch')
    raise SystemExit(1)

# 4. the statement structure: ... D(33) pointers(ring*bpp) C(ring*33) roothash ...
# From the statement start we can find the payload: payload is 145 bytes before
# the statement. statement starts at: power byte. scan backward for it.
# The payload region: after rpctype. Find rpctype by scanning for the pattern
# [burn varint][scid 32 zeros][rpctype][payload 145][statement]
zero = bytes(32)
idx = go_tx.find(zero, 38)
rpctype = idx + 32
payload = go_tx[rpctype+1:rpctype+1+145]
print('payload len:', len(payload))

# 5. try decrypting with the dest key
dest_comp = call('bech32_raw', {'address': ring[1]})['raw']
for label, recv in [('dest', dest_comp),
                    ('ring[wi1]', pubs[wi[1]]),
                    ('ring[wi0]', pubs[wi[0]])]:
    sk = call('shared_key_debug', {'r': r, 'receiver': recv})
    ks = bytes.fromhex(call('xchacha_keystream', {'key': sk['enc_key']})['keystream'])
    plain = bytes(a ^ b for a, b in zip(payload, ks))
    nz = sum(1 for b in plain if b != 0)
    print(f'--- {label}: nonzero={nz} plain[0:4]={plain[:4].hex()}')
    if nz <= 10:
        print('  *** CLEAN PLAINTEXT:', plain[:16].hex())
        print('  plaintext[0] =', plain[0], '(wi0 should be', wi[0], ')')
