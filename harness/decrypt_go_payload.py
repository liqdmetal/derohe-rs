#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Decrypt Go's RPCPayload with the recovered key to see the exact plaintext."""
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
    r = json.loads(p.stdout)
    return r.get('out', {})

# 1. Go builds the tx
ra = rpc('DERO.GetRandomAddress')['result']['address']
ring = ra[:8]
go = rpc('DERO.BuildTx', {'dest': ring[1], 'amount': 100, 'ring': ring})
res = go['result']
go_tx = bytes.fromhex(res['tx'])
wi = res['witness_index']
roothash = rpc('DERO.GetEncryptedBalance', {'address': ring[0], 'scid': '0'*64})['result']['treehash']
words = 'sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly'

# 2. r from the ring_order pubkeys (sender's key at wi0)
seed = call('mnemonic_to_key', {'words': words})['seed']
sender_pub = call('pubkey_from_seed', {'seed': seed})['public']
pubs = []
for addr in res['ring_order']:
    comp = call('bech32_raw', {'address': addr})['raw']
    # inject sender's derived key at wi0 (in case the bech32 differs)
    pubs.append(sender_pub if comp == sender_pub else comp)
r = call('calc_r_debug', {'roothash': roothash, 'pubkeys': ','.join(pubs), 'secret': seed})['r']
print('wi:', wi)
print('r:', r[:24])

# 3. the receiver key Go used: the DEST key (Go encrypts to the receiver = dest)
dest_comp = call('bech32_raw', {'address': ring[1]})['raw']
print('dest key:', dest_comp[:24])

# 3.5 VERIFY r against the tx's D point (D = G*r). Extract D from the tx.
# statement: scid at 38, rpctype at 70, payload 71..215, then statement:
# power(1) bpp(1) fees(uvarint) D(33) ...
zero = bytes(32)
idx = go_tx.find(zero, 38)
st = idx + 33 + 145  # after payload
pos = st + 2  # skip power + bpp
while go_tx[pos] & 0x80:
    pos += 1
pos += 1  # fees
d_point = go_tx[pos:pos+33]
computed_d = call('point_mul_debug', {'scalar': r})['point']
print('D from tx:', d_point[:20].hex())
print('D = G*r  :', computed_d[:20])
print('D matches:', d_point.hex() == computed_d)

# 4. compute enc_key + keystream for the dest key
sk = call('shared_key_debug', {'r': r, 'receiver': dest_comp})
print('shared_point:', sk['shared_point'][:24])
print('enc_key:', sk['enc_key'][:24])
ks = bytes.fromhex(call('xchacha_keystream', {'key': sk['enc_key']})['keystream'])

# 5. parse Go's payload: find scid, rpctype, payload
zero = bytes(32)
idx = go_tx.find(zero, 38)
rpctype = idx + 32
payload = go_tx[rpctype+1:rpctype+1+145]
print('scid at', idx, 'rpctype at', rpctype, 'rpctype byte:', go_tx[rpctype])
print('payload len:', len(payload))

# 6. decrypt
plain = bytes(a ^ b for a, b in zip(payload, ks))
print('decrypted plaintext[0:8]:', plain[:8].hex())
print('plaintext[0]:', plain[0], '(expected wi0 =', wi[0], ')')
print('plaintext[1:8]:', plain[1:8].hex())
print('plaintext[-4:]:', plain[-4:].hex())
print('nonzero count in plaintext:', sum(1 for b in plain if b != 0))

# 7. also try the ring_order[wi1] member's key (in case Go used that)
ring_wi1_comp = call('bech32_raw', {'address': res['ring_order'][wi[1]]})['raw']
print('ring_order[wi1] key:', ring_wi1_comp[:24], '== dest?', ring_wi1_comp == dest_comp)
if ring_wi1_comp != dest_comp:
    sk2 = call('shared_key_debug', {'r': r, 'receiver': ring_wi1_comp})
    ks2 = bytes.fromhex(call('xchacha_keystream', {'key': sk2['enc_key']})['keystream'])
    plain2 = bytes(a ^ b for a, b in zip(payload, ks2))
    print('with ring[wi1] key, plaintext[0:8]:', plain2[:8].hex(), 'nonzero:', sum(1 for b in plain2 if b != 0))
