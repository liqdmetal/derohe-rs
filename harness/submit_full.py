#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Capture the FULL mainnet rejection message (not truncated)."""
import json, subprocess, urllib.request

RPC = 'http://82.65.143.182:10102/json_rpc'
WORDS = 'sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly'
RUST = './crypto/target/release/dero-oracle.exe'


def rpc(method, params=None):
    body = {'jsonrpc': '2.0', 'id': 0, 'method': method}
    if params is not None:
        body['params'] = params
    req = urllib.request.Request(RPC, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def run(binpath, req):
    p = subprocess.run([binpath], input=json.dumps(req) + '\n',
                       capture_output=True, text=True, timeout=300)
    return json.loads(p.stdout.splitlines()[0])


def main():
    info = rpc('DERO.GetInfo')['result']
    height = info['height']
    r = run(RUST, {'op': 'mnemonic_to_key', 'in': {'words': WORDS}})
    seed = r['out']['seed']
    r = run(RUST, {'op': 'pubkey_from_seed', 'in': {'seed': seed}})
    pub = r['out']['public']
    r = run(RUST, {'op': 'bech32_string', 'in': {'raw': pub}})
    self_addr = r['out']['addr']
    addrs = rpc('DERO.GetRandomAddress')['result']['address']
    stable_height = max(0, height - 50)
    ring_members = [self_addr] + [a for a in addrs if a != self_addr][:3]
    balances = []
    roothash = None
    blid = None
    for addr in ring_members:
        eb = rpc('DERO.GetEncryptedBalance',
                 {'address': addr, 'scid': '0' * 64, 'topoheight': stable_height})['result']
        raw = bytes.fromhex(eb.get('data', '')) if eb.get('data') else b''
        pos = 0
        while pos < len(raw) and raw[pos] & 0x80:
            pos += 1
        pos += 1
        balances.append(raw[pos:pos + 66].hex() if len(raw) >= pos + 66 else '')
        if roothash is None:
            roothash = eb.get('treehash', '')
            blid = eb.get('blockhash', '')
    dec = run(RUST, {'op': 'balance_decode',
                     'in': {'balance': balances[0], 'words': WORDS}})
    self_balance = dec['out']['balance']
    dest = ring_members[1]
    r = run(RUST, {'op': 'bech32_raw', 'in': {'address': dest}})
    dest_key = r['out']['raw']
    req = {'op': 'wallet_build_tx', 'in': {
        'words': WORDS, 'dest': dest, 'amount': '100',
        'ring': ','.join(ring_members[2:]),
        'ring_balances': ','.join(balances),
        'balance': str(self_balance), 'dest_key': dest_key,
        'height': str(stable_height), 'blid': blid,
        'roothash': roothash, 'max_bits': '16', 'wi0': '0', 'wi1': '1'}}
    tx_hex = run(RUST, req)['out']['tx']
    # raw HTTP to get the FULL body (urllib may truncate? no — it's the node)
    body = json.dumps({'jsonrpc': '2.0', 'id': 0, 'method': 'DERO.SendRawTransaction',
                       'params': {'tx_as_hex': tx_hex}}).encode()
    r = urllib.request.urlopen(urllib.request.Request(
        RPC, data=body, headers={'Content-Type': 'application/json'}), timeout=60)
    raw_resp = r.read().decode()
    print('FULL RESPONSE:')
    print(raw_resp)
    print('len:', len(raw_resp))


if __name__ == '__main__':
    main()
