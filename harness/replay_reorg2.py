#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
import json, urllib.request, subprocess

def rpc(method, params=None):
    body = {'jsonrpc':'2.0','id':0,'method':method}
    if params: body['params']=params
    req = urllib.request.Request('http://127.0.0.1:25000/json_rpc', data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=15) as r: return json.loads(r.read())

RUST = './crypto/target/release/dero-oracle.exe'
d0 = rpc('DERO.DumpBalances', {'height': 0})
r0 = d0['result']

def apply_chain(extra_blocks):
    """Apply h1..23 then the extra blocks; return (fails, last_xor, last_rh)."""
    reqs, iid = [], 1
    for e in r0['entries']:
        reqs.append({'id':iid,'op':'grav_put','in':{'tree':'B','key':e['key'],'value':e['value']}}); iid+=1
    for e in r0['meta_entries']:
        reqs.append({'id':iid,'op':'grav_put','in':{'tree':'M','key':e['key'],'value':e['value']}}); iid+=1
    for h in range(1, 24):
        b = rpc('DERO.GetBlock', {'height': h})['result']
        bj = json.loads(b['json'])
        txblobs = []
        for th in bj.get('tx_hashes', []):
            t = rpc('DERO.GetTransaction', {'txs_hashes':[th]})['result']['txs']
            if t: txblobs.append(t[0]['blob'])
        inp = {'blob':b['blob'],'height':str(h),'genesis':'false'}
        if txblobs: inp['txs'] = txblobs
        reqs.append({'id':iid,'op':'chain_block_apply','in':inp}); iid+=1
    last_id = None
    for (blob, rh, txs, h) in extra_blocks:
        inp = {'blob':blob,'height':str(h),'genesis':'false'}
        if txs: inp['txs'] = txs
        reqs.append({'id':iid,'op':'chain_block_apply','in':inp})
        last_id = iid
        iid += 1
    p = subprocess.run([RUST], input='\n'.join(json.dumps(r) for r in reqs)+'\n', capture_output=True, text=True, timeout=1800)
    fails = 0
    last_xor = None
    for l in p.stdout.splitlines():
        r = json.loads(l)
        if r.get('id') == last_id:
            if 'out' not in r:
                print('  APPLY ERROR:', r.get('err'))
                fails += 1
                continue
            bal = bytes.fromhex(r['out']['hash'])
            meta = bytes.fromhex(r['out']['meta_hash'])
            last_xor = bytes(a^b for a,b in zip(bal, meta)).hex()
    return fails, last_xor

top = rpc('DERO.GetInfo')['result']['height']
print(f'top height: {top}')

# canonical chain: h24..27 from topo
canon = []
for h in range(24, top+1):
    b = rpc('DERO.GetBlock', {'height': h})['result']
    bj = json.loads(b['json'])
    txblobs = []
    for th in bj.get('tx_hashes', []):
        t = rpc('DERO.GetTransaction', {'txs_hashes':[th]})['result']['txs']
        if t: txblobs.append(t[0]['blob'])
    canon.append((b['blob'], bj.get('roothash',''), txblobs, h))
print('canonical h24 blid:', json.loads(rpc('DERO.GetBlock', {'height': 24})['result']['json'])['blid'][:16])

# the fork result gave blid1/blid2 — fetch both via GetForkBlock
fork_result = json.loads(open('/dev/stdin').read()) if False else None
# re-run Fork to get blid1/blid2? No — fetch from log via GetForkBlock with both known blids
blid1 = 'cf2eb1f132550997ff03c81eabd0cbadf8a7fa0fd3d620ca49274cd0b160644a'
blid2 = 'c6b10c325f2d7a86a63562ecce3876dbb57ccc17c5e8d36f3f21a604e883c25c'
fb1 = rpc('DERO.GetForkBlock', {'blid': blid1})['result']
fb2 = rpc('DERO.GetForkBlock', {'blid': blid2})['result']
print('fork A blob len:', len(fb1['blob'])//2, 'roothash:', fb1['roothash'][:16])
print('fork B blob len:', len(fb2['blob'])//2, 'roothash:', fb2['roothash'][:16])

# which fork block is canonical at h24?
b24 = rpc('DERO.GetBlock', {'height': 24})['result']
b24_blid = json.loads(b24['json'])['blid']
print('canonical h24 == blid2:', b24_blid == blid2, '== blid1:', b24_blid == blid1)

# 1) replay canonical: h1-23 + canon h24-27
f1, x1 = apply_chain(canon)
print(f'CANONICAL branch replay: fails={f1} final={x1[:16]} expected={canon[-1][1][:16]}')

# 2) replay the ORPHAN fork block: h1-23 + fork A (blid1) — verify its roothash
orphan = [(fb1['blob'], fb1['roothash'], fb1['txs'], 24)]
f2, x2 = apply_chain(orphan)
print(f'ORPHAN fork-A branch replay: fails={f2} final={x2[:16]} expected={fb1["roothash"][:16]}')
