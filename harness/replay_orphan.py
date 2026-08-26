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
FORK_A = 'ddda4236f4ccb89157dee0ba5b599027180202eadf7a924aee2197b22726f8a7'
d0 = rpc('DERO.DumpBalances', {'height': 0})
r0 = d0['result']
# fork A's embedded roothash
fa = rpc('DERO.GetBlock', {'blid': FORK_A})['result']
fa_json = json.loads(fa['json'])
fork_a_rh = fa_json.get('roothash','')
print('fork A roothash:', fork_a_rh[:16])
print('fork A height:', fa_json.get('height'))
print('fork A tips:', [t[:12] for t in fa_json.get('tips',[])])

# common prefix h1..h23, then fork A
reqs, iid = [], 1
for e in r0['entries']:
    reqs.append({'id':iid,'op':'grav_put','in':{'tree':'B','key':e['key'],'value':e['value']}}); iid+=1
for e in r0['meta_entries']:
    reqs.append({'id':iid,'op':'grav_put','in':{'tree':'M','key':e['key'],'value':e['value']}}); iid+=1
# h1-23 common prefix
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
# fork A block
inp = {'blob':fa['blob'],'height':str(fa_json.get('height',24)),'genesis':'false'}
reqs.append({'id':iid,'op':'chain_block_apply','in':inp})
fork_id = iid
iid += 1
p = subprocess.run([RUST], input='\n'.join(json.dumps(r) for r in reqs)+'\n', capture_output=True, text=True, timeout=1800)
ok = False
for l in p.stdout.splitlines():
    r = json.loads(l)
    if r.get('id') == fork_id:
        if 'out' not in r:
            print('fork A APPLY ERROR:', r.get('err'))
        else:
            bal = bytes.fromhex(r['out']['hash'])
            meta = bytes.fromhex(r['out']['meta_hash'])
            xor = bytes(a^b for a,b in zip(bal, meta)).hex()
            match = 'MATCH' if xor == fork_a_rh else f'MISMATCH (computed={xor[:16]})'
            print(f'fork A branch replay: {match}')
            ok = (xor == fork_a_rh)
print('ORPHAN BRANCH VERIFIED' if ok else 'ORPHAN BRANCH DIVERGED')
