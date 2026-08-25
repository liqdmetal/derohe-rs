import json, urllib.request, subprocess

def rpc(method, params=None):
    body = {'jsonrpc':'2.0','id':0,'method':method}
    if params: body['params']=params
    req = urllib.request.Request('http://127.0.0.1:25000/json_rpc', data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=15) as r: return json.loads(r.read())

RUST = './crypto/target/release/dero-oracle.exe'
d0 = rpc('DERO.DumpBalances', {'height': 0})
r0 = d0['result']
top = rpc('DERO.GetInfo')['result']['height']
reqs, iid = [], 1
for e in r0['entries']:
    reqs.append({'id':iid,'op':'grav_put','in':{'tree':'B','key':e['key'],'value':e['value']}}); iid+=1
for e in r0['meta_entries']:
    reqs.append({'id':iid,'op':'grav_put','in':{'tree':'M','key':e['key'],'value':e['value']}}); iid+=1
blobs = {}
for h in range(1, top+1):
    b = rpc('DERO.GetBlock', {'height': h})['result']
    bj = json.loads(b['json'])
    txblobs = []
    for th in bj.get('tx_hashes', []):
        t = rpc('DERO.GetTransaction', {'txs_hashes':[th]})['result']['txs']
        if t: txblobs.append(t[0]['blob'])
    blobs[h] = (b['blob'], bj.get('roothash',''), txblobs)
apply_ids = {}
for h in sorted(blobs):
    blob, rh, txs = blobs[h]
    inp = {'blob':blob,'height':str(h),'genesis':'false'}
    if txs: inp['txs'] = txs
    reqs.append({'id':iid,'op':'chain_block_apply','in':inp})
    apply_ids[iid] = h
    iid += 1
p = subprocess.run([RUST], input='\n'.join(json.dumps(r) for r in reqs)+'\n', capture_output=True, text=True, timeout=1800)
fails = 0
for l in p.stdout.splitlines():
    r = json.loads(l)
    if r.get('id') in apply_ids:
        h = apply_ids[r['id']]
        if 'out' not in r:
            print(f'h{h}: APPLY ERROR {r.get("err")}')
            fails += 1
            continue
        bal = bytes.fromhex(r['out']['hash'])
        meta = bytes.fromhex(r['out']['meta_hash'])
        xor = bytes(a^b for a,b in zip(bal, meta)).hex()
        chain_rh = blobs[h][1]
        if xor != chain_rh:
            fails += 1
            print(f'h{h}: computed={xor[:16]} chain={chain_rh[:16]} MISMATCH')
print(f'STATE REPLAY (winning fork chain): {fails} failures across {top} blocks')
