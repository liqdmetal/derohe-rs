import json, urllib.request, subprocess

def rpc(method, params=None):
    body = {'jsonrpc':'2.0','id':0,'method':method}
    if params: body['params']=params
    req = urllib.request.Request('http://127.0.0.1:25000/json_rpc', data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=15) as r: return json.loads(r.read())

RUST = './crypto/target/release/dero-oracle.exe'
scid = 'b422e6e70ee7de6b05aeb0598a17071996682ca895edf9348ccc355cbbfd3f82'
d34 = rpc('DERO.DumpBalances', {'height': 34})['result']
for e in d34['meta_entries']:
    if e['key'].startswith('b422e6e7'):
        print('CHAIN meta value:', e['value'])
d0 = rpc('DERO.DumpBalances', {'height': 0})
r0 = d0['result']
reqs, iid = [], 1
for e in r0['entries']:
    reqs.append({'id':iid,'op':'grav_put','in':{'tree':'B','key':e['key'],'value':e['value']}}); iid+=1
for e in r0['meta_entries']:
    reqs.append({'id':iid,'op':'grav_put','in':{'tree':'M','key':e['key'],'value':e['value']}}); iid+=1
for h in range(1, 35):
    b = rpc('DERO.GetBlock', {'height': h})['result']
    bj = json.loads(b['json'])
    txblobs = []
    for th in bj.get('tx_hashes', []):
        t = rpc('DERO.GetTransaction', {'txs_hashes':[th]})['result']['txs']
        if t: txblobs.append(t[0]['blob'])
    inp = {'blob':b['blob'],'height':str(h),'genesis':'false'}
    if txblobs: inp['txs'] = txblobs
    reqs.append({'id':iid,'op':'chain_block_apply','in':inp}); iid+=1
reqs.append({'id':iid,'op':'grav_get','in':{'tree':'M','key':scid}}); iid+=1
p = subprocess.run([RUST], input='\n'.join(json.dumps(r) for r in reqs)+'\n', capture_output=True, text=True, timeout=1800)
for l in p.stdout.splitlines():
    r = json.loads(l)
    if r.get('id') == iid-1:
        print('MINE meta value:', r.get('out',{}).get('value','NOTFOUND'))
print('stderr:', p.stderr[-500:] if p.stderr else '')
