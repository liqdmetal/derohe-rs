#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Poll a mainnet txid for confirmation (mempool -> chain)."""
import json, subprocess, sys, time, urllib.request

RPC = 'http://82.65.143.182:10102/json_rpc'
TXID = sys.argv[1] if len(sys.argv) > 1 else '47c5ce97532478270a761cc248cc385153b762f2795d00846865c7efc0830597'


def rpc(method, params=None):
    body = {'jsonrpc': '2.0', 'id': 0, 'method': method}
    if params is not None:
        body['params'] = params
    req = urllib.request.Request(RPC, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main():
    start_h = rpc('DERO.GetInfo')['result']['height']
    print(f'polling {TXID[:16]}... from height {start_h}')
    for i in range(40):  # ~12 min
        info = rpc('DERO.GetInfo')['result']
        h = info['height']
        r = rpc('DERO.GetTransaction', {'txs_hashes': [TXID]})
        tx = r.get('result', {}).get('txs', [{}])[0] if r.get('result', {}).get('txs') else {}
        in_pool = tx.get('in_pool', False)
        blk_h = tx.get('block_height', 0)
        print(f'  [{i}] h={h} in_pool={in_pool} block_height={blk_h}')
        if blk_h and blk_h > 0:
            print(f'CONFIRMED in block {blk_h}')
            return 0
        if not in_pool and i > 3:
            print('dropped from pool (not confirmed)')
            return 2
        time.sleep(15)
    print('still pending after poll window')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
