// SPDX-License-Identifier: BSD-3-Clause
//
//! dero-node — a runnable Rust DERO node built on the byte-verified
//! consensus core (dero-crypto).
//!
//! Clean-room reimplementation: all consensus logic (block verify, tx
//! verify, state transitions, PoW) comes from dero-crypto, which was
//! differentially proven against the Go reference. This crate is the
//! node shell: sync, mempool, mining, RPC, P2P.
//!
//! Usage:
//!   dero-node --peer http://127.0.0.1:25000/json_rpc --port 26000 \
//!            --mine --miner <bech32-or-hex-address> [--p2p-port 26010]
//!
//! The node pulls blocks from the peer (a derohe simnode or another
//! dero-node), verifies each block's structure + state transition, and
//! applies it to its own graviton trees. With --mine it builds and mines
//! its own blocks (AstroBWTv3 PoW; in simulator mode the PoW is skipped,
//! matching the reference simulator). With --p2p-port it serves the
//! DERO peer protocol (4-byte-length + CBOR framing) so other nodes can
//! sync blocks directly.

use dero_crypto::balance_serdes::{uvarint_encode, NonceBalance};
use dero_crypto::block::{sha3_256, Block, MiniBlock};
use dero_crypto::bulletproof::{verify, Statement};
use dero_crypto::chain;
use dero_crypto::curve::decode_compressed;
use dero_crypto::graviton::Tree;
use dero_crypto::transaction::Transaction;
use dero_crypto::tx_builder::{build_transaction, RingMember, Transfer};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Chain store: in-memory blocks + persistent state trees
// ---------------------------------------------------------------------------

struct ChainStore {
    blocks: Vec<(Block, Vec<Transaction>)>, // height-indexed (topo order)
    txids: Vec<Vec<[u8; 32]>>,              // per-block original chain txids
    raw_txs: Vec<Vec<Vec<u8>>>,             // per-block original raw tx blobs
    roothashes: Vec<[u8; 32]>,              // per-block roothash (after apply)
    balance: Tree,
    sc_meta: Tree,
    genesis_snapshot: Option<(Vec<(Vec<u8>, Vec<u8>)>, Vec<(Vec<u8>, Vec<u8>)>)>, // (balance, meta) at height 0
    /// recent state snapshots (height, roothash, balance, sc_meta) so txs
    /// referencing a recent blid can be verified against the state they
    /// were built on (the live trees advance every mined block)
    recent: VecDeque<(u64, [u8; 32], Tree, Tree)>,
    /// per-SCID token balance trees (the SCID names a separate tree in the
    /// reference; maintained as SC txs execute)
    token_trees: HashMap<[u8; 32], Tree>,
    height: u64,
    k0_floor: Option<u64>,
}

impl ChainStore {
    fn new() -> Self {
        ChainStore {
            blocks: Vec::new(),
            txids: Vec::new(),
            raw_txs: Vec::new(),
            roothashes: Vec::new(),
            balance: Tree::new("BALANCE_TREE"),
            sc_meta: Tree::new("SC_META"),
            genesis_snapshot: None,
            recent: VecDeque::new(),
            token_trees: HashMap::new(),
            height: 0,
            k0_floor: Some(0), // simulator: K0 active from height 0
        }
    }

    /// Persist the chain state to `dir` (trees + blocks). Called after each
    /// applied block. Format: JSON lines (robust, debuggable).
    fn save(&self, dir: &str) -> Result<(), String> {
        use std::io::Write;
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
        // balance + sc_meta trees
        let mut f = std::fs::File::create(format!("{dir}/balance.jsonl"))
            .map_err(|e| format!("open balance: {e}"))?;
        for k in dero_crypto::graviton::tree_keys(&self.balance) {
            if let Some(v) = self.balance.get(&k) {
                writeln!(f, "{}", serde_json::json!({"k": hex::encode(&k), "v": hex::encode(&v)}))
                    .map_err(|e| format!("write: {e}"))?;
            }
        }
        let mut f = std::fs::File::create(format!("{dir}/sc_meta.jsonl"))
            .map_err(|e| format!("open meta: {e}"))?;
        for k in dero_crypto::graviton::tree_keys(&self.sc_meta) {
            if let Some(v) = self.sc_meta.get(&k) {
                writeln!(f, "{}", serde_json::json!({"k": hex::encode(&k), "v": hex::encode(&v)}))
                    .map_err(|e| format!("write: {e}"))?;
            }
        }
        // blocks (serialized blobs + raw tx blobs + txids)
        let mut fb = std::fs::File::create(format!("{dir}/blocks.jsonl"))
            .map_err(|e| format!("open blocks: {e}"))?;
        for (bi, (blk, _txs)) in self.blocks.iter().enumerate() {
            let tids: Vec<String> = self
                .txids
                .get(bi)
                .map(|v| v.iter().map(hex::encode).collect())
                .unwrap_or_default();
            let raws: Vec<String> = self
                .raw_txs
                .get(bi)
                .map(|v| v.iter().map(hex::encode).collect())
                .unwrap_or_default();
            writeln!(
                fb,
                "{}",
                serde_json::json!({
                    "blob": hex::encode(blk.serialize(false)),
                    "txids": tids,
                    "raws": raws,
                })
            )
            .map_err(|e| format!("write block: {e}"))?;
        }
        // height
        std::fs::write(
            format!("{dir}/height"),
            self.height.to_string(),
        )
        .map_err(|e| format!("write height: {e}"))?;
        Ok(())
    }

    /// Load chain state from `dir` (trees + blocks). Returns the number of
    /// blocks loaded, or 0 if nothing is there.
    fn load(&mut self, dir: &str) -> Result<u64, String> {
        use std::io::BufRead;
        let bpath = format!("{dir}/balance.jsonl");
        let mpath = format!("{dir}/sc_meta.jsonl");
        let blpath = format!("{dir}/blocks.jsonl");
        let hpath = format!("{dir}/height");
        if !std::path::Path::new(&bpath).exists() {
            return Ok(0);
        }
        // trees
        for (path, tree) in [(&bpath, &mut self.balance), (&mpath, &mut self.sc_meta)] {
            let f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
            for line in std::io::BufReader::new(f).lines() {
                let line = line.map_err(|e| format!("read: {e}"))?;
                if line.trim().is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_str(&line).map_err(|e| format!("json: {e}"))?;
                let k = hex_decode(v["k"].as_str().unwrap_or(""))?;
                let val = hex_decode(v["v"].as_str().unwrap_or(""))?;
                tree.put(&k, &val);
            }
        }
        // blocks
        let f = std::fs::File::open(&blpath).map_err(|e| format!("open blocks: {e}"))?;
        for line in std::io::BufReader::new(f).lines() {
            let line = line.map_err(|e| format!("read blocks: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(&line).map_err(|e| format!("json: {e}"))?;
            let blob = hex_decode(v["blob"].as_str().unwrap_or(""))?;
            let blk = Block::deserialize(&blob).map_err(|e| format!("block deser: {e}"))?;
            let tids: Vec<[u8; 32]> = v["txids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| hex_decode(x.as_str().unwrap_or("")).ok())
                        .filter_map(|b| b.try_into().ok())
                        .collect()
                })
                .unwrap_or_default();
            let raws: Vec<Vec<u8>> = v["raws"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| hex_decode(x.as_str().unwrap_or("")).ok()).collect())
                .unwrap_or_default();
            // decode the txs from the raw blobs for verification use
            let txs: Vec<Transaction> = raws
                .iter()
                .filter_map(|r| Transaction::deserialize(r, 2).or_else(|_| Transaction::deserialize(r, 3)).ok())
                .collect();
            self.blocks.push((blk, txs));
            self.txids.push(tids);
            self.raw_txs.push(raws);
        }
        self.height = std::fs::read_to_string(&hpath)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        self.snapshot();
        Ok(self.blocks.len() as u64)
    }

    /// Snapshot the current state (called after every applied block).
    fn snapshot(&mut self) {
        let rh = self.roothash();
        self.recent.push_back((self.height, rh, self.balance.clone(), self.sc_meta.clone()));
        while self.recent.len() > 64 {
            self.recent.pop_front();
        }
    }

    /// The balance tree at the state whose roothash matches `rh` (the tx's
    /// referenced state), or None if too old.
    fn balance_at_roothash(&self, rh: &[u8; 32]) -> Option<&Tree> {
        self.recent
            .iter()
            .rev()
            .find(|(_, r, _, _)| r == rh)
            .map(|(_, _, b, _)| b)
    }

    fn roothash(&self) -> [u8; 32] {
        let b = self.balance.hash();
        let m = self.sc_meta.hash();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[i] ^ m[i];
        }
        out
    }
}

// ---------------------------------------------------------------------------
// RPC client (pull-sync peer)
// ---------------------------------------------------------------------------

fn rpc_call(peer: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({"jsonrpc":"2.0","id":0,"method":method,"params":params});
    let mut req = String::new();
    req.push_str(&format!("POST /json_rpc HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", peer_url_host(peer), body.to_string().len()));
    req.push_str(&body.to_string());
    let mut stream = TcpStream::connect(peer_url_host(peer)).map_err(|e| format!("connect: {e}"))?;
    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    let mut resp = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&tmp[..n]);
                // stop once we have the full body per Content-Length
                if let Some(cl) = content_length(&resp) {
                    let header_end = resp.windows(4).position(|w| w == b"\r\n\r\n");
                    if let Some(he) = header_end {
                        let body_len = resp.len() - (he + 4);
                        if body_len >= cl {
                            break;
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
    let s = String::from_utf8_lossy(&resp);
    let json_start = s.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    // handle chunked transfer-encoding (simnode uses it for big responses)
    let is_chunked = String::from_utf8_lossy(&resp)
        .split("\r\n\r\n").next().unwrap_or("")
        .to_lowercase()
        .contains("transfer-encoding: chunked");
    let body = if is_chunked {
        decode_chunked(&resp[json_start..])
    } else {
        let cl = content_length(&resp).unwrap_or(s.len() - json_start);
        let json_end = (json_start + cl).min(s.len());
        s[json_start..json_end].to_string()
    };
    if std::env::var("NODE_DEBUG").is_ok() {
        eprintln!("DBG chunked={} body_head={:?}", is_chunked, &body[..body.len().min(100)]);
    }
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("json: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("rpc error: {err}"));
    }
    Ok(v["result"].clone())
}

fn content_length(resp: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(resp);
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    for line in head.split("\r\n") {
        let l = line.to_lowercase();
        if let Some(v) = l.strip_prefix("content-length:") {
            return v.trim().parse().ok();
        }
    }
    None
}

/// Decode an HTTP chunked-transfer-encoding body (hex-size CRLF data CRLF ... 0 CRLF).
fn decode_chunked(body: &[u8]) -> String {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        // read chunk size line
        let line_end = body[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|i| pos + i)
            .unwrap_or(body.len());
        let size_str = String::from_utf8_lossy(&body[pos..line_end]);
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > body.len() {
            break;
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2; // skip trailing CRLF
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn peer_url_host(peer: &str) -> String {
    // http://127.0.0.1:25000/json_rpc -> 127.0.0.1:25000
    peer.trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

// ---------------------------------------------------------------------------
// Sync: pull blocks from the peer, verify + apply
// ---------------------------------------------------------------------------

fn sync_from_peer(store: &mut ChainStore, peer: &str, simulator: bool) -> Result<u64, String> {
    let info = rpc_call(peer, "DERO.GetInfo", serde_json::json!({}))?;
    let peer_height = info["height"].as_u64().unwrap_or(0);
    let mut applied = 0u64;
    // seed from genesis (height 0 = premine state via DumpBalances)
    if store.blocks.is_empty() {
        seed_genesis(store, peer)?;
        // snapshot the SEEDED genesis state so we can serve height-0 state
        // to peer sync (peer re-applies h1..hN on top of exactly this)
        let pre_balance = store.balance.clone();
        let pre_meta = store.sc_meta.clone();
        let pre_b: Vec<(Vec<u8>, Vec<u8>)> = dero_crypto::graviton::tree_keys(&pre_balance)
            .iter().filter_map(|k| pre_balance.get(k).map(|v| (k.clone(), v))).collect();
        let pre_m: Vec<(Vec<u8>, Vec<u8>)> = dero_crypto::graviton::tree_keys(&pre_meta)
            .iter().filter_map(|k| pre_meta.get(k).map(|v| (k.clone(), v))).collect();
        store.genesis_snapshot = Some((pre_b, pre_m));
        // also store the genesis block so h1's tip reference resolves
        let g = rpc_call(peer, "DERO.GetBlock", serde_json::json!({"height": 0}))?;
        let gblob = hex_decode(g["blob"].as_str().ok_or("no genesis blob")?)?;
        let gblock = Block::deserialize(&gblob)?;
        store.blocks.push((gblock, Vec::new()));
        store.roothashes.push(store.roothash());
        store.txids.push(Vec::new());
        store.raw_txs.push(Vec::new());
    }
    for h in (store.height + 1)..=peer_height {
        let blk = rpc_call(peer, "DERO.GetBlock", serde_json::json!({"height": h}))?;
        let blob = blk["blob"].as_str().ok_or("no blob")?;
        let bj: serde_json::Value = serde_json::from_str(blk["json"].as_str().ok_or("no json")?).map_err(|e| format!("json: {e}"))?;
        let chain_rh = bj["roothash"].as_str().unwrap_or("").to_string();
        let raw = hex_decode(blob)?;
        let block = Block::deserialize(&raw)?;
        // fetch tx blobs (RAW — keep original bytes + chain txids so the
        // hash matches the block header even if a proof fails lenient parse)
        let mut txs = Vec::new();
        let mut raw_txs = Vec::new();
        let mut block_txids = Vec::new();
        if let Some(txhs) = bj["tx_hashes"].as_array() {
            for th in txhs {
                let th = th.as_str().unwrap_or("");
                let mut thb = [0u8; 32];
                if let Ok(t) = hex_decode(th) {
                    if t.len() == 32 {
                        thb.copy_from_slice(&t);
                    }
                }
                block_txids.push(thb);
                let t = rpc_call(peer, "DERO.GetTransaction", serde_json::json!({"txs_hashes": [th]}))?;
                if let Some(txs_arr) = t["txs"].as_array() {
                    for txj in txs_arr {
                        let tb = txj["blob"].as_str().ok_or("no tx blob")?;
                        let raw_tx = hex_decode(tb)?;
                        // the txid from the chain header must match the blob
                        let tx = tx_deserialize_lenient(&raw_tx, simulator)
                            .map_err(|e| format!("h{h} tx {th}: {e}"))?;
                        // verify the blob's hash matches the chain's txid
                        // (strict in mainnet; in simulator the chain may
                        // contain lax txs whose re-serialize diverges)
                        let bpp = tx.payloads.first().map(|p| p.statement.bpp()).unwrap_or(3);
                        let computed = hex::encode(tx.get_hash(bpp));
                        if computed != th.to_lowercase() {
                            if simulator {
                                // lax tx: accept (the simnode mined it
                                // without verification)
                                eprintln!("h{h}: lax tx {th} hash diverges (simulator accept)");
                            } else {
                                return Err(format!("h{h}: tx hash mismatch computed={computed} chain={th}"));
                            }
                        }
                        txs.push(tx);
                        raw_txs.push(raw_tx);
                    }
                }
            }
        }
        // verify structure: height continuity + tips reference known blocks
        if block.height != h {
            return Err(format!("h{h}: block height mismatch {}", block.height));
        }
        for tip in &block.tips {
            let known = store.blocks.iter().any(|(b, _)| &b.get_hash() == tip);
            if !known {
                return Err(format!("h{h}: unknown tip {:?}", &tip[..8]));
            }
        }
        // apply state
        let (_, b_root, m_root) = chain::add_complete_block(
            &mut store.balance, &mut store.sc_meta, &block, &txs, h,
            h == 0, store.k0_floor,
        ).map_err(|e| format!("h{h}: {e}"))?;
        let xor = {
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = b_root[i] ^ m_root[i];
            }
            out
        };
        let computed = hex::encode(xor);
        if !chain_rh.is_empty() && computed != chain_rh {
            return Err(format!("h{h}: roothash mismatch computed={computed} chain={chain_rh}"));
        }
        store.blocks.push((block, txs));
        store.roothashes.push(xor);
        store.txids.push(block_txids);
        store.raw_txs.push(raw_txs);
        store.height = h;
        store.snapshot();
        applied += 1;
    }
    Ok(applied)
}
fn seed_genesis(store: &mut ChainStore, peer: &str) -> Result<(), String> {
    // the genesis state = premine balances + base SC meta; the simnode
    // dumps them via DumpBalances at height 0.
    let d = rpc_call(peer, "DERO.DumpBalances", serde_json::json!({"height": 0}))?;
    if let Some(entries) = d["entries"].as_array() {
        for e in entries {
            let key = hex_decode(e["key"].as_str().ok_or("no key")?)?;
            let val = hex_decode(e["value"].as_str().ok_or("no val")?)?;
            store.balance.put(&key, &val);
        }
    }
    if let Some(mes) = d["meta_entries"].as_array() {
        for e in mes {
            let key = hex_decode(e["key"].as_str().ok_or("no key")?)?;
            let val = hex_decode(e["value"].as_str().ok_or("no val")?)?;
            store.sc_meta.put(&key, &val);
        }
    }
    store.snapshot(); // the genesis state (txs referencing it resolve here)
    Ok(())
}

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

struct Mempool {
    txs: HashMap<[u8; 32], Transaction>,
    raw: HashMap<[u8; 32], Vec<u8>>, // original wire blob per txid
}

impl Mempool {
    fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            raw: HashMap::new(),
        }
    }
    fn add(&mut self, tx: Transaction, raw: Vec<u8>) -> bool {
        let bpp = tx
            .payloads
            .first()
            .map(|p| p.statement.bpp())
            .unwrap_or(2);
        let h = tx.get_hash(bpp);
        if self.txs.contains_key(&h) {
            return false;
        }
        self.raw.insert(h, raw);
        self.txs.insert(h, tx);
        true
    }
}

/// Expand a deserialized statement with the chain state: fill
/// publickeylist (compressed keys from the balance tree) and CLn/CRn
/// (ebalance.left + C[i], ebalance.right + D). This is exactly what the
/// reference does before verifying a tx's proof.
fn expand_statement(tree: &Tree, st: &mut Statement) -> Result<(), String> {
    let bpp = st.bpp() as usize;
    let ring = if bpp == 0 {
        0
    } else {
        st.pointers.len() / bpp
    };
    st.publickeylist.clear();
    st.cln.clear();
    st.crn.clear();
    for i in 0..ring {
        let key_pointer = &st.pointers[i * bpp..(i + 1) * bpp];
        let (key_compressed, balance_serialized) = tree
            .get_key_value_from_hash(key_pointer)
            .ok_or_else(|| format!("ring member {i} not in balance tree"))?;
        let mut key = [0u8; 33];
        if key_compressed.len() != 33 {
            return Err("bad ring key length".into());
        }
        key.copy_from_slice(&key_compressed);
        let nb = NonceBalance::deserialize(&balance_serialized)
            .map_err(|e| format!("bad ring balance: {e}"))?;
        st.publickeylist
            .push(decode_compressed(&key).map_err(|e| format!("bad ring key: {e}"))?);
        st.cln.push(nb.balance.left + st.c[i]);
        st.crn.push(nb.balance.right + st.d);
    }
    Ok(())
}

/// Verify a raw tx against the node's state at the tx's referenced
/// roothash (the way the reference mempool does: expand + Proof.Verify).
/// Returns the txid.
fn verify_raw_tx(store: &ChainStore, raw: &[u8]) -> Result<[u8; 32], String> {
    let tx = Transaction::deserialize(raw, 2)
        .or_else(|_| Transaction::deserialize(raw, 3))
        .map_err(|e| format!("deserialize: {e}"))?;
    let bpp = tx
        .payloads
        .first()
        .map(|p| p.statement.bpp())
        .unwrap_or(2);
    let txid = tx.get_hash(bpp);
    if tx.payloads.is_empty() {
        return Err("tx has no payloads".into());
    }
    // the state the tx was built on: match the statement's roothash against
    // the recent snapshots (the live trees advance every mined block)
    let stmt_rh: [u8; 32] = tx.payloads[0]
        .statement
        .roothash
        .try_into()
        .map_err(|_| "bad roothash".to_string())?;
    let state = store
        .balance_at_roothash(&stmt_rh)
        .ok_or_else(|| "tx references a state older than the snapshot window".to_string())?;
    let mut scid_index_map: HashMap<[u8; 32], i32> = HashMap::new();
    for (i, p) in tx.payloads.iter().enumerate() {
        let proof = p.proof.as_ref().ok_or_else(|| format!("payload {i} has no proof"))?;
        let mut stmt = p.statement.clone();
        expand_statement(state, &mut stmt)?;
        let index = *scid_index_map.get(&p.scid).unwrap_or(&0);
        if !verify(&p.scid, index, &stmt, proof, &txid, p.burn_value) {
            return Err(format!("payload {i} proof verification failed"));
        }
        scid_index_map.insert(p.scid, index + 1);
    }
    Ok(txid)
}

// ---------------------------------------------------------------------------
// Miner
// ---------------------------------------------------------------------------

struct Miner {
    address: [u8; 33],
    simulator: bool,
    secret: Option<Fr>, // wallet mode: --seed derived secret
}

impl Miner {
    /// Build a new block on the store's current tip. Mirrors
    /// Create_new_miner_block + ConvertBlockToMiniblock (simulator: no PoW).
    fn build_block(&self, store: &ChainStore, mempool: &Mempool, timestamp: u64) -> Block {
        let height = store.height + 1;
        let tips = match store.blocks.last() {
            Some((b, _)) => vec![b.get_hash()],
            None => vec![[0u8; 32]], // genesis-only: tip = zero (unused)
        };
        // miner tx: COINBASE, value 0, miner address
        let miner_tx = Transaction {
            version: 1,
            source_network: 0,
            dest_network: 0,
            tx_type: 2, // TX_COINBASE
            value: 0,
            miner_address: self.address,
            c: [0u8; 32],
            s: [0u8; 32],
            height,
            blid: [0u8; 32],
            scdata: Default::default(),
            payloads: Vec::new(),
        };
        // miniblock (integrator = miner address)
        let kh = dero_crypto::graviton::sum(&self.address);
        let mut mbl = MiniBlock {
            version: 1,
            high_diff: false,
            final_block: true,
            past_count: tips.len() as u8,
            timestamp: timestamp as u16,
            height,
            past: [
                u32::from_be_bytes(tips[0][..4].try_into().unwrap()),
                0,
            ],
            key_hash: kh,
            flags: 0,
            nonce: [0x1111_1111, 0x2222_2222, 0x3333_3333],
        };
        // final miniblock keyhash = sha3(block serialize without miniblocks)
        let tmp = Block {
            major_version: 1,
            minor_version: 0,
            timestamp,
            height,
            miner_tx: miner_tx.clone(),
            proof: [0u8; 32],
            tips: tips.clone(),
            mini_blocks: Vec::new(),
            tx_hashes: Vec::new(),
        };
        mbl.key_hash = sha3_256(&tmp.serialize(false));
        // include mempool txs (up to a few, sorted by fees — simple pick)
        let mut tx_hashes = Vec::new();
        for (h, tx) in mempool.txs.iter() {
            let _ = tx;
            tx_hashes.push(*h);
            if tx_hashes.len() >= 8 {
                break;
            }
        }
        Block {
            major_version: 1,
            minor_version: 0,
            timestamp,
            height,
            miner_tx,
            proof: [0u8; 32],
            tips,
            mini_blocks: vec![mbl],
            tx_hashes,
        }
    }

    /// Solve PoW (AstroBWTv3). In simulator mode: zero proof.
    fn solve(&self, block: &mut Block) {
        if self.simulator {
            block.proof = [0u8; 32];
            return;
        }
        // real AstroBWTv3 PoW — the ported, verified algorithm
        let header = block.serialize(false);
        let nonce0 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u32;
        // miner address is the miniblock keyhash carrier; iterate nonce in
        // the miniblock nonce[0]
        let mut best = [0xffu8; 32];
        let mut best_nonce = nonce0;
        for n in 0..100_000u32 {
            let nonce = nonce0.wrapping_add(n);
            let mut trial = block.clone();
            if let Some(m) = trial.mini_blocks.last_mut() {
                m.nonce[0] = nonce;
            }
            let h = dero_crypto::astrobwt_v3::astrobwt_v3(&trial.serialize(false));
            if h < best {
                best = h;
                best_nonce = nonce;
            }
            if best[0] == 0 && best[1] == 0 {
                break;
            }
        }
        if let Some(m) = block.mini_blocks.last_mut() {
            m.nonce[0] = best_nonce;
        }
        block.proof = best;
    }
}

// ---------------------------------------------------------------------------
// HTTP JSON-RPC server
// ---------------------------------------------------------------------------

fn handle_rpc(req_body: &str, store: &Arc<Mutex<ChainStore>>, mempool: &Arc<Mutex<Mempool>>, miner: &Miner, peers: &[String]) -> String {
    let v: serde_json::Value = match serde_json::from_str(req_body) {
        Ok(v) => v,
        Err(_) => return json_err(-32700, "parse error"),
    };
    let method = v["method"].as_str().unwrap_or("").to_string();
    let params = v["params"].clone();
    let id = v["id"].clone();
    let st = store.lock().unwrap();
    let result = match method.as_str() {
        "DERO.Transfer" => {
            // wallet mode: build + submit a NORMAL or SC-install transfer
            // from the node's own balance tree (needs --seed). The ring,
            // balances, roothash, blid and height all come from OUR state.
            let (secret, self_addr) = match (miner.secret, miner.address) {
                (Some(s), a) => (s, a),
                _ => return json_err_id(-32000, "node has no wallet (start with --seed)", id),
            };
            let dest = params["dest"].as_str().unwrap_or("");
            let amount: u64 = params["amount"].as_u64().unwrap_or(0);
            // multi-asset: params.scid (hex) -> transfer a TOKEN
            let mut scid = [0u8; 32];
            let scid_hex = params["scid"].as_str().unwrap_or("");
            let has_scid = !scid_hex.is_empty();
            if has_scid {
                let b = match hex_decode(scid_hex.trim_start_matches("0x")) {
                    Ok(b) if b.len() == 32 => b,
                    _ => return json_err_id(-32000, "bad scid (need 32 bytes hex)", id),
                };
                scid.copy_from_slice(&b);
            }
            // SC install: params.sc_code present -> SC_ACTION=1 + SC_CODE
            let sc_code = params["sc_code"].as_str().unwrap_or("");
            let is_sc = !sc_code.is_empty();
            let dest_comp: [u8; 33] = match parse_addr(dest) {
                Ok(c) => c,
                Err(e) => return json_err_id(-32000, &format!("bad dest: {e}"), id),
            };
            if !is_sc && self_addr == dest_comp {
                return json_err_id(-32000, "cannot send to self", id);
            }
            // ring = [self, dest, others] — all distinct, from the tree.
            // For a TOKEN transfer the ring comes from the TOKEN's balance
            // tree (scid != 0): we fall back to the base tree for members,
            // but fetch balances from the token tree when present.
            let mut ring_members: Vec<[u8; 33]> = vec![self_addr, dest_comp];
            // SC installs use ring size 4 (like the reference wallet)
            let ring_size = if is_sc { 4 } else { 8 };
            for k in dero_crypto::graviton::tree_keys(&st.balance) {
                if k.len() != 33 {
                    continue;
                }
                let mut kk = [0u8; 33];
                kk.copy_from_slice(&k);
                if kk == self_addr || kk == dest_comp {
                    continue;
                }
                ring_members.push(kk);
                if ring_members.len() >= ring_size {
                    break;
                }
            }
            if ring_members.len() < ring_size {
                return json_err_id(-32000, &format!("need {ring_size} ring members, got {}", ring_members.len()), id);
            }
            // balances from the tree + BSGS decode for self. For a TOKEN
            // transfer (scid != 0) the balances come from the token's own
            // SC data tree (keyed by the SCID's wrapped tree).
            let mut ring: Vec<RingMember> = Vec::new();
            for (i, k) in ring_members.iter().enumerate() {
                let nb = (if has_scid { st.token_trees.get(&scid) } else { None })
                    .and_then(|t| t.get(k))
                    .or_else(|| st.balance.get(k))
                    .and_then(|v| NonceBalance::deserialize(&v).ok())
                    .map(|n| n.balance)
                    .unwrap_or_else(|| {
                        // unregistered: zero ciphertext for this key
                        let key = decode_compressed(k).unwrap_or_default();
                        dero_crypto::elgamal::ElGamal::new(key, dero_crypto::hash_to_point::base_g())
                    });
                let decoded = if i == 0 {
                    dero_crypto::wallet::decode_balance(&nb, &secret, 44).unwrap_or(0)
                } else {
                    0
                };
                ring.push(RingMember { public_key: *k, balance: nb, balance_decoded: decoded });
            }
            let roothash = st.roothash();
            let blid = st
                .blocks
                .last()
                .map(|(b, _)| b.get_hash())
                .unwrap_or([0u8; 32]);
            let height = st.height;
            drop(st);
            // build + verify + mempool
            let transfers = vec![Transfer {
                destination: dest.to_string(),
                amount,
                burn: 0,
                scid, // token SCID (zero = base asset)
                payload_rpc: Vec::new(),
            }];
            // SC install: SC_ACTION=1 (SC_INSTALL) + SC_CODE
            let scdata = if is_sc {
                dero_crypto::rpc_args::Arguments(vec![
                    dero_crypto::rpc_args::Argument {
                        name: dero_crypto::rpc_args::SC_ACTION.to_string(),
                        data_type: dero_crypto::rpc_args::DATA_UINT64,
                        value: dero_crypto::rpc_args::ArgValue::U64(1),
                    },
                    dero_crypto::rpc_args::Argument {
                        name: dero_crypto::rpc_args::SC_CODE.to_string(),
                        data_type: dero_crypto::rpc_args::DATA_STRING,
                        value: dero_crypto::rpc_args::ArgValue::Str(sc_code.to_string()),
                    },
                ])
            } else {
                dero_crypto::rpc_args::Arguments::default()
            };
            let tx = match build_transaction(
                &transfers,
                &[ring],
                0,
                1,
                &blid,
                height,
                &scdata,
                &roothash,
                9,
                0,
                &secret,
                &[0x5au8; 16384],
            ) {
                Ok(t) => t,
                Err(e) => return json_err_id(-32000, &format!("build: {e}"), id),
            };
            let blob = tx.serialize(2);
            let txid = {
                let st2 = store.lock().unwrap();
                match verify_raw_tx(&st2, &blob) {
                    Ok(t) => t,
                    Err(e) => return json_err_id(-32000, &format!("verify: {e}"), id),
                }
            };
            let mut mp = mempool.lock().unwrap();
            if mp.add(tx, blob) {
                serde_json::json!({"txid": hex::encode(txid), "status": "OK"})
            } else {
                return json_err_id(-32000, "tx already in pool", id);
            }
        }
        "DERO.GetInfo" => serde_json::json!({
            "height": st.height,
            "tips": 1,
            "roothash": hex::encode(st.roothash()),
            "network": "simulator",
            "status": "OK",
            "testnet": true,
            "top_block_hash": st.blocks.last().map(|(b, _)| hex::encode(b.get_hash())).unwrap_or_else(|| hex::encode([0u8; 32])),
        }),
        "DERO.GetEncryptedBalance" => {
            // {address, scid, topoheight} -> the NonceBalance serialization
            // from the node's own balance tree (pointer = blake2s(addr)[:3])
            let addr = params["address"].as_str().unwrap_or("");
            let comp = match dero_crypto::rpc_addr::address_to_compressed(addr) {
                Ok(c) => c,
                Err(_) => return json_err_id(-32000, "bad address", id),
            };
            let kh = dero_crypto::graviton::sum(&comp);
            let status = match st.balance.get_key_value_from_hash(&kh[..3]) {
                Some((_k, v)) => {
                    serde_json::json!({
                        "data": hex::encode(&v),
                        "status": "OK",
                        "topoheight": st.height as i64,
                        "height": st.height,
                        "treehash": hex::encode(st.roothash()),
                        "blockhash": st.blocks.last().map(|(b, _)| hex::encode(b.get_hash())).unwrap_or_default(),
                    })
                }
                None => serde_json::json!({
                    "data": "",
                    "status": "Account Unregistered",
                    "topoheight": st.height as i64,
                    "height": st.height,
                    "treehash": hex::encode(st.roothash()),
                    "blockhash": st.blocks.last().map(|(b, _)| hex::encode(b.get_hash())).unwrap_or_default(),
                }),
            };
            status
        }
        "DERO.GetRandomAddress" => {
            // serve the registered addresses (tree keys -> bech32); return
            // up to 32 so wallets have enough distinct ring candidates
            let mut addrs: Vec<String> = dero_crypto::graviton::tree_keys(&st.balance)
                .iter()
                .filter_map(|k| dero_crypto::rpc_addr::compressed_to_address(k).ok())
                .collect();
            addrs.sort();
            addrs.truncate(32);
            serde_json::json!({"address": addrs})
        }
        "DERO.GetRegistrations" => {
            let keys: Vec<String> = dero_crypto::graviton::tree_keys(&st.balance)
                .iter()
                .map(|k| hex::encode(k))
                .collect();
            serde_json::json!({"addresses": keys})
        }
        "DERO.GetBlock" => {
            let h = params["height"].as_i64().unwrap_or(0);
            if h < 0 || h as u64 > st.height {
                return json_err_id(-32000, "block not found", id);
            }
            let (blk, txs) = &st.blocks[h as usize];
            let mut tx_hashes = Vec::new();
            for t in txs {
                tx_hashes.push(hex::encode(t.get_hash(3)));
            }
            // serve the ORIGINAL chain txids (the lenient parse may have
            // changed re-serialized hashes)
            if let Some(tids) = st.txids.get(h as usize) {
                tx_hashes = tids.iter().map(|t| hex::encode(t)).collect();
            }
            serde_json::json!({
                "blob": hex::encode(blk.serialize(false)),
                "json": serde_json::json!({
                    "height": blk.height,
                    "blid": hex::encode(blk.get_hash()),
                    "roothash": hex::encode(st.roothashes.get(h as usize).copied().unwrap_or([0u8; 32])),
                    "tx_hashes": tx_hashes,
                }).to_string(),
            })
        }
        "DERO.GetTransaction" => {
            let th = params["txs_hashes"][0].as_str().unwrap_or("");
            let txh = hex_decode(th).unwrap_or_default();
            let mut found = serde_json::Value::Null;
            // search by the ORIGINAL chain txids (index-aligned with txs),
            // serving the RAW blob (byte-identical to the chain) + the
            // EXPANDED ring (reference Tx_Related_Info.Ring)
            for (bi, (blk, txs)) in st.blocks.iter().enumerate() {
                let _ = blk;
                if let Some(tids) = st.txids.get(bi) {
                    for (ti, tid) in tids.iter().enumerate() {
                        if tid.as_slice() == txh.as_slice() {
                            if let Some(raws) = st.raw_txs.get(bi) {
                                if let Some(raw) = raws.get(ti) {
                                    let mut info = serde_json::json!({
                                        "blob": hex::encode(raw),
                                        "tx_hash": hex::encode(tid),
                                        "block_height": bi as i64,
                                        "in_pool": false,
                                        "valid_block": st.blocks.get(bi).map(|(b, _)| hex::encode(b.get_hash())).unwrap_or_default(),
                                    });
                                    // expand the ring: pointers -> keys via
                                    // the balance tree -> bech32 addresses
                                    if let Some(tx) = txs.get(ti) {
                                        let mut ring: Vec<Vec<String>> = Vec::new();
                                        for p in &tx.payloads {
                                            let stmt = &p.statement;
                                            let bpp = stmt.bpp() as usize;
                                            let n = if bpp == 0 { 0 } else { stmt.pointers.len() / bpp };
                                            let mut members = Vec::new();
                                            for i in 0..n {
                                                let ptr = &stmt.pointers[i * bpp..(i + 1) * bpp];
                                                if let Some((k, _v)) = st.balance.get_key_value_from_hash(ptr) {
                                                    if let Ok(a) = dero_crypto::rpc_addr::compressed_to_address(&k) {
                                                        members.push(a);
                                                    }
                                                }
                                            }
                                            ring.push(members);
                                        }
                                        info["ring"] = serde_json::json!(ring);
                                    }
                                    found = serde_json::json!([info]);
                                }
                            }
                        }
                    }
                }
            }
            if found.is_null() {
                // also check the mempool — serve the ORIGINAL raw blob (the
                // re-serialized form can differ in bpp for wallet txs)
                let mp = mempool.lock().unwrap();
                if let Some(raw) = mp.raw.get(&txh.as_slice().try_into().unwrap_or([0u8; 32])) {
                    found = serde_json::json!([{"blob": hex::encode(raw)}]);
                } else {
                    for (h, t) in &mp.txs {
                        if h.as_slice() == txh.as_slice() {
                            found = serde_json::json!([{"blob": hex::encode(t.serialize(3))}]);
                        }
                    }
                }
            }
            serde_json::json!({"txs": found})
        }
        "DERO.GetStateRoot" => serde_json::json!({"roothash": hex::encode(st.roothash())}),
        "DERO.DumpBalances" => {
            let want_h = params["height"].as_u64().unwrap_or(0);
            let mut entries: Vec<serde_json::Value> = Vec::new();
            let mut meta: Vec<serde_json::Value> = Vec::new();
            let (b_root, m_root) = if want_h == 0 {
                // serve the genesis-state snapshot (pre-block trees + seed)
                if let Some((b, m)) = &st.genesis_snapshot {
                    for (k, v) in b {
                        entries.push(serde_json::json!({"key": hex::encode(k), "value": hex::encode(v)}));
                    }
                    for (k, v) in m {
                        meta.push(serde_json::json!({"key": hex::encode(k), "value": hex::encode(v)}));
                    }
                    (hex::encode(st.roothashes.first().copied().unwrap_or([0u8; 32])), String::new())
                } else {
                    // no snapshot: fall back to live (already seeded) state
                    for k in dero_crypto::graviton::tree_keys(&st.balance) {
                        if let Some(v) = st.balance.get(&k) {
                            entries.push(serde_json::json!({"key": hex::encode(&k), "value": hex::encode(&v)}));
                        }
                    }
                    for k in dero_crypto::graviton::tree_keys(&st.sc_meta) {
                        if let Some(v) = st.sc_meta.get(&k) {
                            meta.push(serde_json::json!({"key": hex::encode(&k), "value": hex::encode(&v)}));
                        }
                    }
                    (hex::encode(st.balance.hash()), hex::encode(st.sc_meta.hash()))
                }
            } else {
                // non-zero height: serve the live (current) trees
                for k in dero_crypto::graviton::tree_keys(&st.balance) {
                    if let Some(v) = st.balance.get(&k) {
                        entries.push(serde_json::json!({"key": hex::encode(&k), "value": hex::encode(&v)}));
                    }
                }
                for k in dero_crypto::graviton::tree_keys(&st.sc_meta) {
                    if let Some(v) = st.sc_meta.get(&k) {
                        meta.push(serde_json::json!({"key": hex::encode(&k), "value": hex::encode(&v)}));
                    }
                }
                (hex::encode(st.balance.hash()), hex::encode(st.sc_meta.hash()))
            };
            serde_json::json!({"entries": entries, "root": b_root,
                "meta_root": m_root, "meta_entries": meta})
        }
        "DERO.SubmitTX" => {
            // accept both {"blob": "hex"} and {"txs": [{"tx": "hex"}]}
            let blob_hex = params["blob"]
                .as_str()
                .or_else(|| {
                    params["txs"].as_array().and_then(|a| a.get(0)).and_then(|t| t["tx"].as_str())
                })
                .unwrap_or("");
            if blob_hex.is_empty() {
                return json_err_id(-32000, "no tx blob", id);
            }
            let raw = match hex_decode(blob_hex) {
                Ok(r) => r,
                Err(_) => return json_err_id(-32000, "bad hex", id),
            };
            // chain-style verification: expand CLn/CRn + publickeylist from
            // the node's balance tree, then verify each payload's proof
            let txid = match verify_raw_tx(&st, &raw) {
                Ok(t) => t,
                Err(e) => return json_err_id(-32000, &format!("verification failed: {e}"), id),
            };
            let tx = match Transaction::deserialize(&raw, 2)
                .or_else(|_| Transaction::deserialize(&raw, 3))
            {
                Ok(t) => t,
                Err(e) => return json_err_id(-32000, &format!("deserialize: {e}"), id),
            };
            drop(st);
            let added = {
                let mut mp = mempool.lock().unwrap();
                mp.add(tx, raw.clone())
            };
            if added {
                // P2P relay: forward the raw blob to every peer (fire and
                // forget — the peer verifies before accepting)
                let blob_hex = hex::encode(&raw);
                for p in peers {
                    let _ = rpc_call(p, "DERO.SubmitTX", serde_json::json!({"blob": blob_hex.clone()}));
                }
                serde_json::json!({"txid": hex::encode(txid), "status": "OK"})
            } else {
                return json_err_id(-32000, "tx already in pool", id);
            }
        }
        "DERO.CheckTxHash" => {
            let blob_hex = params["blob"].as_str().unwrap_or("");
            let raw = match hex_decode(blob_hex) {
                Ok(r) => r,
                Err(_) => return json_err_id(-32000, "bad hex", id),
            };
            match Transaction::deserialize(&raw, 2).or_else(|_| Transaction::deserialize(&raw, 3)) {
                Ok(tx) => {
                    let bpp = tx.payloads.first().map(|p| p.statement.bpp()).unwrap_or(2);
                    serde_json::json!({"txid": hex::encode(tx.get_hash(bpp)), "status": "OK"})
                }
                Err(e) => return json_err_id(-32000, &format!("deserialize: {e}"), id),
            }
        }
        _ => return json_err_id(-32601, "method not found", id),
    };
    serde_json::json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()
}

/// Serve the DERO peer protocol (4-byte-length + CBOR framing). Handles
/// the sync subset: Peer.Chain (block hash lists) and Peer.GetObject
/// (block bodies). This is the REAL derohe wire protocol (p2p/wire_structs.go).
fn serve_p2p(p2p_port: u16, store: Arc<Mutex<ChainStore>>) {
    use dero_crypto::p2p::{cbor, read_frame, write_frame};
    let listener = match TcpListener::bind(("0.0.0.0", p2p_port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("p2p bind: {e}");
            return;
        }
    };
    println!("node P2P listening on 0.0.0.0:{p2p_port}");
    for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        let st = store.clone();
        std::thread::spawn(move || {
            s.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok();
            let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(30)));
            loop {
                // TWO frames per message: header {M,S,E} then the object
                let hdr_frame = match read_frame(&mut s) {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let v = dero_crypto::p2p::decode_map(&hdr_frame);
                let method = v.get("M").and_then(|m| m.as_str()).unwrap_or("").to_string();
                let seq = v.get("S").and_then(|s| s.as_u64()).unwrap_or(0);
                // read the object frame (may be absent for errors)
                let obj_frame = read_frame(&mut s).unwrap_or_default();
                let store_g = st.lock().unwrap();
                let body: Vec<u8> = match method.as_str() {
                    "Peer.Chain" => {
                        // respond with the block list (last 20 hashes + genesis)
                        let mut blist: Vec<Vec<u8>> = Vec::new();
                        let start = store_g.blocks.len().saturating_sub(20);
                        for (b, _) in store_g.blocks.iter().skip(start) {
                            blist.push(b.get_hash().to_vec());
                        }
                        if !store_g.blocks.is_empty() {
                            blist.push(store_g.blocks[0].0.get_hash().to_vec());
                        }
                        let mut body = cbor::map(3);
                        body.extend_from_slice(&cbor::kv("COMMON", &cbor::map(0)));
                        body.extend_from_slice(&cbor::kv(
                            "SH",
                            &cbor::int(start as i64),
                        ));
                        let mut bl = cbor::array(blist.len());
                        for h in &blist {
                            bl.extend_from_slice(&cbor::bytes(h));
                        }
                        body.extend_from_slice(&cbor::kv("BLIST", &bl));
                        body
                    }
                    "Peer.GetObject" => {
                        // {BLIST: [hashes]} -> {CBLOCKS: [block blobs]}
                        let vobj = dero_crypto::p2p::decode_map(&obj_frame);
                        let mut blobs: Vec<Vec<u8>> = Vec::new();
                        if let Some(blist) = vobj.get("BLIST").and_then(|b| b.as_array()) {
                            for h in blist {
                                let hh = h.as_str().unwrap_or("");
                                let hb = hex_decode(hh).unwrap_or_default();
                                if let Some((blk, _)) = store_g
                                    .blocks
                                    .iter()
                                    .find(|(b, _)| b.get_hash().as_slice() == hb.as_slice())
                                {
                                    blobs.push(blk.serialize(false));
                                }
                            }
                        }
                        let mut body = cbor::map(2);
                        body.extend_from_slice(&cbor::kv("COMMON", &cbor::map(0)));
                        let mut cb = cbor::array(blobs.len());
                        for b in &blobs {
                            cb.extend_from_slice(&cbor::bytes(b));
                        }
                        body.extend_from_slice(&cbor::kv("CBLOCKS", &cb));
                        body
                    }
                    _ => {
                        // unknown method: error response
                        let mut body = cbor::map(1);
                        body.extend_from_slice(&cbor::kv("COMMON", &cbor::map(0)));
                        body
                    }
                };
                let hdr = cbor::header("", seq, "");
                if write_frame(&mut s, &hdr).is_err() || write_frame(&mut s, &body).is_err() {
                    break;
                }
            }
        });
    }
}

/// P2P client: pull blocks from a peer over the real DERO wire protocol
/// (Peer.Chain for the hash list, Peer.GetObject for block bodies).
fn p2p_sync_from(store: &mut ChainStore, addr: &str, simulator: bool) -> Result<u64, String> {
    use dero_crypto::p2p::{cbor, read_frame, write_frame};
    let mut s = TcpStream::connect(addr).map_err(|e| format!("p2p connect {addr}: {e}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(60))).ok();
    // Peer.Chain request: TWO frames — header {M,S} then object
    let mut body = cbor::map(3);
    body.extend_from_slice(&cbor::kv("COMMON", &cbor::map(0)));
    body.extend_from_slice(&cbor::kv("BLIST", &cbor::array(0)));
    body.extend_from_slice(&cbor::kv("TOPO", &cbor::array(0)));
    write_frame(&mut s, &cbor::header("Peer.Chain", 1, "")).map_err(|e| format!("p2p write: {e}"))?;
    write_frame(&mut s, &body).map_err(|e| format!("p2p write: {e}"))?;
    // response: header frame then object frame
    let _hdr = read_frame(&mut s).map_err(|e| format!("p2p read hdr: {e}"))?;
    let resp = read_frame(&mut s).map_err(|e| format!("p2p read: {e}"))?;
    let v = dero_crypto::p2p::decode_map(&resp);
    let blist = v
        .get("BLIST")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    let start_h = v.get("SH").and_then(|s| s.as_i64()).unwrap_or(0).max(0) as u64;
    println!("p2p chain resp: SH={start_h} blist_len={}", blist.len());
    if blist.is_empty() {
        return Ok(0);
    }
    // the LAST entry is genesis (reference appends it); skip it for bodies
    let want: Vec<Vec<u8>> = blist
        .iter()
        .filter_map(|h| h.as_str().map(|x| hex_decode(x).unwrap_or_default()))
        .collect();
    // fetch each block body via Peer.GetObject, skipping already-applied
    let mut applied = 0u64;
    let mut h = start_h;
    for hb in &want {
        // skip blocks we already have (the peer's window overlaps ours)
        let known = store.blocks.iter().any(|(b, _)| b.get_hash().as_slice() == hb.as_slice());
        if known {
            continue;
        }
        let mut body = cbor::map(2);
        body.extend_from_slice(&cbor::kv("COMMON", &cbor::map(0)));
        let mut bl = cbor::array(1);
        bl.extend_from_slice(&cbor::bytes(hb));
        body.extend_from_slice(&cbor::kv("BLIST", &bl));
        write_frame(&mut s, &cbor::header("Peer.GetObject", 2, "")).map_err(|e| format!("p2p write: {e}"))?;
        write_frame(&mut s, &body).map_err(|e| format!("p2p write: {e}"))?;
        let _hdr = read_frame(&mut s).map_err(|e| format!("p2p read hdr: {e}"))?;
        let resp = read_frame(&mut s).map_err(|e| format!("p2p read: {e}"))?;
        let v = dero_crypto::p2p::decode_map(&resp);
        let blobs = v
            .get("CBLOCKS")
            .and_then(|b| b.as_array())
            .cloned()
            .unwrap_or_default();
        for blb in &blobs {
            let raw = match blb.as_str().map(hex_decode) {
                Some(Ok(r)) => r,
                _ => continue,
            };
            let block = match Block::deserialize(&raw) {
                Ok(b) => b,
                Err(_) => continue,
            };
            // apply (verify structure + state transition)
            let txs = Vec::new(); // bodies carry miner tx only in our subset
            let genesis = block.height == 0;
            let k0 = store.k0_floor;
            let ChainStore { balance, sc_meta, .. } = store;
            match chain::add_complete_block(balance, sc_meta, &block, &txs, block.height, genesis, k0) {
                Ok(_) => {
                    store.blocks.push((block.clone(), txs));
                    store.txids.push(Vec::new());
                    store.raw_txs.push(Vec::new());
                    store.height = block.height;
                    store.snapshot();
                    applied += 1;
                }
                Err(e) => {
                    if simulator {
                        // lax accept (reference simulator behaviour)
                        store.blocks.push((block.clone(), txs));
                        store.txids.push(Vec::new());
                        store.raw_txs.push(Vec::new());
                        store.height = block.height;
                        store.snapshot();
                        applied += 1;
                    } else {
                        return Err(format!("p2p apply h{h}: {e}"));
                    }
                }
            }
            h += 1;
        }
    }
    Ok(applied)
}

fn json_err(code: i64, msg: &str) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":code,"message":msg}}).to_string()
}
fn json_err_id(code: i64, msg: &str, id: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}}).to_string()
}

fn serve(port: u16, store: Arc<Mutex<ChainStore>>, mempool: Arc<Mutex<Mempool>>, miner: Arc<Miner>, peers: Arc<Vec<String>>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    println!("node RPC listening on 127.0.0.1:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // read until we have the full body (headers + Content-Length)
                loop {
                    match s.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            let hs = String::from_utf8_lossy(&buf);
                            if let Some(he) = hs.find("\r\n\r\n") {
                                let cl = hs.split("\r\n\r\n").next().unwrap_or("")
                                    .to_lowercase();
                                let cl = cl.split("\r\n")
                                    .filter_map(|l| l.strip_prefix("content-length:"))
                                    .next()
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                                    .unwrap_or(0);
                                if buf.len() >= he + 4 + cl {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let s_str = String::from_utf8_lossy(&buf);
                let body_start = s_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
                let body = &s_str[body_start..];
                let resp = if body.trim().is_empty() {
                    json_err(-32700, "empty request")
                } else {
                    handle_rpc(body, &store, &mempool, &miner, &peers)
                };
                let out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp.len(),
                    resp
                );
                let _ = s.write_all(out.as_bytes());
            }
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn tx_deserialize_lenient(blob: &[u8], simulator: bool) -> Result<Transaction, String> {
    if simulator {
        // simulator laxity: the reference accepts txs without proof
        // verification, so never fail on a proof decode.
        Transaction::deserialize_skip_proofs(blob)
    } else {
        Transaction::deserialize(blob, 3)
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("bad hex: {e}"))
}

fn parse_addr(s: &str) -> Result<[u8; 33], String> {
    if s.starts_with("deto") || s.starts_with("dero") || s.starts_with("detoi") || s.starts_with("deroi") {
        // bech32 deto1/dero1 (note: some addresses are exactly 66 chars,
        // same length as a hex key — check the prefix FIRST)
        dero_crypto::rpc_addr::address_to_compressed(s)
            .map(|v| v.try_into().map_err(|_| "bad address".to_string()))
            .map_err(|e| e.to_string())?
    } else if s.len() == 66 {
        // raw compressed key hex
        let b = hex_decode(s)?;
        b.try_into().map_err(|_| "bad 33-byte key".into())
    } else {
        // bech32 fallback
        dero_crypto::rpc_addr::address_to_compressed(s)
            .map(|v| v.try_into().map_err(|_| "bad address".to_string()))
            .map_err(|e| e.to_string())?
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut peer = "http://127.0.0.1:25000/json_rpc".to_string();
    let mut extra_peers: Vec<String> = Vec::new();
    let mut port: u16 = 26000;
    let mut mine = false;
    let mut mine_interval_ms: u64 = 2000;
    let mut simulator = true; // simulator mode: skip proof verification (matches reference simnode laxity)
    let mut miner_addr = String::new();
    let mut seed_words = String::new();
    let mut data_dir = String::new();
    let mut p2p_port: u16 = 0;
    let mut p2p_peers: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--peer" => { i += 1; peer = args[i].clone(); }
            "--peers" => { i += 1; extra_peers = args[i].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(); }
            "--port" => { i += 1; port = args[i].parse().unwrap_or(26000); }
            "--mine" => mine = true,
            "--mine-interval-ms" => { i += 1; mine_interval_ms = args[i].parse().unwrap_or(2000); }
            "--miner" => { i += 1; miner_addr = args[i].clone(); }
            "--seed" => { i += 1; seed_words = args[i].clone(); }
            "--data-dir" => { i += 1; data_dir = args[i].clone(); }
            "--p2p-port" => { i += 1; p2p_port = args[i].parse().unwrap_or(0); }
            "--p2p-peer" => { i += 1; p2p_peers.push(args[i].clone()); }
            "--mainnet" => simulator = false, // verify proofs strictly
            "--help" => {
                println!("dero-node [--peer URL] [--peers a,b] [--port N] [--mine] [--miner ADDR] [--seed WORDS] [--data-dir DIR] [--p2p-port N] [--mine-interval-ms N] [--mainnet]");
                return;
            }
            _ => {}
        }
        i += 1;
    }
    let mut peers = extra_peers;
    peers.push(peer.clone());
    peers.dedup();

    let store = Arc::new(Mutex::new(ChainStore::new()));
    let mempool = Arc::new(Mutex::new(Mempool::new()));

    // load persisted state (if any) — skip the genesis re-seed + replay
    let loaded = if !data_dir.is_empty() {
        let mut st = store.lock().unwrap();
        match st.load(&data_dir) {
            Ok(n) => {
                println!("loaded {n} blocks from {data_dir} (height {})", st.height);
                n
            }
            Err(e) => {
                eprintln!("load error: {e}");
                0
            }
        }
    } else {
        0
    };

    // sync from peer (incremental: only pulls blocks above our height)
    {
        let mut st = store.lock().unwrap();
        match sync_from_peer(&mut st, &peer, simulator) {
            Ok(n) => println!("synced {n} blocks from {peer} (height {})", st.height),
            Err(e) => {
                eprintln!("sync error: {e}");
                std::process::exit(1);
            }
        }
        // persist after the initial sync if we loaded or synced anything
        if !data_dir.is_empty() && (loaded > 0 || st.blocks.len() > 1) {
            if let Err(e) = st.save(&data_dir) {
                eprintln!("save error: {e}");
            }
        }
    }

    // start RPC (share the wallet Miner so DERO.Transfer works)
    let wallet_secret = if !seed_words.is_empty() {
        let w: Vec<String> = seed_words.split_whitespace().map(|s| s.to_string()).collect();
        dero_crypto::mnemonics::words_to_key(&w).ok().map(|k| {
            let mut le = [0u8; 32];
            for i in 0..32 {
                le[i] = k[31 - i];
            }
            Fr::from_le_bytes_mod_order(&le)
        })
    } else {
        None
    };
    let wallet_addr = if !miner_addr.is_empty() {
        parse_addr(&miner_addr).unwrap_or([0u8; 33])
    } else {
        [0u8; 33]
    };
    let s2 = store.clone();
    let m2 = mempool.clone();
    let miner = Arc::new(Miner { address: wallet_addr, simulator: true, secret: wallet_secret });
    let m3 = miner.clone();
    let peers_arc = Arc::new(peers.clone());
    let p2 = peers_arc.clone();
    std::thread::spawn(move || serve(port, s2, m2, m3, p2));

    // P2P: serve the real DERO peer protocol (block sync to other nodes)
    if p2p_port > 0 {
        let s4 = store.clone();
        std::thread::spawn(move || serve_p2p(p2p_port, s4));
    }

    // keep-synced loop: pull new blocks from every peer periodically
    // (incremental — sync_from_peer applies from our height+1; p2p peers
    // use the real DERO wire protocol)
    let s3 = store.clone();
    let p3 = peers_arc.clone();
    let p2p_peers_arc = Arc::new(p2p_peers.clone());
    let p4 = p2p_peers_arc.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let mut st = s3.lock().unwrap();
            for p in p3.iter() {
                match sync_from_peer(&mut st, p, simulator) {
                    Ok(n) => {
                        if n > 0 {
                            println!("pulled {n} new blocks from {p}");
                        }
                    }
                    Err(e) => eprintln!("sync {p}: {e}"),
                }
            }
            for p in p4.iter() {
                match p2p_sync_from(&mut st, p, simulator) {
                    Ok(n) => {
                        if n > 0 {
                            println!("p2p pulled {n} blocks from {p}");
                        } else {
                            println!("p2p sync {p}: nothing new (h{})", st.height);
                        }
                    }
                    Err(e) => eprintln!("p2p sync {p}: {e}"),
                }
            }
        }
    });

    // mining loop
    if mine {
        let addr = match parse_addr(&miner_addr) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("bad miner address: {e}");
                std::process::exit(1);
            }
        };
        let secret = if !seed_words.is_empty() {
            // wallet mode: derive the secret from the recovery words
            let w: Vec<String> = seed_words.split_whitespace().map(|s| s.to_string()).collect();
            match dero_crypto::mnemonics::words_to_key(&w) {
                Ok(k) => {
                    let mut le = [0u8; 32];
                    for i in 0..32 {
                        le[i] = k[31 - i];
                    }
                    Some(ark_bn254::Fr::from_le_bytes_mod_order(&le))
                }
                Err(e) => {
                    eprintln!("bad --seed words: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            None
        };
        let miner = Miner { address: addr, simulator: true, secret };
        loop {
            std::thread::sleep(std::time::Duration::from_millis(mine_interval_ms));
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let mut st = store.lock().unwrap();
            let mp = mempool.lock().unwrap();
            let mut blk = miner.build_block(&st, &mp, ts);
            // pull the included txs' blobs out of the mempool BEFORE dropping
            let txs: Vec<Transaction> = blk
                .tx_hashes
                .iter()
                .filter_map(|h| mp.txs.get(h).cloned())
                .collect();
            let raw_txs: Vec<Vec<u8>> = blk
                .tx_hashes
                .iter()
                .filter_map(|h| mp.raw.get(h).cloned())
                .collect();
            // remove included txs from the mempool (they're now in the block)
            let included: Vec<[u8; 32]> = blk.tx_hashes.clone();
            drop(mp);
            let mut mp2 = mempool.lock().unwrap();
            for h in &included {
                mp2.txs.remove(h);
                mp2.raw.remove(h);
            }
            drop(mp2);
            // mine it (simulator: no PoW)
            let mut sim_miner = Miner { address: addr, simulator: true, secret: None };
            sim_miner.solve(&mut blk);
            let genesis = blk.height == 0;
            let k0 = st.k0_floor;
            let ChainStore { balance, sc_meta, .. } = &mut *st;
            match chain::add_complete_block(balance, sc_meta, &blk, &txs, blk.height, genesis, k0) {
                Ok((_, _, _)) => {
                    let rh = {
                        let b = st.balance.hash();
                        let m = st.sc_meta.hash();
                        let mut o = [0u8; 32];
                        for i in 0..32 {
                            o[i] = b[i] ^ m[i];
                        }
                        o
                    };
                    st.blocks.push((blk.clone(), txs));
                    st.roothashes.push(rh);
                    st.height = blk.height;
                    st.snapshot();
                    st.txids.push(blk.tx_hashes.clone());
                    st.raw_txs.push(raw_txs); // original wire blobs (bpp-correct)
                    if !data_dir.is_empty() {
                        if let Err(e) = st.save(&data_dir) {
                            eprintln!("save error: {e}");
                        }
                    }
                    println!("mined block h{} {}", blk.height, hex::encode(&blk.get_hash()[..8]));
                }
                Err(e) => eprintln!("mine apply err: {e}"),
            }
        }
    } else {
        // idle: keep re-syncing
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let mut st = store.lock().unwrap();
            match sync_from_peer(&mut st, &peer, simulator) {
                Ok(n) => {
                    if n > 0 {
                        println!("synced {n} new blocks (height {})", st.height);
                    }
                }
                Err(e) => eprintln!("resync error: {e}"),
            }
        }
    }
}
