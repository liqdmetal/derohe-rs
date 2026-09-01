// SPDX-License-Identifier: BSD-3-Clause
//
//! Differential-test oracle binary: mirrors oracle/main.go's JSONL protocol so
//! harness/difftest.py can compare Go reference vs Rust implementation.
//!
//!   req:  {"id": <int>, "op": "<op>", "in": { ... }}
//!   resp: {"id": <int>, "ok": true, "out": { ... }}
//!         {"id": <int>, "ok": false, "err": "<message>"}

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use ark_bn254::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::fields::AdditiveGroup;
use ark_ff::PrimeField;
use serde_json::{json, Value};

use dero_crypto::bulletproof;
use dero_crypto::curve::{be32_to_bigint, decode_compressed, encode_compressed, encode_uncompressed};
use dero_crypto::elgamal::ElGamal;
use dero_crypto::fft;
use dero_crypto::fieldvector::{fr_from_be_bytes, fr_from_hex, fr_to_be_bytes, FieldVector};
use dero_crypto::hash_to_point;
use dero_crypto::innerproduct;
use dero_crypto::keccak;
use dero_crypto::pedersen::{self, point_to_hex};
use dero_crypto::pedersen::point_from_hex as ppoint_from_hex;
use dero_crypto::pointvector::PointVector;
use dero_crypto::polynomial::{self, Polynomial};

/// Parse a JSON array of 32-byte-hex strings into raw byte arrays.
fn hex32_list(hexes: &[String]) -> Vec<[u8; 32]> {
    hexes.iter().map(|h| {
        let b = hex::decode(h).expect("valid hex");
        assert_eq!(b.len(), 32, "must be 32 bytes");
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    }).collect()
}

/// Rebuild a realistic statement: C[i] = r*pk_i + delta_i*G, D = r*G, zero
/// encrypted balances (CLn = C, CRn = D) — mirrors Go realisticStatement.
fn realistic_statement(st: &mut bulletproof::Statement, w: &bulletproof::Witness, burn: u64) {
    let g = dero_crypto::hash_to_point::base_g();
    let n = st.publickeylist.len();
    let mut c = Vec::with_capacity(n);
    for i in 0..n {
        let delta: i128 = if i == w.index[0] {
            -(w.transfer_amount as i128 + st.fees as i128 + burn as i128)
        } else if i == w.index[1] {
            w.transfer_amount as i128
        } else {
            0
        };
        let mut db = [0u8; 32];
        db[24..32].copy_from_slice(&delta.unsigned_abs().to_be_bytes()[8..]);
        let sc = if delta < 0 { -fr_from_be_bytes(&db) } else { fr_from_be_bytes(&db) };
        let mut x = g.mul_bigint(sc.into_bigint());
        x += st.publickeylist[i].mul_bigint(be32_to_bigint(&fr_to_be_bytes(w.r)));
        c.push(x);
    }
    let d = g.mul_bigint(be32_to_bigint(&fr_to_be_bytes(w.r)));
    st.c = c.clone();
    st.d = d;
    st.cln = c;
    st.crn = vec![d; n];
}

/// Build a Statement + Witness from the request input (mirrors Go
/// statementFromIn: ring pairs CLn = C, CRn = D).
fn statement_from_in(inp: &serde_json::Map<String, Value>) -> Result<(bulletproof::Statement, bulletproof::Witness), String> {
    let pk = str_list(inp, "publickeylist")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
    let c = str_list(inp, "c")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
    let d = ppoint_from_hex(&s_key(inp, "d")?);
    let roothash: [u8; 32] = hex_decode(&s_key(inp, "roothash")?)?.try_into().map_err(|_| "roothash must be 32 bytes")?;
    let fees: u64 = s_key(inp, "fees")?.parse().map_err(|e| format!("fees: {}", e))?;
    // witness fields are optional (verify requests carry only the statement)
    let secret_key = match s_key(inp, "secretkey") { Ok(h) => fr_from_hex(&h), Err(_) => Fr::ZERO };
    let r = match s_key(inp, "r") { Ok(h) => fr_from_hex(&h), Err(_) => Fr::ZERO };
    let transfer: u64 = match s_key(inp, "transfer") { Ok(v) => v.parse().map_err(|e| format!("transfer: {}", e))?, Err(_) => 0 };
    let balance: u64 = match s_key(inp, "balance") { Ok(v) => v.parse().map_err(|e| format!("balance: {}", e))?, Err(_) => 0 };
    let idx: Vec<usize> = match inp.get("index").and_then(|v| v.as_array()) {
        Some(a) => a.iter().filter_map(|v| v.as_i64().map(|x| x as usize)).collect(),
        None => vec![0, 0],
    };
    let index = [idx[0], idx[1]];
    let st = bulletproof::Statement {
        publickeylist: pk.clone(),
        c: c.clone(),
        cln: c.clone(),
        crn: vec![d; pk.len()],
        d,
        roothash,
        fees,
        pointers: Vec::new(),
    };
    let w = bulletproof::Witness { secret_key, r, transfer_amount: transfer, balance, index };
    Ok((st, w))
}

fn s_key(inp: &serde_json::Map<String, Value>, k: &str) -> Result<String, String> {
    inp.get(k).and_then(|v| v.as_str()).map(|x| x.to_string()).ok_or_else(|| format!("missing key {}", k))
}

/// Shared persistent graviton trees across requests (single static).
static mut GRAV_TREES: Option<std::collections::HashMap<String, dero_crypto::graviton::Tree>> = None;
fn grav_tree_mut(name: &str) -> &'static mut dero_crypto::graviton::Tree {
    unsafe {
        let map = GRAV_TREES.get_or_insert_with(|| std::collections::HashMap::new());
        if !map.contains_key(name) {
            map.insert(name.to_string(), dero_crypto::graviton::Tree::new(name));
        }
        map.get_mut(name).unwrap()
    }
}

/// Parse an RFC3339 (Nano) timestamp into (unix_secs, nanos) — mirrors Go
/// time.Parse(time.RFC3339Nano) for the Z/offset forms the harness uses.
fn parse_rfc3339(s: &str) -> Result<(i64, u32), String> {
    let s = s.trim();
    let (date, rest) = s.split_at(10.min(s.len()));
    let rest = &rest[1..]; // skip 'T'
    let (time, zone) = rest.split_at(8.min(rest.len()));
    let year: i64 = date[0..4].parse().map_err(|_| "year")?;
    let month: i64 = date[5..7].parse().map_err(|_| "month")?;
    let day: i64 = date[8..10].parse().map_err(|_| "day")?;
    let hour: i64 = time[0..2].parse().map_err(|_| "hour")?;
    let minute: i64 = time[3..5].parse().map_err(|_| "minute")?;
    let second: i64 = time[6..8].parse().map_err(|_| "second")?;
    let mut frac_nanos: u32 = 0;
    let zone = if zone.starts_with('.') {
        let mut frac = String::new();
        for c in zone.chars().skip(1) {
            if c.is_ascii_digit() {
                frac.push(c);
            } else {
                break;
            }
        }
        while frac.len() < 9 {
            frac.push('0');
        }
        frac_nanos = frac[..9].parse().map_err(|_| "frac")?;
        &zone[zone.find(|c: char| c == 'Z' || c == '+' || c == '-').unwrap_or(0)..]
    } else {
        zone
    };
    // days since epoch (civil -> days, Howard Hinnant algorithm)
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let mut secs = days * 86400 + hour * 3600 + minute * 60 + second;
    let mut nanos = frac_nanos;
    if let Some(off) = zone.strip_prefix('+') {
        let h: i64 = off[..2].parse().map_err(|_| "off h")?;
        let m: i64 = off[3..5].parse().map_err(|_| "off m")?;
        secs -= h * 3600 + m * 60;
    } else if let Some(off) = zone.strip_prefix('-') {
        let h: i64 = off[..2].parse().map_err(|_| "off h")?;
        let m: i64 = off[3..5].parse().map_err(|_| "off m")?;
        secs += h * 3600 + m * 60;
    } else if zone == "Z" || zone.is_empty() {
        // UTC
    } else {
        return Err(format!("bad zone {}", zone));
    }
    // normalize nanos
    if nanos >= 1_000_000_000 {
        secs += (nanos / 1_000_000_000) as i64;
        nanos %= 1_000_000_000;
    }
    Ok((secs, nanos))
}

/// Build a Block from JSON — mirrors Go blockFromIn.
fn block_from_in(inp: &serde_json::Map<String, Value>) -> Result<dero_crypto::block::Block, String> {
    use dero_crypto::block::{Block, MiniBlock};
    let u64 = |k: &str| -> Result<u64, String> {
        s_key(inp, k)?.parse().map_err(|e| format!("{}: {}", k, e))
    };
    let hx32 = |k: &str| -> Result<[u8; 32], String> {
        let b = hex_decode(&s_key(inp, k)?)?;
        b.try_into().map_err(|_| format!("{} must be 32 bytes", k))
    };
    let hx32_list = |v: &Value, what: &str| -> Result<Vec<[u8; 32]>, String> {
        let arr = v.as_array().ok_or(format!("{} must be a list", what))?;
        let mut out = Vec::with_capacity(arr.len());
        for h in arr {
            let s = h.as_str().ok_or(format!("{} entry not string", what))?;
            let b = hex_decode(s)?;
            out.push(b.try_into().map_err(|_| format!("{} entry must be 32 bytes", what))?);
        }
        Ok(out)
    };
    let miner_tx = inp
        .get("miner_tx")
        .and_then(|v| v.as_object())
        .ok_or("missing miner_tx")?;
    let miner_tx = tx_from_in(miner_tx)?;

    let mut mini_blocks = Vec::new();
    if let Some(arr) = inp.get("miniblocks").and_then(|v| v.as_array()) {
        for mj in arr {
            let m = mj.as_object().ok_or("miniblock not object")?;
            let u8 = |k: &str| -> Result<u8, String> {
                m.get(k).and_then(|v| v.as_str()).unwrap_or("0").parse().map_err(|e| format!("{}: {}", k, e))
            };
            let uv = |k: &str| -> Result<u64, String> {
                m.get(k).and_then(|v| v.as_str()).unwrap_or("0").parse().map_err(|e| format!("{}: {}", k, e))
            };
            let mut past = [0u32; 2];
            if let Some(p) = m.get("past").and_then(|v| v.as_array()) {
                for (i, x) in p.iter().enumerate().take(2) {
                    past[i] = x.as_str().unwrap_or("0").parse().unwrap_or(0);
                }
            }
            let mut nonce = [0u32; 3];
            if let Some(n) = m.get("nonce").and_then(|v| v.as_array()) {
                for (i, x) in n.iter().enumerate().take(3) {
                    nonce[i] = x.as_str().unwrap_or("0").parse().unwrap_or(0);
                }
            }
            let keyhash = hex_decode(m.get("keyhash").and_then(|v| v.as_str()).ok_or("keyhash")?)?;
            let mut kh = [0u8; 32];
            kh.copy_from_slice(&keyhash);
            mini_blocks.push(MiniBlock {
                version: u8("version")?,
                high_diff: m.get("highdiff").and_then(|v| v.as_bool()) == Some(true),
                final_block: m.get("final").and_then(|v| v.as_bool()) == Some(true),
                past_count: u8("pastcount")?,
                timestamp: uv("timestamp")? as u16,
                height: uv("height")?,
                past,
                key_hash: kh,
                flags: uv("flags")? as u32,
                nonce,
            });
        }
    }
    Ok(Block {
        major_version: u64("major")?,
        minor_version: u64("minor")?,
        timestamp: u64("timestamp")?,
        height: u64("height")?,
        miner_tx,
        proof: hx32("proof")?,
        tips: inp.get("tips").map(|v| hx32_list(v, "tips")).transpose()?.unwrap_or_default(),
        mini_blocks,
        tx_hashes: inp
            .get("tx_hashes")
            .map(|v| hx32_list(v, "tx_hashes"))
            .transpose()?
            .unwrap_or_default(),
    })
}

/// Build a VALID tx exactly like Go buildValidTx (mirrors
/// walletapi/transaction_build.go): real encrypted balances + real proof.
fn build_valid_tx(inp: &serde_json::Map<String, Value>) -> Result<dero_crypto::transaction::Transaction, String> {
    use ark_ec::PrimeGroup;
    use ark_ff::PrimeField;
    use dero_crypto::bulletproof::{self, Statement, Witness};
    use dero_crypto::curve::decode_compressed;
    use dero_crypto::elgamal::ElGamal;
    use dero_crypto::hash_to_point::base_g;
    use dero_crypto::rpc_args::Arguments;
    use dero_crypto::transaction::{AssetPayload, Transaction, TX_NORMAL, PAYLOAD_LIMIT};

    let g = base_g();
    let pk_hex: Vec<String> = inp.get("publickeylist").and_then(|v| v.as_array())
        .ok_or("missing publickeylist")?
        .iter().map(|v| v.as_str().unwrap_or("").to_string()).collect();
    let ring: Vec<_> = pk_hex.iter().map(|h| decode_compressed(&hex::decode(h).unwrap()).unwrap()).collect();
    let n = ring.len();
    let sk = fr_from_hex(&s_key(inp, "secretkey")?);
    let r = fr_from_hex(&s_key(inp, "r")?);
    let value: u64 = s_key(inp, "value")?.parse().unwrap_or(0);
    let fees: u64 = s_key(inp, "fees")?.parse().unwrap_or(0);
    let burn: u64 = s_key(inp, "burn")?.parse().unwrap_or(0);
    let bal_hex: Vec<String> = inp.get("balances").and_then(|v| v.as_array())
        .ok_or("missing balances")?
        .iter().map(|v| v.as_str().unwrap_or("0").to_string()).collect();
    let balance: Vec<u64> = bal_hex.iter().map(|h| u64::from_str_radix(h, 16).unwrap_or(0)).collect();
    let eb_hex: Vec<String> = inp.get("eblind").and_then(|v| v.as_array())
        .ok_or("missing eblind")?
        .iter().map(|v| v.as_str().unwrap_or("0").to_string()).collect();
    let eblind: Vec<u64> = eb_hex.iter().map(|h| u64::from_str_radix(h, 16).unwrap_or(0)).collect();
    let rand = hex_decode(&s_key(inp, "rand")?)?;
    let roothash_b = hex_decode(&s_key(inp, "roothash")?)?;
    let mut roothash = [0u8; 32];
    roothash.copy_from_slice(&roothash_b);
    let scid_b = hex_decode(&s_key(inp, "scid")?)?;
    let mut scid = [0u8; 32];
    scid.copy_from_slice(&scid_b);
    // u = upoint * sender_secret (transaction_build.go:266) — NOT random:
    // verifier's A_u = upoint*s_sk + u*c_neg cancels only when u = upoint*sk.
    let mut uinput = b"DERO".to_vec();
    uinput.extend_from_slice(&roothash);
    uinput.extend_from_slice(&scid);
    uinput.extend_from_slice(b"0"); // scid_index strconv
    let upoint = dero_crypto::hash_to_point::hash_to_point(&dero_crypto::keccak::keccak256(&uinput));
    let u = upoint.mul_bigint(sk.into_bigint());

    let mut c = Vec::with_capacity(n);
    let mut cln = Vec::with_capacity(n);
    let mut crn = Vec::with_capacity(n);
    for i in 0..n {
        let delta: i128 = if i == 0 {
            -(value as i128 + fees as i128 + burn as i128)
        } else if i == 1 {
            value as i128
        } else {
            0
        };
        let mut db = [0u8; 32];
        db[24..32].copy_from_slice(&delta.unsigned_abs().to_be_bytes()[8..]);
        let dsc = if delta < 0 { -fr_from_be_bytes(&db) } else { fr_from_be_bytes(&db) };
        let mut x = g.mul_bigint(dsc.into_bigint());
        x += ring[i].mul_bigint(r.into_bigint());
        c.push(x);

        let bl = g.mul_bigint(ark_bn254::Fr::from(balance[i]).into_bigint());
        let ebl = ring[i].mul_bigint(ark_bn254::Fr::from(eblind[i]).into_bigint());
        let left = bl + ebl;
        let right = g.mul_bigint(ark_bn254::Fr::from(eblind[i]).into_bigint());
        let eg = ElGamal::new(left, right);
        cln.push(eg.left + c[i]);
        crn.push(eg.right + g.mul_bigint(r.into_bigint()));
    }
    let d = g.mul_bigint(r.into_bigint());

    let st = Statement {
        publickeylist: ring.clone(),
        c: c.clone(),
        cln: cln.clone(),
        crn: crn.clone(),
        d,
        roothash,
        fees,
        pointers: Vec::new(),
    };
    // note: Rust serialization derives bpp from the caller (serialize(3)); no
    // per-statement bpp field to set.
    let w = Witness {
        secret_key: sk,
        r,
        transfer_amount: value,
        balance: balance[0] - value - fees - burn, // REMAINING after transfer
        index: [0, 1],
    };

    let mut rpc_payload = vec![0u8; PAYLOAD_LIMIT];
    // sender position byte (like the wallet: witness_index[0])
    rpc_payload[0] = 0;
    // assemble the tx WITHOUT the proof first: the txid = keccak(header) must
    // be bound inside the proof, so compute it before generate_proof
    let mut tx = Transaction {
        version: 1,
        source_network: 0,
        dest_network: 0,
        tx_type: TX_NORMAL,
        value: 0,
        miner_address: [0u8; 33],
        c: [0u8; 32],
        s: [0u8; 32],
        height: 0,
        blid: [0u8; 32],
        scdata: Arguments::default(),
        payloads: vec![AssetPayload {
            scid,
            burn_value: burn,
            rpc_type: 0,
            rpc_payload: vec![0u8; PAYLOAD_LIMIT],
            statement: st.clone(),
            proof: None,
        }],
    };
    // blid + height passthrough (chain submission)
    if let Some(blid_s) = inp.get("blid").and_then(|v| v.as_str()) {
        if let Ok(bb) = hex::decode(blid_s) {
            if bb.len() == 32 {
                tx.blid.copy_from_slice(&bb);
            }
        }
    }
    if let Some(h_s) = inp.get("txheight").and_then(|v| v.as_str()) {
        if let Ok(hv) = h_s.parse::<u64>() {
            tx.height = hv;
        }
    }
    let tx_hash = tx.get_hash(3);
    let proof = bulletproof::generate_proof(&scid, 0, &tx.payloads[0].statement, &w, &u, &tx_hash, burn, &rand);
    tx.payloads[0].proof = Some(proof);
    Ok(tx)
}

/// Build a Transaction from JSON — mirrors Go txFromIn.
fn tx_from_in(inp: &serde_json::Map<String, Value>) -> Result<dero_crypto::transaction::Transaction, String> {
    use dero_crypto::rpc_args::{Argument, ArgValue, Arguments};
    use dero_crypto::transaction::{AssetPayload, Transaction, PAYLOAD_LIMIT};

    let uvar = |k: &str| -> Result<u64, String> {
        s_key(inp, k)?.parse().map_err(|e| format!("{}: {}", k, e))
    };
    let hx32 = |k: &str| -> Result<[u8; 32], String> {
        let b = hex_decode(&s_key(inp, k)?)?;
        b.try_into().map_err(|_| format!("{} must be 32 bytes", k))
    };

    let tx_type = uvar("txtype")?;
    let mut tx = Transaction {
        version: uvar("version")?,
        source_network: uvar("source_network")?,
        dest_network: uvar("dest_network")?,
        tx_type,
        value: 0,
        miner_address: [0u8; 33],
        c: [0u8; 32],
        s: [0u8; 32],
        height: 0,
        blid: [0u8; 32],
        scdata: Arguments::default(),
        payloads: Vec::new(),
    };
    use dero_crypto::transaction::{
        TX_BURN, TX_COINBASE, TX_NORMAL, TX_PREMINE, TX_REGISTRATION, TX_SC,
    };
    if tx_type == TX_PREMINE || tx_type == TX_SC {
        tx.value = uvar("value")?;
    }
    if tx_type == TX_PREMINE || tx_type == TX_COINBASE || tx_type == TX_REGISTRATION {
        let b = hex_decode(&s_key(inp, "miner_address")?)?;
        if b.len() != 33 {
            return Err("miner_address must be 33 bytes".into());
        }
        tx.miner_address.copy_from_slice(&b);
    }
    if tx_type == TX_REGISTRATION {
        tx.c = hx32("c")?;
        tx.s = hx32("s")?;
    }
    if tx_type == TX_BURN || tx_type == TX_NORMAL || tx_type == TX_SC {
        tx.height = uvar("height")?;
        tx.blid = hx32("blid")?;
        let pay_arr = inp.get("payloads").and_then(|v| v.as_array()).ok_or("missing payloads")?;
        for pj in pay_arr {
            let p = pj.as_object().ok_or("payload not object")?;
            let burn: u64 = p.get("burn").and_then(|v| v.as_str()).unwrap_or("0").parse().map_err(|e| format!("burn: {}", e))?;
            let scid_b = hex_decode(p.get("scid").and_then(|v| v.as_str()).ok_or("scid")?)?;
            let mut scid = [0u8; 32];
            scid.copy_from_slice(&scid_b);
            let rpc_type: u8 = p.get("rpctype").and_then(|v| v.as_str()).unwrap_or("0").parse().map_err(|e| format!("rpctype: {}", e))?;
            let rpc_payload = hex_decode(p.get("rpcpayload").and_then(|v| v.as_str()).ok_or("rpcpayload")?)?;
            if rpc_payload.len() != PAYLOAD_LIMIT {
                return Err(format!("rpcpayload: expected {} bytes, got {}", PAYLOAD_LIMIT, rpc_payload.len()));
            }
            let stmt_in = p.get("statement").and_then(|v| v.as_object()).ok_or("payload statement missing")?;
            let (mut st, w) = statement_from_in(stmt_in)?;
            realistic_statement(&mut st, &w, burn);
            let proof_b = hex_decode(p.get("proof").and_then(|v| v.as_str()).ok_or("proof")?)?;
            let m = st.publickeylist.len() / 2;
            let proof = bulletproof::deserialize(&proof_b, m).map_err(|e| format!("proof: {}", e))?;
            tx.payloads.push(AssetPayload {
                scid,
                burn_value: burn,
                rpc_type,
                rpc_payload,
                statement: st,
                proof: Some(proof),
            });
        }
    }
    if tx_type == TX_SC {
        let sc_arr = inp.get("scdata").and_then(|v| v.as_array()).ok_or("missing scdata")?;
        let mut args = Vec::new();
        for aj in sc_arr {
            let a = aj.as_object().ok_or("scdata arg not object")?;
            let name = a.get("name").and_then(|v| v.as_str()).ok_or("scdata name")?.to_string();
            let dtype = a.get("datatype").and_then(|v| v.as_str()).ok_or("scdata datatype")?.as_bytes()[0];
            let v = a.get("value").and_then(|v| v.as_str()).ok_or("scdata value")?.to_string();
            let value = match dtype {
                dero_crypto::rpc_args::DATA_STRING => ArgValue::Str(v),
                dero_crypto::rpc_args::DATA_INT64 => ArgValue::I64(v.parse().map_err(|e| format!("int64: {}", e))?),
                dero_crypto::rpc_args::DATA_UINT64 => ArgValue::U64(v.parse().map_err(|e| format!("uint64: {}", e))?),
                dero_crypto::rpc_args::DATA_FLOAT64 => ArgValue::F64(v.parse().map_err(|e| format!("float64: {}", e))?),
                dero_crypto::rpc_args::DATA_HASH => {
                    let b = hex_decode(&v)?;
                    ArgValue::Hash(b.try_into().map_err(|_| "hash must be 32 bytes")?)
                }
                dero_crypto::rpc_args::DATA_ADDRESS => {
                    let b = hex_decode(&v)?;
                    ArgValue::Addr(b.try_into().map_err(|_| "address must be 33 bytes")?)
                }
                dero_crypto::rpc_args::DATA_TIME => {
                    if v == "0" || v == "null" {
                        ArgValue::TimeZero
                    } else {
                        let (secs, nanos) = parse_rfc3339(&v)?;
                        ArgValue::Time { secs, nanos }
                    }
                }
                _ => return Err(format!("unknown scdata datatype {}", dtype as char)),
            };
            args.push(Argument { name, data_type: dtype, value });
        }
        tx.scdata = Arguments(args);
    }
    Ok(tx)
}

/// Deserialize a Go-serialized Proof (mirrors Go Proof.Deserialize).
/// m = number of CLnG entries (ring pairs count / 2).
fn deserialize_proof(b: &[u8], m: usize) -> Result<bulletproof::Proof, String> {
    let mut pos = 0usize;
    let mut take = |n: usize, label: &str| -> Result<&[u8], String> {
        if pos + n > b.len() {
            return Err(format!("proof buffer too short at {} ({})", label, pos));
        }
        let s = &b[pos..pos + n];
        pos += n;
        Ok(s)
    };
    let pt = |bytes: &[u8], label: &str| -> Result<G1Projective, String> {
        match decode_compressed(bytes) {
            Ok(p) => Ok(p),
            Err(e) => Err(format!("{}: {}", label, e)),
        }
    };
    let sc = |bytes: &[u8]| -> Result<[u8; 32], String> {
        let mut a = [0u8; 32];
        a.copy_from_slice(bytes);
        Ok(a)
    };
    let ba = pt(take(33, "BA")?, "BA")?;
    let bs = pt(take(33, "BS")?, "BS")?;
    let a = pt(take(33, "A")?, "A")?;
    let b = pt(take(33, "B")?, "B")?;
    let mut clng = Vec::with_capacity(m);
    let mut crng = Vec::with_capacity(m);
    let mut c_0g = Vec::with_capacity(m);
    let mut dg = Vec::with_capacity(m);
    let mut y_0g = Vec::with_capacity(m);
    let mut gg = Vec::with_capacity(m);
    let mut c_xg = Vec::with_capacity(m);
    let mut y_xg = Vec::with_capacity(m);
    for i in 0..m {
        clng.push(pt(take(33, "CLnG")?, &format!("CLnG[{}]", i))?);
        crng.push(pt(take(33, "CRnG")?, &format!("CRnG[{}]", i))?);
        c_0g.push(pt(take(33, "C_0G")?, &format!("C_0G[{}]", i))?);
        dg.push(pt(take(33, "DG")?, &format!("DG[{}]", i))?);
        y_0g.push(pt(take(33, "y_0G")?, &format!("y_0G[{}]", i))?);
        gg.push(pt(take(33, "gG")?, &format!("gG[{}]", i))?);
        c_xg.push(pt(take(33, "C_XG")?, &format!("C_XG[{}]", i))?);
        y_xg.push(pt(take(33, "y_XG")?, &format!("y_XG[{}]", i))?);
    }
    let u = pt(take(33, "u")?, "u")?;
    let mut f_raw = Vec::with_capacity(2 * m);
    for _ in 0..2 * m {
        f_raw.push(sc(take(32, "f")?)?);
    }
    let f = FieldVector::new(f_raw);
    let z_a = fr_from_be_bytes(take(32, "z_A")?);
    let t_1 = pt(take(33, "T_1")?, "T_1")?;
    let t_2 = pt(take(33, "T_2")?, "T_2")?;
    let that = fr_from_be_bytes(take(32, "that")?);
    let mu = fr_from_be_bytes(take(32, "mu")?);
    let c = fr_from_be_bytes(take(32, "c")?);
    let s_sk = fr_from_be_bytes(take(32, "s_sk")?);
    let s_r = fr_from_be_bytes(take(32, "s_r")?);
    let s_b = fr_from_be_bytes(take(32, "s_b")?);
    let s_tau = fr_from_be_bytes(take(32, "s_tau")?);
    // IP section: a(32) b(32) + 7 rounds of L(33) R(33)
    let ip_a = sc(take(32, "ip_a")?)?;
    let ip_b = sc(take(32, "ip_b")?)?;
    let mut ls = Vec::with_capacity(7);
    let mut rs = Vec::with_capacity(7);
    for i in 0..7 {
        ls.push(pt(take(33, "L")?, &format!("L[{}]", i))?);
        rs.push(pt(take(33, "R")?, &format!("R[{}]", i))?);
    }
    Ok(bulletproof::Proof {
        ba, bs, a, b, clng, crng, c_0g, dg, y_0g, gg, c_xg, y_xg, u,
        f, z_a, t_1, t_2, that, mu, c, s_sk, s_r, s_b, s_tau,
        ip: innerproduct::InnerProduct { a: ip_a, b: ip_b, ls, rs },
    })
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("bad hex: {}", e))
}

/// Read a JSON array of strings from the input object.
fn str_list(inp: &serde_json::Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    inp.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .ok_or_else(|| format!("missing array key {}", key))
}

fn point_from_hex(s: &str) -> Result<G1Projective, String> {
    let b = hex_decode(s)?;
    decode_compressed(&b)
}

fn eg_from_map(inp: &serde_json::Map<String, Value>, prefix: &str) -> Result<ElGamal, String> {
    let l = inp
        .get(&format!("{}left", prefix))
        .and_then(|v| v.as_str())
        .ok_or("missing left")?;
    let r = inp
        .get(&format!("{}right", prefix))
        .and_then(|v| v.as_str())
        .ok_or("missing right")?;
    Ok(ElGamal::new(point_from_hex(l)?, point_from_hex(r)?))
}

fn eg_out(e: &ElGamal) -> Value {
    json!({
        "left": hex::encode(encode_compressed(&e.left)),
        "right": hex::encode(encode_compressed(&e.right)),
    })
}

fn handle(id: i64, op: &str, raw: &Value) -> Value {
    let inp = match raw.as_object() {
        Some(o) => o,
        None => {
            return json!({"id": id, "ok": false, "err": "input must be an object"});
        }
    };
    let s = |k: &str| -> Result<String, String> {
        inp.get(k)
            .and_then(|v| v.as_str())
            .map(|x| x.to_string())
            .ok_or_else(|| format!("missing key {k}"))
    };
    // u64p: parse a required uint64 field in one line (condensed + typed error)
    let u64p = |k: &str| -> Result<u64, String> {
        inp.get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing key {k}"))?
            .parse::<u64>()
            .map_err(|_| format!("{k} not a uint64"))
    };
    // boolp: strict boolean — rejects anything but "true"/"false"
    let boolp = |k: &str| -> Result<bool, String> {
        match s(k)?.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!("{k} must be true/false, got {other:?}")),
        }
    };

    let result: Result<Value, String> = (|| {
        match op {
            "mnemonic_to_key" => {
                let words: Vec<String> = s("words")?
                    .split_whitespace()
                    .map(|w| w.to_string())
                    .collect();
                let key = dero_crypto::mnemonics::words_to_key(&words)?;
                Ok(json!({"seed": hex::encode(key)}))
            }
            "pubkey_from_seed" => {
                let seed = hex_decode(&s("seed")?)?;
                if seed.len() != 32 {
                    return Err("seed must be 32 bytes".into());
                }
                let mut sb = [0u8; 32];
                sb.copy_from_slice(&seed);
                // Go: GPoint.ScalarMult(Seed) where Seed = big.Int of the
                // seed BYTES (big-endian interpretation). Replicate exactly.
                let mut le = [0u8; 32];
                for i in 0..32 {
                    le[i] = sb[31 - i];
                }
                let fr = ark_bn254::Fr::from_le_bytes_mod_order(&le);
                let g = dero_crypto::hash_to_point::base_g();
                let pk = g.mul_bigint(fr.into_bigint());
                Ok(json!({"public": hex::encode(dero_crypto::curve::encode_compressed(&pk))}))
            }
            "wallet_build_tx" => {
                // build a NORMAL transfer with the Rust wallet builder.
                // Input: words, dest (bech32), amount, ring (bech32 ring
                // order), ring_balances (encrypted balance hex per member),
                // height, blid.
                let words = s("words")?;
                let words_vec: Vec<String> = words.split_whitespace().map(|w| w.to_string()).collect();
                let seed = dero_crypto::mnemonics::words_to_key(&words_vec)?;
                // sender secret = seed (big-endian scalar)
                let mut le = [0u8; 32];
                for i in 0..32 {
                    le[i] = seed[31 - i];
                }
                let secret = ark_bn254::Fr::from_le_bytes_mod_order(&le);

                let dest = s("dest")?;
                let amount: u64 = s("amount")?.parse().map_err(|e| format!("amount: {e}"))?;
                let height: u64 = s("height")?.parse().map_err(|e| format!("height: {e}"))?;
                let max_bits: usize = s("max_bits")?.parse().map_err(|e| format!("max_bits: {e}"))?;
                let blid_hex = s("blid")?;
                let mut blid = [0u8; 32];
                blid.copy_from_slice(&hex_decode(&blid_hex)?);
                let rh_hex = s("roothash")?;
                let mut roothash = [0u8; 32];
                roothash.copy_from_slice(&hex_decode(&rh_hex)?);
                let ring: Vec<String> = s("ring")?.split(',').map(|x| x.to_string()).collect();
                let ring_bal: Vec<String> = s("ring_balances")?.split(',').map(|x| x.to_string()).collect();
                let wi0: usize = s("wi0")?.parse().map_err(|e| format!("wi0: {e}"))?;
                let wi1: usize = s("wi1")?.parse().map_err(|e| format!("wi1: {e}"))?;
                let dest_key_hex = s("dest_key")?;
                if std::env::var("WALLET_DEBUG").is_ok() {
                    eprintln!("wallet_build_tx: wi0={wi0} wi1={wi1} ring={ring:?} ring_bal0={} ring_bal1={}", ring_bal.get(0).map(|x| &x[..8]).unwrap_or(""), ring_bal.get(1).map(|x| &x[..8]).unwrap_or(""));
                }
                // ring members: [self, receiver, anonset...] with balances
                // = emap (self, receiver, anonset...). The `ring` input is
                // the anonset bech32 addresses; self/dest keys are derived.
                let mut members: Vec<dero_crypto::tx_builder::RingMember> = Vec::new();
                let g = dero_crypto::hash_to_point::base_g();
                let self_pk = g.mul_bigint(secret.into_bigint());
                let self_comp = dero_crypto::curve::encode_compressed(&self_pk);
                // balance helper
                let parse_bal = |b: &str| -> Result<dero_crypto::elgamal::ElGamal, String> {
                    let bb = hex_decode(b)?;
                    dero_crypto::elgamal::ElGamal::deserialize(&bb)
                        .map_err(|e| format!("elgamal: {e}"))
                };
                // member 0 = self (sender) with emap[0]
                let sb = hex_decode(&ring_bal[0])?;
                let self_bal_decoded: u64 =
                    match inp.get("balance").and_then(|v| v.as_str()) {
                        Some(b) => b.parse().map_err(|e| format!("balance: {e}"))?,
                        None => 0,
                    };
                members.push(dero_crypto::tx_builder::RingMember {
                    public_key: self_comp,
                    balance: dero_crypto::elgamal::ElGamal::deserialize(&sb)
                        .map_err(|e| format!("self elgamal: {e}"))?,
                    balance_decoded: self_bal_decoded,
                });
                // member 1 = receiver (dest) with emap[1]
                let mut dk = [0u8; 33];
                let db = hex_decode(&dest_key_hex)?;
                dk.copy_from_slice(&db);
                let rb1 = hex_decode(&ring_bal[1])?;
                members.push(dero_crypto::tx_builder::RingMember {
                    public_key: dk,
                    balance: dero_crypto::elgamal::ElGamal::deserialize(&rb1)
                        .map_err(|e| format!("recv elgamal: {e}"))?,
                    balance_decoded: 0,
                });
                // members 2+ = anonset with emap[2:]
                let mut i = 2;
                for addr in &ring {
                    let comp = dero_crypto::rpc_addr::address_to_compressed(addr)
                        .map_err(|e| format!("addr: {e}"))?;
                    let mut a = [0u8; 33];
                    a.copy_from_slice(&comp);
                    let bal = parse_bal(&ring_bal[i])?;
                    members.push(dero_crypto::tx_builder::RingMember {
                        public_key: a,
                        balance: bal,
                    balance_decoded: 0,
                    });
                    i += 1;
                }
                if std::env::var("WALLET_DEBUG").is_ok() {
                    for (mi, m) in members.iter().enumerate() {
                        eprintln!("member[{mi}] pk={} bal.left={}", hex::encode(&m.public_key[..8]), hex::encode(&dero_crypto::curve::encode_compressed(&m.balance.left)[..8]));
                    }
                    eprintln!("wi0={wi0} wi1={wi1} dest={}", &dest_key_hex[..8]);
                }
                // ring order: Go's statement order — self must be at position
                // 0 (witness_index[0]) and receiver at 1. The ring input from
                // the harness is already Go's ring_order.
                let tx = dero_crypto::tx_builder::build_transaction(
                    &[dero_crypto::tx_builder::Transfer {
                        destination: dest.clone(),
                        amount,
                        burn: 0,
                        scid: [0u8; 32],
                        payload_rpc: Vec::new(),
                    }],
                    &[members],
                    wi0, wi1,
                    &blid,
                    height,
                    &dero_crypto::rpc_args::Arguments::default(),
                    &roothash,
                    max_bits,
                    0,  // fees placeholder
                    &secret,
                    &[0x5au8; 16384], // enough randomness for the proof draws (273 × 32)
                )?;
                // bpp is the STATEMENT's own (2 for wallet txs) — NOT
                // max_bits/8 (max_bits=9 → 1, which would corrupt the ring)
                let bpp = tx.payloads[0].statement.bpp();
                // debug: the builder's own r + shared key (for the differential)
                if std::env::var("WALLET_DEBUG").is_ok() {
                    let stmt = &tx.payloads[0].statement;
                    // also print the builder's ebalances[0].left via the witness
                    // switch recovery: publickeylist[0]'s balance is the one at
                    // position 0 — compute CLn[0] - C[0]
                    let c0 = stmt.c[0];
                    let cln0 = stmt.cln[0];
                    let implied = cln0 - c0;
                    eprintln!("DEBUG tx r={} c0={} cln0={} implied0={}",
                        hex::encode(&dero_crypto::wallet::fr_to_be32(
                            dero_crypto::wallet::calc_r(&roothash, &stmt.publickeylist, &secret))),
                        hex::encode(&dero_crypto::curve::encode_compressed(&c0))[..12].to_string(),
                        hex::encode(&dero_crypto::curve::encode_compressed(&cln0))[..12].to_string(),
                        hex::encode(&dero_crypto::curve::encode_compressed(&implied))[..12].to_string());
                }
                Ok(json!({"tx": hex::encode(tx.serialize(bpp))}))
            }
            "wallet_cln_debug" => {
                // rebuild the CLn/CRn from the same inputs the builder uses
                // and return them, so we can compare against Go's tx directly.
                let words = s("words")?;
                let words_vec: Vec<String> = words.split_whitespace().map(|w| w.to_string()).collect();
                let seed = dero_crypto::mnemonics::words_to_key(&words_vec)?;
                let mut le = [0u8; 32];
                for i in 0..32 {
                    le[i] = seed[31 - i];
                }
                let secret = ark_bn254::Fr::from_le_bytes_mod_order(&le);
                let max_bits: usize = s("max_bits")?.parse().map_err(|e| format!("max_bits: {e}"))?;
                let wi0: usize = s("wi0")?.parse().map_err(|e| format!("wi0: {e}"))?;
                let wi1: usize = s("wi1")?.parse().map_err(|e| format!("wi1: {e}"))?;
                let ring_bal: Vec<String> = s("ring_balances")?.split(',').map(|x| x.to_string()).collect();
                let dest_key_hex = s("dest_key")?;
                // build members like wallet_build_tx
                let g = dero_crypto::hash_to_point::base_g();
                let self_pk = g.mul_bigint(secret.into_bigint());
                let self_comp = dero_crypto::curve::encode_compressed(&self_pk);
                let parse_bal = |b: &str| -> Result<dero_crypto::elgamal::ElGamal, String> {
                    let bb = hex_decode(b)?;
                    dero_crypto::elgamal::ElGamal::deserialize(&bb)
                        .map_err(|e| format!("elgamal: {e}"))
                };
                let mut members: Vec<dero_crypto::tx_builder::RingMember> = Vec::new();
                let sb = hex_decode(&ring_bal[0])?;
                members.push(dero_crypto::tx_builder::RingMember {
                    public_key: self_comp,
                    balance: dero_crypto::elgamal::ElGamal::deserialize(&sb).map_err(|e| e)?,
                    balance_decoded: 0,
                });
                let mut dk = [0u8; 33];
                dk.copy_from_slice(&hex_decode(&dest_key_hex)?);
                let rb1 = hex_decode(&ring_bal[1])?;
                members.push(dero_crypto::tx_builder::RingMember {
                    public_key: dk,
                    balance: dero_crypto::elgamal::ElGamal::deserialize(&rb1).map_err(|e| e)?,
                    balance_decoded: 0,
                });
                let ring: Vec<String> = s("ring")?.split(',').map(|x| x.to_string()).collect();
                let mut i = 2;
                for addr in &ring {
                    let comp = dero_crypto::rpc_addr::address_to_compressed(addr).map_err(|e| e)?;
                    let mut a = [0u8; 33];
                    a.copy_from_slice(&comp);
                    members.push(dero_crypto::tx_builder::RingMember {
                        public_key: a,
                        balance: parse_bal(&ring_bal[i])?,
                    balance_decoded: 0,
                    });
                    i += 1;
                }
                // replicate the builder's publickeylist + ebalances
                let sender = g.mul_bigint(secret.into_bigint());
                let witness_index = [wi0, wi1];
                let receiver_comp = dero_crypto::curve::decode_compressed(&members[1].public_key)?;
                let mut anonset: Vec<&dero_crypto::tx_builder::RingMember> = members[2..].iter().collect();
                let mut publickeylist: Vec<ark_bn254::G1Projective> = Vec::new();
                let mut ebalances_list: Vec<dero_crypto::elgamal::ElGamal> = Vec::new();
                for k in 0..members.len() {
                    let (pk, bal) = if k == witness_index[0] {
                        (sender, members[0].balance.clone())
                    } else if k == witness_index[1] {
                        (receiver_comp, members[1].balance.clone())
                    } else {
                        let m = anonset.remove(0);
                        (dero_crypto::curve::decode_compressed(&m.public_key)?, m.balance.clone())
                    };
                    publickeylist.push(pk);
                    ebalances_list.push(bal);
                }
                // compute C (like the builder)
                let rh = hex_decode(&s("roothash")?)?;
                let mut roothash = [0u8; 32];
                roothash.copy_from_slice(&rh);
                let r = dero_crypto::wallet::calc_r(&roothash, &publickeylist, &secret);
                let amount: u64 = s("amount")?.parse().map_err(|e| format!("amount: {e}"))?;
                let bpp = (max_bits / 8) as u8;
                let mut c: Vec<ark_bn254::G1Projective> = Vec::new();
                for k in 0..publickeylist.len() {
                    let delta: i64 = if k == wi0 { -(amount as i64) } else if k == wi1 { amount as i64 } else { 0 };
                    let abs_delta = delta.unsigned_abs() as u64;
                    let mut gd = g.mul_bigint(ark_ff::BigInt::<4>::from(abs_delta));
                    if delta < 0 {
                        gd = -gd;
                    }
                    let pkr = publickeylist[k].mul_bigint(r.into_bigint());
                    c.push(gd + pkr);
                }
                let d = g.mul_bigint(r.into_bigint());
                let mut cln: Vec<ark_bn254::G1Projective> = Vec::new();
                let mut crn: Vec<ark_bn254::G1Projective> = Vec::new();
                for k in 0..publickeylist.len() {
                    cln.push(ebalances_list[k].left + c[k]);
                    crn.push(ebalances_list[k].right + d);
                }
                let mut cln_h: Vec<String> = Vec::new();
                let mut crn_h: Vec<String> = Vec::new();
                for k in 0..cln.len() {
                    cln_h.push(hex::encode(dero_crypto::curve::encode_compressed(&cln[k])));
                    crn_h.push(hex::encode(dero_crypto::curve::encode_compressed(&crn[k])));
                }
                Ok(json!({"cln": cln_h, "crn": crn_h, "r": hex::encode(dero_crypto::wallet::fr_to_be32(r))}))
            }
            "calc_r_debug" => {
                // compute r = ReducedHash(HashToPoint("DERO"||roothash||pubkeys) * secret)
                // for debugging the wallet tx differential
                let rh = hex_decode(&s("roothash")?)?;
                let mut roothash = [0u8; 32];
                roothash.copy_from_slice(&rh);
                let pubs: Vec<String> = s("pubkeys")?.split(',').map(|x| x.to_string()).collect();
                let mut pts = Vec::new();
                for h in &pubs {
                    let b = hex_decode(h)?;
                    pts.push(dero_crypto::curve::decode_compressed(&b)?);
                }
                let secret_hex = s("secret")?;
                let mut le = [0u8; 32];
                let sb = hex_decode(&secret_hex)?;
                for i in 0..32 {
                    le[i] = sb[31 - i];
                }
                let secret = ark_bn254::Fr::from_le_bytes_mod_order(&le);
                let r = dero_crypto::wallet::calc_r(&roothash, &pts, &secret);
                let mut out = [0u8; 32];
                let be = dero_crypto::wallet::fr_to_be32(r);
                out.copy_from_slice(&be);
                Ok(json!({"r": hex::encode(out)}))
            }
            "point_add_debug" => {
                // add two compressed points, return the compressed sum
                let a = dero_crypto::curve::decode_compressed(&hex_decode(&s("a")?)?)?;
                let b = dero_crypto::curve::decode_compressed(&hex_decode(&s("b")?)?)?;
                let s = a + b;
                Ok(json!({"point": hex::encode(dero_crypto::curve::encode_compressed(&s))}))
            }
            "point_sub_debug" => {
                // subtract two compressed points (a - b)
                let a = dero_crypto::curve::decode_compressed(&hex_decode(&s("a")?)?)?;
                let b = dero_crypto::curve::decode_compressed(&hex_decode(&s("b")?)?)?;
                let s = a - b;
                Ok(json!({"point": hex::encode(dero_crypto::curve::encode_compressed(&s))}))
            }
            "point_mul_debug" => {
                // compute G*scalar and return the compressed point (for
                // verifying D = G*r against the tx)
                let scalar = hex_decode(&s("scalar")?)?;
                let mut le = [0u8; 32];
                for i in 0..32 {
                    le[i] = scalar[31 - i];
                }
                let fr = ark_bn254::Fr::from_le_bytes_mod_order(&le);
                let g = dero_crypto::hash_to_point::base_g();
                let pt = g.mul_bigint(fr.into_bigint());
                Ok(json!({"point": hex::encode(dero_crypto::curve::encode_compressed(&pt))}))
            }
            "shared_key_debug" => {
                // compute the RPCPayload encryption key:
                // shared = keccak(compressed(receiver_pk * r))
                // key    = keccak(shared || receiver_comp)
                let r_hex = s("r")?;
                let r = dero_crypto::curve::be32_to_bigint(&hex_decode(&r_hex)?);
                let r_fr = ark_bn254::Fr::from_le_bytes_mod_order(&{
                    let mut le = [0u8; 32];
                    let be = hex_decode(&r_hex)?;
                    for i in 0..32 {
                        le[i] = be[31 - i];
                    }
                    le
                });
                let recv_hex = s("receiver")?;
                let recv = dero_crypto::curve::decode_compressed(&hex_decode(&recv_hex)?)?;
                let shared_pt = recv.mul_bigint(r_fr.into_bigint());
                let shared_comp = dero_crypto::curve::encode_compressed(&shared_pt);
                let shared_key = dero_crypto::keccak::keccak256(&shared_comp);
                let enc_key = dero_crypto::keccak::keccak256(&[&shared_key[..], &hex_decode(&recv_hex)?[..]].concat());
                Ok(json!({"shared_point": hex::encode(shared_comp),
                          "shared_key": hex::encode(shared_key),
                          "enc_key": hex::encode(enc_key)}))
            }
            "xchacha_keystream" => {
                // return the XChaCha20 keystream (zero 24-byte nonce) for a key
                let key = hex_decode(&s("key")?)?;
                let mut k = [0u8; 32];
                k.copy_from_slice(&key);
                let mut ks = vec![0u8; 145];
                dero_crypto::wallet::encrypt_decrypt_user_data(&k, &mut ks);
                Ok(json!({"keystream": hex::encode(ks)}))
            }
            "proof_verify_tx" => {
                // self-verify a full tx blob's proofs (expand-free: the
                // builder's in-memory statement is complete)
                let b = hex_decode(&s("blob")?)?;
                let tx = dero_crypto::transaction::Transaction::deserialize(&b, 2)
                    .or_else(|_| dero_crypto::transaction::Transaction::deserialize(&b, 3))
                    .map_err(|e| format!("deserialize: {e}"))?;
                let bpp = tx.payloads.first().map(|p| p.statement.bpp()).unwrap_or(2);
                let txid = tx.get_hash(bpp);
                let mut scid_map: std::collections::HashMap<[u8; 32], i32> = std::collections::HashMap::new();
                let mut all_ok = true;
                for (i, p) in tx.payloads.iter().enumerate() {
                    let index = *scid_map.get(&p.scid).unwrap_or(&0);
                    if let Some(proof) = &p.proof {
                        let ok = dero_crypto::bulletproof::verify(
                            &p.scid, index, &p.statement, proof, &txid, p.burn_value,
                        );
                        if !ok {
                            all_ok = false;
                        }
                    }
                    scid_map.insert(p.scid, index + 1);
                }
                Ok(json!({"ok": all_ok}))
            }
            "wallet_scan_tx" => {
                // classify one tx for our wallet (wallet_state scan)
                let b = hex_decode(&s("blob")?)?;
                let tx = dero_crypto::transaction::Transaction::deserialize(&b, 2)
                    .or_else(|_| dero_crypto::transaction::Transaction::deserialize(&b, 3))
                    .map_err(|e| format!("deserialize: {e}"))?;
                let words: Vec<String> = s("words")?
                    .split_whitespace()
                    .map(|w| w.to_string())
                    .collect();
                let seed = dero_crypto::mnemonics::words_to_key(&words)
                    .map_err(|e| format!("words: {e}"))?;
                let mut le = [0u8; 32];
                for i in 0..32 {
                    le[i] = seed[31 - i];
                }
                let secret = ark_bn254::Fr::from_le_bytes_mod_order(&le);
                let sender = dero_crypto::hash_to_point::base_g()
                    .mul_bigint(secret.into_bigint());
                let our_key = dero_crypto::curve::encode_compressed(&sender);
                let height: u64 = s("height")?.parse().map_err(|e| format!("height: {e}"))?;
                let topoheight: u64 = s("topoheight")?.parse().map_err(|e| format!("topo: {e}"))?;
                // optional expanded ring: JSON [[bech32, ...], ...] per payload
                // (the node serves it; the wire statement has only pointers)
                let ring_json = inp
                    .get("ring")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mut ring_per_payload: Vec<Vec<String>> = Vec::new();
                if !ring_json.is_empty() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ring_json) {
                        if let Some(arr) = v.as_array() {
                            for pl in arr {
                                let mut members = Vec::new();
                                if let Some(ms) = pl.as_array() {
                                    for m in ms {
                                        if let Some(a) = m.as_str() {
                                            members.push(a.to_string());
                                        }
                                    }
                                }
                                ring_per_payload.push(members);
                            }
                        }
                    }
                }
                let mut entries_out: Vec<serde_json::Value> = Vec::new();
                for (ti, p) in tx.payloads.iter().enumerate() {
                    let mut st = p.statement.clone();
                    // expand publickeylist from the served ring addresses
                    if st.publickeylist.is_empty() {
                        if let Some(members) = ring_per_payload.get(ti) {
                            let mut pks = Vec::new();
                            for a in members {
                                if let Ok(comp) = dero_crypto::rpc_addr::address_to_compressed(a) {
                                    if let Ok(pk) = dero_crypto::curve::decode_compressed(&comp) {
                                        pks.push(pk);
                                    }
                                }
                            }
                            st.publickeylist = pks;
                        }
                    }
                    // our position
                    let pos = match dero_crypto::wallet_state::find_our_pos(&st, &our_key) {
                        Some(x) => x,
                        None => continue,
                    };
                    // prev balance: fetch from the node? we can't here — the
                    // oracle has no RPC. Instead: decode the CURRENT balance
                    // from the statement CLn/CRn (cln[pos] - C[pos] = ebal.left
                    // at tx time) and compute the change directly.
                    // changed = cln[pos] - C[pos] + C[pos]... simpler: the
                    // change IS the delta we can read from C[pos]/D against
                    // our secret: value = decode(cln[pos] - C[pos]... )
                    // We reconstruct: prev_ebal.left = cln[pos] - C[pos],
                    // prev_ebal.right = crn[pos] - D.
                    let prev_left = st.cln.get(pos).copied().unwrap_or_default()
                        - st.c.get(pos).copied().unwrap_or_default();
                    let prev_right = st.crn.get(pos).copied().unwrap_or_default()
                        - st.d;
                    let prev_ebal = dero_crypto::elgamal::ElGamal::new(prev_left, prev_right);
                    // changed = prev + changes
                    let changes = dero_crypto::elgamal::ElGamal::new(st.c[pos], st.d);
                    let changed_e = prev_ebal.add(&changes);
                    let prev_v = dero_crypto::wallet::decode_balance(&prev_ebal, &secret, 44).unwrap_or(0);
                    let changed_v = dero_crypto::wallet::decode_balance(&changed_e, &secret, 44).unwrap_or(0);
                    let fees = st.fees;
                    let (incoming, status, amount) = if prev_v == changed_v {
                        (false, 0, 0) // ring member
                    } else if prev_v > changed_v {
                        (false, 1, prev_v - changed_v - fees) // out
                    } else {
                        (true, 0, changed_v - prev_v) // in
                    };
                    entries_out.push(serde_json::json!({
                        "txid": hex::encode(tx.get_hash(st.bpp())),
                        "height": height,
                        "topoheight": topoheight,
                        "txpos": ti,
                        "pos": pos,
                        "amount": amount,
                        "fees": fees,
                        "incoming": incoming,
                        "status": status,
                        "prev": prev_v,
                        "changed": changed_v,
                    }));
                }
                Ok(json!({"entries": entries_out}))
            }
            "balance_decode" => {
                // decode an ElGamal balance with the wallet secret (BSGS)
                let bal_b = hex_decode(&s("balance")?)?;
                let ebal = dero_crypto::elgamal::ElGamal::deserialize(&bal_b)
                    .map_err(|e| format!("elgamal: {e}"))?;
                let words: Vec<String> = s("words")?
                    .split_whitespace()
                    .map(|w| w.to_string())
                    .collect();
                let seed = dero_crypto::mnemonics::words_to_key(&words)
                    .map_err(|e| format!("words: {e}"))?;
                let mut le = [0u8; 32];
                for i in 0..32 {
                    le[i] = seed[31 - i];
                }
                let secret = ark_bn254::Fr::from_le_bytes_mod_order(&le);
                match dero_crypto::wallet::decode_balance(&ebal, &secret, 44) {
                    Ok(b) => Ok(json!({"balance": b})),
                    Err(e) => Err(e),
                }
            }
            "keccak256" | "keccak512" => {
                let data = hex_decode(&s("data")?)?;
                let out = if op == "keccak256" {
                    hex::encode(keccak::keccak256(&data))
                } else {
                    hex::encode(keccak::keccak512(&data))
                };
                Ok(json!({"hash": out}))
            }
            "base_g" => {
                let p = hash_to_point::base_g();
                Ok(json!({"point": hex::encode(encode_compressed(&p))}))
            }
            "pedersen_gparams" => {
                let p = pedersen::generator_params(128);
                let mut gh = keccak::keccak256(b""); // Go: hash starts at keccak256(empty)
                let mut hh = keccak::keccak256(b"");
                for i in 0..128 {
                    gh = keccak::keccak256(&[gh.as_slice(), &encode_compressed(&p.gs[i])].concat());
                    hh = keccak::keccak256(&[hh.as_slice(), &encode_compressed(&p.hs[i])].concat());
                }
                Ok(json!({
                    "g": point_to_hex(&p.g),
                    "h": point_to_hex(&p.h),
                    "gsum": point_to_hex(&p.gsum),
                    "gs_hash": hex::encode(gh),
                    "hs_hash": hex::encode(hh),
                    "gs0": point_to_hex(&p.gs[0]),
                    "gs1": point_to_hex(&p.gs[1]),
                    "hs0": point_to_hex(&p.hs[0]),
                    "hs1": point_to_hex(&p.hs[1]),
                }))
            }
            "pedersen_commit_scalar" => {
                let value: [u8; 32] = hex_decode(&s("value")?)?.try_into().map_err(|_| "value must be 32 bytes")?;
                let r: [u8; 32] = hex_decode(&s("randomness")?)?.try_into().map_err(|_| "randomness must be 32 bytes")?;
                let p = pedersen::generator_params(128);
                let point = pedersen::pedersen_commit_scalar(&p, &value, &r);
                Ok(json!({"point": point_to_hex(&point)}))
            }
            "pedersen_commit" => {
                let gv = FieldVector::from_hex(&str_list(inp, "gvalues")?);
                let hv = FieldVector::from_hex(&str_list(inp, "hvalues")?);
                let r: [u8; 32] = hex_decode(&s("randomness")?)?.try_into().map_err(|_| "randomness must be 32 bytes")?;
                let p = pedersen::generator_params(128);
                let point = pedersen::pedersen_commit(&p, &gv, &hv, &r);
                Ok(json!({"point": point_to_hex(&point)}))
            }
            "fieldvector_add" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                let b = FieldVector::from_hex(&str_list(inp, "b")?);
                Ok(json!({"c": a.add(&b).to_hex()}))
            }
            "fieldvector_hadamard" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                let b = FieldVector::from_hex(&str_list(inp, "b")?);
                Ok(json!({"c": a.hadamard(&b).to_hex()}))
            }
            "fieldvector_innerproduct" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                let b = FieldVector::from_hex(&str_list(inp, "b")?);
                Ok(json!({"scalar": hex::encode(fr_to_be_bytes(a.inner_product(&b)))}))
            }
            "fieldvector_times" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                let m = fr_from_hex(&s("scalar")?);
                Ok(json!({"c": a.times(m).to_hex()}))
            }
            "fieldvector_negate" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                Ok(json!({"c": a.negate().to_hex()}))
            }
            "fieldvector_flip" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                Ok(json!({"c": a.flip().to_hex()}))
            }
            "fieldvector_extract" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                let parity = s("parity")? == "1";
                Ok(json!({"c": a.extract(parity).to_hex()}))
            }
            "fieldvector_concat" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                let b = FieldVector::from_hex(&str_list(inp, "b")?);
                Ok(json!({"c": a.concat(&b).to_hex()}))
            }
            "fieldvector_sum" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                Ok(json!({"scalar": hex::encode(fr_to_be_bytes(a.sum()))}))
            }
            "pointvector_multexp" => {
                let pts = str_list(inp, "points")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
                let exps = FieldVector::from_hex(&str_list(inp, "exps")?);
                let point = pedersen::multi_exp(&pts, &exps);
                Ok(json!({"point": point_to_hex(&point)}))
            }
            "fft_fieldvector" => {
                let a = FieldVector::from_hex(&str_list(inp, "a")?);
                let inv = s("inverse")? == "1";
                Ok(json!({"c": fft::fft_fieldvector(&a, inv).to_hex()}))
            }
            "fft_generatorvector" => {
                let pts = str_list(inp, "points")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
                let inv = s("inverse")? == "1";
                let pv = PointVector::new(pts);
                let res = fft::fft_generatorvector(&pv, inv);
                Ok(json!({"points": res.0.iter().map(point_to_hex).collect::<Vec<_>>()}))
            }
            "convolution" => {
                let exps = FieldVector::from_hex(&str_list(inp, "exps")?);
                let pts = str_list(inp, "points")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
                let pv = PointVector::new(pts);
                let res = fft::convolution(&exps, &pv);
                Ok(json!({"points": res.0.iter().map(point_to_hex).collect::<Vec<_>>()}))
            }
            "polynomial_mul" => {
                let a = hex32_list(&str_list(inp, "a")?);
                let b = hex32_list(&str_list(inp, "b")?);
                let prod = Polynomial::new(Some(a)).mul(&Polynomial::new(Some(b)));
                Ok(json!({"c": prod.coefficients.iter().map(hex::encode).collect::<Vec<_>>()}))
            }
            "recursive_polynomials" => {
                let a = hex32_list(&str_list(inp, "a")?);
                let b = hex32_list(&str_list(inp, "b")?);
                let a_fr = a.iter().map(|x| fr_from_be_bytes(x)).collect::<Vec<_>>();
                let b_fr = b.iter().map(|x| fr_from_be_bytes(x)).collect::<Vec<_>>();
                let list = polynomial::recursive_polynomials(&Polynomial::new(None), &a_fr, &b_fr);
                let out: Vec<Vec<String>> = list.iter()
                    .map(|p| p.coefficients.iter().map(hex::encode).collect())
                    .collect();
                Ok(json!({"list": out}))
            }
            "reducedhash" => {
                let data = hex_decode(&s("data")?)?;
                Ok(json!({"scalar": hex::encode(fr_to_be_bytes(innerproduct::reduced_hash(&data)))}))
            }
            "ip_generate" => {
                let as_ = FieldVector::from_hex(&str_list(inp, "as")?);
                let bs = FieldVector::from_hex(&str_list(inp, "bs")?);
                if as_.length() != bs.length() {
                    return Err("as/bs length mismatch".into());
                }
                let salt: [u8; 32] = hex_decode(&s("salt")?)?.try_into().map_err(|_| "salt must be 32 bytes")?;
                let params = pedersen::generator_params(128);
                let p = innerproduct::honest_p(&params, &as_, &bs);
                let ip = innerproduct::generate(&params, &p, &as_, &bs, &salt);
                let verified = innerproduct::verify(&ip, &params.hs, &params.h, &p, &salt, &params);
                let proof = innerproduct::serialize(&ip);
                let n = 1usize << ip.ls.len();
                Ok(json!({
                    "proof": hex::encode(proof),
                    "p": point_to_hex(&p),
                    "verified": verified,
                    "a": hex::encode(ip.a),
                    "b": hex::encode(ip.b),
                    "ls": ip.ls.iter().map(point_to_hex).collect::<Vec<_>>(),
                    "rs": ip.rs.iter().map(point_to_hex).collect::<Vec<_>>(),
                    "hs": params.hs[..n].iter().map(point_to_hex).collect::<Vec<_>>(),
                }))
            }
            "ip_verify" => {
                let a: [u8; 32] = hex_decode(&s("a")?)?.try_into().map_err(|_| "a must be 32 bytes")?;
                let b: [u8; 32] = hex_decode(&s("b")?)?.try_into().map_err(|_| "b must be 32 bytes")?;
                let salt: [u8; 32] = hex_decode(&s("salt")?)?.try_into().map_err(|_| "salt must be 32 bytes")?;
                let p = ppoint_from_hex(&s("p")?);
                let ls = str_list(inp, "ls")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
                let rs = str_list(inp, "rs")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
                let hs = str_list(inp, "hs")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
                let params = pedersen::generator_params(128);
                let ip = innerproduct::InnerProduct { a, b, ls, rs };
                let verified = innerproduct::verify(&ip, &hs, &params.h, &p, &salt, &params);
                Ok(json!({"verified": verified}))
            }
            "proof_generate" => {
                let mut st = statement_from_in(inp)?;
                let burn: u64 = s("burn")?.parse().map_err(|e| format!("burn: {}", e))?;
                realistic_statement(&mut st.0, &st.1, burn);
                let rand = hex_decode(&s("rand")?)?;
                let scid: [u8; 32] = hex_decode(&s("scid")?)?.try_into().map_err(|_| "scid must be 32 bytes")?;
                let scid_index: i32 = s("scid_index")?.parse().map_err(|e| format!("scid_index: {}", e))?;
                let txid: [u8; 32] = hex_decode(&s("txid")?)?.try_into().map_err(|_| "txid must be 32 bytes")?;
                let u = ppoint_from_hex(&s("u")?);
                let proof = bulletproof::generate_proof(&scid, scid_index, &st.0, &st.1, &u, &txid, burn, &rand);
                let ser = bulletproof::serialize(&proof);
                let self_ok = bulletproof::verify(&scid, scid_index, &st.0, &proof, &txid, burn);
                Ok(json!({
                    "proof": hex::encode(ser),
                    "nonce": hex::encode(bulletproof::nonce(&proof)),
                    "parity": bulletproof::parity(&proof),
                    "self_verified": self_ok,
                }))
            }
            "proof_verify" => {
                // corrupted statements can make decode_compressed fail
                // ("not a square mod P") — map to a clean REJECT, matching
                // the Go reference's panic->reject mapping.
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<serde_json::Value, String> {
                    let mut st = statement_from_in(inp)?;
                    let burn: u64 = s("burn")?.parse().map_err(|e| format!("burn: {}", e))?;
                    // when the full statement (cln/crn/c/d) is supplied, use it
                    // verbatim (valid-tx accept testing)
                    let has_cln = inp.contains_key("cln");
                    if has_cln {
                        let plist = |k: &str| -> Result<Vec<G1Projective>, String> {
                            let arr = inp.get(k).and_then(|v| v.as_array()).ok_or(format!("missing {}", k))?;
                            arr.iter().map(|v| {
                                let h = v.as_str().ok_or("hex")?;
                                let b = hex::decode(h).map_err(|e| e.to_string())?;
                                decode_compressed(&b)
                            }).collect()
                        };
                        st.0.cln = plist("cln")?;
                        st.0.crn = plist("crn")?;
                        st.0.c = plist("c")?;
                        st.0.d = {
                            let b = hex::decode(&s("d")?).map_err(|e| e.to_string())?;
                            decode_compressed(&b)?
                        };
                    } else {
                        realistic_statement(&mut st.0, &st.1, burn);
                    }
                    let proof_b = hex_decode(&s("proof")?)?;
                    let scid: [u8; 32] = hex_decode(&s("scid")?)?.try_into().map_err(|_| "scid must be 32 bytes")?;
                    let scid_index: i32 = s("scid_index")?.parse().map_err(|e| format!("scid_index: {}", e))?;
                    let txid: [u8; 32] = hex_decode(&s("txid")?)?.try_into().map_err(|_| "txid must be 32 bytes")?;
                    // deserialize: parse the proof struct from the byte stream
                    let proof = deserialize_proof(&proof_b, st.0.publickeylist.len() / 2)?;
                    let verified = bulletproof::verify(&scid, scid_index, &st.0, &proof, &txid, burn);
                    Ok(json!({"verified": verified}))
                }));
                match res {
                    Ok(Ok(v)) => Ok(v),
                    _ => Ok(json!({"verified": false})),
                }
            }
            "noncebalance_marshal" => {
                let nh: u64 = s("nonceheight")?.parse().map_err(|e| format!("nonceheight: {}", e))?;
                let bal_b = hex_decode(&s("balance")?)?;
                let bal = dero_crypto::elgamal::ElGamal::deserialize(&bal_b)?;
                let nb = dero_crypto::balance_serdes::NonceBalance { nonce_height: nh, balance: bal };
                Ok(json!({"bytes": hex::encode(nb.serialize())}))
            }
            "noncebalance_unmarshal" => {
                let b = hex_decode(&s("bytes")?)?;
                let nb = dero_crypto::balance_serdes::NonceBalance::deserialize(&b)?;
                Ok(json!({
                    "nonceheight": nb.nonce_height,
                    "balance": hex::encode(nb.balance.serialize()),
                }))
            }
            "noncebalance_unmarshal_nonce" => {
                let b = hex_decode(&s("bytes")?)?;
                let nh = dero_crypto::balance_serdes::NonceBalance::parse_nonce(&b)?;
                Ok(json!({"nonceheight": nh}))
            }
            "tx_serialize" => {
                let tx = tx_from_in(inp)?;
                // Reject unknown tx types gracefully (matches Go's behavior)
                let valid = matches!(tx.tx_type, 0..=5);
                if !valid {
                    return Err(format!("unknown transaction type {}", tx.tx_type));
                }
                // Version must be 1 (only supported version on mainnet)
                if tx.version != 1 {
                    return Err(format!("transaction version {} not supported", tx.version));
                }
                let ser = tx.serialize(3);
                let header = tx.serialize_header(3);
                let core = tx.serialize_core_statement(3);
                let hash = tx.get_hash(3);
                Ok(json!({
                    "bytes": hex::encode(ser),
                    "header": hex::encode(header),
                    "core": hex::encode(core),
                    "hash": hex::encode(hash),
                }))
            }
            "tx_deserialize" => {
                let b = hex_decode(&s("bytes")?)?;
                let tx = dero_crypto::transaction::Transaction::deserialize(&b, 3)?;
                let payload_scids: Vec<String> = tx
                    .payloads
                    .iter()
                    .map(|p| hex::encode(&p.scid))
                    .collect();
                // serialize with the statement's OWN bpp (wallet txs use 2)
                let sbpp = tx
                    .payloads
                    .first()
                    .map(|p| p.statement.bpp())
                    .unwrap_or(3);
                Ok(json!({
                    "bytes": hex::encode(tx.serialize(sbpp)),
                    "hash": hex::encode(tx.get_hash(sbpp)),
                    "payload_scids": payload_scids,
                    "txtype": tx.tx_type,
                }))
            }
            "block_serialize" => {
                let bl = block_from_in(inp)?;
                let ser = bl.serialize(false);
                let ser_skip = bl.serialize(true);
                let hash = bl.get_hash();
                let hash_skip = bl.get_hash_skip_last_mini_block();
                let tips_hash = bl.get_tips_hash();
                let txs_hash = bl.get_txs_hash();
                Ok(json!({
                    "bytes": hex::encode(ser),
                    "bytes_skip_last": hex::encode(ser_skip),
                    "hash": hex::encode(hash),
                    "hash_skip_last": hex::encode(hash_skip),
                    "tips_hash": hex::encode(tips_hash),
                    "txs_hash": hex::encode(txs_hash),
                }))
            }
            "block_deserialize" => {
                let b = hex_decode(&s("bytes")?)?;
                let bl = dero_crypto::block::Block::deserialize(&b)?;
                let mut miner_stmts = Vec::new();
                for p in &bl.miner_tx.payloads {
                    let st = &p.statement;
                    miner_stmts.push(serde_json::json!({
                        "roothash": hex::encode(st.roothash),
                        "fees": st.fees.to_string(),
                        "ring": st.pointers.len() / 3,
                    }));
                }
                Ok(json!({
                    "bytes": hex::encode(bl.serialize(false)),
                    "hash": hex::encode(bl.get_hash()),
                    "miner_tx_hash": hex::encode(bl.miner_tx.get_hash(3)),
                    "miner_statements": miner_stmts,
                }))
            }
            "chain_block_apply" => {
                // apply a REAL block blob: ALL txs (balance moves) then the
                // miner tx (rewards) — the exact Add_Complete_Block order.
                // Returns the new balance-tree root.
                use dero_crypto::chain;
                use dero_crypto::elgamal::ElGamal;
                use dero_crypto::hash_to_point::base_g;
                let b = hex_decode(&s("blob")?)?;
                let bl = dero_crypto::block::Block::deserialize(&b)?;
                let genesis = s_key(inp, "genesis").map(|v| v == "true").unwrap_or(false);
                let height: u64 = s_key(inp, "height").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let bt = grav_tree_mut("B");
                if !genesis {
                    // ensure the miner is registered (zero balance) so the
                    // reward add works; real chain has it from an earlier tx
                    if bt.get(&bl.miner_tx.miner_address.to_vec()).is_none() {
                        if let Ok(pk) = dero_crypto::curve::decode_compressed(&bl.miner_tx.miner_address) {
                            let zb = ElGamal::new(pk, base_g());
                            let nb = dero_crypto::balance_serdes::NonceBalance { nonce_height: 0, balance: zb };
                            bt.put(&bl.miner_tx.miner_address, &nb.serialize());
                        }
                    }
                }
                // 1) the block's non-coinbase txs (balance moves + fees)
                // the block blob's txs are NOT embedded — the block header
                // only hashes them. The harness passes tx blobs separately.
                // SC txs also run process_transaction_sc (SC_META + SCID
                // data tree writes) — the SC_META root joins the XOR.
                let mut fees = 0u64;
                let mt = grav_tree_mut("M"); // persistent SC_META tree
                if let Some(txblobs) = inp.get("txs").and_then(|v| v.as_array()) {
                    for tb in txblobs {
                        let hexb = tb.as_str().ok_or("tx hex")?;
                        let raw = hex_decode(hexb)?;
                        let tx = dero_crypto::transaction::Transaction::deserialize(&raw, 3)?;
                        fees += chain::process_transaction(&mut std::collections::HashMap::new(), &tx, bt, height, true);
                        if tx.tx_type == dero_crypto::transaction::TX_SC {
                            // process_transaction_sc: install/call + SC_META
                            // + SCID data tree writes
                            let mut cache = std::collections::HashMap::new();
                            let mut ss = dero_crypto::sc::Snapshot { trees: std::collections::HashMap::new() };
                            let blid = bl.get_hash();
                            let r = chain::process_transaction_sc(
                                &mut cache, &mut ss, bt, mt, height, height, 0,
                                &blid, &tx, Some(0), // K0 floor: active from height 0 in simulator
                            );
                            if let Err(e) = &r {
                                eprintln!("SC apply err at h{}: {}", height, e);
                            }
                            // expose the SCID data-tree hash for the harness
                            let txid = tx.get_hash(tx.payloads.first().map(|p| p.statement.bpp()).unwrap_or(3));
                            if let Some(dt) = cache.get(&txid) {
                                eprintln!("SC data tree hash: {}", hex::encode(dt.hash()));
                                eprintln!("SC data tree dump: {}", hex::encode(dt.debug_dump()));
                            }
                        }
                    }
                }
                chain::process_miner_transaction(
                    &bl.miner_tx.miner_address, bl.miner_tx.value,
                    &bl.mini_blocks, genesis, bt, fees, height,
                );
                Ok(json!({"hash": hex::encode(bt.hash()), "meta_hash": hex::encode(mt.hash())}))
            }
            "tx_build_valid" => {
                let tx = build_valid_tx(inp)?;
                let ser = tx.serialize(3);
                let hash = tx.get_hash(3);
                let p = tx.payloads[0].proof.as_ref().unwrap();
                let st = &tx.payloads[0].statement;
                let accepted = bulletproof::verify(&tx.payloads[0].scid, 0, st, p, &hash, tx.payloads[0].burn_value);
                let c_hex: Vec<String> = st.c.iter().map(|x| hex::encode(encode_compressed(x))).collect();
                let cln_hex: Vec<String> = st.cln.iter().map(|x| hex::encode(encode_compressed(x))).collect();
                let crn_hex: Vec<String> = st.crn.iter().map(|x| hex::encode(encode_compressed(x))).collect();
                Ok(json!({
                    "bytes": hex::encode(ser),
                    "hash": hex::encode(hash),
                    "proof": hex::encode(bulletproof::serialize(p)),
                    "accepted": accepted,
                    "c": c_hex, "cln": cln_hex, "crn": crn_hex,
                    "d": hex::encode(encode_compressed(&st.d)),
                    "roothash": hex::encode(st.roothash),
                    "fees": st.fees.to_string(),
                }))
            }
            "block_miniblock_serialize" => {
                let m = inp;
                let kh_b = hex_decode(&s_key(m, "keyhash")?)?;
                let mut kh = [0u8; 32];
                kh[..kh_b.len().min(32)].copy_from_slice(&kh_b);
                let past = [
                    s_key(m, "past0")?.parse().unwrap_or(0),
                    s_key(m, "past1")?.parse().unwrap_or(0),
                ];
                let nonce = [
                    s_key(m, "nonce0")?.parse().unwrap_or(0),
                    s_key(m, "nonce1")?.parse().unwrap_or(0),
                    s_key(m, "nonce2")?.parse().unwrap_or(0),
                ];
                let mbl = dero_crypto::block::MiniBlock {
                    version: s_key(m, "version")?.parse::<u8>().map_err(|e| e.to_string())?,
                    high_diff: m.get("highdiff").and_then(|v| v.as_bool()) == Some(true),
                    final_block: m.get("final").and_then(|v| v.as_bool()) == Some(true),
                    past_count: s_key(m, "pastcount")?.parse::<u8>().map_err(|e| e.to_string())?,
                    timestamp: s_key(m, "timestamp")?.parse().unwrap_or(0),
                    height: s_key(m, "height")?.parse().unwrap_or(0),
                    past,
                    key_hash: kh,
                    flags: s_key(m, "flags")?.parse().unwrap_or(0),
                    nonce,
                };
                Ok(json!({"bytes": hex::encode(mbl.serialize())}))
            }
            "pow32" => {
                let b = hex_decode(&s("bytes")?)?;
                let h = dero_crypto::astrobwt::pow32(&b);
                Ok(json!({"hash": hex::encode(h)}))
            }
            "pow_v3" => {
                let b = hex_decode(&s("bytes")?)?;
                let h = dero_crypto::astrobwt_v3::astrobwt_v3(&b);
                Ok(json!({"hash": hex::encode(h)}))
            }
            "pow_v3_debug" => {
                let b = hex_decode(&s("bytes")?)?;
                let d = dero_crypto::astrobwt_v3::astrobwt_v3_debug(&b);
                Ok(json!({
                    "hash": hex::encode(d.hash),
                    "sha_key": hex::encode(d.sha_key),
                    "after_salsa": hex::encode(d.after_salsa),
                    "after_rc4": hex::encode(d.after_rc4),
                    "lhash": d.lhash.to_string(),
                    "prev_lhash": d.prev_lhash.to_string(),
                    "iter1_switch": d.iter1_switch.to_string(),
                    "iter1_op": d.iter1_op.to_string(),
                    "iter1_pos1": d.iter1_pos1.to_string(),
                    "iter1_pos2": d.iter1_pos2.to_string(),
                    "iter1_state": hex::encode(d.iter1_state),
                    "iter1_lhash": d.iter1_lhash.to_string(),
                    "iter1_prev": d.iter1_prev.to_string(),
                    "tries": d.tries.to_string(),
                    "data_len": d.data_len.to_string(),
                    "final_state": hex::encode(d.final_state),
                    "data_prefix": hex::encode(d.data_prefix),
                    "data_prefix2": hex::encode(d.data_prefix2),
                    "data_prefix200": hex::encode(d.data_prefix200),
                    "data_full": hex::encode(&d.data_full),
                    "op_log": d.op_log.iter().map(|x| format!("{:02x}", x)).collect::<String>(),
                    "pos_log": d.pos_log.iter().map(|x| format!("{:08x}", x)).collect::<String>(),
                    "switch_log": d.switch_log.iter().map(|x| format!("{:016x}", x)).collect::<String>(),
                }))
            }
            "check_pow" => {
                let h = hex_decode(&s("hash")?)?;
                let difficulty: num_bigint::BigUint = s("difficulty")?.parse().map_err(|e: num_bigint::ParseBigIntError| e.to_string())?;
                // HashToBig: reverse to big-endian, then compare to 2^256/diff
                let mut rev = [0u8; 32];
                for i in 0..16 {
                    rev[i] = h[31 - i];
                    rev[31 - i] = h[i];
                }
                let pow = num_bigint::BigUint::from_bytes_be(&rev);
                let target = (num_bigint::BigUint::from(1u8) << 256usize) / &difficulty;
                Ok(json!({"valid": pow <= target}))
            }
            "dvm_parse" => {
                use dero_crypto::dvm;
                let code = s("code")?;
                match dvm::parse_smart_contract(&code) {
                    Ok(sc) => {
                        let mut names: Vec<String> = sc.functions.keys().cloned().collect();
                        names.sort();
                        let mut out = serde_json::Map::new();
                        out.insert("ok".into(), json!(true));
                        out.insert("functions".into(), json!(names));
                        for name in &names {
                            let f = &sc.functions[name];
                            let paramtypes: Vec<String> = f.params.iter().map(|p| format!("{}", p.vtype as u8)).collect();
                            let lines: Vec<String> = f.line_numbers.iter().map(|ln| format!("{}:{}", ln, f.lines[ln].join(" "))).collect();
                            out.insert(format!("fn_{}", name), json!({
                                "ret": (f.return_value.vtype as u8).to_string(),
                                "params": paramtypes,
                                "lines": lines,
                            }));
                        }
                        Ok(serde_json::Value::Object(out))
                    }
                    Err(e) => Ok(json!({"ok": false, "err": e})),
                }
            }
            "dvm_uses_signer" => {
                use dero_crypto::dvm;
                let code = s("code")?;
                match dvm::parse_smart_contract(&code) {
                    Ok(sc) => {
                        // Mirror of Go dvm.ContractUsesSigner (K0 Fix B2):
                        // true iff any function line token equals "SIGNER"
                        // (case-insensitive, matching DVM dispatch).
                        let mut uses_signer = false;
                        for f in sc.functions.values() {
                            for line in f.lines.values() {
                                for tok in line {
                                    if tok.eq_ignore_ascii_case("SIGNER") {
                                        uses_signer = true;
                                        break;
                                    }
                                }
                                if uses_signer { break; }
                            }
                            if uses_signer { break; }
                        }
                        Ok(json!({"ok": true, "uses_signer": uses_signer}))
                    }
                    Err(e) => Ok(json!({"ok": false, "err": e})),
                }
            }
            "dvm_rnd" => {
                use dero_crypto::dvm::{initialize_rnd, Rnd};
                let hx = |k: &str| -> [u8; 32] {
                    let mut h = [0u8; 32];
                    if let Ok(v) = hex::decode(s_key(inp, k).unwrap_or_default()) {
                        let n = v.len().min(32);
                        h[..n].copy_from_slice(&v[..n]);
                    }
                    h
                };
                let scid = hx("scid");
                let blid = hx("blid");
                let txid = hx("txid");
                let mut r: Rnd = initialize_rnd(&scid, &blid, &txid);
                let n: u64 = s_key(inp, "n").unwrap_or_else(|_| "5".into()).parse().unwrap_or(5);
                let mut vals = Vec::new();
                for _ in 0..n {
                    vals.push(r.random().to_string());
                }
                Ok(json!({"vals": vals}))
            }
            "dvm_run" => {
                use dero_crypto::dvm::*;
                let code = s("code")?;
                let sc = parse_smart_contract(&code).map_err(|e| e)?;
                let hx = |k: &str| -> [u8; 32] {
                    let mut h = [0u8; 32];
                    if let Ok(v) = hex::decode(s_key(inp, k).unwrap_or_default()) {
                        let n = v.len().min(32);
                        h[..n].copy_from_slice(&v[..n]);
                    }
                    h
                };
                let scid = hx("scid");
                let blid = hx("blid");
                let txid = hx("txid");
                let entrypoint = s("entrypoint")?;
                let height: u64 = s_key(inp, "height").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let ts: u64 = s_key(inp, "timestamp").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let signer = s_key(inp, "signer").unwrap_or_default();
                let mut params: HashMap<String, String> = HashMap::new();
                if let Some(v) = inp.get("params") {
                    if let Ok(pm) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&v.to_string()) {
                        for (k, val) in pm {
                            params.insert(k, val.as_str().unwrap_or("").to_string());
                        }
                    }
                }
                let mut state = SharedState {
                    scid_zero: [0; 32],
                    scid_self: scid,
                    gas_compute_used: 0,
                    gas_compute_limit: 10000000,
                    gas_compute_check: true,
                    gas_store_used: 0,
                    gas_store_limit: 0,
                    gas_store_check: false,
                    chain_inputs: BlockchainInput {
                        scid, blid, txid, signer,
                        bl_height: height, bl_topoheight: 0, bl_timestamp: ts,
                    },
                    assets: HashMap::new(),
                    assets_transfer: HashMap::new(),
                    ram_store: HashMap::new(),
                    monitor_recursion: 0,
                    monitor_lines_interpreted: 0,
                    monitor_ops: 0,
                    store: Box::new(TXStorage { scid, raw_keys: HashMap::new(), transfers: HashMap::new(), state: None }),
                    rnd: initialize_rnd(&scid, &blid, &txid),
                };
                state.store.state = Some(state.clone());
                let result = run_smart_contract(&sc, &entrypoint, &mut state, &params);
                let mut out = serde_json::Map::new();
                out.insert("gas_compute".into(), json!(state.gas_compute_used.to_string()));
                out.insert("gas_storage".into(), json!(state.gas_store_used.to_string()));
                out.insert("ops".into(), json!(state.monitor_ops.to_string()));
                out.insert("lines".into(), json!(state.monitor_lines_interpreted.to_string()));
                match result {
                    Ok(v) => {
                        out.insert("ok".into(), json!(true));
                        // Go oracle emits ret_type as a string (fmt.Sprintf) —
                        // match it so the differential diff is byte-exact.
                        out.insert("ret_type".into(), json!((v.vtype as u8).to_string()));
                        match v.vtype {
                            Vtype::Uint64 => { out.insert("ret".into(), json!(v.value_uint64.to_string())); }
                            Vtype::String => { out.insert("ret".into(), json!(v.value_string)); }
                            _ => {}
                        }
                        let mut keys: Vec<&String> = state.store.raw_keys.keys().collect();
                        keys.sort();
                        let mut kv = serde_json::Map::new();
                        for k in keys {
                            kv.insert(k.clone(), json!(hex::encode(&state.store.raw_keys[k])));
                        }
                        out.insert("store".into(), json!(kv));
                        // Emit external transfers (SEND_*) accumulated during
                        // execution, mirroring the Go oracle's dvm_run output so
                        // difftest can compare send_external byte-for-byte.
                        let mut senders: Vec<[u8; 32]> = state.store.transfers.keys().cloned().collect();
                        senders.sort();
                        let mut transfers = Vec::new();
                        for sender in senders {
                            if let Some(list) = state.store.transfers.get(&sender) {
                                for t in list {
                                    transfers.push(json!({
                                        "sender": hex::encode(sender),
                                        "asset": hex::encode(t.asset),
                                        "address": hex::encode(t.address),
                                        "amount": t.amount.to_string(),
                                    }));
                                }
                            }
                        }
                        out.insert("transfers".into(), json!(transfers));
                    }
                    Err(e) => {
                        out.insert("ok".into(), json!(false));
                        out.insert("err".into(), json!(e));
                    }
                }
                Ok(serde_json::Value::Object(out))
            }
            "bech32_raw" => {
                use dero_crypto::rpc_addr;
                let addr = s("address")?;
                match rpc_addr::address_to_compressed(&addr) {
                    Ok(pk) => Ok(json!({"raw": hex::encode(pk)})),
                    Err(_) => Ok(json!({"raw": ""})),
                }
            }
            "bech32_string" => {
                use dero_crypto::rpc_addr;
                let raw = hex_decode(&s("raw")?)?;
                // Go's NewAddressFromKeys requires the key to be a valid
                // on-curve compressed point; invalid keys yield "".
                let valid = raw.len() == 33 && dero_crypto::curve::decode_compressed(&raw).is_ok();
                if !valid {
                    return Ok(json!({"addr": ""}));
                }
                match rpc_addr::compressed_to_address(&raw) {
                    Ok(addr) => Ok(json!({"addr": addr})),
                    Err(_) => Ok(json!({"addr": ""})),
                }
            }
            "bech32_valid" => {
                use dero_crypto::rpc_addr;
                let addr = s("address")?;
                let valid = rpc_addr::address_to_compressed(&addr).is_ok();
                Ok(json!({"valid": valid}))
            }
            "hexdecode" => {
                let hx = s("hex")?;
                match hex::decode(&hx) {
                    Ok(b) => Ok(json!({"out": hex::encode(b)})),
                    Err(e) => Err(e.to_string()),
                }
            }
            "tx_extract_verify" => {
                let blob = hex_decode(&s("blob")?)?;
                let bl = dero_crypto::block::Block::deserialize(&blob)?;
                let tx = bl.miner_tx;
                let txid = tx.get_hash(3);
                let mut out = serde_json::Map::new();
                out.insert("txid".into(), json!(hex::encode(txid)));
                for p in &tx.payloads {
                    let st = &p.statement;
                    let pk: Vec<String> = st.publickeylist.iter().map(|k| hex::encode(encode_compressed(k))).collect();
                    let cln: Vec<String> = st.cln.iter().map(|k| hex::encode(encode_compressed(k))).collect();
                    let crn: Vec<String> = st.crn.iter().map(|k| hex::encode(encode_compressed(k))).collect();
                    let c: Vec<String> = st.c.iter().map(|k| hex::encode(encode_compressed(k))).collect();
                    // run the full verify on the real statement (whatever it
                    // carries after deserialize — same as the Go side)
                    let proof = p.proof.clone().expect("miner tx proof present");
                    let verified = bulletproof::verify(&p.scid, 0, st, &proof, &txid, p.burn_value);
                    let proof_ser = bulletproof::serialize(&proof);
                    out.insert("payload".into(), json!({
                        "scid": hex::encode(p.scid),
                        "scid_index": 0,
                        "burn": p.burn_value.to_string(),
                        "publickeys": pk,
                        "cln": cln,
                        "crn": crn,
                        "c": c,
                        "d": hex::encode(encode_compressed(&st.d)),
                        "roothash": hex::encode(st.roothash),
                        "fees": st.fees.to_string(),
                        "proof": hex::encode(proof_ser),
                        "verified": verified,
                    }));
                }
                Ok(serde_json::Value::Object(out))
            }
            "grav_put" | "grav_delete" | "grav_get" => {
                use dero_crypto::graviton::Tree;
                let tname = s("tree")?;
                let tree = grav_tree_mut(&tname);
                let key = hex_decode(&s("key")?)?;
                match op {
                    "grav_put" => {
                        let val = hex_decode(&s("value")?)?;
                        tree.put(&key, &val);
                        Ok(json!({"hash": hex::encode(tree.hash())}))
                    }
                    "grav_delete" => {
                        tree.delete(&key);
                        Ok(json!({"hash": hex::encode(tree.hash())}))
                    }
                    _ => {
                        match tree.get(&key) {
                            Some(v) => Ok(json!({"found": true, "value": hex::encode(v)})),
                            None => Ok(json!({"found": false})),
                        }
                    }
                }
            }
            "grav_register" => {
                use dero_crypto::elgamal::ElGamal;
                use dero_crypto::hash_to_point::base_g;
                let tname = s("tree")?;
                let addr = hex_decode(&s("address")?)?;
                let pk = dero_crypto::curve::decode_compressed(&addr).map_err(|e| e)?;
                // Go ConstructElGamal(pk, ElGamal_BASE_G): Left = pk, Right = G
                let zerobalance = ElGamal::new(pk, base_g());
                let nb = dero_crypto::balance_serdes::NonceBalance { nonce_height: 0, balance: zerobalance };
                grav_tree_mut(&tname).put(&addr, &nb.serialize());
                Ok(json!({"registered": true}))
            }
            "chain_reward" => {
                use dero_crypto::chain;
                let height: u64 = s("height")?.parse().map_err(|_| "bad height".to_string())?;
                Ok(json!({"reward": chain::calc_block_reward(height).to_string()}))
            }
            "k0_floor" => {
                // K0 Fix B1 floor rule (mirror of Go
                // blockchain.K0RingSizeFloorReject): from the fork height
                // onward, NORMAL(3)/BURN(4) txs with ringsize < 4 are
                // rejected. All other tx types are exempt. The fork height
                // is passed explicitly so the differential vectors can
                // sweep the boundary.
                use dero_crypto::transaction::*;
                let height = u64p("height")?;
                let txtype = u64p("txtype")?;
                let ringsize = u64p("ringsize")?;
                let floor = u64p("floor")?;
                if txtype > TX_SC {
                    return Err(format!("unknown txtype {txtype}"));
                }
                if ringsize == 0 || ringsize > 128 {
                    return Err(format!("ringsize {ringsize} out of range 1..=128"));
                }
                let reject = height >= floor
                    && ringsize < 4
                    && (txtype == TX_NORMAL || txtype == TX_BURN);
                Ok(json!({"reject": reject}))
            }
            "b2_reject" => {
                // K0 Fix B2 decision rules (mirror of Go
                // OracleK0B2InstallReject / OracleK0B2CallReject):
                //   install: ring-2 SC_INSTALL of a no-SIGNER contract,
                //            post-fork -> reject
                //   call:    ring-2 SC_CALL to a NoSigner-bit contract -> reject
                let height = u64p("height")?;
                let ringsize = u64p("ringsize")?;
                let floor = u64p("floor")?;
                if ringsize == 0 || ringsize > 128 {
                    return Err(format!("ringsize {ringsize} out of range 1..=128"));
                }
                if floor == 0 {
                    return Err("floor must be > 0".into());
                }
                let uses_signer = boolp("uses_signer")?;
                let no_signer = boolp("no_signer")?;
                let install_reject = height >= floor && ringsize == 2 && !uses_signer;
                let call_reject = ringsize == 2 && no_signer;
                Ok(json!({"install_reject": install_reject, "call_reject": call_reject}))
            }
            "chain_miner_tx" => {
                use dero_crypto::chain;
                use dero_crypto::graviton::Tree;
                let genesis = s_key(inp, "genesis").map(|v| v == "true").unwrap_or(false);
                let fees: u64 = s_key(inp, "fees").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let height: u64 = s_key(inp, "height").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let miner_addr = hex_decode(&s("miner_address")?)?;
                let mut addr = [0u8; 33];
                addr.copy_from_slice(&miner_addr);
                let miner_value: u64 = s_key(inp, "miner_value").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                // persistent "B" tree (shared with grav_register/grav_put)
                let bt = grav_tree_mut("B");
                // miniblocks from JSON
                let mut mbls = Vec::new();
                if let Some(v) = inp.get("miniblocks") {
                    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&v.to_string()) {
                        for m in arr {
                            let kh = hex::decode(m.get("KeyHash").and_then(|x| x.as_str()).unwrap_or("")).unwrap_or_default();
                            let mut kh32 = [0u8; 32];
                            let n = kh.len().min(32);
                            kh32[..n].copy_from_slice(&kh[..n]);
                            mbls.push(dero_crypto::block::MiniBlock {
                                version: m.get("Version").and_then(|x| x.as_u64()).unwrap_or(1) as u8,
                                high_diff: false,
                                final_block: m.get("Final").and_then(|x| x.as_bool()).unwrap_or(false),
                                past_count: m.get("PastCount").and_then(|x| x.as_u64()).unwrap_or(1) as u8,
                                timestamp: m.get("Timestamp").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
                                height: m.get("Height").and_then(|x| x.as_u64()).unwrap_or(0),
                                past: [m.get("Past").and_then(|x| x.as_array()).and_then(|a| a.get(0)).and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                                       m.get("Past").and_then(|x| x.as_array()).and_then(|a| a.get(1)).and_then(|x| x.as_u64()).unwrap_or(0) as u32],
                                key_hash: kh32,
                                flags: m.get("Flags").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                                nonce: [0, 0, 0],
                            });
                        }
                    }
                }
                chain::process_miner_transaction(&addr, miner_value, &mbls, genesis, bt, fees, height);
                Ok(json!({"hash": hex::encode(bt.hash())}))
            }
            "chain_tx" => {
                use dero_crypto::chain;
                use dero_crypto::elgamal::ElGamal;
                use dero_crypto::hash_to_point::base_g;
                let height: u64 = s_key(inp, "height").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let bt = grav_tree_mut("B");
                // register ring keys from JSON
                if let Some(payv) = inp.get("payloads") {
                    if let Ok(pays) = serde_json::from_str::<Vec<serde_json::Value>>(&payv.to_string()) {
                        for pj in pays {
                            let stmt = &pj["statement"];
                            if let Some(pks) = stmt.get("publickeylist").and_then(|x| x.as_array()) {
                                for pksv in pks {
                                    let pk_b = hex_decode(&pksv.as_str().unwrap_or(""))?;
                                    if bt.get(&pk_b).is_none() {
                                        let pk = dero_crypto::curve::decode_compressed(&pk_b).map_err(|e| e)?;
                                        let zb = ElGamal::new(pk, base_g());
                                        let nb = dero_crypto::balance_serdes::NonceBalance { nonce_height: 0, balance: zb };
                                        bt.put(&pk_b, &nb.serialize());
                                    }
                                }
                            }
                        }
                    }
                }
                let mut tx = tx_from_in(inp)?;
                // roundtrip to fill pointers
                let ser = tx.serialize(3);
                tx = dero_crypto::transaction::Transaction::deserialize(&ser, 3)?;
                let fees = chain::process_transaction(
                    &mut std::collections::HashMap::new(), &tx, bt, height, false,
                );
                Ok(json!({"hash": hex::encode(bt.hash()), "fees": fees.to_string()}))
            }
            "chain_block" => {
                use dero_crypto::chain;
                use dero_crypto::elgamal::ElGamal;
                use dero_crypto::hash_to_point::base_g;
                let height: u64 = s_key(inp, "height").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let fees: u64 = s_key(inp, "fees").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                let bt = grav_tree_mut("B");
                // miner_tx part
                let miner_addr = hex_decode(&s("miner_address")?)?;
                let mut addr = [0u8; 33];
                addr.copy_from_slice(&miner_addr);
                let mut mbls = Vec::new();
                if let Some(v) = inp.get("miniblocks") {
                    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&v.to_string()) {
                        for m in arr {
                            let kh = hex::decode(m.get("KeyHash").and_then(|x| x.as_str()).unwrap_or("")).unwrap_or_default();
                            let mut kh32 = [0u8; 32];
                            let n = kh.len().min(32);
                            kh32[..n].copy_from_slice(&kh[..n]);
                            mbls.push(dero_crypto::block::MiniBlock {
                                version: m.get("Version").and_then(|x| x.as_u64()).unwrap_or(1) as u8,
                                high_diff: false,
                                final_block: m.get("Final").and_then(|x| x.as_bool()).unwrap_or(false),
                                past_count: m.get("PastCount").and_then(|x| x.as_u64()).unwrap_or(1) as u8,
                                timestamp: m.get("Timestamp").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
                                height: m.get("Height").and_then(|x| x.as_u64()).unwrap_or(0),
                                past: [m.get("Past").and_then(|x| x.as_array()).and_then(|a| a.get(0)).and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                                       m.get("Past").and_then(|x| x.as_array()).and_then(|a| a.get(1)).and_then(|x| x.as_u64()).unwrap_or(0) as u32],
                                key_hash: kh32,
                                flags: m.get("Flags").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                                nonce: [0, 0, 0],
                            });
                        }
                    }
                }
                chain::process_miner_transaction(&addr, 0, &mbls, false, bt, fees, height);
                // then the txs
                if let Some(payv) = inp.get("payloads") {
                    if let Ok(pays) = serde_json::from_str::<Vec<serde_json::Value>>(&payv.to_string()) {
                        for pj in pays {
                            let stmt = &pj["statement"];
                            if let Some(pks) = stmt.get("publickeylist").and_then(|x| x.as_array()) {
                                for pksv in pks {
                                    let pk_b = hex_decode(&pksv.as_str().unwrap_or(""))?;
                                    if bt.get(&pk_b).is_none() {
                                        let pk = dero_crypto::curve::decode_compressed(&pk_b).map_err(|e| e)?;
                                        let zb = ElGamal::new(pk, base_g());
                                        let nb = dero_crypto::balance_serdes::NonceBalance { nonce_height: 0, balance: zb };
                                        bt.put(&pk_b, &nb.serialize());
                                    }
                                }
                            }
                            // rebuild single-payload tx JSON
                            let mut single = inp.clone();
                            single.insert("payloads".into(), serde_json::json!([pj]));
                            let mut tx = tx_from_in(&single)?;
                            let ser = tx.serialize(3);
                            tx = dero_crypto::transaction::Transaction::deserialize(&ser, 3)?;
                            chain::process_transaction(
                                &mut std::collections::HashMap::new(), &tx, bt, height, false,
                            );
                        }
                    }
                }
                Ok(json!({"hash": hex::encode(bt.hash())}))
            }
            "chain_sc_install" => {
                use dero_crypto::sc::{self, Snapshot, TreeWrapper};
                use dero_crypto::graviton::Tree;
                use std::collections::HashMap;
                let blob = hex_decode(&s("blob")?)?;
                let tx = dero_crypto::transaction::Transaction::deserialize(&blob, 3)?;
                let height: u64 = s_key(inp, "height").unwrap_or_else(|_| "0".into()).parse().unwrap_or(0);
                // fresh snapshot + cache
                let mut ss = Snapshot { trees: HashMap::new() };
                let mut cache: HashMap<[u8; 32], Tree> = HashMap::new();
                let mut bt = Tree::new("B");
                let mut mt = Tree::new("M");
                let txid = tx.get_hash(3);
                let scid = txid;
                // signer: from JSON (harness knows the ring keys)
                let signer: [u8; 33] = if let Ok(s) = hex_decode(&s_key(inp, "signer").unwrap_or_default()) {
                    let mut s2 = [0u8; 33];
                    let n = s.len().min(33);
                    s2[..n].copy_from_slice(&s[..n]);
                    s2
                } else if let Some(p) = tx.payloads.first() {
                    let st = &p.statement;
                    if !st.publickeylist.is_empty() {
                        let pk = dero_crypto::curve::encode_compressed(&st.publickeylist[0]);
                        let mut s2 = [0u8; 33];
                        s2.copy_from_slice(&pk);
                        s2
                    } else { [0u8; 33] }
                } else { [0u8; 33] };
                if bt.get(&signer.to_vec()).is_none() {
                    if let Ok(pk) = dero_crypto::curve::decode_compressed(&signer) {
                        let zb = dero_crypto::elgamal::ElGamal::new(pk, dero_crypto::hash_to_point::base_g());
                        let nb = dero_crypto::balance_serdes::NonceBalance { nonce_height: 0, balance: zb };
                        bt.put(&signer, &nb.serialize());
                    }
                }
                // process_transaction_sc: if the tx has SCDATA with SCACTION
                // SC_INSTALL + SCCODE, parse + install + run Initialize.
                // k0_floor is the B1/B2 activation height (Go
                // K0_MIN_RING4_HEIGHT); omitted => pre-fork (NoSigner never set).
                let k0_floor = s_key(inp, "k0_floor").ok().and_then(|v| v.parse::<u64>().ok());
                let gas = match dero_crypto::chain::process_transaction_sc(
                    &mut cache, &mut ss, &mut bt, &mut mt,
                    height, height, 0, &txid, &tx, k0_floor,
                ) {
                    Ok(g) => g,
                    Err(e) => {
                        return Ok(json!({"err": e, "gas": "0"}));
                    }
                };
                let data_root = cache.get(&scid).map(|t| hex::encode(t.hash())).unwrap_or_default();
                let balance_root = hex::encode(bt.hash());
                let meta_root = hex::encode(mt.hash());
                Ok(json!({"scid": hex::encode(scid), "gas": gas.to_string(),
                          "data_root": data_root, "balance_root": balance_root,
                          "meta_root": meta_root}))
            }
            "bp_debug" => {
                let st = statement_from_in(inp)?;
                let rand = hex_decode(&s("rand")?)?;
                let dbg = bulletproof::debug_prefix(&st.0, &st.1, &rand);
                Ok(json!(dbg))
            }
            "hashtopoint" => {
                let seed_b = hex_decode(&s("seed")?)?;
                if seed_b.len() != 32 {
                    return Err("seed must be 32 bytes".into());
                }
                let seed: [u8; 32] = seed_b.try_into().unwrap();
                let p = hash_to_point::hash_to_point(&seed);
                Ok(json!({"point": hex::encode(encode_compressed(&p))}))
            }
            "point_marshal_uncompressed" => {
                let p = point_from_hex(&s("point")?)?;
                Ok(json!({"point": hex::encode(encode_uncompressed(&p))}))
            }
            "point_scalarmult" => {
                let p = point_from_hex(&s("point")?)?;
                let scalar_b = hex_decode(&s("scalar")?)?;
                if scalar_b.len() != 32 {
                    return Err("scalar must be 32 bytes".into());
                }
                let k = be32_to_bigint(&scalar_b);
                let r = p.mul_bigint(k);
                Ok(json!({"point": hex::encode(encode_compressed(&r))}))
            }
            "point_add" => {
                let a = point_from_hex(&s("a")?)?;
                let b = point_from_hex(&s("b")?)?;
                let r = a + b;
                Ok(json!({"point": hex::encode(encode_compressed(&r))}))
            }
            "strict_point_decode" => {
                // Mirror of Go dvm.strictDecodeG1 (K0/I3 wargame fix): a
                // canonical compressed encoding must have x < p. Go's
                // LENIENT decoder (proof points) accepts x>=p via unreduced
                // big-int arithmetic; the STRICT boundary (DVM builtins)
                // still rejects them. Verdict-only output.
                let b = hex_decode(&s("point")?)?;
                if b.len() != 33 {
                    Ok(json!({"ok": false}))
                } else {
                    // strict: x must be < p (canonical field element)
                    let x = num_bigint::BigUint::from_bytes_be(&b[..32]);
                    if x >= dero_crypto::curve::p_as_biguint() {
                        return Ok(json!({"ok": false}));
                    }
                    match point_from_hex(&s("point")?) {
                        Ok(_) => Ok(json!({"ok": true})),
                        Err(_) => Ok(json!({"ok": false})),
                    }
                }
            }
            "point_neg" => {
                let p = point_from_hex(&s("point")?)?;
                let r = -p;
                Ok(json!({"point": hex::encode(encode_compressed(&r))}))
            }
            "elgamal_commit" => {
                let key = point_from_hex(&s("key")?)?;
                let value: [u8; 32] = hex_decode(&s("value")?)?.try_into().map_err(|_| "value must be 32 bytes")?;
                let r: [u8; 32] = hex_decode(&s("randomness")?)?.try_into().map_err(|_| "randomness must be 32 bytes")?;
                Ok(eg_out(&ElGamal::commit(&key, &value, &r)))
            }
            "elgamal_add" => {
                let a = eg_from_map(inp, "a_")?;
                let b = eg_from_map(inp, "b_")?;
                Ok(eg_out(&a.add(&b)))
            }
            "elgamal_plus" => {
                let e = eg_from_map(inp, "")?;
                let value: [u8; 32] = hex_decode(&s("value")?)?.try_into().map_err(|_| "value must be 32 bytes")?;
                Ok(eg_out(&e.plus(&value)))
            }
            "elgamal_mul" => {
                let e = eg_from_map(inp, "")?;
                let scalar: [u8; 32] = hex_decode(&s("scalar")?)?.try_into().map_err(|_| "scalar must be 32 bytes")?;
                Ok(eg_out(&e.mul(&scalar)))
            }
            "elgamal_neg" => {
                let e = eg_from_map(inp, "")?;
                Ok(eg_out(&e.neg()))
            }
            "elgamal_serialize" => {
                let e = eg_from_map(inp, "")?;
                Ok(json!({"bytes": hex::encode(e.serialize())}))
            }
            "elgamal_deserialize" => {
                let b = hex_decode(&s("bytes")?)?;
                match ElGamal::deserialize(&b) {
                    Ok(e) => Ok(eg_out(&e)),
                    Err(e) => Err(e),
                }
            }
            _ => Err(format!("unknown op {:?}", op)),
        }
    })();

    match result {
        Ok(out) => json!({"id": id, "ok": true, "out": out}),
        Err(e) => json!({"id": id, "ok": false, "err": e}),
    }
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({"id": -1, "ok": false, "err": format!("bad request json: {}", e)});
                let _ = writeln!(out, "{}", resp);
                continue;
            }
        };
        let id = req["id"].as_i64().unwrap_or(-1);
        let op = req["op"].as_str().unwrap_or("");
        let raw = req.get("in").cloned().unwrap_or(Value::Null);
        let resp = handle(id, op, &raw);
        let _ = writeln!(out, "{}", resp);
    }
    let _ = out.flush();
}
