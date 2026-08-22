//! Differential-test oracle binary: mirrors oracle/main.go's JSONL protocol so
//! harness/difftest.py can compare Go reference vs Rust implementation.
//!
//!   req:  {"id": <int>, "op": "<op>", "in": { ... }}
//!   resp: {"id": <int>, "ok": true, "out": { ... }}
//!         {"id": <int>, "ok": false, "err": "<message>"}

use std::io::{self, BufRead, Write};

use ark_bn254::G1Projective;
use ark_ec::PrimeGroup;
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

/// Build a Statement + Witness from the request input (mirrors Go
/// statementFromIn: ring pairs CLn = C, CRn = D).
fn statement_from_in(inp: &serde_json::Map<String, Value>) -> Result<(bulletproof::Statement, bulletproof::Witness), String> {
    let pk = str_list(inp, "publickeylist")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
    let c = str_list(inp, "c")?.iter().map(|h| ppoint_from_hex(h)).collect::<Vec<_>>();
    let d = ppoint_from_hex(&s_key(inp, "d")?);
    let roothash: [u8; 32] = hex_decode(&s_key(inp, "roothash")?)?.try_into().map_err(|_| "roothash must be 32 bytes")?;
    let fees: u64 = s_key(inp, "fees")?.parse().map_err(|e| format!("fees: {}", e))?;
    let secret_key = fr_from_hex(&s_key(inp, "secretkey")?);
    let r = fr_from_hex(&s_key(inp, "r")?);
    let transfer: u64 = s_key(inp, "transfer")?.parse().map_err(|e| format!("transfer: {}", e))?;
    let balance: u64 = s_key(inp, "balance")?.parse().map_err(|e| format!("balance: {}", e))?;
    let idx_raw = inp.get("index").and_then(|v| v.as_array()).ok_or("missing index")?;
    let idx: Vec<usize> = idx_raw.iter().filter_map(|v| v.as_i64().map(|x| x as usize)).collect();
    let index = [idx[0], idx[1]];
    let st = bulletproof::Statement {
        publickeylist: pk.clone(),
        c: c.clone(),
        cln: c.clone(),
        crn: vec![d; pk.len()],
        d,
        roothash,
        fees,
    };
    let w = bulletproof::Witness { secret_key, r, transfer_amount: transfer, balance, index };
    Ok((st, w))
}

fn s_key(inp: &serde_json::Map<String, Value>, k: &str) -> Result<String, String> {
    inp.get(k).and_then(|v| v.as_str()).map(|x| x.to_string()).ok_or_else(|| format!("missing key {}", k))
}

/// Deserialize a Go-serialized Proof (mirrors Go Proof.Deserialize).
/// m = number of CLnG entries (ring pairs count / 2).
fn deserialize_proof(b: &[u8], m: usize) -> Result<bulletproof::Proof, String> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8], String> {
        if pos + n > b.len() {
            return Err("proof buffer too short".into());
        }
        let s = &b[pos..pos + n];
        pos += n;
        Ok(s)
    };
    let pt = |bytes: &[u8]| -> Result<G1Projective, String> { decode_compressed(bytes) };
    let sc = |bytes: &[u8]| -> Result<[u8; 32], String> {
        let mut a = [0u8; 32];
        a.copy_from_slice(bytes);
        Ok(a)
    };
    let ba = pt(take(33)?)?;
    let bs = pt(take(33)?)?;
    let a = pt(take(33)?)?;
    let b = pt(take(33)?)?;
    let mut clng = Vec::with_capacity(m);
    let mut crng = Vec::with_capacity(m);
    let mut c_0g = Vec::with_capacity(m);
    let mut dg = Vec::with_capacity(m);
    let mut y_0g = Vec::with_capacity(m);
    let mut gg = Vec::with_capacity(m);
    let mut c_xg = Vec::with_capacity(m);
    let mut y_xg = Vec::with_capacity(m);
    for _ in 0..m {
        clng.push(pt(take(33)?)?);
        crng.push(pt(take(33)?)?);
        c_0g.push(pt(take(33)?)?);
        dg.push(pt(take(33)?)?);
        y_0g.push(pt(take(33)?)?);
        gg.push(pt(take(33)?)?);
        c_xg.push(pt(take(33)?)?);
        y_xg.push(pt(take(33)?)?);
    }
    let u = pt(take(33)?)?;
    let mut f_raw = Vec::with_capacity(2 * m);
    for _ in 0..2 * m {
        f_raw.push(sc(take(32)?)?);
    }
    let f = FieldVector::new(f_raw);
    let z_a = fr_from_be_bytes(take(32)?);
    let t_1 = pt(take(33)?)?;
    let t_2 = pt(take(33)?)?;
    let that = fr_from_be_bytes(take(32)?);
    let mu = fr_from_be_bytes(take(32)?);
    let c = fr_from_be_bytes(take(32)?);
    let s_sk = fr_from_be_bytes(take(32)?);
    let s_r = fr_from_be_bytes(take(32)?);
    let s_b = fr_from_be_bytes(take(32)?);
    let s_tau = fr_from_be_bytes(take(32)?);
    // IP section: a(32) b(32) + 7 rounds of L(33) R(33)
    let ip_a = sc(take(32)?)?;
    let ip_b = sc(take(32)?)?;
    let mut ls = Vec::with_capacity(7);
    let mut rs = Vec::with_capacity(7);
    for _ in 0..7 {
        ls.push(pt(take(33)?)?);
        rs.push(pt(take(33)?)?);
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
            .ok_or_else(|| format!("missing key {}", k))
    };

    let result: Result<Value, String> = (|| {
        match op {
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
                let st = statement_from_in(inp)?;
                let rand = hex_decode(&s("rand")?)?;
                let scid: [u8; 32] = hex_decode(&s("scid")?)?.try_into().map_err(|_| "scid must be 32 bytes")?;
                let scid_index: i32 = s("scid_index")?.parse().map_err(|e| format!("scid_index: {}", e))?;
                let txid: [u8; 32] = hex_decode(&s("txid")?)?.try_into().map_err(|_| "txid must be 32 bytes")?;
                let burn: u64 = s("burn")?.parse().map_err(|e| format!("burn: {}", e))?;
                let u = ppoint_from_hex(&s("u")?);
                let proof = bulletproof::generate_proof(&scid, scid_index, &st.0, &st.1, &u, &txid, burn, &rand);
                let ser = bulletproof::serialize(&proof);
                Ok(json!({
                    "proof": hex::encode(ser),
                    "nonce": hex::encode(bulletproof::nonce(&proof)),
                    "parity": bulletproof::parity(&proof),
                }))
            }
            "proof_verify" => {
                let st = statement_from_in(inp)?;
                let proof_b = hex_decode(&s("proof")?)?;
                let scid: [u8; 32] = hex_decode(&s("scid")?)?.try_into().map_err(|_| "scid must be 32 bytes")?;
                let scid_index: i32 = s("scid_index")?.parse().map_err(|e| format!("scid_index: {}", e))?;
                let txid: [u8; 32] = hex_decode(&s("txid")?)?.try_into().map_err(|_| "txid must be 32 bytes")?;
                let burn: u64 = s("burn")?.parse().map_err(|e| format!("burn: {}", e))?;
                // deserialize: parse the proof struct from the byte stream
                let proof = deserialize_proof(&proof_b, st.0.publickeylist.len() / 2)?;
                let verified = bulletproof::verify(&scid, scid_index, &st.0, &proof, &txid, burn);
                Ok(json!({"verified": verified}))
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
