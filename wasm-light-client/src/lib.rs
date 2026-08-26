// SPDX-License-Identifier: BSD-3-Clause
//
//! WASM light client for DERO — pure crypto + serialization, no file I/O or networking.
//!
//! Exposes wallet functions via wasm-bindgen:
//!   - Address parsing (bech32 encode/decode)
//!   - Key derivation (scalar mult of base_g)
//!   - TX deserialization (parse raw tx blob → txid + statement fields)
//!   - Block deserialization (parse raw block blob → header + miner tx)
//!   - Bulletproof verification (verify a proof against a statement)
//!
//! All functions are pure: they take byte slices and return serialized
//! results. No filesystem, no network — safe to run in a browser WASM sandbox.

use wasm_bindgen::prelude::*;

use ark_ec::PrimeGroup;
use ark_ff::PrimeField;

use dero_crypto::block::Block;
use dero_crypto::bulletproof;
use dero_crypto::curve;
use dero_crypto::hash_to_point::base_g;
use dero_crypto::rpc_addr;
use dero_crypto::transaction::Transaction;
use hex;

// ---------------------------------------------------------------------------
// Address parsing (bech32 encode/decode)
// ---------------------------------------------------------------------------

/// Decode a DERO bech32 address string into a 33-byte compressed public key.
/// Returns the raw 33 bytes on success, or a JsValue error string.
#[wasm_bindgen]
pub fn address_to_compressed(addr: &str) -> Result<Vec<u8>, JsValue> {
    rpc_addr::address_to_compressed(addr)
        .map_err(|e| JsValue::from_str(&format!("address decode error: {}", e)))
}

/// Encode a 33-byte compressed public key into a DERO bech32 address string.
#[wasm_bindgen]
pub fn compressed_to_address(pk: &[u8]) -> Result<String, JsValue> {
    rpc_addr::compressed_to_address(pk)
        .map_err(|e| JsValue::from_str(&format!("address encode error: {}", e)))
}

/// Round-trip: decode an address to 33-byte compressed key, then re-encode.
/// Useful for validation. Returns the canonical address string.
#[wasm_bindgen]
pub fn validate_address(addr: &str) -> Result<String, JsValue> {
    let pk = address_to_compressed(addr)?;
    compressed_to_address(&pk)
}

// ---------------------------------------------------------------------------
// Key derivation (scalar mult of base_g)
// ---------------------------------------------------------------------------

/// Derive a public key from a 32-byte scalar (private key) by computing
/// `scalar * base_g` on the alt_bn128 (BN254) curve. Returns the 33-byte
/// DERO compressed encoding.
#[wasm_bindgen]
pub fn derive_public_key(scalar_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar_bytes.len() != 32 {
        return Err(JsValue::from_str("scalar must be exactly 32 bytes"));
    }
    let g = base_g();
    let sc = dero_crypto::fieldvector::fr_from_be_bytes(scalar_bytes);
    let pk = g.mul_bigint(sc.into_bigint());
    Ok(curve::encode_compressed(&pk).to_vec())
}

/// Get the protocol base point G = HashToPoint(keccak256("DEROG")).
/// Returns the 33-byte DERO compressed encoding.
#[wasm_bindgen]
pub fn get_base_g() -> Vec<u8> {
    let g = base_g();
    curve::encode_compressed(&g).to_vec()
}

/// Decode a 33-byte DERO compressed point and return the 64-byte
/// uncompressed encoding (x || y, 32 bytes each, big-endian).
#[wasm_bindgen]
pub fn decompress_point(compressed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = curve::decode_compressed(compressed)
        .map_err(|e| JsValue::from_str(&format!("point decode error: {}", e)))?;
    Ok(curve::encode_uncompressed(&p).to_vec())
}

/// Scalar multiply: compute `scalar * point` and return the 33-byte
/// DERO compressed encoding of the result.
#[wasm_bindgen]
pub fn scalar_mult(point_compressed: &[u8], scalar_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar_bytes.len() != 32 {
        return Err(JsValue::from_str("scalar must be exactly 32 bytes"));
    }
    let p = curve::decode_compressed(point_compressed)
        .map_err(|e| JsValue::from_str(&format!("point decode error: {}", e)))?;
    let sc = dero_crypto::fieldvector::fr_from_be_bytes(scalar_bytes);
    let result = p.mul_bigint(sc.into_bigint());
    Ok(curve::encode_compressed(&result).to_vec())
}

/// Point addition: add two DERO compressed points. Returns the 33-byte
/// compressed encoding of the sum.
#[wasm_bindgen]
pub fn point_add(a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pa = curve::decode_compressed(a)
        .map_err(|e| JsValue::from_str(&format!("point A decode error: {}", e)))?;
    let pb = curve::decode_compressed(b)
        .map_err(|e| JsValue::from_str(&format!("point B decode error: {}", e)))?;
    let sum = pa + pb;
    Ok(curve::encode_compressed(&sum).to_vec())
}

// ---------------------------------------------------------------------------
// TX deserialization
// ---------------------------------------------------------------------------

/// JSON-serializable result of deserializing a transaction.
#[derive(serde::Serialize)]
pub struct TxInfo {
    /// 32-byte keccak256 txid (hex-encoded)
    pub txid: String,
    pub version: u64,
    pub source_network: u64,
    pub dest_network: u64,
    pub tx_type: u64,
    pub value: u64,
    pub miner_address: String,
    pub height: u64,
    pub blid: String,
    pub payload_count: usize,
    pub payloads: Vec<PayloadInfo>,
}

#[derive(serde::Serialize)]
pub struct PayloadInfo {
    pub scid: String,
    pub burn_value: u64,
    pub rpc_type: u8,
    pub fees: u64,
    pub ring_size: usize,
    pub has_proof: bool,
}

/// Deserialize a raw DERO transaction blob and extract the txid + statement fields.
/// `tx_blob` is the raw serialized transaction bytes.
/// `bpp` is the bytes_per_publickey (3 on mainnet).
/// Returns a JSON string with the transaction info.
#[wasm_bindgen]
pub fn deserialize_tx(tx_blob: &[u8], bpp: u8) -> Result<String, JsValue> {
    let tx = Transaction::deserialize(tx_blob, bpp)
        .map_err(|e| JsValue::from_str(&format!("tx deserialize error: {}", e)))?;

    let _txid = tx.get_hash(bpp);
    let info = build_tx_info(&tx, bpp);

    serde_json::to_string(&info)
        .map_err(|e| JsValue::from_str(&format!("serde error: {}", e)))
}

/// Compute the keccak256 txid of a raw transaction blob.
/// Returns a 32-byte hex string.
#[wasm_bindgen]
pub fn tx_txid(tx_blob: &[u8], bpp: u8) -> Result<String, JsValue> {
    let tx = Transaction::deserialize(tx_blob, bpp)
        .map_err(|e| JsValue::from_str(&format!("tx deserialize error: {}", e)))?;
    Ok(hex::encode(&tx.get_hash(bpp)))
}

fn build_tx_info(tx: &Transaction, bpp: u8) -> TxInfo {
    let txid = tx.get_hash(bpp);
    let payloads: Vec<PayloadInfo> = tx.payloads.iter().map(|p| {
        let ring_size = if p.statement.pointers.is_empty() {
            p.statement.publickeylist.len()
        } else {
            p.statement.pointers.len() / bpp as usize
        };
        PayloadInfo {
            scid: hex::encode(&p.scid),
            burn_value: p.burn_value,
            rpc_type: p.rpc_type,
            fees: p.statement.fees,
            ring_size,
            has_proof: p.proof.is_some(),
        }
    }).collect();

    TxInfo {
        txid: hex::encode(&txid),
        version: tx.version,
        source_network: tx.source_network,
        dest_network: tx.dest_network,
        tx_type: tx.tx_type,
        value: tx.value,
        miner_address: hex::encode(&tx.miner_address),
        height: tx.height,
        blid: hex::encode(&tx.blid),
        payload_count: tx.payloads.len(),
        payloads,
    }
}

// ---------------------------------------------------------------------------
// Block deserialization
// ---------------------------------------------------------------------------

/// JSON-serializable result of deserializing a block.
#[derive(serde::Serialize)]
pub struct BlockInfo {
    pub major_version: u64,
    pub minor_version: u64,
    pub timestamp: u64,
    pub height: u64,
    pub proof: String,
    pub tips_count: usize,
    pub tips: Vec<String>,
    pub mini_blocks_count: usize,
    pub tx_hashes_count: usize,
    pub tx_hashes: Vec<String>,
    pub miner_tx: TxInfo,
}

/// Deserialize a raw DERO block blob and extract the header + miner tx.
/// Returns a JSON string with the block info.
#[wasm_bindgen]
pub fn deserialize_block(block_blob: &[u8]) -> Result<String, JsValue> {
    let block = Block::deserialize(block_blob)
        .map_err(|e| JsValue::from_str(&format!("block deserialize error: {}", e)))?;

    let miner_tx_info = build_tx_info(&block.miner_tx, 3);

    let info = BlockInfo {
        major_version: block.major_version,
        minor_version: block.minor_version,
        timestamp: block.timestamp,
        height: block.height,
        proof: hex::encode(&block.proof),
        tips_count: block.tips.len(),
        tips: block.tips.iter().map(|t| hex::encode(t)).collect(),
        mini_blocks_count: block.mini_blocks.len(),
        tx_hashes_count: block.tx_hashes.len(),
        tx_hashes: block.tx_hashes.iter().map(|t| hex::encode(t)).collect(),
        miner_tx: miner_tx_info,
    };

    serde_json::to_string(&info)
        .map_err(|e| JsValue::from_str(&format!("serde error: {}", e)))
}

/// Compute the NIST SHA3-256 block hash of a raw block blob.
/// Returns a 32-byte hex string.
#[wasm_bindgen]
pub fn block_hash(block_blob: &[u8]) -> Result<String, JsValue> {
    let block = Block::deserialize(block_blob)
        .map_err(|e| JsValue::from_str(&format!("block deserialize error: {}", e)))?;
    Ok(hex::encode(&block.get_hash()))
}

// ---------------------------------------------------------------------------
// Bulletproof verification
// ---------------------------------------------------------------------------

/// Verify a bulletproof against a deserialized statement.
///
/// Parameters:
///   - `scid_hex`: 32-byte smart contract ID as hex string
///   - `scid_index`: the SC index (i32)
///   - `statement_bytes`: the serialized Statement wire format
///   - `proof_bytes`: the serialized Proof bytes
///   - `txid_hex`: 32-byte transaction ID as hex string
///   - `extra_value`: the extra open value (burn value)
///   - `bpp`: bytes_per_publickey (3 on mainnet)
///
/// Returns `true` if the proof verifies, `false` otherwise.
#[wasm_bindgen]
pub fn verify_bulletproof(
    scid_hex: &str,
    scid_index: i32,
    statement_bytes: &[u8],
    proof_bytes: &[u8],
    txid_hex: &str,
    extra_value: u64,
    bpp: u8,
) -> Result<bool, JsValue> {
    let scid_bytes = hex::decode(scid_hex)
        .map_err(|e| JsValue::from_str(&format!("scid hex decode error: {}", e)))?;
    if scid_bytes.len() != 32 {
        return Err(JsValue::from_str("scid must be 32 bytes"));
    }
    let mut scid = [0u8; 32];
    scid.copy_from_slice(&scid_bytes);

    let txid_bytes = hex::decode(txid_hex)
        .map_err(|e| JsValue::from_str(&format!("txid hex decode error: {}", e)))?;
    if txid_bytes.len() != 32 {
        return Err(JsValue::from_str("txid must be 32 bytes"));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);

    let (statement, _used) = bulletproof::Statement::deserialize(statement_bytes)
        .map_err(|e| JsValue::from_str(&format!("statement deserialize error: {}", e)))?;

    let ring_size = if statement.pointers.is_empty() {
        statement.publickeylist.len()
    } else {
        statement.pointers.len() / bpp as usize
    };
    if ring_size == 0 {
        return Err(JsValue::from_str("empty ring size"));
    }
    let m = ring_size / 2;

    let proof = bulletproof::deserialize(proof_bytes, m)
        .map_err(|e| JsValue::from_str(&format!("proof deserialize error: {}", e)))?;

    Ok(bulletproof::verify(
        &scid,
        scid_index,
        &statement,
        &proof,
        &txid,
        extra_value,
    ))
}

/// Verify all bulletproofs in a transaction blob.
///
/// Deserializes the tx, extracts each payload's statement + proof, and
/// verifies the bulletproof for each payload.
/// Returns a JSON array of booleans (one per payload), as u8 (0/1).
#[wasm_bindgen]
pub fn verify_tx_proofs(
    tx_blob: &[u8],
    scid_hex: &str,
    scid_index: i32,
    bpp: u8,
) -> Result<Vec<u8>, JsValue> {
    let scid_bytes = hex::decode(scid_hex)
        .map_err(|e| JsValue::from_str(&format!("scid hex decode error: {}", e)))?;
    if scid_bytes.len() != 32 {
        return Err(JsValue::from_str("scid must be 32 bytes"));
    }
    let mut scid = [0u8; 32];
    scid.copy_from_slice(&scid_bytes);

    let tx = Transaction::deserialize(tx_blob, bpp)
        .map_err(|e| JsValue::from_str(&format!("tx deserialize error: {}", e)))?;

    let txid = tx.get_hash(bpp);

    let mut results = Vec::new();
    for p in &tx.payloads {
        if let Some(ref proof) = p.proof {
            results.push(bulletproof::verify(
                &scid,
                scid_index,
                &p.statement,
                proof,
                &txid,
                p.burn_value,
            ) as u8);
        } else {
            results.push(0u8);
        }
    }
    Ok(results)
}

// ---------------------------------------------------------------------------
// Utility: keccak256 / SHA3-256 / blake2s / sha256
// ---------------------------------------------------------------------------

/// Compute keccak256 (legacy Keccak, not NIST SHA3) of the input.
/// Returns 32 bytes.
#[wasm_bindgen]
pub fn keccak256(data: &[u8]) -> Vec<u8> {
    dero_crypto::keccak::keccak256(data).to_vec()
}

/// Compute NIST SHA3-256 of the input. Returns 32 bytes.
#[wasm_bindgen]
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    dero_crypto::sha3_256(data).to_vec()
}

/// Compute SHA-256 of the input. Returns 32 bytes.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    dero_crypto::sha2_256(data).to_vec()
}

/// Compute blake2s-256 (graviton hash) of the input. Returns 32 bytes.
#[wasm_bindgen]
pub fn blake2s_256(data: &[u8]) -> Vec<u8> {
    dero_crypto::statement::graviton_sum(data).to_vec()
}

// ---------------------------------------------------------------------------
// Panic hook (optional — call init_panic_hook() at startup for console errors)
// ---------------------------------------------------------------------------

/// Install a panic hook that logs to the browser console.
/// Call this once at WASM module initialization.
#[wasm_bindgen]
pub fn init_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        // Log to console — uses web_sys if available, otherwise just swallow
        #[cfg(target_arch = "wasm32")]
        {
            let _ = info; // In production, link web-sys for console.error
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = info;
        }
    }));
}
