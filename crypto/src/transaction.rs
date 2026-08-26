// SPDX-License-Identifier: BSD-3-Clause
//
//! Transaction serialization — mirrors derohe `transaction/transaction.go`.
//!
//! Layout (version 1):
//!   header:
//!     version uvarint, source_network uvarint, dest_network uvarint,
//!     txtype uvarint,
//!     [PREMINE|SC_TX] value uvarint,
//!     [PREMINE|COINBASE|REGISTRATION] miner_address 33,
//!     [REGISTRATION] c 32, s 32,
//!     [BURN|NORMAL|SC] height uvarint, blid 32, asset_count uvarint,
//!         per payload: burn uvarint, scid 32, rpctype 1, rpcpayload 145,
//!                      statement (see statement.rs),
//!     [SC_TX] scdata_len uvarint + scdata (CBOR),
//!   proofs (in full Serialize): per payload, the bulletproof proof.
//!
//! The tx hash (GetHash) is keccak256 of the header only (no proofs).

use crate::balance_serdes::{uvarint_decode, uvarint_encode};
use crate::bulletproof::{self, Proof, Statement};
use crate::keccak::keccak256;
use crate::rpc_args::Arguments;

pub const PAYLOAD_LIMIT: usize = 145; // 1 + 144
pub const PAYLOAD0_LIMIT: usize = 144;

pub const TX_PREMINE: u64 = 0;
pub const TX_REGISTRATION: u64 = 1;
pub const TX_COINBASE: u64 = 2;
pub const TX_NORMAL: u64 = 3;
pub const TX_BURN: u64 = 4;
pub const TX_SC: u64 = 5;

#[derive(Debug, Clone)]
pub struct AssetPayload {
    pub scid: [u8; 32],
    pub burn_value: u64,
    pub rpc_type: u8,
    pub rpc_payload: Vec<u8>,
    pub statement: Statement,
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub version: u64,
    pub source_network: u64,
    pub dest_network: u64,
    pub tx_type: u64,
    pub value: u64,
    pub miner_address: [u8; 33],
    pub c: [u8; 32],
    pub s: [u8; 32],
    pub height: u64,
    pub blid: [u8; 32],
    pub scdata: Arguments,
    pub payloads: Vec<AssetPayload>,
}

impl std::fmt::Debug for Statement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Statement")
            .field("publickeylist_len", &self.publickeylist.len())
            .field("c_len", &self.c.len())
            .field("fees", &self.fees)
            .field("pointers_len", &self.pointers.len())
            .finish()
    }
}

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("clng_len", &self.clng.len())
            .finish()
    }
}

fn valid_type(t: u64) -> bool {
    matches!(t, TX_PREMINE | TX_REGISTRATION | TX_COINBASE | TX_BURN | TX_NORMAL | TX_SC)
}

fn payload_marshal_header_statement(p: &AssetPayload, bpp: u8) -> Result<Vec<u8>, String> {
    if p.rpc_payload.len() != PAYLOAD_LIMIT {
        return Err(format!(
            "RPCPayload should be {} bytes, but have {} bytes",
            PAYLOAD_LIMIT,
            p.rpc_payload.len()
        ));
    }
    let mut out = uvarint_encode(p.burn_value);
    out.extend_from_slice(&p.scid);
    out.push(p.rpc_type);
    out.extend_from_slice(&p.rpc_payload);
    out.extend_from_slice(&p.statement.serialize(bpp));
    Ok(out)
}

impl Transaction {
    /// Go `SerializeHeader`.
    pub fn serialize_header(&self, bpp: u8) -> Vec<u8> {
        assert!(valid_type(self.tx_type), "unknown transaction type");
        let mut out = uvarint_encode(self.version);
        out.extend_from_slice(&uvarint_encode(self.source_network));
        out.extend_from_slice(&uvarint_encode(self.dest_network));
        out.extend_from_slice(&uvarint_encode(self.tx_type));
        if self.tx_type == TX_PREMINE || self.tx_type == TX_SC {
            out.extend_from_slice(&uvarint_encode(self.value));
        }
        if self.tx_type == TX_PREMINE || self.tx_type == TX_COINBASE || self.tx_type == TX_REGISTRATION {
            out.extend_from_slice(&self.miner_address);
        }
        if self.tx_type == TX_REGISTRATION {
            out.extend_from_slice(&self.c);
            out.extend_from_slice(&self.s);
        }
        if self.tx_type == TX_BURN || self.tx_type == TX_NORMAL || self.tx_type == TX_SC {
            out.extend_from_slice(&uvarint_encode(self.height));
            out.extend_from_slice(&self.blid);
            out.extend_from_slice(&uvarint_encode(self.payloads.len() as u64));
            for p in &self.payloads {
                let b = payload_marshal_header_statement(p, bpp).expect("payload marshal");
                out.extend_from_slice(&b);
            }
        }
        if self.tx_type == TX_SC {
            let data = self.scdata.marshal_binary().expect("scdata marshal");
            out.extend_from_slice(&uvarint_encode(data.len() as u64));
            out.extend_from_slice(&data);
        }
        out
    }

    /// Go `Serialize`: header + per-payload proofs.
    pub fn serialize(&self, bpp: u8) -> Vec<u8> {
        let mut out = self.serialize_header(bpp);
        for p in &self.payloads {
            if let Some(proof) = &p.proof {
                out.extend_from_slice(&bulletproof::serialize(proof));
            }
        }
        out
    }

    /// Go `Deserialize` with proof decoding TOLERATED: if a proof point
    /// fails to decode, the proof is set to None instead of erroring. The
    /// statement (ring keys, changes, fees) is always parsed. Used by the
    /// node in simulator mode where the reference skips proof verification.
    pub fn deserialize_skip_proofs(buf: &[u8]) -> Result<Transaction, String> {
        let mut pos = 0usize;
        let mut take_var = |buf: &[u8], pos: &mut usize| -> Result<u64, String> {
            let (v, n) = uvarint_decode(&buf[*pos..]).ok_or("bad varint")?;
            if n <= 0 {
                return Err("bad varint".into());
            }
            *pos += n;
            Ok(v)
        };

        let version = take_var(buf, &mut pos)?;
        if version != 1 {
            return Err("Transaction version not equal to 1".into());
        }
        let source_network = take_var(buf, &mut pos)?;
        let dest_network = take_var(buf, &mut pos)?;
        let tx_type = take_var(buf, &mut pos)?;
        if !valid_type(tx_type) {
            return Err("unknown transaction type".into());
        }

        let mut tx = Transaction {
            version,
            source_network,
            dest_network,
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

        if tx_type == TX_PREMINE || tx_type == TX_SC {
            tx.value = take_var(buf, &mut pos)?;
        }
        if tx_type == TX_PREMINE || tx_type == TX_COINBASE || tx_type == TX_REGISTRATION {
            if buf.len() - pos < 33 {
                return Err("Invalid Miner Address in Transaction".into());
            }
            tx.miner_address.copy_from_slice(&buf[pos..pos + 33]);
            pos += 33;
        }
        if tx_type == TX_REGISTRATION {
            if buf.len() - pos < 32 {
                return Err("Invalid C in Transaction".into());
            }
            tx.c.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
            if buf.len() - pos < 32 {
                return Err("Invalid S in Transaction".into());
            }
            tx.s.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
        }

        if tx_type == TX_BURN || tx_type == TX_NORMAL || tx_type == TX_SC {
            tx.height = take_var(buf, &mut pos)?;
            if buf.len() - pos < 32 {
                return Err("Invalid BLID value in Transaction".into());
            }
            tx.blid.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
            let asset_count = take_var(buf, &mut pos)?;
            if asset_count < 1 {
                return Err("Invalid asset_count in Transaction".into());
            }
            for _ in 0..asset_count {
                let mut p = AssetPayload {
                    scid: [0u8; 32],
                    burn_value: 0,
                    rpc_type: 0,
                    rpc_payload: Vec::new(),
                    statement: Statement {
                        publickeylist: Vec::new(),
                        c: Vec::new(),
                        cln: Vec::new(),
                        crn: Vec::new(),
                        d: crate::hash_to_point::base_g(),
                        roothash: [0u8; 32],
                        fees: 0,
                        pointers: Vec::new(),
                    },
                    proof: None,
                };
                p.burn_value = take_var(buf, &mut pos)?;
                if buf.len() - pos < 32 {
                    return Err("payload scid: short buffer".into());
                }
                p.scid.copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                if buf.len() - pos < 1 {
                    return Err("payload rpctype: short buffer".into());
                }
                p.rpc_type = buf[pos];
                pos += 1;
                if buf.len() - pos < PAYLOAD_LIMIT {
                    return Err("payload rpcpayload: short buffer".into());
                }
                p.rpc_payload = buf[pos..pos + PAYLOAD_LIMIT].to_vec();
                pos += PAYLOAD_LIMIT;
                let (st, used) = Statement::deserialize(&buf[pos..])?;
                p.statement = st;
                pos += used;
                tx.payloads.push(p);
            }
        }

        if tx_type == TX_SC {
            let sc_len = take_var(buf, &mut pos)?;
            if sc_len as usize > buf.len() - pos {
                return Err("SC len out of possible range".into());
            }
            tx.scdata = Arguments::unmarshal_binary(&buf[pos..pos + sc_len as usize])?;
            pos += sc_len as usize;
        }

        // proofs: parse but tolerate ANY failure (simulator laxity)
        if tx_type == TX_BURN || tx_type == TX_NORMAL || tx_type == TX_SC {
            for p in tx.payloads.iter_mut() {
                let st_bpp = p.statement.bpp();
                let ring = if p.statement.pointers.is_empty() { 0 } else { p.statement.pointers.len() / st_bpp as usize };
                // ring must be a power of 2 for the proof length formula;
                // simulator chains may contain bad rings — skip the proof
                let m = if ring.is_power_of_two() && ring > 0 {
                    ring.trailing_zeros() as usize
                } else {
                    // unknown/odd ring: can't locate the proof — leave proof
                    // None and advance past the remainder conservatively
                    p.proof = None;
                    continue;
                };
                match bulletproof::deserialize(&buf[pos..], m) {
                    Ok(proof) => {
                        pos += bulletproof::serialized_len(&proof);
                        p.proof = Some(proof);
                    }
                    Err(_) => {
                        // skip the proof section by canonical length
                        pos += Self::proof_len_for_m(m);
                    }
                }
            }
        }

        Ok(tx)
    }

    /// The serialized proof length for a given m (ring exponent).
    pub fn proof_len_for_m(m: usize) -> usize {
        4 * 33 + m * 8 * 33 + 33 + 2 * m * 32 + 32 + 66 + 9 * 32 + 32 + 32 + 14 * 33
    }

    /// Go `SerializeCoreStatement`: header only (excludes proofs).
    pub fn serialize_core_statement(&self, bpp: u8) -> Vec<u8> {
        self.serialize_header(bpp)
    }

    /// Go `GetHash`: keccak256(core statement) for version 1.
    pub fn get_hash(&self, bpp: u8) -> [u8; 32] {
        match self.version {
            1 => keccak256(&self.serialize_core_statement(bpp)),
            _ => panic!("Transaction version unknown"),
        }
    }

    /// Go `Deserialize`. bpp = expected bytes_per_publickey (3 on mainnet).
    pub fn deserialize(buf: &[u8], bpp: u8) -> Result<Transaction, String> {
        let mut pos = 0usize;
        let mut take_var = |buf: &[u8], pos: &mut usize| -> Result<u64, String> {
            let (v, n) = uvarint_decode(&buf[*pos..]).ok_or("bad varint")?;
            if n <= 0 {
                return Err("bad varint".into());
            }
            *pos += n;
            Ok(v)
        };

        let version = take_var(buf, &mut pos)?;
        if version != 1 {
            return Err("Transaction version not equal to 1".into());
        }
        let source_network = take_var(buf, &mut pos)?;
        let dest_network = take_var(buf, &mut pos)?;
        let tx_type = take_var(buf, &mut pos)?;
        if !valid_type(tx_type) {
            return Err("unknown transaction type".into());
        }

        let mut tx = Transaction {
            version,
            source_network,
            dest_network,
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

        if tx_type == TX_PREMINE || tx_type == TX_SC {
            tx.value = take_var(buf, &mut pos)?;
        }
        if tx_type == TX_PREMINE || tx_type == TX_COINBASE || tx_type == TX_REGISTRATION {
            if buf.len() - pos < 33 {
                return Err("Invalid Miner Address in Transaction".into());
            }
            tx.miner_address.copy_from_slice(&buf[pos..pos + 33]);
            pos += 33;
        }
        if tx_type == TX_REGISTRATION {
            if buf.len() - pos < 32 {
                return Err("Invalid C in Transaction".into());
            }
            tx.c.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
            if buf.len() - pos < 32 {
                return Err("Invalid S in Transaction".into());
            }
            tx.s.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
        }

        if tx_type == TX_BURN || tx_type == TX_NORMAL || tx_type == TX_SC {
            tx.height = take_var(buf, &mut pos)?;
            if buf.len() - pos < 32 {
                return Err("Invalid BLID value in Transaction".into());
            }
            tx.blid.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
            let asset_count = take_var(buf, &mut pos)?;
            if asset_count < 1 {
                return Err("Invalid asset_count in Transaction".into());
            }
            for _ in 0..asset_count {
                let mut p = AssetPayload {
                    scid: [0u8; 32],
                    burn_value: 0,
                    rpc_type: 0,
                    rpc_payload: Vec::new(),
                    statement: Statement {
                        publickeylist: Vec::new(),
                        c: Vec::new(),
                        cln: Vec::new(),
                        crn: Vec::new(),
                        d: crate::hash_to_point::base_g(),
                        roothash: [0u8; 32],
                        fees: 0,
                        pointers: Vec::new(),
                    },
                    proof: None,
                };
                p.burn_value = take_var(buf, &mut pos)?;
                if buf.len() - pos < 32 {
                    return Err("payload scid: short buffer".into());
                }
                p.scid.copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                if buf.len() - pos < 1 {
                    return Err("payload rpctype: short buffer".into());
                }
                p.rpc_type = buf[pos];
                pos += 1;
                if buf.len() - pos < PAYLOAD_LIMIT {
                    return Err("payload rpcpayload: short buffer".into());
                }
                p.rpc_payload = buf[pos..pos + PAYLOAD_LIMIT].to_vec();
                pos += PAYLOAD_LIMIT;
                let (st, used) = Statement::deserialize(&buf[pos..])?;
                p.statement = st;
                pos += used;
                tx.payloads.push(p);
            }
        }

        if tx_type == TX_SC {
            let sc_len = take_var(buf, &mut pos)?;
            if sc_len as usize > buf.len() - pos {
                return Err("SC len out of possible range".into());
            }
            tx.scdata = Arguments::unmarshal_binary(&buf[pos..pos + sc_len as usize])?;
            pos += sc_len as usize;
        }

        if tx_type == TX_BURN || tx_type == TX_NORMAL || tx_type == TX_SC {
            for p in tx.payloads.iter_mut() {
                // ring size from the statement's publickey pointers:
                // pointers_len = ring_size * bpp. bpp comes from the
                // STATEMENT's own bytes (Go: Bytes_per_publickey), NOT a
                // caller-supplied constant — wallet txs use bpp=2.
                let st_bpp = p.statement.bpp();
                let ring = if p.statement.pointers.is_empty() { 0 } else { p.statement.pointers.len() / st_bpp as usize };
                let m = if ring > 0 { (ring as f64).log2() as usize } else { 0 };
                let proof = bulletproof::deserialize(&buf[pos..], m).map_err(|e| format!("proof: {e}"))?;
                pos += bulletproof::serialized_len(&proof);
                p.proof = Some(proof);
            }
        }

        if !(tx_type == TX_PREMINE || tx_type == TX_COINBASE) && buf.len() - pos != 0 {
            return Err(format!(
                "Extra unknown data in Transaction, extrabytes {}",
                buf.len() - pos
            ));
        }

        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_to_point::base_g;
    use ark_ec::PrimeGroup;

    fn stmt() -> Statement {
        use ark_ff::PrimeField;
        let g = base_g();
        let pks: Vec<_> = (0..2).map(|i| g.mul_bigint(ark_bn254::Fr::from(i + 1).into_bigint())).collect();
        Statement {
            publickeylist: pks.clone(),
            c: pks.clone(),
            cln: Vec::new(),
            crn: Vec::new(),
            d: g,
            roothash: [3u8; 32],
            fees: 10,
            pointers: Vec::new(),
        }
    }

    fn payload() -> AssetPayload {
        AssetPayload {
            scid: [0u8; 32],
            burn_value: 5,
            rpc_type: 0,
            rpc_payload: vec![0u8; PAYLOAD_LIMIT],
            statement: stmt(),
            proof: None,
        }
    }

    #[test]
    fn header_layout_types() {
        // premine: version, networks, type, value, miner_address
        let mut tx = Transaction {
            version: 1,
            source_network: 0,
            dest_network: 0,
            tx_type: TX_PREMINE,
            value: 1000,
            miner_address: [1u8; 33],
            c: [0u8; 32],
            s: [0u8; 32],
            height: 0,
            blid: [0u8; 32],
            scdata: Arguments::default(),
            payloads: Vec::new(),
        };
        let h = tx.serialize_header(3);
        assert_eq!(h[0], 1); // version
        assert_eq!(h[1], 0); // src net
        assert_eq!(h[2], 0); // dst net
        assert_eq!(h[3], 0); // type PREMINE
        assert_eq!(h[4], 0xe8); // value 1000 uvarint = 0xe8 0x07
        assert_eq!(h[5], 0x07);
        assert_eq!(&h[6..39], &[1u8; 33]); // miner address
        assert_eq!(h.len(), 6 + 33);

        tx.tx_type = TX_COINBASE;
        let h2 = tx.serialize_header(3);
        assert_eq!(h2.len(), 4 + 33); // no value for coinbase

        tx.tx_type = TX_REGISTRATION;
        let h3 = tx.serialize_header(3);
        assert_eq!(h3.len(), 4 + 33 + 64); // + C + S

        tx.tx_type = TX_NORMAL;
        tx.payloads = vec![payload()];
        let h4 = tx.serialize_header(3);
        // header + height varint + blid + count + payload
        assert!(h4.len() > 4 + 32 + 1 + 1 + PAYLOAD_LIMIT);
    }

    #[test]
    fn rpc_payload_len_enforced() {
        let mut p = payload();
        p.rpc_payload = vec![0u8; 10];
        let mut tx = Transaction {
            version: 1,
            source_network: 0,
            dest_network: 0,
            tx_type: TX_NORMAL,
            value: 0,
            miner_address: [0u8; 33],
            c: [0u8; 32],
            s: [0u8; 32],
            height: 100,
            blid: [0u8; 32],
            scdata: Arguments::default(),
            payloads: vec![p],
        };
        let r = std::panic::catch_unwind(|| tx.serialize_header(3));
        assert!(r.is_err()); // panics like Go
    }
}
